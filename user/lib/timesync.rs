// The time service's arithmetic (v0.79 stage D) without input or output: one NTS measurement
// as an interval, the quorum of operators, the final interval, the NTS-KE backoff, the span
// for the second certificate check.  /bin/timekeeper uses it; /bin/synctest tests it.
//
// One measurement (all in integer milliseconds):
//   T1, T4 – this machine's uptime when the query left and the answer came; T2, T3 – the
//   server's Receive and Transmit.  delta = (T4 - T1) - (T3 - T2) (ntp::delay_ms: -1 ms counts
//   as 0, less than that, T4 < T1 or above 10 s – refused).  T = T3 + delta / 2 – the server's
//   time when the answer came.  U = ceil(delta / 2) + ceil(root delay / 2) + ceil(root
//   dispersion) + 1000: the path asymmetry (RFC 8915: up to half the round trip), the server's
//   own distance from its reference (RFC 5905's root delay / 2 + root dispersion, as the
//   server reports it) and 1 s for the resolution of the clock.  Interval [T - U, T + U].
//   To compare measurements taken at different moments each is kept as an offset from the
//   uptime: off = T - T4.
//
// The quorum: one vote per operator (two entries of the list with the same operator_id are one
// vote – the first that measured); a subset of at least 2 operators agrees when their
// intervals, each widened by 1 s on both sides (2 s tolerance, as v0.78), have a point in
// common – the widening serves only this decision.  The largest agreeing subset wins; two or
// more different subsets of that size (A~B, B~C, A!~C) is "ambiguous" and nothing is set.
// The final interval is the envelope of the members' own (not widened) intervals:
// [min(T - U), max(T + U)], T = its middle, U = half its width – never narrower than the
// servers' disagreement.  It contains the true time only if at least one member's interval
// is a correct bound for its own measurement; NTS authenticates where a time came from, not
// that the server's estimates are right.
#![allow(dead_code)]

use super::ntp;

/// One side of the widening for the agreement test (ms).
pub const TOLERANCE_MS: i64 = 1000;
/// The resolution term of U (ms).
pub const RESOLUTION_MS: u64 = 1000;
/// NTS-KE retry after a failure: 10 s, then x 1.5, at most 5 days.
pub const KE_FIRST_MS: u64 = 10_000;
pub const KE_MAX_MS: u64 = 5 * 86_400_000;
/// Operators in one quorum, entries in one list.
pub const MAX_SOURCES: usize = 8;

/// A 16.16 fixed-point number of seconds in ms, rounded up.
pub fn fixed_ms_up(v: u32) -> u64 {
    (v as u64 * 1000).div_ceil(65_536)
}

/// The interval of one NTS answer: (T in Unix ms, U in ms).  `sent_ms` / `received_ms` from
/// the uptime; `pivot` = the build date (the NTP era).
pub fn measure(r: &ntp::Reply, sent_ms: u64, received_ms: u64, pivot: u64) -> Result<(i64, u64), ntp::Reject> {
    let delay = ntp::delay_ms(r, sent_ms, received_ms)?;
    let t = ntp::server_time_ms(r, delay, pivot);
    let u = delay.div_ceil(2) + (r.root_delay as u64 * 1000).div_ceil(2 * 65_536) + fixed_ms_up(r.root_dispersion) + RESOLUTION_MS;
    Ok((t, u))
}

/// A measurement in the quorum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    /// T minus the uptime when the answer came (ms).
    pub off: i64,
    pub u: u64,
    /// The operator (an index: entries with the same operator_id share it).
    pub op: usize,
    /// The list entry it came from.
    pub entry: usize,
}

impl Sample {
    fn lo(&self) -> i64 {
        self.off - self.u as i64
    }
    fn hi(&self) -> i64 {
        self.off + self.u as i64
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quorum {
    /// The entries of the winning subset (`n` of them), and the final interval as an offset
    /// from the uptime and U.
    Agreed { members: [usize; MAX_SOURCES], n: usize, off: i64, u: u64 },
    /// Fewer than two operators measured.
    TooFew,
    /// No two operators agree.
    NoAgreement,
    /// Several different largest agreeing subsets.
    Ambiguous,
}

/// Whether the intervals of the samples in `set` (bits), widened by the tolerance, meet.
fn agree(s: &[Sample], set: u32) -> bool {
    let mut lo = i64::MIN;
    let mut hi = i64::MAX;
    for (i, x) in s.iter().enumerate() {
        if set & (1 << i) != 0 {
            lo = lo.max(x.lo() - TOLERANCE_MS);
            hi = hi.min(x.hi() + TOLERANCE_MS);
        }
    }
    lo <= hi
}

/// The quorum of the samples (in the list's order) – see the file comment.
pub fn quorum(samples: &[Sample]) -> Quorum {
    // One vote per operator: the first sample of each.
    let mut votes = [Sample { off: 0, u: 0, op: 0, entry: 0 }; MAX_SOURCES];
    let mut n = 0;
    for s in samples {
        if n < MAX_SOURCES && !votes[..n].iter().any(|v| v.op == s.op) {
            votes[n] = *s;
            n += 1;
        }
    }
    if n < 2 {
        return Quorum::TooFew;
    }
    let v = &votes[..n];
    let mut best_size = 0u32;
    let mut best_set = 0u32;
    let mut ties = 0;
    for set in 1u32..(1 << n) {
        let size = set.count_ones();
        if size < 2 || size < best_size || !agree(v, set) {
            continue;
        }
        if size > best_size {
            best_size = size;
            best_set = set;
            ties = 1;
        } else {
            ties += 1;
        }
    }
    if best_size == 0 {
        return Quorum::NoAgreement;
    }
    if ties > 1 {
        return Quorum::Ambiguous;
    }
    let (off, u) = envelope(v, best_set);
    let mut members = [0usize; MAX_SOURCES];
    let mut k = 0;
    for (i, x) in v.iter().enumerate() {
        if best_set & (1 << i) != 0 {
            members[k] = x.entry;
            k += 1;
        }
    }
    Quorum::Agreed { members, n: k, off, u }
}

/// The envelope of the members' own intervals: (middle, half width rounded up).
pub fn envelope(s: &[Sample], set: u32) -> (i64, u64) {
    let mut lo = i64::MAX;
    let mut hi = i64::MIN;
    for (i, x) in s.iter().enumerate() {
        if set & (1 << i) != 0 {
            lo = lo.min(x.lo());
            hi = hi.max(x.hi());
        }
    }
    let mid = lo + (hi - lo) / 2;
    (mid, (hi - mid) as u64)
}

/// [T - U, T + U] in whole seconds for the certificate check, widened outwards (the
/// stricter way): notBefore <= floor((T - U) / 1000), notAfter >= ceil((T + U) / 1000).
pub fn cert_span(t_ms: i64, u_ms: u64) -> (i64, i64) {
    let lo = t_ms - u_ms as i64;
    let hi = t_ms + u_ms as i64;
    (lo.div_euclid(1000), hi.div_euclid(1000) + if hi.rem_euclid(1000) != 0 { 1 } else { 0 })
}

/// The NTS-KE backoff of one server: after a failure the next attempt waits 10 s, then
/// 15 s, 22.5 s, ... at most 5 days; only an NTS-KE followed by a good NTS answer resets it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    /// Uptime (ms) from which the next attempt may start (0 = now).
    pub next: u64,
    pub delay: u64,
}

impl Backoff {
    pub const fn new() -> Backoff {
        Backoff { next: 0, delay: KE_FIRST_MS }
    }
    pub fn due(&self, now: u64) -> bool {
        now >= self.next
    }
    pub fn failed(&mut self, now: u64) {
        self.next = now + self.delay;
        self.delay = (self.delay * 3 / 2).min(KE_MAX_MS);
    }
    pub fn succeeded(&mut self) {
        *self = Backoff::new();
    }
}
