// synctest – NTS TEST's program for the time service's arithmetic without a network
// (user/lib/timesync.rs) and the kept certificate chain (common/desotls/chain.rs):
//   - one measurement as an interval: delta, T = T3 + delta / 2, U = ceil(delta / 2) +
//     ceil(root delay / 2) + ceil(root dispersion) + 1 s; refusals (negative delta, > 10 s,
//     answer before the query) before anything is computed;
//   - the quorum: one server, two that agree / do not, three with one off, a tie (A~B, B~C,
//     A!~C), two servers 1.8 s apart (U >= 0.9 s + their own), two entries of one operator,
//     the envelope (not the intersection);
//   - the NTS-KE backoff: 10 / 15 / 22.5 s, at most 5 days, reset;
//   - the span for the second check (outwards to whole seconds);
//   - PeerChain: kept bytes, more than 24 KiB or 8 certificates refused, moving wipes.
// "synctest: N checks OK".
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;
#[path = "../../common/desotls/mod.rs"]
mod desotls;
#[path = "../lib/ntp.rs"]
mod ntp;
#[path = "../lib/timesync.rs"]
mod timesync;

use desoos::*;
use desotls::chain::{self, PeerChain};
use timesync::{Backoff, Quorum, Sample};

entry!(main);

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("synctest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

static mut A: PeerChain = PeerChain::new();
static mut B: PeerChain = PeerChain::new();
static mut BIG: [u8; chain::MAX_BYTES + 1] = [0; chain::MAX_BYTES + 1];

/// A reply received at NTP time `t2` and sent at `t3` (32.32), root delay / dispersion 16.16.
fn reply(t2: u64, t3: u64, rd: u32, disp: u32) -> ntp::Reply {
    ntp::Reply { stratum: 2, receive: t2, transmit: t3, root_delay: rd, root_dispersion: disp }
}

/// Unix ms -> NTP 32.32.
fn ts(unix_ms: u64) -> u64 {
    let secs = unix_ms / 1000 + 2_208_988_800;
    let frac = (((unix_ms % 1000) << 32) + 999) / 1000;
    secs << 32 | frac
}

fn s(off: i64, u: u64, op: usize, entry: usize) -> Sample {
    Sample { off, u, op, entry }
}

fn main(_: Args) -> i32 {
    let mut n = 0;
    let pivot = 1_767_225_600; // 2026-01-01
    let base = 1_767_225_600_000u64 + 12_000; // a moment in 2026, ms (whole seconds: the 32.32 fractions stay exact enough)

    // --- one measurement ---
    // Sent at uptime 1000, back at 1100 (100 ms), the server held it 20 ms: delta 80.
    let r = reply(ts(base), ts(base + 20), 0, 0);
    let m = timesync::measure(&r, 1000, 1100, pivot);
    check!(n, m == Ok(((base + 20 + 40) as i64, 40 + 1000)), "delta 80, no root: {:?}", m);
    // Root delay 0.5 s (32768/65536), root dispersion 0.25 s: + ceil(250) + ceil(250).
    let r = reply(ts(base), ts(base + 20), 32_768, 16_384);
    check!(n, timesync::measure(&r, 1000, 1100, pivot) == Ok(((base + 60) as i64, 40 + 250 + 250 + 1000)), "root delay and dispersion");
    // Rounded up: root delay of 1/65536 s -> ceil(0.0076 ms) = 1; dispersion 1/65536 -> 1.
    let r = reply(ts(base), ts(base), 1, 1);
    check!(n, timesync::measure(&r, 1000, 1001, pivot) == Ok(((base) as i64, 1 + 1 + 1 + 1000)), "rounding up: {:?}", timesync::measure(&r, 1000, 1001, pivot));
    // Odd delta: T = T3 + floor(delta / 2), U has ceil(delta / 2).
    let r = reply(ts(base), ts(base), 0, 0);
    check!(n, timesync::measure(&r, 0, 81, pivot) == Ok(((base + 40) as i64, 41 + 1000)), "odd delta");
    // The server held it 2 ms longer than the round trip (beyond the 1 ms step) -> refused.
    let r = reply(ts(base), ts(base + 102), 0, 0);
    check!(n, timesync::measure(&r, 1000, 1100, pivot).is_err(), "negative delta refused");
    // -1 ms counts as 0.
    let r = reply(ts(base), ts(base + 101), 0, 0);
    check!(n, timesync::measure(&r, 1000, 1100, pivot) == Ok(((base + 101) as i64, 1000)), "delta -1 ms = 0");
    // Above 10 s.
    let r = reply(ts(base), ts(base), 0, 0);
    check!(n, timesync::measure(&r, 0, 10_001, pivot).is_err(), "delta > 10 s refused");
    check!(n, timesync::measure(&r, 0, 10_000, pivot).is_ok(), "delta = 10 s taken");
    // The answer before the query.
    check!(n, timesync::measure(&r, 500, 400, pivot).is_err(), "T4 < T1 refused");
    check!(n, timesync::fixed_ms_up(65_536) == 1000 && timesync::fixed_ms_up(65_537) == 1001 && timesync::fixed_ms_up(0) == 0, "16.16 -> ms up");

    // --- the quorum ---
    let u = 1016;
    check!(n, timesync::quorum(&[s(0, u, 0, 0)]) == Quorum::TooFew, "one server: nothing");
    check!(n, timesync::quorum(&[]) == Quorum::TooFew, "none: nothing");
    match timesync::quorum(&[s(0, u, 0, 0), s(400, u, 1, 1)]) {
        Quorum::Agreed { members, n: k, off, u: uu } => {
            check!(n, k == 2 && members[..2] == [0, 1], "two agree: members {:?}", &members[..k]);
            check!(n, off == 200 && uu == 1216, "two agree: envelope {} +-{}", off, uu);
        }
        q => {
            check!(n, false, "two agreeing: {:?}", q);
        }
    }
    check!(n, timesync::quorum(&[s(0, u, 0, 0), s(30_000, u, 1, 1)]) == Quorum::NoAgreement, "two that disagree: nothing");
    // The edge of the tolerance: 2 * (U + 1 s) apart still agrees, 1 ms more does not.
    let edge = 2 * (u as i64 + timesync::TOLERANCE_MS);
    check!(n, matches!(timesync::quorum(&[s(0, u, 0, 0), s(edge, u, 1, 1)]), Quorum::Agreed { .. }), "at the tolerance edge: agree");
    check!(n, timesync::quorum(&[s(0, u, 0, 0), s(edge + 1, u, 1, 1)]) == Quorum::NoAgreement, "1 ms past the edge: no");
    match timesync::quorum(&[s(0, u, 0, 0), s(400, u, 1, 1), s(30_000, u, 2, 2)]) {
        Quorum::Agreed { members, n: k, .. } => {
            check!(n, k == 2 && members[..2] == [0, 1], "three, one off: the two");
        }
        q => {
            check!(n, false, "three with one off: {:?}", q);
        }
    }
    match timesync::quorum(&[s(0, u, 0, 0), s(400, u, 1, 1), s(800, u, 2, 2)]) {
        Quorum::Agreed { n: k, off, u: uu, .. } => {
            check!(n, k == 3 && off == 400 && uu == 1416, "three agree: {} {} +-{}", k, off, uu);
        }
        q => {
            check!(n, false, "three agreeing: {:?}", q);
        }
    }
    // A~B, B~C, A!~C: two largest groups – ambiguous.
    check!(n, timesync::quorum(&[s(0, u, 0, 0), s(3000, u, 1, 1), s(6000, u, 2, 2)]) == Quorum::Ambiguous, "tie: ambiguous");
    // Two servers 1.8 s apart: U at least 0.9 s plus their own.
    match timesync::quorum(&[s(0, u, 0, 0), s(1800, u, 1, 1)]) {
        Quorum::Agreed { off, u: uu, .. } => {
            check!(n, off == 900 && uu >= 900 + u && uu == 1916, "1.8 s apart: {} +-{}", off, uu);
        }
        q => {
            check!(n, false, "1.8 s apart: {:?}", q);
        }
    }
    // The envelope, not the intersection: a narrow and a wide interval -> as wide as the wide one.
    match timesync::quorum(&[s(0, 1000, 0, 0), s(0, 3000, 1, 1)]) {
        Quorum::Agreed { off, u: uu, .. } => {
            check!(n, off == 0 && uu == 3000, "envelope: {} +-{}", off, uu);
        }
        q => {
            check!(n, false, "envelope: {:?}", q);
        }
    }
    // One operator, two entries: one vote.
    check!(n, timesync::quorum(&[s(0, u, 0, 0), s(400, u, 0, 1)]) == Quorum::TooFew, "same operator: one vote");
    match timesync::quorum(&[s(0, u, 0, 0), s(400, u, 0, 1), s(200, u, 1, 2)]) {
        Quorum::Agreed { members, n: k, .. } => {
            check!(n, k == 2 && members[..2] == [0, 2], "same operator twice + another: the first of the operator and the other");
        }
        q => {
            check!(n, false, "same operator + another: {:?}", q);
        }
    }

    // --- the span for the second check ---
    check!(n, timesync::cert_span(1_000_500, 1000) == (999, 1002), "span outwards: {:?}", timesync::cert_span(1_000_500, 1000));
    check!(n, timesync::cert_span(1_000_000, 1000) == (999, 1001), "span on whole seconds");
    check!(n, timesync::cert_span(-1500, 0) == (-2, -1), "span below 0");

    // --- the backoff ---
    let mut b = Backoff::new();
    check!(n, b.due(0), "a new server: at once");
    b.failed(1000);
    check!(n, b.next == 11_000 && !b.due(10_999) && b.due(11_000), "first failure: 10 s");
    b.failed(11_000);
    check!(n, b.next == 26_000, "second: 15 s ({})", b.next);
    b.failed(26_000);
    check!(n, b.next == 48_500, "third: 22.5 s ({})", b.next);
    for _ in 0..100 {
        b.failed(0);
    }
    check!(n, b.delay == timesync::KE_MAX_MS && b.next == timesync::KE_MAX_MS, "at most 5 days");
    b.succeeded();
    check!(n, b == Backoff::new(), "reset after NTS-KE + a good answer");

    // --- the kept chain ---
    let a = unsafe { &mut *core::ptr::addr_of_mut!(A) };
    let bb = unsafe { &mut *core::ptr::addr_of_mut!(B) };
    let big = unsafe { &mut *core::ptr::addr_of_mut!(BIG) };
    check!(n, a.store(&[b"leaf", b"intermediate"]).is_ok() && a.count() == 2 && a.bytes() == 16, "kept");
    {
        let mut out: [&[u8]; chain::MAX_CERTS] = [&[]; chain::MAX_CERTS];
        let k = a.certs(&mut out);
        check!(n, k == 2 && out[0] == b"leaf" && out[1] == b"intermediate", "the same bytes, in order");
    }
    a.move_to(bb);
    {
        let mut out: [&[u8]; chain::MAX_CERTS] = [&[]; chain::MAX_CERTS];
        let k = bb.certs(&mut out);
        check!(n, k == 2 && out[1] == b"intermediate" && a.wiped(), "moved: the copy the same, the source wiped");
    }
    big.fill(7);
    check!(n, a.store(&[&big[..chain::MAX_BYTES]]).is_ok(), "exactly 24 KiB kept");
    check!(n, a.store(&[&big[..chain::MAX_BYTES + 1]]).is_err() && a.wiped(), "24 KiB + 1 refused, nothing kept");
    check!(n, a.store(&[&big[..12_288], &big[..12_289]]).is_err() && a.wiped() && a.store(&[&big[..12_288], &big[..12_288]]).is_ok(), "two certificates over 24 KiB refused, exactly 24 KiB kept");
    let nine: [&[u8]; 9] = [b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"8", b"9"];
    check!(n, a.store(&nine).is_err() && a.store(&nine[..8]).is_ok(), "9 certificates refused, 8 kept");
    check!(n, a.store(&[]).is_err(), "an empty chain refused");
    bb.clear();
    check!(n, bb.wiped(), "cleared");

    println!("synctest: {} checks OK (measurement interval, quorum and envelope, tie, operators, backoff 10/15/22.5 s, certificate span, kept chain)", n);
    0
}
