// NTP (RFC 5905; the client side of SNTP, RFC 4330) without any input or output: the
// query, the checks on an answer, the arithmetic.  /bin/nettime uses it over a UDP socket
// of netd; NTS will reuse the header, the arithmetic and the era rule and add the
// extension fields (an answer longer than 48 bytes is accepted here, its extensions not
// read).
//
// Plain NTP is not authenticated: nothing computed here may set a clock or raise a lower
// bound for one – it is information only.
//
// Order of the checks on an answer (`check_reply`):
//   1. length >= 48, mode 4 (server), version 3 or 4, Origin == the Transmit value of
//      our query (64 random bits: an answer to another query, an old one or a forged one
//      fails here);
//   2. stratum 0 = Kiss-o'-Death – its own branch: the Receive and Transmit fields of a
//      KoD are undefined and not looked at.  DENY / RSTR / RATE are told apart, any other
//      code is refused;
//   3. an ordinary answer: LI != 3 (server not synchronized), stratum 1-15, Receive and
//      Transmit != 0, Transmit not before Receive, root delay (signed 16.16) >= 0 and
//      < 16 s, root dispersion (unsigned 16.16) < 16 s, and
//      root_distance_proxy = root delay / 2 + root dispersion <= 1.5 s.  The 1.5 s is
//      DeSoOS's own limit: RFC 5905's MAXDIST (1 s) is for the full root distance with
//      peer delay, dispersion and jitter, which one query does not have.
#![allow(dead_code)]

/// An NTP packet without extension fields.
pub const PACKET: usize = 48;
/// The NTP port.
pub const PORT: u16 = 123;
/// Seconds from 1900-01-01 (NTP) to 1970-01-01 (Unix).
const NTP_UNIX: i64 = 2_208_988_800;
/// root_distance_proxy above this is refused (16.16 fixed point: 1.5 s).
const DISTANCE_MAX: u64 = 3 << 15;
/// Root delay / dispersion of 16 s and more is refused (16.16 fixed point).
const ROOT_MAX: u32 = 16 << 16;
/// A round trip longer than this is refused.
pub const DELAY_MAX_MS: u64 = 10_000;

/// Why an answer was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    Short,
    Mode,
    Version,
    Origin,
    KodUnknown,
    Unsynchronized,
    Stratum,
    ZeroTimestamp,
    Backwards,
    RootDelay,
    RootDispersion,
    Distance,
    Delay,
}

impl Reject {
    pub fn as_str(self) -> &'static str {
        match self {
            Reject::Short => "shorter than 48 bytes",
            Reject::Mode => "not a server answer (mode)",
            Reject::Version => "NTP version not 3 or 4",
            Reject::Origin => "origin does not match the query",
            Reject::KodUnknown => "stratum 0 with an unknown kiss code",
            Reject::Unsynchronized => "server not synchronized (leap 3)",
            Reject::Stratum => "stratum out of 1-15",
            Reject::ZeroTimestamp => "receive or transmit time is zero",
            Reject::Backwards => "transmit time before receive time",
            Reject::RootDelay => "root delay negative or 16 s and more",
            Reject::RootDispersion => "root dispersion 16 s and more",
            Reject::Distance => "root distance above 1.5 s",
            Reject::Delay => "round trip negative or above 10 s",
        }
    }
}

/// Kiss-o'-Death codes that mean something to a client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kod {
    /// Access denied: stop asking this server.
    Deny,
    /// Access restricted: stop asking this server.
    Rstr,
    /// Asking too often: slow down (a one-shot tool stops asking).
    Rate,
}

impl Kod {
    pub fn as_str(self) -> &'static str {
        match self {
            Kod::Deny => "DENY - the server refuses this client",
            Kod::Rstr => "RSTR - the server restricts this client",
            Kod::Rate => "RATE - the server asks to slow down",
        }
    }
}

/// The fields of an accepted answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub stratum: u8,
    /// NTP 32.32 timestamps as sent: when the server received our query (T2) and sent
    /// its answer (T3).
    pub receive: u64,
    pub transmit: u64,
    /// 16.16 fixed point, seconds.
    pub root_delay: u32,
    pub root_dispersion: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    Time(Reply),
    Kod(Kod),
}

/// The query: LI 0, version 4, mode 3 (client), poll 0, precision 0x20, Transmit =
/// `xmit`, everything else zero (data minimization: nothing about this machine or its
/// clock).  `xmit` must be 64 fresh random bits – it is the one-time identifier the
/// answer has to bring back in its Origin field.
pub fn build_query(xmit: u64) -> [u8; PACKET] {
    let mut p = [0u8; PACKET];
    p[0] = 4 << 3 | 3;
    p[3] = 0x20;
    p[40..48].copy_from_slice(&xmit.to_be_bytes());
    p
}

fn be32(d: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]])
}

fn be64(d: &[u8], at: usize) -> u64 {
    ((be32(d, at) as u64) << 32) | be32(d, at + 4) as u64
}

/// Checks an answer to the query that carried `xmit` (the order is in the file comment).
pub fn check_reply(data: &[u8], xmit: u64) -> Result<Answer, Reject> {
    if data.len() < PACKET {
        return Err(Reject::Short);
    }
    if data[0] & 7 != 4 {
        return Err(Reject::Mode);
    }
    let version = data[0] >> 3 & 7;
    if version != 3 && version != 4 {
        return Err(Reject::Version);
    }
    if be64(data, 24) != xmit {
        return Err(Reject::Origin);
    }
    let stratum = data[1];
    if stratum == 0 {
        return match &data[12..16] {
            b"DENY" => Ok(Answer::Kod(Kod::Deny)),
            b"RSTR" => Ok(Answer::Kod(Kod::Rstr)),
            b"RATE" => Ok(Answer::Kod(Kod::Rate)),
            _ => Err(Reject::KodUnknown),
        };
    }
    if data[0] >> 6 == 3 {
        return Err(Reject::Unsynchronized);
    }
    if stratum > 15 {
        return Err(Reject::Stratum);
    }
    let receive = be64(data, 32);
    let transmit = be64(data, 40);
    if receive == 0 || transmit == 0 {
        return Err(Reject::ZeroTimestamp);
    }
    // Across an era change the 64-bit value wraps: the difference decides.
    if (transmit.wrapping_sub(receive) as i64) < 0 {
        return Err(Reject::Backwards);
    }
    let root_delay = be32(data, 4);
    let root_dispersion = be32(data, 8);
    // Signed 16.16: the top bit set is a negative delay.
    if root_delay >= ROOT_MAX {
        return Err(Reject::RootDelay);
    }
    if root_dispersion >= ROOT_MAX {
        return Err(Reject::RootDispersion);
    }
    if root_delay as u64 / 2 + root_dispersion as u64 > DISTANCE_MAX {
        return Err(Reject::Distance);
    }
    Ok(Answer::Time(Reply { stratum, receive, transmit, root_delay, root_dispersion }))
}

/// A 32.32 span in milliseconds (rounded down).
fn span_ms(span: u64) -> u64 {
    ((span as u128 * 1000) >> 32) as u64
}

/// The round trip without the server's own time: delay = (T4 - T1) - (T3 - T2), in ms.
/// `sent_ms` / `received_ms` are from this machine's monotonic clock (1 ms steps, so a
/// result of -1 ms counts as 0).  Negative beyond that or above 10 s: refused.
pub fn delay_ms(r: &Reply, sent_ms: u64, received_ms: u64) -> Result<u64, Reject> {
    let Some(trip) = received_ms.checked_sub(sent_ms) else { return Err(Reject::Delay) };
    let server = span_ms(r.transmit.wrapping_sub(r.receive));
    if server > trip + 1 {
        return Err(Reject::Delay);
    }
    let d = trip.saturating_sub(server);
    if d > DELAY_MAX_MS {
        return Err(Reject::Delay);
    }
    Ok(d)
}

/// An NTP timestamp as Unix milliseconds.  The 32-bit seconds wrap every 2^32 s (the
/// first time on 2036-02-07): the era is the one that puts the result nearest to
/// `pivot_unix` (the build date).  Right only within 2^31 s (about 68 years) of the pivot
/// – beyond that the same bits mean a date 136 years away and nothing in the packet can
/// tell.
pub fn unix_ms(ts: u64, pivot_unix: u64) -> i64 {
    let secs = (ts >> 32) as i64 - NTP_UNIX;
    let era = (pivot_unix as i64 - secs + (1 << 31)).div_euclid(1 << 32);
    let secs = secs + (era << 32);
    secs * 1000 + (((ts & 0xFFFF_FFFF) * 1000) >> 32) as i64
}

/// The server's time (Unix ms) at the moment its answer arrived: T3 + delay / 2.  An
/// estimate: it assumes the way there and the way back take equally long; when they do
/// not, the error is at most delay / 2 (the path asymmetry bound).  The server's own
/// error is not known.
pub fn server_time_ms(r: &Reply, delay_ms: u64, pivot_unix: u64) -> i64 {
    unix_ms(r.transmit, pivot_unix) + (delay_ms / 2) as i64
}

/// Milliseconds as whole seconds, half a second rounded away from zero – the same for
/// both signs (+1500 ms -> +2 s, -1500 ms -> -2 s).
pub fn round_secs(ms: i64) -> i64 {
    let s = (ms.unsigned_abs() + 500) / 1000;
    if ms < 0 { -(s as i64) } else { s as i64 }
}

/// What the clock is compared with in the summary.
#[derive(Clone, Copy)]
pub enum Against<'a> {
    /// One server, by the name it was asked as.
    Server(&'a str),
    /// The median of this many servers.
    Median(usize),
}

/// The summary's verdict for a difference "clock minus network time" given in
/// milliseconds (not rounded before): `round_secs` decides – |ms| < 500 is
/// "agrees to the second with ...", exactly 500 ms and more is "is about N s ahead of
/// ..." / "is about N s behind ...".  /bin/nettime prints this and nothing else for it.
pub struct OffsetText<'a> {
    pub ms: i64,
    pub against: Against<'a>,
}

impl core::fmt::Display for OffsetText<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let secs = round_secs(self.ms);
        if secs == 0 {
            f.write_str("agrees to the second with ")?;
        } else if secs > 0 {
            write!(f, "is about {} s ahead of ", secs)?;
        } else {
            write!(f, "is about {} s behind ", -secs)?;
        }
        match self.against {
            Against::Server(name) => f.write_str(name),
            Against::Median(n) => write!(f, "the median of {} servers", n),
        }
    }
}

/// The median of `v` (sorted in place; the lower middle for an even count; 0 for none).
pub fn median(v: &mut [i64]) -> i64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    v[(v.len() - 1) / 2]
}

/// How many of the offsets lie within `limit` of `center`.
pub fn agreeing(v: &[i64], center: i64, limit: i64) -> usize {
    v.iter().filter(|&&x| (x - center).abs() <= limit).count()
}

/// Servers "do not agree" when at least three answered and fewer than half of them are
/// within the limit of the median.  Two answers cannot settle a majority.
pub fn disagree(answers: usize, agreeing: usize) -> bool {
    answers >= 3 && agreeing * 2 < answers
}
