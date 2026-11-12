// NTP TEST's program (kernel/user/test_ntp.rs).
//
// `ntptest` – the library user/lib/ntp.rs without a network: the query's bytes, every
// refusal of an answer and the order of the checks (a Kiss-o'-Death is recognised before
// the timestamp checks and only with the right Origin), the delay, the NTP era (the
// 2036 wrap, the edges of the +-68 years around the build date), the median.
// "ntptest: N checks OK".
//
// `ntptest net` (started by init with the services) – /bin/nettime against
// tests/ntp-stub.py on the host (10.0.2.2:58123-58153, the name ntp.desoos from
// tests/dns-stub.py): a correct answer, forged and late ones, Kiss-o'-Death, silence and
// the one retry, every malformed answer, two to four servers, the arguments, the udp
// right, how many packets went out and what was in them – and at the end the clock's
// verdict is what it was (the kernel side of the test compares the hardware RTC with the
// clock before and after).  "ntptest net: N cases OK".
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../lib/ntp.rs"]
mod ntp;

use desoos::*;
use ntp::{Answer, Kod, Reject};

entry!(main);

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("ntptest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

const NTP_UNIX: u64 = 2_208_988_800;
const XMIT: u64 = 0x0123_4567_89AB_CDEF;

/// A correct server answer to the query with `xmit`: stratum 2, received at NTP second
/// `secs`, sent 1/4 s later.
fn reply(xmit: u64, secs: u32) -> [u8; 48] {
    let mut p = [0u8; 48];
    p[0] = 4 << 3 | 4;
    p[1] = 2;
    p[3] = 0xEC;
    p[4..8].copy_from_slice(&0x0000_0290u32.to_be_bytes());
    p[8..12].copy_from_slice(&0x0000_0290u32.to_be_bytes());
    p[12..16].copy_from_slice(b"TEST");
    p[24..32].copy_from_slice(&xmit.to_be_bytes());
    p[32..36].copy_from_slice(&secs.to_be_bytes());
    p[40..44].copy_from_slice(&secs.to_be_bytes());
    p[44..48].copy_from_slice(&0x4000_0000u32.to_be_bytes());
    p
}

fn with(mut p: [u8; 48], at: usize, bytes: &[u8]) -> [u8; 48] {
    p[at..at + bytes.len()].copy_from_slice(bytes);
    p
}

fn library() -> i32 {
    let mut n = 0;
    let now32 = 3_970_000_000u32; // 2025-10
    let good = reply(XMIT, now32);

    // The query.
    let q = ntp::build_query(XMIT);
    check!(n, q.len() == 48 && q[0] == 0x23 && q[1] == 0 && q[2] == 0 && q[3] == 0x20, "query header {:02x?}", &q[..4]);
    check!(n, q[4..40].iter().all(|&b| b == 0) && q[40..48] == XMIT.to_be_bytes(), "query: zeros and the Transmit value");

    // A correct answer.
    let r = ntp::check_reply(&good, XMIT);
    check!(n, matches!(r, Ok(Answer::Time(t)) if t.stratum == 2 && t.receive == (now32 as u64) << 32 && t.transmit == (now32 as u64) << 32 | 0x4000_0000 && t.root_delay == 0x290), "a correct answer: {:?}", r);
    check!(n, matches!(ntp::check_reply(&with(good, 0, &[3 << 3 | 4]), XMIT), Ok(Answer::Time(_))), "version 3 is accepted");
    let mut long = [0u8; 112];
    long[..48].copy_from_slice(&good);
    long[48..52].copy_from_slice(&[0x01, 0x04, 0x00, 0x40]);
    check!(n, matches!(ntp::check_reply(&long, XMIT), Ok(Answer::Time(_))), "an answer with extension fields is accepted");

    // Step 1: length, mode, version, Origin.
    for (len, what) in [(47, "47 bytes"), (0, "empty"), (12, "12 bytes")] {
        check!(n, ntp::check_reply(&good[..len], XMIT) == Err(Reject::Short), "{}", what);
    }
    for mode in [0u8, 1, 2, 3, 5, 6, 7] {
        check!(n, ntp::check_reply(&with(good, 0, &[4 << 3 | mode]), XMIT) == Err(Reject::Mode), "mode {}", mode);
    }
    for v in [0u8, 1, 2, 5, 6, 7] {
        check!(n, ntp::check_reply(&with(good, 0, &[v << 3 | 4]), XMIT) == Err(Reject::Version), "version {}", v);
    }
    check!(n, ntp::check_reply(&good, XMIT + 1) == Err(Reject::Origin), "an answer to another query");
    check!(n, ntp::check_reply(&good, XMIT ^ 1 << 63) == Err(Reject::Origin), "Origin differs in the top bit");
    check!(n, ntp::check_reply(&with(good, 24, &[0; 8]), XMIT) == Err(Reject::Origin), "Origin zero");
    // The query echoed back (mode 3) fails on the mode, whatever else it holds.
    check!(n, ntp::check_reply(&q, XMIT) == Err(Reject::Mode), "the query echoed");

    // Step 2: Kiss-o'-Death – before LI, stratum range and the timestamps.
    let kod = |code: &[u8; 4], rx: [u8; 8], tx: [u8; 8]| with(with(with(with(good, 0, &[3 << 6 | 4 << 3 | 4]), 1, &[0]), 12, code), 32, &[rx, tx].concat_bytes());
    for (code, want) in [(b"RATE", Kod::Rate), (b"DENY", Kod::Deny), (b"RSTR", Kod::Rstr)] {
        check!(n, ntp::check_reply(&kod(code, [0; 8], [0; 8]), XMIT) == Ok(Answer::Kod(want)), "KoD {:?} with zero timestamps", core::str::from_utf8(code));
        check!(n, ntp::check_reply(&kod(code, [0xFF; 8], [1; 8]), XMIT) == Ok(Answer::Kod(want)), "KoD {:?} with garbage timestamps", core::str::from_utf8(code));
        check!(n, ntp::check_reply(&kod(code, [0; 8], [0; 8]), XMIT + 1) == Err(Reject::Origin), "KoD {:?} with a wrong Origin is a forgery", core::str::from_utf8(code));
    }
    for code in [b"XXXX", b"INIT", b"STEP", b"rate", b"\0\0\0\0"] {
        check!(n, ntp::check_reply(&kod(code, [0; 8], [0; 8]), XMIT) == Err(Reject::KodUnknown), "stratum 0 with code {:?}", code);
    }

    // Step 3: an ordinary answer.
    check!(n, ntp::check_reply(&with(good, 0, &[3 << 6 | 4 << 3 | 4]), XMIT) == Err(Reject::Unsynchronized), "LI 3");
    for li in [1u8, 2] {
        check!(n, matches!(ntp::check_reply(&with(good, 0, &[li << 6 | 4 << 3 | 4]), XMIT), Ok(Answer::Time(_))), "LI {} (leap second warning) is accepted", li);
    }
    for s in [16u8, 17, 255] {
        check!(n, ntp::check_reply(&with(good, 1, &[s]), XMIT) == Err(Reject::Stratum), "stratum {}", s);
    }
    for s in [1u8, 15] {
        check!(n, matches!(ntp::check_reply(&with(good, 1, &[s]), XMIT), Ok(Answer::Time(t)) if t.stratum == s), "stratum {} is accepted", s);
    }
    check!(n, ntp::check_reply(&with(good, 32, &[0; 8]), XMIT) == Err(Reject::ZeroTimestamp), "Receive zero");
    check!(n, ntp::check_reply(&with(good, 40, &[0; 8]), XMIT) == Err(Reject::ZeroTimestamp), "Transmit zero");
    check!(n, ntp::check_reply(&with(good, 40, &(now32 - 1).to_be_bytes()), XMIT) == Err(Reject::Backwards), "Transmit before Receive");
    // Across the era change: received at the last second of era 0, sent in era 1.
    let wrap = with(with(good, 32, &[0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]), 40, &[0, 0, 0, 0, 0x40, 0, 0, 0]);
    check!(n, matches!(ntp::check_reply(&wrap, XMIT), Ok(Answer::Time(_))), "Receive in era 0, Transmit in era 1");
    for (delay, why) in [(0x8000_0000u32, "negative (most negative)"), (0xFFFF_8000, "-0.5 s"), (16 << 16, "16 s"), (0x7FFF_FFFF, "32767 s")] {
        check!(n, ntp::check_reply(&with(good, 4, &delay.to_be_bytes()), XMIT) == Err(Reject::RootDelay), "root delay {}", why);
    }
    for disp in [16u32 << 16, 0xFFFF_FFFF] {
        check!(n, ntp::check_reply(&with(good, 8, &disp.to_be_bytes()), XMIT) == Err(Reject::RootDispersion), "root dispersion {:#x}", disp);
    }
    // root_distance_proxy = delay / 2 + dispersion against 1.5 s (0x18000 in 16.16).
    let dist = |delay: u32, disp: u32| ntp::check_reply(&with(with(good, 4, &delay.to_be_bytes()), 8, &disp.to_be_bytes()), XMIT);
    check!(n, dist(0x3333, 0x1_8000) == Err(Reject::Distance), "distance 1.6 s");
    check!(n, matches!(dist(0x3333, 0x1_4CCC), Ok(Answer::Time(_))), "distance 1.4 s");
    check!(n, matches!(dist(0x2_0000, 0x8000), Ok(Answer::Time(_))), "distance exactly 1.5 s");
    check!(n, dist(0x2_0000, 0x8001) == Err(Reject::Distance), "distance just above 1.5 s");
    check!(n, dist(15 << 16, 0) == Err(Reject::Distance), "root delay 15 s alone");

    // The delay: (T4 - T1) - (T3 - T2); the answer above took the server 250 ms.
    let Ok(Answer::Time(t)) = ntp::check_reply(&good, XMIT) else { return 1 };
    check!(n, ntp::delay_ms(&t, 1000, 1290) == Ok(40), "delay 290 - 250: {:?}", ntp::delay_ms(&t, 1000, 1290));
    check!(n, ntp::delay_ms(&t, 1000, 1250) == Ok(0), "delay 0");
    check!(n, ntp::delay_ms(&t, 1000, 1249) == Ok(0), "delay -1 ms is the clock's step: 0");
    check!(n, ntp::delay_ms(&t, 1000, 1248) == Err(Reject::Delay), "delay -2 ms");
    check!(n, ntp::delay_ms(&t, 1000, 999) == Err(Reject::Delay), "received before sent");
    check!(n, ntp::delay_ms(&t, 1000, 11_250) == Ok(10_000), "delay 10 s");
    check!(n, ntp::delay_ms(&t, 1000, 11_251) == Err(Reject::Delay), "delay above 10 s");

    // The era: nearest to the pivot (the build date).
    let Ok(clock) = time_unix() else { return 1 };
    let pivot = clock.build_epoch;
    let ts = |unix: u64| ((unix + NTP_UNIX) & 0xFFFF_FFFF) << 32;
    check!(n, pivot > 1_700_000_000 && pivot < 4_000_000_000, "the build date {}", pivot);
    check!(n, ntp::unix_ms(NTP_UNIX << 32, pivot) == 0, "1970-01-01: {}", ntp::unix_ms(NTP_UNIX << 32, pivot));
    check!(n, ntp::unix_ms(ts(pivot), pivot) == pivot as i64 * 1000, "the build date itself");
    check!(n, ntp::unix_ms(0, pivot) == 2_085_978_496_000, "NTP second 0 is 2036-02-07 06:28:16: {}", ntp::unix_ms(0, pivot));
    check!(n, ntp::unix_ms(100 << 32 | 0x8000_0000, pivot) == 2_085_978_596_500, "era 1, second 100.5: {}", ntp::unix_ms(100 << 32 | 0x8000_0000, pivot));
    check!(n, ntp::unix_ms(0xFFFF_FFFF << 32 | 0xFFFF_FFFF, pivot) == 2_085_978_495_999, "the last instant of era 0: {}", ntp::unix_ms(0xFFFF_FFFF << 32 | 0xFFFF_FFFF, pivot));
    let edge = (1u64 << 31) - 86_400;
    check!(n, ntp::unix_ms(ts(pivot + edge), pivot) == (pivot + edge) as i64 * 1000, "build + 68 years - 1 day");
    check!(n, ntp::unix_ms(ts(pivot - edge), pivot) == (pivot - edge) as i64 * 1000, "build - 68 years + 1 day");
    // Outside the range the same bits mean a date 2^32 s away – the documented limit.
    let far = pivot + (1 << 31) + 86_400;
    check!(n, ntp::unix_ms(ts(far), pivot) == (far as i64 - (1 << 32)) * 1000, "beyond +68 years the result is 136 years early");
    // The 2040 answer of the stub's server 14.
    check!(n, ntp::unix_ms(ts(2_222_164_800), pivot) == 2_222_164_800_000, "2040-06-01 12:00:00");
    let t2040 = ntp::Reply { stratum: 2, receive: ts(2_222_164_800), transmit: ts(2_222_164_800), root_delay: 0, root_dispersion: 0 };
    check!(n, ntp::server_time_ms(&t2040, 31, pivot) == 2_222_164_800_015, "T3 + delay / 2");

    // Showing the results: dates before 1970 (the +-68 years reach back to ~1958), the
    // rounding of a difference to whole seconds (symmetric).
    let mut b = [0u8; 19];
    check!(n, format_utc_signed(-378_691_200, &mut b) == "1958-01-01 00:00:00", "1958-01-01: {:?}", format_utc_signed(-378_691_200, &mut b));
    check!(n, format_utc_signed(-1, &mut b) == "1969-12-31 23:59:59", "one second before 1970: {:?}", format_utc_signed(-1, &mut b));
    check!(n, format_utc_signed(-315_619_200 + 3661, &mut b) == "1960-01-01 01:01:01", "1960-01-01 01:01:01");
    check!(n, format_utc_signed(0, &mut b) == "1970-01-01 00:00:00" && format_utc_signed(2_222_164_800, &mut b) == "2040-06-01 12:00:00", "1970 and 2040");
    for (ms, want) in [(1500i64, 2i64), (-1500, -2), (1499, 1), (-1499, -1), (500, 1), (-500, -1), (499, 0), (-499, 0), (0, 0), (-3_600_400, -3600), (3_600_400, 3600)] {
        check!(n, ntp::round_secs(ms) == want, "round_secs({}) = {}, not {}", ms, ntp::round_secs(ms), want);
    }

    // The summary's words, from the difference in ms (the very text nettime prints).
    struct Line {
        b: [u8; 96],
        n: usize,
    }
    impl core::fmt::Write for Line {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let k = s.len().min(self.b.len() - self.n);
            self.b[self.n..self.n + k].copy_from_slice(&s.as_bytes()[..k]);
            self.n += k;
            Ok(())
        }
    }
    let words = |ms: i64, against: ntp::Against| {
        let mut l = Line { b: [0; 96], n: 0 };
        let _ = core::fmt::Write::write_fmt(&mut l, format_args!("{}", ntp::OffsetText { ms, against }));
        l
    };
    for (ms, want) in [
        (-1500i64, "is about 2 s behind X"),
        (1500, "is about 2 s ahead of X"),
        (-499, "agrees to the second with X"),
        (499, "agrees to the second with X"),
        (-500, "is about 1 s behind X"),
        (500, "is about 1 s ahead of X"),
        (0, "agrees to the second with X"),
        (-3_600_400, "is about 3600 s behind X"),
    ] {
        let l = words(ms, ntp::Against::Server("X"));
        let got = core::str::from_utf8(&l.b[..l.n]).unwrap_or("?");
        check!(n, got == want, "summary for {} ms: {:?}, not {:?}", ms, got, want);
    }
    let l = words(-1500, ntp::Against::Median(3));
    check!(n, &l.b[..l.n] == b"is about 2 s behind the median of 3 servers", "summary against the median: {:?}", core::str::from_utf8(&l.b[..l.n]));

    // The median and the agreement.
    check!(n, ntp::median(&mut []) == 0 && ntp::median(&mut [5]) == 5, "median of none and of one");
    check!(n, ntp::median(&mut [3_600_000, 0, 0]) == 0 && ntp::median(&mut [3_600_000, 0, 3_600_000]) == 3_600_000, "median of three");
    check!(n, ntp::median(&mut [20_000, 0, 10_000]) == 10_000 && ntp::median(&mut [30, 10, 40, 20]) == 20, "median: the middle; the lower middle of four");
    check!(n, ntp::median(&mut [-5, -7, 9]) == -5, "median with negative offsets");
    let verdict = |v: &mut [i64]| {
        let m = ntp::median(v);
        let a = ntp::agreeing(v, m, 2000);
        (a, ntp::disagree(v.len(), a))
    };
    check!(n, verdict(&mut [0, 0, 3_600_000]) == (2, false), "0, 0, +1 h: {:?}", verdict(&mut [0, 0, 3_600_000]));
    check!(n, verdict(&mut [0, 3_600_000, 3_600_000]) == (2, false), "0, +1 h, +1 h");
    check!(n, verdict(&mut [0, 10_000, 20_000]) == (1, true), "0, +10 s, +20 s");
    check!(n, verdict(&mut [0, 3_600_000]) == (1, false), "two answers an hour apart: no verdict");
    check!(n, verdict(&mut [0, 2000, 4000]) == (3, false), "exactly 2 s from the median agrees");
    check!(n, verdict(&mut [0, 10_000, 20_000, 30_000]) == (1, true) && verdict(&mut [0, 0, 10_000, 20_000]) == (2, false), "four answers");
    check!(n, verdict(&mut [7]) == (1, false), "one answer");

    println!("ntptest: {} checks OK (query bytes, the order of the checks with Kiss-o'-Death before the timestamps, delay, NTP era around the build date {}, dates before 1970, rounding, the summary's words, median)", n, pivot);
    0
}

trait Concat {
    fn concat_bytes(&self) -> [u8; 16];
}

impl Concat for [[u8; 8]; 2] {
    fn concat_bytes(&self) -> [u8; 16] {
        let mut o = [0u8; 16];
        o[..8].copy_from_slice(&self[0]);
        o[8..].copy_from_slice(&self[1]);
        o
    }
}

// ---- Against tests/ntp-stub.py ----

const BASE: u16 = 58123;
const OUT_FILE: &str = "/ntp.out";
/// How far (s) the clock may be from the host's time in a test run.
const NEAR: i64 = 20;

static mut OUT: [u8; 4096] = [0; 4096];
static mut REPLY: [u8; 4096] = [0; 4096];

macro_rules! case {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("ntptest net: FAIL case {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

fn ask(req: &str) -> &'static str {
    let Ok(c) = svc_connect("net0") else { return "" };
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(REPLY) };
    let mut info = RecvInfo::default();
    let r = if chan_send(c, req.as_bytes(), 0) == 0 { chan_recv(c, buf, 0, &mut info) } else { -1 };
    close(c);
    if r < 0 { "" } else { core::str::from_utf8(&buf[..r as usize]).unwrap_or("") }
}

/// What a run of nettime gave: exit code, stdout + stderr, how long it took.
struct Run {
    code: u64,
    out: &'static str,
    ms: u64,
}

fn run_via(svc: u64, args: &[&str]) -> Run {
    let mut argv: [&str; 12] = ["nettime"; 12];
    argv[1..1 + args.len()].copy_from_slice(args);
    let fd = open(OUT_FILE, O_WRITE | O_CREATE | O_TRUNC);
    if fd < 0 {
        return Run { code: 997, out: "", ms: 0 };
    }
    let t0 = uptime_ms();
    let pid = spawn_ex("/bin/nettime", &argv[..1 + args.len()], &[(fd as u64, 1), (fd as u64, 2), (svc, SVC)], 0);
    let code = if pid <= 0 { 999 } else { wait(pid as u64, 0).map(|(_, c)| c).unwrap_or(998) };
    let ms = uptime_ms() - t0;
    close(fd as u64);
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
    let fd = open(OUT_FILE, O_READ);
    let n = if fd >= 0 { read(fd as u64, buf).max(0) as usize } else { 0 };
    if fd >= 0 {
        close(fd as u64);
    }
    unlink(OUT_FILE);
    Run { code, out: core::str::from_utf8(&buf[..n]).unwrap_or(""), ms }
}

fn run(args: &[&str]) -> Run {
    run_via(SVC, args)
}

/// "10.0.2.2:<BASE + n>" for up to four servers, in static storage.
fn server(slot: usize, n: u16) -> &'static str {
    static mut NAMES: [[u8; 16]; 4] = [[0; 16]; 4];
    let b = unsafe { &mut (*core::ptr::addr_of_mut!(NAMES))[slot] };
    b[..9].copy_from_slice(b"10.0.2.2:");
    let port = BASE + n;
    for i in 0..5 {
        b[9 + i] = b'0' + (port / 10u16.pow(4 - i as u32) % 10) as u8;
    }
    core::str::from_utf8(&b[..14]).unwrap_or("")
}

/// The stub's counters (queries, bad, dup); `reset` zeroes them first.
fn stats(reset: bool) -> Option<(u64, u64, u64)> {
    let mut reply = [0u8; 256];
    let c = udp_open_via(SVC, "net0", "10.0.2.2", BASE + 30, &mut reply).ok()?;
    let mut got = None;
    let mut info = RecvInfo::default();
    for _ in 0..3 {
        if udp_send(c, if reset { b"reset" } else { b"stats" }) != 0 {
            break;
        }
        if wait_many(&[(c, W_READABLE)], 1000) == Ok(1) {
            let r = chan_recv(c, &mut reply, CHAN_NONBLOCK, &mut info);
            if r > 0 {
                let t = core::str::from_utf8(&reply[..r as usize]).unwrap_or("");
                let f = |k: &str| t.split(' ').find_map(|w| w.strip_prefix(k)).and_then(|v| v.parse::<u64>().ok());
                got = Some((f("queries=")?, f("bad=")?, f("dup=")?));
                break;
            }
        }
    }
    close(c);
    got
}

/// "... is about N s ahead of / behind ..." or "agrees to the second": the clock minus
/// network time in seconds; None when the summary line is not there.
fn rtc_offset(out: &str) -> Option<i64> {
    let line = out.lines().find(|l| l.starts_with("nettime: the clock ("))?;
    if line.contains("agrees to the second") {
        return Some(0);
    }
    let rest = line.split("is about ").nth(1)?;
    let secs = rest.split(' ').next()?.parse::<i64>().ok()?;
    if rest.contains(" s ahead of ") {
        Some(secs)
    } else if rest.contains(" s behind ") {
        Some(-secs)
    } else {
        None
    }
}

fn net() -> i32 {
    let mut n = 0;
    // init starts services right before this program – wait for net0's DHCP address.
    let t = uptime_ms();
    while !ask("status").lines().any(|l| l.starts_with("netd-status") && l.split_whitespace().any(|w| w == "dhcp=bound")) {
        if uptime_ms() - t > 10_000 {
            println!("ntptest net: FAIL: net0 has no DHCP address after 10 s");
            return 1;
        }
        sleep_ms(50);
    }
    let r = ask("dns 10.0.2.2:53530");
    case!(n, r.starts_with("DNS server 10.0.2.2:53530"), "dns set: {:?}", r.trim());
    let Ok(clock0) = time_unix() else { return 1 };
    let up0 = uptime_ms();
    case!(n, stats(true) == Some((0, 0, 0)), "the stub's counters after a reset: {:?}", stats(false));

    // A correct answer, by name.  QEMU's RTC is the host's clock and the stub answers with
    // the host's clock, but DeSoOS's clock is the RTC at boot plus uptime, and uptime runs
    // slow under TCG (seconds after a few minutes) – hence NEAR.
    let r = run(&["ntp.desoos:58123"]);
    case!(n, r.code == 0 && r.out.contains("nettime: ntp.desoos (10.0.2.2): stratum 2, delay ") && r.out.contains("not changed: plain NTP is not authenticated"), "a correct answer: {} {:?}", r.code, r.out);
    case!(n, matches!(rtc_offset(r.out), Some(o) if o.abs() <= NEAR), "the clock against the host's time: {:?} {:?}", rtc_offset(r.out), r.out);
    case!(n, r.out.contains("path asymmetry bound +-") && r.out.contains(" ntp.desoos (the clock counts whole seconds"), "the summary names the limits: {:?}", r.out);
    case!(n, stats(false) == Some((1, 0, 0)), "one minimal query for one answer: {:?}", stats(false));
    let r = run(&[server(0, 15)]);
    case!(n, r.code == 0 && rtc_offset(r.out).is_some(), "an answer with an extension field: {} {:?}", r.code, r.out);
    let r = run(&[server(0, 11)]);
    case!(n, r.code == 0 && rtc_offset(r.out).is_some(), "the answer sent twice: {} {:?}", r.code, r.out);
    let r = run(&[server(0, 24)]);
    case!(n, r.code == 0, "root distance 1.4 s: {} {:?}", r.code, r.out);

    // Forged and late answers.
    stats(true);
    let r = run(&["-t", "300", server(0, 9)]);
    case!(n, r.code == 3 && r.out.contains("answer(s) ignored (the last: origin does not match the query)") && r.out.contains("no answer (2 queries of 300 ms)"), "only forged answers: {} {:?}", r.code, r.out);
    case!(n, stats(false) == Some((2, 0, 0)), "forged answers: one retry, no more: {:?}", stats(false));
    stats(true);
    let r = run(&[server(0, 10)]);
    case!(n, r.code == 0 && r.out.contains("1 answer(s) ignored (the last: origin does not match the query)") && rtc_offset(r.out).is_some(), "a forged answer, then the real one: {} {:?}", r.code, r.out);
    case!(n, stats(false) == Some((1, 0, 0)), "a forged answer does not cause a retry: {:?}", stats(false));
    stats(true);
    let r = run(&["-t", "300", server(0, 13)]);
    case!(n, r.code == 0 && r.out.contains("1 answer(s) ignored (the last: origin does not match the query)"), "an answer to the first query after the retry: {} {:?}", r.code, r.out);
    case!(n, stats(false) == Some((2, 0, 0)), "the retry carries a new Transmit value: {:?}", stats(false));

    // Kiss-o'-Death: recognised, the server not asked again, no time from it.
    for (k, word) in [(5u16, "RATE"), (6, "DENY"), (7, "RSTR")] {
        stats(true);
        let r = run(&[server(0, k)]);
        case!(n, r.code == 3 && r.out.contains("kiss-o'-death") && r.out.contains(word) && r.out.contains("not asked again") && rtc_offset(r.out).is_none(), "KoD {}: {} {:?}", word, r.code, r.out);
        case!(n, stats(false) == Some((1, 0, 0)) && r.ms < 1900, "KoD {}: no retry, no waiting ({} ms): {:?}", word, r.ms, stats(false));
    }
    let r = run(&["-t", "200", server(0, 8)]);
    case!(n, r.code == 3 && r.out.contains("stratum 0 with an unknown kiss code"), "an unknown kiss code: {} {:?}", r.code, r.out);
    stats(true);
    let r = run(&["-t", "300", server(0, 12)]);
    case!(n, r.code == 0 && r.out.contains("1 answer(s) ignored (the last: origin does not match the query)") && !r.out.contains("kiss-o'-death"), "a forged DENY, then the real answer: {} {:?}", r.code, r.out);
    case!(n, stats(false) == Some((2, 0, 0)), "a forged DENY does not stop the questions: {:?}", stats(false));

    // Silence: one retry, then code 3 after 2 x -t.
    stats(true);
    let r = run(&["-t", "300", server(0, 4)]);
    case!(n, r.code == 3 && r.out.contains("no answer (2 queries of 300 ms)") && r.out.contains("no usable answer"), "silence: {} {:?}", r.code, r.out);
    case!(n, stats(false) == Some((2, 0, 0)) && r.ms >= 600 && r.ms < 3000, "silence: 2 queries in 2 x 300 ms ({} ms): {:?}", r.ms, stats(false));

    // Malformed answers: refused, with the reason.
    for (k, why) in [
        (16u16, "server not synchronized (leap 3)"),
        (17, "stratum out of 1-15"),
        (18, "not a server answer (mode)"),
        (19, "NTP version not 3 or 4"),
        (20, "shorter than 48 bytes"),
        (21, "shorter than 48 bytes"),
        (22, "root dispersion 16 s and more"),
        (23, "root distance above 1.5 s"),
        (25, "root delay negative or 16 s and more"),
        (26, "transmit time before receive time"),
        (27, "receive or transmit time is zero"),
        (28, "receive or transmit time is zero"),
        (29, "NTP version not 3 or 4"),
    ] {
        let r = run(&["-t", "150", server(0, k)]);
        case!(n, r.code == 3 && r.out.contains(why) && rtc_offset(r.out).is_none(), "server {} ({}): {} {:?}", k, why, r.code, r.out);
    }

    // The NTP era: a server in 2040.
    let r = run(&[server(0, 14)]);
    case!(n, r.code == 0 && r.out.contains("server time 2040-06-01 12:00:0") && matches!(rtc_offset(r.out), Some(o) if o < -300_000_000), "a server in 2040 (era 1): {} {:?}", r.code, r.out);

    // A server in 1960: before the Unix epoch, within 68 years of the build date.
    let r = run(&[server(0, 31)]);
    case!(n, r.code == 0 && r.out.contains("server time 1960-01-01 00:00:0") && matches!(rtc_offset(r.out), Some(o) if o > 2_000_000_000), "a server in 1960: {} {:?}", r.code, r.out);

    // Several servers, all asked at once.
    let r = run(&[server(0, 0), server(1, 0), server(2, 1)]);
    case!(n, r.code == 0 && r.out.matches("disagrees with the median").count() == 1 && r.out.contains("the median of 3 servers") && matches!(rtc_offset(r.out), Some(o) if o.abs() <= NEAR), "0, 0, +1 h: {} {:?}", r.code, r.out);
    let r = run(&[server(0, 0), server(1, 1), server(2, 1)]);
    case!(n, r.code == 0 && r.out.matches("disagrees with the median").count() == 1 && matches!(rtc_offset(r.out), Some(o) if (o + 3600).abs() <= NEAR), "0, +1 h, +1 h: {} {:?}", r.code, r.out);
    let r = run(&[server(0, 0), server(1, 2), server(2, 3)]);
    case!(n, r.code == 4 && r.out.contains("the servers do not agree (only 1 of 3 within 2 s of the median)") && rtc_offset(r.out).is_none(), "0, +10 s, +20 s: {} {:?}", r.code, r.out);
    let r = run(&[server(0, 0), server(1, 1)]);
    case!(n, r.code == 0 && r.out.contains("two cannot settle which is right") && rtc_offset(r.out).is_none(), "two servers an hour apart: {} {:?}", r.code, r.out);
    let r = run(&[server(0, 0), server(1, 0)]);
    case!(n, r.code == 0 && r.out.contains("the median of 2 servers") && matches!(rtc_offset(r.out), Some(o) if o.abs() <= NEAR), "two servers that agree: {} {:?}", r.code, r.out);
    let r = run(&[server(0, 0), server(1, 0), server(2, 1), server(3, 1)]);
    case!(n, r.code == 0 && r.out.matches("disagrees with the median").count() == 2 && r.out.contains("the median of 4 servers"), "four answers, exactly half near the median: {} {:?}", r.code, r.out);
    stats(true);
    let r = run(&["-t", "400", server(0, 0), server(1, 4), server(2, 0), server(3, 5)]);
    case!(n, r.code == 0 && r.out.contains("the median of 2 servers") && r.out.contains("no answer (2 queries of 400 ms)") && r.out.contains("RATE"), "four servers: two answer, one silent, one KoD: {} {:?}", r.code, r.out);
    case!(n, r.ms >= 800 && r.ms < 3200 && stats(false) == Some((5, 0, 0)), "four servers at once: 2 x 400 ms, not 4 x ({} ms), 5 packets: {:?}", r.ms, stats(false));

    // The arguments.
    let huge = "99999999999999999999";
    for args in [
        &["-t", "99", "ntp.desoos:58123"][..],
        &["-t", "10001", "ntp.desoos:58123"],
        &["-t", "0", "ntp.desoos:58123"],
        &["-t", "abc", "ntp.desoos:58123"],
        &["-t", "2000abc", "ntp.desoos:58123"],
        &["-t", huge, "ntp.desoos:58123"],
        &["-t", "-5", "ntp.desoos:58123"],
        &["-t", "+500", "ntp.desoos:58123"],
        &["-t", "", "ntp.desoos:58123"],
        &["-t"],
        &["-x", "ntp.desoos:58123"],
        &["a:1", "b:1", "c:1", "d:1", "e:1"],
        &["ntp.desoos:0"],
        &["ntp.desoos:65536"],
        &["ntp.desoos:12x"],
        &[":58123"],
    ] {
        stats(true);
        let r = run(args);
        case!(n, r.code == 2 && r.out.contains("usage: nettime") && stats(false) == Some((0, 0, 0)), "nettime {:?} must be a usage error with nothing sent: {} {:?}", args, r.code, r.out);
    }
    let r = run(&["-t", "100", server(0, 0)]);
    case!(n, r.code == 0, "-t 100: {} {:?}", r.code, r.out);
    let r = run(&["-t", "10000", server(0, 0), "net0"]);
    case!(n, r.code == 0, "-t 10000 and the card's name: {} {:?}", r.code, r.out);
    let r = run(&["nx.desoos:58123"]);
    case!(n, r.code == 2 && r.out.contains("no such name"), "an unknown name: {} {:?}", r.code, r.out);
    let r = run(&[server(0, 0), "net9"]);
    case!(n, r.code == 2, "a card that is not there: {} {:?}", r.code, r.out);

    // The udp right.
    let net_only = svc_narrow("net").unwrap_or(0);
    stats(true);
    let r = run_via(net_only, &[server(0, 0)]);
    close(net_only);
    case!(n, r.code == 2 && r.out.contains("needs the udp right") && stats(false) == Some((0, 0, 0)), "without the udp right: {} {:?}", r.code, r.out);
    let with_udp = svc_narrow("net udp").unwrap_or(0);
    let r = run_via(with_udp, &[server(0, 0)]);
    close(with_udp);
    case!(n, r.code == 0, "a narrowed channel with udp: {} {:?}", r.code, r.out);

    // After everything – also the forged answers, the 2040 server and the Kiss-o'-Deaths –
    // the clock still runs with uptime (no step) and its verdict is the same.
    let r = ask("dns auto");
    case!(n, r.starts_with("DNS server"), "dns auto: {:?}", r.trim());
    let Ok(clock1) = time_unix() else { return 1 };
    let ran = (uptime_ms() - up0) as i64 / 1000;
    let moved = clock1.secs as i64 - clock0.secs as i64;
    case!(n, (moved - ran).abs() <= 2, "the clock moved {} s while {} s passed", moved, ran);
    case!(n, clock1.status == clock0.status && clock1.build_epoch == clock0.build_epoch, "the clock's verdict changed: {} -> {}", clock0.status, clock1.status);
    let r = run(&[server(0, 0)]);
    case!(n, matches!(rtc_offset(r.out), Some(o) if o.abs() <= NEAR), "the clock against the host's time at the end: {:?}", r.out);

    println!("ntptest net: {} cases OK (nettime against tests/ntp-stub.py: answers, forged and late ones, Kiss-o'-Death, silence, 13 malformed answers, servers in 1960 and 2040, 2-4 servers at once, arguments, the udp right; the clock and its verdict unchanged after {} s)", n, ran);
    0
}

fn main(args: Args) -> i32 {
    match args.get(1) {
        None => library(),
        Some("net") => net(),
        _ => {
            eprintln!("usage: ntptest [net]");
            2
        }
    }
}
