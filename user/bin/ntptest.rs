// NTP TEST's program (kernel/user/test_ntp.rs).
//
// `ntptest` – the library user/lib/ntp.rs without a network: the query's bytes, every
// refusal of an answer and the order of the checks (a Kiss-o'-Death is recognised before
// the timestamp checks and only with the right Origin), the delay, the NTP era (the
// 2036 wrap, the edges of the +-68 years around the build date), the median.
// "ntptest: N checks OK".
//
// `ntptest net` (started by init with the services) – /bin/nettime against
// tests/ntp-stub.py on the host (10.0.2.2:58123-58153, the name ntp.deso from
// tests/dns-stub.py): a correct answer, forged and late ones, Kiss-o'-Death, silence and
// the one retry, every malformed answer, two to four servers, the arguments, the udp
// right, how many packets went out and what was in them – and at the end the clock's
// verdict is what it was (the kernel side of the test compares the hardware RTC with the
// clock before and after).  "ntptest net: N cases OK".
//
// NTS (user/lib/nts.rs, v0.79 stage B): `ntptest` also checks the NTS-KE records (every
// refusal), the cookie pool, the placeholder count, the request's fields and Authenticator,
// and every answer an NTS client can get (built here with AES-SIV); `ntptest net` runs
// `nettime --nts` against tests/nts-server (rustls + RustCrypto aes-siv – independent of
// DeSoTLS / DeSoCrypto): 27 NTS-KE responses and 15 kinds of NTP answers.
#![no_std]
#![no_main]

#[macro_use]
#[allow(unused_imports)]
extern crate libdeso;
#[allow(unused_imports)]
use libdeso as deso;
#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;
#[path = "../lib/ntp.rs"]
mod ntp;
#[path = "../lib/nts.rs"]
mod nts;

use desocrypto::aes_siv::AesSiv;
use deso::*;
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

    if nts_library(&mut n) != 0 {
        return 1;
    }
    println!("ntptest: {} checks OK (query bytes, the order of the checks with Kiss-o'-Death before the timestamps, delay, NTP era around the build date {}, dates before 1970, rounding, the summary's words, median; NTS: KE records, cookies, placeholders, request, every answer)", n, pivot);
    0
}

// ---- NTS without a network ----

/// A KE record.
fn rec(out: &mut [u8], n: &mut usize, ty: u16, body: &[u8]) {
    out[*n..*n + 2].copy_from_slice(&ty.to_be_bytes());
    out[*n + 2..*n + 4].copy_from_slice(&(body.len() as u16).to_be_bytes());
    out[*n + 4..*n + 4 + body.len()].copy_from_slice(body);
    *n += 4 + body.len();
}

static mut KE: [u8; 70_000] = [0; 70_000];
static mut POOL: nts::Pool = nts::Pool::new();

/// An NTS-KE response from parts: "N" Next Protocol {0}, "A" AEAD {15}, "C" a 96-byte cookie,
/// "E" End of Message, and the special ones below.
fn ke_from(parts: &[&str]) -> &'static [u8] {
    let b = unsafe { &mut *core::ptr::addr_of_mut!(KE) };
    let mut n = 0;
    for p in parts {
        match *p {
            "N" => rec(b, &mut n, 0x8001, &[0, 0]),
            "N1" => rec(b, &mut n, 0x8001, &[0, 1]),
            "N0len" => rec(b, &mut n, 0x8001, &[]),
            "A" => rec(b, &mut n, 0x8004, &[0, 15]),
            "A17" => rec(b, &mut n, 0x8004, &[0, 17]),
            "C" => rec(b, &mut n, 5, &[0xC0; 96]),
            "C98" => rec(b, &mut n, 5, &[0xC9; 98]),
            "C12" => rec(b, &mut n, 5, &[0xC1; 12]),
            "C1024" => rec(b, &mut n, 5, &[0xCA; 1024]),
            "C1028" => rec(b, &mut n, 5, &[0xCB; 1028]),
            "E" => rec(b, &mut n, 0x8000, &[]),
            "Err" => rec(b, &mut n, 0x8002, &[0, 1]),
            "Warn" => rec(b, &mut n, 0x8003, &[0, 0]),
            "U" => rec(b, &mut n, 50, &[1, 2, 3, 4]),
            "Ucrit" => rec(b, &mut n, 0x8000 | 50, &[1, 2, 3, 4]),
            "S" => rec(b, &mut n, 6, b"ntp.deso"),
            "Sbad" => rec(b, &mut n, 6, b"bad host!"),
            "P" => rec(b, &mut n, 7, &[0xE4, 0xD8]),
            "P0" => rec(b, &mut n, 7, &[0, 0]),
            // The Critical Bit and exact lengths (RFC 8915 §4.1).
            "Enc" => rec(b, &mut n, 0x0000, &[]),
            "Ebody" => rec(b, &mut n, 0x8000, &[0, 0]),
            "Nnc" => rec(b, &mut n, 0x0001, &[0, 0]),
            "Anc" => rec(b, &mut n, 0x0004, &[0, 15]),
            "ErrNc" => rec(b, &mut n, 0x0002, &[0, 1]),
            "Err1" => rec(b, &mut n, 0x8002, &[0]),
            "Err3" => rec(b, &mut n, 0x8002, &[0, 1, 2]),
            "WarnNc" => rec(b, &mut n, 0x0003, &[0, 0]),
            "Warn3" => rec(b, &mut n, 0x8003, &[0, 0, 0]),
            "Ccrit" => rec(b, &mut n, 0x8005, &[0xC0; 96]),
            "Scrit" => rec(b, &mut n, 0x8006, b"ntp.deso"),
            "Pcrit" => rec(b, &mut n, 0x8007, &[0xE4, 0xD8]),
            "cut" => n -= 3,
            _ => {}
        }
    }
    &b[..n]
}

fn nts_library(n: &mut usize) -> i32 {
    let mut n2 = *n;
    let r = nts_checks(&mut n2);
    *n = n2;
    r
}

fn nts_checks(n: &mut usize) -> i32 {
    let mut k = *n;
    let pool = unsafe { &mut *core::ptr::addr_of_mut!(POOL) };
    use nts::KeError as E;
    // The request records.
    check!(k, nts::KE_REQUEST == [0x80, 1, 0, 2, 0, 0, 0x80, 4, 0, 2, 0, 15, 0x80, 0, 0, 0], "NTS-KE request bytes");
    // Responses.
    let cases: [(&[&str], Result<usize, E>); 37] = [
        (&["N", "A", "C", "E"], Ok(1)),
        (&["N", "A", "C", "C", "C", "C", "C", "C", "C", "C", "C", "E"], Ok(8)),
        (&["N", "A", "U", "C", "E"], Ok(1)),
        (&["N", "A", "C98", "C", "C12", "E"], Ok(1)),
        (&["N", "A", "C1024", "E"], Ok(1)),
        (&["N", "A", "C", "S", "P", "E"], Ok(1)),
        (&["N", "A", "C"], Err(E::NoEnd)),
        (&["N", "A", "C", "E", "U"], Err(E::AfterEnd)),
        (&["N", "A", "C", "E", "cut"], Err(E::Cut)),
        (&["N", "N", "A", "C", "E"], Err(E::Repeated(1))),
        (&["N", "A", "A", "C", "E"], Err(E::Repeated(4))),
        (&["A", "C", "E"], Err(E::MissingNextProtocol)),
        (&["N", "C", "E"], Err(E::MissingAead)),
        (&["N1", "A", "C", "E"], Err(E::BadNextProtocol)),
        (&["N0len", "A", "C", "E"], Err(E::Short(1))),
        (&["N", "A17", "C", "E"], Err(E::BadAead)),
        (&["Err", "E"], Err(E::Error(1))),
        (&["N", "A", "C", "Warn", "E"], Err(E::Warning(0))),
        (&["N", "A", "C", "Ucrit", "E"], Err(E::UnknownCritical(50))),
        (&["N", "A", "E"], Err(E::NoCookies)),
        (&["N", "A", "C98", "C12", "C1028", "E"], Err(E::NoCookies)),
        (&["N", "A", "C", "Sbad", "E"], Err(E::BadServer)),
        (&["N", "A", "C", "S", "S", "E"], Err(E::Repeated(6))),
        (&["N", "A", "C", "P0", "E"], Err(E::BadPort)),
        (&["N", "A", "C", "P", "P", "E"], Err(E::Repeated(7))),
        // Critical Bit: must be set on End of Message, Next Protocol, Error, Warning; must not
        // be on New Cookie; AEAD and the negotiations either way.  Exact lengths.
        (&["N", "A", "C", "Enc"], Err(E::CriticalBit(0))),
        (&["N", "A", "C", "Ebody"], Err(E::BadLength(0))),
        (&["Nnc", "A", "C", "E"], Err(E::CriticalBit(1))),
        (&["N", "Anc", "C", "E"], Ok(1)),
        (&["N", "A", "C", "Scrit", "Pcrit", "E"], Ok(1)),
        (&["ErrNc", "E"], Err(E::CriticalBit(2))),
        (&["Err1", "E"], Err(E::BadLength(2))),
        (&["Err3", "E"], Err(E::BadLength(2))),
        (&["N", "A", "C", "WarnNc", "E"], Err(E::CriticalBit(3))),
        (&["N", "A", "C", "Warn3", "E"], Err(E::BadLength(3))),
        (&["N", "A", "Ccrit", "E"], Err(E::CriticalBit(5))),
        (&["N", "A", "C", "Ccrit", "E"], Err(E::CriticalBit(5))),
    ];
    for (parts, want) in cases.iter() {
        let got = nts::parse_ke(ke_from(parts), pool).map(|_| pool.n);
        check!(k, got == *want, "NTS-KE {:?}: {:?}, expected {:?}", parts, got, want);
    }
    let neg = nts::parse_ke(ke_from(&["N", "A", "C", "S", "P", "E"]), pool);
    check!(k, matches!(&neg, Ok(g) if g.server() == Some("ntp.deso") && g.port == 0xE4D8), "negotiated server and port");
    let neg = nts::parse_ke(ke_from(&["N", "A", "C", "E"]), pool);
    check!(k, matches!(&neg, Ok(g) if g.server().is_none() && g.port == 123), "no negotiation: the KE server and port 123");
    let _ = nts::parse_ke(ke_from(&["N", "A", "C98", "C", "C", "C", "C", "C", "C", "C", "C", "C", "E"]), pool);
    check!(k, pool.n == 8 && pool.skipped == 1 && pool.overflow == 1, "pool: 8 kept, 1 skipped, 1 over ({} {} {})", pool.n, pool.skipped, pool.overflow);
    // ke_complete: not yet / done / too long.
    let whole = ke_from(&["N", "A", "C", "E"]);
    let wl = whole.len();
    check!(k, nts::ke_complete(&whole[..wl - 1]) == Ok(0) && nts::ke_complete(&whole[..3]) == Ok(0) && nts::ke_complete(whole) == Ok(wl), "ke_complete");
    // A message of exactly 65 536 bytes is taken, 65 537 not.
    for (total, ok) in [(65_536usize, true), (65_537, false)] {
        let b = unsafe { &mut *core::ptr::addr_of_mut!(KE) };
        let mut m = 0;
        rec(b, &mut m, 0x8001, &[0, 0]);
        rec(b, &mut m, 0x8004, &[0, 15]);
        rec(b, &mut m, 5, &[0xC0; 96]);
        let mut left = total - m - 4;
        while left > 0 {
            let body = (left - 4).min(60_000);
            let mut z = m;
            b[z..z + 2].copy_from_slice(&50u16.to_be_bytes());
            b[z + 2..z + 4].copy_from_slice(&(body as u16).to_be_bytes());
            z += 4;
            for x in b[z..z + body].iter_mut() {
                *x = 0;
            }
            m = z + body;
            left -= 4 + body;
        }
        rec(b, &mut m, 0x8000, &[]);
        let r = nts::parse_ke(&b[..m], pool);
        check!(k, m == total && (r.is_ok() == ok) && (ok || r.err() == Some(E::TooLong)), "a response of {} bytes", total);
    }
    // Placeholders: min(7, 7 - r), fewer above the limit, never above 1469 bytes.
    for (r, len, limit, want) in [(7usize, 96usize, 1200usize, Some(0usize)), (0, 96, 1200, Some(7)), (3, 96, 1200, Some(4)), (0, 300, 1200, Some(2)), (0, 300, 1469, Some(3)), (0, 1024, 1200, Some(0)), (9, 96, 1200, Some(0)), (0, 96, 5000, Some(7))] {
        let got = nts::placeholders(r, len, limit);
        check!(k, got == want, "placeholders({}, {}, {}) = {:?}, expected {:?}", r, len, limit, got, want);
    }
    check!(k, nts::request_len(96, 7) == 48 + 36 + 100 * 8 + 40 && nts::request_len(1024, 0) <= nts::REQUEST_MAX, "request lengths");
    // Pool: one cookie never comes out twice; take empties it.
    pool.clear();
    for i in 0..3u8 {
        let mut c = [0u8; 96];
        c[0] = i;
        pool.add(&c);
    }
    let a = pool.take();
    let b2 = pool.take();
    check!(k, matches!((&a, &b2), (Some(x), Some(y)) if x.data[0] == 0 && y.data[0] == 1) && pool.n == 1, "the pool hands out each cookie once, oldest first");
    // The request.
    let c2s = [0x11u8; 32];
    let s2c = [0x22u8; 32];
    let uid = [0x33u8; 32];
    let nonce = [0x44u8; 16];
    let xmit = 0x0123_4567_89AB_CDEFu64;
    let mut cookie = nts::Cookie::EMPTY;
    cookie.len = 96;
    cookie.data[..96].copy_from_slice(&[0xC0; 96]);
    let mut pkt = [0u8; nts::REQUEST_MAX];
    let len = nts::build_request(&mut pkt, xmit, &uid, &cookie, 2, &nonce, &c2s);
    check!(k, len == Ok(nts::request_len(96, 2)), "request length {:?}", len);
    let len = len.unwrap_or(0);
    let p = &pkt[..len];
    check!(k, p[0] == 0x23 && p[3] == 0x20 && p[40..48] == xmit.to_be_bytes(), "request header (Precision 0x20)");
    check!(k, p[48..52] == [0x01, 0x04, 0, 36] && p[52..84] == uid, "Unique Identifier field");
    check!(k, p[84..88] == [0x02, 0x04, 0, 100] && p[88..184] == [0xC0; 96], "cookie field");
    check!(k, p[184..188] == [0x03, 0x04, 0, 100] && p[188..284].iter().all(|&x| x == 0) && p[284..288] == [0x03, 0x04, 0, 100], "two placeholders, zeros, as long as the cookie");
    let at = 384;
    check!(k, p[at..at + 8] == [0x04, 0x04, 0, 40, 0, 16, 0, 16] && p[at + 8..at + 24] == nonce, "Authenticator header and nonce");
    let mut siv = [0u8; 16];
    siv.copy_from_slice(&p[at + 24..at + 40]);
    check!(k, AesSiv::new(&c2s).open(&[&p[..at], &nonce], &mut [], &siv).is_ok(), "the Authenticator verifies with C2S over everything before it");
    check!(k, AesSiv::new(&s2c).open(&[&p[..at], &nonce], &mut [], &siv).is_err(), "... and not with S2C");
    let mut short = cookie;
    short.len = 98;
    check!(k, nts::build_request(&mut pkt, xmit, &uid, &short, 0, &nonce, &c2s).is_err(), "a cookie not divisible by 4 is never sent");
    // Answers (built here: header, Unique Identifier, Authenticator with S2C, two cookies).
    let mut ans = [0u8; 600];
    let now32 = 3_970_000_000u32;
    let make = |out: &mut [u8; 600], stratum: u8, refid: &[u8; 4], uid_in: Option<&[u8; 32]>, key: &[u8; 32], corrupt: bool, after: usize, origin: u64| -> usize {
        let mut h = reply(origin, now32);
        h[1] = stratum;
        h[12..16].copy_from_slice(refid);
        out[..48].copy_from_slice(&h);
        let mut m = 48;
        if let Some(u) = uid_in {
            out[m..m + 4].copy_from_slice(&[0x01, 0x04, 0, 36]);
            out[m + 4..m + 36].copy_from_slice(u);
            m += 36;
        }
        // Plaintext: two cookie fields of 96 bytes.
        let mut plain = [0u8; 200];
        for c in 0..2 {
            plain[c * 100..c * 100 + 4].copy_from_slice(&[0x02, 0x04, 0, 100]);
            for x in plain[c * 100 + 4..c * 100 + 100].iter_mut() {
                *x = 0xD0 + c as u8;
            }
        }
        let nn = [0x55u8; 16];
        let v = AesSiv::new(key).seal(&[&out[..m], &nn], &mut plain).unwrap_or([0; 16]);
        out[m..m + 4].copy_from_slice(&[0x04, 0x04, 0, 4 + 4 + 16 + 16 + 200]);
        out[m + 4..m + 8].copy_from_slice(&[0, 16, 0, 216]);
        out[m + 8..m + 24].copy_from_slice(&nn);
        out[m + 24..m + 40].copy_from_slice(&v);
        out[m + 40..m + 240].copy_from_slice(&plain);
        if corrupt {
            out[m + 30] ^= 1;
        }
        m += 240;
        for _ in 0..after {
            out[m..m + 4].copy_from_slice(&[0x0F, 0x04, 0, 16]);
            m += 16;
        }
        m
    };
    use nts::Reject as R;
    pool.clear();
    let l = make(&mut ans, 2, b"TEST", Some(&uid), &s2c, false, 0, xmit);
    let r = nts::check_response(&ans[..l], xmit, &uid, &s2c, pool);
    check!(k, matches!(r, Ok(nts::Answer::Time { reply, cookies: 2 }) if reply.stratum == 2) && pool.n == 2 && pool.cookies[1].data[0] == 0xD1, "an authenticated answer, two new cookies: {:?}", r);
    let l = make(&mut ans, 2, b"TEST", Some(&uid), &s2c, false, 2, xmit);
    check!(k, matches!(nts::check_response(&ans[..l], xmit, &uid, &s2c, pool), Ok(nts::Answer::Time { .. })), "fields after the Authenticator are ignored");
    let other = [0x34u8; 32];
    let refusals: [(u8, &[u8; 4], Option<&[u8; 32]>, &[u8; 32], bool, u64, R); 9] = [
        (2, b"TEST", Some(&other), &s2c, false, xmit, R::WrongUid),
        (2, b"TEST", None, &s2c, false, xmit, R::NoUid),
        (2, b"TEST", Some(&uid), &s2c, true, xmit, R::AuthFailed),
        (2, b"TEST", Some(&uid), &c2s, false, xmit, R::AuthFailed),
        (2, b"TEST", Some(&uid), &s2c, false, xmit + 1, R::Ntp(ntp::Reject::Origin)),
        (16, b"TEST", Some(&uid), &s2c, false, xmit, R::Ntp(ntp::Reject::Stratum)),
        (0, b"DENY", Some(&uid), &s2c, false, xmit, R::UnauthenticatedKod),
        (0, b"NTSN", Some(&other), &s2c, false, xmit, R::UnauthenticatedKod),
        (0, b"NTSN", None, &s2c, false, xmit, R::UnauthenticatedKod),
    ];
    for (st, refid, u, key, corrupt, origin, want) in refusals.iter() {
        let l = make(&mut ans, *st, refid, *u, key, *corrupt, 0, *origin);
        let r = nts::check_response(&ans[..l], xmit, &uid, &s2c, pool);
        check!(k, r == Err(*want), "answer (stratum {}, {:?}): {:?}, expected {:?}", st, core::str::from_utf8(*refid), r, want);
    }
    // NTS NAK with our Unique Identifier – even with garbage after it.
    let l = make(&mut ans, 0, b"NTSN", Some(&uid), &s2c, true, 0, xmit);
    check!(k, nts::check_response(&ans[..l], xmit, &uid, &s2c, pool) == Ok(nts::Answer::Nak), "NTS NAK with our Unique Identifier");
    // A plain NTP answer (48 bytes): no Unique Identifier.
    let plain = reply(xmit, now32);
    check!(k, nts::check_response(&plain, xmit, &uid, &s2c, pool) == Err(R::NoUid), "a plain NTP answer is refused");
    // No Authenticator: header + Unique Identifier only.
    let l = make(&mut ans, 2, b"TEST", Some(&uid), &s2c, false, 0, xmit);
    check!(k, nts::check_response(&ans[..84], xmit, &uid, &s2c, pool) == Err(R::NoAuthenticator) && l > 84, "no Authenticator");
    // Two Authenticators (the second copied after the first).
    let mut two = [0u8; 900];
    two[..l].copy_from_slice(&ans[..l]);
    two[l..l + 240].copy_from_slice(&ans[84..324]);
    check!(k, nts::check_response(&two[..l + 240], xmit, &uid, &s2c, pool) == Err(R::TwoAuthenticators), "two Authenticators");
    // A field length that is not a multiple of 4 before the Authenticator.
    ans[51] = 35;
    check!(k, nts::check_response(&ans[..l], xmit, &uid, &s2c, pool) == Err(R::BadField), "a malformed field");
    // Authenticator padding (RFC 8915 §5.6): a 13-byte nonce (3 bytes of padding), a 6-byte
    // plaintext (22-byte ciphertext, 2 bytes of padding), 4 bytes of additional padding – all
    // zeros: taken; one byte that is not zero in any of them: refused (none of these bytes is
    // covered by the Authenticator itself, so only this check sees them).
    let padded = |out: &mut [u8; 600], flip: usize| -> usize {
        out[..48].copy_from_slice(&reply(xmit, now32));
        out[48..52].copy_from_slice(&[0x01, 0x04, 0, 36]);
        out[52..84].copy_from_slice(&uid);
        let m = 84;
        let nn = [0x66u8; 13];
        let mut pt = [0x77u8; 6];
        let v = AesSiv::new(&s2c).seal(&[&out[..m], &nn], &mut pt).unwrap_or([0; 16]);
        let flen = 4 + 4 + 16 + 24 + 4;
        for x in out[m..m + flen].iter_mut() {
            *x = 0;
        }
        out[m..m + 4].copy_from_slice(&[0x04, 0x04, 0, flen as u8]);
        out[m + 4..m + 8].copy_from_slice(&[0, 13, 0, 22]);
        out[m + 8..m + 21].copy_from_slice(&nn);
        out[m + 24..m + 40].copy_from_slice(&v);
        out[m + 40..m + 46].copy_from_slice(&pt);
        match flip {
            1 => out[m + 22] = 1, // nonce padding
            2 => out[m + 47] = 1, // ciphertext padding
            3 => out[m + 50] = 1, // additional padding
            _ => {}
        }
        m + flen
    };
    let l = padded(&mut ans, 0);
    let r = nts::check_response(&ans[..l], xmit, &uid, &s2c, pool);
    check!(k, matches!(r, Ok(nts::Answer::Time { cookies: 0, .. })), "Authenticator with zero padding (13-byte nonce, 22-byte ciphertext, additional padding): {:?}", r);
    for (flip, what) in [(1usize, "nonce"), (2, "ciphertext"), (3, "additional")] {
        let l = padded(&mut ans, flip);
        let r = nts::check_response(&ans[..l], xmit, &uid, &s2c, pool);
        check!(k, r == Err(R::AuthenticatorPadding), "{} padding not zero: {:?}", what, r);
    }
    // Wiped: the buffer is zeroed when the guard goes out of scope – also on an early return.
    let mut buf = [0xAAu8; 32];
    {
        let w = nts::Wiped(&mut buf);
        w.0[0] = 0xBB;
    }
    check!(k, buf.iter().all(|&x| x == 0), "Wiped zeroes its buffer at the end of the scope");
    let mut buf = [0xAAu8; 32];
    let early = |b: &mut [u8]| -> Result<(), ()> {
        let w = nts::Wiped(b);
        if w.0[0] == 0xAA {
            return Err(());
        }
        Ok(())
    };
    check!(k, early(&mut buf).is_err() && buf.iter().all(|&x| x == 0), "Wiped zeroes its buffer on an early return");
    *n = k;
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

/// The stub's queries per port (0-29) since its last reset.
fn per_port() -> Option<[u64; 30]> {
    let mut reply = [0u8; 512];
    let c = udp_open_via(SVC, "net0", "10.0.2.2", BASE + 30, &mut reply).ok()?;
    let mut got = None;
    let mut info = RecvInfo::default();
    for _ in 0..3 {
        if udp_send(c, b"stats") != 0 {
            break;
        }
        if wait_many(&[(c, W_READABLE)], 1000) == Ok(1) {
            let r = chan_recv(c, &mut reply, CHAN_NONBLOCK, &mut info);
            if r > 0 {
                let t = core::str::from_utf8(&reply[..r as usize]).unwrap_or("");
                let list = t.split(' ').find_map(|w| w.strip_prefix("per="));
                let mut out = [0u64; 30];
                let mut k = 0;
                for v in list.unwrap_or("").split(',') {
                    if k == 30 {
                        k = 31;
                        break;
                    }
                    match v.parse() {
                        Ok(x) => out[k] = x,
                        Err(_) => break,
                    }
                    k += 1;
                }
                if k == 30 {
                    got = Some(out);
                }
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
    // the host's clock, but DeSo OS's clock is the RTC at boot plus uptime, and uptime runs
    // slow under TCG (seconds after a few minutes) – hence NEAR.
    let r = run(&["ntp.deso:58123"]);
    case!(n, r.code == 0 && r.out.contains("nettime: ntp.deso (10.0.2.2): stratum 2, delay ") && r.out.contains("not changed: plain NTP is not authenticated"), "a correct answer: {} {:?}", r.code, r.out);
    case!(n, matches!(rtc_offset(r.out), Some(o) if o.abs() <= NEAR), "the clock against the host's time: {:?} {:?}", rtc_offset(r.out), r.out);
    case!(n, r.out.contains("path asymmetry bound +-") && r.out.contains(" ntp.deso (the clock counts whole seconds"), "the summary names the limits: {:?}", r.out);
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
    // Per port: the silent server (port 4) exactly 2 queries; the KoD server (port 5) 1, the two
    // answering servers (both on port 0) 1 each – one more per server only when an answer was
    // lost on the way (UDP) and the one retry went out; no other port asked.
    let per = per_port();
    let fair = per.is_some_and(|p| {
        p[4] == 2 && (2..=4).contains(&p[0]) && (1..=2).contains(&p[5]) && p.iter().enumerate().all(|(k, &c)| matches!(k, 0 | 4 | 5) || c == 0)
    });
    case!(
        n,
        r.ms >= 800 && r.ms < 3200 && fair && stats(false).is_some_and(|s| s.1 == 0 && s.2 == 0),
        "four servers at once: 2 x 400 ms, not 4 x ({} ms); queries on ports 0 (two servers) / 4 (silent) / 5 (KoD): {:?} (want 2-4 / 2 / 1-2)",
        r.ms,
        per.map(|p| (p[0], p[4], p[5]))
    );

    // The arguments.
    let huge = "99999999999999999999";
    for args in [
        &["-t", "99", "ntp.deso:58123"][..],
        &["-t", "10001", "ntp.deso:58123"],
        &["-t", "0", "ntp.deso:58123"],
        &["-t", "abc", "ntp.deso:58123"],
        &["-t", "2000abc", "ntp.deso:58123"],
        &["-t", huge, "ntp.deso:58123"],
        &["-t", "-5", "ntp.deso:58123"],
        &["-t", "+500", "ntp.deso:58123"],
        &["-t", "", "ntp.deso:58123"],
        &["-t"],
        &["-x", "ntp.deso:58123"],
        &["a:1", "b:1", "c:1", "d:1", "e:1"],
        &["ntp.deso:0"],
        &["ntp.deso:65536"],
        &["ntp.deso:12x"],
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
    let r = run(&["nx.deso:58123"]);
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

    // NTS against tests/nts-server.
    if nts_net(&mut n) != 0 {
        return 1;
    }

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

    println!("ntptest net: {} cases OK (nettime against tests/ntp-stub.py: answers, forged and late ones, Kiss-o'-Death, silence, 13 malformed answers, servers in 1960 and 2040, 2-4 servers at once, arguments, the udp right; nettime --nts against tests/nts-server (rustls): 27 NTS-KE responses, 15 kinds of NTP answers, placeholders, cookies never reused; the clock and its verdict unchanged after {} s)", n, ran);
    0
}

// ---- NTS against tests/nts-server (rustls, RustCrypto aes-siv) ----

/// tests/nts-server: NTS-KE at +10 + k, NTS-KE leading to NTP behaviour m at +70 + m, the
/// counters at +39 (UDP).
const NTS_BASE: u16 = 58500;
const NTS_CA: &[u8] = include_bytes!("../../tests/tls/ca.pem");
const NTS_CA_PATH: &str = "/nts-ca.pem";

/// "tls.deso:<port>" (the certificate's name; the DNS stub gives 10.0.2.2), static.
fn ke_server(port: u16) -> &'static str {
    static mut NAME: [u8; 24] = [0; 24];
    let b = unsafe { &mut *core::ptr::addr_of_mut!(NAME) };
    const HOST: &[u8] = b"tls.deso:";
    b[..HOST.len()].copy_from_slice(HOST);
    for i in 0..5 {
        b[HOST.len() + i] = b'0' + (port / 10u16.pow(4 - i as u32) % 10) as u8;
    }
    core::str::from_utf8(&b[..HOST.len() + 5]).unwrap_or("")
}

/// The server's counters (requests, dup, bad, maxlen, placeholders); `reset` zeroes them.
fn nts_stats(reset: bool) -> Option<(u64, u64, u64, u64, u64)> {
    let mut reply = [0u8; 256];
    let c = udp_open_via(SVC, "net0", "10.0.2.2", NTS_BASE + 39, &mut reply).ok()?;
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
                got = Some((f("requests=")?, f("dup=")?, f("bad=")?, f("maxlen=")?, f("placeholders=")?));
                break;
            }
        }
    }
    close(c);
    got
}

/// netd has 8 TCP connections and a closed one waits in TIME_WAIT for 2 s: before each
/// NTS-KE wait until there is room (as tlstest does).
fn tcp_room() {
    let t = uptime_ms();
    loop {
        let st = ask("status");
        let line = st.lines().find(|l| l.starts_with("netd-status")).unwrap_or("");
        let used = line.split_whitespace().find_map(|w| w.strip_prefix("tcp=")).and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
        if used < 6 || uptime_ms() - t > 8000 {
            return;
        }
        sleep_ms(50);
    }
}

fn nts_run(t: &str, port: u16) -> Run {
    tcp_room();
    run(&["-t", t, "--nts", "--anchor", NTS_CA_PATH, ke_server(port)])
}

fn nts_net(n: &mut usize) -> i32 {
    let mut k = *n;
    let fd = open(NTS_CA_PATH, O_WRITE | O_CREATE | O_TRUNC);
    case!(k, fd >= 0 && write(fd as u64, NTS_CA) == NTS_CA.len() as i64, "write the test CA");
    close(fd as u64);
    let ke = |x: u16| NTS_BASE + 10 + x;
    let via = |m: u16| NTS_BASE + 70 + m;

    // A correct exchange: authenticated, still nothing changed; 8 cookies -> no placeholders.
    nts_stats(true);
    let r = nts_run("2000", ke(0));
    case!(k, r.code == 0 && r.out.contains(", authenticated (NTS)") && r.out.contains("authenticated (NTS), but not changed") && matches!(rtc_offset(r.out), Some(o) if o.abs() <= NEAR), "nettime --nts: {} {:?}", r.code, r.out);
    let st = nts_stats(false);
    case!(k, matches!(st, Some((1, 0, 0, len, 0)) if len <= 1200), "one NTS request, Authenticator valid at the server, no placeholders (8 cookies): {:?}", st);

    // NTS-KE responses that must be refused – with what nettime says.
    let refused: [(u16, &str); 16] = [
        (1, "without End of Message"),
        (2, "data after End of Message"),
        (3, "no close_notify"),
        (4, "a one-time NTS-KE record came twice"),
        (5, "a one-time NTS-KE record came twice"),
        (6, "no AEAD record"),
        (7, "AEAD is not AEAD_AES_SIV_CMAC_256"),
        (8, "Next Protocol is not exactly NTPv4"),
        (9, "NTS-KE Error record"),
        (10, "Warning record (treated as an error)"),
        (11, "unknown critical NTS-KE record"),
        (13, "NTS-KE record body too short"),
        (15, "longer than 65536 bytes"),
        (16, "no usable cookie"),
        (19, "NTS-KE record cut short"),
        (20, "no usable cookie"),
    ];
    for (x, why) in refused {
        nts_stats(true);
        let r = nts_run("500", ke(x));
        case!(k, r.code == 3 && r.out.contains(why) && nts_stats(false).map(|s| s.0) == Some(0), "NTS-KE {} must be refused ({}), nothing sent to NTP: {} {:?}", x, why, r.code, r.out);
    }
    for (x, why) in [(22u16, "did not confirm the ALPN protocol"), (24, "bad NTPv4 Port Negotiation"), (25, "bad NTPv4 Server Negotiation")] {
        let r = nts_run("500", ke(x));
        case!(k, r.code == 3 && r.out.contains(why), "NTS-KE {} must be refused ({}): {} {:?}", x, why, r.code, r.out);
    }
    // Accepted responses.
    for x in [12u16, 14, 17, 18, 23] {
        let r = nts_run("2000", ke(x));
        case!(k, r.code == 0 && r.out.contains(", authenticated (NTS)"), "NTS-KE {} must be accepted: {} {:?}", x, r.code, r.out);
    }
    // A KE server that never answers the SYN (tests/tls-stub.py, port 58471 – like a dead
    // server): the lookup and the connection get 3 × wait, not netd's 15 s of SYN retries;
    // the failure line has no "()" (no address known) and no "(0 queries ...)".
    let dead = "tls.deso:58471";
    tcp_room();
    let r = run(&["-t", "300", "--nts", "--anchor", NTS_CA_PATH, dead]);
    case!(k, r.code == 3 && r.out.contains("nettime: tls.deso: NTS-KE: no connection within 900 ms") && r.out.contains("nettime: tls.deso: NTS-KE connection failed\n") && !r.out.contains("()") && !r.out.contains("queries") && r.ms < 3000, "dead NTS-KE server: given up after 3 x wait: {} {} ms {:?}", r.code, r.ms, r.out);
    // The dead server before a good one: the good one still gives the time, well before the
    // 15 s netd alone would have waited.
    tcp_room();
    let r = run(&["-t", "1000", "--nts", "--anchor", NTS_CA_PATH, dead, ke_server(ke(0))]);
    case!(k, r.code == 0 && r.out.contains("no connection within 3000 ms") && r.out.contains(", authenticated (NTS)") && r.ms < 12000, "dead NTS-KE server, then a good one: {} {} ms {:?}", r.code, r.ms, r.out);
    // Placeholders: one cookie of 96 bytes -> 7; one of 300 bytes -> 2 (the request stays
    // within 1200 bytes).
    nts_stats(true);
    let r = nts_run("2000", ke(26));
    let st = nts_stats(false);
    case!(k, r.code == 0 && matches!(st, Some((1, 0, 0, len, 7)) if len <= 1200), "one cookie: 7 placeholders: {:?} {:?}", st, r.out);
    nts_stats(true);
    let r = nts_run("2000", ke(21));
    let st = nts_stats(false);
    case!(k, r.code == 0 && matches!(st, Some((1, 0, 0, len, 2)) if len <= 1200 && len > 900), "a 300-byte cookie: 2 placeholders, within 1200 bytes: {:?} {:?}", st, r.out);

    // NTP answers.
    let answers: [(u16, u64, &str); 15] = [
        (0, 0, ", authenticated (NTS)"),
        (1, 3, "NTS Authenticator does not verify"),
        (2, 3, "no NTS Authenticator"),
        (3, 3, "Unique Identifier does not match"),
        (4, 0, "1 answer(s) ignored (the last: Unique Identifier does not match the query)"),
        (5, 0, ", authenticated (NTS)"),
        (6, 0, ", authenticated (NTS)"),
        (7, 0, "1 NTS NAK(s)"),
        (8, 0, "1 answer(s) ignored (the last: unauthenticated kiss-o'-death (ignored))"),
        (9, 0, "1 answer(s) ignored (the last: unauthenticated kiss-o'-death (ignored))"),
        (10, 3, "no Unique Identifier"),
        (11, 3, "stratum out of 1-15"),
        (12, 3, "NTS Authenticator does not verify"),
        (13, 3, "two NTS Authenticators"),
        (14, 3, "NTS NAK - the server did not take the cookie"),
    ];
    for (m, code, what) in answers {
        nts_stats(true);
        let r = nts_run("500", via(m));
        let st = nts_stats(false);
        case!(k, r.code == code && r.out.contains(what), "NTP answer {}: expected {} and {:?}: {} {:?}", m, code, what, r.code, r.out);
        // Every query carried a new cookie and a valid Authenticator; never more than 2.
        case!(k, matches!(st, Some((q, 0, 0, _, _)) if (1..=2).contains(&q)), "NTP answer {}: cookies never reused, Authenticators valid: {:?}", m, st);
    }

    // Without --anchor the system store does not know the test CA; --anchor without --nts.
    tcp_room();
    let r = run(&["-t", "500", "--nts", ke_server(ke(0))]);
    case!(k, r.code == 3 && r.out.contains("TLS refused") && r.out.contains("certificate refused"), "the test CA is not in the system store: {} {:?}", r.code, r.out);
    let r = run(&["--anchor", NTS_CA_PATH, ke_server(ke(0))]);
    case!(k, r.code == 2 && r.out.contains("usage: nettime"), "--anchor without --nts: {} {:?}", r.code, r.out);
    let r = run(&["--nts", "--anchor"]);
    case!(k, r.code == 2 && r.out.contains("usage: nettime"), "--anchor without a file: {} {:?}", r.code, r.out);
    // Without the net right (a channel narrowed to udp only? not possible – "net" is the
    // base of every narrowed channel); the udp right is needed for NTP after NTS-KE.
    tcp_room();
    let net_only = svc_narrow("net").unwrap_or(0);
    let r = run_via(net_only, &["-t", "500", "--nts", "--anchor", NTS_CA_PATH, ke_server(ke(0))]);
    close(net_only);
    case!(k, r.code == 3 && r.out.contains("needs the udp right"), "--nts without the udp right: NTS-KE works, NTP cannot: {} {:?}", r.code, r.out);
    unlink(NTS_CA_PATH);
    *n = k;
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
