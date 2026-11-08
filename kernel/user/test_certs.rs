// CERT TEST – DeSoTLS (common/desotls): certificates and chains in the kernel and in user
// space, the trusted CA store /etc/certs/roots (Mozilla's, sealed), the wall clock and its
// plausibility (syscall 59), /bin/certcheck.  The library is included here only in the
// selftest build.

use alloc::string::String;
use alloc::vec::Vec;

use super::*;
use crate::desocrypto;
use crate::drivers::rtc::{self, DateTime, Implausible};
use crate::fs::FsError;
use crate::time::ticks;

#[path = "../../common/desotls/mod.rs"]
mod desotls;
#[path = "../../common/desotls/tests.rs"]
mod desotls_tests;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[CERT TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

fn wait_for(ms: u64, cond: impl Fn() -> bool) -> bool {
    let end = ticks() + ms;
    while !cond() {
        if ticks() > end {
            return false;
        }
        crate::time::sleep_ms(1);
    }
    true
}

/// Program from /bin with captured output; (how it ended, output).
fn run(path: &str, args: &[&str], ms: u64) -> Option<(ExitKind, String)> {
    let opts = SpawnOptions { capture: true, ..SpawnOptions::default() };
    let id = exec(path, args, "/", &opts).ok()?;
    if !wait_for(ms, || sched::task_info(id).is_none()) {
        let _ = sched::request_exit(id);
        return None;
    }
    let kind = exit_info(id)?.kind;
    Some((kind, String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned()))
}

fn number_after(text: &str, key: &str) -> u64 {
    let Some(i) = text.find(key) else { return 0 };
    text[i + key.len()..].bytes().take_while(|b| b.is_ascii_digit()).fold(0, |v, b| v * 10 + (b - b'0') as u64)
}

/// DER certificates as PEM text.
fn pem(certs: &[&[u8]]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for der in certs {
        s.push_str("-----BEGIN CERTIFICATE-----\n");
        let mut line = 0;
        for chunk in der.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let v = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
            for k in 0..4 {
                if k <= chunk.len() {
                    s.push(T[(v >> (18 - 6 * k) & 63) as usize] as char);
                } else {
                    s.push('=');
                }
            }
            line += 4;
            if line == 64 {
                s.push('\n');
                line = 0;
            }
        }
        if line != 0 {
            s.push('\n');
        }
        s.push_str("-----END CERTIFICATE-----\n");
    }
    s
}

fn dt(y: u16, mo: u8, d: u8, h: u8, mi: u8, s: u8) -> DateTime {
    DateTime { year: y, month: mo, day: d, hour: h, minute: mi, second: s }
}

pub fn self_test() {
    serial_println!("[CERT TEST] Starting DeSoTLS {} tests...", desotls::VERSION);
    crate::selftest::begin();

    // 1. Every DeSoTLS test inside the kernel.
    let t0 = ticks();
    let r = desotls_tests::run();
    check!(r.is_ok(), "in the kernel: {:?}", r.err());
    let n = r.unwrap_or(0);
    serial_println!("[CERT TEST] 1/6 in the kernel: {} checks (strict DER, times, host names and wildcards, PEM, the store format, 115 chain cases - every rule of the profile right and wrong, limits - and 12 real server chains) in {} ms PASS", n, ticks() - t0);

    // 2. The store as installed: the bytes of the image, sealed, Mozilla's anchors usable,
    // the real chains against it.
    let data = crate::fs::read_file("/etc/certs/roots");
    check!(data.as_deref().ok() == Some(crate::initrd::ETC_CERTS_ROOTS), "/etc/certs/roots differs from the image");
    let data = data.unwrap_or_default();
    for p in ["/etc/certs/roots", "/etc/certs", "/etc"] {
        check!(crate::fs::is_sealed(p), "{} is not sealed", p);
    }
    check!(!crate::fs::is_sealed("/etc/services"), "/etc/services must stay writable");
    let r = desotls_tests::real_store(&data);
    check!(r.is_ok(), "the Mozilla store: {:?}", r.err());
    let (anchors, usable) = r.unwrap_or((0, 0));
    let tag = desotls::roots::Roots::parse(&data).map(|r| r.nss_tag).unwrap_or("?");
    serial_println!("[CERT TEST] 2/6 /etc/certs/roots = the image's ({}, {} bytes): {} anchors, {} usable, sealed (file, /etc/certs, /etc); real chains against it PASS", tag, data.len(), anchors, usable);

    // 3. The same in user space.
    let r = run("/bin/certtest", &["certtest"], 120_000);
    check!(r.is_some(), "certtest did not finish");
    let (kind, out) = r.unwrap_or((ExitKind::Exit(-1), String::new()));
    let out = out.trim();
    check!(kind == ExitKind::Exit(0) && out.contains(&alloc::format!("{} checks OK", n)) && out.contains(&alloc::format!("{} anchors", anchors)), "certtest: {:?} {:?}", kind, out);
    serial_println!("[CERT TEST] 3/6 user space: {} PASS", out);

    // 4. The seal: a program tries every way, then the kernel itself (write, truncate,
    // remove, rename, mount over it).
    let r = run("/bin/certtest", &["certtest", "seal"], 60_000);
    check!(r.is_some(), "certtest seal did not finish");
    let (kind, out) = r.unwrap_or((ExitKind::Exit(-1), String::new()));
    check!(kind == ExitKind::Exit(0) && out.contains("attempts refused"), "certtest seal: {:?} {:?}", kind, out.trim());
    let user_refused = number_after(&out, "seal: ");
    let imm = |r: crate::fs::Result<()>| r == Err(FsError::Immutable);
    check!(imm(crate::fs::write_file("/etc/certs/roots", b"evil")), "kernel write_file allowed");
    check!(imm(crate::fs::truncate("/etc/certs/roots", 0)), "kernel truncate allowed");
    check!(crate::fs::write("/etc/certs/roots", 0, b"x") == Err(FsError::Immutable), "kernel write allowed");
    check!(imm(crate::fs::remove("/etc/certs/roots")), "kernel remove of the file allowed");
    check!(imm(crate::fs::remove("/etc/certs")), "kernel remove of /etc/certs allowed");
    check!(imm(crate::fs::remove("/etc")), "kernel remove of /etc allowed");
    check!(imm(crate::fs::mkdir("/etc/certs/k")), "kernel mkdir in /etc/certs allowed");
    check!(imm(crate::fs::create("/etc/k")), "kernel create in /etc allowed");
    check!(imm(crate::fs::rename("/etc/certs/roots", "/certs-moved")), "rename of the store allowed");
    check!(crate::fs::write_file("/certs-other", b"x").is_ok(), "cannot write /certs-other");
    check!(imm(crate::fs::rename("/certs-other", "/etc/certs/roots")), "rename over the store allowed");
    check!(imm(crate::fs::rename("/certs-other", "/etc/new")), "rename into /etc allowed");
    let _ = crate::fs::remove("/certs-other");
    check!(imm(crate::fs::rename("/etc", "/etc2")), "rename of /etc allowed");
    check!(imm(crate::fs::rename("/etc/certs", "/certs")), "rename of /etc/certs allowed");
    for at in ["/etc/certs", "/etc"] {
        let m = crate::fs::mount(at, alloc::boxed::Box::new(crate::fs::ramfs::RamFs::new()));
        check!(m == Err(FsError::Immutable), "mount over {}: {:?}", at, m);
    }
    check!(crate::fs::read_file("/etc/certs/roots").as_deref().ok() == Some(crate::initrd::ETC_CERTS_ROOTS), "/etc/certs/roots changed");
    let h = desocrypto::sha256::sha256(crate::initrd::ETC_CERTS_ROOTS);
    let mut hx = [0u8; 64];
    let hx = desocrypto::hex(&h, &mut hx).unwrap_or("");
    check!(out.contains(hx), "certtest saw another sha256: {:?}", out.trim());
    serial_println!("[CERT TEST] 4/6 seal: {} attempts from a program refused (open for writing / truncate / create, unlink, mkdir, relative paths, '..', directory handles) and 15 from the kernel (write, truncate, remove, mkdir, create, rename from / to / into, mount over /etc and /etc/certs); /etc/services still writable; sha256 {} unchanged PASS", user_refused, &hx[..16]);

    // 5. The clock: the verdict rules on made-up readings, then the real one (QEMU: plausible)
    // and syscall 59 from a program.
    let base = dt(2026, 6, 1, 12, 0, 0);
    let b = base.to_unix();
    check!(rtc::assess(&base, true, true, b).is_ok(), "a normal reading refused");
    check!(rtc::assess(&base, false, true, b) == Err(Implausible::BatteryLost), "VRT clear accepted");
    check!(rtc::assess(&base, true, false, b) == Err(Implausible::Unstable), "an unstable reading accepted");
    for bad in [dt(2026, 13, 1, 0, 0, 0), dt(2026, 0, 1, 0, 0, 0), dt(2026, 4, 31, 0, 0, 0), dt(2027, 2, 29, 0, 0, 0), dt(2026, 6, 0, 0, 0, 0), dt(2026, 6, 1, 24, 0, 0), dt(2026, 6, 1, 0, 60, 0), dt(2026, 6, 1, 0, 0, 60)] {
        check!(rtc::assess(&bad, true, true, 0) == Err(Implausible::BadFields), "fields accepted: {}", bad);
    }
    check!(rtc::assess(&dt(2028, 2, 29, 0, 0, 0), true, true, 0).is_ok(), "29 February 2028 refused");
    check!(rtc::assess(&base, true, true, b + rtc::BUILD_SLACK).is_ok(), "24 h before the build date refused");
    check!(rtc::assess(&base, true, true, b + rtc::BUILD_SLACK + 1) == Err(Implausible::BeforeBuild), "earlier than the build date accepted");
    check!(rtc::assess(&dt(2100, 1, 1, 0, 0, 0), true, true, 0) == Err(Implausible::TooLate), "2100 accepted");
    let (secs, verdict) = rtc::time_status();
    check!(verdict.is_ok(), "the clock is not plausible in QEMU: {:?}", verdict);
    let r = run("/bin/certtest", &["certtest", "clock"], 30_000);
    check!(r.is_some(), "certtest clock did not finish");
    let (kind, out) = r.unwrap_or((ExitKind::Exit(-1), String::new()));
    let mut w = out.trim().trim_start_matches("certtest clock: ").split(' ').map(|x| x.parse::<u64>().unwrap_or(u64::MAX));
    let (us, st, be) = (w.next().unwrap_or(0), w.next().unwrap_or(1), w.next().unwrap_or(0));
    check!(kind == ExitKind::Exit(0) && us.abs_diff(secs) <= 2 && st == 0 && be == rtc::BUILD_EPOCH, "syscall 59: {:?} {:?} (kernel {} s)", kind, out.trim(), secs);
    serial_println!("[CERT TEST] 5/6 clock: 15 made-up readings judged (VRT, unstable, fields, 29 February, build date - 24 h, 2100); now {} UTC plausible, syscall 59 the same (build date {} UTC from {}) PASS", DateTime::from_unix(secs), DateTime::from_unix(rtc::BUILD_EPOCH), rtc::BUILD_EPOCH_SOURCE);

    // 6. /bin/certcheck on a real chain (Amazon's demo server under Amazon Root CA 1, in
    // Mozilla's store): OK at its time, refused for another host and when expired; no
    // certificate, a missing file.
    let Some((host, when, _anchor, chain, nc)) = desotls_tests::real_case(5) else {
        check!(false, "no real chain 5");
        return;
    };
    let text = pem(&chain[..nc]);
    check!(crate::fs::write_file("/certs-chain.pem", text.as_bytes()).is_ok(), "cannot write /certs-chain.pem");
    check!(crate::fs::write_file("/certs-none.pem", b"no certificate here\n").is_ok(), "cannot write /certs-none.pem");
    let when_s = alloc::format!("{}", when);
    let cases: [(&[&str], i64, &str); 6] = [
        (&["certcheck", "/certs-chain.pem", host, "--time", &when_s], 0, "certcheck: OK"),
        (&["certcheck", "/certs-chain.pem", "--time", &when_s], 0, "Amazon Root CA 1"),
        (&["certcheck", "/certs-chain.pem", "wrong.example.com", "--time", &when_s], 1, "host name does not match"),
        (&["certcheck", "/certs-chain.pem", host, "--time", "1900000000"], 1, "certificate expired"),
        (&["certcheck", "/certs-none.pem", host, "--time", &when_s], 1, "no certificate"),
        (&["certcheck", "/certs-missing.pem", host], 2, "certcheck: /certs-missing.pem"),
    ];
    let mut lines = Vec::new();
    for (args, code, want) in cases.iter() {
        let r = run("/bin/certcheck", args, 30_000);
        check!(r.is_some(), "certcheck {:?} did not finish", args);
        let (kind, out) = r.unwrap_or((ExitKind::Exit(-1), String::new()));
        check!(kind == ExitKind::Exit(*code) && out.contains(want), "certcheck {:?}: {:?} {:?}", args, kind, out.trim());
        lines.push(out);
    }
    let _ = crate::fs::remove("/certs-chain.pem");
    let _ = crate::fs::remove("/certs-none.pem");
    let ok_line = lines[0].lines().find(|l| l.starts_with("certcheck: OK")).unwrap_or("").trim();
    serial_println!("[CERT TEST] 6/6 certcheck: {:?}; wrong host, expired, no certificate -> exit 1, missing file -> exit 2 PASS", ok_line);

    serial_println!("[RESULT-CERTS] ver={} lib={} checks={} anchors={} usable={} store={} sealed_refused={}", crate::shell::VERSION, desotls::VERSION, n, anchors, usable, tag, user_refused + 15);
    serial_println!("[CERT TEST] All certificate tests passed!");
    crate::selftest::pass();
}
