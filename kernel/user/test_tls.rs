// TLS TEST – HTTPS with DeSoTLS (common/desotls: client.rs, record.rs, schedule.rs) and
// /bin/netget https:// – only in builds with --cfg selftest.
//
//   1. /bin/tlstest: RFC 8448's handshake byte for byte, records, KeyUpdate, HelloRetryRequest,
//      changed server messages (no network – common/desotls/tls_tests.rs)
//   2. init test /bin/tlstest net: netget https:// against tests/tls-stub.py on the host –
//      both cipher suites, RSA and ECDSA servers, 1 MiB, KeyUpdate both ways, HTTP framing,
//      every refusal (certificates, TLS 1.2, no X25519, a man in the middle changing the
//      Finished, the CertificateVerify, a record or replaying one) with no request reaching
//      the server for the handshake refusals
//   3. the clock not plausible: netget refuses before it even asks netd for a connection

use alloc::string::{String, ToString};

use super::*;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[TLS TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

fn wait_exit(id: TaskId, ms: u64) -> Option<(ExitKind, String)> {
    let end = crate::time::ticks() + ms;
    while sched::task_info(id).is_some() {
        if crate::time::ticks() > end {
            let _ = sched::request_exit(id);
            return None;
        }
        crate::time::sleep_ms(5);
    }
    let kind = exit_info(id)?.kind;
    Some((kind, String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned()))
}

fn run(path: &str, args: &[&str], ms: u64) -> Option<(ExitKind, String)> {
    let opts = SpawnOptions { stdin: Some(alloc::vec::Vec::new()), capture: true, ..SpawnOptions::default() };
    let id = exec(path, args, "/", &opts).ok()?;
    wait_exit(id, ms)
}

fn run_init(program: &str, arg: &str, ms: u64) -> Option<(ExitKind, String)> {
    let opts = SpawnOptions { stdin: Some(alloc::vec::Vec::new()), capture: true, hw_root: true, sysctl: true, input: true, blk: true, ..SpawnOptions::default() };
    let id = exec("/bin/init", &["init", "test", program, arg], "/", &opts).ok()?;
    wait_exit(id, ms)
}

pub fn self_test() {
    serial_println!("[TLS TEST] Starting HTTPS tests (DeSoTLS handshake and records, netget https://)...");
    crate::selftest::begin();

    // 1. The library without a network.
    let r = run("/bin/tlstest", &["tlstest"], 120_000);
    check!(r.is_some(), "tlstest did not finish");
    let (kind, out) = r.unwrap();
    let line = out.lines().find(|l| l.starts_with("tlstest:")).unwrap_or("").trim();
    check!(kind == ExitKind::Exit(0) && line.contains("checks OK"), "tlstest: {:?} {:?}", kind, out.trim());
    let line1 = String::from(line);
    let tls_lib = String::from(line.split("DeSoTLS ").nth(1).unwrap_or("?").trim_end_matches(')'));
    serial_println!("[TLS TEST] 1/3 RFC 8448 handshake byte for byte, records, KeyUpdate, HelloRetryRequest, changed server messages (no network): {} PASS", line);

    // 2. Against the servers on the host.
    let r = run_init("/bin/tlstest", "net", 240_000);
    check!(r.is_some(), "init test /bin/tlstest net did not finish");
    let (kind, out) = r.unwrap();
    let line = out.lines().find(|l| l.starts_with("tlstest net:")).unwrap_or("").trim();
    check!(kind == ExitKind::Exit(0) && line.contains("cases OK"), "tlstest net: {:?} {:?}", kind, out.trim());
    let summary = out.lines().find(|l| l.starts_with("netget: TLS 1.3")).unwrap_or("").trim();
    let line2 = String::from(line);
    serial_println!("[TLS TEST] 2/3 netget https:// against tests/tls-stub.py (OpenSSL): both cipher suites, RSA and ECDSA, 1 MiB, KeyUpdate both ways, HTTP framing, every refusal with nothing sent to the server: {}; {} PASS", summary, line);

    // 3. A clock that is not plausible: refused before anything is sent.
    crate::drivers::rtc::FORCE_IMPLAUSIBLE.store(true, core::sync::atomic::Ordering::Release);
    let r = run("/bin/netget", &["netget", "https://tls.desoos:58443/hello"], 30_000);
    crate::drivers::rtc::FORCE_IMPLAUSIBLE.store(false, core::sync::atomic::Ordering::Release);
    check!(r.is_some(), "netget did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(5) && out.contains("clock not plausible: RTC lost power (VRT clear) - nothing sent"), "netget with an implausible clock: {:?} {:?}", kind, out.trim());
    serial_println!("[TLS TEST] 3/3 clock not plausible: netget refuses before connecting (exit 5) PASS");
    let field = |l: &str, k: &str| l.split(|c| c == ' ' || c == ',').find_map(|w| w.strip_prefix(k)).unwrap_or("?").to_string();
    let checks = line1.split_whitespace().nth(1).unwrap_or("?").to_string();
    let cases = line2.split_whitespace().nth(2).unwrap_or("?").to_string();
    serial_println!(
        "[RESULT-TLS] ver={} lib={} checks={} cases={} hello_ms={} big_kbs={}",
        crate::shell::VERSION,
        tls_lib,
        checks,
        cases,
        field(&line2, "hello_ms="),
        field(&line2, "big_kbs=")
    );

    serial_println!("[TLS TEST] All HTTPS tests passed!");
    crate::selftest::pass();
}
