// NTP TEST – time from the network with /bin/nettime (user/lib/ntp.rs over a UDP socket
// of netd) – only in builds with --cfg selftest.
//
//   1. /bin/ntptest: the library without a network – the query's bytes, the order of the
//      checks on an answer (Kiss-o'-Death before the timestamps, only with the right
//      Origin), the delay, the NTP era around the build date, the median
//   2. init test /bin/ntptest net: nettime against tests/ntp-stub.py on the host – correct,
//      forged, late and malformed answers, Kiss-o'-Death, silence, 2-4 servers at once,
//      the arguments, the udp right; the clock's verdict unchanged
//
// Around both: the hardware RTC minus the clock (RTC at boot + uptime) before and after –
// neither was set (a step of the clock or a write to the RTC would show).
//
// Plain NTP is not authenticated: the kernel has no way in for a time from it, and this
// test checks from the kernel's side too that the verdict on the clock stayed the same.

use alloc::string::{String, ToString};

use super::*;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[NTP TEST] FAIL: {}", format_args!($($msg)*));
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

pub fn self_test() {
    serial_println!("[NTP TEST] Starting NTP tests (user/lib/ntp.rs, nettime)...");
    crate::selftest::begin();
    let verdict0 = crate::drivers::rtc::time_status().1.is_ok();
    let gap = || crate::drivers::rtc::read_hw().to_unix() as i64 - crate::drivers::rtc::now().to_unix() as i64;
    let gap0 = gap();

    // 1. The library without a network.
    let opts = SpawnOptions { stdin: Some(alloc::vec::Vec::new()), capture: true, ..SpawnOptions::default() };
    let r = exec("/bin/ntptest", &["ntptest"], "/", &opts).ok().and_then(|id| wait_exit(id, 60_000));
    check!(r.is_some(), "ntptest did not finish");
    let (kind, out) = r.unwrap();
    let line = out.lines().find(|l| l.starts_with("ntptest:")).unwrap_or("").trim();
    check!(kind == ExitKind::Exit(0) && line.contains("checks OK"), "ntptest: {:?} {:?}", kind, out.trim());
    let checks = line.split_whitespace().nth(1).unwrap_or("?").to_string();
    serial_println!("[NTP TEST] 1/2 the library without a network: {} PASS", line);

    // 2. nettime against the servers on the host.
    let opts = SpawnOptions { stdin: Some(alloc::vec::Vec::new()), capture: true, hw_root: true, sysctl: true, input: true, blk: true, ..SpawnOptions::default() };
    let r = exec("/bin/init", &["init", "test", "/bin/ntptest", "net"], "/", &opts).ok().and_then(|id| wait_exit(id, 180_000));
    check!(r.is_some(), "init test /bin/ntptest net did not finish");
    let (kind, out) = r.unwrap();
    let line = out.lines().find(|l| l.starts_with("ntptest net:")).unwrap_or("").trim();
    check!(kind == ExitKind::Exit(0) && line.contains("cases OK"), "ntptest net: {:?} {:?}", kind, out.trim());
    let cases = line.split_whitespace().nth(2).unwrap_or("?").to_string();
    check!(crate::drivers::rtc::time_status().1.is_ok() == verdict0, "the clock's verdict changed during the NTP tests");
    let gap1 = gap();
    check!((gap1 - gap0).abs() <= 5, "hardware RTC minus the clock: {} s before, {} s after - something set one of them", gap0, gap1);
    serial_println!("[NTP TEST] 2/2 {}; hardware RTC minus the clock {} s before, {} s after PASS", line, gap0, gap1);

    serial_println!("[RESULT-NTP] ver={} checks={} cases={}", crate::shell::VERSION, checks, cases);
    serial_println!("[NTP TEST] All NTP tests passed!");
    crate::selftest::pass();
}
