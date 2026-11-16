// NTS TEST – the time service (/bin/timekeeper, v0.79 stage D) and the kernel's side of it
// (SYS_TIME_SET, SYS_TIME_BOUND, time_lkg.rs set_time) – only in builds with --cfg selftest.
//
//   1. /bin/synctest: the arithmetic without a network – the interval of one answer, the
//      quorum and the envelope, a tie, one vote per operator, the NTS-KE backoff, the span of
//      the second check, the kept chain (24 KiB / 8 certificates)
//   2. the kernel alone (RAM volume at /disk): the numbers SYS_TIME_SET refuses; L = floor(T -
//      U - 2 s) raised and saved; never lower; the clock never below the LKG; an unreadable
//      file written anew with max(L, LKG in memory) even when L is lower; a repair write that
//      fails keeps reason 8 and the next call retries it; SYS_TIME_BOUND's B; the wall clock
//      moved back and forth while two programs read it (each reading one clock or the other)
//      and sleep (the uptime untouched)
//   3. the right: /bin/timetest set (no handle, another kind, SETTIME without WRITE, every
//      number out of range, an LKG lowered – refused, nothing changed, every refusal in the
//      DCP audit), /bin/timetest bound (the 40-byte buffer); timekeeper without SETTIME or
//      with a server given as an argument – refused
//   4. timekeeper against tests/nts-server (init test /bin/timekeeper test:<case>, the clock
//      plausible – no bootstrap): two operators set the clock and raise the LKG; one server,
//      two that disagree, two entries of one operator, a tie, an NTS-KE that sends NTP to
//      another entry's server – nothing; two servers 1.8 s apart – U >= 0.9 s + their own
//   5. recovery: the LKG file damaged (reason 8) – one operator alone sets nothing (still
//      reason 8), a chain not valid yet has no vote; bootstrap with B = the build date, the
//      second check on each kept chain, two of three operators, the file written anew, reason
//      8 gone, the clock plausible, read back from the disk the same
//   6. the second check (bootstrap with the RTC "battery lost"): a server certificate not
//      valid yet, a time after its CA expired, an intermediate that ends inside T +- U (valid
//      at T itself), an intermediate expired at T – each thrown out, the other two set the
//      clock; expired before B, a wrong name – refused in the first step, one left: nothing
//   7. the bound B: reason 7 with a good file – B = the LKG (2046), a chain ending 2045 refused
//      in the first step, no recovery; reason 8 with the LKG 2046 in memory – B = 2046 too
//      (not the build date), refused; the kernel refuses a time below the LKG
//
// Between the cases the wall clock, the LKG in memory and the file go back to a known state;
// at the end the RAM volume goes and everything is as before the suite.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use super::*;
use crate::drivers::rtc::{self, Implausible as I};
use crate::fs;
use crate::time_lkg::{self as lkg, FileState, Refused, Source};

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[NTS TEST] FAIL: {}", format_args!($($msg)*));
            cleanup();
            return;
        }
    };
}

const MOUNT: &str = lkg::SYSTEM_MOUNT;
static mut DISK: Option<usize> = None;
static mut MADE_DIR: bool = false;
/// 2046-01-01 00:00:00 UTC – after the test CA (2045), before the NTS test chain (2060).
const Y2046: u64 = 2_398_377_600;

fn wait_for(ms: u64, cond: impl Fn() -> bool) -> bool {
    let end = crate::time::ticks() + ms;
    while !cond() {
        if crate::time::ticks() > end {
            return false;
        }
        crate::time::sleep_ms(2);
    }
    true
}

fn finish(id: TaskId, ms: u64) -> Option<(ExitKind, String)> {
    if !wait_for(ms, || sched::task_info(id).is_none()) {
        let _ = sched::request_exit(id);
        return None;
    }
    let kind = exit_info(id)?.kind;
    Some((kind, String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned()))
}

fn run(path: &str, args: &[&str], settime: bool, ms: u64) -> Option<(ExitKind, String)> {
    let opts = SpawnOptions { stdin: Some(Vec::new()), capture: true, settime, ..SpawnOptions::default() };
    let id = exec(path, args, "/", &opts).ok()?;
    finish(id, ms)
}

/// `init test /bin/timekeeper test:<case>` with the handles init gets at boot.
fn keeper(case: &str, settime: bool) -> (ExitKind, String) {
    let arg = alloc::format!("test:{}", case);
    let opts = SpawnOptions { stdin: Some(Vec::new()), capture: true, hw_root: true, sysctl: true, input: true, blk: true, settime, ..SpawnOptions::default() };
    match exec("/bin/init", &["init", "test", "/bin/timekeeper", &arg], "/", &opts).ok().and_then(|id| finish(id, 120_000)) {
        Some(r) => r,
        None => (ExitKind::Exit(-1), String::from("did not finish")),
    }
}

/// The result line of a timekeeper round.
fn result(out: &str) -> &str {
    out.lines().find(|l| l.starts_with("timekeeper: result:")).unwrap_or("(no result line)").trim()
}

/// The "+-N ms" of the result line.
fn result_u(out: &str) -> Option<u64> {
    let r = result(out);
    let rest = r.split("+-").nth(1)?;
    rest.split(' ').next()?.parse().ok()
}

fn mount_ram() -> Result<(), String> {
    let d = crate::block::register(Box::new(crate::block::RamDisk::new("ntstest", 1024 * 8))).unwrap_or(usize::MAX);
    unsafe { DISK = Some(d) };
    let p = crate::fs::desofs::format::Params { uuid: core::array::from_fn(|i| 0x30 + i as u8), time: 1_700_000_000, label: "NTS-TEST" };
    crate::fs::desofs::format::format(d, &p).map_err(|e| alloc::format!("format: {}", e))?;
    if fs::stat(MOUNT).is_err() {
        unsafe { MADE_DIR = true };
    }
    match fs::mount_disk(d, MOUNT) {
        fs::DiskMount::DeSoFs(None) => Ok(()),
        other => Err(alloc::format!("mount: {:?}", other)),
    }
}

/// Damages the LKG file on the volume (as a bad sector would) and reads it again: reason 8,
/// the LKG in memory kept.
fn damage() -> bool {
    let mut ok = false;
    fs::with_desofs_at(MOUNT, &mut |v| {
        use crate::fs::FileSystem;
        let mut b = [0u8; 1];
        ok = v.read(lkg::FILE, 20, &mut b).is_ok() && v.write(lkg::FILE, 20, &[b[0] ^ 0x40]).is_ok();
    });
    lkg::load();
    ok && matches!(lkg::file_state(), FileState::Unreadable(_))
}

fn file_bytes() -> Option<Vec<u8>> {
    fs::read_file(&alloc::format!("{}{}", MOUNT, lkg::FILE)).ok()
}

/// A known state: no file on the volume, nothing in memory, the RTC's clock, no forcing.
fn fresh() {
    rtc::FORCE_IMPLAUSIBLE.store(false, core::sync::atomic::Ordering::Release);
    lkg::FAIL_SAVES.store(0, core::sync::atomic::Ordering::Release);
    fs::with_desofs_at(MOUNT, &mut |v| {
        use crate::fs::FileSystem;
        let _ = v.remove(lkg::FILE);
        let _ = v.remove(lkg::TEMP);
    });
    rtc::reset_wall_for_test();
    lkg::reset_for_test();
    lkg::load();
}

fn cleanup() {
    rtc::FORCE_IMPLAUSIBLE.store(false, core::sync::atomic::Ordering::Release);
    lkg::FAIL_SAVES.store(0, core::sync::atomic::Ordering::Release);
    rtc::reset_wall_for_test();
    let _ = fs::unmount(MOUNT);
    if let Some(d) = unsafe { core::ptr::replace(core::ptr::addr_of_mut!(DISK), None) } {
        crate::block::remove(d);
    }
    if unsafe { MADE_DIR } {
        let _ = fs::remove(MOUNT);
        unsafe { MADE_DIR = false };
    }
    lkg::reset_for_test();
    lkg::load();
}

pub fn self_test() {
    serial_println!("[NTS TEST] Starting the time service tests (timekeeper, SYS_TIME_SET, SYS_TIME_BOUND)...");
    crate::selftest::begin();
    let now = || rtc::time_status().0;
    let ok = |r: &(ExitKind, String), code: i64| r.0 == ExitKind::Exit(code);

    // 1. The arithmetic.
    let r = run("/bin/synctest", &["synctest"], false, 60_000);
    check!(r.is_some(), "synctest did not finish");
    let (kind, out) = r.unwrap_or((ExitKind::Exit(-1), String::new()));
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "synctest: {:?} {:?}", kind, out.trim());
    serial_println!("[NTS TEST] 1/7 {} PASS", out.trim());

    // 2. The kernel alone.
    let m = mount_ram();
    check!(m.is_ok(), "{:?}", m.err());
    fresh();
    check!(lkg::file_state() == FileState::Missing && !rtc::synced(), "fresh: {:?}", lkg::file_state());
    let build = rtc::BUILD_EPOCH * 1000;
    let refusals: [((u64, u64, u64), Refused); 12] = [
        ((build + 86_400_000, 1000, 0), Refused::Servers),
        ((build + 86_400_000, 1000, 1), Refused::Servers),
        ((build + 86_400_000, 1000, 4), Refused::Servers),
        ((build + 86_400_000, 1000, u64::MAX), Refused::Servers),
        ((build + 86_400_000, 10_001, 2), Refused::Uncertainty),
        ((build + 999, 1000, 2), Refused::BeforeBuild),
        ((500, 1000, 2), Refused::Overflow),
        ((u64::MAX, 1, 2), Refused::Overflow),
        ((u64::MAX - 5, 10, 3), Refused::Overflow),
        ((rtc::LATEST * 1000 + 500, 500, 2), Refused::TooLate),
        ((0, 0, 2), Refused::BeforeBuild),
        ((build + 86_400_000, u64::MAX, 2), Refused::Uncertainty),
    ];
    for ((t, u, s), want) in refusals.iter() {
        check!(lkg::check_set(*t, *u, *s) == Err(*want), "check_set({}, {}, {}) = {:?}, expected {:?}", t, u, s, lkg::check_set(*t, *u, *s), want);
    }
    check!(lkg::check_set(rtc::LATEST * 1000 + 499, 500, 3).is_ok() && lkg::check_set(build + 1000, 1000, 2).is_ok() && lkg::check_set(build, 0, 2).is_ok(), "the edges of the range refused");
    check!(!rtc::synced() && lkg::bound() == 0 && lkg::file_state() == FileState::Missing, "a refusal changed something");
    // A raise: L = floor(T - U - 2 s).
    let t = now() * 1000 + 700;
    let d = lkg::set_time(t, 1000, 2);
    let l = (t - 3000) / 1000;
    check!(d.map(|d| (d.raised, d.saved, d.repair, d.not_saved, d.lkg)) == Ok((true, true, false, false, l)), "a raise: {:?}, L should be {}", d, l);
    check!(file_bytes().as_deref() == Some(&lkg::encode(l, Source::Nts)[..]) && lkg::source() == Source::Nts && lkg::file_state() == FileState::Good, "the file after a raise");
    check!(rtc::synced() && (rtc::now_ms() as i64 - t as i64).abs() < 2000 && rtc::time_status().1.is_ok(), "the clock after a raise: {} vs {}", rtc::now_ms(), t);
    check!(lkg::describe_sync().contains("from 2 NTS servers"), "date: {}", lkg::describe_sync());
    // Never lower: a whole interval below the LKG is refused.
    check!(lkg::set_time((l - 10) * 1000, 1000, 2) == Err(Refused::BelowLkg) && lkg::bound() == l, "a time below the LKG");
    check!(lkg::set_time(l * 1000 - 1001, 1000, 2) == Err(Refused::BelowLkg), "1 ms below the LKG");
    // L not above the LKG: nothing written, the clock corrected.
    let d = lkg::set_time(l * 1000 + 500, 1000, 3);
    check!(d.map(|d| (d.raised, d.saved, d.clock_ms)) == Ok((false, false, l * 1000 + 500)), "L below the LKG: {:?}", d);
    // T below the LKG, T + U not: the clock is set to the LKG, never below.
    let d = lkg::set_time(l * 1000 - 500, 1000, 2);
    check!(d.map(|d| d.clock_ms) == Ok(l * 1000), "the clock below the LKG: {:?}", d);
    // Repair: the LKG in memory higher than L, the file damaged – written with the LKG in
    // memory (its own source), not with L.
    let x = now() + 100;
    check!(lkg::raise_for_test(x) == lkg::Raised::Saved, "raise_for_test");
    check!(damage(), "could not damage the file");
    check!(lkg::bound() == x && rtc::time_status().1 == Err(I::LkgUnreadable), "after the damage: {} {:?}", lkg::bound(), rtc::time_status().1);
    let snap = lkg::snapshot();
    check!(snap.bound == x && snap.lkg == x && snap.file == 4 && snap.flags & lkg::FLAG_RECOVERY != 0 && snap.flags & lkg::FLAG_PLAUSIBLE == 0, "the snapshot in recovery: {:?}", snap);
    let d = lkg::set_time(x * 1000 + 500, 1000, 2);
    check!(d.map(|d| (d.raised, d.saved, d.repair, d.lkg)) == Ok((false, true, true, x)), "repair with L below the LKG in memory: {:?}", d);
    check!(file_bytes().as_deref() == Some(&lkg::encode(x, Source::Test)[..]) && lkg::file_state() == FileState::Good && rtc::time_status().1.is_ok(), "the repaired file: {:?}", lkg::file_state());
    // A repair write that fails: reason 8 stays, the next call writes.
    check!(damage(), "could not damage the file again");
    lkg::FAIL_SAVES.store(1, core::sync::atomic::Ordering::Release);
    let d = lkg::set_time(x * 1000 + 600, 1000, 2);
    check!(d.map(|d| (d.saved, d.repair, d.not_saved)) == Ok((false, true, true)), "a failed repair: {:?}", d);
    check!(matches!(lkg::file_state(), FileState::Unreadable(_)) && rtc::time_status().1 == Err(I::LkgUnreadable) && lkg::describe().contains("NOT SAVED"), "after a failed repair: {:?} {:?}", lkg::file_state(), rtc::time_status().1);
    let d = lkg::set_time(x * 1000 + 700, 1000, 2);
    check!(d.map(|d| (d.saved, d.repair, d.not_saved)) == Ok((true, true, false)) && lkg::file_state() == FileState::Good, "the retry: {:?}", d);
    // The wall clock moved back and forth while two programs read it.
    let (a, b) = (now() + 86_400, now() + 2 * 86_400);
    let (sa, sb) = (alloc::format!("{}", a), alloc::format!("{}", b));
    let opts = SpawnOptions { stdin: Some(Vec::new()), capture: true, ..SpawnOptions::default() };
    rtc::set_wall_ms(a * 1000);
    let ids: Vec<TaskId> = (0..2).filter_map(|_| exec("/bin/timetest", &["timetest", "clock", &sa, &sb, "1500"], "/", &opts).ok()).collect();
    check!(ids.len() == 2, "could not start timetest clock");
    let up0 = crate::time::uptime_ms();
    let mut flips = 0u64;
    while ids.iter().any(|&id| sched::task_info(id).is_some()) && crate::time::uptime_ms() - up0 < 20_000 {
        rtc::set_wall_ms(if flips % 2 == 0 { b * 1000 } else { a * 1000 });
        flips += 1;
        crate::time::sleep_ms(1);
    }
    let mut lines = String::new();
    for id in ids {
        let r = finish(id, 5000);
        check!(r.as_ref().is_some_and(|r| r.0 == ExitKind::Exit(0) && r.1.contains("readings")), "timetest clock: {:?}", r);
        lines = r.map(|r| String::from(r.1.trim())).unwrap_or_default();
    }
    let t0 = crate::time::uptime_ms();
    rtc::set_wall_ms(a * 1000);
    crate::time::sleep_ms(100);
    rtc::set_wall_ms(1_000_000_000_000);
    crate::time::sleep_ms(100);
    let slept = crate::time::uptime_ms() - t0;
    check!((200..1000).contains(&slept), "two sleeps of 100 ms around clock steps took {} ms of uptime", slept);
    fresh();
    serial_println!("[NTS TEST] 2/7 the kernel: {} refusals of the numbers; L = floor(T - U - 2 s) raised and saved; below the LKG refused; the clock never below the LKG; repair writes max(L, LKG in memory); a failed repair keeps reason 8 and is retried; the clock stepped {} times while two programs read it ({}); sleeps untouched PASS", refusals.len(), flips, lines.trim_start_matches("timetest "));

    // 3. The right.
    let ahead = now() + 3600;
    check!(lkg::raise_for_test(ahead) == lkg::Raised::Saved, "raise ahead");
    let audit0 = super::dcp::refusals();
    let r = run("/bin/timetest", &["timetest", "set"], true, 30_000);
    check!(r.as_ref().is_some_and(|r| ok(r, 0) && r.1.contains("nothing changed")), "timetest set: {:?}", r);
    let set_line = r.map(|r| String::from(r.1.trim())).unwrap_or_default();
    let audited = super::dcp::refusals() - audit0;
    check!(audited >= 17, "only {} refusals in the DCP audit", audited);
    check!(lkg::bound() == ahead && file_bytes().as_deref() == Some(&lkg::encode(ahead, Source::Test)[..]) && !rtc::synced(), "timetest set changed something");
    let r = run("/bin/timetest", &["timetest", "bound"], false, 30_000);
    check!(r.as_ref().is_some_and(|r| ok(r, 0) && r.1.contains("cases OK")), "timetest bound: {:?}", r);
    let bound_line = r.map(|r| String::from(r.1.trim())).unwrap_or_default();
    let r = run("/bin/timekeeper", &["timekeeper"], false, 30_000);
    check!(r.as_ref().is_some_and(|r| ok(r, 2) && r.1.contains("no SETTIME handle")), "timekeeper without SETTIME: {:?}", r);
    let r = run("/bin/timekeeper", &["timekeeper", "tls.desoos:58600"], true, 30_000);
    check!(r.as_ref().is_some_and(|r| ok(r, 2) && r.1.contains("takes no arguments")), "timekeeper with a server as an argument: {:?}", r);
    let r = keeper("two", false);
    check!(ok(&r, 2) && r.1.contains("no SETTIME handle"), "init test timekeeper without SETTIME: {:?}", r);
    check!(lkg::bound() == ahead && !rtc::synced(), "something changed");
    fresh();
    serial_println!("[NTS TEST] 3/7 the right: {}; {} refusals in the DCP audit; {}; timekeeper without SETTIME or with a server given - refused PASS", set_line.trim_start_matches("timetest "), audited, bound_line.trim_start_matches("timetest "));

    // 4. timekeeper, the clock plausible.
    let r = keeper("two", true);
    check!(ok(&r, 0) && result(&r.1).contains("set from 2 operators (alpha, beta)") && result(&r.1).contains("raised") && !r.1.contains("bootstrap"), "two operators: {:?}", r);
    check!(rtc::synced() && lkg::source() == Source::Nts && lkg::file_state() == FileState::Good && lkg::bound() > rtc::BUILD_EPOCH, "after two operators: {:?} {:?}", lkg::source(), lkg::file_state());
    let two = String::from(result(&r.1));
    let cases: [(&str, i64, &str); 5] = [
        ("one", 3, "no quorum - 1 operator(s) answered"),
        ("disagree", 3, "no two operators agree"),
        ("sameop", 3, "no quorum - 1 operator(s) answered"),
        ("tie", 3, "ambiguous quorum"),
        ("redirect", 3, "no quorum - 1 operator(s) answered"),
    ];
    for (case, code, want) in cases.iter() {
        fresh();
        let r = keeper(case, true);
        check!(ok(&r, *code) && result(&r.1).contains(want), "{}: {:?}", case, r);
        check!(!rtc::synced() && lkg::bound() == 0 && lkg::file_state() == FileState::Missing, "{}: something was set", case);
    }
    fresh();
    let r = keeper("apart", true);
    let u = result_u(&r.1).unwrap_or(0);
    check!(ok(&r, 0) && u >= 900 + 1000 && u <= 4000, "two servers 1.8 s apart: U {} {:?}", u, r);
    fresh();
    serial_println!("[NTS TEST] 4/7 timekeeper (clock plausible): {}; one server, two that disagree, one operator twice, a tie (ambiguous), NTP sent to another entry's server - nothing set; 1.8 s apart - U {} ms PASS", two.trim_start_matches("timekeeper: result: "), u);

    // 5. Recovery: the file damaged, nothing in memory.
    let first = now().saturating_sub(30).max(rtc::BUILD_EPOCH + 1);
    let damaged_empty = || {
        if lkg::file_state() != FileState::Good && lkg::raise_for_test(first) != lkg::Raised::Saved {
            return false;
        }
        let d = damage();
        lkg::reset_for_test();
        lkg::load();
        d && matches!(lkg::file_state(), FileState::Unreadable(_)) && lkg::bound() == 0 && rtc::time_status().1 == Err(I::LkgUnreadable)
    };
    check!(damaged_empty(), "not reason 8: {:?} {:?}", lkg::file_state(), rtc::time_status().1);
    // Recovery is no exception to the rules: one operator alone sets nothing, the file stays
    // unreadable; a chain that fails the second check has no vote.
    let r = keeper("refused", true);
    check!(ok(&r, 3) && r.1.contains("timekeeper: recovery:") && result(&r.1).contains("1 operator(s) answered"), "recovery with one operator: {:?}", r);
    check!(matches!(lkg::file_state(), FileState::Unreadable(_)) && !rtc::synced() && lkg::bound() == 0, "recovery with one operator changed something");
    let r = keeper("notyet", true);
    let line = r.1.lines().find(|l| l.contains("(alpha): second check over")).unwrap_or("");
    check!(ok(&r, 0) && r.1.contains("timekeeper: recovery:") && line.contains("failed") && result(&r.1).contains("set from 2 operators (beta, gamma)") && result(&r.1).contains("written anew"), "recovery with a chain not valid yet: {:?}", r);
    fresh();
    check!(damaged_empty(), "not reason 8 again: {:?} {:?}", lkg::file_state(), rtc::time_status().1);
    let r = keeper("three", true);
    check!(ok(&r, 0) && r.1.contains("timekeeper: recovery: last known good time unreadable") && r.1.contains("bootstrap"), "recovery: {:?}", r);
    check!(r.1.matches("second check over").filter(|_| true).count() >= 2 && r.1.contains("(alpha): second check over") && r.1.contains("passed"), "recovery: second checks: {:?}", r.1);
    check!(result(&r.1).contains("set from 2 operators (alpha, beta)") && result(&r.1).contains("unreadable LKG file written anew"), "recovery result: {:?}", result(&r.1));
    let saved = lkg::bound();
    check!(lkg::file_state() == FileState::Good && lkg::source() == Source::Nts && rtc::time_status().1.is_ok() && saved > rtc::BUILD_EPOCH, "after the recovery: {:?} {:?} {}", lkg::file_state(), rtc::time_status().1, saved);
    lkg::reset_for_test();
    lkg::load();
    check!(lkg::file_state() == FileState::Good && lkg::bound() == saved && lkg::source() == Source::Nts && file_bytes().as_deref() == Some(&lkg::encode(saved, Source::Nts)[..]), "read back after the recovery: {:?} {}", lkg::file_state(), lkg::bound());
    let rec = String::from(result(&r.1));
    fresh();
    serial_println!("[NTS TEST] 5/7 recovery from an unreadable LKG: one operator alone - nothing, still reason 8; a chain not valid yet - no vote, the other two repair the file; bootstrap with B = the build date, second checks passed, {}; reason 8 gone, read back from the disk the same PASS", rec.trim_start_matches("timekeeper: result: "));

    // 6. The second check: bootstrap with the RTC "battery lost", no file.
    let second: [(&str, &str); 4] = [
        ("notyet", "certificate not yet valid"),
        ("late", "certificate expired"),
        ("edge", "certificate expired"),
        ("intexpired", "certificate expired"),
    ];
    for (case, why) in second.iter() {
        fresh();
        rtc::FORCE_IMPLAUSIBLE.store(true, core::sync::atomic::Ordering::Release);
        let r = keeper(case, true);
        let line = r.1.lines().find(|l| l.contains("(alpha): second check over")).unwrap_or("");
        check!(ok(&r, 0) && line.contains("failed") && line.contains(why) && line.contains("no vote"), "{}: the second check: {:?}", case, r);
        check!(r.1.contains("bootstrap") && !r.1.contains("recovery"), "{}: bootstrap without recovery: {:?}", case, r.1);
        check!(result(&r.1).contains("set from 2 operators (beta, gamma)"), "{}: {:?}", case, result(&r.1));
        check!(rtc::time_status().1.is_ok(), "{}: the clock not plausible after the time service set it: {:?}", case, rtc::time_status().1);
    }
    fresh();
    rtc::FORCE_IMPLAUSIBLE.store(true, core::sync::atomic::Ordering::Release);
    let r = keeper("refused", true);
    check!(ok(&r, 3) && r.1.contains("TLS refused: certificate refused: certificate expired") && r.1.contains("TLS refused: certificate refused: host name does not match"), "refused in the first step: {:?}", r);
    check!(result(&r.1).contains("1 operator(s) answered") && !rtc::synced() && lkg::bound() == 0, "refused: {:?}", result(&r.1));
    fresh();
    serial_println!("[NTS TEST] 6/7 the second check on the kept chain (bootstrap, RTC battery lost): not valid yet, after the CA expired, an intermediate ending inside T +- U, an intermediate expired - thrown out, the other two set the clock; expired before B and a wrong name refused in the first step PASS");

    // 7. The bound B.
    check!(lkg::raise_for_test(Y2046) == lkg::Raised::Saved && rtc::time_status().1 == Err(I::BeforeLkg), "LKG 2046");
    let s = lkg::snapshot();
    check!(s.bound == Y2046 && s.file == 3 && s.flags & lkg::FLAG_RECOVERY == 0, "B with reason 7: {:?}", s);
    let r = keeper("rsa", true);
    check!(ok(&r, 4) && r.1.contains("2046-01-01 00:00:00 UTC (the last known good time in memory)") && !r.1.contains("recovery"), "reason 7: {:?}", r);
    check!(r.1.contains("TLS refused: certificate refused: certificate expired") && result(&r.1).contains("refused by the kernel"), "reason 7: {:?}", r.1);
    check!(lkg::bound() == Y2046 && file_bytes().as_deref() == Some(&lkg::encode(Y2046, Source::Test)[..]) && !rtc::synced(), "reason 7 changed the LKG");
    check!(damage(), "could not damage the 2046 file");
    let s = lkg::snapshot();
    check!(s.bound == Y2046 && s.file == 4 && s.flags & lkg::FLAG_RECOVERY != 0, "B with reason 8 and the LKG 2046 in memory: {:?}", s);
    let r = keeper("rsa", true);
    check!(ok(&r, 4) && r.1.contains("recovery: last known good time unreadable - bootstrap bound = 2046-01-01 00:00:00 UTC"), "reason 8 with 2046 in memory: {:?}", r);
    check!(r.1.contains("TLS refused: certificate refused: certificate expired") && result(&r.1).contains("refused by the kernel"), "reason 8 with 2046 in memory: {:?}", r.1);
    check!(matches!(lkg::file_state(), FileState::Unreadable(_)) && lkg::bound() == Y2046 && !rtc::synced(), "reason 8 changed something");
    serial_println!("[NTS TEST] 7/7 the bound: reason 7 - B = the LKG 2046, a chain ending 2045 refused in the first step, no recovery; reason 8 with 2046 in memory - B = 2046 (not the build date), refused; the kernel refuses a time below the LKG PASS");

    cleanup();
    check!(lkg::file_state() == FileState::NoVolume && lkg::bound() == 0 && !rtc::synced() && rtc::time_status().1.is_ok(), "after the cleanup: {:?} {} {:?}", lkg::file_state(), lkg::bound(), rtc::time_status().1);
    serial_println!("[NTS TEST] All time service tests passed!");
    crate::selftest::pass();
}
