// LKG TEST – the last known good time (time_lkg.rs) – only in builds with --cfg selftest.
//
//   1. nothing changed the LKG during the suites before (sysfuzz among them): the state the
//      boot left
//   2. the verdict on the clock: the order of the reasons (1-4, 6 -> 8 -> 5 -> 7), margin
//      0 s – on made-up states
//   3. the record on a volume: no file, good, saved twice, a temporary file left, every kind
//      of bad record, a read error (fs/desofs/test_lkg.rs)
//   4. power loss at every write of a save: exactly the old record or the new one
//   5. the live system on a RAM volume mounted at /disk: no file -> the build date; the
//      self-test switch raises and saves; never lower; the clock earlier than the LKG ->
//      reason 7 and netget https refuses before sending anything; a damaged file -> reason
//      8, never a quiet reset; no volume -> the raise stays in memory ("not saved") and the
//      next raise saves it
//   6. /.desoos protected: the kernel's own file functions every way, a program every way
//      (/bin/timetest protect), only /.desoos at the root of a DeSoFS volume
//   7. checked under the same lock as the operation: a volume mounted at /disk in the gap
//      before a changing call takes the VFS lock (fs::RACE_HOOK) – write, truncate, create,
//      mkdir, remove, rename (out of, over, into), write_file, append_file all refused; a
//      program's handle opened on ramfs before the mount writes nothing through it
//   8. no syscall changes the LKG: sysfuzz while the LKG is on /disk – value and file the same
//
// The LKG raised here goes into the future; at the end the RAM volume goes and the memory
// state is set back, so the suites after this one see the clock as before.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use super::*;
use crate::drivers::rtc::{self, Implausible as I};
use crate::fs::{self, FsError};
use crate::time_lkg::{self as lkg, FileState, Raised, Source};

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[LKG TEST] FAIL: {}", format_args!($($msg)*));
            cleanup();
            return;
        }
    };
}

const MOUNT: &str = lkg::SYSTEM_MOUNT;
const BLOCKS: u64 = 1024;
static mut DISK: Option<usize> = None;
static mut MADE_DIR: bool = false;

fn wait_for(ms: u64, cond: impl Fn() -> bool) -> bool {
    let end = crate::time::ticks() + ms;
    while !cond() {
        if crate::time::ticks() > end {
            return false;
        }
        crate::time::sleep_ms(1);
    }
    true
}

fn run(path: &str, args: &[&str], ms: u64) -> Option<(ExitKind, String)> {
    let opts = SpawnOptions { stdin: Some(Vec::new()), capture: true, ..SpawnOptions::default() };
    let id = exec(path, args, "/", &opts).ok()?;
    if !wait_for(ms, || sched::task_info(id).is_none()) {
        let _ = sched::request_exit(id);
        return None;
    }
    let kind = exit_info(id)?.kind;
    Some((kind, String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned()))
}

/// A RAM disk with a fresh DeSoFS volume, mounted at /disk the way the kernel mounts the
/// system volume (fs::mount_disk – which reads the LKG).
fn mount_ram() -> Result<(), String> {
    let d = crate::block::register(Box::new(crate::block::RamDisk::new("lkgtest", BLOCKS * 8)));
    unsafe { DISK = Some(d) };
    let p = crate::fs::desofs::format::Params { uuid: core::array::from_fn(|i| 0x70 + i as u8), time: 1_700_000_000, label: "TIME-TEST" };
    crate::fs::desofs::format::format(d, &p).map_err(|e| alloc::format!("format: {}", e))?;
    if fs::stat(MOUNT).is_err() {
        unsafe { MADE_DIR = true };
    }
    match fs::mount_disk(d, MOUNT) {
        fs::DiskMount::DeSoFs(None) => Ok(()),
        other => Err(alloc::format!("mount: {:?}", other)),
    }
}

fn unmount_ram() {
    let _ = fs::unmount(MOUNT);
}

/// RACE_HOOK: the volume mounted at /disk in the gap before the operation takes the lock.
fn hook_mount() {
    if let Some(d) = unsafe { DISK } {
        let _ = fs::mount_disk(d, MOUNT);
    }
}

/// What /disk shows of the files a changing call could have touched (on the volume).
fn volume_untouched(lkg_rec: &[u8]) -> Result<(), String> {
    if file_bytes().as_deref() != Some(lkg_rec) {
        return Err(String::from("the LKG file changed"));
    }
    for p in ["/disk/.desoos/new", "/disk/.desoos/d", "/disk/stolen", "/disk/.desoos/other"] {
        if fs::stat(p).is_ok() {
            return Err(alloc::format!("{} exists", p));
        }
    }
    if fs::stat("/disk/other").is_err() {
        return Err(String::from("/disk/other is gone"));
    }
    Ok(())
}

/// Puts everything back: the RAM volume gone, the LKG in memory as nothing stored, the
/// state read again (no system volume, as at boot of the test run).
fn cleanup() {
    unmount_ram();
    if let Some(d) = unsafe { core::ptr::replace(core::ptr::addr_of_mut!(DISK), None) } {
        crate::block::remove(d);
    }
    // What the old-handle step left on ramfs under /disk.
    let _ = fs::remove("/disk/.desoos/lkg");
    let _ = fs::remove("/disk/.desoos");
    let _ = fs::remove("/tmp/lkg-opened");
    let _ = fs::remove("/tmp/lkg-go");
    if unsafe { MADE_DIR } {
        let _ = fs::remove(MOUNT);
        unsafe { MADE_DIR = false };
    }
    lkg::reset_for_test();
    lkg::load();
}

fn file_bytes() -> Option<Vec<u8>> {
    fs::read_file(&alloc::format!("{}{}", MOUNT, lkg::FILE)).ok()
}

/// Changes a byte of the LKG file directly on the volume (a bad sector, a torn write) –
/// past the VFS protection, as only the kernel can.
fn damage() -> bool {
    let mut ok = false;
    fs::with_desofs_at(MOUNT, &mut |v| {
        use crate::fs::FileSystem;
        let mut b = [0u8; 1];
        ok = v.read(lkg::FILE, 20, &mut b).is_ok() && v.write(lkg::FILE, 20, &[b[0] ^ 0x40]).is_ok();
    });
    ok
}

/// netget https: refused before anything is sent, with this reason.
fn https_refused(reason: &str) -> Result<(), String> {
    let r = run("/bin/netget", &["netget", "https://tls.desoos:58443/hello"], 30_000).ok_or("netget did not finish")?;
    let (kind, out) = r;
    if kind == ExitKind::Exit(5) && out.contains("TLS refused: clock not plausible") && out.contains(reason) && out.contains("nothing sent") {
        Ok(())
    } else {
        Err(alloc::format!("{:?} {:?}", kind, out.trim()))
    }
}

pub fn self_test() {
    serial_println!("[LKG TEST] Starting the last known good time tests (time_lkg.rs, /.desoos)...");
    crate::selftest::begin();
    let now = || rtc::time_status().0;

    // 1. The state the boot left: in the test run disk 0 is the empty test disk, so there is
    //    no system volume; nothing may have raised the LKG since (no syscall can).
    let st0 = lkg::file_state();
    check!(st0 == FileState::NoVolume && lkg::bound() == 0 && !lkg::dirty() && lkg::source() == Source::Build, "the LKG changed before LKG TEST: {:?}, bound {}, dirty {}, {:?}", st0, lkg::bound(), lkg::dirty(), lkg::source());
    check!(rtc::time_status().1.is_ok(), "the clock is not plausible at the start: {:?}", rtc::time_status().1);
    check!(lkg::describe().contains("build date") && lkg::describe().contains("kept in memory only"), "describe: {}", lkg::describe());
    serial_println!("[LKG TEST] 1/8 the state the boot left: no system volume, the build date, nothing raised by the suites before (sysfuzz among them) PASS");

    // 2. The verdict, on made-up states.
    let b = 2_000_000_000u64;
    let cases: [(Result<(), I>, u64, bool, u64, Result<(), I>); 16] = [
        (Ok(()), b, false, b, Ok(())),                       // RTC = LKG
        (Ok(()), b - 1, false, b, Err(I::BeforeLkg)),        // one second below (margin 0)
        (Ok(()), b - 3600, false, b, Err(I::BeforeLkg)),     // one hour below
        (Ok(()), b + 1, false, b, Ok(())),
        (Ok(()), b, false, 0, Ok(())),                       // nothing stored
        (Err(I::BeforeBuild), 1, false, b, Err(I::BeforeBuild)), // 5 before 7
        (Err(I::BatteryLost), b - 1, false, b, Err(I::BatteryLost)),
        (Err(I::BatteryLost), b, true, b, Err(I::BatteryLost)), // the reading first
        (Err(I::Unstable), b, true, b, Err(I::Unstable)),
        (Err(I::BadFields), b, true, 0, Err(I::BadFields)),
        (Err(I::TooLate), b, true, 0, Err(I::TooLate)),
        (Err(I::NotRead), b, true, 0, Err(I::NotRead)),
        (Ok(()), b, true, 0, Err(I::LkgUnreadable)),         // 8 on its own
        (Ok(()), b - 1, true, b, Err(I::LkgUnreadable)),     // 8 before 7
        (Err(I::BeforeBuild), 1, true, b, Err(I::LkgUnreadable)), // 8 before 5
        (Ok(()), b + 100, false, b, Ok(())),
    ];
    for (rtcv, secs, bad, l, want) in cases.iter() {
        let got = lkg::verdict(*rtcv, *secs, *bad, *l);
        check!(got == *want, "verdict({:?}, {}, bad {}, lkg {}) = {:?}, expected {:?}", rtcv, secs, bad, l, got, want);
    }
    check!(I::BeforeLkg as u8 == 7 && I::LkgUnreadable as u8 == 8, "reason numbers");
    serial_println!("[LKG TEST] 2/8 the verdict: {} made-up states - order 1-4, 6 -> 8 -> 5 -> 7, margin 0 s (one second below the LKG refused) PASS", cases.len());

    // 3. The record on a volume.
    let r = crate::fs::desofs::test_lkg::file_cases();
    check!(r.is_ok(), "the record on a volume: {:?}", r.err());
    serial_println!("[LKG TEST] 3/8 the record on a volume: {} (no file, good, saved twice, a temporary file left, length, magic, every covered byte, version, reserved, source, after 2099, read and stat errors) PASS", r.unwrap_or_default());

    // 4. Power loss.
    let t0 = crate::time::ticks();
    let r = crate::fs::desofs::test_lkg::power_loss();
    check!(r.is_ok(), "power loss: {:?}", r.err());
    serial_println!("[LKG TEST] 4/8 power loss at every write of a save: {} in {} ms PASS", r.unwrap_or_default(), crate::time::ticks() - t0);

    // 5. The live system.
    let m = mount_ram();
    check!(m.is_ok(), "{:?}", m.err());
    check!(lkg::file_state() == FileState::Missing && lkg::bound() == 0, "a fresh /disk: {:?} {}", lkg::file_state(), lkg::bound());
    // A time a little behind the clock (but after the build date – the build date bounds
    // the clock already, so a lower LKG is never stored).
    let t = now();
    let first = t.saturating_sub(30).max(rtc::BUILD_EPOCH + 1).min(t);
    check!(lkg::raise_for_test(first) == Raised::Saved, "raise to {} (clock {}, build {})", first, t, rtc::BUILD_EPOCH);
    check!(file_bytes().as_deref() == Some(&lkg::encode(first, Source::Test)[..]), "the file is not the record");
    check!(lkg::file_state() == FileState::Good && lkg::source() == Source::Test && rtc::time_status().1.is_ok(), "after the raise: {:?} {:?}", lkg::file_state(), rtc::time_status().1);
    check!(lkg::raise_for_test(first - 1) == Raised::NotHigher && lkg::bound() == first, "a lower time lowered the LKG");
    check!(file_bytes().as_deref() == Some(&lkg::encode(first, Source::Test)[..]), "a lower time changed the file");
    // Equal to the clock: plausible (margin 0).
    let t = now();
    check!(lkg::raise_for_test(t) == Raised::Saved && rtc::time_status().1.is_ok(), "the LKG equal to the clock: {:?}", rtc::time_status().1);
    // Ahead of the clock (the RTC "set back"): reason 7, TLS refuses.
    let ahead = now() + 3600;
    check!(lkg::raise_for_test(ahead) == Raised::Saved, "raise ahead of the clock");
    check!(rtc::time_status().1 == Err(I::BeforeLkg), "the clock below the LKG: {:?}", rtc::time_status().1);
    let h = https_refused("clock earlier than the last known good time");
    check!(h.is_ok(), "netget https with the clock below the LKG: {:?}", h.err());
    // Read again from the disk (as after a restart): the same.
    lkg::reset_for_test();
    lkg::load();
    check!(lkg::file_state() == FileState::Good && lkg::bound() == ahead && rtc::time_status().1 == Err(I::BeforeLkg), "read back: {:?} {} {:?}", lkg::file_state(), lkg::bound(), rtc::time_status().1);
    // A damaged file: reason 8 – not a quiet reset to the build date.
    check!(damage(), "could not damage the file");
    lkg::reset_for_test();
    lkg::load();
    check!(lkg::file_state() == FileState::Unreadable(lkg::Bad::Checksum), "a damaged file: {:?}", lkg::file_state());
    check!(rtc::time_status().1 == Err(I::LkgUnreadable) && lkg::describe().contains("UNREADABLE"), "a damaged file: {:?} {}", rtc::time_status().1, lkg::describe());
    let h = https_refused("last known good time unreadable");
    check!(h.is_ok(), "netget https with a damaged LKG file: {:?}", h.err());
    // A new LKG written repairs it (stage D: an authenticated time).
    let ahead2 = ahead + 10;
    check!(lkg::raise_for_test(ahead2) == Raised::Saved && lkg::file_state() == FileState::Good && rtc::time_status().1 == Err(I::BeforeLkg), "a new LKG after the damage: {:?}", rtc::time_status().1);
    // No volume: the raise stays in memory ("not saved"); the next raise saves it, even a
    // lower one.
    unmount_ram();
    let ahead3 = ahead2 + 10;
    check!(lkg::raise_for_test(ahead3) == Raised::InMemory && lkg::dirty() && lkg::bound() == ahead3 && lkg::describe().contains("NOT SAVED"), "a raise without a volume: dirty {} bound {} {}", lkg::dirty(), lkg::bound(), lkg::describe());
    let d = unsafe { DISK };
    check!(d.is_some() && matches!(fs::mount_disk(d.unwrap_or(0), MOUNT), fs::DiskMount::DeSoFs(None)), "mount again");
    check!(lkg::bound() == ahead3 && lkg::dirty(), "mounting a volume with an older record lowered the LKG: {}", lkg::bound());
    check!(lkg::raise_for_test(now()) == Raised::NotHigher && !lkg::dirty(), "the next raise did not save the pending LKG");
    check!(file_bytes().as_deref() == Some(&lkg::encode(ahead3, Source::Test)[..]), "the pending LKG is not on the disk");
    serial_println!("[LKG TEST] 5/8 the live system (RAM volume at /disk): no file - the build date; raised and saved; never lower; equal to the clock - plausible; ahead - reason 7, netget https refused before sending; read back the same; damaged - reason 8 (no quiet reset), https refused, repaired by the next LKG; no volume - kept in memory, 'NOT SAVED', saved by the next raise PASS");

    // 6. /.desoos protected.
    let f = alloc::format!("{}{}", MOUNT, lkg::FILE);
    let res = |r: fs::Result<()>| r == Err(FsError::Reserved);
    let _ = fs::write_file("/disk/lkg-other", b"x");
    let _ = fs::mkdir("/disk/a");
    let kernel_cases: [(&str, bool); 20] = [
        ("write_file", res(fs::write_file(&f, b"evil"))),
        ("append_file", res(fs::append_file(&f, b"evil"))),
        ("write", fs::write(&f, 0, b"x") == Err(FsError::Reserved)),
        ("truncate", res(fs::truncate(&f, 0))),
        ("remove the file", res(fs::remove(&f))),
        ("remove /.desoos", res(fs::remove("/disk/.desoos"))),
        ("mkdir inside", res(fs::mkdir("/disk/.desoos/d"))),
        ("create inside", res(fs::create("/disk/.desoos/new"))),
        ("create lkg.new", res(fs::create("/disk/.desoos/lkg.new"))),
        ("rename out", res(fs::rename(&f, "/disk/stolen"))),
        ("rename over", res(fs::rename("/disk/lkg-other", &f))),
        ("rename into", res(fs::rename("/disk/lkg-other", "/disk/.desoos/other"))),
        ("rename the directory", res(fs::rename("/disk/.desoos", "/disk/other-dir"))),
        ("rename a directory onto it", res(fs::rename("/disk/a", "/disk/.desoos"))),
        ("mount on /.desoos", fs::mount("/disk/.desoos", Box::new(fs::ramfs::RamFs::new())) == Err(FsError::Reserved)),
        ("mount inside", fs::mount("/disk/.desoos/x", Box::new(fs::ramfs::RamFs::new())) == Err(FsError::Reserved)),
        ("'.' spelling", res(fs::remove("/disk/./.desoos/./lkg"))),
        ("'..' spelling", res(fs::write_file("/disk/a/../.desoos/lkg", b"evil"))),
        ("doubled slashes", res(fs::truncate("//disk//.desoos//lkg", 0))),
        ("relative-looking", res(fs::remove("/disk/a/../a/../.desoos"))),
    ];
    for (what, ok) in kernel_cases.iter() {
        check!(*ok, "kernel {} on /.desoos allowed", what);
    }
    // Not wider than it should be: other names, /.desoos below the root of the volume, a
    // /.desoos on ramfs.
    for p in ["/disk/.desoosx", "/disk/a/.desoos", "/disk/.desoo"] {
        check!(fs::mkdir(p).is_ok() && fs::remove(p).is_ok(), "{} is not writable", p);
    }
    check!(!fs::is_reserved("/.desoos") && fs::mkdir("/.desoos").is_ok() && fs::remove("/.desoos").is_ok(), "/.desoos on ramfs is protected - only DeSoFS volumes are");
    check!(fs::read_file(&f).map(|d| d.len()) == Ok(lkg::RECORD_LEN), "the file is not readable");
    let _ = fs::remove("/disk/lkg-other");
    let _ = fs::remove("/disk/a");
    let r = run("/bin/timetest", &["timetest", "protect", MOUNT], 60_000);
    check!(r.is_some(), "timetest protect did not finish");
    let (kind, out) = r.unwrap_or((ExitKind::Exit(-1), String::new()));
    check!(kind == ExitKind::Exit(0) && out.contains("attempts refused"), "timetest protect: {:?} {:?}", kind, out.trim());
    check!(file_bytes().as_deref() == Some(&lkg::encode(ahead3, Source::Test)[..]) && lkg::bound() == ahead3, "the file or the LKG changed");
    serial_println!("[LKG TEST] 6/8 /.desoos protected: {} kernel calls refused (write, truncate, remove, mkdir, create, rename from / to / into / of the directory, mount on and inside, '.', '..', '//'); {}; /.desoosx, a/.desoos and /.desoos on ramfs stay writable PASS", kernel_cases.len(), out.trim().trim_start_matches("timetest "));

    // 7. The check under the same lock as the operation.
    let rec = lkg::encode(ahead3, Source::Test);
    let _ = fs::write_file("/disk/other", b"other");
    const F: &str = "/disk/.desoos/lkg";
    let ops: [(&str, fn() -> fs::Result<()>); 10] = [
        ("write", || fs::write(F, 0, b"evil").map(|_| ())),
        ("truncate", || fs::truncate(F, 0)),
        ("create", || fs::create("/disk/.desoos/new")),
        ("mkdir", || fs::mkdir("/disk/.desoos/d")),
        ("remove", || fs::remove(F)),
        ("rename out", || fs::rename(F, "/disk/stolen")),
        ("rename over", || fs::rename("/disk/other", F)),
        ("rename into", || fs::rename("/disk/other", "/disk/.desoos/other")),
        ("write_file", || fs::write_file(F, b"evil")),
        ("append_file", || fs::append_file(F, b"evil")),
    ];
    for (what, op) in ops.iter() {
        // /disk is plain ramfs when the call starts; the volume arrives in the gap.
        unmount_ram();
        check!(!fs::is_reserved(F), "{}: /disk still reserved after the unmount", what);
        fs::RACE_HOOK.store(hook_mount as fn() as usize, core::sync::atomic::Ordering::SeqCst);
        let r = op();
        fs::RACE_HOOK.store(0, core::sync::atomic::Ordering::SeqCst);
        check!(fs::is_reserved(F), "{}: the hook did not mount the volume", what);
        check!(r == Err(FsError::Reserved), "{} with the volume mounted in the gap: {:?} - the check is not under the operation's lock", what, r);
        let u = volume_untouched(&rec);
        check!(u.is_ok(), "{}: {:?}", what, u.err());
    }
    // A program's handle opened on ramfs before the volume is mounted over /disk.
    unmount_ram();
    let _ = fs::mkdir("/disk/.desoos");
    check!(fs::write_file(F, b"ramfs").is_ok(), "could not write the ramfs file under /disk");
    let _ = fs::remove("/tmp/lkg-opened");
    let _ = fs::remove("/tmp/lkg-go");
    let opts = SpawnOptions { stdin: Some(Vec::new()), capture: true, ..SpawnOptions::default() };
    let id = exec("/bin/timetest", &["timetest", "stale", F, "/tmp/lkg-opened", "/tmp/lkg-go"], "/", &opts).ok();
    check!(id.is_some(), "could not start timetest stale");
    let id = id.unwrap_or(0);
    check!(wait_for(20_000, || fs::stat("/tmp/lkg-opened").is_ok()), "timetest stale did not open the file");
    let d = unsafe { DISK }.unwrap_or(0);
    check!(matches!(fs::mount_disk(d, MOUNT), fs::DiskMount::DeSoFs(None)), "mount over the open handle");
    check!(fs::write_file("/tmp/lkg-go", b"go").is_ok(), "could not signal timetest");
    check!(wait_for(30_000, || sched::task_info(id).is_none()), "timetest stale did not finish");
    let kind = exit_info(id).map(|e| e.kind);
    let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
    check!(kind == Some(ExitKind::Exit(0)) && out.contains("was refused"), "timetest stale: {:?} {:?}", kind, out.trim());
    let u = volume_untouched(&rec);
    check!(u.is_ok(), "after the old handle: {:?}", u.err());
    serial_println!("[LKG TEST] 7/8 checked under the operation's lock: the volume mounted in the gap before the lock - {} changing calls refused (write, truncate, create, mkdir, remove, rename out / over / into, write_file, append_file), nothing on the volume changed; {} PASS", ops.len(), out.trim().trim_start_matches("timetest "));

    // 8. No syscall changes the LKG: sysfuzz with the LKG on /disk.
    let before = file_bytes();
    let r = run("/bin/sysfuzz", &["sysfuzz", "16", "2000"], 120_000);
    check!(r.is_some(), "sysfuzz did not finish");
    let (kind, out) = r.unwrap_or((ExitKind::Exit(-1), String::new()));
    check!(kind == ExitKind::Exit(0) && out.contains("kernel survived"), "sysfuzz: {:?} {:?}", kind, out.trim());
    check!(file_bytes() == before && lkg::bound() == ahead3 && lkg::file_state() == FileState::Good && !lkg::dirty(), "sysfuzz changed the LKG");
    serial_println!("[LKG TEST] 8/8 sysfuzz (16 children, 2000 calls) with the LKG on /disk: value and file unchanged PASS");

    cleanup();
    check!(lkg::file_state() == FileState::NoVolume && lkg::bound() == 0 && rtc::time_status().1.is_ok(), "after the cleanup: {:?} {} {:?}", lkg::file_state(), lkg::bound(), rtc::time_status().1);
    serial_println!("[LKG TEST] All time tests passed!");
    crate::selftest::pass();
}
