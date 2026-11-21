// USB DISK TEST – a USB stick's "DeSoOS system" partition as /disk (v0.80 stage B; rules D, D2,
// E, F of the V080 plan).  Only in builds with --cfg selftest.
//
// 1/2 fake sticks with a write cache (/bin/blkdtest): `desofs format` only in a format session
//     (ESP refused, the session counter used up – nothing written), /disk from the only
//     candidate (rw after the probe and `desofs check`), the last known good time (rule D: a
//     volume without the file / with an older one gets the time from memory, a stick lost
//     during the save – not saved, written later), the choice between sticks (two or more
//     candidates – none; /disk never taken away; a stick removed – decided anew; two
//     partitions on one stick), the internal disk keeps /disk (also damaged), /disk in use,
//     power loss at every write of an operation – the old or the new version.
// 2/2 real usbd and the writable QEMU stick: formatted, /disk read-write, files and the LKG on
//     it, unplugged and plugged back – /disk again with the files; it is left with the LKG and a
//     marker for the third start (USB RESTART TEST: QEMU without virtio and NVMe).

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::*;
use super::usbdisk::AUTO;
use crate::block::{self, Control};
use crate::time::ticks;

fn wait_for(ms: u64, cond: impl Fn() -> bool) -> bool {
    let end = ticks() + ms;
    while !cond() {
        if ticks() > end {
            return false;
        }
        crate::time::sleep_ms(5);
    }
    true
}

fn find(name: &str) -> Option<alloc::sync::Arc<super::ublk::Shared>> {
    super::ublk::list().into_iter().find(|s| s.desc == name && !s.gone() && s.probed())
}

/// The "DeSoOS system" partitions of disk `d`, in table order.
fn sys_parts(d: usize) -> Vec<usize> {
    let mut v: Vec<usize> = block::partitions_of(d).into_iter().filter(|&p| block::partition_kind(p) == Some(crate::gpt::DESOOS_SYSTEM_NAME)).collect();
    v.sort();
    v
}

fn esp_part(d: usize) -> Option<usize> {
    block::partitions_of(d).into_iter().find(|&p| block::partition_kind(p) == Some("EFI System"))
}

fn params() -> crate::fs::desofs::format::Params<'static> {
    crate::fs::desofs::format::Params { uuid: core::array::from_fn(|i| 0x70 + i as u8), time: 1_800_000_000, label: "USBDISK" }
}

/// What is mounted at `path`: Some(source text).
fn mounted(path: &str) -> Option<String> {
    crate::fs::mount_list().into_iter().find(|m| m.0 == path).map(|m| m.2)
}

fn usb_desofs_mounts() -> usize {
    crate::fs::mount_list().iter().filter(|m| m.0.starts_with("/usb") && m.1 == "desofs").count()
}

/// The LKG file on /disk.
fn lkg_on_disk() -> Option<u64> {
    let mut r = None;
    crate::fs::with_desofs_at("/disk", &mut |v| r = crate::time_lkg::load_from(v).ok().flatten().map(|x| x.0));
    r
}

/// Sends a test flag to a fake stick.
fn flag(sh: &super::ublk::Shared, f: u32) -> bool {
    block::control(sh.index.load(Ordering::SeqCst), Control::Test { flags: f }) == Ok(0)
}

const T0: u64 = crate::drivers::rtc::BUILD_EPOCH + 1000;

/// 1/2 – the fake sticks.
fn fake_test() -> Result<String, String> {
    macro_rules! ck {
        ($cond:expr, $($msg:tt)*) => {
            if !$cond {
                AUTO.store(false, Ordering::SeqCst);
                return Err(alloc::format!($($msg)*));
            }
        };
    }
    ck!(mounted("/disk").is_none(), "USB DISK TEST needs a free /disk (found {:?})", mounted("/disk"));
    let free0 = crate::selftest::settled_free_frames();
    let internal = block::test_set_internal(None);
    crate::time_lkg::reset_for_test();
    let opts = SpawnOptions { stdin: Some(Vec::new()), capture: true, blk: true, ..SpawnOptions::default() };
    let id = exec("/bin/blkdtest", &["blkdtest"], "/", &opts).map_err(|_| String::from("cannot start /bin/blkdtest"))?;
    let r = fake_inner(&opts);
    AUTO.store(false, Ordering::SeqCst);
    // The end: the fake exits, its sticks go (and /disk with them).
    if let Some(s) = super::ublk::list().into_iter().find(|s| s.desc.starts_with("blkd-") && !s.gone()) {
        let _ = flag(&s, 0x80);
    }
    let ok = wait_for(10_000, || sched::task_info(id).is_none());
    if !ok {
        let _ = sched::request_exit(id);
    }
    let gone = wait_for(5_000, || super::ublk::count() == 0) && wait_for(2_000, || mounted("/disk").is_none());
    block::test_restore_internal(internal);
    // The LKG as the boot left it (LKG TEST checks it): nothing in memory, no system volume.
    crate::time_lkg::reset_for_test();
    crate::time_lkg::volume_gone();
    let line = r?;
    ck!(ok, "blkdtest did not exit");
    ck!(gone, "blkdtest sticks / /disk left after it exited");
    let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
    let fl = out.lines().find(|l| l.starts_with("blkdtest:")).unwrap_or("").trim();
    ck!(exit_info(id).map(|e| e.kind) == Some(ExitKind::Exit(0)) && fl.contains("checks OK") && fl.ends_with("bad 0"), "blkdtest: {:?}", out.trim());
    crate::sched::reap();
    let free1 = crate::selftest::settled_free_frames();
    ck!(free1 >= free0, "frames leaked ({} -> {})", free0, free1);
    Ok(alloc::format!("{}; {}", line, fl))
}

fn fake_inner(_opts: &SpawnOptions) -> Result<String, String> {
    use crate::fs::desofs::format::format;
    macro_rules! ck {
        ($cond:expr, $($msg:tt)*) => {
            if !$cond {
                return Err(alloc::format!($($msg)*));
            }
        };
    }
    // Disk identities never wrap: the last one refused, not reused.
    let saved_uid = block::test_set_next_uid(u64::MAX);
    let r = block::register(alloc::boxed::Box::new(block::RamDisk::new("uidmax", 8)));
    block::test_set_next_uid(saved_uid);
    ck!(r.is_none(), "a disk registered with the identity counter used up (number {:?})", r);
    ck!(wait_for(10_000, || find("blkd-1").is_some()), "blkd-1 not attached / probed");
    let s1 = find("blkd-1").unwrap();
    let d1 = s1.index.load(Ordering::SeqCst);
    let (e1, p1) = (esp_part(d1), sys_parts(d1));
    ck!(e1.is_some() && p1.len() == 1, "blkd-1: partitions {:?} / {:?}", e1, p1);
    let (e1, p1) = (e1.unwrap(), p1[0]);
    // Rule F: only "DeSoOS system", only in a session; refused – nothing written.
    let r = format(e1, &params());
    ck!(r.as_ref().is_err_and(|e| e.contains("only a \"DeSoOS system\"")), "format of the ESP: {:?}", r);
    let saved = super::ublk::test_set_counters(None, Some(u64::MAX));
    let r = format(p1, &params());
    super::ublk::test_set_counters(None, Some(saved.1));
    ck!(r.as_ref().is_err_and(|e| e.contains("no format session")), "format with the session counter used up: {:?}", r);
    ck!(!crate::fs::desofs::has_marker(p1), "a refused format wrote a superblock");
    let r = format(p1, &params());
    ck!(r.is_ok() && crate::fs::desofs::has_marker(p1), "format of the DeSoOS system partition: {:?}", r);
    ck!(block::is_read_only(p1), "the format grant was left on the partition");
    let g1 = s1.generation;
    ck!(block::control(d1, Control::RegisterRw { generation: g1, start: 2048, len: 5952 }) == Ok(0) && block::control(d1, Control::Withdraw) == Ok(0), "a registration was left after the format session");
    // Rule E2 / D2: the only candidate becomes /disk read-write.
    AUTO.store(true, Ordering::SeqCst);
    super::usbdisk::changed();
    let t0 = ticks();
    ck!(wait_for(8_000, || s1.disk_part() == Some(p1) && mounted("/disk").is_some()), "the only candidate did not become /disk");
    let to_disk_ms = ticks() - t0;
    ck!(!crate::fs::is_read_only("/disk/x"), "/disk from the stick is read-only");
    ck!(crate::fs::write_file("/disk/note", b"v1").is_ok() && crate::fs::read_file("/disk/note").ok().as_deref() == Some(&b"v1"[..]), "file on /disk");
    // Rule D: the LKG on the stick.
    ck!(crate::time_lkg::raise_for_test(T0) == crate::time_lkg::Raised::Saved && lkg_on_disk() == Some(T0), "LKG saved on the stick");
    // (a) a volume holding an OLDER time than memory gets the higher one.
    AUTO.store(false, Ordering::SeqCst);
    ck!(flag(&s1, 0x40), "replug flag");
    ck!(wait_for(8_000, || s1.gone() && find("blkd-1").is_some_and(|s| s.generation != g1)), "blkd-1 not back after the replug");
    ck!(mounted("/disk").is_none() && crate::time_lkg::file_state() == crate::time_lkg::FileState::NoVolume, "/disk left / file state after the stick went: {:?}", mounted("/disk"));
    let s1 = find("blkd-1").unwrap();
    ck!(crate::time_lkg::raise_for_test(T0 + 100) == crate::time_lkg::Raised::InMemory, "LKG raised with no volume");
    crate::time_lkg::test_clear_dirty();
    AUTO.store(true, Ordering::SeqCst);
    super::usbdisk::changed();
    ck!(wait_for(8_000, || s1.disk_part().is_some()), "/disk not back");
    ck!(crate::time_lkg::dirty() && lkg_on_disk() == Some(T0), "an older LKG file did not mark the time in memory for saving (dirty {}, file {:?})", crate::time_lkg::dirty(), lkg_on_disk());
    let _ = crate::time_lkg::raise_for_test(T0 + 100);
    ck!(!crate::time_lkg::dirty() && lkg_on_disk() == Some(T0 + 100), "the higher LKG not written to the stick: {:?}", lkg_on_disk());
    // (b) a volume WITHOUT the file gets the time in memory.
    AUTO.store(false, Ordering::SeqCst);
    let g = s1.generation;
    ck!(flag(&s1, 0x40), "replug flag");
    ck!(wait_for(8_000, || find("blkd-1").is_some_and(|s| s.generation != g)), "blkd-1 not back");
    let s1 = find("blkd-1").unwrap();
    let p1 = sys_parts(s1.index.load(Ordering::SeqCst))[0];
    ck!(format(p1, &params()).is_ok(), "format again");
    crate::time_lkg::test_clear_dirty();
    AUTO.store(true, Ordering::SeqCst);
    super::usbdisk::changed();
    ck!(wait_for(8_000, || s1.disk_part().is_some()), "/disk not back after the new format");
    ck!(crate::time_lkg::dirty() && lkg_on_disk().is_none(), "a volume without the LKG file did not mark the time for saving (dirty {})", crate::time_lkg::dirty());
    let _ = crate::time_lkg::raise_for_test(T0 + 100);
    ck!(lkg_on_disk() == Some(T0 + 100), "the LKG not written to the new volume");
    // (c) the stick lost during the save: nothing reported saved, written once it is back.
    ck!(flag(&s1, 0x100), "power loss flag");
    let g = s1.generation;
    let r = crate::time_lkg::raise_for_test(T0 + 200);
    ck!(r == crate::time_lkg::Raised::InMemory && crate::time_lkg::dirty(), "LKG save during the loss of the stick: {:?}", r);
    ck!(wait_for(8_000, || find("blkd-1").is_some_and(|s| s.generation != g && s.disk_part().is_some())), "/disk not back after the loss");
    let s1 = find("blkd-1").unwrap();
    ck!(lkg_on_disk() == Some(T0 + 100) && crate::time_lkg::dirty(), "after the loss: file {:?}, dirty {}", lkg_on_disk(), crate::time_lkg::dirty());
    let _ = crate::time_lkg::raise_for_test(T0 + 200);
    ck!(lkg_on_disk() == Some(T0 + 200) && !crate::time_lkg::dirty(), "the LKG not written after the stick came back");
    // Rule E: the choice between sticks.  Stick 2 with two DeSoOS system partitions.
    ck!(flag(&s1, 0x200), "attach stick 2");
    ck!(wait_for(8_000, || find("blkd-2").is_some()), "blkd-2 not attached");
    let s2 = find("blkd-2").unwrap();
    let p2 = sys_parts(s2.index.load(Ordering::SeqCst));
    ck!(p2.len() == 2, "blkd-2: {} DeSoOS system partitions", p2.len());
    ck!(format(p2[0], &params()).is_ok() && format(p2[1], &params()).is_ok(), "format of stick 2");
    // /disk is never taken away: stick 2's partitions only read-only.
    ck!(wait_for(8_000, || usb_desofs_mounts() == 2), "stick 2's partitions not mounted read-only ({})", usb_desofs_mounts());
    ck!(s1.disk_part().is_some(), "/disk taken away from stick 1");
    // /disk freed (stick 1 replugged): three candidates – none gets /disk.
    AUTO.store(false, Ordering::SeqCst);
    let g = s1.generation;
    ck!(flag(&s1, 0x40), "replug flag");
    ck!(wait_for(8_000, || find("blkd-1").is_some_and(|s| s.generation != g)), "blkd-1 not back");
    let s1 = find("blkd-1").unwrap();
    AUTO.store(true, Ordering::SeqCst);
    super::usbdisk::changed();
    ck!(wait_for(8_000, || usb_desofs_mounts() == 3), "three candidates: {} read-only mounts", usb_desofs_mounts());
    ck!(mounted("/disk").is_none(), "one of three candidates got /disk");
    // Stick 2 removed: stick 1 alone – from /usbN to /disk (one mount at a time).
    ck!(flag(&s2, 0x20), "detach stick 2");
    ck!(wait_for(8_000, || s1.disk_part().is_some()), "the remaining candidate did not get /disk");
    ck!(usb_desofs_mounts() == 0, "stick 1's volume mounted twice ({} under /usbN)", usb_desofs_mounts());
    // Stick 2 alone: two partitions on one stick – none.
    ck!(flag(&s1, 0x200), "attach stick 2");
    ck!(wait_for(8_000, || usb_desofs_mounts() == 2), "stick 2 not mounted read-only");
    AUTO.store(false, Ordering::SeqCst);
    ck!(flag(&s1, 0x20), "detach stick 1");
    ck!(wait_for(8_000, || mounted("/disk").is_none()), "/disk left after stick 1 went");
    AUTO.store(true, Ordering::SeqCst);
    super::usbdisk::changed();
    crate::time::sleep_ms(super::usbdisk::SETTLE_MS + 600);
    ck!(mounted("/disk").is_none(), "one of two partitions on one stick got /disk");
    // The internal disk with DeSoFS keeps /disk – also damaged.
    let s2 = find("blkd-2").unwrap();
    ck!(flag(&s2, 0x800), "attach stick 1");
    ck!(flag(&s2, 0x20), "detach stick 2");
    let ram = block::register(alloc::boxed::Box::new(block::RamDisk::new("intl", 4096))).unwrap_or(usize::MAX);
    ck!(format(ram, &params()).is_ok(), "format of the RAM disk");
    let old = block::test_set_internal(Some(ram));
    ck!(super::usbdisk::internal_reserves(), "an internal disk with DeSoFS does not reserve /disk");
    let mut sb = alloc::vec![0u8; 4096];
    for s in [1u64, 2] {
        let _ = block::read(ram, s * 8, &mut sb);
        sb[100] ^= 0xFF; // the checksum breaks, the marker stays
        let _ = block::write(ram, s * 8, &sb);
    }
    ck!(super::usbdisk::internal_reserves(), "a damaged DeSoFS on the internal disk does not reserve /disk");
    super::usbdisk::changed();
    ck!(wait_for(8_000, || find("blkd-1").is_some() && usb_desofs_mounts() == 1), "stick 1 not mounted read-only while the internal disk reserves /disk ({})", usb_desofs_mounts());
    ck!(mounted("/disk").is_none(), "a USB stick took /disk from the internal disk");
    block::test_restore_internal(old);
    // The test RAM disks hold physical frames (block::RamDisk): given back, or the frame
    // check at the end of this test counts them as a leak.
    block::remove(ram);
    let _ = block::test_set_internal(None);
    // /disk in use (anything mounted there) is never replaced.
    let ram2 = block::register(alloc::boxed::Box::new(block::RamDisk::new("busy", 4096))).unwrap_or(usize::MAX);
    ck!(format(ram2, &params()).is_ok() && matches!(crate::fs::mount_disk(ram2, "/disk"), crate::fs::DiskMount::DeSoFs(_)), "RAM disk at /disk");
    let s1 = find("blkd-1").unwrap();
    AUTO.store(false, Ordering::SeqCst);
    let g = s1.generation;
    ck!(flag(&s1, 0x40), "replug flag");
    ck!(wait_for(8_000, || find("blkd-1").is_some_and(|s| s.generation != g)), "blkd-1 not back");
    AUTO.store(true, Ordering::SeqCst);
    super::usbdisk::changed();
    ck!(wait_for(8_000, || usb_desofs_mounts() == 1), "stick 1 not read-only while /disk is in use");
    ck!(mounted("/disk").is_some_and(|m| !m.contains("blkd") && find("blkd-1").is_some_and(|s| s.disk_part().is_none())), "a USB stick replaced the volume at /disk");
    ck!(crate::fs::unmount("/disk").is_ok(), "unmount the RAM disk");
    block::remove(ram2);
    let _ = crate::fs::remove("/disk");
    // Free again – stick 1 gets /disk once something changes.
    super::usbdisk::changed();
    ck!(wait_for(8_000, || find("blkd-1").is_some_and(|s| s.disk_part().is_some())), "stick 1 did not get the freed /disk");
    // Rule 5 / 6 (review of stage B): who holds what comes from the mount table.
    // (a) No free /usbN: no attempt counted – a mount point freed later is used.
    let mut filled = Vec::new();
    while let Some(pt) = super::ublk::free_mount_point() {
        let _ = crate::fs::mkdir(&pt);
        ck!(crate::fs::write_file(&alloc::format!("{}/x", pt), b"x").is_ok(), "fill {}", pt);
        filled.push(pt);
    }
    let s1 = find("blkd-1").unwrap();
    ck!(flag(&s1, 0x200), "attach stick 2");
    ck!(wait_for(8_000, || find("blkd-2").is_some()), "blkd-2 not attached");
    crate::time::sleep_ms(super::usbdisk::SETTLE_MS + 600);
    ck!(usb_desofs_mounts() == 0, "mounted with no free /usbN ({})", usb_desofs_mounts());
    // Two earlier failures of each partition (review of the stage B fix): a mount that works
    // clears them – they do not count against later attempts.
    let s2 = find("blkd-2").unwrap();
    for &p in &sys_parts(s2.index.load(Ordering::SeqCst)) {
        let _ = s2.note_ro_fail(p);
        let _ = s2.note_ro_fail(p);
    }
    let free_one = |pt: &str| {
        let _ = crate::fs::remove(&alloc::format!("{}/x", pt));
        let _ = crate::fs::remove(pt);
    };
    free_one(&filled[0]);
    super::usbdisk::changed();
    ck!(wait_for(8_000, || usb_desofs_mounts() == 1), "a freed /usbN not used (the partition marked tried before mounting?)");
    free_one(&filled[1]);
    super::usbdisk::changed();
    ck!(wait_for(8_000, || usb_desofs_mounts() == 2), "the second partition not mounted after a /usbN was freed");
    for &p in &sys_parts(s2.index.load(Ordering::SeqCst)) {
        ck!(s2.note_ro_fail(p) == 1, "earlier failures of disk {} still counted after it was mounted", p);
    }
    for pt in &filled[2..] {
        free_one(pt);
    }
    // (c) `desofs unmount` of a /usbN: not mounted again by itself (the user's intent).
    let s2 = find("blkd-2").unwrap();
    let ro = s2.ro_mounts();
    ck!(ro.len() == 2, "stick 2 records {} read-only mounts", ro.len());
    ck!(crate::fs::unmount(&ro[0].0).is_ok(), "unmount {}", ro[0].0);
    super::usbdisk::unmounted_by_user(&ro[0].0);
    ck!(s2.ro_mount_of(ro[0].1).is_none() && s2.user_off(ro[0].1), "the user's unmount of {} not recorded", ro[0].0);
    crate::time::sleep_ms(super::usbdisk::SETTLE_MS + 600);
    ck!(usb_desofs_mounts() == 1, "a partition the user unmounted came back by itself ({})", usb_desofs_mounts());
    // ... an unmount some other way (not through `desofs unmount`): the record follows the
    // mount table and the partition is mounted again.
    ck!(crate::fs::unmount(&ro[1].0).is_ok(), "unmount {}", ro[1].0);
    super::usbdisk::changed();
    ck!(wait_for(8_000, || usb_desofs_mounts() == 1 && s2.ro_mount_of(ro[1].1).is_some_and(|m| mounted(&m).is_some())), "a partition unmounted some other way not mounted again (stale record?)");
    ck!(flag(&s2, 0x20), "detach stick 2");
    ck!(wait_for(8_000, || find("blkd-2").is_none() && usb_desofs_mounts() == 0), "stick 2 not gone");
    // (b) `desofs unmount` of /disk: the write registration goes AT ONCE, /disk stays free,
    // the LKG has no volume; the stick plugged in again gets /disk back.
    let p1 = s1.disk_part().unwrap();
    ck!(crate::fs::unmount("/disk").is_ok(), "unmount /disk");
    super::usbdisk::unmounted_by_user("/disk");
    ck!(s1.disk_part().is_none() && block::is_read_only(p1), "/disk unmounted by the user: the stick still holds it or may write (record {:?})", s1.disk_part());
    let d1 = s1.index.load(Ordering::SeqCst);
    ck!(block::control(d1, Control::RegisterRw { generation: s1.generation, start: 2048, len: 5952 }) == Ok(0) && block::control(d1, Control::Withdraw) == Ok(0), "the rw registration left after /disk was unmounted");
    ck!(crate::time_lkg::file_state() == crate::time_lkg::FileState::NoVolume, "LKG still sees a system volume after /disk was unmounted");
    crate::time::sleep_ms(super::usbdisk::SETTLE_MS + 600);
    ck!(mounted("/disk").is_none() && usb_desofs_mounts() == 0, "the partition the user unmounted came back by itself ({:?})", mounted("/disk"));
    // ... unmounted some other way: dropped by the next decision and /disk given again.
    AUTO.store(false, Ordering::SeqCst);
    let g = s1.generation;
    ck!(flag(&s1, 0x40), "replug flag");
    ck!(wait_for(8_000, || find("blkd-1").is_some_and(|s| s.generation != g)), "blkd-1 not back");
    AUTO.store(true, Ordering::SeqCst);
    super::usbdisk::changed();
    ck!(wait_for(8_000, || find("blkd-1").is_some_and(|s| s.disk_part().is_some())), "the replugged stick did not get /disk");
    let s1 = find("blkd-1").unwrap();
    let p1 = s1.disk_part().unwrap();
    ck!(crate::fs::unmount("/disk").is_ok(), "unmount /disk");
    super::usbdisk::changed();
    ck!(wait_for(8_000, || s1.disk_part() == Some(p1) && mounted("/disk").is_some()), "/disk unmounted some other way not given again (stale owner?)");
    ck!(!crate::fs::is_read_only("/disk/x"), "/disk given again is read-only");
    // Stage D – programs from the disk.  A shell holding SYSCTL, SETTIME and HW_ROOT (like the
    // one init starts) copies programs to /disk/bin and runs them by name: found after
    // everything of the system, never instead of it, and given exactly what a /bin program gets.
    let sh_opts = |script: &[u8]| SpawnOptions { stdin: Some(script.to_vec()), capture: true, hw_root: true, sysctl: true, settime: true, ..SpawnOptions::default() };
    let run_sh = |script: &[u8], ms: u64| -> Result<(String, u64), String> {
        let id = exec("/bin/sh", &["sh"], "/", &sh_opts(script)).map_err(|_| String::from("cannot start /bin/sh"))?;
        let t0 = ticks();
        if !wait_for(ms, || sched::task_info(id).is_none()) {
            let _ = sched::request_exit(id);
            return Err(String::from("the shell did not finish"));
        }
        Ok((String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned(), ticks() - t0))
    };
    let (out, _) = run_sh(
        b"mkdir /disk/bin\ncp /bin/hello /disk/bin/hellod\ncp /bin/hello /disk/bin/primes\ncp /bin/hello /disk/bin/mem\n\
cp /bin/hello /disk/bin/echo\ncp /bin/hello /disk/bin/run\ncp /bin/privtest /disk/bin/privd\ncp /bin/sleep /disk/bin/napd\n\
mkdir /disk/x\ncp /bin/privtest /disk/x/netconfig\nhellod\nprimes 30\nmem\necho shadow-test\nrun\nprivtest\nprivd\n/disk/x/netconfig\nhelp\n",
        20_000,
    )?;
    ck!(out.matches("Hello from an ELF program").count() == 1, "a /disk/bin program ran instead of a system name, or not at all ({} runs of the copied hello): {:?}", out.matches("Hello from an ELF program").count(), out);
    ck!(out.contains("10 primes below 30"), "/disk/bin/primes hid /bin/primes: {:?}", out);
    ck!(out.contains("shadow-test\n") && out.contains("only in the kernel emergency shell"), "a /disk/bin program hid a built-in / a kernel-only name: {:?}", out);
    let priv_lines: Vec<&str> = out.lines().filter(|l| l.starts_with("privtest:")).collect();
    ck!(priv_lines.len() == 3 && priv_lines.iter().all(|l| *l == priv_lines[0]), "/bin/privtest, /disk/bin/privd and /disk/x/netconfig got different handles: {:?}", priv_lines);
    ck!(priv_lines[0].contains("sysctl refused") && priv_lines[0].contains("time_set refused") && !priv_lines[0].contains(" 4:") && !priv_lines[0].contains(" 7:"), "a program got SYSCTL / SETTIME: {:?}", priv_lines[0]);
    ck!(out.contains("Programs from the disk") && out.contains("hellod") && out.contains("privd"), "help does not list the /disk/bin programs: {:?}", out);
    // Removing the stick while a program from it runs: exec read the whole file first, so it
    // goes on; the next start finds nothing.  Stick 2 keeps a USB disk around (it brings stick
    // 1 back afterwards).
    ck!(flag(&s1, 0x200), "attach stick 2");
    ck!(wait_for(8_000, || find("blkd-2").is_some() && usb_desofs_mounts() == 2), "stick 2 not mounted read-only");
    let s2 = find("blkd-2").unwrap();
    let id = exec("/bin/sh", &["sh"], "/", &sh_opts(b"napd 2500\necho after-nap\nnapd 1\n")).map_err(|_| String::from("cannot start /bin/sh"))?;
    let t0 = ticks();
    ck!(wait_for(3_000, || sched::tasks().iter().any(|t| t.name == "napd")), "napd from /disk/bin did not start");
    ck!(flag(&s1, 0x20), "detach stick 1");
    ck!(wait_for(8_000, || mounted("/disk").is_none()), "/disk left after the stick went");
    ck!(wait_for(15_000, || sched::task_info(id).is_none()), "the shell with napd did not finish");
    let took = ticks() - t0;
    let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
    ck!(out.contains("after-nap") && took >= 2_400, "the program from the removed stick did not run to its end ({} ms): {:?}", took, out);
    ck!(out.contains("napd: command not found"), "the program started again with the stick gone: {:?}", out);
    ck!(flag(&s2, 0x800), "attach stick 1");
    ck!(flag(&s2, 0x20), "detach stick 2");
    ck!(wait_for(10_000, || find("blkd-2").is_none() && find("blkd-1").is_some_and(|s| s.disk_part().is_some())), "stick 1 not back at /disk");
    // Power loss at every write of an operation: the old or the new version, never anything
    // else, and the volume passes `desofs check` (it comes back read-write).
    let mut losses = 0;
    let mut newer = 0;
    ck!(crate::fs::create("/disk/pl").is_ok() || crate::fs::stat("/disk/pl").is_ok(), "create /disk/pl");
    // One operation = one DeSoFS transaction: an overwrite of the same length in place (a
    // `write_file` would be two – truncate, then write – and an empty file between is right).
    let ver = |v: u32| -> Vec<u8> { (0..9000u32).map(|i| (i.wrapping_mul(31) ^ v.wrapping_mul(0x9E37)) as u8).collect() };
    for k in 0..12u32 {
        let s1 = find("blkd-1").unwrap();
        let (old_v, new_v) = (ver(2 * k), ver(2 * k + 1));
        ck!(crate::fs::write("/disk/pl", 0, &old_v).is_ok_and(|n| n == old_v.len()), "write the old version");
        let g = s1.generation;
        ck!(flag(&s1, 0x100 | k << 16 | (k * 37 + 5) << 24), "power loss flag");
        let r = crate::fs::write("/disk/pl", 0, &new_v);
        crate::time::sleep_ms(300);
        if !s1.gone() {
            // The operation needed fewer writes than k: no loss happened.
            let _ = flag(&s1, 0x1000);
            ck!(r.is_ok(), "write without a loss: {:?}", r);
            continue;
        }
        losses += 1;
        ck!(wait_for(8_000, || find("blkd-1").is_some_and(|s| s.generation != g && s.disk_part().is_some())), "after the loss at write {}: /disk not back", k);
        ck!(!crate::fs::is_read_only("/disk/x"), "after the loss at write {}: /disk read-only (desofs check failed?)", k);
        let got = crate::fs::read_file("/disk/pl").unwrap_or_default();
        let is_new = got == new_v;
        ck!(is_new || got == old_v, "after the loss at write {}: neither the old nor the new version ({} bytes)", k, got.len());
        ck!(r.is_err() || is_new, "after the loss at write {}: the write was reported done but the old version came back", k);
        if is_new {
            newer += 1;
        }
    }
    ck!(losses >= 6, "only {} power losses happened", losses);
    // A stick whose FLUSH is refused: the probe fails – /disk only read-only.
    let s1 = find("blkd-1").unwrap();
    AUTO.store(false, Ordering::SeqCst);
    ck!(flag(&s1, 0x4000), "bad flush flag");
    let g = s1.generation;
    ck!(flag(&s1, 0x40), "replug flag");
    ck!(wait_for(8_000, || find("blkd-1").is_some_and(|s| s.generation != g)), "blkd-1 not back");
    AUTO.store(true, Ordering::SeqCst);
    super::usbdisk::changed();
    ck!(wait_for(8_000, || find("blkd-1").is_some_and(|s| s.disk_part().is_some())), "the stick with a refused FLUSH not at /disk");
    ck!(crate::fs::is_read_only("/disk/x"), "a stick whose FLUSH is refused mounted read-write (no probe?)");
    let s1 = find("blkd-1").unwrap();
    AUTO.store(false, Ordering::SeqCst);
    ck!(flag(&s1, 0x8000), "good flush flag");
    let g = s1.generation;
    ck!(flag(&s1, 0x40), "replug flag");
    ck!(wait_for(8_000, || find("blkd-1").is_some_and(|s| s.generation != g)), "blkd-1 not back");
    AUTO.store(true, Ordering::SeqCst);
    super::usbdisk::changed();
    ck!(wait_for(8_000, || find("blkd-1").is_some_and(|s| s.disk_part().is_some())) && !crate::fs::is_read_only("/disk/x"), "/disk not read-write again with a working FLUSH");
    // A damaged volume (a bad data block – `desofs check` finds it, mounting alone would
    // not): /disk only read-only, with the reason; nothing repaired by itself.
    let victim: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(0x01000193) >> 7) as u8 ^ 0x5A).collect();
    ck!(crate::fs::write_file("/disk/victim", &victim).is_ok(), "write /disk/victim");
    let s1 = find("blkd-1").unwrap();
    let d1 = s1.index.load(Ordering::SeqCst);
    let mut raw = alloc::vec![0u8; 8192 * 512];
    ck!(block::read(d1, 0, &mut raw).is_ok(), "read the stick");
    let at = (2048..8000usize).find(|&sec| raw[sec * 512..sec * 512 + 64] == victim[..64]);
    ck!(at.is_some(), "the file's data block not found on the stick");
    AUTO.store(false, Ordering::SeqCst);
    ck!(flag(&s1, 0x2000 | (at.unwrap() as u32) << 16), "damage flag");
    let g = s1.generation;
    ck!(flag(&s1, 0x40), "replug flag");
    ck!(wait_for(8_000, || find("blkd-1").is_some_and(|s| s.generation != g)), "blkd-1 not back");
    AUTO.store(true, Ordering::SeqCst);
    super::usbdisk::changed();
    ck!(wait_for(8_000, || find("blkd-1").is_some_and(|s| s.disk_part().is_some())), "the damaged volume not at /disk");
    ck!(crate::fs::is_read_only("/disk/x"), "a volume with a bad data block mounted read-write (desofs check skipped?)");
    Ok(alloc::format!("/disk in {} ms, power loss at writes 1-12: {} losses, {} new / {} old, FLUSH refused -> /disk read-only, a bad data block -> /disk read-only", to_disk_ms, losses, newer, losses - newer))
}

/// 2/2 – real usbd and the writable QEMU stick.
fn real_test() -> Result<String, String> {
    use crate::fs::desofs::format::format;
    let vectors0 = crate::arch::x86_64::msi::free_count();
    let _ = crate::fs::remove("/tmp/usbw-done");
    let internal = block::test_set_internal(None);
    crate::time_lkg::reset_for_test();
    let opts = SpawnOptions { stdin: Some(Vec::new()), capture: true, hw_root: true, sysctl: true, input: true, blk: true, ..SpawnOptions::default() };
    let id = exec("/bin/init", &["init", "test", "/bin/usbtest", "hold"], "/", &opts).map_err(|_| String::from("cannot start init"))?;
    let r = (|| -> Result<String, String> {
        macro_rules! ck {
            ($cond:expr, $($msg:tt)*) => {
                if !$cond {
                    return Err(alloc::format!($($msg)*));
                }
            };
        }
        let w = || super::ublk::list().into_iter().find(|s| !s.gone() && s.probed() && sys_parts(s.index.load(Ordering::SeqCst)).len() == 1 && s.desc.contains("QEMU"));
        ck!(wait_for(30_000, || w().is_some()), "writable test stick not found");
        let sh = w().unwrap();
        let p = sys_parts(sh.index.load(Ordering::SeqCst))[0];
        let r = format(p, &params());
        ck!(r.is_ok(), "format of the real stick: {:?}", r);
        AUTO.store(true, Ordering::SeqCst);
        super::usbdisk::changed();
        ck!(wait_for(10_000, || sh.disk_part() == Some(p)), "the real stick did not become /disk");
        ck!(!crate::fs::is_read_only("/disk/x"), "/disk from the real stick is read-only");
        let big: Vec<u8> = (0..(1u32 << 20)).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        let t0 = ticks();
        ck!(crate::fs::write_file("/disk/big", &big).is_ok(), "1 MiB file on the real stick");
        let w_ms = ticks() - t0;
        ck!(crate::fs::read_file("/disk/big").ok().as_deref() == Some(&big[..]), "1 MiB read back");
        ck!(crate::time_lkg::raise_for_test(T0 + 500) == crate::time_lkg::Raised::Saved && lkg_on_disk() == Some(T0 + 500), "LKG on the real stick");
        let marker = alloc::format!("{}", T0 + 500);
        ck!(crate::fs::write_file("/disk/usbrestart", marker.as_bytes()).is_ok(), "marker for the third start");
        // Unplugged and plugged back: /disk again, the files intact.
        let g = sh.generation;
        drop(sh);
        serial_println!("[HOTPLUG] device_del usbw");
        ck!(wait_for(15_000, || mounted("/disk").is_none()), "/disk still mounted after the stick was unplugged");
        ck!(crate::time_lkg::file_state() == crate::time_lkg::FileState::NoVolume, "file state after the stick went");
        serial_println!("[HOTPLUG] device_add usb-storage,bus=xhci.0,port=4,drive=usbw,id=usbw,share-rw=on");
        ck!(wait_for(20_000, || w().is_some_and(|s| s.generation > g && s.disk_part().is_some())), "the stick plugged back did not become /disk");
        ck!(crate::fs::read_file("/disk/big").ok().as_deref() == Some(&big[..]) && crate::fs::read_file("/disk/usbrestart").ok().as_deref() == Some(marker.as_bytes()), "files after replugging");
        ck!(crate::time_lkg::file_state() == crate::time_lkg::FileState::Good && lkg_on_disk() == Some(T0 + 500), "LKG after replugging");
        Ok(alloc::format!("formatted (session), /disk read-write, 1 MiB written in {} ms, LKG {} saved, unplugged -> /disk gone (no volume), plugged back -> /disk again with the files and the LKG", w_ms, T0 + 500))
    })();
    AUTO.store(false, Ordering::SeqCst);
    let _ = crate::fs::write_file("/tmp/usbw-done", b"1");
    let ok = wait_for(30_000, || sched::task_info(id).is_none());
    if !ok {
        let _ = sched::request_exit(id);
    }
    let _ = crate::fs::remove("/tmp/usbw-done");
    let gone = wait_for(5_000, || super::ublk::count() == 0) && wait_for(2_000, || mounted("/disk").is_none());
    block::test_restore_internal(internal);
    // The LKG as the boot left it (LKG TEST checks it): nothing in memory, no system volume.
    crate::time_lkg::reset_for_test();
    crate::time_lkg::volume_gone();
    let line = r?;
    let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
    if !(ok && out.lines().any(|l| l.starts_with("usbtest:") && l.contains("checks OK"))) {
        return Err(alloc::format!("usbtest hold: {:?}", out.trim()));
    }
    if !gone {
        return Err(String::from("USB disks / /disk left after usb0 stopped"));
    }
    if crate::arch::x86_64::msi::free_count() != vectors0 {
        return Err(String::from("MSI vectors leaked"));
    }
    Ok(line)
}

pub fn self_test() {
    serial_println!("[USB DISK TEST] Starting tests of a USB stick as /disk (format session, rules D2 / E / D, power loss)...");
    crate::selftest::begin();
    match fake_test() {
        Ok(l) => serial_println!(
            "[USB DISK TEST] 1/2 fake sticks: disk identities never wrap, format only in a session (ESP refused, session counter used up -> nothing written), the only candidate -> /disk read-write (probe, desofs check), LKG: older file / no file -> the time in memory written, stick lost during the save -> not saved, written later; /disk never taken away, 3 candidates -> none, the remaining one -> from /usbN to /disk, 2 partitions on one stick -> none, the internal disk keeps /disk (also damaged), /disk in use kept, no free /usbN -> not counted (used once freed), a working mount clears earlier failures, the user unmounts /usbN or /disk -> left alone until replugged (registration withdrawn at once), unmounted some other way -> record dropped, mounted again; programs from /disk/bin: run by name, never instead of a built-in / /bin / info / kernel-only name, the same handles as a /bin program (no SYSCTL, SETTIME or administration channel), still running after the stick is pulled, then not found; {} PASS",
            l
        ),
        Err(e) => {
            serial_println!("[USB DISK TEST] FAIL: 1/2: {}", e);
            return;
        }
    }
    match real_test() {
        Ok(l) => serial_println!("[USB DISK TEST] 2/2 usbd + writable QEMU stick: {} PASS", l),
        Err(e) => {
            serial_println!("[USB DISK TEST] FAIL: 2/2: {}", e);
            return;
        }
    }
    crate::selftest::pass();
}

/// USB RESTART TEST – the third start of tests/test.sh, QEMU without the virtio and NVMe disks:
/// no internal disk, the writable stick prepared by USB DISK TEST 2/2 becomes /disk by itself
/// (rules E / D2) and the last known good time is read from it at mount.
pub fn usb_restart() {
    serial_println!("[USB RESTART TEST] Starting: the writable stick from the first start as /disk...");
    crate::selftest::begin();
    let r = (|| -> Result<String, String> {
        if block::internal().is_some() {
            return Err(String::from("an internal disk exists (QEMU must run without virtio / NVMe)"));
        }
        AUTO.store(true, Ordering::SeqCst);
        super::usbdisk::changed();
        let _ = crate::fs::remove("/tmp/usbw-done");
        let opts = SpawnOptions { stdin: Some(Vec::new()), capture: true, hw_root: true, sysctl: true, input: true, blk: true, ..SpawnOptions::default() };
        let id = exec("/bin/init", &["init", "test", "/bin/usbtest", "hold"], "/", &opts).map_err(|_| String::from("cannot start init"))?;
        let t0 = ticks();
        let up = wait_for(40_000, || super::ublk::list().iter().any(|s| s.disk_part().is_some()));
        let ms = ticks() - t0;
        let res = (|| -> Result<String, String> {
            if !up {
                return Err(String::from("the stick did not become /disk"));
            }
            let marker = crate::fs::read_file("/disk/usbrestart").map_err(|e| alloc::format!("/disk/usbrestart: {}", e))?;
            let want: u64 = core::str::from_utf8(&marker).ok().and_then(|t| t.trim().parse().ok()).ok_or_else(|| String::from("bad marker"))?;
            let snap = crate::time_lkg::snapshot();
            if snap.lkg != want || snap.file != 3 || crate::fs::is_read_only("/disk/x") {
                return Err(alloc::format!("LKG {} (want {}), file state {}, read-only {}", snap.lkg, want, snap.file, crate::fs::is_read_only("/disk/x")));
            }
            if crate::fs::read_file("/disk/big").map(|b| b.len()).unwrap_or(0) != 1 << 20 {
                return Err(String::from("/disk/big from the first start missing"));
            }
            Ok(alloc::format!("/disk = the USB stick read-write {} ms after init started, LKG {} read from it at mount (file good), files of the first start there", ms, want))
        })();
        AUTO.store(false, Ordering::SeqCst);
        let _ = crate::fs::write_file("/tmp/usbw-done", b"1");
        if !wait_for(30_000, || sched::task_info(id).is_none()) {
            let _ = sched::request_exit(id);
        }
        res
    })();
    match r {
        Ok(l) => {
            serial_println!("[USB RESTART TEST] third start without virtio / NVMe: {} PASS", l);
            crate::selftest::pass();
        }
        Err(e) => serial_println!("[USB RESTART TEST] FAIL: {}", e),
    }
}

/// ONE STICK TEST (V080 stage C) – QEMU started from an image made by tools/mkusb.py (the code of
/// `make-usb.sh --with-disk`), nothing else attached: UEFI loads BOOTX64.EFI from its ESP, the
/// stick's ESP is /usb0 (read-only) and its "DeSoOS system" partition /disk (read-write) – both
/// from the same disk.  Start 1 writes a file and the last known good time; start 2 (the same
/// image, in tests/make-usb-test.sh after the ESP got a new build) finds both, and `tag` – when
/// given – is the build tag the running kernel must have.
pub fn one_stick(part: u32, tag: u64) {
    serial_println!("[ONE STICK TEST] Starting part {}: started from a make-usb.sh --with-disk image...", part);
    crate::selftest::begin();
    let r = (|| -> Result<String, String> {
        if block::internal().is_some() {
            return Err(String::from("an internal disk exists (QEMU must run with the stick image only)"));
        }
        AUTO.store(true, Ordering::SeqCst);
        super::usbdisk::changed();
        let _ = crate::fs::remove("/tmp/usbw-done");
        let opts = SpawnOptions { stdin: Some(Vec::new()), capture: true, hw_root: true, sysctl: true, input: true, blk: true, ..SpawnOptions::default() };
        let id = exec("/bin/init", &["init", "test", "/bin/usbtest", "hold"], "/", &opts).map_err(|_| String::from("cannot start init"))?;
        let t0 = ticks();
        let up = wait_for(40_000, || super::ublk::list().iter().any(|s| s.disk_part().is_some()) && mounted("/usb0").is_some());
        let ms = ticks() - t0;
        let res = (|| -> Result<String, String> {
            if !up {
                return Err(alloc::format!("/disk or /usb0 missing (/disk {:?}, /usb0 {:?})", mounted("/disk"), mounted("/usb0")));
            }
            let sticks = super::ublk::list();
            if sticks.len() != 1 {
                return Err(alloc::format!("{} USB disks, expected the one stick", sticks.len()));
            }
            let disk = sticks[0].index.load(Ordering::SeqCst);
            let parent = |p: &str| crate::fs::mounted_disk(p).and_then(|d| block::with_device(d, |x| x.parent()).ok().flatten());
            if parent("/usb0") != Some(disk) || parent("/disk") != Some(disk) {
                return Err(alloc::format!("/usb0 and /disk not both from the stick (disk {}): {:?} / {:?}", disk, parent("/usb0"), parent("/disk")));
            }
            let esp = crate::fs::mounted_disk("/usb0").unwrap_or(usize::MAX);
            if block::partition_kind(esp) != Some("EFI System") || !crate::fs::is_read_only("/usb0/x") || crate::fs::write_file("/usb0/X.TXT", b"x").is_ok() {
                return Err(String::from("/usb0 is not the read-only ESP"));
            }
            if crate::fs::is_read_only("/disk/x") {
                return Err(String::from("/disk is read-only"));
            }
            if crate::fs::read_file("/usb0/EFI/BOOT/BOOTX64.EFI").map(|b| b.len()).unwrap_or(0) < 1 << 20 {
                return Err(String::from("BOOTX64.EFI not readable on /usb0"));
            }
            let build = crate::shell::BUILD_TAG.filter(|t| !t.is_empty()).unwrap_or("");
            if tag != 0 && crate::selftest::pack_tag(build) != tag {
                return Err(alloc::format!("this kernel is build {:?}, not the expected one", build));
            }
            let lkg = crate::drivers::rtc::BUILD_EPOCH + 10 * 86_400;
            if part == 1 {
                if crate::fs::stat("/disk/onestick").is_ok() {
                    return Err(String::from("/disk/onestick exists on a new stick"));
                }
                crate::fs::write_file("/disk/onestick", alloc::format!("{}", lkg).as_bytes()).map_err(|e| alloc::format!("write /disk/onestick: {}", e))?;
                let r = crate::time_lkg::raise_for_test(lkg);
                if r != crate::time_lkg::Raised::Saved || lkg_on_disk() != Some(lkg) {
                    return Err(alloc::format!("LKG not saved on the stick: {:?}, file {:?}", r, lkg_on_disk()));
                }
                Ok(alloc::format!("/usb0 = ESP read-only, /disk = DeSoOS system read-write {} ms after init started (one disk), file and LKG {} written", ms, lkg))
            } else {
                let marker = crate::fs::read_file("/disk/onestick").map_err(|e| alloc::format!("/disk/onestick from start 1: {}", e))?;
                let want: u64 = core::str::from_utf8(&marker).ok().and_then(|t| t.trim().parse().ok()).ok_or_else(|| String::from("bad /disk/onestick"))?;
                let snap = crate::time_lkg::snapshot();
                if snap.lkg != want || snap.file != 3 {
                    return Err(alloc::format!("LKG {} (want {} from start 1), file state {}", snap.lkg, want, snap.file));
                }
                Ok(alloc::format!("the same image again{}: /disk read-write {} ms after init started, the file and LKG {} of start 1 there (read at mount)", if build.is_empty() { String::new() } else { alloc::format!(", build {}", build) }, ms, want))
            }
        })();
        AUTO.store(false, Ordering::SeqCst);
        let _ = crate::fs::write_file("/tmp/usbw-done", b"1");
        if !wait_for(30_000, || sched::task_info(id).is_none()) {
            let _ = sched::request_exit(id);
        }
        res
    })();
    match r {
        Ok(l) => {
            serial_println!("[ONE STICK TEST] {}/2 {} PASS", part, l);
            crate::selftest::pass();
        }
        Err(e) => serial_println!("[ONE STICK TEST] FAIL: {}/2: {}", part, e),
    }
}
