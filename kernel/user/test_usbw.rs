// USB WRITE TEST – writing to a USB stick (v0.80 stage A; the rules: docs/ARCHITECTURE.md,
// "Writing to a USB disk").  Only in builds with --cfg selftest.
//
// 1/3 the kernel side without hardware: /bin/blkwtest pretends to be a writable stick
//     (it is NOT a lock – the medium shows what got through the kernel's two locks): write
//     protection, no registration, probe (and its late reply), rw, the first and the second
//     lock each alone, 64 KiB pieces and a failed piece, a write timeout, format sessions,
//     generations and the counters that never wrap.
// 2/3 real usbd and the writable QEMU stick (GPT: ESP + "DeSo system", tests/mkgpt.py):
//     probe with a real SYNCHRONIZE CACHE, write / read back / flush, the ESP never changes,
//     the third lock (usbd) alone, a stale generation, usbd's errors reaching the kernel, a
//     held probe reply, read-only sticks refused.
// 3/3 the stick unplugged during writes (QEMU monitor) and usbd killed during writes: the
//     disk comes back with a new generation and no registration, every sector is the old
//     or the new version.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::*;
use crate::block::{self, BlockError, Control};
use crate::time::ticks;

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

/// Sector `lba` of version `ver`: the LBA, the version, then a pattern of both.
fn vpat(ver: u8, lba: u64, i: usize) -> u8 {
    if i < 8 {
        (lba >> (8 * i)) as u8
    } else if i == 8 {
        ver
    } else {
        (lba.wrapping_mul(7) as usize + i * 13) as u8 ^ ver.wrapping_mul(0x5b)
    }
}

fn fill(ver: u8, lba: u64, buf: &mut [u8]) {
    for (k, b) in buf.iter_mut().enumerate() {
        *b = vpat(ver, lba + (k / 512) as u64, k % 512);
    }
}

fn is_ver(ver: u8, lba: u64, sector: &[u8]) -> bool {
    sector.iter().enumerate().all(|(i, &b)| b == vpat(ver, lba, i))
}

/// The partitions of USB disk `disk`: (ESP, "DeSo system") block numbers, if both exist.
fn parts(disk: usize) -> Option<(usize, usize)> {
    let ps = block::partitions_of(disk);
    let esp = ps.iter().copied().find(|&p| block::partition_kind(p) == Some("EFI System"))?;
    let sys = ps.iter().copied().find(|&p| block::partition_kind(p) == Some(crate::gpt::DESO_SYSTEM_NAME))?;
    Some((esp, sys))
}

/// (start, length) of the "DeSo system" partition of `disk` in device blocks (512 B here).
fn sys_range(disk: usize) -> Option<(u64, u64)> {
    let ps = crate::gpt::read(disk).ok()??;
    let p = ps.iter().find(|p| p.kind == crate::gpt::DESO_SYSTEM_NAME)?;
    Some((p.first_sector, p.sectors))
}

fn generation(disk: usize) -> u64 {
    block::control(disk, Control::Generation).unwrap_or(0)
}

/// 1/3 – the fake stick.
fn fake_test() -> Result<String, String> {
    use super::ublk::{TEST_SKIP_UBLK_CHECK, WP_CLEAR, WP_UNKNOWN};
    use crate::block::TEST_SKIP_PARTITION_CHECK;
    macro_rules! ck {
        ($cond:expr, $($msg:tt)*) => {
            if !$cond {
                TEST_SKIP_UBLK_CHECK.store(false, Ordering::SeqCst);
                TEST_SKIP_PARTITION_CHECK.store(false, Ordering::SeqCst);
                return Err(alloc::format!($($msg)*));
            }
        };
    }
    let free0 = crate::selftest::settled_free_frames();
    let opts = SpawnOptions { stdin: Some(Vec::new()), capture: true, blk: true, ..SpawnOptions::default() };
    let id = exec("/bin/blkwtest", &["blkwtest"], "/", &opts).map_err(|_| String::from("cannot start /bin/blkwtest"))?;
    let find = |name: &str| super::ublk::list().into_iter().find(|s| s.desc == name);
    ck!(wait_for(10_000, || find("blkwtest").is_some_and(|s| s.probed()) && find("blkwtest-wp").is_some_and(|s| s.probed())), "blkwtest disks not attached / not probed");
    let (sa, sb) = (find("blkwtest").unwrap(), find("blkwtest-wp").unwrap());
    let (a, b) = (sa.index.load(Ordering::SeqCst), sb.index.load(Ordering::SeqCst));
    let pp = parts(a);
    ck!(pp.is_some(), "blkwtest disk {}: no ESP + DeSo system partitions", a);
    let (p1, p2) = pp.unwrap();
    let (ga, gb) = (generation(a), generation(b));
    ck!(ga != 0 && gb != 0 && ga != gb, "generations {} / {}", ga, gb);
    ck!(block::control(a, Control::WriteProtect) == Ok(WP_CLEAR as u64) && block::control(b, Control::WriteProtect) == Ok(WP_UNKNOWN as u64), "write protection as reported");
    // Write protection unknown – no registration of any kind.
    ck!(block::control(b, Control::Probe { generation: gb }) == Err(BlockError::ReadOnly), "probe on a disk with unknown write protection");
    ck!(block::control(b, Control::RegisterRw { generation: gb, start: 0, len: 8 }) == Err(BlockError::ReadOnly), "rw on a disk with unknown write protection");
    ck!(block::control(b, Control::BeginFormat { generation: gb, start: 0, len: 8 }) == Err(BlockError::ReadOnly), "format on a disk with unknown write protection");
    // Nothing registered: the whole disk, a partition without a grant, a grant without a registration.
    let (start, len) = (2048u64, 5952u64);
    let mut s1 = alloc::vec![0u8; 512];
    fill(1, 0, &mut s1);
    ck!(block::write(a, 2048, &s1) == Err(BlockError::ReadOnly), "write to the whole USB disk");
    ck!(block::write(p2, 0, &s1) == Err(BlockError::ReadOnly), "write to a partition without a grant");
    ck!(block::set_grant(p2, Some(0)).is_ok(), "grant on the partition");
    let refused0 = sa.refused.load(Ordering::SeqCst);
    ck!(block::write(p2, 0, &s1) == Err(BlockError::ReadOnly), "write with a grant but no registration");
    ck!(block::flush(p2) == Err(BlockError::ReadOnly), "flush with a grant but no registration");
    ck!(sa.refused.load(Ordering::SeqCst) == refused0 + 2, "the second lock did not count its refusals");
    // Probe: one FLUSH, then nothing; a stale generation; a held reply = timeout, late reply discarded.
    ck!(block::control(a, Control::Probe { generation: ga + 1 }) == Err(BlockError::NoDevice), "probe with a stale generation");
    ck!(block::control(a, Control::Probe { generation: ga }) == Ok(0), "probe");
    ck!(block::write(p2, 0, &s1) == Err(BlockError::ReadOnly), "a probe gave a write");
    ck!(block::control(a, Control::Test { flags: 4 }) == Ok(0), "test flag");
    let late0 = sa.late.load(Ordering::SeqCst);
    let t0 = ticks();
    let r = block::control(a, Control::Probe { generation: ga });
    let probe_ms = ticks() - t0;
    ck!(r == Err(BlockError::Timeout) && (900..3000).contains(&probe_ms), "held probe reply: {:?} after {} ms", r, probe_ms);
    let mut rb = alloc::vec![0u8; 512];
    ck!(block::read(a, 0, &mut rb).is_ok(), "read after the probe timeout");
    ck!(sa.late.load(Ordering::SeqCst) > late0, "the late probe reply was not discarded as late");
    ck!(block::write(p2, 0, &s1) == Err(BlockError::ReadOnly), "the late probe reply gave a write");
    // rw: one registration at a time, write / read back / flush.
    ck!(block::control(a, Control::RegisterRw { generation: ga, start: u64::MAX - 1, len: 5 }) == Err(BlockError::OutOfRange), "rw range with an overflow");
    ck!(block::control(a, Control::RegisterRw { generation: ga, start: 8000, len: 1000 }) == Err(BlockError::OutOfRange), "rw range past the disk");
    ck!(block::control(a, Control::RegisterRw { generation: ga, start, len }) == Ok(0), "rw registration");
    ck!(block::control(a, Control::RegisterRw { generation: ga, start, len }) == Err(BlockError::Unsupported), "a second registration");
    let mut big = alloc::vec![0u8; 1 << 20];
    fill(1, start, &mut big);
    ck!(block::write(p2, 0, &big) == Ok(()), "1 MiB write (16 pieces)");
    let mut back = alloc::vec![0u8; 1 << 20];
    ck!(block::read(a, start * 1, &mut back).is_ok() && back == big, "1 MiB read back through the whole disk");
    let fl0 = sa.flushes.load(Ordering::SeqCst);
    ck!(block::flush(p2) == Ok(()) && sa.flushes.load(Ordering::SeqCst) == fl0 + 1, "flush");
    // The first lock: the partition's range.
    let mut two = alloc::vec![0u8; 1024];
    fill(9, start + len - 1, &mut two);
    let mut edge0 = alloc::vec![0u8; 512];
    ck!(block::read(a, start + len, &mut edge0).is_ok(), "read past the partition");
    let ref0 = sa.refused.load(Ordering::SeqCst);
    ck!(block::write(p2, len - 1, &two) == Err(BlockError::OutOfRange), "first lock: write across the partition end");
    ck!(block::write(p2, len, &s1) == Err(BlockError::OutOfRange), "first lock: write past the partition end");
    ck!(sa.refused.load(Ordering::SeqCst) == ref0, "the first lock let a write outside the partition through to the disk");
    // The second lock alone.
    TEST_SKIP_PARTITION_CHECK.store(true, Ordering::SeqCst);
    let ref1 = sa.refused.load(Ordering::SeqCst);
    ck!(block::write(p2, len - 1, &two) == Err(BlockError::OutOfRange), "second lock: write across the partition end");
    ck!(block::write(p2, len, &s1) == Err(BlockError::OutOfRange), "second lock: write past the partition end");
    ck!(sa.refused.load(Ordering::SeqCst) == ref1 + 2, "second lock refusals not counted");
    let mut piece = alloc::vec![0u8; 128 * 512];
    fill(9, start + len - 64, &mut piece);
    let mut tail0 = alloc::vec![0u8; 64 * 512];
    ck!(block::read(a, start + len - 64, &mut tail0).is_ok(), "read the partition's last 32 KiB");
    ck!(block::write(p2, len - 64, &piece) == Err(BlockError::OutOfRange), "a 64 KiB piece across the partition end");
    let mut tail = alloc::vec![0u8; 64 * 512];
    ck!(block::read(a, start + len - 64, &mut tail).is_ok() && tail == tail0, "the inside half of a refused piece was written");
    let mut edge1 = alloc::vec![0u8; 512];
    ck!(block::read(a, start + len, &mut edge1).is_ok() && edge1 == edge0, "the sector past the partition changed");
    let mut esp = alloc::vec![0u8; 512];
    ck!(block::read(a, 100, &mut esp).is_ok(), "read the ESP");
    ck!(block::with_device(a, |d| d.write_range(100, &s1, 0)) == Ok(Err(BlockError::OutOfRange)), "second lock: write into the ESP");
    ck!(block::write(p1, 0, &s1) == Err(BlockError::ReadOnly), "write to the ESP partition");
    ck!(block::with_device(a, |d| d.write_range(u64::MAX - 1, &s1, 0)) == Ok(Err(BlockError::OutOfRange)), "lba near u64::MAX");
    ck!(block::with_device(a, |d| d.write_range(start, &[], 0)) == Ok(Err(BlockError::BadBuffer)), "an empty write");
    // Both kernel locks off: the fake takes it – what the locks are for.
    TEST_SKIP_UBLK_CHECK.store(true, Ordering::SeqCst);
    ck!(block::write(p2, len, &s1) == Ok(()), "without the first two locks the write must reach the device");
    TEST_SKIP_UBLK_CHECK.store(false, Ordering::SeqCst);
    TEST_SKIP_PARTITION_CHECK.store(false, Ordering::SeqCst);
    let mut esp1 = alloc::vec![0u8; 512];
    ck!(block::read(a, 100, &mut esp1).is_ok() && esp1 == esp, "the ESP changed");
    // A grant with the wrong tag.
    ck!(block::set_grant(p2, Some(7)).is_ok() && block::write(p2, 0, &s1) == Err(BlockError::ReadOnly), "rw registration took a format tag");
    ck!(block::set_grant(p2, Some(0)).is_ok(), "grant back");
    // Rule G: a failed piece (first, middle, last) fails the whole write.
    for k in [0u32, 7, 15] {
        ck!(block::control(a, Control::Test { flags: 2 | k << 8 }) == Ok(0), "test flag");
        let r = block::write(p2, 0, &big);
        ck!(r == Err(BlockError::Io), "piece {} failed but the write gave {:?}", k + 1, r);
    }
    ck!(block::write(p2, 0, &big) == Ok(()), "write after the failed pieces");
    // A write whose reply is late: Timeout, the slot quarantined and back after the late reply.
    // Its id is the last before the 32-bit counter wraps; the counter is then set back to it –
    // a quarantined id is never given out again, so the late reply cannot answer the next write.
    ck!(block::control(a, Control::Test { flags: 16 }) == Ok(0), "test flag");
    ck!(block::control(a, Control::TestNextId { id: u32::MAX }) == Ok(0), "id counter");
    let (late1, proto1) = (sa.late.load(Ordering::SeqCst), sa.proto_errors.load(Ordering::SeqCst));
    let r = block::write(p2, 0, &s1);
    ck!(r == Err(BlockError::Timeout), "held write reply: {:?}", r);
    ck!(block::control(a, Control::TestNextId { id: u32::MAX }) == Ok(0), "id counter");
    let mut s2 = alloc::vec![0u8; 512];
    fill(2, start, &mut s2);
    ck!(block::write(p2, 0, &s2) == Ok(()), "write after the late reply");
    ck!(sa.late.load(Ordering::SeqCst) == late1 + 1 && sa.proto_errors.load(Ordering::SeqCst) == proto1, "late reply after the id wrap: late {} -> {}, protocol errors {} -> {} (the old id was reused?)", late1, sa.late.load(Ordering::SeqCst), proto1, sa.proto_errors.load(Ordering::SeqCst));
    ck!(block::read(a, start, &mut rb).is_ok() && rb == s2, "the write after the id wrap did not land");
    // Withdrawn – nothing.
    ck!(block::control(a, Control::Withdraw) == Ok(0), "withdraw");
    ck!(block::write(p2, 0, &s1) == Err(BlockError::ReadOnly) && block::flush(p2) == Err(BlockError::ReadOnly), "write / flush after the withdrawal");
    // Format sessions: only their identifier writes and flushes; ended – never again.
    let s_a = block::control(a, Control::BeginFormat { generation: ga, start, len });
    ck!(matches!(s_a, Ok(s) if s != 0), "begin format: {:?}", s_a);
    let s_a = s_a.unwrap();
    ck!(block::set_grant(p2, Some(s_a)).is_ok() && block::write(p2, 0, &s1) == Ok(()) && block::flush(p2) == Ok(()), "write / flush in the format session");
    ck!(block::set_grant(p2, Some(0)).is_ok() && block::write(p2, 0, &s1) == Err(BlockError::ReadOnly) && block::flush(p2) == Err(BlockError::ReadOnly), "ordinary write / flush during the format session");
    ck!(block::set_grant(p2, Some(s_a + 1)).is_ok() && block::write(p2, 0, &s1) == Err(BlockError::ReadOnly), "a foreign session identifier");
    ck!(block::control(a, Control::EndFormat { session: s_a }) == Ok(0), "end format");
    ck!(block::set_grant(p2, Some(s_a)).is_ok() && block::write(p2, 0, &s1) == Err(BlockError::ReadOnly) && block::flush(p2) == Err(BlockError::ReadOnly), "the ended session still writes");
    let s_b = block::control(a, Control::BeginFormat { generation: ga, start, len });
    ck!(matches!(s_b, Ok(s) if s > s_a), "a new session must have a new identifier: {:?} after {}", s_b, s_a);
    ck!(block::control(a, Control::EndFormat { session: s_b.unwrap() }) == Ok(0), "end format");
    // The counters never wrap: a session / a generation that would not fit – refused.
    let saved = super::ublk::test_set_counters(None, Some(u64::MAX));
    let r = block::control(a, Control::BeginFormat { generation: ga, start, len });
    super::ublk::test_set_counters(None, Some(saved.1));
    ck!(r == Err(BlockError::Unsupported), "format with the session counter used up: {:?}", r);
    ck!(block::set_grant(p2, Some(0)).is_ok() && block::write(p2, 0, &s1) == Err(BlockError::ReadOnly), "a refused format left a registration");
    let _ = block::set_grant(p2, None);
    super::ublk::test_set_counters(Some(u64::MAX), None);
    let ov = exec("/bin/blkwtest", &["blkwtest", "overflow"], "/", &opts);
    let ov_ok = ov.is_ok_and(|o| wait_for(10_000, || sched::task_info(o).is_none()) && String::from_utf8_lossy(&captured_output(o).unwrap_or_default()).contains("overflow refused"));
    super::ublk::test_set_counters(Some(saved.0), None);
    ck!(ov_ok, "blk_attach with the generation counter used up was not refused");
    // A partition object of a removed disk never reaches the disk that got its number: an
    // operation holding the old partition, the stick replugged (same layout, rw granted).
    ck!(block::control(a, Control::RegisterRw { generation: ga, start, len }) == Ok(0), "rw before the replug");
    ck!(block::set_grant(p2, Some(0)).is_ok(), "grant before the replug");
    let old = block::hold(p2);
    ck!(old.is_some(), "hold the partition");
    let old = old.unwrap();
    let (old_a, old_p2) = (a, p2);
    ck!(block::control(a, Control::Test { flags: 0x40 }) == Ok(0), "replug flag");
    drop(sa);
    ck!(wait_for(10_000, || find("blkwtest").is_some_and(|s| s.generation != ga && s.probed())), "the replugged fake stick not attached");
    let sa = find("blkwtest").unwrap();
    let a = sa.index.load(Ordering::SeqCst);
    let pp = parts(a);
    ck!(pp.is_some(), "replugged stick: no partitions");
    let (_, p2) = pp.unwrap();
    ck!(a == old_a && p2 == old_p2, "the numbers were not reused (disk {} -> {}, partition {} -> {}) - the test needs them reused", old_a, a, old_p2, p2);
    let ga2 = generation(a);
    ck!(block::control(a, Control::Probe { generation: ga2 }) == Ok(0) && block::control(a, Control::RegisterRw { generation: ga2, start, len }) == Ok(0) && block::set_grant(p2, Some(0)).is_ok(), "rw on the replugged stick");
    let mut before = alloc::vec![0u8; 512];
    ck!(block::read(a, start + 100, &mut before).is_ok(), "read the replugged stick");
    let mut s3 = alloc::vec![0u8; 512];
    fill(3, start + 100, &mut s3);
    let r = old.write(100, &s3);
    let rf = old.flush();
    ck!(r == Err(BlockError::NoDevice) && rf == Err(BlockError::NoDevice), "the old partition object wrote to the new disk: write {:?}, flush {:?}", r, rf);
    let mut after = alloc::vec![0u8; 512];
    ck!(block::read(a, start + 100, &mut after).is_ok() && after == before, "the new disk changed through the old partition");
    ck!(block::write(p2, 100, &s3) == Ok(()), "the new partition object writes");
    drop(old);
    // The end: the fake exits, both disks go.
    ck!(block::control(a, Control::Test { flags: 0x80 }) == Ok(0), "exit flag");
    drop((sa, sb));
    ck!(wait_for(10_000, || sched::task_info(id).is_none()), "blkwtest did not exit");
    ck!(wait_for(5_000, || super::ublk::count() == 0), "blkwtest disks not removed");
    let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
    let line = out.lines().find(|l| l.starts_with("blkwtest:")).unwrap_or("").trim();
    ck!(exit_info(id).map(|e| e.kind) == Some(ExitKind::Exit(0)) && line.contains("checks OK") && line.ends_with("bad 0"), "blkwtest: {:?}", out.trim());
    crate::sched::reap();
    let free1 = crate::selftest::settled_free_frames();
    ck!(free1 >= free0, "frames leaked ({} -> {})", free0, free1);
    Ok(alloc::format!("probe timeout {} ms, {}", probe_ms, line))
}

// The writer task of 3/3: writes version WRITER_VER over the region again and again,
// 64 KiB at a time, until a write fails.
static WRITER_PART: AtomicUsize = AtomicUsize::new(usize::MAX);
static WRITER_VER: AtomicU64 = AtomicU64::new(0);
static WRITER_START: AtomicU64 = AtomicU64::new(0);
static WRITER_PIECES: AtomicU64 = AtomicU64::new(0);
static WRITER_DONE: AtomicU64 = AtomicU64::new(0);
const REGION: u64 = 512; // sectors (256 KiB) at partition sector 4096

fn writer(_: usize) {
    let part = WRITER_PART.load(Ordering::SeqCst);
    let ver = WRITER_VER.load(Ordering::SeqCst) as u8;
    let start = WRITER_START.load(Ordering::SeqCst);
    let mut buf = alloc::vec![0u8; 128 * 512];
    let t0 = ticks();
    'outer: while ticks() - t0 < 30_000 {
        let mut off = 0;
        while off < REGION {
            fill(ver, start + 4096 + off, &mut buf);
            if block::write(part, 4096 + off, &buf).is_err() {
                break 'outer;
            }
            WRITER_PIECES.fetch_add(1, Ordering::SeqCst);
            off += 128;
        }
    }
    WRITER_DONE.store(1, Ordering::SeqCst);
}

/// The writable QEMU stick: (disk, ESP, system partition, its start / length).
fn writable() -> Option<(usize, usize, usize, u64, u64)> {
    for sh in super::ublk::list() {
        if sh.gone() || !sh.probed() {
            continue;
        }
        let d = sh.index.load(Ordering::SeqCst);
        if let (Some((esp, sys)), Some((s, l))) = (parts(d), sys_range(d)) {
            return Some((d, esp, sys, s, l));
        }
    }
    None
}

/// Registers rw on the writable stick's system partition and grants it.
fn open_rw(d: usize, sys: usize, s: u64, l: u64) -> Result<(), BlockError> {
    block::control(d, Control::Probe { generation: generation(d) })?;
    block::control(d, Control::RegisterRw { generation: generation(d), start: s, len: l })?;
    block::set_grant(sys, Some(0))
}

/// Every sector of the region (partition sector 4096..) is version `old` or `new`:
/// Ok((sectors with the new version)).
fn check_region(d: usize, s: u64, old: u8, new: u8) -> Result<u64, String> {
    let mut buf = alloc::vec![0u8; REGION as usize * 512];
    block::read(d, s + 4096, &mut buf).map_err(|e| alloc::format!("read the region: {}", e))?;
    let mut newer = 0;
    for k in 0..REGION as usize {
        let lba = s + 4096 + k as u64;
        let sec = &buf[k * 512..(k + 1) * 512];
        if is_ver(new, lba, sec) {
            newer += 1;
        } else if !is_ver(old, lba, sec) {
            return Err(alloc::format!("sector {} is neither version {} nor {} (torn / garbage)", lba, old, new));
        }
    }
    Ok(newer)
}

/// 2/3 and 3/3 – real usbd (via init, `usbtest hold`) and the writable QEMU stick.
fn real_test() -> Result<(String, String), String> {
    use super::ublk::{TEST_GEN_OFFSET, TEST_SKIP_UBLK_CHECK, WP_CLEAR, WP_SET};
    use crate::block::TEST_SKIP_PARTITION_CHECK;
    let vectors0 = crate::arch::x86_64::msi::free_count();
    let free0 = crate::selftest::settled_free_frames();
    let _ = crate::fs::remove("/tmp/usbw-done");
    let opts = SpawnOptions { stdin: Some(Vec::new()), capture: true, hw_root: true, sysctl: true, input: true, blk: true, ..SpawnOptions::default() };
    let id = exec("/bin/init", &["init", "test", "/bin/usbtest", "hold"], "/", &opts).map_err(|_| String::from("cannot start init"))?;
    // A failure: the hooks off, usbtest released and init (with usb0) gone before the next
    // suite – it must find the hardware free.
    macro_rules! ck {
        ($cond:expr, $($msg:tt)*) => {
            if !$cond {
                TEST_SKIP_UBLK_CHECK.store(false, Ordering::SeqCst);
                TEST_SKIP_PARTITION_CHECK.store(false, Ordering::SeqCst);
                TEST_GEN_OFFSET.store(0, Ordering::SeqCst);
                let _ = crate::fs::write_file("/tmp/usbw-done", b"1");
                if !wait_for(30_000, || sched::task_info(id).is_none()) {
                    let _ = sched::request_exit(id);
                }
                // What usbd and init said (their console is init's captured output).
                let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
                let tail: Vec<&str> = out.lines().rev().take(12).collect();
                for l in tail.iter().rev() {
                    serial_println!("[USB WRITE TEST]   init/usbd: {}", l);
                }
                return Err(alloc::format!($($msg)*));
            }
        };
    }
    ck!(wait_for(30_000, || writable().is_some()), "writable test stick (GPT: ESP + DeSo system) not found");
    let (d, p1, p2, s, l) = writable().unwrap();
    let sh = super::ublk::list().into_iter().find(|x| x.index.load(Ordering::SeqCst) == d).unwrap();
    // The read-only sticks report write protection and get nothing.
    ck!(sh.wp == WP_CLEAR, "writable stick: write protection {} (want off)", sh.wp);
    let ro: Vec<_> = super::ublk::list().into_iter().filter(|x| x.index.load(Ordering::SeqCst) != d && !x.gone()).collect();
    ck!(!ro.is_empty() && ro.iter().all(|x| x.wp == WP_SET), "read-only sticks: write protection {:?} (want ON)", ro.iter().map(|x| x.wp).collect::<Vec<_>>());
    for x in &ro {
        let i = x.index.load(Ordering::SeqCst);
        ck!(block::control(i, Control::Probe { generation: x.generation }) == Err(BlockError::ReadOnly), "probe on a write-protected stick");
    }
    drop(ro);
    let mut esp0 = alloc::vec![0u8; 64 * 512];
    ck!(block::read(p1, 0, &mut esp0).is_ok() && is_ver_esp(&esp0), "ESP marker not readable");
    // Probe (a real SYNCHRONIZE CACHE), rw, 1 MiB written and read back, flush.
    ck!(open_rw(d, p2, s, l).is_ok(), "probe / rw registration on the writable stick");
    let mut big = alloc::vec![0u8; 1 << 20];
    fill(1, s, &mut big);
    let t0 = ticks();
    ck!(block::write(p2, 0, &big) == Ok(()), "1 MiB write");
    let w_ms = ticks() - t0;
    let mut back = alloc::vec![0u8; 1 << 20];
    ck!(block::read(d, s, &mut back).is_ok() && back == big, "1 MiB read back");
    ck!(block::flush(p2) == Ok(()), "flush (SYNCHRONIZE CACHE)");
    // The ESP: no grant, the second lock, the third lock alone.
    let mut s1 = alloc::vec![0u8; 512];
    fill(7, 2048, &mut s1);
    ck!(block::write(p1, 0, &s1) == Err(BlockError::ReadOnly), "write to the ESP partition");
    ck!(block::with_device(d, |x| x.write_range(2048, &s1, 0)) == Ok(Err(BlockError::OutOfRange)), "second lock: write into the ESP");
    TEST_SKIP_UBLK_CHECK.store(true, Ordering::SeqCst);
    ck!(block::with_device(d, |x| x.write_range(2048, &s1, 0)) == Ok(Err(BlockError::Io)), "third lock (usbd) alone: write into the ESP must fail");
    // The third lock alone: past the partition (the backup GPT).
    TEST_SKIP_PARTITION_CHECK.store(true, Ordering::SeqCst);
    let mut gpt0 = alloc::vec![0u8; 512];
    ck!(block::read(d, s + l, &mut gpt0).is_ok(), "read past the partition");
    ck!(block::write(p2, l, &s1) == Err(BlockError::Io), "third lock (usbd) alone: write past the partition");
    let mut two = alloc::vec![0u8; 1024];
    fill(7, s + l - 1, &mut two);
    ck!(block::write(p2, l - 1, &two) == Err(BlockError::Io), "third lock (usbd) alone: write across the partition end");
    let mut gpt1 = alloc::vec![0u8; 512];
    ck!(block::read(d, s + l, &mut gpt1).is_ok() && gpt1 == gpt0, "the sector past the partition changed");
    TEST_SKIP_PARTITION_CHECK.store(false, Ordering::SeqCst);
    TEST_SKIP_UBLK_CHECK.store(false, Ordering::SeqCst);
    let mut esp1 = alloc::vec![0u8; 64 * 512];
    ck!(block::read(p1, 0, &mut esp1).is_ok() && esp1 == esp0, "the ESP changed");
    // A stale generation – usbd refuses WRITE and FLUSH.
    TEST_GEN_OFFSET.store(1, Ordering::SeqCst);
    let (rw, rf) = (block::write(p2, 0, &s1), block::flush(p2));
    TEST_GEN_OFFSET.store(0, Ordering::SeqCst);
    ck!(rw == Err(BlockError::Io) && rf == Err(BlockError::Io), "usbd took a stale generation: write {:?}, flush {:?}", rw, rf);
    ck!(block::write(p2, 0, &big[..512]) == Ok(()), "write with the right generation");
    // usbd's errors reach the kernel.
    ck!(block::control(d, Control::Test { flags: 2 }) == Ok(0), "usbd test flags (self-test build?)");
    ck!(block::write(p2, 0, &s1) == Err(BlockError::Io), "a failed WRITE in usbd reported as success");
    ck!(block::control(d, Control::Test { flags: 8 }) == Ok(0), "usbd test flag");
    ck!(block::flush(p2) == Err(BlockError::Io), "a failed FLUSH in usbd reported as success");
    // No registration: usbd refuses FLUSH and WRITE on its own.
    ck!(block::control(d, Control::Withdraw) == Ok(0), "withdraw");
    TEST_SKIP_UBLK_CHECK.store(true, Ordering::SeqCst);
    let (rw, rf) = (block::write(p2, 0, &s1), block::flush(p2));
    TEST_SKIP_UBLK_CHECK.store(false, Ordering::SeqCst);
    ck!(rw == Err(BlockError::Io) && rf == Err(BlockError::Io), "usbd without a registration: write {:?}, flush {:?}", rw, rf);
    // A held probe reply: timeout, discarded later, no registration.
    ck!(block::control(d, Control::Test { flags: 4 }) == Ok(0), "usbd test flag");
    let late0 = sh.late.load(Ordering::SeqCst);
    let r = block::control(d, Control::Probe { generation: generation(d) });
    ck!(r == Err(BlockError::Timeout), "held probe reply: {:?}", r);
    let mut rb = alloc::vec![0u8; 512];
    ck!(block::read(d, 0, &mut rb).is_ok() && sh.late.load(Ordering::SeqCst) > late0, "the late probe reply was not discarded");
    ck!(block::write(p2, 0, &s1) == Err(BlockError::ReadOnly), "the late probe reply gave a write");
    let line2 = alloc::format!("1 MiB written in {} ms, read back, flushed; ESP unchanged", w_ms);
    // 3/3 – unplugged during writes.
    let _ = block::set_grant(p2, None);
    ck!(open_rw(d, p2, s, l).is_ok(), "rw again");
    let mut region = alloc::vec![0u8; REGION as usize * 512];
    fill(1, s + 4096, &mut region);
    ck!(block::write(p2, 4096, &region) == Ok(()) && block::flush(p2) == Ok(()), "region version 1");
    let g_plug = generation(d);
    WRITER_PART.store(p2, Ordering::SeqCst);
    WRITER_VER.store(2, Ordering::SeqCst);
    WRITER_START.store(s, Ordering::SeqCst);
    WRITER_PIECES.store(0, Ordering::SeqCst);
    WRITER_DONE.store(0, Ordering::SeqCst);
    drop(sh);
    ck!(crate::sched::spawn("usbw-writer", writer, 0).is_ok(), "writer task");
    ck!(wait_for(5_000, || WRITER_PIECES.load(Ordering::SeqCst) >= 4), "writer task writes nothing");
    serial_println!("[HOTPLUG] device_del usbw");
    ck!(wait_for(10_000, || WRITER_DONE.load(Ordering::SeqCst) != 0), "writer not stopped 10 s after the stick was unplugged");
    let pieces = WRITER_PIECES.load(Ordering::SeqCst);
    ck!(wait_for(15_000, || writable().is_none()), "unplugged stick still present - is qemu-hotplug.py running?");
    serial_println!("[HOTPLUG] device_add usb-storage,bus=xhci.0,port=4,drive=usbw,id=usbw,share-rw=on");
    crate::time::sleep_ms(500);
    serial_println!("[HOTPLUG] info usb");
    ck!(wait_for(20_000, || writable().is_some()), "stick plugged back not found");
    let (d, _, p2, s, l) = writable().unwrap();
    let g_new = generation(d);
    ck!(g_new > g_plug, "generation after replugging: {} (was {})", g_new, g_plug);
    ck!(block::set_grant(p2, Some(0)).is_ok() && block::write(p2, 4096, &s1) == Err(BlockError::ReadOnly), "the replugged stick kept a registration");
    let _ = block::set_grant(p2, None);
    let n2 = check_region(d, s, 1, 2);
    ck!(n2.is_ok(), "after unplugging: {}", n2.as_ref().err().unwrap());
    // usbd killed during writes.
    ck!(open_rw(d, p2, s, l).is_ok(), "rw after replugging");
    ck!(block::write(p2, 4096, &region) == Ok(()) && block::flush(p2) == Ok(()), "region version 1 again");
    WRITER_PART.store(p2, Ordering::SeqCst);
    WRITER_VER.store(3, Ordering::SeqCst);
    WRITER_START.store(s, Ordering::SeqCst);
    WRITER_PIECES.store(0, Ordering::SeqCst);
    WRITER_DONE.store(0, Ordering::SeqCst);
    let g_kill = generation(d);
    ck!(crate::sched::spawn("usbw-writer", writer, 0).is_ok(), "writer task");
    ck!(wait_for(5_000, || WRITER_PIECES.load(Ordering::SeqCst) >= 4), "writer task writes nothing");
    let usbd = sched::tasks().into_iter().find(|t| t.user && t.name.contains("usbd"));
    ck!(usbd.as_ref().is_some_and(|t| sched::request_exit(t.id)), "usbd not found / not killed");
    ck!(wait_for(10_000, || WRITER_DONE.load(Ordering::SeqCst) != 0), "writer not stopped 10 s after usbd was killed");
    let pieces3 = WRITER_PIECES.load(Ordering::SeqCst);
    ck!(wait_for(30_000, || writable().is_some_and(|w| generation(w.0) > g_kill)), "stick not back after init restarted usbd");
    let (d, _, p2, s, _) = writable().unwrap();
    let g_back = generation(d);
    ck!(block::set_grant(p2, Some(0)).is_ok() && block::write(p2, 4096, &s1) == Err(BlockError::ReadOnly), "a registration survived the usbd restart");
    let _ = block::set_grant(p2, None);
    let n3 = check_region(d, s, 1, 3);
    ck!(n3.is_ok(), "after killing usbd: {}", n3.as_ref().err().unwrap());
    // The end: usbtest exits, init stops usb0.
    ck!(crate::fs::write_file("/tmp/usbw-done", b"1").is_ok(), "cannot create /tmp/usbw-done");
    let ok = wait_for(30_000, || sched::task_info(id).is_none());
    if !ok {
        let _ = sched::request_exit(id);
    }
    ck!(ok, "init test /bin/usbtest hold did not finish");
    let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
    let line = out.lines().find(|l| l.starts_with("usbtest:")).unwrap_or("").trim();
    ck!(exit_info(id).map(|e| e.kind) == Some(ExitKind::Exit(0)) && line.contains("checks OK"), "usbtest hold: {:?}", out.trim());
    let _ = crate::fs::remove("/tmp/usbw-done");
    ck!(wait_for(5_000, || super::ublk::count() == 0), "USB disks left after usb0 stopped");
    ck!(crate::arch::x86_64::msi::free_count() == vectors0, "MSI vectors leaked");
    crate::sched::reap();
    let free1 = crate::selftest::settled_free_frames();
    ck!(free1 >= free0, "frames leaked ({} -> {})", free0, free1);
    let line3 = alloc::format!(
        "unplugged after {} pieces (64 KiB) -> plugged back with generation {} -> {}, no registration, {} of {} sectors new, the rest old; usbd killed after {} pieces -> back with generation {} -> {}, no registration, {} sectors new, the rest old",
        pieces,
        g_plug,
        g_new,
        n2.unwrap(),
        REGION,
        pieces3,
        g_kill,
        g_back,
        n3.unwrap()
    );
    Ok((line2, line3))
}

/// The ESP marker of tests/mkgpt.py ("DESO-ESP" in every sector).
fn is_ver_esp(buf: &[u8]) -> bool {
    buf.chunks(512).all(|s| &s[..8] == b"DESO-ESP")
}

pub fn self_test() {
    serial_println!("[USB WRITE TEST] Starting USB write tests (registrations, three locks, usbd, hot-plug)...");
    crate::selftest::begin();
    match fake_test() {
        Ok(line) => serial_println!(
            "[USB WRITE TEST] 1/3 kernel side (fake stick): write protection unknown -> nothing, no registration -> refused, probe = one FLUSH (stale generation, late reply discarded), rw (one at a time, overflowing / outside ranges refused), 1 MiB in 16 pieces, first + second lock each alone, ESP refused, failed piece 1 / 8 / 16 -> whole write fails, write timeout -> slot back, no id reused after the 32-bit wrap, an old partition object after a replug (same numbers, rw granted) -> NoDevice, format sessions (only their id, ended = never), counters never wrap: {} PASS",
            line
        ),
        Err(e) => {
            serial_println!("[USB WRITE TEST] FAIL: 1/3: {}", e);
            return;
        }
    }
    match real_test() {
        Ok((l2, l3)) => {
            serial_println!(
                "[USB WRITE TEST] 2/3 usbd + writable QEMU stick: read-only sticks write-protected (probe refused), probe with SYNCHRONIZE CACHE, rw, {}, third lock alone (ESP, past and across the partition end), stale generation refused, usbd WRITE / FLUSH errors reported, no registration -> usbd refuses, held probe reply discarded PASS",
                l2
            );
            serial_println!("[USB WRITE TEST] 3/3 hot-plug and usbd kill during writes: {} PASS", l3);
        }
        Err(e) => {
            serial_println!("[USB WRITE TEST] FAIL: 2/3: {}", e);
            return;
        }
    }
    crate::selftest::pass();
}
