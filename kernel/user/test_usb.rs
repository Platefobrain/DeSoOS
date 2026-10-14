// M20: samotesty USB – kontroler xHCI i usługa /bin/usbd w user space (tylko
// build z --cfg selftest).  Test biegnie w programie /bin/usbtest (prawdziwe
// syscalle z ring 3); jądro sprawdza wynik, a po każdym teście – że nic nie
// wyciekło (przejęcie, bus mastering, wektory MSI, ramki DMA).  QEMU:
// `-device qemu-xhci` z pendrive'em startowym (usb-storage), usb-kbd i
// usb-mouse – test.sh.

use alloc::string::String;

use super::*;
use crate::drivers::pci;
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[USB TEST] FAIL: {}", format_args!($($msg)*));
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

fn run(path: &str, args: &[&str], ms: u64, hw_root: bool, sysctl: bool) -> Option<(ExitKind, String)> {
    run_in(path, args, ms, hw_root, sysctl, false, false)
}

/// Jak `run`; `input` – także uchwyt INPUT (jak prawdziwy init: slot za
/// SYSCTL), `blk` – uchwyt BLK (M20.f, za INPUT).
fn run_in(path: &str, args: &[&str], ms: u64, hw_root: bool, sysctl: bool, input: bool, blk: bool) -> Option<(ExitKind, String)> {
    let opts = SpawnOptions { stdin: Some(alloc::vec::Vec::new()), capture: true, hw_root, sysctl, input, blk, ..SpawnOptions::default() };
    let id = exec(path, args, "/", &opts).ok()?;
    if !wait_for(ms, || sched::task_info(id).is_none()) {
        let _ = sched::request_exit(id);
        return None;
    }
    let kind = exit_info(id)?.kind;
    Some((kind, String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned()))
}

/// Wzór danych /bin/blktest (sektor, bajt).
fn pat(sector: u64, i: usize) -> u8 {
    ((sector.wrapping_mul(13) as usize + i) ^ (sector >> 3) as usize) as u8
}

fn pat_ok(lba: u64, buf: &[u8]) -> bool {
    buf.iter().enumerate().all(|(k, &b)| b == pat(lba + (k / 512) as u64, k % 512))
}

/// Czas odczytu innego dysku (virtio, numer 0) w trakcie czekania na USB.
static OTHER_DISK_MS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn other_disk(_: usize) {
    use core::sync::atomic::Ordering;
    crate::time::sleep_ms(150);
    let mut b = [0u8; 512];
    let t0 = ticks();
    let ok = crate::block::read(0, 0, &mut b).is_ok();
    // +1: 0 znaczy „jeszcze nie skończone”.
    OTHER_DISK_MS.store(if ok { ticks() - t0 + 1 } else { u64::MAX }, Ordering::SeqCst);
}

/// USB TEST 3/7: protokół ublk (blk_attach, odczyty, błędy, timeouty,
/// kwarantanna, spóźniona odpowiedź, znikanie dysku, blokada per dysk).
fn ublk_protocol_test() -> bool {
    use crate::block::{self, BlockError};
    use core::sync::atomic::Ordering;
    macro_rules! ck {
        ($cond:expr, $($msg:tt)*) => {
            if !$cond {
                serial_println!("[USB TEST] FAIL: ublk: {}", format_args!($($msg)*));
                return false;
            }
        };
    }
    let free0 = crate::selftest::settled_free_frames();
    let opts = SpawnOptions { stdin: Some(alloc::vec::Vec::new()), capture: true, blk: true, ..SpawnOptions::default() };
    let id = exec("/bin/blktest", &["blktest"], "/", &opts);
    ck!(id.is_ok(), "cannot start /bin/blktest");
    let id = id.unwrap();
    let find = || super::ublk::list().into_iter().find(|s| s.desc == "blktest");
    ck!(wait_for(10_000, || find().is_some_and(|s| s.probed())), "blktest disk not attached / not probed");
    let sh = find().unwrap();
    let idx = sh.index.load(Ordering::SeqCst);
    ck!(block::is_read_only(idx) && block::with_device(idx, |d| d.sector_count()) == Ok(1024), "disk {}: not read-only or wrong size", idx);
    ck!(sh.mounts().is_empty(), "pattern disk must not be mounted");

    // Odczyty: mały, większy niż slot (dwa żądania), błędne odpowiedzi odrzucone.
    let mut b = alloc::vec![0u8; 4096];
    ck!(block::read(idx, 0, &mut b).is_ok() && pat_ok(0, &b), "read lba 0");
    let mut big = alloc::vec![0u8; 140 * 512];
    ck!(block::read(idx, 10, &mut big).is_ok() && pat_ok(10, &big), "read 70 KiB from lba 10 (two requests)");
    let proto0 = sh.proto_errors.load(Ordering::SeqCst);
    let mut s1 = alloc::vec![0u8; 512];
    ck!(block::read(idx, 100, &mut s1).is_ok() && pat_ok(100, &s1), "read lba 100 after a foreign id and a wrong count");
    ck!(sh.proto_errors.load(Ordering::SeqCst) == proto0 + 2, "protocol errors: {} -> {} (want +2)", proto0, sh.proto_errors.load(Ordering::SeqCst));

    // Timeout (1 s) – a w tym czasie inny dysk (virtio) czyta bez czekania.
    OTHER_DISK_MS.store(0, Ordering::SeqCst);
    let other = crate::sched::spawn("ublk-other-disk", other_disk, 0).is_ok();
    let t0 = ticks();
    let r = block::read(idx, 200, &mut s1);
    let waited = ticks() - t0;
    ck!(r == Err(BlockError::Timeout) && (900..3000).contains(&waited), "no answer: {:?} after {} ms (want Timeout after ~1 s)", r, waited);
    ck!(other && wait_for(3000, || OTHER_DISK_MS.load(Ordering::SeqCst) != 0), "other-disk task did not finish (spawned {}, {})", other, OTHER_DISK_MS.load(Ordering::SeqCst));
    let om = OTHER_DISK_MS.load(Ordering::SeqCst).saturating_sub(1);
    ck!(om < 300, "virtio read waited {} ms while the USB disk was waiting (per-disk lock)", om);
    // Spóźniona odpowiedź zwalnia slot z kwarantanny.
    ck!(block::read(idx, 201, &mut s1).is_ok() && pat_ok(201, &s1), "read lba 201 (after the late answer)");
    ck!(sh.late.load(Ordering::SeqCst) == 1 && sh.timeouts.load(Ordering::SeqCst) == 1, "late {} timeouts {}", sh.late.load(Ordering::SeqCst), sh.timeouts.load(Ordering::SeqCst));
    ck!(block::read(idx, 300, &mut s1) == Err(BlockError::Io), "status EIO must give Io");
    // Zapis: warstwa block i sam sterownik odmawiają.
    ck!(block::write(idx, 0, &s1) == Err(BlockError::ReadOnly), "block write must be ReadOnly");
    ck!(block::with_device(idx, |d| d.write(0, &s1)) == Ok(Err(BlockError::ReadOnly)), "ublk write must be ReadOnly");
    // 3 timeouty pod rząd = dysk znika.
    for lba in 400..403 {
        ck!(block::read(idx, lba, &mut s1) == Err(BlockError::Timeout), "lba {}: want Timeout", lba);
    }
    ck!(sh.gone(), "disk not gone after 3 timeouts in a row");
    let r = block::read(idx, 0, &mut s1);
    ck!(matches!(r, Err(BlockError::NoDevice)), "read after gone: {:?}", r);
    // Monitor usuwa dysk, kanał się zamyka, blktest kończy się sam.
    ck!(wait_for(5_000, || super::ublk::count() == 0), "gone disk not removed by usb-disks");
    drop(sh); // ostatnia referencja do kanału po stronie jądra
    ck!(wait_for(5_000, || sched::task_info(id).is_none()), "blktest did not exit after the kernel closed the channel");
    let kind = exit_info(id).map(|e| e.kind);
    let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
    let line = out.lines().find(|l| l.starts_with("blktest:")).unwrap_or("").trim();
    ck!(kind == Some(ExitKind::Exit(0)) && line.contains("checks OK"), "blktest: {:?} {:?}", kind, out.trim());
    ck!(block::with_device(idx, |_| ()).is_err(), "disk entry {} still present", idx);
    crate::sched::reap();
    let free1 = crate::selftest::settled_free_frames();
    ck!(free1 >= free0, "frames leaked ({} -> {})", free0, free1);
    serial_println!(
        "[USB TEST] 3/7 ublk protocol (fake device): blk_attach errors, reads (1 and 2 requests), foreign id + wrong count rejected, timeout {} ms -> quarantine, other disk not blocked ({} ms), late answer frees the slot, EIO, writes refused, 3 timeouts -> disk gone + removed: {} PASS",
        waited,
        om,
        line
    );
    true
}

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static READER_DONE: AtomicU64 = AtomicU64::new(0);
static READER_BYTES: AtomicU64 = AtomicU64::new(0);
static READER_PATH: crate::sched::spin::SpinLock<String> = crate::sched::spin::SpinLock::new("test reader path", crate::sched::spin::level::TEST_OUTER, String::new());
/// M20.h: pomiary z USB TEST 7/7 do linii [RESULT-USB] ("k=v ...").
static MEASURED: crate::sched::spin::SpinLock<String> = crate::sched::spin::SpinLock::new("test usb measured", crate::sched::spin::level::TEST_OUTER, String::new());

/// Suma kontrolna (jak `ublk::read_bench`) 4 MiB wzoru z DATA.BIN (mkfat32.py).
fn data_bin_sum() -> u64 {
    let mut sum = 0u64;
    for k in 0..(4u64 << 20) / 4 {
        let w = (k as u32).wrapping_mul(2654435761).to_le_bytes();
        for (i, &b) in w.iter().enumerate() {
            sum = sum.wrapping_mul(31).wrapping_add(b as u64 ^ (k * 4 + i as u64));
        }
    }
    sum
}

fn test_disk_path() -> Option<String> {
    crate::fs::mount_list().into_iter().find(|m| m.0.starts_with("/usb") && m.2.contains("DESOOSTEST")).map(|m| alloc::format!("{}/DATA.BIN", m.0))
}

/// Zadanie: czyta plik w kółko po 64 KiB, aż odczyt się nie uda (czas błędu w READER_DONE).
fn usb_reader(_: usize) {
    let path = READER_PATH.lock().clone();
    let mut buf = alloc::vec![0u8; 65536];
    let mut off = 0u64;
    loop {
        match crate::fs::read(&path, off, &mut buf) {
            Ok(0) => off = 0,
            Ok(n) => {
                off += n as u64;
                READER_BYTES.fetch_add(n as u64, Ordering::SeqCst);
            }
            Err(_) => break,
        }
    }
    READER_DONE.store(ticks().max(1), Ordering::SeqCst);
}

// M20.g: dysk, który na żądanie przestaje odpowiadać (odczyt czeka) – test,
// że zawieszony dysk USB nie zatrzymuje reszty VFS.
static HOLD: AtomicBool = AtomicBool::new(false);
static HELD: AtomicU64 = AtomicU64::new(0);
static SLOW_READ: AtomicU64 = AtomicU64::new(0);

struct SlowDisk(crate::block::RamDisk);

impl crate::block::BlockDevice for SlowDisk {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn description(&self) -> String {
        String::from("test disk that can hang")
    }
    fn sector_count(&self) -> u64 {
        self.0.sector_count()
    }
    fn read_only(&self) -> bool {
        false
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), crate::block::BlockError> {
        if HOLD.load(Ordering::SeqCst) {
            HELD.fetch_add(1, Ordering::SeqCst);
            while HOLD.load(Ordering::SeqCst) {
                crate::time::sleep_ms(1);
            }
        }
        self.0.read(lba, buf)
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), crate::block::BlockError> {
        self.0.write(lba, buf)
    }
    fn flush(&mut self) -> Result<(), crate::block::BlockError> {
        Ok(())
    }
}

fn slow_reader(_: usize) {
    let n = crate::fs::read_file("/tmp/slow/a.txt").map(|v| v.len() as u64).unwrap_or(u64::MAX);
    SLOW_READ.store(n, Ordering::SeqCst);
}

fn release_hold(_: usize) {
    crate::time::sleep_ms(3000); // bezpiecznik: regresja nie zawiesza testów na zawsze
    HOLD.store(false, Ordering::SeqCst);
}

/// FAT32 na dysku, który „zawisł” (jak pendrive czekający 5 s na usbd): inne
/// systemy plików (ramfs, /bin) działają dalej.  Wynik: ms odczytu /bin/sh.
fn hung_disk_test() -> Result<u64, String> {
    use alloc::boxed::Box;
    use crate::block;
    let disk = block::register(Box::new(SlowDisk(block::RamDisk::new("slow0", 32768))));
    let cleanup = |disk: usize| {
        let _ = crate::fs::unmount("/tmp/slow");
        let _ = crate::fs::remove("/tmp/slow");
        block::remove(disk);
    };
    let r = (|| -> Result<u64, String> {
        crate::fs::fat32::mkfs(disk, "SLOW", true).map_err(|e| alloc::format!("mkfs: {}", e))?;
        let fs = crate::fs::fat32::Fat32::open(disk).map_err(|e| alloc::format!("open: {}", e))?;
        let _ = crate::fs::mkdir("/tmp/slow");
        crate::fs::mount("/tmp/slow", Box::new(crate::fs::Locked::new(fs))).map_err(|e| alloc::format!("mount: {}", e))?;
        let data = alloc::vec![0x5Au8; 100 * 1024];
        crate::fs::write_file("/tmp/slow/a.txt", &data).map_err(|e| alloc::format!("write: {}", e))?;
        HELD.store(0, Ordering::SeqCst);
        SLOW_READ.store(0, Ordering::SeqCst);
        HOLD.store(true, Ordering::SeqCst);
        crate::sched::spawn("slow-reader", slow_reader, 0).map_err(|e| String::from(e))?;
        crate::sched::spawn("slow-release", release_hold, 0).map_err(|e| String::from(e))?;
        if !wait_for(2_000, || HELD.load(Ordering::SeqCst) > 0) {
            HOLD.store(false, Ordering::SeqCst);
            return Err(String::from("reader did not reach the disk"));
        }
        let t0 = ticks();
        let sh = crate::fs::read_file("/bin/sh").map(|v| v.len()).unwrap_or(0);
        let ok = sh > 0 && crate::fs::stat("/tmp").is_ok() && crate::fs::read_dir("/bin").map_or(false, |v| !v.is_empty());
        let dt = ticks() - t0;
        let still_held = HOLD.load(Ordering::SeqCst);
        HOLD.store(false, Ordering::SeqCst);
        if !wait_for(3_000, || SLOW_READ.load(Ordering::SeqCst) != 0) {
            return Err(String::from("slow reader did not finish"));
        }
        if !ok || !still_held || dt > 500 {
            return Err(alloc::format!("other file systems blocked by the hung disk: /bin/sh read {} B in {} ms (disk still hung: {})", sh, dt, still_held));
        }
        if SLOW_READ.load(Ordering::SeqCst) != data.len() as u64 {
            return Err(alloc::format!("slow file: {} bytes", SLOW_READ.load(Ordering::SeqCst)));
        }
        Ok(dt)
    })();
    cleanup(disk);
    r
}

/// USB TEST 6/7: odporność.
fn robust_test() -> bool {
    macro_rules! ck {
        ($cond:expr, $($msg:tt)*) => {
            if !$cond {
                serial_println!("[USB TEST] FAIL: robustness: {}", format_args!($($msg)*));
                return false;
            }
        };
    }
    let r = hung_disk_test();
    ck!(r.is_ok(), "{}", r.as_ref().err().map(|s| s.as_str()).unwrap_or(""));
    let hung_ms = r.unwrap();
    let xhci = pci::devices().iter().position(|d| (d.class, d.subclass, d.prog_if) == (0x0C, 0x03, 0x30)).unwrap();
    let dev = &pci::devices()[xhci];
    let vectors0 = crate::arch::x86_64::msi::free_count();
    let free0 = crate::selftest::settled_free_frames();
    let r = run_in("/bin/init", &["init", "test", "/bin/usbtest", "robust"], 120_000, true, true, true, true);
    ck!(r.is_some(), "init test /bin/usbtest robust did not finish");
    let (kind, out) = r.unwrap();
    let line = out.lines().find(|l| l.starts_with("usbtest:")).unwrap_or("").trim();
    ck!(kind == ExitKind::Exit(0) && line.contains("checks OK"), "usbtest robust: {:?} {:?}", kind, out.trim());
    ck!(out.contains("USB keyboard and disks back in a moment") && out.contains("disabled after 5 failures"), "init messages for usb0 restart / broken missing: {:?}", out.trim());
    ck!(pci::owner(xhci) == pci::OWNER_FREE && dev.command() & pci::CMD_BUS_MASTER == 0, "xHCI not released after usb0 broke");
    ck!(wait_for(5_000, || super::ublk::count() == 0), "USB disks left after usb0 broke");
    ck!(crate::arch::x86_64::msi::free_count() == vectors0, "MSI vectors leaked");
    let free1 = crate::selftest::settled_free_frames();
    ck!(free1 >= free0, "frames leaked ({} -> {})", free0, free1);
    serial_println!(
        "[USB TEST] 6/7 robustness: hung USB disk does not block other file systems (/bin read in {} ms), kill usbd while a file is read, init restart (disk + keyboard back), 5 failures -> broken + message, controller released, nothing leaked: {} PASS",
        hung_ms,
        line
    );
    true
}

/// Testowy pendrive (etykieta DESOOSTEST) zamontowany w /usbN.
fn test_disk_mounted() -> bool {
    crate::fs::mount_list().iter().any(|m| m.0.starts_with("/usb") && m.2.contains("DESOOSTEST"))
}

/// USB TEST 7/7: dysk za hubem wyjęty i włożony, potem cały hub wyjęty.
fn hotplug_test() -> bool {
    macro_rules! ck {
        ($cond:expr, $($msg:tt)*) => {
            if !$cond {
                serial_println!("[USB TEST] FAIL: hot-plug: {}", format_args!($($msg)*));
                return false;
            }
        };
    }
    let vectors0 = crate::arch::x86_64::msi::free_count();
    let free0 = crate::selftest::settled_free_frames();
    let opts = SpawnOptions { stdin: Some(alloc::vec::Vec::new()), capture: true, hw_root: true, sysctl: true, input: true, blk: true, ..SpawnOptions::default() };
    let id = exec("/bin/init", &["init", "test", "/bin/usbtest", "hotplug"], "/", &opts);
    ck!(id.is_ok(), "cannot start init");
    let id = id.unwrap();
    let t0 = ticks();
    ck!(wait_for(20_000, test_disk_mounted), "test disk behind the hub not mounted");
    let t_mount = ticks() - t0;
    // M20.h: odczyt DATA.BIN (4 MiB wzoru, klaster 512 B) buforem 256 KiB
    // (ciągłe klastry, żądania potokiem) i 4 KiB (jak `cat` – cache klastrów);
    // oba muszą dać dokładnie wzór.
    let path = test_disk_path().unwrap_or_default();
    let want = data_bin_sum();
    let big = super::ublk::read_bench(&path, 256 * 1024, u64::MAX);
    ck!(matches!(big, Ok((b, _, s)) if b == 4 << 20 && s == want), "DATA.BIN read with a 256 KiB buffer: {:?} (pattern sum {:#x})", big, want);
    let small = super::ublk::read_bench(&path, 4096, u64::MAX);
    ck!(matches!(small, Ok((b, _, s)) if b == 4 << 20 && s == want), "DATA.BIN read with a 4 KiB buffer: {:?}", small);
    let (big_kbs, small_kbs) = (
        big.map(|(b, us, _)| b * 1_000_000 / 1024 / us).unwrap_or(0),
        small.map(|(b, us, _)| b * 1_000_000 / 1024 / us).unwrap_or(0),
    );
    // M20.h: `df` – główny FSInfo obrazu jest nieaktualny (mkfat32.py), jądro
    // liczy wolne klastry z FAT; prawdziwa liczba w kopii FSInfo (sektor 7).
    let m = crate::fs::mount_list().into_iter().find(|m| m.0.starts_with("/usb") && m.2.contains("DESOOSTEST"));
    ck!(m.is_some(), "test disk not mounted for df");
    let m = m.unwrap();
    let disk = m.2.split(' ').next().and_then(crate::block::find);
    let mut fi = [0u8; 512];
    ck!(disk.map_or(false, |d| crate::block::read(d, 2048 + 7, &mut fi).is_ok()), "cannot read the backup FSInfo of {:?}", m.2);
    let exact = u32::from_le_bytes([fi[488], fi[489], fi[490], fi[491]]) as u64 * 512;
    let st = crate::fs::mount_stats(&m.0);
    ck!(st.as_ref().map_or(false, |s| s.free_bytes == exact), "df on {}: free {:?} bytes, FAT says {} (stale FSInfo trusted?)", m.0, st.map(|s| s.free_bytes), exact);
    // M20.h: opóźnienie klawiatury USB – klawisze z monitora QEMU (sendkey
    // trafia do usb-kbd: ostatnio aktywowana klawiatura), jądro mierzy od
    // przerwania xHCI do znaku w kolejce wejścia.
    crate::input::hid_latency_reset();
    for _ in 0..5 {
        serial_println!("[HOTPLUG] sendkey x");
        crate::time::sleep_ms(250);
    }
    let _ = wait_for(5_000, || crate::input::hid_latency().0 >= 5);
    let (hid_n, hid_avg, hid_min, hid_max) = crate::input::hid_latency();
    let mut xs = 0;
    while let Some(e) = crate::input::read_event() {
        if e.ch == Some('x') {
            xs += 1;
        }
    }
    ck!(hid_n >= 3 && xs >= 3, "USB keyboard latency: {} measurements, {} x 'x' from QEMU sendkey (key went to PS/2?)", hid_n, xs);
    serial_println!(
        "[USB TEST]   7/7 measured: DATA.BIN {} KiB/s (256 KiB reads), {} KiB/s (4 KiB reads, like cat), identical to the pattern; df counts free clusters from the FAT (stale FSInfo ignored); USB keyboard: interrupt -> character avg {} us (min {}, max {}, {} keys)",
        big_kbs, small_kbs, hid_avg, hid_min, hid_max, hid_n
    );
    *MEASURED.lock() = alloc::format!("kread_kbs={} kcat_kbs={} hid_n={} hid_avg_us={} hid_max_us={}", big_kbs, small_kbs, hid_n, hid_avg, hid_max);
    // M20.g: w trakcie wyjęcia ktoś czyta plik z tego dysku – ma dostać błąd, nie wisieć.
    READER_DONE.store(0, Ordering::SeqCst);
    READER_BYTES.store(0, Ordering::SeqCst);
    *READER_PATH.lock() = path.clone();
    ck!(crate::sched::spawn("usb-reader", usb_reader, 0).is_ok(), "cannot start the reader task");
    ck!(wait_for(5_000, || READER_BYTES.load(Ordering::SeqCst) > 0), "reader task reads nothing from {}", path);
    serial_println!("[HOTPLUG] device_del hubdisk");
    let t1 = ticks();
    ck!(wait_for(8_000, || READER_DONE.load(Ordering::SeqCst) != 0), "reader still blocked 8 s after the disk was unplugged");
    let t_reader = READER_DONE.load(Ordering::SeqCst).saturating_sub(t1);
    ck!(wait_for(15_000, || !test_disk_mounted()), "disk unplugged from the hub (QEMU device_del) still mounted - is qemu-hotplug.py running?");
    let t_out = ticks() - t1;
    serial_println!("[HOTPLUG] device_add usb-storage,bus=xhci.0,port=3.2,drive=usbtest,id=hubdisk");
    let t2 = ticks();
    ck!(wait_for(20_000, test_disk_mounted), "disk plugged back into the hub not mounted again");
    let t_in = ticks() - t2;
    serial_println!("[HOTPLUG] device_del hub1");
    ck!(wait_for(15_000, || !test_disk_mounted()), "disk behind the unplugged hub still mounted");
    let ok = wait_for(30_000, || sched::task_info(id).is_none());
    if !ok {
        let _ = sched::request_exit(id);
    }
    ck!(ok, "usbtest hotplug did not finish");
    let kind = exit_info(id).map(|e| e.kind);
    let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
    let line = out.lines().find(|l| l.starts_with("usbtest:")).unwrap_or("").trim();
    ck!(kind == Some(ExitKind::Exit(0)) && line.contains("checks OK"), "usbtest hotplug: {:?} {:?}", kind, out.trim());
    ck!(wait_for(5_000, || super::ublk::count() == 0), "USB disks left after usb0 stopped");
    ck!(crate::arch::x86_64::msi::free_count() == vectors0, "MSI vectors leaked");
    let free1 = crate::selftest::settled_free_frames();
    ck!(free1 >= free0, "frames leaked ({} -> {})", free0, free1);
    serial_println!(
        "[USB TEST] 7/7 hot-plug behind a hub (QEMU monitor): disk mounted in {} ms, unplugged while a file is read -> reader error in {} ms ({} KiB read), unmounted in {} ms, plugged back -> mounted in {} ms, hub unplugged -> hub + mouse + disk gone, nothing leaked: {} PASS",
        t_mount,
        t_reader,
        READER_BYTES.load(Ordering::SeqCst) / 1024,
        t_out,
        t_in,
        line
    );
    true
}

pub fn self_test() {
    serial_println!("[USB TEST] Starting USB tests (descriptor parser, xHCI controller + enumeration in the usbd service)...");
    crate::selftest::begin();
    let frames0 = crate::selftest::settled_free_frames();

    let xhci = pci::devices().iter().position(|d| (d.class, d.subclass, d.prog_if) == (0x0C, 0x03, 0x30));
    check!(xhci.is_some(), "no xHCI controller (QEMU needs -device qemu-xhci)");
    let xhci = xhci.unwrap();
    let dev = &pci::devices()[xhci];
    check!(pci::owner(xhci) == pci::OWNER_FREE, "xHCI {} must not be owned by a kernel driver", dev.address);

    // 1. M20.c: parser deskryptorów bez sprzętu – poprawne próbki, złośliwe
    // przypadki, 10 000 mutacji; panika = koniec procesu = FAIL.
    let r = run("/bin/usbparse", &["usbparse"], 60_000, false, false);
    check!(r.is_some(), "usbparse did not finish");
    let (kind, out) = r.unwrap();
    let line = out.lines().find(|l| l.starts_with("usbparse:")).unwrap_or("").trim();
    check!(kind == ExitKind::Exit(0) && line.contains("checks OK"), "usbparse: {:?} {:?}", kind, out.trim());
    serial_println!("[USB TEST] 1/7 descriptor parser on hostile data (no hardware): {} PASS", line);

    // 2. dev_find + usbd: reset, pierścień komend i zdarzeń, przerwanie,
    // No-Op, porty; kill w trakcie serii komend i pełny reset nowej instancji;
    // samodzielny koniec usbd.
    let vectors0 = crate::arch::x86_64::msi::free_count();
    let free0 = crate::selftest::settled_free_frames();
    let r = run_in("/bin/usbtest", &["usbtest"], 90_000, true, false, true, true);
    check!(r.is_some(), "usbtest did not finish");
    let (kind, out) = r.unwrap();
    let line = out.lines().find(|l| l.starts_with("usbtest:")).unwrap_or("").trim();
    check!(kind == ExitKind::Exit(0) && line.contains("checks OK"), "usbtest: {:?} {:?}", kind, out.trim());
    check!(pci::owner(xhci) == pci::OWNER_FREE, "xHCI still claimed after usbtest");
    check!(dev.command() & pci::CMD_BUS_MASTER == 0, "xHCI bus mastering still on after usbd ended");
    check!(crate::arch::x86_64::msi::free_count() == vectors0, "MSI vectors leaked by usbd");
    // M20.f: dyski USB znikają po końcu usbd (monitor usb-disks: odmontowanie,
    // usunięcie) – dopiero wtedy bufory DMA wracają.
    check!(wait_for(5_000, || super::ublk::count() == 0), "USB disks still present after usbd ended: {}", super::ublk::count());
    check!(crate::fs::mount_list().iter().all(|m| !m.0.starts_with("/usb")), "/usbN still mounted after usbd ended");
    let free1 = crate::selftest::settled_free_frames();
    check!(free1 >= free0, "frames leaked by usbd ({} -> {})", free0, free1);
    let res = out.lines().find(|l| l.starts_with("usbtest-result ")).unwrap_or("").trim();
    serial_println!("[USB TEST] 2/7 xHCI in user space: dev_find by class, BIOS handoff + reset, rings, MSI, No-Op, enumeration of 2 storage + keyboard + hub with mouse and disk behind it, HID configured (interrupt endpoints, reports), USB disks attached + test disk mounted, kill mid-command and mid-enumeration + full reset (disks gone and back), clean exit, nothing leaked: {} PASS", line);

    // 3. M20.f: protokół ublk bez sprzętu – /bin/blktest udaje usbd i psuje
    // protokół; jądro czyta i sprawdza dane, timeouty, kwarantannę, znikanie.
    if !ublk_protocol_test() {
        return;
    }

    // 3. M20.e: input_inject bez sprzętu – błędy, znaki, autorepeat jądra, dioda
    // Caps Lock, puszczenie klawiszy zabitego źródła.  Jądro czyta kolejkę wejścia.
    crate::input::reset();
    let (ev0, rep0) = crate::input::usb_stats();
    let r = run_in("/bin/inputtest", &["inputtest"], 30_000, false, false, true, false);
    check!(r.is_some(), "inputtest did not finish");
    let (kind, out) = r.unwrap();
    let line = out.lines().find(|l| l.starts_with("inputtest:")).unwrap_or("").trim();
    check!(kind == ExitKind::Exit(0) && line.contains("checks OK"), "inputtest: {:?} {:?}", kind, out.trim());
    let mut text = String::new();
    while let Some(e) = crate::input::read_event() {
        if let Some(c) = e.ch {
            text.push(c);
        }
    }
    let (ev1, rep1) = crate::input::usb_stats();
    let bs = text.chars().filter(|&c| c == 'b').count();
    let qs = text.chars().filter(|&c| c == 'q' || c == 'Q').count();
    check!(text.starts_with("hiA"), "characters from input_inject: {:?}", text);
    check!((4..=12).contains(&bs) && rep1 - rep0 >= 3, "autorepeat: {} x 'b' after 700 ms, {} repeats ({:?})", bs, rep1 - rep0, text);
    check!(qs == 1, "killed source: 'q' must appear once and not repeat ({} times, {:?})", qs, text);
    let m = crate::input::modifiers();
    check!(!m.shift() && !m.caps_lock(), "Shift / Caps Lock left on after the source was killed");
    serial_println!("[USB TEST] 4/7 input_inject: rights, EINVAL, \"hiA\", autorepeat ({} x b), Caps Lock LED, keys of a killed source released ({} events): {} PASS", bs, ev1 - ev0, line);
    crate::input::reset();

    // 4. Prawdziwy init (`init test /bin/usbtest`): init znajduje kontroler po
    // klasie, uruchamia usb0, klient rozmawia z nim przez svc; po teście init
    // zamyka usługi – kontroler wolny, wektory i ramki wróciły.
    let vectors0 = crate::arch::x86_64::msi::free_count();
    let free0 = crate::selftest::settled_free_frames();
    let r = run_in("/bin/init", &["init", "test", "/bin/usbtest"], 90_000, true, true, true, true);
    check!(r.is_some(), "init test /bin/usbtest did not finish");
    let (kind, out) = r.unwrap();
    let line = out.lines().find(|l| l.starts_with("usbtest:")).unwrap_or("").trim();
    check!(kind == ExitKind::Exit(0) && line.contains("checks OK"), "usbtest via init: {:?} {:?}", kind, out.trim());
    check!(out.contains("= xHCI USB controller") && out.contains("init: service usb0 started"), "init did not start usb0: {:?}", out.trim());
    check!(pci::owner(xhci) == pci::OWNER_FREE, "xHCI still claimed after init stopped usb0");
    check!(dev.command() & pci::CMD_BUS_MASTER == 0, "xHCI bus mastering still on after init stopped usb0");
    check!(crate::arch::x86_64::msi::free_count() == vectors0, "MSI vectors leaked by usb0");
    check!(wait_for(5_000, || super::ublk::count() == 0), "USB disks still present after usb0 stopped");
    let free1 = crate::selftest::settled_free_frames();
    check!(free1 >= free0, "frames leaked by usb0 ({} -> {})", free0, free1);
    let res2 = out.lines().find(|l| l.starts_with("usbtest-disk ")).unwrap_or("").trim();
    serial_println!("[USB TEST] 5/7 init finds xHCI by class and starts usb0 (INPUT + BLK), lsusb via svc, pendrive mounted by the kernel: files identical to /bin, 4 MiB pattern, writes refused (3 locks), service stopped cleanly: {} PASS", line);

    // 6. M20.d: podłączanie w locie za hubem.  Linie „[HOTPLUG] …” czyta
    // qemu-hotplug.py (test.sh) i wysyła je do monitora QEMU; jądro patrzy na
    // dyski USB, /bin/usbtest (przez init) – na urządzenia w usb0.
    // 6. M20.g: odporność – zawieszony dysk nie blokuje VFS, kill usbd w trakcie
    // odczytu, restart, 5 awarii → broken.
    if !robust_test() {
        return;
    }
    if !hotplug_test() {
        return;
    }
    serial_println!("[RESULT-USB] ver={} {} {} {}", crate::shell::VERSION, res.trim_start_matches("usbtest-result "), res2.trim_start_matches("usbtest-disk "), MEASURED.lock().clone());

    crate::sched::reap();
    check!(
        wait_for(2_000, || {
            crate::sched::reap();
            crate::sched::stack::free_frames_flushed() >= frames0
        }),
        "frames leaked ({} -> {})",
        frames0,
        crate::sched::stack::free_frames_flushed()
    );
    crate::selftest::pass();
}
