// RESTART TEST – DeSoFS on disk 0 (`/disk`) survives a restart of the whole system.
//
// tests/test.sh runs QEMU twice on the same test disk (build-test-disk.img, created
// empty for every test run):
//   part 1 – the last step of the normal self-test run: disk 0 is formatted as DeSoFS,
//            mounted at /disk the way the kernel does at start (`fs::mount_disk`) and
//            filled with a fixed set: files of 0 B to 1 MiB with a hole (depth 0-2),
//            directories several levels deep, a directory of 300 entries with deleted
//            ones, a rename that replaces a file, removed files.  The system then
//            powers off normally;
//   part 2 – a second start (fw_cfg opt/desoos/phase=restart, only this group): the
//            kernel must have mounted /disk as DeSoFS read-write by itself; every file
//            and directory equals the set byte for byte, the 300-entry directory read
//            in parts, programs (ring 3) on /disk, a new file written and read; then
//            the speed measurements ([RESULT-FS]) and `desofs check` of the volume.
// Part 1 runs only in the automatic test mode and only on an empty disk 0 – never on a
// disk with data (e.g. disk.img of run-qemu.sh in a selftest build).

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::format::{self as fmt, Params};
use crate::fs::{self, DiskMount, FileType};
use crate::serial_println;

type T = Result<String, String>;

macro_rules! ensure {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            return Err(format!($($msg)*));
        }
    };
}

/// Deterministic content: `n` bytes from seed `seed`.
fn pattern(n: usize, seed: u32) -> Vec<u8> {
    (0..n).map(|i| ((i as u32).wrapping_mul(2654435761).wrapping_add(seed.wrapping_mul(97)) >> 11) as u8).collect()
}

/// Expected state: path -> Some(contents) for a file, None for a directory (paths under
/// /disk, without the 300-entry directory's files, which `many()` describes).
fn expected() -> Vec<(String, Option<Vec<u8>>)> {
    let mut v: Vec<(String, Option<Vec<u8>>)> = Vec::new();
    let mut sparse = vec![0u8; (1 << 20) + 4096];
    sparse[..4096].copy_from_slice(&pattern(4096, 5));
    sparse[1 << 20..].copy_from_slice(&pattern(4096, 6));
    for (p, d) in [
        ("/disk/empty", Some(Vec::new())),
        ("/disk/one", Some(pattern(1, 1))),
        ("/disk/page", Some(pattern(4096, 2))),
        ("/disk/mid", Some(pattern(100 * 1024, 3))),
        ("/disk/sparse", Some(sparse)),
        ("/disk/a", None),
        ("/disk/a/b", None),
        ("/disk/a/b/c", None),
        ("/disk/a/b/c/deep.txt", Some(pattern(777, 7))),
        ("/disk/target", Some(pattern(3000, 8))), // was "old-name", replaced "target"
        ("/disk/many", None),
    ] {
        v.push((String::from(p), d));
    }
    v
}

/// The 300-entry directory: entries 010..299 remain (000..009 removed).
fn many() -> Vec<(String, Vec<u8>)> {
    (10..300).map(|i| (format!("entry-with-a-longer-name-{:03}", i), pattern(10 + i, 1000 + i as u32))).collect()
}

fn e(what: &str, r: fs::FsError) -> String {
    format!("{}: {}", what, r)
}

/// Writes `data` to `path` in 64 KiB pieces (each one commit).
fn put(path: &str, off: u64, data: &[u8]) -> Result<(), String> {
    for (k, c) in data.chunks(64 * 1024).enumerate() {
        fs::write(path, off + (k * 64 * 1024) as u64, c).map_err(|x| e(path, x))?;
    }
    Ok(())
}

fn new_file(path: &str, data: &[u8]) -> Result<(), String> {
    fs::create(path).map_err(|x| e(path, x))?;
    put(path, 0, data)
}

/// Part 1: format disk 0, mount it as at start, write the set.
fn write_set() -> T {
    if !crate::selftest::autotest() {
        return Ok(String::from("skipped - not in the automatic test mode (disk 0 may hold your data)"));
    }
    ensure!(crate::block::count() >= 1, "no disk 0");
    let mut head = vec![0u8; 64 * 1024];
    crate::block::read(0, 0, &mut head).map_err(|x| format!("read disk 0: {}", x))?;
    ensure!(head.iter().all(|&b| b == 0), "disk 0 is not the empty test disk - refusing to format it");
    let p = Params { uuid: core::array::from_fn(|i| 0xC0 + i as u8), time: 1_700_000_000, label: "RESTART-TEST" };
    fmt::format(0, &p).map_err(|x| format!("format: {}", x))?;
    let m = fs::mount_disk(0, "/disk");
    ensure!(m == DiskMount::DeSoFs(None), "mount after format: {:?}", m);
    // Files of several sizes, a hole, directories.
    for (path, data) in expected() {
        match data {
            None => fs::mkdir(&path).map_err(|x| e(&path, x))?,
            Some(_) if path == "/disk/sparse" => {
                fs::create(&path).map_err(|x| e(&path, x))?;
                put(&path, 0, &pattern(4096, 5))?;
                put(&path, 1 << 20, &pattern(4096, 6))?;
            }
            Some(_) if path == "/disk/target" => {}
            Some(d) => new_file(&path, &d)?,
        }
    }
    // A rename that replaces a file; removed files.
    new_file("/disk/target", &pattern(500, 99))?;
    new_file("/disk/old-name", &pattern(3000, 8))?;
    fs::rename("/disk/old-name", "/disk/target").map_err(|x| e("rename", x))?;
    new_file("/disk/gone", b"removed before the restart")?;
    fs::remove("/disk/gone").map_err(|x| e("remove", x))?;
    // 300 entries, the first ten removed (deleted entries stay in the directory).
    for i in 0..300 {
        let name = format!("/disk/many/entry-with-a-longer-name-{:03}", i);
        new_file(&name, &pattern(10 + i, 1000 + i as u32))?;
    }
    for i in 0..10 {
        let name = format!("/disk/many/entry-with-a-longer-name-{:03}", i);
        fs::remove(&name).map_err(|x| e(&name, x))?;
    }
    let st = fs::stat("/disk/many").map_err(|x| e("stat many", x))?;
    ensure!(st.size >= 2 * 4096, "300 entries in only {} bytes of directory", st.size);
    // Everything as expected before the power-off, too.
    compare("before the restart")?;
    // A snapshot of exactly this state, then one more file and one changed file in the
    // live tree only.
    let mut made: Result<usize, String> = Err(String::from("/disk not mounted"));
    fs::with_mounted_desofs(0, &mut |v| made = v.snapshot_create(SNAP));
    made.map_err(|x| format!("snapshot: {}", x))?;
    new_file(AFTER_SNAP, &pattern(2000, 66))?;
    put("/disk/one", 0, &pattern(1, 67))?;
    Ok(format!(
        "disk 0 formatted and mounted as at start; {} files and directories (0 B to 1 MiB with a hole, 3 levels, rename replacing a file, removed files) + 300 entries with 10 removed ({} directory blocks); snapshot {} of that state, then a new file and a changed one; powering off normally",
        expected().len(),
        st.size / 4096,
        SNAP
    ))
}

const SNAP: &str = "before-restart";
const AFTER_SNAP: &str = "/disk/after-snapshot";

/// Everything under /disk equals the expected set (extra entries allowed only in `allow`).
fn compare_with(what: &str, allow: &[&str]) -> Result<(), String> {
    let exp = expected();
    let allowed = |p: &str| allow.iter().any(|a| p.starts_with(a));
    for (path, data) in &exp {
        if allowed(path) {
            continue; // changed on purpose; the caller checks it
        }
        let st = fs::stat(path).map_err(|x| format!("{}: {}", what, e(path, x)))?;
        match data {
            None => ensure!(st.kind == FileType::Directory, "{}: {} is not a directory", what, path),
            Some(d) => {
                ensure!(st.kind == FileType::File && st.size == d.len() as u64, "{}: {} size {} (expected {})", what, path, st.size, d.len());
                let got = fs::read_file(path).map_err(|x| format!("{}: {}", what, e(path, x)))?;
                ensure!(got == *d, "{}: {} differs", what, path);
            }
        }
    }
    // No other entries (removed files do not come back).
    let mut stack = vec![String::from("/disk")];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        if dir == "/disk/many" {
            continue;
        }
        for en in fs::read_dir(&dir).map_err(|x| format!("{}: {}", what, e(&dir, x)))? {
            let p = format!("{}/{}", dir, en.name);
            if allowed(&p) {
                continue;
            }
            ensure!(exp.iter().any(|(q, _)| *q == p), "{}: unexpected {}", what, p);
            seen += 1;
            if en.kind == FileType::Directory {
                stack.push(p);
            }
        }
    }
    let exp_n = exp.iter().filter(|(q, _)| !allowed(q)).count();
    ensure!(seen == exp_n, "{}: {} entries, {} expected", what, seen, exp_n);
    // The 300-entry directory, read in parts of 32 (byte positions).
    let want = many();
    let mut got: Vec<String> = Vec::new();
    let mut cur = 0u64;
    let mut parts = 0;
    loop {
        let (part, next) = fs::read_dir_at("/disk/many", cur, 32).map_err(|x| format!("{}: {}", what, e("read_dir_at", x)))?;
        for (_, en) in part {
            got.push(en.name);
        }
        parts += 1;
        match next {
            Some(c) => cur = c,
            None => break,
        }
        ensure!(parts < 100, "{}: the listing never ends", what);
    }
    got.sort();
    let names: Vec<String> = want.iter().map(|(n, _)| n.clone()).collect();
    ensure!(got == names, "{}: /disk/many has {} entries, {} expected", what, got.len(), names.len());
    for (n, d) in &want {
        let p = format!("/disk/many/{}", n);
        ensure!(fs::read_file(&p).map_err(|x| e(&p, x))? == *d, "{}: {} differs", what, p);
    }
    Ok(())
}

fn compare(what: &str) -> Result<(), String> {
    compare_with(what, &[])
}

/// Runs a program and returns its output (or why it failed).
fn run(path: &str, args: &[&str]) -> Result<String, String> {
    let opts = crate::user::SpawnOptions { stdin: Some(Vec::new()), capture: true, ..crate::user::SpawnOptions::default() };
    let id = crate::user::exec(path, args, "/", &opts).map_err(|_| format!("exec {}", path))?;
    let end = crate::time::ticks() + 60_000;
    while crate::sched::task_info(id).is_some() && crate::time::ticks() < end {
        crate::time::sleep_ms(2);
    }
    ensure!(crate::sched::task_info(id).is_none(), "{} did not finish", path);
    Ok(String::from_utf8_lossy(&crate::user::captured_output(id).unwrap_or_default()).into_owned())
}

fn hex(h: &[u8; 32]) -> String {
    let mut s = String::new();
    for b in h {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn auto_mounted() -> T {
    let m = fs::mount_list();
    ensure!(m.iter().any(|(p, kind, _)| p == "/disk" && *kind == "desofs"), "/disk is not DeSoFS after the restart: {:?}", m);
    let r = super::probe(0);
    ensure!(r.state == super::State::ReadWrite, "disk 0: {:?}", r.state);
    Ok(format!("the kernel mounted /disk as DeSoFS by itself, read-write (generation {}, {} nodes)", r.generation, r.nodes))
}

fn contents() -> T {
    compare_with("after the restart", &[AFTER_SNAP, "/disk/one"])?;
    ensure!(fs::read_file(AFTER_SNAP).map_err(|x| e(AFTER_SNAP, x))? == pattern(2000, 66), "{} differs", AFTER_SNAP);
    ensure!(fs::read_file("/disk/one").map_err(|x| e("/disk/one", x))? == pattern(1, 67), "/disk/one is not the version written after the snapshot");
    Ok(format!("every file and directory equal byte for byte ({} + 290 entries; removed ones did not come back); the 300-entry directory read in parts of 32 by byte position", expected().len()))
}

fn programs() -> T {
    let out = run("/bin/sha256sum", &["sha256sum", "/disk/mid"])?;
    let want = hex(&super::sha256(&pattern(100 * 1024, 3)));
    ensure!(out.starts_with(&want), "sha256sum /disk/mid: {:?}", out.trim());
    let out = run("/bin/ls", &["ls", "/disk/many"])?;
    let lines = out.lines().filter(|l| l.contains("entry-with-a-longer-name-")).count();
    ensure!(out.contains("(large directory") && lines == 290, "ls /disk/many: {} entries, large directory note {}", lines, out.contains("(large directory"));
    // Writing after the restart.
    new_file("/disk/after-restart", &pattern(5000, 55))?;
    ensure!(fs::read_file("/disk/after-restart").map_err(|x| e("after-restart", x))? == pattern(5000, 55), "file written after the restart differs");
    compare_with("after a new file", &["/disk/after-restart", AFTER_SNAP, "/disk/one"])?;
    Ok(String::from("/bin/sha256sum reads /disk/mid with the right sum, /bin/ls lists the 290 entries in parts (readdir_part), a new file written and read back"))
}

/// The snapshot taken before the restart: listed, and its view holds the state before the
/// last two changes.
fn snapshot() -> T {
    let (_, list) = super::snapshot_usage(0, true)?;
    let s = list.iter().find(|s| s.name == SNAP).ok_or_else(|| format!("snapshot {} not on the list after the restart", SNAP))?;
    let v = super::vol::Volume::mount_snapshot(0, SNAP)?;
    let at = format!("/snap/{}", SNAP);
    let _ = fs::mkdir("/snap");
    let _ = fs::mkdir(&at);
    fs::mount(&at, alloc::boxed::Box::new(fs::Locked::new(v))).map_err(|x| e("mount the snapshot", x))?;
    let r = (|| -> Result<(), String> {
        let one = fs::read_file(&format!("{}/one", at)).map_err(|x| e("snapshot one", x))?;
        ensure!(one == pattern(1, 1), "the snapshot's /one is the changed version");
        ensure!(fs::stat(&format!("{}/after-snapshot", at)).is_err(), "the file written after the snapshot is in the snapshot");
        let mid = fs::read_file(&format!("{}/mid", at)).map_err(|x| e("snapshot mid", x))?;
        ensure!(mid == pattern(100 * 1024, 3), "the snapshot's /mid differs");
        ensure!(fs::create(&format!("{}/x", at)).is_err(), "a file created in a snapshot view");
        Ok(())
    })();
    fs::unmount(&at).map_err(|x| e("unmount the snapshot", x))?;
    r?;
    Ok(format!("snapshot {} (generation {}, {} blocks of its own) listed after the restart; its view (read-only) has the old /one and no file written after it", SNAP, s.created_gen, s.only.unwrap_or(0)))
}

/// The mounted /disk volume's time counters (vol::Prof).
fn prof_now() -> (super::vol::Prof, super::cache::Stats) {
    let mut p = (super::vol::Prof::default(), super::cache::Stats::default());
    fs::with_mounted_desofs(0, &mut |v| p = (v.prof, v.cache.stats));
    p
}

/// One `[RESULT-FS-PROF]` line: where the time of a benchmark phase went (µs), and what
/// the counting itself cost (timestamps taken × the measured cost of one).
fn prof_line(phase: &str, a: &(super::vol::Prof, super::cache::Stats), b: &(super::vol::Prof, super::cache::Stats), probe_cyc: u64, per_ms: u64) {
    let (ca, cb) = (&a.1, &b.1);
    let (a, b) = (&a.0, &b.0);
    let per_ms = per_ms.max(1);
    let us = |c: u64| c * 1000 / per_ms;
    let d = |x: u64, y: u64| y.saturating_sub(x);
    serial_println!(
        "[RESULT-FS-PROF] phase={} read_ops={} write_ops={} op_us={} blk_reads={} io_read_us={} sha_read_us={} hdr_us={} seal_shas={} sha_seal_us={} blk_writes={} io_write_us={} flush1_us={} sb_write_us={} flush2_us={} commits={} commit_us={} cache_hits={} cache_misses={} cache_stale={} cache_bad={} cache_inserts={} cache_evictions={} probes={} probe_overhead_us={}",
        phase,
        d(a.read_ops, b.read_ops),
        d(a.write_ops, b.write_ops),
        us(d(a.read_op_cyc, b.read_op_cyc) + d(a.write_op_cyc, b.write_op_cyc)),
        d(a.blk_reads, b.blk_reads),
        us(d(a.io_read_cyc, b.io_read_cyc)),
        us(d(a.sha_read_cyc, b.sha_read_cyc)),
        us(d(a.hdr_cyc, b.hdr_cyc)),
        d(a.seal_shas, b.seal_shas),
        us(d(a.sha_seal_cyc, b.sha_seal_cyc)),
        d(a.blk_writes, b.blk_writes),
        us(d(a.io_write_cyc, b.io_write_cyc)),
        us(d(a.flush1_cyc, b.flush1_cyc)),
        us(d(a.sb_write_cyc, b.sb_write_cyc)),
        us(d(a.flush2_cyc, b.flush2_cyc)),
        d(a.commits, b.commits),
        us(d(a.commit_cyc, b.commit_cyc)),
        d(ca.hits, cb.hits),
        d(ca.misses, cb.misses),
        d(ca.stale, cb.stale),
        d(ca.bad, cb.bad),
        d(ca.inserts, cb.inserts),
        d(ca.evictions, cb.evictions),
        d(a.probes, b.probes),
        us(d(a.probes, b.probes) * probe_cyc)
    );
}

/// Cycles one timestamp of vol::Prof costs (the median of 5 runs of 10 000).
fn probe_cost() -> u64 {
    let mut runs = [0u64; 5];
    for r in runs.iter_mut() {
        let mut p = super::vol::Prof::default();
        let t0 = crate::arch::x86_64::clock::tsc_cpu().0;
        let mut x = 0u64;
        for _ in 0..10_000 {
            x = x.wrapping_add(p.now());
        }
        core::hint::black_box(x);
        *r = crate::arch::x86_64::clock::tsc_cpu().0.wrapping_sub(t0) / 10_000;
    }
    runs.sort();
    runs[2]
}

fn bench() -> T {
    let ms = crate::time::uptime_ms;
    let probe_cyc = probe_cost();
    // Cycles per ms measured over the whole benchmark (the restart start skips the LAPIC
    // calibration, and this also holds where the TSC rate is not the nominal one).
    let (tsc0, ms0) = (crate::arch::x86_64::clock::tsc_cpu().0, ms());
    fs::mkdir("/disk/bench").map_err(|x| e("mkdir bench", x))?;
    // A large file: 8 MiB in 64 KiB pieces (each one commit), then read back.
    let big = pattern(8 << 20, 77);
    let p0 = prof_now();
    let t0 = ms();
    new_file("/disk/bench/big", &big)?;
    let t_w = ms() - t0;
    let p1 = prof_now();
    let t0 = ms();
    let mut back = vec![0u8; 64 * 1024];
    let mut same = true;
    for k in 0..(big.len() / back.len()) {
        let n = fs::read("/disk/bench/big", (k * back.len()) as u64, &mut back).map_err(|x| e("read big", x))?;
        same &= n == back.len() && back[..] == big[k * back.len()..(k + 1) * back.len()];
    }
    let t_r = ms() - t0;
    let p2 = prof_now();
    ensure!(same, "the 8 MiB file read back differs");
    // 1000 small files of 100 bytes: create + write, then read all.
    let t0 = ms();
    for i in 0..1000 {
        new_file(&format!("/disk/bench/s{:04}", i), &pattern(100, i))?;
    }
    let t_sc = ms() - t0;
    let p3 = prof_now();
    let t0 = ms();
    for i in 0..1000 {
        let p = format!("/disk/bench/s{:04}", i);
        ensure!(fs::read_file(&p).map_err(|x| e(&p, x))? == pattern(100, i), "{} differs", p);
    }
    let t_sr = ms() - t0;
    let p4 = prof_now();
    // The whole volume checked (unmounted first – check refuses a mounted volume).
    fs::unmount("/disk").map_err(|x| e("unmount /disk", x))?;
    let t0 = ms();
    let rep = super::check::check(0, &mut |_, _| {})?;
    let t_ck = ms() - t0;
    ensure!(rep.errors == 0 && rep.warnings == 0 && rep.slots.iter().all(|s| s.data_ok != Some(true) || s.complete), "desofs check after the restart: {} errors, {} warnings: {:?}", rep.errors, rep.warnings, rep.lines);
    let m = fs::mount_disk(0, "/disk");
    ensure!(m == DiskMount::DeSoFs(None), "mount again: {:?}", m);
    let kbs = |bytes: usize, t: u64| bytes as u64 * 1000 / 1024 / t.max(1);
    let vol_mib = super::probe(0).total_blocks * 4 / 1024;
    let tsc_khz = crate::arch::x86_64::clock::tsc_cpu().0.wrapping_sub(tsc0) / (ms() - ms0).max(1);
    for (phase, a, b) in [("big_write", &p0, &p1), ("big_read", &p1, &p2), ("small_create", &p2, &p3), ("small_read", &p3, &p4)] {
        prof_line(phase, a, b, probe_cyc, tsc_khz);
    }
    serial_println!("[RESULT-FS-PROF] tsc_khz={} probe_cycles={} cache_limit_kib={} cache_used_kib={}", tsc_khz, probe_cyc, super::cache::limit() / 1024, super::cache::used() / 1024);
    serial_println!(
        "[RESULT-FS] ver={} disk=virtio vol_mib={} big_mib=8 chunk_kib=64 big_write_kbs={} big_read_kbs={} small_n=1000 small_b=100 small_create_ms={} small_read_ms={} check_ms={} check_blocks={}",
        crate::shell::VERSION,
        vol_mib,
        kbs(big.len(), t_w),
        kbs(big.len(), t_r),
        t_sc,
        t_sr,
        t_ck,
        rep.data_blocks
    );
    Ok(format!("8 MiB written in {} ms, read in {} ms; 1000 small files created in {} ms, read in {} ms; desofs check of the volume: 0 errors, 0 warnings, complete ({} ms); mounted again", t_w, t_r, t_sc, t_sr, t_ck))
}

fn report(n: usize, total: usize, name: &str, r: T) -> bool {
    match r {
        Ok(line) => {
            serial_println!("[RESTART TEST] {}/{} {}: {} PASS", n, total, name, line);
            true
        }
        Err(why) => {
            serial_println!("[RESTART TEST] FAIL: {}: {}", name, why);
            false
        }
    }
}

/// Part 1 – the last step of the normal self-test run.
pub fn prepare() {
    serial_println!("[RESTART TEST] Part 1: DeSoFS on disk 0 before a restart...");
    crate::selftest::begin();
    if report(1, 6, "write before the restart", write_set()) {
        crate::selftest::pass();
    }
}

/// Part 2 – the second start (tests/test.sh, phase "restart").
pub fn verify() {
    serial_println!("[RESTART TEST] Part 2: after the restart...");
    crate::selftest::begin();
    let steps: [(&str, fn() -> T); 5] = [("automatic mount", auto_mounted), ("contents", contents), ("programs and writing", programs), ("snapshot", snapshot), ("speed and check", bench)];
    for (k, (name, f)) in steps.iter().enumerate() {
        if !report(2 + k, 6, name, f()) {
            return;
        }
    }
    serial_println!("[RESTART TEST] All restart tests passed!");
    crate::selftest::pass();
}
