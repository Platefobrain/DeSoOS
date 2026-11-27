// PKG FORMAT TEST – desopkg's formats (V082 stage A): user/lib/pkgfmt.rs in user space
// (/bin/pkgtest) judges the vectors tools/desopkg.py made at build time (build.sh --selftest,
// in the image as PKG_VECTORS) – the same verdict and reason id as the Python tool for every
// package, manifest, index, signature, key store, accepted index and generation; the image's
// /etc/desopkg; every /bin program through common/elf.rs `check_program` (the rules desopkg will
// check a package's programs with) and the kernel's own loader agreeing on them.

use alloc::string::String;

use super::*;
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[PKG FORMAT TEST] FAIL: {}", format_args!($($msg)*));
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

/// A program from /bin with captured output; (how it ended, output).
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

/// The record count from the vector file's first line ("DESOPKG-VECTORS 1 <count>").
fn vector_count(v: &[u8]) -> Option<usize> {
    let nl = v.iter().position(|&c| c == b'\n')?;
    core::str::from_utf8(&v[..nl]).ok()?.strip_prefix("DESOPKG-VECTORS 1 ")?.parse().ok()
}

pub fn self_test() {
    serial_println!("[PKG FORMAT TEST] Starting desopkg format tests...");
    crate::selftest::begin();
    let t0 = ticks();

    // 1. The vectors: Rust (pkgfmt.rs in /bin/pkgtest) against Python (tools/desopkg.py).
    let vectors = crate::initrd::PKG_VECTORS;
    let count = vector_count(vectors);
    check!(count.is_some_and(|n| n > 0), "no vectors in the image (build.sh --selftest makes them with tools/desopkg.py)");
    let count = count.unwrap_or(0);
    const FILE: &str = "/tmp/pkgvec.bin";
    check!(crate::fs::write_file(FILE, vectors).is_ok(), "cannot write {}", FILE);
    let r = run("/bin/pkgtest", &["pkgtest", "vectors", FILE], 300_000);
    let _ = crate::fs::remove(FILE);
    check!(r.is_some(), "pkgtest vectors did not finish");
    let (kind, out) = r.unwrap();
    let out = out.trim();
    check!(kind == ExitKind::Exit(0) && out.contains(&alloc::format!("{} vectors OK", count)), "pkgtest vectors: {:?} {}", kind, out);
    serial_println!(
        "[PKG FORMAT TEST] 1/3 {} vectors from tools/desopkg.py judged by pkgfmt.rs in user space – the same verdict and reason (manifest, .pkg, index, signature P-256 low-S, keys, accepted index, generations, reserved names: {}) PASS",
        count,
        out.rsplit_once('(').map(|(_, r)| r.trim_end_matches(')')).unwrap_or("")
    );

    // 2. /etc/desopkg in the image.
    let r = run("/bin/pkgtest", &["pkgtest", "etc"], 30_000);
    check!(r.is_some(), "pkgtest etc did not finish");
    let (kind, out) = r.unwrap();
    let out = out.trim();
    check!(kind == ExitKind::Exit(0) && out.starts_with("pkgtest etc: "), "pkgtest etc: {:?} {}", kind, out);
    check!(crate::fs::is_sealed("/etc/desopkg/keys") && crate::fs::is_sealed("/etc/desopkg/repo") && crate::fs::is_sealed("/etc/desopkg"), "/etc/desopkg is not sealed");
    check!(crate::fs::write_file("/etc/desopkg/keys", b"DESOPKG-KEYS 1\nend\n").is_err(), "the sealed /etc/desopkg/keys could be overwritten");
    serial_println!("[PKG FORMAT TEST] 2/3 {} – sealed PASS", out.trim_start_matches("pkgtest etc: "));

    // 3. Every /bin program: common/elf.rs check_program in user space, and the kernel loader.
    let r = run("/bin/pkgtest", &["pkgtest", "elf"], 120_000);
    check!(r.is_some(), "pkgtest elf did not finish");
    let (kind, out) = r.unwrap();
    let out = out.trim();
    check!(kind == ExitKind::Exit(0) && out.starts_with("pkgtest elf: "), "pkgtest elf: {:?} {}", kind, out);
    let mut loaded = 0;
    for e in crate::fs::read_dir("/bin").unwrap_or_default() {
        let path = alloc::format!("/bin/{}", e.name);
        let Ok(b) = crate::fs::read_file(&path) else { continue };
        check!(elf_loader::load(&b, &["x"]).is_ok(), "{}: the kernel loader refuses it", path);
        loaded += 1;
    }
    let programs = out.trim_start_matches("pkgtest elf: ").split(' ').next().and_then(|n| n.parse::<usize>().ok()).unwrap_or(0);
    check!(programs == loaded && loaded > 0, "pkgtest accepted {} programs, the kernel loaded {}", programs, loaded);
    serial_println!("[PKG FORMAT TEST] 3/3 {} /bin programs: common/elf.rs check_program (user space) and the kernel loader agree PASS", loaded);

    serial_println!("[RESULT-PKG] vectors={} programs={} ms={}", count, loaded, ticks() - t0);
    serial_println!("[PKG FORMAT TEST] All desopkg format tests passed!");
    crate::selftest::pass();
}
