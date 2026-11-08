// CRYPTO TEST – DeSoCrypto (common/desocrypto): the same vectors in the kernel
// (overflow checks on, kernel code model) and in user space (/bin/cryptotest),
// sha256sum against the kernel's own result, the speed of SHA-256.
// The library is included here only in the selftest build.

use alloc::string::String;
use alloc::vec::Vec;

use super::*;
use crate::time::ticks;

#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;
#[path = "../../common/desocrypto/tests.rs"]
mod desocrypto_tests;

use desocrypto::sha256::{Sha256, sha256};

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[CRYPTO TEST] FAIL: {}", format_args!($($msg)*));
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

/// Program from /bin with the given input and captured output; (how it ended, output).
fn run(path: &str, args: &[&str], stdin: &[u8], ms: u64) -> Option<(ExitKind, String)> {
    let opts = SpawnOptions { stdin: Some(stdin.to_vec()), capture: true, ..SpawnOptions::default() };
    let id = exec(path, args, "/", &opts).ok()?;
    if !wait_for(ms, || sched::task_info(id).is_none()) {
        let _ = sched::request_exit(id);
        return None;
    }
    let kind = exit_info(id)?.kind;
    Some((kind, String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned()))
}

fn hex(d: &[u8; 32]) -> String {
    let mut t = [0u8; 64];
    String::from(desocrypto::hex(d, &mut t).unwrap_or(""))
}

/// The number after `key ` in `text` (e.g. "sha256 1234 KiB/s").
fn number_after(text: &str, key: &str) -> u64 {
    let Some(i) = text.find(key) else { return 0 };
    text[i + key.len()..].bytes().take_while(|b| b.is_ascii_digit()).fold(0, |v, b| v * 10 + (b - b'0') as u64)
}

pub fn self_test() {
    serial_println!("[CRYPTO TEST] Starting DeSoCrypto {} tests...", desocrypto::VERSION);
    crate::selftest::begin();

    // 1. Every vector and edge case inside the kernel: no heap, no syscalls,
    // wrapping arithmetic only (the kernel panics on an unintended overflow).
    let t0 = ticks();
    let r = desocrypto_tests::run();
    check!(r.is_ok(), "in the kernel: {:?}", r.err());
    let n = r.unwrap_or(0);
    serial_println!("[CRYPTO TEST] 1/4 in the kernel: {} checks (SHA-256 FIPS 180-4, HMAC RFC 4231, HKDF RFC 5869, ChaCha20 / Poly1305 / AEAD RFC 8439, X25519 RFC 7748, the key-erasure generator, arithmetic ranges, limits) in {} ms PASS", n, ticks() - t0);

    // 2. The same in user space.
    let r = run("/bin/cryptotest", &["cryptotest"], &[], 60_000);
    check!(r.is_some(), "cryptotest did not finish");
    let (kind, out) = r.unwrap();
    let out = out.trim();
    check!(kind == ExitKind::Exit(0) && out.contains(&alloc::format!("{} checks OK", n)), "cryptotest: {:?} {:?}", kind, out);
    let user_kbs = number_after(out, "sha256 ");
    let hmac_kbs = number_after(out, "hmac ");
    let aead_kbs = number_after(out, "aead ");
    let x25519_ops = number_after(out, "x25519 ");
    serial_println!("[CRYPTO TEST] 2/4 user space: {} PASS", out);

    // 3. sha256sum: files (empty, "abc", 300 KiB + 13 bytes) against the kernel's
    // result, standard input, a missing file (error, exit 1, the others still listed).
    let mut big: Vec<u8> = Vec::new();
    big.resize(300 * 1024 + 13, 0);
    for (i, b) in big.iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(31).wrapping_add(i as u32 >> 9) as u8;
    }
    let files: [(&str, &[u8]); 3] = [("/crypto-empty.txt", b""), ("/crypto-abc.txt", b"abc"), ("/crypto-big.bin", &big)];
    for (path, data) in &files {
        check!(crate::fs::write_file(path, data).is_ok(), "cannot write {}", path);
    }
    let r = run("/bin/sha256sum", &["sha256sum", files[0].0, files[1].0, "/crypto-missing", files[2].0], &[], 60_000);
    for (path, _) in &files {
        let _ = crate::fs::remove(path);
    }
    check!(r.is_some(), "sha256sum did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(1), "sha256sum with a missing file: {:?} (expected exit 1)", kind);
    for (path, data) in &files {
        let line = alloc::format!("{}  {}", hex(&sha256(data)), path);
        check!(out.lines().any(|l| l == line), "sha256sum: no line {:?} in {:?}", line, out);
    }
    check!(out.contains("sha256sum: /crypto-missing:"), "sha256sum: missing file not reported: {:?}", out);
    check!(out.contains("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  /crypto-abc.txt"), "sha256sum: wrong \"abc\": {:?}", out);
    let r = run("/bin/sha256sum", &["sha256sum"], b"abc", 30_000);
    check!(r.is_some(), "sha256sum (stdin) did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.trim() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -", "sha256sum (stdin): {:?} {:?}", kind, out);
    serial_println!("[CRYPTO TEST] 3/4 sha256sum: 3 files = kernel result, stdin, missing file -> exit 1 PASS");

    // 4. Speed of SHA-256 in the kernel (256 KiB pieces, at least 200 ms).
    let start = ticks();
    let mut kib = 0u64;
    let mut h = Sha256::new();
    let piece = &big[..256 * 1024];
    loop {
        h.update(piece);
        kib += 256;
        if ticks() - start >= 200 {
            break;
        }
    }
    let ms = (ticks() - start).max(1);
    check!(h.finish().is_ok(), "kernel speed run: hash refused");
    let kernel_kbs = kib * 1000 / ms;
    serial_println!("[CRYPTO TEST] 4/4 speed: SHA-256 {} KiB/s in the kernel, {} KiB/s in user space; HMAC {} KiB/s PASS", kernel_kbs, user_kbs, hmac_kbs);
    serial_println!(
        "[RESULT-CRYPTO] ver={} lib={} checks={} sha256_kernel_kbs={} sha256_user_kbs={} hmac_user_kbs={} aead_user_kbs={} x25519_user_ops={}",
        crate::shell::VERSION,
        desocrypto::VERSION,
        n,
        kernel_kbs,
        user_kbs,
        hmac_kbs,
        aead_kbs,
        x25519_ops
    );
    serial_println!("[CRYPTO TEST] All crypto tests passed!");
    crate::selftest::pass();
}
