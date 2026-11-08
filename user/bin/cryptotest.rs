// cryptotest – DeSoCrypto in user space: every test vector and edge case
// (common/desocrypto/tests.rs), then the speed of SHA-256 and HMAC-SHA256.
// Output: "cryptotest: N checks OK (DeSoCrypto x.y.z); sha256 K KiB/s, hmac K KiB/s,
// aead K KiB/s, x25519 N ops/s";
// on a failure "cryptotest: FAIL <group> case <n>" and exit code 1.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;
#[path = "../../common/desocrypto/tests.rs"]
mod desocrypto_tests;

use desocrypto::hmac::HmacSha256;
use desocrypto::sha256::Sha256;

entry!(main);

static mut BUF: [u8; 64 * 1024] = [0; 64 * 1024];
/// Sealed in place by the AEAD speed run (BUF is lent read-only to `speed`).
static mut ABUF: [u8; 64 * 1024] = [0; 64 * 1024];

/// KiB/s of `f` over 64 KiB pieces, measured for at least 200 ms.
fn speed(mut f: impl FnMut(&[u8])) -> u64 {
    // SAFETY: single-threaded program; BUF is only read here.
    let buf: &[u8] = unsafe { &*core::ptr::addr_of!(BUF) };
    let start = desoos::uptime_ms();
    let mut kib = 0u64;
    loop {
        f(buf);
        kib += 64;
        let ms = desoos::uptime_ms() - start;
        if ms >= 200 {
            return kib * 1000 / ms;
        }
    }
}

fn main(_args: desoos::Args) -> i32 {
    let n = match desocrypto_tests::run() {
        Ok(n) => n,
        Err(f) => {
            println!("cryptotest: FAIL {} case {}", f.group, f.case);
            return 1;
        }
    };
    let mut sha = Sha256::new();
    let sha_kbs = speed(|b| sha.update(b));
    let _ = sha.finish();
    let mut mac = HmacSha256::new(b"cryptotest key");
    let hmac_kbs = speed(|b| mac.update(b));
    let _ = mac.finish();
    // ChaCha20-Poly1305: 64 KiB sealed in place, again and again (a fresh nonce each time).
    let key = [7u8; 32];
    let mut ctr = 0u64;
    let aead_kbs = speed(|_| {
        ctr += 1;
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&ctr.to_le_bytes());
        // SAFETY: single-threaded program; only this closure uses ABUF.
        let buf: &mut [u8] = unsafe { &mut *core::ptr::addr_of_mut!(ABUF) };
        let _ = desocrypto::aead::seal(&key, &nonce, b"", buf);
    });
    // X25519: shared secrets per second (at least 200 ms).
    let start = desoos::uptime_ms();
    let mut k = [9u8; 32];
    let mut ops = 0u64;
    let x25519_ops = loop {
        let mut nine = [0u8; 32];
        nine[0] = 9;
        if let Ok(r) = desocrypto::x25519::x25519(&k, &nine) {
            k = r;
        }
        ops += 1;
        let ms = desoos::uptime_ms() - start;
        if ms >= 200 {
            break ops * 1000 / ms;
        }
    };
    println!(
        "cryptotest: {} checks OK (DeSoCrypto {}); sha256 {} KiB/s, hmac {} KiB/s, aead {} KiB/s, x25519 {} ops/s",
        n,
        desocrypto::VERSION,
        sha_kbs,
        hmac_kbs,
        aead_kbs,
        x25519_ops
    );
    0
}
