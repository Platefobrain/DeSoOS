// cryptotest – DeSoCrypto in user space: every test vector and edge case
// (common/desocrypto/tests.rs), then the speed of SHA-256 and HMAC-SHA256.
// Output: "cryptotest: N checks OK (DeSoCrypto x.y.z); sha256 K KiB/s, hmac K KiB/s";
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
    println!(
        "cryptotest: {} checks OK (DeSoCrypto {}); sha256 {} KiB/s, hmac {} KiB/s",
        n,
        desocrypto::VERSION,
        sha_kbs,
        hmac_kbs
    );
    0
}
