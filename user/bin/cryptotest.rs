// cryptotest – DeSoCrypto in user space: every test vector and edge case
// (common/desocrypto/tests.rs – AES-GCM with every AES-NI / PCLMULQDQ combination this CPU
// allows), then the speeds.
// Output, three lines short enough for the screen (240 columns):
//   "cryptotest: N checks OK (DeSoCrypto x.y.z); sha256 K KiB/s, hmac K KiB/s, aead K KiB/s,
//    x25519 N ops/s"
//   "cryptotest: aesni yes|no, pclmul yes|no, aesgcm K KiB/s, aesgcm_soft K KiB/s"
//   "cryptotest: sha512 K KiB/s, verify rsa2048 N/s, p256 N/s, p384 N/s"
// on a failure "cryptotest: FAIL <group> case <n>" and exit code 1.
//
// `cryptotest xmm <n> [seconds]`: the XMM test (0.4 s unless seconds are given – e.g. 20 to
// start several by hand in the shell with `&` while the first still runs) – rounds of (a) a pattern of its own (from n) in
// xmm0-xmm15, a yield, the pattern read back and compared; (b) AES-GCM with the hardware
// paths compared with the software result.  Several of these run at once (RNG / CRYPTO
// TEST) so the CPU switches between them all the time.  Output "cryptotest xmm: R rounds
// OK" or "cryptotest xmm: FAIL ..." (exit 1).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;
#[path = "../../common/desocrypto/tests.rs"]
mod desocrypto_tests;

use desocrypto::aes::Features;
use desocrypto::aes_gcm::AesGcm;
use desocrypto::hmac::HmacSha256;
use desocrypto::sha256::Sha256;
use desocrypto::sha512::Sha512;

entry!(main);

fn key16() -> [u8; 16] {
    [7u8; 16]
}

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

/// Writes `pat` into xmm0-xmm15, yields the CPU (syscall), reads xmm0-xmm15 into `back`
/// – all in one asm block, so nothing else can touch the registers in between.
fn xmm_round(pat: &[u8; 256], back: &mut [u8; 256]) {
    // SAFETY: the asm reads 256 bytes at `pat`, writes 256 bytes at `back`, makes the yield
    // syscall (clobbers rax, rcx, r11) and declares no XMM use to the compiler – this
    // program is built without SSE, so the compiler keeps nothing in XMM across it.
    unsafe {
        core::arch::asm!(
            "movdqu xmm0, [{p}]", "movdqu xmm1, [{p} + 16]", "movdqu xmm2, [{p} + 32]", "movdqu xmm3, [{p} + 48]",
            "movdqu xmm4, [{p} + 64]", "movdqu xmm5, [{p} + 80]", "movdqu xmm6, [{p} + 96]", "movdqu xmm7, [{p} + 112]",
            "movdqu xmm8, [{p} + 128]", "movdqu xmm9, [{p} + 144]", "movdqu xmm10, [{p} + 160]", "movdqu xmm11, [{p} + 176]",
            "movdqu xmm12, [{p} + 192]", "movdqu xmm13, [{p} + 208]", "movdqu xmm14, [{p} + 224]", "movdqu xmm15, [{p} + 240]",
            "syscall",
            "movdqu [{b}], xmm0", "movdqu [{b} + 16], xmm1", "movdqu [{b} + 32], xmm2", "movdqu [{b} + 48], xmm3",
            "movdqu [{b} + 64], xmm4", "movdqu [{b} + 80], xmm5", "movdqu [{b} + 96], xmm6", "movdqu [{b} + 112], xmm7",
            "movdqu [{b} + 128], xmm8", "movdqu [{b} + 144], xmm9", "movdqu [{b} + 160], xmm10", "movdqu [{b} + 176], xmm11",
            "movdqu [{b} + 192], xmm12", "movdqu [{b} + 208], xmm13", "movdqu [{b} + 224], xmm14", "movdqu [{b} + 240], xmm15",
            p = in(reg) pat.as_ptr(),
            b = in(reg) back.as_mut_ptr(),
            inout("rax") desoos::SYS_YIELD => _,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
}

/// The XMM test (see the top).
fn xmm_test(seed: u64, run_ms: u64) -> i32 {
    let key = [0x5au8 ^ seed as u8; 16];
    let nonce = [seed as u8; 12];
    let mut msg = [0u8; 4096];
    for (i, b) in msg.iter_mut().enumerate() {
        *b = (i as u64 * 31 + seed) as u8;
    }
    // The reference: software only, computed once.
    let soft = AesGcm::with_features(&key, Features::NONE);
    let mut want = msg;
    let want_tag = match soft.seal(&nonce, b"xmm", &mut want) {
        Ok(t) => t,
        Err(_) => return 1,
    };
    let hw = AesGcm::new(&key);
    let start = desoos::uptime_ms();
    let mut rounds = 0u64;
    while desoos::uptime_ms() - start < run_ms || rounds < 20 {
        let mut pat = [0u8; 256];
        for (i, b) in pat.iter_mut().enumerate() {
            *b = (i as u64).wrapping_mul(0x9e37).wrapping_add(seed * 977 + rounds * 13) as u8;
        }
        let mut back = [0u8; 256];
        xmm_round(&pat, &mut back);
        if back != pat {
            let r = (0..16).find(|&r| back[16 * r..16 * r + 16] != pat[16 * r..16 * r + 16]).unwrap_or(0);
            println!("cryptotest xmm: FAIL round {}: xmm{} changed across a yield", rounds, r);
            return 1;
        }
        let mut b = msg;
        let t = hw.seal(&nonce, b"xmm", &mut b);
        if b != want || t != Ok(want_tag) {
            println!("cryptotest xmm: FAIL round {}: the hardware AES-GCM result differs from the software one", rounds);
            return 1;
        }
        desoos::syscall3(desoos::SYS_YIELD, 0, 0, 0);
        rounds += 1;
    }
    let f = hw.features();
    println!("cryptotest xmm: {} rounds OK (aesni {}, pclmul {})", rounds, if f.aes { "yes" } else { "no" }, if f.pclmul { "yes" } else { "no" });
    0
}

fn main(args: desoos::Args) -> i32 {
    if args.get(1) == Some("xmm") {
        let seed = args.get(2).and_then(|s| s.parse::<u64>().ok()).unwrap_or(1);
        let run_ms = args.get(3).and_then(|s| s.parse::<u64>().ok()).map(|s| s.min(3600) * 1000).unwrap_or(400);
        return xmm_test(seed, run_ms);
    }
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
    // AES-GCM: the automatic choice and the software path.
    let gcm_speed = |g: &AesGcm| {
        let mut ctr = 0u64;
        speed(|_| {
            ctr += 1;
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&ctr.to_le_bytes());
            // SAFETY: single-threaded program; only this closure uses ABUF.
            let buf: &mut [u8] = unsafe { &mut *core::ptr::addr_of_mut!(ABUF) };
            let _ = g.seal(&nonce, b"", buf);
        })
    };
    let auto = AesGcm::new(&key16());
    let gcm_kbs = gcm_speed(&auto);
    let soft_kbs = gcm_speed(&AesGcm::with_features(&key16(), Features::NONE));
    let f = auto.features();
    println!(
        "cryptotest: {} checks OK (DeSoCrypto {}); sha256 {} KiB/s, hmac {} KiB/s, aead {} KiB/s, x25519 {} ops/s",
        n,
        desocrypto::VERSION,
        sha_kbs,
        hmac_kbs,
        aead_kbs,
        x25519_ops
    );
    println!(
        "cryptotest: aesni {}, pclmul {}, aesgcm {} KiB/s, aesgcm_soft {} KiB/s",
        if f.aes { "yes" } else { "no" },
        if f.pclmul { "yes" } else { "no" },
        gcm_kbs,
        soft_kbs
    );
    let mut sha5 = Sha512::new();
    let sha512_kbs = speed(|b| sha5.update(b));
    let _ = sha5.finish();
    // Signature checks per second (one stored signature each, at least 200 ms).
    let mut per_s = [0u64; 3];
    for (kind, out) in per_s.iter_mut().enumerate() {
        let start = desoos::uptime_ms();
        let mut ops = 0u64;
        *out = loop {
            if !desocrypto_tests::sig_bench(kind as u8, 4) {
                println!("cryptotest: FAIL signature speed run {}", kind);
                return 1;
            }
            ops += 4;
            let ms = desoos::uptime_ms() - start;
            if ms >= 200 {
                break ops * 1000 / ms;
            }
        };
    }
    println!("cryptotest: sha512 {} KiB/s, verify rsa2048 {}/s, p256 {}/s, p384 {}/s", sha512_kbs, per_s[0], per_s[1], per_s[2]);
    0
}
