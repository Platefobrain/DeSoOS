// rngtest – `getrandom` from user space (RNG TEST 3): lengths 0 / 4096 / 4097, a wrong
// flag, addresses that are not writable user memory, a long request through the
// library (several syscalls), the speed; then 64 samples of 16 bytes for the kernel to
// compare between processes running at once.
// Output: "rngtest: N checks OK; getrandom K KiB/s; samples <hex>..." or
// "rngtest: FAIL case <n>" (exit 1).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

static mut BUF: [u8; 16384] = [0; 16384];

fn raw(ptr: u64, len: u64, flags: u64) -> i64 {
    syscall3(SYS_GETRANDOM, ptr, len, flags)
}

fn main(_args: Args) -> i32 {
    // SAFETY: single-threaded program; BUF is used only here.
    let buf: &mut [u8; 16384] = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
    let p = buf.as_mut_ptr() as u64;
    let mut case = 0;
    let mut check = |ok: bool| -> bool {
        case += 1;
        if !ok {
            println!("rngtest: FAIL case {}", case);
        }
        ok
    };
    // 1-2: nothing asked, nothing written.
    if !check(raw(p, 0, 0) == 0 && buf.iter().all(|&b| b == 0)) {
        return 1;
    }
    // 3-4: the largest request fills all of it (4096 zero bytes by chance: never).
    if !check(raw(p, 4096, 0) == 4096) || !check(buf[..4096].iter().any(|&b| b != 0) && buf[4096..].iter().all(|&b| b == 0)) {
        return 1;
    }
    // 5-6: one byte too many, a flag – refused, nothing written past the old contents.
    let before = buf[4096];
    if !check(raw(p, 4097, 0) == ERROR_INVALID_ARGUMENT && buf[4096] == before) || !check(raw(p, 16, 1) == ERROR_INVALID_ARGUMENT) {
        return 1;
    }
    // 7-9: not writable user memory – null, a kernel address, this program's code.
    let code = main as *const () as u64;
    if !check(raw(0, 16, 0) == ERROR_INVALID_ADDRESS)
        || !check(raw(0xffff_8000_0000_0000, 16, 0) == ERROR_INVALID_ADDRESS)
        || !check(raw(code, 16, 0) == ERROR_INVALID_ADDRESS)
    {
        return 1;
    }
    // 10: through the library – 10000 bytes in three syscalls, the tail filled too.
    for b in buf.iter_mut() {
        *b = 0;
    }
    if !check(getrandom(&mut buf[..10000]).is_ok() && buf[9000..10000].iter().any(|&b| b != 0)) {
        return 1;
    }
    // 11: two requests differ.
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    if !check(getrandom(&mut a).is_ok() && getrandom(&mut b).is_ok() && a != b) {
        return 1;
    }
    // Speed: 4096-byte requests for at least 200 ms.
    let start = uptime_ms();
    let mut kib = 0u64;
    let kbs = loop {
        let _ = raw(p, 4096, 0);
        kib += 4;
        let ms = uptime_ms() - start;
        if ms >= 200 {
            break kib * 1000 / ms;
        }
    };
    print!("rngtest: {} checks OK; getrandom {} KiB/s; samples", case, kbs);
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for _ in 0..64 {
        let mut s = [0u8; 16];
        if getrandom(&mut s).is_err() {
            println!();
            println!("rngtest: FAIL samples");
            return 1;
        }
        let mut h = [b' '; 33];
        for (i, x) in s.iter().enumerate() {
            h[1 + 2 * i] = DIGITS[(x >> 4) as usize];
            h[2 + 2 * i] = DIGITS[(x & 15) as usize];
        }
        write(1, &h);
    }
    println!();
    0
}
