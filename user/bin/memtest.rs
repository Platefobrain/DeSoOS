// M17b.d: test pamięci procesu – brk, mmap / munmap, leniwe strony, rosnący
// stos, duże i małe alokacje przez alokator biblioteki.
//   memtest          – wszystkie sprawdzenia; "memtest: N checks OK", kod 0
//   memtest unmapped – dotyka strony po munmap (powinien zginąć od #PF)
//   memtest stack    – rekurencja głębsza niż 8 MiB stosu (powinien zginąć)
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use alloc::vec;
use alloc::vec::Vec;
use desoos::*;

entry!(main);

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("memtest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

/// Rekurencja z ramką ~4 KiB na poziom; zwraca sumę (kompilator nie usunie).
#[inline(never)]
fn deep(level: u64) -> u64 {
    let mut pad = [0u8; 4000];
    pad[(level % 4000) as usize] = level as u8;
    let r = if level == 0 { 0 } else { deep(level - 1) };
    r + core::hint::black_box(&pad)[(level % 4000) as usize] as u64
}

fn main(args: Args) -> i32 {
    match args.get(1) {
        Some("unmapped") => {
            let a = mmap(8192, PROT_READ | PROT_WRITE).unwrap_or(0);
            unsafe { core::ptr::write_volatile(a as *mut u8, 1) };
            munmap(a, 8192);
            unsafe { core::ptr::write_volatile(a as *mut u8, 2) }; // #PF -> koniec
            return 0;
        }
        Some("stack") => {
            return deep(4096) as i32; // ~16 MiB stosu > 8 MiB
        }
        _ => {}
    }
    let mut n = 0;

    // 1. brk: zapytanie, wzrost, zapis na końcu, zmniejszenie.
    let b0 = brk(0);
    check!(n, b0 > 0, "brk(0) = {:#x}", b0);
    let b1 = brk(b0 + 3 * 4096 + 100);
    check!(n, b1 == b0 + 3 * 4096 + 100, "brk grow: {:#x}", b1);
    unsafe {
        core::ptr::write_volatile((b1 - 1) as *mut u8, 0x5a);
        check!(n, core::ptr::read_volatile((b1 - 1) as *const u8) == 0x5a, "last heap byte");
        check!(n, core::ptr::read_volatile(b0 as *const u64) == 0, "fresh heap page must be zero");
    }
    check!(n, brk(b0) == b0, "brk shrink");
    check!(n, brk(1) == b0, "invalid brk must return the current end");

    // 2. mmap: 64 MiB zarezerwowane, dotknięte tylko kilka stron.
    let big = mmap(64 << 20, PROT_READ | PROT_WRITE);
    check!(n, big.is_ok(), "mmap 64 MiB: {:?}", big);
    let big = big.unwrap();
    unsafe {
        for off in [0u64, 4096, 32 << 20, (64 << 20) - 8] {
            core::ptr::write_volatile((big + off) as *mut u64, off ^ 0xdead);
        }
        for off in [0u64, 4096, 32 << 20, (64 << 20) - 8] {
            check!(n, core::ptr::read_volatile((big + off) as *const u64) == off ^ 0xdead, "mmap page at +{:#x}", off);
        }
    }
    // Częściowe munmap (środek), reszta działa.
    check!(n, munmap(big + (16 << 20), 16 << 20) == 0, "partial munmap");
    unsafe {
        check!(n, core::ptr::read_volatile(big as *const u64) == 0xdead, "rest of the region after partial munmap");
    }
    check!(n, munmap(big, 64 << 20) == 0, "munmap all");
    check!(n, mmap(0, PROT_READ).is_err() && munmap(big + 1, 4096) == -22, "bad mmap / munmap arguments");
    check!(n, mmap(16 << 30, PROT_READ | PROT_WRITE).is_err(), "16 GiB mmap must fail (limit)");
    // Długości bliskie 2^64: błąd, nie przepełnienie przy zaokrąglaniu (jądro z overflow-checks).
    check!(n, mmap(u64::MAX, PROT_READ).is_err() && mmap(u64::MAX - 4094, PROT_READ).is_err(), "mmap near 2^64 must fail");
    check!(n, munmap(0x4000_0000_0000 - 4096, u64::MAX) == -22 && munmap(big, u64::MAX - 4094) == -22, "munmap near 2^64 must fail");

    // 3. Kernel kopiuje do niedotkniętych stron (read do świeżego bufora).
    let buf = mmap(8192, PROT_READ | PROT_WRITE).unwrap_or(0);
    let fd = open("/bin/hello", O_READ);
    let r = read(fd as u64, unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, 8192) });
    close(fd as u64);
    check!(n, r == 8192 && unsafe { *(buf as *const [u8; 4]) } == *b"\x7fELF", "read into untouched pages: {}", r);
    munmap(buf, 8192);

    // 4. Alokator: 4 MiB Vec (mmap), dużo małych bloków (brk), zwalnianie.
    let mut v: Vec<u8> = vec![0u8; 4 << 20];
    for (i, b) in v.iter_mut().enumerate().step_by(4096) {
        *b = (i / 4096) as u8;
    }
    check!(n, v.iter().step_by(4096).enumerate().all(|(i, b)| *b == i as u8), "4 MiB Vec");
    drop(v);
    let mut small: Vec<Vec<u64>> = Vec::new();
    for i in 0..20000u64 {
        small.push(vec![i; 8]);
    }
    check!(n, small.iter().enumerate().all(|(i, x)| x[7] == i as u64), "20000 small allocations");
    drop(small);
    let mut grow: Vec<u64> = Vec::new();
    for i in 0..300_000u64 {
        grow.push(i);
    }
    check!(n, grow[299_999] == 299_999 && grow.len() == 300_000, "Vec growing to 2.4 MiB");

    // 5. Stos rośnie: ~1 MiB rekurencji (start: 16 KiB).
    let _ = deep(256);
    n += 1;

    // 6. Dzieci: dostęp po munmap i przepełnienie stosu kończą tylko dziecko.
    for (mode, want) in [("unmapped", 14u64), ("stack", 14)] {
        let pid = spawn("/bin/memtest", &["memtest", mode], 0, STDIO);
        let st = wait(pid as u64, 0);
        check!(n, matches!(st, Ok((_, s)) if s == STATUS_SIGNALED | want), "memtest {}: {:?}", mode, st);
    }

    println!("memtest: {} checks OK", n);
    0
}
