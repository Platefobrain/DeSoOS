// random – n random bytes (default 32, at most 65536) from the kernel's generator
// (`getrandom`), printed in hex on one line.
//
//   random        32 bytes
//   random 16     16 bytes
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

entry!(main);

const MAX: usize = 65536;
static mut BUF: [u8; MAX] = [0; MAX];

fn main(args: desoos::Args) -> i32 {
    let n = match args.get(1) {
        None => 32,
        Some(a) => match a.parse::<usize>() {
            Ok(n) if n <= MAX => n,
            _ => {
                println!("random: give a number of bytes, 0 to {}", MAX);
                return 2;
            }
        },
    };
    // SAFETY: single-threaded program; BUF is used only here.
    let all: &mut [u8; MAX] = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
    let buf = &mut all[..n];
    if let Err(e) = desoos::getrandom(buf) {
        println!("random: getrandom failed ({})", e);
        return 1;
    }
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut line = [0u8; 128];
    for chunk in buf.chunks(64) {
        for (i, b) in chunk.iter().enumerate() {
            line[2 * i] = DIGITS[(b >> 4) as usize];
            line[2 * i + 1] = DIGITS[(b & 15) as usize];
        }
        desoos::write(1, &line[..2 * chunk.len()]);
    }
    desoos::write(1, b"\n");
    for b in buf.iter_mut() {
        // SAFETY: valid &mut u8 (random bytes are not left behind).
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    0
}
