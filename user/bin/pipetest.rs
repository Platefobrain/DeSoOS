// Pipe test – read / write, end of data, EPIPE, data larger
// than the buffer (64 KiB) through `cat` in a child, child output through a pipe.
// Result: "pipetest: N checks OK" and exit code 0, or an error description and code 1.
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use alloc::vec::Vec;
use desoos::*;

entry!(main);

const PATH: &str = "/pipetest.tmp";
const BIG: usize = 200 * 1024;

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("pipetest: FAIL check {}: {}", $n, format_args!($($msg)*));
            unlink(PATH);
            return 1;
        }
    };
}

/// Everything from the descriptor until end of data.
fn drain(fd: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let r = read(fd, &mut buf);
        if r <= 0 {
            return out;
        }
        out.extend_from_slice(&buf[..r as usize]);
    }
}

fn main(_args: Args) -> i32 {
    let mut n = 0;
    let mut buf = [0u8; 64];

    // 1. Write and read in a single process, end of data after close.
    let p = pipe();
    check!(n, p.is_ok(), "pipe: {:?}", p);
    let (r, w) = p.unwrap();
    check!(n, write(w, b"abc") == 3, "write");
    let got = read(r, &mut buf);
    check!(n, got == 3 && &buf[..3] == b"abc", "read: {}", got);
    check!(n, read(w, &mut buf) == -9 && write(r, b"x") == -9, "wrong direction must be EBADF");
    check!(n, seek(r, 0, SEEK_SET) == -29, "seek on a pipe must be ESPIPE");
    check!(n, write(w, b"tail") == 4 && close(w) == 0, "write + close");
    let got = read(r, &mut buf);
    check!(n, got == 4, "data written before close must arrive: {}", got);
    check!(n, read(r, &mut buf) == 0, "end of data after the writer closed");
    close(r);

    // 2. Nobody reads: EPIPE.
    let (r, w) = pipe().unwrap();
    close(r);
    check!(n, write(w, b"lost") == -32, "write without readers must be EPIPE");
    close(w);

    // 3. 200 KiB (more than the buffer) through `cat` in a child into a file: the writer
    // waits until cat reads.
    unlink(PATH);
    let out = open(PATH, O_WRITE | O_CREATE | O_TRUNC);
    check!(n, out >= 0, "open: {}", strerror(out));
    let (r, w) = pipe().unwrap();
    let pid = spawn("/bin/cat", &["cat"], 0, fds(r, out as u64, 2));
    check!(n, pid > 0, "spawn cat: {}", strerror(pid));
    close(r);
    close(out as u64);
    // Pattern (i % 251) in chunks – the program heap is still only 256 KiB.
    let mut chunk = [0u8; 4096];
    let mut wrote = 0usize;
    while wrote < BIG {
        let len = chunk.len().min(BIG - wrote);
        for (j, b) in chunk[..len].iter_mut().enumerate() {
            *b = ((wrote + j) % 251) as u8;
        }
        let r = write(w, &chunk[..len]);
        if r <= 0 {
            break;
        }
        wrote += r as usize;
    }
    check!(n, wrote == BIG, "write {} KiB: {}", BIG / 1024, wrote);
    close(w);
    let st = wait(pid as u64, 0);
    check!(n, matches!(st, Ok((_, 0))), "cat status {:?}", st);
    let f = open(PATH, O_READ) as u64;
    let mut pos = 0usize;
    let mut same = true;
    loop {
        let r = read(f, &mut chunk);
        if r <= 0 {
            break;
        }
        for (j, b) in chunk[..r as usize].iter().enumerate() {
            same &= *b == ((pos + j) % 251) as u8;
        }
        pos += r as usize;
    }
    close(f);
    check!(n, pos == BIG && same, "file after cat: {} bytes, content ok {}", pos, same);

    // 4. Child output through a pipe: primes 100 | (this process).
    let (r, w) = pipe().unwrap();
    let pid = spawn("/bin/primes", &["primes", "100"], 0, fds(0, w, 2));
    check!(n, pid > 0, "spawn primes: {}", strerror(pid));
    close(w);
    let text = drain(r);
    close(r);
    let st = wait(pid as u64, 0);
    let s = core::str::from_utf8(&text).unwrap_or("");
    check!(n, matches!(st, Ok((_, 0))) && s.contains("25 primes below 100"), "primes via pipe: {:?}", s);

    // 5. Reader waits for data from the child (sleep, then write).
    let (r, w) = pipe().unwrap();
    let t0 = uptime_ms();
    let pid = spawn("/bin/sh", &["sh", "-c", "sleep", "100"], 0, fds(0, w, 2));
    check!(n, pid > 0, "spawn sh");
    close(w);
    let got = read(r, &mut buf);
    let dt = uptime_ms() - t0;
    close(r);
    let _ = wait(pid as u64, 0);
    check!(n, got == 0 && dt >= 90, "reader must block until the writer exits: {} after {} ms", got, dt);

    unlink(PATH);
    println!("pipetest: {} checks OK", n);
    0
}

