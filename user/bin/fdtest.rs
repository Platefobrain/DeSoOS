// File object test – dup, dup2, seek, shared position (also with a
// child after spawn).  Result: "fdtest: N checks OK" and code 0, or a description of
// the first error and code 1.  Started by FILE TEST (self-tests).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const PATH: &str = "/fdtest.tmp";

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("fdtest: FAIL check {}: {}", $n, format_args!($($msg)*));
            unlink(PATH);
            return 1;
        }
    };
}

/// The whole file from the start through a descriptor (the position stays at the end).
fn read_all(fd: u64, buf: &mut [u8]) -> usize {
    seek(fd, 0, SEEK_SET);
    let mut n = 0;
    loop {
        let r = read(fd, &mut buf[n..]);
        if r <= 0 {
            return n;
        }
        n += r as usize;
    }
}

fn main(_args: Args) -> i32 {
    let mut n = 0;
    let mut buf = [0u8; 256];
    unlink(PATH);

    // 1. dup: shared position.
    let fd = open(PATH, O_READ | O_WRITE | O_CREATE | O_TRUNC);
    check!(n, fd >= 3, "open: {}", strerror(fd));
    let fd = fd as u64;
    let d = dup(fd);
    check!(n, d >= 0 && d as u64 != fd, "dup: {}", d);
    let d = d as u64;
    check!(n, write(fd, b"hello") == 5, "write via fd");
    check!(n, write(d, b" world") == 6, "write via dup");
    check!(n, seek(fd, 0, SEEK_CUR) == 11, "shared position: {}", seek(fd, 0, SEEK_CUR));
    let len = read_all(d, &mut buf);
    check!(n, &buf[..len] == b"hello world", "content {:?}", core::str::from_utf8(&buf[..len]));

    // 2. seek: SET / CUR / END, errors.
    check!(n, seek(fd, 0, SEEK_END) == 11, "seek end");
    check!(n, seek(fd, -5, SEEK_CUR) == 6, "seek cur -5");
    let r = read(d, &mut buf[..5]);
    check!(n, r == 5 && &buf[..5] == b"world", "read after seek: {}", r);
    check!(n, seek(fd, -1, SEEK_SET) == ERROR_INVALID_ARGUMENT, "negative seek must be ERROR_INVALID_ARGUMENT");
    check!(n, seek(fd, 0, 7) == ERROR_INVALID_ARGUMENT, "bad whence must be ERROR_INVALID_ARGUMENT");
    check!(n, seek(0, 0, SEEK_SET) == ERROR_NOT_SEEKABLE, "seek on console must be ERROR_NOT_SEEKABLE: {}", seek(0, 0, SEEK_SET));
    check!(n, dup(99) == ERROR_INVALID_HANDLE && seek(99, 0, SEEK_SET) == ERROR_INVALID_HANDLE, "bad fd must be ERROR_INVALID_HANDLE");

    // 3. dup2: stdout to a file and back.
    let saved = dup(1);
    check!(n, saved >= 0, "dup(1): {}", saved);
    let saved = saved as u64;
    check!(n, dup2(fd, 1) == 1, "dup2(fd, 1)");
    println!("!via-stdout");
    check!(n, dup2(saved, 1) == 1, "dup2(saved, 1)");
    close(saved);
    let len = read_all(fd, &mut buf);
    check!(n, &buf[..len] == b"hello world!via-stdout\n", "after dup2 {:?}", core::str::from_utf8(&buf[..len]));
    check!(n, dup2(fd, fd) == fd as i64, "dup2(fd, fd)");

    // 4. The child gets the same object: it writes from our position, and our
    // position advances by what it wrote.
    let before = seek(fd, 0, SEEK_END);
    let pid = spawn("/bin/hello", &["hello"], 0, fds(0, fd, 2));
    check!(n, pid > 0, "spawn: {}", strerror(pid));
    let r = wait(pid as u64, 0);
    check!(n, matches!(r, Ok((_, 0))), "child status {:?}", r);
    let after = seek(fd, 0, SEEK_CUR);
    let size = stat(PATH).map(|s| s.size as i64).unwrap_or(-1);
    check!(n, after > before && after == size, "position after child {} (before {}, size {})", after, before, size);

    // 5. close: a closed descriptor no longer works, the copy keeps working.
    check!(n, close(fd) == 0 && write(fd, b"x") == ERROR_INVALID_HANDLE, "closed fd must be ERROR_INVALID_HANDLE");
    check!(n, write(d, b"!") == 1, "dup must survive close of the original");
    close(d);
    check!(n, unlink(PATH) == 0, "unlink");

    println!("fdtest: {} checks OK", n);
    0
}
