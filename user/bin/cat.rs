// M15: cat [plik...] – wypisuje pliki; bez argumentów czyta linie
// z klawiatury aż do Ctrl+D.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::{O_READ, close, open, read, strerror, write};

entry!(main);

fn copy(fd: u64) -> i64 {
    let mut buf = [0u8; 512];
    loop {
        let n = read(fd, &mut buf);
        if n <= 0 {
            return n;
        }
        write(1, &buf[..n as usize]);
    }
}

fn main(args: desoos::Args) -> i32 {
    if args.len() < 2 {
        return if copy(0) < 0 { 1 } else { 0 };
    }
    let mut status = 0;
    for path in args.iter().skip(1) {
        let fd = open(path, O_READ);
        if fd < 0 {
            eprintln!("cat: {}: {}", path, strerror(fd));
            status = 1;
            continue;
        }
        let r = copy(fd as u64);
        close(fd as u64);
        if r < 0 {
            eprintln!("cat: {}: {}", path, strerror(r));
            status = 1;
        }
    }
    status
}
