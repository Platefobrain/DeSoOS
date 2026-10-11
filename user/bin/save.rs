// M15: save <plik> <słowa...> – zapisuje słowa (jedna linia) do pliku.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::{O_CREATE, O_TRUNC, O_WRITE, close, open, strerror, write};

entry!(main);

fn main(args: desoos::Args) -> i32 {
    let Some(path) = args.get(1) else {
        eprintln!("usage: save <file> <words...>");
        return 2;
    };
    let fd = open(path, O_WRITE | O_CREATE | O_TRUNC);
    if fd < 0 {
        eprintln!("save: {}: {}", path, strerror(fd));
        return 1;
    }
    let fd = fd as u64;
    for (i, word) in args.iter().skip(2).enumerate() {
        if i > 0 {
            write(fd, b" ");
        }
        write(fd, word.as_bytes());
    }
    write(fd, b"\n");
    close(fd);
    println!("saved {}", path);
    0
}
