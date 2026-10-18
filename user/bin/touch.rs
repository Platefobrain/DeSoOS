// touch <file>... – creates empty files (existing ones are left unchanged).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::{O_CREATE, O_WRITE, close, open, strerror};

entry!(main);

fn main(args: desoos::Args) -> i32 {
    if args.len() < 2 {
        eprintln!("usage: touch <file>...");
        return 2;
    }
    let mut status = 0;
    for path in args.iter().skip(1) {
        let fd = open(path, O_WRITE | O_CREATE);
        if fd < 0 {
            eprintln!("touch: {}: {}", path, strerror(fd));
            status = 1;
        } else {
            close(fd as u64);
        }
    }
    status
}
