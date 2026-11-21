// cp <source> <dest> – copies a file (dest may be a directory).
#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
#[allow(unused_imports)]
extern crate libdeso;
#[allow(unused_imports)]
use libdeso as deso;

#[path = "../lib/copy.rs"]
mod copy;

entry!(main);

fn main(args: deso::Args) -> i32 {
    let (Some(src), Some(dst), None) = (args.get(1), args.get(2), args.get(3)) else {
        eprintln!("usage: cp <src> <dst>   (dst may be a directory)");
        return 2;
    };
    match copy::copy_file(src, dst) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("cp: {}", e);
            1
        }
    }
}
