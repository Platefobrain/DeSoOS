// rm <path>... – removes files and empty directories.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

entry!(main);

fn main(args: desoos::Args) -> i32 {
    if args.len() < 2 {
        eprintln!("usage: rm <path>...   (files and empty directories)");
        return 2;
    }
    let mut status = 0;
    for path in args.iter().skip(1) {
        let r = desoos::unlink(path);
        if r < 0 {
            eprintln!("rm: {}: {}", path, desoos::strerror(r));
            status = 1;
        }
    }
    status
}
