// mkdir <directory>... – creates directories.
#![no_std]
#![no_main]

#[macro_use]
#[allow(unused_imports)]
extern crate libdeso;
#[allow(unused_imports)]
use libdeso as deso;

entry!(main);

fn main(args: deso::Args) -> i32 {
    if args.len() < 2 {
        eprintln!("usage: mkdir <dir>...");
        return 2;
    }
    let mut status = 0;
    for path in args.iter().skip(1) {
        let r = deso::mkdir(path);
        if r < 0 {
            eprintln!("mkdir: {}: {}", path, deso::strerror(r));
            status = 1;
        }
    }
    status
}
