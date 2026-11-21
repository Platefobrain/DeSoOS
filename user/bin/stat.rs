// stat <path>... – type and size.
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
        eprintln!("usage: stat <path>...");
        return 2;
    }
    let mut status = 0;
    for path in args.iter().skip(1) {
        match deso::stat(path) {
            Ok(s) if s.is_dir => println!("{}: directory", path),
            Ok(s) => println!("{}: file, {} bytes", path, s.size),
            Err(e) => {
                eprintln!("stat: {}: {}", path, deso::strerror(e));
                status = 1;
            }
        }
    }
    status
}
