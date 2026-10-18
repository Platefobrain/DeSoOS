// stat <path>... – type and size.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

entry!(main);

fn main(args: desoos::Args) -> i32 {
    if args.len() < 2 {
        eprintln!("usage: stat <path>...");
        return 2;
    }
    let mut status = 0;
    for path in args.iter().skip(1) {
        match desoos::stat(path) {
            Ok(s) if s.is_dir => println!("{}: directory", path),
            Ok(s) => println!("{}: file, {} bytes", path, s.size),
            Err(e) => {
                eprintln!("stat: {}: {}", path, desoos::strerror(e));
                status = 1;
            }
        }
    }
    status
}
