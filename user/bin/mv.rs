// mv <source> <target> – moves a file (copy + delete; also between / and /disk).
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../lib/deso.rs"]
#[macro_use]
mod deso;

#[path = "../lib/copy.rs"]
mod copy;

entry!(main);

fn main(args: deso::Args) -> i32 {
    let (Some(src), Some(dst), None) = (args.get(1), args.get(2), args.get(3)) else {
        eprintln!("usage: mv <src> <dst>   (dst may be a directory)");
        return 2;
    };
    match deso::stat(src) {
        Ok(s) if s.is_dir => {
            eprintln!("mv: {}: moving directories is not supported yet", src);
            return 1;
        }
        Err(e) => {
            eprintln!("mv: {}: {}", src, deso::strerror(e));
            return 1;
        }
        _ => {}
    }
    if let Err(e) = copy::copy_file(src, dst) {
        eprintln!("mv: {}", e);
        return 1;
    }
    let r = deso::unlink(src);
    if r < 0 {
        eprintln!("mv: copied, but cannot remove {}: {}", src, deso::strerror(r));
        return 1;
    }
    0
}
