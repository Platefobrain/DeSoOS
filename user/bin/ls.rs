// ls [path...] – directory contents (directories with a trailing '/').
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use alloc::vec;
use alloc::vec::Vec;
use desoos::{close, dir_for_listing, readdir_part, stat, strerror, DIR_END};

entry!(main);

fn human(n: u64) -> alloc::string::String {
    if n >= 1024 * 1024 {
        alloc::format!("{}.{} MiB", n / (1024 * 1024), n % (1024 * 1024) * 10 / (1024 * 1024))
    } else if n >= 1024 {
        alloc::format!("{}.{} KiB", n / 1024, n % 1024 * 10 / 1024)
    } else {
        alloc::format!("{} B", n)
    }
}

fn list(path: &str, header: bool) -> i32 {
    match stat(path) {
        Ok(s) if !s.is_dir => {
            println!("{:>10}  {}", human(s.size), path);
            return 0;
        }
        Err(e) => {
            eprintln!("ls: {}: {}", path, strerror(e));
            return 1;
        }
        _ => {}
    }
    // The directory in parts (readdir_part): one part = sorted as before; a larger
    // directory is shown part by part in the file system's order.
    let (dir, rel, owned) = match dir_for_listing(path) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("ls: {}: {}", path, strerror(e));
            return 1;
        }
    };
    let mut buf = vec![0u8; 4096];
    let mut cursor = 0u64;
    let mut first = true;
    let mut status = 0;
    let mut count = 0usize;
    if header {
        println!("{}:", path);
    }
    while cursor != DIR_END {
        let n = readdir_part(dir, rel, &mut buf, &mut cursor);
        if n < 0 {
            eprintln!("ls: {}: {}", path, strerror(n));
            status = 1;
            break;
        }
        let text = core::str::from_utf8(&buf[..n as usize]).unwrap_or("");
        let mut entries: Vec<(bool, u64, &str)> = text
            .lines()
            .filter_map(|l| {
                let mut p = l.splitn(3, '\t');
                let kind = p.next()?;
                let size = p.next()?.parse().unwrap_or(0);
                Some((kind == "d", size, p.next()?))
            })
            .collect();
        if first && cursor == DIR_END {
            // Directories first, then alphabetically.
            entries.sort_by(|a, b| b.0.cmp(&a.0).then(a.2.cmp(b.2)));
        } else if first {
            println!("(large directory - in the file system's order)");
        }
        first = false;
        for (d, size, name) in &entries {
            if *d {
                println!("{:>10}  \x1b[1;34m{}/\x1b[0m", "<dir>", name);
            } else {
                println!("{:>10}  {}", human(*size), name);
            }
        }
        count += entries.len();
    }
    if owned {
        close(dir);
    }
    if count == 0 && status == 0 {
        println!("(empty)");
    }
    status
}

fn main(args: desoos::Args) -> i32 {
    if args.len() < 2 {
        return list(".", false);
    }
    let many = args.len() > 2;
    let mut status = 0;
    for path in args.iter().skip(1) {
        status |= list(path, many);
    }
    status
}
