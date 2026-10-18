// ls [path...] – directory contents (directories with a trailing '/').
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use alloc::vec;
use alloc::vec::Vec;
use desoos::{ERANGE, readdir, stat, strerror};

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
    let mut buf = vec![0u8; 4096];
    let n = loop {
        let n = readdir(path, &mut buf);
        if n == ERANGE && buf.len() < 64 * 1024 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        break n;
    };
    if n < 0 {
        eprintln!("ls: {}: {}", path, strerror(n));
        return 1;
    }
    if header {
        println!("{}:", path);
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
    // Directories first, then alphabetically.
    entries.sort_by(|a, b| b.0.cmp(&a.0).then(a.2.cmp(b.2)));
    for (dir, size, name) in &entries {
        if *dir {
            println!("{:>10}  \x1b[1;34m{}/\x1b[0m", "<dir>", name);
        } else {
            println!("{:>10}  {}", human(*size), name);
        }
    }
    if entries.is_empty() {
        println!("(empty)");
    }
    0
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
