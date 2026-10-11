// M16: kill <pid>... – kończy procesy (init jest chroniony).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::{kill, strerror};

entry!(main);

fn main(args: desoos::Args) -> i32 {
    if args.len() < 2 {
        eprintln!("usage: kill <pid>...   (pids: see 'ps')");
        return 2;
    }
    let mut status = 0;
    for a in args.iter().skip(1) {
        let Ok(pid) = a.parse::<u64>() else {
            eprintln!("kill: {}: not a number", a);
            status = 1;
            continue;
        };
        let r = kill(pid);
        if r < 0 {
            eprintln!("kill: {}: {}", pid, strerror(r));
            status = 1;
        }
    }
    status
}
