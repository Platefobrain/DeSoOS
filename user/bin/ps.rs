// M16: ps – lista zadań (procesy i zadania kernela), z rodzicem (PPID).
// M17: kolumna CPU – na którym rdzeniu zadanie działa.
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use alloc::vec;
use desoos::{ERANGE, strerror, tasks};

entry!(main);

fn main(_: desoos::Args) -> i32 {
    let mut buf = vec![0u8; 4096];
    let n = loop {
        let n = tasks(&mut buf);
        if n == ERANGE && buf.len() < 64 * 1024 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        break n;
    };
    if n < 0 {
        eprintln!("ps: {}", strerror(n));
        return 1;
    }
    let me = desoos::getpid();
    println!("  PID  PPID  NAME          MODE    STATE     CPU   CPU ms  SWITCHES");
    let text = core::str::from_utf8(&buf[..n as usize]).unwrap_or("");
    for line in text.lines() {
        let f: alloc::vec::Vec<&str> = line.split('\t').collect();
        if f.len() < 7 {
            continue;
        }
        let ppid = if f[5] == "user" { f[1] } else { "-" };
        // M17: numer CPU ("~3" = nie działa teraz, ostatnio na CPU 3).
        let cpu = f.get(7).copied().unwrap_or("-");
        println!(
            "{:>5} {:>5}  {:<12}  {:<6}  {:<8} {:>3} {:>8}  {:>8}{}",
            f[0], ppid, f[6], f[5], f[2], cpu, f[3], f[4],
            if f[0].parse::<u64>().ok() == Some(me) { "  <- ps" } else { "" }
        );
    }
    0
}
