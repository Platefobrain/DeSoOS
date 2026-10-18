// sleep <ms> – waits (Ctrl+C interrupts).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

entry!(main);

fn main(args: desoos::Args) -> i32 {
    let Some(ms) = args.get(1).and_then(|a| a.parse::<u64>().ok()) else {
        eprintln!("usage: sleep <ms>");
        return 2;
    };
    desoos::sleep_ms(ms);
    0
}
