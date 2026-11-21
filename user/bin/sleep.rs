// sleep <ms> – waits (Ctrl+C interrupts).
#![no_std]
#![no_main]

#[macro_use]
#[allow(unused_imports)]
extern crate libdeso;
#[allow(unused_imports)]
use libdeso as deso;

entry!(main);

fn main(args: deso::Args) -> i32 {
    let Some(ms) = args.get(1).and_then(|a| a.parse::<u64>().ok()) else {
        eprintln!("usage: sleep <ms>");
        return 2;
    };
    deso::sleep_ms(ms);
    0
}
