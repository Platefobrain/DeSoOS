// The first Rust program loaded as an ELF file (/bin/hello).
#![no_std]
#![no_main]

#[macro_use]
#[allow(unused_imports)]
extern crate libdeso;
#[allow(unused_imports)]
use libdeso as deso;

entry!(main);

fn main(_args: deso::Args) -> i32 {
    println!("Hello from an ELF program! (pid {})", deso::getpid());
    0
}
