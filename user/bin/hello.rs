// The first Rust program loaded as an ELF file (/bin/hello).
#![no_std]
#![no_main]

#[path = "../lib/deso.rs"]
#[macro_use]
mod deso;

entry!(main);

fn main(_args: deso::Args) -> i32 {
    println!("Hello from an ELF program! (pid {})", deso::getpid());
    0
}
