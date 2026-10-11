// M15: pierwszy program w Ruście ładowany jako plik ELF (/bin/hello).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

entry!(main);

fn main(_args: desoos::Args) -> i32 {
    println!("Hello from an ELF program! (pid {})", desoos::getpid());
    0
}
