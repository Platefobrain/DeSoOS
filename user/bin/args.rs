// Prints its arguments (argc/argv from the process stack).
#![no_std]
#![no_main]

#[macro_use]
#[allow(unused_imports)]
extern crate libdeso;
#[allow(unused_imports)]
use libdeso as deso;

entry!(main);

fn main(args: deso::Args) -> i32 {
    println!("argc = {}", args.len());
    for (i, a) in args.iter().enumerate() {
        println!("argv[{}] = {}", i, a);
    }
    0
}
