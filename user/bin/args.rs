// Prints its arguments (argc/argv from the process stack).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

entry!(main);

fn main(args: desoos::Args) -> i32 {
    println!("argc = {}", args.len());
    for (i, a) in args.iter().enumerate() {
        println!("argv[{}] = {}", i, a);
    }
    0
}
