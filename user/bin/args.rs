// M15: wypisuje swoje argumenty (argc/argv ze stosu procesu).
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
