// A program for DeSo OS – the SDK's template (sdk/deso-build.sh new DIR copies it).
// Build: deso-build.sh build main.rs; run: copy build/<name> to /disk/bin on DeSo OS and type
// its name.  The library: libdeso (sdk/libdeso; what it promises: docs/abi/README.md).
#![no_std]
#![no_main]

#[macro_use]
extern crate libdeso;
use libdeso as deso;

entry!(main);

fn main(args: deso::Args) -> i32 {
    println!(
        "Hello from {}, built with the DeSo OS SDK (ABI {}.{}), pid {}",
        args.get(0).unwrap_or("?"),
        deso::ABI_MAJOR,
        deso::ABI_MINOR,
        deso::getpid()
    );
    let mut n = 0;
    for a in args.iter().skip(1) {
        n += 1;
        println!("  argument {}: {}", n, a);
    }
    0
}
