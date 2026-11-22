// libdeso – the DeSo OS program library: the system calls, handles, files, channels, services,
// time and output for programs (the libc counterpart).  Version = the ABI it is built for (1.0.x);
// its constants come only from `abi` (generated from abi/abi.toml by tools/abigen.py), so a
// program built with it uses exactly the numbers the system promises (docs/abi/README.md).
//
// A program:
//     #![no_std]
//     #![no_main]
//     #[macro_use]
//     extern crate libdeso;
//     use libdeso as deso;
//     entry!(main);
//     fn main(args: deso::Args) -> i32 { println!("..."); 0 }
// built with `--extern libdeso=...` and linked with link.ld (static ELF at 0x400000, the ABI
// note in its own PT_NOTE – the loader refuses a program built for an ABI it does not give).
//
// _start (the kernel jumps there with RSP pointing at argc, argv[], NULL, envp NULL, auxv
// AT_NULL – the SysV layout) -> main(args) -> exit(code).  A program that wants Vec / String
// writes `extern crate alloc;` – the allocator (sys) gets memory through brk / mmap.
//
// Modules (stable, ABI 1.0): sys, errors, handles, fs, chan, svc, net, time, dev; everything
// is also at the crate root (`deso::open`, `deso::ERROR_NOT_FOUND`).  `unstable` (only with
// --cfg feature="unstable") makes no compatibility promise.
#![no_std]
#![allow(dead_code)]

pub mod abi;
pub use abi::*;

pub mod sys;
pub use sys::*;
pub mod errors;
pub use errors::*;
pub mod handles;
pub use handles::*;
pub mod fs;
pub use fs::*;
pub mod chan;
pub use chan::*;
pub mod svc;
pub use svc::*;
pub mod net;
pub use net::*;
pub mod time;
pub use time::*;
pub mod dev;
pub use dev::*;

#[cfg(feature = "unstable")]
pub mod unstable;
