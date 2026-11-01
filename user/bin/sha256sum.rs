// sha256sum [file...] – SHA-256 of each file (DeSoCrypto), one line each:
// "<64 hex digits>  <name>", the same format as on Linux, so results can be
// compared.  Without arguments it hashes standard input ("-").
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;

use desocrypto::sha256::Sha256;
use desoos::{O_READ, close, open, read, strerror};

entry!(main);

/// Hashes everything readable from `fd`; Err(negative error) on a read error.
fn hash_fd(fd: u64) -> Result<[u8; 32], i64> {
    let mut h = Sha256::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = read(fd, &mut buf);
        if n < 0 {
            return Err(n);
        }
        if n == 0 {
            break;
        }
        h.update(&buf[..n as usize]);
    }
    // A file cannot reach 2^61 bytes; report it anyway instead of a wrong sum.
    h.finish().map_err(|_| desoos::ERROR_NO_SPACE)
}

fn show(name: &str, digest: &[u8; 32]) {
    let mut text = [0u8; 64];
    if let Ok(s) = desocrypto::hex(digest, &mut text) {
        println!("{}  {}", s, name);
    }
}

fn main(args: desoos::Args) -> i32 {
    if args.len() < 2 {
        return match hash_fd(0) {
            Ok(d) => {
                show("-", &d);
                0
            }
            Err(e) => {
                eprintln!("sha256sum: -: {}", strerror(e));
                1
            }
        };
    }
    let mut status = 0;
    for path in args.iter().skip(1) {
        let fd = open(path, O_READ);
        if fd < 0 {
            eprintln!("sha256sum: {}: {}", path, strerror(fd));
            status = 1;
            continue;
        }
        let r = hash_fd(fd as u64);
        close(fd as u64);
        match r {
            Ok(d) => show(path, &d),
            Err(e) => {
                eprintln!("sha256sum: {}: {}", path, strerror(e));
                status = 1;
            }
        }
    }
    status
}
