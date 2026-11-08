// certtest – DeSoTLS in user space (the kernel CERT TEST runs it).
//
//   certtest          every DeSoTLS test (common/desotls/tests.rs) and the real chains
//                     against /etc/certs/roots: "certtest: N checks OK (DeSoTLS x.y.z);
//                     store <tag>: A anchors, U usable, sha256 <hex>"
//   certtest seal     tries to change the sealed CA store every way a program can – every
//                     attempt must fail and the file must stay the same: "certtest seal: K
//                     attempts refused, sha256 <hex>"
//   certtest clock    "certtest clock: <secs> <status> <build epoch>" (syscall 59)
//
// A failure prints "certtest: FAIL ..." and exits with 1.
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;
#[path = "../../common/desotls/mod.rs"]
mod desotls;
#[path = "../../common/desotls/tests.rs"]
mod desotls_tests;

use alloc::vec::Vec;
use desoos::*;

entry!(main);

const ROOTS: &str = "/etc/certs/roots";

fn read_file(path: &str) -> Result<Vec<u8>, i64> {
    let fd = open(path, O_READ);
    if fd < 0 {
        return Err(fd);
    }
    let mut v = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = read(fd as u64, &mut buf);
        if n <= 0 {
            close(fd as u64);
            return if n < 0 { Err(n) } else { Ok(v) };
        }
        v.extend_from_slice(&buf[..n as usize]);
    }
}

fn hex32(d: &[u8; 32]) -> [u8; 64] {
    let mut t = [0u8; 64];
    let _ = desocrypto::hex(d, &mut t);
    t
}

fn tests() -> i32 {
    let n = match desotls_tests::run() {
        Ok(n) => n,
        Err(f) => {
            println!("certtest: FAIL {} case {}", f.group, f.case);
            return 1;
        }
    };
    let data = match read_file(ROOTS) {
        Ok(d) => d,
        Err(e) => {
            println!("certtest: FAIL cannot read {}: {}", ROOTS, strerror(e));
            return 1;
        }
    };
    let (anchors, usable) = match desotls_tests::real_store(&data) {
        Ok(x) => x,
        Err(f) => {
            println!("certtest: FAIL {} case {}", f.group, f.case);
            return 1;
        }
    };
    let tag = desotls::roots::Roots::parse(&data).map(|r| r.nss_tag).unwrap_or("?");
    let h = hex32(&desocrypto::sha256::sha256(&data));
    println!(
        "certtest: {} checks OK (DeSoTLS {}); store {}: {} anchors, {} usable, sha256 {}",
        n,
        desotls::VERSION,
        tag,
        anchors,
        usable,
        core::str::from_utf8(&h).unwrap_or("")
    );
    0
}

/// Every way a program could change the store; each must fail (most with
/// ERROR_NOT_PERMITTED – the ones through ".." above a directory handle with
/// ERROR_ACCESS_DENIED first).
fn seal() -> i32 {
    let before = match read_file(ROOTS) {
        Ok(d) => desocrypto::sha256::sha256(&d),
        Err(e) => {
            println!("certtest: FAIL cannot read {}: {}", ROOTS, strerror(e));
            return 1;
        }
    };
    let mut refused = 0;
    let mut fail = |what: &str, r: i64, want: i64| -> bool {
        if r >= 0 {
            // A handle that opened must not stay open.
            close(r as u64);
            println!("certtest: FAIL {}: allowed", what);
            return false;
        }
        if r != want {
            println!("certtest: FAIL {}: {} (expected {})", what, error_name(r), error_name(want));
            return false;
        }
        refused += 1;
        true
    };
    let np = ERROR_NOT_PERMITTED;
    let mut ok = true;
    // Opening for writing, every way.
    ok &= fail("open write", open(ROOTS, O_WRITE), np);
    ok &= fail("open read+write", open(ROOTS, O_READ | O_WRITE), np);
    ok &= fail("open truncate", open(ROOTS, O_WRITE | O_TRUNC), np);
    ok &= fail("open create (exists)", open(ROOTS, O_WRITE | O_CREATE), np);
    ok &= fail("open append", open(ROOTS, O_WRITE | O_APPEND), np);
    // Removing the file, the directory, /etc.
    ok &= fail("unlink roots", unlink(ROOTS), np);
    ok &= fail("unlink /etc/certs", unlink("/etc/certs"), np);
    ok &= fail("unlink /etc", unlink("/etc"), np);
    // New entries in the sealed directories.
    ok &= fail("mkdir /etc/certs/x", mkdir("/etc/certs/x"), np);
    ok &= fail("create /etc/certs/extra", open("/etc/certs/extra", O_WRITE | O_CREATE), np);
    ok &= fail("mkdir /etc/x", mkdir("/etc/x"), np);
    ok &= fail("create /etc/extra", open("/etc/extra", O_WRITE | O_CREATE), np);
    // Relative paths and "..".
    let _ = chdir("/etc/certs");
    ok &= fail("relative unlink", unlink("roots"), np);
    ok &= fail("relative open write", open("roots", O_WRITE | O_TRUNC), np);
    let _ = chdir("/etc/services");
    ok &= fail("unlink ../certs/roots", unlink("../certs/roots"), np);
    ok &= fail("open ../certs/./roots", open("../certs/./roots", O_WRITE), np);
    let _ = chdir("/");
    // Through directory handles (openat / unlinkat / mkdirat).
    let d = dir_open("/etc/certs", O_READ | O_WRITE);
    if d < 0 {
        println!("certtest: FAIL dir_open /etc/certs: {}", error_name(d));
        return 1;
    }
    ok &= fail("unlinkat roots", unlinkat(d as u64, "roots"), np);
    ok &= fail("openat roots write", openat(d as u64, "roots", O_WRITE), np);
    ok &= fail("openat create", openat(d as u64, "new", O_WRITE | O_CREATE), np);
    ok &= fail("mkdirat", mkdirat(d as u64, "x"), np);
    close(d as u64);
    let s = dir_open("/etc/services", O_READ | O_WRITE);
    if s >= 0 {
        ok &= fail("unlinkat ../certs/roots", unlinkat(s as u64, "../certs/roots"), ERROR_ACCESS_DENIED);
        close(s as u64);
    }
    // The seal is not wider than it should be: /etc/services stays writable.
    let f = open("/etc/services/zz-certtest.tmp", O_WRITE | O_CREATE);
    if f < 0 || write(f as u64, b"x") != 1 {
        println!("certtest: FAIL /etc/services is not writable any more: {}", error_name(f));
        return 1;
    }
    close(f as u64);
    if unlink("/etc/services/zz-certtest.tmp") < 0 {
        println!("certtest: FAIL cannot remove /etc/services/zz-certtest.tmp");
        return 1;
    }
    // Still readable and unchanged.
    let after = match read_file(ROOTS) {
        Ok(d) => desocrypto::sha256::sha256(&d),
        Err(e) => {
            println!("certtest: FAIL {} unreadable after the attempts: {}", ROOTS, strerror(e));
            return 1;
        }
    };
    if after != before {
        println!("certtest: FAIL {} changed", ROOTS);
        return 1;
    }
    if !ok {
        return 1;
    }
    let h = hex32(&after);
    println!("certtest seal: {} attempts refused, sha256 {}", refused, core::str::from_utf8(&h).unwrap_or(""));
    0
}

fn main(args: Args) -> i32 {
    match args.get(1) {
        None => tests(),
        Some("seal") => seal(),
        Some("clock") => match time_unix() {
            Ok(c) => {
                println!("certtest clock: {} {} {}", c.secs, c.status, c.build_epoch);
                0
            }
            Err(e) => {
                println!("certtest: FAIL time: {}", error_name(e));
                1
            }
        },
        Some(_) => {
            eprintln!("usage: certtest [seal | clock]");
            2
        }
    }
}
