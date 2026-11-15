// timetest – LKG TEST from a program (the kernel's LKG TEST runs it).
//
//   timetest protect <root>   <root> is a DeSoFS volume holding <root>/.desoos/lkg (the last
//                             known good time).  Tries to change it every way a program can –
//                             open for writing / truncate / create / append, unlink of the file
//                             and the directory, mkdir and create inside, relative paths, "."
//                             and "..", directory handles (openat, unlinkat, mkdirat) – every
//                             attempt must be refused (ERROR_NOT_PERMITTED); the file must stay
//                             readable and the same, and the rest of <root> writable:
//                             "timetest protect: K attempts refused, lkg readable (56 bytes),
//                             <root> writable"
//
// A failure prints "timetest: FAIL ..." and exits with 1.
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use desoos::*;

entry!(main);

fn read_file(path: &str) -> Result<Vec<u8>, i64> {
    let fd = open(path, O_READ);
    if fd < 0 {
        return Err(fd);
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = read(fd as u64, &mut buf);
        if n < 0 {
            close(fd as u64);
            return Err(n);
        }
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    close(fd as u64);
    Ok(out)
}

fn protect(root: &str) -> i32 {
    let dir = format!("{}/.desoos", root);
    let file = format!("{}/.desoos/lkg", root);
    let before = match read_file(&file) {
        Ok(d) => d,
        Err(e) => {
            println!("timetest: FAIL cannot read {}: {}", file, strerror(e));
            return 1;
        }
    };
    let mut refused = 0;
    let mut ok = true;
    let mut fail = |what: &str, r: i64| {
        if r >= 0 {
            close(r as u64);
            println!("timetest: FAIL {}: allowed", what);
            ok = false;
        } else if r != ERROR_NOT_PERMITTED {
            println!("timetest: FAIL {}: {} (expected {})", what, error_name(r), error_name(ERROR_NOT_PERMITTED));
            ok = false;
        } else {
            refused += 1;
        }
    };
    // Opening the file for writing, every way.
    fail("open write", open(&file, O_WRITE));
    fail("open read+write", open(&file, O_READ | O_WRITE));
    fail("open truncate", open(&file, O_WRITE | O_TRUNC));
    fail("open create (exists)", open(&file, O_WRITE | O_CREATE));
    fail("open append", open(&file, O_WRITE | O_APPEND));
    // Removing the file and the directory; new entries inside.
    fail("unlink lkg", unlink(&file));
    fail("unlink .desoos", unlink(&dir));
    fail("mkdir .desoos/x", mkdir(&format!("{}/x", dir)));
    fail("create .desoos/extra", open(&format!("{}/extra", dir), O_WRITE | O_CREATE));
    fail("create .desoos/lkg.new", open(&format!("{}/lkg.new", dir), O_WRITE | O_CREATE));
    fail("mkdir .desoos (exists)", mkdir(&dir));
    // Other spellings of the same node: ".", "..", doubled slashes, relative paths.
    fail("open ./.desoos/./lkg", open(&format!("{}/./.desoos/./lkg", root), O_WRITE));
    fail("unlink //.desoos//lkg", unlink(&format!("{}//.desoos//lkg", root)));
    let sub = format!("{}/timetest-sub", root);
    let _ = mkdir(&sub);
    fail("open sub/../.desoos/lkg", open(&format!("{}/../.desoos/lkg", sub), O_WRITE | O_TRUNC));
    let _ = chdir(&dir);
    fail("relative unlink lkg", unlink("lkg"));
    fail("relative open lkg write", open("lkg", O_WRITE | O_TRUNC));
    fail("relative create here", open("new", O_WRITE | O_CREATE));
    let _ = chdir(&sub);
    fail("unlink ../.desoos/lkg", unlink("../.desoos/lkg"));
    fail("open ../.desoos/lkg write", open("../.desoos/lkg", O_WRITE));
    let _ = chdir(root);
    fail("relative unlink .desoos/lkg", unlink(".desoos/lkg"));
    fail("relative mkdir .desoos/y", mkdir(".desoos/y"));
    let _ = chdir("/");
    // Through directory handles.
    let d = dir_open(&dir, O_READ | O_WRITE);
    if d < 0 {
        println!("timetest: FAIL dir_open {}: {}", dir, error_name(d));
        return 1;
    }
    fail("unlinkat lkg", unlinkat(d as u64, "lkg"));
    fail("openat lkg write", openat(d as u64, "lkg", O_WRITE));
    fail("openat lkg truncate", openat(d as u64, "lkg", O_WRITE | O_TRUNC));
    fail("openat create", openat(d as u64, "new", O_WRITE | O_CREATE));
    fail("mkdirat", mkdirat(d as u64, "x"));
    close(d as u64);
    let r = dir_open(root, O_READ | O_WRITE);
    if r < 0 {
        println!("timetest: FAIL dir_open {}: {}", root, error_name(r));
        return 1;
    }
    fail("unlinkat .desoos/lkg from the root", unlinkat(r as u64, ".desoos/lkg"));
    fail("unlinkat .desoos from the root", unlinkat(r as u64, ".desoos"));
    fail("openat .desoos/lkg write from the root", openat(r as u64, ".desoos/lkg", O_WRITE));
    fail("mkdirat .desoos/z from the root", mkdirat(r as u64, ".desoos/z"));
    close(r as u64);
    // Still readable and the same.
    let after = match read_file(&file) {
        Ok(d) => d,
        Err(e) => {
            println!("timetest: FAIL {} unreadable after the attempts: {}", file, strerror(e));
            return 1;
        }
    };
    if after != before || after.len() != 56 {
        println!("timetest: FAIL {} changed or not 56 bytes ({} bytes)", file, after.len());
        return 1;
    }
    // The protection is not wider than it should be: the rest of the volume is writable,
    // also names that only start like it.
    for p in [format!("{}/timetest-ok", root), format!("{}/.desoosx", root), format!("{}/.desoos", sub)] {
        let is_dir = p.ends_with("/.desoos");
        let made = if is_dir {
            mkdir(&p)
        } else {
            let f = open(&p, O_WRITE | O_CREATE);
            if f >= 0 {
                let w = write(f as u64, b"x");
                close(f as u64);
                if w == 1 { 0 } else { -1 }
            } else {
                f
            }
        };
        if made < 0 || unlink(&p) < 0 {
            println!("timetest: FAIL {} is not writable: {}", p, error_name(made));
            return 1;
        }
    }
    let _ = unlink(&sub);
    if !ok {
        return 1;
    }
    println!("timetest protect: {} attempts refused, lkg readable ({} bytes), {} writable", refused, after.len(), root);
    0
}

fn main(args: Args) -> i32 {
    match (args.get(1), args.get(2)) {
        (Some("protect"), Some(root)) => protect(root),
        _ => {
            let usage: String = String::from("usage: timetest protect <root>");
            println!("{}", usage);
            2
        }
    }
}
