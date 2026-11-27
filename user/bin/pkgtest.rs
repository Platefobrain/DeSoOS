// pkgtest – desopkg's formats (user/lib/pkgfmt.rs) in user space; the kernel PKG FORMAT TEST
// runs it (V082 stage A).
//
//   pkgtest vectors <file>   the vectors tools/desopkg.py made (build.sh --selftest): every one
//                            judged by pkgfmt.rs must get the verdict and reason the Python tool
//                            gave – "pkgtest: N vectors OK"; system names: user/lib/cmdnames.rs +
//                            /bin of this system, asked live
//   pkgtest etc              /etc/desopkg/keys and /etc/desopkg/repo of the image parse:
//                            "pkgtest etc: K keys (<ids>), repo <url> <repo>/<channel>/<arch>"
//   pkgtest elf              every program in /bin accepted by common/elf.rs `check_program` –
//                            the rules desopkg checks a package's programs with are the kernel's
//                            own: "pkgtest elf: N programs accepted, ABI 1.0"
//
// A failure prints "pkgtest: FAIL ..." and exits with 1.
#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
#[allow(unused_imports)]
extern crate libdeso;
#[allow(unused_imports)]
use libdeso as deso;

#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;
#[path = "../../common/elf.rs"]
mod elf;
#[path = "../lib/cmdnames.rs"]
mod cmdnames;
#[path = "../lib/pkgfmt.rs"]
mod pkgfmt;
#[path = "../lib/pkgvec.rs"]
mod pkgvec;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use deso::{ERROR_BUFFER_TOO_SMALL, O_READ, close, open, read, strerror};

entry!(main);

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    let fd = open(path, O_READ);
    if fd < 0 {
        return Err(format!("{}: {}", path, strerror(fd)));
    }
    let mut v = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = read(fd as u64, &mut buf);
        if n < 0 {
            close(fd as u64);
            return Err(format!("{}: {}", path, strerror(n)));
        }
        if n == 0 {
            close(fd as u64);
            return Ok(v);
        }
        v.extend_from_slice(&buf[..n as usize]);
    }
}

/// File names in a directory (readdir: "kind\tsize\tname" lines).
fn dir_files(dir: &str) -> Vec<String> {
    let mut buf = vec![0u8; 4096];
    loop {
        let n = deso::readdir(dir, &mut buf);
        if n == ERROR_BUFFER_TOO_SMALL && buf.len() < 256 * 1024 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if n < 0 {
            return Vec::new();
        }
        let text = core::str::from_utf8(&buf[..n as usize]).unwrap_or("");
        return text
            .lines()
            .filter_map(|l| {
                let mut parts = l.splitn(3, '\t');
                let kind = parts.next()?;
                let _size = parts.next()?;
                let name = parts.next()?;
                if kind == "f" { Some(String::from(name)) } else { None }
            })
            .collect();
    }
}

/// The shell's rule (user/bin/sh.rs `system_name`): the lists + /bin/<name> exists.
fn system_name(name: &str) -> bool {
    cmdnames::system_name(name, &|n| deso::stat(&format!("/bin/{}", n)).is_ok())
}

/// Every system name this side knows: the lists + the files of /bin, sorted, without repeats.
fn system_names() -> Vec<String> {
    let mut v = dir_files("/bin");
    v.extend(cmdnames::BUILTINS.iter().map(|(n, _)| String::from(*n)));
    for l in [cmdnames::SYSCTL_BUILTINS, cmdnames::INFO_COMMANDS, cmdnames::KERNEL_ONLY] {
        v.extend(l.iter().map(|n| String::from(*n)));
    }
    v.sort();
    v.dedup();
    v
}

fn vectors(path: &str) -> i32 {
    let data = match read_file(path) {
        Ok(d) => d,
        Err(e) => {
            println!("pkgtest: FAIL {}", e);
            return 1;
        }
    };
    let names = system_names();
    match pkgvec::run(&data, &system_name, &names) {
        Ok((n, fails)) if fails.is_empty() => {
            println!("pkgtest: {} vectors OK ({} system names)", n, names.len());
            0
        }
        Ok((n, fails)) => {
            for f in fails.iter().take(20) {
                println!("pkgtest: FAIL {}", f);
            }
            println!("pkgtest: FAIL {} of {} vectors differ from tools/desopkg.py", fails.len(), n);
            1
        }
        Err(e) => {
            println!("pkgtest: FAIL bad vector file: {}", e);
            1
        }
    }
}

fn etc() -> i32 {
    let keys = match read_file("/etc/desopkg/keys").map(|b| pkgfmt::parse_keys(&b)) {
        Ok(Ok(k)) => k,
        Ok(Err(r)) => {
            println!("pkgtest: FAIL /etc/desopkg/keys refused: {}", r);
            return 1;
        }
        Err(e) => {
            println!("pkgtest: FAIL {}", e);
            return 1;
        }
    };
    let repo = match read_file("/etc/desopkg/repo").map(|b| pkgfmt::parse_repo_config(&b)) {
        Ok(Ok(r)) => r,
        Ok(Err(r)) => {
            println!("pkgtest: FAIL /etc/desopkg/repo refused: {}", r);
            return 1;
        }
        Err(e) => {
            println!("pkgtest: FAIL {}", e);
            return 1;
        }
    };
    let ids: Vec<&str> = keys.iter().map(|k| k.keyid.as_str()).collect();
    println!("pkgtest etc: {} keys ({}), repo {} {}/{}/{}", keys.len(), ids.join(","), repo.url, repo.repo, repo.channel, repo.arch);
    0
}

fn elf_all() -> i32 {
    let mut n = 0;
    for name in dir_files("/bin") {
        let path = format!("/bin/{}", name);
        let b = match read_file(&path) {
            Ok(b) => b,
            Err(e) => {
                println!("pkgtest: FAIL {}", e);
                return 1;
            }
        };
        match elf::check_program_bytes(&b, pkgfmt::SYSTEM_ABI) {
            Ok((_, abi)) if abi == pkgfmt::SYSTEM_ABI => n += 1,
            Ok((_, abi)) => {
                println!("pkgtest: FAIL {}: ABI {}.{}", path, abi.0, abi.1);
                return 1;
            }
            Err(e) => {
                println!("pkgtest: FAIL {}: {}", path, e.as_str());
                return 1;
            }
        }
    }
    println!("pkgtest elf: {} programs accepted, ABI {}.{}", n, pkgfmt::SYSTEM_ABI.0, pkgfmt::SYSTEM_ABI.1);
    if n == 0 { 1 } else { 0 }
}

fn main(args: deso::Args) -> i32 {
    let a: Vec<&str> = args.iter().collect();
    match a.as_slice() {
        [_, "vectors", path] => vectors(path),
        [_, "etc"] => etc(),
        [_, "elf"] => elf_all(),
        _ => {
            eprintln!("usage: pkgtest vectors <file> | etc | elf");
            1
        }
    }
}
