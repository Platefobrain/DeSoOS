// Directory handles (dir_open, openat, readdirat, statat, mkdirat, unlinkat):
//   - work inside a directory by relative paths, "sub/../x" stays inside,
//   - every way out is refused: "..", "sub/../..", "./../x", an absolute path,
//     a long chain of "..", the directory itself where a name is needed,
//   - rights: a read-only copy (handle_dup) cannot create, change, remove; a
//     write-only one cannot list or read; a file handle is not a directory,
//   - a sandboxed child (SPAWN_NO_FILES) given only a read-only directory handle
//     reads inside it – directly and through the library's plain `open` /
//     `readdir` / `stat` (relative paths) – and cannot write, climb out, open a
//     directory by path or reach any other file,
//   - dir_open errors: not a directory, no such path, bad flags.
// Result: "dirtest: N checks OK" and code 0, or the first failure and code 1.
// `dirtest child` – the sandboxed child (exit code = the first failed step, 0 = all fine).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const ROOT: &str = "/dirtest";

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("dirtest: FAIL check {}: {}", $n, format_args!($($msg)*));
            cleanup();
            return 1;
        }
    };
}

fn cleanup() {
    unlink("/dirtest/sub/deep.txt");
    unlink("/dirtest/sub");
    unlink("/dirtest/a.txt");
    unlink("/dirtest/new.txt");
    unlink("/dirtest");
    unlink("/dirtest-outside.txt");
}

fn write_file(fd: i64, data: &[u8]) -> bool {
    let ok = fd >= 0 && write(fd as u64, data) == data.len() as i64;
    if fd >= 0 {
        close(fd as u64);
    }
    ok
}

fn read_file(fd: i64, buf: &mut [u8]) -> i64 {
    if fd < 0 {
        return fd;
    }
    let n = read(fd as u64, buf);
    close(fd as u64);
    n
}

/// The sandboxed child: handle 4 = /dirtest, read only.
fn child() -> i32 {
    let d = 4u64;
    if handle_info(d) != Ok((KIND_DIR, R_READ | R_DUP | R_TRANSFER)) {
        return 10;
    }
    let mut b = [0u8; 64];
    // Through the handle.
    if read_file(openat(d, "a.txt", O_READ), &mut b) != 5 || &b[..5] != b"hello" {
        return 11;
    }
    // Through the library's plain calls (relative paths go into the directory).
    if read_file(open("a.txt", O_READ), &mut b) != 5 {
        return 12;
    }
    if read_file(open("sub/deep.txt", O_READ), &mut b) != 4 || &b[..4] != b"deep" {
        return 13;
    }
    let mut list = [0u8; 256];
    let n = readdir("", &mut list);
    let text = if n > 0 { core::str::from_utf8(&list[..n as usize]).unwrap_or("") } else { "" };
    if !text.contains("a.txt") || !text.contains("sub") {
        return 14;
    }
    if !matches!(stat("sub"), Ok(s) if s.is_dir) {
        return 15;
    }
    // No writing (read-only handle), no way out, no other paths.
    if openat(d, "x.txt", O_WRITE | O_CREATE) != ERROR_ACCESS_DENIED || open("x.txt", O_WRITE | O_CREATE) != ERROR_ACCESS_DENIED {
        return 16;
    }
    if mkdirat(d, "m") != ERROR_ACCESS_DENIED || unlinkat(d, "a.txt") != ERROR_ACCESS_DENIED {
        return 17;
    }
    if openat(d, "../dirtest-outside.txt", O_READ) != ERROR_ACCESS_DENIED || open("../dirtest-outside.txt", O_READ) != ERROR_ACCESS_DENIED {
        return 18;
    }
    if open("/dirtest-outside.txt", O_READ) != ERROR_ACCESS_DENIED || open("/dirtest/a.txt", O_READ) != ERROR_ACCESS_DENIED {
        return 19;
    }
    if dir_open("/", O_READ) != ERROR_ACCESS_DENIED {
        return 20;
    }
    0
}

fn main(args: Args) -> i32 {
    if args.get(1) == Some("child") {
        return child();
    }
    let mut n = 0;
    cleanup();
    check!(n, mkdir(ROOT) == 0, "mkdir {}", ROOT);
    check!(n, write_file(open("/dirtest-outside.txt", O_WRITE | O_CREATE), b"secret"), "outside file");

    // 1. dir_open: the handle, its kind and rights.
    let d = dir_open(ROOT, O_READ | O_WRITE);
    check!(n, d >= 3, "dir_open: {}", strerror(d));
    let d = d as u64;
    check!(n, handle_info(d) == Ok((KIND_DIR, R_READ | R_WRITE | R_DUP | R_TRANSFER)), "dir handle: {:?}", handle_info(d));
    check!(n, dir_open("/dirtest-outside.txt", O_READ) == ERROR_NOT_DIRECTORY, "dir_open of a file must be ERROR_NOT_DIRECTORY");
    check!(n, dir_open("/no-such-dir", O_READ) == ERROR_NOT_FOUND, "dir_open of nothing must be ERROR_NOT_FOUND");
    check!(n, dir_open(ROOT, 0) == ERROR_INVALID_ARGUMENT && dir_open(ROOT, O_CREATE | O_READ) == ERROR_INVALID_ARGUMENT, "bad dir_open flags");

    // 2. Inside: create, read back, subdirectory, list, stat.
    check!(n, write_file(openat(d, "a.txt", O_WRITE | O_CREATE), b"hello"), "openat create a.txt");
    let mut b = [0u8; 64];
    check!(n, read_file(openat(d, "a.txt", O_READ), &mut b) == 5 && &b[..5] == b"hello", "openat read a.txt");
    check!(n, read_file(open("/dirtest/a.txt", O_READ), &mut b) == 5, "the file is really in /dirtest");
    check!(n, mkdirat(d, "sub") == 0, "mkdirat sub");
    check!(n, write_file(openat(d, "sub/deep.txt", O_WRITE | O_CREATE), b"deep"), "openat sub/deep.txt");
    check!(n, read_file(openat(d, "sub/../a.txt", O_READ), &mut b) == 5, "sub/../a.txt stays inside");
    check!(n, read_file(openat(d, "./sub//deep.txt", O_READ), &mut b) == 4, "./sub//deep.txt");
    let mut list = [0u8; 256];
    let ln = readdirat(d, "", &mut list);
    let text = if ln > 0 { core::str::from_utf8(&list[..ln as usize]).unwrap_or("") } else { "" };
    check!(n, text.contains("a.txt") && text.contains("sub"), "readdirat: {:?}", text);
    check!(n, matches!(statat(d, "a.txt"), Ok(s) if !s.is_dir && s.size == 5), "statat a.txt");
    check!(n, matches!(statat(d, "."), Ok(s) if s.is_dir), "statat . = the directory");

    // 3. Every way out is refused.
    for p in ["..", "../dirtest-outside.txt", "sub/../../dirtest-outside.txt", "./../dirtest-outside.txt", "/dirtest-outside.txt", "/dirtest/a.txt", "../../../../../../.."] {
        check!(n, openat(d, p, O_READ) == ERROR_ACCESS_DENIED, "openat {:?} must be ERROR_ACCESS_DENIED: {}", p, openat(d, p, O_READ));
    }
    check!(n, readdirat(d, "..", &mut list) == ERROR_ACCESS_DENIED && matches!(statat(d, "../dirtest-outside.txt"), Err(ERROR_ACCESS_DENIED)), "readdirat / statat above the directory");
    check!(n, mkdirat(d, "../escape") == ERROR_ACCESS_DENIED && unlinkat(d, "../dirtest-outside.txt") == ERROR_ACCESS_DENIED, "mkdirat / unlinkat above the directory");
    check!(n, stat("/escape").is_err() && stat("/dirtest-outside.txt").is_ok(), "nothing changed outside");
    check!(n, unlinkat(d, "") == ERROR_INVALID_ARGUMENT && unlinkat(d, "sub/..") == ERROR_INVALID_ARGUMENT, "the directory itself cannot be removed through its handle");

    // 4. Rights: read only, write only, a file is not a directory.
    let ro = handle_dup(d, R_READ | R_DUP | R_TRANSFER);
    check!(n, ro >= 0, "handle_dup ro");
    let ro = ro as u64;
    check!(n, openat(ro, "new.txt", O_WRITE | O_CREATE) == ERROR_ACCESS_DENIED, "create through a read-only handle");
    check!(n, openat(ro, "a.txt", O_READ | O_WRITE) == ERROR_ACCESS_DENIED, "open for writing through a read-only handle");
    check!(n, mkdirat(ro, "m") == ERROR_ACCESS_DENIED && unlinkat(ro, "a.txt") == ERROR_ACCESS_DENIED, "mkdirat / unlinkat through a read-only handle");
    check!(n, read_file(openat(ro, "a.txt", O_READ), &mut b) == 5 && readdirat(ro, "", &mut list) > 0, "reading through a read-only handle");
    let wo = handle_dup(d, R_WRITE);
    check!(n, wo >= 0, "handle_dup wo");
    let wo = wo as u64;
    check!(n, readdirat(wo, "", &mut list) == ERROR_ACCESS_DENIED && openat(wo, "a.txt", O_READ) == ERROR_ACCESS_DENIED, "reading through a write-only handle");
    check!(n, write_file(openat(wo, "new.txt", O_WRITE | O_CREATE), b"w"), "creating through a write-only handle");
    check!(n, unlinkat(wo, "new.txt") == 0 && stat("/dirtest/new.txt").is_err(), "unlinkat through a write-only handle");
    close(wo);
    let f = open("/dirtest/a.txt", O_READ);
    check!(n, f >= 0 && openat(f as u64, "a.txt", O_READ) == ERROR_INVALID_HANDLE, "a file handle is not a directory");
    if f >= 0 {
        close(f as u64);
    }
    let up = handle_dup(ro, R_ALL);
    check!(n, up >= 0 && handle_info(up as u64) == Ok((KIND_DIR, R_READ | R_DUP | R_TRANSFER)), "rights do not grow");
    if up >= 0 {
        close(up as u64);
    }

    // 5. A sandboxed child with only the read-only directory.
    let pid = spawn_ex("/bin/dirtest", &["dirtest", "child"], &[(1, 1), (1, 2), (ro, 4)], SPAWN_NO_FILES);
    check!(n, pid > 0, "spawn sandboxed child: {}", strerror(pid));
    let w = wait(pid as u64, 0);
    check!(n, w == Ok((pid as u64, 0)), "sandboxed child failed at step {:?}", w.map(|(_, c)| c));
    close(ro);
    close(d);
    cleanup();
    check!(n, stat(ROOT).is_err(), "cleanup");
    println!(
        "dirtest: {} checks OK (inside a directory by relative paths, 7 ways out refused, read-only / write-only rights, a sandboxed child reads only inside its directory - also through plain open / readdir / stat)",
        n
    );
    0
}
