// `desofs` from the user shell (sysctl behind the SYSCTL handle) and busy mounts.
// The kernel starts it with the SYSCTL handle (as init gets it) and a RAM disk <disk>:
//
//   dsfstest refuse <disk> – nothing may change the disk: raw sysctl without the SYSCTL
//     handle (a missing number, the console, a pipe, a directory handle) for format + yes,
//     `/bin/sh` without the handle, a shell started by the shell (children never get it),
//     format / repair without "yes", bad arguments, a bad output handle (missing, no WRITE,
//     not an output) with the right SYSCTL handle.  The kernel then compares the
//     SHA-256 of the whole disk.
//   dsfstest work <disk> – format, info, mount (/desofs), files; unmount refused while
//     something uses the mount and allowed again once it is let go: an open file, an open
//     directory, the current directory of another process (killed, not closed), a file
//     handed to a child; format refused under an open file (the file stays readable);
//     the caller's own current directory does not block, it ends up in "/"; check (refused
//     while mounted, then 0 errors), repair (nothing to repair).
// Result: "dsfstest: N checks OK" and code 0, or the first failure and code 1.
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use alloc::format;
use alloc::string::String;
use desoos::*;

entry!(main);

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("dsfstest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

/// The SYSCTL handle the kernel gave this program (its slot depends on the other handles).
fn find_sysctl() -> Option<u64> {
    (3..8).find(|&h| handle_info(h).map(|(k, _)| k) == Ok(KIND_SYSCTL))
}

/// `sh -c <cmd>`, stdout + stderr into a pipe; `sys`: the SYSCTL handle for the shell (slot 4).
fn sh(cmd: &str, sys: Option<u64>) -> String {
    run_sh(&["sh", "-c", cmd], None, sys)
}

fn run_sh(argv: &[&str], stdin: Option<u64>, sys: Option<u64>) -> String {
    let Ok((r, w)) = pipe() else { return String::from("<no pipe>") };
    let mut map = [(stdin.unwrap_or(0), 0u64), (w, 1), (w, 2), (0, 0)];
    let n = match sys {
        Some(s) => {
            map[3] = (s, 4);
            4
        }
        None => 3,
    };
    let pid = spawn_ex("/bin/sh", argv, &map[..n], 0);
    close(w);
    if pid <= 0 {
        close(r);
        return format!("<spawn {}>", pid);
    }
    let mut out = alloc::vec![0u8; 8192];
    let mut len = 0;
    while len < out.len() {
        let k = read(r, &mut out[len..]);
        if k <= 0 {
            break;
        }
        len += k as usize;
    }
    close(r);
    let _ = wait(pid as u64, 0);
    String::from_utf8_lossy(&out[..len]).into_owned()
}

fn mounted() -> bool {
    stat("/desofs/a").is_ok()
}

fn main(args: Args) -> i32 {
    let mode = args.get(1).unwrap_or("");
    let Some(disk) = args.get(2).and_then(|d| d.parse::<u64>().ok()) else {
        println!("usage: dsfstest refuse|work <disk>");
        return 2;
    };
    let Some(sys) = find_sysctl() else {
        println!("dsfstest: FAIL: started without the SYSCTL handle");
        return 1;
    };
    match mode {
        "refuse" => refuse(sys, disk),
        "work" => work(sys, disk),
        _ => 2,
    }
}

fn refuse(sys: u64, d: u64) -> i32 {
    let mut n = 0;
    let fmt = SYSCTL_DESOFS_FORMAT;
    let yes = d | SYSCTL_YES;

    // Raw sysctl with anything but the SYSCTL handle.
    check!(n, sysctl(60, fmt, yes, 1) == ERROR_INVALID_HANDLE, "format with a missing handle number");
    check!(n, sysctl(1, fmt, yes, 1) == ERROR_INVALID_HANDLE, "format with the console as the handle");
    let (pr, pw) = pipe().unwrap_or((0, 0));
    check!(n, sysctl(pw, fmt, yes, 1) == ERROR_INVALID_HANDLE && sysctl(pr, SYSCTL_DESOFS_REPAIR, yes, 1) == ERROR_INVALID_HANDLE, "format / repair with a pipe as the handle");
    close(pr);
    close(pw);
    let dh = dir_open("/", O_READ);
    check!(n, dh >= 0 && sysctl(dh as u64, fmt, yes, 1) == ERROR_INVALID_HANDLE, "format with a directory handle: {}", dh);
    close(dh as u64);

    // The right handle but a bad output handle: refused before anything is done.
    check!(n, sysctl(sys, fmt, yes, 60) == ERROR_INVALID_HANDLE, "format + yes with a missing output handle");
    let (pr, pw) = pipe().unwrap_or((0, 0));
    check!(n, sysctl(sys, fmt, yes, pr) == ERROR_ACCESS_DENIED, "format + yes into a pipe's read end (no WRITE)");
    close(pr);
    close(pw);
    let f = open("/dsfs-ro", O_WRITE | O_CREATE);
    close(f as u64);
    let f = open("/dsfs-ro", O_READ);
    check!(n, f >= 0 && sysctl(sys, fmt, yes, f as u64) == ERROR_ACCESS_DENIED, "format + yes into a file opened read-only: {}", f);
    close(f as u64);
    unlink("/dsfs-ro");
    let dw = dir_open("/", O_READ | O_WRITE);
    check!(n, dw >= 0 && sysctl(sys, fmt, yes, dw as u64) == ERROR_INVALID_HANDLE, "format + yes into a directory handle (WRITE, but not an output): {}", dw);
    close(dw as u64);

    // Bad arguments with the right handle: refused, nothing done.
    check!(n, sysctl(sys, SYSCTL_DESOFS_INFO, yes, 1) == ERROR_INVALID_ARGUMENT, "info with yes");
    check!(n, sysctl(sys, fmt, d | 1 << 40, 1) == ERROR_INVALID_ARGUMENT, "format with unknown bits");
    check!(n, sysctl(sys, SYSCTL_DESOFS_UNMOUNT, 1, 1) == ERROR_INVALID_ARGUMENT, "unmount with an argument");
    check!(n, sysctl(sys, 11, d, 1) == ERROR_INVALID_ARGUMENT, "action 11");

    // The shell: without the handle, a child shell of a shell with it.
    let t = sh(&format!("desofs format {} yes", d), None);
    check!(n, t.contains("desofs: not allowed - this shell has no system control handle"), "sh without SYSCTL: {:?}", t);
    let t = sh(&format!("sh -c \"desofs format {} yes\"", d), Some(sys));
    check!(n, t.contains("desofs: not allowed"), "a shell started by the shell got SYSCTL: {:?}", t);

    // Without "yes" – only a description.
    let t = sh(&format!("desofs format {}", d), Some(sys));
    check!(n, t.contains("This ERASES everything on disk") && t.contains(&format!("To continue type: desofs format {} yes", d)), "format without yes: {:?}", t);
    let t = sh(&format!("desofs repair {}", d), Some(sys));
    check!(n, t.contains("desofs repair:"), "repair without yes: {:?}", t);
    let t = sh(&format!("desofs info {}", d), Some(sys));
    check!(n, t.contains("not mountable as DeSoFS"), "info after the refusals (the disk must still not be DeSoFS): {:?}", t);
    let t = sh("desofs format", Some(sys));
    check!(n, t.contains("usage: desofs"), "usage: {:?}", t);

    println!("dsfstest: {} checks OK (refuse)", n);
    0
}

fn work(sys: u64, d: u64) -> i32 {
    let mut n = 0;
    let s = Some(sys);

    let t = sh(&format!("desofs format {} yes", d), s);
    check!(n, t.contains("DeSoFS,") && t.contains(&format!("'desofs mount {}' to use it", d)), "format: {:?}", t);
    let t = sh(&format!("desofs info {}", d), s);
    check!(n, t.contains("DeSoFS, read-write"), "info: {:?}", t);
    let t = sh(&format!("desofs mount {}", d), s);
    check!(n, t.contains("mounted at /desofs (DeSoFS, read-write)"), "mount: {:?}", t);
    let t = sh(&format!("desofs mount {}", d), s);
    check!(n, t.contains(&format!("desofs mount: disk {} is already mounted at /desofs", d)), "mount twice: {:?}", t);
    let t = sh(&format!("desofs info {}", d), s);
    check!(n, t.contains("blocks used (counted ") && !t.contains("Some("), "info wording: {:?}", t);
    let fd = open("/desofs/a", O_WRITE | O_CREATE);
    check!(n, fd >= 0 && write(fd as u64, b"hello desofs") == 12, "write /desofs/a: {}", fd);
    close(fd as u64);
    let t = sh(&format!("desofs check {}", d), s);
    check!(n, t.contains("the volume is mounted - unmount first"), "check while mounted: {:?}", t);

    // 1. An open file blocks; closing it lets the unmount through.
    let fd = open("/desofs/a", O_READ);
    check!(n, fd >= 0, "open /desofs/a: {}", fd);
    let t = sh("desofs unmount", s);
    check!(n, t.contains("desofs unmount /desofs: in use (1 open file / directory) - nothing changed") && mounted(), "unmount under an open file: {:?}", t);
    let mut buf = [0u8; 32];
    check!(n, read(fd as u64, &mut buf) == 12 && &buf[..12] == b"hello desofs", "the open file still reads after the refusal");
    close(fd as u64);
    let t = sh("desofs unmount", s);
    check!(n, t.contains("/desofs unmounted") && !mounted(), "unmount after close: {:?}", t);
    let t = sh(&format!("desofs mount {}", d), s);
    check!(n, t.contains("mounted at /desofs"), "mount again: {:?}", t);

    // 2. An open directory.
    let dh = dir_open("/desofs", O_READ);
    check!(n, dh >= 0, "dir_open /desofs: {}", dh);
    let t = sh("desofs unmount", s);
    check!(n, t.contains("in use (1 open file / directory)") && mounted(), "unmount under an open directory: {:?}", t);
    close(dh as u64);
    let t = sh("desofs unmount", s);
    check!(n, t.contains("/desofs unmounted"), "unmount after closing the directory: {:?}", t);
    let _ = sh(&format!("desofs mount {}", d), s);

    // 3. Another process stands in /desofs (its current directory) – killed, not closed.
    check!(n, chdir("/desofs") == 0, "chdir /desofs");
    let pid = spawn_ex("/bin/sleep", &["sleep", "30000"], &[(0, 0), (1, 1), (2, 2)], 0);
    check!(n, chdir("/") == 0 && pid > 0, "spawn sleep in /desofs: {}", pid);
    let t = sh("desofs unmount", s);
    check!(n, t.contains("in use (1 open file / directory)") && mounted(), "unmount under another process's directory: {:?}", t);
    kill(pid as u64);
    let _ = wait(pid as u64, 0);
    let t = sh("desofs unmount", s);
    check!(n, t.contains("/desofs unmounted"), "unmount after the process was killed: {:?}", t);
    let _ = sh(&format!("desofs mount {}", d), s);

    // 4. A file handed to a child: the parent closes its copy, the child's keeps the mount.
    let fd = open("/desofs/a", O_READ);
    let pid = spawn_ex("/bin/sleep", &["sleep", "30000"], &[(fd as u64, 0), (1, 1), (2, 2)], 0);
    close(fd as u64);
    check!(n, fd >= 0 && pid > 0, "spawn sleep with /desofs/a as stdin: {} {}", fd, pid);
    let t = sh("desofs unmount", s);
    check!(n, t.contains("in use (1 open file / directory)"), "unmount under a child's inherited file: {:?}", t);
    kill(pid as u64);
    let _ = wait(pid as u64, 0);

    // 5. Format under an open file: refused, the volume and the file stay.
    let fd = open("/desofs/a", O_READ);
    let t = sh(&format!("desofs format {} yes", d), s);
    check!(n, t.contains("desofs format: cannot unmount /desofs (in use (1 open file / directory)) - nothing changed"), "format under an open file: {:?}", t);
    let mut buf = [0u8; 32];
    check!(n, read(fd as u64, &mut buf) == 12 && &buf[..12] == b"hello desofs", "the file reads after the refused format");
    close(fd as u64);

    // 6. The caller's own current directory does not block it; afterwards it is in "/".
    check!(n, chdir("/desofs") == 0, "chdir /desofs");
    let (r, w) = pipe().unwrap_or((0, 0));
    let rc = sysctl(sys, SYSCTL_DESOFS_UNMOUNT, 0, w);
    close(w);
    let mut buf = [0u8; 256];
    let k = read(r, &mut buf).max(0) as usize;
    close(r);
    let t = core::str::from_utf8(&buf[..k]).unwrap_or("");
    let mut cb = [0u8; 64];
    let cwd = String::from(getcwd(&mut cb));
    check!(n, rc == 0 && t.contains("/desofs unmounted") && cwd == "/" && !mounted(), "unmount from inside: {} {:?}, cwd {:?}", rc, t, cwd);

    // 7. check and repair on the unmounted volume.
    let t = sh(&format!("desofs check {}", d), s);
    check!(n, t.contains("result: 0 errors, 0 warnings"), "check: {:?}", t);
    let t = sh(&format!("desofs repair {} yes", d), s);
    check!(n, t.contains("nothing to repair"), "repair: {:?}", t);

    println!("dsfstest: {} checks OK (work)", n);
    0
}
