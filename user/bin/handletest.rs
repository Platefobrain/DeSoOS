// Test of handles with rights – handle_dup (rights can only shrink),
// handle_info, read / write without the right (ERROR_ACCESS_DENIED), copies without R_DUP (ERROR_ACCESS_DENIED),
// a child after spawn gets the handle with the same (reduced) rights,
// the 64-handle limit, and the kernel's view of the table (`dcp inspect <pid>` – the
// published summary other processes see) follows every change.  Result: "handletest: N checks OK" and code 0, or a description
// of the first failure and code 1.  Run by IPC TEST (self-tests).
//
// `handletest child` – child mode: handle 0 must be a read-only file
// (R_READ | R_DUP); code 0 = matches, 3 = does not.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const PATH: &str = "/handletest.tmp";

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("handletest: FAIL check {}: {}", $n, format_args!($($msg)*));
            unlink(PATH);
            return 1;
        }
    };
}

fn child() -> i32 {
    let ok_info = handle_info(0) == Ok((KIND_FILE, R_READ | R_DUP));
    let mut b = [0u8; 8];
    let ok_read = read(0, &mut b) == 5 && &b[..5] == b"hello";
    let ok_write = write(0, b"x") == ERROR_ACCESS_DENIED;
    let ok_amplify = {
        let h = handle_dup(0, R_ALL);
        h >= 0 && handle_info(h as u64) == Ok((KIND_FILE, R_READ | R_DUP))
    };
    // Handle 0 is a file, not the console – keyboard unavailable.
    let ok_key = readkey("").err() == Some(ERROR_INVALID_HANDLE);
    if ok_info && ok_read && ok_write && ok_amplify && ok_key { 0 } else { 3 }
}

static mut CAPS: [u8; 8192] = [0; 8192];

/// `dcp <args> <pid>` as the kernel shows it to this process (sysinfo); "" on error.
fn dcp_pid(prefix: &str, pid: u64) -> &'static str {
    let mut topic = [0u8; 48];
    let p = prefix.as_bytes();
    topic[..p.len()].copy_from_slice(p);
    let mut digits = [0u8; 20];
    let (mut k, mut v) = (0, pid);
    loop {
        digits[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..k {
        topic[p.len() + i] = digits[k - 1 - i];
    }
    let topic = core::str::from_utf8(&topic[..p.len() + k]).unwrap_or("dcp");
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(CAPS) };
    match sysinfo(topic, buf) {
        Ok(len) => core::str::from_utf8(&buf[..len]).unwrap_or(""),
        Err(_) => "",
    }
}

/// `dcp inspect <own pid>` – the published view other processes get.
fn my_caps() -> &'static str {
    dcp_pid("dcp inspect ", getpid())
}

/// The line of slot `slot` in `dcp inspect` output (columns: slot, capability, rights).
fn caps_line(text: &str, slot: u64) -> Option<&str> {
    text.lines().find(|l| {
        let mut w = l.split_whitespace();
        w.next().and_then(|s| s.parse::<u64>().ok()) == Some(slot)
    })
}

/// Child modes for the DCP view checks.
fn peek_parent() -> i32 {
    // A child without SYS_POWER must not see its parent's capabilities.
    let t = dcp_pid("dcp inspect ", getppid());
    if t.contains("is not yours") { 0 } else { 4 }
}

fn churn() -> i32 {
    // Changes the handle table as fast as possible while the parent inspects it.
    let t = uptime_ms();
    while uptime_ms() - t < 300 {
        let a = dup(1);
        let b = dup(1);
        close(a as u64);
        close(b as u64);
    }
    0
}

fn main(args: Args) -> i32 {
    match args.get(1) {
        Some("child") => return child(),
        Some("peek") => return peek_parent(),
        Some("churn") => return churn(),
        Some("exit") => return 0,
        _ => {}
    }
    let mut n = 0;
    let mut buf = [0u8; 64];
    unlink(PATH);

    // 1. Rights derived from the object (as before rights were introduced).
    check!(n, handle_info(1) == Ok((KIND_CONSOLE, R_READ | R_WRITE | R_DUP | R_TRANSFER)), "console: {:?}", handle_info(1));
    let fd = open(PATH, O_READ | O_WRITE | O_CREATE | O_TRUNC);
    check!(n, fd >= 3, "open: {}", strerror(fd));
    let fd = fd as u64;
    check!(n, handle_info(fd) == Ok((KIND_FILE, R_READ | R_WRITE | R_DUP | R_TRANSFER)), "file rw: {:?}", handle_info(fd));
    check!(n, write(fd, b"hello") == 5, "write via full handle");
    let ro_open = open(PATH, O_READ);
    check!(n, ro_open >= 3 && handle_info(ro_open as u64) == Ok((KIND_FILE, R_READ | R_DUP | R_TRANSFER)), "file opened read-only: {:?}", handle_info(ro_open as u64));
    close(ro_open as u64);
    let (pr, pw) = match pipe() {
        Ok(p) => p,
        Err(e) => {
            println!("handletest: FAIL pipe: {}", strerror(e));
            return 1;
        }
    };
    check!(n, handle_info(pr) == Ok((KIND_PIPE, R_READ | R_DUP | R_TRANSFER)), "pipe read end: {:?}", handle_info(pr));
    check!(n, handle_info(pw) == Ok((KIND_PIPE, R_WRITE | R_DUP | R_TRANSFER)), "pipe write end: {:?}", handle_info(pw));

    // 2. handle_dup reduces rights; read / write without the right = ERROR_ACCESS_DENIED.
    let ro = handle_dup(fd, R_READ | R_DUP);
    check!(n, ro >= 3, "handle_dup: {}", strerror(ro));
    let ro = ro as u64;
    check!(n, handle_info(ro) == Ok((KIND_FILE, R_READ | R_DUP)), "reduced rights: {:?}", handle_info(ro));
    check!(n, write(ro, b"x") == ERROR_ACCESS_DENIED, "write without R_WRITE must be ERROR_ACCESS_DENIED: {}", write(ro, b"x"));
    seek(ro, 0, SEEK_SET);
    check!(n, read(ro, &mut buf) == 5 && &buf[..5] == b"hello", "read via reduced handle");
    let wo = handle_dup(fd, R_WRITE);
    check!(n, wo >= 3 && read(wo as u64, &mut buf) == ERROR_ACCESS_DENIED, "read without R_READ must be ERROR_ACCESS_DENIED");

    // 3. Rights never grow – neither via handle_dup with a full mask, nor via dup / dup2.
    let again = handle_dup(ro, R_ALL);
    check!(n, again >= 0 && handle_info(again as u64) == Ok((KIND_FILE, R_READ | R_DUP)), "handle_dup(ALL) amplified: {:?}", handle_info(again as u64));
    let d = dup(ro);
    check!(n, d >= 0 && handle_info(d as u64) == Ok((KIND_FILE, R_READ | R_DUP)), "dup changed rights: {:?}", handle_info(d as u64));
    check!(n, dup2(ro, 40) == 40 && handle_info(40) == Ok((KIND_FILE, R_READ | R_DUP)), "dup2 changed rights: {:?}", handle_info(40));

    // 4. Without R_DUP there are no copies (dup, dup2, handle_dup, spawn) – ERROR_ACCESS_DENIED.
    let nodup = handle_dup(fd, R_READ);
    check!(n, nodup >= 0, "handle_dup without DUP: {}", strerror(nodup));
    let nodup = nodup as u64;
    check!(n, dup(nodup) == ERROR_ACCESS_DENIED && dup2(nodup, 41) == ERROR_ACCESS_DENIED && handle_dup(nodup, R_READ) == ERROR_ACCESS_DENIED, "copy without R_DUP must be ERROR_ACCESS_DENIED");
    check!(n, spawn("/bin/hello", &["hello"], 0, fds(nodup, 1, 2)) == ERROR_ACCESS_DENIED, "spawn with a handle without R_DUP must be ERROR_ACCESS_DENIED");

    // 4b. The kernel's view for other processes (`dcp inspect <pid>`) shows the same
    // kinds and rights – the summary is published on every change.
    let t = my_caps();
    check!(n, t.contains("handletest (pid"), "caps header: {:?}", t.lines().next());
    check!(n, caps_line(t, 1).map_or(false, |l| l.contains("CONSOLE") && l.contains("READ WRITE COPY SHARE")), "dcp console slot: {:?}", caps_line(t, 1));
    check!(n, caps_line(t, ro).map_or(false, |l| l.contains("FILE") && l.contains("READ COPY") && !l.contains("WRITE")), "dcp reduced file slot: {:?}", caps_line(t, ro));
    check!(n, caps_line(t, nodup).map_or(false, |l| l.contains("FILE") && l.contains(" READ ") && !l.contains("COPY")), "dcp no-COPY slot: {:?}", caps_line(t, nodup));
    check!(n, caps_line(t, pw).map_or(false, |l| l.contains("PIPE") && l.contains("WRITE COPY SHARE")), "dcp pipe slot: {:?}", caps_line(t, pw));
    // Who holds the other end: here we hold both ends of a pipe and of a channel.
    let pr_line = caps_line(t, pr).unwrap_or("");
    check!(n, pr_line.contains("pipe (read end) from itself (slot"), "dcp pipe peer: {:?}", pr_line);
    let (ca, cb) = channel_create().unwrap_or((0, 0));
    let t2 = my_caps();
    check!(n, caps_line(t2, ca).map_or(false, |l| l.contains("channel to itself (slot")) && caps_line(t2, cb).map_or(false, |l| l.contains("channel to itself (slot")), "dcp channel peer: {:?}", caps_line(t2, ca));
    close(cb);
    check!(n, caps_line(my_caps(), ca).map_or(false, |l| l.contains("other end held by no program")), "dcp closed channel peer: {:?}", caps_line(my_caps(), ca));
    close(ca);
    check!(n, close(pw) == 0 && caps_line(my_caps(), pw).is_none(), "dcp still shows a closed handle");
    // No such process; a process that already exited; a child may not look at its parent.
    check!(n, dcp_pid("dcp inspect ", 999_999).contains("no user process"), "dcp inspect of a missing pid");
    let gone = spawn("/bin/handletest", &["handletest", "exit"], 0, fds(0, 1, 2));
    check!(n, gone > 0 && wait(gone as u64, 0).is_ok() && dcp_pid("dcp inspect ", gone as u64).contains("no user process"), "dcp inspect of an exited process");
    let peek = spawn("/bin/handletest", &["handletest", "peek"], 0, fds(0, 1, 2));
    check!(n, peek > 0 && wait(peek as u64, 0) == Ok((peek as u64, 0)), "a child without SYS_POWER saw its parent's capabilities");
    // The parent sees its child, also while the child changes its table on another CPU.
    let ch = spawn("/bin/handletest", &["handletest", "churn"], 0, fds(0, 1, 2));
    check!(n, ch > 0, "spawn churn child: {}", ch);
    let mut views = 0;
    let mut bad = false;
    while matches!(wait(ch as u64, WNOHANG), Ok((0, _))) {
        let t = dcp_pid("dcp inspect ", ch as u64);
        if t.contains("handletest (pid") {
            views += 1;
            // Every slot line well-formed: number, capability, rights.
            bad |= t.lines().filter(|l| l.split_whitespace().next().map_or(false, |w| w.parse::<u64>().is_ok())).any(|l| l.split_whitespace().count() < 3);
        }
    }
    check!(n, views > 0 && !bad, "dcp inspect during handle churn: {} views, malformed: {}", views, bad);

    // 5. The child gets the handle with the same (reduced) rights.
    seek(ro, 0, SEEK_SET);
    let pid = spawn("/bin/handletest", &["handletest", "child"], 0, fds(ro, 1, 2));
    check!(n, pid > 0, "spawn child: {}", strerror(pid));
    check!(n, wait(pid as u64, 0) == Ok((pid as u64, 0)), "child saw wrong rights (or could write / amplify)");

    // 6. Closed handle – ERROR_INVALID_HANDLE; 64-handle limit – ERROR_TOO_MANY_HANDLES.
    check!(n, close(nodup) == 0 && handle_info(nodup) == Err(ERROR_INVALID_HANDLE), "closed handle must be ERROR_INVALID_HANDLE");
    let mut opened = 0;
    loop {
        let h = dup(fd);
        if h < 0 {
            check!(n, h == ERROR_TOO_MANY_HANDLES, "handle limit error: {}", strerror(h));
            break;
        }
        opened += 1;
        if opened > 100 {
            break;
        }
    }
    check!(n, (50..=61).contains(&opened), "handle table size: {} more handles", opened);

    unlink(PATH);
    println!("handletest: {} checks OK", n);
    0
}
