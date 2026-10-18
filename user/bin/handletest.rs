// Test of handles with rights – handle_dup (rights can only shrink),
// handle_info, read / write without the right (EBADF), copies without R_DUP (EACCES),
// a child after spawn gets the handle with the same (reduced) rights,
// the 64-handle limit, and the kernel's view of the table (`caps <pid>` – the
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
    let ok_write = write(0, b"x") == -9;
    let ok_amplify = {
        let h = handle_dup(0, R_ALL);
        h >= 0 && handle_info(h as u64) == Ok((KIND_FILE, R_READ | R_DUP))
    };
    // Handle 0 is a file, not the console – keyboard unavailable.
    let ok_key = readkey("").err() == Some(EBADF);
    if ok_info && ok_read && ok_write && ok_amplify && ok_key { 0 } else { 3 }
}

static mut CAPS: [u8; 8192] = [0; 8192];

/// `caps <own pid>` as the kernel shows it to others (sysinfo); "" on error.
fn my_caps() -> &'static str {
    let mut topic = *b"caps                    ";
    let mut pid = getpid();
    let mut digits = [0u8; 20];
    let mut k = 0;
    loop {
        digits[k] = b'0' + (pid % 10) as u8;
        k += 1;
        pid /= 10;
        if pid == 0 {
            break;
        }
    }
    for i in 0..k {
        topic[5 + i] = digits[k - 1 - i];
    }
    let topic = core::str::from_utf8(&topic[..5 + k]).unwrap_or("caps");
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(CAPS) };
    match sysinfo(topic, buf) {
        Ok(len) => core::str::from_utf8(&buf[..len]).unwrap_or(""),
        Err(_) => "",
    }
}

/// The line of slot `slot` in `caps` output (columns: slot, kind, rights).
fn caps_line(text: &str, slot: u64) -> Option<&str> {
    text.lines().find(|l| {
        let mut w = l.split_whitespace();
        w.next().and_then(|s| s.parse::<u64>().ok()) == Some(slot)
    })
}

fn main(args: Args) -> i32 {
    if args.get(1) == Some("child") {
        return child();
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

    // 2. handle_dup reduces rights; read / write without the right = EBADF.
    let ro = handle_dup(fd, R_READ | R_DUP);
    check!(n, ro >= 3, "handle_dup: {}", strerror(ro));
    let ro = ro as u64;
    check!(n, handle_info(ro) == Ok((KIND_FILE, R_READ | R_DUP)), "reduced rights: {:?}", handle_info(ro));
    check!(n, write(ro, b"x") == -9, "write without R_WRITE must be EBADF: {}", write(ro, b"x"));
    seek(ro, 0, SEEK_SET);
    check!(n, read(ro, &mut buf) == 5 && &buf[..5] == b"hello", "read via reduced handle");
    let wo = handle_dup(fd, R_WRITE);
    check!(n, wo >= 3 && read(wo as u64, &mut buf) == -9, "read without R_READ must be EBADF");

    // 3. Rights never grow – neither via handle_dup with a full mask, nor via dup / dup2.
    let again = handle_dup(ro, R_ALL);
    check!(n, again >= 0 && handle_info(again as u64) == Ok((KIND_FILE, R_READ | R_DUP)), "handle_dup(ALL) amplified: {:?}", handle_info(again as u64));
    let d = dup(ro);
    check!(n, d >= 0 && handle_info(d as u64) == Ok((KIND_FILE, R_READ | R_DUP)), "dup changed rights: {:?}", handle_info(d as u64));
    check!(n, dup2(ro, 40) == 40 && handle_info(40) == Ok((KIND_FILE, R_READ | R_DUP)), "dup2 changed rights: {:?}", handle_info(40));

    // 4. Without R_DUP there are no copies (dup, dup2, handle_dup, spawn) – EACCES.
    let nodup = handle_dup(fd, R_READ);
    check!(n, nodup >= 0, "handle_dup without DUP: {}", strerror(nodup));
    let nodup = nodup as u64;
    check!(n, dup(nodup) == -13 && dup2(nodup, 41) == -13 && handle_dup(nodup, R_READ) == -13, "copy without R_DUP must be EACCES");
    check!(n, spawn("/bin/hello", &["hello"], 0, fds(nodup, 1, 2)) == -13, "spawn with a handle without R_DUP must be EACCES");

    // 4b. The kernel's view for other processes (`caps <pid>`) shows the same
    // kinds and rights – the summary is published on every change.
    let t = my_caps();
    check!(n, t.contains("handletest (pid"), "caps header: {:?}", t.lines().next());
    check!(n, caps_line(t, 1).map_or(false, |l| l.contains("console") && l.contains("read write dup transfer")), "caps console slot: {:?}", caps_line(t, 1));
    check!(n, caps_line(t, ro).map_or(false, |l| l.contains("file") && l.contains("read dup") && !l.contains("write")), "caps reduced file slot: {:?}", caps_line(t, ro));
    check!(n, caps_line(t, nodup).map_or(false, |l| l.contains("file") && l.contains(" read ") && !l.contains("dup")), "caps no-DUP slot: {:?}", caps_line(t, nodup));
    check!(n, caps_line(t, pw).map_or(false, |l| l.contains("pipe") && l.contains("write dup transfer")), "caps pipe slot: {:?}", caps_line(t, pw));
    check!(n, close(pw) == 0 && caps_line(my_caps(), pw).is_none(), "caps still shows a closed handle");

    // 5. The child gets the handle with the same (reduced) rights.
    seek(ro, 0, SEEK_SET);
    let pid = spawn("/bin/handletest", &["handletest", "child"], 0, fds(ro, 1, 2));
    check!(n, pid > 0, "spawn child: {}", strerror(pid));
    check!(n, wait(pid as u64, 0) == Ok((pid as u64, 0)), "child saw wrong rights (or could write / amplify)");

    // 6. Closed handle – EBADF; 64-handle limit – EMFILE.
    check!(n, close(nodup) == 0 && handle_info(nodup) == Err(-9), "closed handle must be EBADF");
    let mut opened = 0;
    loop {
        let h = dup(fd);
        if h < 0 {
            check!(n, h == -24, "handle limit error: {}", strerror(h));
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
