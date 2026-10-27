// File sandbox test (spawn flag SPAWN_NO_FILES).  The parent prepares a file,
// passes a read-only handle to it to a child started in the sandbox, and the
// child tries to get out:
//   - every call that takes a path is refused (open in every mode, stat,
//     readdir, mkdir, unlink, chdir, spawn, spawn_ex) – ERROR_ACCESS_DENIED,
//   - the handle it was given works, with exactly its rights (read yes, write
//     ERROR_ACCESS_DENIED, handle_dup cannot add rights),
//   - console, memory, pipes, channels and getcwd still work (no path),
//   - the kernel's view (`dcp inspect <own pid>`) says "files: none",
//   - the refusals appear in `dcp audit` (sandbox, a capability without WRITE).
// The parent then checks that nothing changed on disk, that unknown spawn flags
// give ERROR_INVALID_ARGUMENT, and that an unsandboxed child still has files.
// Result: "sandtest: N checks OK" and code 0.  Child mode: `sandtest child`
// (exit code 0 = all refusals and permissions as expected, otherwise the
// number of the first failed check).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const PATH: &str = "/sandtest.tmp";
const DATA: &[u8] = b"secret data";

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("sandtest: FAIL check {}: {}", $n, format_args!($($msg)*));
            unlink(PATH);
            return 1;
        }
    };
}

/// Child check: on failure exit with the check number (stdout is the console,
/// the parent prints the number).
macro_rules! expect {
    ($n:ident, $cond:expr) => {
        $n += 1;
        if !$cond {
            return $n;
        }
    };
}

static mut BUF: [u8; 4096] = [0; 4096];

fn own_caps() -> &'static str {
    let mut topic = *b"dcp inspect                    ";
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
        topic[12 + i] = digits[k - 1 - i];
    }
    let topic = core::str::from_utf8(&topic[..12 + k]).unwrap_or("dcp");
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
    match sysinfo(topic, buf) {
        Ok(len) => core::str::from_utf8(&buf[..len]).unwrap_or(""),
        Err(_) => "",
    }
}

/// In the sandbox: handle 3 = read-only file (READ | DUP).
fn child() -> i32 {
    let mut n = 0;
    // 1–9: every path call is refused, whatever the mode or path.
    expect!(n, open(PATH, O_READ) == ERROR_ACCESS_DENIED);
    expect!(n, open(PATH, O_WRITE | O_TRUNC) == ERROR_ACCESS_DENIED);
    expect!(n, open("/new-file", O_WRITE | O_CREATE) == ERROR_ACCESS_DENIED);
    expect!(n, open("relative", O_READ) == ERROR_ACCESS_DENIED);
    expect!(n, stat("/").err() == Some(ERROR_ACCESS_DENIED));
    let mut dir = [0u8; 256];
    expect!(n, readdir("/", &mut dir) == ERROR_ACCESS_DENIED);
    expect!(n, mkdir("/sandbox-escape") == ERROR_ACCESS_DENIED);
    expect!(n, unlink(PATH) == ERROR_ACCESS_DENIED);
    expect!(n, chdir("/bin") == ERROR_ACCESS_DENIED);
    // 10–11: no programs by path either (a way around the sandbox).
    expect!(n, spawn("/bin/hello", &["hello"], 0, fds(1, 1, 1)) == ERROR_ACCESS_DENIED);
    expect!(n, spawn_ex("/bin/cat", &["cat", PATH], &[(1, 1)], 0) == ERROR_ACCESS_DENIED);
    // 12–14: the handle it was given works – with exactly its rights.
    let mut b = [0u8; 32];
    let r = read(3, &mut b);
    expect!(n, r == DATA.len() as i64 && &b[..DATA.len()] == DATA);
    expect!(n, write(3, b"x") == ERROR_ACCESS_DENIED);
    let up = handle_dup(3, R_ALL);
    expect!(n, up >= 0 && handle_info(up as u64) == Ok((KIND_FILE, R_READ | R_DUP)));
    // 15–17: things without paths still work.
    let mut cwd = [0u8; 64];
    expect!(n, !getcwd(&mut cwd).is_empty());
    let p = pipe();
    expect!(n, matches!(p, Ok((r, w)) if write(w, b"ok") == 2 && read(r, &mut b) == 2));
    expect!(n, channel_create().is_ok());
    // 18: the kernel's view says the same.
    let caps = own_caps();
    expect!(n, caps.contains("files: none"));
    0
}

fn main(args: Args) -> i32 {
    if args.get(1) == Some("child") {
        return child();
    }
    let mut n = 0;
    unlink(PATH);
    let fd = open(PATH, O_READ | O_WRITE | O_CREATE | O_TRUNC);
    check!(n, fd >= 3, "create {}: {}", PATH, fd);
    check!(n, write(fd as u64, DATA) == DATA.len() as i64, "write test data");
    close(fd as u64);
    let ro = open(PATH, O_READ);
    check!(n, ro >= 3, "open read-only: {}", ro);
    let ro = handle_dup(ro as u64, R_READ | R_DUP);
    check!(n, ro >= 0, "reduce rights: {}", ro);

    // The sandboxed child (console as 1, the read-only file as 3).
    let pid = spawn_ex("/bin/sandtest", &["sandtest", "child"], &[(1, 1), (ro as u64, 3)], SPAWN_NO_FILES);
    check!(n, pid > 0, "spawn sandboxed child: {}", pid);
    let st = wait(pid as u64, 0);
    let code = st.map(|(_, s)| s).unwrap_or(999);
    check!(n, code == 0, "sandboxed child failed its check {} (1-9 path refused, 10-11 spawn refused, 12-14 handle rights, 15-17 no-path calls, 18 dcp view)", code);
    // The refusals are in the audit log, attributed to the child (we are its parent).
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
    let audit = match sysinfo("dcp audit", buf) {
        Ok(len) => core::str::from_utf8(&buf[..len]).unwrap_or(""),
        Err(_) => "",
    };
    let mine = |needle: &str| audit.lines().filter(|l| l.contains("sandtest (") && l.contains(needle)).count();
    check!(n, mine("no files (sandbox)") >= 11, "dcp audit: sandbox refusals of the child missing ({} found)", mine("no files (sandbox)"));
    check!(n, mine("open /sandtest.tmp") >= 1, "dcp audit: the refused path is not shown");
    check!(n, mine("has no WRITE right") >= 1, "dcp audit: write without WRITE not recorded");

    // Nothing changed on disk; the parent still has files.
    let mut b = [0u8; 32];
    let fd = open(PATH, O_READ);
    check!(n, fd >= 3 && read(fd as u64, &mut b) == DATA.len() as i64 && &b[..DATA.len()] == DATA, "the file changed or vanished");
    close(fd as u64);
    check!(n, stat("/sandbox-escape").is_err() && stat("/new-file").is_err(), "the sandboxed child created something");

    // Unknown spawn flags are refused; without the flag a child has files.
    check!(n, spawn_ex("/bin/hello", &["hello"], &[(1, 1)], 1 << 7) == ERROR_INVALID_ARGUMENT, "unknown spawn flag must be ERROR_INVALID_ARGUMENT");
    let pid = spawn_ex("/bin/cat", &["cat", PATH], &[(1, 1)], 0);
    check!(n, pid > 0 && matches!(wait(pid as u64, 0), Ok((_, 0))), "an unsandboxed child must still read files");
    println!();
    unlink(PATH);
    println!("sandtest: {} checks OK (sandboxed child: 18 checks - paths refused, given handle works with its rights; refusals in dcp audit)", n);
    0
}
