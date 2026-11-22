// A program written against the DeSo OS SDK of ABI 1.0 – part of the frozen copy in
// sdk/compat/abi-1.0 (never edited; sdk/compat/abi-1.0.lock).  tests/sdk-test.sh builds it with
// this copy's own deso-build.sh and SDK TEST runs it on the current system through init
// (`init test /disk/bin/compat10`): what a 1.0 program relies on must still hold.
//   start    the start stack (RSP % 16 == 0 at argc, argv[], NULL, envp NULL, auxv AT_NULL),
//            slots 0-2 open, slot 3 the service channel
//   calls    processes, memory (brk, mmap), random bytes, errors of bad calls
//   handles  a channel (send / receive / a handle passed along), rights, dup, close, a pipe
//   files    create, write, seek, read, stat, a directory, unlink, the errors
//   time     the uptime clock, the wall clock and its bound
//   services the service list, the manager's version (svc 1.0), net0: status and version
// Result: "compat10: N checks OK" and exit code 0.
#![no_std]
#![no_main]

extern crate libdeso;
use libdeso as deso;

use deso::*;

entry!(main);

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("compat10: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

fn main(args: Args) -> i32 {
    let mut n = 0;

    // start
    let sp = args.argv() as u64 - 8;
    let word = |i: usize| unsafe { *(sp as *const u64).add(i) };
    let argc = args.len();
    check!(n, sp % 16 == 0 && word(0) == argc as u64, "start stack: RSP {:#x}, [RSP] {}", sp, word(0));
    check!(n, word(1 + argc) == 0 && word(2 + argc) == 0 && word(3 + argc) == 0, "argv / envp / auxv ends");
    check!(n, (0..3).all(|s| handle_info(s).is_ok()), "slots 0-2");
    check!(n, handle_info(SVC).map(|(k, _)| k) == Ok(KIND_CHANNEL), "slot 3: {:?}", handle_info(SVC));

    // calls
    check!(n, getpid() > 0 && getppid() > 0, "getpid / getppid");
    let b0 = brk(0);
    check!(n, b0 > 0 && brk(b0 + 8192) == b0 + 8192, "brk");
    let m = mmap(65536, PROT_READ | PROT_WRITE);
    check!(n, m.is_ok(), "mmap: {:?}", m);
    let m = m.unwrap_or(0);
    unsafe { *((m + 65535) as *mut u8) = 7 };
    check!(n, unsafe { *((m + 65535) as *const u8) } == 7 && munmap(m, 65536) == 0, "mmap memory / munmap");
    let mut r = [0u8; 32];
    check!(n, getrandom(&mut r).is_ok() && r.iter().any(|&b| b != 0), "getrandom");
    check!(n, close(999) == ERROR_INVALID_HANDLE, "close of a bad handle: {}", close(999));
    check!(n, syscall3(9999, 0, 0, 0) < 0, "an unknown system call fails");

    // handles
    let ch = channel_create();
    check!(n, ch.is_ok(), "channel_create");
    let (a, b) = ch.unwrap_or((0, 0));
    let (pa, pb) = channel_create().unwrap_or((0, 0));
    check!(n, chan_send_h(a, b"compat", &[pb], 0) == 0, "chan_send with a handle");
    let mut buf = [0u8; 64];
    let mut hs = [0u64; MSG_HANDLES];
    let mut info = RecvInfo::default();
    let got = chan_recv_h(b, &mut buf, &mut hs, 0, &mut info);
    check!(n, got == 6 && &buf[..6] == b"compat" && info.handles == 1, "chan_recv: {} handles {}", got, info.handles);
    check!(n, chan_send(hs[0], b"x", 0) == 0 && chan_recv(pa, &mut buf, 0, &mut info) == 1, "the passed handle works");
    let ro = handle_dup(a, R_RECV);
    check!(n, ro >= 0 && chan_send(ro as u64, b"x", 0) == ERROR_ACCESS_DENIED, "a narrowed handle: {}", ro);
    let d = dup(b);
    check!(n, d >= 0 && close(d as u64) == 0, "dup / close");
    for h in [a, b, pa, hs[0], ro as u64] {
        close(h);
    }
    check!(n, chan_send(a, b"x", 0) == ERROR_INVALID_HANDLE, "a closed handle");
    let p = pipe();
    check!(n, p.is_ok(), "pipe");
    let (pr, pw) = p.unwrap_or((0, 0));
    check!(n, write(pw, b"pipe") == 4 && read(pr, &mut buf) == 4, "pipe write / read");
    close(pr);
    close(pw);

    // files
    let f = open("/tmp/compat10.txt", O_READ | O_WRITE | O_CREATE | O_TRUNC);
    check!(n, f >= 0, "open with O_CREATE: {}", f);
    let f = f as u64;
    check!(n, write(f, b"DeSo OS ABI 1.0") == 15, "write");
    check!(n, seek(f, 5, SEEK_SET) == 5 && read(f, &mut buf) == 10 && &buf[..10] == b"OS ABI 1.0", "seek / read");
    close(f);
    check!(n, stat("/tmp/compat10.txt").is_ok_and(|s| !s.is_dir && s.size == 15), "stat");
    check!(n, mkdir("/tmp/compat10.d") == 0 && stat("/tmp/compat10.d").is_ok_and(|s| s.is_dir), "mkdir");
    check!(n, unlink("/tmp/compat10.d") == 0 && unlink("/tmp/compat10.txt") == 0, "unlink");
    check!(n, open("/tmp/compat10.txt", O_READ) == ERROR_NOT_FOUND, "a missing file");

    // time
    let t0 = uptime_ms();
    sleep_ms(20);
    check!(n, uptime_ms() >= t0 + 20, "uptime / sleep");
    check!(n, time_unix().is_ok(), "time_unix: {:?}", time_unix().err());
    check!(n, time_bound().is_ok(), "time_bound: {:?}", time_bound().err());

    // services
    let mut list = [0u8; 2048];
    let l = svc_list(&mut list).unwrap_or(0);
    check!(n, core::str::from_utf8(&list[..l]).is_ok_and(|t| t.contains("net0 ")), "the service list");
    check!(n, svc_version().is_ok_and(|v| v.0 == 1), "the service manager's version: {:?}", svc_version());
    let t0 = uptime_ms();
    let c = loop {
        if let Ok(c) = svc_connect("net0") {
            if chan_send(c, b"status", 0) == 0 && wait_many(&[(c, W_READABLE)], 5000) == Ok(1) {
                let k = chan_recv(c, &mut list, 0, &mut info);
                if k > 0 && list.starts_with(b"net0: ") {
                    break c;
                }
            }
            close(c);
        }
        if uptime_ms() - t0 > 30_000 {
            println!("compat10: FAIL: net0 does not answer status");
            return 1;
        }
        sleep_ms(200);
    };
    n += 1;
    check!(n, net_version(c, 5000).is_ok_and(|v| v.0 == 1), "the network service's version: {:?}", net_version(c, 5000));
    close(c);

    println!("compat10: {} checks OK (start, calls, handles, files, time, services)", n);
    0
}
