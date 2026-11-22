// abiprobe – the ABI description against the running kernel (ABI TEST 2/3):
// every number and every error code it uses comes from sdk/libdeso/src/abi.rs (libdeso::abi),
// which tools/abigen.py generates from abi/abi.toml – the chain abi.toml -> generator ->
// constants -> program -> kernel in one run.
//
//   abiprobe          the probes; one line "abiprobe: ABI x.y, N probes (...), 0 failed" and code
//                     0, or a FAIL line per failed probe and code 1
//   abiprobe exit7    exits with 7 through SYS_EXIT (the parent's SYS_WAIT must see 7)
//   abiprobe nofiles  exits with 7 when it has the console on 1 and opening a file is refused
//   abiprobe slot5    exits with 7 when handle 5 is a pipe and there is no handle 1
//
// The probes: every rights row gets a handle that does not exist in its first handle argument
// (ERROR_INVALID_HANDLE – the gate runs before the call; the later handle arguments of a row are
// reached only with real handles before them, so the kernel's gate test in ABI TEST 1/3 does every
// handle argument); a handle without rights (ERROR_ACCESS_DENIED); reserved numbers and the first
// number past the table (ERROR_NOT_IMPLEMENTED); bad pointers (ERROR_INVALID_ADDRESS); the ordinary
// calls with arguments whose result is known; and the argument order – for every call abi.toml
// gives `order = "abiprobe"`, one call with values chosen so that swapping any two arguments
// changes the result (a pointer where a length or handle belongs, a length longer than the data,
// a handle number that does not exist ...).  Each passed order case prints "abiprobe: order ok
// SYS_..." and ABI TEST checks every one is there.  Only raw syscalls with abi:: numbers – the
// library's wrappers are not used, so a wrapper cannot hide a difference.
#![no_std]
#![no_main]

#[macro_use]
#[allow(unused_imports)]
extern crate libdeso;
#[allow(unused_imports)]
use libdeso as deso;

use libdeso::abi;
use libdeso::abi::table;

use deso::{syscall6, Args};

entry!(main);

/// A handle number that never exists (handle tables are smaller).
const NO_HANDLE: u64 = 999;
/// Below the load range – never mapped.
const BAD_PTR: u64 = 0x10;
/// A kernel address.
const KERNEL_PTR: u64 = 0xFFFF_8000_0000_0000;

fn sys(n: u64, a: [u64; 6]) -> i64 {
    syscall6(n, a[0], a[1], a[2], a[3], a[4], a[5])
}

struct Probe {
    ran: u32,
    failed: u32,
    orders: u32,
}

impl Probe {
    fn want(&mut self, what: &str, got: i64, ok: bool, expect: &str) {
        self.ran += 1;
        if !ok {
            self.failed += 1;
            println!("abiprobe: FAIL {}: got {} ({}), want {}", what, got, deso::error_name(got), expect);
        }
    }
    fn err(&mut self, what: &str, got: i64, e: i64) {
        if e < 0 {
            self.want(what, got, got == e, deso::error_name(e));
        } else if got != e {
            self.ran += 1;
            self.failed += 1;
            println!("abiprobe: FAIL {}: got {} ({}), want {}", what, got, deso::error_name(got), e);
        } else {
            self.ran += 1;
        }
    }
    fn errs(&mut self, what: &str, got: i64, es: &[i64]) {
        self.want(what, got, es.contains(&got), "one of the declared errors");
    }
    fn val(&mut self, what: &str, got: i64, ok: bool) {
        self.want(what, got, got >= 0 && ok, "a value");
    }
    /// An argument-order case: `ok` only with the arguments in the described order.
    fn order(&mut self, name: &str, got: i64, ok: bool) {
        self.want(name, got, got >= 0 && ok, "the result of the arguments in their order");
        if got >= 0 && ok {
            self.orders += 1;
            println!("abiprobe: order ok {}", name);
        }
    }
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn kind_of(h: u64) -> i64 {
    let r = sys(abi::SYS_HANDLE_INFO, [h, 0, 0, 0, 0, 0]);
    if r < 0 { r } else { ((r as u64) >> 32) as i64 }
}

fn p64(v: &mut [u64]) -> u64 {
    v.as_mut_ptr() as u64
}

/// A child of the order cases: 7 when the check holds, 9 when not.
fn child(mode: &str) -> i32 {
    let ok = match mode {
        "nofiles" => {
            let f = b"/bin/hello";
            kind_of(1) == abi::KIND_CONSOLE as i64
                && sys(abi::SYS_OPEN, [f.as_ptr() as u64, f.len() as u64, abi::O_READ, 0, 0, 0]) == abi::ERROR_ACCESS_DENIED
        }
        "slot5" => kind_of(5) == abi::KIND_PIPE as i64 && kind_of(1) == abi::ERROR_INVALID_HANDLE,
        _ => false,
    };
    if ok { 7 } else { 9 }
}

/// The argument order of every call with `order = "abiprobe"` in abi.toml.
fn order(p: &mut Probe) {
    let mut buf = [0u8; 4096];
    let b = buf.as_mut_ptr() as u64;
    let blen = buf.len() as u64;
    let mut out = [0u64; 2];
    let o = out.as_mut_ptr() as u64;
    // 40 bytes: longer than any handle number this program holds, so a length and a handle never
    // stand in for each other.
    let data = b"abiprobe argument order: forty bytes...";
    let s = |t: &[u8]| (t.as_ptr() as u64, t.len() as u64);

    // Streams: a pipe, then a second, empty one for wait_many.
    let mut two = [0u64; 2];
    let mut empty = [0u64; 2];
    if sys(abi::SYS_PIPE, [p64(&mut two), 0, 0, 0, 0, 0]) == 0 && sys(abi::SYS_PIPE, [p64(&mut empty), 0, 0, 0, 0, 0]) == 0 {
        let (r, w) = (two[0], two[1]);
        let n = sys(abi::SYS_WRITE, [w, data.as_ptr() as u64, data.len() as u64, 0, 0, 0]);
        p.order("SYS_WRITE", n, n == data.len() as i64);
        let n = sys(abi::SYS_READ, [r, b, 9, 0, 0, 0]);
        p.order("SYS_READ", n, n == 9 && buf[..9] == data[..9]);
        // The empty pipe is not readable, the first one is: the mask has bit 1 only.
        let list = [empty[0], abi::W_READABLE, r, abi::W_READABLE];
        let n = sys(abi::SYS_WAIT_MANY, [list.as_ptr() as u64, 2, 50, 0, 0, 0]);
        p.order("SYS_WAIT_MANY", n, n == 0b10);
        let n = sys(abi::SYS_DUP2, [r, 15, 0, 0, 0, 0]);
        p.order("SYS_DUP2", n, n == 15 && kind_of(15) == abi::KIND_PIPE as i64);
        sys(abi::SYS_CLOSE, [15, 0, 0, 0, 0, 0]);
        let n = sys(abi::SYS_HANDLE_DUP, [w, abi::R_WRITE, 0, 0, 0, 0]);
        let info = if n >= 0 { sys(abi::SYS_HANDLE_INFO, [n as u64, 0, 0, 0, 0, 0]) } else { -1 };
        p.order("SYS_HANDLE_DUP", n, info >= 0 && info as u64 == abi::KIND_PIPE << 32 | abi::R_WRITE);
        if n >= 0 {
            sys(abi::SYS_CLOSE, [n as u64, 0, 0, 0, 0, 0]);
        }

        // spawn_ex: the pipe's write end as the child's handle 5, nothing else.
        let me = b"/bin/abiprobe";
        let argv = b"abiprobe\0slot5\0";
        let map = [w, 5];
        let pid = sys(abi::SYS_SPAWN_EX, [me.as_ptr() as u64, me.len() as u64, argv.as_ptr() as u64, argv.len() as u64, map.as_ptr() as u64, 1]);
        let mut status = 0u64;
        let wr = if pid > 0 { sys(abi::SYS_WAIT, [pid as u64, &mut status as *mut u64 as u64, 0, 0, 0, 0]) } else { -1 };
        p.order("SYS_SPAWN_EX", pid, pid > 0 && wr == pid && status == 7);
        // A channel: a message of 6 bytes with the pipe's write end (moved to the
        // receiver: the sender's handle is gone after the send).
        let mut ch = [0u64; 2];
        if sys(abi::SYS_CHANNEL_CREATE, [p64(&mut ch), 0, 0, 0, 0, 0]) == 0 {
            let msg = b"order!";
            let hs = [w];
            let n = sys(abi::SYS_CHAN_SEND, [ch[0], msg.as_ptr() as u64, 6, hs.as_ptr() as u64, 1, 0]);
            p.order("SYS_CHAN_SEND", n, n == 0);
            let mut got = [0u64; 4];
            let mut info = [0u64; 3];
            let n = sys(abi::SYS_CHAN_RECV, [ch[1], b, blen, p64(&mut got), 4, p64(&mut info)]);
            p.order("SYS_CHAN_RECV", n, n == 6 && &buf[..6] == msg && info[0] == 6 && info[1] == 1 && kind_of(got[0]) == abi::KIND_PIPE as i64);
            if info[1] == 1 {
                sys(abi::SYS_CLOSE, [got[0], 0, 0, 0, 0, 0]);
            }
            for h in ch {
                sys(abi::SYS_CLOSE, [h, 0, 0, 0, 0, 0]);
            }
        }

        for h in [r, w, empty[0], empty[1]] {
            sys(abi::SYS_CLOSE, [h, 0, 0, 0, 0, 0]);
        }
    }

    // spawn with SPAWN_NO_FILES and STDIO: the child has the console and no file access; wait sees 7.
    let me = b"/bin/abiprobe";
    let argv = b"abiprobe\0nofiles\0";
    let pid = sys(abi::SYS_SPAWN, [me.as_ptr() as u64, me.len() as u64, argv.as_ptr() as u64, argv.len() as u64, abi::SPAWN_NO_FILES, abi::STDIO]);
    let mut status = 0u64;
    let st = &mut status as *mut u64 as u64;
    let wr = if pid > 0 { sys(abi::SYS_WAIT, [pid as u64, st, 0, 0, 0, 0]) } else { -1 };
    p.order("SYS_SPAWN", pid, pid > 0 && wr == pid && status == 7);
    p.order("SYS_WAIT", wr, pid > 0 && wr == pid && status == 7);

    // Files and directories.
    let (bin, bin_n) = s(b"/bin");
    let (hello, hello_n) = s(b"/bin/hello");
    let f = sys(abi::SYS_OPEN, [hello, hello_n, abi::O_READ, 0, 0, 0]);
    p.order("SYS_OPEN", f, kind_of(f as u64) == abi::KIND_FILE as i64);
    if f >= 0 {
        let n = sys(abi::SYS_SEEK, [f as u64, 23, abi::SEEK_SET, 0, 0, 0]);
        p.order("SYS_SEEK", n, n == 23);
        sys(abi::SYS_CLOSE, [f as u64, 0, 0, 0, 0, 0]);
    }
    let n = sys(abi::SYS_STAT, [hello, hello_n, o, 0, 0, 0]);
    p.order("SYS_STAT", n, n == 0 && out[0] == 0 && out[1] > 0);
    let n = sys(abi::SYS_READDIR, [bin, bin_n, b, blen, 0, 0]);
    p.order("SYS_READDIR", n, n > 0 && has(&buf[..n as usize], b"hello"));
    let n = sys(abi::SYS_CHDIR, [bin, bin_n, 0, 0, 0, 0]);
    let c = sys(abi::SYS_GETCWD, [b, blen, 0, 0, 0, 0]);
    p.order("SYS_CHDIR", n, n == 0 && c >= 4 && &buf[..4] == b"/bin");
    sys(abi::SYS_CHDIR, [b"/".as_ptr() as u64, 1, 0, 0, 0, 0]);
    let c = sys(abi::SYS_GETCWD, [b, blen, 0, 0, 0, 0]);
    p.order("SYS_GETCWD", c, c >= 1 && buf[..c as usize].iter().filter(|&&x| x != 0).eq(b"/".iter()));
    let (dir, dir_n) = s(b"/abiprobe-order");
    let n = sys(abi::SYS_MKDIR, [dir, dir_n, 0, 0, 0, 0]);
    let st1 = sys(abi::SYS_STAT, [dir, dir_n, o, 0, 0, 0]);
    p.order("SYS_MKDIR", n, n == 0 && st1 == 0 && out[0] == 1);
    let n = sys(abi::SYS_UNLINK, [dir, dir_n, 0, 0, 0, 0]);
    let st2 = sys(abi::SYS_STAT, [dir, dir_n, o, 0, 0, 0]);
    p.order("SYS_UNLINK", n, n == 0 && st2 == abi::ERROR_NOT_FOUND);

    // Through directory handles: /bin (to read) and / (to read and write).
    let db = sys(abi::SYS_DIR_OPEN, [bin, bin_n, abi::O_READ, 0, 0, 0]);
    let listed = if db >= 0 { sys(abi::SYS_READDIRAT, [db as u64, b".".as_ptr() as u64, 1, b, blen, 0]) } else { -1 };
    p.order("SYS_DIR_OPEN", db, kind_of(db as u64) == abi::KIND_DIR as i64 && listed > 0 && has(&buf[..listed as usize], b"hello"));
    if db >= 0 {
        let (h5, h5_n) = s(b"hello");
        let f = sys(abi::SYS_OPENAT, [db as u64, h5, h5_n, abi::O_READ, 0, 0]);
        p.order("SYS_OPENAT", f, kind_of(f as u64) == abi::KIND_FILE as i64);
        if f >= 0 {
            sys(abi::SYS_CLOSE, [f as u64, 0, 0, 0, 0, 0]);
        }
        sys(abi::SYS_CLOSE, [db as u64, 0, 0, 0, 0, 0]);
    }
    let dr = sys(abi::SYS_DIR_OPEN, [b"/".as_ptr() as u64, 1, abi::O_READ | abi::O_WRITE, 0, 0, 0]);
    if dr >= 0 {
        let d = dr as u64;
        let (sub, sub_n) = s(b"bin");
        let n = sys(abi::SYS_READDIRAT, [d, sub, sub_n, b, blen, 0]);
        p.order("SYS_READDIRAT", n, n > 0 && has(&buf[..n as usize], b"hello"));
        let mut cursor = 0u64;
        let n = sys(abi::SYS_READDIR_PART, [d, sub, sub_n, b, blen, &mut cursor as *mut u64 as u64]);
        p.order("SYS_READDIR_PART", n, n > 0 && has(&buf[..n as usize], b"hello") && cursor != 0);
        let n = sys(abi::SYS_STATAT, [d, sub, sub_n, o, 0, 0]);
        p.order("SYS_STATAT", n, n == 0 && out[0] == 1);
        let (at, at_n) = s(b"abiprobe-order-at");
        let n = sys(abi::SYS_MKDIRAT, [d, at, at_n, 0, 0, 0]);
        let st1 = sys(abi::SYS_STATAT, [d, at, at_n, o, 0, 0]);
        p.order("SYS_MKDIRAT", n, n == 0 && st1 == 0 && out[0] == 1);
        let n = sys(abi::SYS_UNLINKAT, [d, at, at_n, 0, 0, 0]);
        let st2 = sys(abi::SYS_STATAT, [d, at, at_n, o, 0, 0]);
        p.order("SYS_UNLINKAT", n, n == 0 && st2 == abi::ERROR_NOT_FOUND);
        sys(abi::SYS_CLOSE, [d, 0, 0, 0, 0, 0]);
    }

    // Text out of the kernel.
    let n = sys(abi::SYS_TASKS, [b, blen, 0, 0, 0, 0]);
    p.order("SYS_TASKS", n, n > 0 && has(&buf[..n as usize], b"abiprobe"));
    let (topic, topic_n) = s(b"rights");
    let n = sys(abi::SYS_SYSINFO, [topic, topic_n, b, blen, 0, 0]);
    p.order("SYS_SYSINFO", n, n > 6 && &buf[..7] == b"0 exit ");
    let n = sys(abi::SYS_GETRANDOM, [b, 24, 0, 0, 0, 0]);
    p.order("SYS_GETRANDOM", n, n == 24);
    let n = sys(abi::SYS_TIME_BOUND, [b, abi::TIME_BOUND_LEN as u64, 0, 0, 0, 0]);
    p.order("SYS_TIME_BOUND", n, n == abi::TIME_BOUND_LEN as i64);

    // Memory: two pages, the first unmapped, the second still there.
    let m = sys(abi::SYS_MMAP, [8192, abi::PROT_READ | abi::PROT_WRITE, 0, 0, 0, 0]);
    let in_area = m > 0 && (m as u64) >= abi::MMAP_BASE && (m as u64) < abi::MMAP_END;
    if in_area {
        unsafe {
            core::ptr::write_volatile(m as *mut u8, 1);
            core::ptr::write_volatile((m + 4096) as *mut u8, 2);
        }
    }
    p.order("SYS_MMAP", m, in_area);
    if in_area {
        let n = sys(abi::SYS_MUNMAP, [m as u64, 4096, 0, 0, 0, 0]);
        let second = unsafe { core::ptr::read_volatile((m + 4096) as *const u8) };
        p.order("SYS_MUNMAP", n, n == 0 && second == 2);
        sys(abi::SYS_MUNMAP, [m as u64 + 4096, 4096, 0, 0, 0, 0]);
    }
    let sh = sys(abi::SYS_SHM_CREATE, [8192, 0, 0, 0, 0, 0]);
    if sh >= 0 {
        let a = sys(abi::SYS_SHM_MAP, [sh as u64, abi::PROT_READ | abi::PROT_WRITE, 0, 0, 0, 0]);
        if a > 0 {
            unsafe { core::ptr::write_volatile((a + 4096) as *mut u8, 3) };
        }
        p.order("SYS_SHM_MAP", a, a > 0);
        sys(abi::SYS_CLOSE, [sh as u64, 0, 0, 0, 0, 0]);
    }
}

fn main(args: Args) -> i32 {
    match args.get(1) {
        Some("exit7") => {
            sys(abi::SYS_EXIT, [7, 0, 0, 0, 0, 0]);
            return 1; // never reached
        }
        Some(m @ ("nofiles" | "slot5")) => return child(m),
        _ => {}
    }
    let mut p = Probe { ran: 0, failed: 0, orders: 0 };

    // 1. The gate: every rights row, a handle that does not exist in its first handle argument.
    let mut later = 0;
    for &(nr, reg, pos, name) in table::HANDLE_ARGS.iter() {
        if pos > 0 {
            later += 1;
            continue;
        }
        let mut a = [0u64; 6];
        a[reg] = NO_HANDLE;
        p.err(name, sys(nr, a), abi::ERROR_INVALID_HANDLE);
    }
    let gate = p.ran;

    // A handle without rights: the gate refuses what needs a right, lets the kind-only rows through.
    let bare = sys(abi::SYS_HANDLE_DUP, [1, 0, 0, 0, 0, 0]);
    p.val("handle_dup(1, no rights)", bare, true);
    if bare >= 0 {
        let h = bare as u64;
        let msg = b"x";
        p.err("write without WRITE", sys(abi::SYS_WRITE, [h, msg.as_ptr() as u64, 1, 0, 0, 0]), abi::ERROR_ACCESS_DENIED);
        p.err("dup without DUP", sys(abi::SYS_DUP, [h, 0, 0, 0, 0, 0]), abi::ERROR_ACCESS_DENIED);
        let info = sys(abi::SYS_HANDLE_INFO, [h, 0, 0, 0, 0, 0]);
        p.val("handle_info of a handle without rights", info, info >= 0 && (info as u64) & 0xFFFF_FFFF == 0 && (info as u64) >> 32 == abi::KIND_CONSOLE);
        p.err("close", sys(abi::SYS_CLOSE, [h, 0, 0, 0, 0, 0]), 0);
        p.err("close twice", sys(abi::SYS_CLOSE, [h, 0, 0, 0, 0, 0]), abi::ERROR_INVALID_HANDLE);
    }

    // 2. Numbers without a call.
    for &r in table::RESERVED.iter() {
        p.err("reserved number", sys(r, [0; 6]), abi::ERROR_NOT_IMPLEMENTED);
    }
    p.err("first number past the table", sys(table::SYSCALL_COUNT, [0; 6]), abi::ERROR_NOT_IMPLEMENTED);
    p.err("number 0xFFFF", sys(0xFFFF, [0; 6]), abi::ERROR_NOT_IMPLEMENTED);

    // 3. Bad pointers: never a crash, ERROR_INVALID_ADDRESS.
    for bad in [BAD_PTR, KERNEL_PTR] {
        let ia = abi::ERROR_INVALID_ADDRESS;
        p.err("write from a bad pointer", sys(abi::SYS_WRITE, [1, bad, 4, 0, 0, 0]), ia);
        p.err("open with a bad path", sys(abi::SYS_OPEN, [bad, 4, abi::O_READ, 0, 0, 0]), ia);
        p.err("stat with a bad path", sys(abi::SYS_STAT, [bad, 4, 0, 0, 0, 0]), ia);
        p.err("pipe into a bad pointer", sys(abi::SYS_PIPE, [bad, 0, 0, 0, 0, 0]), ia);
        p.err("channel_create into a bad pointer", sys(abi::SYS_CHANNEL_CREATE, [bad, 0, 0, 0, 0, 0]), ia);
        p.err("time into a bad pointer", sys(abi::SYS_TIME, [bad, 0, 0, 0, 0, 0]), ia);
        p.err("getrandom into a bad pointer", sys(abi::SYS_GETRANDOM, [bad, 16, 0, 0, 0, 0]), ia);
        p.err("spawn with a bad path", sys(abi::SYS_SPAWN, [bad, 4, 0, 0, 0, abi::STDIO]), ia);
        p.err("wait_many with a bad list", sys(abi::SYS_WAIT_MANY, [bad, 1, 0, 0, 0, 0]), ia);
    }

    // 4. Ordinary calls with known results.
    p.val("getpid", sys(abi::SYS_GETPID, [0; 6]), sys(abi::SYS_GETPID, [0; 6]) > 0);
    p.val("getppid", sys(abi::SYS_GETPPID, [0; 6]), true);
    p.val("uptime", sys(abi::SYS_UPTIME, [0; 6]), sys(abi::SYS_UPTIME, [0; 6]) > 0);
    p.err("yield", sys(abi::SYS_YIELD, [0; 6]), 0);
    p.err("sleep 1 ms", sys(abi::SYS_SLEEP, [1, 0, 0, 0, 0, 0]), 0);
    let mut buf = [0u8; 4096];
    let b = buf.as_mut_ptr() as u64;
    let r = sys(abi::SYS_GETCWD, [b, buf.len() as u64, 0, 0, 0, 0]);
    p.val("getcwd", r, r >= 1 && buf[0] == b'/');
    p.err("chdir /", sys(abi::SYS_CHDIR, [b"/".as_ptr() as u64, 1, 0, 0, 0, 0]), 0);
    p.val("readdir /", sys(abi::SYS_READDIR, [b"/".as_ptr() as u64, 1, b, buf.len() as u64, 0, 0]), true);
    let missing = b"/abiprobe-missing";
    p.err("open a missing file", sys(abi::SYS_OPEN, [missing.as_ptr() as u64, missing.len() as u64, abi::O_READ, 0, 0, 0]), abi::ERROR_NOT_FOUND);
    p.err("stat a missing file", sys(abi::SYS_STAT, [missing.as_ptr() as u64, missing.len() as u64, b, 0, 0, 0]), abi::ERROR_NOT_FOUND);
    let dir = sys(abi::SYS_DIR_OPEN, [b"/".as_ptr() as u64, 1, abi::O_READ, 0, 0, 0]);
    p.val("dir_open /", dir, true);
    if dir >= 0 {
        let d = dir as u64;
        p.val("readdirat /", sys(abi::SYS_READDIRAT, [d, b".".as_ptr() as u64, 1, b, buf.len() as u64, 0]), true);
        p.err("statat bin", sys(abi::SYS_STATAT, [d, b"bin".as_ptr() as u64, 3, b, 0, 0]), 0);
        let mut cursor = 0u64;
        p.val("readdir_part /", sys(abi::SYS_READDIR_PART, [d, b".".as_ptr() as u64, 1, b, buf.len() as u64, &mut cursor as *mut u64 as u64]), true);
        p.err("mkdirat without WRITE", sys(abi::SYS_MKDIRAT, [d, b"x".as_ptr() as u64, 1, 0, 0, 0]), abi::ERROR_ACCESS_DENIED);
        p.err("close the directory", sys(abi::SYS_CLOSE, [d, 0, 0, 0, 0, 0]), 0);
    }
    p.errs("kill a process that does not exist", sys(abi::SYS_KILL, [0xFFFF_FFFF, 0, 0, 0, 0, 0]), &[abi::ERROR_NO_PROCESS, abi::ERROR_NOT_PERMITTED]);
    let mut status = 0u64;
    let st = &mut status as *mut u64 as u64;
    p.err("wait without children", sys(abi::SYS_WAIT, [abi::WAIT_ANY, st, abi::WNOHANG, 0, 0, 0]), abi::ERROR_NO_CHILD);
    p.val("tasks", sys(abi::SYS_TASKS, [b, buf.len() as u64, 0, 0, 0, 0]), true);
    let topic = b"rights";
    p.val("sysinfo rights", sys(abi::SYS_SYSINFO, [topic.as_ptr() as u64, topic.len() as u64, b, buf.len() as u64, 0, 0]), true);
    let nope = b"abiprobe-no-such-topic";
    p.err("sysinfo of an unknown topic", sys(abi::SYS_SYSINFO, [nope.as_ptr() as u64, nope.len() as u64, b, buf.len() as u64, 0, 0]), abi::ERROR_NOT_FOUND);
    p.err("getrandom 16", sys(abi::SYS_GETRANDOM, [b, 16, 0, 0, 0, 0]), 16);
    p.err("getrandom with flags", sys(abi::SYS_GETRANDOM, [b, 16, 1, 0, 0, 0]), abi::ERROR_INVALID_ARGUMENT);
    p.err("getrandom over GETRANDOM_MAX", sys(abi::SYS_GETRANDOM, [b, abi::GETRANDOM_MAX as u64 + 1, 0, 0, 0, 0]), abi::ERROR_INVALID_ARGUMENT);
    p.err("time", sys(abi::SYS_TIME, [b, 0, 0, 0, 0, 0]), 0);
    p.err("time_bound", sys(abi::SYS_TIME_BOUND, [b, abi::TIME_BOUND_LEN as u64, 0, 0, 0, 0]), abi::TIME_BOUND_LEN as i64);
    p.err("time_bound into a short buffer", sys(abi::SYS_TIME_BOUND, [b, 8, 0, 0, 0, 0]), abi::ERROR_INVALID_ARGUMENT);

    // Memory.
    let end = sys(abi::SYS_BRK, [0; 6]);
    p.val("brk(0)", end, end > 0);
    let m = sys(abi::SYS_MMAP, [4096, abi::PROT_READ | abi::PROT_WRITE, 0, 0, 0, 0]);
    p.val("mmap 4 KiB", m, (m as u64) >= abi::MMAP_BASE && (m as u64) < abi::MMAP_END);
    if m > 0 {
        unsafe { core::ptr::write_volatile(m as *mut u8, 7) };
        p.err("munmap", sys(abi::SYS_MUNMAP, [m as u64, 4096, 0, 0, 0, 0]), 0);
    }

    // Handles: pipe, dup, dup2, seek, channels, shared memory.
    let mut two = [0u64; 2];
    let r = sys(abi::SYS_PIPE, [two.as_mut_ptr() as u64, 0, 0, 0, 0, 0]);
    p.err("pipe", r, 0);
    if r == 0 {
        let k = sys(abi::SYS_HANDLE_INFO, [two[0], 0, 0, 0, 0, 0]);
        p.val("pipe kind", k, k >= 0 && (k as u64) >> 32 == abi::KIND_PIPE);
        p.err("pipe write", sys(abi::SYS_WRITE, [two[1], b"abc".as_ptr() as u64, 3, 0, 0, 0]), 3);
        p.err("pipe read", sys(abi::SYS_READ, [two[0], b, 3, 0, 0, 0]), 3);
        p.err("seek on a pipe", sys(abi::SYS_SEEK, [two[0], 0, abi::SEEK_SET, 0, 0, 0]), abi::ERROR_NOT_SEEKABLE);
        let d = sys(abi::SYS_DUP, [two[0], 0, 0, 0, 0, 0]);
        p.val("dup", d, d >= 3);
        p.err("dup2 to slot 15", sys(abi::SYS_DUP2, [two[0], 15, 0, 0, 0, 0]), 15);
        for h in [two[0], two[1], d as u64, 15] {
            p.err("close", sys(abi::SYS_CLOSE, [h, 0, 0, 0, 0, 0]), 0);
        }
    }
    let r = sys(abi::SYS_CHANNEL_CREATE, [two.as_mut_ptr() as u64, 0, 0, 0, 0, 0]);
    p.err("channel_create", r, 0);
    if r == 0 {
        let mut info = [0u64; 4];
        p.err("chan_send", sys(abi::SYS_CHAN_SEND, [two[0], b"ping".as_ptr() as u64, 4, 0, 0, 0]), 0);
        p.err("chan_recv", sys(abi::SYS_CHAN_RECV, [two[1], b, buf.len() as u64, 0, 0, info.as_mut_ptr() as u64]), 4);
        p.err("chan_recv on an empty channel, CHAN_NONBLOCK", sys(abi::SYS_CHAN_RECV, [two[1], b, buf.len() as u64, 0, abi::CHAN_NONBLOCK << 32, info.as_mut_ptr() as u64]), abi::ERROR_WOULD_BLOCK);
        p.err("chan_send over MSG_MAX", sys(abi::SYS_CHAN_SEND, [two[0], b, abi::MSG_MAX as u64 + 1, 0, 0, 0]), abi::ERROR_MESSAGE_TOO_LARGE);
        for h in two {
            p.err("close", sys(abi::SYS_CLOSE, [h, 0, 0, 0, 0, 0]), 0);
        }
    }
    let s = sys(abi::SYS_SHM_CREATE, [4096, 0, 0, 0, 0, 0]);
    p.val("shm_create", s, true);
    if s >= 0 {
        p.err("shm_size", sys(abi::SYS_SHM_SIZE, [s as u64, 0, 0, 0, 0, 0]), 4096);
        p.val("shm_map", sys(abi::SYS_SHM_MAP, [s as u64, abi::PROT_READ | abi::PROT_WRITE, 0, 0, 0, 0]), true);
        p.err("close", sys(abi::SYS_CLOSE, [s as u64, 0, 0, 0, 0, 0]), 0);
    }

    // A child: SYS_SPAWN, SYS_EXIT with 7, SYS_WAIT sees 7.
    let me = b"/bin/abiprobe";
    let argv = b"abiprobe\0exit7\0";
    let pid = sys(abi::SYS_SPAWN, [me.as_ptr() as u64, me.len() as u64, argv.as_ptr() as u64, argv.len() as u64, 0, abi::STDIO]);
    p.val("spawn a child", pid, pid > 0);
    if pid > 0 {
        let w = sys(abi::SYS_WAIT, [pid as u64, st, 0, 0, 0, 0]);
        p.want("wait for the child: exit status 7", w, w == pid && status == 7, "the pid and status 7");
    }

    // 5. The argument order.
    order(&mut p);

    println!(
        "abiprobe: ABI {}.{}, {} probes ({} rights rows through the gate, {} later handle arguments left to the kernel's gate test, {} reserved, {} argument orders), {} failed",
        abi::ABI_MAJOR,
        abi::ABI_MINOR,
        p.ran,
        gate,
        later,
        table::RESERVED.len(),
        p.orders,
        p.failed
    );
    if p.failed == 0 { 0 } else { 1 }
}
