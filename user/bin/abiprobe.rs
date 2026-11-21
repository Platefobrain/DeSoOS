// abiprobe – the ABI description against the running kernel (ABI TEST, test 5 of the V081
// plan): every number and every error code it uses comes from user/lib/abi_generated.rs,
// which tools/abigen.py generates from abi/abi.toml – the chain abi.toml -> generator ->
// constants -> program -> kernel in one run.
//
//   abiprobe          the probes; one line "abiprobe: ABI x.y, N probes (...), 0 failed" and code
//                     0, or a FAIL line per failed probe and code 1
//   abiprobe exit7    exits with 7 through SYS_EXIT (the parent's SYS_WAIT must see 7)
//
// The probes: every row of the rights table gets a handle that does not exist in its first
// handle argument (ERROR_INVALID_HANDLE – the gate runs before the call); a handle without
// rights (ERROR_ACCESS_DENIED); reserved numbers and the first number past the table
// (ERROR_NOT_IMPLEMENTED); bad pointers (ERROR_INVALID_ADDRESS); and the ordinary calls with
// arguments whose result is known.  Only raw syscalls with abi:: numbers – the library's
// wrappers are not used, so a wrapper cannot hide a difference.
#![no_std]
#![no_main]

#[path = "../lib/deso.rs"]
#[macro_use]
mod deso;

#[path = "../lib/abi_generated.rs"]
mod abi;

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
}

fn main(args: Args) -> i32 {
    if args.get(1) == Some("exit7") {
        sys(abi::SYS_EXIT, [7, 0, 0, 0, 0, 0]);
        return 1; // never reached
    }
    let mut p = Probe { ran: 0, failed: 0 };

    // 1. The gate: every row of the rights table, a handle that does not exist.
    for &(nr, reg, name) in abi::HANDLE_ARGS.iter() {
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
    for &r in abi::RESERVED.iter() {
        p.err("reserved number", sys(r, [0; 6]), abi::ERROR_NOT_IMPLEMENTED);
    }
    p.err("first number past the table", sys(abi::SYSCALL_COUNT, [0; 6]), abi::ERROR_NOT_IMPLEMENTED);
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

    println!(
        "abiprobe: ABI {}.{}, {} probes ({} rights-table rows through the gate, {} reserved), {} failed",
        abi::ABI_MAJOR,
        abi::ABI_MINOR,
        p.ran,
        gate,
        abi::RESERVED.len(),
        p.failed
    );
    if p.failed == 0 { 0 } else { 1 }
}
