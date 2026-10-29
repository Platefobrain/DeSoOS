// Syscall rights table – one row per syscall: which arguments are handles, of
// which kind, and which rights each needs.  `syscall_dispatch` asks `check`
// before the call is decoded (one gate for every syscall); the functions in
// syscalls.rs only use the objects.
//
//   - a handle that does not exist, or is of the wrong kind  -> ERROR_INVALID_HANDLE
//   - a handle without a right the row names                 -> ERROR_ACCESS_DENIED
//   - a syscall number without a row                         -> ERROR_NOT_IMPLEMENTED
//
// Handles passed in a list in process memory (chan_send's handles, the
// wait_many list, spawn / spawn_ex) are checked by the call itself – the row
// says so in `in_call`.  `path`: the call names a path (refused in the file
// sandbox, see `is_path_call`).
//
// The table is exported as text (sysinfo "rights") – RIGHTS TEST takes every
// right away in turn, through real syscalls, and expects ERROR_ACCESS_DENIED each time.

use alloc::string::String;
use core::fmt::Write;

use super::process::{kind, rights::*, Handle};
use super::syscalls::*;
use crate::arch::x86_64::syscall::SyscallFrame;

/// Kind masks (bit = handle_info kind).
const fn k(kind: u64) -> u16 {
    1 << kind
}
const CONSOLE: u16 = k(kind::CONSOLE);
const FILE: u16 = k(kind::FILE);
const PIPE: u16 = k(kind::PIPE);
const CHANNEL: u16 = k(kind::CHANNEL);
const SHM: u16 = k(kind::SHM);
const HW_ROOT: u16 = k(kind::HW_ROOT);
const DEVICE: u16 = k(kind::DEVICE);
const IRQ: u16 = k(kind::IRQ);
const SYSCTL: u16 = k(kind::SYSCTL);
const INPUT: u16 = k(kind::INPUT);
const BLK: u16 = k(kind::BLK);
const DIR: u16 = k(kind::DIR);
/// Data streams: read / write.
const STREAM: u16 = CONSOLE | FILE | PIPE;
const ANY: u16 = 0xFFFE;

/// An extra right needed when a flag bit is set in another argument.
#[derive(Clone, Copy)]
pub struct Cond {
    /// 1 + the argument register with the flags; 0 = no condition.
    pub reg: u8,
    pub bit: u64,
    pub right: u32,
}

const NO_COND: Cond = Cond { reg: 0, bit: 0, right: 0 };

/// One handle argument.
#[derive(Clone, Copy)]
pub struct Arg {
    /// Argument register: 0 rdi, 1 rsi, 2 rdx, 3 r10, 4 r8, 5 r9.
    pub reg: u8,
    pub kinds: u16,
    /// Rights the handle must have always (0 = the kind is enough).
    pub need: u32,
    /// Rights needed only when the call asks for them (e.g. a writable mapping).
    pub conds: [Cond; 2],
}

const fn h(reg: u8, kinds: u16, need: u32) -> Arg {
    Arg { reg, kinds, need, conds: [NO_COND; 2] }
}

/// A mapping: MAP_READ always, MAP_WRITE when `prot` (argument `prot_reg`) asks for writing.
const fn map(reg: u8, kinds: u16, prot_reg: u8) -> Arg {
    Arg { reg, kinds, need: MAP_READ, conds: [Cond { reg: prot_reg + 1, bit: super::vm::PROT_WRITE, right: MAP_WRITE }, NO_COND] }
}

/// Opening through a directory: READ when the flags (argument `flags_reg`) ask to
/// read, WRITE when they ask to write.
const fn open_in(reg: u8, flags_reg: u8) -> Arg {
    Arg {
        reg,
        kinds: DIR,
        need: 0,
        conds: [Cond { reg: flags_reg + 1, bit: O_READ, right: READ }, Cond { reg: flags_reg + 1, bit: O_WRITE, right: WRITE }],
    }
}

pub struct Rule {
    pub name: &'static str,
    pub path: bool,
    pub args: &'static [Arg],
    /// Handles checked by the call itself (a list in process memory); "" = none.
    pub in_call: &'static str,
}

const fn plain(name: &'static str) -> Option<Rule> {
    Some(Rule { name, path: false, args: &[], in_call: "" })
}
const fn path(name: &'static str) -> Option<Rule> {
    Some(Rule { name, path: true, args: &[], in_call: "" })
}
const fn with(name: &'static str, args: &'static [Arg]) -> Option<Rule> {
    Some(Rule { name, path: false, args, in_call: "" })
}

/// Indexed by syscall number.
pub static TABLE: [Option<Rule>; 57] = {
    let mut t = [const { None }; 57];
    t[SYS_EXIT as usize] = plain("exit");
    t[SYS_WRITE as usize] = with("write", &[h(0, STREAM, WRITE)]);
    t[SYS_READ as usize] = with("read", &[h(0, STREAM, READ)]);
    t[SYS_OPEN as usize] = path("open");
    t[SYS_CLOSE as usize] = with("close", &[h(0, ANY, 0)]);
    t[SYS_GETPID as usize] = plain("getpid");
    t[SYS_SLEEP as usize] = plain("sleep");
    t[SYS_YIELD as usize] = plain("yield");
    t[SYS_UPTIME as usize] = plain("uptime");
    t[SYS_SPAWN as usize] = Some(Rule { name: "spawn", path: true, args: &[], in_call: "stdio handles: DUP" });
    t[SYS_WAIT as usize] = plain("wait");
    t[SYS_GETPPID as usize] = plain("getppid");
    t[SYS_KILL as usize] = Some(Rule { name: "kill", path: false, args: &[], in_call: "the target: the caller or its descendants" });
    t[SYS_CHDIR as usize] = path("chdir");
    t[SYS_GETCWD as usize] = plain("getcwd");
    t[SYS_READDIR as usize] = path("readdir");
    t[SYS_STAT as usize] = path("stat");
    t[SYS_MKDIR as usize] = path("mkdir");
    t[SYS_UNLINK as usize] = path("unlink");
    t[SYS_READKEY as usize] = plain("readkey");
    t[SYS_TASKS as usize] = plain("tasks");
    t[SYS_DUP as usize] = with("dup", &[h(0, ANY, DUP)]);
    t[SYS_DUP2 as usize] = with("dup2", &[h(0, ANY, DUP)]);
    t[SYS_SEEK as usize] = with("seek", &[h(0, ANY, 0)]);
    t[SYS_PIPE as usize] = plain("pipe");
    t[SYS_BRK as usize] = plain("brk");
    t[SYS_MMAP as usize] = plain("mmap");
    t[SYS_MUNMAP as usize] = plain("munmap");
    t[SYS_HANDLE_DUP as usize] = with("handle_dup", &[h(0, ANY, DUP)]);
    t[SYS_HANDLE_INFO as usize] = with("handle_info", &[h(0, ANY, 0)]);
    t[SYS_CHANNEL_CREATE as usize] = plain("channel_create");
    t[SYS_CHAN_SEND as usize] = Some(Rule { name: "chan_send", path: false, args: &[h(0, CHANNEL, SEND)], in_call: "handles in the message: TRANSFER" });
    t[SYS_CHAN_RECV as usize] = with("chan_recv", &[h(0, CHANNEL, RECV)]);
    t[SYS_SHM_CREATE as usize] = plain("shm_create");
    t[SYS_SHM_MAP as usize] = with("shm_map", &[map(0, SHM, 1)]);
    t[SYS_SPAWN_EX as usize] = Some(Rule { name: "spawn_ex", path: true, args: &[], in_call: "handles in the map: DUP" });
    t[SYS_SHM_SIZE as usize] = with("shm_size", &[h(0, SHM, 0)]);
    t[SYS_WAIT_MANY as usize] = Some(Rule { name: "wait_many", path: false, args: &[], in_call: "list: RECV / SEND (channel), READ / WRITE (pipe), RECV (interrupt)" });
    t[SYS_DEV_CLAIM as usize] = with("dev_claim", &[h(0, HW_ROOT, 0)]);
    t[SYS_DEV_INFO as usize] = with("dev_info", &[h(0, DEVICE, 0)]);
    t[SYS_DEV_MAP as usize] = with("dev_map", &[map(0, DEVICE, 2)]);
    t[SYS_IRQ_BIND as usize] = with("irq_bind", &[h(0, DEVICE, MAP_WRITE)]);
    t[SYS_IRQ_READ as usize] = with("irq_read", &[h(0, IRQ, RECV)]);
    t[SYS_DMA_ALLOC as usize] = with("dma_alloc", &[h(0, DEVICE, MAP_WRITE)]);
    t[SYS_DMA_PHYS as usize] = with("dma_phys", &[h(0, SHM, 0)]);
    t[SYS_SYSINFO as usize] = plain("sysinfo");
    // The result text goes to the handle in r10 when there is any (checked by the call: WRITE).
    t[SYS_SYSCTL as usize] = Some(Rule { name: "sysctl", path: false, args: &[h(0, SYSCTL, 0)], in_call: "output handle: WRITE" });
    t[SYS_DEV_FIND as usize] = with("dev_find", &[h(0, HW_ROOT, 0)]);
    t[SYS_INPUT_INJECT as usize] = with("input_inject", &[h(0, INPUT, WRITE)]);
    t[SYS_BLK_ATTACH as usize] =
        with("blk_attach", &[h(0, BLK, WRITE), h(1, CHANNEL, SEND | RECV | TRANSFER), h(2, SHM, MAP_READ)]);
    t[SYS_DIR_OPEN as usize] = path("dir_open");
    t[SYS_OPENAT as usize] = with("openat", &[open_in(0, 3)]);
    t[SYS_READDIRAT as usize] = with("readdirat", &[h(0, DIR, READ)]);
    t[SYS_STATAT as usize] = with("statat", &[h(0, DIR, READ)]);
    t[SYS_MKDIRAT as usize] = with("mkdirat", &[h(0, DIR, WRITE)]);
    t[SYS_UNLINKAT as usize] = with("unlinkat", &[h(0, DIR, WRITE)]);
    t
};

/// The rights a handle argument needs with these argument values.
#[inline]
pub fn need_of(a: &Arg, args: &[u64; 6]) -> u32 {
    let mut need = a.need;
    for c in &a.conds {
        if c.reg != 0 && args[(c.reg - 1) as usize] & c.bit != 0 {
            need |= c.right;
        }
    }
    need
}

/// The gate: every handle argument of syscall `nr` exists, is of the right kind
/// and has the rights.  `lookup` gives (kind, rights) of a handle number.
#[inline]
pub fn check_with(nr: u64, args: &[u64; 6], lookup: impl Fn(u64) -> Result<(u64, u32), i64>) -> Result<(), i64> {
    let Some(Some(rule)) = TABLE.get(nr as usize) else { return Err(ERROR_NOT_IMPLEMENTED) };
    for a in rule.args {
        let (kd, have) = lookup(args[a.reg as usize])?;
        if a.kinds & (1u16 << (kd & 15)) == 0 {
            return Err(ERROR_INVALID_HANDLE);
        }
        let need = need_of(a, args);
        if have & need != need {
            return Err(ERROR_ACCESS_DENIED);
        }
    }
    Ok(())
}

pub fn frame_args(f: &SyscallFrame) -> [u64; 6] {
    [f.rdi, f.rsi, f.rdx, f.r10, f.r8, f.r9]
}

/// The gate for a call from process `p`.
#[inline]
pub fn check(p: &super::Process, f: &SyscallFrame) -> Result<(), i64> {
    check_with(f.rax, &frame_args(f), |n| p.handle(n).map(|h: &Handle| (h.kind(), h.rights)))
}

/// The first missing right of a refused call (audit) – 0 when none is missing.
pub fn missing(p: &super::Process, f: &SyscallFrame) -> u32 {
    let Some(Some(rule)) = TABLE.get(f.rax as usize) else { return 0 };
    let args = frame_args(f);
    for a in rule.args {
        if let Ok(hd) = p.handle(args[a.reg as usize]) {
            let need = need_of(a, &args);
            if hd.rights & need != need {
                return need & !hd.rights;
            }
        }
    }
    0
}

/// System calls that take a path – refused in the file sandbox.
pub fn is_path_call(nr: u64) -> bool {
    matches!(TABLE.get(nr as usize), Some(Some(r)) if r.path)
}

/// The table as text (sysinfo "rights"), one line per syscall:
/// `nr name path|- [reg:kinds:need[+creg:bit:right]... ...] [| checked in the call: ...]`
/// (kinds, need, bit and right in hex; `+creg:bit:right` – `right` is also needed
/// when argument `creg` has `bit` set).
pub fn text() -> String {
    let mut s = String::new();
    for (nr, r) in TABLE.iter().enumerate() {
        let Some(r) = r else { continue };
        let _ = write!(s, "{} {} {}", nr, r.name, if r.path { "path" } else { "-" });
        for a in r.args {
            let _ = write!(s, " {}:{:x}:{:x}", a.reg, a.kinds, a.need);
            for c in a.conds.iter().filter(|c| c.reg != 0) {
                let _ = write!(s, "+{}:{:x}:{:x}", c.reg - 1, c.bit, c.right);
            }
        }
        if !r.in_call.is_empty() {
            let _ = write!(s, " | checked in the call: {}", r.in_call);
        }
        s.push('\n');
    }
    s
}
