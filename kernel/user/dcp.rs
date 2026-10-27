// DCP – DeSoOS Capability Permissions: the `dcp` command.
//
// In DeSoOS a process has no user identity; what it may do is exactly the set
// of handles (capabilities) it holds, with their rights, plus the file sandbox
// flag.  This module shows that model and keeps a log of refusals:
//
//   dcp                 every visible process: devices, system powers, files
//   dcp inspect <pid>   every capability of one process with its rights
//   dcp audit           the last refusals (sandbox, missing rights, ERROR_ACCESS_DENIED)
//
// Read-only: it shows the model, it does not change it.
//
// Who sees what: a process sees itself and its descendants; a process holding
// the SYSCTL capability (the shell) and the kernel's emergency shell see
// everything.  Handle names and devices of other programs are not everybody's
// business.
//
// A process changes its own handle table without locks, so other CPUs must not
// touch its handles.  Instead each table publishes a 64-bit summary per slot
// (`FdTable`, process.rs) on every change:
//
//   bits  0..8   kind (0 = empty slot)          – process::kind
//   bits  8..24  rights                         – process::rights
//   bits 24..64  detail, depends on the kind:
//                DEVICE  bus:dev.fn (16 bits) + class + subclass
//                IRQ     MSI vector (8 bits) + bus:dev.fn of the device
//                SHM     size in pages (39 bits) + bit 39: DMA buffer
//                IPC, PIPE  object identity (39 bits, from its address) +
//                        bit 39: which end – `dcp inspect` finds who holds the
//                        other end by matching identities across processes
//                others  0

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

use super::process::{kind, rights, Fd, Handle};
use crate::sched::spin::{level, SpinLock};

/// Handle slots per process (the syscall layer allows numbers 0..64).
pub const SLOTS: usize = 64;

/// Summary of one handle (see the layout above).
pub fn summary(h: &Handle) -> u64 {
    let detail: u64 = match &h.obj {
        Fd::Device(c) => dev_bits(c.dev()),
        Fd::Irq(o) => o.vector() as u64 | (bdf(o.device()) << 8),
        Fd::Shm(s) => (s.len() / 4096).min((1 << 39) - 1) | if s.dma_phys().is_some() { 1 << 39 } else { 0 },
        Fd::Channel(e) => end_bits(e.ident()),
        Fd::Pipe(e) => end_bits(e.ident()),
        _ => 0,
    };
    h.kind() | ((h.rights as u64 & 0xFFFF) << 8) | (detail << 24)
}

/// Identity of a channel / pipe end: the object's address (heap, 16-byte
/// aligned – unique among live objects) in 39 bits, the side in bit 39.
fn end_bits((obj, side): (u64, u64)) -> u64 {
    ((obj >> 4) & ((1 << 39) - 1)) | (side & 1) << 39
}

fn bdf(d: &crate::drivers::pci::Device) -> u64 {
    (d.address.bus as u64) << 8 | (d.address.device as u64 & 31) << 3 | (d.address.function as u64 & 7)
}

fn dev_bits(d: &crate::drivers::pci::Device) -> u64 {
    bdf(d) | (d.class as u64) << 16 | (d.subclass as u64) << 24
}

fn kind_of(s: u64) -> u64 {
    s & 0xFF
}

fn rights_of(s: u64) -> u32 {
    ((s >> 8) & 0xFFFF) as u32
}

fn detail_of(s: u64) -> u64 {
    s >> 24
}

/// DCP name of a capability kind.
fn cap_name(k: u64) -> &'static str {
    match k {
        kind::CONSOLE => "CONSOLE",
        kind::FILE => "FILE",
        kind::PIPE => "PIPE",
        kind::CHANNEL => "IPC",
        kind::SHM => "MEM_SHARE",
        kind::HW_ROOT => "DEVICE_CLAIM",
        kind::DEVICE => "DEVICE_CONTROL",
        kind::IRQ => "DEVICE_IRQ",
        kind::SYSCTL => "SYS_POWER",
        kind::INPUT => "INPUT_SEND",
        kind::BLK => "DISK_ATTACH",
        _ => "?",
    }
}

/// What the capability lets the process do (one short phrase).
fn cap_meaning(k: u64) -> &'static str {
    match k {
        kind::CONSOLE => "text on screen",
        kind::FILE => "an open file",
        kind::PIPE => "pipe end",
        kind::CHANNEL => "messages (and capabilities) to another process",
        kind::SHM => "shared memory",
        kind::HW_ROOT => "may claim PCI devices",
        kind::DEVICE => "claimed device",
        kind::IRQ => "device interrupts",
        kind::SYSCTL => "reboot, halt, sync, stress",
        kind::INPUT => "keys and mouse to the system",
        kind::BLK => "may add USB disks",
        _ => "",
    }
}

/// DCP names of rights.
const RIGHT_NAMES: [(u32, &str); 8] = [
    (rights::READ, "READ"),
    (rights::WRITE, "WRITE"),
    (rights::SEND, "SEND"),
    (rights::RECV, "RECEIVE"),
    (rights::MAP_READ, "MAP_READ"),
    (rights::MAP_WRITE, "MAP_WRITE"),
    (rights::DUP, "COPY"),
    (rights::TRANSFER, "SHARE"),
];

fn rights_text(r: u32) -> String {
    let mut t = String::new();
    for (bit, name) in RIGHT_NAMES {
        if r & bit != 0 {
            if !t.is_empty() {
                t.push(' ');
            }
            t.push_str(name);
        }
    }
    if t.is_empty() {
        t.push('-');
    }
    t
}

fn bdf_text(b: u64) -> String {
    alloc::format!("{:02x}:{:02x}.{}", (b >> 8) & 0xFF, (b >> 3) & 31, b & 7)
}

fn detail_text(s: u64) -> String {
    let d = detail_of(s);
    match kind_of(s) {
        kind::DEVICE => {
            let (class, sub) = (((d >> 16) & 0xFF) as u8, ((d >> 24) & 0xFF) as u8);
            alloc::format!("{} {}", crate::drivers::pci::class_name(class, sub), bdf_text(d & 0xFFFF))
        }
        kind::IRQ => alloc::format!("interrupts of {} (vector {:#x})", bdf_text((d >> 8) & 0xFFFF), d & 0xFF),
        kind::SHM => {
            let kib = (d & ((1 << 39) - 1)) * 4;
            alloc::format!("shared memory {} KiB{}", kib, if d & (1 << 39) != 0 { " (DMA)" } else { "" })
        }
        k => String::from(cap_meaning(k)),
    }
}

/// What a slot is for: slots 0, 1, 2 are the standard input, output and error
/// output of every program (also when redirected to a file or a pipe).
fn slot_text(slot: usize, s: u64, rows: &[ProcRow], me: u64) -> String {
    let what = match kind_of(s) {
        kind::CHANNEL | kind::PIPE => peer_text(s, rows, me),
        _ => detail_text(s),
    };
    // Slots 0–2 are stdin / stdout / stderr only when they hold something you can
    // read or write (a service may keep e.g. an interrupt in slot 0).
    if !matches!(kind_of(s), kind::CONSOLE | kind::FILE | kind::PIPE) {
        return what;
    }
    let role = match slot {
        0 => "input",
        1 => "output",
        2 => "errors",
        _ => return what,
    };
    if kind_of(s) == kind::CONSOLE {
        return String::from(match slot {
            0 => "input (keyboard)",
            1 => "output (screen)",
            _ => "errors (screen)",
        });
    }
    alloc::format!("{}: {}", role, what)
}

/// Who holds the other end of a channel or pipe: "channel to usbd (10)",
/// "pipe to cat (12)", "channel to itself (slot 9)".
fn peer_text(s: u64, rows: &[ProcRow], me: u64) -> String {
    let d = detail_of(s);
    let (obj, side) = (d & ((1 << 39) - 1), d >> 39);
    let mut holders: Vec<String> = Vec::new();
    for (pid, _, name, _, slots) in rows.iter() {
        for (i, &o) in slots.iter().enumerate() {
            let od = detail_of(o);
            if kind_of(o) == kind_of(s) && od & ((1 << 39) - 1) == obj && od >> 39 != side {
                if *pid == me {
                    holders.push(alloc::format!("itself (slot {})", i));
                } else {
                    holders.push(alloc::format!("{} ({})", name, pid));
                }
            }
        }
    }
    holders.dedup();
    let what = if kind_of(s) == kind::PIPE {
        if side == 1 { "pipe (write end) to" } else { "pipe (read end) from" }
    } else {
        "channel to"
    };
    if holders.is_empty() {
        let what = if kind_of(s) == kind::PIPE { "pipe" } else { "channel" };
        return alloc::format!("{} - other end held by no program (the kernel, closed, or in a message)", what);
    }
    let more = holders.len().saturating_sub(3);
    holders.truncate(3);
    let mut t = alloc::format!("{} {}", what, holders.join(", "));
    if more > 0 {
        let _ = write!(t, " +{} more", more);
    }
    t
}

// ------------------------------------------------------------
// Who may see what
// ------------------------------------------------------------

/// The process asking (`None` = the kernel's emergency shell – sees all).
#[derive(Clone, Copy)]
pub struct Viewer {
    pub pid: u64,
    /// Holds SYSCTL – sees every process (the shell).
    pub all: bool,
}

type ProcRow = (u64, u64, String, bool, [u64; SLOTS]);

/// `target` is the viewer itself or one of its descendants (or the viewer sees all).
fn visible(rows: &[ProcRow], viewer: Option<Viewer>, target: u64) -> bool {
    let Some(v) = viewer else { return true };
    if v.all || target == v.pid {
        return true;
    }
    let mut cur = target;
    for _ in 0..64 {
        let Some(row) = rows.iter().find(|r| r.0 == cur) else { return false };
        if row.1 == v.pid {
            return true;
        }
        if row.1 == 0 || row.1 == cur {
            return false;
        }
        cur = row.1;
    }
    false
}

// ------------------------------------------------------------
// dcp, dcp inspect
// ------------------------------------------------------------

/// `dcp ...` – `args` without the word "dcp".  None = unknown arguments.
pub fn dcp(args: &str, viewer: Option<Viewer>) -> Option<String> {
    let words: Vec<&str> = args.split_whitespace().collect();
    match words.as_slice() {
        [] => Some(overview(viewer)),
        ["inspect", pid] => pid.parse::<u64>().ok().map(|p| inspect(p, viewer)),
        ["audit"] => Some(audit(viewer)),
        _ => None,
    }
}

pub const USAGE: &str = "usage: dcp | dcp inspect <pid> | dcp audit";

fn overview(viewer: Option<Viewer>) -> String {
    let mut out = String::new();
    let rows = crate::sched::process_caps();
    let _ = writeln!(out, "DCP - who may do what");
    let _ = writeln!(out, "  PID  NAME          DEVICES          SYSTEM                             FILES");
    let mut hidden = 0;
    for row in rows.iter() {
        let (id, _, name, sandboxed, slots) = row;
        if !visible(&rows, viewer, *id) {
            hidden += 1;
            continue;
        }
        let used: Vec<u64> = slots.iter().copied().filter(|&s| kind_of(s) != 0).collect();
        let has = |k: u64| used.iter().any(|&s| kind_of(s) == k);
        let devices: Vec<u64> = used.iter().copied().filter(|&s| kind_of(s) == kind::DEVICE).collect();
        let dev = if has(kind::HW_ROOT) {
            String::from("DEVICE_CLAIM")
        } else if devices.len() == 1 {
            alloc::format!("1 ({})", bdf_text(detail_of(devices[0]) & 0xFFFF))
        } else if !devices.is_empty() {
            alloc::format!("{}", devices.len())
        } else {
            String::from("-")
        };
        let mut sys = String::new();
        for k in [kind::SYSCTL, kind::INPUT, kind::BLK] {
            if has(k) {
                if !sys.is_empty() {
                    sys.push(' ');
                }
                sys.push_str(cap_name(k));
            }
        }
        if sys.is_empty() {
            sys.push('-');
        }
        let short: String = name.chars().take(12).collect();
        let files = if *sandboxed { "none" } else { "all" };
        let _ = writeln!(out, "{:>5}  {:<12}  {:<15}  {:<33}  {}", id, short, dev, sys, files);
    }
    if hidden > 0 {
        let _ = writeln!(out, "({} other process(es) not shown - only your own and your children's; all with SYS_POWER)", hidden);
    }
    let _ = writeln!(out, "FILES: all = any path, none = sandbox (only what it was given).  Details: dcp inspect <pid>, refusals: dcp audit");
    out
}

fn inspect(pid: u64, viewer: Option<Viewer>) -> String {
    let mut out = String::new();
    let rows = crate::sched::process_caps();
    let Some(row) = rows.iter().find(|r| r.0 == pid) else {
        let _ = writeln!(out, "dcp: no user process {} (kernel tasks have no capabilities; pids: dcp)", pid);
        return out;
    };
    if !visible(&rows, viewer, pid) {
        let _ = writeln!(out, "dcp: process {} is not yours (only your own and your children's; all with SYS_POWER)", pid);
        return out;
    }
    let (id, ppid, name, sandboxed, slots) = row;
    let parent = match rows.iter().find(|r| r.0 == *ppid) {
        Some(p) => alloc::format!("{} ({})", ppid, p.2),
        None if *ppid == 0 => String::from("the kernel"),
        None => alloc::format!("{}", ppid),
    };
    let _ = writeln!(out, "{} (pid {}, started by {})", name, id, parent);
    let _ = writeln!(out, "  slot  capability      rights                          what");
    let mut n = 0;
    for (i, &s) in slots.iter().enumerate() {
        if kind_of(s) == 0 {
            continue;
        }
        n += 1;
        let _ = writeln!(out, "  {:>4}  {:<14}  {:<30}  {}", i, cap_name(kind_of(s)), rights_text(rights_of(s)), slot_text(i, s, &rows, *id));
    }
    if n == 0 {
        let _ = writeln!(out, "  (no capabilities)");
    }
    if *sandboxed {
        let _ = writeln!(out, "files: none (sandbox) - only file capabilities it was given");
    } else {
        let _ = writeln!(out, "files: all paths");
    }
    out
}

// ------------------------------------------------------------
// dcp audit – the last refusals
// ------------------------------------------------------------

/// Why a call was refused.
#[derive(Clone, Copy, PartialEq)]
pub enum Reason {
    /// A path call in the file sandbox.
    Sandbox,
    /// read / write on a handle without the READ / WRITE right.
    NoRight(u32),
    /// ERROR_ACCESS_DENIED – a capability without the needed right, or a forbidden object.
    Denied,
}

const AUDIT_LOG: usize = 64;
const NAME_MAX: usize = 12;
const WHAT_MAX: usize = 40;

#[derive(Clone, Copy)]
struct Entry {
    ms: u64,
    pid: u64,
    ppid: u64,
    name: [u8; NAME_MAX],
    name_len: u8,
    syscall: u64,
    what: [u8; WHAT_MAX],
    what_len: u8,
    reason: Reason,
}

struct Log {
    entries: [Option<Entry>; AUDIT_LOG],
    next: usize,
}

/// Leaf lock: nothing is taken or allocated under it.
static LOG: SpinLock<Log> = SpinLock::new("dcp-audit", level::EXIT_LOG + 1, Log { entries: [None; AUDIT_LOG], next: 0 });
static REFUSALS: AtomicU64 = AtomicU64::new(0);

/// All refusals since boot (tests).
#[allow(dead_code)]
pub fn refusals() -> u64 {
    REFUSALS.load(Ordering::Relaxed)
}

fn copy_text<const N: usize>(s: &[u8]) -> ([u8; N], u8) {
    let mut b = [0u8; N];
    let mut n = 0;
    for &c in s.iter() {
        if n == N {
            break;
        }
        b[n] = if (0x20..0x7f).contains(&c) { c } else { b'?' };
        n += 1;
    }
    (b, n as u8)
}

/// Records a refusal (from the syscall layer, no locks held).
pub fn record(pid: u64, ppid: u64, name: &str, syscall: u64, what: &[u8], reason: Reason) {
    REFUSALS.fetch_add(1, Ordering::Relaxed);
    let (name, name_len) = copy_text::<NAME_MAX>(name.as_bytes());
    let (what, what_len) = copy_text::<WHAT_MAX>(what);
    let e = Entry { ms: crate::time::uptime_ms(), pid, ppid, name, name_len, syscall, what, what_len, reason };
    let mut log = LOG.lock();
    let i = log.next % AUDIT_LOG;
    log.entries[i] = Some(e);
    log.next = log.next.wrapping_add(1);
}

fn syscall_name(nr: u64) -> &'static str {
    use super::syscalls::*;
    match nr {
        SYS_WRITE => "write",
        SYS_READ => "read",
        SYS_OPEN => "open",
        SYS_SPAWN => "spawn",
        SYS_SPAWN_EX => "spawn",
        SYS_CHDIR => "chdir",
        SYS_READDIR => "readdir",
        SYS_STAT => "stat",
        SYS_MKDIR => "mkdir",
        SYS_UNLINK => "unlink",
        SYS_DUP | SYS_DUP2 | SYS_HANDLE_DUP => "copy handle",
        SYS_CHAN_SEND => "send",
        SYS_CHAN_RECV => "receive",
        SYS_SHM_MAP => "map memory",
        SYS_DEV_CLAIM => "claim device",
        SYS_DEV_MAP => "map device",
        SYS_IRQ_BIND => "bind interrupt",
        SYS_DMA_ALLOC => "dma alloc",
        SYS_WAIT_MANY => "wait",
        SYS_INPUT_INJECT => "input",
        SYS_BLK_ATTACH => "add disk",
        SYS_SYSCTL => "sysctl",
        SYS_DEV_FIND => "find device",
        _ => "syscall",
    }
}

fn audit(viewer: Option<Viewer>) -> String {
    let mut copy: Vec<Entry> = Vec::with_capacity(AUDIT_LOG);
    {
        let log = LOG.lock();
        for k in 0..AUDIT_LOG {
            // Oldest first.
            if let Some(e) = log.entries[(log.next + k) % AUDIT_LOG] {
                copy.push(e);
            }
        }
    }
    let mut out = String::new();
    let _ = writeln!(out, "DCP audit - last refusals ({} since boot, last {} kept)", REFUSALS.load(Ordering::Relaxed), AUDIT_LOG);
    let mut shown = 0;
    for e in copy.iter() {
        // A program sees refusals of itself and its children; all with SYS_POWER.
        if let Some(v) = viewer {
            if !v.all && e.pid != v.pid && e.ppid != v.pid {
                continue;
            }
        }
        shown += 1;
        let name = core::str::from_utf8(&e.name[..e.name_len as usize]).unwrap_or("?");
        let what = core::str::from_utf8(&e.what[..e.what_len as usize]).unwrap_or("?");
        let why = match e.reason {
            Reason::Sandbox => String::from("no files (sandbox)"),
            Reason::NoRight(r) => alloc::format!("capability has no {} right", rights_text(r)),
            Reason::Denied => String::from("permission (ERROR_ACCESS_DENIED)"),
        };
        let what = alloc::format!("{} {}", syscall_name(e.syscall), what);
        let who = alloc::format!("{} ({})", name, e.pid);
        let _ = writeln!(out, "  {:>6}.{:03}  {:<18}  {:<30}  refused: {}", e.ms / 1000, e.ms % 1000, who, what.trim_end(), why);
    }
    if shown == 0 {
        let _ = writeln!(out, "  (none visible to you)");
    }
    out
}
