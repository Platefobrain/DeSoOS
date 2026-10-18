// Capabilities view – what every process may do (`caps <pid>`, `secinfo`).
//
// In DeSoOS a process has no user identity; what it may do is exactly the set
// of handles it holds (and their rights).  This module turns the handle tables
// into text.  Read-only: it shows the model, it does not change it.
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
//                others  0

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use super::process::{kind, rights, Fd, Handle};

/// Handle slots per process (the syscall layer allows numbers 0..64).
pub const SLOTS: usize = 64;

/// Summary of one handle (see the layout above).
pub fn summary(h: &Handle) -> u64 {
    let detail: u64 = match &h.obj {
        Fd::Device(c) => dev_bits(c.dev()),
        Fd::Irq(o) => o.vector() as u64 | (bdf(o.device()) << 8),
        Fd::Shm(s) => (s.len() / 4096).min((1 << 39) - 1) | if s.dma_phys().is_some() { 1 << 39 } else { 0 },
        _ => 0,
    };
    h.kind() | ((h.rights as u64 & 0xFFFF) << 8) | (detail << 24)
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

fn kind_name(k: u64) -> &'static str {
    match k {
        kind::CONSOLE => "console",
        kind::FILE => "file",
        kind::PIPE => "pipe",
        kind::CHANNEL => "channel",
        kind::SHM => "shm",
        kind::HW_ROOT => "hw-root",
        kind::DEVICE => "device",
        kind::IRQ => "irq",
        kind::SYSCTL => "sysctl",
        kind::INPUT => "input",
        kind::BLK => "blk",
        _ => "?",
    }
}

/// What the kind lets the process do (one short phrase).
fn kind_meaning(k: u64) -> &'static str {
    match k {
        kind::CONSOLE => "text in/out",
        kind::FILE => "open file",
        kind::PIPE => "pipe end",
        kind::CHANNEL => "messages (and handles) to another process",
        kind::SHM => "shared memory",
        kind::HW_ROOT => "may claim PCI devices",
        kind::DEVICE => "claimed PCI device (registers, DMA)",
        kind::IRQ => "device interrupts",
        kind::SYSCTL => "reboot, halt, sync, stress",
        kind::INPUT => "keyboard / mouse events to the kernel",
        kind::BLK => "may register disks in the kernel",
        _ => "",
    }
}

fn rights_text(r: u32) -> String {
    const NAMES: [(u32, &str); 8] = [
        (rights::READ, "read"),
        (rights::WRITE, "write"),
        (rights::SEND, "send"),
        (rights::RECV, "recv"),
        (rights::MAP_READ, "map-r"),
        (rights::MAP_WRITE, "map-w"),
        (rights::DUP, "dup"),
        (rights::TRANSFER, "transfer"),
    ];
    let mut t = String::new();
    for (bit, name) in NAMES {
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
            alloc::format!("{} {}", bdf_text(d & 0xFFFF), crate::drivers::pci::class_name(class, sub))
        }
        kind::IRQ => alloc::format!("vector {:#x} ({})", d & 0xFF, bdf_text((d >> 8) & 0xFFFF)),
        kind::SHM => {
            let kib = (d & ((1 << 39) - 1)) * 4;
            alloc::format!("{} KiB{}", kib, if d & (1 << 39) != 0 { ", DMA" } else { "" })
        }
        _ => String::new(),
    }
}

/// File access of a process: any path, or only the handles it was given
/// (file sandbox – path calls give EACCES).
fn files_text(sandboxed: bool) -> &'static str {
    if sandboxed { "none by path (sandbox) - only file handles it was given" } else { "all paths" }
}

/// `caps <pid>` – every handle of one process: kind, rights, detail.
pub fn caps(pid: u64) -> String {
    let mut out = String::new();
    let Some((id, ppid, name, sandboxed, slots)) = crate::sched::process_caps().into_iter().find(|p| p.0 == pid) else {
        let _ = writeln!(out, "caps: no user process {} (kernel tasks have no handles; pids: secinfo)", pid);
        return out;
    };
    let _ = writeln!(out, "{} (pid {}, parent {})", name, id, ppid);
    let _ = writeln!(out, "  slot  kind      rights                     detail");
    let mut n = 0;
    for (i, &s) in slots.iter().enumerate() {
        if kind_of(s) == 0 {
            continue;
        }
        n += 1;
        let detail = detail_text(s);
        let what = if detail.is_empty() { String::from(kind_meaning(kind_of(s))) } else { detail };
        let _ = writeln!(out, "  {:>4}  {:<8}  {:<25}  {}", i, kind_name(kind_of(s)), rights_text(rights_of(s)), what);
    }
    if n == 0 {
        let _ = writeln!(out, "  (no handles)");
    }
    let _ = writeln!(out, "files: {}", files_text(sandboxed));
    out
}

/// `secinfo` – one line per process: how many handles and which powers.
pub fn secinfo() -> String {
    let mut out = String::new();
    let procs = crate::sched::process_caps();
    let _ = writeln!(out, "  PID  PPID  NAME          HANDLES  HARDWARE     SYSTEM             FILES");
    for (id, ppid, name, sandboxed, slots) in procs.iter() {
        let used: Vec<u64> = slots.iter().copied().filter(|&s| kind_of(s) != 0).collect();
        let has = |k: u64| used.iter().any(|&s| kind_of(s) == k);
        let devices = used.iter().filter(|&&s| kind_of(s) == kind::DEVICE).count();
        let hw = if has(kind::HW_ROOT) {
            String::from("hw-root")
        } else if devices > 0 {
            alloc::format!("{} device{}", devices, if devices > 1 { "s" } else { "" })
        } else {
            String::from("-")
        };
        let mut sys = String::new();
        for (k, label) in [(kind::SYSCTL, "sysctl"), (kind::INPUT, "input"), (kind::BLK, "blk")] {
            if has(k) {
                if !sys.is_empty() {
                    sys.push(' ');
                }
                sys.push_str(label);
            }
        }
        if sys.is_empty() {
            sys.push('-');
        }
        let short: String = name.chars().take(12).collect();
        let files = if *sandboxed { "none" } else { "all" };
        let _ = writeln!(out, "{:>5} {:>5}  {:<12}  {:>7}  {:<11}  {:<17}  {}", id, ppid, short, used.len(), hw, sys, files);
    }
    let _ = writeln!(
        out,
        "{} process(es); details: caps <pid>.  FILES: all = any path, none = sandbox (only handles given; {} path calls refused so far).",
        procs.len(),
        super::syscalls::SANDBOX_DENIED.load(core::sync::atomic::Ordering::Relaxed)
    );
    out
}
