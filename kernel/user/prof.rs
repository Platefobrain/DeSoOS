// Profile of kernel entries – time (TSC) per kind of syscall and
// exception / interrupt, counted per CPU (no false sharing).
//
// Motivation: one build ran ~9% fewer scripts than an earlier one while lock
// statistics were identical.  The profile shows where CPU time goes instead of guessing.
//
//   let t = prof::start();
//   ...
//   prof::stop(prof::PF_USER, t);
//
// What is measured is the task's CPU time (sched::task_cpu_cycles): sleeping in a syscall
// and other tasks' time do not count; interrupts taken meanwhile do.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

use crate::arch::x86_64::percpu::PerCpu;

/// Categories 0..SYSCALLS are syscall numbers.
pub const SYSCALLS: usize = 51; // syscall numbers 0..51 (48 dev_find, 49–50 reserved in the design)
pub const PF_USER: usize = 51;
pub const IRQ_PIT: usize = 52;
pub const IRQ_TIMER: usize = 53;
pub const IRQ_RESCHED: usize = 54;
pub const REAP: usize = 55;
pub const EXIT: usize = 56;
pub const LOAD_ELF: usize = 57;
pub const CTX_SWITCH: usize = 58;
pub const DRV_EXEC: usize = 59;
/// Measurements whose end precedes their start (should not happen – a sanity check).
const TSC_SKEW: usize = 60;
pub const SP_READ: usize = 61;
pub const SP_ELF: usize = 62;
pub const SP_TASK: usize = 63;
const N: usize = 64;

const NAMES: [&str; N] = [
    "exit(sys)", "write", "read", "open", "close", "getpid", "sleep", "yield", "uptime", "spawn", "wait",
    "getppid", "kill", "chdir", "getcwd", "readdir", "stat", "mkdir", "unlink", "readkey", "tasks", "(21)",
    "dup", "dup2", "seek", "pipe", "brk", "mmap", "munmap", "handle_dup", "handle_info", "chan_create",
    "chan_send", "chan_recv", "shm_create", "shm_map", "spawn_ex", "shm_size", "wait_many", "dev_claim",
    "dev_info", "dev_map", "irq_bind", "irq_read", "dma_alloc", "dma_phys", "sysinfo", "sysctl", "dev_find", "input_inject", "blk_attach", "#PF user", "IRQ PIT", "LAPIC timer",
    "resched IPI", "reap", "exit proc", " spawn:load", "ctx switch", "drv exec", "TSC skew", " sp:readfile", " sp:elf+pt", " sp:task",
];

/// Compile-time string comparison.
const fn same(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

// Once, after adding syscall numbers, one name was missing and the labels in the
// table shifted by one ("ctx switch" showed spawn:load).  Compilation now
// fails when the names do not match the categories.
const _: () = assert!(
    same(NAMES[28], "munmap")
        && same(NAMES[29], "handle_dup")
        && same(NAMES[36], "spawn_ex")
        && same(NAMES[38], "wait_many")
        && same(NAMES[41], "dev_map")
        && same(NAMES[48], "dev_find")
        && same(NAMES[PF_USER], "#PF user")
        && same(NAMES[REAP], "reap")
        && same(NAMES[EXIT], "exit proc")
        && same(NAMES[LOAD_ELF], " spawn:load")
        && same(NAMES[CTX_SWITCH], "ctx switch")
        && same(NAMES[DRV_EXEC], "drv exec")
        && same(NAMES[TSC_SKEW], "TSC skew")
        && same(NAMES[SP_READ], " sp:readfile")
        && same(NAMES[SP_ELF], " sp:elf+pt")
        && same(NAMES[SP_TASK], " sp:task"),
    "prof.rs: NAMES do not match the category numbers"
);


/// [call count, cycles] for each category; one block per CPU.
struct Slot([AtomicU64; 2 * N]);

static DATA: PerCpu<Slot> = crate::per_cpu!(Slot([const { AtomicU64::new(0) }; 2 * N]));

/// Start of a measurement: CPU time of the current task (sched::task_cpu_cycles).
/// On real hardware a raw TSC from different cores gave nonsense after migration
/// (stat averaging 64 ms) – core TSCs are not synchronized.  A task's CPU time
/// is always computed by the scheduler on a single CPU; sleep and other tasks do not count.
#[inline(always)]
pub fn start() -> u64 {
    crate::sched::task_cpu_cycles()
}

/// End of a measurement – into the block of the CPU we finish on.
#[inline(always)]
pub fn stop(cat: usize, t0: u64) {
    let t1 = crate::sched::task_cpu_cycles();
    let d = &DATA[crate::arch::x86_64::cpu::id()].0;
    d[2 * cat].fetch_add(1, Relaxed);
    if t1 >= t0 {
        d[2 * cat + 1].fetch_add(t1 - t0, Relaxed);
    } else {
        d[2 * TSC_SKEW].fetch_add(1, Relaxed);
    }
}

/// A measurement taken separately (cycles on the same CPU).
#[inline(always)]
pub fn add(cat: usize, cycles: u64) {
    let d = &DATA[crate::arch::x86_64::cpu::id()].0;
    d[2 * cat].fetch_add(1, Relaxed);
    d[2 * cat + 1].fetch_add(cycles, Relaxed);
}

pub fn reset() {
    crate::sched::spin::spin_wait_reset();
    for s in DATA.iter() {
        for a in s.0.iter() {
            a.store(0, Relaxed);
        }
    }
}

fn totals() -> [(u64, u64); N] {
    let mut t = [(0u64, 0u64); N];
    for s in DATA.iter() {
        for (c, slot) in t.iter_mut().enumerate() {
            slot.0 = slot.0.saturating_add(s.0[2 * c].load(Relaxed));
            slot.1 = slot.1.saturating_add(s.0[2 * c + 1].load(Relaxed));
        }
    }
    t
}

/// Report: the `top` most expensive categories.  `cpu_ms` = time of all CPUs
/// (ms x number of CPUs), `scripts` = scripts in that time (cost per script).
pub fn lines(top: usize, cpu_ms: u64, scripts: u64) -> Vec<String> {
    let per_ms = crate::arch::x86_64::lapic::tsc_per_ms().max(1);
    let t = totals();
    let mut idx: Vec<usize> = (0..N).filter(|&c| t[c].0 > 0 && c != TSC_SKEW).collect();
    idx.sort_by(|&a, &b| t[b].1.cmp(&t[a].1));
    let mut out = Vec::new();
    out.push(format!("  prof:  name calls avg_us  CPU%  us/script"));
    for &c in idx.iter().take(top) {
        let (n, cyc) = t[c];
        let us_total = cyc.saturating_mul(1000) / per_ms;
        let avg10 = us_total.saturating_mul(10) / n.max(1);
        let pct10 = cyc.saturating_mul(1000) / cpu_ms.max(1).saturating_mul(per_ms);
        out.push(format!(
            "    {:<11} {:>8} {:>5}.{} {:>3}.{}% {:>6}{}",
            NAMES[c],
            n,
            avg10 / 10,
            avg10 % 10,
            pct10 / 10,
            pct10 % 10,
            us_total / scripts.max(1),
            ""
        ));
    }
    out.push(format!("    check: {} measurement(s) with negative time (should be 0)", t[TSC_SKEW].0));
    // Spinning on spinlocks, per name.
    out.push(format!("  spin wait: name waits avg_us CPU%"));
    for (name, n, cyc) in crate::sched::spin::spin_wait_stats().into_iter().take(8) {
        let us_total = cyc.saturating_mul(1000) / per_ms;
        let avg10 = us_total.saturating_mul(10) / n.max(1);
        let pct10 = cyc.saturating_mul(1000) / cpu_ms.max(1).saturating_mul(per_ms);
        out.push(format!(
            "    {:<18} {:>9} {:>5}.{} {:>3}.{}%",
            name, n, avg10 / 10, avg10 % 10, pct10 / 10, pct10 % 10
        ));
    }
    out
}
