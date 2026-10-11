// M17b.f: profil wejść do kernela – czas (TSC) na rodzaj syscalla i
// wyjątku / przerwania, liczony per CPU (bez false sharingu).
//
// Legion: v0.17.31 robi ~9% mniej skryptów niż v0.17.28, a statystyki
// blokad są takie same.  Profil mówi, gdzie idzie czas CPU, zamiast zgadywać.
//
//   let t = prof::start();
//   ...
//   prof::stop(prof::PF_USER, t);
//
// Mierzony jest czas CPU zadania (sched::task_cpu_cycles): sen w syscallu
// i czas innych zadań się nie liczą; przerwania w trakcie – tak.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

use crate::arch::x86_64::percpu::PerCpu;

/// Kategorie 0..SYSCALLS to numery syscalli.
pub const SYSCALLS: usize = 40; // M18: numery syscalli 0..40 (było 29)
pub const PF_USER: usize = 40;
pub const IRQ_PIT: usize = 41;
pub const IRQ_TIMER: usize = 42;
pub const IRQ_RESCHED: usize = 43;
pub const REAP: usize = 44;
pub const EXIT: usize = 45;
pub const LOAD_ELF: usize = 46;
pub const CTX_SWITCH: usize = 47;
pub const DRV_EXEC: usize = 48;
/// Pomiary z końcem przed początkiem (nie powinno się zdarzać – kontrola).
const TSC_SKEW: usize = 49;
pub const SP_READ: usize = 50;
pub const SP_ELF: usize = 51;
pub const SP_TASK: usize = 52;
const N: usize = 56;

const NAMES: [&str; N] = [
    "exit(sys)", "write", "read", "open", "close", "getpid", "sleep", "yield", "uptime", "spawn", "wait",
    "getppid", "kill", "chdir", "getcwd", "readdir", "stat", "mkdir", "unlink", "readkey", "tasks", "kcmd",
    "dup", "dup2", "seek", "pipe", "brk", "mmap", "munmap", "handle_dup", "handle_info", "chan_create",
    "chan_send", "chan_recv", "shm_create", "shm_map", "spawn_ex", "shm_size", "sys38", "sys39", "#PF user", "IRQ PIT", "LAPIC timer",
    "resched IPI", "reap", "exit proc", " spawn:load", "ctx switch", "drv exec", "TSC skew", " sp:readfile", " sp:elf+pt", " sp:task", "?", "?", "?",
];

/// Porównanie napisów w czasie kompilacji.
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

// v0.18.0: po dodaniu numerów syscalli zabrakło jednej nazwy i etykiety w
// tabeli przesunęły się o jedną ("ctx switch" pokazywał spawn:load).  Kompilacja
// przerywa się, gdy nazwy nie zgadzają się z kategoriami.
const _: () = assert!(
    same(NAMES[28], "munmap")
        && same(NAMES[29], "handle_dup")
        && same(NAMES[36], "spawn_ex")
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
    "prof.rs: NAMES nie zgadzają się z numerami kategorii"
);


/// [liczba wywołań, cykle] dla każdej kategorii; jeden blok na CPU.
struct Slot([AtomicU64; 2 * N]);

static DATA: PerCpu<Slot> = crate::per_cpu!(Slot([const { AtomicU64::new(0) }; 2 * N]));

/// Początek pomiaru: czas CPU bieżącego zadania (sched::task_cpu_cycles).
/// Legion v0.17.32: surowy TSC z różnych rdzeni dawał bzdury po migracji
/// (stat średnio 64 ms) – TSC rdzeni nie są zgrane.  Czas CPU zadania
/// liczy scheduler zawsze na jednym CPU; sen i inne zadania się nie liczą.
#[inline(always)]
pub fn start() -> u64 {
    crate::sched::task_cpu_cycles()
}

/// Koniec pomiaru – do bloku CPU, na którym kończymy.
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

/// Pomiar zrobiony samodzielnie (cykle na tym samym CPU).
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

/// Raport: `top` najdroższych kategorii.  `cpu_ms` = czas wszystkich CPU
/// (ms x liczba CPU), `scripts` = skrypty w tym czasie (koszt na skrypt).
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
    // M17b.f: kręcenie na spinlockach, per nazwa.
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
