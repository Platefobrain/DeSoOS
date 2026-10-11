// M17: samotesty SMP – rdzenie online, zadania na wielu CPU, procesy
// równolegle, syscalle z kilku CPU naraz (tylko build z --cfg selftest).

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::*;
use crate::arch::x86_64::{cpu::MAX_CPUS, smp};
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[SMP TEST] FAIL: {}", format_args!($($msg)*));
            STOP.store(true, Ordering::SeqCst);
            return;
        }
    };
}

static STOP: AtomicBool = AtomicBool::new(false);
static SPINS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

fn wait_for(ms: u64, mut cond: impl FnMut() -> bool) -> bool {
    let end = ticks() + ms;
    while !cond() {
        if ticks() > end {
            return false;
        }
        crate::time::sleep_ms(1);
    }
    true
}

// Spinnery testu 2 kończą się SAME (po >= 2 CPU albo po 10 s zegara HPET) –
// wcześniej czekały na STOP od zadania testowego, które bywało zagładzane.
/// CPU, na których kręciły się spinnery (zapisują je same).
static SPIN_CPUS: AtomicU64 = AtomicU64::new(0);
/// Ile CPU muszą razem odwiedzić spinnery, żeby skończyć wcześniej.
static SPIN_GOAL: AtomicU64 = AtomicU64::new(2);
/// Po ilu ms (+1) od startu cel został osiągnięty (0 = jeszcze nie).
static SPIN_DONE_AT: AtomicU64 = AtomicU64::new(0);
/// Znacznik zegara (clock::stamp) startu spinnerów – czas rzeczywisty w zrzucie.
static SPIN_CLOCK: AtomicU64 = AtomicU64::new(0);

/// Spinnery startują razem (po utworzeniu wszystkich).
static SPIN_GO: AtomicBool = AtomicBool::new(false);
const SPIN_LIMIT_US: u64 = 10_000_000;

fn spinner(i: usize) {
    // Kręcimy się BEZ Big Kernel Lock (tylko atomiki).  Wcześniej spinner
    // trzymał BKL cały czas, oddając go tylko w ticku: zadanie testowe
    // tworzyło kolejne spinnery po kawałku co 10 ms, BSP czekał na BKL
    // z wyłączonymi przerwaniami i gubił ticki PIT – u Dawida "10 s" testu
    // trwało 99 s, a spinnery 1–3 wystartowały już po terminie (maska 0b1000).
    // Termin liczony zegarem HPET (czas rzeczywisty), nie tickami.
    crate::sched::bkl::unlocked(|| {
        while !SPIN_GO.load(Ordering::Acquire) && !STOP.load(Ordering::Relaxed) {
            core::hint::spin_loop();
        }
        let start = SPIN_CLOCK.load(Ordering::Relaxed);
        let mut n: u64 = 0;
        while !STOP.load(Ordering::SeqCst) {
            SPINS[i].fetch_add(1, Ordering::Relaxed);
            let me = crate::arch::x86_64::cpu::id();
            let cpus = SPIN_CPUS.fetch_or(1 << me, Ordering::Relaxed) | (1 << me);
            // Koniec, gdy razem byliśmy na dość wielu CPU – szybki sprzęt
            // kończy w milisekundach, wolny emulator ma czas do 10 s.
            if cpus.count_ones() as u64 >= SPIN_GOAL.load(Ordering::Relaxed) {
                let ms = crate::arch::x86_64::clock::elapsed_us(start) / 1000 + 1;
                let _ = SPIN_DONE_AT.compare_exchange(0, ms, Ordering::SeqCst, Ordering::SeqCst);
                break;
            }
            n += 1;
            if n % 1024 == 0 && crate::arch::x86_64::clock::elapsed_us(start) > SPIN_LIMIT_US {
                break;
            }
            core::hint::spin_loop();
        }
    });
}

/// M17a: stan wszystkich CPU, BKL i spinnerów (tylko przy kłopotach).
fn dump_state(why: &str, ids: &[TaskId], k: usize) {
    use crate::arch::x86_64::{clock, cpu};
    use crate::sched::bkl;
    let (next, serving, owner) = bkl::state();
    let site = bkl::owner_site();
    serial_println!(
        "[SMP TEST] state ({}): tick {} ({} ms real since spinners started), ready tasks {}, BKL next {} serving {} owner CPU {} site {:?}",
        why,
        ticks(),
        clock::elapsed_us(SPIN_CLOCK.load(Ordering::Relaxed)) / 1000,
        crate::sched::ready_count(),
        next,
        serving,
        owner as i32 - 1,
        site
    );
    for c in 0..smp::online_count() {
        let (timer, ipis) = smp::counters(c);
        serial_println!(
            "[SMP TEST]   CPU {}: current {:?}, need_resched {}, lapic ticks {}, resched IPIs {}, BKL wait ticket {:?}, preempt {}, in_irq {}",
            c,
            crate::sched::current_on(c),
            crate::sched::need_resched_of(c),
            timer,
            ipis,
            bkl::waiting_ticket(c),
            cpu::preempt_count_of(c),
            cpu::in_interrupt_of(c)
        );
    }
    for (i, &id) in ids.iter().enumerate().take(k) {
        let t = crate::sched::task_info(id);
        serial_println!(
            "[SMP TEST]   spinner {} (task {}): spins {}, state {:?}, cpu {:?}, cpu_mask {:#b}, switches {}",
            i,
            id,
            SPINS[i].load(Ordering::Relaxed),
            t.as_ref().map(|t| t.state),
            t.as_ref().and_then(|t| t.cpu),
            t.as_ref().map(|t| t.cpu_mask).unwrap_or(0),
            t.as_ref().map(|t| t.switches).unwrap_or(0)
        );
    }
}

fn start(path: &str, args: &[&str], stdin: &[u8]) -> Option<TaskId> {
    let opts = SpawnOptions { stdin: Some(stdin.to_vec()), capture: true, ..SpawnOptions::default() };
    exec(path, args, "/", &opts).ok()
}

pub fn self_test() {
    serial_println!("[SMP TEST] Starting SMP tests...");
    crate::selftest::begin();
    STOP.store(false, Ordering::SeqCst);

    // 1. Rdzenie z MADT działają, timery LAPIC tykają.
    let expected = crate::acpi::madt().map(|m| m.cpus.len().min(MAX_CPUS)).unwrap_or(1);
    let n = smp::online_count();
    check!(n == expected, "{} CPU(s) online, MADT lists {}", n, expected);
    check!(n == 1 || smp::active(), "SMP not active with {} CPUs", n);
    if n > 1 {
        let before: Vec<u64> = (1..n).map(|c| smp::counters(c).0).collect();
        crate::time::sleep_ms(50);
        for c in 1..n {
            check!(smp::online(c), "CPU {} not online", c);
            let now = smp::counters(c).0;
            check!(now > before[c - 1], "CPU {}: LAPIC timer not ticking ({} -> {})", c, before[c - 1], now);
        }
    }
    check!(crate::sched::bkl::held(), "test task does not hold the Big Kernel Lock");
    serial_println!("[SMP TEST] 1/5 {} CPU(s) online, LAPIC timers ticking PASS", n);
    if n == 1 {
        serial_println!("[SMP TEST] one CPU - skipping parallel tests");
        crate::selftest::pass();
        return;
    }

    // 2. Zadania kernela trafiają na różne CPU (BKL przekazywany w ticku).
    //    Spinnery kończą się same: gdy razem były na >= 2 CPU albo po 10 s;
    //    test tylko patrzy (i mierzy, po jakim czasie inne CPU przejęły pracę).
    let k = n.min(MAX_CPUS);
    SPIN_CPUS.store(0, Ordering::SeqCst);
    SPIN_DONE_AT.store(0, Ordering::SeqCst);
    SPIN_GOAL.store(2, Ordering::SeqCst);
    SPIN_GO.store(false, Ordering::SeqCst);
    let mut ids = Vec::new();
    for i in 0..k {
        SPINS[i].store(0, Ordering::SeqCst);
        let id = crate::sched::spawn("smp-spin", spinner, i);
        check!(id.is_ok(), "cannot spawn spinner");
        ids.push(id.unwrap());
    }
    SPIN_CLOCK.store(crate::arch::x86_64::clock::stamp(), Ordering::SeqCst);
    SPIN_GO.store(true, Ordering::SeqCst);
    // Po 3 s bez drugiego CPU – zrzut stanu (diagnostyka rzadkiego FAIL
    // pod TCG: kto trzyma BKL, kto czeka, czy timery tykają).
    let mut dumped = false;
    let all_gone = wait_for(20_000, || {
        if !dumped && SPIN_DONE_AT.load(Ordering::Relaxed) == 0 && crate::arch::x86_64::clock::elapsed_us(SPIN_CLOCK.load(Ordering::Relaxed)) > 3_000_000 {
            dumped = true;
            dump_state("no second CPU after 3 s", &ids, k);
        }
        ids.iter().all(|&id| crate::sched::task_info(id).is_none())
    });
    if !all_gone {
        dump_state("spinners did not end", &ids, k);
    }
    check!(all_gone, "spinners did not end");
    let mask = SPIN_CPUS.load(Ordering::SeqCst) as u16;
    if mask.count_ones() < 2 && !dumped {
        dump_state("only one CPU", &ids, k);
    }
    check!(mask.count_ones() >= 2, "kernel tasks ran only on CPU mask {:#b} in 10 s (other CPUs never took a task)", mask);
    let done_at = SPIN_DONE_AT.load(Ordering::SeqCst);
    serial_println!(
        "[SMP TEST] 2/5 {} kernel tasks on CPU mask {:#b}, second CPU after {} ms PASS",
        k,
        mask,
        done_at.saturating_sub(1)
    );

    // 3. Procesy naprawdę równolegle: kilka `primes` naraz na różnych CPU.
    let t0 = ticks();
    let mut procs = Vec::new();
    for _ in 0..n {
        let id = start("/bin/primes", &["primes", "400000"], b"");
        check!(id.is_some(), "cannot start /bin/primes");
        procs.push(id.unwrap());
    }
    let mut max_parallel = 0;
    while procs.iter().any(|&id| crate::sched::task_info(id).is_some()) && ticks() < t0 + 60_000 {
        let mut cpus = 0u16;
        for &id in &procs {
            if let Some(t) = crate::sched::task_info(id) {
                if let Some(c) = t.cpu {
                    cpus |= 1 << c;
                }
            }
        }
        max_parallel = max_parallel.max(cpus.count_ones());
        crate::time::sleep_ms(2);
    }
    let wall = ticks() - t0;
    for &id in &procs {
        let gone = wait_for(2_000, || crate::sched::task_info(id).is_none());
        check!(gone, "primes {} still running after {} ms", id, wall);
        let info = exit_info(id);
        check!(matches!(info.map(|i| i.kind), Some(ExitKind::Exit(0))), "primes {} ended with {:?}", id, info.map(|i| i.kind));
        let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
        check!(out.contains("33860 primes below 400000"), "primes {} output: {:?}", id, out);
    }
    // Przy 2 CPU drugi zajmuje to zadanie testowe – równoległość od 3.
    check!(n < 3 || max_parallel >= 2, "processes never ran at the same time (max {} CPUs)", max_parallel);
    serial_println!(
        "[SMP TEST] 3/5 {} x primes: up to {} running at once, {} ms PASS",
        n,
        max_parallel,
        wall
    );

    // 4. Syscalle z wielu CPU naraz: kilka shelli (spawn/wait, VFS, pliki).
    let mut shells = Vec::new();
    for i in 0..n * 2 {
        let script = alloc::format!(
            "mkdir /tmp-smp{i}\necho hello{i} > /tmp-smp{i}/f\ncat /tmp-smp{i}/f\nprimes 3000\nls /tmp-smp{i}\nrm /tmp-smp{i}/f\nrm /tmp-smp{i}\nexit {i}\n"
        );
        let id = start("/bin/sh", &["sh"], script.as_bytes());
        check!(id.is_some(), "cannot start sh {}", i);
        shells.push((i, id.unwrap()));
    }
    for &(i, id) in &shells {
        check!(wait_for(30_000, || crate::sched::task_info(id).is_none()), "sh {} timeout", i);
        let kind = exit_info(id).map(|e| e.kind);
        let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
        check!(kind == Some(ExitKind::Exit(i as i64)), "sh {} ended with {:?}:\n{}", i, kind, out);
        let hello = alloc::format!("hello{}", i);
        check!(out.contains(&hello), "sh {} output lacks {:?}:\n{}", i, hello, out);
        check!(out.contains("430 primes below 3000"), "sh {} output lacks primes:\n{}", i, out);
        check!(crate::fs::stat(&alloc::format!("/tmp-smp{}", i)).is_err(), "sh {}: directory not removed", i);
    }
    let ipis: u64 = (0..n).map(|c| smp::counters(c).1).sum();
    let used = shells.iter().filter_map(|&(_, id)| exit_info(id)).count();
    check!(used == shells.len(), "exit info missing");
    check!(ipis > 0, "no wake-up IPIs were delivered");
    serial_println!("[SMP TEST] 4/5 {} shells at once (spawn/wait/VFS), {} wake-up IPIs PASS", shells.len(), ipis);

    // 5. FPU/SSE przy migracji: 2n procesów xmm (więcej niż CPU – muszą się
    //    przełączać i przechodzić między rdzeniami), żaden rejestr nie wycieka.
    let code = programs::code("xmm");
    check!(code.is_some(), "no xmm program");
    let mut xmm = Vec::new();
    for i in 0..n * 2 {
        let id = spawn_process("xmm", code.unwrap(), 0x1000_0000_0000 * (i as u64 + 1));
        check!(id.is_ok(), "spawn xmm");
        xmm.push(id.unwrap());
    }
    let mut migrated = 0u16;
    // Licznik schedulera – próbkowanie cpu_mask co 5 ms gubiło migracje
    // procesów, które zdążyły się zakończyć (KVM po v0.17.12: procesy
    // startują bez BKL i kończą się w kilkadziesiąt ms).
    let mig0 = crate::sched::user_migrations();
    let end = ticks() + 120_000;
    while xmm.iter().any(|&id| crate::sched::task_info(id).is_some()) && ticks() < end {
        for &id in &xmm {
            if let Some(t) = crate::sched::task_info(id) {
                if t.cpu_mask.count_ones() >= 2 {
                    migrated |= 1 << (id % 16);
                }
            }
        }
        crate::time::sleep_ms(5);
    }
    for (i, &id) in xmm.iter().enumerate() {
        check!(wait_for(2_000, || crate::sched::task_info(id).is_none()), "xmm {} did not end", i);
        let r = exit_info(id);
        check!(
            r.map(|e| (e.kind, e.rax)) == Some((ExitKind::Breakpoint, 1)),
            "xmm {}: {:?} rax {:#x} (0xbad = XMM changed, 0xbad1 = x87 changed)",
            i,
            r.map(|e| e.kind),
            r.map(|e| e.rax).unwrap_or(0)
        );
    }
    let migrations = crate::sched::user_migrations() - mig0;
    check!(migrated != 0 || migrations != 0, "no xmm process ever moved to another CPU");
    serial_println!(
        "[SMP TEST] 5/5 {} x xmm (xmm0-15 + st0), {} seen on 2+ CPUs, {} migrations, no register leaked PASS",
        xmm.len(),
        migrated.count_ones(),
        migrations
    );

    crate::selftest::pass();
}
