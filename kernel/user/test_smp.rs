// SMP self-tests – cores online, tasks on many CPUs, processes
// in parallel, syscalls from several CPUs at once (only builds with --cfg selftest).

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

// The test 2 spinners finish ON THEIR OWN (after >= 2 CPUs or after 10 s of HPET time) –
// waiting for a STOP from the test task was unreliable, since that task could be starved.
/// CPUs the spinners ran on (they record them themselves).
static SPIN_CPUS: AtomicU64 = AtomicU64::new(0);
/// How many CPUs the spinners must visit in total to finish early.
static SPIN_GOAL: AtomicU64 = AtomicU64::new(2);
/// After how many ms (+1) from the start the goal was reached (0 = not yet).
static SPIN_DONE_AT: AtomicU64 = AtomicU64::new(0);
/// Clock timestamp (clock::stamp) of the spinners' start – real time in the dump.
static SPIN_CLOCK: AtomicU64 = AtomicU64::new(0);

/// The spinners start together (after all have been created).
static SPIN_GO: AtomicBool = AtomicBool::new(false);
const SPIN_LIMIT_US: u64 = 10_000_000;

fn spinner(i: usize) {
    // We spin WITHOUT the Big Kernel Lock (atomics only).  If the spinner
    // held the BKL all the time, releasing it only in the tick, the test task
    // would create the spinners bit by bit every 10 ms, the BSP would wait for the BKL
    // with interrupts disabled and lose PIT ticks – on real hardware a "10 s" test
    // took 99 s, and spinners 1–3 started only after the deadline (mask 0b1000).
    // The deadline is measured with the HPET clock (real time), not ticks.
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
            // Done once together we have been on enough CPUs – fast hardware
            // finishes in milliseconds, a slow emulator has up to 10 s.
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

/// State of all CPUs, the BKL and the spinners (only when in trouble).
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

    // 1. Cores from the MADT are running, LAPIC timers are ticking.
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
    serial_println!("[SMP TEST] 1/7 {} CPU(s) online, LAPIC timers ticking PASS", n);
    if n == 1 {
        serial_println!("[SMP TEST] one CPU - skipping parallel tests");
        crate::selftest::pass();
        return;
    }

    // 2. Kernel tasks land on different CPUs (BKL handed over in the tick).
    //    The spinners finish on their own: once together they have been on >= 2 CPUs or after 10 s;
    //    the test only watches (and measures how long it took other CPUs to take over the work).
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
    // After 3 s without a second CPU – state dump (diagnostics for a rare FAIL
    // under TCG: who holds the BKL, who waits, whether timers tick).
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
        "[SMP TEST] 2/7 {} kernel tasks on CPU mask {:#b}, second CPU after {} ms PASS",
        k,
        mask,
        done_at.saturating_sub(1)
    );

    // 3. Truly parallel processes: several `primes` at once on different CPUs.
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
    // With 2 CPUs the second one is occupied by this test task – parallelism from 3.
    check!(n < 3 || max_parallel >= 2, "processes never ran at the same time (max {} CPUs)", max_parallel);
    serial_println!(
        "[SMP TEST] 3/7 {} x primes: up to {} running at once, {} ms PASS",
        n,
        max_parallel,
        wall
    );

    // 4. Syscalls from many CPUs at once: several shells (spawn/wait, VFS, files).
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
    serial_println!("[SMP TEST] 4/7 {} shells at once (spawn/wait/VFS), {} wake-up IPIs PASS", shells.len(), ipis);

    // 5. FPU/SSE during migration: 2n xmm processes (more than CPUs – they must
    //    switch and move between cores), no register leaks.
    let code = programs::code("xmm");
    check!(code.is_some(), "no xmm program");
    let mut xmm = Vec::new();
    for i in 0..n * 2 {
        let id = spawn_process("xmm", code.unwrap(), 0x1000_0000_0000 * (i as u64 + 1));
        check!(id.is_ok(), "spawn xmm");
        xmm.push(id.unwrap());
    }
    let mut migrated = 0u16;
    // Scheduler counter – sampling cpu_mask every 5 ms missed migrations
    // of processes that had already finished (under KVM processes
    // start without the BKL and finish within tens of ms).
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
        "[SMP TEST] 5/7 {} x xmm (xmm0-15 + st0), {} seen on 2+ CPUs, {} migrations, no register leaked PASS",
        xmm.len(),
        migrated.count_ones(),
        migrations
    );

    // 6. Task table under an RW lock – readers (with_process,
    //    task_exists) on other CPUs during process spawn / exit / reap;
    //    a task freed under a reader = bad tag = FAIL.
    if !table_test(n) {
        return;
    }
    // 7. Switching outside the scheduler lock – pairs of tasks on different CPUs
    //    wake each other in a loop (a lost wake-up = waiting until the deadline
    //    1 s = FAIL), next to tasks that are exiting (reap vs on_cpu).
    if !switch_test(n) {
        return;
    }

    crate::selftest::pass();
}

static T6_STOP: AtomicBool = AtomicBool::new(false);
static T6_OPS: AtomicU64 = AtomicU64::new(0);
static T6_FOUND: AtomicU64 = AtomicU64::new(0);
static T6_DONE: AtomicU64 = AtomicU64::new(0);
static T6_IDS: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];

fn table_reader(i: usize) {
    crate::sched::bkl::unlocked(|| {
        let mut k = i * 7;
        while !T6_STOP.load(Ordering::Relaxed) {
            let id = T6_IDS[k % 64].load(Ordering::Relaxed);
            k = k.wrapping_add(1);
            if id == 0 {
                core::hint::spin_loop();
                continue;
            }
            if crate::sched::with_process(id, |p| p.ppid()).is_some() {
                T6_FOUND.fetch_add(1, Ordering::Relaxed);
            }
            let _ = crate::sched::task_exists(id);
            T6_OPS.fetch_add(1, Ordering::Relaxed);
        }
    });
    T6_DONE.fetch_add(1, Ordering::SeqCst);
}

fn table_test(n: usize) -> bool {
    macro_rules! ck {
        ($cond:expr, $($msg:tt)*) => {
            if !$cond {
                serial_println!("[SMP TEST] FAIL: task table: {}", format_args!($($msg)*));
                T6_STOP.store(true, Ordering::SeqCst);
                return false;
            }
        };
    }
    let code = programs::code("pid");
    ck!(code.is_some(), "no pid program");
    let bad0 = crate::sched::table_bad();
    T6_STOP.store(false, Ordering::SeqCst);
    T6_DONE.store(0, Ordering::SeqCst);
    T6_OPS.store(0, Ordering::SeqCst);
    T6_FOUND.store(0, Ordering::SeqCst);
    let readers = (n.max(2) - 1).min(4);
    for i in 0..readers {
        ck!(crate::sched::spawn("table-reader", table_reader, i).is_ok(), "spawn reader");
    }
    let end = ticks() + 1500;
    let mut spawned = 0u64;
    let mut live: Vec<TaskId> = Vec::new();
    while ticks() < end {
        // Alive = has a process that has not finished (task_exists also sees
        // finished ones until they are reaped – and reaping is done by spawn or idle,
        // which is absent when CPUs are busy: KVM, 16 processes).
        live.retain(|&id| crate::sched::with_process(id, |_| ()).is_some());
        if live.len() < 16 {
            match spawn_process("pid", code.unwrap(), 0) {
                Ok(id) => {
                    T6_IDS[(spawned % 64) as usize].store(id, Ordering::Relaxed);
                    live.push(id);
                    spawned += 1;
                }
                Err(e) => ck!(false, "spawn pid: {}", e),
            }
        } else {
            crate::sched::yield_now();
        }
    }
    T6_STOP.store(true, Ordering::SeqCst);
    ck!(wait_for(5_000, || T6_DONE.load(Ordering::SeqCst) == readers as u64), "readers did not stop");
    ck!(wait_for(5_000, || live.iter().all(|&id| crate::sched::with_process(id, |_| ()).is_none())), "pid processes did not end");
    for a in T6_IDS.iter() {
        a.store(0, Ordering::Relaxed);
    }
    let bad = crate::sched::table_bad() - bad0;
    let ops = T6_OPS.load(Ordering::SeqCst);
    ck!(bad == 0, "{} freed task(s) seen by readers of the task table", bad);
    ck!(spawned >= 20 && ops >= 1000, "too little churn: {} processes, {} lookups", spawned, ops);
    serial_println!(
        "[SMP TEST] 6/7 task table: {} lookups on {} CPU(s) ({} found a live process) while {} processes started, ended and were freed, no freed task seen PASS",
        ops,
        readers,
        T6_FOUND.load(Ordering::SeqCst),
        spawned
    );
    true
}

const PAIRS: usize = 4;
static T7_STOP: AtomicBool = AtomicBool::new(false);
static T7_TURN: [AtomicU64; PAIRS] = [const { AtomicU64::new(0) }; PAIRS];
static T7_ROUNDS: AtomicU64 = AtomicU64::new(0);
static T7_LOST: AtomicU64 = AtomicU64::new(0);
static T7_DONE: AtomicU64 = AtomicU64::new(0);
static T7_DYING: AtomicU64 = AtomicU64::new(0);
static T7_WQ: [[crate::sched::sync::WaitQueue; 2]; PAIRS] =
    [const { [const { crate::sched::sync::WaitQueue::new() }; 2] }; PAIRS];

/// Task `i` = pair i / 2, side i % 2: waits for its turn, hands it over to
/// the other side and wakes it.
fn pinger(i: usize) {
    let (pair, side) = (i / 2, (i % 2) as u64);
    while !T7_STOP.load(Ordering::Relaxed) {
        let ok = T7_WQ[pair][side as usize].wait_until(
            || T7_TURN[pair].load(Ordering::SeqCst) == side || T7_STOP.load(Ordering::Relaxed),
            Some(1000),
        );
        if T7_STOP.load(Ordering::Relaxed) {
            break;
        }
        if !ok {
            T7_LOST.fetch_add(1, Ordering::SeqCst);
        }
        T7_ROUNDS.fetch_add(1, Ordering::Relaxed);
        T7_TURN[pair].store(1 - side, Ordering::SeqCst);
        T7_WQ[pair][1 - side as usize].wake_all();
    }
    // The other side may be waiting – wake it at the end.
    T7_WQ[pair][1 - side as usize].wake_all();
    T7_DONE.fetch_add(1, Ordering::SeqCst);
}

fn dying(_: usize) {
    T7_DYING.fetch_add(1, Ordering::Relaxed);
}

fn switch_test(n: usize) -> bool {
    macro_rules! ck {
        ($cond:expr, $($msg:tt)*) => {
            if !$cond {
                serial_println!("[SMP TEST] FAIL: switch outside the lock: {}", format_args!($($msg)*));
                T7_STOP.store(true, Ordering::SeqCst);
                return false;
            }
        };
    }
    let _ = n;
    T7_STOP.store(false, Ordering::SeqCst);
    T7_ROUNDS.store(0, Ordering::SeqCst);
    T7_LOST.store(0, Ordering::SeqCst);
    T7_DONE.store(0, Ordering::SeqCst);
    T7_DYING.store(0, Ordering::SeqCst);
    for t in T7_TURN.iter() {
        t.store(0, Ordering::SeqCst);
    }
    let (sw0, ow0, us0) = crate::sched::switch_stats();
    for i in 0..PAIRS * 2 {
        ck!(crate::sched::spawn("pinger", pinger, i).is_ok(), "spawn pinger");
    }
    let end = ticks() + 1500;
    let mut spawned = 0u64;
    while ticks() < end {
        if crate::sched::spawn("dying", dying, 0).is_ok() {
            spawned += 1;
        }
        if spawned % 8 == 0 {
            crate::time::sleep_ms(1);
        }
    }
    T7_STOP.store(true, Ordering::SeqCst);
    for p in T7_WQ.iter() {
        p[0].wake_all();
        p[1].wake_all();
    }
    ck!(wait_for(5_000, || T7_DONE.load(Ordering::SeqCst) == (PAIRS * 2) as u64), "pingers did not stop ({} of {})", T7_DONE.load(Ordering::SeqCst), PAIRS * 2);
    ck!(wait_for(5_000, || T7_DYING.load(Ordering::SeqCst) == spawned), "short tasks did not all run ({} of {})", T7_DYING.load(Ordering::SeqCst), spawned);
    let rounds = T7_ROUNDS.load(Ordering::SeqCst);
    let lost = T7_LOST.load(Ordering::SeqCst);
    let (sw1, ow1, ow_us) = crate::sched::switch_stats();
    ck!(lost == 0, "{} wake-up(s) lost (waited the whole 1 s) in {} rounds", lost, rounds);
    ck!(rounds >= 200, "too few rounds: {}", rounds);
    serial_println!(
        "[SMP TEST] 7/7 task switches outside the scheduler lock: {} wake-up rounds in {} pairs + {} short tasks ended and freed, none lost; {} switches, {} waited for a task still leaving another CPU ({} us) PASS",
        rounds,
        PAIRS,
        spawned,
        sw1 - sw0,
        ow1 - ow0,
        ow_us - us0
    );
    true
}
