// SMP stress test – run after every change that narrows the use of the BKL.
//
// For `ms` milliseconds, all at once:
//   * a pool of processes (shell with a script: directories, files, spawn/wait;
//     `primes`), each one checked as soon as it finishes (exit code, output)
//     and replaced with a new one,
//   * `xmm` processes (FPU/SSE registers across context switches and migration),
//   * kernel tasks that hammer spinlocks WITHOUT the Big Kernel Lock (bkl::unlocked):
//     the counter under a SpinLock must match exactly the sum of the tasks'
//     local counters.
// At the end: no deadlock reports, all tasks cleaned up,
// free frames back to the pre-test level (no leak).
//
// Self-test `[STRESS TEST]` (short) and the `stress [s]` command (longer, manual).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::*;
use crate::arch::x86_64::{cpu::MAX_CPUS, smp};
use crate::sched::bkl;
use crate::sched::spin::{level, IrqSpinLock, SpinLock};
use crate::time::ticks;

static STOP: AtomicBool = AtomicBool::new(false);
static SPIN_COUNTER: SpinLock<u64> = SpinLock::new("stress-counter", level::TEST_INNER, 0);
static IRQ_COUNTER: IrqSpinLock<u64> = IrqSpinLock::new("stress-irq-counter", level::TEST_IRQ, 0);
static LOCAL: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static TICK_HITS: AtomicU64 = AtomicU64::new(0);
/// Heap and frame allocations without the BKL (tasks + timer interrupt).
static ALLOC_OPS: AtomicU64 = AtomicU64::new(0);
static FRAME_OPS: AtomicU64 = AtomicU64::new(0);
/// First detected allocation error (0 = none): 1 = data in a heap block
/// overwritten, 2 = data in a frame overwritten, 3 = out of memory.
static ALLOC_BAD: AtomicU64 = AtomicU64::new(0);

/// Test result.
pub struct Report {
    pub ms: u64,
    pub cpus: usize,
    /// Shell scripts, primes, IPC tasks (ipcload).
    pub jobs: [u64; 3],
    pub xmm: usize,
    pub spin_ops: u64,
    pub spin_contended: u64,
    pub allocs: u64,
    pub frames: u64,
    pub bkl_taken: u64,
    pub bkl_waited: u64,
    /// Percentage of (all) CPU time spent in idle `hlt`.
    pub idle_pct: u64,
    /// Percentage of time the stress driver loop was working (outside
    /// its 2 ms sleep) – close to 100% = the stress test limits itself.
    pub driver_pct: u64,
    /// Number of driver loops.
    pub drivers: usize,
    /// Size of the process pool (measurement configuration).
    pub pool: usize,
    /// Kernel entry profile (prof.rs).
    pub prof: Vec<String>,
}

impl Report {
    /// Result in a few short lines – for the screen (autostress, `stress`); a single
    /// long line did not fit the screen width.
    pub fn lines(&self) -> Vec<String> {
        alloc::vec![
            format!("{} ms on {} CPU(s)", self.ms, self.cpus),
            format!(
                "  mode:  {} - pool {} processes, {} driver(s)",
                if pool_per_cpu() == 0 { "compare (default)" } else { "max load (DESOOS_STRESS_POOL)" },
                self.pool,
                self.drivers
            ),
            format!("  load:  {}% idle, {} stress driver(s) {}% busy", self.idle_pct, self.drivers, self.driver_pct),
            format!("  jobs:  {} shell scripts + {} primes + {} xmm OK", self.jobs[0], self.jobs[1], self.xmm),
            format!(
                "  ipc:   {} ipcload jobs OK ({} round trips via shared memory + channel, {} children killed while waiting)",
                self.jobs[2],
                self.jobs[2] * IPCLOAD_ROUNDS,
                self.jobs[2]
            ),
            format!("  spin:  {} spinlock ops ({} contended)", self.spin_ops, self.spin_contended),
            format!("  alloc: {} heap + {} frame allocs without BKL", self.allocs, self.frames),
            format!("  BKL:   taken {} times, waited {} times", self.bkl_taken, self.bkl_waited),
        ]
        .into_iter()
        .chain(self.prof.iter().cloned())
        .collect()
    }
}

impl core::fmt::Display for Report {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "{} ms on {} CPU(s), {}% idle, {} driver(s) {}% busy: {} shell scripts + {} primes + {} xmm OK; {} spinlock ops, {} heap + {} frame allocs without BKL ({} contended); BKL taken {} times, waited {} times",
            self.ms, self.cpus, self.idle_pct, self.drivers, self.driver_pct, self.jobs[0], self.jobs[1], self.xmm, self.spin_ops, self.allocs, self.frames, self.spin_contended, self.bkl_taken, self.bkl_waited
        )
    }
}

/// Operations on the shared counter per round (followed by allocations and
/// a 1 ms sleep).  With 500, 16 tasks spun on a single lock – on real hardware
/// a large share of CPU went to waiting alone, so stress measured itself more than the system.  50
/// still gives millions of contended operations (the lost-increment test remains).
const HAMMER_OPS: usize = 50;

/// Kernel task: loops on spinlocks without the BKL, with a short sleep every so often.
fn hammer(i: usize) {
    // The whole loop runs without the BKL – including the sleep (the scheduler does not need the BKL).
    // Re-taking the BKL after every round just for sleep_ms(1) caused
    // a huge number of "end of bkl::unlocked" acquisitions and seconds of waiting.
    bkl::unlocked(|| while !STOP.load(Ordering::Relaxed) {
        {
            for _ in 0..HAMMER_OPS {
                {
                    let mut g = SPIN_COUNTER.lock();
                    // Non-atomic read-modify-write: without mutual
                    // exclusion it would lose increments.
                    let v = core::hint::black_box(*g);
                    *g = v + 1;
                }
                LOCAL[i % MAX_CPUS].fetch_add(1, Ordering::Relaxed);
                if i % 2 == 0 {
                    let mut g = IRQ_COUNTER.lock();
                    *g += 1;
                }
            }
            // Heap and frame allocator without the BKL, on many CPUs at once.
            alloc_round(i);
        }
        crate::time::sleep_ms(1);
    });
}

/// Allocation round (without the BKL): blocks of various sizes with a pattern
/// that depends on the task (overwrite by another CPU = error), every 8th round
/// a frame from the frame allocator (write via the direct map, check, free).
fn alloc_round(i: usize) {
    let seed = (i as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut kept: Vec<Vec<u64>> = Vec::new();
    for k in 0..16u64 {
        let len = 1 + (((seed >> (k % 32)) as usize).wrapping_add(k as usize * 37)) % 700;
        let mut v: Vec<u64> = Vec::new();
        if v.try_reserve_exact(len).is_err() {
            ALLOC_BAD.store(3, Ordering::Relaxed);
            return;
        }
        for j in 0..len as u64 {
            v.push(seed ^ (k << 32) ^ j);
        }
        kept.push(v);
        ALLOC_OPS.fetch_add(1, Ordering::Relaxed);
    }
    for (k, v) in kept.iter().enumerate() {
        if v.iter().enumerate().any(|(j, &x)| x != seed ^ ((k as u64) << 32) ^ j as u64) {
            let _ = ALLOC_BAD.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
        }
    }
    drop(kept);
    if LOCAL[i % MAX_CPUS].load(Ordering::Relaxed) % 8 == 0 {
        match crate::memory::alloc_frame() {
            Some(f) => {
                let p = crate::memory::phys_to_virt(f) as *mut u64;
                unsafe {
                    for j in 0..512 {
                        p.add(j).write_volatile(seed ^ j as u64);
                    }
                    if (0..512).any(|j| p.add(j).read_volatile() != seed ^ j as u64) {
                        let _ = ALLOC_BAD.compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst);
                    }
                }
                crate::memory::free_frame(f);
                FRAME_OPS.fetch_add(1, Ordering::Relaxed);
            }
            None => ALLOC_BAD.store(3, Ordering::Relaxed),
        }
    }
}

/// Timer tick hook (interrupt on the BSP) – the same IrqSpinLock as the tasks;
/// also allocates from the interrupt (heap under an IrqSpinLock).
fn tick_hook(_: u64) {
    let mut g = IRQ_COUNTER.lock();
    *g += 1;
    TICK_HITS.fetch_add(1, Ordering::Relaxed);
    drop(g);
    let b = alloc::boxed::Box::new([0x5au8; 48]);
    if b.iter().any(|&x| x != 0x5a) {
        let _ = ALLOC_BAD.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
    }
    ALLOC_OPS.fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, Copy)]
enum Job {
    Shell,
    Primes,
    /// /bin/ipcload – a pair of processes on a channel + shared memory,
    /// the child is killed while waiting.  One per driver loop, OUTSIDE the pool
    /// (the script pool is unchanged – the comparison mode stays comparable).
    Ipc,
}

/// Exchanges in one ipcload run (user/bin/ipcload.rs, ROUNDS).
const IPCLOAD_ROUNDS: u64 = 200;

fn start_job(kind: Job, n: u64) -> Result<TaskId, String> {
    let (path, args, script): (&str, Vec<&str>, String) = match kind {
        Job::Shell => (
            "/bin/sh",
            alloc::vec!["sh"],
            format!(
                "mkdir /st{n}\necho stress{n} > /st{n}/f\ncat /st{n}/f\nprimes 300\nls /st{n}\nrm /st{n}/f\nrm /st{n}\nexit 0\n"
            ),
        ),
        Job::Primes => ("/bin/primes", alloc::vec!["primes", "20000"], String::new()),
        Job::Ipc => ("/bin/ipcload", alloc::vec!["ipcload"], String::new()),
    };
    // foreground: normal exit without a console message (thousands of processes).
    let opts = SpawnOptions { stdin: Some(script.into_bytes()), capture: true, foreground: true, ..SpawnOptions::default() };
    let t0 = prof::start();
    let r = exec(path, &args, "/", &opts).map_err(|e| format!("{}", e));
    prof::stop(prof::DRV_EXEC, t0);
    r
}

fn check_job(kind: Job, n: u64, id: TaskId) -> Result<(), String> {
    let kind_ok = exit_info(id).map(|e| e.kind);
    let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
    if kind_ok != Some(ExitKind::Exit(0)) {
        if kind_ok.is_none() {
            return Err(format!("job {}: exit record already evicted from the exit log (output: {})", id, out));
        }
        return Err(format!("job {} ended with {:?}: {}", id, kind_ok, out));
    }
    let want = match kind {
        Job::Shell => format!("stress{}", n),
        Job::Primes => String::from("2262 primes below 20000"),
        Job::Ipc => format!("ipcload: OK {} round trips", IPCLOAD_ROUNDS),
    };
    if !out.contains(&want) {
        return Err(format!("job {} output lacks {:?}: {}", id, want, out));
    }
    if let Job::Shell = kind {
        if !out.contains("62 primes below 300") {
            return Err(format!("shell {} output lacks primes: {}", id, out));
        }
        if crate::fs::stat(&format!("/st{}", n)).is_ok() {
            return Err(format!("shell {}: /st{} not removed: {}", id, n, out));
        }
    }
    Ok(())
}

fn wait_for(ms: u64, cond: impl Fn() -> bool) -> bool {
    let end = ticks() + ms;
    while !cond() {
        if ticks() > end {
            return false;
        }
        crate::time::sleep_ms(1);
    }
    true
}

// Stress driver loops – each has its own part of the pool and its own
// task numbers (d, d + D, d + 2D, ...).
static DRV_END: AtomicU64 = AtomicU64::new(0);
static DRV_COUNT: AtomicU64 = AtomicU64::new(1);
static DRV_POOL: AtomicU64 = AtomicU64::new(1);
static DRV_DONE: AtomicU64 = AtomicU64::new(0);
static DRV_BUSY_US: AtomicU64 = AtomicU64::new(0);
static DRV_TOTAL_US: AtomicU64 = AtomicU64::new(0);
static DRV_JOBS: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
static DRV_ERR: crate::sched::sync::Mutex<Option<String>> = crate::sched::sync::Mutex::new(None);

fn driver(d: usize) {
    // Without the BKL: exec, result checking and the VFS have their own locks.
    bkl::unlocked(|| driver_loop(d));
    DRV_DONE.fetch_add(1, Ordering::SeqCst);
}

fn driver_loop(d: usize) {
    let end = DRV_END.load(Ordering::SeqCst);
    let step = DRV_COUNT.load(Ordering::SeqCst);
    let pool = DRV_POOL.load(Ordering::SeqCst) as usize;
    let mut running: Vec<(Job, u64, TaskId)> = Vec::new();
    let mut next = d as u64;
    let t0 = crate::arch::x86_64::clock::stamp();
    let mut busy: u64 = 0;
    let mut counted = false;
    let mut err: Option<String> = None;
    while err.is_none() && !STOP.load(Ordering::Relaxed) && (ticks() < end || !running.is_empty()) {
        let loop_t0 = crate::arch::x86_64::clock::stamp();
        // Finished.
        let mut i = 0;
        while i < running.len() {
            let (kind, num, id) = running[i];
            if !sched::task_exists(id) {
                running.swap_remove(i);
                match check_job(kind, num, id) {
                    Ok(()) => {
                        DRV_JOBS[kind as usize].fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => err = Some(e),
                }
            } else {
                i += 1;
            }
        }
        // One IPC task per loop, outside the pool.
        if err.is_none() && ticks() < end && !running.iter().any(|r| matches!(r.0, Job::Ipc)) {
            match start_job(Job::Ipc, next) {
                Ok(id) => running.push((Job::Ipc, next, id)),
                Err(e) => err = Some(format!("cannot start ipcload: {}", e)),
            }
        }
        // New ones (until time runs out).
        while err.is_none() && ticks() < end && running.iter().filter(|r| !matches!(r.0, Job::Ipc)).count() < pool {
            let kind = if next % 3 == 2 { Job::Primes } else { Job::Shell };
            match start_job(kind, next) {
                Ok(id) => running.push((kind, next, id)),
                Err(e) => {
                    let (used, max) = crate::sched::stack::used_slots();
                    err = Some(format!("cannot start job {}: {} (task stack slots {}/{})", next, e, used, max))
                }
            }
            next += step;
        }
        if ticks() < end {
            busy += crate::arch::x86_64::clock::elapsed_us(loop_t0);
        } else if !counted {
            counted = true;
            DRV_BUSY_US.fetch_add(busy, Ordering::SeqCst);
            DRV_TOTAL_US.fetch_add(crate::arch::x86_64::clock::elapsed_us(t0), Ordering::SeqCst);
        }
        crate::time::sleep_ms(2);
    }
    if let Some(e) = err {
        STOP.store(true, Ordering::SeqCst);
        DRV_ERR.lock().get_or_insert(e);
    }
}

/// Stress test for `ms` ms.  Err = description of the first error.
pub fn run(ms: u64) -> Result<Report, String> {
    let n = smp::online_count();
    let frames0 = crate::sched::stack::free_frames_flushed();
    let heap0 = crate::memory::heap::mapped_bytes() as u64;
    let tasks0 = sched::tasks().len();
    let (_, _, dl0) = crate::sched::spin::stats();
    let (bkl_a0, bkl_c0, _) = bkl::stats();
    let (_, spin_c0, _) = crate::sched::spin::stats();

    STOP.store(false, Ordering::SeqCst);
    *SPIN_COUNTER.lock() = 0;
    *IRQ_COUNTER.lock() = 0;
    TICK_HITS.store(0, Ordering::SeqCst);
    ALLOC_OPS.store(0, Ordering::SeqCst);
    FRAME_OPS.store(0, Ordering::SeqCst);
    ALLOC_BAD.store(0, Ordering::SeqCst);
    for l in LOCAL.iter() {
        l.store(0, Ordering::SeqCst);
    }

    // Kernel tasks on spinlocks (one per CPU, at most 8).
    let mut hammers = Vec::new();
    for i in 0..n.clamp(2, 8) {
        hammers.push(sched::spawn("stress-spin", hammer, i).map_err(|e| format!("spawn hammer: {}", e))?);
    }
    crate::time::set_tick_hook(Some(tick_hook));

    // xmm processes (FPU/SSE registers), at most as many as there are CPUs.
    let xmm_code = programs::code("xmm").ok_or("no xmm program")?;
    let mut xmm = Vec::new();
    let mut xmm_left: Vec<TaskId> = Vec::new();
    for i in 0..n.min(4) {
        let id = spawn_process("xmm", xmm_code, 0x5000_0000_0000 + i as u64 * 0x1000_0000).map_err(|e| format!("spawn xmm: {}", e))?;
        xmm.push(id);
        xmm_left.push(id);
    }
    // xmm result checked right after exit (the exit log keeps the last 64).
    let check_xmm = |left: &mut Vec<TaskId>| -> Result<(), String> {
        let mut i = 0;
        while i < left.len() {
            let x = left[i];
            if !sched::task_exists(x) {
                let r = exit_info(x);
                if r.map(|e| (e.kind, e.rax)) != Some((ExitKind::Breakpoint, 1)) {
                    return Err(format!("xmm {}: {:?} rax {:#x}", x, r.map(|e| e.kind), r.map(|e| e.rax).unwrap_or(0)));
                }
                left.swap_remove(i);
            } else {
                i += 1;
            }
        }
        Ok(())
    };

    // Process pool: finished = checked and replaced.
    // 3 per CPU, at most 48 (with 2 per CPU, at most 12, the CPUs on real hardware
    // were mostly idle, so stress measured the latency of a single
    // task rather than throughput).  The captured output buffer keeps
    // the last CAPTURED_LOG = 256, the exit log EXIT_LOG = 2048 – with headroom.
    // Two measurement modes.  Default (3 per CPU, at most 48) – fixed,
    // comparable between versions.  Full load: build with
    // DESOOS_STRESS_POOL=P (P per CPU, at most 128 – the captured
    // output log keeps the last 256).  In default mode a noticeable share of
    // idle time remains – the stress test limits itself.
    let per_cpu = pool_per_cpu();
    let pool = if per_cpu == 0 { (n * 3).clamp(2, 48) } else { (n * per_cpu).clamp(2, 128) };
    // Several driver loops (kernel tasks without the BKL) – a single one was
    // ~90% busy and limited the stress test.  One per 4 CPUs,
    // at most 4; the pool is split between them.
    let drivers = (n / 4).clamp(1, 4);
    let end = ticks() + ms;
    DRV_END.store(end, Ordering::SeqCst);
    DRV_COUNT.store(drivers as u64, Ordering::SeqCst);
    DRV_POOL.store((pool / drivers).max(1) as u64, Ordering::SeqCst);
    DRV_DONE.store(0, Ordering::SeqCst);
    DRV_BUSY_US.store(0, Ordering::SeqCst);
    DRV_TOTAL_US.store(0, Ordering::SeqCst);
    for j in DRV_JOBS.iter() {
        j.store(0, Ordering::SeqCst);
    }
    *DRV_ERR.lock() = None;
    prof::reset();
    let idle_sum = || (0..crate::arch::x86_64::cpu::MAX_CPUS).filter(|&c| smp::online(c)).map(sched::idle_us).sum::<u64>();
    let (idle0, t_idle0) = (idle_sum(), ticks());
    let mut idle_pct: Option<u64> = None;
    let mut err: Option<String> = None;
    for d in 0..drivers {
        if let Err(e) = sched::spawn("stress-driver", driver, d) {
            err = Some(format!("spawn driver: {}", e));
            STOP.store(true, Ordering::SeqCst);
            break;
        }
    }
    let spawned = if err.is_some() { DRV_DONE.load(Ordering::SeqCst) } else { drivers as u64 };
    while DRV_DONE.load(Ordering::SeqCst) < spawned {
        if ticks() >= end && idle_pct.is_none() {
            let cpu_us = (ticks() - t_idle0).max(1) * 1000 * n as u64;
            idle_pct = Some(((idle_sum() - idle0) * 100 / cpu_us).min(100));
        }
        if let Err(e) = check_xmm(&mut xmm_left) {
            err.get_or_insert(e);
            STOP.store(true, Ordering::SeqCst);
        }
        crate::time::sleep_ms(2);
        if ticks() > end + 60_000 {
            err.get_or_insert(String::from("job(s) still running 60 s after the end"));
            STOP.store(true, Ordering::SeqCst);
        }
        if ticks() > end + 70_000 {
            break;
        }
    }
    if err.is_none() {
        err = DRV_ERR.lock().take();
    }
    let jobs = [DRV_JOBS[0].load(Ordering::SeqCst), DRV_JOBS[1].load(Ordering::SeqCst), DRV_JOBS[2].load(Ordering::SeqCst)];
    let prof_lines = prof::lines(12, (ticks() - t_idle0).max(1) * n as u64, jobs[0]);
    let driver_pct =
        (DRV_BUSY_US.load(Ordering::SeqCst) * 100 / DRV_TOTAL_US.load(Ordering::SeqCst).max(1)).min(100);

    // Cleanup: stop the kernel tasks, end xmm.
    STOP.store(true, Ordering::SeqCst);
    crate::time::set_tick_hook(None);
    if !wait_for(5_000, || hammers.iter().all(|&h| !sched::task_exists(h))) {
        err.get_or_insert(String::from("spinlock tasks did not stop"));
    }
    let deadline = ticks() + 120_000;
    while err.is_none() && !xmm_left.is_empty() && ticks() < deadline {
        if let Err(e) = check_xmm(&mut xmm_left) {
            err = Some(e);
        }
        crate::time::sleep_ms(2);
    }
    if !xmm_left.is_empty() {
        err.get_or_insert(String::from("xmm processes did not finish"));
    }
    if let Some(e) = err {
        return Err(e);
    }

    // Spinlocks: counter == sum of local counters.
    let local: u64 = LOCAL.iter().map(|l| l.load(Ordering::SeqCst)).sum();
    let counted = *SPIN_COUNTER.lock();
    if counted != local {
        return Err(format!("SpinLock lost updates: counter {} != {} increments", counted, local));
    }
    let irq_expected: u64 = (0..hammers.len()).filter(|i| i % 2 == 0).map(|i| LOCAL[i].load(Ordering::SeqCst)).sum::<u64>()
        + TICK_HITS.load(Ordering::SeqCst);
    let irq_counted = *IRQ_COUNTER.lock();
    if irq_counted != irq_expected {
        return Err(format!("IrqSpinLock lost updates: {} != {}", irq_counted, irq_expected));
    }
    match ALLOC_BAD.load(Ordering::SeqCst) {
        0 => {}
        1 => return Err(String::from("heap block overwritten (allocation without BKL)")),
        2 => return Err(String::from("frame contents overwritten (frame allocator without BKL)")),
        _ => return Err(String::from("out of memory in the allocation rounds")),
    }
    let (_, spin_c1, dl1) = crate::sched::spin::stats();
    if dl1 != dl0 {
        return Err(format!("{} deadlock report(s) during the test", dl1 - dl0));
    }

    // Everything cleaned up, frames returned (idle reaps finished tasks).
    if !wait_for(3_000, || sched::tasks().len() == tasks0) {
        return Err(format!("{} task(s) left over", sched::tasks().len() as i64 - tasks0 as i64));
    }
    // Pages the heap still holds (it returns them above SHRINK_AT) are
    // not a leak; page tables of kernel regions may linger for a while.
    // A real leak is a few frames per process x hundreds of processes, so
    // the PT_SLACK tolerance will not hide it.
    const PT_SLACK: u64 = 32;
    let heap_growth = || (crate::memory::heap::mapped_bytes() as u64).saturating_sub(heap0) / 4096;
    if !wait_for(3_000, || crate::sched::stack::free_frames_flushed() + heap_growth() + PT_SLACK >= frames0) {
        return Err(format!(
            "frame leak: {} free before, {} after (+{} heap pages, {} allowed for page tables)",
            frames0,
            crate::memory::free_frame_count(),
            heap_growth(),
            PT_SLACK
        ));
    }
    let (bkl_a1, bkl_c1, _) = bkl::stats();
    Ok(Report {
        ms,
        cpus: n,
        jobs,
        xmm: xmm.len(),
        spin_ops: local,
        spin_contended: spin_c1 - spin_c0,
        allocs: ALLOC_OPS.load(Ordering::SeqCst),
        frames: FRAME_OPS.load(Ordering::SeqCst),
        bkl_taken: bkl_a1 - bkl_a0,
        bkl_waited: bkl_c1 - bkl_c0,
        idle_pct: idle_pct.unwrap_or(0),
        driver_pct,
        drivers,
        pool,
        prof: prof_lines,
    })
}


// ------------------------------------------------------------
// Automatic stress test after boot
// ------------------------------------------------------------

/// Seconds from the build (`DESOOS_AUTOSTRESS=60 ./make-usb.sh ...` or
/// `./build.sh --autostress=60`); 0 = disabled.
/// Processes per CPU from the build (`DESOOS_STRESS_POOL`); 0 = default mode.
pub fn pool_per_cpu() -> usize {
    match option_env!("DESOOS_STRESS_POOL") {
        Some(s) => s.trim().parse::<usize>().unwrap_or(0).min(32),
        None => 0,
    }
}

pub fn auto_seconds() -> u64 {
    match option_env!("DESOOS_AUTOSTRESS") {
        Some(s) => s.trim().parse::<u64>().unwrap_or(0).min(3600),
        None => 0,
    }
}

/// Starts a kernel task that runs the stress test after 5 s and prints the result
/// plus `cpus` and `mem` (serial + screen).  The system keeps running normally.
pub fn start_auto_from_build() {
    let secs = auto_seconds();
    if secs == 0 {
        return;
    }
    crate::serial_println!("[AUTOSTRESS v{}] stress test of {} s starts 5 s after boot", crate::shell::VERSION, secs);
    if crate::sched::spawn("autostress", auto_task, secs as usize).is_err() {
        crate::serial_println!("[AUTOSTRESS v{}] cannot start the task", crate::shell::VERSION);
    }
}

// ------------------------------------------------------------
// usbd in autostress – during the stress test a task keeps reading
// the largest file from the USB stick (/usbN, e.g. the boot stick on real hardware);
// every pass computes a checksum – all of them must be equal.
// ------------------------------------------------------------

static USB_STOP: AtomicBool = AtomicBool::new(false);
static USB_DONE: AtomicBool = AtomicBool::new(false);
static USB_BYTES: AtomicU64 = AtomicU64::new(0);
static USB_ERRORS: AtomicU64 = AtomicU64::new(0);
static USB_PASSES: AtomicU64 = AtomicU64::new(0);
static USB_MISMATCH: AtomicU64 = AtomicU64::new(0);
static USB_FILE: SpinLock<String> = SpinLock::new("autostress usb file", level::TEST_OUTER, String::new());

/// Largest file (≤ 64 MiB) under `dir`, up to 4 directory levels deep.
fn largest_file(dir: &str, depth: u32, best: &mut (u64, String)) {
    let Ok(entries) = crate::fs::read_dir(dir) else { return };
    for e in entries {
        if e.name == "." || e.name == ".." {
            continue;
        }
        let path = format!("{}/{}", dir, e.name);
        match e.kind {
            crate::fs::FileType::Directory if depth < 4 => largest_file(&path, depth + 1, best),
            crate::fs::FileType::File if e.size > best.0 && e.size <= 64 * 1024 * 1024 => *best = (e.size, path),
            _ => {}
        }
    }
}

fn usb_stress_task(_: usize) {
    let path = USB_FILE.lock().clone();
    let mut buf = alloc::vec![0u8; 65536];
    let mut first: Option<u64> = None;
    while !USB_STOP.load(Ordering::SeqCst) {
        let mut off = 0u64;
        let mut sum = 0u64;
        let mut ok = true;
        loop {
            if USB_STOP.load(Ordering::SeqCst) {
                ok = false; // incomplete pass – no comparison
                break;
            }
            match crate::fs::read(&path, off, &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    for (i, &b) in buf[..n].iter().enumerate() {
                        sum = sum.wrapping_mul(31).wrapping_add(b as u64 ^ (off + i as u64));
                    }
                    off += n as u64;
                    USB_BYTES.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(_) => {
                    USB_ERRORS.fetch_add(1, Ordering::Relaxed);
                    ok = false;
                    crate::time::sleep_ms(100);
                    break;
                }
            }
        }
        if ok {
            USB_PASSES.fetch_add(1, Ordering::Relaxed);
            match first {
                None => first = Some(sum),
                Some(f) if f != sum => {
                    USB_MISMATCH.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
    }
    USB_DONE.store(true, Ordering::SeqCst);
}

/// Starts reading from the USB stick (if mounted): Some(file).
fn usb_stress_start() -> Option<String> {
    let mount = crate::fs::mount_list().into_iter().find(|m| m.0.starts_with("/usb"))?;
    let mut best = (0u64, String::new());
    largest_file(&mount.0, 0, &mut best);
    if best.0 == 0 {
        return None;
    }
    *USB_FILE.lock() = best.1.clone();
    for a in [&USB_BYTES, &USB_ERRORS, &USB_PASSES, &USB_MISMATCH] {
        a.store(0, Ordering::SeqCst);
    }
    USB_STOP.store(false, Ordering::SeqCst);
    USB_DONE.store(false, Ordering::SeqCst);
    crate::sched::spawn("usb-stress", usb_stress_task, 0).ok()?;
    Some(best.1)
}

fn auto_task(secs: usize) {
    crate::time::sleep_ms(5_000);
    let cpus = crate::arch::x86_64::smp::online_count();
    crate::serial_println!("[AUTOSTRESS v{}] {} s on {} CPU(s)...", crate::shell::VERSION, secs, cpus);
    // Read from the USB stick on an idle system (before the stress test).
    let usb_calm = usb_calm_bench();
    let usb_file = usb_stress_start();
    let t_usb = ticks();
    let result = run(secs as u64 * 1000);
    let usb_ms = (ticks() - t_usb).max(1);
    if usb_file.is_some() {
        USB_STOP.store(true, Ordering::SeqCst);
        let t0 = ticks();
        while !USB_DONE.load(Ordering::SeqCst) && ticks() - t0 < 10_000 {
            crate::time::sleep_ms(10);
        }
    }
    let mut out = String::new();
    crate::shell::cpus_report(&mut out);
    crate::shell::mem_report(&mut out);
    for line in out.lines() {
        crate::serial_println!("[AUTOSTRESS v{}] {}", crate::shell::VERSION, line);
    }
    // IPC measurement after the stress test (idle system).
    let bench = run_ipcbench();
    let v = crate::shell::VERSION;
    match &result {
        Ok(r) => {
            for (i, l) in r.lines().iter().enumerate() {
                crate::serial_println!("[AUTOSTRESS v{}] {}{}", v, if i == 0 { "PASS: " } else { "" }, l);
            }
        }
        Err(e) => crate::serial_println!("[AUTOSTRESS v{}] FAIL: {}", v, e),
    }
    match &bench {
        Ok((human, _)) => crate::serial_println!("[AUTOSTRESS v{}]   {}", v, human),
        Err(e) => crate::serial_println!("[AUTOSTRESS v{}]   ipcbench FAIL: {}", v, e),
    }
    let (ub, ue, up, um) = (
        USB_BYTES.load(Ordering::SeqCst),
        USB_ERRORS.load(Ordering::SeqCst),
        USB_PASSES.load(Ordering::SeqCst),
        USB_MISMATCH.load(Ordering::SeqCst),
    );
    let usb_kv = match &usb_file {
        Some(f) => {
            crate::serial_println!(
                "[AUTOSTRESS v{}]   usb: {} read during the stress: {} MiB, {} KiB/s, {} full passes ({}), {} errors",
                v,
                f,
                ub / (1024 * 1024),
                ub * 1000 / 1024 / usb_ms,
                up,
                if up == 0 { String::from("none complete") } else if um == 0 { String::from("all identical") } else { format!("{} DIFFERENT", um) },
                ue
            );
            format!(" usb_mib={} usb_kbs={} usb_err={} usb_bad={}", ub / (1024 * 1024), ub * 1000 / 1024 / usb_ms, ue, um)
        }
        None => {
            crate::serial_println!("[AUTOSTRESS v{}]   usb: no USB disk mounted - USB read test skipped", v);
            String::new()
        }
    };
    // USB keyboard – from the xHCI interrupt to the character in the kernel (all
    // key presses since boot, including during the stress test).
    let (hn, havg, hmin, hmax) = crate::input::hid_latency();
    if hn == 0 {
        crate::serial_println!("[AUTOSTRESS v{}]   usb keyboard: no USB key presses since boot - latency not measured", v);
    } else {
        crate::serial_println!("[AUTOSTRESS v{}]   usb keyboard: {} key presses, interrupt -> character avg {} us (min {}, max {})", v, hn, havg, hmin, hmax);
    }
    let mut usb_line = format!("[RESULT-USB] ver={} hid_n={} hid_avg_us={} hid_max_us={}", v, hn, havg, hmax);
    if let Some((f, big, small, same)) = &usb_calm {
        crate::serial_println!(
            "[AUTOSTRESS v{}]   usb: {} read before the stress: {} KiB/s (256 KiB reads), {} KiB/s (4 KiB reads, like cat){}",
            v,
            f,
            big,
            small,
            if *same { ", identical" } else { ", DIFFERENT DATA" }
        );
        usb_line.push_str(&format!(" read_kbs={} cat_kbs={} same={}", big, small, *same as u8));
    }
    if let Some(kv) = usb_kv.strip_prefix(' ') {
        usb_line.push(' ');
        usb_line.push_str(kv);
    }
    // A single line for machine comparison of versions (agent / script).
    let mode = if pool_per_cpu() == 0 { String::from("compare") } else { format!("max{}", pool_per_cpu()) };
    let calm_ok = usb_calm.as_ref().map_or(true, |c| c.3);
    let pass = result.is_ok() && bench.is_ok() && ue == 0 && um == 0 && calm_ok;
    let line = match &result {
        Ok(r) => format!(
            "[RESULT] ver={} mode={} idlepoll={}{} cpus={} ms={} scripts={} primes={} ipc={} idle={} {}{} pass={}",
            v,
            mode,
            if crate::sched::idle_adapt() { "a" } else { "" },
            crate::sched::idle_poll_us(),
            r.cpus,
            r.ms,
            r.jobs[0],
            r.jobs[1],
            r.jobs[2],
            r.idle_pct,
            bench.as_ref().map(|(_, k)| k.clone()).unwrap_or_default(),
            usb_kv,
            pass as u8
        ),
        Err(e) => format!("[RESULT] ver={} mode={} cpus={} pass=0 error=\"{}\"", v, mode, cpus, e),
    };
    crate::serial_println!("{}", line);
    if usb_calm.is_some() || hn > 0 {
        crate::serial_println!("{}", usb_line);
    }
}

/// Largest file from /usbN (at most 64 MiB) with a 256 KiB and a 4 KiB buffer:
/// (file, KiB/s, KiB/s, same data).  None – no USB stick / error.
fn usb_calm_bench() -> Option<(String, u64, u64, bool)> {
    let mount = crate::fs::mount_list().into_iter().find(|m| m.0.starts_with("/usb"))?;
    let mut best = (0u64, String::new());
    largest_file(&mount.0, 0, &mut best);
    if best.0 == 0 {
        return None;
    }
    let max = 64 << 20;
    let big = crate::user::ublk::read_bench(&best.1, 256 * 1024, max);
    let small = crate::user::ublk::read_bench(&best.1, 4096, max.min(16 << 20));
    let kbs = |r: &Result<(u64, u64, u64), crate::fs::FsError>| r.as_ref().map(|&(b, us, _)| b * 1_000_000 / 1024 / us).unwrap_or(0);
    // Same length -> sums must be equal (4 KiB reads at most 16 MiB).
    let same = match (&big, &small) {
        (Ok((b1, _, s1)), Ok((b2, _, s2))) => b1 != b2 || s1 == s2,
        _ => false,
    };
    Some((best.1, kbs(&big), kbs(&small), same))
}

/// /bin/ipcbench – (line for humans, "k=v ..." for [RESULT]).
fn run_ipcbench() -> Result<(String, String), String> {
    let opts = SpawnOptions { stdin: Some(Vec::new()), capture: true, ..SpawnOptions::default() };
    let id = exec("/bin/ipcbench", &["ipcbench"], "/", &opts).map_err(|e| format!("{}", e))?;
    if !wait_for(120_000, || !sched::task_exists(id)) {
        let _ = sched::request_exit(id);
        return Err(String::from("did not finish in 120 s"));
    }
    let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
    if exit_info(id).map(|e| e.kind) != Some(ExitKind::Exit(0)) {
        return Err(String::from(out.trim()));
    }
    let human = out.lines().find(|l| l.starts_with("ipcbench: ")).unwrap_or("").into();
    let kv = out.lines().find_map(|l| l.strip_prefix("ipcbench-result ")).unwrap_or("").into();
    Ok((human, kv))
}
