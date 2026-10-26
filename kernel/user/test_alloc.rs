// Heap and frame allocator on their own locks – self-tests
// (selftest build only, --cfg selftest).  Everything here runs WITHOUT the Big Kernel
// Lock, on many CPUs at once.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::x86_64::{cpu, smp, tlb};
use crate::sched::bkl;
use crate::serial_println;
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[ALLOC TEST] FAIL: {}", format_args!($($msg)*));
            STOP.store(true, Ordering::SeqCst);
            crate::time::set_tick_hook(None);
            return;
        }
    };
}

static STOP: AtomicBool = AtomicBool::new(false);
static DONE: AtomicU64 = AtomicU64::new(0);
static BAD: AtomicU64 = AtomicU64::new(0);
static CPUS: AtomicU64 = AtomicU64::new(0);
static OPS: AtomicU64 = AtomicU64::new(0);
static IRQ_ALLOCS: AtomicU64 = AtomicU64::new(0);

const BIG_ROUNDS: usize = 12;
/// More than SHRINK_AT (512 KiB) – every free shrinks the heap
/// (TLB shootdown), every allocation grows it (map_page) – without the BKL.
const BIG_WORDS: usize = 640 * 1024 / 8;
const SMALL_ROUNDS: u64 = 1500;

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

fn pattern(i: usize, round: usize, j: usize) -> u64 {
    ((i as u64) << 56) ^ ((round as u64) << 40) ^ j as u64 ^ 0x5A5A_0000_0000
}

// ------------------------------------------------------------
// Block taken on one CPU, freed on another (per-CPU heap lists)
// ------------------------------------------------------------

/// Producer -> consumer channel: (address, size, pattern seed, allocating CPU).
static XCHAN: crate::sched::spin::SpinLock<Vec<(usize, usize, u32, u8)>> =
    crate::sched::spin::SpinLock::new("alloc-xchan", crate::sched::spin::level::TEST_INNER, Vec::new());
static X_PRODUCED: AtomicU64 = AtomicU64::new(0);
static X_FREED: AtomicU64 = AtomicU64::new(0);
/// Freed on a different CPU than allocated.
static X_CROSS: AtomicU64 = AtomicU64::new(0);
static X_PRODUCERS_LEFT: AtomicU64 = AtomicU64::new(0);
const X_ROUNDS: u32 = 6000;
/// Sizes: all classes, including non-powers of 2 (rounded up to a class).
// Also large classes (up to 32 KiB) and class boundaries.
const X_SIZES: [usize; 17] = [8, 16, 24, 40, 64, 100, 128, 300, 512, 777, 1500, 2048, 2049, 4096, 6000, 12000, 32768];

fn x_byte(seed: u32, k: usize) -> u8 {
    (seed as usize).wrapping_mul(31).wrapping_add(k * 7) as u8 ^ 0xA5
}

fn x_fill(p: *mut u8, size: usize, seed: u32) {
    for k in 0..size {
        unsafe { *p.add(k) = x_byte(seed, k) };
    }
}

fn x_ok(p: *const u8, size: usize, seed: u32) -> bool {
    (0..size).all(|k| unsafe { *p.add(k) } == x_byte(seed, k))
}

fn x_layout(size: usize) -> core::alloc::Layout {
    core::alloc::Layout::from_size_align(size, 8).unwrap()
}

/// Producer: takes blocks, fills them with a pattern, keeps every fourth until the end
/// (checked at the end – frees by others must not touch it), hands the rest
/// to consumers through the channel.
fn x_producer(i: usize) {
    bkl::unlocked(|| {
        let mut kept: Vec<(usize, usize, u32)> = Vec::with_capacity(X_ROUNDS as usize / 4 + 1);
        for r in 0..X_ROUNDS {
            if STOP.load(Ordering::Relaxed) {
                break;
            }
            let size = X_SIZES[(r as usize + i * 5) % X_SIZES.len()];
            let seed = (i as u32) << 24 | r;
            let p = unsafe { alloc::alloc::alloc(x_layout(size)) };
            if p.is_null() {
                BAD.store(3, Ordering::SeqCst);
                break;
            }
            let at = cpu::id() as u8;
            x_fill(p, size, seed);
            if r % 4 == 0 {
                kept.push((p as usize, size, seed));
                continue;
            }
            // Bounded channel – we do not flood the heap.
            loop {
                {
                    let mut q = XCHAN.lock();
                    if q.len() < 256 {
                        q.push((p as usize, size, seed, at));
                        break;
                    }
                }
                crate::sched::yield_now();
            }
            X_PRODUCED.fetch_add(1, Ordering::Relaxed);
        }
        for &(p, size, seed) in kept.iter() {
            if !x_ok(p as *const u8, size, seed) {
                let _ = BAD.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
            }
            unsafe { alloc::alloc::dealloc(p as *mut u8, x_layout(size)) };
        }
    });
    X_PRODUCERS_LEFT.fetch_sub(1, Ordering::SeqCst);
    DONE.fetch_add(1, Ordering::SeqCst);
}

/// Consumer: checks the pattern (nobody wrote over the block in transit) and frees it
/// – usually on a different CPU than the one that took the block.
fn x_consumer(_: usize) {
    bkl::unlocked(|| loop {
        let item = XCHAN.lock().pop();
        match item {
            Some((p, size, seed, at)) => {
                if !x_ok(p as *const u8, size, seed) {
                    let _ = BAD.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
                }
                // Write over the block right before freeing it (like real code).
                unsafe { core::ptr::write_bytes(p as *mut u8, 0xEE, size) };
                if cpu::id() as u8 != at {
                    X_CROSS.fetch_add(1, Ordering::Relaxed);
                }
                CPUS.fetch_or(1 << cpu::id(), Ordering::Relaxed);
                unsafe { alloc::alloc::dealloc(p as *mut u8, x_layout(size)) };
                X_FREED.fetch_add(1, Ordering::Relaxed);
            }
            None => {
                if X_PRODUCERS_LEFT.load(Ordering::SeqCst) == 0 && XCHAN.lock().is_empty() {
                    break;
                }
                crate::sched::yield_now();
            }
        }
    });
    DONE.fetch_add(1, Ordering::SeqCst);
}

/// Large blocks: the heap grows and shrinks in parallel on several CPUs.
/// Largest heap size during the large-block test (blocks may
/// fit into holes – then the heap does not grow and there is nothing to return).
static PEAK: AtomicU64 = AtomicU64::new(0);

fn big(i: usize) {
    bkl::unlocked(|| {
        for round in 0..BIG_ROUNDS {
            if STOP.load(Ordering::Relaxed) {
                break;
            }
            let mut v: Vec<u64> = Vec::new();
            if v.try_reserve_exact(BIG_WORDS).is_err() {
                BAD.store(3, Ordering::SeqCst);
                break;
            }
            for j in 0..BIG_WORDS {
                v.push(pattern(i, round, j));
            }
            CPUS.fetch_or(1 << cpu::id(), Ordering::Relaxed);
            PEAK.fetch_max(crate::memory::heap_mapped_bytes() as u64, Ordering::Relaxed);
            if v.iter().enumerate().any(|(j, &x)| x != pattern(i, round, j)) {
                let _ = BAD.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
            }
            OPS.fetch_add(1, Ordering::Relaxed);
        }
    });
    DONE.fetch_add(1, Ordering::SeqCst);
}

/// Small blocks and frames at once.
fn small(i: usize) {
    bkl::unlocked(|| {
        let mut kept: Vec<Vec<u32>> = Vec::new();
        for r in 0..SMALL_ROUNDS {
            if STOP.load(Ordering::Relaxed) {
                break;
            }
            let len = 1 + ((r as usize * 131 + i * 17) % 300);
            let v: Vec<u32> = (0..len as u32).map(|x| x ^ (i as u32) << 24).collect();
            kept.push(v);
            if kept.len() > 24 {
                let old = kept.remove((r as usize * 7) % kept.len());
                if old.iter().enumerate().any(|(j, &x)| x != (j as u32) ^ (i as u32) << 24) {
                    let _ = BAD.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
                }
            }
            if r % 4 == 0 {
                match crate::memory::alloc_frame() {
                    Some(f) => {
                        let p = crate::memory::phys_to_virt(f) as *mut u64;
                        unsafe {
                            p.write_volatile(f ^ i as u64);
                            p.add(511).write_volatile(!f);
                            if p.read_volatile() != f ^ i as u64 || p.add(511).read_volatile() != !f {
                                let _ = BAD.compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst);
                            }
                        }
                        if !crate::memory::free_frame(f) {
                            let _ = BAD.compare_exchange(0, 4, Ordering::SeqCst, Ordering::SeqCst);
                        }
                    }
                    None => BAD.store(3, Ordering::SeqCst),
                }
            }
            CPUS.fetch_or(1 << cpu::id(), Ordering::Relaxed);
            OPS.fetch_add(1, Ordering::Relaxed);
        }
    });
    DONE.fetch_add(1, Ordering::SeqCst);
}

/// Allocation from the timer interrupt during test 2.
fn irq_hook(_: u64) {
    let v: Vec<u8> = alloc::vec![0xA5; 96];
    if v.iter().any(|&b| b != 0xA5) {
        let _ = BAD.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
    }
    IRQ_ALLOCS.fetch_add(1, Ordering::Relaxed);
}

fn bad_text(code: u64) -> &'static str {
    match code {
        1 => "heap block overwritten",
        2 => "frame contents overwritten",
        3 => "out of memory",
        4 => "free_frame refused a frame it had just given out",
        5 => "the same frame given to two owners (tag overwritten)",
        6 => "double free of a frame accepted",
        _ => "?",
    }
}

fn noop(_: usize) {}

// Per-CPU frame caches – every frame has a single owner, frames are freed
// on a different CPU than allocated, double-free is rejected for a cached frame too.
const F_PER: usize = 400;
static F_POOL: crate::sched::spin::SpinLock<Vec<u64>> =
    crate::sched::spin::SpinLock::new("alloc-fpool", crate::sched::spin::level::TEST_INNER, Vec::new());
static F_READY: AtomicU64 = AtomicU64::new(0);
static F_PUSHED: AtomicU64 = AtomicU64::new(0);
static F_TASKS: AtomicU64 = AtomicU64::new(0);

fn f_tag(i: usize, j: usize) -> u64 {
    ((i as u64) << 32 | j as u64) ^ 0x5a5a_0000_a5a5_0000
}

fn f_worker(i: usize) {
    CPUS.fetch_or(1 << cpu::id(), Ordering::SeqCst);
    let k = F_TASKS.load(Ordering::SeqCst);
    let mut mine: Vec<u64> = Vec::with_capacity(F_PER);
    for j in 0..F_PER {
        match crate::memory::alloc_frame() {
            Some(f) => {
                unsafe { *(crate::memory::phys_to_virt(f) as *mut u64) = f_tag(i, j) };
                mine.push(f);
            }
            None => {
                BAD.store(3, Ordering::SeqCst);
                break;
            }
        }
    }
    // Everyone has taken theirs – only now check the markers (a frame
    // handed to two owners would carry the second one's marker).
    F_READY.fetch_add(1, Ordering::SeqCst);
    while F_READY.load(Ordering::SeqCst) < k && !STOP.load(Ordering::SeqCst) {
        crate::sched::yield_now();
    }
    for (j, &f) in mine.iter().enumerate() {
        if unsafe { *(crate::memory::phys_to_virt(f) as *const u64) } != f_tag(i, j) {
            let _ = BAD.compare_exchange(0, 5, Ordering::SeqCst, Ordering::SeqCst);
        }
    }
    // Half goes to a shared pool; from the pool we free others' frames (on a different CPU).
    let half = mine.split_off(F_PER / 2);
    F_POOL.lock().extend_from_slice(&half);
    F_PUSHED.fetch_add(1, Ordering::SeqCst);
    while F_PUSHED.load(Ordering::SeqCst) < k && !STOP.load(Ordering::SeqCst) {
        crate::sched::yield_now();
    }
    let mut first = true;
    loop {
        let f = F_POOL.lock().pop();
        let Some(f) = f else { break };
        if !crate::memory::free_frame(f) {
            let _ = BAD.compare_exchange(0, 4, Ordering::SeqCst, Ordering::SeqCst);
        }
        if first {
            first = false;
            // The frame now sits in this CPU's cache – a second free must fail.
            if crate::memory::free_frame(f) {
                let _ = BAD.compare_exchange(0, 6, Ordering::SeqCst, Ordering::SeqCst);
            }
        }
    }
    for f in mine {
        if !crate::memory::free_frame(f) {
            let _ = BAD.compare_exchange(0, 4, Ordering::SeqCst, Ordering::SeqCst);
        }
    }
    DONE.fetch_add(1, Ordering::SeqCst);
}

pub fn self_test() {
    serial_println!("[ALLOC TEST] Starting heap / frame allocator tests without BKL...");
    crate::selftest::begin();
    STOP.store(false, Ordering::SeqCst);
    let n = smp::online_count();
    let k = n.clamp(2, 4);
    crate::sched::reap();
    let (_, _, dl0) = crate::sched::spin::stats();

    // 1. Large blocks: the heap grows (map_page) and shrinks (unmap + TLB shootdown)
    //    on several CPUs at once, without the BKL.
    let mapped0 = crate::memory::heap_mapped_bytes();
    let used0 = crate::memory::heap_used_bytes();
    let (rq0, _, _, _, _) = tlb::stats();
    DONE.store(0, Ordering::SeqCst);
    BAD.store(0, Ordering::SeqCst);
    CPUS.store(0, Ordering::SeqCst);
    OPS.store(0, Ordering::SeqCst);
    PEAK.store(0, Ordering::SeqCst);
    for i in 0..k {
        check!(crate::sched::spawn("alloc-big", big, i).is_ok(), "spawn big");
    }
    check!(wait_for(120_000, || DONE.load(Ordering::SeqCst) == k as u64), "big allocators did not finish ({} / {})", DONE.load(Ordering::SeqCst), k);
    let bad = BAD.load(Ordering::SeqCst);
    check!(bad == 0, "big blocks: {}", bad_text(bad));
    crate::sched::reap();
    let (rq1, _, _, _, _) = tlb::stats();
    let mapped1 = crate::memory::heap_mapped_bytes();
    let cpus = CPUS.load(Ordering::SeqCst).count_ones();
    check!(n == 1 || cpus >= 2, "big allocators ran on {} CPU", cpus);
    check!(mapped1 <= mapped0 + 640 * 1024, "heap did not shrink back ({} -> {} KiB)", mapped0 / 1024, mapped1 / 1024);
    check!(
        rq1 > rq0 || n == 1 || PEAK.load(Ordering::SeqCst) <= mapped0 as u64,
        "no TLB shootdown from heap shrinking"
    );
    serial_println!(
        "[ALLOC TEST] 1/5 {} tasks x {} x 640 KiB on {} CPUs without BKL: heap grows and shrinks ({} shootdowns), data intact PASS",
        k,
        BIG_ROUNDS,
        cpus,
        rq1 - rq0
    );

    // 2. Small blocks + frames on several CPUs, the timer interrupt allocates too,
    //    while the test task (with the BKL) creates and ends tasks
    //    (stacks: map/unmap in another kernel region).
    let frames0 = crate::memory::free_frame_count();
    DONE.store(0, Ordering::SeqCst);
    CPUS.store(0, Ordering::SeqCst);
    OPS.store(0, Ordering::SeqCst);
    IRQ_ALLOCS.store(0, Ordering::SeqCst);
    crate::time::set_tick_hook(Some(irq_hook));
    for i in 0..k {
        check!(crate::sched::spawn("alloc-small", small, i).is_ok(), "spawn small");
    }
    let mut spawned = 0;
    while DONE.load(Ordering::SeqCst) < k as u64 && spawned < 2000 {
        if crate::sched::spawn("alloc-noop", noop, 0).is_ok() {
            spawned += 1;
        }
        crate::time::sleep_ms(1);
    }
    let finished = wait_for(120_000, || DONE.load(Ordering::SeqCst) == k as u64);
    crate::time::set_tick_hook(None);
    check!(finished, "small allocators did not finish ({} / {})", DONE.load(Ordering::SeqCst), k);
    let bad = BAD.load(Ordering::SeqCst);
    check!(bad == 0, "small blocks / frames: {}", bad_text(bad));
    let irq = IRQ_ALLOCS.load(Ordering::SeqCst);
    check!(irq > 0, "no allocation from the timer interrupt");
    wait_for(2_000, || {
        crate::sched::reap();
        crate::sched::tasks().iter().all(|t| t.name != "alloc-noop" && t.name != "alloc-small")
    });
    let used1 = crate::memory::heap_used_bytes();
    check!(used1 <= used0 + 16 * 1024, "heap used {} -> {} bytes (leak?)", used0, used1);
    let frames1 = crate::memory::free_frame_count();
    let heap_pages = (crate::memory::heap_mapped_bytes() as u64).saturating_sub(mapped0 as u64) / 4096;
    // Headroom for page tables of kernel regions (stack slots of 2000 tasks, heap),
    // which linger for a while – a real leak is frames on every round.
    check!(frames1 + heap_pages + 64 >= frames0, "frames {} -> {} (+{} heap pages)", frames0, frames1, heap_pages);
    serial_println!(
        "[ALLOC TEST] 2/5 {} tasks x {} small blocks + frames, {} allocs in the timer IRQ, {} task stacks meanwhile, nothing lost PASS",
        k,
        SMALL_ROUNDS,
        irq,
        spawned
    );

    // 3. Blocks taken on one CPU, freed on another (per-CPU heap
    //    lists) – patterns intact, nothing is lost.
    let used_x0 = crate::memory::heap_used_bytes();
    DONE.store(0, Ordering::SeqCst);
    CPUS.store(0, Ordering::SeqCst);
    X_PRODUCED.store(0, Ordering::SeqCst);
    X_FREED.store(0, Ordering::SeqCst);
    X_CROSS.store(0, Ordering::SeqCst);
    X_PRODUCERS_LEFT.store(k as u64, Ordering::SeqCst);
    for i in 0..k {
        check!(crate::sched::spawn("alloc-xprod", x_producer, i).is_ok(), "spawn producer");
        check!(crate::sched::spawn("alloc-xcons", x_consumer, i).is_ok(), "spawn consumer");
    }
    check!(wait_for(120_000, || DONE.load(Ordering::SeqCst) == 2 * k as u64), "cross-CPU tasks did not finish ({} / {})", DONE.load(Ordering::SeqCst), 2 * k);
    let bad = BAD.load(Ordering::SeqCst);
    check!(bad == 0, "cross-CPU blocks: {}", bad_text(bad));
    let (produced, freed, cross) =
        (X_PRODUCED.load(Ordering::SeqCst), X_FREED.load(Ordering::SeqCst), X_CROSS.load(Ordering::SeqCst));
    check!(produced == freed, "blocks lost in the channel: {} sent, {} freed", produced, freed);
    check!(n == 1 || cross > 0, "no block freed on another CPU ({} blocks)", freed);
    *XCHAN.lock() = Vec::new();
    crate::sched::reap();
    let used_x1 = crate::memory::heap_used_bytes();
    check!(used_x1 <= used_x0 + 16 * 1024, "heap used {} -> {} bytes after cross-CPU frees (leak?)", used_x0, used_x1);
    serial_println!(
        "[ALLOC TEST] 3/5 {} producer(s) + {} consumer(s): {} blocks, {} freed on another CPU, patterns intact PASS",
        k,
        k,
        freed,
        cross
    );

    // 4. Per-CPU frame caches.  Rejections without the lock: address 0, unaligned,
    // outside RAM, reserved (bitmap), double-free (also from the CPU cache);
    // then k tasks with F_PER frames each, half freed on another CPU.
    crate::sched::reap();
    // Reference point taken after the tasks from step 3 are reaped (stacks come back
    // at reap) – measuring right away ended with MORE free frames than at the start.
    let fr0 = {
        let (mut last, mut stable) = (u64::MAX, 0);
        for _ in 0..400 {
            crate::sched::reap();
            let now = crate::memory::free_frame_count() as u64;
            if now == last {
                stable += 1;
                if stable >= 10 {
                    break;
                }
            } else {
                (last, stable) = (now, 0);
            }
            crate::time::sleep_ms(5);
        }
        crate::memory::free_frame_count()
    };
    let (bitmap_phys, _) = crate::memory::bitmap_info();
    check!(
        !crate::memory::free_frame(0) && !crate::memory::free_frame(0x1234) && !crate::memory::free_frame(1 << 50) && !crate::memory::free_frame(bitmap_phys),
        "free_frame accepted 0 / unaligned / non-RAM / reserved frame"
    );
    let f = crate::memory::alloc_frame();
    check!(f.is_some(), "alloc_frame");
    let f = f.unwrap_or(0);
    check!(crate::memory::free_frame(f) && !crate::memory::free_frame(f), "double free of a frame in the CPU cache accepted");
    DONE.store(0, Ordering::SeqCst);
    BAD.store(0, Ordering::SeqCst);
    CPUS.store(0, Ordering::SeqCst);
    F_READY.store(0, Ordering::SeqCst);
    F_PUSHED.store(0, Ordering::SeqCst);
    F_TASKS.store(k as u64, Ordering::SeqCst);
    serial_println!("[ALLOC TEST]   4/5 starting {} frame workers ({} free frames)", k, fr0);
    for i in 0..k {
        check!(crate::sched::spawn("alloc-frames", f_worker, i).is_ok(), "spawn frame worker");
    }
    if !wait_for(60_000, || DONE.load(Ordering::SeqCst) == k as u64) {
        // Where they are stuck: the phase counters, the pool, each worker's state.
        serial_println!(
            "[ALLOC TEST] frame workers stuck: ready {} pushed {} done {} of {}, pool {} frames, free frames {}",
            F_READY.load(Ordering::SeqCst),
            F_PUSHED.load(Ordering::SeqCst),
            DONE.load(Ordering::SeqCst),
            k,
            F_POOL.lock().len(),
            crate::memory::free_frame_count()
        );
        for t in crate::sched::tasks().iter().filter(|t| t.name == "alloc-frames") {
            serial_println!("[ALLOC TEST]   task {} {:?} cpu {:?} (last {}), {} switches, {} ticks", t.id, t.state, t.cpu, t.last_cpu, t.switches, t.cpu_ticks);
        }
    }
    check!(DONE.load(Ordering::SeqCst) == k as u64, "frame workers did not finish ({} / {})", DONE.load(Ordering::SeqCst), k);
    let bad = BAD.load(Ordering::SeqCst);
    check!(bad == 0, "frame caches: {}", bad_text(bad));
    *F_POOL.lock() = Vec::new();
    crate::sched::reap();
    let fcpus = CPUS.load(Ordering::SeqCst).count_ones();
    let fr1 = crate::memory::free_frame_count();
    check!(wait_for(2_000, || { crate::sched::reap(); crate::memory::free_frame_count() >= fr0 }), "frames {} -> {} after the per-CPU cache test", fr0, fr1);
    serial_println!(
        "[ALLOC TEST] 4/5 frame caches: {} tasks x {} frames on {} CPU(s), each frame one owner, half freed on another CPU, double free / reserved / bad addresses refused, count back to {} PASS",
        k,
        F_PER,
        fcpus,
        fr0
    );

    // 5. Allocator locks: nobody reported a deadlock during the test.
    let (acq, cont, dl) = crate::sched::spin::stats();
    check!(dl == dl0, "{} deadlock report(s) during the test", dl - dl0);
    serial_println!("[ALLOC TEST] 5/5 spinlocks so far: {} taken, {} contended, 0 deadlock reports PASS", acq, cont);

    crate::selftest::pass();
}
