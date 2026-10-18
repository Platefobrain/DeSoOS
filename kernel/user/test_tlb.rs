// TLB shootdown self-tests (only in builds with --cfg selftest).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::x86_64::{cpu, smp, tlb};
use crate::memory::{alloc_frame, free_frame, free_frame_count, kernel_data_flags, map_page, phys_to_virt};
use crate::sched::bkl;
use crate::serial_println;
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[TLB TEST] FAIL: {}", format_args!($($msg)*));
            STOP.store(true, Ordering::SeqCst);
            stop_reader();
            return;
        }
    };
}

static STOP: AtomicBool = AtomicBool::new(false);

/// Test page: the end of the on-demand region, mapped explicitly.
const VA: u64 = crate::memory::DEMAND_START + crate::memory::DEMAND_SIZE - 0x10_0000;
const VAL_A: u64 = 0xA1A1_A1A1_A1A1_A1A1;
const VAL_B: u64 = 0xB2B2_B2B2_B2B2_B2B2;

/// Reader: last seen value, CPU, number of reads, stop flag.
static SEEN: AtomicU64 = AtomicU64::new(0);
static READER_CPU: AtomicU64 = AtomicU64::new(u64::MAX);
static READER_CPUS: AtomicU64 = AtomicU64::new(0);
static READS: AtomicU64 = AtomicU64::new(0);
static READER_DONE: AtomicBool = AtomicBool::new(false);
static READER_STARTED: AtomicBool = AtomicBool::new(false);

/// After a FAIL: the reader must finish before the next test starts (stress
/// counts tasks; the test page then stays mapped – it is only a test).
fn stop_reader() {
    if READER_STARTED.swap(false, Ordering::SeqCst) {
        wait_for(2_000, || READER_DONE.load(Ordering::SeqCst));
        crate::sched::reap();
    }
}

static FLUSHERS_DONE: AtomicU64 = AtomicU64::new(0);
const FLUSHES_PER_TASK: u64 = 300;

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

/// Reads the test page in a loop, without the BKL (to run in parallel with the test).
fn reader(_: usize) {
    bkl::unlocked(|| {
        while !STOP.load(Ordering::Relaxed) {
            let v = unsafe { core::ptr::read_volatile(VA as *const u64) };
            SEEN.store(v, Ordering::Relaxed);
            let c = cpu::id() as u64;
            READER_CPU.store(c, Ordering::Relaxed);
            READER_CPUS.fetch_or(1 << c, Ordering::Relaxed);
            READS.fetch_add(1, Ordering::Relaxed);
            core::hint::spin_loop();
        }
    });
    READER_DONE.store(true, Ordering::SeqCst);
}

/// Many initiators at once (without the BKL): shootdowns compete for the request lock.
fn flusher(_: usize) {
    bkl::unlocked(|| {
        for _ in 0..FLUSHES_PER_TASK {
            tlb::flush_kernel(VA, 1);
        }
    });
    FLUSHERS_DONE.fetch_add(1, Ordering::SeqCst);
}

/// Waits until the reader sees `val` (fresh reads after the change).
fn reader_sees(val: u64, ms: u64) -> bool {
    let r0 = READS.load(Ordering::Relaxed);
    wait_for(ms, || READS.load(Ordering::Relaxed) > r0 + 1000 && SEEN.load(Ordering::Relaxed) == val)
}

pub fn self_test() {
    serial_println!("[TLB TEST] Starting TLB shootdown tests...");
    crate::selftest::begin();
    STOP.store(false, Ordering::SeqCst);
    let n = smp::online_count();

    // 1. A shootdown reaches all other CPUs (single page
    //    and full flush), handler without the BKL.
    let (r0, i0, f0, _, h0) = tlb::stats();
    tlb::flush_kernel(VA, 1);
    tlb::flush_kernel_all();
    let (r1, i1, f1, _, h1) = tlb::stats();
    let others = (n - 1) as u64;
    if n > 1 {
        check!(r1 - r0 == 2, "requests {} -> {}", r0, r1);
        check!(i1 - i0 == 2 * others, "IPIs sent {} (want {})", i1 - i0, 2 * others);
        check!(h1 - h0 == 2 * others, "acks {} (want {})", h1 - h0, 2 * others);
        check!(f1 - f0 == 1, "full flushes {}", f1 - f0);
    }
    serial_println!("[TLB TEST] 1/5 page + full shootdown acknowledged by {} other CPU(s) PASS", others);
    if n == 1 {
        serial_println!("[TLB TEST] one CPU - skipping cross-CPU tests");
        crate::selftest::pass();
        return;
    }

    // A reader on another CPU "warms up" the TLB with page VA -> frame A.
    let (Some(fa), Some(fb)) = (alloc_frame(), alloc_frame()) else {
        check!(false, "no frames");
        return;
    };
    unsafe {
        core::ptr::write_volatile(phys_to_virt(fa) as *mut u64, VAL_A);
        core::ptr::write_volatile(phys_to_virt(fb) as *mut u64, VAL_B);
    }
    check!(map_page(VA, fa, kernel_data_flags()), "map test page");
    READER_DONE.store(false, Ordering::SeqCst);
    READER_CPUS.store(0, Ordering::SeqCst);
    SEEN.store(0, Ordering::SeqCst);
    check!(crate::sched::spawn("tlb-reader", reader, 0).is_ok(), "spawn reader");
    READER_STARTED.store(true, Ordering::SeqCst);
    // The reader is running (reading nonstop), and so are we – so it is surely on
    // a different CPU than ours at this moment.
    let r0 = READS.load(Ordering::Relaxed);
    check!(
        wait_for(5_000, || SEEN.load(Ordering::Relaxed) == VAL_A && READS.load(Ordering::Relaxed) > r0 + 1000),
        "reader did not start (seen {:#x}, CPU {})",
        SEEN.load(Ordering::Relaxed),
        READER_CPU.load(Ordering::Relaxed) as i64
    );
    let me = cpu::id() as u64;
    let rcpu = READER_CPU.load(Ordering::Relaxed);

    // 2. Test control: WITHOUT a shootdown the reader should still see A
    //    (stale entry in its TLB).  QEMU TCG keeps such entries; a real
    //    CPU / KVM may evict the entry on its own – then it is informational only.
    let old = crate::memory::retarget_page_local(VA, fb);
    check!(old == Some(fa), "retarget A->B: {:?}", old);
    let r_before = READS.load(Ordering::Relaxed);
    crate::time::sleep_ms(50);
    let stale = SEEN.load(Ordering::Relaxed) == VAL_A;
    let moved = READER_CPU.load(Ordering::Relaxed) != rcpu;
    let reads = READS.load(Ordering::Relaxed) - r_before;
    serial_println!(
        "[TLB TEST] 2/5 control without shootdown: reader on CPU {} {} after {} reads{} PASS",
        rcpu,
        if stale { "still saw the OLD page (stale TLB entry - the test can detect it)" } else { "already saw the new page (CPU dropped the entry itself)" },
        reads,
        if moved { ", reader moved to another CPU" } else { "" }
    );
    // Now with a shootdown (the reader sees B either way after the flush).
    tlb::flush_kernel(VA, 1);
    check!(reader_sees(VAL_B, 2_000), "reader still sees {:#x} after shootdown A->B", SEEN.load(Ordering::Relaxed));

    // 3. B -> A with a shootdown: the reader MUST see A.
    let old = crate::memory::retarget_page_local(VA, fa);
    check!(old == Some(fb), "retarget B->A: {:?}", old);
    let (_, _, _, w0, _) = tlb::stats();
    tlb::flush_kernel(VA, 1);
    let (_, _, _, w1, _) = tlb::stats();
    check!(reader_sees(VAL_A, 2_000), "reader on CPU {} still sees {:#x} after shootdown B->A", READER_CPU.load(Ordering::Relaxed), SEEN.load(Ordering::Relaxed));
    serial_println!(
        "[TLB TEST] 3/5 remap on CPU {} seen by reader on CPU {} right after shootdown ({} us for acks) PASS",
        me,
        READER_CPU.load(Ordering::Relaxed),
        w1 - w0
    );

    // 4. Many initiators at once (without the BKL) with a running reader:
    //    every request acknowledged by all other CPUs.
    let k = n.clamp(2, 4) as u64;
    FLUSHERS_DONE.store(0, Ordering::SeqCst);
    let (r0, _, _, _, h0) = tlb::stats();
    for _ in 0..k {
        check!(crate::sched::spawn("tlb-flush", flusher, 0).is_ok(), "spawn flusher");
    }
    check!(wait_for(60_000, || FLUSHERS_DONE.load(Ordering::SeqCst) == k), "flushers did not finish ({} / {})", FLUSHERS_DONE.load(Ordering::SeqCst), k);
    let (r1, _, _, _, h1) = tlb::stats();
    check!(r1 - r0 >= k * FLUSHES_PER_TASK, "requests {} < {}", r1 - r0, k * FLUSHES_PER_TASK);
    check!(h1 - h0 == (r1 - r0) * others, "acks {} != requests {} x {} CPUs", h1 - h0, r1 - r0, others);
    serial_println!(
        "[TLB TEST] 4/5 {} concurrent initiators x {} shootdowns, {} acks ({} while waiting with IF=0) PASS",
        k,
        FLUSHES_PER_TASK,
        h1 - h0,
        tlb::polled()
    );

    // Cleanup: the reader stops, the page is unmapped (shootdown), frames come back.
    STOP.store(true, Ordering::SeqCst);
    check!(wait_for(2_000, || READER_DONE.load(Ordering::SeqCst)), "reader did not end");
    READER_STARTED.store(false, Ordering::SeqCst);
    crate::sched::reap();
    let free0 = free_frame_count();
    let f = crate::memory::unmap_page(VA);
    check!(f == Some(fa), "unmap test page: {:?}", f);
    check!(free_frame(fa) && free_frame(fb), "free test frames");
    check!(free_frame_count() >= free0 + 2, "frames not returned ({} -> {})", free0, free_frame_count());

    // 5. With multiple CPUs the heap gives pages back again (it used to only grow).
    let mapped0 = crate::memory::heap_mapped_bytes();
    let (rq0, _, _, _, _) = tlb::stats();
    // The heap may contain free holes left by blocks from per-CPU lists – allocate
    // 1 MiB blocks until the heap really grows (at most 32).
    let mut bigs: Vec<Vec<u8>> = Vec::new();
    while bigs.len() < 32 && crate::memory::heap_mapped_bytes() < mapped0 + 1024 * 1024 {
        let mut big: Vec<u8> = Vec::new();
        big.resize(1024 * 1024, 0x5a);
        bigs.push(big);
    }
    let mapped1 = crate::memory::heap_mapped_bytes();
    check!(bigs.iter().all(|b| b.iter().all(|&x| x == 0x5a)), "heap data");
    drop(bigs);
    let mapped2 = crate::memory::heap_mapped_bytes();
    let (rq1, _, _, _, _) = tlb::stats();
    check!(mapped1 >= mapped0 + 1024 * 1024, "heap did not grow ({} -> {})", mapped0, mapped1);
    check!(mapped2 < mapped1 - 512 * 1024, "heap did not shrink ({} -> {} -> {} bytes)", mapped0, mapped1, mapped2);
    check!(rq1 > rq0, "heap shrink without shootdown");
    serial_println!(
        "[TLB TEST] 5/5 heap grows to {} KiB and gives pages back ({} KiB) with {} shootdown(s) PASS",
        mapped1 / 1024,
        mapped2 / 1024,
        rq1 - rq0
    );

    crate::selftest::pass();
}
