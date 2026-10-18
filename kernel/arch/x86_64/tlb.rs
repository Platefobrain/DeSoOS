// TLB shootdown.
//
// Every CPU caches address translations in its TLB.  When one CPU removes or
// changes a mapping in the UPPER half (kernel: heap, task stacks, MMIO –
// shared by all PML4s), the others may still hold a stale entry and write to a
// frame the allocator has already handed to someone else.  Hence:
//
//     clear PTE  ->  shootdown (IPI + wait for acknowledgement)  ->  free_frame
//
// The lower half (process) does not need a shootdown as long as processes are
// single-threaded: a process runs on one CPU at a time, and a CPU that leaves it
// always loads a different CR3 (another task, a kernel task, idle), which without PCID
// and without global pages flushes all its entries.  Threads / shared memory
// – the address space's `active_cpus` mask, see ARCHITECTURE.md.
//
// Mechanism: one request at a time (the `LOCK` lock), range in atomics,
// `PENDING` = mask of CPUs that have not acknowledged yet.  Receiver: vector
// 0x43 – WITHOUT the BKL (the initiator usually holds the BKL and would wait for us forever)
// and without locks.  Pitfall: a CPU waiting with IF = 0 (for the BKL, a spinlock, or
// the shootdown lock itself) will not receive the IPI – every such loop calls `poll()`,
// which handles a request directed to this CPU.

use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};

use super::cpu::{self, MAX_CPUS};
use super::{clock, interrupts, lapic, smp};

/// "Invalidate TLB" IPI vector (0x40 timer, 0x41 resched, 0x42 halt).
pub const TLB_VECTOR: u8 = 0x43;

/// Above this many pages – a full flush (CR3 reload) instead of `invlpg`.
const MAX_INVLPG: u64 = 32;

/// After this many µs of waiting for acknowledgement – a report (who is not responding).
const REPORT_US: u64 = 1_000_000;

const PAGE: u64 = 4096;

/// Request owner (CPU number + 1; 0 = free).
static LOCK: AtomicU32 = AtomicU32::new(0);
/// Request range: start and number of pages (0 = full flush).
static REQ_START: AtomicU64 = AtomicU64::new(0);
static REQ_PAGES: AtomicU64 = AtomicU64::new(0);
/// CPUs that have not invalidated their entries yet.
static PENDING: AtomicU16 = AtomicU16::new(0);

// Statistics (`cpus`, tests).
static REQUESTS: AtomicU64 = AtomicU64::new(0);
static IPIS_SENT: AtomicU64 = AtomicU64::new(0);
static FULL_FLUSHES: AtomicU64 = AtomicU64::new(0);
static WAIT_US: AtomicU64 = AtomicU64::new(0);
static HANDLED: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static POLLED: AtomicU64 = AtomicU64::new(0);


#[inline]
fn invlpg(va: u64) {
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags)) };
}

/// CR3 reload – flushes all TLB entries (the kernel does not use global
/// pages, so the upper half too).
#[inline]
pub fn flush_all_local() {
    unsafe {
        core::arch::asm!("mov {0}, cr3", "mov cr3, {0}", out(reg) _, options(nostack, preserves_flags));
    }
}

fn flush_local(start: u64, pages: u64) {
    if pages == 0 || pages > MAX_INVLPG {
        flush_all_local();
    } else {
        for i in 0..pages {
            invlpg(start + i * PAGE);
        }
    }
}

/// Handles a request directed to this CPU (if any).  No locks and no
/// BKL – called from the 0x43 handler and from every wait loop with IF = 0.
#[inline]
pub fn poll() -> bool {
    // With IF = 0: some wait loops (SpinLock, console) run with IF = 1 –
    // an IPI in the middle would handle the request a second time, and returning here would clear
    // the bit of the NEXT request without invalidating its range.
    interrupts::without_interrupts(|| {
        let me = cpu::id();
        let bit = 1u16 << me;
        if PENDING.load(Ordering::Acquire) & bit == 0 {
            return false;
        }
        flush_local(REQ_START.load(Ordering::Relaxed), REQ_PAGES.load(Ordering::Relaxed));
        HANDLED[me].fetch_add(1, Ordering::Relaxed);
        PENDING.fetch_and(!bit, Ordering::AcqRel);
        true
    })
}

/// Handler of vector 0x43 (exceptions.rs, before the BKL).
pub fn on_ipi() {
    poll();
    lapic::eoi();
}

/// Invalidates `pages` pages from `start` (0 pages = everything) in the UPPER half
/// on all CPUs – on return no CPU has a stale entry, so the
/// frame may be returned to the allocator.  May be called with IF = 0 and with the BKL.
pub fn flush_kernel(start: u64, pages: u64) {
    // Also during AP startup (before SMP is "active"): an AP that is already
    // online might have cached entries.  An AP starts with a full flush
    // under the BKL (smp::ap_entry) and sets ONLINE while still holding the BKL.
    if smp::panicking() {
        flush_local(start, pages);
        return;
    }
    shootdown(start, pages);
}

/// Full flush of the upper half on all CPUs (e.g. a freed page table).
pub fn flush_kernel_all() {
    flush_kernel(0, 0);
}

fn shootdown(start: u64, pages: u64) {
    interrupts::without_interrupts(|| {
        // Targets computed with IF = 0: before (with IF = 1) the task could
        // migrate to another CPU and wait for an acknowledgement from itself
        // (found by TLB TEST 4: "CPU 0 waits ... from CPU mask 0b1").
        let cpu_now = cpu::id();
        let mut targets: u16 = 0;
        for c in 0..MAX_CPUS {
            if c != cpu_now && smp::online(c) {
                targets |= 1 << c;
            }
        }
        if targets == 0 {
            flush_local(start, pages);
            return;
        }
        let me = cpu_now as u32 + 1;
        // One initiator at a time.  While waiting we acknowledge other requests –
        // otherwise two initiators would wait for each other.
        // Wait by reading; try to acquire only when the lock is free.
        while LOCK.load(Ordering::Relaxed) != 0 || LOCK.compare_exchange_weak(0, me, Ordering::Acquire, Ordering::Relaxed).is_err() {
            poll_from_wait();
            core::hint::spin_loop();
        }
        REQUESTS.fetch_add(1, Ordering::Relaxed);
        if pages == 0 || pages > MAX_INVLPG {
            FULL_FLUSHES.fetch_add(1, Ordering::Relaxed);
        }
        REQ_START.store(start, Ordering::Relaxed);
        REQ_PAGES.store(pages, Ordering::Relaxed);
        PENDING.store(targets, Ordering::Release);
        for c in 0..MAX_CPUS {
            if targets & (1 << c) != 0 {
                lapic::send_ipi(smp::apic_id(c), TLB_VECTOR);
                IPIS_SENT.fetch_add(1, Ordering::Relaxed);
            }
        }
        flush_local(start, pages);
        let t0 = clock::stamp();
        let mut n: u32 = 0;
        let mut reported = false;
        while PENDING.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
            n = n.wrapping_add(1);
            if n % 4096 == 0 {
                smp::watchdog_poll();
                if smp::panicking() {
                    break;
                }
                if !reported && clock::elapsed_us(t0) > REPORT_US {
                    reported = true;
                    crate::serial_println!(
                        "[TLB] CPU {} waits {} ms for shootdown ack from CPU mask {:#b} ({:#x}, {} pages)",
                        cpu::id(),
                        clock::elapsed_us(t0) / 1000,
                        PENDING.load(Ordering::Relaxed),
                        start,
                        pages
                    );
                }
            }
        }
        WAIT_US.fetch_add(clock::elapsed_us(t0), Ordering::Relaxed);
        LOCK.store(0, Ordering::Release);
    });
}

/// (requests, IPIs sent, full flushes, µs spent waiting for acknowledgements,
///  handled by all CPUs) – `cpus`, tests.
pub fn stats() -> (u64, u64, u64, u64, u64) {
    let handled = HANDLED.iter().map(|h| h.load(Ordering::Relaxed)).sum();
    (
        REQUESTS.load(Ordering::Relaxed),
        IPIS_SENT.load(Ordering::Relaxed),
        FULL_FLUSHES.load(Ordering::Relaxed),
        WAIT_US.load(Ordering::Relaxed),
        handled,
    )
}

/// How many requests CPU `c` handled.
#[allow(dead_code)]
pub fn handled_by(c: usize) -> u64 {
    HANDLED[c % MAX_CPUS].load(Ordering::Relaxed)
}

/// From a wait loop with IF = 0 (BKL, spinlocks, console): `poll` + counter.
#[inline]
pub fn poll_from_wait() {
    if PENDING.load(Ordering::Relaxed) != 0 && poll() {
        POLLED.fetch_add(1, Ordering::Relaxed);
    }
}

/// How many requests were handled in wait loops (instead of in the IPI handler).
#[allow(dead_code)]
pub fn polled() -> u64 {
    POLLED.load(Ordering::Relaxed)
}
