// Big Kernel Lock (BKL) – one lock for the whole kernel.
//
// Rule (like Linux 2.0–2.2): at any moment ONE processor executes kernel
// code.  The others meanwhile run process code in ring 3 (that happens
// truly in parallel), sleep in `hlt` or wait for the lock.
// Thanks to this, the whole kernel written for one core (sections
// `without_interrupts`, static structures) stays correct on many
// cores.  Fine-grained locks (scheduler, heap, VFS separately) come later.
//
// Who holds the BKL:
//   * every CPU executing kernel code (kernel tasks, syscalls, interrupts),
//   * a CPU in ring 3 – NO (released on SYSRET / IRETQ to the process),
//   * a CPU in `hlt` – NO (interrupts::enable_and_hlt releases it while sleeping).
// Kernel entries: syscall_dispatch, exception_dispatch (interrupts
// and exceptions), AP startup.  The lock belongs to the processor, not the task –
// a task switch does not change it.
//
// Ticket lock: order of entry = order of waiting.
// Always taken with interrupts disabled (otherwise an interrupt on the
// same CPU would wait for a ticket behind itself).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::arch::x86_64::{cpu, interrupts};

static NEXT: AtomicU32 = AtomicU32::new(0);
static SERVING: AtomicU32 = AtomicU32::new(0);
/// CPU number + 1 (0 = nobody).
static OWNER: AtomicU32 = AtomicU32::new(0);

// Ticket this CPU is currently waiting for (+1; 0 = not waiting) – for the
// watchdog report and detecting nested waiting (a second ticket of the same
// CPU = deadlock with itself).
static WAITING: [AtomicU32; crate::arch::x86_64::cpu::MAX_CPUS] =
    [const { AtomicU32::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];

/// Where and since when the current owner holds the BKL (watchdog report).
static OWNER_SITE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static OWNER_SINCE: AtomicU64 = AtomicU64::new(0);

/// (file, line, ms since acquisition) – where the current owner took the BKL.
/// For named sites (`Site::Tag`) line = 0.
pub fn owner_site() -> Option<(&'static str, u32, u64)> {
    let a = OWNER_SITE.load(Ordering::Relaxed);
    if a == 0 || OWNER.load(Ordering::Relaxed) == 0 {
        return None;
    }
    let (f, l) = site_name(a);
    Some((f, l, crate::time::ticks().saturating_sub(OWNER_SINCE.load(Ordering::Relaxed))))
}

// ------------------------------------------------------------
// Who takes the BKL – statistics per acquisition site
// ------------------------------------------------------------
//
// Site key: the address of a `Location` (#[track_caller] – file:line) or the address
// of a static name `&'static str` with the lowest bit set (both are
// 8-aligned, so bit 0 tells them apart).  Lock-free table: an entry
// is claimed by compare_exchange of the key, the counters are atomics.  Hold
// time is measured by the TSC of the same CPU (the BKL is released by the CPU that took it –
// also on a task switch), so mismatched TSCs across cores do not matter.

const SITES: usize = 48;

/// Each entry in its own cache line (counters are updated from many CPUs).
#[repr(align(64))]
pub(crate) struct SiteStat {
    key: core::sync::atomic::AtomicUsize,
    pub(crate) taken: AtomicU64,
    pub(crate) waited: AtomicU64,
    pub(crate) wait_us: AtomicU64,
    pub(crate) hold_tsc: AtomicU64,
}

/// Table of lock acquisition sites (BKL, scheduler lock).
pub(crate) struct SiteTable {
    tab: [SiteStat; SITES],
    overflow: AtomicU64,
}

impl SiteTable {
    pub(crate) const fn new() -> Self {
        SiteTable {
            tab: [const {
                SiteStat {
                    key: core::sync::atomic::AtomicUsize::new(0),
                    taken: AtomicU64::new(0),
                    waited: AtomicU64::new(0),
                    wait_us: AtomicU64::new(0),
                    hold_tsc: AtomicU64::new(0),
                }
            }; SITES],
            overflow: AtomicU64::new(0),
        }
    }

    pub(crate) fn entry(&self, i: usize) -> &SiteStat {
        &self.tab[i]
    }

    pub(crate) fn slot_for(&self, key: usize) -> Option<usize> {
        let start = (key >> 3).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 58; // 0..63
        for k in 0..SITES {
            let i = (start as usize + k) % SITES;
            let cur = self.tab[i].key.load(Ordering::Acquire);
            if cur == key {
                return Some(i);
            }
            if cur == 0 {
                match self.tab[i].key.compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => return Some(i),
                    Err(other) if other == key => return Some(i),
                    Err(_) => continue,
                }
            }
        }
        self.overflow.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// All sites, sorted descending by waiting + holding time.
    pub(crate) fn stats(&self) -> alloc::vec::Vec<SiteInfo> {
        // Without LAPIC calibration (one CPU) the hold time is unknown (0).
        let tsc_ms = crate::arch::x86_64::lapic::tsc_per_ms();
        let mut v: alloc::vec::Vec<SiteInfo> = self
            .tab
            .iter()
            .filter_map(|e| {
                let key = e.key.load(Ordering::Acquire);
                if key == 0 {
                    return None;
                }
                let (file, line) = site_name(key);
                Some(SiteInfo {
                    file,
                    line,
                    taken: e.taken.load(Ordering::Relaxed),
                    waited: e.waited.load(Ordering::Relaxed),
                    wait_us: e.wait_us.load(Ordering::Relaxed),
                    held_us: if tsc_ms == 0 { 0 } else { e.hold_tsc.load(Ordering::Relaxed).saturating_mul(1000) / tsc_ms },
                })
            })
            .collect();
        v.sort_by(|a, b| (b.wait_us + b.held_us).cmp(&(a.wait_us + a.held_us)));
        v
    }

    pub(crate) fn overflow(&self) -> u64 {
        self.overflow.load(Ordering::Relaxed)
    }
}

static SITE_TAB: SiteTable = SiteTable::new();
/// Entry (+1) and TSC of the current owner's acquisition (written only by the owner).
static OWNER_SLOT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static OWNER_TSC: AtomicU64 = AtomicU64::new(0);

#[inline]
pub(crate) fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    ((hi as u64) << 32) | lo as u64
}

#[allow(dead_code)]
pub(crate) fn location_key(l: &'static core::panic::Location<'static>) -> usize {
    l as *const core::panic::Location as usize
}

pub(crate) fn tag_key(t: &'static &'static str) -> usize {
    (t as *const &'static str as usize) | 1
}

/// (file or name, line – 0 for a name).
fn site_name(key: usize) -> (&'static str, u32) {
    if key & 1 == 1 {
        let t: &'static &'static str = unsafe { &*((key & !1) as *const &'static str) };
        (t, 0)
    } else {
        let l: &'static core::panic::Location<'static> = unsafe { &*(key as *const core::panic::Location<'static>) };
        (l.file(), l.line())
    }
}

/// Statistics of one BKL acquisition site (`cpus`, autostress).
pub struct SiteInfo {
    pub file: &'static str,
    pub line: u32,
    pub taken: u64,
    pub waited: u64,
    pub wait_us: u64,
    pub held_us: u64,
}

/// All sites, sorted descending by waiting + holding time.
pub fn site_stats() -> alloc::vec::Vec<SiteInfo> {
    SITE_TAB.stats()
}

/// Sites that did not fit in the statistics table.
pub fn site_overflow() -> u64 {
    SITE_TAB.overflow()
}

/// Named acquisition sites (instead of file:line) – readable on a screen photo.
pub mod tag {
    pub static AFTER_WAIT: &str = "after switch: wait_event (WaitQueue)";
    pub static AFTER_SLEEP: &str = "after switch: sleep";
    pub static AFTER_YIELD: &str = "after switch: yield";
    pub static AFTER_PREEMPT: &str = "after switch: preempt (irq)";
    pub static NEW_TASK: &str = "new task start";
    pub static SYSCALL: &str = "syscall under BKL";
    pub static HLT_WAKE: &str = "wake from hlt";
    pub static UNLOCKED_END: &str = "end of bkl::unlocked";
    pub static YIELD: &str = "yield_if_contended (re-take)";
    pub static AP_START: &str = "AP start";
    pub static IDLE_REAP: &str = "idle: reap dead tasks";
    pub static BOOT: &str = "boot (kernel_main)";
    pub static KBD_POLL: &str = "keyboard poll in timer tick (try)";
    pub static IRQ_PIT_USER: &str = "irq PIT tick (from ring 3)";
    pub static IRQ_PIT_KERNEL: &str = "irq PIT tick (from kernel)";
    pub static IRQ_TIMER_USER: &str = "irq LAPIC timer (from ring 3)";
    pub static IRQ_TIMER_KERNEL: &str = "irq LAPIC timer (from kernel)";
    pub static IRQ_RESCHED_USER: &str = "irq resched IPI (from ring 3)";
    pub static IRQ_RESCHED_KERNEL: &str = "irq resched IPI (from kernel)";
    pub static IRQ_OTHER_USER: &str = "irq device/MSI (from ring 3)";
    pub static IRQ_OTHER_KERNEL: &str = "irq device/MSI (from kernel)";
    pub static EXC_USER: &str = "exception (from ring 3)";
    pub static EXC_KERNEL: &str = "exception (from kernel)";
}

/// Ticket CPU `c` is waiting for (None – not waiting).
pub fn waiting_ticket(c: usize) -> Option<u32> {
    match WAITING[c % crate::arch::x86_64::cpu::MAX_CPUS].load(Ordering::Relaxed) {
        0 => None,
        t => Some(t - 1),
    }
}

// Statistics – how many times the BKL was taken, how many times we had to wait and how much
// time was spent waiting (a measure of what removing the BKL will gain).
static ACQUIRES: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static CONTENDED: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
/// Total time spent waiting for the BKL in microseconds (clock.rs clock).
static WAIT_US: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();

/// (acquisitions, acquisitions with waiting, microseconds waited) – `cpus`, tests.
pub fn stats() -> (u64, u64, u64) {
    (ACQUIRES.get(), CONTENDED.get(), WAIT_US.get())
}

/// Whether the current CPU holds the BKL.
///
/// The CPU number and the owner are read with IF = 0.  With IF = 1 the task
/// could be preempted and migrated to another CPU between the two reads (the BKL
/// follows the task: released on switch, taken in after_switch) –
/// the result would be wrong (a spurious panic "wait_event returned without the
/// BKL"; `enable_and_hlt` could go to sleep holding the BKL).
#[inline]
pub fn held() -> bool {
    crate::arch::x86_64::interrupts::without_interrupts(|| OWNER.load(Ordering::Acquire) == cpu::id() as u32 + 1)
}

/// Takes the BKL (waits for its turn).  Interrupts must be disabled.
#[track_caller]
pub fn acquire() {
    acquire_at(location_key(core::panic::Location::caller()));
}

/// Like `acquire`, but the statistics site has a name (`bkl::tag::*`).
#[allow(dead_code)]
pub fn acquire_tagged(t: &'static &'static str) {
    acquire_at(tag_key(t));
}

/// Like `acquire_if_needed`, with a named site; `true` = taken now.
pub fn acquire_if_needed_tagged(t: &'static &'static str) -> bool {
    if held() {
        return false;
    }
    acquire_at(tag_key(t));
    true
}

fn acquire_at(site: usize) {
    debug_assert!(!interrupts::are_enabled(), "BKL taken with interrupts enabled");
    let me = cpu::id();
    if let Some(t) = waiting_ticket(me) {
        panic!("BKL: CPU {} waits for ticket {} and asks again (nested acquire)", me, t);
    }
    let ticket = NEXT.fetch_add(1, Ordering::AcqRel);
    WAITING[me].store(ticket.wrapping_add(1), Ordering::Relaxed);
    ACQUIRES.add(1);
    let mut waited_us = None;
    if SERVING.load(Ordering::Acquire) != ticket {
        // Statistics use the TSC (same CPU); the report uses HPET every 4096 spins.
        let (tsc0, cpu0) = crate::arch::x86_64::clock::tsc_cpu();
        let mut start = 0u64;
        let mut n: u32 = 0;
        let mut reported = false;
        while SERVING.load(Ordering::Acquire) != ticket {
            core::hint::spin_loop();
            n = n.wrapping_add(1);
            // We wait with IF = 0 – TLB shootdown requests are handled here
            // (the initiator may hold the BKL and wait for us).
            if n % 64 == 0 {
                crate::arch::x86_64::tlb::poll_from_wait();
            }
            if n % 4096 == 0 {
                crate::arch::x86_64::smp::watchdog_poll();
                // Long wait for the BKL (starvation / slow handoff).
                if start == 0 {
                    start = crate::arch::x86_64::clock::stamp().max(1);
                }
                if !reported {
                    let waited = crate::arch::x86_64::clock::elapsed_us(start) / 1000;
                    if waited >= crate::arch::x86_64::smp::BKL_WAIT_REPORT_MS {
                        reported = true;
                        crate::arch::x86_64::smp::bkl_wait_report(ticket, waited);
                    }
                }
            }
        }
        let us = crate::arch::x86_64::clock::tsc_wait_us(tsc0, cpu0);
        CONTENDED.add(1);
        WAIT_US.add(us);
        waited_us = Some(us);
    }
    WAITING[me].store(0, Ordering::Relaxed);
    // Site statistics (already as the owner – nobody else writes
    // OWNER_SLOT / OWNER_TSC).
    let slot = SITE_TAB.slot_for(site);
    if let Some(i) = slot {
        let e = SITE_TAB.entry(i);
        e.taken.fetch_add(1, Ordering::Relaxed);
        if let Some(us) = waited_us {
            e.waited.fetch_add(1, Ordering::Relaxed);
            e.wait_us.fetch_add(us, Ordering::Relaxed);
        }
    }
    OWNER_SLOT.store(slot.map_or(0, |i| i + 1), Ordering::Relaxed);
    OWNER_TSC.store(rdtsc(), Ordering::Relaxed);
    OWNER_SITE.store(site, Ordering::Relaxed);
    OWNER_SINCE.store(crate::time::ticks(), Ordering::Relaxed);
    OWNER.store(cpu::id() as u32 + 1, Ordering::Release);
}

/// Takes the BKL only if it is free and nobody is waiting (no
/// queueing); `false` = not taken.  Interrupts must be disabled.  For
/// work that can wait until the next opportunity (polling the keyboard
/// in the timer tick without the BKL).
pub fn try_acquire_tagged(t: &'static &'static str) -> bool {
    debug_assert!(!interrupts::are_enabled(), "BKL taken with interrupts enabled");
    if held() {
        return false;
    }
    let serving = SERVING.load(Ordering::Acquire);
    if NEXT.compare_exchange(serving, serving.wrapping_add(1), Ordering::AcqRel, Ordering::Relaxed).is_err() {
        return false;
    }
    ACQUIRES.add(1);
    let site = tag_key(t);
    let slot = SITE_TAB.slot_for(site);
    if let Some(i) = slot {
        SITE_TAB.entry(i).taken.fetch_add(1, Ordering::Relaxed);
    }
    OWNER_SLOT.store(slot.map_or(0, |i| i + 1), Ordering::Relaxed);
    OWNER_TSC.store(rdtsc(), Ordering::Relaxed);
    OWNER_SITE.store(site, Ordering::Relaxed);
    OWNER_SINCE.store(crate::time::ticks(), Ordering::Relaxed);
    OWNER.store(cpu::id() as u32 + 1, Ordering::Release);
    true
}

/// Takes the BKL if this CPU does not have it yet; `true` = taken now.
#[inline]
#[track_caller]
pub fn acquire_if_needed() -> bool {
    if held() {
        return false;
    }
    acquire();
    true
}

/// Releases the BKL (owner only).
pub fn release() {
    debug_assert!(held(), "BKL released by a CPU that does not hold it");
    // Hold time (TSC of the same CPU).
    let slot = OWNER_SLOT.swap(0, Ordering::Relaxed);
    if slot != 0 {
        let d = rdtsc().wrapping_sub(OWNER_TSC.load(Ordering::Relaxed));
        if d < (1u64 << 48) {
            SITE_TAB.entry(slot - 1).hold_tsc.fetch_add(d, Ordering::Relaxed);
        }
    }
    OWNER.store(0, Ordering::Release);
    SERVING.fetch_add(1, Ordering::AcqRel);
}

/// Whether another CPU is waiting for the BKL.
#[inline]
pub fn contended() -> bool {
    NEXT.load(Ordering::Relaxed).wrapping_sub(SERVING.load(Ordering::Relaxed)) > 1
}

/// Yield point: another CPU is waiting – release and re-take (the ticket queue
/// lets it in first).  Called from the timer interrupt when the interrupted code had
/// interrupts enabled – that is like preemption, so it is safe.
pub fn yield_if_contended() {
    // While holding a spinlock we must not wait for the BKL (another CPU with the BKL
    // could be waiting for our spinlock – deadlock).
    if held() && contended() && super::spin::held_count() == 0 && crate::arch::x86_64::cpu::preempt_count() == 0 {
        release();
        acquire_tagged(&tag::YIELD);
    }
}

/// Runs `f` WITHOUT the Big Kernel Lock (other CPUs may execute kernel
/// code meanwhile).  `f` may touch only data protected by
/// its own locks (spinlocks, atomics) – not the heap, VFS or scheduler
/// while those rely only on the BKL.  An interrupt meanwhile takes the BKL for the duration
/// of the handler and releases it on return (exceptions.rs).
#[allow(dead_code)]
pub fn unlocked<R>(f: impl FnOnce() -> R) -> R {
    let irq = interrupts::are_enabled();
    interrupts::disable();
    let had = held();
    if had {
        debug_assert!(super::spin::held_count() == 0, "bkl::unlocked while holding a spinlock");
        release();
    }
    if irq {
        interrupts::enable();
    }
    let r = f();
    interrupts::disable();
    if had {
        acquire_if_needed_tagged(&tag::UNLOCKED_END);
    }
    if irq {
        interrupts::enable();
    }
    r
}

/// Runs `f` WITH the BKL – from code that runs without it (syscalls without the
/// BKL that call the scheduler: waiting, waking).  If the BKL was already taken,
/// nothing changes.  `f` may sleep: the task returns, possibly on another CPU,
/// which then holds the BKL (switching always happens under the BKL) – and we release it there.
#[allow(dead_code)]
pub fn with<R>(f: impl FnOnce() -> R) -> R {
    let irq = interrupts::are_enabled();
    interrupts::disable();
    let took = acquire_if_needed();
    if irq {
        interrupts::enable();
    }
    let r = f();
    if took {
        interrupts::disable();
        if held() {
            release();
        }
        if irq {
            interrupts::enable();
        }
    }
    r
}

/// (next ticket, now serving, owner) – diagnostics / tests.
#[allow(dead_code)]
pub fn state() -> (u32, u32, u32) {
    (NEXT.load(Ordering::Relaxed), SERVING.load(Ordering::Relaxed), OWNER.load(Ordering::Relaxed))
}
