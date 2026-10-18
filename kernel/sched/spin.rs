// Spinlocks – locks for short critical sections on multiple CPUs.
//
// Two kinds:
//   * SpinLock<T>    – interrupts stay enabled, but preemption of this
//                      CPU is suspended (preempt counter in cpu.rs), so that
//                      the owner does not give the CPU to a task waiting for the
//                      same lock.  It MUST NOT be taken in an interrupt.
//   * IrqSpinLock<T> – additionally disables interrupts (IF state restored
//                      on release).  For data also touched by an
//                      interrupt handler (on the same CPU a plain SpinLock
//                      would deadlock with itself).
//
// Rule for interrupts: a lock taken in an interrupt handler (IrqSpinLock)
// must have a level HIGHER than every SpinLock held with interrupts
// enabled – the handler can jump into the middle of such a section.  The order
// checker catches this (the interrupt adds itself to this CPU's locks).
//
// Diagnostics (a mini lockdep):
//   * ordering: every lock has a level (`level`); on one CPU you may only take
//     locks with a level HIGHER than all those already held – the order is
//     documented in ARCHITECTURE.md, constants in `level`.  A violation = panic with
//     the names of both locks and their code locations,
//   * recursion: the same CPU takes a lock it already holds -> panic (otherwise
//     it would spin forever),
//   * deadlock: waiting longer than DEADLOCK_REPORT_US (2 s, clock.rs
//     time – HPET, not TSC) -> report (who waits and where; who holds it, since
//     when and from where), after DEADLOCK_PANIC_US (10 s) -> panic,
//   * sleeping with a spinlock (schedule() with a lock held) -> panic
//     (sched::schedule checks `held_count`).
//
// Order relative to the Big Kernel Lock: the BKL is "outside" – while holding
// a spinlock you must not wait for the BKL.  That is why releasing the BKL in the timer tick
// and in `hlt` is skipped when the CPU holds any spinlock.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::panic::Location;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::arch::x86_64::cpu::{self, MAX_CPUS};
use crate::arch::x86_64::{clock, interrupts};

/// Lock levels (acquisition order: ascending).  List and rationale:
/// ARCHITECTURE.md, "Lock ordering".
#[allow(dead_code)]
pub mod level {
    /// VFS (outer – calls block, heap, the allocator).
    pub const VFS: u8 = 20;
    /// Block layer and disk drivers.
    pub const BLOCK: u8 = 30;
    /// Processes: zombie table, family, descriptors.
    /// Passing channel ends in messages (the "no cycles" rule);
    /// the channel queue lock (PROCESS) is below it.
    pub const CHAN_XFER: u8 = 35;
    pub const PROCESS: u8 = 40;
    /// `wait_many` observer lists (channels, pipes, interrupts) –
    /// above the channel / pipe queues (PROCESS), below the scheduler (wakeup after
    /// releasing the list).  IrqSpinLock: an interrupt handler reads it too.
    pub const WAITERS: u8 = 45;
    /// Scheduler (task list, per-CPU queues).
    pub const SCHED: u8 = 50;
    /// Address spaces / page tables.
    pub const PAGING: u8 = 55;
    /// Process output state – captured stdout (tests), the line
    /// being edited by the shell (background messages).  Allocation is allowed under it.
    pub const OUTPUT: u8 = 100;
    /// Tests.
    pub const TEST_OUTER: u8 = 200;
    pub const TEST_INNER: u8 = 210;
    /// Tests: a lock also taken in an interrupt handler – higher than any
    /// lock held with interrupts enabled (an interrupt nests at
    /// any point in code with IF = 1).
    pub const TEST_IRQ: u8 = 220;
    /// Process exit log – written from interrupts (killing a
    /// ring-3 process) and from syscalls without the BKL; a leaf, no allocation.
    pub const EXIT_LOG: u8 = 225;
    /// Kernel heap.  Allocation is allowed from anywhere – including from an
    /// interrupt handler that jumped into a section under any SpinLock
    /// (IF = 1) – so the heap and the frame allocator are nearly innermost
    /// (higher than anything someone holds while allocating).  The heap calls the frame
    /// allocator and TLB shootdown (when shrinking).
    pub const HEAP: u8 = 230;
    /// Frame allocator (called by the heap and page tables).
    pub const FRAMES: u8 = 240;
    /// TLB shootdown – its own request lock (tlb.rs, outside lockdep).
    pub const TLB: u8 = 250;
    /// Console / serial – its own lock (console.rs, outside lockdep):
    /// logging is always allowed.
    pub const CONSOLE: u8 = 255;
}

/// Waiting for a spinlock longer than this = report (critical sections take
/// microseconds), and longer than DEADLOCK_PANIC_US = panic.  Measured with the
/// clock.rs clock (HPET), because core TSCs can disagree.
pub const DEADLOCK_REPORT_US: u64 = 2_000_000;
pub const DEADLOCK_PANIC_US: u64 = 10_000_000;

/// Maximum number of locks held at once by one CPU.
const MAX_HELD: usize = 8;
const HELD_IN_IRQ: usize = 1;

/// Locks held by each CPU (`RawSpin` address, 0 = empty slot).
/// Bit 0 of the address (RawSpin is 64 B aligned) = lock taken in an
/// interrupt handler.  Level order is checked only within a single
/// context: an interrupt handler (IrqSpinLock) does not violate the order relative to a
/// lock held by the interrupted code – that code cannot hold it with IF = 0 and
/// wait for the handler.  Previously a usbd MSI interrupt (wait_many wakeup,
/// 'waiters' level 45) on a CPU whose interrupted code held 'stress-counter'
/// (210) caused a false lockdep PANIC when typing on a USB keyboard
/// during the stress test.  Recursion (the same lock) – still always checked.
static HELD: crate::arch::x86_64::percpu::PerCpu<[AtomicUsize; MAX_HELD]> = crate::per_cpu!([const { AtomicUsize::new(0) }; MAX_HELD]);
static HELD_COUNT: crate::arch::x86_64::percpu::PerCpu<AtomicUsize> = crate::per_cpu!(AtomicUsize::new(0));

/// Statistics (`cpus` command, tests).
static ACQUIRES: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static CONTENDED: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static DEADLOCK_REPORTS: AtomicU64 = AtomicU64::new(0);

/// Number of spinlocks held by CPU `c` (watchdog report).
pub fn held_count_of(c: usize) -> usize {
    HELD_COUNT[c % MAX_CPUS].load(Ordering::Relaxed)
}

/// Number of spinlocks held by the current CPU.
#[inline]
pub fn held_count() -> usize {
    HELD_COUNT[cpu::id()].load(Ordering::Relaxed)
}

/// The first lock held by this CPU: (name, acquisition site) – reports.
pub fn first_held() -> Option<(&'static str, &'static str, u32)> {
    for slot in HELD[cpu::id()].iter() {
        let a = slot.load(Ordering::Relaxed) & !HELD_IN_IRQ;
        if a != 0 {
            let l = unsafe { &*(a as *const RawSpin) };
            let (f, line) = site_str(l.site.load(Ordering::Relaxed));
            return Some((l.name, f, line));
        }
    }
    None
}

/// (acquisitions, acquisitions with waiting, deadlock reports) – diagnostics.
pub fn stats() -> (u64, u64, u64) {
    (ACQUIRES.get(), CONTENDED.get(), DEADLOCK_REPORTS.load(Ordering::Relaxed))
}

// ------------------------------------------------------------
// Wait (spin) time per lock name
// ------------------------------------------------------------

/// Table entry: name pointer and length, number of waits, TSC cycles.
struct SpinSlot {
    name: AtomicUsize,
    len: AtomicUsize,
    n: AtomicU64,
    cyc: AtomicU64,
}

const SPIN_SLOTS: usize = 24;

/// Per-CPU table (only this CPU writes; an interrupt may come in the middle –
/// entries are claimed with CAS).
static SPIN_WAIT: crate::arch::x86_64::percpu::PerCpu<[SpinSlot; SPIN_SLOTS]> = crate::per_cpu!(
    [const { SpinSlot { name: AtomicUsize::new(0), len: AtomicUsize::new(0), n: AtomicU64::new(0), cyc: AtomicU64::new(0) } };
        SPIN_SLOTS]
);

fn spin_wait_record(name: &'static str, cycles: u64) {
    let key = name.as_ptr() as usize;
    for s in SPIN_WAIT[cpu::id()].iter() {
        let cur = s.name.load(Ordering::Relaxed);
        if cur == key || (cur == 0 && s.name.compare_exchange(0, key, Ordering::Relaxed, Ordering::Relaxed).is_ok()) {
            s.len.store(name.len(), Ordering::Relaxed);
            s.n.fetch_add(1, Ordering::Relaxed);
            s.cyc.fetch_add(cycles, Ordering::Relaxed);
            return;
        }
    }
}

pub fn spin_wait_reset() {
    for t in SPIN_WAIT.iter() {
        for s in t.iter() {
            s.n.store(0, Ordering::Relaxed);
            s.cyc.store(0, Ordering::Relaxed);
        }
    }
}

/// (name, waits, cycles) – summed over all CPUs, sorted by cycles descending.
pub fn spin_wait_stats() -> alloc::vec::Vec<(&'static str, u64, u64)> {
    let mut v: alloc::vec::Vec<(&'static str, u64, u64)> = alloc::vec::Vec::new();
    for t in SPIN_WAIT.iter() {
        for s in t.iter() {
            let p = s.name.load(Ordering::Relaxed);
            let len = s.len.load(Ordering::Relaxed);
            let n = s.n.load(Ordering::Relaxed);
            if p == 0 || len == 0 || n == 0 {
                continue;
            }
            let name: &'static str =
                unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(p as *const u8, len)) };
            match v.iter_mut().find(|e| e.0 == name) {
                Some(e) => {
                    e.1 += n;
                    e.2 = e.2.saturating_add(s.cyc.load(Ordering::Relaxed));
                }
                None => v.push((name, n, s.cyc.load(Ordering::Relaxed))),
            }
        }
    }
    v.sort_by(|a, b| b.2.cmp(&a.2));
    v
}

/// The part common to both kinds: lock state + diagnostics.  Kept in its
/// own cache line – a neighbouring hot lock does not slow this one down.
#[repr(align(64))]
pub struct RawSpin {
    locked: AtomicBool,
    /// Owner CPU number + 1 (0 = free).
    owner: AtomicU32,
    /// `&'static Location` of the acquisition site (diagnostics).
    site: AtomicUsize,
    /// System clock tick (ms) at acquisition time – cheap and shared by all CPUs.
    since: AtomicU64,
    name: &'static str,
    level: u8,
}

/// A lock rule violation: description (used by tests to avoid panicking).
#[derive(Debug, PartialEq, Eq)]
pub enum LockError {
    /// This CPU already holds this lock.
    Recursive,
    /// Ordering: a held lock (name, level) has a level >= the new one.
    Order { held: &'static str, held_level: u8 },
    /// Too many locks at once.
    TooMany,
}

fn site_str(site: usize) -> (&'static str, u32) {
    if site == 0 {
        return ("?", 0);
    }
    let l: &'static Location<'static> = unsafe { &*(site as *const Location<'static>) };
    (l.file(), l.line())
}

impl RawSpin {
    pub const fn new(name: &'static str, level: u8) -> Self {
        RawSpin {
            locked: AtomicBool::new(false),
            owner: AtomicU32::new(0),
            site: AtomicUsize::new(0),
            since: AtomicU64::new(0),
            name,
            level,
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Whether taking this lock now, on this CPU, breaks the rules.
    pub fn check(&self) -> Result<(), LockError> {
        let me = cpu::id();
        if self.owner.load(Ordering::Relaxed) == me as u32 + 1 {
            return Err(LockError::Recursive);
        }
        let n = HELD_COUNT[me].load(Ordering::Relaxed);
        if n >= MAX_HELD {
            return Err(LockError::TooMany);
        }
        let in_irq = cpu::in_interrupt();
        for slot in HELD[me].iter() {
            let a = slot.load(Ordering::Relaxed);
            // In an interrupt we compare only with locks taken in an interrupt.
            if a != 0 && (!in_irq || a & HELD_IN_IRQ != 0) {
                let other = unsafe { &*((a & !HELD_IN_IRQ) as *const RawSpin) };
                if other.level >= self.level {
                    return Err(LockError::Order { held: other.name, held_level: other.level });
                }
            }
        }
        Ok(())
    }

    #[track_caller]
    fn acquire(&self) {
        self.acquire_with(Location::caller(), DEADLOCK_REPORT_US, DEADLOCK_PANIC_US);
    }

    fn acquire_with(&self, caller: &'static Location<'static>, report_after: u64, panic_after: u64) {
        if let Err(e) = self.check() {
            let (f, l) = (caller.file(), caller.line());
            match e {
                LockError::Recursive => {
                    panic!("spinlock '{}': CPU {} takes it again at {}:{} (deadlock with itself)", self.name, cpu::id(), f, l)
                }
                LockError::Order { held, held_level } => panic!(
                    "spinlock order: '{}' (level {}) taken at {}:{} while holding '{}' (level {}) - see ARCHITECTURE.md",
                    self.name, self.level, f, l, held, held_level
                ),
                LockError::TooMany => panic!("spinlock '{}': more than {} locks held at {}:{}", self.name, MAX_HELD, f, l),
            }
        }
        ACQUIRES.add(1);
        if !self.try_take() {
            CONTENDED.add(1);
            // Spin time per lock name (same CPU – preemption
            // disabled before acquire).
            let spin_t0 = super::bkl::rdtsc();
            // Deadlock detection – HPET (TSC can be unreliable:
            // TCG, differing core TSCs), read only at the first check
            // (every 1024 spins), never under a lock.
            let mut start = 0u64;
            let mut reported = false;
            let mut n: u32 = 0;
            loop {
                while self.locked.load(Ordering::Relaxed) {
                    core::hint::spin_loop();
                    n = n.wrapping_add(1);
                    // IrqSpinLock waits with IF = 0 – handle TLB shootdown here.
                    if n % 64 == 0 {
                        crate::arch::x86_64::tlb::poll_from_wait();
                    }
                    if n % 1024 != 0 {
                        continue;
                    }
                    crate::arch::x86_64::smp::watchdog_poll();
                    if start == 0 {
                        start = clock::stamp().max(1);
                    }
                    let waited = clock::elapsed_us(start);
                    if waited > report_after && !reported {
                        reported = true;
                        self.report_deadlock(caller, waited);
                    }
                    if waited > panic_after {
                        panic!("spinlock '{}': deadlock (CPU {} waited > {} ms)", self.name, cpu::id(), panic_after / 1000);
                    }
                }
                if self.try_take() {
                    break;
                }
            }
            spin_wait_record(self.name, super::bkl::rdtsc().saturating_sub(spin_t0));
        }
        self.owner.store(cpu::id() as u32 + 1, Ordering::Relaxed);
        self.site.store(caller as *const Location as usize, Ordering::Relaxed);
        self.since.store(crate::time::ticks(), Ordering::Relaxed);
        self.push_held();
    }

    #[inline]
    fn try_take(&self) -> bool {
        !self.locked.load(Ordering::Relaxed)
            && self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    fn release(&self) {
        self.pop_held();
        self.owner.store(0, Ordering::Relaxed);
        self.site.store(0, Ordering::Relaxed);
        self.locked.store(false, Ordering::Release);
    }

    fn push_held(&self) {
        let me = cpu::id();
        for slot in HELD[me].iter() {
            if slot.load(Ordering::Relaxed) == 0 {
                let tag = if cpu::in_interrupt() { HELD_IN_IRQ } else { 0 };
                slot.store(self as *const RawSpin as usize | tag, Ordering::Relaxed);
                HELD_COUNT[me].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }

    fn pop_held(&self) {
        let me = cpu::id();
        let addr = self as *const RawSpin as usize;
        for slot in HELD[me].iter() {
            if slot.load(Ordering::Relaxed) & !HELD_IN_IRQ == addr {
                slot.store(0, Ordering::Relaxed);
                HELD_COUNT[me].fetch_sub(1, Ordering::Relaxed);
                return;
            }
        }
    }

    #[cold]
    fn report_deadlock(&self, caller: &Location, waited: u64) {
        DEADLOCK_REPORTS.fetch_add(1, Ordering::Relaxed);
        let owner = self.owner.load(Ordering::Relaxed);
        let (hf, hl) = site_str(self.site.load(Ordering::Relaxed));
        let held_for = crate::time::ticks().saturating_sub(self.since.load(Ordering::Relaxed));
        crate::serial_println!(
            "[LOCK] possible deadlock: CPU {} waits {} ms for '{}' at {}:{}; held by CPU {} for {} ms, taken at {}:{}",
            cpu::id(),
            waited / 1000,
            self.name,
            caller.file(),
            caller.line(),
            owner as i64 - 1,
            held_for,
            hf,
            hl
        );
    }

    /// Tests: waits at most `us` microseconds; Err = (owner CPU, site).
    #[allow(dead_code)]
    pub fn try_lock_for(&self, us: u64) -> Result<(), (i64, &'static str, u32)> {
        let start = clock::stamp();
        while !self.try_take() {
            if clock::elapsed_us(start) > us {
                let (f, l) = site_str(self.site.load(Ordering::Relaxed));
                return Err((self.owner.load(Ordering::Relaxed) as i64 - 1, f, l));
            }
            crate::arch::x86_64::tlb::poll_from_wait();
            core::hint::spin_loop();
        }
        self.locked.store(false, Ordering::Release);
        Ok(())
    }

    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

// ------------------------------------------------------------
// SpinLock<T>
// ------------------------------------------------------------

pub struct SpinLock<T> {
    raw: RawSpin,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

pub struct SpinGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> SpinLock<T> {
    pub const fn new(name: &'static str, level: u8, value: T) -> Self {
        SpinLock { raw: RawSpin::new(name, level), data: UnsafeCell::new(value) }
    }

    /// Takes the lock.  Suspends preemption of this CPU until release.
    #[track_caller]
    pub fn lock(&self) -> SpinGuard<'_, T> {
        debug_assert!(!cpu::in_interrupt(), "SpinLock '{}' in an interrupt - use IrqSpinLock", self.raw.name);
        cpu::preempt_disable();
        self.raw.acquire();
        SpinGuard { lock: self }
    }

    pub fn raw(&self) -> &RawSpin {
        &self.raw
    }

    /// Tests: like `lock`, but the deadlock report comes after `report_after`
    /// microseconds (no panic).
    #[allow(dead_code)]
    #[track_caller]
    pub fn lock_reporting_after(&self, report_after: u64) -> SpinGuard<'_, T> {
        cpu::preempt_disable();
        self.raw.acquire_with(Location::caller(), report_after, u64::MAX);
        SpinGuard { lock: self }
    }
}

impl<T> Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.raw.release();
        cpu::preempt_enable();
    }
}

// ------------------------------------------------------------
// IrqSpinLock<T>
// ------------------------------------------------------------

pub struct IrqSpinLock<T> {
    raw: RawSpin,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for IrqSpinLock<T> {}
unsafe impl<T: Send> Send for IrqSpinLock<T> {}

pub struct IrqSpinGuard<'a, T> {
    lock: &'a IrqSpinLock<T>,
    irq_was_enabled: bool,
}

impl<T> IrqSpinLock<T> {
    pub const fn new(name: &'static str, level: u8, value: T) -> Self {
        IrqSpinLock { raw: RawSpin::new(name, level), data: UnsafeCell::new(value) }
    }

    /// Takes the lock with interrupts disabled (also from an interrupt handler).
    #[track_caller]
    pub fn lock(&self) -> IrqSpinGuard<'_, T> {
        let irq_was_enabled = interrupts::are_enabled();
        interrupts::disable();
        cpu::preempt_disable();
        self.raw.acquire();
        IrqSpinGuard { lock: self, irq_was_enabled }
    }

    pub fn raw(&self) -> &RawSpin {
        &self.raw
    }
}

impl<T> Deref for IrqSpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for IrqSpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for IrqSpinGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.raw.release();
        cpu::preempt_enable();
        if self.irq_was_enabled {
            interrupts::enable();
        }
    }
}

// ------------------------------------------------------------
// RwSpinLock – a spinning readers–writer lock
// ------------------------------------------------------------
//
// For structures read very often, changed less often, with sections
// on the order of µs (the ramfs directory tree).  A sleeping KRwLock paid for every
// wait with a sleep and a wakeup through the scheduler (on real hardware: hundreds of
// thousands of read waits).  Rules as for SpinLock: preemption suspended
// (preempt counter), you must not sleep or take a KMutex under it (schedule()
// checks held_count), not in an interrupt.  Writer priority: a waiting
// writer stops NEW readers (no read recursion!).  No
// lockdep (it has no level) – heap / frames may be taken under it.

const RW_WRITER: u32 = 1 << 31;

pub struct RwSpinLock {
    name: &'static str,
    /// RW_WRITER | number of readers.
    state: AtomicU32,
    writers_waiting: AtomicU32,
    registered: AtomicBool,
    // Statistics (`cpus`): acquisitions, acquisitions with waiting, µs of waiting (TSC,
    // same CPU – we wait without preemption), µs of holding (TSC).
    reads: AtomicU64,
    writes: AtomicU64,
    read_waited: AtomicU64,
    write_waited: AtomicU64,
    wait_us: AtomicU64,
    hold_tsc: AtomicU64,
}

/// Registry of named RwSpinLocks (statistics) – registered on first acquisition,
/// unregistered in Drop (the lock is sometimes part of a heap object).
static NAMED_RWSPIN: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];

pub struct RwSpinStats {
    pub name: &'static str,
    pub reads: u64,
    pub writes: u64,
    pub read_waited: u64,
    pub write_waited: u64,
    pub wait_us: u64,
    pub held_us: u64,
}

pub fn rwspin_stats() -> alloc::vec::Vec<RwSpinStats> {
    let tsc_ms = crate::arch::x86_64::lapic::tsc_per_ms();
    NAMED_RWSPIN
        .iter()
        .filter_map(|a| {
            let p = a.load(Ordering::Acquire);
            if p == 0 {
                return None;
            }
            let l = unsafe { &*(p as *const RwSpinLock) };
            Some(RwSpinStats {
                name: l.name,
                reads: l.reads.load(Ordering::Relaxed),
                writes: l.writes.load(Ordering::Relaxed),
                read_waited: l.read_waited.load(Ordering::Relaxed),
                write_waited: l.write_waited.load(Ordering::Relaxed),
                wait_us: l.wait_us.load(Ordering::Relaxed),
                held_us: if tsc_ms == 0 { 0 } else { l.hold_tsc.load(Ordering::Relaxed).saturating_mul(1000) / tsc_ms },
            })
        })
        .collect()
}

pub struct RwSpinReadGuard<'a> {
    lock: &'a RwSpinLock,
    t0: u64,
}

pub struct RwSpinWriteGuard<'a> {
    lock: &'a RwSpinLock,
    t0: u64,
}

impl RwSpinLock {
    pub const fn new(name: &'static str) -> Self {
        RwSpinLock {
            name,
            state: AtomicU32::new(0),
            writers_waiting: AtomicU32::new(0),
            registered: AtomicBool::new(false),
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            read_waited: AtomicU64::new(0),
            write_waited: AtomicU64::new(0),
            wait_us: AtomicU64::new(0),
            hold_tsc: AtomicU64::new(0),
        }
    }

    fn register(&self) {
        if self.registered.load(Ordering::Relaxed) || self.registered.swap(true, Ordering::AcqRel) {
            return;
        }
        let me = self as *const RwSpinLock as usize;
        for slot in NAMED_RWSPIN.iter() {
            if slot.compare_exchange(0, me, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                return;
            }
        }
    }

    /// Spinning with deadlock detection (HPET every 1024 spins, like RawSpin).
    fn spin_wait(&self, mut ready: impl FnMut() -> bool) -> u64 {
        let (tsc0, cpu0) = clock::tsc_cpu();
        let mut start = 0u64;
        let mut reported = false;
        let mut n: u32 = 0;
        while !ready() {
            core::hint::spin_loop();
            n = n.wrapping_add(1);
            // A waiter with IF = 0 (task table) acknowledges TLB shootdown.
            if n % 64 == 0 {
                crate::arch::x86_64::tlb::poll_from_wait();
            }
            if n % 1024 != 0 {
                continue;
            }
            crate::arch::x86_64::smp::watchdog_poll();
            if start == 0 {
                start = clock::stamp().max(1);
            }
            let waited = clock::elapsed_us(start);
            if waited > DEADLOCK_REPORT_US && !reported {
                reported = true;
                DEADLOCK_REPORTS.fetch_add(1, Ordering::Relaxed);
                crate::serial_println!(
                    "[LOCK] possible deadlock: CPU {} waits {} ms for rwlock '{}' (state {:#x}, writers waiting {})",
                    cpu::id(),
                    waited / 1000,
                    self.name,
                    self.state.load(Ordering::Relaxed),
                    self.writers_waiting.load(Ordering::Relaxed)
                );
            }
            if waited > DEADLOCK_PANIC_US {
                panic!("rwlock '{}': deadlock (CPU {} waited > {} ms)", self.name, cpu::id(), DEADLOCK_PANIC_US / 1000);
            }
        }
        clock::tsc_wait_us(tsc0, cpu0)
    }

    fn try_read(&self) -> bool {
        let s = self.state.load(Ordering::Relaxed);
        s & RW_WRITER == 0
            && self.writers_waiting.load(Ordering::Relaxed) == 0
            && self.state.compare_exchange_weak(s, s + 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    fn try_write(&self) -> bool {
        self.state.compare_exchange_weak(0, RW_WRITER, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    fn enter(&self) {
        debug_assert!(!cpu::in_interrupt(), "RwSpinLock '{}' in an interrupt", self.name);
        self.register();
        cpu::preempt_disable();
        // Counts as a held spinlock: schedule() with it held = panic.
        HELD_COUNT[cpu::id()].fetch_add(1, Ordering::Relaxed);
        ACQUIRES.add(1);
    }

    fn leave(&self, t0: u64) {
        self.hold_tsc.fetch_add(crate::sched::bkl::rdtsc().wrapping_sub(t0) & ((1 << 48) - 1), Ordering::Relaxed);
        HELD_COUNT[cpu::id()].fetch_sub(1, Ordering::Relaxed);
        cpu::preempt_enable();
    }

    pub fn read(&self) -> RwSpinReadGuard<'_> {
        self.enter();
        if !self.try_read() {
            CONTENDED.add(1);
            let us = self.spin_wait(|| self.try_read());
            self.read_waited.fetch_add(1, Ordering::Relaxed);
            self.wait_us.fetch_add(us, Ordering::Relaxed);
        }
        self.reads.fetch_add(1, Ordering::Relaxed);
        RwSpinReadGuard { lock: self, t0: crate::sched::bkl::rdtsc() }
    }

    pub fn write(&self) -> RwSpinWriteGuard<'_> {
        self.enter();
        if !self.try_write() {
            CONTENDED.add(1);
            // Priority: new readers wait until we get in.
            self.writers_waiting.fetch_add(1, Ordering::Relaxed);
            let us = self.spin_wait(|| self.try_write());
            self.writers_waiting.fetch_sub(1, Ordering::Relaxed);
            self.write_waited.fetch_add(1, Ordering::Relaxed);
            self.wait_us.fetch_add(us, Ordering::Relaxed);
        }
        self.writes.fetch_add(1, Ordering::Relaxed);
        RwSpinWriteGuard { lock: self, t0: crate::sched::bkl::rdtsc() }
    }

    /// Diagnostics / tests: (writer, readers).
    #[allow(dead_code)]
    pub fn state(&self) -> (bool, u32) {
        let s = self.state.load(Ordering::Relaxed);
        (s & RW_WRITER != 0, s & !RW_WRITER)
    }
}

impl Drop for RwSpinReadGuard<'_> {
    fn drop(&mut self) {
        self.lock.state.fetch_sub(1, Ordering::Release);
        self.lock.leave(self.t0);
    }
}

impl Drop for RwSpinWriteGuard<'_> {
    fn drop(&mut self) {
        self.lock.state.fetch_and(!RW_WRITER, Ordering::Release);
        self.lock.leave(self.t0);
    }
}

impl Drop for RwSpinLock {
    fn drop(&mut self) {
        let me = self as *const RwSpinLock as usize;
        for slot in NAMED_RWSPIN.iter() {
            let _ = slot.compare_exchange(me, 0, Ordering::AcqRel, Ordering::Relaxed);
        }
    }
}
