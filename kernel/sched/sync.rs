// Task synchronization – wait queues and a mutex.
//
// WaitQueue: a task sleeps until a condition holds; it is woken by
// `wake_all()` (e.g. from an interrupt handler) or by a timeout.  The condition is
// checked with interrupts disabled, so a wakeup cannot
// "get lost" between the check and going to sleep.  Without the scheduler (early
// boot) waiting is the old `sti; hlt`.
//
// Mutex: a sleeping lock (a waiting task does not use the CPU),
// reentrant – the same task can take it multiple times (the VFS calls
// itself, e.g. write_file -> stat).  Must not be taken in an interrupt.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::{can_block, current_id, wake_channel, wake_one_channel};
use crate::arch::x86_64::interrupts;

pub struct WaitQueue {
    // The queue address is the channel identifier – the field must not be
    // zero-sized (static ZSTs could share an address).
    _id: AtomicU8,
}

impl WaitQueue {
    pub const fn new() -> Self {
        WaitQueue { _id: AtomicU8::new(0) }
    }

    fn channel(&self) -> usize {
        self as *const WaitQueue as usize
    }

    /// Wakes all tasks waiting in this queue (also from an interrupt).
    pub fn wake_all(&self) {
        wake_channel(self.channel());
    }

    /// Wakes one – the longest-waiting; `true` – someone was woken.
    pub fn wake_one(&self) -> bool {
        wake_one_channel(self.channel())
    }

    /// Waits until `cond()` is true or `timeout_ms` elapses.
    /// Returns the condition result.  Requires interrupts enabled.
    pub fn wait_until(&self, mut cond: impl FnMut() -> bool, timeout_ms: Option<u64>) -> bool {
        // The condition check and going to sleep happen under the scheduler lock
        // (sched::wait_event); the wakeup (wake_channel) takes it too, so it cannot
        // get lost – no BKL needed (the BKL used to guarantee this).
        let was_enabled = interrupts::are_enabled();
        assert!(was_enabled, "wait_until with interrupts disabled");
        let deadline = match timeout_ms {
            Some(ms) => crate::time::ticks() + crate::time::ms_to_ticks(ms) + 1,
            None => u64::MAX,
        };
        if can_block() {
            return super::wait_event(self.channel(), deadline, &mut cond);
        }
        self.wait_until_hlt(cond, deadline)
    }

    /// Without the scheduler (early boot) or in the idle task: `sti; hlt`.
    fn wait_until_hlt(&self, mut cond: impl FnMut() -> bool, deadline: u64) -> bool {
        let result = loop {
            interrupts::disable();
            if cond() {
                break true;
            }
            if crate::time::ticks() >= deadline {
                break false;
            }
            // sti+hlt is atomic: an IRQ cannot be lost between the check and hlt.
            interrupts::enable_and_hlt();
        };
        interrupts::enable();
        result
    }
}

/// Reentrant lock without data (guards module state, e.g. the VFS).
pub struct KMutex {
    owner: AtomicU64, // 0 = free
    depth: AtomicU32,
    queue: WaitQueue,
    contended: AtomicU64,
    // Statistics (named locks – `cpus`: "sleeping locks").
    name: &'static str,
    registered: AtomicBool,
    acquires: AtomicU64,
    /// Acquisitions that had to wait (counted once per `lock`).
    waited: AtomicU64,
    /// Acquisitions after a short spin, without sleeping.
    spun: AtomicU64,
    /// How many tasks are waiting (unlock wakes one if > 0).
    sleepers: AtomicU32,
    wait_us: AtomicU64,
    /// Hold time is sampled – every HOLD_SAMPLE-th acquisition stores an
    /// HPET timestamp (0 = this acquisition is not a sample), sum of sampled µs × HOLD_SAMPLE.
    /// (TSC is not used: the holder may sleep and change CPU, and TSCs of different
    /// cores can differ on real hardware, giving absurd hold times.)
    taken_stamp: AtomicU64,
    /// CPU on which the lock was taken (TSC is comparable only on that CPU).
    taken_cpu: AtomicU32,
    hold_us: AtomicU64,
}

/// How often an acquisition measures hold time (an HPET read costs ~1 µs).
const HOLD_SAMPLE: u64 = 16;

/// How many spins (`pause`) to do before sleeping – on the order of
/// tens of µs.  Only with several CPUs (with one, the holder will not
/// run anyway until we give up the CPU).
/// Long spinning was measured on real hardware to burn CPU under heavy contention
/// (6% idle) and lower throughput by 9%; it is kept as a tuning knob
/// for measurements.
/// Enabled briefly (200 × `pause` – a few µs): critical sections
/// last microseconds (HPET / RTC reads under the lock no longer stretch
/// them), while sleeping and waking cost two passes through the scheduler.
const SPIN_ITERS: u32 = 200;

/// Spins until `ready()` or the spin limit; `true` = ready.
fn spin_until(mut ready: impl FnMut() -> bool) -> bool {
    if SPIN_ITERS == 0 || !crate::arch::x86_64::smp::active() {
        return false;
    }
    for _ in 0..SPIN_ITERS {
        if ready() {
            return true;
        }
        core::hint::spin_loop();
    }
    ready()
}

// Registry of named KMutexes (static – fixed address).  An entry is added on
// the first `lock`.
const MAX_NAMED: usize = 16;
static NAMED: [core::sync::atomic::AtomicUsize; MAX_NAMED] = [const { core::sync::atomic::AtomicUsize::new(0) }; MAX_NAMED];

/// Statistics of one sleeping lock.
pub struct KMutexStats {
    pub name: &'static str,
    pub acquires: u64,
    pub waited: u64,
    pub spun: u64,
    pub wait_us: u64,
    pub held_us: u64,
}

/// All named locks that have been taken so far (sorted by waiting +
/// holding time, descending).
pub fn kmutex_stats() -> alloc::vec::Vec<KMutexStats> {
    let mut v: alloc::vec::Vec<KMutexStats> = NAMED
        .iter()
        .filter_map(|a| {
            let p = a.load(Ordering::Acquire);
            if p == 0 {
                return None;
            }
            let m = unsafe { &*(p as *const KMutex) };
            Some(KMutexStats {
                name: m.name,
                acquires: m.acquires.load(Ordering::Relaxed),
                waited: m.waited.load(Ordering::Relaxed),
                spun: m.spun.load(Ordering::Relaxed),
                wait_us: m.wait_us.load(Ordering::Relaxed),
                held_us: m.hold_us.load(Ordering::Relaxed),
            })
        })
        .collect();
    v.sort_by(|a, b| (b.wait_us + b.held_us).cmp(&(a.wait_us + a.held_us)));
    v
}

pub struct KMutexGuard<'a> {
    mutex: &'a KMutex,
}

impl KMutex {
    pub const fn new() -> Self {
        Self::new_named("")
    }

    /// Named lock – counted in `cpus` ("sleeping locks").
    /// Only for static locks (the registry stores the address).
    pub const fn new_named(name: &'static str) -> Self {
        KMutex {
            owner: AtomicU64::new(0),
            depth: AtomicU32::new(0),
            queue: WaitQueue::new(),
            contended: AtomicU64::new(0),
            name,
            registered: AtomicBool::new(false),
            acquires: AtomicU64::new(0),
            waited: AtomicU64::new(0),
            spun: AtomicU64::new(0),
            sleepers: AtomicU32::new(0),
            wait_us: AtomicU64::new(0),
            taken_stamp: AtomicU64::new(0),
            taken_cpu: AtomicU32::new(0),
            hold_us: AtomicU64::new(0),
        }
    }

    fn register(&self) {
        if self.name.is_empty() || self.registered.load(Ordering::Relaxed) {
            return;
        }
        if self.registered.swap(true, Ordering::AcqRel) {
            return;
        }
        let me = self as *const KMutex as usize;
        for slot in NAMED.iter() {
            if slot.compare_exchange(0, me, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                return;
            }
        }
    }

    fn try_take(&self, me: u64) -> bool {
        // compare_exchange – two CPUs without the BKL cannot take it at once
        // (disabling interrupts alone is not enough with several CPUs in the kernel).
        match self.owner.compare_exchange(0, me, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => {
                self.depth.store(1, Ordering::Relaxed);
                if !self.name.is_empty() {
                    let sample = self.acquires.load(Ordering::Relaxed) % HOLD_SAMPLE == 0;
                    // TSC + CPU (rdtscp), not HPET – this read happens under the lock.
                    if sample {
                        let (t, c) = crate::arch::x86_64::clock::tsc_cpu();
                        self.taken_cpu.store(c, Ordering::Relaxed);
                        self.taken_stamp.store(t.max(1), Ordering::Relaxed);
                    } else {
                        self.taken_stamp.store(0, Ordering::Relaxed);
                    }
                }
                true
            }
            Err(owner) if owner == me => {
                self.depth.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(_) => false,
        }
    }

    pub fn lock(&self) -> KMutexGuard<'_> {
        let me = current_id();
        self.register();
        if !self.try_take(me) {
            self.contended.fetch_add(1, Ordering::Relaxed);
            // Spin briefly first – sections under these locks
            // last microseconds, while sleeping and waking go through the scheduler
            // (on the order of 1 ms per wait on real hardware).
            if spin_until(|| self.owner.load(Ordering::Relaxed) == 0) && self.try_take(me) {
                self.spun.fetch_add(1, Ordering::Relaxed);
                self.acquires.fetch_add(1, Ordering::Relaxed);
                return KMutexGuard { mutex: self };
            }
            // Waiting is counted once per `lock` (time from the HPET clock).
            let t0 = crate::arch::x86_64::clock::stamp();
            // Register as waiting BEFORE checking the condition under the
            // scheduler lock – an unlocker that sees sleepers > 0
            // wakes one; if this task is not asleep yet, the condition
            // (owner == 0), checked under the same lock, keeps it from sleeping.
            self.sleepers.fetch_add(1, Ordering::SeqCst);
            // End of waiting is read BEFORE acquiring (an HPET read under the
            // lock would lengthen the hold time).
            let mut t1 = t0;
            while !self.try_take(me) {
                self.contended.fetch_add(1, Ordering::Relaxed);
                self.queue.wait_until(|| self.owner.load(Ordering::SeqCst) == 0, None);
                t1 = crate::arch::x86_64::clock::stamp();
            }
            self.sleepers.fetch_sub(1, Ordering::SeqCst);
            self.waited.fetch_add(1, Ordering::Relaxed);
            self.wait_us.fetch_add(crate::arch::x86_64::clock::us_between(t0, t1), Ordering::Relaxed);
        }
        self.acquires.fetch_add(1, Ordering::Relaxed);
        KMutexGuard { mutex: self }
    }

    /// How many times someone had to wait (diagnostics / tests).
    #[allow(dead_code)]
    pub fn contended(&self) -> u64 {
        self.contended.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub fn is_locked(&self) -> bool {
        self.owner.load(Ordering::Relaxed) != 0
    }
}

impl Drop for KMutexGuard<'_> {
    fn drop(&mut self) {
        let m = self.mutex;
        let release = if m.depth.fetch_sub(1, Ordering::Relaxed) == 1 {
            let t0 = m.taken_stamp.load(Ordering::Relaxed);
            if t0 != 0 {
                // CPU changed meanwhile (preemption) – sample skipped.
                if let Some(us) = crate::arch::x86_64::clock::tsc_us_on(t0, m.taken_cpu.load(Ordering::Relaxed)) {
                    m.hold_us.fetch_add(us * HOLD_SAMPLE, Ordering::Relaxed);
                }
            }
            m.owner.store(0, Ordering::SeqCst);
            true
        } else {
            false
        };
        // Wake one waiter (not all of them).  If someone else takes it
        // in the meantime, whoever takes it will wake the next one when
        // unlocking (sleepers is still > 0).
        if release && m.sleepers.load(Ordering::SeqCst) > 0 {
            m.queue.wake_one();
        }
    }
}

/// Mutex with data (like spin::Mutex, but sleeping).
#[allow(dead_code)]
pub struct Mutex<T> {
    lock: KMutex,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for Mutex<T> {}

#[allow(dead_code)]
pub struct MutexGuard<'a, T> {
    _guard: KMutexGuard<'a>,
    data: *mut T,
}

#[allow(dead_code)]
impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Mutex { lock: KMutex::new(), data: UnsafeCell::new(value) }
    }

    /// Named in the statistics (static ones only).
    pub const fn new_named(name: &'static str, value: T) -> Self {
        Mutex { lock: KMutex::new_named(name), data: UnsafeCell::new(value) }
    }

    /// Note: reentrant – a second `lock()` in the same task would give two
    /// `&mut` references to the same data, so for `Mutex<T>` it is
    /// forbidden (panic).
    pub fn lock(&self) -> MutexGuard<'_, T> {
        let guard = self.lock.lock();
        assert!(self.lock.depth.load(Ordering::Relaxed) == 1, "Mutex<T> locked twice by the same task");
        MutexGuard { _guard: guard, data: self.data.get() }
    }
}

impl<T> core::ops::Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.data }
    }
}

impl<T> core::ops::DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.data }
    }
}

// ------------------------------------------------------------
// KRwLock – sleeping readers–writer lock (VFS)
// ------------------------------------------------------------
//
// Many readers at once or one writer.  Like KMutex it is reentrant –
// the writer may take it again (for reading and for writing), a reader may
// read again (a nested read does not wait for a queued writer –
// otherwise it would deadlock with it).  A reader can NOT upgrade to writing
// (panic – otherwise it would wait for itself).  A writer waiting in the queue
// holds back new readers (they will not starve it).
//
// State under IrqSpinLock (short sections, no allocation): an interrupt inside a section
// under a plain SpinLock takes the BKL – deadlock with a CPU that holds the BKL
// and waits for the same lock (rule from ARCHITECTURE.md).
//
// Separate reader and writer queues (each with its own change
// counter – the wait condition is a single atomic).  Unlock wakes only those
// who can enter:
//   * a writer finishes: the waiting readers – as a whole group (and they may enter despite
//     waiting writers: `readers_pass`), and if there are none – ONE writer;
//   * the last reader leaves: ONE writer.
// Readers and writers interleave (neither side starves the other).
// Waking everyone on every unlock caused huge wait times on a ramfs
// tree stress test.

const MAX_READERS: usize = 64;

struct RwState {
    writer: u64,
    wdepth: u32,
    writers_waiting: u32,
    readers_waiting: u32,
    /// How many waiting readers a writer's unlock lets in (despite
    /// waiting writers).
    readers_pass: u32,
    readers: [(u64, u32); MAX_READERS],
    nreaders: usize,
}

pub struct KRwLock {
    name: &'static str,
    state: crate::sched::spin::IrqSpinLock<RwState>,
    read_q: WaitQueue,
    write_q: WaitQueue,
    read_gen: AtomicU64,
    write_gen: AtomicU64,
    registered: AtomicBool,
    reads: AtomicU64,
    writes: AtomicU64,
    read_waited: AtomicU64,
    write_waited: AtomicU64,
    wait_us: AtomicU64,
    /// Waits that ended while spinning (without sleeping).
    spun: AtomicU64,
}

static NAMED_RW: [core::sync::atomic::AtomicUsize; 8] = [const { core::sync::atomic::AtomicUsize::new(0) }; 8];

/// Like `KMutexStats`, split into reads / writes.
pub struct KRwLockStats {
    pub name: &'static str,
    pub reads: u64,
    pub writes: u64,
    pub read_waited: u64,
    pub write_waited: u64,
    pub wait_us: u64,
    pub spun: u64,
}

pub fn krwlock_stats() -> alloc::vec::Vec<KRwLockStats> {
    NAMED_RW
        .iter()
        .filter_map(|a| {
            let p = a.load(Ordering::Acquire);
            if p == 0 {
                return None;
            }
            let l = unsafe { &*(p as *const KRwLock) };
            Some(KRwLockStats {
                name: l.name,
                reads: l.reads.load(Ordering::Relaxed),
                writes: l.writes.load(Ordering::Relaxed),
                read_waited: l.read_waited.load(Ordering::Relaxed),
                write_waited: l.write_waited.load(Ordering::Relaxed),
                wait_us: l.wait_us.load(Ordering::Relaxed),
                spun: l.spun.load(Ordering::Relaxed),
            })
        })
        .collect()
}

pub enum KRwGuard<'a> {
    Read(&'a KRwLock),
    Write(&'a KRwLock),
}

/// Whom to wake after unlocking (outside the state lock).
enum RwWake {
    Nobody,
    Readers,
    Writer,
}

impl KRwLock {
    /// A named lock enters the statistics on first use – after that
    /// it must not be moved (static or already on the heap).
    pub const fn new_named(name: &'static str) -> Self {
        KRwLock {
            name,
            state: crate::sched::spin::IrqSpinLock::new(
                "krwlock-state",
                crate::sched::spin::level::PROCESS,
                RwState {
                    writer: 0,
                    wdepth: 0,
                    writers_waiting: 0,
                    readers_waiting: 0,
                    readers_pass: 0,
                    readers: [(0, 0); MAX_READERS],
                    nreaders: 0,
                },
            ),
            read_q: WaitQueue::new(),
            write_q: WaitQueue::new(),
            read_gen: AtomicU64::new(0),
            write_gen: AtomicU64::new(0),
            registered: AtomicBool::new(false),
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            read_waited: AtomicU64::new(0),
            write_waited: AtomicU64::new(0),
            wait_us: AtomicU64::new(0),
            spun: AtomicU64::new(0),
        }
    }

    fn register(&self) {
        if self.name.is_empty() || self.registered.load(Ordering::Relaxed) || self.registered.swap(true, Ordering::AcqRel) {
            return;
        }
        let me = self as *const KRwLock as usize;
        for slot in NAMED_RW.iter() {
            if slot.compare_exchange(0, me, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                return;
            }
        }
    }

    /// Waits for the counter `counter` (read under the state lock) to change.
    fn wait_gen(&self, q: &WaitQueue, counter: &AtomicU64, seen: u64) {
        if spin_until(|| counter.load(Ordering::Acquire) != seen) {
            self.spun.fetch_add(1, Ordering::Relaxed);
            return;
        }
        q.wait_until(|| counter.load(Ordering::Acquire) != seen, None);
    }

    fn wake(&self, w: RwWake) {
        match w {
            RwWake::Nobody => {}
            RwWake::Readers => {
                self.read_gen.fetch_add(1, Ordering::AcqRel);
                self.read_q.wake_all();
            }
            RwWake::Writer => {
                self.write_gen.fetch_add(1, Ordering::AcqRel);
                self.write_q.wake_one();
            }
        }
    }

    /// Whether the current task holds this lock for reading.
    pub fn read_held(&self) -> bool {
        let me = current_id();
        let st = self.state.lock();
        st.readers[..st.nreaders].iter().any(|r| r.0 == me)
    }

    pub fn read(&self) -> KRwGuard<'_> {
        self.register();
        let me = current_id();
        let mut t0 = 0;
        let mut t1 = 0; // End of waiting is read before acquiring
        let mut queued = false;
        loop {
            let seen;
            {
                let mut st = self.state.lock();
                if st.writer == me {
                    st.wdepth += 1;
                    drop(st);
                    self.reads.fetch_add(1, Ordering::Relaxed);
                    return KRwGuard::Write(self);
                }
                let n = st.nreaders;
                if let Some(r) = st.readers[..n].iter_mut().find(|r| r.0 == me) {
                    r.1 += 1;
                    drop(st);
                    self.reads.fetch_add(1, Ordering::Relaxed);
                    return KRwGuard::Read(self);
                }
                // May enter: no writer and (nobody waits to write or
                // this is the group let in after a writer's unlock).
                let pass = queued && st.readers_pass > 0;
                if st.writer == 0 && (st.writers_waiting == 0 || pass) && n < MAX_READERS {
                    st.readers[n] = (me, 1);
                    st.nreaders = n + 1;
                    if queued {
                        st.readers_waiting -= 1;
                        if st.readers_pass > 0 {
                            st.readers_pass -= 1;
                        }
                    }
                    drop(st);
                    self.reads.fetch_add(1, Ordering::Relaxed);
                    if t0 != 0 {
                        self.read_waited.fetch_add(1, Ordering::Relaxed);
                        self.wait_us.fetch_add(crate::arch::x86_64::clock::us_between(t0, t1), Ordering::Relaxed);
                    }
                    return KRwGuard::Read(self);
                }
                if !queued {
                    queued = true;
                    st.readers_waiting += 1;
                }
                seen = self.read_gen.load(Ordering::Acquire);
            }
            if t0 == 0 {
                t0 = crate::arch::x86_64::clock::stamp().max(1);
            }
            self.wait_gen(&self.read_q, &self.read_gen, seen);
            t1 = crate::arch::x86_64::clock::stamp();
        }
    }

    pub fn write(&self) -> KRwGuard<'_> {
        self.register();
        let me = current_id();
        let mut t0 = 0;
        let mut t1 = 0; // End of waiting is read before acquiring
        let mut queued = false;
        loop {
            let seen;
            {
                let mut st = self.state.lock();
                if st.writer == me {
                    st.wdepth += 1;
                    drop(st);
                    self.writes.fetch_add(1, Ordering::Relaxed);
                    return KRwGuard::Write(self);
                }
                if st.readers[..st.nreaders].iter().any(|r| r.0 == me) {
                    drop(st);
                    panic!("KRwLock '{}': task {} holds it for reading and asks to write", self.name, me);
                }
                if st.writer == 0 && st.nreaders == 0 {
                    st.writer = me;
                    st.wdepth = 1;
                    if queued {
                        st.writers_waiting -= 1;
                    }
                    drop(st);
                    self.writes.fetch_add(1, Ordering::Relaxed);
                    if t0 != 0 {
                        self.write_waited.fetch_add(1, Ordering::Relaxed);
                        self.wait_us.fetch_add(crate::arch::x86_64::clock::us_between(t0, t1), Ordering::Relaxed);
                    }
                    return KRwGuard::Write(self);
                }
                if !queued {
                    queued = true;
                    st.writers_waiting += 1;
                }
                seen = self.write_gen.load(Ordering::Acquire);
            }
            if t0 == 0 {
                t0 = crate::arch::x86_64::clock::stamp().max(1);
            }
            self.wait_gen(&self.write_q, &self.write_gen, seen);
            t1 = crate::arch::x86_64::clock::stamp();
        }
    }
}

impl Drop for KRwGuard<'_> {
    fn drop(&mut self) {
        let me = current_id();
        let (l, wake) = match *self {
            KRwGuard::Write(l) => {
                let mut st = l.state.lock();
                debug_assert!(st.writer == me, "KRwLock write guard dropped by another task");
                st.wdepth -= 1;
                let mut wake = RwWake::Nobody;
                if st.wdepth == 0 {
                    st.writer = 0;
                    if st.readers_waiting > 0 {
                        // A group of readers enters despite waiting writers.
                        st.readers_pass = st.readers_waiting;
                        wake = RwWake::Readers;
                    } else if st.writers_waiting > 0 {
                        wake = RwWake::Writer;
                    }
                }
                (l, wake)
            }
            KRwGuard::Read(l) => {
                let mut st = l.state.lock();
                let n = st.nreaders;
                let i = st.readers[..n].iter().position(|r| r.0 == me).expect("KRwLock read guard without a reader slot");
                st.readers[i].1 -= 1;
                let mut wake = RwWake::Nobody;
                if st.readers[i].1 == 0 {
                    st.readers[i] = st.readers[n - 1];
                    st.readers[n - 1] = (0, 0);
                    st.nreaders = n - 1;
                    if st.nreaders == 0 && st.writers_waiting > 0 {
                        wake = RwWake::Writer;
                    } else if n == MAX_READERS && st.readers_waiting > 0 {
                        wake = RwWake::Readers; // a slot became free
                    }
                }
                (l, wake)
            }
        };
        l.wake(wake);
    }
}

// A KRwLock can be part of a heap object (a mounted and
// unmounted ramfs) – on drop it is removed from the statistics registry.
impl Drop for KRwLock {
    fn drop(&mut self) {
        let me = self as *const KRwLock as usize;
        for slot in NAMED_RW.iter() {
            let _ = slot.compare_exchange(me, 0, Ordering::AcqRel, Ordering::Relaxed);
        }
    }
}
