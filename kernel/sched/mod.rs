// Scheduler – kernel tasks, preemptive round-robin.
//
// * Task = its own stack (stack.rs, with a guard page) + a saved RSP.
//   A switch (`sched_switch`) pushes the callee-saved registers
//   (rbx, rbp, r12–r15) onto the stack, saves RSP and loads another task's
//   RSP.  The remaining registers are already saved by the compiler (ordinary
//   call) or by isr_common (interrupt).
// * Task 1 ("kernel") is the boot thread – it runs on the stack from DSB and after
//   the self-tests becomes the shell.  Task 0 ("idle") executes `hlt` when nobody
//   else is ready, and cleans up finished tasks.
// * Preemption: the PIT tick (on_tick) counts down the QUANTUM_TICKS quantum and wakes
//   sleeping tasks; the switch happens in irq::dispatch AFTER sending EOI
//   (`preempt`).  A task woken by an interrupt (keyboard, disk)
//   gets the CPU right after that interrupt.
// * All scheduler state changes with interrupts disabled.  On
//   multiple cores, exclusivity is additionally provided by the Big Kernel Lock (bkl.rs) –
//   kernel code, including the scheduler, runs on one CPU at a time.
// * Each CPU has its own `current`, quantum and idle task (pinned to
//   it); ordinary tasks take any free CPU (shared list).
// * FPU/SSE: the kernel is soft-float; the x87/SSE state of user processes
//   is saved/restored by schedule() (FXSAVE/FXRSTOR, arch/fpu.rs).

pub mod bkl;
// Per-CPU helpers; first users: the frame allocator and the heap.
#[allow(dead_code)]
pub mod spin;
pub mod stack;
pub mod sync;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::arch::global_asm;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::arch::x86_64::fpu::{self, FxState};
use crate::arch::x86_64::interrupts::{self, without_interrupts};
use crate::serial_println;
use stack::TaskStack;

pub type TaskId = u64;

pub const IDLE_ID: TaskId = 0;
pub const BOOT_ID: TaskId = 1;

/// Time quantum in ticks (1 tick = 1 ms).
pub const QUANTUM_TICKS: u32 = 10;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Ready,
    Running,
    Blocked,
    Dead,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Ready => "ready",
            State::Running => "running",
            State::Blocked => "blocked",
            State::Dead => "dead",
        }
    }
}

struct Task {
    id: TaskId,
    name: String,
    state: State,
    rsp: u64,
    stack: Option<TaskStack>, // None = boot stack (task 1) / idle
    wait_channel: usize,      // 0 = sleep without a queue
    wake_at: u64,             // wake-up tick (u64::MAX = no limit)
    /// Counts ticks of the CPU the task runs on – lock-free.
    cpu_ticks: AtomicU64,
    switches: u64,
    exit_requested: bool,
    /// User process (address space, file
    /// descriptors); None = kernel task (kernel CR3).
    process: Option<Box<crate::user::Process>>,
    /// The process's x87/SSE registers while it is not running (FXSAVE).
    fpu: FxState,
    /// Idle task of the processor with this number (pinned to it).
    idle_cpu: Option<u8>,
    /// Last CPU it ran on, and the mask of all CPUs it has used.
    last_cpu: u8,
    cpu_mask: u16,
    /// Scheduler lock depth at the moment of the switch (the task,
    /// on return, releases as many levels as it had – the lock belongs to the CPU).
    sched_depth: u32,
    /// TSC cycles of CPU time (from scheduler exit to scheduler entry, always
    /// measured on a single CPU – core TSCs are not synchronized on some machines).
    run_tsc: AtomicU64,
    /// The task gave up the BKL at a switch (schedule) – it will take it
    /// back after leaving the scheduler (`after_switch`).
    bkl_dropped: bool,
    /// It is in the ready queue (`Scheduler::ready`).
    queued: bool,
    /// List links embedded in the task (no allocation under the scheduler
    /// lock): ready queue, channel bucket, deadline list,
    /// id bucket.
    rq: Link,
    wq: Link,
    sq: Link,
    in_sleepers: bool,
    id_next: *mut Task,
    /// Mirror of `state == Dead` for readers under the task-table lock
    /// (without the scheduler lock – `state` changes under it).
    dead: AtomicBool,
    /// The task is (still) on some CPU – from being picked by
    /// schedule() until the CPU leaving it finishes the
    /// switch (registers and FPU saved, stack abandoned).  Another CPU will not
    /// switch to a task with this flag set, and reap will not free it.
    on_cpu: AtomicBool,
    /// Liveness marker (tests: a freed task seen by a
    /// table reader = TASK_FREED).
    magic: AtomicU64,
}

const TASK_MAGIC: u64 = 0x7a5c_7a5c_7a5c_7a5c;
const TASK_FREED: u64 = 0xdead_dead_dead_dead;

impl Drop for Task {
    fn drop(&mut self) {
        self.magic.store(TASK_FREED, Ordering::SeqCst);
    }
}

/// Doubly linked list link (pointers to Box<Task>).
#[derive(Clone, Copy)]
struct Link {
    prev: *mut Task,
    next: *mut Task,
}

impl Link {
    const NONE: Link = Link { prev: core::ptr::null_mut(), next: core::ptr::null_mut() };
}

/// Doubly linked list of tasks (`link` selects the link).
#[derive(Clone, Copy)]
struct TList {
    head: *mut Task,
    tail: *mut Task,
    len: usize,
}

impl TList {
    const EMPTY: TList = TList { head: core::ptr::null_mut(), tail: core::ptr::null_mut(), len: 0 };

    fn push_back(&mut self, p: *mut Task, link: fn(&mut Task) -> &mut Link) {
        *link(tm(p)) = Link { prev: self.tail, next: core::ptr::null_mut() };
        if self.tail.is_null() {
            self.head = p;
        } else {
            link(tm(self.tail)).next = p;
        }
        self.tail = p;
        self.len += 1;
    }

    fn remove(&mut self, p: *mut Task, link: fn(&mut Task) -> &mut Link) {
        let l = *link(tm(p));
        if l.prev.is_null() {
            self.head = l.next;
        } else {
            link(tm(l.prev)).next = l.next;
        }
        if l.next.is_null() {
            self.tail = l.prev;
        } else {
            link(tm(l.next)).prev = l.prev;
        }
        *link(tm(p)) = Link::NONE;
        self.len -= 1;
    }

    fn pop_front(&mut self, link: fn(&mut Task) -> &mut Link) -> Option<*mut Task> {
        let p = self.head;
        if p.is_null() {
            return None;
        }
        self.remove(p, link);
        Some(p)
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.head.is_null()
    }
}

fn rq_link(t: &mut Task) -> &mut Link {
    &mut t.rq
}
fn wq_link(t: &mut Task) -> &mut Link {
    &mut t.wq
}
fn sq_link(t: &mut Task) -> &mut Link {
    &mut t.sq
}

const WAIT_BUCKETS: usize = 256;
const ID_BUCKETS: usize = 1024;

fn wait_bucket(channel: usize) -> usize {
    ((channel >> 3) ^ (channel >> 11) ^ (channel >> 19)) % WAIT_BUCKETS
}

impl Task {
    /// Top of the task's kernel stack (TSS.RSP0, when the task is in ring 3).
    fn kernel_stack_top(&self) -> u64 {
        match &self.stack {
            Some(st) => st.top(),
            None => crate::memory::kernel_layout().stack_top,
        }
    }

    fn cr3(&self) -> u64 {
        match &self.process {
            Some(p) => p.space.cr3(),
            None => crate::memory::kernel_cr3(),
        }
    }
}

/// Task information (for `ps` and tests).
#[derive(Clone)]
pub struct TaskInfo {
    pub id: TaskId,
    pub name: String,
    pub state: State,
    pub cpu_ticks: u64,
    pub switches: u64,
    #[allow(dead_code)]
    pub stack_top: u64,
    /// User process (ring 3, its own address space).
    pub user: bool,
    /// Parent of the process (0 = kernel; kernel tasks also 0).
    pub ppid: TaskId,
    /// CPU it is running on now (None = not running) / ran on last.
    pub cpu: Option<usize>,
    pub last_cpu: usize,
    /// Mask of CPUs the task has ever run on.
    #[allow(dead_code)]
    pub cpu_mask: u16,
}

use crate::arch::x86_64::cpu::MAX_CPUS;

/// Current task on a CPU where nothing is running (not started yet).
const NO_TASK: TaskId = u64::MAX;

struct Scheduler {
    tasks: Vec<Box<Task>>,
    /// Current task of each CPU.
    current: [TaskId; MAX_CPUS],
    next_id: TaskId,
    /// Idle task of each CPU (NO_TASK = CPU not started).
    idle: [TaskId; MAX_CPUS],
    // Dedicated structures instead of scanning the whole task list under the
    // scheduler lock (previously 65% of acquisitions waited, 232 s in total – every
    // schedule / wake-up / tick scanned all tasks).  Pointers
    // to Box<Task> (address stable until reap; a queued task is never
    // dead, so reap does not invalidate them).
    // Lists embedded in tasks and bucket arrays – no
    // allocation under the scheduler lock (an earlier version with BTreeMap/Vec allocated on
    // every sleep and wake-up – under the heap lock, with IF = 0: 79%
    // waiting, 335 s).
    /// Ready tasks (state Ready, not idle) – FIFO, round-robin.
    ready: TList,
    /// Task by id: buckets (id % ID_BUCKETS), chain `id_next`.
    ids: [*mut Task; ID_BUCKETS],
    /// Sleeping on a channel (WaitQueue): buckets by channel address.
    waiters: [TList; WAIT_BUCKETS],
    /// Sleeping with a deadline (the tick scans only these).
    sleepers: TList,
}

static mut SCHED: Scheduler = Scheduler {
    tasks: Vec::new(),
    current: [NO_TASK; MAX_CPUS],
    next_id: 2,
    idle: [NO_TASK; MAX_CPUS],
    ready: TList::EMPTY,
    ids: [core::ptr::null_mut(); ID_BUCKETS],
    waiters: [TList::EMPTY; WAIT_BUCKETS],
    sleepers: TList::EMPTY,
};
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// Address of each CPU's current task structure (Box<Task> – the address
/// is stable, the task is not freed while it is current anywhere).
/// BKL-free paths (getpid/uptime/write syscalls) read their task
/// and process from here instead of from the task list (which changes under the BKL).
static CUR_TASK: crate::arch::x86_64::percpu::PerCpu<core::sync::atomic::AtomicUsize> = crate::per_cpu!(core::sync::atomic::AtomicUsize::new(0));

fn publish_current(s: &Scheduler, c: usize) {
    let addr = index_of(s, s.current[c]).map(|i| &*s.tasks[i] as *const Task as usize).unwrap_or(0);
    CUR_TASK[c].store(addr, Ordering::Release);
}

/// Current task of this CPU without the BKL.  Call with IF = 0 (otherwise
/// the task could migrate between reading the CPU number and the pointer).
fn current_task_unlocked() -> Option<&'static Task> {
    debug_assert!(!crate::arch::x86_64::interrupts::are_enabled());
    let a = CUR_TASK[cpu()].load(Ordering::Acquire);
    (a != 0).then(|| unsafe { &*(a as *const Task) })
}

/// (id, process) of the current task without the BKL – for BKL-free syscalls.
/// A process is single-threaded: its descriptors and memory are changed only by itself
/// (in syscalls), so its own process may be read without a lock.  With IF = 0.
pub fn current_unlocked() -> Option<(TaskId, &'static mut crate::user::Process)> {
    let t = current_task_unlocked()?;
    let id = t.id;
    let p: *const crate::user::Process = t.process.as_deref()?;
    Some((id, unsafe { &mut *(p as *mut crate::user::Process) }))
}

/// `kill` / Ctrl+C for the current task – without the BKL (reads a flag
/// set by another CPU under the BKL).  With IF = 0.
pub fn should_exit_unlocked() -> bool {
    match current_task_unlocked() {
        Some(t) => unsafe { core::ptr::read_volatile(&t.exit_requested) },
        None => false,
    }
}

/// Tick at the previous on_tick (BSP).
static LAST_BSP_TICK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static NEED_RESCHED: crate::arch::x86_64::percpu::PerCpu<AtomicBool> = crate::per_cpu!(AtomicBool::new(false));

#[inline]
fn cpu() -> usize {
    crate::arch::x86_64::cpu::id()
}

/// Current task of this CPU.
#[inline]
fn cur_id(s: &Scheduler) -> TaskId {
    s.current[cpu()]
}
static TOTAL_SWITCHES: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();

/// Access to the state: only with interrupts disabled.
fn sched() -> &'static mut Scheduler {
    debug_assert!(!interrupts::are_enabled());
    // Task list and scheduler state only under the scheduler lock
    // (the BKL is no longer needed).
    assert!(sched_lock_held(), "sched: task list touched on CPU {} without the scheduler lock", cpu());
    unsafe { &mut *core::ptr::addr_of_mut!(SCHED) }
}

// ------------------------------------------------------------
// Task table under its own RW lock
// ------------------------------------------------------------
//
// `tasks` + `ids` (the task list and id buckets) change under the scheduler
// lock AND the write side of this lock (add: spawn, idle, init; remove:
// reap).  Readers that only need "task with id X and its process"
// (with_process, task_exists, children_of, for_each_process) take only this lock
// for reading – in parallel, without the scheduler lock (with_process used to take
// the scheduler lock ~11 million times per minute).  reparent_with –
// write side (excludes with_process as the scheduler lock used to).
// * Order: scheduler -> table.  Readers / reparent do NOT take the scheduler
//   lock while holding the table.
// * Always with IF = 0 (readers too): a writer holds the scheduler lock with
//   IF = 0 and waits for readers – a reader interrupted by a wake-up
//   (wake_channel -> scheduler lock) would deadlock with it.
// * A task lives as long as it is in the table (reap removes it under the write lock), so
//   a reference obtained while reading is valid until the lock is released.  Readers do not
//   see `state` – only the `dead` mirror.
static TABLE: spin::RwSpinLock = spin::RwSpinLock::new("task table");

/// Scheduler state for reading the task table (only `tasks`, `ids` and
/// immutable or atomic task fields) – under `TABLE` with IF = 0.
/// (tests) Tasks with a bad marker seen under the table lock.
static TABLE_BAD: AtomicU64 = AtomicU64::new(0);

#[cfg_attr(not(selftest), allow(dead_code))]
pub fn table_bad() -> u64 {
    TABLE_BAD.load(Ordering::Relaxed)
}

/// Checks the marker of a task found in the table (in builds with
/// self-tests: with a spin delay, so that freeing without the table lock has a
/// window in which the test catches it).
#[inline]
fn table_check(t: &Task) {
    #[cfg(selftest)]
    for _ in 0..64 {
        core::hint::spin_loop();
    }
    if t.magic.load(Ordering::SeqCst) != TASK_MAGIC {
        TABLE_BAD.fetch_add(1, Ordering::Relaxed);
    }
}

fn table() -> &'static Scheduler {
    debug_assert!(!interrupts::are_enabled());
    debug_assert!(TABLE.state() != (false, 0), "task table read without its lock");
    unsafe { &*core::ptr::addr_of!(SCHED) }
}

// ------------------------------------------------------------
// Scheduler lock
// ------------------------------------------------------------
//
// One lock for the task list and scheduler state (current, idle, quantum).
// It originally lived alongside the BKL; now it stands alone (the scheduler does not need the BKL).
//
// BKL at a switch (like release/reacquire_kernel_lock in Linux
// 2.x): a task that holds the BKL and GIVES UP the CPU (schedule switches) releases
// it right before the switch (releasing under the scheduler lock is allowed –
// waiting for the BKL is not) and takes it back after leaving the scheduler, when
// it no longer holds the scheduler lock (`after_switch`).  When schedule() does not
// switch (condition met, no other tasks), the BKL stays – code under the
// BKL does not lose it "along the way".  A new task takes the BKL at start
// (sched_new_task_start), as before.
//
// * Recursive on the same CPU (wake_channel -> kick, sleep_until ->
//   block_current -> schedule), always with IF = 0 (it is also taken by the timer
//   interrupt and by wake-ups from interrupts).
// * It is NO LONGER held across the switch – schedule()
//   releases it after picking the next task, and the task on the CPU is protected by the
//   `on_cpu` flag (see finish_switch); guards taken before the switch release nothing
//   when the task returns (SCHED_SKIP).  Earlier design, for reference:
// * It belonged to the CPU, not to the task, and was held ACROSS the switch:
//   schedule() took it in the old task, and the new task released it (after returning
//   from its own schedule() or in sched_new_task_start).  Thanks to that no
//   other CPU would take the old task before its registers were saved.
//   The per-CPU depth was saved in the task at the switch
//   (Task::sched_depth) and restored on return – each task released
//   as many levels as it had taken itself.
// * Order: BKL -> scheduler lock -> heap / frames (allocations under it
//   are allowed).  While holding it one must not WAIT for the BKL (releasing is fine) nor
//   for a KMutex, do a TLB shootdown (task stacks are freed after releasing it)
//   nor sleep.
// * Outside lockdep (like the TLB and console locks): recursion and crossing
//   task switches are intentional here.

/// Owner (CPU number + 1; 0 = free) and per-CPU depth.
/// In its own cache line (the hottest lock in the kernel).
static SCHED_OWNER: crate::arch::x86_64::percpu::CacheLine<core::sync::atomic::AtomicU32> =
    crate::arch::x86_64::percpu::CacheLine(core::sync::atomic::AtomicU32::new(0));
static SCHED_DEPTH: crate::arch::x86_64::percpu::PerCpu<core::sync::atomic::AtomicU32> = crate::per_cpu!(core::sync::atomic::AtomicU32::new(0));
/// Statistics: acquisitions (first level), acquisitions with waiting, µs of waiting.
static SCHED_ACQ: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static SCHED_CONT: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static SCHED_WAIT_US: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
/// Diagnostics: the longest single wait for the
/// scheduler lock (µs), the location of that wait, how many waits > 100 µs, how many
/// waits from interrupts (on_tick, wake-up from IRQ) and the longest of them.
static SCHED_WAIT_MAX: AtomicU64 = AtomicU64::new(0);
static SCHED_WAIT_MAX_SITE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static SCHED_WAIT_LONG: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static SCHED_WAIT_IRQ_MAX: AtomicU64 = AtomicU64::new(0);

/// (longest wait µs, its location, waits > 100 µs, longest in interrupt µs).
pub fn sched_wait_extremes() -> (u64, &'static str, u64, u64) {
    let site = SCHED_WAIT_MAX_SITE.load(Ordering::Relaxed);
    let name: &'static str = if site == 0 { "-" } else { unsafe { *(site as *const &'static str) } };
    (SCHED_WAIT_MAX.load(Ordering::Relaxed), name, SCHED_WAIT_LONG.get(), SCHED_WAIT_IRQ_MAX.load(Ordering::Relaxed))
}
/// Who takes the scheduler lock (file:line), waiting and holding times.
static SCHED_SITES: bkl::SiteTable = bkl::SiteTable::new();
/// Entry (+1) and acquisition TSC on this CPU (released by the same CPU – IF = 0).
static SCHED_HOLD_SLOT: crate::arch::x86_64::percpu::PerCpu<core::sync::atomic::AtomicUsize> = crate::per_cpu!(core::sync::atomic::AtomicUsize::new(0));
static SCHED_HOLD_TSC: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));

/// Switches outside the scheduler lock and waits for `on_cpu`
/// (the picked task was still leaving another CPU): count, TSC ticks.
static SWITCH_N: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static ONCPU_WAITS: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static ONCPU_TSC: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
/// The task this CPU is just leaving (the next task clears its `on_cpu`
/// as the first thing it does – `finish_switch`).
static PREV_TASK: crate::arch::x86_64::percpu::PerCpu<core::sync::atomic::AtomicUsize> = crate::per_cpu!(core::sync::atomic::AtomicUsize::new(0));
/// Scheduler lock guards taken BEFORE the switch by the
/// task that has just returned – the lock is already released (schedule
/// releases it before switching), so their Drop releases nothing.
static SCHED_SKIP: crate::arch::x86_64::percpu::PerCpu<core::sync::atomic::AtomicU32> = crate::per_cpu!(core::sync::atomic::AtomicU32::new(0));

/// (switches, waits for on_cpu, µs of those waits) – `cpus`.
pub fn switch_stats() -> (u64, u64, u64) {
    let per_ms = crate::arch::x86_64::lapic::tsc_per_ms().max(1);
    (SWITCH_N.get(), ONCPU_WAITS.get(), ONCPU_TSC.get() * 1000 / per_ms)
}

/// After a switch (new task, IF = 0, without the scheduler lock) –
/// this CPU's previous task is already saved: clears `on_cpu` (from now on
/// another CPU may run it, and reap may free it).  `skip` – how many scheduler lock
/// guards this task took before its own switch.
fn finish_switch(skip: u32) {
    let c = cpu();
    SCHED_SKIP[c].store(skip, Ordering::Relaxed);
    let prev = PREV_TASK[c].swap(0, Ordering::Relaxed);
    if prev != 0 {
        unsafe { (*(prev as *const Task)).on_cpu.store(false, Ordering::Release) };
    }
}

fn sched_hold_end(me: usize) {
    let slot = SCHED_HOLD_SLOT[me].swap(0, Ordering::Relaxed);
    if slot != 0 {
        let d = bkl::rdtsc().wrapping_sub(SCHED_HOLD_TSC[me].load(Ordering::Relaxed));
        if d < 1 << 48 {
            SCHED_SITES.entry(slot - 1).hold_tsc.fetch_add(d, Ordering::Relaxed);
        }
    }
}

/// Scheduler lock acquisition sites (`cpus`, autostress) and untracked acquisitions.
pub fn sched_lock_sites() -> (alloc::vec::Vec<bkl::SiteInfo>, u64) {
    (SCHED_SITES.stats(), SCHED_SITES.overflow())
}

/// After this many µs of waiting for the scheduler lock – report (sections last µs).
const SCHED_REPORT_US: u64 = 2_000_000;

fn sched_lock_held() -> bool {
    SCHED_OWNER.load(Ordering::Relaxed) == cpu() as u32 + 1
}

/// Guard of the (recursive) scheduler lock.  Released on the CPU
/// the task is on at release time (after a switch it may be a different one).
struct SchedGuard {
    irq: bool,
}

#[must_use]
fn lock_sched_at(site: &'static &'static str) -> SchedGuard {
    let irq = interrupts::are_enabled();
    interrupts::disable();
    let me = cpu();
    let tag = me as u32 + 1;
    assert!(
        SCHED_SKIP[me].load(Ordering::Relaxed) == 0,
        "sched: scheduler lock taken on CPU {} before the guards from before a task switch were dropped",
        me
    );
    if SCHED_OWNER.load(Ordering::Relaxed) == tag {
        SCHED_DEPTH[me].fetch_add(1, Ordering::Relaxed);
        return SchedGuard { irq };
    }
    SCHED_ACQ.add(1);
    let slot = SCHED_SITES.slot_for(bkl::tag_key(site));
    if let Some(i) = slot {
        SCHED_SITES.entry(i).taken.fetch_add(1, Ordering::Relaxed);
    }
    if SCHED_OWNER.compare_exchange(0, tag, Ordering::Acquire, Ordering::Relaxed).is_err() {
        SCHED_CONT.add(1);
        // TSC (IF = 0 – same CPU), not HPET – reading it after taking
        // the lock lengthened the hold time.
        // Statistics – this CPU's TSC (IF = 0); the long-wait
        // report – HPET (TSC can be unreliable), read every 4096 spins.
        let (tsc0, cpu0) = crate::arch::x86_64::clock::tsc_cpu();
        let mut start = 0u64;
        let mut n: u32 = 0;
        let mut reported = false;
        // Wait by READING only (test-and-test-and-set) – an acquisition attempt
        // (atomic instruction) only when the lock looks free.
        // Previously every loop iteration was a compare_exchange: 15 waiting CPUs
        // kept stealing the cache line holding the lock from each other and from the holder
        // – the holder released it more slowly (41% of acquisitions
        // waited, 18.9 s).  Ordinary spinlocks (spin.rs) already wait this way.
        loop {
            if SCHED_OWNER.load(Ordering::Relaxed) == 0
                && SCHED_OWNER.compare_exchange_weak(0, tag, Ordering::Acquire, Ordering::Relaxed).is_ok()
            {
                break;
            }
            core::hint::spin_loop();
            n = n.wrapping_add(1);
            if n % 64 == 0 {
                crate::arch::x86_64::tlb::poll_from_wait();
            }
            if n % 4096 == 0 {
                crate::arch::x86_64::smp::watchdog_poll();
                if start == 0 {
                    start = crate::arch::x86_64::clock::stamp().max(1);
                }
                let waited = crate::arch::x86_64::clock::elapsed_us(start);
                if !reported && waited > SCHED_REPORT_US {
                    reported = true;
                    serial_println!(
                        "[SCHED] CPU {} waits {} ms for the scheduler lock, held by CPU {}",
                        me,
                        waited / 1000,
                        SCHED_OWNER.load(Ordering::Relaxed) as i64 - 1
                    );
                }
            }
        }
        let waited = crate::arch::x86_64::clock::tsc_wait_us(tsc0, cpu0);
        SCHED_WAIT_US.add(waited);
        if waited > 100 {
            SCHED_WAIT_LONG.add(1);
        }
        if waited > SCHED_WAIT_MAX.fetch_max(waited, Ordering::Relaxed) {
            SCHED_WAIT_MAX_SITE.store(site as *const &'static str as usize, Ordering::Relaxed);
        }
        if crate::arch::x86_64::cpu::in_interrupt() {
            SCHED_WAIT_IRQ_MAX.fetch_max(waited, Ordering::Relaxed);
        }
        if let Some(i) = slot {
            SCHED_SITES.entry(i).waited.fetch_add(1, Ordering::Relaxed);
            SCHED_SITES.entry(i).wait_us.fetch_add(waited, Ordering::Relaxed);
        }
    }
    SCHED_DEPTH[me].store(1, Ordering::Relaxed);
    SCHED_HOLD_SLOT[me].store(slot.map_or(0, |i| i + 1), Ordering::Relaxed);
    SCHED_HOLD_TSC[me].store(bkl::rdtsc(), Ordering::Relaxed);
    SchedGuard { irq }
}

impl Drop for SchedGuard {
    fn drop(&mut self) {
        let me = cpu();
        // Guard from before the switch – schedule() has already released the lock.
        let skip = SCHED_SKIP[me].load(Ordering::Relaxed);
        if skip > 0 {
            SCHED_SKIP[me].store(skip - 1, Ordering::Relaxed);
            if self.irq {
                interrupts::enable();
            }
            return;
        }
        debug_assert!(sched_lock_held(), "scheduler lock released by a CPU that does not hold it");
        if SCHED_DEPTH[me].fetch_sub(1, Ordering::Relaxed) == 1 {
            sched_hold_end(me);
            SCHED_OWNER.store(0, Ordering::Release);
        }
        if self.irq {
            interrupts::enable();
        }
    }
}

/// First entry of a new task (task_trampoline, IF = 0): the scheduler lock
/// taken by the previous task's schedule() – release all of it.
#[unsafe(no_mangle)]
extern "sysv64" fn sched_new_task_start() {
    // The scheduler lock is already free (schedule() releases it before the
    // switch); only the previous task gets its `on_cpu` cleared.
    finish_switch(0);
    // The task starts with the BKL (kernel tasks run under the BKL,
    // processes give it up in enter_user) – the previous task gave it up at the
    // switch.  Only AFTER releasing the scheduler lock (ordering).
    // A user process starts without the BKL – its entry
    // (user_task_entry -> enter_user) reads only its own process and immediately
    // jumps to ring 3 (previously: take the BKL only to release it a moment later –
    // hundreds of thousands of times under stress).
    let user = current_task_unlocked().is_some_and(|t| t.process.is_some());
    if !user {
        bkl::acquire_if_needed_tagged(&bkl::tag::NEW_TASK);
    }
}

/// After leaving the scheduler (without the scheduler lock) – if this
/// task gave up the BKL at the switch, it takes it back.  Called by:
/// wait_event, sleep_until, yield_now, preempt.
fn after_switch(why: &'static &'static str) {
    without_interrupts(|| {
        debug_assert!(!sched_lock_held(), "after_switch with the scheduler lock held");
        let a = CUR_TASK[cpu()].load(Ordering::Acquire);
        if a == 0 {
            return;
        }
        let t = unsafe { &mut *(a as *mut Task) };
        if t.bkl_dropped {
            t.bkl_dropped = false;
            bkl::acquire_if_needed_tagged(why);
        }
    });
}

/// "Gave up the BKL" flag of the current task – clear / set (IF = 0,
/// own task only; preempt saves the flag of the interrupted context).
fn take_bkl_dropped() -> bool {
    let a = CUR_TASK[cpu()].load(Ordering::Acquire);
    if a == 0 {
        return false;
    }
    let t = unsafe { &mut *(a as *mut Task) };
    core::mem::replace(&mut t.bkl_dropped, false)
}

fn set_bkl_dropped(v: bool) {
    let a = CUR_TASK[cpu()].load(Ordering::Acquire);
    if a != 0 {
        unsafe { (*(a as *mut Task)).bkl_dropped = v };
    }
}

/// Waits on channel `channel` until `cond()` is true or tick
/// `deadline` passes – checking the condition and going to sleep happen under the scheduler lock,
/// and the wake-up (wake_channel) takes it too, so a wake-up from another CPU is not
/// lost (previously the BKL guaranteed this).  `cond` runs with IF = 0 under
/// the scheduler lock: only atomics / short reads, no KMutex or BKL.
/// Requires the scheduler and a task that may sleep (sync::WaitQueue checks).
pub fn wait_event(channel: usize, deadline: u64, cond: &mut dyn FnMut() -> bool) -> bool {
    let had_bkl = bkl::held();
    let result = loop {
        let woke_or_timeout = without_interrupts(|| {
            let _g = lock_sched_at(&"wait_event");
            if cond() {
                return Some(true);
            }
            if crate::time::ticks() >= deadline {
                return Some(false);
            }
            block_current(channel, deadline);
            None
        });
        after_switch(&bkl::tag::AFTER_WAIT);
        if let Some(r) = woke_or_timeout {
            break r;
        }
    };
    // Invariant: whoever waited holding the BKL returns holding the BKL (see preempt).
    if had_bkl && !bkl::held() {
        let flag = without_interrupts(|| {
            let a = CUR_TASK[cpu()].load(Ordering::Acquire);
            a != 0 && unsafe { (*(a as *const Task)).bkl_dropped }
        });
        panic!(
            "wait_event returned without the BKL on CPU {} (task {}, flag {}, bkl {:?}, site {:?})",
            cpu(),
            current_id(),
            flag,
            bkl::state(),
            bkl::owner_site()
        );
    }
    result
}

/// Tests: (scheduler lock owner: CPU number + 1, depth on this CPU).
#[allow(dead_code)]
pub fn sched_lock_state() -> (u32, u32) {
    without_interrupts(|| (SCHED_OWNER.load(Ordering::Relaxed), SCHED_DEPTH[cpu()].load(Ordering::Relaxed)))
}

/// (acquisitions, acquisitions with waiting, µs of waiting) of the scheduler lock – `cpus`.
pub fn sched_lock_stats() -> (u64, u64, u64) {
    (SCHED_ACQ.get(), SCHED_CONT.get(), SCHED_WAIT_US.get())
}

/// Without checking the BKL – only error reports (panic, watchdog), which must
/// not wait for the BKL.
fn sched_raw() -> &'static Scheduler {
    unsafe { &*core::ptr::addr_of!(SCHED) }
}

fn index_of(s: &Scheduler, id: TaskId) -> Option<usize> {
    s.tasks.iter().position(|t| t.id == id)
}

// ------------------------------------------------------------
// Scheduler queues (everything under the scheduler lock)
// ------------------------------------------------------------

#[inline]
fn tm(p: *mut Task) -> &'static mut Task {
    unsafe { &mut *p }
}

/// Task by id (bucket – a few comparisons).
fn find(s: &Scheduler, id: TaskId) -> Option<*mut Task> {
    let mut p = s.ids[(id as usize) % ID_BUCKETS];
    while !p.is_null() {
        if tm(p).id == id {
            return Some(p);
        }
        p = tm(p).id_next;
    }
    None
}

fn id_insert(s: &mut Scheduler, p: *mut Task) {
    let b = (tm(p).id as usize) % ID_BUCKETS;
    tm(p).id_next = s.ids[b];
    s.ids[b] = p;
}

fn id_remove(s: &mut Scheduler, p: *mut Task) {
    let b = (tm(p).id as usize) % ID_BUCKETS;
    let mut cur: *mut *mut Task = &mut s.ids[b];
    unsafe {
        while !(*cur).is_null() {
            if *cur == p {
                *cur = tm(p).id_next;
                tm(p).id_next = core::ptr::null_mut();
                return;
            }
            cur = &mut tm(*cur).id_next;
        }
    }
}

/// New task onto the list (and into the ready queue, if ready).
fn add_task(s: &mut Scheduler, mut t: Box<Task>) {
    let p: *mut Task = &mut *t;
    {
        let _t = TABLE.write();
        s.tasks.push(t);
        id_insert(s, p);
    }
    enqueue(s, p);
}

/// Into the ready queue (Ready only, not idle, no duplicates).
fn enqueue(s: &mut Scheduler, p: *mut Task) {
    let t = tm(p);
    if t.state == State::Ready && t.idle_cpu.is_none() && !t.queued {
        t.queued = true;
        s.ready.push_back(p, rq_link);
        READY_N.store(s.ready.len, Ordering::Relaxed);
    }
}

/// Removal from the ready queue (if present).
fn dequeue(s: &mut Scheduler, p: *mut Task) {
    if tm(p).queued {
        tm(p).queued = false;
        s.ready.remove(p, rq_link);
        READY_N.store(s.ready.len, Ordering::Relaxed);
    }
}

/// Sleeping -> ready: removal from the channel bucket and from the deadline list.
fn unblock(s: &mut Scheduler, p: *mut Task) {
    let t = tm(p);
    if t.state != State::Blocked {
        return;
    }
    if t.wait_channel != 0 {
        s.waiters[wait_bucket(t.wait_channel)].remove(p, wq_link);
    }
    if t.in_sleepers {
        t.in_sleepers = false;
        s.sleepers.remove(p, sq_link);
    }
    t.state = State::Ready;
    t.wait_channel = 0;
    t.wake_at = u64::MAX;
    enqueue(s, p);
}


// ------------------------------------------------------------
// Context switching
// ------------------------------------------------------------

global_asm!(r#"
    .section .text
    .global sched_switch
    // rdi = &mut u64 (where to save the current task's RSP), rsi = new task's RSP
    sched_switch:
        push rbp
        push rbx
        push r12
        push r13
        push r14
        push r15
        mov [rdi], rsp
        mov rsp, rsi
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        ret

    .global task_trampoline
    // First entry into a new task: r12 = function, rbx = argument.
    task_trampoline:
        // A new task starts in the middle of the previous task's schedule() –
        // the scheduler lock is held; release it before enabling IF.
        call sched_new_task_start
        mov rdi, r12
        mov rsi, rbx
        sti
        call task_main
        ud2
"#);

unsafe extern "sysv64" {
    fn sched_switch(old_rsp: *mut u64, new_rsp: u64);
    fn task_trampoline();
}

#[unsafe(no_mangle)]
extern "sysv64" fn task_main(entry: usize, arg: usize) -> ! {
    let f: fn(usize) = unsafe { core::mem::transmute(entry) };
    f(arg);
    exit()
}

/// Picks the next task and switches.  Call with interrupts disabled.
fn schedule() {
    // Never on an IST stack (an exception handler on an IST stack must not sleep
    // or switch tasks – see gdt::on_ist_stack).
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    assert!(
        !crate::arch::x86_64::gdt::on_ist_stack(rsp),
        "sched: task switch on an IST stack (rsp {:#x}) - exception handler tried to block",
        rsp
    );
    // A switch (sleep, yield) while holding a spinlock = deadlock, if
    // the next task on this CPU wants the same lock.
    assert!(
        spin::held_count() == 0,
        "sched: task switch on CPU {} while holding {} spinlock(s), first {:?}",
        cpu(),
        spin::held_count(),
        spin::first_held()
    );
    // Without the BKL – only the scheduler lock.
    // Raw TSC: no migration inside schedule(), and CUR_TASK changes midway.
    let t_prof = idle_tsc();
    let _g = lock_sched_at(&"schedule");
    let s = sched();
    let me = cpu();
    let Some(curp) = find(s, s.current[me]) else {
        return;
    };
    // Next one from the ready queue (FIFO) instead of scanning the list.
    let mut nextp = None;
    while let Some(p) = s.ready.pop_front(rq_link) {
        READY_N.store(s.ready.len, Ordering::Relaxed);
        let t = tm(p);
        t.queued = false;
        if t.state == State::Ready && t.idle_cpu.is_none() {
            nextp = Some(p);
            break;
        }
    }
    let cur = tm(curp);
    let nextp = match nextp {
        Some(p) => p,
        // Nothing ready: the current task keeps running if it can; otherwise idle.
        None if cur.state == State::Running => {
            QUANTUM[me].store(QUANTUM_TICKS, Ordering::Relaxed);
            return;
        }
        None => match find(s, s.idle[me]) {
            Some(p) if p != curp => p,
            _ => return,
        },
    };
    QUANTUM[me].store(QUANTUM_TICKS, Ordering::Relaxed);
    // The picked task may still be leaving another CPU (woken or
    // put back in the queue right before its switch) – wait until that CPU
    // saves its registers (it clears the flag without the scheduler lock: a few hundred ns).
    if tm(nextp).on_cpu.load(Ordering::Acquire) {
        let t0 = bkl::rdtsc();
        let mut n: u32 = 0;
        while tm(nextp).on_cpu.load(Ordering::Acquire) {
            core::hint::spin_loop();
            n = n.wrapping_add(1);
            if n % 64 == 0 {
                crate::arch::x86_64::tlb::poll_from_wait();
            }
            if n % 4096 == 0 {
                crate::arch::x86_64::smp::watchdog_poll();
            }
        }
        ONCPU_WAITS.add(1);
        ONCPU_TSC.add(bkl::rdtsc().wrapping_sub(t0) & ((1 << 48) - 1));
    }
    tm(nextp).on_cpu.store(true, Ordering::Relaxed);
    if cur.state == State::Running {
        cur.state = State::Ready;
        enqueue(s, curp); // to the end of the queue (not for idle)
    }
    let next = tm(nextp);
    next.state = State::Running;
    // End of this CPU's idleness – adjust the spin window.
    if cur.idle_cpu.is_some() && next.idle_cpu.is_none() {
        idle_feedback(me);
    }
    // Statistics: a process resumed on a different CPU than last time (SMP TEST 5).
    if next.process.is_some() && next.switches > 0 && next.last_cpu != me as u8 {
        USER_MIGRATIONS.fetch_add(1, Ordering::Relaxed);
    }
    next.switches += 1;
    next.last_cpu = me as u8;
    next.cpu_mask |= 1 << me;
    s.current[me] = next.id;
    CUR_TASK[me].store(nextp as usize, Ordering::Release);
    TOTAL_SWITCHES.add(1);
    SWITCH_N.add(1);

    // A task must not run on two CPUs – the next one is not
    // the current task of any other CPU.
    debug_assert!(
        !s.current.iter().enumerate().any(|(c, &id)| c != me && id == next.id),
        "sched: task {} is already current on another CPU",
        next.id
    );
    // State-dependent decisions – still under the lock (after releasing it another CPU
    // may change the current task's `state`, e.g. wake it).
    let save_fpu = cur.process.is_some() && cur.state != State::Dead;
    let idle_switch = (cur.idle_cpu.is_some(), next.idle_cpu.is_some());
    let cr3 = next.cr3();
    let cr3_changes = cr3 != cur.cr3();
    // The scheduler lock is released BEFORE the switch – only the queues and states
    // remained under it.  The current task is protected by `on_cpu` (nobody will
    // run or free it before the next task clears the flag in
    // finish_switch), the next one – by our `on_cpu` flag.  Guards taken by
    // the current task (depth) release nothing after it returns.
    cur.sched_depth = SCHED_DEPTH[me].load(Ordering::Relaxed);
    PREV_TASK[me].store(curp as usize, Ordering::Relaxed);
    SCHED_DEPTH[me].store(0, Ordering::Relaxed);
    sched_hold_end(me);
    SCHED_OWNER.store(0, Ordering::Release);

    // Kernel stack for interrupts from ring 3 (TSS.RSP0) and for SYSCALL
    // (per-CPU block), plus the address space.
    crate::arch::x86_64::gdt::set_rsp0(next.kernel_stack_top());
    crate::arch::x86_64::syscall::set_kernel_stack(next.kernel_stack_top());
    // FPU/SSE – save the state of the process giving up the CPU, restore the
    // state of the next one; kernel tasks run with CR0.TS = 1.
    if save_fpu {
        unsafe { fpu::save(&mut cur.fpu) };
    }
    if next.process.is_some() {
        fpu::clear_ts();
        unsafe { fpu::restore(&next.fpu) };
    } else {
        fpu::set_ts();
    }

    // CR3 only when the address space changes (earlier SMP code
    // reloaded it always).  Changes to the upper half are invalidated by TLB
    // shootdown; to the lower half – by the reload itself: a CPU leaving a process
    // always loads a different CR3, and a process runs on one CPU at a time (tlb.rs).
    if cr3_changes {
        unsafe { core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags)) };
    }

    // The BKL does not pass to the next task – we release it (we will take it
    // back in after_switch, after leaving the scheduler).
    if bkl::held() {
        bkl::release();
        cur.bkl_dropped = true;
    }
    // Time in idle (the "% idle" statistic).
    if idle_switch.0 || idle_switch.1 {
        let now = idle_tsc();
        if idle_switch.0 {
            let since = IDLE_SINCE[me].load(Ordering::Relaxed);
            if since != 0 {
                IDLE_TSC[me].fetch_add(now.wrapping_sub(since), Ordering::Relaxed);
            }
        }
        IDLE_SINCE[me].store(if idle_switch.1 { now } else { 0 }, Ordering::Relaxed);
    }
    let old: *mut u64 = &mut cur.rsp;
    let new = next.rsp;
    // Task CPU time – from its entry onto this CPU until now (both
    // TSC reads on the same CPU).
    {
        let now = idle_tsc();
        let since = SWITCHED_IN[me].swap(now, Ordering::Relaxed);
        if since != 0 && now > since {
            cur.run_tsc.fetch_add(now - since, Ordering::Relaxed);
        }
        crate::user::prof::add(crate::user::prof::CTX_SWITCH, now.saturating_sub(t_prof));
    }
    unsafe { sched_switch(old, new) };
    // We are back (possibly on a different CPU): this CPU's previous task gets
    // `on_cpu` cleared; our guards from before the switch release nothing.
    let depth = current_task_unlocked().map_or(0, |t| t.sched_depth);
    finish_switch(depth);
}

// ------------------------------------------------------------
// API
// ------------------------------------------------------------

fn idle_task(_: usize) {
    idle_loop()
}

fn new_task(id: TaskId, name: &str, stack: Option<TaskStack>, rsp: u64, state: State) -> Box<Task> {
    Box::new(Task {
        id,
        name: String::from(name),
        state,
        rsp,
        stack,
        wait_channel: 0,
        wake_at: u64::MAX,
        cpu_ticks: AtomicU64::new(0),
        switches: 0,
        exit_requested: false,
        process: None,
        fpu: FxState::initial(),
        idle_cpu: None,
        last_cpu: 0,
        cpu_mask: 0,
        sched_depth: 0,
        run_tsc: AtomicU64::new(0),
        bkl_dropped: false,
        queued: false,
        rq: Link::NONE,
        wq: Link::NONE,
        sq: Link::NONE,
        in_sleepers: false,
        id_next: core::ptr::null_mut(),
        dead: AtomicBool::new(false),
        magic: AtomicU64::new(TASK_MAGIC),
        on_cpu: AtomicBool::new(state == State::Running),
    })
}

/// Starts the scheduler: the current code becomes task 1, idle is created.
pub fn init() {
    without_interrupts(|| {
        let _g = lock_sched_at(&"init");
        let s = sched();
        let mut boot = new_task(BOOT_ID, "kernel", None, 0, State::Running);
        boot.cpu_mask = 1;
        add_task(s, boot);
        s.current[0] = BOOT_ID;
        publish_current(s, 0);
    });
    // idle via an ordinary spawn (gets its own stack), then its ID is changed to 0.
    let id = spawn("idle", idle_task, 0).expect("sched: cannot create idle task");
    without_interrupts(|| {
        let _g = lock_sched_at(&"init #2");
        let s = sched();
        if let Some(p) = find(s, id) {
            let _t = TABLE.write();
            id_remove(s, p);
            // idle never sits in the ready queue (spawn put it there)
            dequeue(s, p);
            let t = tm(p);
            t.id = IDLE_ID;
            t.idle_cpu = Some(0);
            id_insert(s, p);
        }
        s.idle[0] = IDLE_ID;
        s.next_id = id;
    });
    ACTIVE.store(true, Ordering::SeqCst);
    serial_println!(
        "[SCHED] Scheduler started: round-robin, {} ms quantum, task stacks {} KiB + guard",
        QUANTUM_TICKS,
        stack::STACK_SIZE / 1024
    );
}

pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Creates a kernel task executing `entry(arg)`.  It ends when
/// `entry` returns (or via `exit()`).
pub fn spawn(name: &str, entry: fn(usize), arg: usize) -> Result<TaskId, &'static str> {
    spawn_in(name, entry, arg, None, false)
}

/// A task with its own address space (a process).  `entry` runs
/// in ring 0 on the task's kernel stack, with the process's CR3 – and from there jumps to
/// ring 3 (user::enter_user).
pub fn spawn_user(
    name: &str,
    entry: fn(usize),
    arg: usize,
    process: Box<crate::user::Process>,
    foreground: bool,
) -> Result<TaskId, &'static str> {
    spawn_in(name, entry, arg, Some(process), foreground)
}

fn spawn_in(
    name: &str,
    entry: fn(usize),
    arg: usize,
    process: Option<Box<crate::user::Process>>,
    foreground: bool,
) -> Result<TaskId, &'static str> {
    // First reap finished tasks.  Previously only idle did this
    // – with many CPUs under load idle barely runs and dead
    // tasks (64 KiB stack + process memory) piled up into the thousands until
    // memory ran out (stress: 2308 dead tasks, "out of memory").
    if DEAD_TASKS.load(Ordering::Relaxed) > 0 {
        reap();
    }
    let stack = TaskStack::new().ok_or("out of memory for the task stack")?;
    let top = stack.top();
    // Initial frame for sched_switch (see above): r15 r14 r13 r12 rbx
    // rbp, return address = task_trampoline, 2 x 0 (alignment: after `ret`
    // RSP % 16 == 0, so `call task_main` gives correct ABI alignment).
    let frame: [u64; 9] = [
        0,                            // r15
        0,                            // r14
        0,                            // r13
        entry as usize as u64,        // r12
        arg as u64,                   // rbx
        0,                            // rbp
        task_trampoline as *const () as usize as u64,
        0,
        0,
    ];
    let rsp = top - (frame.len() as u64) * 8;
    unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), rsp as *mut u64, frame.len()) };

    let mut task = new_task(0, name, Some(stack), rsp, State::Ready);
    task.process = process;
    Ok(without_interrupts(|| {
        let _g = lock_sched_at(&"spawn_in");
        let s = sched();
        let id = s.next_id;
        s.next_id += 1;
        let mut task = task;
        task.id = id;
        add_task(s, task);
        // Process to the foreground – before the task becomes
        // visible to other CPUs (scheduler lock): it will not start before
        // Ctrl+C can see it.
        if foreground {
            crate::console::push_foreground(id);
        }
        // New task straight onto an idle CPU (if there is one).
        kick_idle(s);
        id
    }))
}

/// Yields the CPU to other ready tasks.
#[allow(dead_code)]
pub fn yield_now() {
    if !active() {
        return;
    }
    without_interrupts(|| {
        NEED_RESCHED[cpu()].store(false, Ordering::Relaxed);
        schedule();
    });
    after_switch(&bkl::tag::AFTER_YIELD);
}

/// Ends the current task (task 1 must not be ended).
pub fn exit() -> ! {
    interrupts::disable();
    let _g = lock_sched_at(&"exit");
    let s = sched();
    let cur = cur_id(s);
    assert!(
        cur != BOOT_ID && find(s, cur).map_or(true, |p| tm(p).idle_cpu.is_none()),
        "sched: kernel/idle task cannot exit"
    );
    if let Some(p) = find(s, cur) {
        tm(p).state = State::Dead;
        tm(p).dead.store(true, Ordering::Release);
        DEAD_TASKS.fetch_add(1, Ordering::Relaxed);
    }
    schedule();
    unreachable!("sched: dead task was scheduled again");
}

pub fn current_id() -> TaskId {
    if !active() {
        return BOOT_ID;
    }
    // Without the task list (it is under the BKL) – a per-CPU pointer.
    without_interrupts(|| current_task_unlocked().map(|t| t.id).unwrap_or(BOOT_ID))
}

/// Name of the current task (error reports; no allocation).
pub fn with_current_name<R>(f: impl FnOnce(TaskId, &str) -> R) -> Option<R> {
    if !active() {
        return None;
    }
    without_interrupts(|| {
        let s = sched_raw();
        let i = index_of(s, cur_id(s))?;
        Some(f(s.tasks[i].id, &s.tasks[i].name))
    })
}

/// Whether the current task may sleep (the scheduler is running and it is not idle).
pub fn can_block() -> bool {
    active() && without_interrupts(|| current_task_unlocked().is_some_and(|t| t.idle_cpu.is_none()))
}

/// Puts the current task to sleep on channel `channel` until woken or until tick
/// `deadline`.  Call with interrupts disabled (see sync::WaitQueue).
pub fn block_current(channel: usize, deadline: u64) {
    let _g = lock_sched_at(&"block_current");
    let s = sched();
    if let Some(p) = find(s, cur_id(s)) {
        let t = tm(p);
        t.state = State::Blocked;
        t.wait_channel = channel;
        t.wake_at = deadline;
        // Onto the channel list and the deadline list (wake-up without scanning).
        if channel != 0 {
            s.waiters[wait_bucket(channel)].push_back(p, wq_link);
        }
        if deadline != u64::MAX {
            t.in_sleepers = true;
            s.sleepers.push_back(p, sq_link);
            NEXT_WAKE.fetch_min(deadline, Ordering::Relaxed);
        }
    }
    schedule();
}

/// Wakes the tasks waiting on a channel (safe in interrupt context).
pub fn wake_channel(channel: usize) {
    if !active() {
        return;
    }
    // Only the scheduler lock (no BKL) – also from interrupts.
    without_interrupts(|| {
        let _g = lock_sched_at(&"wake_channel");
        let s = sched();
        if channel == 0 {
            return;
        }
        // Only this channel's bucket.
        let mut woke = 0;
        let mut p = s.waiters[wait_bucket(channel)].head;
        while !p.is_null() {
            let next = tm(p).wq.next;
            if tm(p).state == State::Blocked && tm(p).wait_channel == channel {
                unblock(s, p); // removes it from the bucket
                woke += 1;
            }
            p = next;
        }
        for _ in 0..woke.min(MAX_CPUS) {
            kick(s);
        }
    });
}

/// Wakes ONE task waiting on the channel – the one waiting longest
/// (the bucket is a FIFO queue).  `true` – one was woken.  Sleeping locks
/// hand themselves over to a single waiter this way instead of waking all of them (thundering herd:
/// all go through the scheduler, one takes the lock, the rest go back to sleep) – like
/// the mutex in Linux (first from wait_list) and WAKEUP_FIRST in HelenOS.
pub fn wake_one_channel(channel: usize) -> bool {
    if !active() || channel == 0 {
        return false;
    }
    without_interrupts(|| {
        let _g = lock_sched_at(&"wake_one_channel");
        let s = sched();
        let mut p = s.waiters[wait_bucket(channel)].head;
        while !p.is_null() {
            let next = tm(p).wq.next;
            if tm(p).state == State::Blocked && tm(p).wait_channel == channel {
                unblock(s, p);
                kick(s);
                return true;
            }
            p = next;
        }
        false
    })
}

/// Sleeps until tick `deadline` (time::sleep_* calls this once the scheduler has started).
pub fn sleep_until(deadline: u64) {
    // Without the BKL; the BKL (if held) comes back in after_switch.
    let had_bkl = bkl::held();
    without_interrupts(|| {
        while crate::time::ticks() < deadline {
            let g = lock_sched_at(&"sleep_until");
            let s = sched();
            if find(s, cur_id(s)).map(|p| tm(p).exit_requested).unwrap_or(false) {
                break; // `kill` – the task is to exit, not keep sleeping
            }
            block_current(0, deadline);
            drop(g);
        }
    });
    after_switch(&bkl::tag::AFTER_SLEEP);
    assert!(!had_bkl || bkl::held(), "sleep_until returned without the BKL on CPU {}", cpu());
}

/// Request to end a task (the task itself checks `should_exit`).
pub fn request_exit(id: TaskId) -> bool {
    if id == BOOT_ID || id == IDLE_ID {
        return false;
    }
    if without_interrupts(|| {
        let _g = lock_sched_at(&"request_exit");
        let s = sched();
        find(s, id).is_some_and(|p| tm(p).idle_cpu.is_some())
    }) {
        return false; // idle tasks (of each CPU) are never ended
    }
    without_interrupts(|| {
        let _g = lock_sched_at(&"request_exit #2");
        let s = sched();
        match find(s, id) {
            Some(p) if tm(p).state != State::Dead => {
                tm(p).exit_requested = true;
                // Wake the waiting task so it can notice (wait
                // conditions in syscalls check should_exit; others simply
                // go back to sleep).
                if tm(p).state == State::Blocked {
                    unblock(s, p);
                    kick(s);
                }
                true
            }
            _ => false,
        }
    })
}

/// Process of the current task.  Only its own task accesses the process
/// (syscalls), and the structure is in a Box – its address does not change, so
/// the reference is valid until the task ends.  Cleanup (reap) only concerns
/// finished tasks.
pub fn current_process() -> Option<&'static mut crate::user::Process> {
    if !active() {
        return None;
    }
    // Without the task list – a per-CPU pointer (works even without the BKL).
    without_interrupts(|| current_unlocked().map(|(_, p)| p))
}

/// `f` on the process of task `pid` (None: no such task, a kernel
/// task or a finished one).  With interrupts disabled – only short
/// reads of atomic / immutable fields.
pub fn with_process<R>(pid: TaskId, f: impl FnOnce(&crate::user::Process) -> R) -> Option<R> {
    if !active() {
        return None;
    }
    // Only the task table, for reading (without the scheduler lock).
    without_interrupts(|| {
        let _t = TABLE.read();
        let t = unsafe { &*find(table(), pid)? };
        table_check(t);
        if t.dead.load(Ordering::Acquire) {
            return None;
        }
        t.process.as_deref().map(f)
    })
}

/// Live processes whose parent is `ppid`.
#[allow(dead_code)]
pub fn children_of(ppid: TaskId) -> Vec<TaskId> {
    if !active() {
        return Vec::new();
    }
    let mut out = Vec::new();
    without_interrupts(|| {
        let _t = TABLE.read();
        for t in table().tasks.iter() {
            if !t.dead.load(Ordering::Acquire) {
                if let Some(p) = t.process.as_deref() {
                    if p.ppid() == ppid {
                        out.push(t.id);
                    }
                }
            }
        }
    });
    out
}

/// Children of process `from` get a new parent `to` (0 = kernel).
/// `first` (under the scheduler lock – e.g. an exiting parent sets
/// `exiting` and takes its zombies), then the live children of `from` get parent
/// `to`, and `to` – its live-children counter +n.  One section: a child exiting
/// at the same time (with_process on the parent) sees either the old
/// parent, which still accepts, or already the new one.
pub fn reparent_with(from: TaskId, to: TaskId, first: impl FnOnce()) -> usize {
    if !active() {
        first();
        return 0;
    }
    without_interrupts(|| {
        // Write side of the task table (excludes with_process – see above).
        let _t = TABLE.write();
        first();
        let s = table();
        let mut n = 0;
        for t in s.tasks.iter() {
            if !t.dead.load(Ordering::Acquire) {
                if let Some(p) = t.process.as_deref() {
                    if p.ppid() == from {
                        p.ppid.store(to, Ordering::SeqCst);
                        n += 1;
                    }
                }
            }
        }
        // The new parent now has children (its exit must hand them over).
        if n > 0 && to != 0 {
            if let Some(t) = find(s, to) {
                if let Some(p) = unsafe { &*t }.process.as_deref() {
                    p.has_children.store(true, Ordering::SeqCst);
                    p.live_children.fetch_add(n as u32, Ordering::SeqCst);
                }
            }
        }
        n
    })
}

/// `f` for each live process (tests: zombies in all parents).
#[allow(dead_code)]
pub fn for_each_process(mut f: impl FnMut(TaskId, &crate::user::Process)) {
    if !active() {
        return;
    }
    without_interrupts(|| {
        let _t = TABLE.read();
        for t in table().tasks.iter() {
            if !t.dead.load(Ordering::Acquire) {
                if let Some(p) = t.process.as_deref() {
                    f(t.id, p);
                }
            }
        }
    })
}

/// Top of the current task's kernel stack (return from ring 3 to the kernel).
pub fn current_kernel_stack_top() -> u64 {
    without_interrupts(|| {
        let _g = lock_sched_at(&"current_kernel_stack_top");
        let s = sched();
        find(s, cur_id(s)).map(|p| tm(p).kernel_stack_top()).unwrap_or(0)
    })
}

pub fn should_exit() -> bool {
    // Without the BKL (the current task's flag via the per-CPU pointer).
    active() && without_interrupts(should_exit_unlocked)
}

/// Published handle summaries of user processes (`caps`, `secinfo`):
/// (pid, ppid, name, file sandbox, summary of each slot).  Read under the scheduler lock – a
/// process is freed only after its task is removed under the same lock, and only
/// atomics are read (the owner changes its table without locks).
pub fn process_caps() -> Vec<(TaskId, TaskId, String, bool, [u64; crate::user::caps::SLOTS])> {
    if !active() {
        return Vec::new();
    }
    let mut out = Vec::new();
    without_interrupts(|| {
        let _g = lock_sched_at(&"process_caps");
        let s = sched();
        for t in s.tasks.iter() {
            if t.state == State::Dead {
                continue;
            }
            if let Some(p) = t.process.as_deref() {
                out.push((t.id, p.ppid(), t.name.clone(), p.no_files, p.handle_summary()));
            }
        }
    });
    out
}

/// List of tasks (excluding finished ones).
pub fn tasks() -> Vec<TaskInfo> {
    if !active() {
        return Vec::new();
    }
    let mut out = Vec::new();
    without_interrupts(|| {
        let _g = lock_sched_at(&"tasks");
        let s = sched();
        for t in s.tasks.iter() {
            if t.state == State::Dead {
                continue;
            }
            out.push(TaskInfo {
                id: t.id,
                name: t.name.clone(),
                state: t.state,
                cpu_ticks: t.cpu_ticks.load(Ordering::Relaxed),
                switches: t.switches,
                stack_top: t.stack.as_ref().map(|st| st.top()).unwrap_or(0),
                user: t.process.is_some(),
                ppid: t.process.as_deref().map(|p| p.ppid()).unwrap_or(0),
                cpu: s.current.iter().position(|&c| c == t.id),
                last_cpu: t.last_cpu as usize,
                cpu_mask: t.cpu_mask,
            });
        }
    });
    out
}

/// Whether a task still exists (without copying the task list –
/// the stress loop asked task_info about 48 tasks every 2 ms).
pub fn task_exists(id: TaskId) -> bool {
    without_interrupts(|| {
        let _t = TABLE.read();
        find(table(), id).map(|p| table_check(unsafe { &*p })).is_some()
    })
}

pub fn task_info(id: TaskId) -> Option<TaskInfo> {
    tasks().into_iter().find(|t| t.id == id)
}

pub fn total_switches() -> u64 {
    TOTAL_SWITCHES.get()
}

/// Frees finished tasks (stack, structure).  Called by idle and tests.
/// How many times a user process was resumed on a different CPU than before.
static USER_MIGRATIONS: AtomicU64 = AtomicU64::new(0);

/// Counter of process migrations between CPUs (tests).
#[allow(dead_code)]
pub fn user_migrations() -> u64 {
    USER_MIGRATIONS.load(Ordering::Relaxed)
}

/// Finished tasks waiting for cleanup (the idle loop checks
/// this without the BKL and takes it only when there is something to clean up).
static DEAD_TASKS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub fn reap() -> usize {
    let t0 = crate::user::prof::start();
    // Space prepared before taking the scheduler lock (no allocation
    // under it; more dead tasks than space – they will wait for next time).
    let room = DEAD_TASKS.load(Ordering::Relaxed).clamp(1, 64);
    let mut dead: Vec<Box<Task>> = Vec::with_capacity(room);
    without_interrupts(|| {
        let _g = lock_sched_at(&"reap");
        let s = sched();
        let _t = TABLE.write();
        let mut i = 0;
        while i < s.tasks.len() {
            // A dead task may still be leaving a CPU (on_cpu).
            if dead.len() < room
                && s.tasks[i].state == State::Dead
                && !s.current.contains(&s.tasks[i].id)
                && !s.tasks[i].on_cpu.load(Ordering::Acquire)
            {
                let id = s.tasks[i].id;
                let p: *mut Task = &mut *s.tasks[i];
                let _ = id;
                id_remove(s, p);
                dead.push(s.tasks.swap_remove(i));
            } else {
                i += 1;
            }
        }
        let _ = DEAD_TASKS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |d| Some(d.saturating_sub(dead.len())));
    });
    let n = dead.len();
    drop(dead); // stacks unmapped, frames returned (with interrupts enabled)
    crate::user::prof::stop(crate::user::prof::REAP, t0);
    n
}

// ------------------------------------------------------------
// Interrupts: tick + preemption
// ------------------------------------------------------------

// Tick without the scheduler lock when there is nobody to wake.  CPU time
// and quantum are this CPU's data (only this CPU changes its current task, and in an
// interrupt IF = 0), and "there are ready tasks" – the READY_N counter (a hint;
// a wake-up sends an IPI anyway).  Previously every CPU took the global
// lock every 1 ms: ~16 thousand acquisitions/s on a 16-CPU machine just for time accounting.
/// Quantum of each CPU's current task (ms).
static QUANTUM: crate::arch::x86_64::percpu::PerCpu<AtomicU32> = crate::per_cpu!(AtomicU32::new(QUANTUM_TICKS));
/// Length of the ready queue (written under the lock, read without it – a hint).
static READY_N: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// Earliest deadline on the `sleepers` list (u64::MAX = empty); after a
/// wake-up before the deadline it may be too early – then just a needless acquisition.
static NEXT_WAKE: AtomicU64 = AtomicU64::new(u64::MAX);

/// From IRQ0 (time::on_tick) – BSP only (PIT, 1 tick = 1 ms): wakes sleeping
/// tasks and counts the BSP task's quantum.
pub fn on_tick(now: u64) {
    if !active() {
        return;
    }
    // The tick may jump by a few ms (HPET catch-up after lost
    // PIT interrupts) – CPU time and quantum are counted by the clock.
    let last = LAST_BSP_TICK.swap(now, core::sync::atomic::Ordering::Relaxed);
    let ms = if last == 0 { 1 } else { now.saturating_sub(last).clamp(1, 1000) as u32 };
    tick_cpu(ms);
    if now < NEXT_WAKE.load(Ordering::Relaxed) {
        return;
    }
    let _g = lock_sched_at(&"on_tick");
    let s = sched();
    let mut woke = 0;
    let mut next = u64::MAX;
    // Only tasks with a deadline (unsorted list – there are
    // few of them: `sleep` sleepers, waits with a timeout).
    let mut p = s.sleepers.head;
    while !p.is_null() {
        let nextp = tm(p).sq.next;
        if tm(p).wake_at <= now {
            unblock(s, p); // also removes it from the deadline list
            woke += 1;
        } else {
            next = next.min(tm(p).wake_at);
        }
        p = nextp;
    }
    NEXT_WAKE.store(next, Ordering::Relaxed);
    for _ in 0..woke.min(MAX_CPUS) {
        kick(s);
    }
}

/// "Switch at the next opportunity" flag of CPU `c` (diagnostics).
#[allow(dead_code)]
pub fn need_resched_of(c: usize) -> bool {
    NEED_RESCHED[c % MAX_CPUS].load(Ordering::Relaxed)
}

/// Number of ready tasks (not idle) – diagnostics.
#[allow(dead_code)]
pub fn ready_count() -> usize {
    without_interrupts(|| {
        let _g = lock_sched_at(&"ready_count");
        sched().ready.len
    })
}

/// LAPIC timer tick of an AP (every `ms` ms).
pub fn ap_tick(ms: u32) {
    if !active() {
        return;
    }
    tick_cpu(ms);
}

/// CPU time of this processor's current task and its quantum (from the timer
/// interrupt, IF = 0, without the scheduler lock – see QUANTUM).
fn tick_cpu(ms: u32) {
    let me = cpu();
    let Some(cur) = current_task_unlocked() else { return };
    cur.cpu_ticks.fetch_add(ms as u64, Ordering::Relaxed);
    let q = QUANTUM[me].load(Ordering::Relaxed).saturating_sub(ms);
    QUANTUM[me].store(q, Ordering::Relaxed);
    if q == 0 {
        NEED_RESCHED[me].store(true, Ordering::Relaxed);
    }
    // Idle, and there are ready tasks (e.g. a wake-up without an IPI) – take them.
    if cur.idle_cpu.is_some() && READY_N.load(Ordering::Relaxed) > 0 {
        NEED_RESCHED[me].store(true, Ordering::Relaxed);
    }
}

/// Some task became ready – who should take it.  If this CPU
/// is idle – itself (after the interrupt).  Otherwise the first idle CPU,
/// woken by an IPI (from `hlt`).  When all are busy – this CPU
/// (preemption, as on a single core).
fn kick(s: &mut Scheduler) {
    let me = cpu();
    if s.current[me] == s.idle[me] {
        NEED_RESCHED[me].store(true, Ordering::Relaxed);
        return;
    }
    if !kick_idle(s) {
        NEED_RESCHED[me].store(true, Ordering::Relaxed);
    }
}

/// Wakes one idle CPU (other than this one); `false` – there is none.
fn kick_idle(s: &mut Scheduler) -> bool {
    let me = cpu();
    for c in 0..MAX_CPUS {
        if c != me
            && s.idle[c] != NO_TASK
            && s.current[c] == s.idle[c]
            && crate::arch::x86_64::smp::online(c)
            && !NEED_RESCHED[c].swap(true, Ordering::SeqCst)
        {
            // The CPU is spinning in idle – it will see the flag itself, no interrupt needed.
            if POLLING[c].load(Ordering::SeqCst) {
                IPI_SKIPPED.add(1);
            } else {
                crate::arch::x86_64::smp::send_resched(c);
            }
            return true;
        }
    }
    false
}

/// From irq::dispatch, after EOI: switches if needed.
/// Preemption at the end of an interrupt.  `had_bkl` – whether the interrupted context
/// held the BKL.  If not (process in ring 3, BKL-free code, idle),
/// the BKL is NOT taken back after return – the rest of the interrupt (killing
/// a process: the exit log has its own lock) does not need it, and exiting
/// the interrupt would release it anyway.  Such "take it only to
/// release it" was a large share of the acquisitions after a switch.
pub fn preempt_irq(had_bkl: bool) {
    // The CPU holds a SpinLock – the switch will wait (NEED_RESCHED stays set).
    if crate::arch::x86_64::cpu::preempt_count() > 0 {
        return;
    }
    if active() && NEED_RESCHED[cpu()].swap(false, Ordering::Relaxed) {
        // An interrupt may have hit between putting the task to sleep and its
        // after_switch (IF = 1 briefly) – the "gave up the BKL" flag then belongs to the
        // interrupted context, not to the interrupt.  We stash it for the duration of the
        // switch here and restore it (found by: SCHED TEST 7,
        // "wait_event lost BKL" – the interrupt took the flag and released the BKL).
        let pending = take_bkl_dropped();
        schedule();
        if had_bkl {
            after_switch(&bkl::tag::AFTER_PREEMPT);
        } else {
            // Only this interrupt took the BKL – we do not reacquire it.
            let _ = take_bkl_dropped();
        }
        set_bkl_dropped(pending);
    }
}

/// Registers the boot context of processor `cpu` (AP) as its idle
/// task – on stack `stack`.  Called by the BSP before waking the AP; the AP after start
/// simply runs `idle_loop` on that stack.
pub fn spawn_idle_for_cpu(cpu_index: usize, stack: TaskStack) -> TaskId {
    without_interrupts(|| {
        let _g = lock_sched_at(&"spawn_idle_for_cpu");
        let s = sched();
        let id = s.next_id;
        s.next_id += 1;
        let mut name = String::from("idle");
        let _ = core::fmt::Write::write_fmt(&mut name, format_args!("/{}", cpu_index));
        let mut t = new_task(id, &name, Some(stack), 0, State::Running);
        t.idle_cpu = Some(cpu_index as u8);
        t.last_cpu = cpu_index as u8;
        t.cpu_mask = 1 << cpu_index;
        add_task(s, t);
        s.current[cpu_index] = id;
        publish_current(s, cpu_index);
        s.idle[cpu_index] = id;
        id
    })
}

/// Top of a task's stack (AP: boot stack = its idle stack).
pub fn task_stack_top(id: TaskId) -> Option<u64> {
    without_interrupts(|| {
        let _g = lock_sched_at(&"task_stack_top");
        let s = sched();
        index_of(s, id).and_then(|i| s.tasks[i].stack.as_ref().map(|st| st.top()))
    })
}

/// Idle loop (BSP: task 0; AP: the processor's boot context).
/// One reaper at a time (idle loop).
static REAPER: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// TSC ticks during which the CPU ran its idle task (counted
/// in schedule() when switching from / to idle – measuring around `hlt` would
/// also count the time of tasks the interrupt switched to midway), and the start of
/// the current idle period.  Always the same CPU's TSC.
static IDLE_TSC: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static IDLE_SINCE: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));

/// TSC at the moment this CPU's current task got onto the CPU.
static SWITCHED_IN: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));

/// CPU cycles of the current task up to now (monotonic for the
/// task, also after migration; time when it was not running does not count).
pub fn task_cpu_cycles() -> u64 {
    crate::arch::x86_64::interrupts::without_interrupts(|| {
        let me = cpu();
        let a = CUR_TASK[me].load(Ordering::Acquire);
        if a == 0 {
            return 0;
        }
        let t = unsafe { &*(a as *const Task) };
        let since = SWITCHED_IN[me].load(Ordering::Relaxed);
        let now = idle_tsc();
        t.run_tsc.load(Ordering::Relaxed) + if since != 0 && now > since { now - since } else { 0 }
    })
}

fn idle_tsc() -> u64 {
    let (lo, hi): (u32, u32);
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    ((hi as u64) << 32) | lo as u64
}

/// Microseconds in `hlt` of the idle loop on CPU `c` (0 without TSC calibration).
pub fn idle_us(c: usize) -> u64 {
    let per_ms = crate::arch::x86_64::lapic::tsc_per_ms();
    if per_ms == 0 {
        return 0;
    }
    IDLE_TSC[c % MAX_CPUS].load(Ordering::Relaxed).saturating_mul(1000) / per_ms
}

/// How many µs an idle CPU spins before `hlt` (from the build:
/// `DESOOS_IDLE_POLL_US`, default 200; 0 = hlt immediately).  Rationale: on
/// real hardware `hlt` puts the core into a deeper sleep (AMD: C1 → CC6), the wake-up
/// takes tens of µs and lengthens every task hand-off – with less lock contention
/// cores spin less and sleep more often (on real hardware: idle 26 → 28–32%,
/// stress −5%; no drop under KVM).  Like `haltpoll` in Linux.
/// This is the UPPER bound of the window; each CPU's window adapts itself
/// (`DESOOS_IDLE_POLL_ADAPT`, default 1), see `idle_adapt`.
pub fn idle_poll_us() -> u64 {
    match option_env!("DESOOS_IDLE_POLL_US") {
        Some(s) => s.trim().parse::<u64>().unwrap_or(200).min(10_000),
        None => 200,
    }
}

/// Spin window adapted per CPU (like `haltpoll` in Linux):
/// work arrived within `idle_poll_us()` of going to sleep – window ×2 (spinning
/// would have caught it); longer idleness – window /2, down to 0 (an idle system
/// does not spin – battery).  0 – fixed window = `idle_poll_us()`.
pub fn idle_adapt() -> bool {
    !matches!(option_env!("DESOOS_IDLE_POLL_ADAPT").map(|s| s.trim()), Some("0"))
}

const POLL_GROW_MIN_US: u64 = 10;

/// (wake-ups while spinning, hlt entries) – `cpus`.
static IDLE_POLL_HITS: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static IDLE_HALTS: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
/// The CPU is spinning in the idle loop – wake-up without an IPI (the flag is enough).
static POLLING: crate::arch::x86_64::percpu::PerCpu<AtomicBool> = crate::per_cpu!(AtomicBool::new(false));
static IPI_SKIPPED: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
/// Current spin window (µs) of each CPU and the TSC of the first `hlt`
/// in the current idle period (0 = did not sleep).
static POLL_WIN: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(50));
static HLT_AT: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static POLL_GROWS: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static POLL_SHRINKS: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();

/// (wake-ups while spinning, hlt, skipped IPIs, window increases, window decreases, average window µs).
pub fn idle_poll_stats() -> (u64, u64, u64, u64, u64, u64) {
    let n = crate::arch::x86_64::smp::online_count().max(1);
    let sum: u64 = (0..n).map(|c| POLL_WIN[c].load(Ordering::Relaxed)).sum();
    // Fixed window: show the actual value, not the initial POLL_WIN.
    let avg = if idle_adapt() { sum / n as u64 } else { idle_poll_us() };
    (IDLE_POLL_HITS.get(), IDLE_HALTS.get(), IPI_SKIPPED.get(), POLL_GROWS.get(), POLL_SHRINKS.get(), avg)
}

/// CPU `me` starts working after being idle – if it slept (`hlt`),
/// adjust the window: work came quickly – larger, after a long sleep – smaller.
fn idle_feedback(me: usize) {
    let t = HLT_AT[me].swap(0, Ordering::Relaxed);
    if t == 0 || !idle_adapt() {
        return;
    }
    let max = idle_poll_us();
    let per_us = (crate::arch::x86_64::lapic::tsc_per_ms() / 1000).max(1);
    let slept = bkl::rdtsc().wrapping_sub(t) / per_us;
    let w = POLL_WIN[me].load(Ordering::Relaxed);
    if slept <= max {
        POLL_WIN[me].store((w * 2).max(POLL_GROW_MIN_US).min(max), Ordering::Relaxed);
        POLL_GROWS.add(1);
    } else if w > 0 {
        let nw = w / 2;
        POLL_WIN[me].store(if nw < POLL_GROW_MIN_US { 0 } else { nw }, Ordering::Relaxed);
        POLL_SHRINKS.add(1);
    }
}

pub fn idle_loop() -> ! {
    // Idle loop without the BKL.  Previously it held it permanently: released it for
    // the duration of `hlt` and took it back after every wake-up – also after a TLB
    // shootdown IPI (vector 0x43 does not take the BKL), only to call reap
    // and go back to sleep.  On a 16-CPU machine: 2.37 million such acquisitions, 89% with
    // waiting – 129 s out of 173 s of total BKL waiting.  Now the BKL is taken only for
    // cleanup (freeing a process and its address space – still under the BKL),
    // and only when there is something to clean up.
    interrupts::disable();
    if bkl::held() {
        bkl::release();
    }
    // First idle period of this CPU (an AP starts directly in idle).
    if IDLE_SINCE[cpu()].load(Ordering::Relaxed) == 0 {
        IDLE_SINCE[cpu()].store(idle_tsc(), Ordering::Relaxed);
    }
    interrupts::enable();
    loop {
        // One CPU reaps at a time – the other idle CPUs do not queue up
        // for the BKL for the same task (previously 143 thousand acquisitions,
        // 78% with waiting).
        if DEAD_TASKS.load(Ordering::Relaxed) > 0
            && REAPER.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok()
        {
            interrupts::disable();
            let took = bkl::acquire_if_needed_tagged(&bkl::tag::IDLE_REAP);
            interrupts::enable();
            reap();
            if took {
                interrupts::disable();
                bkl::release();
                interrupts::enable();
            }
            REAPER.store(false, Ordering::Release);
        }
        // First a short spin with IF = 1 – a wake-up (IPI) hits a
        // running core and switches to the task immediately (preempt at the end of the
        // interrupt); after spinning, `hlt` as before.
        let me = cpu();
        let max = idle_poll_us();
        let poll = if idle_adapt() { POLL_WIN[me].load(Ordering::Relaxed).min(max) } else { max };
        if poll > 0 {
            let per_us = (crate::arch::x86_64::lapic::tsc_per_ms() / 1000).max(1);
            let t0 = bkl::rdtsc();
            let mut hit = false;
            let mut reap_due = false;
            // "I am spinning" flag – the waker does not send an IPI.  Ordering
            // (Dekker): the waker sets NEED_RESCHED, then reads POLLING; we
            // clear POLLING, then read NEED_RESCHED once more –
            // one of the two always sees the other, the wake-up is not lost.
            POLLING[me].store(true, Ordering::SeqCst);
            while bkl::rdtsc().wrapping_sub(t0) < poll * per_us {
                if NEED_RESCHED[me].load(Ordering::SeqCst) {
                    hit = true;
                    break;
                }
                if DEAD_TASKS.load(Ordering::Relaxed) > 0 && !REAPER.load(Ordering::Relaxed) {
                    reap_due = true;
                    break;
                }
                core::hint::spin_loop();
            }
            POLLING[me].store(false, Ordering::SeqCst);
            if !hit && NEED_RESCHED[me].load(Ordering::SeqCst) {
                hit = true;
            }
            if hit {
                IDLE_POLL_HITS.add(1);
                if NEED_RESCHED[me].swap(false, Ordering::Relaxed) {
                    yield_now();
                }
                continue;
            }
            if reap_due {
                continue;
            }
        }
        // Before hlt: a final check with IF = 0 (a wake-up without an IPI may have
        // arrived right before POLLING was cleared); an IPI after this point will wake hlt.
        interrupts::disable();
        if NEED_RESCHED[me].load(Ordering::SeqCst) {
            interrupts::enable();
            if NEED_RESCHED[me].swap(false, Ordering::Relaxed) {
                yield_now();
            }
            continue;
        }
        if HLT_AT[me].load(Ordering::Relaxed) == 0 {
            HLT_AT[me].store(bkl::rdtsc().max(1), Ordering::Relaxed);
        }
        IDLE_HALTS.add(1);
        interrupts::enable_and_hlt();
    }
}

/// Id of CPU `c`'s current task without locks or allocation (watchdog
/// report – the state may be changing, this is only a hint).
pub fn current_id_on(c: usize) -> Option<TaskId> {
    let s = unsafe { &*core::ptr::addr_of!(SCHED) };
    let id = s.current[c % MAX_CPUS];
    (id != NO_TASK).then_some(id)
}

/// Current task of processor `cpu` (diagnostics: `cpus`).
pub fn current_on(cpu_index: usize) -> Option<(TaskId, String, bool)> {
    if !active() || cpu_index >= MAX_CPUS {
        return None;
    }
    without_interrupts(|| {
        let _g = lock_sched_at(&"current_on");
        let s = sched();
        let id = s.current[cpu_index];
        let i = index_of(s, id)?;
        Some((id, s.tasks[i].name.clone(), id == s.idle[cpu_index]))
    })
}

#[cfg(selftest)]
mod test;
#[cfg(selftest)]
pub use test::self_test;
