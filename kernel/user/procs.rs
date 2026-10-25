// Process family – parent/child, zombies, wait, init.
//
// * Every process has a parent (Process.ppid).  0 = kernel (init supervisor,
//   kernel shell, self-tests) – the kernel cleans up such processes itself, as it
//   always has (sched::task_info / user::exit_info).
// * A process with a process parent becomes a zombie when it exits: the task
//   disappears, but the exit code waits on the parent's zombie list until the parent collects it
//   (`wait`).
// * An exiting process hands its children (live and zombie) over to init.  When
//   init is not running yet (self-tests, kernel shell) – to the kernel: live
//   children keep running, zombies disappear.
// * Zombies live in the parent process (`Process.zombies`, a spinlock
//   per parent) – instead of a single table under a sleeping lock that
//   all processes fought over (on a 16-thread machine under full load: 12.3 million
//   acquisitions, 168 s of waiting per minute).  Rules:
//     - a child appends itself under the scheduler lock (with_process on the parent)
//       and the parent's list lock, checking that the parent is not exiting and that
//       it is still its parent (otherwise it tries the new one),
//     - an exiting parent, in ONE section under the scheduler lock, sets
//       `exiting`, takes its zombies and hands over live children (reparent_with),
//       then passes the zombies to init,
//     - `wait` takes only the lock of its own list; live children are counted by the same
//       counter that the child decrements together with the zombie entry.
//
// Status (wait): exit code 0..255 or STATUS_SIGNALED | reason
// (9 = kill/Ctrl+C, CPU exception number, 0xFF = bad return address).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::ExitKind;
use crate::sched::sync::WaitQueue;
use crate::sched::{self, TaskId};

pub const STATUS_SIGNALED: u64 = 0x100;
pub const REASON_KILLED: u64 = 9;
pub const REASON_BAD_RETURN: u64 = 0xFF;

/// wait(pid = ANY): any child.
pub const WAIT_ANY: u64 = u64::MAX;
/// wait flag: do not wait (0 when no child has finished yet).
pub const WNOHANG: u64 = 1;

#[derive(Clone, Copy, Default)]
pub struct Zombie {
    pid: TaskId,
    status: u64,
}

/// Lock of the zombie list inside a process.  NOT `IrqSpinLock`:
/// RawSpin has 64 B alignment (a cache line), which gave the whole `Process`
/// 64-byte alignment and sent every process down the heap slow path (blocks > 2 KiB or
/// alignment > 16 – the global list): heap lock waits went up
/// by 50%.  Here: one byte + interrupts disabled for the section (a few
/// instructions), no lockdep – taken only in procs.rs, never two at once.
pub struct ChildList {
    locked: core::sync::atomic::AtomicBool,
    list: core::cell::UnsafeCell<Zombies>,
}

unsafe impl Sync for ChildList {}
unsafe impl Send for ChildList {}

pub struct ChildGuard<'a> {
    owner: &'a ChildList,
    irq: bool,
}

impl ChildList {
    pub const fn new() -> Self {
        ChildList { locked: core::sync::atomic::AtomicBool::new(false), list: core::cell::UnsafeCell::new(Zombies::new()) }
    }

    pub fn lock(&self) -> ChildGuard<'_> {
        use crate::arch::x86_64::interrupts;
        let irq = interrupts::are_enabled();
        interrupts::disable();
        // Wait by reading, attempt to acquire only when the lock is free.  We wait
        // with IF = 0, so TLB shootdown requests are acknowledged here: the holder
        // may free heap memory (the heap shrinks -> shootdown) and wait for us –
        // without this, both waited forever (found on TCG: exiting orphans pushing
        // to init while the process handing them over shrank the heap).
        let mut n: u32 = 0;
        while self.locked.load(Ordering::Relaxed) || self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
            n = n.wrapping_add(1);
            if n % 64 == 0 {
                crate::arch::x86_64::tlb::poll_from_wait();
            }
        }
        ChildGuard { owner: self, irq }
    }
}

impl core::ops::Deref for ChildGuard<'_> {
    type Target = Zombies;
    fn deref(&self) -> &Zombies {
        unsafe { &*self.owner.list.get() }
    }
}

impl core::ops::DerefMut for ChildGuard<'_> {
    fn deref_mut(&mut self) -> &mut Zombies {
        unsafe { &mut *self.owner.list.get() }
    }
}

impl Drop for ChildGuard<'_> {
    fn drop(&mut self) {
        self.owner.locked.store(false, Ordering::Release);
        if self.irq {
            crate::arch::x86_64::interrupts::enable();
        }
    }
}

/// The parent's zombie list – the first INLINE entries in the process itself, then
/// a Vec.  Without this every process with children allocated and freed a heap buffer
/// (under KVM: heap lock waits +45%).  Collection order: arbitrary
/// (POSIX does not guarantee one).
const INLINE: usize = 4;

pub struct Zombies {
    inline: [Zombie; INLINE],
    n: usize,
    more: Vec<Zombie>,
}

impl Zombies {
    pub const fn new() -> Self {
        Zombies { inline: [Zombie { pid: 0, status: 0 }; INLINE], n: 0, more: Vec::new() }
    }

    fn push(&mut self, z: Zombie) {
        if self.n < INLINE {
            self.inline[self.n] = z;
            self.n += 1;
        } else {
            self.more.push(z);
        }
    }

    /// The first entry matching `f` – removed from the list.
    fn take_first(&mut self, f: impl Fn(&Zombie) -> bool) -> Option<Zombie> {
        if let Some(i) = self.inline[..self.n].iter().position(&f) {
            let z = self.inline[i];
            self.n -= 1;
            self.inline[i] = self.inline[self.n];
            if let Some(m) = self.more.pop() {
                self.inline[self.n] = m;
                self.n += 1;
            }
            return Some(z);
        }
        let i = self.more.iter().position(&f)?;
        Some(self.more.swap_remove(i))
    }

    fn take_all(&mut self) -> Vec<Zombie> {
        if self.n == 0 {
            return Vec::new();
        }
        let mut all = core::mem::take(&mut self.more);
        all.extend_from_slice(&self.inline[..self.n]);
        self.n = 0;
        all
    }

    fn iter(&self) -> impl Iterator<Item = &Zombie> {
        self.inline[..self.n].iter().chain(self.more.iter())
    }
}

/// A parent waits on a queue chosen by its own pid – a process exit
/// wakes only its parent (and possibly init).
#[repr(align(8))] // distinct addresses = distinct scheduler channel buckets
struct ChildQ(WaitQueue);
const CHILD_QUEUES: usize = 64;
static CHILD_EXIT: [ChildQ; CHILD_QUEUES] = [const { ChildQ(WaitQueue::new()) }; CHILD_QUEUES];

fn child_q(parent: TaskId) -> &'static WaitQueue {
    &CHILD_EXIT[(parent as usize) % CHILD_QUEUES].0
}
static INIT_PID: AtomicU64 = AtomicU64::new(0);

/// Init (0 = not running).
pub fn init_pid() -> TaskId {
    INIT_PID.load(Ordering::SeqCst)
}

pub fn set_init_pid(pid: TaskId) {
    INIT_PID.store(pid, Ordering::SeqCst);
}

pub fn status_of(kind: ExitKind) -> u64 {
    match kind {
        ExitKind::Exit(code) => (code as u64) & 0xFF,
        ExitKind::Killed => STATUS_SIGNALED | REASON_KILLED,
        ExitKind::BadReturn => STATUS_SIGNALED | REASON_BAD_RETURN,
        ExitKind::Breakpoint => STATUS_SIGNALED | 3,
        ExitKind::PageFault { .. } => STATUS_SIGNALED | 14,
        ExitKind::GeneralProtection { .. } => STATUS_SIGNALED | 13,
        ExitKind::InvalidOpcode => STATUS_SIGNALED | 6,
        ExitKind::FpuUnavailable => STATUS_SIGNALED | 7,
        ExitKind::SimdException => STATUS_SIGNALED | 19,
        ExitKind::Exception { vector } => STATUS_SIGNALED | (vector & 0xFF),
    }
}

/// Whether `pid` is a live user process that is not exiting yet.
fn accepts_children(pid: TaskId) -> bool {
    pid != 0 && sched::with_process(pid, |p| !p.exiting.load(Ordering::SeqCst)).unwrap_or(false)
}

/// The current process is exiting (user::exit_current, before sched::exit):
/// children to init, own exit code to the parent.
pub fn on_exit(me: TaskId, kind: ExitKind) {
    let Some(p) = sched::current_process() else { return };
    let p: &super::Process = p;
    let heir = match init_pid() {
        init if init != me && accepts_children(init) => init,
        _ => 0,
    };

    // 1. `exiting` + own zombies taken + live children -> init (or the kernel,
    // when init is not running or this is init itself) – one section under the
    // scheduler lock.  Without children (has_children) the task list scan is skipped.
    let mut orphans: Vec<Zombie> = Vec::new();
    let take = || {
        let mut z = p.zombies.lock();
        p.exiting.store(true, Ordering::SeqCst);
        z.take_all()
    };
    if p.has_children.load(Ordering::SeqCst) {
        sched::reparent_with(me, heir, || orphans = take());
    } else {
        orphans = take();
    }
    if heir != 0 && !orphans.is_empty() {
        // `drain`, not `into_iter`: the vector's memory is freed after the zombie
        // lock is released (less heap work inside the section).
        let handed = sched::with_process(heir, |h| {
            let mut z = h.zombies.lock();
            if h.exiting.load(Ordering::SeqCst) {
                return false;
            }
            for o in orphans.drain(..) {
                z.push(o);
            }
            h.child_gen.fetch_add(1, Ordering::SeqCst);
            true
        });
        drop(orphans);
        if handed == Some(true) {
            child_q(heir).wake_all();
        }
    }

    // 2. Own status -> parent (a live process that is not exiting); the parent
    // has one live child fewer – in the same section as the zombie entry.
    enum Push {
        Done,
        Retry,
        Refused,
    }
    let status = status_of(kind);
    loop {
        let ppid = p.ppid();
        if ppid == 0 {
            break;
        }
        let r = sched::with_process(ppid, |pp| {
            if p.ppid() != ppid {
                return Push::Retry; // the parent has just handed us on
            }
            let mut z = pp.zombies.lock();
            if pp.exiting.load(Ordering::SeqCst) {
                return Push::Refused;
            }
            let _ = pp.live_children.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1));
            z.push(Zombie { pid: me, status });
            pp.child_gen.fetch_add(1, Ordering::SeqCst);
            Push::Done
        });
        match r {
            Some(Push::Retry) => continue,
            Some(Push::Done) => {
                child_q(ppid).wake_all();
                break;
            }
            _ => break,
        }
    }
}

/// Whether the parent will collect the status of `pid` via wait (a process with a process parent).
pub fn has_process_parent(p: &super::Process) -> bool {
    accepts_children(p.ppid())
}

/// wait(pid, flags): Ok((pid, status)), Ok((0, 0)) with WNOHANG and no result.
pub fn wait(me: TaskId, pid: TaskId, flags: u64) -> Result<(TaskId, u64), i64> {
    use super::syscalls::{ECHILD, EINTR};
    let Some(p) = sched::current_process() else { return Err(ECHILD) };
    let p: &super::Process = p;
    loop {
        let seen = p.child_gen.load(Ordering::SeqCst);
        let any_live = {
            let mut z = p.zombies.lock();
            if let Some(z) = z.take_first(|z| pid == WAIT_ANY || z.pid == pid) {
                return Ok((z.pid, z.status));
            }
            p.live_children.load(Ordering::SeqCst) > 0
        };
        let waiting = if pid == WAIT_ANY {
            any_live
        } else {
            sched::with_process(pid, |c| c.ppid() == me).unwrap_or(false)
        };
        if !waiting {
            // The child may have added a zombie and disappeared between the checks.
            if p.child_gen.load(Ordering::SeqCst) != seen {
                continue;
            }
            return Err(ECHILD);
        }
        if flags & WNOHANG != 0 {
            return Ok((0, 0));
        }
        child_q(me).wait_until(|| p.child_gen.load(Ordering::SeqCst) != seen || sched::should_exit(), None);
        if sched::should_exit() {
            return Err(EINTR);
        }
    }
}

/// Zombies waiting for their parent (ps, tests): (pid, parent, status).
#[allow(dead_code)]
pub fn zombies() -> Vec<(TaskId, TaskId, u64)> {
    let mut out = Vec::new();
    sched::for_each_process(|ppid, p| {
        for z in p.zombies.lock().iter() {
            out.push((z.pid, ppid, z.status));
        }
    });
    out
}
