// Waiting on many handles at once (`wait_many`).
// Design: ARCHITECTURE.md, "User-space services".
//
// Every object that can be waited on (a channel end queue, a pipe, an
// interrupt) has `Observers` – a list of WaitQueue channels of the tasks waiting
// on it.  `wait_many`:
//   1. registers its channel (the address of a local WaitQueue) with every object,
//   2. checks the conditions and sleeps on its own WaitQueue (condition under the
//      scheduler lock – sched::wait_event),
//   3. unregisters from all objects.
// After a state change (atomics, SeqCst) an object reads the list and wakes every channel.
// No wakeup is lost: the list write happens before the condition check, and the state
// change before the list read – either the waiter sees the new state, or it is already
// on the list and gets woken (wake_channel takes the scheduler lock).
//
// The list is under an IrqSpinLock (level WAITERS: above the channel and pipe queues,
// below the scheduler) – the interrupt handler reads it as well.  Waking
// happens after releasing the list: a copy into an array on the stack, no allocation.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::sched::spin::{level, IrqSpinLock};

/// Maximum number of observers woken at once without allocation (more – a second round).
const BATCH: usize = 16;

pub struct Observers {
    list: IrqSpinLock<Vec<usize>>,
    /// List length (changed under the lock) – `notify` with no waiters does not
    /// take the lock (every send / recv calls notify).  SeqCst like the object
    /// state: a waiter increments the counter BEFORE checking the condition, and
    /// the object changes state BEFORE reading the counter – one of them sees the other.
    count: AtomicUsize,
}

impl Observers {
    pub const fn new() -> Observers {
        Observers { list: IrqSpinLock::new("waiters", level::WAITERS, Vec::new()), count: AtomicUsize::new(0) }
    }

    /// Registers a waiter's channel (allocates – not from an interrupt).
    pub fn add(&self, channel: usize) {
        let mut l = self.list.lock();
        l.push(channel);
        self.count.store(l.len(), Ordering::SeqCst);
    }

    /// Unregisters a channel (one entry – the same object may be on a
    /// `wait_many` list several times).
    pub fn remove(&self, channel: usize) {
        let mut l = self.list.lock();
        if let Some(i) = l.iter().position(|&c| c == channel) {
            l.swap_remove(i);
        }
        self.count.store(l.len(), Ordering::SeqCst);
    }

    /// Wakes all waiters (also from an interrupt – no allocation).
    pub fn notify(&self) {
        if self.count.load(Ordering::SeqCst) == 0 {
            return;
        }
        let mut start = 0;
        loop {
            let mut buf = [0usize; BATCH];
            let (n, more) = {
                let l = self.list.lock();
                if start >= l.len() {
                    return;
                }
                let n = (l.len() - start).min(BATCH);
                buf[..n].copy_from_slice(&l[start..start + n]);
                (n, start + n < l.len())
            };
            for &c in &buf[..n] {
                crate::sched::wake_channel(c);
            }
            if !more {
                return;
            }
            start += n;
        }
    }
}
