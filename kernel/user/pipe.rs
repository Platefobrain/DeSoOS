// Pipes – `pipe()` returns two descriptors: one for reading and one for writing.
//
// * Kernel buffer (PIPE_CAP bytes) under a SpinLock (PROCESS level; under it only
//   byte copying and allocation), the length is also kept in an atomic – the
//   wait condition (checked under the scheduler lock) takes no locks.
// * read: waits until there is data; an empty pipe with no writers = end (0).
// * write: writes everything, waiting for space; with no readers – ERROR_CLOSED
//   (if nothing was written; otherwise the number of bytes written).
// * Ends (PipeEnd) are reference-counted with Arc: descriptors from dup / spawn share
//   one end; when the last one goes away the end closes (Drop) and wakes the
//   other side.  A process closes its descriptors already in exit_current (not
//   only at reap) – the reader sees end of data immediately.
// * Waiting is interrupted by kill / Ctrl+C (ERROR_INTERRUPTED).
// * A list of `wait_many` observers – woken on every change.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use super::syscalls::{ERROR_INTERRUPTED, ERROR_OUT_OF_MEMORY, ERROR_CLOSED};
use super::waitset::Observers;
use crate::sched::spin::{level, SpinLock};
use crate::sched::sync::WaitQueue;

/// Buffer capacity (like PIPE_BUF in Linux: 64 KiB).
pub const PIPE_CAP: usize = 64 * 1024;

pub struct Pipe {
    buf: SpinLock<VecDeque<u8>>,
    len: AtomicUsize,
    readers: AtomicU32,
    writers: AtomicU32,
    /// Readers wait for data / for the writers to go away.
    readable: WaitQueue,
    /// Writers wait for space / for the readers to go away.
    writable: WaitQueue,
    /// `wait_many` on either end.
    obs: Observers,
}

/// Unread data is returned to the kbuf budget.
impl Drop for Pipe {
    fn drop(&mut self) {
        let n = self.buf.lock().len();
        super::kbuf::give(n as u64);
    }
}

impl Pipe {
    fn wake_readers(&self) {
        self.readable.wake_all();
        self.obs.notify();
    }

    fn wake_writers(&self) {
        self.writable.wake_all();
        self.obs.notify();
    }
}

pub struct PipeEnd {
    pipe: Arc<Pipe>,
    pub write: bool,
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        if self.write {
            self.pipe.writers.fetch_sub(1, Ordering::SeqCst);
            self.pipe.wake_readers();
        } else {
            self.pipe.readers.fetch_sub(1, Ordering::SeqCst);
            self.pipe.wake_writers();
        }
    }
}

/// New pipe: (read end, write end).
impl PipeEnd {
    /// Identity for `dcp`: (pipe object, 1 = write end / 0 = read end).
    pub fn ident(&self) -> (u64, u64) {
        (Arc::as_ptr(&self.pipe) as u64, self.write as u64)
    }
}

pub fn new() -> (Arc<PipeEnd>, Arc<PipeEnd>) {
    let pipe = Arc::new(Pipe {
        buf: SpinLock::new("pipe", level::PROCESS, VecDeque::new()),
        len: AtomicUsize::new(0),
        readers: AtomicU32::new(1),
        writers: AtomicU32::new(1),
        readable: WaitQueue::new(),
        writable: WaitQueue::new(),
        obs: Observers::new(),
    });
    (Arc::new(PipeEnd { pipe: pipe.clone(), write: false }), Arc::new(PipeEnd { pipe, write: true }))
}

impl PipeEnd {
    /// Read end – there is data or nobody is writing (read will not
    /// wait); write end – there is space or nobody is reading.
    pub fn ready(&self) -> bool {
        let p = &self.pipe;
        if self.write {
            p.len.load(Ordering::SeqCst) < PIPE_CAP || p.readers.load(Ordering::SeqCst) == 0
        } else {
            p.len.load(Ordering::SeqCst) > 0 || p.writers.load(Ordering::SeqCst) == 0
        }
    }

    pub fn observers(&self) -> &Observers {
        &self.pipe.obs
    }

    /// Up to `max` bytes; an empty result = end of data (nobody writes any more).
    pub fn read(&self, max: usize) -> Result<Vec<u8>, i64> {
        let p = &self.pipe;
        loop {
            {
                let mut b = p.buf.lock();
                if !b.is_empty() {
                    let n = max.min(b.len());
                    let out: Vec<u8> = b.drain(..n).collect();
                    p.len.store(b.len(), Ordering::SeqCst);
                    drop(b);
                    super::kbuf::give(n as u64);
                    p.wake_writers();
                    return Ok(out);
                }
            }
            if p.writers.load(Ordering::SeqCst) == 0 {
                // The last writer may have appended just before closing.
                if p.len.load(Ordering::SeqCst) == 0 {
                    return Ok(Vec::new());
                }
                continue;
            }
            if max == 0 {
                return Ok(Vec::new());
            }
            p.readable.wait_until(
                || p.len.load(Ordering::SeqCst) > 0 || p.writers.load(Ordering::SeqCst) == 0 || crate::sched::should_exit(),
                None,
            );
            if crate::sched::should_exit() {
                return Err(ERROR_INTERRUPTED);
            }
        }
    }

    /// All of `data` (waits for space); ERROR_CLOSED when nobody is reading.
    pub fn write(&self, data: &[u8]) -> Result<usize, i64> {
        let p = &self.pipe;
        let mut done = 0;
        while done < data.len() {
            if p.readers.load(Ordering::SeqCst) == 0 {
                return if done > 0 { Ok(done) } else { Err(ERROR_CLOSED) };
            }
            let wrote = {
                let mut b = p.buf.lock();
                let room = PIPE_CAP.saturating_sub(b.len());
                // Counted in the kernel buffer budget (kbuf).
                let want = room.min(data.len() - done);
                let n = super::kbuf::take_upto(want as u64) as usize;
                if want > 0 && n == 0 {
                    drop(b);
                    return if done > 0 { Ok(done) } else { Err(ERROR_OUT_OF_MEMORY) };
                }
                b.extend(&data[done..done + n]);
                p.len.store(b.len(), Ordering::SeqCst);
                n
            };
            if wrote > 0 {
                done += wrote;
                p.wake_readers();
                continue;
            }
            p.writable.wait_until(
                || p.len.load(Ordering::SeqCst) < PIPE_CAP || p.readers.load(Ordering::SeqCst) == 0 || crate::sched::should_exit(),
                None,
            );
            if crate::sched::should_exit() {
                return if done > 0 { Ok(done) } else { Err(ERROR_INTERRUPTED) };
            }
        }
        Ok(done)
    }
}
