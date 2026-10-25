// Channels – `channel_create()` returns a pair of ends; each end has its own
// queue of incoming messages (the channel is bidirectional).
// Design: ARCHITECTURE.md, „IPC”.
//
// * Message: up to MSG_MAX bytes of data + up to MSG_HANDLES handles
//   + the sender (pid) filled in by the kernel.  Queue: up to QUEUE_MAX messages.
// * One lock per queue (SpinLock, level PROCESS – like a pipe); only queue
//   operations happen under it.  Copying from / to the process – in the syscall, outside the lock.
// * Waiting as in pipes: the condition is on atomics (`len`, `closed`), wakeup
//   after a change – no lost wakeups; interrupted by kill / Ctrl+C (EINTR).
// * An end is reference-counted by Arc (handles in tables and in messages in flight);
//   when the last one goes away – Drop: the end is closed, its queue drained
//   (handles in messages released), the other side woken (EPIPE).
// * Each queue also has a list of `wait_many` watchers – woken
//   on every change (message, free space, close).
// * No cycles.  A channel end whose queue holds a message carrying
//   another channel end cannot itself travel in a message (EBUSY).
//   Without this rule: end A in queue B, end B in queue A, the process closes
//   the rest – the channels keep each other alive and the memory never comes back.  Proof
//   that a cycle is impossible: the last insertion closing the cycle would insert
//   an end whose queue already holds the previous element of the cycle – refused.
//   The check and the insertion happen together under the global XFER lock (only messages
//   carrying channel ends – ordinary messages do not take it).

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::process::Handle;
use super::waitset::Observers;
use super::syscalls::{EAGAIN, EBUSY, EINTR, ENOMEM, EPIPE};
use crate::sched::spin::{level, SpinLock};
use crate::sched::sync::WaitQueue;

/// Largest message (data bytes).
pub const MSG_MAX: usize = 4096;
/// Maximum number of handles in a message.
pub const MSG_HANDLES: usize = 8;
/// Maximum number of messages in the queue of one end.
pub const QUEUE_MAX: usize = 64;

pub struct Message {
    pub data: Vec<u8>,
    pub handles: Vec<Handle>,
    /// Sender (pid) – filled in by the kernel, the process cannot supply it.
    pub sender: u64,
}

impl Message {
    /// Channel ends carried in the message.
    fn channel_ends(&self) -> impl Iterator<Item = &Arc<ChanEnd>> {
        self.handles.iter().filter_map(|h| if let super::process::Fd::Channel(e) = &h.obj { Some(e) } else { None })
    }
    fn carries_channel(&self) -> bool {
        self.channel_ends().next().is_some()
    }
    /// Cost against the kernel buffer budget (kbuf).
    fn cost(&self) -> u64 {
        self.data.len() as u64 + super::kbuf::MSG_OVERHEAD
    }
}

/// The "no cycles" check + insertion of a message carrying channel ends.
static XFER: SpinLock<()> = SpinLock::new("chan-xfer", level::CHAN_XFER, ());

/// How many channels are alive (leak test: returns to the previous value after the test).
pub static LIVE_CHANNELS: AtomicUsize = AtomicUsize::new(0);

impl Drop for Channel {
    fn drop(&mut self) {
        LIVE_CHANNELS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Incoming queue of one end.
struct Inbox {
    q: SpinLock<VecDeque<Message>>,
    len: AtomicUsize,
    /// Messages in the queue that carry channel ends.
    chans: AtomicUsize,
    /// The end owning this queue is closed (its last handle went away).
    closed: AtomicBool,
    /// Receivers wait for a message / the other side closing.
    readable: WaitQueue,
    /// Senders (the other side) wait for space / this end closing.
    writable: WaitQueue,
    /// `wait_many` on this queue (receiver – READABLE, senders –
    /// WRITABLE).
    obs: Observers,
}

impl Inbox {
    fn new() -> Inbox {
        Inbox {
            q: SpinLock::new("channel", level::PROCESS, VecDeque::new()),
            len: AtomicUsize::new(0),
            chans: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            readable: WaitQueue::new(),
            writable: WaitQueue::new(),
            obs: Observers::new(),
        }
    }

    /// After a state change: waiters in recv / send and in `wait_many`.
    fn wake_readers(&self) {
        self.readable.wake_all();
        self.obs.notify();
    }

    fn wake_writers(&self) {
        self.writable.wake_all();
        self.obs.notify();
    }
}

pub struct Channel {
    inbox: [Inbox; 2],
}

/// Channel end: receives from `inbox[side]`, sends to `inbox[1 - side]`.
pub struct ChanEnd {
    ch: Arc<Channel>,
    side: usize,
}

/// Receive error: a code or "buffer too small" with the required size.
pub enum RecvError {
    Code(i64),
    /// (bytes, handles) of the first message – it stays in the queue.
    TooSmall(usize, usize),
}

/// New channel: two ends.
pub fn new() -> (Arc<ChanEnd>, Arc<ChanEnd>) {
    let ch = Arc::new(Channel { inbox: [Inbox::new(), Inbox::new()] });
    LIVE_CHANNELS.fetch_add(1, Ordering::Relaxed);
    (Arc::new(ChanEnd { ch: ch.clone(), side: 0 }), Arc::new(ChanEnd { ch, side: 1 }))
}

impl ChanEnd {
    fn mine(&self) -> &Inbox {
        &self.ch.inbox[self.side]
    }

    fn peer(&self) -> &Inbox {
        &self.ch.inbox[1 - self.side]
    }

    /// Identity for `dcp`: (channel object, side 0 / 1) – which end of which
    /// channel; both ends share the first value.
    pub fn ident(&self) -> (u64, u64) {
        (Arc::as_ptr(&self.ch) as u64, self.side as u64)
    }

    /// The same channel (either end).  No end of a channel may
    /// travel through that channel: the end would land in its own queue
    /// (or a queue it holds itself) and would never be released.
    pub fn same_channel(&self, other: &ChanEnd) -> bool {
        Arc::ptr_eq(&self.ch, &other.ch)
    }

    /// Sends a message to the other side.  On error the message comes back (the handles
    /// in it return to the sender).
    pub fn send(&self, msg: Message, nonblock: bool) -> Result<(), (i64, Message)> {
        let peer = self.peer();
        let mut msg = Some(msg);
        loop {
            if peer.closed.load(Ordering::SeqCst) {
                return Err((EPIPE, msg.take().unwrap()));
            }
            {
                // A message with channel ends – none of them may have a message
                // with a channel in its own queue (otherwise a cycle is possible).
                let carries = msg.as_ref().unwrap().carries_channel();
                let _x = if carries { Some(XFER.lock()) } else { None };
                if carries && msg.as_ref().unwrap().channel_ends().any(|e| e.mine().chans.load(Ordering::SeqCst) > 0) {
                    return Err((EBUSY, msg.take().unwrap()));
                }
                let mut q = peer.q.lock();
                // Again under the queue lock: the receiver may have closed after
                // the check above.  Drop sets `closed` before taking this
                // lock and drains the queue under it – so either we see
                // `closed`, or its draining will take our message.
                if peer.closed.load(Ordering::SeqCst) {
                    drop(q);
                    return Err((EPIPE, msg.take().unwrap()));
                }
                if q.len() < QUEUE_MAX {
                    // Kernel buffer budget – above it ENOMEM, the message comes back.
                    if !super::kbuf::try_take(msg.as_ref().unwrap().cost()) {
                        drop(q);
                        return Err((ENOMEM, msg.take().unwrap()));
                    }
                    if carries {
                        peer.chans.fetch_add(1, Ordering::SeqCst);
                    }
                    q.push_back(msg.take().unwrap());
                    peer.len.store(q.len(), Ordering::SeqCst);
                    drop(q);
                    peer.wake_readers();
                    return Ok(());
                }
            }
            if nonblock {
                return Err((EAGAIN, msg.take().unwrap()));
            }
            peer.writable.wait_until(
                || {
                    peer.len.load(Ordering::SeqCst) < QUEUE_MAX
                        || peer.closed.load(Ordering::SeqCst)
                        || crate::sched::should_exit()
                },
                None,
            );
            if crate::sched::should_exit() {
                return Err((EINTR, msg.take().unwrap()));
            }
        }
    }

    /// Removes the first message if it fits in `cap` bytes and `hcap`
    /// handles.  Empty queue and the other side closed – EPIPE.
    /// `room` – free slots in the receiver's handle table: more handles in the
    /// message = EMFILE, the message stays.
    pub fn recv(&self, cap: usize, hcap: usize, room: usize, nonblock: bool) -> Result<Message, RecvError> {
        let mine = self.mine();
        loop {
            {
                let mut q = mine.q.lock();
                if let Some(front) = q.front() {
                    if front.data.len() > cap || front.handles.len() > hcap {
                        return Err(RecvError::TooSmall(front.data.len(), front.handles.len()));
                    }
                    if front.handles.len() > room {
                        return Err(RecvError::Code(super::syscalls::EMFILE));
                    }
                    let m = q.pop_front().unwrap();
                    super::kbuf::give(m.cost());
                    if m.carries_channel() {
                        mine.chans.fetch_sub(1, Ordering::SeqCst);
                    }
                    mine.len.store(q.len(), Ordering::SeqCst);
                    drop(q);
                    mine.wake_writers();
                    return Ok(m);
                }
            }
            if self.peer().closed.load(Ordering::SeqCst) {
                // The other side may have sent just before closing.
                if mine.len.load(Ordering::SeqCst) == 0 {
                    return Err(RecvError::Code(EPIPE));
                }
                continue;
            }
            if nonblock {
                return Err(RecvError::Code(EAGAIN));
            }
            let peer = self.peer();
            mine.readable.wait_until(
                || mine.len.load(Ordering::SeqCst) > 0 || peer.closed.load(Ordering::SeqCst) || crate::sched::should_exit(),
                None,
            );
            if crate::sched::should_exit() {
                return Err(RecvError::Code(EINTR));
            }
        }
    }
}

/// Kernel side (ublk) – receive with a deadline.
impl ChanEnd {
    /// Removes the first message (any size; the kernel releases the handles in
    /// it – the caller only reads the data).  Waits at most `timeout_ms`.
    /// Errors: ETIMEDOUT, EPIPE (other side closed, queue empty),
    /// EINTR (the task we wait in was killed).
    pub fn recv_timeout(&self, timeout_ms: u64) -> Result<Message, i64> {
        let mine = self.mine();
        let deadline = crate::time::ticks() + crate::time::ms_to_ticks(timeout_ms);
        loop {
            {
                let mut q = mine.q.lock();
                if let Some(m) = q.pop_front() {
                    super::kbuf::give(m.cost());
                    if m.carries_channel() {
                        mine.chans.fetch_sub(1, Ordering::SeqCst);
                    }
                    mine.len.store(q.len(), Ordering::SeqCst);
                    drop(q);
                    mine.wake_writers();
                    return Ok(m);
                }
            }
            if self.peer().closed.load(Ordering::SeqCst) {
                if mine.len.load(Ordering::SeqCst) == 0 {
                    return Err(EPIPE);
                }
                continue;
            }
            if crate::sched::should_exit() {
                return Err(EINTR);
            }
            let now = crate::time::ticks();
            if now >= deadline {
                return Err(super::syscalls::ETIMEDOUT);
            }
            let peer = self.peer();
            mine.readable.wait_until(
                || mine.len.load(Ordering::SeqCst) > 0 || peer.closed.load(Ordering::SeqCst) || crate::sched::should_exit(),
                Some(((deadline - now) * 1000 / crate::time::HZ as u64).max(1)),
            );
        }
    }

    /// The other side is closed (e.g. the usbd process has exited).
    pub fn peer_closed(&self) -> bool {
        self.peer().closed.load(Ordering::SeqCst)
    }
}

/// State for `wait_many`.
impl ChanEnd {
    /// There is a message or the other side is closed (recv will not block).
    pub fn readable(&self) -> bool {
        self.mine().len.load(Ordering::SeqCst) > 0 || self.peer().closed.load(Ordering::SeqCst)
    }

    /// There is room on the other side or it is closed (send will not block).
    pub fn writable(&self) -> bool {
        self.peer().len.load(Ordering::SeqCst) < QUEUE_MAX || self.peer().closed.load(Ordering::SeqCst)
    }

    /// Watchers: READABLE – own queue, WRITABLE – the other side's queue
    /// (closing the other side wakes both).
    pub fn observers(&self, write: bool) -> &Observers {
        if write { &self.peer().obs } else { &self.mine().obs }
    }
}

impl Drop for ChanEnd {
    fn drop(&mut self) {
        let mine = self.mine();
        mine.closed.store(true, Ordering::SeqCst);
        // Nobody will ever receive messages sent to a closed end – free them
        // (with the handles inside) outside the lock: dropping a handle may close another
        // channel and take its lock.
        let left: Vec<Message> = {
            let mut q = mine.q.lock();
            let v: Vec<Message> = q.drain(..).collect();
            super::kbuf::give(v.iter().map(|m| m.cost()).sum());
            mine.len.store(0, Ordering::SeqCst);
            mine.chans.store(0, Ordering::SeqCst);
            v
        };
        drop(left);
        // Senders to this end get EPIPE; the receiver on the other side gets EPIPE
        // when its queue is empty.
        mine.wake_writers();
        self.peer().wake_readers();
    }
}
