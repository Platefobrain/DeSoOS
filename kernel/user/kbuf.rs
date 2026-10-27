// Budget of kernel buffers occupied by processes – messages in
// channel queues and data in pipes.  They live on the kernel heap (64 MiB): without
// a budget a few processes could fill the heap with queues (64 messages × 4 KiB per
// queue, 64 handles per process) and the kernel would crash on the next allocation.
// Over budget: chan_send / pipe write – ERROR_OUT_OF_MEMORY (nothing is lost, the process
// can try again later).

use core::sync::atomic::{AtomicU64, Ordering::SeqCst};

pub const KBUF_MAX: u64 = 16 * 1024 * 1024;
/// Per-message overhead (structure, vectors) added to the data.
pub const MSG_OVERHEAD: u64 = 64;

static USED: AtomicU64 = AtomicU64::new(0);
static DENIED: AtomicU64 = AtomicU64::new(0);

/// All of `n` or nothing.
pub fn try_take(n: u64) -> bool {
    let ok = USED.fetch_update(SeqCst, SeqCst, |u| u.checked_add(n).filter(|&x| x <= KBUF_MAX)).is_ok();
    if !ok {
        DENIED.fetch_add(1, SeqCst);
    }
    ok
}

/// Up to `n` bytes (as much as fits) – returns the amount reserved.
pub fn take_upto(n: u64) -> u64 {
    let mut got = 0;
    let _ = USED.fetch_update(SeqCst, SeqCst, |u| {
        got = n.min(KBUF_MAX.saturating_sub(u));
        Some(u + got)
    });
    if got < n {
        DENIED.fetch_add(1, SeqCst);
    }
    got
}

pub fn give(n: u64) {
    USED.fetch_sub(n, SeqCst);
}

/// (bytes in use, refusals).
pub fn stats() -> (u64, u64) {
    (USED.load(SeqCst), DENIED.load(SeqCst))
}
