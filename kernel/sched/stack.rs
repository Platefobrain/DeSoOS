// Kernel task stacks – each in its own 1 MiB "slot" in the
// TASK_STACKS_BASE region (PML4[448]).  Only the top STACK_SIZE of the
// slot is mapped; everything below is empty, so a stack overflow ends
// in a #PF (guard page) rather than overwriting someone else's memory.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::memory::{alloc_frame, free_frame, kernel_data_flags, map_page, phys_to_virt};

pub const TASK_STACKS_BASE: u64 = 0xffff_e000_0000_0000;
const SLOT_SIZE: u64 = 1024 * 1024;
const MAX_SLOTS: usize = 4096;
pub const STACK_SIZE: u64 = 64 * 1024;
const PAGE: u64 = 4096;

// 1 bit per slot (1 = taken).
static SLOTS: [AtomicU64; MAX_SLOTS / 64] = [const { AtomicU64::new(0) }; MAX_SLOTS / 64];

// Cache of freed stacks.  A finished task leaves its stack
// mapped (bit in MAPPED, slot free in SLOTS) – the next spawn takes it without
// allocating and zeroing 16 frames, and reap skips the unmapping and the TLB shootdown to
// all CPUs – all of which used to happen under the global `stack-pages` lock
// (QEMU with 8 CPUs: 38% of CPU time spent waiting for it).
// Invariant: a free slot with the MAPPED bit is fully mapped (the bit is
// set after mapping, cleared before unmapping – both while the slot is taken).
static MAPPED: [AtomicU64; MAX_SLOTS / 64] = [const { AtomicU64::new(0) }; MAX_SLOTS / 64];
/// How many mapped stacks are waiting for reuse.
static CACHED: AtomicUsize = AtomicUsize::new(0);
/// At most this many stacks are cached (x 64 KiB = 16 MiB).
const CACHE_MAX: usize = 256;

/// The lowest free slot (as without the cache – the same page tables) and whether it
/// still has a mapped stack from the stack cache.
fn take_slot() -> Option<(usize, bool)> {
    // compare_exchange – spawn runs without the BKL on many CPUs at once
    // (a plain load + store is only safe under the BKL).
    for (w, word) in SLOTS.iter().enumerate() {
        let mut v = word.load(Ordering::Relaxed);
        while v != u64::MAX {
            let bit = (!v).trailing_zeros() as usize;
            match word.compare_exchange_weak(v, v | (1 << bit), Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return Some((w * 64 + bit, MAPPED[w].load(Ordering::Acquire) & (1 << bit) != 0)),
                Err(now) => v = now,
            }
        }
    }
    None
}

/// Unmaps all stacks from the stack cache (as without the cache) – frame
/// leak tests count free frames without them.
pub fn flush_cache() {
    for (w, word) in SLOTS.iter().enumerate() {
        let mut m = MAPPED[w].load(Ordering::Acquire) & !word.load(Ordering::Relaxed);
        while m != 0 {
            let bit = m.trailing_zeros() as usize;
            m &= m - 1;
            let b = 1u64 << bit;
            // Taking a slot: only if free and still mapped.
            if word.fetch_or(b, Ordering::AcqRel) & b != 0 {
                continue;
            }
            if MAPPED[w].load(Ordering::Acquire) & b == 0 {
                release_slot(w * 64 + bit);
                continue;
            }
            CACHED.fetch_sub(1, Ordering::Relaxed);
            let stack = TaskStack { slot: w * 64 + bit };
            stack.unmap_locked();
            release_slot(stack.slot);
            core::mem::forget(stack);
        }
    }
}

/// Mapping and unmapping of stack pages – the page tables of the stack
/// region (PML4[448]) are shared by neighbouring slots, and spawn and cleanup
/// run without the BKL on many CPUs at once.
static STACK_PAGES: crate::sched::spin::IrqSpinLock<()> =
    crate::sched::spin::IrqSpinLock::new("stack-pages", crate::sched::spin::level::PAGING, ());

fn release_slot(slot: usize) {
    SLOTS[slot / 64].fetch_and(!(1 << (slot % 64)), Ordering::Relaxed);
}

/// How many stack slots are taken (diagnostics: `mem`).
pub fn used_slots() -> (usize, usize) {
    (SLOTS.iter().map(|w| w.load(Ordering::Relaxed).count_ones() as usize).sum(), MAX_SLOTS)
}

pub struct TaskStack {
    slot: usize,
}

impl TaskStack {
    /// Allocates and maps a stack (zeroed).
    pub fn new() -> Option<Self> {
        let (slot, mapped) = take_slot()?;
        if mapped {
            CACHED.fetch_sub(1, Ordering::Relaxed);
            return Some(TaskStack { slot });
        }
        let _pages = STACK_PAGES.lock();
        let stack = TaskStack { slot };
        let bottom = stack.bottom();
        let mut va = bottom;
        while va < stack.top() {
            let Some(frame) = alloc_frame() else {
                stack.unmap_from(bottom, va);
                release_slot(slot);
                core::mem::forget(stack);
                return None;
            };
            unsafe { core::ptr::write_bytes(phys_to_virt(frame) as *mut u8, 0, PAGE as usize) };
            if !map_page(va, frame, kernel_data_flags()) {
                free_frame(frame);
                stack.unmap_from(bottom, va);
                release_slot(slot);
                core::mem::forget(stack);
                return None;
            }
            va += PAGE;
        }
        MAPPED[slot / 64].fetch_or(1 << (slot % 64), Ordering::Release);
        Some(stack)
    }

    pub fn top(&self) -> u64 {
        TASK_STACKS_BASE + (self.slot as u64 + 1) * SLOT_SIZE
    }

    pub fn bottom(&self) -> u64 {
        self.top() - STACK_SIZE
    }

    fn unmap_from(&self, from: u64, to: u64) {
        // One shootdown per batch of pages, frames returned after it.
        crate::memory::unmap_range_free(from, to);
    }

    fn unmap_locked(&self) {
        MAPPED[self.slot / 64].fetch_and(!(1 << (self.slot % 64)), Ordering::Release);
        let _pages = STACK_PAGES.lock();
        self.unmap_from(self.bottom(), self.top());
    }
}

impl Drop for TaskStack {
    fn drop(&mut self) {
        // Room in the stack cache – the slot is free but stays mapped.
        if CACHED.fetch_add(1, Ordering::Relaxed) < CACHE_MAX {
            release_slot(self.slot);
            return;
        }
        CACHED.fetch_sub(1, Ordering::Relaxed);
        self.unmap_locked();
        release_slot(self.slot);
    }
}

/// Whether the address lies in the unmapped part of a task's stack slot (below the stack).
pub fn is_guard(address: u64) -> bool {
    let end = TASK_STACKS_BASE + MAX_SLOTS as u64 * SLOT_SIZE;
    (TASK_STACKS_BASE..end).contains(&address)
        && (address - TASK_STACKS_BASE) % SLOT_SIZE < SLOT_SIZE - STACK_SIZE
}

/// Free frames after `flush_cache` (leak tests, stress).
pub fn free_frames_flushed() -> u64 {
    flush_cache();
    crate::memory::free_frame_count()
}
