// Control of the IF flag (maskable hardware interrupts).
//
// `without_interrupts` is the single-core equivalent of a lock: the code inside
// will not be interrupted by an IRQ.  Nesting is safe – on
// exit the IF state from before entry is restored (not a blind `sti`).

use core::arch::asm;

const RFLAGS_IF: u64 = 1 << 9;

#[inline]
pub fn enable() {
    unsafe {
        // No `nomem`: sti/cli/hlt must be a compiler barrier – an interrupt
        // can change memory (keyboard and serial queues, ticks), so reads
        // must not be moved across these instructions or cached.
        asm!("sti", options(nostack));
    }
}

#[inline]
pub fn disable() {
    unsafe {
        asm!("cli", options(nostack));
    }
}

#[inline]
pub fn are_enabled() -> bool {
    let rflags: u64;
    unsafe {
        asm!("pushfq", "pop {}", out(reg) rflags, options(nomem, preserves_flags));
    }
    rflags & RFLAGS_IF != 0
}

/// `sti; hlt` as one sequence: `sti` enables interrupts only after
/// the next instruction, so an IRQ cannot "slip in" between them and be
/// missed (the CPU always wakes up from hlt).
///
/// While sleeping the CPU gives up the Big Kernel Lock (otherwise another CPU that
/// handles the interrupt needed for the wakeup would wait for the lock
/// forever).  After waking it takes it back – usually it is already held by
/// the handler of the interrupt that woke the CPU (it interrupted kernel code, so it
/// did not release it).  Returns with interrupts enabled, like a plain `sti; hlt`.
#[inline]
#[allow(dead_code)]
pub fn enable_and_hlt() {
    debug_assert!(crate::sched::spin::held_count() == 0, "hlt while holding a spinlock");
    let had = crate::sched::bkl::held();
    if had {
        disable();
        crate::sched::bkl::release();
    }
    unsafe {
        asm!("sti", "hlt", options(nostack));
    }
    if had {
        disable();
        crate::sched::bkl::acquire_if_needed_tagged(&crate::sched::bkl::tag::HLT_WAKE);
        enable();
    }
}

/// Runs `f` with interrupts disabled and restores the previous IF state.
#[inline]
pub fn without_interrupts<R>(f: impl FnOnce() -> R) -> R {
    let was_enabled = are_enabled();
    if was_enabled {
        disable();
    }
    let result = f();
    if was_enabled {
        enable();
    }
    result
}
