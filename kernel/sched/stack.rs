// M12: stosy zadań kernela – każdy we własnym "slocie" 1 MiB w obszarze
// TASK_STACKS_BASE (PML4[448]).  Zamapowane jest tylko górne STACK_SIZE
// slotu; cała reszta pod spodem jest pusta, więc przepełnienie stosu kończy
// się #PF (strona-strażnik), a nie nadpisaniem cudzej pamięci.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::memory::{alloc_frame, free_frame, kernel_data_flags, map_page, phys_to_virt};

pub const TASK_STACKS_BASE: u64 = 0xffff_e000_0000_0000;
const SLOT_SIZE: u64 = 1024 * 1024;
const MAX_SLOTS: usize = 4096;
pub const STACK_SIZE: u64 = 64 * 1024;
const PAGE: u64 = 4096;

// 1 bit na slot (1 = zajęty).
static SLOTS: [AtomicU64; MAX_SLOTS / 64] = [const { AtomicU64::new(0) }; MAX_SLOTS / 64];

// M17b.g: pamięć zwolnionych stosów.  Zakończone zadanie zostawia swój stos
// zamapowany (bit w MAPPED, slot wolny w SLOTS) – następny spawn bierze go bez
// alokacji i zerowania 16 ramek, a reap bez odmapowania i TLB shootdown na
// wszystkie CPU – wszystko to wcześniej pod globalną blokadą `stack-pages`
// (QEMU 8 CPU: 38% czasu CPU na czekaniu na nią).
// Niezmiennik: wolny slot z bitem MAPPED jest w całości zamapowany (bit
// ustawiany po mapowaniu, kasowany przed odmapowaniem – oba przy zajętym slocie).
static MAPPED: [AtomicU64; MAX_SLOTS / 64] = [const { AtomicU64::new(0) }; MAX_SLOTS / 64];
/// Ile stosów czeka zamapowanych na ponowne użycie.
static CACHED: AtomicUsize = AtomicUsize::new(0);
/// Najwyżej tyle stosów w pamięci (x 64 KiB = 16 MiB).
const CACHE_MAX: usize = 256;

/// Najniższy wolny slot (jak przed M17b.g – te same tablice stron) i czy ma
/// jeszcze zamapowany stos z pamięci stosów.
fn take_slot() -> Option<(usize, bool)> {
    // M17a.f2: compare_exchange – spawn działa bez BKL na wielu CPU naraz
    // (wcześniej load + store pod BKL).
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

/// Odmapowuje wszystkie stosy z pamięci stosów (jak przed M17b.g) – testy
/// wycieku ramek liczą wolne ramki bez nich.
pub fn flush_cache() {
    for (w, word) in SLOTS.iter().enumerate() {
        let mut m = MAPPED[w].load(Ordering::Acquire) & !word.load(Ordering::Relaxed);
        while m != 0 {
            let bit = m.trailing_zeros() as usize;
            m &= m - 1;
            let b = 1u64 << bit;
            // Zajęcie slotu: tylko wolny i nadal zamapowany.
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

/// M17a.f2: mapowanie i zdejmowanie stron stosów – tablice stron obszaru
/// stosów (PML4[448]) są wspólne dla sąsiednich slotów, a spawn i sprzątanie
/// działają już bez BKL na wielu CPU naraz.
static STACK_PAGES: crate::sched::spin::IrqSpinLock<()> =
    crate::sched::spin::IrqSpinLock::new("stack-pages", crate::sched::spin::level::PAGING, ());

fn release_slot(slot: usize) {
    SLOTS[slot / 64].fetch_and(!(1 << (slot % 64)), Ordering::Relaxed);
}

/// Ile slotów stosów jest zajętych (diagnostyka: `mem`).
pub fn used_slots() -> (usize, usize) {
    (SLOTS.iter().map(|w| w.load(Ordering::Relaxed).count_ones() as usize).sum(), MAX_SLOTS)
}

pub struct TaskStack {
    slot: usize,
}

impl TaskStack {
    /// Alokuje i mapuje stos (wyzerowany).
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
        // M17a.b: jeden shootdown na paczkę stron, ramki oddane po nim.
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
        // Miejsce w pamięci stosów – slot wolny, ale zamapowany.
        if CACHED.fetch_add(1, Ordering::Relaxed) < CACHE_MAX {
            release_slot(self.slot);
            return;
        }
        CACHED.fetch_sub(1, Ordering::Relaxed);
        self.unmap_locked();
        release_slot(self.slot);
    }
}

/// Czy adres leży w niezamapowanej części slotu stosu zadania (pod stosem).
pub fn is_guard(address: u64) -> bool {
    let end = TASK_STACKS_BASE + MAX_SLOTS as u64 * SLOT_SIZE;
    (TASK_STACKS_BASE..end).contains(&address)
        && (address - TASK_STACKS_BASE) % SLOT_SIZE < SLOT_SIZE - STACK_SIZE
}

/// Wolne ramki po `flush_cache` (testy wycieku, stress).
pub fn free_frames_flushed() -> u64 {
    flush_cache();
    crate::memory::free_frame_count()
}
