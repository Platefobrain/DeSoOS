// M5: sterowanie flagą IF (maskowalne przerwania sprzętowe).
//
// `without_interrupts` to jednordzeniowy odpowiednik blokady: kod w środku
// nie zostanie przerwany przez IRQ.  Zagnieżdżanie jest bezpieczne – na
// wyjściu przywracany jest stan IF sprzed wejścia (a nie ślepe `sti`).

use core::arch::asm;

const RFLAGS_IF: u64 = 1 << 9;

#[inline]
pub fn enable() {
    unsafe {
        // Bez `nomem`: sti/cli/hlt muszą być barierą dla kompilatora – przerwanie
        // może zmienić pamięć (kolejki klawiatury, seriala, ticki), więc odczyty
        // nie mogą być przenoszone przez te instrukcje ani zapamiętywane.
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

/// `sti; hlt` jako jedna sekwencja: `sti` włącza przerwania dopiero po
/// następnej instrukcji, więc IRQ nie może "wskoczyć" między nie i zostać
/// przegapione (CPU zawsze obudzi się z hlt).
///
/// M17: na czas snu CPU oddaje Big Kernel Lock (inaczej inny CPU, który
/// obsługuje przerwanie potrzebne do pobudki, czekałby na blokadę w
/// nieskończoność).  Po pobudce bierze ją z powrotem – zwykle ma ją już
/// handler przerwania, które obudziło CPU (przerwał kod kernela, więc jej
/// nie oddał).  Wraca z włączonymi przerwaniami, jak zwykłe `sti; hlt`.
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

/// Uruchamia `f` z wyłączonymi przerwaniami i przywraca poprzedni stan IF.
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
