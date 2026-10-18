// v0.35.2: budżet buforów jądra zajmowanych przez procesy – komunikaty w
// kolejkach kanałów i dane w potokach.  Leżą na heapie jądra (64 MiB): bez
// budżetu kilka procesów zapełniłoby heap kolejkami (64 komunikaty × 4 KiB na
// kolejkę, 64 uchwyty na proces) i jądro padłoby przy następnej alokacji.
// Ponad budżetem: chan_send / zapis do potoku – ENOMEM (nic nie ginie, proces
// może spróbować później).

use core::sync::atomic::{AtomicU64, Ordering::SeqCst};

pub const KBUF_MAX: u64 = 16 * 1024 * 1024;
/// Narzut na komunikat (struktura, wektory) doliczany do danych.
pub const MSG_OVERHEAD: u64 = 64;

static USED: AtomicU64 = AtomicU64::new(0);
static DENIED: AtomicU64 = AtomicU64::new(0);

/// Całe `n` albo nic.
pub fn try_take(n: u64) -> bool {
    let ok = USED.fetch_update(SeqCst, SeqCst, |u| u.checked_add(n).filter(|&x| x <= KBUF_MAX)).is_ok();
    if !ok {
        DENIED.fetch_add(1, SeqCst);
    }
    ok
}

/// Do `n` bajtów (ile się mieści) – zwraca zarezerwowane.
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

/// (zajęte bajty, odmowy).
pub fn stats() -> (u64, u64) {
    (USED.load(SeqCst), DENIED.load(SeqCst))
}
