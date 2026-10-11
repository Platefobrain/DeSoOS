// M17a krok b: TLB shootdown.
//
// Każdy CPU trzyma w TLB tłumaczenia adresów.  Gdy jeden CPU zdejmuje albo
// zmienia mapowanie w GÓRNEJ połowie (kernel: heap, stosy zadań, MMIO –
// wspólna dla wszystkich PML4), pozostałe mogą mieć stary wpis i pisać do
// ramki, którą alokator oddał już komuś innemu.  Dlatego:
//
//     wyczyść PTE  ->  shootdown (IPI + czekanie na potwierdzenie)  ->  free_frame
//
// Dolna połowa (proces) shootdownu nie potrzebuje, dopóki procesy są
// jednowątkowe: proces działa naraz na jednym CPU, a CPU, który go opuszcza,
// zawsze ładuje inny CR3 (inne zadanie, zadanie kernela, idle), co bez PCID
// i bez stron global czyści wszystkie jego wpisy.  Wątki / wspólna pamięć
// (M17b) – maska `active_cpus` przestrzeni adresowej, patrz ARCHITEKTURA.md.
//
// Mechanizm: jedno żądanie naraz (blokada `LOCK`), zakres w atomikach,
// `PENDING` = maska CPU, które jeszcze nie potwierdziły.  Odbiorca: wektor
// 0x43 – BEZ BKL (inicjator zwykle trzyma BKL, czekałby na nas w nieskończoność)
// i bez blokad.  Pułapka: CPU czekający z IF = 0 (na BKL, na spinlock, na
// samą blokadę shootdown) nie odbierze IPI – każda taka pętla woła `poll()`,
// który obsługuje żądanie skierowane do tego CPU.

use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};

use super::cpu::{self, MAX_CPUS};
use super::{clock, interrupts, lapic, smp};

/// Wektor IPI "unieważnij TLB" (0x40 timer, 0x41 resched, 0x42 halt).
pub const TLB_VECTOR: u8 = 0x43;

/// Powyżej tylu stron – pełny flush (przeładowanie CR3) zamiast `invlpg`.
const MAX_INVLPG: u64 = 32;

/// Po tylu µs czekania na potwierdzenie – raport (kto nie odpowiada).
const REPORT_US: u64 = 1_000_000;

const PAGE: u64 = 4096;

/// Właściciel żądania (numer CPU + 1; 0 = wolne).
static LOCK: AtomicU32 = AtomicU32::new(0);
/// Zakres żądania: początek i liczba stron (0 = pełny flush).
static REQ_START: AtomicU64 = AtomicU64::new(0);
static REQ_PAGES: AtomicU64 = AtomicU64::new(0);
/// CPU, które jeszcze nie unieważniły wpisów.
static PENDING: AtomicU16 = AtomicU16::new(0);

// Statystyka (`cpus`, testy).
static REQUESTS: AtomicU64 = AtomicU64::new(0);
static IPIS_SENT: AtomicU64 = AtomicU64::new(0);
static FULL_FLUSHES: AtomicU64 = AtomicU64::new(0);
static WAIT_US: AtomicU64 = AtomicU64::new(0);
static HANDLED: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static POLLED: AtomicU64 = AtomicU64::new(0);


#[inline]
fn invlpg(va: u64) {
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags)) };
}

/// Przeładowanie CR3 – czyści wszystkie wpisy TLB (kernel nie używa stron
/// global, więc także górnej połowy).
#[inline]
pub fn flush_all_local() {
    unsafe {
        core::arch::asm!("mov {0}, cr3", "mov cr3, {0}", out(reg) _, options(nostack, preserves_flags));
    }
}

fn flush_local(start: u64, pages: u64) {
    if pages == 0 || pages > MAX_INVLPG {
        flush_all_local();
    } else {
        for i in 0..pages {
            invlpg(start + i * PAGE);
        }
    }
}

/// Obsługuje żądanie skierowane do tego CPU (jeśli jest).  Bez blokad i bez
/// BKL – wołane z handlera 0x43 i z każdej pętli czekania z IF = 0.
#[inline]
pub fn poll() -> bool {
    // Z IF = 0: część pętli czekania (SpinLock, konsola) działa z IF = 1 –
    // IPI w środku obsłużyłby żądanie drugi raz, a powrót tutaj skasowałby
    // bit NASTĘPNEGO żądania bez unieważnienia jego zakresu.
    interrupts::without_interrupts(|| {
        let me = cpu::id();
        let bit = 1u16 << me;
        if PENDING.load(Ordering::Acquire) & bit == 0 {
            return false;
        }
        flush_local(REQ_START.load(Ordering::Relaxed), REQ_PAGES.load(Ordering::Relaxed));
        HANDLED[me].fetch_add(1, Ordering::Relaxed);
        PENDING.fetch_and(!bit, Ordering::AcqRel);
        true
    })
}

/// Handler wektora 0x43 (exceptions.rs, przed BKL).
pub fn on_ipi() {
    poll();
    lapic::eoi();
}

/// Unieważnia `pages` stron od `start` (0 stron = wszystko) w GÓRNEJ połowie
/// na wszystkich CPU – po powrocie żaden CPU nie ma starego wpisu, więc
/// ramkę wolno oddać alokatorowi.  Można wołać z IF = 0 i z BKL.
pub fn flush_kernel(start: u64, pages: u64) {
    // Także w trakcie startu AP (zanim SMP jest "active"): AP, który już
    // jest online, mógł zapamiętać wpisy.  AP zaczyna od pełnego flusha
    // pod BKL (smp::ap_entry), a ONLINE ustawia, wciąż trzymając BKL.
    if smp::panicking() {
        flush_local(start, pages);
        return;
    }
    shootdown(start, pages);
}

/// Pełny flush górnej połowy na wszystkich CPU (np. zwolniona tablica stron).
pub fn flush_kernel_all() {
    flush_kernel(0, 0);
}

fn shootdown(start: u64, pages: u64) {
    interrupts::without_interrupts(|| {
        // Cele liczone z IF = 0: wcześniej (z IF = 1) zadanie mogło się
        // przenieść na inny CPU i czekać na potwierdzenie od samego siebie
        // (znalezione TLB TEST 4: "CPU 0 waits ... from CPU mask 0b1").
        let cpu_now = cpu::id();
        let mut targets: u16 = 0;
        for c in 0..MAX_CPUS {
            if c != cpu_now && smp::online(c) {
                targets |= 1 << c;
            }
        }
        if targets == 0 {
            flush_local(start, pages);
            return;
        }
        let me = cpu_now as u32 + 1;
        // Jeden inicjator naraz.  Czekając, potwierdzamy cudze żądania –
        // inaczej dwaj inicjatorzy czekaliby na siebie nawzajem.
        while LOCK.compare_exchange_weak(0, me, Ordering::Acquire, Ordering::Relaxed).is_err() {
            poll_from_wait();
            core::hint::spin_loop();
        }
        REQUESTS.fetch_add(1, Ordering::Relaxed);
        if pages == 0 || pages > MAX_INVLPG {
            FULL_FLUSHES.fetch_add(1, Ordering::Relaxed);
        }
        REQ_START.store(start, Ordering::Relaxed);
        REQ_PAGES.store(pages, Ordering::Relaxed);
        PENDING.store(targets, Ordering::Release);
        for c in 0..MAX_CPUS {
            if targets & (1 << c) != 0 {
                lapic::send_ipi(smp::apic_id(c), TLB_VECTOR);
                IPIS_SENT.fetch_add(1, Ordering::Relaxed);
            }
        }
        flush_local(start, pages);
        let t0 = clock::stamp();
        let mut n: u32 = 0;
        let mut reported = false;
        while PENDING.load(Ordering::Acquire) != 0 {
            core::hint::spin_loop();
            n = n.wrapping_add(1);
            if n % 4096 == 0 {
                smp::watchdog_poll();
                if smp::panicking() {
                    break;
                }
                if !reported && clock::elapsed_us(t0) > REPORT_US {
                    reported = true;
                    crate::serial_println!(
                        "[TLB] CPU {} waits {} ms for shootdown ack from CPU mask {:#b} ({:#x}, {} pages)",
                        cpu::id(),
                        clock::elapsed_us(t0) / 1000,
                        PENDING.load(Ordering::Relaxed),
                        start,
                        pages
                    );
                }
            }
        }
        WAIT_US.fetch_add(clock::elapsed_us(t0), Ordering::Relaxed);
        LOCK.store(0, Ordering::Release);
    });
}

/// (żądania, wysłane IPI, pełne flushe, µs czekania na potwierdzenia,
///  obsłużone przez wszystkie CPU) – `cpus`, testy.
pub fn stats() -> (u64, u64, u64, u64, u64) {
    let handled = HANDLED.iter().map(|h| h.load(Ordering::Relaxed)).sum();
    (
        REQUESTS.load(Ordering::Relaxed),
        IPIS_SENT.load(Ordering::Relaxed),
        FULL_FLUSHES.load(Ordering::Relaxed),
        WAIT_US.load(Ordering::Relaxed),
        handled,
    )
}

/// Ile żądań obsłużył CPU `c`.
#[allow(dead_code)]
pub fn handled_by(c: usize) -> u64 {
    HANDLED[c % MAX_CPUS].load(Ordering::Relaxed)
}

/// Z pętli czekania z IF = 0 (BKL, spinlocki, konsola): `poll` + licznik.
#[inline]
pub fn poll_from_wait() {
    if PENDING.load(Ordering::Relaxed) != 0 && poll() {
        POLLED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Ile żądań obsłużono w pętlach czekania (zamiast w handlerze IPI).
#[allow(dead_code)]
pub fn polled() -> u64 {
    POLLED.load(Ordering::Relaxed)
}
