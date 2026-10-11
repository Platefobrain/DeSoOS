// M17: numer bieżącego procesora.
//
// Każdy CPU ma w MSR IA32_TSC_AUX swój numer (0 = procesor startowy, BSP,
// 1.. = kolejne uruchomione rdzenie); `rdtscp` zwraca go w ECX.  To szybkie
// i nie zależy od rejestru GS (w kernelu GS należy do procesu – swapgs
// robimy tylko na kilka instrukcji wejścia SYSCALL).

use core::sync::atomic::{AtomicBool, Ordering};

/// Najwięcej obsługiwanych procesorów (Ryzen 7 4800H = 16 wątków).
pub const MAX_CPUS: usize = 16;

const IA32_TSC_AUX: u32 = 0xC000_0103;

static RDTSCP: AtomicBool = AtomicBool::new(false);

/// Wykrywa RDTSCP i ustawia numer BSP (0).  Na samym początku startu.
pub fn init_bsp() {
    #[allow(unused_unsafe)]
    let ok = unsafe { core::arch::x86_64::__cpuid(0x8000_0001) }.edx & (1 << 27) != 0;
    if ok {
        set_id(0);
    }
    RDTSCP.store(ok, Ordering::SeqCst);
}

/// Czy da się rozróżniać procesory (warunek SMP).
pub fn has_rdtscp() -> bool {
    RDTSCP.load(Ordering::Relaxed)
}

/// Zapisuje numer procesora (każdy CPU u siebie).
pub fn set_id(cpu: usize) {
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") IA32_TSC_AUX, in("eax") cpu as u32, in("edx") 0u32,
            options(nostack, preserves_flags));
    }
}

/// Numer bieżącego procesora (0 bez RDTSCP – tylko BSP).
#[inline]
pub fn id() -> usize {
    if !RDTSCP.load(Ordering::Relaxed) {
        return 0;
    }
    let aux: u32;
    unsafe {
        core::arch::asm!("rdtscp", out("ecx") aux, out("eax") _, out("edx") _, options(nomem, nostack, preserves_flags));
    }
    (aux as usize) % MAX_CPUS
}

// ------------------------------------------------------------
// M17a: wstrzymanie wywłaszczania i "jestem w przerwaniu" (per CPU)
// ------------------------------------------------------------

use core::sync::atomic::AtomicU32;

static PREEMPT: crate::arch::x86_64::percpu::PerCpu<AtomicU32> = crate::per_cpu!(AtomicU32::new(0));
static IN_IRQ: crate::arch::x86_64::percpu::PerCpu<AtomicBool> = crate::per_cpu!(AtomicBool::new(false));

/// Wstrzymuje wywłaszczanie tego CPU (zagnieżdżalne) – SpinLock.
#[allow(dead_code)]
#[inline]
pub fn preempt_disable() {
    // Odczyt numeru CPU i zwiększenie licznika muszą być niepodzielne:
    // przerwanie zegara pomiędzy nimi mogłoby przenieść zadanie na inny
    // CPU, a licznik wzrósłby na starym (zadanie trzymałoby blokadę, dając
    // się wywłaszczyć).  Po zwiększeniu zadanie już się nie przeniesie, więc
    // preempt_enable tego nie potrzebuje.
    super::interrupts::without_interrupts(|| {
        PREEMPT[id()].fetch_add(1, Ordering::Relaxed);
    });
}

#[allow(dead_code)]
#[inline]
pub fn preempt_enable() {
    let old = PREEMPT[id()].fetch_sub(1, Ordering::Relaxed);
    assert!(old > 0, "preempt_enable without preempt_disable on CPU {}", id());
}

/// Licznik wywłaszczania i flaga przerwania dowolnego CPU (raport watchdoga).
pub fn preempt_count_of(c: usize) -> u32 {
    PREEMPT[c % MAX_CPUS].load(Ordering::Relaxed)
}

pub fn in_interrupt_of(c: usize) -> bool {
    IN_IRQ[c % MAX_CPUS].load(Ordering::Relaxed)
}

/// > 0: tick zegara nie przełączy zadania na tym CPU (NEED_RESCHED czeka).
#[inline]
pub fn preempt_count() -> u32 {
    PREEMPT[id()].load(Ordering::Relaxed)
}

static IRQ_HAD_BKL: crate::arch::x86_64::percpu::PerCpu<AtomicBool> = crate::per_cpu!(AtomicBool::new(false));

/// Czy kontekst przerwany przez bieżące przerwanie trzymał BKL (exceptions.rs
/// ustawia przy wejściu; irq::after_interrupt oddaje BKL tylko wtedy).
pub fn set_irq_had_bkl(v: bool) {
    IRQ_HAD_BKL[id()].store(v, Ordering::Relaxed);
}

pub fn irq_had_bkl() -> bool {
    IRQ_HAD_BKL[id()].load(Ordering::Relaxed)
}

/// Wejście / wyjście z handlera przerwania sprzętowego (exceptions.rs, irq.rs).
#[inline]
pub fn set_in_interrupt(v: bool) {
    IN_IRQ[id()].store(v, Ordering::Relaxed);
}

/// Czy ten CPU wykonuje teraz handler przerwania (przed `after_interrupt`).
#[allow(dead_code)]
#[inline]
pub fn in_interrupt() -> bool {
    IN_IRQ[id()].load(Ordering::Relaxed)
}
