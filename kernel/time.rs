// M5: zegar systemowy – ticki z PIT (IRQ0), uptime, sleep.
//
// PIT kanał 0 -> IRQ0 -> on_tick(): TICKS += 1 (+ opcjonalny hook, np. dla
// schedulera w M12).  Wszystko, co tu jest, zakłada jeden rdzeń.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::arch::x86_64::{interrupts, irq, pit};
use crate::serial_println;

/// Docelowa częstotliwość ticków (1 tick ≈ 1 ms).
pub const HZ: u32 = 1000;

const TIMER_IRQ: u8 = 0;

static TICKS: AtomicU64 = AtomicU64::new(0);
// fn(u64) jako usize; 0 = brak hooka.
static TICK_HOOK: AtomicUsize = AtomicUsize::new(0);

pub type TickHook = fn(ticks: u64);

/// M17a: licznik ticków zwiększany jeszcze PRZED Big Kernel Lock
/// (exceptions.rs, wektor IRQ0) – czas systemu idzie dokładnie także wtedy,
/// gdy przerwanie zegara czeka w kolejce do BKL.  Reszta ticku (budzenie
/// zadań, kwant) – w on_tick, już pod BKL.
pub fn pit_tick_early() {
    // M17a.b: ticki doganiają zegar HPET.  CPU 0 czekający na BKL z IF = 0
    // gubił przerwania PIT (kontroler trzyma tylko jedno oczekujące), więc
    // przy zatorze czas systemu stał: u Dawida 10 s testu trwało 99 s,
    // `stress 30` – ~115 s.  Teraz przerwanie PIT jest tylko "budzikiem":
    // każde dodaje co najmniej 1 tick (jak dotąd), a gdy HPET mówi, że
    // minęło więcej milisekund, brakujące ticki są dodawane od razu.
    //
    // Tylko przy SMP: na jednym CPU przerwania giną wyłącznie wtedy, gdy
    // emulator nie dostaje czasu od hosta – testy z ciasnymi limitami
    // (sleep 30 ms -> 30..40) mierzyłyby wtedy przestoje hosta.
    use crate::arch::x86_64::{clock, smp};
    let mut n: u64 = 1;
    if !smp::active() {
        HPET_LAST.store(0, Ordering::Relaxed);
    } else if clock::hpet() {
        let now = clock::stamp();
        let last = HPET_LAST.swap(now, Ordering::Relaxed);
        if last != 0 {
            let d = clock::diff_us(last, now).clamp(0, 10_000_000);
            let mut acc = HPET_ACC_US.load(Ordering::Relaxed) + d;
            let due = (acc / 1000).max(0) as u64;
            n = due.clamp(1, 10_000);
            acc -= n as i64 * 1000;
            // Zapas ujemny (PIT minimalnie szybszy niż HPET) nie rośnie bez końca.
            HPET_ACC_US.store(acc.max(-5_000), Ordering::Relaxed);
            if n > 1 {
                CAUGHT_UP.fetch_add(n - 1, Ordering::Relaxed);
            }
        }
    }
    TICKS.fetch_add(n, Ordering::Relaxed);
}

/// M17a.b: HPET przy poprzednim przerwaniu PIT i niedoliczone mikrosekundy.
static HPET_LAST: AtomicU64 = AtomicU64::new(0);
static HPET_ACC_US: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
/// Ile ticków dodano za zgubione przerwania PIT (`cpus`, testy).
static CAUGHT_UP: AtomicU64 = AtomicU64::new(0);

/// Ticki dodane za zgubione przerwania PIT (doganianie HPET).
pub fn caught_up_ticks() -> u64 {
    CAUGHT_UP.load(Ordering::Relaxed)
}

fn on_tick(_irq: u8) {
    let now = TICKS.load(Ordering::Relaxed);
    // M12: kwant czasu i budzenie śpiących zadań.
    crate::sched::on_tick(now);
    // M16b: klawiatura PS/2 także bez IRQ1 (laptopy) – odpytywanie portu.
    // M17a.g4: tick działa bez BKL, a dekoder klawiatury i wejście shella
    // są jeszcze pod BKL – odpytujemy tylko, gdy BKL jest wolny od ręki
    // (inaczej przy następnym ticku odpytywania; IRQ1 bierze go normalnie).
    // Gdy przerwany kontekst już go trzyma, przerwanie może z niego korzystać.
    if crate::drivers::keyboard::poll_due(now) {
        use crate::sched::bkl;
        if bkl::held() {
            crate::drivers::keyboard::poll_tick(now);
        } else if bkl::try_acquire_tagged(&bkl::tag::KBD_POLL) {
            crate::drivers::keyboard::poll_tick(now);
            bkl::release();
        }
    }
    let hook = TICK_HOOK.load(Ordering::Acquire);
    if hook != 0 {
        let hook: TickHook = unsafe { core::mem::transmute(hook) };
        hook(now);
    }
}

/// Programuje PIT, rejestruje handler IRQ0 i odmaskowuje linię.
/// Przerwania włącza wołający (`interrupts::enable()`).
pub fn init() {
    let actual = pit::init(HZ);
    if !irq::register(TIMER_IRQ, on_tick) {
        panic!("time: IRQ0 already has a handler");
    }
    irq::unmask(TIMER_IRQ);

    let mhz = pit::actual_frequency_millihz();
    serial_println!(
        "[TIME] PIT channel 0: divisor {}, {}.{:03} Hz (target {} Hz, ~{} Hz)",
        pit::divisor(),
        mhz / 1000,
        mhz % 1000,
        HZ,
        actual
    );
}

/// Liczba ticków od startu timera.
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Czas od startu timera w ms, liczony z rzeczywistej częstotliwości PIT.
#[allow(dead_code)]
pub fn uptime_ms() -> u64 {
    let mhz = pit::actual_frequency_millihz();
    if mhz == 0 {
        return 0;
    }
    // ticks / (mhz/1000) s = ticks * 1_000_000 / mhz ms
    (ticks() as u128 * 1_000_000 / mhz as u128) as u64
}

/// Ustawia (Some) lub zdejmuje (None) funkcję wołaną w każdym ticku,
/// z kontekstu przerwania.
#[allow(dead_code)]
pub fn set_tick_hook(hook: Option<TickHook>) {
    TICK_HOOK.store(hook.map_or(0, |h| h as usize), Ordering::Release);
}

/// Czeka co najmniej `n` ticków, usypiając CPU (hlt) między przerwaniami.
/// Wymaga włączonych przerwań – inaczej czekałoby wiecznie.
#[allow(dead_code)]
pub fn sleep_ticks(n: u64) {
    assert!(interrupts::are_enabled(), "sleep with interrupts disabled");
    let target = ticks() + n;
    // M12: po starcie schedulera zadanie zasypia, a CPU dostają inne.
    if crate::sched::can_block() {
        crate::sched::sleep_until(target);
        return;
    }
    while ticks() < target {
        // sti+hlt atomowo: tick nie może przepaść między sprawdzeniem a hlt.
        interrupts::disable();
        if ticks() >= target {
            interrupts::enable();
            break;
        }
        interrupts::enable_and_hlt();
    }
}

/// Milisekundy -> ticki (w górę).
pub fn ms_to_ticks(ms: u64) -> u64 {
    (ms * HZ as u64).div_ceil(1000)
}

/// Czeka co najmniej `ms` milisekund (zaokrąglone w górę do ticków).
#[allow(dead_code)]
pub fn sleep_ms(ms: u64) {
    let n = (ms * HZ as u64).div_ceil(1000);
    // +1: bieżący tick jest już częściowo miniony.
    sleep_ticks(n + 1);
}

// ------------------------------------------------------------
// TEST (tylko build z --cfg selftest)
// ------------------------------------------------------------

#[cfg(selftest)]
macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[TIME TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

/// Odmierza `n` przeładowań licznika PIT, patrząc tylko na sam licznik
/// (niezależnie od IRQ).  Każde przeładowanie = 1 okres = ~1 ms.
///
/// Między odczytami jest krótka przerwa: w QEMU (TCG) każdy dostęp do portu
/// bierze globalną blokadę emulatora, a ciasna pętla `in/out` potrafi
/// zagłodzić wątek, który zgłasza IRQ z PIT – licznik biegnie, ale ticki
/// nie przychodzą (widać to zwłaszcza w buildzie bez optymalizacji).
#[cfg(selftest)]
fn wait_pit_periods(n: u32) {
    let mut last = pit::read_counter();
    let mut wraps = 0;
    while wraps < n {
        for _ in 0..POLL_GAP_SPINS {
            core::hint::spin_loop();
        }
        let now = pit::read_counter();
        if now > last {
            wraps += 1;
        }
        last = now;
    }
}

// Przerwa między odczytami portów w pętlach testowych (patrz wyżej).
#[cfg(selftest)]
const POLL_GAP_SPINS: u32 = 2000;

// CMOS RTC: sekundy (rejestr 0x00), bit UIP w rejestrze 0x0A.
#[cfg(selftest)]
fn cmos_read(reg: u8) -> u8 {
    use crate::arch::x86_64::port::{inb, outb};
    interrupts::without_interrupts(|| unsafe {
        outb(0x70, reg | 0x80); // bit 7 = NMI wyłączone na czas odczytu
        let v = inb(0x71);
        outb(0x70, 0x00);
        v
    })
}

#[cfg(selftest)]
fn rtc_seconds() -> u8 {
    loop {
        while cmos_read(0x0A) & 0x80 != 0 {
            for _ in 0..POLL_GAP_SPINS {
                core::hint::spin_loop();
            }
        }
        let s = cmos_read(0x00);
        if cmos_read(0x0A) & 0x80 == 0 && cmos_read(0x00) == s {
            return s;
        }
    }
}

/// Czeka na zmianę sekundy RTC; między odczytami CPU śpi do kolejnego
/// ticku (hlt), więc odczyt CMOS jest raz na ~1 ms, a nie w ciasnej pętli.
#[cfg(selftest)]
fn wait_rtc_edge() {
    let start = rtc_seconds();
    while rtc_seconds() == start {
        interrupts::enable_and_hlt();
    }
}

#[cfg(selftest)]
static HOOK_CALLS: AtomicU64 = AtomicU64::new(0);
#[cfg(selftest)]
static HOOK_ERRORS: AtomicU64 = AtomicU64::new(0);

#[cfg(selftest)]
fn heap_hook(tick: u64) {
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    let b = Box::new(tick);
    let mut v: Vec<u64> = Vec::with_capacity(8);
    for i in 0..8 {
        v.push(tick ^ i);
    }
    let ok = *b == tick && v.iter().enumerate().all(|(i, &x)| x == tick ^ i as u64);
    if !ok {
        HOOK_ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    HOOK_CALLS.fetch_add(1, Ordering::Relaxed);
}

#[cfg(selftest)]
pub fn self_test() {
    use crate::arch::x86_64::idt::{gate_ist, gate_present, IRQ_BASE, IRQ_VECTORS};
    use alloc::vec::Vec;

    serial_println!("[TIME TEST] Starting timer + IRQ tests...");
    crate::selftest::begin();

    // 1. PIC zremapowany, IMR: tylko IRQ0 odblokowane; bramki IRQ w IDT.
    //    M17: z I/O APIC – PIC cały zamaskowany, IRQ0 odblokowane w I/O APIC.
    let imr = crate::arch::x86_64::pic::masks();
    if irq::ioapic_mode() {
        check!(imr == 0xFFFF, "IMR = {:#06x}, expected 0xffff (PIC disabled)", imr);
        check!(!irq::is_masked(0), "IRQ0 masked in the I/O APIC");
    } else {
        check!(imr == 0xFFFE, "IMR = {:#06x}, expected 0xfffe", imr);
    }
    for v in IRQ_BASE..IRQ_BASE + IRQ_VECTORS {
        check!(gate_present(v), "IRQ gate {:#x} not present", v);
        check!(gate_ist(v) == 0, "IRQ gate {:#x} uses IST {}", v, gate_ist(v));
    }
    // M16b: zaraz za IRQ są wektory MSI (0x30..0x3F); M17: potem timer
    // LAPIC i IPI (0x40..0x43), bez IST; dalej nic.
    use crate::arch::x86_64::lapic;
    for v in [lapic::TIMER_VECTOR, lapic::RESCHED_VECTOR, lapic::HALT_VECTOR, crate::arch::x86_64::tlb::TLB_VECTOR] {
        check!(gate_present(v as usize), "LAPIC gate {:#x} not present", v);
        check!(gate_ist(v as usize) == 0, "LAPIC gate {:#x} uses IST", v);
    }
    let after = crate::arch::x86_64::tlb::TLB_VECTOR as usize + 1;
    check!(!gate_present(after), "gate {:#x} present", after);
    serial_println!(
        "[TIME TEST] 1/8 {}, IRQ gates 0x20-0x2f PASS",
        if irq::ioapic_mode() { "I/O APIC: IRQ0 routed, PIC disabled" } else { "PIC remapped, IMR = 0xfffe" }
    );

    // 2. PIT: dzielnik i licznik, który faktycznie odlicza.
    let div = pit::divisor();
    check!(div == 1193, "PIT divisor = {}", div);
    let first = pit::read_counter();
    check!(first >= 1 && first <= div, "PIT counter {} outside 1..={}", first, div);
    let mut moved = false;
    for _ in 0..10_000 {
        if pit::read_counter() != first {
            moved = true;
            break;
        }
    }
    check!(moved, "PIT counter stuck at {}", first);
    serial_println!("[TIME TEST] 2/8 PIT channel 0 counting (divisor {}) PASS", div);

    // 3. Po sti (kernel_main) ticki płyną; >1 tick dowodzi, że EOI działa.
    //    Czekamy przez hlt (CPU śpi do przerwania) – nie ma ciasnej pętli
    //    na portach, więc wynik nie zależy od szybkości hosta / emulatora.
    //    Jedyne odmaskowane IRQ to IRQ0, więc każde wybudzenie = tick.
    //    Jeśli IRQ0 w ogóle nie działa, system zatrzyma się tutaj.
    check!(interrupts::are_enabled(), "interrupts not enabled (IF = 0)");
    let t0 = ticks();
    let pit_start = pit::read_counter();
    for _ in 0..20 {
        interrupts::enable_and_hlt();
    }
    let t1 = ticks();
    check!(t1 - t0 >= 20, "only {} ticks after 20 wake-ups", t1 - t0);
    // M17a.b: ticki = przerwania + doliczone za zgubione (HPET).
    check!(irq::count(0) + caught_up_ticks() >= t1, "IRQ0 count {} + caught up {} < ticks {}", irq::count(0), caught_up_ticks(), t1);
    check!(pit_start >= 1 && pit_start <= div, "PIT counter {}", pit_start);
    serial_println!("[TIME TEST] 3/8 IRQ0 delivered, {} ticks (EOI ok) PASS", t1 - t0);

    // 4. mask/unmask: zamaskowane IRQ0 nie dochodzi, po odmaskowaniu
    //    oczekujące przerwanie zostaje dostarczone.
    irq::mask(0);
    let before = ticks();
    wait_pit_periods(10);
    let masked = ticks() - before;
    irq::unmask(0);
    check!(masked == 0, "{} ticks arrived while IRQ0 masked", masked);
    sleep_ticks(2);
    check!(ticks() > before, "no ticks after unmask");
    serial_println!("[TIME TEST] 4/8 IRQ0 mask/unmask PASS");

    // 5. without_interrupts: zagnieżdżanie przywraca IF, w środku cisza.
    // Odczyt "przed" już przy wyłączonych przerwaniach – inaczej tick między
    // odczytem a cli liczyłby się jako "w środku" (wyścig w samym teście).
    let outer_before = ticks();
    let inside = interrupts::without_interrupts(|| {
        let before = ticks();
        let nested_if = interrupts::without_interrupts(|| interrupts::are_enabled());
        let still_off = !interrupts::are_enabled();
        wait_pit_periods(5);
        (nested_if, still_off, ticks() - before)
    });
    check!(!inside.0 && inside.1, "IF leaked inside without_interrupts");
    check!(inside.2 == 0, "{} ticks inside without_interrupts", inside.2);
    check!(interrupts::are_enabled(), "IF not restored");
    sleep_ticks(1);
    check!(ticks() > outer_before, "pending tick lost after without_interrupts");
    serial_println!("[TIME TEST] 5/8 without_interrupts (nested, IF restored) PASS");

    // 6. sleep_ms: nie krócej niż zadano i niewiele dłużej.
    let before = ticks();
    sleep_ms(100);
    let slept = ticks() - before;
    check!(slept >= 100 && slept <= 110, "sleep_ms(100) took {} ticks", slept);
    serial_println!("[TIME TEST] 6/8 sleep_ms(100) = {} ticks PASS", slept);

    // 7. Częstotliwość względem niezależnego zegara (CMOS RTC, 1 s).
    wait_rtc_edge();
    let before = ticks();
    wait_rtc_edge();
    let per_second = ticks() - before;
    let lo = HZ as u64 * 8 / 10;
    let hi = HZ as u64 * 12 / 10;
    check!(per_second >= lo && per_second <= hi, "{} ticks per RTC second (expected ~{})", per_second, HZ);
    // M17a.g14: zegar ścienny z uptime – konwersje i zgodność z RTC.
    {
        use crate::drivers::rtc::{self, DateTime};
        for (secs, y, mo, d, h, mi, se) in [
            (0u64, 1970u16, 1u8, 1u8, 0u8, 0u8, 0u8),
            (951_782_400, 2000, 2, 29, 0, 0, 0),
            (1_791_417_599, 2026, 10, 7, 23, 59, 59),
            (4_107_542_400, 2100, 3, 1, 0, 0, 0),
        ] {
            let dt = DateTime { year: y, month: mo, day: d, hour: h, minute: mi, second: se };
            check!(dt.to_unix() == secs && DateTime::from_unix(secs) == dt, "date {} <-> {} s", dt, secs);
        }
        let hw = rtc::read_hw().to_unix() as i64;
        let now = rtc::now().to_unix() as i64;
        check!((now - hw).abs() <= 2, "wall clock {} s from RTC", now - hw);
    }
    serial_println!("[TIME TEST] 7/8 {} ticks per RTC second (target {}), wall clock = RTC PASS", per_second, HZ);

    // 8. Heap z przerwaniami: hook ticku alokuje w IRQ, pętla główna też.
    let hook_start = HOOK_CALLS.load(Ordering::Relaxed);
    let used_start = crate::memory::heap_used_bytes();
    set_tick_hook(Some(heap_hook));
    // M17a.b: 50 PRZERWAŃ (hook działa raz na przerwanie; ticki mogą
    // przeskakiwać, gdy przerwania PIT giną – doganianie HPET).
    //
    // M17a.c: heap pod IrqSpinLock – w ciasnej pętli alokacji IF = 1 tylko
    // przez kilka instrukcji między `sti` a kolejnym `cli`, a QEMU (TCG)
    // sprawdza przerwania na granicach bloków kodu: u Dawida przerwanie nie
    // trafiało w to okno i test stał (licznik przerwań, ticki – wszystko
    // od przerwań).  Co rundę krótka pętla z IF = 1 (gałęzie = granice
    // bloków), a na wszelki wypadek limit czasu z HPET.
    let irq_end = irq::count(0) + 50;
    let end = ticks() + 5_000;
    let start = crate::arch::x86_64::clock::stamp();
    let mut rounds = 0u64;
    while irq::count(0) < irq_end && ticks() < end {
        let mut v: Vec<u64> = Vec::new();
        for i in 0..64 {
            v.push(i * 3);
        }
        if v.iter().enumerate().any(|(i, &x)| x != i as u64 * 3) {
            set_tick_hook(None);
            serial_println!("[TIME TEST] FAIL: main-loop Vec corrupted");
            return;
        }
        drop(v);
        rounds += 1;
        for _ in 0..64 {
            core::hint::spin_loop();
            core::hint::black_box(rounds);
        }
        if rounds % 1024 == 0 && crate::arch::x86_64::clock::elapsed_us(start) > 10_000_000 {
            break;
        }
    }
    set_tick_hook(None);
    let calls = HOOK_CALLS.load(Ordering::Relaxed) - hook_start;
    check!(calls >= 45, "tick hook ran only {} times", calls);
    check!(HOOK_ERRORS.load(Ordering::Relaxed) == 0, "tick hook saw corrupted data");
    check!(
        crate::memory::heap_used_bytes() == used_start,
        "heap leak: {} -> {}",
        used_start,
        crate::memory::heap_used_bytes()
    );
    serial_println!(
        "[TIME TEST] 8/8 heap under IRQ load ({} IRQ allocs, {} main rounds) PASS",
        calls,
        rounds
    );

    serial_println!("[TIME TEST] =================================");
    crate::selftest::pass();
    serial_println!("[TIME TEST] TIMER + IRQ TESTS PASSED (uptime {} ms)", uptime_ms());
    serial_println!("[TIME TEST] =================================");
}
