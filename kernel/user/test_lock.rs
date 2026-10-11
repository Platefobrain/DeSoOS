// M17a: samotesty spinlocków i stress test SMP (tylko build z --cfg selftest).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::*;
use crate::arch::x86_64::{cpu, interrupts, smp};
use crate::sched::bkl;
use crate::sched::spin::{self, level, IrqSpinLock, LockError, SpinLock};
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[LOCK TEST] FAIL: {}", format_args!($($msg)*));
            STOP.store(true, Ordering::SeqCst);
            return;
        }
    };
}

static STOP: AtomicBool = AtomicBool::new(false);
static OUTER: SpinLock<u32> = SpinLock::new("test-outer", level::TEST_OUTER, 0);
static INNER: SpinLock<u32> = SpinLock::new("test-inner", level::TEST_INNER, 0);
static IRQ_LOCK: IrqSpinLock<u32> = IrqSpinLock::new("test-irq", level::TEST_IRQ, 0);
static COUNTER: SpinLock<u64> = SpinLock::new("test-counter", level::TEST_INNER, 0);
static DONE: AtomicU64 = AtomicU64::new(0);
static CPUS_SEEN: AtomicU64 = AtomicU64::new(0);
static HOLDING: AtomicBool = AtomicBool::new(false);
static HOLD_CPU: AtomicU64 = AtomicU64::new(u64::MAX);

const ROUNDS: u64 = 20_000;

fn wait_for(ms: u64, cond: impl Fn() -> bool) -> bool {
    let end = ticks() + ms;
    while !cond() {
        if ticks() > end {
            return false;
        }
        crate::time::sleep_ms(1);
    }
    true
}

/// Zadanie: ROUNDS nieatomowych zwiększeń pod spinlockiem, bez BKL.
fn incrementer(_: usize) {
    bkl::unlocked(|| {
        for _ in 0..ROUNDS {
            let mut g = COUNTER.lock();
            let v = core::hint::black_box(*g);
            core::hint::spin_loop();
            *g = v + 1;
            CPUS_SEEN.fetch_or(1 << cpu::id(), Ordering::Relaxed);
        }
    });
    DONE.fetch_add(1, Ordering::SeqCst);
}

/// Zadanie: trzyma OUTER ~150 ms (bez BKL), żeby test zobaczył raport.
fn holder(_: usize) {
    bkl::unlocked(|| {
        let _g = OUTER.lock();
        HOLD_CPU.store(cpu::id() as u64, Ordering::SeqCst);
        HOLDING.store(true, Ordering::SeqCst);
        let end = ticks() + 150;
        while ticks() < end {
            core::hint::spin_loop();
        }
        HOLDING.store(false, Ordering::SeqCst);
    });
    DONE.fetch_add(1, Ordering::SeqCst);
}

pub fn self_test() {
    serial_println!("[LOCK TEST] Starting spinlock tests...");
    crate::selftest::begin();
    STOP.store(false, Ordering::SeqCst);

    // 1. Podstawy: guard, licznik trzymanych blokad, wywłaszczanie, IF.
    check!(spin::held_count() == 0 && cpu::preempt_count() == 0, "start: held {} preempt {}", spin::held_count(), cpu::preempt_count());
    {
        let mut g = OUTER.lock();
        *g += 1;
        check!(spin::held_count() == 1, "held_count {} with one lock", spin::held_count());
        check!(cpu::preempt_count() == 1, "preemption not disabled under SpinLock");
        check!(interrupts::are_enabled(), "SpinLock disabled interrupts");
        let i = INNER.lock();
        check!(spin::held_count() == 2 && *i == 0, "nested lock");
    }
    check!(spin::held_count() == 0 && cpu::preempt_count() == 0, "after unlock: held {} preempt {}", spin::held_count(), cpu::preempt_count());
    {
        let _g = IRQ_LOCK.lock();
        check!(!interrupts::are_enabled(), "IrqSpinLock left interrupts on");
    }
    check!(interrupts::are_enabled(), "IrqSpinLock did not restore IF = 1");
    interrupts::disable();
    {
        let _g = IRQ_LOCK.lock();
    }
    let still_off = !interrupts::are_enabled();
    interrupts::enable();
    check!(still_off, "IrqSpinLock turned interrupts on (they were off)");
    serial_println!("[LOCK TEST] 1/6 SpinLock/IrqSpinLock: guard, preemption off, IF restored PASS");

    // 2. Wykrywanie złamania zasad (bez panic – RawSpin::check).
    {
        let _i = INNER.lock();
        let r = OUTER.raw().check();
        check!(
            r == Err(LockError::Order { held: "test-inner", held_level: level::TEST_INNER }),
            "order violation not detected: {:?}",
            r
        );
        check!(INNER.raw().check() == Err(LockError::Recursive), "recursion not detected");
    }
    {
        let _o = OUTER.lock();
        check!(INNER.raw().check() == Ok(()), "valid order rejected");
    }
    serial_println!("[LOCK TEST] 2/6 lock order and recursion detected (lockdep-lite) PASS");

    // 3. Wzajemne wykluczanie na wielu CPU, bez BKL.
    let n = smp::online_count();
    let k = n.clamp(2, 4);
    *COUNTER.lock() = 0;
    DONE.store(0, Ordering::SeqCst);
    CPUS_SEEN.store(0, Ordering::SeqCst);
    let (_, cont0, _) = spin::stats();
    for _ in 0..k {
        check!(crate::sched::spawn("t-spin", incrementer, 0).is_ok(), "spawn");
    }
    check!(wait_for(60_000, || DONE.load(Ordering::SeqCst) == k as u64), "incrementers did not finish ({} / {})", DONE.load(Ordering::SeqCst), k);
    let total = *COUNTER.lock();
    let (_, cont1, _) = spin::stats();
    let seen = CPUS_SEEN.load(Ordering::SeqCst).count_ones();
    check!(total == k as u64 * ROUNDS, "lost updates: {} != {}", total, k as u64 * ROUNDS);
    check!(n == 1 || seen >= 2, "spinlock tasks ran on only {} CPU", seen);
    serial_println!(
        "[LOCK TEST] 3/6 {} tasks x {} increments without BKL = {} (CPUs {}, {} contended) PASS",
        k,
        ROUNDS,
        total,
        seen,
        cont1 - cont0
    );

    // 4. Wykrywacz zakleszczeń: inny CPU trzyma blokadę -> raport, potem wejście.
    if n > 1 {
        DONE.store(0, Ordering::SeqCst);
        check!(crate::sched::spawn("t-hold", holder, 0).is_ok(), "spawn holder");
        check!(wait_for(2_000, || HOLDING.load(Ordering::SeqCst)), "holder did not take the lock");
        let r = OUTER.raw().try_lock_for(1_000);
        check!(matches!(r, Err((c, f, _)) if c as u64 == HOLD_CPU.load(Ordering::SeqCst) && f.contains("test_lock")), "try_lock_for: {:?}", r);
        let (_, _, dl0) = spin::stats();
        // Raport po 1 ms; holder puszcza po 150 ms -> wchodzimy.
        bkl::unlocked(|| drop(OUTER.lock_reporting_after(1_000)));
        let (_, _, dl1) = spin::stats();
        check!(dl1 == dl0 + 1, "deadlock report count {} -> {}", dl0, dl1);
        check!(wait_for(2_000, || DONE.load(Ordering::SeqCst) == 1), "holder did not finish");
        serial_println!("[LOCK TEST] 4/6 deadlock detector: holder CPU {} and site reported PASS", HOLD_CPU.load(Ordering::SeqCst));
    } else {
        serial_println!("[LOCK TEST] 4/6 deadlock detector skipped (1 CPU) PASS");
    }

    // 5. BKL: kontekst bez BKL zostaje bez BKL po przerwaniu; statystyka działa.
    let (a0, _, _) = bkl::stats();
    let ok = bkl::unlocked(|| {
        let t = ticks() + 20;
        let mut ok = true;
        while ticks() < t {
            if bkl::held() {
                ok = false; // przerwanie zostawiło nam BKL
            }
            core::hint::spin_loop();
        }
        ok
    });
    let (a1, _, _) = bkl::stats();
    check!(ok, "BKL still held after an interrupt in a BKL-free section");
    check!(bkl::held(), "BKL not taken back after bkl::unlocked");
    check!(a1 > a0, "BKL statistics not counting");
    serial_println!("[LOCK TEST] 5/6 BKL-free section stays BKL-free across interrupts, {} BKL takes counted PASS", a1 - a0);

    // 6. Watchdog zawieszeń: zegar PIT staje (IRQ0 zamaskowane na ponad
    //    10 s) – któryś CPU musi to zgłosić (NMI zbiera RIP-y).  Ten CPU
    //    czeka z włączonymi przerwaniami, oddając BKL (inne CPU działają).
    if n > 1 {
        let before = smp::watchdog_reports();
        let start = crate::arch::x86_64::clock::stamp();
        crate::arch::x86_64::irq::mask(0);
        bkl::unlocked(|| {
            while smp::watchdog_reports() == before && crate::arch::x86_64::clock::elapsed_us(start) < 60_000_000 {
                core::hint::spin_loop();
            }
        });
        crate::arch::x86_64::irq::unmask(0);
        check!(smp::watchdog_reports() > before, "watchdog did not report a stopped PIT clock");
        serial_println!("[LOCK TEST] 6/6 lockup watchdog: stopped PIT clock reported with NMI RIPs PASS");
    } else {
        serial_println!("[LOCK TEST] 6/6 lockup watchdog skipped (1 CPU) PASS");
    }

    crate::selftest::pass();
}


/// Stress test SMP (krótki – w samotestach).
pub fn stress_self_test() {
    serial_println!("[STRESS TEST] Starting SMP stress test (3 s)...");
    crate::selftest::begin();
    match super::stress::run(3_000) {
        Ok(r) => {
            serial_println!("[STRESS TEST] 1/1 {} PASS", r);
            crate::selftest::pass();
        }
        Err(e) => serial_println!("[STRESS TEST] FAIL: {}", e),
    }
}
