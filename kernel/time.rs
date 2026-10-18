// System clock – ticks from the PIT (IRQ0), uptime, sleep.
//
// PIT channel 0 -> IRQ0 -> on_tick(): TICKS += 1 (+ an optional hook, e.g. for
// the scheduler).  Everything here assumes a single core.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::arch::x86_64::{interrupts, irq, pit};
use crate::serial_println;

/// Target tick frequency (1 tick ≈ 1 ms).
pub const HZ: u32 = 1000;

const TIMER_IRQ: u8 = 0;

static TICKS: AtomicU64 = AtomicU64::new(0);
// fn(u64) as usize; 0 = no hook.
static TICK_HOOK: AtomicUsize = AtomicUsize::new(0);

pub type TickHook = fn(ticks: u64);

/// Tick counter incremented even BEFORE the Big Kernel Lock
/// (exceptions.rs, IRQ0 vector) – system time stays accurate even when
/// the timer interrupt is queued waiting for the BKL.  The rest of the tick (waking
/// tasks, time slice) happens in on_tick, already under the BKL.
pub fn pit_tick_early() {
    // Ticks catch up with the HPET clock.  CPU 0 waiting for the BKL with IF = 0
    // used to lose PIT interrupts (the controller holds only one pending), so
    // under congestion system time stood still: on real hardware a 10 s test took 99 s,
    // `stress 30` – ~115 s.  Now the PIT interrupt is only an "alarm clock":
    // each one adds at least 1 tick (as before), and when the HPET says that
    // more milliseconds have passed, the missing ticks are added right away.
    //
    // SMP only: on a single CPU interrupts are lost only when
    // the emulator gets no time from the host – tests with tight limits
    // (sleep 30 ms -> 30..40) would then measure host stalls.
    use crate::arch::x86_64::{clock, smp};
    let mut n: u64 = 1;
    if !smp::active() {
        HPET_LAST.store(0, Ordering::Relaxed);
    } else if clock::hpet() {
        let now = clock::stamp();
        let last = HPET_LAST.swap(now, Ordering::Relaxed);
        if last != 0 {
            let d = clock::diff_us(last, now).clamp(0, 10_000_000);
            // Longest gap between PIT interrupts (CPU 0) and how many are > 2 ms.
            GAP_MAX_US.fetch_max(d as u64, Ordering::Relaxed);
            if d > 2000 {
                GAP_LONG.fetch_add(1, Ordering::Relaxed);
            }
            let mut acc = HPET_ACC_US.load(Ordering::Relaxed) + d;
            let due = (acc / 1000).max(0) as u64;
            n = due.clamp(1, 10_000);
            acc -= n as i64 * 1000;
            // A negative margin (PIT slightly faster than HPET) does not grow forever.
            HPET_ACC_US.store(acc.max(-5_000), Ordering::Relaxed);
            if n > 1 {
                CAUGHT_UP.fetch_add(n - 1, Ordering::Relaxed);
            }
        }
    }
    TICKS.fetch_add(n, Ordering::Relaxed);
}

/// HPET at the previous PIT interrupt and the microseconds not yet accounted for.
static HPET_LAST: AtomicU64 = AtomicU64::new(0);
static HPET_ACC_US: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);
/// How many ticks were added for lost PIT interrupts (`cpus`, tests).
static CAUGHT_UP: AtomicU64 = AtomicU64::new(0);
static GAP_MAX_US: AtomicU64 = AtomicU64::new(0);
static GAP_LONG: AtomicU64 = AtomicU64::new(0);

/// (longest gap between PIT interrupts in µs, number of gaps > 2 ms).
pub fn tick_gaps() -> (u64, u64) {
    (GAP_MAX_US.load(Ordering::Relaxed), GAP_LONG.load(Ordering::Relaxed))
}

/// Ticks added for lost PIT interrupts (HPET catch-up).
pub fn caught_up_ticks() -> u64 {
    CAUGHT_UP.load(Ordering::Relaxed)
}

fn on_tick(_irq: u8) {
    let now = TICKS.load(Ordering::Relaxed);
    // Time slice and waking sleeping tasks.
    crate::sched::on_tick(now);
    // PS/2 keyboard also without IRQ1 (laptops) – port polling.
    // The tick runs without the BKL, while the keyboard decoder and shell input
    // are still under the BKL – we poll only when the BKL is free right away
    // (otherwise on the next polling tick; IRQ1 takes it normally).
    // When the interrupted context already holds it, the interrupt may use it.
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

/// Programs the PIT, registers the IRQ0 handler and unmasks the line.
/// Interrupts are enabled by the caller (`interrupts::enable()`).
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

/// Number of ticks since the timer started.
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Time since the timer started in ms, computed from the actual PIT frequency.
#[allow(dead_code)]
pub fn uptime_ms() -> u64 {
    let mhz = pit::actual_frequency_millihz();
    if mhz == 0 {
        return 0;
    }
    // ticks / (mhz/1000) s = ticks * 1_000_000 / mhz ms
    (ticks() as u128 * 1_000_000 / mhz as u128) as u64
}

/// Sets (Some) or removes (None) the function called on every tick,
/// from interrupt context.
#[allow(dead_code)]
pub fn set_tick_hook(hook: Option<TickHook>) {
    TICK_HOOK.store(hook.map_or(0, |h| h as usize), Ordering::Release);
}

/// Waits at least `n` ticks, halting the CPU (hlt) between interrupts.
/// Requires interrupts to be enabled – otherwise it would wait forever.
#[allow(dead_code)]
pub fn sleep_ticks(n: u64) {
    assert!(interrupts::are_enabled(), "sleep with interrupts disabled");
    let target = ticks() + n;
    // Once the scheduler has started the task goes to sleep and the CPU goes to others.
    if crate::sched::can_block() {
        crate::sched::sleep_until(target);
        return;
    }
    while ticks() < target {
        // sti+hlt atomically: a tick cannot slip in between the check and hlt.
        interrupts::disable();
        if ticks() >= target {
            interrupts::enable();
            break;
        }
        interrupts::enable_and_hlt();
    }
}

/// Milliseconds -> ticks (rounded up).
pub fn ms_to_ticks(ms: u64) -> u64 {
    (ms * HZ as u64).div_ceil(1000)
}

/// Waits at least `ms` milliseconds (rounded up to ticks).
#[allow(dead_code)]
pub fn sleep_ms(ms: u64) {
    let n = (ms * HZ as u64).div_ceil(1000);
    // +1: the current tick has already partly elapsed.
    sleep_ticks(n + 1);
}

// ------------------------------------------------------------
// TEST (only in builds with --cfg selftest)
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

/// Counts `n` reloads of the PIT counter, looking only at the counter itself
/// (independently of the IRQ).  Each reload = 1 period = ~1 ms.
///
/// There is a short pause between reads: in QEMU (TCG) every port access
/// takes the emulator's global lock, and a tight `in/out` loop can
/// starve the thread that raises the PIT IRQ – the counter runs, but ticks
/// do not arrive (especially visible in an unoptimized build).
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

// Pause between port reads in the test loops (see above).
#[cfg(selftest)]
const POLL_GAP_SPINS: u32 = 2000;

// CMOS RTC: seconds (register 0x00), UIP bit in register 0x0A.
#[cfg(selftest)]
fn cmos_read(reg: u8) -> u8 {
    use crate::arch::x86_64::port::{inb, outb};
    interrupts::without_interrupts(|| unsafe {
        outb(0x70, reg | 0x80); // bit 7 = NMI disabled during the read
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

/// Waits for the RTC second to change; between reads the CPU sleeps until the next
/// tick (hlt), so CMOS is read once per ~1 ms rather than in a tight loop.
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

    // 1. PIC remapped, IMR: only IRQ0 unmasked; IRQ gates in the IDT.
    //    With an I/O APIC – the PIC is fully masked, IRQ0 unmasked in the I/O APIC.
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
    // Right after the IRQs come the MSI vectors (0x30..0x3F); then the LAPIC
    // timer and IPIs (0x40..0x43), without IST; nothing beyond that.
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

    // 2. PIT: divisor and a counter that actually counts down.
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

    // 3. After sti (kernel_main) ticks flow; >1 tick proves that EOI works.
    //    We wait with hlt (the CPU sleeps until an interrupt) – there is no tight loop
    //    on ports, so the result does not depend on host / emulator speed.
    //    The only unmasked IRQ is IRQ0, so every wakeup = a tick.
    //    If IRQ0 does not work at all, the system will stop here.
    check!(interrupts::are_enabled(), "interrupts not enabled (IF = 0)");
    let t0 = ticks();
    let pit_start = pit::read_counter();
    for _ in 0..20 {
        interrupts::enable_and_hlt();
    }
    let t1 = ticks();
    check!(t1 - t0 >= 20, "only {} ticks after 20 wake-ups", t1 - t0);
    // Ticks = interrupts + those added for lost ones (HPET).
    check!(irq::count(0) + caught_up_ticks() >= t1, "IRQ0 count {} + caught up {} < ticks {}", irq::count(0), caught_up_ticks(), t1);
    check!(pit_start >= 1 && pit_start <= div, "PIT counter {}", pit_start);
    serial_println!("[TIME TEST] 3/8 IRQ0 delivered, {} ticks (EOI ok) PASS", t1 - t0);

    // 4. mask/unmask: a masked IRQ0 is not delivered, after unmasking
    //    the pending interrupt gets delivered.
    irq::mask(0);
    let before = ticks();
    wait_pit_periods(10);
    let masked = ticks() - before;
    irq::unmask(0);
    check!(masked == 0, "{} ticks arrived while IRQ0 masked", masked);
    sleep_ticks(2);
    check!(ticks() > before, "no ticks after unmask");
    serial_println!("[TIME TEST] 4/8 IRQ0 mask/unmask PASS");

    // 5. without_interrupts: nesting restores IF, silence inside.
    // The "before" read already with interrupts disabled – otherwise a tick between
    // the read and cli would count as "inside" (a race in the test itself).
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

    // 6. sleep_ms: not shorter than requested and not much longer.
    let before = ticks();
    sleep_ms(100);
    let slept = ticks() - before;
    check!(slept >= 100 && slept <= 110, "sleep_ms(100) took {} ticks", slept);
    serial_println!("[TIME TEST] 6/8 sleep_ms(100) = {} ticks PASS", slept);

    // 7. Frequency against an independent clock (CMOS RTC, 1 s).
    wait_rtc_edge();
    let before = ticks();
    wait_rtc_edge();
    let per_second = ticks() - before;
    let lo = HZ as u64 * 8 / 10;
    let hi = HZ as u64 * 12 / 10;
    check!(per_second >= lo && per_second <= hi, "{} ticks per RTC second (expected ~{})", per_second, HZ);
    // Wall clock from uptime – conversions and agreement with the RTC.
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

    // 8. Heap with interrupts: the tick hook allocates in the IRQ, so does the main loop.
    let hook_start = HOOK_CALLS.load(Ordering::Relaxed);
    let used_start = crate::memory::heap_used_bytes();
    set_tick_hook(Some(heap_hook));
    // 50 INTERRUPTS (the hook runs once per interrupt; ticks may
    // jump when PIT interrupts are lost – HPET catch-up).
    //
    // The heap is under an IrqSpinLock – in a tight allocation loop IF = 1 only
    // for a few instructions between `sti` and the next `cli`, and QEMU (TCG)
    // checks interrupts at code-block boundaries: on some hosts the interrupt never
    // hit that window and the test hung (interrupt counter, ticks – everything
    // depends on interrupts).  Each round has a short loop with IF = 1 (branches = block
    // boundaries), plus an HPET time limit just in case.
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
