// Clock for measuring time intervals – HPET, or TSC when there is no HPET.
//
// Why not TSC alone: on some machines the per-core TSC counters are not
// consistent with each other (e.g. QEMU with TCG emulation on a host whose cores have different
// TSCs – a virtual CPU thread migrated between host cores sees jumps
// of seconds).  The watchdog and deadlock detector measured with TSC then reported
// false "clock stopped" / "deadlock" (seen on real hardware: NMI
// response times of exactly 1x, 2x, 3x, 5x 2535 ms).  HPET is a single counter on
// the motherboard, shared by all CPUs – Linux switches to it
// when it deems the TSC unstable.
//
// The API measures INTERVALS: `stamp()` + `elapsed_us(start)`.  The HPET counter may be
// 32-bit (common on AMD; 14.318 MHz -> wraps every ~300 s), so
// the difference is computed on as many bits as the counter has – correct for
// intervals shorter than ~5 minutes (ours: at most a few tens of seconds).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::serial_println;

const REG_CAP: u64 = 0x000;
const REG_CONF: u64 = 0x010;
const REG_COUNTER: u64 = 0x0F0;
const CONF_ENABLE: u64 = 1;
const CAP_64BIT: u64 = 1 << 13;

static BASE: AtomicU64 = AtomicU64::new(0);
/// HPET counter period in femtoseconds (0 = no HPET).
static PERIOD_FS: AtomicU64 = AtomicU64::new(0);
static WIDE: AtomicBool = AtomicBool::new(false);

#[inline]
fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    ((hi as u64) << 32) | lo as u64
}

fn read64(off: u64) -> u64 {
    unsafe { core::ptr::read_volatile((BASE.load(Ordering::Relaxed) + off) as *const u64) }
}

fn read32(off: u64) -> u32 {
    unsafe { core::ptr::read_volatile((BASE.load(Ordering::Relaxed) + off) as *const u32) }
}

fn write64(off: u64, v: u64) {
    unsafe { core::ptr::write_volatile((BASE.load(Ordering::Relaxed) + off) as *mut u64, v) }
}

/// Enables the HPET counter from the ACPI table (without "legacy replacement" mode – the PIT
/// keeps running).  Call after acpi::init and memory setup.
pub fn init() {
    let Some(phys) = crate::acpi::hpet_base() else {
        serial_println!("[CLOCK] no HPET - time intervals measured with TSC");
        return;
    };
    let Some(virt) = crate::memory::map_mmio(phys, 0x400) else {
        serial_println!("[CLOCK] cannot map HPET at {:#x} - using TSC", phys);
        return;
    };
    BASE.store(virt, Ordering::SeqCst);
    let cap = read64(REG_CAP);
    let period = cap >> 32;
    // Specification: period > 0 and <= 100 ns.
    if period == 0 || period > 100_000_000 {
        serial_println!("[CLOCK] HPET at {:#x}: bad period {} fs - using TSC", phys, period);
        BASE.store(0, Ordering::SeqCst);
        return;
    }
    let conf = read64(REG_CONF);
    if conf & CONF_ENABLE == 0 {
        write64(REG_CONF, conf | CONF_ENABLE);
    }
    WIDE.store(cap & CAP_64BIT != 0, Ordering::SeqCst);
    // Whether the counter really ticks.
    let a = read32(REG_COUNTER);
    let mut moved = false;
    for _ in 0..1_000_000 {
        if read32(REG_COUNTER) != a {
            moved = true;
            break;
        }
        core::hint::spin_loop();
    }
    if !moved {
        serial_println!("[CLOCK] HPET at {:#x} does not count - using TSC", phys);
        BASE.store(0, Ordering::SeqCst);
        return;
    }
    PERIOD_FS.store(period, Ordering::SeqCst);
    serial_println!(
        "[CLOCK] HPET at {:#x}: {} kHz, {}-bit counter - time intervals (watchdog, spinlocks) independent of TSC",
        phys,
        1_000_000_000_000 / period,
        if cap & CAP_64BIT != 0 { 64 } else { 32 }
    );
}

/// Whether intervals are measured by HPET.
pub fn hpet() -> bool {
    PERIOD_FS.load(Ordering::Relaxed) != 0
}

/// 64-bit HPET counter read without tearing: upper half, lower, upper again
/// (until both upper halves match).  QEMU may perform a single 64-bit read as
/// two 32-bit ones – on a carry out of the lower half the result jumped by 2^32
/// ticks (43 s) forward or backward (seen on real hardware: "368934882128455 ms" of waiting
/// for the BKL in `cpus` – two negative intervals).
fn read_counter64() -> u64 {
    loop {
        let hi = read32(REG_COUNTER + 4);
        let lo = read32(REG_COUNTER);
        if read32(REG_COUNTER + 4) == hi {
            return ((hi as u64) << 32) | lo as u64;
        }
    }
}

/// Timestamp (raw; only for `elapsed_us`).
#[inline]
pub fn stamp() -> u64 {
    if hpet() {
        if WIDE.load(Ordering::Relaxed) { read_counter64() } else { read32(REG_COUNTER) as u64 }
    } else {
        rdtsc()
    }
}

/// TSC timestamp for measurements in lock paths.  Reading the HPET is an
/// MMIO access – under KVM an exit to QEMU (serialized between vCPUs, tens of
/// µs), on hardware ~1 µs; done after taking a lock it lengthened the
/// hold time (critical sections take ~1 µs) – the scheduler lock got 87% of waits.  TSC:
/// a few tens of cycles, but comparable only on the same CPU (on some machines
/// per-core TSCs differ) and can be unreliable (TCG) – statistics only,
/// never deadlock detection (that uses HPET, outside the lock).
///
/// TSC and CPU number in a single instruction (rdtscp; without rdtscp – CPU 0).
#[inline]
pub fn tsc_cpu() -> (u64, u32) {
    if !crate::arch::x86_64::cpu::has_rdtscp() {
        return (rdtsc(), 0);
    }
    let (lo, hi, aux): (u32, u32, u32);
    unsafe { core::arch::asm!("rdtscp", out("eax") lo, out("edx") hi, out("ecx") aux, options(nomem, nostack, preserves_flags)) };
    (((hi as u64) << 32) | lo as u64, aux)
}

/// Microseconds since a `tsc_cpu()` timestamp, if we are on the same CPU
/// (otherwise None – per-core TSCs are not comparable).
#[inline]
pub fn tsc_us_on(start: u64, cpu: u32) -> Option<u64> {
    let (now, c) = tsc_cpu();
    if c != cpu {
        return None;
    }
    let d = now.wrapping_sub(start);
    if d > 1 << 62 {
        return Some(0);
    }
    let per_ms = crate::arch::x86_64::lapic::tsc_per_ms();
    Some(if per_ms == 0 { d / 4000 } else { d / (per_ms / 1000).max(1) })
}

/// Lock wait time for STATISTICS (TSC since `tsc_cpu()`).
/// 0 when the CPU changed or the result is unreliable (> 10 s – a TSC jump,
/// e.g. under TCG).  For deadlock detection use HPET (`stamp`), not this.
#[inline]
pub fn tsc_wait_us(start: u64, cpu: u32) -> u64 {
    match tsc_us_on(start, cpu) {
        Some(us) if us <= 10_000_000 => us,
        _ => 0,
    }
}

/// Microseconds between two `stamp()` timestamps (b later than a; 0 for
/// the reverse order).
pub fn us_between(a: u64, b: u64) -> u64 {
    diff_us(a, b).max(0) as u64
}

/// Microseconds since the `start` timestamp (0 while the clock is still unknown).
#[inline]
pub fn elapsed_us(start: u64) -> u64 {
    let now = stamp();
    let period = PERIOD_FS.load(Ordering::Relaxed);
    if period != 0 {
        let ticks = if WIDE.load(Ordering::Relaxed) {
            // A timestamp "from the future" (e.g. taken before init – TSC) = 0, not 2^64.
            let d = now.wrapping_sub(start);
            if d > u64::MAX / 2 {
                return 0;
            }
            d
        } else {
            (now as u32).wrapping_sub(start as u32) as u64
        };
        // fs -> us: * period / 1e9 (u128 – no overflow).
        ((ticks as u128 * period as u128) / 1_000_000_000) as u64
    } else {
        let per_ms = super::lapic::tsc_per_ms();
        if per_ms == 0 {
            return 0;
        }
        let d = now.wrapping_sub(start);
        if d > u64::MAX / 2 {
            return 0;
        }
        d.saturating_mul(1000) / per_ms
    }
}

/// Difference between two timestamps in microseconds (b after a; signed).
pub fn diff_us(a: u64, b: u64) -> i64 {
    let period = PERIOD_FS.load(Ordering::Relaxed);
    if period != 0 {
        let d = if WIDE.load(Ordering::Relaxed) { b.wrapping_sub(a) as i64 } else { (b as u32).wrapping_sub(a as u32) as i32 as i64 };
        ((d as i128 * period as i128) / 1_000_000_000) as i64
    } else {
        let per_ms = super::lapic::tsc_per_ms().max(1) as i64;
        (b.wrapping_sub(a) as i64).saturating_mul(1000) / per_ms
    }
}
