// M17a: zegar do mierzenia odcinków czasu – HPET, a bez niego TSC.
//
// Dlaczego nie samo TSC: na części maszyn liczniki TSC rdzeni nie są ze
// sobą zgodne (np. QEMU z emulacją TCG na hoście, którego rdzenie mają różne
// TSC – wątek wirtualnego CPU przenoszony między rdzeniami hosta widzi skoki
// o sekundy).  Watchdog i detektor zakleszczeń mierzone TSC zgłaszały wtedy
// fałszywe "zegar stoi" / "deadlock" (test na komputerze Dawida: czasy
// odpowiedzi na NMI równo 1x, 2x, 3x, 5x 2535 ms).  HPET to jeden licznik na
// płycie głównej, wspólny dla wszystkich CPU – Linux przechodzi na niego,
// gdy uzna TSC za niestabilny.
//
// API mierzy ODCINKI: `stamp()` + `elapsed_us(start)`.  Licznik HPET bywa
// 32-bitowy (często u AMD; 14,318 MHz -> przekręca się co ~300 s), więc
// różnica liczona jest na tylu bitach, ile ma licznik – poprawna dla
// odcinków krótszych niż ~5 minut (nasze: najwyżej kilkadziesiąt sekund).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::serial_println;

const REG_CAP: u64 = 0x000;
const REG_CONF: u64 = 0x010;
const REG_COUNTER: u64 = 0x0F0;
const CONF_ENABLE: u64 = 1;
const CAP_64BIT: u64 = 1 << 13;

static BASE: AtomicU64 = AtomicU64::new(0);
/// Okres licznika HPET w femtosekundach (0 = brak HPET).
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

/// Włącza licznik HPET z tablicy ACPI (bez trybu "legacy replacement" – PIT
/// działa dalej).  Po acpi::init i starcie pamięci.
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
    // Specyfikacja: okres > 0 i <= 100 ns.
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
    // Czy licznik naprawdę idzie.
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

/// Czy odcinki mierzy HPET.
pub fn hpet() -> bool {
    PERIOD_FS.load(Ordering::Relaxed) != 0
}

/// 64-bitowy licznik HPET bez rozerwania: górna połowa, dolna, znowu górna
/// (aż obie górne równe).  Jeden 64-bitowy odczyt QEMU potrafi wykonać jako
/// dwa 32-bitowe – przy przeniesieniu z dolnej połowy wynik skakał o 2^32
/// taktów (43 s) w przód albo w tył (u Dawida: "368934882128455 ms" czekania
/// na BKL w `cpus` – dwa odcinki ujemne).
fn read_counter64() -> u64 {
    loop {
        let hi = read32(REG_COUNTER + 4);
        let lo = read32(REG_COUNTER);
        if read32(REG_COUNTER + 4) == hi {
            return ((hi as u64) << 32) | lo as u64;
        }
    }
}

/// Znacznik czasu (surowy; tylko do `elapsed_us`).
#[inline]
pub fn stamp() -> u64 {
    if hpet() {
        if WIDE.load(Ordering::Relaxed) { read_counter64() } else { read32(REG_COUNTER) as u64 }
    } else {
        rdtsc()
    }
}

/// M17a.g13: znacznik TSC do pomiarów w ścieżkach blokad.  Odczyt HPET to
/// dostęp MMIO – w KVM wyjście do QEMU (szeregowane między vCPU, dziesiątki
/// µs), na sprzęcie ~1 µs; robiony po wzięciu blokady wydłużał jej
/// trzymanie (sekcje trwają ~1 µs) – blokada schedulera 87% czekań.  TSC:
/// kilkadziesiąt cykli, ale porównywalny tylko na tym samym CPU (Legion:
/// TSC rdzeni się różnią) i bywa niewiarygodny (TCG) – tylko statystyka,
/// nigdy wykrywanie zakleszczeń (to HPET, poza blokadą).
///
/// TSC i numer CPU jednym rozkazem (rdtscp; bez rdtscp – CPU 0).
#[inline]
pub fn tsc_cpu() -> (u64, u32) {
    if !crate::arch::x86_64::cpu::has_rdtscp() {
        return (rdtsc(), 0);
    }
    let (lo, hi, aux): (u32, u32, u32);
    unsafe { core::arch::asm!("rdtscp", out("eax") lo, out("edx") hi, out("ecx") aux, options(nomem, nostack, preserves_flags)) };
    (((hi as u64) << 32) | lo as u64, aux)
}

/// Mikrosekundy od znacznika `tsc_cpu()`, jeśli jesteśmy na tym samym CPU
/// (inaczej None – TSC rdzeni nieporównywalne).
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

/// M17a.g14: czas czekania na blokadę do STATYSTYKI (TSC od `tsc_cpu()`).
/// 0, gdy CPU się zmienił albo wynik jest niewiarygodny (> 10 s – skok TSC,
/// np. pod TCG).  Do wykrywania zakleszczeń – HPET (`stamp`), nie to.
#[inline]
pub fn tsc_wait_us(start: u64, cpu: u32) -> u64 {
    match tsc_us_on(start, cpu) {
        Some(us) if us <= 10_000_000 => us,
        _ => 0,
    }
}

/// Mikrosekundy między dwoma znacznikami `stamp()` (b później niż a; 0 przy
/// odwrotnej kolejności).
pub fn us_between(a: u64, b: u64) -> u64 {
    diff_us(a, b).max(0) as u64
}

/// Mikrosekundy od znacznika `start` (0, gdy zegar jeszcze nieznany).
#[inline]
pub fn elapsed_us(start: u64) -> u64 {
    let now = stamp();
    let period = PERIOD_FS.load(Ordering::Relaxed);
    if period != 0 {
        let ticks = if WIDE.load(Ordering::Relaxed) {
            // Znacznik "z przyszłości" (np. sprzed init – TSC) = 0, nie 2^64.
            let d = now.wrapping_sub(start);
            if d > u64::MAX / 2 {
                return 0;
            }
            d
        } else {
            (now as u32).wrapping_sub(start as u32) as u64
        };
        // fs -> us: * period / 1e9 (u128 – bez przepełnienia).
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

/// Różnica dwóch znaczników w mikrosekundach (b po a; ze znakiem).
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
