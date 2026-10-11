// M16b: Local APIC – minimum potrzebne do przerwań MSI/MSI-X.
//
// Przerwania z PIC-a (zegar, klawiatura, serial) dalej idą jak dotąd:
// firmware zostawia LAPIC w trybie "virtual wire" (PIC -> LINT0 jako ExtINT)
// i ich EOI dostaje PIC.  Urządzenia PCIe z MSI/MSI-X piszą natomiast
// komunikat pod adres 0xFEE0_0000 – trafia on prosto do LAPIC jako
// przerwanie o podanym wektorze i wymaga EOI w LAPIC.
//
// Dlaczego MSI, a nie INTx: na prawdziwym komputerze to, do której linii
// IRQ podłączono INTx urządzenia, opisuje ACPI w kodzie AML (_PRT) – bez
// interpretera AML nie da się tego ustalić.  MSI nie ma tego problemu.
//
// M17: I/O APIC (ioapic.rs) zamiast PIC, timer LAPIC na AP, IPI (start AP,
// pobudka bezczynnego CPU, zatrzymanie przy panic).
// Obsługiwane oba tryby: xAPIC (MMIO pod adresem z MSR) i x2APIC (MSR),
// bo część firmware włącza x2APIC przed startem systemu.

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use crate::serial_println;

const IA32_APIC_BASE: u32 = 0x1B;
const APIC_GLOBAL_ENABLE: u64 = 1 << 11;
const APIC_X2APIC: u64 = 1 << 10;

const REG_ID: u32 = 0x20;
const REG_VERSION: u32 = 0x30;
const REG_EOI: u32 = 0xB0;
const REG_SVR: u32 = 0xF0;
const REG_TPR: u32 = 0x80;
const REG_ESR: u32 = 0x280;
const REG_ICR_LOW: u32 = 0x300;
const REG_ICR_HIGH: u32 = 0x310;
const REG_LVT_TIMER: u32 = 0x320;
const REG_LVT_LINT0: u32 = 0x350;
const REG_LVT_LINT1: u32 = 0x360;
const REG_LVT_ERROR: u32 = 0x370;
const REG_TIMER_INITIAL: u32 = 0x380;
const REG_TIMER_CURRENT: u32 = 0x390;
const REG_TIMER_DIVIDE: u32 = 0x3E0;

const LVT_MASKED: u32 = 1 << 16;
const TIMER_PERIODIC: u32 = 1 << 17;
/// Dzielnik zegara timera: 16 (kod 0b0011).
const TIMER_DIV_16: u32 = 0b0011;

/// M17: wektory LAPIC – timer AP, IPI "przełącz zadanie", IPI "stop" (panic).
pub const TIMER_VECTOR: u8 = 0x40;
pub const RESCHED_VECTOR: u8 = 0x41;
pub const HALT_VECTOR: u8 = 0x42;
/// Okres timera LAPIC na AP (ms).
pub const AP_TICK_MS: u32 = 10;

const SVR_ENABLE: u32 = 1 << 8;
/// Wektor "spurious" LAPIC (handler nic nie robi, bez EOI – idt.rs).
pub const SPURIOUS_VECTOR: u8 = 0xFF;

const MODE_NONE: u8 = 0;
const MODE_XAPIC: u8 = 1;
const MODE_X2APIC: u8 = 2;

static MODE: AtomicU8 = AtomicU8::new(MODE_NONE);
static BASE: AtomicU64 = AtomicU64::new(0); // adres wirtualny (xAPIC)
static ID: AtomicU64 = AtomicU64::new(0);
/// Takty timera LAPIC (dzielnik 16) na 1 ms – z kalibracji na BSP.
static TICKS_PER_MS: AtomicU64 = AtomicU64::new(0);
/// Takty TSC na 1 ms (ta sama kalibracja; watchdog).
static TSC_PER_MS: AtomicU64 = AtomicU64::new(0);

fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    ((hi as u64) << 32) | lo as u64
}

/// Takty TSC na ms (0 = nieskalibrowane).
pub fn tsc_per_ms() -> u64 {
    TSC_PER_MS.load(Ordering::Relaxed)
}

unsafe fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | lo as u64
}

unsafe fn wrmsr(msr: u32, value: u64) {
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") value as u32, in("edx") (value >> 32) as u32,
            options(nostack, preserves_flags));
    }
}

fn read(reg: u32) -> u32 {
    match MODE.load(Ordering::Relaxed) {
        MODE_X2APIC => unsafe { rdmsr(0x800 + (reg >> 4)) as u32 },
        MODE_XAPIC => unsafe { core::ptr::read_volatile((BASE.load(Ordering::Relaxed) + reg as u64) as *const u32) },
        _ => 0,
    }
}

fn write(reg: u32, value: u32) {
    match MODE.load(Ordering::Relaxed) {
        MODE_X2APIC => unsafe { wrmsr(0x800 + (reg >> 4), value as u64) },
        MODE_XAPIC => unsafe {
            core::ptr::write_volatile((BASE.load(Ordering::Relaxed) + reg as u64) as *mut u32, value)
        },
        _ => {}
    }
}

/// Włącza dostęp do LAPIC.  `false` – brak (MSI niedostępne, sterowniki
/// przechodzą na odpytywanie).  Po starcie pamięci (map_mmio).
pub fn init() -> bool {
    #[allow(unused_unsafe)]
    let has_apic = unsafe { core::arch::x86_64::__cpuid(1) }.edx & (1 << 9) != 0;
    if !has_apic {
        serial_println!("[APIC] CPU without a local APIC - MSI not available");
        return false;
    }
    let base_msr = unsafe { rdmsr(IA32_APIC_BASE) };
    if base_msr & APIC_GLOBAL_ENABLE == 0 {
        serial_println!("[APIC] local APIC disabled by the firmware - MSI not available");
        return false;
    }
    let x2 = base_msr & APIC_X2APIC != 0;
    if x2 {
        MODE.store(MODE_X2APIC, Ordering::SeqCst);
    } else {
        let phys = base_msr & 0x000F_FFFF_FFFF_F000;
        let Some(virt) = crate::memory::map_mmio(phys, 4096) else {
            serial_println!("[APIC] cannot map the local APIC at {:#x} - MSI not available", phys);
            return false;
        };
        BASE.store(virt, Ordering::SeqCst);
        MODE.store(MODE_XAPIC, Ordering::SeqCst);
    }
    let id = if x2 { read(REG_ID) as u64 } else { (read(REG_ID) >> 24) as u64 };
    ID.store(id, Ordering::SeqCst);

    // LAPIC programowo wyłączony (rzadkie) – włączamy go w konfiguracji
    // "virtual wire" (LINT0 = ExtINT z PIC-a, LINT1 = NMI), tak jak Linux,
    // żeby przerwania z PIC-a dalej dochodziły.
    let svr = read(REG_SVR);
    let was_enabled = svr & SVR_ENABLE != 0;
    if !was_enabled {
        write(REG_LVT_LINT0, 0x700); // ExtINT
        write(REG_LVT_LINT1, 0x400); // NMI
        write(REG_SVR, (svr & !0xFF) | SVR_ENABLE | SPURIOUS_VECTOR as u32);
    }
    serial_println!(
        "[APIC] local APIC {} id {} version {:#x}{} - MSI/MSI-X available",
        if x2 { "x2APIC" } else { "xAPIC" },
        id,
        read(REG_VERSION) & 0xFF,
        if was_enabled { "" } else { " (enabled now, virtual wire)" }
    );
    true
}

pub fn available() -> bool {
    MODE.load(Ordering::Relaxed) != MODE_NONE
}

/// Koniec obsługi przerwania MSI.
pub fn eoi() {
    write(REG_EOI, 0);
}

/// ID Local APIC procesora startowego (BSP) – zapisane przy init.
pub fn bsp_id() -> u64 {
    ID.load(Ordering::Relaxed)
}

/// ID Local APIC procesora, na którym działa kod (M17: SMP).
pub fn id() -> u64 {
    match MODE.load(Ordering::Relaxed) {
        MODE_X2APIC => read(REG_ID) as u64,
        MODE_XAPIC => (read(REG_ID) >> 24) as u64,
        _ => 0,
    }
}

// ------------------------------------------------------------
// M17: timer LAPIC i przerwania między procesorami (IPI)
// ------------------------------------------------------------

/// Kalibruje timer LAPIC zegarem PIT (ticki co 1 ms).  BSP, z włączonymi
/// przerwaniami, po time::init.  `false` – nie wyszło (brak LAPIC / zegara).
pub fn calibrate_timer() -> bool {
    if !available() {
        return false;
    }
    const MS: u64 = 20;
    // Start na granicy ticku.
    let t0 = crate::time::ticks();
    let mut guard = 0u64;
    while crate::time::ticks() == t0 {
        core::hint::spin_loop();
        guard += 1;
        if guard > 2_000_000_000 {
            return false;
        }
    }
    write(REG_TIMER_DIVIDE, TIMER_DIV_16);
    write(REG_LVT_TIMER, LVT_MASKED | TIMER_VECTOR as u32);
    let start = crate::time::ticks();
    let tsc0 = rdtsc();
    write(REG_TIMER_INITIAL, u32::MAX);
    while crate::time::ticks() < start + MS {
        core::hint::spin_loop();
    }
    let left = read(REG_TIMER_CURRENT);
    TSC_PER_MS.store(rdtsc().wrapping_sub(tsc0) / MS, Ordering::SeqCst);
    write(REG_TIMER_INITIAL, 0);
    let per_ms = (u32::MAX - left) as u64 / MS;
    if per_ms == 0 {
        return false;
    }
    TICKS_PER_MS.store(per_ms, Ordering::SeqCst);
    serial_println!(
        "[APIC] LAPIC timer: {} ticks/ms (bus ~{} MHz, divider 16), TSC ~{} MHz",
        per_ms,
        per_ms * 16 / 1000,
        TSC_PER_MS.load(Ordering::Relaxed) / 1000
    );
    true
}

pub fn timer_ticks_per_ms() -> u64 {
    TICKS_PER_MS.load(Ordering::Relaxed)
}

/// Okresowy timer LAPIC bieżącego CPU: wektor TIMER_VECTOR co `ms` ms.
pub fn start_periodic_timer(ms: u32) {
    let per_ms = TICKS_PER_MS.load(Ordering::Relaxed);
    let count = (per_ms * ms as u64).clamp(1, u32::MAX as u64) as u32;
    write(REG_TIMER_DIVIDE, TIMER_DIV_16);
    write(REG_LVT_TIMER, TIMER_PERIODIC | TIMER_VECTOR as u32);
    write(REG_TIMER_INITIAL, count);
}

/// LAPIC procesora AP: ten sam tryb co BSP, włączony, LINT0/LINT1
/// zamaskowane (przerwania ISA idą przez I/O APIC do BSP), TPR = 0.
pub fn init_ap() -> bool {
    let base = unsafe { rdmsr(IA32_APIC_BASE) };
    match MODE.load(Ordering::Relaxed) {
        MODE_X2APIC => {
            if base & APIC_X2APIC == 0 {
                unsafe { wrmsr(IA32_APIC_BASE, base | APIC_GLOBAL_ENABLE) };
                unsafe { wrmsr(IA32_APIC_BASE, base | APIC_GLOBAL_ENABLE | APIC_X2APIC) };
            }
        }
        MODE_XAPIC => {
            if base & APIC_X2APIC != 0 {
                return false; // AP w innym trybie niż BSP – nie obsługujemy
            }
            if base & APIC_GLOBAL_ENABLE == 0 {
                unsafe { wrmsr(IA32_APIC_BASE, base | APIC_GLOBAL_ENABLE) };
            }
        }
        _ => return false,
    }
    write(REG_TPR, 0);
    write(REG_LVT_LINT0, LVT_MASKED);
    write(REG_LVT_LINT1, 0x400); // NMI
    write(REG_LVT_ERROR, LVT_MASKED);
    write(REG_SVR, SVR_ENABLE | SPURIOUS_VECTOR as u32);
    write(REG_ESR, 0);
    eoi();
    true
}

/// Wysyła IPI: `low` = tryb dostarczenia + wektor, `dest` = APIC ID.
fn send_icr(dest: u32, low: u32) {
    match MODE.load(Ordering::Relaxed) {
        MODE_X2APIC => unsafe { wrmsr(0x830, ((dest as u64) << 32) | low as u64) },
        MODE_XAPIC => {
            write(REG_ICR_HIGH, (dest & 0xFF) << 24);
            write(REG_ICR_LOW, low);
            // Czekamy, aż LAPIC wyśle (bit 12: delivery status).
            let mut n = 0;
            while read(REG_ICR_LOW) & (1 << 12) != 0 && n < 1_000_000 {
                core::hint::spin_loop();
                n += 1;
            }
        }
        _ => {}
    }
}

/// INIT (procesor `apic_id` wraca do stanu po resecie i czeka na SIPI).
pub fn send_init(apic_id: u32) {
    send_icr(apic_id, 0x0000_4500); // INIT, level assert
}

/// Startup IPI: procesor zaczyna w trybie rzeczywistym od adresu `page * 4096`.
pub fn send_sipi(apic_id: u32, page: u8) {
    send_icr(apic_id, 0x0000_4600 | page as u32);
}

/// Zwykłe przerwanie `vector` na procesorze `apic_id`.
pub fn send_ipi(apic_id: u32, vector: u8) {
    send_icr(apic_id, 0x0000_4000 | vector as u32);
}

/// NMI do wszystkich procesorów poza bieżącym (watchdog – działa także przy
/// wyłączonych przerwaniach).
pub fn send_nmi_others() {
    send_icr(0, (0b11 << 18) | 0x0000_4400);
}

/// Przerwanie `vector` do wszystkich procesorów poza bieżącym.
pub fn send_ipi_others(vector: u8) {
    send_icr(0, (0b11 << 18) | 0x0000_4000 | vector as u32);
}

/// Adres komunikatu MSI: przerwanie do procesora startowego (BSP), tryb fizyczny.
pub fn msi_address() -> u64 {
    0xFEE0_0000 | ((bsp_id() & 0xFF) << 12)
}
