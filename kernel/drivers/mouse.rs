// M11b: mysz PS/2 (port 2 kontrolera 8042, IRQ12).
//
// Pakiet (zestaw standardowy, po inicjalizacji w ps2.rs):
//   bajt 0: przyciski (bit 0 lewy, 1 prawy, 2 środkowy), bit 3 = zawsze 1
//           (synchronizacja), bity 4/5 = znak dx/dy, 6/7 = przepełnienie
//   bajt 1: dx, bajt 2: dy (9-bitowe z bitem znaku z bajtu 0)
//   bajt 3: tylko IntelliMouse (ID 3/4): kółko dz, 4 bity ze znakiem
//           (ujemne = kółko od siebie = w górę)
//
// Na razie mysz służy do przewijania konsoli kółkiem (scrollback).  Handler
// IRQ tylko zbiera ruch kółka; przewija `console` (poza przerwaniem), bo
// przerysowanie ekranu jest za długie na handler.  Ruch i przyciski są
// liczone – przydadzą się przy GUI.

use core::sync::atomic::{AtomicI32, AtomicU64, AtomicU8, Ordering};

use super::ps2;
use crate::arch::x86_64::irq;
use crate::serial_println;

const MOUSE_IRQ: u8 = 12;

static PACKET_LEN: AtomicU8 = AtomicU8::new(3);
static WHEEL: AtomicI32 = AtomicI32::new(0); // suma dz od ostatniego odbioru
static PACKETS: AtomicU64 = AtomicU64::new(0);
static BUTTONS: AtomicU8 = AtomicU8::new(0);
static RESYNCS: AtomicU64 = AtomicU64::new(0);

struct Decoder {
    bytes: [u8; 4],
    len: usize,
}

static mut DECODER: Decoder = Decoder { bytes: [0; 4], len: 0 };

fn decoder() -> &'static mut Decoder {
    // Tylko z handlerów IRQ (IF=0).
    unsafe { &mut *core::ptr::addr_of_mut!(DECODER) }
}

/// Jeden bajt od myszy (z IRQ12, albo z IRQ1, jeśli kontroler tak go podał).
pub fn handle_byte(byte: u8) {
    let d = decoder();
    if d.len == 0 && byte & 0x08 == 0 {
        // Bajt 0 musi mieć bit 3 – inaczej zgubiliśmy synchronizację.
        RESYNCS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    d.bytes[d.len] = byte;
    d.len += 1;
    if d.len < PACKET_LEN.load(Ordering::Relaxed) as usize {
        return;
    }
    d.len = 0;
    PACKETS.fetch_add(1, Ordering::Relaxed);
    BUTTONS.store(d.bytes[0] & 0x07, Ordering::Relaxed);
    if PACKET_LEN.load(Ordering::Relaxed) == 4 {
        // 4 bity ze znakiem (ID 4 ma w górnych bitach przyciski 4/5).
        let dz = ((d.bytes[3] << 4) as i8) >> 4;
        if dz != 0 {
            WHEEL.fetch_add(dz as i32, Ordering::Relaxed);
            crate::console::wake_input();
        }
    }
}

fn on_irq(_irq: u8) {
    let Some((byte, aux)) = ps2::read_irq_byte() else {
        return;
    };
    if aux {
        handle_byte(byte);
    } else {
        super::keyboard::handle_byte(byte);
    }
}

/// Rejestruje IRQ12, jeśli ps2::init znalazł mysz.  Wołać po keyboard::init.
pub fn init() -> bool {
    let Some(id) = ps2::mouse_id() else {
        serial_println!("[MOUSE] No PS/2 mouse");
        return false;
    };
    PACKET_LEN.store(if id >= 3 { 4 } else { 3 }, Ordering::Relaxed);
    if !irq::register(MOUSE_IRQ, on_irq) {
        serial_println!("[MOUSE] IRQ12 already taken");
        return false;
    }
    irq::unmask(MOUSE_IRQ);
    serial_println!(
        "[MOUSE] PS/2 mouse ready (IRQ12, ID {}, {})",
        id,
        if id >= 3 { "wheel scrolls the console" } else { "no wheel" }
    );
    true
}

/// Ruch kółka od ostatniego wywołania (ujemny = w górę / od siebie).
pub fn take_wheel() -> i32 {
    WHEEL.swap(0, Ordering::Relaxed)
}

pub fn has_wheel() -> bool {
    WHEEL.load(Ordering::Relaxed) != 0
}

/// (pakiety, przyciski, zgubione synchronizacje) – diagnostyka.
#[allow(dead_code)]
pub fn stats() -> (u64, u8, u64) {
    (
        PACKETS.load(Ordering::Relaxed),
        BUTTONS.load(Ordering::Relaxed),
        RESYNCS.load(Ordering::Relaxed),
    )
}

// ------------------------------------------------------------
// TEST (tylko build z --cfg selftest)
// ------------------------------------------------------------

#[cfg(selftest)]
macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[MOUSE TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

/// Wstrzykuje bajty przez kontroler (0xD3) i czeka, aż IRQ12 je odbierze.
#[cfg(selftest)]
fn inject(bytes: &[u8]) -> bool {
    for &b in bytes {
        let before = irq::count(MOUSE_IRQ);
        if !ps2::inject_mouse_byte(b) {
            return false;
        }
        let deadline = crate::time::ticks() + 50;
        while irq::count(MOUSE_IRQ) == before {
            if crate::time::ticks() > deadline {
                return false;
            }
            crate::arch::x86_64::interrupts::enable_and_hlt();
        }
    }
    true
}

#[cfg(selftest)]
pub fn self_test() {
    serial_println!("[MOUSE TEST] Starting mouse tests...");
    crate::selftest::begin();

    // 1. Mysz włączona, IRQ12 i kaskada odmaskowane.
    let id = ps2::mouse_id().unwrap_or(0xFF);
    let cfg = ps2::config().unwrap_or(0);
    check!(cfg & ps2::CONFIG_PORT2_IRQ != 0, "port 2 IRQ disabled (config {:#x})", cfg);
    check!(cfg & ps2::CONFIG_PORT2_CLOCK_OFF == 0, "port 2 clock off (config {:#x})", cfg);
    check!(!irq::is_masked(MOUSE_IRQ) && (irq::ioapic_mode() || !irq::is_masked(2)), "IRQ12/cascade masked");
    check!(id == 3 || id == 4, "mouse ID {} (no wheel mode)", id);
    serial_println!("[MOUSE TEST] 1/3 mouse ID {}, IRQ12 unmasked, config {:#04x} PASS", id, cfg);

    // 2. Pakiet z kółkiem w górę (dz = -1) i w dół (dz = +2) przez IRQ12.
    take_wheel();
    let p0 = stats().0;
    check!(inject(&[0x08, 0, 0, 0x0F]), "inject wheel up timed out");
    check!(take_wheel() == -1, "wheel up not decoded");
    check!(inject(&[0x09, 0, 0, 0x02]), "inject wheel down timed out");
    check!(take_wheel() == 2, "wheel down not decoded");
    check!(stats().0 == p0 + 2 && stats().1 == 1, "packets/buttons {:?}", stats());
    serial_println!("[MOUSE TEST] 2/3 wheel packets via IRQ12 (up -1, down +2, left button) PASS");

    // 3. Utrata synchronizacji: bajt bez bitu 3 jest pomijany, następny
    //    pakiet dekoduje się poprawnie.
    let r0 = stats().2;
    check!(inject(&[0x00, 0x08, 0, 0, 0x0F]), "inject resync");
    check!(stats().2 == r0 + 1 && take_wheel() == -1, "resync failed {:?}", stats());
    check!(inject(&[0x08, 0, 0, 0]), "inject release");
    serial_println!("[MOUSE TEST] 3/3 resync after a stray byte PASS");

    serial_println!("[MOUSE TEST] =================================");
    crate::selftest::pass();
    serial_println!("[MOUSE TEST] MOUSE TESTS PASSED");
    serial_println!("[MOUSE TEST] =================================");
}
