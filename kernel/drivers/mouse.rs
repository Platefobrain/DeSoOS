// PS/2 mouse (port 2 of the 8042 controller, IRQ12).
//
// Packet (standard set, after initialization in ps2.rs):
//   byte 0: buttons (bit 0 left, 1 right, 2 middle), bit 3 = always 1
//           (synchronization), bits 4/5 = dx/dy sign, 6/7 = overflow
//   byte 1: dx, byte 2: dy (9-bit with the sign bit from byte 0)
//   byte 3: IntelliMouse only (ID 3/4): wheel dz, 4 signed bits
//           (negative = wheel away from the user = up)
//
// For now the mouse is used to scroll the console with the wheel (scrollback).  The IRQ
// handler only accumulates wheel movement; `console` does the scrolling (outside the interrupt),
// because redrawing the screen takes too long for a handler.  Movement and buttons are
// counted – they will be useful for a GUI.

use core::sync::atomic::{AtomicI32, AtomicU64, AtomicU8, Ordering};

use super::ps2;
use crate::arch::x86_64::irq;
use crate::serial_println;

const MOUSE_IRQ: u8 = 12;

static PACKET_LEN: AtomicU8 = AtomicU8::new(3);
static WHEEL: AtomicI32 = AtomicI32::new(0); // sum of dz since the last read
static PACKETS: AtomicU64 = AtomicU64::new(0);
static BUTTONS: AtomicU8 = AtomicU8::new(0);
static RESYNCS: AtomicU64 = AtomicU64::new(0);

struct Decoder {
    bytes: [u8; 4],
    len: usize,
}

static mut DECODER: Decoder = Decoder { bytes: [0; 4], len: 0 };

fn decoder() -> &'static mut Decoder {
    // Only from IRQ handlers (IF=0).
    unsafe { &mut *core::ptr::addr_of_mut!(DECODER) }
}

/// One byte from the mouse (from IRQ12, or from IRQ1 if the controller delivered it that way).
pub fn handle_byte(byte: u8) {
    let d = decoder();
    if d.len == 0 && byte & 0x08 == 0 {
        // Byte 0 must have bit 3 set – otherwise we have lost synchronization.
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
        // 4 signed bits (ID 4 has buttons 4/5 in the upper bits).
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

/// Registers IRQ12 if ps2::init found a mouse.  Call after keyboard::init.
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

/// Wheel movement since the last call (negative = up / away from the user).
/// The USB mouse wheel (usbd via input_inject) is handled like a PS/2 packet.
pub fn add_wheel(dz: i32) {
    WHEEL.fetch_add(dz, Ordering::Relaxed);
    crate::console::wake_input();
}

pub fn take_wheel() -> i32 {
    WHEEL.swap(0, Ordering::Relaxed)
}

pub fn has_wheel() -> bool {
    WHEEL.load(Ordering::Relaxed) != 0
}

/// (packets, buttons, lost synchronizations) – diagnostics.
#[allow(dead_code)]
pub fn stats() -> (u64, u8, u64) {
    (
        PACKETS.load(Ordering::Relaxed),
        BUTTONS.load(Ordering::Relaxed),
        RESYNCS.load(Ordering::Relaxed),
    )
}

// ------------------------------------------------------------
// TEST (selftest build only, --cfg selftest)
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

/// Injects bytes through the controller (0xD3) and waits until IRQ12 receives them.
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

    // 1. Mouse enabled, IRQ12 and the cascade unmasked.
    let id = ps2::mouse_id().unwrap_or(0xFF);
    let cfg = ps2::config().unwrap_or(0);
    check!(cfg & ps2::CONFIG_PORT2_IRQ != 0, "port 2 IRQ disabled (config {:#x})", cfg);
    check!(cfg & ps2::CONFIG_PORT2_CLOCK_OFF == 0, "port 2 clock off (config {:#x})", cfg);
    check!(!irq::is_masked(MOUSE_IRQ) && (irq::ioapic_mode() || !irq::is_masked(2)), "IRQ12/cascade masked");
    check!(id == 3 || id == 4, "mouse ID {} (no wheel mode)", id);
    serial_println!("[MOUSE TEST] 1/3 mouse ID {}, IRQ12 unmasked, config {:#04x} PASS", id, cfg);

    // 2. Packet with the wheel up (dz = -1) and down (dz = +2) via IRQ12.
    take_wheel();
    let p0 = stats().0;
    check!(inject(&[0x08, 0, 0, 0x0F]), "inject wheel up timed out");
    check!(take_wheel() == -1, "wheel up not decoded");
    check!(inject(&[0x09, 0, 0, 0x02]), "inject wheel down timed out");
    check!(take_wheel() == 2, "wheel down not decoded");
    check!(stats().0 == p0 + 2 && stats().1 == 1, "packets/buttons {:?}", stats());
    serial_println!("[MOUSE TEST] 2/3 wheel packets via IRQ12 (up -1, down +2, left button) PASS");

    // 3. Loss of synchronization: a byte without bit 3 is skipped, the next
    //    packet decodes correctly.
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
