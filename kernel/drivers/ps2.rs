// PS/2 controller (Intel 8042).
//
// Ports: 0x60 = data (read: byte from the device, write: byte to the
// device), 0x64 = status (read) / controller command (write).
//
// Configuration after `init()`:
//   * port 1 (keyboard) enabled, IRQ1 enabled,
//   * port 2 (mouse): enabled if a mouse responds; IntelliMouse mode
//     (wheel) via the "magic" sample-rate sequence 200/100/80,
//   * translation enabled: the keyboard speaks scan code set 2, the controller
//     translates to set 1 (simpler, one byte for most keys).
//
// Waiting for the controller: with interrupts enabled via `hlt`
// (woken by the 1 ms tick – no tight loop on the ports), with
// interrupts disabled – a bounded number of attempts.

use crate::arch::x86_64::interrupts;
use crate::arch::x86_64::port::{inb, outb};
use crate::serial_println;

const DATA: u16 = 0x60;
const STATUS: u16 = 0x64;
const COMMAND: u16 = 0x64;

const STATUS_OUTPUT_FULL: u8 = 1 << 0; // a byte is available to read from 0x60
const STATUS_INPUT_FULL: u8 = 1 << 1; // the controller has not accepted the write yet
pub const STATUS_AUX_DATA: u8 = 1 << 5; // the byte in 0x60 comes from port 2 (mouse)

const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_DISABLE_PORT2: u8 = 0xA7;
const CMD_ENABLE_PORT2: u8 = 0xA8;
const CMD_TEST_PORT2: u8 = 0xA9;
const CMD_WRITE_PORT2: u8 = 0xD4; // the next data byte goes to the mouse
#[cfg(selftest)]
const CMD_WRITE_PORT2_OUTPUT: u8 = 0xD3; // "pretend a byte came from the mouse"
#[allow(dead_code)]
const CMD_SELF_TEST: u8 = 0xAA;
#[allow(dead_code)]
const CMD_TEST_PORT1: u8 = 0xAB;
const CMD_DISABLE_PORT1: u8 = 0xAD;
const CMD_ENABLE_PORT1: u8 = 0xAE;
#[cfg(selftest)]
const CMD_WRITE_PORT1_OUTPUT: u8 = 0xD2; // "pretend a byte came from the keyboard"

pub const CONFIG_PORT1_IRQ: u8 = 1 << 0;
pub const CONFIG_PORT2_IRQ: u8 = 1 << 1;
pub const CONFIG_PORT1_CLOCK_OFF: u8 = 1 << 4;
pub const CONFIG_PORT2_CLOCK_OFF: u8 = 1 << 5;
pub const CONFIG_TRANSLATION: u8 = 1 << 6;

// Keyboard commands (via the data port).
#[allow(dead_code)]
const KBD_RESET: u8 = 0xFF;
const KBD_ENABLE_SCANNING: u8 = 0xF4;
pub const KBD_SET_LEDS: u8 = 0xED;
pub const KBD_ACK: u8 = 0xFA;
pub const KBD_RESEND: u8 = 0xFE;
const KBD_SELF_TEST_OK: u8 = 0xAA;

// Mouse commands.
const MOUSE_RESET: u8 = 0xFF;
const MOUSE_SET_DEFAULTS: u8 = 0xF6;
const MOUSE_SET_SAMPLE_RATE: u8 = 0xF3;
const MOUSE_GET_ID: u8 = 0xF2;
const MOUSE_ENABLE_REPORTING: u8 = 0xF4;

/// Mouse ID after initialization: 0 = standard (3 bytes), 3 = IntelliMouse
/// (4 bytes, wheel), 4 = Explorer (4 bytes, wheel + buttons 4/5);
/// 0xFF = no mouse.
static MOUSE_ID: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0xFF);

pub fn mouse_id() -> Option<u8> {
    match MOUSE_ID.load(core::sync::atomic::Ordering::Relaxed) {
        0xFF => None,
        id => Some(id),
    }
}

fn status() -> u8 {
    unsafe { inb(STATUS) }
}

/// Waits until `ready()` returns true, at most about `timeout_ms`.
fn wait_until(timeout_ms: u64, ready: impl Fn() -> bool) -> bool {
    if interrupts::are_enabled() {
        let deadline = crate::time::ticks() + timeout_ms + 1;
        while crate::time::ticks() < deadline {
            if ready() {
                return true;
            }
            interrupts::enable_and_hlt();
        }
        ready()
    } else {
        // Without interrupts ticks are stopped – limit the number of attempts (~1 µs each).
        for _ in 0..timeout_ms * 1000 {
            if ready() {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }
}

fn wait_input_empty() -> bool {
    wait_until(20, || status() & STATUS_INPUT_FULL == 0)
}

fn wait_output_full(timeout_ms: u64) -> bool {
    wait_until(timeout_ms, || status() & STATUS_OUTPUT_FULL != 0)
}

pub fn write_command(cmd: u8) -> bool {
    if !wait_input_empty() {
        return false;
    }
    unsafe { outb(COMMAND, cmd) };
    true
}

/// Sends a byte to the device on port 1 (keyboard).
pub fn write_data(byte: u8) -> bool {
    if !wait_input_empty() {
        return false;
    }
    unsafe { outb(DATA, byte) };
    true
}

fn read_data(timeout_ms: u64) -> Option<u8> {
    if wait_output_full(timeout_ms) {
        Some(unsafe { inb(DATA) })
    } else {
        None
    }
}

/// Reads a byte from the IRQ handler: (byte, whether from port 2).  `None` when
/// the buffer is empty (interrupt without data).
pub fn read_irq_byte() -> Option<(u8, bool)> {
    let s = status();
    if s & STATUS_OUTPUT_FULL == 0 {
        return None;
    }
    let byte = unsafe { inb(DATA) };
    Some((byte, s & STATUS_AUX_DATA != 0))
}

/// Byte from the mouse (port 2); keyboard bytes arriving meanwhile are skipped.
fn read_aux(timeout_ms: u64) -> Option<u8> {
    let deadline_tries = timeout_ms.max(1);
    for _ in 0..deadline_tries {
        if !wait_output_full(1) {
            continue;
        }
        let st = status();
        let byte = unsafe { inb(DATA) };
        if st & STATUS_AUX_DATA != 0 {
            return Some(byte);
        }
    }
    None
}

/// Mouse command (via 0xD4) and wait for ACK.
fn mouse_command(byte: u8) -> bool {
    for _ in 0..3 {
        if !write_command(CMD_WRITE_PORT2) || !write_data(byte) {
            return false;
        }
        match read_aux(50) {
            Some(KBD_ACK) => return true,
            Some(KBD_RESEND) => continue,
            _ => return false,
        }
    }
    false
}

fn mouse_set_rate(rate: u8) -> bool {
    mouse_command(MOUSE_SET_SAMPLE_RATE) && mouse_command(rate)
}

fn mouse_get_id() -> Option<u8> {
    if !mouse_command(MOUSE_GET_ID) {
        return None;
    }
    read_aux(50)
}

/// Port 2: test, mouse reset, wheel mode, enable reporting.
/// Returns the mouse ID or None (no mouse / error – the system keeps going).
fn init_mouse() -> Option<u8> {
    write_command(CMD_TEST_PORT2);
    if read_data(100)? != 0x00 {
        return None;
    }
    write_command(CMD_ENABLE_PORT2);

    // Reset: ACK, 0xAA (self-test OK), 0x00 (ID).
    if !mouse_command(MOUSE_RESET) {
        return None;
    }
    if read_aux(750) != Some(KBD_SELF_TEST_OK) {
        return None;
    }
    let _ = read_aux(50); // ID 0x00
    mouse_command(MOUSE_SET_DEFAULTS);

    // IntelliMouse: 200, 100, 80 -> ID 3 (wheel).
    // Explorer: then 200, 200, 80 -> ID 4 (wheel + buttons 4/5).
    let mut id = 0;
    if mouse_set_rate(200) && mouse_set_rate(100) && mouse_set_rate(80) {
        id = mouse_get_id().unwrap_or(0);
        if id == 3 && mouse_set_rate(200) && mouse_set_rate(200) && mouse_set_rate(80) {
            id = mouse_get_id().unwrap_or(3);
        }
    }
    mouse_set_rate(100); // normal report rate
    if !mouse_command(MOUSE_ENABLE_REPORTING) {
        return None;
    }
    Some(id)
}

fn flush() {
    for _ in 0..32 {
        if status() & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        unsafe { inb(DATA) };
    }
}

fn read_config() -> Option<u8> {
    if !write_command(CMD_READ_CONFIG) {
        return None;
    }
    read_data(20)
}

fn write_config(config: u8) -> bool {
    write_command(CMD_WRITE_CONFIG) && write_data(config)
}

/// Current controller configuration (for tests / diagnostics).
/// With interrupts disabled: when IRQ1 is enabled, the controller's reply
/// also raises IRQ1 and the keyboard handler would take it from the buffer.
#[allow(dead_code)]
pub fn config() -> Option<u8> {
    interrupts::without_interrupts(read_config)
}

/// Sends a command to the keyboard and waits for ACK (retries on RESEND).
fn keyboard_command(byte: u8) -> bool {
    for _ in 0..3 {
        if !write_data(byte) {
            return false;
        }
        match read_data(50) {
            Some(KBD_ACK) => return true,
            Some(KBD_RESEND) => continue,
            _ => return false,
        }
    }
    false
}

pub enum Ps2Error {
    NoController,
    Timeout(&'static str),
}

impl core::fmt::Display for Ps2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Ps2Error::NoController => write!(f, "no i8042 controller (status port = 0xFF)"),
            Ps2Error::Timeout(what) => write!(f, "timeout: {}", what),
        }
    }
}

/// Initializes the controller and keyboard.  IRQ1 must be masked
/// in the PIC at that point; CPU interrupts may be enabled (better – we wait via hlt).
pub fn init() -> Result<(), Ps2Error> {
    // No controller (some newer machines without "legacy"): the port returns 0xFF.
    if status() == 0xFF {
        return Err(Ps2Error::NoController);
    }

    // 1. Disable both ports and flush the buffer (firmware may have left something).
    write_command(CMD_DISABLE_PORT1);
    write_command(CMD_DISABLE_PORT2);
    flush();

    // 2. Configuration: no IRQ during initialization, translation enabled.
    let mut config = read_config().ok_or(Ps2Error::Timeout("read config"))?;
    config &= !(CONFIG_PORT1_IRQ | CONFIG_PORT2_IRQ | CONFIG_PORT1_CLOCK_OFF);
    config |= CONFIG_TRANSLATION | CONFIG_PORT2_CLOCK_OFF;
    if !write_config(config) {
        return Err(Ps2Error::Timeout("write config"));
    }

    // 3–5. NO controller self-test (0xAA), port test (0xAB) or keyboard
    // reset (0xFF) – just like Linux on x86 (i8042.reset and atkbd.reset
    // are off by default).  On some laptops the
    // 8042 is emulated by the EC and after such a reset the keyboard stops
    // sending keys, even though it answers everything correctly.  Firmware
    // leaves the keyboard ready anyway; enabling the port and scanning is enough.
    write_command(CMD_ENABLE_PORT1);
    flush();
    if !keyboard_command(KBD_ENABLE_SCANNING) {
        serial_println!("[PS2] WARNING: keyboard did not ACK 'enable scanning'");
    }
    flush();

    // 5b. Mouse on port 2 (optional).
    match init_mouse() {
        Some(id) => {
            MOUSE_ID.store(id, core::sync::atomic::Ordering::Relaxed);
            config &= !CONFIG_PORT2_CLOCK_OFF;
            config |= CONFIG_PORT2_IRQ;
        }
        None => {
            write_command(CMD_DISABLE_PORT2);
            config |= CONFIG_PORT2_CLOCK_OFF;
            config &= !CONFIG_PORT2_IRQ;
        }
    }

    // 6. Enable IRQ1 (and IRQ12 if there is a mouse) in the controller.  Unmasking
    //    in the PIC is done by the keyboard and mouse drivers.
    flush();
    config |= CONFIG_PORT1_IRQ;
    if !write_config(config) {
        return Err(Ps2Error::Timeout("enable IRQ1"));
    }

    Ok(())
}

/// Resets the computer via the 8042 controller (pulse on the CPU RESET line).
/// Returns only if it did not work.
pub fn reset_cpu() {
    write_command(0xFE);
    for _ in 0..1_000_000 {
        core::hint::spin_loop();
    }
}

/// Test: the controller inserts `byte` into the buffer as if it came from the
/// keyboard (command 0xD2) – raises IRQ1.  The byte does NOT go through
/// translation, so we pass set 1 codes directly.
#[cfg(selftest)]
pub fn inject_keyboard_byte(byte: u8) -> bool {
    write_command(CMD_WRITE_PORT1_OUTPUT) && write_data(byte)
}

/// Test: a byte as if it came from the mouse (command 0xD3) – raises IRQ12.
#[cfg(selftest)]
pub fn inject_mouse_byte(byte: u8) -> bool {
    write_command(CMD_WRITE_PORT2_OUTPUT) && write_data(byte)
}
