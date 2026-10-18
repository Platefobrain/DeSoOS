// Programmable Interval Timer 8253/8254.
//
// Input clock 1.193182 MHz.  Channel 0 in mode 2 (rate generator)
// raises IRQ0 every `divisor` ticks.  Channel 1 unused, channel 2 = speaker.

use super::interrupts::without_interrupts;
use super::port::{inb, outb};

pub const BASE_FREQUENCY: u32 = 1_193_182;

const CHANNEL0: u16 = 0x40;
const COMMAND: u16 = 0x43;

// Command byte: channel 0 | lobyte/hibyte access | mode 2 | binary.
const CMD_CH0_LOHI_MODE2: u8 = 0b00_11_010_0;
// Latch channel 0's counter.
#[allow(dead_code)]
const CMD_CH0_LATCH: u8 = 0b00_00_000_0;

static mut DIVISOR: u16 = 0;

/// Sets channel 0 to `hz` interrupts per second (19..=1_193_182).
/// Returns the actual frequency (the divisor is an integer).
pub fn init(hz: u32) -> u32 {
    let hz = hz.clamp(19, BASE_FREQUENCY);
    // Round to the nearest divisor; 0 would mean 65536.
    let divisor = ((BASE_FREQUENCY + hz / 2) / hz).clamp(1, 65535) as u16;

    without_interrupts(|| unsafe {
        outb(COMMAND, CMD_CH0_LOHI_MODE2);
        outb(CHANNEL0, divisor as u8);
        outb(CHANNEL0, (divisor >> 8) as u8);
        DIVISOR = divisor;
    });

    actual_frequency_millihz() as u32 / 1000
}

pub fn divisor() -> u16 {
    unsafe { DIVISOR }
}

/// Actual frequency in mHz (e.g. 1000150 for 1000.15 Hz).
pub fn actual_frequency_millihz() -> u64 {
    let d = divisor() as u64;
    if d == 0 { 0 } else { BASE_FREQUENCY as u64 * 1000 / d }
}

/// Current value of channel 0's counter (counts down from `divisor` to 1,
/// then reloads).
#[allow(dead_code)]
pub fn read_counter() -> u16 {
    without_interrupts(|| unsafe {
        outb(COMMAND, CMD_CH0_LATCH);
        let lo = inb(CHANNEL0) as u16;
        let hi = inb(CHANNEL0) as u16;
        (hi << 8) | lo
    })
}
