// M5: Programmable Interval Timer 8253/8254.
//
// Zegar wejściowy 1.193182 MHz.  Kanał 0 w trybie 2 (rate generator)
// zgłasza IRQ0 co `divisor` taktów.  Kanał 1 nieużywany, kanał 2 = głośnik.

use super::interrupts::without_interrupts;
use super::port::{inb, outb};

pub const BASE_FREQUENCY: u32 = 1_193_182;

const CHANNEL0: u16 = 0x40;
const COMMAND: u16 = 0x43;

// Command byte: kanał 0 | dostęp lobyte/hibyte | tryb 2 | binarnie.
const CMD_CH0_LOHI_MODE2: u8 = 0b00_11_010_0;
// Latch licznika kanału 0.
#[allow(dead_code)]
const CMD_CH0_LATCH: u8 = 0b00_00_000_0;

static mut DIVISOR: u16 = 0;

/// Ustawia kanał 0 na `hz` przerwań na sekundę (19..=1_193_182).
/// Zwraca rzeczywistą częstotliwość (dzielnik jest całkowity).
pub fn init(hz: u32) -> u32 {
    let hz = hz.clamp(19, BASE_FREQUENCY);
    // Zaokrąglenie do najbliższego dzielnika; 0 oznaczałoby 65536.
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

/// Rzeczywista częstotliwość w mHz (np. 1000150 dla 1000.15 Hz).
pub fn actual_frequency_millihz() -> u64 {
    let d = divisor() as u64;
    if d == 0 { 0 } else { BASE_FREQUENCY as u64 * 1000 / d }
}

/// Bieżąca wartość licznika kanału 0 (odlicza od `divisor` w dół do 1,
/// potem przeładowuje się).
#[allow(dead_code)]
pub fn read_counter() -> u16 {
    without_interrupts(|| unsafe {
        outb(COMMAND, CMD_CH0_LATCH);
        let lo = inb(CHANNEL0) as u16;
        let hi = inb(CHANNEL0) as u16;
        (hi << 8) | lo
    })
}
