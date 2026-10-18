// Serial COM1 (16550): 38400 baud, 8N1.
//
// Output: busy-waiting for a free transmit buffer (works from the first
// kernel instruction, without interrupts).
// Input: IRQ4 "data received" -> 256-byte buffer -> console.

use core::arch::asm;
use core::fmt::Write;

const COM1: u16 = 0x3F8;
const IRQ: u8 = 4;

const REG_DATA: u16 = 0;
const REG_IER: u16 = 1;
const REG_LSR: u16 = 5;

const IER_RX_AVAILABLE: u8 = 1 << 0;
const LSR_DATA_READY: u8 = 1 << 0;
const LSR_TX_EMPTY: u8 = 1 << 5;

/// Whether there is a UART at COM1.  Many laptops have no
/// serial port – the ports then read 0xFF and LSR "always has data",
/// so without this flag the receive-drain loop would spin forever.
static PRESENT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn present() -> bool {
    PRESENT.load(core::sync::atomic::Ordering::Relaxed)
}

pub fn init() {
    // Scratch register (COM1+7): a UART remembers the written byte, an empty
    // bus returns 0xFF.
    let present = unsafe {
        outb(COM1 + 7, 0x5A);
        let a = inb(COM1 + 7);
        outb(COM1 + 7, 0xA5);
        let b = inb(COM1 + 7);
        a == 0x5A && b == 0xA5 && inb(COM1 + REG_LSR) != 0xFF
    };
    PRESENT.store(present, core::sync::atomic::Ordering::Relaxed);
    if !present {
        return;
    }
    unsafe {
        outb(COM1 + 1, 0x00); // no interrupts
        outb(COM1 + 3, 0x80); // DLAB
        outb(COM1 + 0, 0x03); // divisor 3 -> 38400 baud
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x03); // 8N1
        outb(COM1 + 2, 0x07); // FIFO on, cleared, receive threshold 1 byte
        outb(COM1 + 4, 0x0B); // DTR, RTS, OUT2 (OUT2 = IRQ line to the PIC)
    }
}

unsafe fn outb(port: u16, val: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags)
        );
    }
}

unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    unsafe {
        asm!(
            "in al, dx",
            out("al") v,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
    }
    v
}

// How many times to check LSR before deciding nobody is receiving (~100 ms;
// one byte at 38400 baud takes about 260 µs).  Without a limit the kernel would stall
// when the terminal on the other side stops reading.
const TX_SPIN_LIMIT: u32 = 100_000;

// After exceeding the limit we no longer wait for every byte: until the UART
// frees up, bytes are dropped immediately (the screen runs at full speed).
static TX_STALLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn write_byte(b: u8) {
    use core::sync::atomic::Ordering;
    if !present() {
        return;
    }
    unsafe {
        if TX_STALLED.load(Ordering::Relaxed) {
            if inb(COM1 + REG_LSR) & LSR_TX_EMPTY != 0 {
                TX_STALLED.store(false, Ordering::Relaxed);
                outb(COM1 + REG_DATA, b);
            }
            return;
        }
        for _ in 0..TX_SPIN_LIMIT {
            if inb(COM1 + REG_LSR) & LSR_TX_EMPTY != 0 {
                outb(COM1 + REG_DATA, b);
                return;
            }
        }
        TX_STALLED.store(true, Ordering::Relaxed);
    }
}

/// Writes text to serial (\n -> \r\n).
pub fn write_str(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            write_byte(b'\r');
        }
        write_byte(b);
    }
}

struct Serial;

impl Write for Serial {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        write_str(s);
        Ok(())
    }
}

/// Serial only (no screen).
#[allow(dead_code)]
pub fn print_fmt(args: core::fmt::Arguments<'_>) {
    let _ = Serial.write_fmt(args);
}

/// Kernel log: serial + the on-screen console.
#[macro_export]
macro_rules! serial_println {
    () => {
        $crate::console::print_fmt(format_args!("\n"));
    };
    ($($arg:tt)*) => {{
        $crate::console::print_line(format_args!($($arg)*));
    }};
}

// ------------------------------------------------------------
// Receive
// ------------------------------------------------------------

const RX_SIZE: usize = 256;

struct Rx {
    buf: [u8; RX_SIZE],
    head: usize,
    len: usize,
    dropped: u64,
}

static mut RX: Rx = Rx { buf: [0; RX_SIZE], head: 0, len: 0, dropped: 0 };

fn with_rx<R>(f: impl FnOnce(&mut Rx) -> R) -> R {
    crate::arch::x86_64::interrupts::without_interrupts(|| unsafe { f(&mut *core::ptr::addr_of_mut!(RX)) })
}

/// Discards unread bytes (Ctrl+C on a foreground process).
pub fn discard_input() {
    with_rx(|rx| {
        rx.head = 0;
        rx.len = 0;
    });
}

fn on_irq(_irq: u8) {
    // Take everything that is in the FIFO.
    for _ in 0..16 {
        let lsr = unsafe { inb(COM1 + REG_LSR) };
        if lsr == 0xFF || lsr & LSR_DATA_READY == 0 {
            break;
        }
        let b = unsafe { inb(COM1 + REG_DATA) };
        // Ctrl+C from the terminal for a foreground process.
        if b == 0x03 && crate::console::interrupt_foreground() {
            discard_input();
            crate::input::discard_events();
            continue;
        }
        with_rx(|rx| {
            if rx.len == RX_SIZE {
                rx.dropped += 1;
            } else {
                let tail = (rx.head + rx.len) % RX_SIZE;
                rx.buf[tail] = b;
                rx.len += 1;
            }
        });
    }
    crate::console::wake_input();
}

/// Enables interrupt-driven receive (IRQ4).  Requires the PIC + irq setup.
pub fn enable_rx_interrupts() -> bool {
    use crate::arch::x86_64::irq;
    if !present() || !irq::register(IRQ, on_irq) {
        return false;
    }
    unsafe {
        // Discard any stale bytes (the FIFO holds 16 – a limit just in case).
        for _ in 0..64 {
            if inb(COM1 + REG_LSR) & LSR_DATA_READY == 0 {
                break;
            }
            inb(COM1 + REG_DATA);
        }
        outb(COM1 + REG_IER, IER_RX_AVAILABLE);
    }
    irq::unmask(IRQ);
    true
}

/// Next received byte (without waiting).
pub fn read_byte() -> Option<u8> {
    with_rx(|rx| {
        if rx.len == 0 {
            return None;
        }
        let b = rx.buf[rx.head];
        rx.head = (rx.head + 1) % RX_SIZE;
        rx.len -= 1;
        Some(b)
    })
}

pub fn has_input() -> bool {
    with_rx(|rx| rx.len > 0)
}

/// How many bytes were dropped because the buffer was full.
#[allow(dead_code)]
pub fn rx_dropped() -> u64 {
    with_rx(|rx| rx.dropped)
}

/// Whether interrupt-driven receive is enabled (IER) – for tests.
#[allow(dead_code)]
pub fn rx_interrupts_enabled() -> bool {
    unsafe { inb(COM1 + REG_IER) & IER_RX_AVAILABLE != 0 }
}

/// Test: UART loopback (MCR.LOOP) – sent bytes come back to the receiver.
#[cfg(selftest)]
pub fn loopback(enable: bool) {
    unsafe {
        // LOOP (bit 4) + OUT2 + RTS + DTR
        outb(COM1 + 4, if enable { 0x1B } else { 0x0B });
    }
}

#[cfg(selftest)]
pub fn send_raw(b: u8) {
    write_byte(b);
}
