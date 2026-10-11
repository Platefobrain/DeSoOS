// Serial COM1 (16550): 38400 baud, 8N1.
//
// Wyjście: aktywne czekanie na wolny bufor nadawczy (działa od pierwszej
// instrukcji kernela, bez przerwań).
// Wejście (M7): IRQ4 "odebrano dane" -> bufor 256 bajtów -> konsola.

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

/// M16b: czy jest UART pod COM1.  Laptopy (np. Lenovo Legion) nie mają
/// portu szeregowego – porty czytają wtedy 0xFF, a LSR "zawsze ma dane",
/// więc bez tej flagi pętla opróżniania odbioru kręciłaby się w nieskończoność.
static PRESENT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn present() -> bool {
    PRESENT.load(core::sync::atomic::Ordering::Relaxed)
}

pub fn init() {
    // Rejestr scratch (COM1+7): UART zapamiętuje zapisany bajt, pusta
    // szyna zwraca 0xFF.
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
        outb(COM1 + 1, 0x00); // bez przerwań
        outb(COM1 + 3, 0x80); // DLAB
        outb(COM1 + 0, 0x03); // dzielnik 3 -> 38400 baud
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x03); // 8N1
        outb(COM1 + 2, 0x07); // FIFO wł., wyczyszczone, próg odbioru 1 bajt
        outb(COM1 + 4, 0x0B); // DTR, RTS, OUT2 (OUT2 = linia IRQ do PIC-a)
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

// Ile razy sprawdzić LSR, zanim uznamy, że nikt nie odbiera (~100 ms;
// jeden bajt przy 38400 baud to ok. 260 µs).  Bez limitu kernel stanąłby,
// gdy terminal po drugiej stronie przestaje czytać.
const TX_SPIN_LIMIT: u32 = 100_000;

// Po przekroczeniu limitu nie czekamy już na każdy bajt: dopóki UART się
// nie zwolni, bajty przepadają od razu (ekran działa z pełną szybkością).
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

/// Wypisuje tekst na serial (\n -> \r\n).
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

/// Tylko serial (bez ekranu).
#[allow(dead_code)]
pub fn print_fmt(args: core::fmt::Arguments<'_>) {
    let _ = Serial.write_fmt(args);
}

/// Log kernela: serial + (od M7) konsola na ekranie.
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
// Odbiór (M7)
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

/// M14: wyrzuca nieodczytane bajty (Ctrl+C przy procesie na pierwszym planie).
pub fn discard_input() {
    with_rx(|rx| {
        rx.head = 0;
        rx.len = 0;
    });
}

fn on_irq(_irq: u8) {
    // Zabieramy wszystko, co jest w FIFO.
    for _ in 0..16 {
        let lsr = unsafe { inb(COM1 + REG_LSR) };
        if lsr == 0xFF || lsr & LSR_DATA_READY == 0 {
            break;
        }
        let b = unsafe { inb(COM1 + REG_DATA) };
        // M14: Ctrl+C z terminala przy procesie na pierwszym planie.
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

/// Włącza odbiór na przerwaniach (IRQ4).  Wymaga M5 (PIC + irq).
pub fn enable_rx_interrupts() -> bool {
    use crate::arch::x86_64::irq;
    if !present() || !irq::register(IRQ, on_irq) {
        return false;
    }
    unsafe {
        // Wyrzuć ewentualne stare bajty (FIFO ma 16 – limit na wszelki wypadek).
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

/// Następny odebrany bajt (bez czekania).
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

/// Ile bajtów odrzucono przy pełnym buforze.
#[allow(dead_code)]
pub fn rx_dropped() -> u64 {
    with_rx(|rx| rx.dropped)
}

/// Czy odbiór na przerwaniach jest włączony (IER) – do testów.
#[allow(dead_code)]
pub fn rx_interrupts_enabled() -> bool {
    unsafe { inb(COM1 + REG_IER) & IER_RX_AVAILABLE != 0 }
}

/// Test: pętla zwrotna UART (MCR.LOOP) – wysłane bajty wracają do odbiornika.
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
