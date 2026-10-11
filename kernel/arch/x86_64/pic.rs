// M5: kontroler przerwań 8259A (para master/slave, "legacy PIC").
//
// Po resecie PIC wysyła IRQ0..7 na wektory 0x08..0x0F, czyli w miejsce
// wyjątków CPU (#DF = 8!).  Dlatego pierwszym krokiem jest remap:
//
//   master: IRQ0..7  -> wektory 0x20..0x27
//   slave:  IRQ8..15 -> wektory 0x28..0x2F  (podpięty pod IRQ2 mastera)
//
// Po inicjalizacji wszystkie linie są zamaskowane; sterowniki odblokowują
// własne IRQ przez `unmask()`.  Linia kaskady (IRQ2) jest odmaskowywana
// automatycznie, gdy odblokowujemy cokolwiek na slave.
//
// Później (APIC) ten PIC zostanie po prostu w całości zamaskowany – patrz
// `disable()`.

use core::sync::atomic::{AtomicU64, Ordering};

use super::interrupts::without_interrupts;
use super::port::{inb, io_wait, outb};

const MASTER_CMD: u16 = 0x20;
const MASTER_DATA: u16 = 0x21;
const SLAVE_CMD: u16 = 0xA0;
const SLAVE_DATA: u16 = 0xA1;

pub const MASTER_OFFSET: u8 = 0x20;
pub const SLAVE_OFFSET: u8 = 0x28;
pub const IRQ_COUNT: usize = 16;

/// IRQ, pod którym slave jest podpięty do mastera.
pub const CASCADE_IRQ: u8 = 2;

const ICW1_ICW4: u8 = 0x01; // będzie ICW4
const ICW1_INIT: u8 = 0x10; // start sekwencji inicjalizacji
const ICW4_8086: u8 = 0x01; // tryb 8086/88

const CMD_EOI: u8 = 0x20; // non-specific EOI
const OCW3_READ_IRR: u8 = 0x0A;
const OCW3_READ_ISR: u8 = 0x0B;

static SPURIOUS_MASTER: AtomicU64 = AtomicU64::new(0);
static SPURIOUS_SLAVE: AtomicU64 = AtomicU64::new(0);

/// Remapuje oba PIC-e na 0x20/0x28 i maskuje wszystkie linie.
pub fn init() {
    without_interrupts(|| unsafe {
        // ICW1: start inicjalizacji (kaskada, zbocze, będzie ICW4).
        outb(MASTER_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();
        outb(SLAVE_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();

        // ICW2: bazowe wektory.
        outb(MASTER_DATA, MASTER_OFFSET);
        io_wait();
        outb(SLAVE_DATA, SLAVE_OFFSET);
        io_wait();

        // ICW3: master – slave na linii 2 (maska bitowa); slave – jego numer.
        outb(MASTER_DATA, 1 << CASCADE_IRQ);
        io_wait();
        outb(SLAVE_DATA, CASCADE_IRQ);
        io_wait();

        // ICW4: tryb 8086, zwykłe (nie automatyczne) EOI.
        outb(MASTER_DATA, ICW4_8086);
        io_wait();
        outb(SLAVE_DATA, ICW4_8086);
        io_wait();

        // OCW1: wszystko zamaskowane.
        outb(MASTER_DATA, 0xFF);
        outb(SLAVE_DATA, 0xFF);
    });
}

/// Maskuje wszystkie linie obu PIC-ów (np. przed przejściem na APIC).
#[allow(dead_code)]
pub fn disable() {
    without_interrupts(|| unsafe {
        outb(MASTER_DATA, 0xFF);
        outb(SLAVE_DATA, 0xFF);
    });
}

fn data_port(irq: u8) -> (u16, u8) {
    if irq < 8 { (MASTER_DATA, irq) } else { (SLAVE_DATA, irq - 8) }
}

/// Odblokowuje linię IRQ (0..15).
pub fn unmask(irq: u8) {
    assert!((irq as usize) < IRQ_COUNT, "pic: bad irq {}", irq);
    without_interrupts(|| unsafe {
        let (port, bit) = data_port(irq);
        outb(port, inb(port) & !(1 << bit));
        if irq >= 8 {
            outb(MASTER_DATA, inb(MASTER_DATA) & !(1 << CASCADE_IRQ));
        }
    });
}

/// Blokuje linię IRQ (0..15).  Przerwanie zgłoszone w tym czasie czeka
/// w IRR i zostanie dostarczone po `unmask()`.
pub fn mask(irq: u8) {
    assert!((irq as usize) < IRQ_COUNT, "pic: bad irq {}", irq);
    without_interrupts(|| unsafe {
        let (port, bit) = data_port(irq);
        outb(port, inb(port) | (1 << bit));
    });
}

/// Maski (IMR) obu PIC-ów jako 16 bitów: bit n = IRQ n zamaskowane.
pub fn masks() -> u16 {
    unsafe { (inb(MASTER_DATA) as u16) | ((inb(SLAVE_DATA) as u16) << 8) }
}

fn read_register(ocw3: u8) -> u16 {
    unsafe {
        outb(MASTER_CMD, ocw3);
        outb(SLAVE_CMD, ocw3);
        (inb(MASTER_CMD) as u16) | ((inb(SLAVE_CMD) as u16) << 8)
    }
}

/// In-Service Register: które IRQ są właśnie obsługiwane (czekają na EOI).
pub fn in_service() -> u16 {
    read_register(OCW3_READ_ISR)
}

/// Interrupt Request Register: które IRQ są zgłoszone i czekają.
#[allow(dead_code)]
pub fn requested() -> u16 {
    read_register(OCW3_READ_IRR)
}

/// Sprawdza, czy IRQ7 / IRQ15 jest fałszywe (spurious).  PIC zgłasza je,
/// gdy linia opadła zanim CPU potwierdził przerwanie – wtedy bit w ISR NIE
/// jest ustawiony i nie wolno wysłać EOI do tego PIC-a.  Dla fałszywego
/// IRQ15 master jednak widział prawdziwe IRQ2, więc dostaje swoje EOI.
///
/// Zwraca `true` = przerwanie fałszywe, handler ma je zignorować.
pub fn is_spurious(irq: u8) -> bool {
    match irq {
        7 => {
            if in_service() & (1 << 7) == 0 {
                SPURIOUS_MASTER.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            false
        }
        15 => {
            if in_service() & (1 << 15) == 0 {
                SPURIOUS_SLAVE.fetch_add(1, Ordering::Relaxed);
                unsafe {
                    outb(MASTER_CMD, CMD_EOI);
                }
                return true;
            }
            false
        }
        _ => false,
    }
}

/// End Of Interrupt – bez tego PIC nie dostarczy kolejnego IRQ o tym samym
/// lub niższym priorytecie.  IRQ ze slave wymaga EOI do obu układów.
pub fn send_eoi(irq: u8) {
    unsafe {
        if irq >= 8 {
            outb(SLAVE_CMD, CMD_EOI);
        }
        outb(MASTER_CMD, CMD_EOI);
    }
}

#[allow(dead_code)]
pub fn spurious_count() -> (u64, u64) {
    (
        SPURIOUS_MASTER.load(Ordering::Relaxed),
        SPURIOUS_SLAVE.load(Ordering::Relaxed),
    )
}
