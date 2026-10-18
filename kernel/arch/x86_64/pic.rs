// 8259A interrupt controller (master/slave pair, "legacy PIC").
//
// After reset the PIC delivers IRQ0..7 on vectors 0x08..0x0F, i.e. on top of the
// CPU exceptions (#DF = 8!).  That is why the first step is a remap:
//
//   master: IRQ0..7  -> vectors 0x20..0x27
//   slave:  IRQ8..15 -> vectors 0x28..0x2F  (attached to the master's IRQ2)
//
// After initialization all lines are masked; drivers unmask
// their own IRQs via `unmask()`.  The cascade line (IRQ2) is unmasked
// automatically when anything on the slave is unmasked.
//
// With the APIC this PIC is simply masked entirely – see
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

/// IRQ on which the slave is attached to the master.
pub const CASCADE_IRQ: u8 = 2;

const ICW1_ICW4: u8 = 0x01; // ICW4 will follow
const ICW1_INIT: u8 = 0x10; // start of the initialization sequence
const ICW4_8086: u8 = 0x01; // 8086/88 mode

const CMD_EOI: u8 = 0x20; // non-specific EOI
const OCW3_READ_IRR: u8 = 0x0A;
const OCW3_READ_ISR: u8 = 0x0B;

static SPURIOUS_MASTER: AtomicU64 = AtomicU64::new(0);
static SPURIOUS_SLAVE: AtomicU64 = AtomicU64::new(0);

/// Remaps both PICs to 0x20/0x28 and masks all lines.
pub fn init() {
    without_interrupts(|| unsafe {
        // ICW1: start initialization (cascade, edge, ICW4 will follow).
        outb(MASTER_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();
        outb(SLAVE_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();

        // ICW2: base vectors.
        outb(MASTER_DATA, MASTER_OFFSET);
        io_wait();
        outb(SLAVE_DATA, SLAVE_OFFSET);
        io_wait();

        // ICW3: master – slave on line 2 (bit mask); slave – its number.
        outb(MASTER_DATA, 1 << CASCADE_IRQ);
        io_wait();
        outb(SLAVE_DATA, CASCADE_IRQ);
        io_wait();

        // ICW4: 8086 mode, normal (not automatic) EOI.
        outb(MASTER_DATA, ICW4_8086);
        io_wait();
        outb(SLAVE_DATA, ICW4_8086);
        io_wait();

        // OCW1: everything masked.
        outb(MASTER_DATA, 0xFF);
        outb(SLAVE_DATA, 0xFF);
    });
}

/// Masks all lines of both PICs (e.g. before switching to the APIC).
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

/// Unmasks an IRQ line (0..15).
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

/// Masks an IRQ line (0..15).  An interrupt raised meanwhile waits
/// in the IRR and will be delivered after `unmask()`.
pub fn mask(irq: u8) {
    assert!((irq as usize) < IRQ_COUNT, "pic: bad irq {}", irq);
    without_interrupts(|| unsafe {
        let (port, bit) = data_port(irq);
        outb(port, inb(port) | (1 << bit));
    });
}

/// Masks (IMR) of both PICs as 16 bits: bit n = IRQ n masked.
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

/// In-Service Register: which IRQs are currently being serviced (waiting for EOI).
pub fn in_service() -> u16 {
    read_register(OCW3_READ_ISR)
}

/// Interrupt Request Register: which IRQs are raised and pending.
#[allow(dead_code)]
pub fn requested() -> u16 {
    read_register(OCW3_READ_IRR)
}

/// Checks whether IRQ7 / IRQ15 is spurious.  The PIC raises them
/// when the line dropped before the CPU acknowledged the interrupt – then the ISR bit is NOT
/// set and no EOI may be sent to that PIC.  For a spurious
/// IRQ15 the master did see a real IRQ2, though, so it gets its EOI.
///
/// Returns `true` = spurious interrupt, the handler should ignore it.
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

/// End Of Interrupt – without it the PIC will not deliver another IRQ of the same
/// or lower priority.  An IRQ from the slave requires EOI to both chips.
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
