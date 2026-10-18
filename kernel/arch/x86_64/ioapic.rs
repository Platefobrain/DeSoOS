// I/O APIC – interrupts of ISA devices (timer, keyboard, serial,
// mouse) instead of the old 8259 PIC.
//
// Every I/O APIC input (GSI) has an entry in the redirection table: vector,
// target Local APIC, polarity, trigger mode, mask.  ISA lines (IRQ 0..15)
// are connected to GSI 0..15, except for the exceptions described in the MADT ("interrupt
// source override", e.g. timer IRQ0 -> GSI 2).  The vector stays the same as
// with the PIC (0x20 + IRQ), so the handlers in irq.rs do not change; only
// masking (here) and EOI (Local APIC instead of PIC) change.
//
// PCI INTx lines are not connected here: their GSIs are described by ACPI in AML (_PRT).
// PCI devices use MSI/MSI-X (virtio, NVMe).

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use crate::serial_println;

const REG_ID: u32 = 0x00;
const REG_VERSION: u32 = 0x01;
const REG_REDIRECT: u32 = 0x10;

const MASKED: u32 = 1 << 16;
const LEVEL: u32 = 1 << 15;
const ACTIVE_LOW: u32 = 1 << 13;

static BASE: AtomicU64 = AtomicU64::new(0); // virtual address
static GSI_BASE: AtomicU64 = AtomicU64::new(0);
static ENTRIES: AtomicU8 = AtomicU8::new(0);
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// GSI and flags of ISA lines 0..15 (after applying the MADT overrides).
static ISA_GSI: [AtomicU8; 16] = [const { AtomicU8::new(0) }; 16];
static ISA_FLAGS: [AtomicU8; 16] = [const { AtomicU8::new(0) }; 16];

fn read(reg: u32) -> u32 {
    crate::arch::x86_64::interrupts::without_interrupts(|| unsafe {
        let b = BASE.load(Ordering::Relaxed);
        core::ptr::write_volatile(b as *mut u32, reg);
        core::ptr::read_volatile((b + 0x10) as *const u32)
    })
}

fn write(reg: u32, value: u32) {
    crate::arch::x86_64::interrupts::without_interrupts(|| unsafe {
        let b = BASE.load(Ordering::Relaxed);
        core::ptr::write_volatile(b as *mut u32, reg);
        core::ptr::write_volatile((b + 0x10) as *mut u32, value);
    })
}

pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Switches ISA interrupts to the I/O APIC (the PIC stays fully masked).
/// `false` if there is no MADT / I/O APIC / Local APIC – the PIC remains.
pub fn init() -> bool {
    if !super::lapic::available() {
        return false;
    }
    let Some(madt) = crate::acpi::madt() else {
        serial_println!("[IOAPIC] no MADT - staying with the 8259 PIC");
        return false;
    };
    // The first I/O APIC that handles GSI 0 (it has the ISA lines).
    let Some(io) = madt.ioapics.iter().find(|i| i.gsi_base == 0).copied() else {
        serial_println!("[IOAPIC] no I/O APIC for GSI 0 - staying with the 8259 PIC");
        return false;
    };
    let Some(base) = crate::memory::map_mmio(io.address, 0x20) else {
        serial_println!("[IOAPIC] cannot map I/O APIC at {:#x}", io.address);
        return false;
    };
    BASE.store(base, Ordering::SeqCst);
    GSI_BASE.store(io.gsi_base as u64, Ordering::SeqCst);
    let entries = ((read(REG_VERSION) >> 16) & 0xFF) as u8 + 1;
    ENTRIES.store(entries, Ordering::SeqCst);

    // All inputs masked.
    for i in 0..entries as u32 {
        write(REG_REDIRECT + 2 * i, MASKED);
        write(REG_REDIRECT + 2 * i + 1, 0);
    }
    // ISA lines: by default GSI = IRQ, edge, active high; then the overrides.
    for irq in 0..16u8 {
        ISA_GSI[irq as usize].store(irq, Ordering::SeqCst);
        ISA_FLAGS[irq as usize].store(0, Ordering::SeqCst);
    }
    for ov in &madt.overrides {
        if (ov.source as usize) < 16 && ov.gsi < entries as u32 {
            ISA_GSI[ov.source as usize].store(ov.gsi as u8, Ordering::SeqCst);
            ISA_FLAGS[ov.source as usize].store(ov.flags as u8, Ordering::SeqCst);
        }
    }
    // PIC: everything masked forever (the 8259 no longer delivers interrupts).
    super::pic::disable();
    ACTIVE.store(true, Ordering::SeqCst);
    serial_println!(
        "[IOAPIC] I/O APIC id {} at {:#x} ({} inputs), ISA IRQ0 -> GSI {}; 8259 PIC disabled",
        (read(REG_ID) >> 24) & 0xF,
        io.address,
        entries,
        ISA_GSI[0].load(Ordering::Relaxed)
    );
    true
}

/// Redirection entry for ISA line `irq` (vector 0x20 + irq, to the BSP).
fn entry_for(irq: u8, masked: bool) -> (u32, u32, u32) {
    let gsi = ISA_GSI[irq as usize].load(Ordering::Relaxed) as u32;
    let flags = ISA_FLAGS[irq as usize].load(Ordering::Relaxed);
    let mut low = (super::idt::IRQ_BASE as u32 + irq as u32) & 0xFF;
    if flags & 0b11 == 0b11 {
        low |= ACTIVE_LOW;
    }
    if (flags >> 2) & 0b11 == 0b11 {
        low |= LEVEL;
    }
    if masked {
        low |= MASKED;
    }
    let dest = (super::lapic::bsp_id() & 0xFF) as u32;
    (gsi, low, dest << 24)
}

pub fn unmask(irq: u8) {
    if irq >= 16 {
        return;
    }
    let (gsi, low, high) = entry_for(irq, false);
    write(REG_REDIRECT + 2 * gsi + 1, high);
    write(REG_REDIRECT + 2 * gsi, low);
}

pub fn mask(irq: u8) {
    if irq >= 16 {
        return;
    }
    let (gsi, low, high) = entry_for(irq, true);
    write(REG_REDIRECT + 2 * gsi + 1, high);
    write(REG_REDIRECT + 2 * gsi, low);
}

pub fn is_masked(irq: u8) -> bool {
    if irq >= 16 {
        return true;
    }
    let gsi = ISA_GSI[irq as usize].load(Ordering::Relaxed) as u32;
    read(REG_REDIRECT + 2 * gsi) & MASKED != 0
}

/// GSI of an ISA line (tests, diagnostics).
#[allow(dead_code)]
pub fn isa_gsi(irq: u8) -> u8 {
    ISA_GSI[irq as usize & 15].load(Ordering::Relaxed)
}
