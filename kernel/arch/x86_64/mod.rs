pub mod clock;
pub mod cpu;
pub mod exceptions;
pub mod fpu;
pub mod gdt;
pub mod idt;
pub mod interrupts;
pub mod ioapic;
pub mod irq;
pub mod lapic;
pub mod msi;
pub mod pic;
pub mod pit;
pub mod smp;
pub mod syscall;
pub mod tlb;
pub mod port;
pub mod percpu;

/// Loads the GDT + TSS and the IDT (exceptions 0..31 + IRQ gates 0x20..0x2F).
/// Call as early as possible (right after the serial port) so that any later fault
/// ends with a readable report instead of a silent triple fault.
/// Hardware interrupts stay disabled until `irq::init` + `sti`.
pub fn init() {
    gdt::init();
    idt::init();
}

#[cfg(selftest)]
pub use exceptions::self_test;
