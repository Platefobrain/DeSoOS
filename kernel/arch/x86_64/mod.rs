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

/// Ładuje GDT + TSS oraz IDT (wyjątki 0..31 + bramki IRQ 0x20..0x2F).
/// Wołać jak najwcześniej (zaraz po serialu), żeby każdy późniejszy błąd
/// kończył się czytelnym raportem zamiast cichego triple faulta.
/// Przerwania sprzętowe pozostają wyłączone do M5 (`irq::init` + `sti`).
pub fn init() {
    gdt::init();
    idt::init();
}

#[cfg(selftest)]
pub use exceptions::self_test;
