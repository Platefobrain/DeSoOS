// M16b: wektory przerwań MSI/MSI-X (0x30..0x3F).
//
// Sterownik prosi o wektor (`alloc`), wpisuje go do capability MSI/MSI-X
// urządzenia (drivers/pci.rs) razem z adresem LAPIC.  Przerwanie przychodzi
// prosto do LAPIC, więc EOI idzie do LAPIC (nie do PIC-a).  Dalej jak przy
// IRQ: wywłaszczenie i kill procesu w ring 3 (irq::after_interrupt).

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::exceptions::ExceptionFrame;

pub const MSI_BASE: usize = 0x30;
pub const MSI_VECTORS: usize = 16;

pub type MsiHandler = fn(vector: u8);

static HANDLERS: [AtomicUsize; MSI_VECTORS] = [const { AtomicUsize::new(0) }; MSI_VECTORS];
static COUNTS: [AtomicU64; MSI_VECTORS] = [const { AtomicU64::new(0) }; MSI_VECTORS];

/// Wolny wektor z handlerem; None, gdy nie ma LAPIC albo wektorów.
pub fn alloc(handler: MsiHandler) -> Option<u8> {
    if !super::lapic::available() {
        return None;
    }
    for (i, slot) in HANDLERS.iter().enumerate() {
        if slot.compare_exchange(0, handler as usize, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            return Some((MSI_BASE + i) as u8);
        }
    }
    None
}

/// Ile przerwań przyszło na wektorze (testy, diagnostyka).
#[allow(dead_code)]
pub fn count(vector: u8) -> u64 {
    let i = (vector as usize).wrapping_sub(MSI_BASE);
    if i < MSI_VECTORS { COUNTS[i].load(Ordering::Relaxed) } else { 0 }
}

/// Z exception_dispatch dla wektorów 0x30..0x3F.
pub fn dispatch(frame: &mut ExceptionFrame) {
    let i = frame.vector as usize - MSI_BASE;
    COUNTS[i].fetch_add(1, Ordering::Relaxed);
    let h = HANDLERS[i].load(Ordering::Acquire);
    if h != 0 {
        let h: MsiHandler = unsafe { core::mem::transmute(h) };
        h(frame.vector as u8);
    }
    super::lapic::eoi();
    super::irq::after_interrupt(frame);
}
