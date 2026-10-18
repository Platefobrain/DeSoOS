// MSI/MSI-X interrupt vectors (0x30..0x3F).
//
// A driver requests a vector (`alloc`) and writes it into the device's MSI/MSI-X capability
// (drivers/pci.rs) together with the LAPIC address.  The interrupt arrives
// directly at the LAPIC, so EOI goes to the LAPIC (not to the PIC).  After that, as with
// an IRQ: preemption and killing of a ring 3 process (irq::after_interrupt).

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::exceptions::ExceptionFrame;

pub const MSI_BASE: usize = 0x30;
pub const MSI_VECTORS: usize = 16;

pub type MsiHandler = fn(vector: u8);

static HANDLERS: [AtomicUsize; MSI_VECTORS] = [const { AtomicUsize::new(0) }; MSI_VECTORS];
static COUNTS: [AtomicU64; MSI_VECTORS] = [const { AtomicU64::new(0) }; MSI_VECTORS];

/// A free vector with a handler; None when there is no LAPIC or no vectors left.
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

/// Releases a vector (a user-space service may restart – without this
/// we would run out of vectors after 16 restarts).  An interrupt arriving after
/// the release is only counted (handler 0).
pub fn free(vector: u8) {
    let i = (vector as usize).wrapping_sub(MSI_BASE);
    if i < MSI_VECTORS {
        HANDLERS[i].store(0, Ordering::Release);
    }
}

/// Free vectors (vector leak tests).
#[allow(dead_code)]
pub fn free_count() -> usize {
    HANDLERS.iter().filter(|h| h.load(Ordering::Relaxed) == 0).count()
}

/// How many interrupts arrived on a vector (tests, diagnostics).
#[allow(dead_code)]
pub fn count(vector: u8) -> u64 {
    let i = (vector as usize).wrapping_sub(MSI_BASE);
    if i < MSI_VECTORS { COUNTS[i].load(Ordering::Relaxed) } else { 0 }
}

/// Called from exception_dispatch for vectors 0x30..0x3F.
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
