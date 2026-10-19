// PCI device claimed by a user-space service.
// Design: ARCHITECTURE.md, "User-space services".
//
// * `HW_ROOT` (a handle without DUP / TRANSFER rights) is given only to /bin/init –
//   `dev_claim` takes individual devices out of it.
// * `DevClaim` – a claim: reference-counted with Arc (DEVICE handles and register
//   mappings in processes).  When the last one goes away, Drop returns the device
//   (pci::release_user); it first disables interrupts and bus
//   mastering, then frees the vector and the DMA buffers.
// * BAR mapping: register pages uncached (UC), never executable;
//   pages with the MSI-X table / PBA are skipped.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::waitset::Observers;
use crate::arch::x86_64::msi;
use crate::drivers::pci::{self, Bar, Device};
use crate::sched::spin::{level, SpinLock};

pub struct DevClaim {
    index: usize,
    /// The device's DMA buffers (and their total size) – they live as long as the
    /// claim: the device could write to a buffer the service has already closed.
    dma: SpinLock<(Vec<Arc<super::shm::ShmObj>>, u64)>,
    /// Bound interrupt (one per device).
    irq: AtomicBool,
    /// The device was granted bus mastering (MSI, later DMA) – on
    /// release it is disabled BEFORE anything else returns to the kernel.
    bus_master: AtomicBool,
}

impl DevClaim {
    pub fn claim(addr: pci::Address) -> Result<DevClaim, pci::ClaimError> {
        pci::claim_user(addr).map(|index| DevClaim {
            index,
            dma: SpinLock::new("dma-buffers", level::PROCESS, (Vec::new(), 0)),
            irq: AtomicBool::new(false),
            bus_master: AtomicBool::new(false),
        })
    }

    pub fn dev(&self) -> &'static Device {
        &pci::devices()[self.index]
    }

    /// Pages of BAR `bar` to map: Some(physical page address) or None
    /// (a hole – MSI-X).  Error: no memory BAR, a BAR smaller than a page
    /// or not aligned (registers of another device could lie on the same
    /// page), larger than MAX_BAR.
    pub fn bar_pages(&self, bar: usize) -> Result<Vec<Option<u64>>, i64> {
        use super::syscalls::EINVAL;
        const PAGE: u64 = 4096;
        const MAX_BAR: u64 = 256 * 1024 * 1024;
        let d = self.dev();
        let Some(&Bar::Memory { base, size, .. }) = d.bars.get(bar) else { return Err(EINVAL) };
        if size < PAGE || base % PAGE != 0 || size > MAX_BAR {
            return Err(EINVAL);
        }
        let holes = d.msix_regions(bar);
        let pages = size.div_ceil(PAGE);
        let mut out = Vec::with_capacity(pages as usize);
        for p in 0..pages {
            let (lo, hi) = (p * PAGE, (p + 1) * PAGE);
            let hole = holes.iter().any(|&(off, len)| off < hi && off + len > lo);
            out.push(if hole { None } else { Some(base + lo) });
        }
        Ok(out)
    }
}

/// Largest DMA buffer, and the total per device.
pub const DMA_BUF_MAX: u64 = 2 * 1024 * 1024;
pub const DMA_DEV_MAX: u64 = 16 * 1024 * 1024;

impl DevClaim {
    /// dma_alloc: a buffer of contiguous frames below `2^bits` (24..=64), enables
    /// bus mastering for the device.  EINVAL: size 0 / > 2 MiB, bad `bits`;
    /// ENOMEM: the 16 MiB per-device limit or no contiguous memory.
    pub fn dma_alloc(&self, size: u64, bits: u64) -> Result<Arc<super::shm::ShmObj>, i64> {
        use super::syscalls::{EINVAL, ENOMEM};
        if size == 0 || size > DMA_BUF_MAX || !(24..=64).contains(&bits) {
            return Err(EINVAL);
        }
        let len = size.div_ceil(4096) * 4096;
        let limit = if bits >= 64 { u64::MAX } else { 1u64 << bits };
        let mut dma = self.dma.lock();
        if dma.1 + len > DMA_DEV_MAX {
            return Err(ENOMEM);
        }
        let buf = super::shm::ShmObj::new_dma(len, limit)?;
        dma.0.push(buf.clone());
        dma.1 += len;
        drop(dma);
        if !self.bus_master.swap(true, Ordering::SeqCst) {
            self.dev().set_bus_master(true);
        }
        Ok(buf)
    }
}

impl Drop for DevClaim {
    fn drop(&mut self) {
        // The device goes quiet (no DMA and MSI), only then is it returned.
        if self.bus_master.load(Ordering::SeqCst) {
            self.dev().disable_msi();
            self.dev().set_bus_master(false);
        }
        // Only now the DMA buffers (the `dma` field is freed after this Drop – the frames
        // come back once the last mapping in processes is gone too).
        pci::release_user(self.index);
    }
}

/// PCI address from the service number: bus << 8 | device << 3 | function.
pub fn address(bdf: u64) -> Option<pci::Address> {
    if bdf > 0xFFFF {
        return None;
    }
    Some(pci::Address { bus: (bdf >> 8) as u8, device: ((bdf >> 3) & 31) as u8, function: (bdf & 7) as u8 })
}

// ------------------------------------------------------------
// Device interrupts for services.
//
// MSI vector 0x30 + i ↔ slot i (static – the interrupt handler does not touch
// memory that could be freed).  Handler: counter + waking
// observers (`wait_many` with W_IRQ) – nothing more.  MSI is edge-triggered, so
// the line does not need masking; several interrupts before handling = one wakeup
// with a counter.
// ------------------------------------------------------------

pub struct IrqSlot {
    count: AtomicU64,
    /// Timestamp (`clock::stamp`) of the last interrupt – for
    /// measuring "USB keyboard interrupt -> character in the kernel".
    last: AtomicU64,
    obs: Observers,
}

static SLOTS: [IrqSlot; msi::MSI_VECTORS] =
    [const { IrqSlot { count: AtomicU64::new(0), last: AtomicU64::new(0), obs: Observers::new() } }; msi::MSI_VECTORS];

fn user_irq(vector: u8) {
    let i = vector as usize - msi::MSI_BASE;
    if let Some(s) = SLOTS.get(i) {
        s.last.store(crate::arch::x86_64::clock::stamp(), Ordering::Relaxed);
        s.count.fetch_add(1, Ordering::SeqCst);
        s.obs.notify();
    }
}

/// A device interrupt bound to a service (IRQ handle).  Holds the
/// device claim; Drop disables MSI and frees the vector.
pub struct IrqObj {
    vector: u8,
    claim: Arc<DevClaim>,
}

impl IrqObj {
    /// irq_bind: MSI vector (or MSI-X entry 0), bus mastering (MSI is the device
    /// writing to memory).  EBUSY – interrupt already bound or no
    /// free vectors; ENODEV – device without MSI / MSI-X.
    pub fn bind(claim: Arc<DevClaim>) -> Result<IrqObj, i64> {
        use super::syscalls::{EBUSY, ENODEV};
        use crate::drivers::pci::{CAP_MSI, CAP_MSIX};
        let d = claim.dev();
        let has_msi = d.find_capability(CAP_MSI).is_some();
        if !has_msi && d.find_capability(CAP_MSIX).is_none() {
            return Err(ENODEV);
        }
        if claim.irq.swap(true, Ordering::SeqCst) {
            return Err(EBUSY);
        }
        let Some(vector) = msi::alloc(user_irq) else {
            claim.irq.store(false, Ordering::SeqCst);
            return Err(EBUSY);
        };
        let slot = &SLOTS[vector as usize - msi::MSI_BASE];
        slot.count.store(0, Ordering::SeqCst);
        slot.last.store(0, Ordering::Relaxed);
        claim.bus_master.store(true, Ordering::SeqCst);
        d.set_bus_master(true);
        let ok = if has_msi { d.enable_msi(vector) } else { d.enable_msix(0, vector) };
        if ok.is_err() {
            d.disable_msi();
            msi::free(vector);
            claim.irq.store(false, Ordering::SeqCst);
            return Err(ENODEV);
        }
        Ok(IrqObj { vector, claim })
    }

    fn slot(&self) -> &'static IrqSlot {
        &SLOTS[self.vector as usize - msi::MSI_BASE]
    }

    /// MSI vector (`dcp`).
    pub fn vector(&self) -> u8 {
        self.vector
    }

    /// The claimed device (`dcp`).
    pub fn device(&self) -> &'static crate::drivers::pci::Device {
        self.claim.dev()
    }

    /// Interrupts since the last read (resets the counter).
    pub fn take(&self) -> u64 {
        self.slot().count.swap(0, Ordering::SeqCst)
    }

    /// Timestamp of the last interrupt (0 – none yet).
    pub fn last_stamp(&self) -> u64 {
        self.slot().last.load(Ordering::Relaxed)
    }

    pub fn pending(&self) -> bool {
        self.slot().count.load(Ordering::SeqCst) > 0
    }

    pub fn observers(&self) -> &Observers {
        &self.slot().obs
    }
}

impl Drop for IrqObj {
    fn drop(&mut self) {
        // The device stops sending (register read – the write has landed), then
        // the vector is returned; a late interrupt will hit an empty handler.
        let d = self.claim.dev();
        d.disable_msi();
        let _ = d.command();
        msi::free(self.vector);
        self.slot().count.store(0, Ordering::SeqCst);
        self.claim.irq.store(false, Ordering::SeqCst);
    }
}
