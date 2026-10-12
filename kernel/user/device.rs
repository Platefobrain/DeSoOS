// M19.c: urządzenie PCI przejęte przez usługę w user space.
// Projekt: ARCHITEKTURA.md, „Usługi w user space”.
//
// * `HW_ROOT` (uchwyt bez praw DUP / TRANSFER) dostaje tylko /bin/init – z
//   niego `dev_claim` wyjmuje pojedyncze urządzenie.
// * `DevClaim` – przejęcie: liczone przez Arc (uchwyty DEVICE i mapowania
//   rejestrów w procesach).  Gdy znika ostatnie – Drop oddaje urządzenie
//   (pci::release_user); od 19.d / 19.e najpierw wyłącza przerwania i bus
//   mastering, potem zwalnia wektor i bufory DMA.
// * Mapowanie BAR-u: strony rejestrów bez cache (UC), nigdy wykonywalne;
//   strony z tablicą MSI-X / PBA pominięte.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::waitset::Observers;
use crate::arch::x86_64::msi;
use crate::drivers::pci::{self, Bar, Device};
use crate::sched::spin::{level, SpinLock};

pub struct DevClaim {
    index: usize,
    /// M19.e: bufory DMA urządzenia (i ich łączny rozmiar) – żyją tak długo jak
    /// przejęcie: urządzenie mogłoby pisać do bufora, który usługa już zamknęła.
    dma: SpinLock<(Vec<Arc<super::shm::ShmObj>>, u64)>,
    /// M19.d: przerwanie przypięte (jedno na urządzenie).
    irq: AtomicBool,
    /// M19.d: urządzenie dostało bus mastering (MSI, później DMA) – przy
    /// oddaniu wyłączany, ZANIM cokolwiek innego wróci do jądra.
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

    /// Strony BAR-u `bar` do zmapowania: Some(fizyczny adres strony) albo None
    /// (dziura – MSI-X).  Błąd: brak BAR-u pamięci, BAR mniejszy niż strona
    /// albo nie wyrównany (na tej samej stronie mogłyby leżeć rejestry innego
    /// urządzenia), większy niż MAX_BAR.
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

/// M19.e: największy bufor DMA i łącznie na urządzenie.
pub const DMA_BUF_MAX: u64 = 2 * 1024 * 1024;
pub const DMA_DEV_MAX: u64 = 16 * 1024 * 1024;

impl DevClaim {
    /// dma_alloc: bufor z ciągłych ramek poniżej `2^bits` (24..=64), włącza
    /// urządzeniu bus mastering.  EINVAL: rozmiar 0 / > 2 MiB, złe `bits`;
    /// ENOMEM: limit 16 MiB na urządzenie albo brak ciągłej pamięci.
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
        // M19.d: urządzenie milknie (bez DMA i MSI), dopiero potem wraca.
        if self.bus_master.load(Ordering::SeqCst) {
            self.dev().disable_msi();
            self.dev().set_bus_master(false);
        }
        // Dopiero teraz bufory DMA (pole `dma` zwalnia się po tym Drop – ramki
        // wracają, gdy zniknie też ostatnie mapowanie w procesach).
        pci::release_user(self.index);
    }
}

/// Adres PCI z numeru usługi: bus << 8 | urządzenie << 3 | funkcja.
pub fn address(bdf: u64) -> Option<pci::Address> {
    if bdf > 0xFFFF {
        return None;
    }
    Some(pci::Address { bus: (bdf >> 8) as u8, device: ((bdf >> 3) & 31) as u8, function: (bdf & 7) as u8 })
}

// ------------------------------------------------------------
// M19.d: przerwania urządzeń dla usług.
//
// Wektor MSI 0x30 + i ↔ slot i (statyczny – handler przerwania nie dotyka
// pamięci, która mogłaby zostać zwolniona).  Handler: licznik + pobudka
// obserwatorów (`wait_many` z W_IRQ) – nic więcej.  MSI jest zboczowe, więc
// linii nie trzeba maskować; kilka przerwań przed obsługą = jedna pobudka
// z licznikiem.
// ------------------------------------------------------------

pub struct IrqSlot {
    count: AtomicU64,
    obs: Observers,
}

static SLOTS: [IrqSlot; msi::MSI_VECTORS] =
    [const { IrqSlot { count: AtomicU64::new(0), obs: Observers::new() } }; msi::MSI_VECTORS];

fn user_irq(vector: u8) {
    let i = vector as usize - msi::MSI_BASE;
    if let Some(s) = SLOTS.get(i) {
        s.count.fetch_add(1, Ordering::SeqCst);
        s.obs.notify();
    }
}

/// Przerwanie urządzenia przypięte do usługi (uchwyt IRQ).  Trzyma
/// przejęcie urządzenia; Drop wyłącza MSI i zwalnia wektor.
pub struct IrqObj {
    vector: u8,
    claim: Arc<DevClaim>,
}

impl IrqObj {
    /// irq_bind: wektor MSI (albo MSI-X wpis 0), bus mastering (MSI to zapis
    /// urządzenia do pamięci).  EBUSY – przerwanie już przypięte albo brak
    /// wolnych wektorów; ENODEV – urządzenie bez MSI / MSI-X.
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

    /// Przerwania od ostatniego odczytu (zeruje licznik).
    pub fn take(&self) -> u64 {
        self.slot().count.swap(0, Ordering::SeqCst)
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
        // Urządzenie przestaje wysyłać (odczyt rejestru – zapis dotarł), potem
        // wektor wraca; spóźnione przerwanie trafi już w pusty handler.
        let d = self.claim.dev();
        d.disable_msi();
        let _ = d.command();
        msi::free(self.vector);
        self.slot().count.store(0, Ordering::SeqCst);
        self.claim.irq.store(false, Ordering::SeqCst);
    }
}
