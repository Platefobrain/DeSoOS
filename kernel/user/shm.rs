// M18.e: pamięć współdzielona – obiekt z ramkami, mapowany do przestrzeni
// kilku procesów.  Projekt: ARCHITEKTURA.md, „IPC”.
//
// * `shm_create(rozmiar)` – ramki brane od razu i zerowane, rozmiar
//   zaokrąglony do 4 KiB, najwyżej SHM_MAX.
// * Obiekt liczony przez Arc: uchwyty (Fd::Shm) i mapowania (ProcMem.shared).
//   Ramki wracają do alokatora w Drop – gdy znika ostatni uchwyt i ostatnie
//   mapowanie.  Przestrzeń adresowa procesu NIGDY nie zwalnia ramek obiektu:
//   munmap / koniec procesu tylko zdejmuje wpisy (vm.rs, Process::drop).
// * Mapowanie zawsze z NX; zapis tylko z prawem MAP_WRITE.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::syscalls::{EINVAL, ENOMEM};
use crate::memory::{alloc_frame_user, alloc_frames_below, free_frame, phys_to_virt};

/// Największy obiekt (bajty).
pub const SHM_MAX: u64 = 16 * 1024 * 1024;
const PAGE: u64 = 4096;

pub struct ShmObj {
    frames: Vec<u64>,
    /// M19.e: bufor DMA – ramki ciągłe od tego adresu fizycznego (dma_phys).
    dma_phys: Option<u64>,
}

impl ShmObj {
    /// Nowy obiekt `size` bajtów (zaokrąglone w górę do strony), wyzerowany.
    pub fn new(size: u64) -> Result<Arc<ShmObj>, i64> {
        if size == 0 || size > SHM_MAX {
            return Err(EINVAL);
        }
        let pages = size.div_ceil(PAGE) as usize;
        let mut frames = Vec::new();
        frames.try_reserve_exact(pages).map_err(|_| ENOMEM)?;
        for _ in 0..pages {
            // v0.35.2: ponad zapasem jądra.
            let Some(f) = alloc_frame_user() else {
                for &f in frames.iter() {
                    free_frame(f);
                }
                return Err(ENOMEM);
            };
            unsafe { core::ptr::write_bytes(phys_to_virt(f) as *mut u8, 0, PAGE as usize) };
            frames.push(f);
        }
        Ok(Arc::new(ShmObj { frames, dma_phys: None }))
    }

    /// M19.e: bufor DMA – `size` bajtów w CIĄGŁYCH ramkach leżących całe
    /// poniżej `limit` (szyna adresów urządzenia), wyzerowany.
    pub fn new_dma(size: u64, limit: u64) -> Result<Arc<ShmObj>, i64> {
        if size == 0 || size > SHM_MAX {
            return Err(EINVAL);
        }
        let pages = size.div_ceil(PAGE) as usize;
        let mut frames = Vec::new();
        frames.try_reserve_exact(pages).map_err(|_| ENOMEM)?;
        let first = alloc_frames_below(pages, 1, limit).ok_or(ENOMEM)?;
        for i in 0..pages as u64 {
            let f = first + i * PAGE;
            unsafe { core::ptr::write_bytes(phys_to_virt(f) as *mut u8, 0, PAGE as usize) };
            frames.push(f);
        }
        Ok(Arc::new(ShmObj { frames, dma_phys: Some(first) }))
    }

    pub fn dma_phys(&self) -> Option<u64> {
        self.dma_phys
    }

    /// Rozmiar w bajtach (wielokrotność strony).
    pub fn len(&self) -> u64 {
        self.frames.len() as u64 * PAGE
    }

    pub fn frames(&self) -> &[u64] {
        &self.frames
    }
}

impl Drop for ShmObj {
    fn drop(&mut self) {
        for &f in self.frames.iter() {
            free_frame(f);
        }
    }
}
