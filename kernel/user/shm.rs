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
use crate::memory::{alloc_frame, free_frame, phys_to_virt};

/// Największy obiekt (bajty).
pub const SHM_MAX: u64 = 16 * 1024 * 1024;
const PAGE: u64 = 4096;

pub struct ShmObj {
    frames: Vec<u64>,
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
            let Some(f) = alloc_frame() else {
                for &f in frames.iter() {
                    free_frame(f);
                }
                return Err(ENOMEM);
            };
            unsafe { core::ptr::write_bytes(phys_to_virt(f) as *mut u8, 0, PAGE as usize) };
            frames.push(f);
        }
        Ok(Arc::new(ShmObj { frames }))
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
