// Shared memory – an object with frames, mapped into the address spaces of
// several processes.  Design: ARCHITECTURE.md, "IPC".
//
// * `shm_create(size)` – frames are taken immediately and zeroed, size
//   rounded up to 4 KiB, at most SHM_MAX.
// * The object is reference-counted via Arc: handles (Fd::Shm) and mappings (ProcMem.shared).
//   Frames return to the allocator in Drop – when the last handle and the last
//   mapping are gone.  A process address space NEVER frees the object's frames:
//   munmap / process exit only removes the entries (vm.rs, Process::drop).
// * Always mapped with NX; writable only with the MAP_WRITE right.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::syscalls::{EINVAL, ENOMEM};
use crate::memory::{alloc_frame_user, alloc_frames_below, free_frame, phys_to_virt};

/// Largest object (bytes).
pub const SHM_MAX: u64 = 16 * 1024 * 1024;
const PAGE: u64 = 4096;

pub struct ShmObj {
    frames: Vec<u64>,
    /// DMA buffer – contiguous frames starting at this physical address (dma_phys).
    dma_phys: Option<u64>,
}

impl ShmObj {
    /// New object of `size` bytes (rounded up to a page), zeroed.
    pub fn new(size: u64) -> Result<Arc<ShmObj>, i64> {
        if size == 0 || size > SHM_MAX {
            return Err(EINVAL);
        }
        let pages = size.div_ceil(PAGE) as usize;
        let mut frames = Vec::new();
        frames.try_reserve_exact(pages).map_err(|_| ENOMEM)?;
        for _ in 0..pages {
            // Beyond the kernel's reserve.
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

    /// DMA buffer – `size` bytes in CONTIGUOUS frames lying entirely
    /// below `limit` (the device's address bus), zeroed.
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

    /// Size in bytes (a multiple of the page size).
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
