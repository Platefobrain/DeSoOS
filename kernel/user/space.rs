// Process address space.
//
//   PML4[0..256)   – process only: code, data, stack (pages with the USER bit);
//                    intermediate tables also have USER (the final entry
//                    decides the rights).
//   PML4[256..512) – copy of the kernel entries: they point to the same PDPTs as the kernel
//                    PML4 (paging::init allocates all of them up front, so
//                    the copy never goes stale).  No USER – ring 3 has
//                    no access there.
//   PML4[510]      – the recursive mapping points to the process's OWN PML4,
//                    so map_page also works when CR3 = the process.
//
// Process pages are mapped by walking the tables through the direct map – the process
// does not have to be active (CR3) while it is being built.

use crate::memory::{
    alloc_frame_user, free_frame, kernel_cr3, phys_to_virt, PRESENT, USER, WRITABLE,
};

const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const RECURSIVE_INDEX: usize = 510;
const PAGE: u64 = 4096;
/// First address of the upper (kernel) half.
pub const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

fn table(phys: u64) -> &'static mut [u64; 512] {
    unsafe { &mut *(phys_to_virt(phys) as *mut [u64; 512]) }
}

/// A frame for the process space (pages and tables) – only above
/// the kernel reserve (`alloc_frame_user`).
fn zeroed_frame() -> Option<u64> {
    let f = alloc_frame_user()?;
    unsafe { core::ptr::write_bytes(phys_to_virt(f) as *mut u8, 0, PAGE as usize) };
    Some(f)
}

fn index(va: u64, level: u32) -> usize {
    ((va >> (12 + 9 * (level - 1))) & 0x1ff) as usize
}

pub struct AddressSpace {
    pml4: u64,
}

impl AddressSpace {
    pub fn new() -> Option<Self> {
        let pml4 = zeroed_frame()?;
        let kernel = table(kernel_cr3());
        let mine = table(pml4);
        mine[256..512].copy_from_slice(&kernel[256..512]);
        mine[RECURSIVE_INDEX] = pml4 | PRESENT | WRITABLE;
        Some(AddressSpace { pml4 })
    }

    /// CR3 value of this space.
    pub fn cr3(&self) -> u64 {
        self.pml4
    }

    /// Lower-level table (created with USER when `create`).
    fn next(parent: u64, i: usize, create: bool) -> Option<u64> {
        let e = &mut table(parent)[i];
        if *e & PRESENT == 0 {
            if !create {
                return None;
            }
            *e = zeroed_frame()? | PRESENT | WRITABLE | USER;
        }
        Some(*e & ADDRESS_MASK)
    }

    /// Maps a process page.  `flags` without PRESENT (USER/WRITABLE/NX).
    pub fn map(&mut self, va: u64, frame: u64, flags: u64) -> bool {
        if va % PAGE != 0 || va >= USER_SPACE_END || frame % PAGE != 0 {
            return false;
        }
        let Some(pdpt) = Self::next(self.pml4, index(va, 4), true) else { return false };
        let Some(pd) = Self::next(pdpt, index(va, 3), true) else { return false };
        let Some(pt) = Self::next(pd, index(va, 2), true) else { return false };
        let e = &mut table(pt)[index(va, 1)];
        if *e & PRESENT != 0 {
            return false;
        }
        *e = frame | flags | PRESENT;
        true
    }

    /// A new, zeroed page at `va`; returns its frame.
    pub fn map_new(&mut self, va: u64, flags: u64) -> Option<u64> {
        let frame = zeroed_frame()?;
        if self.map(va, frame, flags) {
            Some(frame)
        } else {
            free_frame(frame);
            None
        }
    }

    /// Removes a page mapping; returns its frame (TLB flush and freeing the
    /// frame – the caller's job).  Intermediate tables that become empty stay until
    /// `prune` (munmap / brk call it) or the end of the process.
    pub fn unmap(&mut self, va: u64) -> Option<u64> {
        if va >= USER_SPACE_END {
            return None;
        }
        let pdpt = Self::next(self.pml4, index(va, 4), false)?;
        let pd = Self::next(pdpt, index(va, 3), false)?;
        let pt = Self::next(pd, index(va, 2), false)?;
        let e = &mut table(pt)[index(va, 1)];
        if *e & PRESENT == 0 {
            return None;
        }
        let frame = *e & ADDRESS_MASK;
        *e = 0;
        Some(frame)
    }

    /// Frees the intermediate tables (page table, directory, PDPT) that hold no entry any
    /// more in the 2 MiB stretches touching [start, end) – after an unmap.  Without it a
    /// process that keeps mapping new areas (mmap moves on to fresh addresses) collected
    /// empty tables for as long as it ran (found by the soak test).  Returns the number of
    /// freed tables; the caller then flushes the TLB with its cached table entries (a CR3
    /// reload – `flush_if_active`).
    pub fn prune(&mut self, start: u64, end: u64) -> u64 {
        const R2M: u64 = 1 << 21;
        let end = end.min(USER_SPACE_END);
        let mut freed = 0;
        let mut va = start & !(R2M - 1);
        while va < end {
            let (i4, i3, i2) = (index(va, 4), index(va, 3), index(va, 2));
            let up = |bits: u32| (va | ((1u64 << bits) - 1)).saturating_add(1);
            let Some(pdpt) = Self::next(self.pml4, i4, false) else {
                va = up(39);
                continue;
            };
            let Some(pd) = Self::next(pdpt, i3, false) else {
                va = up(30);
                continue;
            };
            let next = up(21);
            let Some(pt) = Self::next(pd, i2, false) else {
                va = next;
                continue;
            };
            if table(pt).iter().any(|&e| e != 0) {
                va = next;
                continue;
            }
            table(pd)[i2] = 0;
            free_frame(pt);
            freed += 1;
            if table(pd).iter().all(|&e| e == 0) {
                table(pdpt)[i3] = 0;
                free_frame(pd);
                freed += 1;
                if table(pdpt).iter().all(|&e| e == 0) {
                    table(self.pml4)[i4] = 0;
                    free_frame(pdpt);
                    freed += 1;
                }
            }
            va = next;
        }
        freed
    }

    /// After `prune` freed tables: a CR3 reload drops this CPU's cached translations
    /// and table entries when this space is the active one (other CPUs load another CR3
    /// whenever they leave the process – see tlb.rs).
    pub fn flush_if_active(&self) {
        let cr3: u64;
        unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags)) };
        if cr3 & ADDRESS_MASK == self.pml4 {
            unsafe { core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags)) };
        }
    }

    /// End of the unmapped stretch around `va` when a whole table above the page
    /// is missing (the next 2 MiB / 1 GiB / 512 GiB boundary); `va` itself when the page
    /// table for `va` exists.  Lets range walks skip untouched areas.
    pub fn hole_end(&self, va: u64) -> u64 {
        let up = |bits: u32| (va | ((1u64 << bits) - 1)).saturating_add(1);
        if va >= USER_SPACE_END {
            return va;
        }
        let Some(pdpt) = Self::next(self.pml4, index(va, 4), false) else { return up(39) };
        let Some(pd) = Self::next(pdpt, index(va, 3), false) else { return up(30) };
        if Self::next(pd, index(va, 2), false).is_none() {
            return up(21);
        }
        va
    }

    /// (physical address, entry flags) for `va` in the lower half.
    #[allow(dead_code)]
    pub fn translate(&self, va: u64) -> Option<(u64, u64)> {
        if va >= USER_SPACE_END {
            return None;
        }
        let pdpt = Self::next(self.pml4, index(va, 4), false)?;
        let pd = Self::next(pdpt, index(va, 3), false)?;
        let pt = Self::next(pd, index(va, 2), false)?;
        let e = table(pt)[index(va, 1)];
        if e & PRESENT == 0 {
            return None;
        }
        Some(((e & ADDRESS_MASK) + (va & (PAGE - 1)), e & !ADDRESS_MASK))
    }

    /// Changes the flags of a mapped page (ELF segments sharing a page).
    pub fn set_flags(&mut self, va: u64, flags: u64) -> bool {
        let Some(pdpt) = Self::next(self.pml4, index(va, 4), false) else { return false };
        let Some(pd) = Self::next(pdpt, index(va, 3), false) else { return false };
        let Some(pt) = Self::next(pd, index(va, 2), false) else { return false };
        let e = &mut table(pt)[index(va, 1)];
        if *e & PRESENT == 0 {
            return false;
        }
        *e = (*e & ADDRESS_MASK) | flags | PRESENT;
        true
    }

    /// Writes bytes at a process address (the pages must be
    /// mapped) – through the direct map, the process does not have to be active.
    pub fn write_bytes(&mut self, va: u64, data: &[u8]) -> bool {
        let mut done = 0usize;
        while done < data.len() {
            let addr = va + done as u64;
            let Some((phys, _)) = self.translate(addr) else { return false };
            let in_page = (PAGE - (addr & (PAGE - 1))) as usize;
            let n = in_page.min(data.len() - done);
            unsafe {
                core::ptr::copy_nonoverlapping(data[done..].as_ptr(), phys_to_virt(phys) as *mut u8, n);
            }
            done += n;
        }
        true
    }

    /// PML4 entry (tests: upper half shared with the kernel).
    #[allow(dead_code)]
    pub fn pml4_entry(&self, i: usize) -> u64 {
        table(self.pml4)[i]
    }
}

impl Drop for AddressSpace {
    /// Frees all of the process's pages, tables and the PML4.  The space must not
    /// be active (CR3) at that time – another task cleans it up.
    fn drop(&mut self) {
        let pml4 = table(self.pml4);
        for i4 in 0..256 {
            if pml4[i4] & PRESENT == 0 {
                continue;
            }
            let pdpt_phys = pml4[i4] & ADDRESS_MASK;
            let pdpt = table(pdpt_phys);
            for i3 in 0..512 {
                if pdpt[i3] & PRESENT == 0 {
                    continue;
                }
                let pd_phys = pdpt[i3] & ADDRESS_MASK;
                let pd = table(pd_phys);
                for i2 in 0..512 {
                    if pd[i2] & PRESENT == 0 {
                        continue;
                    }
                    let pt_phys = pd[i2] & ADDRESS_MASK;
                    let pt = table(pt_phys);
                    for i1 in 0..512 {
                        if pt[i1] & PRESENT != 0 {
                            free_frame(pt[i1] & ADDRESS_MASK);
                        }
                    }
                    free_frame(pt_phys);
                }
                free_frame(pd_phys);
            }
            free_frame(pdpt_phys);
        }
        free_frame(self.pml4);
    }
}
