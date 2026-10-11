// M13a: przestrzeń adresowa procesu.
//
//   PML4[0..256)   – tylko proces: kod, dane, stos (strony z bitem USER);
//                    tablice pośrednie też z USER (o prawach decyduje wpis
//                    końcowy).
//   PML4[256..512) – kopia wpisów kernela: wskazują na te same PDPT co PML4
//                    kernela (paging::init alokuje je wszystkie od razu, więc
//                    kopia się nie zdezaktualizuje).  Bez USER – ring 3 nie
//                    ma tam dostępu.
//   PML4[510]      – mapowanie rekurencyjne wskazuje na WŁASNY PML4 procesu,
//                    więc map_page działa też, gdy CR3 = proces.
//
// Strony procesu mapujemy, chodząc po tablicach przez direct map – proces
// nie musi być aktywny (CR3) w czasie budowania.

use crate::memory::{
    alloc_frame, free_frame, kernel_cr3, phys_to_virt, PRESENT, USER, WRITABLE,
};

const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const RECURSIVE_INDEX: usize = 510;
const PAGE: u64 = 4096;
/// Pierwszy adres górnej (kernelowej) połowy.
pub const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

fn table(phys: u64) -> &'static mut [u64; 512] {
    unsafe { &mut *(phys_to_virt(phys) as *mut [u64; 512]) }
}

fn zeroed_frame() -> Option<u64> {
    let f = alloc_frame()?;
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

    /// Wartość CR3 tej przestrzeni.
    pub fn cr3(&self) -> u64 {
        self.pml4
    }

    /// Tablica niższego poziomu (tworzy ją z USER, gdy `create`).
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

    /// Mapuje stronę procesu.  `flags` bez PRESENT (USER/WRITABLE/NX).
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

    /// Nowa, wyzerowana strona pod `va`; zwraca jej ramkę.
    pub fn map_new(&mut self, va: u64, flags: u64) -> Option<u64> {
        let frame = zeroed_frame()?;
        if self.map(va, frame, flags) {
            Some(frame)
        } else {
            free_frame(frame);
            None
        }
    }

    /// M17b.d: usuwa mapowanie strony; zwraca jej ramkę (TLB i zwolnienie
    /// ramki – wołający).  Puste tablice pośrednie zostają (do końca procesu).
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

    /// (adres fizyczny, flagi wpisu) dla `va` w dolnej połowie.
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

    /// M15: zmienia flagi zamapowanej strony (segmenty ELF dzielące stronę).
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

    /// M15: zapisuje bajty pod adresem procesu (strony muszą być
    /// zamapowane) – przez direct map, proces nie musi być aktywny.
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

    /// Wpis PML4 (testy: górna połowa wspólna z kernelem).
    #[allow(dead_code)]
    pub fn pml4_entry(&self, i: usize) -> u64 {
        table(self.pml4)[i]
    }
}

impl Drop for AddressSpace {
    /// Oddaje wszystkie strony procesu, tablice i PML4.  Przestrzeń nie
    /// może być wtedy aktywna (CR3) – sprząta ją inne zadanie.
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
