// M17b.d: pamięć procesu – obszary (VMA) z leniwym przydziałem stron.
//
//   [obraz ELF][brk: sterta rośnie w górę ->]   ...   [mmap: od MMAP_BASE ->]
//   ...   [stos: do STACK_MAX w dół od USER_STACK_TOP; strona-strażnik pod]
//
// * Obszar to tylko zakres adresów z prawami – strony dostaje dopiero przy
//   pierwszym dostępie: #PF z ring 3 (nieobecna strona w obszarze) albo
//   kopiowanie przez kernel (copy_from_user / copy_to_user dociąga strony,
//   zanim sprawdzi prawa).  Nowa strona jest wyzerowana.
// * brk(addr) – koniec sterty (0 = zapytanie); mmap(len, prot) – anonimowy
//   obszar (adresy rosną, bez ponownego użycia – przestrzeń 128 TiB);
//   munmap(addr, len) – tylko obszary z mmap, także ich części.
// * Proces jest jednowątkowy: obszary i tablice stron zmienia tylko on sam
//   (syscall, #PF), więc bez blokad.  Zwolnione strony: invlpg na tym CPU
//   wystarcza – przestrzeń jest aktywna tylko tu (inne CPU po przełączeniu
//   zadania przeładowały CR3).
// * Limit: obszary procesu razem (bez stosu) najwyżej MAX_MAPPED – chroni
//   tablice stron; ramki i tak przydziela dopiero dostęp.  Brak ramki przy
//   #PF = proces kończony (#PF), przy kopiowaniu – EFAULT.

use alloc::vec::Vec;

use super::space::AddressSpace;
use super::{USER_STACK_SIZE, USER_STACK_TOP};
use crate::memory::{USER, WRITABLE};

const PAGE: u64 = 4096;
/// Początek obszarów mmap (16 TiB).
pub const MMAP_BASE: u64 = 0x0000_1000_0000_0000;
/// Najdalej rosnący stos (8 MiB, w tym strona-strażnik na dole).
pub const STACK_MAX: u64 = 8 * 1024 * 1024;
/// Sterta (brk) najwyżej tyle.
pub const BRK_MAX: u64 = 1 << 30;
/// Wszystkie obszary sterty i mmap razem.
pub const MAX_MAPPED: u64 = 4 << 30;

/// M17b.d2: ile stron dociągać naraz (fault-around): sterta i mmap – w górę od
/// strony błędu, stos – w dół.  Pomiar (QEMU TCG, 1 CPU, stress 20 s, po 3
/// przebiegi): 1 strona – 553 skrypty, 16 stron – 515 (zerowanie 64 KiB na
/// każdy #PF, a procesy w stressie dotykają ich mało: ~0,5 #PF na proces),
/// stara sterta 256 KiB w .bss – 541.  Zostaje 1 (pokrętło do pomiarów).
pub const FAULT_AROUND: u64 = 1;

// Statystyka (per CPU, bez wspólnej linii cache): #PF obsłużone, strony
// dociągnięte przez #PF i przez kopiowanie kernela, wywołania brk / mmap.
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};
static PF_TRAPS: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static PF_PAGES: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static COPY_PAGES: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static MEM_CALLS: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));

fn bump(a: &crate::arch::x86_64::percpu::PerCpu<AtomicU64>, n: u64) {
    a[crate::arch::x86_64::cpu::id()].fetch_add(n, Relaxed);
}

fn sum(a: &crate::arch::x86_64::percpu::PerCpu<AtomicU64>) -> u64 {
    a.iter().map(|x| x.load(Relaxed)).sum()
}

/// (#PF obsłużone, strony z #PF, strony z kopiowania, brk + mmap + munmap) – `cpus`.
pub fn stats() -> (u64, u64, u64, u64) {
    (sum(&PF_TRAPS), sum(&PF_PAGES), sum(&COPY_PAGES), sum(&MEM_CALLS))
}

/// Licznik wywołań brk / mmap / munmap (syscalls.rs).
pub fn count_call() {
    bump(&MEM_CALLS, 1);
}

pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VmaKind {
    Heap,
    Mmap,
    Stack,
    /// M18.e: pamięć współdzielona – strony zamapowane od razu, ramki należą
    /// do obiektu (ProcMem.shared), nigdy nie są zwalniane przez proces.
    /// M19.c: tak samo rejestry urządzenia (BAR) – strony fizyczne urządzenia.
    Shared,
}

#[derive(Clone, Copy, Debug)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub writable: bool,
    pub kind: VmaKind,
}

/// M19.c: właściciel stron obszaru wspólnego – trzymany, dopóki obszar jest
/// zamapowany (obiekt pamięci współdzielonej albo przejęcie urządzenia).
#[allow(dead_code)]
pub enum SharedRef {
    Shm(alloc::sync::Arc<super::shm::ShmObj>),
    Dev(alloc::sync::Arc<super::device::DevClaim>),
}

pub struct ProcMem {
    brk_start: u64,
    brk: u64,
    mmap_next: u64,
    vmas: Vec<Vma>,
    /// M18.e: mapowania pamięci współdzielonej (początek obszaru, obiekt) –
    /// trzymają obiekt przy życiu.
    shared: Vec<(u64, SharedRef)>,
    /// Strony dociągnięte leniwie (statystyka, testy).
    pub faulted: u64,
}

fn page_up(x: u64) -> u64 {
    (x + PAGE - 1) & !(PAGE - 1)
}

impl ProcMem {
    /// `image_end` – pierwszy adres za obrazem programu (sterta zaczyna się
    /// stronę dalej – strona-strażnik).
    pub fn new(image_end: u64) -> Self {
        let brk_start = page_up(image_end) + PAGE;
        let stack = Vma {
            start: USER_STACK_TOP - STACK_MAX + PAGE,
            end: USER_STACK_TOP - USER_STACK_SIZE,
            writable: true,
            kind: VmaKind::Stack,
        };
        ProcMem { brk_start, brk: brk_start, mmap_next: MMAP_BASE, vmas: alloc::vec![stack], shared: Vec::new(), faulted: 0 }
    }

    fn find(&self, va: u64) -> Option<&Vma> {
        self.vmas.iter().find(|v| va >= v.start && va < v.end)
    }

    fn mapped_total(&self) -> u64 {
        self.vmas.iter().filter(|v| v.kind != VmaKind::Stack).map(|v| v.end - v.start).sum()
    }

    /// Dociąga stronę pod `va`, jeśli leży w obszarze (i zapis jest tam
    /// dozwolony); `true` = strona jest teraz zamapowana przez nas.  M17b.d2:
    /// razem z nią do FAULT_AROUND sąsiednich nieobecnych stron obszaru
    /// (`from_copy` – kopiowanie przez kernel, tylko statystyka).
    pub fn fault_in(&mut self, space: &mut AddressSpace, va: u64, write: bool, from_copy: bool) -> bool {
        let Some(v) = self.find(va).copied() else { return false };
        if write && !v.writable {
            return false;
        }
        // Wspólna pamięć jest zamapowana w całości – brak strony tam to błąd
        // (nie dociągamy prywatnej strony w miejsce wspólnej).
        if v.kind == VmaKind::Shared {
            return false;
        }
        let page = va & !(PAGE - 1);
        if space.translate(page).is_some() {
            return false; // obecna – to naruszenie praw, nie brak strony
        }
        let flags = USER | if v.writable { WRITABLE } else { 0 } | crate::memory::nx_flag();
        if space.map_new(page, flags).is_none() {
            return false;
        }
        // Sąsiedzi: stos rośnie w dół, reszta w górę.  Brak pamięci – trudno,
        // sama strona błędu już jest.
        let (lo, hi) = if v.kind == VmaKind::Stack {
            (page.saturating_sub((FAULT_AROUND - 1) * PAGE).max(v.start), page)
        } else {
            (page + PAGE, (page + FAULT_AROUND * PAGE).min(v.end))
        };
        let mut mapped = 1;
        let mut p = lo;
        while p < hi {
            if p != page && space.translate(p).is_none() {
                if space.map_new(p, flags).is_none() {
                    break;
                }
                mapped += 1;
            }
            p += PAGE;
        }
        self.faulted += mapped;
        if from_copy {
            bump(&COPY_PAGES, mapped);
        } else {
            bump(&PF_TRAPS, 1);
            bump(&PF_PAGES, mapped);
        }
        true
    }

    /// Czy strona leży w jakimś obszarze (do sprawdzania zakresów).
    pub fn covers(&self, va: u64) -> bool {
        self.find(va).is_some()
    }

    /// brk(addr): nowy koniec sterty (0 – tylko zapytanie).  Przy błędzie
    /// zwraca dotychczasowy koniec (jak Linux).
    pub fn set_brk(&mut self, space: &mut AddressSpace, addr: u64) -> u64 {
        if addr == 0 || addr < self.brk_start || addr > self.brk_start + BRK_MAX {
            return self.brk;
        }
        let old_end = page_up(self.brk);
        let new_end = page_up(addr);
        if new_end > old_end && self.mapped_total() + (new_end - old_end) > MAX_MAPPED {
            return self.brk;
        }
        if new_end < old_end {
            unmap_range(space, new_end, old_end);
        }
        self.vmas.retain(|v| v.kind != VmaKind::Heap);
        if new_end > self.brk_start {
            self.vmas.push(Vma { start: self.brk_start, end: new_end, writable: true, kind: VmaKind::Heap });
        }
        self.brk = addr;
        addr
    }

    /// mmap(len, prot) – adres nowego obszaru albo błąd (-errno).
    pub fn mmap(&mut self, len: u64, prot: u64) -> Result<u64, i64> {
        use super::syscalls::{EINVAL, ENOMEM};
        if len == 0 || prot & !(PROT_READ | PROT_WRITE) != 0 {
            return Err(EINVAL);
        }
        let len = page_up(len);
        if self.mapped_total() + len > MAX_MAPPED {
            return Err(ENOMEM);
        }
        let start = self.mmap_next;
        // Strona przerwy między obszarami – przepełnienie bufora trafia w #PF.
        self.mmap_next += len + PAGE;
        self.vmas.push(Vma { start, end: start + len, writable: prot & PROT_WRITE != 0, kind: VmaKind::Mmap });
        Ok(start)
    }

    /// M18.e: mapuje obiekt pamięci współdzielonej (cały) – adres obszaru.
    pub fn map_shared(
        &mut self,
        space: &mut AddressSpace,
        obj: alloc::sync::Arc<super::shm::ShmObj>,
        write: bool,
    ) -> Result<u64, i64> {
        let pages: Vec<Option<u64>> = obj.frames().iter().map(|&f| Some(f)).collect();
        self.map_pages(space, &pages, write, 0, SharedRef::Shm(obj))
    }

    /// M19.c: rejestry urządzenia (strony fizyczne BAR-u) – bez cache (UC),
    /// nigdy wykonywalne; None = dziura (MSI-X), dostęp tam = #PF.
    pub fn map_mmio(
        &mut self,
        space: &mut AddressSpace,
        pages: &[Option<u64>],
        write: bool,
        claim: alloc::sync::Arc<super::device::DevClaim>,
    ) -> Result<u64, i64> {
        use crate::memory::{CACHE_DISABLE, WRITE_THROUGH};
        self.map_pages(space, pages, write, CACHE_DISABLE | WRITE_THROUGH, SharedRef::Dev(claim))
    }

    /// Obszar wspólny: strony mapowane od razu, `keep` trzyma ich właściciela.
    fn map_pages(
        &mut self,
        space: &mut AddressSpace,
        pages: &[Option<u64>],
        write: bool,
        extra: u64,
        keep: SharedRef,
    ) -> Result<u64, i64> {
        use super::syscalls::ENOMEM;
        let len = pages.len() as u64 * PAGE;
        if self.mapped_total() + len > MAX_MAPPED {
            return Err(ENOMEM);
        }
        let start = self.mmap_next;
        let flags = USER | if write { WRITABLE } else { 0 } | crate::memory::nx_flag() | extra;
        for (i, page) in pages.iter().enumerate() {
            let Some(f) = *page else { continue };
            if !space.map(start + i as u64 * PAGE, f, flags) {
                unmap_keep(space, start, start + i as u64 * PAGE);
                return Err(ENOMEM);
            }
        }
        self.mmap_next += len + PAGE;
        self.vmas.push(Vma { start, end: start + len, writable: write, kind: VmaKind::Shared });
        self.shared.push((start, keep));
        Ok(start)
    }

    /// M18.e: zdejmuje wszystkie mapowania wspólne (koniec procesu – zanim
    /// przestrzeń adresowa zwolni swoje strony; ramki obiektów zostają).
    pub fn release_shared(&mut self, space: &mut AddressSpace) {
        for v in self.vmas.iter().filter(|v| v.kind == VmaKind::Shared) {
            unmap_keep(space, v.start, v.end);
        }
        self.vmas.retain(|v| v.kind != VmaKind::Shared);
        self.shared.clear();
    }

    /// munmap(addr, len): usuwa [addr, addr+len) z obszarów mmap (dzieli je),
    /// oddaje dociągnięte strony.  M18.e: obszar wspólny tylko w całości
    /// (zakres go obejmuje) – częściowo: EINVAL.
    pub fn munmap(&mut self, space: &mut AddressSpace, addr: u64, len: u64) -> Result<(), i64> {
        use super::syscalls::EINVAL;
        if addr % PAGE != 0 || len == 0 || addr < MMAP_BASE {
            return Err(EINVAL);
        }
        let end = addr.checked_add(page_up(len)).ok_or(EINVAL)?;
        let shared_hit = |v: &Vma| v.kind == VmaKind::Shared && v.end > addr && v.start < end;
        if self.vmas.iter().any(|v| shared_hit(v) && (v.start < addr || v.end > end)) {
            return Err(EINVAL);
        }
        for v in self.vmas.iter().filter(|v| shared_hit(v)) {
            unmap_keep(space, v.start, v.end);
            self.shared.retain(|(s, _)| *s != v.start);
        }
        self.vmas.retain(|v| !shared_hit(v));
        let mut out = Vec::with_capacity(self.vmas.len() + 1);
        for v in self.vmas.drain(..) {
            if v.kind != VmaKind::Mmap || v.end <= addr || v.start >= end {
                out.push(v);
                continue;
            }
            if v.start < addr {
                out.push(Vma { end: addr, ..v });
            }
            if v.end > end {
                out.push(Vma { start: end, ..v });
            }
            unmap_range(space, v.start.max(addr), v.end.min(end));
        }
        self.vmas = out;
        Ok(())
    }

    /// (obszary bez stosu w bajtach, strony dociągnięte) – testy.
    #[allow(dead_code)]
    pub fn stats(&self) -> (u64, u64) {
        (self.mapped_total(), self.faulted)
    }
}

/// M18.e: zdejmuje wpisy z [start, end) BEZ zwalniania ramek (należą do
/// obiektu pamięci współdzielonej).
fn unmap_keep(space: &mut AddressSpace, start: u64, end: u64) {
    let mut va = start;
    while va < end {
        if space.unmap(va).is_some() {
            unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags)) };
        }
        va += PAGE;
    }
}

/// Oddaje zamapowane strony z [start, end).
fn unmap_range(space: &mut AddressSpace, start: u64, end: u64) {
    let mut va = start;
    while va < end {
        if let Some(frame) = space.unmap(va) {
            unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags)) };
            crate::memory::free_frame(frame);
        }
        va += PAGE;
    }
}
