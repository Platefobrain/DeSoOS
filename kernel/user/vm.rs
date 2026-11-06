// Process memory – areas (VMAs) with lazy page allocation.
//
//   [ELF image][brk: heap grows up ->]   ...   [mmap: from MMAP_BASE ->]
//   ...   [stack: down to STACK_MAX below USER_STACK_TOP; guard page beneath]
//
// * An area is just an address range with permissions – it gets pages only on
//   first access: a #PF from ring 3 (non-present page in the area) or
//   a kernel copy (copy_from_user / copy_to_user faults pages in
//   before checking permissions).  A new page is zeroed.
// * brk(addr) – end of the heap (0 = query); mmap(len, prot) – anonymous
//   area; munmap(addr, len) – only mmap areas, parts of them too.
// * Addresses for mmap: the next free gap from where the last area ended
//   (next fit, so a freed address does not come back at once); at the end of the
//   mmap range (MMAP_END, below the stack) the search starts again from MMAP_BASE
//   – freed ranges are reused, the range never runs out while the areas fit.
//   Every area has a free guard page above it.
// * prot: PROT_READ, PROT_READ | PROT_WRITE, or 0 (PROT_NONE – the range is reserved,
//   every access is a #PF; no page is ever mapped there).
// * Areas are kept sorted by address (lookup by binary search).
// * A process is single-threaded: areas and page tables are changed only by itself
//   (syscall, #PF), so no locks.  Freed pages: invlpg on this CPU
//   is enough – the address space is active only here (other CPUs reloaded CR3
//   on task switch).
// * Limits: the process's areas together (excluding the stack) at most MAX_MAPPED – this protects
//   the page tables; frames are only allocated on access anyway.  At most MAX_VMAS
//   areas – this protects the kernel heap (an area list entry per area); the list
//   grows with fallible allocation, so a full kernel heap is ERROR_OUT_OF_MEMORY too.
//   No frame on #PF = process terminated (#PF), during a copy – ERROR_INVALID_ADDRESS.

use alloc::vec::Vec;

use super::space::AddressSpace;
use super::{USER_STACK_SIZE, USER_STACK_TOP};
use crate::memory::{USER, WRITABLE};

const PAGE: u64 = 4096;
/// Start of mmap areas (16 TiB).
pub const MMAP_BASE: u64 = 0x0000_1000_0000_0000;
/// Maximum stack growth (8 MiB, including the guard page at the bottom).
pub const STACK_MAX: u64 = 8 * 1024 * 1024;
/// Heap (brk) at most this much.
pub const BRK_MAX: u64 = 1 << 30;
/// All heap and mmap areas together.
pub const MAX_MAPPED: u64 = 4 << 30;
/// Areas per process (heap, stack, mmap, shared): at most this many – 4096 × 24 B
/// = 96 KiB of kernel heap.  The library allocator maps only blocks over 2 KiB on
/// their own, the test programs use a few dozen.
pub const MAX_VMAS: usize = 4096;
/// End of the mmap range: the stack's lowest possible page (guard page included) is above.
pub const MMAP_END: u64 = USER_STACK_TOP - STACK_MAX;

/// How many pages to fault in at once (fault-around): heap and mmap – upwards from
/// the faulting page, stack – downwards.  Measurement (QEMU TCG, 1 CPU, stress 20 s, 3
/// runs each): 1 page – 553 scripts, 16 pages – 515 (zeroing 64 KiB on
/// every #PF, while processes under stress touch few pages: ~0.5 #PF per process),
/// the old 256 KiB heap in .bss – 541.  It stays at 1 (a knob for measurements).
pub const FAULT_AROUND: u64 = 1;

// Statistics (per CPU, no shared cache line): #PFs handled, pages
// faulted in by #PF and by kernel copies, brk / mmap calls.
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

/// (#PFs handled, pages from #PF, pages from copies, brk + mmap + munmap) – `cpus`.
pub fn stats() -> (u64, u64, u64, u64) {
    (sum(&PF_TRAPS), sum(&PF_PAGES), sum(&COPY_PAGES), sum(&MEM_CALLS))
}

/// Counter of brk / mmap / munmap calls (syscalls.rs).
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
    /// Shared memory – pages mapped right away, the frames belong
    /// to the object (ProcMem.shared) and are never freed by the process.
    /// The same goes for device registers (BAR) – physical device pages.
    Shared,
}

#[derive(Clone, Copy, Debug)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    /// false = PROT_NONE: no access at all (no page is mapped).
    pub readable: bool,
    pub writable: bool,
    pub kind: VmaKind,
}

/// Owner of a shared area's pages – held as long as the area is
/// mapped (a shared memory object or a device claim).
#[allow(dead_code)]
pub enum SharedRef {
    Shm(alloc::sync::Arc<super::shm::ShmObj>),
    Dev(alloc::sync::Arc<super::device::DevClaim>),
}

pub struct ProcMem {
    brk_start: u64,
    brk: u64,
    /// Where the search for the next mmap address starts.
    mmap_next: u64,
    /// Sorted by `start`, never overlapping.
    vmas: Vec<Vma>,
    /// Bytes of all areas except the stack (kept up to date, not summed on every call).
    mapped: u64,
    /// Shared memory mappings (area start, object) –
    /// they keep the object alive.
    shared: Vec<(u64, SharedRef)>,
    /// Pages faulted in lazily (statistics, tests).
    pub faulted: u64,
}

fn page_up(x: u64) -> u64 {
    (x + PAGE - 1) & !(PAGE - 1)
}

/// Length from a process rounded up to a page – `None` on overflow
/// (the kernel is built with overflow-checks: `page_up(u64::MAX)` = panic).
fn page_up_user(x: u64) -> Option<u64> {
    Some(x.checked_add(PAGE - 1)? & !(PAGE - 1))
}

impl ProcMem {
    /// Bytes of the heap (brk) and of the other areas (mmap, shared memory) – `counters`.
    pub fn footprint(&self) -> (u64, u64) {
        (self.brk - self.brk_start, self.mapped)
    }

    /// `image_end` – the first address past the program image (the heap starts
    /// one page further – guard page).
    pub fn new(image_end: u64) -> Self {
        let brk_start = page_up(image_end) + PAGE;
        let stack = Vma {
            start: USER_STACK_TOP - STACK_MAX + PAGE,
            end: USER_STACK_TOP - USER_STACK_SIZE,
            readable: true,
            writable: true,
            kind: VmaKind::Stack,
        };
        ProcMem { brk_start, brk: brk_start, mmap_next: MMAP_BASE, vmas: alloc::vec![stack], mapped: 0, shared: Vec::new(), faulted: 0 }
    }

    fn find(&self, va: u64) -> Option<&Vma> {
        let i = self.vmas.partition_point(|v| v.end <= va);
        self.vmas.get(i).filter(|v| va >= v.start)
    }

    fn mapped_total(&self) -> u64 {
        self.mapped
    }

    /// Adds an area in its place in the sorted list – ERROR_OUT_OF_MEMORY at MAX_VMAS
    /// areas or when the kernel heap has no room (nothing is changed then).
    fn insert(&mut self, v: Vma) -> Result<(), i64> {
        use super::syscalls::ERROR_OUT_OF_MEMORY;
        if self.vmas.len() >= MAX_VMAS || self.vmas.try_reserve(1).is_err() {
            return Err(ERROR_OUT_OF_MEMORY);
        }
        let i = self.vmas.partition_point(|o| o.start < v.start);
        self.vmas.insert(i, v);
        if v.kind != VmaKind::Stack {
            self.mapped += v.end - v.start;
        }
        Ok(())
    }

    /// The lowest address >= `from` where `len` bytes fit in the mmap range with a
    /// guard page above (and above the area below it).
    fn find_gap(&self, from: u64, len: u64) -> Option<u64> {
        let mut c = from;
        let fits = |c: u64, limit: u64| c.checked_add(len).and_then(|e| e.checked_add(PAGE)).map_or(false, |e| e <= limit);
        // The areas are sorted and do not overlap, so their ends are sorted too: skip the
        // ones entirely below `from` by binary search (with thousands of areas a linear
        // scan made every mmap O(n)).
        let first = self.vmas.partition_point(|v| v.end + PAGE <= from);
        for v in self.vmas[first..].iter().filter(|v| matches!(v.kind, VmaKind::Mmap | VmaKind::Shared)) {
            if v.end + PAGE <= c {
                continue;
            }
            if fits(c, v.start) {
                return Some(c);
            }
            c = c.max(v.end + PAGE);
        }
        fits(c, MMAP_END + PAGE).then_some(c)
    }

    /// Address for a new `len`-byte area: next fit, then from the start of the range.
    fn place(&self, len: u64) -> Option<u64> {
        self.find_gap(self.mmap_next, len).or_else(|| self.find_gap(MMAP_BASE, len))
    }

    /// Faults in the page at `va` if it lies in an area (and writing is
    /// allowed there); `true` = the page is now mapped by us.
    /// Together with it up to FAULT_AROUND neighbouring non-present pages of the area
    /// (`from_copy` – kernel copy, statistics only).
    pub fn fault_in(&mut self, space: &mut AddressSpace, va: u64, write: bool, from_copy: bool) -> bool {
        let Some(v) = self.find(va).copied() else { return false };
        // PROT_NONE: an access is an error, never a reason to map a page.
        if !v.readable || (write && !v.writable) {
            return false;
        }
        // Shared memory is mapped in full – a missing page there is an error
        // (we do not fault in a private page in place of a shared one).
        if v.kind == VmaKind::Shared {
            return false;
        }
        let page = va & !(PAGE - 1);
        if space.translate(page).is_some() {
            return false; // present – this is a permission violation, not a missing page
        }
        let flags = USER | if v.writable { WRITABLE } else { 0 } | crate::memory::nx_flag();
        if space.map_new(page, flags).is_none() {
            return false;
        }
        // Neighbours: the stack grows down, the rest up.  Out of memory – too bad,
        // the faulting page itself is already there.
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

    /// Whether the page lies in some area that may be accessed (for range checks).
    pub fn covers(&self, va: u64) -> bool {
        self.find(va).is_some_and(|v| v.readable)
    }

    /// brk(addr): new end of the heap (0 – query only).  On error
    /// returns the current end (like Linux).
    pub fn set_brk(&mut self, space: &mut AddressSpace, addr: u64) -> u64 {
        if addr == 0 || addr < self.brk_start || addr > self.brk_start + BRK_MAX {
            return self.brk;
        }
        let old_end = page_up(self.brk);
        let new_end = page_up(addr);
        if new_end > old_end && self.mapped_total() + (new_end - old_end) > MAX_MAPPED {
            return self.brk;
        }
        let heap = Vma { start: self.brk_start, end: new_end, readable: true, writable: true, kind: VmaKind::Heap };
        match self.vmas.iter_mut().find(|v| v.kind == VmaKind::Heap) {
            Some(v) if new_end > self.brk_start => {
                self.mapped = self.mapped - (v.end - v.start) + (new_end - self.brk_start);
                *v = heap;
            }
            Some(_) => {
                self.vmas.retain(|v| v.kind != VmaKind::Heap);
                self.mapped -= old_end - self.brk_start;
            }
            None if new_end > self.brk_start => {
                if self.insert(heap).is_err() {
                    return self.brk;
                }
            }
            None => {}
        }
        if new_end < old_end {
            unmap_range(space, new_end, old_end);
            if space.prune(new_end, old_end) > 0 {
                space.flush_if_active();
            }
        }
        self.brk = addr;
        addr
    }

    /// mmap(len, prot) – address of the new area or an error (-errno).
    pub fn mmap(&mut self, len: u64, prot: u64) -> Result<u64, i64> {
        use super::syscalls::{ERROR_INVALID_ARGUMENT, ERROR_OUT_OF_MEMORY};
        if len == 0 || prot & !(PROT_READ | PROT_WRITE) != 0 {
            return Err(ERROR_INVALID_ARGUMENT);
        }
        // Length from the process: limit first, then rounding (no overflows).
        if len > MAX_MAPPED {
            return Err(ERROR_OUT_OF_MEMORY);
        }
        let len = page_up(len);
        if self.mapped_total() + len > MAX_MAPPED {
            return Err(ERROR_OUT_OF_MEMORY);
        }
        if prot == PROT_WRITE {
            return Err(ERROR_INVALID_ARGUMENT); // writing implies reading on x86-64
        }
        // A gap page between areas – a buffer overflow hits a #PF.
        let start = self.place(len).ok_or(ERROR_OUT_OF_MEMORY)?;
        self.insert(Vma { start, end: start + len, readable: prot != 0, writable: prot & PROT_WRITE != 0, kind: VmaKind::Mmap })?;
        self.mmap_next = start + len + PAGE;
        Ok(start)
    }

    /// Maps a shared memory object (whole) – returns the area address.
    pub fn map_shared(
        &mut self,
        space: &mut AddressSpace,
        obj: alloc::sync::Arc<super::shm::ShmObj>,
        write: bool,
    ) -> Result<u64, i64> {
        let frames = obj.frames();
        let mut pages: Vec<Option<u64>> = Vec::new();
        if pages.try_reserve_exact(frames.len()).is_err() {
            return Err(super::syscalls::ERROR_OUT_OF_MEMORY);
        }
        pages.extend(frames.iter().map(|&f| Some(f)));
        self.map_pages(space, &pages, write, 0, SharedRef::Shm(obj))
    }

    /// Device registers (physical BAR pages) – uncached (UC),
    /// never executable; None = hole (MSI-X), access there = #PF.
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

    /// Shared area: pages mapped right away, `keep` holds their owner.
    fn map_pages(
        &mut self,
        space: &mut AddressSpace,
        pages: &[Option<u64>],
        write: bool,
        extra: u64,
        keep: SharedRef,
    ) -> Result<u64, i64> {
        use super::syscalls::ERROR_OUT_OF_MEMORY;
        let len = pages.len() as u64 * PAGE;
        if self.mapped_total() + len > MAX_MAPPED {
            return Err(ERROR_OUT_OF_MEMORY);
        }
        if self.vmas.len() >= MAX_VMAS {
            return Err(ERROR_OUT_OF_MEMORY);
        }
        let start = self.place(len).ok_or(ERROR_OUT_OF_MEMORY)?;
        let flags = USER | if write { WRITABLE } else { 0 } | crate::memory::nx_flag() | extra;
        for (i, page) in pages.iter().enumerate() {
            let Some(f) = *page else { continue };
            if !space.map(start + i as u64 * PAGE, f, flags) {
                unmap_keep(space, start, start + i as u64 * PAGE);
                return Err(ERROR_OUT_OF_MEMORY);
            }
        }
        let v = Vma { start, end: start + len, readable: true, writable: write, kind: VmaKind::Shared };
        if self.shared.try_reserve(1).is_err() || self.insert(v).is_err() {
            unmap_keep(space, start, start + len);
            return Err(ERROR_OUT_OF_MEMORY);
        }
        self.mmap_next = start + len + PAGE;
        self.shared.push((start, keep));
        Ok(start)
    }

    /// Removes all shared mappings (process exit – before
    /// the address space frees its pages; the objects' frames stay).
    pub fn release_shared(&mut self, space: &mut AddressSpace) {
        for v in self.vmas.iter().filter(|v| v.kind == VmaKind::Shared) {
            unmap_keep(space, v.start, v.end);
            self.mapped -= v.end - v.start;
        }
        self.vmas.retain(|v| v.kind != VmaKind::Shared);
        self.shared.clear();
    }

    /// munmap(addr, len): removes [addr, addr+len) from mmap areas (splitting them),
    /// releases faulted-in pages.  A shared area only as a whole
    /// (the range covers it) – partially: ERROR_INVALID_ARGUMENT.  Cutting a hole in
    /// the middle of an area makes two of them – at MAX_VMAS: ERROR_OUT_OF_MEMORY.
    pub fn munmap(&mut self, space: &mut AddressSpace, addr: u64, len: u64) -> Result<(), i64> {
        use super::syscalls::{ERROR_INVALID_ARGUMENT, ERROR_OUT_OF_MEMORY};
        if addr % PAGE != 0 || len == 0 || addr < MMAP_BASE {
            return Err(ERROR_INVALID_ARGUMENT);
        }
        let end = page_up_user(len).and_then(|l| addr.checked_add(l)).ok_or(ERROR_INVALID_ARGUMENT)?;
        let shared_hit = |v: &Vma| v.kind == VmaKind::Shared && v.end > addr && v.start < end;
        if self.vmas.iter().any(|v| shared_hit(v) && (v.start < addr || v.end > end)) {
            return Err(ERROR_INVALID_ARGUMENT);
        }
        // A hole inside one area: one area more (at most one – areas do not overlap).
        let splits = self.vmas.iter().any(|v| v.kind == VmaKind::Mmap && v.start < addr && v.end > end);
        let mut out = Vec::new();
        if (splits && self.vmas.len() >= MAX_VMAS) || out.try_reserve(self.vmas.len() + 1).is_err() {
            return Err(ERROR_OUT_OF_MEMORY);
        }
        for v in self.vmas.iter().filter(|v| shared_hit(v)) {
            unmap_keep(space, v.start, v.end);
            self.mapped -= v.end - v.start;
            self.shared.retain(|(s, _)| *s != v.start);
        }
        self.vmas.retain(|v| !shared_hit(v));
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
            let (a, b) = (v.start.max(addr), v.end.min(end));
            unmap_range(space, a, b);
            self.mapped -= b - a;
        }
        self.vmas = out;
        // Tables left without any entry go too (a later access maps them again).
        if space.prune(addr, end) > 0 {
            space.flush_if_active();
        }
        Ok(())
    }

    /// (areas excluding the stack in bytes, pages faulted in, number of areas) – tests.
    #[allow(dead_code)]
    pub fn stats(&self) -> (u64, u64, usize) {
        (self.mapped_total(), self.faulted, self.vmas.len())
    }

}

/// Removes entries in [start, end) WITHOUT freeing the frames (they belong to
/// a shared memory object).
fn unmap_keep(space: &mut AddressSpace, start: u64, end: u64) {
    let mut va = start;
    while va < end {
        let skip = space.hole_end(va);
        if skip > va {
            va = skip;
            continue;
        }
        if space.unmap(va).is_some() {
            unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags)) };
        }
        va += PAGE;
    }
}

/// Releases the mapped pages in [start, end).
fn unmap_range(space: &mut AddressSpace, start: u64, end: u64) {
    let mut va = start;
    while va < end {
        // Untouched stretches (no page table) are skipped whole: munmap of a large,
        // mostly untouched area does not walk every page.
        let skip = space.hole_end(va);
        if skip > va {
            va = skip;
            continue;
        }
        if let Some(frame) = space.unmap(va) {
            unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags)) };
            crate::memory::free_frame(frame);
        }
        va += PAGE;
    }
}
