// 4-level paging, kernel in the higher half.
//
// Layout after `init()` (details in layout.rs):
//   * PML4[0..256)   -> EMPTY – the lower half is left for processes;
//                       as a side effect every null pointer is a #PF
//   * PML4[256..)    -> direct map: physical X at DIRECT_MAP_BASE + X,
//                       2 MiB pages (RAM + framebuffer)
//   * PML4[510]      -> recursive mapping (PML4 points to itself)
//   * PML4[511]      -> kernel image + stack, taken over from the DSB tables
//
// The direct map is needed because the frame allocator keeps its free list
// *inside the frames themselves*, page tables get zeroed, and DMA (virtio) and
// the framebuffer are seen by the CPU – all of it by physical address.

use crate::serial_println;

use super::layout::{phys_to_virt, DIRECT_MAP_MAX, KERNEL_PML4_FIRST, KERNEL_PML4_INDEX};
use super::{alloc_frame, free_frame, highest_physical_address, overlaps_conventional, overlaps_known_memory};

const PAGE_SIZE: u64 = 4096;
const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
const ENTRIES: usize = 512;

pub const PRESENT: u64 = 1 << 0;
pub const WRITABLE: u64 = 1 << 1;
/// Page accessible from ring 3 (must be set at every table level).
pub const USER: u64 = 1 << 2;
/// No-execute (works only with EFER.NXE – see `nx_flag`).
pub const NO_EXECUTE: u64 = 1 << 63;
const HUGE: u64 = 1 << 7;
// Memory type bits: PWT/PCD select a PAT entry (together with the PAT bit).
pub const WRITE_THROUGH: u64 = 1 << 3; // PWT
pub const CACHE_DISABLE: u64 = 1 << 4; // PCD

const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const HUGE_2M_MASK: u64 = 0x000f_ffff_ffe0_0000;
#[allow(dead_code)]
const HUGE_1G_MASK: u64 = 0x000f_ffff_c000_0000;

// PML4[510] -> PML4
const RECURSIVE_INDEX: usize = 510;

#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [u64; ENTRIES],
}

impl PageTable {
    /// Table at physical address `physical`, seen through the direct map
    /// (the DSB tables before `init`, our own after it).
    unsafe fn from_physical(physical: u64) -> &'static mut Self {
        unsafe { &mut *(phys_to_virt(physical) as *mut PageTable) }
    }

    fn try_allocate() -> Option<(u64, &'static mut Self)> {
        let frame = alloc_frame()?;
        let table = unsafe { Self::from_physical(frame) };
        unsafe {
            core::ptr::write_bytes(
                table as *mut PageTable as *mut u8,
                0,
                core::mem::size_of::<PageTable>(),
            );
        }
        Some((frame, table))
    }

    fn allocate() -> (u64, &'static mut Self) {
        Self::try_allocate().expect("paging: out of physical frames")
    }
}

fn index(virtual_address: u64, level: u8) -> usize {
    match level {
        4 => ((virtual_address >> 39) & 0x1ff) as usize,
        3 => ((virtual_address >> 30) & 0x1ff) as usize,
        2 => ((virtual_address >> 21) & 0x1ff) as usize,
        1 => ((virtual_address >> 12) & 0x1ff) as usize,
        _ => unreachable!(),
    }
}

fn is_canonical(virtual_address: u64) -> bool {
    let top = virtual_address >> 47;
    top == 0 || top == 0x1_ffff
}

fn flush_tlb(virtual_address: u64) {
    unsafe {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) virtual_address,
            options(nostack, preserves_flags)
        );
    }
}

// ------------------------------------------------------------
// BOOTSTRAP (before CR3 – new tables reachable through the DSB direct map)
// ------------------------------------------------------------

fn bootstrap_next_table(
    parent: &mut PageTable,
    entry_index: usize,
) -> &'static mut PageTable {
    if parent.entries[entry_index] & PRESENT == 0 {
        let (frame, _) = PageTable::allocate();
        parent.entries[entry_index] = frame | PRESENT | WRITABLE;
    }

    if parent.entries[entry_index] & HUGE != 0 {
        panic!("paging: bootstrap hit a huge page");
    }

    unsafe { PageTable::from_physical(parent.entries[entry_index] & ADDRESS_MASK) }
}

fn bootstrap_map_huge(pml4: &mut PageTable, va: u64, pa: u64, flags: u64) {
    let pdpt = bootstrap_next_table(pml4, index(va, 4));
    let pd = bootstrap_next_table(pdpt, index(va, 3));

    let i = index(va, 2);
    if pd.entries[i] & PRESENT != 0 {
        panic!("paging: bootstrap huge page already mapped");
    }
    pd.entries[i] = (pa & HUGE_2M_MASK) | flags | PRESENT | HUGE;
}

// ------------------------------------------------------------
// RECURSIVE MAPPING  (R = 510)
//
//   PML4        = [R][R][R][R]
//   PDPT(i)     = [R][R][R][i]
//   PD(i,j)     = [R][R][i][j]
//   PT(i,j,k)   = [R][i][j][k]
//
// Each index is 9 bits; the levels sit at bits 39, 30, 21, 12.
// ------------------------------------------------------------

const R: u64 = RECURSIVE_INDEX as u64;
const SIGN: u64 = 0xffff_0000_0000_0000;

const fn recursive_address(a: u64, b: u64, c: u64, d: u64) -> u64 {
    SIGN | (a << 39) | (b << 30) | (c << 21) | (d << 12)
}

fn table_at(address: u64) -> &'static mut PageTable {
    unsafe { &mut *(address as *mut PageTable) }
}

fn recursive_pml4() -> &'static mut PageTable {
    table_at(recursive_address(R, R, R, R))
}

fn recursive_pdpt(pml4_index: usize) -> &'static mut PageTable {
    table_at(recursive_address(R, R, R, pml4_index as u64))
}

fn recursive_pd(pml4_index: usize, pdpt_index: usize) -> &'static mut PageTable {
    table_at(recursive_address(R, R, pml4_index as u64, pdpt_index as u64))
}

fn recursive_pt(
    pml4_index: usize,
    pdpt_index: usize,
    pd_index: usize,
) -> &'static mut PageTable {
    table_at(recursive_address(
        R,
        pml4_index as u64,
        pdpt_index as u64,
        pd_index as u64,
    ))
}

/// Attaches a freshly allocated table to `entry` and invalidates the TLB for its
/// recursive address (`table_va`).
fn link_new_table(entry: &mut u64, table_va: u64, extra: u64) -> bool {
    let Some((frame, _)) = PageTable::try_allocate() else {
        return false;
    };
    *entry = frame | PRESENT | WRITABLE | extra;
    flush_tlb(table_va);
    true
}


fn table_is_empty(table: &PageTable) -> bool {
    table.entries.iter().all(|&e| e == 0)
}

// ------------------------------------------------------------
// PUBLIC API
// ------------------------------------------------------------

/// Maps a 4 KiB page.  `false` when: the address is unaligned / non-canonical,
/// the page is already mapped, the address lies inside a large page (2 MiB / 1 GiB)
/// or we ran out of frames for intermediate tables.
pub fn map_page(virtual_address: u64, physical_address: u64, flags: u64) -> bool {
    // Tasks can be preempted anywhere – page table changes are made
    // with interrupts disabled (single core).
    crate::arch::x86_64::interrupts::without_interrupts(|| {
        map_page_locked(virtual_address, physical_address, flags)
    })
}

fn map_page_locked(virtual_address: u64, physical_address: u64, flags: u64) -> bool {
    if virtual_address % PAGE_SIZE != 0 || physical_address % PAGE_SIZE != 0 {
        return false;
    }
    if !is_canonical(virtual_address) || physical_address & !ADDRESS_MASK != 0 {
        return false;
    }

    let (i4, i3, i2, i1) = (
        index(virtual_address, 4),
        index(virtual_address, 3),
        index(virtual_address, 2),
        index(virtual_address, 1),
    );

    // The recursive slot belongs to the kernel – pages must not be mapped there.
    if i4 == RECURSIVE_INDEX {
        return false;
    }

    // In the lower half (process address space) intermediate tables have
    // USER – the final entry decides the permissions anyway.
    let table_flags = if i4 < KERNEL_PML4_FIRST { USER } else { 0 };

    let pml4 = recursive_pml4();
    if pml4.entries[i4] & PRESENT == 0
        && !link_new_table(&mut pml4.entries[i4], recursive_address(R, R, R, i4 as u64), table_flags)
    {
        return false;
    }

    let pdpt = recursive_pdpt(i4);
    if pdpt.entries[i3] & PRESENT == 0
        && !link_new_table(
            &mut pdpt.entries[i3],
            recursive_address(R, R, i4 as u64, i3 as u64),
            table_flags,
        )
    {
        return false;
    }
    if pdpt.entries[i3] & HUGE != 0 {
        return false;
    }

    let pd = recursive_pd(i4, i3);
    if pd.entries[i2] & PRESENT == 0
        && !link_new_table(
            &mut pd.entries[i2],
            recursive_address(R, i4 as u64, i3 as u64, i2 as u64),
            table_flags,
        )
    {
        return false;
    }
    if pd.entries[i2] & HUGE != 0 {
        return false;
    }

    let pt = recursive_pt(i4, i3, i2);
    if pt.entries[i1] & PRESENT != 0 {
        return false;
    }

    pt.entries[i1] = (physical_address & ADDRESS_MASK) | flags | PRESENT;
    flush_tlb(virtual_address);
    true
}

/// Removes the mapping of a 4 KiB page and returns the physical address of the frame
/// (freeing the frame itself is the caller's business).  Empty intermediate tables
/// (PT, PD, PDPT) are freed and returned to the frame allocator.
///
/// In the higher half (kernel), after return NO CPU still holds
/// the stale TLB entry (shootdown), so the frame may be released right away.
pub fn unmap_page(virtual_address: u64) -> Option<u64> {
    let mut frame = None;
    unmap_range_with(virtual_address, virtual_address.saturating_add(PAGE_SIZE), |f| frame = Some(f));
    frame
}

/// Removes 4 KiB page mappings in [start, end) and returns their frames to
/// the allocator (task stacks, heap).  One shootdown per batch of up to 32 pages
/// instead of one per page.  Returns the number of pages unmapped.
pub fn unmap_range_free(start: u64, end: u64) -> usize {
    let mut n = 0;
    unmap_range_with(start, end, |f| {
        if !free_frame(f) {
            serial_println!("[MM] WARNING: could not free frame {:#x}", f);
        }
        n += 1;
    });
    n
}

/// Batch of pages per shootdown.
const UNMAP_CHUNK: usize = 32;

/// Common loop: clears the batch's PTEs, invalidates the TLB (locally or on
/// all CPUs), only then releases the tables and calls `done` with the frames.
/// Allocation-free (the heap also calls it while shrinking).
fn unmap_range_with(start: u64, end: u64, mut done: impl FnMut(u64)) {
    if start % PAGE_SIZE != 0 || end <= start {
        return;
    }
    crate::arch::x86_64::interrupts::without_interrupts(|| {
        let mut va = start;
        while va < end {
            let chunk_start = va;
            let mut frames = [0u64; UNMAP_CHUNK];
            let mut nf = 0;
            let mut tables = [0u64; 3 * UNMAP_CHUNK];
            let mut nt = 0;
            while va < end && nf < UNMAP_CHUNK {
                if let Some(f) = unmap_page_locked(va, &mut tables, &mut nt) {
                    frames[nf] = f;
                    nf += 1;
                }
                va += PAGE_SIZE;
            }
            if nf == 0 && nt == 0 {
                continue;
            }
            // Lower half = process address space loaded ONLY on this CPU
            // (single-threaded processes) – the local invlpg already happened.  The higher half
            // is shared: shootdown, and a full one when tables were freed
            // (recursive entries and the paging-structure caches).
            if index(chunk_start, 4) >= KERNEL_PML4_FIRST {
                if nt > 0 {
                    crate::arch::x86_64::tlb::flush_kernel_all();
                } else {
                    crate::arch::x86_64::tlb::flush_kernel(chunk_start, (va - chunk_start) / PAGE_SIZE);
                }
            }
            for &t in &tables[..nt] {
                if !free_frame(t) {
                    serial_println!("[MM] WARNING: could not free page table frame {:#x}", t);
                }
            }
            for &f in &frames[..nf] {
                done(f);
            }
        }
    })
}

/// Clears the entry and invalidates it locally; appends the table frame to `tables`
/// (released only after the shootdown).
fn release_table_deferred(entry: &mut u64, table_va: u64, tables: &mut [u64], nt: &mut usize) {
    let frame = *entry & ADDRESS_MASK;
    *entry = 0;
    flush_tlb(table_va);
    tables[*nt] = frame;
    *nt += 1;
}

fn unmap_page_locked(virtual_address: u64, tables: &mut [u64], nt: &mut usize) -> Option<u64> {
    if virtual_address % PAGE_SIZE != 0 || !is_canonical(virtual_address) {
        return None;
    }

    let (i4, i3, i2, i1) = (
        index(virtual_address, 4),
        index(virtual_address, 3),
        index(virtual_address, 2),
        index(virtual_address, 1),
    );

    if i4 == RECURSIVE_INDEX || recursive_pml4().entries[i4] & PRESENT == 0 {
        return None;
    }
    let pdpte = recursive_pdpt(i4).entries[i3];
    if pdpte & PRESENT == 0 || pdpte & HUGE != 0 {
        return None;
    }
    let pde = recursive_pd(i4, i3).entries[i2];
    if pde & PRESENT == 0 || pde & HUGE != 0 {
        return None;
    }

    let pt = recursive_pt(i4, i3, i2);
    let entry = pt.entries[i1];
    if entry & PRESENT == 0 {
        return None;
    }

    pt.entries[i1] = 0;
    flush_tlb(virtual_address);

    // Bottom-up cleanup: after a table is freed its recursive address
    // stops being valid, so `pt` / `pd` / `pdpt` are no longer used
    // after the corresponding release_table_deferred().  This also applies to the higher
    // half with multiple CPUs (kernel tables used to be kept forever, because
    // without a shootdown another CPU could hold a recursive entry of the old table).
    if table_is_empty(pt) {
        let pd = recursive_pd(i4, i3);
        release_table_deferred(
            &mut pd.entries[i2],
            recursive_address(R, i4 as u64, i3 as u64, i2 as u64),
            tables,
            nt,
        );

        if table_is_empty(pd) {
            let pdpt = recursive_pdpt(i4);
            release_table_deferred(
                &mut pdpt.entries[i3],
                recursive_address(R, R, i4 as u64, i3 as u64),
                tables,
                nt,
            );

            // Higher-half PML4 entries are never freed: they are shared by
            // all process address spaces – the copy in a process PML4
            // must point to a live table.
            if i4 < KERNEL_PML4_FIRST && table_is_empty(pdpt) {
                let pml4 = recursive_pml4();
                release_table_deferred(
                    &mut pml4.entries[i4],
                    recursive_address(R, R, R, i4 as u64),
                    tables,
                    nt,
                );
            }
        }

        // Also invalidate any cached paging-structure entries
        // for the address itself.
        flush_tlb(virtual_address);
    }

    Some(entry & ADDRESS_MASK)
}

/// Virtual -> physical (handles 4 KiB, 2 MiB and 1 GiB pages).
#[allow(dead_code)]
pub fn translate(virtual_address: u64) -> Option<u64> {
    if !is_canonical(virtual_address) {
        return None;
    }

    let (i4, i3, i2, i1) = (
        index(virtual_address, 4),
        index(virtual_address, 3),
        index(virtual_address, 2),
        index(virtual_address, 1),
    );

    if recursive_pml4().entries[i4] & PRESENT == 0 {
        return None;
    }

    let pdpte = recursive_pdpt(i4).entries[i3];
    if pdpte & PRESENT == 0 {
        return None;
    }
    if pdpte & HUGE != 0 {
        return Some((pdpte & HUGE_1G_MASK) + (virtual_address & 0x3fff_ffff));
    }

    let pde = recursive_pd(i4, i3).entries[i2];
    if pde & PRESENT == 0 {
        return None;
    }
    if pde & HUGE != 0 {
        return Some((pde & HUGE_2M_MASK) + (virtual_address & 0x1f_ffff));
    }

    let pte = recursive_pt(i4, i3, i2).entries[i1];
    if pte & PRESENT == 0 {
        return None;
    }
    Some((pte & ADDRESS_MASK) + (virtual_address & 0xfff))
}

// ------------------------------------------------------------
// INIT
// ------------------------------------------------------------

static KERNEL_CR3: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static NX_ENABLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Kernel CR3 (the PML4 from `init`) – used by kernel tasks.
pub fn kernel_cr3() -> u64 {
    KERNEL_CR3.load(core::sync::atomic::Ordering::Relaxed)
}

/// NO_EXECUTE if NX is enabled, otherwise 0 (bit 63 without EFER.NXE is a
/// reserved bit -> #PF).
pub fn nx_flag() -> u64 {
    if NX_ENABLED.load(core::sync::atomic::Ordering::Relaxed) { NO_EXECUTE } else { 0 }
}

/// Flags for ordinary kernel data (heap, stacks): write + NX.
pub fn kernel_data_flags() -> u64 {
    WRITABLE | nx_flag()
}

const IA32_EFER: u32 = 0xC000_0080;
const EFER_NXE: u64 = 1 << 11;

/// Enables EFER.NXE if the CPU has NX (CPUID 8000_0001h:EDX[20]).
fn enable_nx() -> u64 {
    #[allow(unused_unsafe)]
    let max = unsafe { core::arch::x86_64::__cpuid(0x8000_0000) }.eax;
    if max < 0x8000_0001 {
        return 0;
    }
    #[allow(unused_unsafe)]
    let edx = unsafe { core::arch::x86_64::__cpuid(0x8000_0001) }.edx;
    if edx & (1 << 20) == 0 {
        serial_println!("[MM] CPU without NX - pages stay executable");
        return 0;
    }
    unsafe { wrmsr(IA32_EFER, rdmsr(IA32_EFER) | EFER_NXE) };
    NX_ENABLED.store(true, core::sync::atomic::Ordering::Relaxed);
    serial_println!("[MM] NX enabled (EFER.NXE)");
    NO_EXECUTE
}

fn read_cr3() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// CR0.WP: the kernel cannot write to read-only pages either (kernel code and
/// rodata).  Without it the R/W bit only protects against ring 3.
fn enable_write_protect() {
    unsafe {
        core::arch::asm!(
            "mov {t}, cr0",
            "or {t}, {wp}",
            "mov cr0, {t}",
            t = out(reg) _,
            wp = const 1u64 << 16,
            options(nostack, preserves_flags)
        );
    }
}

pub fn init() {
    serial_println!("[MM] Initializing paging...");

    let highest = highest_physical_address();
    let limit = (highest + HUGE_PAGE_SIZE - 1) & !(HUGE_PAGE_SIZE - 1);
    if limit == 0 || limit > DIRECT_MAP_MAX {
        panic!("paging: unsupported physical memory size");
    }

    let (pml4_frame, pml4) = PageTable::allocate();
    serial_println!("[MM] PML4 frame = {:#x}", pml4_frame);

    // NX (EFER.NXE) – kernel data and the direct map are non-executable.
    let nx = enable_nx();
    let data_flags = WRITABLE | nx;

    // Direct map: RAM and reservations (framebuffer, ...) in 2 MiB pages.
    // Holes without memory (the PCI window) stay empty – map_mmio adds
    // device registers there as uncached 4 KiB pages.
    let mut address = 0;
    let mut huge_pages = 0;
    while address < limit {
        if overlaps_known_memory(address, address + HUGE_PAGE_SIZE) {
            bootstrap_map_huge(pml4, phys_to_virt(address), address, data_flags);
            huge_pages += 1;
        }
        address += HUGE_PAGE_SIZE;
    }
    serial_println!(
        "[MM] Direct map: phys 0..{:#x} at {:#x} ({} x 2 MiB, holes left unmapped)",
        limit,
        phys_to_virt(0),
        huge_pages
    );

    // Kernel image and stack: DSB mapped them in PML4[511] – we take over that
    // entry (the lower-level tables stay the same).
    let dsb_pml4 = unsafe { PageTable::from_physical(read_cr3() & ADDRESS_MASK) };
    let kernel_entry = dsb_pml4.entries[KERNEL_PML4_INDEX];
    if kernel_entry & PRESENT == 0 {
        panic!("paging: kernel is not mapped in PML4[511] (old loader?)");
    }
    pml4.entries[KERNEL_PML4_INDEX] = kernel_entry;
    let layout = super::kernel_layout();
    serial_println!(
        "[MM] Kernel: {:#x} -> phys {:#x} ({} KiB), stack top {:#x} ({} KiB + guard page)",
        layout.kernel_virt,
        layout.kernel_phys,
        layout.kernel_size / 1024,
        layout.stack_top,
        layout.stack_size / 1024
    );

    pml4.entries[RECURSIVE_INDEX] = pml4_frame | PRESENT | WRITABLE;
    serial_println!("[MM] Recursive slot = {}", RECURSIVE_INDEX);

    // All higher-half entries get a PDPT table right away.
    // Process address spaces copy PML4[256..512) – if the kernel added
    // a new entry later (e.g. the first task stack), processes would not
    // see it.  Cost: about 1 MiB for empty PDPTs.
    let mut added = 0;
    for i in KERNEL_PML4_FIRST..512 {
        if pml4.entries[i] & PRESENT == 0 {
            let (frame, _) = PageTable::allocate();
            pml4.entries[i] = frame | PRESENT | WRITABLE;
            added += 1;
        }
    }
    serial_println!("[MM] Kernel half: PML4[{}..512) pre-allocated (+{} PDPT)", KERNEL_PML4_FIRST, added);
    KERNEL_CR3.store(pml4_frame, core::sync::atomic::Ordering::Relaxed);
    serial_println!("[MM] Lower half empty (PML4[0..{}))", KERNEL_PML4_FIRST);

    serial_println!("[MM] Loading CR3...");
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) pml4_frame,
            options(nostack, preserves_flags)
        );
    }
    enable_write_protect();
    serial_println!("[MM] Paging initialized (CR0.WP on)");
}

// ------------------------------------------------------------
// Memory type – write-combining for the framebuffer (PAT)
// ------------------------------------------------------------
//
// PAT (MSR 0x277) has 8 entries; a page selects an entry with the PAT|PCD|PWT bits.
// Default: PA0=WB, PA1=WT, PA2=UC-, PA3=UC (repeated in PA4..7).
// We change PA1 from WT to WC – pages with only PWT=1 become
// write-combining.  Nothing else in the kernel uses PWT, so this is safe.
//
// WC: writes to the framebuffer are combined into bursts and do not pollute the cache.
// Ordinary (WB) memory for the framebuffer works in QEMU, but on real
// hardware it can produce artifacts and is slow.

const IA32_PAT: u32 = 0x277;
pub const PAT_WC: u64 = 0x01;

unsafe fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | lo as u64
}

unsafe fn wrmsr(msr: u32, value: u64) {
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nostack, preserves_flags)
        );
    }
}

pub fn pat_supported() -> bool {
    // CPUID.01h:EDX[16].  `__cpuid` is safe in newer Rust versions,
    // older ones require unsafe – allow, so that it works on both.
    #[allow(unused_unsafe)]
    let r = unsafe { core::arch::x86_64::__cpuid(1) };
    r.edx & (1 << 16) != 0
}

pub fn read_pat() -> u64 {
    unsafe { rdmsr(IA32_PAT) }
}

fn reload_cr3() {
    unsafe {
        core::arch::asm!("mov {t}, cr3", "mov cr3, {t}", t = out(reg) _, options(nostack, preserves_flags));
    }
}

static PAT_PROGRAMMED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Per-CPU paging setup on an AP – PAT (PA1 = WC,
/// as on the BSP; otherwise the framebuffer would have a different memory type on the AP) and CR0.WP.
/// EFER.NXE is already set by the trampoline.
pub fn init_ap_cpu() {
    if PAT_PROGRAMMED.load(core::sync::atomic::Ordering::Relaxed) {
        program_pat();
    }
    enable_write_protect();
}

/// Sets PA1 = WC (procedure from the Intel SDM: wbinvd before and after, TLB flush).
fn program_pat() {
    PAT_PROGRAMMED.store(true, core::sync::atomic::Ordering::Relaxed);
    crate::arch::x86_64::interrupts::without_interrupts(|| unsafe {
        let pat = (read_pat() & !(0xFF << 8)) | (PAT_WC << 8);
        core::arch::asm!("wbinvd", options(nostack, preserves_flags));
        wrmsr(IA32_PAT, pat);
        core::arch::asm!("wbinvd", options(nostack, preserves_flags));
        reload_cr3();
    });
}

/// PD entry of the direct-map 2 MiB page that contains the physical `address`.
fn direct_map_entry(address: u64) -> Option<&'static mut u64> {
    let va = phys_to_virt(address);
    let (i4, i3) = (index(va, 4), index(va, 3));
    if recursive_pml4().entries[i4] & PRESENT == 0 {
        return None;
    }
    let pdpt = recursive_pdpt(i4);
    if pdpt.entries[i3] & PRESENT == 0 || pdpt.entries[i3] & HUGE != 0 {
        return None;
    }
    let entry = &mut recursive_pd(i4, i3).entries[index(va, 2)];
    if *entry & (PRESENT | HUGE) != (PRESENT | HUGE) {
        return None;
    }
    Some(entry)
}

/// Flags of the entry that maps `virtual_address` (4 KiB, 2 MiB or
/// 1 GiB page; HUGE bit set for large pages).  For tests / diagnostics.
#[allow(dead_code)]
pub fn page_flags(virtual_address: u64) -> Option<u64> {
    if !is_canonical(virtual_address) {
        return None;
    }
    let (i4, i3, i2, i1) = (
        index(virtual_address, 4),
        index(virtual_address, 3),
        index(virtual_address, 2),
        index(virtual_address, 1),
    );
    let pml4e = recursive_pml4().entries[i4];
    if pml4e & PRESENT == 0 {
        return None;
    }
    let pdpte = recursive_pdpt(i4).entries[i3];
    if pdpte & PRESENT == 0 {
        return None;
    }
    if pdpte & HUGE != 0 {
        return Some(pdpte & !HUGE_1G_MASK);
    }
    let pde = recursive_pd(i4, i3).entries[i2];
    if pde & PRESENT == 0 {
        return None;
    }
    if pde & HUGE != 0 {
        return Some(pde & !HUGE_2M_MASK);
    }
    let pte = recursive_pt(i4, i3, i2).entries[i1];
    if pte & PRESENT == 0 {
        return None;
    }
    Some(pte & !ADDRESS_MASK)
}

/// Sets write-combining for a physical range in the direct map
/// (framebuffer).  Skips 2 MiB pages that overlap ordinary RAM.
/// Returns the number of pages changed.
pub fn map_write_combining(start: u64, size: u64) -> usize {
    if size == 0 || !pat_supported() {
        return 0;
    }
    if read_pat() & (0xFF << 8) != PAT_WC << 8 {
        program_pat();
    }

    let first = start & !(HUGE_PAGE_SIZE - 1);
    let end = start + size;
    let mut changed = 0;
    let mut page = first;
    while page < end {
        if overlaps_conventional(page, page + HUGE_PAGE_SIZE) {
            serial_println!("[MM] WARNING: 2 MiB page {:#x} overlaps RAM, left cacheable", page);
        } else if let Some(entry) = direct_map_entry(page) {
            *entry = (*entry & !CACHE_DISABLE) | WRITE_THROUGH;
            flush_tlb(phys_to_virt(page));
            changed += 1;
        }
        page += HUGE_PAGE_SIZE;
    }
    if changed > 0 {
        crate::arch::x86_64::tlb::flush_kernel_all(); // other CPUs too
    }
    changed
}

// ------------------------------------------------------------
// Device registers (MMIO) – uncached, in the direct map.
// ------------------------------------------------------------

/// Splits a direct-map 2 MiB page (the one containing the physical
/// `address`) into 512 4 KiB pages with the same flags.  The mapping does not
/// change – afterwards a single page can be given a different memory type.
/// `true` when the address is already mapped with 4 KiB pages or the split succeeded.
pub fn split_direct_map_huge(address: u64) -> bool {
    crate::arch::x86_64::interrupts::without_interrupts(|| {
        let base = address & !(HUGE_PAGE_SIZE - 1);
        let Some(entry) = direct_map_entry(base) else {
            // No large page: either already 4 KiB, or nothing is here.
            return translate(phys_to_virt(base)).is_some() || translate(phys_to_virt(address)).is_some();
        };
        let Some((frame, table)) = PageTable::try_allocate() else {
            return false;
        };
        // Large-page flags without HUGE (bit 12 = PAT of a large page – unused).
        let flags = *entry & !HUGE_2M_MASK & !HUGE & !(1 << 12);
        for (i, e) in table.entries.iter_mut().enumerate() {
            *e = (base + i as u64 * PAGE_SIZE) | flags;
        }
        // The PT inherits the intermediate permissions (higher half: no USER).
        *entry = frame | PRESENT | WRITABLE;
        reload_cr3();
        // Other CPUs may hold the large-page entry – full shootdown.
        crate::arch::x86_64::tlb::flush_kernel_all();
        true
    })
}

/// PT entry of the 4 KiB page at `virtual_address` (None: missing or a large page).
fn pte_mut(virtual_address: u64) -> Option<&'static mut u64> {
    let (i4, i3, i2, i1) = (
        index(virtual_address, 4),
        index(virtual_address, 3),
        index(virtual_address, 2),
        index(virtual_address, 1),
    );
    if recursive_pml4().entries[i4] & PRESENT == 0 {
        return None;
    }
    let pdpte = recursive_pdpt(i4).entries[i3];
    if pdpte & PRESENT == 0 || pdpte & HUGE != 0 {
        return None;
    }
    let pde = recursive_pd(i4, i3).entries[i2];
    if pde & PRESENT == 0 || pde & HUGE != 0 {
        return None;
    }
    let pte = &mut recursive_pt(i4, i3, i2).entries[i1];
    if *pte & PRESENT == 0 {
        return None;
    }
    Some(pte)
}

/// TLB self-test only: remaps an existing 4 KiB page to another
/// frame and invalidates the entry ONLY on this CPU (the test does the shootdown itself or
/// deliberately skips it).  Returns the previous frame.
#[cfg(selftest)]
pub fn retarget_page_local(virtual_address: u64, new_physical: u64) -> Option<u64> {
    crate::arch::x86_64::interrupts::without_interrupts(|| {
        let pte = pte_mut(virtual_address)?;
        let old = *pte & ADDRESS_MASK;
        *pte = (*pte & !ADDRESS_MASK) | (new_physical & ADDRESS_MASK);
        flush_tlb(virtual_address);
        Some(old)
    })
}

/// Maps a physical range of device registers in the direct map
/// (DIRECT_MAP_BASE + phys), using 4 KiB pages with PCD|PWT = UC (uncached).
/// Returns the virtual address of the first byte.
///
/// A range in a hole without RAM gets new 4 KiB pages; a range that
/// lies inside a direct-map 2 MiB page (e.g. together with RAM or another
/// reservation) first has that page split into 4 KiB pages – then ONLY the
/// register pages are uncached, the rest stays as it was.  The registers themselves
/// must not overlap ordinary RAM.
pub fn map_mmio(physical: u64, size: u64) -> Option<u64> {
    if size == 0 {
        return None;
    }
    let first = physical & !(PAGE_SIZE - 1);
    let end = physical.checked_add(size)?;
    if end > DIRECT_MAP_MAX {
        return None;
    }
    if overlaps_conventional(first, end) {
        serial_println!("[MM] map_mmio: {:#x}+{:#x} overlaps RAM - refused", physical, size);
        return None;
    }
    const UC: u64 = CACHE_DISABLE | WRITE_THROUGH;
    let ok = crate::arch::x86_64::interrupts::without_interrupts(|| {
        let mut page = first;
        while page < end {
            let va = phys_to_virt(page);
            if direct_map_entry(page).is_some() && !split_direct_map_huge(page) {
                return false;
            }
            match translate(va) {
                Some(p) if p == page => {
                    // A 4 KiB page already exists (after the split or from before) –
                    // only switch the memory type to UC.
                    let Some(pte) = pte_mut(va) else { return false };
                    if *pte & UC != UC {
                        *pte |= UC;
                        flush_tlb(va);
                        crate::arch::x86_64::tlb::flush_kernel(va, 1);
                    }
                }
                Some(_) => return false, // something else at this address
                None => {
                    if !map_page_locked(va, page, WRITABLE | UC | nx_flag()) {
                        return false;
                    }
                }
            }
            page += PAGE_SIZE;
        }
        true
    });
    if !ok {
        return None;
    }
    Some(phys_to_virt(physical))
}

/// Firmware tables (ACPI) in the direct map – read-only, cached.
/// Pages already mapped (RAM, reservations, earlier calls) stay
/// unchanged; missing ones get 4 KiB pages with no write or execute permission.
/// Returns the virtual address of `physical`.
pub fn map_firmware(physical: u64, size: u64) -> Option<u64> {
    if size == 0 {
        return None;
    }
    let first = physical & !(PAGE_SIZE - 1);
    let end = physical.checked_add(size)?;
    if end > DIRECT_MAP_MAX {
        return None;
    }
    let ok = crate::arch::x86_64::interrupts::without_interrupts(|| {
        let mut page = first;
        while page < end {
            let va = phys_to_virt(page);
            match translate(va) {
                Some(p) if p == page => {}
                Some(_) => return false,
                None => {
                    if !map_page_locked(va, page, nx_flag()) {
                        return false;
                    }
                }
            }
            page += PAGE_SIZE;
        }
        true
    });
    if ok { Some(phys_to_virt(physical)) } else { None }
}

// ------------------------------------------------------------
// TEST (only in builds with --cfg selftest)
// ------------------------------------------------------------

#[cfg(selftest)]
macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[MM TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

#[cfg(selftest)]
pub fn self_test() {
    use super::{free_frame, free_frame_count};

    serial_println!("[MM TEST] Starting paging tests...");
    crate::selftest::begin();

    // 1. Direct map + empty lower half.
    for address in [0u64, 0x1000, 0x20_0000, 0x20_1000, 0x40_0000, 0x1234_5678] {
        check!(
            translate(phys_to_virt(address)) == Some(address),
            "direct map {:#x} -> {:?}",
            address,
            translate(phys_to_virt(address))
        );
    }
    for address in [0u64, 0x123, 0x1000, 0x20_0000, 0x1234_5678] {
        check!(translate(address).is_none(), "lower half {:#x} is mapped", address);
    }
    check!(
        recursive_pml4().entries[..KERNEL_PML4_FIRST].iter().all(|&e| e == 0),
        "lower half of PML4 not empty"
    );
    check!(translate(0x0001_0000_0000_0000).is_none(), "non-canonical VA translated");
    serial_println!("[MM TEST] 1/7 direct map + empty lower half PASS");

    // 2. map / write / read / translate in a brand-new PML4/PDPT/PD.
    //    (pml4=1, pdpt=1, pd=1, pt=1 - catches bugs in computing the PD address)
    let va: u64 = 0x0000_0080_4020_1000;
    let free_start = free_frame_count();
    let frame = match alloc_frame() {
        Some(f) => f,
        None => {
            serial_println!("[MM TEST] FAIL: alloc_frame after paging");
            return;
        }
    };
    let free_before = free_frame_count();

    check!(!map_page(va + 1, frame, WRITABLE), "unaligned VA accepted");
    check!(!map_page(va, frame + 1, WRITABLE), "unaligned PA accepted");
    check!(!map_page(0x0001_0000_0000_0000, frame, WRITABLE), "non-canonical VA accepted");
    check!(map_page(va, frame, WRITABLE), "map_page returned false");
    check!(
        free_before - free_frame_count() == 3,
        "expected 3 new tables (PDPT+PD+PT), got {}",
        free_before - free_frame_count()
    );
    check!(translate(va) == Some(frame), "translate after map");
    check!(translate(va + 0x123) == Some(frame + 0x123), "translate with offset");

    unsafe {
        core::ptr::write_volatile(va as *mut u64, 0xDE5_0511_CAFE_F00D);
        check!(
            core::ptr::read_volatile(phys_to_virt(frame) as *const u64) == 0xDE5_0511_CAFE_F00D,
            "write through VA not visible at PA"
        );
        core::ptr::write_volatile(phys_to_virt(frame + 8) as *mut u64, 0x1122_3344_5566_7788);
        check!(
            core::ptr::read_volatile((va + 8) as *const u64) == 0x1122_3344_5566_7788,
            "write at PA not visible through VA"
        );
    }
    check!(!map_page(va, frame, WRITABLE), "double map accepted");
    serial_println!("[MM TEST] 2/7 map + read/write + translate PASS");

    // 3. A second page in the same PT needs no new tables.
    let frame2 = match alloc_frame() {
        Some(f) => f,
        None => {
            serial_println!("[MM TEST] FAIL: alloc_frame #2");
            return;
        }
    };
    let free_mid = free_frame_count();
    check!(map_page(va + PAGE_SIZE, frame2, WRITABLE), "map neighbour");
    check!(free_mid == free_frame_count(), "neighbour allocated extra tables");
    check!(translate(va + PAGE_SIZE) == Some(frame2), "translate neighbour");
    serial_println!("[MM TEST] 3/7 second page in same PT PASS");

    // 4. Mapping inside a large page must be rejected.
    let huge = phys_to_virt(0x20_0000);
    check!(!map_page(huge, frame, WRITABLE), "map inside 2 MiB page accepted");
    check!(unmap_page(huge).is_none(), "unmap inside 2 MiB page succeeded");
    serial_println!("[MM TEST] 4/7 huge-page guard PASS");

    // 5. unmap.
    check!(unmap_page(va) == Some(frame), "unmap returned wrong frame");
    check!(unmap_page(va + PAGE_SIZE) == Some(frame2), "unmap neighbour");
    check!(translate(va).is_none(), "still mapped after unmap");
    check!(unmap_page(va).is_none(), "double unmap succeeded");
    check!(free_frame(frame), "free_frame(frame)");
    check!(free_frame(frame2), "free_frame(frame2)");
    check!(
        free_frame_count() == free_start,
        "page tables leaked after unmap (start={}, now={})",
        free_start,
        free_frame_count()
    );
    check!(recursive_pml4().entries[1] == 0, "PML4[1] not cleared");
    serial_println!("[MM TEST] 5/7 unmap + free + tables released PASS");

    // 6. Selective table freeing + reuse after freeing.
    //    a and b: same PD, different PTs (2 MiB apart).
    let va_a: u64 = 0x0000_0100_8000_0000; // pml4=2 pdpt=2 pd=0
    let va_b: u64 = va_a + HUGE_PAGE_SIZE; // pml4=2 pdpt=2 pd=1
    let (fa, fb) = match (alloc_frame(), alloc_frame()) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            serial_println!("[MM TEST] FAIL: alloc_frame for test 6");
            return;
        }
    };
    let f0 = free_frame_count();

    check!(!map_page(recursive_address(R, 0, 0, 0), fa, WRITABLE), "recursive slot mappable");
    check!(map_page(va_a, fa, WRITABLE), "map a");
    check!(f0 - free_frame_count() == 3, "a: expected 3 tables");
    check!(map_page(va_b, fb, WRITABLE), "map b");
    check!(f0 - free_frame_count() == 4, "b: expected +1 table (PT)");

    check!(unmap_page(va_a) == Some(fa), "unmap a");
    check!(f0 - free_frame_count() == 3, "PT of a not released");
    check!(translate(va_b) == Some(fb), "b lost after unmapping a");
    check!(translate(va_a).is_none(), "a still mapped");

    check!(unmap_page(va_b) == Some(fb), "unmap b");
    check!(free_frame_count() == f0, "PT/PD/PDPT of b not released");
    check!(recursive_pml4().entries[2] == 0, "PML4[2] not cleared");

    // Tables are rebuilt correctly after freeing (no forgotten TLB entries).
    check!(map_page(va_a, fa, WRITABLE), "re-map a");
    unsafe {
        core::ptr::write_volatile(va_a as *mut u64, 0xABCD_EF01_2345_6789);
        check!(
            core::ptr::read_volatile(phys_to_virt(fa) as *const u64) == 0xABCD_EF01_2345_6789,
            "re-mapped page not backed by fa"
        );
    }
    check!(unmap_page(va_a) == Some(fa), "unmap a again");
    check!(free_frame_count() == f0, "tables leaked after re-map cycle");
    check!(free_frame(fa) && free_frame(fb), "free fa/fb");
    check!(translate(phys_to_virt(0x20_0000)) == Some(0x20_0000), "direct map damaged");
    serial_println!("[MM TEST] 6/7 selective table release + re-map PASS");

    // 7. Kernel in the higher half: code read-only, data writable,
    //    stack with a guard page.
    let layout = super::kernel_layout();
    let code = self_test as fn() as usize as u64;
    check!(code >= super::KERNEL_BASE, "kernel code at {:#x} (not higher half)", code);
    check!(
        translate(code) == super::layout::kernel_virt_to_phys(code),
        "kernel code {:#x} -> {:?}, expected {:?}",
        code,
        translate(code),
        super::layout::kernel_virt_to_phys(code)
    );
    let code_flags = page_flags(code).unwrap_or(0);
    check!(code_flags & PRESENT != 0 && code_flags & WRITABLE == 0, "kernel code writable ({:#x})", code_flags);
    static mut PROBE: u64 = 0;
    let data = core::ptr::addr_of!(PROBE) as u64;
    check!(page_flags(data).unwrap_or(0) & WRITABLE != 0, "kernel .bss not writable");
    let cr0: u64;
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
    }
    check!(cr0 & (1 << 16) != 0, "CR0.WP not set");
    let rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    check!(
        rsp > layout.stack_bottom() && rsp <= layout.stack_top,
        "RSP {:#x} outside kernel stack {:#x}..{:#x}",
        rsp,
        layout.stack_bottom(),
        layout.stack_top
    );
    check!(translate(layout.stack_bottom()) == Some(layout.stack_phys), "stack bottom not backed");
    check!(translate(layout.stack_top - 8).is_some(), "stack top not mapped");
    check!(translate(layout.guard_page()).is_none(), "guard page {:#x} is mapped", layout.guard_page());
    check!(super::is_stack_guard(layout.guard_page() + 0x10), "is_stack_guard");
    serial_println!(
        "[MM TEST] 7/7 higher-half kernel (code RO, WP on, stack + guard page) PASS"
    );

    serial_println!("[MM TEST] =================================");
    crate::selftest::pass();
    serial_println!("[MM TEST] PAGING TESTS PASSED");
    serial_println!("[MM TEST] =================================");
}
