// Physical frame allocator (4 KiB).
//
// A bitmap instead of a free list stored in the frames themselves.
//   * 1 bit per frame from address 0 to the end of the highest RAM (1 = free);
//     512 MiB RAM -> 16 KiB bitmap, 64 GiB -> 2 MiB.  The bitmap lives in RAM
//     (the first suitable chunk of conventional memory, reserved) and is
//     accessed through the direct map.
//   * free_frame: the double-free check is one bit – O(1) (instead of
//     walking the whole list).
//   * alloc_frame: searches from a hint, one 64-bit word at a time.
//   * alloc_frames(n, align): n CONTIGUOUS frames (DMA buffers).
//   * Free frames are not written to – their contents are never touched.
//
// A per-CPU reserve of free frames (like the heap's per-CPU lists).
// Under SMP stress the `frames` lock saw tens of millions of waits per minute,
// 4–6% CPU (every process takes dozens of frames: image, stack, page tables).
//   * alloc_frame / free_frame: pop from / push onto this CPU's frame array
//     with IF = 0, without the lock; empty = a batch of FCACHE_BATCH frames from under
//     the lock, full = a batch goes back.  Frames in the reserves count as free
//     (free_frame_count), but are marked used in the bitmap.
//   * Protection against double-free and freeing someone else's / a reserved frame
//     without the lock: a second "issued" bitmap (atomic, 1 = frame is with its owner).
//     free_frame clears this bit first (fetch_and) – if it was not set, the
//     free is refused.  Every path that hands out a frame sets it.
//   * Contiguous ranges (DMA, alloc_frames*, alloc_frame_below) – still
//     taken under the lock.

use crate::bootinfo::BootInfo;
use crate::serial_println;
use core::ptr;

use super::layout::{kernel_layout, phys_to_virt, DIRECT_MAP_BASE};

const PAGE_SIZE: u64 = 4096;
const EFI_CONVENTIONAL_MEMORY: u32 = 7;

// Page 0 is never handed out (address 0 = "no frame").
const NULL_PAGE_END: u64 = PAGE_SIZE;
const LOW_MEMORY_END: u64 = 0x10_0000;

const MAX_RESERVATIONS: usize = 16;
const BITS: u64 = 64;
const MAX_CONVENTIONAL_RANGES: usize = 128;

#[derive(Clone, Copy)]
struct Range {
    start: u64,
    end: u64, // exclusive
}

struct FrameAllocator {
    /// Bitmap (1 = free) in the direct map, `words` 64-bit words.
    bitmap: *mut u64,
    words: usize,
    /// Number of frames described by the bitmap (frames 0..frames).
    frames: u64,
    bitmap_phys: u64,
    /// Word at which alloc_frame starts searching.
    hint: usize,
    free_frames: u64,

    // Original UEFI conventional-memory ranges.  Keeping these lets
    // free_frame() reject arbitrary physical addresses instead of blindly
    // writing through them.
    conventional: [Range; MAX_CONVENTIONAL_RANGES],
    conventional_len: usize,

    // Memory which must never be returned by the allocator.
    reservations: [Range; MAX_RESERVATIONS],
    reservations_len: usize,
}

// Its own lock (FRAMES level) instead of just without_interrupts +
// the Big Kernel Lock – frames can be taken and freed on many CPUs at once, also
// from code without the BKL and from interrupt handlers.
static ALLOCATOR: crate::sched::spin::IrqSpinLock<Option<FrameAllocator>> =
    crate::sched::spin::IrqSpinLock::new("frames", crate::sched::spin::level::FRAMES, None);

fn align_down(addr: u64) -> u64 {
    addr & !(PAGE_SIZE - 1)
}

fn align_up(addr: u64) -> u64 {
    // Saturating arithmetic avoids wrapping at the top of the physical
    // address space.
    addr.saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && a_end > b_start
}

fn push_range(list: &mut [Range], len: &mut usize, start: u64, end: u64) -> bool {
    if end <= start {
        return true;
    }
    if *len >= list.len() {
        return false;
    }
    list[*len] = Range { start, end };
    *len += 1;
    true
}

fn push_reservation(list: &mut [Range], len: &mut usize, start: u64, end: u64) {
    if end <= start {
        return;
    }
    if !push_range(list, len, start, end) {
        serial_println!(
            "[MM] WARNING: reservation table full, dropping {:#x}-{:#x}",
            start,
            end
        );
    }
}

fn reserved(reservations: &[Range], len: usize, frame: u64) -> bool {
    let frame_end = frame.saturating_add(PAGE_SIZE);
    for i in 0..len {
        let r = reservations[i];
        if ranges_overlap(frame, frame_end, r.start, r.end) {
            return true;
        }
    }
    false
}

fn in_ranges(ranges: &[Range], len: usize, frame: u64) -> bool {
    let frame_end = frame.saturating_add(PAGE_SIZE);
    for i in 0..len {
        let r = ranges[i];
        if frame >= r.start && frame_end <= r.end {
            return true;
        }
    }
    false
}

// UEFI memory descriptor: type u32 @0, physical_start u64 @8, page_count u64 @24
// `base` is the virtual address of the map (direct map).
unsafe fn descriptor(base: usize, index: usize, desc_size: usize) -> (u32, u64, u64) {
    let d = (base + index * desc_size) as *const u8;
    unsafe {
        let ty = ptr::read_unaligned(d as *const u32);
        let phys = ptr::read_unaligned(d.add(8) as *const u64);
        let pages = ptr::read_unaligned(d.add(24) as *const u64);
        (ty, phys, pages)
    }
}

fn build_reservations(boot: &BootInfo) -> ([Range; MAX_RESERVATIONS], usize) {
    let mut list = [Range { start: 0, end: 0 }; MAX_RESERVATIONS];
    let mut len = 0;

    // Keep the null page out of the allocator because 0 is the free-list
    // sentinel. This also avoids ever handing out the first physical page.
    push_reservation(&mut list, &mut len, 0, NULL_PAGE_END);

// Kernel image and boot stack (the bootloader allocates them as LOADER_DATA,
// so they are not "conventional" anyway – the reservation is a second line of defense).
    let layout = kernel_layout();
    push_reservation(
        &mut list,
        &mut len,
        align_down(layout.kernel_phys),
        align_up(layout.kernel_phys.saturating_add(layout.kernel_size)),
    );
    push_reservation(
        &mut list,
        &mut len,
        align_down(layout.stack_phys),
        align_up(layout.stack_phys.saturating_add(layout.stack_size)),
    );

    let boot_ptr = bootinfo_phys(boot);
    push_reservation(
        &mut list,
        &mut len,
        align_down(boot_ptr),
        align_up(boot_ptr.saturating_add(core::mem::size_of::<BootInfo>() as u64)),
    );

    if boot.memory_map_addr != 0 && boot.memory_map_size != 0 {
        let map_start = align_down(boot.memory_map_addr);
        let map_end = align_up(boot.memory_map_addr.saturating_add(boot.memory_map_size));
        push_reservation(&mut list, &mut len, map_start, map_end);
    }

    if boot.framebuffer_addr != 0 && boot.framebuffer_size != 0 {
        let fb_start = align_down(boot.framebuffer_addr);
        let fb_end = align_up(boot.framebuffer_addr.saturating_add(boot.framebuffer_size));
        push_reservation(&mut list, &mut len, fb_start, fb_end);
    }

    (list, len)
}

fn collect_conventional_ranges(
    boot: &BootInfo,
) -> ([Range; MAX_CONVENTIONAL_RANGES], usize, u64) {
    let mut ranges = [Range { start: 0, end: 0 }; MAX_CONVENTIONAL_RANGES];
    let mut len = 0;
    let mut conventional_bytes = 0u64;

    let base = phys_to_virt(boot.memory_map_addr) as usize;
    let desc_size = boot.memory_map_desc_size as usize;
    if boot.memory_map_addr == 0 || desc_size < 40 || boot.memory_map_size == 0 {
        return (ranges, 0, 0);
    }

    let count = boot.memory_map_size as usize / desc_size;
    for i in 0..count {
        let (ty, phys, pages) = unsafe { descriptor(base, i, desc_size) };
        if ty != EFI_CONVENTIONAL_MEMORY || pages == 0 {
            continue;
        }

        conventional_bytes = conventional_bytes.saturating_add(
            pages.saturating_mul(PAGE_SIZE),
        );

        let start = align_up(phys);
        let end = align_down(phys.saturating_add(pages.saturating_mul(PAGE_SIZE)));
        if end <= start {
            continue;
        }

        if !push_range(&mut ranges, &mut len, start, end) {
            serial_println!(
                "[MM] ERROR: conventional range table full, dropping {:#x}-{:#x}",
                start,
                end
            );
        }
    }

    (ranges, len, conventional_bytes)
}

/// Place for the bitmap: the first piece of conventional memory that does not
/// overlap the reservations.
fn find_bitmap_place(
    conventional: &[Range],
    conventional_len: usize,
    reservations: &[Range],
    reservations_len: usize,
    bytes: u64,
) -> Option<u64> {
    let size = align_up(bytes);
    for i in 0..conventional_len {
        let r = conventional[i];
        // Above 1 MiB – low memory is needed for the SMP trampoline.
        let mut start = align_up(r.start.max(LOW_MEMORY_END));
        while start.saturating_add(size) <= r.end {
            let end = start + size;
            let mut conflict = None;
            for j in 0..reservations_len {
                let res = reservations[j];
                if ranges_overlap(start, end, res.start, res.end) {
                    conflict = Some(res.end);
                    break;
                }
            }
            match conflict {
                None => return Some(start),
                Some(next) => start = align_up(next),
            }
        }
    }
    None
}

// Bitmap in the direct map (raw pointer) – protected by the ALLOCATOR lock.
unsafe impl Send for FrameAllocator {}

impl FrameAllocator {
    fn word(&self, i: usize) -> &mut u64 {
        debug_assert!(i < self.words);
        unsafe { &mut *self.bitmap.add(i) }
    }

    fn is_free(&self, frame_index: u64) -> bool {
        *self.word((frame_index / BITS) as usize) & (1 << (frame_index % BITS)) != 0
    }

    fn set_free(&mut self, frame_index: u64, free: bool) {
        let w = self.word((frame_index / BITS) as usize);
        let bit = 1u64 << (frame_index % BITS);
        if free {
            *w |= bit;
        } else {
            *w &= !bit;
        }
    }

    /// Whether the frame may be returned to the allocator (RAM, not reserved, in the bitmap).
    fn valid_frame(&self, frame: u64) -> bool {
        frame != 0
            && frame % PAGE_SIZE == 0
            && frame / PAGE_SIZE < self.frames
            && in_ranges(&self.conventional, self.conventional_len, frame)
            && !reserved(&self.reservations, self.reservations_len, frame)
    }

    fn alloc_one(&mut self) -> Option<u64> {
        if self.free_frames == 0 {
            return None;
        }
        for n in 0..self.words {
            let i = (self.hint + n) % self.words;
            let w = *self.word(i);
            if w != 0 {
                let bit = w.trailing_zeros() as u64;
                let index = i as u64 * BITS + bit;
                self.set_free(index, false);
                self.free_frames -= 1;
                self.hint = i;
                return Some(index * PAGE_SIZE);
            }
        }
        None
    }

    /// Lowest free frame below address `limit`.
    fn alloc_below(&mut self, limit: u64) -> Option<u64> {
        let last = (limit / PAGE_SIZE).min(self.frames);
        let mut f = 1;
        while f < last {
            if *self.word((f / BITS) as usize) == 0 {
                f = (f / BITS + 1) * BITS;
                continue;
            }
            if self.is_free(f) {
                self.set_free(f, false);
                self.free_frames -= 1;
                return Some(f * PAGE_SIZE);
            }
            f += 1;
        }
        None
    }

    /// `count` contiguous free frames, the first one aligned to `align` frames.
    fn alloc_run(&mut self, count: u64, align: u64) -> Option<u64> {
        self.alloc_run_below(count, align, self.frames)
    }

    /// Like alloc_run, but the whole range below frame `end` (DMA buffers of
    /// devices with a narrower address bus – e.g. `edu`: 28 bits).
    fn alloc_run_below(&mut self, count: u64, align: u64, end: u64) -> Option<u64> {
        if count == 0 || count > self.free_frames || align == 0 || !align.is_power_of_two() {
            return None;
        }
        let end = end.min(self.frames);
        let mut start = align;
        while start + count <= end {
            // Fast skip over completely used words.
            if *self.word((start / BITS) as usize) == 0 {
                start = ((start / BITS + 1) * BITS).next_multiple_of(align);
                continue;
            }
            match (start..start + count).find(|&f| !self.is_free(f)) {
                None => {
                    for f in start..start + count {
                        self.set_free(f, false);
                    }
                    self.free_frames -= count;
                    return Some(start * PAGE_SIZE);
                }
                Some(busy) => start = (busy + 1).next_multiple_of(align),
            }
        }
        None
    }
}

/// Physical address of BootInfo (the bootloader passes a pointer from the direct map).
fn bootinfo_phys(boot: &BootInfo) -> u64 {
    (boot as *const BootInfo as u64).wrapping_sub(DIRECT_MAP_BASE)
}

fn log_reservation(label: &str, start: u64, end: u64) {
    serial_println!("[MM] Reserved {}: {:#x}-{:#x}", label, start, end);
}

pub fn init(boot: &BootInfo) {
    serial_println!("[MM] Initializing frame allocator...");

    let (reservations, reservations_len) = build_reservations(boot);
    log_reservation("null page", 0, NULL_PAGE_END);
    let layout = kernel_layout();
    log_reservation("kernel", layout.kernel_phys, layout.kernel_phys + layout.kernel_size);
    log_reservation("kernel stack", layout.stack_phys, layout.stack_phys + layout.stack_size);

    let boot_ptr = bootinfo_phys(boot);
    log_reservation(
        "BootInfo",
        align_down(boot_ptr),
        align_up(boot_ptr.saturating_add(core::mem::size_of::<BootInfo>() as u64)),
    );

    if boot.memory_map_addr != 0 && boot.memory_map_size != 0 {
        log_reservation(
            "memory map",
            align_down(boot.memory_map_addr),
            align_up(boot.memory_map_addr.saturating_add(boot.memory_map_size)),
        );
    }

    if boot.framebuffer_addr != 0 && boot.framebuffer_size != 0 {
        log_reservation(
            "framebuffer",
            align_down(boot.framebuffer_addr),
            align_up(boot.framebuffer_addr.saturating_add(boot.framebuffer_size)),
        );
    }

    let (conventional, conventional_len, conventional_bytes) =
        collect_conventional_ranges(boot);

    // Bitmap: frames 0..end of the highest RAM range.
    let mut ram_end = 0;
    for i in 0..conventional_len {
        ram_end = ram_end.max(conventional[i].end);
    }
    let frames = ram_end / PAGE_SIZE;
    let words = frames.div_ceil(BITS) as usize;
    // Two bitmaps back to back – free (pool) and issued (atomic).
    let bitmap_bytes = (words * 8 * 2) as u64;

    let mut reservations = reservations;
    let mut reservations_len = reservations_len;
    let Some(bitmap_phys) = find_bitmap_place(
        &conventional,
        conventional_len,
        &reservations,
        reservations_len,
        bitmap_bytes,
    ) else {
        panic!("frame allocator: no room for the {} KiB bitmap", bitmap_bytes / 1024);
    };
    push_reservation(
        &mut reservations,
        &mut reservations_len,
        bitmap_phys,
        bitmap_phys + align_up(bitmap_bytes),
    );
    log_reservation("frame bitmap", bitmap_phys, bitmap_phys + align_up(bitmap_bytes));

    let bitmap = phys_to_virt(bitmap_phys) as *mut u64;
    unsafe { ptr::write_bytes(bitmap, 0, words * 2) };
    ISSUED.store(unsafe { bitmap.add(words) } as *mut core::sync::atomic::AtomicU64, core::sync::atomic::Ordering::SeqCst);
    NFRAMES.store(frames, core::sync::atomic::Ordering::SeqCst);

    let mut alloc = FrameAllocator {
        bitmap,
        words,
        frames,
        bitmap_phys,
        hint: 0,
        free_frames: 0,
        conventional,
        conventional_len,
        reservations,
        reservations_len,
    };
    for i in 0..conventional_len {
        let r = conventional[i];
        let mut frame = r.start;
        while frame + PAGE_SIZE <= r.end {
            if alloc.valid_frame(frame) {
                alloc.set_free(frame / PAGE_SIZE, true);
                alloc.free_frames += 1;
            }
            frame += PAGE_SIZE;
        }
    }

    let conventional_mib = conventional_bytes / (1024 * 1024);
    serial_println!("[MM] Conventional memory: {} MiB", conventional_mib);
    serial_println!(
        "[MM] Free frames: {} (bitmap {} KiB for {} frames)",
        alloc.free_frames,
        bitmap_bytes.div_ceil(1024),
        frames
    );

    // A frame below 1 MiB for the AP startup trampoline (after SIPI the processor
    // starts in real mode) – reserved right away, before regular
    // allocations take the low memory.
    let tramp = alloc.alloc_below(0x10_0000);
    if let Some(t) = tramp {
        mark_issued(t);
    }
    match tramp {
        Some(t) => serial_println!("[MM] Reserved AP trampoline frame: {:#x}", t),
        None => serial_println!("[MM] No free frame below 1 MiB - only one CPU will be used"),
    }
    TRAMPOLINE.store(tramp.unwrap_or(0), core::sync::atomic::Ordering::SeqCst);

    FREE_MIRROR.store(alloc.free_frames, core::sync::atomic::Ordering::Relaxed);
    *ALLOCATOR.lock() = Some(alloc);
}

static TRAMPOLINE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Reserved AP trampoline frame (< 1 MiB); None – none.
pub fn trampoline_frame() -> Option<u64> {
    match TRAMPOLINE.load(core::sync::atomic::Ordering::Relaxed) {
        0 => None,
        t => Some(t),
    }
}

/// A frame below `limit` (e.g. page tables for 32-bit CR3 mode).
pub fn alloc_frame_below(limit: u64) -> Option<u64> {
    let f = unsafe { with_allocator(|alloc| alloc.alloc_below(limit))? }?;
    mark_issued(f);
    Some(f)
}

// Interrupts are disabled for the duration of the operation – an IRQ handler must not
// see the bitmap half-modified.  IrqSpinLock also covers other CPUs.
unsafe fn with_allocator<R>(f: impl FnOnce(&mut FrameAllocator) -> R) -> Option<R> {
    let mut slot = ALLOCATOR.lock();
    let alloc = slot.as_mut()?;
    let r = f(alloc);
    FREE_MIRROR.store(alloc.free_frames, core::sync::atomic::Ordering::Relaxed);
    Some(r)
}

// ------------------------------------------------------------
// Kernel-only memory reserve
// ------------------------------------------------------------

/// Copy of `free_frames` from the bitmap, read without the lock (approximate – for
/// checking the reserve on every process #PF without touching the lock).
static FREE_MIRROR: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// How many times a process was refused a frame (kernel reserve).
static USER_DENIED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Free frames without the lock (bitmap + CPU reserves), approximate.
pub fn free_frames_approx() -> u64 {
    use core::sync::atomic::Ordering::Relaxed;
    FREE_MIRROR.load(Relaxed) + FCACHED.iter().map(|c| c.load(Relaxed)).sum::<u64>()
}

/// Reserve of frames that processes will not get: 1/16 of memory, 16..256 MiB.
/// The kernel lives off it (heap, task stacks, tables) – a process eating memory
/// gets an error or dies, while the kernel keeps running.
pub fn user_reserve_frames() -> u64 {
    (NFRAMES.load(core::sync::atomic::Ordering::Relaxed) / 16).clamp(4096, 65536)
}

/// A frame for a process (pages, page tables, shared memory) – only
/// above the kernel reserve.
pub fn alloc_frame_user() -> Option<u64> {
    if free_frames_approx() < user_reserve_frames() {
        USER_DENIED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        return None;
    }
    alloc_frame()
}

/// (reserve in frames, refusals).
pub fn user_reserve_stats() -> (u64, u64) {
    (user_reserve_frames(), USER_DENIED.load(core::sync::atomic::Ordering::Relaxed))
}

pub fn alloc_frame() -> Option<u64> {
    let f = if FCACHE_ON.load(core::sync::atomic::Ordering::Relaxed) {
        cached_alloc()
    } else {
        unsafe { with_allocator(|alloc| alloc.alloc_one())? }
    }?;
    mark_issued(f);
    Some(f)
}

/// `count` contiguous frames (e.g. a DMA buffer), the first aligned to
/// `align` frames (power of two; 1 = no requirement).  Returns the address of the first.
#[allow(dead_code)]
pub fn alloc_frames(count: usize, align: usize) -> Option<u64> {
    let f = unsafe { with_allocator(|alloc| alloc.alloc_run(count as u64, align as u64))? }?;
    mark_issued_run(f, count as u64);
    Some(f)
}

// Returns true only when `frame` was a valid, currently allocated frame.
// Invalid addresses and double-frees are rejected (one bit test - O(1)).
pub fn free_frame(frame: u64) -> bool {
    // Only a frame issued by the allocator ("issued" bit) – otherwise refused:
    // double-free, address outside RAM, reservation, frame in someone's reserve.
    if !take_issued(frame) {
        return false;
    }
    if FCACHE_ON.load(core::sync::atomic::Ordering::Relaxed) {
        cached_free(frame);
        return true;
    }
    let ok = unsafe {
        with_allocator(|alloc| {
            if !alloc.valid_frame(frame) || alloc.is_free(frame / PAGE_SIZE) {
                return false;
            }
            alloc.set_free(frame / PAGE_SIZE, true);
            alloc.free_frames += 1;
            true
        })
        .unwrap_or(false)
    };
    if !ok {
        mark_issued(frame); // inconsistency – do not lose the state
    }
    ok
}

/// `count` contiguous frames lying entirely below address `limit`.
pub fn alloc_frames_below(count: usize, align: usize, limit: u64) -> Option<u64> {
    let f = unsafe { with_allocator(|alloc| alloc.alloc_run_below(count as u64, align as u64, limit / PAGE_SIZE))? }?;
    mark_issued_run(f, count as u64);
    Some(f)
}

/// Frees `count` contiguous frames starting at `first`.  All or nothing: if
/// any frame is invalid or already free, nothing changes.
#[allow(dead_code)]
pub fn free_frames(first: u64, count: usize) -> bool {
    unsafe {
        with_allocator(|alloc| {
            let count = count as u64;
            if count == 0 {
                return false;
            }
            for k in 0..count {
                let f = first + k * PAGE_SIZE;
                if !alloc.valid_frame(f) || alloc.is_free(f / PAGE_SIZE) || !is_issued(f) {
                    return false;
                }
            }
            for k in 0..count {
                take_issued(first + k * PAGE_SIZE);
                alloc.set_free(first / PAGE_SIZE + k, true);
            }
            alloc.free_frames += count;
            true
        })
        .unwrap_or(false)
    }
}

/// Physical address and size of the bitmap (diagnostics / tests).
#[allow(dead_code)]
pub fn bitmap_info() -> (u64, u64) {
    unsafe { with_allocator(|alloc| (alloc.bitmap_phys, alloc.frames)).unwrap_or((0, 0)) }
}

#[allow(dead_code)]
pub fn free_frame_count() -> u64 {
    let global = unsafe { with_allocator(|alloc| alloc.free_frames).unwrap_or(0) };
    global + FCACHED.iter().map(|c| c.load(core::sync::atomic::Ordering::Relaxed)).sum::<u64>()
}

// ------------------------------------------------------------
// "Issued" bitmap and per-CPU frame reserves
// ------------------------------------------------------------

static ISSUED: core::sync::atomic::AtomicPtr<core::sync::atomic::AtomicU64> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
static NFRAMES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Word of the "issued" bitmap and the frame's bit mask; None – address outside the bitmap.
fn issued_bit(frame: u64) -> Option<(&'static core::sync::atomic::AtomicU64, u64)> {
    use core::sync::atomic::Ordering::Relaxed;
    let base = ISSUED.load(Relaxed);
    let index = frame / PAGE_SIZE;
    if base.is_null() || frame % PAGE_SIZE != 0 || frame == 0 || index >= NFRAMES.load(Relaxed) {
        return None;
    }
    Some((unsafe { &*base.add((index / BITS) as usize) }, 1u64 << (index % BITS)))
}

fn mark_issued(frame: u64) {
    if let Some((w, m)) = issued_bit(frame) {
        w.fetch_or(m, core::sync::atomic::Ordering::AcqRel);
    }
}

fn mark_issued_run(first: u64, count: u64) {
    for k in 0..count {
        mark_issued(first + k * PAGE_SIZE);
    }
}

fn is_issued(frame: u64) -> bool {
    issued_bit(frame).is_some_and(|(w, m)| w.load(core::sync::atomic::Ordering::Acquire) & m != 0)
}

/// Clears the "issued" bit; false – the frame was not issued (free refused).
fn take_issued(frame: u64) -> bool {
    issued_bit(frame).is_some_and(|(w, m)| w.fetch_and(!m, core::sync::atomic::Ordering::AcqRel) & m != 0)
}

const FCACHE_MAX: usize = 64;
const FCACHE_BATCH: usize = 32;

struct FCache {
    frames: [u64; FCACHE_MAX],
    n: usize,
}

struct FCacheCell(core::cell::UnsafeCell<FCache>);
// Accessed only from the owning CPU with IF = 0.
unsafe impl Sync for FCacheCell {}

static FCACHES: crate::arch::x86_64::percpu::PerCpu<FCacheCell> =
    crate::per_cpu!(FCacheCell(core::cell::UnsafeCell::new(FCache { frames: [0; FCACHE_MAX], n: 0 })));
/// How many frames are in the CPU reserve (free_frame_count sums them without touching the reserves).
static FCACHED: crate::arch::x86_64::percpu::PerCpu<core::sync::atomic::AtomicU64> =
    crate::per_cpu!(core::sync::atomic::AtomicU64::new(0));
/// Enabled after the allocator self-tests (they check exact bitmap counters).
static FCACHE_ON: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn enable_frame_caches() {
    FCACHE_ON.store(true, core::sync::atomic::Ordering::SeqCst);
}

fn cached_alloc() -> Option<u64> {
    use crate::arch::x86_64::interrupts;
    let irq = interrupts::are_enabled();
    interrupts::disable();
    let me = crate::arch::x86_64::cpu::id();
    let c = unsafe { &mut *FCACHES[me].0.get() };
    if c.n == 0 {
        // Empty: a batch from under the lock.
        let mut slot = ALLOCATOR.lock();
        if let Some(alloc) = slot.as_mut() {
            while c.n < FCACHE_BATCH {
                match alloc.alloc_one() {
                    Some(f) => {
                        c.frames[c.n] = f;
                        c.n += 1;
                    }
                    None => break,
                }
            }
            FREE_MIRROR.store(alloc.free_frames, core::sync::atomic::Ordering::Relaxed);
        }
    }
    let f = if c.n > 0 {
        c.n -= 1;
        Some(c.frames[c.n])
    } else {
        None
    };
    FCACHED[me].store(c.n as u64, core::sync::atomic::Ordering::Relaxed);
    if irq {
        interrupts::enable();
    }
    f
}

fn cached_free(frame: u64) {
    use crate::arch::x86_64::interrupts;
    let irq = interrupts::are_enabled();
    interrupts::disable();
    let me = crate::arch::x86_64::cpu::id();
    let c = unsafe { &mut *FCACHES[me].0.get() };
    if c.n == FCACHE_MAX {
        // Full: a batch goes back to the bitmap in a single visit under the lock.
        let mut slot = ALLOCATOR.lock();
        if let Some(alloc) = slot.as_mut() {
            while c.n > FCACHE_MAX - FCACHE_BATCH {
                c.n -= 1;
                let f = c.frames[c.n];
                alloc.set_free(f / PAGE_SIZE, true);
                alloc.free_frames += 1;
            }
            FREE_MIRROR.store(alloc.free_frames, core::sync::atomic::Ordering::Relaxed);
        }
    }
    c.frames[c.n] = frame;
    c.n += 1;
    FCACHED[me].store(c.n as u64, core::sync::atomic::Ordering::Relaxed);
    if irq {
        interrupts::enable();
    }
}

/// Whether the physical range [start, end) overlaps regular RAM (conventional
/// memory from the UEFI map).  Used to avoid setting write-combining on RAM.
pub fn overlaps_conventional(start: u64, end: u64) -> bool {
    unsafe {
        with_allocator(|alloc| {
            for i in 0..alloc.conventional_len {
                let r = alloc.conventional[i];
                if ranges_overlap(start, end, r.start, r.end) {
                    return true;
                }
            }
            false
        })
        .unwrap_or(true)
    }
}

/// Whether the physical range overlaps RAM or a reservation (kernel, stack,
/// BootInfo, memory map, framebuffer).  Only such 2 MiB pages
/// go into the direct map – holes (e.g. the PCI window below 4 GiB) stay
/// empty, so `map_mmio` can map uncached registers there.
pub fn overlaps_known_memory(start: u64, end: u64) -> bool {
    unsafe {
        with_allocator(|alloc| {
            let conv = (0..alloc.conventional_len)
                .any(|i| ranges_overlap(start, end, alloc.conventional[i].start, alloc.conventional[i].end));
            let res = (0..alloc.reservations_len)
                .any(|i| ranges_overlap(start, end, alloc.reservations[i].start, alloc.reservations[i].end));
            conv || res
        })
        .unwrap_or(false)
    }
}

// Highest physical address (exclusive) that paging must be able to reach:
// end of the last conventional range or reserved region (framebuffer, ...).
pub fn highest_physical_address() -> u64 {
    unsafe {
        with_allocator(|alloc| {
            let mut max = 0u64;
            for i in 0..alloc.conventional_len {
                max = max.max(alloc.conventional[i].end);
            }
            for i in 0..alloc.reservations_len {
                max = max.max(alloc.reservations[i].end);
            }
            max
        })
        .unwrap_or(0)
    }
}

// ------------------------------------------------------------
// TEST (only builds with --cfg selftest)
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
    serial_println!("[MM TEST] Starting frame allocator tests...");
    crate::selftest::begin();

    let before = free_frame_count();

    // 1. Allocate three frames.
    let (f1, f2, f3) = match (alloc_frame(), alloc_frame(), alloc_frame()) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => {
            serial_println!("[MM TEST] FAIL: alloc_frame returned None");
            return;
        }
    };
    check!(
        before - free_frame_count() == 3,
        "counter after 3 allocs: {}",
        before - free_frame_count()
    );
    serial_println!(
        "[MM TEST] 1/8 alloc 3 frames PASS ({:#x}, {:#x}, {:#x})",
        f1,
        f2,
        f3
    );

    // 2. Alignment and uniqueness.
    let mask = PAGE_SIZE - 1;
    check!(
        f1 & mask == 0 && f2 & mask == 0 && f3 & mask == 0,
        "frame not 4 KiB aligned"
    );
    check!(f1 != f2 && f1 != f3 && f2 != f3, "duplicate allocation");
    serial_println!("[MM TEST] 2/8 alignment + uniqueness PASS");

    // 3. Freeing.
    let (ok1, ok2, ok3) = (free_frame(f1), free_frame(f2), free_frame(f3));
    check!(ok1 && ok2 && ok3, "free ({}, {}, {})", ok1, ok2, ok3);
    serial_println!("[MM TEST] 3/8 free PASS");

    // 4. Double-free protection.
    check!(!free_frame(f1), "double-free was accepted");
    serial_println!("[MM TEST] 4/8 double-free protection PASS");

    // 5. Reserved / out-of-range memory.
    check!(!free_frame(0x0000), "null page accepted");
    let layout = kernel_layout();
    check!(!free_frame(layout.kernel_phys), "kernel memory accepted");
    check!(!free_frame(layout.stack_phys), "kernel stack accepted");
    check!(!free_frame(0x8000_0000), "framebuffer accepted");
    check!(!free_frame(0x1234), "unaligned address accepted");
    serial_println!("[MM TEST] 5/8 reserved memory protection PASS");

    // 6. The free frame counter returns to its initial value.
    let after = free_frame_count();
    check!(
        after == before,
        "frame count changed (before={}, after={})",
        before,
        after
    );
    serial_println!("[MM TEST] 6/8 free frame counter PASS ({} free)", after);

    // 7. Contiguous frames (DMA buffers): 16 frames = 64 KiB, aligned to 64 KiB.
    let base = match alloc_frames(16, 16) {
        Some(b) => b,
        None => {
            serial_println!("[MM TEST] FAIL: alloc_frames(16, 16) returned None");
            return;
        }
    };
    check!(base % (16 * PAGE_SIZE) == 0, "run {:#x} not 64 KiB aligned", base);
    check!(free_frame_count() == before - 16, "counter after alloc_frames");
    unsafe {
        // The whole block is regular RAM visible through the direct map.
        ptr::write_bytes(phys_to_virt(base) as *mut u8, 0x5A, 16 * PAGE_SIZE as usize);
        check!(
            *(phys_to_virt(base + 15 * PAGE_SIZE + 4095) as *const u8) == 0x5A,
            "last byte of the run"
        );
    }
    let single = alloc_frame().unwrap_or(0);
    check!(
        single != 0 && !(base..base + 16 * PAGE_SIZE).contains(&single),
        "alloc_frame returned {:#x} inside the run",
        single
    );
    check!(free_frame(single), "free single");
    let run2 = alloc_frames(3, 1).unwrap_or(0);
    check!(run2 != 0 && !(base..base + 16 * PAGE_SIZE).contains(&run2), "second run overlaps");
    check!(free_frames(run2, 3), "free second run");
    check!(free_frames(base, 16), "free_frames(base, 16)");
    check!(free_frame_count() == before, "counter after free_frames");
    serial_println!("[MM TEST] 7/8 contiguous frames (16 x 4 KiB at {:#x}) PASS", base);

    // 8. Errors: zero frames, too many, bad alignment multiple,
    //    partially free range (nothing changes), double-free in O(1).
    check!(alloc_frames(0, 1).is_none(), "alloc_frames(0) succeeded");
    check!(alloc_frames(usize::MAX / 2, 1).is_none(), "huge alloc_frames succeeded");
    check!(alloc_frames(2, 3).is_none(), "non-power-of-two align accepted");
    let r = alloc_frames(4, 1).unwrap_or(0);
    check!(r != 0, "alloc_frames(4)");
    check!(free_frame(r + PAGE_SIZE), "free one frame of the run");
    let mid = free_frame_count();
    check!(!free_frames(r, 4), "free_frames over a partly free run accepted");
    check!(free_frame_count() == mid, "failed free_frames changed the counter");
    check!(!free_frame(r + PAGE_SIZE), "double free accepted");
    check!(free_frame(r) && free_frame(r + 2 * PAGE_SIZE) && free_frame(r + 3 * PAGE_SIZE), "free rest");
    check!(free_frame_count() == before, "counter after error tests");
    let (bitmap, frames) = bitmap_info();
    check!(!free_frame(bitmap), "bitmap frame accepted");
    serial_println!(
        "[MM TEST] 8/8 errors + O(1) double-free (bitmap at {:#x}, {} frames) PASS",
        bitmap,
        frames
    );

    serial_println!("[MM TEST] =================================");
    crate::selftest::pass();
    serial_println!("[MM TEST] FRAME ALLOCATOR TESTS PASSED");
    serial_println!("[MM TEST] =================================");
}
