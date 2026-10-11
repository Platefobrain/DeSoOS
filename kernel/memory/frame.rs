// M1: alokator ramek fizycznych (4 KiB).
//
// M11: bitmapa zamiast listy wolnych ramek w samych ramkach.
//   * 1 bit na ramkę od adresu 0 do końca najwyższego RAM-u (1 = wolna);
//     512 MiB RAM -> 16 KiB bitmapy, 64 GiB -> 2 MiB.  Bitmapa leży w RAM-ie
//     (pierwszy pasujący kawałek conventional memory, zarezerwowany) i jest
//     czytana przez direct map.
//   * free_frame: sprawdzenie double-free to jeden bit – O(1) (wcześniej
//     przejście po całej liście).
//   * alloc_frame: szukanie od podpowiedzi słowami po 64 bity.
//   * alloc_frames(n, align): n CIĄGŁYCH ramek (bufory DMA).
//   * Wolne ramki nie są już zapisywane – ich zawartość nie jest dotykana.

use crate::bootinfo::BootInfo;
use crate::serial_println;
use core::ptr;

use super::layout::{kernel_layout, phys_to_virt, DIRECT_MAP_BASE};

const PAGE_SIZE: u64 = 4096;
const EFI_CONVENTIONAL_MEMORY: u32 = 7;

// Strona 0 nigdy nie jest wydawana (adres 0 = "brak ramki").
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
    /// Bitmapa (1 = wolna) w direct mapie, `words` słów po 64 bity.
    bitmap: *mut u64,
    words: usize,
    /// Liczba ramek opisanych bitmapą (ramki 0..frames).
    frames: u64,
    bitmap_phys: u64,
    /// Słowo, od którego alloc_frame zaczyna szukanie.
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

// M17a.c: własna blokada (poziom FRAMES) zamiast samego without_interrupts +
// Big Kernel Lock – ramki można brać i oddawać na wielu CPU naraz, także
// z kodu bez BKL i z handlerów przerwań.
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
// `base` to adres wirtualny mapy (direct map).
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

    // Obraz kernela i stos startowy (M10: DSB alokuje je jako LOADER_DATA,
    // więc i tak nie są "conventional" – rezerwacja to druga linia obrony).
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

/// Miejsce na bitmapę: pierwszy fragment conventional memory, który nie
/// nachodzi na rezerwacje.
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
        // Powyżej 1 MiB – niska pamięć przyda się na trampolinę SMP (M17).
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

// Bitmapa w direct mapie (surowy wskaźnik) – chroniona blokadą ALLOCATOR.
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

    /// Czy ramkę wolno oddać do alokatora (RAM, nie rezerwacja, w bitmapie).
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

    /// M17: najniższa wolna ramka poniżej adresu `limit`.
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

    /// `count` ciągłych wolnych ramek, pierwsza wyrównana do `align` ramek.
    fn alloc_run(&mut self, count: u64, align: u64) -> Option<u64> {
        if count == 0 || count > self.free_frames || align == 0 || !align.is_power_of_two() {
            return None;
        }
        let mut start = align;
        while start + count <= self.frames {
            // Szybki przeskok przez całkowicie zajęte słowa.
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

/// Fizyczny adres BootInfo/// Fizyczny adres BootInfo (DSB podaje wskaźnik z direct mapy).
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

    // Bitmapa: ramki 0..koniec najwyższego zakresu RAM.
    let mut ram_end = 0;
    for i in 0..conventional_len {
        ram_end = ram_end.max(conventional[i].end);
    }
    let frames = ram_end / PAGE_SIZE;
    let words = frames.div_ceil(BITS) as usize;
    let bitmap_bytes = (words * 8) as u64;

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
    unsafe { ptr::write_bytes(bitmap, 0, words) };

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

    // M17: ramka poniżej 1 MiB na trampolinę startu AP (procesor po SIPI
    // zaczyna w trybie rzeczywistym) – zarezerwowana od razu, zanim zwykłe
    // alokacje zajmą niską pamięć.
    let tramp = alloc.alloc_below(0x10_0000);
    match tramp {
        Some(t) => serial_println!("[MM] Reserved AP trampoline frame: {:#x}", t),
        None => serial_println!("[MM] No free frame below 1 MiB - only one CPU will be used"),
    }
    TRAMPOLINE.store(tramp.unwrap_or(0), core::sync::atomic::Ordering::SeqCst);

    *ALLOCATOR.lock() = Some(alloc);
}

static TRAMPOLINE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// M17: zarezerwowana ramka trampoliny AP (< 1 MiB); None – brak.
pub fn trampoline_frame() -> Option<u64> {
    match TRAMPOLINE.load(core::sync::atomic::Ordering::Relaxed) {
        0 => None,
        t => Some(t),
    }
}

/// M17: ramka poniżej `limit` (np. tablice stron dla trybu 32-bit CR3).
pub fn alloc_frame_below(limit: u64) -> Option<u64> {
    unsafe { with_allocator(|alloc| alloc.alloc_below(limit))? }
}

// M5: przerwania wyłączone na czas operacji – handler IRQ nie może trafić
// na bitmapę w połowie modyfikacji.  M17a.c: IrqSpinLock (też inne CPU).
unsafe fn with_allocator<R>(f: impl FnOnce(&mut FrameAllocator) -> R) -> Option<R> {
    let mut slot = ALLOCATOR.lock();
    let alloc = slot.as_mut()?;
    Some(f(alloc))
}

pub fn alloc_frame() -> Option<u64> {
    unsafe { with_allocator(|alloc| alloc.alloc_one())? }
}

/// M11: `count` ciągłych ramek (np. bufor DMA), pierwsza wyrównana do
/// `align` ramek (potęga dwójki; 1 = bez wymagań).  Zwraca adres pierwszej.
#[allow(dead_code)]
pub fn alloc_frames(count: usize, align: usize) -> Option<u64> {
    unsafe { with_allocator(|alloc| alloc.alloc_run(count as u64, align as u64))? }
}

// Returns true only when `frame` was a valid, currently allocated frame.
// Invalid addresses and double-frees are rejected (one bit test - O(1)).
pub fn free_frame(frame: u64) -> bool {
    unsafe {
        with_allocator(|alloc| {
            if !alloc.valid_frame(frame) || alloc.is_free(frame / PAGE_SIZE) {
                return false;
            }
            alloc.set_free(frame / PAGE_SIZE, true);
            alloc.free_frames += 1;
            true
        })
        .unwrap_or(false)
    }
}

/// Oddaje `count` ciągłych ramek od `first`.  Wszystko albo nic: gdy
/// któraś ramka jest nieprawidłowa albo już wolna, nic się nie zmienia.
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
                if !alloc.valid_frame(f) || alloc.is_free(f / PAGE_SIZE) {
                    return false;
                }
            }
            for k in 0..count {
                alloc.set_free(first / PAGE_SIZE + k, true);
            }
            alloc.free_frames += count;
            true
        })
        .unwrap_or(false)
    }
}

/// Adres fizyczny i rozmiar bitmapy (diagnostyka / testy).
#[allow(dead_code)]
pub fn bitmap_info() -> (u64, u64) {
    unsafe { with_allocator(|alloc| (alloc.bitmap_phys, alloc.frames)).unwrap_or((0, 0)) }
}

#[allow(dead_code)]
pub fn free_frame_count() -> u64 {
    unsafe {
        with_allocator(|alloc| alloc.free_frames).unwrap_or(0)
    }
}

/// Czy zakres fizyczny [start, end) nachodzi na zwykły RAM (conventional
/// memory z mapy UEFI).  Używane, żeby nie ustawić write-combining na RAM-ie.
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

/// Czy zakres fizyczny nachodzi na RAM albo rezerwację (kernel, stos,
/// BootInfo, mapa pamięci, framebuffer).  M10: tylko takie strony 2 MiB
/// trafiają do direct mapy – dziury (np. okno PCI pod 4 GiB) zostają
/// puste, więc `map_mmio` może zmapować tam rejestry bez cache.
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
// TEST (tylko build z --cfg selftest)
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

    // 1. Alokacja trzech ramek.
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

    // 2. Wyrównanie i unikalność.
    let mask = PAGE_SIZE - 1;
    check!(
        f1 & mask == 0 && f2 & mask == 0 && f3 & mask == 0,
        "frame not 4 KiB aligned"
    );
    check!(f1 != f2 && f1 != f3 && f2 != f3, "duplicate allocation");
    serial_println!("[MM TEST] 2/8 alignment + uniqueness PASS");

    // 3. Zwalnianie.
    let (ok1, ok2, ok3) = (free_frame(f1), free_frame(f2), free_frame(f3));
    check!(ok1 && ok2 && ok3, "free ({}, {}, {})", ok1, ok2, ok3);
    serial_println!("[MM TEST] 3/8 free PASS");

    // 4. Ochrona przed double-free.
    check!(!free_frame(f1), "double-free was accepted");
    serial_println!("[MM TEST] 4/8 double-free protection PASS");

    // 5. Pamięć zarezerwowana / poza zakresem.
    check!(!free_frame(0x0000), "null page accepted");
    let layout = kernel_layout();
    check!(!free_frame(layout.kernel_phys), "kernel memory accepted");
    check!(!free_frame(layout.stack_phys), "kernel stack accepted");
    check!(!free_frame(0x8000_0000), "framebuffer accepted");
    check!(!free_frame(0x1234), "unaligned address accepted");
    serial_println!("[MM TEST] 5/8 reserved memory protection PASS");

    // 6. Licznik wolnych ramek wraca do stanu początkowego.
    let after = free_frame_count();
    check!(
        after == before,
        "frame count changed (before={}, after={})",
        before,
        after
    );
    serial_println!("[MM TEST] 6/8 free frame counter PASS ({} free)", after);

    // 7. Ciągłe ramki (bufory DMA): 16 ramek = 64 KiB, wyrównane do 64 KiB.
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
        // Cały blok jest zwykłym RAM-em widocznym przez direct map.
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

    // 8. Błędy: zero ramek, za dużo, zła wielokrotność wyrównania,
    //    częściowo wolny zakres (nic się nie zmienia), double-free w O(1).
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
