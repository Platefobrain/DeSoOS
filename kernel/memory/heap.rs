// M3: kernel heap.
//
// * Obszar wirtualny: HEAP_START .. HEAP_START + HEAP_MAX_SIZE
//   (PML4[384], z dala od direct mapy w PML4[256..384) i slotu rekurencyjnego).
// * Strony są brane z alokatora ramek (M1) i mapowane przez map_page (M2).
// * Heap rośnie na żądanie (alloc bez miejsca -> mapujemy kolejne strony).
// * M11: i się kurczy – gdy na końcu heapa zbierze się ponad SHRINK_AT
//   wolnego miejsca, strony powyżej (koniec ostatniego zajętego bloku +
//   SHRINK_KEEP) są odmapowywane, a ramki wracają do alokatora ramek.
//   Nigdy poniżej INITIAL_SIZE.  Zapas SHRINK_KEEP chroni przed ciągłym
//   mapowaniem/odmapowywaniem przy alokacjach na granicy.
// * Algorytm: lista wolnych bloków posortowana po adresie, first-fit,
//   scalanie sąsiadów przy zwalnianiu.  Węzły listy siedzą w samych
//   wolnych blokach, więc alokacje nie mają nagłówków.
//
// Współbieżność: M5 – alloc/dealloc z wyłączonymi przerwaniami (handler IRQ
// może alokować).  M17a.c – własny IrqSpinLock (poziom HEAP): heap działa
// także bez Big Kernel Lock, na wielu CPU naraz.  Wewnątrz: alokator ramek
// (własna blokada), map_page w obszarze heapa (PML4[384] – tablice tego
// obszaru zmienia tylko heap, pod swoją blokadą) i TLB shootdown przy
// zmniejszaniu (czekający na blokadę heapa potwierdzają shootdown w pętli).

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use crate::sched::spin::{level, IrqSpinLock};
use crate::serial_println;

use super::{alloc_frame, free_frame, map_page, unmap_page};

const PAGE_SIZE: usize = 4096;

pub const HEAP_START: usize = 0xffff_c000_0000_0000;
pub const HEAP_MAX_SIZE: usize = 64 * 1024 * 1024;

const INITIAL_SIZE: usize = 128 * 1024;
const GROW_MIN: usize = 128 * 1024;
const SHRINK_AT: usize = 512 * 1024;
const SHRINK_KEEP: usize = 128 * 1024;

// Każdy blok (wolny i zajęty) ma rozmiar podzielny przez 16 i adres podzielny
// przez 16; w wolnym bloku mieści się Node.
const MIN_BLOCK: usize = 16;

#[repr(C)]
struct Node {
    size: usize,
    next: *mut Node,
}

struct Heap {
    ready: bool,
    head: *mut Node,
    mapped_end: usize, // exclusive
    used: usize,       // bajty w zajętych blokach (po zaokrągleniu)
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// Rozmiar bloku dla Layout – JEDNA reguła niezależnie od list CPU (M17b.h2):
/// małe bloki (<= MAX_CLASS, wyrównanie <= 16) zawsze zaokrąglone do klasy
/// (potęga 2), więc blok wzięty z heapa przed `enable_cpu_caches` i oddany
/// na listę CPU po (albo odwrotnie) ma ten sam rozmiar.  Wcześniej 80 B
/// wzięte jako 80 i oddane jako klasa 128 nadpisałoby sąsiada.
fn block_size(layout: Layout) -> usize {
    match class_of(layout) {
        Some((_, size)) => size,
        None => align_up(layout.size().max(MIN_BLOCK), MIN_BLOCK),
    }
}

fn block_align(layout: Layout) -> usize {
    layout.align().max(MIN_BLOCK)
}

impl Heap {
    const fn empty() -> Self {
        Heap {
            ready: false,
            head: ptr::null_mut(),
            mapped_end: HEAP_START,
            used: 0,
        }
    }

    /// Zwraca węzeł, w którym po scaleniu leży zwolniony blok.
    unsafe fn insert_free(&mut self, addr: usize, size: usize) -> *mut Node {
        unsafe {
            let mut prev: *mut Node = ptr::null_mut();
            let mut cur = self.head;
            while !cur.is_null() && (cur as usize) < addr {
                prev = cur;
                cur = (*cur).next;
            }

            // Wykrywanie double-free / uszkodzenia: blok nie może nachodzić
            // na sąsiadów.
            if !prev.is_null() && prev as usize + (*prev).size > addr {
                panic!("heap: overlapping free (double free?) at {:#x}", addr);
            }
            if !cur.is_null() && addr + size > cur as usize {
                panic!("heap: overlapping free (double free?) at {:#x}", addr);
            }

            let node = addr as *mut Node;
            (*node).size = size;
            (*node).next = cur;
            if prev.is_null() {
                self.head = node;
            } else {
                (*prev).next = node;
            }

            // scal z następnym
            if !cur.is_null() && addr + (*node).size == cur as usize {
                (*node).size += (*cur).size;
                (*node).next = (*cur).next;
            }

            // scal z poprzednim
            if !prev.is_null() && prev as usize + (*prev).size == addr {
                (*prev).size += (*node).size;
                (*prev).next = (*node).next;
                return prev;
            }
            node
        }
    }

    unsafe fn alloc_from_list(&mut self, size: usize, align: usize) -> *mut u8 {
        unsafe {
            let mut prev: *mut Node = ptr::null_mut();
            let mut cur = self.head;

            while !cur.is_null() {
                let region_start = cur as usize;
                let region_end = region_start + (*cur).size;
                let next = (*cur).next;

                let alloc_start = align_up(region_start, align);
                let fits = match alloc_start.checked_add(size) {
                    Some(alloc_end) => alloc_end <= region_end,
                    None => false,
                };

                if fits {
                    let alloc_end = alloc_start + size;
                    // Oba kawałki są wielokrotnością 16, więc jeśli istnieją,
                    // mieszczą w sobie Node.
                    let front = alloc_start - region_start;
                    let back = region_end - alloc_end;

                    let mut link = next;
                    if back > 0 {
                        let n = alloc_end as *mut Node;
                        (*n).size = back;
                        (*n).next = link;
                        link = n;
                    }
                    if front > 0 {
                        let n = region_start as *mut Node;
                        (*n).size = front;
                        (*n).next = link;
                        link = n;
                    }
                    if prev.is_null() {
                        self.head = link;
                    } else {
                        (*prev).next = link;
                    }

                    self.used += size;
                    return alloc_start as *mut u8;
                }

                prev = cur;
                cur = next;
            }

            ptr::null_mut()
        }
    }

    /// Mapuje `bytes` (zaokrąglone do stron) na końcu heapa i dodaje je do
    /// listy wolnych bloków.  Wszystko albo nic.
    unsafe fn grow(&mut self, bytes: usize) -> bool {
        let want = align_up(bytes.max(GROW_MIN), PAGE_SIZE);
        let min = align_up(bytes, PAGE_SIZE);
        let limit = HEAP_START + HEAP_MAX_SIZE;

        let grow_by = if self.mapped_end + want <= limit {
            want
        } else if self.mapped_end + min <= limit {
            min
        } else {
            return false;
        };

        let start = self.mapped_end;
        let pages = grow_by / PAGE_SIZE;

        for i in 0..pages {
            let va = (start + i * PAGE_SIZE) as u64;
            let ok = match alloc_frame() {
                Some(frame) => {
                    if map_page(va, frame, super::kernel_data_flags()) {
                        true
                    } else {
                        free_frame(frame);
                        false
                    }
                }
                None => false,
            };

            if !ok {
                // Rollback już zmapowanych stron.
                for j in 0..i {
                    let va = (start + j * PAGE_SIZE) as u64;
                    if let Some(frame) = unmap_page(va) {
                        free_frame(frame);
                    }
                }
                return false;
            }
        }

        self.mapped_end = start + grow_by;
        unsafe {
            self.insert_free(start, grow_by);
        }
        true
    }

    /// Odmapowuje wolny koniec heapa, gdy jest większy niż SHRINK_AT.
    /// `last` – wolny węzeł kończący się na końcu heapa (M17b.h: wcześniej
    /// szukany przejściem całej listy przy KAŻDYM zwolnieniu).
    unsafe fn shrink(&mut self, last: *mut Node) {
        // M17a.b: przy wielu CPU znowu oddaje strony – unmap_range_free robi
        // TLB shootdown, zanim ramki wrócą do alokatora (od M17 do M17a.a
        // heap przy SMP tylko rósł).
        unsafe {
            let start = last as usize;
            let end = start + (*last).size;
            if end != self.mapped_end || (*last).size < SHRINK_AT {
                return;
            }

            let new_end = (align_up(start, PAGE_SIZE) + SHRINK_KEEP).max(HEAP_START + INITIAL_SIZE);
            if new_end >= self.mapped_end {
                return;
            }
            // Najpierw skróć blok (węzeł leży na początku bloku, poniżej
            // new_end), potem oddaj strony.
            (*last).size = new_end - start;
            let pages = (self.mapped_end - new_end) / PAGE_SIZE;
            let n = super::unmap_range_free(new_end as u64, self.mapped_end as u64);
            if n != pages {
                panic!("heap: {} of {} pages at {:#x} were mapped", n, pages, new_end);
            }
            self.mapped_end = new_end;
        }
    }

    unsafe fn allocate(&mut self, layout: Layout) -> *mut u8 {
        if !self.ready {
            return ptr::null_mut();
        }

        let size = block_size(layout);
        let align = block_align(layout);

        unsafe {
            let p = self.alloc_from_list(size, align);
            if !p.is_null() {
                return p;
            }

            let need = if align > MIN_BLOCK { size + align } else { size };
            if !self.grow(need) {
                return ptr::null_mut();
            }
            self.alloc_from_list(size, align)
        }
    }

    unsafe fn deallocate(&mut self, p: *mut u8, layout: Layout) {
        let size = block_size(layout);
        let addr = p as usize;

        if addr < HEAP_START || addr + size > self.mapped_end || addr % MIN_BLOCK != 0 {
            panic!("heap: dealloc of foreign pointer {:#x}", addr);
        }

        self.used -= size;
        unsafe {
            let node = self.insert_free(addr, size);
            if node as usize + (*node).size == self.mapped_end && (*node).size >= SHRINK_AT {
                self.shrink(node);
            }
        }
    }
}

// Węzły listy wolnych bloków to surowe wskaźniki do pamięci heapa – całość
// chroniona blokadą HEAP_LOCK.
unsafe impl Send for Heap {}

pub struct KernelHeap;

static HEAP_LOCK: IrqSpinLock<Heap> = IrqSpinLock::new("heap", level::HEAP, Heap::empty());

// ------------------------------------------------------------
// M17b.h: listy wolnych bloków per CPU
// ------------------------------------------------------------
//
// Legion v0.17.32/33 (16 CPU, stress): ~70 mln czekań na blokadę `heap`,
// średnio 11 µs – 83% czasu wszystkich CPU na kręceniu.  Lista wolnych
// bloków jest przeglądana pod blokadą przy każdym alloc i (wtedy dwa razy)
// przy każdym dealloc, a jądro alokuje w każdym syscallu (ścieżki, bufory).
//
// Małe bloki (do 2 KiB – od P2 do 32 KiB, wyrównanie <= 16) mają klasy 16, 32, ..., 2048 (32768).
// Każdy CPU trzyma dla każdej klasy listę wolnych bloków (węzeł w samym
// bloku); alloc / dealloc to zdjęcie / dołożenie na listę tego CPU przy
// wyłączonych przerwaniach (przerwanie też alokuje) – bez blokady.  Pusta lista
// = jedna wizyta pod blokadą heapa po paczkę bloków; za długa = połowa wraca
// do heapa naraz.  Blok może wrócić na listę innego CPU niż ten, z którego
// pochodzi – klasa wynika z Layout, więc rozmiar się zgadza.
// Bloki na listach liczą się w heapie jako zajęte (`used`).

// P2 (v0.21.0): klasy także 4, 8, 16, 32 KiB.  Pomiar (stress, v0.20.2):
// 89% alokacji wolną ścieżką (globalna lista pod blokadą `heap`) to bloki
// 2–8 KiB, dalsze 7% – 16–32 KiB (zadania, bufory, ELF przy spawn).
const CLASSES: usize = 12; // 16, 32, ..., 2048, 4096, ..., 32768
const MAX_CLASS: usize = 32768;

struct CpuCache {
    head: [usize; CLASSES],
    count: [u32; CLASSES],
}

struct CpuCacheCell(core::cell::UnsafeCell<CpuCache>);
// Dostęp tylko z własnego CPU przy IF = 0.
unsafe impl Sync for CpuCacheCell {}

static CACHES: crate::arch::x86_64::percpu::PerCpu<CpuCacheCell> = crate::per_cpu!(CpuCacheCell(
    core::cell::UnsafeCell::new(CpuCache { head: [0; CLASSES], count: [0; CLASSES] })
));

/// Bajty w blokach na listach (per CPU, suma może być chwilowo ujemna na
/// jednym CPU – blok zwolniony na innym niż ten, który go wziął z heapa).
static CACHED_BYTES: crate::arch::x86_64::percpu::PerCpu<core::sync::atomic::AtomicI64> =
    crate::per_cpu!(core::sync::atomic::AtomicI64::new(0));

fn cached_bytes() -> usize {
    CACHED_BYTES.iter().map(|c| c.load(core::sync::atomic::Ordering::Relaxed)).sum::<i64>().max(0) as usize
}

#[inline]
fn cached_add(cpu: usize, d: i64) {
    CACHED_BYTES[cpu].fetch_add(d, core::sync::atomic::Ordering::Relaxed);
}

/// Włączone po samoteście heapa (on sprawdza dokładne liczniki i scalanie).
static CACHE_ON: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn enable_cpu_caches() {
    CACHE_ON.store(true, core::sync::atomic::Ordering::SeqCst);
}

/// Klasa bloku: (indeks, rozmiar) albo None (duży / mocniej wyrównany).
#[inline]
fn class_of(layout: Layout) -> Option<(usize, usize)> {
    if layout.align() > MIN_BLOCK || layout.size() > MAX_CLASS {
        return None;
    }
    let size = layout.size().max(MIN_BLOCK).next_power_of_two();
    Some((size.trailing_zeros() as usize - 4, size))
}

/// Ile bloków klasy trzyma lista jednego CPU (małe: ~16 KiB na klasę, 8..64).
#[inline]
fn class_limit(size: usize) -> u32 {
    if size <= 2048 {
        ((16 * 1024 / size) as u32).clamp(8, 64)
    } else {
        // P2: duże klasy – mniej bloków na CPU (4 KiB: 8, 8 KiB: 8, 16 KiB: 4,
        // 32 KiB: 2; razem ≤ 224 KiB na CPU).
        ((64 * 1024 / size) as u32).clamp(2, 8)
    }
}

#[inline]
fn irq_save() -> bool {
    let on = crate::arch::x86_64::interrupts::are_enabled();
    crate::arch::x86_64::interrupts::disable();
    on
}

#[inline]
fn irq_restore(on: bool) {
    if on {
        crate::arch::x86_64::interrupts::enable();
    }
}

unsafe fn cached_alloc(c: usize, size: usize) -> *mut u8 {
    debug_assert!(size == 1 << (c + 4));
    let irq = irq_save();
    let me = crate::arch::x86_64::cpu::id();
    let cache = unsafe { &mut *CACHES[me].0.get() };
    let head = cache.head[c];
    if head != 0 {
        cache.head[c] = unsafe { *(head as *const usize) };
        cache.count[c] -= 1;
        cached_add(me, -(size as i64));
        irq_restore(irq);
        return head as *mut u8;
    }
    // Pusto: paczka bloków spod blokady heapa (połowa limitu), jeden dla nas.
    let batch = (class_limit(size) / 2).max(1) as usize;
    let layout = unsafe { Layout::from_size_align_unchecked(size, MIN_BLOCK) };
    let mut first: *mut u8 = ptr::null_mut();
    {
        let mut h = HEAP_LOCK.lock();
        for _ in 0..batch {
            let p = unsafe { h.allocate(layout) };
            if p.is_null() {
                break;
            }
            if first.is_null() {
                first = p;
            } else {
                unsafe { *(p as *mut usize) = cache.head[c] };
                cache.head[c] = p as usize;
                cache.count[c] += 1;
                cached_add(me, size as i64);
            }
        }
    }
    irq_restore(irq);
    first
}

unsafe fn cached_dealloc(p: *mut u8, c: usize, size: usize) {
    let irq = irq_save();
    let me = crate::arch::x86_64::cpu::id();
    let cache = unsafe { &mut *CACHES[me].0.get() };
    unsafe { *(p as *mut usize) = cache.head[c] };
    cache.head[c] = p as usize;
    cache.count[c] += 1;
    cached_add(me, size as i64);
    let limit = class_limit(size);
    if cache.count[c] > limit {
        // Połowa wraca do heapa jedną wizytą pod blokadą.
        let layout = unsafe { Layout::from_size_align_unchecked(size, MIN_BLOCK) };
        let mut h = HEAP_LOCK.lock();
        while cache.count[c] > limit / 2 {
            let b = cache.head[c];
            cache.head[c] = unsafe { *(b as *const usize) };
            cache.count[c] -= 1;
            cached_add(me, -(size as i64));
            unsafe { h.deallocate(b as *mut u8, layout) };
        }
    }
    irq_restore(irq);
}

unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if CACHE_ON.load(core::sync::atomic::Ordering::Relaxed) {
            if let Some((c, size)) = class_of(layout) {
                return unsafe { cached_alloc(c, size) };
            }
        }
        unsafe { HEAP_LOCK.lock().allocate(layout) }
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        if CACHE_ON.load(core::sync::atomic::Ordering::Relaxed) {
            if let Some((c, size)) = class_of(layout) {
                return unsafe { cached_dealloc(p, c, size) };
            }
        }
        unsafe { HEAP_LOCK.lock().deallocate(p, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: KernelHeap = KernelHeap;

// ------------------------------------------------------------
// PUBLIC API
// ------------------------------------------------------------

pub fn init() {
    serial_println!("[MM] Initializing kernel heap...");

    let mapped_end = {
        let mut h = HEAP_LOCK.lock();
        h.ready = true;
        if !unsafe { h.grow(INITIAL_SIZE) } {
            drop(h);
            panic!("heap: cannot map initial heap");
        }
        h.mapped_end
    };

    serial_println!(
        "[MM] Heap: {:#x}..{:#x} ({} KiB mapped, max {} MiB)",
        HEAP_START,
        mapped_end,
        (mapped_end - HEAP_START) / 1024,
        HEAP_MAX_SIZE / (1024 * 1024)
    );
}

#[allow(dead_code)]
pub fn used_bytes() -> usize {
    // M17b.h: bez bloków czekających na listach CPU (te są wolne dla jądra).
    HEAP_LOCK.lock().used.saturating_sub(cached_bytes())
}

#[allow(dead_code)]
pub fn mapped_bytes() -> usize {
    HEAP_LOCK.lock().mapped_end - HEAP_START
}

#[allow(dead_code)]
pub fn free_region_count() -> usize {
    let h = HEAP_LOCK.lock();
    let mut n = 0;
    let mut cur = h.head;
    while !cur.is_null() {
        n += 1;
        cur = unsafe { (*cur).next };
    }
    n
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
    // Wywołania wprost przez GlobalAlloc, a nie alloc::alloc::alloc: przy
    // optymalizacji (-O) kompilator ma prawo usunąć parę alloc+dealloc
    // nieużywanej pamięci, a wtedy testy układu heapa sprawdzałyby nic.
    unsafe fn raw_alloc(layout: Layout) -> *mut u8 {
        unsafe { core::hint::black_box(GlobalAlloc::alloc(&ALLOCATOR, layout)) }
    }
    unsafe fn raw_dealloc(p: *mut u8, layout: Layout) {
        unsafe { GlobalAlloc::dealloc(&ALLOCATOR, core::hint::black_box(p), layout) }
    }
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::vec::Vec;

    serial_println!("[MM TEST] Starting heap tests...");
    crate::selftest::begin();

    check!(used_bytes() == 0, "heap not empty at start ({})", used_bytes());
    check!(free_region_count() == 1, "expected 1 free region at start");

    // 1. Box.
    {
        let b = Box::new(0xDE5_0511_CAFE_F00Du64);
        check!(*b == 0xDE5_0511_CAFE_F00D, "Box value");
        check!(used_bytes() > 0, "Box not accounted");
        check!(
            (&*b as *const u64 as usize) >= HEAP_START,
            "Box not in heap region"
        );
    }
    check!(used_bytes() == 0, "Box leaked");
    serial_println!("[MM TEST] 1/10 Box PASS");

    // 2. Vec rosnący ponad początkowy rozmiar heapa.
    let mapped_before = mapped_bytes();
    let peak;
    {
        let mut v: Vec<u64> = Vec::new();
        for i in 0..100_000u64 {
            v.push(i * 3);
        }
        let mut sum = 0u64;
        for x in v.iter() {
            sum = sum.wrapping_add(*x);
        }
        check!(sum == 3 * (99_999u64 * 100_000 / 2), "Vec sum {}", sum);
        check!(mapped_bytes() > mapped_before, "heap did not grow");
        peak = mapped_bytes();
    }
    check!(used_bytes() == 0, "Vec leaked");
    check!(free_region_count() == 1, "heap fragmented after Vec");
    serial_println!(
        "[MM TEST] 2/10 Vec growth PASS (heap grew to {} KiB, back to {} KiB)",
        peak / 1024,
        mapped_bytes() / 1024
    );

    // 3. Wyrównania.
    for align in [16usize, 64, 256, 4096] {
        let layout = match Layout::from_size_align(100, align) {
            Ok(l) => l,
            Err(_) => {
                serial_println!("[MM TEST] FAIL: bad layout");
                return;
            }
        };
        let p = unsafe { raw_alloc(layout) };
        check!(!p.is_null(), "alloc align {} returned null", align);
        check!(p as usize % align == 0, "align {} violated: {:p}", align, p);
        unsafe {
            ptr::write_bytes(p, 0xAB, 100);
            raw_dealloc(p, layout);
        }
    }
    check!(used_bytes() == 0, "aligned allocs leaked");
    check!(free_region_count() == 1, "heap fragmented after aligned allocs");
    serial_println!("[MM TEST] 3/10 alignment PASS");

    // 4. Scalanie: zwalniamy a, c, b -> jedna wolna strefa.
    {
        let layout = Layout::from_size_align(512, 16).unwrap();
        let a = unsafe { raw_alloc(layout) };
        let b = unsafe { raw_alloc(layout) };
        let c = unsafe { raw_alloc(layout) };
        check!(!a.is_null() && !b.is_null() && !c.is_null(), "alloc a/b/c");
        check!(a != b && b != c && a != c, "overlapping allocations");
        unsafe {
            raw_dealloc(a, layout);
            raw_dealloc(c, layout);
        }
        check!(free_region_count() >= 2, "expected a hole while b is live");
        unsafe {
            raw_dealloc(b, layout);
        }
        check!(used_bytes() == 0, "a/b/c leaked");
        check!(free_region_count() == 1, "free blocks not coalesced");
    }
    serial_println!("[MM TEST] 4/10 coalescing PASS");

    // 5. Ponowne użycie adresu.
    {
        let layout = Layout::from_size_align(64, 16).unwrap();
        let p = unsafe { raw_alloc(layout) };
        unsafe { raw_dealloc(p, layout) };
        let q = unsafe { raw_alloc(layout) };
        check!(p == q, "freed block not reused ({:p} vs {:p})", p, q);
        unsafe { raw_dealloc(q, layout) };
    }
    serial_println!("[MM TEST] 5/10 reuse PASS");

    // 6. String / format! / Vec<String>.
    {
        let s = alloc::format!("DeSoOS {} {}", 3, "heap");
        check!(s == "DeSoOS 3 heap", "format!");
        let mut names: Vec<String> = Vec::new();
        for i in 0..200 {
            names.push(alloc::format!("entry-{}", i));
        }
        check!(names[199] == "entry-199", "Vec<String>");
    }
    check!(used_bytes() == 0, "String/Vec<String> leaked");
    serial_println!("[MM TEST] 6/10 String + Vec<String> PASS");

    // 7. Stress: losowe alloc/free z weryfikacją zawartości.
    {
        const SLOTS: usize = 256;
        let mut slots: [(*mut u8, usize, usize, u8); SLOTS] =
            [(ptr::null_mut(), 0, 0, 0); SLOTS];
        let mut rng: u64 = 0x1234_5678_9abc_def1;

        for _ in 0..20_000 {
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let idx = ((rng >> 33) as usize) % SLOTS;
            let (p, size, align, tag) = slots[idx];

            if !p.is_null() {
                let bytes = unsafe { core::slice::from_raw_parts(p, size) };
                check!(bytes.iter().all(|&b| b == tag), "corruption in slot {}", idx);
                let layout = Layout::from_size_align(size, align).unwrap();
                unsafe { raw_dealloc(p, layout) };
                slots[idx] = (ptr::null_mut(), 0, 0, 0);
            } else {
                let size = if (rng >> 20) % 64 == 0 {
                    1 + ((rng >> 24) as usize) % 40_000
                } else {
                    1 + ((rng >> 24) as usize) % 3000
                };
                let align = 1usize << (((rng >> 50) as usize) % 7);
                let tag = (rng >> 40) as u8;
                let layout = Layout::from_size_align(size, align).unwrap();
                let p = unsafe { raw_alloc(layout) };
                check!(!p.is_null(), "stress alloc null (size {})", size);
                check!(p as usize % align == 0, "stress align");
                unsafe { ptr::write_bytes(p, tag, size) };
                slots[idx] = (p, size, align, tag);
            }
        }

        for idx in 0..SLOTS {
            let (p, size, align, tag) = slots[idx];
            if p.is_null() {
                continue;
            }
            let bytes = unsafe { core::slice::from_raw_parts(p, size) };
            check!(bytes.iter().all(|&b| b == tag), "corruption at cleanup {}", idx);
            let layout = Layout::from_size_align(size, align).unwrap();
            unsafe { raw_dealloc(p, layout) };
        }
    }
    check!(used_bytes() == 0, "stress leaked ({} bytes)", used_bytes());
    check!(free_region_count() == 1, "heap fragmented after stress");
    serial_println!("[MM TEST] 7/10 stress PASS");

    // 8. Alokacja ponad limit heapa -> null, a heap zostaje spójny.
    {
        let layout = Layout::from_size_align(HEAP_MAX_SIZE * 2, 16).unwrap();
        let p = unsafe { raw_alloc(layout) };
        check!(p.is_null(), "oversized alloc succeeded");
    }
    check!(used_bytes() == 0, "used changed after failed alloc");
    check!(free_region_count() == 1, "heap damaged by failed alloc");
    serial_println!("[MM TEST] 8/10 out-of-limit alloc PASS");

    // 9. Kurczenie: duży blok mapuje strony, po zwolnieniu ramki wracają.
    {
        let frames_before = super::free_frame_count();
        let mapped_start = mapped_bytes();
        let layout = Layout::from_size_align(4 * 1024 * 1024, 16).unwrap();
        let p = unsafe { raw_alloc(layout) };
        check!(!p.is_null(), "4 MiB alloc");
        unsafe { ptr::write_bytes(p, 0x77, 4 * 1024 * 1024) };
        let mapped_peak = mapped_bytes();
        check!(mapped_peak >= mapped_start + 4 * 1024 * 1024, "heap did not grow to 4 MiB");
        check!(
            super::free_frame_count() + (4 * 1024 * 1024 / PAGE_SIZE) as u64 <= frames_before,
            "frames not taken"
        );
        unsafe { raw_dealloc(p, layout) };
        check!(mapped_bytes() == mapped_start, "heap not shrunk ({} KiB mapped)", mapped_bytes() / 1024);
        check!(
            super::free_frame_count() == frames_before,
            "frames not returned (before {}, now {})",
            frames_before,
            super::free_frame_count()
        );
        check!(free_region_count() == 1, "heap damaged by shrinking");

        // Mały blok na końcu nie powoduje odmapowania (próg SHRINK_AT).
        let small = Layout::from_size_align(200 * 1024, 16).unwrap();
        let q = unsafe { raw_alloc(small) };
        check!(!q.is_null(), "200 KiB alloc");
        let mapped_q = mapped_bytes();
        unsafe { raw_dealloc(q, small) };
        check!(mapped_bytes() == mapped_q, "shrunk below the SHRINK_AT threshold");
        serial_println!(
            "[MM TEST] 9/10 shrink PASS ({} KiB -> {} KiB, frames returned)",
            mapped_peak / 1024,
            mapped_start / 1024
        );
    }

    // 10. M17b.h2: granica włączenia list CPU.  Bloki o rozmiarach spoza
    // potęg 2 wzięte z heapa PRZED włączeniem, oddane PO (na listę CPU) –
    // sąsiednie bloki-strażnicy nie mogą się zmienić, a ponownie wzięte bloki
    // tej klasy zapisane w CAŁOŚCI (rozmiar klasy) też nie ruszają strażników.
    {
        const SIZES: [usize; 6] = [24, 80, 200, 520, 1100, 2000];
        let mut odd: [(*mut u8, Layout); 6] = [(ptr::null_mut(), Layout::new::<u8>()); 6];
        let mut guards: [(*mut u8, Layout); 6] = [(ptr::null_mut(), Layout::new::<u8>()); 6];
        for (i, &sz) in SIZES.iter().enumerate() {
            let l = Layout::from_size_align(sz, 8).unwrap();
            let p = unsafe { raw_alloc(l) };
            let g = unsafe { raw_alloc(l) };
            check!(!p.is_null() && !g.is_null(), "boundary alloc {}", sz);
            unsafe {
                ptr::write_bytes(p, 0x11, sz);
                ptr::write_bytes(g, 0xC0 + i as u8, sz);
            }
            odd[i] = (p, l);
            guards[i] = (g, l);
        }
        enable_cpu_caches();
        for &(p, l) in odd.iter() {
            unsafe { raw_dealloc(p, l) };
        }
        // Ponownie: ta sama klasa, zapis całego bloku klasy (najgorszy przypadek).
        let mut again: [(*mut u8, Layout); 6] = [(ptr::null_mut(), Layout::new::<u8>()); 6];
        for (i, &sz) in SIZES.iter().enumerate() {
            let l = Layout::from_size_align(sz, 8).unwrap();
            let p = unsafe { raw_alloc(l) };
            check!(!p.is_null(), "boundary re-alloc {}", sz);
            unsafe { ptr::write_bytes(p, 0x22, block_size(l)) };
            again[i] = (p, l);
        }
        for (i, &(g, l)) in guards.iter().enumerate() {
            let ok = (0..l.size()).all(|k| unsafe { *g.add(k) } == 0xC0 + i as u8);
            check!(ok, "guard block {} ({} B) overwritten across the cache boundary", i, l.size());
        }
        for &(p, l) in again.iter().chain(guards.iter()) {
            unsafe { raw_dealloc(p, l) };
        }
        check!(used_bytes() == 0, "boundary blocks leaked ({} B)", used_bytes());
        serial_println!("[MM TEST] 10/10 per-CPU lists: blocks freed across enable keep neighbours intact PASS");
    }

    serial_println!("[MM TEST] =================================");
    crate::selftest::pass();
    serial_println!("[MM TEST] HEAP TESTS PASSED");
    serial_println!("[MM TEST] =================================");
}
