// M17a krok c: heap i alokator ramek na własnych blokadach – samotesty
// (tylko build z --cfg selftest).  Wszystko tu dzieje się BEZ Big Kernel
// Lock, na wielu CPU naraz.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::x86_64::{cpu, smp, tlb};
use crate::sched::bkl;
use crate::serial_println;
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[ALLOC TEST] FAIL: {}", format_args!($($msg)*));
            STOP.store(true, Ordering::SeqCst);
            crate::time::set_tick_hook(None);
            return;
        }
    };
}

static STOP: AtomicBool = AtomicBool::new(false);
static DONE: AtomicU64 = AtomicU64::new(0);
static BAD: AtomicU64 = AtomicU64::new(0);
static CPUS: AtomicU64 = AtomicU64::new(0);
static OPS: AtomicU64 = AtomicU64::new(0);
static IRQ_ALLOCS: AtomicU64 = AtomicU64::new(0);

const BIG_ROUNDS: usize = 12;
/// Więcej niż SHRINK_AT (512 KiB) – każde zwolnienie zmniejsza heap
/// (TLB shootdown), każda alokacja go powiększa (map_page) – bez BKL.
const BIG_WORDS: usize = 640 * 1024 / 8;
const SMALL_ROUNDS: u64 = 1500;

fn wait_for(ms: u64, mut cond: impl FnMut() -> bool) -> bool {
    let end = ticks() + ms;
    while !cond() {
        if ticks() > end {
            return false;
        }
        crate::time::sleep_ms(1);
    }
    true
}

fn pattern(i: usize, round: usize, j: usize) -> u64 {
    ((i as u64) << 56) ^ ((round as u64) << 40) ^ j as u64 ^ 0x5A5A_0000_0000
}

// ------------------------------------------------------------
// M17b.h2: blok wzięty na jednym CPU, oddany na innym (listy heapa per CPU)
// ------------------------------------------------------------

/// Kanał producent -> konsument: (adres, rozmiar, ziarno wzoru, CPU alokacji).
static XCHAN: crate::sched::spin::SpinLock<Vec<(usize, usize, u32, u8)>> =
    crate::sched::spin::SpinLock::new("alloc-xchan", crate::sched::spin::level::TEST_INNER, Vec::new());
static X_PRODUCED: AtomicU64 = AtomicU64::new(0);
static X_FREED: AtomicU64 = AtomicU64::new(0);
/// Zwolnione na innym CPU niż wzięte.
static X_CROSS: AtomicU64 = AtomicU64::new(0);
static X_PRODUCERS_LEFT: AtomicU64 = AtomicU64::new(0);
const X_ROUNDS: u32 = 6000;
/// Rozmiary: wszystkie klasy, także nie-potęgi 2 (zaokrąglane do klasy).
const X_SIZES: [usize; 12] = [8, 16, 24, 40, 64, 100, 128, 300, 512, 777, 1500, 2048];

fn x_byte(seed: u32, k: usize) -> u8 {
    (seed as usize).wrapping_mul(31).wrapping_add(k * 7) as u8 ^ 0xA5
}

fn x_fill(p: *mut u8, size: usize, seed: u32) {
    for k in 0..size {
        unsafe { *p.add(k) = x_byte(seed, k) };
    }
}

fn x_ok(p: *const u8, size: usize, seed: u32) -> bool {
    (0..size).all(|k| unsafe { *p.add(k) } == x_byte(seed, k))
}

fn x_layout(size: usize) -> core::alloc::Layout {
    core::alloc::Layout::from_size_align(size, 8).unwrap()
}

/// Producent: bierze bloki, wypełnia wzorem, co czwarty trzyma do końca
/// (sprawdzany na końcu – cudze zwolnienia nie mogą go ruszyć), resztę
/// oddaje konsumentom przez kanał.
fn x_producer(i: usize) {
    bkl::unlocked(|| {
        let mut kept: Vec<(usize, usize, u32)> = Vec::with_capacity(X_ROUNDS as usize / 4 + 1);
        for r in 0..X_ROUNDS {
            if STOP.load(Ordering::Relaxed) {
                break;
            }
            let size = X_SIZES[(r as usize + i * 5) % X_SIZES.len()];
            let seed = (i as u32) << 24 | r;
            let p = unsafe { alloc::alloc::alloc(x_layout(size)) };
            if p.is_null() {
                BAD.store(3, Ordering::SeqCst);
                break;
            }
            let at = cpu::id() as u8;
            x_fill(p, size, seed);
            if r % 4 == 0 {
                kept.push((p as usize, size, seed));
                continue;
            }
            // Kanał ograniczony – nie zalewamy heapa.
            loop {
                {
                    let mut q = XCHAN.lock();
                    if q.len() < 256 {
                        q.push((p as usize, size, seed, at));
                        break;
                    }
                }
                crate::sched::yield_now();
            }
            X_PRODUCED.fetch_add(1, Ordering::Relaxed);
        }
        for &(p, size, seed) in kept.iter() {
            if !x_ok(p as *const u8, size, seed) {
                let _ = BAD.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
            }
            unsafe { alloc::alloc::dealloc(p as *mut u8, x_layout(size)) };
        }
    });
    X_PRODUCERS_LEFT.fetch_sub(1, Ordering::SeqCst);
    DONE.fetch_add(1, Ordering::SeqCst);
}

/// Konsument: sprawdza wzór (nikt nie pisał po bloku w drodze) i zwalnia
/// – zwykle na innym CPU niż ten, który blok wziął.
fn x_consumer(_: usize) {
    bkl::unlocked(|| loop {
        let item = XCHAN.lock().pop();
        match item {
            Some((p, size, seed, at)) => {
                if !x_ok(p as *const u8, size, seed) {
                    let _ = BAD.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
                }
                // Zapis po bloku tuż przed zwolnieniem (jak prawdziwy kod).
                unsafe { core::ptr::write_bytes(p as *mut u8, 0xEE, size) };
                if cpu::id() as u8 != at {
                    X_CROSS.fetch_add(1, Ordering::Relaxed);
                }
                CPUS.fetch_or(1 << cpu::id(), Ordering::Relaxed);
                unsafe { alloc::alloc::dealloc(p as *mut u8, x_layout(size)) };
                X_FREED.fetch_add(1, Ordering::Relaxed);
            }
            None => {
                if X_PRODUCERS_LEFT.load(Ordering::SeqCst) == 0 && XCHAN.lock().is_empty() {
                    break;
                }
                crate::sched::yield_now();
            }
        }
    });
    DONE.fetch_add(1, Ordering::SeqCst);
}

/// Duże bloki: heap rośnie i maleje równolegle na kilku CPU.
/// M17b.h: największy rozmiar heapa w czasie testu dużych bloków (mogą się
/// zmieścić w dziurach – wtedy heap nie rośnie i nie ma czego oddawać).
static PEAK: AtomicU64 = AtomicU64::new(0);

fn big(i: usize) {
    bkl::unlocked(|| {
        for round in 0..BIG_ROUNDS {
            if STOP.load(Ordering::Relaxed) {
                break;
            }
            let mut v: Vec<u64> = Vec::new();
            if v.try_reserve_exact(BIG_WORDS).is_err() {
                BAD.store(3, Ordering::SeqCst);
                break;
            }
            for j in 0..BIG_WORDS {
                v.push(pattern(i, round, j));
            }
            CPUS.fetch_or(1 << cpu::id(), Ordering::Relaxed);
            PEAK.fetch_max(crate::memory::heap_mapped_bytes() as u64, Ordering::Relaxed);
            if v.iter().enumerate().any(|(j, &x)| x != pattern(i, round, j)) {
                let _ = BAD.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
            }
            OPS.fetch_add(1, Ordering::Relaxed);
        }
    });
    DONE.fetch_add(1, Ordering::SeqCst);
}

/// Małe bloki i ramki naraz.
fn small(i: usize) {
    bkl::unlocked(|| {
        let mut kept: Vec<Vec<u32>> = Vec::new();
        for r in 0..SMALL_ROUNDS {
            if STOP.load(Ordering::Relaxed) {
                break;
            }
            let len = 1 + ((r as usize * 131 + i * 17) % 300);
            let v: Vec<u32> = (0..len as u32).map(|x| x ^ (i as u32) << 24).collect();
            kept.push(v);
            if kept.len() > 24 {
                let old = kept.remove((r as usize * 7) % kept.len());
                if old.iter().enumerate().any(|(j, &x)| x != (j as u32) ^ (i as u32) << 24) {
                    let _ = BAD.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
                }
            }
            if r % 4 == 0 {
                match crate::memory::alloc_frame() {
                    Some(f) => {
                        let p = crate::memory::phys_to_virt(f) as *mut u64;
                        unsafe {
                            p.write_volatile(f ^ i as u64);
                            p.add(511).write_volatile(!f);
                            if p.read_volatile() != f ^ i as u64 || p.add(511).read_volatile() != !f {
                                let _ = BAD.compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst);
                            }
                        }
                        if !crate::memory::free_frame(f) {
                            let _ = BAD.compare_exchange(0, 4, Ordering::SeqCst, Ordering::SeqCst);
                        }
                    }
                    None => BAD.store(3, Ordering::SeqCst),
                }
            }
            CPUS.fetch_or(1 << cpu::id(), Ordering::Relaxed);
            OPS.fetch_add(1, Ordering::Relaxed);
        }
    });
    DONE.fetch_add(1, Ordering::SeqCst);
}

/// Alokacja z przerwania zegara w trakcie testu 2.
fn irq_hook(_: u64) {
    let v: Vec<u8> = alloc::vec![0xA5; 96];
    if v.iter().any(|&b| b != 0xA5) {
        let _ = BAD.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
    }
    IRQ_ALLOCS.fetch_add(1, Ordering::Relaxed);
}

fn bad_text(code: u64) -> &'static str {
    match code {
        1 => "heap block overwritten",
        2 => "frame contents overwritten",
        3 => "out of memory",
        4 => "free_frame refused a frame it had just given out",
        _ => "?",
    }
}

fn noop(_: usize) {}

pub fn self_test() {
    serial_println!("[ALLOC TEST] Starting heap / frame allocator tests without BKL...");
    crate::selftest::begin();
    STOP.store(false, Ordering::SeqCst);
    let n = smp::online_count();
    let k = n.clamp(2, 4);
    crate::sched::reap();
    let (_, _, dl0) = crate::sched::spin::stats();

    // 1. Duże bloki: heap rośnie (map_page) i maleje (unmap + TLB shootdown)
    //    na kilku CPU naraz, bez BKL.
    let mapped0 = crate::memory::heap_mapped_bytes();
    let used0 = crate::memory::heap_used_bytes();
    let (rq0, _, _, _, _) = tlb::stats();
    DONE.store(0, Ordering::SeqCst);
    BAD.store(0, Ordering::SeqCst);
    CPUS.store(0, Ordering::SeqCst);
    OPS.store(0, Ordering::SeqCst);
    PEAK.store(0, Ordering::SeqCst);
    for i in 0..k {
        check!(crate::sched::spawn("alloc-big", big, i).is_ok(), "spawn big");
    }
    check!(wait_for(120_000, || DONE.load(Ordering::SeqCst) == k as u64), "big allocators did not finish ({} / {})", DONE.load(Ordering::SeqCst), k);
    let bad = BAD.load(Ordering::SeqCst);
    check!(bad == 0, "big blocks: {}", bad_text(bad));
    crate::sched::reap();
    let (rq1, _, _, _, _) = tlb::stats();
    let mapped1 = crate::memory::heap_mapped_bytes();
    let cpus = CPUS.load(Ordering::SeqCst).count_ones();
    check!(n == 1 || cpus >= 2, "big allocators ran on {} CPU", cpus);
    check!(mapped1 <= mapped0 + 640 * 1024, "heap did not shrink back ({} -> {} KiB)", mapped0 / 1024, mapped1 / 1024);
    check!(
        rq1 > rq0 || n == 1 || PEAK.load(Ordering::SeqCst) <= mapped0 as u64,
        "no TLB shootdown from heap shrinking"
    );
    serial_println!(
        "[ALLOC TEST] 1/4 {} tasks x {} x 640 KiB on {} CPUs without BKL: heap grows and shrinks ({} shootdowns), data intact PASS",
        k,
        BIG_ROUNDS,
        cpus,
        rq1 - rq0
    );

    // 2. Małe bloki + ramki na kilku CPU, przerwanie zegara też alokuje,
    //    a zadanie testowe (z BKL) w tym czasie tworzy i kończy zadania
    //    (stosy: map/unmap w innym obszarze kernela).
    let frames0 = crate::memory::free_frame_count();
    DONE.store(0, Ordering::SeqCst);
    CPUS.store(0, Ordering::SeqCst);
    OPS.store(0, Ordering::SeqCst);
    IRQ_ALLOCS.store(0, Ordering::SeqCst);
    crate::time::set_tick_hook(Some(irq_hook));
    for i in 0..k {
        check!(crate::sched::spawn("alloc-small", small, i).is_ok(), "spawn small");
    }
    let mut spawned = 0;
    while DONE.load(Ordering::SeqCst) < k as u64 && spawned < 2000 {
        if crate::sched::spawn("alloc-noop", noop, 0).is_ok() {
            spawned += 1;
        }
        crate::time::sleep_ms(1);
    }
    let finished = wait_for(120_000, || DONE.load(Ordering::SeqCst) == k as u64);
    crate::time::set_tick_hook(None);
    check!(finished, "small allocators did not finish ({} / {})", DONE.load(Ordering::SeqCst), k);
    let bad = BAD.load(Ordering::SeqCst);
    check!(bad == 0, "small blocks / frames: {}", bad_text(bad));
    let irq = IRQ_ALLOCS.load(Ordering::SeqCst);
    check!(irq > 0, "no allocation from the timer interrupt");
    wait_for(2_000, || {
        crate::sched::reap();
        crate::sched::tasks().iter().all(|t| t.name != "alloc-noop" && t.name != "alloc-small")
    });
    let used1 = crate::memory::heap_used_bytes();
    check!(used1 <= used0 + 16 * 1024, "heap used {} -> {} bytes (leak?)", used0, used1);
    let frames1 = crate::memory::free_frame_count();
    let heap_pages = (crate::memory::heap_mapped_bytes() as u64).saturating_sub(mapped0 as u64) / 4096;
    // Zapas na tablice stron obszarów kernela (sloty stosów 2000 zadań, heap),
    // które chwilę zostają – prawdziwy wyciek to ramki na każdą rundę.
    check!(frames1 + heap_pages + 64 >= frames0, "frames {} -> {} (+{} heap pages)", frames0, frames1, heap_pages);
    serial_println!(
        "[ALLOC TEST] 2/4 {} tasks x {} small blocks + frames, {} allocs in the timer IRQ, {} task stacks meanwhile, nothing lost PASS",
        k,
        SMALL_ROUNDS,
        irq,
        spawned
    );

    // 3. M17b.h2: bloki wzięte na jednym CPU, zwalniane na innym (listy heapa
    //    per CPU) – wzory nienaruszone, nic nie ginie.
    let used_x0 = crate::memory::heap_used_bytes();
    DONE.store(0, Ordering::SeqCst);
    CPUS.store(0, Ordering::SeqCst);
    X_PRODUCED.store(0, Ordering::SeqCst);
    X_FREED.store(0, Ordering::SeqCst);
    X_CROSS.store(0, Ordering::SeqCst);
    X_PRODUCERS_LEFT.store(k as u64, Ordering::SeqCst);
    for i in 0..k {
        check!(crate::sched::spawn("alloc-xprod", x_producer, i).is_ok(), "spawn producer");
        check!(crate::sched::spawn("alloc-xcons", x_consumer, i).is_ok(), "spawn consumer");
    }
    check!(wait_for(120_000, || DONE.load(Ordering::SeqCst) == 2 * k as u64), "cross-CPU tasks did not finish ({} / {})", DONE.load(Ordering::SeqCst), 2 * k);
    let bad = BAD.load(Ordering::SeqCst);
    check!(bad == 0, "cross-CPU blocks: {}", bad_text(bad));
    let (produced, freed, cross) =
        (X_PRODUCED.load(Ordering::SeqCst), X_FREED.load(Ordering::SeqCst), X_CROSS.load(Ordering::SeqCst));
    check!(produced == freed, "blocks lost in the channel: {} sent, {} freed", produced, freed);
    check!(n == 1 || cross > 0, "no block freed on another CPU ({} blocks)", freed);
    *XCHAN.lock() = Vec::new();
    crate::sched::reap();
    let used_x1 = crate::memory::heap_used_bytes();
    check!(used_x1 <= used_x0 + 16 * 1024, "heap used {} -> {} bytes after cross-CPU frees (leak?)", used_x0, used_x1);
    serial_println!(
        "[ALLOC TEST] 3/4 {} producer(s) + {} consumer(s): {} blocks, {} freed on another CPU, patterns intact PASS",
        k,
        k,
        freed,
        cross
    );

    // 4. Blokady alokatorów: nikt nie zgłosił zakleszczenia w trakcie testu.
    let (acq, cont, dl) = crate::sched::spin::stats();
    check!(dl == dl0, "{} deadlock report(s) during the test", dl - dl0);
    serial_println!("[ALLOC TEST] 4/4 spinlocks so far: {} taken, {} contended, 0 deadlock reports PASS", acq, cont);

    crate::selftest::pass();
}
