// M17: Big Kernel Lock (BKL) – jedna blokada na cały kernel.
//
// Zasada (jak Linux 2.0–2.2): w danej chwili kod kernela wykonuje JEDEN
// procesor.  Pozostałe w tym czasie wykonują kod procesów w ring 3 (to się
// dzieje naprawdę równolegle), śpią w `hlt` albo czekają na blokadę.
// Dzięki temu cały kernel napisany dla jednego rdzenia (sekcje
// `without_interrupts`, statyczne struktury) zostaje poprawny na wielu
// rdzeniach.  Drobne blokady (scheduler, heap, VFS osobno) – później.
//
// Kto trzyma BKL:
//   * każdy CPU wykonujący kod kernela (zadania kernela, syscalle, przerwania),
//   * CPU w ring 3 – NIE (zwalnia przy SYSRET / IRETQ do procesu),
//   * CPU w `hlt` – NIE (interrupts::enable_and_hlt zwalnia na czas snu).
// Wejścia do kernela: syscall_dispatch, exception_dispatch (przerwania
// i wyjątki), start AP.  Blokada należy do procesora, nie do zadania –
// przełączenie zadań jej nie zmienia.
//
// Blokada biletowa (ticket lock): kolejność wejścia = kolejność czekania.
// Zawsze brana przy wyłączonych przerwaniach (inaczej przerwanie na tym
// samym CPU czekałoby na bilet za samym sobą).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::arch::x86_64::{cpu, interrupts};

static NEXT: AtomicU32 = AtomicU32::new(0);
static SERVING: AtomicU32 = AtomicU32::new(0);
/// Numer CPU + 1 (0 = nikt).
static OWNER: AtomicU32 = AtomicU32::new(0);

// M17a: bilet, na który dany CPU teraz czeka (+1; 0 = nie czeka) – raport
// watchdoga i wykrywanie zagnieżdżonego czekania (drugi bilet tego samego
// CPU = zakleszczenie z samym sobą).
static WAITING: [AtomicU32; crate::arch::x86_64::cpu::MAX_CPUS] =
    [const { AtomicU32::new(0) }; crate::arch::x86_64::cpu::MAX_CPUS];

/// Skąd i od kiedy obecny właściciel trzyma BKL (raport watchdoga).
static OWNER_SITE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static OWNER_SINCE: AtomicU64 = AtomicU64::new(0);

/// (plik, linia, ms od wzięcia) – gdzie obecny właściciel wziął BKL.
/// Dla miejsc z nazwą (`Site::Tag`) linia = 0.
pub fn owner_site() -> Option<(&'static str, u32, u64)> {
    let a = OWNER_SITE.load(Ordering::Relaxed);
    if a == 0 || OWNER.load(Ordering::Relaxed) == 0 {
        return None;
    }
    let (f, l) = site_name(a);
    Some((f, l, crate::time::ticks().saturating_sub(OWNER_SINCE.load(Ordering::Relaxed))))
}

// ------------------------------------------------------------
// M17a.g: kto bierze BKL – statystyka per miejsce wzięcia
// ------------------------------------------------------------
//
// Klucz miejsca: adres `Location` (#[track_caller] – plik:linia) albo adres
// statycznej nazwy `&'static str` z ustawionym najmłodszym bitem (oba są
// wyrównane do 8, więc bit 0 je rozróżnia).  Tablica bez blokad: wpis
// zajmowany przez compare_exchange klucza, liczniki – atomiki.  Czas
// trzymania mierzony TSC tego samego CPU (BKL oddaje CPU, który go wziął –
// od f2 także przy przełączeniu), więc niezgodne TSC rdzeni nie przeszkadzają.

const SITES: usize = 48;

/// M17b.e: każdy wpis w osobnej linii cache (liczniki zmieniane z wielu CPU).
#[repr(align(64))]
pub(crate) struct SiteStat {
    key: core::sync::atomic::AtomicUsize,
    pub(crate) taken: AtomicU64,
    pub(crate) waited: AtomicU64,
    pub(crate) wait_us: AtomicU64,
    pub(crate) hold_tsc: AtomicU64,
}

/// M17a.g12: tablica miejsc wzięcia blokady (BKL, blokada schedulera).
pub(crate) struct SiteTable {
    tab: [SiteStat; SITES],
    overflow: AtomicU64,
}

impl SiteTable {
    pub(crate) const fn new() -> Self {
        SiteTable {
            tab: [const {
                SiteStat {
                    key: core::sync::atomic::AtomicUsize::new(0),
                    taken: AtomicU64::new(0),
                    waited: AtomicU64::new(0),
                    wait_us: AtomicU64::new(0),
                    hold_tsc: AtomicU64::new(0),
                }
            }; SITES],
            overflow: AtomicU64::new(0),
        }
    }

    pub(crate) fn entry(&self, i: usize) -> &SiteStat {
        &self.tab[i]
    }

    pub(crate) fn slot_for(&self, key: usize) -> Option<usize> {
        let start = (key >> 3).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 58; // 0..63
        for k in 0..SITES {
            let i = (start as usize + k) % SITES;
            let cur = self.tab[i].key.load(Ordering::Acquire);
            if cur == key {
                return Some(i);
            }
            if cur == 0 {
                match self.tab[i].key.compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => return Some(i),
                    Err(other) if other == key => return Some(i),
                    Err(_) => continue,
                }
            }
        }
        self.overflow.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Wszystkie miejsca, posortowane malejąco wg czasu czekania + trzymania.
    pub(crate) fn stats(&self) -> alloc::vec::Vec<SiteInfo> {
        // Bez kalibracji LAPIC (jeden CPU) – czasu trzymania nie znamy (0).
        let tsc_ms = crate::arch::x86_64::lapic::tsc_per_ms();
        let mut v: alloc::vec::Vec<SiteInfo> = self
            .tab
            .iter()
            .filter_map(|e| {
                let key = e.key.load(Ordering::Acquire);
                if key == 0 {
                    return None;
                }
                let (file, line) = site_name(key);
                Some(SiteInfo {
                    file,
                    line,
                    taken: e.taken.load(Ordering::Relaxed),
                    waited: e.waited.load(Ordering::Relaxed),
                    wait_us: e.wait_us.load(Ordering::Relaxed),
                    held_us: if tsc_ms == 0 { 0 } else { e.hold_tsc.load(Ordering::Relaxed).saturating_mul(1000) / tsc_ms },
                })
            })
            .collect();
        v.sort_by(|a, b| (b.wait_us + b.held_us).cmp(&(a.wait_us + a.held_us)));
        v
    }

    pub(crate) fn overflow(&self) -> u64 {
        self.overflow.load(Ordering::Relaxed)
    }
}

static SITE_TAB: SiteTable = SiteTable::new();
/// Wpis (+1) i TSC wzięcia obecnego właściciela (pisze tylko właściciel).
static OWNER_SLOT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static OWNER_TSC: AtomicU64 = AtomicU64::new(0);

#[inline]
pub(crate) fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    ((hi as u64) << 32) | lo as u64
}

#[allow(dead_code)]
pub(crate) fn location_key(l: &'static core::panic::Location<'static>) -> usize {
    l as *const core::panic::Location as usize
}

pub(crate) fn tag_key(t: &'static &'static str) -> usize {
    (t as *const &'static str as usize) | 1
}

/// (plik albo nazwa, linia – 0 dla nazwy).
fn site_name(key: usize) -> (&'static str, u32) {
    if key & 1 == 1 {
        let t: &'static &'static str = unsafe { &*((key & !1) as *const &'static str) };
        (t, 0)
    } else {
        let l: &'static core::panic::Location<'static> = unsafe { &*(key as *const core::panic::Location<'static>) };
        (l.file(), l.line())
    }
}

/// Statystyka jednego miejsca wzięcia BKL (`cpus`, autostress).
pub struct SiteInfo {
    pub file: &'static str,
    pub line: u32,
    pub taken: u64,
    pub waited: u64,
    pub wait_us: u64,
    pub held_us: u64,
}

/// Wszystkie miejsca, posortowane malejąco wg czasu czekania + trzymania.
pub fn site_stats() -> alloc::vec::Vec<SiteInfo> {
    SITE_TAB.stats()
}

/// Miejsca, które nie zmieściły się w tablicy statystyki.
pub fn site_overflow() -> u64 {
    SITE_TAB.overflow()
}

/// Nazwane miejsca wzięcia (zamiast pliku:linii) – czytelne na zdjęciu ekranu.
pub mod tag {
    pub static AFTER_WAIT: &str = "after switch: wait_event (WaitQueue)";
    pub static AFTER_SLEEP: &str = "after switch: sleep";
    pub static AFTER_YIELD: &str = "after switch: yield";
    pub static AFTER_PREEMPT: &str = "after switch: preempt (irq)";
    pub static NEW_TASK: &str = "new task start";
    pub static SYSCALL: &str = "syscall under BKL";
    pub static HLT_WAKE: &str = "wake from hlt";
    pub static UNLOCKED_END: &str = "end of bkl::unlocked";
    pub static YIELD: &str = "yield_if_contended (re-take)";
    pub static AP_START: &str = "AP start";
    pub static IDLE_REAP: &str = "idle: reap dead tasks";
    pub static BOOT: &str = "boot (kernel_main)";
    pub static KBD_POLL: &str = "keyboard poll in timer tick (try)";
    pub static IRQ_PIT_USER: &str = "irq PIT tick (from ring 3)";
    pub static IRQ_PIT_KERNEL: &str = "irq PIT tick (from kernel)";
    pub static IRQ_TIMER_USER: &str = "irq LAPIC timer (from ring 3)";
    pub static IRQ_TIMER_KERNEL: &str = "irq LAPIC timer (from kernel)";
    pub static IRQ_RESCHED_USER: &str = "irq resched IPI (from ring 3)";
    pub static IRQ_RESCHED_KERNEL: &str = "irq resched IPI (from kernel)";
    pub static IRQ_OTHER_USER: &str = "irq device/MSI (from ring 3)";
    pub static IRQ_OTHER_KERNEL: &str = "irq device/MSI (from kernel)";
    pub static EXC_USER: &str = "exception (from ring 3)";
    pub static EXC_KERNEL: &str = "exception (from kernel)";
}

/// Bilet, na który czeka CPU `c` (None – nie czeka).
pub fn waiting_ticket(c: usize) -> Option<u32> {
    match WAITING[c % crate::arch::x86_64::cpu::MAX_CPUS].load(Ordering::Relaxed) {
        0 => None,
        t => Some(t - 1),
    }
}

// M17a: statystyka – ile razy brano BKL, ile razy trzeba było czekać i ile
// czasu zeszło na czekanie (miara tego, co zyskamy, zdejmując BKL).
static ACQUIRES: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static CONTENDED: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
/// Łączny czas czekania na BKL w mikrosekundach (zegar clock.rs).
static WAIT_US: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();

/// (wzięcia, wzięcia z czekaniem, mikrosekundy czekania) – `cpus`, testy.
pub fn stats() -> (u64, u64, u64) {
    (ACQUIRES.get(), CONTENDED.get(), WAIT_US.get())
}

/// Czy bieżący CPU trzyma BKL.
///
/// M17a.f2: odczyt numeru CPU i właściciela z IF = 0.  Z IF = 1 zadanie
/// mogło zostać wywłaszczone i przeniesione na inny CPU między nimi (BKL
/// idzie za zadaniem: oddany przy przełączeniu, wzięty w after_switch) –
/// wynik byłby fałszywy (fałszywy panic "wait_event returned without the
/// BKL"; `enable_and_hlt` mógłby usnąć z BKL).
#[inline]
pub fn held() -> bool {
    crate::arch::x86_64::interrupts::without_interrupts(|| OWNER.load(Ordering::Acquire) == cpu::id() as u32 + 1)
}

/// Bierze BKL (czeka na swoją kolej).  Przerwania muszą być wyłączone.
#[track_caller]
pub fn acquire() {
    acquire_at(location_key(core::panic::Location::caller()));
}

/// Jak `acquire`, ale miejsce w statystyce ma nazwę (`bkl::tag::*`).
#[allow(dead_code)]
pub fn acquire_tagged(t: &'static &'static str) {
    acquire_at(tag_key(t));
}

/// Jak `acquire_if_needed`, z nazwanym miejscem; `true` = wziął teraz.
pub fn acquire_if_needed_tagged(t: &'static &'static str) -> bool {
    if held() {
        return false;
    }
    acquire_at(tag_key(t));
    true
}

fn acquire_at(site: usize) {
    debug_assert!(!interrupts::are_enabled(), "BKL taken with interrupts enabled");
    let me = cpu::id();
    if let Some(t) = waiting_ticket(me) {
        panic!("BKL: CPU {} waits for ticket {} and asks again (nested acquire)", me, t);
    }
    let ticket = NEXT.fetch_add(1, Ordering::AcqRel);
    WAITING[me].store(ticket.wrapping_add(1), Ordering::Relaxed);
    ACQUIRES.add(1);
    let mut waited_us = None;
    if SERVING.load(Ordering::Acquire) != ticket {
        // M17a.g14: statystyka – TSC (ten sam CPU), raport – HPET co 4096 obrotów.
        let (tsc0, cpu0) = crate::arch::x86_64::clock::tsc_cpu();
        let mut start = 0u64;
        let mut n: u32 = 0;
        let mut reported = false;
        while SERVING.load(Ordering::Acquire) != ticket {
            core::hint::spin_loop();
            n = n.wrapping_add(1);
            // M17a.b: czekamy z IF = 0 – żądanie TLB shootdown obsługujemy tu
            // (inicjator może trzymać BKL i czekać na nas).
            if n % 64 == 0 {
                crate::arch::x86_64::tlb::poll_from_wait();
            }
            if n % 4096 == 0 {
                crate::arch::x86_64::smp::watchdog_poll();
                // M17a: długie czekanie na BKL (zagłodzenie / wolne przekazywanie).
                if start == 0 {
                    start = crate::arch::x86_64::clock::stamp().max(1);
                }
                if !reported {
                    let waited = crate::arch::x86_64::clock::elapsed_us(start) / 1000;
                    if waited >= crate::arch::x86_64::smp::BKL_WAIT_REPORT_MS {
                        reported = true;
                        crate::arch::x86_64::smp::bkl_wait_report(ticket, waited);
                    }
                }
            }
        }
        let us = crate::arch::x86_64::clock::tsc_wait_us(tsc0, cpu0);
        CONTENDED.add(1);
        WAIT_US.add(us);
        waited_us = Some(us);
    }
    WAITING[me].store(0, Ordering::Relaxed);
    // M17a.g: statystyka miejsca (już jako właściciel – nikt inny nie pisze
    // OWNER_SLOT / OWNER_TSC).
    let slot = SITE_TAB.slot_for(site);
    if let Some(i) = slot {
        let e = SITE_TAB.entry(i);
        e.taken.fetch_add(1, Ordering::Relaxed);
        if let Some(us) = waited_us {
            e.waited.fetch_add(1, Ordering::Relaxed);
            e.wait_us.fetch_add(us, Ordering::Relaxed);
        }
    }
    OWNER_SLOT.store(slot.map_or(0, |i| i + 1), Ordering::Relaxed);
    OWNER_TSC.store(rdtsc(), Ordering::Relaxed);
    OWNER_SITE.store(site, Ordering::Relaxed);
    OWNER_SINCE.store(crate::time::ticks(), Ordering::Relaxed);
    OWNER.store(cpu::id() as u32 + 1, Ordering::Release);
}

/// M17a.g4: bierze BKL tylko, jeśli jest wolny i nikt nie czeka (bez
/// kolejki); `false` = nie wziął.  Przerwania muszą być wyłączone.  Dla
/// prac, które mogą poczekać do następnej okazji (odpytywanie klawiatury
/// w ticku zegara bez BKL).
pub fn try_acquire_tagged(t: &'static &'static str) -> bool {
    debug_assert!(!interrupts::are_enabled(), "BKL taken with interrupts enabled");
    if held() {
        return false;
    }
    let serving = SERVING.load(Ordering::Acquire);
    if NEXT.compare_exchange(serving, serving.wrapping_add(1), Ordering::AcqRel, Ordering::Relaxed).is_err() {
        return false;
    }
    ACQUIRES.add(1);
    let site = tag_key(t);
    let slot = SITE_TAB.slot_for(site);
    if let Some(i) = slot {
        SITE_TAB.entry(i).taken.fetch_add(1, Ordering::Relaxed);
    }
    OWNER_SLOT.store(slot.map_or(0, |i| i + 1), Ordering::Relaxed);
    OWNER_TSC.store(rdtsc(), Ordering::Relaxed);
    OWNER_SITE.store(site, Ordering::Relaxed);
    OWNER_SINCE.store(crate::time::ticks(), Ordering::Relaxed);
    OWNER.store(cpu::id() as u32 + 1, Ordering::Release);
    true
}

/// Bierze BKL, jeśli ten CPU go jeszcze nie ma; `true` = wziął teraz.
#[inline]
#[track_caller]
pub fn acquire_if_needed() -> bool {
    if held() {
        return false;
    }
    acquire();
    true
}

/// Oddaje BKL (tylko właściciel).
pub fn release() {
    debug_assert!(held(), "BKL released by a CPU that does not hold it");
    // M17a.g: czas trzymania (TSC tego samego CPU).
    let slot = OWNER_SLOT.swap(0, Ordering::Relaxed);
    if slot != 0 {
        let d = rdtsc().wrapping_sub(OWNER_TSC.load(Ordering::Relaxed));
        if d < (1u64 << 48) {
            SITE_TAB.entry(slot - 1).hold_tsc.fetch_add(d, Ordering::Relaxed);
        }
    }
    OWNER.store(0, Ordering::Release);
    SERVING.fetch_add(1, Ordering::AcqRel);
}

/// Czy inny CPU czeka na BKL.
#[inline]
pub fn contended() -> bool {
    NEXT.load(Ordering::Relaxed).wrapping_sub(SERVING.load(Ordering::Relaxed)) > 1
}

/// Punkt oddania: inny CPU czeka – oddaj i weź z powrotem (kolejka biletowa
/// przepuści go pierwszego).  Z przerwania zegara, gdy przerwany kod miał
/// włączone przerwania – to jak wywłaszczenie, więc bezpieczne.
pub fn yield_if_contended() {
    // M17a: trzymając spinlock nie wolno czekać na BKL (inny CPU z BKL
    // mógłby czekać na nasz spinlock – zakleszczenie).
    if held() && contended() && super::spin::held_count() == 0 && crate::arch::x86_64::cpu::preempt_count() == 0 {
        release();
        acquire_tagged(&tag::YIELD);
    }
}

/// M17a: wykonuje `f` BEZ Big Kernel Lock (inne CPU mogą w tym czasie
/// wykonywać kod kernela).  `f` może dotykać tylko danych chronionych
/// własnymi blokadami (spinlocki, atomiki) – nie heapa, VFS ani schedulera,
/// dopóki te mają tylko BKL.  Przerwanie w trakcie bierze BKL na czas
/// handlera i oddaje go przy powrocie (exceptions.rs).
#[allow(dead_code)]
pub fn unlocked<R>(f: impl FnOnce() -> R) -> R {
    let irq = interrupts::are_enabled();
    interrupts::disable();
    let had = held();
    if had {
        debug_assert!(super::spin::held_count() == 0, "bkl::unlocked while holding a spinlock");
        release();
    }
    if irq {
        interrupts::enable();
    }
    let r = f();
    interrupts::disable();
    if had {
        acquire_if_needed_tagged(&tag::UNLOCKED_END);
    }
    if irq {
        interrupts::enable();
    }
    r
}

/// M17a.e: wykonuje `f` Z BKL – z kodu, który działa bez niego (syscalle bez
/// BKL wołające scheduler: czekanie, budzenie).  Jeśli BKL był już wzięty,
/// nic nie zmienia.  `f` może usnąć: zadanie wraca, być może na innym CPU,
/// który wtedy trzyma BKL (przełączenie zawsze pod BKL) – i tam go oddajemy.
#[allow(dead_code)]
pub fn with<R>(f: impl FnOnce() -> R) -> R {
    let irq = interrupts::are_enabled();
    interrupts::disable();
    let took = acquire_if_needed();
    if irq {
        interrupts::enable();
    }
    let r = f();
    if took {
        interrupts::disable();
        if held() {
            release();
        }
        if irq {
            interrupts::enable();
        }
    }
    r
}

/// (bilet następny, obsługiwany, właściciel) – diagnostyka / testy.
#[allow(dead_code)]
pub fn state() -> (u32, u32, u32) {
    (NEXT.load(Ordering::Relaxed), SERVING.load(Ordering::Relaxed), OWNER.load(Ordering::Relaxed))
}
