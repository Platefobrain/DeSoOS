// M17a: spinlocki – blokady na krótkie sekcje krytyczne przy wielu CPU.
//
// Dwa rodzaje:
//   * SpinLock<T>    – przerwania zostają włączone, ale wywłaszczanie tego
//                      CPU jest wstrzymane (licznik preempt w cpu.rs), żeby
//                      właściciel nie oddał CPU zadaniu, które czeka na tę
//                      samą blokadę.  NIE wolno jej brać w przerwaniu.
//   * IrqSpinLock<T> – dodatkowo wyłącza przerwania (stan IF przywracany
//                      przy zwolnieniu).  Dla danych, których dotyka też
//                      handler przerwania (na tym samym CPU zwykły SpinLock
//                      dałby zakleszczenie z samym sobą).
//
// Zasada dla przerwań: blokada brana w handlerze przerwania (IrqSpinLock)
// musi mieć poziom WYŻSZY niż każdy SpinLock trzymany z włączonymi
// przerwaniami – handler może wskoczyć w środek takiej sekcji.  Sprawdzacz
// kolejności to wychwytuje (przerwanie dopisuje się do blokad tego CPU).
//
// Diagnostyka (lockdep w wersji mini):
//   * kolejność: każda blokada ma poziom (`level`); na jednym CPU wolno brać
//     tylko blokady o poziomie WYŻSZYM niż wszystkie już trzymane – spisana
//     kolejność w ARCHITEKTURA.md, stałe w `level`.  Złamanie = panic z
//     nazwami obu blokad i miejscami w kodzie,
//   * rekurencja: ten sam CPU bierze blokadę, którą już ma -> panic (inaczej
//     kręciłby się w nieskończoność),
//   * zakleszczenie: czekanie dłużej niż DEADLOCK_REPORT_US (2 s, zegar
//     clock.rs – HPET, nie TSC) -> raport (kto czeka, gdzie; kto trzyma, od
//     kiedy i skąd), po DEADLOCK_PANIC_US (10 s) -> panic,
//   * spanie ze spinlockiem (schedule() przy trzymanej blokadzie) -> panic
//     (sched::schedule sprawdza `held_count`).
//
// Kolejność względem Big Kernel Lock: BKL jest "na zewnątrz" – trzymając
// spinlock nie wolno czekać na BKL.  Dlatego oddanie BKL w ticku zegara
// i w `hlt` jest pomijane, gdy CPU trzyma jakikolwiek spinlock.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::panic::Location;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::arch::x86_64::cpu::{self, MAX_CPUS};
use crate::arch::x86_64::{clock, interrupts};

/// Poziomy blokad (kolejność brania: rosnąco).  Spis i uzasadnienie:
/// ARCHITEKTURA.md, "Kolejność blokad".
#[allow(dead_code)]
pub mod level {
    /// VFS (zewnętrzna – woła block, heap, alokator).
    pub const VFS: u8 = 20;
    /// Warstwa block i sterowniki dysków.
    pub const BLOCK: u8 = 30;
    /// Procesy: tablica zombie, rodzina, deskryptory.
    /// v0.35.1: przekazywanie końców kanałów w komunikatach (zasada „bez cykli”);
    /// pod nią blokada kolejki kanału (PROCESS).
    pub const CHAN_XFER: u8 = 35;
    pub const PROCESS: u8 = 40;
    /// M19.b: listy obserwatorów `wait_many` (kanały, potoki, przerwania) –
    /// nad kolejkami kanałów / potoków (PROCESS), pod schedulerem (pobudka po
    /// zwolnieniu listy).  IrqSpinLock: czyta ją też handler przerwania.
    pub const WAITERS: u8 = 45;
    /// Scheduler (lista zadań, kolejki per CPU).
    pub const SCHED: u8 = 50;
    /// Przestrzenie adresowe / tablice stron.
    pub const PAGING: u8 = 55;
    /// M17a.d: stan wyjścia procesów – przechwycone stdout (testy), linia
    /// edytowana przez shell (komunikaty z tła).  Pod nią wolno alokować.
    pub const OUTPUT: u8 = 100;
    /// Testy.
    pub const TEST_OUTER: u8 = 200;
    pub const TEST_INNER: u8 = 210;
    /// Testy: blokada brana też w handlerze przerwania – wyżej niż każda
    /// trzymana przy włączonych przerwaniach (przerwanie zagnieżdża się w
    /// dowolnym miejscu kodu z IF = 1).
    pub const TEST_IRQ: u8 = 220;
    /// M17a.g2: dziennik zakończeń procesów – zapisywany z przerwania (kill
    /// procesu w ring 3) i z syscalli bez BKL; liść, bez alokacji.
    pub const EXIT_LOG: u8 = 225;
    /// M17a.c: heap kernela.  Alokować wolno z każdego miejsca – także z
    /// handlera przerwania, który wskoczył w sekcję pod dowolnym SpinLockiem
    /// (IF = 1) – więc heap i alokator ramek są prawie najbardziej wewnętrzne
    /// (wyżej niż wszystko, co ktoś trzyma, alokując).  Heap woła alokator
    /// ramek i TLB shootdown (zmniejszanie).
    pub const HEAP: u8 = 230;
    /// Alokator ramek (woła go heap i tablice stron).
    pub const FRAMES: u8 = 240;
    /// TLB shootdown – własna blokada żądania (tlb.rs, poza lockdep).
    pub const TLB: u8 = 250;
    /// Konsola / serial – własna blokada (console.rs, poza lockdep):
    /// logować wolno zawsze.
    pub const CONSOLE: u8 = 255;
}

/// Czekanie na spinlock dłuższe niż to = raport (sekcje krytyczne trwają
/// mikrosekundy), a dłuższe niż DEADLOCK_PANIC_US = panic.  Mierzone zegarem
/// clock.rs (HPET), bo TSC rdzeni bywa niezgodne.
pub const DEADLOCK_REPORT_US: u64 = 2_000_000;
pub const DEADLOCK_PANIC_US: u64 = 10_000_000;

/// Najwięcej blokad trzymanych naraz przez jeden CPU.
const MAX_HELD: usize = 8;
const HELD_IN_IRQ: usize = 1;

/// Trzymane blokady każdego CPU (adres `RawSpin`, 0 = puste miejsce).
/// v0.25.1: bit 0 adresu (RawSpin jest wyrównany do 64 B) = blokada wzięta w
/// handlerze przerwania.  Kolejność poziomów sprawdzamy tylko w obrębie jednego
/// kontekstu: handler przerwania (IrqSpinLock) nie łamie kolejności względem
/// blokady trzymanej przez przerwany kod – ten nie może jej trzymać z IF = 0 i
/// czekać na handler.  Wcześniej przerwanie MSI usbd (pobudka wait_many,
/// 'waiters' poziom 45) na CPU, którego przerwany kod trzymał 'stress-counter'
/// (210), dawało fałszywy PANIC lockdep przy pisaniu na klawiaturze USB w
/// trakcie stressu.  Rekurencja (ta sama blokada) – nadal sprawdzana zawsze.
static HELD: crate::arch::x86_64::percpu::PerCpu<[AtomicUsize; MAX_HELD]> = crate::per_cpu!([const { AtomicUsize::new(0) }; MAX_HELD]);
static HELD_COUNT: crate::arch::x86_64::percpu::PerCpu<AtomicUsize> = crate::per_cpu!(AtomicUsize::new(0));

/// Statystyka (komenda `cpus`, testy).
static ACQUIRES: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static CONTENDED: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static DEADLOCK_REPORTS: AtomicU64 = AtomicU64::new(0);

/// Liczba spinlocków trzymanych przez CPU `c` (raport watchdoga).
pub fn held_count_of(c: usize) -> usize {
    HELD_COUNT[c % MAX_CPUS].load(Ordering::Relaxed)
}

/// Liczba spinlocków trzymanych przez bieżący CPU.
#[inline]
pub fn held_count() -> usize {
    HELD_COUNT[cpu::id()].load(Ordering::Relaxed)
}

/// Pierwsza blokada trzymana przez ten CPU: (nazwa, miejsce wzięcia) – raporty.
pub fn first_held() -> Option<(&'static str, &'static str, u32)> {
    for slot in HELD[cpu::id()].iter() {
        let a = slot.load(Ordering::Relaxed) & !HELD_IN_IRQ;
        if a != 0 {
            let l = unsafe { &*(a as *const RawSpin) };
            let (f, line) = site_str(l.site.load(Ordering::Relaxed));
            return Some((l.name, f, line));
        }
    }
    None
}

/// (wzięcia, wzięcia z czekaniem, raporty zakleszczeń) – diagnostyka.
pub fn stats() -> (u64, u64, u64) {
    (ACQUIRES.get(), CONTENDED.get(), DEADLOCK_REPORTS.load(Ordering::Relaxed))
}

// ------------------------------------------------------------
// M17b.f: czas czekania (kręcenia) per nazwa blokady
// ------------------------------------------------------------

/// Wpis tabeli: wskaźnik i długość nazwy, liczba czekań, cykle TSC.
struct SpinSlot {
    name: AtomicUsize,
    len: AtomicUsize,
    n: AtomicU64,
    cyc: AtomicU64,
}

const SPIN_SLOTS: usize = 24;

/// Tabela per CPU (tylko ten CPU pisze; przerwanie może wejść w środek –
/// zajęcie wpisu przez CAS).
static SPIN_WAIT: crate::arch::x86_64::percpu::PerCpu<[SpinSlot; SPIN_SLOTS]> = crate::per_cpu!(
    [const { SpinSlot { name: AtomicUsize::new(0), len: AtomicUsize::new(0), n: AtomicU64::new(0), cyc: AtomicU64::new(0) } };
        SPIN_SLOTS]
);

fn spin_wait_record(name: &'static str, cycles: u64) {
    let key = name.as_ptr() as usize;
    for s in SPIN_WAIT[cpu::id()].iter() {
        let cur = s.name.load(Ordering::Relaxed);
        if cur == key || (cur == 0 && s.name.compare_exchange(0, key, Ordering::Relaxed, Ordering::Relaxed).is_ok()) {
            s.len.store(name.len(), Ordering::Relaxed);
            s.n.fetch_add(1, Ordering::Relaxed);
            s.cyc.fetch_add(cycles, Ordering::Relaxed);
            return;
        }
    }
}

pub fn spin_wait_reset() {
    for t in SPIN_WAIT.iter() {
        for s in t.iter() {
            s.n.store(0, Ordering::Relaxed);
            s.cyc.store(0, Ordering::Relaxed);
        }
    }
}

/// (nazwa, czekania, cykle) – zsumowane ze wszystkich CPU, malejąco po cyklach.
pub fn spin_wait_stats() -> alloc::vec::Vec<(&'static str, u64, u64)> {
    let mut v: alloc::vec::Vec<(&'static str, u64, u64)> = alloc::vec::Vec::new();
    for t in SPIN_WAIT.iter() {
        for s in t.iter() {
            let p = s.name.load(Ordering::Relaxed);
            let len = s.len.load(Ordering::Relaxed);
            let n = s.n.load(Ordering::Relaxed);
            if p == 0 || len == 0 || n == 0 {
                continue;
            }
            let name: &'static str =
                unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(p as *const u8, len)) };
            match v.iter_mut().find(|e| e.0 == name) {
                Some(e) => {
                    e.1 += n;
                    e.2 = e.2.saturating_add(s.cyc.load(Ordering::Relaxed));
                }
                None => v.push((name, n, s.cyc.load(Ordering::Relaxed))),
            }
        }
    }
    v.sort_by(|a, b| b.2.cmp(&a.2));
    v
}

/// Część wspólna obu rodzajów: stan blokady + diagnostyka.  M17b.e: w
/// osobnej linii cache – sąsiednia gorąca blokada nie spowalnia tej.
#[repr(align(64))]
pub struct RawSpin {
    locked: AtomicBool,
    /// Numer CPU właściciela + 1 (0 = wolna).
    owner: AtomicU32,
    /// `&'static Location` miejsca wzięcia (diagnostyka).
    site: AtomicUsize,
    /// Tick zegara systemowego (ms) chwili wzięcia – tani i wspólny dla CPU.
    since: AtomicU64,
    name: &'static str,
    level: u8,
}

/// Złamanie zasad blokad: opis (używają testy, żeby nie panikować).
#[derive(Debug, PartialEq, Eq)]
pub enum LockError {
    /// Ten CPU już trzyma tę blokadę.
    Recursive,
    /// Kolejność: trzymana blokada (nazwa, poziom) ma poziom >= nowej.
    Order { held: &'static str, held_level: u8 },
    /// Za dużo blokad naraz.
    TooMany,
}

fn site_str(site: usize) -> (&'static str, u32) {
    if site == 0 {
        return ("?", 0);
    }
    let l: &'static Location<'static> = unsafe { &*(site as *const Location<'static>) };
    (l.file(), l.line())
}

impl RawSpin {
    pub const fn new(name: &'static str, level: u8) -> Self {
        RawSpin {
            locked: AtomicBool::new(false),
            owner: AtomicU32::new(0),
            site: AtomicUsize::new(0),
            since: AtomicU64::new(0),
            name,
            level,
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Czy wzięcie tej blokady teraz, na tym CPU, łamie zasady.
    pub fn check(&self) -> Result<(), LockError> {
        let me = cpu::id();
        if self.owner.load(Ordering::Relaxed) == me as u32 + 1 {
            return Err(LockError::Recursive);
        }
        let n = HELD_COUNT[me].load(Ordering::Relaxed);
        if n >= MAX_HELD {
            return Err(LockError::TooMany);
        }
        let in_irq = cpu::in_interrupt();
        for slot in HELD[me].iter() {
            let a = slot.load(Ordering::Relaxed);
            // W przerwaniu porównujemy tylko z blokadami wziętymi w przerwaniu.
            if a != 0 && (!in_irq || a & HELD_IN_IRQ != 0) {
                let other = unsafe { &*((a & !HELD_IN_IRQ) as *const RawSpin) };
                if other.level >= self.level {
                    return Err(LockError::Order { held: other.name, held_level: other.level });
                }
            }
        }
        Ok(())
    }

    #[track_caller]
    fn acquire(&self) {
        self.acquire_with(Location::caller(), DEADLOCK_REPORT_US, DEADLOCK_PANIC_US);
    }

    fn acquire_with(&self, caller: &'static Location<'static>, report_after: u64, panic_after: u64) {
        if let Err(e) = self.check() {
            let (f, l) = (caller.file(), caller.line());
            match e {
                LockError::Recursive => {
                    panic!("spinlock '{}': CPU {} takes it again at {}:{} (deadlock with itself)", self.name, cpu::id(), f, l)
                }
                LockError::Order { held, held_level } => panic!(
                    "spinlock order: '{}' (level {}) taken at {}:{} while holding '{}' (level {}) - see ARCHITEKTURA.md",
                    self.name, self.level, f, l, held, held_level
                ),
                LockError::TooMany => panic!("spinlock '{}': more than {} locks held at {}:{}", self.name, MAX_HELD, f, l),
            }
        }
        ACQUIRES.add(1);
        if !self.try_take() {
            CONTENDED.add(1);
            // M17b.f: czas kręcenia per nazwa blokady (ten sam CPU – wywłaszczanie
            // wyłączone przed acquire).
            let spin_t0 = super::bkl::rdtsc();
            // M17a.g14: wykrywanie zakleszczeń – HPET (TSC bywa niewiarygodny:
            // TCG, różne TSC rdzeni), czytany dopiero przy pierwszym sprawdzeniu
            // (co 1024 obroty), nigdy pod blokadą.
            let mut start = 0u64;
            let mut reported = false;
            let mut n: u32 = 0;
            loop {
                while self.locked.load(Ordering::Relaxed) {
                    core::hint::spin_loop();
                    n = n.wrapping_add(1);
                    // M17a.b: IrqSpinLock czeka z IF = 0 – TLB shootdown tutaj.
                    if n % 64 == 0 {
                        crate::arch::x86_64::tlb::poll_from_wait();
                    }
                    if n % 1024 != 0 {
                        continue;
                    }
                    crate::arch::x86_64::smp::watchdog_poll();
                    if start == 0 {
                        start = clock::stamp().max(1);
                    }
                    let waited = clock::elapsed_us(start);
                    if waited > report_after && !reported {
                        reported = true;
                        self.report_deadlock(caller, waited);
                    }
                    if waited > panic_after {
                        panic!("spinlock '{}': deadlock (CPU {} waited > {} ms)", self.name, cpu::id(), panic_after / 1000);
                    }
                }
                if self.try_take() {
                    break;
                }
            }
            spin_wait_record(self.name, super::bkl::rdtsc().saturating_sub(spin_t0));
        }
        self.owner.store(cpu::id() as u32 + 1, Ordering::Relaxed);
        self.site.store(caller as *const Location as usize, Ordering::Relaxed);
        self.since.store(crate::time::ticks(), Ordering::Relaxed);
        self.push_held();
    }

    #[inline]
    fn try_take(&self) -> bool {
        !self.locked.load(Ordering::Relaxed)
            && self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    fn release(&self) {
        self.pop_held();
        self.owner.store(0, Ordering::Relaxed);
        self.site.store(0, Ordering::Relaxed);
        self.locked.store(false, Ordering::Release);
    }

    fn push_held(&self) {
        let me = cpu::id();
        for slot in HELD[me].iter() {
            if slot.load(Ordering::Relaxed) == 0 {
                let tag = if cpu::in_interrupt() { HELD_IN_IRQ } else { 0 };
                slot.store(self as *const RawSpin as usize | tag, Ordering::Relaxed);
                HELD_COUNT[me].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }

    fn pop_held(&self) {
        let me = cpu::id();
        let addr = self as *const RawSpin as usize;
        for slot in HELD[me].iter() {
            if slot.load(Ordering::Relaxed) & !HELD_IN_IRQ == addr {
                slot.store(0, Ordering::Relaxed);
                HELD_COUNT[me].fetch_sub(1, Ordering::Relaxed);
                return;
            }
        }
    }

    #[cold]
    fn report_deadlock(&self, caller: &Location, waited: u64) {
        DEADLOCK_REPORTS.fetch_add(1, Ordering::Relaxed);
        let owner = self.owner.load(Ordering::Relaxed);
        let (hf, hl) = site_str(self.site.load(Ordering::Relaxed));
        let held_for = crate::time::ticks().saturating_sub(self.since.load(Ordering::Relaxed));
        crate::serial_println!(
            "[LOCK] possible deadlock: CPU {} waits {} ms for '{}' at {}:{}; held by CPU {} for {} ms, taken at {}:{}",
            cpu::id(),
            waited / 1000,
            self.name,
            caller.file(),
            caller.line(),
            owner as i64 - 1,
            held_for,
            hf,
            hl
        );
    }

    /// Testy: czeka najwyżej `us` mikrosekund; Err = (CPU właściciela, miejsce).
    #[allow(dead_code)]
    pub fn try_lock_for(&self, us: u64) -> Result<(), (i64, &'static str, u32)> {
        let start = clock::stamp();
        while !self.try_take() {
            if clock::elapsed_us(start) > us {
                let (f, l) = site_str(self.site.load(Ordering::Relaxed));
                return Err((self.owner.load(Ordering::Relaxed) as i64 - 1, f, l));
            }
            crate::arch::x86_64::tlb::poll_from_wait();
            core::hint::spin_loop();
        }
        self.locked.store(false, Ordering::Release);
        Ok(())
    }

    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

// ------------------------------------------------------------
// SpinLock<T>
// ------------------------------------------------------------

pub struct SpinLock<T> {
    raw: RawSpin,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

pub struct SpinGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> SpinLock<T> {
    pub const fn new(name: &'static str, level: u8, value: T) -> Self {
        SpinLock { raw: RawSpin::new(name, level), data: UnsafeCell::new(value) }
    }

    /// Bierze blokadę.  Wstrzymuje wywłaszczanie tego CPU do zwolnienia.
    #[track_caller]
    pub fn lock(&self) -> SpinGuard<'_, T> {
        debug_assert!(!cpu::in_interrupt(), "SpinLock '{}' in an interrupt - use IrqSpinLock", self.raw.name);
        cpu::preempt_disable();
        self.raw.acquire();
        SpinGuard { lock: self }
    }

    pub fn raw(&self) -> &RawSpin {
        &self.raw
    }

    /// Testy: jak `lock`, ale raport zakleszczenia już po `report_after`
    /// mikrosekundach (bez panic).
    #[allow(dead_code)]
    #[track_caller]
    pub fn lock_reporting_after(&self, report_after: u64) -> SpinGuard<'_, T> {
        cpu::preempt_disable();
        self.raw.acquire_with(Location::caller(), report_after, u64::MAX);
        SpinGuard { lock: self }
    }
}

impl<T> Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.raw.release();
        cpu::preempt_enable();
    }
}

// ------------------------------------------------------------
// IrqSpinLock<T>
// ------------------------------------------------------------

pub struct IrqSpinLock<T> {
    raw: RawSpin,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for IrqSpinLock<T> {}
unsafe impl<T: Send> Send for IrqSpinLock<T> {}

pub struct IrqSpinGuard<'a, T> {
    lock: &'a IrqSpinLock<T>,
    irq_was_enabled: bool,
}

impl<T> IrqSpinLock<T> {
    pub const fn new(name: &'static str, level: u8, value: T) -> Self {
        IrqSpinLock { raw: RawSpin::new(name, level), data: UnsafeCell::new(value) }
    }

    /// Bierze blokadę z wyłączonymi przerwaniami (także z handlera przerwania).
    #[track_caller]
    pub fn lock(&self) -> IrqSpinGuard<'_, T> {
        let irq_was_enabled = interrupts::are_enabled();
        interrupts::disable();
        cpu::preempt_disable();
        self.raw.acquire();
        IrqSpinGuard { lock: self, irq_was_enabled }
    }

    pub fn raw(&self) -> &RawSpin {
        &self.raw
    }
}

impl<T> Deref for IrqSpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for IrqSpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for IrqSpinGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.raw.release();
        cpu::preempt_enable();
        if self.irq_was_enabled {
            interrupts::enable();
        }
    }
}

// ------------------------------------------------------------
// M17a.g16: RwSpinLock – kręcąca się blokada czytelnicy–pisarz
// ------------------------------------------------------------
//
// Dla struktur czytanych bardzo często, zmienianych rzadziej, z sekcjami
// rzędu µs (drzewo katalogów ramfs).  Usypiająca KRwLock płaciła za każde
// czekanie uśpieniem i pobudką przez scheduler (Legion v0.17.26: 438 tys.
// czekań odczytu, 505 s).  Zasady jak SpinLock: wywłaszczanie wstrzymane
// (licznik preempt), nie wolno spać ani brać KMutex pod nią (schedule()
// sprawdza held_count), nie w przerwaniu.  Pierwszeństwo pisarza: czekający
// pisarz zatrzymuje NOWYCH czytelników (bez rekurencji odczytu!).  Bez
// lockdep (nie ma poziomu) – pod nią wolno brać heap / ramki.

const RW_WRITER: u32 = 1 << 31;

pub struct RwSpinLock {
    name: &'static str,
    /// RW_WRITER | liczba czytelników.
    state: AtomicU32,
    writers_waiting: AtomicU32,
    registered: AtomicBool,
    // Statystyka (`cpus`): wzięcia, wzięcia z czekaniem, µs czekania (TSC,
    // ten sam CPU – czekamy bez wywłaszczenia), µs trzymania (TSC).
    reads: AtomicU64,
    writes: AtomicU64,
    read_waited: AtomicU64,
    write_waited: AtomicU64,
    wait_us: AtomicU64,
    hold_tsc: AtomicU64,
}

/// Rejestr RwSpinLock z nazwą (statystyka) – wpis przy pierwszym wzięciu,
/// wypis w Drop (blokada bywa częścią obiektu na heapie).
static NAMED_RWSPIN: [AtomicUsize; 8] = [const { AtomicUsize::new(0) }; 8];

pub struct RwSpinStats {
    pub name: &'static str,
    pub reads: u64,
    pub writes: u64,
    pub read_waited: u64,
    pub write_waited: u64,
    pub wait_us: u64,
    pub held_us: u64,
}

pub fn rwspin_stats() -> alloc::vec::Vec<RwSpinStats> {
    let tsc_ms = crate::arch::x86_64::lapic::tsc_per_ms();
    NAMED_RWSPIN
        .iter()
        .filter_map(|a| {
            let p = a.load(Ordering::Acquire);
            if p == 0 {
                return None;
            }
            let l = unsafe { &*(p as *const RwSpinLock) };
            Some(RwSpinStats {
                name: l.name,
                reads: l.reads.load(Ordering::Relaxed),
                writes: l.writes.load(Ordering::Relaxed),
                read_waited: l.read_waited.load(Ordering::Relaxed),
                write_waited: l.write_waited.load(Ordering::Relaxed),
                wait_us: l.wait_us.load(Ordering::Relaxed),
                held_us: if tsc_ms == 0 { 0 } else { l.hold_tsc.load(Ordering::Relaxed).saturating_mul(1000) / tsc_ms },
            })
        })
        .collect()
}

pub struct RwSpinReadGuard<'a> {
    lock: &'a RwSpinLock,
    t0: u64,
}

pub struct RwSpinWriteGuard<'a> {
    lock: &'a RwSpinLock,
    t0: u64,
}

impl RwSpinLock {
    pub const fn new(name: &'static str) -> Self {
        RwSpinLock {
            name,
            state: AtomicU32::new(0),
            writers_waiting: AtomicU32::new(0),
            registered: AtomicBool::new(false),
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            read_waited: AtomicU64::new(0),
            write_waited: AtomicU64::new(0),
            wait_us: AtomicU64::new(0),
            hold_tsc: AtomicU64::new(0),
        }
    }

    fn register(&self) {
        if self.registered.load(Ordering::Relaxed) || self.registered.swap(true, Ordering::AcqRel) {
            return;
        }
        let me = self as *const RwSpinLock as usize;
        for slot in NAMED_RWSPIN.iter() {
            if slot.compare_exchange(0, me, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                return;
            }
        }
    }

    /// Kręcenie z wykrywaniem zakleszczeń (HPET co 1024 obroty, jak RawSpin).
    fn spin_wait(&self, mut ready: impl FnMut() -> bool) -> u64 {
        let (tsc0, cpu0) = clock::tsc_cpu();
        let mut start = 0u64;
        let mut reported = false;
        let mut n: u32 = 0;
        while !ready() {
            core::hint::spin_loop();
            n = n.wrapping_add(1);
            // P4.b: czekający z IF = 0 (tablica zadań) potwierdza TLB shootdown.
            if n % 64 == 0 {
                crate::arch::x86_64::tlb::poll_from_wait();
            }
            if n % 1024 != 0 {
                continue;
            }
            crate::arch::x86_64::smp::watchdog_poll();
            if start == 0 {
                start = clock::stamp().max(1);
            }
            let waited = clock::elapsed_us(start);
            if waited > DEADLOCK_REPORT_US && !reported {
                reported = true;
                DEADLOCK_REPORTS.fetch_add(1, Ordering::Relaxed);
                crate::serial_println!(
                    "[LOCK] possible deadlock: CPU {} waits {} ms for rwlock '{}' (state {:#x}, writers waiting {})",
                    cpu::id(),
                    waited / 1000,
                    self.name,
                    self.state.load(Ordering::Relaxed),
                    self.writers_waiting.load(Ordering::Relaxed)
                );
            }
            if waited > DEADLOCK_PANIC_US {
                panic!("rwlock '{}': deadlock (CPU {} waited > {} ms)", self.name, cpu::id(), DEADLOCK_PANIC_US / 1000);
            }
        }
        clock::tsc_wait_us(tsc0, cpu0)
    }

    fn try_read(&self) -> bool {
        let s = self.state.load(Ordering::Relaxed);
        s & RW_WRITER == 0
            && self.writers_waiting.load(Ordering::Relaxed) == 0
            && self.state.compare_exchange_weak(s, s + 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    fn try_write(&self) -> bool {
        self.state.compare_exchange_weak(0, RW_WRITER, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }

    fn enter(&self) {
        debug_assert!(!cpu::in_interrupt(), "RwSpinLock '{}' in an interrupt", self.name);
        self.register();
        cpu::preempt_disable();
        // Liczy się jako trzymany spinlock: schedule() z nim = panic.
        HELD_COUNT[cpu::id()].fetch_add(1, Ordering::Relaxed);
        ACQUIRES.add(1);
    }

    fn leave(&self, t0: u64) {
        self.hold_tsc.fetch_add(crate::sched::bkl::rdtsc().wrapping_sub(t0) & ((1 << 48) - 1), Ordering::Relaxed);
        HELD_COUNT[cpu::id()].fetch_sub(1, Ordering::Relaxed);
        cpu::preempt_enable();
    }

    pub fn read(&self) -> RwSpinReadGuard<'_> {
        self.enter();
        if !self.try_read() {
            CONTENDED.add(1);
            let us = self.spin_wait(|| self.try_read());
            self.read_waited.fetch_add(1, Ordering::Relaxed);
            self.wait_us.fetch_add(us, Ordering::Relaxed);
        }
        self.reads.fetch_add(1, Ordering::Relaxed);
        RwSpinReadGuard { lock: self, t0: crate::sched::bkl::rdtsc() }
    }

    pub fn write(&self) -> RwSpinWriteGuard<'_> {
        self.enter();
        if !self.try_write() {
            CONTENDED.add(1);
            // Pierwszeństwo: nowi czytelnicy czekają, aż wejdziemy.
            self.writers_waiting.fetch_add(1, Ordering::Relaxed);
            let us = self.spin_wait(|| self.try_write());
            self.writers_waiting.fetch_sub(1, Ordering::Relaxed);
            self.write_waited.fetch_add(1, Ordering::Relaxed);
            self.wait_us.fetch_add(us, Ordering::Relaxed);
        }
        self.writes.fetch_add(1, Ordering::Relaxed);
        RwSpinWriteGuard { lock: self, t0: crate::sched::bkl::rdtsc() }
    }

    /// Diagnostyka / testy: (pisarz, czytelnicy).
    #[allow(dead_code)]
    pub fn state(&self) -> (bool, u32) {
        let s = self.state.load(Ordering::Relaxed);
        (s & RW_WRITER != 0, s & !RW_WRITER)
    }
}

impl Drop for RwSpinReadGuard<'_> {
    fn drop(&mut self) {
        self.lock.state.fetch_sub(1, Ordering::Release);
        self.lock.leave(self.t0);
    }
}

impl Drop for RwSpinWriteGuard<'_> {
    fn drop(&mut self) {
        self.lock.state.fetch_and(!RW_WRITER, Ordering::Release);
        self.lock.leave(self.t0);
    }
}

impl Drop for RwSpinLock {
    fn drop(&mut self) {
        let me = self as *const RwSpinLock as usize;
        for slot in NAMED_RWSPIN.iter() {
            let _ = slot.compare_exchange(me, 0, Ordering::AcqRel, Ordering::Relaxed);
        }
    }
}
