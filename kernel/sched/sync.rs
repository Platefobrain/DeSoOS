// M12: synchronizacja zadań – kolejki oczekiwania i mutex.
//
// WaitQueue: zadanie usypia, dopóki warunek nie jest spełniony; budzi je
// `wake_all()` (np. z handlera przerwania) albo upływ czasu.  Warunek jest
// sprawdzany przy wyłączonych przerwaniach, więc pobudka nie może
// "przepaść" między sprawdzeniem a uśpieniem.  Bez schedulera (wczesny
// start) czekanie to stare `sti; hlt`.
//
// Mutex: blokada usypiająca (czekające zadanie nie zajmuje CPU),
// reentrant – to samo zadanie może ją wziąć wiele razy (VFS woła sam
// siebie, np. write_file -> stat).  Nie wolno jej brać w przerwaniu.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::{can_block, current_id, wake_channel, wake_one_channel};
use crate::arch::x86_64::interrupts;

pub struct WaitQueue {
    // Adres kolejki to identyfikator kanału – pole nie może mieć rozmiaru
    // zero (statyczne ZST mogłyby dzielić adres).
    _id: AtomicU8,
}

impl WaitQueue {
    pub const fn new() -> Self {
        WaitQueue { _id: AtomicU8::new(0) }
    }

    fn channel(&self) -> usize {
        self as *const WaitQueue as usize
    }

    /// Budzi wszystkie zadania czekające w tej kolejce (także z przerwania).
    pub fn wake_all(&self) {
        wake_channel(self.channel());
    }

    /// M17a.g10: budzi jedno – najdłużej czekające; `true` – obudzono.
    pub fn wake_one(&self) -> bool {
        wake_one_channel(self.channel())
    }

    /// Czeka, aż `cond()` będzie prawdą albo minie `timeout_ms`.
    /// Zwraca wynik warunku.  Wymaga włączonych przerwań.
    pub fn wait_until(&self, mut cond: impl FnMut() -> bool, timeout_ms: Option<u64>) -> bool {
        // M17a.f2: sprawdzenie warunku i uśpienie pod blokadą schedulera
        // (sched::wait_event); pobudka (wake_channel) też ją bierze, więc nie
        // przepada – bez BKL (do f1 gwarantował to BKL).
        let was_enabled = interrupts::are_enabled();
        assert!(was_enabled, "wait_until with interrupts disabled");
        let deadline = match timeout_ms {
            Some(ms) => crate::time::ticks() + crate::time::ms_to_ticks(ms) + 1,
            None => u64::MAX,
        };
        if can_block() {
            return super::wait_event(self.channel(), deadline, &mut cond);
        }
        self.wait_until_hlt(cond, deadline)
    }

    /// Bez schedulera (wczesny start) albo w zadaniu idle: `sti; hlt`.
    fn wait_until_hlt(&self, mut cond: impl FnMut() -> bool, deadline: u64) -> bool {
        let result = loop {
            interrupts::disable();
            if cond() {
                break true;
            }
            if crate::time::ticks() >= deadline {
                break false;
            }
            // sti+hlt atomowo: IRQ nie przepadnie między sprawdzeniem a hlt.
            interrupts::enable_and_hlt();
        };
        interrupts::enable();
        result
    }
}

/// Blokada reentrant bez danych (strzeże stanu modułu, np. VFS).
pub struct KMutex {
    owner: AtomicU64, // 0 = wolna
    depth: AtomicU32,
    queue: WaitQueue,
    contended: AtomicU64,
    // M17a.g5: statystyka (blokady z nazwą – `cpus`: "sleeping locks").
    name: &'static str,
    registered: AtomicBool,
    acquires: AtomicU64,
    /// Wzięcia, przy których trzeba było czekać (raz na `lock`).
    waited: AtomicU64,
    /// M17a.g8: wzięcia po krótkim kręceniu się, bez usypiania.
    spun: AtomicU64,
    /// M17a.g10: ile zadań czeka (zwolnienie budzi jedno, jeśli > 0).
    sleepers: AtomicU32,
    wait_us: AtomicU64,
    /// M17a.g6: czas trzymania próbkowany – co HOLD_SAMPLE-te wzięcie znacznik
    /// HPET (0 = to wzięcie nie jest próbką), suma µs próbek × HOLD_SAMPLE.
    /// (v0.17.14 mierzyła TSC – trzymający śpi i zmienia CPU, a TSC rdzeni
    /// Legiona się różnią: 33 815 s trzymania w 60 s testu.)
    taken_stamp: AtomicU64,
    /// M17a.g13: CPU, na którym wzięto (TSC porównywalny tylko na nim).
    taken_cpu: AtomicU32,
    hold_us: AtomicU64,
}

/// Co które wzięcie mierzy czas trzymania (odczyt HPET kosztuje ~1 µs).
const HOLD_SAMPLE: u64 = 16;

/// M17a.g8: ile obrotów (`pause`) kręcić się przed uśpieniem – rzędu
/// kilkudziesięciu µs.  Tylko przy kilku CPU (na jednym trzymający i tak
/// nie ruszy, dopóki nie oddamy CPU).
/// M17a.g9: wyłączone (0) – na Legionie (v0.17.17) przy dużym tłoku kręcenie
/// spalało CPU (6% idle) i obniżyło przepustowość o 9%; zostawione jako
/// pokrętło do pomiarów.
/// M17a.g15: włączone krótko (200 × `pause` – kilka µs): po g13/g14 sekcje
/// trwają mikrosekundy (wcześniej wydłużały je odczyty HPET / RTC pod
/// blokadą), a uśpienie i pobudka kosztują dwa przejścia przez scheduler.
const SPIN_ITERS: u32 = 200;

/// Kręci się, aż `ready()` albo limit obrotów; `true` = gotowe.
fn spin_until(mut ready: impl FnMut() -> bool) -> bool {
    if SPIN_ITERS == 0 || !crate::arch::x86_64::smp::active() {
        return false;
    }
    for _ in 0..SPIN_ITERS {
        if ready() {
            return true;
        }
        core::hint::spin_loop();
    }
    ready()
}

// M17a.g5: rejestr nazwanych KMutex (statyczne – adres stały).  Wpis przy
// pierwszym `lock`.
const MAX_NAMED: usize = 16;
static NAMED: [core::sync::atomic::AtomicUsize; MAX_NAMED] = [const { core::sync::atomic::AtomicUsize::new(0) }; MAX_NAMED];

/// Statystyka jednej blokady usypiającej.
pub struct KMutexStats {
    pub name: &'static str,
    pub acquires: u64,
    pub waited: u64,
    pub spun: u64,
    pub wait_us: u64,
    pub held_us: u64,
}

/// Wszystkie nazwane blokady, które były już brane (sortowane: czekanie +
/// trzymanie malejąco).
pub fn kmutex_stats() -> alloc::vec::Vec<KMutexStats> {
    let mut v: alloc::vec::Vec<KMutexStats> = NAMED
        .iter()
        .filter_map(|a| {
            let p = a.load(Ordering::Acquire);
            if p == 0 {
                return None;
            }
            let m = unsafe { &*(p as *const KMutex) };
            Some(KMutexStats {
                name: m.name,
                acquires: m.acquires.load(Ordering::Relaxed),
                waited: m.waited.load(Ordering::Relaxed),
                spun: m.spun.load(Ordering::Relaxed),
                wait_us: m.wait_us.load(Ordering::Relaxed),
                held_us: m.hold_us.load(Ordering::Relaxed),
            })
        })
        .collect();
    v.sort_by(|a, b| (b.wait_us + b.held_us).cmp(&(a.wait_us + a.held_us)));
    v
}

pub struct KMutexGuard<'a> {
    mutex: &'a KMutex,
}

impl KMutex {
    pub const fn new() -> Self {
        Self::new_named("")
    }

    /// M17a.g5: blokada z nazwą – liczona w `cpus` ("sleeping locks").
    /// Tylko dla blokad statycznych (rejestr trzyma adres).
    pub const fn new_named(name: &'static str) -> Self {
        KMutex {
            owner: AtomicU64::new(0),
            depth: AtomicU32::new(0),
            queue: WaitQueue::new(),
            contended: AtomicU64::new(0),
            name,
            registered: AtomicBool::new(false),
            acquires: AtomicU64::new(0),
            waited: AtomicU64::new(0),
            spun: AtomicU64::new(0),
            sleepers: AtomicU32::new(0),
            wait_us: AtomicU64::new(0),
            taken_stamp: AtomicU64::new(0),
            taken_cpu: AtomicU32::new(0),
            hold_us: AtomicU64::new(0),
        }
    }

    fn register(&self) {
        if self.name.is_empty() || self.registered.load(Ordering::Relaxed) {
            return;
        }
        if self.registered.swap(true, Ordering::AcqRel) {
            return;
        }
        let me = self as *const KMutex as usize;
        for slot in NAMED.iter() {
            if slot.compare_exchange(0, me, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                return;
            }
        }
    }

    fn try_take(&self, me: u64) -> bool {
        // M17a.e: compare_exchange – dwa CPU bez BKL nie wezmą jej naraz
        // (wcześniej wystarczało without_interrupts: jeden CPU w kernelu).
        match self.owner.compare_exchange(0, me, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => {
                self.depth.store(1, Ordering::Relaxed);
                if !self.name.is_empty() {
                    let sample = self.acquires.load(Ordering::Relaxed) % HOLD_SAMPLE == 0;
                    // M17a.g13: TSC + CPU (rdtscp), nie HPET – odczyt pod blokadą.
                    if sample {
                        let (t, c) = crate::arch::x86_64::clock::tsc_cpu();
                        self.taken_cpu.store(c, Ordering::Relaxed);
                        self.taken_stamp.store(t.max(1), Ordering::Relaxed);
                    } else {
                        self.taken_stamp.store(0, Ordering::Relaxed);
                    }
                }
                true
            }
            Err(owner) if owner == me => {
                self.depth.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(_) => false,
        }
    }

    pub fn lock(&self) -> KMutexGuard<'_> {
        let me = current_id();
        self.register();
        if !self.try_take(me) {
            self.contended.fetch_add(1, Ordering::Relaxed);
            // M17a.g8: najpierw chwilę kręcimy się – sekcje pod tymi blokadami
            // trwają mikrosekundy, a uśpienie i pobudka idą przez scheduler
            // (Legion v0.17.16: ~1 ms na jedno czekanie).
            if spin_until(|| self.owner.load(Ordering::Relaxed) == 0) && self.try_take(me) {
                self.spun.fetch_add(1, Ordering::Relaxed);
                self.acquires.fetch_add(1, Ordering::Relaxed);
                return KMutexGuard { mutex: self };
            }
            // M17a.g5: czekanie liczone raz na `lock` (czas – zegar HPET).
            let t0 = crate::arch::x86_64::clock::stamp();
            // M17a.g10: zgłoszenie czekania PRZED sprawdzeniem warunku pod
            // blokadą schedulera – zwalniający, który zobaczy sleepers > 0,
            // budzi jednego; jeśli to zadanie jeszcze nie śpi, warunek
            // (owner == 0) sprawdzony pod tą samą blokadą nie da mu zasnąć.
            self.sleepers.fetch_add(1, Ordering::SeqCst);
            // M17a.g13: koniec czekania odczytany PRZED wzięciem (HPET pod
            // blokadą wydłużał jej trzymanie).
            let mut t1 = t0;
            while !self.try_take(me) {
                self.contended.fetch_add(1, Ordering::Relaxed);
                self.queue.wait_until(|| self.owner.load(Ordering::SeqCst) == 0, None);
                t1 = crate::arch::x86_64::clock::stamp();
            }
            self.sleepers.fetch_sub(1, Ordering::SeqCst);
            self.waited.fetch_add(1, Ordering::Relaxed);
            self.wait_us.fetch_add(crate::arch::x86_64::clock::us_between(t0, t1), Ordering::Relaxed);
        }
        self.acquires.fetch_add(1, Ordering::Relaxed);
        KMutexGuard { mutex: self }
    }

    /// Ile razy ktoś musiał czekać (diagnostyka / testy).
    #[allow(dead_code)]
    pub fn contended(&self) -> u64 {
        self.contended.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub fn is_locked(&self) -> bool {
        self.owner.load(Ordering::Relaxed) != 0
    }
}

impl Drop for KMutexGuard<'_> {
    fn drop(&mut self) {
        let m = self.mutex;
        let release = if m.depth.fetch_sub(1, Ordering::Relaxed) == 1 {
            let t0 = m.taken_stamp.load(Ordering::Relaxed);
            if t0 != 0 {
                // Zmiana CPU w trakcie (wywłaszczenie) – próbka pominięta.
                if let Some(us) = crate::arch::x86_64::clock::tsc_us_on(t0, m.taken_cpu.load(Ordering::Relaxed)) {
                    m.hold_us.fetch_add(us * HOLD_SAMPLE, Ordering::Relaxed);
                }
            }
            m.owner.store(0, Ordering::SeqCst);
            true
        } else {
            false
        };
        // M17a.g10: budzimy jednego czekającego (nie wszystkich).  Wzięty
        // przez kogoś innego w międzyczasie – ten, kto weźmie, przy zwolnieniu
        // obudzi następnego (sleepers nadal > 0).
        if release && m.sleepers.load(Ordering::SeqCst) > 0 {
            m.queue.wake_one();
        }
    }
}

/// Mutex z danymi (jak spin::Mutex, ale usypiający).
#[allow(dead_code)]
pub struct Mutex<T> {
    lock: KMutex,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for Mutex<T> {}

#[allow(dead_code)]
pub struct MutexGuard<'a, T> {
    _guard: KMutexGuard<'a>,
    data: *mut T,
}

#[allow(dead_code)]
impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Mutex { lock: KMutex::new(), data: UnsafeCell::new(value) }
    }

    /// M17a.g5: z nazwą w statystyce (tylko dla statycznych).
    pub const fn new_named(name: &'static str, value: T) -> Self {
        Mutex { lock: KMutex::new_named(name), data: UnsafeCell::new(value) }
    }

    /// Uwaga: reentrant – drugi `lock()` w tym samym zadaniu dałby dwie
    /// referencje `&mut` do tych samych danych, więc dla `Mutex<T>` jest to
    /// zabronione (panic).
    pub fn lock(&self) -> MutexGuard<'_, T> {
        let guard = self.lock.lock();
        assert!(self.lock.depth.load(Ordering::Relaxed) == 1, "Mutex<T> locked twice by the same task");
        MutexGuard { _guard: guard, data: self.data.get() }
    }
}

impl<T> core::ops::Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.data }
    }
}

impl<T> core::ops::DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.data }
    }
}

// ------------------------------------------------------------
// M17a.g6: KRwLock – usypiająca blokada czytelnicy–pisarz (VFS)
// ------------------------------------------------------------
//
// Wielu czytelników naraz albo jeden pisarz.  Jak KMutex: reentrant –
// pisarz może wziąć ją ponownie (do odczytu i do zapisu), czytelnik może
// ponownie czytać (zagnieżdżony odczyt nie czeka na pisarza w kolejce –
// inaczej zakleszczyłby się z nim).  Czytelnik NIE może przejść na zapis
// (panic – inaczej czekałby na samego siebie).  Pisarz czekający w kolejce
// zatrzymuje nowych czytelników (nie zagłodzą go).
//
// Stan pod IrqSpinLock (krótkie sekcje, bez alokacji): przerwanie w sekcji
// pod zwykłym SpinLock bierze BKL – zakleszczenie z CPU, który trzyma BKL
// i czeka na tę samą blokadę (zasada z ARCHITEKTURA.md).
//
// M17a.g10: osobne kolejki czytelników i pisarzy (każda ze swoim licznikiem
// zmian – warunek czekania to jeden atomik).  Zwolnienie budzi tylko tych,
// którzy mogą wejść:
//   * pisarz kończy: czekający czytelnicy – całą grupą (i mogą wejść mimo
//     czekających pisarzy: `readers_pass`), a gdy ich nie ma – JEDEN pisarz;
//   * ostatni czytelnik wychodzi: JEDEN pisarz.
// Czytelnicy i pisarze się przeplatają (żadna strona nie zagłodzi drugiej).
// Wcześniej każde zwolnienie budziło wszystkich (Legion v0.17.19: drzewo
// ramfs – 1108 s czekania).

const MAX_READERS: usize = 64;

struct RwState {
    writer: u64,
    wdepth: u32,
    writers_waiting: u32,
    readers_waiting: u32,
    /// Ilu czekających czytelników wpuszcza zwolnienie pisarza (mimo
    /// czekających pisarzy).
    readers_pass: u32,
    readers: [(u64, u32); MAX_READERS],
    nreaders: usize,
}

pub struct KRwLock {
    name: &'static str,
    state: crate::sched::spin::IrqSpinLock<RwState>,
    read_q: WaitQueue,
    write_q: WaitQueue,
    read_gen: AtomicU64,
    write_gen: AtomicU64,
    registered: AtomicBool,
    reads: AtomicU64,
    writes: AtomicU64,
    read_waited: AtomicU64,
    write_waited: AtomicU64,
    wait_us: AtomicU64,
    /// M17a.g8: czekania zakończone kręceniem się (bez uśpienia).
    spun: AtomicU64,
}

static NAMED_RW: [core::sync::atomic::AtomicUsize; 8] = [const { core::sync::atomic::AtomicUsize::new(0) }; 8];

/// Jak `KMutexStats`, z podziałem na odczyty / zapisy.
pub struct KRwLockStats {
    pub name: &'static str,
    pub reads: u64,
    pub writes: u64,
    pub read_waited: u64,
    pub write_waited: u64,
    pub wait_us: u64,
    pub spun: u64,
}

pub fn krwlock_stats() -> alloc::vec::Vec<KRwLockStats> {
    NAMED_RW
        .iter()
        .filter_map(|a| {
            let p = a.load(Ordering::Acquire);
            if p == 0 {
                return None;
            }
            let l = unsafe { &*(p as *const KRwLock) };
            Some(KRwLockStats {
                name: l.name,
                reads: l.reads.load(Ordering::Relaxed),
                writes: l.writes.load(Ordering::Relaxed),
                read_waited: l.read_waited.load(Ordering::Relaxed),
                write_waited: l.write_waited.load(Ordering::Relaxed),
                wait_us: l.wait_us.load(Ordering::Relaxed),
                spun: l.spun.load(Ordering::Relaxed),
            })
        })
        .collect()
}

pub enum KRwGuard<'a> {
    Read(&'a KRwLock),
    Write(&'a KRwLock),
}

/// Kogo obudzić po zwolnieniu (poza blokadą stanu).
enum RwWake {
    Nobody,
    Readers,
    Writer,
}

impl KRwLock {
    /// Nazwana blokada trafia do statystyk przy pierwszym użyciu – po nim
    /// nie wolno jej przenosić (statyczna albo już na heapie).
    pub const fn new_named(name: &'static str) -> Self {
        KRwLock {
            name,
            state: crate::sched::spin::IrqSpinLock::new(
                "krwlock-state",
                crate::sched::spin::level::PROCESS,
                RwState {
                    writer: 0,
                    wdepth: 0,
                    writers_waiting: 0,
                    readers_waiting: 0,
                    readers_pass: 0,
                    readers: [(0, 0); MAX_READERS],
                    nreaders: 0,
                },
            ),
            read_q: WaitQueue::new(),
            write_q: WaitQueue::new(),
            read_gen: AtomicU64::new(0),
            write_gen: AtomicU64::new(0),
            registered: AtomicBool::new(false),
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            read_waited: AtomicU64::new(0),
            write_waited: AtomicU64::new(0),
            wait_us: AtomicU64::new(0),
            spun: AtomicU64::new(0),
        }
    }

    fn register(&self) {
        if self.name.is_empty() || self.registered.load(Ordering::Relaxed) || self.registered.swap(true, Ordering::AcqRel) {
            return;
        }
        let me = self as *const KRwLock as usize;
        for slot in NAMED_RW.iter() {
            if slot.compare_exchange(0, me, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                return;
            }
        }
    }

    /// Czeka na zmianę licznika `counter` (widzianego pod blokadą stanu).
    fn wait_gen(&self, q: &WaitQueue, counter: &AtomicU64, seen: u64) {
        if spin_until(|| counter.load(Ordering::Acquire) != seen) {
            self.spun.fetch_add(1, Ordering::Relaxed);
            return;
        }
        q.wait_until(|| counter.load(Ordering::Acquire) != seen, None);
    }

    fn wake(&self, w: RwWake) {
        match w {
            RwWake::Nobody => {}
            RwWake::Readers => {
                self.read_gen.fetch_add(1, Ordering::AcqRel);
                self.read_q.wake_all();
            }
            RwWake::Writer => {
                self.write_gen.fetch_add(1, Ordering::AcqRel);
                self.write_q.wake_one();
            }
        }
    }

    /// Czy bieżące zadanie trzyma tę blokadę do odczytu.
    pub fn read_held(&self) -> bool {
        let me = current_id();
        let st = self.state.lock();
        st.readers[..st.nreaders].iter().any(|r| r.0 == me)
    }

    pub fn read(&self) -> KRwGuard<'_> {
        self.register();
        let me = current_id();
        let mut t0 = 0;
        let mut t1 = 0; // M17a.g13: koniec czekania odczytany przed wzięciem
        let mut queued = false;
        loop {
            let seen;
            {
                let mut st = self.state.lock();
                if st.writer == me {
                    st.wdepth += 1;
                    drop(st);
                    self.reads.fetch_add(1, Ordering::Relaxed);
                    return KRwGuard::Write(self);
                }
                let n = st.nreaders;
                if let Some(r) = st.readers[..n].iter_mut().find(|r| r.0 == me) {
                    r.1 += 1;
                    drop(st);
                    self.reads.fetch_add(1, Ordering::Relaxed);
                    return KRwGuard::Read(self);
                }
                // Wolno wejść: brak pisarza i (nikt nie czeka na zapis albo
                // to grupa wpuszczona po zwolnieniu pisarza).
                let pass = queued && st.readers_pass > 0;
                if st.writer == 0 && (st.writers_waiting == 0 || pass) && n < MAX_READERS {
                    st.readers[n] = (me, 1);
                    st.nreaders = n + 1;
                    if queued {
                        st.readers_waiting -= 1;
                        if st.readers_pass > 0 {
                            st.readers_pass -= 1;
                        }
                    }
                    drop(st);
                    self.reads.fetch_add(1, Ordering::Relaxed);
                    if t0 != 0 {
                        self.read_waited.fetch_add(1, Ordering::Relaxed);
                        self.wait_us.fetch_add(crate::arch::x86_64::clock::us_between(t0, t1), Ordering::Relaxed);
                    }
                    return KRwGuard::Read(self);
                }
                if !queued {
                    queued = true;
                    st.readers_waiting += 1;
                }
                seen = self.read_gen.load(Ordering::Acquire);
            }
            if t0 == 0 {
                t0 = crate::arch::x86_64::clock::stamp().max(1);
            }
            self.wait_gen(&self.read_q, &self.read_gen, seen);
            t1 = crate::arch::x86_64::clock::stamp();
        }
    }

    pub fn write(&self) -> KRwGuard<'_> {
        self.register();
        let me = current_id();
        let mut t0 = 0;
        let mut t1 = 0; // M17a.g13: koniec czekania odczytany przed wzięciem
        let mut queued = false;
        loop {
            let seen;
            {
                let mut st = self.state.lock();
                if st.writer == me {
                    st.wdepth += 1;
                    drop(st);
                    self.writes.fetch_add(1, Ordering::Relaxed);
                    return KRwGuard::Write(self);
                }
                if st.readers[..st.nreaders].iter().any(|r| r.0 == me) {
                    drop(st);
                    panic!("KRwLock '{}': task {} holds it for reading and asks to write", self.name, me);
                }
                if st.writer == 0 && st.nreaders == 0 {
                    st.writer = me;
                    st.wdepth = 1;
                    if queued {
                        st.writers_waiting -= 1;
                    }
                    drop(st);
                    self.writes.fetch_add(1, Ordering::Relaxed);
                    if t0 != 0 {
                        self.write_waited.fetch_add(1, Ordering::Relaxed);
                        self.wait_us.fetch_add(crate::arch::x86_64::clock::us_between(t0, t1), Ordering::Relaxed);
                    }
                    return KRwGuard::Write(self);
                }
                if !queued {
                    queued = true;
                    st.writers_waiting += 1;
                }
                seen = self.write_gen.load(Ordering::Acquire);
            }
            if t0 == 0 {
                t0 = crate::arch::x86_64::clock::stamp().max(1);
            }
            self.wait_gen(&self.write_q, &self.write_gen, seen);
            t1 = crate::arch::x86_64::clock::stamp();
        }
    }
}

impl Drop for KRwGuard<'_> {
    fn drop(&mut self) {
        let me = current_id();
        let (l, wake) = match *self {
            KRwGuard::Write(l) => {
                let mut st = l.state.lock();
                debug_assert!(st.writer == me, "KRwLock write guard dropped by another task");
                st.wdepth -= 1;
                let mut wake = RwWake::Nobody;
                if st.wdepth == 0 {
                    st.writer = 0;
                    if st.readers_waiting > 0 {
                        // Grupa czytelników wchodzi mimo czekających pisarzy.
                        st.readers_pass = st.readers_waiting;
                        wake = RwWake::Readers;
                    } else if st.writers_waiting > 0 {
                        wake = RwWake::Writer;
                    }
                }
                (l, wake)
            }
            KRwGuard::Read(l) => {
                let mut st = l.state.lock();
                let n = st.nreaders;
                let i = st.readers[..n].iter().position(|r| r.0 == me).expect("KRwLock read guard without a reader slot");
                st.readers[i].1 -= 1;
                let mut wake = RwWake::Nobody;
                if st.readers[i].1 == 0 {
                    st.readers[i] = st.readers[n - 1];
                    st.readers[n - 1] = (0, 0);
                    st.nreaders = n - 1;
                    if st.nreaders == 0 && st.writers_waiting > 0 {
                        wake = RwWake::Writer;
                    } else if n == MAX_READERS && st.readers_waiting > 0 {
                        wake = RwWake::Readers; // zwolniło się miejsce
                    }
                }
                (l, wake)
            }
        };
        l.wake(wake);
    }
}

// M17a.g7: KRwLock bywa częścią obiektu na heapie (ramfs zamontowany i
// odmontowany) – przy zwolnieniu znika z rejestru statystyk.
impl Drop for KRwLock {
    fn drop(&mut self) {
        let me = self as *const KRwLock as usize;
        for slot in NAMED_RW.iter() {
            let _ = slot.compare_exchange(me, 0, Ordering::AcqRel, Ordering::Relaxed);
        }
    }
}
