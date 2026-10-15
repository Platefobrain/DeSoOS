// M12: scheduler – zadania kernela, round-robin z wywłaszczaniem.
//
// * Zadanie = własny stos (stack.rs, ze stroną-strażnikiem) + zapisany RSP.
//   Przełączenie (`sched_switch`) odkłada na stos rejestry zachowywane
//   przez wołanego (rbx, rbp, r12–r15), zapisuje RSP i ładuje RSP innego
//   zadania.  Reszta rejestrów jest już zapisana przez kompilator (zwykłe
//   wywołanie) albo przez isr_common (przerwanie).
// * Zadanie 1 ("kernel") to wątek startowy – działa na stosie od DSB i po
//   samotestach zostaje shellem.  Zadanie 0 ("idle") robi `hlt`, gdy nikt
//   inny nie jest gotowy, i sprząta zakończone zadania.
// * Wywłaszczanie: tick PIT (on_tick) odlicza kwant QUANTUM_TICKS i budzi
//   śpiące zadania; przełączenie dzieje się w irq::dispatch PO wysłaniu EOI
//   (`preempt`).  Zadanie obudzone przez przerwanie (klawiatura, dysk)
//   dostaje CPU od razu po tym przerwaniu.
// * Cały stan schedulera zmienia się przy wyłączonych przerwaniach.  M17:
//   na wielu rdzeniach wyłączność daje dodatkowo Big Kernel Lock (bkl.rs) –
//   kod kernela, w tym scheduler, wykonuje jeden CPU naraz.
// * M17: każdy CPU ma własne `current`, kwant i zadanie idle (przypięte do
//   niego); zwykłe zadania biorą dowolny wolny CPU (wspólna lista).
// * FPU/SSE (M13b): kernel jest soft-float; stan x87/SSE procesów
//   użytkownika zapisuje/odtwarza schedule() (FXSAVE/FXRSTOR, arch/fpu.rs).

pub mod bkl;
// M17a krok a: narzędzia; pierwsi użytkownicy w kroku c (alokator ramek, heap).
#[allow(dead_code)]
pub mod spin;
pub mod stack;
pub mod sync;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::arch::global_asm;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::arch::x86_64::fpu::{self, FxState};
use crate::arch::x86_64::interrupts::{self, without_interrupts};
use crate::serial_println;
use stack::TaskStack;

pub type TaskId = u64;

pub const IDLE_ID: TaskId = 0;
pub const BOOT_ID: TaskId = 1;

/// Kwant czasu w tickach (1 tick = 1 ms).
pub const QUANTUM_TICKS: u32 = 10;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Ready,
    Running,
    Blocked,
    Dead,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Ready => "ready",
            State::Running => "running",
            State::Blocked => "blocked",
            State::Dead => "dead",
        }
    }
}

struct Task {
    id: TaskId,
    name: String,
    state: State,
    rsp: u64,
    stack: Option<TaskStack>, // None = stos startowy (zadanie 1) / idle
    wait_channel: usize,      // 0 = sen bez kolejki
    wake_at: u64,             // tick pobudki (u64::MAX = bez limitu)
    /// M17a.g12: liczy tick CPU, na którym zadanie działa – bez blokady.
    cpu_ticks: AtomicU64,
    switches: u64,
    exit_requested: bool,
    /// M13a/M14: proces użytkownika (przestrzeń adresowa, deskryptory
    /// plików); None = zadanie kernela (CR3 kernela).
    process: Option<Box<crate::user::Process>>,
    /// M13b: rejestry x87/SSE procesu, gdy nie działa (FXSAVE).
    fpu: FxState,
    /// M17: zadanie idle procesora o tym numerze (przypięte do niego).
    idle_cpu: Option<u8>,
    /// M17: ostatni CPU, na którym działało, i maska wszystkich użytych CPU.
    last_cpu: u8,
    cpu_mask: u16,
    /// M17a.f1: głębokość blokady schedulera w chwili przełączenia (zadanie
    /// po powrocie zwalnia tyle poziomów, ile miało – blokada należy do CPU).
    sched_depth: u32,
    /// M17b.f: cykle TSC na CPU (od wejścia do wyjścia ze schedulera, zawsze
    /// mierzone na jednym CPU – TSC rdzeni Legiona nie są zgrane).
    run_tsc: AtomicU64,
    /// M17a.f2: zadanie oddało BKL przy przełączeniu (schedule) – weźmie go
    /// z powrotem po wyjściu ze schedulera (`after_switch`).
    bkl_dropped: bool,
    /// M17a.f3a: jest w kolejce gotowych (`Scheduler::ready`).
    queued: bool,
    /// M17a.f3b: łącza list wbudowane w zadanie (bez alokacji pod blokadą
    /// schedulera): kolejka gotowych, kubełek kanału, lista terminów,
    /// kubełek numeru.
    rq: Link,
    wq: Link,
    sq: Link,
    in_sleepers: bool,
    id_next: *mut Task,
    /// P4.b: lustro `state == Dead` dla czytających pod blokadą tablicy zadań
    /// (bez blokady schedulera – `state` zmienia się pod nią).
    dead: AtomicBool,
    /// P4.c: zadanie jest (jeszcze) na jakimś CPU – od wybrania przez
    /// schedule() do chwili, gdy CPU, który z niego schodzi, skończy
    /// przełączenie (rejestry i FPU zapisane, stos opuszczony).  Inny CPU nie
    /// przełączy się na zadanie z tą flagą, reap go nie zwolni.
    on_cpu: AtomicBool,
    /// P4.b: znacznik życia (testy: zwolnione zadanie widziane przez
    /// czytającego tablicę = TASK_FREED).
    magic: AtomicU64,
}

const TASK_MAGIC: u64 = 0x7a5c_7a5c_7a5c_7a5c;
const TASK_FREED: u64 = 0xdead_dead_dead_dead;

impl Drop for Task {
    fn drop(&mut self) {
        self.magic.store(TASK_FREED, Ordering::SeqCst);
    }
}

/// M17a.f3b: łącze listy dwukierunkowej (wskaźniki na Box<Task>).
#[derive(Clone, Copy)]
struct Link {
    prev: *mut Task,
    next: *mut Task,
}

impl Link {
    const NONE: Link = Link { prev: core::ptr::null_mut(), next: core::ptr::null_mut() };
}

/// Lista dwukierunkowa zadań (łącze wybiera `link`).
#[derive(Clone, Copy)]
struct TList {
    head: *mut Task,
    tail: *mut Task,
    len: usize,
}

impl TList {
    const EMPTY: TList = TList { head: core::ptr::null_mut(), tail: core::ptr::null_mut(), len: 0 };

    fn push_back(&mut self, p: *mut Task, link: fn(&mut Task) -> &mut Link) {
        *link(tm(p)) = Link { prev: self.tail, next: core::ptr::null_mut() };
        if self.tail.is_null() {
            self.head = p;
        } else {
            link(tm(self.tail)).next = p;
        }
        self.tail = p;
        self.len += 1;
    }

    fn remove(&mut self, p: *mut Task, link: fn(&mut Task) -> &mut Link) {
        let l = *link(tm(p));
        if l.prev.is_null() {
            self.head = l.next;
        } else {
            link(tm(l.prev)).next = l.next;
        }
        if l.next.is_null() {
            self.tail = l.prev;
        } else {
            link(tm(l.next)).prev = l.prev;
        }
        *link(tm(p)) = Link::NONE;
        self.len -= 1;
    }

    fn pop_front(&mut self, link: fn(&mut Task) -> &mut Link) -> Option<*mut Task> {
        let p = self.head;
        if p.is_null() {
            return None;
        }
        self.remove(p, link);
        Some(p)
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.head.is_null()
    }
}

fn rq_link(t: &mut Task) -> &mut Link {
    &mut t.rq
}
fn wq_link(t: &mut Task) -> &mut Link {
    &mut t.wq
}
fn sq_link(t: &mut Task) -> &mut Link {
    &mut t.sq
}

const WAIT_BUCKETS: usize = 256;
const ID_BUCKETS: usize = 1024;

fn wait_bucket(channel: usize) -> usize {
    ((channel >> 3) ^ (channel >> 11) ^ (channel >> 19)) % WAIT_BUCKETS
}

impl Task {
    /// Szczyt stosu kernela zadania (TSS.RSP0, gdy zadanie jest w ring 3).
    fn kernel_stack_top(&self) -> u64 {
        match &self.stack {
            Some(st) => st.top(),
            None => crate::memory::kernel_layout().stack_top,
        }
    }

    fn cr3(&self) -> u64 {
        match &self.process {
            Some(p) => p.space.cr3(),
            None => crate::memory::kernel_cr3(),
        }
    }
}

/// Informacje o zadaniu (dla `ps` i testów).
#[derive(Clone)]
pub struct TaskInfo {
    pub id: TaskId,
    pub name: String,
    pub state: State,
    pub cpu_ticks: u64,
    pub switches: u64,
    #[allow(dead_code)]
    pub stack_top: u64,
    /// Proces użytkownika (ring 3, własna przestrzeń adresowa).
    pub user: bool,
    /// M16: rodzic procesu (0 = kernel; zadania kernela też 0).
    pub ppid: TaskId,
    /// M17: CPU, na którym działa teraz (None = nie działa) / działało ostatnio.
    pub cpu: Option<usize>,
    pub last_cpu: usize,
    /// M17: maska CPU, na których zadanie kiedykolwiek działało.
    #[allow(dead_code)]
    pub cpu_mask: u16,
}

use crate::arch::x86_64::cpu::MAX_CPUS;

/// Zadanie bieżące na CPU, na którym nic nie działa (jeszcze nie uruchomiony).
const NO_TASK: TaskId = u64::MAX;

struct Scheduler {
    tasks: Vec<Box<Task>>,
    /// M17: zadanie bieżące każdego CPU.
    current: [TaskId; MAX_CPUS],
    next_id: TaskId,
    /// M17: zadanie idle każdego CPU (NO_TASK = CPU nie uruchomiony).
    idle: [TaskId; MAX_CPUS],
    // M17a.f3a: struktury zamiast przeglądania całej listy zadań pod blokadą
    // schedulera (Legion v0.17.17: 65% wzięć czeka, 232 s – każde
    // schedule / pobudka / tick przeglądało wszystkie zadania).  Wskaźniki
    // na Box<Task> (adres stały do reap; zadanie w kolejce nigdy nie jest
    // martwe, więc reap ich nie unieważnia).
    // M17a.f3b: listy wbudowane w zadania i tablice kubełków – żadnej
    // alokacji pod blokadą schedulera (v0.17.18 z BTreeMap/Vec alokowała przy
    // każdym uśpieniu i pobudce – pod blokadą heapa, z IF = 0: Legion 79%
    // czekania, 335 s).
    /// Gotowe zadania (stan Ready, nie idle) – FIFO, round-robin.
    ready: TList,
    /// Zadanie po numerze: kubełki (numer % ID_BUCKETS), łańcuch `id_next`.
    ids: [*mut Task; ID_BUCKETS],
    /// Uśpione na kanale (WaitQueue): kubełki po adresie kanału.
    waiters: [TList; WAIT_BUCKETS],
    /// Uśpione z terminem (tick przegląda tylko je).
    sleepers: TList,
}

static mut SCHED: Scheduler = Scheduler {
    tasks: Vec::new(),
    current: [NO_TASK; MAX_CPUS],
    next_id: 2,
    idle: [NO_TASK; MAX_CPUS],
    ready: TList::EMPTY,
    ids: [core::ptr::null_mut(); ID_BUCKETS],
    waiters: [TList::EMPTY; WAIT_BUCKETS],
    sleepers: TList::EMPTY,
};
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// M17a.d: adres struktury zadania bieżącego każdego CPU (Box<Task> – adres
/// stały, zadanie nie jest zwalniane, dopóki jest bieżące gdziekolwiek).
/// Ścieżki bez BKL (syscalle getpid/uptime/write) czytają stąd swoje zadanie
/// i proces zamiast z listy zadań (ta zmienia się pod BKL).
static CUR_TASK: crate::arch::x86_64::percpu::PerCpu<core::sync::atomic::AtomicUsize> = crate::per_cpu!(core::sync::atomic::AtomicUsize::new(0));

fn publish_current(s: &Scheduler, c: usize) {
    let addr = index_of(s, s.current[c]).map(|i| &*s.tasks[i] as *const Task as usize).unwrap_or(0);
    CUR_TASK[c].store(addr, Ordering::Release);
}

/// M17a.d: zadanie bieżące tego CPU bez BKL.  Wołać z IF = 0 (inaczej
/// zadanie mogłoby się przenieść między odczytem numeru CPU a wskaźnika).
fn current_task_unlocked() -> Option<&'static Task> {
    debug_assert!(!crate::arch::x86_64::interrupts::are_enabled());
    let a = CUR_TASK[cpu()].load(Ordering::Acquire);
    (a != 0).then(|| unsafe { &*(a as *const Task) })
}

/// M17a.d: (id, proces) bieżącego zadania bez BKL – dla syscalli bez BKL.
/// Proces jest jednowątkowy: jego deskryptory i pamięć zmienia tylko on sam
/// (w syscallach), więc własny proces wolno czytać bez blokady.  Z IF = 0.
pub fn current_unlocked() -> Option<(TaskId, &'static mut crate::user::Process)> {
    let t = current_task_unlocked()?;
    let id = t.id;
    let p: *const crate::user::Process = t.process.as_deref()?;
    Some((id, unsafe { &mut *(p as *mut crate::user::Process) }))
}

/// M17a.d: `kill` / Ctrl+C dla bieżącego zadania – bez BKL (odczyt flagi
/// ustawianej przez inny CPU pod BKL).  Z IF = 0.
pub fn should_exit_unlocked() -> bool {
    match current_task_unlocked() {
        Some(t) => unsafe { core::ptr::read_volatile(&t.exit_requested) },
        None => false,
    }
}

/// M17a.b: tick przy poprzednim on_tick (BSP).
static LAST_BSP_TICK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static NEED_RESCHED: crate::arch::x86_64::percpu::PerCpu<AtomicBool> = crate::per_cpu!(AtomicBool::new(false));

#[inline]
fn cpu() -> usize {
    crate::arch::x86_64::cpu::id()
}

/// Zadanie bieżące tego CPU.
#[inline]
fn cur_id(s: &Scheduler) -> TaskId {
    s.current[cpu()]
}
static TOTAL_SWITCHES: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();

/// Dostęp do stanu: tylko przy wyłączonych przerwaniach.
fn sched() -> &'static mut Scheduler {
    debug_assert!(!interrupts::are_enabled());
    // M17a.f2: lista zadań i stan schedulera tylko pod blokadą schedulera
    // (BKL już nie jest potrzebny).
    assert!(sched_lock_held(), "sched: task list touched on CPU {} without the scheduler lock", cpu());
    unsafe { &mut *core::ptr::addr_of_mut!(SCHED) }
}

// ------------------------------------------------------------
// P4.b: tablica zadań pod własną blokadą RW
// ------------------------------------------------------------
//
// `tasks` + `ids` (lista zadań i kubełki numerów) zmieniają się pod blokadą
// schedulera ORAZ zapisem tej blokady (dodanie: spawn, idle, init; usunięcie:
// reap).  Czytający, którym wystarczy „zadanie o numerze X i jego proces”
// (with_process, task_exists, children_of, for_each_process), biorą tylko ją
// do odczytu – równolegle, bez blokady schedulera (Legion v0.29.0:
// with_process 11 mln wzięć blokady schedulera na minutę).  reparent_with –
// zapis (wyklucza with_process jak dotąd blokada schedulera).
// * Kolejność: scheduler -> tablica.  Czytający / reparent NIE biorą blokady
//   schedulera, trzymając tablicę.
// * Zawsze z IF = 0 (także czytający): pisarz trzyma blokadę schedulera z
//   IF = 0 i czeka na czytających – czytający przerwany przez pobudkę
//   (wake_channel -> blokada schedulera) zakleszczyłby się z nim.
// * Zadanie żyje, dopóki jest w tablicy (reap usuwa pod zapisem), więc
//   referencja z odczytu jest ważna do zwolnienia blokady.  `state` czytający
//   nie widzą – tylko lustro `dead`.
static TABLE: spin::RwSpinLock = spin::RwSpinLock::new("task table");

/// Stan schedulera do odczytu tablicy zadań (tylko `tasks`, `ids` i pola
/// zadań niezmienne lub atomowe) – pod `TABLE` z IF = 0.
/// P4.b (testy): zadania o złym znaczniku widziane pod blokadą tablicy.
static TABLE_BAD: AtomicU64 = AtomicU64::new(0);

#[cfg_attr(not(selftest), allow(dead_code))]
pub fn table_bad() -> u64 {
    TABLE_BAD.load(Ordering::Relaxed)
}

/// P4.b: sprawdzenie znacznika zadania znalezionego w tablicy (build z
/// samotestami: z chwilą kręcenia, żeby zwolnienie bez blokady tablicy miało
/// okno, w którym test je złapie).
#[inline]
fn table_check(t: &Task) {
    #[cfg(selftest)]
    for _ in 0..64 {
        core::hint::spin_loop();
    }
    if t.magic.load(Ordering::SeqCst) != TASK_MAGIC {
        TABLE_BAD.fetch_add(1, Ordering::Relaxed);
    }
}

fn table() -> &'static Scheduler {
    debug_assert!(!interrupts::are_enabled());
    debug_assert!(TABLE.state() != (false, 0), "task table read without its lock");
    unsafe { &*core::ptr::addr_of!(SCHED) }
}

// ------------------------------------------------------------
// M17a.f1: blokada schedulera
// ------------------------------------------------------------
//
// Jedna blokada na listę zadań i stan schedulera (current, idle, kwant).
// M17a.f1 – obok BKL; od M17a.f2 – sama (scheduler nie potrzebuje BKL).
//
// BKL przy przełączeniu (f2, jak release/reacquire_kernel_lock w Linuksie
// 2.x): zadanie, które trzyma BKL i ODDAJE CPU (schedule przełącza), zwalnia
// go tuż przed przełączeniem (zwalniać wolno pod blokadą schedulera –
// czekać na BKL już nie) i bierze z powrotem po wyjściu ze schedulera, gdy
// nie trzyma już blokady schedulera (`after_switch`).  Gdy schedule() nie
// przełącza (warunek spełniony, brak innych zadań), BKL zostaje – kod pod
// BKL nie traci go "po drodze".  Nowe zadanie bierze BKL na start
// (sched_new_task_start), jak dotąd.
//
// * Rekurencyjna na tym samym CPU (wake_channel -> kick, sleep_until ->
//   block_current -> schedule), zawsze z IF = 0 (bierze ją też przerwanie
//   zegara i pobudka z przerwania).
// * P4.c (v0.32.0): NIE jest już trzymana przez przełączenie – schedule()
//   oddaje ją po wyborze następnego zadania, a zadanie na CPU chroni flaga
//   `on_cpu` (patrz finish_switch); strażniki sprzed przełączenia po powrocie
//   zadania nic nie zwalniają (SCHED_SKIP).  Opis sprzed P4.c:
// * Należy do CPU, nie do zadania, i jest trzymana PRZEZ przełączenie:
//   schedule() bierze ją w starym zadaniu, a oddaje nowe zadanie (po powrocie
//   ze swojego schedule() albo w sched_new_task_start).  Dzięki temu żaden
//   inny CPU nie weźmie starego zadania, zanim jego rejestry nie są zapisane.
//   Głębokość per CPU jest zapisywana w zadaniu przy przełączeniu
//   (Task::sched_depth) i odtwarzana po powrocie – każde zadanie zwalnia
//   tyle poziomów, ile samo wzięło.
// * Kolejność: BKL -> blokada schedulera -> heap / ramki (alokacje pod nią
//   dozwolone).  Trzymając ją nie wolno CZEKAĆ na BKL (zwolnić – wolno) ani
//   na KMutex, robić TLB shootdown (stosy zadań zwalniamy po jej oddaniu)
//   ani spać.
// * Poza lockdep (jak blokady TLB i konsoli): rekurencja i przejście przez
//   przełączenie zadań są tu celowe.

/// Właściciel (numer CPU + 1; 0 = wolna) i głębokość per CPU.
/// M17b.e: w osobnej linii cache (najgorętsza blokada jądra).
static SCHED_OWNER: crate::arch::x86_64::percpu::CacheLine<core::sync::atomic::AtomicU32> =
    crate::arch::x86_64::percpu::CacheLine(core::sync::atomic::AtomicU32::new(0));
static SCHED_DEPTH: crate::arch::x86_64::percpu::PerCpu<core::sync::atomic::AtomicU32> = crate::per_cpu!(core::sync::atomic::AtomicU32::new(0));
/// Statystyka: wzięcia (pierwszy poziom), wzięcia z czekaniem, µs czekania.
static SCHED_ACQ: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static SCHED_CONT: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static SCHED_WAIT_US: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
/// v0.32.1 (diagnostyka spadku stressu): najdłuższe pojedyncze czekanie na
/// blokadę schedulera (µs), miejsce tego czekania, ile czekań > 100 µs, ile
/// czekań z przerwania (on_tick, pobudka z IRQ) i najdłuższe z nich.
static SCHED_WAIT_MAX: AtomicU64 = AtomicU64::new(0);
static SCHED_WAIT_MAX_SITE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static SCHED_WAIT_LONG: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static SCHED_WAIT_IRQ_MAX: AtomicU64 = AtomicU64::new(0);

/// (najdłuższe czekanie µs, jego miejsce, czekania > 100 µs, najdłuższe w przerwaniu µs).
pub fn sched_wait_extremes() -> (u64, &'static str, u64, u64) {
    let site = SCHED_WAIT_MAX_SITE.load(Ordering::Relaxed);
    let name: &'static str = if site == 0 { "-" } else { unsafe { *(site as *const &'static str) } };
    (SCHED_WAIT_MAX.load(Ordering::Relaxed), name, SCHED_WAIT_LONG.get(), SCHED_WAIT_IRQ_MAX.load(Ordering::Relaxed))
}
/// M17a.g12: kto bierze blokadę schedulera (plik:linia), czekanie i trzymanie.
static SCHED_SITES: bkl::SiteTable = bkl::SiteTable::new();
/// Wpis (+1) i TSC wzięcia na tym CPU (zwalnia ten sam CPU – IF = 0).
static SCHED_HOLD_SLOT: crate::arch::x86_64::percpu::PerCpu<core::sync::atomic::AtomicUsize> = crate::per_cpu!(core::sync::atomic::AtomicUsize::new(0));
static SCHED_HOLD_TSC: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));

/// P4.c: przełączenia poza blokadą schedulera i czekania na `on_cpu`
/// (wybrane zadanie jeszcze schodziło z innego CPU): liczba, takty TSC.
static SWITCH_N: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static ONCPU_WAITS: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static ONCPU_TSC: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
/// P4.c: zadanie, z którego ten CPU właśnie schodzi (zdejmuje mu `on_cpu`
/// pierwsze, co wykona następne zadanie – `finish_switch`).
static PREV_TASK: crate::arch::x86_64::percpu::PerCpu<core::sync::atomic::AtomicUsize> = crate::per_cpu!(core::sync::atomic::AtomicUsize::new(0));
/// P4.c: strażniki blokady schedulera wzięte PRZED przełączeniem przez
/// zadanie, które właśnie wróciło – blokada jest już zwolniona (schedule
/// oddaje ją przed przełączeniem), więc ich Drop nic nie zwalnia.
static SCHED_SKIP: crate::arch::x86_64::percpu::PerCpu<core::sync::atomic::AtomicU32> = crate::per_cpu!(core::sync::atomic::AtomicU32::new(0));

/// (przełączenia, czekania na on_cpu, µs tych czekań) – `cpus`.
pub fn switch_stats() -> (u64, u64, u64) {
    let per_ms = crate::arch::x86_64::lapic::tsc_per_ms().max(1);
    (SWITCH_N.get(), ONCPU_WAITS.get(), ONCPU_TSC.get() * 1000 / per_ms)
}

/// P4.c: po przełączeniu (nowe zadanie, IF = 0, bez blokady schedulera) –
/// poprzednie zadanie tego CPU jest już zapisane: zdjęcie `on_cpu` (od teraz
/// inny CPU może je uruchomić, reap – zwolnić).  `skip` – ile strażników
/// blokady to zadanie wzięło przed swoim przełączeniem.
fn finish_switch(skip: u32) {
    let c = cpu();
    SCHED_SKIP[c].store(skip, Ordering::Relaxed);
    let prev = PREV_TASK[c].swap(0, Ordering::Relaxed);
    if prev != 0 {
        unsafe { (*(prev as *const Task)).on_cpu.store(false, Ordering::Release) };
    }
}

fn sched_hold_end(me: usize) {
    let slot = SCHED_HOLD_SLOT[me].swap(0, Ordering::Relaxed);
    if slot != 0 {
        let d = bkl::rdtsc().wrapping_sub(SCHED_HOLD_TSC[me].load(Ordering::Relaxed));
        if d < 1 << 48 {
            SCHED_SITES.entry(slot - 1).hold_tsc.fetch_add(d, Ordering::Relaxed);
        }
    }
}

/// Miejsca wzięcia blokady schedulera (`cpus`, autostress) i nieśledzone wzięcia.
pub fn sched_lock_sites() -> (alloc::vec::Vec<bkl::SiteInfo>, u64) {
    (SCHED_SITES.stats(), SCHED_SITES.overflow())
}

/// Po tylu µs czekania na blokadę schedulera – raport (sekcje trwają µs).
const SCHED_REPORT_US: u64 = 2_000_000;

fn sched_lock_held() -> bool {
    SCHED_OWNER.load(Ordering::Relaxed) == cpu() as u32 + 1
}

/// Strażnik blokady schedulera (rekurencyjnej).  Zwolnienie na CPU, na
/// którym zadanie jest w chwili zwolnienia (po przełączeniu może być inny).
struct SchedGuard {
    irq: bool,
}

#[must_use]
fn lock_sched_at(site: &'static &'static str) -> SchedGuard {
    let irq = interrupts::are_enabled();
    interrupts::disable();
    let me = cpu();
    let tag = me as u32 + 1;
    assert!(
        SCHED_SKIP[me].load(Ordering::Relaxed) == 0,
        "sched: scheduler lock taken on CPU {} before the guards from before a task switch were dropped",
        me
    );
    if SCHED_OWNER.load(Ordering::Relaxed) == tag {
        SCHED_DEPTH[me].fetch_add(1, Ordering::Relaxed);
        return SchedGuard { irq };
    }
    SCHED_ACQ.add(1);
    let slot = SCHED_SITES.slot_for(bkl::tag_key(site));
    if let Some(i) = slot {
        SCHED_SITES.entry(i).taken.fetch_add(1, Ordering::Relaxed);
    }
    if SCHED_OWNER.compare_exchange(0, tag, Ordering::Acquire, Ordering::Relaxed).is_err() {
        SCHED_CONT.add(1);
        // M17a.g13: TSC (IF = 0 – ten sam CPU), nie HPET – odczyt po wzięciu
        // blokady wydłużał jej trzymanie.
        // M17a.g14: statystyka – TSC tego CPU (IF = 0); raport o długim
        // czekaniu – HPET (TSC bywa niewiarygodny), czytany co 4096 obrotów.
        let (tsc0, cpu0) = crate::arch::x86_64::clock::tsc_cpu();
        let mut start = 0u64;
        let mut n: u32 = 0;
        let mut reported = false;
        // P4.0: czekanie samym ODCZYTEM (test-and-test-and-set) – próba
        // przejęcia (instrukcja atomowa) dopiero, gdy blokada wygląda na wolną.
        // Wcześniej każdy obrót pętli był compare_exchange: 15 czekających CPU
        // zabierało sobie nawzajem i trzymającemu linię pamięci podręcznej z
        // blokadą – trzymający wolniej ją oddawał (Legion v0.29.0: 41% wzięć
        // czeka, 18,9 s).  Tak czekają już zwykłe spinlocki (spin.rs).
        loop {
            if SCHED_OWNER.load(Ordering::Relaxed) == 0
                && SCHED_OWNER.compare_exchange_weak(0, tag, Ordering::Acquire, Ordering::Relaxed).is_ok()
            {
                break;
            }
            core::hint::spin_loop();
            n = n.wrapping_add(1);
            if n % 64 == 0 {
                crate::arch::x86_64::tlb::poll_from_wait();
            }
            if n % 4096 == 0 {
                crate::arch::x86_64::smp::watchdog_poll();
                if start == 0 {
                    start = crate::arch::x86_64::clock::stamp().max(1);
                }
                let waited = crate::arch::x86_64::clock::elapsed_us(start);
                if !reported && waited > SCHED_REPORT_US {
                    reported = true;
                    serial_println!(
                        "[SCHED] CPU {} waits {} ms for the scheduler lock, held by CPU {}",
                        me,
                        waited / 1000,
                        SCHED_OWNER.load(Ordering::Relaxed) as i64 - 1
                    );
                }
            }
        }
        let waited = crate::arch::x86_64::clock::tsc_wait_us(tsc0, cpu0);
        SCHED_WAIT_US.add(waited);
        if waited > 100 {
            SCHED_WAIT_LONG.add(1);
        }
        if waited > SCHED_WAIT_MAX.fetch_max(waited, Ordering::Relaxed) {
            SCHED_WAIT_MAX_SITE.store(site as *const &'static str as usize, Ordering::Relaxed);
        }
        if crate::arch::x86_64::cpu::in_interrupt() {
            SCHED_WAIT_IRQ_MAX.fetch_max(waited, Ordering::Relaxed);
        }
        if let Some(i) = slot {
            SCHED_SITES.entry(i).waited.fetch_add(1, Ordering::Relaxed);
            SCHED_SITES.entry(i).wait_us.fetch_add(waited, Ordering::Relaxed);
        }
    }
    SCHED_DEPTH[me].store(1, Ordering::Relaxed);
    SCHED_HOLD_SLOT[me].store(slot.map_or(0, |i| i + 1), Ordering::Relaxed);
    SCHED_HOLD_TSC[me].store(bkl::rdtsc(), Ordering::Relaxed);
    SchedGuard { irq }
}

impl Drop for SchedGuard {
    fn drop(&mut self) {
        let me = cpu();
        // P4.c: strażnik sprzed przełączenia – blokadę oddało już schedule().
        let skip = SCHED_SKIP[me].load(Ordering::Relaxed);
        if skip > 0 {
            SCHED_SKIP[me].store(skip - 1, Ordering::Relaxed);
            if self.irq {
                interrupts::enable();
            }
            return;
        }
        debug_assert!(sched_lock_held(), "scheduler lock released by a CPU that does not hold it");
        if SCHED_DEPTH[me].fetch_sub(1, Ordering::Relaxed) == 1 {
            sched_hold_end(me);
            SCHED_OWNER.store(0, Ordering::Release);
        }
        if self.irq {
            interrupts::enable();
        }
    }
}

/// Pierwsze wejście nowego zadania (task_trampoline, IF = 0): blokada
/// schedulera wzięta przez schedule() poprzedniego zadania – oddajemy całą.
#[unsafe(no_mangle)]
extern "sysv64" fn sched_new_task_start() {
    // P4.c: blokada schedulera jest już wolna (schedule() oddaje ją przed
    // przełączeniem); tylko poprzednie zadanie dostaje zdjęte `on_cpu`.
    finish_switch(0);
    // M17a.f2: zadanie startuje z BKL (zadania kernela działają pod BKL,
    // procesy oddają go w enter_user) – poprzednie zadanie oddało go przy
    // przełączeniu.  Dopiero PO oddaniu blokady schedulera (kolejność).
    // M17a.g3: proces użytkownika startuje bez BKL – jego wejście
    // (user_task_entry -> enter_user) czyta tylko własny proces i od razu
    // skacze do ring 3 (wcześniej: weź BKL, żeby za chwilę oddać – 308 tys.
    // razy w stressie na Legionie).
    let user = current_task_unlocked().is_some_and(|t| t.process.is_some());
    if !user {
        bkl::acquire_if_needed_tagged(&bkl::tag::NEW_TASK);
    }
}

/// M17a.f2: po wyjściu ze schedulera (bez blokady schedulera) – jeśli to
/// zadanie oddało BKL przy przełączeniu, bierze go z powrotem.  Wołają:
/// wait_event, sleep_until, yield_now, preempt.
fn after_switch(why: &'static &'static str) {
    without_interrupts(|| {
        debug_assert!(!sched_lock_held(), "after_switch with the scheduler lock held");
        let a = CUR_TASK[cpu()].load(Ordering::Acquire);
        if a == 0 {
            return;
        }
        let t = unsafe { &mut *(a as *mut Task) };
        if t.bkl_dropped {
            t.bkl_dropped = false;
            bkl::acquire_if_needed_tagged(why);
        }
    });
}

/// M17a.f2: flaga "oddał BKL" bieżącego zadania – zdjęcie / ustawienie (IF = 0,
/// tylko własne zadanie; preempt odkłada flagę przerwanego kontekstu).
fn take_bkl_dropped() -> bool {
    let a = CUR_TASK[cpu()].load(Ordering::Acquire);
    if a == 0 {
        return false;
    }
    let t = unsafe { &mut *(a as *mut Task) };
    core::mem::replace(&mut t.bkl_dropped, false)
}

fn set_bkl_dropped(v: bool) {
    let a = CUR_TASK[cpu()].load(Ordering::Acquire);
    if a != 0 {
        unsafe { (*(a as *mut Task)).bkl_dropped = v };
    }
}

/// M17a.f2: czeka na kanale `channel`, aż `cond()` będzie prawdą albo minie
/// tick `deadline` – sprawdzenie warunku i uśpienie pod blokadą schedulera,
/// a pobudka (wake_channel) też ją bierze, więc pobudka z innego CPU nie
/// przepada (wcześniej gwarantował to BKL).  `cond` działa z IF = 0 pod
/// blokadą schedulera: tylko atomiki / krótkie odczyty, bez KMutex i BKL.
/// Wymaga schedulera i zadania, które może spać (sync::WaitQueue sprawdza).
pub fn wait_event(channel: usize, deadline: u64, cond: &mut dyn FnMut() -> bool) -> bool {
    let had_bkl = bkl::held();
    let result = loop {
        let woke_or_timeout = without_interrupts(|| {
            let _g = lock_sched_at(&"wait_event");
            if cond() {
                return Some(true);
            }
            if crate::time::ticks() >= deadline {
                return Some(false);
            }
            block_current(channel, deadline);
            None
        });
        after_switch(&bkl::tag::AFTER_WAIT);
        if let Some(r) = woke_or_timeout {
            break r;
        }
    };
    // Niezmiennik f2: kto czekał z BKL, wraca z BKL (patrz preempt).
    if had_bkl && !bkl::held() {
        let flag = without_interrupts(|| {
            let a = CUR_TASK[cpu()].load(Ordering::Acquire);
            a != 0 && unsafe { (*(a as *const Task)).bkl_dropped }
        });
        panic!(
            "wait_event returned without the BKL on CPU {} (task {}, flag {}, bkl {:?}, site {:?})",
            cpu(),
            current_id(),
            flag,
            bkl::state(),
            bkl::owner_site()
        );
    }
    result
}

/// Testy: (właściciel blokady schedulera: numer CPU + 1, głębokość na tym CPU).
#[allow(dead_code)]
pub fn sched_lock_state() -> (u32, u32) {
    without_interrupts(|| (SCHED_OWNER.load(Ordering::Relaxed), SCHED_DEPTH[cpu()].load(Ordering::Relaxed)))
}

/// (wzięcia, wzięcia z czekaniem, µs czekania) blokady schedulera – `cpus`.
pub fn sched_lock_stats() -> (u64, u64, u64) {
    (SCHED_ACQ.get(), SCHED_CONT.get(), SCHED_WAIT_US.get())
}

/// Bez sprawdzania BKL – tylko raporty błędów (panic, watchdog), które nie
/// mogą czekać na BKL.
fn sched_raw() -> &'static Scheduler {
    unsafe { &*core::ptr::addr_of!(SCHED) }
}

fn index_of(s: &Scheduler, id: TaskId) -> Option<usize> {
    s.tasks.iter().position(|t| t.id == id)
}

// ------------------------------------------------------------
// M17a.f3a: kolejki schedulera (wszystko pod blokadą schedulera)
// ------------------------------------------------------------

#[inline]
fn tm(p: *mut Task) -> &'static mut Task {
    unsafe { &mut *p }
}

/// Zadanie po numerze (kubełek – kilka porównań).
fn find(s: &Scheduler, id: TaskId) -> Option<*mut Task> {
    let mut p = s.ids[(id as usize) % ID_BUCKETS];
    while !p.is_null() {
        if tm(p).id == id {
            return Some(p);
        }
        p = tm(p).id_next;
    }
    None
}

fn id_insert(s: &mut Scheduler, p: *mut Task) {
    let b = (tm(p).id as usize) % ID_BUCKETS;
    tm(p).id_next = s.ids[b];
    s.ids[b] = p;
}

fn id_remove(s: &mut Scheduler, p: *mut Task) {
    let b = (tm(p).id as usize) % ID_BUCKETS;
    let mut cur: *mut *mut Task = &mut s.ids[b];
    unsafe {
        while !(*cur).is_null() {
            if *cur == p {
                *cur = tm(p).id_next;
                tm(p).id_next = core::ptr::null_mut();
                return;
            }
            cur = &mut tm(*cur).id_next;
        }
    }
}

/// Nowe zadanie na listę (i do kolejki gotowych, jeśli gotowe).
fn add_task(s: &mut Scheduler, mut t: Box<Task>) {
    let p: *mut Task = &mut *t;
    {
        let _t = TABLE.write();
        s.tasks.push(t);
        id_insert(s, p);
    }
    enqueue(s, p);
}

/// Do kolejki gotowych (tylko Ready, nie idle, bez powtórzeń).
fn enqueue(s: &mut Scheduler, p: *mut Task) {
    let t = tm(p);
    if t.state == State::Ready && t.idle_cpu.is_none() && !t.queued {
        t.queued = true;
        s.ready.push_back(p, rq_link);
        READY_N.store(s.ready.len, Ordering::Relaxed);
    }
}

/// Zdjęcie z kolejki gotowych (jeśli jest).
fn dequeue(s: &mut Scheduler, p: *mut Task) {
    if tm(p).queued {
        tm(p).queued = false;
        s.ready.remove(p, rq_link);
        READY_N.store(s.ready.len, Ordering::Relaxed);
    }
}

/// Uśpione -> gotowe: zdjęcie z kubełka kanału i z listy terminów.
fn unblock(s: &mut Scheduler, p: *mut Task) {
    let t = tm(p);
    if t.state != State::Blocked {
        return;
    }
    if t.wait_channel != 0 {
        s.waiters[wait_bucket(t.wait_channel)].remove(p, wq_link);
    }
    if t.in_sleepers {
        t.in_sleepers = false;
        s.sleepers.remove(p, sq_link);
    }
    t.state = State::Ready;
    t.wait_channel = 0;
    t.wake_at = u64::MAX;
    enqueue(s, p);
}


// ------------------------------------------------------------
// Przełączanie kontekstu
// ------------------------------------------------------------

global_asm!(r#"
    .section .text
    .global sched_switch
    // rdi = &mut u64 (gdzie zapisać RSP bieżącego zadania), rsi = RSP nowego
    sched_switch:
        push rbp
        push rbx
        push r12
        push r13
        push r14
        push r15
        mov [rdi], rsp
        mov rsp, rsi
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        ret

    .global task_trampoline
    // Pierwsze wejście w nowe zadanie: r12 = funkcja, rbx = argument.
    task_trampoline:
        // M17a.f1: nowe zadanie startuje w środku schedule() poprzedniego –
        // blokada schedulera jest wzięta; zwalniamy ją, zanim włączymy IF.
        call sched_new_task_start
        mov rdi, r12
        mov rsi, rbx
        sti
        call task_main
        ud2
"#);

unsafe extern "sysv64" {
    fn sched_switch(old_rsp: *mut u64, new_rsp: u64);
    fn task_trampoline();
}

#[unsafe(no_mangle)]
extern "sysv64" fn task_main(entry: usize, arg: usize) -> ! {
    let f: fn(usize) = unsafe { core::mem::transmute(entry) };
    f(arg);
    exit()
}

/// Wybiera następne zadanie i przełącza.  Wołać z wyłączonymi przerwaniami.
fn schedule() {
    // M16: nigdy na stosie IST (handler wyjątku na IST nie może usypiać
    // ani przełączać zadań – patrz gdt::on_ist_stack).
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    assert!(
        !crate::arch::x86_64::gdt::on_ist_stack(rsp),
        "sched: task switch on an IST stack (rsp {:#x}) - exception handler tried to block",
        rsp
    );
    // M17a: przełączenie (sen, yield) ze spinlockiem = zakleszczenie, gdy
    // następne zadanie na tym CPU zechce tej samej blokady.
    assert!(
        spin::held_count() == 0,
        "sched: task switch on CPU {} while holding {} spinlock(s), first {:?}",
        cpu(),
        spin::held_count(),
        spin::first_held()
    );
    // M17a.f2: bez BKL – tylko blokada schedulera.
    // Raw TSC: w schedule() bez migracji, a CUR_TASK zmienia się w środku.
    let t_prof = idle_tsc();
    let _g = lock_sched_at(&"schedule");
    let s = sched();
    let me = cpu();
    let Some(curp) = find(s, s.current[me]) else {
        return;
    };
    // M17a.f3a: następne z kolejki gotowych (FIFO) zamiast przeglądania listy.
    let mut nextp = None;
    while let Some(p) = s.ready.pop_front(rq_link) {
        READY_N.store(s.ready.len, Ordering::Relaxed);
        let t = tm(p);
        t.queued = false;
        if t.state == State::Ready && t.idle_cpu.is_none() {
            nextp = Some(p);
            break;
        }
    }
    let cur = tm(curp);
    let nextp = match nextp {
        Some(p) => p,
        // Nic gotowego: bieżące działa dalej, jeśli może; inaczej idle.
        None if cur.state == State::Running => {
            QUANTUM[me].store(QUANTUM_TICKS, Ordering::Relaxed);
            return;
        }
        None => match find(s, s.idle[me]) {
            Some(p) if p != curp => p,
            _ => return,
        },
    };
    QUANTUM[me].store(QUANTUM_TICKS, Ordering::Relaxed);
    // P4.c: wybrane zadanie mogło jeszcze schodzić z innego CPU (obudzone albo
    // oddane do kolejki tuż przed jego przełączeniem) – czekamy, aż tamten CPU
    // zapisze jego rejestry (zdejmuje flagę bez blokady schedulera: kilkaset ns).
    if tm(nextp).on_cpu.load(Ordering::Acquire) {
        let t0 = bkl::rdtsc();
        let mut n: u32 = 0;
        while tm(nextp).on_cpu.load(Ordering::Acquire) {
            core::hint::spin_loop();
            n = n.wrapping_add(1);
            if n % 64 == 0 {
                crate::arch::x86_64::tlb::poll_from_wait();
            }
            if n % 4096 == 0 {
                crate::arch::x86_64::smp::watchdog_poll();
            }
        }
        ONCPU_WAITS.add(1);
        ONCPU_TSC.add(bkl::rdtsc().wrapping_sub(t0) & ((1 << 48) - 1));
    }
    tm(nextp).on_cpu.store(true, Ordering::Relaxed);
    if cur.state == State::Running {
        cur.state = State::Ready;
        enqueue(s, curp); // na koniec kolejki (idle – nie)
    }
    let next = tm(nextp);
    next.state = State::Running;
    // v0.34.0: koniec bezczynności tego CPU – dopasowanie okna kręcenia.
    if cur.idle_cpu.is_some() && next.idle_cpu.is_none() {
        idle_feedback(me);
    }
    // Statystyka: proces wznowiony na innym CPU niż ostatnio (SMP TEST 5).
    if next.process.is_some() && next.switches > 0 && next.last_cpu != me as u8 {
        USER_MIGRATIONS.fetch_add(1, Ordering::Relaxed);
    }
    next.switches += 1;
    next.last_cpu = me as u8;
    next.cpu_mask |= 1 << me;
    s.current[me] = next.id;
    CUR_TASK[me].store(nextp as usize, Ordering::Release);
    TOTAL_SWITCHES.add(1);
    SWITCH_N.add(1);

    // M17a.f1: zadanie nie może działać na dwóch CPU – następne nie jest
    // bieżącym żadnego innego CPU.
    debug_assert!(
        !s.current.iter().enumerate().any(|(c, &id)| c != me && id == next.id),
        "sched: task {} is already current on another CPU",
        next.id
    );
    // Decyzje zależne od stanu – jeszcze pod blokadą (po jej oddaniu inny CPU
    // może zmienić `state` bieżącego zadania, np. obudzić je).
    let save_fpu = cur.process.is_some() && cur.state != State::Dead;
    let idle_switch = (cur.idle_cpu.is_some(), next.idle_cpu.is_some());
    let cr3 = next.cr3();
    let cr3_changes = cr3 != cur.cr3();
    // P4.c: blokada schedulera oddana PRZED przełączeniem – pod nią zostały
    // tylko kolejki i stany.  Bieżące zadanie chroni `on_cpu` (nikt go nie
    // uruchomi ani nie zwolni, zanim następne zadanie nie zdejmie flagi w
    // finish_switch), następne – nasza flaga `on_cpu`.  Strażniki wzięte przez
    // bieżące zadanie (głębokość) po jego powrocie nic nie zwalniają.
    cur.sched_depth = SCHED_DEPTH[me].load(Ordering::Relaxed);
    PREV_TASK[me].store(curp as usize, Ordering::Relaxed);
    SCHED_DEPTH[me].store(0, Ordering::Relaxed);
    sched_hold_end(me);
    SCHED_OWNER.store(0, Ordering::Release);

    // M13a/M14: stos kernela dla przerwań z ring 3 (TSS.RSP0) i dla SYSCALL
    // (blok per CPU) oraz przestrzeń adresowa.
    crate::arch::x86_64::gdt::set_rsp0(next.kernel_stack_top());
    crate::arch::x86_64::syscall::set_kernel_stack(next.kernel_stack_top());
    // M13b: FPU/SSE – zapis stanu procesu, który oddaje CPU, odtworzenie
    // stanu następnego; zadania kernela działają z CR0.TS = 1.
    if save_fpu {
        unsafe { fpu::save(&mut cur.fpu) };
    }
    if next.process.is_some() {
        fpu::clear_ts();
        unsafe { fpu::restore(&next.fpu) };
    } else {
        fpu::set_ts();
    }

    // M17a.b: CR3 tylko przy zmianie przestrzeni adresowej (do M17a.a przy
    // SMP przeładowywany zawsze).  Zmiany górnej połowy unieważnia TLB
    // shootdown; dolnej – samo przeładowanie: CPU, który opuszcza proces,
    // zawsze ładuje inny CR3, a proces działa naraz na jednym CPU (tlb.rs).
    if cr3_changes {
        unsafe { core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags)) };
    }

    // M17a.f2: BKL nie przechodzi na następne zadanie – oddajemy go (weźmiemy
    // z powrotem w after_switch, po wyjściu ze schedulera).
    if bkl::held() {
        bkl::release();
        cur.bkl_dropped = true;
    }
    // M17a.g2: czas w idle (statystyka "% idle").
    if idle_switch.0 || idle_switch.1 {
        let now = idle_tsc();
        if idle_switch.0 {
            let since = IDLE_SINCE[me].load(Ordering::Relaxed);
            if since != 0 {
                IDLE_TSC[me].fetch_add(now.wrapping_sub(since), Ordering::Relaxed);
            }
        }
        IDLE_SINCE[me].store(if idle_switch.1 { now } else { 0 }, Ordering::Relaxed);
    }
    let old: *mut u64 = &mut cur.rsp;
    let new = next.rsp;
    // M17b.f: czas CPU zadania – od jego wejścia na ten CPU do teraz (oba
    // odczyty TSC na tym samym CPU).
    {
        let now = idle_tsc();
        let since = SWITCHED_IN[me].swap(now, Ordering::Relaxed);
        if since != 0 && now > since {
            cur.run_tsc.fetch_add(now - since, Ordering::Relaxed);
        }
        crate::user::prof::add(crate::user::prof::CTX_SWITCH, now.saturating_sub(t_prof));
    }
    unsafe { sched_switch(old, new) };
    // Wróciliśmy (może na innym CPU): poprzednie zadanie tego CPU dostaje
    // zdjęte `on_cpu`; nasze strażniki sprzed przełączenia nic nie zwalniają.
    let depth = current_task_unlocked().map_or(0, |t| t.sched_depth);
    finish_switch(depth);
}

// ------------------------------------------------------------
// API
// ------------------------------------------------------------

fn idle_task(_: usize) {
    idle_loop()
}

fn new_task(id: TaskId, name: &str, stack: Option<TaskStack>, rsp: u64, state: State) -> Box<Task> {
    Box::new(Task {
        id,
        name: String::from(name),
        state,
        rsp,
        stack,
        wait_channel: 0,
        wake_at: u64::MAX,
        cpu_ticks: AtomicU64::new(0),
        switches: 0,
        exit_requested: false,
        process: None,
        fpu: FxState::initial(),
        idle_cpu: None,
        last_cpu: 0,
        cpu_mask: 0,
        sched_depth: 0,
        run_tsc: AtomicU64::new(0),
        bkl_dropped: false,
        queued: false,
        rq: Link::NONE,
        wq: Link::NONE,
        sq: Link::NONE,
        in_sleepers: false,
        id_next: core::ptr::null_mut(),
        dead: AtomicBool::new(false),
        magic: AtomicU64::new(TASK_MAGIC),
        on_cpu: AtomicBool::new(state == State::Running),
    })
}

/// Startuje scheduler: bieżący kod staje się zadaniem 1, powstaje idle.
pub fn init() {
    without_interrupts(|| {
        let _g = lock_sched_at(&"init");
        let s = sched();
        let mut boot = new_task(BOOT_ID, "kernel", None, 0, State::Running);
        boot.cpu_mask = 1;
        add_task(s, boot);
        s.current[0] = BOOT_ID;
        publish_current(s, 0);
    });
    // idle przez zwykły spawn (dostaje własny stos), potem zmiana ID na 0.
    let id = spawn("idle", idle_task, 0).expect("sched: cannot create idle task");
    without_interrupts(|| {
        let _g = lock_sched_at(&"init #2");
        let s = sched();
        if let Some(p) = find(s, id) {
            let _t = TABLE.write();
            id_remove(s, p);
            // idle nie bywa w kolejce gotowych (spawn go tam wstawił)
            dequeue(s, p);
            let t = tm(p);
            t.id = IDLE_ID;
            t.idle_cpu = Some(0);
            id_insert(s, p);
        }
        s.idle[0] = IDLE_ID;
        s.next_id = id;
    });
    ACTIVE.store(true, Ordering::SeqCst);
    serial_println!(
        "[SCHED] Scheduler started: round-robin, {} ms quantum, task stacks {} KiB + guard",
        QUANTUM_TICKS,
        stack::STACK_SIZE / 1024
    );
}

pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Tworzy zadanie kernela wykonujące `entry(arg)`.  Kończy się, gdy
/// `entry` wróci (albo przez `exit()`).
pub fn spawn(name: &str, entry: fn(usize), arg: usize) -> Result<TaskId, &'static str> {
    spawn_in(name, entry, arg, None, false)
}

/// M13a: zadanie z własną przestrzenią adresową (proces).  `entry` działa
/// w ring 0 na stosie kernela zadania, z CR3 procesu – i stamtąd skacze do
/// ring 3 (user::enter_user).
pub fn spawn_user(
    name: &str,
    entry: fn(usize),
    arg: usize,
    process: Box<crate::user::Process>,
    foreground: bool,
) -> Result<TaskId, &'static str> {
    spawn_in(name, entry, arg, Some(process), foreground)
}

fn spawn_in(
    name: &str,
    entry: fn(usize),
    arg: usize,
    process: Option<Box<crate::user::Process>>,
    foreground: bool,
) -> Result<TaskId, &'static str> {
    // M17a: najpierw sprzątamy zakończone zadania.  Wcześniej robił to tylko
    // idle – przy wielu CPU pod obciążeniem idle prawie nie działa i martwe
    // zadania (stos 64 KiB + pamięć procesu) piętrzyły się w tysiące, aż
    // kończyła się pamięć (stress: 2308 martwych zadań, "out of memory").
    if DEAD_TASKS.load(Ordering::Relaxed) > 0 {
        reap();
    }
    let stack = TaskStack::new().ok_or("out of memory for the task stack")?;
    let top = stack.top();
    // Początkowa ramka dla sched_switch (patrz wyżej): r15 r14 r13 r12 rbx
    // rbp, adres powrotu = task_trampoline, 2 x 0 (wyrównanie: po `ret`
    // RSP % 16 == 0, więc `call task_main` daje poprawne wyrównanie ABI).
    let frame: [u64; 9] = [
        0,                            // r15
        0,                            // r14
        0,                            // r13
        entry as usize as u64,        // r12
        arg as u64,                   // rbx
        0,                            // rbp
        task_trampoline as *const () as usize as u64,
        0,
        0,
    ];
    let rsp = top - (frame.len() as u64) * 8;
    unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), rsp as *mut u64, frame.len()) };

    let mut task = new_task(0, name, Some(stack), rsp, State::Ready);
    task.process = process;
    Ok(without_interrupts(|| {
        let _g = lock_sched_at(&"spawn_in");
        let s = sched();
        let id = s.next_id;
        s.next_id += 1;
        let mut task = task;
        task.id = id;
        add_task(s, task);
        // M17a.f2: proces na pierwszy plan – zanim zadanie stanie się
        // widoczne dla innych CPU (blokada schedulera): nie ruszy, zanim
        // Ctrl+C nie będzie go widział.
        if foreground {
            crate::console::push_foreground(id);
        }
        // M17: nowe zadanie od razu na bezczynny CPU (jeśli jest).
        kick_idle(s);
        id
    }))
}

/// Oddaje CPU innym gotowym zadaniom.
#[allow(dead_code)]
pub fn yield_now() {
    if !active() {
        return;
    }
    without_interrupts(|| {
        NEED_RESCHED[cpu()].store(false, Ordering::Relaxed);
        schedule();
    });
    after_switch(&bkl::tag::AFTER_YIELD);
}

/// Kończy bieżące zadanie (zadania 1 nie wolno zakończyć).
pub fn exit() -> ! {
    interrupts::disable();
    let _g = lock_sched_at(&"exit");
    let s = sched();
    let cur = cur_id(s);
    assert!(
        cur != BOOT_ID && find(s, cur).map_or(true, |p| tm(p).idle_cpu.is_none()),
        "sched: kernel/idle task cannot exit"
    );
    if let Some(p) = find(s, cur) {
        tm(p).state = State::Dead;
        tm(p).dead.store(true, Ordering::Release);
        DEAD_TASKS.fetch_add(1, Ordering::Relaxed);
    }
    schedule();
    unreachable!("sched: dead task was scheduled again");
}

pub fn current_id() -> TaskId {
    if !active() {
        return BOOT_ID;
    }
    // M17a.e: bez listy zadań (ta jest pod BKL) – wskaźnik per CPU.
    without_interrupts(|| current_task_unlocked().map(|t| t.id).unwrap_or(BOOT_ID))
}

/// Nazwa bieżącego zadania (raporty błędów; bez alokacji).
pub fn with_current_name<R>(f: impl FnOnce(TaskId, &str) -> R) -> Option<R> {
    if !active() {
        return None;
    }
    without_interrupts(|| {
        let s = sched_raw();
        let i = index_of(s, cur_id(s))?;
        Some(f(s.tasks[i].id, &s.tasks[i].name))
    })
}

/// Czy bieżące zadanie może zasnąć (scheduler działa i to nie idle).
pub fn can_block() -> bool {
    active() && without_interrupts(|| current_task_unlocked().is_some_and(|t| t.idle_cpu.is_none()))
}

/// Usypia bieżące zadanie na kanale `channel` do pobudki albo do ticku
/// `deadline`.  Wołać z wyłączonymi przerwaniami (patrz sync::WaitQueue).
pub fn block_current(channel: usize, deadline: u64) {
    let _g = lock_sched_at(&"block_current");
    let s = sched();
    if let Some(p) = find(s, cur_id(s)) {
        let t = tm(p);
        t.state = State::Blocked;
        t.wait_channel = channel;
        t.wake_at = deadline;
        // M17a.f3a: na listę kanału i listę terminów (pobudka bez przeglądania).
        if channel != 0 {
            s.waiters[wait_bucket(channel)].push_back(p, wq_link);
        }
        if deadline != u64::MAX {
            t.in_sleepers = true;
            s.sleepers.push_back(p, sq_link);
            NEXT_WAKE.fetch_min(deadline, Ordering::Relaxed);
        }
    }
    schedule();
}

/// Budzi zadania czekające na kanale (bezpieczne w przerwaniu).
pub fn wake_channel(channel: usize) {
    if !active() {
        return;
    }
    // M17a.f2: tylko blokada schedulera (bez BKL) – także z przerwania.
    without_interrupts(|| {
        let _g = lock_sched_at(&"wake_channel");
        let s = sched();
        if channel == 0 {
            return;
        }
        // M17a.f3a/b: tylko kubełek tego kanału.
        let mut woke = 0;
        let mut p = s.waiters[wait_bucket(channel)].head;
        while !p.is_null() {
            let next = tm(p).wq.next;
            if tm(p).state == State::Blocked && tm(p).wait_channel == channel {
                unblock(s, p); // zdejmuje z kubełka
                woke += 1;
            }
            p = next;
        }
        for _ in 0..woke.min(MAX_CPUS) {
            kick(s);
        }
    });
}

/// M17a.g10: budzi JEDNO zadanie czekające na kanale – najdłużej czekające
/// (kubełek jest kolejką FIFO).  `true` – obudzono.  Blokady usypiające
/// przekazują się tak jednemu czekającemu zamiast budzić wszystkich (stado:
/// wszyscy przez scheduler, jeden bierze blokadę, reszta wraca spać) – jak
/// mutex w Linuksie (pierwszy z wait_list) i WAKEUP_FIRST w HelenOS.
pub fn wake_one_channel(channel: usize) -> bool {
    if !active() || channel == 0 {
        return false;
    }
    without_interrupts(|| {
        let _g = lock_sched_at(&"wake_one_channel");
        let s = sched();
        let mut p = s.waiters[wait_bucket(channel)].head;
        while !p.is_null() {
            let next = tm(p).wq.next;
            if tm(p).state == State::Blocked && tm(p).wait_channel == channel {
                unblock(s, p);
                kick(s);
                return true;
            }
            p = next;
        }
        false
    })
}

/// Śpi do ticku `deadline` (time::sleep_* woła to po starcie schedulera).
pub fn sleep_until(deadline: u64) {
    // M17a.f2: bez BKL; BKL (jeśli był) wraca w after_switch.
    let had_bkl = bkl::held();
    without_interrupts(|| {
        while crate::time::ticks() < deadline {
            let g = lock_sched_at(&"sleep_until");
            let s = sched();
            if find(s, cur_id(s)).map(|p| tm(p).exit_requested).unwrap_or(false) {
                break; // `kill` – zadanie ma się zakończyć, nie spać dalej
            }
            block_current(0, deadline);
            drop(g);
        }
    });
    after_switch(&bkl::tag::AFTER_SLEEP);
    assert!(!had_bkl || bkl::held(), "sleep_until returned without the BKL on CPU {}", cpu());
}

/// Prośba o zakończenie zadania (zadanie samo sprawdza `should_exit`).
pub fn request_exit(id: TaskId) -> bool {
    if id == BOOT_ID || id == IDLE_ID {
        return false;
    }
    if without_interrupts(|| {
        let _g = lock_sched_at(&"request_exit");
        let s = sched();
        find(s, id).is_some_and(|p| tm(p).idle_cpu.is_some())
    }) {
        return false; // zadania idle (każdego CPU) nie kończymy
    }
    without_interrupts(|| {
        let _g = lock_sched_at(&"request_exit #2");
        let s = sched();
        match find(s, id) {
            Some(p) if tm(p).state != State::Dead => {
                tm(p).exit_requested = true;
                // Czekające zadanie budzimy, żeby mogło to zauważyć (warunki
                // czekania w syscallach sprawdzają should_exit; inne po prostu
                // zasną ponownie).
                if tm(p).state == State::Blocked {
                    unblock(s, p);
                    kick(s);
                }
                true
            }
            _ => false,
        }
    })
}

/// M14: proces bieżącego zadania.  Do procesu sięga tylko jego własne
/// zadanie (syscalle), a struktura jest w Box – adres się nie zmienia, więc
/// referencja jest ważna do końca zadania.  Sprzątanie (reap) dotyczy tylko
/// zakończonych zadań.
pub fn current_process() -> Option<&'static mut crate::user::Process> {
    if !active() {
        return None;
    }
    // M17a.e: bez listy zadań – wskaźnik per CPU (działa także bez BKL).
    without_interrupts(|| current_unlocked().map(|(_, p)| p))
}

/// M16: `f` na procesie zadania `pid` (None: brak zadania, zadanie
/// kernela albo zakończone).  Przy wyłączonych przerwaniach – tylko krótkie
/// odczyty pól atomowych / niezmiennych.
pub fn with_process<R>(pid: TaskId, f: impl FnOnce(&crate::user::Process) -> R) -> Option<R> {
    if !active() {
        return None;
    }
    // P4.b: tylko tablica zadań do odczytu (bez blokady schedulera).
    without_interrupts(|| {
        let _t = TABLE.read();
        let t = unsafe { &*find(table(), pid)? };
        table_check(t);
        if t.dead.load(Ordering::Acquire) {
            return None;
        }
        t.process.as_deref().map(f)
    })
}

/// M16: żywe procesy, których rodzicem jest `ppid`.
#[allow(dead_code)]
pub fn children_of(ppid: TaskId) -> Vec<TaskId> {
    if !active() {
        return Vec::new();
    }
    let mut out = Vec::new();
    without_interrupts(|| {
        let _t = TABLE.read();
        for t in table().tasks.iter() {
            if !t.dead.load(Ordering::Acquire) {
                if let Some(p) = t.process.as_deref() {
                    if p.ppid() == ppid {
                        out.push(t.id);
                    }
                }
            }
        }
    });
    out
}

/// M16: dzieci procesu `from` dostają nowego rodzica `to` (0 = kernel).
/// P1: `first` (pod blokadą schedulera – np. kończący się rodzic ustawia
/// `exiting` i zabiera swoje zombie), potem żywe dzieci `from` dostają rodzica
/// `to`, a `to` – licznik żywych dzieci +n.  Jedna sekcja: dziecko kończące
/// się w tym samym czasie (with_process na rodzicu) widzi albo starego
/// rodzica, który jeszcze przyjmuje, albo już nowego.
pub fn reparent_with(from: TaskId, to: TaskId, first: impl FnOnce()) -> usize {
    if !active() {
        first();
        return 0;
    }
    without_interrupts(|| {
        // P4.b: zapis tablicy zadań (wyklucza with_process – patrz wyżej).
        let _t = TABLE.write();
        first();
        let s = table();
        let mut n = 0;
        for t in s.tasks.iter() {
            if !t.dead.load(Ordering::Acquire) {
                if let Some(p) = t.process.as_deref() {
                    if p.ppid() == from {
                        p.ppid.store(to, Ordering::SeqCst);
                        n += 1;
                    }
                }
            }
        }
        // M17a.g11: nowy rodzic ma teraz dzieci (jego koniec musi je oddać).
        if n > 0 && to != 0 {
            if let Some(t) = find(s, to) {
                if let Some(p) = unsafe { &*t }.process.as_deref() {
                    p.has_children.store(true, Ordering::SeqCst);
                    p.live_children.fetch_add(n as u32, Ordering::SeqCst);
                }
            }
        }
        n
    })
}

/// P1: `f` dla każdego żywego procesu (testy: zombie we wszystkich rodzicach).
#[allow(dead_code)]
pub fn for_each_process(mut f: impl FnMut(TaskId, &crate::user::Process)) {
    if !active() {
        return;
    }
    without_interrupts(|| {
        let _t = TABLE.read();
        for t in table().tasks.iter() {
            if !t.dead.load(Ordering::Acquire) {
                if let Some(p) = t.process.as_deref() {
                    f(t.id, p);
                }
            }
        }
    })
}

/// Szczyt stosu kernela bieżącego zadania (powrót z ring 3 do kernela).
pub fn current_kernel_stack_top() -> u64 {
    without_interrupts(|| {
        let _g = lock_sched_at(&"current_kernel_stack_top");
        let s = sched();
        find(s, cur_id(s)).map(|p| tm(p).kernel_stack_top()).unwrap_or(0)
    })
}

pub fn should_exit() -> bool {
    // M17a.e: bez BKL (flaga bieżącego zadania przez wskaźnik per CPU).
    active() && without_interrupts(should_exit_unlocked)
}

/// Lista zadań (bez zakończonych).
pub fn tasks() -> Vec<TaskInfo> {
    if !active() {
        return Vec::new();
    }
    let mut out = Vec::new();
    without_interrupts(|| {
        let _g = lock_sched_at(&"tasks");
        let s = sched();
        for t in s.tasks.iter() {
            if t.state == State::Dead {
                continue;
            }
            out.push(TaskInfo {
                id: t.id,
                name: t.name.clone(),
                state: t.state,
                cpu_ticks: t.cpu_ticks.load(Ordering::Relaxed),
                switches: t.switches,
                stack_top: t.stack.as_ref().map(|st| st.top()).unwrap_or(0),
                user: t.process.is_some(),
                ppid: t.process.as_deref().map(|p| p.ppid()).unwrap_or(0),
                cpu: s.current.iter().position(|&c| c == t.id),
                last_cpu: t.last_cpu as usize,
                cpu_mask: t.cpu_mask,
            });
        }
    });
    out
}

/// M17a.g6: czy zadanie jeszcze istnieje (bez kopiowania listy zadań –
/// pętla stressu pytała task_info o 48 zadań co 2 ms).
pub fn task_exists(id: TaskId) -> bool {
    without_interrupts(|| {
        let _t = TABLE.read();
        find(table(), id).map(|p| table_check(unsafe { &*p })).is_some()
    })
}

pub fn task_info(id: TaskId) -> Option<TaskInfo> {
    tasks().into_iter().find(|t| t.id == id)
}

pub fn total_switches() -> u64 {
    TOTAL_SWITCHES.get()
}

/// Zwalnia zakończone zadania (stos, struktura).  Woła idle i testy.
/// Ile razy proces użytkownika wznowiono na innym CPU niż poprzednio.
static USER_MIGRATIONS: AtomicU64 = AtomicU64::new(0);

/// Licznik migracji procesów między CPU (testy).
#[allow(dead_code)]
pub fn user_migrations() -> u64 {
    USER_MIGRATIONS.load(Ordering::Relaxed)
}

/// M17a.g1: zakończone zadania czekające na sprzątanie (pętla idle sprawdza
/// to bez BKL i bierze go tylko wtedy, gdy jest co sprzątać).
static DEAD_TASKS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub fn reap() -> usize {
    let t0 = crate::user::prof::start();
    // M17a.f3b: miejsce przygotowane przed blokadą schedulera (bez alokacji
    // pod nią; więcej martwych niż miejsca – zostaną na następny raz).
    let room = DEAD_TASKS.load(Ordering::Relaxed).clamp(1, 64);
    let mut dead: Vec<Box<Task>> = Vec::with_capacity(room);
    without_interrupts(|| {
        let _g = lock_sched_at(&"reap");
        let s = sched();
        let _t = TABLE.write();
        let mut i = 0;
        while i < s.tasks.len() {
            // P4.c: martwe zadanie może jeszcze schodzić z CPU (on_cpu).
            if dead.len() < room
                && s.tasks[i].state == State::Dead
                && !s.current.contains(&s.tasks[i].id)
                && !s.tasks[i].on_cpu.load(Ordering::Acquire)
            {
                let id = s.tasks[i].id;
                let p: *mut Task = &mut *s.tasks[i];
                let _ = id;
                id_remove(s, p);
                dead.push(s.tasks.swap_remove(i));
            } else {
                i += 1;
            }
        }
        let _ = DEAD_TASKS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |d| Some(d.saturating_sub(dead.len())));
    });
    let n = dead.len();
    drop(dead); // stosy odmapowane, ramki wracają (z włączonymi przerwaniami)
    crate::user::prof::stop(crate::user::prof::REAP, t0);
    n
}

// ------------------------------------------------------------
// Przerwania: tick + wywłaszczenie
// ------------------------------------------------------------

// M17a.g12: tick bez blokady schedulera, gdy nie ma kogo budzić.  Czas CPU
// i kwant to dane tego CPU (zadanie bieżące zmienia tylko ten CPU, a w
// przerwaniu IF = 0), a "są gotowe zadania" – licznik READY_N (podpowiedź;
// pobudka i tak wysyła IPI).  Wcześniej każdy CPU co 1 ms brał globalną
// blokadę: na Legionie ~16 tys. wzięć/s tylko na liczenie czasu.
/// Kwant zadania bieżącego każdego CPU (ms).
static QUANTUM: crate::arch::x86_64::percpu::PerCpu<AtomicU32> = crate::per_cpu!(AtomicU32::new(QUANTUM_TICKS));
/// Długość kolejki gotowych (pisana pod blokadą, czytana bez – podpowiedź).
static READY_N: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// Najwcześniejszy termin na liście `sleepers` (u64::MAX = pusta); po
/// pobudce przed terminem może być za wcześnie – wtedy tylko zbędne wzięcie.
static NEXT_WAKE: AtomicU64 = AtomicU64::new(u64::MAX);

/// Z IRQ0 (time::on_tick) – tylko BSP (PIT, 1 tick = 1 ms): budzi śpiące
/// zadania i liczy kwant zadania BSP.
pub fn on_tick(now: u64) {
    if !active() {
        return;
    }
    // M17a.b: tick może przeskoczyć o kilka ms (doganianie HPET po zgubionych
    // przerwaniach PIT) – czas CPU i kwant liczone według zegara.
    let last = LAST_BSP_TICK.swap(now, core::sync::atomic::Ordering::Relaxed);
    let ms = if last == 0 { 1 } else { now.saturating_sub(last).clamp(1, 1000) as u32 };
    tick_cpu(ms);
    if now < NEXT_WAKE.load(Ordering::Relaxed) {
        return;
    }
    let _g = lock_sched_at(&"on_tick");
    let s = sched();
    let mut woke = 0;
    let mut next = u64::MAX;
    // M17a.f3a/b: tylko zadania z terminem (lista bez sortowania – jest ich
    // niewiele: śpiące `sleep`, czekania z timeoutem).
    let mut p = s.sleepers.head;
    while !p.is_null() {
        let nextp = tm(p).sq.next;
        if tm(p).wake_at <= now {
            unblock(s, p); // zdejmuje też z listy terminów
            woke += 1;
        } else {
            next = next.min(tm(p).wake_at);
        }
        p = nextp;
    }
    NEXT_WAKE.store(next, Ordering::Relaxed);
    for _ in 0..woke.min(MAX_CPUS) {
        kick(s);
    }
}

/// M17a: flaga "przełącz przy najbliższej okazji" CPU `c` (diagnostyka).
#[allow(dead_code)]
pub fn need_resched_of(c: usize) -> bool {
    NEED_RESCHED[c % MAX_CPUS].load(Ordering::Relaxed)
}

/// M17a: liczba gotowych zadań (nie idle) – diagnostyka.
#[allow(dead_code)]
pub fn ready_count() -> usize {
    without_interrupts(|| {
        let _g = lock_sched_at(&"ready_count");
        sched().ready.len
    })
}

/// M17: tick timera LAPIC procesora AP (co `ms` ms).
pub fn ap_tick(ms: u32) {
    if !active() {
        return;
    }
    tick_cpu(ms);
}

/// Czas CPU zadania bieżącego tego procesora i jego kwant (z przerwania
/// zegara, IF = 0, bez blokady schedulera – patrz QUANTUM).
fn tick_cpu(ms: u32) {
    let me = cpu();
    let Some(cur) = current_task_unlocked() else { return };
    cur.cpu_ticks.fetch_add(ms as u64, Ordering::Relaxed);
    let q = QUANTUM[me].load(Ordering::Relaxed).saturating_sub(ms);
    QUANTUM[me].store(q, Ordering::Relaxed);
    if q == 0 {
        NEED_RESCHED[me].store(true, Ordering::Relaxed);
    }
    // Idle, a są gotowe zadania (np. pobudka bez IPI) – bierzemy je.
    if cur.idle_cpu.is_some() && READY_N.load(Ordering::Relaxed) > 0 {
        NEED_RESCHED[me].store(true, Ordering::Relaxed);
    }
}

/// M17: jakieś zadanie stało się gotowe – kto ma je wziąć.  Jeśli ten CPU
/// stoi w idle – on sam (po przerwaniu).  Inaczej pierwszy bezczynny CPU,
/// budzony przerwaniem IPI (z `hlt`).  Gdy wszystkie są zajęte – ten CPU
/// (wywłaszczenie, jak na jednym rdzeniu).
fn kick(s: &mut Scheduler) {
    let me = cpu();
    if s.current[me] == s.idle[me] {
        NEED_RESCHED[me].store(true, Ordering::Relaxed);
        return;
    }
    if !kick_idle(s) {
        NEED_RESCHED[me].store(true, Ordering::Relaxed);
    }
}

/// Budzi jeden bezczynny CPU (inny niż ten); `false` – nie ma takiego.
fn kick_idle(s: &mut Scheduler) -> bool {
    let me = cpu();
    for c in 0..MAX_CPUS {
        if c != me
            && s.idle[c] != NO_TASK
            && s.current[c] == s.idle[c]
            && crate::arch::x86_64::smp::online(c)
            && !NEED_RESCHED[c].swap(true, Ordering::SeqCst)
        {
            // v0.34.0: CPU kręci się w idle – zobaczy flagę sam, bez przerwania.
            if POLLING[c].load(Ordering::SeqCst) {
                IPI_SKIPPED.add(1);
            } else {
                crate::arch::x86_64::smp::send_resched(c);
            }
            return true;
        }
    }
    false
}

/// Z irq::dispatch, po EOI: przełącza, jeśli trzeba.
/// Wywłaszczenie z końca przerwania.  `had_bkl` – czy przerwany kontekst
/// trzymał BKL.  M17a.g2: jeśli nie (proces w ring 3, kod bez BKL, idle),
/// po powrocie BKL NIE jest brany z powrotem – reszta przerwania (kill
/// procesu: dziennik zakończeń ma własną blokadę) go nie potrzebuje, a wyjście
/// z przerwania i tak by go oddało.  Legion v0.17.10: takie "weź, żeby
/// oddać" było dużą częścią 434 tys. wzięć po przełączeniu.
pub fn preempt_irq(had_bkl: bool) {
    // M17a: CPU trzyma SpinLock – przełączenie poczeka (NEED_RESCHED zostaje).
    if crate::arch::x86_64::cpu::preempt_count() > 0 {
        return;
    }
    if active() && NEED_RESCHED[cpu()].swap(false, Ordering::Relaxed) {
        // M17a.f2: przerwanie mogło wskoczyć między uśpieniem zadania a jego
        // after_switch (IF = 1 na chwilę) – flaga "oddał BKL" należy wtedy do
        // przerwanego kontekstu, nie do przerwania.  Odkładamy ją na czas
        // przełączenia tutaj i przywracamy (znalezione: SCHED TEST 7,
        // "wait_event lost BKL" – przerwanie zabierało flagę i oddawało BKL).
        let pending = take_bkl_dropped();
        schedule();
        if had_bkl {
            after_switch(&bkl::tag::AFTER_PREEMPT);
        } else {
            // BKL wzięło tylko to przerwanie – nie wracamy po niego.
            let _ = take_bkl_dropped();
        }
        set_bkl_dropped(pending);
    }
}

/// M17: rejestruje kontekst startowy procesora `cpu` (AP) jako jego zadanie
/// idle – na stosie `stack`.  Woła BSP przed obudzeniem AP; AP po starcie
/// po prostu wykonuje `idle_loop` na tym stosie.
pub fn spawn_idle_for_cpu(cpu_index: usize, stack: TaskStack) -> TaskId {
    without_interrupts(|| {
        let _g = lock_sched_at(&"spawn_idle_for_cpu");
        let s = sched();
        let id = s.next_id;
        s.next_id += 1;
        let mut name = String::from("idle");
        let _ = core::fmt::Write::write_fmt(&mut name, format_args!("/{}", cpu_index));
        let mut t = new_task(id, &name, Some(stack), 0, State::Running);
        t.idle_cpu = Some(cpu_index as u8);
        t.last_cpu = cpu_index as u8;
        t.cpu_mask = 1 << cpu_index;
        add_task(s, t);
        s.current[cpu_index] = id;
        publish_current(s, cpu_index);
        s.idle[cpu_index] = id;
        id
    })
}

/// Szczyt stosu zadania (AP: stos startowy = stos jego idle).
pub fn task_stack_top(id: TaskId) -> Option<u64> {
    without_interrupts(|| {
        let _g = lock_sched_at(&"task_stack_top");
        let s = sched();
        index_of(s, id).and_then(|i| s.tasks[i].stack.as_ref().map(|st| st.top()))
    })
}

/// M17: pętla idle (BSP: zadanie 0; AP: kontekst startowy procesora).
/// M17a.g2: jeden sprzątający naraz (pętla idle).
static REAPER: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// M17a.g2: takty TSC, przez które CPU wykonywał swoje zadanie idle (liczone
/// w schedule() przy przełączeniu z / na idle – pomiar wokół `hlt` liczyłby
/// też czas zadań, na które przerwanie przełączyło w środku), i początek
/// bieżącego okresu idle.  TSC zawsze tego samego CPU.
static IDLE_TSC: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static IDLE_SINCE: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));

/// M17b.f: TSC chwili, w której bieżące zadanie tego CPU weszło na CPU.
static SWITCHED_IN: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));

/// M17b.f: cykle CPU bieżącego zadania do tej chwili (monotoniczne dla
/// zadania, także po migracji; czas, gdy nie działało, się nie liczy).
pub fn task_cpu_cycles() -> u64 {
    crate::arch::x86_64::interrupts::without_interrupts(|| {
        let me = cpu();
        let a = CUR_TASK[me].load(Ordering::Acquire);
        if a == 0 {
            return 0;
        }
        let t = unsafe { &*(a as *const Task) };
        let since = SWITCHED_IN[me].load(Ordering::Relaxed);
        let now = idle_tsc();
        t.run_tsc.load(Ordering::Relaxed) + if since != 0 && now > since { now - since } else { 0 }
    })
}

fn idle_tsc() -> u64 {
    let (lo, hi): (u32, u32);
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) };
    ((hi as u64) << 32) | lo as u64
}

/// Mikrosekundy w `hlt` pętli idle na CPU `c` (0 bez kalibracji TSC).
pub fn idle_us(c: usize) -> u64 {
    let per_ms = crate::arch::x86_64::lapic::tsc_per_ms();
    if per_ms == 0 {
        return 0;
    }
    IDLE_TSC[c % MAX_CPUS].load(Ordering::Relaxed).saturating_mul(1000) / per_ms
}

/// v0.32.2: ile µs bezczynny CPU kręci się przed `hlt` (z buildu:
/// `DESOOS_IDLE_POLL_US`, domyślnie 50; 0 = od razu hlt).  Hipoteza: na
/// prawdziwym sprzęcie `hlt` usypia rdzeń głębiej (AMD: C1 → CC6), pobudka
/// trwa dziesiątki µs i wydłuża każde przekazanie zadania – od P4 rdzenie
/// mniej kręcą się na blokadzie, a częściej śpią (Legion: idle 26 → 28–32%,
/// stress −5%; KVM bez spadku).  Jak `haltpoll` w Linuksie.
/// v0.34.0: to jest GÓRNA granica okna; okno każdego CPU dobiera się samo
/// (`DESOOS_IDLE_POLL_ADAPT`, domyślnie 1), patrz `idle_adapt`.
pub fn idle_poll_us() -> u64 {
    match option_env!("DESOOS_IDLE_POLL_US") {
        Some(s) => s.trim().parse::<u64>().unwrap_or(200).min(10_000),
        None => 200,
    }
}

/// v0.34.0: okno kręcenia dobierane per CPU (jak `haltpoll` w Linuksie):
/// praca przyszła w ciągu `idle_poll_us()` od uśpienia – okno ×2 (kręcenie
/// by ją złapało); dłuższa bezczynność – okno /2, aż do 0 (bezczynny system
/// nie kręci się – bateria).  0 – stałe okno = `idle_poll_us()`.
pub fn idle_adapt() -> bool {
    !matches!(option_env!("DESOOS_IDLE_POLL_ADAPT").map(|s| s.trim()), Some("0"))
}

const POLL_GROW_MIN_US: u64 = 10;

/// (pobudki w trakcie kręcenia, wejścia w hlt) – `cpus`.
static IDLE_POLL_HITS: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static IDLE_HALTS: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
/// v0.34.0: CPU kręci się w pętli idle – pobudka bez IPI (wystarczy flaga).
static POLLING: crate::arch::x86_64::percpu::PerCpu<AtomicBool> = crate::per_cpu!(AtomicBool::new(false));
static IPI_SKIPPED: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
/// v0.34.0: bieżące okno kręcenia (µs) każdego CPU i TSC pierwszego `hlt`
/// w obecnym okresie bezczynności (0 = nie spał).
static POLL_WIN: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(50));
static HLT_AT: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static POLL_GROWS: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();
static POLL_SHRINKS: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();

/// (pobudki w kręceniu, hlt, pominięte IPI, wzrosty okna, spadki okna, średnie okno µs).
pub fn idle_poll_stats() -> (u64, u64, u64, u64, u64, u64) {
    let n = crate::arch::x86_64::smp::online_count().max(1);
    let sum: u64 = (0..n).map(|c| POLL_WIN[c].load(Ordering::Relaxed)).sum();
    // Stałe okno: pokaż faktyczną wartość, nie startowe POLL_WIN.
    let avg = if idle_adapt() { sum / n as u64 } else { idle_poll_us() };
    (IDLE_POLL_HITS.get(), IDLE_HALTS.get(), IPI_SKIPPED.get(), POLL_GROWS.get(), POLL_SHRINKS.get(), avg)
}

/// v0.34.0: CPU `me` zaczyna pracę po bezczynności – jeśli spał (`hlt`),
/// dopasuj okno: praca przyszła szybko – większe, po długim śnie – mniejsze.
fn idle_feedback(me: usize) {
    let t = HLT_AT[me].swap(0, Ordering::Relaxed);
    if t == 0 || !idle_adapt() {
        return;
    }
    let max = idle_poll_us();
    let per_us = (crate::arch::x86_64::lapic::tsc_per_ms() / 1000).max(1);
    let slept = bkl::rdtsc().wrapping_sub(t) / per_us;
    let w = POLL_WIN[me].load(Ordering::Relaxed);
    if slept <= max {
        POLL_WIN[me].store((w * 2).max(POLL_GROW_MIN_US).min(max), Ordering::Relaxed);
        POLL_GROWS.add(1);
    } else if w > 0 {
        let nw = w / 2;
        POLL_WIN[me].store(if nw < POLL_GROW_MIN_US { 0 } else { nw }, Ordering::Relaxed);
        POLL_SHRINKS.add(1);
    }
}

pub fn idle_loop() -> ! {
    // M17a.g1: pętla idle bez BKL.  Wcześniej trzymała go stale: oddawała na
    // czas `hlt` i brała z powrotem po każdej pobudce – także po IPI TLB
    // shootdown (wektor 0x43 nie bierze BKL), tylko po to, żeby zawołać reap
    // i znowu usnąć.  Legion (v0.17.9, 16 CPU): 2,37 mln takich wzięć, 89% z
    // czekaniem – 129 s z 173 s całego czekania na BKL.  Teraz BKL tylko na
    // sprzątanie (zwolnienie procesu i jego przestrzeni – jeszcze pod BKL),
    // i tylko gdy jest co sprzątać.
    interrupts::disable();
    if bkl::held() {
        bkl::release();
    }
    // Pierwszy okres idle tego CPU (AP startuje od razu w idle).
    if IDLE_SINCE[cpu()].load(Ordering::Relaxed) == 0 {
        IDLE_SINCE[cpu()].store(idle_tsc(), Ordering::Relaxed);
    }
    interrupts::enable();
    loop {
        // M17a.g2: sprząta jeden CPU naraz – pozostałe bezczynne CPU nie stają
        // w kolejce do BKL po to samo zadanie (Legion v0.17.10: 143 tys. wzięć,
        // 78% z czekaniem).
        if DEAD_TASKS.load(Ordering::Relaxed) > 0
            && REAPER.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok()
        {
            interrupts::disable();
            let took = bkl::acquire_if_needed_tagged(&bkl::tag::IDLE_REAP);
            interrupts::enable();
            reap();
            if took {
                interrupts::disable();
                bkl::release();
                interrupts::enable();
            }
            REAPER.store(false, Ordering::Release);
        }
        // v0.32.2: najpierw krótkie kręcenie z IF = 1 – pobudka (IPI) trafia w
        // działający rdzeń i od razu przełącza na zadanie (preempt na końcu
        // przerwania); po kręceniu `hlt` jak dotąd.
        let me = cpu();
        let max = idle_poll_us();
        let poll = if idle_adapt() { POLL_WIN[me].load(Ordering::Relaxed).min(max) } else { max };
        if poll > 0 {
            let per_us = (crate::arch::x86_64::lapic::tsc_per_ms() / 1000).max(1);
            let t0 = bkl::rdtsc();
            let mut hit = false;
            let mut reap_due = false;
            // v0.34.0: flaga „kręcę się” – budzący nie wysyła IPI.  Kolejność
            // (Dekker): budzący ustawia NEED_RESCHED, potem czyta POLLING; my
            // zdejmujemy POLLING, potem jeszcze raz czytamy NEED_RESCHED –
            // jedno z dwojga zawsze zobaczy drugie, pobudka nie przepada.
            POLLING[me].store(true, Ordering::SeqCst);
            while bkl::rdtsc().wrapping_sub(t0) < poll * per_us {
                if NEED_RESCHED[me].load(Ordering::SeqCst) {
                    hit = true;
                    break;
                }
                if DEAD_TASKS.load(Ordering::Relaxed) > 0 && !REAPER.load(Ordering::Relaxed) {
                    reap_due = true;
                    break;
                }
                core::hint::spin_loop();
            }
            POLLING[me].store(false, Ordering::SeqCst);
            if !hit && NEED_RESCHED[me].load(Ordering::SeqCst) {
                hit = true;
            }
            if hit {
                IDLE_POLL_HITS.add(1);
                if NEED_RESCHED[me].swap(false, Ordering::Relaxed) {
                    yield_now();
                }
                continue;
            }
            if reap_due {
                continue;
            }
        }
        // Przed hlt: ostatnie sprawdzenie z IF = 0 (pobudka bez IPI mogła
        // przyjść tuż przed zdjęciem POLLING); IPI po tym punkcie obudzi hlt.
        interrupts::disable();
        if NEED_RESCHED[me].load(Ordering::SeqCst) {
            interrupts::enable();
            if NEED_RESCHED[me].swap(false, Ordering::Relaxed) {
                yield_now();
            }
            continue;
        }
        if HLT_AT[me].load(Ordering::Relaxed) == 0 {
            HLT_AT[me].store(bkl::rdtsc().max(1), Ordering::Relaxed);
        }
        IDLE_HALTS.add(1);
        interrupts::enable_and_hlt();
    }
}

/// M17a: numer zadania bieżącego CPU `c` bez blokad i alokacji (raport
/// watchdoga – stan może być w trakcie zmiany, to tylko wskazówka).
pub fn current_id_on(c: usize) -> Option<TaskId> {
    let s = unsafe { &*core::ptr::addr_of!(SCHED) };
    let id = s.current[c % MAX_CPUS];
    (id != NO_TASK).then_some(id)
}

/// M17: zadanie bieżące procesora `cpu` (diagnostyka: `cpus`).
pub fn current_on(cpu_index: usize) -> Option<(TaskId, String, bool)> {
    if !active() || cpu_index >= MAX_CPUS {
        return None;
    }
    without_interrupts(|| {
        let _g = lock_sched_at(&"current_on");
        let s = sched();
        let id = s.current[cpu_index];
        let i = index_of(s, id)?;
        Some((id, s.tasks[i].name.clone(), id == s.idle[cpu_index]))
    })
}

#[cfg(selftest)]
mod test;
#[cfg(selftest)]
pub use test::self_test;
