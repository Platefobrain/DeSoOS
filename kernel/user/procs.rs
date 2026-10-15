// M16: rodzina procesów – rodzic/dziecko, zombie, wait, init.
//
// * Każdy proces ma rodzica (Process.ppid).  0 = kernel (nadzorca init,
//   shell kernela, samotesty) – takie procesy kernel sprząta sam, jak do tej
//   pory (sched::task_info / user::exit_info).
// * Proces z rodzicem-procesem po zakończeniu zostaje zombie: zadanie
//   znika, ale kod wyjścia czeka na liście zombie rodzica, aż ten go odbierze
//   (`wait`).
// * Kończący się proces oddaje swoje dzieci (żywe i zombie) do init.  Gdy
//   init jeszcze nie działa (samotesty, shell kernela) – do kernela: żywe
//   dzieci działają dalej, zombie znikają.
// * P1 (po M19): zombie żyją w procesie-rodzicu (`Process.zombies`, spinlock
//   na rodzica) – zamiast jednej tablicy pod usypiającą blokadą, o którą
//   biły się wszystkie procesy (Legion v0.19.7, pełne obciążenie: 12,3 mln
//   wzięć, 168 s czekania w minucie).  Zasady:
//     - dziecko dopisuje się pod blokadą schedulera (with_process na rodzicu)
//       i blokadą listy rodzica, sprawdzając, że rodzic się nie kończy i że
//       wciąż jest jego rodzicem (inaczej próbuje u nowego),
//     - kończący się rodzic w JEDNEJ sekcji pod blokadą schedulera ustawia
//       `exiting`, zabiera swoje zombie i oddaje żywe dzieci (reparent_with),
//       potem zombie przekazuje init,
//     - `wait` bierze tylko blokadę własnej listy; żywe dzieci liczy ten sam
//       licznik, który dziecko zmniejsza razem z wpisem zombie.
//
// Status (wait): kod wyjścia 0..255 albo STATUS_SIGNALED | powód
// (9 = kill/Ctrl+C, numer wyjątku CPU, 0xFF = zły adres powrotu).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::ExitKind;
use crate::sched::sync::WaitQueue;
use crate::sched::{self, TaskId};

pub const STATUS_SIGNALED: u64 = 0x100;
pub const REASON_KILLED: u64 = 9;
pub const REASON_BAD_RETURN: u64 = 0xFF;

/// wait(pid = ANY): dowolne dziecko.
pub const WAIT_ANY: u64 = u64::MAX;
/// Flaga wait: nie czekaj (0, gdy żadne dziecko się jeszcze nie skończyło).
pub const WNOHANG: u64 = 1;

#[derive(Clone, Copy, Default)]
pub struct Zombie {
    pid: TaskId,
    status: u64,
}

/// P1 (v0.20.2): blokada listy zombie w procesie.  NIE `IrqSpinLock`:
/// RawSpin ma wyrównanie 64 B (linia cache), przez co cały `Process` miał
/// wyrównanie 64 i każdy proces szedł wolną ścieżką heapa (bloki > 2 KiB albo
/// wyrównanie > 16 – globalna lista): w v0.20.0/0.20.1 czekania na heap
/// +50%.  Tu: jeden bajt + przerwania wyłączone na czas sekcji (kilka
/// instrukcji), bez lockdep – brana tylko w procs.rs, nigdy dwie naraz.
pub struct ChildList {
    locked: core::sync::atomic::AtomicBool,
    list: core::cell::UnsafeCell<Zombies>,
}

unsafe impl Sync for ChildList {}
unsafe impl Send for ChildList {}

pub struct ChildGuard<'a> {
    owner: &'a ChildList,
    irq: bool,
}

impl ChildList {
    pub const fn new() -> Self {
        ChildList { locked: core::sync::atomic::AtomicBool::new(false), list: core::cell::UnsafeCell::new(Zombies::new()) }
    }

    pub fn lock(&self) -> ChildGuard<'_> {
        use crate::arch::x86_64::interrupts;
        let irq = interrupts::are_enabled();
        interrupts::disable();
        // P4.0: czekanie odczytem, próba przejęcia dopiero przy wolnej blokadzie.
        while self.locked.load(Ordering::Relaxed) || self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        ChildGuard { owner: self, irq }
    }
}

impl core::ops::Deref for ChildGuard<'_> {
    type Target = Zombies;
    fn deref(&self) -> &Zombies {
        unsafe { &*self.owner.list.get() }
    }
}

impl core::ops::DerefMut for ChildGuard<'_> {
    fn deref_mut(&mut self) -> &mut Zombies {
        unsafe { &mut *self.owner.list.get() }
    }
}

impl Drop for ChildGuard<'_> {
    fn drop(&mut self) {
        self.owner.locked.store(false, Ordering::Release);
        if self.irq {
            crate::arch::x86_64::interrupts::enable();
        }
    }
}

/// P1: lista zombie rodzica – pierwsze INLINE wpisy w samym procesie, dalej
/// Vec.  Bez tego każdy proces z dziećmi alokował i zwalniał bufor na heapie
/// (KVM v0.20.0: czekania na blokadę heapa +45%).  Kolejność odbioru: dowolna
/// (POSIX jej nie gwarantuje).
const INLINE: usize = 4;

pub struct Zombies {
    inline: [Zombie; INLINE],
    n: usize,
    more: Vec<Zombie>,
}

impl Zombies {
    pub const fn new() -> Self {
        Zombies { inline: [Zombie { pid: 0, status: 0 }; INLINE], n: 0, more: Vec::new() }
    }

    fn push(&mut self, z: Zombie) {
        if self.n < INLINE {
            self.inline[self.n] = z;
            self.n += 1;
        } else {
            self.more.push(z);
        }
    }

    /// Pierwszy wpis spełniający `f` – zdjęty z listy.
    fn take_first(&mut self, f: impl Fn(&Zombie) -> bool) -> Option<Zombie> {
        if let Some(i) = self.inline[..self.n].iter().position(&f) {
            let z = self.inline[i];
            self.n -= 1;
            self.inline[i] = self.inline[self.n];
            if let Some(m) = self.more.pop() {
                self.inline[self.n] = m;
                self.n += 1;
            }
            return Some(z);
        }
        let i = self.more.iter().position(&f)?;
        Some(self.more.swap_remove(i))
    }

    fn take_all(&mut self) -> Vec<Zombie> {
        if self.n == 0 {
            return Vec::new();
        }
        let mut all = core::mem::take(&mut self.more);
        all.extend_from_slice(&self.inline[..self.n]);
        self.n = 0;
        all
    }

    fn iter(&self) -> impl Iterator<Item = &Zombie> {
        self.inline[..self.n].iter().chain(self.more.iter())
    }
}

/// M17a.g11: rodzic czeka w kolejce wybranej po swoim numerze – koniec
/// procesu budzi tylko jego rodzica (i ewentualnie init).
#[repr(align(8))] // osobne adresy = osobne kubełki kanałów schedulera
struct ChildQ(WaitQueue);
const CHILD_QUEUES: usize = 64;
static CHILD_EXIT: [ChildQ; CHILD_QUEUES] = [const { ChildQ(WaitQueue::new()) }; CHILD_QUEUES];

fn child_q(parent: TaskId) -> &'static WaitQueue {
    &CHILD_EXIT[(parent as usize) % CHILD_QUEUES].0
}
static INIT_PID: AtomicU64 = AtomicU64::new(0);

/// Init (0 = nie działa).
pub fn init_pid() -> TaskId {
    INIT_PID.load(Ordering::SeqCst)
}

pub fn set_init_pid(pid: TaskId) {
    INIT_PID.store(pid, Ordering::SeqCst);
}

pub fn status_of(kind: ExitKind) -> u64 {
    match kind {
        ExitKind::Exit(code) => (code as u64) & 0xFF,
        ExitKind::Killed => STATUS_SIGNALED | REASON_KILLED,
        ExitKind::BadReturn => STATUS_SIGNALED | REASON_BAD_RETURN,
        ExitKind::Breakpoint => STATUS_SIGNALED | 3,
        ExitKind::PageFault { .. } => STATUS_SIGNALED | 14,
        ExitKind::GeneralProtection { .. } => STATUS_SIGNALED | 13,
        ExitKind::InvalidOpcode => STATUS_SIGNALED | 6,
        ExitKind::FpuUnavailable => STATUS_SIGNALED | 7,
        ExitKind::SimdException => STATUS_SIGNALED | 19,
        ExitKind::Exception { vector } => STATUS_SIGNALED | (vector & 0xFF),
    }
}

/// Czy `pid` to żywy proces użytkownika, który jeszcze się nie kończy.
fn accepts_children(pid: TaskId) -> bool {
    pid != 0 && sched::with_process(pid, |p| !p.exiting.load(Ordering::SeqCst)).unwrap_or(false)
}

/// Bieżący proces się kończy (user::exit_current, przed sched::exit):
/// dzieci do init, własny kod wyjścia do rodzica.
pub fn on_exit(me: TaskId, kind: ExitKind) {
    let Some(p) = sched::current_process() else { return };
    let p: &super::Process = p;
    let heir = match init_pid() {
        init if init != me && accepts_children(init) => init,
        _ => 0,
    };

    // 1. `exiting` + własne zombie zabrane + żywe dzieci -> init (albo kernel,
    // gdy init nie działa lub to sam init) – jedna sekcja pod blokadą
    // schedulera.  Bez dzieci (has_children) przegląd listy zadań pomijamy.
    let mut orphans: Vec<Zombie> = Vec::new();
    let take = || {
        let mut z = p.zombies.lock();
        p.exiting.store(true, Ordering::SeqCst);
        z.take_all()
    };
    if p.has_children.load(Ordering::SeqCst) {
        sched::reparent_with(me, heir, || orphans = take());
    } else {
        orphans = take();
    }
    if heir != 0 && !orphans.is_empty() {
        let handed = sched::with_process(heir, move |h| {
            let mut z = h.zombies.lock();
            if h.exiting.load(Ordering::SeqCst) {
                return false;
            }
            for o in orphans {
                z.push(o);
            }
            h.child_gen.fetch_add(1, Ordering::SeqCst);
            true
        });
        if handed == Some(true) {
            child_q(heir).wake_all();
        }
    }

    // 2. Własny status -> rodzic (żywy proces, który się nie kończy); rodzic
    // ma o jedno żywe dziecko mniej – w tej samej sekcji co wpis zombie.
    enum Push {
        Done,
        Retry,
        Refused,
    }
    let status = status_of(kind);
    loop {
        let ppid = p.ppid();
        if ppid == 0 {
            break;
        }
        let r = sched::with_process(ppid, |pp| {
            if p.ppid() != ppid {
                return Push::Retry; // rodzic właśnie oddał nas dalej
            }
            let mut z = pp.zombies.lock();
            if pp.exiting.load(Ordering::SeqCst) {
                return Push::Refused;
            }
            let _ = pp.live_children.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1));
            z.push(Zombie { pid: me, status });
            pp.child_gen.fetch_add(1, Ordering::SeqCst);
            Push::Done
        });
        match r {
            Some(Push::Retry) => continue,
            Some(Push::Done) => {
                child_q(ppid).wake_all();
                break;
            }
            _ => break,
        }
    }
}

/// Czy rodzic odbierze status `pid` przez wait (proces z rodzicem-procesem).
pub fn has_process_parent(p: &super::Process) -> bool {
    accepts_children(p.ppid())
}

/// wait(pid, flags): Ok((pid, status)), Ok((0, 0)) przy WNOHANG bez wyniku.
pub fn wait(me: TaskId, pid: TaskId, flags: u64) -> Result<(TaskId, u64), i64> {
    use super::syscalls::{ECHILD, EINTR};
    let Some(p) = sched::current_process() else { return Err(ECHILD) };
    let p: &super::Process = p;
    loop {
        let seen = p.child_gen.load(Ordering::SeqCst);
        let any_live = {
            let mut z = p.zombies.lock();
            if let Some(z) = z.take_first(|z| pid == WAIT_ANY || z.pid == pid) {
                return Ok((z.pid, z.status));
            }
            p.live_children.load(Ordering::SeqCst) > 0
        };
        let waiting = if pid == WAIT_ANY {
            any_live
        } else {
            sched::with_process(pid, |c| c.ppid() == me).unwrap_or(false)
        };
        if !waiting {
            // Dziecko mogło dopisać zombie i zniknąć między sprawdzeniami.
            if p.child_gen.load(Ordering::SeqCst) != seen {
                continue;
            }
            return Err(ECHILD);
        }
        if flags & WNOHANG != 0 {
            return Ok((0, 0));
        }
        child_q(me).wait_until(|| p.child_gen.load(Ordering::SeqCst) != seen || sched::should_exit(), None);
        if sched::should_exit() {
            return Err(EINTR);
        }
    }
}

/// Zombie czekające na rodzica (ps, testy): (pid, rodzic, status).
#[allow(dead_code)]
pub fn zombies() -> Vec<(TaskId, TaskId, u64)> {
    let mut out = Vec::new();
    sched::for_each_process(|ppid, p| {
        for z in p.zombies.lock().iter() {
            out.push((z.pid, ppid, z.status));
        }
    });
    out
}
