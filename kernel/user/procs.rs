// M16: rodzina procesów – rodzic/dziecko, zombie, wait, init.
//
// * Każdy proces ma rodzica (Process.ppid).  0 = kernel (nadzorca init,
//   shell kernela, samotesty) – takie procesy kernel sprząta sam, jak do tej
//   pory (sched::task_info / user::exit_info).
// * Proces z rodzicem-procesem po zakończeniu zostaje zombie: zadanie
//   znika, ale kod wyjścia czeka w tablicy ZOMBIES, aż rodzic go odbierze
//   (`wait`).
// * Kończący się proces oddaje swoje dzieci (żywe i zombie) do init.  Gdy
//   init jeszcze nie działa (samotesty, shell kernela) – do kernela: żywe
//   dzieci działają dalej, zombie znikają.
// * Wszystkie zmiany rodzica i tablicy zombie – pod blokadą ZOMBIES, więc
//   dziecko kończące się w tym samym czasie co rodzic nie zgubi wpisu.
//
// Status (wait): kod wyjścia 0..255 albo STATUS_SIGNALED | powód
// (9 = kill/Ctrl+C, numer wyjątku CPU, 0xFF = zły adres powrotu).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::ExitKind;
use crate::sched::sync::{Mutex, WaitQueue};
use crate::sched::{self, TaskId};

pub const STATUS_SIGNALED: u64 = 0x100;
pub const REASON_KILLED: u64 = 9;
pub const REASON_BAD_RETURN: u64 = 0xFF;

/// wait(pid = ANY): dowolne dziecko.
pub const WAIT_ANY: u64 = u64::MAX;
/// Flaga wait: nie czekaj (0, gdy żadne dziecko się jeszcze nie skończyło).
pub const WNOHANG: u64 = 1;

struct Zombie {
    pid: TaskId,
    ppid: TaskId,
    status: u64,
}

static ZOMBIES: Mutex<Vec<Zombie>> = Mutex::new_named("process table (zombies)", Vec::new());
/// M17a.g11: rodzic czeka w kolejce wybranej po swoim numerze – koniec
/// procesu budzi tylko jego rodzica (i ewentualnie init), a nie wszystkich
/// czekających w `wait` (wcześniej: jedna kolejka, stado przy każdym końcu).
#[repr(align(8))] // osobne adresy = osobne kubełki kanałów schedulera
struct ChildQ(WaitQueue);
const CHILD_QUEUES: usize = 64;
static CHILD_EXIT: [ChildQ; CHILD_QUEUES] = [const { ChildQ(WaitQueue::new()) }; CHILD_QUEUES];

fn child_q(parent: TaskId) -> &'static WaitQueue {
    &CHILD_EXIT[(parent as usize) % CHILD_QUEUES].0
}
/// Rośnie przy każdym nowym zombie (warunek czekania bez blokady).
static GENERATION: AtomicU64 = AtomicU64::new(0);
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
    let mut zombies = ZOMBIES.lock();
    p.exiting.store(true, Ordering::SeqCst);
    let mut wake_heir = 0;

    // 1. Dzieci -> init (albo kernel, gdy init nie działa lub to sam init).
    // M17a.g11: tylko gdy są jakieś dzieci – przegląd listy zadań i
    // sprawdzenie init biorą blokadę schedulera, a trzymamy ZOMBIES.
    let live_children = p.has_children.load(Ordering::SeqCst);
    if live_children || zombies.iter().any(|z| z.ppid == me) {
        let heir = match init_pid() {
            init if init != me && accepts_children(init) => init,
            _ => 0,
        };
        if live_children {
            let n = sched::reparent(me, heir);
            if n > 0 && heir != 0 {
                sched::with_process(heir, |h| h.live_children.fetch_add(n as u32, Ordering::SeqCst));
            }
        }
        if heir == 0 {
            zombies.retain(|z| z.ppid != me);
        } else {
            let mut handed = false;
            for z in zombies.iter_mut().filter(|z| z.ppid == me) {
                z.ppid = heir;
                handed = true;
            }
            if handed {
                GENERATION.fetch_add(1, Ordering::SeqCst);
                wake_heir = heir;
            }
        }
    }

    // 2. Własny status -> rodzic (jeśli to proces, który jeszcze żyje).
    let ppid = p.ppid();
    let mut wake_parent = 0;
    // M17a.g15: rodzic przyjmuje status (nie kończy się) – i ma o jedno żywe
    // dziecko mniej (w tej samej sekcji co wpis zombie: wait widzi jedno albo
    // drugie).
    let accepted = ppid != 0
        && sched::with_process(ppid, |pp| {
            if pp.exiting.load(Ordering::SeqCst) {
                return false;
            }
            let _ = pp.live_children.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1));
            true
        })
        .unwrap_or(false);
    if accepted {
        zombies.push(Zombie { pid: me, ppid, status: status_of(kind) });
        GENERATION.fetch_add(1, Ordering::SeqCst);
        wake_parent = ppid;
    }
    drop(zombies);
    if wake_parent != 0 {
        child_q(wake_parent).wake_all();
    }
    if wake_heir != 0 && child_q(wake_heir) as *const _ != child_q(wake_parent) as *const _ {
        child_q(wake_heir).wake_all();
    }
}

/// Czy rodzic odbierze status `pid` przez wait (proces z rodzicem-procesem).
pub fn has_process_parent(p: &super::Process) -> bool {
    accepts_children(p.ppid())
}

/// wait(pid, flags): Ok((pid, status)), Ok((0, 0)) przy WNOHANG bez wyniku.
pub fn wait(me: TaskId, pid: TaskId, flags: u64) -> Result<(TaskId, u64), i64> {
    use super::syscalls::{ECHILD, EINTR};
    loop {
        let seen = GENERATION.load(Ordering::SeqCst);
        // M17a.g15: zombie i żywe dzieci sprawdzane pod tą samą blokadą co
        // koniec dziecka (zmniejszenie licznika + wpis zombie) – bez
        // przeglądania listy zadań (wcześniej children_of: 946 tys. przeglądów
        // pod blokadą schedulera na Legionie).
        let waiting_for_any = {
            let mut zombies = ZOMBIES.lock();
            if let Some(i) = zombies.iter().position(|z| z.ppid == me && (pid == WAIT_ANY || z.pid == pid)) {
                let z = zombies.remove(i);
                return Ok((z.pid, z.status));
            }
            if pid == WAIT_ANY {
                sched::with_process(me, |p| p.live_children.load(Ordering::SeqCst) > 0).unwrap_or(false)
            } else {
                sched::with_process(pid, |c| c.ppid() == me).unwrap_or(false)
            }
        };
        if !waiting_for_any {
            return Err(ECHILD);
        }
        if flags & WNOHANG != 0 {
            return Ok((0, 0));
        }
        child_q(me).wait_until(|| GENERATION.load(Ordering::SeqCst) != seen || sched::should_exit(), None);
        if sched::should_exit() {
            return Err(EINTR);
        }
    }
}

/// Zombie czekające na rodzica (ps, testy).
#[allow(dead_code)]
pub fn zombies() -> Vec<(TaskId, TaskId, u64)> {
    ZOMBIES.lock().iter().map(|z| (z.pid, z.ppid, z.status)).collect()
}
