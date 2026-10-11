// M12: samotesty schedulera (tylko build z --cfg selftest).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::sync::{KMutex, Mutex, WaitQueue};
use super::*;
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[SCHED TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

/// Czeka (śpiąc po 1 ms), aż `cond` będzie prawdą; false po `ms`.
fn wait_for(ms: u64, cond: impl Fn() -> bool) -> bool {
    let end = ticks() + ms;
    while !cond() {
        if ticks() > end {
            return false;
        }
        crate::time::sleep_ms(1);
    }
    true
}

fn alive(id: TaskId) -> bool {
    task_info(id).is_some()
}

static FLAG: AtomicBool = AtomicBool::new(false);
static COUNTER: AtomicU64 = AtomicU64::new(0);
static SPIN: AtomicU64 = AtomicU64::new(0);
static STOP: AtomicBool = AtomicBool::new(false);
static DONE: AtomicU64 = AtomicU64::new(0);
static SLEPT: AtomicU64 = AtomicU64::new(0);
static TEST_WQ: WaitQueue = WaitQueue::new();
static TEST_LOCK: KMutex = KMutex::new();
static SHARED: Mutex<u64> = Mutex::new(0);

fn set_flag(_: usize) {
    FLAG.store(true, Ordering::SeqCst);
}

fn yielder(_: usize) {
    for _ in 0..50 {
        COUNTER.fetch_add(1, Ordering::SeqCst);
        yield_now();
    }
    DONE.fetch_add(1, Ordering::SeqCst);
}

fn spinner(_: usize) {
    // Nigdy nie oddaje CPU sam – działa tylko dzięki wywłaszczaniu.
    while !STOP.load(Ordering::SeqCst) {
        SPIN.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
}

fn sleeper(ms: usize) {
    let t0 = ticks();
    crate::time::sleep_ms(ms as u64);
    SLEPT.store(ticks() - t0, Ordering::SeqCst);
}

fn waiter(_: usize) {
    TEST_WQ.wait_until(|| FLAG.load(Ordering::SeqCst), None);
    DONE.fetch_add(1, Ordering::SeqCst);
}

fn locker(_: usize) {
    for _ in 0..200 {
        let _g = TEST_LOCK.lock();
        let mut v = SHARED.lock();
        let old = *v;
        yield_now(); // wywłaszczenie w środku sekcji krytycznej
        *v = old + 1;
    }
    DONE.fetch_add(1, Ordering::SeqCst);
}

pub fn self_test() {
    serial_println!("[SCHED TEST] Starting scheduler tests...");
    crate::selftest::begin();

    // 1. Start: zadanie 1 (kernel) działa, idle istnieje.
    let list = tasks();
    check!(current_id() == BOOT_ID, "current = {}", current_id());
    check!(list.iter().any(|t| t.id == BOOT_ID && t.state == State::Running), "kernel task not running");
    check!(list.iter().any(|t| t.id == IDLE_ID), "no idle task");
    serial_println!("[SCHED TEST] 1/8 kernel + idle tasks PASS");

    // 2. spawn -> zadanie działa i kończy się; stos wraca do alokatora.
    reap();
    let frames = crate::sched::stack::free_frames_flushed();
    FLAG.store(false, Ordering::SeqCst);
    let id = match spawn("t-flag", set_flag, 0) {
        Ok(id) => id,
        Err(e) => {
            serial_println!("[SCHED TEST] FAIL: spawn: {}", e);
            return;
        }
    };
    check!(wait_for(100, || FLAG.load(Ordering::SeqCst)), "spawned task did not run");
    check!(wait_for(100, || !alive(id)), "task did not exit");
    // Sprząta też idle – może być w trakcie zwalniania stosu, więc czekamy.
    check!(
        wait_for(100, || {
            reap();
            crate::sched::stack::free_frames_flushed() == frames
        }),
        "stack frames not returned ({} -> {})",
        frames,
        crate::sched::stack::free_frames_flushed()
    );
    serial_println!("[SCHED TEST] 2/8 spawn + exit + stack freed PASS");

    // 3. yield: dwa zadania na zmianę (100 przełączeń).
    COUNTER.store(0, Ordering::SeqCst);
    DONE.store(0, Ordering::SeqCst);
    let sw0 = total_switches();
    let (a, b) = (spawn("t-yield-a", yielder, 0), spawn("t-yield-b", yielder, 0));
    check!(a.is_ok() && b.is_ok(), "spawn yielders");
    check!(wait_for(500, || DONE.load(Ordering::SeqCst) == 2), "yielders did not finish");
    check!(COUNTER.load(Ordering::SeqCst) == 100, "counter {}", COUNTER.load(Ordering::SeqCst));
    check!(total_switches() - sw0 >= 100, "only {} switches", total_switches() - sw0);
    serial_println!("[SCHED TEST] 3/8 yield ping-pong ({} switches) PASS", total_switches() - sw0);

    // 4. Wywłaszczanie: zadanie bez yield + zadanie 1 też w pętli bez hlt.
    SPIN.store(0, Ordering::SeqCst);
    STOP.store(false, Ordering::SeqCst);
    let sid = spawn("t-spin", spinner, 0);
    check!(sid.is_ok(), "spawn spinner");
    let sid = sid.unwrap();
    let t0 = ticks();
    let mut mine: u64 = 0;
    while ticks() < t0 + 60 {
        mine += 1;
        core::hint::spin_loop();
    }
    let spun = SPIN.load(Ordering::SeqCst);
    STOP.store(true, Ordering::SeqCst);
    check!(spun > 0, "spinner never ran - no preemption");
    check!(mine > 0, "kernel task starved");
    let cpu = task_info(sid).map(|t| t.cpu_ticks).unwrap_or(0);
    check!(cpu >= 10, "spinner got only {} ticks of CPU", cpu);
    check!(wait_for(100, || !alive(sid)), "spinner did not stop");
    serial_println!("[SCHED TEST] 4/8 preemption (busy task got {} ms of 60) PASS", cpu);

    // 5. sleep: zadanie śpi 30 ms (nie zajmuje CPU).
    SLEPT.store(0, Ordering::SeqCst);
    let zid = spawn("t-sleep", sleeper, 30).unwrap_or(0);
    check!(zid != 0, "spawn sleeper");
    check!(wait_for(20, || task_info(zid).map(|t| t.state) == Some(State::Blocked)), "sleeper not blocked");
    check!(wait_for(200, || SLEPT.load(Ordering::SeqCst) != 0), "sleeper did not wake");
    let slept = SLEPT.load(Ordering::SeqCst);
    check!((30..=40).contains(&slept), "slept {} ms (want 30..40)", slept);
    check!(task_info(zid).map(|t| t.cpu_ticks).unwrap_or(0) <= 2, "sleeper used CPU");
    serial_println!("[SCHED TEST] 5/8 sleep 30 ms -> {} ms, blocked meanwhile PASS", slept);

    // 6. WaitQueue: pobudka przez wake_all i limit czasu.
    FLAG.store(false, Ordering::SeqCst);
    DONE.store(0, Ordering::SeqCst);
    let wid = spawn("t-wait", waiter, 0).unwrap_or(0);
    check!(wait_for(20, || task_info(wid).map(|t| t.state) == Some(State::Blocked)), "waiter not blocked");
    crate::time::sleep_ms(5);
    check!(DONE.load(Ordering::SeqCst) == 0, "waiter woke up without a reason");
    FLAG.store(true, Ordering::SeqCst);
    TEST_WQ.wake_all();
    check!(wait_for(20, || DONE.load(Ordering::SeqCst) == 1), "waiter not woken");
    let t0 = ticks();
    let r = TEST_WQ.wait_until(|| false, Some(20));
    let waited = ticks() - t0;
    check!(!r && (20..=25).contains(&waited), "timeout: result {} after {} ms", r, waited);
    serial_println!("[SCHED TEST] 6/8 wait queue: wake_all + 20 ms timeout ({} ms) PASS", waited);

    // 7. Mutex: 3 zadania x 200 inkrementacji z yield w sekcji krytycznej.
    *SHARED.lock() = 0;
    DONE.store(0, Ordering::SeqCst);
    for _ in 0..3 {
        check!(spawn("t-lock", locker, 0).is_ok(), "spawn locker");
    }
    check!(wait_for(2000, || DONE.load(Ordering::SeqCst) == 3), "lockers did not finish");
    let total = *SHARED.lock();
    check!(total == 600, "lost updates: {} (want 600)", total);
    check!(TEST_LOCK.contended() > 0, "mutex never contended");
    {
        let _a = TEST_LOCK.lock();
        let _b = TEST_LOCK.lock(); // reentrant
        check!(TEST_LOCK.is_locked(), "not locked");
    }
    check!(!TEST_LOCK.is_locked(), "not released");
    serial_println!(
        "[SCHED TEST] 7/8 mutex: 600/600 updates, {} waits, reentrant PASS",
        TEST_LOCK.contended()
    );

    // 8. Stos zadania: strona-strażnik pod stosem, sprzątanie wszystkiego.
    let gid = spawn("t-guard", set_flag, 0).unwrap_or(0);
    let top = task_info(gid).map(|t| t.stack_top).unwrap_or(0);
    check!(top != 0, "no stack info");
    let bottom = top - stack::STACK_SIZE;
    check!(crate::memory::translate(bottom).is_some(), "stack bottom not mapped");
    check!(crate::memory::translate(bottom - 4096).is_none(), "guard page mapped");
    check!(crate::memory::is_stack_guard(bottom - 8), "is_stack_guard");
    check!(!crate::memory::is_stack_guard(bottom + 8), "stack counted as guard");
    check!(wait_for(100, || !alive(gid)), "guard task did not exit");
    reap();
    check!(
        tasks().len() == 2,
        "{} tasks left (want kernel + idle)",
        tasks().len()
    );
    check!(
        wait_for(100, || {
            reap();
            crate::sched::stack::free_frames_flushed() == frames
        }),
        "frames leaked by tests ({} -> {})",
        frames,
        crate::sched::stack::free_frames_flushed()
    );
    serial_println!("[SCHED TEST] 8/8 task stack guard page + cleanup PASS");

    serial_println!("[SCHED TEST] =================================");
    crate::selftest::pass();
    serial_println!("[SCHED TEST] SCHEDULER TESTS PASSED");
    serial_println!("[SCHED TEST] =================================");
}
