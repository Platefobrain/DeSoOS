// M17a krok d: syscalle bez Big Kernel Lock – samotesty (tylko build z
// --cfg selftest).

use alloc::string::String;
use alloc::vec::Vec;

use super::*;
use crate::arch::x86_64::smp;
use crate::sched::bkl;
use crate::serial_println;
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[NOBKL TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

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

fn start(name: &str) -> Option<TaskId> {
    let opts = SpawnOptions { capture: true, ..SpawnOptions::default() };
    spawn_with(name, programs::code(name)?, &opts).ok()
}

// M17a.f1: ping-pong przez WaitQueue (zgubiona pobudka = zawieszenie) i
// burza przełączeń (yield) na wielu CPU.
static TURN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static PONGS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static PP_WQ: crate::sched::sync::WaitQueue = crate::sched::sync::WaitQueue::new();
static YIELDS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static YIELD_STOP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
const ROUNDS: u64 = 1000;

fn pong(_: usize) {
    use core::sync::atomic::Ordering::SeqCst;
    for _ in 0..ROUNDS {
        PP_WQ.wait_until(|| TURN.load(SeqCst) == 1, Some(30_000));
        if TURN.load(SeqCst) != 1 {
            return; // zawieszenie – test to zgłosi
        }
        TURN.store(0, SeqCst);
        PONGS.fetch_add(1, SeqCst);
        PP_WQ.wake_all();
    }
}

fn yielder(_: usize) {
    use core::sync::atomic::Ordering::Relaxed;
    // Bez BKL (yield bierze go tylko na chwilę) – zadanie kernela trzymające
    // BKL w ciasnej pętli zagłodziłoby resztę (przy 8 CPU test stał).
    crate::sched::bkl::unlocked(|| {
        while !YIELD_STOP.load(Relaxed) {
            crate::sched::yield_now();
            YIELDS.fetch_add(1, Relaxed);
            // Chwila pracy między przełączeniami – bez tego 4 zadania walczą
            // tylko o BKL (w QEMU z 8 CPU na 2 rdzeniach: minuty).
            for _ in 0..2_000 {
                core::hint::spin_loop();
            }
        }
    });
}

// M17a.f2: burza pobudek bez BKL – kilka zadań czeka na kolejne "pokolenia"
// licznika, zadanie budzące (też bez BKL) podbija go i budzi wszystkich.
// Zgubiona pobudka przy ostatnim pokoleniu = zadanie wisi do timeoutu.
static GEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static STORM_WQ: crate::sched::sync::WaitQueue = crate::sched::sync::WaitQueue::new();
static STORM_WAKES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static STORM_TIMEOUTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static STORM_DONE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static STORM_BKL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
const STORM_ROUNDS: u64 = 3000;

fn storm_waiter(_: usize) {
    use core::sync::atomic::Ordering::SeqCst;
    crate::sched::bkl::unlocked(|| {
        let mut seen = 0;
        while seen < STORM_ROUNDS {
            let ok = STORM_WQ.wait_until(|| GEN.load(SeqCst) > seen, Some(30_000));
            if !ok {
                STORM_TIMEOUTS.fetch_add(1, SeqCst);
                break;
            }
            if crate::sched::bkl::held() {
                STORM_BKL.fetch_add(1, SeqCst);
            }
            seen = GEN.load(SeqCst);
            STORM_WAKES.fetch_add(1, SeqCst);
        }
    });
    STORM_DONE.fetch_add(1, SeqCst);
}

fn storm_waker(_: usize) {
    use core::sync::atomic::Ordering::SeqCst;
    crate::sched::bkl::unlocked(|| {
        for r in 1..=STORM_ROUNDS {
            GEN.store(r, SeqCst);
            STORM_WQ.wake_all();
            for _ in 0..500 {
                core::hint::spin_loop();
            }
            if r % 64 == 0 {
                crate::sched::yield_now();
            }
        }
    });
    STORM_DONE.fetch_add(1, SeqCst);
}

const LINE: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN\n";

pub fn self_test() {
    serial_println!("[NOBKL TEST] Starting syscalls without the Big Kernel Lock...");
    crate::selftest::begin();
    let n = smp::online_count();
    let k = n.clamp(2, 4);

    // 1. getpid bez BKL: k procesów x 100 000 getpid (program "regs" przy
    //    okazji sprawdza, że rejestry przeżywają syscall).  BKL bierze się
    //    tylko przy starcie / końcu procesów i w przerwaniach – nie na
    //    każdy syscall.
    let (fast0, _) = syscalls::syscall_stats();
    let (bkl0, _, _) = bkl::stats();
    let t0 = ticks();
    let mut ids = Vec::new();
    for _ in 0..k {
        let id = start("regs");
        check!(id.is_some(), "spawn regs");
        ids.push(id.unwrap());
    }
    check!(wait_for(60_000, || ids.iter().all(|&i| sched::task_info(i).is_none())), "regs did not end");
    let wall = ticks() - t0;
    for &id in &ids {
        let e = exit_info(id).map(|e| e.kind);
        check!(e == Some(ExitKind::Exit(0)), "regs {}: {:?} (registers changed?)", id, e);
    }
    let (fast1, _) = syscalls::syscall_stats();
    let (bkl1, _, _) = bkl::stats();
    let getpids = fast1[0] - fast0[0];
    let taken = bkl1 - bkl0;
    let want = k as u64 * 100_000;
    check!(getpids >= want, "only {} getpid without BKL (want {})", getpids, want);
    check!(taken < want / 4, "BKL taken {} times for {} getpid - fast path not used?", taken, want);
    serial_println!(
        "[NOBKL TEST] 1/10 {} x 100000 getpid without BKL in {} ms, BKL taken only {} times meanwhile PASS",
        k,
        wall,
        taken
    );

    // 2. write bez BKL: k procesów po 2000 linii naraz do przechwyconego
    //    stdout – każda linia cała (write jest niepodzielny), nic nie ginie.
    let (fast0, _) = syscalls::syscall_stats();
    let mut ids = Vec::new();
    for _ in 0..k {
        let id = start("lines");
        check!(id.is_some(), "spawn lines");
        ids.push(id.unwrap());
    }
    check!(wait_for(60_000, || ids.iter().all(|&i| sched::task_info(i).is_none())), "lines did not end");
    for &id in &ids {
        let e = exit_info(id).map(|e| e.kind);
        check!(e == Some(ExitKind::Exit(0)), "lines {}: {:?}", id, e);
        let out = captured_output(id).unwrap_or_default();
        check!(out.len() == 2000 * LINE.len(), "lines {}: {} bytes (want {})", id, out.len(), 2000 * LINE.len());
        check!(out.chunks(LINE.len()).all(|c| c == LINE), "lines {}: a line is broken", id);
    }
    let (fast1, _) = syscalls::syscall_stats();
    let writes = fast1[2] - fast0[2];
    check!(writes >= k as u64 * 2000, "only {} writes without BKL", writes);
    serial_println!("[NOBKL TEST] 2/10 {} x 2000 lines written at once without BKL, every line intact PASS", k);

    // 3. kill procesu, który robi tylko syscalle bez BKL (Ctrl+C musi
    //    działać także wtedy).
    let id = start("pidloop");
    check!(id.is_some(), "spawn pidloop");
    let id = id.unwrap();
    let (f0, _) = syscalls::syscall_stats();
    check!(wait_for(5_000, || syscalls::syscall_stats().0[0] > f0[0] + 1000), "pidloop does not run");
    check!(sched::request_exit(id), "request_exit");
    check!(wait_for(5_000, || sched::task_info(id).is_none()), "pidloop not killed");
    let e = exit_info(id).map(|e| e.kind);
    check!(e == Some(ExitKind::Killed), "pidloop ended with {:?}", e);
    serial_println!("[NOBKL TEST] 3/10 kill of a process doing only BKL-free syscalls PASS");

    // 4. Pliki bez BKL (M17a.e): k shelli naraz dopisuje po 40 linii do
    //    własnych plików (echo >> – open/write/close w shellu, bez nowych
    //    procesów), VFS i ramfs pod FS_LOCK, nie pod BKL.
    let (f0, _) = syscalls::syscall_stats();
    let mut shells = Vec::new();
    for i in 0..k {
        let mut script = alloc::format!("echo start{i} > /nobkl{i}.txt\n");
        for j in 0..40 {
            script.push_str(&alloc::format!("echo line{i}-{j} >> /nobkl{i}.txt\n"));
        }
        script.push_str("pwd\nexit 0\n");
        let opts = SpawnOptions { stdin: Some(script.into_bytes()), capture: true, ..SpawnOptions::default() };
        let id = exec("/bin/sh", &["sh"], "/", &opts);
        check!(id.is_ok(), "start sh {}", i);
        shells.push((i, id.unwrap()));
    }
    check!(wait_for(60_000, || shells.iter().all(|&(_, id)| sched::task_info(id).is_none())), "shells did not end");
    for &(i, id) in &shells {
        let e = exit_info(id).map(|e| e.kind);
        check!(e == Some(ExitKind::Exit(0)), "sh {}: {:?}", i, e);
        let path = alloc::format!("/nobkl{}.txt", i);
        let data = crate::fs::read_file(&path);
        check!(data.is_ok(), "{}: {:?}", path, data.err());
        let text = String::from_utf8_lossy(&data.unwrap()).into_owned();
        let mut want = alloc::format!("start{}\n", i);
        for j in 0..40 {
            want.push_str(&alloc::format!("line{}-{}\n", i, j));
        }
        check!(text == want, "{}: content differs ({} bytes, want {})", path, text.len(), want.len());
        check!(crate::fs::remove(&path).is_ok(), "remove {}", path);
    }
    let (f1, _) = syscalls::syscall_stats();
    let files = f1[3] - f0[3];
    check!(files >= k as u64 * 41 * 2, "only {} file syscalls without BKL", files);
    serial_println!(
        "[NOBKL TEST] 4/10 {} shells x 41 appends to own files at once, {} file syscalls without BKL, contents exact PASS",
        k,
        files
    );

    // 5. Procesy bez BKL (M17a.e2): k shelli naraz uruchamia po 15 programów
    //    (spawn + wait – tablica zombie pod własną blokadą, lista zadań tylko
    //    na chwilę pod BKL); każdy program wypisuje swój pid.
    let (f0, _) = syscalls::syscall_stats();
    let mut shells = Vec::new();
    for i in 0..k {
        let mut script = String::new();
        for _ in 0..15 {
            script.push_str("hello\n");
        }
        script.push_str("exit 0\n");
        let opts = SpawnOptions { stdin: Some(script.into_bytes()), capture: true, ..SpawnOptions::default() };
        let id = exec("/bin/sh", &["sh"], "/", &opts);
        check!(id.is_ok(), "start sh {}", i);
        shells.push((i, id.unwrap()));
    }
    check!(wait_for(60_000, || shells.iter().all(|&(_, id)| sched::task_info(id).is_none())), "shells did not end");
    for &(i, id) in &shells {
        let e = exit_info(id).map(|e| e.kind);
        check!(e == Some(ExitKind::Exit(0)), "sh {}: {:?}", i, e);
        let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
        let n = out.matches("Hello from an ELF program!").count();
        check!(n == 15, "sh {}: {} programs printed (want 15):\n{}", i, n, out);
    }
    check!(super::procs::zombies().is_empty(), "zombies left: {:?}", super::procs::zombies());
    let (f1, _) = syscalls::syscall_stats();
    let procs = f1[4] - f0[4];
    check!(procs >= k as u64 * 15 * 2, "only {} process syscalls without BKL", procs);
    serial_println!(
        "[NOBKL TEST] 5/10 {} shells x 15 programs at once (spawn/wait without BKL: {}), no zombies left PASS",
        k,
        procs
    );

    // 6. Blokada schedulera (M17a.f1): ping-pong dwóch zadań przez WaitQueue
    //    (2000 pobudek w obie strony – zgubiona = zawieszenie), w tym czasie
    //    k zadań robi yield w kółko (przełączenia na wielu CPU).  Potem
    //    blokada wolna, głębokość 0.
    {
        use core::sync::atomic::Ordering::SeqCst;
        let (a0, _, _) = crate::sched::sched_lock_stats();
        TURN.store(0, SeqCst);
        PONGS.store(0, SeqCst);
        YIELDS.store(0, SeqCst);
        YIELD_STOP.store(false, SeqCst);
        let mut yid = Vec::new();
        for _ in 0..k {
            let id = sched::spawn("t-yield", yielder, 0);
            check!(id.is_ok(), "spawn yielder");
            yid.push(id.unwrap());
        }
        check!(sched::spawn("t-pong", pong, 0).is_ok(), "spawn pong");
        let t0 = ticks();
        let mut ok = true;
        for _ in 0..ROUNDS {
            TURN.store(1, SeqCst);
            PP_WQ.wake_all();
            if !PP_WQ.wait_until(|| TURN.load(SeqCst) == 0, Some(30_000)) {
                ok = false;
                break;
            }
        }
        let wall = ticks() - t0;
        YIELD_STOP.store(true, SeqCst);
        let gone = wait_for(5_000, || yid.iter().all(|&i| sched::task_info(i).is_none()));
        check!(ok, "ping-pong stuck after {} rounds (lost wake-up?)", PONGS.load(SeqCst));
        check!(gone, "yielders did not stop");
        check!(PONGS.load(SeqCst) == ROUNDS, "{} pongs (want {})", PONGS.load(SeqCst), ROUNDS);
        let (owner, depth) = crate::sched::sched_lock_state();
        check!(depth == 0, "scheduler lock depth {} on this CPU after the test", depth);
        check!(owner == 0 || owner != crate::arch::x86_64::cpu::id() as u32 + 1, "scheduler lock still held by this CPU");
        let (a1, _, _) = crate::sched::sched_lock_stats();
        serial_println!(
            "[NOBKL TEST] 6/10 scheduler lock: {} ping-pong wake-ups in {} ms + {} yields on {} tasks, lock free afterwards ({} takes) PASS",
            2 * ROUNDS,
            wall,
            YIELDS.load(SeqCst),
            k,
            a1 - a0
        );
    }

    // 7. Burza pobudek bez BKL (M17a.f2): k zadań czeka na WaitQueue, zadanie
    //    bez BKL budzi je 3000 razy; w tym czasie k procesów "sleeper" robi
    //    sleep(100) – syscall bez BKL.  Nikt nie wisi, nikt nie wraca z BKL.
    {
        use core::sync::atomic::Ordering::SeqCst;
        GEN.store(0, SeqCst);
        STORM_WAKES.store(0, SeqCst);
        STORM_TIMEOUTS.store(0, SeqCst);
        STORM_DONE.store(0, SeqCst);
        STORM_BKL.store(0, SeqCst);
        let (f0, _) = syscalls::syscall_stats();
        let mut sleepers = Vec::new();
        for _ in 0..k {
            let id = start("sleeper");
            check!(id.is_some(), "spawn sleeper");
            sleepers.push(id.unwrap());
        }
        for _ in 0..k {
            check!(sched::spawn("t-storm", storm_waiter, 0).is_ok(), "spawn storm waiter");
        }
        let t0 = ticks();
        check!(sched::spawn("t-storm-wake", storm_waker, 0).is_ok(), "spawn storm waker");
        let done = wait_for(60_000, || STORM_DONE.load(SeqCst) == k as u64 + 1);
        let wall = ticks() - t0;
        check!(done, "wake-up storm stuck: {} / {} tasks done, generation {}", STORM_DONE.load(SeqCst), k + 1, GEN.load(SeqCst));
        check!(STORM_TIMEOUTS.load(SeqCst) == 0, "{} waiter(s) timed out (lost wake-up)", STORM_TIMEOUTS.load(SeqCst));
        check!(STORM_BKL.load(SeqCst) == 0, "a BKL-free waiter came back holding the BKL");
        check!(wait_for(30_000, || sleepers.iter().all(|&i| sched::task_info(i).is_none())), "sleepers did not end");
        let mut worst = 0;
        for &id in &sleepers {
            let e = exit_info(id).map(|e| e.kind);
            let ms = match e {
                Some(ExitKind::Exit(ms)) => ms,
                _ => -1,
            };
            check!(ms >= 100, "sleeper {}: {:?} (sleep(100) shorter?)", id, e);
            worst = worst.max(ms);
        }
        let (f1, _) = syscalls::syscall_stats();
        let sleeps = f1[5] - f0[5];
        check!(sleeps >= k as u64, "only {} sleep/yield syscalls without BKL", sleeps);
        serial_println!(
            "[NOBKL TEST] 7/10 wake-up storm: {} tasks x {} generations ({} wake-ups) in {} ms, none lost; {} x sleep(100) without BKL (longest {} ms) PASS",
            k,
            STORM_ROUNDS,
            STORM_WAKES.load(SeqCst),
            wall,
            k,
            worst
        );
    }

    // 8. kill w trakcie uśpienia (M17a.f2): k procesów "ticker" śpi po 1 s
    //    (sleep bez BKL); kill budzi je od razu – kończą się po chwili, nie
    //    po końcu snu.
    {
        let mut tickers = Vec::new();
        for _ in 0..k {
            let id = start("ticker");
            check!(id.is_some(), "spawn ticker");
            tickers.push(id.unwrap());
        }
        // Wszystkie śpią (po pierwszym "tick" – sleep 1 s).
        let asleep = wait_for(10_000, || {
            tickers.iter().all(|&i| sched::task_info(i).is_some_and(|t| t.state == crate::sched::State::Blocked && t.switches > 0))
        });
        check!(asleep, "tickers did not go to sleep");
        let t0 = ticks();
        for &id in &tickers {
            check!(sched::request_exit(id), "request_exit ticker {}", id);
        }
        check!(wait_for(5_000, || tickers.iter().all(|&i| sched::task_info(i).is_none())), "tickers not killed");
        let wall = ticks() - t0;
        for &id in &tickers {
            let e = exit_info(id).map(|e| e.kind);
            check!(e == Some(ExitKind::Killed), "ticker {} ended with {:?}", id, e);
        }
        check!(wall < 700, "kill took {} ms - sleeping process not woken?", wall);
        serial_println!("[NOBKL TEST] 8/10 kill of {} processes sleeping without BKL: gone after {} ms PASS", k, wall);
    }

    // 9. Statystyka BKL per miejsce (M17a.g): każde wzięcie przypisane
    //    miejscu, syscall pod BKL i pobudka po przełączeniu widoczne, czas
    //    trzymania mierzony.
    {
        let sum = |name: &str| {
            bkl::site_stats().iter().filter(|e| e.line == 0 && e.file == name).map(|e| (e.taken, e.held_us)).next().unwrap_or((0, 0))
        };
        let (sys0, _) = sum(bkl::tag::SYSCALL);
        let id = start("badsys"); // nieznany syscall -> ścieżka pod BKL
        check!(id.is_some(), "spawn badsys");
        let id = id.unwrap();
        check!(wait_for(10_000, || sched::task_info(id).is_none()), "badsys did not end");
        let (sys1, _) = sum(bkl::tag::SYSCALL);
        check!(sys1 > sys0, "syscall under BKL not counted ({} -> {})", sys0, sys1);
        let (acq0, _, _) = bkl::stats();
        let sites = bkl::site_stats();
        let tracked: u64 = sites.iter().map(|e| e.taken).sum::<u64>() + bkl::site_overflow();
        let (acq, _, _) = bkl::stats();
        // Wzięcia trwające właśnie na innych CPU mogą jeszcze nie być w tablicy.
        check!(tracked + 64 >= acq0 && tracked <= acq, "sites count {} takes, BKL {}..{}", tracked, acq0, acq);
        let held: u64 = sites.iter().map(|e| e.held_us).sum();
        check!(held > 0 || crate::arch::x86_64::lapic::tsc_per_ms() == 0, "no hold time measured");
        let mut report = String::new();
        crate::shell::cpus_report(&mut report);
        for l in report.lines().skip_while(|l| !l.starts_with("idle:")).take_while(|l| !l.starts_with("spinlocks")) {
            serial_println!("[NOBKL TEST]   {}", l);
        }
        let top = &sites[0];
        serial_println!(
            "[NOBKL TEST] 9/10 BKL by site: {} sites, {} of {} takes tracked, top: {}{} ({} taken, held {} ms) PASS",
            sites.len(),
            tracked,
            acq,
            top.file,
            if top.line > 0 { alloc::format!(":{}", top.line) } else { String::new() },
            top.taken,
            top.held_us / 1000
        );
    }

    // 10. P1: rodzina procesów bez globalnej tablicy zombie – prawdziwy init
    // (`init test /bin/famtest`, zarejestrowany jako init: sieroty idą do
    // niego): 200 dzieci naraz, wait(pid), WNOHANG, 8 x 25 sierot, 4 rodziców
    // po 50 dzieci równolegle.  Potem: żadnych zombie, żadnego famtest.
    let opts = SpawnOptions { stdin: Some(Vec::new()), capture: true, ..SpawnOptions::default() };
    let id = exec("/bin/init", &["init", "test", "/bin/famtest"], "/", &opts);
    check!(id.is_ok(), "cannot start init test /bin/famtest");
    let id = id.unwrap_or(0);
    super::procs::set_init_pid(id);
    let done = wait_for(60_000, || sched::task_info(id).is_none());
    super::procs::set_init_pid(0);
    check!(done, "init test /bin/famtest did not finish");
    let kind = exit_info(id).map(|e| e.kind);
    let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
    let line = out.lines().find(|l| l.starts_with("famtest:")).unwrap_or("").trim();
    check!(kind == Some(ExitKind::Exit(0)) && line.contains("checks OK"), "famtest: {:?} {:?}", kind, out.trim());
    check!(
        wait_for(2_000, || !sched::tasks().iter().any(|t| t.name == "famtest")),
        "famtest processes left (orphans not reaped by init)"
    );
    check!(out.contains("init: test program ended, 200 orphans reaped"), "init must reap all 200 orphans: {:?}", out.trim());
    check!(super::procs::zombies().is_empty(), "zombies left: {:?}", super::procs::zombies());
    serial_println!("[NOBKL TEST] 10/10 process family with per-parent zombie lists, 200 orphans reaped by init: {} PASS", line);

    crate::selftest::pass();
}
