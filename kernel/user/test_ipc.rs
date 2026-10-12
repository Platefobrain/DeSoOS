// M18: samotesty IPC – uchwyty z prawami, kanały, pamięć współdzielona
// (tylko build z --cfg selftest).  Testy biegną w programach z /bin
// (prawdziwe syscalle z ring 3); kernel sprawdza kod wyjścia i wyjście.

use alloc::string::String;

use super::*;
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[IPC TEST] FAIL: {}", format_args!($($msg)*));
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

/// Program z /bin z przechwyconym wyjściem; (sposób zakończenia, wyjście).
fn run(path: &str, args: &[&str], ms: u64) -> Option<(ExitKind, String)> {
    let opts = SpawnOptions { stdin: Some(alloc::vec::Vec::new()), capture: true, ..SpawnOptions::default() };
    let id = exec(path, args, "/", &opts).ok()?;
    if !wait_for(ms, || sched::task_info(id).is_none()) {
        let _ = sched::request_exit(id);
        return None;
    }
    let kind = exit_info(id)?.kind;
    Some((kind, String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned()))
}

pub fn self_test() {
    serial_println!("[IPC TEST] Starting IPC tests (handles, channels, shared memory)...");
    crate::selftest::begin();
    let frames0 = crate::selftest::settled_free_frames();

    // 1. M18.b: uchwyty z prawami – handle_dup tylko zmniejsza, read / write
    // bez prawa = EBADF, kopie bez DUP = EACCES, dziecko dziedziczy prawa,
    // limit 64.
    let r = run("/bin/handletest", &["handletest"], 10_000);
    check!(r.is_some(), "handletest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "handletest: {:?} {:?}", kind, out.trim());
    serial_println!("[IPC TEST] 1/5 handle rights: reduce only, EBADF / EACCES, inherited by a child, 64 per process: {} PASS", out.trim());

    // 2. M18.c: kanały – obie strony, nadawca od jądra, EAGAIN, EMSGSIZE,
    // prawa SEND / RECV, EPIPE po zamknięciu, ping-pong z dzieckiem, kill
    // dziecka czekającego w recv.
    let r = run("/bin/chantest", &["chantest"], 60_000);
    check!(r.is_some(), "chantest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "chantest: {:?} {:?}", kind, out.trim());
    serial_println!("[IPC TEST] 2/5 channels: both ways, sender from the kernel, EAGAIN, EMSGSIZE, rights, EPIPE, kill while waiting: {} PASS", out.trim());

    // 3. M18.d: uchwyty w komunikatach (przeniesienie, prawa, TRANSFER, własny
    // kanał, EMSGSIZE / EMFILE bez utraty), zwalnianie z zamkniętej kolejki,
    // spawn_ex – dziecko tylko z jednym uchwytem dostaje plik przez kanał.
    let r = run("/bin/xfertest", &["xfertest"], 20_000);
    check!(r.is_some(), "xfertest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "xfertest: {:?} {:?}", kind, out.trim());
    serial_println!("[IPC TEST] 3/5 handles in messages + spawn_ex: moved with rights, TRANSFER, own channel refused, nothing lost on EMSGSIZE / EMFILE, child with one handle: {} PASS", out.trim());

    // 4. M18.e: pamięć współdzielona – dwa mapowania i dwa procesy na tych
    // samych stronach, dane + dzwonek przez kanał, tylko do odczytu, NX,
    // munmap w całości, obiekt żyje, dopóki jest zamapowany.
    let r = run("/bin/shmtest", &["shmtest"], 30_000);
    check!(r.is_some(), "shmtest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "shmtest: {:?} {:?}", kind, out.trim());
    serial_println!("[IPC TEST] 4/5 shared memory: same pages in 2 mappings / 2 processes, doorbell over a channel, read-only, NX, whole munmap, lives while mapped: {} PASS", out.trim());

    // 5. M18.f: zadanie stressu (ipcload: shm + dzwonek, kill dziecka w
    // trakcie czekania), pokaz (ipcdemo) i pomiar (ipcbench – wynik w logu).
    let r = run("/bin/ipcload", &["ipcload"], 30_000);
    check!(r.is_some(), "ipcload did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("ipcload: OK"), "ipcload: {:?} {:?}", kind, out.trim());
    let r = run("/bin/ipcdemo", &["ipcdemo"], 10_000);
    check!(r.is_some(), "ipcdemo did not finish");
    let (kind, demo) = r.unwrap();
    check!(
        kind == ExitKind::Exit(0) && demo.contains("CZESC Z DESOOS") && demo.contains("we wspolnej pamieci"),
        "ipcdemo: {:?} {:?}",
        kind,
        demo.trim()
    );
    let r = run("/bin/ipcbench", &["ipcbench"], 120_000);
    check!(r.is_some(), "ipcbench did not finish");
    let (kind, bench) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && bench.contains("ipcbench-result"), "ipcbench: {:?} {:?}", kind, bench.trim());
    let human = bench.lines().find(|l| l.starts_with("ipcbench: ")).unwrap_or("");
    serial_println!("[IPC TEST] 5/5 stress job (ipcload), demo (ipcdemo), benchmark: {} PASS", human);

    crate::sched::reap();
    check!(
        wait_for(2_000, || {
            crate::sched::reap();
            crate::sched::stack::free_frames_flushed() == frames0
        }),
        "frames leaked ({} -> {})",
        frames0,
        crate::sched::stack::free_frames_flushed()
    );
    crate::selftest::pass();
}
