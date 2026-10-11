// M17b: samotesty obiektów plików, potoków i pamięci procesu (tylko build z
// --cfg selftest).  Testy biegną w programach z /bin (prawdziwe syscalle z
// ring 3); kernel sprawdza kod wyjścia i wyjście.

use alloc::string::String;

use super::*;
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[FILE TEST] FAIL: {}", format_args!($($msg)*));
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
    serial_println!("[FILE TEST] Starting file object / pipe / process memory tests...");
    crate::selftest::begin();

    // 1. Obiekty plików: dup, dup2, seek, wspólna pozycja (także z dzieckiem).
    let r = run("/bin/fdtest", &["fdtest"], 10_000);
    check!(r.is_some(), "fdtest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "fdtest: {:?} {:?}", kind, out.trim());
    serial_println!("[FILE TEST] 1/4 dup, dup2, seek, shared position (also with a spawned child): {} PASS", out.trim());

    // 2. Potoki: odczyt / zapis, koniec danych, EPIPE, 200 KiB przez cat,
    // wyjście dziecka przez potok, czekanie czytającego.
    let r = run("/bin/pipetest", &["pipetest"], 20_000);
    check!(r.is_some(), "pipetest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "pipetest: {:?} {:?}", kind, out.trim());
    serial_println!("[FILE TEST] 2/4 pipes: EOF, EPIPE, 200 KiB through cat, child output, blocking reader: {} PASS", out.trim());

    // 3. Potoki w shellu: program | program, wbudowane | program,
    // trzy etapy z przekierowaniem, błędy składni.
    let script: &[u8] = b"echo one two | cat\nprimes 30 | cat | cat > /pipe.out\ncat /pipe.out\nhelp | cat\necho x |\nrm /pipe.out\n";
    let opts = SpawnOptions { stdin: Some(script.to_vec()), capture: true, ..SpawnOptions::default() };
    let sh = exec("/bin/sh", &["sh"], "/", &opts).ok();
    check!(sh.is_some(), "sh did not start");
    let sh = sh.unwrap();
    check!(wait_for(20_000, || sched::task_info(sh).is_none()), "sh with pipelines did not finish");
    let out = String::from_utf8_lossy(&captured_output(sh).unwrap_or_default()).into_owned();
    check!(out.contains("one two\n"), "echo | cat: {:?}", out);
    check!(out.contains("10 primes below 30"), "primes | cat | cat > file, cat file: {:?}", out);
    check!(out.contains("Programs in /bin"), "help | cat: {:?}", out);
    check!(out.contains("missing command around |"), "syntax error not reported: {:?}", out);
    check!(crate::fs::stat("/pipe.out").is_err(), "/pipe.out left behind");
    serial_println!("[FILE TEST] 3/4 shell: echo | cat, primes | cat | cat > file, help | cat, syntax error PASS");

    // 4. Pamięć procesu: brk, mmap / munmap (także częściowe), leniwe strony
    // (64 MiB obszaru, kilka stron użytych), kopiowanie kernela do
    // niedotkniętych stron, alokator (4 MiB Vec, 20000 małych bloków),
    // rosnący stos, #PF po munmap i przepełnienie 8 MiB stosu.
    let frames = crate::memory::free_frame_count();
    let r = run("/bin/memtest", &["memtest"], 30_000);
    check!(r.is_some(), "memtest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "memtest: {:?} {:?}", kind, out.trim());
    // Ramki wracają (reap w pętli idle – chwilę po końcu procesu).
    check!(
        wait_for(3_000, || crate::memory::free_frame_count() + 64 >= frames),
        "memtest leaked frames: {} before, {} after",
        frames,
        crate::memory::free_frame_count()
    );
    serial_println!("[FILE TEST] 4/4 process memory: brk, mmap/munmap, lazy pages, growing stack, allocator: {} PASS", out.trim());

    serial_println!("[FILE TEST] All file tests passed!");
    crate::selftest::pass();
}
