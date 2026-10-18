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

/// Usuwa plik albo katalog z zawartością; liczba usuniętych wpisów.
fn rm_rf(path: &str) -> u64 {
    let mut n = 0;
    if let Ok(entries) = crate::fs::read_dir(path) {
        for e in entries {
            n += rm_rf(&alloc::format!("{}/{}", path.trim_end_matches('/'), e.name));
        }
    }
    if crate::fs::remove(path).is_ok() {
        n += 1;
    }
    n
}

pub fn self_test() {
    serial_println!("[FILE TEST] Starting file object / pipe / process memory tests...");
    crate::selftest::begin();

    // 1. Obiekty plików: dup, dup2, seek, wspólna pozycja (także z dzieckiem).
    let r = run("/bin/fdtest", &["fdtest"], 10_000);
    check!(r.is_some(), "fdtest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "fdtest: {:?} {:?}", kind, out.trim());
    serial_println!("[FILE TEST] 1/6 dup, dup2, seek, shared position (also with a spawned child): {} PASS", out.trim());

    // 2. Potoki: odczyt / zapis, koniec danych, EPIPE, 200 KiB przez cat,
    // wyjście dziecka przez potok, czekanie czytającego.
    let r = run("/bin/pipetest", &["pipetest"], 20_000);
    check!(r.is_some(), "pipetest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "pipetest: {:?} {:?}", kind, out.trim());
    serial_println!("[FILE TEST] 2/6 pipes: EOF, EPIPE, 200 KiB through cat, child output, blocking reader: {} PASS", out.trim());

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
    serial_println!("[FILE TEST] 3/6 shell: echo | cat, primes | cat | cat > file, help | cat, syntax error PASS");

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
    serial_println!("[FILE TEST] 4/6 process memory: brk, mmap/munmap, lazy pages, growing stack, allocator: {} PASS", out.trim());

    // 5. Fuzzer wywołań systemowych: dzieci bez uchwytów wołają losowe
    // syscalle ze skrajnymi argumentami; jądro nie może paść ani się
    // zawiesić, ramki wracają.
    let root0: alloc::vec::Vec<String> = crate::fs::read_dir("/").map(|v| v.into_iter().map(|e| e.name).collect()).unwrap_or_default();
    let frames = crate::memory::free_frame_count();
    let r = run("/bin/sysfuzz", &["sysfuzz", "32", "3000"], 120_000);
    check!(r.is_some(), "sysfuzz did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("kernel survived"), "sysfuzz: {:?} {:?}", kind, out.trim());
    // Śmieci z losowych ścieżek (pliki i katalogi o dziwnych nazwach w /fuzz
    // i w /) – usuwa jądro, rekurencyjnie, żeby nie przeszkadzały dalszym testom.
    let mut junk = rm_rf("/fuzz");
    for e in crate::fs::read_dir("/").unwrap_or_default() {
        if !root0.contains(&e.name) {
            junk += rm_rf(&alloc::format!("/{}", e.name));
        }
    }
    check!(
        wait_for(3_000, || crate::memory::free_frame_count() + 256 >= frames),
        "sysfuzz leaked frames: {} before, {} after",
        frames,
        crate::memory::free_frame_count()
    );
    check!(crate::fs::stat("/fuzz").is_err(), "/fuzz could not be removed");
    serial_println!("[FILE TEST] 5/6 syscall fuzzer: {}; {} junk entries removed PASS", out.trim(), junk);

    // 6. v0.35.2: limity – bomba procesów, pamięć współdzielona, pożeracz
    // pamięci, zapełnienie ramfs, bufory IPC.  Program dostaje błąd albo ginie,
    // jądro działa; po teście wszystko wraca.
    use core::sync::atomic::Ordering::Relaxed;
    let procs0 = super::process::LIVE_PROCS.load(Relaxed);
    let (kb0, _) = super::kbuf::stats();
    let ram0 = crate::fs::ramfs::bytes_used();
    // Jak w stressie: stosy skończonych zadań zostają zamapowane do ponownego
    // użycia (free_frames_flushed je liczy), heap oddaje strony z opóźnieniem.
    let frames = crate::sched::stack::free_frames_flushed();
    let heap0 = crate::memory::heap::mapped_bytes() as u64;
    let r = run("/bin/limtest", &["limtest"], 600_000);
    check!(r.is_some(), "limtest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "limtest: {:?} {:?}", kind, out.trim());
    check!(wait_for(5_000, || super::process::LIVE_PROCS.load(Relaxed) <= procs0), "processes left: {} before, {} after", procs0, super::process::LIVE_PROCS.load(Relaxed));
    check!(super::kbuf::stats().0 <= kb0, "IPC buffer budget not returned: {} before, {} after", kb0, super::kbuf::stats().0);
    check!(crate::fs::ramfs::bytes_used() <= ram0, "ramfs bytes not returned: {} before, {} after", ram0, crate::fs::ramfs::bytes_used());
    let heap_growth = || (crate::memory::heap::mapped_bytes() as u64).saturating_sub(heap0) / 4096;
    check!(
        wait_for(5_000, || crate::sched::stack::free_frames_flushed() + heap_growth() + 256 >= frames),
        "limtest leaked frames: {} before, {} after (+{} heap pages)",
        frames,
        crate::sched::stack::free_frames_flushed(),
        heap_growth()
    );
    let r = run("/bin/hello", &["hello"], 10_000);
    check!(matches!(r, Some((ExitKind::Exit(0), _))), "a program must run normally after the limits test: {:?}", r.map(|x| x.0));
    serial_println!("[FILE TEST] 6/6 limits (processes, kernel memory reserve, ramfs, IPC buffers): {} PASS", out.trim());

    serial_println!("[FILE TEST] All file tests passed!");
    crate::selftest::pass();
}
