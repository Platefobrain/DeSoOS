// Self-tests of file objects, pipes and process memory (selftest build only,
// --cfg selftest).  The tests run in programs from /bin (real syscalls from
// ring 3); the kernel checks the exit code and the output.

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

/// Program from /bin with captured output; (how it ended, output).
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

/// Removes a file or a directory with its contents; number of removed entries.
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

    // 1. File objects: dup, dup2, seek, shared position (also with a child).
    let r = run("/bin/fdtest", &["fdtest"], 10_000);
    check!(r.is_some(), "fdtest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "fdtest: {:?} {:?}", kind, out.trim());
    serial_println!("[FILE TEST] 1/7 dup, dup2, seek, shared position (also with a spawned child): {} PASS", out.trim());

    // 2. Pipes: read / write, end of data, ERROR_CLOSED, 200 KiB through cat,
    // child output through a pipe, a waiting reader.
    let r = run("/bin/pipetest", &["pipetest"], 20_000);
    check!(r.is_some(), "pipetest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "pipetest: {:?} {:?}", kind, out.trim());
    serial_println!("[FILE TEST] 2/7 pipes: EOF, ERROR_CLOSED, 200 KiB through cat, child output, blocking reader: {} PASS", out.trim());

    // 3. Pipes in the shell: program | program, builtin | program,
    // three stages with redirection, syntax errors.
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
    serial_println!("[FILE TEST] 3/7 shell: echo | cat, primes | cat | cat > file, help | cat, syntax error PASS");

    // 4. Process memory: brk, mmap / munmap (also partial), lazy pages
    // (64 MiB region, a few pages used), kernel copying into
    // untouched pages, allocator (4 MiB Vec, 20000 small blocks),
    // growing stack, #PF after munmap and an 8 MiB stack overflow.
    let frames = crate::memory::free_frame_count();
    let r = run("/bin/memtest", &["memtest"], 30_000);
    check!(r.is_some(), "memtest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "memtest: {:?} {:?}", kind, out.trim());
    // Frames come back (reap in the idle loop – shortly after the process ends).
    check!(
        wait_for(3_000, || crate::memory::free_frame_count() + 64 >= frames),
        "memtest leaked frames: {} before, {} after",
        frames,
        crate::memory::free_frame_count()
    );
    serial_println!("[FILE TEST] 4/7 process memory: brk, mmap/munmap, lazy pages, growing stack, allocator: {} PASS", out.trim());

    // 5. System call fuzzer: children without handles call random
    // syscalls with extreme arguments; the kernel must not crash or
    // hang, frames come back.
    let root0: alloc::vec::Vec<String> = crate::fs::read_dir("/").map(|v| v.into_iter().map(|e| e.name).collect()).unwrap_or_default();
    let frames = crate::memory::free_frame_count();
    let r = run("/bin/sysfuzz", &["sysfuzz", "32", "3000"], 120_000);
    check!(r.is_some(), "sysfuzz did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("kernel survived"), "sysfuzz: {:?} {:?}", kind, out.trim());
    // Junk from random paths (files and directories with odd names in /fuzz
    // and in /) – removed by the kernel, recursively, so it does not disturb later tests.
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
    serial_println!("[FILE TEST] 5/7 syscall fuzzer: {}; {} junk entries removed PASS", out.trim(), junk);

    // 6. Limits – process bomb, shared memory, memory
    // hog, filling ramfs, IPC buffers.  The program gets an error or dies,
    // the kernel keeps running; after the test everything comes back.
    use core::sync::atomic::Ordering::Relaxed;
    let procs0 = super::process::LIVE_PROCS.load(Relaxed);
    let (kb0, _) = super::kbuf::stats();
    let ram0 = crate::fs::ramfs::bytes_used();
    // As in stress: stacks of finished tasks stay mapped for reuse
    // (free_frames_flushed counts them), the heap returns pages with a delay.
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
    // ramfs files in 64 KiB chunks: 4 KiB appends, reads across chunk edges at odd
    // offsets, truncate + extend (zeros), and the time for 10 MiB of appends (each
    // used to copy the whole file).
    {
        let path = "/ramchunk.tmp";
        let pat = |i: usize| (i * 13 + i / 4093) as u8;
        let ram_a = crate::fs::ramfs::bytes_used();
        check!(crate::fs::create(path).is_ok(), "create {}", path);
        let mut piece = [0u8; 4096];
        for k in 0..75 {
            for (j, b) in piece.iter_mut().enumerate() {
                *b = pat(k * 4096 + j);
            }
            check!(crate::fs::write(path, (k * 4096) as u64, &piece) == Ok(4096), "append {}", k);
        }
        let mut buf = [0u8; 5000];
        for &off in &[0usize, 65_000, 131_071, 196_600, 302_000] {
            let n = crate::fs::read(path, off as u64, &mut buf).unwrap_or(0);
            let want = (300 * 1024 - off).min(5000);
            check!(n == want && (0..n).all(|i| buf[i] == pat(off + i)), "read at {}: {} bytes, pattern {}", off, n, (0..n).all(|i| buf[i] == pat(off + i)));
        }
        check!(crate::fs::truncate(path, 70_000).is_ok(), "truncate");
        check!(crate::fs::write(path, 139_999, &[7]) == Ok(1), "extend by writing");
        let n = crate::fs::read(path, 69_000, &mut buf).unwrap_or(0);
        check!(n == 5000 && (0..1000).all(|i| buf[i] == pat(69_000 + i)) && buf[1000..].iter().all(|&b| b == 0), "after truncate + extend: old bytes, then zeros");
        let t0 = crate::time::ticks();
        for k in 75..2560 {
            check!(crate::fs::write(path, (k * 4096) as u64, &piece) == Ok(4096), "append {} (10 MiB)", k);
        }
        let ms = crate::time::ticks() - t0;
        check!(crate::fs::remove(path).is_ok(), "remove");
        check!(crate::fs::ramfs::bytes_used() == ram_a, "ramfs bytes after the chunk test: {} -> {}", ram_a, crate::fs::ramfs::bytes_used());
        serial_println!("[FILE TEST]   ramfs chunks: 300 KiB pattern, edges, truncate + extend OK; 10 MiB of 4 KiB appends in {} ms", ms);
    }
    serial_println!("[FILE TEST] 6/7 limits (processes, kernel memory reserve, ramfs, IPC buffers): {} PASS", out.trim());

    // 7. File sandbox: a child started with SPAWN_NO_FILES cannot use any path
    // (open, stat, readdir, mkdir, unlink, chdir, spawn) and works only with the
    // handles it was given, with their rights; the kernel counts the refusals.
    let denied0 = super::syscalls::SANDBOX_DENIED.load(Relaxed);
    let r = run("/bin/sandtest", &["sandtest"], 30_000);
    check!(r.is_some(), "sandtest did not finish");
    let (kind, out) = r.unwrap();
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "sandtest: {:?} {:?}", kind, out.trim());
    let denied = super::syscalls::SANDBOX_DENIED.load(Relaxed) - denied0;
    check!(denied >= 11, "sandbox refusals counted: {}", denied);
    check!(crate::fs::stat("/sandtest.tmp").is_err(), "sandtest left its file");
    let line = out.lines().find(|l| l.contains("checks OK")).unwrap_or("").trim();
    serial_println!("[FILE TEST] 7/7 file sandbox: {} ({} path calls refused) PASS", line, denied);

    serial_println!("[FILE TEST] All file tests passed!");
    crate::selftest::pass();
}
