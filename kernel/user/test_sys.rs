// M14: samotesty syscalli (tylko build z --cfg selftest).

use alloc::vec::Vec;

use super::*;

use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[SYSCALL TEST] FAIL: {}", format_args!($($msg)*));
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

fn start(name: &str, stdin: Option<&[u8]>) -> Option<TaskId> {
    let opts = SpawnOptions { stdin: stdin.map(|s| s.to_vec()), capture: true, ..SpawnOptions::default() };
    spawn_with(name, programs::code(name)?, &opts).ok()
}

/// Uruchamia z przechwyceniem wyjścia; (sposób zakończenia, wyjście).
fn run_capture(name: &str, stdin: Option<&[u8]>) -> Option<(ExitKind, Vec<u8>)> {
    let id = start(name, stdin)?;
    if !wait_for(5000, || sched::task_info(id).is_none()) {
        return None;
    }
    Some((exit_info(id)?.kind, captured_output(id).unwrap_or_default()))
}

fn frames_back(before: u64) -> bool {
    wait_for(300, || {
        sched::reap();
        crate::sched::stack::free_frames_flushed() == before
    })
}

pub fn self_test() {
    use crate::arch::x86_64::{exceptions, syscall};
    serial_println!("[SYSCALL TEST] Starting syscall tests...");
    crate::selftest::begin();
    let frames = crate::sched::stack::free_frames_flushed();

    // 1. MSR-y SYSCALL/SYSRET i blok per CPU.
    let (sce, star, lstar, fmask, kgs, krsp) = syscall::state();
    check!(sce, "EFER.SCE off");
    check!(star == (0x08u64 << 32) | (syscall::SYSRET_BASE << 48), "STAR {:#x}", star);
    check!(lstar == syscall::entry_address(), "LSTAR {:#x}", lstar);
    check!(fmask & (1 << 9) != 0 && fmask & (1 << 10) != 0, "SFMASK {:#x} (IF/DF not cleared)", fmask);
    check!(kgs == syscall::percpu_address(), "KERNEL_GS_BASE {:#x}", kgs);
    check!(krsp == crate::memory::kernel_layout().stack_top, "per-CPU kernel stack {:#x}", krsp);
    serial_println!(
        "[SYSCALL TEST] 1/10 EFER.SCE, STAR, LSTAR, SFMASK, per-CPU stack (SMAP {}) PASS",
        smap_enabled()
    );

    // 2. write + exit.
    let r = run_capture("hello", None);
    check!(
        r.as_ref().map(|(k, o)| (*k, o.as_slice())) == Some((ExitKind::Exit(0), &b"Hello from ring 3! (syscall write)\n"[..])),
        "hello: {:?}",
        r.as_ref().map(|(k, o)| (*k, alloc::string::String::from_utf8_lossy(o)))
    );
    serial_println!("[SYSCALL TEST] 2/10 write(1) + exit(0) PASS");

    // 3. Pliki: open/write/close/open/read/close przez VFS.
    let _ = crate::fs::remove("/tmp/ring3.txt");
    let r = run_capture("files", None);
    let want = b"written by a ring 3 process\n";
    check!(
        r.as_ref().map(|(k, o)| (*k, o.as_slice())) == Some((ExitKind::Exit(0), &want[..])),
        "files: {:?}",
        r.as_ref().map(|(k, o)| (*k, alloc::string::String::from_utf8_lossy(o)))
    );
    check!(crate::fs::read_file("/tmp/ring3.txt").ok().as_deref() == Some(&want[..]), "file content in the VFS");
    let _ = crate::fs::remove("/tmp/ring3.txt");
    serial_println!("[SYSCALL TEST] 3/10 open/write/read/close on the VFS (/tmp/ring3.txt) PASS");

    // 4. read z wejścia.
    let r = run_capture("cat", Some(b"abc\n"));
    check!(
        r.as_ref().map(|(k, o)| (*k, o.as_slice())) == Some((ExitKind::Exit(0), &b"Type something: You typed: abc\n"[..])),
        "cat: {:?}",
        r.as_ref().map(|(k, o)| (*k, alloc::string::String::from_utf8_lossy(o)))
    );
    serial_println!("[SYSCALL TEST] 4/10 read(0) from stdin PASS");

    // 5. Błędy: zły wskaźnik, nieznany syscall; getpid.
    let r = run_capture("badptr", None).map(|(k, _)| k);
    check!(r == Some(ExitKind::Exit(-14)), "badptr: {:?}", r);
    let r = run_capture("badsys", None).map(|(k, _)| k);
    check!(r == Some(ExitKind::Exit(-38)), "badsys: {:?}", r);
    let pid = start("pid", None);
    check!(pid.is_some() && wait_for(2000, || sched::task_info(pid.unwrap()).is_none()), "pid did not end");
    let pid = pid.unwrap();
    check!(exit_info(pid).map(|e| e.kind) == Some(ExitKind::Exit(pid as i64)), "getpid: {:?}", exit_info(pid).map(|e| e.kind));
    serial_println!("[SYSCALL TEST] 5/10 kernel pointer -> EFAULT, unknown syscall -> ENOSYS, getpid PASS");

    // 6. Rejestry po 100 000 syscalli, 3 procesy naraz (przełączanie w trakcie).
    let ids: Vec<TaskId> = (0..3).filter_map(|_| start("regs", None)).collect();
    check!(ids.len() == 3, "spawn regs");
    check!(wait_for(20_000, || ids.iter().all(|i| sched::task_info(*i).is_none())), "regs did not end");
    for id in &ids {
        let k = exit_info(*id).map(|e| e.kind);
        check!(k == Some(ExitKind::Exit(0)), "regs {}: {:?} (1 = a register changed)", id, k);
    }
    serial_println!("[SYSCALL TEST] 6/10 3 x 100 000 syscalls, all registers preserved PASS");

    // 7. sleep w syscallu (zadanie śpi, CPU dla innych): 4 naraz.
    let ids: Vec<TaskId> = (0..4).filter_map(|_| start("sleeper", None)).collect();
    check!(ids.len() == 4, "spawn sleepers");
    check!(wait_for(3000, || ids.iter().all(|i| sched::task_info(*i).is_none())), "sleepers did not end");
    for id in &ids {
        let k = exit_info(*id).map(|e| e.kind);
        check!(matches!(k, Some(ExitKind::Exit(ms)) if (100..=120).contains(&ms)), "sleeper {}: {:?}", id, k);
    }
    serial_println!("[SYSCALL TEST] 7/10 sleep(100) in 4 processes at once -> 100..120 ms each PASS");

    // 8. kill procesu czekającego w syscallu (read z klawiatury).
    let opts = SpawnOptions { capture: true, ..SpawnOptions::default() };
    let id = spawn_with("cat", programs::code("cat").unwrap(), &opts).ok();
    check!(id.is_some(), "spawn cat");
    let id = id.unwrap();
    check!(
        wait_for(500, || sched::task_info(id).map(|t| t.state) == Some(sched::State::Blocked)),
        "cat not blocked in read"
    );
    check!(sched::request_exit(id), "request_exit");
    check!(wait_for(200, || sched::task_info(id).is_none()), "blocked process not killed");
    check!(exit_info(id).map(|e| e.kind) == Some(ExitKind::Killed), "cat: {:?}", exit_info(id).map(|e| e.kind));
    serial_println!("[SYSCALL TEST] 8/10 kill while blocked in read() PASS");

    // 9. SYSRET: syscall jako ostatnia instrukcja dolnej połowy -> RIP
    //    powrotu 0x0000_8000_0000_0000 (niekanoniczny) -> proces kończony.
    let mut page = alloc::vec![0u8; 4096];
    page[0xff9..].copy_from_slice(&[0xb8, 0x07, 0x00, 0x00, 0x00, 0x0f, 0x05]); // mov eax, 7; syscall
    let opts = SpawnOptions { code_at: 0x0000_7fff_ffff_f000, entry_offset: 0xff9, ..SpawnOptions::default() };
    let id = spawn_with("edge", &page, &opts).ok();
    check!(id.is_some(), "spawn edge");
    let id = id.unwrap();
    check!(wait_for(1000, || sched::task_info(id).is_none()), "edge did not end");
    let e = exit_info(id);
    check!(
        e.map(|e| (e.kind, e.rip)) == Some((ExitKind::BadReturn, 0x0000_8000_0000_0000)),
        "edge: {:?}",
        e.map(|e| (e.kind, e.rip))
    );
    serial_println!("[SYSCALL TEST] 9/10 non-canonical SYSRET address -> process killed, not a kernel #GP PASS");

    // 10. SMAP: kernel nie czyta strony użytkownika poza copy_from_user.
    if smap_enabled() {
        let mut sp = AddressSpace::new().unwrap();
        sp.map_new(USER_DATA, USER | WRITABLE).unwrap();
        let fault = without_interrupts(|| unsafe {
            let old: u64;
            core::arch::asm!("mov {}, cr3", out(reg) old);
            core::arch::asm!("mov cr3, {}", in(reg) sp.cr3());
            let r = exceptions::probe_read(USER_DATA);
            core::arch::asm!("mov cr3, {}", in(reg) old);
            r
        });
        drop(sp);
        check!(fault.is_some(), "kernel read a user page with SMAP on");
        let f = fault.unwrap();
        check!(f.vector == 14 && f.error & 1 == 1 && f.error & 4 == 0 && f.cr2 == USER_DATA, "SMAP fault {:#x} err {:#x}", f.cr2, f.error);
        serial_println!("[SYSCALL TEST] 10/10 SMAP: kernel access to a user page outside stac/clac -> #PF PASS");
    } else {
        serial_println!("[SYSCALL TEST] 10/10 SMAP skipped (CPU without SMAP) PASS");
    }

    check!(frames_back(frames), "frames leaked ({} -> {})", frames, crate::sched::stack::free_frames_flushed());

    serial_println!("[SYSCALL TEST] =================================");
    crate::selftest::pass();
    serial_println!("[SYSCALL TEST] SYSCALL TESTS PASSED");
    serial_println!("[SYSCALL TEST] =================================");
}
