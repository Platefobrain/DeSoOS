// M16: samotesty – porządki (IST, MMIO 4 KiB), rodzina procesów
// (spawn/wait/zombie/sieroty), shell w user space (tylko build z --cfg selftest).

use alloc::string::String;

use super::*;
use crate::memory::{page_flags, phys_to_virt, translate};
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[INIT TEST] FAIL: {}", format_args!($($msg)*));
            procs::set_init_pid(0);
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

/// Proces z /bin (wejście z bufora, wyjście przechwycone).
fn start(path: &str, args: &[&str], stdin: &[u8]) -> Option<TaskId> {
    let opts = SpawnOptions { stdin: Some(stdin.to_vec()), capture: true, ..SpawnOptions::default() };
    exec(path, args, "/", &opts).ok()
}

/// Czeka na koniec procesu; (sposób zakończenia, wyjście).
fn finish(id: TaskId, ms: u64) -> Option<(ExitKind, String)> {
    if !wait_for(ms, || sched::task_info(id).is_none()) {
        let _ = sched::request_exit(id);
        return None;
    }
    let kind = exit_info(id)?.kind;
    Some((kind, String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned()))
}

fn task_named(name: &str) -> Option<sched::TaskInfo> {
    sched::tasks().into_iter().find(|t| t.name == name)
}

pub fn self_test() {
    use crate::arch::x86_64::gdt;
    serial_println!("[INIT TEST] Starting init / process family / user shell tests...");
    crate::selftest::begin();
    let frames = crate::sched::stack::free_frames_flushed();
    let heap_mapped = crate::memory::heap::mapped_bytes();

    // 1. Stosy IST ze stronami-strażnikami.
    for ist in 1..=5u8 {
        let top = gdt::ist_top(ist);
        let bottom = top - crate::sched::stack::STACK_SIZE;
        check!(top >= crate::sched::stack::TASK_STACKS_BASE, "IST {} top {:#x} not in guarded slots", ist, top);
        check!(translate(top - 8).is_some(), "IST {} top not mapped", ist);
        check!(translate(bottom - 4096).is_none(), "IST {} has no guard page under {:#x}", ist, bottom);
        check!(gdt::on_ist_stack(top - 8), "on_ist_stack({:#x}) = false", top - 8);
    }
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp) };
    check!(!gdt::on_ist_stack(rsp), "task stack {:#x} reported as IST", rsp);
    serial_println!("[INIT TEST] 1/9 IST stacks in guarded slots, schedule() guard PASS");

    // 2. Podział strony 2 MiB direct mapy na 4 KiB (map_mmio z RAM-em obok).
    let frame = crate::memory::alloc_frame();
    check!(frame.is_some(), "no frame");
    let frame = frame.unwrap();
    let base = frame & !0x1f_ffff;
    let before = page_flags(phys_to_virt(base));
    check!(crate::memory::split_direct_map_huge(frame), "split failed");
    let mut ok = true;
    for i in 0..512u64 {
        let pa = base + i * 4096;
        if translate(phys_to_virt(pa)) != Some(pa) {
            ok = false;
        }
    }
    check!(ok, "translation changed after split");
    let after = page_flags(phys_to_virt(frame)).unwrap_or(0);
    check!(after & (1 << 7) == 0, "still a 2 MiB page after split (flags {:#x})", after);
    check!(
        before.map(|b| b & 0x8000_0000_0000_001f) == Some(after & 0x8000_0000_0000_001f),
        "flags {:?} -> {:#x}", before, after
    );
    check!(crate::memory::split_direct_map_huge(frame), "second split should be a no-op");
    check!(crate::memory::map_mmio(frame, 4096).is_none(), "map_mmio accepted RAM");
    crate::memory::free_frame(frame);
    serial_println!("[INIT TEST] 2/9 direct map 2 MiB -> 4 KiB split (map_mmio) PASS");

    // 3. Stos pierwszego planu (Ctrl+C kończy proces z wierzchu).
    crate::console::push_foreground(1001);
    crate::console::push_foreground(1002);
    check!(crate::console::top_foreground() == 1002, "top {}", crate::console::top_foreground());
    crate::console::remove_foreground(1002);
    check!(crate::console::top_foreground() == 1001, "top after remove {}", crate::console::top_foreground());
    crate::console::remove_foreground(1001);
    check!(crate::console::top_foreground() == 0, "stack not empty");
    serial_println!("[INIT TEST] 3/9 foreground stack (Ctrl+C target) PASS");

    // 4. Shell w user space: wbudowane, programy, przekierowania, edycja linii.
    let script: &[u8] = b"echo hello world\n\
pwd\n\
cd /bin\n\
pwd\n\
cd /nope\n\
cd /\n\
mkdir /m16\n\
touch /m16/a\n\
echo text > /m16/b\n\
echo more >> /m16/b\n\
cat /m16/b\n\
ls /m16\n\
cp /m16/b /m16/c\n\
cat < /m16/c\n\
rm /m16/a\n\
stat /m16/a\n\
nosuchcmd\n\
args \"one two\" three\n\
echo abc\x1b[D\x1b[DX\n\
\x1b[A\n\
ver\n\
k uptime > /m16/up\n\
stat /m16/up\n\
kill 1\n\
exit 7\n";
    let sh = start("/bin/sh", &["sh"], script);
    check!(sh.is_some(), "cannot start /bin/sh");
    let r = finish(sh.unwrap(), 20_000);
    check!(r.is_some(), "sh timeout");
    let (kind, out) = r.unwrap();
    let expect = [
        "hello world\n",
        "\n/\n",
        "\n/bin\n",
        "cd: /nope: no such file or directory",
        "text\nmore\n",
        "a\n",
        "stat: /m16/a: no such file or directory",
        "sh: nosuchcmd: command not found",
        "argc = 3\nargv[0] = args\nargv[1] = one two\nargv[2] = three\n",
        "\naXbc\n",
        "DeSoOS v",
        "/m16/up: file,",
        "kill: 1: no such process",
    ];
    for e in expect {
        check!(out.contains(e), "sh output lacks {:?}:\n{}", e, out);
    }
    check!(out.matches("\naXbc\n").count() == 2, "history (Up) did not repeat the line:\n{}", out);
    check!(kind == ExitKind::Exit(7), "sh ended with {:?}", kind);
    check!(crate::fs::read_file("/m16/c").ok().as_deref() == Some(b"text\nmore\n".as_slice()), "cp content");
    serial_println!("[INIT TEST] 4/9 user shell: builtins, /bin programs, > >> <, quotes, line editing, k PASS");

    // 5. Bez zombie: shell odebrał status każdego dziecka.
    check!(procs::zombies().is_empty(), "zombies left: {:?}", procs::zombies());
    serial_println!("[INIT TEST] 5/9 no zombies after the shell PASS");

    // 6. Sierota bez init: dziecko kończącego się procesu przechodzi do kernela.
    let sh = start("/bin/sh", &["sh", "-c", "sleep", "400", "&"], b"");
    check!(sh.is_some(), "cannot start sh -c");
    let sh = sh.unwrap();
    let r = finish(sh, 5_000);
    check!(matches!(r, Some((ExitKind::Exit(0), _))), "sh -c: {:?}", r);
    let orphan = task_named("sleep");
    check!(orphan.is_some(), "background sleep not running");
    let orphan = orphan.unwrap();
    check!(orphan.ppid == 0, "orphan ppid {} (want 0 = kernel)", orphan.ppid);
    check!(finish(orphan.id, 2_000).is_some(), "orphan did not end");
    check!(procs::zombies().is_empty(), "orphan left a zombie");
    serial_println!("[INIT TEST] 6/9 orphan without init goes to the kernel PASS");

    // 7. Sierota z init: proces "init" (shell) dostaje wnuka i go sprząta.
    // "sleep 200" na początku: set_init_pid wołamy dopiero po starcie shella –
    // bez chwili zapasu wewnętrzny `sh -c` potrafił skończyć się wcześniej
    // i sierota szła do kernela (v0.17.12: procesy startują bez BKL, szybciej).
    let init = start("/bin/sh", &["sh"], b"sleep 200\nsh -c \"sleep 300 &\"\nwait\nexit 3\n");
    check!(init.is_some(), "cannot start init shell");
    let init = init.unwrap();
    procs::set_init_pid(init);
    let adopted = wait_for(3_000, || task_named("sleep").map(|t| t.ppid) == Some(init));
    check!(adopted, "sleep not adopted by init {} ({:?})", init, task_named("sleep").map(|t| t.ppid));
    check!(syscalls::sys_kill(init) == Err(syscalls::EPERM), "kill(init) allowed");
    let r = finish(init, 5_000);
    procs::set_init_pid(0);
    check!(matches!(r, Some((ExitKind::Exit(3), _))), "init shell: {:?}", r);
    check!(task_named("sleep").is_none(), "adopted sleep still running");
    check!(procs::zombies().is_empty(), "zombies after init: {:?}", procs::zombies());
    serial_println!("[INIT TEST] 7/9 orphan adopted and reaped by init, kill(init) = EPERM PASS");

    // 8. Ctrl+C (kill) programu na pierwszym planie kończy program, nie shell.
    let sh = start("/bin/sh", &["sh"], b"primes 50000000\necho after\n");
    check!(sh.is_some(), "cannot start sh");
    let sh = sh.unwrap();
    check!(wait_for(3_000, || task_named("primes").is_some()), "primes did not start");
    // M17a.e: shell rejestruje dziecko na pierwszym planie tuż PO utworzeniu
    // zadania – drugi CPU może zobaczyć "primes" chwilę wcześniej (u Dawida:
    // "foreground 0 is not primes").  Czekamy na oba warunki.
    wait_for(3_000, || crate::console::top_foreground() == task_named("primes").map(|t| t.id).unwrap_or(0));
    let fg = crate::console::top_foreground();
    check!(fg == task_named("primes").map(|t| t.id).unwrap_or(0), "foreground {} is not primes", fg);
    check!(crate::console::interrupt_foreground(), "Ctrl+C found no foreground process");
    let r = finish(sh, 5_000);
    check!(matches!(&r, Some((ExitKind::Exit(0), o)) if o.contains("after\n")), "shell after Ctrl+C: {:?}", r);
    check!(crate::console::top_foreground() == 0, "foreground stack not empty");
    serial_println!("[INIT TEST] 8/9 Ctrl+C ends the foreground program, the shell continues PASS");

    // 9. Sprzątanie: pliki i ramki.  Ramki heapa (heap rośnie przy wczytaniu
    // programu i oddaje strony tylko od końca) i tablica PT z testu 2 nie są
    // wyciekiem – liczymy je osobno.
    for f in ["/m16/b", "/m16/c", "/m16/up"] {
        let _ = crate::fs::remove(f);
    }
    let _ = crate::fs::remove("/m16");
    let accounted = || {
        let heap_growth = (crate::memory::heap::mapped_bytes().saturating_sub(heap_mapped) / 4096) as u64;
        crate::sched::stack::free_frames_flushed() + heap_growth + 1 // +1: tablica PT po podziale strony 2 MiB
    };
    let back = wait_for(1_000, || {
        sched::reap();
        accounted() >= frames
    });
    check!(back, "frames leaked ({} -> {} incl. heap growth)", frames, accounted());
    serial_println!("[INIT TEST] 9/9 no frame leak PASS");
    crate::selftest::pass();
    serial_println!("[INIT TEST] All init / process / shell tests passed");
}
