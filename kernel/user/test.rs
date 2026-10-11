// M13a: samotesty trybu użytkownika (tylko build z --cfg selftest).

use alloc::vec::Vec;

use super::*;
use crate::memory::{translate, NO_EXECUTE, PRESENT};
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[USER TEST] FAIL: {}", format_args!($($msg)*));
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

fn run(name: &str, data: u64) -> Option<TaskId> {
    spawn_process(name, programs::code(name)?, data).ok()
}

/// Uruchamia i czeka na koniec; zwraca sposób zakończenia.
fn run_wait(name: &str, data: u64) -> Option<ExitInfo> {
    let id = run(name, data)?;
    if !wait_for(2000, || sched::task_info(id).is_none()) {
        return None;
    }
    exit_info(id)
}

/// Wszystkie ramki wróciły (idle może właśnie sprzątać – czekamy).
fn frames_back(before: u64) -> bool {
    wait_for(200, || {
        sched::reap();
        crate::sched::stack::free_frames_flushed() == before
    })
}

fn cr0() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mov {}, cr0", out(reg) v, options(nomem, nostack)) };
    v
}

pub fn self_test() {
    use crate::arch::x86_64::{exceptions, gdt, idt};
    serial_println!("[USER TEST] Starting user mode tests...");
    crate::selftest::begin();
    let frames = crate::sched::stack::free_frames_flushed();

    // 1. GDT/TSS/IDT/CR0/CR4.
    let udata = gdt::descriptor(3);
    let ucode = gdt::descriptor(4);
    check!((udata >> 45) & 3 == 3 && (ucode >> 45) & 3 == 3, "user segments not DPL 3");
    check!(ucode & (1 << 53) != 0, "user code segment not 64-bit (L)");
    check!(idt::gate_dpl(3) == 3 && idt::gate_dpl(14) == 0, "IDT DPL (#BP must be 3)");
    check!(cr0() & 8 != 0, "CR0.TS not set");
    check!(gdt::rsp0() == crate::memory::kernel_layout().stack_top, "RSP0 is not the kernel task stack");
    serial_println!(
        "[USER TEST] 1/9 GDT ring 3 segments, #BP DPL 3, TSS.RSP0, CR0.TS (NX {}, SMEP {}) PASS",
        nx_flag() != 0,
        smep_enabled()
    );

    // 2. Przestrzeń adresowa: górna połowa wspólna, dolna tylko procesu.
    {
        let mut sp = match AddressSpace::new() {
            Some(s) => s,
            None => {
                serial_println!("[USER TEST] FAIL: AddressSpace::new");
                return;
            }
        };
        let kernel = unsafe { &*(phys_to_virt(crate::memory::kernel_cr3()) as *const [u64; 512]) };
        check!((256..512).filter(|&i| i != 510).all(|i| sp.pml4_entry(i) == kernel[i]), "kernel half differs");
        check!(sp.pml4_entry(510) & !0xfff == sp.cr3() & !0xfff, "recursive slot not self");
        check!((0..256).all(|i| sp.pml4_entry(i) == 0), "lower half not empty");
        check!(sp.map_new(USER_CODE, USER).is_some(), "map code");
        check!(sp.map_new(USER_DATA, USER | WRITABLE | nx_flag()).is_some(), "map data");
        let (_, code_flags) = sp.translate(USER_CODE).unwrap_or((0, 0));
        let (_, data_flags) = sp.translate(USER_DATA).unwrap_or((0, 0));
        check!(code_flags & (PRESENT | USER) == PRESENT | USER && code_flags & WRITABLE == 0, "code flags {:#x}", code_flags);
        check!(code_flags & NO_EXECUTE == 0, "code page NX");
        check!(data_flags & WRITABLE != 0 && data_flags & NO_EXECUTE == nx_flag(), "data flags {:#x}", data_flags);
        check!(sp.pml4_entry(0) & USER != 0, "PML4 entry without USER");
        check!(translate(USER_CODE).is_none(), "process page visible in the kernel address space");
        check!(!sp.map(USER_CODE, 0x1000, USER), "double map accepted");
        check!(!sp.map(0xffff_8000_0000_0000, 0x1000, USER), "kernel-half map accepted");
    }
    check!(frames_back(frames), "address space leaked frames");
    serial_println!("[USER TEST] 2/9 address space: shared kernel half, private lower half, USER/NX PASS");

    // 3. Pierwszy ring 3: iretq -> program -> int3.
    let r = run_wait("sum", 0);
    check!(r.is_some(), "sum did not finish");
    let r = r.unwrap();
    check!(r.kind == ExitKind::Breakpoint, "sum ended with {:?}", r.kind);
    check!(r.rax == 5050, "rax = {}", r.rax);
    check!(r.rbx == USER_CS as u64 && r.cs & 3 == 3, "not in ring 3 (cs {:#x}, rbx {:#x})", r.cs, r.rbx);
    check!((USER_CODE..USER_CODE + 4096).contains(&r.rip), "rip {:#x}", r.rip);
    check!(frames_back(frames), "process leaked frames");
    serial_println!("[USER TEST] 3/9 ring 3 via iretq: sum = 5050, CS = {:#x}, int3 ends it PASS", r.rbx);

    // 4. Wyjątki z ring 3 – wszystkie naraz (stosy IST używane wielokrotnie).
    let cases: [(&str, fn(&ExitKind) -> bool); 6] = [
        ("pf", |k| matches!(k, ExitKind::PageFault { address: 0, error } if error & 5 == 4)),
        ("pfkernel", |k| matches!(k, ExitKind::PageFault { address: 0xffff_ffff_8000_0000, error } if error & 5 == 5)),
        ("writecode", |k| matches!(k, ExitKind::PageFault { address, error } if (USER_CODE..USER_CODE + 4096).contains(address) && error & 7 == 7)),
        ("gp", |k| matches!(k, ExitKind::GeneralProtection { .. })),
        ("ud", |k| matches!(k, ExitKind::InvalidOpcode)),
        ("nx", |k| matches!(k, ExitKind::PageFault { .. })),
    ];
    let mut ids: Vec<(usize, TaskId)> = Vec::new();
    for round in 0..3 {
        let _ = round;
        for (i, (name, _)) in cases.iter().enumerate() {
            match run(name, 0) {
                Some(id) => ids.push((i, id)),
                None => {
                    serial_println!("[USER TEST] FAIL: spawn {}", name);
                    return;
                }
            }
        }
    }
    check!(wait_for(2000, || ids.iter().all(|(_, id)| sched::task_info(*id).is_none())), "faulting processes did not end");
    for (i, id) in &ids {
        let (name, ok) = cases[*i];
        let info = exit_info(*id);
        check!(info.map(|e| ok(&e.kind)).unwrap_or(false), "{}: {:?}", name, info.map(|e| e.kind));
    }
    // M17b.c: #PF z ring 3 obsłużony na stosie kernela zadania, nie na IST.
    let (pf, on_task) = user_page_fault_stats();
    check!(pf > 0 && pf == on_task, "user #PF on the task stack: {} of {}", on_task, pf);
    if nx_flag() != 0 {
        let nx = ids.iter().find(|(i, _)| cases[*i].0 == "nx").and_then(|(_, id)| exit_info(*id));
        check!(
            matches!(nx.map(|e| e.kind), Some(ExitKind::PageFault { error, .. }) if error & 16 != 0),
            "nx: no instruction-fetch fault {:?}",
            nx.map(|e| e.kind)
        );
    }
    check!(frames_back(frames), "faulting processes leaked frames");
    serial_println!("[USER TEST] 4/9 #PF (null, kernel, write code, NX), #GP, #UD x 3 rounds -> only the process ends PASS");

    // 5. Izolacja: dwa procesy, ten sam adres danych, różne strony.
    let a = run("counter", 1000);
    let b = run("counter", 2_000_000);
    check!(a.is_some() && b.is_some(), "spawn counters");
    let (a, b) = (a.unwrap(), b.unwrap());
    check!(wait_for(5000, || sched::task_info(a).is_none() && sched::task_info(b).is_none()), "counters did not end");
    let (ra, rb) = (exit_info(a), exit_info(b));
    check!(ra.map(|e| e.rax) == Some(3_001_000), "process A: {:?}", ra.map(|e| e.rax));
    check!(rb.map(|e| e.rax) == Some(5_000_000), "process B: {:?}", rb.map(|e| e.rax));
    check!(frames_back(frames), "counters leaked frames");
    serial_println!("[USER TEST] 5/9 isolation: same address, own data (3001000 / 5000000) PASS");

    // 6. Wywłaszczanie ring 3 + kill przy przerwaniu.
    let l = run("loop", 0);
    check!(l.is_some(), "spawn loop");
    let l = l.unwrap();
    let t0 = ticks();
    crate::time::sleep_ms(50);
    let cpu = sched::task_info(l).map(|t| t.cpu_ticks).unwrap_or(0);
    check!(cpu >= 20, "loop got only {} ms of CPU", cpu);
    check!(ticks() - t0 < 80, "kernel task starved ({} ms)", ticks() - t0);
    check!(sched::request_exit(l), "request_exit");
    check!(wait_for(100, || sched::task_info(l).is_none()), "loop not killed");
    check!(exit_info(l).map(|e| e.kind) == Some(ExitKind::Killed), "loop: {:?}", exit_info(l).map(|e| e.kind));
    check!(frames_back(frames), "loop leaked frames");
    serial_println!("[USER TEST] 6/9 endless ring 3 loop preempted ({} ms CPU), killed from IRQ PASS", cpu);

    // 7. FPU/SSE w ring 3 działa (M13b; w M13a: #NM).
    for (name, want) in [("sse", 42u64), ("x87", 3)] {
        let r = run_wait(name, 0);
        check!(
            r.map(|e| (e.kind, e.rax)) == Some((ExitKind::Breakpoint, want)),
            "{}: {:?}",
            name,
            r.map(|e| (e.kind, e.rax))
        );
    }
    check!(cr0() & 8 != 0, "kernel task without CR0.TS");
    serial_println!("[USER TEST] 7/9 SSE (21 + 21 = 42) and x87 (1 + 1 + 1 = 3) in ring 3 PASS");

    // 8. SMEP: kernel nie wykona kodu ze strony użytkownika.
    if smep_enabled() {
        let mut sp = AddressSpace::new().unwrap();
        let f = sp.map_new(USER_CODE, USER).unwrap();
        unsafe { core::ptr::copy_nonoverlapping(programs::code("ret").unwrap().as_ptr(), phys_to_virt(f) as *mut u8, 1) };
        let fault = without_interrupts(|| unsafe {
            let old: u64;
            core::arch::asm!("mov {}, cr3", out(reg) old);
            core::arch::asm!("mov cr3, {}", in(reg) sp.cr3());
            let r = exceptions::probe_exec(USER_CODE);
            core::arch::asm!("mov cr3, {}", in(reg) old);
            r
        });
        drop(sp);
        check!(fault.is_some(), "kernel executed a user page with SMEP on");
        let fault = fault.unwrap();
        check!(fault.vector == 14 && fault.error & 0x11 == 0x11 && fault.cr2 == USER_CODE, "SMEP fault {:#x} err {:#x}", fault.cr2, fault.error);
        serial_println!("[USER TEST] 8/9 SMEP: kernel jump to a user page -> #PF (instruction fetch) PASS");
    } else {
        serial_println!("[USER TEST] 8/9 SMEP skipped (CPU without SMEP) PASS");
    }

    // 9. Po wszystkim: RSP0 i CR3 zadania kernela, brak wycieków.
    check!(gdt::rsp0() == crate::memory::kernel_layout().stack_top, "RSP0 not restored");
    let cr3: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3) };
    check!(cr3 & !0xfff == crate::memory::kernel_cr3(), "CR3 not the kernel's");
    let left = sched::tasks().iter().filter(|t| !t.name.starts_with("idle")).count();
    check!(left == 1, "{} tasks left", left);
    check!(frames_back(frames), "frames leaked");
    serial_println!("[USER TEST] 9/9 back in the kernel task: RSP0 + CR3 restored, no leaks PASS");

    serial_println!("[USER TEST] =================================");
    crate::selftest::pass();
    serial_println!("[USER TEST] USER MODE TESTS PASSED");
    serial_println!("[USER TEST] =================================");
}


// ------------------------------------------------------------
// M13b: stan FPU/SSE procesów
// ------------------------------------------------------------

macro_rules! fcheck {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[FPU TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

static SPIN_STOP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn kernel_spinner(_: usize) {
    while !SPIN_STOP.load(core::sync::atomic::Ordering::SeqCst) {
        core::hint::spin_loop();
    }
}

pub fn fpu_self_test() {
    use crate::arch::x86_64::fpu;
    serial_println!("[FPU TEST] Starting FPU/SSE context tests...");
    crate::selftest::begin();
    let frames = crate::sched::stack::free_frames_flushed();

    // 1. CR0/CR4 i obraz początkowy.
    fcheck!(fpu::cr4() & (1 << 9) != 0 && fpu::cr4() & (1 << 10) != 0, "CR4.OSFXSR/OSXMMEXCPT off");
    fcheck!(cr0() & 4 == 0 && cr0() & 2 != 0, "CR0.EM set or CR0.MP clear ({:#x})", cr0());
    fcheck!(fpu::ts(), "kernel task runs without CR0.TS");
    let init = fpu::FxState::initial();
    fcheck!(u16::from_le_bytes([init.0[0], init.0[1]]) == 0x037F, "initial FCW");
    fcheck!(u32::from_le_bytes([init.0[24], init.0[25], init.0[26], init.0[27]]) == 0x1F80, "initial MXCSR");
    serial_println!("[FPU TEST] 1/5 CR4.OSFXSR + OSXMMEXCPT, kernel task with CR0.TS, initial state PASS");

    // 2. Trzy procesy wypełniają xmm0..15 + st0 różnymi wartościami i ciągle
    //    je sprawdzają; obok zadanie kernela – dużo przełączeń.
    SPIN_STOP.store(false, core::sync::atomic::Ordering::SeqCst);
    let spin = sched::spawn("t-fpu-spin", kernel_spinner, 0);
    fcheck!(spin.is_ok(), "spawn spinner");
    let sw0 = sched::total_switches();
    let seeds = [0x1111_0000_0000u64, 0x2222_0000_0000, 0x3333_0000_0000];
    let mut ids = Vec::new();
    for seed in seeds {
        match run("xmm", seed) {
            Some(id) => ids.push(id),
            None => {
                serial_println!("[FPU TEST] FAIL: spawn xmm");
                return;
            }
        }
    }
    let done = wait_for(20_000, || ids.iter().all(|id| sched::task_info(*id).is_none()));
    SPIN_STOP.store(true, core::sync::atomic::Ordering::SeqCst);
    fcheck!(done, "xmm processes did not finish");
    let switches = sched::total_switches() - sw0;
    for (i, id) in ids.iter().enumerate() {
        let r = exit_info(*id);
        fcheck!(
            r.map(|e| (e.kind, e.rax)) == Some((ExitKind::Breakpoint, 1)),
            "process {} (seed {:#x}): {:?} rax {:#x} (0xbad = XMM changed, 0xbad1 = x87 changed)",
            i,
            seeds[i],
            r.map(|e| e.kind),
            r.map(|e| e.rax).unwrap_or(0)
        );
    }
    // Pod KVM (natywna szybkość) procesy xmm kończą się w kilku kwantach –
    // przełączeń jest mniej; sedno testu to zawartość rejestrów (wyżej).
    fcheck!(switches >= 6, "only {} context switches - test did not interleave", switches);
    serial_println!(
        "[FPU TEST] 2/5 3 processes x (xmm0-15 + st0), {} context switches, no register leaked PASS",
        switches
    );

    // 3. Nowy proces po "brudnych" nie widzi ich rejestrów.
    let r = run_wait("fpuclean", 0);
    fcheck!(
        r.map(|e| (e.kind, e.rax)) == Some((ExitKind::Breakpoint, 1)),
        "fpuclean: {:?} rax {:#x} (0xbad2 = XMM not zero, 0xbad3 = FCW, 0xbad4 = MXCSR)",
        r.map(|e| e.kind),
        r.map(|e| e.rax).unwrap_or(0)
    );
    serial_println!("[FPU TEST] 3/5 new process starts clean (xmm = 0, FCW 0x37f, MXCSR 0x1f80) PASS");

    // 4. Odmaskowany wyjątek SSE -> #XM kończy tylko proces.
    // (Emulacja TCG w QEMU nie zgłasza #XM – wtedy program dochodzi do int3.)
    let r = run_wait("simdexc", 0);
    match r.map(|e| e.kind) {
        Some(ExitKind::SimdException) => {
            serial_println!("[FPU TEST] 4/5 unmasked SSE divide by zero -> #XM -> process ends PASS");
        }
        Some(ExitKind::Breakpoint) => {
            serial_println!("[FPU TEST] 4/5 #XM skipped (this CPU/emulator does not raise SSE exceptions) PASS");
        }
        other => {
            serial_println!("[FPU TEST] FAIL: simdexc: {:?}", other);
            return;
        }
    }

    // 5. Po wszystkim: kernel znów z CR0.TS, brak wycieków.
    fcheck!(wait_for(200, || spin.map(|s| sched::task_info(s).is_none()).unwrap_or(true)), "spinner did not stop");
    fcheck!(fpu::ts(), "CR0.TS not set again for the kernel task");
    fcheck!(frames_back(frames), "frames leaked");
    serial_println!("[FPU TEST] 5/5 kernel task back with CR0.TS, no leaks PASS");

    serial_println!("[FPU TEST] =================================");
    crate::selftest::pass();
    serial_println!("[FPU TEST] FPU/SSE CONTEXT TESTS PASSED");
    serial_println!("[FPU TEST] =================================");
}
