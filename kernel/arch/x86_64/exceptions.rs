// M4: obsługa wyjątków CPU.
//
// * #PF – najpierw próbuje mapowania on-demand (memory::handle_page_fault),
//   dopiero potem traktuje fault jako błąd.
// * #BP – nieszkodliwy, wraca do kodu.
// * Reszta – czytelny raport na serialu i zatrzymanie CPU.
//
// Mechanizm "recovery" (RESUME_RIP/RESUME_RSP) istnieje po to, żeby self-test
// mógł sprowokować wyjątek, zobaczyć czy handler go poprawnie złapał
// i wrócić do kodu testu.  Bez uzbrojenia (RESUME_RIP == 0) każdy błąd jest
// śmiertelny.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::idt::{EXCEPTION_VECTORS, IRQ_BASE, IRQ_VECTORS};
#[cfg(selftest)]
use super::gdt::{GDT_ENTRIES, IST_FATAL, KERNEL_CS, KERNEL_DS, TSS_SELECTOR};
#[cfg(selftest)]
use super::idt::{gate_ist, gate_present};
use crate::serial_println;

/// Ramka odłożona na stos przez `isr_common` (kolejność = odwrotność push).
#[repr(C)]
pub struct ExceptionFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error_code: u64,
    // Wkładane przez CPU:
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const NAMES: [&str; EXCEPTION_VECTORS] = [
    "#DE Divide Error",
    "#DB Debug",
    "NMI Non-Maskable Interrupt",
    "#BP Breakpoint",
    "#OF Overflow",
    "#BR Bound Range Exceeded",
    "#UD Invalid Opcode",
    "#NM Device Not Available",
    "#DF Double Fault",
    "Coprocessor Segment Overrun",
    "#TS Invalid TSS",
    "#NP Segment Not Present",
    "#SS Stack-Segment Fault",
    "#GP General Protection Fault",
    "#PF Page Fault",
    "Reserved (15)",
    "#MF x87 Floating-Point",
    "#AC Alignment Check",
    "#MC Machine Check",
    "#XM SIMD Floating-Point",
    "#VE Virtualization",
    "#CP Control Protection",
    "Reserved (22)",
    "Reserved (23)",
    "Reserved (24)",
    "Reserved (25)",
    "Reserved (26)",
    "Reserved (27)",
    "#HV Hypervisor Injection",
    "#VC VMM Communication",
    "#SX Security",
    "Reserved (31)",
];

// ------------------------------------------------------------
// Stan współdzielony z testami
// ------------------------------------------------------------

/// M17b.c: #PF w trakcie obsługi #PF kernela na tym samym CPU (per CPU –
/// różne CPU mogą obsługiwać #PF równocześnie).
static IN_PAGE_FAULT: crate::arch::x86_64::percpu::PerCpu<AtomicBool> = crate::per_cpu!(AtomicBool::new(false));
static BREAKPOINTS: AtomicU64 = AtomicU64::new(0);

static RESUME_RIP: AtomicU64 = AtomicU64::new(0);
static RESUME_RSP: AtomicU64 = AtomicU64::new(0);
static LAST_VECTOR: AtomicU64 = AtomicU64::new(u64::MAX);
static LAST_ERROR: AtomicU64 = AtomicU64::new(0);
static LAST_CR2: AtomicU64 = AtomicU64::new(0);

fn read_cr2() -> u64 {
    let v: u64;
    unsafe {
        asm!("mov {}, cr2", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

fn read_cr3() -> u64 {
    let v: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// Jeśli test uzbroił recovery: zapisuje co się stało i przekierowuje
/// wykonanie na adres wznowienia.
fn try_recover(frame: &mut ExceptionFrame, cr2: u64) -> bool {
    let resume = RESUME_RIP.swap(0, Ordering::SeqCst);
    if resume == 0 {
        return false;
    }

    LAST_VECTOR.store(frame.vector, Ordering::SeqCst);
    LAST_ERROR.store(frame.error_code, Ordering::SeqCst);
    LAST_CR2.store(cr2, Ordering::SeqCst);

    frame.rip = resume;
    let rsp = RESUME_RSP.swap(0, Ordering::SeqCst);
    if rsp != 0 {
        frame.rsp = rsp;
    }
    true
}

// ------------------------------------------------------------
// Dispatch
// ------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "sysv64" fn exception_dispatch(frame: &mut ExceptionFrame) {
    // M17: "stop" od procesora, który wpadł w panic – bez BKL (trzyma go
    // tamten), po prostu zatrzymujemy ten CPU.  NMI w trakcie panic tak samo.
    if frame.vector == super::lapic::HALT_VECTOR as u64
        || (frame.vector == 2 && super::smp::panicking())
    {
        loop {
            unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
        }
    }
    // M17a.b: TLB shootdown – bez BKL (inicjator zwykle go trzyma i czeka
    // na nasze potwierdzenie) i bez żadnych blokad.
    if frame.vector == super::tlb::TLB_VECTOR as u64 {
        super::tlb::on_ipi();
        return;
    }
    // M17: wejście do kernela – Big Kernel Lock (z ring 3 albo z `hlt`
    // procesor go nie trzyma).  Bramki przerwań wyłączyły IF.
    // M17a: watchdog zawieszeń – przed BKL (właśnie BKL może stać).
    if frame.vector == 2 && super::smp::watchdog_nmi(frame.rip, frame.rflags) {
        return;
    }
    // NMI nigdy nie bierze BKL: przychodzi także wtedy, gdy ten CPU sam czeka
    // na BKL (z wyłączonymi przerwaniami) – drugi bilet = zakleszczenie.
    // Niezamówione NMI przy wielu CPU (sprzęt: błąd pamięci, przycisk) –
    // raport bez BKL i powrót.
    if frame.vector == 2 && super::smp::active() {
        crate::serial_println!("[NMI] unexpected NMI on CPU {} at {:#x}", super::cpu::id(), frame.rip);
        return;
    }
    if frame.vector == IRQ_BASE as u64 {
        crate::time::pit_tick_early();
    }
    if frame.vector == super::lapic::TIMER_VECTOR as u64 || frame.vector == IRQ_BASE as u64 {
        super::smp::watchdog_tick(frame.rip);
    }
    // M17a: czy przerwany kontekst trzymał BKL (kod kernela bez BKL – ścieżki
    // zdjęte spod BKL, bkl::unlocked – nie trzyma).
    let had_bkl = crate::sched::bkl::held();
    let from_kernel = frame.cs & 3 == 0;
    // M17a.g: osobne miejsce w statystyce BKL dla rodzaju wejścia i tego,
    // co zostało przerwane (proces / kernel) – `cpus`: "BKL by site".
    {
        use crate::sched::bkl::tag;
        let user = frame.cs & 3 == 3;
        let v = frame.vector;
        let t: &'static &'static str = if v == IRQ_BASE as u64 {
            if user { &tag::IRQ_PIT_USER } else { &tag::IRQ_PIT_KERNEL }
        } else if v == super::lapic::TIMER_VECTOR as u64 {
            if user { &tag::IRQ_TIMER_USER } else { &tag::IRQ_TIMER_KERNEL }
        } else if v == super::lapic::RESCHED_VECTOR as u64 {
            if user { &tag::IRQ_RESCHED_USER } else { &tag::IRQ_RESCHED_KERNEL }
        } else if v >= 32 {
            if user { &tag::IRQ_OTHER_USER } else { &tag::IRQ_OTHER_KERNEL }
        } else if user {
            &tag::EXC_USER
        } else {
            &tag::EXC_KERNEL
        };
        // M17a.g4: tick zegara (PIT, LAPIC) i IPI przełączenia bez BKL – ich
        // praca to atomiki, blokada schedulera, watchdog i hook ticku
        // (odpytywanie klawiatury bierze BKL tylko, gdy jest wolny – time.rs).
        // Legion v0.17.12: ~38 s z 46 s czekania na BKL to te przerwania.
        // M17b.d: #PF procesu (leniwe strony) – też bez BKL.
        let no_bkl = v == IRQ_BASE as u64
            || v == super::lapic::TIMER_VECTOR as u64
            || v == super::lapic::RESCHED_VECTOR as u64
            || (v == 14 && user);
        if !no_bkl {
            crate::sched::bkl::acquire_if_needed_tagged(t);
        }
    }
    // M17a: przerwanie sprzętowe (wektory >= 32) – do irq::after_interrupt
    // ten CPU jest "w przerwaniu" (SpinLock tu zabroniony, IrqSpinLock tak).
    let hw = frame.vector >= 32;
    if hw {
        super::cpu::set_in_interrupt(true);
        super::cpu::set_irq_had_bkl(had_bkl);
    }
    dispatch_inner(frame);
    if hw {
        super::cpu::set_in_interrupt(false);
    }
    // Powrót do procesu (ring 3) = wyjście z kernela: oddajemy BKL.  Ramka
    // mogła się zmienić (wyjątek procesu -> powrót do trampoliny w ring 0)
    // albo należeć do innego zadania niż na wejściu (wywłaszczenie) – liczy
    // się, dokąd wracamy teraz.  M17a: powrót do kodu kernela, który działał
    // bez BKL – też oddajemy (stan BKL należy do przerwanego kontekstu; po
    // wywłaszczeniu i powrocie, także na innym CPU, to nadal ten sam kontekst).
    // Wyjątek z ring 3 przekierowany do kernela (koniec procesu) wraca do
    // kodu, który BKL potrzebuje – dlatego `from_kernel`.
    if (frame.cs & 3 == 3 || (from_kernel && !had_bkl)) && crate::sched::bkl::held() {
        crate::sched::bkl::release();
    }
}

fn dispatch_inner(frame: &mut ExceptionFrame) {
    // M13a: wyjątek procesu (ring 3) kończy tylko proces – poza NMI, #DF i
    // #MC, które dotyczą całej maszyny.
    if frame.cs & 3 == 3
        && (frame.vector as usize) < EXCEPTION_VECTORS
        && !matches!(frame.vector, 2 | 8 | 18)
    {
        let cr2 = if frame.vector == 14 { read_cr2() } else { 0 };
        crate::user::handle_exception(frame, cr2);
        return;
    }
    match frame.vector {
        // M5: przerwania sprzętowe z PIC-a.
        v if v >= IRQ_BASE as u64 && v < (IRQ_BASE + IRQ_VECTORS) as u64 => {
            super::irq::dispatch(frame);
        }
        // M16b: MSI/MSI-X (EOI do LAPIC) i "spurious" LAPIC (bez EOI).
        v if v >= super::msi::MSI_BASE as u64 && v < (super::msi::MSI_BASE + super::msi::MSI_VECTORS) as u64 => {
            super::msi::dispatch(frame);
        }
        0xFF => {}
        // M17: timer LAPIC procesora AP i IPI "przełącz zadanie".
        v if v == super::lapic::TIMER_VECTOR as u64 => {
            let t0 = crate::user::prof::start();
            super::lapic::eoi();
            super::smp::on_ap_timer();
            crate::user::prof::stop(crate::user::prof::IRQ_TIMER, t0);
            super::irq::after_interrupt(frame);
        }
        v if v == super::lapic::RESCHED_VECTOR as u64 => {
            let t0 = crate::user::prof::start();
            super::lapic::eoi();
            super::smp::on_resched_ipi();
            crate::user::prof::stop(crate::user::prof::IRQ_RESCHED, t0);
            super::irq::after_interrupt(frame);
        }
        3 => {
            BREAKPOINTS.fetch_add(1, Ordering::SeqCst);
        }
        14 => page_fault(frame),
        // M17b.c: #DF (IST) – zwykle przepełnienie stosu kernela: #PF bez IST nie
        // zmieścił ramki na stosie.  CR2 = adres, którego #PF dotyczył.
        8 => {
            let cr2 = read_cr2();
            if !try_recover(frame, cr2) {
                fatal(frame, Some(cr2), "double fault (kernel stack overflow if CR2 is a guard page)");
            }
        }
        7 => fatal(frame, None, "#NM in the kernel: FPU/SSE instruction while CR0.TS = 1 (the kernel must stay soft-float)"),
        _ => {
            if !try_recover(frame, 0) {
                fatal(frame, None, "unhandled CPU exception");
            }
        }
    }
}

fn page_fault(frame: &mut ExceptionFrame) {
    let cr2 = read_cr2();

    // #PF kernela w trakcie obsługi #PF kernela (ten sam CPU) to błąd kernela
    // (M17b.c: bez IST ramki by się nie nadpisały, ale handler ma być prosty).
    let me = super::cpu::id();
    if IN_PAGE_FAULT[me].swap(true, Ordering::SeqCst) {
        fatal(frame, Some(cr2), "nested page fault inside the page fault handler");
    }

    if crate::memory::handle_page_fault(cr2, frame.error_code) {
        IN_PAGE_FAULT[me].store(false, Ordering::SeqCst);
        return;
    }

    IN_PAGE_FAULT[me].store(false, Ordering::SeqCst);

    if try_recover(frame, cr2) {
        return;
    }

    fatal(frame, Some(cr2), "unrecoverable page fault");
}

// ------------------------------------------------------------
// Raport błędu
// ------------------------------------------------------------

fn describe_page_fault(error: u64) {
    serial_println!(
        "[EXC]   {} | {} | {}{}{}",
        if error & 1 != 0 { "protection violation" } else { "page not present" },
        if error & 2 != 0 { "write" } else { "read" },
        if error & 4 != 0 { "user mode" } else { "kernel mode" },
        if error & 8 != 0 { " | reserved bit set" } else { "" },
        if error & 16 != 0 { " | instruction fetch" } else { "" },
    );
}

fn describe_selector_error(error: u64) {
    let table = match (error >> 1) & 3 {
        0 => "GDT",
        1 | 3 => "IDT",
        _ => "LDT",
    };
    serial_println!(
        "[EXC]   selector index {} in {}{}",
        error >> 3,
        table,
        if error & 1 != 0 { " (external event)" } else { "" }
    );
}

fn fatal(frame: &ExceptionFrame, cr2: Option<u64>, note: &str) -> ! {
    let vector = frame.vector as usize;
    let name = if vector < EXCEPTION_VECTORS { NAMES[vector] } else { "unknown" };

    serial_println!("[EXC] ==========================================");
    serial_println!("[EXC] KERNEL EXCEPTION: {} (vector {})", name, frame.vector);
    serial_println!("[EXC] {}", note);
    crate::sched::with_current_name(|id, name| {
        serial_println!("[EXC] task: {} '{}'", id, name);
    });
    serial_println!("[EXC] error code = {:#x}", frame.error_code);

    match vector {
        14 => describe_page_fault(frame.error_code),
        10 | 11 | 12 | 13 if frame.error_code != 0 => describe_selector_error(frame.error_code),
        _ => {}
    }

    if let Some(address) = cr2 {
        serial_println!("[EXC] CR2 (fault address) = {:#x}", address);
        if crate::memory::is_stack_guard(address) {
            serial_println!("[EXC] -> KERNEL STACK OVERFLOW (hit the guard page below the stack)");
        }
    }
    serial_println!("[EXC] CR3 = {:#x}", read_cr3());
    serial_println!(
        "[EXC] RIP = {:#x}  CS = {:#x}  RFLAGS = {:#x}",
        frame.rip,
        frame.cs,
        frame.rflags
    );
    serial_println!("[EXC] RSP = {:#x}  SS = {:#x}", frame.rsp, frame.ss);
    serial_println!(
        "[EXC] RAX={:#018x} RBX={:#018x} RCX={:#018x} RDX={:#018x}",
        frame.rax, frame.rbx, frame.rcx, frame.rdx
    );
    serial_println!(
        "[EXC] RSI={:#018x} RDI={:#018x} RBP={:#018x} R8 ={:#018x}",
        frame.rsi, frame.rdi, frame.rbp, frame.r8
    );
    serial_println!(
        "[EXC] R9 ={:#018x} R10={:#018x} R11={:#018x} R12={:#018x}",
        frame.r9, frame.r10, frame.r11, frame.r12
    );
    serial_println!(
        "[EXC] R13={:#018x} R14={:#018x} R15={:#018x}",
        frame.r13, frame.r14, frame.r15
    );
    serial_println!("[EXC] System halted.");
    #[cfg(selftest)]
    crate::selftest::exit_if_autotest(false);

    loop {
        unsafe {
            asm!("cli", "hlt");
        }
    }
}

// ------------------------------------------------------------
// TEST (tylko build z --cfg selftest)
// ------------------------------------------------------------

#[cfg(selftest)]
macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[ARCH TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

#[cfg(selftest)]
fn reset_last() {
    LAST_VECTOR.store(u64::MAX, Ordering::SeqCst);
    LAST_ERROR.store(0, Ordering::SeqCst);
    LAST_CR2.store(u64::MAX, Ordering::SeqCst);
}

#[cfg(selftest)]
fn trigger_ud() {
    unsafe {
        asm!(
            "lea {t}, [rip + 2f]",
            "mov [{slot}], {t}",
            "ud2",
            "2:",
            t = out(reg) _,
            slot = in(reg) RESUME_RIP.as_ptr(),
        );
    }
}

#[cfg(selftest)]
fn trigger_de() {
    unsafe {
        asm!(
            "lea {t}, [rip + 2f]",
            "mov [{slot}], {t}",
            "xor edx, edx",
            "mov eax, 1",
            "xor ecx, ecx",
            "div ecx",
            "2:",
            t = out(reg) _,
            slot = in(reg) RESUME_RIP.as_ptr(),
            out("rax") _,
            out("rdx") _,
            out("rcx") _,
        );
    }
}

// `int 0x7f` przy nieobecnej bramce IDT daje #GP z kodem błędu 0x7f*8 + 2.
// (0x21 od M5 jest zajęte przez IRQ1.)
#[cfg(selftest)]
const UNUSED_VECTOR: u64 = 0x7f;
#[cfg(selftest)]
fn trigger_gp() {
    unsafe {
        asm!(
            "lea {t}, [rip + 2f]",
            "mov [{slot}], {t}",
            "int 0x7f",
            "2:",
            t = out(reg) _,
            slot = in(reg) RESUME_RIP.as_ptr(),
        );
    }
}

/// Wynik nieudanego odczytu z `probe_read`.
#[cfg(selftest)]
#[allow(dead_code)]
pub struct Fault {
    pub vector: u64,
    pub error: u64,
    pub cr2: u64,
}

/// Próbuje odczytać bajt spod `address`.  Jeśli CPU zgłosi wyjątek (i handler
/// nie naprawi go np. przez mapowanie on-demand), zwraca jego opis zamiast
/// zatrzymywać system.  `None` = odczyt się udał.
#[cfg(selftest)]
pub fn probe_read(address: u64) -> Option<Fault> {
    reset_last();
    unsafe {
        asm!(
            "lea {t}, [rip + 2f]",
            "mov [{slot}], {t}",
            "mov {v}, qword ptr [{addr}]",
            "2:",
            t = out(reg) _,
            v = out(reg) _,
            slot = in(reg) RESUME_RIP.as_ptr(),
            addr = in(reg) address,
        );
    }
    // Odczyt się udał -> handler nie zdjął uzbrojenia.
    RESUME_RIP.store(0, Ordering::SeqCst);

    let vector = LAST_VECTOR.load(Ordering::SeqCst);
    if vector == u64::MAX {
        None
    } else {
        Some(Fault {
            vector,
            error: LAST_ERROR.load(Ordering::SeqCst),
            cr2: LAST_CR2.load(Ordering::SeqCst),
        })
    }
}

/// M13a: próbuje WYKONAĆ kod pod `address` (`call`).  Z SMEP skok kernela
/// na stronę użytkownika daje #PF – wtedy zwraca opis błędu.  `None` = kod
/// się wykonał (musi kończyć się `ret`).
#[cfg(selftest)]
pub fn probe_exec(address: u64) -> Option<Fault> {
    reset_last();
    unsafe {
        asm!(
            "mov [{rsp_slot}], rsp",
            "lea rax, [rip + 2f]",
            "mov [{rip_slot}], rax",
            "call {addr}",
            "2:",
            out("rax") _,
            rsp_slot = in(reg) RESUME_RSP.as_ptr(),
            rip_slot = in(reg) RESUME_RIP.as_ptr(),
            addr = in(reg) address,
            clobber_abi("C"),
        );
    }
    RESUME_RIP.store(0, Ordering::SeqCst);
    RESUME_RSP.store(0, Ordering::SeqCst);
    let vector = LAST_VECTOR.load(Ordering::SeqCst);
    if vector == u64::MAX {
        None
    } else {
        Some(Fault {
            vector,
            error: LAST_ERROR.load(Ordering::SeqCst),
            cr2: LAST_CR2.load(Ordering::SeqCst),
        })
    }
}

/// Ustawia RSP na niezamapowany adres i robi `int3`.  CPU nie może zapisać
/// ramki wyjątku na takim stosie, więc dostajemy #PF; M17b.c: #PF nie ma IST,
/// więc też nie zapisze ramki -> #DF, który działa na stosie IST.
#[cfg(selftest)]
fn trigger_bad_stack(bad_rsp: u64) {
    unsafe {
        asm!(
            "mov {t}, rsp",
            "mov [{rsp_slot}], {t}",
            "lea {t}, [rip + 2f]",
            "mov [{rip_slot}], {t}",
            "mov rsp, {bad}",
            "int3",
            "2:",
            t = out(reg) _,
            rsp_slot = in(reg) RESUME_RSP.as_ptr(),
            rip_slot = in(reg) RESUME_RIP.as_ptr(),
            bad = in(reg) bad_rsp,
        );
    }
}

#[cfg(selftest)]
pub fn self_test() {
    serial_println!("[ARCH TEST] Starting exception tests...");
    crate::selftest::begin();

    // 1. Tablice załadowane.
    let cs: u16;
    let ss: u16;
    let tr: u16;
    unsafe {
        asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
        asm!("mov {0:x}, ss", out(reg) ss, options(nomem, nostack, preserves_flags));
        asm!("str {0:x}", out(reg) tr, options(nomem, nostack, preserves_flags));
    }
    let mut gdtr = [0u8; 10];
    let mut idtr = [0u8; 10];
    unsafe {
        asm!("sgdt [{}]", in(reg) gdtr.as_mut_ptr());
        asm!("sidt [{}]", in(reg) idtr.as_mut_ptr());
    }
    let gdt_limit = u16::from_le_bytes([gdtr[0], gdtr[1]]);
    let idt_limit = u16::from_le_bytes([idtr[0], idtr[1]]);

    check!(cs == KERNEL_CS, "CS = {:#x}", cs);
    check!(ss == KERNEL_DS, "SS = {:#x}", ss);
    check!(tr == TSS_SELECTOR, "TR = {:#x}", tr);
    check!(gdt_limit as usize == GDT_ENTRIES * 8 - 1, "GDT limit = {}", gdt_limit);
    check!(idt_limit == 4095, "IDT limit = {}", idt_limit);
    serial_println!("[ARCH TEST] 1/8 GDT + TSS + IDT loaded PASS");

    // 2. Bramki i IST.
    for v in 0..EXCEPTION_VECTORS {
        check!(gate_present(v), "gate {} not present", v);
    }
    check!(!gate_present(UNUSED_VECTOR as usize), "gate {:#x} unexpectedly present", UNUSED_VECTOR);
    check!(gate_ist(8) == 1, "#DF IST = {}", gate_ist(8));
    check!(gate_ist(2) == 2, "NMI IST = {}", gate_ist(2));
    check!(gate_ist(18) == 3, "#MC IST = {}", gate_ist(18));
    check!(gate_ist(13) == IST_FATAL, "#GP IST = {}", gate_ist(13));
    check!(gate_ist(6) == IST_FATAL, "#UD IST = {}", gate_ist(6));
    check!(gate_ist(14) == 0, "#PF must not use IST (M17b.c), IST = {}", gate_ist(14));
    check!(gate_ist(3) == 0 && gate_ist(0) == 0, "#BP / #DE should not use IST");
    // M16: niezmiennik irq::dispatch -> preempt() -> kill_from_interrupt –
    // IRQ zawsze na stosie kernela przerwanego zadania (idt.rs).
    for v in super::idt::IRQ_BASE..super::idt::IRQ_BASE + super::pic::IRQ_COUNT {
        check!(gate_ist(v) == 0, "IRQ vector {:#x} uses IST {} (must be 0)", v, gate_ist(v));
    }
    for v in super::msi::MSI_BASE..super::msi::MSI_BASE + super::msi::MSI_VECTORS {
        check!(gate_present(v) && gate_ist(v) == 0, "MSI vector {:#x}: present {} IST {}", v, gate_present(v), gate_ist(v));
    }
    serial_println!("[ARCH TEST] 2/8 IDT gates + IST assignment (IRQ vectors without IST) PASS");

    // 3. #BP wraca do kodu.
    let before = BREAKPOINTS.load(Ordering::SeqCst);
    unsafe {
        asm!("int3");
    }
    check!(BREAKPOINTS.load(Ordering::SeqCst) == before + 1, "#BP not counted");
    serial_println!("[ARCH TEST] 3/8 #BP returns to caller PASS");

    // 4. #UD.
    reset_last();
    trigger_ud();
    check!(LAST_VECTOR.load(Ordering::SeqCst) == 6, "#UD vector = {}", LAST_VECTOR.load(Ordering::SeqCst));
    serial_println!("[ARCH TEST] 4/8 #UD (ud2) caught PASS");

    // 5. #DE.
    reset_last();
    trigger_de();
    check!(LAST_VECTOR.load(Ordering::SeqCst) == 0, "#DE vector = {}", LAST_VECTOR.load(Ordering::SeqCst));
    serial_println!("[ARCH TEST] 5/8 #DE (div by zero) caught PASS");

    // 6. #GP z kodem błędu.
    reset_last();
    trigger_gp();
    check!(LAST_VECTOR.load(Ordering::SeqCst) == 13, "#GP vector = {}", LAST_VECTOR.load(Ordering::SeqCst));
    check!(
        LAST_ERROR.load(Ordering::SeqCst) == UNUSED_VECTOR * 8 + 2,
        "#GP error code = {:#x}",
        LAST_ERROR.load(Ordering::SeqCst)
    );
    serial_println!("[ARCH TEST] 6/8 #GP (error code {:#x}) caught PASS", LAST_ERROR.load(Ordering::SeqCst));

    // 7. #PF: odczyt z niezamapowanego adresu (poza obszarem on-demand).
    //    Uwaga: na tym etapie działają jeszcze tablice UEFI, w których
    //    adres 0 jest zamapowany – dlatego używamy adresu daleko poza RAM-em.
    //    Pułapka na null (nasze tablice) jest sprawdzana w teście on-demand.
    let unmapped: u64 = 0x0000_7fff_fe00_0000;
    let fault = probe_read(unmapped);
    check!(fault.is_some(), "read of {:#x} did not fault", unmapped);
    let fault = fault.unwrap();
    check!(fault.vector == 14, "#PF vector = {}", fault.vector);
    check!(fault.cr2 == unmapped, "CR2 = {:#x}", fault.cr2);
    check!(fault.error & 1 == 0, "P bit set for not-present page");
    check!(fault.error & 2 == 0, "W bit set for a read");
    serial_println!("[ARCH TEST] 7/8 #PF (unmapped read, CR2 exact) caught PASS");

    // 8. Wyjątek na nieużywalnym stosie – działa tylko dzięki IST (#DF).
    //    M10: "nieużywalny stos" = strona-strażnik pod stosem kernela, czyli
    //    dokładnie to, co dzieje się przy przepełnieniu stosu.
    let layout = crate::memory::kernel_layout();
    let bad: u64 = layout.stack_bottom();
    reset_last();
    trigger_bad_stack(bad);
    let cr2 = LAST_CR2.load(Ordering::SeqCst);
    let rsp_now: u64;
    unsafe {
        asm!("mov {}, rsp", out(reg) rsp_now, options(nomem, nostack, preserves_flags));
    }
    check!(LAST_VECTOR.load(Ordering::SeqCst) == 8, "vector = {} (want #DF)", LAST_VECTOR.load(Ordering::SeqCst));
    check!(cr2 < bad && cr2 + 64 >= bad, "CR2 = {:#x} not near bad RSP", cr2);
    check!(crate::memory::is_stack_guard(cr2), "CR2 = {:#x} not in the guard page", cr2);
    check!(
        rsp_now > layout.stack_bottom() && rsp_now <= layout.stack_top,
        "RSP not restored: {:#x}",
        rsp_now
    );
    serial_println!("[ARCH TEST] 8/8 stack overflow into the guard page: #PF -> #DF handled via IST PASS");

    serial_println!("[ARCH TEST] =================================");
    crate::selftest::pass();
    serial_println!("[ARCH TEST] EXCEPTION TESTS PASSED");
    serial_println!("[ARCH TEST] =================================");
}
