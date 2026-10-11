// M17: SMP – uruchamianie pozostałych rdzeni (AP, "application processors").
//
// Po starcie działa tylko procesor startowy (BSP).  Resztę budzi sekwencja
// INIT – SIPI – SIPI wysłana przez Local APIC.  SIPI podaje stronę pamięci
// (adres < 1 MiB), od której AP zaczyna – w 16-bitowym trybie rzeczywistym,
// jak procesor z 1978 roku.  Dlatego potrzebna jest trampolina:
//
//   1. tryb rzeczywisty (CS = strona trampoliny): GDT trampoliny, CR4.PAE,
//      CR3 = tymczasowa PML4 (< 4 GiB, bo ładowana 32-bitowym rejestrem),
//      EFER.LME (+ NXE), CR0.PG|PE naraz – od razu tryb 64-bit (bez
//      przystanku w trybie chronionym), daleki skok do kodu 64-bit,
//   2. 64 bity, wciąż na stronie trampoliny (mapa 1:1 pierwszych 2 MiB
//      w tymczasowej PML4): stos AP i skok do `ap_entry` w kernelu
//      (górna połowa – tymczasowa PML4 ma skopiowane wpisy kernela),
//   3. `ap_entry` (Rust): CR3 kernela, numer CPU (TSC_AUX), Big Kernel
//      Lock, własna GDT/TSS (IST), IDT, FPU/SMEP/SMAP/SYSCALL, PAT, LAPIC
//      + timer LAPIC (100 Hz), "online" – i pętla idle.
//
// Stan kernela (scheduler, heap, VFS) chroni Big Kernel Lock (sched/bkl.rs):
// kod kernela wykonuje jeden CPU naraz, procesy w ring 3 działają naprawdę
// równolegle.  TLB: bez IPI "shootdown" – przy wielu CPU każde przełączenie
// zadania przeładowuje CR3 (pełny flush), a heap nie oddaje stron (heap.rs).
// Procesy są jednowątkowe, więc ich mapowania żyją w TLB tylko jednego CPU.
//
// Przerwania urządzeń (I/O APIC, MSI) idą do BSP; tick PIT (BSP) budzi
// śpiące zadania; bezczynny AP budzi IPI RESCHED_VECTOR (sched::kick).

use core::arch::global_asm;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use super::cpu::{self, MAX_CPUS};
use super::{clock, lapic};
use crate::serial_println;

static ONLINE: crate::arch::x86_64::percpu::PerCpu<AtomicBool> = crate::per_cpu!(AtomicBool::new(false));
static APIC_IDS: crate::arch::x86_64::percpu::PerCpu<AtomicU32> = crate::per_cpu!(AtomicU32::new(0));
static TIMER_TICKS: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static RESCHED_IPIS: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static COUNT: AtomicUsize = AtomicUsize::new(1);
static ACTIVE: AtomicBool = AtomicBool::new(false);
static PANICKING: AtomicBool = AtomicBool::new(false);

/// Czy CPU `c` działa.
pub fn online(c: usize) -> bool {
    c < MAX_CPUS && ONLINE[c].load(Ordering::Acquire)
}

/// Liczba działających procesorów.
pub fn online_count() -> usize {
    COUNT.load(Ordering::Relaxed)
}

/// Czy działa więcej niż jeden CPU.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

pub fn panicking() -> bool {
    PANICKING.load(Ordering::Relaxed)
}

/// APIC ID procesora `c`.
pub fn apic_id(c: usize) -> u32 {
    APIC_IDS[c % MAX_CPUS].load(Ordering::Relaxed)
}

/// (ticki timera LAPIC, odebrane IPI "resched") procesora `c` – `cpus`, testy.
pub fn counters(c: usize) -> (u64, u64) {
    (TIMER_TICKS[c % MAX_CPUS].load(Ordering::Relaxed), RESCHED_IPIS[c % MAX_CPUS].load(Ordering::Relaxed))
}

/// Budzi CPU `c` (IPI) – sched::kick ustawił mu NEED_RESCHED.
pub fn send_resched(c: usize) {
    if online(c) && c != cpu::id() {
        lapic::send_ipi(apic_id(c), lapic::RESCHED_VECTOR);
    }
}

/// Z wektora TIMER_VECTOR (AP, co AP_TICK_MS).
pub fn on_ap_timer() {
    TIMER_TICKS[cpu::id()].fetch_add(1, Ordering::Relaxed);
    crate::sched::ap_tick(lapic::AP_TICK_MS);
}

/// Z wektora RESCHED_VECTOR (przełączenie zrobi irq::after_interrupt).
pub fn on_resched_ipi() {
    RESCHED_IPIS[cpu::id()].fetch_add(1, Ordering::Relaxed);
}

// ------------------------------------------------------------
// M17a: watchdog zawieszeń (jak "NMI watchdog" w Linuksie)
// ------------------------------------------------------------
//
// Zawieszenie = zegar PIT (przerwanie na CPU 0) przestaje iść przez
// WATCHDOG_MS.  Tick liczony jest przed BKL (time::pit_tick_early), więc to
// znaczy: CPU 0 nie dostaje przerwań zegara (wyłączone przerwania, zawieszony
// CPU) – a nie tylko "przerwanie czeka w kolejce do BKL".  Sprawdza to każdy CPU, który długo czeka – na Big Kernel
// Lock albo na spinlock (`watchdog_poll` w ich pętlach; przy zawieszeniu to
// właśnie tam stoją pozostałe CPU) – oraz tick timera LAPIC (przed BKL).
// Pierwszy, który zauważy, wysyła NMI do wszystkich (dochodzi także przy
// wyłączonych przerwaniach): każdy CPU zapisuje swój RIP, a zgłaszający
// wypisuje stan BKL, bilety i adresy (addr2line -e build/kernel.elf <adres>).
// Raport raz na zawieszenie (na dany numer ticku); pełne – pierwsze 3.


/// Próg zawieszenia (jak „soft lockup” w Linuksie: ~10–20 s).  Czas mierzy
/// clock.rs (HPET – wspólny dla CPU; TSC tylko bez HPET).
const WATCHDOG_MS: u64 = 10_000;
static LAST_RIP: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static NMI_RIP: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static NMI_FLAGS: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
/// NMI zamówione przez watchdog dla danego CPU (kasuje je ten CPU w handlerze).
/// Per CPU, a nie jedna flaga z oknem czasowym: NMI, które dojdzie po
/// raporcie, też musi zostać rozpoznane (inaczej poszłoby zwykłą ścieżką
/// i chciało BKL, na który ten CPU już czeka – zakleszczenie z samym sobą).
static NMI_EXPECTED: crate::arch::x86_64::percpu::PerCpu<AtomicBool> = crate::per_cpu!(AtomicBool::new(false));
/// Per CPU: ostatnio widziany tick PIT i znacznik czasu (clock.rs) chwili,
/// gdy go zobaczył.  Tylko dane własnego CPU – wspólna para (tick, czas)
/// pisana przez wiele CPU rozjeżdżała się i dawała fałszywe "zegar stoi".
static WD_TICK: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(u64::MAX));
static WD_STAMP: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static WD_REPORTED_TICK: AtomicU64 = AtomicU64::new(u64::MAX);
static WD_REPORTS: AtomicU64 = AtomicU64::new(0);
/// Raporty już wypisane (testy czekają na wypisanie, nie na początek raportu).
static WD_DONE: AtomicU64 = AtomicU64::new(0);
static NMI_STAMP: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
/// Pełnych raportów najwyżej tyle na uruchomienie (potem jedna linia).
const WD_FULL_REPORTS: u64 = 3;

/// Z exception_dispatch, przed BKL: tick zegara (PIT na BSP, LAPIC na AP).
pub fn watchdog_tick(rip: u64) {
    LAST_RIP[cpu::id()].store(rip, Ordering::Relaxed);
    watchdog_poll();
}

/// Sprawdza, czy zegar stoi (woła się z pętli czekania; tanie).
pub fn watchdog_poll() {
    if !active() {
        return;
    }
    let me = cpu::id();
    let t = crate::time::ticks();
    if t != WD_TICK[me].load(Ordering::Relaxed) {
        WD_TICK[me].store(t, Ordering::Relaxed);
        WD_STAMP[me].store(clock::stamp(), Ordering::Relaxed);
        return;
    }
    if clock::elapsed_us(WD_STAMP[me].load(Ordering::Relaxed)) < WATCHDOG_MS * 1000 {
        return;
    }
    // Jeden raport na zawieszenie (pierwszy CPU, który to zobaczy).
    let prev = WD_REPORTED_TICK.load(Ordering::Relaxed);
    if prev == t || WD_REPORTED_TICK.compare_exchange(prev, t, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        return;
    }
    watchdog_report(t);
}

/// Z exception_dispatch: NMI wysłane przez watchdog (bez BKL).  `true` =
/// obsłużone.
pub fn watchdog_nmi(rip: u64, rflags: u64) -> bool {
    if !NMI_EXPECTED[cpu::id()].swap(false, Ordering::AcqRel) {
        return false;
    }
    NMI_FLAGS[cpu::id()].store(rflags, Ordering::Relaxed);
    NMI_STAMP[cpu::id()].store(clock::stamp(), Ordering::Relaxed);
    NMI_RIP[cpu::id()].store(rip, Ordering::Relaxed);
    true
}

/// Ile raportów zawieszenia było (testy).
#[allow(dead_code)]
pub fn watchdog_reports() -> u64 {
    WD_DONE.load(Ordering::Acquire)
}

#[cold]
fn watchdog_report(tick: u64) {
    let me = cpu::id();
    lockup_dump(format_args!("PIT clock stuck at tick {} for {} ms (seen by CPU {})", tick, WATCHDOG_MS, me));
}

/// M17a: CPU czeka na Big Kernel Lock dłużej niż BKL_WAIT_REPORT_MS (z
/// bkl::acquire, zegar clock.rs).  Zegar może przy tym iść (tick liczony
/// przed BKL), więc samo "zegar stoi" tego nie złapie: zagłodzenie albo
/// bardzo wolne przekazywanie BKL.
pub const BKL_WAIT_REPORT_MS: u64 = 10_000;

#[cold]
pub fn bkl_wait_report(ticket: u32, waited_ms: u64) {
    if !active() {
        return;
    }
    lockup_dump(format_args!("CPU {} waits {} ms for the Big Kernel Lock (ticket {})", cpu::id(), waited_ms, ticket));
}

/// Pełny raport: nagłówek, stan BKL, NMI do pozostałych CPU (RIP, IF,
/// czas odpowiedzi), licznik wywłaszczania i spinlocki każdego CPU.
#[cold]
fn lockup_dump(what: core::fmt::Arguments) {
    let n = WD_REPORTS.fetch_add(1, Ordering::Relaxed) + 1;
    let me = cpu::id();
    if n > WD_FULL_REPORTS {
        crate::serial_println!("[WATCHDOG] {} - report #{}", what, n);
        WD_DONE.fetch_add(1, Ordering::Release);
        return;
    }
    let sent = clock::stamp();
    for r in NMI_RIP.iter() {
        r.store(0, Ordering::Relaxed);
    }
    for c in 0..MAX_CPUS {
        if c != me && online(c) {
            NMI_EXPECTED[c].store(true, Ordering::SeqCst);
        }
    }
    lapic::send_nmi_others();
    while clock::elapsed_us(sent) < 200_000 {
        super::tlb::poll_from_wait();
        core::hint::spin_loop();
    }
    let (next, serving, owner) = crate::sched::bkl::state();
    // Bez blokad konsoli – stan i tak jest zepsuty.
    crate::serial_println!(
        "[WATCHDOG] {}; BKL: next {} serving {} owner CPU {}",
        what,
        next,
        serving,
        owner as i64 - 1
    );
    if let Some((f, l, held)) = crate::sched::bkl::owner_site() {
        crate::serial_println!(
            "[WATCHDOG]   BKL taken at {}:{}, held for {} ms",
            f,
            l,
            held
        );
    }
    for c in 0..MAX_CPUS {
        if online(c) {
            crate::serial_println!(
                "[WATCHDOG]   CPU {}: preempt {}, spinlocks {}, in interrupt {}, current task {:?}",
                c,
                cpu::preempt_count_of(c),
                crate::sched::spin::held_count_of(c),
                cpu::in_interrupt_of(c),
                crate::sched::current_id_on(c)
            );
            let rip = NMI_RIP[c].load(Ordering::Relaxed);
            // Po ilu us CPU obsłużył NMI (wspólny zegar clock.rs): na
            // sprzęcie mikrosekundy; dużo więcej = CPU się nie wykonywał.
            let lat = if rip == 0 { 0 } else { clock::diff_us(sent, NMI_STAMP[c].load(Ordering::Relaxed)) };
            crate::serial_println!(
                "[WATCHDOG]   CPU {}: NMI answered after {} us{}",
                c,
                lat,
                if clock::hpet() { "" } else { " (TSC - may differ between CPUs)" }
            );
            crate::serial_println!(
                "[WATCHDOG]   CPU {}: BKL ticket {:?}, NMI rip {:#x} IF={}, last timer rip {:#x}{}",
                c,
                crate::sched::bkl::waiting_ticket(c),
                rip,
                if rip == 0 { '?' } else if NMI_FLAGS[c].load(Ordering::Relaxed) & (1 << 9) != 0 { '1' } else { '0' },
                LAST_RIP[c].load(Ordering::Relaxed),
                if c == me { " (reporter)" } else { "" }
            );
        }
    }
    WD_DONE.fetch_add(1, Ordering::Release);
}

/// Panic: zatrzymuje pozostałe procesory (żeby nie pisały po ekranie ani
/// nie psuły stanu, który właśnie raportujemy).
pub fn halt_others() {
    if !PANICKING.swap(true, Ordering::SeqCst) && active() {
        lapic::send_ipi_others(lapic::HALT_VECTOR);
    }
}

// ------------------------------------------------------------
// Trampolina (kopiowana pod adres < 1 MiB)
// ------------------------------------------------------------

global_asm!(r#"
    .section .text
    .balign 16
    .global ap_tramp_start
ap_tramp_start:
    .code16
    cli
    cld
    movw %cs, %ax
    movw %ax, %ds
    lgdtl (.Ltr_gdtr - ap_tramp_start)
    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4
    movl (.Ltr_cr3 - ap_tramp_start), %eax
    movl %eax, %cr3
    movl $0xC0000080, %ecx
    rdmsr
    orl (.Ltr_efer - ap_tramp_start), %eax
    wrmsr
    movl %cr0, %eax
    andl $0x9FFFFFFF, %eax
    orl $0x80000001, %eax
    movl %eax, %cr0
    ljmpl *(.Ltr_far - ap_tramp_start)

    .code64
.Ltr_long:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    xorw %ax, %ax
    movw %ax, %fs
    movw %ax, %gs
    movq .Ltr_stack(%rip), %rsp
    movq .Ltr_cpu(%rip), %rdi
    movq .Ltr_entry(%rip), %rax
    pushq $0
    jmpq *%rax

    .balign 8
    .global ap_tramp_data
ap_tramp_data:
    .quad 0
    .quad 0x00AF9A000000FFFF
    .quad 0x00CF92000000FFFF
.Ltr_gdtr:
    .word 23
    .long 0
.Ltr_far:
    .long 0
    .word 0x08
    .long 0
.Ltr_cr3:
    .long 0
.Ltr_efer:
    .long 0
.Ltr_stack:
    .quad 0
.Ltr_entry:
    .quad 0
.Ltr_cpu:
    .quad 0
    .global ap_tramp_long
    .set ap_tramp_long, .Ltr_long
    .global ap_tramp_end
ap_tramp_end:
"#, options(att_syntax));

unsafe extern "C" {
    static ap_tramp_start: u8;
    static ap_tramp_data: u8;
    static ap_tramp_long: u8;
    static ap_tramp_end: u8;
}

/// Dane trampoliny (układ = blok `ap_tramp_data` wyżej).
#[repr(C, packed)]
struct TrampData {
    gdt: [u64; 3],
    gdtr_limit: u16,
    gdtr_base: u32,
    far_offset: u32,
    far_selector: u16,
    _pad: u32,
    cr3: u32,
    efer: u32,
    stack: u64,
    entry: u64,
    cpu: u64,
}

const _: () = assert!(core::mem::size_of::<TrampData>() == 72);

const EFER_LME: u32 = 1 << 8;
const EFER_NXE: u32 = 1 << 11;
const PTE_PRESENT: u64 = 1;
const PTE_WRITABLE: u64 = 2;
const PTE_HUGE: u64 = 1 << 7;

/// Tymczasowa PML4 (< 4 GiB): wpisy kernela (256..511) z PML4 kernela +
/// mapa 1:1 pierwszych 2 MiB (strona 2 MiB) dla trampoliny.
/// Zwraca (pml4, pdpt, pd) – fizyczne, do zwolnienia po starcie AP.
fn build_temp_tables() -> Option<(u64, u64, u64)> {
    use crate::memory::{alloc_frame_below, free_frame, kernel_cr3, phys_to_virt};
    let pml4 = alloc_frame_below(0x1_0000_0000)?;
    let Some(pdpt) = alloc_frame_below(0x1_0000_0000) else {
        free_frame(pml4);
        return None;
    };
    let Some(pd) = alloc_frame_below(0x1_0000_0000) else {
        free_frame(pml4);
        free_frame(pdpt);
        return None;
    };
    unsafe {
        let new = phys_to_virt(pml4) as *mut u64;
        let kern = phys_to_virt(kernel_cr3() & 0x000F_FFFF_FFFF_F000) as *const u64;
        core::ptr::write_bytes(new, 0, 512);
        for i in 256..512 {
            *new.add(i) = *kern.add(i);
        }
        let pdpt_v = phys_to_virt(pdpt) as *mut u64;
        let pd_v = phys_to_virt(pd) as *mut u64;
        core::ptr::write_bytes(pdpt_v, 0, 512);
        core::ptr::write_bytes(pd_v, 0, 512);
        *pd_v = PTE_PRESENT | PTE_WRITABLE | PTE_HUGE; // 0..2 MiB
        *pdpt_v = pd | PTE_PRESENT | PTE_WRITABLE;
        *new = pdpt | PTE_PRESENT | PTE_WRITABLE;
    }
    Some((pml4, pdpt, pd))
}

/// Uruchamia wszystkie rdzenie z MADT.  BSP, po starcie schedulera (czeka
/// przez sleep_ms – na ten czas oddaje BKL, który AP musi wziąć).
pub fn init() {
    ONLINE[0].store(true, Ordering::SeqCst);
    APIC_IDS[0].store(lapic::bsp_id() as u32, Ordering::SeqCst);

    let Some(madt) = crate::acpi::madt() else {
        serial_println!("[SMP] no MADT - running on 1 CPU");
        return;
    };
    let aps: alloc::vec::Vec<u32> = madt.cpus.iter().copied().filter(|&id| id as u64 != lapic::bsp_id()).collect();
    if aps.is_empty() {
        serial_println!("[SMP] MADT lists 1 CPU - nothing to start");
        return;
    }
    if !lapic::available() || !super::ioapic::active() {
        serial_println!("[SMP] no Local APIC / I/O APIC - running on 1 CPU");
        return;
    }
    if !cpu::has_rdtscp() {
        serial_println!("[SMP] CPU without RDTSCP (CPU number) - running on 1 CPU");
        return;
    }
    let Some(tramp) = crate::memory::trampoline_frame() else {
        serial_println!("[SMP] no trampoline frame below 1 MiB - running on 1 CPU");
        return;
    };
    if !lapic::calibrate_timer() {
        serial_println!("[SMP] LAPIC timer calibration failed - running on 1 CPU");
        return;
    }
    let Some((pml4, pdpt, pd)) = build_temp_tables() else {
        serial_println!("[SMP] no memory for temporary page tables - running on 1 CPU");
        return;
    };

    // Kod trampoliny pod `tramp`.
    let start = core::ptr::addr_of!(ap_tramp_start) as u64;
    let end = core::ptr::addr_of!(ap_tramp_end) as u64;
    let data_off = core::ptr::addr_of!(ap_tramp_data) as u64 - start;
    let long_off = core::ptr::addr_of!(ap_tramp_long) as u64 - start;
    let tramp_v = crate::memory::phys_to_virt(tramp);
    unsafe { core::ptr::copy_nonoverlapping(start as *const u8, tramp_v as *mut u8, (end - start) as usize) };
    let data = (tramp_v + data_off) as *mut TrampData;
    let efer = EFER_LME | if crate::memory::nx_flag() != 0 { EFER_NXE } else { 0 };
    unsafe {
        (*data).gdtr_base = (tramp + data_off) as u32;
        (*data).far_offset = (tramp + long_off) as u32;
        (*data).cr3 = pml4 as u32;
        (*data).efer = efer;
        (*data).entry = ap_entry as *const () as u64;
    }

    serial_println!(
        "[SMP] starting {} AP(s) (APIC id {:?}), trampoline at {:#x}",
        aps.len().min(MAX_CPUS - 1),
        aps,
        tramp
    );
    let mut next = 1usize;
    let mut idle_ready = false;
    for &id in &aps {
        if next >= MAX_CPUS {
            serial_println!("[SMP] more than {} CPUs - the rest stays off", MAX_CPUS);
            break;
        }
        let c = next;
        // GDT/TSS + stos idle (raz na numer – po nieudanym starcie numer
        // przechodzi na następny rdzeń).
        if !idle_ready {
            if !super::gdt::prepare_cpu(c) {
                serial_println!("[SMP] no memory for CPU {} stacks", c);
                break;
            }
            let Some(stack) = crate::sched::stack::TaskStack::new() else {
                serial_println!("[SMP] no memory for CPU {} idle stack", c);
                break;
            };
            let idle = crate::sched::spawn_idle_for_cpu(c, stack);
            let top = crate::sched::task_stack_top(idle).unwrap_or(0);
            unsafe {
                (*data).stack = top;
                (*data).cpu = c as u64;
            }
            idle_ready = true;
        }
        APIC_IDS[c].store(id, Ordering::SeqCst);

        lapic::send_init(id);
        crate::time::sleep_ms(10);
        lapic::send_sipi(id, (tramp >> 12) as u8);
        crate::time::sleep_ms(1);
        if !online(c) {
            lapic::send_sipi(id, (tramp >> 12) as u8);
        }
        let deadline = crate::time::ticks() + crate::time::ms_to_ticks(500);
        while !online(c) && crate::time::ticks() < deadline {
            crate::time::sleep_ms(1);
        }
        if online(c) {
            next += 1;
            idle_ready = false;
        } else {
            serial_println!("[SMP] CPU with APIC id {} did not start - left halted", id);
            lapic::send_init(id); // na wypadek, gdyby był w połowie trampoliny
            crate::time::sleep_ms(10);
        }
    }

    {
        use crate::memory::free_frame;
        free_frame(pd);
        free_frame(pdpt);
        free_frame(pml4);
    }

    let n = online_count();
    if n > 1 {
        // M17a.b: bez wymuszonego przeładowania CR3 przy każdym przełączeniu –
        // zmiany górnej połowy unieważnia TLB shootdown (tlb.rs).
        ACTIVE.store(true, Ordering::SeqCst);
    }
    serial_println!(
        "[SMP] {} CPU(s) online; Big Kernel Lock; LAPIC timer {} Hz on APs",
        n,
        1000 / lapic::AP_TICK_MS
    );
}

/// Pierwszy kod AP w Rust (z trampoliny; przerwania wyłączone, stos idle).
extern "sysv64" fn ap_entry(c: u64) -> ! {
    let c = c as usize;
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) crate::memory::kernel_cr3(), options(nostack, preserves_flags));
    }
    cpu::set_id(c);
    crate::sched::bkl::acquire_tagged(&crate::sched::bkl::tag::AP_START);
    // M17a.b: czekając na BKL ten CPU mógł zapamiętać w TLB wpisy, które BSP
    // w tym czasie zdjął (nie był jeszcze online – shootdown go pominął).
    // Zmiany górnej połowy są dziś pod BKL, więc od tej chwili do ONLINE nikt
    // ich nie robi.  (Gdy paging dostanie własną blokadę – M17a.c – ONLINE
    // trzeba ustawić przed tym flushem.)
    super::tlb::flush_all_local();

    super::gdt::load_cpu(c);
    super::idt::load();
    crate::memory::paging_init_ap_cpu();
    crate::user::init_ap_cpu(c);
    if !lapic::init_ap() {
        serial_println!("[SMP] CPU {}: Local APIC in a different mode than the BSP - stopping it", c);
        crate::sched::bkl::release();
        loop {
            unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
        }
    }
    lapic::start_periodic_timer(lapic::AP_TICK_MS);

    COUNT.fetch_add(1, Ordering::SeqCst);
    ONLINE[c].store(true, Ordering::Release);
    serial_println!("[SMP] CPU {} online (APIC id {}, LAPIC id read back {})", c, apic_id(c), lapic::id());
    crate::sched::idle_loop()
}
