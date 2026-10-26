// SMP – starting the remaining cores (APs, "application processors").
//
// After boot only the bootstrap processor (BSP) runs.  The rest are woken by the
// INIT – SIPI – SIPI sequence sent through the Local APIC.  SIPI gives a memory page
// (address < 1 MiB) where the AP starts – in 16-bit real mode,
// like a processor from 1978.  That is why a trampoline is needed:
//
//   1. real mode (CS = trampoline page): trampoline GDT, CR4.PAE,
//      CR3 = temporary PML4 (< 4 GiB, since it is loaded from a 32-bit register),
//      EFER.LME (+ NXE), CR0.PG|PE at once – straight into 64-bit mode (no
//      stop in protected mode), far jump to 64-bit code,
//   2. 64-bit, still on the trampoline page (1:1 map of the first 2 MiB
//      in the temporary PML4): AP stack and jump to `ap_entry` in the kernel
//      (upper half – the temporary PML4 has the kernel entries copied),
//   3. `ap_entry` (Rust): kernel CR3, CPU number (TSC_AUX), Big Kernel
//      Lock, own GDT/TSS (IST), IDT, FPU/SMEP/SMAP/SYSCALL, PAT, LAPIC
//      + LAPIC timer (100 Hz), "online" – and the idle loop.
//
// Kernel state (scheduler, heap, VFS) is protected by the Big Kernel Lock (sched/bkl.rs):
// kernel code runs on one CPU at a time, ring-3 processes run truly
// in parallel.  TLB: no "shootdown" IPI – with multiple CPUs every task
// switch reloads CR3 (full flush), and the heap never returns pages (heap.rs).
// Processes are single-threaded, so their mappings live in the TLB of only one CPU.
//
// Device interrupts (I/O APIC, MSI) go to the BSP; the PIT tick (BSP) wakes
// sleeping tasks; an idle AP is woken by the RESCHED_VECTOR IPI (sched::kick).

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

/// Whether CPU `c` is running.
pub fn online(c: usize) -> bool {
    c < MAX_CPUS && ONLINE[c].load(Ordering::Acquire)
}

/// Number of running processors.
pub fn online_count() -> usize {
    COUNT.load(Ordering::Relaxed)
}

/// Whether more than one CPU is running.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

pub fn panicking() -> bool {
    PANICKING.load(Ordering::Relaxed)
}

/// APIC ID of processor `c`.
pub fn apic_id(c: usize) -> u32 {
    APIC_IDS[c % MAX_CPUS].load(Ordering::Relaxed)
}

/// (LAPIC timer ticks, received "resched" IPIs) of processor `c` – `cpus`, tests.
pub fn counters(c: usize) -> (u64, u64) {
    (TIMER_TICKS[c % MAX_CPUS].load(Ordering::Relaxed), RESCHED_IPIS[c % MAX_CPUS].load(Ordering::Relaxed))
}

/// Wakes CPU `c` (IPI) – sched::kick has set NEED_RESCHED for it.
pub fn send_resched(c: usize) {
    if online(c) && c != cpu::id() {
        lapic::send_ipi(apic_id(c), lapic::RESCHED_VECTOR);
    }
}

/// From TIMER_VECTOR (AP, every AP_TICK_MS).
pub fn on_ap_timer() {
    TIMER_TICKS[cpu::id()].fetch_add(1, Ordering::Relaxed);
    crate::sched::ap_tick(lapic::AP_TICK_MS);
}

/// From RESCHED_VECTOR (the switch is done by irq::after_interrupt).
pub fn on_resched_ipi() {
    RESCHED_IPIS[cpu::id()].fetch_add(1, Ordering::Relaxed);
}

// ------------------------------------------------------------
// Hang watchdog (like the "NMI watchdog" in Linux)
// ------------------------------------------------------------
//
// A hang = the PIT clock (interrupt on CPU 0) stops advancing for
// WATCHDOG_MS.  The tick is counted before the BKL (time::pit_tick_early), so this
// means: CPU 0 receives no timer interrupts (interrupts disabled, CPU
// hung) – not just "the interrupt is queued for the BKL".  It is checked by every CPU that waits long – for the Big Kernel
// Lock or for a spinlock (`watchdog_poll` in their loops; during a hang that is
// exactly where the other CPUs are stuck) – and by the LAPIC timer tick (before the BKL).
// The first one to notice sends an NMI to everyone (delivered even with
// interrupts disabled): each CPU records its RIP, and the reporting CPU
// prints the BKL state, tickets and addresses (addr2line -e build/kernel.elf <address>).
// One report per hang (per tick number); full reports only for the first 3.


/// Hang threshold (like the "soft lockup" in Linux: ~10–20 s).  Time is measured by
/// clock.rs (HPET – shared by all CPUs; TSC only without HPET).
const WATCHDOG_MS: u64 = 10_000;
static LAST_RIP: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static NMI_RIP: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static NMI_FLAGS: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
/// NMI requested by the watchdog for a given CPU (cleared by that CPU in the handler).
/// Per CPU rather than a single flag with a time window: an NMI arriving after
/// the report must also be recognized (otherwise it would take the normal path
/// and want the BKL this CPU is already waiting for – a deadlock with itself).
static NMI_EXPECTED: crate::arch::x86_64::percpu::PerCpu<AtomicBool> = crate::per_cpu!(AtomicBool::new(false));
/// Per CPU: the last seen PIT tick and the timestamp (clock.rs) of the moment
/// it was seen.  Only the CPU's own data – a shared (tick, time) pair
/// written by many CPUs drifted apart and gave false "clock stopped" reports.
static WD_TICK: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(u64::MAX));
static WD_STAMP: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
static WD_REPORTED_TICK: AtomicU64 = AtomicU64::new(u64::MAX);
static WD_REPORTS: AtomicU64 = AtomicU64::new(0);
/// Reports already printed (tests wait for the printing to finish, not for the report to start).
static WD_DONE: AtomicU64 = AtomicU64::new(0);
static NMI_STAMP: crate::arch::x86_64::percpu::PerCpu<AtomicU64> = crate::per_cpu!(AtomicU64::new(0));
/// At most this many full reports per boot (then one line).
const WD_FULL_REPORTS: u64 = 3;

/// From exception_dispatch, before the BKL: timer tick (PIT on the BSP, LAPIC on APs).
pub fn watchdog_tick(rip: u64) {
    LAST_RIP[cpu::id()].store(rip, Ordering::Relaxed);
    crate::time::gap_probe();
    watchdog_poll();
    #[cfg(selftest)]
    stall_poll();
}

/// Self-tests (automatic mode): nothing printed for STALL_MS while the clock runs –
/// a test is stuck somewhere other than a spinlock or the BKL (a task that never
/// wakes, a wait loop).  One full report (RIP of every CPU, their current tasks),
/// so the run that is killed by the timeout still says where it stood.
#[cfg(selftest)]
const STALL_MS: u64 = 30_000;
#[cfg(selftest)]
static STALL_LINES: AtomicU64 = AtomicU64::new(u64::MAX);
#[cfg(selftest)]
static STALL_STAMP: AtomicU64 = AtomicU64::new(0);
#[cfg(selftest)]
static STALL_REPORTED: AtomicBool = AtomicBool::new(false);

#[cfg(selftest)]
fn stall_poll() {
    if !active() || !crate::selftest::autotest() || STALL_REPORTED.load(Ordering::Relaxed) {
        return;
    }
    let lines = crate::drivers::serial::LINES.load(Ordering::Relaxed);
    let seen = STALL_LINES.load(Ordering::Relaxed);
    if lines != seen {
        if STALL_LINES.compare_exchange(seen, lines, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            STALL_STAMP.store(clock::stamp(), Ordering::Relaxed);
        }
        return;
    }
    if clock::elapsed_us(STALL_STAMP.load(Ordering::Relaxed)) < STALL_MS * 1000 {
        return;
    }
    if STALL_REPORTED.swap(true, Ordering::AcqRel) {
        return;
    }
    lockup_dump(format_args!("self-test printed nothing for {} s (seen by CPU {}) - a task is stuck", STALL_MS / 1000, cpu::id()));
}

/// Checks whether the clock has stopped (called from wait loops; cheap).
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
    // One report per hang (the first CPU that notices it).
    let prev = WD_REPORTED_TICK.load(Ordering::Relaxed);
    if prev == t || WD_REPORTED_TICK.compare_exchange(prev, t, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        return;
    }
    watchdog_report(t);
}

/// From exception_dispatch: an NMI sent by the watchdog (without the BKL).  `true` =
/// handled.
pub fn watchdog_nmi(rip: u64, rflags: u64) -> bool {
    if !NMI_EXPECTED[cpu::id()].swap(false, Ordering::AcqRel) {
        return false;
    }
    NMI_FLAGS[cpu::id()].store(rflags, Ordering::Relaxed);
    NMI_STAMP[cpu::id()].store(clock::stamp(), Ordering::Relaxed);
    NMI_RIP[cpu::id()].store(rip, Ordering::Relaxed);
    true
}

/// How many hang reports there were (tests).
#[allow(dead_code)]
pub fn watchdog_reports() -> u64 {
    WD_DONE.load(Ordering::Acquire)
}

#[cold]
fn watchdog_report(tick: u64) {
    let me = cpu::id();
    lockup_dump(format_args!("PIT clock stuck at tick {} for {} ms (seen by CPU {})", tick, WATCHDOG_MS, me));
}

/// A CPU waits for the Big Kernel Lock longer than BKL_WAIT_REPORT_MS (from
/// bkl::acquire, clock.rs time).  The clock may keep running meanwhile (the tick is counted
/// before the BKL), so "clock stopped" alone will not catch it: starvation or
/// very slow BKL hand-over.
pub const BKL_WAIT_REPORT_MS: u64 = 10_000;

#[cold]
pub fn bkl_wait_report(ticket: u32, waited_ms: u64) {
    if !active() {
        return;
    }
    lockup_dump(format_args!("CPU {} waits {} ms for the Big Kernel Lock (ticket {})", cpu::id(), waited_ms, ticket));
}

/// Full report: header, BKL state, NMI to the other CPUs (RIP, IF,
/// response time), preemption counter and spinlocks of each CPU.
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
    // No console locks – the state is broken anyway.
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
            // After how many us the CPU handled the NMI (shared clock.rs time): on
            // hardware microseconds; much more = the CPU was not executing.
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

/// Panic: stops the other processors (so they do not write over the screen or
/// corrupt the state we are reporting).
pub fn halt_others() {
    if !PANICKING.swap(true, Ordering::SeqCst) && active() {
        lapic::send_ipi_others(lapic::HALT_VECTOR);
    }
}

// ------------------------------------------------------------
// Trampoline (copied to an address < 1 MiB)
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

/// Trampoline data (layout = the `ap_tramp_data` block above).
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

/// Temporary PML4 (< 4 GiB): kernel entries (256..511) from the kernel PML4 +
/// a 1:1 map of the first 2 MiB (one 2 MiB page) for the trampoline.
/// Returns (pml4, pdpt, pd) – physical, to be freed after the AP has started.
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

/// Starts all cores from the MADT.  On the BSP, after the scheduler starts (waits
/// with sleep_ms – meanwhile it releases the BKL, which the AP must take).
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

    // Trampoline code at `tramp`.
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
        // GDT/TSS + idle stack (once per number – after a failed start the number
        // moves on to the next core).
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
            lapic::send_init(id); // in case it was halfway through the trampoline
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
        // No forced CR3 reload on every switch –
        // changes to the upper half are invalidated by TLB shootdown (tlb.rs).
        ACTIVE.store(true, Ordering::SeqCst);
    }
    serial_println!(
        "[SMP] {} CPU(s) online; Big Kernel Lock; LAPIC timer {} Hz on APs",
        n,
        1000 / lapic::AP_TICK_MS
    );
}

/// First AP code in Rust (from the trampoline; interrupts disabled, idle stack).
extern "sysv64" fn ap_entry(c: u64) -> ! {
    let c = c as usize;
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) crate::memory::kernel_cr3(), options(nostack, preserves_flags));
    }
    cpu::set_id(c);
    crate::sched::bkl::acquire_tagged(&crate::sched::bkl::tag::AP_START);
    // While waiting for the BKL this CPU may have cached TLB entries that the BSP
    // removed in the meantime (it was not online yet – the shootdown skipped it).
    // Upper-half changes are currently made under the BKL, so nobody makes them
    // from now until ONLINE.  (Once paging gets its own lock, ONLINE
    // must be set before this flush.)
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
