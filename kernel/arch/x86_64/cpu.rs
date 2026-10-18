// Current processor number.
//
// Every CPU has its number in the IA32_TSC_AUX MSR (0 = boot processor, BSP,
// 1.. = subsequently started cores); `rdtscp` returns it in ECX.  This is fast
// and does not depend on the GS register (in the kernel GS belongs to the process – swapgs
// is done only for the few SYSCALL entry instructions).

use core::sync::atomic::{AtomicBool, Ordering};

/// Maximum number of supported processors (e.g. a 16-thread laptop CPU).
pub const MAX_CPUS: usize = 16;

const IA32_TSC_AUX: u32 = 0xC000_0103;

static RDTSCP: AtomicBool = AtomicBool::new(false);

/// Detects RDTSCP and sets the BSP number (0).  At the very start of boot.
pub fn init_bsp() {
    #[allow(unused_unsafe)]
    let ok = unsafe { core::arch::x86_64::__cpuid(0x8000_0001) }.edx & (1 << 27) != 0;
    if ok {
        set_id(0);
    }
    RDTSCP.store(ok, Ordering::SeqCst);
}

/// Whether processors can be told apart (an SMP precondition).
pub fn has_rdtscp() -> bool {
    RDTSCP.load(Ordering::Relaxed)
}

/// Stores the processor number (each CPU on itself).
pub fn set_id(cpu: usize) {
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") IA32_TSC_AUX, in("eax") cpu as u32, in("edx") 0u32,
            options(nostack, preserves_flags));
    }
}

/// Current processor number (0 without RDTSCP – BSP only).
#[inline]
pub fn id() -> usize {
    if !RDTSCP.load(Ordering::Relaxed) {
        return 0;
    }
    let aux: u32;
    unsafe {
        core::arch::asm!("rdtscp", out("ecx") aux, out("eax") _, out("edx") _, options(nomem, nostack, preserves_flags));
    }
    (aux as usize) % MAX_CPUS
}

// ------------------------------------------------------------
// Preemption disable and "in interrupt" flag (per CPU)
// ------------------------------------------------------------

use core::sync::atomic::AtomicU32;

static PREEMPT: crate::arch::x86_64::percpu::PerCpu<AtomicU32> = crate::per_cpu!(AtomicU32::new(0));
static IN_IRQ: crate::arch::x86_64::percpu::PerCpu<AtomicBool> = crate::per_cpu!(AtomicBool::new(false));

/// Disables preemption on this CPU (nestable) – SpinLock.
#[allow(dead_code)]
#[inline]
pub fn preempt_disable() {
    // Reading the CPU number and incrementing the counter must be atomic:
    // a timer interrupt between them could migrate the task to another
    // CPU, and the counter would be incremented on the old one (the task would hold a lock while
    // remaining preemptible).  After the increment the task will not migrate anymore, so
    // preempt_enable does not need this.
    super::interrupts::without_interrupts(|| {
        PREEMPT[id()].fetch_add(1, Ordering::Relaxed);
    });
}

#[allow(dead_code)]
#[inline]
pub fn preempt_enable() {
    let old = PREEMPT[id()].fetch_sub(1, Ordering::Relaxed);
    assert!(old > 0, "preempt_enable without preempt_disable on CPU {}", id());
}

/// Preemption counter and interrupt flag of any CPU (watchdog report).
pub fn preempt_count_of(c: usize) -> u32 {
    PREEMPT[c % MAX_CPUS].load(Ordering::Relaxed)
}

pub fn in_interrupt_of(c: usize) -> bool {
    IN_IRQ[c % MAX_CPUS].load(Ordering::Relaxed)
}

/// > 0: the timer tick will not switch tasks on this CPU (NEED_RESCHED waits).
#[inline]
pub fn preempt_count() -> u32 {
    PREEMPT[id()].load(Ordering::Relaxed)
}

static IRQ_HAD_BKL: crate::arch::x86_64::percpu::PerCpu<AtomicBool> = crate::per_cpu!(AtomicBool::new(false));

/// Whether the context interrupted by the current interrupt held the BKL (exceptions.rs
/// sets it on entry; irq::after_interrupt releases the BKL only in that case).
pub fn set_irq_had_bkl(v: bool) {
    IRQ_HAD_BKL[id()].store(v, Ordering::Relaxed);
}

pub fn irq_had_bkl() -> bool {
    IRQ_HAD_BKL[id()].load(Ordering::Relaxed)
}

/// Entry to / exit from a hardware interrupt handler (exceptions.rs, irq.rs).
#[inline]
pub fn set_in_interrupt(v: bool) {
    IN_IRQ[id()].store(v, Ordering::Relaxed);
}

/// Whether this CPU is currently running an interrupt handler (before `after_interrupt`).
#[allow(dead_code)]
#[inline]
pub fn in_interrupt() -> bool {
    IN_IRQ[id()].load(Ordering::Relaxed)
}
