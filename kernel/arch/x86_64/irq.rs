// Hardware interrupt handling (IRQ0..15 from the 8259 PIC).
//
// Path: device -> PIC -> vector 0x20+n -> stub `irq_n` (idt.rs)
//   -> isr_common -> exception_dispatch -> irq::dispatch -> handler -> EOI.
//
// The handler runs with interrupts disabled (interrupt-type gate), on
// the interrupted kernel code's stack.  It must be short; it may allocate (the heap
// and the frame allocator disable interrupts for the duration of the operation).
//
// EOI is sent AFTER the handler.  Note: when the timer handler
// switches tasks, EOI must be sent before the switch.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::exceptions::ExceptionFrame;
use super::idt::IRQ_BASE;
use super::interrupts::without_interrupts;
use super::pic::{self, IRQ_COUNT};
use crate::serial_println;

/// IRQ handler; argument = line number (0..15).
pub type IrqHandler = fn(irq: u8);

// Function pointers as usize (0 = no handler).
static HANDLERS: [AtomicUsize; IRQ_COUNT] = [const { AtomicUsize::new(0) }; IRQ_COUNT];
static COUNTS: [AtomicU64; IRQ_COUNT] = [const { AtomicU64::new(0) }; IRQ_COUNT];
static UNHANDLED: AtomicU64 = AtomicU64::new(0);

/// PIC remap (all lines masked).  If there is a MADT and an I/O
/// APIC, ISA interrupts go through the I/O APIC and the PIC is disabled.
/// Interrupts stay disabled – they are enabled only by `interrupts::enable()`
/// after the handlers are registered.
pub fn init() {
    serial_println!("[IRQ] Remapping PIC 8259: IRQ0-7 -> {:#x}, IRQ8-15 -> {:#x}",
        pic::MASTER_OFFSET, pic::SLAVE_OFFSET);
    pic::init();
    serial_println!("[IRQ] PIC ready, all lines masked (IMR = {:#06x})", pic::masks());
    super::ioapic::init();
}

/// Whether ISA interrupts go through the I/O APIC (otherwise the 8259 PIC).
pub fn ioapic_mode() -> bool {
    super::ioapic::active()
}

/// Unmasks an ISA line (PIC or I/O APIC).
pub fn unmask(irq: u8) {
    if ioapic_mode() { super::ioapic::unmask(irq) } else { pic::unmask(irq) }
}

/// Masks an ISA line (PIC or I/O APIC).
pub fn mask(irq: u8) {
    if ioapic_mode() { super::ioapic::mask(irq) } else { pic::mask(irq) }
}

pub fn is_masked(irq: u8) -> bool {
    if ioapic_mode() { super::ioapic::is_masked(irq) } else { pic::masks() & (1 << irq) != 0 }
}

/// Registers a handler.  `false` if the line already has a handler.
/// Does not unmask the line – the driver does that (`pic::unmask`) when it is ready.
pub fn register(irq: u8, handler: IrqHandler) -> bool {
    assert!((irq as usize) < IRQ_COUNT, "irq: bad line {}", irq);
    HANDLERS[irq as usize]
        .compare_exchange(0, handler as usize, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

/// Removes a handler (and masks the line).
#[allow(dead_code)]
pub fn unregister(irq: u8) {
    assert!((irq as usize) < IRQ_COUNT, "irq: bad line {}", irq);
    without_interrupts(|| {
        mask(irq);
        HANDLERS[irq as usize].store(0, Ordering::SeqCst);
    });
}

/// How many times a given line has been serviced (excluding spurious IRQs).
#[allow(dead_code)]
pub fn count(irq: u8) -> u64 {
    COUNTS[irq as usize].load(Ordering::Relaxed)
}

#[allow(dead_code)]
pub fn unhandled_count() -> u64 {
    UNHANDLED.load(Ordering::Relaxed)
}

/// Called from `exception_dispatch` for vectors 0x20..0x2F.
pub fn dispatch(frame: &mut ExceptionFrame) {
    let irq = (frame.vector as usize - IRQ_BASE) as u8;

    // Spurious IRQ7/IRQ15 from the PIC: no EOI (is_spurious handles the cascade itself).
    let apic = ioapic_mode();
    if !apic && pic::is_spurious(irq) {
        return;
    }

    COUNTS[irq as usize].fetch_add(1, Ordering::Relaxed);
    let t0 = crate::user::prof::start();

    let handler = HANDLERS[irq as usize].load(Ordering::Acquire);
    if handler != 0 {
        let handler: IrqHandler = unsafe { core::mem::transmute(handler) };
        handler(irq);
    } else {
        // Nobody claimed it – mask the line so it does not flood the system.
        if UNHANDLED.fetch_add(1, Ordering::Relaxed) < 8 {
            serial_println!("[IRQ] unhandled IRQ{} – masking line", irq);
        }
        mask(irq);
    }

    if apic {
        super::lapic::eoi();
    } else {
        pic::send_eoi(irq);
    }
    if irq == 0 {
        crate::user::prof::stop(crate::user::prof::IRQ_PIT, t0);
    }

    // Task switch only AFTER EOI – otherwise the PIC would wait for
    // EOI until the interrupted task gets the CPU again.
    after_interrupt(frame);
}

/// Common tail of a hardware interrupt (IRQ from the PIC, MSI) – already after
/// EOI: preemption and kill of a process that was in ring 3.
pub fn after_interrupt(frame: &mut ExceptionFrame) {
    // Whether the interrupted context held the BKL (set on entry to this
    // interrupt; IF = 0 until now, so nobody overwrote it).
    let had_bkl = super::cpu::irq_had_bkl();
    // The "in interrupt" part is done (the task switch below
    // may give the CPU to another task – which is no longer in an interrupt).
    super::cpu::set_in_interrupt(false);
    // The interrupted kernel code had interrupts enabled (so it could have been
    // preempted) – if another CPU is waiting for the Big Kernel Lock, we let
    // it through.  Without this a kernel task spinning on one CPU would starve
    // the rest (e.g. timer interrupts on the BSP).
    //
    // Only when the interrupted code HELD the BKL before the interrupt (a long
    // kernel task).  An interrupt that woke an idle CPU from `hlt`
    // took the BKL only for itself – releasing it and queueing again
    // cost a full queue rotation on every tick of every CPU: the BKL
    // circulated thousands of times per second, and idle CPUs did not manage to take
    // ready tasks (seconds instead of milliseconds).
    if frame.cs & 3 == 0 && frame.rflags & (1 << 9) != 0 && had_bkl {
        crate::sched::bkl::yield_if_contended();
    }
    crate::sched::preempt_irq(had_bkl);

    // `kill` of a process that is in ring 3 – we terminate it at the
    // next interrupt (the process will not check this itself).
    //
    // The ordering with preempt() is correct: `frame` lies on the kernel stack of
    // THIS task (IRQ/MSI without IST – idt.rs), and preempt() returns here only
    // when the scheduler picks this task again – then current == owner of the
    // frame, so should_exit() and redirect_to_exit() refer to the same
    // task.
    if frame.cs & 3 == 3 && crate::sched::should_exit() {
        crate::user::kill_from_interrupt(frame);
    }
}
