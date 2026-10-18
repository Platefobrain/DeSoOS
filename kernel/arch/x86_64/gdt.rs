// GDT + TSS.
//
// Selector layout (matching the SYSCALL/SYSRET requirements:
// STAR[47:32] = 0x08 -> CS = 0x08, SS = 0x10;
// STAR[63:48] = 0x13 -> SS = 0x13 + 8 = 0x1b, CS = 0x13 + 16 = 0x23 – RPL 3
// already in the selector, because AMD does not enforce it, see syscall.rs):
//
//   0x00  null
//   0x08  kernel code (64-bit)
//   0x10  kernel data
//   0x18  user data   (DPL 3)
//   0x20  user code   (DPL 3, 64-bit)
//   0x28  TSS (16-byte descriptor, occupies slots 5 and 6)

use core::arch::asm;
use core::mem::size_of;
use core::ptr::{addr_of, addr_of_mut};

use crate::serial_println;
use super::cpu::{self, MAX_CPUS};

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
#[allow(dead_code)]
pub const USER_DS: u16 = 0x18 | 3;
#[allow(dead_code)]
pub const USER_CS: u16 = 0x20 | 3;
pub const TSS_SELECTOR: u16 = 0x28;

pub const GDT_ENTRIES: usize = 7;

// IST numbers (1..=7) used by the IDT gates.
pub const IST_DOUBLE_FAULT: u8 = 1;
pub const IST_NMI: u8 = 2;
pub const IST_MACHINE_CHECK: u8 = 3;
/// #UD, #NP, #SS, #GP, #TS – exceptions after which the kernel halts anyway.
pub const IST_FATAL: u8 = 4;
/// #PF no longer uses IST (task stack) – stack 5 stays in reserve.
#[allow(dead_code)]
pub const IST_PAGE_FAULT: u8 = 5;

const IST_COUNT: usize = 5;
pub const IST_STACK_SIZE: usize = 16 * 1024;

// RSP0 – the stack the CPU switches to on an interrupt / exception from ring 3.
// One TSS per CPU; on every switch the scheduler writes here the
// top of the current task's kernel stack (`set_rsp0`).  At boot: the boot
// stack from the bootloader.
fn kernel_stack_top() -> u64 {
    crate::memory::kernel_layout().stack_top
}

/// TSS of processor `c` (every CPU has its own TSS and its own GDT – the TSS
/// descriptor in the GDT gets the "busy" bit after `ltr`, so they cannot be shared).
fn tss(c: usize) -> *mut Tss {
    unsafe { addr_of_mut!(TSS[c]) }
}

/// Sets TSS.RSP0 of the current CPU (call with interrupts disabled – scheduler).
pub fn set_rsp0(top: u64) {
    unsafe { core::ptr::write_unaligned(addr_of_mut!((*tss(cpu::id())).rsp[0]), top) };
}

/// Current TSS.RSP0 of the current CPU (tests / diagnostics).
#[allow(dead_code)]
pub fn rsp0() -> u64 {
    unsafe { core::ptr::read_unaligned(addr_of!((*tss(cpu::id())).rsp[0])) }
}

/// GDT descriptor (tests: user segments).
#[allow(dead_code)]
pub fn descriptor(index: usize) -> u64 {
    unsafe { (*addr_of!(GDT[cpu::id()]))[index] }
}

// Boot IST stacks (.bss, no guard pages).  After memory
// init `move_ist_to_guarded_stacks` moves the IST onto stacks from the
// task stack area (guard page below – overflow = #PF/#DF,
// not a silent overwrite of neighbouring data in .bss).
#[repr(C, align(16))]
struct IstStack([u8; IST_STACK_SIZE]);

static mut IST_STACKS: [IstStack; IST_COUNT] =
    [const { IstStack([0; IST_STACK_SIZE]) }; IST_COUNT];

/// [bottom, top) ranges of the IST stacks in use (after the move: the new ones),
/// for every CPU.
static IST_RANGES: [[[core::sync::atomic::AtomicU64; 2]; IST_COUNT]; MAX_CPUS] =
    [const { [const { [core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)] }; IST_COUNT] }; MAX_CPUS];

/// Top of IST stack number `ist` (1..=IST_COUNT) from the current CPU's TSS (tests / diagnostics).
#[allow(dead_code)]
pub fn ist_top(ist: u8) -> u64 {
    unsafe { core::ptr::read_unaligned(addr_of!((*tss(cpu::id())).ist[ist as usize - 1])) }
}

/// Whether `rsp` lies on one of the IST stacks (the old one in .bss or a new one).
/// The scheduler must not switch tasks on an IST stack – the next
/// exception of that type would start from the top of the same stack and overwrite
/// the frame of the task that gave up the CPU.
pub fn on_ist_stack(rsp: u64) -> bool {
    use core::sync::atomic::Ordering;
    let bss_start = addr_of!(IST_STACKS) as u64;
    let bss_end = bss_start + (IST_COUNT * IST_STACK_SIZE) as u64;
    if (bss_start..bss_end).contains(&rsp) {
        return true;
    }
    IST_RANGES.iter().flatten().any(|r| {
        let (lo, hi) = (r[0].load(Ordering::Relaxed), r[1].load(Ordering::Relaxed));
        lo != 0 && rsp >= lo && rsp <= hi
    })
}

/// Moves the IST of processor `c` onto new stacks with guard pages; `false` = out of memory.
fn guarded_ist_for(c: usize) -> usize {
    use core::sync::atomic::Ordering;
    let mut moved = 0;
    for i in 0..IST_COUNT {
        let Some(stack) = crate::sched::stack::TaskStack::new() else {
            continue;
        };
        let (bottom, top) = (stack.bottom(), stack.top());
        core::mem::forget(stack); // the IST stack lives until the system shuts down
        IST_RANGES[c][i][0].store(bottom, Ordering::Relaxed);
        IST_RANGES[c][i][1].store(top, Ordering::Relaxed);
        unsafe { core::ptr::write_unaligned(addr_of_mut!((*tss(c)).ist[i]), top) };
        moved += 1;
    }
    moved
}

/// Prepares the GDT + TSS of AP processor `c` (IST stacks with guard pages).
/// Called by the BSP before waking the AP; `false` – out of memory for the stacks.
pub fn prepare_cpu(c: usize) -> bool {
    build(c);
    guarded_ist_for(c) == IST_COUNT
}

/// The AP loads its GDT and TSS (prepared by `prepare_cpu`).
pub fn load_cpu(c: usize) {
    unsafe { load(c) };
}

/// Moves the IST onto stacks with guard pages (stack.rs).  Call after
/// memory init, with interrupts disabled and NOT on an IST stack.
/// The old stacks in .bss remain (unused).
pub fn move_ist_to_guarded_stacks() {
    let moved = guarded_ist_for(0);
    if moved < IST_COUNT {
        serial_println!("[ARCH] WARNING: no memory for {} guarded IST stack(s) - keeping .bss stacks", IST_COUNT - moved);
    }
    serial_println!(
        "[ARCH] IST stacks moved to guarded slots: {} x {} KiB (guard page below each)",
        moved,
        crate::sched::stack::STACK_SIZE / 1024
    );
}

#[repr(C, packed)]
struct Tss {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

static mut TSS: [Tss; MAX_CPUS] = [const { Tss {
    reserved0: 0,
    rsp: [0; 3],
    reserved1: 0,
    ist: [0; 7],
    reserved2: 0,
    reserved3: 0,
    iomap_base: 0,
} }; MAX_CPUS];

static mut GDT: [[u64; GDT_ENTRIES]; MAX_CPUS] = [[0; GDT_ENTRIES]; MAX_CPUS];

#[repr(C, packed)]
struct DescriptorPointer {
    limit: u16,
    base: u64,
}

// The "accessed" bit is set up front so that the CPU does not have to write to the GDT.
const KERNEL_CODE: u64 = 0x00AF_9B00_0000_FFFF;
const KERNEL_DATA: u64 = 0x00CF_9300_0000_FFFF;
const USER_DATA: u64 = 0x00CF_F300_0000_FFFF;
const USER_CODE: u64 = 0x00AF_FB00_0000_FFFF;

fn tss_descriptor(base: u64, limit: u64) -> (u64, u64) {
    let low = (limit & 0xffff)
        | ((base & 0x00ff_ffff) << 16)
        | (0x89u64 << 40) // present, DPL 0, 64-bit TSS (available)
        | (((limit >> 16) & 0xf) << 48)
        | (((base >> 24) & 0xff) << 56);
    let high = base >> 32;
    (low, high)
}

/// Fills the GDT and TSS of processor `c` (RSP0 = boot stack, IST from .bss
/// only for the BSP – APs get their own in `prepare_cpu`).
fn build(c: usize) {
    unsafe {
        let tss = tss(c);
        core::ptr::write_unaligned(addr_of_mut!((*tss).rsp[0]), kernel_stack_top());
        if c == 0 {
            for i in 0..IST_COUNT {
                let base = addr_of!(IST_STACKS[i]) as u64;
                core::ptr::write_unaligned(addr_of_mut!((*tss).ist[i]), base + IST_STACK_SIZE as u64);
            }
        }
        // No I/O permission bitmap: offset beyond the TSS limit.
        core::ptr::write_unaligned(addr_of_mut!((*tss).iomap_base), size_of::<Tss>() as u16);

        let (tss_low, tss_high) = tss_descriptor(tss as u64, size_of::<Tss>() as u64 - 1);

        let gdt = addr_of_mut!(GDT[c]);
        (*gdt)[0] = 0;
        (*gdt)[1] = KERNEL_CODE;
        (*gdt)[2] = KERNEL_DATA;
        (*gdt)[3] = USER_DATA;
        (*gdt)[4] = USER_CODE;
        (*gdt)[5] = tss_low;
        (*gdt)[6] = tss_high;
    }
}

/// lgdt + segment reload + ltr for processor `c`.
unsafe fn load(c: usize) {
    unsafe {
        let gdt = addr_of_mut!(GDT[c]);
        let pointer = DescriptorPointer {
            limit: (GDT_ENTRIES * 8 - 1) as u16,
            base: gdt as u64,
        };

        asm!(
            "lgdt [{}]",
            in(reg) &pointer,
            options(readonly, nostack, preserves_flags)
        );

        // Reloading CS requires a far return; the other segment registers
        // are loaded with a plain mov.
        asm!(
            "push {cs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ds, {ds:x}",
            "mov es, {ds:x}",
            "mov ss, {ds:x}",
            "mov fs, {zero:x}",
            "mov gs, {zero:x}",
            cs = const KERNEL_CS as u64,
            ds = in(reg) KERNEL_DS as u64,
            zero = in(reg) 0u64,
            tmp = out(reg) _,
        );

        asm!(
            "ltr {0:x}",
            in(reg) TSS_SELECTOR,
            options(nomem, nostack, preserves_flags)
        );
    }
}

pub fn init() {
    serial_println!("[ARCH] Initializing GDT + TSS...");
    build(0);
    unsafe { load(0) };

    serial_println!(
        "[ARCH] GDT loaded ({} entries), TSS at {:#x}, RSP0 = {:#x}",
        GDT_ENTRIES,
        tss(0) as u64,
        kernel_stack_top()
    );
    serial_println!(
        "[ARCH] IST stacks: {} x {} KiB",
        IST_COUNT,
        IST_STACK_SIZE / 1024
    );
}
