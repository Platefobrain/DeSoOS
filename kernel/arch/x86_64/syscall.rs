// Entry into the kernel via SYSCALL and return via SYSRET.
//
// SYSCALL (from ring 3): RIP -> RCX, RFLAGS -> R11, CS/SS from MSR STAR, RIP from
// LSTAR, RFLAGS &= ~SFMASK (IF = 0).  The stack is NOT switched (TSS.RSP0
// applies only to interrupts/exceptions), so the first instructions must
// pick up the kernel stack themselves:
//
//   swapgs                 GS.base = per-CPU block (MSR KERNEL_GS_BASE)
//   mov gs:[8], rsp        stash the user RSP
//   mov rsp, gs:[0]        kernel stack of the current task (set by the scheduler)
//   push gs:[8]
//   swapgs                 GS.base is the user's again
//
// The kernel GS is active only for these few instructions (IF = 0), so
// task switching during a syscall and interrupts need not know about it.
//
// Then: a SyscallFrame (registers), syscall_dispatch (user/syscalls.rs),
// cli, register restore, user RSP, SYSRET.  SYSRET with a
// non-canonical RCX would raise #GP in ring 0 on the user stack (a well-known Intel
// pitfall) – dispatch checks the return RIP and kills the process if needed.
//
// ABI (as in Linux): RAX = number, arguments RDI, RSI, RDX, R10, R8, R9,
// result in RAX (negative = -errno).  RCX and R11 are clobbered, the rest preserved.

use core::arch::global_asm;

use super::gdt::KERNEL_CS;

const IA32_EFER: u32 = 0xC000_0080;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;
const IA32_GS_BASE: u32 = 0xC000_0101;
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;
const EFER_SCE: u64 = 1;

/// RFLAGS cleared on entry: TF, IF, DF, NT, AC.
pub const SFMASK: u64 = (1 << 8) | (1 << 9) | (1 << 10) | (1 << 14) | (1 << 18);

/// Per-CPU block (one per core; each CPU's KERNEL_GS_BASE
/// points to its block).
#[repr(C)]
pub struct PerCpu {
    /// Kernel stack top of the current task (offset 0 – used by the assembly).
    pub kernel_rsp: u64,
    /// User RSP at the moment of entry (offset 8).
    pub user_rsp: u64,
}

static mut PERCPU: [PerCpu; super::cpu::MAX_CPUS] =
    [const { PerCpu { kernel_rsp: 0, user_rsp: 0 } }; super::cpu::MAX_CPUS];

fn percpu(c: usize) -> *mut PerCpu {
    unsafe { core::ptr::addr_of_mut!(PERCPU[c]) }
}

/// Process registers saved by syscall_entry (order = reverse of the pushes).
#[repr(C)]
pub struct SyscallFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rax: u64,
    /// Return RIP (from RCX).
    pub rip: u64,
    /// User RFLAGS (from R11).
    pub rflags: u64,
    pub rsp: u64,
}

global_asm!(r#"
    .section .text
    .global syscall_entry
    syscall_entry:
        swapgs
        mov gs:[8], rsp
        mov rsp, gs:[0]
        push qword ptr gs:[8]
        swapgs
        push r11
        push rcx
        push rax
        push rbx
        push rdx
        push rsi
        push rdi
        push rbp
        push r8
        push r9
        push r10
        push r12
        push r13
        push r14
        push r15
        mov rdi, rsp
        cld
        call syscall_dispatch
        cli
        pop r15
        pop r14
        pop r13
        pop r12
        pop r10
        pop r9
        pop r8
        pop rbp
        pop rdi
        pop rsi
        pop rdx
        pop rbx
        pop rax
        pop rcx
        pop r11
        pop rsp
        sysretq
"#);

unsafe extern "C" {
    fn syscall_entry();
}

unsafe fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
    }
    ((hi as u64) << 32) | lo as u64
}

unsafe fn wrmsr(msr: u32, value: u64) {
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") value as u32, in("edx") (value >> 32) as u32, options(nostack, preserves_flags));
    }
}

/// SYSRET selector base in STAR[63:48] – with RPL 3 (see init_cpu).
pub const SYSRET_BASE: u64 = 0x10 | 3;

/// Enables SYSCALL/SYSRET.  Selectors (gdt.rs): STAR[47:32] = 0x08 ->
/// SYSCALL: CS 0x08, SS 0x10; STAR[63:48] = 0x13 -> SYSRET: SS 0x18|3,
/// CS 0x20|3 (64-bit).
pub fn init() {
    init_cpu(super::cpu::id());
}

/// SYSCALL MSRs of the current processor `c` (BSP: init, AP: at startup).
pub fn init_cpu(c: usize) {
    unsafe {
        // STAR[63:48] = 0x13 (0x10 | RPL 3), as in Linux (__USER32_CS with RPL 3):
        // SYSRET gives CS = 0x13 + 16 = 0x23, SS = 0x13 + 8 = 0x1b.  Intel itself
        // forces RPL 3, AMD takes the selector as is – with 0x10 on AMD CPUs
        // (KVM and real hardware) SS after SYSRET = 0x18 (RPL 0), and the next return from
        // an interrupt to the process (iretq) ended in #GP(0x18) in the kernel.
        wrmsr(IA32_STAR, ((KERNEL_CS as u64) << 32) | (SYSRET_BASE << 48));
        wrmsr(IA32_LSTAR, syscall_entry as *const () as u64);
        wrmsr(IA32_FMASK, SFMASK);
        wrmsr(IA32_GS_BASE, 0);
        wrmsr(IA32_KERNEL_GS_BASE, percpu(c) as u64);
        wrmsr(IA32_EFER, rdmsr(IA32_EFER) | EFER_SCE);
        (*percpu(c)).kernel_rsp = super::gdt::rsp0();
    }
}

/// Kernel stack for SYSCALL (scheduler, together with TSS.RSP0) – current CPU.
pub fn set_kernel_stack(top: u64) {
    unsafe { (*percpu(super::cpu::id())).kernel_rsp = top };
}

/// (EFER.SCE, STAR, LSTAR, SFMASK, KERNEL_GS_BASE, kernel_rsp) – for tests.
#[allow(dead_code)]
pub fn state() -> (bool, u64, u64, u64, u64, u64) {
    unsafe {
        (
            rdmsr(IA32_EFER) & EFER_SCE != 0,
            rdmsr(IA32_STAR),
            rdmsr(IA32_LSTAR),
            rdmsr(IA32_FMASK),
            rdmsr(IA32_KERNEL_GS_BASE),
            (*percpu(super::cpu::id())).kernel_rsp,
        )
    }
}

#[allow(dead_code)]
pub fn entry_address() -> u64 {
    syscall_entry as *const () as u64
}

#[allow(dead_code)]
pub fn percpu_address() -> u64 {
    percpu(super::cpu::id()) as u64
}
