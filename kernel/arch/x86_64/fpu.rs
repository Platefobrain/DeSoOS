// FPU/SSE state of processes (FXSAVE/FXRSTOR).
//
// The kernel is soft-float – it never uses x87/SSE itself.  The FPU/XMM registers
// therefore always belong to the user process that ran last.
// The scheduler switches them eagerly on every task switch:
//   * from a process  -> FXSAVE into its Task (512 B),
//   * to a process -> CR0.TS = 0 and FXRSTOR from its Task,
//   * to a kernel task -> CR0.TS = 1 (an FPU/SSE instruction in the kernel = #NM
//     = kernel error report).
// No lazy switching (first use -> #NM -> save): simpler
// and free of LazyFP-type vulnerabilities, and with SMP there is no need to track which
// core holds whose state.
//
// Instructions as bytes (`fxsave64 [rdi]` / `fxrstor64 [rdi]`), so as not to
// depend on whether the assembler accepts them in a soft-float build.
// XSAVE/XRSTOR (AVX, CPUID, XCR0) – later.

use core::arch::asm;

/// FXSAVE image (512 B, 16-byte aligned).
#[repr(C, align(16))]
pub struct FxState(pub [u8; 512]);

impl FxState {
    /// State after FNINIT + default MXCSR: FCW = 0x037F (all x87 exceptions
    /// masked), MXCSR = 0x1F80 (SSE exceptions masked), registers 0.
    pub const fn initial() -> Self {
        let mut b = [0u8; 512];
        b[0] = 0x7F;
        b[1] = 0x03;
        b[24] = 0x80;
        b[25] = 0x1F;
        FxState(b)
    }
}

const CR0_MP: u64 = 1 << 1;
const CR0_EM: u64 = 1 << 2;
const CR0_TS: u64 = 1 << 3;
const CR0_NE: u64 = 1 << 5;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;

/// CR0/CR4 set up for FXSAVE and SSE in ring 3; leaves CR0.TS = 1 (the current task
/// is the kernel).
pub fn init() {
    unsafe {
        let mut cr0: u64;
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
        cr0 = (cr0 | CR0_MP | CR0_NE | CR0_TS) & !CR0_EM;
        asm!("mov cr0, {}", in(reg) cr0, options(nostack));
        let mut cr4: u64;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        cr4 |= CR4_OSFXSR | CR4_OSXMMEXCPT;
        asm!("mov cr4, {}", in(reg) cr4, options(nostack));
    }
}

#[inline]
pub fn clear_ts() {
    unsafe { asm!("clts", options(nomem, nostack)) };
}

#[inline]
pub fn set_ts() {
    unsafe {
        asm!("mov {t}, cr0", "or {t}, 8", "mov cr0, {t}", t = out(reg) _, options(nostack));
    }
}

#[allow(dead_code)]
pub fn ts() -> bool {
    let cr0: u64;
    unsafe { asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack)) };
    cr0 & CR0_TS != 0
}

#[allow(dead_code)]
pub fn cr4() -> u64 {
    let v: u64;
    unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack)) };
    v
}

/// FXSAVE64 – requires CR0.TS = 0.
#[inline]
pub unsafe fn save(state: *mut FxState) {
    unsafe { asm!(".byte 0x48, 0x0f, 0xae, 0x07", in("rdi") state, options(nostack)) };
}

/// FXRSTOR64 – requires CR0.TS = 0.
#[inline]
pub unsafe fn restore(state: *const FxState) {
    unsafe { asm!(".byte 0x48, 0x0f, 0xae, 0x0f", in("rdi") state, options(nostack)) };
}
