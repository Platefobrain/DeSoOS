// M13b: stan FPU/SSE procesów (FXSAVE/FXRSTOR).
//
// Kernel jest soft-float – sam nigdy nie używa x87/SSE.  Rejestry FPU/XMM
// należą więc zawsze do procesu użytkownika, który ostatnio działał.
// Scheduler przełącza je "na twardo" (eager) przy każdej zmianie zadania:
//   * z procesu  -> FXSAVE do jego Task (512 B),
//   * do procesu -> CR0.TS = 0 i FXRSTOR z jego Task,
//   * do zadania kernela -> CR0.TS = 1 (instrukcja FPU/SSE w kernelu = #NM
//     = raport błędu kernela).
// Bez leniwego przełączania (pierwsze użycie -> #NM -> zapis): prościej
// i bez podatności typu LazyFP, a przy SMP (M17) nie trzeba śledzić, który
// rdzeń trzyma czyj stan.
//
// Instrukcje jako bajty (`fxsave64 [rdi]` / `fxrstor64 [rdi]`), żeby nie
// zależeć od tego, czy asembler przyjmie je w buildzie soft-float.
// XSAVE/XRSTOR (AVX, CPUID, XCR0) – później.

use core::arch::asm;

/// Obraz FXSAVE (512 B, wyrównany do 16).
#[repr(C, align(16))]
pub struct FxState(pub [u8; 512]);

impl FxState {
    /// Stan po FNINIT + domyślny MXCSR: FCW = 0x037F (wszystkie wyjątki x87
    /// zamaskowane), MXCSR = 0x1F80 (wyjątki SSE zamaskowane), rejestry 0.
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

/// CR0/CR4 pod FXSAVE i SSE w ring 3; zostawia CR0.TS = 1 (bieżące zadanie
/// to kernel).
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

/// FXSAVE64 – wymaga CR0.TS = 0.
#[inline]
pub unsafe fn save(state: *mut FxState) {
    unsafe { asm!(".byte 0x48, 0x0f, 0xae, 0x07", in("rdi") state, options(nostack)) };
}

/// FXRSTOR64 – wymaga CR0.TS = 0.
#[inline]
pub unsafe fn restore(state: *const FxState) {
    unsafe { asm!(".byte 0x48, 0x0f, 0xae, 0x0f", in("rdi") state, options(nostack)) };
}
