// M14: wejście do kernela przez SYSCALL i powrót przez SYSRET.
//
// SYSCALL (z ring 3): RIP -> RCX, RFLAGS -> R11, CS/SS z MSR STAR, RIP z
// LSTAR, RFLAGS &= ~SFMASK (IF = 0).  Stos NIE jest przełączany (TSS.RSP0
// dotyczy tylko przerwań/wyjątków), więc pierwsze instrukcje muszą same
// wziąć stos kernela:
//
//   swapgs                 GS.base = blok per CPU (MSR KERNEL_GS_BASE)
//   mov gs:[8], rsp        RSP użytkownika na bok
//   mov rsp, gs:[0]        stos kernela bieżącego zadania (ustawia scheduler)
//   push gs:[8]
//   swapgs                 GS.base znów użytkownika
//
// GS kernela jest aktywne tylko przez te kilka instrukcji (IF = 0), więc
// przełączanie zadań w trakcie syscalla i przerwania nie muszą o nim wiedzieć.
//
// Dalej: ramka SyscallFrame (rejestry), syscall_dispatch (user/syscalls.rs),
// cli, odtworzenie rejestrów, RSP użytkownika, SYSRET.  SYSRET z
// niekanonicznym RCX dałby #GP w ring 0 na stosie użytkownika (znana pułapka
// Intela) – dispatch sprawdza RIP powrotu i w razie czego kończy proces.
//
// ABI (jak w Linuksie): RAX = numer, argumenty RDI, RSI, RDX, R10, R8, R9,
// wynik w RAX (ujemny = -errno).  RCX i R11 są niszczone, reszta zachowana.

use core::arch::global_asm;

use super::gdt::KERNEL_CS;

const IA32_EFER: u32 = 0xC000_0080;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;
const IA32_GS_BASE: u32 = 0xC000_0101;
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;
const EFER_SCE: u64 = 1;

/// RFLAGS czyszczone przy wejściu: TF, IF, DF, NT, AC.
pub const SFMASK: u64 = (1 << 8) | (1 << 9) | (1 << 10) | (1 << 14) | (1 << 18);

/// Blok per CPU (M17: po jednym na rdzeń; KERNEL_GS_BASE każdego CPU
/// wskazuje jego blok).
#[repr(C)]
pub struct PerCpu {
    /// Szczyt stosu kernela bieżącego zadania (offset 0 – używa go asembler).
    pub kernel_rsp: u64,
    /// RSP użytkownika na chwilę wejścia (offset 8).
    pub user_rsp: u64,
}

static mut PERCPU: [PerCpu; super::cpu::MAX_CPUS] =
    [const { PerCpu { kernel_rsp: 0, user_rsp: 0 } }; super::cpu::MAX_CPUS];

fn percpu(c: usize) -> *mut PerCpu {
    unsafe { core::ptr::addr_of_mut!(PERCPU[c]) }
}

/// Rejestry procesu odłożone przez syscall_entry (kolejność = odwrotność push).
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
    /// RIP powrotu (z RCX).
    pub rip: u64,
    /// RFLAGS użytkownika (z R11).
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

/// Baza selektorów SYSRET w STAR[63:48] – z RPL 3 (patrz init_cpu).
pub const SYSRET_BASE: u64 = 0x10 | 3;

/// Włącza SYSCALL/SYSRET.  Selektory (gdt.rs): STAR[47:32] = 0x08 ->
/// SYSCALL: CS 0x08, SS 0x10; STAR[63:48] = 0x13 -> SYSRET: SS 0x18|3,
/// CS 0x20|3 (64-bit).
pub fn init() {
    init_cpu(super::cpu::id());
}

/// MSR-y SYSCALL bieżącego procesora `c` (BSP: init, AP: przy starcie).
pub fn init_cpu(c: usize) {
    unsafe {
        // STAR[63:48] = 0x13 (0x10 | RPL 3), jak w Linuksie (__USER32_CS z RPL 3):
        // SYSRET daje CS = 0x13 + 16 = 0x23, SS = 0x13 + 8 = 0x1b.  Intel sam
        // wymusza RPL 3, AMD bierze selektor tak, jak jest – z 0x10 na Ryzenie
        // (KVM, Legion) SS po SYSRET = 0x18 (RPL 0), a następny powrót z
        // przerwania do procesu (iretq) kończył się #GP(0x18) w kernelu.
        wrmsr(IA32_STAR, ((KERNEL_CS as u64) << 32) | (SYSRET_BASE << 48));
        wrmsr(IA32_LSTAR, syscall_entry as *const () as u64);
        wrmsr(IA32_FMASK, SFMASK);
        wrmsr(IA32_GS_BASE, 0);
        wrmsr(IA32_KERNEL_GS_BASE, percpu(c) as u64);
        wrmsr(IA32_EFER, rdmsr(IA32_EFER) | EFER_SCE);
        (*percpu(c)).kernel_rsp = super::gdt::rsp0();
    }
}

/// Stos kernela dla SYSCALL (scheduler, razem z TSS.RSP0) – bieżący CPU.
pub fn set_kernel_stack(top: u64) {
    unsafe { (*percpu(super::cpu::id())).kernel_rsp = top };
}

/// (EFER.SCE, STAR, LSTAR, SFMASK, KERNEL_GS_BASE, kernel_rsp) – testy.
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
