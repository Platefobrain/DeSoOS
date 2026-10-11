// M4: IDT + wejścia (stuby) wyjątków 0..31.
// M5: + stuby IRQ0..15 (wektory 0x20..0x2F), dispatch w irq.rs.
//
// Każdy stub uzupełnia ramkę do jednolitego układu (sztuczny kod błędu 0
// tam, gdzie CPU żadnego nie wkłada), odkłada numer wektora i skacze do
// `isr_common`, które zapisuje wszystkie rejestry ogólne i woła
// `exception_dispatch` (exceptions.rs).  Układ ramki na stosie odpowiada
// `ExceptionFrame`.
//
// Stos jest wyrównany do 16 B w chwili `call`: CPU wyrównuje RSP przed
// zapisem ramki (5 qwordów + kod błędu), stub dokłada wektor, a
// isr_common 15 rejestrów -> razem 22 qwordy = 176 B.

use core::arch::global_asm;
use core::ptr::addr_of_mut;

use super::gdt::{
    IST_DOUBLE_FAULT, IST_FATAL, IST_MACHINE_CHECK, IST_NMI,
    KERNEL_CS,
};
use crate::serial_println;

pub const EXCEPTION_VECTORS: usize = 32;

// M5: pierwszy wektor IRQ i ich liczba (PIC: IRQ0..15 -> 0x20..0x2F).
pub const IRQ_BASE: usize = 0x20;
pub const IRQ_VECTORS: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct Gate {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl Gate {
    const MISSING: Gate = Gate {
        offset_low: 0,
        selector: 0,
        ist: 0,
        type_attr: 0,
        offset_mid: 0,
        offset_high: 0,
        reserved: 0,
    };

    fn new(handler: u64, ist: u8, type_attr: u8) -> Gate {
        Gate {
            offset_low: handler as u16,
            selector: KERNEL_CS,
            ist,
            type_attr,
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }
}

// present, DPL 0, 64-bit interrupt gate (IF czyszczone przy wejściu).
const GATE_INTERRUPT: u8 = 0x8E;
// M13a: present, DPL 3 – `int3` z ring 3 trafia do #BP zamiast do #GP.
const GATE_INTERRUPT_USER: u8 = 0xEE;

#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

static mut IDT: [Gate; 256] = [Gate::MISSING; 256];

global_asm!(r#"
.section .text.isr, "ax"

.global isr_common
isr_common:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rdi, rsp
    cld
    call exception_dispatch
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16
    iretq

.global isr_0
isr_0:
    push 0
    push 0
    jmp isr_common

.global isr_1
isr_1:
    push 0
    push 1
    jmp isr_common

.global isr_2
isr_2:
    push 0
    push 2
    jmp isr_common

.global isr_3
isr_3:
    push 0
    push 3
    jmp isr_common

.global isr_4
isr_4:
    push 0
    push 4
    jmp isr_common

.global isr_5
isr_5:
    push 0
    push 5
    jmp isr_common

.global isr_6
isr_6:
    push 0
    push 6
    jmp isr_common

.global isr_7
isr_7:
    push 0
    push 7
    jmp isr_common

.global isr_8
isr_8:
    push 8
    jmp isr_common

.global isr_9
isr_9:
    push 0
    push 9
    jmp isr_common

.global isr_10
isr_10:
    push 10
    jmp isr_common

.global isr_11
isr_11:
    push 11
    jmp isr_common

.global isr_12
isr_12:
    push 12
    jmp isr_common

.global isr_13
isr_13:
    push 13
    jmp isr_common

.global isr_14
isr_14:
    push 14
    jmp isr_common

.global isr_15
isr_15:
    push 0
    push 15
    jmp isr_common

.global isr_16
isr_16:
    push 0
    push 16
    jmp isr_common

.global isr_17
isr_17:
    push 17
    jmp isr_common

.global isr_18
isr_18:
    push 0
    push 18
    jmp isr_common

.global isr_19
isr_19:
    push 0
    push 19
    jmp isr_common

.global isr_20
isr_20:
    push 0
    push 20
    jmp isr_common

.global isr_21
isr_21:
    push 21
    jmp isr_common

.global isr_22
isr_22:
    push 0
    push 22
    jmp isr_common

.global isr_23
isr_23:
    push 0
    push 23
    jmp isr_common

.global isr_24
isr_24:
    push 0
    push 24
    jmp isr_common

.global isr_25
isr_25:
    push 0
    push 25
    jmp isr_common

.global isr_26
isr_26:
    push 0
    push 26
    jmp isr_common

.global isr_27
isr_27:
    push 0
    push 27
    jmp isr_common

.global isr_28
isr_28:
    push 0
    push 28
    jmp isr_common

.global isr_29
isr_29:
    push 29
    jmp isr_common

.global isr_30
isr_30:
    push 30
    jmp isr_common

.global isr_31
isr_31:
    push 0
    push 31
    jmp isr_common


// M5: IRQ0..15 z PIC-a (wektory 0x20..0x2F); ta sama ramka co wyjątki.

.global irq_0
irq_0:
    push 0
    push 32
    jmp isr_common

.global irq_1
irq_1:
    push 0
    push 33
    jmp isr_common

.global irq_2
irq_2:
    push 0
    push 34
    jmp isr_common

.global irq_3
irq_3:
    push 0
    push 35
    jmp isr_common

.global irq_4
irq_4:
    push 0
    push 36
    jmp isr_common

.global irq_5
irq_5:
    push 0
    push 37
    jmp isr_common

.global irq_6
irq_6:
    push 0
    push 38
    jmp isr_common

.global irq_7
irq_7:
    push 0
    push 39
    jmp isr_common

.global irq_8
irq_8:
    push 0
    push 40
    jmp isr_common

.global irq_9
irq_9:
    push 0
    push 41
    jmp isr_common

.global irq_10
irq_10:
    push 0
    push 42
    jmp isr_common

.global irq_11
irq_11:
    push 0
    push 43
    jmp isr_common

.global irq_12
irq_12:
    push 0
    push 44
    jmp isr_common

.global irq_13
irq_13:
    push 0
    push 45
    jmp isr_common

.global irq_14
irq_14:
    push 0
    push 46
    jmp isr_common

.global irq_15
irq_15:
    push 0
    push 47
    jmp isr_common

.pushsection .rodata
.balign 8
.global isr_stub_table
isr_stub_table:
    .quad isr_0
    .quad isr_1
    .quad isr_2
    .quad isr_3
    .quad isr_4
    .quad isr_5
    .quad isr_6
    .quad isr_7
    .quad isr_8
    .quad isr_9
    .quad isr_10
    .quad isr_11
    .quad isr_12
    .quad isr_13
    .quad isr_14
    .quad isr_15
    .quad isr_16
    .quad isr_17
    .quad isr_18
    .quad isr_19
    .quad isr_20
    .quad isr_21
    .quad isr_22
    .quad isr_23
    .quad isr_24
    .quad isr_25
    .quad isr_26
    .quad isr_27
    .quad isr_28
    .quad isr_29
    .quad isr_30
    .quad isr_31

.balign 8
.global irq_stub_table
irq_stub_table:
    .quad irq_0
    .quad irq_1
    .quad irq_2
    .quad irq_3
    .quad irq_4
    .quad irq_5
    .quad irq_6
    .quad irq_7
    .quad irq_8
    .quad irq_9
    .quad irq_10
    .quad irq_11
    .quad irq_12
    .quad irq_13
    .quad irq_14
    .quad irq_15
.popsection
"#);

unsafe extern "C" {
    static isr_stub_table: [u64; EXCEPTION_VECTORS];
    static irq_stub_table: [u64; IRQ_VECTORS];
}

// M16b: stuby wektorów MSI (0x30..0x3F) i "spurious" LAPIC (0xFF).
global_asm!(r#"
.section .text.isr, "ax"
.global msi_0
msi_0:
    push 0
    push 48
    jmp isr_common

.global msi_1
msi_1:
    push 0
    push 49
    jmp isr_common

.global msi_2
msi_2:
    push 0
    push 50
    jmp isr_common

.global msi_3
msi_3:
    push 0
    push 51
    jmp isr_common

.global msi_4
msi_4:
    push 0
    push 52
    jmp isr_common

.global msi_5
msi_5:
    push 0
    push 53
    jmp isr_common

.global msi_6
msi_6:
    push 0
    push 54
    jmp isr_common

.global msi_7
msi_7:
    push 0
    push 55
    jmp isr_common

.global msi_8
msi_8:
    push 0
    push 56
    jmp isr_common

.global msi_9
msi_9:
    push 0
    push 57
    jmp isr_common

.global msi_10
msi_10:
    push 0
    push 58
    jmp isr_common

.global msi_11
msi_11:
    push 0
    push 59
    jmp isr_common

.global msi_12
msi_12:
    push 0
    push 60
    jmp isr_common

.global msi_13
msi_13:
    push 0
    push 61
    jmp isr_common

.global msi_14
msi_14:
    push 0
    push 62
    jmp isr_common

.global msi_15
msi_15:
    push 0
    push 63
    jmp isr_common

.global apic_timer
apic_timer:
    push 0
    push 64
    jmp isr_common

.global apic_resched
apic_resched:
    push 0
    push 65
    jmp isr_common

.global apic_halt
apic_halt:
    push 0
    push 66
    jmp isr_common

.global apic_tlb
apic_tlb:
    push 0
    push 67
    jmp isr_common

.global apic_spurious
apic_spurious:
    push 0
    push 255
    jmp isr_common

.pushsection .rodata
.balign 8
.global msi_stub_table
msi_stub_table:
    .quad msi_0
    .quad msi_1
    .quad msi_2
    .quad msi_3
    .quad msi_4
    .quad msi_5
    .quad msi_6
    .quad msi_7
    .quad msi_8
    .quad msi_9
    .quad msi_10
    .quad msi_11
    .quad msi_12
    .quad msi_13
    .quad msi_14
    .quad msi_15
.popsection
"#);

unsafe extern "C" {
    static msi_stub_table: [u64; super::msi::MSI_VECTORS];
    fn apic_spurious();
    fn apic_timer();
    fn apic_resched();
    fn apic_halt();
    fn apic_tlb();
}

/// Stos IST dla wyjątku.  Tylko wyjątki, które nie przełączają zadań.
///
/// NIEZMIENNIK (M16): wektory IRQ (0x20–0x2F) NIE mogą mieć IST.  Na tym
/// opiera się `irq::dispatch -> sched::preempt_irq() -> user::kill_from_interrupt`:
/// ramka przerwania leży na stosie kernela przerwanego zadania (z ring 3:
/// TSS.RSP0 = jego stos), więc gdy `preempt()` przełączy zadanie i kiedyś
/// wróci, `current` znowu jest właścicielem `frame`.  Ze wspólnym stosem IST
/// ramki różnych zadań nadpisywałyby się.  Pilnuje tego samotest
/// (exceptions.rs) i asercja w sched::schedule().
fn ist_for_vector(vector: usize) -> u8 {
    match vector {
        8 => IST_DOUBLE_FAULT,
        2 => IST_NMI,
        18 => IST_MACHINE_CHECK,
        // M17b.c: #PF bez IST – z ring 3 na stosie kernela zadania (TSS.RSP0),
        // więc obsługa może blokować (leniwy przydział stron procesu, M17b.d).
        // Przepełnienie stosu kernela: #PF nie zmieści ramki -> #DF (IST).
        6 | 10 | 11 | 12 | 13 => IST_FATAL,
        _ => 0,
    }
}

pub fn init() {
    serial_println!("[ARCH] Initializing IDT...");

    unsafe {
        let idt = addr_of_mut!(IDT);

        for vector in 0..EXCEPTION_VECTORS {
            let handler = isr_stub_table[vector];
            let attr = if vector == 3 { GATE_INTERRUPT_USER } else { GATE_INTERRUPT };
            (*idt)[vector] = Gate::new(handler, ist_for_vector(vector), attr);
        }

        // IRQ: bramki przerwań (IF=0 w handlerze), zwykły stos kernela –
        // bez IST (patrz niezmiennik przy ist_for_vector).
        for irq in 0..IRQ_VECTORS {
            let handler = irq_stub_table[irq];
            (*idt)[IRQ_BASE + irq] = Gate::new(handler, 0, GATE_INTERRUPT);
        }
        // M16b: MSI/MSI-X – tak samo bez IST (ten sam niezmiennik).
        for i in 0..super::msi::MSI_VECTORS {
            (*idt)[super::msi::MSI_BASE + i] = Gate::new(msi_stub_table[i], 0, GATE_INTERRUPT);
        }
        (*idt)[super::lapic::SPURIOUS_VECTOR as usize] =
            Gate::new(apic_spurious as *const () as u64, 0, GATE_INTERRUPT);
        // M17: timer LAPIC (AP) i IPI – bez IST (ten sam niezmiennik co IRQ).
        (*idt)[super::lapic::TIMER_VECTOR as usize] = Gate::new(apic_timer as *const () as u64, 0, GATE_INTERRUPT);
        (*idt)[super::lapic::RESCHED_VECTOR as usize] = Gate::new(apic_resched as *const () as u64, 0, GATE_INTERRUPT);
        (*idt)[super::lapic::HALT_VECTOR as usize] = Gate::new(apic_halt as *const () as u64, 0, GATE_INTERRUPT);
        // M17a.b: TLB shootdown – bez IST i bez BKL (exceptions.rs).
        (*idt)[super::tlb::TLB_VECTOR as usize] = Gate::new(apic_tlb as *const () as u64, 0, GATE_INTERRUPT);
    }
    load();

    serial_println!(
        "[ARCH] IDT loaded ({} exception vectors + {} IRQ vectors at {:#x}, IST: #DF=1 NMI=2 #MC=3 #GP/#UD/...=4, #PF without IST)",
        EXCEPTION_VECTORS,
        IRQ_VECTORS,
        IRQ_BASE
    );
}

/// lidt – wspólna IDT (M17: wołają też AP przy starcie).
pub fn load() {
    unsafe {
        let pointer = IdtPointer {
            limit: (core::mem::size_of::<[Gate; 256]>() - 1) as u16,
            base: addr_of_mut!(IDT) as u64,
        };
        core::arch::asm!(
            "lidt [{}]",
            in(reg) &pointer,
            options(readonly, nostack, preserves_flags)
        );
    }
}

/// Numer IST ustawiony w bramce danego wektora (do testów).
#[cfg(selftest)]
pub fn gate_ist(vector: usize) -> u8 {
    unsafe { (*addr_of_mut!(IDT))[vector].ist }
}

/// DPL bramki (do testów: #BP musi mieć 3).
#[cfg(selftest)]
pub fn gate_dpl(vector: usize) -> u8 {
    unsafe { ((*addr_of_mut!(IDT))[vector].type_attr >> 5) & 3 }
}

/// Czy bramka wektora jest present (do testów).
#[cfg(selftest)]
pub fn gate_present(vector: usize) -> bool {
    unsafe { (*addr_of_mut!(IDT))[vector].type_attr & 0x80 != 0 }
}
