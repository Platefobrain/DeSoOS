// M4: GDT + TSS.
//
// Układ selektorów (zgodny z wymaganiami SYSCALL/SYSRET na M13–M14:
// STAR[47:32] = 0x08 -> CS = 0x08, SS = 0x10;
// STAR[63:48] = 0x13 -> SS = 0x13 + 8 = 0x1b, CS = 0x13 + 16 = 0x23 – RPL 3
// już w selektorze, bo AMD go nie wymusza, patrz syscall.rs):
//
//   0x00  null
//   0x08  kernel code (64-bit)
//   0x10  kernel data
//   0x18  user data   (DPL 3)
//   0x20  user code   (DPL 3, 64-bit)
//   0x28  TSS (deskryptor 16-bajtowy, zajmuje sloty 5 i 6)

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

// Numery IST (1..=7) używane przez bramki IDT.
pub const IST_DOUBLE_FAULT: u8 = 1;
pub const IST_NMI: u8 = 2;
pub const IST_MACHINE_CHECK: u8 = 3;
/// #UD, #NP, #SS, #GP, #TS – wyjątki po których kernel i tak się zatrzymuje.
pub const IST_FATAL: u8 = 4;
/// M17b.c: #PF już bez IST (stos zadania) – stos 5 zostaje w rezerwie.
#[allow(dead_code)]
pub const IST_PAGE_FAULT: u8 = 5;

const IST_COUNT: usize = 5;
pub const IST_STACK_SIZE: usize = 16 * 1024;

// RSP0 – stos, na który CPU przełączy się przy przerwaniu / wyjątku z ring 3.
// Jeden TSS na CPU; M13a: scheduler przy każdym przełączeniu wpisuje tu
// szczyt stosu kernela bieżącego zadania (`set_rsp0`).  Na starcie: stos
// startowy z DSB.
fn kernel_stack_top() -> u64 {
    crate::memory::kernel_layout().stack_top
}

/// TSS procesora `c` (M17: każdy CPU ma własny TSS i własną GDT – deskryptor
/// TSS w GDT dostaje bit "busy" po `ltr`, więc nie da się ich współdzielić).
fn tss(c: usize) -> *mut Tss {
    unsafe { addr_of_mut!(TSS[c]) }
}

/// Ustawia TSS.RSP0 bieżącego CPU (wołać przy wyłączonych przerwaniach – scheduler).
pub fn set_rsp0(top: u64) {
    unsafe { core::ptr::write_unaligned(addr_of_mut!((*tss(cpu::id())).rsp[0]), top) };
}

/// Aktualne TSS.RSP0 bieżącego CPU (testy / diagnostyka).
#[allow(dead_code)]
pub fn rsp0() -> u64 {
    unsafe { core::ptr::read_unaligned(addr_of!((*tss(cpu::id())).rsp[0])) }
}

/// Deskryptor GDT (testy: segmenty użytkownika).
#[allow(dead_code)]
pub fn descriptor(index: usize) -> u64 {
    unsafe { (*addr_of!(GDT[cpu::id()]))[index] }
}

// Stosy IST na start (.bss, bez stron-strażników).  M16: po starcie
// pamięci `move_ist_to_guarded_stacks` przenosi IST na stosy z obszaru
// stosów zadań (strona-strażnik pod spodem – przepełnienie = #PF/#DF,
// a nie ciche nadpisanie sąsiednich danych w .bss).
#[repr(C, align(16))]
struct IstStack([u8; IST_STACK_SIZE]);

static mut IST_STACKS: [IstStack; IST_COUNT] =
    [const { IstStack([0; IST_STACK_SIZE]) }; IST_COUNT];

/// Zakresy [dół, szczyt) stosów IST w użyciu (po przeniesieniu: nowe),
/// M17: dla każdego CPU.
static IST_RANGES: [[[core::sync::atomic::AtomicU64; 2]; IST_COUNT]; MAX_CPUS] =
    [const { [const { [core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)] }; IST_COUNT] }; MAX_CPUS];

/// Szczyt stosu IST nr `ist` (1..=IST_COUNT) z TSS bieżącego CPU (testy / diagnostyka).
#[allow(dead_code)]
pub fn ist_top(ist: u8) -> u64 {
    unsafe { core::ptr::read_unaligned(addr_of!((*tss(cpu::id())).ist[ist as usize - 1])) }
}

/// Czy `rsp` leży na którymś stosie IST (starym w .bss albo nowym).
/// M16: scheduler nie może przełączyć zadania na stosie IST – kolejny
/// wyjątek tego typu zacząłby od szczytu tego samego stosu i nadpisał
/// ramkę zadania, które oddało CPU.
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

/// IST procesora `c` na nowe stosy ze stronami-strażnikami; `false` = brak pamięci.
fn guarded_ist_for(c: usize) -> usize {
    use core::sync::atomic::Ordering;
    let mut moved = 0;
    for i in 0..IST_COUNT {
        let Some(stack) = crate::sched::stack::TaskStack::new() else {
            continue;
        };
        let (bottom, top) = (stack.bottom(), stack.top());
        core::mem::forget(stack); // stos IST żyje do końca działania systemu
        IST_RANGES[c][i][0].store(bottom, Ordering::Relaxed);
        IST_RANGES[c][i][1].store(top, Ordering::Relaxed);
        unsafe { core::ptr::write_unaligned(addr_of_mut!((*tss(c)).ist[i]), top) };
        moved += 1;
    }
    moved
}

/// M17: przygotowuje GDT + TSS procesora AP `c` (stosy IST ze strażnikami).
/// Woła BSP przed obudzeniem AP; `false` – brak pamięci na stosy.
pub fn prepare_cpu(c: usize) -> bool {
    build(c);
    guarded_ist_for(c) == IST_COUNT
}

/// M17: AP ładuje swoją GDT i TSS (przygotowane przez `prepare_cpu`).
pub fn load_cpu(c: usize) {
    unsafe { load(c) };
}

/// M16: przenosi IST na stosy ze stronami-strażnikami (stack.rs).  Wołać po
/// starcie pamięci, przy wyłączonych przerwaniach i NIE na stosie IST.
/// Stare stosy w .bss zostają (nieużywane).
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

// Bit "accessed" ustawiony z góry, żeby CPU nie musiał zapisywać do GDT.
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

/// Wypełnia GDT i TSS procesora `c` (RSP0 = stos startowy, IST z .bss
/// tylko dla BSP – AP dostaje swoje w `prepare_cpu`).
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
        // Brak I/O permission bitmap: offset poza limitem TSS.
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

/// lgdt + przeładowanie segmentów + ltr dla procesora `c`.
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

        // Przeładowanie CS wymaga far return; reszta rejestrów segmentowych
        // ładuje się zwykłym mov.
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
