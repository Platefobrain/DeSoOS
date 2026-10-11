// M5: obsługa przerwań sprzętowych (IRQ0..15 z PIC 8259).
//
// Ścieżka: urządzenie -> PIC -> wektor 0x20+n -> stub `irq_n` (idt.rs)
//   -> isr_common -> exception_dispatch -> irq::dispatch -> handler -> EOI.
//
// Handler działa z wyłączonymi przerwaniami (bramka typu interrupt), na
// stosie przerwanego kodu kernela.  Musi być krótki; może alokować (heap
// i alokator ramek wyłączają przerwania na czas operacji).
//
// EOI jest wysyłane PO handlerze.  Uwaga na M12: jeśli handler timera
// będzie przełączał zadania, EOI trzeba wysłać przed przełączeniem.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::exceptions::ExceptionFrame;
use super::idt::IRQ_BASE;
use super::interrupts::without_interrupts;
use super::pic::{self, IRQ_COUNT};
use crate::serial_println;

/// Handler IRQ; argument = numer linii (0..15).
pub type IrqHandler = fn(irq: u8);

// Wskaźniki funkcji jako usize (0 = brak handlera).
static HANDLERS: [AtomicUsize; IRQ_COUNT] = [const { AtomicUsize::new(0) }; IRQ_COUNT];
static COUNTS: [AtomicU64; IRQ_COUNT] = [const { AtomicU64::new(0) }; IRQ_COUNT];
static UNHANDLED: AtomicU64 = AtomicU64::new(0);

/// Remap PIC-a (wszystkie linie zamaskowane).  M17: jeśli są MADT i I/O
/// APIC – przerwania ISA idą przez I/O APIC, a PIC zostaje wyłączony.
/// Przerwania pozostają wyłączone – włącza je dopiero `interrupts::enable()`
/// po rejestracji handlerów.
pub fn init() {
    serial_println!("[IRQ] Remapping PIC 8259: IRQ0-7 -> {:#x}, IRQ8-15 -> {:#x}",
        pic::MASTER_OFFSET, pic::SLAVE_OFFSET);
    pic::init();
    serial_println!("[IRQ] PIC ready, all lines masked (IMR = {:#06x})", pic::masks());
    super::ioapic::init();
}

/// M17: czy przerwania ISA idą przez I/O APIC (inaczej PIC 8259).
pub fn ioapic_mode() -> bool {
    super::ioapic::active()
}

/// Odmaskowuje linię ISA (PIC albo I/O APIC).
pub fn unmask(irq: u8) {
    if ioapic_mode() { super::ioapic::unmask(irq) } else { pic::unmask(irq) }
}

/// Maskuje linię ISA (PIC albo I/O APIC).
pub fn mask(irq: u8) {
    if ioapic_mode() { super::ioapic::mask(irq) } else { pic::mask(irq) }
}

pub fn is_masked(irq: u8) -> bool {
    if ioapic_mode() { super::ioapic::is_masked(irq) } else { pic::masks() & (1 << irq) != 0 }
}

/// Rejestruje handler.  `false`, jeśli linia ma już handler.
/// Nie odmaskowuje linii – to robi sterownik (`pic::unmask`), gdy jest gotowy.
pub fn register(irq: u8, handler: IrqHandler) -> bool {
    assert!((irq as usize) < IRQ_COUNT, "irq: bad line {}", irq);
    HANDLERS[irq as usize]
        .compare_exchange(0, handler as usize, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

/// Zdejmuje handler (i maskuje linię).
#[allow(dead_code)]
pub fn unregister(irq: u8) {
    assert!((irq as usize) < IRQ_COUNT, "irq: bad line {}", irq);
    without_interrupts(|| {
        mask(irq);
        HANDLERS[irq as usize].store(0, Ordering::SeqCst);
    });
}

/// Ile razy dana linia została obsłużona (bez fałszywych IRQ).
#[allow(dead_code)]
pub fn count(irq: u8) -> u64 {
    COUNTS[irq as usize].load(Ordering::Relaxed)
}

#[allow(dead_code)]
pub fn unhandled_count() -> u64 {
    UNHANDLED.load(Ordering::Relaxed)
}

/// Wołane z `exception_dispatch` dla wektorów 0x20..0x2F.
pub fn dispatch(frame: &mut ExceptionFrame) {
    let irq = (frame.vector as usize - IRQ_BASE) as u8;

    // Fałszywe IRQ7/IRQ15 z PIC-a: bez EOI (is_spurious samo obsługuje kaskadę).
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
        // Nikt się nie zgłosił – maskujemy linię, żeby nie zalała systemu.
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

    // M12: przełączenie zadania dopiero PO EOI – inaczej PIC czekałby na
    // EOI, dopóki przerwane zadanie znowu nie dostanie CPU.
    after_interrupt(frame);
}

/// Wspólny koniec przerwania sprzętowego (IRQ z PIC-a, M16b: MSI) – już po
/// EOI: wywłaszczenie i kill procesu, który był w ring 3.
pub fn after_interrupt(frame: &mut ExceptionFrame) {
    // Czy przerwany kontekst trzymał BKL (ustawione na wejściu tego
    // przerwania; do tej chwili IF = 0, więc nikt tego nie nadpisał).
    let had_bkl = super::cpu::irq_had_bkl();
    // M17a: część "w przerwaniu" skończona (przełączenie zadania poniżej
    // może oddać CPU innemu zadaniu – ono już nie jest w przerwaniu).
    super::cpu::set_in_interrupt(false);
    // M17: przerwany kod kernela miał włączone przerwania (mógł więc zostać
    // wywłaszczony) – jeśli inny CPU czeka na Big Kernel Lock, przepuszczamy
    // go.  Bez tego zadanie kernela kręcące się na jednym CPU zagłodziłoby
    // resztę (np. przerwania zegara na BSP).
    //
    // M17a: tylko gdy przerwany kod TRZYMAŁ BKL przed przerwaniem (długie
    // zadanie kernela).  Przerwanie, które obudziło bezczynny CPU z `hlt`,
    // wzięło BKL tylko dla siebie – oddanie go i ponowne stanięcie w kolejce
    // kosztowało pełny obrót kolejki przy każdym ticku każdego CPU: BKL
    // krążył tysiące razy na sekundę, a bezczynne CPU nie zdążały wziąć
    // gotowych zadań (sekundy zamiast milisekund).
    if frame.cs & 3 == 0 && frame.rflags & (1 << 9) != 0 && had_bkl {
        crate::sched::bkl::yield_if_contended();
    }
    crate::sched::preempt_irq(had_bkl);

    // M13a: `kill` procesu, który jest w ring 3 – kończymy go przy
    // najbliższym przerwaniu (proces sam tego nie sprawdzi).
    //
    // Kolejność z preempt() jest poprawna: `frame` leży na stosie kernela
    // TEGO zadania (IRQ/MSI bez IST – idt.rs), a preempt() wraca tu dopiero,
    // gdy scheduler znowu wybierze to zadanie – wtedy current == właściciel
    // ramki, więc should_exit() i redirect_to_exit() dotyczą tego samego
    // zadania.
    if frame.cs & 3 == 3 && crate::sched::should_exit() {
        crate::user::kill_from_interrupt(frame);
    }
}
