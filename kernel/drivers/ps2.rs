// M6: kontroler PS/2 (Intel 8042).
//
// Porty: 0x60 = dane (odczyt: bajt od urządzenia, zapis: bajt do
// urządzenia), 0x64 = status (odczyt) / komenda kontrolera (zapis).
//
// Konfiguracja po `init()`:
//   * port 1 (klawiatura) włączony, IRQ1 włączone,
//   * port 2 (mysz, M11b): włączony, jeśli mysz odpowie; tryb IntelliMouse
//     (kółko) przez "magiczną" sekwencję częstotliwości 200/100/80,
//   * translacja włączona: klawiatura mówi zestawem 2, kontroler
//     tłumaczy na zestaw 1 (prostszy, jeden bajt na większość klawiszy).
//
// Czekanie na kontroler: przy włączonych przerwaniach przez `hlt`
// (budzi tick co 1 ms – nie ma ciasnej pętli na portach), przy
// wyłączonych – ograniczona liczba prób.

use crate::arch::x86_64::interrupts;
use crate::arch::x86_64::port::{inb, outb};
use crate::serial_println;

const DATA: u16 = 0x60;
const STATUS: u16 = 0x64;
const COMMAND: u16 = 0x64;

const STATUS_OUTPUT_FULL: u8 = 1 << 0; // jest bajt do odczytu z 0x60
const STATUS_INPUT_FULL: u8 = 1 << 1; // kontroler jeszcze nie przyjął zapisu
pub const STATUS_AUX_DATA: u8 = 1 << 5; // bajt w 0x60 pochodzi z portu 2 (mysz)

const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_DISABLE_PORT2: u8 = 0xA7;
const CMD_ENABLE_PORT2: u8 = 0xA8;
const CMD_TEST_PORT2: u8 = 0xA9;
const CMD_WRITE_PORT2: u8 = 0xD4; // następny bajt danych idzie do myszy
#[cfg(selftest)]
const CMD_WRITE_PORT2_OUTPUT: u8 = 0xD3; // "udawaj bajt od myszy"
#[allow(dead_code)]
const CMD_SELF_TEST: u8 = 0xAA;
#[allow(dead_code)]
const CMD_TEST_PORT1: u8 = 0xAB;
const CMD_DISABLE_PORT1: u8 = 0xAD;
const CMD_ENABLE_PORT1: u8 = 0xAE;
#[cfg(selftest)]
const CMD_WRITE_PORT1_OUTPUT: u8 = 0xD2; // "udawaj bajt od klawiatury"

pub const CONFIG_PORT1_IRQ: u8 = 1 << 0;
pub const CONFIG_PORT2_IRQ: u8 = 1 << 1;
pub const CONFIG_PORT1_CLOCK_OFF: u8 = 1 << 4;
pub const CONFIG_PORT2_CLOCK_OFF: u8 = 1 << 5;
pub const CONFIG_TRANSLATION: u8 = 1 << 6;

// Komendy do klawiatury (przez port danych).
#[allow(dead_code)]
const KBD_RESET: u8 = 0xFF;
const KBD_ENABLE_SCANNING: u8 = 0xF4;
pub const KBD_SET_LEDS: u8 = 0xED;
pub const KBD_ACK: u8 = 0xFA;
pub const KBD_RESEND: u8 = 0xFE;
const KBD_SELF_TEST_OK: u8 = 0xAA;

// Komendy myszy.
const MOUSE_RESET: u8 = 0xFF;
const MOUSE_SET_DEFAULTS: u8 = 0xF6;
const MOUSE_SET_SAMPLE_RATE: u8 = 0xF3;
const MOUSE_GET_ID: u8 = 0xF2;
const MOUSE_ENABLE_REPORTING: u8 = 0xF4;

/// ID myszy po inicjalizacji: 0 = zwykła (3 bajty), 3 = IntelliMouse
/// (4 bajty, kółko), 4 = Explorer (4 bajty, kółko + przyciski 4/5);
/// 0xFF = brak myszy.
static MOUSE_ID: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0xFF);

pub fn mouse_id() -> Option<u8> {
    match MOUSE_ID.load(core::sync::atomic::Ordering::Relaxed) {
        0xFF => None,
        id => Some(id),
    }
}

fn status() -> u8 {
    unsafe { inb(STATUS) }
}

/// Czeka, aż `ready()` zwróci true, najwyżej ok. `timeout_ms`.
fn wait_until(timeout_ms: u64, ready: impl Fn() -> bool) -> bool {
    if interrupts::are_enabled() {
        let deadline = crate::time::ticks() + timeout_ms + 1;
        while crate::time::ticks() < deadline {
            if ready() {
                return true;
            }
            interrupts::enable_and_hlt();
        }
        ready()
    } else {
        // Bez przerwań ticki stoją – ograniczamy liczbę prób (~1 µs każda).
        for _ in 0..timeout_ms * 1000 {
            if ready() {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }
}

fn wait_input_empty() -> bool {
    wait_until(20, || status() & STATUS_INPUT_FULL == 0)
}

fn wait_output_full(timeout_ms: u64) -> bool {
    wait_until(timeout_ms, || status() & STATUS_OUTPUT_FULL != 0)
}

pub fn write_command(cmd: u8) -> bool {
    if !wait_input_empty() {
        return false;
    }
    unsafe { outb(COMMAND, cmd) };
    true
}

/// Wysyła bajt do urządzenia na porcie 1 (klawiatury).
pub fn write_data(byte: u8) -> bool {
    if !wait_input_empty() {
        return false;
    }
    unsafe { outb(DATA, byte) };
    true
}

fn read_data(timeout_ms: u64) -> Option<u8> {
    if wait_output_full(timeout_ms) {
        Some(unsafe { inb(DATA) })
    } else {
        None
    }
}

/// Odczyt bajtu z handlera IRQ: (bajt, czy z portu 2).  `None`, gdy
/// bufor jest pusty (przerwanie bez danych).
pub fn read_irq_byte() -> Option<(u8, bool)> {
    let s = status();
    if s & STATUS_OUTPUT_FULL == 0 {
        return None;
    }
    let byte = unsafe { inb(DATA) };
    Some((byte, s & STATUS_AUX_DATA != 0))
}

/// Bajt od myszy (port 2); bajty klawiatury w międzyczasie są pomijane.
fn read_aux(timeout_ms: u64) -> Option<u8> {
    let deadline_tries = timeout_ms.max(1);
    for _ in 0..deadline_tries {
        if !wait_output_full(1) {
            continue;
        }
        let st = status();
        let byte = unsafe { inb(DATA) };
        if st & STATUS_AUX_DATA != 0 {
            return Some(byte);
        }
    }
    None
}

/// Komenda do myszy (przez 0xD4) i czekanie na ACK.
fn mouse_command(byte: u8) -> bool {
    for _ in 0..3 {
        if !write_command(CMD_WRITE_PORT2) || !write_data(byte) {
            return false;
        }
        match read_aux(50) {
            Some(KBD_ACK) => return true,
            Some(KBD_RESEND) => continue,
            _ => return false,
        }
    }
    false
}

fn mouse_set_rate(rate: u8) -> bool {
    mouse_command(MOUSE_SET_SAMPLE_RATE) && mouse_command(rate)
}

fn mouse_get_id() -> Option<u8> {
    if !mouse_command(MOUSE_GET_ID) {
        return None;
    }
    read_aux(50)
}

/// Port 2: test, reset myszy, tryb z kółkiem, włączenie raportowania.
/// Zwraca ID myszy albo None (brak myszy / błąd – system działa dalej).
fn init_mouse() -> Option<u8> {
    write_command(CMD_TEST_PORT2);
    if read_data(100)? != 0x00 {
        return None;
    }
    write_command(CMD_ENABLE_PORT2);

    // Reset: ACK, 0xAA (self-test OK), 0x00 (ID).
    if !mouse_command(MOUSE_RESET) {
        return None;
    }
    if read_aux(750) != Some(KBD_SELF_TEST_OK) {
        return None;
    }
    let _ = read_aux(50); // ID 0x00
    mouse_command(MOUSE_SET_DEFAULTS);

    // IntelliMouse: 200, 100, 80 -> ID 3 (kółko).
    // Explorer: potem 200, 200, 80 -> ID 4 (kółko + przyciski 4/5).
    let mut id = 0;
    if mouse_set_rate(200) && mouse_set_rate(100) && mouse_set_rate(80) {
        id = mouse_get_id().unwrap_or(0);
        if id == 3 && mouse_set_rate(200) && mouse_set_rate(200) && mouse_set_rate(80) {
            id = mouse_get_id().unwrap_or(3);
        }
    }
    mouse_set_rate(100); // zwykła częstotliwość raportów
    if !mouse_command(MOUSE_ENABLE_REPORTING) {
        return None;
    }
    Some(id)
}

fn flush() {
    for _ in 0..32 {
        if status() & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        unsafe { inb(DATA) };
    }
}

fn read_config() -> Option<u8> {
    if !write_command(CMD_READ_CONFIG) {
        return None;
    }
    read_data(20)
}

fn write_config(config: u8) -> bool {
    write_command(CMD_WRITE_CONFIG) && write_data(config)
}

/// Aktualna konfiguracja kontrolera (do testów / diagnostyki).
/// Z wyłączonymi przerwaniami: gdy IRQ1 jest włączone, odpowiedź kontrolera
/// też wywołuje IRQ1 i handler klawiatury zabrałby ją z bufora.
#[allow(dead_code)]
pub fn config() -> Option<u8> {
    interrupts::without_interrupts(read_config)
}

/// Wysyła komendę do klawiatury i czeka na ACK (ponawia przy RESEND).
fn keyboard_command(byte: u8) -> bool {
    for _ in 0..3 {
        if !write_data(byte) {
            return false;
        }
        match read_data(50) {
            Some(KBD_ACK) => return true,
            Some(KBD_RESEND) => continue,
            _ => return false,
        }
    }
    false
}

pub enum Ps2Error {
    NoController,
    Timeout(&'static str),
}

impl core::fmt::Display for Ps2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Ps2Error::NoController => write!(f, "no i8042 controller (status port = 0xFF)"),
            Ps2Error::Timeout(what) => write!(f, "timeout: {}", what),
        }
    }
}

/// Inicjalizuje kontroler i klawiaturę.  IRQ1 musi być wtedy zamaskowane
/// w PIC-u; przerwania CPU mogą być włączone (lepiej – czekamy przez hlt).
pub fn init() -> Result<(), Ps2Error> {
    // Brak kontrolera (część nowych komputerów bez "legacy"): port zwraca 0xFF.
    if status() == 0xFF {
        return Err(Ps2Error::NoController);
    }

    // 1. Wyłącz oba porty i opróżnij bufor (firmware mógł coś zostawić).
    write_command(CMD_DISABLE_PORT1);
    write_command(CMD_DISABLE_PORT2);
    flush();

    // 2. Konfiguracja: bez IRQ na czas inicjalizacji, translacja włączona.
    let mut config = read_config().ok_or(Ps2Error::Timeout("read config"))?;
    config &= !(CONFIG_PORT1_IRQ | CONFIG_PORT2_IRQ | CONFIG_PORT1_CLOCK_OFF);
    config |= CONFIG_TRANSLATION | CONFIG_PORT2_CLOCK_OFF;
    if !write_config(config) {
        return Err(Ps2Error::Timeout("write config"));
    }

    // 3–5. M16b: BEZ testu kontrolera (0xAA), testu portu (0xAB) i resetu
    // klawiatury (0xFF) – tak jak Linux na x86 (i8042.reset i atkbd.reset
    // domyślnie wyłączone).  Na laptopach (np. Lenovo Legion z Ryzenem)
    // 8042 jest emulowany przez EC i po takim resecie klawiatura przestaje
    // wysyłać znaki, choć na wszystko odpowiada poprawnie.  Firmware i tak
    // zostawia klawiaturę gotową; wystarczy włączyć port i skanowanie.
    write_command(CMD_ENABLE_PORT1);
    flush();
    if !keyboard_command(KBD_ENABLE_SCANNING) {
        serial_println!("[PS2] WARNING: keyboard did not ACK 'enable scanning'");
    }
    flush();

    // 5b. Mysz na porcie 2 (opcjonalna).
    match init_mouse() {
        Some(id) => {
            MOUSE_ID.store(id, core::sync::atomic::Ordering::Relaxed);
            config &= !CONFIG_PORT2_CLOCK_OFF;
            config |= CONFIG_PORT2_IRQ;
        }
        None => {
            write_command(CMD_DISABLE_PORT2);
            config |= CONFIG_PORT2_CLOCK_OFF;
            config &= !CONFIG_PORT2_IRQ;
        }
    }

    // 6. Włącz IRQ1 (i IRQ12, jeśli jest mysz) w kontrolerze.  Odmaskowanie
    //    w PIC-u robią sterowniki klawiatury i myszy.
    flush();
    config |= CONFIG_PORT1_IRQ;
    if !write_config(config) {
        return Err(Ps2Error::Timeout("enable IRQ1"));
    }

    Ok(())
}

/// Reset komputera przez kontroler 8042 (impuls na linii RESET CPU).
/// Zwraca tylko, jeśli nie zadziałało.
pub fn reset_cpu() {
    write_command(0xFE);
    for _ in 0..1_000_000 {
        core::hint::spin_loop();
    }
}

/// Test: kontroler wstawia `byte` do bufora tak, jakby przyszedł od
/// klawiatury (komenda 0xD2) – generuje IRQ1.  Bajt NIE przechodzi przez
/// translację, więc podajemy od razu kody zestawu 1.
#[cfg(selftest)]
pub fn inject_keyboard_byte(byte: u8) -> bool {
    write_command(CMD_WRITE_PORT1_OUTPUT) && write_data(byte)
}

/// Test: bajt tak, jakby przyszedł od myszy (komenda 0xD3) – generuje IRQ12.
#[cfg(selftest)]
pub fn inject_mouse_byte(byte: u8) -> bool {
    write_command(CMD_WRITE_PORT2_OUTPUT) && write_data(byte)
}
