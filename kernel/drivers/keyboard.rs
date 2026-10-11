// M6: klawiatura PS/2 – IRQ1, dekoder kodów zestawu 1, diody.
//
// Handler IRQ1 czyta bajt z kontrolera, dekoduje go na `KeyCode`
// (+ wciśnięty/puszczony) i przekazuje do `input::handle_key`.  Układ
// klawiatury, modyfikatory i kolejka zdarzeń są w `input.rs` – wspólne
// z przyszłą klawiaturą USB (M19).
//
// Zestaw 1 (po translacji w 8042):
//   * zwykły klawisz: 1 bajt, bit 7 = puszczenie (make | 0x80),
//   * 0xE0 xx: klawisze rozszerzone (strzałki, prawy Ctrl/Alt, Delete...),
//   * 0xE0 0x2A / 0xE0 0xAA...: "sztuczne" Shifty przy PrintScreen – ignorowane,
//   * 0xE1 1D 45 E1 9D C5: Pause (tylko wciśnięcie, bez puszczenia).
//
// Diody (Caps/Num/Scroll Lock): komenda 0xED + bajt stanu.  Każdy bajt
// klawiatura potwierdza ACK (0xFA), który przychodzi jako zwykłe IRQ1 –
// dlatego wysyłanie jest małą maszyną stanów w handlerze.

use core::sync::atomic::{AtomicU64, Ordering};

use super::ps2;
use crate::arch::x86_64::irq;
use crate::input::{self, KeyCode};
use crate::serial_println;

const KEYBOARD_IRQ: u8 = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Led {
    Idle,
    WaitCommandAck,
    WaitDataAck,
}

struct Decoder {
    extended: bool,    // był prefiks 0xE0
    pause_left: u8,    // ile bajtów sekwencji Pause (0xE1 ...) jeszcze zostało
    led: Led,
    led_dirty: bool,   // stan blokad zmienił się w trakcie wysyłania
    last_sent: u8,     // do ponowienia po RESEND
}

static mut DECODER: Decoder = Decoder {
    extended: false,
    pause_left: 0,
    led: Led::Idle,
    led_dirty: false,
    last_sent: 0,
};

static BYTES: AtomicU64 = AtomicU64::new(0);
static SCANCODES: AtomicU64 = AtomicU64::new(0);
static UNKNOWN: AtomicU64 = AtomicU64::new(0);

/// Zestaw 1, bez prefiksu.
fn base_key(code: u8) -> Option<KeyCode> {
    use KeyCode::*;
    Some(match code {
        0x01 => Escape,
        0x02 => Key1, 0x03 => Key2, 0x04 => Key3, 0x05 => Key4, 0x06 => Key5,
        0x07 => Key6, 0x08 => Key7, 0x09 => Key8, 0x0A => Key9, 0x0B => Key0,
        0x0C => Minus, 0x0D => Equals, 0x0E => Backspace, 0x0F => Tab,
        0x10 => Q, 0x11 => W, 0x12 => E, 0x13 => R, 0x14 => T, 0x15 => Y,
        0x16 => U, 0x17 => I, 0x18 => O, 0x19 => P,
        0x1A => LeftBracket, 0x1B => RightBracket, 0x1C => Enter, 0x1D => LeftCtrl,
        0x1E => A, 0x1F => S, 0x20 => D, 0x21 => F, 0x22 => G, 0x23 => H,
        0x24 => J, 0x25 => K, 0x26 => L,
        0x27 => Semicolon, 0x28 => Quote, 0x29 => Backtick, 0x2A => LeftShift,
        0x2B => Backslash,
        0x2C => Z, 0x2D => X, 0x2E => C, 0x2F => V, 0x30 => B, 0x31 => N, 0x32 => M,
        0x33 => Comma, 0x34 => Period, 0x35 => Slash, 0x36 => RightShift,
        0x37 => KpStar, 0x38 => LeftAlt, 0x39 => Space, 0x3A => CapsLock,
        0x3B => F1, 0x3C => F2, 0x3D => F3, 0x3E => F4, 0x3F => F5,
        0x40 => F6, 0x41 => F7, 0x42 => F8, 0x43 => F9, 0x44 => F10,
        0x45 => NumLock, 0x46 => ScrollLock,
        0x47 => Kp7, 0x48 => Kp8, 0x49 => Kp9, 0x4A => KpMinus,
        0x4B => Kp4, 0x4C => Kp5, 0x4D => Kp6, 0x4E => KpPlus,
        0x4F => Kp1, 0x50 => Kp2, 0x51 => Kp3, 0x52 => Kp0, 0x53 => KpPeriod,
        0x56 => NonUsBackslash, 0x57 => F11, 0x58 => F12,
        _ => return None,
    })
}

/// Zestaw 1, po prefiksie 0xE0.
fn extended_key(code: u8) -> Option<KeyCode> {
    use KeyCode::*;
    Some(match code {
        0x1C => KpEnter,
        0x1D => RightCtrl,
        0x35 => KpSlash,
        0x37 => PrintScreen,
        0x38 => RightAlt,
        0x46 => Pause, // Ctrl+Break
        0x47 => Home,
        0x48 => Up,
        0x49 => PageUp,
        0x4B => Left,
        0x4D => Right,
        0x4F => End,
        0x50 => Down,
        0x51 => PageDown,
        0x52 => Insert,
        0x53 => Delete,
        0x5B => LeftGui,
        0x5C => RightGui,
        0x5D => Menu,
        _ => return None,
    })
}

fn decoder() -> &'static mut Decoder {
    // Dostęp tylko z handlera IRQ1 (IF=0) i z init przy zamaskowanym IRQ1.
    unsafe { &mut *core::ptr::addr_of_mut!(DECODER) }
}

/// Dekoduje jeden bajt; `Some` = pełny kod klawisza.
fn decode(d: &mut Decoder, byte: u8) -> Option<(KeyCode, bool)> {
    if d.pause_left > 0 {
        d.pause_left -= 1;
        return if d.pause_left == 0 { Some((KeyCode::Pause, true)) } else { None };
    }
    match byte {
        0xE0 => {
            d.extended = true;
            return None;
        }
        0xE1 => {
            d.extended = false;
            d.pause_left = 5;
            return None;
        }
        _ => {}
    }

    let extended = core::mem::replace(&mut d.extended, false);
    let code = byte & 0x7F;
    let pressed = byte & 0x80 == 0;

    let key = if extended {
        // Sztuczne Shifty dookoła PrintScreen / klawiszy nawigacji.
        if code == 0x2A || code == 0x36 {
            return None;
        }
        extended_key(code)
    } else {
        base_key(code)
    };

    match key {
        Some(k) => Some((k, pressed)),
        None => {
            UNKNOWN.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

fn led_byte() -> u8 {
    let m = input::modifiers();
    (m.scroll_lock() as u8) | ((m.num_lock() as u8) << 1) | ((m.caps_lock() as u8) << 2)
}

fn send(d: &mut Decoder, byte: u8) {
    d.last_sent = byte;
    ps2::write_data(byte);
}

fn start_led_update(d: &mut Decoder) {
    if d.led == Led::Idle {
        d.led_dirty = false;
        d.led = Led::WaitCommandAck;
        send(d, ps2::KBD_SET_LEDS);
    } else {
        d.led_dirty = true;
    }
}

/// Obsługa ACK/RESEND od klawiatury.  `true` = bajt był odpowiedzią.
fn handle_reply(d: &mut Decoder, byte: u8) -> bool {
    match byte {
        ps2::KBD_ACK => {
            match d.led {
                Led::WaitCommandAck => {
                    d.led = Led::WaitDataAck;
                    send(d, led_byte());
                }
                Led::WaitDataAck => {
                    d.led = Led::Idle;
                    if d.led_dirty {
                        start_led_update(d);
                    }
                }
                Led::Idle => {}
            }
            true
        }
        ps2::KBD_RESEND => {
            if d.led != Led::Idle {
                let b = d.last_sent;
                send(d, b);
            }
            true
        }
        // Echo, błędy / przepełnienie bufora klawiatury.
        0xEE | 0x00 | 0xFF => true,
        _ => false,
    }
}

fn on_irq(_irq: u8) {
    IRQ_HITS.fetch_add(1, Ordering::Relaxed);
    take_byte();
}

/// M16b: na części laptopów (EC udający 8042, przerwania przez IOAPIC)
/// IRQ1 nie dochodzi przez PIC, choć dane w porcie 0x60 są.  Dlatego tick
/// zegara co POLL_TICKS ms sprawdza też port sam (w przerwaniu zegara –
/// bez wyścigu z handlerem IRQ1).  Gdy IRQ1 działa, port jest już pusty.
static READY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static IRQ_HITS: AtomicU64 = AtomicU64::new(0);
static POLLED: AtomicU64 = AtomicU64::new(0);
const POLL_TICKS: u64 = 5;

/// Z time::on_tick (IRQ0, przerwania wyłączone).
/// M17a.g4: czy w tym ticku przypada odpytywanie (bez BKL).
pub fn poll_due(now: u64) -> bool {
    now % POLL_TICKS == 0 && READY.load(Ordering::Relaxed)
}

pub fn poll_tick(now: u64) {
    if now % POLL_TICKS != 0 || !READY.load(Ordering::Relaxed) {
        return;
    }
    for _ in 0..8 {
        if !take_byte() {
            break;
        }
        POLLED.fetch_add(1, Ordering::Relaxed);
    }
}

/// (bajty przez IRQ1, bajty złapane odpytywaniem) – komenda `irq`, diagnostyka.
#[allow(dead_code)]
pub fn delivery_stats() -> (u64, u64) {
    (IRQ_HITS.load(Ordering::Relaxed), POLLED.load(Ordering::Relaxed))
}

/// M16b: pasek stanu (komputery bez portu szeregowego): czas od startu,
/// bajty z klawiatury (IRQ / odpytywanie) i rejestr stanu 8042 – widać, czy
/// system żyje i czy klawiatura cokolwiek wysyła.
fn status_bar(_: usize) {
    loop {
        let (irq, poll) = delivery_stats();
        let st = unsafe { crate::arch::x86_64::port::inb(0x64) };
        let text = alloc::format!(
            " up {}s | kbd irq {} poll {} | 8042 st {:02x} | IRQ1 {} ",
            crate::time::uptime_ms() / 1000,
            irq,
            poll,
            st,
            crate::arch::x86_64::irq::count(KEYBOARD_IRQ)
        );
        crate::console::with_framebuffer(|fb| fb.draw_overlay(&text, 0, 6));
        crate::time::sleep_ms(500);
    }
}

/// Uruchamia pasek stanu (zadanie kernela).
pub fn start_status_bar() {
    let _ = crate::sched::spawn("statusbar", status_bar, 0);
}

/// Jeden bajt z kontrolera (jeśli jest); `false` = bufor pusty.
fn take_byte() -> bool {
    let Some((byte, aux)) = ps2::read_irq_byte() else {
        return false;
    };
    if aux {
        // Bajt z portu 2 (mysz) odebrany przy IRQ1 – oddaj sterownikowi myszy.
        super::mouse::handle_byte(byte);
        return true;
    }
    handle_byte(byte);
    true
}

/// Jeden bajt od klawiatury (z IRQ1, albo z IRQ12, jeśli kontroler tak podał).
pub fn handle_byte(byte: u8) {
    BYTES.fetch_add(1, Ordering::Relaxed);

    let d = decoder();
    if handle_reply(d, byte) {
        return;
    }
    SCANCODES.fetch_add(1, Ordering::Relaxed);

    if let Some((key, pressed)) = decode(d, byte) {
        if input::handle_key(key, pressed) {
            start_led_update(d);
        }
        crate::console::wake_input();
    }
}

/// Inicjalizuje kontroler PS/2 i klawiaturę, rejestruje IRQ1.
/// Wymaga działającego timera (M5) i włączonych przerwań.
pub fn init() -> bool {
    serial_println!("[KBD] Initializing PS/2 controller + keyboard...");
    if let Err(e) = ps2::init() {
        serial_println!("[KBD] PS/2 keyboard not available: {}", e);
        return false;
    }
    if !irq::register(KEYBOARD_IRQ, on_irq) {
        serial_println!("[KBD] IRQ1 already taken");
        return false;
    }
    irq::unmask(KEYBOARD_IRQ);
    READY.store(true, Ordering::Relaxed);
    serial_println!("[KBD] PS/2 keyboard ready (IRQ1 + polling every {} ms, scancode set 1 via translation, layout: pl programmer)", POLL_TICKS);
    true
}

/// Liczba bajtów-kodów (bez ACK/RESEND) przekazanych do dekodera.
#[allow(dead_code)]
pub fn scancodes_received() -> u64 {
    SCANCODES.load(Ordering::Relaxed)
}

// ------------------------------------------------------------
// TEST (tylko build z --cfg selftest)
// ------------------------------------------------------------

#[cfg(selftest)]
macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[KBD TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

/// Wstrzykuje bajty przez kontroler (IRQ1 jak od prawdziwej klawiatury)
/// i czeka, aż handler je przetworzy.
#[cfg(selftest)]
fn inject(bytes: &[u8]) -> bool {
    use crate::arch::x86_64::interrupts;
    for &b in bytes {
        // Nie wchodzimy w paradę trwającej wymianie z klawiaturą (diody).
        if !led_idle() {
            return false;
        }
        let before = SCANCODES.load(Ordering::Relaxed);
        // 0xD2 + bajt muszą iść razem – handler IRQ nie może wpisać
        // niczego do portu danych pomiędzy nimi.
        if !interrupts::without_interrupts(|| ps2::inject_keyboard_byte(b)) {
            return false;
        }
        let deadline = crate::time::ticks() + 100;
        while SCANCODES.load(Ordering::Relaxed) == before {
            if crate::time::ticks() > deadline {
                return false;
            }
            interrupts::enable_and_hlt();
        }
    }
    true
}

#[cfg(selftest)]
fn led_idle() -> bool {
    let deadline = crate::time::ticks() + 100;
    loop {
        if crate::arch::x86_64::interrupts::without_interrupts(|| decoder().led == Led::Idle) {
            return true;
        }
        if crate::time::ticks() > deadline {
            return false;
        }
        crate::arch::x86_64::interrupts::enable_and_hlt();
    }
}

/// Zbiera znaki ze wszystkich zdarzeń w kolejce.
#[cfg(selftest)]
fn drain_chars(out: &mut [char]) -> usize {
    let mut n = 0;
    while let Some(e) = input::read_event() {
        if let Some(c) = e.ch {
            if n < out.len() {
                out[n] = c;
            }
            n += 1;
        }
    }
    n
}

#[cfg(selftest)]
pub fn self_test() {
    use crate::drivers::ps2::{CONFIG_PORT1_IRQ, CONFIG_PORT2_CLOCK_OFF, CONFIG_TRANSLATION};
    use crate::input::{KeyEvent, Modifiers};

    serial_println!("[KBD TEST] Starting keyboard tests...");
    crate::selftest::begin();
    input::reset();

    // 1. Kontroler skonfigurowany, IRQ1 odmaskowane.
    let cfg = ps2::config();
    check!(cfg.is_some(), "cannot read controller config");
    let cfg = cfg.unwrap();
    check!(cfg & CONFIG_PORT1_IRQ != 0, "port 1 IRQ disabled (config {:#x})", cfg);
    check!(cfg & CONFIG_TRANSLATION != 0, "translation disabled (config {:#x})", cfg);
    // Port 2 włączony dokładnie wtedy, gdy jest mysz (M11b).
    check!(
        (cfg & CONFIG_PORT2_CLOCK_OFF == 0) == ps2::mouse_id().is_some(),
        "port 2 state does not match the mouse (config {:#x})",
        cfg
    );
    check!(!irq::is_masked(KEYBOARD_IRQ), "IRQ1 masked");
    serial_println!("[KBD TEST] 1/9 controller config {:#04x}, IRQ1 unmasked PASS", cfg);

    // 2. 'a': wciśnięcie + puszczenie przez prawdziwą ścieżkę IRQ1.
    check!(inject(&[0x1E, 0x9E]), "inject 'a' timed out");
    let e1 = input::read_event();
    let e2 = input::read_event();
    check!(
        e1 == Some(KeyEvent { key: KeyCode::A, pressed: true, mods: Modifiers::empty(), ch: Some('a') }),
        "press event {:?}", e1
    );
    check!(
        matches!(e2, Some(KeyEvent { key: KeyCode::A, pressed: false, ch: None, .. })),
        "release event {:?}", e2
    );
    check!(input::read_event().is_none(), "extra events");
    serial_println!("[KBD TEST] 2/9 'a' press/release via IRQ1 PASS");

    // 3. Shift: "A!" i po puszczeniu Shift znów małe.
    check!(inject(&[0x2A, 0x1E, 0x9E, 0x02, 0x82, 0xAA, 0x1E, 0x9E]), "inject shift");
    let mut buf = ['\0'; 8];
    let n = drain_chars(&mut buf);
    check!(n == 3 && buf[..3] == ['A', '!', 'a'], "got {:?}", &buf[..n.min(8)]);
    check!(!input::modifiers().shift(), "shift stuck");
    serial_println!("[KBD TEST] 3/9 Shift ('A', '!', release) PASS");

    // 4. Caps Lock: przełącza litery, nie cyfry; Shift odwraca; dioda.
    check!(inject(&[0x3A, 0xBA]), "inject caps");
    check!(input::modifiers().caps_lock(), "caps lock not on");
    check!(led_idle(), "LED update (0xED) not acknowledged");
    check!(inject(&[0x1E, 0x9E, 0x02, 0x82, 0x2A, 0x1E, 0x9E, 0xAA]), "inject caps keys");
    check!(inject(&[0x3A, 0x3A, 0xBA]), "inject caps off (with autorepeat)");
    check!(!input::modifiers().caps_lock(), "caps lock still on (autorepeat toggled?)");
    check!(led_idle(), "LED update not acknowledged");
    let n = drain_chars(&mut buf);
    check!(n == 3 && buf[..3] == ['A', '1', 'a'], "got {:?}", &buf[..n.min(8)]);
    serial_println!("[KBD TEST] 4/9 Caps Lock (+Shift, autorepeat, LED ACK) PASS");

    // 5. Klawisze rozszerzone i sztuczny Shift.
    check!(inject(&[0xE0, 0x48, 0xE0, 0xC8, 0xE0, 0x2A, 0xE0, 0x53, 0xE0, 0x1C]), "inject extended");
    let up = input::read_event();
    let up_rel = input::read_event();
    let del = input::read_event();
    let kp_enter = input::read_event();
    check!(matches!(up, Some(KeyEvent { key: KeyCode::Up, pressed: true, ch: None, .. })), "up {:?}", up);
    check!(matches!(up_rel, Some(KeyEvent { key: KeyCode::Up, pressed: false, .. })), "up release {:?}", up_rel);
    check!(matches!(del, Some(KeyEvent { key: KeyCode::Delete, pressed: true, .. })), "fake shift not ignored: {:?}", del);
    check!(matches!(kp_enter, Some(KeyEvent { key: KeyCode::KpEnter, ch: Some('\n'), .. })), "kp enter {:?}", kp_enter);
    check!(!input::modifiers().shift(), "fake shift changed modifiers");
    serial_println!("[KBD TEST] 5/9 extended keys (E0), fake shift ignored PASS");

    // 6. AltGr (prawy Alt) – polskie znaki.
    check!(inject(&[0xE0, 0x38, 0x1E, 0x9E, 0x2A, 0x1F, 0x9F, 0xAA, 0x16, 0x96, 0x2E, 0xE0, 0xB8]), "inject altgr");
    let n = drain_chars(&mut buf);
    check!(n == 4 && buf[..4] == ['ą', 'Ś', '€', 'ć'], "got {:?}", &buf[..n.min(8)]);
    check!(!input::modifiers().altgr(), "altgr stuck");
    check!(inject(&[0xAE]), "release c");
    input::read_event();
    serial_println!("[KBD TEST] 6/9 AltGr: 'ą', 'Ś', '€', 'ć' PASS");

    // 7. Ctrl+C i znaki sterujące.
    check!(inject(&[0x1D, 0x2E, 0xAE, 0x9D, 0x1C, 0x0F, 0x0E, 0x01]), "inject ctrl");
    let n = drain_chars(&mut buf);
    check!(
        n == 5 && buf[..5] == ['\x03', '\n', '\t', '\x08', '\x1b'],
        "got {:?}", &buf[..n.min(8)]
    );
    serial_println!("[KBD TEST] 7/9 Ctrl+C, Enter, Tab, Backspace, Esc PASS");

    // 8. Pause (E1 1D 45 E1 9D C5) = jedno zdarzenie, dekoder wraca do normy.
    check!(inject(&[0xE1, 0x1D, 0x45, 0xE1, 0x9D, 0xC5, 0x1E]), "inject pause");
    let p = input::read_event();
    let a = input::read_event();
    check!(matches!(p, Some(KeyEvent { key: KeyCode::Pause, pressed: true, .. })), "pause {:?}", p);
    check!(matches!(a, Some(KeyEvent { key: KeyCode::A, ch: Some('a'), .. })), "after pause {:?}", a);
    check!(!input::modifiers().ctrl(), "pause sequence set ctrl");
    check!(inject(&[0x9E]), "release a");
    input::read_event();
    serial_println!("[KBD TEST] 8/9 Pause sequence PASS");

    // 9. Kolejka: kolejność FIFO i przepełnienie (bez IRQ – wprost do input).
    input::reset();
    let keys = [KeyCode::A, KeyCode::B, KeyCode::C];
    for i in 0..300 {
        input::handle_key(keys[i % 3], true);
    }
    check!(input::pending() == 256, "queue holds {}", input::pending());
    check!(input::dropped() == 44, "dropped {}", input::dropped());
    for i in 0..256 {
        let e = input::read_event();
        check!(matches!(e, Some(ev) if ev.key == keys[i % 3]), "event {} = {:?}", i, e);
    }
    check!(input::read_event().is_none(), "queue not empty");
    input::reset();
    serial_println!("[KBD TEST] 9/9 event queue FIFO + overflow (256, 44 dropped) PASS");

    serial_println!("[KBD TEST] =================================");
    crate::selftest::pass();
    serial_println!(
        "[KBD TEST] KEYBOARD TESTS PASSED ({} bytes from controller)",
        BYTES.load(Ordering::Relaxed)
    );
    serial_println!("[KBD TEST] =================================");
}
