// M6: podsystem wejścia – wspólny interfejs dla wszystkich klawiatur.
//
// Sterownik (PS/2 teraz, USB w M19) zamienia swoje kody na `KeyCode`
// i woła `handle_key(key, pressed)`.  Wszystko dalej – modyfikatory,
// Caps/Num Lock, układ klawiatury, kolejka zdarzeń – dzieje się tutaj,
// więc reszta systemu nie wie, skąd przyszedł klawisz.
//
// Układ: polski programisty (US QWERTY + AltGr dla ąćęłńóśźż, AltGr+u = €).
//
// Kolejka: 256 zdarzeń.  Producent = handler IRQ (IF=0), konsument = kod
// kernela; pobieranie odbywa się z wyłączonymi przerwaniami.  Przy
// przepełnieniu nowe zdarzenia są odrzucane (licznik `dropped()`).

use crate::arch::x86_64::interrupts::without_interrupts;

/// Kod klawisza niezależny od sprzętu i układu (pozycja na klawiaturze US).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code)]
pub enum KeyCode {
    Escape,
    F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12,
    PrintScreen, ScrollLock, Pause,
    Backtick, Key1, Key2, Key3, Key4, Key5, Key6, Key7, Key8, Key9, Key0,
    Minus, Equals, Backspace,
    Tab, Q, W, E, R, T, Y, U, I, O, P, LeftBracket, RightBracket, Backslash,
    CapsLock, A, S, D, F, G, H, J, K, L, Semicolon, Quote, Enter,
    LeftShift, NonUsBackslash, Z, X, C, V, B, N, M, Comma, Period, Slash, RightShift,
    LeftCtrl, LeftGui, LeftAlt, Space, RightAlt, RightGui, Menu, RightCtrl,
    Insert, Home, PageUp, Delete, End, PageDown,
    Up, Down, Left, Right,
    NumLock, KpSlash, KpStar, KpMinus, KpPlus, KpEnter, KpPeriod,
    Kp0, Kp1, Kp2, Kp3, Kp4, Kp5, Kp6, Kp7, Kp8, Kp9,
}

/// Stan modyfikatorów i blokad w chwili zdarzenia.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Modifiers(u16);

#[allow(dead_code)]
impl Modifiers {
    pub const LSHIFT: u16 = 1 << 0;
    pub const RSHIFT: u16 = 1 << 1;
    pub const LCTRL: u16 = 1 << 2;
    pub const RCTRL: u16 = 1 << 3;
    pub const ALT: u16 = 1 << 4;
    pub const ALTGR: u16 = 1 << 5;
    pub const LGUI: u16 = 1 << 6;
    pub const RGUI: u16 = 1 << 7;
    pub const CAPS_LOCK: u16 = 1 << 8;
    pub const NUM_LOCK: u16 = 1 << 9;
    pub const SCROLL_LOCK: u16 = 1 << 10;

    pub const fn empty() -> Self {
        Modifiers(0)
    }
    pub fn bits(self) -> u16 {
        self.0
    }
    pub fn has(self, bit: u16) -> bool {
        self.0 & bit != 0
    }
    pub fn shift(self) -> bool {
        self.has(Self::LSHIFT | Self::RSHIFT)
    }
    pub fn ctrl(self) -> bool {
        self.has(Self::LCTRL | Self::RCTRL)
    }
    pub fn alt(self) -> bool {
        self.has(Self::ALT)
    }
    pub fn altgr(self) -> bool {
        self.has(Self::ALTGR)
    }
    pub fn caps_lock(self) -> bool {
        self.has(Self::CAPS_LOCK)
    }
    pub fn num_lock(self) -> bool {
        self.has(Self::NUM_LOCK)
    }
    pub fn scroll_lock(self) -> bool {
        self.has(Self::SCROLL_LOCK)
    }
}

/// Jedno zdarzenie klawiatury.  `ch` jest ustawione tylko przy wciśnięciu
/// (także przy autorepeat) klawisza, który daje znak.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyEvent {
    pub key: KeyCode,
    pub pressed: bool,
    pub mods: Modifiers,
    pub ch: Option<char>,
}

impl KeyEvent {
    const EMPTY: KeyEvent = KeyEvent {
        key: KeyCode::Escape,
        pressed: false,
        mods: Modifiers::empty(),
        ch: None,
    };
}

// ------------------------------------------------------------
// Stan (dostęp tylko z wyłączonymi przerwaniami)
// ------------------------------------------------------------

const QUEUE_SIZE: usize = 256;

struct State {
    queue: [KeyEvent; QUEUE_SIZE],
    head: usize, // następny do odczytu
    len: usize,
    dropped: u64,
    mods: Modifiers,
    // Które klawisze blokad są wciśnięte – autorepeat nie może ich przełączać.
    lock_keys_down: u16,
}

static mut STATE: State = State {
    queue: [KeyEvent::EMPTY; QUEUE_SIZE],
    head: 0,
    len: 0,
    dropped: 0,
    mods: Modifiers::empty(),
    lock_keys_down: 0,
};

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    without_interrupts(|| unsafe { f(&mut *core::ptr::addr_of_mut!(STATE)) })
}

// ------------------------------------------------------------
// Układ klawiatury
// ------------------------------------------------------------

fn letter(key: KeyCode) -> Option<u8> {
    use KeyCode::*;
    Some(match key {
        A => b'a', B => b'b', C => b'c', D => b'd', E => b'e', F => b'f', G => b'g',
        H => b'h', I => b'i', J => b'j', K => b'k', L => b'l', M => b'm', N => b'n',
        O => b'o', P => b'p', Q => b'q', R => b'r', S => b's', T => b't', U => b'u',
        V => b'v', W => b'w', X => b'x', Y => b'y', Z => b'z',
        _ => return None,
    })
}

/// AltGr + litera w polskim układzie programisty: (mała, wielka).
fn polish(letter: u8) -> Option<(char, char)> {
    Some(match letter {
        b'a' => ('ą', 'Ą'),
        b'c' => ('ć', 'Ć'),
        b'e' => ('ę', 'Ę'),
        b'l' => ('ł', 'Ł'),
        b'n' => ('ń', 'Ń'),
        b'o' => ('ó', 'Ó'),
        b's' => ('ś', 'Ś'),
        b'x' => ('ź', 'Ź'),
        b'z' => ('ż', 'Ż'),
        _ => return None,
    })
}

/// Klawisze nieliterowe: (bez shift, z shift).
fn symbol(key: KeyCode) -> Option<(char, char)> {
    use KeyCode::*;
    Some(match key {
        Backtick => ('`', '~'),
        Key1 => ('1', '!'), Key2 => ('2', '@'), Key3 => ('3', '#'), Key4 => ('4', '$'),
        Key5 => ('5', '%'), Key6 => ('6', '^'), Key7 => ('7', '&'), Key8 => ('8', '*'),
        Key9 => ('9', '('), Key0 => ('0', ')'),
        Minus => ('-', '_'), Equals => ('=', '+'),
        LeftBracket => ('[', '{'), RightBracket => (']', '}'), Backslash => ('\\', '|'),
        Semicolon => (';', ':'), Quote => ('\'', '"'),
        Comma => (',', '<'), Period => ('.', '>'), Slash => ('/', '?'),
        NonUsBackslash => ('\\', '|'),
        Space => (' ', ' '),
        _ => return None,
    })
}

/// Znak dla wciśniętego klawisza przy danych modyfikatorach.
pub fn translate(key: KeyCode, mods: Modifiers) -> Option<char> {
    use KeyCode::*;

    if let Some(l) = letter(key) {
        let upper = mods.shift() != mods.caps_lock();
        if mods.altgr() {
            if l == b'u' {
                return Some('€');
            }
            return polish(l).map(|(lo, up)| if upper { up } else { lo });
        }
        if mods.ctrl() {
            // Ctrl+A..Z -> 0x01..0x1A (Ctrl+C = 0x03 itd.)
            return Some((l - b'a' + 1) as char);
        }
        let c = if upper { l.to_ascii_uppercase() } else { l };
        return Some(c as char);
    }

    if let Some((normal, shifted)) = symbol(key) {
        if mods.altgr() {
            return None;
        }
        return Some(if mods.shift() { shifted } else { normal });
    }

    match key {
        Enter | KpEnter => Some('\n'),
        Tab => Some('\t'),
        Backspace => Some('\x08'),
        Escape => Some('\x1b'),
        KpSlash => Some('/'),
        KpStar => Some('*'),
        KpMinus => Some('-'),
        KpPlus => Some('+'),
        _ if mods.num_lock() => match key {
            Kp0 => Some('0'), Kp1 => Some('1'), Kp2 => Some('2'), Kp3 => Some('3'),
            Kp4 => Some('4'), Kp5 => Some('5'), Kp6 => Some('6'), Kp7 => Some('7'),
            Kp8 => Some('8'), Kp9 => Some('9'), KpPeriod => Some('.'),
            _ => None,
        },
        _ => None,
    }
}

// ------------------------------------------------------------
// API dla sterowników
// ------------------------------------------------------------

/// Sterownik zgłasza wciśnięcie / puszczenie klawisza.  Zwraca `true`,
/// jeśli zmienił się stan blokad (Caps/Num/Scroll) – sterownik może wtedy
/// zaktualizować diody.  Wołać z wyłączonymi przerwaniami (handler IRQ)
/// albo z dowolnego miejsca – sama pilnuje IF.
pub fn handle_key(key: KeyCode, pressed: bool) -> bool {
    with_state(|s| {
        let mut locks_changed = false;

        let modifier = match key {
            KeyCode::LeftShift => Modifiers::LSHIFT,
            KeyCode::RightShift => Modifiers::RSHIFT,
            KeyCode::LeftCtrl => Modifiers::LCTRL,
            KeyCode::RightCtrl => Modifiers::RCTRL,
            KeyCode::LeftAlt => Modifiers::ALT,
            KeyCode::RightAlt => Modifiers::ALTGR,
            KeyCode::LeftGui => Modifiers::LGUI,
            KeyCode::RightGui => Modifiers::RGUI,
            _ => 0,
        };
        if modifier != 0 {
            if pressed {
                s.mods.0 |= modifier;
            } else {
                s.mods.0 &= !modifier;
            }
        }

        let lock = match key {
            KeyCode::CapsLock => Modifiers::CAPS_LOCK,
            KeyCode::NumLock => Modifiers::NUM_LOCK,
            KeyCode::ScrollLock => Modifiers::SCROLL_LOCK,
            _ => 0,
        };
        if lock != 0 {
            if pressed && s.lock_keys_down & lock == 0 {
                s.mods.0 ^= lock;
                locks_changed = true;
            }
            if pressed {
                s.lock_keys_down |= lock;
            } else {
                s.lock_keys_down &= !lock;
            }
        }

        let ch = if pressed { translate(key, s.mods) } else { None };
        // M14: Ctrl+C przy procesie na pierwszym planie kończy proces i nie
        // trafia do kolejki (shell nie zobaczy "^C").
        // Jak w terminalu: wpisane wcześniej, nieodczytane znaki przepadają.
        if ch == Some('\u{3}') && crate::console::interrupt_foreground() {
            s.head = 0;
            s.len = 0;
            crate::drivers::serial::discard_input();
            return locks_changed;
        }
        let event = KeyEvent { key, pressed, mods: s.mods, ch };

        if s.len == QUEUE_SIZE {
            s.dropped += 1;
        } else {
            let tail = (s.head + s.len) % QUEUE_SIZE;
            s.queue[tail] = event;
            s.len += 1;
        }

        locks_changed
    })
}

/// Bieżący stan modyfikatorów i blokad.
pub fn modifiers() -> Modifiers {
    with_state(|s| s.mods)
}

// ------------------------------------------------------------
// API dla konsumentów (konsola, później shell / procesy)
// ------------------------------------------------------------

/// Następne zdarzenie z kolejki (bez czekania).
pub fn read_event() -> Option<KeyEvent> {
    with_state(|s| {
        if s.len == 0 {
            return None;
        }
        let e = s.queue[s.head];
        s.head = (s.head + 1) % QUEUE_SIZE;
        s.len -= 1;
        Some(e)
    })
}

/// Czy w kolejce są zdarzenia.
pub fn has_events() -> bool {
    with_state(|s| s.len > 0)
}

/// Następny znak (pomija zdarzenia bez znaku), bez czekania.
#[allow(dead_code)]
pub fn read_char() -> Option<char> {
    while let Some(e) = read_event() {
        if let Some(c) = e.ch {
            return Some(c);
        }
    }
    None
}

/// Czeka (hlt) na następne zdarzenie.  Wymaga włączonych przerwań.
#[allow(dead_code)]
pub fn wait_event() -> KeyEvent {
    loop {
        if let Some(e) = read_event() {
            return e;
        }
        // M12: śpi w kolejce wejścia (budzi IRQ klawiatury).
        crate::console::INPUT_WAIT.wait_until(has_events, None);
    }
}

/// Ile zdarzeń odrzucono, bo kolejka była pełna.
#[allow(dead_code)]
pub fn dropped() -> u64 {
    with_state(|s| s.dropped)
}

/// M14: wyrzuca nieodczytane zdarzenia (Ctrl+C przy procesie na
/// pierwszym planie).
pub fn discard_events() {
    with_state(|s| {
        s.head = 0;
        s.len = 0;
    });
}

/// Czyści kolejkę i modyfikatory (testy).
#[cfg(selftest)]
pub fn reset() {
    with_state(|s| {
        s.head = 0;
        s.len = 0;
        s.dropped = 0;
        s.mods = Modifiers::empty();
        s.lock_keys_down = 0;
    });
}

#[cfg(selftest)]
pub fn pending() -> usize {
    with_state(|s| s.len)
}

// ------------------------------------------------------------
// M20.e: wejście z USB (usbd przez syscall input_inject)
//
// usbd przysyła kody HID (usage, strona 7) – tu tłumaczymy je na `KeyCode`
// i dalej wszystko jak przy PS/2.  Klawiatura USB (w przeciwieństwie do PS/2)
// sama nie powtarza klawiszy, więc autorepeat robi jądro: 500 ms, potem co
// 33 ms (~30/s).  Jeden powtarzany klawisz naraz – ostatnio wciśnięty, jak na
// zwykłej klawiaturze.  Puszczenie klawiszy źródła, które zniknęło (koniec
// usbd), też tutaj.
//
// v0.25.1: robi to zadanie jądra "input-repeat" (pod BKL), NIE tick zegara.
// W v0.25.0 był to tick: przerwanie zegara budziło czekających na wejście
// (blokada 'waiters', poziom 45) na CPU, którego przerwany kod trzymał
// 'stress-counter' (210) – lockdep: PANIC przy pisaniu w trakcie stressu.
// ------------------------------------------------------------

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const REPEAT_DELAY_MS: u64 = 500;
pub const REPEAT_PERIOD_MS: u64 = 33;

/// Powtarzany klawisz: HID usage (0 = brak), źródło, następna chwila (ms).
static REPEAT_USAGE: AtomicU64 = AtomicU64::new(0);
static REPEAT_SRC: AtomicU64 = AtomicU64::new(0);
static REPEAT_NEXT: AtomicU64 = AtomicU64::new(0);
/// Klawisze źródeł, które zniknęły – do puszczenia w ticku.
static ORPHANS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static ORPHANS_PENDING: AtomicBool = AtomicBool::new(false);
/// Liczniki (testy, `sysinfo`): zdarzenia z USB i powtórzenia.
static USB_EVENTS: AtomicU64 = AtomicU64::new(0);
static USB_REPEATS: AtomicU64 = AtomicU64::new(0);

/// HID usage (strona 7) -> KeyCode.
pub fn hid_key(usage: u8) -> Option<KeyCode> {
    use KeyCode::*;
    const LETTERS: [KeyCode; 26] = [A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z];
    const DIGITS: [KeyCode; 10] = [Key1, Key2, Key3, Key4, Key5, Key6, Key7, Key8, Key9, Key0];
    const FKEYS: [KeyCode; 12] = [F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12];
    const KP: [KeyCode; 9] = [Kp1, Kp2, Kp3, Kp4, Kp5, Kp6, Kp7, Kp8, Kp9];
    Some(match usage {
        0x04..=0x1D => LETTERS[(usage - 0x04) as usize],
        0x1E..=0x27 => DIGITS[(usage - 0x1E) as usize],
        0x28 => Enter,
        0x29 => Escape,
        0x2A => Backspace,
        0x2B => Tab,
        0x2C => Space,
        0x2D => Minus,
        0x2E => Equals,
        0x2F => LeftBracket,
        0x30 => RightBracket,
        0x31 | 0x32 => Backslash,
        0x33 => Semicolon,
        0x34 => Quote,
        0x35 => Backtick,
        0x36 => Comma,
        0x37 => Period,
        0x38 => Slash,
        0x39 => CapsLock,
        0x3A..=0x45 => FKEYS[(usage - 0x3A) as usize],
        0x46 => PrintScreen,
        0x47 => ScrollLock,
        0x48 => Pause,
        0x49 => Insert,
        0x4A => Home,
        0x4B => PageUp,
        0x4C => Delete,
        0x4D => End,
        0x4E => PageDown,
        0x4F => Right,
        0x50 => Left,
        0x51 => Down,
        0x52 => Up,
        0x53 => NumLock,
        0x54 => KpSlash,
        0x55 => KpStar,
        0x56 => KpMinus,
        0x57 => KpPlus,
        0x58 => KpEnter,
        0x59..=0x61 => KP[(usage - 0x59) as usize],
        0x62 => Kp0,
        0x63 => KpPeriod,
        0x64 => NonUsBackslash,
        0x65 => Menu,
        0xE0 => LeftCtrl,
        0xE1 => LeftShift,
        0xE2 => LeftAlt,
        0xE3 => LeftGui,
        0xE4 => RightCtrl,
        0xE5 => RightShift,
        0xE6 => RightAlt,
        0xE7 => RightGui,
        _ => return None,
    })
}

/// Klawisze, które się nie powtarzają (modyfikatory, blokady).
fn no_repeat(k: KeyCode) -> bool {
    use KeyCode::*;
    matches!(k, LeftShift | RightShift | LeftCtrl | RightCtrl | LeftAlt | RightAlt | LeftGui | RightGui | CapsLock | NumLock | ScrollLock | Pause | PrintScreen)
}

/// Klawisz z USB (syscall input_inject – pod BKL).
pub fn usb_key(src: u64, usage: u8, pressed: bool, now: u64) {
    let Some(k) = hid_key(usage) else { return };
    USB_EVENTS.fetch_add(1, Ordering::Relaxed);
    handle_key(k, pressed);
    if pressed && !no_repeat(k) {
        REPEAT_SRC.store(src, Ordering::Relaxed);
        REPEAT_NEXT.store(now + REPEAT_DELAY_MS, Ordering::Relaxed);
        REPEAT_USAGE.store(usage as u64, Ordering::Release);
        REPEAT_GEN.fetch_add(1, Ordering::Release);
        REPEAT_WAIT.wake_all();
    } else if !pressed && REPEAT_USAGE.load(Ordering::Relaxed) == usage as u64 && REPEAT_SRC.load(Ordering::Relaxed) == src {
        REPEAT_USAGE.store(0, Ordering::Release);
    }
    crate::console::wake_input();
}

/// Mysz z USB: kółko przewija konsolę (jak PS/2; dodatnie = w dół).
pub fn usb_mouse(_buttons: u8, wheel: i8) {
    USB_EVENTS.fetch_add(1, Ordering::Relaxed);
    if wheel != 0 {
        crate::drivers::mouse::add_wheel(wheel as i32);
    }
}

/// Źródło zniknęło (Drop uchwytu INPUT): jego klawisze do puszczenia przez
/// zadanie input-repeat (tu tylko atomiki).
pub fn usb_release_all(bits: [u64; 4], src: u64) {
    if REPEAT_SRC.load(Ordering::Relaxed) == src {
        REPEAT_USAGE.store(0, Ordering::Release);
    }
    if bits.iter().any(|&b| b != 0) {
        for (o, b) in ORPHANS.iter().zip(bits) {
            o.fetch_or(b, Ordering::Relaxed);
        }
        ORPHANS_PENDING.store(true, Ordering::Release);
    }
}

/// Zadanie "input-repeat": czeka (WaitQueue) do terminu powtórzenia albo na
/// pobudkę z usb_key; puszczenie klawiszy zniknięłych źródeł – co 100 ms (Drop
/// uchwytu nie budzi zadania – może biec w kontekście z blokadami).
static REPEAT_WAIT: crate::sched::sync::WaitQueue = crate::sched::sync::WaitQueue::new();
/// Rośnie przy każdej pobudce – zadanie przelicza termin (nowy klawisz).
static REPEAT_GEN: AtomicU64 = AtomicU64::new(0);

fn repeat_task(_: usize) {
    loop {
        let now = crate::time::ticks();
        if repeat_due(now) {
            crate::sched::bkl::with(|| repeat_tick(now));
        }
        let usage = REPEAT_USAGE.load(Ordering::Acquire);
        let timeout = if usage != 0 {
            REPEAT_NEXT.load(Ordering::Relaxed).saturating_sub(now).max(1)
        } else if USB_EVENTS.load(Ordering::Relaxed) == 0 {
            1000 // jeszcze żadnej klawiatury USB – rzadko
        } else {
            100
        };
        let seen = REPEAT_GEN.load(Ordering::Acquire);
        REPEAT_WAIT.wait_until(|| repeat_due(crate::time::ticks()) || REPEAT_GEN.load(Ordering::Acquire) != seen, Some(timeout));
    }
}

/// Start zadania autorepeat (raz, przy starcie jądra – przed samotestami USB).
pub fn start_repeat_task() {
    if crate::sched::spawn("input-repeat", repeat_task, 0).is_err() {
        crate::serial_println!("[INPUT] cannot start the USB key repeat task - no autorepeat for USB keyboards");
    }
}

/// Czy zadanie ma coś do zrobienia (same atomiki).
pub fn repeat_due(now: u64) -> bool {
    ORPHANS_PENDING.load(Ordering::Acquire)
        || (REPEAT_USAGE.load(Ordering::Acquire) != 0 && now >= REPEAT_NEXT.load(Ordering::Relaxed))
}

/// Zadanie input-repeat (pod BKL): puszczenie klawiszy po zniknięciu źródła, autorepeat.
pub fn repeat_tick(now: u64) {
    if ORPHANS_PENDING.swap(false, Ordering::AcqRel) {
        for (w, o) in ORPHANS.iter().enumerate() {
            let mut bits = o.swap(0, Ordering::Relaxed);
            while bits != 0 {
                let b = bits.trailing_zeros();
                bits &= bits - 1;
                if let Some(k) = hid_key((w as u32 * 64 + b) as u8) {
                    handle_key(k, false);
                }
            }
        }
        crate::console::wake_input();
    }
    let usage = REPEAT_USAGE.load(Ordering::Acquire);
    if usage != 0 && now >= REPEAT_NEXT.load(Ordering::Relaxed) {
        if let Some(k) = hid_key(usage as u8) {
            handle_key(k, true);
            USB_REPEATS.fetch_add(1, Ordering::Relaxed);
            crate::console::wake_input();
        }
        REPEAT_NEXT.store(now + REPEAT_PERIOD_MS, Ordering::Relaxed);
    }
}

/// Diody klawiatury dla usbd: bit 0 Num Lock, 1 Caps Lock, 2 Scroll Lock (jak
/// raport wyjściowy HID).
pub fn led_bits() -> u64 {
    let m = modifiers();
    (m.num_lock() as u64) | (m.caps_lock() as u64) << 1 | (m.scroll_lock() as u64) << 2
}

// M20.h: opóźnienie klawiatury USB – od przerwania kontrolera xHCI (handler
// jądra) do znaku w kolejce wejścia jądra (po usbd: obudzenie, zdarzenie z
// pierścienia, raport HID, input_inject).  Tylko wciśnięcia; > 1 s pomijane
// (to nie było przerwanie tego raportu).
static HID_N: AtomicU64 = AtomicU64::new(0);
static HID_SUM: AtomicU64 = AtomicU64::new(0);
static HID_MIN: AtomicU64 = AtomicU64::new(u64::MAX);
static HID_MAX: AtomicU64 = AtomicU64::new(0);

pub fn hid_latency_record(us: u64) {
    if us > 1_000_000 {
        return;
    }
    HID_N.fetch_add(1, Ordering::Relaxed);
    HID_SUM.fetch_add(us, Ordering::Relaxed);
    HID_MIN.fetch_min(us, Ordering::Relaxed);
    HID_MAX.fetch_max(us, Ordering::Relaxed);
}

/// (liczba, średnia, min, max) w µs; min = 0 przy braku pomiarów.
pub fn hid_latency() -> (u64, u64, u64, u64) {
    let n = HID_N.load(Ordering::Relaxed);
    let min = HID_MIN.load(Ordering::Relaxed);
    (n, HID_SUM.load(Ordering::Relaxed) / n.max(1), if n == 0 { 0 } else { min }, HID_MAX.load(Ordering::Relaxed))
}

#[cfg_attr(not(selftest), allow(dead_code))]
pub fn hid_latency_reset() {
    HID_N.store(0, Ordering::Relaxed);
    HID_SUM.store(0, Ordering::Relaxed);
    HID_MIN.store(u64::MAX, Ordering::Relaxed);
    HID_MAX.store(0, Ordering::Relaxed);
}

/// (zdarzenia z USB, powtórzenia) – testy i statystyki.
#[allow(dead_code)]
pub fn usb_stats() -> (u64, u64) {
    (USB_EVENTS.load(Ordering::Relaxed), USB_REPEATS.load(Ordering::Relaxed))
}
