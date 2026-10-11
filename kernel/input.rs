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
