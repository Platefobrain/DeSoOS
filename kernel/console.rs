// M7: konsola kernela.
//
// Wyjście: każdy tekst idzie na serial (terminal) i – po `init()` – na
// konsolę framebuffera.  Wszystkie logi (`serial_println!`) przechodzą tędy,
// więc widać je też na ekranie QEMU.
//
// Wejście: klawiatura PS/2 (zdarzenia z `input`) oraz bajty z seriala
// (pisanie w terminalu).  Oba źródła zamieniane są na wspólne `Key`.
// Z seriala rozumiemy UTF-8 i sekwencje ESC[A/B/C/D/H/F/3~ (strzałki,
// Home, End, Delete), 0x7F/0x08 = Backspace, CR = Enter.

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::x86_64::interrupts::without_interrupts;
use crate::bootinfo::BootInfo;
use crate::drivers::fbcon::FbConsole;
use crate::drivers::serial;
use crate::input::{self, KeyCode};
use crate::sched::sync::WaitQueue;
use crate::serial_println;

static mut FB: Option<FbConsole> = None;
static FB_ADDRESS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
// Konsola framebuffera jest w trakcie rysowania (np. wyjątek w środku) –
// wtedy piszemy już tylko na serial.
static FB_BUSY: AtomicBool = AtomicBool::new(false);

/// M17a.d: który CPU rysuje (numer + 1) – ten sam CPU w środku rysowania
/// (wyjątek) dostaje None, inny CPU chwilę czeka (wcześniej BKL gwarantował,
/// że rysuje jeden CPU; teraz `write` procesu działa bez BKL).
static FB_OWNER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn with_fb<R>(f: impl FnOnce(&mut FbConsole) -> R) -> Option<R> {
    without_interrupts(|| {
        let me = crate::arch::x86_64::cpu::id() as u32 + 1;
        if FB_OWNER.load(Ordering::Relaxed) == me {
            return None;
        }
        let start = crate::arch::x86_64::clock::stamp();
        let mut n: u32 = 0;
        while FB_BUSY.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
            n = n.wrapping_add(1);
            if n % 64 == 0 {
                crate::arch::x86_64::tlb::poll_from_wait();
            }
            if n % 1024 == 0 && crate::arch::x86_64::clock::elapsed_us(start) > 50_000 {
                return None; // ktoś stoi w środku rysowania – tylko serial
            }
        }
        FB_OWNER.store(me, Ordering::Relaxed);
        let result = unsafe { (*core::ptr::addr_of_mut!(FB)).as_mut().map(f) };
        FB_OWNER.store(0, Ordering::Relaxed);
        FB_BUSY.store(false, Ordering::Release);
        result
    })
}

/// Uruchamia konsolę framebuffera (wymaga heapa i pagingu).
pub fn init(boot: &BootInfo) -> bool {
    if boot.framebuffer_addr == 0 || boot.width == 0 || boot.height == 0 {
        serial_println!("[CON] No framebuffer – console on serial only");
        return false;
    }

    let wc_pages = crate::memory::map_write_combining(boot.framebuffer_addr, boot.framebuffer_size);

    // M10: CPU widzi framebuffer przez direct map (WC ustawione wyżej).
    let Some(fb) = FbConsole::new(
        crate::memory::phys_to_virt(boot.framebuffer_addr),
        boot.width as usize,
        boot.height as usize,
        boot.stride as usize,
        boot.pixel_format,
    ) else {
        serial_println!(
            "[CON] Unsupported framebuffer (format {}) – console on serial only",
            boot.pixel_format
        );
        return false;
    };
    let (cols, rows) = (fb.cols, fb.rows);
    FB_ADDRESS.store(boot.framebuffer_addr, Ordering::Relaxed);
    without_interrupts(|| unsafe {
        *core::ptr::addr_of_mut!(FB) = Some(fb);
    });

    serial_println!(
        "[CON] Framebuffer console {}x{} px at {:#x} -> {}x{} chars, {} ({} x 2 MiB write-combining)",
        boot.width,
        boot.height,
        boot.framebuffer_addr,
        cols,
        rows,
        if boot.pixel_format == 1 { "BGR" } else { "RGB" },
        wc_pages
    );
    true
}

/// Fizyczny adres framebuffera (0 = brak konsoli ekranowej).
#[allow(dead_code)]
pub fn fb_address() -> u64 {
    FB_ADDRESS.load(Ordering::Relaxed)
}

/// Rozmiar konsoli ekranowej w znakach (jeśli jest).
#[allow(dead_code)]
pub fn fb_size() -> Option<(usize, usize)> {
    with_fb(|fb| (fb.cols, fb.rows))
}

/// Dostęp do konsoli framebuffera (testy / diagnostyka).
#[allow(dead_code)]
pub fn with_framebuffer<R>(f: impl FnOnce(&mut FbConsole) -> R) -> Option<R> {
    with_fb(f)
}

struct ConsoleWriter;

/// Czy ostatni wypisany znak to '\n' (komunikat z tła zaczyna wtedy od
/// razu, inaczej od nowej linii).
static AT_LINE_START: AtomicBool = AtomicBool::new(true);

impl Write for ConsoleWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        serial::write_str(s);
        with_fb(|fb| fb.write_bytes(s.as_bytes()));
        if let Some(last) = s.chars().last() {
            AT_LINE_START.store(last == '\n', Ordering::Relaxed);
        }
        Ok(())
    }
}

// M17a: blokada wyjścia – cała linia logu na raz.  Przy wielu CPU (BKL
// oddawany w ticku, sekcje bez BKL) dwa komunikaty mieszały się w połowie
// (stress: "...(int3 at 0x40019[USER] process 13 ...").  Własna blokada,
// nie SpinLock: drukujemy także trzymając inne blokady (lockdep), w panic,
// NMI i raportach watchdoga.  Ten sam CPU wchodzi ponownie (przerwanie /
// panic w trakcie wypisywania), a obcy CPU czeka najwyżej ~20 ms i pisze
// mimo to – log nigdy nie może zawiesić systemu.  Wywłaszczanie wstrzymane
// na czas linii (tick nie przełączy zadania ani nie odda BKL w środku).
static OUT_OWNER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
const OUT_WAIT_US: u64 = 20_000;

/// `true` = wzięta (do oddania w `out_unlock`), `false` = już nasza / przejęta.
fn out_lock() -> bool {
    use crate::arch::x86_64::{clock, cpu};
    cpu::preempt_disable();
    let me = cpu::id() as u32 + 1;
    if OUT_OWNER.load(Ordering::Relaxed) == me {
        return false;
    }
    let start = clock::stamp();
    let mut n: u64 = 0;
    loop {
        if OUT_OWNER.compare_exchange_weak(0, me, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            return true;
        }
        core::hint::spin_loop();
        n += 1;
        if n % 64 == 0 {
            crate::arch::x86_64::tlb::poll_from_wait();
        }
        if n % 1024 == 0 && (clock::elapsed_us(start) > OUT_WAIT_US || n > 100_000_000) {
            // Właściciel stoi (np. czeka na BKL, który trzymamy) – piszemy.
            OUT_OWNER.store(me, Ordering::Release);
            return true;
        }
    }
}

fn out_unlock(took: bool) {
    if took {
        let me = crate::arch::x86_64::cpu::id() as u32 + 1;
        let _ = OUT_OWNER.compare_exchange(me, 0, Ordering::Release, Ordering::Relaxed);
    }
    crate::arch::x86_64::cpu::preempt_enable();
}

pub fn print_fmt(args: core::fmt::Arguments<'_>) {
    let t = out_lock();
    let _ = ConsoleWriter.write_fmt(args);
    out_unlock(t);
}

/// Linia logu (`serial_println!`): tekst + '\n' bez wtrąceń innych CPU.
pub fn print_line(args: core::fmt::Arguments<'_>) {
    let t = out_lock();
    let _ = ConsoleWriter.write_fmt(args);
    let _ = ConsoleWriter.write_str("\n");
    out_unlock(t);
}

#[allow(dead_code)]
pub fn write_str(s: &str) {
    let t = out_lock();
    let _ = ConsoleWriter.write_str(s);
    out_unlock(t);
}

// ------------------------------------------------------------
// Komunikaty z tła (np. koniec procesu) a edytowana linia shella
// ------------------------------------------------------------

/// Linia, którą shell właśnie edytuje (gotowy tekst do narysowania: prompt +
/// wpisany tekst + pozycja kursora).  None = shell nie czeka na klawisze.
/// M17a.d: SpinLock (nie usypiający Mutex) – czyta ją `write` bez BKL.
static INPUT_LINE: crate::sched::spin::IrqSpinLock<Option<alloc::string::String>> =
    crate::sched::spin::IrqSpinLock::new("input-line", crate::sched::spin::level::OUTPUT, None);

/// Shell: ustawia / czyści edytowaną linię (przed i po czekaniu na klawisz).
pub fn set_input_line(line: Option<alloc::string::String>) {
    *INPUT_LINE.lock() = line;
}

/// Tekst komunikatu z tła: jeśli shell edytuje linię – wyczyść ją, wypisz
/// komunikat i narysuj prompt z wpisanym tekstem jeszcze raz (jak readline).
pub fn compose_async(message: &str, line: Option<&str>) -> alloc::string::String {
    let mut s = alloc::string::String::new();
    if line.is_some() {
        s.push_str("\r\x1b[K");
    }
    s.push_str(message);
    s.push('\n');
    if let Some(l) = line {
        s.push_str(l);
    }
    s
}

/// M14: wyjście procesu (write na fd 1/2).  Gdy shell akurat edytuje linię
/// (proces działa w tle) – jak komunikat z tła: linia od nowa pod tekstem.
pub fn write_from_process(text: &str) {
    let line = INPUT_LINE.lock().clone();
    match line {
        None => write_str(text),
        Some(l) => {
            let mut s = alloc::string::String::from("\r\x1b[K");
            s.push_str(text);
            if !text.ends_with('\n') {
                s.push('\n');
            }
            s.push_str(&l);
            write_str(&s);
        }
    }
}

// ------------------------------------------------------------
// M14: procesy na pierwszym planie (Ctrl+C)
// ------------------------------------------------------------

static FOREGROUND: [core::sync::atomic::AtomicU64; 16] = [const { core::sync::atomic::AtomicU64::new(0) }; 16];

/// Shell: procesy na pierwszym planie (Ctrl+C je kończy).
pub fn set_foreground(ids: &[u64]) {
    for (i, slot) in FOREGROUND.iter().enumerate() {
        slot.store(ids.get(i).copied().unwrap_or(0), Ordering::SeqCst);
    }
}

pub fn clear_foreground() {
    set_foreground(&[]);
}

// M16: procesy pierwszego planu uruchamiane przez procesy (shell w user
// space) – stos: shell w shellu kładzie swoje dziecko na wierzch, Ctrl+C
// kończy tylko proces z wierzchu (a nie np. wewnętrzny shell).
static FG_STACK: [core::sync::atomic::AtomicU64; 16] = [const { core::sync::atomic::AtomicU64::new(0) }; 16];

/// Proces `id` na wierzch stosu pierwszego planu (spawn z flagą FOREGROUND).
pub fn push_foreground(id: u64) {
    crate::arch::x86_64::interrupts::without_interrupts(|| {
        if let Some(slot) = FG_STACK.iter().find(|s| s.load(Ordering::SeqCst) == 0) {
            slot.store(id, Ordering::SeqCst);
        } else {
            // Pełny stos: zastępujemy najstarszy wpis (rzadkie – 16 poziomów).
            for i in 0..FG_STACK.len() - 1 {
                FG_STACK[i].store(FG_STACK[i + 1].load(Ordering::SeqCst), Ordering::SeqCst);
            }
            FG_STACK[FG_STACK.len() - 1].store(id, Ordering::SeqCst);
        }
    });
}

/// Zdejmuje proces `id` z pierwszego planu (koniec procesu / wait).
pub fn remove_foreground(id: u64) {
    if id == 0 {
        return;
    }
    crate::arch::x86_64::interrupts::without_interrupts(|| {
        let mut entries: alloc::vec::Vec<u64> = FG_STACK
            .iter()
            .map(|s| s.load(Ordering::SeqCst))
            .filter(|&v| v != 0 && v != id)
            .collect();
        entries.resize(FG_STACK.len(), 0);
        for (slot, v) in FG_STACK.iter().zip(entries) {
            slot.store(v, Ordering::SeqCst);
        }
        for slot in FOREGROUND.iter() {
            let _ = slot.compare_exchange(id, 0, Ordering::SeqCst, Ordering::SeqCst);
        }
    });
}

/// Proces z wierzchu stosu pierwszego planu (0 = brak).
#[allow(dead_code)]
pub fn top_foreground() -> u64 {
    FG_STACK.iter().map(|s| s.load(Ordering::SeqCst)).filter(|&v| v != 0).last().unwrap_or(0)
}

/// Z IRQ klawiatury / seriala przy Ctrl+C: jeśli są procesy na pierwszym
/// planie – prośba o ich zakończenie i `true` (klawisz nie idzie dalej).
/// M16: najpierw proces z wierzchu stosu procesów (shell w user space);
/// gdy pusty – grupa ustawiona przez shell kernela (`run n` = n procesów).
pub fn interrupt_foreground() -> bool {
    let top = top_foreground();
    if top != 0 && crate::sched::request_exit(top) {
        return true;
    }
    let mut any = false;
    for slot in FOREGROUND.iter() {
        let id = slot.load(Ordering::SeqCst);
        if id != 0 {
            crate::sched::request_exit(id);
            any = true;
        }
    }
    any
}

/// Wypisuje komunikat z innego zadania tak, żeby nie rozbić linii shella.
/// Nie wołać z przerwań (blokada).
pub fn print_async(args: core::fmt::Arguments<'_>) {
    let mut message = alloc::format!("{}", args);
    let line = INPUT_LINE.lock().clone();
    if line.is_none() && !AT_LINE_START.load(Ordering::Relaxed) {
        message.insert(0, '\n'); // np. proces przerwany w połowie linii
    }
    write_str(&compose_async(&message, line.as_deref()));
}

/// Konsola jako `fmt::Write` (dla shella).
pub fn writer() -> impl Write {
    ConsoleWriter
}

// ------------------------------------------------------------
// Wejście
// ------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    Char(char),
    /// Ctrl + litera (mała), np. Ctrl('c').
    Ctrl(char),
    Enter,
    Backspace,
    Delete,
    Tab,
    Escape,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
}

/// Zdarzenie z klawiatury -> Key (tylko wciśnięcia).
pub fn key_from_event(e: &input::KeyEvent) -> Option<Key> {
    if !e.pressed {
        return None;
    }
    let k = match e.key {
        KeyCode::Enter | KeyCode::KpEnter => Key::Enter,
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Delete => Key::Delete,
        KeyCode::Tab => Key::Tab,
        KeyCode::Escape => Key::Escape,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        // Klawiatura numeryczna bez Num Lock = nawigacja.
        KeyCode::Kp4 if !e.mods.num_lock() => Key::Left,
        KeyCode::Kp6 if !e.mods.num_lock() => Key::Right,
        KeyCode::Kp8 if !e.mods.num_lock() => Key::Up,
        KeyCode::Kp2 if !e.mods.num_lock() => Key::Down,
        KeyCode::Kp7 if !e.mods.num_lock() => Key::Home,
        KeyCode::Kp1 if !e.mods.num_lock() => Key::End,
        KeyCode::KpPeriod if !e.mods.num_lock() => Key::Delete,
        _ => match e.ch {
            Some(c) if (c as u32) >= 1 && (c as u32) <= 26 => Key::Ctrl((b'a' + c as u8 - 1) as char),
            Some(c) if (c as u32) >= 0x20 => Key::Char(c),
            _ => return None,
        },
    };
    Some(k)
}

/// Dekoder bajtów z terminala (serial) -> Key.
pub struct SerialDecoder {
    state: u8, // 0 = zwykły, 1 = po ESC, 2 = po ESC[
    param: u16,
    utf8: [u8; 4],
    utf8_len: usize,
    utf8_need: usize,
    last_cr: bool,
}

impl SerialDecoder {
    pub const fn new() -> Self {
        SerialDecoder { state: 0, param: 0, utf8: [0; 4], utf8_len: 0, utf8_need: 0, last_cr: false }
    }

    pub fn feed(&mut self, b: u8) -> Option<Key> {
        match self.state {
            1 => {
                if b == b'[' || b == b'O' {
                    self.state = 2;
                    self.param = 0;
                    return None;
                }
                self.state = 0;
                // ESC + coś innego: samo ESC, znak przepada (rzadkie)
                return Some(Key::Escape);
            }
            2 => {
                if b.is_ascii_digit() {
                    self.param = self.param.saturating_mul(10).saturating_add((b - b'0') as u16);
                    return None;
                }
                if b == b';' {
                    return None;
                }
                self.state = 0;
                return match b {
                    b'A' => Some(Key::Up),
                    b'B' => Some(Key::Down),
                    b'C' => Some(Key::Right),
                    b'D' => Some(Key::Left),
                    b'H' => Some(Key::Home),
                    b'F' => Some(Key::End),
                    b'~' => match self.param {
                        1 | 7 => Some(Key::Home),
                        4 | 8 => Some(Key::End),
                        3 => Some(Key::Delete),
                        _ => None,
                    },
                    _ => None,
                };
            }
            _ => {}
        }

        if self.utf8_need > 0 {
            if b & 0xC0 != 0x80 {
                self.utf8_need = 0;
                return Some(Key::Char('?'));
            }
            self.utf8[self.utf8_len] = b;
            self.utf8_len += 1;
            if self.utf8_len < self.utf8_need {
                return None;
            }
            self.utf8_need = 0;
            let c = core::str::from_utf8(&self.utf8[..self.utf8_len])
                .ok()
                .and_then(|s| s.chars().next())
                .unwrap_or('?');
            return Some(Key::Char(c));
        }

        let was_cr = core::mem::replace(&mut self.last_cr, false);
        match b {
            0x1B => {
                self.state = 1;
                None
            }
            b'\r' => {
                self.last_cr = true;
                Some(Key::Enter)
            }
            b'\n' => {
                // CR LF od terminala = jedno Enter
                if was_cr { None } else { Some(Key::Enter) }
            }
            0x7F | 0x08 => Some(Key::Backspace),
            b'\t' => Some(Key::Tab),
            0x01..=0x1A => Some(Key::Ctrl((b'a' + b - 1) as char)),
            0x20..=0x7E => Some(Key::Char(b as char)),
            0xC0..=0xDF | 0xE0..=0xEF | 0xF0..=0xF7 => {
                self.utf8[0] = b;
                self.utf8_len = 1;
                self.utf8_need = match b {
                    0xC0..=0xDF => 2,
                    0xE0..=0xEF => 3,
                    _ => 4,
                };
                None
            }
            _ => None,
        }
    }
}

static mut SERIAL_DECODER: SerialDecoder = SerialDecoder::new();

/// M11: przewija ekran konsoli (scrollback) o `lines` linii wstecz
/// (ujemne = w przód).  Zwraca nowe przesunięcie (0 = na żywo).
pub fn scroll_view(lines: isize) -> usize {
    with_fb(|fb| fb.scroll_view(lines)).unwrap_or(0)
}

/// Przewijanie ekranu klawiaturą (obsługuje konsola, shell tych klawiszy
/// nie widzi):
///   Shift+↑ / Shift+↓       – o 1 linię,
///   Shift+PgUp / Shift+PgDn – o cały ekran (tyle linii, ile ma konsola).
fn scrollback_key(e: &input::KeyEvent) -> bool {
    if !e.mods.shift() {
        return false;
    }
    let page = || fb_size().map(|(_, rows)| rows.max(1) as isize).unwrap_or(0);
    // Klawiatura numeryczna też (8/2/9/3 = ↑/↓/PgUp/PgDn) – na części
    // laptopów i klawiatur PgUp jest tylko tam.
    let lines = match e.key {
        KeyCode::Up | KeyCode::Kp8 => 1,
        KeyCode::Down | KeyCode::Kp2 => -1,
        KeyCode::PageUp | KeyCode::Kp9 => page(),
        KeyCode::PageDown | KeyCode::Kp3 => -page(),
        _ => return false,
    };
    if e.pressed {
        scroll_view(lines);
    }
    true
}

/// Linie przewijane jednym "ząbkiem" kółka myszy.
const WHEEL_LINES: isize = 3;

/// Następny klawisz z klawiatury lub seriala (bez czekania).  Po drodze
/// obsługuje kółko myszy (przewijanie konsoli).
pub fn poll_key() -> Option<Key> {
    let wheel = crate::drivers::mouse::take_wheel();
    if wheel != 0 {
        // dz < 0 = kółko od siebie = w górę = wstecz.
        scroll_view(-(wheel as isize) * WHEEL_LINES);
    }
    while let Some(e) = input::read_event() {
        if scrollback_key(&e) {
            continue;
        }
        if let Some(k) = key_from_event(&e) {
            return Some(k);
        }
    }
    while let Some(b) = serial::read_byte() {
        // Dekoder używany tylko z kodu kernela (nie z IRQ).
        let d = unsafe { &mut *core::ptr::addr_of_mut!(SERIAL_DECODER) };
        if let Some(k) = d.feed(b) {
            return Some(k);
        }
    }
    None
}

/// M12: zadania czekające na wejście (klawiatura, serial, kółko myszy).
pub static INPUT_WAIT: WaitQueue = WaitQueue::new();

/// Z handlerów IRQ wejścia: jest coś nowego.
pub fn wake_input() {
    INPUT_WAIT.wake_all();
}

pub fn input_pending() -> bool {
    input::has_events() || serial::has_input() || crate::drivers::mouse::has_wheel()
}

/// Czeka na klawisz.  Zadanie śpi (inne zadania działają), budzi je
/// przerwanie klawiatury / seriala / myszy.  Wymaga włączonych przerwań.
pub fn wait_key() -> Key {
    loop {
        if let Some(k) = poll_key() {
            return k;
        }
        INPUT_WAIT.wait_until(input_pending, None);
    }
}
