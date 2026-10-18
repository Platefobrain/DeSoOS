// Kernel console.
//
// Output: all text goes to the serial port (terminal) and – after `init()` – to
// the framebuffer console.  All logs (`serial_println!`) pass through here,
// so they are also visible on the QEMU screen.
//
// Input: PS/2 keyboard (events from `input`) and bytes from the serial port
// (typing in a terminal).  Both sources are converted into a common `Key`.
// From serial we understand UTF-8 and the sequences ESC[A/B/C/D/H/F/3~ (arrows,
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
// The framebuffer console is in the middle of drawing (e.g. an exception mid-way) –
// then we write to serial only.
static FB_BUSY: AtomicBool = AtomicBool::new(false);

/// Which CPU is drawing (number + 1) – the same CPU in the middle of drawing
/// (exception) gets None, another CPU waits briefly (the BKL used to guarantee
/// that only one CPU draws; now a process `write` runs without the BKL).
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
                return None; // someone is in the middle of drawing – serial only
            }
        }
        FB_OWNER.store(me, Ordering::Relaxed);
        let result = unsafe { (*core::ptr::addr_of_mut!(FB)).as_mut().map(f) };
        FB_OWNER.store(0, Ordering::Relaxed);
        FB_BUSY.store(false, Ordering::Release);
        result
    })
}

/// Starts the framebuffer console (requires the heap and paging).
pub fn init(boot: &BootInfo) -> bool {
    if boot.framebuffer_addr == 0 || boot.width == 0 || boot.height == 0 {
        serial_println!("[CON] No framebuffer – console on serial only");
        return false;
    }

    let wc_pages = crate::memory::map_write_combining(boot.framebuffer_addr, boot.framebuffer_size);

    // The CPU sees the framebuffer through the direct map (WC set above).
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

/// Physical address of the framebuffer (0 = no screen console).
#[allow(dead_code)]
pub fn fb_address() -> u64 {
    FB_ADDRESS.load(Ordering::Relaxed)
}

/// Size of the screen console in characters (if present).
#[allow(dead_code)]
pub fn fb_size() -> Option<(usize, usize)> {
    with_fb(|fb| (fb.cols, fb.rows))
}

/// Access to the framebuffer console (tests / diagnostics).
#[allow(dead_code)]
pub fn with_framebuffer<R>(f: impl FnOnce(&mut FbConsole) -> R) -> Option<R> {
    with_fb(f)
}

struct ConsoleWriter;

/// Whether the last printed character was '\n' (a background message then starts
/// right away, otherwise on a new line).
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

// Output lock – a whole log line at once.  With multiple CPUs (BKL
// released on tick, sections without the BKL) two messages got interleaved mid-line
// (stress: "...(int3 at 0x40019[USER] process 13 ...").  A custom lock,
// not SpinLock: we also print while holding other locks (lockdep), in panic,
// NMI and watchdog reports.  The same CPU re-enters (interrupt /
// panic while printing), and a foreign CPU waits at most ~20 ms and writes
// anyway – logging must never hang the system.  Preemption is disabled
// for the duration of the line (the tick won't switch tasks or release the BKL mid-line).
static OUT_OWNER: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
const OUT_WAIT_US: u64 = 20_000;

/// `true` = acquired (release in `out_unlock`), `false` = already ours / taken over.
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
            // The owner is stuck (e.g. waiting for the BKL that we hold) – write anyway.
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

/// Log line (`serial_println!`): text + '\n' without interjections from other CPUs.
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
// Background messages vs. the line being edited in the shell
// ------------------------------------------------------------

/// The line the shell is currently editing (ready text to draw: prompt +
/// typed text + cursor position).  None = the shell is not waiting for keys.
/// SpinLock (not a sleeping Mutex) – `write` reads it without the BKL.
static INPUT_LINE: crate::sched::spin::IrqSpinLock<Option<alloc::string::String>> =
    crate::sched::spin::IrqSpinLock::new("input-line", crate::sched::spin::level::OUTPUT, None);

/// Shell: sets / clears the edited line (before and after waiting for a key).
pub fn set_input_line(line: Option<alloc::string::String>) {
    *INPUT_LINE.lock() = line;
}

/// Text of a background message: if the shell is editing a line – clear it, print
/// the message and redraw the prompt with the typed text (like readline).
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

/// Process output (write to fd 1/2).  When the shell happens to be editing a line
/// (process running in the background) – like a background message: line redrawn below the text.
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
// Foreground processes (Ctrl+C)
// ------------------------------------------------------------

static FOREGROUND: [core::sync::atomic::AtomicU64; 16] = [const { core::sync::atomic::AtomicU64::new(0) }; 16];

/// Shell: foreground processes (Ctrl+C terminates them).
pub fn set_foreground(ids: &[u64]) {
    for (i, slot) in FOREGROUND.iter().enumerate() {
        slot.store(ids.get(i).copied().unwrap_or(0), Ordering::SeqCst);
    }
}

pub fn clear_foreground() {
    set_foreground(&[]);
}

// Foreground processes started by processes (user-space
// shell) – a stack: a shell inside a shell puts its child on top, Ctrl+C
// terminates only the topmost process (not e.g. the inner shell).
static FG_STACK: [core::sync::atomic::AtomicU64; 16] = [const { core::sync::atomic::AtomicU64::new(0) }; 16];

/// Pushes process `id` on top of the foreground stack (spawn with the FOREGROUND flag).
pub fn push_foreground(id: u64) {
    crate::arch::x86_64::interrupts::without_interrupts(|| {
        if let Some(slot) = FG_STACK.iter().find(|s| s.load(Ordering::SeqCst) == 0) {
            slot.store(id, Ordering::SeqCst);
        } else {
            // Stack full: replace the oldest entry (rare – 16 levels).
            for i in 0..FG_STACK.len() - 1 {
                FG_STACK[i].store(FG_STACK[i + 1].load(Ordering::SeqCst), Ordering::SeqCst);
            }
            FG_STACK[FG_STACK.len() - 1].store(id, Ordering::SeqCst);
        }
    });
}

/// Removes process `id` from the foreground (process exit / wait).
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

/// Process at the top of the foreground stack (0 = none).
#[allow(dead_code)]
pub fn top_foreground() -> u64 {
    FG_STACK.iter().map(|s| s.load(Ordering::SeqCst)).filter(|&v| v != 0).last().unwrap_or(0)
}

/// From the keyboard / serial IRQ on Ctrl+C: if there are foreground
/// processes – request their termination and return `true` (the key goes no further).
/// First the top of the process stack (user-space shell);
/// when empty – the group set by the kernel shell (`run n` = n processes).
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

/// Prints a message from another task without breaking the shell line.
/// Do not call from interrupts (lock).
pub fn print_async(args: core::fmt::Arguments<'_>) {
    let mut message = alloc::format!("{}", args);
    let line = INPUT_LINE.lock().clone();
    if line.is_none() && !AT_LINE_START.load(Ordering::Relaxed) {
        message.insert(0, '\n'); // e.g. a process interrupted in the middle of a line
    }
    write_str(&compose_async(&message, line.as_deref()));
}

/// Console as `fmt::Write` (for the shell).
pub fn writer() -> impl Write {
    ConsoleWriter
}

// ------------------------------------------------------------
// Input
// ------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    Char(char),
    /// Ctrl + letter (lowercase), e.g. Ctrl('c').
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

/// Keyboard event -> Key (key presses only).
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
        // Numeric keypad without Num Lock = navigation.
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

/// Terminal (serial) byte decoder -> Key.
pub struct SerialDecoder {
    state: u8, // 0 = normal, 1 = after ESC, 2 = after ESC[
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
                // ESC + something else: plain ESC, the character is dropped (rare)
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
                // CR LF from the terminal = a single Enter
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

/// Scrolls the console screen (scrollback) by `lines` lines back
/// (negative = forward).  Returns the new offset (0 = live).
pub fn scroll_view(lines: isize) -> usize {
    with_fb(|fb| fb.scroll_view(lines)).unwrap_or(0)
}

/// Scrolling the screen with the keyboard (handled by the console, the shell
/// does not see these keys):
///   Shift+↑ / Shift+↓       – by 1 line,
///   Shift+PgUp / Shift+PgDn – by a whole screen (as many lines as the console has).
fn scrollback_key(e: &input::KeyEvent) -> bool {
    if !e.mods.shift() {
        return false;
    }
    let page = || fb_size().map(|(_, rows)| rows.max(1) as isize).unwrap_or(0);
    // The numeric keypad too (8/2/9/3 = ↑/↓/PgUp/PgDn) – on some
    // laptops and keyboards PgUp exists only there.
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

/// Lines scrolled per mouse wheel "notch".
const WHEEL_LINES: isize = 3;

/// Next key from the keyboard or serial (no waiting).  Along the way it
/// handles the mouse wheel (console scrolling).
pub fn poll_key() -> Option<Key> {
    let wheel = crate::drivers::mouse::take_wheel();
    if wheel != 0 {
        // dz < 0 = wheel away from the user = up = back.
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
        // Decoder used only from kernel code (not from IRQs).
        let d = unsafe { &mut *core::ptr::addr_of_mut!(SERIAL_DECODER) };
        if let Some(k) = d.feed(b) {
            return Some(k);
        }
    }
    None
}

/// Tasks waiting for input (keyboard, serial, mouse wheel).
pub static INPUT_WAIT: WaitQueue = WaitQueue::new();

/// From input IRQ handlers: something new arrived.
pub fn wake_input() {
    INPUT_WAIT.wake_all();
}

pub fn input_pending() -> bool {
    input::has_events() || serial::has_input() || crate::drivers::mouse::has_wheel()
}

/// Waits for a key.  The task sleeps (other tasks run), woken by a
/// keyboard / serial / mouse interrupt.  Requires interrupts enabled.
pub fn wait_key() -> Key {
    loop {
        if let Some(k) = poll_key() {
            return k;
        }
        INPUT_WAIT.wait_until(input_pending, None);
    }
}
