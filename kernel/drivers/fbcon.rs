// M7: konsola tekstowa na framebufferze z UEFI (GOP).
//
// Siatka komórek 8x16 (czcionka z font.rs), 16 kolorów, kursor.
// Rozumie ten sam podzbiór ANSI co terminal po drugiej stronie seriala,
// więc konsola wysyła jeden strumień bajtów w oba miejsca:
//
//   \n  nowa linia (jak CR+LF)      \r  początek linii
//   \x08 kursor w lewo              \t  do następnej wielokrotności 8
//   ESC[K   czyść do końca linii    ESC[2J  czyść ekran
//   ESC[H / ESC[r;cH  pozycja       ESC[nC / ESC[nD  kursor w prawo / lewo
//   ESC[...m  kolory: 0, 1 (jasny), 30–37, 90–97, 39, 40–47, 49
//
// Framebuffer tylko zapisujemy (nie czytamy – na pamięci WC odczyt jest
// bardzo wolny).  Stan ekranu trzymamy w siatce komórek; przy przewijaniu
// rysujemy tylko komórki, które się zmieniły.
//
// M11: scrollback – linie, które wyjechały górą, trafiają do historii
// (max SCROLLBACK_LINES).  `scroll_view(n)` pokazuje ekran przesunięty o n
// linii wstecz (Shift+PgUp/PgDn w console.rs), w prawym górnym rogu widać
// wskaźnik pozycji.  Każde nowe wyjście wraca na dół (jak w terminalu).

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use super::font;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub fg: u8,
    pub bg: u8,
}

const BLANK: Cell = Cell { ch: ' ', fg: DEFAULT_FG, bg: DEFAULT_BG };
pub const DEFAULT_FG: u8 = 7;
pub const DEFAULT_BG: u8 = 0;
pub const SCROLLBACK_LINES: usize = 1000;

// Paleta 16 kolorów (0xRRGGBB), jak w typowym terminalu.
const PALETTE: [u32; 16] = [
    0x000000, 0xAA0000, 0x00AA00, 0xAA5500, 0x0000AA, 0xAA00AA, 0x00AAAA, 0xAAAAAA,
    0x555555, 0xFF5555, 0x55FF55, 0xFFFF55, 0x5555FF, 0xFF55FF, 0x55FFFF, 0xFFFFFF,
];

enum Parse {
    Normal,
    Escape,
    Csi { params: [u16; 4], count: usize },
}

pub struct FbConsole {
    base: *mut u32,
    width: usize,
    height: usize,
    stride: usize, // piksele na linię
    bgr: bool,     // true: bajty B,G,R,x (u32 = 0x00RRGGBB)
    pub cols: usize,
    pub rows: usize,
    cells: Vec<Cell>,
    pub x: usize,
    pub y: usize,
    fg: u8,
    bg: u8,
    bright: bool,
    parse: Parse,
    cursor_drawn: bool,
    utf8: [u8; 4],
    utf8_len: usize,
    utf8_need: usize,
    /// Linie, które wyjechały górą (najstarsza z przodu).
    history: VecDeque<Vec<Cell>>,
    /// O ile linii widok jest przesunięty wstecz (0 = na żywo).
    view: usize,
}

// Wskaźnik do framebuffera; konsola jest używana tylko pod `without_interrupts`.
unsafe impl Send for FbConsole {}

impl FbConsole {
    /// `pixel_format`: 0 = RGB (bajty R,G,B,x), 1 = BGR (bajty B,G,R,x).
    pub fn new(addr: u64, width: usize, height: usize, stride: usize, pixel_format: u32) -> Option<Self> {
        if addr == 0 || width < font::WIDTH || height < font::HEIGHT || stride < width || pixel_format > 1 {
            return None;
        }
        let cols = width / font::WIDTH;
        let rows = height / font::HEIGHT;
        let mut con = FbConsole {
            base: addr as *mut u32,
            width,
            height,
            stride,
            bgr: pixel_format == 1,
            cols,
            rows,
            cells: vec![BLANK; cols * rows],
            x: 0,
            y: 0,
            fg: DEFAULT_FG,
            bg: DEFAULT_BG,
            bright: false,
            parse: Parse::Normal,
            cursor_drawn: false,
            utf8: [0; 4],
            utf8_len: 0,
            utf8_need: 0,
            history: VecDeque::new(),
            view: 0,
        };
        con.clear_screen();
        Some(con)
    }

    #[allow(dead_code)]
    pub fn size_pixels(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    #[allow(dead_code)]
    pub fn cell(&self, col: usize, row: usize) -> Cell {
        self.cells[row * self.cols + col]
    }

    fn color(&self, index: u8) -> u32 {
        let rgb = PALETTE[(index & 15) as usize];
        if self.bgr {
            rgb
        } else {
            // RGB: bajty R,G,B -> u32 little-endian = 0x00BBGGRR
            ((rgb & 0xFF) << 16) | (rgb & 0xFF00) | ((rgb >> 16) & 0xFF)
        }
    }

    /// Kolor piksela w formacie framebuffera (do testów).
    #[allow(dead_code)]
    pub fn native_color(&self, index: u8) -> u32 {
        self.color(index)
    }

    #[allow(dead_code)]
    pub fn read_pixel(&self, x: usize, y: usize) -> u32 {
        unsafe { core::ptr::read_volatile(self.base.add(y * self.stride + x)) }
    }

    fn draw_cell(&mut self, col: usize, row: usize, invert: bool) {
        let cell = self.cells[row * self.cols + col];
        self.draw_cell_value(col, row, cell, invert);
    }

    fn draw_cell_value(&mut self, col: usize, row: usize, cell: Cell, invert: bool) {
        let (mut fg, mut bg) = (self.color(cell.fg), self.color(cell.bg));
        if invert {
            core::mem::swap(&mut fg, &mut bg);
        }
        let glyph = font::glyph(cell.ch);
        let px = col * font::WIDTH;
        let py = row * font::HEIGHT;
        for (dy, bits) in glyph.iter().enumerate() {
            let line = unsafe { self.base.add((py + dy) * self.stride + px) };
            for dx in 0..font::WIDTH {
                let on = bits & (0x80 >> dx) != 0;
                unsafe {
                    core::ptr::write_volatile(line.add(dx), if on { fg } else { bg });
                }
            }
        }
    }

    /// M16b: napis rysowany wprost w pikselach (bez zmiany zawartości
    /// konsoli) – pasek stanu w prawym górnym rogu.  Znika przy przewinięciu
    /// i jest rysowany ponownie przez zadanie paska.
    pub fn draw_overlay(&mut self, text: &str, fg: u8, bg: u8) {
        let n = text.chars().count().min(self.cols);
        let start = self.cols - n;
        for (i, ch) in text.chars().take(n).enumerate() {
            self.draw_cell_value(start + i, 0, Cell { ch, fg, bg }, false);
        }
    }

    fn set_cell(&mut self, col: usize, row: usize, cell: Cell) {
        let i = row * self.cols + col;
        if self.cells[i] != cell {
            self.cells[i] = cell;
            self.draw_cell(col, row, false);
        }
    }

    fn hide_cursor(&mut self) {
        if self.cursor_drawn {
            self.cursor_drawn = false;
            if self.x < self.cols && self.y < self.rows {
                self.draw_cell(self.x, self.y, false);
            }
        }
    }

    fn show_cursor(&mut self) {
        if self.x < self.cols && self.y < self.rows {
            self.draw_cell(self.x, self.y, true);
            self.cursor_drawn = true;
        }
    }

    pub fn clear_screen(&mut self) {
        for i in 0..self.cells.len() {
            self.cells[i] = BLANK;
        }
        let bg = self.color(DEFAULT_BG);
        for y in 0..self.rows * font::HEIGHT {
            let line = unsafe { self.base.add(y * self.stride) };
            for x in 0..self.cols * font::WIDTH {
                unsafe { core::ptr::write_volatile(line.add(x), bg) };
            }
        }
        self.x = 0;
        self.y = 0;
        self.cursor_drawn = false;
    }

    fn scroll(&mut self) {
        let cols = self.cols;
        // Górna linia do historii (przy pełnej historii używamy ponownie
        // bufora najstarszej linii – bez nowej alokacji).
        let mut line = if self.history.len() >= SCROLLBACK_LINES {
            self.history.pop_front().unwrap_or_default()
        } else {
            Vec::with_capacity(cols)
        };
        line.clear();
        line.extend_from_slice(&self.cells[..cols]);
        self.history.push_back(line);

        for row in 0..self.rows - 1 {
            for col in 0..cols {
                let below = self.cells[(row + 1) * cols + col];
                self.set_cell(col, row, below);
            }
        }
        let last = self.rows - 1;
        for col in 0..cols {
            self.set_cell(col, last, BLANK);
        }
    }

    fn newline(&mut self) {
        self.x = 0;
        self.y += 1;
        if self.y >= self.rows {
            self.scroll();
            self.y = self.rows - 1;
        }
    }

    fn put_char(&mut self, c: char) {
        match c {
            '\n' => self.newline(),
            '\r' => self.x = 0,
            '\x08' => self.x = self.x.saturating_sub(1),
            '\t' => {
                let next = (self.x / 8 + 1) * 8;
                while self.x < next.min(self.cols) {
                    self.put_char(' ');
                }
            }
            c if (c as u32) < 0x20 => {}
            c => {
                if self.x >= self.cols {
                    self.newline();
                }
                let fg = if self.bright && self.fg < 8 { self.fg + 8 } else { self.fg };
                let cell = Cell { ch: c, fg, bg: self.bg };
                let (x, y) = (self.x, self.y);
                self.set_cell(x, y, cell);
                self.x += 1;
            }
        }
    }

    fn csi(&mut self, cmd: u8, params: &[u16]) {
        let p = |i: usize, default: u16| -> u16 {
            match params.get(i) {
                Some(&v) if v != 0 => v,
                _ => default,
            }
        };
        match cmd {
            b'K' => {
                // 0 (domyślnie): od kursora do końca linii
                let (x, y) = (self.x, self.y);
                for col in x..self.cols {
                    self.set_cell(col, y, BLANK);
                }
            }
            b'J' => {
                if params.first().copied().unwrap_or(0) == 2 {
                    self.clear_screen();
                }
            }
            b'H' => {
                self.y = (p(0, 1) as usize - 1).min(self.rows - 1);
                self.x = (p(1, 1) as usize - 1).min(self.cols - 1);
            }
            b'C' => self.x = (self.x + p(0, 1) as usize).min(self.cols - 1),
            b'D' => self.x = self.x.saturating_sub(p(0, 1) as usize),
            b'm' => {
                if params.is_empty() {
                    self.fg = DEFAULT_FG;
                    self.bg = DEFAULT_BG;
                    self.bright = false;
                }
                for &v in params {
                    match v {
                        0 => {
                            self.fg = DEFAULT_FG;
                            self.bg = DEFAULT_BG;
                            self.bright = false;
                        }
                        1 => self.bright = true,
                        22 => self.bright = false,
                        30..=37 => self.fg = (v - 30) as u8,
                        39 => self.fg = DEFAULT_FG,
                        40..=47 => self.bg = (v - 40) as u8,
                        49 => self.bg = DEFAULT_BG,
                        90..=97 => self.fg = (v - 90 + 8) as u8,
                        100..=107 => self.bg = (v - 100 + 8) as u8,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    fn byte_to_char(&mut self, b: u8) -> Option<char> {
        if self.utf8_need > 0 {
            if b & 0xC0 != 0x80 {
                self.utf8_need = 0;
                return Some('?');
            }
            self.utf8[self.utf8_len] = b;
            self.utf8_len += 1;
            if self.utf8_len == self.utf8_need {
                self.utf8_need = 0;
                return core::str::from_utf8(&self.utf8[..self.utf8_len])
                    .ok()
                    .and_then(|s| s.chars().next())
                    .or(Some('?'));
            }
            return None;
        }
        let need = match b {
            0x00..=0x7F => return Some(b as char),
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            _ => return Some('?'),
        };
        self.utf8[0] = b;
        self.utf8_len = 1;
        self.utf8_need = need;
        None
    }

    fn feed(&mut self, c: char) {
        match core::mem::replace(&mut self.parse, Parse::Normal) {
            Parse::Normal => {
                if c == '\x1b' {
                    self.parse = Parse::Escape;
                } else {
                    self.put_char(c);
                }
            }
            Parse::Escape => {
                if c == '[' {
                    self.parse = Parse::Csi { params: [0; 4], count: 0 };
                }
                // inne sekwencje ESC ignorujemy
            }
            Parse::Csi { mut params, mut count } => match c {
                '0'..='9' => {
                    if count == 0 {
                        count = 1;
                    }
                    let i = count - 1;
                    if i < params.len() {
                        params[i] = params[i].saturating_mul(10).saturating_add(c as u16 - '0' as u16);
                    }
                    self.parse = Parse::Csi { params, count };
                }
                ';' => {
                    count = if count == 0 { 2 } else { count + 1 };
                    self.parse = Parse::Csi { params, count };
                }
                '\x40'..='\x7e' => {
                    let n = count.min(params.len());
                    self.csi(c as u8, &params[..n]);
                }
                _ => {} // nieznany znak – porzucamy sekwencję
            },
        }
    }

    // --------------------------------------------------------
    // M11: scrollback
    // --------------------------------------------------------

    /// Liczba linii w historii.
    #[allow(dead_code)]
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// O ile linii widok jest przesunięty wstecz (0 = na żywo).
    #[allow(dead_code)]
    pub fn view_offset(&self) -> usize {
        self.view
    }

    /// Komórka, którą faktycznie widać na ekranie (z uwzględnieniem
    /// przewinięcia wstecz).
    pub fn visible_cell(&self, col: usize, row: usize) -> Cell {
        // Wiersz `row` ekranu = linia nr (history.len() - view + row)
        // w ciągu [historia..., bieżący ekran...].
        let line = self.history.len() - self.view + row;
        if line < self.history.len() {
            self.history[line].get(col).copied().unwrap_or(BLANK)
        } else {
            self.cells[(line - self.history.len()) * self.cols + col]
        }
    }

    fn redraw_view(&mut self) {
        self.cursor_drawn = false;
        for row in 0..self.rows {
            for col in 0..self.cols {
                let cell = self.visible_cell(col, row);
                self.draw_cell_value(col, row, cell, false);
            }
        }
        if self.view == 0 {
            self.show_cursor();
            return;
        }
        // Wskaźnik w prawym górnym rogu, np. " -25/1000 ".
        let label = alloc::format!(" -{}/{} ", self.view, self.history.len());
        let n = label.chars().count().min(self.cols);
        for (i, ch) in label.chars().take(n).enumerate() {
            let cell = Cell { ch, fg: DEFAULT_FG, bg: DEFAULT_BG };
            self.draw_cell_value(self.cols - n + i, 0, cell, true);
        }
    }

    /// Przewija widok: `lines` > 0 wstecz (w górę), < 0 w przód.  Zwraca
    /// nowe przesunięcie.
    pub fn scroll_view(&mut self, lines: isize) -> usize {
        let target = if lines >= 0 {
            self.view.saturating_add(lines as usize)
        } else {
            self.view.saturating_sub(lines.unsigned_abs())
        }
        .min(self.history.len());
        if target != self.view {
            self.view = target;
            self.redraw_view();
        }
        self.view
    }

    /// Wypisuje bajty (UTF-8 + ANSI) i odświeża kursor.  Gdy widok jest
    /// przewinięty wstecz, najpierw wraca na dół.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        if self.view != 0 {
            self.view = 0;
            self.redraw_view();
        }
        self.hide_cursor();
        for &b in bytes {
            if let Some(c) = self.byte_to_char(b) {
                self.feed(c);
            }
        }
        self.show_cursor();
    }
}
