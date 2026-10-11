// M16: shell w user space (ring 3).  Uruchamia go init.
//
//   desoos:/disk$ ls /bin
//   desoos:/$ primes 100 > /disk/p.txt &
//
// * Edycja linii: ←/→, Home/End, Backspace/Delete, historia ↑/↓, Tab =
//   dopełnianie nazwy komendy, Ctrl+C = porzuć linię, Ctrl+U = wyczyść,
//   Ctrl+L = wyczyść ekran, Ctrl+D na pustej linii = wyjście.
// * Słowa jak w zwykłym shellu: spacje dzielą, "..." i '...' grupują.
// * Przekierowania: > plik, >> plik, < plik; & na końcu = w tle.
// * M17b: potoki `a | b | c` (programy z /bin; z wbudowanych echo, pwd,
//   help, history).
// * Komendy wbudowane: cd, pwd, echo, exit, help, history, clear, wait, k.
// * Inne nazwy: program /bin/<nazwa> albo ścieżka (z '/'), a gdy go nie ma –
//   komenda diagnostyczna shella kernela (syscall kcmd; `k <komenda>`
//   wymusza kernel).
// * Ctrl+C w trakcie programu kończy program (nie shell) – kernel zna
//   proces pierwszego planu (spawn z SPAWN_FOREGROUND).
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use desoos::{
    ECHILD, ENOENT, ERANGE, Key, O_APPEND, O_CREATE, O_READ, O_TRUNC, O_WRITE, SPAWN_FOREGROUND, WAIT_ANY, WNOHANG,
    close, describe_status, fds, open, readkey, spawn, strerror, wait, write,
};

entry!(main);

const TERMINAL_WIDTH: usize = 80;
const MIN_LINE: usize = 24;
const HISTORY_MAX: usize = 32;

const BUILTINS: &[(&str, &str)] = &[
    ("cd", "cd [dir]           change directory (no argument: /)"),
    ("pwd", "pwd                print the current directory"),
    ("echo", "echo [text...]     print text"),
    ("exit", "exit [code]        leave the shell (init starts a new one)"),
    ("help", "help               this list"),
    ("history", "history            command history"),
    ("clear", "clear              clear the screen (also Ctrl+L)"),
    ("wait", "wait               wait for background programs"),
    ("k", "k <command>        kernel diagnostics (k help: list)"),
];

/// Komendy shella kernela dostępne przez kcmd (do dopełniania i podpowiedzi).
const KERNEL_COMMANDS: &[&str] = &[
    "ver", "uptime", "mem", "irq", "spawn", "colors", "lspci", "acpi", "disk", "hexdump", "write", "mount", "df", "mkfs",
    "sync", "date", "reboot", "halt", "run",
];

// ------------------------------------------------------------
// Wyjście
// ------------------------------------------------------------

fn out(s: &str) {
    write(1, s.as_bytes());
}

// ------------------------------------------------------------
// Edytor linii
// ------------------------------------------------------------

enum Edit {
    Nothing,
    Echo(char),
    Redraw,
    Submit(String),
    Cancel,
    ClearScreen,
    Candidates(Vec<String>),
    Eof,
}

struct LineEditor {
    buf: Vec<char>,
    cursor: usize,
    history: Vec<String>,
    browsing: Option<usize>,
    draft: Vec<char>,
    prompt: String,
    prompt_width: usize,
}

impl LineEditor {
    fn new() -> Self {
        LineEditor {
            buf: Vec::new(),
            cursor: 0,
            history: Vec::new(),
            browsing: None,
            draft: Vec::new(),
            prompt: String::new(),
            prompt_width: 0,
        }
    }

    /// "desoos:/disk$ " – '$' odróżnia shell procesu od shella kernela ('>').
    fn set_prompt(&mut self, cwd: &str) {
        self.prompt = format!("\x1b[1;32mdesoos\x1b[0m:\x1b[1;34m{}\x1b[0m$ ", cwd);
        self.prompt_width = "desoos:".len() + cwd.chars().count() + 2;
    }

    fn max_len(&self) -> usize {
        TERMINAL_WIDTH.saturating_sub(self.prompt_width + 1).max(MIN_LINE)
    }

    fn line(&self) -> String {
        self.buf.iter().collect()
    }

    fn set_line(&mut self, chars: Vec<char>) {
        self.buf = chars;
        self.cursor = self.buf.len();
    }

    fn reset(&mut self) {
        self.buf.clear();
        self.cursor = 0;
        self.browsing = None;
        self.draft.clear();
    }

    fn handle(&mut self, key: Key) -> Edit {
        match key {
            Key::Char(c) => {
                if self.buf.len() >= self.max_len() {
                    return Edit::Nothing;
                }
                self.buf.insert(self.cursor, c);
                self.cursor += 1;
                if self.cursor == self.buf.len() { Edit::Echo(c) } else { Edit::Redraw }
            }
            Key::Backspace => {
                if self.cursor == 0 {
                    return Edit::Nothing;
                }
                self.cursor -= 1;
                self.buf.remove(self.cursor);
                Edit::Redraw
            }
            Key::Delete => {
                if self.cursor == self.buf.len() {
                    return Edit::Nothing;
                }
                self.buf.remove(self.cursor);
                Edit::Redraw
            }
            Key::Left if self.cursor > 0 => {
                self.cursor -= 1;
                Edit::Redraw
            }
            Key::Right if self.cursor < self.buf.len() => {
                self.cursor += 1;
                Edit::Redraw
            }
            Key::Home | Key::Ctrl('a') => {
                self.cursor = 0;
                Edit::Redraw
            }
            Key::End | Key::Ctrl('e') => {
                self.cursor = self.buf.len();
                Edit::Redraw
            }
            Key::Up => {
                if self.history.is_empty() {
                    return Edit::Nothing;
                }
                let pos = match self.browsing {
                    None => {
                        self.draft = self.buf.clone();
                        self.history.len() - 1
                    }
                    Some(0) => return Edit::Nothing,
                    Some(p) => p - 1,
                };
                self.browsing = Some(pos);
                self.set_line(self.history[pos].chars().collect());
                Edit::Redraw
            }
            Key::Down => {
                let Some(pos) = self.browsing else {
                    return Edit::Nothing;
                };
                if pos + 1 < self.history.len() {
                    self.browsing = Some(pos + 1);
                    self.set_line(self.history[pos + 1].chars().collect());
                } else {
                    self.browsing = None;
                    let draft = core::mem::take(&mut self.draft);
                    self.set_line(draft);
                }
                Edit::Redraw
            }
            Key::Enter => {
                let line = self.line();
                let trimmed = line.trim();
                if !trimmed.is_empty() && self.history.last().map(|s| s.as_str()) != Some(trimmed) {
                    if self.history.len() == HISTORY_MAX {
                        self.history.remove(0);
                    }
                    self.history.push(String::from(trimmed));
                }
                self.reset();
                Edit::Submit(line)
            }
            Key::Ctrl('c') => {
                self.reset();
                Edit::Cancel
            }
            Key::Ctrl('d') if self.buf.is_empty() => Edit::Eof,
            Key::Eof => Edit::Eof,
            Key::Ctrl('u') => {
                self.buf.clear();
                self.cursor = 0;
                Edit::Redraw
            }
            Key::Ctrl('l') => Edit::ClearScreen,
            Key::Tab => self.complete(),
            _ => Edit::Nothing,
        }
    }

    /// Dopełnianie pierwszego słowa: komendy wbudowane, /bin, kernel.
    fn complete(&mut self) -> Edit {
        if self.cursor != self.buf.len() || self.buf.contains(&' ') {
            return Edit::Nothing;
        }
        let prefix = self.line();
        let mut matches: Vec<String> =
            command_names().into_iter().filter(|n| n.starts_with(prefix.as_str())).collect();
        matches.sort();
        matches.dedup();
        match matches.len() {
            0 => Edit::Nothing,
            1 => {
                let mut chars: Vec<char> = matches[0].chars().collect();
                chars.push(' ');
                self.set_line(chars);
                Edit::Redraw
            }
            _ => Edit::Candidates(matches),
        }
    }

    fn render(&self) -> String {
        let mut s = format!("\r{}{}\x1b[K", self.prompt, self.line());
        let back = self.buf.len() - self.cursor;
        if back > 0 {
            s.push_str(&format!("\x1b[{}D", back));
        }
        s
    }
}

// ------------------------------------------------------------
// Słowa i przekierowania
// ------------------------------------------------------------

struct Word {
    text: String,
    /// Słowo (albo jego część) w cudzysłowie – nie jest operatorem.
    quoted: bool,
}

fn split_words(line: &str) -> Result<Vec<Word>, &'static str> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quoted = false;
    let mut quote: Option<char> = None;
    for c in line.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => {
                quote = Some(c);
                in_word = true;
                quoted = true;
            }
            // M17b: '|' poza cudzysłowem – osobne słowo (operator potoku).
            None if c == '|' => {
                if in_word {
                    words.push(Word { text: core::mem::take(&mut cur), quoted });
                    in_word = false;
                    quoted = false;
                }
                words.push(Word { text: String::from("|"), quoted: false });
            }
            None if c == ' ' || c == '\t' => {
                if in_word {
                    words.push(Word { text: core::mem::take(&mut cur), quoted });
                    in_word = false;
                    quoted = false;
                }
            }
            None => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if quote.is_some() {
        return Err("missing closing quote");
    }
    if in_word {
        words.push(Word { text: cur, quoted });
    }
    Ok(words)
}

struct Command {
    args: Vec<String>,
    stdin: Option<String>,
    stdout: Option<(String, bool)>, // (plik, dopisywanie)
    background: bool,
}

/// Linia: jedna komenda albo potok `a | b | c` (& tylko na końcu).
fn parse(line: &str) -> Result<Option<Vec<Command>>, &'static str> {
    let words = split_words(line)?;
    let segments: Vec<&[Word]> = words.split(|w| !w.quoted && w.text == "|").collect();
    if segments.len() == 1 {
        return Ok(parse_words(segments[0])?.map(|c| vec![c]));
    }
    let mut cmds = Vec::new();
    for (i, seg) in segments.iter().enumerate() {
        let cmd = parse_words(seg)?.ok_or("missing command around |")?;
        if cmd.background && i + 1 < segments.len() {
            return Err("& only at the end of a pipeline");
        }
        cmds.push(cmd);
    }
    Ok(Some(cmds))
}

fn parse_words(words: &[Word]) -> Result<Option<Command>, &'static str> {
    let mut cmd = Command { args: Vec::new(), stdin: None, stdout: None, background: false };
    let mut i = 0;
    while i < words.len() {
        let w = &words[i];
        let t = w.text.as_str();
        if !w.quoted {
            if t == "&" && i == words.len() - 1 {
                cmd.background = true;
                i += 1;
                continue;
            }
            // > plik, >> plik, < plik (także sklejone: >plik).
            let op = if t.starts_with(">>") { Some((2, true)) } else if t.starts_with('>') { Some((1, false)) } else { None };
            if let Some((len, append)) = op {
                let target = if t.len() > len { String::from(&t[len..]) } else {
                    i += 1;
                    words.get(i).map(|w| w.text.clone()).ok_or("missing file name after >")?
                };
                cmd.stdout = Some((target, append));
                i += 1;
                continue;
            }
            if let Some(rest) = t.strip_prefix('<') {
                let target = if !rest.is_empty() { String::from(rest) } else {
                    i += 1;
                    words.get(i).map(|w| w.text.clone()).ok_or("missing file name after <")?
                };
                cmd.stdin = Some(target);
                i += 1;
                continue;
            }
            if i == words.len() - 1 && t.len() > 1 && t.ends_with('&') {
                cmd.args.push(String::from(&t[..t.len() - 1]));
                cmd.background = true;
                i += 1;
                continue;
            }
        }
        cmd.args.push(w.text.clone());
        i += 1;
    }
    if cmd.args.is_empty() {
        if cmd.stdin.is_some() || cmd.stdout.is_some() || cmd.background {
            return Err("missing command");
        }
        return Ok(None);
    }
    Ok(Some(cmd))
}

// ------------------------------------------------------------
// Pomocnicze
// ------------------------------------------------------------

/// Nazwy plików w /bin.
fn bin_programs() -> Vec<String> {
    let mut buf = vec![0u8; 4096];
    loop {
        let n = desoos::readdir("/bin", &mut buf);
        if n == ERANGE && buf.len() < 64 * 1024 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if n < 0 {
            return Vec::new();
        }
        let text = core::str::from_utf8(&buf[..n as usize]).unwrap_or("");
        return text
            .lines()
            .filter_map(|l| {
                let mut parts = l.splitn(3, '\t');
                let kind = parts.next()?;
                let _size = parts.next()?;
                let name = parts.next()?;
                if kind == "f" { Some(String::from(name)) } else { None }
            })
            .collect();
    }
}

fn command_names() -> Vec<String> {
    let mut names: Vec<String> = BUILTINS.iter().map(|(n, _)| String::from(*n)).collect();
    names.extend(bin_programs());
    names.extend(KERNEL_COMMANDS.iter().map(|n| String::from(*n)));
    names
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = if ca == *cb { 0 } else { 1 };
            cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

fn suggest(name: &str) -> Option<String> {
    command_names()
        .into_iter()
        .map(|n| (edit_distance(name, &n), n))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, n)| n)
}

/// Ścieżka programu: z '/' – jak podano (kernel liczy względem cwd),
/// inaczej /bin/<nazwa>, o ile istnieje.
fn find_program(name: &str) -> Option<String> {
    if name.contains('/') {
        return Some(String::from(name));
    }
    let path = format!("/bin/{}", name);
    match desoos::stat(&path) {
        Ok(s) if !s.is_dir => Some(path),
        _ => None,
    }
}

/// Otwiera pliki przekierowań; zwraca (fd wejścia, fd wyjścia) – 0/1 bez
/// przekierowania.  Pliki zamyka `close_redirects`.
fn open_redirects(cmd: &Command) -> Result<(u64, u64), String> {
    let mut fin = 0u64;
    if let Some(path) = &cmd.stdin {
        let fd = open(path, O_READ);
        if fd < 0 {
            return Err(format!("{}: {}", path, strerror(fd)));
        }
        fin = fd as u64;
    }
    let mut fout = 1u64;
    if let Some((path, append)) = &cmd.stdout {
        let flags = O_WRITE | O_CREATE | if *append { O_APPEND } else { O_TRUNC };
        let fd = open(path, flags);
        if fd < 0 {
            if fin != 0 {
                close(fin);
            }
            return Err(format!("{}: {}", path, strerror(fd)));
        }
        fout = fd as u64;
    }
    Ok((fin, fout))
}

fn close_redirects(fin: u64, fout: u64) {
    if fin != 0 {
        close(fin);
    }
    if fout != 1 {
        close(fout);
    }
}

// ------------------------------------------------------------
// Shell
// ------------------------------------------------------------

struct Shell {
    editor: LineEditor,
    cwd: String,
    background: Vec<(u64, String)>,
    exit: Option<i32>,
}

impl Shell {
    fn refresh_cwd(&mut self) {
        let mut buf = [0u8; 256];
        self.cwd = String::from(desoos::getcwd(&mut buf));
    }

    /// Zakończone programy z tła (przed promptem, jak w bash).
    fn reap_background(&mut self) {
        loop {
            match wait(WAIT_ANY, WNOHANG) {
                Ok((0, _)) | Err(_) => return,
                Ok((pid, status)) => self.report_done(pid, status),
            }
        }
    }

    fn report_done(&mut self, pid: u64, status: u64) {
        if let Some(i) = self.background.iter().position(|(p, _)| *p == pid) {
            let (_, name) = self.background.remove(i);
            if status & desoos::STATUS_SIGNALED == 0 && status != 0 {
                println!("[{}] {} exited (code {})", pid, name, status);
            } else {
                println!("[{}] {} {}", pid, name, describe_status(status));
            }
        }
    }

    fn run_line(&mut self, line: &str) {
        let mut cmds = match parse(line) {
            Ok(Some(cmds)) => cmds,
            Ok(None) => return,
            Err(e) => {
                eprintln!("sh: {}", e);
                return;
            }
        };
        if cmds.len() > 1 {
            self.pipeline(&cmds);
            return;
        }
        let cmd = cmds.remove(0);
        let name = cmd.args[0].clone();
        if BUILTINS.iter().any(|(n, _)| *n == name) {
            self.builtin(&cmd);
            return;
        }
        if let Some(path) = find_program(&name) {
            self.external(&path, &cmd);
            return;
        }
        // Komenda shella kernela (diagnostyka) – jeśli taka jest.
        if self.kernel(&cmd, false) {
            return;
        }
        match suggest(&name) {
            Some(s) => eprintln!("sh: {}: command not found - did you mean '{}'? (type 'help')", name, s),
            None => eprintln!("sh: {}: command not found (type 'help')", name),
        }
    }

    fn external(&mut self, path: &str, cmd: &Command) {
        let (fin, fout) = match open_redirects(cmd) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("sh: {}", e);
                return;
            }
        };
        let args: Vec<&str> = cmd.args.iter().map(|s| s.as_str()).collect();
        let flags = if cmd.background { 0 } else { SPAWN_FOREGROUND };
        let pid = spawn(path, &args, flags, fds(fin, fout, 2));
        close_redirects(fin, fout);
        if pid < 0 {
            eprintln!("sh: {}: {}", cmd.args[0], strerror(pid));
            return;
        }
        let pid = pid as u64;
        if cmd.background {
            println!("[{}] {} started in the background ('ps', 'kill {}', 'wait')", pid, cmd.args[0], pid);
            self.background.push((pid, cmd.args[0].clone()));
            return;
        }
        match wait(pid, 0) {
            Ok((_, status)) => {
                if status == desoos::STATUS_SIGNALED | 9 {
                    // Ctrl+C (albo kill z innego miejsca) – jak w zwykłym shellu.
                    out("^C\n");
                }
            }
            Err(e) => eprintln!("sh: wait: {}", strerror(e)),
        }
    }

    /// M17b: potok `a | b | c`.  Najpierw wszystkie potoki i programy (każdy
    /// dostaje swój koniec jako 0 / 1; jawne < > mają pierwszeństwo), potem
    /// shell zamyka swoje kopie końców – czytający dostaje koniec danych, gdy
    /// skończy się piszący – a wbudowane (echo, pwd, help, history) pisze sam
    /// do swojego potoku.  Na końcu czeka na wszystkie programy.
    fn pipeline(&mut self, cmds: &[Command]) {
        const PIPE_BUILTINS: &[&str] = &["echo", "pwd", "help", "history"];
        // Sprawdzenie nazw przed utworzeniem czegokolwiek.
        let mut paths: Vec<Option<String>> = Vec::new();
        for c in cmds {
            let name = c.args[0].as_str();
            if PIPE_BUILTINS.contains(&name) {
                paths.push(None);
            } else if BUILTINS.iter().any(|(n, _)| *n == name) {
                eprintln!("sh: {}: not supported in a pipeline", name);
                return;
            } else if let Some(p) = find_program(name) {
                paths.push(Some(p));
            } else {
                eprintln!("sh: {}: command not found (type 'help')", name);
                return;
            }
        }
        let n = cmds.len();
        let mut pipes: Vec<(u64, u64)> = Vec::new();
        for _ in 1..n {
            match desoos::pipe() {
                Ok(p) => pipes.push(p),
                Err(e) => {
                    eprintln!("sh: pipe: {}", strerror(e));
                    for (r, w) in pipes {
                        close(r);
                        close(w);
                    }
                    return;
                }
            }
        }
        let background = cmds[n - 1].background;
        let flags = if background { 0 } else { SPAWN_FOREGROUND };
        let mut pids: Vec<(u64, String)> = Vec::new();
        let mut redirects: Vec<(u64, u64)> = Vec::new();
        let mut builtins: Vec<(usize, u64)> = Vec::new();
        for (i, c) in cmds.iter().enumerate() {
            let mut fin = if i == 0 { 0 } else { pipes[i - 1].0 };
            let mut fout = if i == n - 1 { 1 } else { pipes[i].1 };
            match open_redirects(c) {
                Ok((rin, rout)) => {
                    if rin != 0 {
                        fin = rin;
                    }
                    if rout != 1 {
                        fout = rout;
                    }
                    redirects.push((rin, rout));
                }
                Err(e) => {
                    eprintln!("sh: {}", e);
                    continue;
                }
            }
            match &paths[i] {
                None => builtins.push((i, fout)),
                Some(path) => {
                    let args: Vec<&str> = c.args.iter().map(|s| s.as_str()).collect();
                    let pid = spawn(path, &args, flags, fds(fin, fout, 2));
                    if pid < 0 {
                        eprintln!("sh: {}: {}", c.args[0], strerror(pid));
                    } else {
                        pids.push((pid as u64, c.args[0].clone()));
                    }
                }
            }
        }
        // Kopie końców w shellu – zamknięte (poza wyjściem wbudowanych).
        for (r, w) in &pipes {
            close(*r);
            if !builtins.iter().any(|(_, fout)| fout == w) {
                close(*w);
            }
        }
        for (i, fout) in &builtins {
            self.print_builtin(&cmds[*i], *fout);
            if pipes.iter().any(|(_, w)| w == fout) {
                close(*fout);
            }
        }
        for (rin, rout) in redirects {
            close_redirects(rin, rout);
        }
        if background {
            let names: Vec<&str> = cmds.iter().map(|c| c.args[0].as_str()).collect();
            let label = names.join(" | ");
            if let Some((last, _)) = pids.last() {
                println!("[{}] {} started in the background ('ps', 'wait')", last, label);
            }
            for (pid, name) in pids {
                self.background.push((pid, name));
            }
            return;
        }
        let mut interrupted = false;
        for (pid, _) in pids {
            if let Ok((_, status)) = wait(pid, 0) {
                interrupted |= status == desoos::STATUS_SIGNALED | 9;
            }
        }
        if interrupted {
            out("^C\n");
        }
    }

    /// Wbudowane komendy, które tylko piszą (także w potoku).
    fn print_builtin(&self, cmd: &Command, fout: u64) {
        let mut o = desoos::Out::new(fout);
        use core::fmt::Write;
        match cmd.args[0].as_str() {
            "pwd" => {
                let _ = writeln!(o, "{}", self.cwd);
            }
            "echo" => {
                let _ = writeln!(o, "{}", cmd.args[1..].join(" "));
            }
            "help" => {
                let _ = writeln!(o, "Shell commands:");
                for (_, usage) in BUILTINS {
                    let _ = writeln!(o, "  {}", usage);
                }
                let mut bin = bin_programs();
                bin.sort();
                let _ = writeln!(o, "Programs in /bin:");
                let _ = writeln!(o, "  {}", bin.join("  "));
                let _ = writeln!(o, "Kernel diagnostics (run directly or as 'k <command>'):");
                let _ = writeln!(o, "  {}", KERNEL_COMMANDS.join("  "));
                let _ = writeln!(o, "  ('run' = ring 3 test programs in asm from M13-M14, e.g. run sum, run xmm 4)");
                let _ = writeln!(o, "Syntax: cmd args  > file  >> file  < file  a | b  &   (\"quotes\" group words)");
            }
            "history" => {
                for (i, h) in self.editor.history.iter().enumerate() {
                    let _ = writeln!(o, "{:>3}  {}", i + 1, h);
                }
            }
            _ => {}
        }
    }

    /// Komenda shella kernela przez kcmd.  `forced`: `k <komenda>`.
    fn kernel(&mut self, cmd: &Command, forced: bool) -> bool {
        let words: &[String] = if forced { &cmd.args[1..] } else { &cmd.args[..] };
        if words.is_empty() {
            eprintln!("usage: k <command> [args]   (k help: kernel commands)");
            return true;
        }
        let line = words.join(" ");
        let (fin, fout) = match open_redirects(cmd) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("sh: {}", e);
                return true;
            }
        };
        let r = desoos::kcmd(&line, fout);
        close_redirects(fin, fout);
        if r == ENOENT {
            if forced {
                eprintln!("k: {}: no such kernel command (k help)", words[0]);
            }
            return forced;
        }
        if r < 0 {
            eprintln!("k: {}", strerror(r));
        }
        true
    }

    fn builtin(&mut self, cmd: &Command) {
        let name = cmd.args[0].as_str();
        if name == "k" {
            self.kernel(cmd, true);
            return;
        }
        let (fin, fout) = match open_redirects(cmd) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("sh: {}", e);
                return;
            }
        };
        let mut o = desoos::Out::new(fout);
        use core::fmt::Write;
        match name {
            "cd" => {
                let target = cmd.args.get(1).map(|s| s.as_str()).unwrap_or("/");
                let r = desoos::chdir(target);
                if r < 0 {
                    eprintln!("cd: {}: {}", target, strerror(r));
                }
                self.refresh_cwd();
            }
            "pwd" | "echo" | "help" | "history" => {
                drop(o);
                self.print_builtin(cmd, fout);
                close_redirects(fin, fout);
                return;
            }
            "exit" => {
                let code = cmd.args.get(1).and_then(|s| s.parse::<i32>().ok()).unwrap_or(0);
                self.exit = Some(code);
            }
            "clear" => {
                let _ = write!(o, "\x1b[2J\x1b[H");
            }
            "wait" => {
                drop(o);
                loop {
                    match wait(WAIT_ANY, 0) {
                        Ok((pid, status)) => self.report_done(pid, status),
                        Err(ECHILD) => break,
                        Err(e) => {
                            eprintln!("wait: {}", strerror(e));
                            break;
                        }
                    }
                }
                close_redirects(fin, fout);
                return;
            }
            _ => {}
        }
        drop(o);
        close_redirects(fin, fout);
    }

    fn read_and_run(&mut self) {
        self.editor.set_prompt(&self.cwd);
        out(&self.editor.render());
        loop {
            let snapshot = self.editor.render();
            let key = match readkey(&snapshot) {
                Ok(k) => k,
                Err(_) => Key::Eof,
            };
            match self.editor.handle(key) {
                Edit::Nothing => {}
                Edit::Echo(c) => {
                    let mut b = [0u8; 4];
                    out(c.encode_utf8(&mut b));
                }
                Edit::Redraw => out(&self.editor.render()),
                Edit::Cancel => {
                    out("^C\n");
                    return;
                }
                Edit::Eof => {
                    out("\n");
                    self.exit = Some(0);
                    return;
                }
                Edit::ClearScreen => {
                    out("\x1b[2J\x1b[H");
                    out(&self.editor.render());
                }
                Edit::Candidates(list) => {
                    out("\n");
                    out(&list.join("  "));
                    out("\n");
                    out(&self.editor.render());
                }
                Edit::Submit(line) => {
                    out("\n");
                    self.run_line(&line);
                    return;
                }
            }
        }
    }
}

fn main(args: desoos::Args) -> i32 {
    let mut sh = Shell { editor: LineEditor::new(), cwd: String::from("/"), background: Vec::new(), exit: None };
    sh.refresh_cwd();
    // sh -c "komenda": jedna linia i koniec (skrypty, testy).
    if args.get(1) == Some("-c") {
        let line: Vec<&str> = args.iter().skip(2).collect();
        sh.run_line(&line.join(" "));
        return sh.exit.unwrap_or(0);
    }
    println!("\x1b[1;36mDeSoOS\x1b[0m user-space shell (pid {}) - type 'help'", desoos::getpid());
    while sh.exit.is_none() {
        sh.reap_background();
        sh.read_and_run();
    }
    sh.exit.unwrap_or(0)
}
