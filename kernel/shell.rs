// M7: prosty shell kernela.
//
// M16: zwykłym shellem jest /bin/sh (user space, uruchamia go init).  Ten
// shell zostaje jako:
//   * awaryjny – gdy nie ma /bin/init albo init ciągle pada (user::run_init),
//   * źródło tekstu dla user space: M19.i syscall sysinfo (tylko odczyt: mem,
//     lspci, cpus...) i sysctl (reboot, halt, sync, stress – z uchwytem SYSCTL);
//     mkfs, zapis na dysk i run (programy testowe) – tylko tutaj.
// Wejście z klawiatury PS/2 i z terminala (serial), wyjście na serial
// i ekran (console.rs).
//
// Edycja linii: strzałki ←/→, Home/End, Backspace/Delete, historia ↑/↓,
// Tab = dopełnianie nazwy komendy, Ctrl+C = porzuć linię, Ctrl+U = wyczyść
// linię, Ctrl+L = wyczyść ekran.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::console::{self, Key};

/// Wersja z Cargo.toml (build.sh przekazuje ją w zmiennej DESOOS_VERSION).
pub const VERSION: &str = match option_env!("DESOOS_VERSION") {
    Some(v) => v,
    None => "dev",
};

/// Linia razem z promptem mieści się w 80 kolumnach terminala.
const TERMINAL_WIDTH: usize = 80;
const MIN_LINE: usize = 24;
const HISTORY_MAX: usize = 32;

// ------------------------------------------------------------
// Edytor linii
// ------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum Edit {
    /// Nic do narysowania.
    Nothing,
    /// Dopisano znak na końcu – wystarczy go wypisać.
    Echo(char),
    /// Linia się zmieniła – narysuj ją od nowa.
    Redraw,
    /// Enter – gotowa linia.
    Submit(String),
    /// Ctrl+C.
    Cancel,
    /// Ctrl+L.
    ClearScreen,
    /// Tab z wieloma pasującymi komendami – pokaż listę.
    Candidates(Vec<&'static str>),
}

pub struct LineEditor {
    buf: Vec<char>,
    cursor: usize,
    history: Vec<String>,
    /// Pozycja w historii podczas przeglądania ↑/↓ (None = edytujemy nową linię).
    browsing: Option<usize>,
    draft: Vec<char>,
    prompt: String,
    prompt_width: usize,
}

impl LineEditor {
    pub fn new() -> Self {
        let mut ed = LineEditor {
            buf: Vec::new(),
            cursor: 0,
            history: Vec::new(),
            browsing: None,
            draft: Vec::new(),
            prompt: String::new(),
            prompt_width: 0,
        };
        ed.set_prompt("/");
        ed
    }

    /// Prompt z bieżącym katalogiem: "desoos:/disk> ".
    pub fn set_prompt(&mut self, cwd: &str) {
        self.prompt = alloc::format!("\x1b[1;32mdesoos\x1b[0m:\x1b[1;34m{}\x1b[0m> ", cwd);
        self.prompt_width = "desoos:".len() + cwd.chars().count() + 2;
    }

    /// Maksymalna długość linii (prompt + linia < szerokość terminala).
    pub fn max_len(&self) -> usize {
        TERMINAL_WIDTH.saturating_sub(self.prompt_width + 1).max(MIN_LINE)
    }

    pub fn line(&self) -> String {
        self.buf.iter().collect()
    }

    #[allow(dead_code)]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn history(&self) -> &[String] {
        &self.history
    }

    fn set_line(&mut self, chars: Vec<char>) {
        self.buf = chars;
        self.cursor = self.buf.len();
    }

    pub fn handle(&mut self, key: Key) -> Edit {
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

    fn reset(&mut self) {
        self.buf.clear();
        self.cursor = 0;
        self.browsing = None;
        self.draft.clear();
    }

    /// Dopełnianie nazwy komendy (tylko pierwsze słowo, kursor na końcu).
    fn complete(&mut self) -> Edit {
        if self.cursor != self.buf.len() || self.buf.contains(&' ') {
            return Edit::Nothing;
        }
        let prefix = self.line();
        let matches: Vec<&'static str> =
            COMMANDS.iter().map(|c| c.name).filter(|n| n.starts_with(prefix.as_str())).collect();
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

    /// Rysuje prompt + linię i ustawia kursor.
    pub fn render(&self, out: &mut dyn Write) {
        let line = self.line();
        let _ = write!(out, "\r{}{}\x1b[K", self.prompt, line);
        let back = self.buf.len() - self.cursor;
        if back > 0 {
            let _ = write!(out, "\x1b[{}D", back);
        }
    }
}

// ------------------------------------------------------------
// Komendy
// ------------------------------------------------------------

struct Command {
    name: &'static str,
    usage: &'static str,
    help: &'static str,
    run: fn(args: &str, out: &mut dyn Write, ctx: &mut Context),
}

/// Dane z shella dostępne dla komend.
pub struct Context<'a> {
    pub history: &'a [String],
    /// Bieżący katalog (ścieżka absolutna).
    pub cwd: &'a mut String,
}

static COMMANDS: &[Command] = &[
    Command { name: "help", usage: "help", help: "list commands", run: cmd_help },
    Command { name: "clear", usage: "clear", help: "clear the screen (also Ctrl+L)", run: cmd_clear },
    Command { name: "echo", usage: "echo <text>", help: "print text", run: cmd_echo },
    Command { name: "ver", usage: "ver", help: "system version", run: cmd_ver },
    Command { name: "uptime", usage: "uptime", help: "time since the timer started", run: cmd_uptime },
    Command { name: "mem", usage: "mem", help: "physical memory, kernel heap and image", run: cmd_mem },
    Command { name: "irq", usage: "irq", help: "interrupt counters per IRQ line", run: cmd_irq },
    Command { name: "sleep", usage: "sleep <ms>", help: "wait (the shell task sleeps)", run: cmd_sleep },
    Command { name: "ps", usage: "ps", help: "list tasks (id, state, CPU, CPU time)", run: cmd_ps },
    Command { name: "cpus", usage: "cpus", help: "processors: online, current task, timer ticks, IPIs", run: cmd_cpus },
    Command { name: "stress", usage: "stress [s]", help: "SMP stress test: processes, files, spinlocks (default 10 s)", run: cmd_stress },
    Command { name: "spawn", usage: "spawn <spin|tick>", help: "start a demo task: spin = busy loop, tick = wakes every 1 s", run: cmd_spawn },
    Command { name: "kill", usage: "kill <id>", help: "ask a task to end", run: cmd_kill },
    Command { name: "run", usage: "run <prog> [n] [&]", help: "run a ring 3 test program, n copies at once (no name: list)", run: cmd_run },
    Command { name: "keys", usage: "keys", help: "show raw key events (Esc ends)", run: cmd_keys },
    Command { name: "colors", usage: "colors", help: "show the 16 console colors", run: cmd_colors },
    Command { name: "history", usage: "history", help: "command history", run: cmd_history },
    Command { name: "lspci", usage: "lspci [-v]", help: "list PCI devices (-v: BARs, capabilities)", run: cmd_lspci },
    Command { name: "acpi", usage: "acpi", help: "ACPI tables (MCFG = PCIe ECAM)", run: cmd_acpi },
    Command { name: "disk", usage: "disk [read|write]", help: "disks: list | read <n> <lba> | write <n> <lba> <text>", run: cmd_disk },
    Command { name: "ls", usage: "ls [path]", help: "list a directory", run: cmd_ls },
    Command { name: "cd", usage: "cd [path]", help: "change directory (no argument: /)", run: cmd_cd },
    Command { name: "pwd", usage: "pwd", help: "print current directory", run: cmd_pwd },
    Command { name: "cat", usage: "cat <file>", help: "print a file", run: cmd_cat },
    Command { name: "hexdump", usage: "hexdump <file>", help: "print a file in hex", run: cmd_hexdump },
    Command { name: "touch", usage: "touch <file>", help: "create an empty file", run: cmd_touch },
    Command { name: "write", usage: "write <file> <text>", help: "replace file content (same as echo text > file)", run: cmd_write },
    Command { name: "mkdir", usage: "mkdir <dir>", help: "create a directory", run: cmd_mkdir },
    Command { name: "rm", usage: "rm <path>", help: "remove a file or an empty directory", run: cmd_rm },
    Command { name: "cp", usage: "cp <src> <dst>", help: "copy a file (also between / and /disk)", run: cmd_cp },
    Command { name: "mv", usage: "mv <src> <dst>", help: "move/rename a file (copy + remove)", run: cmd_mv },
    Command { name: "stat", usage: "stat <path>", help: "file information", run: cmd_stat },
    Command { name: "mount", usage: "mount", help: "list mounted file systems", run: cmd_mount },
    Command { name: "df", usage: "df", help: "free space per file system", run: cmd_df },
    Command { name: "mkfs", usage: "mkfs <disk> [yes]", help: "format a disk as FAT32 (erases it!)", run: cmd_mkfs },
    Command { name: "sync", usage: "sync", help: "flush file system buffers to disk", run: cmd_sync },
    Command { name: "date", usage: "date", help: "date and time from the RTC (UTC)", run: cmd_date },
    Command { name: "reboot", usage: "reboot", help: "restart the computer", run: cmd_reboot },
    Command { name: "halt", usage: "halt", help: "stop the CPU", run: cmd_halt },
];

fn cmd_help(_: &str, out: &mut dyn Write, _: &mut Context) {
    let _ = writeln!(out, "Commands:");
    for c in COMMANDS {
        let _ = writeln!(out, "  \x1b[1m{:<12}\x1b[0m {}", c.usage, c.help);
    }
    let _ = writeln!(out, "Keys: arrows, Home/End, Tab (complete), Up/Down (history), Ctrl+C, Ctrl+U, Ctrl+L");
    let _ = writeln!(out, "      Scroll back: Shift+Up/Down (1 line), Shift+PgUp/PgDn (1 screen), wheel");
}

fn cmd_clear(_: &str, out: &mut dyn Write, _: &mut Context) {
    let _ = write!(out, "\x1b[2J\x1b[H");
}

fn cmd_echo(args: &str, out: &mut dyn Write, _: &mut Context) {
    let _ = writeln!(out, "{}", split_args(args).join(" "));
}

fn cmd_ver(_: &str, out: &mut dyn Write, _: &mut Context) {
    let _ = writeln!(out, "DeSoOS v{} (x86_64, UEFI)", VERSION);
}

fn cmd_uptime(_: &str, out: &mut dyn Write, _: &mut Context) {
    let ms = crate::time::uptime_ms();
    let _ = writeln!(
        out,
        "up {}.{:03} s ({} ticks, {} Hz, {} ms)",
        ms / 1000,
        ms % 1000,
        crate::time::ticks(),
        crate::time::HZ,
        ms
    );
}

fn cmd_mem(_: &str, out: &mut dyn Write, _: &mut Context) {
    mem_report(out);
}

/// `mem` (także automatyczny stress test po starcie).
pub fn mem_report(out: &mut dyn Write) {
    let free = crate::memory::free_frame_count();
    let _ = writeln!(out, "physical: {} free frames = {} MiB", free, free * 4 / 1024);
    let _ = writeln!(
        out,
        "heap:     {} KiB used, {} KiB mapped",
        crate::memory::heap_used_bytes() / 1024,
        crate::memory::heap_mapped_bytes() / 1024
    );
    let (used, max) = crate::sched::stack::used_slots();
    let _ = writeln!(out, "stacks:   {} of {} task stack slots used ({} tasks)", used, max, crate::sched::tasks().len());
    let k = crate::memory::kernel_layout();
    let _ = writeln!(
        out,
        "kernel:   {:#x} phys {:#x}, {} KiB, stack {} KiB",
        k.kernel_virt,
        k.kernel_phys,
        k.kernel_size / 1024,
        k.stack_size / 1024
    );
}

fn cmd_irq(_: &str, out: &mut dyn Write, _: &mut Context) {
    const NAMES: [&str; 16] = [
        "timer (PIT)", "keyboard", "cascade", "COM2", "COM1", "LPT2", "floppy", "LPT1",
        "RTC", "", "", "", "mouse", "FPU", "ATA 1", "ATA 2",
    ];
    use crate::arch::x86_64::irq;
    let _ = writeln!(out, "interrupt controller: {}", if irq::ioapic_mode() { "I/O APIC + Local APIC" } else { "8259 PIC" });
    for line in 0..16u8 {
        let n = irq::count(line);
        let masked = irq::is_masked(line);
        if n > 0 || !masked {
            let _ = writeln!(
                out,
                "IRQ{:<2} {:<12} {:>10}{}",
                line,
                NAMES[line as usize],
                n,
                if masked { "  (masked)" } else { "" }
            );
        }
    }
    // M16b: klawiatura – ile bajtów przyszło przerwaniem, ile odpytywaniem.
    let (by_irq, by_poll) = crate::drivers::keyboard::delivery_stats();
    let _ = writeln!(out, "PS/2 keyboard bytes: {} via IRQ1, {} via polling", by_irq, by_poll);
    for v in crate::arch::x86_64::msi::MSI_BASE..crate::arch::x86_64::msi::MSI_BASE + crate::arch::x86_64::msi::MSI_VECTORS {
        let n = crate::arch::x86_64::msi::count(v as u8);
        if n > 0 {
            let _ = writeln!(out, "MSI vector {:#x} {:>10}", v, n);
        }
    }
}

fn cmd_sleep(args: &str, out: &mut dyn Write, _: &mut Context) {
    match args.trim().parse::<u64>() {
        Ok(ms) if ms <= 60_000 => {
            let before = crate::time::ticks();
            crate::time::sleep_ms(ms);
            let _ = writeln!(out, "slept {} ticks", crate::time::ticks() - before);
        }
        _ => {
            let _ = writeln!(out, "usage: sleep <ms>  (0..60000)");
        }
    }
}

// ------------------------------------------------------------
// M12: zadania
// ------------------------------------------------------------

fn cmd_ps(_: &str, out: &mut dyn Write, _: &mut Context) {
    use crate::sched;
    let list = sched::tasks();
    let up = crate::time::ticks().max(1);
    let _ = writeln!(out, "  ID  NAME          MODE    STATE    CPU   CPU ms   CPU%  SWITCHES");
    for t in &list {
        // M17: CPU, na którym działa ("~n" – nie działa, ostatnio CPU n).
        let cpu = match t.cpu {
            Some(c) => alloc::format!("{}", c),
            None => alloc::format!("~{}", t.last_cpu),
        };
        let _ = writeln!(
            out,
            "{:>4}  {:<12}  {:<6}  {:<8} {:>3} {:>7}  {:>4}%  {:>8}",
            t.id,
            t.name,
            if t.user { "user" } else { "kernel" },
            t.state.name(),
            cpu,
            t.cpu_ticks,
            t.cpu_ticks * 100 / up,
            t.switches
        );
    }
    let _ = writeln!(
        out,
        "{} tasks, {} context switches, uptime {} ms, {} ms quantum",
        list.len(),
        sched::total_switches(),
        up,
        sched::QUANTUM_TICKS
    );
}

/// M17: procesory – stan, zadanie bieżące, ticki timera, IPI.
fn cmd_cpus(_: &str, out: &mut dyn Write, _: &mut Context) {
    cpus_report(out);
}

/// `cpus` (także automatyczny stress test po starcie).
pub fn cpus_report(out: &mut dyn Write) {
    use crate::arch::x86_64::{cpu::MAX_CPUS, lapic, smp};
    let _ = writeln!(
        out,
        "{} CPU(s) online, kernel: Big Kernel Lock, LAPIC timer {} ticks/ms",
        smp::online_count(),
        lapic::timer_ticks_per_ms()
    );
    let _ = writeln!(out, " CPU  APIC  TASK                  TIMER   IPI");
    for c in 0..MAX_CPUS {
        if !smp::online(c) {
            continue;
        }
        let task = match crate::sched::current_on(c) {
            Some((id, _, true)) => alloc::format!("idle ({})", id),
            Some((id, name, _)) => alloc::format!("{} {}", id, name),
            None => alloc::string::String::from("-"),
        };
        let (timer, ipi) = smp::counters(c);
        let timer = if c == 0 { alloc::format!("PIT {}", crate::time::ticks()) } else { alloc::format!("{}", timer) };
        let _ = writeln!(out, "{:>4}  {:>4}  {:<20}  {:>6}  {:>4}", c, smp::apic_id(c), task, timer, ipi);
    }
    // M17a: miara blokad – ile czekania na BKL (cel M17a: zbić to do zera).
    let (acq, cont, cyc) = crate::sched::bkl::stats();
    let _ = writeln!(
        out,
        "Big Kernel Lock: {} taken, {} had to wait ({}%), {} ms waiting in total (all CPUs added up)",
        acq,
        cont,
        if acq > 0 { cont * 100 / acq } else { 0 },
        cyc / 1000
    );
    // M17a.g2: czas w zadaniu idle (od startu; APy startują ~na początku).
    {
        let online: alloc::vec::Vec<usize> = (0..MAX_CPUS).filter(|&c| smp::online(c)).collect();
        let idle: u64 = online.iter().map(|&c| crate::sched::idle_us(c)).sum();
        let total = crate::time::uptime_ms() * 1000 * online.len() as u64;
        let _ = writeln!(
            out,
            "idle: {} ms of {} ms CPU time since boot ({}%)",
            idle / 1000,
            total / 1000,
            if total > 0 { idle * 100 / total } else { 0 }
        );
    }
    // M17a.g: kto bierze BKL – miejsca posortowane wg czasu (czekanie +
    // trzymanie); to, co zdejmujemy najpierw.
    let sites = crate::sched::bkl::site_stats();
    let lost = crate::sched::bkl::site_overflow();
    let _ = writeln!(
        out,
        "BKL by site (top {} of {}, by wait + hold time){}:",
        sites.len().min(8),
        sites.len(),
        if lost > 0 { alloc::format!(", {} takes not tracked", lost) } else { alloc::string::String::new() }
    );
    for e in sites.iter().take(8) {
        let name = if e.line == 0 {
            alloc::string::String::from(e.file)
        } else {
            alloc::format!("{}:{}", e.file.trim_start_matches("kernel/"), e.line)
        };
        let _ = writeln!(
            out,
            "  {:<38} {:>9} taken, {:>3}% waited, wait {:>7} ms, held {:>7} ms",
            name,
            e.taken,
            if e.taken > 0 { e.waited * 100 / e.taken } else { 0 },
            e.wait_us / 1000,
            e.held_us / 1000
        );
    }
    // M17a.g5: blokady usypiające (KMutex) – czekanie to sen, nie kręcenie
    // się, więc nie widać go w BKL / blokadzie schedulera, tylko w "idle".
    for e in crate::sched::sync::kmutex_stats() {
        let _ = writeln!(
            out,
            "sleeping lock {:<26} {:>9} taken, {:>3}% slept, {:>3}% spun, wait {:>7} ms, held {:>7} ms",
            e.name,
            e.acquires,
            if e.acquires > 0 { e.waited * 100 / e.acquires } else { 0 },
            if e.acquires > 0 { e.spun * 100 / e.acquires } else { 0 },
            e.wait_us / 1000,
            e.held_us / 1000
        );
    }
    for e in crate::sched::sync::krwlock_stats() {
        let _ = writeln!(
            out,
            "sleeping lock {:<26} {:>9} reads + {} writes, waited {} + {} ({} by spinning), wait {:>7} ms",
            e.name,
            e.reads,
            e.writes,
            e.read_waited,
            e.write_waited,
            e.spun,
            e.wait_us / 1000
        );
    }
    // M17a.g16: kręcące się blokady czytelnicy–pisarz (drzewo ramfs).
    for e in crate::sched::spin::rwspin_stats() {
        let _ = writeln!(
            out,
            "spin rwlock {:<28} {:>9} reads + {} writes, waited {} + {}, wait {:>7} ms, held {:>6} ms",
            e.name,
            e.reads,
            e.writes,
            e.read_waited,
            e.write_waited,
            e.wait_us / 1000,
            e.held_us / 1000
        );
    }
    let (sacq, scont, sdl) = crate::sched::spin::stats();
    let _ = writeln!(out, "spinlocks: {} taken, {} had to wait, {} deadlock report(s)", sacq, scont, sdl);
    // M17a.b: TLB shootdown.
    let (req, ipis, full, wait_us, handled) = crate::arch::x86_64::tlb::stats();
    let _ = writeln!(
        out,
        "TLB shootdown: {} requests ({} full flush), {} IPIs, {} acks ({} while waiting with IF=0), {} us waiting for acks",
        req,
        full,
        ipis,
        handled,
        crate::arch::x86_64::tlb::polled(),
        wait_us
    );
    // M17a.f1: blokada schedulera (decyzja o kolejkach per CPU – f3).
    let (sa, sc, sw) = crate::sched::sched_lock_stats();
    let _ = writeln!(
        out,
        "scheduler lock: {} taken, {} had to wait ({}%), {} ms waiting in total",
        sa,
        sc,
        if sa > 0 { sc * 100 / sa } else { 0 },
        sw / 1000
    );
    // M17a.g12: kto bierze blokadę schedulera (plik:linia).
    let (ssites, slost) = crate::sched::sched_lock_sites();
    let _ = writeln!(
        out,
        "scheduler lock by site (top {} of {}, by wait + hold time){}:",
        ssites.len().min(10),
        ssites.len(),
        if slost > 0 { alloc::format!(", {} takes not tracked", slost) } else { alloc::string::String::new() }
    );
    for e in ssites.iter().take(10) {
        let _ = writeln!(
            out,
            "  {:<26} {:>8} taken, {:>3}% waited, wait {:>7} ms, held {:>6} ms",
            e.file,
            e.taken,
            if e.taken > 0 { e.waited * 100 / e.taken } else { 0 },
            e.wait_us / 1000,
            e.held_us / 1000
        );
    }
    // M17b.d: pamięć procesów – leniwe strony.
    let (traps, pf_pages, copy_pages, calls) = crate::user::vm::stats();
    let _ = writeln!(
        out,
        "process memory: {} page faults -> {} pages ({}.{} per fault), {} pages via kernel copy, {} brk/mmap",
        traps,
        pf_pages,
        if traps > 0 { pf_pages / traps } else { 0 },
        if traps > 0 { pf_pages * 10 / traps % 10 } else { 0 },
        copy_pages,
        calls
    );
    // M17a.d: syscalle bez BKL.
    let (fast, slow) = crate::user::syscalls::syscall_stats();
    let fast_all: u64 = fast.iter().sum();
    let _ = writeln!(
        out,
        "syscalls: {} without BKL (getpid {}, uptime {}, write {}, files {}, processes {}, sleep/yield {}), {} under BKL ({}% without)",
        fast_all,
        fast[0],
        fast[1],
        fast[2],
        fast[3],
        fast[4],
        fast[5],
        slow,
        if fast_all + slow > 0 { fast_all * 100 / (fast_all + slow) } else { 0 }
    );
    let _ = writeln!(
        out,
        "clock: {} ticks added for lost PIT interrupts (caught up from HPET)",
        crate::time::caught_up_ticks()
    );
    if let Some(m) = crate::acpi::madt() {
        if m.cpus.len() > smp::online_count() {
            let _ = writeln!(out, "MADT lists {} CPU(s); {} not started", m.cpus.len(), m.cpus.len() - smp::online_count());
        }
    }
}

/// M17a: stress test SMP (user/stress.rs).
fn cmd_stress(args: &str, out: &mut dyn Write, _: &mut Context) {
    let secs = match args.trim() {
        "" => 10,
        a => match a.parse::<u64>() {
            Ok(s) if (1..=600).contains(&s) => s,
            _ => {
                let _ = writeln!(out, "usage: stress [seconds]  (1..600)");
                return;
            }
        },
    };
    crate::serial_println!("[STRESS] {} s on {} CPU(s)...", secs, crate::arch::x86_64::smp::online_count());
    match crate::user::stress::run(secs * 1000) {
        Ok(r) => {
            for (i, l) in r.lines().iter().enumerate() {
                let _ = writeln!(out, "{}{}", if i == 0 { "stress PASS: " } else { "" }, l);
            }
        }
        Err(e) => {
            let _ = writeln!(out, "stress FAIL: {}", e);
        }
    }
}

/// Demo: pętla bez oddawania CPU – działa tylko dzięki wywłaszczaniu.
fn demo_spin(_: usize) {
    let mut n: u64 = 0;
    while !crate::sched::should_exit() {
        for _ in 0..10_000 {
            n = core::hint::black_box(n.wrapping_add(1));
        }
    }
}

/// Demo: budzi się co sekundę (śpi – nie zajmuje CPU).
fn demo_tick(_: usize) {
    while !crate::sched::should_exit() {
        crate::time::sleep_ms(1000);
    }
}

fn cmd_spawn(args: &str, out: &mut dyn Write, _: &mut Context) {
    let (name, entry): (&str, fn(usize)) = match args.trim() {
        "spin" => ("spin", demo_spin),
        "tick" => ("tick", demo_tick),
        _ => {
            let _ = writeln!(out, "usage: spawn <spin|tick>  (spin = busy loop, tick = sleeps 1 s in a loop)");
            return;
        }
    };
    match crate::sched::spawn(name, entry, 0) {
        Ok(id) => {
            let _ = writeln!(out, "started task {} '{}' (see 'ps', stop with 'kill {}')", id, name, id);
        }
        Err(e) => {
            let _ = writeln!(out, "spawn: {}", e);
        }
    }
}

fn cmd_kill(args: &str, out: &mut dyn Write, _: &mut Context) {
    let Ok(id) = args.trim().parse::<u64>() else {
        let _ = writeln!(out, "usage: kill <id>  (ids: see 'ps')");
        return;
    };
    if !crate::sched::request_exit(id) {
        let _ = writeln!(out, "kill: no such task or it cannot be stopped ({})", id);
        return;
    }
    // Zadanie kończy się samo przy najbliższej okazji – chwilę czekamy.
    for _ in 0..100 {
        if crate::sched::task_info(id).is_none() {
            let _ = writeln!(out, "task {} ended", id);
            return;
        }
        crate::time::sleep_ms(10);
    }
    let _ = writeln!(out, "task {} was asked to end (it has not finished yet)", id);
}

/// M13a: program testowy w ring 3.  `run <prog> [n] [&]`: n kopii naraz
/// (1..16); na pierwszym planie shell czeka na koniec wszystkich (Ctrl+C =
/// kill), z `&` działają w tle.
fn cmd_run(args: &str, out: &mut dyn Write, ctx: &mut Context) {
    use crate::user;
    let first = args.split_whitespace().next().unwrap_or("").trim_end_matches('&');
    // M15: program ELF – ścieżka (z '/') albo /bin/<nazwa>; potem programy
    // wbudowane (asm z M13/M14).
    if !first.is_empty() {
        if let Some(path) = find_program(first, ctx.cwd) {
            run_elf(&path, args, out, ctx);
            return;
        }
        if first.contains('/') {
            let _ = writeln!(out, "run: {}: no such program file", first);
            return;
        }
    }
    let mut parts = args.split_whitespace();
    let first = parts.next().unwrap_or("");
    let mut background = first.ends_with('&');
    let name = first.trim_end_matches('&');
    let mut count = 1usize;
    for t in parts {
        if t.ends_with('&') {
            background = true;
        }
        let t = t.trim_end_matches('&');
        if t.is_empty() {
            continue;
        }
        match t.parse::<usize>() {
            Ok(n) if (1..=16).contains(&n) => count = n,
            _ => {
                let _ = writeln!(out, "usage: run <program> [n] [&]   (n = 1..16 copies at once)");
                return;
            }
        }
    }
    let Some(code) = user::programs::code(name) else {
        let bin = bin_programs();
        if !name.is_empty() {
            let programs = user::programs::LIST
                .iter()
                .map(|(n, _)| *n)
                .filter(|n| *n != "ret")
                .chain(bin.iter().map(|s| s.as_str()));
            match closest(name, programs) {
                Some(p) => {
                    let _ = writeln!(out, "run: unknown program '{}' - did you mean '{}'?", name, p);
                }
                None => {
                    let _ = writeln!(out, "run: unknown program '{}' ('run' lists the programs)", name);
                }
            }
            return;
        }
        let _ = writeln!(out, "usage: run <program|path> [args...] [&]   (ring 3, own address space)");
        let _ = writeln!(out, "ELF programs in /bin (run <name> [args...] [&]):");
        let _ = writeln!(out, "  {}", if bin.is_empty() { String::from("(none)") } else { bin.join("  ") });
        let _ = writeln!(out, "built-in test programs (run <name> [n] [&], n = 1..16 copies):");
        for (n, about) in user::programs::LIST {
            // Nazwy zajęte przez /bin (hello, cat) – wygrywa program ELF.
            if *n != "ret" && !bin.iter().any(|b| b == n) {
                let _ = writeln!(out, "  {:<10} {}", n, about);
            }
        }
        return;
    };
    // Wartość startowa w stronie danych procesu (np. "xmm" wypełnia nią
    // rejestry) – różna dla każdego uruchomienia i każdej kopii.
    let base = crate::time::ticks() << 20;
    let mut ids = Vec::new();
    for i in 0..count {
        match user::spawn_process(name, code, base + ((i as u64) << 40)) {
            Ok(id) => ids.push(id),
            Err(e) => {
                let _ = writeln!(out, "run: {}", e);
                break;
            }
        }
    }
    if ids.is_empty() {
        return;
    }
    if background {
        report_background(&ids, name, out);
        return;
    }
    wait_foreground(&ids);
    if ids.len() > 1 {
        let ok = ids
            .iter()
            .filter(|id| matches!(user::exit_info(**id), Some(e) if e.kind == user::ExitKind::Breakpoint))
            .count();
        let _ = writeln!(out, "{} processes ended, {} with int3", ids.len(), ok);
    }
}

/// M15: ścieżka programu ELF dla `run <name>`: z '/' – względem cwd,
/// inaczej /bin/<name>.  None, gdy nie ma takiego pliku.
fn find_program(name: &str, cwd: &str) -> Option<String> {
    let path = if name.contains('/') {
        crate::fs::normalize(cwd, name)
    } else {
        alloc::format!("/bin/{}", name)
    };
    match crate::fs::stat(&path) {
        Ok(m) if m.kind == crate::fs::FileType::File => Some(path),
        _ => None,
    }
}

/// Nazwy plików w /bin.
fn bin_programs() -> Vec<String> {
    crate::fs::read_dir("/bin")
        .map(|v| v.into_iter().filter(|e| e.kind == crate::fs::FileType::File).map(|e| e.name).collect())
        .unwrap_or_default()
}

/// `run <path|name> [args...] [&]` dla programu ELF.
fn run_elf(path: &str, args: &str, out: &mut dyn Write, ctx: &mut Context) {
    use crate::user;
    let mut words: Vec<&str> = args.split_whitespace().collect();
    let mut background = false;
    if let Some(last) = words.last_mut() {
        if last.ends_with('&') {
            background = true;
            *last = last.trim_end_matches('&');
            if last.is_empty() {
                words.pop();
            }
        }
    }
    // argv[0] = nazwa tak, jak ją wpisano.
    let name = path.rsplit('/').next().unwrap_or(path);
    let opts = user::SpawnOptions { foreground: !background, ..user::SpawnOptions::default() };
    let id = match user::exec(path, &words, ctx.cwd, &opts) {
        Ok(id) => id,
        Err(e) => {
            let _ = writeln!(out, "run: {}: {}", path, e);
            return;
        }
    };
    if background {
        report_background(&[id], name, out);
        return;
    }
    wait_foreground(&[id]);
}

fn report_background(ids: &[u64], name: &str, out: &mut dyn Write) {
    let list: Vec<String> = ids.iter().map(|i| alloc::format!("{}", i)).collect();
    let _ = writeln!(
        out,
        "{} '{}' started in the background: {} ('ps', 'kill <id>')",
        if ids.len() == 1 { "process" } else { "processes" },
        name,
        list.join(", ")
    );
}

/// Pierwszy plan: czekamy na koniec wszystkich.  Shell nie czyta wtedy
/// klawiatury (może to robić proces – read z fd 0); Ctrl+C kończy procesy
/// już w przerwaniu klawiatury / seriala (console::interrupt_foreground).
fn wait_foreground(ids: &[u64]) {
    crate::console::set_foreground(ids);
    while ids.iter().any(|id| crate::sched::task_info(*id).is_some()) {
        crate::time::sleep_ms(10);
    }
    crate::console::clear_foreground();
}

fn cmd_keys(_: &str, out: &mut dyn Write, _: &mut Context) {
    let _ = writeln!(out, "Press keys on the PS/2 keyboard (QEMU window). Esc ends.");
    loop {
        let e = crate::input::wait_event();
        let _ = writeln!(
            out,
            "{:<14} {:<8} mods={:#06x} ch={:?}",
            alloc::format!("{:?}", e.key),
            if e.pressed { "pressed" } else { "released" },
            e.mods.bits(),
            e.ch
        );
        if e.key == crate::input::KeyCode::Escape && e.pressed {
            break;
        }
    }
}

fn cmd_colors(_: &str, out: &mut dyn Write, _: &mut Context) {
    // Na jasnych tłach (7 i 8..15) czarny tekst, inaczej numer byłby niewidoczny.
    for i in 0..8 {
        let fg = if i == 7 { 30 } else { 97 };
        let _ = write!(out, "\x1b[{};{}m {:>2} \x1b[0m", fg, 40 + i, i);
    }
    let _ = writeln!(out);
    for i in 0..8 {
        let _ = write!(out, "\x1b[30;{}m {:>2} \x1b[0m", 100 + i, i + 8);
    }
    let _ = writeln!(out);
    for i in 0..8 {
        let _ = write!(out, "\x1b[{}m{:>4}\x1b[0m", 30 + i, i);
    }
    for i in 0..8 {
        let _ = write!(out, "\x1b[{}m{:>4}\x1b[0m", 90 + i, i + 8);
    }
    let _ = writeln!(out);
}

fn cmd_history(_: &str, out: &mut dyn Write, ctx: &mut Context) {
    for (i, line) in ctx.history.iter().enumerate() {
        let _ = writeln!(out, "{:>3}  {}", i + 1, line);
    }
}

fn cmd_lspci(args: &str, out: &mut dyn Write, _: &mut Context) {
    use crate::drivers::pci;
    let verbose = args.trim() == "-v";
    for (i, d) in pci::devices().iter().enumerate() {
        let _ = write!(
            out,
            "{} {:04x}:{:04x} {} (class {:02x}:{:02x}:{:02x} rev {:02x})",
            d.address, d.vendor, d.device, d.class_name(), d.class, d.subclass, d.prog_if, d.revision
        );
        if d.interrupt_pin != 0 && d.interrupt_line != 0xFF {
            let _ = write!(out, " IRQ {}", d.interrupt_line);
        }
        // M19.c: kto obsługuje urządzenie.
        match pci::owner(i) {
            pci::OWNER_KERNEL => {
                let _ = write!(out, " [kernel driver]");
            }
            pci::OWNER_USER => {
                let _ = write!(out, " [user-space service]");
            }
            _ => {}
        }
        let _ = writeln!(out);
        if verbose {
            for (i, bar) in d.bars.iter().enumerate() {
                if let Some(s) = pci::describe_bar(bar) {
                    let _ = writeln!(out, "    BAR{}: {}", i, s);
                }
            }
            let caps = d.capabilities();
            if !caps.is_empty() {
                let _ = write!(out, "    caps:");
                for (off, id) in caps {
                    let _ = write!(out, " {:02x}@{:02x}", id, off);
                }
                let _ = writeln!(out);
            }
        }
    }
}

fn cmd_acpi(_: &str, out: &mut dyn Write, _: &mut Context) {
    let _ = write!(out, "{}", crate::acpi::describe());
    let ecam = crate::drivers::pci::ecam_base();
    if ecam != 0 {
        let _ = writeln!(out, "PCI config space: ECAM at {:#x}", ecam);
    } else {
        let _ = writeln!(out, "PCI config space: ports 0xCF8/0xCFC");
    }
}

fn hexdump(out: &mut dyn Write, base: u64, data: &[u8]) {
    for (i, line) in data.chunks(16).enumerate() {
        let _ = write!(out, "{:08x}  ", base + (i * 16) as u64);
        for (j, b) in line.iter().enumerate() {
            let _ = write!(out, "{:02x}{}", b, if j == 7 { "  " } else { " " });
        }
        let _ = write!(out, " |");
        for b in line {
            let c = if (0x20..0x7F).contains(b) { *b as char } else { '.' };
            let _ = write!(out, "{}", c);
        }
        let _ = writeln!(out, "|");
    }
}

fn cmd_disk(args: &str, out: &mut dyn Write, _: &mut Context) {
    use crate::block::{self, SECTOR_SIZE};
    let mut parts = args.split_whitespace();
    match parts.next() {
        None => {
            if block::count() == 0 {
                let _ = writeln!(out, "no disks");
            }
            for i in 0..block::count() {
                let _ = block::with_device(i, |d| {
                    let _ = writeln!(
                        out,
                        "{}: {} - {} MiB{} - {}",
                        i,
                        d.name(),
                        d.sector_count() * SECTOR_SIZE as u64 / (1024 * 1024),
                        if d.read_only() { " (read-only)" } else { "" },
                        d.description()
                    );
                });
            }
        }
        Some("read") => {
            let n = parts.next().and_then(|s| s.parse::<usize>().ok());
            let lba = parts.next().and_then(|s| s.parse::<u64>().ok());
            let (Some(n), Some(lba)) = (n, lba) else {
                let _ = writeln!(out, "usage: disk read <disk> <lba>");
                return;
            };
            let mut buf = [0u8; SECTOR_SIZE];
            match block::read(n, lba, &mut buf) {
                Ok(()) => hexdump(out, lba * SECTOR_SIZE as u64, &buf),
                Err(e) => {
                    let _ = writeln!(out, "error: {}", e);
                }
            }
        }
        Some("write") => {
            let n = parts.next().and_then(|s| s.parse::<usize>().ok());
            let lba = parts.next().and_then(|s| s.parse::<u64>().ok());
            let text: alloc::vec::Vec<&str> = parts.collect();
            let (Some(n), Some(lba)) = (n, lba) else {
                let _ = writeln!(out, "usage: disk write <disk> <lba> <text>");
                return;
            };
            let text = text.join(" ");
            let mut buf = [0u8; SECTOR_SIZE];
            let len = text.len().min(SECTOR_SIZE);
            buf[..len].copy_from_slice(&text.as_bytes()[..len]);
            let result = block::write(n, lba, &buf).and_then(|_| block::with_device(n, |d| d.flush())?);
            match result {
                Ok(()) => {
                    let _ = writeln!(out, "wrote {} bytes to sector {} (rest zero-filled)", len, lba);
                }
                Err(e) => {
                    let _ = writeln!(out, "error: {}", e);
                }
            }
        }
        Some(_) => {
            let _ = writeln!(out, "usage: disk | disk read <disk> <lba> | disk write <disk> <lba> <text>");
        }
    }
}

// ------------------------------------------------------------
// Pliki (M9)
// ------------------------------------------------------------

fn human_size(n: u64) -> String {
    if n < 1024 {
        alloc::format!("{} B", n)
    } else if n < 1024 * 1024 {
        alloc::format!("{}.{} KiB", n / 1024, n % 1024 * 10 / 1024)
    } else {
        alloc::format!("{}.{} MiB", n / (1024 * 1024), n % (1024 * 1024) * 10 / (1024 * 1024))
    }
}

/// Dzieli argumenty na słowa; "..." i '...' pozwalają na spacje w nazwach,
/// a \ przed znakiem bierze go dosłownie.
pub fn split_args(args: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut in_word = false;
    let mut chars = args.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '"') | (None, '\'') => {
                quote = Some(c);
                in_word = true;
            }
            (None, '\\') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                    in_word = true;
                }
            }
            (None, c) if c.is_whitespace() => {
                if in_word {
                    out.push(core::mem::take(&mut cur));
                    in_word = false;
                }
            }
            (None, c) => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

/// Pozycja '>' poza cudzysłowami.
fn find_redirect(line: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (None, '"') | (None, '\'') => quote = Some(c),
            (None, '>') => return Some(i),
            _ => {}
        }
    }
    None
}

fn path_arg(ctx: &Context, arg: &str) -> String {
    crate::fs::normalize(ctx.cwd, arg)
}

fn cmd_ls(args: &str, out: &mut dyn Write, ctx: &mut Context) {
    use crate::fs::{self, FileType};
    let words = split_args(args);
    let path = path_arg(ctx, words.first().map(|s| s.as_str()).unwrap_or("."));
    match fs::stat(&path) {
        Ok(m) if m.kind == FileType::File => {
            let _ = writeln!(out, "{:>10}  {}", m.size, path);
            return;
        }
        Err(e) => {
            let _ = writeln!(out, "ls: {}: {}", path, e);
            return;
        }
        _ => {}
    }
    match fs::read_dir(&path) {
        Ok(entries) => {
            for e in &entries {
                let date = e.modified.map(|d| alloc::format!("{}", d)).unwrap_or_else(|| String::from("-                  "));
                match e.kind {
                    FileType::Directory => {
                        let _ = writeln!(out, "{:>10}  {}  \x1b[1;34m{}/\x1b[0m", "<DIR>", date, e.name);
                    }
                    FileType::File => {
                        let _ = writeln!(out, "{:>10}  {}  {}", e.size, date, e.name);
                    }
                }
            }
            let files = entries.iter().filter(|e| e.kind == FileType::File).count();
            let bytes: u64 = entries.iter().map(|e| e.size).sum();
            let _ = writeln!(out, "{} file(s), {} dir(s), {}", files, entries.len() - files, human_size(bytes));
        }
        Err(e) => {
            let _ = writeln!(out, "ls: {}: {}", path, e);
        }
    }
}

fn cmd_cd(args: &str, out: &mut dyn Write, ctx: &mut Context) {
    let words = split_args(args);
    let target = match words.first() {
        None => String::from("/"),
        Some(w) => path_arg(ctx, w),
    };
    match crate::fs::stat(&target) {
        Ok(m) if m.kind == crate::fs::FileType::Directory => *ctx.cwd = target,
        Ok(_) => {
            let _ = writeln!(out, "cd: {}: not a directory", target);
        }
        Err(e) => {
            let _ = writeln!(out, "cd: {}: {}", target, e);
        }
    }
}

fn cmd_pwd(_: &str, out: &mut dyn Write, ctx: &mut Context) {
    let _ = writeln!(out, "{}", ctx.cwd);
}

fn cmd_cat(args: &str, out: &mut dyn Write, ctx: &mut Context) {
    let words = split_args(args);
    if words.is_empty() {
        let _ = writeln!(out, "usage: cat <file>");
        return;
    }
    for name in &words {
        let path = path_arg(ctx, name);
        match crate::fs::read_file(&path) {
            Ok(data) => {
                let text = String::from_utf8_lossy(&data);
                let _ = write!(out, "{}", text);
                if !text.is_empty() && !text.ends_with('\n') {
                    let _ = writeln!(out);
                }
            }
            Err(e) => {
                let _ = writeln!(out, "cat: {}: {}", path, e);
            }
        }
    }
}

fn cmd_hexdump(args: &str, out: &mut dyn Write, ctx: &mut Context) {
    let words = split_args(args);
    let path = path_arg(ctx, words.first().map(|s| s.as_str()).unwrap_or(""));
    match crate::fs::read_file(&path) {
        Ok(data) => hexdump(out, 0, &data[..data.len().min(4096)]),
        Err(e) => {
            let _ = writeln!(out, "hexdump: {}: {}", path, e);
        }
    }
}

fn cmd_touch(args: &str, out: &mut dyn Write, ctx: &mut Context) {
    for name in &split_args(args) {
        let path = path_arg(ctx, name);
        match crate::fs::stat(&path) {
            Ok(_) => {}
            Err(crate::fs::FsError::NotFound) => {
                if let Err(e) = crate::fs::create(&path).and_then(|_| crate::fs::sync_all()) {
                    let _ = writeln!(out, "touch: {}: {}", path, e);
                }
            }
            Err(e) => {
                let _ = writeln!(out, "touch: {}: {}", path, e);
            }
        }
    }
}

fn cmd_write(args: &str, out: &mut dyn Write, ctx: &mut Context) {
    let words = split_args(args);
    let name = words.first().cloned().unwrap_or_default();
    let text = words[words.len().min(1)..].join(" ");
    if name.is_empty() {
        let _ = writeln!(out, "usage: write <file> <text>");
        return;
    }
    let path = path_arg(ctx, &name);
    let mut data = text;
    data.push('\n');
    if let Err(e) = crate::fs::write_file(&path, data.as_bytes()) {
        let _ = writeln!(out, "write: {}: {}", path, e);
    }
}

fn cmd_mkdir(args: &str, out: &mut dyn Write, ctx: &mut Context) {
    for name in &split_args(args) {
        let path = path_arg(ctx, name);
        if let Err(e) = crate::fs::mkdir(&path).and_then(|_| crate::fs::sync_all()) {
            let _ = writeln!(out, "mkdir: {}: {}", path, e);
        }
    }
}

fn cmd_rm(args: &str, out: &mut dyn Write, ctx: &mut Context) {
    for name in &split_args(args) {
        let path = path_arg(ctx, name);
        if path == *ctx.cwd || ctx.cwd.starts_with(&alloc::format!("{}/", path)) {
            let _ = writeln!(out, "rm: {}: is the current directory", path);
            continue;
        }
        if let Err(e) = crate::fs::remove(&path).and_then(|_| crate::fs::sync_all()) {
            let _ = writeln!(out, "rm: {}: {}", path, e);
        }
    }
}

/// Cel kopiowania: jeśli `dst` jest katalogiem, plik ląduje w nim pod tą samą nazwą.
fn copy_target(src: &str, dst: &str) -> String {
    match crate::fs::stat(dst) {
        Ok(m) if m.kind == crate::fs::FileType::Directory => {
            let (_, name) = crate::fs::split_parent(src);
            crate::fs::normalize(dst, name)
        }
        _ => String::from(dst),
    }
}

fn cmd_cp(args: &str, out: &mut dyn Write, ctx: &mut Context) {
    let parts = split_args(args);
    if parts.len() != 2 {
        let _ = writeln!(out, "usage: cp <src> <dst>");
        return;
    }
    let src = path_arg(ctx, &parts[0]);
    let dst = copy_target(&src, &path_arg(ctx, &parts[1]));
    let result = crate::fs::read_file(&src).and_then(|data| crate::fs::write_file(&dst, &data).map(|_| data.len()));
    match result {
        Ok(n) => {
            let _ = writeln!(out, "{} -> {} ({})", src, dst, human_size(n as u64));
        }
        Err(e) => {
            let _ = writeln!(out, "cp: {}", e);
        }
    }
}

fn cmd_mv(args: &str, out: &mut dyn Write, ctx: &mut Context) {
    let parts = split_args(args);
    if parts.len() != 2 {
        let _ = writeln!(out, "usage: mv <src> <dst>");
        return;
    }
    let src = path_arg(ctx, &parts[0]);
    let dst = copy_target(&src, &path_arg(ctx, &parts[1]));
    if src == dst {
        return;
    }
    match crate::fs::stat(&src) {
        Ok(m) if m.kind == crate::fs::FileType::Directory => {
            let _ = writeln!(out, "mv: moving directories is not supported yet");
            return;
        }
        Err(e) => {
            let _ = writeln!(out, "mv: {}: {}", src, e);
            return;
        }
        _ => {}
    }
    let result = crate::fs::read_file(&src)
        .and_then(|data| crate::fs::write_file(&dst, &data))
        .and_then(|_| crate::fs::remove(&src))
        .and_then(|_| crate::fs::sync_all());
    if let Err(e) = result {
        let _ = writeln!(out, "mv: {}", e);
    }
}

fn cmd_stat(args: &str, out: &mut dyn Write, ctx: &mut Context) {
    let words = split_args(args);
    let path = path_arg(ctx, words.first().map(|s| s.as_str()).unwrap_or("."));
    match crate::fs::stat(&path) {
        Ok(m) => {
            let _ = writeln!(out, "path:     {}", path);
            let _ = writeln!(out, "type:     {:?}", m.kind);
            let _ = writeln!(out, "size:     {} ({})", m.size, human_size(m.size));
            if let Some(d) = m.modified {
                let _ = writeln!(out, "modified: {}", d);
            }
        }
        Err(e) => {
            let _ = writeln!(out, "stat: {}: {}", path, e);
        }
    }
}

fn cmd_mount(_: &str, out: &mut dyn Write, _: &mut Context) {
    for (path, kind, source) in crate::fs::mount_list() {
        let _ = writeln!(out, "{:<8} {:<6} {}", path, kind, source);
    }
}

fn cmd_df(_: &str, out: &mut dyn Write, _: &mut Context) {
    let _ = writeln!(out, "{:<8} {:>12} {:>12} {:>12}", "mount", "size", "used", "free");
    for (path, _, _) in crate::fs::mount_list() {
        if let Some(st) = crate::fs::mount_stats(&path) {
            let _ = writeln!(
                out,
                "{:<8} {:>12} {:>12} {:>12}",
                path,
                human_size(st.total_bytes),
                human_size(st.total_bytes - st.free_bytes),
                human_size(st.free_bytes)
            );
        }
    }
}

fn cmd_mkfs(args: &str, out: &mut dyn Write, ctx: &mut Context) {
    let mut parts = args.split_whitespace();
    let Some(disk) = parts.next().and_then(|s| s.parse::<usize>().ok()) else {
        let _ = writeln!(out, "usage: mkfs <disk> yes   (disk numbers: 'disk')");
        return;
    };
    let name = match crate::block::with_device(disk, |d| String::from(d.name())) {
        Ok(n) => n,
        Err(e) => {
            let _ = writeln!(out, "mkfs: {}", e);
            return;
        }
    };
    if crate::block::is_read_only(disk) {
        let _ = writeln!(out, "mkfs: disk {} ({}) is read-only (write protection) - nothing changed", disk, name);
        return;
    }
    if parts.next() != Some("yes") {
        let _ = writeln!(out, "This ERASES everything on disk {} ({}).", disk, name);
        let _ = writeln!(out, "To continue type: mkfs {} yes", disk);
        return;
    }
    // Dysk 0 jest montowany w /disk – najpierw odmontować.
    if disk == 0 {
        if ctx.cwd.starts_with("/disk") {
            *ctx.cwd = String::from("/");
        }
        let _ = crate::fs::unmount("/disk");
    }
    match crate::fs::fat32::mkfs(disk, "DESOOS", false) {
        Ok(info) => {
            let _ = writeln!(out, "{}: {}", name, info);
        }
        Err(crate::fs::FsError::Unsupported) => {
            let _ = writeln!(out, "mkfs: disk too small for FAT32 (needs at least ~33 MiB)");
            return;
        }
        Err(e) => {
            let _ = writeln!(out, "mkfs: {}", e);
            return;
        }
    }
    if disk == 0 {
        let _ = crate::fs::mkdir("/disk");
        match crate::fs::fat32::Fat32::open(0).and_then(|f| crate::fs::mount("/disk", alloc::boxed::Box::new(f))) {
            Ok(()) => {
                let _ = writeln!(out, "mounted at /disk");
            }
            Err(e) => {
                let _ = writeln!(out, "mount /disk: {}", e);
            }
        }
    }
}

fn cmd_sync(_: &str, out: &mut dyn Write, _: &mut Context) {
    if let Err(e) = crate::fs::sync_all() {
        let _ = writeln!(out, "sync: {}", e);
    }
}

fn cmd_date(_: &str, out: &mut dyn Write, _: &mut Context) {
    let _ = writeln!(out, "{} UTC", crate::drivers::rtc::now());
}

fn cmd_reboot(_: &str, out: &mut dyn Write, _: &mut Context) {
    let _ = crate::fs::sync_all();
    let _ = writeln!(out, "Rebooting...");
    crate::drivers::ps2::reset_cpu();
    // Kontroler nie zresetował – triple fault (pusta IDT + wyjątek).
    unsafe {
        let null_idt: [u8; 10] = [0; 10];
        core::arch::asm!("lidt [{}]", "int3", in(reg) &null_idt, options(noreturn));
    }
}

fn cmd_halt(_: &str, out: &mut dyn Write, _: &mut Context) {
    let _ = crate::fs::sync_all();
    let _ = writeln!(out, "System halted. You can close QEMU.");
    loop {
        unsafe { core::arch::asm!("cli", "hlt") };
    }
}

/// Odległość edycyjna (Damerau-Levenshtein, z zamianą sąsiednich liter).
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = alloc::vec![alloc::vec![0usize; b.len() + 1]; a.len() + 1];
    for i in 0..=a.len() {
        d[i][0] = i;
    }
    for j in 0..=b.len() {
        d[0][j] = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            d[i][j] = (d[i - 1][j] + 1).min(d[i][j - 1] + 1).min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[a.len()][b.len()]
}

/// Najbliższa znana komenda dla literówki (np. "mfks" -> "mkfs").
/// Najbliższa nazwa (literówka: najwyżej 2 zmiany i mniej niż długość).
fn closest<'a>(name: &str, candidates: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    candidates
        .map(|c| (edit_distance(name, c), c))
        .filter(|(d, _)| *d <= 2 && *d < name.chars().count())
        .min_by_key(|(d, _)| *d)
        .map(|(_, n)| n)
}

fn suggest(name: &str) -> Option<&'static str> {
    closest(name, COMMANDS.iter().map(|c| c.name))
}

/// Wykonuje linię.  `false` = nieznana komenda.
pub fn execute(line: &str, out: &mut dyn Write, ctx: &mut Context) -> bool {
    let line = line.trim();
    if line.is_empty() {
        return true;
    }
    // Przekierowanie wyjścia: "komenda > plik" (zastąp) albo "komenda >> plik" (dopisz).
    if let Some(pos) = find_redirect(line) {
        let append = line[pos..].starts_with(">>");
        let target_words = split_args(&line[pos + if append { 2 } else { 1 }..]);
        let target = target_words.first().map(|s| s.as_str()).unwrap_or("");
        let command = line[..pos].trim();
        if target.is_empty() || command.is_empty() {
            let _ = writeln!(out, "syntax: <command> > <file>  or  <command> >> <file>");
            return true;
        }
        let path = crate::fs::normalize(ctx.cwd, target);
        let mut captured = String::new();
        let known = execute(command, &mut captured, ctx);
        let result = if append {
            crate::fs::append_file(&path, captured.as_bytes())
        } else {
            crate::fs::write_file(&path, captured.as_bytes())
        };
        if let Err(e) = result {
            let _ = writeln!(out, "{}: {}", path, e);
        }
        return known;
    }
    let (name, args) = match line.find(' ') {
        Some(i) => (&line[..i], line[i + 1..].trim_start()),
        None => (line, ""),
    };
    match COMMANDS.iter().find(|c| c.name == name) {
        Some(c) => {
            (c.run)(args, out, ctx);
            true
        }
        None => {
            match suggest(name) {
                Some(s) => {
                    let _ = writeln!(out, "unknown command: {} - did you mean '{}'? (type 'help')", name, s);
                }
                None => {
                    let _ = writeln!(out, "unknown command: {} (type 'help')", name);
                }
            }
            false
        }
    }
}

/// M19.i: komendy tylko do odczytu dla user space (syscall sysinfo) –
/// zastępują most kcmd.  Argumenty: tylko `lspci -v`; `disk` tylko lista
/// (odczyt / zapis sektorów, mkfs, run – wyłącznie w awaryjnym shellu jądra).
pub const SYSINFO_TOPICS: &[&str] = &["ver", "uptime", "date", "mem", "irq", "cpus", "lspci", "acpi", "disk", "mount", "df"];

pub fn sysinfo(line: &str) -> Option<String> {
    let line = line.trim();
    let mut words = line.split_whitespace();
    let name = words.next()?;
    let args: Vec<&str> = words.collect();
    if !SYSINFO_TOPICS.contains(&name) {
        return None;
    }
    let args_ok = match name {
        "lspci" => args.is_empty() || args == ["-v"],
        _ => args.is_empty(),
    };
    if !args_ok {
        return None;
    }
    Some(run_to_string(line))
}

/// M19.i: akcje systemowe (syscall sysctl – tylko z uchwytem SYSCTL, który
/// jądro daje init, a init shellowi).  1 reboot, 2 halt, 3 sync, 4 stress
/// `arg` sekund (0 = domyślnie 10, najwyżej 600).
pub const SYSCTL_REBOOT: u64 = 1;
pub const SYSCTL_HALT: u64 = 2;
pub const SYSCTL_SYNC: u64 = 3;
pub const SYSCTL_STRESS: u64 = 4;

pub fn sysctl(op: u64, arg: u64) -> Option<String> {
    let line = match op {
        SYSCTL_REBOOT => String::from("reboot"),
        SYSCTL_HALT => String::from("halt"),
        SYSCTL_SYNC => String::from("sync"),
        SYSCTL_STRESS if arg <= 600 => {
            if arg == 0 { String::from("stress") } else { alloc::format!("stress {}", arg) }
        }
        _ => return None,
    };
    Some(run_to_string(&line))
}

fn run_to_string(line: &str) -> String {
    let mut out = String::new();
    let mut cwd = String::from("/");
    execute(line, &mut out, &mut Context { history: &[], cwd: &mut cwd });
    out
}

// ------------------------------------------------------------
// Pętla shella
// ------------------------------------------------------------

pub fn run() -> ! {
    let mut out = console::writer();
    let _ = writeln!(out);
    let _ = writeln!(out, "\x1b[1;36mDeSoOS v{}\x1b[0m - type 'help' for commands", VERSION);

    let mut editor = LineEditor::new();
    let mut cwd = String::from("/");
    loop {
        editor.set_prompt(&cwd);
        editor.render(&mut out);
        loop {
            // Linia do odrysowania, gdyby w trakcie czekania przyszedł
            // komunikat z innego zadania (np. koniec procesu w tle).
            let mut snapshot = String::new();
            editor.render(&mut snapshot);
            console::set_input_line(Some(snapshot));
            let key = console::wait_key();
            console::set_input_line(None);
            match editor.handle(key) {
                Edit::Nothing => {}
                Edit::Echo(c) => {
                    let _ = write!(out, "{}", c);
                }
                Edit::Redraw => editor.render(&mut out),
                Edit::Cancel => {
                    let _ = writeln!(out, "^C");
                    break;
                }
                Edit::ClearScreen => {
                    let _ = write!(out, "\x1b[2J\x1b[H");
                    editor.render(&mut out);
                }
                Edit::Candidates(list) => {
                    let _ = writeln!(out);
                    for name in list {
                        let _ = write!(out, "{}  ", name);
                    }
                    let _ = writeln!(out);
                    editor.render(&mut out);
                }
                Edit::Submit(line) => {
                    let _ = writeln!(out);
                    let history = editor.history().to_vec();
                    execute(&line, &mut out, &mut Context { history: &history, cwd: &mut cwd });
                    break;
                }
            }
        }
    }
}

// ------------------------------------------------------------
// TEST (tylko build z --cfg selftest)
// ------------------------------------------------------------

#[cfg(selftest)]
macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            crate::serial_println!("[CON TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

#[cfg(selftest)]
pub fn self_test() {
    use crate::console::SerialDecoder;
    use crate::drivers::{fbcon, font, serial};
    use crate::serial_println;

    serial_println!("[CON TEST] Starting console + shell tests...");
    crate::selftest::begin();

    // 1-5: konsola framebuffera (jeśli jest).
    let fb_ok = console::fb_size().is_some();
    if fb_ok {
        // 1. Geometria i write-combining.
        let r = console::with_framebuffer(|fb| (fb.cols, fb.rows, fb.size_pixels()));
        let (cols, rows, (w, h)) = r.unwrap();
        check!(cols == w / font::WIDTH && rows == h / font::HEIGHT, "grid {}x{} for {}x{}", cols, rows, w, h);
        let fb_addr = crate::console::fb_address();
        if crate::memory::pat_supported() {
            let pat = crate::memory::read_pat();
            check!((pat >> 8) & 0xFF == crate::memory::PAT_WC, "PAT PA1 = {:#x}", (pat >> 8) & 0xFF);
            let flags = crate::memory::page_flags(crate::memory::phys_to_virt(fb_addr));
            check!(flags.is_some(), "framebuffer page not in direct map");
            let flags = flags.unwrap();
            check!(
                flags & crate::memory::WRITE_THROUGH != 0 && flags & crate::memory::CACHE_DISABLE == 0,
                "framebuffer page flags {:#x} (want PWT=1 PCD=0 -> WC)", flags
            );
        }
        serial_println!("[CON TEST] 1/10 framebuffer {}x{} chars, write-combining PASS", cols, rows);

        // 2. Rysowanie glifu: piksele komórki (0,0) = glif 'A'.
        let bad = console::with_framebuffer(|fb| {
            fb.write_bytes(b"\x1b[2J\x1b[HA");
            let fg = fb.native_color(fbcon::DEFAULT_FG);
            let bg = fb.native_color(fbcon::DEFAULT_BG);
            let g = font::glyph('A');
            for y in 0..font::HEIGHT {
                for x in 0..font::WIDTH {
                    let want = if g[y] & (0x80 >> x) != 0 { fg } else { bg };
                    if fb.read_pixel(x, y) != want {
                        return Some((x, y));
                    }
                }
            }
            None
        })
        .unwrap();
        check!(bad.is_none(), "pixel {:?} of glyph 'A' wrong", bad);
        serial_println!("[CON TEST] 2/10 glyph 'A' pixels in framebuffer PASS");

        // 3. ANSI: kolor, kursor w lewo, czyszczenie do końca linii, pozycja.
        let r = console::with_framebuffer(|fb| {
            fb.write_bytes(b"\x1b[2J\x1b[Hab\x1b[31mc\x1b[0m");
            let c = fb.cell(2, 0);
            let colored = c.ch == 'c' && c.fg == 1;
            fb.write_bytes(b"\x1b[2D\x1b[K");
            let cleared = fb.cell(0, 0).ch == 'a' && fb.cell(1, 0).ch == ' ' && fb.cell(2, 0).ch == ' ';
            fb.write_bytes(b"\x1b[3;5H");
            (colored, cleared, fb.x, fb.y)
        })
        .unwrap();
        check!(r.0, "SGR 31 not applied");
        check!(r.1, "ESC[2D ESC[K wrong");
        check!(r.2 == 4 && r.3 == 2, "ESC[3;5H -> ({}, {})", r.2, r.3);
        serial_println!("[CON TEST] 3/10 ANSI colors, cursor, clear-to-EOL PASS");

        // 4. Zawijanie i przewijanie.
        let r = console::with_framebuffer(|fb| {
            fb.write_bytes(b"\x1b[2J\x1b[H");
            // rows linii + '\n' -> jedno przewinięcie, na górze zostaje "L1".
            for i in 0..fb.rows {
                let s = alloc::format!("L{}\n", i);
                fb.write_bytes(s.as_bytes());
            }
            let top = (fb.cell(0, 0).ch, fb.cell(1, 0).ch, fb.cell(2, 0).ch);
            fb.write_bytes(b"\x1b[2J\x1b[H");
            for _ in 0..fb.cols + 3 {
                fb.write_bytes(b"x");
            }
            (top, fb.y, fb.x, fb.cell(fb.cols - 1, 0).ch)
        })
        .unwrap();
        check!(r.0 == ('L', '1', ' '), "after scroll top row = {:?}", r.0);
        check!(r.1 == 1 && r.2 == 3 && r.3 == 'x', "wrap -> y={} x={}", r.1, r.2);
        serial_println!("[CON TEST] 4/10 line wrap + scroll PASS");

        // 5. UTF-8 i polskie glify.
        let r = console::with_framebuffer(|fb| {
            fb.write_bytes("\x1b[2J\x1b[Hżółć€".as_bytes());
            [fb.cell(0, 0).ch, fb.cell(1, 0).ch, fb.cell(4, 0).ch]
        })
        .unwrap();
        check!(r == ['ż', 'ó', '€'], "cells {:?}", r);
        check!(font::glyph('ż') != font::glyph('?') && font::glyph('ą') != font::glyph('a'), "missing Polish glyphs");
        console::with_framebuffer(|fb| fb.write_bytes(b"\x1b[2J\x1b[H"));
        serial_println!("[CON TEST] 5/10 UTF-8 + Polish glyphs PASS");
    } else {
        serial_println!("[CON TEST] 1-5/10 skipped (no framebuffer)");
    }

    // 6. Serial RX na przerwaniach (pętla zwrotna UART).
    // M16b: bez portu szeregowego (laptop) odbioru po prostu nie ma.
    if !serial::present() {
        serial_println!("[CON TEST] 6/10 no COM1 port - serial RX skipped PASS");
    } else {
        check!(serial::rx_interrupts_enabled(), "COM1 RX interrupt not enabled");
        while serial::read_byte().is_some() {}
        let before = crate::arch::x86_64::irq::count(4);
        serial::loopback(true);
        for &b in b"x\x1b[A" {
            serial::send_raw(b);
        }
        let deadline = crate::time::ticks() + 50;
        let mut got = Vec::new();
        while got.len() < 4 && crate::time::ticks() < deadline {
            while let Some(b) = serial::read_byte() {
                got.push(b);
            }
            crate::arch::x86_64::interrupts::enable_and_hlt();
        }
        serial::loopback(false);
        check!(got == b"x\x1b[A", "loopback received {:?}", got);
        check!(crate::arch::x86_64::irq::count(4) > before, "IRQ4 not delivered");
        serial_println!("[CON TEST] 6/10 COM1 RX via IRQ4 (UART loopback) PASS");
    }

    // 7. Dekoder terminala.
    let mut d = SerialDecoder::new();
    let mut keys = Vec::new();
    for &b in "a\r\n\x7f\x1b[D\x1b[3~\x03ż\x1b[1~".as_bytes() {
        if let Some(k) = d.feed(b) {
            keys.push(k);
        }
    }
    check!(
        keys == [Key::Char('a'), Key::Enter, Key::Backspace, Key::Left, Key::Delete, Key::Ctrl('c'), Key::Char('ż'), Key::Home],
        "decoded {:?}", keys
    );
    serial_println!("[CON TEST] 7/10 terminal decoder (UTF-8, ESC sequences, CR LF) PASS");

    // 8. Edytor linii.
    let mut ed = LineEditor::new();
    for k in [Key::Char('h'), Key::Char('e'), Key::Char('l'), Key::Char('o'), Key::Left, Key::Char('l')] {
        ed.handle(k);
    }
    check!(ed.line() == "hello" && ed.cursor() == 4, "insert: {:?} @{}", ed.line(), ed.cursor());
    ed.handle(Key::Home);
    ed.handle(Key::Delete);
    check!(ed.handle(Key::End) == Edit::Redraw, "End");
    check!(ed.handle(Key::Char('!')) == Edit::Echo('!'), "echo at end");
    check!(ed.handle(Key::Enter) == Edit::Submit(String::from("ello!")), "submit");
    ed.handle(Key::Char('x'));
    ed.handle(Key::Up);
    check!(ed.line() == "ello!", "history up: {:?}", ed.line());
    ed.handle(Key::Down);
    check!(ed.line() == "x", "history down restores draft: {:?}", ed.line());
    ed.handle(Key::Ctrl('u'));
    for c in "upt".chars() {
        ed.handle(Key::Char(c));
    }
    ed.handle(Key::Tab);
    check!(ed.line() == "uptime ", "tab: {:?}", ed.line());
    ed.handle(Key::Ctrl('c'));
    ed.handle(Key::Char('h'));
    check!(matches!(ed.handle(Key::Tab), Edit::Candidates(ref v) if v.contains(&"help") && v.contains(&"history")), "tab candidates");
    serial_println!("[CON TEST] 8/10 line editor (insert, Home/Del, history, Tab) PASS");

    // 9. Komendy (wyjście do bufora).
    let mut cwd = String::from("/");
    let mut ctx = Context { history: &[], cwd: &mut cwd };
    let ctx = &mut ctx;
    let mut s = String::new();
    check!(execute("echo  hi there", &mut s, ctx) && s == "hi there\n", "echo -> {:?}", s);
    s.clear();
    check!(execute("uptime", &mut s, ctx) && s.contains("ticks"), "uptime -> {:?}", s);
    s.clear();
    check!(execute("mem", &mut s, ctx) && s.contains("MiB"), "mem -> {:?}", s);
    s.clear();
    check!(execute("irq", &mut s, ctx) && s.contains("IRQ0"), "irq -> {:?}", s);
    s.clear();
    check!(!execute("nosuch", &mut s, ctx) && s.contains("unknown"), "unknown -> {:?}", s);
    s.clear();
    check!(!execute("mfks 0 yes", &mut s, ctx) && s.contains("did you mean 'mkfs'"), "suggest -> {:?}", s);
    s.clear();
    check!(execute("run see", &mut s, ctx) && s.contains("did you mean 'sse'"), "run suggest -> {:?}", s);
    check!(
        console::compose_async("msg", Some("\rP> ab")) == "\r\x1b[Kmsg\n\rP> ab"
            && console::compose_async("msg", None) == "msg\n",
        "async message + prompt redraw"
    );
    s.clear();
    check!(execute("help", &mut s, ctx) && s.contains("reboot"), "help");
    serial_println!("[CON TEST] 9/10 commands (echo, uptime, mem, irq, help, unknown) PASS");

    // 10. Scrollback (M11): linie, które wyjechały górą, da się obejrzeć.
    if fb_ok {
        let r = console::with_framebuffer(|fb| {
            fb.write_bytes(b"\x1b[2J\x1b[H");
            let h0 = fb.history_len();
            let rows = fb.rows;
            for i in 0..rows + 5 {
                fb.write_bytes(alloc::format!("S{}\n", i).as_bytes());
            }
            let pushed = fb.history_len() - h0;
            let line = |fb: &crate::drivers::fbcon::FbConsole, row: usize| -> alloc::string::String {
                (0..4).map(|c| fb.visible_cell(c, row).ch).collect::<alloc::string::String>()
            };
            let live_top = line(fb, 0);
            let v6 = fb.scroll_view(6);
            let back_top = line(fb, 0);
            let back_row6 = line(fb, 6);
            let v3 = fb.scroll_view(-3);
            let mid_top = line(fb, 0);
            let vmax = fb.scroll_view(1_000_000);
            fb.write_bytes(b"");
            let after = (fb.view_offset(), line(fb, 0));
            (pushed, live_top, v6, back_top, back_row6, v3, mid_top, vmax, fb.history_len(), after)
        })
        .unwrap();
        check!(r.0 == 6, "{} lines went to history (expected 6)", r.0);
        check!(r.1 == "S6  ", "live top = {:?}", r.1);
        check!(r.2 == 6 && r.3 == "S0  " && r.4 == "S6  ", "6 back: top {:?}, row 6 {:?}", r.3, r.4);
        check!(r.5 == 3 && r.6 == "S3  ", "3 back: top {:?}", r.6);
        check!(r.7 == r.8 && r.8 <= crate::drivers::fbcon::SCROLLBACK_LINES, "clamp {} vs {}", r.7, r.8);
        check!(r.9.0 == 0 && r.9.1 == "S6  ", "output did not return to live view: {:?}", r.9);
        console::with_framebuffer(|fb| fb.write_bytes(b"\x1b[2J\x1b[H"));
        serial_println!("[CON TEST] 10/10 scrollback ({} lines kept, Shift+PgUp/PgDn) PASS", r.8);
    } else {
        serial_println!("[CON TEST] 10/10 skipped (no framebuffer)");
    }

    serial_println!("[CON TEST] =================================");
    crate::selftest::pass();
    serial_println!("[CON TEST] CONSOLE + SHELL TESTS PASSED");
    serial_println!("[CON TEST] =================================");
}
