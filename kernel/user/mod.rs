// M13a: tryb użytkownika – procesy w ring 3 z własną przestrzenią adresową.
//
// Proces = zadanie schedulera (M12) + AddressSpace (space.rs).  Zadanie
// startuje w ring 0 na swoim stosie kernela, z CR3 procesu, i `iretq`
// przechodzi do ring 3 (CS 0x23, SS 0x1b) pod USER_CODE.
//
// Przerwanie z ring 3: CPU bierze stos z TSS.RSP0 (scheduler ustawia go na
// stos kernela bieżącego zadania).  Wyjątek z ring 3 kończy TYLKO proces:
//   * handler działa na stosie IST (#PF, #GP, #UD...) albo RSP0 – NIE wolno
//     tam przełączać zadań (wspólny stos IST nadpisałby następny wyjątek),
//   * zapisuje przyczynę i podmienia ramkę powrotu: `iretq` wraca do ring 0,
//     do `user_exit_trampoline`, na czysty stos kernela zadania (RSP0),
//   * dopiero tam proces się kończy (sched::exit) – na własnym stosie.
// `kill` procesu w ring 3 działa tak samo (z IRQ timera, irq::dispatch).
//
// FPU/SSE (M13b): każdy proces ma własne rejestry x87/SSE – scheduler
// zapisuje je (FXSAVE) i odtwarza (FXRSTOR) przy każdym przełączeniu
// (arch/x86_64/fpu.rs).  Nowy proces zaczyna od czystego stanu.  Zadania
// kernela działają z CR0.TS = 1: FPU/SSE w kernelu = #NM = błąd kernela.

pub mod elf_loader;
pub mod process;
pub mod procs;
pub mod programs;
pub mod space;
pub mod syscalls;
#[cfg(selftest)]
mod test;
#[cfg(selftest)]
mod test_elf;
#[cfg(selftest)]
mod test_sys;
#[cfg(selftest)]
mod test_init;
#[cfg(selftest)]
mod test_smp;
#[cfg(selftest)]
mod test_lock;
#[cfg(selftest)]
mod test_tlb;
#[cfg(selftest)]
mod test_alloc;
#[cfg(selftest)]
mod test_nobkl;
// M17b.b: potoki.
pub mod channel;
pub mod pipe;
pub mod shm;
pub mod prof;
// M17b.d: pamięć procesu (brk, mmap, leniwe strony).
pub mod vm;
// M17b: obiekty plików, potoki, pamięć procesu.
#[cfg(selftest)]
mod test_files;
#[cfg(selftest)]
mod test_ipc;
// M17a: stress test SMP (samotest i komenda `stress`).
pub mod stress;

pub use process::Process;
pub use space::AddressSpace;

use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::x86_64::exceptions::ExceptionFrame;
use crate::arch::x86_64::gdt::{KERNEL_CS, KERNEL_DS, USER_CS, USER_DS};
#[allow(unused_imports)] // testy (test.rs, test_sys.rs) biorą go przez `use super::*`
use crate::arch::x86_64::interrupts::without_interrupts;
use crate::memory::{nx_flag, phys_to_virt, USER, WRITABLE};
use crate::sched::{self, TaskId};
use crate::serial_println;

pub const USER_CODE: u64 = 0x40_0000;
pub const USER_DATA: u64 = 0x60_0000;
pub const USER_STACK_TOP: u64 = 0x0000_7fff_ffff_0000;
pub const USER_STACK_SIZE: u64 = 16 * 1024;
const PAGE: u64 = 4096;

static SMEP: AtomicBool = AtomicBool::new(false);
static SMAP: AtomicBool = AtomicBool::new(false);

#[allow(dead_code)]
pub fn smap_enabled() -> bool {
    SMAP.load(Ordering::Relaxed)
}

// ------------------------------------------------------------
// Start
// ------------------------------------------------------------

/// FPU/SSE (CR0, CR4.OSFXSR) i SMEP.  Po sched::init.
pub fn init() {
    crate::arch::x86_64::fpu::init();
    #[allow(unused_unsafe)]
    let smep = unsafe { core::arch::x86_64::__cpuid_count(7, 0) }.ebx & (1 << 7) != 0;
    if smep {
        unsafe {
            core::arch::asm!("mov {t}, cr4", "bts {t}, 20", "mov cr4, {t}", t = out(reg) _, options(nostack));
        }
        SMEP.store(true, Ordering::Relaxed);
    }
    // M14: SMAP – kernel nie czyta/pisze stron użytkownika poza oknem
    // stac/clac (copy_from_user / copy_to_user).
    #[allow(unused_unsafe)]
    let smap = unsafe { core::arch::x86_64::__cpuid_count(7, 0) }.ebx & (1 << 20) != 0;
    if smap {
        unsafe {
            core::arch::asm!("mov {t}, cr4", "bts {t}, 21", "mov cr4, {t}", t = out(reg) _, options(nostack));
        }
        SMAP.store(true, Ordering::Relaxed);
    }
    syscalls::set_smap(smap);
    crate::arch::x86_64::syscall::init();
    serial_println!(
        "[USER] Ring 3 ready: NX {}, SMEP {}, SMAP {}, FPU/SSE per process, SYSCALL/SYSRET",
        if nx_flag() != 0 { "on" } else { "off (CPU without NX)" },
        if smep { "on" } else { "off (CPU without SMEP)" },
        if smap { "on" } else { "off (CPU without SMAP)" }
    );
}

/// M17: ustawienia ring 3 per CPU na procesorze AP – te same co na BSP
/// (FPU/SSE, SMEP, SMAP, MSR-y SYSCALL z blokiem per CPU `cpu`).
pub fn init_ap_cpu(cpu: usize) {
    crate::arch::x86_64::fpu::init();
    if SMEP.load(Ordering::Relaxed) {
        unsafe { core::arch::asm!("mov {t}, cr4", "bts {t}, 20", "mov cr4, {t}", t = out(reg) _, options(nostack)) };
    }
    if SMAP.load(Ordering::Relaxed) {
        unsafe { core::arch::asm!("mov {t}, cr4", "bts {t}, 21", "mov cr4, {t}", t = out(reg) _, options(nostack)) };
    }
    crate::arch::x86_64::syscall::init_cpu(cpu);
}

#[allow(dead_code)]
pub fn smep_enabled() -> bool {
    SMEP.load(Ordering::Relaxed)
}

// ------------------------------------------------------------
// Uruchamianie procesu
// ------------------------------------------------------------

/// Opcje uruchomienia procesu.
pub struct SpawnOptions {
    /// Pierwszy qword strony danych (USER_DATA).
    pub data: u64,
    /// Testy: wejście procesu z bufora (None = klawiatura).
    pub stdin: Option<Vec<u8>>,
    /// Testy: wyjście procesu do bufora (captured_output) zamiast na ekran.
    pub capture: bool,
    /// Adres strony kodu (domyślnie USER_CODE) i punkt wejścia w niej.
    pub code_at: u64,
    pub entry_offset: u64,
    /// M15: shell czeka na proces (exit(0) bez komunikatu).
    pub foreground: bool,
}

impl Default for SpawnOptions {
    fn default() -> Self {
        SpawnOptions { data: 0, stdin: None, capture: false, code_at: USER_CODE, entry_offset: 0, foreground: false }
    }
}

/// Tworzy proces z kodem `code` (pod USER_CODE), stroną danych (qword 0 =
/// `data`) i stosem 16 KiB; zwraca numer zadania.
pub fn spawn_process(name: &str, code: &[u8], data: u64) -> Result<TaskId, &'static str> {
    spawn_with(name, code, &SpawnOptions { data, ..SpawnOptions::default() })
}

pub fn spawn_with(name: &str, code: &[u8], opts: &SpawnOptions) -> Result<TaskId, &'static str> {
    if code.is_empty() || code.len() > 64 * 1024 {
        return Err("bad program size");
    }
    let mut space = AddressSpace::new().ok_or("out of memory")?;
    let nx = nx_flag();

    // Kod: tylko odczyt + wykonywanie.
    for (i, chunk) in code.chunks(PAGE as usize).enumerate() {
        let frame = space.map_new(opts.code_at + i as u64 * PAGE, USER).ok_or("out of memory")?;
        unsafe {
            core::ptr::copy_nonoverlapping(chunk.as_ptr(), phys_to_virt(frame) as *mut u8, chunk.len());
        }
    }
    // Dane: zapis, bez wykonywania.
    let data_frame = space.map_new(USER_DATA, USER | WRITABLE | nx).ok_or("out of memory")?;
    unsafe { core::ptr::write(phys_to_virt(data_frame) as *mut u64, opts.data) };
    // Stos: zapis, bez wykonywania; strona pod nim zostaje pusta (strażnik).
    let mut va = USER_STACK_TOP - USER_STACK_SIZE;
    while va < USER_STACK_TOP {
        space.map_new(va, USER | WRITABLE | nx).ok_or("out of memory")?;
        va += PAGE;
    }

    let mut process = alloc::boxed::Box::new(Process::new(space));
    apply_test_io(&mut process, opts);
    sched::spawn_user(name, user_task_entry, (opts.code_at + opts.entry_offset) as usize, process, false)
}

// ------------------------------------------------------------
// M15: programy ELF
// ------------------------------------------------------------

/// Największy plik programu, który `exec` wczyta do pamięci.
pub const MAX_PROGRAM_FILE: usize = 8 * 1024 * 1024;

/// Proces z obrazu ELF; `args[0]` to nazwa programu (argv[0]).
pub fn spawn_elf(
    name: &str,
    bytes: &[u8],
    args: &[&str],
    cwd: &str,
    opts: &SpawnOptions,
) -> Result<TaskId, elf_loader::LoadError> {
    let loaded = elf_loader::load(bytes, args)?;
    let mut process = alloc::boxed::Box::new(Process::new(loaded.space));
    process.mem = vm::ProcMem::new(loaded.image_end);
    process.initial_rsp = loaded.rsp;
    process.cwd = alloc::string::String::from(cwd);
    process.foreground = opts.foreground;
    apply_test_io(&mut process, opts);
    sched::spawn_user(name, user_task_entry, loaded.entry as usize, process, false)
        .map_err(|_| elf_loader::LoadError::NoMemory)
}

/// Testy: wejście z bufora / wyjście do bufora (dzieci procesu je dziedziczą).
fn apply_test_io(process: &mut Process, opts: &SpawnOptions) {
    process.stdin = opts
        .stdin
        .clone()
        .map(|v| alloc::sync::Arc::new(crate::sched::sync::Mutex::new(v.into_iter().collect())));
    if opts.capture {
        process.stdout_creator = true;
        process.stdout = Some(alloc::sync::Arc::new(crate::sched::spin::IrqSpinLock::new(
            "stdout-capture",
            crate::sched::spin::level::OUTPUT,
            Vec::new(),
        )));
    }
}

/// Błąd `exec`: plik (VFS) albo ładowanie.
#[derive(Debug)]
pub enum ExecError {
    Fs(crate::fs::FsError),
    TooBig,
    Load(elf_loader::LoadError),
}

impl core::fmt::Display for ExecError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ExecError::Fs(e) => write!(f, "{}", e),
            ExecError::TooBig => write!(f, "file too big (max 8 MiB)"),
            ExecError::Load(e) => write!(f, "{}", e.as_str()),
        }
    }
}

/// Uruchamia program z pliku (ścieżka absolutna).  Nazwa zadania = ostatni
/// człon ścieżki.
pub fn exec(path: &str, args: &[&str], cwd: &str, opts: &SpawnOptions) -> Result<TaskId, ExecError> {
    let bytes = read_program(path)?;
    let name = path.rsplit('/').next().unwrap_or(path);
    spawn_elf(name, &bytes, args, cwd, opts).map_err(ExecError::Load)
}

/// Plik programu (ścieżka absolutna) do pamięci.
fn read_program(path: &str) -> Result<Vec<u8>, ExecError> {
    let meta = crate::fs::stat(path).map_err(ExecError::Fs)?;
    if meta.kind == crate::fs::FileType::Directory {
        return Err(ExecError::Fs(crate::fs::FsError::IsADirectory));
    }
    if meta.size as usize > MAX_PROGRAM_FILE {
        return Err(ExecError::TooBig);
    }
    crate::fs::read_file(path).map_err(ExecError::Fs)
}

/// M16: syscall spawn – proces-dziecko bieżącego procesu `parent` (zadanie
/// `parent_pid`).  Dziecko dziedziczy katalog bieżący, bufory testowe
/// wejścia/wyjścia i dostaje kopie deskryptorów `fds` jako swoje 0, 1, 2.
/// `foreground`: Ctrl+C kończy dziecko (stos procesów pierwszego planu).
pub fn spawn_child(
    parent_pid: TaskId,
    parent: &Process,
    path: &str,
    args: &[&str],
    foreground: bool,
    fds: Vec<Option<process::Handle>>,
) -> Result<TaskId, ExecError> {
    let t0 = prof::start();
    let bytes = read_program(path)?;
    let t1 = prof::start();
    prof::add(prof::SP_READ, t1 - t0);
    let loaded = elf_loader::load(&bytes, args).map_err(ExecError::Load)?;
    drop(bytes);
    prof::stop(prof::SP_ELF, t1);
    let mut child = alloc::boxed::Box::new(Process::new(loaded.space));
    child.mem = vm::ProcMem::new(loaded.image_end);
    child.initial_rsp = loaded.rsp;
    child.cwd = parent.cwd.clone();
    child.foreground = foreground;
    child.stdin = parent.stdin.clone();
    child.stdout = parent.stdout.clone();
    child.ppid.store(parent_pid, Ordering::SeqCst);
    // M17a.g11: zanim dziecko stanie się widoczne (on_exit rodzica sprawdza).
    parent.has_children.store(true, Ordering::SeqCst);
    child.fds = fds;
    let name = path.rsplit('/').next().unwrap_or(path);
    // M17a.e2/f2: wczytanie programu i budowa przestrzeni – bez BKL; wpis na
    // pierwszy plan robi spawn pod blokadą schedulera, zanim zadanie stanie
    // się widoczne – dziecko nie ruszy, zanim Ctrl+C nie będzie go widział.
    // M17a.g15: licznik żywych dzieci (wait bez przeglądania listy zadań) –
    // przed startem dziecka (jego koniec go zmniejsza).
    parent.live_children.fetch_add(1, Ordering::SeqCst);
    let t2 = prof::start();
    let r = sched::spawn_user(name, user_task_entry, loaded.entry as usize, child, foreground).map_err(|_| {
        parent.live_children.fetch_sub(1, Ordering::SeqCst);
        ExecError::Load(elf_loader::LoadError::NoMemory)
    });
    prof::stop(prof::SP_TASK, t2);
    r
}

// ------------------------------------------------------------
// M16: init
// ------------------------------------------------------------

pub const INIT_PATH: &str = "/bin/init";

/// Zadanie startowe kernela po samotestach: uruchamia /bin/init i go
/// pilnuje.  Init kończy się -> start od nowa; 3 razy w 10 s albo brak pliku
/// -> shell kernela (awaryjnie, wszystkie komendy diagnostyczne).
pub fn run_init() -> ! {
    let mut failures: Vec<u64> = Vec::new();
    loop {
        let pid = match exec(INIT_PATH, &["init"], "/", &SpawnOptions::default()) {
            Ok(pid) => pid,
            Err(e) => {
                serial_println!("[INIT] cannot start {}: {} - starting the kernel shell", INIT_PATH, e);
                crate::console::print_fmt(format_args!(
                    "\x1b[1;31mcannot start {}: {}\x1b[0m - kernel shell\n",
                    INIT_PATH, e
                ));
                crate::shell::run()
            }
        };
        procs::set_init_pid(pid);
        serial_println!("[INIT] {} started (pid {})", INIT_PATH, pid);
        while sched::task_info(pid).is_some() {
            crate::time::sleep_ms(50);
        }
        procs::set_init_pid(0);
        let now = crate::time::uptime_ms();
        failures.retain(|&t| now.saturating_sub(t) < 10_000);
        failures.push(now);
        if failures.len() >= 3 {
            serial_println!("[INIT] init ended 3 times within 10 s - starting the kernel shell");
            crate::console::print_fmt(format_args!(
                "\x1b[1;31minit keeps ending\x1b[0m - kernel shell (type 'help')\n"
            ));
            crate::shell::run()
        }
        serial_println!("[INIT] init (pid {}) ended - restarting", pid);
        crate::time::sleep_ms(200);
    }
}

/// Pierwsze wejście zadania-procesu (ring 0, CR3 procesu już załadowane).
/// Programy asm: RSP = USER_STACK_TOP; ELF: RSP wskazuje argc.
fn user_task_entry(entry: usize) {
    let rsp = sched::current_process().map(|p| p.initial_rsp).unwrap_or(USER_STACK_TOP);
    enter_user(entry as u64, rsp)
}

/// Skok do ring 3 przez `iretq` (ramka: SS, RSP, RFLAGS, CS, RIP).
fn enter_user(rip: u64, rsp: u64) -> ! {
    // M17: wyjście z kernela – BKL oddajemy przy wyłączonych przerwaniach
    // (przerwanie po oddaniu, a przed iretq, wróciłoby tu z BKL w ręku);
    // iretq włączy IF z ramki.
    crate::arch::x86_64::interrupts::disable();
    // M17a.g3: nowy proces startuje już bez BKL.
    if crate::sched::bkl::held() {
        crate::sched::bkl::release();
    }
    unsafe {
        core::arch::asm!(
            "push {ss}",
            "push {rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            // Żadne wartości z kernela nie trafiają do procesu.
            "xor eax, eax",
            "xor ebx, ebx",
            "xor ecx, ecx",
            "xor edx, edx",
            "xor esi, esi",
            "xor edi, edi",
            "xor ebp, ebp",
            "xor r8d, r8d",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            "xor r12d, r12d",
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
            "iretq",
            ss = in(reg) USER_DS as u64,
            rsp = in(reg) rsp,
            rflags = in(reg) 0x202u64, // IF = 1
            cs = in(reg) USER_CS as u64,
            rip = in(reg) rip,
            options(noreturn)
        );
    }
}

// ------------------------------------------------------------
// Zakończenie procesu
// ------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExitKind {
    /// M14: syscall exit(code).
    Exit(i64),
    /// M14: RIP powrotu z syscalla niekanoniczny (SYSRET dałby #GP w ring 0).
    BadReturn,
    /// `int3` – w M13a normalny koniec programu testowego.
    Breakpoint,
    PageFault { address: u64, error: u64 },
    GeneralProtection { error: u64 },
    InvalidOpcode,
    /// #NM w procesie – nie powinno się zdarzyć od M13b (stan FPU jest
    /// zawsze załadowany); zostaje jako zabezpieczenie.
    FpuUnavailable,
    /// #XM – odmaskowany wyjątek SSE (np. dzielenie przez zero).
    SimdException,
    /// `kill` / Ctrl+C.
    Killed,
    Exception { vector: u64 },
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct ExitInfo {
    pub id: TaskId,
    pub kind: ExitKind,
    pub rip: u64,
    pub rax: u64,
    pub rbx: u64,
    pub cs: u64,
}

use alloc::vec::Vec;

// M17a.b: 256 (było 64) – SMP TEST 4 przy 8 CPU: 16 shelli x ~6 procesów
// wypychało z dziennika wpisy pierwszych shelli ("exit info missing").
// M17a.g3: 2048 – mocniejszy stress na Legionie (48 zadań naraz, ~20 tys.
// procesów/s) wypychał wpis, zanim pętla stressu go sprawdziła ("job ...
// ended with None").  ~64 B na wpis -> 128 KiB w .bss.
const EXIT_LOG: usize = 2048;
/// M17a.g2: własna blokada (wcześniej BKL + IF = 0).  Zapisują go syscalle
/// bez BKL (kill w trakcie – `record_exit`) i przerwanie (kill procesu w
/// ring 3), czytają testy i stress – dwa zapisy naraz gubiły wpis.
struct ExitLog {
    entries: [Option<ExitInfo>; EXIT_LOG],
    next: usize,
}

static EXITS: crate::sched::spin::IrqSpinLock<ExitLog> = crate::sched::spin::IrqSpinLock::new(
    "exit-log",
    crate::sched::spin::level::EXIT_LOG,
    ExitLog { entries: [None; EXIT_LOG], next: 0 },
);

fn record(info: ExitInfo) {
    let mut log = EXITS.lock();
    let i = log.next % EXIT_LOG;
    log.entries[i] = Some(info);
    log.next += 1;
}

/// Jak zakończył się proces `id` (ostatnie EXIT_LOG procesów).
pub fn exit_info(id: TaskId) -> Option<ExitInfo> {
    // Od najnowszego: wpis o indeksie next-1 wstecz (pierścień).
    let log = EXITS.lock();
    (1..=EXIT_LOG.min(log.next)).map(|k| (log.next - k) % EXIT_LOG).filter_map(|i| log.entries[i]).find(|e| e.id == id)
}

/// Zapis przyczyny zakończenia bieżącego procesu (syscalle).
pub(crate) fn record_exit(kind: ExitKind, rip: u64, rax: u64, rbx: u64) {
    record(ExitInfo { id: sched::current_id(), kind, rip, rax, rbx, cs: USER_CS as u64 });
}

/// Wyjście procesów uruchomionych z `capture` (testy): ostatnie CAPTURED_LOG.
const CAPTURED_LOG: usize = 256;
static CAPTURED: crate::sched::sync::Mutex<Vec<(TaskId, Vec<u8>)>> = crate::sched::sync::Mutex::new_named("captured output", Vec::new());

/// Przechwycone wyjście zakończonego procesu (SpawnOptions::capture).
#[allow(dead_code)]
pub fn captured_output(id: TaskId) -> Option<Vec<u8>> {
    CAPTURED.lock().iter().rev().find(|(i, _)| *i == id).map(|(_, v)| v.clone())
}

/// Kończy bieżący proces: komunikat, przechwycone wyjście, status dla
/// rodzica (M16), sched::exit.  Na stosie kernela zadania (syscall albo
/// trampolina po wyjątku), z włączonymi przerwaniami.
pub(crate) fn exit_current() -> ! {
    // M17a.g3: bez BKL.  Wszystko tu ma własne blokady: dziennik zakończeń
    // (IrqSpinLock), przechwycone wyjście (sync::Mutex), stdout procesu
    // (IrqSpinLock), konsola, stos pierwszego planu (atomiki), tablica
    // zombie (procs, KMutex), lista zadań (blokada schedulera).  Przestrzeń
    // adresową zwalnia potem reap (pętla idle, pod BKL).  Wołający z BKL
    // (wyjątek procesu, syscall pod BKL) oddaje go w sched::exit przy
    // przełączeniu.
    let t0 = prof::start();
    let id = sched::current_id();
    let info = exit_info(id);
    let kind = info.map(|i| i.kind).unwrap_or(ExitKind::Killed);
    if let Some(p) = sched::current_process() {
        // M17b.b: deskryptory zamknięte od razu (nie przy reap) – czytający z
        // potoku dostaje koniec danych, gdy kończy się ostatni piszący.
        p.fds.clear();
        if let Some(out) = p.stdout.take() {
            // M17a.e: tylko twórca bufora (albo jego ostatni właściciel) – dzieci
            // dziedziczące bufor wypychały z dziennika wpis rodzica (SMP TEST 4
            // przy 8 CPU: 16 shelli x kilka dzieci > 32 wpisy, "output lacks").
            if p.stdout_creator || alloc::sync::Arc::strong_count(&out) == 1 {
                let text = out.lock().clone();
                let mut log = CAPTURED.lock();
                if log.len() >= CAPTURED_LOG {
                    log.remove(0);
                }
                log.push((id, text));
            }
        }
        // Komunikat kernela o końcu procesu:
        //  * rodzic-proces (M16) dostaje status przez wait – kernel mówi
        //    tylko o awariach (wyjątek CPU, zły powrót z syscalla),
        //  * rodzic-kernel (shell kernela, testy) – jak w M15: normalny koniec
        //    na pierwszym planie bez komunikatu, reszta z komunikatem.
        let crashed = !matches!(kind, ExitKind::Exit(_) | ExitKind::Killed);
        let report = if procs::has_process_parent(p) {
            crashed
        } else {
            !(kind == ExitKind::Exit(0) && p.foreground)
        };
        if let (true, Some(info)) = (report, info) {
            let name = sched::with_current_name(|_, n| alloc::string::String::from(n)).unwrap_or_default();
            // Komunikat z tła – shell odrysuje swój prompt pod nim.
            crate::console::print_async(format_args!("[USER] process {} '{}' {}", id, name, describe(&info)));
        }
        crate::console::remove_foreground(id);
        procs::on_exit(id, kind);
    }
    prof::stop(prof::EXIT, t0);
    sched::exit()
}

/// Podmienia ramkę powrotu: zamiast do ring 3 `iretq` wraca do ring 0,
/// do `user_exit_trampoline`, na szczyt stosu kernela zadania.
fn redirect_to_exit(frame: &mut ExceptionFrame, kind: ExitKind) {
    record(ExitInfo {
        id: sched::current_id(),
        kind,
        rip: frame.rip,
        rax: frame.rax,
        rbx: frame.rbx,
        cs: frame.cs,
    });
    frame.rip = user_exit_trampoline as *const () as u64;
    frame.cs = KERNEL_CS as u64;
    frame.ss = KERNEL_DS as u64;
    frame.rflags = 0x2; // IF = 0
    // -8: jak po `call` (RSP % 16 == 8 na wejściu do funkcji).
    frame.rsp = sched::current_kernel_stack_top() - 8;
}

/// Wyjątek z ring 3 (exceptions.rs).  Działa na stosie IST/RSP0 – nic tu
/// nie przełącza zadań.
/// M17b.c: #PF z ring 3 – ile było i ile miało ramkę na stosie kernela
/// zadania (nie na IST); samotest sprawdza, że wszystkie.
static USER_PF: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static USER_PF_TASK_STACK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// (#PF z ring 3, z nich obsłużone na stosie zadania).
#[allow(dead_code)]
pub fn user_page_fault_stats() -> (u64, u64) {
    use core::sync::atomic::Ordering::Relaxed;
    (USER_PF.load(Relaxed), USER_PF_TASK_STACK.load(Relaxed))
}

pub fn handle_exception(frame: &mut ExceptionFrame, cr2: u64) {
    // M17b.d: nieobecna strona w obszarze procesu (sterta, mmap, stos) –
    // dociągnięta; proces wraca do tej samej instrukcji.  Bez BKL (stos
    // zadania – M17b.c; przestrzeń zmienia tylko ten proces).
    if frame.vector == 14 && frame.error_code & 1 == 0 {
        if let Some(p) = sched::current_process() {
            let t0 = prof::start();
            if p.mem.fault_in(&mut p.space, cr2, frame.error_code & 2 != 0, false) {
                prof::stop(prof::PF_USER, t0);
                return;
            }
        }
    }
    if frame.vector == 14 {
        use core::sync::atomic::Ordering::Relaxed;
        USER_PF.fetch_add(1, Relaxed);
        let top = sched::current_kernel_stack_top();
        let at = frame as *const ExceptionFrame as u64;
        if top != 0 && at < top && at >= top - crate::sched::stack::STACK_SIZE {
            USER_PF_TASK_STACK.fetch_add(1, Relaxed);
        }
    }
    let kind = match frame.vector {
        3 => ExitKind::Breakpoint,
        14 => ExitKind::PageFault { address: cr2, error: frame.error_code },
        13 => ExitKind::GeneralProtection { error: frame.error_code },
        6 => ExitKind::InvalidOpcode,
        7 => ExitKind::FpuUnavailable,
        19 => ExitKind::SimdException,
        v => ExitKind::Exception { vector: v },
    };
    redirect_to_exit(frame, kind);
}

/// `kill` procesu, który jest właśnie w ring 3 (z irq::dispatch).
pub fn kill_from_interrupt(frame: &mut ExceptionFrame) {
    redirect_to_exit(frame, ExitKind::Killed);
}

fn describe(info: &ExitInfo) -> alloc::string::String {
    use alloc::format;
    match info.kind {
        ExitKind::Exit(code) => format!("exited (code {})", code),
        ExitKind::BadReturn => format!(
            "killed: non-canonical return address {:#x} after syscall (SYSRET would fault)",
            info.rip
        ),
        ExitKind::Breakpoint => format!("ended (int3 at {:#x}, rax = {})", info.rip, info.rax),
        ExitKind::PageFault { address, error } => format!(
            "killed: #PF {} {:#x} ({}) at {:#x}",
            if error & 16 != 0 { "executing" } else if error & 2 != 0 { "writing" } else { "reading" },
            address,
            if error & 1 != 0 { "protection" } else { "not mapped" },
            info.rip
        ),
        ExitKind::GeneralProtection { error } => {
            format!("killed: #GP (error {:#x}) at {:#x}", error, info.rip)
        }
        ExitKind::InvalidOpcode => format!("killed: #UD invalid instruction at {:#x}", info.rip),
        ExitKind::FpuUnavailable => {
            format!("killed: unexpected #NM (FPU state not loaded) at {:#x}", info.rip)
        }
        ExitKind::SimdException => {
            format!("killed: #XM SIMD floating-point exception at {:#x}", info.rip)
        }
        ExitKind::Killed => alloc::string::String::from("killed"),
        ExitKind::Exception { vector } => format!("killed: exception {} at {:#x}", vector, info.rip),
    }
}

/// Tu wraca `iretq` po wyjątku / kill w ring 3 – już na stosie kernela
/// zadania (nie IST), więc można bezpiecznie zakończyć zadanie.
extern "sysv64" fn user_exit_trampoline() -> ! {
    // M16: exit_current bierze blokady usypiające (tablica zombie) – z
    // włączonymi przerwaniami, jak w syscallu.
    crate::arch::x86_64::interrupts::enable();
    exit_current()
}

#[cfg(selftest)]
pub use test::{fpu_self_test, self_test};
#[cfg(selftest)]
pub use test_sys::self_test as syscall_self_test;
#[cfg(selftest)]
pub use test_elf::self_test as elf_self_test;
#[cfg(selftest)]
pub use test_init::self_test as init_self_test;
#[cfg(selftest)]
pub use test_files::self_test as files_self_test;
#[cfg(selftest)]
pub use test_ipc::self_test as ipc_self_test;
#[cfg(selftest)]
pub use test_smp::self_test as smp_self_test;
#[cfg(selftest)]
pub use test_lock::{self_test as lock_self_test, stress_self_test};
#[cfg(selftest)]
pub use test_tlb::self_test as tlb_self_test;
#[cfg(selftest)]
pub use test_alloc::self_test as alloc_self_test;
#[cfg(selftest)]
pub use test_nobkl::self_test as nobkl_self_test;
