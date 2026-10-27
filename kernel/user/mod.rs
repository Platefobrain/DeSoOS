// User mode: processes in ring 3 with their own address space.
//
// Process = scheduler task + AddressSpace (space.rs).  The task
// starts in ring 0 on its kernel stack, with the process CR3, and `iretq`
// switches to ring 3 (CS 0x23, SS 0x1b) at USER_CODE.
//
// Interrupt from ring 3: the CPU takes the stack from TSS.RSP0 (the scheduler sets it to
// the current task's kernel stack).  An exception from ring 3 terminates ONLY the process:
//   * the handler runs on the IST stack (#PF, #GP, #UD...) or RSP0 – task switching
//     is NOT allowed there (the shared IST stack would be overwritten by the next exception),
//   * it records the cause and replaces the return frame: `iretq` returns to ring 0,
//     to `user_exit_trampoline`, on the task's clean kernel stack (RSP0),
//   * only there does the process exit (sched::exit) – on its own stack.
// `kill` of a process in ring 3 works the same way (from the timer IRQ, irq::dispatch).
//
// FPU/SSE: every process has its own x87/SSE registers – the scheduler
// saves them (FXSAVE) and restores them (FXRSTOR) on every switch
// (arch/x86_64/fpu.rs).  A new process starts with a clean state.  Kernel
// tasks run with CR0.TS = 1: FPU/SSE in the kernel = #NM = kernel bug.

pub mod elf_loader;
pub mod dcp;
pub mod process;
pub mod procs;
pub mod programs;
pub mod space;
pub mod syscalls;
pub mod sysrights;
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
// Pipes.
pub mod channel;
pub mod waitset;
pub mod device;
pub mod pipe;
pub mod kbuf;
pub mod shm;
// INPUT handle (input events from usbd).
pub mod inputsrc;
// In-kernel USB disk (ublk) – read requests go over a channel to usbd.
pub mod ublk;
pub mod prof;
// Process memory (brk, mmap, lazy pages).
pub mod vm;
// File objects, pipes, process memory.
#[cfg(selftest)]
mod test_files;
#[cfg(selftest)]
mod test_ipc;
// The syscall rights table.
#[cfg(selftest)]
mod test_rights;
// User-space services (wait_many, devices, service manager).
#[cfg(selftest)]
mod test_svc;
// USB (xHCI, usbd).
#[cfg(selftest)]
mod test_usb;
#[cfg(selftest)]
mod test_net;
// SMP stress test (self-test and the `stress` command).
pub mod stress;

pub use process::Process;
pub use space::AddressSpace;

use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::x86_64::exceptions::ExceptionFrame;
use crate::arch::x86_64::gdt::{KERNEL_CS, KERNEL_DS, USER_CS, USER_DS};
#[allow(unused_imports)] // tests (test.rs, test_sys.rs) take it via `use super::*`
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
// Startup
// ------------------------------------------------------------

/// FPU/SSE (CR0, CR4.OSFXSR) and SMEP.  After sched::init.
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
    // SMAP – the kernel does not read/write user pages outside the
    // stac/clac window (copy_from_user / copy_to_user).
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

/// Per-CPU ring 3 setup on an AP – the same as on the BSP
/// (FPU/SSE, SMEP, SMAP, SYSCALL MSRs with the per-CPU block `cpu`).
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
// Starting a process
// ------------------------------------------------------------

/// Process start options.
pub struct SpawnOptions {
    /// First qword of the data page (USER_DATA).
    pub data: u64,
    /// Tests: process input from a buffer (None = keyboard).
    pub stdin: Option<Vec<u8>>,
    /// Tests: process output to a buffer (captured_output) instead of the screen.
    pub capture: bool,
    /// Code page address (USER_CODE by default) and the entry point within it.
    pub code_at: u64,
    pub entry_offset: u64,
    /// The shell waits for the process (exit(0) without a message).
    pub foreground: bool,
    /// HW_ROOT handle in slot 3 (only /bin/init and kernel tests).
    pub hw_root: bool,
    /// SYSCTL handle after HW_ROOT (slot 4) – only /bin/init and kernel tests.
    pub sysctl: bool,
    /// INPUT handle after SYSCTL (slot 5 in init) – only /bin/init and kernel tests.
    pub input: bool,
    /// BLK handle after INPUT (slot 6 in init) – only /bin/init and kernel tests.
    pub blk: bool,
}

impl Default for SpawnOptions {
    fn default() -> Self {
        SpawnOptions { data: 0, stdin: None, capture: false, code_at: USER_CODE, entry_offset: 0, foreground: false, hw_root: false, sysctl: false, input: false, blk: false }
    }
}

/// Creates a process with code `code` (at USER_CODE), a data page (qword 0 =
/// `data`) and a 16 KiB stack; returns the task number.
pub fn spawn_process(name: &str, code: &[u8], data: u64) -> Result<TaskId, &'static str> {
    spawn_with(name, code, &SpawnOptions { data, ..SpawnOptions::default() })
}

pub fn spawn_with(name: &str, code: &[u8], opts: &SpawnOptions) -> Result<TaskId, &'static str> {
    if code.is_empty() || code.len() > 64 * 1024 {
        return Err("bad program size");
    }
    let mut space = AddressSpace::new().ok_or("out of memory")?;
    let nx = nx_flag();

    // Code: read + execute only.
    for (i, chunk) in code.chunks(PAGE as usize).enumerate() {
        let frame = space.map_new(opts.code_at + i as u64 * PAGE, USER).ok_or("out of memory")?;
        unsafe {
            core::ptr::copy_nonoverlapping(chunk.as_ptr(), phys_to_virt(frame) as *mut u8, chunk.len());
        }
    }
    // Data: writable, not executable.
    let data_frame = space.map_new(USER_DATA, USER | WRITABLE | nx).ok_or("out of memory")?;
    unsafe { core::ptr::write(phys_to_virt(data_frame) as *mut u64, opts.data) };
    // Stack: writable, not executable; the page below it stays empty (guard).
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
// ELF programs
// ------------------------------------------------------------

/// Largest program file that `exec` will load into memory.
pub const MAX_PROGRAM_FILE: usize = 8 * 1024 * 1024;

/// Process from an ELF image; `args[0]` is the program name (argv[0]).
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
    if opts.hw_root {
        // The only place where HW_ROOT is created (slot 3).
        process.fds.push(Some(process::Handle::new(process::Fd::HwRoot)));
    }
    if opts.sysctl {
        // The only place where SYSCTL is created (slot 4 in init).
        process.fds.push(Some(process::Handle::new(process::Fd::Sysctl)));
    }
    if opts.input {
        // The only place where INPUT is created (slot 5 in init).
        process.fds.push(Some(process::Handle::new(process::Fd::Input(alloc::boxed::Box::new(inputsrc::InputEnd::new())))));
    }
    if opts.blk {
        // The only place where BLK is created (slot 6 in init).
        process.fds.push(Some(process::Handle::new(process::Fd::Blk)));
    }
    apply_test_io(&mut process, opts);
    sched::spawn_user(name, user_task_entry, loaded.entry as usize, process, false)
        .map_err(|_| elf_loader::LoadError::NoMemory)
}

/// Tests: input from a buffer / output to a buffer (inherited by the process's children).
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

/// `exec` error: file (VFS) or loading.
#[derive(Debug)]
pub enum ExecError {
    Fs(crate::fs::FsError),
    TooBig,
    Load(elf_loader::LoadError),
    /// Process limit reached (ERROR_WOULD_BLOCK).
    TooManyProcesses,
}

impl core::fmt::Display for ExecError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ExecError::Fs(e) => write!(f, "{}", e),
            ExecError::TooBig => write!(f, "file too big (max 8 MiB)"),
            ExecError::TooManyProcesses => write!(f, "too many processes"),
            ExecError::Load(e) => write!(f, "{}", e.as_str()),
        }
    }
}

/// Runs a program from a file (absolute path).  Task name = last
/// path component.
pub fn exec(path: &str, args: &[&str], cwd: &str, opts: &SpawnOptions) -> Result<TaskId, ExecError> {
    let bytes = read_program(path)?;
    let name = path.rsplit('/').next().unwrap_or(path);
    spawn_elf(name, &bytes, args, cwd, opts).map_err(ExecError::Load)
}

/// Loads a program file (absolute path) into memory.
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

/// spawn syscall – child process of the current process `parent` (task
/// `parent_pid`).  The child inherits the current directory, the test input/output
/// buffers and gets copies of descriptors `fds` as its 0, 1, 2.
/// `foreground`: Ctrl+C terminates the child (foreground process stack).
pub fn spawn_child(
    parent_pid: TaskId,
    parent: &Process,
    path: &str,
    args: &[&str],
    foreground: bool,
    no_files: bool,
    fds: Vec<Option<process::Handle>>,
) -> Result<TaskId, ExecError> {
    // Process limit; init and its children (shell, services) have a reserve.
    let privileged = parent_pid == procs::init_pid() || parent.trusted;
    let limit = if privileged { process::MAX_PROCS } else { process::MAX_PROCS - process::PROC_RESERVE };
    if process::LIVE_PROCS.load(Ordering::SeqCst) >= limit {
        return Err(ExecError::TooManyProcesses);
    }
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
    // The sandbox is inherited and can only be added, never removed.
    child.no_files = parent.no_files || no_files;
    child.stdin = parent.stdin.clone();
    child.stdout = parent.stdout.clone();
    child.ppid.store(parent_pid, Ordering::SeqCst);
    child.trusted = parent_pid == procs::init_pid();
    // Before the child becomes visible (the parent's on_exit checks this).
    parent.has_children.store(true, Ordering::SeqCst);
    child.fds = process::FdTable::from_vec(fds);
    let name = path.rsplit('/').next().unwrap_or(path);
    // Loading the program and building the address space happen without the BKL; the
    // foreground entry is made by spawn under the scheduler lock, before the task becomes
    // visible – the child will not run before Ctrl+C can see it.
    // Live-children counter (wait without scanning the task list) –
    // incremented before the child starts (its exit decrements it).
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
// init
// ------------------------------------------------------------

pub const INIT_PATH: &str = "/bin/init";

/// Kernel startup task after the self-tests: runs /bin/init and
/// supervises it.  Init exits -> restart; 3 times within 10 s or a missing file
/// -> kernel shell (fallback, all diagnostic commands).
pub fn run_init() -> ! {
    let mut failures: Vec<u64> = Vec::new();
    loop {
        let pid = match exec(INIT_PATH, &["init"], "/", &SpawnOptions { hw_root: true, sysctl: true, input: true, blk: true, ..SpawnOptions::default() }) {
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

/// First entry of a process task (ring 0, process CR3 already loaded).
/// Asm programs: RSP = USER_STACK_TOP; ELF: RSP points to argc.
fn user_task_entry(entry: usize) {
    let rsp = sched::current_process().map(|p| p.initial_rsp).unwrap_or(USER_STACK_TOP);
    enter_user(entry as u64, rsp)
}

/// Jump to ring 3 via `iretq` (frame: SS, RSP, RFLAGS, CS, RIP).
fn enter_user(rip: u64, rsp: u64) -> ! {
    // Leaving the kernel – the BKL is released with interrupts disabled
    // (an interrupt after releasing it but before iretq would return here holding the BKL);
    // iretq enables IF from the frame.
    crate::arch::x86_64::interrupts::disable();
    // A new process starts without the BKL.
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
            // No kernel values leak into the process.
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
// Process termination
// ------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExitKind {
    /// exit(code) syscall.
    Exit(i64),
    /// Non-canonical syscall return RIP (SYSRET would #GP in ring 0).
    BadReturn,
    /// `int3` – the normal end of early asm test programs.
    Breakpoint,
    PageFault { address: u64, error: u64 },
    GeneralProtection { error: u64 },
    InvalidOpcode,
    /// #NM in a process – should never happen (the FPU state is
    /// always loaded); kept as a safeguard.
    FpuUnavailable,
    /// #XM – unmasked SSE exception (e.g. division by zero).
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

// 2048 entries: with 64 entries, SMP TEST 4 on 8 CPUs (16 shells x ~6 processes) pushed out
// the first shells' entries ("exit info missing"); a heavy stress run on a 16-thread machine
// (48 jobs at once, ~20k processes/s) pushed out an entry before the stress loop
// checked it ("job ... ended with None").
// ~64 B per entry -> 128 KiB in .bss.
const EXIT_LOG: usize = 2048;
/// Has its own lock.  Written by syscalls
/// without the BKL (kill in progress – `record_exit`) and by interrupts (kill of a process in
/// ring 3), read by tests and stress – two concurrent writes used to lose an entry.
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

/// How process `id` terminated (last EXIT_LOG processes).
pub fn exit_info(id: TaskId) -> Option<ExitInfo> {
    // From the newest: entry at index next-1 backwards (ring buffer).
    let log = EXITS.lock();
    (1..=EXIT_LOG.min(log.next)).map(|k| (log.next - k) % EXIT_LOG).filter_map(|i| log.entries[i]).find(|e| e.id == id)
}

/// Records the termination cause of the current process (syscalls).
pub(crate) fn record_exit(kind: ExitKind, rip: u64, rax: u64, rbx: u64) {
    record(ExitInfo { id: sched::current_id(), kind, rip, rax, rbx, cs: USER_CS as u64 });
}

/// Output of processes started with `capture` (tests): last CAPTURED_LOG.
const CAPTURED_LOG: usize = 256;
static CAPTURED: crate::sched::sync::Mutex<Vec<(TaskId, Vec<u8>)>> = crate::sched::sync::Mutex::new_named("captured output", Vec::new());

/// Captured output of a terminated process (SpawnOptions::capture).
#[allow(dead_code)]
pub fn captured_output(id: TaskId) -> Option<Vec<u8>> {
    CAPTURED.lock().iter().rev().find(|(i, _)| *i == id).map(|(_, v)| v.clone())
}

/// Terminates the current process: message, captured output, status for
/// the parent, sched::exit.  On the task's kernel stack (syscall or
/// trampoline after an exception), with interrupts enabled.
pub(crate) fn exit_current() -> ! {
    // No BKL.  Everything here has its own locks: the exit log
    // (IrqSpinLock), captured output (sync::Mutex), process stdout
    // (IrqSpinLock), the console, the foreground stack (atomics), the zombie
    // table (procs, KMutex), the task list (scheduler lock).  The address space
    // is freed later by reap (idle loop, under the BKL).  A caller holding the BKL
    // (process exception, syscall under the BKL) releases it in sched::exit on
    // the switch.
    let t0 = prof::start();
    let id = sched::current_id();
    let info = exit_info(id);
    let kind = info.map(|i| i.kind).unwrap_or(ExitKind::Killed);
    if let Some(p) = sched::current_process() {
        // Descriptors are closed immediately (not at reap) – a reader of a
        // pipe gets end-of-data when the last writer exits.
        p.fds.clear();
        // Shared mappings (shared memory, device registers) are also released
        // immediately – a claimed device is returned before the parent gets the status from
        // wait (otherwise only at reap; a service restart would get ERROR_BUSY).
        p.mem.release_shared(&mut p.space);
        if let Some(out) = p.stdout.take() {
            // Only the buffer's creator (or its last owner) – children
            // inheriting the buffer pushed the parent's entry out of the log (SMP TEST 4
            // on 8 CPUs: 16 shells x a few children > 32 entries, "output lacks").
            if p.stdout_creator || alloc::sync::Arc::strong_count(&out) == 1 {
                let text = out.lock().clone();
                let mut log = CAPTURED.lock();
                if log.len() >= CAPTURED_LOG {
                    log.remove(0);
                }
                log.push((id, text));
            }
        }
        // Kernel message about the process exit:
        //  * process parent: gets the status via wait – the kernel reports
        //    only failures (CPU exception, bad syscall return),
        //  * kernel parent (kernel shell, tests): a normal foreground exit
        //    produces no message, everything else does.
        let crashed = !matches!(kind, ExitKind::Exit(_) | ExitKind::Killed);
        let report = if procs::has_process_parent(p) {
            crashed
        } else {
            !(kind == ExitKind::Exit(0) && p.foreground)
        };
        if let (true, Some(info)) = (report, info) {
            let name = sched::with_current_name(|_, n| alloc::string::String::from(n)).unwrap_or_default();
            // Background message – the shell will redraw its prompt below it.
            crate::console::print_async(format_args!("[USER] process {} '{}' {}", id, name, describe(&info)));
        }
        crate::console::remove_foreground(id);
        procs::on_exit(id, kind);
    }
    prof::stop(prof::EXIT, t0);
    sched::exit()
}

/// Replaces the return frame: instead of ring 3, `iretq` returns to ring 0,
/// to `user_exit_trampoline`, at the top of the task's kernel stack.
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
    // -8: as after a `call` (RSP % 16 == 8 on function entry).
    frame.rsp = sched::current_kernel_stack_top() - 8;
}

/// Exception from ring 3 (exceptions.rs).  Runs on the IST/RSP0 stack – nothing here
/// switches tasks.
/// #PF from ring 3 – how many there were and how many had their frame on the task's
/// kernel stack (not on IST); the self-test checks that all of them did.
static USER_PF: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static USER_PF_TASK_STACK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// (#PF from ring 3, of which handled on the task stack).
#[allow(dead_code)]
pub fn user_page_fault_stats() -> (u64, u64) {
    use core::sync::atomic::Ordering::Relaxed;
    (USER_PF.load(Relaxed), USER_PF_TASK_STACK.load(Relaxed))
}

pub fn handle_exception(frame: &mut ExceptionFrame, cr2: u64) {
    // Non-present page in a process region (heap, mmap, stack) –
    // faulted in; the process returns to the same instruction.  No BKL (task
    // stack; the address space is changed only by this process).
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

/// `kill` of a process that is currently in ring 3 (from irq::dispatch).
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

/// `iretq` returns here after an exception / kill in ring 3 – already on the task's
/// kernel stack (not IST), so the task can be terminated safely.
extern "sysv64" fn user_exit_trampoline() -> ! {
    // exit_current takes sleeping locks (zombie table) – with
    // interrupts enabled, as in a syscall.
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
pub use test_rights::self_test as rights_self_test;
#[cfg(selftest)]
pub use test_svc::self_test as svc_self_test;
#[cfg(selftest)]
pub use test_usb::self_test as usb_self_test;
#[cfg(selftest)]
pub use test_net::self_test as net_self_test;
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
