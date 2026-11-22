// libdeso::sys – The raw system call, process start and end, processes, memory, keys, the heap, output.

#[allow(unused_imports)]
use crate::*;
use core::arch::{asm, global_asm};

/// Parent descriptors the child will get as 0, 1, 2.
pub const fn fds(stdin: u64, stdout: u64, stderr: u64) -> u64 {
    stdin | (stdout << 16) | (stderr << 32)
}

#[inline(always)]
pub fn syscall3(n: u64, a: u64, b: u64, c: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n as i64 => ret,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub fn syscall6(n: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n as i64 => ret,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            in("r10") d,
            in("r8") e,
            in("r9") f,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

pub fn exit(code: i32) -> ! {
    syscall3(SYS_EXIT, code as i64 as u64, 0, 0);
    loop {}
}

/// Fills `buf` with random bytes from the kernel's generator (any length – 4096-byte
/// syscalls).  Never blocks; no right needed.
pub fn getrandom(buf: &mut [u8]) -> Result<(), i64> {
    for chunk in buf.chunks_mut(GETRANDOM_MAX) {
        let r = syscall3(SYS_GETRANDOM, chunk.as_mut_ptr() as u64, chunk.len() as u64, 0);
        if r < 0 {
            return Err(r);
        }
    }
    Ok(())
}

/// Starts a program; the child gets ONLY the handles from `map`
/// [(parent handle, number in child)] – copies with the same rights (R_DUP).
pub fn spawn_ex(path: &str, args: &[&str], map: &[(u64, u64)], flags: u64) -> i64 {
    let mut buf = [0u8; 4096];
    let mut n = 0;
    for a in args {
        let b = a.as_bytes();
        if n + b.len() + 1 > buf.len() {
            return -7; // ERROR_TOO_MANY_ARGUMENTS
        }
        buf[n..n + b.len()].copy_from_slice(b);
        n += b.len() + 1;
    }
    let mut flat = [0u64; 32];
    if map.len() > 16 {
        return -22;
    }
    for (i, &(from, to)) in map.iter().enumerate() {
        flat[2 * i] = from;
        flat[2 * i + 1] = to;
    }
    syscall6(SYS_SPAWN_EX, path.as_ptr() as u64, path.len() as u64, buf.as_ptr() as u64, n as u64, flat.as_ptr() as u64, map.len() as u64 | flags << 32)
}

/// End of the heap (0 = query); on error – the current one.
pub fn brk(addr: u64) -> u64 {
    syscall3(SYS_BRK, addr, 0, 0) as u64
}

/// Anonymous memory region (zeroed, pages allocated on first access).
pub fn mmap(len: u64, prot: u64) -> Result<u64, i64> {
    let r = syscall3(SYS_MMAP, len, prot, 0);
    if r < 0 { Err(r) } else { Ok(r as u64) }
}

pub fn munmap(addr: u64, len: u64) -> i64 {
    syscall3(SYS_MUNMAP, addr, len, 0)
}

pub fn getpid() -> u64 {
    syscall3(SYS_GETPID, 0, 0, 0) as u64
}

pub fn sleep_ms(ms: u64) {
    syscall3(SYS_SLEEP, ms, 0, 0);
}

pub fn uptime_ms() -> u64 {
    syscall3(SYS_UPTIME, 0, 0, 0) as u64
}

// ------------------------------------------------------------
// Processes
// ------------------------------------------------------------

/// Starts program `path` (relative to the current directory) with arguments
/// `args` (args[0] = name).  Returns the pid or -errno.
pub fn spawn(path: &str, args: &[&str], flags: u64, fds: u64) -> i64 {
    let mut buf = [0u8; 4096];
    let mut n = 0;
    for a in args {
        let b = a.as_bytes();
        if n + b.len() + 1 > buf.len() {
            return -7; // ERROR_TOO_MANY_ARGUMENTS
        }
        buf[n..n + b.len()].copy_from_slice(b);
        n += b.len() + 1; // byte 0 is already there
    }
    syscall6(SYS_SPAWN, path.as_ptr() as u64, path.len() as u64, buf.as_ptr() as u64, n as u64, flags, fds)
}

/// Waits for child `pid` (WAIT_ANY = any).  Ok((pid, status)); with
/// WNOHANG Ok((0, 0)) when nothing has finished yet.
pub fn wait(pid: u64, flags: u64) -> Result<(u64, u64), i64> {
    let mut status: u64 = 0;
    let r = syscall3(SYS_WAIT, pid, &mut status as *mut u64 as u64, flags);
    if r < 0 { Err(r) } else { Ok((r as u64, status)) }
}

pub fn getppid() -> u64 {
    syscall3(SYS_GETPPID, 0, 0, 0) as u64
}

pub fn kill(pid: u64) -> i64 {
    syscall3(SYS_KILL, pid, 0, 0)
}

/// Task list: lines "pid\tppid\tstate\tms\tswitches\ttype\tname\n".
pub fn tasks(buf: &mut [u8]) -> i64 {
    syscall3(SYS_TASKS, buf.as_mut_ptr() as u64, buf.len() as u64, 0)
}

/// Read-only text from the kernel ("mem", "lspci -v", "cpus", "disk"...)
/// into `buf`.  Err(ERROR_NOT_FOUND) – unknown topic; Err(ERROR_BUFFER_TOO_SMALL) – buffer too small.
pub fn sysinfo(topic: &str, buf: &mut [u8]) -> Result<usize, i64> {
    let r = syscall6(SYS_SYSINFO, topic.as_ptr() as u64, topic.len() as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0);
    if r < 0 { Err(r) } else { Ok(r as usize) }
}

/// System action via the SYSCTL handle (`h`); the result is written as text to `fd`.
pub fn sysctl(h: u64, op: u64, arg: u64, fd: u64) -> i64 {
    syscall6(SYS_SYSCTL, h, op, arg, fd, 0, 0)
}

/// System action with a name (snapshots): the kernel copies at most 24 bytes and checks them.
pub fn sysctl_name(h: u64, op: u64, arg: u64, fd: u64, name: &str) -> i64 {
    syscall6(SYS_SYSCTL, h, op, arg, fd, name.as_ptr() as u64, name.len() as u64)
}

/// Description of a wait status.
pub fn describe_status(status: u64) -> &'static str {
    if status & STATUS_SIGNALED == 0 {
        return if status == 0 { "done" } else { "exited with an error" };
    }
    match status & 0xFF {
        9 => "killed",
        14 => "crashed (page fault)",
        13 => "crashed (general protection)",
        6 => "crashed (invalid instruction)",
        19 => "crashed (SIMD exception)",
        3 => "ended (int3)",
        _ => "crashed",
    }
}

// ------------------------------------------------------------
// Keys (readkey) – for the line editor
// ------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    Char(char),
    /// Ctrl + letter (lowercase).
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
    /// End of input (test buffer exhausted).
    Eof,
}

/// Waits for a key.  `line` = what the kernel redraws if a background
/// process prints something while we wait (prompt + typed text).
pub fn readkey(line: &str) -> Result<Key, i64> {
    let r = syscall3(SYS_READKEY, line.as_ptr() as u64, line.len() as u64, 0);
    if r < 0 {
        return Err(r);
    }
    let r = r as u64;
    const SPECIAL: u64 = 0x11_0000;
    const CTRL: u64 = 0x12_0000;
    Ok(match r {
        0 => Key::Eof,
        r if r >= CTRL => Key::Ctrl(char::from_u32((r - CTRL) as u32).unwrap_or('?')),
        r if r > SPECIAL => match r - SPECIAL {
            1 => Key::Enter,
            2 => Key::Backspace,
            3 => Key::Delete,
            4 => Key::Tab,
            5 => Key::Escape,
            6 => Key::Left,
            7 => Key::Right,
            8 => Key::Up,
            9 => Key::Down,
            10 => Key::Home,
            _ => Key::End,
        },
        r => Key::Char(char::from_u32(r as u32).unwrap_or('?')),
    })
}

// ------------------------------------------------------------
// Process heap – on top of brk / mmap
// ------------------------------------------------------------
//
// Size classes 16 B .. 64 KiB (powers of two), each with its own free
// list; new blocks come from the heap chunk [next, end), which grows via
// brk by at least 64 KiB.  Larger blocks get their own mmap region (freed
// by munmap).  The kernel allocates pages on first access, so the
// reservation costs nothing.  The process is single-threaded – no locks.

const CLASSES: usize = 13; // 16 << 12 = 64 KiB
const GROW: usize = 64 * 1024;

struct Heap {
    next: core::cell::Cell<usize>,
    end: core::cell::Cell<usize>,
    free: [core::cell::Cell<usize>; CLASSES],
}
unsafe impl Sync for Heap {}

static HEAP: Heap = Heap {
    next: core::cell::Cell::new(0),
    end: core::cell::Cell::new(0),
    free: [const { core::cell::Cell::new(0) }; CLASSES],
};

fn class_of(layout: core::alloc::Layout) -> Option<(usize, usize)> {
    let size = layout.size().max(layout.align()).max(16).next_power_of_two();
    let class = size.trailing_zeros() as usize - 4;
    if class < CLASSES { Some((class, size)) } else { None }
}

fn page_up(x: usize) -> usize {
    (x + 4095) & !4095
}

/// Block of `size` (aligned to `size`) from the heap chunk; if none, the heap grows.
fn carve(size: usize) -> *mut u8 {
    if HEAP.end.get() == 0 {
        let b = brk(0) as usize;
        HEAP.next.set(b);
        HEAP.end.set(b);
    }
    let start = (HEAP.next.get() + size - 1) & !(size - 1);
    if start + size > HEAP.end.get() {
        let want = (start + size).max(HEAP.end.get() + GROW);
        let got = brk(want as u64) as usize;
        if got < start + size {
            return core::ptr::null_mut();
        }
        HEAP.end.set(got);
    }
    HEAP.next.set(start + size);
    start as *mut u8
}

pub struct ArenaAlloc;

unsafe impl core::alloc::GlobalAlloc for ArenaAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let Some((class, size)) = class_of(layout) else {
            // Large blocks: their own region (page alignment is enough).
            if layout.align() > 4096 {
                return core::ptr::null_mut();
            }
            return match mmap(page_up(layout.size()) as u64, PROT_READ | PROT_WRITE) {
                Ok(a) => a as *mut u8,
                Err(_) => core::ptr::null_mut(),
            };
        };
        let head = HEAP.free[class].get();
        if head != 0 {
            HEAP.free[class].set(unsafe { *(head as *const usize) });
            return head as *mut u8;
        }
        carve(size)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        match class_of(layout) {
            Some((class, _)) => {
                unsafe { *(ptr as *mut usize) = HEAP.free[class].get() };
                HEAP.free[class].set(ptr as usize);
            }
            None => {
                munmap(ptr as u64, page_up(layout.size()) as u64);
            }
        }
    }
}

#[global_allocator]
static ALLOCATOR: ArenaAlloc = ArenaAlloc;

/// Output buffer for print!/println!: the whole text of one call goes out in
/// a single `write` (a line from a background process does not mix with the shell prompt).
/// Flushed when full and at the end (drop).
pub struct Out {
    fd: u64,
    len: usize,
    buf: [u8; 256],
}

impl Out {
    pub fn new(fd: u64) -> Self {
        Out { fd, len: 0, buf: [0; 256] }
    }
    pub fn flush(&mut self) {
        if self.len > 0 {
            write(self.fd, &self.buf[..self.len]);
            self.len = 0;
        }
    }
}

impl core::fmt::Write for Out {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &b in s.as_bytes() {
            if self.len == self.buf.len() {
                self.flush();
            }
            self.buf[self.len] = b;
            self.len += 1;
        }
        Ok(())
    }
}

impl Drop for Out {
    fn drop(&mut self) {
        self.flush();
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        let _ = core::fmt::Write::write_fmt(&mut $crate::Out::new(1), format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {{
        let mut o = $crate::Out::new(1);
        let _ = core::fmt::Write::write_fmt(&mut o, format_args!($($arg)*));
        let _ = core::fmt::Write::write_str(&mut o, "\n");
    }};
}

#[macro_export]
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        let mut o = $crate::Out::new(2);
        let _ = core::fmt::Write::write_fmt(&mut o, format_args!($($arg)*));
        let _ = core::fmt::Write::write_str(&mut o, "\n");
    }};
}

/// Program arguments (argv) – pointers into the process stack.
#[derive(Clone, Copy)]
pub struct Args {
    argc: usize,
    argv: *const *const u8,
}

impl Args {
    pub fn len(&self) -> usize {
        self.argc
    }

    pub fn get(&self, i: usize) -> Option<&'static str> {
        if i >= self.argc {
            return None;
        }
        unsafe {
            let p = *self.argv.add(i);
            // read_volatile: the compiler will not turn the loop into a strlen call
            // (programs have no libc).
            let mut n = 0;
            while core::ptr::read_volatile(p.add(n)) != 0 {
                n += 1;
            }
            core::str::from_utf8(core::slice::from_raw_parts(p, n)).ok()
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &'static str> + '_ {
        (0..self.argc).filter_map(move |i| self.get(i))
    }

    /// The `argv` array on the start stack (docs/abi/STARTUP.md): `argc` is the word before
    /// it (the start RSP), then `argv[argc]` = NULL, the empty `envp` (NULL) and `auxv`
    /// (AT_NULL, 0).
    pub fn argv(&self) -> *const *const u8 {
        self.argv
    }
}

/// The ABI note (docs/abi/README.md): which DeSo OS ABI this program was built for.  link.ld
/// puts the section in the read-only segment and in its own PT_NOTE; the loader reads it
/// before mapping anything (no note = a program from before ABI 1.0 = 1.0).
#[repr(C, align(4))]
struct AbiNote {
    namesz: u32,
    descsz: u32,
    kind: u32,
    name: [u8; 8],
    major: u16,
    minor: u16,
    flags: u32,
}

#[unsafe(link_section = ".note.deso.abi")]
#[used]
static ABI_NOTE: AbiNote = AbiNote { namesz: 5, descsz: 8, kind: 1, name: *b"DeSo\0\0\0\0", major: ABI_MAJOR, minor: ABI_MINOR, flags: 0 };

global_asm!(r#"
    .section .text._start, "ax"
    .global _start
    _start:
        xor ebp, ebp
        mov rdi, rsp
        and rsp, -16
        call deso_start
        ud2
"#);

unsafe extern "Rust" {
    fn deso_main(args: Args) -> i32;
}

#[unsafe(no_mangle)]
extern "sysv64" fn deso_start(sp: *const u64) -> ! {
    let args = unsafe { Args { argc: *sp as usize, argv: sp.add(1) as *const *const u8 } };
    let code = unsafe { deso_main(args) };
    exit(code)
}

/// Connects the program's `fn main(args: Args) -> i32` to _start.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[unsafe(no_mangle)]
        pub fn deso_main(args: $crate::Args) -> i32 {
            $main(args)
        }
    };
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let _ = core::fmt::Write::write_fmt(&mut Out::new(2), format_args!("panic: {}\n", info));
    exit(101)
}
