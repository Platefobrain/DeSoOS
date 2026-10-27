// System calls.
//
// Number in RAX, arguments in RDI, RSI, RDX, R10, R8, R9, result in RAX;
// error = a negative code (ERROR_* below; the numbers are the Unix ones).
//
//   0  exit(code)                       terminates the process
//   1  write(fd, buf, len) -> n         fd 1/2 = console, 3+ = file
//   2  read(fd, buf, len) -> n          fd 0 = console (whole line), 3+ = file
//   3  open(path, path_len, flags) -> fd
//   4  close(fd)
//   5  getpid() -> id
//   6  sleep(ms)
//   7  yield()
//   8  uptime() -> ms
//
// Process management (init + shell in user space):
//
//   9  spawn(path, len, argv, argv_len, flags, fds) -> pid
//        argv = arguments separated by a 0 byte (argv[0] = program name),
//        flags: 1 FOREGROUND (Ctrl+C terminates the child),
//        fds = in | out << 16 | err << 32 – parent descriptors that the
//        child gets as 0, 1, 2 (copies)
//  10  wait(pid, status_ptr, flags) -> pid
//        pid = -1 (u64::MAX) any child; flags: 1 WNOHANG (0 = nobody has
//        finished yet); status: code 0..255 or 0x100 | reason
//        (9 = kill/Ctrl+C, otherwise the CPU exception number)
//  11  getppid() -> pid
//  12  kill(pid)                         processes only; init is protected
//  13  chdir(path, len)
//  14  getcwd(buf, len) -> n
//  15  readdir(path, len, buf, buflen) -> n   lines "d|f\t<size>\t<name>\n"
//  16  stat(path, len, out)              out = [type (0 file, 1 directory), size]
//  17  mkdir(path, len)
//  18  unlink(path, len)                 file or empty directory
//  19  readkey(line, len) -> key         raw keys for the line editor;
//        line = prompt + text to redraw when a background process prints
//        something while waiting; 0 = end of input
//  20  tasks(buf, len) -> n              lines "pid\tppid\tstate\tms\tswitches\ttype\tname\n"
//  21  (free – formerly kcmd, a bridge to kernel shell commands; replaced by
//        46 sysinfo and 47 sysctl)
//
// File objects: a descriptor points to a shared object (OpenFile:
// path, rights, position) – copies (dup, dup2, spawn) share the position.
//
//  22  dup(fd) -> new fd                 lowest free one
//  23  dup2(old, new) -> new             new is closed and points to old's object
//  24  seek(fd, offset, whence) -> pos   whence 0 SET, 1 CUR, 2 END;
//        console – ERROR_NOT_SEEKABLE
//  25  pipe(out) -> 0                    out = [read fd, write fd]; read waits
//        for data (0 = nobody writes any more), write – for space (ERROR_CLOSED when
//        nobody reads); 64 KiB buffer
//
// Process memory (pages allocated on first access):
//
//  26  brk(addr) -> heap end             0 = query; on error – the current end
//  27  mmap(len, prot) -> addr           anonymous, zeroed; prot 1 READ, 2 WRITE
//  28  munmap(addr, len)                 only mmap regions (parts too)
//
// open flags: 1 READ, 2 WRITE, 4 CREATE, 8 TRUNC, 16 APPEND.
//
// Process memory: pointer + length are checked (lower half, pages present
// with the USER bit, WRITABLE for writes), and the copying itself goes
// through process addresses between `stac` and `clac` (SMAP: outside this
// window the kernel has no access to user pages).

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use alloc::sync::Arc;

use super::process::{rights, Fd, Handle, OpenFile, Process};
use crate::sched::sync::Mutex;
use super::space::USER_SPACE_END;
use super::{exit_current, record_exit, ExitKind};
use crate::arch::x86_64::interrupts::{self, without_interrupts};
use crate::arch::x86_64::syscall::SyscallFrame;
use crate::fs::{self, FileType, FsError};
use crate::memory::{USER, WRITABLE};
use crate::sched;

pub const SYS_EXIT: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_READ: u64 = 2;
pub const SYS_OPEN: u64 = 3;
pub const SYS_CLOSE: u64 = 4;
pub const SYS_GETPID: u64 = 5;
pub const SYS_SLEEP: u64 = 6;
pub const SYS_YIELD: u64 = 7;
pub const SYS_UPTIME: u64 = 8;
pub const SYS_SPAWN: u64 = 9;
pub const SYS_WAIT: u64 = 10;
pub const SYS_GETPPID: u64 = 11;
pub const SYS_KILL: u64 = 12;
pub const SYS_CHDIR: u64 = 13;
pub const SYS_GETCWD: u64 = 14;
pub const SYS_READDIR: u64 = 15;
pub const SYS_STAT: u64 = 16;
pub const SYS_MKDIR: u64 = 17;
pub const SYS_UNLINK: u64 = 18;
pub const SYS_READKEY: u64 = 19;
pub const SYS_TASKS: u64 = 20;
pub const SYS_DUP: u64 = 22;
pub const SYS_DUP2: u64 = 23;
pub const SYS_SEEK: u64 = 24;
pub const SYS_PIPE: u64 = 25;
pub const SYS_BRK: u64 = 26;
pub const SYS_MMAP: u64 = 27;
pub const SYS_MUNMAP: u64 = 28;
/// Copy of a handle with rights `old & mask` (requires DUP).
pub const SYS_HANDLE_DUP: u64 = 29;
/// (kind << 32) | rights.
pub const SYS_HANDLE_INFO: u64 = 30;
/// channel_create(out) – out = [end 0, end 1] (2 × u64).
pub const SYS_CHANNEL_CREATE: u64 = 31;
/// chan_send(h, data, len, handles, n_handles, flags).
pub const SYS_CHAN_SEND: u64 = 32;
/// chan_recv(h, buffer, cap, handles, hcap | flags << 32, info) -> len;
/// info = [len, n_handles, sender] (3 × u64).
pub const SYS_CHAN_RECV: u64 = 33;
/// Do not wait (full / empty queue – ERROR_WOULD_BLOCK).
pub const CHAN_NONBLOCK: u64 = 1;
/// spawn_ex(path, len, argv, len, map, n | flags << 32) – the child
/// gets ONLY the handles from the map [(parent handle, number in child)] (2 × u64).
pub const SYS_SPAWN_EX: u64 = 36;
/// shm_create(size) -> handle (MAP_READ|MAP_WRITE|DUP|TRANSFER).
pub const SYS_SHM_CREATE: u64 = 34;
/// shm_map(h, prot) -> addr; PROT_WRITE requires MAP_WRITE.  Unmapping
/// – munmap of the whole region.
pub const SYS_SHM_MAP: u64 = 35;
/// shm_size(h) -> object size in bytes.
pub const SYS_SHM_SIZE: u64 = 37;
/// wait_many(list, n, timeout_ms) -> mask of ready entries (bit i = entry i),
/// 0 = timed out.  List = n × [handle, signals] (2 × u64), n ≤ WAIT_MAX;
/// timeout u64::MAX = no limit, 0 = just check.
pub const SYS_WAIT_MANY: u64 = 38;
pub const WAIT_MAX: u64 = 16;
/// wait_many signals.
pub const W_READABLE: u64 = 1;
pub const W_WRITABLE: u64 = 2;
/// Interrupt (IRQ object): counter > 0.
pub const W_IRQ: u64 = 4;
/// Interrupt from a handle (rights: the table, sysrights.rs).
fn irq_obj(p: &Process, h: u64) -> Result<Arc<super::device::IrqObj>, i64> {
    let Fd::Irq(q) = p.fd(h)? else { return Err(ERROR_INVALID_HANDLE) };
    Ok(q.clone())
}

/// dev_claim(hw_root, bdf) -> DEVICE handle; bdf = bus << 8 | dev << 3 | fn.
pub const SYS_DEV_CLAIM: u64 = 39;
/// dev_find(hw_root, class, nr) – init looks devices up by class (e.g.
/// xHCI controllers 0C0330), not by a fixed address.  Only from HW_ROOT (ERROR_INVALID_HANDLE);
/// ERROR_INVALID_ARGUMENT – class > 24 bits; ERROR_NOT_FOUND – fewer than nr + 1 matches.  Finding a
/// device claims nothing – access is decided by dev_claim.
fn sys_dev_find(p: &mut Process, root: u64, class: u64, nr: u64) -> SysResult {
    if !matches!(p.fd(root)?, Fd::HwRoot) {
        return Err(ERROR_INVALID_HANDLE);
    }
    if class > 0xFF_FFFF {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    let d = crate::drivers::pci::devices()
        .iter()
        .filter(|d| ((d.class as u64) << 16 | (d.subclass as u64) << 8 | d.prog_if as u64) == class)
        .nth(nr.min(usize::MAX as u64) as usize)
        .ok_or(ERROR_NOT_FOUND)?;
    let a = d.address;
    Ok((a.bus as u64) << 8 | (a.device as u64) << 3 | a.function as u64)
}

/// blk_attach – usbd registers a USB stick as a kernel disk (ublk.rs).
/// ERROR_INVALID_HANDLE – not BLK / not a channel / not SHM; ERROR_ACCESS_DENIED – BLK without WRITE, channel without
/// SEND + RECV + TRANSFER, buffer without MAP_READ; ERROR_INVALID_ARGUMENT – bad block size,
/// 0 blocks, slots outside 1..8, buffer smaller than slots × 64 KiB; ERROR_NO_SPACE –
/// 8 USB disks at once; ERROR_INVALID_ADDRESS.  The kernel takes its own references to the channel and
/// the buffer (usbd may close its handles).
fn sys_blk_attach(p: &mut Process, h: u64, ch: u64, buf: u64, info: u64) -> SysResult {
    // Kinds and rights of all three handles: the table (sysrights.rs).
    if !matches!(p.fd(h)?, Fd::Blk) {
        return Err(ERROR_INVALID_HANDLE);
    }
    let c = chan_end(p, ch)?;
    let b = shm_obj(p, buf)?;
    let raw = copy_from_user(p, info, 64)?;
    let blocks = u64::from_le_bytes(raw[0..8].try_into().unwrap());
    let bs = u32::from_le_bytes(raw[8..12].try_into().unwrap());
    let slots = u32::from_le_bytes(raw[12..16].try_into().unwrap()) as usize;
    let timeout = u32::from_le_bytes(raw[16..20].try_into().unwrap()) as u64;
    if !matches!(bs, 512 | 4096) || blocks == 0 || blocks.checked_mul(bs as u64).is_none() {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    if slots == 0 || slots > super::ublk::SLOTS_MAX || b.len() < (slots * super::ublk::SLOT_BYTES) as u64 {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    let timeout = if timeout == 0 { super::ublk::TIMEOUT_MS } else { timeout.clamp(100, 30_000) };
    let desc: String = raw[24..64]
        .iter()
        .take_while(|&&x| x != 0)
        .map(|&x| if (0x20..0x7F).contains(&x) { x as char } else { '?' })
        .collect();
    super::ublk::attach(c, b, blocks, bs, slots, timeout, String::from(desc.trim()))
}

/// input_inject – keyboard / mouse events from a service (usbd) into the
/// kernel input subsystem (console, shell, readkey – unchanged for everything else).
/// ERROR_INVALID_HANDLE – not INPUT; ERROR_ACCESS_DENIED – no WRITE; ERROR_INVALID_ARGUMENT – n = 0 / > 64 or a bad
/// kind (then no event goes through); ERROR_INVALID_ADDRESS – bad pointer.
fn sys_input_inject(p: &mut Process, h: u64, ptr: u64, n: u64) -> SysResult {
    if !matches!(p.fd(h)?, Fd::Input(_)) {
        return Err(ERROR_INVALID_HANDLE);
    }
    if n == 0 || n > 64 {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    let data = copy_from_user(p, ptr, n * 8)?;
    if data.chunks(8).any(|e| !matches!(e[0], 1 | 2)) {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    // Latency "controller interrupt -> character in the kernel" – measured from
    // the last device interrupt of this process (usbd has one: xHCI).
    let irq_t = p.fds.iter().flatten().filter_map(|h| if let Fd::Irq(o) = &h.obj { Some(o.last_stamp()) } else { None }).max().unwrap_or(0);
    let hd = p.handle(h)?;
    let Fd::Input(src) = &hd.obj else { return Err(ERROR_INVALID_HANDLE) };
    let now = crate::time::ticks();
    let mut measured = false;
    for e in data.chunks(8) {
        match e[0] {
            1 => {
                let usage = e[2]; // HID usage (page 7 – keyboard) fits in a byte
                let pressed = e[1] != 0;
                // Release of a key this source did not press – ignore it.
                if !pressed && !src.is_pressed(usage) {
                    continue;
                }
                src.mark(usage, pressed);
                crate::input::usb_key(src.id, usage, pressed, now);
                if pressed && !measured && irq_t != 0 {
                    measured = true;
                    let us = crate::arch::x86_64::clock::us_between(irq_t, crate::arch::x86_64::clock::stamp());
                    crate::input::hid_latency_record(us);
                }
            }
            _ => crate::input::usb_mouse(e[2], e[1] as i8),
        }
    }
    Ok(crate::input::led_bits())
}

/// dev_info(dev, out) – out = 10 × u64: [vendor | device << 16,
/// class << 16 | subclass << 8 | prog_if, BAR 0..5 sizes, I/O BAR mask,
/// flags (1 = MSI, 2 = MSI-X)].
pub const SYS_DEV_INFO: u64 = 40;
/// dev_map(dev, bar, prot) -> register address (UC, NX); munmap as a whole.
pub const SYS_DEV_MAP: u64 = 41;
/// irq_bind(dev) -> IRQ handle (MSI / MSI-X vector, bus mastering);
/// requires MAP_WRITE on the device.  ERROR_BUSY – already bound / no vectors left.
pub const SYS_IRQ_BIND: u64 = 42;
/// irq_read(irq) -> interrupts since the last read (resets the counter).
pub const SYS_IRQ_READ: u64 = 43;
/// dma_alloc(dev, size, addr_bits) -> SHM handle (contiguous frames below
/// 2^bits, ≤ 2 MiB, ≤ 16 MiB per device; bus mastering); requires MAP_WRITE.
pub const SYS_DMA_ALLOC: u64 = 44;
/// dma_phys(shm) -> physical address of a DMA buffer (ERROR_INVALID_ARGUMENT – ordinary memory).
pub const SYS_DMA_PHYS: u64 = 45;
/// sysinfo(topic, len, buffer, cap) -> text length (read-only).
pub const SYS_SYSINFO: u64 = 46;
/// sysctl(SYSCTL handle, action, arg, fd) – 1 reboot, 2 halt, 3 sync, 4 stress.
pub const SYS_SYSCTL: u64 = 47;
/// dev_find(hw_root, class, nr) -> bdf of the `nr`-th PCI device with the class
/// (24 bits: class << 16 | subclass << 8 | prog_if); ERROR_NOT_FOUND – no more devices.
pub const SYS_DEV_FIND: u64 = 48;
/// input_inject(INPUT, events, n) -> LED state (bit 0 Num, 1 Caps,
/// 2 Scroll); 8-byte event: kind (1 key, 2 mouse), pressed / wheel,
/// code (HID usage / buttons), dx, dy; n ≤ 64.
pub const SYS_INPUT_INJECT: u64 = 49;
/// blk_attach(BLK, channel, buffer, info) -> USB disk number (0 = sda);
/// 64-byte info: blocks u64, block size u32 (512 / 4096), slots u32 (1..8,
/// 64 KiB each in the buffer), timeout_ms u32 (0 = 5000, otherwise 100..30000), 4 bytes
/// zero, 40-byte description (ASCII).  The disk is always read-only.
pub const SYS_BLK_ATTACH: u64 = 50;
/// Maximum number of entries in the spawn_ex map.
pub const SPAWN_EX_MAX: u64 = 16;

pub const SPAWN_FOREGROUND: u64 = 1;
/// The child (and all its descendants) gets no file system access by path –
/// only the handles passed to it (file sandbox).
pub const SPAWN_NO_FILES: u64 = 2;
/// Spawn flags a process may pass.
const SPAWN_FLAGS: u64 = SPAWN_FOREGROUND | SPAWN_NO_FILES;

pub const O_READ: u64 = 1;
pub const O_WRITE: u64 = 2;
pub const O_CREATE: u64 = 4;
pub const O_TRUNC: u64 = 8;
pub const O_APPEND: u64 = 16;

// DeSoOS errors – negative syscall results, the same names and numbers in
// programs (user/lib/desoos.rs).  The numbers are the Unix ones (a future Linux
// compatibility layer needs no translation); the names are DeSoOS's.
pub const ERROR_NOT_PERMITTED: i64 = -1;
pub const ERROR_NOT_FOUND: i64 = -2;
pub const ERROR_NO_PROCESS: i64 = -3;
pub const ERROR_INTERRUPTED: i64 = -4;
pub const ERROR_IO: i64 = -5;
pub const ERROR_INVALID_HANDLE: i64 = -9;
pub const ERROR_WOULD_BLOCK: i64 = -11;
/// Message too large / receiver buffer too small.
pub const ERROR_MESSAGE_TOO_LARGE: i64 = -90;
/// Device already has an owner / no device at that address.
pub const ERROR_BUSY: i64 = -16;
pub const ERROR_NO_DEVICE: i64 = -19;
pub const ERROR_NO_CHILD: i64 = -10;
pub const ERROR_TOO_MANY_ARGUMENTS: i64 = -7;
pub const ERROR_NOT_EXECUTABLE: i64 = -8;
pub const ERROR_OUT_OF_MEMORY: i64 = -12;
#[allow(dead_code)]
pub const ERROR_ACCESS_DENIED: i64 = -13;
pub const ERROR_INVALID_ADDRESS: i64 = -14;
pub const ERROR_ALREADY_EXISTS: i64 = -17;
pub const ERROR_NOT_DIRECTORY: i64 = -20;
pub const ERROR_IS_DIRECTORY: i64 = -21;
pub const ERROR_INVALID_ARGUMENT: i64 = -22;
pub const ERROR_TOO_MANY_HANDLES: i64 = -24;
pub const ERROR_NO_SPACE: i64 = -28;
pub const ERROR_NOT_SEEKABLE: i64 = -29;
pub const ERROR_CLOSED: i64 = -32;
pub const ERROR_READ_ONLY: i64 = -30;
pub const ERROR_BUFFER_TOO_SMALL: i64 = -34;
pub const ERROR_NOT_EMPTY: i64 = -39;
pub const ERROR_NOT_IMPLEMENTED: i64 = -38;
/// No reply in time (ublk – usbd did not respond).
pub const ERROR_TIMED_OUT: i64 = -110;

/// Largest single write/read (longer ones – several calls).
const MAX_IO: u64 = 64 * 1024;
/// Handles per process.
const MAX_FDS: usize = 64;

type SysResult = Result<u64, i64>;

fn fs_error(e: FsError) -> i64 {
    match e {
        FsError::NotFound => ERROR_NOT_FOUND,
        FsError::NotADirectory => ERROR_NOT_DIRECTORY,
        FsError::IsADirectory => ERROR_IS_DIRECTORY,
        FsError::AlreadyExists => ERROR_ALREADY_EXISTS,
        FsError::NoSpace => ERROR_NO_SPACE,
        FsError::InvalidName => ERROR_INVALID_ARGUMENT,
        FsError::NotEmpty => ERROR_NOT_EMPTY,
        FsError::ReadOnly => ERROR_READ_ONLY,
        _ => ERROR_IO,
    }
}

// ------------------------------------------------------------
// Process memory
// ------------------------------------------------------------

static SMAP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn set_smap(on: bool) {
    SMAP.store(on, core::sync::atomic::Ordering::Relaxed);
}

/// Whether [ptr, ptr+len) is process memory with the required rights.
/// Absent pages of process regions (heap, mmap, stack) are faulted in
/// first – the kernel copies into them as if the process wrote to them.
fn user_range_ok(p: &mut Process, ptr: u64, len: u64, write: bool) -> bool {
    if len == 0 {
        return true;
    }
    let Some(end) = ptr.checked_add(len) else { return false };
    if end > USER_SPACE_END {
        return false;
    }
    let mut page = ptr & !0xfff;
    while page < end {
        if p.space.translate(page).is_none() && p.mem.covers(page) {
            p.mem.fault_in(&mut p.space, page, write, true);
        }
        match p.space.translate(page) {
            Some((_, flags)) if flags & USER != 0 && (!write || flags & WRITABLE != 0) => {}
            _ => return false,
        }
        page += 4096;
    }
    true
}

/// Access to process memory: STAC/CLAC (when SMAP is present), no interrupts
/// in between (the AC flag does not leak into handlers).
fn with_user_access<R>(f: impl FnOnce() -> R) -> R {
    without_interrupts(|| {
        let smap = SMAP.load(core::sync::atomic::Ordering::Relaxed);
        if smap {
            unsafe { core::arch::asm!(".byte 0x0f, 0x01, 0xcb", options(nomem, nostack)) }; // stac
        }
        let r = f();
        if smap {
            unsafe { core::arch::asm!(".byte 0x0f, 0x01, 0xca", options(nomem, nostack)) }; // clac
        }
        r
    })
}

pub fn copy_from_user(p: &mut Process, ptr: u64, len: u64) -> Result<Vec<u8>, i64> {
    if !user_range_ok(p, ptr, len, false) {
        return Err(ERROR_INVALID_ADDRESS);
    }
    let mut buf = vec![0u8; len as usize];
    with_user_access(|| unsafe {
        core::ptr::copy_nonoverlapping(ptr as *const u8, buf.as_mut_ptr(), len as usize)
    });
    Ok(buf)
}

pub fn copy_to_user(p: &mut Process, ptr: u64, data: &[u8]) -> Result<(), i64> {
    if !user_range_ok(p, ptr, data.len() as u64, true) {
        return Err(ERROR_INVALID_ADDRESS);
    }
    with_user_access(|| unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len())
    });
    Ok(())
}

// ------------------------------------------------------------
// System calls
// ------------------------------------------------------------

fn sys_write(p: &mut Process, fd: u64, ptr: u64, len: u64) -> SysResult {
    let len = len.min(MAX_IO);
    let data = copy_from_user(p, ptr, len)?;
    write_fd(p, fd, &data)
}

/// Writes ready data to a process descriptor (write, kcmd).
fn write_fd(p: &mut Process, fd: u64, data: &[u8]) -> SysResult {
    if p.is_console(fd) {
        if fd == 0 {
            return Err(ERROR_INVALID_HANDLE);
        }
        if let Some(out) = p.stdout.as_ref() {
            out.lock().extend_from_slice(data);
        } else {
            crate::console::write_from_process(&String::from_utf8_lossy(data));
        }
        return Ok(data.len() as u64);
    }
    match p.fd(fd)? {
        // A channel has no READ / WRITE (messages – chan_send / chan_recv).
        Fd::Console | Fd::Channel(_) | Fd::Shm(_) | Fd::HwRoot | Fd::Device(_) | Fd::Irq(_) | Fd::Sysctl | Fd::Input(_) | Fd::Blk => Err(ERROR_INVALID_HANDLE),
        Fd::Pipe(e) => {
            if !e.write {
                return Err(ERROR_INVALID_HANDLE);
            }
            let e = e.clone();
            e.write(data).map(|n| n as u64)
        }
        Fd::File(f) => {
            if !f.write {
                return Err(ERROR_INVALID_HANDLE);
            }
            let f = f.clone();
            let mut offset = f.offset.lock();
            if f.append {
                *offset = fs::stat(&f.path).map_err(fs_error)?.size;
            }
            let n = fs::write(&f.path, *offset, data).map_err(fs_error)?;
            *offset += n as u64;
            Ok(n as u64)
        }
    }
}

/// A line from the console (echo, Backspace, Enter finishes).  Ctrl+C / kill -> ERROR_INTERRUPTED.
fn read_console_line(max: usize) -> Result<Vec<u8>, i64> {
    use crate::console::{self, Key};
    let mut line = String::new();
    loop {
        if sched::should_exit() {
            return Err(ERROR_INTERRUPTED);
        }
        match console::poll_key() {
            Some(Key::Char(c)) => {
                if line.len() + c.len_utf8() < max {
                    line.push(c);
                    let mut b = [0u8; 4];
                    console::write_str(c.encode_utf8(&mut b));
                }
            }
            Some(Key::Backspace) => {
                if line.pop().is_some() {
                    console::write_str("\x08 \x08");
                }
            }
            Some(Key::Enter) => {
                console::write_str("\n");
                line.push('\n');
                return Ok(line.into_bytes());
            }
            Some(Key::Ctrl('d')) => return Ok(line.into_bytes()),
            Some(Key::Ctrl('c')) => {
                console::write_str("^C\n");
                sched::request_exit(sched::current_id());
                return Err(ERROR_INTERRUPTED);
            }
            Some(_) => {}
            None => {
                console::INPUT_WAIT.wait_until(|| console::input_pending() || sched::should_exit(), None);
            }
        }
    }
}

fn sys_read(p: &mut Process, fd: u64, ptr: u64, len: u64) -> SysResult {
    let len = len.min(MAX_IO);
    if !user_range_ok(p, ptr, len, true) {
        return Err(ERROR_INVALID_ADDRESS);
    }
    let data = if p.is_console(fd) {
        if fd != 0 {
            return Err(ERROR_INVALID_HANDLE);
        }
        match p.stdin.as_ref() {
            Some(input) => {
                let mut input = input.lock();
                let n = (len as usize).min(input.len());
                input.drain(..n).collect()
            }
            None => read_console_line(len as usize)?,
        }
    } else {
        match p.fd(fd)? {
            Fd::Console | Fd::Channel(_) | Fd::Shm(_) | Fd::HwRoot | Fd::Device(_) | Fd::Irq(_) | Fd::Sysctl | Fd::Input(_) | Fd::Blk => return Err(ERROR_INVALID_HANDLE),
            Fd::Pipe(e) => {
                if e.write {
                    return Err(ERROR_INVALID_HANDLE);
                }
                let e = e.clone();
                e.read(len as usize)?
            }
            Fd::File(f) => {
                if !f.read {
                    return Err(ERROR_INVALID_HANDLE);
                }
                let f = f.clone();
                let mut offset = f.offset.lock();
                let mut buf = vec![0u8; len as usize];
                let n = fs::read(&f.path, *offset, &mut buf).map_err(fs_error)?;
                *offset += n as u64;
                buf.truncate(n);
                buf
            }
        }
    };
    copy_to_user(p, ptr, &data)?;
    Ok(data.len() as u64)
}

fn sys_open(p: &mut Process, ptr: u64, len: u64, flags: u64) -> SysResult {
    if len == 0 || len > 255 {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    if flags & (O_READ | O_WRITE) == 0 || flags & !(O_READ | O_WRITE | O_CREATE | O_TRUNC | O_APPEND) != 0 {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    let raw = copy_from_user(p, ptr, len)?;
    let name = core::str::from_utf8(&raw).map_err(|_| ERROR_INVALID_ARGUMENT)?;
    let path = fs::normalize(&p.cwd, name);
    let write = flags & O_WRITE != 0;
    // Writes to a read-only file system (USB stick, SSD) fail immediately.
    if write && fs::is_read_only(&path) {
        return Err(ERROR_READ_ONLY);
    }
    match fs::stat(&path) {
        Ok(m) if m.kind == FileType::Directory => return Err(ERROR_IS_DIRECTORY),
        Ok(_) => {
            if write && flags & O_TRUNC != 0 {
                fs::truncate(&path, 0).map_err(fs_error)?;
            }
        }
        Err(FsError::NotFound) if flags & O_CREATE != 0 && write => {
            fs::create(&path).map_err(fs_error)?;
        }
        Err(e) => return Err(fs_error(e)),
    }
    let file = Fd::File(Arc::new(OpenFile {
        path,
        read: flags & O_READ != 0,
        write,
        append: flags & O_APPEND != 0,
        offset: Mutex::new(0),
    }));
    install_fd(p, 3, file)
}

/// The lowest free descriptor >= `from` gets `fd` (rights per object).
fn install_fd(p: &mut Process, from: usize, fd: Fd) -> SysResult {
    install_handle(p, from, Handle::new(fd))
}

/// The lowest free number >= `from` gets handle `h` (with its rights).
fn install_handle(p: &mut Process, from: usize, h: Handle) -> SysResult {
    let slot = (from..MAX_FDS).find(|&i| p.fds.get(i).map_or(true, |f| f.is_none())).ok_or(ERROR_TOO_MANY_HANDLES)?;
    p.fds.set(slot, Some(h));
    Ok(slot as u64)
}

/// Handle a child gets (spawn, spawn_ex – a list, not in the table) – requires DUP.
fn handle_for_copy(p: &Process, fd: u64) -> Result<Handle, i64> {
    let h = p.handle(fd)?;
    if h.rights & rights::DUP == 0 {
        return Err(ERROR_ACCESS_DENIED);
    }
    Ok(h.clone())
}

/// handle_dup(h, mask) – a new handle (lowest free) to the same
/// object with rights `old & mask`.  Rights never grow.
fn sys_handle_dup(p: &mut Process, fd: u64, mask: u64) -> SysResult {
    let mut h = p.handle(fd)?.clone();
    h.rights &= mask as u32 & rights::ALL;
    install_handle(p, 0, h)
}

/// Channel end from a handle (ERROR_INVALID_HANDLE – not a channel; rights: the table).
fn chan_end(p: &Process, h: u64) -> Result<Arc<super::channel::ChanEnd>, i64> {
    let Fd::Channel(e) = p.fd(h)? else { return Err(ERROR_INVALID_HANDLE) };
    Ok(e.clone())
}

/// Object waited on by wait_many (the Arc is held for the whole wait –
/// closing the handle meanwhile does not free the object).
enum Waitable {
    Chan(Arc<super::channel::ChanEnd>, bool),
    Pipe(Arc<super::pipe::PipeEnd>),
    Irq(Arc<super::device::IrqObj>),
}

impl Waitable {
    fn ready(&self) -> bool {
        match self {
            Waitable::Chan(e, write) => {
                if *write { e.writable() } else { e.readable() }
            }
            Waitable::Pipe(e) => e.ready(),
            Waitable::Irq(i) => i.pending(),
        }
    }

    fn observers(&self) -> &super::waitset::Observers {
        match self {
            Waitable::Chan(e, write) => e.observers(*write),
            Waitable::Pipe(e) => e.observers(),
            Waitable::Irq(i) => i.observers(),
        }
    }
}

/// wait_many – waits until one of the handles is ready.  The whole list is
/// checked before waiting (ERROR_INVALID_HANDLE / ERROR_ACCESS_DENIED / ERROR_INVALID_ARGUMENT for the first bad
/// entry).  A READABLE | WRITABLE entry on a channel – two objects, one bit.
fn sys_wait_many(p: &mut Process, list: u64, n: u64, timeout: u64) -> SysResult {
    if n == 0 || n > WAIT_MAX {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    let raw = copy_from_user(p, list, n * 16)?;
    // (bit, object) – up to 2 objects per entry.
    let mut objs: Vec<(u32, Waitable)> = Vec::with_capacity(n as usize * 2);
    for i in 0..n as usize {
        let h = u64::from_le_bytes(raw[i * 16..i * 16 + 8].try_into().unwrap());
        let sig = u64::from_le_bytes(raw[i * 16 + 8..i * 16 + 16].try_into().unwrap());
        if sig == 0 || sig & !(W_READABLE | W_WRITABLE | W_IRQ) != 0 {
            return Err(ERROR_INVALID_ARGUMENT);
        }
        let hd = p.handle(h)?;
        match &hd.obj {
            Fd::Channel(e) => {
                if sig & W_IRQ != 0 {
                    return Err(ERROR_INVALID_ARGUMENT);
                }
                if sig & W_READABLE != 0 {
                    if hd.rights & rights::RECV == 0 {
                        return Err(ERROR_ACCESS_DENIED);
                    }
                    objs.push((i as u32, Waitable::Chan(e.clone(), false)));
                }
                if sig & W_WRITABLE != 0 {
                    if hd.rights & rights::SEND == 0 {
                        return Err(ERROR_ACCESS_DENIED);
                    }
                    objs.push((i as u32, Waitable::Chan(e.clone(), true)));
                }
            }
            Fd::Pipe(e) => {
                // A pipe end has one direction: read – READABLE, write – WRITABLE.
                let want = if e.write { W_WRITABLE } else { W_READABLE };
                if sig != want {
                    return Err(ERROR_INVALID_ARGUMENT);
                }
                let need = if e.write { rights::WRITE } else { rights::READ };
                if hd.rights & need == 0 {
                    return Err(ERROR_ACCESS_DENIED);
                }
                objs.push((i as u32, Waitable::Pipe(e.clone())));
            }
            Fd::Irq(q) => {
                if sig != W_IRQ {
                    return Err(ERROR_INVALID_ARGUMENT);
                }
                if hd.rights & rights::RECV == 0 {
                    return Err(ERROR_ACCESS_DENIED);
                }
                objs.push((i as u32, Waitable::Irq(q.clone())));
            }
            _ => return Err(ERROR_INVALID_ARGUMENT),
        }
    }
    let mask = |objs: &[(u32, Waitable)]| objs.iter().filter(|(_, o)| o.ready()).fold(0u64, |m, (b, _)| m | 1 << b);
    let now = mask(&objs);
    if now != 0 || timeout == 0 {
        return Ok(now);
    }
    // Own queue on the stack – its address is the channel; registration with objects BEFORE
    // checking the condition (under the scheduler lock in wait_until).
    let wq = crate::sched::sync::WaitQueue::new();
    let ch = &wq as *const _ as usize;
    for (_, o) in &objs {
        o.observers().add(ch);
    }
    // A very long limit (> ~34 years) = no limit – avoids deadline overflow.
    let limit = if timeout >= 1 << 40 { None } else { Some(timeout) };
    wq.wait_until(|| objs.iter().any(|(_, o)| o.ready()) || sched::should_exit(), limit);
    for (_, o) in &objs {
        o.observers().remove(ch);
    }
    if sched::should_exit() {
        return Err(ERROR_INTERRUPTED);
    }
    Ok(mask(&objs))
}

/// channel_create(out) – two channel ends (lowest free numbers).
fn sys_channel_create(p: &mut Process, out: u64) -> SysResult {
    if !user_range_ok(p, out, 16, true) {
        return Err(ERROR_INVALID_ADDRESS);
    }
    let (a, b) = super::channel::new();
    let ha = install_fd(p, 0, Fd::Channel(a))?;
    let hb = match install_fd(p, 0, Fd::Channel(b)) {
        Ok(h) => h,
        Err(e) => {
            p.fds.take(ha as usize);
            return Err(e);
        }
    };
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&ha.to_le_bytes());
    bytes[8..].copy_from_slice(&hb.to_le_bytes());
    copy_to_user(p, out, &bytes)?;
    Ok(0)
}

/// chan_send – data is copied into the kernel before taking any lock.
/// Handles from the list are MOVED (they disappear from the sender's table, require
/// TRANSFER); if sending fails – they return to their slots.
fn sys_chan_send(p: &mut Process, f: &SyscallFrame) -> SysResult {
    use super::channel::MSG_HANDLES;
    let (h, buf, len, hptr, nh, flags) = (f.rdi, f.rsi, f.rdx, f.r10, f.r8, f.r9);
    if flags & !CHAN_NONBLOCK != 0 || nh as usize > MSG_HANDLES {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    if len as usize > super::channel::MSG_MAX {
        return Err(ERROR_MESSAGE_TOO_LARGE);
    }
    let end = chan_end(p, h)?;
    let data = copy_from_user(p, buf, len)?;
    // Handle list: they exist, have TRANSFER, no duplicates, none is
    // an end of this channel.  The whole list is checked before removing anything.
    let mut nums: Vec<usize> = Vec::new();
    if nh > 0 {
        let raw = copy_from_user(p, hptr, nh * 8)?;
        for c in raw.chunks_exact(8) {
            let n = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
            let hd = p.handle(n)?;
            if hd.rights & rights::TRANSFER == 0 {
                return Err(ERROR_ACCESS_DENIED);
            }
            if let Fd::Channel(e) = &hd.obj {
                if e.same_channel(&end) {
                    return Err(ERROR_INVALID_ARGUMENT);
                }
            }
            if nums.contains(&(n as usize)) {
                return Err(ERROR_INVALID_ARGUMENT);
            }
            nums.push(n as usize);
        }
    }
    let handles: Vec<Handle> = nums.iter().map(|&n| p.fds.take(n).unwrap()).collect();
    let msg = super::channel::Message { data, handles, sender: sched::current_id() };
    match end.send(msg, flags & CHAN_NONBLOCK != 0) {
        Ok(()) => Ok(0),
        Err((e, msg)) => {
            // The process is single-threaded – the slots are still free.
            for (n, hd) in nums.into_iter().zip(msg.handles) {
                p.fds.set(n, Some(hd));
            }
            Err(e)
        }
    }
}

/// chan_recv – the message is taken under the channel lock and copied to
/// the process after the lock is released.  Buffer too small: ERROR_MESSAGE_TOO_LARGE, info = required
/// size, the message stays.
fn sys_chan_recv(p: &mut Process, f: &SyscallFrame) -> SysResult {
    use super::channel::RecvError;
    let (h, buf, cap, hptr, hcap_flags, info) = (f.rdi, f.rsi, f.rdx, f.r10, f.r8, f.r9);
    let hcap = (hcap_flags & 0xFFFF) as usize;
    let flags = hcap_flags >> 32;
    if flags & !CHAN_NONBLOCK != 0 || hcap_flags & 0xFFFF_0000 != 0 {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    let cap = cap.min(super::channel::MSG_MAX as u64);
    let hcap = hcap.min(super::channel::MSG_HANDLES);
    if !user_range_ok(p, buf, cap, true)
        || (info != 0 && !user_range_ok(p, info, 24, true))
        || (hcap > 0 && !user_range_ok(p, hptr, hcap as u64 * 8, true))
    {
        return Err(ERROR_INVALID_ADDRESS);
    }
    // Free slots in the table – a message with more handles
    // stays in the queue (ERROR_TOO_MANY_HANDLES), nothing is lost.
    let room = (0..MAX_FDS).filter(|&i| p.fds.get(i).map_or(true, |x| x.is_none())).count();
    let end = chan_end(p, h)?;
    let write_info = |p: &mut Process, len: u64, nh: u64, sender: u64| -> Result<(), i64> {
        if info == 0 {
            return Ok(());
        }
        let mut b = [0u8; 24];
        b[..8].copy_from_slice(&len.to_le_bytes());
        b[8..16].copy_from_slice(&nh.to_le_bytes());
        b[16..].copy_from_slice(&sender.to_le_bytes());
        copy_to_user(p, info, &b)
    };
    match end.recv(cap as usize, hcap, room, flags & CHAN_NONBLOCK != 0) {
        Ok(m) => {
            let (len, nh, sender) = (m.data.len() as u64, m.handles.len() as u64, m.sender);
            copy_to_user(p, buf, &m.data)?;
            // Handles – lowest free numbers (space checked above).
            let mut nums = [0u8; 8 * super::channel::MSG_HANDLES];
            for (i, hd) in m.handles.into_iter().enumerate() {
                let n = install_handle(p, 0, hd)?;
                nums[i * 8..i * 8 + 8].copy_from_slice(&n.to_le_bytes());
            }
            if nh > 0 {
                copy_to_user(p, hptr, &nums[..nh as usize * 8])?;
            }
            write_info(p, len, nh, sender)?;
            Ok(len)
        }
        Err(RecvError::TooSmall(len, nh)) => {
            write_info(p, len as u64, nh as u64, 0)?;
            Err(ERROR_MESSAGE_TOO_LARGE)
        }
        Err(RecvError::Code(e)) => Err(e),
    }
}

/// Shared memory object from a handle (rights: the table).
fn shm_obj(p: &Process, h: u64) -> Result<Arc<super::shm::ShmObj>, i64> {
    let Fd::Shm(o) = p.fd(h)? else { return Err(ERROR_INVALID_HANDLE) };
    Ok(o.clone())
}

/// shm_create(size) – a new (zeroed) object under the lowest
/// free number.
fn sys_shm_create(p: &mut Process, size: u64) -> SysResult {
    let obj = super::shm::ShmObj::new(size)?;
    install_fd(p, 0, Fd::Shm(obj))
}

/// shm_map(h, prot) – the whole object in the process mmap region; always NX,
/// writes only with MAP_WRITE.
fn sys_shm_map(p: &mut Process, h: u64, prot: u64) -> SysResult {
    use super::vm::{PROT_READ, PROT_WRITE};
    if prot & !(PROT_READ | PROT_WRITE) != 0 {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    let write = prot & PROT_WRITE != 0;
    let obj = shm_obj(p, h)?;
    super::vm::count_call();
    p.mem.map_shared(&mut p.space, obj, write)
}

/// Claimed device from a handle (ERROR_INVALID_HANDLE – not a device; rights: the table).
fn dev_obj(p: &Process, h: u64) -> Result<Arc<super::device::DevClaim>, i64> {
    let Fd::Device(d) = p.fd(h)? else { return Err(ERROR_INVALID_HANDLE) };
    Ok(d.clone())
}

/// dev_claim(hw_root, bdf) – a PCI device for a service.  ERROR_ACCESS_DENIED:
/// in-kernel driver, disk, graphics, bridge, system device; ERROR_BUSY:
/// another service owns it; ERROR_NO_DEVICE: no device at that address.
fn sys_dev_claim(p: &mut Process, root: u64, bdf: u64) -> SysResult {
    if !matches!(p.fd(root)?, Fd::HwRoot) {
        return Err(ERROR_INVALID_HANDLE);
    }
    let addr = super::device::address(bdf).ok_or(ERROR_INVALID_ARGUMENT)?;
    let claim = super::device::DevClaim::claim(addr).map_err(|e| match e {
        crate::drivers::pci::ClaimError::NoDevice => ERROR_NO_DEVICE,
        crate::drivers::pci::ClaimError::Busy => ERROR_BUSY,
        crate::drivers::pci::ClaimError::Forbidden => ERROR_ACCESS_DENIED,
    })?;
    install_fd(p, 0, Fd::Device(Arc::new(claim)))
}

/// dev_info(dev, out) – device description (10 × u64, see SYS_DEV_INFO).
fn sys_dev_info(p: &mut Process, h: u64, out: u64) -> SysResult {
    use crate::drivers::pci::{Bar, CAP_MSI, CAP_MSIX};
    let claim = dev_obj(p, h)?;
    let d = claim.dev();
    let mut v = [0u64; 10];
    v[0] = d.vendor as u64 | (d.device as u64) << 16;
    v[1] = (d.class as u64) << 16 | (d.subclass as u64) << 8 | d.prog_if as u64;
    for (i, b) in d.bars.iter().enumerate() {
        match *b {
            Bar::Memory { size, .. } => v[2 + i] = size,
            Bar::Io { size, .. } => {
                v[2 + i] = size as u64;
                v[8] |= 1 << i;
            }
            Bar::None => {}
        }
    }
    v[9] = d.find_capability(CAP_MSI).is_some() as u64 | (d.find_capability(CAP_MSIX).is_some() as u64) << 1;
    let mut bytes = [0u8; 80];
    for (i, x) in v.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&x.to_le_bytes());
    }
    copy_to_user(p, out, &bytes)?;
    Ok(0)
}

/// dev_map(dev, bar, prot) – BAR registers in the process: uncached,
/// never executable, without MSI-X pages.  The mapping holds the claim (closing
/// the handle does not release it while the region is mapped).
fn sys_dev_map(p: &mut Process, h: u64, bar: u64, prot: u64) -> SysResult {
    use super::vm::{PROT_READ, PROT_WRITE};
    if prot & PROT_READ == 0 || prot & !(PROT_READ | PROT_WRITE) != 0 || bar > 5 {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    let write = prot & PROT_WRITE != 0;
    let claim = dev_obj(p, h)?;
    let pages = claim.bar_pages(bar as usize)?;
    super::vm::count_call();
    p.mem.map_mmio(&mut p.space, &pages, write, claim)
}

/// handle_info(h) -> (kind << 32) | rights.
fn sys_handle_info(p: &mut Process, fd: u64) -> SysResult {
    let h = p.handle(fd)?;
    Ok(h.kind() << 32 | h.rights as u64)
}

/// pipe(out) – out = [read fd, write fd] (2 × u64).
fn sys_pipe(p: &mut Process, out: u64) -> SysResult {
    if !user_range_ok(p, out, 16, true) {
        return Err(ERROR_INVALID_ADDRESS);
    }
    let (r, w) = super::pipe::new();
    let rfd = install_fd(p, 0, Fd::Pipe(r))?;
    let wfd = match install_fd(p, 0, Fd::Pipe(w)) {
        Ok(fd) => fd,
        Err(e) => {
            p.fds.take(rfd as usize);
            return Err(e);
        }
    };
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&rfd.to_le_bytes());
    bytes[8..].copy_from_slice(&wfd.to_le_bytes());
    copy_to_user(p, out, &bytes)?;
    Ok(0)
}

/// dup(fd) – a new descriptor (lowest free) to the same object.
fn sys_dup(p: &mut Process, fd: u64) -> SysResult {
    let h = p.handle(fd)?.clone();
    install_handle(p, 0, h)
}

/// dup2(old, new) – `new` points to the object of `old` (the previous object of
/// `new` is closed).  old == new – nothing (as long as old is open).
fn sys_dup2(p: &mut Process, old: u64, new: u64) -> SysResult {
    let f = p.handle(old)?.clone();
    let new = new as usize;
    if new >= MAX_FDS {
        return Err(ERROR_INVALID_HANDLE);
    }
    if old as usize != new {
        p.fds.set(new, Some(f));
    }
    Ok(new as u64)
}

pub const SEEK_SET: u64 = 0;
pub const SEEK_CUR: u64 = 1;
pub const SEEK_END: u64 = 2;

/// seek(fd, offset, whence) -> new position.  Console – ERROR_NOT_SEEKABLE.
fn sys_seek(p: &mut Process, fd: u64, offset: u64, whence: u64) -> SysResult {
    let Fd::File(f) = p.fd(fd)? else { return Err(ERROR_NOT_SEEKABLE) };
    let f = f.clone();
    let mut pos = f.offset.lock();
    let base: i64 = match whence {
        SEEK_SET => 0,
        SEEK_CUR => *pos as i64,
        SEEK_END => fs::stat(&f.path).map_err(fs_error)?.size as i64,
        _ => return Err(ERROR_INVALID_ARGUMENT),
    };
    let new = base.checked_add(offset as i64).ok_or(ERROR_INVALID_ARGUMENT)?;
    if new < 0 {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    *pos = new as u64;
    Ok(new as u64)
}

fn sys_close(p: &mut Process, fd: u64) -> SysResult {
    match p.fds.take(fd as usize) {
        Some(_) => Ok(0),
        None => Err(ERROR_INVALID_HANDLE),
    }
}

// ------------------------------------------------------------
// Processes, directories, keys
// ------------------------------------------------------------

/// Path from process memory (1..=255 bytes of UTF-8), normalized
/// relative to the current directory.
fn user_path(p: &mut Process, ptr: u64, len: u64) -> Result<String, i64> {
    if len == 0 || len > 255 {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    let raw = copy_from_user(p, ptr, len)?;
    let name = core::str::from_utf8(&raw).map_err(|_| ERROR_INVALID_ARGUMENT)?;
    Ok(fs::normalize(&p.cwd, name))
}

fn exec_error(e: super::ExecError) -> i64 {
    use super::elf_loader::LoadError;
    match e {
        super::ExecError::Fs(e) => fs_error(e),
        super::ExecError::TooBig => ERROR_TOO_MANY_ARGUMENTS,
        super::ExecError::TooManyProcesses => ERROR_WOULD_BLOCK,
        super::ExecError::Load(LoadError::NoMemory) => ERROR_OUT_OF_MEMORY,
        super::ExecError::Load(LoadError::TooManyArgs) => ERROR_TOO_MANY_ARGUMENTS,
        super::ExecError::Load(_) => ERROR_NOT_EXECUTABLE,
    }
}

fn sys_spawn(p: &mut Process, f: &SyscallFrame) -> SysResult {
    let (flags, fds) = (f.r8, f.r9);
    if flags & !SPAWN_FLAGS != 0 {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    // The child gets copies of the handles with their rights (requires DUP).
    let child_fd = |shift: u32| -> Result<Option<Handle>, i64> { handle_for_copy(p, (fds >> shift) & 0xFFFF).map(Some) };
    let child_fds = alloc::vec![child_fd(0)?, child_fd(16)?, child_fd(32)?];
    spawn_common(p, f, flags, child_fds)
}

/// spawn_ex – the child gets only the handles from the map (copies, require
/// DUP); numbers in the child < 64, no duplicates.  No stdio unless the parent
/// provides it.
fn sys_spawn_ex(p: &mut Process, f: &SyscallFrame) -> SysResult {
    let (map, n, flags) = (f.r8, f.r9 & 0xFFFF_FFFF, f.r9 >> 32);
    if flags & !SPAWN_FLAGS != 0 || n > SPAWN_EX_MAX {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    let raw = if n > 0 { copy_from_user(p, map, n * 16)? } else { Vec::new() };
    let mut child_fds: Vec<Option<Handle>> = Vec::new();
    for c in raw.chunks_exact(16) {
        let word = |i: usize| u64::from_le_bytes([c[i], c[i + 1], c[i + 2], c[i + 3], c[i + 4], c[i + 5], c[i + 6], c[i + 7]]);
        let (from, to) = (word(0), word(8) as usize);
        if to >= MAX_FDS || child_fds.get(to).map_or(false, |x| x.is_some()) {
            return Err(ERROR_INVALID_ARGUMENT);
        }
        let hd = handle_for_copy(p, from)?;
        if child_fds.len() <= to {
            child_fds.resize_with(to + 1, || None);
        }
        child_fds[to] = Some(hd);
    }
    spawn_common(p, f, flags, child_fds)
}

/// Common part of spawn / spawn_ex: path (rdi, rsi), arguments (rdx, r10).
fn spawn_common(p: &mut Process, f: &SyscallFrame, flags: u64, child_fds: Vec<Option<Handle>>) -> SysResult {
    let (path_ptr, path_len, argv_ptr, argv_len) = (f.rdi, f.rsi, f.rdx, f.r10);
    if argv_len > 4096 {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    let path = user_path(p, path_ptr, path_len)?;
    let raw = copy_from_user(p, argv_ptr, argv_len)?;
    let text = core::str::from_utf8(&raw).map_err(|_| ERROR_INVALID_ARGUMENT)?;
    let mut args: Vec<&str> = text.split('\0').collect();
    if text.ends_with('\0') {
        args.pop();
    }
    if args.is_empty() {
        args.push(path.rsplit('/').next().unwrap_or(&path));
    }
    let me = sched::current_id();
    let t_load = super::prof::start();
    let pid = super::spawn_child(me, p, &path, &args, flags & SPAWN_FOREGROUND != 0, flags & SPAWN_NO_FILES != 0, child_fds)
        .map_err(exec_error)?;
    super::prof::stop(super::prof::LOAD_ELF, t_load);
    Ok(pid)
}

fn sys_wait(p: &mut Process, pid: u64, status_ptr: u64, flags: u64) -> SysResult {
    if flags & !super::procs::WNOHANG != 0 {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    if status_ptr != 0 && !user_range_ok(p, status_ptr, 8, true) {
        return Err(ERROR_INVALID_ADDRESS);
    }
    let (child, status) = super::procs::wait(sched::current_id(), pid, flags)?;
    if child != 0 {
        crate::console::remove_foreground(child);
        if status_ptr != 0 {
            copy_to_user(p, status_ptr, &status.to_le_bytes())?;
        }
    }
    Ok(child)
}

pub(super) fn sys_kill(pid: u64) -> SysResult {
    if !sched::with_process(pid, |_| ()).is_some() {
        return Err(ERROR_NO_PROCESS); // no such process (kill from a process does not touch kernel tasks)
    }
    if pid == super::procs::init_pid() {
        return Err(ERROR_NOT_PERMITTED);
    }
    if sched::request_exit(pid) { Ok(0) } else { Err(ERROR_NO_PROCESS) }
}

fn sys_chdir(p: &mut Process, ptr: u64, len: u64) -> SysResult {
    let path = user_path(p, ptr, len)?;
    match fs::stat(&path) {
        Ok(m) if m.kind == FileType::Directory => {
            p.cwd = path;
            Ok(0)
        }
        Ok(_) => Err(ERROR_NOT_DIRECTORY),
        Err(e) => Err(fs_error(e)),
    }
}

/// Text into a process buffer: all of it or ERROR_BUFFER_TOO_SMALL (nothing is truncated).
fn text_to_user(p: &mut Process, ptr: u64, len: u64, text: &str) -> SysResult {
    if text.len() as u64 > len.min(MAX_IO) {
        return Err(ERROR_BUFFER_TOO_SMALL);
    }
    copy_to_user(p, ptr, text.as_bytes())?;
    Ok(text.len() as u64)
}

fn sys_readdir(p: &mut Process, f: &SyscallFrame) -> SysResult {
    use core::fmt::Write;
    let path = user_path(p, f.rdi, f.rsi)?;
    let entries = fs::read_dir(&path).map_err(fs_error)?;
    let mut text = String::new();
    for e in entries {
        let kind = if e.kind == FileType::Directory { 'd' } else { 'f' };
        let _ = writeln!(text, "{}\t{}\t{}", kind, e.size, e.name);
    }
    text_to_user(p, f.rdx, f.r10, &text)
}

fn sys_stat(p: &mut Process, ptr: u64, len: u64, out: u64) -> SysResult {
    let path = user_path(p, ptr, len)?;
    let m = fs::stat(&path).map_err(fs_error)?;
    let kind: u64 = if m.kind == FileType::Directory { 1 } else { 0 };
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&kind.to_le_bytes());
    buf[8..].copy_from_slice(&m.size.to_le_bytes());
    copy_to_user(p, out, &buf)?;
    Ok(0)
}

/// Key -> number for readkey (never zero: 0 = end of input).
pub fn encode_key(k: crate::console::Key) -> u64 {
    use crate::console::Key;
    const SPECIAL: u64 = 0x11_0000;
    const CTRL: u64 = 0x12_0000;
    match k {
        Key::Char(c) => c as u64,
        Key::Ctrl(c) => CTRL + c as u64,
        Key::Enter => SPECIAL + 1,
        Key::Backspace => SPECIAL + 2,
        Key::Delete => SPECIAL + 3,
        Key::Tab => SPECIAL + 4,
        Key::Escape => SPECIAL + 5,
        Key::Left => SPECIAL + 6,
        Key::Right => SPECIAL + 7,
        Key::Up => SPECIAL + 8,
        Key::Down => SPECIAL + 9,
        Key::Home => SPECIAL + 10,
        Key::End => SPECIAL + 11,
    }
}

fn sys_readkey(p: &mut Process, ptr: u64, len: u64) -> SysResult {
    use crate::console;
    // Keyboard only for a process whose handle 0 is the console with the READ right
    // (like `read(0)`); e.g. a process with a file or pipe on 0 – ERROR_INVALID_HANDLE.
    if !p.is_console(0) || p.handle(0)?.rights & rights::READ == 0 {
        return Err(ERROR_INVALID_HANDLE);
    }
    // Tests: keys from the buffer (bytes as from a terminal).
    if let Some(input) = p.stdin.clone() {
        let mut input = input.lock();
        while let Some(b) = input.pop_front() {
            if let Some(k) = p.key_decoder.feed(b) {
                return Ok(encode_key(k));
            }
        }
        return Ok(0);
    }
    let line = if len > 0 {
        let raw = copy_from_user(p, ptr, len.min(1024))?;
        Some(String::from_utf8_lossy(&raw).into_owned())
    } else {
        None
    };
    // Line to redraw if a message from another task arrives while waiting
    // (e.g. a background process finishing) – as in the kernel shell.
    loop {
        if sched::should_exit() {
            return Err(ERROR_INTERRUPTED);
        }
        if let Some(k) = console::poll_key() {
            return Ok(encode_key(k));
        }
        console::set_input_line(line.clone());
        console::INPUT_WAIT.wait_until(|| console::input_pending() || sched::should_exit(), None);
        console::set_input_line(None);
    }
}

fn sys_tasks(p: &mut Process, ptr: u64, len: u64) -> SysResult {
    use core::fmt::Write;
    let mut text = String::new();
    for t in sched::tasks() {
        let _ = writeln!(
            text,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            t.id,
            t.ppid,
            t.state.name(),
            t.cpu_ticks, // 1 tick = 1 ms (PIT 1000 Hz)
            t.switches,
            if t.user { "user" } else { "kernel" },
            t.name,
            // CPU it is running on now (or last ran on, marked with '~').
            match t.cpu {
                Some(c) => alloc::format!("{}", c),
                None => alloc::format!("~{}", t.last_cpu),
            }
        );
    }
    text_to_user(p, ptr, len, &text)
}

/// sysinfo(topic, len, buffer, cap) – read-only text (mem, lspci,
/// cpus, disk...; list: shell::SYSINFO_TOPICS).  ERROR_NOT_FOUND: unknown topic or
/// disallowed arguments; ERROR_BUFFER_TOO_SMALL: buffer too small (nothing is truncated).
fn sys_sysinfo(p: &mut Process, ptr: u64, len: u64, buf: u64, cap: u64) -> SysResult {
    if len == 0 || len > 64 {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    let raw = copy_from_user(p, ptr, len)?;
    let topic = core::str::from_utf8(&raw).map_err(|_| ERROR_INVALID_ARGUMENT)?;
    // `dcp` – what the caller may see depends on the caller (dcp.rs).
    if topic.trim() == "rights" {
        return text_to_user(p, buf, cap, &super::sysrights::text());
    }
    let text = match topic.trim().strip_prefix("dcp") {
        Some(rest) if rest.is_empty() || rest.starts_with(' ') => {
            let all = p.fds.iter().flatten().any(|h| matches!(h.obj, Fd::Sysctl));
            let viewer = super::dcp::Viewer { pid: sched::current_id(), all };
            super::dcp::dcp(rest, Some(viewer)).ok_or(ERROR_NOT_FOUND)?
        }
        _ => crate::shell::sysinfo(topic).ok_or(ERROR_NOT_FOUND)?,
    };
    text_to_user(p, buf, cap, &text)
}

/// sysctl(SYSCTL handle, action, arg, fd) – reboot / halt / sync /
/// stress; result text goes to `fd`.  ERROR_INVALID_HANDLE: not a SYSCTL handle; ERROR_INVALID_ARGUMENT: bad action.
fn sys_sysctl(p: &mut Process, h: u64, op: u64, arg: u64, fd: u64) -> SysResult {
    if !matches!(p.fd(h)?, Fd::Sysctl) {
        return Err(ERROR_INVALID_HANDLE);
    }
    let out = crate::shell::sysctl(op, arg).ok_or(ERROR_INVALID_ARGUMENT)?;
    if !out.is_empty() {
        // The output handle is not in the table (only used when there is text).
        if p.handle(fd)?.rights & rights::WRITE == 0 {
            return Err(ERROR_ACCESS_DENIED);
        }
        write_fd(p, fd, out.as_bytes())?;
    }
    Ok(0)
}

// ------------------------------------------------------------
// Syscalls without the Big Kernel Lock
// ------------------------------------------------------------
//
// Without the BKL: getpid, uptime, write (console, stdout, files) and
// files and directories: open, close, read from a file / stdin buffer, readkey from the buffer,
// stat, readdir, mkdir, unlink, chdir, getcwd.  They touch only: their own process (single-threaded –
// descriptors, cwd and memory are changed only by it, sched::current_unlocked),
// the tick counter, the heap, the console, the stdout buffer (SpinLock) and the VFS / block
// layer (own locks FS_LOCK / disk locks – KMutex with compare_exchange).
// Waiting for the disk (WaitQueue) – only the scheduler lock.
// Processes: spawn, wait, kill, getppid – the zombie table under its own
// lock.  Sleep and yield – only the scheduler lock.  Under the BKL
// remain: exit (task end), read / readkey from the keyboard, tasks, sysinfo, sysctl.

static FAST: [crate::arch::x86_64::percpu::PerCpuCounter; 6] = [const { crate::arch::x86_64::percpu::PerCpuCounter::new() }; 6];
static SLOW: crate::arch::x86_64::percpu::PerCpuCounter = crate::arch::x86_64::percpu::PerCpuCounter::new();

/// (getpid, uptime, write, files/directories, processes, sleep/yield – without the BKL;
/// the rest under the BKL) – `cpus`, tests.
pub fn syscall_stats() -> ([u64; 6], u64) {
    let mut fast = [0u64; 6];
    for (i, f) in FAST.iter().enumerate() {
        fast[i] = f.get();
    }
    (fast, SLOW.get())
}

/// Whether a syscall may run without the BKL; Some(counter).  With IF = 0 (before the BKL).
fn bkl_free_slot(frame: &SyscallFrame) -> Option<usize> {
    if !sched::active() || frame.rip >= USER_SPACE_END {
        return None;
    }
    let (_, p) = sched::current_unlocked()?;
    match frame.rax {
        SYS_GETPID => Some(0),
        SYS_UPTIME => Some(1),
        SYS_WRITE => Some(2),
        // Reading from a file or the stdin buffer (tests, stress) – without the BKL;
        // from the keyboard (state shared with the interrupt, shell line) – under the BKL.
        SYS_READ => (matches!(p.fds.get(frame.rdi as usize), Some(Some(Handle { obj: Fd::File(_) | Fd::Pipe(_), .. }))) || p.stdin.is_some())
            .then_some(3),
        SYS_READKEY => p.stdin.is_some().then_some(3),
        SYS_DUP | SYS_DUP2 | SYS_SEEK | SYS_PIPE | SYS_HANDLE_DUP | SYS_HANDLE_INFO => Some(3),
        // Channels – own locks, without the BKL.
        SYS_CHANNEL_CREATE | SYS_CHAN_SEND | SYS_CHAN_RECV | SYS_WAIT_MANY => Some(3),
        // Interrupt counter – atomic.
        SYS_IRQ_READ => Some(3),
        // Shared memory – like brk / mmap (changed only by the process).
        SYS_SHM_CREATE | SYS_SHM_MAP | SYS_SHM_SIZE | SYS_DMA_PHYS => Some(4),
        // Process memory – changed only by the process itself, frames without the BKL.
        SYS_BRK | SYS_MMAP | SYS_MUNMAP => Some(4),
        SYS_OPEN | SYS_CLOSE | SYS_STAT | SYS_READDIR | SYS_MKDIR | SYS_UNLINK | SYS_CHDIR | SYS_GETCWD => Some(3),
        // Processes – zombie table under its own lock
        // (task list: under the scheduler lock).
        SYS_SPAWN | SYS_SPAWN_EX | SYS_WAIT | SYS_KILL | SYS_GETPPID => Some(4),
        // Process exit without the BKL (exit_current – own locks).
        SYS_EXIT => Some(4),
        // The scheduler has its own lock – sleep and yield without the BKL.
        SYS_SLEEP | SYS_YIELD => Some(5),
        _ => None,
    }
}


/// Path calls refused in the file sandbox (tests).
pub static SANDBOX_DENIED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Records a refused call in the DCP audit log (dcp.rs).  Only on errors.
#[cold]
fn audit_refusal(p: &mut Process, frame: &SyscallFrame, sandboxed: bool) {
    use super::dcp::Reason;
    let (reason, what): (Reason, Vec<u8>) = if sandboxed {
        // The path (best effort, at most 40 bytes).
        let path = if (1..=255).contains(&frame.rsi) { copy_from_user(p, frame.rdi, frame.rsi.min(40)).unwrap_or_default() } else { Vec::new() };
        (Reason::Sandbox, path)
    } else if let r @ 1.. = super::sysrights::missing(p, frame) {
        // The gate refused: the handle exists but lacks a right from the table.
        (Reason::NoRight(r), alloc::format!("handle {}", frame.rdi).into_bytes())
    } else {
        (Reason::Denied, alloc::format!("handle {}", frame.rdi).into_bytes())
    };
    let name = sched::current_name();
    super::dcp::record(sched::current_id(), p.ppid(), &name, frame.rax, &what, reason);
}

/// Called from syscall_entry (assembly) – on the task's kernel stack.
#[unsafe(no_mangle)]
extern "sysv64" fn syscall_dispatch(frame: &mut SyscallFrame) {
    // Profiling (from entry, including waiting for the BKL, until SYSRET).
    let t0 = super::prof::start();
    let nr = frame.rax as usize;
    // Some syscalls run without the BKL; the rest enter the kernel under the
    // Big Kernel Lock (with IF = 0).
    match bkl_free_slot(frame) {
        Some(slot) => {
            FAST[slot].add(1);
        }
        None => {
            SLOW.add(1);
            crate::sched::bkl::acquire_tagged(&crate::sched::bkl::tag::SYSCALL);
        }
    }
    // Syscalls run with interrupts enabled (SFMASK cleared IF).
    interrupts::enable();
    let Some(p) = sched::current_process() else {
        panic!("syscall from a task without a process");
    };
    let (a0, a1, a2) = (frame.rdi, frame.rsi, frame.rdx);
    // File sandbox: every call that names a path is refused before it is
    // decoded (the `path` column of the rights table, sysrights.rs).
    let sandboxed = p.no_files && super::sysrights::is_path_call(frame.rax);
    // The rights gate: every handle argument exists, has the right kind and the
    // rights from the table – before the call is decoded.
    let gate = if sandboxed { Ok(()) } else { super::sysrights::check(p, frame) };
    let result: SysResult = match frame.rax {
        _ if sandboxed => {
            SANDBOX_DENIED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Err(ERROR_ACCESS_DENIED)
        }
        _ if gate.is_err() => gate.map(|_| 0),
        SYS_EXIT => {
            record_exit(ExitKind::Exit(a0 as i64), frame.rip, frame.rax, frame.rbx);
            exit_current();
        }
        SYS_WRITE => sys_write(p, a0, a1, a2),
        SYS_READ => sys_read(p, a0, a1, a2),
        SYS_OPEN => sys_open(p, a0, a1, a2),
        SYS_CLOSE => sys_close(p, a0),
        SYS_GETPID => Ok(sched::current_id()),
        SYS_SLEEP => {
            crate::time::sleep_ms(a0.min(3_600_000));
            Ok(0)
        }
        SYS_YIELD => {
            sched::yield_now();
            Ok(0)
        }
        SYS_UPTIME => Ok(crate::time::uptime_ms()),
        SYS_SPAWN => sys_spawn(p, frame),
        SYS_SPAWN_EX => sys_spawn_ex(p, frame),
        SYS_WAIT => sys_wait(p, a0, a1, a2),
        SYS_GETPPID => Ok(p.ppid()),
        SYS_KILL => sys_kill(a0),
        SYS_CHDIR => sys_chdir(p, a0, a1),
        SYS_GETCWD => {
            let cwd = p.cwd.clone();
            text_to_user(p, a0, a1, &cwd)
        }
        SYS_READDIR => sys_readdir(p, frame),
        SYS_STAT => sys_stat(p, a0, a1, a2),
        SYS_MKDIR => user_path(p, a0, a1).and_then(|path| fs::mkdir(&path).map(|_| 0).map_err(fs_error)),
        SYS_UNLINK => user_path(p, a0, a1).and_then(|path| fs::remove(&path).map(|_| 0).map_err(fs_error)),
        SYS_READKEY => sys_readkey(p, a0, a1),
        SYS_TASKS => sys_tasks(p, a0, a1),
        SYS_SYSINFO => sys_sysinfo(p, a0, a1, a2, frame.r10),
        SYS_SYSCTL => sys_sysctl(p, a0, a1, a2, frame.r10),
        SYS_DUP => sys_dup(p, a0),
        SYS_DUP2 => sys_dup2(p, a0, a1),
        SYS_SEEK => sys_seek(p, a0, a1, a2),
        SYS_PIPE => sys_pipe(p, a0),
        SYS_HANDLE_DUP => sys_handle_dup(p, a0, a1),
        SYS_HANDLE_INFO => sys_handle_info(p, a0),
        SYS_CHANNEL_CREATE => sys_channel_create(p, a0),
        SYS_CHAN_SEND => sys_chan_send(p, frame),
        SYS_CHAN_RECV => sys_chan_recv(p, frame),
        SYS_WAIT_MANY => sys_wait_many(p, a0, a1, a2),
        SYS_DEV_CLAIM => sys_dev_claim(p, a0, a1),
        SYS_DEV_INFO => sys_dev_info(p, a0, a1),
        SYS_DEV_FIND => sys_dev_find(p, a0, a1, a2),
        SYS_INPUT_INJECT => sys_input_inject(p, a0, a1, a2),
        SYS_BLK_ATTACH => sys_blk_attach(p, a0, a1, a2, frame.r10),
        SYS_DEV_MAP => sys_dev_map(p, a0, a1, a2),
        SYS_IRQ_BIND => dev_obj(p, a0)
            .and_then(super::device::IrqObj::bind)
            .and_then(|q| install_fd(p, 0, Fd::Irq(Arc::new(q)))),
        SYS_IRQ_READ => irq_obj(p, a0).map(|q| q.take()),
        SYS_DMA_ALLOC => dev_obj(p, a0)
            .and_then(|d| d.dma_alloc(a1, a2))
            .and_then(|b| install_fd(p, 0, Fd::Shm(b))),
        SYS_DMA_PHYS => shm_obj(p, a0).and_then(|o| o.dma_phys().ok_or(ERROR_INVALID_ARGUMENT)),
        SYS_SHM_CREATE => sys_shm_create(p, a0),
        SYS_SHM_MAP => sys_shm_map(p, a0, a1),
        SYS_SHM_SIZE => shm_obj(p, a0).map(|o| o.len()),
        SYS_BRK => {
            super::vm::count_call();
            Ok(p.mem.set_brk(&mut p.space, a0))
        }
        SYS_MMAP => {
            super::vm::count_call();
            p.mem.mmap(a0, a1)
        }
        SYS_MUNMAP => p.mem.munmap(&mut p.space, a0, a1).map(|_| 0),
        _ => Err(ERROR_NOT_IMPLEMENTED),
    };
    // DCP audit: refusals (sandbox, a handle without the right, ERROR_ACCESS_DENIED).
    if let Err(e) = result {
        if sandboxed || e == ERROR_ACCESS_DENIED {
            audit_refusal(p, frame, sandboxed);
        }
    }
    frame.rax = match result {
        Ok(v) => v,
        Err(e) => e as u64,
    };
    p.syscalls += 1;

    // kill / Ctrl+C during a syscall (e.g. waiting for the keyboard).
    if sched::should_exit() {
        record_exit(ExitKind::Killed, frame.rip, frame.rax, frame.rbx);
        exit_current();
    }
    // SYSRET with a non-canonical RIP = #GP in ring 0 on the user stack.
    if frame.rip >= USER_SPACE_END {
        record_exit(ExitKind::BadReturn, frame.rip, frame.rax, frame.rbx);
        exit_current();
    }
    // Only arithmetic flags and DF go back to the process; IF is always 1.
    frame.rflags = (frame.rflags & 0xED5) | 0x202;
    interrupts::disable();
    if nr < super::prof::SYSCALLS {
        super::prof::stop(nr, t0);
    }
    // SYSRET to the process – leaving the kernel (without the BKL if it was taken;
    // paths without the BKL do not hold it).
    if crate::sched::bkl::held() {
        crate::sched::bkl::release();
    }
}
