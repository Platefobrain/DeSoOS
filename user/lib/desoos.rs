// Small library for DeSoOS user programs (the libc counterpart).
//
// A program pulls it in with:
//     #[path = "../lib/desoos.rs"]
//     #[macro_use]
//     mod desoos;
//     desoos::entry!(main);
//     fn main(args: desoos::Args) -> i32 { println!("..."); 0 }
//
// _start (the kernel jumps here with RSP pointing at argc, argv[], NULL, envp
// NULL, auxv AT_NULL – the SysV layout) -> main(args) -> exit(code).
// Syscalls: numbers from kernel/user/syscalls.rs (table in ARCHITECTURE.md).
//
// Processes (spawn/wait/kill), directories, keys for the line editor
// and a heap: a program that wants Vec/String writes at its crate root
// `extern crate alloc;` – the allocator (below) gets memory via brk / mmap.

#![allow(dead_code)]

use core::arch::{asm, global_asm};

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
pub const SYS_HANDLE_DUP: u64 = 29;
pub const SYS_HANDLE_INFO: u64 = 30;
pub const SYS_CHANNEL_CREATE: u64 = 31;
pub const SYS_CHAN_SEND: u64 = 32;
pub const SYS_CHAN_RECV: u64 = 33;
pub const SYS_SHM_CREATE: u64 = 34;
pub const SYS_SHM_MAP: u64 = 35;
pub const SYS_SPAWN_EX: u64 = 36;
pub const SYS_SHM_SIZE: u64 = 37;
pub const SYS_WAIT_MANY: u64 = 38;
pub const SYS_DEV_CLAIM: u64 = 39;
pub const SYS_DEV_INFO: u64 = 40;
pub const SYS_DEV_MAP: u64 = 41;
pub const SYS_IRQ_BIND: u64 = 42;
pub const SYS_IRQ_READ: u64 = 43;
pub const SYS_DMA_ALLOC: u64 = 44;
pub const SYS_DMA_PHYS: u64 = 45;
pub const SYS_SYSINFO: u64 = 46;
pub const SYS_SYSCTL: u64 = 47;
/// dev_find(hw_root, class, nr) – a PCI device by class.
pub const SYS_DEV_FIND: u64 = 48;
/// input_inject(INPUT, events, n) – keyboard / mouse from usbd.
pub const SYS_INPUT_INJECT: u64 = 49;
/// blk_attach(BLK, channel, buffer, info) – usbd registers a USB stick.
pub const SYS_BLK_ATTACH: u64 = 50;

/// wait_many signals.
pub const W_READABLE: u64 = 1;
pub const W_WRITABLE: u64 = 2;
pub const W_IRQ: u64 = 4;
/// Maximum number of entries in wait_many; no timeout.
pub const WAIT_MAX: usize = 16;
pub const FOREVER: u64 = u64::MAX;
/// Maximum number of handles in a message.
pub const MSG_HANDLES: usize = 8;
/// Do not wait for space / a message (EAGAIN).
pub const CHAN_NONBLOCK: u64 = 1;
/// Largest message (bytes).
pub const MSG_MAX: usize = 4096;
pub const EAGAIN: i64 = -11;
pub const EPIPE: i64 = -32;
pub const EMSGSIZE: i64 = -90;

/// Handle rights (bits) – rights can only be reduced (`handle_dup`).
pub const R_READ: u64 = 1;
pub const R_WRITE: u64 = 2;
pub const R_SEND: u64 = 4;
pub const R_RECV: u64 = 8;
pub const R_MAP_READ: u64 = 16;
pub const R_MAP_WRITE: u64 = 32;
pub const R_DUP: u64 = 64;
pub const R_TRANSFER: u64 = 128;
pub const R_ALL: u64 = 0xFF;

/// Object kind returned by `handle_info`.
pub const KIND_CONSOLE: u64 = 1;
pub const KIND_FILE: u64 = 2;
pub const KIND_PIPE: u64 = 3;
pub const KIND_CHANNEL: u64 = 4;
pub const KIND_SHM: u64 = 5;
/// Hardware access (init only, slot 3) and a claimed PCI device.
pub const KIND_HW_ROOT: u64 = 6;
pub const KIND_DEVICE: u64 = 7;
pub const KIND_IRQ: u64 = 8;
/// Right to perform system actions (reboot, halt, sync, stress) – init slot 4,
/// the shell started by init also gets slot 4 (it does not pass it on to programs).
pub const KIND_SYSCTL: u64 = 9;
/// INPUT handle (kernel -> init slot 5 -> usbd slot 5).
pub const KIND_INPUT: u64 = 10;
pub const INPUT: u64 = 5;
/// BLK handle (USB disk registration) – held by init and usbd in slot 6.
pub const KIND_BLK: u64 = 11;
pub const BLK: u64 = 6;
pub const ETIMEDOUT: i64 = -110;
pub const HW_ROOT: u64 = 3;
pub const SYSCTL: u64 = 4;
pub const SYSCTL_REBOOT: u64 = 1;
pub const SYSCTL_HALT: u64 = 2;
pub const SYSCTL_SYNC: u64 = 3;
pub const SYSCTL_STRESS: u64 = 4;
/// dev_claim errors.
pub const EBUSY: i64 = -16;
pub const ENODEV: i64 = -19;

/// mmap: region protection.
pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;

/// seek: from the start / from the current position / from the end.
pub const SEEK_SET: u64 = 0;
pub const SEEK_CUR: u64 = 1;
pub const SEEK_END: u64 = 2;

/// spawn: Ctrl+C terminates the child (foreground process).
pub const SPAWN_FOREGROUND: u64 = 1;
/// spawn: the child gets the parent's 0, 1, 2.
pub const STDIO: u64 = fds(0, 1, 2);
/// wait: any child / do not wait.
pub const WAIT_ANY: u64 = u64::MAX;
pub const WNOHANG: u64 = 1;
/// Status from wait: terminated by the kernel (kill, exception) + reason in bits 0..7.
pub const STATUS_SIGNALED: u64 = 0x100;

pub const ENOENT: i64 = -2;
pub const EBADF: i64 = -9;
pub const ECHILD: i64 = -10;
pub const ERANGE: i64 = -34;
pub const ENOMEM: i64 = -12;
pub const ENOSPC: i64 = -28;

/// Parent descriptors the child will get as 0, 1, 2.
pub const fn fds(stdin: u64, stdout: u64, stderr: u64) -> u64 {
    stdin | (stdout << 16) | (stderr << 32)
}

pub const O_READ: u64 = 1;
pub const O_WRITE: u64 = 2;
pub const O_CREATE: u64 = 4;
pub const O_TRUNC: u64 = 8;
pub const O_APPEND: u64 = 16;

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

pub fn write(fd: u64, data: &[u8]) -> i64 {
    syscall3(SYS_WRITE, fd, data.as_ptr() as u64, data.len() as u64)
}

pub fn read(fd: u64, buf: &mut [u8]) -> i64 {
    syscall3(SYS_READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64)
}

pub fn open(path: &str, flags: u64) -> i64 {
    syscall3(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, flags)
}

pub fn close(fd: u64) -> i64 {
    syscall3(SYS_CLOSE, fd, 0, 0)
}

/// New descriptor for the same object (shared position).
pub fn dup(fd: u64) -> i64 {
    syscall3(SYS_DUP, fd, 0, 0)
}

/// New handle for the same object with rights `old & mask` (requires R_DUP).
pub fn handle_dup(h: u64, mask: u64) -> i64 {
    syscall3(SYS_HANDLE_DUP, h, mask, 0)
}

/// (kind, rights) of a handle.
pub fn handle_info(h: u64) -> Result<(u64, u64), i64> {
    let r = syscall3(SYS_HANDLE_INFO, h, 0, 0);
    if r < 0 { Err(r) } else { Ok(((r as u64) >> 32, (r as u64) & 0xFFFF_FFFF)) }
}

/// Channel – (end 0, end 1); messages flow both ways.
pub fn channel_create() -> Result<(u64, u64), i64> {
    let mut out = [0u64; 2];
    let r = syscall3(SYS_CHANNEL_CREATE, out.as_mut_ptr() as u64, 0, 0);
    if r < 0 { Err(r) } else { Ok((out[0], out[1])) }
}

/// Sends a message (up to MSG_MAX bytes); flags: 0 or CHAN_NONBLOCK.
pub fn chan_send(h: u64, data: &[u8], flags: u64) -> i64 {
    syscall6(SYS_CHAN_SEND, h, data.as_ptr() as u64, data.len() as u64, 0, 0, flags)
}

/// Sends a message with handles – the handles are MOVED (they disappear from
/// the sender, require R_TRANSFER); on error they stay with the sender.
pub fn chan_send_h(h: u64, data: &[u8], handles: &[u64], flags: u64) -> i64 {
    syscall6(SYS_CHAN_SEND, h, data.as_ptr() as u64, data.len() as u64, handles.as_ptr() as u64, handles.len() as u64, flags)
}

/// Receive result – length, number of handles, sender (pid filled in by the kernel).
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct RecvInfo {
    pub len: u64,
    pub handles: u64,
    pub sender: u64,
}

/// Receives a message into `buf`.  Err(EMSGSIZE) – buffer too small, `info` holds
/// the required size, the message stays in the queue.
pub fn chan_recv(h: u64, buf: &mut [u8], flags: u64, info: &mut RecvInfo) -> i64 {
    let mut raw = [0u64; 3];
    let r = syscall6(SYS_CHAN_RECV, h, buf.as_mut_ptr() as u64, buf.len() as u64, 0, flags << 32, raw.as_mut_ptr() as u64);
    *info = RecvInfo { len: raw[0], handles: raw[1], sender: raw[2] };
    r
}

/// Receives a message with handles – numbers of the new handles go to `handles`
/// (info.handles of them).  EMSGSIZE – `buf` or `handles` too small; EMFILE –
/// no room in the handle table; in both cases the message stays queued.
pub fn chan_recv_h(h: u64, buf: &mut [u8], handles: &mut [u64], flags: u64, info: &mut RecvInfo) -> i64 {
    let mut raw = [0u64; 3];
    let hcap = handles.len().min(MSG_HANDLES) as u64;
    let r = syscall6(SYS_CHAN_RECV, h, buf.as_mut_ptr() as u64, buf.len() as u64, handles.as_mut_ptr() as u64, hcap | flags << 32, raw.as_mut_ptr() as u64);
    *info = RecvInfo { len: raw[0], handles: raw[1], sender: raw[2] };
    r
}

/// Starts a program; the child gets ONLY the handles from `map`
/// [(parent handle, number in child)] – copies with the same rights (R_DUP).
pub fn spawn_ex(path: &str, args: &[&str], map: &[(u64, u64)], flags: u64) -> i64 {
    let mut buf = [0u8; 4096];
    let mut n = 0;
    for a in args {
        let b = a.as_bytes();
        if n + b.len() + 1 > buf.len() {
            return -7; // E2BIG
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

/// Shared memory object (`size` bytes, rounded up to 4 KiB,
/// zeroed) – a handle or -errno.
pub fn shm_create(size: u64) -> i64 {
    syscall3(SYS_SHM_CREATE, size, 0, 0)
}

/// Maps the whole object (PROT_READ, PROT_READ | PROT_WRITE) – returns the address.
/// Unmap with munmap(address, shm_size(h)).  The memory is never executable.
pub fn shm_map(h: u64, prot: u64) -> Result<u64, i64> {
    let r = syscall3(SYS_SHM_MAP, h, prot, 0);
    if r < 0 { Err(r) } else { Ok(r as u64) }
}

/// Size of a shared memory object in bytes.
pub fn shm_size(h: u64) -> i64 {
    syscall3(SYS_SHM_SIZE, h, 0, 0)
}

/// Waits until one of the handles in the list [(handle, signals)] is ready
/// (W_READABLE: recv / read will not block; W_WRITABLE: send / write).
/// Ok(mask) – bit i = entry i is ready; Ok(0) – `timeout_ms` elapsed
/// (FOREVER = no limit, 0 = just check).
pub fn wait_many(list: &[(u64, u64)], timeout_ms: u64) -> Result<u64, i64> {
    let mut flat = [0u64; 2 * WAIT_MAX];
    if list.len() > WAIT_MAX {
        return Err(-22);
    }
    for (i, &(h, sig)) in list.iter().enumerate() {
        flat[2 * i] = h;
        flat[2 * i + 1] = sig;
    }
    let r = syscall3(SYS_WAIT_MANY, flat.as_ptr() as u64, list.len() as u64, timeout_ms);
    if r < 0 { Err(r) } else { Ok(r as u64) }
}

/// PCI address of a device (bus, device, function) for dev_claim.
pub const fn bdf(bus: u64, dev: u64, func: u64) -> u64 {
    bus << 8 | dev << 3 | func
}

/// Claims a PCI device (via the HW_ROOT handle) – a DEVICE handle or
/// -errno (EACCES: in-kernel driver / disk / graphics / bridge; EBUSY: owned by
/// another service; ENODEV: no such device).
pub fn dev_claim(root: u64, bdf: u64) -> i64 {
    syscall3(SYS_DEV_CLAIM, root, bdf, 0)
}

/// PCI class of an xHCI controller (USB 3): 0C (serial bus), 03 (USB), 30 (xHCI).
pub const CLASS_XHCI: u64 = 0x0C_03_30;

/// Address (bdf) of the `nr`-th PCI device of class `class` (24 bits:
/// class << 16 | subclass << 8 | prog_if) – HW_ROOT only.  ENOENT: no
/// more devices; EBADF: the handle is not HW_ROOT.  Does not claim the device.
pub fn dev_find(root: u64, class: u64, nr: u64) -> i64 {
    syscall3(SYS_DEV_FIND, root, class, nr)
}

/// Event for input_inject (8 B): kind 1 = key (pressed,
/// HID usage), 2 = mouse (wheel, buttons).
pub fn key_event(usage: u8, pressed: bool) -> [u8; 8] {
    [1, pressed as u8, usage, 0, 0, 0, 0, 0]
}

pub fn mouse_event(buttons: u8, wheel: i8) -> [u8; 8] {
    [2, wheel as u8, buttons, 0, 0, 0, 0, 0]
}

/// Events for the kernel input subsystem (≤ 64) – LED state (bit 0
/// Num, 1 Caps, 2 Scroll) or -errno (EBADF / EACCES / EINVAL).
pub fn input_inject(h: u64, events: &[[u8; 8]]) -> i64 {
    syscall3(SYS_INPUT_INJECT, h, events.as_ptr() as u64, events.len() as u64)
}

/// Disk description for blk_attach (64 B).
pub struct BlkInfo {
    pub blocks: u64,
    pub block_size: u32,
    /// Number of 64 KiB slots in the buffer (1..8).
    pub slots: u32,
    /// 0 = default (5 s).
    pub timeout_ms: u32,
    pub desc: [u8; 40],
}

/// Registers a USB disk (read-only) – number (0 = sda) or -errno.
/// The kernel sends 32 B requests over the channel (id, op 1 = READ, lba u64, blocks u32,
/// slot u32), reply ≥ 12 B (id, status, blocks); data goes into the buffer slot.
pub fn blk_attach(h: u64, chan: u64, buf: u64, info: &BlkInfo) -> i64 {
    let mut raw = [0u8; 64];
    raw[0..8].copy_from_slice(&info.blocks.to_le_bytes());
    raw[8..12].copy_from_slice(&info.block_size.to_le_bytes());
    raw[12..16].copy_from_slice(&info.slots.to_le_bytes());
    raw[16..20].copy_from_slice(&info.timeout_ms.to_le_bytes());
    raw[24..64].copy_from_slice(&info.desc);
    syscall6(SYS_BLK_ATTACH, h, chan, buf, raw.as_ptr() as u64, 0, 0)
}

/// Kernel name of a USB disk: 0 -> sda, 26 -> sdaa.
pub fn disk_name(mut n: u64, out: &mut [u8; 8]) -> &str {
    let mut tmp = [0u8; 6];
    let mut k = 0;
    loop {
        tmp[k] = b'a' + (n % 26) as u8;
        k += 1;
        if n < 26 || k == tmp.len() {
            break;
        }
        n = n / 26 - 1;
    }
    out[0] = b's';
    out[1] = b'd';
    for i in 0..k {
        out[2 + i] = tmp[k - 1 - i];
    }
    core::str::from_utf8(&out[..2 + k]).unwrap_or("sd?")
}

/// Description of a claimed device.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DevInfo {
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    /// BAR sizes (0 = none); I/O BARs are flagged in `io_mask`.
    pub bars: [u64; 6],
    pub io_mask: u8,
    pub msi: bool,
    pub msix: bool,
}

pub fn dev_info(h: u64) -> Result<DevInfo, i64> {
    let mut v = [0u64; 10];
    let r = syscall3(SYS_DEV_INFO, h, v.as_mut_ptr() as u64, 0);
    if r < 0 {
        return Err(r);
    }
    let mut bars = [0u64; 6];
    bars.copy_from_slice(&v[2..8]);
    Ok(DevInfo {
        vendor: v[0] as u16,
        device: (v[0] >> 16) as u16,
        class: (v[1] >> 16) as u8,
        subclass: (v[1] >> 8) as u8,
        prog_if: v[1] as u8,
        bars,
        io_mask: v[8] as u8,
        msi: v[9] & 1 != 0,
        msix: v[9] & 2 != 0,
    })
}

/// Maps a BAR's registers (PROT_READ or PROT_READ | PROT_WRITE) – uncached,
/// never executable.  Unmap with munmap(address, BAR size).
pub fn dev_map(h: u64, bar: u64, prot: u64) -> Result<u64, i64> {
    let r = syscall3(SYS_DEV_MAP, h, bar, prot);
    if r < 0 { Err(r) } else { Ok(r as u64) }
}

/// Binds the device interrupt (requires R_MAP_WRITE) – an IRQ handle.
/// Wait with wait_many and W_IRQ; read the counter with irq_read.
pub fn irq_bind(dev: u64) -> i64 {
    syscall3(SYS_IRQ_BIND, dev, 0, 0)
}

/// Interrupts since the last read (resets the counter).
pub fn irq_read(irq: u64) -> i64 {
    syscall3(SYS_IRQ_READ, irq, 0, 0)
}

/// DMA buffer for a device – a shared memory handle (map it with
/// shm_map) made of contiguous frames below 2^bits (the device's address bus).  The buffer
/// lives as long as the device claim (closing the handle does not free it).
pub fn dma_alloc(dev: u64, size: u64, bits: u64) -> i64 {
    syscall3(SYS_DMA_ALLOC, dev, size, bits)
}

/// Physical address of a DMA buffer (to program into the device).
pub fn dma_phys(buf: u64) -> Result<u64, i64> {
    let r = syscall3(SYS_DMA_PHYS, buf, 0, 0);
    if r < 0 { Err(r) } else { Ok(r as u64) }
}

/// Channel to the service manager (init) – programs started from the shell have
/// it in slot 3 (send only).  Init has HW_ROOT in slot 3.
pub const SVC: u64 = 3;

/// Connects to a service by name (e.g. "edu") – returns a channel end for
/// talking to the service.  Unknown / not running service: the channel is closed by
/// init, the first operation on it gives EPIPE.
pub fn svc_connect(name: &str) -> Result<u64, i64> {
    let mut msg = [0u8; 64];
    let p = b"connect ";
    if p.len() + name.len() > msg.len() {
        return Err(-22);
    }
    msg[..p.len()].copy_from_slice(p);
    msg[p.len()..p.len() + name.len()].copy_from_slice(name.as_bytes());
    let (mine, theirs) = channel_create()?;
    let r = chan_send_h(SVC, &msg[..p.len() + name.len()], &[theirs], 0);
    if r != 0 {
        close(mine);
        close(theirs);
        return Err(r);
    }
    Ok(mine)
}

/// Service list from init (lines "name state pid N restarts N (program)")
/// into `buf`; returns the length.
pub fn svc_list(buf: &mut [u8]) -> Result<usize, i64> {
    let (mine, theirs) = channel_create()?;
    let r = chan_send_h(SVC, b"list", &[theirs], 0);
    if r != 0 {
        close(mine);
        close(theirs);
        return Err(r);
    }
    let mut msg = [0u8; MSG_MAX];
    let mut info = RecvInfo::default();
    let r = chan_recv(mine, &mut msg, 0, &mut info);
    close(mine);
    if r < 0 {
        return Err(r);
    }
    let n = (r as usize).min(buf.len());
    buf[..n].copy_from_slice(&msg[..n]);
    Ok(n)
}

/// `new` refers to the object of `old` (the previous `new` is closed).
pub fn dup2(old: u64, new: u64) -> i64 {
    syscall3(SYS_DUP2, old, new, 0)
}

/// Pipe – (read fd, write fd).
pub fn pipe() -> Result<(u64, u64), i64> {
    let mut out = [0u64; 2];
    let r = syscall3(SYS_PIPE, out.as_mut_ptr() as u64, 0, 0);
    if r < 0 { Err(r) } else { Ok((out[0], out[1])) }
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

/// New position (SEEK_SET / SEEK_CUR / SEEK_END); result – the position.
pub fn seek(fd: u64, offset: i64, whence: u64) -> i64 {
    syscall3(SYS_SEEK, fd, offset as u64, whence)
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
            return -7; // E2BIG
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

pub fn chdir(path: &str) -> i64 {
    syscall3(SYS_CHDIR, path.as_ptr() as u64, path.len() as u64, 0)
}

/// Current directory into `buf`; returns it as &str.
pub fn getcwd(buf: &mut [u8]) -> &str {
    let n = syscall3(SYS_GETCWD, buf.as_mut_ptr() as u64, buf.len() as u64, 0);
    if n <= 0 {
        return "/";
    }
    core::str::from_utf8(&buf[..n as usize]).unwrap_or("/")
}

/// Directory contents: lines "d|f\t<size>\t<name>\n".  ERANGE = buffer too small.
pub fn readdir(path: &str, buf: &mut [u8]) -> i64 {
    syscall6(SYS_READDIR, path.as_ptr() as u64, path.len() as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0)
}

#[derive(Clone, Copy)]
pub struct Stat {
    pub is_dir: bool,
    pub size: u64,
}

pub fn stat(path: &str) -> Result<Stat, i64> {
    let mut out = [0u64; 2];
    let r = syscall3(SYS_STAT, path.as_ptr() as u64, path.len() as u64, out.as_mut_ptr() as u64);
    if r < 0 { Err(r) } else { Ok(Stat { is_dir: out[0] == 1, size: out[1] }) }
}

pub fn mkdir(path: &str) -> i64 {
    syscall3(SYS_MKDIR, path.as_ptr() as u64, path.len() as u64, 0)
}

pub fn unlink(path: &str) -> i64 {
    syscall3(SYS_UNLINK, path.as_ptr() as u64, path.len() as u64, 0)
}

/// Task list: lines "pid\tppid\tstate\tms\tswitches\ttype\tname\n".
pub fn tasks(buf: &mut [u8]) -> i64 {
    syscall3(SYS_TASKS, buf.as_mut_ptr() as u64, buf.len() as u64, 0)
}

/// Read-only text from the kernel ("mem", "lspci -v", "cpus", "disk"...)
/// into `buf`.  Err(ENOENT) – unknown topic; Err(ERANGE) – buffer too small.
pub fn sysinfo(topic: &str, buf: &mut [u8]) -> Result<usize, i64> {
    let r = syscall6(SYS_SYSINFO, topic.as_ptr() as u64, topic.len() as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0);
    if r < 0 { Err(r) } else { Ok(r as usize) }
}

/// System action via the SYSCTL handle (`h`); the result is written as text to `fd`.
pub fn sysctl(h: u64, op: u64, arg: u64, fd: u64) -> i64 {
    syscall6(SYS_SYSCTL, h, op, arg, fd, 0, 0)
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

/// Description of an error code (-errno).
pub fn strerror(e: i64) -> &'static str {
    match e {
        -1 => "operation not permitted",
        -2 => "no such file or directory",
        -3 => "no such process",
        -7 => "argument list too long",
        -8 => "not an executable (bad ELF file)",
        -10 => "no child processes",
        -12 => "out of memory",
        -4 => "interrupted",
        -5 => "I/O error",
        -9 => "bad file descriptor",
        -13 => "permission denied",
        -14 => "bad address",
        -17 => "already exists",
        -20 => "not a directory",
        -21 => "is a directory",
        -22 => "invalid argument",
        -24 => "too many open files",
        -28 => "no space left",
        -29 => "illegal seek",
        -32 => "broken pipe",
        -30 => "read-only file system",
        -34 => "buffer too small",
        -11 => "try again (would block)",
        -90 => "message too long",
        -16 => "device or resource busy",
        -19 => "no such device",
        -38 => "unknown syscall",
        -39 => "directory not empty",
        _ => "error",
    }
}

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
        let _ = core::fmt::Write::write_fmt(&mut $crate::desoos::Out::new(1), format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {{
        let mut o = $crate::desoos::Out::new(1);
        let _ = core::fmt::Write::write_fmt(&mut o, format_args!($($arg)*));
        let _ = core::fmt::Write::write_str(&mut o, "\n");
    }};
}

#[macro_export]
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        let mut o = $crate::desoos::Out::new(2);
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
}

global_asm!(r#"
    .section .text._start, "ax"
    .global _start
    _start:
        xor ebp, ebp
        mov rdi, rsp
        and rsp, -16
        call desoos_start
        ud2
"#);

unsafe extern "Rust" {
    fn desoos_main(args: Args) -> i32;
}

#[unsafe(no_mangle)]
extern "sysv64" fn desoos_start(sp: *const u64) -> ! {
    let args = unsafe { Args { argc: *sp as usize, argv: sp.add(1) as *const *const u8 } };
    let code = unsafe { desoos_main(args) };
    exit(code)
}

/// Connects the program's `fn main(args: Args) -> i32` to _start.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[unsafe(no_mangle)]
        pub fn desoos_main(args: $crate::desoos::Args) -> i32 {
            $main(args)
        }
    };
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let _ = core::fmt::Write::write_fmt(&mut Out::new(2), format_args!("panic: {}\n", info));
    exit(101)
}
