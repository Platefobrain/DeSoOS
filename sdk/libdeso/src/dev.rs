// libdeso::dev – Devices: PCI claims, registers, interrupts, DMA, input, USB disks (services that hold the right handles).

#[allow(unused_imports)]
use crate::*;

/// PCI address of a device (bus, device, function) for dev_claim.
pub const fn bdf(bus: u64, dev: u64, func: u64) -> u64 {
    bus << 8 | dev << 3 | func
}

/// Claims a PCI device (via the HW_ROOT handle) – a DEVICE handle or
/// -errno (ERROR_ACCESS_DENIED: in-kernel driver / disk / graphics / bridge; ERROR_BUSY: owned by
/// another service; ERROR_NO_DEVICE: no such device).
pub fn dev_claim(root: u64, bdf: u64) -> i64 {
    syscall3(SYS_DEV_CLAIM, root, bdf, 0)
}

/// Address (bdf) of the `nr`-th PCI device of class `class` (24 bits:
/// class << 16 | subclass << 8 | prog_if) – HW_ROOT only.  ERROR_NOT_FOUND: no
/// more devices; ERROR_INVALID_HANDLE: the handle is not HW_ROOT.  Does not claim the device.
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
/// Num, 1 Caps, 2 Scroll) or -errno (ERROR_INVALID_HANDLE / ERROR_ACCESS_DENIED / ERROR_INVALID_ARGUMENT).
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
    /// Write protection (MODE SENSE): 0 unknown, 1 off, 2 on.  Only 1 lets the kernel
    /// ever write a partition of the disk.
    pub wp: u32,
    pub desc: [u8; 40],
}

/// Registers a USB disk (read-only as a whole) – number (0 = sda) or -errno.
/// The kernel sends 48 B requests over the channel (id, op, lba u64, blocks u32, slot u32,
/// gen u64, session u64, len u64 – ops READ 1, WRITE 2, FLUSH 3, REG 4; kernel/user/ublk.rs),
/// reply ≥ 12 B (id, status, blocks); data goes through the buffer slot.
pub fn blk_attach(h: u64, chan: u64, buf: u64, info: &BlkInfo) -> i64 {
    let mut raw = [0u8; 64];
    raw[0..8].copy_from_slice(&info.blocks.to_le_bytes());
    raw[8..12].copy_from_slice(&info.block_size.to_le_bytes());
    raw[12..16].copy_from_slice(&info.slots.to_le_bytes());
    raw[16..20].copy_from_slice(&info.timeout_ms.to_le_bytes());
    raw[20..24].copy_from_slice(&info.wp.to_le_bytes());
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
