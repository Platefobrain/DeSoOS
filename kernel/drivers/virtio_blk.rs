// virtio-blk disk driver (virtio 1.0 "modern", PCI).
//
// How to talk to a virtio device:
//   * Configuration through structures in BARs, pointed to by PCI capabilities
//     of the "vendor specific" type (0x09): common cfg, notify, ISR, device cfg.
//   * Data through a "virtqueue" (split ring) in RAM:
//       - descriptor table (physical address + length + flags),
//       - "available ring": the kernel writes the numbers of chains to process,
//       - "used ring": the device writes what it has finished.
//     The device reads and writes this memory itself (DMA).
//   * After adding a request the kernel "knocks" (notify), and when done the device
//     raises an interrupt: MSI-X (vector from arch/msi.rs; works with both the PIC
//     and the I/O APIC), and if unavailable – INTx through the PIC (level-triggered –
//     cleared by reading ISR) or polling.
//
// A disk request = a chain of 3 descriptors:
//   [header: type + sector] -> [data] -> [1 status byte]
//
// Simplifications: one request at a time, max 64 KiB (128 sectors) per request –
// larger reads are split; data goes through a DMA buffer (16 contiguous
// frames from alloc_frames)
// and is copied.  We wait via hlt (woken by the disk interrupt or a timer tick).

use alloc::format;
use alloc::string::String;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, AtomicU64, Ordering};

use super::pci::{self, Bar, Device};
use crate::arch::x86_64::{interrupts, irq, msi};
use crate::block::{self, BlockDevice, BlockError, SECTOR_SIZE};
use crate::memory::{alloc_frame, alloc_frames, map_mmio, phys_to_virt};
use crate::serial_println;

pub const VENDOR_VIRTIO: u16 = 0x1AF4;
/// 0x1001 = virtio-blk "transitional" (legacy + modern), 0x1042 = modern only.
pub const DEVICE_IDS: [u16; 2] = [0x1001, 0x1042];

const CAP_VENDOR: u8 = 0x09;
const CFG_COMMON: u8 = 1;
const CFG_NOTIFY: u8 = 2;
const CFG_ISR: u8 = 3;
const CFG_DEVICE: u8 = 4;

// common cfg (offsets)
const C_DEVICE_FEATURE_SELECT: u64 = 0;
const C_DEVICE_FEATURE: u64 = 4;
const C_DRIVER_FEATURE_SELECT: u64 = 8;
const C_DRIVER_FEATURE: u64 = 12;
const C_MSIX_CONFIG: u64 = 16;
const C_DEVICE_STATUS: u64 = 20;
const C_CONFIG_GENERATION: u64 = 21;
const C_QUEUE_SELECT: u64 = 22;
const C_QUEUE_SIZE: u64 = 24;
const C_QUEUE_MSIX_VECTOR: u64 = 26;
const C_QUEUE_ENABLE: u64 = 28;
const C_QUEUE_NOTIFY_OFF: u64 = 30;
const C_QUEUE_DESC: u64 = 32;
const C_QUEUE_DRIVER: u64 = 40;
const C_QUEUE_DEVICE: u64 = 48;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 128;

const NO_VECTOR: u16 = 0xFFFF;

const F_BLK_RO: u64 = 1 << 5;
const F_BLK_FLUSH: u64 = 1 << 9;
const F_VERSION_1: u64 = 1 << 32;

const REQ_IN: u32 = 0; // read
const REQ_OUT: u32 = 1; // write
const REQ_FLUSH: u32 = 4;

const DESC_NEXT: u16 = 1;
const DESC_WRITE: u16 = 2; // the device writes to the buffer

const QUEUE_SIZE_MAX: u16 = 64;
const PAGE: usize = 4096;
const DATA_FRAMES: usize = 16;
const DATA_BUFFER: usize = DATA_FRAMES * PAGE; // 64 KiB, physically contiguous
const SECTORS_PER_REQUEST: usize = DATA_BUFFER / SECTOR_SIZE;
const REQUEST_TIMEOUT_MS: u64 = 2000;

// Layout of the "req" frame: request header at 0, status byte at 64.
const STATUS_OFFSET: u64 = 64;

static IRQS: AtomicU64 = AtomicU64::new(0);
static REQUESTS: AtomicU64 = AtomicU64::new(0);
/// A task waiting for a request to complete sleeps here (woken by the IRQ).
static BLK_WAIT: crate::sched::sync::WaitQueue = crate::sched::sync::WaitQueue::new();
static ISR_ADDRESS: AtomicU64 = AtomicU64::new(0);

fn mmio_r8(a: u64) -> u8 {
    unsafe { read_volatile(a as *const u8) }
}
fn mmio_r16(a: u64) -> u16 {
    unsafe { read_volatile(a as *const u16) }
}
fn mmio_r32(a: u64) -> u32 {
    unsafe { read_volatile(a as *const u32) }
}
fn mmio_w8(a: u64, v: u8) {
    unsafe { write_volatile(a as *mut u8, v) }
}
fn mmio_w16(a: u64, v: u16) {
    unsafe { write_volatile(a as *mut u16, v) }
}
fn mmio_w32(a: u64, v: u32) {
    unsafe { write_volatile(a as *mut u32, v) }
}
fn mmio_w64(a: u64, v: u64) {
    mmio_w32(a, v as u32);
    mmio_w32(a + 4, (v >> 32) as u32);
}

pub struct VirtioBlk {
    name: String,
    pci: pci::Address,
    common: u64,
    notify: u64,
    device_cfg: u64,
    capacity: u64,
    read_only: bool,
    has_flush: bool,
    irq: Irq,
    queue_size: u16,
    desc: u64,
    avail: u64,
    used: u64,
    avail_idx: u16,
    last_used: u16,
    req_frame: u64,
    data_frame: u64,
}

/// How the device signals request completion.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Irq {
    None,
    Intx(u8),
    Msix(u8),
}

fn on_msi(_vector: u8) {
    IRQS.fetch_add(1, Ordering::Relaxed);
    BLK_WAIT.wake_all();
}

/// Configuration structures found (virtual addresses = physical).
struct Caps {
    common: u64,
    /// Physical address of the notify structure (the queue "knock" address is computed
    /// from it and mapped separately).
    notify_phys: u64,
    notify_multiplier: u32,
    isr: u64,
    device: u64,
}

fn read_caps(dev: &Device) -> Result<Caps, &'static str> {
    let mut common = None;
    let mut notify = None;
    let mut isr = None;
    let mut device = None;
    let mut multiplier = 0;
    let mut notify_phys = 0;

    for (off, id) in dev.capabilities() {
        if id != CAP_VENDOR {
            continue;
        }
        let a = dev.address;
        let cfg_type = pci::read8(a, off + 3);
        let bar = pci::read8(a, off + 4) as usize;
        let offset = pci::read32(a, off + 8) as u64;
        let length = pci::read32(a, off + 12) as u64;
        if bar >= 6 {
            continue;
        }
        let Bar::Memory { base, size, .. } = dev.bars[bar] else {
            continue; // structures in an IO BAR are skipped
        };
        if base == 0 || offset + length > size {
            continue;
        }
        let addr = base + offset;
        let slot = match cfg_type {
            CFG_COMMON => &mut common,
            CFG_NOTIFY => {
                multiplier = pci::read32(a, off + 16);
                &mut notify
            }
            CFG_ISR => &mut isr,
            CFG_DEVICE => &mut device,
            _ => continue,
        };
        if slot.is_none() {
            // map_mmio returns a virtual address (direct map).
            let virt = map_mmio(addr, length.max(1)).ok_or("cannot map virtio registers")?;
            if cfg_type == CFG_NOTIFY {
                notify_phys = addr;
            }
            *slot = Some(virt);
        }
    }

    Ok(Caps {
        common: common.ok_or("no common cfg (legacy-only virtio device?)")?,
        notify_phys: notify.map(|_| notify_phys).ok_or("no notify cfg")?,
        notify_multiplier: multiplier,
        isr: isr.ok_or("no ISR cfg")?,
        device: device.ok_or("no device cfg")?,
    })
}

fn zeroed_frame() -> Option<u64> {
    let f = alloc_frame()?;
    unsafe { core::ptr::write_bytes(phys_to_virt(f) as *mut u8, 0, PAGE) };
    Some(f)
}

fn on_irq(_irq: u8) {
    let isr = ISR_ADDRESS.load(Ordering::Relaxed);
    if isr != 0 {
        // Reading ISR clears the interrupt (the level-triggered line drops).
        if mmio_r8(isr) != 0 {
            IRQS.fetch_add(1, Ordering::Relaxed);
            BLK_WAIT.wake_all();
        }
    }
}

impl VirtioBlk {
    fn status(&self) -> u8 {
        mmio_r8(self.common + C_DEVICE_STATUS)
    }

    fn set_status(&self, s: u8) {
        mmio_w8(self.common + C_DEVICE_STATUS, s);
    }

    fn fail(&self, why: &'static str) -> &'static str {
        self.set_status(self.status() | STATUS_FAILED);
        why
    }

    /// Initialization per the virtio 1.0 specification, section 3.1.
    fn new(dev: &Device, index: usize) -> Result<Self, &'static str> {
        dev.enable(true, false);
        let caps = read_caps(dev)?;

        let mut me = VirtioBlk {
            name: format!("vd{}", (b'a' + index as u8) as char),
            pci: dev.address,
            common: caps.common,
            notify: 0,
            device_cfg: caps.device,
            capacity: 0,
            read_only: false,
            has_flush: false,
            irq: Irq::None,
            queue_size: 0,
            desc: 0,
            avail: 0,
            used: 0,
            avail_idx: 0,
            last_used: 0,
            req_frame: 0,
            data_frame: 0,
        };

        // 1. Reset and wait until the device acknowledges it.
        me.set_status(0);
        let mut ok = false;
        for _ in 0..100_000 {
            if me.status() == 0 {
                ok = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !ok {
            return Err("device did not reset");
        }
        me.set_status(STATUS_ACKNOWLEDGE);
        me.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER);

        // 2. Features: we require VERSION_1, we take RO and FLUSH.
        mmio_w32(me.common + C_DEVICE_FEATURE_SELECT, 0);
        let lo = mmio_r32(me.common + C_DEVICE_FEATURE) as u64;
        mmio_w32(me.common + C_DEVICE_FEATURE_SELECT, 1);
        let hi = mmio_r32(me.common + C_DEVICE_FEATURE) as u64;
        let offered = lo | (hi << 32);
        if offered & F_VERSION_1 == 0 {
            return Err(me.fail("device does not offer VIRTIO_F_VERSION_1"));
        }
        let wanted = F_VERSION_1 | (offered & (F_BLK_RO | F_BLK_FLUSH));
        mmio_w32(me.common + C_DRIVER_FEATURE_SELECT, 0);
        mmio_w32(me.common + C_DRIVER_FEATURE, wanted as u32);
        mmio_w32(me.common + C_DRIVER_FEATURE_SELECT, 1);
        mmio_w32(me.common + C_DRIVER_FEATURE, (wanted >> 32) as u32);
        me.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
        if me.status() & STATUS_FEATURES_OK == 0 {
            return Err(me.fail("device rejected features"));
        }
        me.read_only = wanted & F_BLK_RO != 0;
        me.has_flush = wanted & F_BLK_FLUSH != 0;

        // 3. Capacity (u64 in device cfg; read consistently using config_generation).
        loop {
            let generation = mmio_r8(me.common + C_CONFIG_GENERATION);
            let lo = mmio_r32(me.device_cfg) as u64;
            let hi = mmio_r32(me.device_cfg + 4) as u64;
            if mmio_r8(me.common + C_CONFIG_GENERATION) == generation {
                me.capacity = lo | (hi << 32);
                break;
            }
        }

        // 4. Queue 0.
        mmio_w16(me.common + C_MSIX_CONFIG, NO_VECTOR);
        mmio_w16(me.common + C_QUEUE_SELECT, 0);
        let max = mmio_r16(me.common + C_QUEUE_SIZE);
        if max == 0 {
            return Err(me.fail("queue 0 not available"));
        }
        let size = max.min(QUEUE_SIZE_MAX);
        me.queue_size = size;

        let ring_frame = zeroed_frame().ok_or("out of memory")?;
        let used_frame = zeroed_frame().ok_or("out of memory")?;
        me.req_frame = zeroed_frame().ok_or("out of memory")?;
        me.data_frame = alloc_frames(DATA_FRAMES, 1).ok_or("out of memory (64 KiB DMA buffer)")?;
        me.desc = ring_frame; // 16 B * size <= 1024
        me.avail = ring_frame + 2048; // 6 + 2 * size
        me.used = used_frame; // 6 + 8 * size

        mmio_w16(me.common + C_QUEUE_SIZE, size);
        mmio_w16(me.common + C_QUEUE_MSIX_VECTOR, NO_VECTOR);
        mmio_w64(me.common + C_QUEUE_DESC, me.desc);
        mmio_w64(me.common + C_QUEUE_DRIVER, me.avail);
        mmio_w64(me.common + C_QUEUE_DEVICE, me.used);
        let notify_off = mmio_r16(me.common + C_QUEUE_NOTIFY_OFF) as u64;
        let notify_phys = caps.notify_phys + notify_off * caps.notify_multiplier as u64;
        me.notify = map_mmio(notify_phys, 2).ok_or("cannot map notify register")?;
        // 5. Interrupt.  MSI-X first (entry 0 of the MSI-X table for
        //    queue 0) – independent of the interrupt controller; the written vector
        //    is read back (the device answers NO_VECTOR if it did not
        //    accept it).  Otherwise INTx through the PIC (only without an I/O APIC – the
        //    PCI line number for the I/O APIC is in AML), otherwise polling.
        if let Some(v) = msi::alloc(on_msi) {
            if dev.enable_msix(0, v).is_ok() {
                mmio_w16(me.common + C_QUEUE_MSIX_VECTOR, 0);
                if mmio_r16(me.common + C_QUEUE_MSIX_VECTOR) == 0 {
                    me.irq = Irq::Msix(v);
                }
            }
        }
        mmio_w16(me.common + C_QUEUE_ENABLE, 1);

        let line = dev.interrupt_line;
        if me.irq == Irq::None && !irq::ioapic_mode() && dev.interrupt_pin != 0 && line != 0 && line < 16 && line != 2 {
            ISR_ADDRESS.store(caps.isr, Ordering::Relaxed);
            if irq::register(line, on_irq) {
                pci::set_level_triggered(line);
                dev.enable(true, true);
                irq::unmask(line);
                me.irq = Irq::Intx(line);
            }
        }

        // 6. Done.
        me.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
        Ok(me)
    }

    fn write_desc(&self, i: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let d = phys_to_virt(self.desc) + i as u64 * 16;
        unsafe {
            write_volatile(d as *mut u64, addr);
            write_volatile((d + 8) as *mut u32, len);
            write_volatile((d + 12) as *mut u16, flags);
            write_volatile((d + 14) as *mut u16, next);
        }
    }

    fn used_idx(&self) -> u16 {
        unsafe { read_volatile((phys_to_virt(self.used) + 2) as *const u16) }
    }

    /// Sends one request and waits for the result.  `data_len` bytes from/to data_frame.
    fn submit(&mut self, req_type: u32, sector: u64, data_len: usize) -> Result<(), BlockError> {
        REQUESTS.fetch_add(1, Ordering::Relaxed);
        let req = self.req_frame;
        let status_addr = req + STATUS_OFFSET;
        // The device gets physical addresses, the CPU writes through the direct map.
        let req_v = phys_to_virt(req);
        unsafe {
            write_volatile(req_v as *mut u32, req_type);
            write_volatile((req_v + 4) as *mut u32, 0);
            write_volatile((req_v + 8) as *mut u64, sector);
            write_volatile(phys_to_virt(status_addr) as *mut u8, 0xFF);
        }

        if data_len > 0 {
            let data_flags = if req_type == REQ_IN { DESC_NEXT | DESC_WRITE } else { DESC_NEXT };
            self.write_desc(0, req, 16, DESC_NEXT, 1);
            self.write_desc(1, self.data_frame, data_len as u32, data_flags, 2);
        } else {
            self.write_desc(0, req, 16, DESC_NEXT, 2);
        }
        self.write_desc(2, status_addr, 1, DESC_WRITE, 0);

        // Put the chain (starting at descriptor 0) into the available ring.
        let slot = self.avail_idx % self.queue_size;
        unsafe {
            write_volatile((phys_to_virt(self.avail) + 4 + slot as u64 * 2) as *mut u16, 0);
        }
        fence(Ordering::SeqCst);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        unsafe {
            write_volatile((phys_to_virt(self.avail) + 2) as *mut u16, self.avail_idx);
        }
        fence(Ordering::SeqCst);
        mmio_w16(self.notify, 0);

        // Wait until the device advances used.idx.  With an interrupt the
        // task sleeps in BLK_WAIT (CPUs get other tasks), the IRQ wakes it.
        if self.irq != Irq::None && interrupts::are_enabled() {
            let last = self.last_used;
            let used = phys_to_virt(self.used) + 2;
            let done = BLK_WAIT.wait_until(
                || unsafe { read_volatile(used as *const u16) } != last,
                Some(REQUEST_TIMEOUT_MS),
            );
            if !done {
                return Err(BlockError::Timeout);
            }
        }
        let deadline = crate::time::ticks() + REQUEST_TIMEOUT_MS;
        let mut spins: u64 = 0;
        while self.used_idx() == self.last_used {
            if interrupts::are_enabled() {
                if crate::time::ticks() > deadline {
                    return Err(BlockError::Timeout);
                }
                interrupts::disable();
                if self.used_idx() == self.last_used {
                    interrupts::enable_and_hlt();
                } else {
                    interrupts::enable();
                }
            } else {
                spins += 1;
                if spins > 50_000_000 {
                    return Err(BlockError::Timeout);
                }
                core::hint::spin_loop();
            }
        }
        fence(Ordering::SeqCst);
        self.last_used = self.last_used.wrapping_add(1);

        match unsafe { read_volatile(phys_to_virt(status_addr) as *const u8) } {
            0 => Ok(()),
            1 => Err(BlockError::Io),
            2 => Err(BlockError::Unsupported),
            _ => Err(BlockError::Io),
        }
    }

}

impl BlockDevice for VirtioBlk {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> String {
        format!(
            "virtio-blk at PCI {}, {} sectors ({} MiB){}{}",
            self.pci,
            self.capacity,
            self.capacity * SECTOR_SIZE as u64 / (1024 * 1024),
            if self.read_only { ", read-only" } else { "" },
            match self.irq {
                Irq::Intx(l) => format!(", IRQ {}", l),
                Irq::Msix(v) => format!(", MSI-X vector {:#x}", v),
                Irq::None => String::from(", polling"),
            }
        )
    }

    fn sector_count(&self) -> u64 {
        self.capacity
    }

    fn read_only(&self) -> bool {
        self.read_only
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        block::check_range(self.capacity, lba, buf.len())?;
        for (i, chunk) in buf.chunks_mut(SECTORS_PER_REQUEST * SECTOR_SIZE).enumerate() {
            let sector = lba + (i * SECTORS_PER_REQUEST) as u64;
            self.submit(REQ_IN, sector, chunk.len())?;
            unsafe {
                core::ptr::copy_nonoverlapping(phys_to_virt(self.data_frame) as *const u8, chunk.as_mut_ptr(), chunk.len());
            }
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        block::check_range(self.capacity, lba, buf.len())?;
        if self.read_only {
            return Err(BlockError::ReadOnly);
        }
        for (i, chunk) in buf.chunks(SECTORS_PER_REQUEST * SECTOR_SIZE).enumerate() {
            let sector = lba + (i * SECTORS_PER_REQUEST) as u64;
            unsafe {
                core::ptr::copy_nonoverlapping(chunk.as_ptr(), phys_to_virt(self.data_frame) as *mut u8, chunk.len());
            }
            self.submit(REQ_OUT, sector, chunk.len())?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        if !self.has_flush {
            return Ok(()); // device without a write cache
        }
        self.submit(REQ_FLUSH, 0, 0)
    }
}

/// Number of interrupts from virtio disks (for tests).
#[allow(dead_code)]
pub fn irq_count() -> u64 {
    IRQS.load(Ordering::Relaxed)
}

/// Finds virtio-blk disks and registers them in the block layer.
/// Returns the number of disks added.
pub fn init() -> usize {
    let mut added = 0;
    for dev in pci::devices() {
        if dev.vendor != VENDOR_VIRTIO || !DEVICE_IDS.contains(&dev.device) {
            continue;
        }
        if added > 0 {
            // For now one IRQ line / one ISR address – the second disk is skipped.
            serial_println!("[VIRTIO] second virtio-blk at {} ignored (one disk supported for now)", dev.address);
            continue;
        }
        match VirtioBlk::new(dev, added) {
            Ok(d) => {
                pci::set_kernel_owner(dev.address); // a service will not claim it
                serial_println!("[VIRTIO] {}: {}", d.name, d.description());
                block::register(alloc::boxed::Box::new(d));
                added += 1;
            }
            Err(e) => serial_println!("[VIRTIO] virtio-blk at {}: {}", dev.address, e),
        }
    }
    if added == 0 {
        serial_println!("[VIRTIO] no virtio-blk disk");
    }
    added
}

// ------------------------------------------------------------
// TEST (only builds with --cfg selftest)
// ------------------------------------------------------------

#[cfg(selftest)]
macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[BLK TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

#[cfg(selftest)]
pub fn self_test() {
    use alloc::vec;

    serial_println!("[BLK TEST] Starting PCI + virtio-blk tests...");
    crate::selftest::begin();

    // 1. PCI: q35 host bridge at 00:00.0, all devices with a sensible vendor.
    let devs = pci::devices();
    let host = devs.iter().find(|d| d.address == pci::Address { bus: 0, device: 0, function: 0 });
    check!(host.is_some(), "no device at 00:00.0");
    let host = host.unwrap();
    check!(host.class == 0x06 && host.subclass == 0x00, "00:00.0 is class {:02x}:{:02x}", host.class, host.subclass);
    check!(devs.iter().all(|d| d.vendor != 0xFFFF && d.vendor != 0), "bad vendor id");
    check!(devs.len() >= 3, "only {} PCI devices", devs.len());
    serial_println!("[BLK TEST] 1/8 PCI: {} devices, host bridge {:04x}:{:04x} PASS", devs.len(), host.vendor, host.device);

    // 2. Devices without a driver (and with MSI-X) have INTx disabled.
    for d in devs {
        if d.header_type & 0x7F == 0 && d.interrupt_pin != 0 {
            let ours = d.vendor == VENDOR_VIRTIO && DEVICE_IDS.contains(&d.device);
            let intx_off = d.command() & pci::CMD_INTX_DISABLE != 0;
            check!(ours || intx_off, "{} {:04x}:{:04x} still has INTx enabled", d.address, d.vendor, d.device);
        }
    }
    serial_println!("[BLK TEST] 2/8 INTx disabled on devices without a driver PASS");

    // 3. virtio disk registered.
    check!(block::count() >= 1, "no block device (run QEMU with the virtio disk - see run-qemu.sh)");
    let (sectors, name) = block::with_device(0, |d| (d.sector_count(), String::from(d.name()))).unwrap();
    check!(sectors >= 64, "capacity {} sectors", sectors);
    serial_println!("[BLK TEST] 3/8 disk {} registered, {} sectors PASS", name, sectors);

    // 4. Read: two reads of the same data = the same data; 160 sectors =
    //    80 KiB = 2 requests (64 + 16 KiB) through the contiguous DMA buffer.
    let mut a = vec![0u8; 160 * SECTOR_SIZE];
    let mut b = vec![0xAAu8; 160 * SECTOR_SIZE];
    let r0 = REQUESTS.load(Ordering::Relaxed);
    check!(block::read(0, 0, &mut a).is_ok(), "read 160 sectors @0");
    let requests = REQUESTS.load(Ordering::Relaxed) - r0;
    check!(requests == 2, "160 sectors took {} requests (expected 2)", requests);
    check!(block::read(0, 0, &mut b).is_ok(), "second read");
    check!(a == b, "two reads of the same sectors differ");
    serial_println!("[BLK TEST] 4/8 read 160 sectors (2 requests, 64 KiB DMA buffer) PASS");

    // 5. Write + verification read at the end of the disk, then restore the data.
    let lba = sectors - 20;
    let mut original = vec![0u8; 20 * SECTOR_SIZE];
    check!(block::read(0, lba, &mut original).is_ok(), "read original");
    let pattern: alloc::vec::Vec<u8> = (0..20 * SECTOR_SIZE).map(|i| (i * 7 + i / 512) as u8).collect();
    check!(block::write(0, lba, &pattern).is_ok(), "write pattern");
    check!(block::with_device(0, |d| d.flush()).unwrap().is_ok(), "flush");
    let mut back = vec![0u8; 20 * SECTOR_SIZE];
    check!(block::read(0, lba, &mut back).is_ok(), "read back");
    let same = back == pattern;
    let restored = block::write(0, lba, &original).is_ok();
    check!(same, "data read back differs from data written");
    check!(restored, "could not restore original sectors");
    let mut check_restore = vec![0u8; 20 * SECTOR_SIZE];
    check!(block::read(0, lba, &mut check_restore).is_ok() && check_restore == original, "restore mismatch");
    serial_println!("[BLK TEST] 5/8 write + flush + read-back of 20 sectors @{} (restored) PASS", lba);

    // 6. Errors: beyond the disk, wrong buffer size, no disk.
    let mut one = [0u8; SECTOR_SIZE];
    check!(block::read(0, sectors, &mut one) == Err(BlockError::OutOfRange), "read past end");
    check!(block::read(0, sectors - 1, &mut [0u8; 2 * SECTOR_SIZE]) == Err(BlockError::OutOfRange), "read across end");
    check!(block::read(0, 0, &mut [0u8; 100]) == Err(BlockError::BadBuffer), "bad buffer size");
    check!(block::read(7, 0, &mut one) == Err(BlockError::NoDevice), "missing disk");
    serial_println!("[BLK TEST] 6/8 range / buffer / device errors PASS");

    // 7. Interrupts: every request ends with an interrupt (MSI-X).
    let kind = block::with_device(0, |d| d.description()).unwrap_or_default();
    let before = irq_count();
    check!(block::read(0, 1, &mut one).is_ok(), "read for IRQ test");
    let after = irq_count();
    if kind.contains("MSI-X") {
        check!(after > before, "no virtio MSI-X interrupt");
        serial_println!("[BLK TEST] 7/8 completion interrupt via MSI-X PASS");
    } else if kind.contains("IRQ") {
        check!(after > before, "no virtio INTx interrupt");
        serial_println!("[BLK TEST] 7/8 completion interrupt via INTx PASS");
    } else {
        serial_println!("[BLK TEST] 7/8 no interrupt available - polling mode PASS");
    }

    // 8. Performance (rough): 1 MiB read.
    let mut big = vec![0u8; 1024 * 1024];
    let t0 = crate::time::ticks();
    check!(block::read(0, 0, &mut big[..(sectors.min(2048) as usize) * SECTOR_SIZE]).is_ok(), "1 MiB read");
    let ms = crate::time::ticks() - t0;
    serial_println!("[BLK TEST] 8/8 read {} KiB in {} ms PASS", sectors.min(2048) / 2, ms);

    serial_println!("[BLK TEST] =================================");
    crate::selftest::pass();
    serial_println!("[BLK TEST] PCI + VIRTIO-BLK TESTS PASSED");
    serial_println!("[BLK TEST] =================================");
}
