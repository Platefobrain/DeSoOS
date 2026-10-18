// PCI bus – device discovery and configuration access.
//
// Configuration space access:
//   * "mechanism #1" – ports 0xCF8 (address) and 0xCFC (data): works on every
//     x86 PC, but only gives the first 256 bytes of configuration.  We use it
//     to scan the bus.
//   * PCIe ECAM – configuration as memory (4 KiB per function), address
//     from the ACPI MCFG table.  After the scan each function found gets
//     its ECAM page mapped; if ECAM reads match the ports, all
//     configuration access goes through ECAM (including the extended part
//     0x100..0xFFF – `read32_ext`).
//
// MSI / MSI-X (`enable_msix`, `enable_msi`) – interrupts as writes to the
// LAPIC, without an INTx line (whose number on real hardware we cannot know without
// an AML interpreter).
//
// `init()` scans all buses/devices/functions, stores the list
// and disables INTx interrupts for devices we do not support (e.g. a network
// card sharing an IRQ line with the virtio disk – its interrupt without a driver
// would lock up the system).  A driver enables INTx for its own device.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use crate::arch::x86_64::interrupts::without_interrupts;
use crate::arch::x86_64::port::{inb, outb};
use crate::serial_println;

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

pub const REG_VENDOR: u8 = 0x00;
pub const REG_COMMAND: u8 = 0x04;
pub const REG_STATUS: u8 = 0x06;
pub const REG_CLASS: u8 = 0x08; // revision, prog-if, subclass, class
pub const REG_HEADER_TYPE: u8 = 0x0E;
pub const REG_BAR0: u8 = 0x10;
pub const REG_CAPABILITIES: u8 = 0x34;
pub const REG_INTERRUPT_LINE: u8 = 0x3C;
pub const REG_INTERRUPT_PIN: u8 = 0x3D;

pub const CAP_MSI: u8 = 0x05;
pub const CAP_MSIX: u8 = 0x11;

pub const CMD_IO: u16 = 1 << 0;
pub const CMD_MEMORY: u16 = 1 << 1;
pub const CMD_BUS_MASTER: u16 = 1 << 2;
pub const CMD_INTX_DISABLE: u16 = 1 << 10;
const STATUS_CAPABILITIES: u16 = 1 << 4;

// ------------------------------------------------------------
// Configuration access
// ------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Address {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:02x}:{:02x}.{}", self.bus, self.device, self.function)
    }
}

fn select(a: Address, offset: u8) {
    let address = 0x8000_0000u32
        | (a.bus as u32) << 16
        | (a.device as u32) << 11
        | (a.function as u32) << 8
        | (offset as u32 & 0xFC);
    unsafe {
        // outl
        core::arch::asm!("out dx, eax", in("dx") CONFIG_ADDRESS, in("eax") address,
            options(nomem, nostack, preserves_flags));
    }
}

fn read_data32() -> u32 {
    let v: u32;
    unsafe {
        core::arch::asm!("in eax, dx", in("dx") CONFIG_DATA, out("eax") v,
            options(nomem, nostack, preserves_flags));
    }
    v
}

fn write_data32(v: u32) {
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") CONFIG_DATA, in("eax") v,
            options(nomem, nostack, preserves_flags));
    }
}

// ECAM (segment 0).  Enabled in init after verification.
static ECAM_ON: AtomicBool = AtomicBool::new(false);
static ECAM_BASE: AtomicU64 = AtomicU64::new(0);
static ECAM_BUSES: AtomicU64 = AtomicU64::new(0); // start | end << 8

/// Physical address of a register in ECAM (without checking whether ECAM works).
fn ecam_phys(a: Address, offset: u16) -> Option<u64> {
    let base = ECAM_BASE.load(Ordering::Relaxed);
    let buses = ECAM_BUSES.load(Ordering::Relaxed);
    let (start, end) = ((buses & 0xFF) as u8, ((buses >> 8) & 0xFF) as u8);
    if base == 0 || a.bus < start || a.bus > end || a.device > 31 || a.function > 7 || offset > 0xFFC {
        return None;
    }
    Some(
        base + ((a.bus - start) as u64) * (1 << 20)
            + (a.device as u64) * (1 << 15)
            + (a.function as u64) * (1 << 12)
            + (offset & 0xFFC) as u64,
    )
}

/// Virtual address of a register in ECAM, if the function's page is mapped.
fn ecam_virt(a: Address, offset: u16) -> Option<u64> {
    let phys = ecam_phys(a, offset)?;
    let page = phys & !0xFFF;
    let va = crate::memory::phys_to_virt(page);
    if crate::memory::translate(va) != Some(page) {
        return None;
    }
    Some(va + (phys & 0xFFF))
}

fn port_read32(a: Address, offset: u8) -> u32 {
    without_interrupts(|| {
        select(a, offset);
        read_data32()
    })
}

// The address write + data read pair must not be interrupted by another
// configuration access (e.g. from an IRQ handler) – hence without_interrupts.
pub fn read32(a: Address, offset: u8) -> u32 {
    if ECAM_ON.load(Ordering::Relaxed) {
        if let Some(va) = ecam_virt(a, offset as u16) {
            return unsafe { core::ptr::read_volatile(va as *const u32) };
        }
    }
    port_read32(a, offset)
}

pub fn write32(a: Address, offset: u8, value: u32) {
    if ECAM_ON.load(Ordering::Relaxed) {
        if let Some(va) = ecam_virt(a, offset as u16) {
            unsafe { core::ptr::write_volatile(va as *mut u32, value) };
            return;
        }
    }
    without_interrupts(|| {
        select(a, offset);
        write_data32(value);
    })
}

/// Extended PCIe configuration (0x100..0xFFF) – only through ECAM.
#[allow(dead_code)]
pub fn read32_ext(a: Address, offset: u16) -> Option<u32> {
    if !ECAM_ON.load(Ordering::Relaxed) {
        return None;
    }
    let va = ecam_virt(a, offset)?;
    Some(unsafe { core::ptr::read_volatile(va as *const u32) })
}

/// Whether configuration goes through ECAM (lspci, tests).
pub fn ecam_enabled() -> bool {
    ECAM_ON.load(Ordering::Relaxed)
}

/// ECAM address (0 = none).
pub fn ecam_base() -> u64 {
    if ecam_enabled() { ECAM_BASE.load(Ordering::Relaxed) } else { 0 }
}

/// Tests: reads the same register through the ports (comparison with ECAM).
#[allow(dead_code)]
pub fn read32_port(a: Address, offset: u8) -> u32 {
    port_read32(a, offset)
}

/// Maps the ECAM pages of the functions found and enables ECAM if
/// the reads match the ports.  After the bus scan.
fn setup_ecam(found: &[Device]) {
    let Some(e) = crate::acpi::mcfg().iter().find(|e| e.segment == 0).copied() else {
        serial_println!("[PCI] no MCFG (ACPI) - config space via ports 0xCF8/0xCFC (256 B per function)");
        return;
    };
    ECAM_BASE.store(e.base, Ordering::SeqCst);
    ECAM_BUSES.store(e.bus_start as u64 | (e.bus_end as u64) << 8, Ordering::SeqCst);
    for d in found {
        let Some(phys) = ecam_phys(d.address, 0) else {
            serial_println!("[PCI] {} outside the ECAM bus range - ECAM not used", d.address);
            return;
        };
        if crate::memory::map_mmio(phys, 4096).is_none() {
            serial_println!("[PCI] cannot map ECAM page {:#x} - ECAM not used", phys);
            return;
        }
        // The same register through ECAM and through the ports: ID and class.
        for off in [REG_VENDOR, REG_CLASS] {
            let via_ecam = unsafe { core::ptr::read_volatile(ecam_virt(d.address, off as u16).unwrap() as *const u32) };
            let via_port = port_read32(d.address, off);
            if via_ecam != via_port {
                serial_println!(
                    "[PCI] ECAM mismatch at {} reg {:#x}: {:#x} != {:#x} - ECAM not used",
                    d.address, off, via_ecam, via_port
                );
                return;
            }
        }
    }
    ECAM_ON.store(true, Ordering::SeqCst);
    serial_println!(
        "[PCI] config space via PCIe ECAM at {:#x} (buses {}-{}, 4 KiB per function)",
        e.base, e.bus_start, e.bus_end
    );
}

pub fn read16(a: Address, offset: u8) -> u16 {
    (read32(a, offset & 0xFC) >> ((offset & 2) * 8)) as u16
}

pub fn read8(a: Address, offset: u8) -> u8 {
    (read32(a, offset & 0xFC) >> ((offset & 3) * 8)) as u8
}

pub fn write16(a: Address, offset: u8, value: u16) {
    let aligned = offset & 0xFC;
    let shift = (offset & 2) * 8;
    let old = read32(a, aligned);
    let new = (old & !(0xFFFF << shift)) | ((value as u32) << shift);
    write32(a, aligned, new);
}

// ------------------------------------------------------------
// Devices
// ------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bar {
    None,
    Memory { base: u64, size: u64, prefetchable: bool, is64: bool },
    Io { port: u16, size: u32 },
}

#[derive(Clone, Debug)]
pub struct Device {
    pub address: Address,
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub header_type: u8,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
    pub bars: [Bar; 6],
}

impl Device {
    pub fn command(&self) -> u16 {
        read16(self.address, REG_COMMAND)
    }

    pub fn set_command(&self, value: u16) {
        write16(self.address, REG_COMMAND, value);
    }

    /// Enables memory/IO decoding, bus mastering (DMA) and INTx interrupts.
    pub fn enable(&self, bus_master: bool, intx: bool) {
        let mut cmd = self.command() | CMD_MEMORY | CMD_IO;
        if bus_master {
            cmd |= CMD_BUS_MASTER;
        }
        if intx {
            cmd &= !CMD_INTX_DISABLE;
        } else {
            cmd |= CMD_INTX_DISABLE;
        }
        self.set_command(cmd);
    }

    /// Capability list: (offset, id).
    pub fn capabilities(&self) -> Vec<(u8, u8)> {
        let mut caps = Vec::new();
        if read16(self.address, REG_STATUS) & STATUS_CAPABILITIES == 0 {
            return caps;
        }
        let mut ptr = read8(self.address, REG_CAPABILITIES) & 0xFC;
        let mut guard = 0;
        while ptr >= 0x40 && guard < 48 {
            let id = read8(self.address, ptr);
            caps.push((ptr, id));
            ptr = read8(self.address, ptr + 1) & 0xFC;
            guard += 1;
        }
        caps
    }

    pub fn class_name(&self) -> &'static str {
        class_name(self.class, self.subclass)
    }

    pub fn find_capability(&self, id: u8) -> Option<u8> {
        self.capabilities().into_iter().find(|&(_, i)| i == id).map(|(off, _)| off)
    }

    /// MSI-X – entry `entry` of the MSI-X table to vector `vector` (to the
    /// current CPU).  The other entries stay masked.  INTx disabled.
    pub fn enable_msix(&self, entry: u16, vector: u8) -> Result<(), &'static str> {
        let cap = self.find_capability(CAP_MSIX).ok_or("no MSI-X capability")?;
        let ctrl = read16(self.address, cap + 2);
        let table_size = (ctrl & 0x7FF) + 1;
        if entry >= table_size {
            return Err("MSI-X entry out of range");
        }
        let table = read32(self.address, cap + 4);
        let bir = (table & 7) as usize;
        let offset = (table & !7) as u64;
        let Bar::Memory { base, .. } = self.bars.get(bir).copied().unwrap_or(Bar::None) else {
            return Err("MSI-X table BAR is not a memory BAR");
        };
        let tbl = crate::memory::map_mmio(base + offset, table_size as u64 * 16).ok_or("cannot map the MSI-X table")?;
        // Enable with the whole function masked, set the entry, remove the masks.
        write16(self.address, cap + 2, ctrl | (1 << 15) | (1 << 14));
        let e = tbl + entry as u64 * 16;
        let addr = crate::arch::x86_64::lapic::msi_address();
        unsafe {
            core::ptr::write_volatile(e as *mut u32, addr as u32);
            core::ptr::write_volatile((e + 4) as *mut u32, (addr >> 32) as u32);
            core::ptr::write_volatile((e + 8) as *mut u32, vector as u32); // fixed, edge
            core::ptr::write_volatile((e + 12) as *mut u32, 0); // unmasked
        }
        self.set_command(self.command() | CMD_INTX_DISABLE);
        write16(self.address, cap + 2, (ctrl | (1 << 15)) & !(1 << 14));
        Ok(())
    }

    /// MSI (single message) to vector `vector`.  INTx disabled.
    pub fn enable_msi(&self, vector: u8) -> Result<(), &'static str> {
        let cap = self.find_capability(CAP_MSI).ok_or("no MSI capability")?;
        let ctrl = read16(self.address, cap + 2);
        let is64 = ctrl & (1 << 7) != 0;
        let addr = crate::arch::x86_64::lapic::msi_address();
        write32(self.address, cap + 4, addr as u32);
        let data_off = if is64 {
            write32(self.address, cap + 8, (addr >> 32) as u32);
            cap + 12
        } else {
            cap + 8
        };
        write16(self.address, data_off, vector as u16);
        self.set_command(self.command() | CMD_INTX_DISABLE);
        // Multiple Message Enable = 1 message, MSI Enable.
        write16(self.address, cap + 2, (ctrl & !(7 << 4)) | 1);
        Ok(())
    }

    /// Disables MSI and MSI-X (the device stops sending interrupts).
    pub fn disable_msi(&self) {
        if let Some(cap) = self.find_capability(CAP_MSI) {
            let ctrl = read16(self.address, cap + 2);
            write16(self.address, cap + 2, ctrl & !1);
        }
        if let Some(cap) = self.find_capability(CAP_MSIX) {
            let ctrl = read16(self.address, cap + 2);
            write16(self.address, cap + 2, ctrl & !(1 << 15));
        }
    }

    /// Bus mastering (DMA and MSI interrupts – those are device writes
    /// to memory too).  Disabling ends with a register read: writes to
    /// PCI configuration may be buffered, a read guarantees they have landed.
    pub fn set_bus_master(&self, on: bool) {
        let cmd = self.command();
        self.set_command(if on { cmd | CMD_BUS_MASTER | CMD_MEMORY } else { cmd & !CMD_BUS_MASTER });
        let _ = self.command();
    }
}

pub fn class_name(class: u8, subclass: u8) -> &'static str {
    match (class, subclass) {
        (0x01, 0x00) => "SCSI storage",
        (0x01, 0x01) => "IDE controller",
        (0x01, 0x06) => "SATA controller",
        (0x01, 0x08) => "NVMe controller",
        (0x01, _) => "storage controller",
        (0x02, 0x00) => "Ethernet controller",
        (0x02, _) => "network controller",
        (0x03, 0x00) => "VGA controller",
        (0x03, _) => "display controller",
        (0x04, _) => "multimedia device",
        (0x06, 0x00) => "host bridge",
        (0x06, 0x01) => "ISA bridge",
        (0x06, 0x04) => "PCI bridge",
        (0x06, _) => "bridge",
        (0x0C, 0x03) => "USB controller",
        (0x0C, 0x05) => "SMBus",
        (0x0C, _) => "serial bus controller",
        (0x00, _) => "unclassified",
        _ => "other",
    }
}

/// BAR size and type (write all ones, read the mask, restore).
/// Device decoding is disabled for the duration of the measurement.
fn probe_bars(a: Address, count: usize) -> [Bar; 6] {
    let mut bars = [Bar::None; 6];
    let cmd = read16(a, REG_COMMAND);
    write16(a, REG_COMMAND, cmd & !(CMD_IO | CMD_MEMORY));

    let mut i = 0;
    while i < count {
        let reg = REG_BAR0 + (i as u8) * 4;
        let orig = read32(a, reg);
        write32(a, reg, 0xFFFF_FFFF);
        let mask = read32(a, reg);
        write32(a, reg, orig);

        if mask == 0 {
            i += 1;
            continue;
        }
        if orig & 1 == 1 {
            let size = (!(mask & 0xFFFF_FFFC)).wrapping_add(1) & 0xFFFF;
            bars[i] = Bar::Io { port: (orig & 0xFFFC) as u16, size };
            i += 1;
            continue;
        }

        let is64 = (orig >> 1) & 3 == 2;
        let prefetchable = orig & 8 != 0;
        let mut base = (orig & 0xFFFF_FFF0) as u64;
        let mut size_mask = (mask & 0xFFFF_FFF0) as u64 | 0xFFFF_FFFF_0000_0000;
        if is64 && i + 1 < count {
            let reg_hi = reg + 4;
            let orig_hi = read32(a, reg_hi);
            write32(a, reg_hi, 0xFFFF_FFFF);
            let mask_hi = read32(a, reg_hi);
            write32(a, reg_hi, orig_hi);
            base |= (orig_hi as u64) << 32;
            size_mask = (size_mask & 0xFFFF_FFFF) | ((mask_hi as u64) << 32);
        }
        let size = (!size_mask).wrapping_add(1);
        bars[i] = Bar::Memory { base, size, prefetchable, is64 };
        i += if is64 { 2 } else { 1 };
    }

    write16(a, REG_COMMAND, cmd);
    bars
}

fn read_device(a: Address) -> Option<Device> {
    let id = read32(a, REG_VENDOR);
    let vendor = id as u16;
    if vendor == 0xFFFF {
        return None;
    }
    let class_reg = read32(a, REG_CLASS);
    let header_type = read8(a, REG_HEADER_TYPE);
    // A type 0 header has 6 BARs, a PCI-PCI bridge (type 1) – 2.
    let bar_count = match header_type & 0x7F {
        0 => 6,
        1 => 2,
        _ => 0,
    };
    Some(Device {
        address: a,
        vendor,
        device: (id >> 16) as u16,
        class: (class_reg >> 24) as u8,
        subclass: (class_reg >> 16) as u8,
        prog_if: (class_reg >> 8) as u8,
        revision: class_reg as u8,
        header_type,
        interrupt_line: read8(a, REG_INTERRUPT_LINE),
        interrupt_pin: read8(a, REG_INTERRUPT_PIN),
        bars: probe_bars(a, bar_count),
    })
}

static mut DEVICES: Vec<Device> = Vec::new();

/// List of devices found (after `init`).
pub fn devices() -> &'static [Device] {
    unsafe { &*core::ptr::addr_of!(DEVICES) }
}

#[allow(dead_code)]
pub fn find(vendor: u16, device_ids: &[u16]) -> Option<&'static Device> {
    devices().iter().find(|d| d.vendor == vendor && device_ids.contains(&d.device))
}

/// Scans the bus.  Requires the heap.
pub fn init() {
    let mut found = Vec::new();
    for bus in 0..=255u8 {
        for device in 0..32u8 {
            let a0 = Address { bus, device, function: 0 };
            let Some(d0) = read_device(a0) else { continue };
            let multi = d0.header_type & 0x80 != 0;
            found.push(d0);
            if multi {
                for function in 1..8u8 {
                    if let Some(d) = read_device(Address { bus, device, function }) {
                        found.push(d);
                    }
                }
            }
        }
    }

    // ECAM from ACPI MCFG (compared with the ports before enabling).
    setup_ecam(&found);

    // No driver = no INTx interrupts (bridges are left alone).
    for d in &found {
        if d.header_type & 0x7F == 0 && d.interrupt_pin != 0 {
            d.set_command(d.command() | CMD_INTX_DISABLE);
        }
    }

    serial_println!("[PCI] {} devices found", found.len());
    for d in &found {
        serial_println!(
            "[PCI]   {} {:04x}:{:04x} {}{}",
            d.address,
            d.vendor,
            d.device,
            d.class_name(),
            if d.interrupt_pin != 0 && d.interrupt_line != 0xFF {
                alloc::format!(" (IRQ {})", d.interrupt_line)
            } else {
                alloc::string::String::new()
            }
        );
    }
    unsafe {
        *core::ptr::addr_of_mut!(DEVICES) = found;
    }
}

// ------------------------------------------------------------
// Device owner – a kernel driver or a user-space service
// (dev_claim).  One device – one owner at a time.
// ------------------------------------------------------------

pub const OWNER_FREE: u8 = 0;
pub const OWNER_KERNEL: u8 = 1;
pub const OWNER_USER: u8 = 2;
/// Devices further down the list cannot be claimed by a service.
const MAX_OWNED: usize = 256;
static OWNERS: [AtomicU8; MAX_OWNED] = [const { AtomicU8::new(OWNER_FREE) }; MAX_OWNED];

/// Reason for a `claim_user` refusal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClaimError {
    NoDevice,
    /// A kernel driver, or a class a service never gets.
    Forbidden,
    /// Another service already has this device.
    Busy,
}

/// Device index in the `devices()` list.
pub fn index_of(a: Address) -> Option<usize> {
    devices().iter().position(|d| d.address == a)
}

/// A kernel driver handles the device (virtio-blk, NVMe).
pub fn set_kernel_owner(a: Address) {
    if let Some(i) = index_of(a).filter(|&i| i < MAX_OWNED) {
        OWNERS[i].store(OWNER_KERNEL, Ordering::SeqCst);
    }
}

pub fn owner(index: usize) -> u8 {
    if index < MAX_OWNED { OWNERS[index].load(Ordering::SeqCst) } else { OWNER_KERNEL }
}

/// Classes a service never gets: mass storage (0x01 – even without a
/// driver: protects disks on real hardware), display (0x03 –
/// console framebuffer), bridges (0x06), system devices (0x08 – PIC,
/// IOAPIC, timers, IOMMU).
pub fn class_forbidden(d: &Device) -> bool {
    matches!(d.class, 0x01 | 0x03 | 0x06 | 0x08)
}

/// A service claims a device – the index or the reason for refusal.
pub fn claim_user(a: Address) -> Result<usize, ClaimError> {
    let i = index_of(a).ok_or(ClaimError::NoDevice)?;
    let d = &devices()[i];
    if i >= MAX_OWNED || class_forbidden(d) || d.header_type & 0x7F != 0 {
        return Err(ClaimError::Forbidden);
    }
    match OWNERS[i].compare_exchange(OWNER_FREE, OWNER_USER, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => Ok(i),
        Err(OWNER_USER) => Err(ClaimError::Busy),
        Err(_) => Err(ClaimError::Forbidden),
    }
}

/// A service returns a device (the last handle / mapping is gone).
pub fn release_user(index: usize) {
    if index < MAX_OWNED {
        let _ = OWNERS[index].compare_exchange(OWNER_USER, OWNER_FREE, Ordering::SeqCst, Ordering::SeqCst);
    }
}

impl Device {
    /// MSI-X regions (table, PBA) in BAR `bar` – (offset, length).
    /// A service must not map them: a write there routes an interrupt to any
    /// vector (e.g. a kernel IPI).
    pub fn msix_regions(&self, bar: usize) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let Some(cap) = self.find_capability(CAP_MSIX) else { return out };
        let entries = (read16(self.address, cap + 2) & 0x7FF) as u64 + 1;
        let table = read32(self.address, cap + 4);
        let pba = read32(self.address, cap + 8);
        if (table & 7) as usize == bar {
            out.push(((table & !7) as u64, entries * 16));
        }
        if (pba & 7) as usize == bar {
            out.push(((pba & !7) as u64, entries.div_ceil(64) * 8));
        }
        out
    }
}

/// For readable descriptions (shell `lspci`).
pub fn describe_bar(bar: &Bar) -> Option<alloc::string::String> {
    match *bar {
        Bar::None => None,
        Bar::Memory { base, size, prefetchable, is64 } => Some(alloc::format!(
            "mem {:#x} size {:#x}{}{}",
            base,
            size,
            if is64 { " 64-bit" } else { "" },
            if prefetchable { " prefetchable" } else { "" }
        )),
        Bar::Io { port, size } => Some(alloc::format!("io {:#x} size {:#x}", port, size)),
    }
}

// ELCR – PIC trigger-mode registers (0x4D0: IRQ0-7, 0x4D1: IRQ8-15).
// PCI interrupts (INTx) are level-triggered.
pub fn set_level_triggered(irq: u8) {
    let port = if irq < 8 { 0x4D0 } else { 0x4D1 };
    unsafe {
        let v = inb(port);
        outb(port, v | (1 << (irq % 8)));
    }
}

#[allow(dead_code)]
pub fn is_level_triggered(irq: u8) -> bool {
    let port = if irq < 8 { 0x4D0 } else { 0x4D1 };
    unsafe { inb(port) & (1 << (irq % 8)) != 0 }
}
