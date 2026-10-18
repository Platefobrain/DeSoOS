// Block device layer – a common interface for disks.
//
// Every disk driver (virtio-blk now, NVMe / AHCI later) implements
// `BlockDevice` and registers itself via `register()`.  Upper layers (the file
// system, the shell) use only this interface – they do not know what disk it is.
//
// One request at a time per disk (the call waits for completion).  Access is
// under a lock (a separate one for each disk); a task waiting for the
// disk sleeps (virtio: BLK_WAIT).
//
// Notes:
//   * Read-only disks are enforced HERE (independently of the driver
//     and file system): `write` on such a disk fails with ReadOnly before
//     anything reaches the driver.  Real NVMe disks are always
//     read-only (drivers/nvme.rs).
//   * Partitions (GPT – gpt.rs) are separate disks, e.g. "nvme0n1p1": they have
//     an offset and length and inherit "read-only" from the disk.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

pub const SECTOR_SIZE: usize = 512;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockError {
    /// LBA or length beyond the disk.
    OutOfRange,
    /// Buffer is not a multiple of the sector size.
    BadBuffer,
    /// Read-only disk.
    ReadOnly,
    /// The device reported an I/O error.
    Io,
    /// Operation not supported by the device.
    Unsupported,
    /// The device did not respond in time.
    Timeout,
    /// There is no disk with that number.
    NoDevice,
}

impl core::fmt::Display for BlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            BlockError::OutOfRange => "sector out of range",
            BlockError::BadBuffer => "buffer is not a multiple of the sector size",
            BlockError::ReadOnly => "device is read-only",
            BlockError::Io => "I/O error",
            BlockError::Unsupported => "operation not supported",
            BlockError::Timeout => "device timeout",
            BlockError::NoDevice => "no such disk",
        };
        f.write_str(s)
    }
}

pub trait BlockDevice {
    /// Short name, e.g. "vda".
    fn name(&self) -> &str;
    /// Human-readable description (type, model).
    fn description(&self) -> String;
    /// Number of 512 B sectors.
    fn sector_count(&self) -> u64;
    fn read_only(&self) -> bool;
    /// Native block size of the device (512 or 4096) – the interface still
    /// counts in 512 B sectors, but GPT gives addresses in device blocks.
    fn logical_block_size(&self) -> usize {
        SECTOR_SIZE
    }
    /// GPT partition type (None: a whole disk, not a partition).
    fn partition_kind(&self) -> Option<&'static str> {
        None
    }
    /// Number of the parent disk (for a partition) or None.
    fn parent(&self) -> Option<usize> {
        None
    }
    /// Reads `buf.len() / 512` sectors starting at `lba`.
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError>;
    /// Writes `buf.len() / 512` sectors starting at `lba`.
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError>;
    /// Forces the device cache to be written to the medium.
    fn flush(&mut self) -> Result<(), BlockError>;
}

/// Range check shared by the drivers.
pub fn check_range(dev_sectors: u64, lba: u64, len: usize) -> Result<u64, BlockError> {
    if len == 0 || len % SECTOR_SIZE != 0 {
        return Err(BlockError::BadBuffer);
    }
    let count = (len / SECTOR_SIZE) as u64;
    match lba.checked_add(count) {
        Some(end) if end <= dev_sectors => Ok(count),
        _ => Err(BlockError::OutOfRange),
    }
}

// One lock PER DISK (rather than one global „block layer” lock) – a read from
// a USB stick can wait up to 5 s for usbd, and it must not stall NVMe
// or virtio meanwhile.  The disk list is under a short lock (entry lookup, Arc),
// the operation under the disk lock (KMutex – reentrant, sleeping).  A partition
// takes its own lock, then the parent disk's lock (always in this order).
// Order: FS_LOCK -> partition lock -> disk lock.
//
// Removal (a USB disk went away): the list entry = None, the number returns to the pool
// only when nothing uses it any more – the remover first unmounts the file
// systems on the disk and its partitions (ublk.rs).  An operation in progress holds an Arc.

struct Disk {
    /// Copy of the name – `find` without taking the disk lock.
    name: String,
    /// Parent disk (for a partition) – `partitions_of` without disk locks.
    parent: Option<usize>,
    lock: crate::sched::sync::KMutex,
    dev: core::cell::UnsafeCell<Box<dyn BlockDevice>>,
}

// The device changes only under `lock` (KMutex – one task at a time).
unsafe impl Sync for Disk {}
unsafe impl Send for Disk {}

static DISKS: crate::sched::spin::SpinLock<Vec<Option<Arc<Disk>>>> =
    crate::sched::spin::SpinLock::new("block list", crate::sched::spin::level::BLOCK, Vec::new());

fn disk(index: usize) -> Option<Arc<Disk>> {
    DISKS.lock().get(index).cloned().flatten()
}

/// Adds a disk; returns its number (the first free one – e.g. after a removed USB disk).
pub fn register(device: Box<dyn BlockDevice>) -> usize {
    let d = Arc::new(Disk {
        name: String::from(device.name()),
        parent: device.parent(),
        lock: crate::sched::sync::KMutex::new(),
        dev: core::cell::UnsafeCell::new(device),
    });
    let mut list = DISKS.lock();
    if list.capacity() == 0 {
        // No moving of the table as more disks are added (tests count frames).
        list.reserve(32);
    }
    if let Some(i) = list.iter().position(|e| e.is_none()) {
        list[i] = Some(d);
        return i;
    }
    list.push(Some(d));
    list.len() - 1
}

/// Removes a disk (frees the entry).  The caller has already unmounted file systems from
/// it and from its partitions.
pub fn remove(index: usize) {
    let old = {
        let mut list = DISKS.lock();
        match list.get_mut(index) {
            Some(e) => e.take(),
            None => None,
        }
    };
    drop(old); // Drop the device outside the list lock
}

/// Number of entries (numbers 0..count; removed ones give NoDevice).
pub fn count() -> usize {
    DISKS.lock().len()
}

/// Operation on disk number `index` (under that disk's lock).
pub fn with_device<R>(index: usize, f: impl FnOnce(&mut dyn BlockDevice) -> R) -> Result<R, BlockError> {
    let d = disk(index).ok_or(BlockError::NoDevice)?;
    let _g = d.lock.lock();
    Ok(f(unsafe { &mut **d.dev.get() }))
}

pub fn read(index: usize, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
    with_device(index, |d| d.read(lba, buf))?
}

pub fn write(index: usize, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
    with_device(index, |d| {
        // Second line of defense – a read-only disk never receives a write.
        if d.read_only() {
            return Err(BlockError::ReadOnly);
        }
        d.write(lba, buf)
    })?
}

pub fn flush(index: usize) -> Result<(), BlockError> {
    with_device(index, |d| if d.read_only() { Ok(()) } else { d.flush() })?
}

#[allow(dead_code)]
pub fn is_read_only(index: usize) -> bool {
    with_device(index, |d| d.read_only()).unwrap_or(true)
}

/// Number of the disk named `name`.
#[allow(dead_code)]
pub fn find(name: &str) -> Option<usize> {
    DISKS.lock().iter().position(|d| matches!(d, Some(d) if d.name == name))
}

/// Partition numbers of disk `parent` (registered by scan_partitions).
pub fn partitions_of(parent: usize) -> Vec<usize> {
    let list = DISKS.lock();
    (0..list.len()).filter(|&i| matches!(&list[i], Some(d) if d.parent == Some(parent))).collect()
}

// ------------------------------------------------------------
// Partitions as separate disks
// ------------------------------------------------------------

pub struct Partition {
    name: String,
    parent: usize,
    /// Start and length in 512 B sectors.
    start: u64,
    sectors: u64,
    read_only: bool,
    block_size: usize,
    kind: &'static str,
    label: String,
}

impl BlockDevice for Partition {
    fn name(&self) -> &str {
        &self.name
    }
    fn description(&self) -> String {
        alloc::format!(
            "partition of disk {} at sector {}, {} MiB, {}{}{}",
            self.parent,
            self.start,
            self.sectors * SECTOR_SIZE as u64 / (1024 * 1024),
            self.kind,
            if self.label.is_empty() { String::new() } else { alloc::format!(" \"{}\"", self.label) },
            if self.read_only { ", read-only" } else { "" }
        )
    }
    fn sector_count(&self) -> u64 {
        self.sectors
    }
    fn read_only(&self) -> bool {
        self.read_only
    }
    fn logical_block_size(&self) -> usize {
        self.block_size
    }
    fn partition_kind(&self) -> Option<&'static str> {
        Some(self.kind)
    }
    fn parent(&self) -> Option<usize> {
        Some(self.parent)
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        check_range(self.sectors, lba, buf.len())?;
        read(self.parent, self.start + lba, buf)
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        check_range(self.sectors, lba, buf.len())?;
        if self.read_only {
            return Err(BlockError::ReadOnly);
        }
        write(self.parent, self.start + lba, buf)
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        flush(self.parent)
    }
}

/// Reads the GPT of disk `disk` and registers its partitions as disks
/// "<name>p<n>" (or "<name><n>" unless the name ends with a digit... as in
/// Linux: nvme0n1 -> nvme0n1p1, vda -> vda1).  Returns the number of partitions.
pub fn scan_partitions(disk: usize) -> usize {
    let Ok((name, read_only, block_size)) =
        with_device(disk, |d| (String::from(d.name()), d.read_only(), d.logical_block_size()))
    else {
        return 0;
    };
    let parts = match crate::gpt::read(disk) {
        Ok(Some(p)) => p,
        Ok(None) => return 0,
        Err(e) => {
            crate::serial_println!("[BLK] {}: GPT: {}", name, e);
            return 0;
        }
    };
    let sep = if name.ends_with(|c: char| c.is_ascii_digit()) { "p" } else { "" };
    let mut n = 0;
    for p in &parts {
        let pname = alloc::format!("{}{}{}", name, sep, p.index);
        if find(&pname).is_some() {
            continue; // already registered
        }
        let part = Partition {
            name: pname.clone(),
            parent: disk,
            start: p.first_sector,
            sectors: p.sectors,
            read_only,
            block_size,
            kind: p.kind,
            label: p.name.clone(),
        };
        let index = register(Box::new(part));
        crate::serial_println!(
            "[BLK]   disk {}: {} = {} MiB, {}{}",
            index,
            pname,
            p.sectors * SECTOR_SIZE as u64 / (1024 * 1024),
            p.kind,
            if p.name.is_empty() { String::new() } else { alloc::format!(" \"{}\"", p.name) }
        );
        n += 1;
    }
    n
}

/// Partition type of disk `index` (None: not a partition).
#[allow(dead_code)]
pub fn partition_kind(index: usize) -> Option<&'static str> {
    with_device(index, |d| d.partition_kind()).ok().flatten()
}

// ------------------------------------------------------------
// In-memory disk (file system tests without touching a real disk)
// ------------------------------------------------------------

#[cfg(selftest)]
pub struct RamDisk {
    name: String,
    data: Vec<u8>,
}

#[cfg(selftest)]
impl RamDisk {
    pub fn new(name: &str, sectors: u64) -> Self {
        RamDisk { name: String::from(name), data: alloc::vec![0u8; sectors as usize * SECTOR_SIZE] }
    }
}

#[cfg(selftest)]
impl BlockDevice for RamDisk {
    fn name(&self) -> &str {
        &self.name
    }
    fn description(&self) -> String {
        alloc::format!("RAM disk, {} KiB", self.data.len() / 1024)
    }
    fn sector_count(&self) -> u64 {
        (self.data.len() / SECTOR_SIZE) as u64
    }
    fn read_only(&self) -> bool {
        false
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        check_range(self.sector_count(), lba, buf.len())?;
        let o = lba as usize * SECTOR_SIZE;
        buf.copy_from_slice(&self.data[o..o + buf.len()]);
        Ok(())
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        check_range(self.sector_count(), lba, buf.len())?;
        let o = lba as usize * SECTOR_SIZE;
        self.data[o..o + buf.len()].copy_from_slice(buf);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
}


