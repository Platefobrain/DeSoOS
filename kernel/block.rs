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
//   * A USB disk (ublk) stays read-only as a whole, always.  Only one of its partitions may
//     get a write GRANT from the kernel (`set_grant`) after the write rules (docs/ARCHITECTURE.md,
//     "Writing to a USB disk"): tag 0 = ordinary read-write, any other tag = the identifier of
//     the format session.  Such a partition writes through `write_range` / `flush_range` of
//     the disk, which checks its own registration again (the second of three locks).

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
    /// A write from a partition with a grant (`tag`: 0 rw, otherwise the format session).
    /// A disk without registrations (everything but ublk) writes only when it is not
    /// read-only and only with tag 0.
    fn write_range(&mut self, lba: u64, buf: &[u8], tag: u64) -> Result<(), BlockError> {
        if self.read_only() || tag != 0 {
            return Err(BlockError::ReadOnly);
        }
        self.write(lba, buf)
    }
    /// A flush from a partition with a grant (as `write_range`).
    fn flush_range(&mut self, tag: u64) -> Result<(), BlockError> {
        if self.read_only() || tag != 0 {
            return Err(BlockError::ReadOnly);
        }
        self.flush()
    }
    /// Registrations and other control of a USB disk (ublk); others – Unsupported.
    fn control(&mut self, _c: Control) -> Result<u64, BlockError> {
        Err(BlockError::Unsupported)
    }
    /// A partition: sets or clears its write grant; false – not a partition.
    fn set_grant(&mut self, _grant: Option<u64>) -> bool {
        false
    }
    /// A partition: (start, length) in 512 B sectors of its parent.
    fn partition_range(&self) -> Option<(u64, u64)> {
        None
    }
}

/// Control of a USB disk (ublk.rs) – the registrations of the write rules.  Block numbers are
/// absolute device blocks; `generation` is the disk's generation (a stale one – NoDevice).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(selftest), allow(dead_code))]
pub enum Control {
    /// The disk's generation.
    Generation,
    /// Write protection as usbd saw it: 0 unknown, 1 not protected, 2 protected.
    WriteProtect,
    /// A probe registration, one FLUSH through it, the probe withdrawn – Ok only after a
    /// confirmed SYNCHRONIZE CACHE.
    Probe { generation: u64 },
    /// A read-write registration of [start, start + len).
    RegisterRw { generation: u64, start: u64, len: u64 },
    /// A format registration – Ok(the new session identifier).
    BeginFormat { generation: u64, start: u64, len: u64 },
    /// The end of that session (also after an error).
    EndFormat { session: u64 },
    /// The registration withdrawn (unmount).
    Withdraw,
    /// Self-tests: a test flag sent to the device (usbd / the fake), the reply's status.
    #[cfg(selftest)]
    Test { flags: u32 },
    /// Self-tests: the request id counter set to `id` (the wrap test).
    #[cfg(selftest)]
    TestNextId { id: u32 },
}

/// Self-tests: the partition skips its own range check (the first lock), so that the second
/// and the third lock are tested alone.
#[cfg(selftest)]
pub static TEST_SKIP_PARTITION_CHECK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

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
// – the remover first unmounts the file systems on the disk and its partitions (ublk.rs).
// An operation in progress holds an Arc of its disk object; a partition finds its parent by
// number AND identity (`uid`), so an old partition object never reaches a new disk that got
// the old number.

struct Disk {
    /// This disk object's identity – a counter that never repeats, unlike the number in the
    /// list (which a later disk may get).  A partition remembers its parent's `uid` and every
    /// operation checks it, so a partition of a removed disk never reaches the disk that got
    /// the same number afterwards.
    uid: u64,
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

static NEXT_UID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

static DISKS: crate::sched::spin::SpinLock<Vec<Option<Arc<Disk>>>> =
    crate::sched::spin::SpinLock::new("block list", crate::sched::spin::level::BLOCK, Vec::new());

fn disk(index: usize) -> Option<Arc<Disk>> {
    DISKS.lock().get(index).cloned().flatten()
}

/// Takes the next disk identity; None when the one after it would not fit (never 0, never
/// reused – the counter does not wrap).
fn take_uid() -> Option<u64> {
    use core::sync::atomic::Ordering;
    let mut cur = NEXT_UID.load(Ordering::SeqCst);
    loop {
        let next = cur.checked_add(1)?;
        match NEXT_UID.compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Some(cur),
            Err(v) => cur = v,
        }
    }
}

/// Self-tests: sets the next disk identity (the overflow test); returns the old value.
#[cfg(selftest)]
pub fn test_set_next_uid(v: u64) -> u64 {
    NEXT_UID.swap(v, core::sync::atomic::Ordering::SeqCst)
}

/// Adds a disk; returns its number (the first free one – e.g. after a removed USB disk).
/// None – the identity counter is used up (the disk is refused, never given an old identity).
pub fn register(device: Box<dyn BlockDevice>) -> Option<usize> {
    let uid = take_uid()?;
    let d = Arc::new(Disk {
        uid,
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
        return Some(i);
    }
    list.push(Some(d));
    Some(list.len() - 1)
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

/// The identity of the disk now at `index` (None – no disk there).
pub fn uid(index: usize) -> Option<u64> {
    disk(index).map(|d| d.uid)
}

/// Like `with_device`, but only if the disk at `index` is still the object `uid` – after a
/// removal and reuse of the number: NoDevice.
fn with_disk_uid<R>(index: usize, uid: u64, f: impl FnOnce(&mut dyn BlockDevice) -> R) -> Result<R, BlockError> {
    let d = disk(index).ok_or(BlockError::NoDevice)?;
    if d.uid != uid {
        return Err(BlockError::NoDevice);
    }
    let _g = d.lock.lock();
    Ok(f(unsafe { &mut **d.dev.get() }))
}

/// `read` / `write` / `flush` for a user that holds a disk by number AND identity (a DeSoFS
/// volume): after the disk was removed and its number reused – NoDevice, never the new disk.
pub fn read_as(index: usize, uid: u64, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
    with_disk_uid(index, uid, |d| d.read(lba, buf))?
}

pub fn write_as(index: usize, uid: u64, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
    with_disk_uid(index, uid, |d| if d.read_only() { Err(BlockError::ReadOnly) } else { d.write(lba, buf) })?
}

pub fn flush_as(index: usize, uid: u64) -> Result<(), BlockError> {
    with_disk_uid(index, uid, |d| if d.read_only() { Ok(()) } else { d.flush() })?
}

/// Self-tests: a disk object kept after it left the list (an operation that started before a
/// removal); `write` goes through the object itself.
#[cfg(selftest)]
pub struct Held(Arc<Disk>);

#[cfg(selftest)]
pub fn hold(index: usize) -> Option<Held> {
    disk(index).map(Held)
}

#[cfg(selftest)]
impl Held {
    pub fn write(&self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        let _g = self.0.lock.lock();
        unsafe { &mut **self.0.dev.get() }.write(lba, buf)
    }
    pub fn flush(&self) -> Result<(), BlockError> {
        let _g = self.0.lock.lock();
        unsafe { &mut **self.0.dev.get() }.flush()
    }
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

/// A write of a partition with a grant into its parent disk – only if the parent is still the
/// same object (`uid`); the disk checks it again.
fn write_part(index: usize, uid: u64, lba: u64, buf: &[u8], tag: u64) -> Result<(), BlockError> {
    with_disk_uid(index, uid, |d| d.write_range(lba, buf, tag))?
}

fn flush_part(index: usize, uid: u64, tag: u64) -> Result<(), BlockError> {
    with_disk_uid(index, uid, |d| d.flush_range(tag))?
}

/// Control of a USB disk (`Control`).
#[cfg_attr(not(selftest), allow(dead_code))]
pub fn control(index: usize, c: Control) -> Result<u64, BlockError> {
    with_device(index, |d| d.control(c))?
}

/// Partition `index`: (parent disk, start, length in the parent's DEVICE blocks).
pub fn partition_blocks(index: usize) -> Option<(usize, u64, u64)> {
    let (parent, range) = with_device(index, |d| (d.parent(), d.partition_range())).ok()?;
    let (parent, (start, sectors)) = (parent?, range?);
    let bs = with_device(parent, |d| d.logical_block_size()).ok()? as u64;
    let f = (bs / SECTOR_SIZE as u64).max(1);
    Some((parent, start / f, sectors / f))
}

/// The internal disk (V080 rule E): the first disk registered before the file systems start
/// (PCI: virtio-blk, then NVMe) – remembered by identity, never by number, so a USB disk
/// that later gets number 0 is never it.  0 = none.
static INTERNAL_UID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static INTERNAL_INDEX: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(usize::MAX);

/// Called once by `fs::init`: the internal disk is disk 0 if one is registered by then.
pub fn set_internal() {
    use core::sync::atomic::Ordering;
    if let Some(u) = uid(0) {
        INTERNAL_UID.store(u, Ordering::SeqCst);
        INTERNAL_INDEX.store(0, Ordering::SeqCst);
    }
}

/// The internal disk's number, if it is still the same object.
pub fn internal() -> Option<usize> {
    use core::sync::atomic::Ordering;
    let (i, u) = (INTERNAL_INDEX.load(Ordering::SeqCst), INTERNAL_UID.load(Ordering::SeqCst));
    if u != 0 && uid(i) == Some(u) { Some(i) } else { None }
}

/// Self-tests: makes disk `index` the internal disk (None – no internal disk); returns the old
/// setting for `test_restore_internal`.
#[cfg(selftest)]
pub fn test_set_internal(index: Option<usize>) -> (usize, u64) {
    use core::sync::atomic::Ordering;
    let old = (INTERNAL_INDEX.load(Ordering::SeqCst), INTERNAL_UID.load(Ordering::SeqCst));
    match index.and_then(|i| uid(i).map(|u| (i, u))) {
        Some((i, u)) => {
            INTERNAL_INDEX.store(i, Ordering::SeqCst);
            INTERNAL_UID.store(u, Ordering::SeqCst);
        }
        None => INTERNAL_UID.store(0, Ordering::SeqCst),
    }
    old
}

#[cfg(selftest)]
pub fn test_restore_internal(old: (usize, u64)) {
    use core::sync::atomic::Ordering;
    INTERNAL_INDEX.store(old.0, Ordering::SeqCst);
    INTERNAL_UID.store(old.1, Ordering::SeqCst);
}

/// Sets (Some(tag)) or clears (None) the write grant of partition `index`.
#[cfg_attr(not(selftest), allow(dead_code))]
pub fn set_grant(index: usize, grant: Option<u64>) -> Result<(), BlockError> {
    if with_device(index, |d| d.set_grant(grant))? {
        Ok(())
    } else {
        Err(BlockError::Unsupported)
    }
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
    /// The parent disk object's identity (`Disk::uid`) – checked by every operation.
    parent_uid: u64,
    /// Start and length in 512 B sectors.
    start: u64,
    sectors: u64,
    read_only: bool,
    /// Write grant on a read-only disk (USB): Some(0) rw, Some(session) format.
    grant: Option<u64>,
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
            match (self.read_only, self.grant) {
                (false, _) => "",
                (true, None) => ", read-only",
                (true, Some(0)) => ", read-write (granted)",
                (true, Some(_)) => ", being formatted",
            }
        )
    }
    fn sector_count(&self) -> u64 {
        self.sectors
    }
    fn read_only(&self) -> bool {
        self.read_only && self.grant.is_none()
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
        with_disk_uid(self.parent, self.parent_uid, |d| d.read(self.start + lba, buf))?
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        // The first of the three locks: the partition's own range (with a grant – before
        // anything goes to the disk).
        #[cfg(selftest)]
        let skip = TEST_SKIP_PARTITION_CHECK.load(core::sync::atomic::Ordering::SeqCst) && self.grant.is_some();
        #[cfg(not(selftest))]
        let skip = false;
        if !skip {
            check_range(self.sectors, lba, buf.len())?;
        } else if buf.is_empty() || buf.len() % SECTOR_SIZE != 0 {
            return Err(BlockError::BadBuffer);
        }
        let abs = self.start.checked_add(lba).ok_or(BlockError::OutOfRange)?;
        match (self.read_only, self.grant) {
            (false, _) => with_disk_uid(self.parent, self.parent_uid, |d| if d.read_only() { Err(BlockError::ReadOnly) } else { d.write(abs, buf) })?,
            (true, Some(tag)) => write_part(self.parent, self.parent_uid, abs, buf, tag),
            (true, None) => Err(BlockError::ReadOnly),
        }
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        match (self.read_only, self.grant) {
            (true, Some(tag)) => flush_part(self.parent, self.parent_uid, tag),
            _ => with_disk_uid(self.parent, self.parent_uid, |d| if d.read_only() { Ok(()) } else { d.flush() })?,
        }
    }
    fn write_range(&mut self, lba: u64, buf: &[u8], tag: u64) -> Result<(), BlockError> {
        // Only a whole disk takes partition writes.
        let _ = (lba, buf, tag);
        Err(BlockError::ReadOnly)
    }
    fn flush_range(&mut self, _tag: u64) -> Result<(), BlockError> {
        Err(BlockError::ReadOnly)
    }
    fn partition_range(&self) -> Option<(u64, u64)> {
        Some((self.start, self.sectors))
    }
    fn set_grant(&mut self, grant: Option<u64>) -> bool {
        // A grant only where the disk itself is read-only (USB); elsewhere nothing changes.
        if self.read_only {
            self.grant = grant;
        }
        true
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
    let Some(parent_uid) = uid(disk) else { return 0 };
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
            parent_uid,
            start: p.first_sector,
            sectors: p.sectors,
            read_only,
            grant: None,
            block_size,
            kind: p.kind,
            label: p.name.clone(),
        };
        let Some(index) = register(Box::new(part)) else {
            crate::serial_println!("[BLK] {}: disk identities used up - partition {} not registered", name, pname);
            continue;
        };
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
// RAM disk in physical frames (`desofs ramdisk <MiB>`): a writable disk on a computer
// whose own disks stay read-only (DeSoFS and the soak test on real hardware).  Its frames
// stay taken until the next start – there is no way to remove it (its contents are lost
// at power-off anyway).
// ------------------------------------------------------------

pub const RAM_DISK_MAX_MIB: u64 = 1024;
const RAM_DISKS_MAX: usize = 4;
static RAM_DISKS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub struct FrameDisk {
    name: String,
    /// Physical address of every 4 KiB page of the disk, in order.
    frames: Vec<u64>,
}

impl FrameDisk {
    /// Copies between `buf` and the disk at byte `off`, page by page.
    fn each(&mut self, off: usize, len: usize, mut f: impl FnMut(&mut [u8], core::ops::Range<usize>)) {
        let mut done = 0;
        while done < len {
            let (k, o) = ((off + done) / 4096, (off + done) % 4096);
            let n = (4096 - o).min(len - done);
            let page = unsafe { core::slice::from_raw_parts_mut(crate::memory::phys_to_virt(self.frames[k]) as *mut u8, 4096) };
            f(&mut page[o..o + n], done..done + n);
            done += n;
        }
    }
}

impl Drop for FrameDisk {
    /// Only when it was never registered (a RAM disk is never removed).
    fn drop(&mut self) {
        for &f in &self.frames {
            crate::memory::free_frame(f);
        }
    }
}

impl BlockDevice for FrameDisk {
    fn name(&self) -> &str {
        &self.name
    }
    fn description(&self) -> String {
        alloc::format!("RAM disk, {} MiB (gone at power-off)", self.frames.len() as u64 * 4096 / (1024 * 1024))
    }
    fn sector_count(&self) -> u64 {
        self.frames.len() as u64 * (4096 / SECTOR_SIZE as u64)
    }
    fn read_only(&self) -> bool {
        false
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        check_range(self.sector_count(), lba, buf.len())?;
        self.each(lba as usize * SECTOR_SIZE, buf.len(), |disk, r| buf[r].copy_from_slice(disk));
        Ok(())
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        check_range(self.sector_count(), lba, buf.len())?;
        self.each(lba as usize * SECTOR_SIZE, buf.len(), |disk, r| disk.copy_from_slice(&buf[r]));
        Ok(())
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
}

/// A new zeroed RAM disk of `mib` MiB; Ok(disk number).  Refused: a size outside
/// 1..=RAM_DISK_MAX_MIB, more than RAM_DISKS_MAX of them, or less than a quarter of the free
/// memory (and at least 64 MiB) left afterwards for everything else.
pub fn create_ram_disk(mib: u64) -> Result<usize, String> {
    use core::sync::atomic::Ordering;
    if !(1..=RAM_DISK_MAX_MIB).contains(&mib) {
        return Err(alloc::format!("size must be 1-{} MiB", RAM_DISK_MAX_MIB));
    }
    let pages = mib * 256;
    let free = crate::memory::free_frame_count();
    let keep = (free / 4).max(64 * 256);
    if free < pages + keep {
        return Err(alloc::format!("not enough memory: {} MiB free, {} MiB must stay free", free / 256, keep / 256));
    }
    let n = RAM_DISKS.fetch_add(1, Ordering::SeqCst);
    if n >= RAM_DISKS_MAX {
        RAM_DISKS.fetch_sub(1, Ordering::SeqCst);
        return Err(alloc::format!("at most {} RAM disks", RAM_DISKS_MAX));
    }
    let mut frames: Vec<u64> = Vec::new();
    if frames.try_reserve_exact(pages as usize).is_err() {
        RAM_DISKS.fetch_sub(1, Ordering::SeqCst);
        return Err(String::from("not enough kernel heap"));
    }
    for _ in 0..pages {
        match crate::memory::alloc_frame() {
            Some(f) => {
                unsafe { core::ptr::write_bytes(crate::memory::phys_to_virt(f) as *mut u8, 0, 4096) };
                frames.push(f);
            }
            None => {
                for f in frames {
                    crate::memory::free_frame(f);
                }
                RAM_DISKS.fetch_sub(1, Ordering::SeqCst);
                return Err(String::from("not enough memory"));
            }
        }
    }
    match register(Box::new(FrameDisk { name: alloc::format!("ram{}", n), frames })) {
        Some(i) => Ok(i),
        None => {
            RAM_DISKS.fetch_sub(1, Ordering::SeqCst);
            Err(String::from("disk identities used up"))
        }
    }
}

// ------------------------------------------------------------

/// Contents in 64 KiB pieces, not one block: a 16 MiB test disk is then 256 small heap
/// blocks instead of one 16 MiB block, which a fragmented heap (e.g. right after the heap
/// reserve test filled it) may not have.
#[cfg(selftest)]
const RAM_CHUNK: usize = 64 * 1024;

#[cfg(selftest)]
pub struct RamDisk {
    name: String,
    sectors: u64,
    chunks: Vec<Vec<u8>>,
}

#[cfg(selftest)]
impl RamDisk {
    pub fn new(name: &str, sectors: u64) -> Self {
        let bytes = sectors as usize * SECTOR_SIZE;
        let chunks = (0..bytes.div_ceil(RAM_CHUNK)).map(|k| alloc::vec![0u8; RAM_CHUNK.min(bytes - k * RAM_CHUNK)]).collect();
        RamDisk { name: String::from(name), sectors, chunks }
    }

    /// Copies between `buf` and the disk at byte `off`, piece by piece.
    fn each(&mut self, off: usize, len: usize, mut f: impl FnMut(&mut [u8], core::ops::Range<usize>)) {
        let mut done = 0;
        while done < len {
            let (k, o) = ((off + done) / RAM_CHUNK, (off + done) % RAM_CHUNK);
            let n = (RAM_CHUNK - o).min(len - done);
            f(&mut self.chunks[k][o..o + n], done..done + n);
            done += n;
        }
    }
}

#[cfg(selftest)]
impl BlockDevice for RamDisk {
    fn name(&self) -> &str {
        &self.name
    }
    fn description(&self) -> String {
        alloc::format!("RAM disk, {} KiB", self.sectors * SECTOR_SIZE as u64 / 1024)
    }
    fn sector_count(&self) -> u64 {
        self.sectors
    }
    fn read_only(&self) -> bool {
        false
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        check_range(self.sector_count(), lba, buf.len())?;
        self.each(lba as usize * SECTOR_SIZE, buf.len(), |disk, r| buf[r].copy_from_slice(disk));
        Ok(())
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        check_range(self.sector_count(), lba, buf.len())?;
        self.each(lba as usize * SECTOR_SIZE, buf.len(), |disk, r| disk.copy_from_slice(&buf[r]));
        Ok(())
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
}


