// ublk – in-kernel USB disk.  Design: ARCHITECTURE.md, section "Disk – `ublk` and the request protocol".
//
// usbd (user space) drives the flash drive (Bulk-Only + SCSI) and registers it
// with syscall 50 `blk_attach(BLK, channel, buffer, info)`.  The kernel sees a regular
// `BlockDevice` ("sda", "sdb", …) – always READ-ONLY – and turns every read
// into a request sent over the channel to usbd; the flash drive writes the data via DMA
// straight into the shared buffer (no copy in usbd), and the kernel copies it from there.
//
// Protocol (channel – control, buffer – data):
//   kernel -> usbd (32 B): id u32, op u32 (1 = READ, there are no others), lba u64
//                         (device blocks), blocks u32, slot u32, 8 B zero
//   usbd -> kernel (≥ 12 B): id u32, status i32 (0, ERROR_IO, ERROR_NO_DEVICE), blocks u32
// * The buffer is split into 64 KiB slots (1..8), one slot per request.  Slot:
//   free -> owned by usbd (request sent) -> free after a reply with this `id`,
//   status 0 and the requested block count (only then does the kernel copy the data).
//   Any other reply (someone else's / unknown `id`, wrong block count, message too
//   short) – rejected, protocol error counter incremented.
// * Timeout (5 s; a test may set a shorter one): ERROR_IO for the reader, slot in
//   QUARANTINE – the device may still write to it.  It returns to the pool after a
//   late reply with this `id` or never (the disk disappears along with the buffer).
// * 3 timeouts in a row, a closed channel (usbd exit) or status ERROR_NO_DEVICE
//   (flash drive removed) = the disk DISAPPEARS: further reads – NoDevice.
// * Kernel task `usb-disks` (monitor): new disk -> GPT partitions, FAT32 ->
//   /usb0, /usb1, … (read-only); disk gone -> unmount, remove the
//   partitions and the disk, free the buffer and channel (the disk number returns to the pool).
//
// Read-only – three independent locks: usbd has no SCSI write command,
// the protocol has no write operation, this disk reports read_only (the block
// layer rejects writes before they reach the driver) – and `write` here refuses too.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use super::channel::{ChanEnd, Message};
use super::shm::ShmObj;
use super::syscalls::{ERROR_INTERRUPTED, ERROR_NO_DEVICE, ERROR_NO_SPACE, ERROR_CLOSED, ERROR_TIMED_OUT};
use crate::block::{self, check_range, BlockDevice, BlockError, SECTOR_SIZE};
use crate::sched::spin::{level, SpinLock};
use crate::sched::sync::WaitQueue;

/// Buffer slot size (one request).
pub const SLOT_BYTES: usize = 64 * 1024;
/// Maximum slots per disk.
pub const SLOTS_MAX: usize = 8;
/// Maximum USB disks at once.
pub const DISKS_MAX: usize = 8;
/// Default per-request timeout (a flash drive can take seconds to wake up).
pub const TIMEOUT_MS: u64 = 5000;
/// This many timeouts in a row = the disk is gone.
const TIMEOUTS_GONE: u32 = 3;
const OP_READ: u32 = 1;

const NEW: u8 = 0;
const READY: u8 = 1;

/// Shared disk state – read by the monitor and tests without the disk lock (a read
/// may hold it for up to 5 s).
pub struct Shared {
    /// sda = 0, sdb = 1, … (only grows, never reused).
    #[allow(dead_code)]
    pub num: u64,
    pub name: String,
    pub desc: String,
    chan: Arc<ChanEnd>,
    gone: AtomicBool,
    state: AtomicU8,
    /// Number in the block layer.
    pub index: AtomicUsize,
    pub reads: AtomicU64,
    pub bytes: AtomicU64,
    pub timeouts: AtomicU64,
    pub proto_errors: AtomicU64,
    pub late: AtomicU64,
    /// Mount points (/usb0, …) – changed only by the monitor.
    mounts: SpinLock<Vec<String>>,
}

impl Shared {
    pub fn gone(&self) -> bool {
        self.gone.load(Ordering::SeqCst)
    }

    /// The monitor has already checked partitions and mounted what it could (self-tests).
    #[cfg_attr(not(selftest), allow(dead_code))]
    pub fn probed(&self) -> bool {
        self.state.load(Ordering::SeqCst) == READY
    }

    /// Mount points (self-tests).
    #[cfg_attr(not(selftest), allow(dead_code))]
    pub fn mounts(&self) -> Vec<String> {
        self.mounts.lock().clone()
    }

    fn set_gone(&self) {
        if !self.gone.swap(true, Ordering::SeqCst) {
            wake_monitor();
        }
    }
}

static REGISTRY: SpinLock<Vec<Arc<Shared>>> = SpinLock::new("ublk registry", level::BLOCK, Vec::new());
static NEXT_NUM: AtomicU64 = AtomicU64::new(0);
static MONITOR_GEN: AtomicU64 = AtomicU64::new(0);
static MONITOR_WAKE: WaitQueue = WaitQueue::new();
static MONITOR_STARTED: AtomicBool = AtomicBool::new(false);

fn wake_monitor() {
    MONITOR_GEN.fetch_add(1, Ordering::SeqCst);
    MONITOR_WAKE.wake_all();
}

/// Name as in Linux: 0 -> sda, 25 -> sdz, 26 -> sdaa.
pub fn disk_name(mut n: u64) -> String {
    let mut letters = Vec::new();
    loop {
        letters.push(b'a' + (n % 26) as u8);
        if n < 26 {
            break;
        }
        n = n / 26 - 1;
    }
    letters.reverse();
    let mut s = String::from("sd");
    s.push_str(core::str::from_utf8(&letters).unwrap_or("?"));
    s
}

/// USB disks present in the kernel (tests, `disk`).
pub fn list() -> Vec<Arc<Shared>> {
    REGISTRY.lock().clone()
}

pub fn count() -> usize {
    REGISTRY.lock().len()
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Slot {
    Free,
    Busy(u32),
    Quarantine(u32),
}

struct Ublk {
    sh: Arc<Shared>,
    buf: Arc<ShmObj>,
    blocks: u64,
    bs: u32,
    slots: [Slot; SLOTS_MAX],
    nslots: usize,
    next_id: u32,
    timeout_ms: u64,
    timeouts_row: u32,
}

/// Copy from the buffer (object frames; DMA – contiguous, but we do not assume it).
fn copy_out(obj: &ShmObj, mut off: usize, dst: &mut [u8]) {
    let frames = obj.frames();
    let mut done = 0;
    while done < dst.len() {
        let (pi, po) = (off / 4096, off % 4096);
        let n = (4096 - po).min(dst.len() - done);
        let src = (crate::memory::phys_to_virt(frames[pi]) as usize + po) as *const u8;
        unsafe { core::ptr::copy_nonoverlapping(src, dst[done..].as_mut_ptr(), n) };
        done += n;
        off += n;
    }
}

fn le32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// Request in flight – where it lands in the reader's buffer.
#[derive(Clone, Copy)]
struct InFlight {
    id: u32,
    n: u32,
    /// Offset in the reader's buffer, bytes skipped at the start of the slot, length.
    at: usize,
    skip: usize,
    len: usize,
}

impl Ublk {
    /// Sends a request for `n` blocks from `first` into free slot `slot`.
    fn send(&mut self, slot: usize, first: u64, n: u32) -> Result<u32, BlockError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let mut data = alloc::vec![0u8; 32];
        data[0..4].copy_from_slice(&id.to_le_bytes());
        data[4..8].copy_from_slice(&OP_READ.to_le_bytes());
        data[8..16].copy_from_slice(&first.to_le_bytes());
        data[16..20].copy_from_slice(&n.to_le_bytes());
        data[20..24].copy_from_slice(&(slot as u32).to_le_bytes());
        if let Err((e, _)) = self.sh.chan.send(Message { data, handles: Vec::new(), sender: 0 }, true) {
            if e == ERROR_CLOSED {
                self.sh.set_gone();
                return Err(BlockError::NoDevice);
            }
            return Err(BlockError::Io); // usbd queue full
        }
        self.slots[slot] = Slot::Busy(id);
        Ok(id)
    }

    /// Pipelined read – up to `nslots` requests at once (usbd sends the next
    /// SCSI command right after the previous one, without waiting for the kernel).  Slot data
    /// is copied only after a valid reply with this `id` and block count.
    /// Reply error: no new requests go out, we wait for the sent ones (slots
    /// return to the pool); timeout: sent slots go to quarantine.
    fn read_pipelined(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        let bs = self.bs as usize;
        let f = (bs / SECTOR_SIZE) as u64;
        let per = SLOT_BYTES / bs;
        let mut fl: [Option<InFlight>; SLOTS_MAX] = [None; SLOTS_MAX];
        let mut planned = 0usize;
        let mut copied = 0usize;
        let mut error: Option<BlockError> = None;
        let mut deadline = crate::time::ticks() + crate::time::ms_to_ticks(self.timeout_ms);
        loop {
            // New requests into free slots.
            while error.is_none() && planned < buf.len() {
                let Some(slot) = self.slots[..self.nslots].iter().position(|s| *s == Slot::Free) else { break };
                let s512 = lba + (planned / SECTOR_SIZE) as u64;
                let first = s512 / f;
                let skip = ((s512 % f) as usize) * SECTOR_SIZE;
                let want = buf.len() - planned;
                let n = (skip + want).div_ceil(bs).min(per);
                let len = (n * bs - skip).min(want);
                match self.send(slot, first, n as u32) {
                    Ok(id) => {
                        fl[slot] = Some(InFlight { id, n: n as u32, at: planned, skip, len });
                        planned += len;
                    }
                    Err(BlockError::NoDevice) => return Err(BlockError::NoDevice),
                    Err(e) => error = Some(e),
                }
            }
            if fl.iter().all(|x| x.is_none()) {
                if let Some(e) = error {
                    return Err(e);
                }
                if copied >= buf.len() {
                    return Ok(());
                }
                // No free slot (all quarantined – the device is silent).
                return Err(BlockError::Io);
            }
            let left = deadline.saturating_sub(crate::time::ticks());
            let r = if left == 0 { Err(ERROR_TIMED_OUT) } else { self.sh.chan.recv_timeout(left * 1000 / crate::time::HZ as u64) };
            match r {
                Ok(m) => {
                    if m.data.len() < 12 {
                        self.sh.proto_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let (rid, status, cnt) = (le32(&m.data, 0), le32(&m.data, 4) as i32 as i64, le32(&m.data, 8));
                    if let Some(slot) = (0..SLOTS_MAX).find(|&i| fl[i].map_or(false, |x| x.id == rid)) {
                        let x = fl[slot].unwrap();
                        if status == 0 && cnt != x.n {
                            // Wrong block count – rejected; keep waiting (or time out).
                            self.sh.proto_errors.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        fl[slot] = None;
                        self.timeouts_row = 0;
                        deadline = crate::time::ticks() + crate::time::ms_to_ticks(self.timeout_ms);
                        if status == 0 {
                            if error.is_none() {
                                copy_out(&self.buf, slot * SLOT_BYTES + x.skip, &mut buf[x.at..x.at + x.len]);
                                copied += x.len;
                            }
                            self.slots[slot] = Slot::Free;
                            continue;
                        }
                        self.slots[slot] = Slot::Free;
                        if status == ERROR_NO_DEVICE {
                            self.sh.set_gone();
                            return Err(BlockError::NoDevice);
                        }
                        error.get_or_insert(BlockError::Io);
                        continue;
                    }
                    if let Some(q) = self.slots.iter().position(|s| *s == Slot::Quarantine(rid)) {
                        // Late reply after a timeout – the slot returns, data discarded.
                        self.slots[q] = Slot::Free;
                        self.sh.late.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    self.sh.proto_errors.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) if e == ERROR_TIMED_OUT || e == ERROR_INTERRUPTED => {
                    for (slot, x) in fl.iter().enumerate() {
                        if let Some(x) = x {
                            self.slots[slot] = Slot::Quarantine(x.id);
                        }
                    }
                    if e == ERROR_TIMED_OUT {
                        self.sh.timeouts.fetch_add(1, Ordering::Relaxed);
                        self.timeouts_row += 1;
                        if self.timeouts_row >= TIMEOUTS_GONE {
                            self.sh.set_gone();
                        }
                    }
                    return Err(BlockError::Timeout);
                }
                Err(_) => {
                    for (slot, x) in fl.iter().enumerate() {
                        if x.is_some() {
                            self.slots[slot] = Slot::Free;
                        }
                    }
                    self.sh.set_gone();
                    return Err(BlockError::NoDevice);
                }
            }
        }
    }
}

impl BlockDevice for Ublk {
    fn name(&self) -> &str {
        &self.sh.name
    }
    fn description(&self) -> String {
        alloc::format!(
            "USB disk \"{}\", {} MiB, {}-byte blocks, read-only{}",
            self.sh.desc,
            self.sector_count() * SECTOR_SIZE as u64 / (1024 * 1024),
            self.bs,
            if self.sh.gone() { ", removed" } else { "" }
        )
    }
    fn sector_count(&self) -> u64 {
        self.blocks * (self.bs as u64 / SECTOR_SIZE as u64)
    }
    fn read_only(&self) -> bool {
        true
    }
    fn logical_block_size(&self) -> usize {
        self.bs as usize
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        check_range(self.sector_count(), lba, buf.len())?;
        if self.sh.gone() {
            return Err(BlockError::NoDevice);
        }
        self.read_pipelined(lba, buf)?;
        self.sh.reads.fetch_add(1, Ordering::Relaxed);
        self.sh.bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
        Ok(())
    }
    fn write(&mut self, _lba: u64, _buf: &[u8]) -> Result<(), BlockError> {
        Err(BlockError::ReadOnly)
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
}

/// blk_attach: new USB disk.  Result: number (0 = sda).  ERROR_NO_SPACE – 8 disks.
pub fn attach(chan: Arc<ChanEnd>, buf: Arc<ShmObj>, blocks: u64, bs: u32, slots: usize, timeout_ms: u64, desc: String) -> Result<u64, i64> {
    if count() >= DISKS_MAX {
        return Err(ERROR_NO_SPACE);
    }
    let num = NEXT_NUM.fetch_add(1, Ordering::SeqCst);
    let sh = Arc::new(Shared {
        num,
        name: disk_name(num),
        desc,
        chan,
        gone: AtomicBool::new(false),
        state: AtomicU8::new(NEW),
        index: AtomicUsize::new(usize::MAX),
        reads: AtomicU64::new(0),
        bytes: AtomicU64::new(0),
        timeouts: AtomicU64::new(0),
        proto_errors: AtomicU64::new(0),
        late: AtomicU64::new(0),
        mounts: SpinLock::new("ublk mounts", level::BLOCK, Vec::new()),
    });
    let dev = Ublk {
        sh: sh.clone(),
        buf,
        blocks,
        bs,
        slots: [Slot::Free; SLOTS_MAX],
        nslots: slots,
        next_id: 1,
        timeout_ms,
        timeouts_row: 0,
    };
    let index = block::register(Box::new(dev));
    sh.index.store(index, Ordering::SeqCst);
    crate::serial_println!(
        "[USB] {}: \"{}\", {} MiB, {}-byte blocks, read-only (disk {})",
        sh.name,
        sh.desc,
        blocks * bs as u64 / (1024 * 1024),
        bs,
        index
    );
    REGISTRY.lock().push(sh);
    start_monitor();
    wake_monitor();
    Ok(num)
}

// ------------------------------------------------------------
// Monitor: mounting new disks, cleanup after removal
// ------------------------------------------------------------

pub fn start_monitor() {
    if MONITOR_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    if crate::sched::spawn("usb-disks", monitor, 0).is_err() {
        MONITOR_STARTED.store(false, Ordering::SeqCst);
        crate::serial_println!("[USB] cannot start the usb-disks task - USB disks will not be mounted");
    }
}

fn monitor(_: usize) {
    loop {
        let seen = MONITOR_GEN.load(Ordering::SeqCst);
        for sh in list() {
            if !sh.gone() && sh.chan.peer_closed() {
                sh.set_gone();
            }
            if sh.state.load(Ordering::SeqCst) == NEW {
                probe(&sh);
                sh.state.store(READY, Ordering::SeqCst);
            }
            if sh.gone() {
                remove(&sh);
                REGISTRY.lock().retain(|x| !Arc::ptr_eq(x, &sh));
            }
        }
        // usbd closing the channel does not wake this task – while disks are
        // present we check every 200 ms.
        let timeout = if count() > 0 { Some(200) } else { None };
        MONITOR_WAKE.wait_until(|| MONITOR_GEN.load(Ordering::SeqCst) != seen, timeout);
    }
}

/// GPT and FAT32 partitions -> /usbN (first free).  Without GPT: the whole disk or
/// the first FAT32 partition from the MBR (as with /disk).
fn probe(sh: &Shared) {
    let index = sh.index.load(Ordering::SeqCst);
    if sh.gone() {
        return; // usbd exited before we got to look
    }
    block::scan_partitions(index);
    let parts = block::partitions_of(index);
    let targets: Vec<usize> = if parts.is_empty() { alloc::vec![index] } else { parts };
    let mut why = String::new();
    for i in targets {
        if sh.gone() {
            break;
        }
        match crate::fs::fat32::Fat32::open(i) {
            Ok(fs) => {
                let source = crate::fs::FileSystem::source(&fs);
                let Some(path) = free_mount_point() else {
                    why = String::from("no free /usbN");
                    break;
                };
                let _ = crate::fs::mkdir(&path);
                // Own lock – waiting on the flash drive does not stall the rest of the VFS.
                match crate::fs::mount(&path, Box::new(crate::fs::Locked::new(fs))) {
                    Ok(()) => {
                        crate::serial_println!("[USB] {}: {} = fat32 ({}), read-only", sh.name, path, source);
                        sh.mounts.lock().push(path);
                    }
                    Err(e) => {
                        let _ = crate::fs::remove(&path);
                        why = alloc::format!("mount {}: {}", path, e);
                    }
                }
            }
            Err(e) => why = alloc::format!("{}", e),
        }
    }
    if sh.mounts.lock().is_empty() {
        crate::serial_println!("[USB] {}: not mounted ({})", sh.name, if why.is_empty() { "no FAT32 file system" } else { &why });
    }
}

fn free_mount_point() -> Option<String> {
    (0..16).map(|n| alloc::format!("/usb{}", n)).find(|p| crate::fs::stat(p).is_err())
}

/// Disk gone: unmount (no write-back – the disk is read-only anyway),
/// remove the partitions and the disk (buffer freed, number back to the pool).
fn remove(sh: &Shared) {
    let mounts: Vec<String> = core::mem::take(&mut *sh.mounts.lock());
    for m in &mounts {
        let _ = crate::fs::unmount_lost(m);
        let _ = crate::fs::remove(m);
    }
    let index = sh.index.load(Ordering::SeqCst);
    for p in block::partitions_of(index) {
        block::remove(p);
    }
    block::remove(index);
    crate::serial_println!(
        "[USB] {}: removed{} (reads {}, timeouts {}, protocol errors {})",
        sh.name,
        if mounts.is_empty() { String::new() } else { alloc::format!(", {} unmounted", mounts.join(" ")) },
        sh.reads.load(Ordering::Relaxed),
        sh.timeouts.load(Ordering::Relaxed),
        sh.proto_errors.load(Ordering::Relaxed)
    );
}

/// Measures reading a file from a USB disk with buffer size `bufsize` (at most `max`
/// bytes): (bytes, µs, checksum – the same for every buffer size if
/// the data is the same).  Used by autostress and USB TEST 7/7.
pub fn read_bench(path: &str, bufsize: usize, max: u64) -> Result<(u64, u64, u64), crate::fs::FsError> {
    let mut buf = alloc::vec![0u8; bufsize];
    let t0 = crate::arch::x86_64::clock::stamp();
    let mut off = 0u64;
    let mut sum = 0u64;
    while off < max {
        let want = ((max - off) as usize).min(bufsize);
        let n = crate::fs::read(path, off, &mut buf[..want])?;
        if n == 0 {
            break;
        }
        for (i, &b) in buf[..n].iter().enumerate() {
            sum = sum.wrapping_mul(31).wrapping_add(b as u64 ^ (off + i as u64));
        }
        off += n as u64;
    }
    Ok((off, crate::arch::x86_64::clock::elapsed_us(t0).max(1), sum))
}
