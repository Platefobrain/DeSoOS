// ublk – in-kernel USB disk.  Design: docs/ARCHITECTURE.md, sections "Disk – `ublk` and the
// request protocol" and "Writing to a USB disk".
//
// usbd (user space) drives the flash drive (Bulk-Only + SCSI) and registers it
// with syscall 50 `blk_attach(BLK, channel, buffer, info)`.  The kernel sees a regular
// `BlockDevice` ("sda", "sdb", …) – READ-ONLY AS A WHOLE, always – and turns every read
// into a request sent over the channel to usbd; the flash drive writes the data via DMA
// straight into the shared buffer (no copy in usbd), and the kernel copies it from there.
//
// Protocol (channel – control, buffer – data).  Kernel -> usbd, 48 B:
//   0 id u32, 4 op u32, 8 lba u64 (absolute device blocks), 16 blocks u32, 20 slot u32,
//   24 generation u64 (this disk's generation), 32 session u64, 40 len u64
//   op 1 READ  – `blocks` from `lba` into `slot`
//   op 2 WRITE – `blocks` from `slot` to `lba` (generation, session: 0 rw, else the format session)
//   op 3 FLUSH – SYNCHRONIZE CACHE (generation, session)
//   op 4 REG   – a registration: `blocks` = kind (0 withdraw, 1 probe, 2 rw, 3 format),
//                `lba` / `len` = the range (rw, format; 0 / 0 for a probe), `session` (format),
//                `slot` = the FLUSH limit of a probe (1)
//   op 9 TEST  – self-test builds only: `blocks` = test flags for the device
// usbd -> kernel (≥ 12 B): id u32, status i32 (0, ERROR_IO, ERROR_NO_DEVICE), blocks u32
// * The buffer is split into 64 KiB slots (1..8), one slot per READ / WRITE.  Slot:
//   free -> owned by usbd (request sent) -> free after a reply with this `id`,
//   status 0 and the requested block count (only then does the kernel copy read data).
//   Any other reply (someone else's / unknown `id`, wrong block count, message too
//   short) – rejected, protocol error counter incremented.
// * Timeout (5 s; a test may set a shorter one): ERROR_IO / Timeout for the caller, slot in
//   QUARANTINE – the device may still use it.  It returns to the pool after a
//   late reply with this `id` or never (the disk disappears along with the buffer).  A
//   FLUSH / REG that timed out leaves its `id` in a short "stale" list: its late reply is
//   discarded, never taken as an answer to a later request.
// * 3 timeouts in a row, a closed channel (usbd exit) or status ERROR_NO_DEVICE
//   (flash drive removed) = the disk DISAPPEARS: further requests – NoDevice.
// * Kernel task `usb-disks` (monitor): new disk -> GPT partitions, FAT32 ->
//   /usb0, /usb1, … (read-only); disk gone -> unmount, remove the
//   partitions and the disk, free the buffer and channel (the disk number returns to the pool).
//
// Writing (v0.80, rules A–G of the V080 plan): the disk as a whole never takes a write
// (`read_only` = true, the block layer refuses before the driver).  Only a partition with a
// GRANT from the kernel writes – through `write_range` / `flush_range` here, and only inside
// THE registration this disk holds: at most one at a time, created and withdrawn only by the
// kernel (`control`), each a message usbd checks on its own too:
//   probe  – exactly one FLUSH, no WRITE (before the full rules: is FLUSH confirmed at all?)
//   rw     – WRITE inside [start, start + len) and FLUSH (after the full rules)
//   format – WRITE / FLUSH only with that session's identifier (`desofs format`)
// Three independent locks against a write outside the partition: the partition object
// (its range), this disk (the registration, every 64 KiB piece), usbd (its copy of the
// registration, every SCSI command).  The generation (a counter that never repeats a
// value) ties a registration to one instance of the device: a stick removed and another
// one plugged in under the same number gets a new generation and starts with none.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use super::channel::{ChanEnd, Message};
use super::shm::ShmObj;
use super::syscalls::{ERROR_INTERRUPTED, ERROR_NO_DEVICE, ERROR_NO_SPACE, ERROR_CLOSED, ERROR_TIMED_OUT};
use crate::block::{self, check_range, BlockDevice, BlockError, Control, SECTOR_SIZE};
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
/// Request size (kernel -> usbd).
pub const MSG_BYTES: usize = 48;
pub const OP_READ: u32 = 1;
pub const OP_WRITE: u32 = 2;
pub const OP_FLUSH: u32 = 3;
pub const OP_REG: u32 = 4;
#[cfg(selftest)]
pub const OP_TEST: u32 = 9;
pub const REG_NONE: u32 = 0;
pub const REG_PROBE: u32 = 1;
pub const REG_RW: u32 = 2;
pub const REG_FORMAT: u32 = 3;
/// Write protection as usbd reported it in blk_attach (0 – unknown: never written).
pub const WP_UNKNOWN: u8 = 0;
pub const WP_CLEAR: u8 = 1;
pub const WP_SET: u8 = 2;
/// Timed-out FLUSH / REG requests whose late replies are awaited (discarded); that many – the
/// disk is gone (an id is never dropped from the list while the disk lives).
const STALE_MAX: usize = 16;

const NEW: u8 = 0;
const READY: u8 = 1;

/// Shared disk state – read by the monitor and tests without the disk lock (a read
/// may hold it for up to 5 s).
pub struct Shared {
    /// sda = 0, sdb = 1, … (only grows, never reused).
    #[allow(dead_code)]
    pub num: u64,
    /// The generation of this instance (never repeated, never 0).
    pub generation: u64,
    /// Write protection (WP_*).
    pub wp: u8,
    pub name: String,
    pub desc: String,
    chan: Arc<ChanEnd>,
    gone: AtomicBool,
    state: AtomicU8,
    /// Number in the block layer.
    pub index: AtomicUsize,
    pub reads: AtomicU64,
    pub bytes: AtomicU64,
    pub writes: AtomicU64,
    pub wbytes: AtomicU64,
    pub flushes: AtomicU64,
    /// Requests the kernel itself refused (the second lock) – nothing was sent.
    pub refused: AtomicU64,
    pub timeouts: AtomicU64,
    pub proto_errors: AtomicU64,
    pub late: AtomicU64,
    /// Mount points (/usb0, …, /disk) – changed only by the monitor.
    mounts: SpinLock<Vec<String>>,
    /// The partition (block number) this stick holds /disk with (usize::MAX – none).
    disk_part: AtomicUsize,
    /// DeSoFS partitions mounted read-only under /usbN.
    ro_dsfs: SpinLock<Vec<(String, usize)>>,
    /// Failed read-only mounts per partition (given up after `RO_TRIES`).
    ro_fail: SpinLock<Vec<(usize, u8)>>,
    /// Partitions the user unmounted: never mounted again by themselves (this plug-in).
    user_off: SpinLock<Vec<usize>>,
}

/// Read-only mounts of one partition tried this often before giving up (a damaged volume
/// fails every time; an I/O hiccup once).
pub(super) const RO_TRIES: u8 = 3;

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

    /// The partition this stick holds /disk with.
    pub fn disk_part(&self) -> Option<usize> {
        match self.disk_part.load(Ordering::SeqCst) {
            usize::MAX => None,
            p => Some(p),
        }
    }

    /// /disk no longer held (unmounted): true when it was.
    pub(super) fn clear_disk_part(&self) -> bool {
        let was = self.disk_part.swap(usize::MAX, Ordering::SeqCst) != usize::MAX;
        self.mounts.lock().retain(|m| m != crate::time_lkg::SYSTEM_MOUNT);
        was
    }

    pub(super) fn ro_mounts(&self) -> Vec<(String, usize)> {
        self.ro_dsfs.lock().clone()
    }

    pub(super) fn set_disk_part(&self, part: usize) {
        self.disk_part.store(part, Ordering::SeqCst);
        self.mounts.lock().push(String::from(crate::time_lkg::SYSTEM_MOUNT));
    }

    pub(super) fn ro_mount_of(&self, part: usize) -> Option<String> {
        self.ro_dsfs.lock().iter().find(|(_, p)| *p == part).map(|(m, _)| m.clone())
    }

    pub(super) fn add_ro_mount(&self, path: &str, part: usize) {
        self.ro_dsfs.lock().push((String::from(path), part));
        self.mounts.lock().push(String::from(path));
    }

    pub(super) fn forget_mount(&self, path: &str) {
        self.ro_dsfs.lock().retain(|(m, _)| m != path);
        self.mounts.lock().retain(|m| m != path);
    }

    /// No more read-only attempts for this partition: given up, or unmounted by the user.
    pub(super) fn ro_given_up(&self, part: usize) -> bool {
        self.ro_fail.lock().iter().any(|&(p, n)| p == part && n >= RO_TRIES) || self.user_off(part)
    }

    /// One more failed read-only mount; the count so far.
    pub(super) fn note_ro_fail(&self, part: usize) -> u8 {
        let mut v = self.ro_fail.lock();
        match v.iter_mut().find(|(p, _)| *p == part) {
            Some((_, n)) => {
                *n = n.saturating_add(1);
                *n
            }
            None => {
                v.push((part, 1));
                1
            }
        }
    }

    pub fn user_off(&self, part: usize) -> bool {
        self.user_off.lock().contains(&part)
    }

    pub(super) fn set_user_off(&self, part: usize) {
        let mut v = self.user_off.lock();
        if !v.contains(&part) {
            v.push(part);
        }
    }
}

static REGISTRY: SpinLock<Vec<Arc<Shared>>> = SpinLock::new("ublk registry", level::BLOCK, Vec::new());
static NEXT_NUM: AtomicU64 = AtomicU64::new(0);
static MONITOR_GEN: AtomicU64 = AtomicU64::new(0);
static MONITOR_WAKE: WaitQueue = WaitQueue::new();
static MONITOR_STARTED: AtomicBool = AtomicBool::new(false);
/// The next disk generation and format session – counters that never wrap: when the next
/// value would not fit (`checked_add`), the attach / format is refused.
static NEXT_GEN: AtomicU64 = AtomicU64::new(1);
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
/// Self-tests: the disk skips its own registration check (the second lock), so that the
/// third lock (usbd) is tested alone.
#[cfg(selftest)]
pub static TEST_SKIP_UBLK_CHECK: AtomicBool = AtomicBool::new(false);
/// Self-tests: added to the generation in every request (a stale generation for usbd).
#[cfg(selftest)]
pub static TEST_GEN_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Takes the counter's value; None when the one after it would not fit (never 0, never reused).
fn take(counter: &AtomicU64) -> Option<u64> {
    let mut cur = counter.load(Ordering::SeqCst);
    loop {
        let next = cur.checked_add(1)?;
        match counter.compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Some(cur),
            Err(v) => cur = v,
        }
    }
}

/// Self-tests: sets the next generation / session (the overflow test).
#[cfg(selftest)]
pub fn test_set_counters(generation: Option<u64>, session: Option<u64>) -> (u64, u64) {
    let old = (NEXT_GEN.load(Ordering::SeqCst), NEXT_SESSION.load(Ordering::SeqCst));
    if let Some(g) = generation {
        NEXT_GEN.store(g, Ordering::SeqCst);
    }
    if let Some(s) = session {
        NEXT_SESSION.store(s, Ordering::SeqCst);
    }
    old
}

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

/// The registration this disk holds (the kernel's copy; usbd keeps its own).
#[derive(Clone, Copy, PartialEq, Debug)]
enum Reg {
    None,
    Probe,
    Rw { start: u64, len: u64 },
    Format { session: u64, start: u64, len: u64 },
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
    reg: Reg,
    stale: Vec<u32>,
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

/// Copy into the buffer (a WRITE's data, before the request goes out).
fn copy_in(obj: &ShmObj, mut off: usize, src: &[u8]) {
    let frames = obj.frames();
    let mut done = 0;
    while done < src.len() {
        let (pi, po) = (off / 4096, off % 4096);
        let n = (4096 - po).min(src.len() - done);
        let dst = (crate::memory::phys_to_virt(frames[pi]) as usize + po) as *mut u8;
        unsafe { core::ptr::copy_nonoverlapping(src[done..].as_ptr(), dst, n) };
        done += n;
        off += n;
    }
}

fn le32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// Request in flight – where it lands in the reader's buffer (or comes from the writer's).
#[derive(Clone, Copy)]
struct InFlight {
    id: u32,
    n: u32,
    /// Offset in the caller's buffer, bytes skipped at the start of the slot, length.
    at: usize,
    skip: usize,
    len: usize,
}

/// One request (the fields of the 48-byte message).
#[derive(Clone, Copy, Default)]
struct Req {
    op: u32,
    lba: u64,
    blocks: u32,
    slot: u32,
    session: u64,
    len: u64,
}

impl Ublk {
    /// Sends one request; Ok(its id).  A full usbd queue – Io; a closed channel – the disk is gone.
    fn send_req(&mut self, r: Req) -> Result<u32, BlockError> {
        let id = self.alloc_id();
        let mut data = alloc::vec![0u8; MSG_BYTES];
        data[0..4].copy_from_slice(&id.to_le_bytes());
        data[4..8].copy_from_slice(&r.op.to_le_bytes());
        data[8..16].copy_from_slice(&r.lba.to_le_bytes());
        data[16..20].copy_from_slice(&r.blocks.to_le_bytes());
        data[20..24].copy_from_slice(&r.slot.to_le_bytes());
        #[cfg(selftest)]
        let generation = self.sh.generation.wrapping_add(TEST_GEN_OFFSET.load(Ordering::SeqCst));
        #[cfg(not(selftest))]
        let generation = self.sh.generation;
        data[24..32].copy_from_slice(&generation.to_le_bytes());
        data[32..40].copy_from_slice(&r.session.to_le_bytes());
        data[40..48].copy_from_slice(&r.len.to_le_bytes());
        if let Err((e, _)) = self.sh.chan.send(Message { data, handles: Vec::new(), sender: 0 }, true) {
            if e == ERROR_CLOSED {
                self.sh.set_gone();
                return Err(BlockError::NoDevice);
            }
            return Err(BlockError::Io); // usbd queue full
        }
        Ok(id)
    }

    /// The next request id.  Every id a reply may still come for is in a busy slot, a
    /// quarantined slot or the stale list (when that list is full the disk is declared gone –
    /// nothing is ever dropped from it); after the 32-bit counter wraps those ids are skipped,
    /// so a late reply can never match a new request.
    fn alloc_id(&mut self) -> u32 {
        loop {
            let id = self.next_id;
            self.next_id = self.next_id.wrapping_add(1).max(1);
            let taken = self.slots.iter().any(|s| matches!(s, Slot::Busy(x) | Slot::Quarantine(x) if *x == id)) || self.stale.contains(&id);
            if !taken {
                return id;
            }
        }
    }

    /// Self-tests: the id counter set close to its wrap.
    #[cfg(selftest)]
    fn set_next_id(&mut self, id: u32) {
        self.next_id = id.max(1);
    }

    /// Sends a READ / WRITE for `n` blocks at `first` with free slot `slot`.
    fn send(&mut self, op: u32, slot: usize, first: u64, n: u32, session: u64) -> Result<u32, BlockError> {
        let id = self.send_req(Req { op, lba: first, blocks: n, slot: slot as u32, session, len: 0 })?;
        self.slots[slot] = Slot::Busy(id);
        Ok(id)
    }

    /// A reply that answers nothing in flight: a late one after a timeout (slot back to the
    /// pool / stale id forgotten) or a protocol error.
    fn unmatched(&mut self, rid: u32) {
        if let Some(q) = self.slots.iter().position(|s| *s == Slot::Quarantine(rid)) {
            // Late reply after a timeout – the slot returns, data discarded.
            self.slots[q] = Slot::Free;
            self.sh.late.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if let Some(k) = self.stale.iter().position(|&s| s == rid) {
            // Late reply to a timed-out FLUSH / REG – discarded, never an answer.
            self.stale.remove(k);
            self.sh.late.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.sh.proto_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// One timeout of a request: counted, 3 in a row – the disk is gone.
    fn timed_out(&mut self) {
        self.sh.timeouts.fetch_add(1, Ordering::Relaxed);
        self.timeouts_row += 1;
        if self.timeouts_row >= TIMEOUTS_GONE {
            self.sh.set_gone();
        }
    }

    /// Sends a request without a slot (FLUSH, REG, TEST) and waits for its reply:
    /// Ok((status, blocks)).  Timeout – its id goes to the stale list.
    fn call(&mut self, r: Req) -> Result<(i64, u32), BlockError> {
        let id = self.send_req(r)?;
        let deadline = crate::time::ticks() + crate::time::ms_to_ticks(self.timeout_ms);
        loop {
            let left = deadline.saturating_sub(crate::time::ticks());
            let got = if left == 0 { Err(ERROR_TIMED_OUT) } else { self.sh.chan.recv_timeout(left * 1000 / crate::time::HZ as u64) };
            match got {
                Ok(m) => {
                    if m.data.len() < 12 {
                        self.sh.proto_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let (rid, status, cnt) = (le32(&m.data, 0), le32(&m.data, 4) as i32 as i64, le32(&m.data, 8));
                    if rid != id {
                        self.unmatched(rid);
                        continue;
                    }
                    self.timeouts_row = 0;
                    if status == ERROR_NO_DEVICE {
                        self.sh.set_gone();
                        return Err(BlockError::NoDevice);
                    }
                    return Ok((status, cnt));
                }
                Err(e) if e == ERROR_TIMED_OUT || e == ERROR_INTERRUPTED => {
                    self.stale.push(id);
                    if self.stale.len() >= STALE_MAX {
                        // So many unanswered requests – the device is not to be trusted; its ids
                        // are never forgotten (alloc_id), the disk goes instead.
                        self.sh.set_gone();
                    }
                    if e == ERROR_TIMED_OUT {
                        self.timed_out();
                    }
                    return Err(BlockError::Timeout);
                }
                Err(_) => {
                    self.sh.set_gone();
                    return Err(BlockError::NoDevice);
                }
            }
        }
    }

    /// The second lock: may blocks [first, first + n) be written with `tag` under the
    /// registration this disk holds?
    fn may_write(&self, first: u64, n: u64, tag: u64) -> Result<(), BlockError> {
        #[cfg(selftest)]
        if TEST_SKIP_UBLK_CHECK.load(Ordering::SeqCst) {
            return Ok(());
        }
        if n == 0 {
            return Err(BlockError::BadBuffer);
        }
        let (start, len) = match self.reg {
            Reg::Rw { start, len } if tag == 0 => (start, len),
            Reg::Format { session, start, len } if session != 0 && tag == session => (start, len),
            _ => return Err(BlockError::ReadOnly),
        };
        let end = first.checked_add(n).ok_or(BlockError::OutOfRange)?;
        let limit = start.checked_add(len).ok_or(BlockError::OutOfRange)?;
        if first < start || end > limit || end > self.blocks {
            return Err(BlockError::OutOfRange);
        }
        Ok(())
    }

    /// May a FLUSH go out with `tag` (rw: 0, format: its session)?
    fn may_flush(&self, tag: u64) -> Result<(), BlockError> {
        #[cfg(selftest)]
        if TEST_SKIP_UBLK_CHECK.load(Ordering::SeqCst) {
            return Ok(());
        }
        match self.reg {
            Reg::Rw { .. } if tag == 0 => Ok(()),
            Reg::Format { session, .. } if session != 0 && tag == session => Ok(()),
            _ => Err(BlockError::ReadOnly),
        }
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
                match self.send(OP_READ, slot, first, n as u32, 0) {
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
            match self.wait_slot(&mut fl, &mut deadline)? {
                None => continue,
                Some((slot, x, status)) => {
                    if status == 0 {
                        if error.is_none() {
                            copy_out(&self.buf, slot * SLOT_BYTES + x.skip, &mut buf[x.at..x.at + x.len]);
                            copied += x.len;
                        }
                        continue;
                    }
                    error.get_or_insert(BlockError::Io);
                }
            }
        }
    }

    /// Waits for one reply to a slot request in `fl`: Ok(Some((slot, request, status))) –
    /// the slot is free again; Ok(None) – a reply that was not for us (handled); Err –
    /// timeout (in-flight slots quarantined), the device gone, ERROR_NO_DEVICE.
    fn wait_slot(&mut self, fl: &mut [Option<InFlight>; SLOTS_MAX], deadline: &mut u64) -> Result<Option<(usize, InFlight, i64)>, BlockError> {
        let left = deadline.saturating_sub(crate::time::ticks());
        let r = if left == 0 { Err(ERROR_TIMED_OUT) } else { self.sh.chan.recv_timeout(left * 1000 / crate::time::HZ as u64) };
        match r {
            Ok(m) => {
                if m.data.len() < 12 {
                    self.sh.proto_errors.fetch_add(1, Ordering::Relaxed);
                    return Ok(None);
                }
                let (rid, status, cnt) = (le32(&m.data, 0), le32(&m.data, 4) as i32 as i64, le32(&m.data, 8));
                let Some(slot) = (0..SLOTS_MAX).find(|&i| fl[i].map_or(false, |x| x.id == rid)) else {
                    self.unmatched(rid);
                    return Ok(None);
                };
                let x = fl[slot].unwrap();
                if status == 0 && cnt != x.n {
                    // Wrong block count – rejected; keep waiting (or time out).
                    self.sh.proto_errors.fetch_add(1, Ordering::Relaxed);
                    return Ok(None);
                }
                fl[slot] = None;
                self.slots[slot] = Slot::Free;
                self.timeouts_row = 0;
                *deadline = crate::time::ticks() + crate::time::ms_to_ticks(self.timeout_ms);
                if status == ERROR_NO_DEVICE {
                    self.sh.set_gone();
                    return Err(BlockError::NoDevice);
                }
                Ok(Some((slot, x, status)))
            }
            Err(e) if e == ERROR_TIMED_OUT || e == ERROR_INTERRUPTED => {
                for (slot, x) in fl.iter().enumerate() {
                    if let Some(x) = x {
                        self.slots[slot] = Slot::Quarantine(x.id);
                    }
                }
                if e == ERROR_TIMED_OUT {
                    self.timed_out();
                }
                Err(BlockError::Timeout)
            }
            Err(_) => {
                for (slot, x) in fl.iter().enumerate() {
                    if x.is_some() {
                        self.slots[slot] = Slot::Free;
                    }
                }
                self.sh.set_gone();
                Err(BlockError::NoDevice)
            }
        }
    }

    /// Pipelined write in 64 KiB pieces (rule G): every piece checked by the second lock
    /// before it goes out; the write succeeds only when EVERY piece got a reply with status
    /// 0 and its block count.  An error: nothing new goes out, the sent pieces are waited
    /// for, the whole write fails (the pieces already written – an unknown state, as with
    /// every failed write).  `first` / `nblocks` in device blocks.
    fn write_pipelined(&mut self, first: u64, buf: &[u8], tag: u64) -> Result<(), BlockError> {
        let bs = self.bs as usize;
        let per = SLOT_BYTES / bs;
        let total = buf.len() / bs;
        let mut fl: [Option<InFlight>; SLOTS_MAX] = [None; SLOTS_MAX];
        let mut planned = 0usize; // blocks
        let mut done = 0usize;
        let mut error: Option<BlockError> = None;
        let mut deadline = crate::time::ticks() + crate::time::ms_to_ticks(self.timeout_ms);
        loop {
            while error.is_none() && planned < total {
                let Some(slot) = self.slots[..self.nslots].iter().position(|s| *s == Slot::Free) else { break };
                let n = (total - planned).min(per);
                let at = first + planned as u64;
                if let Err(e) = self.may_write(at, n as u64, tag) {
                    self.sh.refused.fetch_add(1, Ordering::Relaxed);
                    error = Some(e);
                    break;
                }
                let bytes = n.checked_mul(bs).ok_or(BlockError::OutOfRange)?;
                copy_in(&self.buf, slot * SLOT_BYTES, &buf[planned * bs..planned * bs + bytes]);
                match self.send(OP_WRITE, slot, at, n as u32, tag) {
                    Ok(id) => {
                        fl[slot] = Some(InFlight { id, n: n as u32, at: planned, skip: 0, len: bytes });
                        planned += n;
                    }
                    Err(BlockError::NoDevice) => return Err(BlockError::NoDevice),
                    Err(e) => error = Some(e),
                }
            }
            if fl.iter().all(|x| x.is_none()) {
                if let Some(e) = error {
                    return Err(e);
                }
                if done >= total {
                    return Ok(());
                }
                return Err(BlockError::Io);
            }
            match self.wait_slot(&mut fl, &mut deadline)? {
                None => continue,
                Some((_, x, status)) => {
                    if status == 0 {
                        done += x.n as usize;
                        continue;
                    }
                    error.get_or_insert(BlockError::Io);
                }
            }
        }
    }

    /// A registration message; Ok only with status 0.
    fn register(&mut self, kind: u32, start: u64, len: u64, session: u64) -> Result<(), BlockError> {
        let slot = if kind == REG_PROBE { 1 } else { 0 };
        match self.call(Req { op: OP_REG, lba: start, blocks: kind, slot, session, len })? {
            (0, k) if k == kind => Ok(()),
            (0, _) => {
                self.sh.proto_errors.fetch_add(1, Ordering::Relaxed);
                Err(BlockError::Io)
            }
            _ => Err(BlockError::Io),
        }
    }

    /// Withdraws whatever is registered – locally at once, in usbd by a message (best
    /// effort: a gone device has no registration anyway).
    fn withdraw(&mut self) {
        let had = self.reg != Reg::None;
        self.reg = Reg::None;
        if had && !self.sh.gone() {
            let _ = self.register(REG_NONE, 0, 0, 0);
        }
    }

    /// A new registration range must lie inside the device, without overflow.
    fn check_new_range(&self, start: u64, len: u64) -> Result<(), BlockError> {
        let limit = start.checked_add(len).ok_or(BlockError::OutOfRange)?;
        if len == 0 || limit > self.blocks {
            return Err(BlockError::OutOfRange);
        }
        Ok(())
    }

    /// Before any registration: the same instance (generation) and – fail-closed – a stick
    /// that is known NOT to be write-protected.
    fn check_gen(&self, generation: u64) -> Result<(), BlockError> {
        if self.sh.gone() || generation != self.sh.generation {
            return Err(BlockError::NoDevice);
        }
        if self.sh.wp != WP_CLEAR {
            return Err(BlockError::ReadOnly);
        }
        Ok(())
    }

    fn do_flush(&mut self, session: u64) -> Result<(), BlockError> {
        match self.call(Req { op: OP_FLUSH, session, ..Req::default() })? {
            (0, _) => {
                self.sh.flushes.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            _ => Err(BlockError::Io),
        }
    }
}

impl BlockDevice for Ublk {
    fn name(&self) -> &str {
        &self.sh.name
    }
    fn description(&self) -> String {
        alloc::format!(
            "USB disk \"{}\", {} MiB, {}-byte blocks, read-only{}{}{}",
            self.sh.desc,
            self.sector_count() * SECTOR_SIZE as u64 / (1024 * 1024),
            self.bs,
            match self.sh.wp {
                WP_CLEAR => "",
                WP_SET => ", write-protected",
                _ => ", write protection unknown",
            },
            match self.reg {
                Reg::Rw { start, len } => alloc::format!(", partition blocks {}-{} writable", start, start + len - 1),
                Reg::Format { start, len, .. } => alloc::format!(", partition blocks {}-{} being formatted", start, start + len - 1),
                _ => String::new(),
            },
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
        // The whole disk never takes a write – only a partition with a grant (write_range).
        Err(BlockError::ReadOnly)
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        // Nothing was written through the whole disk.
        Ok(())
    }
    fn write_range(&mut self, lba: u64, buf: &[u8], tag: u64) -> Result<(), BlockError> {
        check_range(self.sector_count(), lba, buf.len())?;
        let f = self.bs as u64 / SECTOR_SIZE as u64;
        if lba % f != 0 || buf.len() % self.bs as usize != 0 {
            return Err(BlockError::BadBuffer);
        }
        if self.sh.gone() {
            return Err(BlockError::NoDevice);
        }
        let (first, n) = (lba / f, (buf.len() / self.bs as usize) as u64);
        if let Err(e) = self.may_write(first, n, tag) {
            self.sh.refused.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }
        self.write_pipelined(first, buf, tag)?;
        self.sh.writes.fetch_add(1, Ordering::Relaxed);
        self.sh.wbytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
        Ok(())
    }
    fn flush_range(&mut self, tag: u64) -> Result<(), BlockError> {
        if self.sh.gone() {
            return Err(BlockError::NoDevice);
        }
        if let Err(e) = self.may_flush(tag) {
            self.sh.refused.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }
        // A barrier: write_range returns only after every piece was answered, and the disk
        // lock keeps the next write out until this FLUSH is answered.
        self.do_flush(tag)
    }
    fn control(&mut self, c: Control) -> Result<u64, BlockError> {
        match c {
            Control::Generation => Ok(self.sh.generation),
            Control::WriteProtect => Ok(self.sh.wp as u64),
            Control::Probe { generation } => {
                self.check_gen(generation)?;
                if self.reg != Reg::None {
                    return Err(BlockError::Unsupported);
                }
                self.register(REG_PROBE, 0, 0, 0)?;
                self.reg = Reg::Probe;
                let r = self.do_flush(0);
                // Used up whatever happened: usbd drops it after its one FLUSH; after a
                // timeout the kernel also tells it to.
                self.reg = Reg::None;
                if r == Err(BlockError::Timeout) && !self.sh.gone() {
                    let _ = self.register(REG_NONE, 0, 0, 0);
                }
                r.map(|_| 0)
            }
            Control::RegisterRw { generation, start, len } => {
                self.check_gen(generation)?;
                if self.reg != Reg::None {
                    return Err(BlockError::Unsupported);
                }
                self.check_new_range(start, len)?;
                self.register(REG_RW, start, len, 0)?;
                self.reg = Reg::Rw { start, len };
                Ok(0)
            }
            Control::BeginFormat { generation, start, len } => {
                self.check_gen(generation)?;
                if self.reg != Reg::None {
                    return Err(BlockError::Unsupported);
                }
                self.check_new_range(start, len)?;
                let session = take(&NEXT_SESSION).ok_or(BlockError::Unsupported)?;
                self.register(REG_FORMAT, start, len, session)?;
                self.reg = Reg::Format { session, start, len };
                Ok(session)
            }
            Control::EndFormat { session } => {
                if matches!(self.reg, Reg::Format { session: s, .. } if s == session) {
                    self.withdraw();
                }
                Ok(0)
            }
            Control::Withdraw => {
                self.withdraw();
                Ok(0)
            }
            #[cfg(selftest)]
            Control::TestNextId { id } => {
                self.set_next_id(id);
                Ok(0)
            }
            #[cfg(selftest)]
            Control::Test { flags } => {
                let (status, _) = self.call(Req { op: OP_TEST, blocks: flags, ..Req::default() })?;
                Ok(status as u64)
            }
        }
    }
}

/// blk_attach: new USB disk.  Result: number (0 = sda).  ERROR_NO_SPACE – 8 disks, or the
/// generation counter is used up (it never wraps).  `wp` – WP_* as usbd saw it.
#[allow(clippy::too_many_arguments)]
pub fn attach(chan: Arc<ChanEnd>, buf: Arc<ShmObj>, blocks: u64, bs: u32, slots: usize, timeout_ms: u64, wp: u8, desc: String) -> Result<u64, i64> {
    if count() >= DISKS_MAX {
        return Err(ERROR_NO_SPACE);
    }
    let Some(generation) = take(&NEXT_GEN) else {
        crate::serial_println!("[USB] disk generation counter used up - disk refused");
        return Err(ERROR_NO_SPACE);
    };
    let wp = if matches!(wp, WP_CLEAR | WP_SET) { wp } else { WP_UNKNOWN };
    let num = NEXT_NUM.fetch_add(1, Ordering::SeqCst);
    let sh = Arc::new(Shared {
        num,
        generation,
        wp,
        name: disk_name(num),
        desc,
        chan,
        gone: AtomicBool::new(false),
        state: AtomicU8::new(NEW),
        index: AtomicUsize::new(usize::MAX),
        reads: AtomicU64::new(0),
        bytes: AtomicU64::new(0),
        writes: AtomicU64::new(0),
        wbytes: AtomicU64::new(0),
        flushes: AtomicU64::new(0),
        refused: AtomicU64::new(0),
        timeouts: AtomicU64::new(0),
        proto_errors: AtomicU64::new(0),
        late: AtomicU64::new(0),
        mounts: SpinLock::new("ublk mounts", level::BLOCK, Vec::new()),
        disk_part: AtomicUsize::new(usize::MAX),
        ro_dsfs: SpinLock::new("ublk ro desofs", level::BLOCK, Vec::new()),
        ro_fail: SpinLock::new("ublk ro fail", level::BLOCK, Vec::new()),
        user_off: SpinLock::new("ublk user off", level::BLOCK, Vec::new()),
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
        reg: Reg::None,
        stale: Vec::new(),
    };
    let Some(index) = block::register(Box::new(dev)) else {
        crate::serial_println!("[USB] disk identities used up - disk refused");
        return Err(ERROR_NO_SPACE);
    };
    sh.index.store(index, Ordering::SeqCst);
    crate::serial_println!(
        "[USB] {}: \"{}\", {} MiB, {}-byte blocks, read-only, write protection {} (disk {}, generation {})",
        sh.name,
        sh.desc,
        blocks * bs as u64 / (1024 * 1024),
        bs,
        match wp {
            WP_CLEAR => "off",
            WP_SET => "ON",
            _ => "unknown",
        },
        index,
        generation
    );
    REGISTRY.lock().push(sh);
    super::usbdisk::changed();
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
                super::usbdisk::changed();
            }
        }
        // A "DeSoOS system" partition as /disk (rules D2 / E) once the USB disks settled.
        super::usbdisk::evaluate();
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

/// A free /usbN: nothing mounted there and the name unused – or an empty directory left by
/// an earlier mount (`desofs unmount` keeps the directory).
pub(super) fn free_mount_point() -> Option<String> {
    let mounted: Vec<String> = crate::fs::mount_list().into_iter().map(|m| m.0).collect();
    (0..16).map(|n| alloc::format!("/usb{}", n)).find(|p| {
        !mounted.contains(p)
            && match crate::fs::stat(p) {
                Err(_) => true,
                Ok(m) => m.kind == crate::fs::FileType::Directory && crate::fs::read_dir(p).is_ok_and(|v| v.is_empty()),
            }
    })
}

/// Disk gone: unmount (no write-back – the disk is read-only anyway),
/// remove the partitions and the disk (buffer freed, number back to the pool).
fn remove(sh: &Shared) {
    let mounts: Vec<String> = core::mem::take(&mut *sh.mounts.lock());
    for m in &mounts {
        let _ = crate::fs::unmount_lost(m);
        let _ = crate::fs::remove(m);
    }
    if sh.clear_disk_part() {
        // The system volume went with the stick: the LKG stays in memory (a pending save
        // waits for the next volume).
        crate::time_lkg::volume_gone();
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
