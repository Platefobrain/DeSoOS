// A USB stick's "DeSo system" partition as /disk (docs/ARCHITECTURE.md "A USB stick as
// /disk").  Called by the usb-disks task (ublk.rs)
// after every change of the USB disks, once they settled.
//
// A CANDIDATE is a (USB disk instance, partition) pair: a GPT partition of type "DeSo system"
// with a DeSoFS marker in one of its superblocks.  Who gets /disk:
//   1. the internal disk (block::internal – the first PCI disk, by identity) keeps /disk when it
//      holds a recognised DeSoFS (a marker in either superblock, or a "DeSo system"
//      partition) – rw or ro, damaged or not – and no USB candidate ever takes it;
//   2. otherwise, and only while /disk is really free (nothing mounted there – e.g. FAT32 from the
//      internal disk stays), EXACTLY ONE candidate gets /disk; two or more – none does;
//   3. every other candidate is mounted read-only under /usbN, never two mounts of one volume;
//   4. /disk already taken is never taken away; after each change everything is decided anew.
//   5. who holds what is read from the mount table, not remembered: /disk or /usbN unmounted
//      some other way – the stale record is dropped (rw registration withdrawn) and the choice
//      made again;
//   6. a partition the user unmounted (`desofs unmount`) is left alone until the stick is
//      plugged in again – it is no candidate (Linux udisks, Windows "safely remove" alike).
// The way to /disk (rule D2), all for ONE generation of the stick: write protection known off
// → partition ≤ 64 GiB → probe (one confirmed SYNCHRONIZE CACHE) → `desofs check` (read only)
// → rw registration + grant → the volume mounted read-write.  Any step that fails – /disk
// read-only, with the reason, and no registration left behind.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::ublk::{self, Shared, WP_CLEAR};
use crate::block::{self, BlockError, Control};
use crate::fs::DiskMount;
use crate::serial_println;

/// The largest "DeSo system" partition that gets rw (the format-1 limit of this DeSoFS).
pub const MAX_RW_BYTES: u64 = 64 << 30;
/// No /disk decision until the USB disks were quiet this long (two sticks plugged in at boot
/// are both seen before anything is decided).
pub const SETTLE_MS: u64 = 1500;

/// Automatic /disk from USB: on in a normal kernel; in a self-test kernel only when a test (or
/// the "usbrestart" phase) turns it on – the other suites keep the /disk they expect.
pub static AUTO: AtomicBool = AtomicBool::new(!cfg!(selftest));
/// The last attach / removal (ticks) and the candidate set last reported.
static LAST_CHANGE: AtomicU64 = AtomicU64::new(0);
static LAST_SIG: AtomicU64 = AtomicU64::new(0);
/// The change last decided on (each change is decided once – no disk I/O while nothing changes).
static DECIDED: AtomicU64 = AtomicU64::new(u64::MAX);

/// Something that may change the decision: a USB disk attached or removed, a partition
/// formatted, the automatic mode switched (self-tests).
pub fn changed() {
    LAST_CHANGE.store(crate::time::ticks().max(1), Ordering::SeqCst);
}

/// One candidate.
struct Cand {
    sh: alloc::sync::Arc<Shared>,
    disk: usize,
    part: usize,
}

fn candidates() -> Vec<Cand> {
    let mut v = Vec::new();
    for sh in ublk::list() {
        if sh.gone() || !sh.probed() {
            continue;
        }
        let disk = sh.index.load(Ordering::SeqCst);
        for p in block::partitions_of(disk) {
            if !sh.user_off(p) && block::partition_kind(p) == Some(crate::gpt::DESO_SYSTEM_NAME) && crate::fs::desofs::has_marker(p) {
                v.push(Cand { sh: sh.clone(), disk, part: p });
            }
        }
    }
    v
}

/// Rule E1: the internal disk holds a recognised DeSoFS.
pub fn internal_reserves() -> bool {
    let Some(i) = block::internal() else { return false };
    crate::fs::desofs::has_marker(i) || block::partitions_of(i).iter().any(|&p| block::partition_kind(p) == Some(crate::gpt::DESO_SYSTEM_NAME))
}

fn disk_taken() -> bool {
    crate::fs::mount_list().iter().any(|m| m.0 == crate::time_lkg::SYSTEM_MOUNT)
}

/// /disk given up by a stick: no rw registration, no grant, no record; the LKG waits for the
/// next system volume.
fn release_disk(sh: &Shared, part: usize, why: &str) {
    let _ = block::control(sh.index.load(Ordering::SeqCst), Control::Withdraw);
    let _ = block::set_grant(part, None);
    if sh.clear_disk_part() {
        crate::time_lkg::volume_gone();
        serial_println!("[USB] {}: /disk {} - write registration withdrawn", sh.name, why);
    }
}

/// Rule 5: the records against the mount table.  A stick "holds /disk" only while DeSoFS of
/// its partition is really mounted there; the same for /usbN.
fn reconcile() {
    for sh in ublk::list() {
        if sh.gone() {
            continue;
        }
        if let Some(p) = sh.disk_part() {
            if crate::fs::mounted_disk(crate::time_lkg::SYSTEM_MOUNT) != Some(p) {
                release_disk(&sh, p, "no longer mounted");
            }
        }
        for (path, part) in sh.ro_mounts() {
            if crate::fs::mounted_disk(&path) != Some(part) {
                sh.forget_mount(&path);
            }
        }
    }
}

/// `desofs unmount` of /disk or /usbN: the stick's records dropped at once (no write
/// registration left for a volume nobody has), and the partition left alone until replugged
/// (rule 6).
pub fn unmounted_by_user(path: &str) {
    for sh in ublk::list() {
        if path == crate::time_lkg::SYSTEM_MOUNT {
            if let Some(p) = sh.disk_part() {
                sh.set_user_off(p);
            }
        }
        if let Some((_, part)) = sh.ro_mounts().into_iter().find(|(m, _)| m == path) {
            sh.set_user_off(part);
        }
    }
    reconcile();
    changed();
}

/// The decision, after the USB disks settled (called by the usb-disks task).
pub fn evaluate() {
    let change = LAST_CHANGE.load(Ordering::SeqCst);
    if !AUTO.load(Ordering::SeqCst) || DECIDED.load(Ordering::SeqCst) == change || crate::time::ticks().saturating_sub(change) < SETTLE_MS {
        return;
    }
    reconcile();
    let cands = candidates();
    let owner = cands.iter().position(|c| c.sh.disk_part() == Some(c.part));
    let reserved = internal_reserves();
    let taken = disk_taken();
    let target = if owner.is_none() && !reserved && !taken && cands.len() == 1 { Some(0) } else { None };
    // The candidate set, reported once per change.
    let sig = cands.iter().fold(cands.len() as u64, |h, c| h.wrapping_mul(1_000_003).wrapping_add(c.sh.generation << 8 ^ c.part as u64));
    if LAST_SIG.swap(sig, Ordering::SeqCst) != sig && owner.is_none() && target.is_none() && !cands.is_empty() {
        let why = if reserved {
            "the internal disk holds DeSoFS"
        } else if taken {
            "/disk is in use"
        } else {
            "more than one DeSo system partition - remove one"
        };
        serial_println!("[USB] /disk not given to a USB stick: {}; DeSo system partitions only read-only", why);
    }
    if let Some(t) = target {
        let c = &cands[t];
        if let Some(path) = c.sh.ro_mount_of(c.part) {
            // Read-only under /usbN so far: one mount at a time.
            if crate::fs::unmount(&path).is_err() {
                // Decided again on the next pass (DECIDED not set).
                serial_println!("[USB] {}: {} busy - stays read-only there, /disk later", c.sh.name, path);
                return;
            }
            let _ = crate::fs::remove(&path);
            c.sh.forget_mount(&path);
        }
        to_disk(c);
    }
    let mut retry = false;
    for (k, c) in cands.iter().enumerate() {
        if Some(k) == owner || Some(k) == target || c.sh.ro_mount_of(c.part).is_some() || c.sh.ro_given_up(c.part) {
            continue;
        }
        retry |= ro_mount(c);
    }
    DECIDED.store(change, Ordering::SeqCst);
    if retry {
        // A failed mount is tried again after the next settle window.
        changed();
    }
}

/// A candidate that does not get /disk: read-only under /usbN.  True – try again later.
/// Only a result counts as an attempt: no free /usbN is no attempt (an unmount or a removed
/// stick frees one and is a change by itself).
fn ro_mount(c: &Cand) -> bool {
    let Some(path) = ublk::free_mount_point() else {
        serial_println!("[USB] {}: DeSo system partition (disk {}) not mounted: no free /usbN", c.sh.name, c.part);
        return false;
    };
    match crate::fs::mount_disk(c.part, &path) {
        DiskMount::DeSoFs(_) => {
            serial_println!("[USB] {}: {} = DeSoFS (partition disk {}), read-only", c.sh.name, path, c.part);
            c.sh.add_ro_mount(&path, c.part);
            c.sh.clear_ro_fail(c.part);
            false
        }
        other => {
            let _ = crate::fs::remove(&path);
            let n = c.sh.note_ro_fail(c.part);
            serial_println!("[USB] {}: DeSo system partition (disk {}) not mounted (attempt {}/{}): {:?}", c.sh.name, c.part, n, ublk::RO_TRIES, other);
            n < ublk::RO_TRIES
        }
    }
}

/// Rule D2 – the way to a read-write /disk.  Err – why only read-only.
fn prepare_rw(c: &Cand) -> Result<(), String> {
    let generation = c.sh.generation;
    if c.sh.wp != WP_CLEAR {
        return Err(String::from(if c.sh.wp == ublk::WP_SET { "the stick is write-protected" } else { "write protection unknown" }));
    }
    let (parent, start, len) = block::partition_blocks(c.part).ok_or_else(|| String::from("partition range unknown"))?;
    let bs = block::with_device(parent, |d| d.logical_block_size()).unwrap_or(512) as u64;
    if parent != c.disk || len.checked_mul(bs).map_or(true, |b| b > MAX_RW_BYTES) {
        return Err(String::from("partition larger than 64 GiB"));
    }
    block::control(c.disk, Control::Probe { generation }).map_err(|e| alloc::format!("FLUSH not confirmed ({})", e))?;
    let rep = crate::fs::desofs::check::check(c.part, &mut |_, _| {}).map_err(|e| alloc::format!("desofs check: {}", e))?;
    if rep.errors > 0 {
        return Err(alloc::format!("desofs check found {} error(s) - see 'desofs check {}' / 'desofs repair {} yes'", rep.errors, c.part, c.part));
    }
    block::control(c.disk, Control::RegisterRw { generation, start, len }).map_err(|e| alloc::format!("rw registration refused ({})", e))?;
    if block::set_grant(c.part, Some(0)).is_err() || block::control(c.disk, Control::Generation) != Ok(generation) {
        let _ = block::control(c.disk, Control::Withdraw);
        let _ = block::set_grant(c.part, None);
        return Err(String::from("the stick changed meanwhile"));
    }
    Ok(())
}

/// The one candidate becomes /disk (rw after rule D2, otherwise read-only with the reason).
fn to_disk(c: &Cand) {
    let rw = prepare_rw(c);
    let path = crate::time_lkg::SYSTEM_MOUNT;
    let m = crate::fs::mount_disk(c.part, path);
    match (&m, &rw) {
        (DiskMount::DeSoFs(None), Ok(())) => {
            serial_println!("[USB] {}: /disk = DeSoFS (partition disk {}, generation {}) read-write", c.sh.name, c.part, c.sh.generation);
        }
        (DiskMount::DeSoFs(why), _) => {
            if rw.is_ok() {
                // Mounted read-only by DeSoFS's own rules: no registration left behind.
                let _ = block::control(c.disk, Control::Withdraw);
                let _ = block::set_grant(c.part, None);
            }
            let reason = match (&rw, why) {
                (Err(e), _) => e.clone(),
                (Ok(()), Some(w)) => w.clone(),
                _ => String::new(),
            };
            serial_println!("[USB] {}: /disk = DeSoFS (partition disk {}) READ-ONLY: {}", c.sh.name, c.part, reason);
        }
        _ => {
            if rw.is_ok() {
                let _ = block::control(c.disk, Control::Withdraw);
                let _ = block::set_grant(c.part, None);
            }
            serial_println!("[USB] {}: DeSo system partition (disk {}) not mounted at /disk: {:?}", c.sh.name, c.part, m);
            return;
        }
    }
    c.sh.set_disk_part(c.part);
}

/// `desofs format` on a USB partition (rule F): a format session around the write.  Ok(None) –
/// not a USB partition (the caller formats as before).
pub fn format_session<R>(index: usize, run: impl FnOnce() -> Result<R, String>) -> Option<Result<R, String>> {
    let parent = block::with_device(index, |d| d.parent()).ok().flatten()?;
    let generation = block::control(parent, Control::Generation).ok()?;
    Some((|| {
        if block::partition_kind(index) != Some(crate::gpt::DESO_SYSTEM_NAME) {
            return Err(String::from("on a USB disk only a \"DeSo system\" partition can be formatted - nothing changed"));
        }
        let (_, start, len) = block::partition_blocks(index).ok_or_else(|| String::from("partition range unknown - nothing changed"))?;
        let bs = block::with_device(parent, |d| d.logical_block_size()).unwrap_or(512) as u64;
        if len.checked_mul(bs).map_or(true, |b| b > MAX_RW_BYTES) {
            return Err(String::from("partition larger than 64 GiB - not supported yet; nothing changed"));
        }
        if block::control(parent, Control::WriteProtect) != Ok(WP_CLEAR as u64) {
            return Err(String::from("the stick is write-protected (or its write protection is unknown) - nothing changed"));
        }
        if !crate::fs::mounts_of_disk(index).is_empty() || crate::fs::desofs::is_mounted(index) {
            return Err(String::from("the partition is mounted - unmount it first; nothing changed"));
        }
        block::control(parent, Control::Probe { generation }).map_err(|e| alloc::format!("FLUSH not confirmed ({}) - nothing changed", e))?;
        let session = match block::control(parent, Control::BeginFormat { generation, start, len }) {
            Ok(s) => s,
            Err(BlockError::Unsupported) => return Err(String::from("no format session (another registration, or the session counter is used up) - nothing changed")),
            Err(e) => return Err(alloc::format!("no format session ({}) - nothing changed", e)),
        };
        // The session ends on every way out, before the result goes back to the shell.
        struct End(usize, usize, u64);
        impl Drop for End {
            fn drop(&mut self) {
                let _ = block::set_grant(self.0, None);
                let _ = block::control(self.1, Control::EndFormat { session: self.2 });
            }
        }
        let _end = End(index, parent, session);
        block::set_grant(index, Some(session)).map_err(|e| alloc::format!("grant: {}", e))?;
        run()
    })())
}
