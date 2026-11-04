// A mounted DeSoFS volume – reading and copy-on-write writing (stage 2a).
//
// Every operation is one transaction (T1): changed blocks are copied to new places in
// memory (`Tx::dirty`), the old ones stay untouched on the disk; at the end the new
// blocks are written bottom-up (a parent stores its children's SHA-256), flushed, and a
// new superblock goes to the slot with the older generation, flushed again.  Only then
// is the operation done.  Blocks the new tree no longer uses are still in the tree of
// the older superblock, so they become free one commit later (docs/desofs/FORMAT.md ch. 10).
//
// Space: before anything is changed an operation computes the most blocks it can
// allocate and refuses with "no space" if they are not there – never half-way.  A
// reserve (max(64 blocks, 1/64), at most 1/4 of the volume) is kept for operations that
// free space (remove, truncate, rename), which on copy-on-write also need new blocks.
//
// Errors: a write or flush error makes the volume read-only at once; so does a broken
// structure (a directory entry that does not match its node).  A bad data block is an
// error of that one read.  Allocation failures are "out of memory", never a panic.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::layout::*;
use super::format::{header, superblock};
use super::{m_meta, sha256, ByteMap, Report, State, M_DATA, M_FREE};
use crate::fs::{DirEntry, FileSystem, FileType, FsError, FsStats, Metadata};

type R<T> = Result<T, FsError>;

const SECT: u64 = (BLOCK / crate::block::SECTOR_SIZE) as u64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Data,
    Dspt,
    Dsnd,
    Dsrt,
}

struct Dirty {
    kind: Kind,
    level: u8,
    buf: Vec<u8>,
}

/// Counters for tests: blocks the last operation allocated and its own upper bound.
#[derive(Default, Clone, Copy, Debug)]
pub struct Counters {
    pub last_alloc: u64,
    pub last_bound: u64,
    pub max_over: u64,
    pub commits: u64,
}

pub struct Volume {
    disk: usize,
    total: u64,
    uuid: [u8; 16],
    label: [u8; 32],
    gn: u64,
    /// Committed root block.
    root: Ptr,
    /// Committed root entries (index, entry).
    entries: Vec<(usize, RootEntry)>,
    /// Generation in slot A / B (None = no valid superblock).
    slot_gen: [Option<u64>; 2],
    map: ByteMap,
    free: u64,
    /// Dropped by the last commit – still in the older superblock's tree.
    pending_free: Vec<u64>,
    free_nodes: Vec<u64>,
    newest_snap: u64,
    used: u64,
    ro: Option<String>,
    cursor: u64,
    pub counters: Counters,
    /// A read-only view of a snapshot (`desofs snapshot mount`): its root entry index and
    /// name; the snapshot's tree stands in for the live one.
    view: Option<(usize, String)>,
}

fn io(e: crate::block::BlockError) -> FsError {
    FsError::Io(e)
}

fn nomem<T>(_: T) -> FsError {
    FsError::NoSpace
}

impl Drop for Volume {
    fn drop(&mut self) {
        super::mounted_dec(self.disk);
        if let Some((i, _)) = &self.view {
            if let Some(c) = VIEWS.get(self.disk).and_then(|d| d.get(*i)) {
                c.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
            }
        }
    }
}

// ---------------- snapshots (stage 5) ----------------

/// Snapshot views alive per disk and root entry – `snapshot delete` refuses a snapshot
/// someone is looking at.  Disks 64 and up have no views (refused).
static VIEWS: [[core::sync::atomic::AtomicU32; ROOT_ENTRIES]; 64] =
    [const { [const { core::sync::atomic::AtomicU32::new(0) }; ROOT_ENTRIES] }; 64];

fn viewed(disk: usize, index: usize) -> bool {
    VIEWS.get(disk).and_then(|d| d.get(index)).map(|c| c.load(core::sync::atomic::Ordering::SeqCst) != 0).unwrap_or(false)
}

/// Most snapshots per volume (root entries 1–31).
pub const MAX_SNAPSHOTS: usize = ROOT_ENTRIES - 1;

/// A name `desofs snapshot create` accepts – stricter than the format (which asks only for
/// non-empty UTF-8 without '/'), because the name becomes a path (`/snap/<name>`) and a
/// shell word: 1–24 bytes, no '/', space, control character (NUL included) or DEL, not
/// "." or "..".
pub fn valid_snapshot_name(name: &str) -> Result<(), String> {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 24 {
        return Err(format!("snapshot name must have 1-24 bytes ({} given)", b.len()));
    }
    if name == "." || name == ".." {
        return Err(String::from("snapshot name cannot be '.' or '..'"));
    }
    if b.iter().any(|&c| c == b'/' || c == b' ' || c < 0x20 || c == 0x7F) {
        return Err(String::from("snapshot name cannot contain '/', spaces or control characters"));
    }
    Ok(())
}

fn name_bytes(name: &str) -> [u8; 24] {
    let mut n = [0u8; 24];
    let b = name.as_bytes();
    n[..b.len().min(24)].copy_from_slice(&b[..b.len().min(24)]);
    n
}

/// One root entry written into a root block (`None` – an empty entry).
fn put_entry(rb: &mut [u8], index: usize, e: Option<&RootEntry>) {
    let o = HDR_SIZE + index * ROOT_ENTRY;
    rb[o..o + ROOT_ENTRY].fill(0);
    if let Some(e) = e {
        set_ptr(rb, o, Some(e.nodes));
        rb[o + 48] = e.depth;
        rb[o + 49] = e.kind;
        rb[o + 56..o + 64].copy_from_slice(&e.next_node.to_le_bytes());
        rb[o + 64..o + 72].copy_from_slice(&e.created_gen.to_le_bytes());
        rb[o + 72..o + 96].copy_from_slice(&e.name);
    }
}

impl Volume {
    /// Mounts disk `index` (after the stage-1 walk).  A volume the walk allows only
    /// read-only is mounted read-only.
    pub fn mount(index: usize) -> Result<Volume, String> {
        let (report, sc): (Report, super::Scanned) = super::scan_volume(index)?;
        let ro = match &report.state {
            State::ReadWrite => None,
            State::ReadOnly(w) => Some(w.clone()),
            State::Refused(w) => return Err(w.clone()),
        };
        let sb = sc.sb;
        // The chosen root block's entries.
        let dev = super::Dev::open(index)?;
        let mut b = vec![0u8; BLOCK];
        dev.read(sb.root.addr, &mut b)?;
        let mut entries = Vec::new();
        let mut newest_snap = 0;
        for i in 0..ROOT_ENTRIES {
            if let Some(e) = RootEntry::parse(&b[HDR_SIZE + i * ROOT_ENTRY..], i, sb.generation)? {
                if e.kind == ROOT_SNAPSHOT {
                    newest_snap = newest_snap.max(e.created_gen);
                }
                entries.push((i, e));
            }
        }
        let map = sc.map;
        let mut free = 0;
        for i in 0..sb.total_blocks {
            if map.get(i) == M_FREE {
                free += 1;
            }
        }
        let (slot_gen, older_only) = if ro.is_some() { (sc.slot_gen, Vec::new()) } else { (sc.slot_gen, sc.older_only) };
        super::mounted_inc(index);
        Ok(Volume {
            disk: index,
            total: sb.total_blocks,
            uuid: sb.uuid,
            label: sb.label,
            gn: sb.generation,
            root: sb.root,
            entries,
            slot_gen,
            map,
            free,
            pending_free: older_only,
            free_nodes: sc.free_nodes,
            newest_snap,
            used: report.used_counted.unwrap_or(sb.used_blocks),
            ro,
            cursor: RESERVED,
            counters: Counters::default(),
            view: None,
        })
    }

    /// A read-only view of snapshot `name` of disk `index`: its tree stands in for the live
    /// one; nothing can be written through it.
    pub fn mount_snapshot(index: usize, name: &str) -> Result<Volume, String> {
        valid_snapshot_name(name).map_err(|e| format!("{} - such a snapshot cannot be mounted", e))?;
        if index >= VIEWS.len() {
            return Err(String::from("disk number too high for a snapshot view"));
        }
        let mut v = Volume::mount(index)?;
        let nb = name_bytes(name);
        let Some((i, e)) = v.entries.iter().find(|(_, e)| e.kind == ROOT_SNAPSHOT && e.name == nb).copied() else {
            return Err(format!("disk {} has no snapshot named {}", index, name));
        };
        let live = RootEntry { kind: ROOT_LIVE, created_gen: 0, name: [0; 24], ..e };
        v.entries.clear();
        v.entries.push((0, live));
        v.ro = Some(format!("snapshot {} (read-only)", name));
        v.pending_free.clear();
        v.free_nodes.clear();
        VIEWS[index][i].fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        v.view = Some((i, String::from(name)));
        Ok(v)
    }

    /// Snapshot entries (index, entry) of the committed root block.
    #[cfg_attr(not(selftest), allow(dead_code))]
    pub fn snapshots(&self) -> Vec<(usize, RootEntry)> {
        self.entries.iter().filter(|(_, e)| e.kind == ROOT_SNAPSHOT).copied().collect()
    }

    fn snapshot_writable(&self) -> Result<(), String> {
        if self.view.is_some() {
            return Err(String::from("a snapshot view is read-only"));
        }
        match &self.ro {
            Some(w) => Err(format!("the volume is read-only ({})", w)),
            None => Ok(()),
        }
    }

    fn find_snapshot(&self, name: &str) -> Result<(usize, RootEntry), String> {
        let nb = name_bytes(name);
        self.entries
            .iter()
            .find(|(_, e)| e.kind == ROOT_SNAPSHOT && e.name == nb && name.len() <= 24)
            .copied()
            .ok_or_else(|| format!("disk {} has no snapshot named {}", self.disk, name))
    }

    /// New snapshot of the committed state: one commit writing a root block whose new entry
    /// is a copy of the live one (created_gen = the generation of that state).  Nothing is
    /// copied; from now on R1 keeps every block born no later than that generation.
    pub fn snapshot_create(&mut self, name: &str) -> Result<usize, String> {
        valid_snapshot_name(name)?;
        self.snapshot_writable()?;
        let nb = name_bytes(name);
        if self.entries.iter().any(|(_, e)| e.kind == ROOT_SNAPSHOT && e.name == nb) {
            return Err(format!("a snapshot named {} already exists", name));
        }
        let Some(idx) = (1..ROOT_ENTRIES).find(|i| !self.entries.iter().any(|(j, _)| j == i)) else {
            return Err(format!("{} snapshots already - delete one first", MAX_SNAPSHOTS));
        };
        let live = self.entries.iter().find(|(i, _)| *i == 0).map(|(_, e)| *e).ok_or("no live root")?;
        let snap = RootEntry { kind: ROOT_SNAPSHOT, created_gen: self.gn, name: nb, ..live };
        self.write_op(|_| Ok((0, false)), |tx| {
            tx.root_edits.push((idx, Some(snap)));
            Ok(())
        })
        .map_err(|e| format!("{}", e))?;
        Ok(idx)
    }

    /// Deletes snapshot `name`: one commit without its entry, then R3 – the block map is
    /// computed again by the mount walk over both superblocks, so a block comes back only
    /// when neither superblock (live root or any snapshot) reaches it.
    pub fn snapshot_delete(&mut self, name: &str) -> Result<(), String> {
        self.snapshot_writable()?;
        let (idx, _) = self.find_snapshot(name)?;
        if viewed(self.disk, idx) {
            return Err(format!("snapshot {} is mounted (/snap/{}) - unmount it first", name, name));
        }
        // The new superblock's used_blocks: without the blocks only this snapshot held.
        let only = super::exclusive_blocks(self.disk, idx)?;
        self.write_op(|_| Ok((0, true)), |tx| {
            tx.root_edits.push((idx, None));
            tx.used_delta -= only as i64;
            Ok(())
        })
        .map_err(|e| format!("{}", e))?;
        self.rescan()
    }

    /// The whole volume goes back to snapshot `name`: one commit whose live entry is a copy
    /// of the snapshot's; every snapshot (newer ones too) stays.  Then R3 as for delete –
    /// the old live state stays reserved while the previous superblock still reaches it.
    pub fn snapshot_restore(&mut self, name: &str) -> Result<(), String> {
        self.snapshot_writable()?;
        let (_, e) = self.find_snapshot(name)?;
        let live = RootEntry { kind: ROOT_LIVE, created_gen: 0, name: [0; 24], ..e };
        // used_blocks of the new superblock: without what only the old live state held.
        let only = super::exclusive_blocks(self.disk, 0)?;
        self.write_op(|_| Ok((0, true)), |tx| {
            tx.live = live;
            tx.used_delta -= only as i64;
            Ok(())
        })
        .map_err(|e| format!("{}", e))?;
        self.rescan()
    }

    /// R3: the allocator's map from a fresh mount walk of the disk (both superblocks, every
    /// root).  On a failure the volume becomes read-only – nothing is allocated from a map
    /// that is not known to be right.
    fn rescan(&mut self) -> Result<(), String> {
        let fail = |v: &mut Volume, why: String| {
            let w = format!("block map after a snapshot change: {}", why);
            crate::serial_println!("[DESOFS] disk {}: {} - now read-only", v.disk, w);
            v.ro = Some(w.clone());
            Err(w)
        };
        match super::scan_volume(self.disk) {
            Ok((report, sc)) if report.state == State::ReadWrite => {
                let mut free = 0;
                for i in 0..self.total {
                    if sc.map.get(i) == M_FREE {
                        free += 1;
                    }
                }
                self.map = sc.map;
                self.free = free;
                self.pending_free = sc.older_only;
                self.free_nodes = sc.free_nodes;
                self.used = report.used_counted.unwrap_or(self.used);
                Ok(())
            }
            Ok((report, _)) => fail(self, format!("{:?}", report.state)),
            Err(e) => fail(self, e),
        }
    }

    pub fn read_only_reason(&self) -> Option<&str> {
        self.ro.as_deref()
    }

    #[allow(dead_code)] // tests and `desofs` output
    pub fn generation(&self) -> u64 {
        self.gn
    }

    #[allow(dead_code)]
    pub fn free_blocks(&self) -> u64 {
        self.free
    }

    /// Tests: blocks the walk finds reachable from either superblock but the allocator
    /// would hand out (must be 0 – otherwise a crash during the next commit could
    /// overwrite the fallback tree).
    #[cfg(selftest)]
    pub fn map_violations(&self) -> Result<u64, String> {
        let (_, sc) = super::scan_volume(self.disk)?;
        let mut bad = 0;
        for i in 0..self.total {
            if sc.map.get(i) != M_FREE && self.map.get(i) == M_FREE {
                bad += 1;
            }
        }
        Ok(bad)
    }

    /// Blocks kept for operations that free space.
    pub fn reserve(&self) -> u64 {
        (64u64.max(self.total / 64)).min(self.total / 4)
    }

    fn tx(&mut self) -> R<Tx<'_>> {
        let gn = self.gn.checked_add(1).ok_or(FsError::NoSpace)?;
        let live = self.entries.iter().find(|(i, _)| *i == 0).map(|(_, e)| *e).ok_or(FsError::Corrupt("no live root"))?;
        Ok(Tx { v: self, gn, live, dirty: BTreeMap::new(), dropped: Vec::new(), allocated: 0, used_delta: 0, taken_nodes: Vec::new(), freed_nodes: Vec::new(), root_edits: Vec::new() })
    }

    fn check_writable(&self) -> R<()> {
        if self.ro.is_some() { Err(FsError::ReadOnly) } else { Ok(()) }
    }

    /// Runs a writing operation as one transaction.
    fn write_op<T>(&mut self, bound: impl FnOnce(&mut Tx) -> R<(u64, bool)>, op: impl FnOnce(&mut Tx) -> R<T>) -> R<T> {
        self.check_writable()?;
        let mut tx = self.tx()?;
        let r = (|| {
            let (need, frees) = bound(&mut tx)?;
            let need = need + 1; // the new root block
            let keep = if frees { 0 } else { tx.v.reserve() };
            if tx.v.free < need + keep {
                return Err(FsError::NoSpace);
            }
            tx.v.counters.last_bound = need;
            let t = op(&mut tx)?;
            Ok(t)
        })();
        match r {
            Ok(t) => {
                tx.commit()?;
                Ok(t)
            }
            Err(e) => {
                tx.abort();
                Err(e)
            }
        }
    }

    /// Runs a reading operation (no commit).
    fn read_op<T>(&mut self, op: impl FnOnce(&mut Tx) -> R<T>) -> R<T> {
        let mut tx = self.tx()?;
        let r = op(&mut tx);
        tx.abort();
        r
    }
}

struct Tx<'a> {
    v: &'a mut Volume,
    gn: u64,
    live: RootEntry,
    dirty: BTreeMap<u64, Dirty>,
    /// Blocks of the committed tree this transaction no longer uses (and no snapshot does).
    dropped: Vec<u64>,
    allocated: u64,
    used_delta: i64,
    taken_nodes: Vec<u64>,
    freed_nodes: Vec<u64>,
    /// Snapshot entries this commit adds (Some) or removes (None).
    root_edits: Vec<(usize, Option<RootEntry>)>,
}

/// Placeholder pointer to a block of this transaction (its checksum is set at commit).
fn placeholder(addr: u64, gn: u64) -> Ptr {
    Ptr { addr, birth: gn, sha: [0; 32] }
}

fn ptr_bytes(p: Option<Ptr>) -> [u8; 48] {
    let mut b = [0u8; 48];
    if let Some(p) = p {
        b[0..8].copy_from_slice(&p.addr.to_le_bytes());
        b[8..16].copy_from_slice(&p.birth.to_le_bytes());
        b[16..48].copy_from_slice(&p.sha);
    }
    b
}

fn get_ptr(b: &[u8], o: usize) -> R<Option<Ptr>> {
    Ptr::parse(&b[o..o + PTR_SIZE]).map_err(FsError::Corrupt)
}

fn set_ptr(b: &mut [u8], o: usize, p: Option<Ptr>) {
    b[o..o + PTR_SIZE].copy_from_slice(&ptr_bytes(p));
}

fn round8(n: usize) -> usize {
    (n + 7) & !7
}

fn now() -> u64 {
    crate::drivers::rtc::now().to_unix()
}

/// A node as 256 bytes plus a few helpers.
#[derive(Clone)]
struct NodeBuf {
    b: [u8; NODE_SIZE],
}

impl NodeBuf {
    fn new(number: u64, typ: u8, parent: u64, gn: u64) -> NodeBuf {
        let mut b = [0u8; NODE_SIZE];
        b[0..8].copy_from_slice(&number.to_le_bytes());
        b[8] = typ;
        b[12..16].copy_from_slice(&1u32.to_le_bytes());
        let t = now();
        b[24..32].copy_from_slice(&t.to_le_bytes());
        b[32..40].copy_from_slice(&t.to_le_bytes());
        b[40..48].copy_from_slice(&parent.to_le_bytes());
        b[48..56].copy_from_slice(&gn.to_le_bytes());
        NodeBuf { b }
    }
    fn typ(&self) -> u8 {
        self.b[8]
    }
    fn depth(&self) -> u8 {
        self.b[9]
    }
    fn set_depth(&mut self, d: u8) {
        self.b[9] = d;
    }
    fn size(&self) -> u64 {
        u64_at(&self.b, 16)
    }
    fn set_size(&mut self, s: u64) {
        self.b[16..24].copy_from_slice(&s.to_le_bytes());
    }
    fn touch(&mut self) {
        self.b[32..40].copy_from_slice(&now().to_le_bytes());
    }
    fn modified(&self) -> u64 {
        u64_at(&self.b, 32)
    }
    fn parent(&self) -> u64 {
        u64_at(&self.b, 40)
    }
    fn set_parent(&mut self, p: u64) {
        self.b[40..48].copy_from_slice(&p.to_le_bytes());
    }
    fn blocks(&self) -> u64 {
        self.size().div_ceil(BLOCK as u64)
    }
    fn direct(&self, i: usize) -> R<Option<Ptr>> {
        get_ptr(&self.b, 56 + i * PTR_SIZE)
    }
    fn set_direct(&mut self, i: usize, p: Option<Ptr>) {
        set_ptr(&mut self.b, 56 + i * PTR_SIZE, p);
    }
    fn root(&self) -> R<Option<Ptr>> {
        self.direct(0)
    }
    fn set_root(&mut self, p: Option<Ptr>) {
        self.set_direct(0, p);
    }
    fn is_dir(&self) -> bool {
        self.typ() == TYPE_DIR
    }
}

fn span(level: u8) -> u64 {
    // Leaves under one pointer of a DSPT at `level`.
    if level <= 1 { 1 } else { (FANOUT as u64).pow(level as u32 - 1) }
}

fn check_name(name: &str) -> R<()> {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 255 || b.contains(&b'/') || b.contains(&0) || name == "." || name == ".." {
        return Err(FsError::InvalidName);
    }
    Ok(())
}

impl<'a> Tx<'a> {
    // ---------------- blocks ----------------

    fn corrupt(&mut self, why: &'static str) -> FsError {
        if self.v.ro.is_none() {
            self.v.ro = Some(String::from(why));
            crate::serial_println!("[DESOFS] disk {}: {} - now read-only", self.v.disk, why);
        }
        FsError::Corrupt(why)
    }

    /// Reads the block behind `p` (from this transaction or the disk, checked).
    fn read(&mut self, p: &Ptr, kind: Kind, level: u8) -> R<Vec<u8>> {
        if let Some(d) = self.dirty.get(&p.addr) {
            let mut b = Vec::new();
            b.try_reserve_exact(BLOCK).map_err(nomem)?;
            b.extend_from_slice(&d.buf);
            return Ok(b);
        }
        if p.addr < RESERVED || p.addr >= self.v.total {
            return Err(self.corrupt("pointer outside the volume"));
        }
        let mut b = Vec::new();
        b.try_reserve_exact(BLOCK).map_err(nomem)?;
        b.resize(BLOCK, 0);
        crate::block::read(self.v.disk, p.addr * SECT, &mut b).map_err(io)?;
        if sha256(&b) != p.sha {
            if kind == Kind::Data {
                return Err(FsError::Corrupt("data block checksum does not match"));
            }
            return Err(self.corrupt("metadata block checksum does not match"));
        }
        let want: Option<&[u8; 4]> = match kind {
            Kind::Data => None,
            Kind::Dspt => Some(KIND_DSPT),
            Kind::Dsnd => Some(KIND_DSND),
            Kind::Dsrt => Some(KIND_DSRT),
        };
        if let Some(k) = want {
            let uuid = self.v.uuid;
            if let Err(w) = check_header(&b, k, level, p.birth, p.addr, &uuid) {
                return Err(self.corrupt(w));
            }
        }
        Ok(b)
    }

    fn alloc(&mut self, kind: Kind, level: u8) -> R<u64> {
        let total = self.v.total;
        let mut a = self.v.cursor.max(RESERVED);
        for _ in 0..total {
            if a >= total {
                a = RESERVED;
            }
            if self.v.map.get(a) == M_FREE && !self.dirty.contains_key(&a) {
                let code = match kind {
                    Kind::Data => M_DATA,
                    Kind::Dspt => m_meta(KIND_DSPT, level),
                    Kind::Dsnd => m_meta(KIND_DSND, 0),
                    Kind::Dsrt => m_meta(KIND_DSRT, 0),
                };
                self.v.map.set(a, code);
                self.v.free -= 1;
                self.v.cursor = a + 1;
                self.allocated += 1;
                self.used_delta += 1;
                return Ok(a);
            }
            a += 1;
        }
        Err(FsError::NoSpace)
    }

    fn new_block(&mut self, kind: Kind, level: u8, buf: Vec<u8>) -> R<u64> {
        let a = self.alloc(kind, level)?;
        self.dirty.insert(a, Dirty { kind, level, buf });
        Ok(a)
    }

    fn zero_block() -> R<Vec<u8>> {
        let mut b = Vec::new();
        b.try_reserve_exact(BLOCK).map_err(nomem)?;
        b.resize(BLOCK, 0);
        Ok(b)
    }

    /// The block behind `p` as a block of this transaction (copied on first change).
    fn cow(&mut self, p: &Ptr, kind: Kind, level: u8) -> R<u64> {
        if self.dirty.contains_key(&p.addr) {
            return Ok(p.addr);
        }
        let b = self.read(p, kind, level)?;
        let a = self.new_block(kind, level, b)?;
        self.drop_block(p);
        Ok(a)
    }

    /// The old version of a block is no longer used by the live tree (R1).
    fn drop_block(&mut self, p: &Ptr) {
        if self.dirty.remove(&p.addr).is_some() {
            // Written by this transaction only – free at once.
            self.v.map.set(p.addr, M_FREE);
            self.v.free += 1;
            self.allocated -= 1;
            self.used_delta -= 1;
            return;
        }
        if self.v.newest_snap == 0 || p.birth > self.v.newest_snap {
            if self.dropped.try_reserve(1).is_ok() {
                self.dropped.push(p.addr);
                self.used_delta -= 1;
            }
            // (out of memory: the block just stays used – leaked until the next mount walk)
        }
    }

    /// Drops a whole subtree (a DSPT at `level`, leaves of `leaf`).
    fn drop_tree(&mut self, p: &Ptr, level: u8, leaf: Kind) -> R<()> {
        let snap_kept = !self.dirty.contains_key(&p.addr) && self.v.newest_snap != 0 && p.birth <= self.v.newest_snap;
        if snap_kept {
            return Ok(()); // a snapshot may hold it, and everything below is no younger
        }
        if level == 0 {
            self.drop_block(p);
            return Ok(());
        }
        let b = self.read(p, Kind::Dspt, level)?;
        for i in 0..FANOUT {
            if let Some(c) = get_ptr(&b, HDR_SIZE + i * PTR_SIZE)? {
                if level == 1 {
                    if leaf == Kind::Data {
                        self.drop_block(&c);
                    } else {
                        self.drop_tree(&c, 0, leaf)?;
                    }
                } else {
                    self.drop_tree(&c, level - 1, leaf)?;
                }
            }
        }
        self.drop_block(p);
        Ok(())
    }

    fn take(&mut self, a: u64) -> Dirty {
        self.dirty.remove(&a).unwrap()
    }
    fn put(&mut self, a: u64, d: Dirty) {
        self.dirty.insert(a, d);
    }

    // ---------------- fixed fan-out trees ----------------

    /// Leaf pointer `index` of a tree whose root is a DSPT at `level`.
    fn tree_get(&mut self, root: Option<Ptr>, level: u8, index: u64) -> R<Option<Ptr>> {
        let mut node = root;
        let mut level = level;
        let mut index = index;
        while let Some(p) = node {
            let s = span(level);
            let i = (index / s) as usize;
            if i >= FANOUT {
                return Ok(None);
            }
            let b = self.read(&p, Kind::Dspt, level)?;
            let c = get_ptr(&b, HDR_SIZE + i * PTR_SIZE)?;
            if level == 1 {
                return Ok(c);
            }
            index %= s;
            level -= 1;
            node = c;
        }
        Ok(None)
    }

    /// Changes leaf `index` (via `f(old) -> new`), copying the path; a pointer block
    /// left without pointers is removed (an empty pointer instead).
    fn tree_set(&mut self, root: Option<Ptr>, level: u8, index: u64, f: &mut dyn FnMut(&mut Tx, Option<Ptr>) -> R<Option<Ptr>>) -> R<Option<Ptr>> {
        let s = span(level);
        let i = (index / s) as usize;
        if i >= FANOUT {
            return Err(FsError::NoSpace);
        }
        let rem = index % s;
        match root {
            None => {
                let c = if level == 1 { f(self, None)? } else { self.tree_set(None, level - 1, rem, f)? };
                let Some(c) = c else { return Ok(None) };
                let mut b = Self::zero_block()?;
                set_ptr(&mut b, HDR_SIZE + i * PTR_SIZE, Some(c));
                let a = self.new_block(Kind::Dspt, level, b)?;
                Ok(Some(placeholder(a, self.gn)))
            }
            Some(p) => {
                let a = self.cow(&p, Kind::Dspt, level)?;
                let mut d = self.take(a);
                let old = match get_ptr(&d.buf, HDR_SIZE + i * PTR_SIZE) {
                    Ok(o) => o,
                    Err(e) => {
                        self.put(a, d);
                        return Err(e);
                    }
                };
                let r = if level == 1 { f(self, old) } else { self.tree_set(old, level - 1, rem, f) };
                let c = match r {
                    Ok(c) => c,
                    Err(e) => {
                        self.put(a, d);
                        return Err(e);
                    }
                };
                set_ptr(&mut d.buf, HDR_SIZE + i * PTR_SIZE, c);
                let empty = zeros(&d.buf[HDR_SIZE..]);
                self.put(a, d);
                if empty {
                    self.drop_block(&placeholder(a, self.gn));
                    return Ok(None);
                }
                Ok(Some(placeholder(a, self.gn)))
            }
        }
    }

    /// Removes every leaf at index >= `keep` below a DSPT at `level` covering from `base`.
    fn tree_trim(&mut self, root: Option<Ptr>, level: u8, base: u64, keep: u64, leaf: Kind) -> R<Option<Ptr>> {
        let Some(p) = root else { return Ok(None) };
        let s = span(level);
        if base >= keep {
            self.drop_tree(&p, level, leaf)?;
            return Ok(None);
        }
        if base + s * FANOUT as u64 <= keep {
            return Ok(Some(p));
        }
        let a = self.cow(&p, Kind::Dspt, level)?;
        let mut d = self.take(a);
        for i in 0..FANOUT {
            let cbase = base + i as u64 * s;
            let o = HDR_SIZE + i * PTR_SIZE;
            let c = match get_ptr(&d.buf, o) {
                Ok(c) => c,
                Err(e) => {
                    self.put(a, d);
                    return Err(e);
                }
            };
            let nc = if level == 1 {
                match c {
                    Some(c) if cbase >= keep => {
                        self.drop_block(&c);
                        None
                    }
                    c => c,
                }
            } else {
                match self.tree_trim(c, level - 1, cbase, keep, leaf) {
                    Ok(x) => x,
                    Err(e) => {
                        self.put(a, d);
                        return Err(e);
                    }
                }
            };
            set_ptr(&mut d.buf, o, nc);
        }
        let empty = zeros(&d.buf[HDR_SIZE..]);
        self.put(a, d);
        if empty {
            self.drop_block(&placeholder(a, self.gn));
            return Ok(None);
        }
        Ok(Some(placeholder(a, self.gn)))
    }

    // ---------------- nodes ----------------

    fn get_node(&mut self, n: u64) -> R<Option<NodeBuf>> {
        if n == 0 {
            return Ok(None);
        }
        let idx = n / NODES_PER_BLOCK;
        let cap = (FANOUT as u64).checked_pow(self.live.depth as u32).unwrap_or(u64::MAX);
        if idx >= cap {
            return Ok(None);
        }
        let leaf = self.tree_get(Some(self.live.nodes), self.live.depth, idx)?;
        let Some(leaf) = leaf else { return Ok(None) };
        let b = self.read(&leaf, Kind::Dsnd, 0)?;
        let off = HDR_SIZE + (n % NODES_PER_BLOCK) as usize * NODE_SIZE;
        match Node::parse(&b[off..], n, self.gn) {
            Ok(Some(_)) => {
                let mut nb = NodeBuf { b: [0; NODE_SIZE] };
                nb.b.copy_from_slice(&b[off..off + NODE_SIZE]);
                Ok(Some(nb))
            }
            Ok(None) => Ok(None),
            Err(w) => Err(self.corrupt(w)),
        }
    }

    /// Writes node `n` (None = free it).  Grows the node table when needed.
    fn put_node(&mut self, n: u64, node: Option<&NodeBuf>) -> R<()> {
        let idx = n / NODES_PER_BLOCK;
        while idx >= (FANOUT as u64).pow(self.live.depth as u32) {
            if self.live.depth >= MAX_DEPTH {
                return Err(FsError::NoSpace);
            }
            let mut b = Self::zero_block()?;
            set_ptr(&mut b, HDR_SIZE, Some(self.live.nodes));
            let a = self.new_block(Kind::Dspt, self.live.depth + 1, b)?;
            self.live.nodes = placeholder(a, self.gn);
            self.live.depth += 1;
        }
        let slot = (n % NODES_PER_BLOCK) as usize;
        let bytes = node.map(|x| x.b);
        let mut f = |tx: &mut Tx, old: Option<Ptr>| -> R<Option<Ptr>> {
            let a = match old {
                Some(o) => tx.cow(&o, Kind::Dsnd, 0)?,
                None => {
                    if bytes.is_none() {
                        return Ok(None);
                    }
                    let b = Self::zero_block()?;
                    tx.new_block(Kind::Dsnd, 0, b)?
                }
            };
            let mut d = tx.take(a);
            let off = HDR_SIZE + slot * NODE_SIZE;
            match bytes {
                Some(b) => d.buf[off..off + NODE_SIZE].copy_from_slice(&b),
                None => d.buf[off..off + NODE_SIZE].fill(0),
            }
            let empty = (0..NODES_PER_BLOCK as usize).all(|s| d.buf[HDR_SIZE + s * NODE_SIZE + 8] == 0);
            tx.put(a, d);
            if empty {
                // Errata E4: no empty node blocks.
                tx.drop_block(&placeholder(a, tx.gn));
                return Ok(None);
            }
            Ok(Some(placeholder(a, tx.gn)))
        };
        let r = self.tree_set(Some(self.live.nodes), self.live.depth, idx, &mut f)?;
        // The range with node 1 is never empty, so the table root stays.
        self.live.nodes = r.ok_or(FsError::Corrupt("node table became empty"))?;
        Ok(())
    }

    fn new_node_number(&mut self) -> R<u64> {
        if let Some(n) = self.v.free_nodes.pop() {
            self.taken_nodes.push(n);
            return Ok(n);
        }
        let n = self.live.next_node;
        self.live.next_node = n.checked_add(1).ok_or(FsError::NoSpace)?;
        Ok(n)
    }

    // ---------------- file data ----------------

    fn data_get(&mut self, node: &NodeBuf, index: u64) -> R<Option<Ptr>> {
        if node.depth() == 0 {
            return if index < 4 { node.direct(index as usize) } else { Ok(None) };
        }
        self.tree_get(node.root()?, node.depth(), index)
    }

    /// Sets data block `index` (the old block is dropped).
    fn data_set(&mut self, node: &mut NodeBuf, index: u64, leaf: Option<Ptr>) -> R<()> {
        if node.depth() == 0 {
            let i = index as usize;
            if let Some(o) = node.direct(i)? {
                self.drop_block(&o);
            }
            node.set_direct(i, leaf);
            return Ok(());
        }
        let mut f = |tx: &mut Tx, old: Option<Ptr>| -> R<Option<Ptr>> {
            if let Some(o) = old {
                tx.drop_block(&o);
            }
            Ok(leaf)
        };
        let r = self.tree_set(node.root()?, node.depth(), index, &mut f)?;
        node.set_root(r);
        Ok(())
    }

    fn grow_depth(&mut self, node: &mut NodeBuf, target: u8) -> R<()> {
        while node.depth() < target {
            if node.depth() == 0 {
                let mut b = Self::zero_block()?;
                let mut any = false;
                for i in 0..4 {
                    let p = node.direct(i)?;
                    any |= p.is_some();
                    set_ptr(&mut b, HDR_SIZE + i * PTR_SIZE, p);
                    node.set_direct(i, None);
                }
                let root = if any { Some(placeholder(self.new_block(Kind::Dspt, 1, b)?, self.gn)) } else { None };
                node.set_root(root);
                node.set_depth(1);
            } else {
                let d = node.depth();
                let root = match node.root()? {
                    Some(r) => {
                        let mut b = Self::zero_block()?;
                        set_ptr(&mut b, HDR_SIZE, Some(r));
                        Some(placeholder(self.new_block(Kind::Dspt, d + 1, b)?, self.gn))
                    }
                    None => None,
                };
                node.set_root(root);
                node.set_depth(d + 1);
            }
        }
        Ok(())
    }

    /// Lowers the depth to `target` (everything past the size already removed).
    fn shrink_depth(&mut self, node: &mut NodeBuf, target: u8) -> R<()> {
        while node.depth() > target {
            let d = node.depth();
            let root = node.root()?;
            if d >= 2 {
                let child = match root {
                    Some(r) => {
                        let b = self.read(&r, Kind::Dspt, d)?;
                        let c = get_ptr(&b, HDR_SIZE)?;
                        self.drop_block(&r);
                        c
                    }
                    None => None,
                };
                node.set_root(child);
                node.set_depth(d - 1);
            } else {
                let mut kids = [None; 4];
                if let Some(r) = root {
                    let b = self.read(&r, Kind::Dspt, 1)?;
                    for (i, k) in kids.iter_mut().enumerate() {
                        *k = get_ptr(&b, HDR_SIZE + i * PTR_SIZE)?;
                    }
                    self.drop_block(&r);
                }
                for (i, k) in kids.iter().enumerate() {
                    node.set_direct(i, *k);
                }
                node.set_depth(0);
            }
        }
        Ok(())
    }

    /// Removes data blocks at index >= `keep`.
    fn trim(&mut self, node: &mut NodeBuf, keep: u64) -> R<()> {
        if node.depth() == 0 {
            for i in keep.min(4) as usize..4 {
                if let Some(o) = node.direct(i)? {
                    self.drop_block(&o);
                }
                node.set_direct(i, None);
            }
            return Ok(());
        }
        let r = self.tree_trim(node.root()?, node.depth(), 0, keep, Kind::Data)?;
        node.set_root(r);
        Ok(())
    }

    /// Drops all data of a node.
    fn drop_data(&mut self, node: &NodeBuf) -> R<()> {
        if node.depth() == 0 {
            for i in 0..4 {
                if let Some(o) = node.direct(i)? {
                    self.drop_block(&o);
                }
            }
            return Ok(());
        }
        if let Some(r) = node.root()? {
            self.drop_tree(&r, node.depth(), Kind::Data)?;
        }
        Ok(())
    }

    fn read_data_block(&mut self, node: &NodeBuf, index: u64) -> R<Vec<u8>> {
        match self.data_get(node, index)? {
            Some(p) => self.read(&p, Kind::Data, 0),
            None => Self::zero_block(),
        }
    }

    /// Replaces data block `index` with `content` (a new block).
    fn write_data_block(&mut self, node: &mut NodeBuf, index: u64, content: Vec<u8>) -> R<()> {
        let a = self.new_block(Kind::Data, 0, content)?;
        let p = placeholder(a, self.gn);
        self.data_set(node, index, Some(p))
    }

    // ---------------- directories ----------------

    /// A directory block (checked: present, checksum, layout).
    fn dir_block(&mut self, dir: &NodeBuf, index: u64) -> R<Vec<u8>> {
        let Some(p) = self.data_get(dir, index)? else {
            return Err(self.corrupt("hole in a directory"));
        };
        let b = self.read(&p, Kind::Data, 0)?;
        if let Err(w) = check_dir_block(&b, |_, _, _| Ok(())) {
            return Err(self.corrupt(w));
        }
        Ok(b)
    }

    /// Finds `name` in a directory: (block, offset, node, type).
    fn dir_find(&mut self, dir: &NodeBuf, name: &[u8]) -> R<Option<(u64, usize, u64, u8)>> {
        for bi in 0..dir.blocks() {
            let b = self.dir_block(dir, bi)?;
            let mut off = 0;
            while off < BLOCK {
                let rec = u16_at(&b, off + 10) as usize;
                let node = u64_at(&b, off);
                let len = b[off + 9] as usize;
                if node != 0 && &b[off + 12..off + 12 + len] == name {
                    return Ok(Some((bi, off, node, b[off + 8])));
                }
                off += rec;
            }
        }
        Ok(None)
    }

    /// Looks up a node from a directory and checks it matches the entry.
    fn entry_node(&mut self, dir_n: u64, node: u64, typ: u8) -> R<NodeBuf> {
        let Some(nb) = self.get_node(node)? else {
            return Err(self.corrupt("directory entry points to a free node"));
        };
        if nb.typ() != typ || nb.parent() != dir_n {
            return Err(self.corrupt("directory entry does not match its node"));
        }
        Ok(nb)
    }

    fn dir_active(&mut self, dir: &NodeBuf) -> R<usize> {
        let mut n = 0;
        for bi in 0..dir.blocks() {
            let b = self.dir_block(dir, bi)?;
            n += check_dir_block(&b, |_, _, _| Ok(())).map_err(FsError::Corrupt)?;
        }
        Ok(n)
    }

    /// Adds an entry (the directory node is updated in `dir`, written by the caller).
    fn dir_insert(&mut self, dir: &mut NodeBuf, name: &[u8], node: u64, typ: u8) -> R<()> {
        if self.dir_active(dir)? >= DIR_MAX_ENTRIES {
            return Err(FsError::TooMany);
        }
        let need = round8(12 + name.len());
        let write_entry = |b: &mut [u8], off: usize, rec: usize| {
            b[off..off + rec].fill(0);
            b[off..off + 8].copy_from_slice(&node.to_le_bytes());
            b[off + 8] = typ;
            b[off + 9] = name.len() as u8;
            b[off + 10..off + 12].copy_from_slice(&(rec as u16).to_le_bytes());
            b[off + 12..off + 12 + name.len()].copy_from_slice(name);
        };
        for bi in 0..dir.blocks() {
            let mut b = self.dir_block(dir, bi)?;
            let mut off = 0;
            let mut done = false;
            while off < BLOCK {
                let rec = u16_at(&b, off + 10) as usize;
                let cur = u64_at(&b, off);
                if cur == 0 && rec >= need {
                    if rec - need >= 16 {
                        write_entry(&mut b, off, need);
                        b[off + need..off + rec].fill(0);
                        b[off + need + 10..off + need + 12].copy_from_slice(&((rec - need) as u16).to_le_bytes());
                    } else {
                        write_entry(&mut b, off, rec);
                    }
                    done = true;
                    break;
                }
                if cur != 0 {
                    let used = round8(12 + b[off + 9] as usize);
                    if rec - used >= need {
                        b[off + 10..off + 12].copy_from_slice(&(used as u16).to_le_bytes());
                        write_entry(&mut b, off + used, rec - used);
                        done = true;
                        break;
                    }
                }
                off += rec;
            }
            if done {
                self.write_data_block(dir, bi, b)?;
                dir.touch();
                return Ok(());
            }
        }
        // A new block at the end.
        let bi = dir.blocks();
        let new_size = (bi + 1) * BLOCK as u64;
        let target = min_depth(bi + 1);
        if target > MAX_DEPTH || bi + 1 > capacity(MAX_DEPTH) {
            return Err(FsError::NoSpace);
        }
        self.grow_depth(dir, target)?;
        let mut b = Self::zero_block()?;
        write_entry(&mut b, 0, BLOCK);
        self.write_data_block(dir, bi, b)?;
        dir.set_size(new_size);
        dir.touch();
        Ok(())
    }

    fn dir_remove(&mut self, dir: &mut NodeBuf, bi: u64, off: usize) -> R<()> {
        let mut b = self.dir_block(dir, bi)?;
        let rec = u16_at(&b, off + 10) as usize;
        b[off..off + rec].fill(0);
        b[off + 10..off + 12].copy_from_slice(&(rec as u16).to_le_bytes());
        self.write_data_block(dir, bi, b)?;
        dir.touch();
        Ok(())
    }

    fn dir_list(&mut self, dir_n: u64, dir: &NodeBuf, max: usize) -> R<Vec<DirEntry>> {
        let mut out = Vec::new();
        for bi in 0..dir.blocks() {
            let b = self.dir_block(dir, bi)?;
            let mut off = 0;
            while off < BLOCK {
                let rec = u16_at(&b, off + 10) as usize;
                let node = u64_at(&b, off);
                if node != 0 {
                    if out.len() >= max {
                        return Err(FsError::TooMany);
                    }
                    let len = b[off + 9] as usize;
                    let name = core::str::from_utf8(&b[off + 12..off + 12 + len]).map_err(|_| FsError::Corrupt("name"))?;
                    let nb = self.entry_node(dir_n, node, b[off + 8])?;
                    let e = DirEntry {
                        name: String::from(name),
                        kind: if nb.is_dir() { FileType::Directory } else { FileType::File },
                        size: nb.size(),
                        modified: Some(crate::drivers::rtc::DateTime::from_unix(nb.modified())),
                    };
                    crate::fs::try_push(&mut out, e)?;
                }
                off += rec;
            }
        }
        Ok(out)
    }

    /// Part of a directory from byte position `cursor` = logical block × 4096 + offset of
    /// an entry (docs/desofs/FORMAT.md chapter 13): up to `max` entries and the position of the
    /// next active entry (None = end).  The position must be the start of an entry
    /// (FsError::BadCursor otherwise); deleted entries are stepped over by their length.
    fn dir_list_at(&mut self, dir_n: u64, dir: &NodeBuf, cursor: u64, max: usize) -> R<crate::fs::DirPart> {
        let blocks = dir.blocks();
        let (bi0, off0) = (cursor / BLOCK as u64, (cursor % BLOCK as u64) as usize);
        if bi0 > blocks || (bi0 == blocks && off0 != 0) {
            return Err(FsError::BadCursor);
        }
        let max = max.max(1);
        let mut out = Vec::new();
        for bi in bi0..blocks {
            let b = self.dir_block(dir, bi)?;
            let mut off = 0;
            if bi == bi0 {
                // Step from the block start to the cursor: it must land on an entry.
                while off < off0 {
                    off += u16_at(&b, off + 10) as usize;
                }
                if off != off0 {
                    return Err(FsError::BadCursor);
                }
            }
            while off < BLOCK {
                let rec = u16_at(&b, off + 10) as usize;
                let node = u64_at(&b, off);
                if node != 0 {
                    if out.len() >= max {
                        return Ok((out, Some(bi * BLOCK as u64 + off as u64)));
                    }
                    let len = b[off + 9] as usize;
                    let name = core::str::from_utf8(&b[off + 12..off + 12 + len]).map_err(|_| FsError::Corrupt("name"))?;
                    let nb = self.entry_node(dir_n, node, b[off + 8])?;
                    let e = DirEntry {
                        name: String::from(name),
                        kind: if nb.is_dir() { FileType::Directory } else { FileType::File },
                        size: nb.size(),
                        modified: Some(crate::drivers::rtc::DateTime::from_unix(nb.modified())),
                    };
                    crate::fs::try_push(&mut out, (bi * BLOCK as u64 + off as u64, e))?;
                }
                off += rec;
            }
        }
        Ok((out, None))
    }

    // ---------------- paths ----------------

    /// Node of `path` ("/" = 1): (number, node, parent number, name, block, offset).
    fn lookup(&mut self, path: &str) -> R<(u64, NodeBuf, Option<(u64, u64, usize)>)> {
        let mut n = 1;
        let mut nb = self.get_node(1)?.ok_or(FsError::Corrupt("no root directory"))?;
        let mut loc = None;
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            if !nb.is_dir() {
                return Err(FsError::NotADirectory);
            }
            let Some((bi, off, child, typ)) = self.dir_find(&nb, comp.as_bytes())? else {
                return Err(FsError::NotFound);
            };
            let cb = self.entry_node(n, child, typ)?;
            loc = Some((n, bi, off));
            n = child;
            nb = cb;
        }
        Ok((n, nb, loc))
    }

    /// Parent directory and name of a new entry.
    fn parent_of<'p>(&mut self, path: &'p str) -> R<(u64, NodeBuf, &'p str)> {
        let (parent, name) = crate::fs::split_parent(path);
        check_name(name)?;
        let (pn, pb, _) = self.lookup(parent)?;
        if !pb.is_dir() {
            return Err(FsError::NotADirectory);
        }
        Ok((pn, pb, name))
    }

    // ---------------- operations ----------------

    fn create(&mut self, path: &str, typ: u8) -> R<()> {
        let (pn, mut pb, name) = self.parent_of(path)?;
        if self.dir_find(&pb, name.as_bytes())?.is_some() {
            return Err(FsError::AlreadyExists);
        }
        let n = self.new_node_number()?;
        let nb = NodeBuf::new(n, typ, pn, self.gn);
        self.put_node(n, Some(&nb))?;
        self.dir_insert(&mut pb, name.as_bytes(), n, typ)?;
        self.put_node(pn, Some(&pb))
    }

    fn write(&mut self, path: &str, offset: u64, data: &[u8]) -> R<usize> {
        let (n, mut nb, _) = self.lookup(path)?;
        if nb.is_dir() {
            return Err(FsError::IsADirectory);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let end = offset.checked_add(data.len() as u64).ok_or(FsError::NoSpace)?;
        let new_size = nb.size().max(end);
        let blocks = new_size.div_ceil(BLOCK as u64);
        if blocks > capacity(MAX_DEPTH) {
            return Err(FsError::NoSpace);
        }
        self.grow_depth(&mut nb, min_depth(blocks))?;
        let first = offset / BLOCK as u64;
        let last = (end - 1) / BLOCK as u64;
        let mut done = 0usize;
        for bi in first..=last {
            let bstart = bi * BLOCK as u64;
            let from = offset.max(bstart) - bstart;
            let to = end.min(bstart + BLOCK as u64) - bstart;
            let mut b = if from == 0 && to == BLOCK as u64 { Self::zero_block()? } else { self.read_data_block(&nb, bi)? };
            let n_here = (to - from) as usize;
            b[from as usize..to as usize].copy_from_slice(&data[done..done + n_here]);
            done += n_here;
            self.write_data_block(&mut nb, bi, b)?;
        }
        nb.set_size(new_size);
        nb.touch();
        self.put_node(n, Some(&nb))?;
        Ok(data.len())
    }

    fn truncate(&mut self, path: &str, size: u64) -> R<()> {
        let (n, mut nb, _) = self.lookup(path)?;
        if nb.is_dir() {
            return Err(FsError::IsADirectory);
        }
        let old = nb.size();
        let blocks = size.div_ceil(BLOCK as u64);
        if blocks > capacity(MAX_DEPTH) {
            return Err(FsError::NoSpace);
        }
        if size < old {
            self.trim(&mut nb, blocks)?;
            let tail = (size % BLOCK as u64) as usize;
            if tail != 0 {
                // Bytes past the new end of the last block are zero (they show if the
                // file grows again).
                let bi = blocks - 1;
                if self.data_get(&nb, bi)?.is_some() {
                    let mut b = self.read_data_block(&nb, bi)?;
                    b[tail..].fill(0);
                    self.write_data_block(&mut nb, bi, b)?;
                }
            }
            self.shrink_depth(&mut nb, min_depth(blocks))?;
        } else if size > old {
            self.grow_depth(&mut nb, min_depth(blocks))?;
        }
        nb.set_size(size);
        nb.touch();
        self.put_node(n, Some(&nb))
    }

    fn remove(&mut self, path: &str) -> R<()> {
        let (n, nb, loc) = self.lookup(path)?;
        let Some((pn, bi, off)) = loc else { return Err(FsError::Busy) };
        if nb.is_dir() && self.dir_active(&nb)? != 0 {
            return Err(FsError::NotEmpty);
        }
        let mut pb = self.get_node(pn)?.ok_or(FsError::Corrupt("parent vanished"))?;
        self.dir_remove(&mut pb, bi, off)?;
        self.put_node(pn, Some(&pb))?;
        self.drop_data(&nb)?;
        self.put_node(n, None)?;
        self.freed_nodes.push(n);
        Ok(())
    }

    fn rename(&mut self, from: &str, to: &str) -> R<()> {
        let (sn, mut sb, sloc) = self.lookup(from)?;
        let Some((spn, sbi, soff)) = sloc else { return Err(FsError::Busy) };
        let (dpn, _dpb, dname) = self.parent_of(to)?;
        // A directory cannot go into itself or below.
        if sb.is_dir() {
            let mut p = dpn;
            loop {
                if p == sn {
                    return Err(FsError::InvalidName);
                }
                if p == 1 {
                    break;
                }
                p = self.get_node(p)?.ok_or(FsError::Corrupt("broken parent chain"))?.parent();
            }
        }
        // The target name.
        let dpb0 = self.get_node(dpn)?.ok_or(FsError::Corrupt("parent vanished"))?;
        if let Some((tbi, toff, tn, ttyp)) = self.dir_find(&dpb0, dname.as_bytes())? {
            if tn == sn {
                return Ok(()); // the same entry
            }
            let tb = self.entry_node(dpn, tn, ttyp)?;
            match (sb.is_dir(), tb.is_dir()) {
                (false, true) => return Err(FsError::IsADirectory),
                (true, false) => return Err(FsError::NotADirectory),
                (true, true) if self.dir_active(&tb)? != 0 => return Err(FsError::NotEmpty),
                _ => {}
            }
            // Replace: the target entry and node go (in this same commit).
            let mut dpb = dpb0;
            self.dir_remove(&mut dpb, tbi, toff)?;
            self.put_node(dpn, Some(&dpb))?;
            self.drop_data(&tb)?;
            self.put_node(tn, None)?;
            self.freed_nodes.push(tn);
        }
        // Out of the source directory (read again – it may be the same directory).
        let mut spb = self.get_node(spn)?.ok_or(FsError::Corrupt("parent vanished"))?;
        self.dir_remove(&mut spb, sbi, soff)?;
        self.put_node(spn, Some(&spb))?;
        let mut dpb = self.get_node(dpn)?.ok_or(FsError::Corrupt("parent vanished"))?;
        self.dir_insert(&mut dpb, dname.as_bytes(), sn, sb.typ())?;
        self.put_node(dpn, Some(&dpb))?;
        if spn != dpn {
            sb.set_parent(dpn);
            self.put_node(sn, Some(&sb))?;
        }
        Ok(())
    }

    // ---------------- upper bounds of new blocks ----------------

    /// New blocks to change one node (its node block and the table path).
    fn node_cost(&self) -> u64 {
        self.live.depth as u64 + 2
    }

    /// New blocks to rewrite `k` data blocks of a tree that will have `depth`.
    fn data_cost(k: u64, depth: u8) -> u64 {
        let mut c = k;
        let mut level_k = k;
        for _ in 0..depth {
            level_k = level_k.div_ceil(FANOUT as u64) + 1;
            c += level_k;
        }
        c + depth as u64
    }

    /// Changing one directory: an entry block (or a new one), its path, depth growth.
    fn dir_cost(&mut self, dir_depth: u8) -> u64 {
        Self::data_cost(1, dir_depth + 1) + self.node_cost()
    }

    // ---------------- commit ----------------

    /// Computes the checksums below a block of this transaction (children first).
    fn seal(&mut self, a: u64) -> R<()> {
        let Some(mut d) = self.dirty.remove(&a) else { return Ok(()) };
        let mut offs: Vec<usize> = Vec::new();
        let count;
        match d.kind {
            Kind::Data => {
                self.dirty.insert(a, d);
                return Ok(());
            }
            Kind::Dsrt => {
                let mut c = 0;
                for i in 0..ROOT_ENTRIES {
                    let o = HDR_SIZE + i * ROOT_ENTRY;
                    if d.buf[o + 49] != 0 {
                        c += 1;
                        offs.push(o);
                    }
                }
                count = c;
            }
            Kind::Dspt => {
                let mut c = 0;
                for i in 0..FANOUT {
                    let o = HDR_SIZE + i * PTR_SIZE;
                    if u64_at(&d.buf, o) != 0 {
                        c += 1;
                        offs.push(o);
                    }
                }
                count = c;
            }
            Kind::Dsnd => {
                let mut c = 0;
                for s in 0..NODES_PER_BLOCK as usize {
                    let o = HDR_SIZE + s * NODE_SIZE;
                    if d.buf[o + 8] == 0 {
                        continue;
                    }
                    c += 1;
                    let n = if d.buf[o + 9] == 0 { 4 } else { 1 };
                    for k in 0..n {
                        if u64_at(&d.buf, o + 56 + k * PTR_SIZE) != 0 {
                            offs.push(o + 56 + k * PTR_SIZE);
                        }
                    }
                }
                count = c;
            }
        }
        for o in offs {
            let child = u64_at(&d.buf, o);
            if self.dirty.contains_key(&child) {
                self.seal(child)?;
                let h = sha256(&self.dirty.get(&child).unwrap().buf);
                d.buf[o + 8..o + 16].copy_from_slice(&self.gn.to_le_bytes());
                d.buf[o + 16..o + 48].copy_from_slice(&h);
            }
        }
        let k: &[u8; 4] = match d.kind {
            Kind::Dsrt => KIND_DSRT,
            Kind::Dspt => KIND_DSPT,
            _ => KIND_DSND,
        };
        let uuid = self.v.uuid;
        header(&mut d.buf, k, d.level, count as u16, self.gn, a, &uuid);
        self.dirty.insert(a, d);
        Ok(())
    }

    fn fail(&mut self, why: &str) -> FsError {
        self.v.ro = Some(String::from(why));
        crate::serial_println!("[DESOFS] disk {}: {} - now read-only", self.v.disk, why);
        FsError::ReadOnly
    }

    fn commit(mut self) -> R<()> {
        // New root block: the committed one with the live entry replaced.
        let root = self.v.root;
        let mut rb = self.read(&root, Kind::Dsrt, 0)?;
        let o = HDR_SIZE;
        set_ptr(&mut rb, o, Some(self.live.nodes));
        rb[o + 48] = self.live.depth;
        rb[o + 56..o + 64].copy_from_slice(&self.live.next_node.to_le_bytes());
        for (i, e) in core::mem::take(&mut self.root_edits) {
            put_entry(&mut rb, i, e.as_ref());
        }
        let ra = self.new_block(Kind::Dsrt, 0, rb)?;
        // The old root block is never part of a snapshot.
        self.dropped.push(root.addr);
        self.used_delta -= 1;
        self.seal(ra)?;
        let rsha = sha256(&self.dirty.get(&ra).unwrap().buf);
        let new_root = Ptr { addr: ra, birth: self.gn, sha: rsha };
        // 1. New blocks.
        let disk = self.v.disk;
        let mut err = None;
        for (a, d) in self.dirty.iter() {
            if let Err(e) = crate::block::write(disk, a * SECT, &d.buf) {
                err = Some(e);
                break;
            }
        }
        if err.is_some() {
            return Err(self.fail("write error during a commit"));
        }
        // 2. Flush.
        if crate::block::flush(disk).is_err() {
            return Err(self.fail("flush error during a commit"));
        }
        // 3. Superblock to the slot with the older generation (bad slot = oldest, tie -> B).
        let slot = match self.v.slot_gen {
            [None, _] => 0,
            [_, None] => 1,
            [Some(a), Some(b)] => if a < b { 0 } else { 1 },
        };
        let used = (self.v.used as i64 + self.used_delta).max(0) as u64;
        let rp = ptr_bytes(Some(new_root));
        let sb = superblock(&self.v.uuid, self.gn, self.v.total, used, now(), &rp, &self.v.label);
        if crate::block::write(disk, (1 + slot as u64) * SECT, &sb).is_err() {
            return Err(self.fail("superblock write error"));
        }
        // 4. Flush – only now is the operation done.
        if crate::block::flush(disk).is_err() {
            return Err(self.fail("flush error after the superblock"));
        }
        // 5. Adopt the new state; blocks dropped by the previous commit are now free.
        let v = &mut *self.v;
        for a in v.pending_free.drain(..) {
            v.map.set(a, M_FREE);
            v.free += 1;
        }
        v.pending_free = core::mem::take(&mut self.dropped);
        v.free_nodes.extend(self.freed_nodes.drain(..));
        v.slot_gen[slot] = Some(self.gn);
        v.gn = self.gn;
        v.root = new_root;
        // Every entry as sealed (real checksums instead of placeholders; snapshots added,
        // removed or the live one replaced by this commit), and R1's newest snapshot.
        let rbuf = &self.dirty.get(&ra).unwrap().buf;
        let mut entries = Vec::new();
        if entries.try_reserve_exact(ROOT_ENTRIES).is_err() {
            v.ro = Some(String::from("out of memory after a commit"));
        } else {
            let mut newest = 0;
            for i in 0..ROOT_ENTRIES {
                if let Ok(Some(e)) = RootEntry::parse(&rbuf[HDR_SIZE + i * ROOT_ENTRY..], i, self.gn) {
                    if e.kind == ROOT_SNAPSHOT {
                        newest = newest.max(e.created_gen);
                    }
                    entries.push((i, e));
                }
            }
            v.entries = entries;
            v.newest_snap = newest;
        }
        v.used = used;
        v.counters.last_alloc = self.allocated;
        v.counters.max_over = v.counters.max_over.max(self.allocated.saturating_sub(v.counters.last_bound));
        v.counters.commits += 1;
        self.dirty.clear();
        Ok(())
    }

    fn abort(mut self) {
        for (a, _) in core::mem::take(&mut self.dirty) {
            self.v.map.set(a, M_FREE);
            self.v.free += 1;
        }
        for n in self.taken_nodes.drain(..) {
            self.v.free_nodes.push(n);
        }
    }
}

// ---------------- the VFS interface ----------------

impl FileSystem for Volume {
    fn kind(&self) -> &'static str {
        "desofs"
    }
    fn source(&self) -> String {
        match &self.view {
            Some((_, name)) => alloc::format!("disk {}, snapshot {}", self.disk, name),
            None => alloc::format!("disk {}", self.disk),
        }
    }
    fn disk(&self) -> Option<usize> {
        Some(self.disk)
    }
    fn with_desofs(&mut self, f: &mut dyn FnMut(&mut Volume)) -> bool {
        if self.view.is_some() {
            return false; // a snapshot view is not the volume
        }
        f(self);
        true
    }
    fn stat(&mut self, path: &str) -> R<Metadata> {
        self.read_op(|tx| {
            let (_, nb, _) = tx.lookup(path)?;
            Ok(Metadata {
                kind: if nb.is_dir() { FileType::Directory } else { FileType::File },
                size: nb.size(),
                modified: Some(crate::drivers::rtc::DateTime::from_unix(nb.modified())),
            })
        })
    }
    fn read_dir(&mut self, path: &str) -> R<Vec<DirEntry>> {
        self.read_dir_max(path, usize::MAX)
    }
    fn read_dir_max(&mut self, path: &str, max: usize) -> R<Vec<DirEntry>> {
        self.read_op(|tx| {
            let (n, nb, _) = tx.lookup(path)?;
            if !nb.is_dir() {
                return Err(FsError::NotADirectory);
            }
            tx.dir_list(n, &nb, max)
        })
    }
    fn read_dir_at(&mut self, path: &str, cursor: u64, max: usize) -> R<crate::fs::DirPart> {
        self.read_op(|tx| {
            let (n, nb, _) = tx.lookup(path)?;
            if !nb.is_dir() {
                return Err(FsError::NotADirectory);
            }
            tx.dir_list_at(n, &nb, cursor, max)
        })
    }
    fn read(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> R<usize> {
        self.read_op(|tx| {
            let (_, nb, _) = tx.lookup(path)?;
            if nb.is_dir() {
                return Err(FsError::IsADirectory);
            }
            if offset >= nb.size() {
                return Ok(0);
            }
            let n = (buf.len() as u64).min(nb.size() - offset) as usize;
            let mut done = 0;
            while done < n {
                let pos = offset + done as u64;
                let bi = pos / BLOCK as u64;
                let from = (pos % BLOCK as u64) as usize;
                let k = (BLOCK - from).min(n - done);
                let b = tx.read_data_block(&nb, bi)?;
                buf[done..done + k].copy_from_slice(&b[from..from + k]);
                done += k;
            }
            Ok(n)
        })
    }
    fn write(&mut self, path: &str, offset: u64, data: &[u8]) -> R<usize> {
        self.write_op(
            |tx| {
                let (_, nb, _) = tx.lookup(path)?;
                let end = offset.saturating_add(data.len() as u64).max(nb.size());
                let depth = min_depth(end.div_ceil(BLOCK as u64));
                let k = (data.len() as u64).div_ceil(BLOCK as u64) + 1;
                Ok((Tx::data_cost(k, depth) + tx.node_cost(), false))
            },
            |tx| tx.write(path, offset, data),
        )
    }
    fn truncate(&mut self, path: &str, size: u64) -> R<()> {
        self.write_op(
            |tx| {
                let (_, nb, _) = tx.lookup(path)?;
                let depth = nb.depth().max(min_depth(size.div_ceil(BLOCK as u64)));
                Ok((Tx::data_cost(1, depth) + tx.node_cost(), size < nb.size()))
            },
            |tx| tx.truncate(path, size),
        )
    }
    fn create(&mut self, path: &str) -> R<()> {
        self.write_op(
            |tx| {
                let (_, pb, _) = tx.parent_of(path)?;
                Ok((tx.dir_cost(pb.depth()) + 2 * tx.node_cost(), false))
            },
            |tx| tx.create(path, TYPE_FILE),
        )
    }
    fn mkdir(&mut self, path: &str) -> R<()> {
        self.write_op(
            |tx| {
                let (_, pb, _) = tx.parent_of(path)?;
                Ok((tx.dir_cost(pb.depth()) + 2 * tx.node_cost(), false))
            },
            |tx| tx.create(path, TYPE_DIR),
        )
    }
    fn remove(&mut self, path: &str) -> R<()> {
        self.write_op(
            |tx| {
                let (_, _, loc) = tx.lookup(path)?;
                let pd = match loc {
                    Some((pn, _, _)) => tx.get_node(pn)?.map(|p| p.depth()).unwrap_or(0),
                    None => 0,
                };
                Ok((tx.dir_cost(pd) + 2 * tx.node_cost(), true))
            },
            |tx| tx.remove(path),
        )
    }
    fn rename(&mut self, from: &str, to: &str) -> R<()> {
        self.write_op(
            |tx| {
                let (_, _, loc) = tx.lookup(from)?;
                let sd = match loc {
                    Some((pn, _, _)) => tx.get_node(pn)?.map(|p| p.depth()).unwrap_or(0),
                    None => 0,
                };
                let (_, dpb, _) = tx.parent_of(to)?;
                Ok((tx.dir_cost(sd) + 2 * tx.dir_cost(dpb.depth()) + 3 * tx.node_cost(), true))
            },
            |tx| tx.rename(from, to),
        )
    }
    fn stats(&mut self) -> Option<FsStats> {
        let usable = self.free.saturating_sub(self.reserve());
        Some(FsStats { total_bytes: self.total * BLOCK as u64, free_bytes: usable * BLOCK as u64 })
    }
    fn sync(&mut self) -> R<()> {
        Ok(()) // every operation is committed before it returns
    }
    fn read_only(&self) -> bool {
        self.ro.is_some()
    }
}
