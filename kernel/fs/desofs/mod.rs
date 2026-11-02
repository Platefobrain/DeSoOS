// DeSoFS – DeSoOS's own copy-on-write file system (format 1, docs/DESOFS-FORMAT.md).
//
// So far (stage 1): read-only checking of a volume – `probe(disk)` reads both
// superblocks, walks every tree reachable from them, checks every metadata block
// and node against the specification and decides what a mount would be allowed to
// do (read-write, read-only, or refused).  Nothing is ever written here; there is no
// allocator and no file access yet.
//
// The walk (chapter 9 + errata E1, E3):
// * a map with one byte per block: free / reserved / DATA / METADATA with kind and
//   level – the same bytes can never serve two roles, whatever order the walk meets
//   them in;
// * one bit per block for the root being walked: a block reached twice inside one
//   root is damage (no sharing inside a tree in format 1);
// * a metadata block met again from another root (the other superblock, a snapshot)
//   is read again and checked with the new pointer – checksum, birth, kind, level –
//   and its subtree is then skipped (it was checked already);
// * the live root of the newer superblock is walked first, so its duplicate check is
//   complete (E3).
//
// SHA-256 comes from DeSoCrypto (common/desocrypto) – the kernel's first use of it.

pub mod layout;
pub mod format;
pub mod vol;
pub mod check;
#[cfg(selftest)]
pub mod test;
#[cfg(selftest)]
pub mod test_write;
#[cfg(selftest)]
pub mod test_crash;
#[cfg(selftest)]
pub mod test_check;
#[cfg(selftest)]
pub mod restart;

#[path = "../../../common/desocrypto/mod.rs"]
mod desocrypto;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use layout::*;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    desocrypto::sha256::sha256(data)
}

/// What a mount of the volume may do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// Both trees known – writes allowed (from stage 2 on).
    ReadWrite,
    /// Readable, but not every reachable block is known (or a feature asks for it).
    ReadOnly(String),
    /// Nothing safe to mount; the disk is left untouched.
    Refused(String),
}

/// Result of `probe`.
#[derive(Clone, Debug)]
pub struct Report {
    pub state: State,
    /// Superblock slot the volume would be mounted from (1 = A, 2 = B; 0 when refused).
    pub slot: u8,
    /// Slot the next commit goes to (the older one; B on a tie).
    pub next_slot: u8,
    pub generation: u64,
    pub total_blocks: u64,
    pub used_stored: u64,
    /// Distinct blocks reachable from the chosen superblock (None if not counted).
    pub used_counted: Option<u64>,
    pub nodes: u64,
    pub snapshots: u32,
    pub label: String,
    pub uuid: [u8; 16],
    /// Bytes taken by the two maps.
    pub map_bytes: usize,
    pub warnings: Vec<String>,
}

impl Report {
    fn refused(why: String) -> Report {
        Report {
            state: State::Refused(why),
            slot: 0,
            next_slot: 0,
            generation: 0,
            total_blocks: 0,
            used_stored: 0,
            used_counted: None,
            nodes: 0,
            snapshots: 0,
            label: String::new(),
            uuid: [0; 16],
            map_bytes: 0,
            warnings: Vec::new(),
        }
    }
}

// ------------------------------------------------------------
// Device access – only reads.
// ------------------------------------------------------------

pub(crate) struct Dev {
    pub(crate) index: usize,
    /// Whole 4 KiB blocks the device holds.
    pub(crate) blocks: u64,
}

impl Dev {
    pub(crate) fn open(index: usize) -> Result<Dev, String> {
        let sectors = crate::block::with_device(index, |d| d.sector_count()).map_err(|e| format!("disk {}: {}", index, e))?;
        Ok(Dev { index, blocks: sectors / (BLOCK as u64 / crate::block::SECTOR_SIZE as u64) })
    }

    pub(crate) fn read(&self, block: u64, buf: &mut [u8]) -> Result<(), String> {
        let lba = block.checked_mul((BLOCK / crate::block::SECTOR_SIZE) as u64).ok_or_else(|| String::from("block address overflow"))?;
        if block >= self.blocks {
            return Err(format!("block {} beyond the device", block));
        }
        crate::block::read(self.index, lba, &mut buf[..BLOCK]).map_err(|e| format!("read error at block {}: {}", block, e))
    }
}

// ------------------------------------------------------------
// The maps (errata E1) – in 64 KiB pieces, allocated fallibly.
// ------------------------------------------------------------

const CHUNK: usize = 64 * 1024;

/// One byte per block.
pub(crate) const M_FREE: u8 = 0;
pub(crate) const M_RESERVED: u8 = 1;
pub(crate) const M_DATA: u8 = 2;
/// METADATA: 0x80 | kind << 4 | level.
pub(crate) fn m_meta(kind: &[u8; 4], level: u8) -> u8 {
    let k = if kind == KIND_DSRT { 1 } else if kind == KIND_DSPT { 2 } else { 3 };
    0x80 | (k << 4) | level
}

pub(crate) struct ByteMap {
    chunks: Vec<Vec<u8>>,
}

impl ByteMap {
    pub(crate) fn new(len: u64) -> Option<ByteMap> {
        let n = (len as usize).div_ceil(CHUNK);
        let mut chunks = Vec::new();
        chunks.try_reserve_exact(n).ok()?;
        for k in 0..n {
            let size = CHUNK.min(len as usize - k * CHUNK);
            let mut c = Vec::new();
            c.try_reserve_exact(size).ok()?;
            c.resize(size, 0);
            chunks.push(c);
        }
        Some(ByteMap { chunks })
    }
    pub(crate) fn get(&self, i: u64) -> u8 {
        self.chunks[i as usize / CHUNK][i as usize % CHUNK]
    }
    pub(crate) fn set(&mut self, i: u64, v: u8) {
        self.chunks[i as usize / CHUNK][i as usize % CHUNK] = v;
    }
    fn clear(&mut self) {
        for c in self.chunks.iter_mut() {
            c.fill(0);
        }
    }
    fn bytes(&self) -> usize {
        self.chunks.iter().map(|c| c.len()).sum()
    }
    pub(crate) fn len(&self) -> u64 {
        self.bytes() as u64
    }
}

/// One bit per block (the root being walked).
struct BitMap {
    bytes: ByteMap,
}

impl BitMap {
    fn new(len: u64) -> Option<BitMap> {
        Some(BitMap { bytes: ByteMap::new(len.div_ceil(8))? })
    }
    /// Sets the bit; true if it was already set.
    fn test_and_set(&mut self, i: u64) -> bool {
        let b = self.bytes.get(i / 8);
        let m = 1u8 << (i % 8);
        self.bytes.set(i / 8, b | m);
        b & m != 0
    }
}

// ------------------------------------------------------------
// The walk.
// ------------------------------------------------------------

/// Statistics of one superblock's walk.
#[derive(Default)]
struct Walked {
    nodes: u64,
    snapshots: u32,
    /// Blocks newly marked by this walk.
    marked: u64,
}

struct Scan<'a> {
    dev: &'a Dev,
    total: u64,
    sb_gen: u64,
    uuid: [u8; 16],
    map: &'a mut ByteMap,
    root_bits: &'a mut BitMap,
    /// One 4 KiB buffer per depth of the walk (heap – the walk nests ~12 levels).
    bufs: Vec<Vec<u8>>,
    marked: u64,
    /// When set: every newly marked block is recorded (the older superblock's own
    /// blocks – freed after the first commit of a read-write mount).
    collect: Option<Vec<u64>>,
    /// Free node numbers below `next_node` seen in the live root of the newer
    /// superblock (reused first when files are created).
    free_nodes: Vec<u64>,
    collect_free: bool,
    first_root: bool,
    next_node_limit: u64,
}

/// Most free node numbers remembered from a mount walk.
const FREE_NODES_MAX: usize = 4096;

enum Met {
    /// First time: the block was read, checked and is in `bufs[depth]`.
    Fresh,
    /// Checked before from another root; read again and identical – skip the subtree.
    Shared,
}

type Res<T> = Result<T, String>;

fn at(addr: u64, why: &str) -> String {
    format!("block {}: {}", addr, why)
}

impl<'a> Scan<'a> {
    fn buf(&mut self, depth: usize) -> Res<&mut [u8]> {
        while self.bufs.len() <= depth {
            let mut v = Vec::new();
            v.try_reserve_exact(BLOCK).map_err(|_| String::from("out of memory"))?;
            v.resize(BLOCK, 0);
            self.bufs.push(v);
        }
        Ok(&mut self.bufs[depth][..])
    }

    fn record(&mut self, addr: u64) -> Res<()> {
        if let Some(v) = &mut self.collect {
            v.try_reserve(1).map_err(|_| String::from("out of memory"))?;
            v.push(addr);
        }
        Ok(())
    }

    /// Checks shared by data and metadata pointers.
    fn check_ptr(&mut self, p: &Ptr) -> Res<()> {
        if p.addr < RESERVED || p.addr >= self.total {
            return Err(at(p.addr, "pointer outside the volume or into blocks 0-15"));
        }
        if p.birth == 0 || p.birth > self.sb_gen {
            return Err(at(p.addr, "pointer birth outside 1..=generation"));
        }
        Ok(())
    }

    /// A data block: only marked (its checksum is checked when it is read).
    fn mark_data(&mut self, p: &Ptr) -> Res<()> {
        self.check_ptr(p)?;
        if self.root_bits.test_and_set(p.addr) {
            return Err(at(p.addr, "reached twice in one tree"));
        }
        match self.map.get(p.addr) {
            M_FREE => {
                self.map.set(p.addr, M_DATA);
                self.marked += 1;
                self.record(p.addr)
            }
            M_DATA => Ok(()), // shared with another root
            _ => Err(at(p.addr, "used both as data and as metadata")),
        }
    }

    /// A metadata block.  Fresh: read into `bufs[depth]`, header checked, count returned.
    fn enter(&mut self, p: &Ptr, kind: &'static [u8; 4], level: u8, depth: usize) -> Res<(Met, u16)> {
        self.check_ptr(p)?;
        if kind != KIND_DSRT && self.root_bits.test_and_set(p.addr) {
            return Err(at(p.addr, "reached twice in one tree"));
        }
        let code = m_meta(kind, level);
        let seen = self.map.get(p.addr);
        if seen == M_DATA {
            return Err(at(p.addr, "used both as data and as metadata"));
        }
        if seen != M_FREE && seen != code {
            return Err(at(p.addr, "met as a different kind or level than before"));
        }
        let (dev, uuid) = (self.dev, self.uuid);
        let buf = self.buf(depth)?;
        dev.read(p.addr, buf)?;
        if sha256(buf) != p.sha {
            return Err(at(p.addr, "checksum does not match"));
        }
        let count = check_header(buf, kind, level, p.birth, p.addr, &uuid).map_err(|w| at(p.addr, w))?;
        if seen == code {
            return Ok((Met::Shared, count));
        }
        self.map.set(p.addr, code);
        self.marked += 1;
        self.record(p.addr)?;
        Ok((Met::Fresh, count))
    }

    /// Pointer `i` of the DSPT in `bufs[depth]`.
    fn child(&self, depth: usize, i: usize) -> Result<Option<Ptr>, Why> {
        Ptr::parse(&self.bufs[depth][HDR_SIZE + i * PTR_SIZE..])
    }

    /// Checks the pointer array of a fresh DSPT: count = non-empty, at least 1.
    fn dspt_count(&self, depth: usize, count: u16, addr: u64) -> Res<()> {
        let mut n = 0;
        for i in 0..FANOUT {
            if self.child(depth, i).map_err(|w| at(addr, w))?.is_some() {
                n += 1;
            }
        }
        if n == 0 {
            return Err(at(addr, "pointer block without any pointer"));
        }
        if n != count as usize {
            return Err(at(addr, "header count differs from the pointers"));
        }
        Ok(())
    }

    /// Data tree of a node: DSPT at `level` covering logical blocks from `base`.
    fn data_tree(&mut self, p: &Ptr, level: u8, base: u64, blocks: u64, dir: bool, depth: usize) -> Res<()> {
        let (met, count) = self.enter(p, KIND_DSPT, level, depth)?;
        if let Met::Shared = met {
            return Ok(());
        }
        self.dspt_count(depth, count, p.addr)?;
        // Logical data blocks under one pointer: level 1 -> 1, level k -> 84^(k-1).
        let span = if level == 1 { 1 } else { capacity(level - 1) };
        for i in 0..FANOUT {
            let child = self.child(depth, i).map_err(|w| at(p.addr, w))?;
            let start = base + i as u64 * span;
            match child {
                None => {
                    if dir && start < blocks {
                        return Err(at(p.addr, "hole in a directory"));
                    }
                }
                Some(c) => {
                    if start >= blocks {
                        return Err(at(p.addr, "data pointer beyond the file size"));
                    }
                    if level == 1 {
                        self.mark_data(&c)?;
                    } else {
                        self.data_tree(&c, level - 1, start, blocks, dir, depth + 1)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Data of one node (the node bytes are copied out by the caller).
    fn node_data(&mut self, node: &Node, data: &[u8; 192], depth: usize) -> Res<()> {
        let blocks = node.blocks();
        let dir = node.typ == TYPE_DIR;
        if node.depth == 0 {
            for i in 0..4u64 {
                let p = Ptr::parse(&data[i as usize * PTR_SIZE..]).map_err(|w| format!("node {}: {}", node.number, w))?;
                match p {
                    None if dir && i < blocks => return Err(format!("node {}: hole in a directory", node.number)),
                    None => {}
                    Some(_) if i >= blocks => return Err(format!("node {}: data pointer beyond the file size", node.number)),
                    Some(p) => self.mark_data(&p)?,
                }
            }
            return Ok(());
        }
        match Ptr::parse(&data[0..PTR_SIZE]).map_err(|w| format!("node {}: {}", node.number, w))? {
            None if dir => Err(format!("node {}: directory without its tree", node.number)),
            None => Ok(()), // the whole file is a hole
            Some(p) => self.data_tree(&p, node.depth, 0, blocks, dir, depth),
        }
    }

    /// Node table: DSPT at `level`; level 1 points to DSND blocks.
    fn node_table(&mut self, p: &Ptr, level: u8, base: u64, st: &mut RootStats, depth: usize) -> Res<()> {
        let (met, count) = self.enter(p, KIND_DSPT, level, depth)?;
        if let Met::Shared = met {
            st.shared = true;
            return Ok(());
        }
        self.dspt_count(depth, count, p.addr)?;
        let span = if level == 1 { 1 } else { capacity(level - 1) };
        for i in 0..FANOUT {
            let child = self.child(depth, i).map_err(|w| at(p.addr, w))?;
            let start = base + i as u64 * span;
            match child {
                None => {
                    if start == 0 {
                        return Err(at(p.addr, "node-table range with node 1 is empty"));
                    }
                }
                Some(c) if level == 1 => self.node_block(&c, start, st, depth + 1)?,
                Some(c) => self.node_table(&c, level - 1, start, st, depth + 1)?,
            }
        }
        Ok(())
    }

    /// One DSND block = nodes `index * 15 ..`.
    fn node_block(&mut self, p: &Ptr, index: u64, st: &mut RootStats, depth: usize) -> Res<()> {
        let (met, count) = self.enter(p, KIND_DSND, 0, depth)?;
        if let Met::Shared = met {
            st.shared = true;
            return Ok(());
        }
        if !zeros(&self.bufs[depth][HDR_SIZE + NODES_PER_BLOCK as usize * NODE_SIZE..]) {
            return Err(at(p.addr, "node block tail not zero"));
        }
        let mut used = 0;
        for slot in 0..NODES_PER_BLOCK {
            let number = index * NODES_PER_BLOCK + slot;
            let off = HDR_SIZE + slot as usize * NODE_SIZE;
            let node = Node::parse(&self.bufs[depth][off..], number, self.sb_gen).map_err(|w| format!("node {}: {}", number, w))?;
            let Some(node) = node else {
                if self.collect_free && number != 0 && number < self.next_node_limit && self.free_nodes.len() < FREE_NODES_MAX {
                    self.free_nodes.try_reserve(1).map_err(|_| String::from("out of memory"))?;
                    self.free_nodes.push(number);
                }
                continue;
            };
            used += 1;
            let mut data = [0u8; 192];
            data.copy_from_slice(&self.bufs[depth][off + 56..off + 248]);
            st.nodes += 1;
            st.max_number = st.max_number.max(number);
            st.max_parent = st.max_parent.max(node.parent);
            if number == 1 {
                st.has_root = true;
            }
            self.node_data(&node, &data, depth + 1)?;
        }
        if used != count {
            return Err(at(p.addr, "header count differs from the nodes"));
        }
        if used == 0 {
            // Errata E4: an empty node block is an empty pointer in its parent.
            return Err(at(p.addr, "node block without any node"));
        }
        Ok(())
    }

    /// One root (live file system or a snapshot).
    fn root(&mut self, e: &RootEntry) -> Res<RootStats> {
        self.root_bits.bytes.clear();
        let mut st = RootStats::default();
        self.next_node_limit = e.next_node;
        self.collect_free = self.first_root && e.kind == ROOT_LIVE;
        self.first_root = false;
        let r = self.node_table(&e.nodes, e.depth, 0, &mut st, 1);
        self.collect_free = false;
        r?;
        if !st.shared {
            if !st.has_root {
                return Err(String::from("no root directory (node 1)"));
            }
            if st.max_number >= e.next_node || st.max_parent >= e.next_node {
                return Err(String::from("next_node not above every node number"));
            }
        }
        Ok(st)
    }

    /// Everything reachable from one superblock: its DSRT and every root in it.
    fn superblock(&mut self, sb: &Superblock) -> Res<Walked> {
        self.sb_gen = sb.generation;
        let before = self.marked;
        let (met, count) = self.enter(&sb.root, KIND_DSRT, 0, 0)?;
        let mut w = Walked::default();
        if let Met::Shared = met {
            return Ok(w); // the same tree as the other superblock (tie)
        }
        let b = &self.bufs[0];
        if !zeros(&b[HDR_SIZE + ROOT_ENTRIES * ROOT_ENTRY..]) {
            return Err(at(sb.root.addr, "root block tail not zero"));
        }
        let mut entries = Vec::new();
        for i in 0..ROOT_ENTRIES {
            let off = HDR_SIZE + i * ROOT_ENTRY;
            if let Some(e) = RootEntry::parse(&b[off..], i, sb.generation).map_err(|w| at(sb.root.addr, w))? {
                entries.push(e);
            }
        }
        if entries.len() != count as usize {
            return Err(at(sb.root.addr, "header count differs from the root entries"));
        }
        for (i, e) in entries.iter().enumerate() {
            if e.kind == ROOT_SNAPSHOT && entries[..i].iter().any(|o| o.kind == ROOT_SNAPSHOT && o.name == e.name) {
                return Err(at(sb.root.addr, "two snapshots with the same name"));
            }
        }
        for e in &entries {
            let st = self.root(e)?;
            if e.kind == ROOT_LIVE {
                w.nodes = st.nodes;
            } else {
                w.snapshots += 1;
            }
        }
        w.marked = self.marked - before;
        Ok(w)
    }
}

#[derive(Default)]
struct RootStats {
    nodes: u64,
    max_number: u64,
    max_parent: u64,
    has_root: bool,
    /// Part of the node table was shared with a root walked before (not fully counted).
    shared: bool,
}

/// Does either superblock slot of the disk carry the DeSoFS marker (whatever the rest of
/// it says)?  Such a disk is handled only by DeSoFS rules (`fs::mount_disk`).
pub fn has_marker(index: usize) -> bool {
    let Ok(dev) = Dev::open(index) else { return false };
    if dev.blocks < 3 {
        return false;
    }
    let mut b = alloc::vec![0u8; BLOCK];
    (1..=2).any(|s| dev.read(s, &mut b).is_ok() && &b[0..8] == MAGIC)
}

/// One superblock's tree on its own (`desofs check` / `repair`): every metadata block
/// and node of every root in it, with fresh maps.  Returns (blocks marked, live nodes,
/// snapshots).
pub(crate) fn walk_one(dev: &Dev, sb: &Superblock) -> Res<(u64, u64, u32)> {
    if sb.total_blocks < MIN_BLOCKS || sb.total_blocks > dev.blocks || sb.total_blocks > MAX_BLOCKS_V1 {
        return Err(String::from("volume size outside the device or the format-1 limits"));
    }
    if sb.incompat != 0 {
        return Err(String::from("unknown incompatible feature"));
    }
    let (Some(mut map), Some(mut bits)) = (ByteMap::new(sb.total_blocks), BitMap::new(sb.total_blocks)) else {
        return Err(String::from("not enough memory for the block maps"));
    };
    for i in 0..RESERVED {
        map.set(i, M_RESERVED);
    }
    let mut scan = Scan {
        dev,
        total: sb.total_blocks,
        sb_gen: 0,
        uuid: sb.uuid,
        map: &mut map,
        root_bits: &mut bits,
        bufs: Vec::new(),
        marked: 0,
        collect: None,
        free_nodes: Vec::new(),
        collect_free: false,
        first_root: true,
        next_node_limit: 0,
    };
    let w = scan.superblock(sb)?;
    Ok((w.marked, w.nodes, w.snapshots))
}

// ------------------------------------------------------------
// Mounted volumes – `desofs check` and `repair` refuse a mounted disk.
// ------------------------------------------------------------

const MOUNT_SLOTS: usize = 64;
static MOUNTED: [core::sync::atomic::AtomicU32; MOUNT_SLOTS] = [const { core::sync::atomic::AtomicU32::new(0) }; MOUNT_SLOTS];

pub(crate) fn mounted_inc(disk: usize) {
    if let Some(c) = MOUNTED.get(disk) {
        c.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }
}

pub(crate) fn mounted_dec(disk: usize) {
    if let Some(c) = MOUNTED.get(disk) {
        c.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
    }
}

/// Is a DeSoFS volume of this disk mounted (a `Volume` alive)?  Disks numbered 64 and up
/// are never tracked – treated as mounted, so nothing writes to them from here.
pub fn is_mounted(disk: usize) -> bool {
    MOUNTED.get(disk).map(|c| c.load(core::sync::atomic::Ordering::SeqCst) != 0).unwrap_or(true)
}

// ------------------------------------------------------------
// probe – read-only check of a volume and the mount decision.
// ------------------------------------------------------------

/// Reads disk `index` and decides what mounting it as DeSoFS would be allowed to do.
/// Never writes.
pub fn probe(index: usize) -> Report {
    match scan_volume(index) {
        Ok((r, _)) => r,
        Err(why) => Report::refused(why),
    }
}

/// What a mount needs besides the report.
pub(crate) struct Scanned {
    pub map: ByteMap,
    /// Blocks reachable only from the older superblock (free after the first commit).
    pub older_only: Vec<u64>,
    pub free_nodes: Vec<u64>,
    pub sb: Superblock,
    /// Generation in slot A / B (None = no valid superblock there).
    pub slot_gen: [Option<u64>; 2],
}

pub(crate) fn scan_volume(index: usize) -> Res<(Report, Scanned)> {
    let dev = Dev::open(index)?;
    if dev.blocks < 3 {
        return Err(String::from("not a DeSoFS volume (device too small)"));
    }
    let mut buf = alloc::vec![0u8; BLOCK];
    let mut sbs: [Option<Superblock>; 2] = [None, None];
    let mut why = [""; 2];
    for slot in 0..2 {
        dev.read(1 + slot as u64, &mut buf)?;
        match Superblock::parse(&buf) {
            Ok(sb) => sbs[slot] = Some(sb),
            Err(w) => why[slot] = w,
        }
    }
    if sbs[0].is_none() && sbs[1].is_none() {
        return Err(format!("not a DeSoFS volume (A: {}; B: {})", why[0], why[1]));
    }
    // Both valid: same uuid, same size; a tie only with the identical root.
    let mut tie = false;
    if let (Some(a), Some(b)) = (&sbs[0], &sbs[1]) {
        if a.uuid != b.uuid {
            return Err(String::from("the two superblocks belong to different volumes (uuid differs)"));
        }
        if a.total_blocks != b.total_blocks {
            return Err(String::from("the two superblocks disagree on the volume size"));
        }
        if a.generation == b.generation {
            if a.root != b.root {
                return Err(String::from("two different states with the same generation"));
            }
            tie = true;
        }
    }
    for sb in sbs.iter().flatten() {
        if sb.total_blocks < MIN_BLOCKS {
            return Err(String::from("volume smaller than 64 blocks"));
        }
        if sb.total_blocks > dev.blocks {
            return Err(String::from("volume larger than the device"));
        }
        if sb.total_blocks > MAX_BLOCKS_V1 {
            return Err(String::from("volume over 64 GiB (not supported yet)"));
        }
        if sb.incompat != 0 {
            return Err(String::from("unknown incompatible feature"));
        }
    }
    // Newer first (higher generation; on a tie slot B).
    let (newer, older): (usize, Option<usize>) = match (&sbs[0], &sbs[1]) {
        (Some(a), Some(b)) => {
            if b.generation >= a.generation { (1, Some(0)) } else { (0, Some(1)) }
        }
        (Some(_), None) => (0, None),
        _ => (1, None),
    };
    let total = sbs[newer].as_ref().unwrap().total_blocks;
    let uuid = sbs[newer].as_ref().unwrap().uuid;
    let (Some(mut map), Some(mut bits)) = (ByteMap::new(total), BitMap::new(total)) else {
        return Err(String::from("not enough memory for the block maps"));
    };
    let map_bytes = map.bytes() + bits.bytes.bytes();

    let reset = |map: &mut ByteMap| {
        map.clear();
        for i in 0..RESERVED {
            map.set(i, M_RESERVED);
        }
    };
    reset(&mut map);
    let mut scan = Scan {
        dev: &dev,
        total,
        sb_gen: 0,
        uuid,
        map: &mut map,
        root_bits: &mut bits,
        bufs: Vec::new(),
        marked: 0,
        collect: None,
        free_nodes: Vec::new(),
        collect_free: false,
        first_root: true,
        next_node_limit: 0,
    };

    let new_res = scan.superblock(sbs[newer].as_ref().unwrap());
    let old_res = match (older, &new_res) {
        (Some(o), Ok(_)) => {
            scan.collect = Some(Vec::new());
            Some(scan.superblock(sbs[o].as_ref().unwrap()))
        }
        (Some(o), Err(_)) => {
            // E3: the damaged newer tree leaves no traces – the older one alone.
            reset(scan.map);
            scan.marked = 0;
            scan.free_nodes.clear();
            Some(scan.superblock(sbs[o].as_ref().unwrap()))
        }
        (None, _) => None,
    };
    let older_only = scan.collect.take().unwrap_or_default();
    let free_nodes = core::mem::take(&mut scan.free_nodes);

    let mut warnings = Vec::new();
    let ro_feature = sbs.iter().flatten().any(|s| s.ro_compat != 0);
    let (state, chosen, walked) = match (new_res, old_res) {
        (Ok(w), None) => (State::ReadWrite, newer, w),
        (Ok(w), Some(Ok(_))) => (State::ReadWrite, newer, w),
        (Ok(w), Some(Err(e))) => (State::ReadOnly(format!("the older superblock's tree is damaged ({})", e)), newer, w),
        (Err(e), Some(Ok(w))) => (State::ReadOnly(format!("the newer superblock's tree is damaged ({}) - older state", e)), older.unwrap(), w),
        (Err(e), Some(Err(e2))) => return Err(format!("both trees damaged ({}; {})", e, e2)),
        (Err(e), None) => return Err(format!("tree damaged ({})", e)),
    };
    let state = match state {
        State::ReadWrite if ro_feature => State::ReadOnly(String::from("unknown read-only-compatible feature")),
        s => s,
    };
    let sb = sbs[chosen].as_ref().unwrap();
    // The chosen superblock is always walked first from a map holding only blocks 0-15
    // (the newer one, or the older one after the reset), so its count is exact.
    let used_counted = Some(walked.marked);
    if walked.marked != sb.used_blocks {
        warnings.push(format!("used_blocks {} in the superblock, {} counted", sb.used_blocks, walked.marked));
    }
    // Next commit: the slot with the older generation; a bad slot counts as oldest; tie -> B.
    let next_slot = match older {
        None => if newer == 0 { 2 } else { 1 },
        Some(_) if tie => 2,
        Some(o) => o as u8 + 1,
    };
    let slot_gen = [sbs[0].as_ref().map(|s| s.generation), sbs[1].as_ref().map(|s| s.generation)];
    let scanned = Scanned { map, older_only, free_nodes, sb: sb.clone(), slot_gen };
    let report = Report {
        state,
        slot: chosen as u8 + 1,
        next_slot,
        generation: sb.generation,
        total_blocks: sb.total_blocks,
        used_stored: sb.used_blocks,
        used_counted,
        nodes: walked.nodes,
        snapshots: walked.snapshots,
        label: String::from(sb.label_str()),
        uuid: sb.uuid,
        map_bytes,
        warnings,
    };
    Ok((report, scanned))
}
