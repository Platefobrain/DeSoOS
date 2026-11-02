// `desofs check` and `desofs repair` (DESOFS-FORMAT chapter 9 "leaving read-only",
// chapter 13 "when it is checked", errata E3).
//
// check – reads, never writes, refuses a mounted volume:
//   1. each superblock on its own: its checksum, then its whole metadata tree (the
//      mount walk with fresh maps);
//   2. every data block of every file and directory, in the live root and in every
//      snapshot, against the SHA-256 in its pointer;
//   3. directories and relations per root: every entry names an existing node of the
//      same type whose parent is that directory, every node but 1 is listed exactly
//      once, node 1 nowhere, no directory cycles;
//   4. data shared between roots: two different pointer blocks that point to the same
//      data block must hold the identical 48 bytes (E3);
//   5. used_blocks against the count (a warning – the field is informative).
// Errors name the file (path) where one can be found.
//
// repair – the only way out of read-only: a copy of the superblock whose tree passed
// the full check goes into the other slot with generation = highest valid + 1, then a
// flush.  Nothing is allocated, the good superblock is only read, an interrupted
// repair leaves the good superblock and can be repeated.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::layout::*;
use super::{sha256, Dev};

type Res<T> = Result<T, String>;

/// Kind of a report line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    /// Damaged data or structure.
    Error,
    /// Not damage, but not as it should be (e.g. used_blocks).
    Warning,
    /// Statistics.
    Info,
}

/// What check found about one superblock slot.
#[derive(Clone, Debug, Default)]
pub struct Slot {
    /// The superblock's own checksum and fields are valid.
    pub sb_ok: bool,
    pub sb_why: String,
    pub generation: u64,
    /// Its metadata tree: None = not walked (bad superblock).
    pub tree: Option<Result<(), String>>,
    /// Blocks reachable from it (when the tree is sound).
    pub counted: u64,
    pub used_stored: u64,
    /// Data, directories and relations of its roots: None = not checked.
    pub data_ok: Option<bool>,
}

pub struct CheckReport {
    pub lines: Vec<(Level, String)>,
    pub errors: u64,
    pub warnings: u64,
    pub slots: [Slot; 2],
    pub files: u64,
    pub dirs: u64,
    pub data_blocks: u64,
    pub snapshots: u32,
}

/// Error lines kept in the report (the rest is only counted).
const MAX_ERROR_LINES: u64 = 64;
/// Highest node number the relation check takes (memory: 9 bytes per number).
const MAX_NODES: u64 = 1 << 24;
/// Data blocks met from two different pointer blocks that are compared (E3).
const MAX_SHARED: usize = 65536;

impl CheckReport {
    fn new() -> Self {
        CheckReport { lines: Vec::new(), errors: 0, warnings: 0, slots: [Slot::default(), Slot::default()], files: 0, dirs: 0, data_blocks: 0, snapshots: 0 }
    }
    fn error(&mut self, text: String) {
        self.errors += 1;
        if self.errors <= MAX_ERROR_LINES {
            self.lines.push((Level::Error, text));
        }
    }
    fn warning(&mut self, text: String) {
        self.warnings += 1;
        self.lines.push((Level::Warning, text));
    }
    fn info(&mut self, text: String) {
        self.lines.push((Level::Info, text));
    }
}

/// Flags per block (one byte each, in 64 KiB pieces).
const F_DATA: u8 = 1; // data block read and checked at least once
const F_META: u8 = 2; // metadata block met before (its data pointers are checked)
const F_MULTI: u8 = 4; // data block met from two different pointer blocks

/// u64 per node number, in pieces, allocated fallibly.
struct U64s {
    chunks: Vec<Vec<u64>>,
}

const U64_CHUNK: usize = 8192;

impl U64s {
    fn new(len: u64) -> Option<U64s> {
        let n = (len as usize).div_ceil(U64_CHUNK);
        let mut chunks = Vec::new();
        chunks.try_reserve_exact(n).ok()?;
        for k in 0..n {
            let size = U64_CHUNK.min(len as usize - k * U64_CHUNK);
            let mut c = Vec::new();
            c.try_reserve_exact(size).ok()?;
            c.resize(size, 0);
            chunks.push(c);
        }
        Some(U64s { chunks })
    }
    fn get(&self, i: u64) -> u64 {
        self.chunks[i as usize / U64_CHUNK][i as usize % U64_CHUNK]
    }
    fn set(&mut self, i: u64, v: u64) {
        self.chunks[i as usize / U64_CHUNK][i as usize % U64_CHUNK] = v;
    }
}

fn bytes(len: u64) -> Res<super::ByteMap> {
    super::ByteMap::new(len).ok_or_else(|| String::from("not enough memory for check"))
}

/// Logical blocks under one pointer of a DSPT at `level`.
fn span(level: u8) -> u64 {
    if level <= 1 { 1 } else { capacity(level - 1) }
}

enum Mode {
    /// Data checksums, node table, directories and relations.
    Full,
    /// Only the pointers of data blocks met from two pointer blocks (E3).
    Compare,
}

/// A damaged data block found in a root, named after the walk (path lookup).
struct DataError {
    node: u64,
    logical: u64,
    addr: u64,
    why: &'static str,
}

struct Ck<'a> {
    dev: &'a Dev,
    flags: super::ByteMap,
    rep: CheckReport,
    multi: u64,
    shared: BTreeMap<u64, (u64, [u8; 32])>,
    shared_skipped: u64,
    mode: Mode,
    done: u64,
    goal: u64,
    progress: &'a mut dyn FnMut(u64, u64),
    data_errors: Vec<DataError>,
}

impl<'a> Ck<'a> {
    fn read(&self, addr: u64) -> Res<Vec<u8>> {
        let mut b = vec![0u8; BLOCK];
        self.dev.read(addr, &mut b)?;
        Ok(b)
    }

    /// A metadata block the walk already accepted (checksum checked again).
    fn meta(&self, p: &Ptr) -> Res<Vec<u8>> {
        let b = self.read(p.addr)?;
        if sha256(&b) != p.sha {
            return Err(format!("block {}: checksum does not match", p.addr));
        }
        Ok(b)
    }

    /// Pointer `index` (logical block / node block) of a tree at `level`.
    fn lookup(&self, mut p: Ptr, mut level: u8, mut index: u64) -> Res<Option<Ptr>> {
        loop {
            let b = self.meta(&p)?;
            let s = span(level);
            let i = index / s;
            if i >= FANOUT as u64 {
                return Ok(None);
            }
            let Some(c) = Ptr::parse(&b[HDR_SIZE + i as usize * PTR_SIZE..]).map_err(String::from)? else {
                return Ok(None);
            };
            if level == 1 {
                return Ok(Some(c));
            }
            index %= s;
            p = c;
            level -= 1;
        }
    }

    /// Node `n` of a root (None if the slot is empty).
    fn node(&self, e: &RootEntry, n: u64) -> Res<Option<(Node, [u8; 192])>> {
        let Some(p) = self.lookup(e.nodes, e.depth, n / NODES_PER_BLOCK)? else {
            return Ok(None);
        };
        let b = self.meta(&p)?;
        let off = HDR_SIZE + (n % NODES_PER_BLOCK) as usize * NODE_SIZE;
        let Some(node) = Node::parse(&b[off..], n, u64::MAX).map_err(String::from)? else {
            return Ok(None);
        };
        let mut data = [0u8; 192];
        data.copy_from_slice(&b[off + 56..off + 248]);
        Ok(Some((node, data)))
    }

    /// Pointer of logical block `i` of a node.
    fn data_ptr(&self, node: &Node, data: &[u8; 192], i: u64) -> Res<Option<Ptr>> {
        if node.depth == 0 {
            if i >= 4 {
                return Ok(None);
            }
            return Ptr::parse(&data[i as usize * PTR_SIZE..]).map_err(String::from);
        }
        match Ptr::parse(&data[0..PTR_SIZE]).map_err(String::from)? {
            None => Ok(None),
            Some(r) => self.lookup(r, node.depth, i),
        }
    }

    /// A directory block's entries (node, type, name), or why the block is damaged.
    fn dir_entries(&self, p: &Ptr) -> Res<Result<Vec<(u64, u8, String)>, &'static str>> {
        let b = self.read(p.addr)?;
        if sha256(&b) != p.sha {
            return Ok(Err("checksum does not match"));
        }
        let mut out = Vec::new();
        let r = check_dir_block(&b, |n, t, name| {
            out.try_reserve(1).map_err(|_| "out of memory")?;
            out.push((n, t, String::from(core::str::from_utf8(name).unwrap_or("?"))));
            Ok(())
        });
        Ok(r.map(|_| out))
    }

    /// The path of node `n` in root `e` (best effort – "node N" when it cannot be found).
    fn path(&self, e: &RootEntry, n: u64) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut cur = n;
        for _ in 0..64 {
            if cur == 1 {
                let mut s = String::new();
                for p in parts.iter().rev() {
                    s.push('/');
                    s.push_str(p);
                }
                return if s.is_empty() { String::from("/") } else { s };
            }
            let Ok(Some((node, _))) = self.node(e, cur) else { break };
            let Ok(Some((pn, pdata))) = self.node(e, node.parent) else { break };
            let mut found = None;
            for i in 0..pn.blocks() {
                let Ok(Some(p)) = self.data_ptr(&pn, &pdata, i) else { continue };
                if let Ok(Ok(list)) = self.dir_entries(&p) {
                    if let Some((_, _, name)) = list.into_iter().find(|(c, _, _)| *c == cur) {
                        found = Some(name);
                        break;
                    }
                }
            }
            let Some(name) = found else { break };
            parts.push(name);
            cur = node.parent;
        }
        format!("node {}", n)
    }

    /// A data pointer met in the walk.  `fresh`: its pointer block was not met before.
    fn data(&mut self, p: &Ptr, fresh: bool, node: u64, logical: u64) -> Res<()> {
        let f = self.flags.get(p.addr);
        if let Mode::Compare = self.mode {
            if f & F_MULTI != 0 && fresh {
                match self.shared.get(&p.addr) {
                    Some(&(birth, sha)) => {
                        if birth != p.birth || sha != p.sha {
                            self.rep.error(format!("data block {}: shared by two roots with different pointers (birth {} / {})", p.addr, birth, p.birth));
                        }
                    }
                    None if self.shared.len() < MAX_SHARED => {
                        self.shared.insert(p.addr, (p.birth, p.sha));
                    }
                    None => self.shared_skipped += 1,
                }
            }
            return Ok(());
        }
        if !fresh {
            return Ok(());
        }
        if f & F_DATA != 0 {
            // A second pointer block names the same data block: read it again with this
            // pointer and compare the pointers later (E3).
            if f & F_MULTI == 0 {
                self.multi += 1;
            }
            self.flags.set(p.addr, f | F_MULTI);
        } else {
            self.flags.set(p.addr, f | F_DATA);
            self.rep.data_blocks += 1;
            self.done += 1;
            if self.done % 256 == 0 {
                (self.progress)(self.done, self.goal);
            }
        }
        let b = self.read(p.addr)?;
        if sha256(&b) != p.sha {
            if self.data_errors.len() < MAX_ERROR_LINES as usize {
                self.data_errors.push(DataError { node, logical, addr: p.addr, why: "checksum does not match" });
            } else {
                self.rep.errors += 1;
            }
        }
        Ok(())
    }

    /// Data tree of a node at `level` from logical block `base`.
    fn data_tree(&mut self, p: &Ptr, level: u8, base: u64, fresh: bool, node: u64) -> Res<()> {
        let fresh = fresh && self.flags.get(p.addr) & F_META == 0;
        let f = self.flags.get(p.addr);
        self.flags.set(p.addr, f | F_META);
        let b = self.meta(p)?;
        for i in 0..FANOUT {
            let Some(c) = Ptr::parse(&b[HDR_SIZE + i * PTR_SIZE..]).map_err(String::from)? else { continue };
            let start = base + i as u64 * span(level);
            if level == 1 {
                self.data(&c, fresh, node, start)?;
            } else {
                self.data_tree(&c, level - 1, start, fresh, node)?;
            }
        }
        Ok(())
    }

    fn node_data(&mut self, node: &Node, data: &[u8; 192], fresh: bool) -> Res<()> {
        if node.depth == 0 {
            for i in 0..4 {
                if let Some(p) = Ptr::parse(&data[i * PTR_SIZE..]).map_err(String::from)? {
                    self.data(&p, fresh, node.number, i as u64)?;
                }
            }
            return Ok(());
        }
        if let Some(r) = Ptr::parse(&data[0..PTR_SIZE]).map_err(String::from)? {
            self.data_tree(&r, node.depth, 0, fresh, node.number)?;
        }
        Ok(())
    }

    /// Every node of a node table: `f(ck, node, data, fresh)`.
    fn nodes(&mut self, p: &Ptr, level: u8, base: u64, fresh: bool, f: &mut dyn FnMut(&mut Ck, &Node, &[u8; 192], bool) -> Res<()>) -> Res<()> {
        let fresh = fresh && self.flags.get(p.addr) & F_META == 0;
        let fl = self.flags.get(p.addr);
        self.flags.set(p.addr, fl | F_META);
        let b = self.meta(p)?;
        for i in 0..FANOUT {
            let Some(c) = Ptr::parse(&b[HDR_SIZE + i * PTR_SIZE..]).map_err(String::from)? else { continue };
            let start = base + i as u64 * span(level);
            if level > 1 {
                self.nodes(&c, level - 1, start, fresh, f)?;
                continue;
            }
            let fresh2 = fresh && self.flags.get(c.addr) & F_META == 0;
            let fl = self.flags.get(c.addr);
            self.flags.set(c.addr, fl | F_META);
            let nb = self.meta(&c)?;
            for slot in 0..NODES_PER_BLOCK {
                let number = start * NODES_PER_BLOCK + slot;
                let off = HDR_SIZE + slot as usize * NODE_SIZE;
                let Some(node) = Node::parse(&nb[off..], number, u64::MAX).map_err(String::from)? else { continue };
                let mut data = [0u8; 192];
                data.copy_from_slice(&nb[off + 56..off + 248]);
                f(self, &node, &data, fresh2)?;
            }
        }
        Ok(())
    }

    /// Data of every node of one root (Compare mode: only the E3 pointers).
    fn root_data(&mut self, e: &RootEntry) -> Res<()> {
        self.nodes(&e.nodes, e.depth, 0, true, &mut |ck, node, data, fresh| ck.node_data(node, data, fresh))
    }

    /// Full check of one root: data, then directories and relations.
    fn root(&mut self, e: &RootEntry, name: &str) -> Res<()> {
        let errors0 = self.rep.errors;
        if e.next_node > MAX_NODES {
            self.rep.warning(format!("{}: {} node numbers - relations not checked (limit {})", name, e.next_node, MAX_NODES));
            self.data_errors.clear();
            self.root_data(e)?;
            self.name_data_errors(e, name);
            return Ok(());
        }
        let mut typ = bytes(e.next_node)?;
        let mut parent = U64s::new(e.next_node).ok_or_else(|| String::from("not enough memory for check"))?;
        let (mut files, mut dirs) = (0u64, 0u64);
        self.data_errors.clear();
        // Pass 1: node types and parents, every data block.
        self.nodes(&e.nodes, e.depth, 0, true, &mut |ck, node, data, fresh| {
            if node.number < typ_len(&typ) {
                typ.set(node.number, node.typ);
                parent.set(node.number, node.parent);
            }
            if node.typ == TYPE_DIR { dirs += 1 } else { files += 1 }
            ck.node_data(node, data, fresh)
        })?;
        self.name_data_errors(e, name);
        // Pass 2: directory entries.
        let mut refs = bytes(e.next_node)?;
        let mut problems: Vec<(u64, String)> = Vec::new();
        let next = e.next_node;
        self.nodes(&e.nodes, e.depth, 0, false, &mut |ck, node, data, _| {
            if node.typ != TYPE_DIR {
                return Ok(());
            }
            for i in 0..node.blocks() {
                let Some(p) = ck.data_ptr(node, data, i)? else {
                    problems.push((node.number, format!("block {}: hole in a directory", i)));
                    continue;
                };
                let list = match ck.dir_entries(&p)? {
                    Ok(l) => l,
                    Err("checksum does not match") => continue, // reported with the data
                    Err(w) => {
                        problems.push((node.number, format!("block {}: {}", i, w)));
                        continue;
                    }
                };
                for (c, t, cname) in list {
                    if c >= next || typ.get(c) == 0 {
                        problems.push((node.number, format!("entry '{}' names node {}, which does not exist", cname, c)));
                        continue;
                    }
                    if typ.get(c) != t {
                        problems.push((node.number, format!("entry '{}': type differs from node {}", cname, c)));
                    }
                    if parent.get(c) != node.number {
                        problems.push((node.number, format!("entry '{}': node {} has parent {}", cname, c, parent.get(c))));
                    }
                    let r = refs.get(c);
                    refs.set(c, r.saturating_add(1));
                }
            }
            Ok(())
        })?;
        for (n, w) in problems {
            let p = self.path(e, n);
            self.rep.error(format!("{}: directory {}: {}", name, p, w));
        }
        // Every node listed once (node 1 never), no cycles.
        let mut state = bytes(next)?;
        for n in 1..next {
            let t = typ.get(n);
            if t == 0 {
                continue;
            }
            let r = refs.get(n);
            if n == 1 {
                if t != TYPE_DIR {
                    self.rep.error(format!("{}: node 1 is not a directory", name));
                }
                if r != 0 {
                    self.rep.error(format!("{}: the root directory is listed in a directory", name));
                }
                continue;
            }
            if r == 0 {
                self.rep.error(format!("{}: node {} ({}) has no directory entry (orphan)", name, n, if t == TYPE_DIR { "directory" } else { "file" }));
            } else if r > 1 {
                let p = self.path(e, n);
                self.rep.error(format!("{}: {} is listed in {} directory entries", name, p, r));
            }
            if t == TYPE_DIR && state.get(n) == 0 {
                // Follow the parents up to node 1: 1 = on this path, 2 = reaches 1, 3 = bad.
                let mut chain = Vec::new();
                let mut cur = n;
                let mut good = true;
                loop {
                    if cur == 1 || state.get(cur) == 2 {
                        break;
                    }
                    if state.get(cur) == 1 || state.get(cur) == 3 {
                        good = false;
                        break;
                    }
                    state.set(cur, 1);
                    chain.push(cur);
                    let p = parent.get(cur);
                    if p >= next || typ.get(p) != TYPE_DIR {
                        self.rep.error(format!("{}: node {}: parent {} is not a directory", name, cur, p));
                        good = false;
                        break;
                    }
                    cur = p;
                }
                if !good && state.get(cur) == 1 {
                    self.rep.error(format!("{}: directories in a cycle (node {}) - not reachable from /", name, cur));
                }
                for c in chain {
                    state.set(c, if good { 2 } else { 3 });
                }
            }
        }
        self.rep.files += files;
        self.rep.dirs += dirs;
        let errs = self.rep.errors - errors0;
        self.rep.info(format!("{}: {} files, {} directories{}", name, files, dirs, if errs == 0 { String::from(", OK") } else { format!(", {} errors", errs) }));
        Ok(())
    }

    fn name_data_errors(&mut self, e: &RootEntry, name: &str) {
        let list = core::mem::take(&mut self.data_errors);
        for d in list {
            let p = self.path(e, d.node);
            self.rep.error(format!("{}: {}: block {} (disk block {}) - {}", name, p, d.logical, d.addr, d.why));
        }
    }
}

fn typ_len(m: &super::ByteMap) -> u64 {
    m.len()
}

fn slot_name(i: usize) -> char {
    if i == 0 { 'A' } else { 'B' }
}

/// The roots of a superblock's root block (live first).
fn roots(ck: &Ck, sb: &Superblock) -> Res<Vec<RootEntry>> {
    let b = ck.meta(&sb.root)?;
    let mut out = Vec::new();
    for i in 0..ROOT_ENTRIES {
        if let Some(e) = RootEntry::parse(&b[HDR_SIZE + i * ROOT_ENTRY..], i, sb.generation).map_err(String::from)? {
            out.push(e);
        }
    }
    out.sort_by_key(|e| if e.kind == ROOT_LIVE { 0 } else { 1 });
    Ok(out)
}

fn root_name(e: &RootEntry) -> String {
    if e.kind == ROOT_LIVE {
        return String::from("live");
    }
    let end = e.name.iter().position(|&c| c == 0).unwrap_or(e.name.len());
    format!("snapshot \"{}\"", core::str::from_utf8(&e.name[..end]).unwrap_or("?"))
}

/// `desofs check <disk>`.  `progress(done, total)` is called now and then while data is
/// read.  Err: not a DeSoFS volume, mounted, or out of memory.
pub fn check(index: usize, progress: &mut dyn FnMut(u64, u64)) -> Res<CheckReport> {
    if super::is_mounted(index) {
        return Err(String::from("the volume is mounted - unmount first"));
    }
    let dev = Dev::open(index)?;
    if dev.blocks < 3 {
        return Err(String::from("not a DeSoFS volume (device too small)"));
    }
    let mut rep = CheckReport::new();
    let mut sbs: [Option<Superblock>; 2] = [None, None];
    let mut buf = vec![0u8; BLOCK];
    for s in 0..2 {
        dev.read(1 + s as u64, &mut buf)?;
        match Superblock::parse(&buf) {
            Ok(sb) => {
                rep.slots[s].sb_ok = true;
                rep.slots[s].generation = sb.generation;
                rep.slots[s].used_stored = sb.used_blocks;
                sbs[s] = Some(sb);
            }
            Err(w) => rep.slots[s].sb_why = String::from(w),
        }
    }
    if sbs[0].is_none() && sbs[1].is_none() {
        return Err(format!("not a DeSoFS volume (A: {}; B: {})", rep.slots[0].sb_why, rep.slots[1].sb_why));
    }
    if let (Some(a), Some(b)) = (&sbs[0], &sbs[1]) {
        if a.uuid != b.uuid || a.total_blocks != b.total_blocks {
            rep.error(String::from("the two superblocks belong to different volumes (uuid or size differs)"));
            return Ok(rep);
        }
        if a.generation == b.generation && a.root != b.root {
            rep.error(String::from("two different states with the same generation"));
            return Ok(rep);
        }
    }
    // 1. Each tree on its own.
    for s in 0..2 {
        let Some(sb) = &sbs[s] else {
            rep.error(format!("superblock {}: {}", slot_name(s), rep.slots[s].sb_why));
            continue;
        };
        match super::walk_one(&dev, sb) {
            Ok((marked, _, snaps)) => {
                rep.slots[s].tree = Some(Ok(()));
                rep.slots[s].counted = marked;
                if s == 0 || rep.slots[0].tree.is_none() || sbs[0].as_ref().map(|a| a.root != sb.root).unwrap_or(true) {
                    rep.snapshots = rep.snapshots.max(snaps);
                }
                if marked != sb.used_blocks {
                    rep.warning(format!("superblock {}: used_blocks {} in the superblock, {} counted", slot_name(s), sb.used_blocks, marked));
                }
            }
            Err(w) => {
                rep.error(format!("superblock {}: tree damaged ({})", slot_name(s), w));
                rep.slots[s].tree = Some(Err(w));
            }
        }
    }
    // 2-4. Data, directories, relations of every sound tree (once if both are the same).
    let goal = (0..2).filter_map(|s| if rep.slots[s].tree == Some(Ok(())) { Some(rep.slots[s].counted) } else { None }).max().unwrap_or(0);
    let total = sbs.iter().flatten().map(|s| s.total_blocks).max().unwrap_or(0);
    let mut ck = Ck {
        dev: &dev,
        flags: bytes(total)?,
        rep,
        multi: 0,
        shared: BTreeMap::new(),
        shared_skipped: 0,
        mode: Mode::Full,
        done: 0,
        goal,
        progress,
        data_errors: Vec::new(),
    };
    let mut checked: Vec<(usize, Ptr)> = Vec::new();
    let order: [usize; 2] = match (&sbs[0], &sbs[1]) {
        (Some(a), Some(b)) if a.generation > b.generation => [0, 1],
        _ => [1, 0],
    };
    for &s in &order {
        let Some(sb) = sbs[s].clone() else { continue };
        if ck.rep.slots[s].tree != Some(Ok(())) {
            continue;
        }
        if let Some(&(o, _)) = checked.iter().find(|(_, r)| *r == sb.root) {
            ck.rep.slots[s].data_ok = ck.rep.slots[o].data_ok;
            continue;
        }
        let errors0 = ck.rep.errors;
        for e in roots(&ck, &sb)? {
            let name = format!("{} {}", slot_name(s), root_name(&e));
            ck.root(&e, &name)?;
        }
        ck.rep.slots[s].data_ok = Some(ck.rep.errors == errors0);
        checked.push((s, sb.root));
    }
    // 4. Data blocks met from two pointer blocks: the pointers must be identical.
    if ck.multi > 0 {
        ck.mode = Mode::Compare;
        ck.flags = {
            // Keep only F_MULTI; F_META is set again by the second walk.
            let mut f = ck.flags;
            for i in 0..total {
                let v = f.get(i);
                f.set(i, v & F_MULTI);
            }
            f
        };
        let errors0 = ck.rep.errors;
        for &(s, _) in &checked.clone() {
            let sb = sbs[s].clone().unwrap();
            for e in roots(&ck, &sb)? {
                ck.root_data(&e)?;
            }
        }
        if ck.rep.errors != errors0 {
            for &(s, _) in &checked {
                ck.rep.slots[s].data_ok = Some(false);
            }
        }
        if ck.shared_skipped > 0 {
            let n = ck.shared_skipped;
            ck.rep.warning(format!("{} shared data pointers not compared (more than {} shared blocks)", n, MAX_SHARED));
        }
    }
    let mut rep = ck.rep;
    // One line per superblock: its checksum, its tree, its data.
    for s in 0..2 {
        let sl = &rep.slots[s];
        let line = if !sl.sb_ok {
            format!("superblock {}: checksum or fields bad ({})", slot_name(s), sl.sb_why)
        } else {
            let tree = match &sl.tree {
                Some(Ok(())) => format!("tree OK ({} blocks)", sl.counted),
                Some(Err(_)) => String::from("tree damaged"),
                None => String::from("tree not walked"),
            };
            let data = match sl.data_ok {
                Some(true) => "data OK",
                Some(false) => "data damaged",
                None => "data not checked",
            };
            format!("superblock {}: generation {}, checksum OK, {}, {}", slot_name(s), sl.generation, tree, data)
        };
        rep.lines.insert(s, (Level::Info, line));
    }
    if rep.errors > MAX_ERROR_LINES {
        let more = rep.errors - MAX_ERROR_LINES;
        rep.info(format!("... and {} more errors", more));
    }
    let (e, w) = (rep.errors, rep.warnings);
    let (files, dirs, data) = (rep.files, rep.dirs, rep.data_blocks);
    rep.info(format!("{} files, {} directories, {} data blocks read", files, dirs, data));
    rep.info(format!("result: {} errors, {} warnings{}", e, w, if e == 0 { "" } else { " - check changes nothing; see 'desofs repair'" }));
    Ok(rep)
}

/// `desofs repair <disk>`: `apply` false only says what would be done.  Ok: a message;
/// Err: refused (nothing written) or a write failed (the good superblock untouched).
pub fn repair(index: usize, apply: bool) -> Res<String> {
    if super::is_mounted(index) {
        return Err(String::from("the volume is mounted - unmount first"));
    }
    if crate::block::is_read_only(index) {
        return Err(String::from("the disk is read-only - nothing changed"));
    }
    // The whole check first – no write before it is finished.
    let rep = check(index, &mut |_, _| {})?;
    let good: Vec<usize> = (0..2).filter(|&s| rep.slots[s].sb_ok && rep.slots[s].tree == Some(Ok(())) && rep.slots[s].data_ok == Some(true)).collect();
    let sound_trees = (0..2).filter(|&s| rep.slots[s].sb_ok && rep.slots[s].tree == Some(Ok(()))).count();
    if good.len() == 2 {
        return Err(String::from("nothing to repair - both superblocks and their trees are sound"));
    }
    if good.is_empty() {
        return Err(if sound_trees > 0 {
            String::from("the only sound tree has damaged data or directories - repair would keep a damaged state; refused")
        } else {
            String::from("no superblock with a sound tree - repair refused")
        });
    }
    let g = good[0];
    let bad = 1 - g;
    if rep.slots[bad].sb_ok && rep.slots[bad].tree == Some(Ok(())) {
        // The other tree is structurally sound but its data is damaged: still the bad one.
    }
    let dev = Dev::open(index)?;
    let mut b = vec![0u8; BLOCK];
    dev.read(1 + g as u64, &mut b)?;
    let sb = Superblock::parse(&b).map_err(|w| format!("superblock changed while repairing: {}", w))?;
    let high = (0..2).filter(|&s| rep.slots[s].sb_ok).map(|s| rep.slots[s].generation).max().unwrap_or(sb.generation);
    let gen_new = high.checked_add(1).ok_or_else(|| String::from("generation at its maximum - repair refused"))?;
    let lost = if rep.slots[bad].sb_ok && rep.slots[bad].generation > sb.generation {
        format!("; the changes of generation {} are lost", rep.slots[bad].generation)
    } else {
        String::new()
    };
    let plan = format!("superblock {} gets a copy of superblock {} (generation {} -> {}){}", slot_name(bad), slot_name(g), sb.generation, gen_new, lost);
    if !apply {
        return Ok(plan);
    }
    let mut root = [0u8; 48];
    root[0..8].copy_from_slice(&sb.root.addr.to_le_bytes());
    root[8..16].copy_from_slice(&sb.root.birth.to_le_bytes());
    root[16..48].copy_from_slice(&sb.root.sha);
    let copy = super::format::superblock(&sb.uuid, gen_new, sb.total_blocks, rep.slots[g].counted, sb.commit_time, &root, &sb.label);
    let sect = (BLOCK / crate::block::SECTOR_SIZE) as u64;
    crate::block::write(index, (1 + bad as u64) * sect, &copy).map_err(|e| format!("write error ({}) - superblock {} untouched; run repair again", e, slot_name(g)))?;
    crate::block::flush(index).map_err(|e| format!("flush error ({}) - superblock {} untouched; run repair again", e, slot_name(g)))?;
    let r = super::probe(index);
    if r.state != super::State::ReadWrite {
        return Err(format!("after the repair the volume is {:?}", r.state));
    }
    Ok(format!("{} - done, the volume is read-write again", plan))
}
