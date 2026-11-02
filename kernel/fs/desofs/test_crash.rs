// DESOFS TEST – power loss.  Every write of an operation is recorded (address,
// 512-byte sectors, flushes) against the image the disk held before it; crash images are
// then rebuilt from that log and mounted from scratch:
//
//   - every write point (and every sector of a superblock write): the first k writes
//     landed, nothing after;
//   - writes between two flushes in any order: a random subset of the sectors (or of
//     the whole writes) since the last flush landed, everything flushed before did;
//   - a write or a flush failing at each position: the operation fails, the volume turns
//     read-only, and whatever part of the unflushed writes landed, a remount works;
//   - the same with a snapshot: no write of any operation touches one of its blocks.
//
// Every crash image must mount read-write with exact counts and hold the state before or
// after the operation (whole tree and file contents); at the points where the state can
// change it must also keep working: a new file written on it passes the same checks
// (no reachable block free in the allocator) and survives a remount.  All disks live in RAM.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use super::layout::*;
use super::test_write::{check, mount, params, pattern, ref_model, same_as, snapshot_blocks, walk_ok, Model, T};
use super::vol::Volume;
use crate::block::{self, BlockDevice, BlockError, SECTOR_SIZE};
use crate::fs::{FileSystem, FsError};

macro_rules! ensure {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            return Err(format!($($msg)*));
        }
    };
}

const SECTORS_PER_BLOCK: u64 = (BLOCK / SECTOR_SIZE) as u64;
static ZERO: [u8; BLOCK] = [0u8; BLOCK];

/// A disk image: one entry per block, empty = all zeros.
pub(super) type Image = Rc<Vec<Vec<u8>>>;

pub(super) enum Ev {
    Write(u64, Vec<u8>),
    Flush,
}

#[derive(Default)]
pub(super) struct Log {
    pub(super) on: bool,
    pub(super) ev: Vec<Ev>,
    writes: u64,
    flushes: u64,
    /// Fail the n-th write / flush (0 = never); after a failure everything fails.
    fail_write: u64,
    fail_flush: u64,
    failed: bool,
}

/// A RAM disk over a shared image: writes go to an overlay; an optional log records them.
struct CrashDev {
    base: Image,
    over: BTreeMap<u64, Vec<u8>>,
    blocks: u64,
    log: Option<Rc<RefCell<Log>>>,
}

impl CrashDev {
    fn block(&self, b: u64) -> &[u8] {
        if let Some(x) = self.over.get(&b) {
            return x;
        }
        match self.base.get(b as usize) {
            Some(x) if !x.is_empty() => x,
            _ => &ZERO,
        }
    }
}

impl BlockDevice for CrashDev {
    fn name(&self) -> &str {
        "crash"
    }
    fn description(&self) -> String {
        String::from("power-loss RAM disk")
    }
    fn sector_count(&self) -> u64 {
        self.blocks * SECTORS_PER_BLOCK
    }
    fn read_only(&self) -> bool {
        false
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        block::check_range(self.sector_count(), lba, buf.len())?;
        for (k, s) in buf.chunks_mut(SECTOR_SIZE).enumerate() {
            let sec = lba + k as u64;
            let o = (sec % SECTORS_PER_BLOCK) as usize * SECTOR_SIZE;
            s.copy_from_slice(&self.block(sec / SECTORS_PER_BLOCK)[o..o + SECTOR_SIZE]);
        }
        Ok(())
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        block::check_range(self.sector_count(), lba, buf.len())?;
        if let Some(l) = &self.log {
            let mut l = l.borrow_mut();
            l.writes += 1;
            if l.failed || (l.fail_write != 0 && l.writes >= l.fail_write) {
                l.failed = true;
                return Err(BlockError::Io);
            }
            if l.on {
                l.ev.push(Ev::Write(lba, buf.to_vec()));
            }
        }
        put(&mut self.over, &self.base, lba, buf);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        if let Some(l) = &self.log {
            let mut l = l.borrow_mut();
            l.flushes += 1;
            if l.failed || (l.fail_flush != 0 && l.flushes >= l.fail_flush) {
                l.failed = true;
                return Err(BlockError::Io);
            }
            if l.on {
                l.ev.push(Ev::Flush);
            }
        }
        Ok(())
    }
}

/// Writes sectors into an overlay (blocks copied from the image on first touch).
fn put(over: &mut BTreeMap<u64, Vec<u8>>, base: &Image, lba: u64, buf: &[u8]) {
    for (k, s) in buf.chunks(SECTOR_SIZE).enumerate() {
        let sec = lba + k as u64;
        let b = sec / SECTORS_PER_BLOCK;
        let blk = over.entry(b).or_insert_with(|| match base.get(b as usize) {
            Some(x) if !x.is_empty() => x.clone(),
            _ => vec![0u8; BLOCK],
        });
        let o = (sec % SECTORS_PER_BLOCK) as usize * SECTOR_SIZE;
        blk[o..o + SECTOR_SIZE].copy_from_slice(s);
    }
}

pub(super) fn attach(base: &Image, blocks: u64, over: BTreeMap<u64, Vec<u8>>, log: Option<Rc<RefCell<Log>>>) -> usize {
    block::register(Box::new(CrashDev { base: base.clone(), over, blocks, log }))
}

/// The whole disk as an image (zero blocks stored empty).
pub(super) fn snapshot(d: usize, blocks: u64) -> Result<Image, String> {
    let mut img = Vec::with_capacity(blocks as usize);
    let mut b = vec![0u8; BLOCK];
    for i in 0..blocks {
        block::read(d, i * SECTORS_PER_BLOCK, &mut b).map_err(|e| format!("read: {}", e))?;
        img.push(if b.iter().all(|&x| x == 0) { Vec::new() } else { b.clone() });
    }
    Ok(Rc::new(img))
}

// ---------------- operations and the model ----------------

#[derive(Clone, Copy, Debug)]
enum Op {
    Mkdir(&'static str),
    Create(&'static str),
    /// path, offset, length, pattern seed
    Write(&'static str, u64, usize, u32),
    Truncate(&'static str, u64),
    Rename(&'static str, &'static str),
    Remove(&'static str),
}

fn apply(op: Op, v: &mut Volume, m: &mut Model) -> Result<(), FsError> {
    match op {
        Op::Mkdir(p) => {
            v.mkdir(p)?;
            m.insert(p.into(), None);
        }
        Op::Create(p) => {
            v.create(p)?;
            m.insert(p.into(), Some(Vec::new()));
        }
        Op::Write(p, off, n, seed) => {
            let data = pattern(n, seed);
            v.write(p, off, &data)?;
            if let Some(Some(f)) = m.get_mut(p) {
                let (o, end) = (off as usize, off as usize + n);
                if f.len() < end {
                    f.resize(end, 0);
                }
                f[o..end].copy_from_slice(&data);
            }
        }
        Op::Truncate(p, size) => {
            v.truncate(p, size)?;
            if let Some(Some(f)) = m.get_mut(p) {
                f.resize(size as usize, 0);
            }
        }
        Op::Rename(a, b) => {
            v.rename(a, b)?;
            if a != b {
                m.remove(b);
                let keys: Vec<String> = m.keys().filter(|k| *k == a || k.starts_with(&format!("{}/", a))).cloned().collect();
                for k in keys {
                    let val = m.remove(&k).unwrap();
                    m.insert(format!("{}{}", b, &k[a.len()..]), val);
                }
            }
        }
        Op::Remove(p) => {
            v.remove(p)?;
            m.remove(p);
        }
    }
    Ok(())
}

// ---------------- crash images ----------------

/// One 512-byte sector write from the log.
pub(super) struct Sw<'a> {
    epoch: u32,
    call: u32,
    lba: u64,
    data: &'a [u8],
}

pub(super) fn sectors(ev: &[Ev]) -> Vec<Sw<'_>> {
    let mut out = Vec::new();
    let (mut epoch, mut call) = (0u32, 0u32);
    for e in ev {
        match e {
            Ev::Flush => epoch += 1,
            Ev::Write(lba, data) => {
                for (k, s) in data.chunks(SECTOR_SIZE).enumerate() {
                    out.push(Sw { epoch, call, lba: lba + k as u64, data: s });
                }
                call += 1;
            }
        }
    }
    out
}

pub(super) fn build(base: &Image, sw: &[Sw], pick: impl Fn(usize) -> bool) -> BTreeMap<u64, Vec<u8>> {
    let mut over = BTreeMap::new();
    for (i, s) in sw.iter().enumerate() {
        if pick(i) {
            put(&mut over, base, s.lba, s.data);
        }
    }
    over
}

fn is_superblock(lba: u64) -> bool {
    let b = lba / SECTORS_PER_BLOCK;
    b == 1 || b == 2
}

pub(super) struct Rng(pub(super) u64);
impl Rng {
    pub(super) fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

const PROBE: &str = "/zz-after-crash";

/// Mounts a crash image: read-write, exact counts, the state before or after the
/// operation; with `writable` also a new file, the full checks and a remount.
/// Returns true for the state after.
fn verify(base: &Image, blocks: u64, over: BTreeMap<u64, Vec<u8>>, g: u64, before: &Model, after: &Model, writable: bool, what: &str) -> Result<bool, String> {
    let d = attach(base, blocks, over, None);
    let r = (|| -> Result<bool, String> {
        walk_ok(d, what)?;
        let mut v = mount(d)?;
        ensure!(v.read_only_reason().is_none(), "{}: mounted read-only ({:?})", what, v.read_only_reason());
        // The generation says which state it must be: the old one (g) or the new (g + 1).
        let is_after = v.generation() == g + 1;
        ensure!(is_after || v.generation() == g, "{}: generation {} after a crash during commit {}", what, v.generation(), g + 1);
        same_as(&mut v, if is_after { after } else { before }, what)?;
        if writable {
            let mut m = if is_after { after.clone() } else { before.clone() };
            let data = pattern(5000, 77);
            // On a volume at the edge of full a clean refusal for space is fine.
            match v.create(PROBE) {
                Ok(()) => {
                    m.insert(PROBE.into(), Some(Vec::new()));
                    match v.write(PROBE, 0, &data) {
                        Ok(_) => {
                            m.insert(PROBE.into(), Some(data));
                        }
                        Err(FsError::NoSpace) => {}
                        Err(e) => return Err(format!("{}: write after the crash: {}", what, e)),
                    }
                }
                Err(FsError::NoSpace) => {}
                Err(e) => return Err(format!("{}: create after the crash: {}", what, e)),
            }
            check(&mut v, d, &m, what)?;
            drop(v);
            let mut v = mount(d)?;
            same_as(&mut v, &m, what)?;
        }
        Ok(is_after)
    })();
    block::remove(d);
    r
}

#[derive(Default)]
struct Stats {
    ops: usize,
    images: usize,
    after: usize,
    torn_sb: usize,
    writes: usize,
    reused: usize,
    refused: usize,
}

/// Runs `setup` without recording, then each of `ops`, recording it; every recorded
/// operation is checked at every write point (`prefix`) and with `draws` random
/// subsets per flush interval.  `snap`: blocks no write may touch.
fn scenario(start: &Image, blocks: u64, mut m: Model, setup: &[Op], ops: &[Op], prefix: bool, draws: usize, snap: Option<&BTreeMap<u64, [u8; 32]>>) -> Result<Stats, String> {
    let log = Rc::new(RefCell::new(Log::default()));
    let d = attach(start, blocks, BTreeMap::new(), Some(log.clone()));
    let res = (|| -> Result<Stats, String> {
        let mut st = Stats::default();
        let mut v = mount(d)?;
        for &op in setup {
            if let Op::Write(p, ..) = op {
                if !m.contains_key(p) {
                    continue;
                }
            }
            match apply(op, &mut v, &mut m) {
                Ok(()) | Err(FsError::NoSpace) => {}
                Err(e) => return Err(format!("setup {:?}: {}", op, e)),
            }
        }
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for &op in ops {
            let what = format!("{:?}", op);
            // A file whose create was refused for space is left out.
            if let Op::Write(p, ..) | Op::Truncate(p, _) | Op::Remove(p) = op {
                if !m.contains_key(p) {
                    continue;
                }
            }
            let base = snapshot(d, blocks)?;
            let before = m.clone();
            let g = v.generation();
            {
                let mut l = log.borrow_mut();
                l.ev.clear();
                l.on = true;
            }
            let r = apply(op, &mut v, &mut m);
            let ev = {
                let mut l = log.borrow_mut();
                l.on = false;
                core::mem::take(&mut l.ev)
            };
            if let Err(FsError::NoSpace) = r {
                // Refused before changing anything: nothing written, nothing changed.
                ensure!(ev.is_empty() && m == before, "{}: refused for space but wrote {} times", what, ev.len());
                st.refused += 1;
                continue;
            }
            r.map_err(|e| format!("{}: {}", what, e))?;
            check(&mut v, d, &m, &what)?;
            let sw = sectors(&ev);
            ensure!(!sw.is_empty(), "{}: nothing written", what);
            st.ops += 1;
            for e in &ev {
                if let Ev::Write(lba, data) = e {
                    st.writes += 1;
                    let b0 = lba / SECTORS_PER_BLOCK;
                    let nb = (data.len() / BLOCK).max(1) as u64;
                    for b in b0..b0 + nb {
                        if b >= RESERVED && base.get(b as usize).is_some_and(|x| !x.is_empty()) {
                            st.reused += 1;
                        }
                        if let Some(s) = snap {
                            ensure!(!s.contains_key(&b), "{}: wrote block {} of the snapshot", what, b);
                        }
                    }
                }
            }
            if prefix {
                // Every write boundary; inside a superblock write every sector.
                let mut points = vec![0usize];
                for i in 0..sw.len() {
                    let end_of_call = i + 1 == sw.len() || sw[i + 1].call != sw[i].call;
                    if end_of_call || is_superblock(sw[i].lba) {
                        points.push(i + 1);
                    }
                    if is_superblock(sw[i].lba) && !end_of_call {
                        st.torn_sb += 1;
                    }
                }
                for p in points {
                    let over = build(&base, &sw, |i| i < p);
                    // The new-file check where the state can change: at a flush and
                    // inside / after a superblock write.
                    let edge = p == 0 || p == sw.len() || is_superblock(sw[p - 1].lba) || sw[p].epoch != sw[p - 1].epoch;
                    let a = verify(&base, blocks, over, g, &before, &m, edge, &format!("{} crashed after {} of {} sectors", what, p, sw.len()))?;
                    st.images += 1;
                    st.after += a as usize;
                }
            }
            if draws > 0 {
                let epochs = sw.last().map(|s| s.epoch).unwrap_or(0);
                for e in 0..=epochs {
                    if !sw.iter().any(|s| s.epoch == e) {
                        continue;
                    }
                    for k in 0..draws {
                        // Even draws: any sector of the interval; odd: whole writes.
                        let coins: Vec<bool> = if k % 2 == 0 {
                            sw.iter().map(|_| rng.next() & 1 == 1).collect()
                        } else {
                            let calls = sw.last().map(|s| s.call + 1).unwrap_or(0);
                            let c: Vec<bool> = (0..calls).map(|_| rng.next() & 1 == 1).collect();
                            sw.iter().map(|s| c[s.call as usize]).collect()
                        };
                        let over = build(&base, &sw, |i| sw[i].epoch < e || (sw[i].epoch == e && coins[i]));
                        let a = verify(&base, blocks, over, g, &before, &m, k < 2, &format!("{}: interval {} draw {}", what, e, k))?;
                        st.images += 1;
                        st.after += a as usize;
                    }
                }
            }
        }
        Ok(st)
    })();
    block::remove(d);
    res
}

fn formatted(blocks: u64) -> Result<Image, String> {
    let d = attach(&Rc::new(Vec::new()), blocks, BTreeMap::new(), None);
    let r = super::format::format(d, &params()).map_err(|e| format!("format: {}", e)).and_then(|_| snapshot(d, blocks));
    block::remove(d);
    r
}

/// Operations over a small volume (96 blocks), so that freed blocks are reused soon:
/// directories, a file growing from depth 0 to 2 (a hole), overwrite, shrink, rename
/// with replace, a directory moved, removes.
const CRASH_BLOCKS: u64 = 96;
const OPS: [Op; 21] = [
    Op::Mkdir("/d"),
    Op::Create("/d/a"),
    Op::Write("/d/a", 0, 5, 1),
    Op::Create("/big"),
    Op::Write("/big", 0, 65536, 2),
    Op::Write("/big", 65536, 20000, 3),
    Op::Write("/big", 344064, 4096, 4),
    Op::Write("/big", 100000, 9000, 5),
    Op::Truncate("/big", 30000),
    Op::Write("/big", 0, 30000, 7),
    Op::Write("/big", 0, 30000, 8),
    Op::Rename("/d/a", "/a2"),
    Op::Create("/d/b"),
    Op::Write("/d/b", 0, 3000, 6),
    Op::Rename("/a2", "/d/b"),
    Op::Mkdir("/e"),
    Op::Rename("/d", "/e/d"),
    Op::Remove("/e/d/b"),
    Op::Remove("/e/d"),
    Op::Truncate("/big", 0),
    Op::Remove("/big"),
];

// ---------------- 15. every write point ----------------

/// A 64-block volume at the edge of full: crashes while space is refused, freed and
/// reused.
const FILL: [&str; 24] = [
    "/g00", "/g01", "/g02", "/g03", "/g04", "/g05", "/g06", "/g07", "/g08", "/g09", "/g10", "/g11",
    "/g12", "/g13", "/g14", "/g15", "/g16", "/g17", "/g18", "/g19", "/g20", "/g21", "/g22", "/g23",
];

/// Setup: a file, then small files until there is no space.
fn tight_setup() -> Vec<Op> {
    let mut ops = vec![Op::Create("/f"), Op::Write("/f", 0, 4096, 20)];
    for (i, p) in FILL.iter().enumerate() {
        ops.push(Op::Create(p));
        ops.push(Op::Write(p, 0, 4096, 30 + i as u32));
    }
    ops
}

/// Recorded: one more file (refused), three removed, the first file rewritten.
const TIGHT: [Op; 11] = [
    Op::Create("/g-more"),
    Op::Remove("/g00"),
    Op::Remove("/g01"),
    Op::Remove("/g02"),
    Op::Write("/f", 0, 4096, 60),
    Op::Write("/f", 0, 4096, 61),
    Op::Write("/f", 0, 4096, 62),
    Op::Write("/f", 4096, 4096, 63),
    Op::Write("/f", 0, 8192, 64),
    Op::Truncate("/f", 100),
    Op::Write("/f", 0, 4096, 65),
];

pub fn t_points() -> T {
    let img = formatted(CRASH_BLOCKS)?;
    let st = scenario(&img, CRASH_BLOCKS, Model::new(), &[], &OPS, true, 0, None)?;
    ensure!(st.torn_sb >= 7 * st.ops, "only {} torn superblock points in {} operations", st.torn_sb, st.ops);
    ensure!(st.reused > 0, "no block reused - the volume is too large for this test");
    let small = formatted(MIN_BLOCKS)?;
    let t = scenario(&small, MIN_BLOCKS, Model::new(), &tight_setup(), &TIGHT, true, 0, None)?;
    ensure!(t.refused > 0 && t.ops >= 6, "64-block volume: {} operations, {} refused for space", t.ops, t.refused);
    Ok(format!("{} operations ({} writes, {} over blocks freed earlier): crash after every write and inside every superblock write ({} torn superblocks) = {} images; each mounts read-write with exact counts, holds the old or the new state ({} new), at every flush and superblock sector also takes a new file and survives a remount; a 64-block volume at the edge of full: {} operations ({} refused for space, nothing written), {} images, {} writes over freed blocks", st.ops, st.writes, st.reused, st.torn_sb, st.images, st.after, t.ops, t.refused, t.images, t.reused))
}

// ---------------- 16. writes between flushes in any order ----------------

pub fn t_reorder() -> T {
    let img = formatted(CRASH_BLOCKS)?;
    let st = scenario(&img, CRASH_BLOCKS, Model::new(), &[], &OPS, false, 12, None)?;
    Ok(format!("{} operations, 12 random subsets per flush interval (any sectors / whole writes, everything flushed before kept) = {} images: old or new state ({} new), never a mix", st.ops, st.images, st.after))
}

// ---------------- 17. a write or flush failing at each position ----------------

pub fn t_failures() -> T {
    let img = formatted(CRASH_BLOCKS)?;
    let setup = [Op::Mkdir("/d"), Op::Create("/d/a"), Op::Write("/d/a", 0, 3000, 1), Op::Create("/big"), Op::Write("/big", 0, 40000, 2)];
    let targets = [Op::Write("/d/a", 1000, 5000, 3), Op::Write("/big", 344064, 4096, 4), Op::Rename("/d/a", "/big"), Op::Remove("/d/a")];
    // Build the state after the setup.
    let d = attach(&img, CRASH_BLOCKS, BTreeMap::new(), None);
    let mut m = Model::new();
    let prep = (|| -> Result<Image, String> {
        let mut v = mount(d)?;
        for &op in &setup {
            apply(op, &mut v, &mut m).map_err(|e| format!("setup {:?}: {}", op, e))?;
        }
        drop(v);
        snapshot(d, CRASH_BLOCKS)
    })();
    block::remove(d);
    let start = prep?;
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    let (mut runs, mut images, mut after_n) = (0usize, 0usize, 0usize);
    for &op in &targets {
        let what = format!("{:?}", op);
        // A clean run: the state after and the number of writes and flushes.
        let log = Rc::new(RefCell::new(Log::default()));
        let d = attach(&start, CRASH_BLOCKS, BTreeMap::new(), Some(log.clone()));
        let mut after = m.clone();
        let clean = (|| -> Result<(u64, u64, u64), String> {
            let mut v = mount(d)?;
            let g = v.generation();
            let (w0, f0) = (log.borrow().writes, log.borrow().flushes);
            apply(op, &mut v, &mut after).map_err(|e| format!("{}: {}", what, e))?;
            let l = log.borrow();
            Ok((l.writes - w0, l.flushes - f0, g))
        })();
        block::remove(d);
        let (nw, nf, g) = clean?;
        ensure!(nw > 0 && nf >= 2, "{}: {} writes, {} flushes", what, nw, nf);
        for k in 0..(nw + nf) {
            let (fw, ff) = if k < nw { (k + 1, 0) } else { (0, k - nw + 1) };
            let log = Rc::new(RefCell::new(Log::default()));
            let d = attach(&start, CRASH_BLOCKS, BTreeMap::new(), Some(log.clone()));
            let label = if fw != 0 { format!("{} with write {} failing", what, fw) } else { format!("{} with flush {} failing", what, ff) };
            let run = (|| -> Result<Vec<Ev>, String> {
                let mut v = mount(d)?;
                {
                    let mut l = log.borrow_mut();
                    // Positions count from the start of the operation.
                    l.fail_write = if fw != 0 { l.writes + fw } else { 0 };
                    l.fail_flush = if ff != 0 { l.flushes + ff } else { 0 };
                    l.on = true;
                }
                let mut tmp = m.clone();
                let r = apply(op, &mut v, &mut tmp);
                ensure!(r.is_err(), "{}: the operation succeeded", label);
                ensure!(v.read_only_reason().is_some(), "{}: the volume is still writable", label);
                ensure!(matches!(v.create("/x"), Err(FsError::ReadOnly)), "{}: a read-only volume took a create", label);
                let mut l = log.borrow_mut();
                l.on = false;
                Ok(core::mem::take(&mut l.ev))
            })();
            block::remove(d);
            let ev = run?;
            runs += 1;
            // Whatever part of the unflushed writes landed.
            let sw = sectors(&ev);
            let last = sw.last().map(|s| s.epoch).unwrap_or(0);
            for j in 0..8 {
                let coins: Vec<bool> = match j {
                    0 => sw.iter().map(|_| true).collect(),
                    1 => sw.iter().map(|_| false).collect(),
                    _ => sw.iter().map(|_| rng.next() & 1 == 1).collect(),
                };
                let over = build(&start, &sw, |i| sw[i].epoch < last || coins[i]);
                let a = verify(&start, CRASH_BLOCKS, over, g, &m, &after, j < 2, &format!("{} (landed: {})", label, j))?;
                images += 1;
                after_n += a as usize;
            }
        }
    }
    Ok(format!("{} operations, a write or flush failing at each of their positions ({} runs): every run returns an error, turns the volume read-only and refuses a create; {} images of what may have landed – each mounts read-write with the old or the new state ({} new)", targets.len(), runs, images, after_n))
}

// ---------------- 18. a snapshot through crashes ----------------

pub fn t_crash_snapshot() -> T {
    let raw = crate::initrd::DESOFS_REF;
    ensure!(raw.len() >= 64 * BLOCK, "reference image missing");
    let blocks = (raw.len() / BLOCK) as u64;
    let img: Image = Rc::new(raw.chunks(BLOCK).map(|c| if c.iter().all(|&x| x == 0) { Vec::new() } else { c.to_vec() }).collect());
    // The snapshot's blocks (root entry 1 of the newer superblock's root block).
    let d = attach(&img, blocks, BTreeMap::new(), None);
    let snap = snapshot_blocks(d, u64_at(&raw[2 * BLOCK..], 80), 1);
    block::remove(d);
    ensure!(snap.len() >= 10, "snapshot has only {} blocks", snap.len());
    let ops = [
        Op::Write("/hello.txt", 0, 10, 8),
        Op::Remove("/big.bin"),
        Op::Create("/n1"),
        Op::Write("/n1", 0, 6000, 9),
        Op::Mkdir("/nd"),
        Op::Rename("/sub/a.txt", "/nd/moved"),
        Op::Remove("/sub"),
    ];
    let st = scenario(&img, blocks, ref_model(), &[], &ops, true, 8, Some(&snap))?;
    Ok(format!("reference image with a snapshot of {} blocks: {} operations, {} crash images (every write point + 8 subsets per interval) – none of the {} writes touches a snapshot block; old or new state ({} new)", snap.len(), st.ops, st.images, st.writes, st.after))
}
