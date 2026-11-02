// DESOFS TEST – `desofs check`, `desofs repair` and directories read in parts.
//
// Damage is made on copies of images: a changed byte without new checksums (the sum
// must catch it), or a change "resealed" – every checksum above it recomputed – so that
// the rule itself must catch it.  Every disk is a RAM disk.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use super::check::{self, CheckReport};
use super::layout::*;
use super::test::{blk, locate, node_off, put64, rd, reseal, seal_sb};
use super::test_crash::{attach, build, sectors, Image, Log, Rng};
use super::test_write::{formatted, mount, pattern, read_all, walk_ok, write_all, T};
use super::{probe, sha256, State};
use crate::block::{self, BlockDevice, BlockError, RamDisk};
use crate::fs::{DirEntry, FileSystem, FsError};

macro_rules! ensure {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            return Err(format!($($msg)*));
        }
    };
}

fn disk_of(img: &[u8]) -> usize {
    let d = block::register(Box::new(RamDisk::new("dsfc", (img.len() / 512) as u64)));
    let _ = block::write(d, 0, img);
    d
}

fn image(d: usize, blocks: u64) -> Vec<u8> {
    let mut v = vec![0u8; blocks as usize * BLOCK];
    let _ = block::read(d, 0, &mut v);
    v
}

fn run_check(img: &[u8]) -> Result<CheckReport, String> {
    let d = disk_of(img);
    let r = check::check(d, &mut |_, _| {});
    block::remove(d);
    r
}

fn text(r: &CheckReport) -> String {
    let mut s = String::new();
    for (_, l) in &r.lines {
        s.push_str(l);
        s.push_str(" | ");
    }
    s
}

fn errors_with(r: &CheckReport, parts: &[&str]) -> bool {
    r.lines.iter().any(|(lv, l)| *lv == check::Level::Error && parts.iter().all(|p| l.contains(p)))
}

fn reference() -> Vec<u8> {
    crate::initrd::DESOFS_REF.to_vec()
}

// ---------------- 19. check on sound volumes ----------------

pub fn t_check_clean() -> T {
    // A fresh volume.
    let d = formatted(256)?;
    let r = check::check(d, &mut |_, _| {});
    block::remove(d);
    let r = r?;
    ensure!(r.errors == 0 && r.warnings == 0, "fresh volume: {}", text(&r));
    ensure!(r.slots.iter().all(|s| s.sb_ok && s.tree == Some(Ok(())) && s.data_ok == Some(true)), "fresh volume slots: {}", text(&r));
    // After real work: files from depth 0 to 2, a hole, directories.
    let d = formatted(1024)?;
    let res = (|| -> T {
        let mut v = mount(d)?;
        v.mkdir("/d").map_err(|e| format!("{}", e))?;
        v.mkdir("/d/e").map_err(|e| format!("{}", e))?;
        for (i, n) in [100usize, 5000, 70_000].iter().enumerate() {
            let p = format!("/d/f{}", i);
            v.create(&p).map_err(|e| format!("{}", e))?;
            write_all(&mut v, &p, 0, &pattern(*n, i as u32))?;
        }
        v.create("/d/e/sparse").map_err(|e| format!("{}", e))?;
        write_all(&mut v, "/d/e/sparse", 400_000, b"end")?;
        v.rename("/d/f0", "/top").map_err(|e| format!("{}", e))?;
        v.remove("/d/f1").map_err(|e| format!("{}", e))?;
        // A mounted volume is refused.
        let m = check::check(d, &mut |_, _| {});
        ensure!(matches!(&m, Err(e) if e.contains("unmount first")), "check of a mounted volume: {:?}", m.as_ref().map(|r| r.errors));
        let rp = check::repair(d, true);
        ensure!(matches!(&rp, Err(e) if e.contains("unmount first")), "repair of a mounted volume: {:?}", rp);
        drop(v);
        let before = image(d, 1024);
        let r = check::check(d, &mut |_, _| {})?;
        let after = image(d, 1024);
        ensure!(sha256(&before) == sha256(&after), "check changed the disk");
        ensure!(r.errors == 0 && r.warnings == 0, "after work: {}", text(&r));
        ensure!(r.lines.iter().any(|(_, l)| l.contains("live: 3 files, 3 directories, OK")), "live root counts: {}", text(&r));
        Ok(format!("{} data blocks read", r.data_blocks))
    })();
    block::remove(d);
    let work = res?;
    // The reference image: two superblocks, a snapshot, a shared DSPT.
    let r = run_check(&reference())?;
    ensure!(r.errors == 0 && r.warnings == 0 && r.snapshots == 1, "reference image: {}", text(&r));
    ensure!(r.lines.iter().any(|(_, l)| l.contains("snapshot \"before-v5\"") && l.contains("OK")), "snapshot not checked: {}", text(&r));
    Ok(format!("fresh volume, a volume after work ({}, files depth 0-2, a hole, rename, remove) and the reference image with its snapshot: 0 errors, 0 warnings, each superblock reported as checksum / tree / data; check writes nothing (disk SHA-256 before = after); a mounted volume -> 'unmount first' for check and repair", work))
}

// ---------------- 20. check finds damage ----------------

/// Entry `name` of the directory block at `addr`: offset in the image.
fn entry_off(img: &[u8], addr: u64, name: &[u8]) -> Option<usize> {
    let b = rd(img, addr);
    let mut off = 0;
    while off < BLOCK {
        let rec = u16_at(b, off + 10) as usize;
        if rec < 16 {
            return None;
        }
        let len = b[off + 9] as usize;
        if u64_at(b, off) != 0 && &b[off + 12..off + 12 + len] == name {
            return Some(addr as usize * BLOCK + off);
        }
        off += rec;
    }
    None
}

pub fn t_check_damage() -> T {
    let base = reference();
    let m = locate(&base);
    let mut cases = 0;
    let mut case = |what: &str, img: Vec<u8>, parts: &[&str], mount_rw: bool| -> Result<(), String> {
        let r = run_check(&img)?;
        ensure!(r.errors > 0 && errors_with(&r, parts), "{}: expected an error with {:?}: {}", what, parts, text(&r));
        if mount_rw {
            let d = disk_of(&img);
            let st = probe(d).state;
            block::remove(d);
            ensure!(st == State::ReadWrite, "{}: the mount walk (metadata only) should still allow read-write: {:?}", what, st);
        }
        cases += 1;
        Ok(())
    };
    // A data byte of a file – only check sees it (the mount reads metadata only).
    let mut img = base.clone();
    blk(&mut img, m.hello5)[3] ^= 0x40;
    case("file data byte", img, &["/hello.txt", "block 0", "checksum"], true)?;
    // A data block of a directory.
    let mut img = base.clone();
    blk(&mut img, m.sub_dir)[40] ^= 1;
    case("directory data byte", img, &["/sub", "checksum"], true)?;
    // One node listed twice, another not at all: hello.txt's entry now names a.txt.
    let mut img = base.clone();
    let o = entry_off(&img, m.root_dir, b"hello.txt").ok_or("hello.txt entry")?;
    put64(&mut img, o, 5);
    reseal(&mut img);
    case("node listed twice", img.clone(), &["listed in 2 directory entries"], false)?;
    case("orphan", img.clone(), &["node 2", "orphan"], false)?;
    case("wrong parent", img, &["node 5 has parent 4"], false)?;
    // Entry type differs from the node.
    let mut img = base.clone();
    let o = entry_off(&img, m.root_dir, b"hello.txt").ok_or("hello.txt entry")?;
    img[o + 8] = TYPE_DIR;
    reseal(&mut img);
    case("entry type", img, &["type differs from node 2"], false)?;
    // A node whose parent is another directory than the one listing it.
    let mut img = base.clone();
    let o = m.nd5 as usize * BLOCK + node_off(2) + 40;
    put64(&mut img, o, 4);
    reseal(&mut img);
    case("node parent", img, &["'hello.txt'", "has parent 4"], false)?;
    // A directory cycle: /sub's parent is /sub itself.
    let mut img = base.clone();
    let o = m.nd5 as usize * BLOCK + node_off(4) + 40;
    put64(&mut img, o, 4);
    reseal(&mut img);
    case("cycle", img, &["cycle"], false)?;
    // A directory entry removed: /sub and below it unreachable.
    let mut img = base.clone();
    let o = entry_off(&img, m.root_dir, b"sub").ok_or("sub entry")?;
    let rec = u16_at(&img, o + 10);
    img[o..o + rec as usize].fill(0);
    img[o + 10..o + 12].copy_from_slice(&rec.to_le_bytes());
    reseal(&mut img);
    case("entry removed", img, &["node 4 (directory)", "orphan"], false)?;
    // E3: the live tree and the snapshot reach a.txt's data through different node
    // blocks – with a different birth in one of them.
    let mut img = base.clone();
    let o = m.nd5 as usize * BLOCK + node_off(5) + 56 + 8;
    let b = u64_at(&img, o);
    put64(&mut img, o, if b < 5 { b + 1 } else { b - 1 });
    reseal(&mut img);
    case("shared data, different pointer", img, &["shared by two roots", "different pointers"], false)?;
    // used_blocks wrong: a warning, not an error.
    let mut img = base.clone();
    let u = u64_at(rd(&img, 2), 48);
    put64(blk(&mut img, 2), 48, u + 3);
    seal_sb(&mut img, 2);
    let r = run_check(&img)?;
    ensure!(r.errors == 0 && r.warnings == 1 && r.lines.iter().any(|(lv, l)| *lv == check::Level::Warning && l.contains("used_blocks")), "used_blocks: {}", text(&r));
    // A superblock with a sound checksum but a damaged tree, and a bad superblock.
    let mut img = base.clone();
    blk(&mut img, m.rt4)[HDR_SIZE + 60] ^= 1;
    let r = run_check(&img)?;
    ensure!(r.slots[0].sb_ok && matches!(r.slots[0].tree, Some(Err(_))) && r.slots[0].data_ok.is_none(), "A: checksum OK, tree damaged: {}", text(&r));
    ensure!(r.slots[1].tree == Some(Ok(())) && r.slots[1].data_ok == Some(true), "B sound: {}", text(&r));
    let mut img = base.clone();
    blk(&mut img, 1)[100] ^= 1;
    let r = run_check(&img)?;
    ensure!(!r.slots[0].sb_ok && r.slots[0].tree.is_none() && r.slots[1].data_ok == Some(true), "A bad superblock: {}", text(&r));
    Ok(format!("reference image, {} damage cases: file data, directory data (only check sees these - the mount stays read-write), a node in two entries, an orphan, a wrong parent, entry type, a cycle, a removed entry, shared data with a different pointer (E3) - all resealed but the data ones; used_blocks -> one warning, no error; superblock with a sound checksum and a damaged tree / a bad superblock reported apart", cases))
}

// ---------------- 21. repair ----------------

/// A RAM disk that is read-only.
struct RoDisk {
    inner: RamDisk,
}

impl BlockDevice for RoDisk {
    fn name(&self) -> &str {
        "rodisk"
    }
    fn description(&self) -> String {
        String::from("read-only RAM disk")
    }
    fn sector_count(&self) -> u64 {
        self.inner.sector_count()
    }
    fn read_only(&self) -> bool {
        true
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.inner.read(lba, buf)
    }
    fn write(&mut self, _lba: u64, _buf: &[u8]) -> Result<(), BlockError> {
        Err(BlockError::ReadOnly)
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
}

/// Reference image with A's tree damaged (its root block) – read-only volume.
fn older_damaged() -> Vec<u8> {
    let mut img = reference();
    let m = locate(&img);
    blk(&mut img, m.rt4)[HDR_SIZE + 60] ^= 1;
    img
}

pub fn t_repair() -> T {
    let mut done = Vec::new();
    // Older tree damaged: B (newer) is copied to A.
    let img = older_damaged();
    let d = disk_of(&img);
    let r = (|| -> T {
        ensure!(matches!(probe(d).state, State::ReadOnly(_)), "damaged A should mount read-only");
        let b_before = image(d, 128)[2 * BLOCK..3 * BLOCK].to_vec();
        let plan = check::repair(d, false)?;
        ensure!(plan.contains("superblock A gets a copy of superblock B") && plan.contains("5 -> 6"), "plan: {}", plan);
        ensure!(matches!(probe(d).state, State::ReadOnly(_)), "repair without 'yes' changed something");
        check::repair(d, true)?;
        let after = image(d, 128);
        ensure!(after[2 * BLOCK..3 * BLOCK] == b_before[..], "the good superblock B was changed");
        let (a, b) = (Superblock::parse(rd(&after, 1)), Superblock::parse(rd(&after, 2)));
        let (Ok(a), Ok(b)) = (a, b) else { return Err(String::from("superblocks after repair")) };
        ensure!(a.root == b.root && a.generation == 6 && b.generation == 5 && a.uuid == b.uuid, "after repair: A gen {} B gen {}", a.generation, b.generation);
        walk_ok(d, "after repair")?;
        let rep = check::check(d, &mut |_, _| {})?;
        ensure!(rep.errors == 0, "check after repair: {}", text(&rep));
        // Writable and lasting.
        let mut v = mount(d)?;
        v.create("/after-repair").map_err(|e| format!("{}", e))?;
        write_all(&mut v, "/after-repair", 0, b"works")?;
        drop(v);
        let mut v = mount(d)?;
        ensure!(read_all(&mut v, "/after-repair")? == b"works", "file written after repair lost");
        ensure!(read_all(&mut v, "/hello.txt")? == b"Hello DeSoFS v5\n", "newer state not kept");
        Ok(String::new())
    })();
    block::remove(d);
    r?;
    done.push("older tree damaged -> B copied to A (gen 6), B untouched, read-write, a new file survives a remount");
    // Newer tree damaged: A (older) is copied to B, generation 5 is lost.
    let mut img = reference();
    let m = locate(&img);
    blk(&mut img, m.rt5)[HDR_SIZE + 60] ^= 1;
    let d = disk_of(&img);
    let r = (|| -> T {
        let plan = check::repair(d, false)?;
        ensure!(plan.contains("superblock B gets a copy of superblock A") && plan.contains("generation 5 are lost"), "plan: {}", plan);
        check::repair(d, true)?;
        walk_ok(d, "after repair of B")?;
        let mut v = mount(d)?;
        ensure!(read_all(&mut v, "/hello.txt")? == b"Hello DeSoFS\n", "older state expected");
        Ok(String::new())
    })();
    block::remove(d);
    r?;
    done.push("newer tree damaged -> A copied to B, back to generation 4 (stated in the plan)");
    // Refusals.
    let refuse = |what: &str, img: &[u8], part: &str| -> Result<(), String> {
        let d = disk_of(img);
        let before = image(d, (img.len() / BLOCK) as u64);
        let r = check::repair(d, true);
        let after = image(d, (img.len() / BLOCK) as u64);
        block::remove(d);
        ensure!(matches!(&r, Err(e) if e.contains(part)), "{}: {:?}", what, r);
        ensure!(before == after, "{}: refused but the disk changed", what);
        Ok(())
    };
    refuse("both sound", &reference(), "nothing to repair")?;
    let mut img = reference();
    blk(&mut img, m.rt4)[HDR_SIZE + 60] ^= 1;
    blk(&mut img, m.rt5)[HDR_SIZE + 60] ^= 1;
    refuse("both damaged", &img, "no superblock")?;
    let mut img = older_damaged();
    blk(&mut img, m.hello5)[0] ^= 1;
    refuse("sound tree, damaged data", &img, "would keep a damaged state")?;
    // Generation at its maximum: B = u64::MAX (only B valid).
    let d = formatted(64)?;
    let mut img = image(d, 64);
    block::remove(d);
    put64(blk(&mut img, 2), 32, u64::MAX);
    seal_sb(&mut img, 2);
    blk(&mut img, 1).fill(0);
    refuse("generation u64::MAX", &img, "maximum")?;
    // A read-only disk.
    let img = older_damaged();
    let ro = block::register(Box::new(RoDisk { inner: RamDisk::new("ro", (img.len() / 512) as u64) }));
    let r = check::repair(ro, true);
    block::remove(ro);
    ensure!(matches!(&r, Err(e) if e.contains("read-only")), "read-only disk: {:?}", r);
    done.push("refused: both sound, both damaged, a sound tree with damaged data, generation u64::MAX, a read-only disk, a mounted volume (test 19) - nothing written");
    // Interrupted at every sector of the superblock write (and a random part of it).
    let img = older_damaged();
    let base: Image = Rc::new(img.chunks(BLOCK).map(|c| if c.iter().all(|&x| x == 0) { Vec::new() } else { c.to_vec() }).collect());
    let blocks = (img.len() / BLOCK) as u64;
    let log = Rc::new(RefCell::new(Log::default()));
    log.borrow_mut().on = true;
    let d = attach(&base, blocks, BTreeMap::new(), Some(log.clone()));
    let r = check::repair(d, true);
    block::remove(d);
    r?;
    let ev = core::mem::take(&mut log.borrow_mut().ev);
    let sw = sectors(&ev);
    ensure!(sw.len() == 8, "repair wrote {} sectors (expected one superblock)", sw.len());
    let mut rng = Rng(0x5EED_0F_0E9A_12);
    let mut images = 0;
    for k in 0..(9 + 16) {
        let coins: Vec<bool> = if k <= 8 { (0..sw.len()).map(|i| i < k).collect() } else { (0..sw.len()).map(|_| rng.next() & 1 == 1).collect() };
        let over = build(&base, &sw, |i| coins[i]);
        let d = attach(&base, blocks, over, None);
        let r = (|| -> Result<(), String> {
            let st = probe(d).state;
            ensure!(!matches!(st, State::Refused(_)), "interrupted repair ({} of 8 sectors): refused: {:?}", k, st);
            let now = image(d, blocks);
            ensure!(now[2 * BLOCK..3 * BLOCK] == img[2 * BLOCK..3 * BLOCK], "interrupted repair touched the good superblock");
            match check::repair(d, true) {
                Ok(_) => {}
                Err(e) if e.contains("nothing to repair") => {}
                Err(e) => return Err(format!("repair again after an interruption ({}): {}", k, e)),
            }
            walk_ok(d, "after the repeated repair")
        })();
        block::remove(d);
        r?;
        images += 1;
    }
    done.push("interrupted after each of the 8 superblock sectors and 16 random parts: still mountable, the good superblock untouched, repair again works");
    let mut s = String::new();
    for (i, x) in done.iter().enumerate() {
        if i > 0 {
            s.push_str("; ");
        }
        s.push_str(x);
    }
    Ok(format!("{} ({} interrupted images)", s, images))
}

// ---------------- 22. directories in parts ----------------

pub fn t_cursor() -> T {
    let d = formatted(2048)?;
    let r = (|| -> T {
        let mut v = mount(d)?;
        v.mkdir("/d").map_err(|e| format!("{}", e))?;
        let name = |i: usize| format!("file-with-a-longer-name-{:03}", i);
        for i in 0..150 {
            v.create(&format!("/d/{}", name(i))).map_err(|e| format!("create {}: {}", i, e))?;
        }
        let blocks = v.stat("/d").map_err(|e| format!("{}", e))?.size / BLOCK as u64;
        ensure!(blocks >= 2, "150 entries in {} directory block", blocks);
        // Stable: every file never touched while reading.  Churn: every 3rd is removed
        // during the reading, new ones are created.
        let stable: BTreeSet<String> = (0..150).filter(|i| i % 3 != 0).map(name).collect();
        let mut seen: BTreeMap<String, u32> = BTreeMap::new();
        let mut cursor = 0u64;
        let mut parts = 0;
        let mut churn = 0;
        loop {
            let (part, next) = v.read_dir_at("/d", cursor, 7).map_err(|e| format!("read_dir_at {}: {}", cursor, e))?;
            ensure!(part.len() <= 7, "part of {} entries", part.len());
            for e in part {
                *seen.entry(e.name).or_insert(0) += 1;
            }
            parts += 1;
            if churn < 50 {
                v.remove(&format!("/d/{}", name(churn * 3))).map_err(|e| format!("{}", e))?;
                v.create(&format!("/d/new-{:02}", churn)).map_err(|e| format!("{}", e))?;
                churn += 1;
            }
            match next {
                Some(c) => {
                    ensure!(c > cursor, "cursor went back: {} -> {}", cursor, c);
                    cursor = c;
                }
                None => break,
            }
            ensure!(parts < 1000, "the listing never ended");
        }
        for s in &stable {
            ensure!(seen.get(s) == Some(&1), "{} seen {:?} times", s, seen.get(s));
        }
        ensure!(seen.values().all(|&n| n == 1), "an entry seen twice");
        // End and wrong positions.
        let end = blocks * BLOCK as u64;
        let (p, n) = v.read_dir_at("/d", end, 7).map_err(|e| format!("at the end: {}", e))?;
        ensure!(p.is_empty() && n.is_none(), "reading at the end: {} entries", p.len());
        ensure!(matches!(v.read_dir_at("/d", 3, 7), Err(FsError::BadCursor)), "cursor inside an entry accepted");
        ensure!(matches!(v.read_dir_at("/d", end + BLOCK as u64, 7), Err(FsError::BadCursor)), "cursor past the directory accepted");
        ensure!(matches!(v.read_dir_at("/d", end + 8, 7), Err(FsError::BadCursor)), "cursor past the end accepted");
        // The whole listing in parts = read_dir.
        let all: BTreeSet<String> = v.read_dir("/d").map_err(|e| format!("{}", e))?.into_iter().map(|e| e.name).collect();
        let mut parts_set = BTreeSet::new();
        let mut c = 0;
        loop {
            let (p, n) = v.read_dir_at("/d", c, 11).map_err(|e| format!("{}", e))?;
            for e in p {
                ensure!(parts_set.insert(e.name), "duplicate in a quiet listing");
            }
            match n {
                Some(x) => c = x,
                None => break,
            }
        }
        ensure!(parts_set == all, "parts {} vs read_dir {}", parts_set.len(), all.len());
        Ok(format!("{} directory blocks, {} parts of 7 with 50 removes and 50 creates in between: every untouched entry exactly once, nothing twice; the end -> empty; a position inside an entry / past the directory -> refused; a quiet listing in parts = read_dir", blocks, parts))
    })();
    block::remove(d);
    let desofs = r?;
    // The default method (ramfs, a list index) through the VFS.
    let _ = crate::fs::mkdir("/tmp/curtest");
    for i in 0..20 {
        let _ = crate::fs::write_file(&format!("/tmp/curtest/f{:02}", i), b"x");
    }
    let mut got: Vec<DirEntry> = Vec::new();
    let mut c = 0;
    loop {
        let (p, n) = crate::fs::read_dir_at("/tmp/curtest", c, 7).map_err(|e| format!("ramfs: {}", e))?;
        got.extend(p);
        match n {
            Some(x) => c = x,
            None => break,
        }
    }
    let bad = crate::fs::read_dir_at("/tmp/curtest", 21, 7);
    for i in 0..20 {
        let _ = crate::fs::remove(&format!("/tmp/curtest/f{:02}", i));
    }
    let _ = crate::fs::remove("/tmp/curtest");
    ensure!(got.len() == 20, "ramfs in parts: {} entries", got.len());
    ensure!(matches!(bad, Err(FsError::BadCursor)), "ramfs: position past the end accepted");
    Ok(format!("DeSoFS: {}; ramfs through the VFS (default: a list index): 20 entries in parts of 7, a position past the end refused", desofs))
}
