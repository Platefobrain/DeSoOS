// DESOFS TEST – snapshots (stage 5): create, read-only views, names and the limit;
// space – R1 keeps every block a snapshot holds through heavy reuse, R3 gives back
// exactly the blocks only a deleted snapshot held; restore (every snapshot stays); power
// loss during create, delete and restore at every write and inside every superblock
// sector, each operation twice in a row so that both superblock slots are hit.
//
// After every step the stage-1 walk must accept the volume read-write with exact counts
// and no block reachable from either superblock may be free in the allocator.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use super::test_crash::{self as crash, Ev, Image, Log};
use super::test_write::{check, formatted, mount, pattern, read_all, same_as, walk_ok, write_all, Model, T};
use super::vol::Volume;
use crate::block;
use crate::fs::{FileSystem, FsError};

macro_rules! ensure {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            return Err(format!($($msg)*));
        }
    };
}

fn disk_sum(d: usize) -> [u8; 32] {
    let n = block::with_device(d, |x| x.sector_count()).unwrap_or(0);
    let mut v = vec![0u8; (n as usize) * 512];
    let _ = block::read(d, 0, &mut v);
    super::sha256(&v)
}

fn snap_names(v: &Volume) -> Vec<String> {
    let mut n: Vec<String> = v
        .snapshots()
        .iter()
        .map(|(_, e)| {
            let end = e.name.iter().position(|&c| c == 0).unwrap_or(24);
            String::from(core::str::from_utf8(&e.name[..end]).unwrap_or("?"))
        })
        .collect();
    n.sort();
    n
}

fn view(d: usize, name: &str) -> Result<Volume, String> {
    Volume::mount_snapshot(d, name).map_err(|e| format!("view {}: {}", name, e))
}

/// A small commit on the live tree (moves the superblock on one generation).
fn tick(v: &mut Volume, m: &mut Model, k: u32) -> Result<(), String> {
    if !m.contains_key("/t") {
        v.create("/t").map_err(|e| format!("create /t: {}", e))?;
    }
    let data = pattern(100, k);
    v.write("/t", 0, &data).map_err(|e| format!("tick write: {}", e))?;
    m.insert("/t".into(), Some(data));
    Ok(())
}

fn ticks(v: &mut Volume, m: &mut Model, n: u32, seed: u32) -> Result<(), String> {
    for k in 0..n {
        tick(v, m, seed + k)?;
    }
    Ok(())
}

fn full_check(d: usize, what: &str) -> Result<(), String> {
    let rep = super::check::check(d, &mut |_, _| {}).map_err(|e| format!("{}: check: {}", what, e))?;
    ensure!(rep.errors == 0 && rep.warnings == 0 && rep.slots.iter().all(|s| !s.sb_ok || s.complete), "{}: check: {} errors, {} warnings {:?}", what, rep.errors, rep.warnings, rep.lines);
    Ok(())
}

// ---------------- 25. create, views, names, the limit ----------------

pub fn t_create() -> T {
    let d = formatted(512)?;
    let r = (|| -> T {
        let mut v = mount(d)?;
        let mut m = Model::new();
        v.create("/a").map_err(|e| format!("{}", e))?;
        write_all(&mut v, "/a", 0, &pattern(20000, 1))?;
        m.insert("/a".into(), Some(pattern(20000, 1)));
        v.mkdir("/dir").map_err(|e| format!("{}", e))?;
        m.insert("/dir".into(), None);
        v.create("/dir/b").map_err(|e| format!("{}", e))?;
        write_all(&mut v, "/dir/b", 0, &pattern(5000, 2))?;
        m.insert("/dir/b".into(), Some(pattern(5000, 2)));
        check(&mut v, d, &m, "before the snapshot")?;

        // Names the kernel refuses – nothing written.
        let sum = disk_sum(d);
        let long = "a".repeat(25);
        let bad = ["", long.as_str(), "a/b", "a b", ".", "..", "x\u{0}y", "x\ty", "x\u{7f}", "\n"];
        for n in bad {
            ensure!(v.snapshot_create(n).is_err(), "name {:?} accepted", n);
        }
        ensure!(disk_sum(d) == sum, "a refused name changed the disk");
        let gen0 = v.generation();
        v.snapshot_create("s1")?;
        ensure!(v.snapshot_create("s1").is_err(), "a second snapshot named s1 accepted");
        ensure!(snap_names(&v) == ["s1"], "snapshots {:?}", snap_names(&v));
        ensure!(v.snapshots()[0].1.created_gen == gen0, "created_gen {} for the state of generation {}", v.snapshots()[0].1.created_gen, gen0);
        check(&mut v, d, &m, "snapshot s1 created")?;
        let frozen = m.clone();

        // Every kind of change on the live tree.
        write_all(&mut v, "/a", 100, &pattern(300, 3))?;
        let mut a = pattern(20000, 1);
        a[100..400].copy_from_slice(&pattern(300, 3));
        write_all(&mut v, "/a", 20000, &pattern(9000, 4))?;
        a.extend_from_slice(&pattern(9000, 4));
        m.insert("/a".into(), Some(a));
        v.truncate("/dir/b", 10).map_err(|e| format!("{}", e))?;
        m.insert("/dir/b".into(), Some(pattern(5000, 2)[..10].to_vec()));
        v.rename("/dir/b", "/b2").map_err(|e| format!("{}", e))?;
        let b = m.remove("/dir/b").unwrap();
        m.insert("/b2".into(), b);
        v.remove("/dir").map_err(|e| format!("{}", e))?;
        m.remove("/dir");
        v.mkdir("/new").map_err(|e| format!("{}", e))?;
        m.insert("/new".into(), None);
        check(&mut v, d, &m, "live tree changed")?;

        // The view still holds the old state, and cannot be written.
        let mut s1 = view(d, "s1")?;
        same_as(&mut s1, &frozen, "view s1")?;
        ensure!(matches!(s1.create("/x"), Err(FsError::ReadOnly)) && matches!(s1.write("/a", 0, b"z"), Err(FsError::ReadOnly)), "a snapshot view accepted a write");
        ensure!(s1.snapshot_create("x").is_err(), "a snapshot taken through a view");
        ensure!(v.snapshot_delete("s1").is_err(), "a viewed snapshot deleted");
        drop(s1);
        ensure!(Volume::mount_snapshot(d, "nope").is_err(), "a view of a missing snapshot");

        // Up to 31; the 32nd is refused without a write.
        for k in 2..=31 {
            v.snapshot_create(&format!("s{}", k))?;
        }
        let sum = disk_sum(d);
        ensure!(v.snapshot_create("s32").is_err(), "a 32nd snapshot accepted");
        ensure!(disk_sum(d) == sum, "the refused 32nd snapshot changed the disk");
        check(&mut v, d, &m, "31 snapshots")?;
        let (_, list) = super::snapshot_usage(d, true)?;
        ensure!(list.len() == 31, "snapshot list has {} entries", list.len());
        // s2..s31 hold the same state as the live tree had: only s1 has blocks of its own.
        let s1_only = list.iter().find(|s| s.name == "s1").and_then(|s| s.only).unwrap_or(0);
        ensure!(s1_only > 0, "s1 holds no blocks of its own");
        drop(v);
        full_check(d, "31 snapshots, unmounted")?;
        let mut s31 = view(d, "s31")?;
        same_as(&mut s31, &m, "view s31")?;
        Ok(format!("names refused without a write ({} cases: empty, 25 bytes, '/', space, '.', '..', NUL, control, DEL, newline), duplicate refused; the view of s1 equals the state before overwrite / append / truncate / rename / remove / mkdir and refuses writes; a viewed snapshot cannot be deleted; 31 snapshots, the 32nd refused with the disk unchanged; s1 alone holds {} blocks; check 0 errors", bad.len(), s1_only))
    })();
    block::remove(d);
    r
}

// ---------------- 26. space: R1 and R3 ----------------

pub fn t_space() -> T {
    let d = formatted(1024)?;
    let r = (|| -> T {
        let mut v = mount(d)?;
        let mut m = Model::new();
        let big = pattern(1024 * 1024, 9);
        v.create("/big").map_err(|e| format!("{}", e))?;
        write_all(&mut v, "/big", 0, &big)?;
        m.insert("/big".into(), Some(big.clone()));
        ticks(&mut v, &mut m, 3, 100)?;
        let f0 = v.free_blocks();
        v.snapshot_create("keep")?;
        ticks(&mut v, &mut m, 3, 110)?;
        // Creating it costs nothing (one root block replaces another); the commits after it
        // keep the old copies of what they changed – exactly the blocks only it now holds.
        let (_, list) = super::snapshot_usage(d, true)?;
        let held = list[0].only.unwrap_or(0);
        ensure!(f0 - v.free_blocks() == held, "free went down by {} after the snapshot, it alone holds {}", f0 as i64 - v.free_blocks() as i64, held);

        // R1: removing the file gives nothing back while the snapshot holds it.
        v.remove("/big").map_err(|e| format!("{}", e))?;
        m.remove("/big");
        ticks(&mut v, &mut m, 3, 120)?;
        let f1 = v.free_blocks();
        ensure!(f1 <= f0, "removing a file held by a snapshot freed {} blocks", f1 - f0);
        check(&mut v, d, &m, "file removed under a snapshot")?;
        let (_, list) = super::snapshot_usage(d, true)?;
        let only = list[0].only.unwrap_or(0);
        ensure!(only >= 256, "the snapshot holds only {} blocks of its own (the 1 MiB file is 256)", only);

        // Heavy reuse of every free block, then the snapshot's file is still intact.
        v.create("/fill").map_err(|e| format!("{}", e))?;
        let chunk = pattern(64 * 1024, 7);
        let mut off = 0u64;
        loop {
            match v.write("/fill", off, &chunk) {
                Ok(_) => off += chunk.len() as u64,
                Err(FsError::NoSpace) => break,
                Err(e) => return Err(format!("fill: {}", e)),
            }
        }
        ensure!(off >= 64 * 1024, "the fill wrote only {} bytes", off);
        v.remove("/fill").map_err(|e| format!("{}", e))?;
        ticks(&mut v, &mut m, 3, 130)?;
        check(&mut v, d, &m, "after filling and emptying the volume")?;
        {
            let mut keep = view(d, "keep")?;
            ensure!(read_all(&mut keep, "/big")? == big, "the snapshot's file changed after the volume was filled");
        }

        // R3: delete gives back exactly the blocks only the snapshot held.
        let f2 = v.free_blocks();
        v.snapshot_delete("keep")?;
        check(&mut v, d, &m, "snapshot deleted")?;
        ticks(&mut v, &mut m, 3, 140)?;
        let f3 = v.free_blocks();
        ensure!(f3 == f2 + only, "delete gave back {} blocks, the snapshot alone held {}", f3 as i64 - f2 as i64, only);
        check(&mut v, d, &m, "two commits after the delete")?;
        drop(v);
        full_check(d, "after the delete")?;
        Ok(format!("a snapshot costs nothing, the commits after it keep exactly the {} old blocks only it then holds (free {} before); a removed 1 MiB file stays while the snapshot holds it ({} blocks only in the snapshot) and survives filling the volume ({} KiB) and emptying it; delete gives back exactly {} blocks; no reachable block ever free, check 0 errors", held, f0, only, off / 1024, only))
    })();
    block::remove(d);
    r
}

// ---------------- 27. restore ----------------

pub fn t_restore() -> T {
    let d = formatted(512)?;
    let r = (|| -> T {
        let mut v = mount(d)?;
        let mut m = Model::new();
        for (p, n, seed) in [("/a", 9000usize, 1u32), ("/b", 3000, 2)] {
            v.create(p).map_err(|e| format!("{}", e))?;
            write_all(&mut v, p, 0, &pattern(n, seed))?;
            m.insert(p.into(), Some(pattern(n, seed)));
        }
        v.snapshot_create("s1")?;
        let m1 = m.clone();
        write_all(&mut v, "/a", 0, &pattern(9000, 3))?;
        m.insert("/a".into(), Some(pattern(9000, 3)));
        v.remove("/b").map_err(|e| format!("{}", e))?;
        m.remove("/b");
        v.create("/c").map_err(|e| format!("{}", e))?;
        m.insert("/c".into(), Some(Vec::new()));
        v.snapshot_create("s2")?;
        let m2 = m.clone();
        write_all(&mut v, "/a", 0, &pattern(40000, 4))?;
        m.insert("/a".into(), Some(pattern(40000, 4)));
        check(&mut v, d, &m, "before restore")?;

        ensure!(v.snapshot_restore("nope").is_err(), "restore of a missing snapshot");
        let live_only = super::exclusive_blocks(d, 0)?;
        let f0 = v.free_blocks();
        v.snapshot_restore("s1")?;
        check(&mut v, d, &m1, "restored to s1")?;
        ensure!(snap_names(&v) == ["s1", "s2"], "snapshots after restore: {:?}", snap_names(&v));
        {
            let mut s2 = view(d, "s2")?;
            same_as(&mut s2, &m2, "view s2 after restoring s1")?;
        }
        // The old live state stays reserved while the previous superblock reaches it.
        ensure!(v.free_blocks() <= f0, "restore freed blocks the previous superblock still reaches");
        let mut m = m1.clone();
        ticks(&mut v, &mut m, 3, 50)?;
        check(&mut v, d, &m, "writing after restore")?;
        ensure!(v.free_blocks() + 8 >= f0 + live_only, "after restore and two commits only {} of {} blocks of the old live state came back", v.free_blocks() as i64 - f0 as i64, live_only);
        // Restore to the newer snapshot works the same way.
        v.snapshot_restore("s2")?;
        check(&mut v, d, &m2, "restored to s2")?;
        drop(v);
        full_check(d, "after two restores")?;
        Ok(format!("restore to s1: the live tree equals s1 byte for byte, s1 and the newer s2 stay, s2's view unchanged; the old live state ({} blocks of its own) stays reserved while the previous superblock reaches it and comes back two commits later; writing after restore; restore to s2; check 0 errors", live_only))
    })();
    block::remove(d);
    r
}

// ---------------- 28. power loss ----------------

/// Expected state after a snapshot operation: live tree and every snapshot by name.
#[derive(Clone)]
struct State {
    live: Model,
    snaps: BTreeMap<String, Model>,
}

fn verify(base: &Image, blocks: u64, over: BTreeMap<u64, Vec<u8>>, g: u64, before: &State, after: &State, what: &str) -> Result<bool, String> {
    let d = crash::attach(base, blocks, over, None);
    let r = (|| -> Result<bool, String> {
        walk_ok(d, what)?;
        let mut v = mount(d)?;
        ensure!(v.read_only_reason().is_none(), "{}: mounted read-only ({:?})", what, v.read_only_reason());
        let is_after = v.generation() == g + 1;
        ensure!(is_after || v.generation() == g, "{}: generation {} after a crash during commit {}", what, v.generation(), g + 1);
        let st = if is_after { after } else { before };
        same_as(&mut v, &st.live, what)?;
        let names: Vec<String> = st.snaps.keys().cloned().collect();
        ensure!(snap_names(&v) == names, "{}: snapshots {:?}, expected {:?}", what, snap_names(&v), names);
        for (n, sm) in &st.snaps {
            let mut s = view(d, n)?;
            same_as(&mut s, sm, &format!("{} view {}", what, n))?;
        }
        let bad = v.map_violations()?;
        ensure!(bad == 0, "{}: {} reachable blocks free in the allocator", what, bad);
        // Still writable, and the new file keeps every rule.
        let mut m = st.live.clone();
        let data = pattern(3000, 99);
        v.create("/zz").map_err(|e| format!("{}: create: {}", what, e))?;
        v.write("/zz", 0, &data).map_err(|e| format!("{}: write: {}", what, e))?;
        m.insert("/zz".into(), Some(data));
        check(&mut v, d, &m, what)?;
        Ok(is_after)
    })();
    block::remove(d);
    r
}

pub fn t_crash() -> T {
    const BLOCKS: u64 = 128;
    let img = crash::formatted(BLOCKS)?;
    let log = Rc::new(RefCell::new(Log::default()));
    let d = crash::attach(&img, BLOCKS, BTreeMap::new(), Some(log.clone()));
    let r = (|| -> T {
        let mut v = mount(d)?;
        let mut st = State { live: Model::new(), snaps: BTreeMap::new() };
        for (p, n, seed) in [("/a", 5000usize, 1u32), ("/b", 3000, 2)] {
            v.create(p).map_err(|e| format!("{}", e))?;
            write_all(&mut v, p, 0, &pattern(n, seed))?;
            st.live.insert(p.into(), Some(pattern(n, seed)));
        }
        #[derive(Clone, Copy)]
        enum S {
            Create(&'static str),
            Delete(&'static str),
            Restore(&'static str),
            Change,
        }
        let plan = [
            S::Create("s1"),
            S::Change,
            S::Create("s2"),
            S::Create("s3"),
            S::Restore("s1"),
            S::Restore("s2"),
            S::Delete("s1"),
            S::Delete("s3"),
        ];
        let (mut images, mut after_n, mut torn, mut ops) = (0, 0, 0, 0);
        let mut slots: Vec<u64> = Vec::new();
        for step in plan {
            if let S::Change = step {
                // Two unrecorded commits between s1 and s2.
                write_all(&mut v, "/a", 0, &pattern(5000, 7))?;
                st.live.insert("/a".into(), Some(pattern(5000, 7)));
                v.remove("/b").map_err(|e| format!("{}", e))?;
                st.live.remove("/b");
                continue;
            }
            let base = crash::snapshot(d, BLOCKS)?;
            let before = st.clone();
            let g = v.generation();
            {
                let mut l = log.borrow_mut();
                l.ev.clear();
                l.on = true;
            }
            let (res, what) = match step {
                S::Create(n) => (v.snapshot_create(n).map(|_| ()), format!("create {}", n)),
                S::Delete(n) => (v.snapshot_delete(n), format!("delete {}", n)),
                S::Restore(n) => (v.snapshot_restore(n), format!("restore {}", n)),
                S::Change => unreachable!(),
            };
            let ev = {
                let mut l = log.borrow_mut();
                l.on = false;
                core::mem::take(&mut l.ev)
            };
            res.map_err(|e| format!("{}: {}", what, e))?;
            match step {
                S::Create(n) => {
                    st.snaps.insert(n.into(), st.live.clone());
                }
                S::Delete(n) => {
                    st.snaps.remove(n);
                }
                S::Restore(n) => st.live = st.snaps[n].clone(),
                S::Change => {}
            }
            check(&mut v, d, &st.live, &what)?;
            ensure!(snap_names(&v) == st.snaps.keys().cloned().collect::<Vec<_>>(), "{}: snapshots {:?}", what, snap_names(&v));
            // Which superblock slot this commit wrote.
            let sb_block = ev.iter().find_map(|e| match e {
                Ev::Write(lba, _) if crash::is_superblock(*lba) => Some(lba / crash::SECTORS_PER_BLOCK),
                _ => None,
            });
            slots.push(sb_block.unwrap_or(0));
            let sw = crash::sectors(&ev);
            ensure!(!sw.is_empty(), "{}: nothing written", what);
            ops += 1;
            let mut points = vec![0usize];
            for i in 0..sw.len() {
                let end_of_call = i + 1 == sw.len() || sw[i + 1].call != sw[i].call;
                if end_of_call || crash::is_superblock(sw[i].lba) {
                    points.push(i + 1);
                }
                if crash::is_superblock(sw[i].lba) && !end_of_call {
                    torn += 1;
                }
            }
            for p in points {
                let over = crash::build(&base, &sw, |i| i < p);
                let a = verify(&base, BLOCKS, over, g, &before, &st, &format!("{} crashed after {} of {} sectors", what, p, sw.len()))?;
                images += 1;
                after_n += a as usize;
            }
        }
        // Each operation twice in a row: the second wrote the other superblock slot.
        ensure!(slots.len() == 7 && slots[1] != slots[2] && slots[3] != slots[4] && slots[5] != slots[6], "superblock slots per operation {:?} – each pair must hit both", slots);
        drop(v);
        full_check(d, "after the crash sequence")?;
        Ok(format!("{} snapshot operations (create x3, restore x2, delete x2; each kind twice in a row – superblock slots {:?}): crash after every write and inside every superblock sector ({} torn superblocks) = {} images; each mounts read-write with exact counts, the live tree and every snapshot (through its view) of the state before or after ({} after), no reachable block free, still writable", ops, slots, torn, images, after_n))
    })();
    block::remove(d);
    r
}
