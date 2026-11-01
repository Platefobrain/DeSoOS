// DESOFS TEST – writing: format (byte for byte against tests/mkdesofs.py),
// files, directories, rename, a full disk with the reserve, a snapshot that must stay
// untouched, the VFS and programs, and a failing disk (read-only, old or new state).
//
// After every operation the stage-1 walk must accept the volume as read-write with
// exactly the used blocks it counts, and the contents must equal a model kept by the
// test.  Every image is a RAM disk.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::layout::*;
use super::format::{self as fmt, Params};
use super::vol::Volume;
use super::{probe, sha256, State};
use crate::block::{self, BlockDevice, BlockError, RamDisk};
use crate::fs::{FileSystem, FileType, FsError};

pub type T = Result<String, String>;

macro_rules! ensure {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            return Err(format!($($msg)*));
        }
    };
}

const TIME: u64 = 1_700_000_000;

pub(super) fn params() -> Params<'static> {
    Params { uuid: core::array::from_fn(|i| 0xA0 + i as u8), time: TIME, label: "DESOFS-FMT" }
}

fn new_disk(blocks: u64) -> usize {
    block::register(Box::new(RamDisk::new("dsfw", blocks * 8)))
}

fn formatted(blocks: u64) -> Result<usize, String> {
    let d = new_disk(blocks);
    fmt::format(d, &params()).map_err(|e| format!("format: {}", e))?;
    Ok(d)
}

pub(super) fn mount(d: usize) -> Result<Volume, String> {
    Volume::mount(d).map_err(|e| format!("mount: {}", e))
}

/// The stage-1 walk accepts the volume read-write with exact counts.
pub(super) fn walk_ok(d: usize, what: &str) -> Result<(), String> {
    let r = probe(d);
    ensure!(r.state == State::ReadWrite, "{}: walk says {:?}", what, r.state);
    ensure!(r.used_counted == Some(r.used_stored) && r.warnings.is_empty(), "{}: used {:?} vs {} {:?}", what, r.used_counted, r.used_stored, r.warnings);
    Ok(())
}

pub(super) fn pattern(n: usize, seed: u32) -> Vec<u8> {
    (0..n).map(|i| ((i as u32).wrapping_mul(2654435761).wrapping_add(seed) >> 13) as u8).collect()
}

pub(super) fn read_all(v: &mut Volume, path: &str) -> Result<Vec<u8>, String> {
    let m = v.stat(path).map_err(|e| format!("stat {}: {}", path, e))?;
    let mut buf = vec![0u8; m.size as usize];
    let mut done = 0;
    while done < buf.len() {
        let n = v.read(path, done as u64, &mut buf[done..]).map_err(|e| format!("read {}: {}", path, e))?;
        ensure!(n > 0, "read {}: stopped at {}", path, done);
        done += n;
    }
    Ok(buf)
}

fn write_all(v: &mut Volume, path: &str, off: u64, data: &[u8]) -> Result<(), String> {
    for (k, c) in data.chunks(64 * 1024).enumerate() {
        v.write(path, off + (k * 64 * 1024) as u64, c).map_err(|e| format!("write {}: {}", path, e))?;
    }
    Ok(())
}

/// Model: path -> Some(contents) for a file, None for a directory.
pub(super) type Model = BTreeMap<String, Option<Vec<u8>>>;

/// Everything on the volume equals the model (walks every directory).
pub(super) fn same_as(v: &mut Volume, m: &Model, what: &str) -> Result<(), String> {
    let mut seen = 0;
    let mut stack = vec![String::from("/")];
    while let Some(dir) = stack.pop() {
        let list = v.read_dir(&dir).map_err(|e| format!("{}: read_dir {}: {}", what, dir, e))?;
        for e in list {
            let p = if dir == "/" { format!("/{}", e.name) } else { format!("{}/{}", dir, e.name) };
            let want = m.get(&p).ok_or_else(|| format!("{}: {} on the volume, not in the model", what, p))?;
            match (e.kind, want) {
                (FileType::Directory, None) => stack.push(p),
                (FileType::File, Some(data)) => {
                    let got = read_all(v, &p)?;
                    ensure!(e.size == data.len() as u64 && got == *data, "{}: {} differs ({} vs {} bytes)", what, p, got.len(), data.len());
                }
                _ => return Err(format!("{}: {} has the wrong type", what, p)),
            }
            seen += 1;
        }
    }
    ensure!(seen == m.len(), "{}: {} entries on the volume, {} in the model", what, seen, m.len());
    Ok(())
}

pub(super) fn check(v: &mut Volume, d: usize, m: &Model, what: &str) -> Result<(), String> {
    walk_ok(d, what)?;
    let bad = v.map_violations()?;
    ensure!(bad == 0, "{}: {} blocks reachable from a superblock are free in the allocator", what, bad);
    same_as(v, m, what)?;
    ensure!(v.counters.max_over == 0, "{}: an operation allocated more than its own bound ({} over)", what, v.counters.max_over);
    Ok(())
}

// ---------------- 8. format ----------------

pub fn t_format() -> T {
    let want = crate::initrd::DESOFS_FMT;
    ensure!(want.len() == 64 * BLOCK, "format image from mkdesofs.py missing");
    let d = formatted(64)?;
    let mut got = vec![0u8; 64 * BLOCK];
    let _ = block::read(d, 0, &mut got);
    let diff = (0..64).find(|&b| got[b * BLOCK..(b + 1) * BLOCK] != want[b * BLOCK..(b + 1) * BLOCK]);
    let r = probe(d);
    block::remove(d);
    ensure!(diff.is_none(), "kernel format differs from tests/mkdesofs.py --format in block {:?}", diff);
    ensure!(r.state == State::ReadWrite && r.generation == 1 && r.next_slot == 2 && r.nodes == 1 && r.used_counted == Some(3), "formatted volume: {:?} g_before {} next {} nodes {} used {:?}", r.state, r.generation, r.next_slot, r.nodes, r.used_counted);
    // A whole disk with an MBR partition table is refused; a FAT boot sector is not one.
    let d = new_disk(64);
    let mut s0 = vec![0u8; 512];
    s0[510] = 0x55;
    s0[511] = 0xAA;
    s0[446 + 4] = 0x83;
    s0[446 + 12] = 64;
    let _ = block::write(d, 0, &s0);
    let refused = fmt::format(d, &params());
    s0[0] = 0xEB;
    let _ = block::write(d, 0, &s0);
    let fat_ok = fmt::format(d, &params());
    block::remove(d);
    ensure!(matches!(&refused, Err(e) if e.contains("partition table")), "MBR disk: {:?}", refused);
    ensure!(fat_ok.is_ok(), "over a FAT boot sector: {:?}", fat_ok);
    let small = new_disk(63);
    let r2 = fmt::format(small, &params());
    block::remove(small);
    ensure!(r2.is_err(), "63-block disk formatted");
    Ok(String::from("kernel format = tests/mkdesofs.py --format byte for byte (both superblocks, DSRT, DSPT, DSND with node 1); generation 1, next commit to B; a whole disk with a partition table refused, over a FAT boot sector allowed, under 64 blocks refused"))
}

// ---------------- 9. files ----------------

pub fn t_files() -> T {
    let d = formatted(2048)?;
    let r = (|| -> T {
        let mut v = mount(d)?;
        let mut m = Model::new();
        let g0 = v.generation();
        v.create("/a.txt").map_err(|e| format!("create: {}", e))?;
        m.insert("/a.txt".into(), Some(Vec::new()));
        check(&mut v, d, &m, "empty file")?;
        ensure!(v.generation() == g0 + 1, "one operation, one commit: generation {} -> {}", g0, v.generation());
        write_all(&mut v, "/a.txt", 0, b"hello")?;
        m.insert("/a.txt".into(), Some(b"hello".to_vec()));
        check(&mut v, d, &m, "small write")?;
        // A hole: write past the end.
        write_all(&mut v, "/a.txt", 10_000, b"tail")?;
        let mut a = b"hello".to_vec();
        a.resize(10_000, 0);
        a.extend_from_slice(b"tail");
        m.insert("/a.txt".into(), Some(a.clone()));
        check(&mut v, d, &m, "write past the end (hole)")?;
        // 1 MiB: depth 0 -> 2.
        v.create("/big").map_err(|e| format!("create big: {}", e))?;
        let big = pattern(1 << 20, 7);
        write_all(&mut v, "/big", 0, &big)?;
        m.insert("/big".into(), Some(big.clone()));
        check(&mut v, d, &m, "1 MiB file (depth 2)")?;
        // Overwrite the middle across a block edge.
        let mid = pattern(9000, 99);
        write_all(&mut v, "/big", 300_000, &mid)?;
        let mut b2 = big.clone();
        b2[300_000..309_000].copy_from_slice(&mid);
        m.insert("/big".into(), Some(b2.clone()));
        check(&mut v, d, &m, "overwrite in the middle")?;
        // Truncate down: depth 2 -> 1 -> 0, a tail inside a block, then grow (zeros).
        for (size, what) in [(200 * 1024, "truncate to 200 KiB (depth 1)"), (10 * 1024, "truncate to 10 KiB (depth 0)"), (5000, "truncate to 5000 B")] {
            v.truncate("/big", size as u64).map_err(|e| format!("{}: {}", what, e))?;
            b2.truncate(size);
            m.insert("/big".into(), Some(b2.clone()));
            check(&mut v, d, &m, what)?;
        }
        v.truncate("/big", 9000).map_err(|e| format!("grow: {}", e))?;
        b2.resize(9000, 0);
        m.insert("/big".into(), Some(b2.clone()));
        check(&mut v, d, &m, "grow by truncate (zeros)")?;
        v.truncate("/big", 0).map_err(|e| format!("to 0: {}", e))?;
        m.insert("/big".into(), Some(Vec::new()));
        check(&mut v, d, &m, "truncate to 0")?;
        // Remount: everything is on the disk.
        let g_before = v.generation();
        drop(v);
        let mut v = mount(d)?;
        ensure!(v.generation() == g_before, "remount: generation {} -> {}", g_before, v.generation());
        check(&mut v, d, &m, "after remount")?;
        v.remove("/a.txt").map_err(|e| format!("remove: {}", e))?;
        m.remove("/a.txt");
        check(&mut v, d, &m, "remove")?;
        ensure!(matches!(v.read("/a.txt", 0, &mut [0u8; 4]), Err(FsError::NotFound)), "removed file still readable");
        Ok(format!("create, write, hole, 1 MiB (depth 0 -> 2), overwrite across blocks, truncate 2 -> 1 -> 0 and a partial block, grow with zeros, remount, remove; generation {}, every state accepted by the walk", v.generation()))
    })();
    block::remove(d);
    r
}

// ---------------- 10. directories ----------------

pub fn t_dirs() -> T {
    let d = formatted(4096)?;
    let r = (|| -> T {
        let mut v = mount(d)?;
        let mut m = Model::new();
        for p in ["/d", "/d/e"] {
            v.mkdir(p).map_err(|e| format!("mkdir {}: {}", p, e))?;
            m.insert(p.into(), None);
        }
        for i in 0..300 {
            let p = format!("/d/f{:03}", i);
            v.create(&p).map_err(|e| format!("create {}: {}", p, e))?;
            let data = format!("file {}", i).into_bytes();
            write_all(&mut v, &p, 0, &data)?;
            m.insert(p, Some(data));
        }
        check(&mut v, d, &m, "300 files in a directory")?;
        let blocks = v.stat("/d").map_err(|e| format!("{}", e))?.size / BLOCK as u64;
        ensure!(blocks >= 2, "300 entries in only {} directory block", blocks);
        for i in (0..300).step_by(3) {
            let p = format!("/d/f{:03}", i);
            v.remove(&p).map_err(|e| format!("remove {}: {}", p, e))?;
            m.remove(&p);
        }
        check(&mut v, d, &m, "every third removed")?;
        for i in 0..50 {
            let p = format!("/d/new-name-{:02}", i);
            v.create(&p).map_err(|e| format!("create {}: {}", p, e))?;
            m.insert(p, Some(Vec::new()));
        }
        check(&mut v, d, &m, "50 new files in the freed places")?;
        let after = v.stat("/d").map_err(|e| format!("{}", e))?.size / BLOCK as u64;
        ensure!(after == blocks, "directory grew from {} to {} blocks instead of reusing entries", blocks, after);
        ensure!(matches!(v.remove("/d"), Err(FsError::NotEmpty)), "non-empty directory removed");
        ensure!(matches!(v.create("/d/f001"), Err(FsError::AlreadyExists)), "duplicate name created");
        ensure!(matches!(v.create("/nope/x"), Err(FsError::NotFound)), "file in a missing directory");
        ensure!(matches!(v.create("/d/f001/x"), Err(FsError::NotADirectory)), "file under a file");
        for bad in ["/d/.", "/d/..", "/d/a\0b"] {
            ensure!(matches!(v.create(bad), Err(FsError::InvalidName) | Err(FsError::AlreadyExists) | Err(FsError::NotFound)), "name {:?} accepted", bad);
        }
        let long: String = core::iter::repeat('x').take(256).collect();
        ensure!(matches!(v.create(&format!("/d/{}", long)), Err(FsError::InvalidName)), "256-byte name accepted");
        let ok255: String = core::iter::repeat('y').take(255).collect();
        v.create(&format!("/d/{}", ok255)).map_err(|e| format!("255-byte name: {}", e))?;
        m.insert(format!("/d/{}", ok255), Some(Vec::new()));
        v.remove("/d/e").map_err(|e| format!("rmdir empty: {}", e))?;
        m.remove("/d/e");
        ensure!(matches!(v.remove("/"), Err(FsError::Busy)), "root removed");
        check(&mut v, d, &m, "after the refusals")?;
        Ok(String::from("300 files (more than one directory block), every third removed, 50 new reuse the freed entries (no growth); refusals: non-empty rmdir, duplicate, missing parent, file as directory, . / .. / NUL, 256-byte name (255 fine), removing /"))
    })();
    block::remove(d);
    r
}

// ---------------- 11. rename ----------------

pub fn t_rename() -> T {
    let d = formatted(2048)?;
    let r = (|| -> T {
        let mut v = mount(d)?;
        let mut m = Model::new();
        for p in ["/a", "/b", "/a/sub", "/empty"] {
            v.mkdir(p).map_err(|e| format!("mkdir {}: {}", p, e))?;
            m.insert(p.into(), None);
        }
        for (p, s) in [("/a/x", 1), ("/a/y", 2), ("/b/z", 3)] {
            v.create(p).map_err(|e| format!("{}", e))?;
            let data = pattern(5000 + s * 100, s as u32);
            write_all(&mut v, p, 0, &data)?;
            m.insert(p.into(), Some(data));
        }
        let mv = |v: &mut Volume, m: &mut Model, from: &str, to: &str| -> Result<(), String> {
            v.rename(from, to).map_err(|e| format!("rename {} -> {}: {}", from, to, e))?;
            let keys: Vec<String> = m.keys().filter(|k| *k == from || k.starts_with(&format!("{}/", from))).cloned().collect();
            for k in keys {
                let val = m.remove(&k).unwrap();
                m.insert(format!("{}{}", to, &k[from.len()..]), val);
            }
            Ok(())
        };
        mv(&mut v, &mut m, "/a/x", "/a/x2")?;
        check(&mut v, d, &m, "rename in a directory")?;
        mv(&mut v, &mut m, "/a/x2", "/b/x3")?;
        check(&mut v, d, &m, "move to another directory")?;
        // Replace an existing file (atomic): /b/z's node goes, /b/x3 takes its name.
        mv(&mut v, &mut m, "/b/x3", "/b/z")?;
        check(&mut v, d, &m, "replace an existing file")?;
        // A directory with contents moves; then onto an empty directory.
        mv(&mut v, &mut m, "/a/sub", "/b/sub")?;
        mv(&mut v, &mut m, "/a", "/empty")?;
        check(&mut v, d, &m, "directory onto an empty directory")?;
        // Refusals.
        ensure!(matches!(v.rename("/empty", "/empty/y2"), Err(FsError::InvalidName)), "directory moved into itself");
        ensure!(matches!(v.rename("/b", "/b/sub/deeper"), Err(FsError::InvalidName)), "directory moved below itself");
        ensure!(matches!(v.rename("/empty/y", "/b"), Err(FsError::IsADirectory)), "file onto a directory");
        ensure!(matches!(v.rename("/b/sub", "/b/z"), Err(FsError::NotADirectory)), "directory onto a file");
        ensure!(matches!(v.rename("/b", "/empty"), Err(FsError::NotEmpty)), "directory onto a non-empty directory");
        ensure!(matches!(v.rename("/", "/q"), Err(FsError::Busy)), "root renamed");
        ensure!(matches!(v.rename("/missing", "/q"), Err(FsError::NotFound)), "missing source");
        let g = v.generation();
        v.rename("/b/z", "/b/z").map_err(|e| format!("rename onto itself: {}", e))?;
        ensure!(v.generation() == g + 1 || v.generation() == g, "self rename");
        check(&mut v, d, &m, "after the refusals")?;
        drop(v);
        let mut v = mount(d)?;
        check(&mut v, d, &m, "after remount")?;
        Ok(String::from("rename in a directory, move between directories, atomic replace of a file, a directory with contents, a directory onto an empty one; refusals: into itself / below itself, file onto directory, directory onto file, onto a non-empty directory, root, missing source; onto itself is a no-op"))
    })();
    block::remove(d);
    r
}

// ---------------- 12. full disk ----------------

pub fn t_full() -> T {
    let d = formatted(256)?;
    let r = (|| -> T {
        let mut v = mount(d)?;
        let mut m = Model::new();
        let reserve = v.reserve();
        let chunk = pattern(16 * 1024, 5);
        let mut n = 0;
        loop {
            let p = format!("/f{}", n);
            match v.create(&p) {
                Ok(()) => {}
                Err(FsError::NoSpace) => break,
                Err(e) => return Err(format!("create {}: {}", p, e)),
            }
            m.insert(p.clone(), Some(Vec::new()));
            match v.write(&p, 0, &chunk) {
                Ok(_) => {
                    m.insert(p, Some(chunk.clone()));
                }
                Err(FsError::NoSpace) => break,
                Err(e) => return Err(format!("write {}: {}", p, e)),
            }
            n += 1;
            ensure!(n < 1000, "the disk never filled");
        }
        check(&mut v, d, &m, "full disk")?;
        let free = v.free_blocks();
        ensure!(free >= 1, "nothing left for the reserve ({} free)", free);
        // Operations that free space still work in the reserve.
        let first = String::from("/f0");
        v.truncate(&first, 100).map_err(|e| format!("truncate on a full disk: {}", e))?;
        if let Some(Some(dt)) = m.get_mut(&first) {
            dt.truncate(100);
        }
        v.rename("/f1", "/renamed").map_err(|e| format!("rename on a full disk: {}", e))?;
        let val = m.remove("/f1").unwrap();
        m.insert("/renamed".into(), val);
        for k in 2..n.min(6) {
            let p = format!("/f{}", k);
            v.remove(&p).map_err(|e| format!("remove {} on a full disk: {}", p, e))?;
            m.remove(&p);
        }
        check(&mut v, d, &m, "after freeing")?;
        // Space came back (the blocks dropped by the last commit free after the next one).
        v.create("/again").map_err(|e| format!("create after freeing: {}", e))?;
        m.insert("/again".into(), Some(Vec::new()));
        v.write("/again", 0, &chunk[..4096]).map_err(|e| format!("write after freeing: {}", e))?;
        m.insert("/again".into(), Some(chunk[..4096].to_vec()));
        check(&mut v, d, &m, "writing again")?;
        Ok(format!("256-block volume filled ({} files of 16 KiB) -> no space before the reserve of {} blocks; truncate, rename and remove still work; space comes back; no operation allocated more than its precomputed bound", n, reserve))
    })();
    block::remove(d);
    r
}

// ---------------- 13. a snapshot stays untouched ----------------

/// Every block reachable from root entry `entry` of the root block `rt` (addr -> bytes hash).
pub(super) fn snapshot_blocks(d: usize, rt: u64, entry: usize) -> BTreeMap<u64, [u8; 32]> {
    let mut out = BTreeMap::new();
    let rd = |a: u64| {
        let mut b = vec![0u8; BLOCK];
        let _ = block::read(d, a * 8, &mut b);
        b
    };
    let r = rd(rt);
    let nt = u64_at(&r, HDR_SIZE + entry * ROOT_ENTRY);
    let mut stack = vec![nt];
    while let Some(a) = stack.pop() {
        if a == 0 || out.contains_key(&a) {
            continue;
        }
        let b = rd(a);
        out.insert(a, sha256(&b));
        if &b[0..4] == KIND_DSPT {
            for i in 0..FANOUT {
                stack.push(u64_at(&b, HDR_SIZE + i * PTR_SIZE));
            }
        } else if &b[0..4] == KIND_DSND {
            for s in 0..NODES_PER_BLOCK as usize {
                let o = HDR_SIZE + s * NODE_SIZE;
                if b[o + 8] == 0 {
                    continue;
                }
                let k = if b[o + 9] == 0 { 4 } else { 1 };
                for j in 0..k {
                    stack.push(u64_at(&b, o + 56 + j * PTR_SIZE));
                }
            }
        }
    }
    out
}

/// The live tree of the reference image from tests/mkdesofs.py.
pub(super) fn ref_model() -> Model {
    let mut m = Model::new();
    m.insert("/hello.txt".into(), Some(b"Hello DeSoFS v5\n".to_vec()));
    let mut big = Vec::new();
    for k in 0..25u32 {
        if (5..=9).contains(&k) {
            big.extend_from_slice(&[0u8; BLOCK]);
        } else {
            big.extend((0..BLOCK as u32).map(|i| ((k * 31 + i * 7) & 0xFF) as u8));
        }
    }
    m.insert("/big.bin".into(), Some(big));
    m.insert("/sub".into(), None);
    m.insert("/sub/a.txt".into(), Some(b"abc\n".to_vec()));
    m
}

pub fn t_snapshot() -> T {
    let img = crate::initrd::DESOFS_REF;
    let d = new_disk((img.len() / BLOCK) as u64);
    let _ = block::write(d, 0, img);
    let r = (|| -> T {
        let rt5 = u64_at(&img[2 * BLOCK..], 80);
        let snap = snapshot_blocks(d, rt5, 1);
        ensure!(snap.len() >= 10, "snapshot has only {} blocks", snap.len());
        let unchanged = |what: &str| -> Result<(), String> {
            for (&a, h) in &snap {
                let mut b = vec![0u8; BLOCK];
                let _ = block::read(d, a * 8, &mut b);
                ensure!(&sha256(&b) == h, "{}: snapshot block {} overwritten", what, a);
            }
            Ok(())
        };
        let mut v = mount(d)?;
        let mut m = ref_model();
        check(&mut v, d, &m, "reference image mounted")?;
        write_all(&mut v, "/hello.txt", 0, b"Rewritten!")?;
        let mut x = b"Hello DeSoFS v5\n".to_vec();
        x[..10].copy_from_slice(b"Rewritten!");
        m.insert("/hello.txt".into(), Some(x));
        check(&mut v, d, &m, "rewrite a file the snapshot also has")?;
        unchanged("after a rewrite")?;
        v.remove("/big.bin").map_err(|e| format!("remove: {}", e))?;
        m.remove("/big.bin");
        check(&mut v, d, &m, "remove a file the snapshot also has")?;
        unchanged("after a remove")?;
        for i in 0..20 {
            let p = format!("/n{}", i);
            if v.create(&p).is_err() {
                break;
            }
            m.insert(p.clone(), Some(Vec::new()));
            let data = pattern(6000, i);
            if v.write(&p, 0, &data).is_err() {
                break;
            }
            m.insert(p, Some(data));
            unchanged("while filling")?;
        }
        v.rename("/sub/a.txt", "/moved").map_err(|e| format!("rename: {}", e))?;
        let val = m.remove("/sub/a.txt").unwrap();
        m.insert("/moved".into(), val);
        check(&mut v, d, &m, "filled up and renamed")?;
        unchanged("at the end")?;
        Ok(format!("reference image (snapshot of {} blocks) mounted read-write; rewrite, remove, fill up, rename – no snapshot block ever overwritten, the walk accepts every state", snap.len()))
    })();
    block::remove(d);
    r
}

// ---------------- 14. VFS, programs, a failing disk ----------------

static FAIL_AT: AtomicU64 = AtomicU64::new(0);
static WRITES: AtomicU64 = AtomicU64::new(0);

/// A RAM disk whose N-th write (or a flush after it) fails.
struct FailDisk {
    inner: RamDisk,
}

impl BlockDevice for FailDisk {
    fn name(&self) -> &str {
        "fail"
    }
    fn description(&self) -> String {
        String::from("failing RAM disk")
    }
    fn sector_count(&self) -> u64 {
        self.inner.sector_count()
    }
    fn read_only(&self) -> bool {
        false
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.inner.read(lba, buf)
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        let n = WRITES.fetch_add(1, Ordering::SeqCst) + 1;
        let at = FAIL_AT.load(Ordering::SeqCst);
        if at != 0 && n >= at {
            return Err(BlockError::Io);
        }
        self.inner.write(lba, buf)
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        let at = FAIL_AT.load(Ordering::SeqCst);
        if at != 0 && WRITES.load(Ordering::SeqCst) >= at {
            return Err(BlockError::Io);
        }
        Ok(())
    }
}

pub fn t_vfs() -> T {
    // Through the VFS: write, read, rename, a program reading the file.
    let d = formatted(1024)?;
    let r = (|| -> T {
        let v = mount(d)?;
        let _ = crate::fs::mkdir("/dsfs-test");
        crate::fs::mount("/dsfs-test", Box::new(crate::fs::Locked::new(v))).map_err(|e| format!("mount: {}", e))?;
        let data = pattern(100_000, 3);
        crate::fs::write_file("/dsfs-test/data.bin", &data).map_err(|e| format!("write_file: {}", e))?;
        crate::fs::rename("/dsfs-test/data.bin", "/dsfs-test/moved.bin").map_err(|e| format!("rename: {}", e))?;
        let back = crate::fs::read_file("/dsfs-test/moved.bin").map_err(|e| format!("read_file: {}", e))?;
        ensure!(back == data, "read back differs");
        ensure!(matches!(crate::fs::rename("/dsfs-test/moved.bin", "/tmp/x"), Err(FsError::Unsupported)), "rename across file systems");
        ensure!(matches!(crate::fs::rename("/dsfs-test", "/elsewhere"), Err(FsError::Busy)), "mount point renamed");
        let names: Vec<String> = crate::fs::read_dir("/dsfs-test").map_err(|e| format!("{}", e))?.into_iter().map(|e| e.name).collect();
        ensure!(names == ["moved.bin"], "listing {:?}", names);
        // A program (ring 3, syscalls) reads the file from DeSoFS.
        let opts = crate::user::SpawnOptions { stdin: Some(Vec::new()), capture: true, ..crate::user::SpawnOptions::default() };
        let id = crate::user::exec("/bin/sha256sum", &["sha256sum", "/dsfs-test/moved.bin"], "/", &opts).map_err(|_| String::from("exec sha256sum"))?;
        let end = crate::time::ticks() + 30_000;
        while crate::sched::task_info(id).is_some() && crate::time::ticks() < end {
            crate::time::sleep_ms(2);
        }
        let out = String::from_utf8_lossy(&crate::user::captured_output(id).unwrap_or_default()).into_owned();
        let mut s = String::new();
        for b in sha256(&data) {
            s.push_str(&format!("{:02x}", b));
        }
        ensure!(out.starts_with(&s), "sha256sum on DeSoFS: {:?} (expected {})", out.trim(), s);
        crate::fs::remove("/dsfs-test/moved.bin").map_err(|e| format!("remove: {}", e))?;
        crate::fs::unmount("/dsfs-test").map_err(|e| format!("unmount: {}", e))?;
        let _ = crate::fs::remove("/dsfs-test");
        walk_ok(d, "after the VFS test")?;
        Ok(String::from("mounted through the VFS: write_file, rename, read_file, listing; rename across file systems -> unsupported, a mount point -> busy; /bin/sha256sum (ring 3) reads the file from DeSoFS with the right sum"))
    })();
    block::remove(d);
    let first = r?;

    // A failing disk: every write position of one operation – the operation fails, the
    // volume becomes read-only, a remount shows the old or the new state.
    let blocks = 512u64;
    let mut cases = 0;
    for fail_at in 1..=12u64 {
        FAIL_AT.store(0, Ordering::SeqCst);
        WRITES.store(0, Ordering::SeqCst);
        let d = block::register(Box::new(FailDisk { inner: RamDisk::new("fail", blocks * 8) }));
        let res = (|| -> Result<bool, String> {
            fmt::format(d, &params()).map_err(|e| format!("format: {}", e))?;
            let mut v = mount(d)?;
            v.create("/f").map_err(|e| format!("{}", e))?;
            v.write("/f", 0, b"old").map_err(|e| format!("{}", e))?;
            let base = WRITES.load(Ordering::SeqCst);
            FAIL_AT.store(base + fail_at, Ordering::SeqCst);
            let w = v.write("/f", 0, b"new");
            let failed = w.is_err();
            if failed {
                ensure!(v.read_only_reason().is_some(), "write failed but the volume is still writable");
                ensure!(matches!(v.create("/g"), Err(FsError::ReadOnly)), "read-only volume took a create");
            }
            FAIL_AT.store(0, Ordering::SeqCst);
            drop(v);
            let mut v = mount(d)?;
            let got = read_all(&mut v, "/f")?;
            ensure!(got == b"old" || got == b"new", "after a failure at write {}: {:?}", fail_at, got);
            walk_ok(d, "after a failed write")?;
            Ok(failed)
        })();
        block::remove(d);
        FAIL_AT.store(0, Ordering::SeqCst);
        let failed = res?;
        cases += 1;
        if !failed {
            break; // the operation needed fewer writes than fail_at
        }
    }
    Ok(format!("{}; failing disk at each of {} write positions of one operation: the operation fails, the volume turns read-only, a remount shows the old or the new state, never a mix", first, cases))
}
