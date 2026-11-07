// DESOFS TEST 29–32 – the block cache (cache.rs): hits without reading the disk, an
// address used again for other contents (the old copy never comes back), the global limit
// (frames + index) and its return at unmount, nothing from a failed commit, a damaged
// cached copy caught by the SHA-256 on the hit.  Every image is a RAM disk.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

use super::cache;
use super::probe;
use super::test_write::{formatted, mount, params, pattern, read_all, write_all, T};
use crate::block::{self, BlockDevice, BlockError, RamDisk};
use crate::fs::FileSystem;

macro_rules! ensure {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            return Err(format!($($msg)*));
        }
    };
}

/// 29: hits.  A fresh mount starts empty; the first read of a file reads the disk, the
/// second reads nothing; a block a commit wrote serves the next read straight away.
pub fn t_hits() -> T {
    let d = formatted(1024)?;
    let data = pattern(40 * 1024, 29);
    {
        let mut v = mount(d)?;
        v.mkdir("/dir").map_err(|e| format!("mkdir: {}", e))?;
        v.create("/dir/f").map_err(|e| format!("create: {}", e))?;
        write_all(&mut v, "/dir/f", 0, &data)?;
    }
    let mut v = mount(d)?;
    ensure!(v.cache.len() == 0 && v.cache.held() == 0, "a fresh mount holds {} blocks / {} B", v.cache.len(), v.cache.held());
    let r0 = v.prof.blk_reads;
    ensure!(read_all(&mut v, "/dir/f")? == data, "first read differs");
    let (r1, h1) = (v.prof.blk_reads, v.cache.stats.hits);
    ensure!(r1 > r0, "the first read read no block from the disk");
    ensure!(read_all(&mut v, "/dir/f")? == data, "second read differs");
    let (r2, h2) = (v.prof.blk_reads, v.cache.stats.hits);
    ensure!(r2 == r1 && h2 > h1, "second read: {} disk reads (want 0), {} hits", r2 - r1, h2 - h1);
    // A commit's blocks serve the next read (after its second flush).
    let more = pattern(8 * 1024, 30);
    write_all(&mut v, "/dir/f", 0, &more)?;
    ensure!(v.cache.stats.commit_inserts > 0, "the commit put nothing into the cache");
    let r3 = v.prof.blk_reads;
    let mut want = data.clone();
    want[..more.len()].copy_from_slice(&more);
    ensure!(read_all(&mut v, "/dir/f")? == want, "read after the write differs");
    ensure!(v.prof.blk_reads == r3, "read after the write read {} blocks from the disk", v.prof.blk_reads - r3);
    Ok(format!("first read {} blocks from the disk, the second 0 ({} hits); a write's blocks served the next read from the cache", r1 - r0, h2 - h1))
}

/// 30: an address used again.  (a) The key: a block cached under one checksum is not
/// found under another – the entry is dropped as stale and not found again under the old
/// one either.  (b) On a small volume files are deleted and written again with other
/// contents until blocks come back at addresses the cache holds: every read equals the new
/// contents, no stale copy ever reaches the SHA-256 check (`bad` stays 0).
pub fn t_reuse() -> T {
    // (a) the key, on its own.
    let mut c = cache::BlockCache::new();
    let (a, b) = (pattern(4096, 301), pattern(4096, 302));
    let (sa, sb) = (super::sha256(&a), super::sha256(&b));
    let mut out = alloc::vec![0u8; 4096];
    c.insert(500, &sa, &a, true, false);
    ensure!(c.get(500, &sa, &mut out) && out == a, "a block is not found under its own checksum");
    ensure!(!c.get(500, &sb, &mut out), "a block was found under another checksum");
    ensure!(c.stats.stale == 1 && !c.holds(500), "the stale entry was not dropped");
    ensure!(!c.get(500, &sa, &mut out), "the dropped entry came back");
    c.insert(500, &sa, &a, true, false);
    c.insert(500, &sb, &b, true, false);
    ensure!(c.stats.replaced == 1 && c.get(500, &sb, &mut out) && out == b && !c.get(500, &sa, &mut out), "a new block at the same address did not replace the old one");
    drop(c);
    // (b) on a volume.
    let d = formatted(128)?;
    let mut v = mount(d)?;
    let mut rounds = 0;
    for r in 0..60u32 {
        let name = format!("/f{}", r % 3);
        let _ = v.remove(&name);
        v.create(&name).map_err(|e| format!("create {}: {}", name, e))?;
        let data = pattern(12 * 1024 + r as usize * 100, 1000 + r);
        write_all(&mut v, &name, 0, &data)?;
        ensure!(read_all(&mut v, &name)? == data, "round {}: {} differs", r, name);
        rounds += 1;
        if v.cache.stats.replaced + v.cache.stats.stale >= 20 {
            break;
        }
    }
    let again = v.cache.stats.replaced + v.cache.stats.stale;
    ensure!(again > 0, "no address was used again with other contents in {} rounds", rounds);
    ensure!(v.cache.stats.bad == 0, "{} stale copies reached the SHA-256 check (the key must catch them)", v.cache.stats.bad);
    Ok(format!("the key: another checksum = not found, the entry dropped; {} rounds on 128 blocks: {} addresses used again for other contents, every read right, 0 failed checks", rounds, again))
}

/// Resets the test limit even when the test fails half-way.
struct LimitGuard;
impl Drop for LimitGuard {
    fn drop(&mut self) {
        cache::set_test_limit(0);
    }
}

/// 31: the global limit.  With a 300 KiB limit a 1 MiB file is written and read twice:
/// the caches never hold more (frames and index together), the reads are right, and
/// unmounting gives every byte back.
pub fn t_limit() -> T {
    let d = formatted(2048)?;
    let used0 = cache::used();
    let lim = used0 + 300 * 1024;
    let _g = LimitGuard;
    cache::set_test_limit(lim);
    let data = pattern(1024 * 1024, 31);
    let mut peak = 0;
    {
        let mut v = mount(d)?;
        v.create("/big").map_err(|e| format!("create: {}", e))?;
        for (k, c) in data.chunks(64 * 1024).enumerate() {
            v.write("/big", (k * 64 * 1024) as u64, c).map_err(|e| format!("write: {}", e))?;
            peak = peak.max(cache::used());
            ensure!(cache::used() <= lim, "after write {}: {} B held, limit {}", k, cache::used(), lim);
        }
        for pass in 0..2 {
            ensure!(read_all(&mut v, "/big")? == data, "pass {}: the file differs", pass);
            peak = peak.max(cache::used());
            ensure!(cache::used() <= lim, "after read {}: {} B held, limit {}", pass, cache::used(), lim);
        }
        ensure!(v.cache.stats.evictions > 0, "1 MiB through a 300 KiB cache replaced nothing");
        ensure!(v.cache.held() == cache::used() - used0, "the volume holds {} B, the budget says {}", v.cache.held(), cache::used() - used0);
    }
    ensure!(cache::used() == used0, "after unmount {} B still held (was {})", cache::used(), used0);
    Ok(format!("1 MiB through a {} KiB limit: at most {} KiB held (frames + index), replaced blocks, every byte back at unmount", (lim - used0) / 1024, (peak - used0) / 1024))
}

static FLUSHES: AtomicU64 = AtomicU64::new(0);
static FAIL_FLUSH: AtomicU64 = AtomicU64::new(0);

/// A RAM disk whose N-th flush fails (counted from the start).
struct FlushFail {
    inner: RamDisk,
}

impl BlockDevice for FlushFail {
    fn name(&self) -> &str {
        "flushfail"
    }
    fn description(&self) -> String {
        String::from("RAM disk with a failing flush")
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
        self.inner.write(lba, buf)
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        let n = FLUSHES.fetch_add(1, Ordering::SeqCst) + 1;
        if n == FAIL_FLUSH.load(Ordering::SeqCst) {
            return Err(BlockError::Io);
        }
        Ok(())
    }
}

/// 32: nothing uncommitted, a damaged copy caught.  (a) A commit whose first or second
/// flush fails puts nothing into the cache (the volume turns read-only as before).
/// (b) Every cached copy of a file damaged in memory: the next read still returns the
/// right contents – each hit fails its SHA-256, is dropped and read from the disk.
pub fn t_safety() -> T {
    let mut flushes = [0u64; 2];
    for (k, which) in [1u64, 2].iter().enumerate() {
        FAIL_FLUSH.store(0, Ordering::SeqCst);
        let d = block::register(Box::new(FlushFail { inner: RamDisk::new("flushfail", 512 * 8) }));
        super::format::format(d, &params()).map_err(|e| format!("format: {}", e))?;
        let mut v = mount(d)?;
        v.create("/f").map_err(|e| format!("create: {}", e))?;
        write_all(&mut v, "/f", 0, &pattern(8 * 1024, 32))?;
        let before = v.cache.stats.commit_inserts;
        FAIL_FLUSH.store(FLUSHES.load(Ordering::SeqCst) + which, Ordering::SeqCst);
        let r = v.write("/f", 0, &pattern(8 * 1024, 33));
        FAIL_FLUSH.store(0, Ordering::SeqCst);
        ensure!(r.is_err(), "the write with flush {} failing succeeded", which);
        ensure!(v.read_only_reason().is_some(), "flush {} failed but the volume stayed writable", which);
        ensure!(v.cache.stats.commit_inserts == before, "flush {} failed but {} blocks of that commit entered the cache", which, v.cache.stats.commit_inserts - before);
        flushes[k] = *which;
    }
    // (b) damaged copies.
    let d = formatted(1024)?;
    let data = pattern(64 * 1024, 34);
    {
        let mut v = mount(d)?;
        v.create("/g").map_err(|e| format!("create: {}", e))?;
        write_all(&mut v, "/g", 0, &data)?;
    }
    let mut v = mount(d)?;
    ensure!(read_all(&mut v, "/g")? == data, "first read differs");
    let total = probe(d).total_blocks;
    let mut damaged = 0;
    for a in 0..total {
        if v.cache.damage(a) {
            damaged += 1;
        }
    }
    ensure!(damaged > 0, "nothing was cached to damage");
    let r0 = v.prof.blk_reads;
    ensure!(read_all(&mut v, "/g")? == data, "a damaged cached copy was returned");
    ensure!(v.cache.stats.bad > 0, "no hit noticed the damage");
    ensure!(v.read_only_reason().is_none(), "the volume turned read-only because of a damaged cache copy (the disk is fine)");
    Ok(format!("a failing flush {} / {}: nothing of that commit cached; {} cached copies damaged: {} caught by the SHA-256 on the hit, read again from the disk ({} blocks), contents right", flushes[0], flushes[1], damaged, v.cache.stats.bad, v.prof.blk_reads - r0))
}
