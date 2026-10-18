// FAT32 – reading and writing, long names (VFAT/LFN), formatting.
//
// FAT32 disk layout (512 B sectors, from the start of the partition):
//
//   [0] boot sector with BPB (params)   [1] FSInfo (free-cluster count)
//   [6] boot sector backup              ... reserved sectors
//   FAT #1, FAT #2                      table: cluster -> next cluster
//   data area                           clusters 2, 3, 4, ... (directories and files)
//
// File/directory = chain of clusters in the FAT (0 = free, >= 0x0FFFFFF8 = end).
// Directory = array of 32 B entries.  A long name is several LFN entries
// (13 UTF-16 characters each) right before the regular 8.3 entry with a checksum.
//
// Supported: a disk without a partition table ("superfloppy") or the first
// FAT32 partition from the MBR.  GPT, FAT12/16 and non-512 B sectors – later.
//
// Buffering: FAT sectors in a small cache (written back at the end of each operation
// and on sync), file and directory data written immediately.
//
// Faster reads (USB flash drive, every request is a SCSI command):
// * the FAT is read in blocks of 8 sectors (4 KiB = 1024 entries), not one at a time,
// * cluster cache (directories, file tails; write-through – always
//   consistent with the disk): reading a file does not re-read the directories on
//   the path every time, `cat` with a small buffer does not read the same cluster 16 times,
// * contiguous file clusters in a single read (up to RUN_MAX), bypassing the cache,
// * read-ahead: a small read from the data area (512 B –
//   4 KiB cluster, `cat` reading 512 B at a time) reads 64 KiB into a buffer at once; further
//   reads from that range come from memory,
// * the position in the cluster chain is remembered (a sequential read does not walk
//   the chain from the start on every call),
// * `df`: free clusters counted from the FAT (once, in 64 KiB blocks) – FSInfo
//   is often stale (another OS does not have to update it).

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::{split_parent, DirEntry, FileSystem, FileType, FsError, FsStats, Metadata, Result};
use crate::block::{self, SECTOR_SIZE};
use crate::drivers::rtc::{self, DateTime};

const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_HIDDEN: u8 = 0x02;
const ATTR_SYSTEM: u8 = 0x04;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LFN: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;

const NT_LOWER_BASE: u8 = 0x08;
const NT_LOWER_EXT: u8 = 0x10;

const FAT_MASK: u32 = 0x0FFF_FFFF;
const EOC: u32 = 0x0FFF_FFFF;
const EOC_MIN: u32 = 0x0FFF_FFF8;
const BAD: u32 = 0x0FFF_FFF7;

/// FAT blocks in the cache; block = FAT_BLOCK sectors.
const FAT_CACHE_SECTORS: usize = 16;
const FAT_BLOCK: usize = 8;
/// Cluster cache – at most this many bytes / entries.
const CCACHE_BYTES: usize = 512 * 1024;
const CCACHE_MAX: usize = 64;
/// Longest contiguous cluster read at once.
const RUN_MAX: usize = 1024 * 1024;
/// Read-ahead – this many sectors at once.
const RA_SECTORS: usize = 128;
/// Free-cluster counting – this many FAT bytes per read.
const FREE_SCAN_BYTES: usize = 64 * 1024;
const FSINFO_LEAD: u32 = 0x4161_5252;
const FSINFO_STRUCT: u32 = 0x6141_7272;
const FSINFO_TRAIL: u32 = 0xAA55_0000;

/// Minimum number of FAT32 clusters per the Microsoft specification.
pub const FAT32_MIN_CLUSTERS: u32 = 65525;

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

fn fat_date_time(dt: DateTime) -> (u16, u16) {
    let year = dt.year.clamp(1980, 2107);
    let date = ((year - 1980) << 9) | ((dt.month as u16) << 5) | dt.day as u16;
    let time = ((dt.hour as u16) << 11) | ((dt.minute as u16) << 5) | (dt.second as u16 / 2);
    (date, time)
}

fn from_fat_date_time(date: u16, time: u16) -> Option<DateTime> {
    if date == 0 {
        return None;
    }
    Some(DateTime {
        year: 1980 + (date >> 9),
        month: ((date >> 5) & 0x0F) as u8,
        day: (date & 0x1F) as u8,
        hour: (time >> 11) as u8,
        minute: ((time >> 5) & 0x3F) as u8,
        second: ((time & 0x1F) * 2) as u8,
    })
}

/// Whether a sector looks like a FAT32 boot sector.
fn is_fat32_boot(s: &[u8]) -> bool {
    let spc = s[13];
    s[510] == 0x55
        && s[511] == 0xAA
        && le16(s, 11) == 512
        && spc != 0
        && spc.is_power_of_two()
        && le16(s, 14) != 0
        && s[16] != 0
        && le16(s, 17) == 0
        && le16(s, 19) == 0
        && le16(s, 22) == 0
        && le32(s, 36) != 0
        && le32(s, 32) != 0
}

// ------------------------------------------------------------
// Names
// ------------------------------------------------------------

fn lfn_checksum(short: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &b in short {
        sum = (sum >> 1 | sum << 7).wrapping_add(b);
    }
    sum
}

fn sfn_char_ok(c: u8) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit() || b"!#$%&'()-@^_`{}~".contains(&c)
}

fn valid_long_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.ends_with('.')
        && !name.ends_with(' ')
        && name.encode_utf16().count() <= 255
        && name.chars().all(|c| (c as u32) >= 0x20 && !"\"*/:<>?\\|".contains(c))
}

/// Display name from an 8.3 entry (+ NT lowercase flags).
fn short_to_name(short: &[u8; 11], nt: u8) -> String {
    let mut base: Vec<u8> = short[..8].iter().copied().collect();
    if base[0] == 0x05 {
        base[0] = 0xE5;
    }
    let base = core::str::from_utf8(&base).unwrap_or("?").trim_end();
    let ext = core::str::from_utf8(&short[8..]).unwrap_or("").trim_end();
    let base = if nt & NT_LOWER_BASE != 0 { base.to_lowercase() } else { String::from(base) };
    let ext = if nt & NT_LOWER_EXT != 0 { ext.to_lowercase() } else { String::from(ext) };
    if ext.is_empty() { base } else { format!("{}.{}", base, ext) }
}

/// If the name is a valid 8.3 name in uniform letter case
/// (e.g. "README.TXT", "notes.txt") – returns the 8.3 entry and NT flags.
fn exact_short_name(name: &str) -> Option<([u8; 11], u8)> {
    if !name.is_ascii() || name.starts_with('.') {
        return None;
    }
    let (base, ext) = match name.rfind('.') {
        Some(i) => (&name[..i], &name[i + 1..]),
        None => (name, ""),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 || base.contains('.') {
        return None;
    }
    let case = |part: &str| -> Option<u8> {
        let has_lower = part.bytes().any(|c| c.is_ascii_lowercase());
        let has_upper = part.bytes().any(|c| c.is_ascii_uppercase());
        match (has_lower, has_upper) {
            (true, true) => None,
            (true, false) => Some(1),
            _ => Some(0),
        }
    };
    let lower_base = case(base)?;
    let lower_ext = case(ext)?;
    let mut short = [b' '; 11];
    for (i, c) in base.bytes().enumerate() {
        let c = c.to_ascii_uppercase();
        if !sfn_char_ok(c) {
            return None;
        }
        short[i] = c;
    }
    for (i, c) in ext.bytes().enumerate() {
        let c = c.to_ascii_uppercase();
        if !sfn_char_ok(c) {
            return None;
        }
        short[8 + i] = c;
    }
    if short[0] == 0xE5 {
        short[0] = 0x05;
    }
    let nt = if lower_base == 1 { NT_LOWER_BASE } else { 0 } | if lower_ext == 1 { NT_LOWER_EXT } else { 0 };
    Some((short, nt))
}

/// Unique 8.3 name with "~N" for a long name.
fn generate_short_name(name: &str, existing: &[[u8; 11]]) -> [u8; 11] {
    let trimmed = name.trim_start_matches('.');
    let (base, ext) = match trimmed.rfind('.') {
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => (trimmed, ""),
    };
    let conv = |s: &str, max: usize| -> Vec<u8> {
        let mut out = Vec::new();
        for c in s.chars() {
            if out.len() == max {
                break;
            }
            if c == ' ' || c == '.' {
                continue;
            }
            let u = c.to_ascii_uppercase();
            let b = if u.is_ascii() && sfn_char_ok(u as u8) { u as u8 } else { b'_' };
            out.push(b);
        }
        out
    };
    let mut b = conv(base, 8);
    if b.is_empty() {
        b.push(b'_');
    }
    let e = conv(ext, 3);
    for n in 1..1_000_000u32 {
        let tail = format!("~{}", n);
        let keep = b.len().min(8 - tail.len());
        let mut short = [b' '; 11];
        short[..keep].copy_from_slice(&b[..keep]);
        short[keep..keep + tail.len()].copy_from_slice(tail.as_bytes());
        short[8..8 + e.len()].copy_from_slice(&e);
        if !existing.contains(&short) {
            return short;
        }
    }
    [b'_'; 11]
}

// ------------------------------------------------------------
// In-memory directories
// ------------------------------------------------------------

struct DirBuf {
    clusters: Vec<u32>,
    data: Vec<u8>,
    dirty: Vec<bool>,
}

impl DirBuf {
    fn slots(&self) -> usize {
        self.data.len() / 32
    }
    fn slot(&self, i: usize) -> &[u8] {
        &self.data[i * 32..i * 32 + 32]
    }
    fn set_slot(&mut self, i: usize, bytes: &[u8; 32], cluster_bytes: usize) {
        self.data[i * 32..i * 32 + 32].copy_from_slice(bytes);
        self.dirty[i * 32 / cluster_bytes] = true;
    }
    fn mark(&mut self, i: usize, byte0: u8, cluster_bytes: usize) {
        self.data[i * 32] = byte0;
        self.dirty[i * 32 / cluster_bytes] = true;
    }
}

#[derive(Clone)]
struct Entry {
    name: String,
    short: [u8; 11],
    attr: u8,
    cluster: u32,
    size: u32,
    mdate: u16,
    mtime: u16,
    first_slot: usize,
    sfn_slot: usize,
}

impl Entry {
    fn is_dir(&self) -> bool {
        self.attr & ATTR_DIRECTORY != 0
    }
    fn kind(&self) -> FileType {
        if self.is_dir() { FileType::Directory } else { FileType::File }
    }
}

fn parse_dir(buf: &DirBuf) -> Vec<Entry> {
    let mut out = Vec::new();
    // Collected long-name parts: (first slot, count, checksum, parts)
    let mut lfn: Option<(usize, usize, u8, Vec<Option<[u16; 13]>>)> = None;

    for i in 0..buf.slots() {
        let s = buf.slot(i);
        if s[0] == 0x00 {
            break;
        }
        if s[0] == 0xE5 {
            lfn = None;
            continue;
        }
        let attr = s[11];
        if attr & 0x3F == ATTR_LFN {
            let ord = s[0];
            let index = (ord & 0x1F) as usize;
            if index == 0 || index > 20 {
                lfn = None;
                continue;
            }
            if ord & 0x40 != 0 {
                lfn = Some((i, index, s[13], vec![None; index]));
            }
            if let Some((_, count, sum, parts)) = lfn.as_mut() {
                if index <= *count && s[13] == *sum {
                    let mut chars = [0u16; 13];
                    for k in 0..5 {
                        chars[k] = le16(s, 1 + k * 2);
                    }
                    for k in 0..6 {
                        chars[5 + k] = le16(s, 14 + k * 2);
                    }
                    for k in 0..2 {
                        chars[11 + k] = le16(s, 28 + k * 2);
                    }
                    parts[index - 1] = Some(chars);
                } else {
                    lfn = None;
                }
            }
            continue;
        }
        if attr & ATTR_VOLUME_ID != 0 || s[0] == b'.' {
            lfn = None;
            continue;
        }

        let mut short = [0u8; 11];
        short.copy_from_slice(&s[..11]);
        let mut first_slot = i;
        let mut name = None;
        if let Some((start, count, sum, parts)) = lfn.take() {
            if sum == lfn_checksum(&short) && start + count == i && parts.iter().all(|p| p.is_some()) {
                let mut units = Vec::new();
                'outer: for p in parts.iter().flatten() {
                    for &u in p {
                        if u == 0x0000 {
                            break 'outer;
                        }
                        units.push(u);
                    }
                }
                name = Some(String::from_utf16_lossy(&units));
                first_slot = start;
            }
        }
        let name = name.unwrap_or_else(|| short_to_name(&short, s[12]));
        out.push(Entry {
            name,
            short,
            attr,
            cluster: ((le16(s, 20) as u32) << 16) | le16(s, 26) as u32,
            size: le32(s, 28),
            mtime: le16(s, 22),
            mdate: le16(s, 24),
            first_slot,
            sfn_slot: i,
        });
    }
    out
}

fn names_equal(a: &str, b: &str) -> bool {
    a == b || a.to_lowercase() == b.to_lowercase()
}

// ------------------------------------------------------------
// File system
// ------------------------------------------------------------

/// FAT block in the cache (FAT_BLOCK sectors from `sector`, fewer at the end of the FAT).
struct FatSector {
    sector: u32,
    data: Vec<u8>,
    dirty: bool,
    used: u64,
}

/// Cached cluster.
struct CachedCluster {
    cluster: u32,
    data: Vec<u8>,
    used: u64,
}

pub struct Fat32 {
    disk: usize,
    disk_name: String,
    part_lba: u64,
    spc: u32,
    cluster_bytes: usize,
    reserved: u32,
    num_fats: u32,
    fat_size: u32,
    root_cluster: u32,
    data_start: u64,
    total_clusters: u32,
    fsinfo_sector: u16,
    free_count: Option<u32>,
    next_free: u32,
    fsinfo_dirty: bool,
    label: String,
    fat_cache: Vec<FatSector>,
    clock: u64,
    /// Cluster cache, position in the chain (first cluster, index,
    /// cluster), free count computed from the FAT (not from FSInfo).
    ccache: Vec<CachedCluster>,
    ccache_max: usize,
    hint: Option<(u32, usize, u32)>,
    free_scanned: bool,
    /// Read-ahead buffer: first sector (relative to the partition),
    /// number of valid sectors (0 – empty), data.
    ra_lba: u64,
    ra_len: usize,
    ra: Vec<u8>,
    /// Read-only disk (USB flash drive, real SSD) – changes are
    /// rejected immediately, before anything reaches the in-memory buffers.
    read_only: bool,
}

enum Located {
    Root,
    Entry(DirBuf, Entry),
}

impl Fat32 {
    // ---------------- disk access ----------------

    fn read_sectors(&self, lba: u64, buf: &mut [u8]) -> Result<()> {
        Ok(block::read(self.disk, self.part_lba + lba, buf)?)
    }

    fn write_sectors(&self, lba: u64, buf: &[u8]) -> Result<()> {
        Ok(block::write(self.disk, self.part_lba + lba, buf)?)
    }

    fn cluster_lba(&self, c: u32) -> u64 {
        self.data_start + (c as u64 - 2) * self.spc as u64
    }

    fn valid_cluster(&self, c: u32) -> bool {
        c >= 2 && c < self.total_clusters + 2
    }

    /// Whole cluster `c` into `buf` (cluster_bytes) – through the cluster cache.
    fn read_cluster(&mut self, c: u32, buf: &mut [u8]) -> Result<()> {
        if !self.valid_cluster(c) {
            return Err(FsError::Corrupt("cluster number out of range"));
        }
        self.clock += 1;
        if let Some(e) = self.ccache.iter_mut().find(|e| e.cluster == c) {
            e.used = self.clock;
            buf.copy_from_slice(&e.data);
            return Ok(());
        }
        self.read_data(self.cluster_lba(c), buf)?;
        self.cache_put(c, buf);
        Ok(())
    }

    /// Read from the data area; small reads go through the read-ahead buffer.
    fn read_data(&mut self, lba: u64, out: &mut [u8]) -> Result<()> {
        let ns = out.len() / SECTOR_SIZE;
        if ns >= RA_SECTORS {
            return self.read_sectors(lba, out);
        }
        let hit = self.ra_len > 0 && lba >= self.ra_lba && lba + ns as u64 <= self.ra_lba + self.ra_len as u64;
        if !hit {
            let end = self.data_start + self.total_clusters as u64 * self.spc as u64;
            let n = (RA_SECTORS as u64).min(end.saturating_sub(lba)) as usize;
            if n < ns {
                return self.read_sectors(lba, out);
            }
            if self.ra.is_empty() {
                self.ra = vec![0u8; RA_SECTORS * SECTOR_SIZE];
            }
            self.ra_len = 0;
            let mut ra = core::mem::take(&mut self.ra);
            let r = self.read_sectors(lba, &mut ra[..n * SECTOR_SIZE]);
            self.ra = ra;
            r?;
            self.ra_lba = lba;
            self.ra_len = n;
        }
        let off = (lba - self.ra_lba) as usize * SECTOR_SIZE;
        out.copy_from_slice(&self.ra[off..off + out.len()]);
        Ok(())
    }

    fn cache_put(&mut self, c: u32, data: &[u8]) {
        if let Some(e) = self.ccache.iter_mut().find(|e| e.cluster == c) {
            e.data.copy_from_slice(data);
            e.used = self.clock;
            return;
        }
        if self.ccache.len() >= self.ccache_max {
            let (oldest, _) = self.ccache.iter().enumerate().min_by_key(|(_, e)| e.used).unwrap();
            let mut e = self.ccache.swap_remove(oldest);
            e.data.copy_from_slice(data);
            e.cluster = c;
            e.used = self.clock;
            self.ccache.push(e);
            return;
        }
        self.ccache.push(CachedCluster { cluster: c, data: data.to_vec(), used: self.clock });
    }

    /// Cluster write – to disk and to the cache (if present there; write-through).
    fn write_cluster(&mut self, c: u32, buf: &[u8]) -> Result<()> {
        if !self.valid_cluster(c) {
            return Err(FsError::Corrupt("cluster number out of range"));
        }
        let lba = self.cluster_lba(c);
        if self.ra_len > 0 && lba < self.ra_lba + self.ra_len as u64 && lba + self.spc as u64 > self.ra_lba {
            self.ra_len = 0; // write within the read-ahead buffer range – invalidated
        }
        let r = self.write_sectors(lba, buf);
        if r.is_ok() {
            if let Some(e) = self.ccache.iter_mut().find(|e| e.cluster == c) {
                e.data.copy_from_slice(buf);
            }
        } else {
            // Disk state unknown – no copy in the cache.
            self.ccache.retain(|e| e.cluster != c);
        }
        r
    }

    /// Next cluster in the chain (error when the chain ends / is invalid).
    fn next_cluster(&mut self, c: u32) -> Result<u32> {
        let n = self.fat_get(c)?;
        if n >= EOC_MIN {
            return Err(FsError::Corrupt("file shorter than its size"));
        }
        if !self.valid_cluster(n) || n == BAD {
            return Err(FsError::Corrupt("bad cluster in chain"));
        }
        Ok(n)
    }

    /// Cluster number `idx` of the chain starting at `first` – from the remembered position,
    /// if it is the same chain and not past `idx`.
    fn cluster_at(&mut self, first: u32, idx: usize) -> Result<u32> {
        let (mut i, mut c) = match self.hint {
            Some((f, hi, hc)) if f == first && hi <= idx => (hi, hc),
            _ => (0, first),
        };
        if !self.valid_cluster(c) {
            return Err(FsError::Corrupt("bad cluster in chain"));
        }
        if idx > self.total_clusters as usize {
            return Err(FsError::Corrupt("cluster chain loop"));
        }
        while i < idx {
            c = self.next_cluster(c)?;
            i += 1;
        }
        self.hint = Some((first, idx, c));
        Ok(c)
    }

    // ---------------- mounting ----------------

    /// Opens FAT32 on disk `disk` (the whole disk or the first FAT32 partition from the MBR).
    pub fn open(disk: usize) -> Result<Self> {
        let disk_name = block::with_device(disk, |d| String::from(d.name()))?;
        let mut s0 = [0u8; SECTOR_SIZE];
        block::read(disk, 0, &mut s0)?;

        let mut part_lba = None;
        if is_fat32_boot(&s0) {
            part_lba = Some(0u64);
        } else if s0[510] == 0x55 && s0[511] == 0xAA {
            for p in 0..4 {
                let e = &s0[446 + p * 16..446 + p * 16 + 16];
                let kind = e[4];
                if kind == 0xEE {
                    return Err(FsError::Unsupported); // GPT
                }
                if matches!(kind, 0x0B | 0x0C) {
                    let start = le32(e, 8) as u64;
                    let mut bs = [0u8; SECTOR_SIZE];
                    block::read(disk, start, &mut bs)?;
                    if is_fat32_boot(&bs) {
                        part_lba = Some(start);
                        break;
                    }
                }
            }
        }
        let part_lba = part_lba.ok_or(FsError::NoFileSystem)?;
        let mut bs = [0u8; SECTOR_SIZE];
        block::read(disk, part_lba, &mut bs)?;

        let spc = bs[13] as u32;
        let reserved = le16(&bs, 14) as u32;
        let num_fats = bs[16] as u32;
        let total = le32(&bs, 32) as u64;
        let fat_size = le32(&bs, 36);
        let root_cluster = le32(&bs, 44);
        let fsinfo_sector = le16(&bs, 48);
        let data_start = reserved as u64 + num_fats as u64 * fat_size as u64;
        if data_start >= total {
            return Err(FsError::Corrupt("data area outside the volume"));
        }
        let by_size = ((total - data_start) / spc as u64) as u32;
        let by_fat = fat_size.saturating_mul(SECTOR_SIZE as u32 / 4).saturating_sub(2);
        let total_clusters = by_size.min(by_fat);
        let label = String::from(core::str::from_utf8(&bs[71..82]).unwrap_or("").trim_end());

        let mut fs = Fat32 {
            disk,
            disk_name,
            part_lba,
            spc,
            cluster_bytes: spc as usize * SECTOR_SIZE,
            reserved,
            num_fats,
            fat_size,
            root_cluster,
            data_start,
            total_clusters,
            fsinfo_sector,
            free_count: None,
            next_free: 2,
            fsinfo_dirty: false,
            label,
            fat_cache: Vec::new(),
            clock: 0,
            ccache: Vec::new(),
            ccache_max: (CCACHE_BYTES / (spc as usize * SECTOR_SIZE).max(1)).clamp(4, CCACHE_MAX),
            hint: None,
            free_scanned: false,
            ra_lba: 0,
            ra_len: 0,
            ra: Vec::new(),
            read_only: block::is_read_only(disk),
        };
        if !fs.valid_cluster(root_cluster) {
            return Err(FsError::Corrupt("bad root cluster"));
        }

        // FSInfo: free-cluster hint (may be stale – we check the range).
        if fsinfo_sector != 0 && (fsinfo_sector as u32) < reserved {
            let mut fi = [0u8; SECTOR_SIZE];
            fs.read_sectors(fsinfo_sector as u64, &mut fi)?;
            if le32(&fi, 0) == FSINFO_LEAD && le32(&fi, 484) == FSINFO_STRUCT {
                let free = le32(&fi, 488);
                if free <= total_clusters {
                    fs.free_count = Some(free);
                }
                let next = le32(&fi, 492);
                if fs.valid_cluster(next) {
                    fs.next_free = next;
                }
            }
        }
        Ok(fs)
    }

    // ---------------- FAT ----------------

    /// FAT block starting at sector `sector` (a multiple of FAT_BLOCK).
    fn fat_slot(&mut self, sector: u32) -> Result<usize> {
        self.clock += 1;
        if let Some(i) = self.fat_cache.iter().position(|s| s.sector == sector) {
            self.fat_cache[i].used = self.clock;
            return Ok(i);
        }
        if self.fat_cache.len() >= FAT_CACHE_SECTORS {
            let (oldest, _) = self.fat_cache.iter().enumerate().min_by_key(|(_, s)| s.used).unwrap();
            self.write_fat_sector(oldest)?;
            self.fat_cache.remove(oldest);
        }
        let n = (FAT_BLOCK as u32).min(self.fat_size.saturating_sub(sector)).max(1) as usize;
        let mut data = vec![0u8; n * SECTOR_SIZE];
        self.read_sectors(self.reserved as u64 + sector as u64, &mut data)?;
        self.fat_cache.push(FatSector { sector, data, dirty: false, used: self.clock });
        Ok(self.fat_cache.len() - 1)
    }

    fn write_fat_sector(&mut self, i: usize) -> Result<()> {
        if !self.fat_cache[i].dirty {
            return Ok(());
        }
        let s = &self.fat_cache[i];
        for copy in 0..self.num_fats {
            let lba = self.reserved as u64 + copy as u64 * self.fat_size as u64 + s.sector as u64;
            block::write(self.disk, self.part_lba + lba, &s.data)?;
        }
        self.fat_cache[i].dirty = false;
        Ok(())
    }

    fn fat_get(&mut self, c: u32) -> Result<u32> {
        let off = c as usize * 4;
        let blk = FAT_BLOCK * SECTOR_SIZE;
        let i = self.fat_slot((off / blk * FAT_BLOCK) as u32)?;
        Ok(le32(&self.fat_cache[i].data, off % blk) & FAT_MASK)
    }

    fn fat_set(&mut self, c: u32, value: u32) -> Result<()> {
        // Chains change – the remembered position is stale.
        self.hint = None;
        let off = c as usize * 4;
        let blk = FAT_BLOCK * SECTOR_SIZE;
        let i = self.fat_slot((off / blk * FAT_BLOCK) as u32)?;
        let o = off % blk;
        let old = le32(&self.fat_cache[i].data, o);
        put32(&mut self.fat_cache[i].data, o, (old & !FAT_MASK) | (value & FAT_MASK));
        self.fat_cache[i].dirty = true;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        for i in 0..self.fat_cache.len() {
            self.write_fat_sector(i)?;
        }
        if self.fsinfo_dirty && self.fsinfo_sector != 0 && (self.fsinfo_sector as u32) < self.reserved {
            let mut fi = [0u8; SECTOR_SIZE];
            self.read_sectors(self.fsinfo_sector as u64, &mut fi)?;
            if le32(&fi, 0) == FSINFO_LEAD {
                put32(&mut fi, 488, self.free_count.unwrap_or(0xFFFF_FFFF));
                put32(&mut fi, 492, self.next_free);
                self.write_sectors(self.fsinfo_sector as u64, &fi)?;
            }
            self.fsinfo_dirty = false;
        }
        Ok(())
    }

    fn chain(&mut self, first: u32) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        let mut c = first;
        while c < EOC_MIN {
            if !self.valid_cluster(c) || c == BAD {
                return Err(FsError::Corrupt("bad cluster in chain"));
            }
            if out.len() as u32 > self.total_clusters {
                return Err(FsError::Corrupt("cluster chain loop"));
            }
            out.push(c);
            c = self.fat_get(c)?;
        }
        Ok(out)
    }

    fn free_clusters(&mut self) -> Result<u32> {
        if let Some(n) = self.free_count {
            if self.free_scanned || !self.read_only {
                return Ok(n);
            }
        }
        let n = self.count_free()?;
        self.free_scanned = true;
        if self.free_count != Some(n) && !self.read_only {
            self.fsinfo_dirty = true;
        }
        self.free_count = Some(n);
        Ok(n)
    }

    /// Free clusters counted from the FAT (in FREE_SCAN_BYTES blocks, bypassing the
    /// FAT cache; modified blocks are written first so the disk is up to date).
    fn count_free(&mut self) -> Result<u32> {
        if !self.read_only {
            for i in 0..self.fat_cache.len() {
                self.write_fat_sector(i)?;
            }
        }
        let entries = self.total_clusters as usize + 2;
        let mut buf = vec![0u8; FREE_SCAN_BYTES];
        let mut n = 0u32;
        let mut e = 0usize;
        while e < entries {
            let bytes = ((entries - e) * 4).min(FREE_SCAN_BYTES);
            let sectors = bytes.div_ceil(SECTOR_SIZE);
            let b = &mut buf[..sectors * SECTOR_SIZE];
            self.read_sectors(self.reserved as u64 + (e * 4 / SECTOR_SIZE) as u64, b)?;
            for k in 0..bytes / 4 {
                let c = e + k;
                if c >= 2 && le32(b, k * 4) & FAT_MASK == 0 {
                    n += 1;
                }
            }
            e += bytes / 4;
        }
        Ok(n)
    }

    /// Allocates a free cluster (marked as end of chain), links it after `prev`.
    fn alloc_cluster(&mut self, prev: Option<u32>) -> Result<u32> {
        let n = self.total_clusters;
        let start = if self.valid_cluster(self.next_free) { self.next_free } else { 2 };
        for k in 0..n {
            let c = 2 + (start - 2 + k) % n;
            if self.fat_get(c)? == 0 {
                self.fat_set(c, EOC)?;
                if let Some(p) = prev {
                    self.fat_set(p, c)?;
                }
                self.next_free = if c + 1 < n + 2 { c + 1 } else { 2 };
                if let Some(f) = self.free_count.as_mut() {
                    *f = f.saturating_sub(1);
                }
                self.fsinfo_dirty = true;
                return Ok(c);
            }
        }
        Err(FsError::NoSpace)
    }

    fn free_chain(&mut self, first: u32) -> Result<()> {
        if first == 0 {
            return Ok(());
        }
        for c in self.chain(first)? {
            self.fat_set(c, 0)?;
            if let Some(f) = self.free_count.as_mut() {
                *f += 1;
            }
        }
        self.fsinfo_dirty = true;
        Ok(())
    }

    /// Truncates a chain to `keep` clusters (the rest is freed).
    fn cut_chain(&mut self, chain: &[u32], keep: usize) -> Result<()> {
        if keep < chain.len() {
            if keep > 0 {
                self.fat_set(chain[keep - 1], EOC)?;
            }
            for &c in &chain[keep..] {
                self.fat_set(c, 0)?;
                if let Some(f) = self.free_count.as_mut() {
                    *f += 1;
                }
            }
            self.fsinfo_dirty = true;
        }
        Ok(())
    }

    // ---------------- directories ----------------

    fn load_dir(&mut self, first: u32) -> Result<DirBuf> {
        let first = if first == 0 { self.root_cluster } else { first };
        let clusters = self.chain(first)?;
        let mut data = vec![0u8; clusters.len() * self.cluster_bytes];
        for (i, &c) in clusters.iter().enumerate() {
            self.read_cluster(c, &mut data[i * self.cluster_bytes..(i + 1) * self.cluster_bytes])?;
        }
        let dirty = vec![false; clusters.len()];
        Ok(DirBuf { clusters, data, dirty })
    }

    fn store_dir(&mut self, buf: &mut DirBuf) -> Result<()> {
        for i in 0..buf.clusters.len() {
            if buf.dirty[i] {
                let cb = self.cluster_bytes;
                self.write_cluster(buf.clusters[i], &buf.data[i * cb..(i + 1) * cb])?;
                buf.dirty[i] = false;
            }
        }
        Ok(())
    }

    fn lookup(&mut self, dir_first: u32, name: &str) -> Result<(DirBuf, Entry)> {
        let buf = self.load_dir(dir_first)?;
        let wanted_upper = name.to_uppercase();
        let found = parse_dir(&buf).into_iter().find(|e| {
            names_equal(&e.name, name) || short_to_name(&e.short, 0) == wanted_upper
        });
        match found {
            Some(e) => Ok((buf, e)),
            None => Err(FsError::NotFound),
        }
    }

    fn locate(&mut self, path: &str) -> Result<Located> {
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return Ok(Located::Root);
        }
        let mut dir = self.root_cluster;
        for (i, part) in parts.iter().enumerate() {
            let (buf, e) = self.lookup(dir, part)?;
            if i == parts.len() - 1 {
                return Ok(Located::Entry(buf, e));
            }
            if !e.is_dir() {
                return Err(FsError::NotADirectory);
            }
            dir = if e.cluster == 0 { self.root_cluster } else { e.cluster };
        }
        unreachable!()
    }

    /// First cluster of the directory at `path`.
    fn dir_cluster(&mut self, path: &str) -> Result<u32> {
        match self.locate(path)? {
            Located::Root => Ok(self.root_cluster),
            Located::Entry(_, e) if e.is_dir() => Ok(if e.cluster == 0 { self.root_cluster } else { e.cluster }),
            Located::Entry(..) => Err(FsError::NotADirectory),
        }
    }

    fn file_entry(&mut self, path: &str) -> Result<(DirBuf, Entry)> {
        match self.locate(path)? {
            Located::Root => Err(FsError::IsADirectory),
            Located::Entry(_, e) if e.is_dir() => Err(FsError::IsADirectory),
            Located::Entry(buf, e) => Ok((buf, e)),
        }
    }

    /// Writes the changed fields of an 8.3 entry (cluster, size, time).
    fn update_entry(&mut self, buf: &mut DirBuf, e: &Entry) -> Result<()> {
        let mut slot = [0u8; 32];
        slot.copy_from_slice(buf.slot(e.sfn_slot));
        let (d, t) = fat_date_time(rtc::now());
        put16(&mut slot, 20, (e.cluster >> 16) as u16);
        put16(&mut slot, 26, e.cluster as u16);
        put32(&mut slot, 28, e.size);
        put16(&mut slot, 22, t);
        put16(&mut slot, 24, d);
        put16(&mut slot, 18, d);
        slot[11] = e.attr;
        buf.set_slot(e.sfn_slot, &slot, self.cluster_bytes);
        self.store_dir(buf)
    }

    /// Creates an entry (with a long name if needed) in directory `dir_first`.
    fn add_entry(&mut self, dir_first: u32, name: &str, attr: u8, cluster: u32) -> Result<()> {
        if !valid_long_name(name) {
            return Err(FsError::InvalidName);
        }
        let mut buf = self.load_dir(dir_first)?;
        let entries = parse_dir(&buf);
        if entries.iter().any(|e| names_equal(&e.name, name)) {
            return Err(FsError::AlreadyExists);
        }
        let existing: Vec<[u8; 11]> = entries.iter().map(|e| e.short).collect();

        let (short, nt, lfn_units) = match exact_short_name(name) {
            Some((s, nt)) if !existing.contains(&s) => (s, nt, None),
            _ => {
                let s = generate_short_name(name, &existing);
                let units: Vec<u16> = name.encode_utf16().collect();
                (s, 0, Some(units))
            }
        };
        let lfn_count = lfn_units.as_ref().map_or(0, |u| u.len().div_ceil(13));
        let needed = lfn_count + 1;

        // Look for `needed` consecutive free slots (0xE5 or 0x00 = end).
        let mut start = None;
        let mut run = 0;
        for i in 0..buf.slots() {
            let b0 = buf.slot(i)[0];
            if b0 == 0x00 {
                // From the end of the directory everything is free (together with preceding 0xE5).
                start = Some(i - run);
                break;
            }
            if b0 == 0xE5 {
                run += 1;
                if run == needed {
                    start = Some(i + 1 - needed);
                    break;
                }
            } else {
                run = 0;
            }
        }
        let start = start.unwrap_or(buf.slots());
        // Not enough room – the directory grows by zeroed clusters.
        while start + needed > buf.slots() {
            let last = *buf.clusters.last().unwrap();
            let c = self.alloc_cluster(Some(last))?;
            let zero = vec![0u8; self.cluster_bytes];
            self.write_cluster(c, &zero)?;
            buf.clusters.push(c);
            buf.data.extend_from_slice(&zero);
            buf.dirty.push(false);
        }

        // LFN entries: from the last fragment (flag 0x40) to the first.
        if let Some(units) = &lfn_units {
            let sum = lfn_checksum(&short);
            for k in 0..lfn_count {
                let part = lfn_count - k; // fragment number 1..=count
                let mut chars = [0xFFFFu16; 13];
                for j in 0..13 {
                    let idx = (part - 1) * 13 + j;
                    if idx < units.len() {
                        chars[j] = units[idx];
                    } else if idx == units.len() {
                        chars[j] = 0x0000;
                    }
                }
                let mut s = [0u8; 32];
                s[0] = part as u8 | if k == 0 { 0x40 } else { 0 };
                for j in 0..5 {
                    put16(&mut s, 1 + j * 2, chars[j]);
                }
                s[11] = ATTR_LFN;
                s[13] = sum;
                for j in 0..6 {
                    put16(&mut s, 14 + j * 2, chars[5 + j]);
                }
                for j in 0..2 {
                    put16(&mut s, 28 + j * 2, chars[11 + j]);
                }
                buf.set_slot(start + k, &s, self.cluster_bytes);
            }
        }

        let (d, t) = fat_date_time(rtc::now());
        let mut s = [0u8; 32];
        s[..11].copy_from_slice(&short);
        s[11] = attr;
        s[12] = nt;
        put16(&mut s, 14, t);
        put16(&mut s, 16, d);
        put16(&mut s, 18, d);
        put16(&mut s, 20, (cluster >> 16) as u16);
        put16(&mut s, 22, t);
        put16(&mut s, 24, d);
        put16(&mut s, 26, cluster as u16);
        put32(&mut s, 28, 0);
        buf.set_slot(start + lfn_count, &s, self.cluster_bytes);
        self.store_dir(&mut buf)
    }

    fn do_write(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<usize> {
        let (mut dir, mut e) = self.file_entry(path)?;
        if data.is_empty() {
            return Ok(0);
        }
        let end = offset.checked_add(data.len() as u64).ok_or(FsError::NoSpace)?;
        if end > u32::MAX as u64 {
            return Err(FsError::NoSpace); // FAT32 limit: 4 GiB - 1
        }
        let cb = self.cluster_bytes as u64;
        let old_size = e.size as u64;
        let mut chain = if e.cluster == 0 { Vec::new() } else { self.chain(e.cluster)? };
        let old_len = chain.len();
        let needed = end.div_ceil(cb) as usize;
        while chain.len() < needed {
            match self.alloc_cluster(chain.last().copied()) {
                Ok(c) => chain.push(c),
                Err(err) => {
                    // Rollback: free whatever we managed to add.
                    self.cut_chain(&chain, old_len)?;
                    self.flush()?;
                    return Err(err);
                }
            }
        }

        let old_clusters = old_size.div_ceil(cb) as usize;
        let first_idx = (old_size.min(offset) / cb) as usize;
        let mut buf = vec![0u8; cb as usize];
        for idx in first_idx..needed {
            let cstart = idx as u64 * cb;
            let cend = cstart + cb;
            let full = offset <= cstart && end >= cend;
            if !full && idx < old_clusters {
                self.read_cluster(chain[idx], &mut buf)?;
                // Bytes past the old end of file may be garbage – zero them.
                if old_size < cend {
                    let from = old_size.saturating_sub(cstart) as usize;
                    buf[from..].fill(0);
                }
            } else {
                buf.fill(0);
            }
            let lo = offset.max(cstart);
            let hi = end.min(cend);
            if lo < hi {
                let src = (lo - offset) as usize..(hi - offset) as usize;
                buf[(lo - cstart) as usize..(hi - cstart) as usize].copy_from_slice(&data[src]);
            }
            self.write_cluster(chain[idx], &buf)?;
        }

        e.cluster = chain[0];
        e.size = old_size.max(end) as u32;
        e.attr |= ATTR_ARCHIVE;
        self.update_entry(&mut dir, &e)?;
        self.flush()?;
        Ok(data.len())
    }
}

impl FileSystem for Fat32 {
    fn kind(&self) -> &'static str {
        "fat32"
    }

    fn read_only(&self) -> bool {
        self.read_only
    }

    fn source(&self) -> String {
        format!(
            "{}{}, label '{}', {} MiB, {} B clusters",
            self.disk_name,
            if self.part_lba != 0 { format!(" partition @{}", self.part_lba) } else { String::new() },
            self.label,
            self.total_clusters as u64 * self.cluster_bytes as u64 / (1024 * 1024),
            self.cluster_bytes
        )
    }

    fn stat(&mut self, path: &str) -> Result<Metadata> {
        Ok(match self.locate(path)? {
            Located::Root => Metadata { kind: FileType::Directory, size: 0, modified: None },
            Located::Entry(_, e) => Metadata {
                kind: e.kind(),
                size: if e.is_dir() { 0 } else { e.size as u64 },
                modified: from_fat_date_time(e.mdate, e.mtime),
            },
        })
    }

    fn read_dir(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        let first = self.dir_cluster(path)?;
        let buf = self.load_dir(first)?;
        Ok(parse_dir(&buf)
            .into_iter()
            .map(|e| DirEntry {
                kind: e.kind(),
                size: if e.is_dir() { 0 } else { e.size as u64 },
                modified: from_fat_date_time(e.mdate, e.mtime),
                name: e.name,
            })
            .collect())
    }

    fn read(&mut self, path: &str, offset: u64, out: &mut [u8]) -> Result<usize> {
        let (_, e) = self.file_entry(path)?;
        let size = e.size as u64;
        if offset >= size || out.is_empty() || e.cluster == 0 {
            return Ok(0);
        }
        let n = (out.len() as u64).min(size - offset) as usize;
        let cb = self.cluster_bytes;
        // Chain position from the remembered one, contiguous clusters in a single
        // read, tails through the cluster cache.
        let mut idx = (offset / cb as u64) as usize;
        let mut c = self.cluster_at(e.cluster, idx)?;
        let mut done = 0;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let within = ((offset + done as u64) % cb as u64) as usize;
            let left = n - done;
            if within == 0 && left >= cb {
                // Run of full clusters c, c+1, … (at most RUN_MAX bytes).
                let max = (left / cb).min((RUN_MAX / cb).max(1));
                let mut k = 1;
                let mut next = None;
                while k < max {
                    let nx = self.next_cluster(c + k as u32 - 1)?;
                    if nx != c + k as u32 {
                        next = Some(nx);
                        break;
                    }
                    k += 1;
                }
                if !self.valid_cluster(c + k as u32 - 1) {
                    return Err(FsError::Corrupt("cluster number out of range"));
                }
                let lba = self.cluster_lba(c);
                self.read_data(lba, &mut out[done..done + k * cb])?;
                done += k * cb;
                idx += k - 1;
                c += k as u32 - 1;
                if done >= n {
                    break;
                }
                c = match next {
                    Some(nx) => nx,
                    None => self.next_cluster(c)?,
                };
                idx += 1;
            } else {
                if buf.is_empty() {
                    buf = vec![0u8; cb];
                }
                self.read_cluster(c, &mut buf)?;
                let take = (cb - within).min(left);
                out[done..done + take].copy_from_slice(&buf[within..within + take]);
                done += take;
                if done >= n {
                    break;
                }
                c = self.next_cluster(c)?;
                idx += 1;
            }
        }
        self.hint = Some((e.cluster, idx, c));
        Ok(n)
    }

    fn write(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<usize> {
        if self.read_only {
            return Err(FsError::ReadOnly);
        }
        self.do_write(path, offset, data)
    }

    fn truncate(&mut self, path: &str, size: u64) -> Result<()> {
        if self.read_only {
            return Err(FsError::ReadOnly);
        }
        let (mut dir, mut e) = self.file_entry(path)?;
        let old = e.size as u64;
        if size > old {
            // Extending = writing a single zero at the end (the hole fills with zeros).
            self.do_write(path, size - 1, &[0])?;
            return Ok(());
        }
        if size == old {
            return Ok(());
        }
        let chain = if e.cluster == 0 { Vec::new() } else { self.chain(e.cluster)? };
        let keep = size.div_ceil(self.cluster_bytes as u64) as usize;
        self.cut_chain(&chain, keep)?;
        if keep == 0 {
            e.cluster = 0;
        }
        e.size = size as u32;
        self.update_entry(&mut dir, &e)?;
        self.flush()
    }

    fn create(&mut self, path: &str) -> Result<()> {
        if self.read_only {
            return Err(FsError::ReadOnly);
        }
        let (parent, name) = split_parent(path);
        let dir = self.dir_cluster(parent)?;
        self.add_entry(dir, name, ATTR_ARCHIVE, 0)?;
        self.flush()
    }

    fn mkdir(&mut self, path: &str) -> Result<()> {
        if self.read_only {
            return Err(FsError::ReadOnly);
        }
        let (parent, name) = split_parent(path);
        if !valid_long_name(name) {
            return Err(FsError::InvalidName);
        }
        let parent_cluster = self.dir_cluster(parent)?;
        if self.lookup(parent_cluster, name).is_ok() {
            return Err(FsError::AlreadyExists);
        }
        let c = self.alloc_cluster(None)?;
        let mut data = vec![0u8; self.cluster_bytes];
        let (d, t) = fat_date_time(rtc::now());
        let dotdot = if parent_cluster == self.root_cluster { 0 } else { parent_cluster };
        for (i, (nm, cl)) in [(b".          ", c), (b"..         ", dotdot)].iter().enumerate() {
            let s = &mut data[i * 32..i * 32 + 32];
            s[..11].copy_from_slice(*nm);
            s[11] = ATTR_DIRECTORY;
            put16(s, 14, t);
            put16(s, 16, d);
            put16(s, 18, d);
            put16(s, 20, (cl >> 16) as u16);
            put16(s, 22, t);
            put16(s, 24, d);
            put16(s, 26, *cl as u16);
        }
        self.write_cluster(c, &data)?;
        if let Err(e) = self.add_entry(parent_cluster, name, ATTR_DIRECTORY, c) {
            self.free_chain(c)?;
            self.flush()?;
            return Err(e);
        }
        self.flush()
    }

    fn remove(&mut self, path: &str) -> Result<()> {
        if self.read_only {
            return Err(FsError::ReadOnly);
        }
        let (mut dir, e) = match self.locate(path)? {
            Located::Root => return Err(FsError::Busy),
            Located::Entry(buf, e) => (buf, e),
        };
        if e.is_dir() && e.cluster != 0 {
            let content = self.load_dir(e.cluster)?;
            if !parse_dir(&content).is_empty() {
                return Err(FsError::NotEmpty);
            }
        }
        self.free_chain(e.cluster)?;
        for slot in e.first_slot..=e.sfn_slot {
            dir.mark(slot, 0xE5, self.cluster_bytes);
        }
        self.store_dir(&mut dir)?;
        self.flush()
    }

    fn stats(&mut self) -> Option<FsStats> {
        let free = self.free_clusters().ok()? as u64;
        let _ = self.flush();
        Some(FsStats {
            total_bytes: self.total_clusters as u64 * self.cluster_bytes as u64,
            free_bytes: free * self.cluster_bytes as u64,
        })
    }

    fn sync(&mut self) -> Result<()> {
        self.flush()?;
        block::with_device(self.disk, |d| d.flush())??;
        Ok(())
    }
}

// ------------------------------------------------------------
// Formatting
// ------------------------------------------------------------

/// Formats the whole disk as FAT32 (without a partition table).  All data
/// on the disk is lost.  `allow_small` allows fewer than 65525 clusters
/// (tests only – such a volume does not conform to the specification).
pub fn mkfs(disk: usize, label: &str, allow_small: bool) -> Result<String> {
    let sectors = block::with_device(disk, |d| {
        if d.read_only() { Err(FsError::ReadOnly) } else { Ok(d.sector_count()) }
    })??;
    let total = sectors.min(u32::MAX as u64) as u32;
    let bytes = total as u64 * SECTOR_SIZE as u64;
    const MIB: u64 = 1024 * 1024;
    // Microsoft table: cluster size depending on the volume size.
    let spc: u32 = if bytes <= 260 * MIB {
        1
    } else if bytes <= 8192 * MIB {
        8
    } else if bytes <= 16384 * MIB {
        16
    } else if bytes <= 32768 * MIB {
        32
    } else {
        64
    };
    let reserved: u32 = 32;
    let num_fats: u32 = 2;
    if total <= reserved + 64 {
        return Err(FsError::NoSpace);
    }
    let tmp2 = (256 * spc + num_fats) / 2;
    let fat_size = (total - reserved + tmp2 - 1) / tmp2;
    let data_start = reserved + num_fats * fat_size;
    if data_start >= total {
        return Err(FsError::NoSpace);
    }
    let clusters = (total - data_start) / spc;
    if clusters < FAT32_MIN_CLUSTERS && !allow_small {
        return Err(FsError::Unsupported);
    }
    if clusters < 16 {
        return Err(FsError::NoSpace);
    }

    // 1. Zeroing: reserved sectors, both FATs, root directory cluster.
    let zero = vec![0u8; 64 * 1024];
    let zero_end = data_start as u64 + spc as u64;
    let mut lba = 0u64;
    while lba < zero_end {
        let n = ((zero_end - lba) as usize * SECTOR_SIZE).min(zero.len());
        block::write(disk, lba, &zero[..n])?;
        lba += (n / SECTOR_SIZE) as u64;
    }

    // 2. Boot sector.
    let now = rtc::now();
    let (d, t) = fat_date_time(now);
    let volume_id = ((d as u32) << 16 | t as u32) ^ (crate::time::ticks() as u32).wrapping_mul(2654435761);
    let mut bs = [0u8; SECTOR_SIZE];
    bs[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    bs[3..11].copy_from_slice(b"DESOOS  ");
    put16(&mut bs, 11, SECTOR_SIZE as u16);
    bs[13] = spc as u8;
    put16(&mut bs, 14, reserved as u16);
    bs[16] = num_fats as u8;
    bs[21] = 0xF8; // fixed disk
    put16(&mut bs, 24, 63);
    put16(&mut bs, 26, 255);
    put32(&mut bs, 32, total);
    put32(&mut bs, 36, fat_size);
    put32(&mut bs, 44, 2); // root directory in cluster 2
    put16(&mut bs, 48, 1); // FSInfo
    put16(&mut bs, 50, 6); // boot sector backup
    bs[64] = 0x80;
    bs[66] = 0x29;
    put32(&mut bs, 67, volume_id);
    let mut lab = [b' '; 11];
    for (i, c) in label.bytes().filter(|c| c.is_ascii_graphic() || *c == b' ').take(11).enumerate() {
        lab[i] = c.to_ascii_uppercase();
    }
    bs[71..82].copy_from_slice(&lab);
    bs[82..90].copy_from_slice(b"FAT32   ");
    bs[510] = 0x55;
    bs[511] = 0xAA;
    block::write(disk, 0, &bs)?;
    block::write(disk, 6, &bs)?;

    // 3. FSInfo (+ backup).
    let mut fi = [0u8; SECTOR_SIZE];
    put32(&mut fi, 0, FSINFO_LEAD);
    put32(&mut fi, 484, FSINFO_STRUCT);
    put32(&mut fi, 488, clusters - 1);
    put32(&mut fi, 492, 3);
    put32(&mut fi, 508, FSINFO_TRAIL);
    block::write(disk, 1, &fi)?;
    block::write(disk, 7, &fi)?;
    // Sector 2 also ends with a signature (part of the FAT32 boot record).
    let mut s2 = [0u8; SECTOR_SIZE];
    s2[510] = 0x55;
    s2[511] = 0xAA;
    block::write(disk, 2, &s2)?;
    block::write(disk, 8, &s2)?;

    // 4. Start of the FAT: media byte, marker, root directory = end of chain.
    let mut fat0 = [0u8; SECTOR_SIZE];
    put32(&mut fat0, 0, 0x0FFF_FFF8);
    put32(&mut fat0, 4, 0x0FFF_FFFF);
    put32(&mut fat0, 8, EOC);
    for copy in 0..num_fats {
        block::write(disk, (reserved + copy * fat_size) as u64, &fat0)?;
    }

    // 5. Volume label as an entry in the root directory.
    let mut root = [0u8; SECTOR_SIZE];
    root[..11].copy_from_slice(&lab);
    root[11] = ATTR_VOLUME_ID;
    put16(&mut root, 22, t);
    put16(&mut root, 24, d);
    block::write(disk, data_start as u64, &root)?;

    block::with_device(disk, |d| d.flush())??;
    Ok(format!(
        "FAT32: {} MiB, {} clusters of {} B, FAT {} sectors x {}",
        bytes / MIB,
        clusters,
        spc as usize * SECTOR_SIZE,
        fat_size,
        num_fats
    ))
}
