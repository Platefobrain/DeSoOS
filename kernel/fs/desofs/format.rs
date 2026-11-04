// `desofs format` – writes the state of docs/desofs/FORMAT.md chapter 14: blocks 0-15 zeroed
// first (both superblock slots too, so an older volume's superblock can never sit next
// to the new one), then the node block, the node-table pointer block and the root
// block, then superblock B, then A – each step followed by a flush.  An interrupted
// format leaves a volume that is not recognised or has one valid superblock with a
// complete tree.  The result is byte-for-byte what tests/mkdesofs.py --format writes.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::layout::*;
use super::sha256;

/// What `format` needs from the caller (fixed in tests, random / the clock otherwise).
pub struct Params<'a> {
    pub uuid: [u8; 16],
    pub time: u64,
    pub label: &'a str,
}

fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

/// Header of a metadata block (chapter 4).
pub fn header(b: &mut [u8], kind: &[u8; 4], level: u8, count: u16, generation: u64, addr: u64, uuid: &[u8; 16]) {
    b[0..4].copy_from_slice(kind);
    b[4] = level;
    b[5] = 0;
    put16(b, 6, count);
    put64(b, 8, generation);
    put64(b, 16, addr);
    b[24..40].copy_from_slice(uuid);
    b[40..HDR_SIZE].fill(0);
}

/// A pointer to `block` (its contents) written at `b[o..o + 48]`.
pub fn put_ptr(b: &mut [u8], o: usize, addr: u64, birth: u64, block: &[u8]) {
    put64(b, o, addr);
    put64(b, o + 8, birth);
    b[o + 16..o + 48].copy_from_slice(&sha256(block));
}

/// A superblock (chapter 2) with its checksum.
pub fn superblock(uuid: &[u8; 16], generation: u64, total: u64, used: u64, time: u64, root: &[u8; 48], label: &[u8; 32]) -> Vec<u8> {
    let mut b = vec![0u8; BLOCK];
    b[0..8].copy_from_slice(MAGIC);
    put32(&mut b, 8, VERSION);
    put32(&mut b, 12, BLOCK as u32);
    b[16..32].copy_from_slice(uuid);
    put64(&mut b, 32, generation);
    put64(&mut b, 40, total);
    put64(&mut b, 48, used);
    put64(&mut b, 56, time);
    b[80..128].copy_from_slice(root);
    b[128..160].copy_from_slice(label);
    let sum = sha256(&b[..SB_CHECKSUM]);
    b[SB_CHECKSUM..].copy_from_slice(&sum);
    b
}

/// Does sector 0 / 1 hold a partition table (and not a file system's boot sector)?
fn has_partition_table(index: usize) -> Result<bool, String> {
    let mut s = vec![0u8; 1024];
    crate::block::read(index, 0, &mut s).map_err(|e| alloc::format!("read error: {}", e))?;
    if &s[512..520] == b"EFI PART" {
        return Ok(true); // GPT header
    }
    if s[510] != 0x55 || s[511] != 0xAA {
        return Ok(false);
    }
    // A FAT / NTFS boot sector (superfloppy) starts with a jump; an MBR does not.
    if s[0] == 0xEB || s[0] == 0xE9 {
        return Ok(false);
    }
    // At least one plausible partition entry.
    Ok((0..4).any(|i| {
        let e = &s[446 + 16 * i..446 + 16 * (i + 1)];
        (e[0] == 0 || e[0] == 0x80) && e[4] != 0 && u32::from_le_bytes([e[12], e[13], e[14], e[15]]) != 0
    }))
}

/// Formats disk `index`.  Returns the number of blocks of the new volume.
pub fn format(index: usize, p: &Params) -> Result<u64, String> {
    let w = |block: u64, data: &[u8]| -> Result<(), String> {
        crate::block::write(index, block * (BLOCK / crate::block::SECTOR_SIZE) as u64, data).map_err(|e| alloc::format!("write error at block {}: {}", block, e))
    };
    let flush = || crate::block::flush(index).map_err(|e| alloc::format!("flush error: {}", e));
    if crate::block::is_read_only(index) {
        return Err(String::from("the disk is read-only - nothing changed"));
    }
    // Never under a mounted file system – a second guard behind the shell's unmount.
    if super::is_mounted(index) || !crate::fs::mounts_of_disk(index).is_empty() {
        return Err(String::from("the disk is mounted - unmount it first; nothing changed"));
    }
    let partition = crate::block::with_device(index, |d| d.parent().is_some() || d.partition_kind().is_some()).map_err(|e| alloc::format!("disk {}: {}", index, e))?;
    if !partition && has_partition_table(index)? {
        return Err(String::from("the disk has a partition table - format a partition, not the whole disk"));
    }
    let dev = super::Dev::open(index)?;
    if dev.blocks < MIN_BLOCKS {
        return Err(String::from("disk smaller than 256 KiB (64 blocks)"));
    }
    let total = dev.blocks.min(MAX_BLOCKS_V1);
    let mut label = [0u8; 32];
    let l = p.label.as_bytes();
    if l.len() > 32 || l.contains(&0) {
        return Err(String::from("label longer than 32 bytes"));
    }
    label[..l.len()].copy_from_slice(l);

    // 1. Blocks 0-15 zero (old superblocks of any earlier volume gone first).
    w(0, &vec![0u8; RESERVED as usize * BLOCK])?;
    flush()?;
    // 2. Node block (16), node-table pointer block (17), root block (18), generation 1.
    let (dsnd, dspt, dsrt) = (16u64, 17u64, 18u64);
    let mut nd = vec![0u8; BLOCK];
    header(&mut nd, KIND_DSND, 0, 1, 1, dsnd, &p.uuid);
    let n1 = HDR_SIZE + NODE_SIZE; // node 1
    put64(&mut nd, n1, 1);
    nd[n1 + 8] = TYPE_DIR;
    put32(&mut nd, n1 + 12, 1); // links
    put64(&mut nd, n1 + 24, p.time);
    put64(&mut nd, n1 + 32, p.time);
    put64(&mut nd, n1 + 40, 1); // parent
    put64(&mut nd, n1 + 48, 1); // node_gen
    let mut pt = vec![0u8; BLOCK];
    header(&mut pt, KIND_DSPT, 1, 1, 1, dspt, &p.uuid);
    put_ptr(&mut pt, HDR_SIZE, dsnd, 1, &nd);
    let mut rt = vec![0u8; BLOCK];
    header(&mut rt, KIND_DSRT, 0, 1, 1, dsrt, &p.uuid);
    put_ptr(&mut rt, HDR_SIZE, dspt, 1, &pt);
    rt[HDR_SIZE + 48] = 1; // depth
    rt[HDR_SIZE + 49] = ROOT_LIVE;
    put64(&mut rt, HDR_SIZE + 56, 2); // next_node
    w(dsnd, &nd)?;
    w(dspt, &pt)?;
    w(dsrt, &rt)?;
    flush()?;
    // 3. Superblocks: identical, B first.
    let mut root = [0u8; 48];
    put_ptr(&mut root, 0, dsrt, 1, &rt);
    let sb = superblock(&p.uuid, 1, total, 3, p.time, &root, &label);
    w(2, &sb)?;
    flush()?;
    w(1, &sb)?;
    flush()?;
    Ok(total)
}

/// A random uuid for a new volume: SHA-256 of the time stamp counter, the tick count
/// and the clock (good enough to tell volumes apart; not a secret).
pub fn random_uuid() -> [u8; 16] {
    let mut seed = [0u8; 32];
    // SAFETY: RDTSC has no side effects.
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    seed[0..8].copy_from_slice(&tsc.to_le_bytes());
    seed[8..16].copy_from_slice(&crate::time::ticks().to_le_bytes());
    seed[16..24].copy_from_slice(&crate::drivers::rtc::now().to_unix().to_le_bytes());
    let h = sha256(&seed);
    let mut u = [0u8; 16];
    u.copy_from_slice(&h[..16]);
    u
}
