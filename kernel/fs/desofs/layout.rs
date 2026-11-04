// DeSoFS format 1 – on-disk structures and their checks (docs/desofs/FORMAT.md).
//
// Everything read from a disk is untrusted: each parser checks every field the
// specification constrains (ranges, fields that must be zero, counts) and returns
// a reason instead of panicking.  Little-endian everywhere.

// Some fields and limits are used only from stage 2 on (writes, directory access).
#![allow(dead_code)]

pub const BLOCK: usize = 4096;
pub const MAGIC: &[u8; 8] = b"DESOFS01";
pub const VERSION: u32 = 1;
/// Blocks 0-15 are reserved (0 zero, 1-2 superblocks, 3-15 zero).
pub const RESERVED: u64 = 16;
pub const MIN_BLOCKS: u64 = 64;
/// Volume limit of format-1 implementations now: 64 GiB.
pub const MAX_BLOCKS_V1: u64 = (64u64 << 30) / BLOCK as u64;
pub const FANOUT: usize = 84;
pub const NODES_PER_BLOCK: u64 = 15;
pub const NODE_SIZE: usize = 256;
pub const PTR_SIZE: usize = 48;
pub const HDR_SIZE: usize = 64;
pub const ROOT_ENTRIES: usize = 32;
pub const ROOT_ENTRY: usize = 96;
pub const MAX_DEPTH: u8 = 5;
pub const SB_CHECKSUM: usize = 4064;
/// Most active entries in one directory.
pub const DIR_MAX_ENTRIES: usize = 65536;

pub const KIND_DSRT: &[u8; 4] = b"DSRT";
pub const KIND_DSPT: &[u8; 4] = b"DSPT";
pub const KIND_DSND: &[u8; 4] = b"DSND";

pub type Why = &'static str;

pub fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
pub fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
pub fn u64_at(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}
pub fn zeros(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0)
}

/// 48-byte pointer: block number, birth generation, SHA-256 of the block.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ptr {
    pub addr: u64,
    pub birth: u64,
    pub sha: [u8; 32],
}

impl Ptr {
    /// `None` = the empty pointer (48 zero bytes).  `addr` 0 with anything else set
    /// is damage – one form of a hole on the disk.
    pub fn parse(b: &[u8]) -> Result<Option<Ptr>, Why> {
        let b = &b[..PTR_SIZE];
        let addr = u64_at(b, 0);
        if addr == 0 {
            return if zeros(b) { Ok(None) } else { Err("empty pointer with non-zero fields") };
        }
        let mut sha = [0u8; 32];
        sha.copy_from_slice(&b[16..48]);
        Ok(Some(Ptr { addr, birth: u64_at(b, 8), sha }))
    }
}

/// Superblock (blocks 1 and 2) after its own checks – magic, version, block size,
/// checksum, the zero areas, the label, a non-empty root.  Size checks against the
/// device are the caller's (they need the device).
#[derive(Clone, Debug)]
pub struct Superblock {
    pub uuid: [u8; 16],
    pub generation: u64,
    pub total_blocks: u64,
    pub used_blocks: u64,
    pub commit_time: u64,
    pub compat: u32,
    pub ro_compat: u32,
    pub incompat: u32,
    pub root: Ptr,
    pub label: [u8; 32],
}

impl Superblock {
    pub fn parse(b: &[u8]) -> Result<Superblock, Why> {
        if &b[0..8] != MAGIC {
            return Err("no DESOFS01 marker");
        }
        let sum = super::sha256(&b[..SB_CHECKSUM]);
        if sum[..] != b[SB_CHECKSUM..BLOCK] {
            return Err("superblock checksum does not match");
        }
        if u32_at(b, 8) != VERSION {
            return Err("unknown format version");
        }
        if u32_at(b, 12) != BLOCK as u32 {
            return Err("block size is not 4096");
        }
        if !zeros(&b[76..80]) || !zeros(&b[160..SB_CHECKSUM]) {
            return Err("superblock: reserved bytes not zero");
        }
        let mut label = [0u8; 32];
        label.copy_from_slice(&b[128..160]);
        let end = label.iter().position(|&c| c == 0).unwrap_or(32);
        if core::str::from_utf8(&label[..end]).is_err() || !zeros(&label[end..]) {
            return Err("label is not UTF-8 followed by zeros");
        }
        let root = Ptr::parse(&b[80..128])?.ok_or("superblock: empty root pointer")?;
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&b[16..32]);
        Ok(Superblock {
            uuid,
            generation: u64_at(b, 32),
            total_blocks: u64_at(b, 40),
            used_blocks: u64_at(b, 48),
            commit_time: u64_at(b, 56),
            compat: u32_at(b, 64),
            ro_compat: u32_at(b, 68),
            incompat: u32_at(b, 72),
            root,
            label,
        })
    }

    pub fn label_str(&self) -> &str {
        let end = self.label.iter().position(|&c| c == 0).unwrap_or(32);
        core::str::from_utf8(&self.label[..end]).unwrap_or("")
    }
}

/// Header of a metadata block (first 64 bytes).
pub fn check_header(b: &[u8], kind: &[u8; 4], level: u8, birth: u64, addr: u64, uuid: &[u8; 16]) -> Result<u16, Why> {
    if &b[0..4] != kind {
        return Err("block of the wrong kind");
    }
    if b[4] != level {
        return Err("block at the wrong level");
    }
    if b[5] != 0 || !zeros(&b[40..HDR_SIZE]) {
        return Err("header: reserved bytes not zero");
    }
    if u64_at(b, 8) != birth {
        return Err("header generation differs from the pointer's birth");
    }
    if u64_at(b, 16) != addr {
        return Err("header self address differs (block written to a wrong place)");
    }
    if &b[24..40] != uuid {
        return Err("header uuid differs (block of another volume)");
    }
    Ok(u16_at(b, 6))
}

/// Capacity of a data tree in blocks: depth 0 = 4 direct pointers, d = 84^d.
pub fn capacity(depth: u8) -> u64 {
    if depth == 0 { 4 } else { (FANOUT as u64).pow(depth as u32) }
}

/// The smallest depth that holds `blocks` (one form on the disk).
pub fn min_depth(blocks: u64) -> u8 {
    let mut d = 0;
    while d < MAX_DEPTH && capacity(d) < blocks {
        d += 1;
    }
    d
}

pub const TYPE_FILE: u8 = 1;
pub const TYPE_DIR: u8 = 2;

/// An occupied node after the format-1 checks (docs/desofs/FORMAT.md chapter 7).
#[derive(Clone, Copy, Debug)]
pub struct Node {
    pub number: u64,
    pub typ: u8,
    pub depth: u8,
    pub size: u64,
    pub parent: u64,
    pub node_gen: u64,
    pub modified: u64,
}

impl Node {
    /// `None` = free slot (all 256 bytes zero).
    pub fn parse(b: &[u8], number: u64, sb_gen: u64) -> Result<Option<Node>, Why> {
        let b = &b[..NODE_SIZE];
        let typ = b[8];
        if typ == 0 {
            return if zeros(b) { Ok(None) } else { Err("free node with non-zero bytes") };
        }
        if number == 0 {
            return Err("node 0 is in use");
        }
        if u64_at(b, 0) != number {
            return Err("node number differs from its place in the table");
        }
        if typ != TYPE_FILE && typ != TYPE_DIR {
            return Err("unknown node type");
        }
        let depth = b[9];
        if depth > MAX_DEPTH {
            return Err("node depth over 5");
        }
        if u16_at(b, 10) != 0 {
            return Err("node flags not 0 (format 1)");
        }
        if u32_at(b, 12) != 1 {
            return Err("node links not 1 (format 1)");
        }
        let size = u64_at(b, 16);
        let blocks = size.div_ceil(BLOCK as u64);
        if blocks > capacity(depth) {
            return Err("node size over the capacity of its depth");
        }
        if depth != min_depth(blocks) {
            return Err("node depth is not the smallest that holds its size");
        }
        if typ == TYPE_DIR && size % BLOCK as u64 != 0 {
            return Err("directory size not a multiple of 4096");
        }
        let parent = u64_at(b, 40);
        if parent == 0 {
            return Err("node parent is 0");
        }
        let node_gen = u64_at(b, 48);
        if node_gen == 0 || node_gen > sb_gen {
            return Err("node_gen outside 1..=generation");
        }
        if depth >= 1 && !zeros(&b[56 + PTR_SIZE..248]) {
            return Err("node data after the tree root not zero");
        }
        if !zeros(&b[248..NODE_SIZE]) {
            return Err("node: reserved bytes not zero");
        }
        if number == 1 && (typ != TYPE_DIR || parent != 1) {
            return Err("node 1 is not the root directory with parent 1");
        }
        Ok(Some(Node { number, typ, depth, size, parent, node_gen, modified: u64_at(b, 32) }))
    }

    pub fn blocks(&self) -> u64 {
        self.size.div_ceil(BLOCK as u64)
    }
}

/// One root-block entry (docs/desofs/FORMAT.md chapter 5).
#[derive(Clone, Copy, Debug)]
pub struct RootEntry {
    pub kind: u8,
    pub nodes: Ptr,
    pub depth: u8,
    pub next_node: u64,
    pub created_gen: u64,
    pub name: [u8; 24],
}

pub const ROOT_LIVE: u8 = 1;
pub const ROOT_SNAPSHOT: u8 = 2;

impl RootEntry {
    /// `None` = empty entry (96 zero bytes).
    pub fn parse(b: &[u8], index: usize, sb_gen: u64) -> Result<Option<RootEntry>, Why> {
        let b = &b[..ROOT_ENTRY];
        let kind = b[49];
        if kind == 0 {
            if index == 0 {
                return Err("root entry 0 (the live file system) is empty");
            }
            return if zeros(b) { Ok(None) } else { Err("empty root entry with non-zero bytes") };
        }
        match (index, kind) {
            (0, ROOT_LIVE) => {}
            (0, _) => return Err("root entry 0 is not the live file system"),
            (_, ROOT_SNAPSHOT) => {}
            _ => return Err("root entry of a wrong kind"),
        }
        if !zeros(&b[50..56]) {
            return Err("root entry: reserved bytes not zero");
        }
        let nodes = Ptr::parse(&b[0..48])?.ok_or("root entry: empty node-table pointer")?;
        let depth = b[48];
        if depth == 0 || depth > MAX_DEPTH {
            return Err("node-table depth outside 1..5");
        }
        let next_node = u64_at(b, 56);
        if next_node < 2 {
            return Err("next_node below 2");
        }
        let created_gen = u64_at(b, 64);
        let mut name = [0u8; 24];
        name.copy_from_slice(&b[72..96]);
        if kind == ROOT_LIVE {
            if created_gen != 0 || !zeros(&name) {
                return Err("live root entry with a name or created_gen");
            }
        } else {
            if created_gen == 0 || created_gen > sb_gen {
                return Err("snapshot created_gen outside 1..=generation");
            }
            let end = name.iter().position(|&c| c == 0).unwrap_or(24);
            let ok = end > 0
                && core::str::from_utf8(&name[..end]).is_ok()
                && !name[..end].contains(&b'/')
                && zeros(&name[end..]);
            if !ok {
                return Err("snapshot name not non-empty UTF-8 without '/' followed by zeros");
            }
        }
        Ok(Some(RootEntry { kind, nodes, depth, next_node, created_gen, name }))
    }
}

/// Checks one directory block (docs/desofs/FORMAT.md chapter 8) and calls `entry(node,
/// type, name)` for every occupied entry; returns how many there were.  Entries
/// must cover the block exactly; deleted entries and padding must be zeros.
pub fn check_dir_block(b: &[u8], mut entry: impl FnMut(u64, u8, &[u8]) -> Result<(), Why>) -> Result<usize, Why> {
    let mut off = 0;
    let mut active = 0;
    while off < BLOCK {
        if off + 12 > BLOCK {
            return Err("directory entry header past the block end");
        }
        let node = u64_at(b, off);
        let typ = b[off + 8];
        let name_len = b[off + 9] as usize;
        let rec = u16_at(b, off + 10) as usize;
        if rec < 16 || rec % 8 != 0 || off + rec > BLOCK {
            return Err("directory entry length wrong");
        }
        let e = &b[off..off + rec];
        if node == 0 {
            if !zeros(&e[0..10]) || !zeros(&e[12..]) {
                return Err("deleted directory entry not zeroed");
            }
        } else {
            if typ != TYPE_FILE && typ != TYPE_DIR {
                return Err("directory entry of an unknown type");
            }
            if name_len == 0 || 12 + name_len > rec {
                return Err("directory entry name length wrong");
            }
            let name = &e[12..12 + name_len];
            if core::str::from_utf8(name).is_err() || name.contains(&b'/') || name.contains(&0) {
                return Err("directory entry name not UTF-8 without '/' and NUL");
            }
            if name == b"." || name == b".." {
                return Err("directory entry named . or ..");
            }
            if !zeros(&e[12 + name_len..]) {
                return Err("directory entry padding not zero");
            }
            entry(node, typ, name)?;
            active += 1;
        }
        off += rec;
    }
    Ok(active)
}
