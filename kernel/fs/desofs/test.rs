// DESOFS TEST – DeSoFS format 1, stage 1: the read-only check of a volume.
//
// The reference image comes from tests/mkdesofs.py – an independent implementation
// of the format written from docs/DESOFS-FORMAT.md – so the kernel and the script
// must agree on every byte.  Then copies of it are broken in each way the
// specification forbids; most changes are "resealed" (every checksum above the change
// recomputed), so the check has to catch the rule itself, not just a bad checksum.
// Nothing is written to a real disk: every image lives in a RAM disk.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use super::layout::*;
use super::{probe, sha256, Report, State};
use crate::block::{self, RamDisk, SECTOR_SIZE};
use crate::serial_println;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[DESOFS TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

// ---------------- image helpers ----------------

pub(super) fn blk(img: &mut [u8], n: u64) -> &mut [u8] {
    &mut img[n as usize * BLOCK..(n as usize + 1) * BLOCK]
}
pub(super) fn rd(img: &[u8], n: u64) -> &[u8] {
    &img[n as usize * BLOCK..(n as usize + 1) * BLOCK]
}
pub(super) fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
pub(super) fn ptr_addr(img: &[u8], n: u64, off: usize) -> u64 {
    u64_at(rd(img, n), off)
}
/// A correct pointer to block `addr` with `birth`.
fn make_ptr(img: &[u8], addr: u64, birth: u64) -> [u8; 48] {
    let mut p = [0u8; 48];
    p[0..8].copy_from_slice(&addr.to_le_bytes());
    p[8..16].copy_from_slice(&birth.to_le_bytes());
    p[16..48].copy_from_slice(&sha256(rd(img, addr)));
    p
}

/// Superblock checksum and root-pointer checksum of `slot` (1 or 2), nothing else.
pub(super) fn seal_sb(img: &mut [u8], slot: u64) {
    let root = ptr_addr(img, slot, 80);
    if root > 0 && (root as usize) < img.len() / BLOCK {
        let h = sha256(rd(img, root));
        blk(img, slot)[96..128].copy_from_slice(&h);
    }
    let sum = sha256(&rd(img, slot)[..SB_CHECKSUM]);
    blk(img, slot)[SB_CHECKSUM..BLOCK].copy_from_slice(&sum);
}

/// Recomputes every pointer checksum below `addr` (children first), up to 16 levels –
/// enough for any real tree, and it stops on the loops some tests make on purpose.
fn fix(img: &mut [u8], addr: u64, guard: u32) {
    let blocks = (img.len() / BLOCK) as u64;
    if addr < RESERVED || addr >= blocks || guard > 16 {
        return;
    }
    let kind: [u8; 4] = rd(img, addr)[0..4].try_into().unwrap();
    let mut slots: Vec<usize> = Vec::new(); // offsets of child pointers
    if &kind == KIND_DSRT {
        for i in 0..ROOT_ENTRIES {
            let o = HDR_SIZE + i * ROOT_ENTRY;
            if rd(img, addr)[o + 49] != 0 {
                slots.push(o);
            }
        }
    } else if &kind == KIND_DSPT {
        for i in 0..FANOUT {
            slots.push(HDR_SIZE + i * PTR_SIZE);
        }
    } else if &kind == KIND_DSND {
        for s in 0..NODES_PER_BLOCK as usize {
            let o = HDR_SIZE + s * NODE_SIZE;
            let b = rd(img, addr);
            if b[o + 8] == 0 {
                continue;
            }
            let n = if b[o + 9] == 0 { 4 } else { 1 };
            for k in 0..n {
                slots.push(o + 56 + k * PTR_SIZE);
            }
        }
    } else {
        return; // data
    }
    for o in slots {
        let child = ptr_addr(img, addr, o);
        if child == 0 || child >= blocks {
            continue;
        }
        fix(img, child, guard + 1);
        let h = sha256(rd(img, child));
        blk(img, addr)[o + 16..o + 48].copy_from_slice(&h);
    }
}

/// Reseals both superblocks (those that still carry the marker).
pub(super) fn reseal(img: &mut [u8]) {
    for slot in [1u64, 2] {
        if &rd(img, slot)[0..8] == MAGIC {
            let root = ptr_addr(img, slot, 80);
            fix(img, root, 0);
            seal_sb(img, slot);
        }
    }
}

/// Probes `img` on a RAM disk of `sectors` sectors (the image is cut to fit).
fn run_dev(img: &[u8], sectors: u64) -> Report {
    let disk = block::register(Box::new(RamDisk::new("dsfs", sectors)));
    let n = (img.len()).min(sectors as usize * SECTOR_SIZE);
    let _ = block::write(disk, 0, &img[..n]);
    let r = probe(disk);
    block::remove(disk);
    r
}
fn run(img: &[u8]) -> Report {
    run_dev(img, (img.len() / SECTOR_SIZE) as u64)
}

fn refused(r: &Report, part: &str) -> bool {
    matches!(&r.state, State::Refused(w) if w.contains(part))
}
fn read_only(r: &Report, part: &str) -> bool {
    matches!(&r.state, State::ReadOnly(w) if w.contains(part))
}
fn why(r: &Report) -> String {
    match &r.state {
        State::ReadWrite => String::from("read-write"),
        State::ReadOnly(w) => alloc::format!("read-only: {}", w),
        State::Refused(w) => alloc::format!("refused: {}", w),
    }
}

/// Where things are in the reference image (found by following its pointers).
pub(super) struct Map {
    pub(super) rt4: u64,
    pub(super) rt5: u64,
    pub(super) nt5: u64,
    pub(super) nd4: u64,
    pub(super) nd5: u64,
    pub(super) big: u64,
    pub(super) hello5: u64,
    pub(super) a_txt: u64,
    pub(super) root_dir: u64,
    pub(super) sub_dir: u64,
}

pub(super) fn node_off(slot: usize) -> usize {
    HDR_SIZE + slot * NODE_SIZE
}

pub(super) fn locate(img: &[u8]) -> Map {
    let rt4 = ptr_addr(img, 1, 80);
    let rt5 = ptr_addr(img, 2, 80);
    let nt5 = ptr_addr(img, rt5, HDR_SIZE);
    let nt4 = ptr_addr(img, rt4, HDR_SIZE);
    let nd5 = ptr_addr(img, nt5, HDR_SIZE);
    let nd4 = ptr_addr(img, nt4, HDR_SIZE);
    let data = |slot: usize| ptr_addr(img, nd5, node_off(slot) + 56);
    Map { rt4, rt5, nt5, nd4, nd5, big: data(3), hello5: data(2), a_txt: data(5), root_dir: data(1), sub_dir: data(4) }
}

/// A copy with only superblock B (A zeroed) – any damage in B's tree is then a refusal.
fn single(base: &[u8]) -> Vec<u8> {
    let mut v = base.to_vec();
    blk(&mut v, 1).fill(0);
    v
}

pub fn self_test() {
    serial_println!("[DESOFS TEST] Starting DeSoFS format 1 tests (read-only volume check)...");
    crate::selftest::begin();
    let base: &[u8] = crate::initrd::DESOFS_REF;
    check!(base.len() == 128 * BLOCK, "reference image missing ({} bytes; build.sh runs tests/mkdesofs.py)", base.len());
    let m = locate(base);

    // 1. The reference image from the independent Python implementation: read-write,
    // newer superblock B (generation 5), next commit to A, 5 nodes, 1 snapshot, the
    // counted blocks equal used_blocks (shared blocks counted once).  A tie (A = copy
    // of B) is accepted and the next commit then goes to B.
    let r = run(base);
    check!(r.state == State::ReadWrite, "reference image: {}", why(&r));
    check!(r.slot == 2 && r.next_slot == 1 && r.generation == 5, "reference: slot {} next {} gen {}", r.slot, r.next_slot, r.generation);
    check!(r.nodes == 5 && r.snapshots == 1 && r.label == "DESOFS-TEST", "reference: {} nodes, {} snapshots, label {:?}", r.nodes, r.snapshots, r.label);
    check!(r.used_counted == Some(31) && r.used_stored == 31 && r.warnings.is_empty(), "reference: used {:?}/{} {:?}", r.used_counted, r.used_stored, r.warnings);
    check!(r.map_bytes == 128 + 16, "map bytes {} for 128 blocks (expected 144)", r.map_bytes);
    let mut img = base.to_vec();
    let b2 = rd(&img, 2).to_vec();
    blk(&mut img, 1).copy_from_slice(&b2);
    let r = run(&img);
    check!(r.state == State::ReadWrite && r.slot == 2 && r.next_slot == 2, "tie: {} slot {} next {}", why(&r), r.slot, r.next_slot);
    serial_println!("[DESOFS TEST] 1/22 reference image (tests/mkdesofs.py): read-write, generation 5 in B, {} nodes, {} snapshot, {} blocks used, next commit to A; tie -> next to B PASS", 5, 1, 31);

    // 2. Superblocks.
    let mut cases: u32 = 0;
    macro_rules! sb_case {
        ($name:expr, $edit:expr, $ok:expr) => {{
            let mut img = base.to_vec();
            #[allow(clippy::redundant_closure_call)]
            ($edit)(&mut img);
            let r = run(&img);
            check!(($ok)(&r), "{}: {}", $name, why(&r));
            cases += 1;
        }};
    }
    let only_a = |r: &Report| r.state == State::ReadWrite && r.slot == 1 && r.generation == 4 && r.next_slot == 2 && r.used_counted == Some(28) && r.snapshots == 0;
    sb_case!("no file system", |i: &mut Vec<u8>| i.fill(0), |r: &Report| refused(r, "not a DeSoFS"));
    sb_case!("random bytes", |i: &mut Vec<u8>| for (k, b) in i.iter_mut().enumerate() { *b = (k as u32).wrapping_mul(2654435761).to_le_bytes()[2] }, |r: &Report| refused(r, "not a DeSoFS"));
    sb_case!("B checksum broken", |i: &mut Vec<u8>| blk(i, 2)[200] ^= 1, only_a);
    sb_case!("both checksums broken", |i: &mut Vec<u8>| { blk(i, 1)[200] ^= 1; blk(i, 2)[200] ^= 1 }, |r: &Report| refused(r, "not a DeSoFS"));
    sb_case!("different uuid", |i: &mut Vec<u8>| { blk(i, 1)[16] ^= 1; seal_sb(i, 1) }, |r: &Report| refused(r, "uuid"));
    sb_case!("same generation, other root", |i: &mut Vec<u8>| { put64(blk(i, 1), 32, 5); seal_sb(i, 1) }, |r: &Report| refused(r, "same generation"));
    sb_case!("version 2 in B", |i: &mut Vec<u8>| { put32(blk(i, 2), 8, 2); seal_sb(i, 2) }, only_a);
    sb_case!("block size 8192 in B", |i: &mut Vec<u8>| { put32(blk(i, 2), 12, 8192); seal_sb(i, 2) }, only_a);
    sb_case!("unknown incompat feature", |i: &mut Vec<u8>| { put32(blk(i, 2), 72, 1); seal_sb(i, 2) }, |r: &Report| refused(r, "incompatible"));
    sb_case!("unknown ro_compat feature", |i: &mut Vec<u8>| { put32(blk(i, 2), 68, 1); seal_sb(i, 2) }, |r: &Report| read_only(r, "read-only-compatible"));
    sb_case!("63 blocks", |i: &mut Vec<u8>| { for s in [1, 2] { put64(blk(i, s), 40, 63); seal_sb(i, s) } }, |r: &Report| refused(r, "smaller than 64"));
    sb_case!("sizes differ", |i: &mut Vec<u8>| { put64(blk(i, 1), 40, 63); seal_sb(i, 1) }, |r: &Report| refused(r, "disagree"));
    sb_case!("label not UTF-8", |i: &mut Vec<u8>| { blk(i, 2)[128] = 0xFF; seal_sb(i, 2) }, only_a);
    sb_case!("label garbage after NUL", |i: &mut Vec<u8>| { blk(i, 2)[150] = b'x'; seal_sb(i, 2) }, only_a);
    sb_case!("reserved bytes in B", |i: &mut Vec<u8>| { blk(i, 2)[3000] = 1; seal_sb(i, 2) }, only_a);
    sb_case!("empty root in B", |i: &mut Vec<u8>| { blk(i, 2)[80..128].fill(0); seal_sb(i, 2) }, only_a);
    // Volume larger than the device (a 48-block disk).
    let r = run_dev(base, 48 * 8);
    check!(refused(&r, "larger than the device"), "volume > device: {}", why(&r));
    cases += 1;
    serial_println!("[DESOFS TEST] 2/22 superblocks: {} cases (marker, checksum, uuid, same generation, version, block size, features, size limits, label, reserved bytes, empty root) PASS", cases);

    // 3. Pointers and block headers (single superblock: damage = refusal).
    cases = 0;
    macro_rules! case {
        ($name:expr, $part:expr, $edit:expr) => {{
            let mut img = single(base);
            #[allow(clippy::redundant_closure_call)]
            ($edit)(&mut img);
            let r = run(&img);
            check!(refused(&r, $part), "{}: {} (expected refusal with {:?})", $name, why(&r), $part);
            cases += 1;
        }};
    }
    let n2 = node_off(2) + 56; // node 2 (hello.txt) data
    case!("pointer into blocks 0-15", "blocks 0-15", |i: &mut Vec<u8>| { put64(blk(i, m.nd5), n2, 5); reseal(i) });
    case!("pointer past the volume", "outside the volume", |i: &mut Vec<u8>| { put64(blk(i, m.nd5), n2, 128); reseal(i) });
    case!("empty pointer with a birth", "empty pointer with non-zero", |i: &mut Vec<u8>| { put64(blk(i, m.nd5), n2 + 48 + 8, 7); reseal(i) });
    case!("data birth 0", "birth outside", |i: &mut Vec<u8>| { put64(blk(i, m.nd5), n2 + 8, 0); reseal(i) });
    case!("data birth from the future", "birth outside", |i: &mut Vec<u8>| { put64(blk(i, m.nd5), n2 + 8, 6); reseal(i) });
    case!("metadata birth from the future", "birth outside", |i: &mut Vec<u8>| { put64(blk(i, m.rt5), HDR_SIZE + 8, 6); reseal(i) });
    case!("wrong kind", "wrong kind", |i: &mut Vec<u8>| { blk(i, m.nd5)[0..4].copy_from_slice(KIND_DSPT); reseal(i) });
    case!("wrong level", "wrong level", |i: &mut Vec<u8>| { blk(i, m.nt5)[4] = 2; reseal(i) });
    case!("wrong count", "count differs", |i: &mut Vec<u8>| { blk(i, m.nd5)[6] = 4; reseal(i) });
    case!("wrong self address", "self address", |i: &mut Vec<u8>| { put64(blk(i, m.nd5), 16, 40); reseal(i) });
    case!("foreign uuid", "uuid differs", |i: &mut Vec<u8>| { blk(i, m.nd5)[30] ^= 1; reseal(i) });
    case!("generation != birth", "generation differs", |i: &mut Vec<u8>| { put64(blk(i, m.nd5), 8, 4); reseal(i) });
    case!("header reserved bytes", "reserved bytes", |i: &mut Vec<u8>| { blk(i, m.nd5)[50] = 1; reseal(i) });
    case!("checksum (not resealed)", "checksum does not match", |i: &mut Vec<u8>| blk(i, m.nd5)[node_off(2) + 24] ^= 1);
    case!("pointer block without pointers", "without any pointer", |i: &mut Vec<u8>| { blk(i, m.big)[HDR_SIZE..].fill(0); blk(i, m.big)[6] = 0; reseal(i) });
    serial_println!("[DESOFS TEST] 3/22 pointers and headers: {} cases (range, reserved blocks, empty-pointer form, birth for data and metadata, kind, level, count, self address, uuid, generation, padding, checksum, empty pointer block) PASS", cases);

    // 4. Tree structure: a block twice in one tree, the same block as data and metadata
    // (both orders), a loop, a shared block of another kind, holes, pointers past the size.
    cases = 0;
    let n5 = node_off(5) + 56;
    case!("data block twice in one tree", "twice in one tree", |i: &mut Vec<u8>| { let p = make_ptr(i, m.hello5, 5); blk(i, m.nd5)[n5..n5 + 48].copy_from_slice(&p); reseal(i) });
    case!("data first, then metadata", "both as data and as metadata", |i: &mut Vec<u8>| { let p = make_ptr(i, m.nd4, 4); blk(i, m.nd5)[n2..n2 + 48].copy_from_slice(&p); reseal(i) });
    case!("metadata first, then data", "both as data and as metadata", |i: &mut Vec<u8>| { let o = node_off(2) + 56; let p = make_ptr(i, m.nd5, 5); blk(i, m.nd4)[o..o + 48].copy_from_slice(&p); reseal(i) });
    case!("loop to an ancestor", "twice in one tree", |i: &mut Vec<u8>| { let o = node_off(3) + 56; let p = make_ptr(i, m.nt5, 5); blk(i, m.nd5)[o..o + 48].copy_from_slice(&p); reseal(i) });
    case!("shared block of another kind", "different kind or level", |i: &mut Vec<u8>| { let o = HDR_SIZE + ROOT_ENTRY; let p = make_ptr(i, m.nd5, 5); blk(i, m.rt5)[o..o + 48].copy_from_slice(&p); reseal(i) });
    case!("hole in a directory", "hole in a directory", |i: &mut Vec<u8>| { let o = node_off(1) + 56; blk(i, m.nd5)[o..o + 48].fill(0); reseal(i) });
    case!("direct pointer past the size", "beyond the file size", |i: &mut Vec<u8>| { let p = make_ptr(i, m.a_txt, 4); blk(i, m.nd5)[n2 + 48..n2 + 96].copy_from_slice(&p); reseal(i) });
    case!("tree pointer past the size", "beyond the file size", |i: &mut Vec<u8>| { let src = HDR_SIZE; let dst = HDR_SIZE + 30 * PTR_SIZE; let p: [u8; 48] = rd(i, m.big)[src..src + 48].try_into().unwrap(); blk(i, m.big)[dst..dst + 48].copy_from_slice(&p); blk(i, m.big)[6] += 1; reseal(i) });
    serial_println!("[DESOFS TEST] 4/22 tree structure: {} cases (block twice in a tree, data/metadata in both orders, loop, shared block of another kind, directory hole, pointers past the size at depth 0 and 1) PASS", cases);

    // 5. Nodes and root entries.
    cases = 0;
    let nd = |slot: usize, at: usize| node_off(slot) + at;
    case!("flags", "flags not 0", |i: &mut Vec<u8>| { blk(i, m.nd5)[nd(2, 10)] = 1; reseal(i) });
    case!("links", "links not 1", |i: &mut Vec<u8>| { blk(i, m.nd5)[nd(2, 12)] = 2; reseal(i) });
    case!("node_gen 0", "node_gen outside", |i: &mut Vec<u8>| { put64(blk(i, m.nd5), nd(2, 48), 0); reseal(i) });
    case!("node_gen from the future", "node_gen outside", |i: &mut Vec<u8>| { put64(blk(i, m.nd5), nd(2, 48), 6); reseal(i) });
    case!("depth 6", "depth over 5", |i: &mut Vec<u8>| { blk(i, m.nd5)[nd(2, 9)] = 6; reseal(i) });
    case!("depth not the smallest", "not the smallest", |i: &mut Vec<u8>| { blk(i, m.nd5)[nd(2, 9)] = 1; reseal(i) });
    case!("size over capacity", "over the capacity", |i: &mut Vec<u8>| { put64(blk(i, m.nd5), nd(2, 16), 17 * 4096); reseal(i) });
    case!("number not its place", "differs from its place", |i: &mut Vec<u8>| { put64(blk(i, m.nd5), nd(2, 0), 9); reseal(i) });
    case!("unknown type", "unknown node type", |i: &mut Vec<u8>| { blk(i, m.nd5)[nd(2, 8)] = 3; reseal(i) });
    case!("directory size", "multiple of 4096", |i: &mut Vec<u8>| { put64(blk(i, m.nd5), nd(4, 16), 100); reseal(i) });
    case!("data after the tree root", "after the tree root", |i: &mut Vec<u8>| { blk(i, m.nd5)[nd(3, 56 + 48)] = 1; reseal(i) });
    case!("node 1 a file", "node 1 is not", |i: &mut Vec<u8>| { blk(i, m.nd5)[nd(1, 8)] = 1; put64(blk(i, m.nd5), nd(1, 16), 13); reseal(i) });
    case!("node 1 parent 2", "node 1 is not", |i: &mut Vec<u8>| { put64(blk(i, m.nd5), nd(1, 40), 2); reseal(i) });
    case!("no node 1", "no root directory", |i: &mut Vec<u8>| { blk(i, m.nd5)[node_off(1)..node_off(2)].fill(0); blk(i, m.nd5)[6] = 4; reseal(i) });
    case!("node 0 in use", "node 0 is in use", |i: &mut Vec<u8>| { blk(i, m.nd5)[nd(0, 8)] = 1; reseal(i) });
    case!("garbage in a free node", "free node with non-zero", |i: &mut Vec<u8>| { blk(i, m.nd5)[nd(7, 100)] = 1; reseal(i) });
    case!("parent 0", "parent is 0", |i: &mut Vec<u8>| { put64(blk(i, m.nd5), nd(2, 40), 0); reseal(i) });
    case!("empty node block (errata E4)", "without any node", |i: &mut Vec<u8>| {
        // A node block with no node at all (block 100 is free in the reference image),
        // linked as the second leaf of the live node table.
        let hdr: Vec<u8> = rd(i, m.nd5)[..HDR_SIZE].to_vec();
        let b = blk(i, 100);
        b.fill(0);
        b[..HDR_SIZE].copy_from_slice(&hdr);
        b[6] = 0;
        b[16..24].copy_from_slice(&100u64.to_le_bytes());
        let p = make_ptr(i, 100, 5);
        let o = HDR_SIZE + PTR_SIZE;
        blk(i, m.nt5)[o..o + 48].copy_from_slice(&p);
        blk(i, m.nt5)[6] = 2;
        reseal(i)
    });
    case!("node block tail", "tail not zero", |i: &mut Vec<u8>| { blk(i, m.nd5)[4000] = 1; reseal(i) });
    case!("next_node 1", "below 2", |i: &mut Vec<u8>| { put64(blk(i, m.rt5), HDR_SIZE + 56, 1); reseal(i) });
    case!("next_node not above the nodes", "next_node not above", |i: &mut Vec<u8>| { put64(blk(i, m.rt5), HDR_SIZE + 56, 5); reseal(i) });
    case!("parent >= next_node", "next_node not above", |i: &mut Vec<u8>| { put64(blk(i, m.nd5), nd(5, 40), 9); reseal(i) });
    let e1 = HDR_SIZE + ROOT_ENTRY;
    case!("second live root", "wrong kind", |i: &mut Vec<u8>| { blk(i, m.rt5)[e1 + 49] = 1; reseal(i) });
    case!("garbage in an empty root entry", "empty root entry", |i: &mut Vec<u8>| { blk(i, m.rt5)[HDR_SIZE + 5 * ROOT_ENTRY + 10] = 1; reseal(i) });
    case!("table depth != level", "wrong level", |i: &mut Vec<u8>| { blk(i, m.rt5)[HDR_SIZE + 48] = 2; reseal(i) });
    case!("snapshot without a name", "snapshot name", |i: &mut Vec<u8>| { blk(i, m.rt5)[e1 + 72..e1 + 96].fill(0); reseal(i) });
    case!("snapshot name with /", "snapshot name", |i: &mut Vec<u8>| { blk(i, m.rt5)[e1 + 74] = b'/'; reseal(i) });
    case!("snapshot name garbage", "snapshot name", |i: &mut Vec<u8>| { blk(i, m.rt5)[e1 + 95] = b'x'; reseal(i) });
    case!("two snapshots, one name", "same name", |i: &mut Vec<u8>| { let e: Vec<u8> = rd(i, m.rt5)[e1..e1 + ROOT_ENTRY].to_vec(); let e2 = e1 + ROOT_ENTRY; blk(i, m.rt5)[e2..e2 + ROOT_ENTRY].copy_from_slice(&e); blk(i, m.rt5)[6] = 3; reseal(i) });
    case!("snapshot from the future", "created_gen", |i: &mut Vec<u8>| { put64(blk(i, m.rt5), e1 + 64, 6); reseal(i) });
    case!("live root with a name", "live root entry", |i: &mut Vec<u8>| { blk(i, m.rt5)[HDR_SIZE + 72] = b'x'; reseal(i) });
    case!("root block tail", "tail not zero", |i: &mut Vec<u8>| { blk(i, m.rt5)[4090] = 1; reseal(i) });
    serial_println!("[DESOFS TEST] 5/22 nodes and root entries: {} cases (flags, links, node_gen, depth, size, number, type, directory size, padding, node 0/1, parent, next_node, root-entry kinds, table depth, snapshot names, tails) PASS", cases);

    // 6. Two superblocks: damage in one tree only, in both, and metadata shared with
    // the older superblock met again with a wrong birth, a wrong checksum, or as
    // another kind (errata E1 – the block is read again and checked).
    cases = 0;
    macro_rules! two {
        ($name:expr, $edit:expr, $ok:expr) => {{
            let mut img = base.to_vec();
            #[allow(clippy::redundant_closure_call)]
            ($edit)(&mut img);
            let r = run(&img);
            check!(($ok)(&r), "{}: {}", $name, why(&r));
            cases += 1;
        }};
    }
    let ro_newer = |r: &Report| read_only(r, "older superblock's tree is damaged") && r.slot == 2 && r.generation == 5;
    two!("older tree damaged", |i: &mut Vec<u8>| { blk(i, m.rt4)[6] = 2; reseal(i) }, ro_newer);
    two!("newer tree damaged", |i: &mut Vec<u8>| { blk(i, m.nd5)[nd(2, 10)] = 1; reseal(i) },
        |r: &Report| read_only(r, "newer superblock's tree is damaged") && r.slot == 1 && r.generation == 4 && r.used_counted == Some(28) && r.warnings.is_empty());
    two!("both trees damaged", |i: &mut Vec<u8>| { blk(i, m.nd5)[nd(2, 10)] = 1; blk(i, m.rt4)[6] = 2; reseal(i) }, |r: &Report| refused(r, "both trees damaged"));
    two!("shared block met again: wrong birth", |i: &mut Vec<u8>| { put64(blk(i, m.rt4), HDR_SIZE + 8, 3); seal_sb(i, 1) }, ro_newer);
    two!("shared block met again: wrong checksum", |i: &mut Vec<u8>| { blk(i, m.rt4)[HDR_SIZE + 20] ^= 1; seal_sb(i, 1) }, ro_newer);
    two!("shared block met again as another kind", |i: &mut Vec<u8>| { let p = make_ptr(i, m.nd4, 4); blk(i, m.rt4)[HDR_SIZE..HDR_SIZE + 48].copy_from_slice(&p); seal_sb(i, 1) }, ro_newer);
    let r = run(base);
    check!(r.used_counted == Some(31), "shared subtrees counted more than once: {:?}", r.used_counted);
    cases += 1;
    serial_println!("[DESOFS TEST] 6/22 two superblocks: {} cases (older / newer / both trees damaged -> read-only newer / read-only older / refused; shared metadata from the older superblock re-read: wrong birth, wrong checksum, another kind -> read-only; shared blocks counted once) PASS", cases);

    // 7. Directory blocks (checked when a directory is used) and the map budget.
    let mut names: Vec<Vec<u8>> = Vec::new();
    let n = check_dir_block(rd(base, m.root_dir), |_, _, name| {
        names.push(name.to_vec());
        Ok(())
    });
    check!(n == Ok(3) && names == [b"hello.txt".to_vec(), b"big.bin".to_vec(), b"sub".to_vec()], "root directory: {:?} {:?}", n, names);
    check!(check_dir_block(rd(base, m.sub_dir), |_, _, _| Ok(())) == Ok(1), "sub directory");
    cases = 2;
    macro_rules! dir_case {
        ($name:expr, $part:expr, $edit:expr) => {{
            let mut b = rd(base, m.root_dir).to_vec();
            #[allow(clippy::redundant_closure_call)]
            ($edit)(&mut b);
            let r = check_dir_block(&b, |_, _, _| Ok(()));
            check!(matches!(r, Err(w) if w.contains($part)), "{}: {:?}", $name, r);
            cases += 1;
        }};
    }
    // First entry: node 2, "hello.txt" (9), rec 24; second at 24: "big.bin" (7), rec 24; third at 48.
    dir_case!("rec_len 8", "length wrong", |b: &mut Vec<u8>| b[10] = 8);
    dir_case!("rec_len not a multiple of 8", "length wrong", |b: &mut Vec<u8>| b[10] = 20);
    dir_case!("entry past the block", "length wrong", |b: &mut Vec<u8>| { let o = 48; b[o + 10..o + 12].copy_from_slice(&5000u16.to_le_bytes()) });
    dir_case!("entries short of the block", "length wrong", |b: &mut Vec<u8>| { let o = 48; b[o + 10..o + 12].copy_from_slice(&16u16.to_le_bytes()) });
    dir_case!("name .", ". or ..", |b: &mut Vec<u8>| { b[9] = 1; b[12..24].fill(0); b[12] = b'.' });
    dir_case!("name ..", ". or ..", |b: &mut Vec<u8>| { b[9] = 2; b[12..24].fill(0); b[12] = b'.'; b[13] = b'.' });
    dir_case!("name with /", "without '/'", |b: &mut Vec<u8>| b[14] = b'/');
    dir_case!("name with NUL", "without '/'", |b: &mut Vec<u8>| b[14] = 0);
    dir_case!("name not UTF-8", "not UTF-8", |b: &mut Vec<u8>| b[14] = 0xFF);
    dir_case!("padding", "padding not zero", |b: &mut Vec<u8>| b[23] = 1);
    dir_case!("deleted entry not zeroed", "not zeroed", |b: &mut Vec<u8>| b[0..8].fill(0));
    dir_case!("name length 0", "name length", |b: &mut Vec<u8>| b[9] = 0);
    dir_case!("unknown type", "unknown type", |b: &mut Vec<u8>| b[8] = 3);
    let r = check_dir_block(rd(base, m.root_dir), |_, _, name| if name == b"big.bin" { Err("duplicate name") } else { Ok(()) });
    check!(r == Err("duplicate name"), "caller's refusal not passed on: {:?}", r);
    // Errata E1: the two maps for the largest volume of format 1 now (64 GiB).
    let max_maps = MAX_BLOCKS_V1 + MAX_BLOCKS_V1.div_ceil(8);
    check!(max_maps == 18 << 20, "64 GiB map budget {} bytes (expected 18 MiB)", max_maps);
    serial_println!("[DESOFS TEST] 7/22 directory blocks: {} cases (valid blocks, lengths, coverage, . and .., '/', NUL, UTF-8, padding, deleted entry, type, caller refusal); maps: 144 B for 128 blocks, 18 MiB for 64 GiB PASS", cases);

    // 8-14: writing; 15-18: power loss; 19-22: check, repair, directories in parts.
    let steps: [(&str, fn() -> super::test_write::T); 15] = [
        ("format", super::test_write::t_format),
        ("files", super::test_write::t_files),
        ("directories", super::test_write::t_dirs),
        ("rename", super::test_write::t_rename),
        ("full disk", super::test_write::t_full),
        ("snapshot", super::test_write::t_snapshot),
        ("VFS, program, failing disk", super::test_write::t_vfs),
        ("power loss at every write", super::test_crash::t_points),
        ("power loss, writes reordered", super::test_crash::t_reorder),
        ("write / flush errors", super::test_crash::t_failures),
        ("power loss with a snapshot", super::test_crash::t_crash_snapshot),
        ("check, sound volumes", super::test_check::t_check_clean),
        ("check finds damage", super::test_check::t_check_damage),
        ("repair", super::test_check::t_repair),
        ("directories in parts", super::test_check::t_cursor),
    ];
    for (k, (name, f)) in steps.iter().enumerate() {
        match f() {
            Ok(line) => serial_println!("[DESOFS TEST] {}/22 {}: {} PASS", 8 + k, name, line),
            Err(e) => {
                serial_println!("[DESOFS TEST] FAIL: {}: {}", name, e);
                return;
            }
        }
    }
    serial_println!("[DESOFS TEST] All DeSoFS tests passed!");
    crate::selftest::pass();
}
