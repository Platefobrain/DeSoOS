// Block cache of a DeSoFS volume (one per mounted volume or snapshot view).
//
// * A block is found by its address AND the SHA-256 its parent's pointer holds.  Copy-on-
//   write never overwrites a live block, and an address used again later carries another
//   checksum – so nothing ever has to be invalidated: an entry whose checksum does not
//   match the pointer is stale and is dropped on sight.
// * A hit is still checked: the volume computes the SHA-256 of the copy again and checks the
//   header (kind, level, generation, address, uuid) exactly as for a block read from the
//   disk.  A copy that fails is dropped and the block read from the disk (`bad` counter).
//   What a hit cannot see: the disk copy going bad AFTER the block was cached – `desofs
//   check` / `repair` read the disk itself, never this cache.
// * What enters: a block read from the disk after its checks passed; the blocks a commit
//   wrote, only after its second flush (the operation is on the disk) – never anything
//   uncommitted.
// * Memory: block contents in 4 KiB physical frames, the index (slots + hash table) on the
//   heap.  ONE global budget for every cache together – min(1/16 of memory, 64 MiB) –
//   counts the frames and the capacity of the index structures; it is reserved atomically
//   BEFORE anything is allocated (several volumes at once cannot pass it).  No new frame
//   while free memory is below 1/8 of it (or the kernel's reserve).  Dropping the cache
//   (unmount) gives everything back.
// * Replacement: Clock.  A hit sets the slot's reference bit; the hand skips (and clears)
//   referenced slots.  Metadata enters referenced, data blocks not – a large file read once
//   goes out first and does not push out the directories and node tables.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

const BLOCK: usize = 4096;
const MAX_CAP: u64 = 64 * 1024 * 1024;

/// Bytes reserved by all caches together (frames + index capacity).
static USED: AtomicU64 = AtomicU64::new(0);
/// Test override of the limit (0 = the normal one).
static TEST_LIMIT: AtomicU64 = AtomicU64::new(0);

/// The global limit: min(1/16 of memory, 64 MiB).
pub fn limit() -> u64 {
    match TEST_LIMIT.load(Ordering::Relaxed) {
        0 => (crate::memory::total_frames() * 4096 / 16).min(MAX_CAP),
        t => t,
    }
}

/// Bytes all block caches hold now (`sysinfo counters`).
pub fn used() -> u64 {
    USED.load(Ordering::Relaxed)
}

#[cfg(selftest)]
pub fn set_test_limit(bytes: u64) {
    TEST_LIMIT.store(bytes, Ordering::SeqCst);
}

/// Takes `bytes` of the global budget, or nothing (compare-exchange: two volumes at once
/// never pass the limit together).
fn reserve(bytes: u64) -> bool {
    let lim = limit();
    let mut cur = USED.load(Ordering::Relaxed);
    loop {
        let Some(new) = cur.checked_add(bytes).filter(|&n| n <= lim) else { return false };
        match USED.compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(c) => cur = c,
        }
    }
}

fn release(bytes: u64) {
    USED.fetch_sub(bytes, Ordering::AcqRel);
}

/// Counters of one cache (also kept in the volume's `Prof`).
#[derive(Clone, Copy, Default, Debug)]
pub struct Stats {
    pub hits: u64,
    pub misses: u64,
    /// The address was there with another checksum (an address used again): dropped.
    pub stale: u64,
    /// A hit whose copy failed its SHA-256 / header check: dropped, read from the disk.
    pub bad: u64,
    pub inserts: u64,
    /// A new block put at an address cached with other contents (an address used again).
    pub replaced: u64,
    /// Inserts from commits (after the second flush).
    pub commit_inserts: u64,
    pub evictions: u64,
    /// Inserts given up (no budget, no frame, low memory).
    pub refused: u64,
}

#[derive(Clone, Copy)]
struct Slot {
    addr: u64,
    sha: [u8; 32],
    /// Physical frame holding the block (0 = an empty slot).
    frame: u64,
    referenced: bool,
}

const EMPTY: u32 = u32::MAX;

pub struct BlockCache {
    slots: Vec<Slot>,
    /// Open addressing (linear probing) over `slots`: slot index or EMPTY; size a power of
    /// two, at least twice the slot capacity.
    table: Vec<u32>,
    hand: usize,
    /// Slots without a block (left by a dropped entry) – reused before new ones.
    empty: usize,
    /// Bytes of the global budget this cache holds (frames + index capacity).
    held: u64,
    pub stats: Stats,
}

fn hash(addr: u64) -> usize {
    let mut z = addr.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    z ^= z >> 29;
    z as usize
}

fn page(frame: u64) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut(crate::memory::phys_to_virt(frame) as *mut u8, BLOCK) }
}

impl BlockCache {
    pub const fn new() -> BlockCache {
        BlockCache { slots: Vec::new(), table: Vec::new(), hand: 0, empty: 0, held: 0, stats: Stats { hits: 0, misses: 0, stale: 0, bad: 0, inserts: 0, replaced: 0, commit_inserts: 0, evictions: 0, refused: 0 } }
    }

    /// Bytes this cache holds of the global budget.
    pub fn held(&self) -> u64 {
        self.held
    }

    /// Heap the index really takes: the blocks the kernel heap hands out for these
    /// capacities (its size classes round up), not just the bytes asked for.
    fn index_bytes(slots: usize, table: usize) -> u64 {
        let b = crate::memory::heap_block_bytes;
        let s = if slots == 0 { 0 } else { b(slots * core::mem::size_of::<Slot>(), core::mem::align_of::<Slot>()) };
        let t = if table == 0 { 0 } else { b(table * core::mem::size_of::<u32>(), core::mem::align_of::<u32>()) };
        (s + t) as u64
    }

    fn find(&self, addr: u64) -> Option<(usize, usize)> {
        if self.table.is_empty() {
            return None;
        }
        let mask = self.table.len() - 1;
        let mut i = hash(addr) & mask;
        loop {
            let s = self.table[i];
            if s == EMPTY {
                return None;
            }
            if self.slots[s as usize].addr == addr && self.slots[s as usize].frame != 0 {
                return Some((i, s as usize));
            }
            i = (i + 1) & mask;
        }
    }

    /// Removes table position `i` (backward-shift deletion keeps the probe chains whole).
    fn unlink(&mut self, mut i: usize) {
        let mask = self.table.len() - 1;
        self.table[i] = EMPTY;
        let mut j = (i + 1) & mask;
        while self.table[j] != EMPTY {
            let s = self.table[j];
            let home = hash(self.slots[s as usize].addr) & mask;
            // Move j back to i when its home position is not in (i, j] (cyclically).
            let between = if i <= j { home > i && home <= j } else { home > i || home <= j };
            if !between {
                self.table[i] = s;
                self.table[j] = EMPTY;
                i = j;
            }
            j = (j + 1) & mask;
        }
    }

    fn link(&mut self, s: usize) {
        let mask = self.table.len() - 1;
        let mut i = hash(self.slots[s].addr) & mask;
        while self.table[i] != EMPTY {
            i = (i + 1) & mask;
        }
        self.table[i] = s as u32;
    }

    /// Frees slot `s` (its frame and its table position `ti`).
    fn drop_slot(&mut self, ti: usize, s: usize) {
        self.unlink(ti);
        crate::memory::free_frame(self.slots[s].frame);
        release(BLOCK as u64);
        self.held -= BLOCK as u64;
        self.slots[s].frame = 0;
        self.empty += 1;
    }

    /// Copy of block `addr` if the cache holds it with checksum `sha`; an entry with
    /// another checksum is stale and dropped.  The caller still verifies the copy.
    pub fn get(&mut self, addr: u64, sha: &[u8; 32], out: &mut [u8]) -> bool {
        match self.find(addr) {
            Some((_, s)) if self.slots[s].sha == *sha => {
                out[..BLOCK].copy_from_slice(page(self.slots[s].frame));
                self.slots[s].referenced = true;
                self.stats.hits += 1;
                true
            }
            Some((ti, s)) => {
                self.drop_slot(ti, s);
                self.stats.stale += 1;
                self.stats.misses += 1;
                false
            }
            None => {
                self.stats.misses += 1;
                false
            }
        }
    }

    /// A hit failed its check: the entry goes (the block is then read from the disk).
    pub fn reject(&mut self, addr: u64) {
        if let Some((ti, s)) = self.find(addr) {
            self.drop_slot(ti, s);
        }
        self.stats.bad += 1;
    }

    /// More slots (and a table for them) – reserved in the budget first.  Called only when
    /// every slot is in use (len == capacity).
    fn grow(&mut self) -> bool {
        let old_cap = self.slots.capacity();
        let new_cap = if old_cap == 0 { 64 } else { old_cap * 2 };
        let new_table = (new_cap * 2).next_power_of_two();
        let before = Self::index_bytes(old_cap, self.table.capacity());
        let after = Self::index_bytes(new_cap, new_table);
        if !reserve(after - before) {
            return false;
        }
        // The table first: if the slots then fail, nothing of the old index changed.
        let mut table: Vec<u32> = Vec::new();
        if table.try_reserve_exact(new_table).is_err() || self.slots.try_reserve_exact(new_cap - self.slots.len()).is_err() {
            release(after - before);
            return false;
        }
        // The budget follows what was really allocated (try_reserve_exact may give more).
        let real = Self::index_bytes(self.slots.capacity(), table.capacity());
        if real > after && !reserve(real - after) {
            self.slots.shrink_to(old_cap);
            release(after - before);
            let now = Self::index_bytes(self.slots.capacity(), self.table.capacity());
            // shrink_to may keep more than asked: whatever stays is counted (over the
            // limit only by that rounding, and given back at unmount).
            if now > before {
                USED.fetch_add(now - before, Ordering::AcqRel);
                self.held += now - before;
            }
            return false;
        }
        self.held += real.max(after) - before;
        table.resize(new_table, EMPTY);
        self.table = table;
        for s in 0..self.slots.len() {
            if self.slots[s].frame != 0 {
                self.link(s);
            }
        }
        true
    }

    /// Clock: the next unreferenced slot holding a block (clearing reference bits on the
    /// way); its frame is reused.  None when nothing holds a block.
    fn victim(&mut self) -> Option<usize> {
        let n = self.slots.len();
        if n == 0 {
            return None;
        }
        for _ in 0..2 * n {
            let s = self.hand % n;
            self.hand = (s + 1) % n;
            if self.slots[s].frame == 0 {
                continue;
            }
            if self.slots[s].referenced {
                self.slots[s].referenced = false;
                continue;
            }
            return Some(s);
        }
        None
    }

    /// A free slot with a frame for a new block: a new frame when the budget and memory
    /// allow, otherwise the Clock victim's frame.
    fn place(&mut self) -> Option<(usize, u64)> {
        let mem_ok = || {
            let free = crate::memory::free_frames_approx();
            free >= crate::memory::total_frames() / 8 && free >= crate::memory::user_reserve_frames()
        };
        if mem_ok() && reserve(BLOCK as u64) {
            if let Some(f) = crate::memory::alloc_frame() {
                self.held += BLOCK as u64;
                // An empty slot, or a new one.
                if self.empty > 0 {
                    if let Some(s) = self.slots.iter().position(|sl| sl.frame == 0) {
                        self.empty -= 1;
                        return Some((s, f));
                    }
                }
                if self.slots.len() < self.slots.capacity() || self.grow() {
                    self.slots.push(Slot { addr: 0, sha: [0; 32], frame: 0, referenced: false });
                    return Some((self.slots.len() - 1, f));
                }
                crate::memory::free_frame(f);
                release(BLOCK as u64);
                self.held -= BLOCK as u64;
            } else {
                release(BLOCK as u64);
            }
        }
        // Reuse the frame of a victim.
        let s = self.victim()?;
        let (ti, _) = self.find(self.slots[s].addr)?;
        self.unlink(ti);
        let f = self.slots[s].frame;
        self.slots[s].frame = 0;
        self.stats.evictions += 1;
        Some((s, f))
    }

    /// Keeps a verified block.  `meta`: metadata (enters referenced).
    pub fn insert(&mut self, addr: u64, sha: &[u8; 32], data: &[u8], meta: bool, from_commit: bool) {
        if let Some((ti, s)) = self.find(addr) {
            if self.slots[s].sha == *sha {
                return; // already there
            }
            self.drop_slot(ti, s);
            self.stats.replaced += 1;
        }
        let Some((s, f)) = self.place() else {
            self.stats.refused += 1;
            return;
        };
        page(f).copy_from_slice(&data[..BLOCK]);
        self.slots[s] = Slot { addr, sha: *sha, frame: f, referenced: meta };
        self.link(s);
        self.stats.inserts += 1;
        if from_commit {
            self.stats.commit_inserts += 1;
        }
    }

    /// Blocks held now.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.frame != 0).count()
    }

    /// Test only: damages the cached copy of `addr` (one byte flipped) – the next hit must
    /// see it.  false: not cached.
    #[cfg(selftest)]
    pub fn damage(&mut self, addr: u64) -> bool {
        match self.find(addr) {
            Some((_, s)) => {
                page(self.slots[s].frame)[100] ^= 0x5A;
                true
            }
            None => false,
        }
    }

    /// Test only: whether `addr` is cached (with any checksum).
    #[cfg(selftest)]
    pub fn holds(&self, addr: u64) -> bool {
        self.find(addr).is_some()
    }
}

impl Drop for BlockCache {
    fn drop(&mut self) {
        for s in self.slots.iter() {
            if s.frame != 0 {
                crate::memory::free_frame(s.frame);
            }
        }
        release(self.held);
        self.held = 0;
    }
}
