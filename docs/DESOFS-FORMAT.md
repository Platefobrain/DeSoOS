# DeSoFS on-disk format 1

DeSoFS is the native file system of DeSoOS: copy-on-write, SHA-256 over every block (a Merkle tree), two
superblocks, no journal and no allocation structure on disk. This document is the **closed specification of format
1** (version 8 of the design, accepted 2026-11-01, plus errata E1–E3). The binary layout does not change during
implementation stages 1–4; problems found while implementing are added as numbered errata at the end, and errata may
not change the architecture or the meaning of a field. After stage 4 a format change needs a new format version or a
compat / ro_compat / incompat feature bit.

Design decisions behind it: copy-on-write (like btrfs, ZFS, ReFS, APFS, RedoxFS) instead of a journal (ext4, NTFS);
checksums over metadata **and** file data (like btrfs, ZFS, RedoxFS); recognition by a marker on a whole disk or a
partition; snapshots later, with the format ready for them now. Free space is derived by walking the trees at mount
(P1), blocks are freed by birth generation for ordinary changes and by a reachability walk when a snapshot is deleted
(R1 + R3), and every operation is committed before it returns (T1).

What it protects against: power loss at any moment (the volume comes back as one complete version) and damaged or
misdirected blocks (detected, never returned as data, never a kernel panic). What it does not protect against:
deliberate changes – someone who rewrites data can recompute the checksums too (signatures are a later DeSoCrypto
topic).

## 0. General rules

| Rule | Value |
|---|---|
| block size | **4096 bytes**, stored in the superblock (anything else → refuse to mount) |
| byte order | little-endian everywhere |
| block address | u64, number of the 4 KiB block from the start of the volume (disk or partition) |
| checksum | **SHA-256 (32 bytes) in the parent's pointer**; the superblock carries its own |
| overwriting | a live block is **never** overwritten; the only exception are the two superblocks, alternately |
| untrusted input | every value read from a disk is checked; a violation is `Corrupt`, never a panic |
| free space | every field described as "zero", every empty entry and every unused tail of a block must be zero |

## 1. Volume map

```
block 0      zero (not used by DeSoFS)
block 1      superblock A
block 2      superblock B
blocks 3-15  reserved (zero)
block 16 ... everything else, anywhere: root blocks, trees, nodes, directories, data
```

All block numbers count from the start of the **volume**:

- **Whole disk:** DeSoFS owns the disk; `desofs format` zeroes blocks 0–15 first, so an old FAT32 / MBR / other
  superblock is no longer recognised.
- **Partition:** block 0 is the first 4 KiB of the partition; formatting stays inside it.
- `desofs format` refuses a whole disk that carries a partition table (GPT or MBR) and asks for a partition.
- Without `yes`, `desofs format <disk>` only shows what would be erased.
- An incomplete 4 KiB block at the end of the device does not belong to the volume (format rounds down); a mount uses
  `total_blocks` from the superblock even if the device is larger (E2).

## 2. Superblock (4096 bytes, blocks 1 and 2)

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 8 | magic | `DESOFS01` |
| 8 | 4 | version | 1 |
| 12 | 4 | block_size | 4096 |
| 16 | 16 | uuid | random at format time |
| 32 | 8 | generation | commit number, +1 per commit (checked arithmetic; at `u64::MAX` commits are refused) |
| 40 | 8 | total_blocks | ≥ 64 (256 KiB); total_blocks × 4096 ≤ device size (checked multiplication) |
| 48 | 8 | used_blocks | number of **distinct** blocks reachable from this superblock's root (its DSRT, metadata, data, snapshots), blocks 0–15 excluded; informational – recounted at mount, a mismatch is a warning |
| 56 | 8 | commit_time | seconds since 1970 (RTC) |
| 64 | 4 | compat | features that may be ignored |
| 68 | 4 | ro_compat | unknown feature → mount read-only |
| 72 | 4 | incompat | unknown feature → do not mount |
| 76 | 4 | – | zero |
| 80 | 48 | root | pointer (§3) to the root block (DSRT); never empty |
| 128 | 32 | label | UTF-8 up to the first zero byte, zeros after it (E2) |
| 160 | 3904 | – | zero |
| 4064 | 32 | checksum | SHA-256 of bytes 0–4063 |

**Choosing a superblock.** A superblock is valid when magic, version, block_size and checksum are right. Then:

| Situation | Result |
|---|---|
| none valid | not a DeSoFS volume – nothing mounted, nothing written (never an automatic format) |
| one valid | that one |
| both valid, different `uuid` | **refuse** (leftovers of two volumes) |
| both valid, different `total_blocks` | **refuse** (no resizing in format 1 – damage) (E3) |
| both valid, different generations | the higher generation wins (then the rules of §9) |
| both valid, same generation, identical `root` (48 bytes) | the same state written twice – mount |
| both valid, same generation, different `root` | **refuse** – never pick one of two states silently |

**Where the next commit goes:** to the slot with the **older** (lower) generation; a slot with a bad checksum or
zeros counts as oldest. On a tie (same generation, same root – e.g. right after `desofs format`) always **slot B**.
Never by `generation % 2` – after `desofs repair` the parity need not match the slot.

## 3. Pointer (48 bytes)

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 8 | addr | block number; 0 = empty pointer |
| 8 | 8 | birth | generation in which the block was written |
| 16 | 32 | sha256 | SHA-256 of the whole 4096-byte block it points to |

Reading through a pointer: read `addr`, hash it, compare with `sha256`; a mismatch is an error. The checksum in the
parent also catches a valid block in the wrong place (an old version, a wrong address).

- **The empty pointer is 48 zero bytes** – one form of a hole. `addr` 0 with any other byte set → the block holding it
  is damaged.
- A non-empty pointer: `addr` inside the volume and outside blocks 0–15; **1 ≤ birth ≤ superblock generation** (also
  for data blocks, which have no header); for a metadata block additionally birth = generation in the child's header.

Where an empty pointer is allowed:

| Place | Empty pointer |
|---|---|
| `root` in the superblock | not allowed |
| `nodes` of an occupied root entry | not allowed (the node table always holds node 1) |
| DSPT of the node table | allowed for a range without any occupied node; never for the range with node 1 |
| DSPT of file data | allowed – a hole (sparse file); not allowed below the size of a directory |
| direct pointers in a node (depth 0) | allowed – a hole; beyond the file size mandatory |

A DSPT whose pointers are all empty (`count` 0) is not allowed – the parent holds an empty pointer instead.

## 4. Metadata block header (64 bytes)

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 4 | kind | `DSRT` root block, `DSPT` pointer block, `DSND` node block |
| 4 | 1 | level | DSND 0, DSPT 1–5, DSRT 0 |
| 5 | 1 | – | zero |
| 6 | 2 | count | occupied entries – **must match the contents**: DSRT entries with kind ≠ 0, DSPT non-empty pointers, DSND nodes with type ≠ 0 |
| 8 | 8 | generation | generation in which **this block** was written (= birth in the parent, ≤ superblock generation) |
| 16 | 8 | self_addr | the block's own number |
| 24 | 16 | uuid | volume uuid |
| 40 | 24 | – | zero |

Two different generations: the superblock's is the commit (state of the volume); the header's is when this block was
written. A block may be older than the superblock (unchanged parts of the tree; after `desofs repair` even the
DSRT). Data blocks of files and directories have no header – plain 4096 bytes, checksum only in the pointer.

## 5. Root block `DSRT` (one per new commit tree)

After the header: **32 entries of 96 bytes** (3072 bytes), the rest zero.

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 48 | nodes | pointer to the root of the node table |
| 48 | 1 | depth | depth of the node table, 1–5; **must equal the `level` of that DSPT** |
| 49 | 1 | kind | 0 empty, 1 live file system, 2 snapshot |
| 50 | 6 | – | zero |
| 56 | 8 | next_node | next new node number |
| 64 | 8 | created_gen | generation of creation (snapshots) |
| 72 | 24 | name | snapshot name |

- Entry 0 is always the live file system (kind 1); entries 1–31 are snapshots (kind 2) – at most 31.
- An empty entry is 96 zero bytes. Kind 1 only in entry 0, with an empty name and created_gen 0.
- A snapshot: name non-empty UTF-8 without `/`, zero-padded to 24 bytes, unique among snapshots;
  1 ≤ created_gen ≤ superblock generation.
- `next_node` ≥ 2 and above every occupied node number and every `parent` in that tree. A new number reuses a freed
  one first (§7), otherwise takes `next_node`; `next_node + 1` is checked; at `u64::MAX` no new numbers
  (`ERROR_NO_SPACE`), freed ones can still be reused with a new node_gen (E2). Node 0 is reserved; node 1 is the root
  directory, must exist, is a directory and is never freed.
- A new DSRT is written by every commit that changes the tree; `desofs repair` writes none.

## 6. Trees: pointer blocks and the node table

**Levels:** a tree of depth d has a DSPT of level d at its root; a DSPT of level k points to DSPTs of level k − 1, a
DSPT of level 1 points to the leaves – data blocks (file, directory) or DSND blocks (node table). A child of another
kind or level than expected is `Corrupt`.

**Pointer block `DSPT`:** header + **84 pointers** (84 × 48 = 4032; 64 + 4032 = 4096). A fixed fan-out tree: the
index is computed by division.

| Depth | File data (4 KiB blocks) | Node table (84^d DSND × 15 nodes) |
|---|---|---|
| 0 | 4 blocks = 16 KiB (pointers inside the node) | – (always ≥ 1) |
| 1 | 84 = 336 KiB | 1 260 |
| 2 | 7 056 = 27.56 MiB | 105 840 |
| 3 | 592 704 = 2.26 GiB | 8 890 560 |
| 4 | 49 787 136 = 189.92 GiB | 746 807 040 |
| 5 | 4 182 119 424 = 15.58 TiB | 62 731 791 360 |

**Node table:** a DSPT tree; its leaves are **node blocks `DSND`**: header + **15 nodes of 256 bytes** (3840) + 192
zero bytes. Node n is in leaf n / 15, slot n % 15.

## 7. Node (256 bytes)

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 8 | number | own number (= its place in the table) |
| 8 | 1 | type | 0 free, 1 file, 2 directory |
| 9 | 1 | depth | 0 = up to 4 direct pointers; 1–5 = a DSPT tree whose root has level = depth |
| 10 | 2 | flags | for the future; **0 in format 1** |
| 12 | 4 | links | for the future (hard links); **1 in format 1** |
| 16 | 8 | size | bytes |
| 24 | 8 | created | seconds since 1970 |
| 32 | 8 | modified | seconds since 1970 |
| 40 | 8 | parent | directory node holding it; the root directory (node 1) has parent 1 |
| 48 | 8 | node_gen | generation of the commit that created the node |
| 56 | 192 | data | depth 0: 4 pointers to data blocks; depth ≥ 1: bytes 0–47 the tree root, **48–191 zero** |
| 248 | 8 | – | zero |

A free node (type 0) is 256 zero bytes. No owner and no permission bits – rights are handles (DCP).

Conditions for an occupied node: number = its place; type 1 or 2; depth 0–5; flags 0; links 1; size ≤ capacity of
the depth; **depth is the smallest that holds the size** (one form); a directory's size is a multiple of 4096;
1 ≤ node_gen ≤ superblock generation; parent ≠ 0 and < next_node; zero fields zero.

**Pointers and the file size (every depth):** logical block i exists when i × 4096 < size. A data pointer for a block
beyond the size is empty – direct pointers and every DSPT level (a subtree entirely beyond the size is an empty
pointer in its parent). Inside the size an empty pointer is a hole – allowed for files, not for directories. No
preallocation in format 1.

**node_gen:** writes, truncation, rename and move keep it; only a new node gets a new one – also under a reused
number. Node generations only grow, so an old handle (number + old node_gen) never reaches a new file. A number freed
in commit N may be reused from commit N + 1 on.

## 8. Directory

A directory is a node of type 2 whose **data** are blocks of entries. An entry (variable length, 8-byte aligned,
never crossing a block boundary):

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 8 | node | node number; 0 = deleted entry |
| 8 | 1 | type | copy of the node type |
| 9 | 1 | name_len | 1–255 |
| 10 | 2 | rec_len | length of the whole entry, ≥ 16 and a multiple of 8 |
| 12 | n | name | UTF-8, no `/`, no zero byte |
| 12 + n | … | – | padding: zero |

- Entries are adjacent and cover the whole block (the rec_len sum is 4096).
- A deleted entry: node 0 and everything except rec_len zero.
- Names are unique, compared **byte by byte** (case-sensitive, no UTF-8 normalisation – like ext4, btrfs, RedoxFS).
  `.` and `..` are never stored (they follow from the node and parent); an entry named `.` or `..` is damage.
- At most **65 536 active entries** per directory (deleted ones do not count). Linear search in format 1.
- The entry does not contain node_gen – it is for handles, not part of the entry.
- **readdir cursor** = number of the **logical** directory block (0, 1, 2… – not the disk address, which changes with
  copy-on-write) × 4096 + offset of the entry. It points to a place; entries added or removed by someone else during
  reading may appear or not (also a new file in the place of a removed one); an entry that existed the whole time
  appears exactly once. No snapshot view (as in POSIX).
- `rename` is one commit (both directories) – atomic.

Conditions on directories and their relations: size a multiple of 4096, every block below the size exists; every
occupied entry points to an existing node with the same type; the node found from directory D has parent = D (files
too – one entry per node in format 1); every node except 1 is referenced exactly once, from the directory equal to its
parent; node 1 is referenced from nowhere; no directory cycles, no multiple parents.

When they are checked:

| When | What |
|---|---|
| mount (walk) | metadata trees, every node (§7), levels, pointers |
| every use of a directory | that directory: size, entries, padding, type match, parent of the node found |
| `desofs check` (stage 3) | everything: each node referenced once, no cycles, no multiple parents, nodes without an entry |

A structural mismatch found while working → **read-only** (like ext4 `errors=remount-ro`), not just an error of one
operation. A damaged file **data** block is an error of that one read only.

## 9. Free space – no structure on disk (P1)

A map of used blocks **in memory only**, computed at mount. Used are:
1. blocks 0–15;
2. everything reachable from the **current** superblock: its DSRT and all trees of all its entries (live and
   snapshots);
3. everything reachable from the **previous** valid superblock: its DSRT and all its trees – the fallback if the
   current one turns out bad.

"Reachable" means DSRT, DSPT, DSND blocks (read and checked) and the data and directory blocks they point to (only
marked, not read). Everything else is free. No list has to survive a restart: after a restart the walk over both
superblocks gives exactly the same state.

**Three rules of the walk:**
1. **No loops:** edges are typed – superblock → DSRT → DSPT of level d → … → DSPT level 1 → DSND → data or DSPT of
   level depth → … → data; each step has a known kind and level, and data blocks contain no pointers. A pointer to an
   ancestor has the wrong kind or level. (Thanks to the Merkle tree a loop cannot even be sealed: the ancestor's
   checksum would depend on itself.)
2. **Inside one root** (one DSRT entry) a block reached twice is `Corrupt` – no sharing inside a tree in format 1.
3. **Between roots** (live, snapshots, the other superblock's tree) sharing is legal (see E1 for how it is checked).

**The type of every marked block, independent of walk order:** a block marked DATA and met as METADATA, or the other
way round, is `Corrupt`, also between roots. The same bytes cannot serve two roles.

**States of the two superblocks at mount** – the rule: **a writable allocator only starts when it is known which
blocks are reachable**:

| Newer slot | Older slot | Result |
|---|---|---|
| tree OK | tree OK | normal mount, writes |
| tree OK | bad checksum / zeros | normal mount, writes – a bad superblock has no tree |
| tree OK | tree damaged | newer version **read-only** |
| tree damaged | tree OK | older version **read-only** |
| tree damaged | bad / damaged | **refuse** |

"Tree damaged" = a reachable DSRT / DSPT / DSND block with a bad checksum or failing a check (header, address, depth,
type). A damaged data block does not change reachability; it shows when that file is read. **A good walk does not
mean the contents of all files are good** – data checksums are checked on read; a full check of every byte is
`desofs check` (stage 3, like `btrfs scrub` / `zpool scrub`).

**Leaving read-only – `desofs repair <disk>`** (stage 3), **without allocating any block**: pick the superblock with a
fully valid tree; walk and check all of it; copy that superblock (same uuid, same root) with generation = highest
generation among superblocks with a valid own checksum + 1 (refused at `u64::MAX`); write the copy into the slot of
the damaged superblock; flush; only then allow writes. An interrupted repair leaves the good superblock untouched.
Blocks of the damaged tree become unreachable and are eventually overwritten – if it was the newer state, its last
changes are lost (like `zpool import -F`).

Format-1 volume limit for now: **64 GiB** (larger later with a stored map hint, a ro_compat feature).

## 10. Commit

```
1. all new blocks (data, then bottom-up: trees, nodes, node table, root block) – only into free blocks;
   a parent hashes its children, so writes go from the bottom up
2. flush
3. superblock (generation + 1, checked; root = the new root block) -> the slot with the older generation (§2)
4. flush
5. blocks reachable only from the superblock just overwritten -> free
```

**Reuse follows from reachability from both superblocks.** A block reachable from either valid superblock or from a
snapshot is used; reachable from none – free. A block dropped in commit N is still in tree N − 1; only commit N + 1
overwrites that slot, so the block is reused at the earliest in N + 2 (like ZFS deferred frees, btrfs pinned
extents) – derived from the trees, not from a list. A block may be reallocated **only when its unreachability from
both superblocks on disk is confirmed**, never "because two generations passed"; an in-memory helper list must give
exactly what the walk would, and only during uninterrupted, error-free work.

**Flush and errors:**
- an operation returns success only after the confirmed flush of step 4;
- the device must support flush (virtio with FLUSH, RAM disk); without it – read-only;
- **a write or flush error → read-only at once** (that operation fails, later writes get `ERROR_READ_ONLY`);
- **the outcome of that one operation is unknown until the next mount**: the new superblock may or may not have
  reached the disk; the next mount picks the highest valid superblock – the old or the new version, always complete;
- a 4 KiB superblock write is not atomic (8 sectors); a partial write fails its checksum.

Power loss:

| When | After the next mount |
|---|---|
| before the new superblock is written (steps 1–2) | previous version; new blocks are free by themselves |
| while the superblock is written (step 3) | previous version if the write is incomplete; if it survived whole, the new one may win |
| after the superblock write, before the confirmed flush | old **or** new version – whatever the device kept; always one of them, complete |
| after the confirmed flush of step 4 | new version |

**When to commit (T1):** after every operation (create, write, remove, rename) – when the call returns, the data is
on the disk (like a Linux `sync` mount). Batching (every few seconds or on `sync`) may come later.

## 11. Freeing blocks and snapshots (R1 + R3)

| Step | Meaning | When |
|---|---|---|
| logical free | the block belongs neither to the live file system nor to any snapshot | R1 or R3 |
| physical reuse | the block may be overwritten | when unreachable from both superblocks (N + 2) |

**R1 – ordinary changes:** no snapshots → the old block is freed logically at once. With snapshots: birth > the
newest snapshot's generation → born after it, no snapshot has it → freed logically; birth ≤ → a snapshot **may**
hold it – kept conservatively (the R3 walk or `desofs check` reclaims it if no snapshot does).

**R3 – deleting a snapshot** (stage 5): a reachability walk marking everything reachable from the live root, the other
snapshots, the previous valid superblock and blocks 0–15; everything else that was used is freed logically, reused
after N + 2. Refused if any of those trees is unreadable.

## 12. Recognition and refusals

- Recognition: block 1 (or 2) = `DESOFS01` + a valid superblock checksum (no false hits on random data). DeSoFS is
  checked before FAT32.
- Refusal (message, disk untouched): the cases of §2; unknown version / incompat feature; block size ≠ 4096;
  total_blocks above the device or below 64; a volume over 64 GiB; damaged trees as in §9.
- A damaged file data block while working → error of that operation only. A damaged directory block or a structural
  mismatch → read-only.
- A read-only device or one without flush → read-only; `desofs format` refuses.

## 13. Limits of format 1 now

| What | Limit |
|---|---|
| volume | 256 KiB (64 blocks) to 64 GiB (the format allows 2^32 blocks = 16 TiB later) |
| file | 15.58 TiB (depth 5), in practice ≤ the volume |
| name | 255 bytes UTF-8 |
| directory | 65 536 active entries |
| snapshots | 31 |
| nodes | up to 2^64 (in practice limited by space) |

## 14. State after `desofs format`

| What | Value |
|---|---|
| blocks 0–15 | zeroed first (both superblock slots too), then the superblocks written |
| superblocks A and B | **identical**: new random uuid, generation 1, same root, used_blocks 3, label from the command – a spare copy from the first moment; the first commit (generation 2) goes to slot B (tie) |
| DSRT (generation 1) | entry 0: kind 1, depth 1, next_node 2, nodes → DSPT; entries 1–31 empty |
| DSPT of the node table (level 1) | pointer 0 → DSND; the other 83 empty; count 1 |
| DSND (level 0) | node 0 free; **node 1**: type 2, depth 0, size 0, links 1, parent 1, node_gen 1, created = modified = now, data zero; nodes 2–14 free; count 1 |
| data blocks | none (an empty root directory has no blocks) |

Write order: zeros in blocks 0–15 → flush → DSND → DSPT → DSRT → flush → superblock B → flush → superblock A → flush.
An interrupted format leaves a volume that is not recognised or has one valid superblock with a complete tree – both
safe; formatting can be repeated.

## Errata

**E1 (2026-11-01, §9) – memory of the walk.** The map has **one byte per block**: free / reserved / DATA / METADATA
with kind and level; the root being walked has **one bit per block**. A metadata block met again from another root
is **read again** and checked with the new pointer – SHA-256 of the contents equal to the pointer's, header
generation = birth, kind and level as stored in the map; then its subtree is skipped. Pointers need not be stored.
Budget of the two maps: 64 MiB volume – 16 KiB + 2 KiB; 64 GiB – 16 MiB + 2 MiB = **18 MiB** (a limit of these two
maps, not of all RAM during a mount; I/O buffers and the walk's stack come on top). Not enough memory → refuse with a
message, no panic. (Replaces an earlier "about 13 MiB" estimate that was not a bound: with many small files DSND
blocks can be a large part of the volume.)

**E2 (2026-11-01, §1, §2, §5) – details.** The label is UTF-8 up to the first zero byte, zeros after it; a mount uses
`total_blocks` from the superblock even if the device has more whole blocks; with `next_node` = `u64::MAX` freed
numbers can still be reused with a new node_gen; "64 KiB pieces" is how the maps are allocated, not a limit on the
memory of the walk.

**E3 (2026-11-01, §2, §9) – found while designing the walk (stage 1).**
- Rule 2 with skipped shared subtrees (E1) is complete for the **first** root walked – the live file system of the
  newer superblock (nothing is marked yet, nothing is skipped); for later roots (snapshots, the older superblock's
  tree) it covers the parts that are not shared. Safe: writes and R1 frees touch only the live root; blocks of
  snapshots and of the older superblock are freed only by reachability. A full check of every root is `desofs check`.
- If the newer tree is damaged, the map is recomputed from the older superblock alone – no traces of the damaged tree
  (its bad pointers could cause false DATA/METADATA conflicts).
- Both superblocks valid with the same uuid but different `total_blocks` → refuse.
- A pointer that two roots use for the same data block should be identical in all 48 bytes; that is checked by
  `desofs check`, not at mount (it would need the pointer of every data block in memory). The allocator stays safe
  (the block is marked used either way) and a conflicting checksum shows when reading through the wrong pointer.

**E4 (2026-11-01, §3, §6) – no empty node blocks.** Like a DSPT, a DSND without any node (`count` 0) is not allowed –
the parent holds an empty pointer instead (one form on the disk). The range holding node 1 is never empty. The walk
refuses such a block; the writer never produces one (a node block whose last node is freed is removed).
