# DeSoFS

DeSoOS's own file system: copy-on-write (a block is never overwritten in place), the SHA-256 of every block stored in
its parent's pointer, two superblocks, every operation committed to the disk before it returns, snapshots of the whole
volume. Format 1 is closed – `FORMAT.md` describes it byte by byte.

What it can do (details and design in `../ARCHITECTURE.md`, section "DeSoFS"):

- `desofs format` / `mount` / `unmount` – disk 0 is mounted at `/disk` at start, other disks at `/desofs`;
- a block cache: verified blocks kept between operations, every hit checked by its SHA-256 again (`desofs check`
  always reads the disk);
- `desofs ramdisk <MiB>` – a disk in memory to format (real hardware: the computer's disks stay read-only);
- `desofs check` – every block's checksum, directories and relations; `desofs repair` – back to the other
  superblock's whole state when one tree is damaged;
- `desofs snapshot create / list / mount / delete / restore` – up to 31 snapshots, nothing copied when one is made;
- power loss at any moment leaves the state before or after the last operation – never a mix.

Where things are:

| Path | What |
|---|---|
| `kernel/fs/desofs/` | the code (map in its `README.md`) |
| `tests/mkdesofs.py` | an independent implementation in Python: the reference image the kernel tests read, and `--format` to make a DeSoFS disk image on the host |
| `FORMAT.md` | the on-disk format |

Tests: DESOFS TEST 1–28 (reading, writing, power loss, check / repair, snapshots), RESTART TEST (data on `/disk`
after a real restart, `[RESULT-FS]` speed figures), INIT TEST 9 (`desofs` through the user shell).
