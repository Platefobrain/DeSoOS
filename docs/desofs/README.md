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
- power loss at any moment leaves the state before or after the last operation – never a mix;
- `/.desoos` at the root of a volume belongs to the system: on the system volume (`/disk`) it holds the last known
  good time (`../time/LKG.md`); the VFS refuses every change there by programs and by the shell's file commands –
  only the kernel writes it. It is an ordinary directory in the format (nothing in `FORMAT.md` changes).

Where things are:

| Path | What |
|---|---|
| `kernel/fs/desofs/` | the code (map in its `README.md`) |
| `tests/mkdesofs.py` | an independent implementation in Python: the reference image the kernel tests read; `--format` = `tools/mkdesofs.py` with a fixed uuid / time |
| `tools/mkdesofs.py` | the production formatter on the host (an empty volume, chapter 14 – the kernel's `desofs format` byte for byte; random uuid, the current time, ≤ 64 GiB); `tools/mkusb.py` uses it for partition 2 of `make-usb.sh --with-disk` |
| `FORMAT.md` | the on-disk format |

Tests: DESOFS TEST 1–32 (reading, writing, power loss, check / repair, snapshots, the block cache), RESTART TEST
(data on `/disk` after a real restart, the last known good time read back, `[RESULT-FS]` speed figures), INIT TEST 9
(`desofs` through the user shell), LKG TEST (the LKG record on a volume, power loss during its save, `/.desoos`
protected).
