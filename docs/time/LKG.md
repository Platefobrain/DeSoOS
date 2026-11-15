# The last known good time (LKG)

A lower bound for the wall clock that survives a restart (v0.79, `kernel/time_lkg.rs`). The clock is the RTC
read at boot plus the uptime (`README.md` in this folder); anyone with the firmware set-up can set the RTC to any date,
and a dead battery resets it. The build date is a weak lower bound. The LKG is a better one: a time the system once
knew to be true. A clock earlier than the LKG is not plausible, and TLS (https, NTS-KE) refuses to connect.

## What raises it

| Source | Raises the LKG? |
|---|---|
| nothing stored yet | the build date is the bound (with its 24 h tolerance – reason 5) |
| an authenticated time from NTS, through the time service (`SYS_TIME_SET`, `TIMEKEEPER.md`) | **yes** – the only one, and only by what is certain: ⌊T − U − 2 s⌋ |
| the self-test switch (selftest builds only) | yes – LKG TEST and RESTART TEST |
| the RTC, plain NTP, an HTTP `Date` header, a certificate's notBefore, a time a program gives | **no** – there is no way in the code |

The LKG is never lowered – a raise below the current one changes nothing, and `SYS_TIME_SET` with T + U below it is
refused. While the file is unreadable (reason 8), every accepted `SYS_TIME_SET` writes it anew with max(L, the LKG in
memory) – the repair write (`TIMEKEEPER.md`).

## Where it is kept

`/.desoos/lkg` on the **system volume** – the DeSoFS volume mounted read-write at `/disk` (so `/disk/.desoos/lkg` in
the VFS). Without such a volume (no disk, FAT32, a read-only disk – a real SSD in DeSoOS today) the LKG lives in memory
only, from the build date on; `date` says "kept in memory only".

The record is 56 bytes (little-endian):

| Offset | Field |
|---|---|
| 0 | `DESOLKG1` |
| 8 | version (u16) = 1 |
| 10 | source (u16): 2 NTS, 3 self-test |
| 12 | 0 (u32, reserved) |
| 16 | time (u64): Unix seconds, UTC |
| 24 | SHA-256 over bytes 0–23 |

The checksum protects against an **accident** (a torn write, a bad sector). It does not protect against someone who
changes the file outside DeSoOS and computes the sum again – see "Threats".

## Reading (at boot, and whenever a volume is mounted at /disk)

| The file | Result |
|---|---|
| does not exist | nothing stored – the build date |
| good | loaded (a time below the build date is kept but bounds nothing) |
| a read or stat error, wrong length, wrong magic, wrong checksum, unknown version, reserved bytes not 0, unknown source, a time after 2099 | **reason 8** "last known good time unreadable": the clock is not plausible until the time service writes the file anew (recovery: a bootstrap with max(LKG in memory, build date) as the bound – `TIMEKEEPER.md`) or the volume is repaired – never a quiet fall-back to the build date; a line on the console |

A later mount never lowers a bound already in memory (another volume at `/disk`, or one without the file, keeps the
higher time).

## Writing – atomic and durable

1. `/.desoos` created if missing; a temporary file left by an interrupted save is removed;
2. the whole record into `/.desoos/lkg.new`;
3. read back and compared byte for byte;
4. `sync`;
5. `rename` onto `/.desoos/lkg`;
6. `sync`.

Every DeSoFS operation is its own transaction (copy-on-write, flushed, one new superblock – `../desofs/FORMAT.md`), so
after a power loss at any point there is exactly the old record or the new one, never an empty or a mixed file. LKG
TEST cuts the power at every 512-byte sector of every write of a save and makes a write fail at every position.

Every raise is saved at once. If the save fails (or there is no system volume), the raised LKG stays in memory,
`date` shows "NOT SAVED" (without a system volume: "kept in memory only"), and the next raise tries the save again
first – also when that raise is not higher.

## The verdict on the clock

The status of syscall 59 (and `date`, `certcheck`, netget, nettime) – the first reason that applies:

1. the RTC reading: 1 not read, 2 battery lost (VRT), 3 readings do not agree, 4 fields out of range, 6 after 2099;
2. **8** – the LKG file is unreadable;
3. 5 – earlier than the build date minus 24 h;
4. **7** – earlier than the LKG (margin 0 s: one second below is too early).

Reason 7 compares with a stored or raised LKG; the build date keeps its 24 h tolerance as reason 5 (an RTC kept in
local time west of UTC). The state of the file is kept apart from the verdict: `date` shows "UNREADABLE" even when the
RTC itself is the first reason.

The RTC is never written and the clock is never changed here: a clock below the LKG is refused, not "fixed".

## /.desoos is the kernel's

The VFS refuses every change under `/.desoos` of a DeSoFS volume to everybody but the kernel's own LKG code – programs
and the kernel's own file functions (the shell's `rm`, `mv`, `write` included):

- opening for writing, `O_TRUNC`, `O_CREATE`, `O_APPEND`; `write`, `truncate`;
- `unlink` of the file and of the directory; `mkdir` and new files inside;
- `rename` out of it, onto it, into it, of the directory, and a directory onto it;
- mounting on `/.desoos` or inside it;
- through directory handles (`openat`, `unlinkat`, `mkdirat`) and every spelling (`.`, `..`, `//`, relative paths).

The check is made on the **resolved object**: the volume the normalized path lands on and the node's path inside it –
not on the text a program gave. DeSoFS has no links and compares names exactly, so no other path reaches the same node.
It is made **under the same lock** that picks the volume and runs the operation (`with_fs_change`, `resolve_change`,
`try_concurrent_change`, inside `remove` and `rename` – after `rename` lets the lock go, again under the next one): a
volume mounted at `/disk` between a check and the write cannot get the write. An open file keeps a **path**, not a
reference to a file system, so every write through it picks the volume again under that lock – a handle opened on
ramfs before a DeSoFS volume is mounted over `/disk` writes nothing into `/.desoos`. (Opening for writing is also
refused at once – an early answer, not the protection itself.)
Reading stays allowed. Only `/.desoos` at the root of a DeSoFS volume is reserved (`/disk/a/.desoos`, `/disk/.desoosx`
and a `/.desoos` on ramfs are ordinary). The kernel writes the file only through the volume itself
(`fs::with_desofs_at`).

## Threats

| Threat | Stage C |
|---|---|
| damage to the file (power loss, a disk error) | detected – reason 8 |
| a program changing, removing or replacing the file | refused by the VFS |
| a program raising the LKG (a time far ahead would block TLS) | impossible – only `SYS_TIME_SET`, which needs the SETTIME handle (init gives it only to the time service; it cannot be sent in a message) |
| the time service itself wrong or taken over | the kernel checks the numbers and never lowers the LKG, but cannot check that the time came from NTS or two operators – a wrong time within those rules (`TIMEKEEPER.md`) |
| a change to the file outside DeSoOS (another system, the sum computed again) | **not covered** |
| an old disk image put back (rollback of the LKG), or `desofs snapshot restore` from the shell | **not covered** – later a TPM NV index or another hardware monotonic counter |
| `desofs format` of the system disk from the shell | the LKG goes with the volume (the bound in memory stays until the restart) |

## Tests – LKG TEST (38th suite)

1. the state the boot left: nothing raised by the suites before (sysfuzz among them);
2. the verdict on 16 made-up states: the order of the reasons, margin 0 s;
3. the record on a volume: no file, good, saved twice, a temporary file left, length, magic, every covered byte,
   version, reserved bytes, source, after 2099, read and stat errors (68 cases);
4. power loss at every sector of every write of a save, a write failing at every position, for replacing a record
   and for the first save; a temporary file left by a crash is replaced by the next save (317 crash images);
5. the live system on a RAM volume at `/disk`: no file → the build date; raised and saved; never lower; equal to the
   clock → plausible; ahead → reason 7 and netget https refused before sending; read back the same; damaged →
   reason 8, refused; repaired by the next LKG; no volume → in memory, "NOT SAVED", saved by the next raise;
6. `/.desoos` protected: 20 kernel calls and 30 program attempts (`/bin/timetest protect`) refused; the file readable
   and the same; other names writable;
7. checked under the operation's lock: a volume is mounted at `/disk` in the gap before each changing call takes the
   VFS lock (a self-test hook, `fs::RACE_HOOK`) – write, truncate, create, mkdir, remove, rename out / over / into,
   `write_file`, `append_file` all refused, nothing on the volume changed; a program's handle opened on ramfs before
   the mount (`/bin/timetest stale`) writes nothing through it;
8. sysfuzz with the LKG on `/disk`: the value and the file unchanged.

RESTART TEST: the first start saves an LKG, damages it on the volume (reason 8) and lets the time service recover it
(NTS from two operators of `tests/nts-server`, the file written anew); the second start reads it back at boot – good,
from NTS, no reason 8, the clock plausible – and the file is still protected; then an LKG two days ahead of the clock:
reason 7, netget https refuses before sending.  The time service's own tests: NTS TEST (`TIMEKEEPER.md`).

Mutations caught: a margin of 1 s, a quiet reset on a bad file, `truncate + write` instead of `rename`, the
protection on the text of the path, reason 7 before 8, an LKG that can go down, a failed save never retried, opening
for writing not refused; the reserved check made before the lock instead of under it – in the write / create / mkdir /
truncate path, in `remove`, in `rename`, in `write_file` / `append_file`.

## Compared with other systems

| | Lower bound | Raised from | Changes the clock? |
|---|---|---|---|
| Linux (systemd-timesyncd) | systemd's build time + the file `/var/lib/systemd/timesync/clock` | every NTP sync (unauthenticated) | yes |
| Windows (Secure Time Seeding) | – | timestamps from TLS handshakes | yes – known to jump the clock |
| Android | the build time | NITZ, GNSS, NTP | yes |
| RedoxOS | – | – | – |
| **DeSoOS** | the build date + the LKG on the system volume | only NTS through the time service (two of three operators) | the time service sets the wall clock to max(T, LKG); a clock below the LKG is otherwise refused, not changed |
