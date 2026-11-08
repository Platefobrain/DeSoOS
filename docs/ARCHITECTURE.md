# DeSoOS Architecture

How the system is built and how it works. Change history lives in `CHANGELOG.md`, test results and current limitations
in `docs/RELEASE.md`.

## Overview

DeSoOS is an x86_64 kernel written in Rust. It boots from UEFI (its own bootloader, DSB) and runs on
multiple cores (up to 16). It targets ordinary PCs and laptops as well as QEMU.

**A modular monolith now, a hybrid as the goal. Priority: speed.**

- The kernel keeps everything that almost every syscall passes through or that must keep up with an
  interrupt (memory, scheduler, IPC, VFS, basic drivers).
- User space gets what is large, risky and off the critical path (networking, USB, audio, GUI).
- Every driver sits behind a common interface (`BlockDevice`, `input`, `console`, `FileSystem`), so
  moving it to user space means swapping the implementation, not rewriting the system.
- **Measure first, then change.** Every performance decision is based on a profile and a stress run on
  real hardware (a 16-thread laptop) as well as QEMU.
- **Nothing "for AI" in the kernel.** The kernel enforces permissions (handles); an agent will be an
  ordinary program (see "Future: the DeSo AI agent").

Why not a pure microkernel: everything would depend on IPC, and without an IOMMU a driver with DMA can
write any memory anyway. Why not a monolith forever: a bug in a large, optional driver takes down the whole
system.

## Layers

```
                                 DeSoOS
                                    │
        ┌───────────────────────────┴───────────────────────────┐
     KERNEL                                                 USER SPACE
        │                                                       │
syscalls + handles ────────── boundary ────────── init, shell, programs (/bin)
        │                                                       │
  ┌─────┼────────────┬───────────┬─────────────┐                │
 MM Scheduler       IPC         VFS         drivers         services
  │  + locks     channels,       │         (console,      ┌─────┼─────┐
  │            shared memory     │        PS/2, PCI,     USB   NET  AUDIO
  │                  │      page cache   NVMe, virtio)          │
  │                  │           │             │                │
  │                  ╚═══════════╪═════════════╪════════════════╡  data: shared memory
  │                            block           │                │
  │                                            ╘════════════════╛  control: MMIO, IRQ→handle, DMA, (IOMMU)
  │
  └──────── arch / SMP: per-CPU, APIC, IPI, spinlocks, TLB shootdown ────────
```

| Component | Where | Why / condition |
|---|---|---|
| memory, scheduler, syscalls, IPC | kernel | core of the system |
| interrupts, timers, SMP | kernel | must be on time |
| console, serial, framebuffer, PS/2 | kernel | needed for boot and diagnostics |
| PCI, disks (virtio, NVMe), GPT | kernel | on the path of every file read |
| VFS, page cache, FAT32, a future native FS | **kernel, permanently** | every `open`/`read`/`write` |
| init, shell, tools | user space | |
| networking | user space (`/bin/netd`, one per card) | card driver + ARP/IPv4/ICMP/UDP/TCP/DHCP/DNS in one process; programs talk to it over channels |
| USB + HID + USB storage | user space (`/bin/usbd`) | keyboard events go to the kernel via `input_inject`, disk sectors via `ublk`; a crashed usbd is restarted by init |
| audio, GUI, exotic filesystems | user space (future) | ring buffers / surfaces in shared memory; FS through the VFS (like FUSE) |

**The file system stays in the kernel.** A user-space FS means process → kernel → FS server → kernel →
disk on every call – that is what slowed down early microkernels. Linux, Windows and macOS keep the VFS in
the kernel.

**IPC rule: a message is control, data goes through shared memory** – a ring buffer on both sides, many
requests per batch, a notification only when the queue was empty. A call into the kernel costs
nanoseconds, a conversation with a service microseconds (channel ping-pong ≈ 6.6 µs on real hardware) – that
does not matter for a keyboard, but it does for disks and networking.

## Memory

### Address space

| Address | PML4 | What |
|---|---|---|
| `0x0000_0000_0000_0000 ..` | 0..255 | process (own PML4): ELF from `0x40_0000`, heap (`brk`), mmap regions from `0x1000_0000_0000`, stack below `0x7fff_ffff_0000` (grows to 8 MiB) |
| `0xffff_8000_0000_0000` | 256..383 | direct map: physical X at this address + X |
| `0xffff_c000_0000_0000` | 384 | kernel heap (max 64 MiB) |
| `0xffff_d000_0000_0000` | 416 | on-demand region |
| `0xffff_e000_0000_0000` | 448 | task stacks: 1 MiB slot, top 64 KiB mapped, the rest is a guard |
| `0xffff_ff00_0000_0000` | 510 | recursive mapping |
| `0xffff_ffff_8000_0000` | 511 | kernel image (code read-only), then a guard + 256 KiB stack |

The upper half is shared (entries 256..511 are allocated at boot), so changing CR3 swaps only the process
part. Protection: NX, SMEP, SMAP, CR0.WP, W^X for programs.

### Physical frames

- A bitmap of 4 KiB frames, plus contiguous ranges (for DMA); protected by an `IrqSpinLock`.
- **Per-CPU frame cache:** each CPU keeps up to 64 free frames, refilled and drained in batches of 32 under
  the lock (IF = 0). A single `alloc_frame` / `free_frame` takes no lock. Frames in the caches count as free.
- A second, atomic "allocated" bitmap verifies, without a lock, that a frame being freed really was allocated
  (double free, reserved frames, addresses outside RAM – refused).
- Contiguous ranges are always allocated under the lock; `alloc_frames_below` finds a range below an address
  limit (for 32-bit DMA devices).

### Kernel heap

- Blocks up to 32 KiB (alignment ≤ 16) are served from size classes 16 B..32 KiB (powers of two). Each CPU has
  its own free list per class (no lock, IF = 0; large classes hold 2–8 blocks) and exchanges batches with the
  shared heap.
- Larger blocks and alignment > 16 (for example structures containing a `SpinLock`, which is aligned to a
  64 B cache line) go to a shared address-ordered list (first-fit, coalescing) under one lock – avoid this
  on hot paths.
- The heap grows and returns pages from its end.
- **Rule: a hot allocator has no global lock per operation.** Why: a single heap lock once consumed 83% of
  CPU time on 16 cores.
- **Kernel heap reserve (8 MiB).** An empty heap is a kernel panic (a stable Rust toolchain has no fallible `Box`
  / `Arc`), so programs may fill the heap only up to 56 MiB: every syscall that makes the kernel allocate for the
  caller (data copies, new objects, processes, memory areas, paths, text for the caller – `allocates()` in
  `syscalls.rs`) is refused with `ERROR_OUT_OF_MEMORY` beforehand while less than the reserve plus 128 KiB is left
  (`heap::admit`, lock-free: an atomic copy of the bytes in use). Calls that give memory back or need none (exit,
  close, wait, kill, sleep, unlink, munmap) always work. The rest belongs to the kernel itself – the scheduler,
  interrupts, process exit, services' own work. This covers every way a program can grow the heap at once (many
  processes with many memory areas, blocked pipe writers, empty files, many objects – each with its own budget,
  but all of them together could exceed the heap); the budgets stay as the first line.
- **Rule: no multi-MiB heap blocks at run time.** After the heap has been full, its free space is fragmented
  (blocks allocated meanwhile stay where they are), so a large contiguous block may not exist even with most of the
  heap free. Large buffers live in pieces (ramfs files in 64 KiB chunks, the selftest RAM disk too) or in frames.
- **Sizes from a disk are untrusted.** A whole-file buffer (`fs::read_file`, exec), a FAT32 cluster chain and a
  FAT32 directory are allocated with `try_reserve`: a pendrive claiming a 4 GiB file or a huge chain gives
  `ERROR_NO_SPACE`, not a failed allocation; a directory over 65 536 entries (the FAT maximum, 2 MiB) is refused as
  corrupt before anything is allocated. Directory entries are read one at a time (`for_each_entry` – lookups build
  no list); a listing takes at most as many entries as can fit (`read_dir_max`: `readdir` asks for buffer / 7 + 1, a
  larger directory is `ERROR_BUFFER_TOO_SMALL` before any list is built), and the text for the caller stops at its
  buffer. Captured output of kernel-started programs keeps at most 1 MiB.

### Kernel memory reserve

Processes may use every frame except the **kernel reserve: 1/16 of RAM, clamped to 16–256 MiB**. The check is
lock-free (a copy of the free-frame counter plus the per-CPU caches) and happens on every process page
fault. Over the limit: the faulting process is killed, `shm_create` returns `ERROR_OUT_OF_MEMORY`. The kernel itself can
always allocate (see "Resource limits").

### Task stacks

64 KiB with a guard page. The stack of a finished task stays mapped and is reused by the next spawn (no
zeroing and no TLB shootdown).

### Process memory (`kernel/user/vm.rs`)

- A list of regions (heap, mmap, stack, shared), sorted by address; at most **4096 regions** per process (96 KiB of
  kernel heap) – one more is `ERROR_OUT_OF_MEMORY`, and so is a full kernel heap (the list grows with fallible
  allocation).
- **Lazy pages:** a page is created zeroed on first access (#PF from ring 3, or `copy_from_user` /
  `copy_to_user`).
- `brk` up to 1 GiB; anonymous `mmap`/`munmap`; 4 GiB total per process (a counter, not a sum on every call).
- **mmap addresses:** `0x1000_0000_0000` (`MMAP_BASE`) up to the lowest stack page (`MMAP_END`); next fit from the
  end of the last region with a guard page above every region, and from `MMAP_BASE` again at the end – ranges
  freed by `munmap` are reused, the range never runs out while the regions fit.
- **Protection:** `PROT_READ`, `PROT_READ | PROT_WRITE`, or `0` (`PROT_NONE` – a reserved range, never mapped: every
  access is a #PF, a kernel copy is `ERROR_INVALID_ADDRESS`). Pages are never executable.
- `munmap` skips stretches without a page table (2 MiB / 1 GiB / 512 GiB) instead of walking every page.
- `munmap` (and a shrinking `brk`) frees the page tables, directories and PDPTs that are left without any entry
  in the unmapped range (`AddressSpace::prune`), then reloads CR3 on this CPU so no cached entry points at a freed
  table (other CPUs load another CR3 whenever they leave the process). Before v0.67.0 they stayed until the process
  ended – with next-fit addresses a long-running process that keeps mapping collected one table per new 2 MiB (found
  by the soak test).
- A process is single-threaded, so only the process itself changes its regions and page tables – no locks.
- A ring-3 #PF runs on the task stack (no IST); a kernel stack overflow → #DF (on an IST stack).
- **Shared regions** – pages of a shared memory object, mapped eagerly, always NX; the frames belong to the
  object, not the process (see IPC).

## Processes and programs

```
kernel ── starts ──> /bin/init ──> /bin/sh ──> programs (ls, primes &, a | b ...)
                         ^                         |
                         └── orphans ──────────────┘
```

- The kernel starts only `/bin/init`. If init dies it is restarted; 3 deaths within 10 s → the kernel
  emergency shell. Init starts the shell and services (it contains the service manager) and reaps orphans;
  `kill(init)` → `ERROR_NOT_PERMITTED`.
- **`kill` only for descendants:** a process may end itself and its descendants (children, their children...),
  anything else → `ERROR_ACCESS_DENIED` (the kernel walks the parent links). Init is everyone's ancestor, so it can
  end anything; services are init's children, so a program ends a service only by asking init (`"kill <name>"` on
  the service channel – needs the shell's own channel, not the program channel). The shell's `kill` is a built-in
  (an external `/bin/kill` would be the shell's child, a sibling of the jobs, and could not end them).
- **`spawn` instead of `fork`/`exec`** – a new ELF image, a copy of the cwd, selected handles. `spawn_ex` gives
  the child **only** the listed handles (the basis of sandboxing).
- **Zombies.** A finished process stays a zombie (only its exit code) until the parent calls `wait`. Status:
  code 0..255 or `0x100 | reason` (9 = kill, 14 = #PF).
  - Zombies are stored **in the parent process** (`Process.zombies`, a per-parent lock), not in a global table.
    The child appends itself under the scheduler lock (`with_process` on the parent – it checks that the parent
    is not exiting and is still its parent). An exiting parent, in one section, sets `exiting`, takes its zombies
    and hands live children over (`reparent_with`); its zombies go to init. `wait` takes only its own list lock.
    A child whose parent finished exiting between the child reading `ppid` and looking the parent up checks
    `ppid` again and goes to the new parent (init) – otherwise its exit status was lost.
  - The list holds 4 entries inline in the process (no heap), more in a `Vec`.
  - The list lock is a single byte, not an `IrqSpinLock`. Why: `IrqSpinLock` is 64 B aligned and would push every
    `Process` onto the slow heap path. A compile-time assertion keeps `Process` ≤ 2 KiB with alignment ≤ 16.
  - A waiting parent sleeps in one of 64 wait queues; the wake condition is its own `child_gen` counter.
- **Ctrl+C** ends the process on top of the foreground stack, not the shell.
- **Programs** – static ELF64 written in Rust (`user/bin/*.rs`, library `user/lib/desoos.rs`), built into the
  kernel image (initrd) and unpacked into ramfs as `/bin/<name>`. Loader: lower half only, from 1 MiB, W^X, a
  System V-style stack (argc, argv). The library allocator uses `brk` (small blocks) and `mmap` (large).
- Shell: pipelines `a | b | c`, `>`, `>>`, `<`, quotes, history, `&`.

## Syscalls and handles

`SYSCALL`/`SYSRET`; number in RAX, arguments in RDI, RSI, RDX, R10, R8, R9; result in RAX (negative = an error, see
"Errors" below). Process memory is accessed only via `copy_from_user`/`copy_to_user` (page check + SMAP). Almost
all syscalls run without the Big Kernel Lock (99% of calls under stress).

| No. | Calls |
|---|---|
| 0–8 | `exit`, `write`, `read`, `open`, `close`, `getpid`, `sleep`, `yield`, `uptime` |
| 9–12 | `spawn`, `wait`, `getppid`, `kill` |
| 13–18 | `chdir`, `getcwd`, `readdir`, `stat`, `mkdir`, `unlink` |
| 19–20 | `readkey` (line editor), `tasks` (ps) |
| 21 | unused (`ERROR_NOT_IMPLEMENTED`) |
| 22–25 | `dup`, `dup2`, `seek`, `pipe` |
| 26–28 | `brk`, `mmap`, `munmap` |
| 29–30 | `handle_dup`, `handle_info` |
| 31–33 | `channel_create`, `chan_send`, `chan_recv` |
| 34, 35, 37 | `shm_create`, `shm_map`, `shm_size` |
| 36 | `spawn_ex` |
| 38 | `wait_many` |
| 39–41 | `dev_claim`, `dev_info`, `dev_map` |
| 42–43 | `irq_bind`, `irq_read` |
| 44–45 | `dma_alloc`, `dma_phys` |
| 46–47 | `sysinfo` (read-only), `sysctl` (reboot, halt, sync, stress, `desofs` – requires a `SYSCTL` handle) |
| 48 | `dev_find` |
| 49 | `input_inject` |
| 50 | `blk_attach` |
| 51–56 | `dir_open`, `openat`, `readdirat`, `statat`, `mkdirat`, `unlinkat` (directory handles) |
| 57 | `readdir_part` (a directory in parts through a directory handle, see DeSoFS) |
| 58 | `getrandom(buf, len, flags)` – up to 4096 random bytes from the kernel's generator; no right needed, never blocks (see "Random numbers") |

The syscall profiler (`prof.rs`) tracks all 58 numbers. Error numbers are the Linux ones, with DeSoOS names (below).

### Errors

One set of error names for the kernel and for programs (`kernel/user/syscalls.rs`, `user/lib/desoos.rs`;
`strerror` gives the text, `error_name` the name). A syscall returns the negative number. The numbers are the
Unix ones, so a future Linux compatibility layer needs no translation; the names are DeSoOS's – readable, with
one prefix, `ERROR_`.

| Name | No. | Text | Typical cause |
|---|---|---|---|
| `ERROR_NOT_PERMITTED` | -1 | operation not permitted | killing init |
| `ERROR_NOT_FOUND` | -2 | not found | no such file, service, topic or device |
| `ERROR_NO_PROCESS` | -3 | no such process | kill / wait on a process that does not exist |
| `ERROR_INTERRUPTED` | -4 | interrupted | Ctrl+C or kill while waiting |
| `ERROR_IO` | -5 | input / output error | the disk or the device failed |
| `ERROR_TOO_MANY_ARGUMENTS` | -7 | too many arguments | spawn with too many arguments |
| `ERROR_NOT_EXECUTABLE` | -8 | not an executable (bad ELF file) | spawn of a file that is not a valid ELF |
| `ERROR_INVALID_HANDLE` | -9 | invalid handle | no such handle, or a handle of the wrong kind |
| `ERROR_NO_CHILD` | -10 | no child processes | wait with no children left |
| `ERROR_WOULD_BLOCK` | -11 | would have to wait | non-blocking send / receive that would wait |
| `ERROR_OUT_OF_MEMORY` | -12 | out of memory | no free memory, a limit reached |
| `ERROR_ACCESS_DENIED` | -13 | access denied | a handle without a right from the rights table; the file sandbox |
| `ERROR_INVALID_ADDRESS` | -14 | invalid memory address | a pointer outside the process memory |
| `ERROR_BUSY` | -16 | already in use | a device another service owns |
| `ERROR_ALREADY_EXISTS` | -17 | already exists | mkdir of an existing name |
| `ERROR_NO_DEVICE` | -19 | no such device | no device at that address |
| `ERROR_NOT_DIRECTORY` | -20 | not a directory | a path through a file |
| `ERROR_IS_DIRECTORY` | -21 | is a directory | open of a directory |
| `ERROR_INVALID_ARGUMENT` | -22 | invalid argument | a bad flag, size or number |
| `ERROR_TOO_MANY_HANDLES` | -24 | too many handles | 64 handles in use |
| `ERROR_NO_SPACE` | -28 | no space left | the disk or a table is full |
| `ERROR_NOT_SEEKABLE` | -29 | not seekable | seek on the console or a pipe |
| `ERROR_READ_ONLY` | -30 | read-only | writing to a read-only disk |
| `ERROR_CLOSED` | -32 | the other end is closed | the other end of a pipe or channel is gone |
| `ERROR_BUFFER_TOO_SMALL` | -34 | buffer too small | the text does not fit (nothing is cut) |
| `ERROR_NOT_IMPLEMENTED` | -38 | no such system call | a syscall number without a row in the rights table |
| `ERROR_NOT_EMPTY` | -39 | directory not empty | removing a directory that has files |
| `ERROR_MESSAGE_TOO_LARGE` | -90 | message too large | a message over 4 KiB / the receive buffer too small |
| `ERROR_TIMED_OUT` | -110 | timed out | a service did not answer in time |

### Handles

Each process has a handle table (64 entries; 0/1/2 = stdin/stdout/stderr). Each entry is an object + rights.

Objects are reference-counted with `Arc` – they live as long as someone can see them.

| Kind | Object |
|---|---|
| — | console, file (`OpenFile` – position shared between copies, as in Unix), pipe end (64 KiB buffer; a write is copied in 4 KiB pieces, so a writer waiting for room holds 4 KiB of kernel heap, not 64), channel end |
| 5 `SHM` | shared memory object (also used for DMA buffers) |
| 6 `HW_ROOT` | the root of hardware access – only init has it |
| 7 `DEVICE` | one claimed PCI device |
| 8 `IRQ` | an interrupt bound to a device |
| 9 `SYSCTL` | permission for system actions (reboot, halt, sync, stress, `desofs`) |
| 10 `INPUT` | an input event source (keyboard/mouse) |
| 11 `BLK` | permission to register a block device |
| 12 `DIR` | a directory: work inside it by relative paths (`READ` – read and list, `WRITE` – create, change, remove) |

| Right | For | Meaning |
|---|---|---|
| `READ`, `WRITE` | console, file, pipe, directory, `INPUT`/`BLK` (`WRITE`) | missing → `ERROR_ACCESS_DENIED` |
| `SEND`, `RECV` | channel; `IRQ` (`RECV`) | missing → `ERROR_ACCESS_DENIED` |
| `MAP_READ`, `MAP_WRITE` | shared memory, device | missing → `ERROR_ACCESS_DENIED` |
| `DUP` | all | may be copied (`dup`, `handle_dup`, handle for a child) |
| `TRANSFER` | all | may be passed in a message |

**Rights can only be reduced** (`handle_dup(h, mask)`); no operation adds them.

**The rights table** (`kernel/user/sysrights.rs`): one row per syscall – which arguments are handles, of which
kinds, and which rights each needs – some only when the call asks for them (a mapping needs `MAP_WRITE` only
when it asks for writing; `openat` needs the directory's `READ` / `WRITE` according to its flags). `syscall_dispatch`
asks the table before the call is decoded – one gate for every syscall; the syscall functions only use the
objects. A handle that does not exist or is of the wrong kind → `ERROR_INVALID_HANDLE`; a handle without a right → `ERROR_ACCESS_DENIED`
(the same for every syscall, `read` / `write` included – unlike POSIX, where a read-only descriptor gives
`ERROR_INVALID_HANDLE`); a number without a row → `ERROR_NOT_IMPLEMENTED`. Handles passed in a list in memory (the handles in a message:
`TRANSFER`; the `wait_many` list; `spawn` / `spawn_ex`: `DUP`; the `sysctl` output handle: `WRITE`) are checked
by the call itself, and the row says so. The table also has the `path` column (file sandbox, below). It is
readable as text (`sysinfo rights`): `nr name path|- reg:kinds:need[+reg:bit:right]… …`.
RIGHTS TEST checks it three ways: the gate alone against every row (every right of every handle argument taken
away in turn), `/bin/rightstest` through real syscalls with a real object of every kind (it reads the table from
the kernel, so a new row is tested without changing it), and the gate's cost (~20–40 ns per syscall in QEMU TCG;
`[RESULT-RIGHTS]`).

**This is the whole permission model (capabilities).** A process has no user or group; what it may do is exactly
the handles it holds. Unlike Linux (UID/GID + `rwx` bits, root may do everything), a program started from the shell
gets only the handles its parent passes; `usbd` holds one claimed controller, `INPUT` and `BLK`, nothing else.
Files are the exception: by default a process may open any path – unless it runs in the file sandbox, where it
reaches only the files and directories it was given.

**File sandbox:** `spawn` / `spawn_ex` with `SPAWN_NO_FILES` starts a process with no file system access by
path. `open` (every mode), `stat`, `readdir`, `mkdir`, `unlink`, `chdir`, `spawn` and `spawn_ex` give `ERROR_ACCESS_DENIED`,
refused in one place before the call is decoded (the `path` column of the rights table; a new path syscall
must be marked there). File handles it was given **at start** keep working with their rights; it cannot receive new
ones: a message carrying a `FILE` or `DIR` handle is removed from its queue and dropped, and its `chan_recv` gives
`ERROR_ACCESS_DENIED` (checked before the size checks, so such a message can neither be taken nor block the queue).
The flag is inherited by every child and can never be cleared. Shell: `nofiles <program> [args]` – e.g. `nofiles cat < file` works (the shell opens the file and
passes the handle), `nofiles cat file` gets "access denied". Half of the `sysfuzz` children run in it.

**Directory handles** (`dir_open` → kind 12 `DIR`): a process works inside one directory by paths relative to the
handle – `openat`, `readdirat`, `statat`, `mkdirat`, `unlinkat`. The path is resolved by the kernel against the
handle's directory: an absolute path, or a `..` that would climb above the directory, is `ERROR_ACCESS_DENIED`;
`sub/../x` stays inside; `""` / `.` is the directory itself (list, stat – not remove). There are no symbolic links
(ramfs, FAT32), so there is no other way out. Rights: `READ` to read and list, `WRITE` to create, change and remove
(`openat` needs whichever its flags ask for); `handle_dup` makes a read-only copy. `dir_open` itself takes a path,
so it is refused in the sandbox – a sandboxed process gets directories only from its parent.
Shell: `nofiles --dir <dir> <program>` (read and write) or `--dir-ro <dir>` (read only) – the program gets the
handle in slot 4; the user library retries a refused relative `open` / `readdir` / `stat` / `mkdir` / `unlink`
inside it, so ordinary programs work unchanged: `nofiles --dir-ro /notes cat todo.txt`. Limit: the handle holds the
directory's path, not the directory itself – a directory removed and created again under the same name is reached
through the old handle (directories cannot be moved yet). Plan: a busy directory before folders can be moved, the
directory itself (a node number) with the native file system.
Test: FILE TEST 8/8 (`/bin/dirtest`: seven ways out refused, read-only / write-only rights, a sandboxed child with
only a read-only directory) and 3/8 (`nofiles --dir` in the shell).

**DCP (DeSoOS Capability Permissions)** is the name of this model, and `dcp` the command that shows it:
`dcp` (every visible process: devices, system powers, file access), `dcp inspect <pid>` (every capability with
its rights and a detail such as the PCI device, MSI vector, shared memory size, or who holds the other end of a
channel / pipe) and `dcp audit` (the last 64
refusals: sandbox path calls, a handle without a right from the table – with the missing right named, other
`ERROR_ACCESS_DENIED`). DCP names: kinds `CONSOLE`,
`FILE`, `PIPE`, `IPC`, `MEM_SHARE`, `DEVICE_CLAIM` (HW_ROOT), `DEVICE_CONTROL`, `DEVICE_IRQ`, `SYS_POWER` (SYSCTL),
`INPUT_SEND`, `DISK_ATTACH` (BLK); rights `READ`, `WRITE`, `SEND`, `RECEIVE`, `MAP_READ`, `MAP_WRITE`, `COPY` (DUP),
`SHARE` (TRANSFER). **Who sees what:** a process sees itself and its descendants (and audit entries of itself and
its descendants – each entry keeps up to 16 ancestors of the refused process as they were at that moment; PIDs
are never reused, so an old entry cannot show up for a newer process); a holder of `SYS_POWER` (the shell) and the kernel's emergency shell see everything. A process
changes its own table without locks, so other CPUs never touch its handles: the table (`FdTable`) publishes a
64-bit summary per slot in atomics on every change (kind, rights, detail), and `dcp` reads only those under the
scheduler lock (`user/dcp.rs`, `sched::process_caps`). The audit log is a fixed ring under a leaf spinlock,
written only on the error path of a syscall.

## IPC

Processes talk through **channels** (small messages, control) and **shared memory** (data).

### Channels (`kernel/user/channel.rs`)

A pair of ends, bidirectional; each end has its own queue.

- A message: up to 4 KiB of data + up to 8 handles; a queue holds up to 64 messages. **The sender's pid is filled
  in by the kernel** – it cannot be forged.
- **Handle transfer:** handles in a message are **moved** (they disappear from the sender and require
  `TRANSFER`). The whole list is validated before anything is removed; on error everything is put back.
- **No-cycle rule:** a channel end cannot travel through its own channel. Also, a channel end whose queue holds
  a message carrying another channel end cannot itself be sent in a message (`ERROR_BUSY`). This makes a cycle of
  ends inside queues impossible – the insertion that would close the cycle would have to send an end whose
  queue already holds the previous element. Why: such a cycle would never be freed. The check and the insertion
  happen under one `chan-xfer` lock (level 35, before the queue lock); only messages carrying channel ends take
  it.
- Full queue / empty queue: block, or `ERROR_WOULD_BLOCK` with `CHAN_NONBLOCK`. Buffer too small (`ERROR_MESSAGE_TOO_LARGE`) or no room
  for handles (`ERROR_TOO_MANY_HANDLES`) – the message **stays** in the queue and `info` reports the required size. Other side
  closed: `ERROR_CLOSED`. Kill / Ctrl+C interrupts the wait.
- Closing the last handle to an end frees the messages in its queue (including handles inside) and wakes the
  other side.
- The kernel can also wait on a channel with a deadline (`ChanEnd::recv` with timeout; used by `ublk`).

### Shared memory (`kernel/user/shm.rs`)

An object of up to 16 MiB; frames are allocated eagerly and zeroed.

- `shm_map(h, prot)` maps the whole object immediately in the mmap area; **never executable**, writable only
  with `MAP_WRITE`. `munmap` only as a whole.
- **Frames belong to the object.** Process exit first removes shared mappings (`release_shared`), then frees
  its own address space; the frames are returned when the last handle and the last mapping are gone.
- "Data ready" is signalled by a short message on a channel (a doorbell). Futexes and library ring buffers –
  Not implemented yet (only when measurements show a need).

### Kernel buffer budget

Channel queues and pipe buffers live on the kernel heap; together they are limited to **16 MiB** (`kbuf`).
Over the budget, `chan_send` / a pipe write returns `ERROR_OUT_OF_MEMORY`, so no process can exhaust the kernel heap
through IPC.

### Locking rules in IPC code

Each channel has its own lock (level `PROCESS`); there is no global IPC lock. Data from the process is copied
before taking the lock, data to the process after releasing it; under the lock there is only queue
manipulation, never sleeping.

### Performance (real hardware, 16 threads)

Ping-pong 6.6 µs; channel 165–190 thousand 4 KiB messages/s (645–744 MB/s); 16 MiB over a channel
21–25 ms vs. 5 ms through shared memory. A stress load of constantly communicating processes (killed while
waiting) does not slow the rest of the system.

## SMP and locking

```
BSP (CPU 0)                           AP (CPU 1..15)
PIT 1000 Hz: time, wake-ups           LAPIC timer 100 Hz: quantum
I/O APIC + MSI: device interrupts     IPI: resched, TLB shootdown, halt (panic)
```

- **AP startup:** INIT-SIPI-SIPI → trampoline below 1 MiB → straight to 64-bit → own GDT/TSS/IST, IDT, FPU,
  SMEP/SMAP, SYSCALL, LAPIC. The CPU number comes from `rdtscp` (TSC_AUX), because GS belongs to the process.
- **FPU/SSE:** saved and restored on every switch – migrating a process needs nothing more.

### Scheduler

- One global ready queue (FIFO), per-CPU `current` and a 10 ms quantum (`QUANTUM_TICKS` = 10). A task becoming
  ready → an idle CPU (IPI) or preemption.
- The lists (ready, `WaitQueue` channels, sleepers with deadlines) are intrusive in `Task` – **nothing allocates
  under the scheduler lock**. `WaitQueue` checks the condition and goes to sleep under the scheduler lock, so a
  wake-up from another CPU cannot be lost.
- **Scheduler lock:** a spinlock with an owner CPU, recursive on the same CPU, always held with IF = 0. Its wait
  loop reads the owner and tries `compare_exchange` only when the lock looks free (test-and-test-and-set). Why:
  a `compare_exchange` on every spin steals the cache line from the holder and from other waiters, and the
  hand-off cost grows with the number of waiters ("Non-scalable locks are dangerous"). The same approach is used
  by the zombie-list lock and the TLB shootdown initiator; ordinary spinlocks also spin on reads, and the BKL is
  a ticket lock.
- **Task table under its own RW lock** (`TABLE` in `sched/mod.rs`, a `RwSpinLock`). It holds `tasks` + `ids`.
  Writers: `spawn_in` (insert), `reap` (remove), `reparent_with` (change parents – must exclude
  `with_process`). Readers in parallel: `with_process`, `task_exists`, `children_of`, `for_each_process`.
  Readers do not see `state`, only an atomic `dead` mirror (state changes under the scheduler lock). Order:
  scheduler → table (spawn and reap take both); readers take only the table, with IF = 0. A task lives as long
  as it is in the table, so a reference obtained while reading is valid until the lock is released. Why: reads
  of processes by id (`wait`, `kill`, parent lookup) were the most frequent users of the scheduler lock.
- **Context switch outside the lock.** Under the scheduler lock: picking the next task, states, queues,
  `current[]`. Then the lock is released, and only after that come FXSAVE/FXRSTOR, TSS / SYSCALL stack, CR3 and
  `sched_switch`. Each task has an `on_cpu` flag, set when it is picked and cleared by the CPU after it has left
  the task (the first thing the next task does, `finish_switch`). A CPU that picked a task still marked `on_cpu`
  (e.g. woken before the previous CPU left it) waits for the flag to clear (a few hundred ns) – like `on_cpu` in
  Linux. Reap skips tasks with `on_cpu` set (a dead task may still be on its own stack). Wake-ups are unchanged
  (state and buckets under the lock), so sleep and wake-up cannot miss each other. Why: switching under the
  lock (the lock was released only by the next task) kept the global lock held during the most expensive part
  of `wait_event` and `exit`; under stress on 16 threads the lock was busy ~27% of the time.
- **Idle polling before `hlt`.** An idle CPU first spins briefly with IF = 1 and a `POLLING` flag set; a waker
  that sees the flag only sets `NEED_RESCHED` and skips the IPI. The flag/`NEED_RESCHED` ordering (Dekker-style,
  `SeqCst`) plus a final check with IF = 0 right before `hlt` guarantee no wake-up is lost. The spin window
  adapts per CPU (like Linux `haltpoll`): if work arrived within the window after sleeping, the window doubles
  (minimum 10 µs); after a longer sleep it halves down to 0, so an idle system does not spin (battery). Upper
  bound: `DESOOS_IDLE_POLL_US` (default 200 µs; 0 = `hlt` immediately); `DESOOS_IDLE_POLL_ADAPT=0` gives a fixed
  window. Why: on real hardware `hlt` puts the core into a deep sleep state and waking takes tens of µs, which
  lengthens every task hand-off.
- **`yield_now` hands the BKL over.** Kernel tasks run under the BKL; the switch releases it, but when nothing
  else is ready on that CPU there is no switch, the task keeps running – and kept the BKL. `yield_now` now lets
  a waiting CPU in (release + a new ticket) before returning. Why: a task waiting for others in a yield loop held
  the BKL until a timer tick happened to hit its short IF = 1 window; the tasks it waited for needed the BKL, so
  under QEMU TCG the whole system stood for seconds to minutes (the rare ALLOC TEST 4/5 "hang": 3 stalls of 30 s
  to 111 s in ~400 runs of the test before, none after the fix in 400 runs with 4 CPUs and 400 with 8).
- The idle loop runs without the BKL; only one CPU at a time reaps dead tasks (taking the BKL only when there is
  something to free). Why: idle CPUs re-taking the BKL after every wake-up caused most of the BKL contention.
- Future (only if measurements show the scheduler lock still contended): per-CPU ready queues with work
  stealing (as in FreeBSD ULE; MuQSS-style trylock when picking), separate locks for wait buckets (protocol like
  Linux `try_to_wake_up`), remote wake-up via a list + IPI (Linux `TTWU_QUEUE`). Why not now: a single global
  queue (as in BFS) scales to about 16 CPUs, which is the current target.

### Lock types

- *Big Kernel Lock* – only rare paths remain (ring-3 exceptions, PS/2 keyboard, `tasks`, freeing a process
  address space in reap, `dev_*` syscalls, `input_inject`). Ticket lock.
- *Scheduler lock* – see above.
- *SpinLock / IrqSpinLock* – short sections; a lock taken both with and without the BKL must be an
  `IrqSpinLock`.
- *RwSpinLock* – read often, µs sections (ramfs tree, task table).
- *KMutex / KRwLock* – sleeping locks (VFS, disks); a short spin (`SPIN_ITERS` = 200) before sleeping, waking
  one waiter.

### Lock ordering

Locks are taken in ascending level order. **Lockdep-lite** checks this at run time: a violation is a panic
naming both locks and where they were taken. Inside an interrupt handler, locks taken by the handler are marked
in the held-locks table and the order is checked only against them (a lock held by the interrupted code is not
a violation – the interrupted code does not wait for the handler); recursion is always checked.

| Level | Lock |
|---|---|
| — | Big Kernel Lock (always outermost) |
| 20 `VFS` | VFS |
| 30 `BLOCK` | block layer disk list, disk drivers |
| 35 `CHAN_XFER` | passing channel ends in messages (no-cycle rule) |
| 40 `PROCESS` | processes (descriptors), pipes, channels |
| 45 `WAITERS` | `wait_many` observer lists (`IrqSpinLock`) |
| 50 `SCHED` | scheduler (outside lockdep, recursive) |
| — | task table (`RwSpinLock`, taken after the scheduler) |
| (52) | per-parent zombie list – a one-byte lock with IF = 0, outside lockdep (under the scheduler or alone; never two at once) |
| 55 `PAGING` | page tables, task stack pages |
| 100 `OUTPUT` | process output (captured stdout, shell line) |
| 225 `EXIT_LOG` | process exit log (leaf, no allocation) |
| 227 `RANDOM` | the random number generator (`random.rs`; leaf, no allocation, never in an interrupt – interrupts write per-CPU counters) |
| 230 / 240 `HEAP` / `FRAMES` | heap / frame allocator (allocation allowed from anywhere, including interrupts) |
| 250 / 255 `TLB` / `CONSOLE` | TLB shootdown / console (logging is always allowed) |

Levels 200–220 are reserved for tests. While holding a spinlock it is forbidden to sleep, wait for the BKL or
execute `hlt`.

### Other SMP mechanisms

- **TLB shootdown** (upper half): clear the PTE → IPI to the other CPUs + wait for acknowledgement → only then
  free the frame. A CPU waiting with IF = 0 services pending requests itself – **every** wait loop with IF = 0
  must call `tlb::poll_from_wait()` (spinlocks, rwlocks, BKL, scheduler lock, console, the zombie-list lock):
  the holder of the lock may free heap memory, the heap shrinks, and the holder waits for acknowledgements from
  exactly the CPUs that wait for its lock. The zombie-list lock (`ChildList`) once lacked it – a rare deadlock
  on TCG; TLB TEST 6/6 recreates that situation. The lower half needs no shootdown –
  a process runs on one CPU at a time (no threads yet).
- **Time:** the HPET is the only shared counter – **TSCs of different cores are not guaranteed to be
  synchronized** on real hardware, so measurements are taken on one CPU (task CPU time). PIT ticks catch up with
  the HPET; wall clock = RTC at boot + uptime.
- **Clock gaps:** the PIT interrupt goes to CPU 0 only. A gap > 2 ms is recorded (`cpus`: start, length, other
  interrupts CPU 0 took meanwhile); after 6 ms another CPU sends CPU 0 an NMI that records RIP, IF and return
  addresses (`gap_probe` / `gap_nmi` in time.rs). On the test laptop the only long gaps (33–40 ms) start exactly
  when `usbd` asks the firmware to hand over an xHCI controller: firmware SMM work (SMI), not the kernel – the NMI
  lands only after the machine resumes, inside the interrupted MSI handler. Linux sees the same. The ticks are
  caught up from the HPET.
- **Per-CPU data** lives in separate cache lines (`PerCpu`, `PerCpuCounter`) – dense arrays of atomics caused
  false sharing (7–15% of throughput).
- **Watchdog:** if the clock stalls for 10 s → NMI to all CPUs and a report (BKL owner, RIP, IF, spinlocks).
  Spinlock deadlock detector (HPET): report after 2 s, panic after 10 s.

## Files

- **VFS** (`kernel/fs/`) with mount points; `/` = ramfs, `/disk` = FAT32, `/esp` = EFI partition, `/usbN` = FAT32
  on USB storage (read-only).
- `FS_LOCK` is a readers–writer lock. Filesystems with their own locking (`ConcurrentFs`) run concurrently under
  the read side. ramfs: the tree under a `RwSpinLock`, each file's contents under its own mutex (a deleted file
  lives as long as someone reads it). File data is kept in 64 KiB chunks (a chunk's capacity doubles up to 64 KiB,
  so small files stay small): appending never copies the whole file – with one `Vec` per file, 10 MiB written in
  4 KiB pieces took 19.5 s in QEMU, now 52 ms.
- `fs::Locked<F>` wraps a filesystem without its own locks in one sleeping `Mutex` and implements
  `ConcurrentFs`, so it also runs under the read side of `FS_LOCK`. Used for FAT32 on USB disks: waiting for a
  slow pendrive blocks only that filesystem. `kind` / `source` / `read_only` are copied at mount time (so `mount`
  and `open` do not wait for the disk); `df` (`mount_stats`) goes through the concurrent path. Mount and unmount
  (write side) wait for in-flight reads – at most the ublk timeout (5 s).
- **FAT32:** long file names (including Polish characters), cluster-leak check; `fat32::mkfs` is used only by tests (the shell command was removed in v0.64.1 – DeSoOS formats only as DeSoFS). **Volume bounds:** on an MBR
  partition the length comes from the partition table; a BPB claiming more sectors than the partition (or the
  disk) does not mount (`file system corrupt`), and every sector read or written is checked against the volume –
  a lying or damaged FAT32 never reaches the next partition. A volume with more clusters than FAT32 can number
  (over 0x0FFFFFF5 – higher values are the bad-cluster and end-of-chain markers) does not mount either. Performance features
  (each pendrive request is a SCSI command costing hundreds of µs to ms):
  - FAT read in blocks of 8 sectors,
  - cluster cache (≤ 512 KiB / 64 entries, write-through) – reading a file does not re-read path directories,
  - contiguous clusters of a file read in one request (≤ 1 MiB),
  - 64 KiB read-ahead for small reads,
  - remembered position in the cluster chain (sequential reads do not walk the chain from the start; `fat_set`
    invalidates it).
- **Read-only disks:** FAT32 on a read-only disk rejects changes immediately (`open` for writing → `ERROR_READ_ONLY`).
  `df` on a read-only disk counts free clusters from the FAT itself (once, in 64 KiB blocks), because FSInfo may
  be stale.
- **Block layer:** disks in a `Vec<Option<Arc<Disk>>>` under a `block list` SpinLock (level `BLOCK`) used only
  for lookup; each `Disk` has its own `KMutex`, so a slow USB disk does not stall NVMe or virtio. Partition →
  parent disk, always in that order; `partitions_of` takes no disk locks. Disks can be removed; a block-layer
  number returns to the pool only after unmount, and `sdX` names keep increasing and are never reused.
- `desofs` works in the shell started by init (sysctl, `SYSCTL` handle). Raw disk writes (`disk read/write`) and
  asm test programs (`run`) are available only in the kernel emergency shell; `/bin/sh` answers "only in the kernel
  emergency shell".

## Hardware and data safety

- **ACPI** – tables only (no AML): MADT (cores, I/O APIC), MCFG (PCIe ECAM), HPET.
- **PCI** – I/O ports, then ECAM (when consistent with ports). Device interrupts via **MSI/MSI-X** (INTx needs
  AML). ISA lines (timer, keyboard, serial, mouse) via the I/O APIC; the 8259 PIC is masked.
- **Disks** – virtio-blk, NVMe (admin + I/O queue), GPT/MBR partitions as separate disks; USB storage via `ublk`.
- **Input/output** – UEFI framebuffer (text console with Polish characters, scrollback), serial, PS/2 (keyboard,
  mouse), USB keyboard/mouse via `/bin/usbd`.

**Data protection on real hardware** – independent barriers:

1. the NVMe driver writes only to a controller emulated by QEMU; a real SSD is read-only,
2. the block layer rejects every write to a read-only disk (partitions, formatting, files → `ERROR_READ_ONLY`),
3. FAT32 on a read-only disk rejects changes up front,
4. USB storage is read-only end to end (see "USB").

## User-space services

Goal: a device driver as an ordinary process. The kernel gives it access to **one** device – through handles,
like everything else. A service crash does not affect the kernel or other processes; init restarts it.

```
 kernel                                  init (has HW_ROOT)               service /bin/edud
 ──────                                  ──────────────────               ─────────────────
 PCI table, device owner           ◄── dev_claim(root, 00:06.0) ──► DEVICE handle ─spawn_ex─► slot 3
 MSI → IRQ object (counter, wake) ─────────────────────────────────────────► wait_many: IRQ
 DMA frames (contiguous, < limit) ◄── dma_alloc(dev, size) ──────────────── maps, writes address
 BAR registers (UC, NX) ─────────────────── dev_map(dev, bar) ──────────────► MMIO in the process
                                         client ── "edu" + channel end ──► init ──► service
```

### Waiting on many handles – `wait_many`

A service waits at once for requests from many clients (each with its own channel) and for an interrupt.
`wait_many(list, n, timeout_ms)` – a list of up to 16 [handle, signals] pairs; returns a mask of ready entries
(bit i = entry i), 0 = timeout.

| Signal | Ready when |
|---|---|
| `READABLE` | channel: a message is queued or the other side closed; pipe: data or no writers |
| `WRITABLE` | channel / pipe: there is room or the other side closed |
| `IRQ` | interrupt object: counter > 0 |

Requires `RECV` / `SEND` / `READ` (as for the operation being waited for). Kill / Ctrl+C interrupts (`ERROR_INTERRUPTED`).

**How it works:** every waitable object (channel end, pipe, IRQ) has an observer list (up to 16 tasks) under its
own lock. `wait_many` registers the task with each object, checks the conditions and sleeps on its own
`WaitQueue` channel (the task number); a state change wakes the observers. After waking it unregisters from all
of them. No scan of all tasks, no global lock. A wake-up is never lost, because registration happens before the
condition check (as in `KMutex`). The observer count is atomic, so an object with no waiters does not take the
list lock. Code: `kernel/user/waitset.rs` (`Observers`, `IrqSpinLock` at level `WAITERS` = 45), `syscalls.rs`
(`sys_wait_many`).

### Device claims

- **`HW_ROOT`** (kind 6) – the only object a device can be taken from. The kernel creates it once and gives it
  **only** to `/bin/init` (slot 3). Init does not pass it on; services get single devices.
- **`dev_find(root, class, n)`** (48) → the BDF of the `n`-th device with a given class (24 bits: class, subclass,
  prog-if); `ERROR_NOT_FOUND` when there are no more, `ERROR_INVALID_HANDLE`. Requires `HW_ROOT`.
- **`dev_claim(root, PCI address)`** → a `DEVICE` handle (kind 7; rights `MAP_READ|MAP_WRITE|DUP|TRANSFER`).
  One device – one owner at a time (`ERROR_BUSY`). Refused (`ERROR_ACCESS_DENIED`):
  - the device has an in-kernel driver (virtio disk, NVMe, the graphics card with the framebuffer),
  - mass storage class (0x01) – **always**, even without a driver (protects disks on real hardware),
  - bridges (0x06) and the interrupt controller – changing their settings breaks the whole system.
- **`dev_info(dev, out)`** – vendor, device, class, BAR sizes, whether MSI is present.
- **`dev_map(dev, bar)`** → an address in the process mmap area: the registers of a memory BAR, **uncached (UC),
  never executable**. Pages containing the MSI-X table / PBA are skipped – writing there could direct an
  interrupt to any vector (e.g. a kernel IPI). The BAR must be ≥ 4 KiB and page-aligned. I/O-port BARs – Not
  implemented yet (future: TSS I/O bitmap).
- A service never writes PCI configuration space (BARs, MSI and bus mastering are set by the kernel).
- A mapping keeps the claim alive. Process exit removes shared mappings already in `exit_current`, so the device
  is free before the parent (the service manager) gets the status from `wait`. `dev_*` syscalls run under the
  BKL (PCI configuration via ports). `lspci` shows the device owner.
- Code: `kernel/user/device.rs` (`DevClaim`, BAR pages), `drivers/pci.rs` (`OWNERS`, `claim_user`,
  `msix_regions`), `vm.rs` (`map_mmio`, `SharedRef`).

### Interrupts

- **`irq_bind(dev)`** → an `IRQ` handle (kind 8, right `RECV`; requires `MAP_WRITE` on the device). The kernel
  allocates an MSI vector (0x30–0x3F, freed again on release – services can restart), writes it to the device,
  enables MSI and bus mastering (MSI is a memory write).
- The kernel handler only increments a counter and wakes observers – nothing else (no locks except the observer
  list, an `IrqSpinLock`). MSI is edge-triggered, so the line need not be masked. The handler also records an
  HPET timestamp of the vector's last interrupt (used for HID latency).
- `irq_read(irq)` → how many interrupts since the last read (and resets it). Several interrupts before handling
  = one wake-up with a count; nothing piles up. The counter means "at least one" – the APIC merges interrupts of
  the same vector that arrive before the previous one was serviced. After waking, a service always reads the
  device status, like any driver.
- INTx (level-triggered lines) – not supported: on real hardware they require ACPI AML.
- Code: `device.rs` – static vector ↔ counter slots + `Observers` (the handler never touches memory someone could
  free), `IrqObj` (keeps the claim; Drop: MSI off → read back a register → `msi::free`).

### DMA

- **`dma_alloc(dev, size, address_bits)`** → a shared memory handle (mapped with `shm_map`) + a physical address
  (`dma_phys`). Frames are **contiguous**, zeroed, below `2^address_bits` (32-bit devices; `edu` defaults to 28
  bits). Up to 2 MiB per buffer, 16 MiB per device. The first `dma_alloc` enables bus mastering.
- **A DMA buffer lives as long as the device claim** – closing the buffer handle does not free it. Otherwise a
  service could free a buffer the device is still writing to, and the frame would end up in the kernel or another
  process.
- **Without an IOMMU** a bus-mastering device can write all memory – a user-space driver is therefore isolated from
  bugs in its code (pointers, panics), not from malicious programming of the device. Hence only init has
  `HW_ROOT`, and disks are excluded from `dev_claim`. IOMMU (Intel VT-d / AMD-Vi) – Future.
- Code: `DevClaim::dma_alloc` (buffer list in the claim, 16 MiB limit), `ShmObj::new_dma`,
  `frame::alloc_frames_below`.

### Cleanup after a service (kill at any moment)

When the last `DEVICE` handle disappears (process exit, close), the kernel, in this order:

1. disables bus mastering and MSI in the device and reads a register back (PCI writes are posted – the read
   guarantees they arrived),
2. unmaps the BARs from the process (already done by process exit or `munmap`),
3. frees the MSI vector and the IRQ object (wakes observers – `wait_many` returns an error),
4. only then frees the DMA frames,
5. releases the claim – a new service instance can take the device.

### Service manager in init

- **Manifests:** init reads `/etc/services/*.svc` once at its start (built into the kernel image from
  `user/etc/services/`, written to ramfs at boot – a file changed later has no effect: init does not read it again, and every boot writes the files anew from the image). A manifest says
  exactly what a service gets – nothing is given by program name any more:

  ```
  name       usb                  # usb0, usb1… with `instances`
  title      xHCI USB controller  # messages only
  program    /bin/usbd
  device     class 0c0330         # every device of the class (dev_find); or `device pci 00:06.0`; or none
  instances  4
  grant      input                # INPUT handle, slot 5
  grant      blk                  # BLK handle, slot 6
  files      none                 # SPAWN_NO_FILES – no path calls at all; or `all`
  ```

  Shipped: `edu` (pci 00:06.0), `echo` (no device), `usb` (class 0C0330, input + blk), `net` (class 020000) – all
  with `files none` (no path calls, and no file or directory handle can be handed to them later). An unknown key or
  grant, a key or grant given twice, a missing name / program / files line, or a service name already used (also by
  an instance like `usb0`) → "bad manifest (…)", the service is not started, the others are. A class manifest whose
  devices would exceed the 16 services is not started at all (no device silently left without its driver); more
  devices than `instances` are reported. `dev_claim` refused for any reason other than `ERROR_BUSY` (e.g. a device a
  kernel driver owns – `ERROR_ACCESS_DENIED`) → "cannot claim device … - not started", state broken, no retrying. For each instance: `dev_claim` from `HW_ROOT` → `spawn_ex`
  (slot 1 console, 3 device, 4 connection channel, plus its grants). No device (`ERROR_NO_DEVICE`) → state "no
  device", no attempts.
- **Restart:** after the process ends, a 100 ms delay, doubled up to 5 s (back to 100 ms after 10 s of stable
  running); 5 failures within 30 s → "broken", no more restarts. `ERROR_BUSY` at start (the old instance is still
  being cleaned up) → retry in 100 ms.
- **Connecting by name:** the shell and its programs have, in slot 3 (`SVC`), a channel end to init with only
  `SEND | DUP` rights (only init can receive). A client creates its own channel and sends `"connect edu"` + one
  end; init forwards that end to the service's connection channel (without waiting); afterwards the client and
  the service talk directly. Unknown / not running service → init closes the end and the client gets `ERROR_CLOSED`.
  `"list"` + an end → init replies with lines "name state pid N restarts N (program)" and closes.
  `"kill <name>"` + an end → init ends the service (it is restarted by the rules below) and replies `killed <name>
  (pid N)`, `not allowed` (the program channel or a narrowed one), `no such service` or `not running`. Library:
  `svc_connect("edu")`, `svc_list(buf)`, `svc_kill("net0", buf)`; commands `services`, `kill <name>`.
- Service crashed → its clients get `ERROR_CLOSED` and reconnect (after the restart).
- The shell checks at startup whether slot 3 is a channel; if so, it starts programs with `spawn_ex` and
  `[(in,0), (out,1), (2,2), (5,3)]` – the program channel from slot 5 as the child's slot 3 (only `netconfig` gets
  the shell's own channel, see "Network access is a capability"), otherwise with `spawn`.
- Init loop: restarts whose time has come → `wait_many` on the svc channel (at most 100 ms) → reaping children
  (`wait` with `WNOHANG`): shell, services, orphans.
- `init test <program>` – self-test mode: instead of the shell, `<program>` runs; when it ends, init closes the
  connection channels, kills the services, waits for them and exits with the program's code.
- **Future: a separate `/bin/svcmgr`.** Init would stay minimal (shell, `svcmgr`, orphans). Benefit: a bug in the
  manager would not restart init and the shell. Cost: after a manager crash the services run unsupervised and a
  new manager must find them (their devices are still claimed – `ERROR_BUSY`). Currently everything is in init because
  it is simpler; the move is a user-space code change only, with no kernel changes – to be done when the manager
  grows or its crashes become a problem.

### `sysinfo` and `sysctl`

- **`sysinfo(topic, buffer)`** (46) – read-only text: `ver`, `uptime`, `date`, `mem`, `counters`, `irq`, `cpus`,
  `lspci` (`-v`), `acpi`, `disk` (list only), `mount`, `df`. Any program may ask. The shell runs these by name
  (`mem`, `lspci -v > file`). `counters` is for programs (the soak test): one `name value` per line – `frames_free`
  (after the task stack cache is emptied), `heap_used`, `heap_mapped`, `heap_console` (the screen scrollback inside
  the heap: a cache of at most 1000 lines that fills up and stays – not a leak), `tasks`, `tasks_dead`, `processes`,
  `zombies`, `ipc_bytes`, `ramfs_bytes`, and `mem_<pid>_<name>` (heap + other areas of every process).
- **`sysctl(handle, action, arg, fd)`** (47) – `reboot`, `halt`, `sync`, `stress [s]` (actions 1–4) and `desofs`
  (5 info, 6 format, 7 mount, 8 unmount, 9 check, 10 repair, 16 ramdisk – `arg` = size in MiB; `arg` = disk number in bits 0–31, bit 32 = "yes" for
  format / repair – checked by the kernel, so without it nothing is written even for a program calling sysctl
  directly; any other bit or "yes" elsewhere → `ERROR_INVALID_ARGUMENT`). The text goes to `fd`, at most 64 KiB
  including the line "... output truncated: N bytes more" (`shell::Capped` keeps room for it; never a silent cut).
  `fd` is checked before the action (v0.65.1: before, a bad one was found only after a format had run) – the console
  (not stdin), or a handle with `WRITE` to a pipe's write end or a file opened for writing; otherwise
  `ERROR_ACCESS_DENIED` (no `WRITE`) / `ERROR_INVALID_HANDLE`. The `desofs` actions
  run the same code as the kernel emergency shell; the result comes at the end (no progress while it runs; the
  syscall holds the BKL, which is released while it waits for the disk). The caller's own current directory does
  not keep a mount busy for it: its pin is dropped for the action and taken again (on "/" if the unmount moved it).
  The handle is checked twice: by the rights table (argument 0 must be a `SYSCTL` handle) and in `sys_sysctl`.
  Works only with a `SYSCTL`
  handle (kind 9, right `DUP` only: it can be given to a child via `spawn_ex`, but not sent in a message). The
  kernel creates it only for init (slot 4); init gives a copy to the shell (slot 4), and the shell does **not**
  pass it to programs – a program started from the shell cannot reboot the computer. System actions sit behind a
  handle, consistent with the permission model.

Init slots at startup: 3 `HW_ROOT`, 4 `SYSCTL`, 5 `INPUT`, 6 `BLK`.

### Example service – `edu`

`edu` (PCI 1234:11e8) is a QEMU device made for learning driver writing: an identification register, factorial
computed in a register, an interrupt on request and after the factorial, DMA to a buffer. The QEMU test scripts
use `-device edu,addr=06`. Real hardware has no `edu`; there `/bin/echod` (a service without hardware) exercises
the manager, restarts and `wait_many`.

**`/bin/edud`** – the edu driver as an ordinary process:

- handles at startup: 1 console, 3 device, 4 connection channel; registers via `dev_map`, interrupt via
  `irq_bind`, buffer via `dma_alloc`,
- one `wait_many` loop: connection channel + interrupt + up to 14 clients; requests served in turn (there is one
  device), replies sent without waiting (a client that does not receive cannot stall the service); completion is
  decided by device status, the interrupt only wakes,
- protocol `user/lib/edu_proto.rs`: a 16 B header (`op`, `arg` / `status`, `value`) + data; `PING`, `FACT`, `COPY`
  (DMA, up to 4000 B), `STATS`; a bad request → `ERROR_INVALID_ARGUMENT`, the service keeps running,
- service killed → clients get `ERROR_CLOSED`, the device is released immediately, a new instance can claim it,
- exit: connection channel closed and no clients – code 0.

**Measured cost** (same work on `edu` in the kernel and in user space, QEMU KVM, 4 CPUs): interrupt → driver
woken 32.6 µs kernel / 31.9 µs service; factorial 53.1 / 55.5 µs (in-process), 84.4 µs for a client via `edud`;
`PING` via the service 22.6 µs; service restart 1.2 ms. Conclusion: a user-space driver adds no measurable cost
to interrupt handling – under KVM the time is dominated by the host waking a halted virtual CPU (~3 µs under TCG,
where the CPU does not sleep). An intermediary (client → service) costs about 2 process switches. Benchmarks:
`kernel_edu_bench` in `test_svc.rs`, `/bin/svcbench`.

## USB

USB keyboards, mice, hubs and USB storage (read-only) are handled by a **user-space service** `/bin/usbd` (one
per xHCI controller), built on the service mechanisms above. The kernel receives only two things from USB:
**input events** and **disk sectors**. Nothing of the USB protocol lives in the kernel.

```
 kernel                                   init (HW_ROOT, INPUT, BLK)          usbd (one per controller)
 ──────                                   ──────────────────────────          ─────────────────────────
 dev_find(class 0C03/30) ───────────────► controller BDFs ─ spawn_ex ───────► slot 3 DEVICE, 4 INPUT, 5 BLK
 PCI table, MSI-X, DMA frames   ◄──────── dev_claim / irq_bind / dma_alloc ── xHCI rings, TRBs, contexts
 kernel/input.rs ◄── input_inject(INPUT, events) ──────────────────────────── HID reports → events
 ublk (BlockDevice) ◄─ channel: request / reply, data in DMA buffer ───────── BOT + SCSI READ(10)
 FAT32 /usbN (read-only)                                       client ── "usb0" ──► init ──► usblist, status
```

### Security boundary – DMA without an IOMMU

usbd itself writes physical addresses into xHCI structures (DCBAA, rings, TRBs, contexts). **The kernel cannot
check those addresses** – the controller reads them directly from memory. Without an IOMMU a buggy or malicious
usbd can make the controller write anywhere in RAM, including the kernel.

- Process isolation of usbd protects against: panics, bad pointers, hangs, leaks, bad state after a crash – the
  kernel cleans up and init restarts it.
- **It does not protect against rogue DMA.** usbd is therefore trusted system code (like an in-kernel driver),
  only running in a process. Hence: only init has `HW_ROOT`, usbd gets a single device, and the usbd binary is
  built into the image (initrd), not loaded from disk.
- Remaining constraints: buffers only from `dma_alloc` (contiguous, 16 MiB per device), living at least as long as
  the claim; after usbd dies, bus mastering is disabled before frames are freed.
- Full DMA isolation: IOMMU – Future.

### Syscalls and handles

| No. | Call | Handle / rights | Result, errors |
|---|---|---|---|
| 48 | `dev_find(root, class, n)` | `HW_ROOT` | BDF of the `n`-th device of the class (24 bits: class, subclass, prog-if); `ERROR_NOT_FOUND` – no more, `ERROR_INVALID_HANDLE` |
| 49 | `input_inject(h, events, n)` | `INPUT`, `WRITE` | LED state (bit 0 Num, 1 Caps, 2 Scroll) – usbd sets them on the keyboard; `ERROR_INVALID_ARGUMENT` (n > 64, bad kind), `ERROR_INVALID_ADDRESS`, `ERROR_INVALID_HANDLE` |
| 50 | `blk_attach(h, channel, buffer, info)` | `BLK`, `WRITE`; channel `SEND`+`RECV`+`TRANSFER`; buffer `MAP_READ` | USB disk number (0 = sda); `ERROR_INVALID_ARGUMENT` (block ≠ 512/4096, 0 blocks, slots outside 1..8, buffer < slots × 64 KiB), `ERROR_NO_SPACE` (8 USB disks), `ERROR_ACCESS_DENIED`, `ERROR_INVALID_HANDLE`, `ERROR_INVALID_ADDRESS` |

Handle kinds **10 `INPUT`** (rights `WRITE` + `DUP`, no `TRANSFER`) and **11 `BLK`**. The kernel gives them to
init at startup (slots 5 and 6); init passes each usbd a copy **without `DUP`** (usbd cannot pass them on); the
shell does not get them. `INPUT` is effectively the system keyboard (it can type into the shell) – hence the
narrow distribution. No new error codes were needed (`ERROR_IO`, `ERROR_NO_DEVICE`, `ERROR_BUSY`, `ERROR_NO_SPACE`, `ERROR_INVALID_ARGUMENT`, `ERROR_INVALID_HANDLE`,
`ERROR_READ_ONLY`).

### Input – `input_inject`

An 8 B event: `kind u8`, `pressed u8`, `code u16` (HID usage, page 7 – keyboard), `dx i16`, `dy i16` (mouse: kind
2, `code` = buttons, `pressed` = wheel as i8). At most 64 events per call.

- All events are validated first (bad kind → `ERROR_INVALID_ARGUMENT`, nothing is applied). The kernel translates HID usage →
  `KeyCode` (table in `kernel/input.rs`, next to the PS/2 translation) and continues as for PS/2: modifiers,
  Caps/Num, Polish layout, console, `readkey`, `keys`. Mouse wheel → `mouse::add_wheel` (console scrolling);
  cursor – together with the GUI (Future).
- **Autorepeat in the kernel** for USB sources (a USB keyboard, unlike PS/2, does not repeat by itself): 500 ms,
  then 30/s; one key at a time (the last pressed), modifiers and lock keys do not repeat; stopped by releasing the
  key or by the source disappearing.
- Each `INPUT` handle is a separate **source**: **a copy of the handle is a new source** with its own map of
  pressed keys (`impl Clone` in `inputsrc.rs`). Releasing a key the source did not press is ignored.
- Closing the last copy (usbd exit) = **releasing all of the source's keys** – no stuck Shift or Ctrl after a
  crash. Drop only touches atomics (`input::usb_release_all`); the actual release is done by the `input-repeat`
  kernel task under the BKL.
- **HID latency:** on a key press, `input_inject` measures the time from the last device interrupt of the process
  (the MSI timestamp) to the character in the kernel input queue (`input::hid_latency` – count, average, min, max;
  values > 1 s are ignored).

### Disk – `ublk` and the request protocol

usbd creates a channel and a buffer (`dma_alloc` – the same buffer the pendrive writes to via DMA, no copy in
usbd) and calls `blk_attach(BLK, channel_end, buffer, info)`.

`info` (64 B): blocks u64, block size u32, slots u32, timeout_ms u32 (0 = 5 s; tests use shorter values,
100..30 000), 4 zero bytes, a 40 B ASCII description (vendor + product from INQUIRY).

The kernel takes **its own references** to the channel and the buffer and registers a `ublk` disk (always
`read_only`), then scans GPT / MBR partitions as for NVMe.

Messages (32 B over the channel – control; data in the buffer):

| Direction | Fields |
|---|---|
| kernel → usbd | `id u32`, `op u32` (1 = READ; nothing else), `lba u64`, `blocks u32`, `slot u32` |
| usbd → kernel | `id u32`, `status i32` (0, `ERROR_IO`, `ERROR_NO_DEVICE` – medium removed), `blocks u32` (reply ≥ 12 B) |

- "Blocks" are **device blocks** (512 or 4096 B); the kernel converts from 512 B sectors, reads whole blocks and
  copies the needed part.
- **Slots:** the buffer is split into 64 KiB slots (default 4 = 256 KiB), one slot per request; `id` increases
  monotonically (64-bit counter in the kernel, 32 bits in the message – it will not wrap during a disk's lifetime).
- **Pipelining:** a read longer than a slot sends up to 4 requests at once (usbd takes the next one from the
  channel right after the previous). On an error reply no new requests are sent and in-flight ones are awaited
  (their slots return); on a timeout in-flight slots go to quarantine.
- **Slot ownership at every moment:** `free` (kernel) → `at usbd` (from sending the request) → `free` after a reply
  with the same `id`, `blocks` = requested and `status` = 0 (only then does the kernel copy the data). Any other
  reply (unknown `id`, wrong block count, oversized message) is **rejected** and counted as a protocol error.
- **Timeout:** 5 s per request (a pendrive may take seconds to wake). After a timeout: `ERROR_IO` for the caller, and the
  slot goes into **quarantine** – it does not return to the pool, because the device may still write into it. It
  returns only after the late reply with that `id` (which the kernel discards) or after usbd dies.
- **3 consecutive timeouts or a closed channel** (usbd died) = the disk **disappears**: further operations return
  `ERROR_NO_DEVICE`/`ERROR_IO`, a filesystem mounted on it returns `ERROR_IO`. The `usb-disks` kernel task (running from boot)
  mounts new disks (`scan_partitions` → FAT32 on partitions, the whole disk or the first MBR partition →
  `/usbN`), checks every 200 ms for closed channels while disks exist, and on loss unmounts without writing
  (`unmount_lost`), removes partitions and the disk, and releases the buffer and channel.
- **usbd death:** the kernel first disables bus mastering (standard service cleanup); the buffer frames live as
  long as ublk holds a reference and are freed only when the disk is removed. Nothing writes to a freed frame.
- **Data from a pendrive is untrusted input** – FAT32 and GPT parsing must survive corrupted disks; tests use a
  deliberately corrupted FAT32 image.
- **usbd does not use the VFS after startup** (it gets only handles from init). Why: it could otherwise wait for a
  lock held on its own behalf and deadlock until the timeout.

**Read-only, enforced four times:** usbd contains no SCSI write command (WRITE(6/10/12/16), FORMAT, MODE SELECT,
SYNCHRONIZE CACHE – a test checks these opcodes are absent from the binary); the ublk protocol has no write
operation; the `ublk` disk reports `read_only` and the block layer rejects writes (`ERROR_READ_ONLY`); FAT32 on a read-only
disk refuses `open` for writing (`ERROR_READ_ONLY`).

### Controller start and shutdown

usbd: `dev_claim`, `dev_map` BAR0, **handoff from BIOS** (USB Legacy Support in the xHCI extended capabilities:
OS Owned bit, wait ≤ 1 s for the BIOS to release, SMIs disabled), reset (HCRST, ≤ 1 s), DCBAA (+ the event ring
segment table in the same page at offset 0x400), scratchpad buffers, command ring, one interrupter with an event
ring, MSI-X (`irq_bind`), Run. 64-bit DMA addresses if the controller has AC64, otherwise `dma_alloc` with a 32-bit
limit. usbd allocates a few larger DMA buffers and subdivides them itself (16 MiB per device, 2 MiB per buffer);
storage buffers are pooled and returned on disconnect. Besides interrupts, the event ring is polled every 10 ms
(counter `polled`). Shutdown: kill at any moment → service cleanup (bus mastering off → vector → frames → claim); a
new instance performs a full controller reset.

### Enumeration – port state machine

```
 Free ─connect─► Debounce(100 ms) ─► Reset(500 ms) ─► Address(Enable Slot + Address Device, 1 s/command)
   ▲                                                                   │
   │                 Descriptors(GET_DESCRIPTOR: 8 B, full device, 9 B configuration, full configuration)
   │                                                                   │
   └── Ignored ◄── Failed(≤ 3 attempts, then until disconnect) ◄── Configuration(Set Configuration, Configure Endpoint)
                                                                       │
                                                         Working (class: hub / HID / mass storage / unknown)
```

- **Every state has a timeout.** On error: Disable Slot, port disabled, retry after 500 ms; after 3 attempts the
  port is ignored until disconnect. Disconnect (or CSC while `Working`) in any state → slot cleanup and back to
  `Free`.
- Port reset only for USB 2 ports; a USB 3 port with PED set is skipped (the link is already trained).
- Address: Enable Slot, input context (slot + EP0; 32/64 B per CSZ), Address Device, device descriptor 8 B →
  Evaluate Context if the EP0 packet size differs, then 18 B, configuration 9 B → `wTotalLength` → full, strings
  (language from string 0, manufacturer, product).
- Control transfer: Setup (IDT) + Data (ISP) + Status (IOC); transfer events queued (16); short packet → remainder
  from the data TRB. STALL / error → Reset Endpoint + Set TR Dequeue (Clear Halt once, then a device error – not a
  failure of the whole usbd).
- **Limits:** 32 devices per controller (and no more than MaxSlots), configuration descriptor ≤ 4 KiB, ≤ 8 stored
  interfaces (alternate setting 0; more are skipped, not an error), ≤ 64 interface descriptors including alternate
  settings (cameras have dozens), ≤ 16 endpoints per device, hub depth ≤ 5, MaxPacketSize consistent with speed.
- Unknown class: the device is visible in `usblist`, with no driver.
- Enumeration time (port reset → class driver ready) is reported per device ("ready in N ms") and in the status
  (`enum_count`, `enum_avg_ms`, `enum_max_ms`).
- Per-device pages (input/output context, EP0 ring) return to a pool on disconnect; descriptor data lives in one
  controller DMA page.

### HID

- Interface 03/01/01 (keyboard) or 03/01/02 (mouse) with an interrupt IN endpoint → Configure Endpoint (DCI =
  number·2+1; interval: HS/SS `bInterval`−1, FS/LS log2(ms·8) in 3..10), Set Configuration, Set Protocol(boot) and
  Set Idle(0) (errors ignored), 8 Normal TRBs.
- Transfer events for endpoints other than EP0 are handled immediately in `poll_events` (also during a control
  transfer); an endpoint error → Reset Endpoint + Set TR Dequeue + new TRBs from the main loop (no recursive
  commands).
- Keyboard report: ErrorRollOver ignored; processing order: modifiers, releases, presses. LEDs: Set Report (OUT,
  1 B) from the main loop. Unplugging a keyboard releases its keys.

### Mass storage

- Bulk-Only Transport with SCSI: `Storage` (bulk IN/OUT, rings, a command page: CBW at 0, CSW at 512, data at
  1024). INQUIRY up to 4 attempts (pauses 200 / 400 / 600 ms; counter `stor_retries`), READ CAPACITY(10),
  READ(10).
- Registration with the kernel happens from the main loop (`attach_pending`), because the kernel reads partitions
  immediately and usbd must already be receiving requests. Disk channels are in the `wait_many` set next to the
  interrupt and clients. Transfer events: HID handled immediately, the rest (EP0, bulk) queued.
- Limits: LUN 0 only; no READ CAPACITY(16) (disks > 2 TiB are refused); no UAS; MaxBurst 0 (SuperSpeed works,
  without bursts).

### Hubs

- `Dev.loc` (route string, depth, ports along the path, TT, `parent`, `hub_port`) and `Dev.hub` (hub ports driven
  by the same state machine as controller ports, a `pending` change map, an interrupt IN endpoint). The slot
  context always comes from `slot_ctx` (route string, root port of the topmost hub, TT; for a hub the Hub bit,
  port count, TT think time) – for Address Device and every Configure Endpoint.
- Hub configuration: Configure Endpoint (status-change endpoint, slot context without hub fields yet) + Set
  Configuration → Set Hub Depth (USB 3; depth = number of hubs above) → hub descriptor (0x29 / 0x2A) → a second
  Configure Endpoint with only the slot context (like Linux `xhci_update_hub_device`) → SET_FEATURE(PORT_POWER) on
  every port, wait `bPwrOn2PwrGood` × 2 ms → 2 TRBs on the change map, all ports marked for checking.
- A change-map event (from `poll_events`, also during another transfer) only marks ports; hub transfers
  (GET_STATUS, CLEAR_FEATURE C_PORT_*, port reset) are done by `service_hubs` from the main loop. Bit 0 (change of
  the hub itself: power / overcurrent) is cleared. Endpoint error → Reset Endpoint + Set TR Dequeue + all ports
  rechecked.
- Speed of a device behind a hub: USB 3 hub → SuperSpeed; USB 2 → bit 9 (low), bit 10 (high), otherwise full. TT:
  low/full speed behind a high-speed hub → (hub slot, port); deeper – TT inherited from the parent.
- Detach: detaching a hub first (recursively) detaches the devices on its ports – their disks disappear in the
  kernel as when a pendrive is pulled. A hub at level 5 gets no ports (the route string has 5 levels).
- A bulk transfer behind a hub is aborted when the parent hub reports a change on that port
  (`XferError::Interrupted` → `ERROR_IO` for the kernel; `needs_recovery` – reset recovery before the next command if the
  device is still there).

### Descriptor parser and hardware-free tests

`user/lib/usb_desc.rs` – a pure parser (no MMIO, no allocation beyond limits) that returns errors instead of
panicking. `/bin/usbparse` runs a table of malicious cases – `bLength` 0, `bLength` larger than the rest,
`wTotalLength` larger than the buffer, `bNumEndpoints` inconsistent with the content, MaxPacketSize 0, descriptor
loops, a HID descriptor with an odd report – plus 10 000 random mutations with a fixed seed. Requirement: zero
panics; every case ends in an error or a valid result within limits.

### usbd restart – what the user sees

- On restart init prints to the screen and COM1: "USB keyboard and disks back in a moment"; usbd at startup prints
  `usb0: xHCI <vendor:device>, N ports` and each connected device.
- The source's keys are released immediately; the keyboard returns after re-enumeration (~0.1–1 s + the restart
  delay 100 ms → 5 s).
- 5 failures within 30 s → `broken`: "USB controller usbN disabled after 5 failures – its USB keyboard and disks are
  unavailable until reboot (PS/2 still works)". A system restart is required; a manual `services restart` – Not
  implemented yet.
- usbd clients (via init, name `usbN`): `status`, `list` (`usblist`), `noop N`, `idle MS` (interrupt pipeline test).

### USB testing

- QEMU: `qemu-xhci` + `usb-kbd`, `usb-mouse`, `usb-hub`, `usb-storage` with a `readonly=on` image; the QEMU monitor
  provides `sendkey` and `device_add` / `device_del` (hot-plug). `test.sh` runs QEMU with the monitor on a unix
  socket and `qemu-hotplug.py`, which forwards "[HOTPLUG] …" lines printed by the kernel self-test to the monitor
  (the disk is a `-blockdev` so it survives `device_del`).
- The same leak checks as for services (frames, handles, MSI vectors, claims) after every USB test and every usbd
  kill; kills during enumeration, typing and pendrive reads.
- Full queues: a flood of HID events (input buffer full – a lost-events counter, usbd is never blocked), all ublk
  slots busy, timeouts (usbd deliberately silent – test mode), late replies and replies with a foreign `id`.
- The test image has a deliberately wrong primary FSInfo (the backup in sector 7 is correct).
- Result line `[RESULT-USB]`: `enum_avg_ms enum_max_ms kread_kbs kcat_kbs hid_n hid_avg_us hid_max_us` (keys sent via
  `sendkey`).

## Network

Same shape as USB: the driver **and the whole protocol stack** run in a user-space service, `/bin/netd`, one per
network card. The kernel gets no network code (at most small helpers if the driver needs them). A bug in a packet
parser kills netd, not the kernel; init restarts it and its clients get `ERROR_CLOSED`.

```
 kernel                       init (HW_ROOT)                       netd (one per NIC)                 programs
 ──────                       ──────────────                       ──────────────────                 ────────
 dev_find(class 02/00) ─────► NIC BDF ─ dev_claim ─ spawn_ex ────► slot 3 DEVICE, 4 connections
 MSI, DMA frames, BAR ◄────── irq_bind / dma_alloc / dev_map ───── rx / tx descriptor rings
                                                                   Ethernet, ARP, IPv4, ICMP,
                                                                   UDP, DHCP, DNS, TCP, loopback
                              "connect net" ──► end ──────────────► control channel ◄──────────── svc_connect("net")
                                                                   socket = one channel per socket ◄──► read / write
```

### Network cards

| Where | Card | Notes |
|---|---|---|
| QEMU (tests) | Intel 82574L (**e1000e**, `8086:10d3`; QEMU's default card on q35) and 82540EM (e1000, `8086:100e`) – same legacy descriptors | **driver done (N2).** QEMU `-netdev user` provides a gateway (10.0.2.2), DHCP and DNS without a real network |
| Real hardware | Realtek **RTL8111/8168** (`10ec:8168`), typical laptop/desktop Ethernet – the test laptop has an RTL8168h (version 541) | **driver done (N8)**, confirmed on the test laptop (DHCP, ping, netget: 10 MiB at 7579 KiB/s – Debian on the same laptop and cable 9.78 MB/s, the link 100 Mb/s) – QEMU has no model of this chip. Registers in memory BAR 2 (BAR 0 is I/O ports); 16-byte descriptors (OWN / end-of-ring / first / last, length with the 4-byte CRC); bring-up: leave the firmware's out-of-band mode, gate reception during the reset, rings, open the gate, MSI before rx/tx on, PHY through GPHY_OCP (advertise, restart auto-negotiation). Written for the 8168g/8168h generation; other versions get a warning. `netconfig` shows the chip version, key registers and any start-up wait that ran out |
| Later | USB Ethernet adapters (ASIX, RTL8153) | through `usbd`, which already exists |
| Not planned | Wi-Fi | needs vendor firmware, 802.11 and WPA2/3 – months of work |

**No DMA from network cards until netd takes them.** A firmware network driver may leave its card receiving
into buffers it freed at ExitBootServices – memory the kernel then uses (one frame there can reset the machine).
DSB turns bus mastering off for every network card right after ExitBootServices, PCI init checks again, and netd
stops reception before `dma_alloc` turns DMA back on.

init finds cards with `dev_find(HW_ROOT, 0x020000, n)` (class Ethernet controller) and starts a `netd` for each
(`net0`, `net1`, like `usbN`). netd checks the chip itself: no driver → a message and exit code 78, which init
records as **"no driver"** (no restarts). netd gets the same slots as other services: 1 console,
3 device, 4 connection channel – no `INPUT`, `BLK` or `SYSCTL`.

**DMA:** netd writes physical addresses into descriptor rings, so – as with usbd – a rogue netd could make the card
write anywhere in RAM (no IOMMU). netd is trusted system code built into the image; untrusted data is the
*packets*, and all their parsing is in netd's process, never in the kernel.

### The card driver (N2)

- **Start:** interrupts masked, `CTRL.RST`, MAC from the receive-address register RA[0] (loaded from the EEPROM at
  reset; EEPROM read via `EERD` as a fallback), RA[0] valid, multicast table cleared.
- **One DMA buffer** (`dma_alloc`, 136 KiB, contiguous): page 0 = 32 receive descriptors, page 1 = 32 transmit
  descriptors (legacy format, 16 B), then 32 × 2 KiB receive buffers and 32 × 2 KiB transmit buffers. Receive
  descriptors all own a buffer (`RDT` = 31); a received frame is handled and its descriptor handed back by moving
  `RDT`. Transmit: copy into the slot's buffer, `EOP | IFCS | RS`, move `TDT`; a slot is reused once the card wrote
  `DD` back.
- **Interrupts:** `irq_bind` (MSI) before `RCTL.EN` / `TCTL.EN` – binding is what turns bus mastering on. Causes:
  receive timer, overrun, descriptor minimum, link change, transmit done. The loop waits on the IRQ, the connection
  channel and the clients with a 1 s timeout; after a timeout the ring is checked anyway ("frames found by polling" –
  0 when interrupts work).
- Received frames are counted by EtherType (ARP / IPv4 / IPv6 / other) and handed to the protocol code (N3, below).
- Client requests (text, like usbd): `status` (card, MAC, link and speed, IPv4, counters, plus a `netd-status k=v`
  line for tests), `arp a.b.c.d` and `ping a.b.c.d [count]`. Tools: `netconfig` (every `netN`), `netarp <ip>`,
  `ping <ip>`.
### ARP, IPv4 and ping (N3)

- **Parsers** (`user/lib/netproto.rs`): pure functions, no allocation, no panics – Ethernet II, ARP (Ethernet/IPv4
  only), IPv4 (header checksum, header and total length checked against the frame, Ethernet padding cut off,
  fragments refused – not reassembled), ICMP (checksum). Every malformed frame ends in an error and is counted
  (`malformed packets dropped` in `netconfig`). The same file builds the frames netd sends, so the test program
  checks both directions. `/bin/netparse` (NET TEST 1/5): RFC 1071 checksum, valid frames, 20 malicious frames with
  the expected error, 20 000 mutations of valid frames.
- **Address:** from DHCP (N4, below); until then netd has none and `ping` / `arp` say so.
- **ARP:** a 16-entry cache, entries valid 60 s, the oldest replaced. A sender is learned from a request for our
  address or when it is already known; replies only when addressed to us (an unasked "is-at" for someone else is
  ignored). Requests for our address are answered.
- **Next hop:** the destination itself on our subnet, else the gateway; its MAC from the cache or by ARP (3 tries
  within 1 s, then "host unreachable" / "gateway unreachable").
- **ICMP echo:** requests to our address are answered straight to the sender's MAC (not to a group address, up to
  1464 data bytes). `ping` sends one request per second with 56 data bytes and an identifier of its own, waits up
  to 1 s per answer and streams one line per answer to the client, then a summary and `ping-end`. Time resolution
  is 1 ms (QEMU's router answers in under 1 ms: `time<1 ms`).
- Since N5 nothing in netd waits: see "Requests without waiting" below.

### UDP and DHCP (N4)

- **UDP** (`parse_udp`, `build_udp_frame`): length checked against the packet, checksum over the pseudo-header
  (0 = not computed, allowed in IPv4); netd sends with a checksum. Packets for ports nobody uses are counted and
  dropped (programs get no UDP sockets yet – UDP is used by netd's own DHCP client and DNS resolver).
- **DHCP parser** (`parse_dhcp`): fixed BOOTP part, magic cookie, options walked with every length checked; a known
  option with a wrong length (mask, router, DNS, lease, T1/T2, server id, message type) is an error, a mask with
  holes is an error, a message without a type (plain BOOTP) is refused. Unknown options are skipped.
- **Client** (`user/lib/dhcp.rs`): a pure state machine – the time is passed in, messages and events come out, so
  netd only sends and applies them. Selecting (DISCOVER after 1, 2, 4, 8, 16, 16... s) → Requesting (REQUEST up to
  4 times, then start over) → Bound → Renewing at T1 (REQUEST to the server, from our address) → Rebinding at T2
  (to everyone, any server may answer) → lease end: address given up, DISCOVER. Resends while renewing or
  rebinding after half the time left, at least 60 s apart (RFC 2131). NAK: start over (and give up the address
  when bound).
- **Untrusted answers:** a reply must carry our transaction id (random per transaction) and our MAC; an offer
  needs a server identifier and a single-machine address (not 0.x, 127.x, multicast or broadcast); while
  requesting or renewing only the chosen server is believed; a gateway off the leased subnet or equal to our
  address is ignored, loopback DNS servers are dropped; prefix 1–30; leases under 30 s are stretched to 30 s;
  T1 / T2 that make no sense are replaced by 1/2 and 7/8 of the lease; "forever" never renews.
- netd asks right after the card is up (DISCOVER from 0.0.0.0 with the broadcast flag; before it has an address
  it accepts DHCP answers sent to the offered address too) and reports
  `net0: address 10.0.2.15/24 from DHCP server 10.0.2.2 in 5 ms, gateway 10.0.2.2, DNS 10.0.2.3`.
  A changed address flushes the ARP cache; a lost one stops ARP and ping until a new lease. Request `renew`
  (`netconfig renew`) renews at once. Checking the address, DECLINE, RELEASE and an address by hand: see below.
- Tests: `/bin/dhcptest` (NET TEST 2/5) drives the state machine through a simulated day: unusable answers,
  resend timing, renewal, rebinding with another server, lease end, NAK, a changed address, odd leases, and that
  a dead server gets fewer than 30 messages from T1 to the lease end. `/bin/netparse` adds UDP and DHCP cases and
  DHCP option mutations; `nettest` checks the lease from QEMU and a renewal.

### DNS and requests without waiting (N5)

- **Requests without waiting:** every client connection carries at most one operation – `ping`, `arp`,
  `resolve`, `renew` – kept in netd's connection table (14 connections) with its own timers. The event loop
  sleeps until a frame, a client message or the earliest timer (DHCP or an operation), then advances whatever is
  due: an echo reply finishes exactly the ping waiting for that sender, id and sequence; a DNS answer the query
  waiting on that port. ARP for the next hop is part of each operation (3 tries, 333 ms apart). Answers to clients
  are sent without blocking – a program that does not read loses lines, never stalls netd; a program that
  closes its connection mid-ping just ends its operation. A second request on a busy connection gets "busy".
  Measured in the test: `status` during two 3 s pings answers at once, and the two pings together take 3 s.
- **Resolver** (`user/lib/dns.rs`, pure): names typed by users are checked (labels 1–63 of letters, digits, `-`,
  `_`; at most 253 characters; a last label of digits is a mistyped address, not a name); the query asks for an
  A record with recursion. Answers are untrusted: the id (random per query) and our port (random 49152–65535)
  must match, the sender must be the server we asked; a wrong id is counted and ignored (the real answer can
  still come). Names in answers are decoded with every length checked, compression pointers only backwards (no
  loops, at most 16 jumps), at most 253 characters, no dots or unprintable bytes inside labels. The question in
  the answer must be ours; only A records for the asked name, or for the end of its CNAME chain (at most 8
  links), are used – at most 4 addresses. A truncated answer (TC – would need TCP) is an error.
- **Cache:** 16 names; an answer lives for its TTL, at most 1 h; "no such name" / "no IPv4 address" 30 s; TTL 0
  and server errors are not kept. Changing the DNS server clears it.
- **Server:** the first DNS server from DHCP (QEMU: 10.0.2.3, which forwards to the host's resolver), 3 queries
  (1, 1, 2 s), then "no answer". `netconfig dns a.b.c.d[:port]` sets one by hand (shown as "set by hand"),
  `netconfig dns auto` goes back to DHCP's. Changing the server is an administrator request – only `netconfig`
  has that right (see "Network access is a capability").
- Tools: `host <name>` (all addresses), `ping <name>` (resolves, then pings the first address).
- Tests: `/bin/dnstest` (NET TEST 3/5): names, the query byte for byte, valid answers (CNAME chain through
  pointers, other types / classes skipped, six addresses → four), 19 malicious answers with the expected error,
  the cache, 20 000 mutations. `tests/dns-stub.py` – a DNS server started by `tests/test.sh` on the host
  (127.0.0.1:53530, reached from the guest as 10.0.2.2:53530) with fixed names under `.desoos`: correct,
  CNAME, several addresses, no such name, no address, server failure, truncated, a pointer loop, a forged answer
  with the wrong id before the real one, TTL 0, silence. nettest checks each, ping by name and the concurrency
  above – no internet needed.

### Address checks, RELEASE, an address by hand (before N8)

- **Check before use** (RFC 5227, shortened): after the DHCP ACK the client is in `Checking`; netd sends two ARP
  probes for the offered address (sender 0.0.0.0, 300 ms apart). Another machine answering for it – or probing for
  it itself – is a conflict: DHCPDECLINE to the server, a new attempt after 10 s (RFC 2131). No answer within
  600 ms: the address is used, the lease times count from then, and a gratuitous ARP announces it.
- **Defence:** later ARP from another MAC with our address as sender is reported on the console
  ("address conflict", counted; again every 100th time) – not answered or fought over.
- **RELEASE:** the lease goes back to the server when an address is set by hand and when netd ends (init stops the
  service); a killed netd cannot – the lease simply expires.
- **By hand:** `netconfig set a.b.c.d/nn [gw a.b.c.d] [dns a.b.c.d]` (admin): checked the same way first (two
  probes; "already used by xx:xx:..." and nothing changes), then the DHCP lease is released, the client stops
  (`State::Off`), the address is announced. The gateway must be another address on the subnet. `netconfig dhcp`
  starts DHCP again from 0.0.0.0. Not kept across a restart of netd (no configuration file yet).
- Tests: dhcptest 68 checks (+ Checking with its timing, DECLINE and the 10 s wait, RELEASE, stop/start); nettest
  96 (+ QEMU's router answering for 10.0.2.2 – refused, bad input, a free address with the lease released and a
  ping from it, refused without admin, back to DHCP).

### TCP (N6)

- **Connection** (`user/lib/tcp.rs`, pure – the time is passed in, segments come out): client side of RFC 9293.
  SYN with our MSS (1460) and window scale (shift 5, RFC 7323 – used only when the peer offers one too); the peer's
  MSS bounded to 64–1460 (536 when it sends none); window = free space of a 1 MiB receive ring (an 8 KiB ring
  would cap a download at window / round trip – 178 KiB/s at 45 ms on the test laptop); an 8 KiB send ring. Sending stays within the peer's window and the congestion window (RFC
  3390 initial window, slow start, congestion avoidance, fast retransmit after 3 duplicate ACKs). Retransmission
  timer from measured RTT (RFC 6298, 200 ms – 60 s, doubled per loss, Karn's rule); after a timeout everything
  from the first unacknowledged byte is sent again; 8 timeouts in a row end the connection; SYN resent after 1, 2,
  4, 8 s, then "timed out". A zero window is probed. Data ahead of a gap (a lost segment) is kept in its place
  in the ring – up to 8 separate pieces – with a duplicate ACK for the gap; when the gap fills, the ACK jumps over
  everything kept (one loss no longer means resending the whole window); overlapping resends are trimmed. Closing: FIN after the queued data; all
  RFC paths (FIN-WAIT-1/2, CLOSING, TIME-WAIT 2 s, CLOSE-WAIT, LAST-ACK); FIN-WAIT-2 gives up after 10 s.
- **Untrusted segments:** checksum and header/option lengths checked by the parser; outside the window → dropped
  with an ACK; RST only with exactly the next sequence number, anywhere else in the window a challenge ACK
  (RFC 5961), likewise a SYN on an open connection; an ACK for data never sent is dropped; challenge ACKs at most
  one per 100 ms. Initial sequence numbers and local ports are random. A segment for no connection gets a RST
  (never for a RST, never to a group address).
- **netd:** 8 connections, their blocks (a 1 MiB receive ring and an 8 KiB send ring each) in a static table that costs nothing in the program
  file (an all-zero block is a valid unused one). The program's messages go into the send ring only when a whole
  message fits (otherwise netd does not read – the program's `chan_send` waits: flow control from TCP back to the
  program); received data goes to the program without blocking – when its channel is full, the data stays in the
  ring and the TCP window closes until the program reads. Peer closed + everything delivered → netd closes its end
  of the channel (the program sees `ERROR_CLOSED`) and finishes the closing. The program closes its end → FIN, or a RST if
  received data was never read; data arriving for a program that is gone → RST.
- **`netget [-o file] [-v] http://host[:port]/path`:** HTTP/1.0 GET, the body to the console or a file, a summary to
  stderr; exit 0 complete, 2 no connection, 3 cut short (fewer bytes than Content-Length), 4 HTTP error.
  `https://` is refused – TLS needs cryptography (later).
- Tests: `/bin/tcptest` (NET TEST 4/6) – 77 checks against a simulated peer: handshake, refused, SYN resend times,
  windows, window scaling, RTO and fast retransmit, zero-window probe, receiving in/out of order and overlapping, a full buffer,
  every closing path, wraparound at 2^32, hostile segments, 20 000 random segments. `tests/http-stub.py` (started
  by `tests/test.sh` on 127.0.0.1:58080, the guest connects to 10.0.2.2:58080 – QEMU's NAT): `/hello`, `/big`
  (1 MiB with a pattern), `/slow`, `/short` (cut), `/reset` (RST), `/nolength`, 404 (nettest, see Testing).
  QEMU's user network terminates TCP itself, so hostile TCP behaviour can only come from tcptest – the stub tests
  the whole path (DNS, ARP, TCP, netd, channel, program).
- Not yet: SACK, a bigger send ring (uploads), urgent data, keepalive.

### Servers and loopback (N7)

- **Server side of TCP** (`Tcb::accept`): a SYN to a listening port creates a block in SynReceived (the peer's MSS
  and window, our SYN+ACK with MSS); a repeated SYN gets the SYN+ACK again; an ACK for something we never sent
  gets a RST; the SYN+ACK is resent after 1, 2, 4 s, then the half-open connection is dropped; data riding on the
  handshake ACK is kept.
- **`listen port`** (needs the listen right; 0 = any free port): the connection becomes the listener. Up to 4
  connections per listener may be in the handshake. When one is open, netd creates a new channel, sends one end
  to the listener with `accepted a.b.c.d:port to port N` and keeps the other as that connection's socket – the
  server program reads and writes it like a client socket, and passes it on with `TRANSFER` if it wants.
  Closing the listener resets the connections still in the handshake. A request that arrives together with the
  handshake (common – QEMU's port forwarding does it) is kept, not mistaken for data of a program that is gone.
- **Loopback:** frames to 127.0.0.1 or to our own address never reach the card – `send` puts them into a 32-frame
  queue that the event loop feeds back into the receive path (127.x is accepted only from that queue, never from
  the cable). Connections to 127.0.0.1 use 127.0.0.1 as their own address. Ping to ourselves is answered the
  same way (the first time our echo answering is tested at all). No ARP for our own addresses.
- **`netweb [-n count] port < page`**: a minimal server – the page from stdin (≤ 64 KiB), GET `/` or `/index.html`,
  else 404, one request at a time with 5 s to send it. `nofiles --listen netweb 8080 < /index.html` runs it with no
  file access at all.
- **From the host:** `run-qemu.sh` forwards the host's 127.0.0.1:18080 to port 8080 of DeSoOS (`HOSTFWD=port`,
  `HOSTFWD=0` – off); `tests/test.sh` forwards 127.0.0.1:58082 to port 8081.
- Tests: tcptest's server-side checks; nettest: narrowed rights (no listen, no DNS change, no
  other service, no widening), listening + loopback to 127.0.0.1 and to our address (200 KiB and 100 KiB both
  ways, the close seen by the server, a refused port), ping to ourselves, and a sandboxed `netweb` reached over
  loopback and **from the host**: `tests/http-stub.py /connect?port=58082` connects from the host through QEMU's
  forwarding into DeSoOS and returns what netweb answered.

- The test laptop also has an **AMD IOMMU** (00:00.2) – a future way to confine the DMA of usbd and netd to their own
  buffers (Future).

### Network access is a capability

There is no "every program may use the network". A program can reach the network only through a channel to netd,
and it gets one only through init's service channel (`SVC`, slot 3). As built in N7:

- **The shell's programs** get the **program channel** in their slot 3: init gives the shell two service channels –
  its own (slot 3, everything) and the program channel (slot 5: every service, network connections and servers, but
  no network administration; the name is about programs, not user accounts, which DeSoOS does not have).
  `svc_connect("net0")` through the program channel reaches netd as `net0 client
  listen`. Only **`netconfig`** gets the shell's own channel and reaches netd as `net0 admin listen`: the
  administrator requests (address, DNS server, DHCP on / renew, receive-ring restart). A shell started from the
  shell has only the program channel, so `netconfig` started from it is not an administrator either.
  The choice is made by the shell from the program's name; with a file system that has owners and write
  rights, a program could replace `/bin/netconfig` – today only the initrd provides it.
- **A narrowed service channel** (`svc_narrow("net")` / `svc_narrow("net listen")`): init creates a new service
  channel that can only open network connections – `connect` to any other service is refused, there is no admin
  right, and it can only be narrowed further, never widened. init hands such connections to netd as
  `net0 client` (+ `listen`). At most 12 narrowed channels; init forgets one when nobody holds it any more.
- **`nofiles --net <program>`** – the file sandbox plus a narrowed channel (connections only);
  **`nofiles --listen <program>`** – plus servers. A compromised server can neither read the disk, nor reach
  another service, nor redirect DNS.
- A program without `SVC` (plain `nofiles`, the `sysfuzz` children) has no way to send a single packet.
- netd checks the rights per connection: `listen` needs listen, `dns`, `set`, `dhcp`, `renew` and `rxrestart`
  need admin ("not allowed for this program"); a connection with no rights in init's text gets neither.
  Accepted sockets have no rights of their own – they only carry data.
- Tests (nettest): the program channel reaches netd and echo, may listen, is refused a DNS change; through `sh -c`
  a program is refused and `netconfig` is allowed.

### Sockets as handles

A socket is **one channel between the program and netd**. As built in N6 it is simply the program's connection to
netd: the request `tcp host port` turns it into the socket once netd answers `connected ...` (the first draft
below passed a separate channel end in an `open` request; one connection per socket proved enough). After that:

- data travels as channel messages (up to 4 KiB each; one Ethernet frame carries at most 1460 B of TCP data, so
  one message fits ~2.8 frames). Measured channel throughput (765 MB/s, test laptop) is far above Gigabit
  Ethernet; a shared-memory ring per socket only if measurements show a need.
- the socket's rights are the channel end's rights: `SEND` (write), `RECV` (read), `DUP`, `TRANSFER` (hand the
  socket to another process, e.g. a server passing an accepted connection to a worker). Read-only or
  write-only sockets are a `handle_dup` away; rights never grow.
- `wait_many` already waits on many channels, so a program can wait for several sockets, a pipe and a timeout at
  once – no new kernel mechanism.
- closing the end = closing the socket (netd sees the closed channel and sends FIN / frees the port). netd dies
  → every socket gets `ERROR_CLOSED`.

### Messages (text)

The control protocol is text, one request per message, one reply (or a stream of lines ending in a marker).
A program's connection comes from init (`svc_connect("net0")`) with its rights already decided (see "Network
access is a capability").

| Request | Reply | Right |
|---|---|---|
| `status` | a description (card, MAC, link, address, lease, DNS, counters, last TCP connection) + a `netd-status k=v …` line for tests | – |
| `arp a.b.c.d` | `arp a.b.c.d is-at xx:…:xx in N ms` or no reply after 1 s | – |
| `ping host [count]` | one line per answer as they come, a summary, `ping-end` | – |
| `resolve name` | the IPv4 addresses (DNS, cached) | – |
| `tcp host port` | `connected a.b.c.d:port from …` – from then on the connection **is** the socket | – |
| `listen port` | the connection becomes a listener; each accepted connection arrives as `accepted a.b.c.d:port to port N` with a new channel (its socket) | listen |
| `dns a.b.c.d[:port]` / `dns auto` | the DNS server by hand / back to DHCP's | admin |
| `set a.b.c.d/nn [gw …] [dns …]`, `dhcp`, `renew` | an address by hand (checked with ARP first), back to DHCP, renew the lease now | admin |
| `rxrestart` | set the receive ring up again (diagnosis, some cards) | admin |

A request without the right: `netd: "…" is an administrator request - not allowed for this program` (or "not
allowed" for listen). On a socket every message is data – TCP payload in, TCP payload out; up to 4 KiB per
message. The peer closing → netd closes its end, the program sees `ERROR_CLOSED`.
Flow control: netd stops reading a socket's channel when the TCP send ring is full; the program's `chan_send`
then blocks (queue of 64 messages) or gets `ERROR_WOULD_BLOCK` with `CHAN_NONBLOCK`.

### Inside netd

- **One thread, one event loop:** `wait_many` on the IRQ, the connection channel, the control channels and the
  socket channels (16 entries per call – netd rotates through larger sets), with the nearest timer as the
  timeout (ARP retries, DHCP lease, TCP retransmission, TIME-WAIT).
- **Layers, each a separate module with no hardware access** (testable on the host like `usbparse`): driver
  (rings, MSI) → Ethernet → ARP cache → IPv4 (no fragment reassembly at first; fragments dropped and counted) →
  ICMP (echo), UDP, TCP → DHCP client, DNS resolver.
- **TCP:** connection state machine, sequence numbers, retransmission timer with backoff, receive / send windows,
  MSS, window scaling, data kept ahead of a gap, FIN / RST, TIME_WAIT; congestion control: slow start, congestion
  avoidance, fast retransmit (details in "TCP").
- **Loopback** (127.0.0.1) inside netd – lets the self-tests run a TCP client and server in one VM without any
  outside network.
- **Limits:** per-client socket count, receive buffer per socket, total buffers (netd's own memory is already
  capped by the kernel limits); a flood of packets costs netd CPU, never kernel memory.

### Tools

- `netconfig` – every card: link, address, lease, DNS, counters, the last TCP connection; `netconfig renew / dns /
  set / dhcp / rxrestart` – the only program with the admin right.
- `ping <address or name> [count]`, `host <name>` (DNS), `netarp <a.b.c.d>` (one ARP request).
- `netget [-o file] [-v] http://host[:port]/path` – HTTP/1.0 download with the speed; `https://` is refused (no TLS).
- `netweb [-n count] <port> < page` – a minimal web server; `nofiles --listen netweb 8080 < /index.html` runs it
  with no file access.

### Testing

NET TEST, 6 parts (QEMU q35 with `-device e1000e -netdev user,...`: gateway 10.0.2.2, DNS 10.0.2.3, no internet
needed):

| Part | Program | What |
|---|---|---|
| 1/6 | `netparse` (59 checks) | 37 hostile frames and messages refused with the right error, 20 000 mutations – no panic, sizes consistent |
| 2/6 | `dhcptest` (68) | the DHCP client with a simulated clock: every state, resends, ARP check, DECLINE, RELEASE, T1/T2, NAK |
| 3/6 | `dnstest` (41) | 19 hostile answers, the cache, 20 000 mutations |
| 4/6 | `tcptest` (77) | TCP against a simulated peer: windows, scaling, retransmission, out-of-order, closing, hostile segments, the server side, 20 000 random segments |
| 5/6 | `nettest` (102) | the real path: init starts netd, DHCP, DNS against `tests/dns-stub.py`, TCP and netget against `tests/http-stub.py`, rights (program channel, narrowed channels), listen + loopback, a sandboxed `netweb` reached from the host, concurrent clients, ARP and ping, netd killed and restarted |
| 6/6 | – | no frames, channels or memory left behind |

- Real hardware: the test laptop over a cable (DHCP from the home router, ping, netget from the internet).
- netd never writes to disk; it only sends packets the user asked for (plus DHCP, ARP and TCP control packets).
  Nothing listens unless a program asked for `listen` (and has the right).

## DeSoFS (`kernel/fs/desofs/`)

DeSoOS's own file system, format 1 – the full specification is `docs/desofs/FORMAT.md` (closed; changes only as
numbered errata until stage 4). In short: copy-on-write, two superblocks written alternately (the next commit goes to
the one with the older generation), every pointer carries the SHA-256 of the block it points to (a Merkle tree), fixed
fan-out trees of 84 pointers, 256-byte nodes with permanent numbers, directories as blocks of entries like ext2. There
is no journal and no allocation structure on disk: free space is what no tree reaches.

Stage 1 (v0.60.0) is read-only: `desofs::probe(disk)` (`mod.rs`, structures in `layout.rs`)
- reads both superblocks and applies the selection rules (uuid, size, generation, tie, features);
- walks everything reachable from the newer superblock first (its live root first – complete duplicate check), then
  from the older one, with a one-byte-per-block map (free / reserved / DATA / METADATA kind+level) and a one-bit map
  per root; a metadata block met again from another root is re-read and checked with the new pointer (checksum,
  birth, kind, level) and its subtree skipped; data blocks are only marked;
- checks every header (kind, level, count, generation = birth, own address, uuid, zero padding), every pointer
  (range, reserved blocks, the one empty form, 1 ≤ birth ≤ generation), every node (format-1 field values, the
  smallest depth for the size, pointers past the size empty, no directory holes), every root entry and the node
  numbers against `next_node`;
- decides: read-write (both trees known), read-only (one tree damaged, or an unknown ro_compat feature) or refused –
  never writes and never panics on a hostile image; the maps are allocated fallibly in 64 KiB pieces.
Directory blocks are checked by `layout::check_dir_block`. SHA-256 comes from DeSoCrypto – its first use in the
kernel.

Stage 2a (v0.61.0) writes – `vol.rs` (`Volume`, a `FileSystem`, mounted through `Locked`) and `format.rs`:
- **one operation = one transaction:** changed blocks are copied to newly allocated places in memory (`Tx::dirty`,
  copy on first change), pointers to them are placeholders; at commit a seal pass goes from the new root block down
  through the new blocks only and fills in checksums bottom-up, then: write new blocks → flush → superblock to the slot
  with the older generation (tie → B) → flush. Only then does the call return;
- **allocator:** next-fit over the stage-1 map; blocks the new tree drops are still in the older superblock's tree, so
  they become free after the next commit (`pending_free`); after a mount, the blocks only the older superblock reaches
  (recorded by the walk) are freed by the first commit. R1: with a snapshot, a block born at or before it is kept;
- **space:** each operation computes an upper bound of new blocks before touching anything and fails with "no space"
  instead of half-way; a reserve of min(max(64, 1/64), 1/4) of the volume is left to remove, truncate and rename (the
  worst case – a cross-directory rename replacing a file with depth-5 trees – is 30 blocks);
- **trees:** fixed fan-out path copy (`tree_set`), pointer blocks without pointers removed, file depth grows and
  shrinks to the smallest that holds the size, node table grows a level when a number does not fit, an emptied node
  block removed (errata E4); directories reuse deleted entries and never shrink (stable readdir cursor);
- **rename:** one commit; replaces a file or an empty directory, refuses a directory into itself, file ↔ directory,
  a non-empty target; new `rename` in the VFS (`FileSystem`, `ConcurrentFs`, `Locked`, `fs::rename`: same file system
  only, mount points busy) – ramfs and FAT32 answer "unsupported", the kernel-shell `mv` then copies;
- **errors:** a write or flush error, or a directory entry that does not match its node, turns the volume read-only;
  a bad data block fails that one read; allocations are fallible.
`desofs format` writes chapter 14 (blocks 0–15 zeroed first; refuses a read-only disk and a whole disk with a
partition table). Kernel shell: `desofs info | format | mount | unmount`.

Testing: `tests/mkdesofs.py` is an independent implementation of the format (written from the specification) and
builds the reference image – two superblocks (generations 4 and 5), a snapshot, a file with a hole, a subdirectory, a
DSPT shared between the trees; `build.sh --selftest` embeds it. DESOFS TEST checks that the kernel accepts exactly
that image, then runs 93 cases, nearly all copies broken in a way the specification forbids – most "resealed" (all checksums above the change
recomputed), so the rule itself must catch it. Every image lives in a RAM disk; nothing touches a real disk. Stage 2a
adds tests 8–14: the kernel's `desofs format` equal byte for byte to `mkdesofs.py --format`; files (depth 0 → 2 → 0,
holes, partial blocks), 300-entry directories, every `rename` rule, a full disk with the reserve, the reference image's
snapshot never overwritten, the VFS with `/bin/sha256sum` reading a DeSoFS file, and a disk that fails at each write
position (operation fails, volume read-only, remount shows old or new). After every operation: the walk accepts the
volume with exact counts, contents equal a model, no operation exceeded its bound, and **no block reachable from
either superblock is free in the allocator** (this invariant catches freeing one commit too early).

Power loss (stage 2b, v0.62.0, `test_crash.rs`, tests 15–18). A test disk (`CrashDev`) keeps an image and records
every write (address, 512-byte sectors) and flush of one operation; crash images are rebuilt from that log on top of
the image the disk held before the operation – the way a disk cache behaves: what was flushed stays, anything since
the last flush may or may not land, in any order, sector by sector.
- every write point: the first k writes landed, nothing after – every write boundary and every sector inside a
  superblock write (a torn superblock), over 21 operations on a 96-block volume (blocks freed earlier are reused) and
  on a 64-block volume at the edge of full (refused operations must write nothing);
- reordered: random subsets of the sectors, or of whole writes, since the last flush (fixed seed);
- write / flush errors at each position: the operation fails, the volume turns read-only; any part of the unflushed
  writes may have landed;
- the reference image's snapshot: no write of any operation touches one of its blocks.
Each image must mount read-write with exact counts, at the generation before (g) or after (g + 1) the operation, with
the matching contents (the model); where the state can change (at a flush, inside / after a superblock) it must also
take a new file, pass the allocator check and survive a remount. Checked by mutation: dropping the flush between the
new blocks and the superblock is caught (a superblock lands before its tree).

### Check and repair (`check.rs`, v0.63.0)

`desofs check <disk>` reads, never writes, and refuses a mounted volume ("unmount first" – a count of live `Volume`s
per disk). Per superblock it reports three things apart: its own checksum, its metadata tree (the mount walk with
fresh maps, `walk_one`), and its data. For every sound tree (once if both superblocks point to the same root):
- every data block of every file and directory, in the live root and in each snapshot, against its pointer's
  SHA-256 – a block reached through a metadata block met before is not read again;
- directories and relations per root in two passes: node types and parents (9 bytes per node number), then every
  directory entry – names an existing node of the same type whose parent is that directory; every node but 1 listed
  exactly once (0 = orphan), node 1 nowhere; parents followed up to node 1 (a cycle is not reachable from `/`);
- E3: a data block met from two different pointer blocks – a second walk compares the 48-byte pointers (up to 65 536
  such blocks, more → a warning);
- `used_blocks` differing from the count is a WARNING, never an error.
- **Completeness:** a limit (16 M node numbers for the relations, 65 536 shared blocks for E3) skips a check – a
  WARNING, the superblock is marked incomplete ("data OK as far as checked (INCOMPLETE)", INCOMPLETE in the result
  line), and `repair` refuses to copy an incomplete superblock (since v0.63.1).
Errors name the path (found by following parents and searching the parent directory); at most 64 error lines.

`desofs repair <disk> [yes]` runs the whole check first and writes nothing before it ends. It needs exactly one
superblock whose checksum, tree and data are all sound; that superblock is only read. Its copy – same uuid, same root,
`used_blocks` as counted, generation = highest valid + 1 – goes to the other slot, then a flush; then `probe` must
say read-write. Without `yes` it only states the plan (including "the changes of generation N are lost" when the
newer state is the damaged one). Refused: nothing to repair, no sound tree, a sound tree with damaged data, a check
that did not run in full (a limit reached), the generation at its maximum, a read-only disk, a mounted volume. A write or flush error leaves the good superblock as
it was; an interrupted repair leaves a mountable volume and can be repeated.

### Directories in parts

`read_dir_at(path, cursor, max) -> (entries, next)` in `FileSystem`, `ConcurrentFs`, `Locked` and the VFS. DeSoFS:
the cursor is a byte position (logical directory block × 4096 + entry offset, `docs/desofs/FORMAT.md` chapter 13) – it must be
the start of an entry (found by stepping over `rec_len` from the block start; deleted entries keep their length, a
length under 16 is a damaged block), otherwise `FsError::BadCursor`. An entry present during the whole listing and
not moved appears exactly once. Default (ramfs, FAT32): an index into the full list. The kernel-shell `ls` reads in
parts of 1024 (one part: sorted as before; more: shown part by part in the file system's order).

### `/disk` as DeSoFS, programs, the restart test (v0.64.0)

**Mounting at start** – `fs::mount_disk(disk, path)`, used by `fs::init` for disk 0 → `/disk`: the DeSoFS marker in
superblock A or B (whatever its checksum) means only DeSoFS rules – read-write, read-only with the reason (the
kernel log says "desofs check 0 / desofs repair 0"), or not mounted with the reason – never a fallback to FAT32;
without the marker FAT32 as before; nothing is ever formatted here. `desofs format 0 yes` mounts the new volume at
`/disk` at once; `desofs mount <disk>` puts disk 0 at `/disk`, others at `/desofs`; `desofs unmount` unmounts
every DeSoFS mount (check / repair need that). A FAT32 `fat32::mkfs` (tests only) zeroes the reserved sectors, so the marker
of an earlier DeSoFS volume goes with it.

**No format under a mounted file system** (v0.64.1): every file system tells its disk (`FileSystem::disk`);
`fs::mounts_of_disk(d)` lists the mount points on disk `d` or its partitions, `fs::unmount_disk(d)` unmounts them
and stops at the first that cannot be unmounted (`unmount` syncs first – a failed sync keeps it mounted). The
kernel-shell `desofs format` unmounts only what is on the target disk and stop with "cannot unmount …
nothing changed" when that fails; `desofs::format::format` and `fat32::mkfs` themselves refuse a disk that is still
mounted (or has a live `Volume`) – a second guard. Test 24: a mounted DeSoFS and a live `Volume` refused (disk
SHA-256 before = after, format works after the unmount); FAT32 whose flush fails – the shell command stops, the file
system stays mounted with its file, the whole disk's SHA-256 is unchanged.

**A mount in use is not unmounted** (v0.65.0): file handles remember a path, not a file system, so unmounting under
them would let them reach whatever is mounted there next (after `desofs format`: a new, empty volume). Every mount
has a pin counter (`users`, atomic); `fs::MountPin::take(path)` – under `FS_LOCK` for reading, the mount the VFS
resolves the path to (longest mount point by whole components, as for every call; "/" is not counted) – is held by
an open file (`OpenFile.pin`, taken before the open does anything), a directory handle (`DirObj.pin`, also taken
first) and a process's current directory (`Process::set_cwd` / `set_cwd_pinned`, the only ways to change it: path
and pin replaced together, the old pin dropped after; `chdir` takes the pin before it checks the directory – v0.65.1,
before an unmount could slip between the check and the pin; a child's `spawn` copies the parent's pin). Test builds
have a stop point in `chdir` between the pin and the check (`chdir_pause`): INIT TEST 9 unmounts there and must be
refused. Drop
is a plain atomic decrement, without a lock: `close`, a handle leaving with a message, process exit (`exit_current`
drops the descriptors and the directory pin at once – a zombie holds nothing) never wait for the VFS. `unmount`
under `FS_LOCK` for writing: pins > 0 → `FsError::InUse(n)` "in use (n open files / directories)" before anything
is written; new pins wait for the lock, so the count cannot grow meanwhile. `unmount_disk` is all or nothing under
one write lock: every mount on the disk unused, then every one synced, only then all removed. Lock order: only
`FS_LOCK` (no process table, no other process's descriptors – `open`, `close`, `chdir` run without the BKL and
change only their own table, so scanning other tables would race). The message has no pid for the same reason; `ps`
and `dcp` show who. The kernel shell moves its directory to "/" only after a successful unmount. `unmount_lost`
(a USB stick pulled out) ignores pins: the disk is gone anyway. INIT TEST 9 (`/bin/dsfstest`).

### Block cache (`cache.rs`, v0.69.0) and the time measurement

- **Measured first** (`vol::Prof`, `[RESULT-FS-PROF]` per benchmark phase of the restart test): TSC timestamps
  (`rdtscp`) around the disk reads, their SHA-256, the header checks, the SHA-256 of sealed blocks, the commit's
  writes, flush 1, the superblock write, flush 2, whole commits and whole operations – the order of writes, flushes
  and checks is untouched; ~50–90 cycles per timestamp, 0.04–0.1 % of a phase. KVM before the cache: reading 1000
  small files 2.44 s = disk reads 68 %, SHA-256 30 % (35 block reads per file: every operation walks the path from
  the root, a directory is searched block by block); creating them 9.45 s = reads 37 %, SHA 13 %, commits 50 % (the
  two flushes 36 %).
- **The cache**: one per mounted volume or snapshot view (`Volume.cache`), between `Tx::read` and the disk. Key =
  (address, the SHA-256 in the parent's pointer): copy-on-write never overwrites a live block and an address used
  again carries another checksum, so nothing is ever invalidated – an entry with another checksum is stale and
  dropped. **A hit is checked like a disk read**: SHA-256 computed again, the header (kind, level, generation,
  address, volume uuid) checked; a copy that fails is dropped (`bad`) and the block read from the disk (a header
  that fails on a good checksum: the disk decides, as without the cache). What the cache cannot see: the disk copy
  going bad after the block was cached – until the copy leaves the cache; `desofs check` / `repair` (and the mount
  walk) read the disk itself, never the cache.
- **What enters**: a block read from the disk after its checks passed; the blocks of a commit only after its second
  flush (each sealed block keeps its checksum for this) – nothing from a commit that failed, nothing uncommitted
  (those blocks are read from the transaction's own dirty map, as before).
- **Memory**: contents in 4 KiB physical frames, the index (slots + an open-addressing hash table on the address)
  on the heap. One global budget for all caches – min(1/16 of memory, 64 MiB) – counts the frames and the heap
  blocks the index really takes (the heap's size classes included); it is reserved by compare-exchange before
  anything is allocated, so volumes working at once cannot pass it. No new frame while free memory is below 1/8 of
  it or below the kernel's reserve – then the cache reuses its own frames. Unmount (dropping the volume) frees every
  frame and returns every byte (`sysinfo counters`: `fs_cache_bytes`).
- **Replacement: Clock.** A hit sets the slot's reference bit; the hand skips and clears referenced slots.
  Metadata (root, pointer, node and directory blocks) enters referenced, data blocks not – a large file read once
  leaves first instead of pushing out the node tables and directories.

### Snapshots (v0.66.0, stage 5 – format 1 unchanged)

- **Create** (`Volume::snapshot_create`): one commit whose root block gets a new entry (the first free of 1–31) –
  a copy of the live entry, kind 2, the name, `created_gen` = the generation of the frozen state. Nothing is copied:
  copy-on-write never overwrites, so the old tree simply stays. From then on R1 keeps every block born no later than
  the newest snapshot's `created_gen`; with one or more snapshots this is exact (a block of the live tree born before
  a snapshot was in that snapshot), so `used_blocks` stays exact too.
- **Names**: 1–24 bytes, no `/`, space, control character (NUL included) or DEL, not `.` / `..`, unique – stricter
  than the format, because a name becomes `/snap/<name>` and a shell word. A snapshot with another name (another
  tool) is read and listed but cannot be mounted.
- **Delete**: one commit without the entry, its `used_blocks` lowered by what only that snapshot held, then **R3** –
  the allocator's map from a fresh mount walk (`scan_volume`: both superblocks, every root of each); blocks reachable
  only from the previous superblock wait for the next commit (N + 2) exactly as after a mount. A walk failure makes
  the volume read-only. Refused while the snapshot is mounted as a view (`VIEWS` counter per disk and entry).
- **Restore**: one commit whose live entry is a copy of the snapshot's; every snapshot (newer ones too) stays;
  `used_blocks` lowered by what only the old live state held; then R3 as for delete – the old live state stays
  reserved while the previous superblock reaches it. Only on an unmounted disk, with "yes".
- **View** (`Volume::mount_snapshot`, `desofs snapshot mount` → `/snap/<name>`): a read-only `Volume` whose live
  root is the snapshot's entry; no allocator use, writes refused; counts as a mounted volume (check, repair, format
  refuse) and holds the snapshot against delete. `desofs unmount` takes views down too.
- **List** (`snapshot_usage`): name, generation and the blocks only that snapshot holds – the other roots of the
  current superblock walked first, then this one; what it marks anew is its own (one walk per snapshot). That is
  what delete gives back (after two commits).
- **Kernel interface**: `desofs snapshot create | list | mount | delete | restore` in both shells; sysctl actions
  11–15, the name as pointer + length (copied, at most 24 bytes, checked by the kernel before the action; every
  other action must pass none). Operations on a mounted volume run on it under `FS_LOCK` (`fs::with_mounted_desofs`,
  `FileSystem::with_desofs`); on an unmounted disk on a volume mounted just for the call.
- Tests: DESOFS TEST 25–28 (create, views, names, the limit; R1 through filling the whole volume, R3 giving back
  exactly what only the snapshot held; restore; power loss at every write and every superblock sector of create,
  delete and restore, each twice in a row so both slots are hit), INIT TEST 9 (`dsfstest`: through `/bin/sh`, raw
  sysctl names), RESTART TEST 5 (a snapshot made before the restart, its view after).

**`readdir_part(dir, path, len, buf, buflen, cursor)`** (syscall 57): a directory in parts through a directory handle
(`READ` – one row in the rights table, like `readdirat`; in the file sandbox the handle given to the program, paths
never above it). Entries in `readdir`'s text form as far as they fit in `buf`; `*cursor` in / out – the byte
position of the next entry in DeSoFS (an index in ramfs / FAT32), `u64::MAX` = end. Every entry carries its own
position (`read_dir_at` returns them), so a part that does not fit resumes exactly at the first entry left out; a
first entry that does not fit = `ERROR_BUFFER_TOO_SMALL`, a wrong position = `ERROR_INVALID_ARGUMENT`. The library
has `dir_for_listing` (a new READ handle, or the sandbox's one) and `readdir_part`; `/bin/ls` reads in parts of
4 KiB (one part: sorted as before; more: part by part in the file system's order).

**Restart test** – `tests/test.sh` starts QEMU twice on the same test disk (`build-test-disk.img`, new for every
run). The last step of the first start (RESTART TEST part 1, `restart.rs`; only in the automatic test mode and only
on an empty disk 0) formats disk 0, mounts it as at start and writes a fixed set: files of 0 B to 1 MiB with a hole,
three directory levels, a 300-entry directory with ten removed, a rename replacing a file, a removed file. The
second start (fw_cfg `opt/desoos/phase=restart`) skips every other self-test and checks: `/disk` mounted as DeSoFS
read-write by the kernel itself; every file and directory byte for byte, nothing removed came back, the big
directory read in parts by byte position; `/bin/sha256sum` and `/bin/ls` (`readdir_part`) on `/disk`; a new file
written and read; then `[RESULT-FS]` – 8 MiB written in 64 KiB pieces and read, 1000 files of 100 B created and read,
`desofs check` of the whole volume (0 errors, 0 warnings, complete) – and `test.sh` adds the QEMU mode and
configuration to that line.

Test 23 (`test_check.rs`): `mount_disk` on RAM disks – sound DeSoFS read-write, a damaged tree read-only, FAT32,
the marker over a valid FAT32 with both superblocks broken → not mounted (never the FAT32), an empty disk → not
mounted and untouched.

Tests 19–22 (`test_check.rs`): check on a fresh volume, after work and on the reference image (0 errors; the disk's
SHA-256 unchanged); ten damage cases (file / directory data unresealed – the mount stays read-write; a node in two
entries, an orphan, wrong parent, entry type, a cycle, a removed entry, E3 – resealed), used_blocks → one warning;
repair of the older / newer tree, every refusal (disk unchanged), an interrupted repair after each of the 8
superblock sectors and 16 random parts (mountable, good superblock untouched, repair again works); 150 entries read
in parts of 7 with 50 removes and 50 creates in between, wrong cursors refused, ramfs through the VFS. Checked by
mutation: no data checksum, no orphan rule, no E3 pass, repair into the good slot, repair without the full check, a
cursor that skips an entry, no cursor validation – each makes the suite fail.

## Cryptography – DeSoCrypto (`common/desocrypto/`)

DeSoOS's own cryptographic library, written for DeSoOS only (no Cargo crate, no outside code). It is a library,
not a service and not a kernel module: whoever needs a hash includes the code (`#[path]`) and calls it directly – no
syscall per operation, and a mistake in it can only hurt the program that uses it.

| Module | What | Standard |
|---|---|---|
| `sha256` | `Sha256::new / update / finish`, `sha256(data)` | FIPS 180-4 |
| `sha512` | `Sha512`, `Sha384` (one core, two starting values), `sha512(data)`, `sha384(data)` | FIPS 180-4 |
| `hash` | `Digest` (trait for generic code), `HashAlg` (chosen at run time: digest, length), `Hasher` (streaming) – SHA-1 / SHA-224 deliberately absent | – |
| `hmac` | `Hmac<D>` over any `Digest`; `HmacSha256::new / update / finish / verify`, `hmac_sha256(key, data)` as before | RFC 2104, vectors RFC 4231 |
| `hkdf` | `extract`, `expand`, `hkdf` (SHA-256); `extract_with / expand_with / hkdf_with::<D>` | RFC 5869 |
| `chacha20` | `block`, `xor_stream` (refuses a wrapping counter) | RFC 8439 |
| `rng` | `KeyErasureRng::new / fill / reseed` – ChaCha20 with fast key erasure | – |
| `poly1305` | `Poly1305::new / update / finish / verify`, `poly1305(key, msg)` – one-time authenticator, limbs 44/44/42 bits | RFC 8439 §2.5 |
| `aead` | `seal(key, nonce, aad, buf) -> tag`, `open(key, nonce, aad, buf, tag)` – ChaCha20-Poly1305 in place | RFC 8439 §2.8 |
| `x25519` | `x25519(secret, their_public)`, `public_key(secret)` – Montgomery ladder, five 51-bit limbs; an all-zero result refused | RFC 7748 (+ RFC 8446 §7.4.2) |
| `aes` | `Aes128::new(key, features)`, `encrypt_blocks` – AES-NI or bitsliced (4 blocks in 8 planes, Boyar–Peralta S-box circuit); `Features::detect / limit` | FIPS-197 |
| `ghash` | `Ghash::new(h, features)`, `update / pad / finish` – PCLMULQDQ or bit by bit with masks | SP 800-38D §6.4 |
| `aes_gcm` | `AesGcm::new / with_features`, `seal / open` in place; 12-byte nonce, 16-byte tag | SP 800-38D |
| `bignum` | `Modulus<N>` (odd, Montgomery CIOS): `pow`, `mul / add / sub / to_mont / from_mont / pow_mont`; up to 4096 bits – **public data only, not constant time** | – |
| `rsa` | `PublicKey::new(n, e)`, `verify_pkcs1(hash, msg, sig)`, `verify_pss(&PssParams, msg, sig)`; `PssParams::tls(h)` | RFC 8017 |
| `ecdsa` | `verify(Curve::P256 / P384, public_key, msg, der_sig)` – each curve with its one hash | FIPS 186-5, SEC 1 |
| `mod.rs` | `Error`, `hex`, `equal_ct` (constant-time compare), `wipe`, `VERSION` | – |

Rules of the code:
- **Only `core`:** no heap, no syscalls, no `std`. Results go into memory the caller owns (an array returned by
  value or a slice passed in). The same files build in the kernel (code model `kernel`, overflow checks on) and in
  ring-3 programs.
- **No silent wrong results:** SHA-256 counts the message length and refuses past 2^61 − 1 bytes
  (`Error::LengthOverflow`) instead of wrapping; HKDF refuses more than 255 × 32 = 8160 bytes (`OutputTooLong`) and a
  PRK under 32 bytes (`KeyTooShort`) without touching the output; `verify` accepts tags of 16–32 bytes only.
- **Arithmetic** is explicitly wrapping (`wrapping_add`, `rotate_right`) – correct with or without overflow checks.
- **Keys** are wiped (volatile writes): `Sha256` and `HmacSha256` clear their whole state when dropped (also
  without `finish`, e.g. on an error path) – the inner SHA-256 state of HMAC is a hash of the key and as good as the
  key; HKDF wipes its PRK and blocks; ChaCha20 wipes its state and key stream, the generator its key; Poly1305 its
  r, s, accumulator and buffer; the AEAD the counter-0 block and the one-time Poly1305 key cut from it; X25519 the
  clamped scalar and the ladder state (x2, z2, x3, z3, the inverse, the product before encoding), and a refused
  all-zero result. Keys come by reference and are not copied by the API. Wiping a structure does not wipe its
  copies: copies in registers or on the stack (the message schedule in `compress`, values the compiler spills) are
  not covered – no full guarantee.
- **Timing:** the implementation avoids branches and table look-ups that depend on secrets (the conditional swap of
  X25519 and the final reduction of Poly1305 use masks; the X25519 inverse uses a fixed public exponent; the zero
  check ORs all bytes first). It has not been formally verified or audited for timing. Tags are compared with
  `equal_ct`.
- **Arithmetic ranges:** every product and sum of Poly1305 and X25519 has its upper bound written next to it, and in
  test builds (`--cfg selftest` / `desocrypto_test`) the bounds are asserted (`bound!`) – far below 2^128.
- **Signatures – verification only, public data only:** `rsa` and `ecdsa` check signatures made by others
  (certificates, TLS CertificateVerify); nothing signs and nothing decrypts with RSA. Their arithmetic (`bignum`,
  Jacobian points, Shamir's trick) is not constant time on purpose – every input is public (the key, the signature,
  the signed data), so there is no secret to leak; it must not be used for anything secret. Every input is bounded:
  RSA n 2048–4096 bits (odd, no leading zero byte), e odd with 3 ≤ e < 2^32, the signature exactly as long as n and
  below it; ECDSA keys must be uncompressed points on the curve with coordinates below p, signatures strict DER
  (short lengths, minimal integers, nothing after them) with 1 ≤ r, s < n. So one check costs at most a 4096-bit
  power with a 32-bit exponent or ~384 point doublings and additions. PKCS#1 v1.5 builds the whole expected block and
  compares it (no parsing of the decrypted block – the Bleichenbacher 2006 forgery needs a lenient parser); the
  DigestInfo without NULL parameters is refused. PSS takes its parameters explicitly (hash, MGF1 hash, salt length):
  `PssParams::tls(h)` is TLS 1.3's rule (same hash, salt = hash length), a certificate's parameters are read by the
  X.509 code and passed as they are – never guessed. ECDSA has exactly one hash per curve (P-256 / SHA-256, P-384 /
  SHA-384) – the pairs TLS 1.3 names and DeSoTLS will announce; no low-s rule (ECDSA has none).
- **AEAD nonces:** reusing a (key, nonce) pair is a serious security failure (the XOR of the plaintexts leaks, the
  Poly1305 key repeats and tags can be forged). DeSoCrypto does not choose nonces – there is no generator or counter
  for them until there is key management to keep them safe. `open` checks the tag before decrypting: with a wrong
  tag the buffer stays exactly as it was.
- **Test-only code stays out:** `assume_length` (a pretended length counter for the limit tests) exists only with
  `--cfg selftest` (the kernel's test build) or `--cfg desocrypto_test` (`build.sh` gives it to `cryptotest` only);
  ordinary programs and the normal kernel do not have it.

Tests: `common/desocrypto/tests.rs` (4181 checks; signatures: SHA-384/512 FIPS 180-4 examples and padding edges,
RFC 4231 for HMAC-SHA384/512, HKDF-SHA384/512 against Python `cryptography`; modular powers of 64–4096-bit numbers
against Python integers; RSA keys and signatures from `cryptography` – PKCS#1 v1.5 and PSS with several parameter
sets, a 2049-bit key (the PSS block one byte shorter than the signature), crafted almost-right blocks (padding 0xfe,
block type 2, no separator, a bit above emBits), s = 0 / n, wrong lengths, keys outside the rules; ECDSA P-256 /
P-384 including the key with private value 1, digests e > n / e = n / e = 0, high s, DER variants and public keys off
the curve or with x + p; Wycheproof (`vectors/wycheproof.bin`, built by `vectors/gen-wycheproof.py` from a pinned
commit – ECDSA P-256 and P-384, RSA PKCS#1 2048/SHA-256, PSS 2048/SHA-256 and the PSS "misc" sets: every "valid" case
verifies, every "invalid" and "acceptable" case is refused; the RSA 3072 / 4096 sets were checked on the host, not
shipped); 36 hand-made mutations of the new code were run on the host – 33 caught, 3 equivalent (a check that a later
check repeats); AES-GCM: FIPS-197 C.1 / A.1, the circuit S-box for all 256 inputs,
1–5 blocks, GF(2^128) products and GHASH against SP 800-38D written on Python integers, NIST Test Cases 1–4, every
length 0–95 and 1000 inside guard bytes, aad of 1 / 15 / 16 / 17 bytes, a wrong tag leaving the buffer untouched –
each with every AES-NI / PCLMULQDQ combination the CPU allows; before that: FIPS 180-4 / NIST, RFC 4231, RFC 5869, RFC 8439, RFC 7748 vectors;
Poly1305 limbs at their maximum and the final reduction around 2^130 − 5; X25519 field operations on edge values,
`cswap`, the seven low-order points; AEAD with a wrong tag / aad / nonce / key / ciphertext bit leaving the buffer
untouched; expected values from Python big integers – the RFC formulas, not the limb code – and the `cryptography`
library; the generator against the same construction in Python; block-edge lengths;
every split of a message; length limits with a pretended counter; wrong tags and parameters). `mod.rs` does not
include it, so it is not in the kernel or ordinary programs: only `/bin/cryptotest` and CRYPTO TEST (selftest build)
include it. CRYPTO TEST runs it in the kernel and in user space, checks `sha256sum` against the kernel's own result
and measures the speed (`[RESULT-CRYPTO]`).

**AES-GCM and the CPU.** AES-NI (CPUID 1 ECX bit 25) and PCLMULQDQ (bit 1) are detected separately and chosen
separately: hardware AES with software GHASH and the reverse are possible; `Features::limit` can only switch a feature
off (the tests run all four combinations; one the CPU lacks is never forced). The hardware paths use inline assembly
(programs are built for the soft-float target, where LLVM cannot handle 128-bit vector values in Rust code) and clear
the XMM registers they used before returning. They exist only in programs: the kernel is built with
`--cfg desocrypto_no_simd` and has no AES-NI / PCLMULQDQ code at all, because its own code runs with CR0.TS = 1 and
never saves XMM for itself – a process's XMM state is saved and restored with FXSAVE / FXRSTOR on every task switch
(`fpu.rs`), and CRYPTO TEST 5 checks it with four processes at once (a pattern in xmm0–xmm15 checked after every
yield, hardware AES-GCM compared with the software result). The fallback is bitsliced AES (four blocks at once; a
last group of 1–3 blocks and a tail under 16 bytes go through a local array – nothing outside the slice is touched)
and bit-by-bit GHASH; both avoid tables and branches on secrets. GCM nonce reuse: it reveals the XOR of the plaintexts
and, under certain conditions, can make it possible to recover H and forge tags – the caller must keep nonces unique.

Passing the RFC and Wycheproof vectors shows agreement with chosen cases of the standards; it does not prove the
implementation secure. DeSoCrypto is not for production use without an audit. Nothing in the system uses the AEAD,
X25519 or the signature checks yet – they are the base for DeSoTLS.

Next: DeSoTLS (TLS 1.3, client only) – X.509 certificates, the trusted CA store and a wall-clock syscall (v0.74), then
the handshake and the record layer with `netget https://` (v0.75).

## Random numbers (`kernel/random.rs`, v0.70.0)

The kernel's generator: a pool of entropy, a ChaCha20 generator with fast key erasure (`desocrypto::rng`) and the
`getrandom` syscall (58). Programs that need many random numbers (`netd`) key their own `KeyErasureRng` from
`getrandom` and reseed it from it every minute; DeSoOS has no `fork`, so a generator's state is never copied into
a second process.

**Sources.** Everything is mixed into the pool (SHA-256); only declared entropy counts. The declared values are a
**trust policy, not a result** – the health checks cannot prove them:

| Source | Mixed | Counted |
|---|---|---|
| UEFI `EFI_RNG_PROTOCOL` – 64 bytes read by DSB before `ExitBootServices` (the RAW algorithm first, otherwise the firmware's default), passed in `BootInfo` with which one it was (magic `DSBOOT13`), copied and wiped there at the very start of `kernel_main` | yes | RAW: ½ bit per bit (256), if the bytes are plausible; the default algorithm (usually a DRBG fed by RDRAND – its source cannot be told): 0 |
| RDSEED – 64-bit words | yes | ½ bit per bit (32 per word), after the start-up check |
| RDRAND | yes | 0 |
| TSC jitter at boot – 64-sample windows of a short memory-touching loop | yes | 1 bit per window that passes the timing check |
| interrupt times – the TSC at every IRQ / MSI, per-CPU mixing words | yes | 1 bit per 64 events whose time difference is not 0 and not the previous one |
| RTC, HPET, CPUID, NVMe serial numbers | yes | 0 |

**Trust policy** (build time, like Linux `random.trust_cpu` / `random.trust_bootloader`): `DESOOS_TRUST_CPU=0` –
RDSEED counts 0; `DESOOS_TRUST_BOOTLOADER=0` – the firmware's RAW bytes count 0. A source not trusted is still mixed
into the pool and health-checked; the classes do not change (UEFI RAW and RDSEED stay one, max). With both off only
the timing class counts (the test laptop: jitter 64 of 64 windows – a fraction of a second; KVM: about 16 s of
interrupt times). Shown in `[RNG] ready … trust: cpu on|off, bootloader on|off`, `[RESULT-RNG]` and `sysinfo
counters` (`rng_trust_cpu`, `rng_trust_bootloader`).

**Not counting the same entropy twice.** The firmware's RNG may be the CPU's RDRAND/RDSEED (OVMF does exactly
that), so UEFI and RDSEED form one hardware class counted as max(UEFI, RDSEED). Jitter and interrupt times both
come from the TSC and may be correlated: one timing class, max(jitter, interrupts). Counted = hardware + timing.
The firmware's default algorithm counts nothing at all: OVMF and many PCs implement it as a DRBG fed by RDRAND, and
counting it would let RDRAND in through the back door on a machine without RDSEED.

The interrupt check is deliberately simpler than the jitter one (a difference counts when it is not 0 and not the
previous one): the 64-difference window check would cost thousands of comparisons inside every interrupt handler.
That is why an interrupt counts only 1/64 of a bit. Without RDSEED and a RAW firmware RNG, and with a clock the
jitter check refuses (KVM), the start waits for interrupt times: 16 384 good ones – about 16 s with the 1000 Hz
timer.

**Health checks** (our own simple checks – not the NIST SP 800-90B tests; they catch obvious failures and prove
nothing about quality): 16 healthy words before a hardware source counts anything; the carry flag of every
RDSEED/RDRAND, up to 100 / 10 retries; words 0 and all ones; the same word twice in a row; a word repeated within
the last 64 (which also catches a repeated sequence of up to 32 words). A failed check, or 3 failed reads in a row,
switch the source off until the next boot (`[RNG] RDSEED disabled until reboot: …`); the others carry on. Timing
windows are not counted when one value makes up more than half of the 64 differences or repeats 8 times in a row.

**Readiness.** `random::init` runs right after interrupts are enabled, before the scheduler and before any process
exists. It waits until 256 bits are counted – collecting jitter and interrupt times and printing `[RNG] waiting for
entropy: N/256 bits …` every second – and never pretends. So `getrandom` never blocks. With RDSEED or the firmware's
RNG this is immediate; the time without them depends on the machine.

**The generator.** The whole state is a 32-byte key. Every call: ChaCha20 with that key, nonce 0, counter from 0;
the first 32 bytes become the new key at once, the rest is the output; the block is wiped. The block counter is
32 bits, so a request over 1 GiB is cut into 1 GiB pieces, each a call with its own key – the counter never
wraps. Every key is used for
one call only, so no (key, counter) pair and no output byte repeats. One `SpinLock` (`RANDOM`); interrupts never
take it. A stolen state gives away the output until the next reseed with new entropy, and nothing produced before.

**Reseeding** is checked inside `fill`: every 60 s or after 1024 interrupts, whichever comes first. The interrupt
times and 4 fresh RDSEED/RDRAND words go into the pool; a new key = SHA-256(key ‖ pool) only when the pool holds at
least 128 newly counted bits – smaller reseeds would let someone who stole the state guess each addition ("catastrophic
reseeding", Fortuna). Otherwise the pool keeps collecting.

**Users:** `getrandom` (`desoos::getrandom` in programs: any length, 4096-byte syscalls), DeSoFS volume uuids,
`netd` (TCP sequence numbers and ports, DNS ids and ports, ping ids; DHCP transaction ids are seeded from it – they
travel in broadcast frames anyway), `/bin/random`. `sysinfo counters`: `rng_reseeds`, `rng_bytes_out`,
`rng_sources_disabled`.

| | Linux | Windows | RedoxOS | Fuchsia | DeSoOS |
|---|---|---|---|---|---|
| where | kernel | kernel + a generator in every process | `randd` (user space) | kernel | kernel; programs may key their own from it |
| generator | ChaCha20, fast key erasure | AES-CTR-DRBG | ChaCha | ChaCha20 | ChaCha20, fast key erasure |
| trust in RDRAND | not alone | not alone | yes | not alone | counted 0 |
| API | `getrandom()` | `ProcessPrng` | `/scheme/rand` | `zx_cprng_draw` (no rights) | `getrandom` (no right) |
| blocks | only before initialization | no | no | no | never (the kernel waits at boot) |

Tests: RNG TEST (substituted sources that fail on purpose, the counting classes, the start-up check; fast key
erasure, a stolen key, the reseed rules; 1 MiB without a repeated block; `getrandom` edge cases and four processes
at once through `/bin/rngtest`), the first bytes of the two starts in `tests/test.sh` compared, `[RESULT-RNG]`.

## Resource limits

No program can take resources the kernel depends on – it gets an error or dies itself.

| Resource | Limit | Over the limit |
|---|---|---|
| processes | 1024 (the last 64 only for init and its children: shell, services) | `spawn` → `ERROR_WOULD_BLOCK` |
| frames for processes (pages, page tables, shared memory) | everything except the kernel reserve: 1/16 of RAM, 16–256 MiB | #PF → process killed, `shm_create` → `ERROR_OUT_OF_MEMORY` |
| IPC buffers on the heap (channel queues + pipes) | 16 MiB total (`kbuf`) | `chan_send` / pipe write → `ERROR_OUT_OF_MEMORY` |
| ramfs (heap): file data + 384 B and the name per file / directory | 24 MiB | `ERROR_NO_SPACE` |
| handles per process | 64 | `ERROR_TOO_MANY_HANDLES` |
| mappings per process | 4 GiB (`brk` ≤ 1 GiB), 4096 areas | `ERROR_OUT_OF_MEMORY` |
| kernel heap, all of the above together | programs stop 8 MiB before the 64 MiB maximum | allocating syscalls → `ERROR_OUT_OF_MEMORY` |
| channel queue | 64 messages, 4 KiB + 8 handles each | `ERROR_WOULD_BLOCK` / blocking |
| stack per process | 8 MiB | #PF → process killed |
| shared memory object | 16 MiB | error |
| DMA | 2 MiB per buffer, 16 MiB per device | error |
| `wait_many` | 16 entries; 16 observers per object | error |
| USB disks | 8 | `ERROR_NO_SPACE` |

Limits are global (there are no users yet). Test: `/bin/limtest`.

## Measurement and testing

- **Self-tests:** `tests/test.sh` – 34 self-test suites, a restart phase and a short soak (288 tests) in QEMU (TCG
  or `ACCEL=kvm`, 1–4 CPUs);
  loop mode `LOOP=suite:rounds` repeats one suite (fw_cfg `opt/desoos/loop`, `selftest::suite`) until a round fails:
  exceptions, memory, scheduler, ring 3, FPU, devices, FS, syscalls, ELF, processes, SMP, locks, TLB, allocators,
  files, IPC, the rights table, cryptography, the random number generator, DeSoFS, services, USB, network, stress. Every security fix has a test that fails without it. Scheduler tests include: tasks querying
  `with_process` / `task_exists` in a loop during spawn / exit / reap (a marker in the task checked on read – a freed
  task = FAIL); a storm of sleeps and wake-ups across CPUs with a safety deadline (wake-up after the deadline = lost
  = FAIL); exit + reap in a loop with an assertion that reap never frees a task with `on_cpu`; and a mutation test
  (without waiting for `on_cpu` the test must fail).
- **RAM disk** (v0.68.0, `block::FrameDisk`): `desofs ramdisk <MiB>` (sysctl 16) – a writable disk of 4 KiB physical
  frames (taken from the frame allocator one by one, zeroed; the list of their addresses is the only heap it uses –
  8 bytes per 4 KiB), named `ramN`, registered like any disk. 1–1024 MiB, at most 4, refused when less than a
  quarter of the free memory (and at least 64 MiB) would stay free. Not removable – its frames come back at the next
  start. Meant for real hardware, where every disk is read-only: DeSoFS and the soak test run there.
- **Soak on real hardware** (v0.68.0, `kernel/user/soak.rs`): a build with `DESOOS_AUTOSOAK=S` runs the soak before
  init with `<S>:<seed>:hw` – a RAM disk (256 MiB with ≥ 1.5 GiB free, else 96 MiB), the services killed are those
  init runs (network cards, USB controllers, `echo`; not `edu`), the network check is a ping of netd's gateway (a
  download only when QEMU's test server answers), a service may take 60 s to come back (real DHCP), the USB check
  is the boot stick's `EFI/BOOT/BOOTX64.EFI` against the SHA-256 of its first reading (first 256 KiB, the whole file
  at checkpoints). Then boot goes on to the normal init; the verdict stays on the screen. `tests/soak.sh` with
  `SOAK_DISK=ram` uses a RAM disk in QEMU (`:ram`, still with the test server and stick), which is how the short
  soak in `tests/test.sh` runs.
- **Soak test** (v0.67.0): `tests/soak.sh` (default 1 hour with KVM, `DURATION=8h`, `SEED=`) starts QEMU with the
  fw_cfg phase `soak <seconds> <seed>`; the boot tests are skipped and the kernel runs `init test /bin/soak
  <seconds>:<seed>` with the handles the real init gets (`kernel/user/test_soak.rs`), so everything goes through the
  real paths – syscalls, init restarting services, `desofs` through `sysctl`, the network through netd. `/bin/soak`
  is a controller with three worker processes (the same program; a control channel each, all randomness from the
  seed):
  - **files** – DeSoFS on `/disk` (the disk formatted first; only a writable virtio disk 0 is accepted): create,
    append, overwrite, patch, truncate, move (copy + delete – `rename` is not a syscall), delete, read, empty
    directories; at most 500 files of up to 256 KiB in 3 levels, 16 MiB in all. The model keeps (size, seed) per
    file – the content is computed from the seed, so the model stays ~12 KiB for hours; every changed file is read
    back and compared. A snapshot every 5 minutes (6 kept), each with its own frozen copy of the model.
  - **svcnet** – kills `net0`, `usb0` or `echo` every 30–90 s. Back = init lists a new pid and a higher restart
    count, and the service works (ping + a 1 MiB download from the host's `http-stub.py` with the right SHA-256 /
    `DATA.BIN` of the test stick read and checked on whichever `/usbN` it came back as / an echo answer) within 30
    s; the times go into min / average / max, and per service an average three times (+ 2 s) that service's first
    period average fails (each service against itself – v0.68.0; a network card on a real DHCP server takes 16–32 s,
    a USB controller 0.2 s); every checkpoint prints min / avg / max per service. Between kills:
    downloads, ping, echo, USB reads.
  - **procs** – spawn / wait (exit codes), kill, pipes, channels, shared memory, mmap / munmap.
  - **Checkpoints** – a baseline after the warm-up (a quarter of the run, at most 5 minutes), then every 30
    minutes and at the end: "pause" to every worker; each finishes its operation, checks all it owns (every file
    and directory listing against the model, every snapshot through its read-only view, every service, one round
    of each process test), answers "paused" with its handle count and heap end, and waits. Then: zombies and dead
    tasks 0; `sysinfo counters` and handles against the baseline – tasks, processes, IPC buffers, ramfs equal; free
    frames within 1 MiB and the kernel heap within 512 KiB (both without the console scrollback), neither worse at
    three checkpoints in a row; handles of the controller, every worker and every service equal; a worker's heap
    end not more than 1 MiB higher; `desofs unmount` (the views go too) → `desofs check` = "0 errors, 0 warnings"
    (complete) → `desofs mount`. A pin that still holds the volume makes the unmount fail – reported, not raced.
  - **Output** – a heartbeat once a minute and a line per service kill (the kernel's "nothing printed" watchdog waits
    150 s in a soak start); a failure prints `[SOAK] ERROR worker=… seq=… …` with the last 64 operations of that
    worker (a ring in memory, not millions of log lines); the end is `[RESULT-SOAK] seconds seed ops_files
    snapshots kills recover_ms net_mib procs checks leaks errors`. `soak.sh` exit codes: 0 PASS, 1 FAIL, 2 HANG (no
    new line for 5 minutes – QEMU stopped, CPU state from the QEMU monitor in the log), 3 QEMU ended by itself, 4
    too long. `tests/test.sh` ends with a 2-minute soak (snapshots every 15 s, kills every 10–20 s, 1 MiB of files).
- **Syscall fuzzer:** `/bin/sysfuzz [children] [calls]` – children (8 in parallel) call random syscalls with random
  and extreme arguments (0, -1, 2^64−1, kernel addresses, near-overflows, a real buffer with a wrong length, random
  handle numbers, nonexistent numbers → `ERROR_NOT_IMPLEMENTED`). Children start with no handles (`spawn_ex` with an empty map), so
  they can only harm themselves; `exit`, `spawn`/`spawn_ex` and `kill` are skipped. A child stuck in a blocking call
  is killed after 4 s, which also exercises cleanup of a process in the middle of a syscall. Requirement: the kernel
  survives, and no frames leak.
- **Descriptor fuzzing:** `/bin/usbparse` (see USB).
- **Autostress** (`DESOOS_AUTOSTRESS=60`) – shell scripts, prime counting, IPC jobs (process pairs: shared memory +
  channel, child killed while waiting), USB reads (`usb-stress`: the largest file ≤ 64 MiB on the first `/usbN`,
  checksums compared between passes), on all CPUs. Compare mode (default) and full-load mode
  (`DESOOS_STRESS_POOL=P`). Report: locks per call site, CPU-time profile of kernel entries (`prof.rs`), spinlock
  spinning, idle polling statistics, leaks.
- The last line, **`[RESULT]`**, is for automatic comparison of builds (humans read the screen, programs read this
  line): `ver mode idlepoll cpus ms scripts primes ipc idle pingpong_ns chan_msgs chan_mbs chan16_ms shm16_ms usb: …
  pass`. Additional lines: `[RESULT-SVC]` (service benchmarks), `[RESULT-USB]`, `[RESULT-RIGHTS]` (the rights
  gate).
- On real hardware (16 threads, 60 s), compare mode runs roughly 390–430 thousand scripts.

## Future: the DeSo AI agent

Long-term vision: a system in which an agent helps maintain and develop software, and computers exchange fixes.
Three layers:

```
DeSoOS Core     kernel + drivers           changed only by a human (after reviewing the diff)
DeSoOS Apps     .eso applications          installed with a manifest, sandboxed by handles
Agent network   a DeSo AI agent on every   exchange of fixes and applications between computers
                computer
```

**Principles:**

- **Nothing AI-specific in the kernel.** The kernel provides general mechanisms – handles with rights, channels,
  shared memory, `spawn_ex` – used by every program, the agent included.
- **The agent is an ordinary user-space program** with only the handles it was given (by init / the user). There
  is no "administrator mode" in the kernel; what it was not given, it cannot touch.
- **A `.eso` application = ELF + manifest:** version, required handles (e.g. "channel to the network service",
  "directory /home/x read-only"), a hash of the sources. The installer shows the permissions, and `spawn_ex` grants
  exactly those.
- **Reproducible builds** – the same sources produce the same binary, so a fix from another computer can be
  verified (build it yourself and compare the hash) instead of trusting a binary.
- **Kernel changes are approved by a human** after reviewing the diff; the agent may propose and test (QEMU,
  `[RESULT]`), not deploy on its own.

**Already in place:** rights that can only be reduced, handle transfer in messages, a sender id filled in by the
kernel, children with selected handles, user-space services, machine-readable test results.
**Not implemented yet:** networking, VFS isolation (today a process sees the whole file tree through paths – a
sandbox needs directories as handles), signatures, the `.eso` format.

## Future: graphics

UEFI framebuffer (current) → virtio-gpu in QEMU → possibly Intel GPUs (open documentation); NVIDIA is out.
The GUI will be a service: windows draw into shared memory, and only notifications travel over a channel.
