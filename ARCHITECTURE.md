# DeSoOS Architecture

How the system is built and how it works. Change history lives in `CHANGELOG.md`, the plan in `ROADMAP.md`.

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
        ┌───────────────────────┴───────────────────────┐
     KERNEL                                         USER SPACE
        │                                               │
   syscalls + handles ────────── boundary ─────── init, shell, programs (/bin)
        │                                               │
  ┌─────┼──────────┬──────────┬────────────┐       services
  MM   Scheduler  IPC        VFS       drivers      ┌────┼─────┐
  │    + locks    channels,   │        (console,    USB  NET  AUDIO
  │               shared   page cache   PS/2, PCI,       │
  │               memory      │         NVMe, virtio)    │
  │                  ╚════════╪══════ data: shared memory ═══╡
  │                         block                         │
  │     hardware delegation: MMIO, IRQ→handle, DMA, (IOMMU) ═╛  control
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
| networking | user space (future) | only with queues (like virtio/io_uring), never one IPC per packet |
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

### Kernel memory reserve

Processes may use every frame except the **kernel reserve: 1/16 of RAM, clamped to 16–256 MiB**. The check is
lock-free (a copy of the free-frame counter plus the per-CPU caches) and happens on every process page
fault. Over the limit: the faulting process is killed, `shm_create` returns `ENOMEM`. The kernel itself can
always allocate (see "Resource limits").

### Task stacks

64 KiB with a guard page. The stack of a finished task stays mapped and is reused by the next spawn (no
zeroing and no TLB shootdown).

### Process memory (`kernel/user/vm.rs`)

- A list of regions (heap, mmap, stack, shared).
- **Lazy pages:** a page is created zeroed on first access (#PF from ring 3, or `copy_from_user` /
  `copy_to_user`).
- `brk` up to 1 GiB; anonymous `mmap`/`munmap`; 4 GiB total per process.
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
  `kill(init)` → `EPERM`.
- **`spawn` instead of `fork`/`exec`** – a new ELF image, a copy of the cwd, selected handles. `spawn_ex` gives
  the child **only** the listed handles (the basis of sandboxing).
- **Zombies.** A finished process stays a zombie (only its exit code) until the parent calls `wait`. Status:
  code 0..255 or `0x100 | reason` (9 = kill, 14 = #PF).
  - Zombies are stored **in the parent process** (`Process.zombies`, a per-parent lock), not in a global table.
    The child appends itself under the scheduler lock (`with_process` on the parent – it checks that the parent
    is not exiting and is still its parent). An exiting parent, in one section, sets `exiting`, takes its zombies
    and hands live children over (`reparent_with`); its zombies go to init. `wait` takes only its own list lock.
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

`SYSCALL`/`SYSRET`; number in RAX, arguments in RDI, RSI, RDX, R10, R8, R9; result in RAX (negative = errno,
Linux-style). Process memory is accessed only via `copy_from_user`/`copy_to_user` (page check + SMAP). Almost
all syscalls run without the Big Kernel Lock (99% of calls under stress).

| No. | Calls |
|---|---|
| 0–8 | `exit`, `write`, `read`, `open`, `close`, `getpid`, `sleep`, `yield`, `uptime` |
| 9–12 | `spawn`, `wait`, `getppid`, `kill` |
| 13–18 | `chdir`, `getcwd`, `readdir`, `stat`, `mkdir`, `unlink` |
| 19–20 | `readkey` (line editor), `tasks` (ps) |
| 21 | unused (`ENOSYS`) |
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
| 46–47 | `sysinfo` (read-only), `sysctl` (reboot, halt, sync, stress – requires a `SYSCTL` handle) |
| 48 | `dev_find` |
| 49 | `input_inject` |
| 50 | `blk_attach` |

The syscall profiler (`prof.rs`) tracks all 51 numbers. Error codes are Linux-compatible, including `EBUSY`
(-16) and `ENODEV` (-19).

### Handles

Each process has a handle table (64 entries; 0/1/2 = stdin/stdout/stderr). Each entry is an object + rights.
Objects are reference-counted with `Arc` – they live as long as someone can see them.

| Kind | Object |
|---|---|
| — | console, file (`OpenFile` – position shared between copies, as in Unix), pipe end (64 KiB buffer), channel end |
| 5 `SHM` | shared memory object (also used for DMA buffers) |
| 6 `HW_ROOT` | the root of hardware access – only init has it |
| 7 `DEVICE` | one claimed PCI device |
| 8 `IRQ` | an interrupt bound to a device |
| 9 `SYSCTL` | permission for system actions (reboot, halt, sync, stress) |
| 10 `INPUT` | an input event source (keyboard/mouse) |
| 11 `BLK` | permission to register a block device |

| Right | For | Meaning |
|---|---|---|
| `READ`, `WRITE` | console, file, pipe, `INPUT`/`BLK` (`WRITE`) | missing → `EBADF` (as in POSIX) |
| `SEND`, `RECV` | channel; `IRQ` (`RECV`) | missing → `EACCES` |
| `MAP_READ`, `MAP_WRITE` | shared memory, device | missing → `EACCES` |
| `DUP` | all | may be copied (`dup`, `handle_dup`, handle for a child) |
| `TRANSFER` | all | may be passed in a message |

**Rights can only be reduced** (`handle_dup(h, mask)`); no operation adds them.

## IPC

Processes talk through **channels** (small messages, control) and **shared memory** (data).

### Channels (`kernel/user/channel.rs`)

A pair of ends, bidirectional; each end has its own queue.

- A message: up to 4 KiB of data + up to 8 handles; a queue holds up to 64 messages. **The sender's pid is filled
  in by the kernel** – it cannot be forged.
- **Handle transfer:** handles in a message are **moved** (they disappear from the sender and require
  `TRANSFER`). The whole list is validated before anything is removed; on error everything is put back.
- **No-cycle rule:** a channel end cannot travel through its own channel. Also, a channel end whose queue holds
  a message carrying another channel end cannot itself be sent in a message (`EBUSY`). This makes a cycle of
  ends inside queues impossible – the insertion that would close the cycle would have to send an end whose
  queue already holds the previous element. Why: such a cycle would never be freed. The check and the insertion
  happen under one `chan-xfer` lock (level 35, before the queue lock); only messages carrying channel ends take
  it.
- Full queue / empty queue: block, or `EAGAIN` with `CHAN_NONBLOCK`. Buffer too small (`EMSGSIZE`) or no room
  for handles (`EMFILE`) – the message **stays** in the queue and `info` reports the required size. Other side
  closed: `EPIPE`. Kill / Ctrl+C interrupts the wait.
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
Over the budget, `chan_send` / a pipe write returns `ENOMEM`, so no process can exhaust the kernel heap
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
| 230 / 240 `HEAP` / `FRAMES` | heap / frame allocator (allocation allowed from anywhere, including interrupts) |
| 250 / 255 `TLB` / `CONSOLE` | TLB shootdown / console (logging is always allowed) |

Levels 200–220 are reserved for tests. While holding a spinlock it is forbidden to sleep, wait for the BKL or
execute `hlt`.

### Other SMP mechanisms

- **TLB shootdown** (upper half): clear the PTE → IPI to the other CPUs + wait for acknowledgement → only then
  free the frame. A CPU waiting with IF = 0 services pending requests itself. The lower half needs no shootdown –
  a process runs on one CPU at a time (no threads yet).
- **Time:** the HPET is the only shared counter – **TSCs of different cores are not guaranteed to be
  synchronized** on real hardware, so measurements are taken on one CPU (task CPU time). PIT ticks catch up with
  the HPET; wall clock = RTC at boot + uptime.
- **Per-CPU data** lives in separate cache lines (`PerCpu`, `PerCpuCounter`) – dense arrays of atomics caused
  false sharing (7–15% of throughput).
- **Watchdog:** if the clock stalls for 10 s → NMI to all CPUs and a report (BKL owner, RIP, IF, spinlocks).
  Spinlock deadlock detector (HPET): report after 2 s, panic after 10 s.

## Files

- **VFS** (`kernel/fs/`) with mount points; `/` = ramfs, `/disk` = FAT32, `/esp` = EFI partition, `/usbN` = FAT32
  on USB storage (read-only).
- `FS_LOCK` is a readers–writer lock. Filesystems with their own locking (`ConcurrentFs`) run concurrently under
  the read side. ramfs: the tree under a `RwSpinLock`, each file's contents under its own mutex (a deleted file
  lives as long as someone reads it).
- `fs::Locked<F>` wraps a filesystem without its own locks in one sleeping `Mutex` and implements
  `ConcurrentFs`, so it also runs under the read side of `FS_LOCK`. Used for FAT32 on USB disks: waiting for a
  slow pendrive blocks only that filesystem. `kind` / `source` / `read_only` are copied at mount time (so `mount`
  and `open` do not wait for the disk); `df` (`mount_stats`) goes through the concurrent path. Mount and unmount
  (write side) wait for in-flight reads – at most the ublk timeout (5 s).
- **FAT32:** long file names (including Polish characters), `mkfs`, cluster-leak check. Performance features
  (each pendrive request is a SCSI command costing hundreds of µs to ms):
  - FAT read in blocks of 8 sectors,
  - cluster cache (≤ 512 KiB / 64 entries, write-through) – reading a file does not re-read path directories,
  - contiguous clusters of a file read in one request (≤ 1 MiB),
  - 64 KiB read-ahead for small reads,
  - remembered position in the cluster chain (sequential reads do not walk the chain from the start; `fat_set`
    invalidates it).
- **Read-only disks:** FAT32 on a read-only disk rejects changes immediately (`open` for writing → `EROFS`).
  `df` on a read-only disk counts free clusters from the FAT itself (once, in 64 KiB blocks), because FSInfo may
  be stale.
- **Block layer:** disks in a `Vec<Option<Arc<Disk>>>` under a `block list` SpinLock (level `BLOCK`) used only
  for lookup; each `Disk` has its own `KMutex`, so a slow USB disk does not stall NVMe or virtio. Partition →
  parent disk, always in that order; `partitions_of` takes no disk locks. Disks can be removed; a block-layer
  number returns to the pool only after unmount, and `sdX` names keep increasing and are never reused.
- Disk changes (`mkfs`, `disk read/write`) and asm test programs (`run`) are available only in the kernel
  emergency shell; `/bin/sh` answers "only in the kernel emergency shell". Future: a service with a disk handle.

## Hardware and data safety

- **ACPI** – tables only (no AML): MADT (cores, I/O APIC), MCFG (PCIe ECAM), HPET.
- **PCI** – I/O ports, then ECAM (when consistent with ports). Device interrupts via **MSI/MSI-X** (INTx needs
  AML). ISA lines (timer, keyboard, serial, mouse) via the I/O APIC; the 8259 PIC is masked.
- **Disks** – virtio-blk, NVMe (admin + I/O queue), GPT/MBR partitions as separate disks; USB storage via `ublk`.
- **Input/output** – UEFI framebuffer (text console with Polish characters, scrollback), serial, PS/2 (keyboard,
  mouse), USB keyboard/mouse via `/bin/usbd`.

**Data protection on real hardware** – independent barriers:

1. the NVMe driver writes only to a controller emulated by QEMU; a real SSD is read-only,
2. the block layer rejects every write to a read-only disk (partitions, `mkfs`, files → `EROFS`),
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

Requires `RECV` / `SEND` / `READ` (as for the operation being waited for). Kill / Ctrl+C interrupts (`EINTR`).

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
  prog-if); `ENOENT` when there are no more, `EBADF`. Requires `HW_ROOT`.
- **`dev_claim(root, PCI address)`** → a `DEVICE` handle (kind 7; rights `MAP_READ|MAP_WRITE|DUP|TRANSFER`).
  One device – one owner at a time (`EBUSY`). Refused (`EACCES`):
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

- Init has a service table (`SERVICES` in init's code), e.g. `edu` → `/bin/edud` with device 00:06.0, `echo` →
  `/bin/echod` without a device, `usbN` → `/bin/usbd` for each xHCI controller found with `dev_find` (class
  0C0330, at most 4). For each: `dev_claim` from `HW_ROOT` → `spawn_ex` (slot 1 console, 3 device, 4 connection
  channel; usbd also gets 4 `INPUT` and 5 `BLK`). No device (`ENODEV`) → state "no device", no attempts.
- **Restart:** after the process ends, a 100 ms delay, doubled up to 5 s (back to 100 ms after 10 s of stable
  running); 5 failures within 30 s → "broken", no more restarts. `EBUSY` at start (the old instance is still
  being cleaned up) → retry in 100 ms.
- **Connecting by name:** the shell and its programs have, in slot 3 (`SVC`), a channel end to init with only
  `SEND | DUP` rights (only init can receive). A client creates its own channel and sends `"connect edu"` + one
  end; init forwards that end to the service's connection channel (without waiting); afterwards the client and
  the service talk directly. Unknown / not running service → init closes the end and the client gets `EPIPE`.
  `"list"` + an end → init replies with lines "name state pid N restarts N (program)" and closes. Library:
  `svc_connect("edu")`, `svc_list(buf)`; command `services`.
- Service crashed → its clients get `EPIPE` and reconnect (after the restart).
- The shell checks at startup whether slot 3 is a channel; if so, it starts programs with `spawn_ex` and
  `[(in,0), (out,1), (2,2), (3,3)]`, otherwise with `spawn`.
- Init loop: restarts whose time has come → `wait_many` on the svc channel (at most 100 ms) → reaping children
  (`wait` with `WNOHANG`): shell, services, orphans.
- `init test <program>` – self-test mode: instead of the shell, `<program>` runs; when it ends, init closes the
  connection channels, kills the services, waits for them and exits with the program's code.
- **Future: a separate `/bin/svcmgr`.** Init would stay minimal (shell, `svcmgr`, orphans). Benefit: a bug in the
  manager would not restart init and the shell. Cost: after a manager crash the services run unsupervised and a
  new manager must find them (their devices are still claimed – `EBUSY`). Currently everything is in init because
  it is simpler; the move is a user-space code change only, with no kernel changes – to be done when the manager
  grows or its crashes become a problem.

### `sysinfo` and `sysctl`

- **`sysinfo(topic, buffer)`** (46) – read-only text: `ver`, `uptime`, `date`, `mem`, `irq`, `cpus`, `lspci`
  (`-v`), `acpi`, `disk` (list only), `mount`, `df`. Any program may ask. The shell runs these by name (`mem`,
  `lspci -v > file`).
- **`sysctl(handle, action, arg, fd)`** (47) – `reboot`, `halt`, `sync`, `stress [s]`; works only with a `SYSCTL`
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
  (DMA, up to 4000 B), `STATS`; a bad request → `EINVAL`, the service keeps running,
- service killed → clients get `EPIPE`, the device is released immediately, a new instance can claim it,
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
 FAT32 /usbN (read-only)                                       client ── "usb0" ──► init ──► lsusb, status
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
| 48 | `dev_find(root, class, n)` | `HW_ROOT` | BDF of the `n`-th device of the class (24 bits: class, subclass, prog-if); `ENOENT` – no more, `EBADF` |
| 49 | `input_inject(h, events, n)` | `INPUT`, `WRITE` | LED state (bit 0 Num, 1 Caps, 2 Scroll) – usbd sets them on the keyboard; `EINVAL` (n > 64, bad kind), `EFAULT`, `EBADF` |
| 50 | `blk_attach(h, channel, buffer, info)` | `BLK`, `WRITE`; channel `SEND`+`RECV`+`TRANSFER`; buffer `MAP_READ` | USB disk number (0 = sda); `EINVAL` (block ≠ 512/4096, 0 blocks, slots outside 1..8, buffer < slots × 64 KiB), `ENOSPC` (8 USB disks), `EACCES`, `EBADF`, `EFAULT` |

Handle kinds **10 `INPUT`** (rights `WRITE` + `DUP`, no `TRANSFER`) and **11 `BLK`**. The kernel gives them to
init at startup (slots 5 and 6); init passes each usbd a copy **without `DUP`** (usbd cannot pass them on); the
shell does not get them. `INPUT` is effectively the system keyboard (it can type into the shell) – hence the
narrow distribution. No new error codes were needed (`EIO`, `ENODEV`, `EBUSY`, `ENOSPC`, `EINVAL`, `EBADF`,
`EROFS`).

### Input – `input_inject`

An 8 B event: `kind u8`, `pressed u8`, `code u16` (HID usage, page 7 – keyboard), `dx i16`, `dy i16` (mouse: kind
2, `code` = buttons, `pressed` = wheel as i8). At most 64 events per call.

- All events are validated first (bad kind → `EINVAL`, nothing is applied). The kernel translates HID usage →
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
| usbd → kernel | `id u32`, `status i32` (0, `EIO`, `ENODEV` – medium removed), `blocks u32` (reply ≥ 12 B) |

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
- **Timeout:** 5 s per request (a pendrive may take seconds to wake). After a timeout: `EIO` for the caller, and the
  slot goes into **quarantine** – it does not return to the pool, because the device may still write into it. It
  returns only after the late reply with that `id` (which the kernel discards) or after usbd dies.
- **3 consecutive timeouts or a closed channel** (usbd died) = the disk **disappears**: further operations return
  `ENODEV`/`EIO`, a filesystem mounted on it returns `EIO`. The `usb-disks` kernel task (running from boot)
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
operation; the `ublk` disk reports `read_only` and the block layer rejects writes (`EROFS`); FAT32 on a read-only
disk refuses `open` for writing (`EROFS`).

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
- Unknown class: the device is visible in `lsusb`, with no driver.
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
  (`XferError::Interrupted` → `EIO` for the kernel; `needs_recovery` – reset recovery before the next command if the
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
- usbd clients (via init, name `usbN`): `status`, `list` (`lsusb`), `noop N`, `idle MS` (interrupt pipeline test).

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

## Resource limits

No program can take resources the kernel depends on – it gets an error or dies itself.

| Resource | Limit | Over the limit |
|---|---|---|
| processes | 1024 (the last 64 only for init and its children: shell, services) | `spawn` → `EAGAIN` |
| frames for processes (pages, page tables, shared memory) | everything except the kernel reserve: 1/16 of RAM, 16–256 MiB | #PF → process killed, `shm_create` → `ENOMEM` |
| IPC buffers on the heap (channel queues + pipes) | 16 MiB total (`kbuf`) | `chan_send` / pipe write → `ENOMEM` |
| ramfs file data (heap) | 24 MiB | `ENOSPC` |
| handles per process | 64 | `EMFILE` |
| mappings per process | 4 GiB (`brk` ≤ 1 GiB) | `ENOMEM` |
| channel queue | 64 messages, 4 KiB + 8 handles each | `EAGAIN` / blocking |
| stack per process | 8 MiB | #PF → process killed |
| shared memory object | 16 MiB | error |
| DMA | 2 MiB per buffer, 16 MiB per device | error |
| `wait_many` | 16 entries; 16 observers per object | error |
| USB disks | 8 | `ENOSPC` |

Limits are global (there are no users yet). Test: `/bin/limtest`.

## Measurement and testing

- **Self-tests:** `tests/test.sh` – 28 self-test suites in QEMU (TCG or `ACCEL=kvm`, 1–4 CPUs): exceptions, memory,
  scheduler, ring 3, FPU, devices, FS, syscalls, ELF, processes, SMP, locks, TLB, allocators, files, IPC, services,
  USB, stress. Every security fix has a test that fails without it. Scheduler tests include: tasks querying
  `with_process` / `task_exists` in a loop during spawn / exit / reap (a marker in the task checked on read – a freed
  task = FAIL); a storm of sleeps and wake-ups across CPUs with a safety deadline (wake-up after the deadline = lost
  = FAIL); exit + reap in a loop with an assertion that reap never frees a task with `on_cpu`; and a mutation test
  (without waiting for `on_cpu` the test must fail).
- **Syscall fuzzer:** `/bin/sysfuzz [children] [calls]` – children (8 in parallel) call random syscalls with random
  and extreme arguments (0, -1, 2^64−1, kernel addresses, near-overflows, a real buffer with a wrong length, random
  handle numbers, nonexistent numbers → `ENOSYS`). Children start with no handles (`spawn_ex` with an empty map), so
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
  pass`. Additional lines: `[RESULT-SVC]` (service benchmarks), `[RESULT-USB]`.
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
