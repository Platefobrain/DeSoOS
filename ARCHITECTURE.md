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

**This is the whole permission model (capabilities).** A process has no user or group; what it may do is exactly
the handles it holds. Unlike Linux (UID/GID + `rwx` bits, root may do everything), a program started from the shell
gets only the handles its parent passes; `usbd` holds one claimed controller, `INPUT` and `BLK`, nothing else.
Files are the exception: by default a process may open any path.

**File sandbox:** `spawn` / `spawn_ex` with `SPAWN_NO_FILES` starts a process with no file system access by
path. `open` (every mode), `stat`, `readdir`, `mkdir`, `unlink`, `chdir`, `spawn` and `spawn_ex` give `EACCES`,
refused in one place before the call is decoded (`is_path_call` in syscalls.rs; a new path syscall must be added
there). File handles it was given keep working with their rights. The flag is inherited by every child and can
never be cleared. Shell: `nofiles <program> [args]` – e.g. `nofiles cat < file` works (the shell opens the file and
passes the handle), `nofiles cat file` gets "permission denied". Half of the `sysfuzz` children run in it.

**DCP (DeSoOS Capability Permissions)** is the name of this model, and `dcp` the command that shows it:
`dcp` (every visible process: devices, system powers, file access), `dcp inspect <pid>` (every capability with
its rights and a detail such as the PCI device, MSI vector, shared memory size, or who holds the other end of a
channel / pipe) and `dcp audit` (the last 64
refusals: sandbox path calls, read / write on a handle without the right, `EACCES`). DCP names: kinds `CONSOLE`,
`FILE`, `PIPE`, `IPC`, `MEM_SHARE`, `DEVICE_CLAIM` (HW_ROOT), `DEVICE_CONTROL`, `DEVICE_IRQ`, `SYS_POWER` (SYSCTL),
`INPUT_SEND`, `DISK_ATTACH` (BLK); rights `READ`, `WRITE`, `SEND`, `RECEIVE`, `MAP_READ`, `MAP_WRITE`, `COPY` (DUP),
`SHARE` (TRANSFER). **Who sees what:** a process sees itself and its descendants (and audit entries of itself and
its children); a holder of `SYS_POWER` (the shell) and the kernel's emergency shell see everything. A process
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

## Network (stage N – in progress: the card driver works, the protocol stack comes next)

Same shape as USB: the driver **and the whole protocol stack** run in a user-space service, `/bin/netd`, one per
network card. The kernel gets no network code (at most small helpers if the driver needs them). A bug in a packet
parser kills netd, not the kernel; init restarts it and its clients get `EPIPE`.

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
| Real hardware | Realtek **RTL8111/8168** (`10ec:8168`), typical laptop/desktop Ethernet – the test laptop has an RTL8168h (version 541) | **driver done (N8)**, confirmed on the test laptop (DHCP, ping, fetch, 10 MiB at 2.6 MiB/s) – QEMU has no model of this chip. Registers in memory BAR 2 (BAR 0 is I/O ports); 16-byte descriptors (OWN / end-of-ring / first / last, length with the 4-byte CRC); bring-up: leave the firmware's out-of-band mode, gate reception during the reset, rings, open the gate, MSI before rx/tx on, PHY through GPHY_OCP (advertise, restart auto-negotiation). Written for the 8168g/8168h generation; other versions get a warning. `ifconfig` shows the chip version, key registers and any start-up wait that ran out |
| Later | USB Ethernet adapters (ASIX, RTL8153) | through `usbd`, which already exists |
| Not planned | Wi-Fi | needs vendor firmware, 802.11 and WPA2/3 – months of work |

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
  line for tests), `arp a.b.c.d` and `ping a.b.c.d [count]`. Tools: `ifconfig` (every `netN`), `arping <ip>`,
  `ping <ip>`.
### ARP, IPv4 and ping (N3)

- **Parsers** (`user/lib/netproto.rs`): pure functions, no allocation, no panics – Ethernet II, ARP (Ethernet/IPv4
  only), IPv4 (header checksum, header and total length checked against the frame, Ethernet padding cut off,
  fragments refused – not reassembled), ICMP (checksum). Every malformed frame ends in an error and is counted
  (`malformed packets dropped` in `ifconfig`). The same file builds the frames netd sends, so the test program
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
  dropped (no sockets yet – N5/N6).
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
  (`ifconfig renew`) renews at once. Checking the address, DECLINE, RELEASE and an address by hand: see below.
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
  (1, 1, 2 s), then "no answer". `ifconfig dns a.b.c.d[:port]` sets one by hand (shown as "set by hand"),
  `ifconfig dns auto` goes back to DHCP's. **Known gap:** any program connected to netd can change the server
  today; with the client kinds from init (N7) this becomes an administrator request.
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
- **By hand:** `ifconfig set a.b.c.d/nn [gw a.b.c.d] [dns a.b.c.d]` (admin): checked the same way first (two
  probes; "already used by xx:xx:..." and nothing changes), then the DHCP lease is released, the client stops
  (`State::Off`), the address is announced. The gateway must be another address on the subnet. `ifconfig dhcp`
  starts DHCP again from 0.0.0.0. Not kept across a restart of netd (no configuration file yet).
- Tests: dhcptest 68 checks (+ Checking with its timing, DECLINE and the 10 s wait, RELEASE, stop/start); nettest
  96 (+ QEMU's router answering for 10.0.2.2 – refused, bad input, a free address with the lease released and a
  ping from it, refused without admin, back to DHCP).

### TCP (N6)

- **Connection** (`user/lib/tcp.rs`, pure – the time is passed in, segments come out): client side of RFC 9293.
  SYN with our MSS (1460) and window scale (shift 3, RFC 7323 – used only when the peer offers one too); the peer's
  MSS bounded to 64–1460 (536 when it sends none); window = free space of a 256 KiB receive ring (one 8 KiB ring
  would cap a download at window / round trip – 178 KiB/s at 45 ms on the test laptop); an 8 KiB send ring. Sending stays within the peer's window and the congestion window (RFC
  3390 initial window, slow start, congestion avoidance, fast retransmit after 3 duplicate ACKs). Retransmission
  timer from measured RTT (RFC 6298, 200 ms – 60 s, doubled per loss, Karn's rule); after a timeout everything
  from the first unacknowledged byte is sent again; 8 timeouts in a row end the connection; SYN resent after 1, 2,
  4, 8 s, then "timed out". A zero window is probed. Only in-order data is kept (out-of-order: dropped, a
  duplicate ACK; the peer resends); overlapping resends are trimmed. Closing: FIN after the queued data; all
  RFC paths (FIN-WAIT-1/2, CLOSING, TIME-WAIT 2 s, CLOSE-WAIT, LAST-ACK); FIN-WAIT-2 gives up after 10 s.
- **Untrusted segments:** checksum and header/option lengths checked by the parser; outside the window → dropped
  with an ACK; RST only with exactly the next sequence number, anywhere else in the window a challenge ACK
  (RFC 5961), likewise a SYN on an open connection; an ACK for data never sent is dropped; challenge ACKs at most
  one per 100 ms. Initial sequence numbers and local ports are random. A segment for no connection gets a RST
  (never for a RST, never to a group address).
- **netd:** 8 connections, their blocks (2 × 8 KiB rings each) in a static table that costs nothing in the program
  file (an all-zero block is a valid unused one). The program's messages go into the send ring only when a whole
  message fits (otherwise netd does not read – the program's `chan_send` waits: flow control from TCP back to the
  program); received data goes to the program without blocking – when its channel is full, the data stays in the
  ring and the TCP window closes until the program reads. Peer closed + everything delivered → netd closes its end
  of the channel (the program sees `EPIPE`) and finishes the closing. The program closes its end → FIN, or a RST if
  received data was never read; data arriving for a program that is gone → RST.
- **`fetch [-o file] [-v] http://host[:port]/path`:** HTTP/1.0 GET, the body to the console or a file, a summary to
  stderr; exit 0 complete, 2 no connection, 3 cut short (fewer bytes than Content-Length), 4 HTTP error.
  `https://` is refused – TLS needs cryptography (later).
- Tests: `/bin/tcptest` (NET TEST 4/6) – 57 checks against a simulated peer: handshake, refused, SYN resend times,
  windows, RTO and fast retransmit, zero-window probe, receiving in/out of order and overlapping, a full buffer,
  every closing path, wraparound at 2^32, hostile segments, 20 000 random segments. `tests/http-stub.py` (started
  by `tests/test.sh` on 127.0.0.1:58080, the guest connects to 10.0.2.2:58080 – QEMU's NAT): `/hello`, `/big`
  (1 MiB with a pattern), `/slow`, `/short` (cut), `/reset` (RST), `/nolength`, 404. nettest: 61 checks.
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
- **`httpd [-n count] port < page`**: a minimal server – the page from stdin (≤ 64 KiB), GET `/` or `/index.html`,
  else 404, one request at a time with 5 s to send it. `nofiles --listen httpd 8080 < /index.html` runs it with no
  file access at all.
- **From the host:** `run-qemu.sh` forwards the host's 127.0.0.1:18080 to port 8080 of DeSoOS (`HOSTFWD=port`,
  `HOSTFWD=0` – off); `tests/test.sh` forwards 127.0.0.1:58082 to port 8081.
- Tests: tcptest + 10 server-side checks (67); nettest 85 checks: narrowed rights (no listen, no DNS change, no
  other service, no widening), listening + loopback to 127.0.0.1 and to our address (200 KiB and 100 KiB both
  ways, the close seen by the server, a refused port), ping to ourselves, and a sandboxed `httpd` reached over
  loopback and **from the host**: `tests/http-stub.py /connect?port=58082` connects from the host through QEMU's
  forwarding into DeSoOS and returns what httpd answered.

- The test laptop also has an **AMD IOMMU** (00:00.2) – a future way to confine the DMA of usbd and netd to their own
  buffers (Future).

### Network access is a capability

There is no "every program may use the network". A program can reach the network only through a channel to netd,
and it gets one only through init's service channel (`SVC`, slot 3). As built in N7:

- **The shell's programs** use the shell's service channel: `svc_connect("net0")` – init hands the connection to
  netd as `net0 admin listen`: connections, servers, and the administrator requests (DNS server, DHCP renew).
- **A narrowed service channel** (`svc_narrow("net")` / `svc_narrow("net listen")`): init creates a new service
  channel that can only open network connections – `connect` to any other service is refused, there is no admin
  right, and it can only be narrowed further, never widened. init hands such connections to netd as
  `net0 client` (+ `listen`). At most 12 narrowed channels; init forgets one when nobody holds it any more.
- **`nofiles --net <program>`** – the file sandbox plus a narrowed channel (connections only);
  **`nofiles --listen <program>`** – plus servers. A compromised server can neither read the disk, nor reach
  another service, nor redirect DNS.
- A program without `SVC` (plain `nofiles`, the `sysfuzz` children) has no way to send a single packet.
- netd checks the rights per connection: `listen` needs listen, `dns` and `renew` need admin ("not allowed for
  this program"). Accepted sockets have no rights of their own – they only carry data.
- Remaining gap: every unsandboxed program of the shell has admin (could change the DNS server). A per-program
  manifest in init would narrow that further (later).

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
  → every socket gets `EPIPE`.

### Messages (draft, binary, little-endian)

Every message starts with a 16-byte header: `op u16`, `flags u16`, `len u32` (bytes after the header), `arg u64`.

| Direction | op | Meaning |
|---|---|---|
| program → netd (control) | `OPEN_TCP` | + socket end, `arg` = IPv4 address and port – connect |
| | `OPEN_UDP` | + socket end, `arg` = local port (0 = any) |
| | `LISTEN_TCP` | + socket end, `arg` = port – only on a `listen` connection, else `EACCES` |
| | `RESOLVE` | data = host name → reply with addresses |
| | `STATUS` | → text: address, gateway, DNS, MAC, counters (`ifconfig`) |
| netd → program (control) | `REPLY` | `arg` = result (≥ 0 or -errno), data = payload |
| socket, both ways | `DATA` | TCP payload / one UDP datagram (UDP: `arg` = peer address and port) |
| netd → program (socket) | `CONNECTED`, `EOF`, `ERROR` | `ERROR` `arg` = `ECONNREFUSED`, `ETIMEDOUT`, `EHOSTUNREACH`, `ECONNRESET` |
| netd → program (listening socket) | `ACCEPT` | + a new socket end for the accepted connection, `arg` = peer |

New error codes live only in the user library and netd (the kernel already has `EPIPE`, `EACCES`, `EAGAIN`).
Flow control: netd stops reading a socket's channel when the TCP send window is full; the program's `chan_send`
then blocks (queue of 64 messages) or gets `EAGAIN` with `CHAN_NONBLOCK`.

### Inside netd

- **One thread, one event loop:** `wait_many` on the IRQ, the connection channel, the control channels and the
  socket channels (16 entries per call – netd rotates through larger sets), with the nearest timer as the
  timeout (ARP retries, DHCP lease, TCP retransmission and keep-alive).
- **Layers, each a separate module with no hardware access** (testable on the host like `usbparse`): driver
  (rings, MSI) → Ethernet → ARP cache → IPv4 (no fragment reassembly at first; fragments dropped and counted) →
  ICMP (echo), UDP, TCP → DHCP client, DNS resolver.
- **TCP:** connection state machine, sequence numbers, retransmission timer with backoff, receive / send windows,
  MSS, FIN / RST, TIME_WAIT. Congestion control simple at first (slow start + congestion avoidance).
- **Loopback** (127.0.0.1) inside netd – lets the self-tests run a TCP client and server in one VM without any
  outside network.
- **Limits:** per-client socket count, receive buffer per socket, total buffers (netd's own memory is already
  capped by the kernel limits); a flood of packets costs netd CPU, never kernel memory.

### Tools

- `ifconfig` (netd `STATUS`), `ping <host>`, `fetch http://host/path` (HTTP/1.0 GET to stdout), a small
  `nc`-like tool for TCP / UDP tests.

### Testing

- QEMU with `-device e1000 -netdev user,...`: DHCP, ping 10.0.2.2, DNS 10.0.2.3 work with no internet access;
  loopback TCP for client/server tests; `hostfwd` to reach a DeSoOS server from the host.
- A fuzzer sends netd random and malformed frames (bad lengths, checksums, options, TCP flags) – netd must neither
  crash nor leak; the kernel is not involved.
- Real hardware (N8): ping and fetch on the test laptop over a cable; throughput measured like the USB stick.
- netd never writes to disk; it only sends packets the user asked for (plus DHCP, ARP and TCP control packets).
  Nothing listens unless a `net-listen` program was started.

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
