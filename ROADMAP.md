# DeSoOS Roadmap

Status: 2026-10-14 – **M20 (USB) done** (v0.29.1): the test laptop's keyboard works (v0.25.1), USB stick read-only (v0.26.0, `/usb0`, confirmed on the test laptop), hubs and hot-plug (v0.27.0), robustness (v0.28.0, confirmed on the test laptop), faster FAT32 and measurements (v0.29.0; test laptop: USB stick 120 MB/s, keyboard 275 µs, stress 432 210). **P4 done** (v0.33.0: stress 534 072, +23.6%). Next: to be chosen (section "Next"). Earlier: **stage P (performance) closed** (v0.22.0): zombies held by parents, per-CPU heap and frames; test laptop: 436 134 / 528 869 scripts (+11% / +18% since M18). Next: **M20 (USB)** – plan below. **M19 (user-space services) done** (v0.19.7): `edu` driver as a process (MMIO, interrupts, DMA), service manager in init, `sysinfo` / `sysctl` instead of `kcmd`. **M18 (IPC) done** (v0.18.4): handles with rights, channels, handles in messages + `spawn_ex`, shared memory; ping-pong 6.6 µs. **M17b done** (v0.17.35). **M17a done** (v0.17.27). Architecture: `ARCHITECTURE.md`.
Details of completed stages: `CHANGELOG.md`.

```
Phase 1  Foundation       M1–M15    ✅  kernel, memory, scheduler, ring 3, syscalls, ELF
Phase 2  Userland         M16–M16b  ✅  init + shell in user space, boot on a real laptop
Phase 3  Scaling          M17–M17b  ✅  multiple cores ✅, fine-grained locks ✅ (M17a), file objects and process memory ✅ (M17b)
Phase 4  Hybrid           M18–M20   ✅  IPC ✅, user-space services ✅, USB ✅
```

Order matters: SMP before IPC (IPC is written once, with spinlocks from the start),
fine-grained locks (M17a) before M17b (new memory, process and VFS code is written without the BKL from the start),
file objects and mmap before IPC (channel handles and shared memory build on them).

Next steps: ~~SMP test on the test laptop~~ ✅ (16 CPUs) → ~~M17a~~ ✅ → ~~M17b~~ ✅ → ~~M18~~ ✅ → ~~M19~~ ✅ → ~~performance fixes (P1–P3)~~ ✅ → ~~M20~~ ✅ → **P4** (scheduler).

---

## Phase 1 – Foundation ✅

| Stage | Name | In short |
|---|---|---|
| M1 | Frame Allocator | 4 KiB frames, bitmap, alloc/free, contiguous frames (DMA) |
| M2 | Paging | 4 levels, map/unmap/translate, recursive mapping |
| M3 | Kernel Heap | first-fit + coalescing, grows and returns pages, max 64 MiB |
| M4 | GDT + IDT + exceptions | TSS, IST, exceptions 0–31, on-demand #PF |
| M5 | Timer + IRQ | PIC 8259, PIT 1000 Hz, uptime, sleep |
| M6 | PS/2 keyboard | 8042, input subsystem, Polish programmer layout |
| M7 | Console + shell | framebuffer, serial, scrollback, in-kernel shell |
| M8 | PCI + VirtIO | PCI scan, virtio-blk, `BlockDevice` trait |
| M9 | Storage + FS | VFS, ramfs, FAT32 (LFN, mkfs), RTC |
| M10 | Higher-half + ELF in DSB | kernel in PML4[511], direct map, kernel code RO |
| M11 | Tooling | `test.sh` (self-tests in QEMU), cleanup ahead of the scheduler |
| M12 | Scheduler | preemptive round-robin, wait queues, mutex |
| M13a | User mode | ring 3, per-process PML4, NX, SMEP, exceptions terminate the process |
| M13b | FPU/SSE | FXSAVE/FXRSTOR (eager), kernel soft-float |
| M14 | Syscalls | SYSCALL/SYSRET, swapgs, SMAP, 9 calls, fds on VFS |
| M15 | ELF Loader | shared parser, W^X, System V-style argc/argv, programs in Rust |

---

## Phase 2 – Userland

### ✅ M16 – Init + Shell (v0.15)

**Goal:** the kernel starts one program, user space manages the rest.

Initial cleanup:

- [x] Comment + self-test: IRQ vectors (0x20–0x2F) have no IST (`gate_ist == 0`).
      The correctness of `irq::dispatch → preempt() → kill_from_interrupt` relies on this.
- [x] Assertion in `schedule()`: a task switch on an IST stack = kernel bug.
- [x] IST stacks moved from `.bss` to a region with guard pages (5 × 64 KiB).
- [x] `map_mmio` splits a 2 MiB direct-map page into 4 KiB pages (uncached only for registers).

Main part:

- [x] The kernel starts only `/bin/init` and supervises it (restart; kernel shell as fallback).
- [x] Syscalls: `spawn`, `wait` (+WNOHANG), `getppid`, `kill`, `chdir`, `getcwd`, `readdir`, `stat`,
      `mkdir`, `unlink`, `readkey`, `tasks`, `kcmd`; `exit` with a code is delivered to the parent.
- [x] Parent/child, zombies until `wait`, orphans adopted by init.
- [x] Shell `user/bin/sh`: line editing and history, quotes, `> >> <`, `&`, built-ins
      `cd pwd echo exit help history clear wait k`.
- [x] Programs in `/bin`: `ls ps kill mkdir rm touch cp mv stat sleep` (+ M15: `cat args hello primes save`);
      kernel diagnostics via `kcmd` (`mem`, `lspci`, `mkfs`, `run`...).
- [x] Ctrl+C terminates the foreground program, not the shell (foreground stack).
- [x] Self-tests `[INIT TEST]` 9/9 (17 suites total).

**Done when:** ✅ after boot a shell runs in ring 3, `ps` shows init → sh → programs,
and after `exit` or `kill <pid sh>` init starts a new shell.

### ✅ M16b – NVMe + first real hardware (v0.16 / v0.16.1)

**Goal:** DeSoOS boots from a USB stick on a real computer and reads the disk.

- [x] ACPI: RSDP from DSB, XSDT/RSDT, MCFG; `acpi` command.
- [x] PCIe ECAM (from MCFG, cross-checked against ports), extended configuration; map_mmio on 4 KiB (M16).
- [x] Local APIC (xAPIC/x2APIC, minimal) + MSI/MSI-X (vectors 0x30–0x3F).
- [x] NVMe driver behind `BlockDevice`: 512 B / 4 KiB blocks, PRP, multiple commands in flight per queue, MSI-X.
- [x] QEMU (`-device nvme`) – self-tests `[NVME TEST]` 9/9; physical SSD **read-only**
      (driver + block layer; verified by tracing NVMe commands: 0 writes).
- [x] GPT: partitions as disks (`nvme0n1p1`), ESP with FAT32 at `/esp`.
- [x] `make-usb.sh` (no formatting, USB sticks only), instructions in README.
- [x] **Boot on the test laptop (16 threads, 16 GB)** from a USB stick: ACPI (vendor tables), ECAM
      0xF8000000, 36 PCI devices, NVMe SK hynix HFM512GD (512 GB) read-only, GPT partitions
      (ESP 512 MiB + Linux), `/esp` mounted read-only, init + shell.

Fixes from the hardware test:

- [x] missing serial port hung the boot (UART detection),
- [x] DSB: "more than 512 GiB of RAM" – the Ryzen graphics framebuffer sits below 0x1ff60000000 (~2 TiB);
      DSB now maps only regions from the UEFI memory map + the framebuffer (up to 64 TiB),
- [x] PS/2: polling the port every 5 ms (when IRQ1 does not arrive), Linux-style initialization (no
      controller or keyboard reset), status bar in the screen corner on machines without a serial port.

**Result:** ✅ console, NVMe with partitions and `/esp` visible in the boot logs. **The keyboard on the test laptop
does not work – and it is not a PS/2 bug**: the laptop keys go through USB (ITE 8910, xHCI controller 05:00.4);
the "AT Translated Set 2 keyboard" (8042) in Linux receives no interrupts while typing. Typing on
this laptop will be possible after M20 (USB/xHCI + HID) – as noted here from the start.
**Update (v0.25.1, M20.e): the test laptop's keyboard works via usbd.**

---

## Phase 3 – Scaling

### ✅ M17 – ACPI + APIC + SMP (v0.17)

**Goal:** all cores are working, locks are ready for parallelism.

- [x] ACPI MADT: cores (LAPIC / x2APIC), I/O APIC, ISA overrides (IRQ0 → GSI 2); `acpi` command.
- [x] I/O APIC instead of PIC 8259 (PIC fully masked, EOI to LAPIC); virtio-blk on MSI-X.
- [x] Starting the remaining cores: INIT-SIPI-SIPI, trampoline < 1 MiB (real mode → straight to
      64-bit), temporary PML4 < 4 GiB; on each AP: GDT/TSS/IST, IDT, FPU, SMEP/SMAP, PAT,
      SYSCALL, LAPIC.
- [x] LAPIC timer (calibrated with the PIT) – 100 Hz on APs; PIT on the BSP keeps time and wakes sleeping tasks.
- [x] Per-CPU data: `current`, quantum, idle task, NEED_RESCHED, TSS, SYSCALL block (KERNEL_GS_BASE);
      CPU number from RDTSCP (TSC_AUX).
- [x] Idle CPU woken by IPI ("resched"), panic halts the other cores (IPI "halt").
- [x] **Locking: Big Kernel Lock** (like Linux 2.0) – a ticket lock for the whole kernel. Kernel code runs
      on one CPU at a time, ring 3 processes run truly in parallel. Released on return to ring 3,
      in `hlt` and in the timer tick when another CPU is waiting.
- [x] TLB: instead of shootdown – with multiple CPUs a full flush (CR3) on every switch, the heap does not
      return pages. Processes are single-threaded, so their mappings live in only one core's TLB.
- [x] `cpus`, CPU column in `ps`; `-smp 4` in `test.sh` and `run-qemu.sh`.
- [x] Self-tests `[SMP TEST]` 5/5 (19 suites): 4 CPUs online, kernel tasks on all cores,
      `primes` in parallel, 8 shells at once (spawn/wait/VFS), FPU/SSE across migration between cores.

**Result:** ✅ with `-smp 4` all self-tests pass, processes spread across cores
(`ps`: `sh` on CPU 0, two `primes` on CPUs 1 and 3). Additionally the entire existing test suite
passed with SMP enabled from boot – except tests that by design count switches on a single
core.

**Honestly:** this is "starter" SMP, not scaling. The kernel is a single bottleneck – compute-bound
programs get full parallelism, but syscall-heavy programs wait for the BKL in turn.

Checkpoint before M17a:

- [x] Boot on the test laptop from a USB stick (2026-10-04): MADT with 16 cores (APIC id 0–15, xAPIC),
      all 15 APs came up on the first try, LAPIC timer 6237 ticks/ms (bus clock ~100 MHz,
      typical for AMD), init and shell work (init has PID 18 – before it 16 idle tasks and a kernel task).

### ✅ M17a – Fine-grained locks instead of the Big Kernel Lock (v0.17.1–v0.17.27, closed 2026-10-08)

**Goal:** kernel code runs in parallel on multiple cores (two `read`s on different CPUs enter the
VFS at once). Cores are NOT assigned to subsystems – any CPU can run any kernel code.

**Migration rule:** the BKL is removed **by paths, not by subsystems**. First a fine-grained lock under the BKL
(works as before), then individual syscalls stop taking the BKL once everything they touch has
its own lock. The system works at every step, and a bug can be attributed to a single step.
Per-CPU `current`, quantum, idle, TSS, SYSCALL block and CPU number already exist since M17.

- [x] **a.** (v0.17.1) `SpinLock` / `IrqSpinLock` (`kernel/sched/spin.rs`) with a per-CPU preemption
      counter; mini-lockdep: level ordering, recursion, sleeping with a spinlock held, deadlock report
      (who waits and where, who holds and from where); **hang watchdog** (clock stalled for 10 s → NMI to all
      CPUs: RIP, IF, BKL tickets); BKL statistics (`cpus`); `bkl::unlocked` – kernel code without the BKL
      (an interrupt releases the BKL on return to such code); lock ordering in ARCHITECTURE.md;
      stress test `[STRESS TEST]` + `stress [s]` command; interval clock on the HPET (core TSCs can be
      out of sync); timer tick counted before the BKL. Self-tests 21/21 (on the developer's machine: 20 s, the second CPU takes over
      work after 2 ms).
      The tools immediately found: a race in `preempt_disable`, an interrupt releasing the BKL after waking
      an idle CPU (the BKL bounced thousands of times per second, idle CPUs picked up tasks after seconds),
      starvation of the test task in test 2/5, several bugs in the watchdog itself.
- [x] **b.** (v0.17.2) TLB shootdown: vector 0x43 without the BKL, one request at a time, waiters with IF = 0
      acknowledge inside their wait loops; `unmap_range_free` (PTE → shootdown → free_frame, batches of 32
      pages); the heap returns pages again under SMP, kernel page tables are freed again, CR3 only on
      address-space change (no more full flush on every switch). `[TLB TEST]` 5/5 – including a
      check that without shootdown a reader on another CPU really sees the stale page (the test does test something).
      Along the way: ticks catch up with the HPET under SMP (lost PIT interrupts – time stalled under congestion),
      automatic stress test after boot (`DESOOS_AUTOSTRESS=60 ./make-usb.sh ...`) for a laptop without a
      keyboard. Bottom half without shootdown until threads (M17b: `active_cpus` mask).
      Test laptop (16 CPUs, autostress 60 s, 2026-10-05): PASS – 47 866 scripts, 359 006 shootdowns
      (5.39 M IPIs = as many acknowledgements, 140 ms of waiting in total), 0 deadlock reports, memory
      is returned. BKL: 99% of acquisitions wait, ~35 s of 60 s per core – that is the bottleneck for steps c–g.
- [x] **c.** (v0.17.3) Frame allocator and heap on their own `IrqSpinLock`s (levels 240 / 230 – almost
      innermost, because allocation is allowed everywhere, including in interrupts). The heap grows (`map_page`
      in its own region) and shrinks (TLB shootdown) without the BKL. `[ALLOC TEST]` 3/3: 4 tasks × 640 KiB without the BKL
      (heap grows and shrinks in parallel), small blocks + frames + allocations in the timer interrupt, meanwhile
      creating task stacks; the stress test now also allocates without the BKL. The BKL itself does not shrink yet –
      the gain comes in d, once syscalls stop taking it (allocations no longer require it).
      Test laptop (16 CPUs, autostress 60 s, 2026-10-05): PASS – 3.05 M heap allocations + 93 k frames without the BKL,
      217 k shootdowns (IPIs = acknowledgements), 0 deadlock reports, memory is returned. 13% of spinlock acquisitions
      wait (mostly the heap – one lock for 16 CPUs; later: per-CPU block cache).
- [x] **d.** (v0.17.4) First syscalls without the BKL: `getpid`, `uptime`, `write` to the console / captured
      stdout (per-CPU pointer to the current task and process, stdout and shell line on SpinLocks,
      framebuffer with an owner). `sleep` moved to f (it enters the scheduler). `[NOBKL TEST]` 3/3:
      4 × 100 000 getpid with ~150 BKL acquisitions, 4 × 2000 lines at once – each intact, kill of a process doing
      only BKL-free syscalls. In stress ~45% of syscalls without the BKL; the rest (spawn, wait, files, read) – in e.
      Test laptop (16 CPUs, autostress 60 s, 2026-10-05): PASS – 39 077 scripts (v0.17.3: 28 928, same extra
      work: +35%), 5.13 M syscalls without the BKL (44%; write 4.97 M), BKL acquisitions 7.45 M (was 9.44 M,
      −21%), 0 deadlock reports, memory is returned.
- [x] **e.** VFS, block layer, processes (zombie table, descriptors).
  - [x] **e1.** (v0.17.5) VFS and block layer without the BKL: `KMutex` with compare_exchange (previously
        `without_interrupts` was enough), `WaitQueue` / `wake_channel` / `sleep` / `yield` take the BKL only briefly
        to enter the scheduler (`bkl::with`; `schedule()` checks the BKL with an assert), `current_id` /
        `current_process` / `should_exit` without the task list. Without the BKL: open, close, read from a file / stdin buffer,
        readkey from the buffer, write to a file, stat, readdir, mkdir, unlink, chdir, getcwd. `[NOBKL TEST]` 4/4
        (4 shells at once append 41 lines each to their own files – exact contents). In stress ~89% of syscalls
        without the BKL (was 45%). Along the way: the captured-output log is written only by the buffer creator
        (children were evicting the parent's entry – SMP TEST 4 with 8 CPUs).
        Test laptop (16 CPUs, autostress 60 s, 2026-10-05): PASS – 46 116 scripts (v0.17.4: 39 077, +18%), 90%
        of syscalls without the BKL (12.2 M; files 6.1 M), only 64% of BKL acquisitions wait now (was 99%), total
        waiting time 274 s (was 566 s, −52%); more acquisitions (9.7 M) – short `bkl::with` while waiting.
        0 deadlock reports, memory is returned.
  - [x] **e2.** (v0.17.6) Processes: spawn, wait, kill, getppid without the BKL – the zombie table already had its own
        lock (KMutex, now safe on multiple CPUs), the task list only briefly under the BKL (public
        scheduler functions via `bkl::with`, `sched()` checks the BKL with an assert). Spawn: ELF and address
        space without the BKL, task creation + foreground entry together under the BKL (Ctrl+C gap closed).
        `[NOBKL TEST]` 5/5 (4 shells × 15 programs at once, no zombies). In stress ~97% of syscalls without the BKL.
        exit stays under the BKL (task exit = scheduler).
        Test laptop (16 CPUs, autostress 60 s, 2026-10-05): PASS – 97% of syscalls without the BKL (processes 0.84 M),
        47% of BKL acquisitions wait (e1: 64%), waiting 199 s (e1: 274 s, −27%), but 42 035 scripts (e1: 46 116, −9%) –
        spawn/wait take the BKL briefly several times (12.2 M acquisitions) instead of once; those acquisitions go away in f.
- [ ] **f.** Scheduler: scheduler lock, then per-CPU queues (riskiest – last).
  - [x] **f1.** (v0.17.7) Scheduler lock alongside the BKL (protects the same thing): recursive, IF = 0, held across
        the task switch (released by the new task; depth stored in the task), `sched()` checks the BKL
        and the lock with an assert, check "task is not current on another CPU". `[NOBKL TEST]` 6/6: ping-pong
        of two tasks via WaitQueue (2000 wakeups) under a storm of switches (yield) on multiple CPUs. `cpus`:
        scheduler lock statistics (0% waiting today – under the BKL).
        Test laptop (16 CPUs, autostress 60 s, 2026-10-05): PASS – scheduler lock 16.0 M acquisitions, 0% waiting
        (as expected: always under the BKL), 41 918 scripts (e2: 42 035 – unchanged), 0 deadlocks.
  - [x] **f2.** (v0.17.8) The BKL leaves the scheduler path: wait/wake/sleep/yield/spawn/reap/kill only under
        the scheduler lock (`sched::wait_event` – condition + sleep under it). The BKL is released at the switch
        and re-acquired after it (`Task::bkl_dropped`, `after_switch` – like Linux 2.x); `preempt` preserves
        the interrupted context's flag. `sleep` and `yield` syscalls without the BKL. Stack pages, captured stdout
        and shell line on `IrqSpinLock` (an interrupt inside a SpinLock section takes the BKL → deadlock with a CPU that
        holds the BKL and waits for that SpinLock – caught on `stack-pages`). `[NOBKL TEST]` 7/8: wakeup storm
        without the BKL (3000 generations) + sleep(100) in processes, 8/8: kill of sleeping processes without the BKL (wakes immediately).
        Interrupt entry (tick) still takes the BKL – step g.
        Test laptop (16 CPUs, autostress 60 s, 2026-10-07): PASS, 0 deadlocks – BKL 3.65 M acquisitions (e2: 12.2 M,
        −70%), 68% wait, waiting 171 s (f1: ~199 s); scheduler lock 17.6 M acquisitions, 19% wait, but
        only 9.8 s in total (~1% of 16 CPUs' time, avg. ~3 µs per wait); 41 140 scripts (f1: 41 918 – no
        change, the bottleneck is still the BKL). QEMU TCG 8 CPUs on the developer's machine: 24/24.
        Decision: f3 (per-CPU queues) after M17b – the scheduler lock is ~1% of time, the BKL ~18%; g first.
  - [ ] **f3.** Per-CPU queues – after measuring scheduler lock contention after f2 (high: right away, low: after M17b).
    - [x] **f3a.** (v0.17.18) Scheduler without scanning the task list (still one lock): ready queue
          (FIFO, round-robin), number → task map, per-channel wait lists (WaitQueue), sorted deadline
          list (the tick wakes only expired ones); `wake_channel`, `on_tick`, `ap_tick`, `schedule`,
          `block_current` – O(1) / O(log n) instead of O(number of tasks). reap only when there are dead tasks.
          Test laptop (2026-10-07): **worse** – 36 689 scripts (41 667), 10% idle, scheduler lock 79% wait,
          **335 s** (232 s); process table 768 s, ramfs tree 946 s. Suspicion: BTreeMap / Vec allocated
          on every sleep and wakeup – under the heap lock (spinlocks 59.6 M waits), with IF = 0, while holding
          the scheduler lock.
    - [x] **f3b.** (v0.17.19) The same queues without allocation: intrusive doubly linked lists embedded in the task (links
          `rq` / `wq` / `sq`), channel (256) and number (1024) buckets in fixed arrays; reap reserves
          space before taking the lock.
          Test laptop (2026-10-07): PASS – 37 578 scripts (f3a: 36 689), 19% idle, scheduler lock 62% wait,
          235 s (f3a: 335 s – allocation under the lock confirmed; but the same as before f3a: 232 s), process table
          357 s (768 s), **ramfs tree 1108 s**, BKL 0.16 s. Conclusion: since g8 (4 stress loops) throughput
          drops – more parallelism = more contention on sleeping locks (a wakeup wakes ALL
          waiters – thundering herd), not less. The best result is still v0.17.16 (1 loop): 45 802.
          Plan: g10 – sleeping locks wake one waiter (handoff, FIFO) instead of all;
          then f3c – per-CPU queues.
- [ ] **g.** The BKL goes away (or stays only for legacy paths, e.g. the kernel shell).
  - [x] **g0.** (v0.17.9) Measurement: who takes the BKL – per-acquisition-site statistics (count, waiting, hold
        time from TSC), interrupt entry broken down by type (PIT, LAPIC timer, resched IPI, devices,
        exceptions) and by what was interrupted (process / kernel). `cpus` and autostress: "BKL by site" (8 most expensive).
        `[NOBKL TEST]` 9/9.
        Test laptop (16 CPUs, autostress 60 s, 2026-10-07): BKL 3.85 M acquisitions, 70% wait, 173 s waiting, of which
        **129 s (74%) is "wake from hlt"** – the idle loop took the BKL after every wakeup (2.37 M times, 89% with
        waiting; woken mostly by TLB shootdown IPIs – 4.8 M, without the BKL), just to call reap and go back to sleep.
        Next: return after switch 10.6 s waiting / 13.8 s holding, syscalls under the BKL (322 k) 9.9 s,
        end of bkl::unlocked 10.4 s, task start 6.1 s, timer interrupts from the kernel ~5 s. 43 066 scripts.
  - [x] **g1.** (v0.17.10) Idle loop without the BKL: BKL only for reap, and only when there are finished tasks
        (`DEAD_TASKS` counter).
        Test laptop (2026-10-07): BKL 1.57 M acquisitions (g0: 3.85 M), 36% wait (70%), **waiting 57.5 s (173 s,
        −67%)**. Scripts 39 482 (43 066) – no gain: stress has a fixed pool of 12 tasks and a 2 ms loop, so
        the script count measures the latency of a single task, not throughput; the waiters were mostly
        idle CPUs. New top: idle reap 13.4 s waiting (all idle CPUs at once for the same thing),
        return after switch 9.5 s / 14.5 s holding, end of bkl::unlocked 11.7 s, syscalls 9.0 s.
  - [x] **g2.** (v0.17.11) One reaper at a time (the other idle CPUs do not queue up); preemption
        from an interrupt that interrupted a BKL-free context does not re-take the BKL (only to release it on
        exit); process exit log on its own `IrqSpinLock` (writes from BKL-free syscalls and from
        interrupts – two at once lost an entry); return after switch split into wait/sleep/yield/preempt;
        "% idle" in stress and `cpus` (time in the idle task, counted in schedule()).
        Test laptop (2026-10-07): BKL 1.32 M acquisitions, 28% wait, **waiting 36.7 s** (g1: 57.5 s; start of g: 173 s),
        idle reap 0.6 s (13.4 s), preempt dropped out of the top eight. Stress: **76% idle** – too weak for 16 CPUs.
        Top: syscalls under the BKL 308 k (= exit, one per process), task start 308 k (= process
        start), end of bkl::unlocked 187 k (stress tasks took the BKL only for sleep), after sleep /
        wait_event (holding 6.4 / 7.2 s – kernel tasks), LAPIC timer from the kernel 6.4 s.
  - [x] **g3.** (v0.17.12) Process exit without the BKL (SYS_EXIT without the BKL, exit_current on its own locks;
        the address space is freed by reap under the BKL), process starts without the BKL; stress tasks entirely without the BKL;
        stronger stress: pool of 3 tasks per CPU (max 48, was 2/CPU, max 12), CAPTURED_LOG 128 – script counts
        from v0.17.12 on are not comparable with older ones.
        Test laptop, 1st run: FAIL after ~7 s (exit log of 256 entries too small at ~20 k processes/s –
        fixed: 2048). Up to that point: BKL 58 k acquisitions, 5 s waiting; scheduler lock 52% wait,
        17.5 s (~15% of CPU time) – f3 is back on the table.
        Test laptop after the fix (2026-10-07): PASS – 58% idle (was 76%), 39 428 scripts (new pool, new
        baseline), 1.08 M processes. BKL 401 k acquisitions, 33% wait, 46 s waiting – of which ~38 s is
        interrupts interrupting the kernel (LAPIC timer 26.2 s, PIT 9.7 s, resched IPI 2.6 s); after wait_event
        holds 20.9 s (kernel tasks). **Scheduler lock: 18.9 M acquisitions, 46% wait, 124 s waiting**
        (~13% of CPU time, with IF = 0 – CPU 0 lost 2283 PIT interrupts, caught up from the HPET). Throughput does not
        grow despite a 4x larger pool → bottlenecks: the scheduler lock and the BKL in interrupts.
        Plan: g4 – timer and resched interrupts without the BKL, then f3 – per-CPU queues.
  - [x] **g4.** (v0.17.13) PIT tick, LAPIC timer and switch IPI without the BKL (atomics, scheduler lock,
        watchdog, tick hook); PS/2 keyboard polling in the tick only when the BKL is immediately free
        (`bkl::try_acquire_tagged`). QEMU 4 CPUs: BKL in stress ~330 acquisitions (g3: ~1.9 k).
        Test laptop (2026-10-07): PASS – **BKL 5.0 s waiting** (g3: 46 s; before g: 173 s – −97%), 228 k acquisitions,
        10% wait; lost PIT interrupts: 0 (was 2283); scheduler lock 37% wait, **55.7 s** (124 s).
        But 63% idle and 38 548 scripts – throughput is flat. The BKL and the scheduler lock are now together ~6% of
        CPU time, and the CPUs are 63% idle → tasks wait while sleeping (suspects: VFS/block KMutex – one for the whole VFS,
        reading the ELF on spawn; the stress loop). Next: g5 – measure sleeping locks (KMutex: who,
        how long they wait), then decide: f3 or finer-grained VFS locks.
  - [x] **g5.** (v0.17.14) Sleeping lock measurement: named KMutex (`new_named`) – acquisitions, waiting
        (once per lock, time from HPET), holding (TSC); VFS, block layer, process table, captured
        output. `cpus` / autostress: "sleeping lock" lines. Stress: "driver N% busy" – how much time the
        driver loop is working (outside its 2 ms sleep). QEMU 4 CPUs: driver 83% busy (suspicion: stress limits
        itself).
        Test laptop (2026-10-07): PASS – 64% idle, **driver 92% busy**, 39 343 scripts. **VFS (FS_LOCK): 2.05 M
        acquisitions, 31% wait, 710 s waiting** (on average ~12 tasks constantly asleep in the VFS queue) – the main
        bottleneck; process table 31 s; scheduler lock 54 s; BKL 4.9 s. KMutex hold time (TSC) came out
        absurd (33 815 s) – the holder sleeps and changes CPU, the test laptop's core TSCs are out of sync → to be fixed.
        Plan g6: VFS as a readers–writer lock (stat/read/readdir/exec in parallel), cheaper stress loop
        (task_info clones the whole task list), KMutex hold time from HPET (sampled).
  - [x] **g6.** (v0.17.15) VFS on `KRwLock` (sleeping readers–writer, reentrant, a queued writer
        blocks new readers, reader → writer = panic): stat / read / read_dir / read_file
        (including loading the ELF on spawn) on ramfs as reads, many at once (`*_shared` in FileSystem – ramfs
        yes, FAT32 no); modifications and FAT32 as writes. KMutex hold time from HPET every 16th acquisition. Stress
        loop: `sched::task_exists` instead of `task_info`.
        Test laptop (2026-10-07): PASS – 44 946 scripts (+14%), 54% idle (64%), driver 90%. VFS: 2.27 M reads
        + 405 k writes, 394 k + 143 k waited, **668 s** (710 s) – almost unchanged: writes
        (mkdir/echo/rm in /stN) block readers (exec from /bin), and a reader holds the lock for the whole
        read_file. Scheduler lock 68.6 s, process table 48.7 s, BKL 4.8 s.
  - [x] **g7.** (v0.17.16) ramfs with its own locks (`ConcurrentFs`, `&self`): directory tree under
        `KRwLock` (lookup as read, create/mkdir/remove as write – briefly), each file's contents under
        its own Mutex (Arc – copying without holding the tree). The VFS calls it under FS_LOCK as read only
        (as write: mounting and FAT32). read_file / write_file / >> as atomic `read_all` /
        `write_whole` / `append`.
        Test laptop (2026-10-07): PASS – VFS 1.6 M reads + **2 writes, 0 waiting** (668 s); but "ramfs tree"
        355 k + 93 k waits, 409 s (~1 ms per wait – sleep and wakeup through the scheduler for a section
        lasting µs); process table 114 s; scheduler lock 51%, 128 s; 44% idle (54%), 45 802 scripts,
        driver 90% busy – stress limits itself again.
  - [x] **g8.** (v0.17.17) Sleeping locks first spin for a while (2000 × pause, a few tens of µs; only
        under SMP), then sleep – KMutex and KRwLock (`cpus`: "% spun"). Stress: several driver loops (1 per
        4 CPUs, max 4, kernel tasks without the BKL), pool shared among them.
        Test laptop (2026-10-07): PASS, but **worse**: 41 667 scripts (45 802), **6% idle** (44%) – CPUs busy
        spinning. ramfs tree: 410 k + 95 k waits (284 k resolved by spinning), 910 s;
        process table 216 s (11% sleep, 11% spin); **scheduler lock 65% wait, 232 s**; BKL 0.16 s;
        driver 63% (no longer limiting). Conclusion: spinning under such contention burns CPU; the real bottleneck
        is the global scheduler lock – every sleep and wakeup goes through it, and `wake_channel` scans
        the whole task list (a KRwLock/KMutex wakeup wakes all waiters at once).
        Plan: g9 – spinning disabled/limited; then f3 – per-CPU queues + wait queues
        (WaitQueue with a task list instead of scanning all tasks).
  - [x] **g9.** (v0.17.18) Spinning before sleep disabled (`SPIN_ITERS = 0`, the code stays as a knob).
  - [x] **g10.** (v0.17.20) Sleeping locks without a thundering herd: KMutex wakes ONE waiter (`sleepers`
        counter; release wakes only when someone is sleeping; the woken one takes the lock or sleeps again – the next
        releaser wakes the next one). KRwLock: separate reader and writer queues; writer release
        admits the whole group of waiting readers (even when writers are waiting – no reader starvation),
        the last reader wakes ONE writer. `sched::wake_one_channel`. Like Linux (mutex – first
        waiter; rwsem – a group of readers or a writer) and HelenOS (`WAKEUP_FIRST`).
        QEMU (TCG, 4 CPUs, 20 s): PASS. Now: `SMP=8 ./stress-qemu.sh`, then the test laptop.
        If the scheduler lock is still high: f3c – per-CPU queues (last CPU, work stealing – like Zircon).
        `SMP=8 ./stress-qemu.sh` (KVM): PASS, 5075 scripts; process table 1239 s waiting (48% sleep,
        held 43 s of 60 s), ramfs tree 138 s, scheduler lock 75% wait (286 s), 8% idle.
  - [x] **g11.** (v0.17.21) Process exit wakes only the parent: `wait` in one of 64 queues chosen by
        parent number (previously one queue – every exit woke all parents, each scanned
        the task list); `Process::has_children` – without children process exit does not do `reparent` (a scan of
        all tasks under the scheduler lock, while holding the process table). QEMU TCG 4 CPUs: process table
        waiting 6.8 s → 3.1 s.
        `SMP=8 ./stress-qemu.sh` (KVM): 6031 scripts (+19%), process table 536 s (1239 s), scheduler
        lock 85% wait, 314 s.
  - [x] **g12.** (v0.17.22) Tick without the scheduler lock (CPU time, per-CPU quantum, `READY_N`; the BSP takes it
        only on a wakeup deadline – `NEXT_WAKE`) + per-function scheduler lock statistics ("scheduler
        lock by site"). Now: `SMP=8 ./stress-qemu.sh`, then the test laptop – choose the next step from the site list
        (candidates: children_of / with_process under the process table, f3c – per-CPU queues).
        `SMP=8 ./stress-qemu.sh` (KVM): 6279 scripts; scheduler lock 87% wait (299 s), although held
        ~1.3 s in total – wait_event 383 k acquisitions, wake_one_channel 198 k, children_of 138 k.
  - [x] **g13.** (v0.17.23) Timing outside the lock: waiting on spinlock / scheduler lock / BKL
        measured with TSC, not HPET (reading the HPET after taking the lock lengthened the hold – tens of µs in KVM);
        KMutex / KRwLock – end of waiting before acquisition, holding with TSC + CPU.
        `SMP=8 ./stress-qemu.sh` (KVM): **16 560 scripts** (2.6×), scheduler lock 4% (192 ms), process
        table without waiting; ramfs tree: 92% of reads wait, 815 s; 44% idle.
  - [x] **g14.** (v0.17.24) Wall clock without CMOS ports: RTC read once at boot, `rtc::now()` =
        boot time + uptime (previously ~45 port operations under the ramfs tree write lock). Now:
        `SMP=8 ./stress-qemu.sh`, then the test laptop.
        v0.17.25: fix for a regression from g13 – deadlock detection back on the HPET (TSC gave a false
        'heap' spinlock panic under TCG).
        `SMP=8 ./stress-qemu.sh` (KVM): **38 352 scripts** (2.3×), locks negligible, 0% idle.
        **Test laptop**: **45 606 scripts** (+21% vs v0.17.19; record 45 802), 2% idle; ramfs tree 30%
        of reads wait (536 s), process table 33 s, children_of holds the scheduler lock 4 s.
  - [x] **g15.** (v0.17.26) `wait` without scanning the task list (`Process::live_children`, specific child
        O(1)) + short spinning before sleep (200 × `pause`). Now: `SMP=8 ./stress-qemu.sh`, the test laptop.
        If spinning hurts (idle ↓, scripts ↓) – `SPIN_ITERS = 0`.
        `SMP=8 ./stress-qemu.sh` (KVM): 38 983 scripts (38 352 – within noise); ramfs tree: 62% of waits
        resolved by spinning, waiting 21.7 s → 15.9 s; children_of disappeared.
        **Test laptop (2026-10-08): RECORD 50 524 scripts** (v0.17.25: 45 606, +10.8%; previous record v0.17.16:
        45 802), 2% idle; BKL 0.26 s; scheduler lock 5% wait, 2.3 s (6.5 s); ramfs tree: 30% of reads
        wait (438 k, only 31 k resolved by spinning), 505 s; process table 43 s; TLB shootdown
        379 k requests, 5.7 M IPIs.
        Status vs "Done when": syscalls 99% without the BKL, BKL off the hot paths (0.26 s waiting in 60 s
        on 16 CPUs), stress without errors. Next candidates: ramfs tree (per-directory lock or a spinning
        readers–writer lock – every stress script does 4 tree writes: mkdir, create, rm, rmdir),
        TLB shootdown only to CPUs that used the address space (like mm_cpumask in Linux).
  - [x] **g16.** (v0.17.27) ramfs tree under a spinning readers–writer lock (`spin::RwSpinLock`);
        read_dir / stats without file locks under the tree. QEMU TCG: tree waiting ~4.2 s → 42 ms. Now:
        `SMP=8 ./stress-qemu.sh`, the test laptop; then closing M17a (summary) or TLB shootdown.
        `SMP=8 ./stress-qemu.sh` (KVM): 41 328 scripts (38 983, +6%); ramfs tree 103 ms (15.9 s).
        **Test laptop (2026-10-08): RECORD 53 809 scripts** (50 524, +6.5%; record before g10–g16: 45 802 –
        +17.5%), 2% idle; ramfs tree: 2.2 s waiting (505 s), held 4.5 s; process table 74 s (1%
        sleeps), captured output 12 s; scheduler lock 2% wait, 2.5 s; BKL 0.23 s; TLB shootdown
        404 k requests, 6.1 M IPIs.
- [x] At **every** step: self-tests (regression) + SMP stress test (many processes, syscalls,
      spawn/wait, files – minutes, not seconds: `stress 300`). Especially after b and f.

Baseline (QEMU, 4 CPUs on 2 host cores, stress 3 s): ~80% of BKL acquisitions have to wait;
with 2 CPUs the system does ~3x more work than with 4 – result inflated by the overloaded host (measurement
on the test laptop: `stress 30`, then `cpus`).
- [ ] Along the way: device interrupts spread across cores (today all go to the BSP).

**Done when:** ✅ syscalls from different CPUs run in parallel (3 × 100 000 syscalls on 3 CPUs
take no longer than on one), the stress test runs without errors, and `bkl` does not appear on hot
paths.

**M17a summary (2026-10-08):**
- Met: NOBKL TEST 1/9 – 4 × 100 000 getpid without the BKL in parallel; syscalls in stress 99% without the BKL
  (on the test laptop 15.8 M, 1 under the BKL); BKL: 0.23 s waiting in 60 s on 16 CPUs (v0.17.8: 171 s); stress
  and self-tests (24 suites, 192 tests; TCG and KVM, 1–8 CPUs) without errors.
- Test laptop, autostress 60 s (shell scripts): v0.17.8 – 41 140 → v0.17.16 – 45 802 → v0.17.19 – 37 578
  (more parallelism = contention on sleeping locks) → g10–g16 – **53 809**. QEMU KVM 8 CPUs: 5 075
  (v0.17.20) → 41 328 (v0.17.27).
- Key lessons (details in ARCHITECTURE.md): (1) measure before changing – per-site statistics
  (BKL, scheduler lock, sleeping locks) pointed to each next step; (2) nothing slow under a lock
  – reading the HPET (g13) and RTC (g14) under a lock stretched µs sections by tens of µs and
  created convoys; (3) wake one, not the herd (g10, g11); (4) µs sections – spin, don't sleep
  (g15, g16); (5) measurement for statistics (TSC) ≠ deadlock detection (HPET) – v0.17.25.
- Open threads (for M17b or later, when measurements show the need):
  - process table (zombies) – 74 s waiting on the test laptop (1% sleeps); per-parent lock,
  - TLB shootdown – 404 k requests, 6.1 M IPIs; only to CPUs that used the address space (mm_cpumask),
  - per-CPU scheduler queues (f3c) – today the scheduler lock waits 2%, not needed,
  - device interrupts spread across cores (today all go to the BSP),
  - the BKL stays for rare paths (exceptions from ring 3, keyboard, `tasks`, address-space reap).
### ✅ M17b – File objects + process memory

**Goal:** foundation for IPC and larger programs.

Steps (as in M17a – each with a test; new code goes straight in without the BKL):
- [x] **a.** (v0.17.28) An fd points to an object: `Fd::File(Arc<OpenFile>)` – copies (dup, dup2, spawn) share
      the position; `dup`, `dup2`, `seek`. FILE TEST 1/3 (`/bin/fdtest`, 24 checks).
- [x] **b.** (v0.17.28) Pipes: `pipe`, 64 KiB buffer, both ends wait, EOF / EPIPE, descriptors closed
      at process exit; shell `a | b | c`. FILE TEST 2/3 (`/bin/pipetest`), 3/3 (shell).
- [x] **c.** (v0.17.29) #PF without IST – from ring 3 on the task stack; kernel stack overflow → #DF (IST),
      ARCH TEST 8/8. USER TEST 4/9 checks that a process #PF has its frame on the task stack.
- [x] **d.** (v0.17.29) Process memory: regions (heap, mmap, stack), pages on first access,
      `brk` / `mmap` / `munmap` (also partial), stack grows up to 8 MiB, process #PF without the BKL; the library
      allocator uses brk / mmap instead of a 256 KiB array in `.bss`. FILE TEST 4/4 (`/bin/memtest`).
      Test laptop (16 threads) (2026-10-08): 47 880 scripts (v0.17.27: 53 809, −11%); KVM 8 CPUs: 38 363 (41 328).
      v0.17.30: "process memory" counters (~0.5 #PF per process – not lazy pages); fault-around measured
      (TCG 1 CPU: 1 page 553, 16 pages 515, old heap in .bss 541) and left at 1. To confirm:
      two test-laptop measurements in a row.
      Test laptop v0.17.30: 45 773 (second measurement after 47 880) – drop confirmed. Per script: the same number of
      scheduler lock acquisitions (~87) and TLB shootdowns (7.5) as in v0.17.27; ~0.4 #PF per process. QEMU TCG 1 CPU
      v0.17.27 vs v0.17.30 – within noise (563/490/551 vs 537/522/512). Bisection on the test laptop:
      `./ab-usb.sh v0.17.27|v0.17.28 /media/...` (old versions in ab/, built in a copy in /tmp).
      A/B on the test laptop (2026-10-09): v0.17.27 – 54 382, v0.17.28 (steps a+b) – 55 834 → file objects and pipes
      are fine; regression in steps c/d (v0.17.29: 47 880, v0.17.30: 45 773). Next: v0.17.29c (v0.17.28 +
      only #PF without IST) and v0.17.30-arena (current kernel, programs with the old 256 KiB heap in .bss).
      Results: v0.17.29c – 51 564, v0.17.30-arena – 47 556 → program heap is innocent; a change in c that
      never runs in the stress test costs ~7% → dependence on variable layout (false sharing).
- [x] **e.** (v0.17.31) Per-CPU data and counters in separate cache lines (`arch/x86_64/percpu.rs`: `PerCpu`,
      `PerCpuCounter`, `CacheLine`); RawSpin, SCHED_OWNER, site-statistics entries – separate lines. QEMU TCG
      1 CPU: 693 scripts (~550), 4 CPUs: 524 (~400–450). Now: the test laptop.
      Test laptop v0.17.31: 50 987 (+11% vs v0.17.30, still ~9% below v0.17.28).
- [x] **f.** (v0.17.32) CPU-time profile of kernel entries (`user/prof.rs`): every syscall, #PF, interrupts,
      switch, reap, parts of `spawn`; `spin wait` table – spinning per spinlock name. Task CPU time is
      computed by the scheduler (TSC always on one CPU) – the test laptop's core TSCs are not synchronized (raw TSC after migration:
      `stat` averaged 64 ms). Version in the autostress lines (`[AUTOSTRESS v0.17.34]`).
- [x] **g.** (v0.17.33) Task stack memory: a finished task's stack stays mapped and is reused at the
      next spawn – no zeroing and no TLB shootdown under the global `stack-pages` (QEMU: 38% CPU). Test laptop:
      shootdowns 373 494 → 476 requests; scripts 49 797 → 51 068 (noise – see h).
- [x] **h.** (v0.17.34) Per-CPU heap free lists (classes 16..2048 B, lock-free); `shrink` without
      walking the list. Test laptop v0.17.32/33: `heap` lock – ~70 M waits of 11 µs each = **83% of the time of all
      CPUs** (a single address-ordered list, first-fit, dealloc walked the whole list twice). **Test laptop v0.17.34:
      360 986 scripts + 180 491 primes (7x)**, `heap` 3% CPU, 32% idle (the stress test limits itself).
      The v0.17.29+ regression was a symptom of this lock (sensitive to the allocation pattern).
- [x] **h2.** (v0.17.35) Before M18: one size rule for small heap blocks (CPU list enabled or not),
      MM TEST 10/10 (list enable threshold), ALLOC TEST 3/4 (block taken on one CPU, freed on another);
      stress in two modes – comparative (default) and full load (`DESOOS_STRESS_POOL=P`).
- Directories via descriptor (open a directory + read entries) – moved to M18/M19, when needed.

**Done when:** ✅ (v0.17.29; test laptop v0.17.34) a program allocates dynamically (e.g. a Rust `Vec` through an allocator
on `mmap`), and the shell supports pipes `a | b`.

---

## Phase 4 – Hybrid

### ✅ M18 – IPC (channels, handles with rights, shared memory)

**Goal:** processes talk safely on many cores – small messages through channels, large data through
shared memory – with a permission model for services (M19), user-space drivers and the future agent.
Design: `ARCHITECTURE.md`, "IPC". Principle: **IPC is control, data goes through shared memory.**

Steps (each with a test; no stress regression vs v0.17.35: 360 713 / 447 028 on the test laptop (16 threads)):
- [x] **a.** Paper design: handles and rights, channels, shared memory, `spawn_ex`, limits, locks,
      syscall numbers (`ARCHITECTURE.md`) – to be reviewed before code.
- [x] **b.** (v0.18.0) Handles with rights: descriptors → handles (object + rights), limit 64, `handle_dup`
      (only reduces), `handle_info`; copies (dup, dup2, spawn) require `DUP`. IPC TEST 1/1
      (`/bin/handletest`, 23 checks); existing tests unchanged (26/26 at 1/2/4 CPUs).
- [x] **c.** (v0.18.1) Channels: `channel_create`, `chan_send`, `chan_recv` (blocking / `NONBLOCK`, full
      queue, buffer too small, other end closed), `kernel/user/channel.rs` modeled on pipes; ABI with
      room for handles from the start (18.d). IPC TEST 2/2 (`/bin/chantest`, 28 checks, ping-pong 10 000 exchanges with
      a child, kill of a child waiting in recv).
- [x] **d.** (v0.18.2) Passing handles in a message (move, `TRANSFER`, both ends of one's own channel
      forbidden, returned on error, `EMFILE` / `EMSGSIZE` without loss) + `spawn_ex` (36) with a handle map.
      IPC TEST 3/3 (`/bin/xfertest`, 32 checks; a child with a single handle receives a file through a channel).
- [x] **e.** (v0.18.3) Shared memory: `shm_create`, `shm_map` (read / write, always NX), `shm_size`,
      whole-region munmap, freed after the last handle and mapping (frames belong to the object – the process
      does not free them); doorbell through a channel. IPC TEST 4/4 (`/bin/shmtest`, 29 checks; verified that without
      `release_shared` the test detects corrupted data).
- [x] **f.** (v0.18.4) IPC in the stress test: `/bin/ipcload` (process pair: 4 KiB through shared memory + doorbell
      through a channel, 200 exchanges, kill of a child waiting in recv) – one per control loop, outside the script pool;
      `ipc:` row in the report. `/bin/ipcbench` (ping-pong 8 B, 4 KiB channel msg/s and MB/s, 16 MiB via channel vs
      shared memory) after autostress; line `[RESULT] ver= mode= cpus= ms= scripts= primes= ipc= idle=
      pingpong_ns= chan_msgs= chan_mbs= chan16_ms= shm16_ms= pass=` – last autostress line
      (`stress-qemu.sh` waits for it). `/bin/ipcdemo` – demo to run by hand. IPC TEST 5/5.
      **Test laptop (2026-10-11):** comparative 392 943 scripts (+9% vs v0.17.35) + 5056 IPC tasks; full
      load 448 079 (447 028); ping-pong 6.6 µs, channel 165–190 k msg/s (645–744 MB/s), 16 MiB via channel
      21–25 ms / via shared memory 5 ms; `pass=1` in both modes.

Moved: replacing the `kcmd` bridge with services → M19; ring buffers → program library on shared
memory (after e); futex → when measurements show a need.

**Done when:** ✅ (v0.18.4, test laptop 2026-10-11) two independent processes talk through a channel and share memory, pass each other handles
with restricted rights, and killing either of them at any moment breaks nothing and leaks nothing.

### ✅ M19 – First user-space service

**Goal:** a device driver as an ordinary process – a crash does not bring the system down, init restarts it, cost
measured. Design: `ARCHITECTURE.md`, "User-space services". Decisions (2026-10-11): first service = `edu`
from QEMU (network – a separate stage later); performance fixes (large heap blocks, process table) – after M19.

Steps (each with a test; no stress regression vs v0.18.4):
- [x] **a.** (2026-10-11) Paper design: `wait_many`, `HW_ROOT` / `dev_claim` / `dev_map`, IRQ, DMA, cleanup after a
      service, service manager, end of `kcmd`, syscall numbers – accepted.
- [x] **b.** (v0.19.0) `wait_many` – waiting on many handles (channels, pipes; IRQ in d), watchers in
      objects. SVC TEST 1/1 (`/bin/waittest`, 34 checks, server with 4 clients).
- [x] **c.** (v0.19.1) `HW_ROOT` for init, `dev_claim` (device owner, refused: in-kernel driver, disks,
      graphics, bridges), `dev_info`, `dev_map` (UC, NX, without the MSI-X table). SVC TEST 2/2 (`/bin/devtest`, 37
      checks on `-device edu`).
- [x] **d.** (v0.19.2) Interrupts: `irq_bind` (MSI vector with release), `irq_read`, `IRQ` signal in `wait_many`.
      SVC TEST 3/3 (`/bin/irqtest`, 25 checks). Test fix: frame-leak baseline after reap.
- [x] **e.** (v0.19.3) DMA: `dma_alloc` (contiguous frames below an address limit), `dma_phys`, buffers live as long as
      the claim; cleanup order: bus mastering off → vector → frames → claim. SVC TEST 4/4
      (`/bin/dmatest`, 23 checks: edu copies a buffer RAM → device → RAM).
- [x] **f.** (v0.19.4) Service `/bin/edud` + `/bin/edutest` on `-device edu` (factorial, interrupts, DMA, 4 clients,
      service kill and restart, clean self-exit). SVC TEST 5/5. Protocol: `user/lib/edu_proto.rs`.
- [x] **g.** (v0.19.5) Service manager in init (table, restart with backoff 100 ms → 5 s, 5 crashes in 30 s = broken,
      connect by name through slot 3 `svc`), `/bin/echod` (a hardware-less service – test on the test laptop), command
      `services`, the shell passes slot 3. SVC TEST 6/6 (`init test /bin/svctest`, 28 checks).
      Variant B for later: a separate `/bin/svcmgr`, minimal init (`ARCHITECTURE.md`, "Service manager").
- [x] **h.** (v0.19.6) Measurement: interrupt → woken driver and factorial via interrupt (kernel vs service in a
      process vs client through `edud`), PING through a service, restart time. SVC TEST 7/7 (`/bin/svcbench` +
      in-kernel edu driver), `[RESULT-SVC]` line in `test.sh` (in autostress edu is held by `edud` from init).
- [x] **i.** (v0.19.7) End of the `kcmd` bridge: syscall 46 `sysinfo` (read-only), 47 `sysctl` (reboot, halt,
      sync, stress) only with a `SYSCTL` handle (kernel → init → shell, no further); `mkfs`, disk writes and `run`
      only in the kernel's emergency shell. Tests: INIT TEST 4/9, svctest (42 checks).
- [x] Close-out (v0.19.7, test laptop 2026-10-11): compare 388 883 scripts (M18: 392 943), max6 443 666 (M18: 448 079) –
      within noise (−1%); ping-pong 6.55 / 6.75 µs, `pass=1`. Under full load the process-table cost is visible
      (lock "process table (zombies)": 168 s of waiting in total on 16 CPUs) – next step.

**Done when:** ✅ (v0.19.7, test laptop 2026-10-11) a user-space driver handles a device (MMIO, interrupts, DMA), killing it at any
moment breaks nothing and leaks nothing, init restarts it, and the overhead is measured.

### ✅ P – Performance fixes (after M19; P1–P3 closed 2026-10-12, P4 for later)

Based on measurements from the test laptop (v0.19.7, full load, 16 CPUs). Each step: tests + test laptop with no regression.
- [x] **P1.** ✅ (v0.20.2, test laptop: compare 394 272 / max6 447 314 – +1.4% / +0.8%, zombie lock gone, scheduler
      in max6 13.1 → 6.3 s of waiting) (v0.20.0) Zombies in the parent process instead of a global table under a sleeping lock ("process
      table (zombies)": 12.3 M acquisitions, 168 s of waiting per minute). Test: NOBKL TEST 10/10 (`/bin/famtest` under
      real init: 200 children at once, wait(pid), WNOHANG, 200 orphans to init, 4 parents in parallel).
      v0.20.1: 4 entries in the process (no allocation). v0.20.2: the real cause of +50% heap waits –
      `IrqSpinLock` (alignment 64) in `Process` pushed every process onto the heap slow path; a custom lightweight
      lock + assertion (`Process` ≤ 2 KiB, alignment ≤ 16).
- [x] **P2.** ✅ (v0.21.0) Heap slow path: per-CPU list classes up to 32 KiB (measured: 96% of slow-path allocations
      are 2–32 KiB blocks). Test laptop: compare 412 608 (+4.7%), max6 473 223 (+5.8%); heap waits −90%,
      heap CPU 6–7.5% → 0.4–0.6%. KVM: 177 373 (record). For later: 32–128 KiB blocks, 64 B alignment.
- [x] **P3.** ✅ (v0.22.0) Frame allocator: a reserve of 64 frames per CPU (batches of 32) + atomic "allocated" bitmap (lock-free
      double-free detection). ALLOC TEST 4/5. Test laptop: compare 436 134 (+5.7%), max6 528 869 (+11.8%); "frames" 48–60 M
      waits → ~20 k, spawn 48 → 25 µs. Stage P since M18: +11% / +18%.
- [x] **P4.** ✅ (v0.33.0) Scheduler lock – test laptop: waiting 18.9 s → ~4.6 s, stress 432 210 → **534 072 (+23.6%)**
      (biggest gain: spinning before `hlt`, v0.32.2). v0.34.0: spin window tuned per CPU (0–200 µs) + wakeup
      without IPI for a spinning CPU – test laptop A/B: tuned 200 → 535 827, fixed 200 → 535 300, fixed 50 → 534 027,
      fixed 20 → 536 961 (differences within noise, ~0.5%). Tuned stays (equally fast, no spinning when idle);
      ~75% of wakeups without IPI, ping-pong 5.0 → 4.35 µs.
      Full load (max6, v0.34.1): **533 725** (v0.22.0: 528 869) – the stress test now limits itself
      (`stress-counter` spinlock 7.9% CPU).
      v0.34.3: lighter spinlock test in the stress test → test laptop compare **599 726**, max6 **593 119** (new baseline).
      Plan and progress (2026-10-14; design: `ARCHITECTURE.md`, "Scheduler – P4"). Test laptop v0.29.0:
      40.1 M acquisitions in 60 s, 41% wait, 18.9 s of waiting; held ~16 s out of 60 s in total (one global lock busy
      ~27% of the time). Acquisitions: `with_process` 11.1 M, `wait_event` 10.6 M, `wake_channel` 7.6 M, `exit` and
      `spawn_in` 3.3 M each, `reap` 1.6 M, `task_exists` 1.0 M. Hold time: `wait_event` 6.3 s, `exit` 3.4 s –
      both end with a task switch (FXSAVE/FXRSTOR, CR3, stack) UNDER the lock.
  - [x] **a.** Paper design (this description + ARCHITECTURE.md; comparison with Linux, Redox, FreeBSD ULE,
        BFS/MuQSS – 2026-10-14).
  - [ ] **0.** (v0.30.0) The scheduler lock waits with plain reads (test-and-test-and-set) instead of compare_exchange on
        every spin – as regular spinlocks already do; the same in the zombie-list lock and the TLB
        shootdown initiator lock. Test laptop: waiting **18.9 → 14.3 s (−25%)**, still 41% of acquisitions wait; wait_event 5.4 → 4.0 s,
        with_process 4.9 → 3.7 s, wake_channel 4.2 → 3.4 s; stress 423 575 (v0.29.0: 432 210 – within spread,
        no gain). KVM 8 CPUs: unchanged (16%, ~1.1 s). Conclusion: the main cost is HOLD time – steps b and c.
  - [ ] **b.** (v0.31.0) Task table (`tasks` + `ids`) under its own RW lock "task table": `with_process`,
        `task_exists`, `children_of`, `for_each_process` – read (in parallel, without the scheduler lock); spawn / idle /
        reap – write (under the scheduler lock, order scheduler → table); `reparent_with` – write. `dead` mirror,
        task liveness marker. SMP TEST 6/6 (readers on 3 CPUs during spawn / exit / reap; mutation without the write in
        reap – detected 2/2). Measurement for c: line `scheduler lock: task switches under it …` (QEMU TCG: 51% of
        hold time is the switch itself). v0.31.1: test fix (KVM). KVM 8 CPUs: scheduler lock acquisitions
        16.2 → 11.5 M (−29%), switching = 43% of hold time (775 ns). Test laptop (v0.31.1): acquisitions 39.6 →
        **27.2 M (−31%)**, waiting 14.3 → **11.1 s** (v0.29.0: 18.9 s), still 41% wait; switching = **36%**
        of hold time (5.6 s of 15.4 s, 624 ns); table: 11.6 M reads + 5.0 M writes, 22 ms of waiting;
        but `spawn_in` holds the lock 1.0 → 1.6 s, `reap` 1.0 → 1.3 s (table write under the scheduler lock);
        stress 416 610 (v0.30.0: 423 575, v0.29.0: 432 210) – no gain.
  - [ ] **c.** (v0.32.0) Scheduler lock released BEFORE the switch: `on_cpu` flag (set on selection,
        cleared by the next task after the switch – `finish_switch`); a CPU that picked a task still
        leaving another CPU waits for the flag to clear (under the lock, without the other side waiting for it); reap
        skips tasks with `on_cpu`; FPU / CR3 / stack / sched_switch now without the lock; guards from before the switch
        release nothing after return (`SCHED_SKIP`) – no more carrying the lock across the switch. SMP TEST
        7/7 (4 pairs of tasks waking each other on different CPUs + short tasks exiting alongside; lost
        wakeup = FAIL); mutation without waiting on `on_cpu` – the kernel crashes immediately (SMP TEST 3). Report: line
        `scheduler: N task switches outside the lock, M waited …`. Test laptop: waiting **3.7 s** (since P4.0: 18.9 s, −80%),
        32% wait, hold ~10.1 s; but stress 409 018 (falling since v0.29.0: −5%), idle 32%, lost ticks 379 –
        v0.32.1: diagnostics + A/B with v0.29.0: test laptop 434 178 vs 412 946 (−4.9%, not from the lock – longest wait
        65 µs), KVM 16 CPUs 342 392 vs 346 764 (+1.3%). v0.32.2: spinning before `hlt` (`DESOOS_IDLE_POLL_US`,
        hypothesis: waking a sleeping core on hardware). ✅ **Test laptop A/B: 0 µs – 412 315, 50 µs – 534 072 (+29.5%),
        idle 32% → 7%** – record (v0.29.0: 434 178). For further steps: tuning the time (20/100/200 µs), no IPI to
        a spinning CPU, max6 on the test laptop, effect on battery power draw.
  - [ ] **d.** Only if the test laptop still waits after 0–c or with > 16 CPUs (BFS with a single queue scaled to ~16):
        per-CPU queues like FreeBSD ULE (an idle CPU steals a task from the busiest one + rare balancing),
        selection like MuQSS (trylock, busy queue – next one), wakeup on another CPU like Linux (wake list + IPI,
        without locking the foreign queue), sleepers under separate locks; access to processes via `Arc`.
  - [ ] **e.** Measurement and close-out: test laptop (compare, max6), `cpus` – waiting on the scheduler lock.
      Heap in max6: 1.1 M waits (1%) – P2b (32–128 KiB blocks) optional.

### Security (after an external code review and a ChatGPT review, 2026-10-17)

Before networking: no program (buggy or malicious) may bring down the kernel or exhaust all resources.
- [x] **1.** (v0.35.0) Audit of argument arithmetic in all system calls (no new bugs; the previous one –
      `mmap`, v0.34.2) + fuzzer `/bin/sysfuzz` in the self-tests: random calls with extreme arguments from children without
      handles + corrupted ELF files. Long run: ~1 M calls, 2000 ELFs – the kernel survived.
- [x] **2.** (v0.35.1) No handle cycles: a channel end with a channel in its own queue cannot be sent (EBUSY); xfertest
      43 checks + live-channel counter in the kernel (0 leaks).
- [x] **3.** (v0.35.2) Limits: 1024 processes (the last 64 only for init and its children – shell, services), memory reserve
      for the kernel only (1/16 of RAM, 16–256 MiB; process pages and shared memory above it), IPC buffer budget 16 MiB
      (channels + pipes, ENOMEM), ramfs 24 MiB (ENOSPC; along the way: a far `seek` + write crashed the kernel). FILE TEST 6/6
      (`/bin/limtest`: fork bomb, shm, memory hog, ramfs, IPC – 17 checks). Test laptop: compare 600 637, max6
      593 350 (unchanged vs v0.34.3), 0 refusals in normal operation. **Stage closed.**

### N – Network (plan 2026-10-18)

**Goal:** DeSoOS on the network – ping, DNS, TCP client (`fetch`), then a server – with the driver and the whole
stack in a user-space service `/bin/netd` (like usbd) and network access as a capability. Design:
`ARCHITECTURE.md`, "Network".
- [x] **N1.** Design: netd per card, `net` / `net-listen` capabilities through init, sockets as channels with
      rights, message protocol, event loop, loopback, tests.
- [x] **N2.** (v0.37.0) Card driver in `/bin/netd` (QEMU e1000e / e1000): reset, MAC, rx/tx rings (legacy
      descriptors, one 136 KiB DMA buffer), MSI; `netN` services in init (class 020000, "no driver" for other chips –
      the test laptop's Realtek until N8); frame counters; `ifconfig`, `arping` (ARP probe – first real frame out
      and back). NET TEST: ARP to QEMU's router, kill + restart by init, card / MSI / DMA returned.
- [x] **N3.** (v0.38.0) Ethernet + ARP + IPv4 + ICMP: `ping 10.0.2.2`. Parsers in `user/lib/netproto.rs` (pure
      code, every malformed frame → error); ARP cache (16, 60 s), answers to ARP and pings for our address,
      next hop on the subnet or via the gateway; static 10.0.2.15/24 (DHCP in N4). NET TEST `/bin/netparse`
      (20 malicious frames, 20 000 mutations), nettest: ping 3/3, unreachable host, bad address, 0 malformed.
- [x] **N4.** (v0.39.0) UDP + DHCP client: address, gateway and DNS from the network; `ifconfig` shows the lease,
      `ifconfig renew`. Client as a pure state machine (`user/lib/dhcp.rs`): selecting, requesting, bound,
      renewing (T1), rebinding (T2), lease end, NAK; untrusted answers checked. NET TEST 2/4 `/bin/dhcptest`
      (54 checks, a simulated day of lease), netparse + UDP/DHCP (37 malicious cases), nettest 24 checks.
- [x] **N5.** (v0.40.0) DNS resolver: `ping <name>`, `host <name>`; cache (TTL, negative answers), CNAME, answers
      checked (random id and port, backward-only pointers, our question). netd without waiting: one operation per
      connection, many programs at once. `ifconfig dns`. NET TEST 3/5 `/bin/dnstest` (19 malicious answers,
      20 000 mutations); `tests/dns-stub.py` – a test DNS server on the host; nettest 46 checks (no internet
      needed). Known gap: any client may change the DNS server until N7.
- [x] **N6.** (v0.41.0) TCP client: `fetch http://...`. Connection as a pure state machine (`user/lib/tcp.rs`):
      windows, congestion control, RTO + fast retransmit, zero-window probe, all closing paths, RFC 5961 checks.
      The netd connection is the socket. NET TEST 4/6 `/bin/tcptest` (57 checks, 20 000 random segments);
      `tests/http-stub.py` on the host; nettest 61 checks (1 MiB with a pattern, cut / reset pages, refused,
      a program leaving mid-download). Loopback moved to N7 (needs a listener).
- [x] **N7.** (v0.42.0) Servers: TCP server side, `listen port` (accepted connections arrive as new channels),
      loopback (127.0.0.1 and our own address), `httpd` (page from stdin), QEMU port forwarding – a server in DeSoOS
      reached from the host. Rights: init's narrowed service channels (`svc_narrow`), `nofiles --net` /
      `nofiles --listen`; netd checks listen / admin per connection. tcptest 67, nettest 85 (host -> sandboxed
      httpd through tests/http-stub.py `/connect`). Gap: unsandboxed shell programs still have admin.
- [x] **Before N8** (v0.43.0): addresses checked with ARP before use (DHCP: DECLINE on a conflict), conflicts
      reported, RELEASE when switching to a fixed address and when netd ends, `ifconfig set a.b.c.d/nn gw ... dns ...`
      / `ifconfig dhcp`. dhcptest 68, nettest 96.
- [x] **N8** (v0.44.0–v0.45.1). Real hardware: RTL8111/8168 driver; ping and fetch on the test laptop over a
      cable; throughput. 8168g/8168h bring-up, registers in BAR 2, diagnostics in `ifconfig`; the receive ring set
      up again after start (the card kept a stale ring from the firmware); interrupts masked while acknowledged
      and re-armed. On the test laptop: DHCP from the home router, ping < 1 ms, fetch from the internet; 10 MiB from
      the UK in 3.9 s (**2643 KiB/s**, was 178 KiB/s with an 8 KiB window) after TCP window scaling, a 256 KiB
      receive ring and 256-descriptor card rings; no loss, no resends.
- Later: packet fuzzer extensions, IPv6, TLS (needs cryptography), USB Ethernet, Wi-Fi (maybe never).

### Permissions – DCP (before networking, 2026-10-18)

DeSoOS's own model instead of Linux users/`rwx` or Windows ACLs: a process may do exactly what its handles allow
(capabilities). Rights per handle (reduce-only, enforced in syscalls, `DUP` / `TRANSFER`) exist since M17/M19.
- [x] **1.** (v0.36.0) View: `secinfo` and `caps <pid>` (replaced by `dcp` in step 3). Published per-slot summaries in atomics – no lock on the hot path.
- [x] **2.** (v0.36.1) File sandbox: `SPAWN_NO_FILES` – `open`, `stat`, `readdir`, `mkdir`, `unlink`, `chdir`,
      `spawn`, `spawn_ex` give `EACCES` (one check before decoding); inherited, cannot be dropped; handles passed in
      work with their rights. Shell `nofiles <program>`; half of the `sysfuzz` children in it; `secinfo` shows `none`.
      FILE TEST 7/7 (`/bin/sandtest`: 18 escape attempts and permission checks in the sandboxed child).
      A sandboxed process cannot start programs (no spawn by path) – spawning from a handle comes with the manifest.
- [x] **3.** (v0.36.2) One command `dcp` with DCP names (`dcp`, `dcp inspect <pid>`, `dcp audit`); `caps` and
      `secinfo` removed. View limited to own process and descendants (all with `SYS_POWER`). Audit log of the last
      64 refusals. Tests: missing / exited pid, a child cannot see its parent, inspection during handle churn on
      another CPU, refusals of the sandboxed child in the audit. **Stage closed.**
- [ ] Then networking: the network service and sockets as handles with their own rights (send, receive, listen,
      transfer).
- Later: sandbox limited to one directory, a manifest for init (what each service gets), full file capabilities
  (directory handles instead of global paths).

### Clock gaps (v0.35.3–v0.35.5, 2026-10-18)

- [x] Diagnostics for long gaps between PIT interrupts (up to ~40 ms on the test laptop): gap log in `cpus` (start,
      length, other interrupts on CPU 0), NMI probe from another CPU (RIP, IF, return addresses), `lsusb -v` with the
      xHCI BIOS handoff timing. Result: the two long gaps (33 ms, 40 ms) start exactly with the BIOS→OS handoff of the
      two AMD xHCI controllers – firmware SMI, not the kernel; the ticks are caught up from the HPET. Nothing to fix.

### ✅ M20 – USB (plan 2026-10-12, done 2026-10-14, v0.29.1)

**Goal:** DeSoOS on hardware without PS/2 – on the test laptop (16 threads) the built-in keyboard works (USB HID, ITE 8910, AMD xHCI
05:00.x), plus a USB mouse and reading a USB stick. The second real user-space driver (after `edu`) and the first one that
working on the computer depends on. Design: `ARCHITECTURE.md`, "USB" (written in step a).

**Decision: USB in user space** (based on the M19 measurement: interrupt → driver in a process 31.9 µs, in the kernel
32.6 µs; intermediary +~29 µs – the keyboard produces an event every ~10 ms, a USB stick waits for a 125 µs microframe anyway):
- `/bin/usbd` – an init service, **one per controller** xHCI (found by class 0C03/30, not by a fixed BDF);
  uses M19: `dev_claim`, `dev_map`, `irq_bind` (MSI-X), `dma_alloc` / `dma_phys`, `wait_many`.
- The kernel gets only what it must: **input** (`INPUT` handle → `input_inject` → `kernel/input.rs`; console,
  shell and `keys` unchanged) and **disk** (`ublk` – a BlockDevice in the kernel; request via channel, data via shared
  memory – the M18 principle). Permissions as with `SYSCTL`: init gives the handles only to usbd.
- A usbd crash = service restart (backoff from M19), not a panic. The price: the kernel's emergency shell has a USB keyboard only
  while usbd is alive (PS/2 unchanged).
- **USB stick read-only** – three independent locks: usbd has no SCSI write command at all, `ublk`
  reports `read_only` and rejects writes, the FS mounts read-only. The boot USB stick is not needed after the kernel
  starts (initrd in memory), so the xHCI reset does not harm it.

Steps (each with a test; no stress regression vs v0.22.0: 436 134 / 528 869 on the test laptop):
- [x] **a.** (2026-10-12, accepted) Paper design (`ARCHITECTURE.md`, "USB (M20 – projekt 20.a)"):
      - **DMA without IOMMU** – explicitly: usbd itself writes physical addresses into xHCI structures, the kernel does not check them;
        process isolation protects against crashes and hangs, not against rogue DMA. AMD-Vi – a separate stage later.
      - **ublk** – request identifier, timeout, rejection of late replies, an owner for every buffer
        slot at every moment (also after usbd dies and after a timeout); per-disk lock in the block layer
        (today one global – waiting on USB would stall NVMe); the disk disappears on unplug (EIO, `umount`).
      - **Enumeration** as a port state machine: a timeout for every state, limits (devices, endpoints,
        descriptor length, hub depth), after an error the port returns to its initial state.
      - **Descriptor parser** in a separate library, tests of malformed and malicious data without hardware.
      - **usbd restart** – a message on screen and COM1, release of held keys, controlled return
        of the keyboard; after 5 crashes a clear "USB disabled" message.
      - **Permissions and cleanup from M19 without duplication** – `dev_claim`, DMA cleanup order, leak
        tests (frames, handles, vectors) used the same way; new `INPUT` / `BLK` handles like `SYSCTL`.
      - Syscall numbers (48+) and handle kinds (10+) without collisions; every protocol with errors, timeouts,
        memory ownership and behavior after the service dies.
- [x] **b.** (v0.23.0) xHCI startup in usbd: init finds controllers by class and starts `usb0`, `usb1`…;
      BIOS handoff (USBLEGSUP), reset, DCBAA, scratchpad buffers, command and event rings, MSI-X,
      No-Op command. USB TEST 1 (`qemu-xhci`); on the test laptop `services` shows the USB services.
      Done: `dev_find` (48), init starts `usbN` by class, usbd: BIOS handoff, reset, rings, MSI,
      No-Op, ports. USB TEST 1/2 + 2/2 (kill during commands, full reset, nothing leaks); QEMU 28/28.
      Test laptop (2026-10-12): 3 controllers (NVIDIA USB-C + 2 × AMD), BIOS handed over, No-Op 5 µs (AMD), 4 devices
      connected; stress compare 436 765 (no regression).
- [x] **c.** (v0.24.0) Ports and enumeration: port state machine (100 ms debounce, USB 2 port reset, timeouts, 3 attempts,
      then ignored until unplug), Enable Slot, Address Device, Evaluate Context (EP0 packet size),
      device and configuration descriptors, strings; unplug = Disable Slot + pages returned; STALL → Reset
      Endpoint + Set TR Dequeue. Parser `user/lib/usb_desc.rs` + `/bin/usbparse` (malicious cases, 10 000 mutations).
      Command `lsusb`. Set Configuration moved to e/f (together with endpoints). USB TEST 1/3 (parser), 2/3
      (`usb-kbd`, `usb-mouse`, `usb-storage`: 3 devices with classes and names; kill during enumeration), 3/3.
      Test laptop (2026-10-12): 7 devices, 0 errors – ITE keyboard 048d:c100 (03/01/01) on usb2 port 4 directly,
      Intel Bluetooth, camera, USB stick, Genesys hub (USB 2 + USB 3); stress compare 434 021 (no regression).
      Order: the keyboard is not behind a hub → e first, then d.
- [x] **d.** (v0.27.0) USB 2 and 3 hubs (also hub behind hub, up to 5 levels): usbd – port status-change endpoint,
      Set Configuration, Set Hub Depth (USB 3), hub descriptor, a second Configure Endpoint with hub fields (Hub bit,
      number of ports, TT think time), port power; hub ports in the same state machine as controller ports
      (GET_STATUS, CLEAR_FEATURE of changes, hub port reset, 3 attempts); device behind a hub: route string, controller
      port of the top-level hub, speed from the hub port, TT (slot and port of the nearest high-speed hub) for low /
      full speed behind a USB 2 hub. Hub unplug = unplug of everything behind it. `lsusb`: "port 3.2".
      Tests: USB TEST 2/6 and 5/6 – mouse and test USB stick behind a QEMU hub (`usb-hub`), 6/6 – hot-plugging
      (QEMU monitor via `qemu-hotplug.py`: disk behind hub removed → unmounted, inserted → mounted, whole hub
      removed → hub, mouse and disk disappear, nothing leaks). `HUB=1 ./run-qemu.sh`. QEMU 28/28 (1 and 4 CPUs).
      **Test laptop (v0.27.0): Genesys hubs 0610 (USB 2, 2 ports) and 0620 (USB 3, 2 ports) work; G502 full-speed mouse
      behind a high-speed hub (TT) – works; 59 GB SuperSpeed USB stick behind a USB 3 hub → /usb1, hot removal / insertion;
      stress 431 338. Port 1.1 – Address Device failed: a charging cable without a phone (a device that does not respond) – correctly ignored.**
- [x] **e.** (v0.25.0, before d – the test laptop's keyboard is not behind a hub) HID: keyboard and mouse in boot protocol –
      usbd: Configure Endpoint (interrupt IN), Set Configuration, Set Protocol (boot), Set Idle, 8 TRBs for reports,
      report diff → HID usage events; kernel: `INPUT` handle (kind 10, init slot 5, every copy = a separate
      source), syscall 49 `input_inject`, HID → KeyCode table, **autorepeat in the kernel** (500 ms, ~30/s), release of
      keys of a killed source (tick under the BKL), LEDs (Set Report). Mouse: the wheel scrolls the console. `USB=1 ./run-qemu.sh`
      (without 8042). USB TEST 2/4 (HID configured, reports via interrupt endpoints – Set Idle), 3/4 (`/bin/inputtest`:
      rights, "hiA", autorepeat, Caps Lock, release after kill; "no release" mutation – detected), 4/4 (init → usbd
      gets INPUT). QEMU with `sendkey` and without 8042: typing, AltGr (ś), autorepeat – work.
      v0.25.1: fix for a false lockdep PANIC (usbd MSI during stress; in an interrupt, ordering only relative to
      interrupt locks), autorepeat in the kernel task `input-repeat` instead of the tick.
      **Test laptop (v0.25.1): the built-in keyboard works in the shell – for the first time** (`help`, `lsusb`); Caps Lock,
      Polish characters (AltGr: ąęśż…) and `echo` work; stress compare 431 023, `pass=1`.
- [x] **f.** (v0.26.0, before d – the test laptop's USB stick is not behind a hub either) Mass storage READ-ONLY:
      usbd: interface 08/06/50, bulk endpoints (TRBs split at 64 KiB boundaries), Bulk-Only (CBW / data / CSW,
      Clear Halt after STALL, reset recovery), SCSI only from a list: INQUIRY, TEST UNIT READY, REQUEST SENSE,
      READ CAPACITY(10), READ(10) (compile-time assertion: no write command). Kernel: `BLK` handle (kind
      11, init slot 6), syscall 50 `blk_attach` (channel + DMA buffer 4 × 64 KiB), `ublk` = disk "sdX" (request ids,
      5 s timeout → slot quarantine, a late reply frees the slot, foreign / bad replies rejected, 3
      timeouts / usbd exit / removal = disk disappears), task `usb-disks` (GPT / MBR, FAT32 → `/usb0`…, on
      disappearance unmount and removal), **per-disk lock** in the block layer (was: one global),
      `ChanEnd::recv_timeout`, FAT32 on a read-only disk rejects changes immediately, `open` for writing → EROFS.
      Tests: USB TEST 2/5 (2 USB sticks, mounting, kill usbd → disk disappears and comes back), 3/5 (`/bin/blktest` pretends to be
      usbd: blk_attach errors, 2 read requests, rejected replies, timeout + quarantine, another disk does not
      wait, EIO, write rejected, 3 timeouts → disk removed), 5/5 (init: files from `/usb0` = `/bin`, 4 MiB pattern,
      write / rm / mkdir → EROFS). Test image: `mkfat32.py` (no mtools or sudo). QEMU 28/28 (1 and 4 CPUs).
      **Test laptop (v0.26.2): boot USB stick "Wilk" (SuperSpeed) = sda → `/usb0` (FAT32 'NOSNIK USB'), `ls`, `df`,
      write → EROFS; stress compare 434 164 (no regression).**
- [x] **g.** (v0.28.0) Robustness: **a hung USB stick does not stall the rest of the VFS** (FAT32 on a USB disk under its own
      lock – `fs::Locked`, called like `ConcurrentFs` under FS_LOCK for reading; `mount`, `open`, `df` without waiting for the
      disk); kill usbd during a file read → the reader gets EIO within a few ms, init restarts usbd (message
      "USB keyboard and disks back in a moment"), disk and keyboard come back; 5 crashes in 30 s → broken + message
      "USB controller usbN disabled … (PS/2 still works)", controller released; **USB stick removed from the hub during a
      read** – bulk transfer aborted immediately by the hub port change (was: 4 s timeout + reset recovery → kernel
      timeout 5 s), the reader gets an error in ~12 ms; autostress reads the largest file from /usbN during the stress test
      (checksum of every pass – all equal; `usb_mib`, `usb_kbs`, `usb_err`, `usb_bad` in [RESULT]).
      USB TEST 6/7 (hung disk + kill + restart + broken) and 7/7 (removal during read). QEMU 28/28 (1 and 4 CPUs).
      **Test laptop (v0.28.0): stress compare 436 488 (no regression, despite reading the USB stick in the background), boot USB stick
      read during the stress test: 268 MiB, 4586 KiB/s, 134 full passes – all identical, 0 errors; USB stick
      removed during `cat /usb1/…` → `I/O error`, `sdb: removed, /usb1 unmounted`, no hang; typing during
      the stress test works.** One note: once `port 5.1` (SuperSpeed behind a USB 3 hub) – `INQUIRY failed` → for h.
- [x] **h.** (v0.29.0) Measurement and close-out: **faster FAT32** (FAT in 4 KiB blocks, cluster cache – path directories
      are not read on every read, contiguous clusters in one read, 64 KiB read-ahead,
      remembered position in the chain), **pipelined ublk** (up to 4 requests at once), **`df`** counts free space from the FAT (FSInfo is sometimes
      stale), **INQUIRY up to 4 attempts**; measurements: device enumeration time (usbd, "ready in N ms"), USB
      keyboard latency (xHCI interrupt → character in the kernel), reads with a 256 KiB / 4 KiB buffer – `[RESULT-USB]` in `test.sh` and
      in autostress. QEMU (TCG): reading 4 MiB from a USB stick via usbtest **716 → 70 620 KiB/s**, kernel 256 KiB:
      74 369 KiB/s, 4 KiB (like `cat`): 36 957 KiB/s; enumeration avg 23 ms / max 49 ms; keyboard avg 535 µs.
      QEMU 28/28 (1 and 4 CPUs); KVM: 106 MB/s, keyboard 229 µs.
      **Test laptop (v0.29.0): boot USB stick (SuperSpeed) before the stress test 121 640 KiB/s with a 256 KiB buffer and 125 365 KiB/s
      with a 4 KiB buffer (v0.28.0: ~4.5 MB/s under stress); during the stress test 52 140 KiB/s, 1519 identical passes;
      keyboard: 37 key presses, interrupt → character avg 275 µs (min 28, max 695); enumeration 2–201 ms (hub 201 ms);
      stress compare 432 210 (v0.28.0: 436 488 – −1%, 3 GiB from the USB stick in the background), pass=1; `df`: /usb0 2.0 MiB used
      (= BOOTX64.EFI 2.0 MiB), /usb1 25 651 MiB of 59 117 MiB.** The 59 GB USB stick in a USB 3 hub enumerated as high
      speed on `port 1.1` (the USB 2 part of that hub) – works; SuperSpeed behind a hub verified in v0.27.0.

For later (outside M20): writing to USB sticks (a separate decision, after a native FS), UAS, USB audio / network / isochronous
transfers, touchpad via I2C-HID (if the test laptop has it on I2C), emergency USB keyboard in the kernel (polling
when usbd is not running), full HID report descriptors (multimedia keys).

**Done when:** on the test laptop the built-in keyboard works in the shell, a USB stick can be read (read-only),
killing usbd at any moment breaks nothing and leaks nothing, init restarts it and the keyboard
comes back, and the stress test does not regress.

---

## Next (in no particular order)

native file system, networking (TCP/IP), GUI (compositor on shared memory), audio,
virtio-gpu, XSAVE/AVX, IOMMU, shared libraries, service manager as a separate program (`/bin/svcmgr`, variant B from M19).

**DeSo AI agent** (vision, `ARCHITECTURE.md` – "Direction: DeSo AI agent"): `.eso` application format (ELF + manifest:
version, required handles, source hash), reproducible builds, the agent as an ordinary user-space program with
handles from the user, exchanging patches between computers; kernel changes are approved by a human after
reviewing the diff. Requires: services (M19), networking, VFS isolation for the sandbox, signatures.

---

## Known gaps

Number in parentheses = the stage in which the gap goes away.

**Memory**
- splitting a 2 MiB direct-map page (map_mmio) is one-way – 4 KiB pages are not merged back later
- the heap shrinks only from the end; large blocks (> 2 KiB) still under a single heap lock (address-ordered list, first-fit)
- core TSCs are not synchronized (test laptop) – times measured on a single CPU (statistics, profile); no TSC synchronization
- frame allocator: `alloc_frames(n)` is linear; no "below 4 GiB" zone for 32-bit DMA
- PML4[256..512) allocated from the start (~1 MiB of empty PDPTs) – the kernel will not add a new entry later
- DSB page tables and LOADER_DATA/BOOT_SERVICES memory are not returned to the allocator
- direct map max 512 GiB RAM (the kernel has room for 64 TiB)
- kernel image without NX (only code is RO) – together with DSB

**Processes and syscalls**
- `spawn` instead of `fork`/`exec`; no environment variables or signals (kill = process exit)
- system actions (`sysctl`) behind a single `SYSCTL` handle – no split into reboot / sync / stress; disk changes only from the kernel's emergency shell
- PID = scheduler task number (0 = BSP idle, 1 = kernel startup task, then the idle tasks of the other cores – with 4 CPUs init has PID 5)
- shell: line max ~70 characters (fits in 80 columns), no scripts, variables or `$?`
- no directories via descriptor (readdir by path)
- IPC: no futex and no ring buffers in the library
- ELF: only static ET_EXEC, envp and auxv empty
- programs from `/bin` built into the kernel image (initrd); the asm test programs (M13–M14) too (since M19.i only from the kernel's emergency shell: `run <nazwa>`)
- limits (v0.35.2) are global, not per user: 1024 processes, kernel memory reserve, 16 MiB of IPC buffers, 24 MiB ramfs; kernel heap 64 MiB
- `read(0)` reads a whole line; background processes compete with the shell for the keyboard (`readkey`/`read` – first come, first served)

**Scheduler and concurrency**
- TLB shootdown only for the upper half (kernel); process address spaces rely on processes being single-threaded (threads – later)
- device interrupts only to the BSP; no priorities or balancing (a task takes the first free CPU)
- on laptops the firmware stops the machine (SMI) for 30–70 ms while each xHCI controller is handed over at boot,
  and for ~2 ms now and then later; PIT ticks are caught up from the HPET
- CPU time on APs is sampled (the LAPIC tick every 10 ms assigns 10 ms to the task that happens to be running)
- at most 16 CPUs (Ryzen 7 4800H = 16 threads); SMP requires RDTSCP, MADT and I/O APIC
- no priorities; `kill` of a kernel task is cooperative (the task itself checks `should_exit`)
- kernel without preemption in the middle of a syscall (only sleeping locks)

**Hardware**
- INTx interrupts on real hardware: a device's IRQ line requires ACPI AML (_PRT) – drivers use MSI/MSI-X
- block layer: one operation across all disks at a time (global lock) – NVMe queues the commands of one request, different tasks wait in turn (M17a)
- virtio-blk: copying through a 64 KiB DMA buffer, only the first virtio disk; NVMe: 128 KiB buffer (copying)
- NVMe: one I/O queue pair, first active namespace, no metadata; a real SSD is read-only (deliberately)
- GPT: read-only; MBR – only via FAT32 (first FAT32 partition); FAT32 only with 512 B sectors (an ESP on a 4Kn disk will not mount)
- without a serial port, logs only on screen (status bar in the top-right corner: time, keyboard)
- USB keyboard only via usbd (user space): a dead usbd = no keyboard until init restarts it
- USB keyboard and mouse only in boot protocol (no multimedia keys); the test laptop's touchpad is unsupported
- USB stick read-only (deliberately), 512 / 4096 B blocks, ≤ 2 TiB, LUN 0, no UAS
- hubs: single TT only (no Multi-TT), no port power management (suspend / LPM), TT tested only on
  real hardware (QEMU has a full-speed hub – no TT)
- FAT32 reads cluster by cluster (USB stick with 512 B clusters: a few hundred KiB/s in QEMU) – faster in M20.h
- IDT: ISA vectors (0x20–0x2F, via I/O APIC), MSI (0x30–0x3F), LAPIC timer / IPI (0x40–0x42), spurious (0xFF); #BP has DPL 3
- FPU: FXSAVE only, no AVX; QEMU TCG does not raise #XM
- mouse (PS/2 and USB) only for console scrolling; system autorepeat only for USB (PS/2 – hardware)
- hard-coded keyboard layout (Polish programmer's)

**Files**
- FAT32: no GPT, FAT12/16, sectors ≠ 512 B; files max 4 GiB; `mv` of directories not implemented; times in UTC
- one lock for the whole VFS (M17a)
- OVMF (QEMU firmware) writes NvVars to the first FAT – also to `/disk` or the ESP of the NVMe disk (firmware behavior, not DeSoOS; `build/` has been read-only since M16b)

**Console**
- scrollback 1000 lines, shell line max 71 characters, font with 234 glyphs (the rest shown as `?`)
- M1–M4 logs only on serial; if serial is blocked, serial output is lost

**Tests**
- recovery procedure in `exceptions.rs` (`RESUME_RIP`, `probe_read`) only for tests
