# DeSoOS Changelog

Format: newest on top. Dates in Central European time.

## v0.35.5 — 2026-10-18

### Clock gaps: is it the USB BIOS handoff?
- Test laptop, v0.35.4: again 4 gaps, all during boot – from 362 ms (17.2 ms, 1 other interrupt), **from 379 ms
  (40.2 ms, 0 other interrupts, not probed)**, 1241 ms (2.5 ms) and 1836 ms (2.1 ms); none during the stress.
  The probe NMI did not get in during the 40 ms gap – NMIs are held back only while CPU 0 is already in an NMI or in
  firmware System Management Mode, and an SMI stops all CPUs. Together with v0.35.3 (the NMI landed right at an MSI
  stub, i.e. right after both were held back) this points to the firmware stopping the machine (SMI) for ~40 ms.
- The prime suspect is the xHCI handoff from the BIOS (usbd starts ~330 ms after boot in QEMU): firmware commonly
  spends tens of ms in SMM tearing down legacy USB emulation. usbd now measures it: `lsusb -v` prints the
  controller line with `BIOS: handed over (from X ms, Y ms; reset Z ms)` – uptime when the handoff started, its
  length, and the halt + reset time.
- **Result on the test laptop:** it has three xHCI controllers, one `usbd` each, started together. Handoffs:
  usb0 not BIOS-owned (reset 33 ms from 353 ms), usb1 handed over from 354 ms (73 ms), usb2 from 387 ms (42 ms).
  Clock gaps: from **354 ms (33.3 ms)** and from **387 ms (40.1 ms)** – starting exactly with the handoffs. The
  second gap was probed: CPU 0 in `user_irq` ← `msi::dispatch` ← `exception_dispatch` ← `isr_common`, i.e. the NMI
  landed in the MSI handler that was running when the firmware froze the machine (v0.35.3: at the MSI stub
  entry). Conclusion: firmware SMI during the xHCI BIOS→OS handoff; nothing to fix in the kernel (the ticks are
  caught up from the HPET, and Linux pays the same at boot). Documented in README and ARCHITECTURE; the
  diagnostics stay (they cost one counter per interrupt on CPU 0).
- limtest: every spawn right after a limit check (process bomb, memory hog) is retried for up to 2 s on `EAGAIN` /
  `ENOMEM` – the killed process's slot and frames are released asynchronously by the idle reaper, so under KVM the
  helper spawn sometimes came too early (`spawn filler: -12`).

## v0.35.4 — 2026-10-18

### Clock-gap probe: crash fix and deeper stack
- **Bug in v0.35.3:** the probe NMI could catch CPU 0 at system call entry – kernel code still running on the
  user's stack pointer – and reading that stack faulted in the NMI handler (kernel panic; seen once in QEMU in the
  NOBKL test). The stack is now scanned only when RSP lies inside the current task's kernel stack (below TSS.RSP0).
- The scan covers up to 16 KiB from RSP towards the stack top, not just the page of RSP (v0.35.3 on the test laptop
  caught a 40.8 ms gap with `IF=0` but found no return addresses in that page).
- `cpus`: `clock gap N: from X ms, Y us, K other interrupts, CPU 0 at 0x… (user|kernel) IF=… stack: …`. The uptime
  is when the gap began (ticks for the gap are added after it is recorded). **K** = other interrupts CPU 0 took during
  the gap (counted at interrupt entry): K > 0 means CPU 0 was running with interrupts enabled and only the PIT
  interrupt was missing; K = 0 means it was stuck with interrupts disabled or stopped by firmware (SMI).
- v0.35.3 caught the 40.8 ms gap at the very first instruction of an MSI interrupt stub (`msi_1`) – CPU 0 was taking a
  device interrupt right then, so it was probably not stuck with interrupts disabled; K tells for sure.
- Test laptop, v0.35.3: all 4 long gaps are during boot (from 354, 378, 1240 and 1867 ms; 24.7 ms, 40.8 ms, 2.2 ms,
  2.1 ms), none during the 60 s stress – the 40.8 ms one with CPU 0 running with interrupts disabled.

## v0.35.3 — 2026-10-18

### Diagnostics: long gaps between clock interrupts
- On real hardware CPU 0 sometimes misses PIT interrupts for up to ~40 ms (time is caught up from the HPET, but
  the cause was unknown). Now another CPU watches the age of the last PIT interrupt from its own timer tick;
  after 6 ms it sends an NMI to CPU 0 (delivered even with interrupts disabled). The NMI handler records where
  CPU 0 was: RIP, IF and kernel-code addresses found on its stack.
- `cpus`: up to 8 lines `clock gap N: at X ms, Y us, CPU 0 at 0x… IF=… stack: 0x… …` (uptime at the end of the gap,
  length, location). Resolve the addresses with `addr2line -e build/kernel.elf <address>` – same build only.
- LOCK TEST 6/6 also checks that the 10 s stopped-clock test triggers the gap probe.
- limtest: after the process bomb, spawn is retried for up to 2 s – the last process slots are freed
  asynchronously (idle reaper), so an immediate `EAGAIN` was a rare false failure.

## v0.35.2 — 2026-10-17

### Security, step 3: limits – stage closed
- **Processes:** at most 1024 (live + not yet reaped). Above 960, `spawn` gets `EAGAIN`; the last 64 slots are reserved
  for init and its direct children (shell, services) – after a fork bomb the shell can still run `ps` / `kill`,
  and init can still restart a service.
- **Kernel-only memory reserve:** 1/16 of RAM (16–256 MiB; the test laptop with 16 GB → 256 MiB, QEMU 512 MiB → 32 MiB).
  Process pages, their page tables and shared memory – only above the reserve (`alloc_frame_user`, lock-free
  check). A memory hog dies (missing page), `shm_create` gets `ENOMEM`, the kernel still has memory to work with.
- **IPC buffers on the kernel heap:** channel queues and pipe data together at most 16 MiB (`kbuf`). Previously a few
  processes could fill the heap (64 MiB) with queues and the kernel crashed on the next allocation. Over budget:
  `chan_send` and pipe writes – `ENOMEM` (the message comes back, nothing is lost).
- **ramfs:** files (also on the heap) at most 24 MiB – beyond that `ENOSPC`. **Bug found along the way:** `seek` to
  a huge position + writing 1 byte made the kernel allocate a gigantic buffer – a kernel panic from any program. Now
  `ENOSPC`. File sizes are changed via `try_reserve` (out of memory = error, not panic).
- `cpus`: line `limits: N of 1024 processes, kernel memory reserve X MiB (… refused), IPC buffers … ramfs …`.
- **Test:** FILE TEST 6/6 – `/bin/limtest` (17 checks): fork bomb until `EAGAIN` (959 processes in QEMU), then
  things work again; `shm_create(16 MiB)` until `ENOMEM`; memory hog killed; ramfs until `ENOSPC` + write at 1 TiB →
  `ENOSPC`; channel queues (with a helper) until `ENOMEM`, a pipe meanwhile – `ENOMEM`, works after closing. The kernel
  checks that processes, the IPC budget, ramfs and frames came back, and that an ordinary program runs.
- **Test laptop (16 threads, v0.35.2):** compare mode **600 637** (v0.34.3: 599 726), max6 **593 350** (593 119) –
  the limits cost nothing; `limits: 6 of 1024 processes, kernel memory reserve 256 MiB (0 user frame(s) refused), IPC buffers 0 of
  16384 KiB (0 refused), ramfs 1287 of 24576 KiB` – normal operation doesn't touch any limit. pass=1.
- USB TEST: the final frame check of the whole suite accounts for heap growth (like stress and the new tests) – on the
  developer's machine (KVM) once "frames leaked (111927 -> 111913)", even though all 7 USB tests, each with its own check,
  passed; after the big tests (ramfs, queues) the heap can be fragmented and grows at the end. The line `[USB TEST] frames after the suite:
  … (heap +N pages)` shows by how much.
- QEMU 28/28.

## v0.35.1 — 2026-10-17

### Security, step 2: no handle cycles in channels
- **Bug (known gap, also pointed out by an external code review and ChatGPT):** a process could put the end of channel A
  into the queue of channel B, and the end of B into the queue of A, then close the remaining handles. The channels held
  each other – nobody would ever receive them, and the kernel memory never came back. A single program could eat memory
  this way in a loop.
- **Rule:** a channel end whose queue holds a message carrying another channel end cannot itself travel in a
  message – `chan_send` returns `EBUSY`, the handle stays with the sender. Once that message is received, the end may
  travel again. A cycle is impossible: the last insertion that would close it always hits this rule. The check and the
  insertion happen together under a single `chan-xfer` lock – only messages with channel ends take it, ordinary messages
  are unchanged (same IPC performance). Services (usbd, connect-by-name via init) work as before.
- **Test:** IPC TEST 3/5 – xfertest 43 checks (was 32): cycles with 2 and 3 channels rejected, ordinary messages
  go through, after receiving the end travels again, an acyclic chain is allowed; the kernel counts live channels – none
  remain after the test. Verified: without the rule the test fails (check 34).
- QEMU 28/28.

## v0.35.0 — 2026-10-17

### Security, step 1: syscall audit + fuzzer
- **Audit:** reviewed all system calls for arithmetic on process-supplied numbers (lengths, addresses,
  counters – like the `mmap` bug from v0.34.2): copying from / to a process (`user_range_ok` with `checked_add`, every length
  bounded: MAX_IO, 255 B paths, 4 KiB arguments, MSG_MAX, list limits), `sleep` (up to 1 h), `seek`, `wait_many`
  (long timeout = no timeout), `dup2`, shared memory, service calls (`dev_map`, `blk_attach`,
  `input_inject`), the ELF parser and loader. **No new bugs found** – the previous one was the only one of its kind.
- **Fuzzer `/bin/sysfuzz`** (FILE TEST 5/5):
  - 32 children without any handles, each making up to 3000 random calls with extreme arguments (0, −1, 2^64−1, kernel
    addresses, near-overflows, a real buffer with a wrong length, random handles; real objects at the start:
    a pipe, channels, shared memory, a file), 8 at a time on several CPUs; a child that gets stuck (sleep, wait_many, recv)
    is killed – this also tests cleaning up a process in the middle of a syscall;
  - 300 corrupted ELF files (copies of `/bin/hello` with randomly changed bytes, mostly in headers, sometimes truncated)
    – written to a file and `spawn`ed: a process can run any file, so the loader is also program input;
  - skipped: `exit`, `spawn` (fork bomb – step 3, limits), `kill` (could kill the parent or init);
  - test: the kernel neither crashes nor hangs, frames come back, junk from random paths is removed by the kernel.
- One-off long run (256 children × 4000 calls ≈ 1 M, 2000 ELF files): the kernel survived, 0 leaks.
- QEMU 28/28.

## v0.34.3 — 2026-10-16

### Stress measures itself less
- The `stress-spin` tasks (spinlock correctness test: 16 tasks increment a shared counter, at the end the sum must
  match) did 500 operations per round – on the test laptop (16 threads) 68,7 M waits, **7,9% CPU spent just spinning** on the
  `stress-counter` lock. Now 50 per round: still millions of contended operations, the lost-increment test stays, but CPU
  goes to the real work (scripts, processes, IPC).
- **Test laptop (v0.34.3):** compare mode **599 726 scripts** (v0.34.1: 535 827, +11,9%), full load (max6)
  **593 119** (533 725, +11,1%); idle 5%, ping-pong 4,5 µs, pass=1; `stress-counter` 7,9% → 0,0% CPU; background USB stick
  73,7 MB/s in compare mode (was 26 MB/s). Still max6 ≈ compare; most expensive now: `spawn` (ELF loading)
  ~9% CPU, heap 0,6–1,0%. Clock: still 45–51 lost PIT ticks and gaps of up to 40 ms – next step.
- **Logs in the `logs/` folder:** `logs/test.log` (tests/test.sh), `logs/stress-qemu.log` (tests/stress-qemu.sh),
  `logs/build-usb.log` (make-usb.sh). The old `test.log`, `stress-qemu.log`, `build-usb.log` in the root folder can be deleted.
- **Script counts from v0.34.3 on are higher due to the test change alone** – compare with v0.34.2 only with this caveat.
- QEMU 28/28.

## v0.34.2 — 2026-10-16

### Security fixes (from an external code review)
- **`mmap` / `munmap` with a length close to 2^64 crashed the kernel.** Rounding up to a page (`page_up`) overflowed
  before the limit check, and the kernel is built with overflow checks – so any program could PANIC the whole
  system with a single `mmap(u64::MAX)` (verified: the old version fails in MemTest). Now the limit first,
  then rounding; `munmap` rounds without overflow → `ENOMEM` / `EINVAL`. FILE TEST 4/4: memtest 25
  checks (was 23).
- **Race between `chan_send` and the receiver closing.** The sender checked "other side closed" before taking the queue lock;
  when the receiver closed at exactly that moment, the message (with handles inside) landed in a dead queue, and
  `send` returned success. Now there is a second check under the queue lock – the sender gets `EPIPE` and the handles come back.
- **`readkey` without permission checks.** It read the keyboard for any process. Now only when handle 0 is the
  console with the READ right (like `read(0)`); otherwise `EBADF`. As a side effect, a process with a file / pipe as input no
  longer steals keystrokes from the shell. IPC TEST 1/5: handletest checks this in a child with a file on handle 0.
- Known gap unchanged: a handle cycle through the queues of several channels stays in memory (described in the roadmap).
- QEMU 28/28.

## v0.34.1 — 2026-10-15

### Test-laptop results for v0.34.0 + small report fix
- **Test laptop A/B (16 CPUs, stress 60 s):**

  | Spin window | Scripts | Idle | Ping-pong | Wake-ups while spinning (without IPI) | Halts (`hlt`) |
  |---|---|---|---|---|---|
  | adaptive up to 200 µs (default) | 535 827 | 7% | 4,35 µs | 831 103 (632 102) | 42 817 |
  | fixed 200 µs | 535 300 | 3% | 4,45 µs | 819 500 (623 851) | 27 504 |
  | fixed 50 µs (like v0.33.0) | 534 027 | 3% | 4,4 µs | 862 796 (655 029) | 58 382 |
  | fixed 20 µs | 536 961 | 2% | 4,35 µs | 739 641 (546 652) | 83 748 |

  All within noise (~0,5%) – a window length between 20 and 200 µs makes no difference. **Adaptive stays**:
  just as fast, and an idle system doesn't spin (battery). Wake-up without IPI works: ~75% of wake-ups without an interrupt,
  ping-pong 5,0 µs (v0.33.0) → 4,35 µs. Average window under load 85 µs.
- **Test laptop, full load (`DESOOS_STRESS_POOL=6`, 96 processes): 533 725 scripts + 266 863 primes** – a record
  (v0.22.0: 528 869, +0,9%), idle 2%, ping-pong 4,45 µs, background USB stick 26 MB/s (764 identical passes), pass=1.
  Scheduler lock: 25,0 M acquisitions, 24% wait, 2,4 s of waiting, longest 121 µs. Full load now yields the same
  as compare mode (535 827) – the limit is now the stress itself: the `stress-counter` counter is 7,9% CPU waiting
  on the spinlock (68,7 M waits), and `spawn` (ELF loading) ~17% of the time.
- The `cpus` report with a fixed window showed "now avg 50 us" (the initial value) instead of the configured one – fixed.

## v0.34.0 — 2026-10-15

### Spinning before `hlt`: self-tuning window + wake-up without an interrupt
- **The spin window adapts per CPU** (like `haltpoll` in Linux): when work arrived within 200 µs of the core going
  to sleep, the window grows ×2 (spinning would have caught it); after longer idleness it shrinks /2, down to 0. Under load
  cores spin up to 200 µs, an idle system not at all – no power wasted on battery.
- **Wake-up without IPI:** a spinning core has a "spinning" flag; the waker just sets its "reschedule" flag, without an
  inter-processor interrupt. The flag ordering (like Dekker's algorithm) guarantees the wake-up isn't lost when the
  core is just finishing spinning and going to sleep.
- Build-time settings: `DESOOS_IDLE_POLL_US` – upper bound of the window (default 200, 0 = no spinning),
  `DESOOS_IDLE_POLL_ADAPT=0` – fixed window (like v0.32.2–v0.33.0 with 50 µs). In [RESULT] `idlepoll=a200` (adaptive) or
  `idlepoll=50` (fixed).
- Report: `idle: spins before hlt (adaptive up to 200 us, now avg N us): X wake-ups while spinning (Y without IPI),
  Z halts, window A x up / B x down`.
- QEMU 28/28 (1 and 4 CPUs).

## v0.33.0 — 2026-10-15

### ✅ P4 closed + test cleanup
- **P4 (scheduler lock) – summary on the test laptop (16 threads):** waiting on the scheduler lock 18,9 s → ~4,6 s per minute,
  longest wait < 100 µs; stress (compare mode) **432 210 → 534 072 (+23,6%)** – mainly thanks to spinning
  before `hlt` (v0.32.2), which came out of hunting for the regression after steps 0–c.
- **Tests in a separate `tests/` folder:** `tests/test.sh`, `tests/stress-qemu.sh`, `tests/mkfat32.py`,
  `tests/qemu-hotplug.py` (previously in the root directory). They work from any location (`tests/test.sh`,
  `ACCEL=kvm tests/test.sh`, `SMP=8 tests/stress-qemu.sh`); logs stay in the root directory as before. Kernel self-test
  code only in the `--selftest` build – the kernel on the USB stick doesn't contain it.
- `build.sh` no longer prints the spinning-before-`hlt` line when it's the default (50 µs).

## v0.32.2 — 2026-10-15

### Hypothesis: waking a sleeping core – spinning before `hlt`
- **A/B on the test laptop (16 threads; back to back, same USB stick):** v0.29.0 **434 178**, v0.32.1 **412 946 (−4,9%)** – the
  regression is real. NOT from the lock: longest wait on the scheduler lock 65 µs (0 waits > 100 µs, in an interrupt
  19 µs), lost ticks 70 (v0.29.0: 56), `spawn` / `exit` / `wait` / `reap` times the same or shorter.
  Only idleness grows: 26% → 28%.
- **KVM 16 CPUs (developer's machine):** v0.29.0 342 392, v0.32.1 **346 764 (+1,3%)**, waiting on the lock 18,9 → 4,4 s,
  IPC tasks +14% – no regression on the virtual machine.
- Hypothesis: on real hardware `hlt` puts the core into a deeper sleep (AMD: C1 → CC6) and wake-up takes tens of µs.
  After P4 the cores spin less on the lock and sleep more often, and every handoff of a task to a sleeping core
  lengthens the spawn → script → wait chain.
- **Test:** an idle CPU spins for `DESOOS_IDLE_POLL_US` µs (default 50) before `hlt` – the wake-up (IPI) hits a
  running core (like `haltpoll` in Linux). `DESOOS_IDLE_POLL_US=0` = as before. Report: `idle: spins N us
  before hlt: X wake-ups while spinning, Y halts`; in [RESULT] `idlepoll=N`.
- ✅ **Test laptop – hypothesis confirmed (A/B, same build, only the variable changed):**

  | | `idlepoll=0` | **`idlepoll=50`** |
  |---|---|---|
  | scripts (compare) | 412 315 | **534 072 (+29,5%)** |
  | idle | 32% | **7%** |
  | IPC tasks | 6 247 | **8 535 (+37%)** |
  | ping-pong / channel | 5,6 µs / 662 MB/s | **5,0 µs / 1001 MB/s** |
  | USB stick during stress | 48 MB/s | **68 MB/s** |

  Wake-ups while spinning: 742 747 (`hlt` entries: 53 441). **Test-laptop record in compare mode** – 23%
  more than v0.29.0 (434 178), more than the previous full-load record (max6 528 869). Longest
  wait on the scheduler lock 83 µs. Conclusion: before P4 the cores "accidentally" didn't sleep, because they spun on the
  lock; after P4 they fell asleep and every task handoff waited for a core to wake up.

## v0.32.1 — 2026-10-15

### Diagnostics: why stress drops even though the scheduler lock stopped being a bottleneck
- **Test laptop (16 threads), v0.32.0 (P4.c):** waiting on the scheduler lock **3,7 s** (v0.31.1: 11,1 s; v0.29.0: 18,9 s – **−80%**),
  32% of acquisitions wait (was 41%), lock held ~10,1 s (15,4 s); `on_cpu`: 430 waits per 9,1 M switches (0,5 ms).
  KVM 8 CPUs: waiting 1083 → 333 ms, holding 7,0 → 4,0 s.
- **But stress on the test laptop drops with every P4 version:** 432 210 → 423 575 → 416 610 → 409 018 (−5%), idle grows
  (26 → 32%) and so does the number of lost timer interrupts on CPU 0 (44 → 379).
- New `cpus` report lines to find the cause:
  - `scheduler lock: longest wait X us (location), N waits over 100 us, longest wait in an interrupt Y us`,
  - `clock: …, longest gap between timer interrupts X us, N gaps over 2 ms` (CPU 0).
- A/B comparison with v0.29.0 (code from `~/Pulpit/DeSoOS-github`) on the same USB stick, back to back.

## v0.32.0 — 2026-10-14

### P4.c: task switching outside the scheduler lock
- **The scheduler lock is released before the switch.** Only choosing the next task, states and queues remain
  under it; FPU save / restore, address-space change (CR3), the stack and the switch itself now happen without it
  (test laptop (16 threads), v0.31.1: switching is 36% of lock hold time – 5,6 s per minute, 624 ns per switch).
- **`on_cpu` flag** in the task (like in Linux): set when a CPU picks the task, cleared by the CPU leaving
  it – right after the switch, once registers and FPU are saved. A CPU that picked a task still
  leaving another CPU (woken just before that CPU's switch) waits for the flag to clear; reaping doesn't
  free a task with the flag set. Wake-up unchanged – state and queues stay under the lock, so sleep and wake-up can't
  miss each other.
- End of the "lock carried across the switch" (it was released by the next task, including a new one – in
  `sched_new_task_start`): guards taken before the switch release nothing after the task returns.
- `cpus` report: `scheduler: N task switches outside the lock, M waited for a task still leaving another CPU`.
- SMP test 7/7: 4 pairs of tasks on different CPUs wake each other in a loop (lost wake-up = waiting until the
  1 s deadline = FAIL), alongside hundreds of short tasks finish and get reaped. Without waiting on `on_cpu` the kernel crashes
  immediately (verified). QEMU 28/28 (1 and 4 CPUs).
- Test laptop, v0.31.1 (P4.b): scheduler lock acquisitions 39,6 → 27,2 M (−31%), waiting 14,3 → 11,1 s; stress
  416 610 – no gain (writing to the task table lengthened `spawn_in` and `reap` under the scheduler lock).

## v0.31.1 — 2026-10-14

### SMP test 6/6 fix
- Under KVM the test aborted with "too little churn: 16 processes": it considered a process alive as long as its task
  was on the list (`task_exists`), and finished tasks are only reaped by `spawn` or the idle loop – which didn't run
  while the CPUs were busy with readers. Now "alive" = has a process that hasn't exited (`with_process`). A test bug, not a kernel bug.
- KVM 8 CPUs (v0.31.0): scheduler lock acquisitions 16,2 → **11,5 M (−29%)**, `with_process` disappeared from the list
  of call sites; task table: 4,9 M reads + 2,0 M writes, 7 ms of waiting. Task switching is **43%** of
  scheduler lock hold time (3,0 s out of 7,0 s, 775 ns per switch) – that's how much step c can recover.

## v0.31.0 — 2026-10-14

### P4.b: task list under its own lock
- **"Which process has number X" queries no longer queue for the scheduler lock.** The task list (and the number
  buckets) has its own RW lock, "task table": `with_process`, `task_exists`, `children_of`, `for_each_process`
  read it in parallel (test laptop (16 threads), v0.30.0: `with_process` 10,8 M scheduler lock acquisitions per minute, 3,7 s
  of waiting). Writes: adding a task (spawn), removing one (reap) – under both the scheduler lock and this one; changing parents
  (`reparent_with`) – only this one, for writing (excludes `with_process` as before).
- Readers see "exited" through an atomic `dead` mirror; a task has a liveness tag (freed = a different tag).
- Waiting on RW locks now acknowledges TLB shootdowns (table readers wait with interrupts disabled).
- **Measurement for step c:** new line `scheduler lock: task switches under it X ms of Y ms held (Z%)` – how much of the
  scheduler lock hold time is the task switch itself. QEMU (TCG, 4 CPUs): 51%.
- Test: SMP TEST 6/6 – readers on several CPUs query processes while hundreds of processes are being started, exiting
  and freed; a freed task seen by a reader = FAIL. Without the write lock in reap the test detects
  the bug (2 out of 2 attempts). QEMU 28/28 (1 and 4 CPUs).

## v0.30.0 — 2026-10-14

### P4.0: the scheduler lock waits by reading
- **P4 plan (scheduler lock)** written down: `ROADMAP.md` and `ARCHITECTURE.md` ("Scheduler – P4"), with a comparison to
  Linux, Redox, FreeBSD ULE and BFS/MuQSS.
- **First step, the simplest:** a CPU waiting on the scheduler lock executed `compare_exchange` (an atomic
  instruction) on every loop iteration – 15 waiters kept stealing the cache line holding the lock from each other and from
  the holder, so the holder released it more slowly. Now it waits by reading only and tries to acquire only
  when the lock looks free (test-and-test-and-set) – ordinary spinlocks already wait this way. The same in the process
  zombie-list lock and in the TLB shootdown initiator lock.
- **Test laptop (16 threads):** waiting on the scheduler lock **18,9 → 14,3 s (−25%)**; still 41% of acquisitions wait (wait_event 5,4 → 4,0 s,
  with_process 4,9 → 3,7 s, wake_channel 4,2 → 3,4 s). Stress 423 575 (v0.29.0: 432 210 – variance, no gain).
  KVM 8 CPUs unchanged. Conclusion: the lock is HELD too long – next steps P4.b and P4.c.
- QEMU 28/28.

## v0.29.1 — 2026-10-14

### ✅ M20 closed – USB on the test laptop (v0.29.0)
- Boot USB stick (SuperSpeed) before stress: **121 640 KiB/s** (256 KiB buffer), **125 365 KiB/s** (4 KiB buffer,
  like `cat`); during stress **52 140 KiB/s** (v0.28.0: 4 586 KiB/s), 3056 MiB, 1519 identical passes, 0 errors.
- USB keyboard: 37 keypresses, interrupt → character in the kernel avg **275 µs** (min 28, max 695).
- Enumeration: camera 88 ms, USB stick 2 ms, USB 2 hub 201 ms, USB 3 hub 137 ms, keyboard 107 ms, mouse 95 ms.
- Stress compare **432 210** (v0.28.0: 436 488, −1% – 3 GiB read from the USB stick in the background), `pass=1`.
- `df`: `/usb0` 2,0 MiB used (= BOOTX64.EFI, 2,0 MiB), `/usb1` 25 651 MiB of 59 117 MiB.
- A 59 GB USB stick in the USB 3 hub enumerated as high speed (`port 1.1` – the USB 2 part of the hub), works.
- No code changes (documentation only).

## v0.29.0 — 2026-10-14

### M20.h: faster USB stick reads, `df`, measurements – closing M20
- **FAT32 much faster.** Previously every `read` re-read the directories along the path (on the test laptop: 3 × 64 KiB from
  the USB stick before every read of `/usb0/EFI/BOOT/BOOTX64.EFI`), each cluster as a separate request, and `cat` with a
  512 B buffer read the same cluster many times. Now: FAT read in 4 KiB blocks, a cluster cache (directories, file
  tails; write-through), contiguous file clusters in a single read (up to 1 MiB), 64 KiB read-ahead for
  small reads, remembered position in the cluster chain.
- **Pipelined ublk:** a long read sends up to 4 requests at once – usbd takes the next one right after the previous, without waiting
  for the kernel to wake up. Response validation unchanged (id, block count, timeout → quarantine).
- **QEMU (TCG):** reading 4 MiB from the USB stick in usbtest **716 → 70 620 KiB/s**; in the kernel with a 256 KiB buffer 74 369 KiB/s,
  with a 4 KiB buffer (like `cat`) 36 957 KiB/s (was 5 577 before read-ahead).
- **`df` on the USB stick:** free space computed from the FAT (once), not from FSInfo – which can be stale. The test image
  deliberately has a bad FSInfo; the test compares against the real number.
- **INQUIRY up to 4 attempts** (delays 200 / 400 / 600 ms) – on the test laptop once `INQUIRY failed` on port 5.1; the error
  message gives the cause ("no answer", "STALL"…), `stor_retries` counter in the usbd status.
- **Measurements:**
  - device enumeration time (port reset → ready): "ready in N ms" at the end of the device line, in the usbd status
    `enum_avg_ms` / `enum_max_ms`; QEMU: avg 23 ms, max 49 ms;
  - USB keyboard latency: from the xHCI interrupt (timestamp in the kernel handler) to the character in the kernel input queue
    (via usbd); QEMU (`sendkey` from the monitor): avg 535 µs, min 278, max 1337;
  - `[RESULT-USB]` in `test.sh`: `enum_avg_ms enum_max_ms kread_kbs kcat_kbs hid_n hid_avg_us hid_max_us`.
- **Autostress (test laptop):** before stress, the largest file on /usbN is read with a 256 KiB and a 4 KiB buffer (the data must be
  the same, otherwise `pass=0`) – line `usb: … read before the stress`; line `usb keyboard:` (keypresses since boot –
  worth pressing a few keys during the run); a separate `[RESULT-USB]` line.
- Tests: USB TEST 7/7 checks reading DATA.BIN with both buffers byte for byte against the pattern, `df` with a bad FSInfo, and
  the keyboard via `sendkey`. QEMU 28/28 (1 and 4 CPUs).

## v0.28.1 — 2026-10-14

### ✅ M20.g on the test laptop – USB robustness works on hardware
- Autostress: compare **436 488** (v0.27.1: 431 338), `pass=1` – no drop, even though the boot USB stick was read in the background.
- `usb:` line – `/usb0/EFI/BOOT/BOOTX64.EFI` read during stress: **268 MiB, 4586 KiB/s, 134 full
  passes, all identical, 0 errors**.
- USB stick pulled during `cat /usb1/liczby.txt` → `cat: … I/O error`, `usb2 port 1.1: device disconnected`,
  `[USB] sdb: removed, /usb1 unmounted (reads 6318, timeouts 0, protocol errors 0)` – no hang.
- Typing during stress works.
- Note for M20.h: once `usb2 port 5.1: 13fe:6700 SuperSpeed … storage setup failed: INQUIRY failed` (the same
  USB stick worked on `port 1.1` after re-plugging; in v0.27.1 it worked on 5.1) – add an INQUIRY retry.
- No code changes (documentation only).

## v0.28.0 — 2026-10-13

### M20.g: USB robustness
- **A hung USB stick doesn't stop the system.** FAT32 on a USB disk now runs under its own lock (`fs::Locked`,
  the VFS calls it as a `ConcurrentFs` under FS_LOCK held for reading only). Previously every read from `/usbN` held FS_LOCK for
  writing – a USB stick waiting up to 5 s for usbd stalled the whole VFS meanwhile (ramfs, `/bin`, launching
  programs). `mount`, `open`, `df` don't wait for the disk either (description and "read-only" remembered at mount time).
- **USB stick pulled from a hub during a read:** usbd aborts waiting for the bulk transfer when the hub reports a change on
  that port (before: 4 s transfer timeout + reset recovery on a nonexistent device → the kernel got a timeout
  after 5 s, unmount after ~7 s). Now the reader gets an error in ~12 ms, the disk is unmounted in ~140 ms. If the device
  is still there after all – reset recovery before the next command.
- **usbd restarts and failures:** init prints "init: usb0: USB keyboard and disks back in a moment" after a usbd restart, and after
  5 failures within 30 s: "init: USB controller usb0 disabled after 5 failures - its USB keyboard and disks are
  unavailable until reboot (PS/2 still works)".
- **usbd in autostress:** if a USB stick is mounted (/usbN – on the test laptop, the boot one), the `usb-stress` task
  reads its largest file in a loop during stress; every full pass computes a checksum – all must
  be equal. Line `usb: … MiB, … KiB/s, N full passes (all identical), 0 errors`, in [RESULT] `usb_mib`, `usb_kbs`,
  `usb_err`, `usb_bad` (an error or a mismatch = `pass=0`). `stress-qemu.sh` attaches the test USB stick.
- **Tests (28 suites, USB TEST 1–7/7):** new 6/7 – (a) FAT32 on a "hung" test disk: reading `/bin/sh` and
  `ls /bin` meanwhile without waiting (0 ms; with the old lock – until the disk is released), (b) `init test /bin/usbtest
  robust`: kill usbd while a file from `/usb0` is being read – the reader gets EIO after a few ms, init restarts usbd,
  the disk and keyboard return in ~0,5 s, files still identical to `/bin`, (c) 4 more kills → 5 failures in 30 s →
  `broken` + message, controller handed back (bus mastering off), nothing leaks; 7/7 – pulling a disk behind a hub during
  a read (a kernel task reads `DATA.BIN`): error in ~12 ms.
## v0.27.1 — 2026-10-13

### ✅ M20.d on the test laptop – hubs, TT and hot-plugging work
- Genesys hubs: `usb2 port 1` 05e3:0610 "USB2.1 Hub" → `hub ready (2 ports, USB 2)`, `usb2 port 5` 05e3:0620
  "USB3.2 Hub" → `hub ready (2 ports, USB 3)` (Set Hub Depth, SuperSpeed behind a hub).
- **Logitech G502 mouse (full speed) behind a high-speed hub** (`port 1.2`) – `mouse ready`: the transaction translator (TT)
  works on real hardware (this could not be checked in QEMU).
- **USB stick "Wilk USB DISK 3.0" 59 GB (SuperSpeed) behind a USB 3 hub** (`port 5.1`) → sdb → `/usb1` (FAT32 'USB DISK',
  64 KiB cluster); pulled out while running → `device disconnected`, `/usb1 unmounted`; plugged back in → sdc → `/usb1`.
- Stress with no regression: compare **431 338** (v0.26.2: 434 164), `pass=1`, ping-pong 6.9 µs.
- One error: `usb2 port 1.1` at boot – `Address Device failed` 3 times, port ignored (after the device was removed
  the port went back to normal). Explanation (from the developer): that socket had a phone charging cable plugged in with no phone – a cable
  with electronics (LED / chip) looks to the hub like a connected device that does not respond. The behaviour is
  correct (Linux: "unable to enumerate USB device"); after the cable was removed, the 59 GB USB stick went into the same socket
  (port 5.1 = USB 3 side of the same socket, 1.1 – USB 2 side).

### Diagnostics and a test fix
- usbd: "Address Device failed" now includes the xHCI completion code (e.g. `USB transaction error`, `split transaction error`,
  `parameter error`), and the message about a failed hub-port enumeration reports the device speed.
- ALLOC TEST 4/5: the same false alarm "more free frames at the end" (once in my runs: 110629 -> 110727) – baseline
  taken after the counter settles, end check uses `>=`.

## v0.27.0 — 2026-10-13

### M20.d: USB hubs (devices behind a hub, hot-plugging)
- **usbd – USB 2 and USB 3 hubs** (also hub behind hub, up to 5 levels): interrupt endpoint with a port-change bitmap,
  Set Configuration, Set Hub Depth (USB 3), hub descriptor (port count, TT think time, power-on time),
  a second Configure Endpoint with the hub fields in the slot context, port power.
- **Hub ports** use the same state machine as controller ports: 100 ms debounce, hub port reset (≤ 500 ms),
  3 attempts, then ignored until disconnect; status via GET_STATUS, changes cleared with CLEAR_FEATURE. Changes are reported by the hub
  (bitmap on the interrupt endpoint) – only reported ports are checked.
- **Device behind a hub:** route string (hub port at each level), controller port of the top-level hub, speed from
  the hub port, **TT** (slot and port of the nearest high-speed hub) for low- and full-speed keyboards / mice behind a USB 2 hub.
  Slot context built in one place (`slot_ctx`) – Address Device and every Configure Endpoint (HID, disk, hub).
- **Disconnecting a hub = disconnecting everything behind it** (disks disappear in the kernel, keys released).
- `lsusb`: `usb0 port 11.2: … mass storage …` (controller port . hub port), `hub ready (8 ports, USB 2)`;
  usbd status: hubs, hub_events, hub_errors.
- `init test /bin/x arg` – the test program receives one argument.
- **Tests (28 suites, USB TEST 1–6/6):** in QEMU a hub on port 3, behind it a mouse (3.1) and the test USB stick (3.2);
  2/6 and 5/6 – 5 devices, the hub and the devices behind it work (USB stick behind the hub mounted, files = /bin); **new 6/6 –
  hot-plugging**: `qemu-hotplug.py` reads "[HOTPLUG] …" lines printed by the self-test from the log and sends them to
  the QEMU monitor – disk behind the hub removed (unmounted in ~200 ms), reinserted (mounted in ~280 ms), the whole hub removed
  (hub, mouse and disk disappear), usbtest sees 5 → 4 → 5 → 2 devices without errors, nothing leaks.
- `HUB=1 ./run-qemu.sh` – hub on port 3; with `USB=1` keyboard and mouse behind the hub (typing through the hub works), `usb.img`
  on port 3.3. QEMU: `qemu-xhci,id=xhci` + fixed device ports; the test USB stick as `-blockdev`.
- Note: the QEMU hub is full speed – TT (high-speed hub + full-speed keyboard) can only be verified on the test laptop.

## v0.26.2 — 2026-10-13

### ✅ M20.f on the test laptop – boot USB stick read by DeSoOS
- `lsusb`: USB stick "Wilk" 13fe:5500 (SuperSpeed, usb1 port 6) → `disk sda ready (7560 MiB, 512-byte blocks,
  read-only)`; kernel: GPT → partition @2048 → FAT32 'NOSNIK USB' (4 KiB cluster) mounted at `/usb0`.
- `ls /usb0` → `EFI/`, `df` → `/usb0 7544 MiB`, `echo x > /usb0/a.txt` → "read-only file system".
- Stress with no regression: compare **434 164** (v0.25.1: 431 023), `pass=1`, ping-pong 6.6 µs. The ITE keyboard still works.

### Cleanup after M20.f
- Compiler warning in the regular build (`methods probed and mounts are never used`, `ublk.rs`) – both methods
  are used only by the self-test; marked `cfg_attr(not(selftest), allow(dead_code))`. Both builds warning-free.
- The `usb-disks` monitor no longer reads partitions of a disk that has already disappeared (usbd killed right after registration) – no misleading
  `[BLK] sdX: GPT: no such disk` in the log.
- v0.26.1 results (on the developer's machine): QEMU TCG 28/28 (USB stick read 1170 KiB/s), KVM 28/28 (828 KiB/s), stress KVM 8 CPUs
  **176 450** (v0.25.1: 179 713 – within noise), `pass=1`.

## v0.26.1 — 2026-10-13

### Test fix: false "frames leaked" in IPC TEST
- Symptom (on the developer's machine, v0.26.0): `[IPC TEST] FAIL: frames leaked (111523 -> 111933)` – at the end of the suite **more** free
  frames than at the start (in my runs once every few passes: 111559 -> 111725). Not a leak: the baseline was captured
  before cleanup after the previous suite had finished (FILE TEST – processes killed by #PF), and the leftovers were freed
  during IPC TEST. The same kind of false alarm had been fixed once before (M19.c).
- Fix: `settled_free_frames` waits for 10 matching samples (50 ms) instead of 3 (15 ms), and the leak checks in
  IPC, SVC and USB (end of suite and after each step) require "free frames no fewer than at the start" – a real
  leak (fewer free) is still detected. (After the first change the same symptom appeared once in USB TEST 5/5:
  110749 -> 110964.) QEMU: 28/28 in 4 consecutive runs.

## v0.26.0 — 2026-10-13

### M20.f: read-only USB stick (before step d – the test laptop's USB stick is not behind a hub either)
- **usbd – mass storage:** interface 08/06/50 (SCSI, Bulk-Only) with bulk IN / OUT endpoints: Configure Endpoint,
  Set Configuration, INQUIRY (disk only – not CD-ROM), TEST UNIT READY (up to 10 attempts, REQUEST SENSE clears UNIT
  ATTENTION), READ CAPACITY(10). Bulk transfers: TRBs split at 64 KiB boundaries (an xHCI requirement) and chained;
  STALL → Reset Endpoint + Set TR Dequeue + Clear Feature(HALT); timeout (4 s) / bad CSW → Bulk-Only
  Reset (reset recovery). Disconnect during a transfer is detected immediately (port), not after a timeout.
- **No writes:** the only SCSI commands are `SCSI_ALLOWED` (TEST UNIT READY, REQUEST SENSE, INQUIRY, READ
  CAPACITY(10), READ(10)) – checked before every command, and a compile-time assertion ensures the list contains
  no write command (WRITE 6/10/12/16, FORMAT, MODE SELECT, SYNCHRONIZE CACHE, UNMAP…).
- **Kernel – `BLK` handle and syscall 50 `blk_attach`** (M20.a design): handle kind 11, created only by the kernel
  for init (slot 6); init gives a copy to each usbd. usbd creates a channel and a DMA buffer (256 KiB = 4 slots of 64 KiB) and
  registers the USB stick; the kernel takes its own references. Errors: EBADF, EACCES (BLK without WRITE, channel without TRANSFER),
  EINVAL (block ≠ 512 / 4096, 0 blocks, slots outside 1..8, buffer too small), ENOSPC (8 disks).
- **`ublk` (`kernel/user/ublk.rs`) – disk "sda", "sdb"…, always read-only:** a read = a request over the channel
  (id, lba, blocks, slot), the USB stick DMAs straight into the slot, the kernel copies only after a valid reply.
  A reply with someone else's id / wrong block count is rejected (counter). 5 s timeout → EIO and the slot goes into **quarantine**
  (the device may still be writing) – it returns after the late reply. 3 timeouts in a row, usbd exiting or the USB stick
  being pulled = **the disk disappears**.
- **Kernel task `usb-disks`:** new disk → GPT partitions (or MBR / whole disk) → FAT32 mounted at `/usb0`,
  `/usb1`… (read-only); disk gone → unmount, partitions and disk removed, buffer and channel released.
- **Per-disk lock in the block layer** (previously: one global "block layer" lock) – waiting for the USB stick (up to 5 s) does not
  stall NVMe or virtio. The disk list is under a short lock; a removed disk frees its number.
- `ChanEnd::recv_timeout` (kernel waits for a reply with a deadline); FAT32 on a read-only disk rejects changes
  immediately (before anything reaches the buffers); `open` for writing on such a file system → EROFS.
- Read-only – **four independent locks**: no write commands in usbd, no write operation in the protocol, disk
  `read_only` (block layer and `ublk` reject writes), FAT32 / `open` → EROFS.
- `lsusb`: "disk sda ready (… MiB, 512-byte blocks, read-only, "vendor product")"; `usbd status`: storage,
  disks, stor_reads, stor_bytes, stor_errors. `disk`, `mount`, `df`, `ls`, `cat` work on `/usb0`.
- Tests (28 suites, USB TEST 1–5/5): 2/5 – two USB sticks in QEMU (boot vvfat + a new FAT32 image), the test one
  mounted by the kernel, kill usbd → disk disappears and comes back with the new instance, DMA buffers returned; 3/5 – new
  `/bin/blktest` impersonates usbd and breaks the protocol (blk_attach errors, reads with 1 and 2 requests, foreign id, wrong
  block count, timeout + quarantine, **virtio read during that time 8 ms – per-disk lock**, late reply, EIO,
  write rejected, 3 timeouts → disk removed, nothing leaks); 5/5 – through the real init: files from `/usb0`
  identical to `/bin`, 4 MiB pattern verified, write / `rm` / `mkdir` → EROFS. `[RESULT-USB]`: `mount_ms`,
  `read_kbs` (QEMU TCG: ~685 KiB/s – FAT32 reads cluster by cluster, the image has 512 B clusters).
- `mkfat32.py` – test USB stick image (MBR + FAT32) without mtools or sudo (`test.sh`); `run-qemu.sh`
  attaches `usb.img` (if present) as a second read-only USB stick. QEMU: `qemu-xhci,p2=8,p3=8` (more
  ports – no automatic hub).

## v0.25.1 — 2026-10-12

### ✅ M20.e on the test laptop – built-in keyboard works
- **First time in DeSoOS history typing on the test laptop (16 threads)**: `lsusb` shows "keyboard ready (input to kernel)" for
  the ITE 048d:c100 keyboard (usb2 port 4); in the shell `help`, `lsusb`, `echo`, Caps Lock and Polish characters
  work (AltGr: ąęśż…).
- Stress with no regression: compare **431 023** (v0.24.0: 434 021, v0.23.0: 436 765 – within noise), `pass=1`,
  ping-pong 6.7 µs.
- QEMU: self-tests 28/28 (TCG and KVM), stress KVM 8 CPUs 179 713, `USB=1` autostress with typing – PASS.

### Fix: lockdep PANIC when typing on a USB keyboard during stress
- Symptom (on the developer's machine, `USB=1 ./run-qemu.sh`, typing during autostress): `PANIC: spinlock order: 'waiters' (level 45)
  taken at kernel/user/waitset.rs:68 while holding 'stress-counter' (level 210)`.
- Cause: the USB controller's MSI interrupt (keyboard report) wakes usbd waiting in `wait_many` – the handler takes
  `waiters` (IrqSpinLock). The interrupted code on that CPU held `stress-counter` (plain SpinLock, interrupts enabled).
  Lockdep checked ordering against **all** locks held on the CPU, including those of the interrupted context – a false alarm: interrupted
  code cannot wait for the handler, and `waiters` is never held with interrupts enabled. The bug had been there since M19
  (service interrupts) and surfaced because this was the first time a service's device interrupts during stress.
- Fix (`sched/spin.rs`): a lock taken in an interrupt handler is tagged (bit 0 of the address in the held-locks table);
  **in an interrupt, ordering is checked only against locks taken in the interrupt**; recursion (same lock) is
  always checked. LOCK TEST 2/6 checks both cases (interrupt: the interrupted code's lock is not a violation; task:
  a violation is still detected).
- Along the way: USB autorepeat and releasing keys of a killed source moved from the timer tick (interrupt context)
  to the kernel task `input-repeat` (under the BKL; woken on key press, a generation counter prevents oversleeping the deadline) – less
  work in interrupt context. The timer tick is back to its pre-v0.25.0 state.
- Test: 20 s autostress on 4 CPUs (TCG, no 8042) with continuous typing via `sendkey` – PASS, no PANIC; self-tests 28/28
  with 1, 2 and 4 CPUs.
- The same situation could have occurred with PS/2 interrupts (IRQ1 / IRQ12) during stress – the lockdep fix covers
  all interrupts.

## v0.25.0 — 2026-10-12

### M20.e: USB keyboard and mouse (before step d – the test laptop's keyboard is not behind a hub)
- **Kernel – `INPUT` handle and syscall 49 `input_inject`** (M20.a design): handle kind 10, created only by the kernel
  for init (slot 5); init gives a copy to each `usbN` (not to the shell). Rights WRITE + DUP, no TRANSFER. **Each copy
  of the handle is a separate source** with a map of pressed keys – when it goes away (exit / kill of usbd), the kernel releases its keys
  (in the timer tick under the BKL; only atomics in Drop), so Shift or Ctrl never stay stuck after a crash.
- `input_inject(h, events, n ≤ 64)`: 8 B event – key (HID usage, pressed) or mouse (buttons,
  wheel); the whole batch is validated first (bad kind → EINVAL, nothing goes through), EBADF / EACCES as for other
  handles. Result: LED state (Num / Caps / Scroll) – usbd sets them on the keyboard.
- Kernel: HID usage → `KeyCode` table (letters, digits, F1–F12, navigation, numeric keypad, modifiers) – the rest
  unchanged: Polish programmer layout, AltGr, Caps Lock, Ctrl+C, console, `readkey`. **Autorepeat in the kernel** for USB
  sources (a USB keyboard does not repeat by itself): 500 ms, then every 33 ms (~30/s), one key at a time, modifiers and locks
  not repeated. USB mouse: the wheel scrolls the console (like PS/2).
- usbd: for the boot keyboard (03/01/01) and boot mouse (03/01/02) interfaces – Configure Endpoint (interrupt IN endpoint,
  interval by speed), Set Configuration, Set Protocol (boot), Set Idle, 8 TRBs waiting for reports. Keyboard report
  (modifiers + 6 keys) → diff against the previous one → events (ErrorRollOver skipped). HID endpoint events
  handled immediately, even during another transfer; endpoint error → endpoint reset and new TRBs. LEDs: Set Report.
  Keyboard disconnect → its keys released. `lsusb`: "keyboard ready (input to kernel)". New request
  `idle MS` (test). **Mass storage still gets no configuration at all** (step f).
- `USB=1 ./run-qemu.sh` – QEMU without the 8042 controller (like the test laptop), keyboard and mouse on USB only.
- Tests (28 suites): USB TEST 2/4 – QEMU keyboard and mouse configured, reports via interrupt endpoints (Set Idle
  16 ms: 50 reports in 400 ms); **3/4 – new `/bin/inputtest`** (16 checks): rights and errors, "hiA" in the kernel queue,
  autorepeat (8 × "b" after 700 ms), Caps Lock LED, a child with a copy of the handle killed with Shift and "q" held – Shift
  released, "q" does not repeat (mutation test: without releasing – "QQQQQQQQQQQ", detected); 4/4 – init gives usbd
  the INPUT handle.
- QEMU in my runs: 28/28 with 1, 2 and 4 CPUs. Manually via the QEMU monitor (`sendkey`, no 8042): `echo Usb`, AltGr+s → "ś",
  Caps Lock, holding "z" for 1.2 s → 23 characters (autorepeat).

## v0.24.0 — 2026-10-12

### ✅ M20.c on the test laptop – all devices recognized
- KVM 8 CPUs: 28/28, stress 170 404 (within noise: 174–178k), usbd start with enumeration ~150 ms.
- **Test laptop (16 threads): 7 devices, 0 enumeration errors** (usb0 NVIDIA – empty):
  - `usb2 port 4: 048d:c100 full speed, USB 2.01, keyboard, interfaces 03/01/01, "ITE Tech. Inc." "ITE Device(8910)"` –
    **built-in keyboard, directly on a controller port** (no hub), boot keyboard interface,
  - `usb2 port 3: 8087:0029` Intel Bluetooth (full speed), `usb1 port 3: 13d3:56ff` Azurewave camera "Integrated Camera"
    (high speed, IAD ef/02/01, interfaces 0e/01 + 0e/02 – alternate settings accepted without error),
  - `usb1 port 6: 13fe:5500` USB stick "Wilk" (SuperSpeed, mass storage 08/06/50),
  - `usb2 port 1: 05e3:0610` and `port 5: 05e3:0620` – Genesys Logic hub (USB 2.1 high-speed part + USB 3.2
    SuperSpeed part of the same hub); devices behind it – step d.
- Speeds after port reset are real (camera and hub high speed; before the reset they showed "full speed").
- Stress with no regression: compare **434 021** (v0.23.0: 436 765, v0.22.0: 436 134), `pass=1`, ping-pong 6.75 µs.
- Conclusion: the keyboard does not need hubs – **order changed: M20.e (HID keyboard and mouse) first, then d**.

### M20.c: USB device recognition (enumeration) + `lsusb`
- usbd: **port state machine** from the M20.a design – connect → 100 ms debounce → port reset (USB 2, ≤ 500 ms; a USB 3
  port with an already trained link needs no reset) → Enable Slot → Address Device → device descriptor (8 B: EP0
  packet size, Evaluate Context if needed; then 18 B) → configuration (9 B, then the whole thing ≤ 4 KiB) → strings
  (vendor, product) → "Running". Every command and transfer has a 1 s timeout. Error → Disable Slot, retry after 500 ms,
  after 3 attempts the port is ignored until disconnect. Disconnect in any state → Disable Slot, DMA pages return to the pool.
  STALL → Reset Endpoint + Set TR Dequeue (e.g. a device without a string).
- **Only descriptor read requests are sent to devices** – no Set Configuration or endpoints (step e/f); nothing
  is sent to the USB stick other than GET_DESCRIPTOR.
- New parser `user/lib/usb_desc.rs` (pure code: no MMIO, allocation or panics): device descriptor, configuration
  with interfaces, endpoints and HID, UTF-16 strings → ASCII. Limits: configuration ≤ 4 KiB, 8 remembered interfaces
  (setting 0; beyond that – skipped, not an error), ≤ 64 interface descriptors with alternate settings (cameras),
  16 endpoints per interface; bLength < 2 (infinite loop), running past wTotalLength, more endpoints than
  declared, bulk / interrupt with size 0, endpoint before interface → error.
- New `/bin/usbparse` (USB TEST 1/3): valid samples (HID keyboard, mass storage, camera with 20 alternate
  settings, 9 interfaces), 21 malicious cases with the expected error, **10 000 mutations** with a fixed seed
  (4 497 accepted within limits, 5 503 rejected, zero panics). Mutation test: removing the "past
  wTotalLength" check – detected.
- New command **`lsusb`**: queries every `usbN` service ("list"), one line per device – port, VID:PID, speed, USB version,
  address, kind (keyboard, mouse, mass storage, hub, Bluetooth, camera…), interface classes, vendor and product.
  Ports with errors are shown too (reason, which attempt).
- `test.sh`: QEMU gets `usb-kbd` and `usb-mouse` next to the USB stick. USB TEST 2/3 (29 checks): 3 devices (08/06/50,
  03/01/01, 03/01/02) named "QEMU USB …", kill during a command series and **during enumeration** → the new instance
  recognizes everything again; 3/3: `lsusb` via init. After each: ownership, bus mastering, vectors and frames – clean.
- QEMU TCG in my runs: 28/28 with 1, 2 and 4 CPUs; usbd start with enumeration ~155 ms. Normal boot with a hub: the QEMU hub
  (0409:55aa) recognized as "hub" – devices behind it are step d.

## v0.23.0 — 2026-10-12

### ✅ M20.b on real hardware (KVM + the test laptop)
- KVM 8 CPUs: 28/28, stress 177 971 (v0.22.0: 174 257 – noise), No-Op 58–70 µs (every command waits for an interrupt,
  and waking a sleeping virtual CPU through the host is costly – like the 32 µs for `edu` in M19), `polled=0`.
- **Test laptop (16 threads): 3 xHCI controllers found by class and started** – `usb0` = 01:00.2 NVIDIA 10de:1aec (the graphics card's
  USB-C; 6 ports, scratchpad 3, BIOS: not owned, No-Op 230 µs, nothing connected), `usb1` = 05:00.3
  and `usb2` = 05:00.4 AMD 1022:1639 (6 ports each: USB 2 1–4, USB 3 5–6; scratchpad 2; **BIOS: handed over**; No-Op
  5.0 µs). Connected: `usb1` port 3, `usb2` ports 1, 3, 4 – among them the built-in ITE keyboard (M20.c will recognize them).
  The "full speed" shown on USB 2 ports before port reset is not the final value – a high-speed device
  only reveals itself during reset (chirp), so the real speeds will come from enumeration.
- Stress on the test laptop with no regression: compare **436 765** (v0.22.0: 436 134), `pass=1`, ping-pong 6.75 µs; three usbd
  instances in the background cost nothing.
- To check at some point: No-Op 230 µs on the NVIDIA controller (interrupts do arrive – with polling it would be
  ~10 ms; suspicion: PCIe link waking from power saving).

### M20.b: USB controller (xHCI) startup in the `usbd` service
- First step of M20 (USB in user space, design: `ARCHITECTURE.md`, "USB (M20 – projekt 20.a)"). No
  USB devices yet – the controller starts, accepts commands and sees ports; enumeration is M20.c.
- Kernel: syscall **48 `dev_find(hw_root, class, nr)`** – address of the `nr`-th PCI device with the given class (24 bits), only
  with `HW_ROOT` (`EBADF`), `EINVAL` for a class > 24 bits, `ENOENT` past the last one. Claims nothing – access is
  decided by `dev_claim`. Profile: 51 numbers (49 `input_inject`, 50 `blk_attach` reserved per the design).
- Init: finds xHCI controllers by class 0C0330 and adds a service `usb0`, `usb1`, … for each (`/bin/usbd`,
  restart with backoff like every service since M19). Log: `init: usb0 = xHCI USB controller 00:03.0`.
- New `/bin/usbd` (one per controller): registers from BAR0; **handoff from the BIOS** (USB Legacy Support: OS Owned,
  ≤ 1 s, then forced as in Linux; SMI disabled); halt and reset (HCRST, each step with a 1 s timeout);
  DCBAA, scratchpad buffers, command ring (Link + Toggle Cycle), event ring (interrupter 0), MSI via
  `irq_bind`, Run; port power (PPC); **No-Op** commands waiting for an interrupt (with a `polled` counter
  in case interrupts don't arrive – diagnostics for the test laptop); port change events (clearing RW1C bits without
  touching PED). On the console: model, version, slots, USB 2 / USB 3 ports, BIOS state, connected devices
  with speed, No-Op time. Clients via `svc` ("usb0"): `status`, `noop N`. Controller error (HSE / HCE) →
  exit with code 3 → init restarts it, the new instance does a full reset.
- DMA without an IOMMU documented in a usbd comment and in `ARCHITECTURE.md` – process isolation protects against a crash, not
  against faulty DMA.
- New **USB TEST** suite (28 suites): 1/2 `/bin/usbtest` (19 checks: `dev_find`, startup, No-Op, ports – QEMU boot USB stick
  visible, `noop 2000`, bad request, **kill during a command series → full reset by the new instance**,
  voluntary exit, controller free); 2/2 `init test /bin/usbtest` – init finds the controller on its own and starts
  `usb0`, status via `svc`. After each: ownership released, bus mastering disabled, MSI vectors and DMA frames returned.
  `[RESULT-USB]` line in `test.sh` (startup, No-Op, restart after kill).
- QEMU TCG in my runs: 28/28 with 1 and 4 CPUs; usbd start ~115 ms (including 100 ms for port reports), No-Op 6–20 µs,
  `polled=0` (interrupts work), restart after kill ~110 ms. Normal boot: `usb0: port 1: device connected,
  SuperSpeed (5 Gb/s), enabled` (boot USB stick).

## v0.22.0 — 2026-10-12

### ✅ P3 closed (KVM + the test laptop)
- KVM 8 CPUs: 27/27, stress 174 257 (within noise; compare on KVM is limited by the pool), waits on "frames" 8.2M → 4 351,
  spawn 34.1 → 23.4 µs, reap 26.0 → 15.1 µs.
- Test laptop, 16 CPUs: compare **436 134** (v0.21.0: 412 608, +5.7%), max6 **528 869** (473 223, +11.8%), `pass=1`,
  ping-pong 6.75 / 6.5 µs. "frames": 48 / 60M waits → 17 / 26k, CPU 4 / 6% → 0%. spawn 48.3 → 24.5 µs
  (compare), 54.3 → 27.3 µs (max6).
- The whole P phase since M18 (v0.18.4: 392 943 / 448 079): **+11% compare, +18% max6**.
- Now the largest: the scheduler lock (37–41% of acquisitions wait, 15–19 s of waiting per 960 s of CPU ≈ 1.6–1.9%), heap
  in max6 again at 1.1M waits (1.0% CPU).

### P3: per-CPU physical frame caches
- Reason (test laptop, v0.21.0): the frame allocator lock "frames" – 48 / 60M waits per minute (compare / max6),
  4 / 6% CPU; every process takes dozens of frames (image, stack, page tables), all under a single lock.
- Each CPU keeps up to 64 free frames; `alloc_frame` / `free_frame` pop / push with interrupts
  disabled, without a lock. Empty – a batch of 32 frames is taken under the lock; full – 32 go back to the bitmap.
  `free_frame_count` counts cached frames as free (leak tests unchanged).
- A second "allocated" bitmap (atomic, same range as the free bitmap, 2× larger): every allocation path sets the
  bit, `free_frame` clears it first (`fetch_and`) – without a lock it rejects double-free (including a frame already
  in a CPU cache), reserved frames and addresses outside RAM.
- Contiguous ranges (`alloc_frames*`, `alloc_frame_below`, DMA) – under the lock as before.
- New test ALLOC TEST 4/5: rejections (0, unaligned, outside RAM, reserved, double-free from cache), k tasks
  of 400 tagged frames each (no frame with two owners), half freed on another CPU, the free-frame counter
  returns exactly. Mutation tests: accepting a double-free and handing out the same frame twice – detected.
- Stress TCG (8 CPUs): waits on "frames" ~2.8k (v0.20.0) → 13. Self-tests 27/27 with 1/2/4 CPUs (once TIME TEST
  790 ticks per RTC second – loaded host on my side, unrelated), stress PASS, no warnings.
## v0.21.0 — 2026-10-11

### ✅ P2 closed (KVM + test laptop)
- KVM 8 CPUs: stress **177 373** (record; v0.20.2: 166 373), heap waits 2 395 873 → 113 785 (−95%),
  spawn 41.8 → 34.1 µs.
- Test laptop (16 threads), 16 CPUs: compare **412 608** (v0.20.2: 394 272, +4.7%), max6 **473 223** (447 314, +5.8%), `pass=1`,
  ping-pong 6.6 / 6.85 µs. Heap: 7.23 / 7.66 M waits → 0.66 / 0.86 M (−90%), CPU 6.0 / 7.5% → 0.4 / 0.6%.
- Next bottleneck: the frame allocator ("frames": 48 / 60 M waits, 4.0 / 6.0% CPU) and the scheduler
  lock (27–35% of acquisitions wait, 5.7 / 12.1 s total on 16 CPUs ≈ 0.6–1.3% CPU).

### ✅ P1 closed (test laptop, 16 CPUs, v0.20.2)
- compare **394 272** scripts (v0.19.7: 388 883, +1.4%), max6 **447 314** (443 666, +0.8%), `pass=1`, ping-pong
  6.75 µs. The "process table (zombies)" lock is gone (it was 168 s of waiting in max6). Scheduler lock in max6:
  6.3 s of waiting (was 13.1 s). Bottlenecks now: heap (7.2–7.7 M waits, 6–7.5% CPU) and the scheduler.

### P2: large heap classes (4–32 KiB) on per-CPU lists
- Measurement of the heap slow path under stress (temporary counter, 8 CPUs): 164 k allocations outside the CPU lists –
  89% are 2–8 KiB blocks, 7% 16–32 KiB, the rest: 32–128 KiB (~1 per script) and 64 B alignment (~1.5 per script).
- Per-CPU list classes extended from 16 B..2 KiB to 16 B..32 KiB (12 classes). Large classes keep fewer blocks per
  CPU (4 KiB: 8, 8 KiB: 8, 16 KiB: 4, 32 KiB: 2 – at most 224 KiB per CPU). Local result: slow-path allocations
  164 k → 6.7 k (−96%), heap lock waits in TCG stress ~17 k → ~0.9 k; heap
  mapped 2.3 → 4.0 MiB (8 CPUs).
- Test: ALLOC TEST 3/4 (producers / consumers on different CPUs) also with 2049 B, 4, 6, 12 and 32 KiB blocks.
- Left for later: 32–128 KiB blocks (pipe buffers, ELF at spawn) and objects with 64 B alignment.
- Self-tests 27/27 at 1/2/4 CPUs, stress PASS, no warnings.

## v0.20.2 — 2026-10-11

### P1 cont.: the real cause of the increase in heap waits
- On the developer's machine (v0.20.1): 27/27 TCG and KVM, stress KVM 166 362, but the "heap" spin is still 3.61 M (v0.19.7: 2.39 M) –
  the hypothesis from v0.20.1 (zombie list allocation) was wrong: the number of allocations did not change.
- Cause: the `IrqSpinLock` in `Process`. `RawSpin` has `#[repr(align(64))]` (its own cache line), so the whole
  `Process` got 64 B alignment, while the heap only serves blocks up to 2 KiB with 16 B alignment on the fast path –
  every process (a million per minute) took the slow path: a global block list under a single lock. This is also visible
  in the profile: spawn 38 → 44 µs, reap 25 → 30 µs.
- The zombie list now has its own one-byte lock (`procs::ChildList`: interrupts disabled for the critical section,
  no lockdep, never two at once) – `level::CHILDREN` removed. Compile-time assertion: `Process` ≤ 2 KiB
  and alignment ≤ 16 (so this does not happen again).
- Takeaway for P2: frequently allocated objects with a `SpinLock` (alignment 64) (channels, pipes, files) also take the heap
  slow path – to be checked.
- Self-tests 27/27 at 1/2/4 CPUs, stress PASS, no warnings.

## v0.20.1 — 2026-10-11

### P1 cont.: zombie list without the heap
- Confirmed on the developer's machine (v0.20.0): 27/27 TCG and KVM, stress KVM 8 CPUs 168 711 scripts, `pass=1`; the
  "process table (zombies)" lock no longer appears in the report.
- But heap lock waits rose by 45% (2.39 → 3.47 M): every process with children allocated and freed
  its own `Vec` for zombies. Now `procs::Zombies` – 4 entries inline in the process (no allocation), only further ones go into
  a `Vec`. Reaping in any order (as in POSIX).
- famtest (200 children at once) also checks overflowing past 4 entries. Self-tests 27/27 at 1/2/4 CPUs, stress PASS.

## v0.20.0 — 2026-10-11

### P1: zombies in the parent process (end of the global ZOMBIES table)
- Reason (test laptop v0.19.7, max6): the "process table (zombies)" lock – a single sleeping lock for all
  processes: 12.3 M acquisitions per minute, 168 s of waiting in total (compare 46 s).
- Each process now has its own list of zombie children (`Process.zombies`, `IrqSpinLock` level 52 – new
  `level::CHILDREN`) and a `child_gen` counter:
  - child exit: under the scheduler lock (`with_process` on the parent) – checks that the parent is still its
    parent (otherwise tries the new one) and that it is not exiting; zombie entry and −1 live children in one section,
  - parent exit: `sched::reparent_with` – in one section under the scheduler lock: `exiting`, taking
    its own zombies, handing over live children (init also gets its live-children counter +n in the same section –
    previously done separately, with a small race); zombies passed to init,
  - `wait`: only the lock of its own list (no scheduler lock for ANY); ECHILD only after checking that
    `child_gen` has not changed (a child could have added itself and disappeared between checks).
- init in `init test` mode: at the end "init: test program ended, N orphans reaped".
- New test NOBKL TEST 10/10 – `/bin/famtest` under a real init (registered as init): 200 children
  at once (each status once, correct code), wait(pid) in reverse order, WNOHANG, 8 × 25 orphaned grandchildren →
  init reaps exactly 200, 4 parents with 50 children each in parallel. Mutation test: lost handover of orphans
  to init – detected.
- Self-tests 27/27 at 1/2/4 CPUs, stress PASS, no warnings; under stress the zombie lock is no longer on the list
  of waited-on locks.

## v0.19.7 — 2026-10-11

### ✅ M19 closed (test laptop, 16 CPUs)
- Confirmed on the developer's machine (v0.19.7): 27/27 TCG and KVM, stress KVM 8 CPUs 172 059 scripts; KVM measurement: interrupt
  34.6 µs kernel / 31.4 µs service, service restart 1.2 ms.
- Test laptop (16 threads): compare **388 883** scripts (M18: 392 943), max6 **443 666** (M18: 448 079) – −1%, within noise;
  ping-pong 6.55 / 6.75 µs, channel 930 MB/s (compare), `pass=1` in both modes. In QEMU (`run-qemu.sh`): `services`
  shows edu and echo, `mem` via sysinfo, `sync` works, `mkfs 0` rejected.
- To improve (next step): under full load the process table lock ("process table (zombies)")
  waits 168 s in total on 16 CPUs (13% of acquisitions had to wait); in compare 46 s.

### M19.i: end of the `kcmd` bridge – `sysinfo` and `sysctl` behind a handle
- Confirmed on the developer's machine (v0.19.6): 27/27 TCG and KVM, stress KVM 8 CPUs 174 243 scripts, `pass=1`.
  KVM measurement: interrupt → driver 32.6 µs kernel / 31.9 µs service, factorial 53.1 / 55.5 µs, via `edud`
  84.4 µs, PING 22.6 µs, restart 1.2 ms (described in ARCHITECTURE.md, "Measurement").
- Syscall 21 `kcmd` removed (ENOSYS). New:
  - 46 `sysinfo(topic, buffer)` – read-only: ver, uptime, date, mem, irq, cpus, lspci (-v), acpi, disk (list),
    mount, df; ERANGE when the buffer is too small.
  - 47 `sysctl(handle, action, arg, fd)` – reboot, halt, sync, stress [s]; only with a `SYSCTL` handle (kind 9,
    DUP right only). The kernel creates it for init (slot 4), init gives it to the shell, the shell does not pass it to programs.
- `/bin/sh`: `mem`, `lspci`… via sysinfo (with redirection); built-in `sync`, `reboot`, `halt`, `stress`;
  `mkfs`, `disk read/write`, `run`, `k` → "only in the kernel emergency shell". Without the SYSCTL handle reboot
  refuses (shell not started by init).
- Tests: INIT TEST 4/9 (sysinfo with redirection, mkfs / k / disk read / reboot rejected), svctest 42
  checks (sysinfo, SYSCTL rights, EBADF / EINVAL, it cannot be sent, a shell without it refuses, kcmd = ENOSYS).
- Self-tests 27/27 at 1/2/4 CPUs, stress PASS, no warnings.

## v0.19.6 — 2026-10-11

### M19.h: measurement – in-kernel driver vs user-space service
- Confirmed on the developer's machine (v0.19.5): 27/27 TCG and KVM, stress KVM 8 CPUs 172 953 scripts, `pass=1`.
- SVC TEST 7/7 measures the same work on `edu` (each measurement ≥ 200 ms):
  - interrupt → woken driver (kernel: `WaitQueue` + MSI handler; user space: `wait_many`),
  - factorial completed by interrupt: kernel / driver in a process / client via the `edud` service,
  - `PING` via the service (pure IPC cost) and service restart (kill → new instance responds).
- Line `[RESULT-SVC] ver=… irq_kernel_ns irq_user_ns fact_kernel_ns fact_user_ns fact_svc_ns ping_svc_ns
  restart_us` – `test.sh` prints it under "Log:". It is absent in autostress (edu is held by `edud` from init).
- `/bin/svcbench`: with HW_ROOT – full measurement; from the shell – PING and factorial via the `edu` service from init.
  svctest: +1 check (svcbench from the shell via the service manager).
- Self-tests 27/27 at 1/2/4 CPUs, stress PASS, no warnings.

## v0.19.5 — 2026-10-11

### M19.g: service manager in init (variant A)
- Confirmed on the developer's machine (v0.19.4): 27/27 TCG and KVM, stress KVM 8 CPUs 168 140 scripts, `pass=1`.
- `/bin/init` starts services from a table: `edu` (`/bin/edud`, device 00:06.0) and `echo` (`/bin/echod`, no
  device). Restart after exit with a 100 ms delay, doubled up to 5 s (after 10 s of running back to 100 ms); 5 failures
  within 30 s → "broken". Missing device → "no device" (test laptop: no edu, echo works).
- Connecting by name: the shell and programs have, in slot 3, a channel to init (send only). `svc_connect("edu")`
  – init hands the client's channel end to the service; unknown / down service → `EPIPE`. `svc_list` and a new
  `services` command (state, pid, restarts, program).
- `/bin/echod` – the simplest service (echoes messages, `pid`, `crash` → code 7), a template and a test on hardware without edu.
- The shell passes slot 3 to the programs it starts (`spawn_ex`) if it received it itself.
- `init test <program>` – self-test mode; SVC TEST 6/6: real init + `/bin/svctest` (28 checks: svc
  channel rights, list, echo by name, restart after a crash with a new pid, edu via the manager, edud restart after kill,
  unknown service and bad requests, `sh -c services`, broken after 5 failures). After the test: edu free, bus mastering
  off, vectors and frames returned.
- Self-tests 27/27 at 1/2/4 CPUs, stress PASS, no warnings.

## v0.19.4 — 2026-10-11

### M19.f: edud – the first user-space service (`edu` driver)
- Confirmed on the developer's machine (v0.19.3): 27/27 TCG and KVM, stress KVM 8 CPUs 166 889 scripts, `pass=1`.
- `/bin/edud`: the edu device driver as an ordinary process. Handles at startup: 1 console, 3 device,
  4 connection channel (in 19.g the service manager in init will provide them). Registers via `dev_map`, factorial and DMA complete
  with an interrupt (`irq_bind` + `wait_many`; completion is decided by the device status), 8 KiB DMA buffer.
  A single `wait_many` loop: connection channel + interrupt + up to 14 clients. Requests are handled one at a time
  (there is one device); the reply is sent without waiting (a client that does not receive will not stall the service).
  Exit: connection channel closed and no clients – code 0.
- Protocol (`user/lib/edu_proto.rs`, shared by the service and clients): 16 B header + data; `PING`
  (identification 0x010000ed), `FACT n` (factorial on the device, 13! = EINVAL – does not fit in the register),
  `COPY` (up to 4000 B: service buffer → device → buffer via DMA), `STATS`. Bad request – EINVAL reply,
  the service keeps running. Connection: the client creates a channel and sends one end to the service's connection channel.
- `/bin/edutest` (16 checks) – starts the service like the future manager (claim from HW_ROOT, `spawn_ex`),
  client: PING, factorials 0..12, copying 4000 B via DMA, bad / short request; 4 client processes with 50 requests each
  at once; **killing the service → client gets EPIPE, the device returns, a new instance works** (manual restart – in
  19.g init will do it); close – the service exits on its own. Kernel after the test: device free, bus mastering
  disabled, vectors and frames returned. SVC TEST 5/5 (219 requests served by the service).
- Self-tests 27/27 at 1/2/4 CPUs, stress PASS, no warnings.

## v0.19.3 — 2026-10-11

### M19.e: DMA – the device reads and writes the service buffer by itself
- Confirmed on the developer's machine (v0.19.2): 27/27 TCG and KVM, stress KVM 8 CPUs 168 412 scripts, `pass=1`.
- Syscalls: 44 `dma_alloc(dev, size, address_bits)` → shared memory handle (mapped via
  `shm_map`) of **contiguous** frames lying entirely below `2^bits` (24..=64; `edu` only sees 28 bits and
  truncates the higher ones – a buffer above that would hit someone else's memory); ≤ 2 MiB per buffer, ≤ 16 MiB per device (`ENOMEM`);
  requires `MAP_WRITE`; enables bus mastering. 45 `dma_phys(buffer)` – physical address (`EINVAL` for ordinary shared
  memory; no BKL).
- **A DMA buffer lives as long as the device claim** (`DevClaim` holds a list) – closing the handle and
  munmap do not free it; frames return only after bus mastering and MSI are disabled when the device is released.
- Frame allocator: `alloc_frames_below(n, align, limit)` – contiguous frames below an address.
- `/bin/dmatest` (23 checks): rights, sizes, bus bits, `dma_phys`; edu reads the buffer (RAM → edu) and
  writes it into the second half (edu → RAM), twice with different patterns, each transfer completing with an interrupt;
  a closed buffer is not handed to someone else (verified by mutation: without the list in the claim a new buffer gets the same
  frames – FAIL); 16 MiB limit; kill of a process with a DMA buffer and an interrupt. Kernel after the test: frames returned
  (15 MiB of buffers), bus mastering disabled, device free. SVC TEST 4/4.
- **irqtest – corrected assumption:** 10 fast interrupts can yield a counter < 10 – interrupts on the same vector
  that arrive before the CPU has handled the previous one are coalesced into one by the APIC (once locally: 9 of 10). The counter means
  "at least one interrupt since the last read", not an exact count; the service checks the device status.
  The test now checks 1..=10 and all bits in the edu status register. Described in ARCHITECTURE.md.
- Self-tests 27/27 at 1/2/4 CPUs (4 CPUs – 3 times in a row), stress PASS, no warnings.

## v0.19.2 — 2026-10-11

### Test fix: false "frames leaked"
- On the developer's machine (v0.19.1, once in two runs): `[IPC TEST] FAIL: frames leaked (115418 -> 115478)` – at the end
  of the suite MORE free frames than at the start. Cause: the starting measurement was taken before reap (idle loop) cleaned up
  the processes of the previous suite (FILE TEST terminates processes via #PF and checks frames with a tolerance). New
  `selftest::settled_free_frames()` – reap until the free frame count stays unchanged for 3 samples 5 ms apart –
  as the baseline in ELF, SYSCALL, INIT, IPC and SVC TEST. It was not a kernel leak.

### M19.d: device interrupts in user space
- Syscalls: 42 `irq_bind(dev)` → **IRQ** handle (kind 8, `RECV` right; requires `MAP_WRITE` on the device) –
  MSI vector (or MSI-X entry 0), bus mastering (MSI is a device write to memory); `EBUSY` – already bound
  or no vectors left, `ENODEV` – device without MSI. 43 `irq_read(irq)` – interrupts since the last read
  (resets; no BKL). `wait_many` with the **`W_IRQ`** signal.
- `device.rs`: static vector ↔ counter + observers slots (the handler does not touch memory that could be
  freed); handler: counter + wakeup – nothing more. MSI is edge-triggered – no masking; several interrupts before
  handling = one wakeup with a counter.
- **Freeing vectors** (`msi::free`, `free_count`) – previously a vector once taken stayed taken forever; a service
  restarted 16 times would have used them all up. Dropping an IRQ handle: MSI off in the device, register read (write
  has landed), vector free. Dropping a device claim: MSI off and **bus mastering off** before the device is returned.
  `pci.rs`: `disable_msi`, `set_bus_master`.
- `/bin/irqtest` (25 checks on `edu`): rights and EBUSY, an on-demand interrupt wakes `wait_many`, counter and
  status in the device, 10 interrupts → 1 wakeup with counter 10, factorial 12! completed by interrupt instead of
  polling, interrupt and channel on one list (correct bits), 20 × bind / close (there are 16
  vectors), killing a process with a bound interrupt. The kernel checks after the test: vectors returned, edu bus mastering
  disabled, device free. Verified that without `msi::free` the test fails ("13 succeeded"). SVC TEST 3/3.
- Self-tests 27/27 at 1/2/4 CPUs, stress PASS, no warnings.

## v0.19.1 — 2026-10-11

### M19.c: device as a handle – HW_ROOT, dev_claim, dev_map
- Confirmed on the developer's machine (v0.19.0): 27/27 TCG and KVM, stress KVM 8 CPUs 166 070 scripts, `pass=1`.
- **HW_ROOT** (handle kind 6): created only in the kernel (`SpawnOptions::hw_root`) – `/bin/init` gets it
  in slot 3 (as do kernel tests). Rights 0: without `DUP` and `TRANSFER` it cannot be copied, given to a child or sent.
- **Device owner** (`drivers/pci.rs`): `OWNERS` table (free / kernel driver / service), virtio-blk
  and NVMe register as kernel drivers. `claim_user` refuses: in-kernel driver, class 0x01 (disks –
  always, even without a driver), 0x03 (graphics), 0x06 (bridges), 0x08 (system devices), functions
  that are not an ordinary device. `lspci` shows the owner.
- Syscalls: 39 `dev_claim(hw_root, bdf)` → **DEVICE** handle (kind 7; `MAP_READ|MAP_WRITE|DUP|TRANSFER`),
  errors `EACCES` / `EBUSY` (-16) / `ENODEV` (-19); 40 `dev_info` (vendor, device, class, BAR sizes, I/O
  BARs, MSI / MSI-X); 41 `dev_map(dev, bar, prot)` – BAR registers in the process, **uncached (UC), never
  executable**, MSI-X table / PBA pages skipped; the BAR must be ≥ 4 KiB and page-aligned (a
  shared page could contain another device's registers), ≤ 256 MiB. Under the BKL (PCI config access
  via ports is not safe on multiple CPUs at once; the syscalls are rare).
- `kernel/user/device.rs`: `DevClaim` (Arc – handles and mappings); Drop releases the device. `vm.rs`: a shared
  region has an owner `SharedRef` (shared memory or a device claim) – a mapping holds the
  claim, `munmap` only as a whole.
- **Process exit removes shared mappings immediately** (`exit_current`, not only at reap) – a claimed
  device is returned before the parent gets the status from `wait` (the test caught this: after kill the device was still
  busy).
- Profile: 48 syscall numbers (was 40). QEMU in `test.sh`, `stress-qemu.sh`, `run-qemu.sh`: `-device edu,addr=06`.
- `/bin/devtest` (37 checks): HW_ROOT cannot be copied / sent / passed on, refusals for a bridge, VGA,
  virtio-blk, NVMe, ISA bridge, SATA; edu: claim, EBUSY, `dev_info`, registers (identification 0x010000ed,
  liveness register, factorial 10! via MMIO), mapping rights, munmap as a whole, claim held by the
  mapping, write through a read-only mapping = #PF, kill of a process with a mapped device → free.
  SVC TEST 2/2. Self-tests 27/27 at 1/2/4 CPUs, stress PASS, no warnings.

## v0.19.0 — 2026-10-11

### M19.a: design of user-space services
- `ARCHITECTURE.md`, "User-space services": `wait_many`, `HW_ROOT` / `dev_claim` / `dev_map`, interrupts as
  counter + wakeup, DMA (buffers live with the device claim, cleanup: bus mastering off → vector → frames),
  service manager in init (variant A; variant B – a separate `/bin/svcmgr` – described for later), first service
  `edu` from QEMU, end of `kcmd`, syscall numbers 38–46. Accepted by the developer.

### M19.b: wait_many – waiting on multiple handles at once
- Syscall 38 `wait_many(list, n, timeout_ms)`: a list of up to 16 [handle, signals] pairs, result = mask of ready
  entries (0 = timed out; `u64::MAX` = no limit, 0 = just check). Signals: `READABLE` (channel: a message
  or the other side closed; pipe: data or no writers), `WRITABLE` (space or the other
  side closed); `IRQ` reserved for 19.d. Rights as for the operation: `RECV` / `SEND`, `READ` / `WRITE`. The whole list
  is checked before waiting (EINVAL / EBADF / EACCES / EFAULT). Kill interrupts (EINTR). No BKL.
- `kernel/user/waitset.rs`: `Observers` – a list of waiting tasks' channels in each object (channel end
  queue, pipe), `IrqSpinLock` at a new `WAITERS` level (45 – above channels / pipes, below the scheduler).
  `wait_many` registers with the objects, sleeps on its own WaitQueue, unregisters after wakeup. Objects wake
  observers on every change (message, space, close). Observer counter – `notify` without
  waiters does not take the lock (every send / recv calls it; without this ping-pong in TCG is ~30% slower).
- `/bin/waittest` (34 checks): list errors, timeout, channels and pipes, the same handle twice,
  closed other side, wakeup by a message from a child, **a server handling 4 clients at once** (2000 requests,
  sender from the kernel), full queue, kill of a process waiting in `wait_many`. Verified that without waking
  observers the test hangs (FAIL).
- New self-test suite **SVC TEST** (27 suites). Profile: name `wait_many`. Library: `wait_many`,
  `W_READABLE` / `W_WRITABLE` / `W_IRQ`, `FOREVER`.
- Self-tests 27/27 at 1, 2 and 4 CPUs, stress 8 CPUs PASS, no warnings.

## v0.18.4 — 2026-10-11

### M18.f: IPC under load, measurement, [RESULT] line
- **M18 closed (2026-10-11, test laptop 16 CPUs, 60 s):** compare mode **392 943 scripts** (v0.17.35: 360 713,
  +9%) + 5056 ipcload tasks (1 011 200 exchanges, 5056 children killed while waiting); full load (pool 6)
  **448 079** (v0.17.35: 447 028). `ipcbench`: ping-pong **6.6 µs**, channel 165–190 k msg/s × 4 KiB
  (645–744 MB/s), 16 MiB via channel 21–25 ms / via shared memory 5 ms. 0 deadlock reports, 0 measurements
  with negative time, `pass=1` in both modes. KVM 8 CPUs: 171 891 scripts, ping-pong 5.6 µs (self-test).
- Developer's measurement (v0.18.3, KVM, 4 CPUs): ping-pong **6 µs** per exchange; 26/26 (TCG and KVM), stress KVM 8 CPUs
  154 988 scripts.
- `/bin/ipcload`: the parent writes 4 KiB of a pattern into shared memory and rings via a channel, the child (spawn_ex:
  channel + read-only memory) computes the sum and replies – 200 exchanges; at the end the parent kills the child
  waiting in `chan_recv` (with mapped memory) and checks that its channel end disappears (EPIPE).
- Stress: a third task kind – one `ipcload` per control loop, **outside the script pool** (compare mode
  stays comparable; the IPC task takes a bit of CPU). New report row `ipc:` (tasks, exchanges, killed
  children).
- `/bin/ipcbench`: 8 B ping-pong (20 000), channel throughput (20 000 × 4 KiB one way: msg/s, MB/s),
  16 MiB via channel (4 KiB messages) versus shared memory (1 MiB chunks + doorbell), with checksums.
  Autostress runs it after the stress and prints the result.
- **`[RESULT]`** – the last line of autostress: `ver mode cpus ms scripts primes ipc idle pingpong_ns chan_msgs
  chan_mbs chan16_ms shm16_ms pass` (error: `pass=0 error="…"`). `stress-qemu.sh` waits for it and prints it;
  timeout + 180 s (measurement after the stress).
- `/bin/ipcdemo` – a demo to run in the shell: channel, `spawn_ex` with three handles (channel, console,
  memory), text back and forth, the child writes to shared memory, the parent reads after the doorbell.
- IPC TEST 5/5: ipcload, ipcdemo (output checked), ipcbench (result in the log). QEMU TCG: ping-pong ~240 µs,
  channel ~25 000 msg/s (~100 MB/s), 16 MiB: channel ~130 ms / memory ~75 ms.
- Self-tests 26/26 at 1, 2 and 4 CPUs, stress 8 CPUs PASS with `ipc:` and `[RESULT]`, no warnings.

## v0.18.3 — 2026-10-11

### M18.e: shared memory
- `kernel/user/shm.rs`: shared memory object – frames taken immediately and zeroed, size rounded up to
  4 KiB, at most 16 MiB. Reference-counted via `Arc` (handles + mappings); frames return in `Drop` when the last
  handle and the last mapping go away.
- `vm.rs`: a new region kind `Shared` – the whole object mapped at once in the mmap area, always NX, write only with
  the `MAP_WRITE` right. `munmap` of a shared region only as a whole (partial – EINVAL) and without freeing frames;
  `fault_in` does not substitute a private page in a shared region.
- **Process exit:** dropping the address space frees every mapped frame – a new `Drop for Process`
  first removes shared mappings (`release_shared`). Verified that without this the test detects corrupted data
  (the object's frames returned to the pool after one of the processes exited).
- Syscalls: 34 `shm_create(size)`, 35 `shm_map(h, prot)`, 37 `shm_size(h)` (no BKL, like brk / mmap).
  Handle: `MAP_READ|MAP_WRITE|DUP|TRANSFER`; `read`/`write` on it – EBADF.
- IPC TEST 4/4: `/bin/shmtest` – 29 checks: sizes and errors, zeroed memory, two mappings of the same
  pages in one process, read-only handle (writable mapping – EACCES), partial / full munmap,
  a writer child gets the handle via a channel, writes 64 KiB and rings via the channel, a reader child with
  a read-only handle computes the sum, write to a read-only mapping / jump into shared memory /
  access after munmap – child killed by #PF, the object lives after its handles are closed as long as it is mapped;
  zero frame leaks (checked by the suite).
- Self-tests 26/26 at 1, 2 and 4 CPUs (QEMU TCG, 4 CPUs twice), stress 8 CPUs PASS, no warnings.

## v0.18.2 — 2026-10-11

### M18.d: handles in messages, spawn_ex
- Developer's measurement (v0.18.1, KVM, 4 CPUs): ping-pong via a channel **8 µs per exchange** (message there and back,
  two process switches); stress KVM 8 CPUs 153 500 scripts – unchanged.
- `chan_send` with a list of handles (up to 8): handles are **moved** – they disappear from the sender's table, require
  `TRANSFER`, rights unchanged. The list is checked in full before anything is removed (exists, `TRANSFER`,
  no duplicates – EBADF / EACCES / EINVAL). No channel end may travel through that same channel
  (EINVAL; earlier in the design – only the sending end; the other end would also create a cycle). Send error
  (full queue, EPIPE, kill) – handles return to their original numbers.
- `chan_recv`: handles at the receiver get the lowest free numbers, numbers written to an array supplied by the process;
  not enough room for the numbers – EMSGSIZE (`info.handles` = how many), full handle table – EMFILE; in both
  cases the message stays in the queue. Handles in messages to a closed end – freed.
- 36 `spawn_ex(path, argv, map, n | flags)` – the child gets **only** the handles from the map [(parent handle,
  number in child)], n ≤ 16, number < 64 without duplicates, each requires `DUP`. Without a map the child does not even have
  a console. `spawn` (3 × stdio) and `spawn_ex` share common code (`spawn_common`); `spawn_child` takes
  the whole handle table.
- IPC TEST 3/3: `/bin/xfertest` – 32 checks: transfer and rights, EACCES without TRANSFER (handle
  stays), duplicate / bad number, both ends of its own channel (EINVAL), an end of another channel via a channel,
  EMSGSIZE and EMFILE without losing the message, freeing a channel end from an abandoned queue (EPIPE), `spawn_ex`
  errors, a child with a single handle (checks it has no other) gets a read-only file
  via a channel, reads, cannot write, replies; sender = parent's pid.
- Self-tests 26/26 at 1, 2 and 4 CPUs (QEMU TCG, 4 CPUs twice), stress 8 CPUs PASS, no warnings.
## v0.18.1 — 2026-10-11

### M18.c: channels
- `kernel/user/channel.rs`: a channel = a pair of endpoints, each with its own incoming queue (bidirectional).
  Messages up to 4 KiB, up to 64 in a queue, sender (pid) filled in by the kernel. Per-queue lock (PROCESS
  level, like a pipe), with only queue operations under it; data copied from the process before the lock and
  to the process after it. Waiting via a `WaitQueue` on atomics (`len`, `closed`) – no lost wakeups,
  interruptible by kill (EINTR). Closing the last handle to an endpoint: the queue is drained, the other side
  gets EPIPE (after receiving whatever had already arrived).
- Syscalls: 31 `channel_create`, 32 `chan_send`, 33 `chan_recv` (no BKL). Rights: sending requires `SEND`,
  receiving `RECV` (EACCES); `read`/`write` on a channel – EBADF. New errors: `EAGAIN` (-11, `CHAN_NONBLOCK`),
  `EMSGSIZE` (-90, message > 4 KiB or buffer too small – then the required size is in `info` and the message
  stays queued). The ABI already has room for handles in a message (M18.d; for now the handle count must be 0).
- IPC TEST 2/2: `/bin/chantest` – 28 checks: both sides, sender, empty message, EAGAIN on an empty and a
  full (64) queue, FIFO, EMSGSIZE, 4096 B, rights, EPIPE after close, ping-pong of 10,000 exchanges with a
  child (QEMU TCG: 122–250 µs per exchange), kill of a child waiting in `chan_recv` (its endpoint disappears).
- Profile fix (v0.18.0): when the syscall number range was extended, one name was missing – the `prof` table
  labels were shifted by one ("ctx switch" showed spawn:load, "TSC skew" – drv exec). The numbers were correct.
  Now there is a compile-time check: names must match the category numbers.
- Self-tests 26/26 on 1, 2 and 4 CPUs (QEMU TCG, 4 CPUs – 4 runs in a row), stress 8 CPUs PASS, no warnings.

## v0.18.0 — 2026-10-11

### M18.a–b: IPC design, handles with rights
- **M18.a** – IPC design in `ARCHITECTURE.md` ("IPC – channels, handles, shared memory"): handles with
  rights, channels (pair of endpoints, 4 KiB + 8 handles per message, 64 in a queue, sender filled in by the
  kernel), shared memory (max 16 MiB, always NX), `spawn_ex`, per-channel lock, syscall numbers 29–36,
  `[RESULT]` line. M18 roadmap: steps a–f.
- **M18.b** – descriptors became **handles**: a table entry = object + rights (`READ`, `WRITE`, `SEND`,
  `RECV`, `MAP_READ`, `MAP_WRITE`, `DUP`, `TRANSFER`). Initial rights match the previous behaviour (read-only
  file = `READ|DUP|TRANSFER`, pipe write end = `WRITE|DUP|TRANSFER`, console
  `READ|WRITE|DUP|TRANSFER`). Limit raised from 16 to 64 handles per process.
- New syscalls: 29 `handle_dup(h, mask)` – a copy with rights `old & mask` (rights never grow),
  30 `handle_info(h)` – object kind and rights. `read`/`write` without the right → `EBADF` (POSIX), copying
  (`dup`, `dup2`, `handle_dup`, child handles in `spawn`) without `DUP` → `EACCES`.
- Profile: room for syscalls 0–39 (new numbers do not collide with the #PF / interrupt categories).
- IPC TEST (new suite, 26 instead of 25): `/bin/handletest` – 23 checks: rights from the object, reducing,
  no escalation via `handle_dup(ALL)` / `dup` / `dup2`, EBADF / EACCES, a child after `spawn` gets a handle
  with the same rights and cannot increase them, limit 64; no frame leak.
- Self-tests 26/26 on 1, 2 and 4 CPUs (QEMU TCG), stress 8 CPUs PASS, no warnings.

## v0.17.35 — 2026-10-10

### Fixes before M18 – heap safety, cross-CPU test, two stress modes
- **Heap: a single block-size rule.** Small blocks (<= 2 KiB, alignment <= 16) are always rounded up to their
  class (power of 2), even when the per-CPU lists are disabled. Previously a block taken before
  `enable_cpu_caches` (e.g. 80 B as 80) and freed after (onto the 128 class list) would have handed 48 B of its
  neighbour to the heap. Today the lists are enabled right after heap init, so it never happened – but a change
  in startup order would have been enough. Now it is impossible.
- MM TEST 10/10: blocks with non-power-of-2 sizes taken before the lists are enabled, freed after, taken again
  and written in full (class size) – guard blocks intact. Verified against the old rule: the test catches the
  bug ("guard block 4 (1100 B) overwritten").
- ALLOC TEST 3/4: producers take blocks (12 sizes, all classes), fill them with a pattern, keep every fourth
  until the end, and pass the rest through a channel (SpinLock, at most 256) to consumers, which check the
  pattern, write over the block and free it – usually on a different CPU (4 CPUs: 14,860 of 18,000; 2 CPUs:
  6,103 of 9,000). No lost blocks and no leaks.
- **Stress: two modes, stated in the report** (`mode:` line). Default – comparative, unchanged (3 processes per
  CPU, at most 48). Full load: `DESOOS_STRESS_POOL=P` at build time (P processes per CPU, at most
  128) – e.g. `DESOOS_AUTOSTRESS=60 DESOOS_STRESS_POOL=6 ./make-usb.sh ...`. Results from different modes are
  not compared.
- Self-tests: 25/25 on 1, 2 and 4 CPUs (QEMU TCG).

## v0.17.34 — 2026-10-09

### Performance – M17b.h: per-CPU heap free lists (end of spinning on the `heap` lock)
- **The test laptop (16 threads)**, `spin wait` table: v0.17.32 – 49,797 scripts, v0.17.33 (stack cache) –
  51,068. In both, **the `heap` lock: ~70 million waits, 11 µs on average = 83% of all CPU time** spent
  spinning. The stack cache works (TLB shootdown: 373,494 → 476 requests, `sp:task` 235 → 126 µs), but next to
  the heap it is noise. This explains the slow file syscalls (270–420 µs with ~2.5 µs in the ramfs tree) – the
  kernel allocates paths and buffers in every syscall.
- Cause: the heap is a single address-sorted free list under an IrqSpinLock – walked on alloc (first-fit), and
  twice on dealloc (insertion + `shrink()` looking for the last node by walking the ENTIRE list on every free).
- `memory/heap.rs`: blocks up to 2 KiB (alignment <= 16) in classes 16..2048; each CPU has a free list per
  class – alloc / dealloc without a lock (interrupts disabled briefly). Empty list = a batch of blocks fetched
  in one visit under the lock; too long (~16 KiB per class) = half returned at once. Enabled after the heap
  self-test. `shrink()` gets the heap-end node from `insert_free` (no list walk). `used_bytes` excludes blocks
  on the lists.
- TLB 5 and ALLOC 1 tests: large blocks may land in heap holes – TLB 5 allocates 1 MiB at a time until the heap
  grows; ALLOC 1 requires a shootdown only if the heap grew.
- QEMU TCG 8 CPUs, 15 s: 650 scripts (v0.17.33: 559, v0.17.32: ~220).
- A/B: `ab/v0.17.33` (no heap lists), `ab/v0.17.32` (no heap lists and no stack cache).
- **Test laptop v0.17.34: 360,986 scripts + 180,491 primes in 60 s** (v0.17.33: 51,068, v0.17.28: 55,834) – 7x.
  `spin wait`: heap 3.0% CPU (was 83%), 37 million waits of 0.7 µs; 32% idle – the stress (pool of 48
  processes, 4 driver loops 18% busy) limits itself. Scheduler lock: 23% of acquisitions waited
  (28.7 million acquisitions, 4.1 s), process table 23 s of sleep. **M17b closed.**

## v0.17.33 — 2026-10-09

### Performance – M17b.g: task stack cache (no `stack-pages` lock on spawn / reap)
- **The test laptop (16 threads)** v0.17.32 (CPU time profile, 16 CPUs, 60 s): 53,234 scripts; per script
  `spawn` 5.2 ms CPU (of which loading the child 4.1 ms), `write` 1.9 ms, `stat` 1.1 ms; file operations at
  270–420 µs each, although the ramfs tree is held ~2.5 µs per operation. 45% of spinlock acquisitions waited
  (93 million of 205 million).
- Profile extended: `spawn` split into `sp:readfile` (program file into memory), `sp:elf+pt` (address space,
  segments, stack), `sp:task` (kernel stack + scheduler); new **spin wait** table – spinning time on spinlocks
  per lock name (TSC on a single CPU – preemption disabled).
- QEMU 8 CPUs: 38% of CPU time is spinning on `stack-pages` (20 ms on average!) in `sp:task` and `reap`. This
  global IrqSpinLock was held while creating a task's kernel stack across allocating and zeroing 16 frames,
  and while freeing it – across unmapping and a TLB shootdown to all CPUs, waiting for acknowledgements.
- **Stack cache** (`sched/stack.rs`): the stack of a finished task stays mapped (`MAPPED` bit, slot free)
  – spawn takes the lowest free slot as before and, if it has a stack, uses it without allocation, zeroing or
  locking; reap without unmapping and shootdown. At most 256 stacks (16 MiB), excess freed the old way.
  Frame-leak tests and stress count free frames after `flush_cache()` (unmaps the stack cache).
- QEMU TCG 8 CPUs: 559 scripts / 15 s (without the stack cache 145 / 10 s); `stack-pages` – 1 wait.
- A/B: `./ab-usb.sh v0.17.32 "/media/<user>/<usb-stick>"` – the same profile without the stack cache.

## v0.17.32 — 2026-10-09

### Measurement – M17b.f: kernel entry profile (time per syscall / exception / interrupt)
- **The test laptop (16 threads)** with v0.17.31: 50,987 scripts – +11% over v0.17.30 (45,773), but still ~9%
  below v0.17.28 (55,834). Per-script lock statistics unchanged, so the missing time is in the execution path
  itself.
- New module `user/prof.rs`: call count and TSC cycles (`rdtscp` – time and CPU number in one instruction),
  per CPU on separate cache lines. Measured: every syscall (from entry, including waiting for the BKL, to
  SYSRET), process #PF (lazy pages), PIT IRQ, LAPIC timer, switch IPI, task switch (excluding `sched_switch`
  itself), reap, process exit, child creation in `spawn` (`spawn:load`) and the stress loop's `exec`.
- Autostress / `stress`: the 12 most expensive entries – count, average µs, % of all CPU time, µs per script.
  Syscalls that may sleep (`(sleeps)`) report wall time, not CPU time.
- Autostress lines carry the version: `[AUTOSTRESS v0.17.32]` – a photo from the test laptop immediately shows
  which build was running (`stress-qemu.sh` recognises both formats).
- Fix after the first boot on the test laptop (panic in `prof.rs`: attempt to add with overflow): the TSCs of
  the Ryzen cores are not perfectly synchronised – a measurement started on one CPU and finished on another gave
  `t1 < t0`, and the subtraction wrapped around ~2^64 cycles. Such measurements are now counted separately
  (`TSC skew`, time 0), and the sums saturate.
- Second boot on the test laptop: a nonsensical table (`stat` 64 ms on average, `spawn` 6248% CPU) – the TSC
  offsets between cores are large, so every measurement with a migration was garbage in both directions
  (40,745 negative). The profile now measures **task CPU time**: the scheduler credits a task with the cycles
  from getting on a CPU to leaving it, both reads on the same CPU (`sched::task_cpu_cycles`). Sleep and other
  tasks' time are not counted; the `check:` line = number of negative measurements (must be 0).

## v0.17.31 — 2026-10-09

### Performance – M17b.e: per-CPU data and counters on separate cache lines (false sharing)
- Bisection on the test laptop (`./ab-usb.sh`, 60 s, 16 CPUs): v0.17.27 – 54,382, v0.17.28 (file objects,
  pipes) – 55,834, v0.17.29c (v0.17.28 + only #PF without IST) – 51,564, v0.17.30 with the old program heap –
  47,556, v0.17.29 / v0.17.30 – 47,880 / 45,773. The v0.17.29c change (#PF gate, per-CPU array) is not executed
  during stress, yet it cost ~7% – a symptom of dependence on the memory layout of variables.
- Cause: dense per-CPU arrays (`[AtomicU32; 16]` – 16 CPUs in 1–2 cache lines) written on hot paths – the
  preemption counter and held-spinlock counter (every acquire / release), the scheduler lock state, quantum,
  NEED_RESCHED, ticks – plus global statistics counters (`fetch_add` from every CPU: spinlock acquisitions
  ~200 million / 60 s, scheduler lock, syscalls). Every write invalidates the line on the other CPUs.
- New module `arch/x86_64/percpu.rs`: `PerCpu<T>` (each element on its own 64 B line, indexed like an array,
  `per_cpu!`), `PerCpuCounter` (each CPU adds to its own, reading sums them), `CacheLine<T>`.
  Migrated: all of the kernel's per-CPU arrays (cpu, spin, scheduler, smp, tlb, vm, stress), the spinlock,
  scheduler lock, BKL and syscall counters; `RawSpin`, site statistics entries and `SCHED_OWNER` – each on its
  own line.
- QEMU TCG: 1 CPU, 20 s – 693 scripts (v0.17.30: ~550, +25%); 4 CPUs, 15 s – 524 (~400–450).

## v0.17.30 — 2026-10-08

### Measurement – M17b.d2: process memory counters, fault-around as a knob
- **The test laptop (16 threads)** (16 CPUs, 60 s) with v0.17.29: 47,880 scripts (v0.17.27: 53,809, −11%);
  `SMP=8 ./stress-qemu.sh`: 38,363 (41,328). Locks unchanged (BKL 0.26 s, scheduler 2%, ramfs 2.2 s); process
  table 101 s (74 s).
- `cpus` / autostress: "process memory: N page faults -> M pages, K pages via kernel copy, brk/mmap".
  Under stress ~0.5 #PF per process – lazy pages are not the cause.
- Fault-around (`vm::FAULT_AROUND`, pulling in neighbouring pages on #PF) – measured and disabled (1):
  QEMU TCG 1 CPU, 3 × 20 s: 1 page – 553 scripts, 16 pages – 515, old 256 KiB heap in `.bss` – 541.
  Per-script cost on 1 CPU did not increase compared to the old allocator; the drop on the test laptop needs to
  be confirmed by another measurement (variation between runs / temperature).

## v0.17.29 — 2026-10-08

### Added – M17b steps c and d: #PF without IST, process memory (brk, mmap, lazy pages)
- #PF without IST: from ring 3 handled on the task's kernel stack (may take locks / wait); a kernel stack
  overflow ends in #DF (IST) with guard-page detection (ARCH TEST 8/8). The "#PF during #PF" flag is now
  per CPU (it was shared by all CPUs).
- Process memory (`kernel/user/vm.rs`): heap, mmap and stack regions; pages on first access
  (#PF from ring 3 or a copy by the kernel). Syscalls `brk` (26), `mmap` (27), `munmap` (28; also
  partial regions). The stack grows lazily up to 8 MiB. Process #PF without BKL.
- Program library: an allocator on brk / mmap instead of a 256 KiB array in `.bss` – processes no longer map
  64 frames for the heap up front; large blocks (> 64 KiB) – their own mmap region, freed with munmap.
- FILE TEST 4/4: `/bin/memtest` (23 checks: brk, 64 MiB mmap with a few pages used, partial munmap, read into
  untouched pages, 4 MiB Vec, 20,000 small allocations, growing stack, #PF after munmap and overflowing the
  8 MiB stack kill only the child; frames are returned). USER TEST 4/9: #PF from ring 3 on the task stack.

## v0.17.28 — 2026-10-08

### Added – M17b steps a and b: file objects, dup / dup2 / seek, pipes
- A descriptor points to an object: `Fd::File(Arc<OpenFile>)` – copies (dup, dup2, child descriptors at spawn)
  share the position, as in Unix. New syscalls: `dup` (22), `dup2` (23), `seek` (24; console / pipe – ESPIPE).
- Pipes: `pipe` (25) – 64 KiB kernel buffer, read waits for data (0 = no writers), write waits for space
  (EPIPE when there are no readers), kill / Ctrl+C interrupts the wait. A process closes its descriptors at
  exit (`exit_current`), not at reap.
- Shell: pipelines `a | b | c` (programs from /bin plus echo, pwd, help, history), with redirections
  (`primes 30 | cat | cat > plik`), in the background (`&` at the end).
- Program library: `dup`, `dup2`, `seek`, `pipe`. New test programs `/bin/fdtest`, `/bin/pipetest`.
- New self-test suite FILE TEST (25 suites): file objects (24 checks), pipes (18 – including
  200 KiB through `cat`, a reader waiting for a writer), pipes in the shell.

## v0.17.27 — 2026-10-08

### M17a closed
- **The test laptop (16 threads)** (16 CPUs, autostress 60 s) with v0.17.27: **record 53,809 scripts**
  (v0.17.26: 50,524, +6.5%; record before g10–g16: 45,802, +17.5%); ramfs tree 2.2 s of waiting (505 s); BKL
  0.23 s; scheduler lock 2% waits. `SMP=8 ./stress-qemu.sh` (KVM): 41,328 scripts.
- "Done when" conditions met: 99% of syscalls without BKL and in parallel (NOBKL TEST 1/9), BKL off the hot
  paths, stress and self-tests without errors. Summary and open threads – `ROADMAP.md` (M17a). Next:
  M17b – file objects + process memory.

### Changed – M17a step g16: ramfs tree under a spinning reader–writer lock
- **The test laptop** (16 CPUs, 60 s) with v0.17.26: **record 50,524 scripts** (v0.17.25: 45,606, +10.8%),
  scheduler lock 2.3 s (6.5 s). What remained was the ramfs tree: 438 thousand read waits (30%), 505 s –
  spinning before sleeping resolved only 31 thousand.
- New `spin::RwSpinLock`: many readers or one writer, spinning instead of sleeping (tree sections take µs,
  while sleep and wakeup cost two passes through the scheduler), writer preference, preemption disabled,
  counts as a held spinlock (sleeping under it = panic), deadlock detection (HPET, 2 s report / 10 s panic).
  Statistics in `cpus`: "spin rwlock …" (acquisitions, waits, wait and hold time).
- ramfs: tree under `RwSpinLock`; `read_dir` and `stats` no longer take (sleeping) file locks under the tree –
  they collect file Arcs and read sizes after releasing it; a removed node is freed outside the lock.
- QEMU TCG 4 CPUs 20 s: waiting on the tree ~4.2 s → 42 ms.

## v0.17.26 — 2026-10-08

### Changed – M17a step g15: wait without scanning tasks, brief spinning before sleeping
- `SMP=8 ./stress-qemu.sh` (KVM) with v0.17.25: **38,352 scripts** (v0.17.23: 16,560); locks negligible.
- **The test laptop (16 threads)** (16 CPUs, 60 s) with v0.17.25: **45,606 scripts** (v0.17.19: 37,578, +21%;
  record v0.17.16: 45,802), 2% idle, BKL 0.24 s, scheduler lock 12% waits, 6.5 s (children_of holds it 4 s –
  946 thousand task list scans), ramfs tree: 30% of reads wait, 536 s; process table 33 s.
- `wait` without `children_of`: a process counts its live children (`Process::live_children`: spawn +1, child
  exit −1 in the same section as the zombie entry, adopted in reparent +n); a specific child – O(1) lookup.
- KMutex / KRwLock: 200 × `pause` before sleeping (a few µs; `SPIN_ITERS`, disabled in g9). After g13/g14
  sections take µs, while sleep + wakeup cost two passes through the scheduler. "spun" in the report shows how
  many waits were resolved by spinning. (QEMU TCG 4 vCPUs on 2 cores – fewer scripts, as expected on an
  overloaded host; representative: KVM and the test laptop.)

## v0.17.25 — 2026-10-08

### Fixed – false spinlock deadlock (regression from v0.17.23)
- `./test.sh` (TCG, 4 CPUs): PANIC "spinlock 'heap': deadlock (CPU 0 waited > 10000 ms)" in ALLOC TEST –
  the report said "waiting 17,364 ms", although the whole run took ~19 s. In g13 deadlock detection (spinlock,
  scheduler lock, BKL) moved from HPET to TSC, and TSC can be unreliable (TCG, differing per-core TSCs) –
  which is why it was on HPET from the start. This also explains the occasional self-test FAILs right after a
  build.
- Deadlock / long-wait detection is back on HPET – read only at the first check (every 1024 / 4096 spins),
  never under the lock. TSC only in wait statistics (`clock::tsc_wait_us`: same CPU, results > 10 s
  discarded).

## v0.17.24 — 2026-10-08

### Fixed – M17a step g14: wall clock without CMOS ports
- `SMP=8 ./stress-qemu.sh` (KVM) with v0.17.23: **16,560 scripts** (v0.17.22: 6279 – 2.6×), scheduler lock
  4% waits (192 ms), process table with no waiting. What remained was the ramfs tree: 441 thousand of 480
  thousand reads wait (92%), 815 s; 44% idle.
- Cause: `rtc::now()` (directory timestamp on create / mkdir / remove) called UNDER the tree write lock –
  ~45 CMOS port operations (under KVM each one is an exit to QEMU), sometimes spinning while the RTC updates.
  On top of that, `cmos()` had no cross-CPU lock (shared index register 0x70).
- RTC read once at boot (`rtc::init`); `rtc::now()` = boot reading + uptime (conversions
  `DateTime::to_unix` / `from_unix`). `rtc::read_hw()` – hardware read.
- TIME TEST 7/8 checks date conversions (1970, 29.02.2000, 2100) and clock agreement with the RTC (±2 s).
- QEMU TCG 4 CPUs 15 s: ramfs tree waits 833 → 252, 6.9 s → 2.5 s.

## v0.17.23 — 2026-10-08

### Fixed – M17a step g13: time measurement no longer extends lock hold times
- `SMP=8 ./stress-qemu.sh` (KVM) with v0.17.22: 6279 scripts; scheduler lock 87% waits, 299 s, although held
  ~1.3 s in total (wait_event ~1 µs per acquisition). Cause: after waiting for a lock (scheduler, spinlock,
  BKL) the wait time was computed by reading the HPET – AFTER the lock had been taken. HPET is MMIO: under KVM
  an exit to QEMU (serialised across vCPUs, tens of µs), on hardware ~1 µs – longer than the whole section.
  Every wait extended the hold time, so the next waiters waited longer (self-reinforcing). Same in KMutex /
  KRwLock (process table, ramfs tree): wait end and hold sample read under the lock.
- Spinlocks, scheduler lock, BKL: waiting measured with TSC (`clock::tsc` / `tsc_us`, same CPU).
  KMutex: hold time – TSC + CPU number (`rdtscp`; CPU change = sample skipped). KMutex / KRwLock:
  wait end (HPET) read after wakeup, BEFORE taking the lock.
- QEMU TCG 4 CPUs 15 s: process table held 36 ms (previously ~1.7 s per 20 s).

## v0.17.22 — 2026-10-08

### Changed – M17a step g12: tick without the scheduler lock + who takes it
- `SMP=8 ./stress-qemu.sh` (KVM) with v0.17.21: **6031 scripts** (v0.17.20: 5075, +19%), process table
  536 s of waiting (1239 s), but scheduler lock 85% waits, 314 s.
- Timer tick without the scheduler lock: every CPU took it every 1 ms just to account the task's CPU time and
  quantum (test laptop: ~16 thousand acquisitions/s). Now CPU time (`cpu_ticks` – atomic), quantum (per CPU)
  and "tasks are ready" (`READY_N` counter) without the lock; the BSP takes it only when the nearest wakeup
  deadline has arrived (`NEXT_WAKE`). QEMU TCG 4 CPUs 15 s: `ap_tick` 4535 acquisitions → 0, `on_tick`
  10,668 → 2667.
- `cpus` / autostress: "scheduler lock by site" – acquisitions, waiting and holding per function (schedule,
  wait_event, sleep_until, spawn_in, exit, children_of, with_process, on_tick, reap …). Site table shared
  with the BKL (`bkl::SiteTable`).

## v0.17.21 — 2026-10-07

### Changed – M17a step g11: process exit wakes only the parent
- `SMP=8 ./stress-qemu.sh` (KVM) with v0.17.20: PASS, 5075 scripts, but process table: 48% of acquisitions
  sleep, **1239 s of waiting**, held 43 s out of 60 s; scheduler lock 75% waits. Causes: every process exit
  woke ALL parents waiting in `wait` (a single queue) – each scanned the task list under the scheduler lock
  and took the process table; `on_exit` held the process table while taking the scheduler lock 3× (including
  a scan of all tasks in `reparent`).
- A parent waits in one of 64 queues chosen by its own number – a process exit wakes its parent
  (and init, when it adopts zombies), not everyone.
- `Process::has_children` – a process that never had children exits without `reparent` and without looking
  up init (a single parent check remains under the process table).
- QEMU (TCG, 4 CPUs, 20 s): waiting on the process table 6.8 s → 3.1 s, scheduler lock 1.5 s → 1.1 s.

## v0.17.20 — 2026-10-07

### Changed – M17a step g10: sleeping locks wake a single waiter
- The test laptop (16 threads) with v0.17.19: 37,578 scripts, scheduler lock 62% waits (235 s), process table
  357 s, ramfs tree 1108 s. Cause: every KMutex / KRwLock release woke ALL waiters – a thundering herd of
  wakeups through the scheduler lock, while only one gets the lock anyway.
- KMutex: sleeper counter; release wakes one (`WaitQueue::wake_one`, `sched::wake_one_channel`),
  and only if someone is sleeping.
- KRwLock: separate reader and writer queues. A writer release admits the group of waiting readers (or wakes
  one writer); the last reader wakes one writer.
- QEMU: self-tests 24/24 (1, 2, 4 CPUs), autostress 20 s on 4 CPUs – PASS.

## v0.17.19 — 2026-10-07

### Changed – M17a step f3b: allocation-free scheduler queues
- The test laptop (16 threads) with v0.17.18 came out worse: 36,689 scripts (41,667), scheduler lock 79%
  waits, 335 s (232 s), process table 768 s. Suspicion: f3a kept the queues in BTreeMap / Vec – every sleep
  and wakeup allocated memory under the (heavily contended) heap lock, with interrupts disabled, while holding
  the scheduler lock.
- Allocation-free queues: intrusive doubly linked lists embedded in the task (ready queue, WaitQueue channel
  buckets – 256, list of tasks with a deadline), number → task in 1024 buckets (chain in the task). The tick
  scans only tasks with a deadline. `reap` reserves space for dead tasks before taking the lock.
- New `./stress-qemu.sh`: the same autostress as on the test laptop, but in QEMU on the host (KVM if
  available; as many CPUs as cores, at most 16; `SECS=60` by default) – result on screen, exit code 0/1/2, log
  `stress-qemu.log`. First here, then the USB stick.

## v0.17.18 — 2026-10-07

### Changed – M17a g9 + f3a: no spinning, scheduler without scanning the task list
- The test laptop (16 threads) with v0.17.17: spinning before sleeping hurt – 6% idle (CPUs busy spinning),
  41,667 scripts (−9%); ramfs tree 910 s, process table 216 s, **scheduler lock 65% waits, 232 s**.
- g9: spinning disabled (`SPIN_ITERS = 0` in sched/sync.rs; the "spun" counters remain).
- f3a: the scheduler no longer scans all tasks under its lock. New structures: ready queue
  (FIFO – round-robin as before), number → task map, per-WaitQueue-channel sleeper lists, sorted
  deadline list. `schedule` – O(1), `wake_channel` – only the channel's tasks, tick – only expired ones,
  `ap_tick` / `on_tick` ("anything ready?") – O(1), task lookup – O(log n). `reap` on spawn only when there
  are dead tasks (previously on every spawn). Task list: `swap_remove` on cleanup.
- QEMU (4 CPUs, stress 3 s): ~113 scripts (v0.17.17: ~100–108).
## v0.17.17 — 2026-10-07

### Changed – M17a step g8: spinning before sleeping, several stress loops
- Test laptop (16 threads) on v0.17.16: VFS 2 writes, 0 waiting (was 668 s). Contention moved to the ramfs tree (409 s, ~1 ms per
  wait for sections lasting microseconds – the cost is sleeping and waking via the scheduler) and
  the process table (114 s). 44% idle, 45 802 scripts, stress loop 90% busy.
- KMutex and KRwLock: on a contended lock, first up to 2000 `pause` spins (a few dozen µs, SMP
  only), only then sleep. `cpus`: "% slept, % spun" (KMutex), "(N by spinning)" (KRwLock).
- Stress: driver loops as separate kernel tasks without the BKL – 1 per 4 CPUs, at most 4 (test laptop: 4), pool of 48
  shared between them, each with its own job numbers. Result: "N stress driver(s) X% busy" (average).

## v0.17.16 — 2026-10-07

### Changed – M17a step g7: ramfs with its own locks
- Test laptop (16 threads) on v0.17.15: 44 946 scripts (+14%), but VFS still 668 s of waiting (710 s) – 405k writes
  (mkdir/echo/rm in /stN) blocked readers (exec from /bin), and a reader held the lock for the whole
  file.
- `ConcurrentFs` (fs/mod.rs): `&self` operations for file systems with their own locks, including atomic
  `read_all` / `write_whole` / `append`. `FileSystem::concurrent()` – Some for ramfs, None for FAT32.
- ramfs: directory tree under a `KRwLock` ("ramfs tree" in `cpus`) – lookup for reading, create / mkdir /
  remove for writing; each file's contents under its own Mutex (Arc) – copying data (e.g. a program on
  exec) without holding the tree and without blocking other files.
- VFS: ramfs operations under FS_LOCK for reading (all of them, including file writes); for writing only mounting
  and FAT32. `remove` checks the mount point and removes under the same read lock.
- A named `KRwLock` registers itself on first use and unregisters when dropped (ramfs
  mounted in tests); ramfs "/" goes to the heap first, then the first operation.

## v0.17.15 — 2026-10-07

### Changed – M17a step g6: VFS readers–writer
- Test laptop (16 threads) on v0.17.14: VFS (a single KMutex) – 2.05M acquisitions, 31% wait, **710 s of waiting** in a 60 s test (on average
  ~12 tasks constantly asleep in the queue); stress loop 92% busy; 64% idle.
- New `KRwLock` (sched/sync.rs): sleeping readers–writer lock, reentrant, a queued writer blocks
  new readers, reader → writer = panic (instead of deadlock); state under an IrqSpinLock.
- FS_LOCK is a `KRwLock`. `FileSystem` got shared reads (`stat_shared`, `read_shared`,
  `read_dir_shared`, `shared_reads`) – ramfs has them (they only read the tree), FAT32 doesn't. stat / read /
  read_dir / read_file (including loading the ELF when starting a program) on ramfs take the lock for reading,
  many at once; modifications and FAT32 – for writing. `cpus`: "sleeping lock vfs: N reads + M writes, waited ...".
- KMutex hold time measured with the HPET every 16th acquisition (×16) instead of the TSC – v0.17.14 showed 33 815 s
  of holding in a 60 s test (the holder sleeps and changes CPU; the test laptop's per-core TSCs differ).
- Stress: `sched::task_exists` (without copying the task list) instead of `task_info` in the driver loop.

## v0.17.14 — 2026-10-07

### Added – M17a step g5: sleeping-lock measurement
- Test laptop (16 threads) on v0.17.13: BKL 5.0 s of waiting (before g: 173 s), 0 lost PIT interrupts, scheduler lock
  55.7 s (was 124 s). Still 63% idle and 38 548 scripts – tasks are waiting asleep.
- Named KMutex (`KMutex::new_named`, `Mutex::new_named`): acquisitions, acquisitions with waiting (once per `lock`),
  wait time (HPET) and hold time (TSC). Named: VFS (FS_LOCK), block layer, process table (zombies),
  captured output. `cpus` and the autostress screen: "sleeping lock ..." lines.
- Stress: "driver N% busy" in the PASS line – how much time the driver loop works outside its 2 ms sleep (close to 100% =
  stress limits itself). In QEMU (4 CPUs): 83%.
- `[NOBKL TEST]` 9/9 also prints the sleeping-lock lines.
- Stress result (autostress, `stress` command) in several short lines (load / jobs / spin / alloc / BKL)
  instead of one line wider than the screen (developer's request).

## v0.17.13 — 2026-10-07

### Changed – M17a step g4: timer interrupts without the Big Kernel Lock
- Test laptop (16 threads) on v0.17.12 (full 60 s, PASS): 58% idle, 39 428 scripts (new pool), BKL 46 s of waiting – of which
  ~38 s is interrupts interrupting the kernel (LAPIC timer 26.2 s, PIT 9.7 s, resched IPI 2.6 s). Scheduler
  lock: 46% of acquisitions wait, 124 s (that's the next step – f3).
- The PIT tick, LAPIC timer and switch IPI don't take the BKL on entry (exceptions.rs). Their work: tick
  counter (atomic), waking sleepers and the quantum (scheduler lock), watchdog, tick hook.
- PS/2 keyboard polling in the tick (decoder and shell input still under the BKL): only when the interrupted context
  holds the BKL or the BKL is immediately free – new `bkl::try_acquire_tagged` (without queueing); otherwise on
  the next polling tick (every 5 ms). IRQ1 takes the BKL as before.
- QEMU (4 CPUs, 3 s stress): BKL ~330 acquisitions (v0.17.12: ~1.9k), ~100 scripts (~88).

## v0.17.12 — 2026-10-07

### Changed – M17a step g3: process start and exit without the BKL, heavier stress
- Test laptop (16 threads) on v0.17.11: BKL waiting 36.7 s (v0.17.10: 57.5 s, before g: 173 s), but stress 76% idle.
  Top of the table: syscalls under the BKL 308k (that's `exit` – one per process) and task start 308k (process
  start – the BKL taken only to release it before jumping to ring 3).
- `exit` without the BKL: SYS_EXIT takes the BKL-free path, `exit_current` doesn't take the BKL (everything it touches
  has its own locks). The address space is still freed in `reap` under the BKL.
- A process starts without the BKL (`sched_new_task_start` takes it only for kernel tasks, `enter_user` releases it
  only if held).
- Stress: kernel tasks (spinlocks, allocations) run without the BKL the whole time, including in `sleep_ms` (previously the BKL came back
  every round just for the sleep – 187k "end of bkl::unlocked" acquisitions). Process pool 3 per CPU, at most 48
  (was 2 per CPU, at most 12), captured-output buffer 128 entries. **Script counts from this version on are not
  comparable with older ones.** In QEMU (4 CPUs): ~88 scripts in 3 s instead of ~55, BKL ~1.9k acquisitions
  instead of ~4.2k.

### Fixed (test)
- `[SMP TEST]` 5/5 on KVM once reported "no xmm process ever moved to another CPU": sampling `cpu_mask` every
  5 ms missed migrations of processes that had already finished (processes now start without the BKL and on KVM finish
  within a few dozen ms). The scheduler counts process migrations (`user_migrations`), the test checks the counter.
- Test laptop, first run of the heavier stress: after ~7 s "job 38190 ended with None" – at ~20k
  processes/s the exit log (256 entries) pushed out an entry before the stress loop checked it. Now
  EXIT_LOG = 2048 (128 KiB), CAPTURED_LOG = 256; stress says so explicitly when an entry has already dropped out.
- `[INIT TEST]` 7/9 (once locally): the inner `sh -c` finished before the test set init – the orphan went
  to the kernel. The init-shell script starts with `sleep 200`.
- Note from this run: the scheduler lock waited on 52% of acquisitions, 17.5 s in a ~7 s test (~15% of 16 CPUs' time) –
  at this load per-CPU queues (f3) start to matter.

## v0.17.11 — 2026-10-07

### Changed – M17a step g2
- Test laptop (16 threads) on v0.17.10: BKL waiting 173 s → 57.5 s (−67%), acquisitions 3.85 → 1.57M. Script count
  unchanged (39 482) – stress has a fixed pool of 12 jobs and a 2 ms loop, so it measures job latency, not
  throughput; mostly idle CPUs were waiting on the BKL.
- One idle CPU reaps at a time (`REAPER`) – previously all of them woke up and queued for the BKL
  for the same finished task (143k acquisitions, 78% with waiting).
- Preemption from an interrupt (`preempt_irq`): if the interrupted context didn't hold the BKL, after returning
  from the switch the BKL is not re-taken – previously it was taken only to be released on exit.
- Statistics: return after switch split into wait_event / sleep / yield / preempt; "% idle" in the stress
  result and an "idle" line in `cpus` (time in the idle task, measured in `schedule()` on switch).

### Fixed
- The process exit log (`exit_info`) was protected only by the BKL + IF = 0, but also written from BKL-free
  syscalls (kill during a syscall) – two concurrent writes could lose an entry. Now its own `IrqSpinLock`
  (level 225, `EXIT_LOG`).

## v0.17.10 — 2026-10-07

### Changed – M17a step g1: idle loop without the Big Kernel Lock
- g0 measurement on the test laptop (16 CPUs, 60 s): of 173 s of BKL waiting, 129 s (74%) is "wake from hlt" – the idle loop
  held the BKL, released it for `hlt` and re-took it after EVERY wakeup (2.37M times, 89% with waiting),
  just to call `reap` and go back to sleep. It was woken mainly by TLB shootdown IPIs (4.8M), which themselves don't
  take the BKL.
- Now idle runs without the BKL; it takes it only for `reap` and only when there are finished tasks (counter
  `DEAD_TASKS`, incremented in `sched::exit`, decremented in `reap`). New site in the statistics: "idle: reap
  dead tasks"; kernel start: "boot (kernel_main)".
- BKL statistics: without LAPIC calibration (1 CPU) hold time = 0 instead of a TSC cycle count.

## v0.17.9 — 2026-10-07

### Added – M17a step g0: who takes the Big Kernel Lock
- BKL statistics per acquisition site (`bkl.rs`): number of acquisitions, how many waited, wait time and hold time
  (TSC of the same CPU). Key: file:line (`#[track_caller]`) or a name (`bkl::tag`). Lock-free table.
- Named sites: interrupt entry split into PIT / LAPIC timer / resched IPI / devices (MSI) /
  exceptions × interrupted process or kernel; return after switch, task start, syscall under the BKL, process
  exit, wakeup from `hlt`, end of `bkl::unlocked`, `yield_if_contended`, AP start.
- `cpus` (and the autostress screen): "BKL by site" – the 8 sites with the largest wait + hold time.
- `[NOBKL TEST]` 9/9: all acquisitions attributed to sites, syscall under the BKL counted, hold time
  measured; the test log shows the table.

### Notes
- In QEMU (4 CPUs, self-tests) at the top: return after switch, PIT tick and LAPIC timer interrupting the kernel,
  wakeup from `hlt`. Test laptop: see v0.17.10.

## v0.17.8 — 2026-10-06

### Changed – M17a step f2: scheduler without the Big Kernel Lock
- The task list and scheduler state are now protected only by the scheduler lock (f1). Without the BKL: waiting
  (`WaitQueue::wait_until` → new `sched::wait_event` – condition and sleep under the scheduler lock, a wakeup
  from another CPU isn't lost), waking, `sleep`, `yield`, `spawn`, `reap`, `tasks`, `kill`. All
  `bkl::with` from e2 removed.
- BKL across task switches (like `release/reacquire_kernel_lock` in Linux 2.x): `schedule()` releases it
  just before the switch (`Task::bkl_dropped`), `after_switch()` re-takes it, after releasing the scheduler
  lock; a new task – in `sched_new_task_start`. While holding the scheduler lock the BKL may be released, but
  must not be waited for.
- `sleep` and `yield` syscalls without the BKL (`cpus`: new "sleep/yield" counter).
- Task stack pages (`stack-pages`), captured stdout and the shell line on an `IrqSpinLock`.
- `[NOBKL TEST]` 7/8: wakeup storm without the BKL (k tasks × 3000 generations) and concurrently `sleep(100)` in processes;
  8/8: killing processes sleeping without the BKL – they exit shortly, not at the end of the sleep.
- `build.sh`: `rustup target add` only when the target is missing (offline build).

### Fixed (during the step)
- A task returned from sleep without the BKL: an interrupt between going to sleep and `after_switch` took the
  `bkl_dropped` flag and released the BKL. `preempt` now preserves the interrupted context's flag; `sleep_until`
  and `wait_event` assert that whoever waited with the BKL returns with the BKL.
- Deadlock "CPU 2 waits for 'stack-pages', held by CPU 1": an interrupt in a section under a `SpinLock` (IF = 1)
  waited for the BKL, and the BKL owner waited for that SpinLock. Rule (ARCHITECTURE.md): a lock taken both with
  and without the BKL must be an `IrqSpinLock`.

- `bkl::held()` read the CPU number and the owner with IF = 1 – a task migrated to another CPU between
  the reads got a wrong result (since f2 the BKL follows the task across switches): spurious panic "wait_event
  returned without the BKL" (~1 in 15 test runs), and `enable_and_hlt` could go to sleep holding the BKL. Now read
  with IF = 0.

### Notes
- Interrupt entry (timer tick) still takes the BKL – that's step g.
- QEMU TCG with 8 CPUs on a 2-core host: `[TIME TEST]` 7/8 (ticks vs. RTC, before SMP start)
  can show ~400–500 ticks/s – the host can't keep up with emulation; 1, 2 and 4 CPUs – 24/24.
- Test laptop (16 CPUs, 60 s autostress): PASS – BKL taken 3.65M times (v0.17.7: ~12M), 171 s of waiting;
  scheduler lock: 19% of acquisitions wait, 9.8 s total (~1% of CPU time); 41 140 scripts (unchanged – the bottleneck
  is still the BKL). Per-CPU queues (f3) postponed until after M17b, next step g.

## v0.17.7 — 2026-10-05

### Added – M17a step f1: scheduler lock (alongside the Big Kernel Lock)
- The task list and scheduler state under their own lock (`lock_sched`, `sched/mod.rs`). For now taken under the BKL –
  it protects the same thing, so behaviour doesn't change; in f2 the BKL will disappear from the scheduler path.
- Recursive lock on the same CPU (wake → kick, sleep → block → schedule), always with IF = 0 (the timer
  interrupt takes it too), outside lockdep.
- Held ACROSS task switches: the old task takes it in `schedule()`, the new one releases it – after returning from
  its own `schedule()` or in `sched_new_task_start` (task_trampoline, before `sti`). The per-CPU depth is
  saved in the task (`Task::sched_depth`) and restored on return, also on another CPU.
- `sched()` asserts the BKL and the scheduler lock; `schedule()` – that the next task isn't
  current on another CPU.
- `[NOBKL TEST]` 6/6: ping-pong of two tasks via a WaitQueue (2 × 1000 wakeups; a lost one = hang) while
  tasks endlessly `yield` on many CPUs; afterwards the lock is free, depth 0.
- `cpus`: scheduler lock acquisitions, waiting (today 0% – under the BKL nobody waits; after f2 this is data for the decision
  on per-CPU queues).

### Notes
- The first version of test 6 hung with 8 CPUs: the `yield` tasks held the BKL in a tight loop (a kernel task
  holds the BKL by default) and starved the rest. Now they run without the BKL, with a bit of work between switches.

## v0.17.6 — 2026-10-05

### Added – M17a step e2: processes without the Big Kernel Lock
- `spawn`, `wait`, `kill`, `getppid` without the BKL. The zombie table (`procs.rs`) already had its own lock (KMutex –
  SMP-safe since e1); the task list takes the BKL only briefly: public scheduler functions
  (`spawn`, `reap`, `tasks`, `task_info`, `with_process`, `children_of`, `reparent`, `request_exit`,
  `current_on`...) via `bkl::with`.
- `sched()` asserts that the BKL is held – accessing the task list without the BKL is a readable panic
  (error reports: `sched_raw`).
- Spawn: loading the ELF and building the address space without the BKL; creating the task and registering it as foreground –
  together under the BKL, so the child won't run before Ctrl+C sees it (gap from `[INIT TEST]` 8/9 closed).
- `[NOBKL TEST]` 5/5: 4 shells at once each run 15 programs (spawn + wait), each one prints, zero
  zombies. `cpus`: counter of process syscalls without the BKL. In stress ~97% of syscalls without the BKL (v0.17.5: ~89%).
- Remaining under the BKL: exit (task end = scheduler), keyboard, sleep, yield, tasks, kcmd.

## v0.17.5 — 2026-10-05

### Added – M17a step e1: VFS, block layer and file syscalls without the Big Kernel Lock
- `KMutex` (the sleeping lock of the VFS and block layer) takes ownership via `compare_exchange` – previously
  `without_interrupts` was enough, because only one CPU at a time was in the kernel.
- `bkl::with(f)` – BKL-free code enters the scheduler only briefly: `WaitQueue::wait_until` (condition check
  and sleep under the BKL – a wakeup from another CPU isn't lost), `wake_channel`, `sleep_until`, `yield_now`;
  `sched::exit` and `exit_current` take the BKL themselves. `schedule()` asserts that the BKL is held.
- `current_id`, `current_process`, `should_exit`, `can_block` – via a per-CPU pointer, without the task list.
- Also without the BKL: `open`, `close`, `read` from a file or from the stdin buffer, `readkey` from the buffer, `write` to a file,
  `stat`, `readdir`, `mkdir`, `unlink`, `chdir`, `getcwd`. Remaining under the BKL: exit, spawn, wait, kill, getppid,
  keyboard, sleep, yield, tasks, kcmd.
- `[NOBKL TEST]` 4/4: 4 shells at once each append 41 lines to their own files (`echo >>`), exact content.
- `cpus`: counter of file syscalls without the BKL. In stress ~89% of syscalls without the BKL (v0.17.4: ~45%).

### Fixed
- Captured-output log (tests): only the process that created the buffer (or its last
  owner) writes – children inheriting the buffer pushed the parent's entry out of the 32-entry log (SMP TEST 4 with 8 CPUs:
  "sh 4 output lacks hello4"). Log: 64 entries.
- `[INIT TEST]` 8/9 (once on the developer's machine: "foreground 0 is not primes"): the shell registers the child as foreground
  right after creating the task, and the test on another CPU saw the "primes" task a moment earlier – the test now waits
  for both conditions. (In this window Ctrl+C wouldn't yet hit the new program – to be fixed in e2.)
- `[ALLOC TEST]` 2/3: reserve for kernel-region page tables 32 → 64 frames (once locally 34 were missing – stack
  slots for up to 2000 tasks; a leak would cost frames every round, not a constant few dozen).

## v0.17.4 — 2026-10-05

### Added – M17a step d: first syscalls without the Big Kernel Lock
- `getpid`, `uptime` and `write` to the console (screen or captured stdout) don't take the BKL – the
  `try_fast` path in `syscall_dispatch`, before `bkl::acquire`. Everything else (files, spawn, wait, read, sleep)
  as well as kill / bad return address – the regular path under the BKL.
- `sched::current_unlocked`: per-CPU pointer to the current task's structure (set on
  switch) – the task and its process without searching the task list (which changes under the BKL);
  `should_exit_unlocked` – kill / Ctrl+C without the BKL.
- Captured process stdout and the line being edited by the shell on a `SpinLock` (level 100, `OUTPUT`) instead of
  a sleeping Mutex (that one requires the scheduler, i.e. the BKL).
- Framebuffer: an owner (CPU number) instead of just a flag – another CPU waits for drawing to finish (up to 50 ms)
  instead of losing text on screen; the same CPU in the middle of drawing (exception) still writes only to serial.
- Test programs `lines` (2000 × write) and `pidloop` (getpid forever).
- `[NOBKL TEST]` 1–3: 4 × 100 000 getpid with ~150 BKL acquisitions in that time (registers survive the
  syscall), 4 processes × 2000 lines at once to captured stdout – every line intact, kill of a process that
  makes only BKL-free syscalls.
- `cpus`: how many syscalls went without the BKL (getpid / uptime / write) and how many under the BKL. In stress ~45% without the BKL.

## v0.17.3 — 2026-10-05

### Added – M17a step c: heap and frame allocator without the Big Kernel Lock
- Kernel heap and frame allocator on their own `IrqSpinLock`s (instead of just `without_interrupts` + BKL):
  allocations and frees work on many CPUs at once, also from BKL-free code and from interrupt handlers.
- Lock levels rearranged: heap 230, frames 240, TLB 250, console 255 – allocation is allowed from anywhere
  (including from an interrupt that landed in a section under any SpinLock), so the allocators must
  be nearly innermost. Table in ARCHITECTURE.md.
- The heap grows (`map_page` in its own region PML4[384]) and shrinks (unmap + TLB shootdown) without the BKL –
  that region's tables are changed only by the heap, under its lock; those waiting for the heap lock acknowledge
  shootdowns in the wait loop.
- `[ALLOC TEST]` 1–3: 4 tasks without the BKL × 12 × 640 KiB (heap grows and shrinks in parallel, data intact),
  small blocks + frames on several CPUs, allocations in the timer interrupt, meanwhile creating and ending tasks
  (stacks in another kernel region); nothing is lost, 0 deadlock reports.
- Stress test: spinlock tasks also do rounds of heap and frame allocations without the BKL (task-dependent
  pattern – overwrite by another CPU = FAIL), the timer interrupt allocates. Report: "heap + frame allocs
  without BKL". Note: due to the extra work the stress script count isn't directly comparable
  with v0.17.2.

### Fixed
- TIME TEST 8 (heap under interrupt load) hung on the developer's machine (QEMU TCG, 180 s timeout): in a tight
  allocation loop under the new `IrqSpinLock` interrupts were enabled only for a few instructions between
  `sti` and the next `cli`, and TCG checks for interrupts at code block boundaries – the timer interrupt never
  hit the window, so the interrupt counter and ticks stood still. The test loop now has a short window
  with IF = 1 every round and an HPET time limit (instead of a hang – a readable FAIL).

## v0.17.2 — 2026-10-04

### Added – M17a step b: TLB shootdown
- `kernel/arch/x86_64/tlb.rs`: IPI vector 0x43, one request at a time (range or full flush, mask of CPUs
  that haven't acknowledged yet). Handler without the BKL and without locks (the initiator usually holds the BKL). CPUs waiting
  with IF = 0 – for the BKL, a spinlock, the console, the request lock itself, in the watchdog report – handle
  the request themselves (`tlb::poll`), so there's no "waiting for the BKL / waiting for acknowledgement" deadlock.
  Report after 1 s of waiting (who isn't responding). Above 32 pages – full flush (CR3).
- `paging::unmap_range_free`: PTE → shootdown → only then `free_frame`, in batches of 32 pages (one shootdown
  per batch); `unmap_page` in the upper half also does a shootdown. Freed page tables = full flush.
- M17 workarounds removed: the heap returns pages under SMP again, kernel page tables are freed again,
  CR3 is reloaded only on an address-space change (previously on every switch).
  Lower half (processes) without shootdown – a process is single-threaded, and the CPU leaving it loads another
  CR3; threads (M17b) will require an `active_cpus` mask.
- `map_mmio` / splitting a 2 MiB page / write-combining – shootdown to all CPUs.
- AP start: full TLB flush after taking the BKL (while it waited, the BSP may have removed mappings).
- `[TLB TEST]` 1–5: acknowledgements from all CPUs; check that WITHOUT a shootdown a reader on another CPU
  really sees the stale page (QEMU TCG: yes – the test actually checks something); remapping visible right after
  the shootdown; 4 initiators at once without the BKL; the heap grows and returns pages under SMP.
- `cpus`: shootdown statistics (requests, full flushes, IPIs, acknowledgements, how many in wait loops, time)
  and the number of ticks added from the HPET.
- Automatic stress test after boot: `DESOOS_AUTOSTRESS=60 ./make-usb.sh /media/...` or
  `./build.sh --autostress=60` – stress test 5 s after boot, then the result, `cpus` and `mem` on screen
  (laptop without a working USB keyboard).

### Fixed
- System time under SMP: ticks catch up with the HPET. CPU 0 waiting for the BKL with IF = 0 lost PIT interrupts –
  locally (4 CPUs on 2 cores) ~60% of interrupts were lost, `stress 30` took ~115 s. The PIT interrupt is now
  an "alarm clock" (at least 1 tick), the HPET adds the missing ms; CPU time and quantum follow the clock. On a single CPU
  (self-tests before SMP) unchanged.
- TLB: found by test 4/5 – shootdown targets computed with IF = 1 (the task migrated to another CPU and waited
  for an acknowledgement from itself); `poll` with IF = 1 could clear the next request's bit without a flush.
- Process exit log 64 → 256 entries (SMP TEST 4 with 8 CPUs: "exit info missing").
- TIME TEST 8 counts interrupts instead of ticks.

## v0.17.1 — 2026-10-04

### Added – M17a step a: tools for removing the Big Kernel Lock
- `kernel/sched/spin.rs`: `SpinLock<T>` (disables CPU preemption) and `IrqSpinLock<T>` (disables
  interrupts, restores IF). Lockdep-mini: lock levels and ordering, recursion on the same CPU,
  task switch while holding a spinlock (panic in `schedule()`), deadlock report after ~6 billion TSC cycles
  (who waits and where, who holds it, since when and from where), panic after 5x that.
- Per-CPU preemption counter and "in interrupt" flag (`cpu.rs`); `preempt()` waits while the CPU holds a
  spinlock.
- `bkl::unlocked(f)` – kernel code without the BKL. An interrupt in such code takes the BKL for the duration of the handler and releases
  it on return (the BKL state belongs to the interrupted context).
- **Hang watchdog** (`smp.rs`): PIT clock stalled for 10 s → NMI to all CPUs, report: RIP, IF, BKL
  ticket of each CPU. Checked in wait loops (BKL, spinlocks) and in the timer tick (before the BKL).
- BKL and spinlock statistics in `cpus` (number of acquisitions, how many with waiting, how many cycles of waiting).
- TSC calibrated together with the LAPIC timer (`[APIC]` log).
- SMP stress test (`kernel/user/stress.rs`): process pool (shell: directories, files, spawn/wait;
  `primes`), `xmm` processes, kernel tasks on spinlocks without the BKL, tick hook on an `IrqSpinLock`;
  checks results, exact counters, deadlock reports, task reaping and frame leaks.
  Command `stress [s]` (default 10 s).
- Self-tests `[LOCK TEST]` 6/6 and `[STRESS TEST]` 1/1 (21 suites).
- `test.sh`: `SMP` variable (default 4).

### Fixed
- `preempt_disable`: reading the CPU number and incrementing the counter weren't atomic – a timer tick
  in between migrated the task to another CPU, and the counter grew on the old one (found by the stress test:
  "task switch while holding a spinlock").
- Lock ordering in the stress test: a lock taken from an interrupt handler must be higher than locks held
  with interrupts enabled (caught by lockdep) – rule written down in ARCHITECTURE.md.
- TIME TEST 5/8: race in the test itself (counter read before `cli`).
- SMP TEST 3/5 with 2 CPUs (process parallelism requires >= 3 CPUs, one is occupied by the test).
- Watchdog (after a test on the developer's machine): spurious "PIT clock stuck" with a working clock –
  a shared (last tick, TSC) pair written by several CPUs drifted apart; now each CPU tracks the clock
  itself. The report also gives the TSC difference between cores; at most 3 full reports per boot.
- Watchdog: a late NMI went down the regular path and took the BKL, which this CPU was already waiting for (panic "nested
  acquire"). An NMI never takes the BKL; each CPU knows whether the NMI was meant for it.
- **Interval clock on the HPET** (`arch/x86_64/clock.rs`, ACPI HPET table; 32- and 64-bit counter):
  watchdog, spinlock deadlock detector, BKL hold and wait times. Previously the TSC – on the developer's
  machine (QEMU/TCG) the virtual CPUs' TSC counters differed by jumps of ~2.5 s (NMI response times of exactly
  1x, 2x, 3x, 5x 2535 ms), which produced spurious "clock stalled" and a spurious "deadlock" panic in the stress test.
  Without an HPET – TSC as before. `cpus` reports BKL waiting in ms.
- **Dead tasks reaped on every `spawn`** (previously only in the idle loop). With many CPUs under
  load idle hardly ran and finished tasks (64 KiB stack + process memory) piled up:
  `stress 30` on the developer's machine ended with "out of memory" (2308 dead tasks at once), and the test shell executed
  its script on the console. After the fix: `stress 150` = 7948 scripts + 3973 `primes`, memory returns to its
  pre-test state. `mem` shows occupied stack slots; `stress` reports the real reason a process failed to start.
- **SYSRET on AMD** (KVM on Ryzen, and therefore the test laptop): STAR[63:48] = 0x13 (RPL 3 in the selector, like Linux)
  instead of 0x10. Intel forces RPL 3 by itself, AMD doesn't – SS after SYSRET was 0x18 and the next return from an interrupt to a
  process (`iretq`) gave #GP(0x18) in the kernel (self-test 3 x 100 000 syscalls under `ACCEL=kvm`).
- With many CPUs, upper-half page tables aren't freed on `unmap_page` (another CPU might have a TLB
  entry for the freed table – until TLB shootdown in step M17a.b).
- FPU TEST 2/5: switch threshold 6 instead of 20 (under KVM processes finish within a few quanta).
- **BKL: an interrupt releases the BKL only if the interrupted code held it.** Previously an interrupt that woke
  an idle CPU from `hlt` took the BKL, then in `after_interrupt` immediately released it and queued again
  – on every tick of every CPU. The BKL circulated thousands of times per second, and idle CPUs picked up ready tasks
  after seconds instead of milliseconds (found thanks to test 2/5 on the developer's machine: 11 204 BKL
  handoffs in 2.8 s; after the fix the second CPU takes over work after 1–8 ms).
- SMP TEST 2/5: spinners finish on their own – once they've been on >= 2 CPUs together or after 10 s (previously they waited for STOP
  from the test task, which was starved by slow BKL handoff – on the developer's machine the test hung
  for minutes); the cores they ran on are recorded by the spinners themselves (the developer's idea); the test reports after how many ms the second CPU
  took over work.
- Watchdog: second sensor – a CPU waits for the BKL longer than 10 s (HPET) → full report (the clock may be running meanwhile).
- Timer tick counted before the BKL (`time::pit_tick_early`): system time stays accurate even with a queue
  for the BKL, and the watchdog reports only a genuine absence of timer interrupts. Test 6/6 masks IRQ0.
- `test.sh` / `run-qemu.sh`: `ACCEL=kvm` (hardware virtualisation – truly parallel CPUs) and the default
  `-accel tcg,thread=multi`. On the developer's machine QEMU responded to NMIs after 2.5–5 s – the virtual CPUs ran
  one after another, and the BKL handed over "one after another" caused second-long stalls and exceeded test limits.
- Watchdog report: where and since when the owner has held the BKL; preemption counter, spinlocks, interrupt
  and current task of each CPU.
- The BSP in idle also picks up ready tasks in its own tick (PIT) – previously only the APs did that (`ap_tick`),
  and the BSP waited for an IPI, which might not arrive when wakeups were busy.
- SMP TEST 2/5: state dump when no second CPU has taken over work after 3 s (BKL: tickets and owner,
  each CPU: current task, NEED_RESCHED, LAPIC ticks, IPIs, BKL waiting; each spinner) –
  diagnostics for a rare FAIL "CPU mask 0b10" under TCG with 4 CPUs.
- Console: a whole log line printed at once (its own output lock, preemption disabled for the duration of the
  line). In `stress` messages from two CPUs got mixed mid-line. The lock can't hang the
  system: the same CPU re-enters (panic/NMI in progress), another CPU waits at most ~20 ms.
- HPET: 64-bit counter read as upper/lower/upper half (QEMU splits a 64-bit read into two
  32-bit ones – on a carry the result jumped by 2^32 cycles). Effect on the developer's machine: "368934882128455 ms"
  of BKL waiting in `cpus` after `stress 300`. A negative interval counts as 0, not 2^64.
- `cpus`: BKL wait time labelled as the sum over all CPUs.
- SMP TEST 2/5 (cause of the rare FAIL "CPU mask 0b10/0b1000" under TCG, found thanks to the state dump
  from the developer's log): a spinner held the BKL the whole time (releasing it only in the tick every 10 ms), so the test task
  created further spinners piecemeal, and the BSP waited for the BKL with interrupts disabled and lost PIT ticks –
  the test's "10 s" took 99 s, spinners 1–3 started after the deadline. Now spinners spin without the BKL, start
  together (after all have been created), and the deadline and "second CPU after" are measured by the HPET clock.

### Notes
- Known issue (until M17a): CPU 0 waiting for the BKL with interrupts disabled loses PIT interrupts, so under
  heavy contention system time (`uptime`, `sleep`) lags. Fix: ticks catching up with the HPET clock or
  shorter BKL hold times (further M17a steps).
- `[NVME TEST] FAIL: partition not found after writing GPT` in `run-qemu.sh` with a `--selftest` build is not
  a bug: `run-qemu` uses a persistent `nvme.img` (the GPT from the previous run is already there), while the test assumes
  an empty disk, as provided by `test.sh`. For manual testing: a plain `./build.sh`.
- The earlier explanation of watchdog reports as "emulator stalls" turned out to be largely
  wrong – most were false alarms (see above). With 4 virtual CPUs on 2 host cores
  BKL handoff can still be slow (e.g. 3 x 100 000 syscalls), so on a weak host: `SMP=2 ./test.sh`.
## v0.17 — 2026-10-04

### Added
- **M17: ACPI MADT, I/O APIC, LAPIC timer, SMP – all cores running.**
  - `acpi.rs`: MADT – cores (LAPIC and x2APIC), I/O APIC, ISA interrupt overrides; visible in `acpi`.
  - `ioapic.rs`: ISA lines (timer, keyboard, serial, mouse) via the I/O APIC (vector 0x20 + IRQ, to the BSP),
    8259 PIC fully masked, EOI to the LAPIC. virtio-blk moved from INTx to MSI-X.
  - `smp.rs`: AP startup via INIT-SIPI-SIPI – trampoline below 1 MiB (frame reserved when the
    allocator starts), from real mode straight to 64-bit, temporary PML4 below 4 GiB.
    Each AP: its own GDT/TSS with guarded IST stacks, IDT, FPU, SMEP/SMAP, PAT (WC), SYSCALL,
    LAPIC and a 100 Hz LAPIC timer (calibrated against the PIT).
  - `cpu.rs`: CPU number from RDTSCP (MSR TSC_AUX), up to 16 CPUs.
  - `sched/bkl.rs`: **Big Kernel Lock** (ticket lock) – one CPU executes the kernel at a time, ring 3
    processes run in parallel. Taken on kernel entry (syscall, interrupt, exception), released on return to
    ring 3, during `hlt`, and in the timer tick when another CPU is waiting.
  - Per-CPU scheduler: `current`, time slice, idle task (pinned), NEED_RESCHED; a ready task wakes
    an idle core via IPI. Per-CPU TSS.RSP0 and SYSCALL block (KERNEL_GS_BASE).
  - TLB without shootdown: with multiple CPUs, a full flush on every switch; the heap does not give pages back.
  - Panic halts the remaining cores (IPI).
  - `cpus` command; `CPU` column in `ps` (kernel shell and `/bin/ps`; the `tasks` syscall has a new field).
  - `test.sh` and `run-qemu.sh`: `-smp 4` (`run-qemu.sh` also `-cpu max`).
  - `[SMP TEST]` self-tests 5/5 (19 suites): 4 CPUs online with LAPIC timers, kernel tasks on all
    cores, 4 x `primes` at once, 8 shells at once (spawn/wait/VFS), 8 xmm processes migrating between
    cores without register leakage. The IDT gate test covers vectors 0x40-0x42.

### Real hardware
- The test laptop (16 threads, Ryzen 7 4800H): **16 CPUs online** – MADT with APIC ids 0-15 (xAPIC), all APs came up
  on the first try, LAPIC timer 6237 ticks/ms (~100 MHz bus).

### Notes
- The entire earlier test suite also passes with SMP enabled from boot (except tests counting
  switches on a single core). In QEMU (4 virtual CPUs on 2 host cores) BKL handoff is
  slow: 3 x 100,000 syscalls take ~48 s instead of ~1 s – on real hardware that's ~100 ns per handoff.
- Fine-grained locks instead of the BKL, and TLB shootdown – before M18 (roadmap).

## v0.16.1 — 2026-10-04

### Real hardware test (the test laptop (16 threads), Ryzen 7 4800H)
- DeSoOS boots from a USB stick: ACPI, ECAM, 36 PCI devices, SK hynix NVMe (read-only),
  GPT partitions, `/esp` read-only, init + shell. The laptop keyboard is on USB (ITE 8910) - coming after M20.

### Fixed
- DSB: "more than 512 GiB of RAM is not supported" on a laptop with 16 GB - the Ryzen graphics framebuffer sits
  ~2 TiB up. DSB now maps only regions from the UEFI map (RAM, ACPI, firmware) and the framebuffer, up to 64 TiB.
- PS/2: initialization as in Linux on x86 - no controller test (0xAA/0xAB) and no keyboard reset (0xFF),
  which break the 8042 emulation in the EC of some laptops; port polling every 5 ms when IRQ1 does not arrive.

### Added
- Status bar in the top-right corner (only without a serial port): uptime, keyboard bytes
  (IRQ / polling), 8042 status register - shows whether the system is alive.
- `irq` also shows keyboard bytes (IRQ1 / polling) and MSI counters.

## v0.16 — 2026-10-03

### Added
- **M16b: NVMe, PCIe ECAM, MSI-X, GPT – preparation for booting on a real computer.**
  - DSB passes the RSDP address (UEFI configuration table) – `BootInfo.acpi_rsdp`, magic `DSBOOT11`.
  - `kernel/acpi.rs`: RSDP -> XSDT/RSDT, checksums, table list, MCFG; `acpi` command.
    Tables mapped read-only (`memory::map_firmware`).
  - PCI: PCIe ECAM from MCFG – enabled after verifying that reads match ports 0xCF8/0xCFC;
    extended configuration `read32_ext`; without MCFG - ports as before.
  - `arch/x86_64/lapic.rs`: Local APIC (xAPIC and x2APIC), minimal scope - EOI for MSI; the PIC keeps working
    via "virtual wire". `arch/x86_64/msi.rs`: vectors 0x30-0x3F (no IST), spurious 0xFF.
  - PCI `enable_msix` / `enable_msi`.
  - `drivers/nvme.rs`: controller reset and enable, admin + I/O queues (64 entries), Identify, first
    active namespace, 512 B and 4 KiB blocks (with read-modify-write), PRP and PRP lists, 128 KiB DMA buffer,
    commands of max 32 KiB (or MDTS) - several queued at once, MSI-X / MSI / polling.
  - **Data protection:** writes only to the QEMU controller (1b36:0010); a real SSD = read-only
    in the driver, and the block layer independently rejects writes to a read-only disk (including `mkfs`,
    `disk write`, files). The file system then reports EROFS ("read-only file system").
  - `kernel/gpt.rs`: GPT (protective MBR, header and table with CRC32, 512/4096 blocks); partitions as separate
    disks (`nvme0n1p1`...) with type and name; the first EFI System partition with FAT32 is mounted at `/esp`.
  - `make-usb.sh`: `--list`, installs DeSoOS onto a mounted FAT32 USB stick (checks: USB, not the system
    disk, vfat, does not overwrite a foreign bootloader), optionally `--format /dev/sdX` with confirmation.
  - README: booting on a real computer, BIOS (Secure Boot, BitLocker), why data is safe.
  - `[NVME TEST]` self-tests 9/9: ACPI + MCFG, ECAM == ports + extended configuration, LAPIC + MSI-X,
    NVMe registration, write/read with restore and interrupts, queue (4 commands at once), write
    protection (block + driver + mkfs), GPT -> partition -> FAT32 -> /esp, read-only partition.
    18 suites in total.

### Fixed
- **Missing serial port (laptops) hung boot**: `enable_rx_interrupts` waited forever
  for an empty receiver (a port without a UART reads 0xFF). The UART is now detected (scratch register) – without it
  serial is disabled and the loopback test is skipped.
- QEMU: `build/` was a `fat:rw:` disk – OVMF wrote NvVars there, and vvfat could corrupt
  `BOOTX64.EFI` in the process (boot ended in the UEFI shell). `build/` is now a read-only USB stick.

### Changed
- Common interrupt exit path (`irq::after_interrupt`) for IRQ and MSI.
- `test.sh` / `run-qemu.sh`: NVMe disk (`build-test-nvme.img` / `nvme.img`), boot from USB.
- Version 0.16.0.

## v0.15 — 2026-10-03

### Added
- **M16: init + shell in user space.**
  - After boot, the kernel starts only `/bin/init` (`user::run_init`) and supervises it: when init
    exits - restart; missing file or 3 exits within 10 s - emergency kernel shell.
  - `/bin/init`: starts `/bin/sh`, reaps finished processes (including orphans), starts a new shell when
    the shell exits or is killed. Init is protected (`kill` -> EPERM).
  - `/bin/sh` (ring 3): line editing as in the kernel shell (arrows, history, Tab over /bin and kernel
    commands, Ctrl+C/U/L, Ctrl+D = exit), quoted words, `> file`, `>> file`, `< file`, `&`
    (background program exit reported before the prompt), builtins `cd pwd echo exit help history clear
    wait k`, programs by name (`/bin/<name>`) or path (`./a`), `sh -c "..."`. Prompt
    `desoos:/$` (the kernel shell uses `>`).
  - New programs: `ls ps kill mkdir rm touch cp mv stat sleep` (`user/lib/copy.rs` for cp/mv).
  - Kernel diagnostic commands (mem, lspci, disk, mkfs, df, date, run...) work in the process shell
    directly or as `k <command>` - the `kcmd` syscall (temporary bridge, output honors `>`).
  - Process family (`kernel/user/procs.rs`): parent (`Process.ppid`), zombies with exit code until
    `wait`, orphans go to init (without init - to the kernel), all under a single lock, so a child
    exiting together with its parent is not lost. Status: code 0..255 or 0x100 | reason (9 = kill).
  - Syscalls 9-21: spawn (argv, FOREGROUND flag, descriptors for the child's 0/1/2), wait (any
    child, WNOHANG), getppid, kill, chdir, getcwd, readdir, stat, mkdir, unlink, readkey (raw
    keys for the line editor, with line redraw on background messages), tasks, kcmd.
  - Ctrl+C: foreground process stack - terminates the topmost program, not the shell (also a shell
    inside a shell). The shell prints `^C`.
  - `user/lib/desoos.rs` library: spawn/wait/kill/..., `Key` + `readkey`, heap (size-class
    allocator on 256 KiB in .bss) - a program with `extern crate alloc;` gets `Vec`/`String`.
  - `[INIT TEST]` self-tests 9/9: guarded IST stacks, 2 MiB page split, foreground
    stack, shell script (builtins, programs, redirections, quotes, editing and history, `k`,
    exit code), no zombies, orphan without init and with init, kill(init) = EPERM, Ctrl+C terminates the program
    and not the shell, no frame leaks. 17 suites in total.
- **Cleanup before M16:**
  - Invariant `irq::dispatch -> preempt() -> kill_from_interrupt` documented in code (IRQs without IST,
    frame on the task stack) + self-test: vectors 0x20-0x2F have IST 0.
  - Assertion in `schedule()`: a task switch on an IST stack = kernel bug.
  - IST stacks moved from .bss to guard-paged stacks (5 x 64 KiB) right after heap init.
  - `map_mmio`: registers inside a 2 MiB direct-map page split it into 4 KiB pages - only the
    register pages are uncached (`split_direct_map_huge`); MMIO with NX.

### Changed
- Process with a process parent: the kernel prints the exit only on a crash (CPU exception); normal exit
  and kill are reported by the shell. Processes started by the kernel (kernel shell, tests) - as before.
- A process's test output/input (buffers) is inherited by children - tests cover the whole process tree.
- `FsError::NotEmpty` -> ENOTEMPTY (-39).
- Kernel shell: emergency shell + command source for `kcmd`.
- Version 0.15.0.

## v0.14 — 2026-10-02

### Added
- **M15: ELF program loading.**
  - `common/elf.rs`: a single ELF64 parser for DSB (kernel) and the kernel (programs) - allocation-free;
    checks magic, class, byte order, machine, ET_EXEC type, header table, filesz <= memsz,
    data within the file, and address overflows. DSB uses it instead of its own code.
  - `kernel/user/elf_loader.rs`: PT_LOAD segments only in the lower half (from 1 MiB - NULL gives #PF),
    W^X (data NX, code read-only, also for a page shared by two segments), `.bss`
    zeroed, entry point inside code, limits (64 MiB image, 8 MiB file, 32 arguments / 4 KiB).
    16 KiB stack with a guard page, holding argc, argv[], NULL, envp NULL, auxv AT_NULL (System V),
    RSP % 16 == 0.
  - Rust programs: `user/lib/desoos.rs` (syscalls, buffered `print!`/`println!`/`eprintln!` - a whole
    line goes out in one write, arguments, `_start`, panic -> exit 101), `user/user.ld` (from 0x400000,
    sections start on new pages), `user/bin/`: hello, args, cat (files or stdin), save, primes.
  - `build.sh` compiles `user/bin/*.rs` (target x86_64-unknown-none, static) into `build/user/` and generates
    `build/user/initrd.rs`; at boot the kernel writes the programs to `/bin` (`kernel/initrd.rs`).
  - `run <name|path> [arguments...] [&]`: first `/bin/<name>` (or a path containing `/`, relative to
    `cd`), then the asm test programs; `run` without arguments shows both lists; the typo
    suggestion includes /bin.
  - A process has a current directory (the shell's cwd) - `open` with a relative path resolves from it.
  - Normal exit of a foreground program (exit 0) without a `[USER] ...` message; code != 0,
    errors and background processes - with a message.
  - `[ELF TEST]` self-tests 9/9: /bin parses and loads, 14 corrupted files rejected (magic,
    class, endian, machine, ET_DYN, truncation, segment in the kernel and on page 0, W+X, filesz > memsz,
    entry in data, offset beyond the file, too many arguments), page permissions (text RX, rodata R+NX,
    data/stack RW+NX, .bss zeroed), stack layout, exec hello/args/save/cat/primes, exec errors,
    no frame leaks. 16 suites in total.

### Changed
- `run hello` and `run cat` run the ELF programs from /bin (the asm versions from M14 remain in tests).
- Roadmap: M15 done, next M16 (init + shell in user space); ARCHITECTURE.md: ELF programs,
  W^X, process and stack layout.
- Version 0.14.0.

## v0.13 — 2026-10-02

### Added
- **M14: syscalls.**
  - `arch/x86_64/syscall.rs`: SYSCALL/SYSRET (EFER.SCE, STAR, LSTAR, SFMASK clears IF/DF/TF/AC/NT).
    Entry: `swapgs` only while fetching the kernel stack from the per-CPU block (MSR KERNEL_GS_BASE),
    frame with user registers, `cli` before restoring registers, `sysretq`. The scheduler sets
    the SYSCALL stack together with TSS.RSP0.
  - Protection against the SYSRET trap: when the return RIP is non-canonical (syscall at the very end of the lower
    half), the process is terminated instead of a #GP in ring 0 on the user stack.
  - `user/syscalls.rs`: exit, write, read, open, close, getpid, sleep, yield, uptime (Linux-like ABI:
    RAX = number, RDI/RSI/RDX/R10/R8/R9, result in RAX, errors as -errno).
  - `user/process.rs`: process = address space + descriptors (0/1/2 console, 3+ VFS files:
    path, position, permissions, append).
  - copy_from_user / copy_to_user: range check (lower half, USER pages, WRITABLE for
    writes), copying between `stac` and `clac`; SMAP (CR4) enabled if the CPU supports it.
  - Process console: read(0) reads a line with echo and Backspace; background process output does not break
    the shell line. Ctrl+C terminates the foreground process right in the keyboard/serial interrupt
    (the shell does not read the keyboard then, so the process can read it) and discards typed, unread
    characters. The process exit message starts on a new line if needed.
  - `kill` wakes a task waiting in any queue (a process waiting in read exits immediately).
  - Programs: hello, cat, files, ticker, pid, sleeper, regs, badptr, badsys (old hello -> `sum`).
  - Self-tests 10/10: MSRs and per-CPU stack, write+exit, VFS files, read from stdin, EFAULT/ENOSYS/
    getpid, 3 x 100,000 syscalls without register changes, sleep in 4 processes at once, kill during
    read, non-canonical RIP on SYSRET, SMAP. 15 suites in total.

### Changed
- Roadmap: M14 done, next M15 (ELF loader); ARCHITECTURE.md: syscall table.
- Version 0.13.0.

## v0.12.1 — 2026-10-02

### Added
- `run <program> [n] [&]`: n copies of a program at once (1..16), each with a different seed value; in the
  foreground the shell waits for all of them (Ctrl+C terminates all) and summarizes the result.
  E.g. `run xmm 3` checks SSE register switching with a single command.
- A background message (process exit) does not break the shell line: the line is cleared, the message
  printed, and the prompt with typed text and cursor position is redrawn (like readline on Linux).
  `console::print_async` + the edited line saved by the shell before waiting for a key.
- Console self-test 9/10 checks the composition of such a message.

### Changed
- Version 0.12.1.

## v0.12 — 2026-10-02

### Added
- **M13b: process FPU/SSE state.**
  - `arch/x86_64/fpu.rs`: FXSAVE/FXRSTOR (512 B per task), CR4.OSFXSR + OSXMMEXCPT, CR0.MP/NE.
  - On every switch, the scheduler saves the x87/SSE registers of the process giving up the CPU and restores
    the next one's (eager - no lazy switching via #NM, so no LazyFP-style
    vulnerability and simpler with SMP). Kernel tasks run with CR0.TS = 1 - an FPU/SSE instruction in the kernel
    ends in an error report.
  - A new process starts with a clean state (registers 0, FCW 0x037F, MXCSR 0x1F80) - it cannot see
    previous processes' registers.
  - #XM (unmasked SSE exception) terminates only the process.
  - Test programs: `sse` (21 + 21 in xmm0 = 42), `x87` (1 + 1 + 1 = 3), `xmm` (xmm0-15 + st0
    checked 2 million times), `fpuclean` (clean state of a new process), `simdexc` (#XM).
  - FPU self-tests 5/5: CR0/CR4, 3 processes with different values in all XMM registers and st0
    switched round and round (approx. 40 switches, no values get mixed; test also verified
    negatively - without the save in the scheduler it detects the bug), clean state of a new process, #XM (QEMU TCG
    does not raise it - then skipped), CR0.TS restored in a kernel task. 14 suites in total.
- `run`: typo suggestion (`run see` -> `did you mean 'sse'?`); each run gets
  a different seed value in the data page.

### Changed
- USER test 7/9: SSE and x87 in ring 3 work (in M13a they terminated the process via #NM).
- Roadmap: M13b done, next M14 (syscalls).
- Version 0.12.0.

## v0.11 — 2026-10-02

### Added
- **M13a: user mode and process isolation.**
  - Process = scheduler task + its own address space (`kernel/user/space.rs`): separate PML4,
    lower half belongs only to the process (USER bit along the whole table path), upper half shared with the kernel,
    PML4[510] points to the process's own PML4.
  - Entry to ring 3 via `iretq` (CS 0x23, SS 0x1b, IF = 1, zeroed registers).
  - On every switch, the scheduler sets TSS.RSP0 (the task's kernel stack) and the process CR3.
  - NX: EFER.NXE, process data/stack/heap/task stacks/direct map non-executable.
  - SMEP (CR4, if the CPU supports it): the kernel will not execute code from a user page.
  - Exceptions from ring 3 (#BP, #PF, #GP, #UD, #NM and others except NMI/#DF/#MC) terminate only the process. The handler
    runs on an IST stack, so it does not switch tasks there: it records the cause and replaces the return
    frame - `iretq` returns to ring 0 onto the task's kernel stack (RSP0), and only there does the process exit.
    Message e.g. `[USER] process 3 'pf' killed: #PF reading 0x0 (not mapped) at 0x400002`.
  - Preemption of ring 3 processes (PIT tick) and `kill` of a process from an interrupt (the process does not have to
    check anything).
  - FPU/SSE disabled until M13b: CR0.TS = 1, a process FPU/SSE instruction -> #NM -> process exit
    with a message; #NM in the kernel = kernel error report.
  - #BP has DPL 3 in the IDT (`int3` from ring 3). Upper-half PML4 entries allocated at boot (processes
    copy them on creation).
  - Shell: `run <program> [&]` (ring 3 test programs: hello, counter, loop, pf, pfkernel,
    writecode, nx, gp, ud, sse, x87), Ctrl+C terminates the foreground process; `ps` shows
    a MODE column (kernel/user).
  - Self-tests 9/9: segments/IDT/TSS/CR0.TS, address space (shared upper half,
    USER/NX flags), first ring 3 (sum 5050, CS = 0x23), 6 kinds of faults x 3 rounds at once (IST stacks
    reused repeatedly), isolation of two processes at the same address, preemption of a loop
    in ring 3 + kill from an interrupt, SSE/x87 -> #NM, SMEP, RSP0/CR3 return without memory leaks.
    13 suites in total.
- `test.sh` runs QEMU with `-cpu max` (NX, SMEP).

### Changed
- Roadmap: M13 split into M13a (done) and M13b (FPU/SSE - next); M14 detailed
  (SYSCALL/SYSRET, swapgs, per-CPU stack, SMAP).
- Version 0.11.0.

## v0.10 — 2026-10-01

### Added
- **M12: scheduler - preemptive kernel tasks.**
  - `kernel/sched/`: tasks (`spawn`, `exit`, `yield_now`, `sleep`), round-robin with a 10 ms time slice
    counted in the PIT tick; context switch in assembly (callee-saved registers + RSP).
    Preemption happens in `irq::dispatch` after sending EOI, so a task woken by an interrupt
    (keyboard, disk) gets the CPU immediately.
  - Task 1 "kernel" is the boot code (later the shell), task 0 "idle" executes `hlt` when nothing is
    ready, and cleans up finished tasks (stack and struct are returned to memory).
  - 64 KiB task stacks in a separate region `0xffff_e000_0000_0000` (1 MiB slot per task) - nothing is
    mapped below the stack, an overflow ends in a
    `KERNEL STACK OVERFLOW` report with the task name (`[EXC] task: 2 'boom'`).
  - Space for FPU/SSE state (FXSAVE, 512 B) in the task struct - M13 will use it.
  - `sched::sync`: `WaitQueue` (waiting for a condition with wakeup from an interrupt and a timeout) and
    `KMutex`/`Mutex<T>` (sleeping, reentrant).
  - Waiting without wasting CPU: the shell waits for a key on the input queue (woken by keyboard,
    serial and mouse IRQs), virtio-blk puts the task to sleep until the disk interrupt, `sleep` puts the task to sleep.
  - Locks: the whole VFS (one lock, order: VFS -> disks) and the block layer.
  - `map_page`/`unmap_page` with interrupts disabled (tasks can be preempted at any
    point).
  - Shell: `ps` (tasks, state, CPU time, switches), `spawn spin|tick` (demo tasks),
    `kill <id>` (termination request).
  - Scheduler self-tests 8/8: spawn + stack cleanup, yield, preemption of a task that never
    gives up the CPU, 30 ms sleep, wait queue (wakeup + timeout), mutex (600/600
    updates with preemption inside the critical section), stack guard page. 12 suites in total.

### Changed
- Roadmap: M12 done, next M13 (user mode).
- Version 0.10.0.

## v0.9.3 — 2026-10-01

### Changed
- Console scrolling also works from the numeric keypad: Shift + 8/2 (by a line), Shift + 9/3
  (by a screen) - on some keyboards and laptops PgUp/PgDn exist only there. Verified in QEMU: left
  and right Shift with PgUp/PgDn, and Shift with the numeric keypad.
- Version 0.9.3.

## v0.9.2 — 2026-10-01

### Changed
- Keyboard console scrolling: Shift+Up / Shift+Down arrow scrolls by 1 line,
  Shift+PgUp / Shift+PgDn by a full screen (as many lines as the console has - depends on resolution;
  previously by half a screen). Mouse wheel unchanged (3 lines). Described in `help` and README.
- Shift+arrows no longer reach the shell (previously Shift+Up/Down browsed command history
  just like plain arrows - that function stays on the arrows without Shift).
- Version 0.9.2.

## v0.9.1 — 2026-10-01

### Added
- **PS/2 mouse: the wheel scrolls the console** (3 lines per notch, like Shift+PgUp/PgDn).
  - `ps2.rs`: port 2 initialization - port test, mouse reset, wheel mode (IntelliMouse /
    Explorer via sample-rate sequences 200/100/80 and 200/200/80), enable reporting, IRQ12.
    A missing mouse is not a problem - port 2 stays disabled.
  - `drivers/mouse.rs`: 3/4-byte packet decoder with resynchronization (bit 3 of byte 0),
    wheel counter consumed by the console outside the interrupt (redrawing the screen is too long for an IRQ).
  - Mouse self-tests 3/3 (packets injected through the controller with command 0xD3 -> IRQ12): ID 3/4,
    wheel up and down, button, resynchronization. 11 test suites in total.
- `help` and README: scrolling works in the QEMU window (in a terminal, the terminal itself scrolls); the mouse must
  be captured by clicking in the window (release: Ctrl+Alt+G).

### Changed
- Version 0.9.1.

## v0.9 — 2026-10-01

### Added
- **M11: tooling and cleanup for the scheduler.**
  - `test.sh`: self-tests in headless QEMU, result as exit code (0 PASS, 1 FAIL, 2 timeout,
    3 QEMU error), log in `test.log`, separate empty test disk. The kernel detects automatic mode
    via the fw_cfg file `opt/desoos/autotest` and shuts QEMU down via `isa-debug-exit` - also on panic
    and on a critical exception. At the end of the self-tests, a summary `Self-tests: 10/10 suites passed`.
  - Bitmap frame allocator (1 bit per frame, 16 KiB for 512 MiB RAM, placed above 1 MiB):
    `free_frame` detects double-free with a single bit (O(1)) instead of walking a list; free frames
    are no longer written to.
  - `alloc_frames(n, align)` / `free_frames(first, n)`: contiguous frames (e.g. DMA buffers), all or nothing.
  - virtio-blk: 64 KiB DMA buffer (16 contiguous frames) instead of 4 KiB - 16 times fewer requests on
    large reads.
  - The heap shrinks: when more than 512 KiB of free space accumulates at its end, pages return to
    the frame allocator (keeping 128 KiB spare, never less than 128 KiB of heap). After self-tests `mem`
    again shows approx. 128 KiB instead of 10 MiB.
  - Console scrollback: 1000 lines, Shift+PgUp / Shift+PgDn scrolls by half a screen, an indicator in the top-right
    corner (e.g. `-50/64`); new output (typing) returns to the bottom. Described in `help`.
  - New self-tests: frame allocator 8/8 (contiguous frames, errors, double-free), heap 9/9 (shrinking),
    console 10/10 (scrollback), disk 4/8 (160 sectors = 2 requests through the 64 KiB buffer).

### Changed
- Roadmap: M11 done, next M12 (scheduler).
- Version 0.9.0.

## v0.8 — 2026-10-01

### Added
- **M10: higher-half kernel + ELF in DSB.**
  - Kernel linked at `0xffffffff80000000` (PML4[511], `kernel/linker.ld`); sections aligned
    to 4 KiB.
  - DSB (`boot/dsb.rs`) loads `kernel.elf`: checks the header (x86_64, ET_EXEC), copies PT_LOAD
    segments into a contiguous physical block at any address, allocates a 256 KiB stack, builds its own
    page tables (identity for the jump, direct map, kernel in 4 KiB pages), after ExitBootServices
    loads CR3, sets RSP and jumps to `e_entry`. Errors (bad ELF, out of memory) are printed on
    screen instead of just a status code.
  - Direct map: physical address X is visible at `0xffff800000000000 + X` (`memory::phys_to_virt`).
    The kernel rebuilds it with 2 MiB pages only for RAM and reservations - holes (the PCI window below
    4 GiB) stay empty, so device registers get uncached mappings there.
  - The lower half of the address space is empty (PML4[0..256)) - room for processes (M13);
    a null pointer dereference is now always a #PF.
  - Kernel stack with a guard page: an overflow ends in a
    `KERNEL STACK OVERFLOW (hit the guard page below the stack)` report instead of silently overwriting memory.
  - Kernel code and rodata read-only, CR0.WP enabled (write to code = #PF).
  - `BootInfo` extended with magic `DSBOOT10` (kernel and DSB from different builds detect each other),
    kernel and stack location; `memory/layout.rs` describes the whole address layout.
  - The `mem` command shows the address and size of the kernel and the stack.
  - Self-tests: paging 7/7 (direct map + empty lower half, kernel RO, CR0.WP, stack and guard page),
    exceptions 8/8 (#PF on the guard page handled via IST), the frame allocator does not accept
    kernel or stack memory.

### Changed
- The kernel reads and writes physical frames (free frame list, page tables, virtio DMA buffers, framebuffer, UEFI
  memory map) through the direct map instead of the identity map.
- `map_mmio` returns an address in the direct map; virtio-blk keeps physical addresses (for the device)
  and virtual addresses (for the CPU) separately.
- TSS.RSP0 = stack top from BootInfo instead of a fixed `0x300000`.
- `build.sh`: instead of `kernel.bin` it produces `kernel.boot.elf` (kernel without symbols, embedded in DSB);
  checks the ELF type and entry point. The 512 KiB limit and the stack space check are gone - a kernel
  built without optimizations (approx. 880 KiB) also boots.
- Roadmap: M10 done, numbering of later milestones shifted (M11 tooling, M12 scheduler,
  M13 user mode, M14 syscalls, M15 ELF loader, M16 init + shell, M16b NVMe, M17 APIC + SMP,
  M18 user-space drivers, M19 USB).
- Version 0.8.0.

### Note
- DSB and the kernel must be built together (`./build.sh`) - an old DSB will not boot a new kernel and vice versa.
## v0.7.2 — 2026-09-30

### Fixed
- **PS/2 keyboard did not work in the optimized (-O) build** – the terminal (serial) worked.
  The `cli` / `sti` / `sti; hlt` inline asm blocks were marked `nomem`, so the compiler assumed memory
  does not change during `hlt` and did not re-read the event queue filled by the keyboard
  interrupt. These instructions are now a compiler barrier.
- **`/disk` existed even without a formatted disk** – it was then an ordinary in-RAM directory (ramfs),
  so files saved "to disk" silently vanished after a restart (e.g. after a typo in `mkfs 0 yes`).
  Now `/disk` is created only when FAT32 is mounted; without it `cd /disk` reports an error.

### Added
- Hint on a mistyped command: `mfks` -> `unknown command: mfks - did you mean 'mkfs'?`

## v0.7.1 — 2026-09-30

### Fixed
- **Boot ended with `Buffer Too Small`** (and fell through to PXE). The kernel built without optimization
  grew after M9 to approx. 627 KB (785 KB with self-tests), while DSB accepts an image of at most 512 KiB
  (`KERNEL_MAX_IMAGE`). `build.sh` now compiles the kernel with `-C opt-level=2` (approx. 280 KB,
  approx. 390 KB with self-tests) and keeps overflow checks (`-C overflow-checks=on`).
- After compiling, `build.sh` checks the size of `kernel.bin` and the room for the stack below 0x300000 and exits
  with a readable error instead of building an image that will not boot.
- Heap test 4/8 under optimization: the compiler could remove an alloc+dealloc pair of unused memory,
  so the test did not see the expected hole. Heap tests now call the allocator directly.

## v0.7 — 2026-09-30

### Added
- **M9: file system.**
  - `kernel/fs/mod.rs` (VFS): tree with mount points, path normalization (`.`, `..`),
    `FileSystem` trait, stat/read_dir/read/write/truncate/create/mkdir/remove/sync operations,
    read_file/write_file/append_file helpers; a mount point cannot be removed.
  - `kernel/fs/ramfs.rs`: in-memory file system, mounted at `/` (with directories `/tmp` and `/disk`).
  - `kernel/fs/fat32.rs`: FAT32 - reading and writing files and directories, long names (LFN/VFAT,
    UTF-16, Polish characters), 8.3 names with lowercase flags, unique `~N` names, case-insensitive
    lookup, appending, writes in the middle of a file, holes filled with zeros,
    truncate, directories grow by clusters, FSInfo, FAT sector cache, `mkfs` (Microsoft cluster size
    table), disk without a partition table or first FAT32 partition from MBR.
  - `kernel/drivers/rtc.rs`: date and time from the CMOS RTC (file timestamps, `date` command).
  - Shell: current directory in the prompt (`desoos:/disk>`), commands ls, cd, pwd, cat, hexdump, touch,
    write, mkdir, rm, cp, mv, stat, mount, df, mkfs, sync, date; `>` and `>>` redirection;
    quoted arguments; `reboot` and `halt` flush buffers first.
  - At boot: `/` = ramfs, `/disk` = FAT32 from the first disk (if formatted).
  - 10 self-tests on a RAM disk (8 MiB, does not touch `disk.img`): paths, ramfs, mkfs, names,
    multi-cluster files, holes and truncate, 40 long names in a directory, no cluster leaks,
    persistence after remount, copying ramfs -> FAT32, redirection and quotes.
- Verified compatibility with Linux (dosfstools/mtools): a disk formatted and written by DeSoOS
  passes `fsck.fat` without errors and is readable in Linux; a disk formatted by `mkfs.fat`
  (also with an MBR partition table) is read and written by DeSoOS, files identical after copying.

### Changed
- Version 0.7.0; roadmap: M9 done, next M9b (NVMe).

## v0.6 — 2026-09-30

### Added
- **M8: PCI + virtio-blk.**
  - `kernel/drivers/pci.rs`: scan of all buses/devices/functions (ports 0xCF8/0xCFC), BAR sizes
    and types (32/64-bit, IO), capability list, enabling DMA/INTx; devices without a
    driver get INTx interrupts disabled (in QEMU the network card shares IRQ 11 with the disk).
    Level-triggered mode for PCI interrupts in the PIC (ELCR).
  - `memory::map_mmio`: device registers identity-mapped, uncached (UC) – also above
    512 GiB (in QEMU/OVMF the virtio configuration lies at 0xC0_0000_0000).
  - `kernel/drivers/virtio_blk.rs`: virtio 1.0 (modern) – initialization per the specification, feature
    negotiation (VERSION_1, RO, FLUSH), virtqueue (split ring) with DMA, read/write/flush requests,
    INTx interrupt (reading ISR clears the line), waiting via hlt with a timeout.
  - `kernel/block.rs`: common disk interface (`BlockDevice`) and disk list – the file system (M9)
    and future NVMe (M9b) use only this.
  - Shell: `lspci [-v]`, `disk`, `disk read`, `disk write` (sector hexdump).
  - `run-qemu.sh`: creates `disk.img` (64 MiB) and attaches it as a virtio disk.
  - 8 self-tests (PCI, INTx, disk registration, multi-request read, write + flush + verification
    read with data restore, range errors, interrupt, read speed).

### Changed
- Version 0.6.0; roadmap: M8 done, M9 next, new milestone M9b (NVMe); tests on real
  hardware once the system is more complete.

## v0.5 — 2026-09-30

### Added
- **M7: console + shell.**
  - `kernel/drivers/fbcon.rs`: text console on the UEFI framebuffer – 8x16 character grid
    (1280x800 -> 160x50), 16 colors, cursor, wrapping and scrolling (only changed cells are drawn,
    the framebuffer is write-only), UTF-8, ANSI subset (ESC[K, ESC[2J, ESC[H, ESC[nC/D, colors).
  - `kernel/drivers/font.rs`: 8x16 font – 234 glyphs (ASCII, Latin-1, Polish letters, €, box drawing,
    arrows) generated from Terminus Font; license in `FONT-LICENSE.txt` (SIL OFL 1.1).
  - Framebuffer as write-combining memory: PAT (PA1 = WC) + PWT bit on the framebuffer's 2 MiB pages
    (`memory::map_write_combining`); pages overlapping RAM are skipped.
  - `kernel/console.rs`: common serial + screen output (all `serial_println!` logs now also go
    to the screen), input from the PS/2 keyboard and from the terminal (UTF-8 and ESC sequence decoder).
  - Serial: interrupt-driven receive (COM1, IRQ4, 256 B buffer), FIFO with a 1-byte threshold.
  - `kernel/shell.rs`: in-kernel shell – line editing (arrows, Home/End, Delete), history (32),
    Tab (command completion), Ctrl+C/U/L; commands: help, clear, echo, ver, uptime, mem, irq, sleep,
    keys, colors, history, reboot (8042 + triple fault), halt.
  - 9 console and shell self-tests (glyph pixels, ANSI, scrolling, Polish characters, COM1 RX via
    UART loopback + IRQ4, terminal decoder, line editor, commands).
  - `build.sh` passes the version from `Cargo.toml` to the kernel (`DESOOS_VERSION`, `ver` command).

### Changed
- `serial_println!` writes through the console (serial + screen).
- Serial transmit has a timeout: when nobody is receiving, bytes are dropped instead of
  stalling the kernel (the screen keeps working, serial recovers on its own once the UART is free).
- The temporary echo from M6 replaced by the shell.
- Version 0.5.0; roadmap: M7 done, M8 next.

## v0.4 — 2026-09-30

### Added
- **M6: PS/2 keyboard.**
  - `kernel/drivers/ps2.rs`: 8042 controller – disabling ports, flush, configuration (translation to
    set 1, port 2 disabled), controller and port 1 self-test, keyboard reset, enabling
    scanning, IRQ1. A missing controller does not halt the system (message + running without a keyboard).
    Waiting for the controller via `hlt` (no tight polling loop on the ports).
  - `kernel/drivers/keyboard.rs`: IRQ1 handler, set 1 decoder (E0 prefix, E1 Pause sequence,
    ignoring fake Shifts), Caps/Num/Scroll Lock LEDs (0xED + ACK/RESEND state machine).
  - `kernel/input.rs`: common input subsystem (interface for PS/2 now and USB in M17): hardware-independent
    `KeyCode`, modifiers and locks (autorepeat does not toggle Caps Lock), Polish programmer's
    layout (AltGr: ąćęłńóśźż, AltGr+u = €), Ctrl+letter = control character, 256-event queue
    (`read_event`, `read_char`, `wait_event`).
  - 9 keyboard self-tests: bytes injected through the controller (command 0xD2) go through the real
    IRQ1 path.
  - Temporary keyboard echo to serial in `kernel_main` (to be replaced by the M7 console).

### Changed
- Version 0.4.0; roadmap: M6 done, M7 next; new items in "Known gaps".

## v0.3 — 2026-09-30

### Added
- **M5: Timer + IRQ (PIC 8259 + PIT).**
  - `kernel/arch/x86_64/pic.rs`: remap IRQ0-15 -> vectors 0x20-0x2F, mask/unmask, EOI,
    spurious IRQ7/IRQ15 detection, ISR/IRR readout, `disable()` for the future APIC.
  - `kernel/arch/x86_64/pit.rs`: channel 0 in mode 2 @ 1000 Hz (divisor 1193), counter readout.
  - `kernel/arch/x86_64/irq.rs`: IRQ handler registration, dispatch, counters,
    automatic masking of lines without a handler.
  - `kernel/arch/x86_64/interrupts.rs`: `enable`/`disable`/`are_enabled`, `enable_and_hlt`,
    `without_interrupts` (nestable).
  - `kernel/arch/x86_64/port.rs`: shared `inb`/`outb`/`io_wait`.
  - `kernel/time.rs`: ticks, `uptime_ms`, `sleep_ms`/`sleep_ticks` (via `hlt`), tick hook
    (for the M10 scheduler); 8 self-tests (incl. comparison with the CMOS RTC clock).
  - IDT: IRQ0-15 stubs (`idt.rs`), vectors 0x20-0x2F routed to `irq::dispatch`.
- **`--selftest` flag** in `build.sh` (`--cfg selftest`): self-tests of all milestones only in the test
  build; test code marked `#[cfg(selftest)]`. The normal build ends with the message
  `[DeSoOS] Kernel ready (idle)`.
- `CHANGELOG.md`.
- `ARCHITECTURE.md`: architecture decision (modular monolith now, hybrid after M12) and driver split.
- `ARCHITECTURE.md`: principle "monolith first, hybrid where it gives stability without losing speed", section on IPC performance (measure before moving, ring buffers, batching).

### Changed
- Heap (`GlobalAlloc`) and frame allocator run with interrupts disabled — allocation is possible in an IRQ handler.
- The #GP test in M4 uses vector 0x7F instead of 0x21 (0x21 is now IRQ1).
- Roadmap: added M16 User-space drivers (optional).
- Roadmap: added M17 USB (xHCI + USB keyboard/mouse) after M16; until then input via PS/2 (M6).
- Roadmap: M5 = PIC + PIT; APIC moved to the end as **M15 APIC + SMP** (only when SMP is needed).
- Version: README v0.3, `Cargo.toml` 0.3.0.

### Fixed
- M5 test 3/8 (`only 1 ticks in 20 PIT periods`) and 7/8 under QEMU/OVMF in the unoptimized build:
  the test waited in a tight loop reading PIT/CMOS ports, which in QEMU (TCG) starved the thread
  raising the PIT IRQ. The test now waits via `hlt` (the CPU sleeps until an interrupt), and the
  port read loops have a pause. The PIC/PIT/IRQ code itself was correct.

## v0.2 — 2026-09-29
- M1 Frame allocator, M2 Paging, M3 Kernel heap, M4 GDT + IDT + exceptions + on-demand mapping.
- DSB: SysV ABI on the jump to the kernel, `BootInfo` in allocated memory, `uefi 0.41`
  `exit_boot_services()` with the memory map preserved; kernel zeroes `.bss`; QEMU with a FAT disk from `build/`.
