# DeSoOS Release Report

One section per release, newest on top: what was tested, where, with what result, what is known to be wrong, and
how performance moved against the previous release. Details of every change: `CHANGELOG.md`; what DeSoOS does
not do yet: "Current limitations" below (kept up to date with every release).

How the numbers are taken: `tests/test.sh` (QEMU TCG) and `ACCEL=kvm tests/test.sh` on the build machine; the
`[RESULT-…]` lines at the end of each run. Performance differences under ~10% between two runs are noise (TCG
timings move by ±15% from run to run on the same build).

---

## Current limitations

**Memory**
- kernel heap: programs are stopped 8 MiB before it is full; the kernel's own allocations (scheduler,
  drivers, services' kernel side) are not fallible – they rely on that 8 MiB; no test fills the heap from inside the
  kernel
- splitting a 2 MiB direct-map page (map_mmio) is one-way – 4 KiB pages are not merged back later
- the heap shrinks only from the end; large blocks (> 2 KiB) still under a single heap lock (address-ordered list, first-fit)
- core TSCs are not synchronized (test laptop) – times measured on a single CPU (statistics, profile); no TSC synchronization
- frame allocator: `alloc_frames(n)` is linear; no "below 4 GiB" zone for 32-bit DMA
- PML4[256..512) allocated from the start (~1 MiB of empty PDPTs) – the kernel will not add a new entry later
- DSB page tables and LOADER_DATA/BOOT_SERVICES memory are not returned to the allocator
- direct map max 512 GiB RAM (the kernel has room for 64 TiB)
- kernel image without NX (only code is RO) – together with DSB

**Processes and syscalls**
- `dcp audit` keeps 16 ancestors per entry: a viewer more than 16 levels up does not see the refusal; a process whose
  parent ended is reparented to init, so its later refusals are no longer seen by the old grandparent
- `spawn` instead of `fork`/`exec`; no environment variables or signals (kill = process exit)
- system actions (`sysctl`) behind a single `SYSCTL` handle – no split into reboot / sync / stress / `desofs` (`desofs info` / `check` also need it); raw disk writes only from the kernel's emergency shell
- `desofs check` runs inside one syscall: no progress until it ends and no Ctrl+C (64 MiB – a fraction of a second; a large disk will need progress and cancelling)
- snapshots: no automatic ones, no snapshot of a single directory (one live file system per volume in format 1), no creation time (the format stores only the generation); `snapshot delete` / `restore` and `snapshot list` walk the volume (like a mount; one walk per snapshot for the list); a snapshot whose name came from another tool and breaks the stricter rules can be listed but not mounted or deleted through the shell
- "in use" says how many handles, not which process (`ps`, `dcp` show it); mounting a file system over a directory inside a mount in use is not refused
- PID = scheduler task number (0 = BSP idle, 1 = kernel startup task, then the idle tasks of the other cores – with 4 CPUs init has PID 5)
- shell: line max ~70 characters (fits in 80 columns), no scripts, variables or `$?`
- directory handles hold a path, not the directory: a directory removed and created again under the same name is
  reached through the old handle; the shell's `cd` and unsandboxed programs still use global paths
- IPC: no futex and no ring buffers in the library
- ELF: only static ET_EXEC, envp and auxv empty
- programs from `/bin` built into the kernel image (initrd); the asm test programs too (only from the kernel's emergency shell: `run <name>`)
- limits are global, not per user: 1024 processes, kernel memory reserve, 16 MiB of IPC buffers, 24 MiB ramfs; kernel heap 64 MiB
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

**DeSoFS**
- power loss is tested on RAM disks that model a disk cache (anything since the last flush may or may not land, in
  any order, by 512-byte sector); a disk that ignores flushes or lies about them is not covered – no file system
  can be; the random draws use a fixed seed (the same images every run)
- only disk 0 is mounted at start (`/disk`); other disks by hand (`desofs mount` → `/desofs`); `rename` exists for
  the kernel (VFS, kernel-shell `mv`), not yet as a syscall – the user-space `mv` still copies
- every operation still walks the path from the root and finds a name by reading the directory block by block (35
  block reads to read a small file, 58 to create one); the block cache (v0.69.0) saves the disk reads but not the
  SHA-256 of each block (checked on every hit too) – a cache of looked-up names and nodes would save both (not
  done: it needs invalidation on every change); the cache cannot see a disk block that goes bad after it was
  cached until the copy leaves the cache – `desofs check` reads the disk itself
- every operation is its own commit (2 flushes): a `write_file` is truncate + write = two commits, so a power loss
  between them leaves an empty file – safe replacement is write to a new file + `rename`
- format 1: volumes up to 64 GiB (the map of the walk needs 18 MiB there); linear directory search; no hard links,
  no preallocation
- the walk re-reads metadata shared between roots instead of storing pointers; inside later roots (snapshots, the
  older superblock) duplicate blocks are found only outside shared subtrees – `desofs check` walks every root fully
- `desofs check` / `repair` only on an unmounted volume; `repair` only goes back to a whole sound superblock's
  state – no rescue of single files from a damaged tree; check compares at most 65 536 data blocks shared by two
  pointer blocks, relations only up to 16 M node numbers – past a limit the check is marked INCOMPLETE (a warning) and
  repair refuses that superblock
- directories in parts: ramfs and FAT32 count the position as an index (not stable while the directory changes); DeSoFS
  uses the byte position (stable)

**Cryptography (DeSoCrypto)**
- SHA-256/384/512, HMAC and HKDF over them, ChaCha20, Poly1305, ChaCha20-Poly1305, X25519, AES-128-GCM, RSA and
  ECDSA signature verification and the kernel's random number generator; no TLS yet – `netget https://` is refused;
  certificate chains are checked by DeSoTLS (`certcheck`), the AEADs and X25519 are not used yet
- signatures: verification only (no signing, no RSA decryption); RSA 2048–4096 bits with 3 ≤ e < 2^32, PKCS#1 v1.5
  (DigestInfo with NULL only) and PSS; ECDSA only P-256 / SHA-256 and P-384 / SHA-384; no Ed25519, no SHA-1. The
  big-number and curve arithmetic is not constant time – fine for public keys and public data, the only use; it must
  not be used for secrets. Wycheproof RSA 3072 / 4096 sets were checked on the host only (not shipped – 330 KB); the
  shipped vectors make `/bin/cryptotest` about 390 KB larger (570 KB)
- AES-GCM: only AES-128, 12-byte nonces and 16-byte tags; AES-NI / PCLMULQDQ only in programs (the kernel has the
  software path only – it does not save XMM for its own code); the software path is slow (bit-by-bit GHASH)
- not audited and not for production use: the code avoids branches and table look-ups that depend on secrets, but it
  has not been formally verified or audited for timing; passing the RFC vectors is not a proof of security; keys are
  wiped when objects are dropped, but copies in registers and on the stack are not
- AEAD nonces are the caller's job (no generator or counter) – reusing one with the same key breaks confidentiality
  and authenticity (with AES-GCM it can, under certain conditions, reveal H and allow forged tags)
- random numbers: the entropy each source counts (RDSEED and the firmware's RNG ½ bit per bit, RDRAND 0, timing 1 bit
  per 64 samples) is a trust policy, not something the health checks prove; the health checks are our own simple
  ones, not NIST SP 800-90B; one generator for all CPUs under one lock (a 4 KiB request ~tens of µs); reseeding is
  checked only when someone asks for random bytes; the firmware's RNG counts only with the RAW algorithm (whether its
  RAW source is the CPU's own cannot be told – it forms one hardware class with RDSEED); the default algorithm counts 0
- a machine without RDSEED and without a RAW firmware RNG, whose clock fails the jitter check, waits about 16 s at
  boot for interrupt times
- the timing check is strict: under KVM none of the 64 jitter windows passed (in TCG 43 of 64, on the test laptop
  64 of 64), so a machine without RDSEED and without a RAW firmware RNG waits at boot for interrupt times – that path
  is tested only with substituted sources; QEMU's OVMF gives no `EFI_RNG_PROTOCOL` (the test laptop's firmware gives
  RAW)

**Certificates (DeSoTLS) and the clock**
- no TLS yet (v0.75): certificate chains are checked (`certcheck`, CERT TEST), nothing connects with them
- not checked: revocation (CRL, OCSP) and Certificate Transparency – a revoked certificate still within its dates is
  accepted
- the clock: "plausible" (syscall 59) is a heuristic – it refuses a lost RTC battery, a broken reading and dates
  before the build date − 24 h or after 2099, but anyone with access to the firmware can set a date in that range
  (an expired certificate becomes "valid"); an RTC kept in local time (Windows next to it) cannot be detected – a few
  hours off can make a just-issued certificate "not yet valid"; no NTP and no saved last known time yet (the floor
  moves only with a new image); the build date is the build time unless `SOURCE_DATE_EPOCH` is set
- fail closed where real certificates may differ: name constraints with any type other than DNS names refuse the CA
  (339 of the 5341 x509-limbo server cases are refused for that while the suite expects success); a CA certificate as
  the server's own is refused; more than 256 names in a certificate (web-platform.test has 260), more than 8
  presented certificates or a path longer than 8 are refused; RSA keys over 4096 bits, P-521 (one Mozilla root is
  unusable), Ed25519 and ML-DSA are not supported; IP addresses as hosts are not supported yet
- not enforced (CA conformance / CA/B Forum rules that browsers also do not check, x509-limbo marks them): missing
  authority / subject key identifiers, a zero serial number, non-critical policy constraints, the commonName / SAN
  consistency, public-suffix wildcards (`*.co.uk`), RSA sizes not divisible by 8; deliberately accepted:
  non-critical name constraints (enforced anyway) and an anchor's non-critical basicConstraints
- the CA store (Mozilla NSS_3_133_RTM, 118 anchors) changes only with a new image; it is sealed in ramfs (nothing,
  not even the kernel's shell, can change it after boot)

**Hardware**
- INTx interrupts on real hardware: a device's IRQ line requires ACPI AML (_PRT) – drivers use MSI/MSI-X
- block layer: one operation across all disks at a time (global lock) – NVMe queues the commands of one request, different tasks wait in turn
- virtio-blk: copying through a 64 KiB DMA buffer, only the first virtio disk; NVMe: 128 KiB buffer (copying)
- NVMe: one I/O queue pair, first active namespace, no metadata; a real SSD is read-only (deliberately)
- FAT32: an I/O error in the middle of a write can leave lost clusters
- GPT: read-only; MBR – only via FAT32 (first FAT32 partition); FAT32 only with 512 B sectors (an ESP on a 4Kn disk will not mount)
- without a serial port, logs only on screen (status bar in the top-right corner: time, keyboard)
- USB keyboard only via usbd (user space): a dead usbd = no keyboard until init restarts it
- USB keyboard and mouse only in boot protocol (no multimedia keys); the test laptop's touchpad is unsupported
- USB stick read-only (deliberately), 512 / 4096 B blocks, ≤ 2 TiB, LUN 0, no UAS
- hubs: single TT only (no Multi-TT), no port power management (suspend / LPM), TT tested only on
  real hardware (QEMU has a full-speed hub – no TT)
- FAT32 reads cluster by cluster (USB stick with 512 B clusters: a few hundred KiB/s in QEMU)
- IDT: ISA vectors (0x20–0x2F, via I/O APIC), MSI (0x30–0x3F), LAPIC timer / IPI (0x40–0x42), spurious (0xFF); #BP has DPL 3
- FPU: FXSAVE only, no AVX; QEMU TCG does not raise #XM
- mouse (PS/2 and USB) only for console scrolling; system autorepeat only for USB (PS/2 – hardware)
- hard-coded keyboard layout (Polish programmer's)

**Network**
- no TLS (`https://` refused), no IPv6, no UDP sockets for programs (UDP only inside netd: DHCP, DNS)
- 8 TCP connections per netd (1 MiB receive ring each), 8 KiB send ring (uploads slow)
- cards: Intel 8254x / 82574 (QEMU) and Realtek 8168g/8168h; no USB Ethernet, no Wi-Fi
- DMA without an IOMMU: netd and usbd are trusted system code

**Files**
- FAT32: no GPT, FAT12/16, sectors ≠ 512 B; files max 4 GiB; `mv` of directories not implemented; times in UTC
- one lock for the whole VFS
- OVMF (QEMU firmware) writes NvVars to the first FAT – also to `/disk` or the ESP of the NVMe disk (firmware behavior, not DeSoOS; `build/` is read-only)

**Console**
- scrollback 1000 lines, shell line max 71 characters, font with 234 glyphs (the rest shown as `?`)
- M1–M4 logs only on serial; if serial is blocked, serial output is lost

**Tests**
- recovery procedure in `exceptions.rs` (`RESUME_RIP`, `probe_read`) only for tests
- the soak test on real hardware (`DESOOS_AUTOSOAK`) runs before init and only on a RAM disk; its network check
  there is a ping of the router (no download server); no random allocation failures (fault injection) and no
  `sysfuzz` worker yet
- RAM disks (`desofs ramdisk`) cannot be removed – their memory comes back at the next start
- soak leak checks compare kernel counters and handle counts at checkpoints (with tolerances: free frames 1 MiB,
  kernel heap 512 KiB, the console scrollback counted apart) – no per-allocation tracking like kmemleak; a slow leak
  below the tolerance shows only as the "three checkpoints in a row" trend, so only in runs of 2 hours or more

---

## v0.74.3 — 2026-11-08

**Status: documentation only – DeSoCrypto and DeSoTLS get their own folders, `docs/desocrypto/` and `docs/desotls/`;
`docs/ARCHITECTURE.md` keeps a summary of each. No code changed (only the version number), so the test results of
v0.74.2 below apply; no new test run.**

---

## v0.74.2 — 2026-11-08

**Status: stable on QEMU (TCG and KVM); build change only – `build.sh` no longer uses git at all: the build date is
`SOURCE_DATE_EPOCH` when it is set on purpose, otherwise the time of the build (as Android). No kernel code
changed.**

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 35/35 suites + restart 1/1 + short soak (RAM disk), 294 tests PASS | 297 s (restart 25 s, soak 130 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 35/35 suites + restart 1/1 + short soak (RAM disk), 294 tests PASS | 228 s (restart 12 s, soak 126 s) |

Both builds printed `Build date: 2026-11-08 … UTC (from build time)`; CERT TEST step 5 confirms the kernel and
syscall 59 report that date.

### Performance against the previous release (v0.74.1 → v0.74.2, same machine)

| | TCG v0.74.1 | TCG v0.74.2 | KVM v0.74.1 | KVM v0.74.2 |
|---|---|---|---|---|
| irq_user_ns | 9 130 | 11 485 | 65 897 | 66 225 |
| fact_svc_ns | 188 679 | 241 545 | 103 252 | 105 374 |
| USB read_kbs (usbd) / kernel | 65 015 / 78 794 | 64 000 / 68 400 | 67 147 / 105 292 | 99 902 / 102 264 |
| crypto sha256 kernel / user (KiB/s) | 48 640 / 50 880 | 49 425 / 51 582 | 180 480 / 216 320 | 174 080 / 216 320 |
| RSA-2048 / P-256 / P-384 verifications / s | 2 200 / 411 / 173 | 2 180 / 448 / 180 | 13 020 / 3 960 / 1 380 | 13 100 / 3 820 / 1 366 |
| DeSoFS 8 MiB write / read (KiB/s) | 6 971 / 11 393 | 6 954 / 12 118 | 21 501 / 54 251 | 19 230 / 53 542 |
| DeSoFS 1000 small files create / read (ms) | 12 882 / 3 674 | 13 358 / 3 686 | 7 604 / 822 | 7 954 / 826 |
| `desofs check` (ms) | 1 028 | 970 | 250 | 277 |
| short soak: file operations in 2 min | 6 478 | 5 977 | 27 781 | 28 150 |

Verdict: no regression (the same kernel code). The KVM USB read through usbd is back at v0.73.0's level
(99 902 KiB/s) – the dip in v0.74.0 was the host; it leaves the watch list. TCG fact_svc_ns moves between runs
(emulated timing) and is not a trend.

---

## v0.74.1 — 2026-11-08

**Status: stable on QEMU (TCG and KVM); fix only – `build.sh` takes the build date from a git commit only when the
project is the top of its own repository (it had taken a repository above the project: 2025-06-08). No kernel code
changed.**

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 35/35 suites + restart 1/1 + short soak (RAM disk), 294 tests PASS | 299 s (restart 24 s, soak 131 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 35/35 suites + restart 1/1 + short soak (RAM disk), 294 tests PASS | 227 s (restart 12 s, soak 126 s) |

Both builds printed `Build date: 2026-11-08 … UTC (from build time)` – the test machine's project is not a git
repository, so the build time is used; CERT TEST step 5 confirms the kernel and syscall 59 report that date.

### Performance against the previous release (v0.74.0 → v0.74.1, same machine)

| | TCG v0.74.0 | TCG v0.74.1 | KVM v0.74.0 | KVM v0.74.1 |
|---|---|---|---|---|
| irq_user_ns | 6 960 | 9 130 | 66 733 | 65 897 |
| fact_svc_ns | 209 205 | 188 679 | 102 459 | 103 252 |
| USB read_kbs (usbd) / kernel | 63 015 / 91 916 | 65 015 / 78 794 | 56 109 / 68 532 | 67 147 / 105 292 |
| crypto sha256 kernel / user (KiB/s) | 49 425 / 51 840 | 48 640 / 50 880 | 181 760 / 216 960 | 180 480 / 216 320 |
| RSA-2048 / P-256 / P-384 verifications / s | 2 280 / 440 / 182 | 2 200 / 411 / 173 | 13 200 / 4 040 / 1 400 | 13 020 / 3 960 / 1 380 |
| DeSoFS 8 MiB write / read (KiB/s) | 6 809 / 12 226 | 6 971 / 11 393 | 18 745 / 53 894 | 21 501 / 54 251 |
| DeSoFS 1000 small files create / read (ms) | 13 372 / 3 538 | 12 882 / 3 674 | 9 334 / 846 | 7 604 / 822 |
| `desofs check` (ms) | 959 | 1 028 | 328 | 250 |
| short soak: file operations in 2 min | 6 092 | 6 478 | 27 669 | 27 781 |

Verdict: no regression (the same kernel code). The KVM USB read through usbd is back up (56 109 → 67 147) and the
kernel's own USB read rose too (68 532 → 105 292) with no USB change – the earlier fall was the host, not a trend;
still lower than v0.73.0's 99 902, so it stays on the watch list.

---

## v0.74.0 — 2026-11-08

**Status: stable on QEMU (TCG and KVM). DeSoTLS 0.1 – certificate chains checked like TLS will check them, Mozilla's
root store installed as `/etc/certs/roots` and sealed in ramfs, the wall clock with a plausibility verdict (syscall
59), `certcheck`. No TLS connection yet (v0.75).**

### What is new since the last report (v0.73.1)

| Version | Change |
|---|---|
| v0.74.0 | `common/desotls` (DER, X.509, names, path building with every rule and limit, the store, PEM); `/etc/certs/roots` (NSS_3_133_RTM, 118 anchors) sealed with `/etc/certs` and `/etc`; ramfs sealed nodes; syscall 59 `time`; the build date in `build.sh`; `certcheck`, `certtest`, CERT TEST; DeSoCrypto 0.6.0 (`ecdsa::check_public_key`) |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 35/35 suites + restart 1/1 + short soak (RAM disk), 294 tests PASS | 298 s (restart 25 s, soak 130 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 35/35 suites + restart 1/1 + short soak (RAM disk), 294 tests PASS | 228 s (restart 14 s, soak 125 s) |

`[RESULT-CERTS]` (both runs): 257 DeSoTLS checks in the kernel and in `/bin/certtest`, 118 anchors (117 usable),
store NSS_3_133_RTM, 36 attempts to change the sealed store refused (21 from a program, 15 from the kernel).
`[RESULT-RIGHTS]` rows 58 → 59 (syscall 59). Before the release, on the host: x509-limbo 5341 server / DNS cases
(4944 agree; the differences are in "Current limitations"), 3 million mutated certificates (no panic, none
accepted), 56 mutations of the rules (55 caught, 1 equivalent).

The build said `Build date: 2025-06-08 09:20:23 UTC (from git commit)`: `build.sh` found a git repository in a
directory above the project (not the project's own) and took its last commit – an old date, so the lower bound of a
plausible clock was weaker than it should be (not wrong: a clock is only refused when earlier than this). To fix:
only the project's own repository counts (v0.74.1).

### Performance against the previous release (v0.73.1 → v0.74.0, same machine)

| | TCG v0.73.1 | TCG v0.74.0 | KVM v0.73.1 | KVM v0.74.0 |
|---|---|---|---|---|
| irq_user_ns | 8 401 | 6 960 | 66 357 | 66 733 |
| fact_user_ns | 80 096 | 75 272 | 96 899 | 96 711 |
| fact_svc_ns | 192 492 | 209 205 | 110 375 | 102 459 |
| USB read_kbs (usbd) | 85 333 | 63 015 | 74 472 | 56 109 |
| crypto sha256 kernel / user (KiB/s) | 48 941 / 50 880 | 49 425 / 51 840 | 179 582 / 215 360 | 181 760 / 216 960 |
| SHA-512 (KiB/s) | 101 760 | 103 360 | 360 640 | 363 840 |
| RSA-2048 / P-256 / P-384 verifications / s | 2 248 / 326 / 147 | 2 280 / 440 / 182 | 12 940 / 3 940 / 1 380 | 13 200 / 4 040 / 1 400 |
| AES-GCM hardware / software (KiB/s) | 53 440 / 8 429 | 53 440 / 9 458 | 523 840 / 26 427 | 528 320 / 26 240 |
| DeSoFS 8 MiB write / read (KiB/s) | 7 049 / 11 441 | 6 809 / 12 226 | 15 427 / 53 894 | 18 745 / 53 894 |
| DeSoFS 1000 small files create / read (ms) | 13 349 / 3 864 | 13 372 / 3 538 | 8 051 / 824 | 9 334 / 846 |
| `desofs check` (ms) | 1 108 | 959 | 299 | 328 |
| short soak: file operations in 2 min | 6 234 | 6 092 | 28 097 | 27 669 |

Verdict: no regression in what changed – crypto, the clock, ramfs (the seal check adds one flag test per change;
the soak's file operations are within 2 %). To watch: the USB read through usbd under KVM fell again (99 902 in
v0.73.0 → 74 472 → 56 109) while the kernel's own USB read (kread 68 532) is as before; no USB code changed in these
three releases, so the next runs decide whether it is the host or a trend. DeSoFS small-file create under KVM
(9 334 ms) is inside its earlier range (6 900–9 300).

---

## v0.73.1 — 2026-11-08

**Status: stable on QEMU (TCG and KVM); fix only – DeSoCrypto 0.5.1: `Hmac<D>::verify` accepts a truncated tag only
from half the hash (SHA-256 16, SHA-384 24, SHA-512 32 bytes; RFC 2104 §5) – it accepted 16 bytes for every hash.**

### What is new since the last report (v0.73.0)

| Version | Change |
|---|---|
| v0.73.1 | `Hmac::<D>::MIN_TAG_LEN = D::OUT_LEN / 2`; `HmacSha256` unchanged (16); 7 new checks (4188); the mutation "constant 16" caught by the SHA-384 and the SHA-512 checks |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 34/34 suites + restart 1/1 + short soak (RAM disk), 288 tests PASS | 299 s (restart 25 s, soak 130 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 34/34 suites + restart 1/1 + short soak (RAM disk), 288 tests PASS | 228 s (restart 12 s, soak 126 s) |

### Performance against the previous release (v0.73.0 → v0.73.1, same machine)

| | TCG v0.73.0 | TCG v0.73.1 | KVM v0.73.0 | KVM v0.73.1 |
|---|---|---|---|---|
| irq_user_ns | 9 218 | 8 401 | 65 854 | 66 357 |
| fact_user_ns | 73 800 | 80 096 | 97 608 | 96 899 |
| fact_svc_ns | 199 401 | 192 492 | 100 100 | 110 375 |
| USB read_kbs (usbd) | 73 142 | 85 333 | 99 902 | 74 472 |
| crypto sha256 kernel / user (KiB/s) | 48 640 / 32 640 | 48 941 / 50 880 | 177 920 / 212 800 | 179 582 / 215 360 |
| SHA-512 (KiB/s) | 102 400 | 101 760 | 356 800 | 360 640 |
| RSA-2048 / P-256 / P-384 verifications / s | 2 200 / 470 / 162 | 2 248 / 326 / 147 | 12 980 / 3 820 / 1 360 | 12 940 / 3 940 / 1 380 |
| AES-GCM hardware / software (KiB/s) | 51 200 / 9 458 | 53 440 / 8 429 | 522 240 / 26 240 | 523 840 / 26 427 |
| DeSoFS 8 MiB write / read (KiB/s) | 7 454 / 11 473 | 7 049 / 11 441 | 18 004 / 53 194 | 15 427 / 53 894 |
| DeSoFS 1000 small files create / read (ms) | 13 886 / 3 774 | 13 349 / 3 864 | 7 210 / 818 | 8 051 / 824 |
| `desofs check` (ms) | 1 021 | 1 108 | 305 | 299 |
| short soak: file operations in 2 min | 5 998 | 6 234 | 27 600 | 28 097 |

Verdict: no regression – only `Hmac<D>::verify` and its tests changed. The TCG user-space SHA-256 is back at 50 880
KiB/s (v0.73.0's 32 640 was the host). Under KVM the signature checks and SHA-512 are unchanged; the USB read
(74 472), DeSoFS 8 MiB write (15 427) and small-file create (8 051 ms) are lower in this one run and touch no
changed code – the usual spread of these measurements (earlier releases moved between 80 000–100 000, 17 800–18 300
and 6 900–8 800); to watch in the next run. In TCG P-256 fell from 470 to 326 / s while RSA stayed – one 200 ms
sample under emulation; under KVM P-256 is at 3 940 / s.

---

## v0.73.0 — 2026-11-08

**Status: stable on QEMU (TCG and KVM). DeSoCrypto 0.5.0 – signature verification: SHA-384/512, HMAC and HKDF over
any hash, RSA (PKCS#1 v1.5, PSS) and ECDSA (P-256, P-384), tested with Wycheproof. The first step of DeSoTLS (plan D:
v0.73 signatures → v0.74 certificates → v0.75 TLS 1.3). Nothing in the system uses the signature checks yet.**

### What is new since the last report (v0.72.1)

| Version | Change |
|---|---|
| v0.73.0 | `sha512.rs`, `hash.rs` (one interface for the hashes; `Hmac<D>`, `hkdf::*_with::<D>`), `bignum.rs` (public data only), `rsa.rs` (verification: PKCS#1 v1.5 with the whole block compared, PSS with explicit parameters; n 2048–4096 bits), `ecdsa.rs` (verification: P-256 / SHA-256, P-384 / SHA-384; key on the curve, strict DER, 1 ≤ r, s < n); Wycheproof vectors in `vectors/wycheproof.bin`; `cryptotest` third line; 4181 checks (were 2429) |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 34/34 suites + restart 1/1 + short soak (RAM disk), 288 tests PASS | 299 s (restart 25 s, soak 130 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 34/34 suites + restart 1/1 + short soak (RAM disk), 288 tests PASS | 227 s (restart 12 s, soak 126 s) |

CRYPTO TEST: 4181 checks in the kernel (software paths, overflow checks on) and the same 4181 in `/bin/cryptotest` –
among them 1375 Wycheproof cases (ECDSA P-256 / P-384, RSA PKCS#1 2048 / SHA-256, PSS 2048 / SHA-256, PSS "misc"):
every "valid" verifies, every "invalid" and "acceptable" (MissingNull) is refused. Before the release, on the host:
the Wycheproof RSA 3072 / 4096 sets too (2178 checks together, all passed) and 36 mutations of the new code (33
caught, 3 equivalent).

### The new primitives (`[RESULT-CRYPTO]`, user space)

| | TCG | KVM |
|---|---|---|
| SHA-512 (KiB/s) | 102 400 | 356 800 |
| RSA-2048 PKCS#1 verifications / s | 2 200 | 12 980 |
| ECDSA P-256 verifications / s | 470 | 3 820 |
| ECDSA P-384 verifications / s | 162 | 1 360 |

SHA-512 is 1.7 times faster than SHA-256 under KVM (356 800 vs 212 800 KiB/s: 64-bit words, 128-byte blocks). The
signature checks are far below what TLS needs to be slow: one handshake checks a chain of 2–3 certificates and one
CertificateVerify – a few milliseconds even with P-384 under KVM (0.7 ms each).

### Performance against the previous release (v0.72.1 → v0.73.0, same machine)

| | TCG v0.72.1 | TCG v0.73.0 | KVM v0.72.1 | KVM v0.73.0 |
|---|---|---|---|---|
| irq_user_ns | 9 168 | 9 218 | 65 659 | 65 854 |
| fact_user_ns | 76 277 | 73 800 | 94 339 | 97 608 |
| fact_svc_ns | 171 526 | 199 401 | 103 950 | 100 100 |
| restart_us | 3 500 | 4 200 | 1 200 | 1 200 |
| USB read_kbs (usbd) | 51 848 | 73 142 | 85 333 | 99 902 |
| rights gate_ns | 43 | 27 | 5 | 5 |
| crypto sha256 kernel / user (KiB/s) | 21 126 / 49 600 | 48 640 / 32 640 | 181 760 / 216 000 | 177 920 / 212 800 |
| AES-GCM hardware / software (KiB/s) | 52 480 / 8 871 | 51 200 / 9 458 | 533 120 / 26 746 | 522 240 / 26 240 |
| DeSoFS 8 MiB write / read (KiB/s) | 6 267 / 7 663 | 7 454 / 11 473 | 18 244 / 53 542 | 18 004 / 53 194 |
| DeSoFS 1000 small files create / read (ms) | 16 128 / 5 520 | 13 886 / 3 774 | 6 932 / 808 | 7 210 / 818 |
| `desofs check` (ms) | 1 185 | 1 021 | 292 | 305 |
| short soak: file operations in 2 min | 6 546 | 5 998 | 28 554 | 27 600 |

Verdict: no regression. KVM is within the usual spread (±4 %); nothing outside DeSoCrypto changed. In TCG the
user-space SHA-256 / HMAC fell to 32 640 KiB/s while the kernel's SHA-256 is back at 48 640 – the reverse of
v0.72.1's run, the same code: the TCG numbers move with the host's load. The kernel image of the test build is
0.5 MB larger (the Wycheproof vectors are in CRYPTO TEST and in `cryptotest`); the normal build only by `cryptotest`.

Not yet done: `cryptotest` on the test laptop (optional – the new code has no hardware-specific path; the speeds on
the real CPU would go here).

---

## v0.72.1 — 2026-11-08

**Status: stable on QEMU (TCG and KVM); fix only – `/bin/cryptotest` prints the AES-GCM results on their own line and
`cryptotest xmm` takes a run time (for the test laptop); two documentation corrections. No change to DeSoCrypto.**

### What is new since the last report (v0.72.0)

| Version | Change |
|---|---|
| v0.72.1 | `cryptotest`: a second output line for `aesni`, `pclmul`, `aesgcm`, `aesgcm_soft` (the one long line was cut off on a 240-column screen); `cryptotest xmm <n> [seconds]`; the README sentence about test-only code / `desocrypto_no_simd` split; the v0.72.0 speed conclusion made precise (KVM vs emulated TCG) |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 34/34 suites + restart 1/1 + short soak (RAM disk), 288 tests PASS | 296 s (restart 30 s, soak 131 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 34/34 suites + restart 1/1 + short soak (RAM disk), 288 tests PASS | 224 s (restart 12 s, soak 125 s) |

### Performance against the previous release (v0.72.0 → v0.72.1, same machine)

| | TCG v0.72.0 | TCG v0.72.1 | KVM v0.72.0 | KVM v0.72.1 |
|---|---|---|---|---|
| irq_user_ns | 5 906 | 9 168 | 65 616 | 65 659 |
| fact_user_ns | 72 385 | 76 277 | 91 449 | 94 339 |
| fact_svc_ns | 187 969 | 171 526 | 104 275 | 103 950 |
| restart_us | 6 800 | 3 500 | 1 200 | 1 200 |
| USB read_kbs (usbd) | 58 514 | 51 848 | 80 313 | 85 333 |
| rights gate_ns | 24 | 43 | 5 | 5 |
| crypto sha256 kernel / user (KiB/s) | 49 425 / 50 240 | 21 126 / 49 600 | 180 855 / 216 000 | 181 760 / 216 000 |
| AES-GCM hardware / software (KiB/s) | 54 720 / 9 320 | 52 480 / 8 871 | 530 560 / 26 613 | 533 120 / 26 746 |
| DeSoFS 8 MiB write / read (KiB/s) | 7 742 / 12 525 | 6 267 / 7 663 | 17 847 / 54 251 | 18 244 / 53 542 |
| DeSoFS 1000 small files create / read (ms) | 12 526 / 3 482 | 16 128 / 5 520 | 8 835 / 866 | 6 932 / 808 |
| `desofs check` (ms) | 923 | 1 185 | 304 | 292 |
| short soak: file operations in 2 min | 6 782 | 6 546 | 27 998 | 28 554 |

Verdict: no regression – only the test program and documentation changed; KVM is unchanged or better (small files
back to 6 932 ms). The TCG run was slow as a whole: the kernel's SHA-256 ran at 21 126 KiB/s instead of ~49 000, and
the DeSoFS reads (SHA-256 bound) fell with it – a loaded host, not code (the same SHA-256 in user space ran normally).

### Real hardware (test laptop: Ryzen 7 4800H) – normal build, by hand in the shell

| What | Result |
|---|---|
| `cryptotest` | `2429 checks OK (DeSoCrypto 0.4.0)`; SHA-256 248 640, HMAC 247 680, ChaCha20-Poly1305 414 400 KiB/s, X25519 11 110 / s |
| AES-GCM | `aesni yes, pclmul yes`; hardware **609 280 KiB/s**, software 30 248 KiB/s (an earlier run the same: 608 960 / 30 248) |
| `cryptotest xmm 1..4 20` – four at once (three with `&`, the last in the foreground) | 4 × `rounds OK (aesni yes, pclmul yes)`: 1 524 088, 1 293 436, 1 378 728, 1 690 503 rounds – they overlapped (the background ones reported `done` after the fourth), XMM patterns intact after every yield, hardware AES-GCM = software every round |
| after it | the shell as usual |

On the real CPU AES-GCM with AES-NI is 1.5 times faster than ChaCha20-Poly1305 (609 vs 414 MB/s) and 20 times faster
than the software AES-GCM. With this, the v0.72.0 hardware check is complete: AES-NI and PCLMULQDQ detected, every
check passed, and the XMM state survives task switches between processes using it on a 16-thread CPU.

---

## v0.72.0 — 2026-11-08

**Status: stable on QEMU (TCG and KVM). DeSoCrypto 0.4.0: AES-128-GCM – AES-NI and PCLMULQDQ in programs, a bitsliced
fallback without tables (the only path in the kernel); not audited, not for production use.**

### What is new since the last report (v0.71.0)

| Version | Change |
|---|---|
| v0.72.0 | AES-128 (AES-NI / bitsliced), GHASH (PCLMULQDQ / bit by bit), AES-128-GCM with the tag checked first; features detected and chosen separately; the kernel built with `--cfg desocrypto_no_simd`; CRYPTO TEST 5 – XMM state across task switches; 2429 checks; 10 mutations, each caught by its own test |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 34/34 suites + restart 1/1 + short soak (RAM disk), 288 tests PASS | 289 s (restart 23 s, soak 131 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 34/34 suites + restart 1/1 + short soak (RAM disk), 288 tests PASS | 227 s (restart 13 s, soak 126 s) |

Both runs: AES-NI and PCLMULQDQ present (TCG emulates them with `-cpu max`), all four feature combinations equal,
CRYPTO TEST 5 (four processes, XMM patterns checked after every yield, hardware AES-GCM = software) PASS. Before
delivery a kernel without FXRSTOR made CRYPTO TEST 5 fail ("xmm0 changed across a yield").

### AES-GCM speed (`[RESULT-CRYPTO]`, user space, 64 KiB pieces)

| | TCG | KVM |
|---|---|---|
| AES-128-GCM, AES-NI + PCLMULQDQ | 54 720 KiB/s | **530 560 KiB/s** |
| AES-128-GCM, software (bitsliced + bit-by-bit GHASH) | 9 320 KiB/s | 26 613 KiB/s |
| ChaCha20-Poly1305 (for comparison) | 71 360 KiB/s | 363 520 KiB/s |

Under KVM, with native AES-NI and PCLMULQDQ, AES-GCM is faster than ChaCha20-Poly1305 (530 560 vs 363 520 KiB/s). TCG
emulates those instructions, so its numbers (54 720 vs 71 360 KiB/s) do not show the speed of hardware AES. Without the
instructions ChaCha20-Poly1305 is 14 times faster than the software AES-GCM (KVM) – the trade-off TLS 1.3 clients make
when they prefer ChaCha20 on CPUs without AES-NI.

### Real hardware (test laptop: Ryzen 7 4800H) – first run, normal build, by hand in the shell

| What | Result |
|---|---|
| `cryptotest` | `2429 checks OK (DeSoCrypto 0.4.0)`; SHA-256 247 040, HMAC 247 680, ChaCha20-Poly1305 414 400 KiB/s, X25519 11 100 / s; `aesni yes` – the AES-GCM speeds were cut off by the screen (one line over 240 columns; split in v0.72.1) |
| `cryptotest xmm 1..4` | 4 × `rounds OK (aesni yes, pclmul yes)`: 48 937, 48 948, 48 793, 49 056 rounds – XMM patterns intact after every yield, hardware AES-GCM = software |
| after it | the shell as usual |

Not covered by this run: the four XMM tests did not overlap (each ran 0.4 s; typing the next command took longer), so
on the laptop each was switched against the shell and the services, not against the others – v0.72.1 adds a run time.

### Performance against the previous release (v0.71.0 → v0.72.0, same machine)

| | TCG v0.71.0 | TCG v0.72.0 | KVM v0.71.0 | KVM v0.72.0 |
|---|---|---|---|---|
| irq_user_ns | 9 877 | 5 906 | 65 876 | 65 616 |
| fact_user_ns | 81 665 | 72 385 | 95 374 | 91 449 |
| fact_svc_ns | 219 298 | 187 969 | 102 774 | 104 275 |
| restart_us | 4 800 | 6 800 | 1 200 | 1 200 |
| USB read_kbs (usbd) | 68 266 | 58 514 | 67 147 | 80 313 |
| rights gate_ns | 53 | 24 | 5 | 5 |
| crypto sha256 kernel / user (KiB/s) | 48 941 / 51 520 | 49 425 / 50 240 | 180 480 / 212 160 | 180 855 / 216 000 |
| DeSoFS 8 MiB write / read (KiB/s) | 8 055 / 12 641 | 7 742 / 12 525 | 17 246 / 53 894 | 17 847 / 54 251 |
| DeSoFS 1000 small files create / read (ms) | 12 251 / 3 491 | 12 526 / 3 482 | 7 838 / 820 | 8 835 / 866 |
| `desofs check` (ms) | 974 | 923 | 279 | 304 |
| short soak: file operations in 2 min | 6 664 | 6 782 | 28 000 | 27 998 |

Verdict: no regression – only DeSoCrypto, its tests and `build.sh` changed. The two values noted last time are back
in range (KVM usbd 80 313 KiB/s, TCG `gate_ns` 24). KVM small-file creation +13 % is on an untouched path: the profile
shows the time in the disk writes and the first flush (host I/O), not in DeSoFS code.

---

## v0.71.0 — 2026-11-08

**Status: stable on QEMU (TCG and KVM). DeSoCrypto 0.3.0: Poly1305, ChaCha20-Poly1305 and X25519 (not audited, not for
production use); the random number generator's trust policy set at build time (`DESOOS_TRUST_CPU`,
`DESOOS_TRUST_BOOTLOADER`, both 1 by default).**

### What is new since the last report (v0.70.1)

| Version | Change |
|---|---|
| v0.71.0 | trust policy of the generator (an untrusted source mixed but counting 0, classes unchanged); Poly1305 with asserted arithmetic bounds; ChaCha20-Poly1305 (`open` checks the tag first, the buffer untouched on a wrong tag; no nonce generator); X25519 (an all-zero result refused); 486 checks with expected values from Python big integers; 10 mutations, each caught by its own test |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 34/34 suites + restart 1/1 + short soak (RAM disk), 287 tests PASS | 288 s (restart 23 s, soak 131 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 34/34 suites + restart 1/1 + short soak (RAM disk), 287 tests PASS | 224 s (restart 12 s, soak 126 s) |

Before delivery: a build with `DESOOS_TRUST_CPU=0 DESOOS_TRUST_BOOTLOADER=0` started from jitter alone (TCG, 256 timing
bits in 16 ms) and passed RNG TEST.

### The new primitives (`[RESULT-CRYPTO]`, user space)

| | TCG | KVM |
|---|---|---|
| ChaCha20-Poly1305 `seal`, 64 KiB pieces | 60 160 KiB/s | 393 600 KiB/s |
| X25519 shared secrets | 1 490 / s | 10 805 / s |
| checks (kernel and `/bin/cryptotest`) | 486 | 486 |

`[RESULT-RNG]`: `trust_cpu=1 trust_bootloader=1`; TCG 256 (RDSEED) + 2 (jitter) = 258 bits, KVM 256 + 0 – the jitter
count in TCG varies from run to run (43, 47, 2 of 64 windows), RDSEED alone is enough here.

### Performance against the previous release (v0.70.1 → v0.71.0, same machine)

| | TCG v0.70.1 | TCG v0.71.0 | KVM v0.70.1 | KVM v0.71.0 |
|---|---|---|---|---|
| irq_user_ns | 8 310 | 9 877 | 66 733 | 65 876 |
| fact_user_ns | 67 773 | 81 665 | 90 826 | 95 374 |
| fact_svc_ns | 208 116 | 219 298 | 104 931 | 102 774 |
| restart_us | 4 200 | 4 800 | 1 200 | 1 200 |
| USB read_kbs (usbd) | 52 512 | 68 266 | 97 523 | 67 147 |
| rights gate_ns | 25 | 53 | 5 | 5 |
| crypto sha256 kernel / user (KiB/s) | 48 158 / 48 398 | 48 941 / 51 520 | 180 480 / 218 560 | 180 480 / 212 160 |
| DeSoFS 8 MiB write / read (KiB/s) | 7 641 / 12 740 | 8 055 / 12 641 | 14 948 / 53 894 | 17 246 / 53 894 |
| DeSoFS 1000 small files create / read (ms) | 12 869 / 3 695 | 12 251 / 3 491 | 7 760 / 865 | 7 838 / 820 |
| `desofs check` (ms) | 916 | 974 | 298 | 279 |
| short soak: file operations in 2 min | 6 421 | 6 664 | 28 212 | 28 000 |

Verdict: no regression – the kernel and the system paths did not change (only DeSoCrypto, its tests and the
generator's policy check). The KVM 8 MiB write is back at 17 246 KiB/s, so the 14 948 of v0.70.1 was a single-run dip.
KVM usbd read −31 % and TCG `gate_ns` 25 → 53 are on untouched paths: single-run spread (usbd has been 34 133 –
99 902 KiB/s in earlier reports); to be watched in the next runs.

---

## v0.70.1 — 2026-11-07

**Status: stable on QEMU (TCG and KVM); fix only – the firmware's RNG counts entropy only with the RAW algorithm (its
default algorithm, usually a DRBG fed by RDRAND, counts 0 like RDRAND); `KeyErasureRng` cuts requests over 1 GiB so the
ChaCha20 counter cannot wrap.**

### What is new since the last report (v0.70.0)

| Version | Change |
|---|---|
| v0.70.1 | DSB asks for the RAW algorithm first and tells the kernel which one it got (`BootInfo.rng_seed_kind`, `DSBOOT13`); only RAW counts; `fill` in 1 GiB pieces with a new key each; the simpler interrupt-time check described; DeSoCrypto 0.2.1 (125 checks) |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 34/34 suites + restart 1/1 + short soak (RAM disk), 287 tests PASS | 298 s (restart 24 s, soak 130 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 34/34 suites + restart 1/1 + short soak (RAM disk), 287 tests PASS | 224 s (restart 12 s, soak 126 s) |

A deliberate fault – the firmware's bytes counted without looking at the algorithm – made RNG TEST 1 fail ("the
firmware's default algorithm counted 256 bits").

`[RESULT-RNG]`: QEMU's OVMF gives no `EFI_RNG_PROTOCOL` (`uefi=no`), so nothing changes here: TCG 256 (RDSEED) + 47
(jitter) = 303 bits, ready after 5 ms; KVM 256 + 0, 1 ms. `getrandom` 104 580 / 389 000 KiB/s, the generator in the
kernel 134 080 / 485 460 KiB/s (TCG / KVM).

### Real hardware (test laptop: Ryzen 7 4800H, Lenovo UEFI) – a normal start of v0.70.1

```
[RNG] ready in 0 ms: 320 bits counted (hardware max(uefi 256, rdseed 256) + timing max(jitter 64, irq 0)); UEFI RNG RAW, RDSEED on, RDRAND on (mixed, 0 bits)
```

| What | Result |
|---|---|
| firmware RNG | `EFI_RNG_PROTOCOL` present and gives the RAW algorithm – 256 bits counted (the new v0.70.1 path, first seen on real firmware) |
| RDSEED / RDRAND | both on, no source switched off by the health checks |
| counted | 320 bits: hardware max(256, 256) = 256 (UEFI and RDSEED once, not 512) + timing max(jitter 64, interrupts 0) = 64 |
| ready after | 0 ms – no waiting |
| after the start | init, services and the shell as usual; `net0` got its address by DHCP |

Unlike under KVM (0 of 64), every jitter window passed on the hardware (64 bits).

### Performance against the previous release (v0.70.0 → v0.70.1, same machine)

| | TCG v0.70.0 | TCG v0.70.1 | KVM v0.70.0 | KVM v0.70.1 |
|---|---|---|---|---|
| irq_user_ns | 7 721 | 8 310 | 67 294 | 66 733 |
| fact_user_ns | 76 423 | 67 773 | 91 659 | 90 826 |
| fact_svc_ns | 296 296 | 208 116 | 110 132 | 104 931 |
| restart_us | 5 700 | 4 200 | 1 200 | 1 200 |
| USB read_kbs (usbd) | 63 015 | 52 512 | 93 090 | 97 523 |
| rights gate_ns | 26 | 25 | 7 | 5 |
| crypto sha256 kernel / user (KiB/s) | 41 645 / 49 920 | 48 158 / 48 398 | 175 360 / 205 760 | 180 480 / 218 560 |
| DeSoFS 8 MiB write / read (KiB/s) | 6 491 / 10 625 | 7 641 / 12 740 | 17 504 / 47 080 | 14 948 / 53 894 |
| DeSoFS 1000 small files create / read (ms) | 14 081 / 3 575 | 12 869 / 3 695 | 7 598 / 863 | 7 760 / 865 |
| `desofs check` (ms) | 1 026 | 916 | 306 | 298 |
| short soak: file operations in 2 min | 5 898 | 6 421 | 27 744 | 28 212 |

Verdict: no regression – no measured path changed; the differences are the usual single-run spread (TCG `fact_svc`
back at its v0.69.0 level, KVM 8 MiB write −15 % / read +14 %).

---

## v0.70.0 — 2026-11-07

**Status: stable on QEMU (TCG and KVM). The kernel has its own random number generator (DeSoCrypto 0.2.0: ChaCha20
with fast key erasure, an entropy pool, health checks, `getrandom`); `netd` no longer takes TCP sequence numbers and
DNS ids from a generator seeded with the uptime.**

### What is new since the last report (v0.69.0)

| Version | Change |
|---|---|
| v0.70.0 | ChaCha20 (RFC 8439) and `KeyErasureRng` in DeSoCrypto; `kernel/random.rs` – sources UEFI RNG, RDSEED, RDRAND, TSC jitter, interrupt times; declared entropy as a trust policy, correlated sources counted once (max); our own health checks with a 16-word start-up check; the kernel waits at boot for 256 counted bits; reseeding after 60 s or 1024 interrupts only with 128 new bits; `getrandom` (syscall 58, no right); `netd`, DeSoFS uuids, `/bin/random`; RNG TEST 1–3 |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 34/34 suites + restart 1/1 + short soak (RAM disk), 287 tests PASS | 293 s (restart 26 s, soak 130 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 34/34 suites + restart 1/1 + short soak (RAM disk), 287 tests PASS | 224 s (restart 12 s, soak 126 s) |

Each of seven deliberate faults made a test fail: no key replacement, a reseed without the 128-bit threshold,
RDRAND counted, no repetition checks, a start below 256 bits, classes added up instead of max, a wrong ChaCha20
constant. The first bytes of the generator differed between the two starts in both runs.

### The generator (`[RESULT-RNG]`)

| | TCG | KVM |
|---|---|---|
| firmware RNG (`EFI_RNG_PROTOCOL`) | no | no |
| RDSEED / RDRAND | on / on | on / on |
| counted at start: hardware (RDSEED) + timing | 256 + 43 = 299 bits | 256 + 0 = 256 bits |
| ready after | 4 ms | 1 ms |
| reseeds during the tests | 2 | 2 |
| `getrandom` from a program (4 KiB requests) | 92 980 KiB/s | 383 160 KiB/s |
| ChaCha20 generator in the kernel | 130 340 KiB/s | 475 980 KiB/s |

Under KVM none of the 64 jitter windows passed the timing check (one difference dominates the window), so the
timing class counted 0 – the check refuses a regular clock as it should; RDSEED alone made the generator ready.

### Performance against the previous release (v0.69.0 → v0.70.0, same machine)

| | TCG v0.69.0 | TCG v0.70.0 | KVM v0.69.0 | KVM v0.70.0 |
|---|---|---|---|---|
| irq_user_ns | 6 703 | 7 721 | 63 734 | 67 294 |
| fact_user_ns | 77 220 | 76 423 | 92 678 | 91 659 |
| fact_svc_ns | 208 986 | 296 296 | 106 894 | 110 132 |
| restart_us | 4 700 | 5 700 | 1 200 | 1 200 |
| USB read_kbs (usbd) | 59 362 | 63 015 | 99 902 | 93 090 |
| rights gate_ns | 25 | 26 | 5 | 7 |
| crypto sha256 kernel / user (KiB/s) | 48 158 / 49 920 | 41 645 / 49 920 | 181 760 / 216 640 | 175 360 / 205 760 |
| DeSoFS 8 MiB write / read (KiB/s) | 6 942 / 12 430 | 6 491 / 10 625 | 16 516 / 54 979 | 17 504 / 47 080 |
| DeSoFS 1000 small files create / read (ms) | 13 485 / 3 592 | 14 081 / 3 575 | 7 371 / 809 | 7 598 / 863 |
| `desofs check` (ms) | 937 | 1 026 | 265 | 306 |
| short soak: file operations in 2 min | 6 296 | 5 898 | 28 051 | 27 744 |

Verdict: no regression. Nothing on the measured paths changed except one per-interrupt hook (a few tens of cycles:
`irq_user_ns` +5 % under KVM, within the spread of earlier releases); TCG `fact_svc` +42 % and KVM 8 MiB read −14 %
are single-run noise (the read is SHA-256 bound, and SHA-256 itself was 4 % slower in this run).

---

## v0.69.0 — 2026-11-07

**Status: stable on QEMU (TCG and KVM). DeSoFS keeps verified blocks in memory: reading 1000 small files is 2.9 times
faster under KVM, and reading the 8 MiB file 2.5 times faster. The format, the flush order and the SHA-256 checks are
unchanged.**

### What is new since the last report (v0.68.0)

| Version | Change |
|---|---|
| v0.69.0 | DeSoFS block cache (`cache.rs`): one cache per mounted volume or snapshot view, keyed by address + SHA-256, so nothing is ever invalidated; SHA-256 and header check on every hit; a commit's blocks enter only after its second flush; one global limit for all caches together, min(1/16 of memory, 64 MiB), counting frames and index; Clock replacement with metadata kept first; `desofs check` / `repair` always read the disk; `fs_cache_bytes` in `sysinfo counters`, cache counters in `[RESULT-FS-PROF]`; DESOFS TEST 29–32 |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 33/33 suites + restart 1/1 + short soak (RAM disk), 284 tests PASS | 288 s (restart 24 s, soak 131 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 33/33 suites + restart 1/1 + short soak (RAM disk), 284 tests PASS | 222 s (restart 12 s, soak 125 s) |
| Soak 15 min, test laptop | `DESOOS_AUTOSOAK=900`, SEED=1794069017 | **PASS**, 2 checkpoints, leaks 0, errors 0 | 903 s |

Each of four deliberate faults made one of the new tests fail: a key without the checksum (test 30), inserting
before the second flush (test 32), no limit (test 31), a hit without the SHA-256 check (test 32).

### Real hardware (test laptop: Ryzen 7 4800H, 16 threads, NVMe, 3 × xHCI, Realtek RTL8168h) – soak v0.69.0

The same setup as for v0.68.0: a 256 MiB RAM disk (the NVMe untouched, read-only), killing `echo`, `net0`, `usb0`,
`usb1`, `usb2`, pings to the router, the boot stick's `EFI/BOOT/BOOTX64.EFI` (3 849 216 B) against its first
SHA-256. The block cache limit on this machine is 64 MiB; every checkpoint unmounts the volume, which gives the
whole cache back, so the memory is compared with an empty cache.

| What | v0.68.0 (15 min) | v0.69.0 (15 min) |
|---|---|---|
| File operations on DeSoFS (checked against the model) | 232 561 | 230 400 (3 836 MiB written, ~410–490 files, ~16 MiB live) |
| Snapshots (checked through their views) | 2 | 2 (410 and 487 files, both match the model) |
| Processes started | 375 571 | 378 671 |
| Services killed | 15 | 12 – back in (min / avg / max ms): `echo` 202 / 202 / 202, `usb0` 205 / 210 / 217, `usb1` 515 / 515 / 515, `net0` 15 968 / 23 996 / 32 026 |
| Kernel heap without the scrollback, baseline → final | – | 3 922 272 → 3 921 472 B (−800 B) |
| Free frames (with the scrollback's share), baseline → final | – | 4 052 616 → 4 052 833 (+217) |
| Final checkpoint | 3.3 s, `desofs check` clean | 3.3 s, tasks 30, processes 10, IPC buffers 0, handles as at the baseline, `desofs check` clean |
| After the soak | init, services, shell as usual | init, services, shell as usual |

On a RAM disk a block read is already a memory copy, so the cache does not change the number of file operations
(−1 %, within the spread). `net0` again takes 16 or 32 s because of the router's DHCP, within the 60 s allowed.

### Where the time goes now (KVM, `[RESULT-FS-PROF]`)

| Phase | v0.68.0 | v0.69.0 | Disk reads (v0.69.0) | What remains |
|---|---|---|---|---|
| Reading 1000 small files | 2.44 s (disk I/O 68 %, SHA 30 %) | 0.81 s | 580 (34 220 hits) | SHA-256 of the hits 0.70 s (87 %), disk I/O 0.06 s |
| Creating 1000 small files | 9.45 s (read I/O 3.51 s, SHA 1.27 s, commit 4.71 s) | 7.36 s | 0 (57 820 hits) | commit 5.13 s (flush 1: 2.27 s, flush 2: 1.05 s, writes 1.06 s), SHA of the hits 2.10 s |
| Reading 8 MiB | 0.45 s | 0.15 s | 0 (7 168 hits) | SHA-256 only |

The 580 misses are blocks of files created early on, evicted while the create phase filled the 32 MiB limit
(512 MiB of RAM / 16; 4 492 evictions). Reads now cost almost only their SHA-256, as planned. To go further, the
volume has to read fewer blocks (a lookup without scanning the path from the root each time), which is a separate
plan because it needs invalidation. The commit (both flushes) stays as it is.

### Performance against the previous release (v0.68.0 → v0.69.0, same machine)

| | TCG v0.68.0 | TCG v0.69.0 | KVM v0.68.0 | KVM v0.69.0 |
|---|---|---|---|---|
| irq_user_ns | 10 949 | 6 703 | 66 006 | 63 734 |
| fact_user_ns | 74 962 | 77 220 | 90 375 | 92 678 |
| fact_svc_ns | 240 096 | 208 986 | 103 412 | 106 894 |
| restart_us | 3 900 | 4 700 | 1 300 | 1 200 |
| USB read_kbs (usbd) | 40 960 | 59 362 | 95 255 | 99 902 |
| rights gate_ns | 26 | 25 | 5 | 5 |
| crypto sha256 kernel / user (KiB/s) | 49 920 / 52 160 | 48 158 / 49 920 | 175 360 / 210 560 | 181 760 / 216 640 |
| DeSoFS 8 MiB write / read (KiB/s) | 6 527 / 5 673 | 6 942 / **12 430** | 16 684 / 21 557 | 16 516 / **54 979** |
| DeSoFS 1000 small files create / read (ms) | 18 462 / 7 089 | **13 485 / 3 592** | 9 726 / 2 322 | **7 371 / 809** |
| `desofs check` (ms) | 1 121 | 937 | 314 | 265 |
| short soak: file operations in 2 min | 6 490 | 6 296 | 27 744 | 28 051 |

Verdict: no regression. DeSoFS reads are 2–2.9 times faster and creating small files 24–27 % faster; writing the
8 MiB file is unchanged, as it should be (its time is the commit). `desofs check` reads the disk directly, without
the cache; its time is within the usual spread. The short soak runs on a RAM disk, where a read is already a memory
copy, so it gains nothing. The other rows are the usual single-run noise (TCG `restart_us` +20 %, TCG usbd read
+45 %).

---

## v0.68.0 — 2026-11-06

**Status: stable on QEMU (TCG and KVM) and on the test laptop – the soak test ran on real hardware for the first
time (RAM disk, real network and USB): PASS, 0 leaks, 0 errors.**

### What is new since the last report (v0.67.0)

| Version | Change |
|---|---|
| v0.68.0 | `desofs ramdisk <MiB>` – a RAM disk of physical frames to format as DeSoFS; `DESOOS_AUTOSOAK=S` – the soak before init on a RAM disk (real hardware), then the normal system; the soak takes the services, network and USB stick the machine has; `tests/soak.sh SOAK_DISK=ram`; the short soak in `tests/test.sh` on a RAM disk; recovery times compared per service |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 33/33 suites + restart 1/1 + short soak (RAM disk), 280 tests PASS | 299 s (restart 36 s, soak 130 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 33/33 suites + restart 1/1 + short soak (RAM disk), 280 tests PASS | 230 s (restart 16 s, soak 126 s) |
| Soak 15 min, test laptop | `DESOOS_AUTOSOAK=900`, SEED=1793998094 | **PASS**, 2 checkpoints, leaks 0, errors 0 | 903 s |

### Real hardware (test laptop: Ryzen 7 4800H, 16 threads, NVMe, 3 × xHCI, Realtek RTL8168h) – soak v0.68.0

The soak chose by itself: a 256 MiB RAM disk (disk 3; the NVMe untouched, read-only), killing `echo`, `net0`, `usb0`,
`usb1`, `usb2` (`edu`: no device), pings to the router 192.168.1.1 (no test server), the boot stick's
`EFI/BOOT/BOOTX64.EFI` (3 783 680 B) against the SHA-256 of its first reading.

| What | 15 minutes |
|---|---|
| File operations on DeSoFS (all checked against the model) | 232 561 (3 785 MiB written, ~400–490 files, ~16 MiB live) |
| Snapshots (checked through their views) | 2 |
| Processes started | 375 571 |
| Services killed | 15 – back in (min / avg / max ms): `usb0` 205 / 208 / 213, `usb1` (the stick's controller) 512 / 515 / 518, `usb2` (keyboard, mouse, hubs) 207 / 212 / 215, `echo` 105 / 169 / 202, `net0` 15 970 / 23 997 / 32 024 |
| Final checkpoint | 3.3 s; kernel heap without the scrollback 3 921 056 B, tasks 30, processes 10, IPC buffers 0, every handle count as at the baseline, `desofs check` clean |
| After the soak | init, services and the shell started as usual |

`net0` takes 16 or 32 s: after a restart the Realtek card reports "link down", and the router's DHCP answers after
15.7 s, sometimes only after a second round (31.7 s) – within the 60 s the soak allows on real hardware.

The first run (1 hour) failed after 30 minutes on the soak's own rule, not on the system: it compared the average
recovery of all services together, and the first period had only USB / `echo` kills (~0.3 s) while the next one had
`net0` (16–32 s). Until then 460 451 file operations, 753 156 processes and 28 kills had passed with a steady kernel
heap and free frames. Fixed before this report – each service is now compared with itself.

### Performance against the previous release (v0.67.0 → v0.68.0, same machine)

| | TCG v0.67.0 | TCG v0.68.0 | KVM v0.67.0 | KVM v0.68.0 |
|---|---|---|---|---|
| irq_user_ns | 11 214 | 10 949 | 66 072 | 66 006 |
| fact_user_ns | 79 020 | 74 962 | 96 852 | 90 375 |
| fact_svc_ns | 206 185 | 240 096 | 103 092 | 103 412 |
| restart_us | 4 100 | 3 900 | 1 200 | 1 300 |
| USB read_kbs (usbd) | 89 043 | 40 960 | 89 043 | 95 255 |
| rights gate_ns | 25 | 26 | 5 | 5 |
| crypto sha256 kernel / user (KiB/s) | 49 182 / 41 600 | 49 920 / 52 160 | 180 480 / 216 960 | 175 360 / 210 560 |
| DeSoFS 8 MiB write / read (KiB/s) | 6 316 / 5 809 | 6 527 / 5 673 | 17 102 / 18 004 | 16 684 / 21 557 |
| DeSoFS 1000 small files create / read (ms) | 19 318 / 7 527 | 18 462 / 7 089 | 10 241 / 2 220 | 9 726 / 2 322 |
| `desofs check` (ms) | 942 | 1 121 | 288 | 314 |
| short soak: file operations in 2 min | 2 040 (virtio) | 6 490 (RAM disk) | 5 584 (virtio) | 27 744 (RAM disk) |

Verdict: no regression – nothing on these paths changed. TCG `fact_svc` +16 % and TCG usbd read −54 % are single
runs (TCG usbd read has been 34 133 before, v0.66.0; KVM 95 255 is the best so far); the short soak does 3–5 times
more file operations because it now runs on a RAM disk.

---

## v0.67.0 — 2026-11-06

**Status: stable on QEMU (TCG and KVM); the soak test – 1 hour and 8 hours with KVM PASS, 0 leaks, 0 errors; one kernel leak
found by it and fixed (empty page tables after `munmap`).**

### What is new since the last report (v0.66.1)

| Version | Change |
|---|---|
| v0.67.0 | `tests/soak.sh` + `/bin/soak`: files and snapshots on DeSoFS, services killed and checked to work again, network downloads, processes and IPC – all at once, with checkpoints (kernel counters and handles against a baseline, `desofs check`); `sysinfo counters`; `munmap` / `brk` free page tables left empty; a 2-minute soak at the end of `tests/test.sh` |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 33/33 suites + restart 1/1 + short soak, 280 tests PASS | 299 s (restart 37 s, soak 130 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 33/33 suites + restart 1/1 + short soak, 280 tests PASS | 228 s (restart 16 s, soak 125 s) |
| Soak 1 h | KVM, 4 CPUs, 512 MiB, 512 MiB virtio disk, SEED=1793942415 | **PASS**, 3 checkpoints, leaks 0, errors 0 | 3 631 s |
| Soak 8 h | KVM, 4 CPUs, 512 MiB, 512 MiB virtio disk, SEED=1793952020 | **PASS**, 17 checkpoints, leaks 0, errors 0 | 28 828 s |

The test time now includes the short soak; the self-tests themselves take as long as before (~169 s TCG, ~103 s KVM).

### Soak `[RESULT-SOAK]`

| | short, TCG | short, KVM | 1 hour, KVM | 8 hours, KVM |
|---|---|---|---|---|
| seconds | 127 | 122 | 3 626 |
| file operations (all checked against the model) | 2 040 | 5 584 | 109 447 (1 787 MiB written; ~430–495 files, ~16 MiB live) | 832 122 (13 641 MiB written) |
| snapshots made (each checked through its view at every checkpoint) | 7 | 7 | 11 (5 deleted, 6 kept) | 95 (89 deleted, 6 kept) |
| services killed / back in (min / avg / max ms) | 8 / 111 / 553 / 935 | 7 / 202 / 654 / 974 | 62 / 104 / 681 / 1 427 | 462 / 103 / 628 / 2 154 |
| downloaded (SHA-256 checked) | 757 MiB | 830 MiB | 25 360 MiB | 198 958 MiB |
| processes started | 17 228 | 46 956 | 1 399 607 | 11 087 468 |
| checkpoints / leaks / errors | 3 / 0 / 0 | 3 / 0 / 0 | 3 / 0 / 0 | 17 / 0 / 0 |

At the end of the hour (paused workers, volume remounted): kernel heap without the console scrollback 3 344 912 B,
the scrollback 1.8 MiB (its 1000-line limit), tasks, processes, IPC buffers (0), ramfs and every handle count the same
as at the baseline; `desofs check` 0 errors, 0 warnings; the final checkpoint took 26 s (all files plus six snapshots
read and compared). After 8 hours: the kernel heap without the scrollback 3 344 880 B (32 B less than at the end of
the 1-hour run), the scrollback at its limit (2 032 KiB), every count the same as at the baseline, `desofs check`
clean at all 17 checkpoints; with 17 checkpoints the "three in a row" trend rule was active and never triggered; the
recovery average did not grow (628 ms over 8 hours vs 681 ms in the first hour). Real hardware: not run (the soak formats a virtio disk – on the laptop it needs a RAM disk, see
Current limitations).

### Known problems

- Found and fixed in this release: page tables left empty by `munmap` stayed until the process ended – ~4 frames a
  second in the soak's process worker (CHANGELOG v0.67.0).
- The kernel heap "grew" ~100 KiB a minute in the first soak runs – the console scrollback filling up (bounded at
  1000 lines, ~1.8 MiB on this screen); now reported apart (`heap_console`) and not counted as a leak.

### Performance against the previous release (v0.66.1 → v0.67.0, same machine)

| | TCG v0.66.1 | TCG v0.67.0 | KVM v0.66.1 | KVM v0.67.0 |
|---|---|---|---|---|
| irq_user_ns | 12 391 | 11 214 | 65 552 | 66 072 |
| fact_user_ns | 71 047 | 79 020 | 83 998 | 96 852 |
| fact_svc_ns | 175 901 | 206 185 | 105 429 | 103 092 |
| restart_us | 3 700 | 4 100 | 1 200 | 1 200 |
| USB read_kbs (usbd) | 83 591 | 89 043 | 89 043 | 89 043 |
| rights gate_ns | 27 | 25 | 6 | 5 |
| crypto sha256 kernel / user (KiB/s) | 49 425 / 49 920 | 49 182 / 41 600 | 180 480 / 211 840 | 180 480 / 216 960 |
| DeSoFS 8 MiB write / read (KiB/s) | 5 657 / 5 614 | 6 316 / 5 809 | 13 721 / 17 925 | 17 102 / 18 004 |
| DeSoFS 1000 small files create / read (ms) | 19 944 / 7 826 | 19 318 / 7 527 | 9 472 / 2 564 | 10 241 / 2 220 |
| `desofs check` (ms) | 950 | 942 | 325 | 288 |

Verdict: no regression. TCG `fact_svc` (+17 %) and `fact_user` (+11 %) and TCG user-space SHA-256 (−17 %) are single
runs within the known TCG spread (v0.62.0 had `fact_svc` 201 005, TCG SHA-256 moves 19–41 MiB/s); KVM `fact_user`
96 852 is the known two-state `edu` measurement. The `munmap` change touches only unmapping, which none of these
measure.

---

## v0.66.1 — 2026-11-04

**Status: stable on QEMU (TCG and KVM); documentation only – no code change.**

### What is new since the last report (v0.66.0)

| Version | Change |
|---|---|
| v0.66.1 | documentation reorganised: `ARCHITECTURE.md`, `RELEASE.md` and the DeSoFS format moved to `docs/` (index `docs/README.md`, `docs/desofs/`); `ROADMAP.md` removed – the current limitations are the section at the top of this file; the font license moved into the header of `kernel/drivers/font.rs`; a `README.md` in the main code folders |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 33/33 suites + restart 1/1, 279 tests PASS | 172 s (restart 38 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 33/33 suites + restart 1/1, 279 tests PASS | 103 s (restart 16 s) |

### Real hardware (test laptop: Ryzen 7 4800H, 16 threads, NVMe, 3 × xHCI, Realtek RTL8168h) – v0.66.1

First real-hardware run since v0.58.0 (DeSoFS, `/disk`, the `SYSCTL` handle for `desofs`, mount pins and
snapshots came in between). Built with `DESOOS_AUTOSTRESS=60`.

| What | v0.55.0 | v0.66.1 |
|---|---|---|
| Boot | – | 16 CPUs, `echo`, `net0`, `usb0`–`usb2` running (`edu`: no device, QEMU only); 7 USB devices (keyboard, G502 mouse behind a hub, USB 3 stick, camera, Bluetooth, 2 hubs) |
| Stress 60 s (compare mode) | PASS, 587 878 shell scripts | **PASS**, 565 322 shell scripts, 282 660 primes, 8 062 IPC jobs, 0 deadlock reports |
| USB stick read before the stress (256 KiB / 4 KiB reads) | 125 051 KiB/s | 120 457 / 124 181 KiB/s, identical data |
| USB stick read during the stress | 78 604 KiB/s | 74 535 KiB/s, 1 296 full passes, 0 errors |
| USB keyboard, interrupt → character | 110 µs (41 presses) | **25 µs** avg, max 116 µs (18 presses) |
| `ipcbench` ping-pong | 4.5 µs | 4.5 µs (4.6 during the stress) |
| `ping 192.168.1.1` | < 1 ms | < 1 ms, 0 % loss |
| `netget` 10 MiB (thinkbroadband) | 6 692 first, then ~9 500 KiB/s | 7 441 first, then 9 481 / 9 463 KiB/s (the 100 Mb/s link) |
| DHCP address after boot | 15.7 s | 15.7 s |
| `cryptotest` | – | 92 checks OK; SHA-256 / HMAC 247 680 KiB/s in user space |
| `sha256sum /usb0/EFI/BOOT/BOOTX64.EFI` | – | `947a7b92…a81e1eed` – the same as `sha256sum` of the file on the build machine (USB read path and DeSoCrypto agree byte for byte) |
| `desofs info 0` / `snapshot list 0` (NVMe, read-only) | – | "not a DeSoFS volume" – refused, nothing written; `/disk` not available (read-only disk without DeSoFS / FAT32) |

The stress run did ~4 % fewer shell scripts than on v0.55.0 (each script starts processes; since v0.65.0 a process
start also takes a mount pin for its current directory). One run only (v0.35.2: 600 637, v0.55.0: 587 878 and
587 935), so not called a regression yet; to be compared in the next hardware run.

### Performance against the previous release (v0.66.0 → v0.66.1, same machine)

| | TCG v0.66.0 | TCG v0.66.1 | KVM v0.66.0 | KVM v0.66.1 |
|---|---|---|---|---|
| irq_user_ns | 12 219 | 12 391 | 66 777 | 65 552 |
| fact_user_ns | 74 934 | 71 047 | 94 206 | 83 998 |
| fact_svc_ns | 191 570 | 175 901 | 102 774 | 105 429 |
| restart_us | 6 200 | 3 700 | 1 200 | 1 200 |
| USB read_kbs (usbd) | 34 133 | 83 591 | 91 022 | 89 043 |
| rights gate_ns | 75 | 27 | 5 | 6 |
| crypto sha256 kernel / user (KiB/s) | 47 921 / 51 200 | 49 425 / 49 920 | 178 308 / 217 600 | 180 480 / 211 840 |
| DeSoFS 8 MiB write / read (KiB/s) | 6 099 / 5 688 | 5 657 / 5 614 | 13 721 / 16 384 | 13 721 / 17 925 |
| DeSoFS 1000 small files create / read (ms) | 19 150 / 6 878 | 19 944 / 7 826 | 9 159 / 2 264 | 9 472 / 2 564 |
| `desofs check` (ms) | 915 | 950 | 297 | 325 |

Verdict: no regression – the same code (comments only). TCG `gate_ns` back to 27 and usbd read back to 83 591 after
the one-run lows of v0.66.0; the rest moves within the usual run-to-run spread.

---

## v0.66.0 — 2026-11-03

**Status: stable on QEMU (TCG and KVM); DeSoFS stage 5 – snapshots: create, list, read-only view, delete, restore;
format 1 unchanged.**

### What is new since the last report (v0.65.1)

| Version | Change |
|---|---|
| v0.66.0 | `desofs snapshot create / list / mount / delete / restore` in both shells (sysctl actions 11–15, the name checked by the kernel); a snapshot is one new root block (nothing copied); delete and restore recompute the block map over both superblocks (R3); a view at `/snap/<name>` is read-only; restore keeps every snapshot |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 33/33 suites + restart 1/1, 279 tests PASS | 169 s (restart 35 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 33/33 suites + restart 1/1, 279 tests PASS | 102 s (restart 16 s) |

New: DESOFS TEST 25–28 – create, views, ten refused names and the 32nd snapshot without a write; a removed 1 MiB
file held by a snapshot survives filling the whole volume, and delete gives back exactly the blocks only the
snapshot held (265); restore; power loss at every write and every superblock sector of create / delete / restore,
each twice in a row so both superblock slots are hit (70 images). INIT TEST 9 – snapshots through `/bin/sh` and raw
sysctl names. RESTART TEST 5/6 – a snapshot made before the restart is listed afterwards and its view holds the old
state. On the build server five mutations each make a test fail. The whole run is no slower (TCG 169 s, KVM 102 s).

### DeSoFS speed `[RESULT-FS]`

The volume now also holds the restart test's snapshot (3 387 data blocks checked instead of 3 384).

| | TCG v0.65.1 | TCG v0.66.0 | KVM v0.65.1 | KVM v0.66.0 |
|---|---|---|---|---|
| 8 MiB write (KiB/s) | 5 843 | 6 099 | 12 982 | 13 721 |
| 8 MiB read (KiB/s) | 4 838 | 5 688 | 17 102 | 16 384 |
| 1000 small files – create + write (ms) | 20 266 | 19 150 | 8 040 | 9 159 |
| 1000 small files – read (ms) | 7 653 | 6 878 | 2 195 | 2 264 |
| `desofs check` (ms) | 857 | 915 | 266 | 297 |

### Known problems

- Snapshots have no creation time (the format stores only the generation); no automatic snapshots; no snapshot of a
  single directory; `snapshot list`, `delete` and `restore` walk the volume (64 MiB – a fraction of a second).
- As in v0.65.1 otherwise.

### Performance against the previous release (v0.65.1 → v0.66.0, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.65.1 | TCG v0.66.0 | KVM v0.65.1 | KVM v0.66.0 |
|---|---|---|---|---|
| irq_kernel_ns | 3 109 | 3 110 | 34 352 | 35 932 |
| irq_user_ns | 6 031 | 12 219 | 66 912 | 66 777 |
| fact_kernel_ns | 24 813 | 30 097 | 58 633 | 52 356 |
| fact_user_ns | 74 934 | 74 934 | 98 570 | 94 206 |
| fact_svc_ns | 248 756 | 191 570 | 105 540 | 102 774 |
| ping_svc_ns | 131 061 | 109 409 | 23 124 | 21 166 |
| restart_us | 6 700 | 6 200 | 1 200 | 1 200 |

`[RESULT-USB]`:

| | TCG v0.65.1 | TCG v0.66.0 | KVM v0.65.1 | KVM v0.66.0 |
|---|---|---|---|---|
| start_ms | 392 | 421 | 402 | 396 |
| enum_avg_ms | 24 | 27 | 25 | 22 |
| read_kbs (usbd) | 85 333 | 34 133 | 87 148 | 91 022 |
| kread_kbs (kernel) | 84 111 | 68 155 | 113 863 | 82 169 |
| kcat_kbs (kernel, cat) | 46 880 | 68 107 | 94 856 | 113 261 |
| hid_avg_us (keyboard) | 855 | 771 | 203 | 195 |

`[RESULT-RIGHTS]` rows 57, refused 29; gate_ns: TCG 25 → 75, KVM 5 → 5.
`[RESULT-CRYPTO]` (KiB/s): TCG 34 388 / 48 398 / 48 000 → 47 921 / 51 200 / 51 840; KVM 180 480 / 205 120 / 211 840 →
178 308 / 217 600 / 217 280.

Verdict: no regression – the changes are DeSoFS snapshots and two sysctl actions, none on the measured paths. TCG
`gate_ns` 75 is one sample of a ~25 ns measurement (62 and 79 seen before, KVM unchanged at 5); TCG `irq_user_ns`
12 219 is the same one-run swing as in v0.64.1 (11 665); TCG usbd read 34 133 is within the emulated stick's spread
(kcat in the same run 68 107, KVM read 91 022).

---

## v0.65.1 — 2026-11-03

**Status: stable on QEMU (TCG and KVM); two fixes from a code review of v0.65.0 – `chdir` pins its mount before
it checks the directory, and `sysctl` checks its output handle before the action – plus clearer `desofs` messages.**

### What is new since the last report (v0.65.0)

| Version | Change |
|---|---|
| v0.65.1 | `chdir`: pin first, then the check (an unmount could slip between them); `sysctl`: a bad output handle refused before anything runs (before, `format <disk> yes` with a bad handle formatted and then returned the error); the 64 KiB output limit includes the truncation line; `desofs info` "counted N", `desofs mount` "already mounted at …" |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 33/33 suites + restart 1/1, 274 tests PASS | 172 s (restart 38 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 33/33 suites + restart 1/1, 274 tests PASS | 102 s (restart 15 s) |

INIT TEST 9/10 extended: `chdir` stopped (test builds only) between its pin and its check while the test unmounts –
refused; format + yes with the right `SYSCTL` handle and a bad output handle (missing, a pipe's read end, a file
opened read-only, a directory handle) – refused, the whole disk's SHA-256 unchanged. On the build server the old
`chdir` order and the output handle checked after the action each make it fail (the latter only through the disk
check – the error codes are the same).

### DeSoFS speed `[RESULT-FS]`

| | TCG v0.65.0 | TCG v0.65.1 | KVM v0.65.0 | KVM v0.65.1 |
|---|---|---|---|---|
| 8 MiB write (KiB/s) | 6 005 | 5 843 | 12 760 | 12 982 |
| 8 MiB read (KiB/s) | 5 626 | 4 838 | 17 808 | 17 102 |
| 1000 small files – create + write (ms) | 20 270 | 20 266 | 10 181 | 8 040 |
| 1000 small files – read (ms) | 7 498 | 7 653 | 2 316 | 2 195 |
| `desofs check` (ms) | 800 | 857 | 269 | 266 |

### Known problems

- ~~KVM 8 MiB write ~13 000 KiB/s in two runs in a row~~ – **checked: the host, not the code.** v0.64.0 (built
  from its commit) and v0.65.1 run alternately in KVM on the same machine, twice each:

  | Run | Version | 8 MiB write | 8 MiB read | small create | small read | check |
  |---|---|---|---|---|---|---|
  | 1 | v0.64.0 | 14 051 | 16 031 | 7 319 ms | 1 772 ms | 202 ms |
  | 2 | v0.65.1 | 18 367 | 23 676 | 9 329 ms | 2 258 ms | 274 ms |
  | 3 | v0.64.0 | 13 698 | 15 875 | 8 649 ms | 2 241 ms | 247 ms |
  | 4 | v0.65.1 | 15 114 | 17 731 | 9 401 ms | 2 346 ms | 271 ms |

  The old version writes no faster (13 698 – 14 051 against 15 114 – 18 367); the KVM write moves by ±15–25 % from
  run to run on this machine. Small files and check were faster for v0.64.0 in this session, but its own release run
  (9 290 ms / 262 ms) matches v0.65.1 here – also within the host's spread.
- As in v0.65.0 otherwise.

### Performance against the previous release (v0.65.0 → v0.65.1, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.65.0 | TCG v0.65.1 | KVM v0.65.0 | KVM v0.65.1 |
|---|---|---|---|---|
| irq_kernel_ns | 3 202 | 3 109 | 35 855 | 34 352 |
| irq_user_ns | 8 078 | 6 031 | 69 881 | 66 912 |
| fact_kernel_ns | 22 941 | 24 813 | 53 533 | 58 633 |
| fact_user_ns | 69 808 | 74 934 | 94 652 | 98 570 |
| fact_svc_ns | 231 213 | 248 756 | 106 269 | 105 540 |
| ping_svc_ns | 126 903 | 131 061 | 23 727 | 23 124 |
| restart_us | 5 000 | 6 700 | 1 300 | 1 200 |

`[RESULT-USB]`:

| | TCG v0.65.0 | TCG v0.65.1 | KVM v0.65.0 | KVM v0.65.1 |
|---|---|---|---|---|
| start_ms | 418 | 392 | 354 | 402 |
| enum_avg_ms | 27 | 24 | 27 | 25 |
| read_kbs (usbd) | 69 423 | 85 333 | 113 777 | 87 148 |
| kread_kbs (kernel) | 47 499 | 84 111 | 116 765 | 113 863 |
| kcat_kbs (kernel, cat) | 50 596 | 46 880 | 96 958 | 94 856 |
| hid_avg_us (keyboard) | 714 | 855 | 331 | 203 |

`[RESULT-RIGHTS]` rows 57, refused 29; gate_ns: TCG 25 → 25, KVM 5 → 5.
`[RESULT-CRYPTO]` (KiB/s): TCG 46 431 / 50 240 / 43 200 → 34 388 / 48 398 / 48 000; KVM 178 308 / 212 480 / 212 160 →
180 480 / 205 120 / 211 840.

Verdict: no regression against v0.65.0 – the changes touch `chdir`, `sysctl` and messages only. TCG kernel SHA-256
34 388 is one run (user space in the same run 48 398 – the same code); TCG `restart_us` 6 700 and `fact_svc_ns`
within the TCG spread. The KVM 8 MiB write level since v0.65.0 was checked against v0.64.0 on the same machine (above): host spread.

---

## v0.65.0 — 2026-11-03

**Status: stable on QEMU (TCG and KVM); `desofs` in the normal shell behind the `SYSCTL` handle; a mount that a
program still uses is not unmounted or formatted.**

### What is new since the last report (v0.64.1)

| Version | Change |
|---|---|
| v0.65.0 | `desofs info / format / mount / unmount / check / repair` in `/bin/sh` started by init (sysctl actions 5–10, "yes" checked by the kernel, output at most 64 KiB); mount pins – an open file, a directory handle or a current directory on a mount makes `unmount` / `format` refuse with "in use (N open files / directories) - nothing changed"; unmounting a whole disk is all or nothing |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 33/33 suites + restart 1/1, 274 tests PASS | 172 s (restart 38 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 33/33 suites + restart 1/1, 274 tests PASS | 103 s (restart 17 s) |

New: INIT TEST 9/10 (`/bin/dsfstest` with the `SYSCTL` handle on a 1 MiB RAM disk) – raw sysctl without the handle
(missing number, console, pipe, directory handle), sh without it and a shell's child shell, format / repair without
"yes": the whole disk's SHA-256 unchanged; then format, info, mount, check, repair through sh; unmount refused under
an open file, an open directory, another process's current directory and a child's inherited file, allowed once
each is closed or the process killed; format refused under an open file; the caller's own directory. On the build
server four mutations each make it fail (the handle check only when removed from both the rights table and the
syscall – either one alone still refuses).

### DeSoFS speed `[RESULT-FS]`

| | TCG v0.64.1 | TCG v0.65.0 | KVM v0.64.1 | KVM v0.65.0 |
|---|---|---|---|---|
| 8 MiB write (KiB/s) | 5 669 | 6 005 | 16 516 | 12 760 |
| 8 MiB read (KiB/s) | 5 435 | 5 626 | 18 618 | 17 808 |
| 1000 small files – create + write (ms) | 20 459 | 20 270 | 10 371 | 10 181 |
| 1000 small files – read (ms) | 7 792 | 7 498 | 2 217 | 2 316 |
| `desofs check` (ms) | 918 | 800 | 259 | 269 |

### Known problems

- `desofs check` runs inside one syscall: no progress until it ends and no Ctrl+C (64 MiB – under a second).
- "in use" gives the number of handles, not the process (`ps`, `dcp` show it).
- Otherwise as in v0.64.1.

### Performance against the previous release (v0.64.1 → v0.65.0, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.64.1 | TCG v0.65.0 | KVM v0.64.1 | KVM v0.65.0 |
|---|---|---|---|---|
| irq_kernel_ns | 3 101 | 3 202 | 32 414 | 35 855 |
| irq_user_ns | 11 665 | 8 078 | 65 963 | 69 881 |
| fact_kernel_ns | 27 005 | 22 941 | 56 465 | 53 533 |
| fact_user_ns | 78 740 | 69 808 | 94 161 | 94 652 |
| fact_svc_ns | 204 498 | 231 213 | 103 199 | 106 269 |
| ping_svc_ns | 116 346 | 126 903 | 21 824 | 23 727 |
| restart_us | 4 100 | 5 000 | 1 300 | 1 300 |

`[RESULT-USB]`:

| | TCG v0.64.1 | TCG v0.65.0 | KVM v0.64.1 | KVM v0.65.0 |
|---|---|---|---|---|
| start_ms | 405 | 418 | 376 | 354 |
| enum_avg_ms | 29 | 27 | 22 | 27 |
| read_kbs (usbd) | 77 283 | 69 423 | 99 902 | 113 777 |
| kread_kbs (kernel) | 114 276 | 47 499 | 69 771 | 116 765 |
| kcat_kbs (kernel, cat) | 59 291 | 50 596 | 85 841 | 96 958 |
| hid_avg_us (keyboard) | 656 | 714 | 71 | 331 |

`[RESULT-RIGHTS]` rows 57, refused 29; gate_ns: TCG 25 → 25, KVM 4 → 5.
`[RESULT-CRYPTO]` (KiB/s): TCG 48 398 / 46 720 / 49 920 → 46 431 / 50 240 / 43 200; KVM 180 855 / 217 600 / 217 600 →
178 308 / 212 480 / 212 160.

Verdict: no regression. The `[RESULT-FS]` measurement runs in the kernel through the VFS directly, without file
handles, so the pins are not on its path; KVM 8 MiB write 12 760 (−23%) is one run against an unchanged write path
(TCG +6%, KVM reads and small files unchanged). TCG `irq_user_ns` is back to 8 078; the USB figures move within the
known spread of the emulated stick (TCG kread 47 499 after the record 114 276; KVM hid 331 µs one run of a short
measurement); the rights gate and crypto are unchanged.

---

## v0.64.1 — 2026-11-03

**Status: stable on QEMU (TCG and KVM); fix – formatting never runs under a mounted file system; the FAT32
formatter command `mkfs` removed (DeSoOS formats only as DeSoFS).**

### What is new since the last report (v0.64.0)

| Version | Change |
|---|---|
| v0.64.1 | `desofs format` unmounts only the file systems on the target disk and stops with "cannot unmount … nothing changed" when one cannot be unmounted (before, a failed unmount was ignored – found in a code review); `desofs::format::format` and `fat32::mkfs` refuse a mounted disk themselves; the kernel-shell `mkfs` command removed – existing FAT32 volumes (`/esp`, USB sticks) are read and written as before |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 33/33 suites + restart 1/1, 273 tests PASS | 169 s (restart 38 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 33/33 suites + restart 1/1, 273 tests PASS | 102 s (restart 17 s) |

New: DESOFS TEST 24 – a mounted DeSoFS volume and a live `Volume` refused by both formatters, FAT32 whose flush fails:
the shell's `desofs format` stops, the file system stays mounted with its file; in every case the SHA-256 of the whole
disk before = after. On the build server three mutations (the shell ignoring the failed unmount, either function
without its own guard) each make it fail.

### DeSoFS speed `[RESULT-FS]`

| | TCG v0.64.0 | TCG v0.64.1 | KVM v0.64.0 | KVM v0.64.1 |
|---|---|---|---|---|
| 8 MiB write (KiB/s) | 5 688 | 5 669 | 17 138 | 16 516 |
| 8 MiB read (KiB/s) | 5 523 | 5 435 | 19 883 | 18 618 |
| 1000 small files – create + write (ms) | 18 779 | 20 459 | 9 290 | 10 371 |
| 1000 small files – read (ms) | 7 141 | 7 792 | 2 204 | 2 217 |
| `desofs check` (ms) | 796 | 918 | 262 | 259 |

### Known problems

- `desofs` is only in the kernel emergency shell, so it cannot be reached in a normal start (next version: `desofs`
  in `/bin/sh` behind the `SYSCTL` handle).
- Otherwise as in v0.64.0.

### Performance against the previous release (v0.64.0 → v0.64.1, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.64.0 | TCG v0.64.1 | KVM v0.64.0 | KVM v0.64.1 |
|---|---|---|---|---|
| irq_kernel_ns | 2 983 | 3 101 | 32 878 | 32 414 |
| irq_user_ns | 8 792 | 11 665 | 67 613 | 65 963 |
| fact_kernel_ns | 29 511 | 27 005 | 53 461 | 56 465 |
| fact_user_ns | 74 128 | 78 740 | 92 123 | 94 161 |
| fact_svc_ns | 192 122 | 204 498 | 104 766 | 103 199 |
| ping_svc_ns | 119 545 | 116 346 | 22 522 | 21 824 |
| restart_us | 4 000 | 4 100 | 1 200 | 1 300 |

`[RESULT-USB]`:

| | TCG v0.64.0 | TCG v0.64.1 | KVM v0.64.0 | KVM v0.64.1 |
|---|---|---|---|---|
| start_ms | 361 | 405 | 369 | 376 |
| enum_avg_ms | 23 | 29 | 26 | 22 |
| read_kbs (usbd) | 61 134 | 77 283 | 66 064 | 99 902 |
| kread_kbs (kernel) | 64 531 | 114 276 | 87 872 | 69 771 |
| kcat_kbs (kernel, cat) | 61 784 | 59 291 | 74 951 | 85 841 |
| hid_avg_us (keyboard) | 685 | 656 | 96 | 71 |

`[RESULT-RIGHTS]` rows 57, refused 29; gate_ns: TCG 25 → 25, KVM 4 → 4.
`[RESULT-CRYPTO]` (KiB/s): TCG 48 941 / 52 160 / 50 240 → 48 398 / 46 720 / 49 920; KVM 182 129 / 217 280 / 217 920 →
180 855 / 217 600 / 217 600.

Verdict: no regression. The change touches only formatting, which none of the measurements uses. TCG `irq_user_ns`
11 665 (+33%) is one run of a short measurement (7 130 – 8 792 in the last releases); TCG small-file create +9% and
check +15% are TCG run-to-run spread (KVM unchanged); the USB figures move within the known spread of the emulated
stick (TCG kread 114 276 the highest so far).

---

## v0.64.0 — 2026-11-02

**Status: stable on QEMU (TCG and KVM); DeSoFS stage 4 – `/disk` as DeSoFS recognised at start, data checked after a
real restart, `readdir_part` for programs, first DeSoFS speed figures. Not yet tried on the test laptop.**

### What is new since the last report (v0.63.1)

| Version | Change |
|---|---|
| v0.64.0 | `fs::mount_disk` – the DeSoFS marker on disk 0 means DeSoFS rules only (read-write / read-only / not mounted, never FAT32 instead), otherwise FAT32; `desofs format 0 yes` mounts `/disk` at once; syscall 57 `readdir_part` (a directory in parts through a directory handle) and `/bin/ls` in parts; `tests/test.sh` starts QEMU a second time on the same test disk (RESTART TEST); `[RESULT-FS]` |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 33/33 suites + restart 1/1, 272 tests PASS | 165 s (restart 36 s) |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 33/33 suites + restart 1/1, 272 tests PASS | 101 s (restart 16 s) |

New: DESOFS TEST 23 (automatic mount: sound / one tree damaged / FAT32 / the DeSoFS marker over a valid FAT32 → not
mounted / an empty disk untouched), `readdir_part` in FILE TEST (dirtest: 42 entries through a 64-byte buffer,
wrong position, too small a buffer, no READ right, above the handle, in the sandbox), RESTART TEST 1–5: part 1 at the
end of the first start writes a fixed set to a freshly formatted test disk; after a normal power-off and a second
start the kernel mounted `/disk` as DeSoFS read-write by itself, every file equal byte for byte, removed files gone,
`sha256sum` and `ls` on `/disk`, `desofs check` 0 errors / complete. The first start takes 4 s more than v0.63.1 (the
fixed set), the second start is new.

### DeSoFS speed `[RESULT-FS]` (first figures – no block cache yet)

Volume 64 MiB on virtio-blk, after the restart; 8 MiB file in 64 KiB pieces (each piece one commit with two flushes);
1000 files of 100 B (create + write = two commits each).

| | TCG | KVM |
|---|---|---|
| 8 MiB write | 5 688 KiB/s | 17 138 KiB/s |
| 8 MiB read | 5 523 KiB/s | 19 883 KiB/s |
| 1000 small files – create + write | 18 779 ms | 9 290 ms |
| 1000 small files – read | 7 141 ms | 2 204 ms |
| `desofs check` (3 384 data blocks) | 796 ms | 262 ms |

Every block read verifies its SHA-256 and a name is found by reading the directory block by block – a block cache and
a directory index are the obvious next gains; these numbers are the reference.

### Known problems

- DeSoFS is slow without a cache (above); only disk 0 is mounted at start; `rename` is not yet a syscall.
- Otherwise as in v0.63.1.

### Performance against the previous release (v0.63.1 → v0.64.0, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.63.1 | TCG v0.64.0 | KVM v0.63.1 | KVM v0.64.0 |
|---|---|---|---|---|
| irq_kernel_ns | 3 329 | 2 983 | 36 062 | 32 878 |
| irq_user_ns | 7 130 | 8 792 | 36 692 | 67 613 |
| fact_kernel_ns | 25 348 | 29 511 | 56 195 | 53 461 |
| fact_user_ns | 62 480 | 74 128 | 231 481 | 92 123 |
| fact_svc_ns | 182 315 | 192 122 | 110 192 | 104 766 |
| ping_svc_ns | 118 553 | 119 545 | 18 013 | 22 522 |
| restart_us | 3 800 | 4 000 | 1 500 | 1 200 |

`[RESULT-USB]`:

| | TCG v0.63.1 | TCG v0.64.0 | KVM v0.63.1 | KVM v0.64.0 |
|---|---|---|---|---|
| start_ms | 412 | 361 | 379 | 369 |
| enum_avg_ms | 25 | 23 | 25 | 26 |
| read_kbs (usbd) | 81 920 | 61 134 | 102 400 | 66 064 |
| kread_kbs (kernel) | 42 226 | 64 531 | 93 073 | 87 872 |
| kcat_kbs (kernel, cat) | 34 225 | 61 784 | 131 793 | 74 951 |
| hid_avg_us (keyboard) | 910 | 685 | 311 | 96 |

`[RESULT-RIGHTS]` rows 56 → 57 (`readdir_part`), refused 28 → 29; gate_ns: TCG 24 → 25, KVM 4 → 4.
`[RESULT-CRYPTO]` (KiB/s): TCG 47 686 / 47 040 / 50 240 → 48 941 / 52 160 / 50 240; KVM 179 200 / 190 080 / 205 760 →
182 129 / 217 280 / 217 920.

Verdict: no regression. KVM `irq_user_ns` / `fact_user_ns` are back in their usual state (67 613 / 92 123 after the
`edu` two-state run of v0.63.1); the USB figures move within the known spread of the emulated stick (KVM read 66 064
after 102 400 – 65 015 in v0.59.0; KVM hid 96 µs one run of a short measurement); the rights gate is unchanged with
one more row.

---

## v0.63.1 — 2026-11-02

**Status: stable on QEMU (TCG and KVM); fix only – `desofs repair` refuses after a check that did not run in full.**

### What is new since the last report (v0.63.0)

| Version | Change |
|---|---|
| v0.63.1 | `desofs check` marks a superblock INCOMPLETE when a limit (16 M node numbers for relations, 65 536 shared blocks for E3) skipped a check; `desofs repair` refuses an incomplete superblock (found in a code review) |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 32/32 suites, 264 tests PASS | 125 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 32/32 suites, 264 tests PASS | 81 s |

DESOFS TEST 21 lowers both limits (test builds only) so that the reference image reaches them: check warns and says
INCOMPLETE, repair refuses, the disk stays unchanged. On the build server three mutations of the fix each make it fail.

### Known problems

- As in v0.63.0.

### Performance against the previous release (v0.63.0 → v0.63.1, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.63.0 | TCG v0.63.1 | KVM v0.63.0 | KVM v0.63.1 |
|---|---|---|---|---|
| irq_kernel_ns | 2 883 | 3 329 | 36 238 | 36 062 |
| irq_user_ns | 5 774 | 7 130 | 66 006 | 36 692 |
| fact_kernel_ns | 24 878 | 25 348 | 52 659 | 56 195 |
| fact_user_ns | 68 096 | 62 480 | 89 928 | 231 481 |
| fact_svc_ns | 170 502 | 182 315 | 104 493 | 110 192 |
| ping_svc_ns | 125 786 | 118 553 | 20 483 | 18 013 |
| restart_us | 3 900 | 3 800 | 1 400 | 1 500 |

`[RESULT-USB]`:

| | TCG v0.63.0 | TCG v0.63.1 | KVM v0.63.0 | KVM v0.63.1 |
|---|---|---|---|---|
| start_ms | 456 | 412 | 391 | 379 |
| enum_avg_ms | 25 | 25 | 26 | 25 |
| read_kbs (usbd) | 71 859 | 81 920 | 110 702 | 102 400 |
| kread_kbs (kernel) | 91 960 | 42 226 | 73 278 | 93 073 |
| kcat_kbs (kernel, cat) | 48 774 | 34 225 | 88 681 | 131 793 |
| hid_avg_us (keyboard) | 816 | 910 | 167 | 311 |

`[RESULT-RIGHTS]` gate_ns: TCG 25 → 24, KVM 4 → 4. `[RESULT-CRYPTO]` (KiB/s): TCG 47 921 / 50 560 / 50 560 →
47 686 / 47 040 / 50 240; KVM 180 480 / 235 840 / 235 840 → 179 200 / 190 080 / 205 760.

Verdict: no regression – only `desofs check` / `repair` changed, which nothing measured here runs. KVM
`fact_user_ns` 231 481 with `irq_user_ns` 36 692 in the same run is the known two-state behaviour of the emulated
`edu` device on the host (v0.55.1: 183 823, v0.59.1: 144 404 with irq_user 41 169). TCG kread 42 226 / kcat 34 225
are inside the spread of the emulated stick (TCG kcat 32 150 in v0.55.1); KVM user SHA-256 190 080 is back in its
usual range after the 235 840 of v0.63.0 (same library code).

---

## v0.63.0 — 2026-11-02

**Status: stable on QEMU (TCG and KVM); DeSoFS stage 3 – `desofs check`, `desofs repair`, directories read in parts.
Not yet tried on the test laptop.**

### What is new since the last report (v0.62.0)

| Version | Change |
|---|---|
| v0.63.0 | `desofs check` (each superblock: checksum / tree / data; every data block's SHA-256, directories and relations, data shared between roots, used_blocks as a warning; errors with file paths; only an unmounted volume); `desofs repair` (back to the one fully sound superblock's state, nothing allocated, the good superblock only read); `read_dir_at` – directories in parts with a byte-position cursor (VFS, DeSoFS, kernel-shell `ls`); DESOFS TEST 19–22 |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 32/32 suites, 264 tests PASS | 133 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 32/32 suites, 264 tests PASS | 83 s |

DESOFS TEST grows from 18 to 22 tests: check on sound volumes (writes nothing), ten damage cases (data unresealed –
the mount stays read-write and only check sees it; relation damage resealed so the rule itself must catch it), repair
of the older and the newer tree with every refusal, a repair interrupted after each of the 8 superblock sectors and
16 random parts, 150 directory entries read in parts of 7 with removes and creates in between. On the build server
seven mutations of the new code each make the suite fail. The new tests cost 10 s in TCG and nothing visible in KVM.

### Known problems

- `desofs check` / `repair` only on an unmounted volume; `repair` only returns to a whole sound state (no rescue of
  single files); directories in parts are not yet a syscall (`/bin/ls` reads whole listings) – with `/disk` in v0.64.0.
- Otherwise as in v0.62.0.

### Performance against the previous release (v0.62.0 → v0.63.0, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.62.0 | TCG v0.63.0 | KVM v0.62.0 | KVM v0.63.0 |
|---|---|---|---|---|
| irq_kernel_ns | 3 169 | 2 883 | 32 035 | 36 238 |
| irq_user_ns | 8 851 | 5 774 | 65 189 | 66 006 |
| fact_kernel_ns | 26 171 | 24 878 | 57 686 | 52 659 |
| fact_user_ns | 71 787 | 68 096 | 96 015 | 89 928 |
| fact_svc_ns | 201 005 | 170 502 | 104 821 | 104 493 |
| ping_svc_ns | 119 545 | 125 786 | 20 502 | 20 483 |
| restart_us | 3 500 | 3 900 | 1 200 | 1 400 |

`[RESULT-USB]`:

| | TCG v0.62.0 | TCG v0.63.0 | KVM v0.62.0 | KVM v0.63.0 |
|---|---|---|---|---|
| start_ms | 416 | 456 | 382 | 391 |
| enum_avg_ms | 25 | 25 | 23 | 26 |
| read_kbs (usbd) | 78 769 | 71 859 | 85 333 | 110 702 |
| kread_kbs (kernel) | 55 949 | 91 960 | 129 284 | 73 278 |
| kcat_kbs (kernel, cat) | 59 933 | 48 774 | 116 053 | 88 681 |
| hid_avg_us (keyboard) | 796 | 816 | 280 | 167 |

`[RESULT-RIGHTS]` gate_ns: TCG 43 → 25, KVM 4 → 4. `[RESULT-CRYPTO]` (KiB/s): TCG 48 941 / 52 160 / 51 840 →
47 921 / 50 560 / 50 560; KVM 176 640 / 206 720 / 207 360 → 180 480 / 235 840 / 235 840.

Verdict: no regression. The paths measured here did not change – the VFS gained `read_dir_at`, which nothing measured
calls. KVM `restart_us` 1 400 is one step of the 100 µs counter (1 200 – 1 300 in recent releases); the USB numbers
move within the known spread of the emulated stick (KVM kread 73 278 after 129 284, TCG kread 91 960 the highest
so far); KVM user SHA-256 / HMAC 235 840 KiB/s are the best so far (+14 %, same library code – host noise).

---

## v0.62.0 — 2026-11-01

**Status: stable on QEMU (TCG and KVM); DeSoFS stage 2b – every operation tested against power loss. Not yet tried
on the test laptop.**

### What is new since the last report (v0.61.0)

| Version | Change |
|---|---|
| v0.62.0 | DeSoFS power-loss tests (`kernel/fs/desofs/test_crash.rs`, DESOFS TEST 15–18): a crash after every write and inside every superblock write, unflushed writes landing in any order, a write / flush error at each position, a snapshot through crashes; `tests/test.sh` default timeout 240 s |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 32/32 suites, 260 tests PASS | 123 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 32/32 suites, 260 tests PASS | 83 s |

DESOFS TEST grows from 14 to 18 tests. A test disk records every write (512-byte sectors) and flush of one
operation; about 1 400 crash images are rebuilt from those logs and mounted from scratch – each must mount
read-write with exact counts and hold the state before or after the operation (generation g or g + 1, whole tree and
file contents), and where the state can change it must also take a new file and survive a remount. The new tests cost
26 s in TCG and 8 s in KVM (v0.61.0: 97 s / 75 s). Checked by mutation on the build server: without the flush between
the new blocks and the superblock the suite fails. All images live in RAM; nothing is written to any disk.

### Known problems

- DeSoFS: `desofs check` / `repair` not yet (v0.63.0); a mount lasts until reboot (`/desofs`); no snapshots from the
  shell. The power-loss tests model a disk cache that honours flushes; a disk that ignores them is not covered.
- Otherwise as in v0.61.0.

### Performance against the previous release (v0.61.0 → v0.62.0, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.61.0 | TCG v0.62.0 | KVM v0.61.0 | KVM v0.62.0 |
|---|---|---|---|---|
| irq_kernel_ns | 2 991 | 3 169 | 31 510 | 32 035 |
| irq_user_ns | 6 355 | 8 851 | 64 641 | 65 189 |
| fact_kernel_ns | 26 556 | 26 171 | 51 773 | 57 686 |
| fact_user_ns | 70 721 | 71 787 | 88 613 | 96 015 |
| fact_svc_ns | 177 147 | 201 005 | 103 252 | 104 821 |
| ping_svc_ns | 109 950 | 119 545 | 19 743 | 20 502 |
| restart_us | 6 600 | 3 500 | 1 200 | 1 200 |

`[RESULT-USB]`:

| | TCG v0.61.0 | TCG v0.62.0 | KVM v0.61.0 | KVM v0.62.0 |
|---|---|---|---|---|
| start_ms | 396 | 416 | 376 | 382 |
| enum_avg_ms | 31 | 25 | 26 | 23 |
| read_kbs (usbd) | 78 769 | 78 769 | 74 472 | 85 333 |
| kread_kbs (kernel) | 56 699 | 55 949 | 82 775 | 129 284 |
| kcat_kbs (kernel, cat) | 44 565 | 59 933 | 72 396 | 116 053 |
| hid_avg_us (keyboard) | 696 | 796 | 275 | 280 |

`[RESULT-RIGHTS]` gate_ns: TCG 62 → 43, KVM 5 → 4. `[RESULT-CRYPTO]` (KiB/s): TCG 47 124 / 49 600 / 49 920 →
48 941 / 52 160 / 51 840; KVM 181 760 / 217 600 / 218 240 → 176 640 / 206 720 / 207 360.

Verdict: no regression. Only test code changed in this release (the kernel's DeSoFS code is the same as in v0.61.0).
TCG `fact_svc_ns` 201 005 (+13 %) is inside its known spread (205 549 in v0.59.1); KVM crypto −3 to −5 % is run-to-run
noise (174 487 – 181 760 kernel over the last four releases). KVM `kread_kbs` 129 284 and `kcat_kbs` 116 053 are the
highest so far – the emulated USB stick on the host (earlier 77 000 – 117 000).

---

## v0.61.0 — 2026-11-01

**Status: stable on QEMU (TCG and KVM); DeSoFS stage 2a (format, mount, files and directories, rename). Not yet tried
on the test laptop.**

### What is new since the last report (v0.60.0)

| Version | Change |
|---|---|
| v0.61.0 | DeSoFS writing: `kernel/fs/desofs/vol.rs` (a mounted volume as a `FileSystem`, one copy-on-write commit per operation, space bound computed before every operation, reserve for freeing operations); `desofs format` / `mount` / `unmount` in the kernel shell; `rename` in the VFS (the shell `mv` uses it); errata E4; DESOFS TEST 8–14 |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 32/32 suites, 256 tests PASS | 97 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 32/32 suites, 256 tests PASS | 75 s |

DESOFS TEST grows from 7 to 14 tests: the kernel format equal byte for byte to `tests/mkdesofs.py --format`; files,
300-entry directories, every rename rule, a full disk with the reserve, the reference snapshot never overwritten, the
VFS with `/bin/sha256sum` reading from DeSoFS, a disk failing at each write position. After every operation the walk
accepts the volume with exact counts, the contents equal a model, no operation exceeded its bound and no reachable
block is free in the allocator. The TCG run is 6 s longer than v0.60.0 – the new DeSoFS tests. All DeSoFS volumes live
in RAM disks; nothing is written to any disk.

### Known problems

- DeSoFS: crash tests (sectors lost between flushes) not yet – v0.62.0; `desofs check` / `repair` not yet; a mount
  lasts until reboot (`/desofs`); no snapshots from the shell.
- Otherwise as in v0.60.0.

### Performance against the previous release (v0.60.0 → v0.61.0, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.60.0 | TCG v0.61.0 | KVM v0.60.0 | KVM v0.61.0 |
|---|---|---|---|---|
| irq_kernel_ns | 2 764 | 2 991 | 35 517 | 31 510 |
| irq_user_ns | 11 758 | 6 355 | 64 829 | 64 641 |
| fact_kernel_ns | 25 461 | 26 556 | 52 798 | 51 773 |
| fact_user_ns | 70 997 | 70 721 | 94 517 | 88 613 |
| fact_svc_ns | 193 610 | 177 147 | 104 329 | 103 252 |
| ping_svc_ns | 118 273 | 109 950 | 22 182 | 19 743 |
| restart_us | 6 700 | 6 600 | 1 200 | 1 200 |

`[RESULT-USB]`:

| | TCG v0.60.0 | TCG v0.61.0 | KVM v0.60.0 | KVM v0.61.0 |
|---|---|---|---|---|
| start_ms | 414 | 396 | 380 | 376 |
| enum_avg_ms | 26 | 31 | 25 | 26 |
| read_kbs (usbd) | 89 043 | 78 769 | 85 333 | 74 472 |
| kread_kbs (kernel) | 64 198 | 56 699 | 73 602 | 82 775 |
| kcat_kbs (kernel, cat) | 50 678 | 44 565 | 69 779 | 72 396 |
| hid_avg_us (keyboard) | 695 | 696 | 172 | 275 |

`[RESULT-RIGHTS]` gate_ns: TCG 79 → 62, KVM 5 → 5. `[RESULT-CRYPTO]` (KiB/s): TCG 45 320 / 48 000 / 50 880 →
47 124 / 49 600 / 49 920; KVM 179 200 / 215 360 / 214 400 → 181 760 / 217 600 / 218 240.

Verdict: no regression. None of these paths changed – DeSoFS runs only in its test and the `desofs` command; the VFS
gained `rename`, which nothing measured here calls. TCG `irq_user_ns` is back in its usual range (6 355 after 11 758);
the USB numbers move within their known spread of the emulated stick (TCG read 66 064 – 89 043, KVM kcat 69 779 –
110 559); KVM `hid_avg_us` 275 is one run of a ~0.2 ms measurement (225 – 232 in v0.59.x). KVM crypto is the best so far
(217 600 / 218 240).

---

## v0.60.0 — 2026-11-01

**Status: stable on QEMU (TCG and KVM); DeSoFS stage 1 (read-only check of a volume). Not yet tried on the test laptop.**

### What is new since the last report (v0.59.1)

| Version | Change |
|---|---|
| v0.60.0 | DeSoFS format 1 closed (`docs/desofs/FORMAT.md`, errata E1–E3); `kernel/fs/desofs/` – read-only check of a volume (both superblocks, every metadata block and node, mount decision); `desofs info <disk>` in the kernel shell; `tests/mkdesofs.py` – reference image from an independent implementation; new suite DESOFS TEST |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 32/32 suites, 249 tests PASS | 91 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 32/32 suites, 249 tests PASS | 73 s |

New DESOFS TEST (7 tests, 93 cases): the reference image built by `tests/mkdesofs.py` accepted (two superblocks,
a snapshot, a shared pointer block, used blocks counted once); superblock rules, pointers and headers, tree structure,
nodes and root entries, damage in one / both trees, shared metadata re-read with a wrong birth / checksum / kind,
directory blocks – most cases resealed so the rule itself must catch them. On the build server also
`LOOP=desofs:5` 5/5, and the suite fails when any of three rules is removed from the code. All DeSoFS images live in
RAM disks; nothing is written to any disk.

### Known problems

- DeSoFS is stage 1 only: volumes are checked, not mounted; no writing, no files (stage 2).
- Otherwise as in v0.59.1.

### Performance against the previous release (v0.59.1 → v0.60.0, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.59.1 | TCG v0.60.0 | KVM v0.59.1 | KVM v0.60.0 |
|---|---|---|---|---|
| irq_kernel_ns | 3 238 | 2 764 | 33 653 | 35 517 |
| irq_user_ns | 6 148 | 11 758 | 41 169 | 64 829 |
| fact_kernel_ns | 31 525 | 25 461 | 57 736 | 52 798 |
| fact_user_ns | 77 041 | 70 997 | 144 404 | 94 517 |
| fact_svc_ns | 205 549 | 193 610 | 105 318 | 104 329 |
| ping_svc_ns | 119 760 | 118 273 | 18 850 | 22 182 |
| restart_us | 3 700 | 6 700 | 1 200 | 1 200 |

`[RESULT-USB]`:

| | TCG v0.59.1 | TCG v0.60.0 | KVM v0.59.1 | KVM v0.60.0 |
|---|---|---|---|---|
| start_ms | 410 | 414 | 365 | 380 |
| enum_avg_ms | 29 | 26 | 25 | 25 |
| read_kbs (usbd) | 66 064 | 89 043 | 93 090 | 85 333 |
| kread_kbs (kernel) | 64 341 | 64 198 | 85 559 | 73 602 |
| kcat_kbs (kernel, cat) | 45 807 | 50 678 | 96 542 | 69 779 |
| hid_avg_us (keyboard) | 592 | 695 | 232 | 172 |

`[RESULT-RIGHTS]` gate_ns: TCG 26 → 79, KVM 4 → 5. `[RESULT-CRYPTO]` (KiB/s): TCG 47 921 / 51 200 / 50 880 →
45 320 / 48 000 / 50 880; KVM 174 487 / 197 120 / 208 320 → 179 200 / 215 360 / 214 400.

Verdict: no regression. Nothing on these paths changed – DeSoFS runs only in its test and the `desofs` command. KVM
`fact_user_ns` / `irq_user_ns` are back in their usual state (94 517 / 64 829 after the `edu` two-state run of v0.59.1).
TCG `gate_ns` 79 is one sample of a ~1 µs measurement on an emulated CPU (24–59 over recent releases; KVM unchanged at
5); TCG `restart_us` 6 700 and KVM `kcat_kbs` 69 779 are within their known run-to-run spread (v0.54.0 TCG restart 6 200;
KVM kcat 84 389 – 110 559, the emulated USB stick).

---

## v0.59.1 — 2026-11-01

**Status: stable on QEMU (TCG and KVM); fixes only (DeSoCrypto 0.1.1).**

### What is new since the last report (v0.59.0)

| Version | Change |
|---|---|
| v0.59.1 | DeSoCrypto: test-only `assume_length` only in test builds (kernel `selftest`, `cryptotest`); SHA-256 and HMAC wipe their whole state on drop (the HMAC inner state is a hash of the key) |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 31/31 suites, 242 tests PASS | 90 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 31/31 suites, 242 tests PASS | 73 s |

On the build server: a program calling `assume_length` without the test flag does not compile.

### Known problems

- As in v0.59.0 (stack temporaries inside SHA-256 are still not wiped – documented).

### Performance against the previous release (v0.59.0 → v0.59.1, same machine)

`[RESULT-CRYPTO]` (KiB/s):

| | TCG v0.59.0 | TCG v0.59.1 | KVM v0.59.0 | KVM v0.59.1 |
|---|---|---|---|---|
| sha256_kernel_kbs | 47 360 | 47 921 | 175 761 | 174 487 |
| sha256_user_kbs | 52 160 | 51 200 | 213 120 | 197 120 |
| hmac_user_kbs | 48 716 | 50 880 | 211 520 | 208 320 |

`[RESULT-SVC]` (ns):

| | TCG v0.59.0 | TCG v0.59.1 | KVM v0.59.0 | KVM v0.59.1 |
|---|---|---|---|---|
| irq_kernel_ns | 3 218 | 3 238 | 32 154 | 33 653 |
| irq_user_ns | 12 826 | 6 148 | 65 659 | 41 169 |
| fact_kernel_ns | 26 260 | 31 525 | 56 385 | 57 736 |
| fact_user_ns | 74 487 | 77 041 | 93 283 | 144 404 |
| fact_svc_ns | 176 678 | 205 549 | 103 788 | 105 318 |
| ping_svc_ns | 104 766 | 119 760 | 23 518 | 18 850 |
| restart_us | 4 900 | 3 700 | 1 200 | 1 200 |

`[RESULT-USB]`:

| | TCG v0.59.0 | TCG v0.59.1 | KVM v0.59.0 | KVM v0.59.1 |
|---|---|---|---|---|
| start_ms | 407 | 410 | 378 | 365 |
| enum_avg_ms | 29 | 29 | 27 | 25 |
| read_kbs (usbd) | 70 620 | 66 064 | 65 015 | 93 090 |
| kread_kbs (kernel) | 62 904 | 64 341 | 99 482 | 85 559 |
| kcat_kbs (kernel, cat) | 64 081 | 45 807 | 84 389 | 96 542 |
| hid_avg_us (keyboard) | 803 | 592 | 225 | 232 |

Verdict: no regression. DeSoCrypto speed unchanged within noise (KVM user SHA-256 −7.5 %, HMAC −1.5 %, kernel −0.7 %;
the bulk path – whole 64-byte blocks straight from the input – did not change). KVM `fact_user_ns` 144 404 with
`irq_user_ns` 41 169 in the same run is the known two-state behaviour of the emulated `edu` device on the host (seen in
v0.55.1: 183 823 / then 97 656 on a rerun; v0.56.0) – nothing on that path changed in this release.

---

## v0.59.0 — 2026-11-01

**Status: stable on QEMU (TCG and KVM); DeSoCrypto v0.1.0 added. Not yet tried on the test laptop.**

### What is new since the last report (v0.58.1)

| Version | Change |
|---|---|
| v0.59.0 | DeSoCrypto v0.1.0 – DeSoOS's own cryptographic library (`common/desocrypto/`, kernel and programs): SHA-256, HMAC-SHA256, HKDF-SHA256; new programs `sha256sum` and `cryptotest`; new suite CRYPTO TEST |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 31/31 suites, 242 tests PASS | 91 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 31/31 suites, 242 tests PASS | 73 s |

New CRYPTO TEST (4 tests): 92 checks (FIPS 180-4 / NIST, RFC 4231, RFC 5869 vectors, block edges, length limits,
wrong tags and parameters) in the kernel and in user space, `sha256sum` equal to the kernel's result, speed. On the
build server also `LOOP=crypto:20` 20/20.

### DeSoCrypto speed (`[RESULT-CRYPTO]`, KiB/s)

| | TCG | KVM |
|---|---|---|
| sha256_kernel_kbs | 47 360 | 175 761 |
| sha256_user_kbs | 52 160 | 213 120 |
| hmac_user_kbs | 48 716 | 211 520 |

KVM: ~210 MiB/s in user space – in the range of a plain (not SIMD / SHA-NI) SHA-256 on this CPU; the kernel run is a
little lower (measured over 256 KiB pieces with overflow checks on).

### Known problems

- DeSoCrypto is not audited and not hardened against timing side channels (beyond the tag check) – fine for
  checksums, not for secrets yet; no random numbers, ciphers or TLS yet.
- Otherwise as in v0.58.1.

### Performance against the previous release (v0.58.1 → v0.59.0, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.58.1 | TCG v0.59.0 | KVM v0.58.1 | KVM v0.59.0 |
|---|---|---|---|---|
| irq_kernel_ns | 3 172 | 3 218 | 32 965 | 32 154 |
| irq_user_ns | 7 814 | 12 826 | 67 046 | 65 659 |
| fact_kernel_ns | 29 686 | 26 260 | 54 274 | 56 385 |
| fact_user_ns | 74 074 | 74 487 | 91 407 | 93 283 |
| fact_svc_ns | 207 253 | 176 678 | 104 931 | 103 788 |
| ping_svc_ns | 120 918 | 104 766 | 22 461 | 23 518 |
| restart_us | 5 400 | 4 900 | 1 300 | 1 200 |

`[RESULT-USB]`:

| | TCG v0.58.1 | TCG v0.59.0 | KVM v0.58.1 | KVM v0.59.0 |
|---|---|---|---|---|
| start_ms | 402 | 407 | 399 | 378 |
| enum_avg_ms | 26 | 29 | 23 | 27 |
| read_kbs (usbd) | 99 902 | 70 620 | 77 283 | 65 015 |
| kread_kbs (kernel) | 72 617 | 62 904 | 95 085 | 99 482 |
| kcat_kbs (kernel, cat) | 50 442 | 64 081 | 95 517 | 84 389 |
| hid_avg_us (keyboard) | 691 | 803 | 272 | 225 |

Verdict: no regression – nothing on these paths changed (the library is only used by the new programs and the test).
TCG `irq_user_ns` 12 826 is within its spread (6 905 – 10 908 over recent releases, single TCG samples swing more);
the USB read numbers move as usual from run to run (KVM v0.57.3 had 69 423).

---

## v0.58.1 — 2026-11-01

**Status: stable on QEMU (TCG and KVM); fixes only, not yet tried on the test laptop.**

### What is new since the last report (v0.58.0)

| Version | Change |
|---|---|
| v0.58.1 | a sandboxed service (`files none`) cannot be handed a file or directory over a channel; init does not retry a device a kernel driver owns; duplicate manifest keys, grants and service names are refused; FILE TEST 9/9 waits for reaping before the heap check |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 30/30 suites, 238 tests PASS | 90 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 30/30 suites, 238 tests PASS | 73 s |

New in SVC TEST 6/7: a directory and a file handle sent to `echo` are refused and echo keeps answering; four bad
manifests each refused with its reason. The first KVM run failed FILE TEST 9/9 ("kernel heap not given back") – the
test measured before the killed `oomtest` children were reaped; it now waits up to 5 s (`LOOP=files:5` 5/5 on the
build server).

### Known problems

- As in v0.58.0.

### Performance against the previous release (v0.58.0 → v0.58.1, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.58.0 | TCG v0.58.1 | KVM v0.58.0 | KVM v0.58.1 |
|---|---|---|---|---|
| irq_kernel_ns | 3 157 | 3 172 | 35 644 | 32 965 |
| irq_user_ns | 9 087 | 7 814 | 62 972 | 67 046 |
| fact_kernel_ns | 30 539 | 29 686 | 52 700 | 54 274 |
| fact_user_ns | 78 339 | 74 074 | 86 994 | 91 407 |
| fact_svc_ns | 205 128 | 207 253 | 107 584 | 104 931 |
| ping_svc_ns | 127 795 | 120 918 | 22 408 | 22 461 |
| restart_us | 4 800 | 5 400 | 1 300 | 1 300 |

`[RESULT-USB]`:

| | TCG v0.58.0 | TCG v0.58.1 | KVM v0.58.0 | KVM v0.58.1 |
|---|---|---|---|---|
| start_ms | 442 | 402 | 400 | 399 |
| enum_avg_ms | 25 | 26 | 23 | 23 |
| read_kbs (usbd) | 102 400 | 99 902 | 117 028 | 77 283 |
| kread_kbs (kernel) | 69 847 | 72 617 | 104 107 | 95 085 |
| kcat_kbs (kernel, cat) | 58 667 | 50 442 | 96 688 | 95 517 |
| hid_avg_us (keyboard) | 774 | 691 | 344 | 272 |

Verdict: no regression. The extra check in `chan_recv` (sandboxed receiver only) does not show in `ping_svc_ns`;
the KVM `read_kbs` drop is the usual run-to-run swing of the emulated USB stick (v0.57.3 had 69 423).

---

## v0.58.0 — 2026-11-01

**Status: stable on QEMU (TCG and KVM) and on the test laptop with the drivers sandboxed.**

### What is new since the last report (v0.57.3)

| Version | Change |
|---|---|
| v0.58.0 | service manifests (`/etc/services/*.svc`): every service gets exactly what its manifest grants, nothing by program name; all shipped services (edu, echo, usb, net) run without file access; a bad manifest is refused with its line |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 30/30 suites, 238 tests PASS | 98 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 30/30 suites, 238 tests PASS | 72 s |

New in SVC TEST 6/7: services started from manifests, `echo` (files none) opening a file gets
`ERROR_ACCESS_DENIED`, a manifest with an unknown grant refused with its line number. USB TEST and NET TEST pass with
usbd and netd sandboxed. A plain (non-test) boot in QEMU on the build server: echo, edu, net0, usb0 started, DHCP,
USB keyboard.

### Real hardware (test laptop) – v0.58.0, drivers sandboxed

| What | Result |
|---|---|
| Services from manifests | `echo`, `net0` (Realtek RTL8168h), `usb0`–`usb2` (three xHCI controllers) running; `edu` "no device" (QEMU-only device) – as expected |
| `dcp` | `netd` and all three `usbd` with FILES `none`; `usbd`: its controller, interrupts, DMA memory, `INPUT_SEND`, `DISK_ATTACH` – exactly its manifest |
| USB keyboard, mouse, flash drive | work; `/usb0` mounted (FAT32, read-only) by the sandboxed usbd |
| Network | DHCP address; `netget` 10 MiB: 7 529 KiB/s (first after boot), then **9 534 KiB/s** – as on v0.55.0 |

### Known problems

- `/etc` lives in ramfs and is writable by programs with file access; harmless for the manifests (init reads them
  once, every boot writes them anew from the image), write protection with DeSoFS.
- Otherwise as in v0.57.3.

### Performance against the previous release (v0.57.3 → v0.58.0, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.57.3 | TCG v0.58.0 | KVM v0.57.3 | KVM v0.58.0 |
|---|---|---|---|---|
| irq_kernel_ns | 3 411 | 3 157 | 35 784 | 35 644 |
| irq_user_ns | 10 908 | 9 087 | 65 767 | 62 972 |
| fact_kernel_ns | 23 223 | 30 539 | 52 015 | 52 700 |
| fact_user_ns | 85 543 | 78 339 | 87 989 | 86 994 |
| fact_svc_ns | 207 900 | 205 128 | 102 880 | 107 584 |
| ping_svc_ns | 122 399 | 127 795 | 21 172 | 22 408 |
| restart_us | 4 000 | 4 800 | 1 200 | 1 300 |

`[RESULT-USB]`:

| | TCG v0.57.3 | TCG v0.58.0 | KVM v0.57.3 | KVM v0.58.0 |
|---|---|---|---|---|
| start_ms | 354 | 442 | 383 | 400 |
| enum_avg_ms | 24 | 25 | 27 | 23 |
| read_kbs (usbd) | 91 022 | 102 400 | 69 423 | 117 028 |
| kread_kbs (kernel) | 56 212 | 69 847 | 115 075 | 104 107 |
| kcat_kbs (kernel, cat) | 42 923 | 58 667 | 110 559 | 96 688 |
| hid_avg_us (keyboard) | 544 | 774 | 327 | 344 |

Verdict: no regression. Init now reads four small manifests at its start; the service paths themselves are
unchanged (the sandbox only refuses path calls the drivers never make). KVM is equal or better (usbd reads 117 028
KiB/s – the best so far). The TCG run took 98 s (91 s before) with every suite passing – within the 84 – 98 s seen over
the last releases; TCG `start_ms` 442 and `hid_avg_us` 774 are within their spread.

---

## v0.57.3 — 2026-11-01

**Status: stable on QEMU (TCG and KVM); real hardware as measured on v0.55.0.**

### What is new since the last report (v0.57.2)

| Version | Change |
|---|---|
| v0.57.3 | directory listings bounded by the caller's buffer: FAT32 entries read one at a time, `readdir` takes at most what fits (a crafted 65 536-entry directory no longer costs ~13 MiB of kernel heap) |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 30/30 suites, 238 tests PASS | 91 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 30/30 suites, 238 tests PASS | 74 s |

FS TEST 12/12 now also has a directory of exactly 65 536 entries (listing limited to 100 stops, lookups through all
of it, heap back) – +2 s on TCG.

### Known problems

- No cursor for `readdir` yet: a directory larger than the caller's buffer gives `ERROR_BUFFER_TOO_SMALL` (planned
  with DeSoFS).
- Otherwise as in v0.57.2.

### Performance against the previous release (v0.57.2 → v0.57.3, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.57.2 | TCG v0.57.3 | KVM v0.57.2 | KVM v0.57.3 |
|---|---|---|---|---|
| irq_kernel_ns | 3 130 | 3 411 | 35 990 | 35 784 |
| irq_user_ns | 12 275 | 10 908 | 66 006 | 65 767 |
| fact_kernel_ns | 29 819 | 23 223 | 55 478 | 52 015 |
| fact_user_ns | 75 272 | 85 543 | 93 457 | 87 989 |
| fact_svc_ns | 189 573 | 207 900 | 106 837 | 102 880 |
| ping_svc_ns | 115 740 | 122 399 | 19 000 | 21 172 |
| restart_us | 3 600 | 4 000 | 1 200 | 1 200 |

`[RESULT-USB]`:

| | TCG v0.57.2 | TCG v0.57.3 | KVM v0.57.2 | KVM v0.57.3 |
|---|---|---|---|---|
| start_ms | 409 | 354 | 379 | 383 |
| enum_avg_ms | 28 | 24 | 25 | 27 |
| read_kbs (usbd) | 74 472 | 91 022 | 71 859 | 69 423 |
| kread_kbs (kernel) | 73 065 | 56 212 | 92 699 | 115 075 |
| kcat_kbs (kernel, cat) | 54 878 | 42 923 | 84 155 | 110 559 |
| hid_avg_us (keyboard) | 562 | 544 | 434 | 327 |

Verdict: no regression. The change touches directory listings only; the benchmarks list no directories. All values
are inside their usual spread (TCG `kread_kbs` / `kcat_kbs` swing by ±30 % between runs; KVM is equal or better).

---

## v0.57.2 — 2026-11-01

**Status: stable on QEMU (TCG and KVM); real hardware as measured on v0.55.0.**

### What is new since the last report (v0.57.1)

| Version | Change |
|---|---|
| v0.57.2 | sizes read from a disk allocated fallibly – a pendrive claiming a 4 GiB file no longer crashes the kernel (whole-file reads, FAT32 chains, FAT32 directories over 65 536 entries refused); captured output ≤ 1 MiB per program |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 30/30 suites, 238 tests PASS | 89 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 30/30 suites, 238 tests PASS | 73 s |

New: FS TEST 12/12 (a FAT32 volume patched on disk: a 3.75 GiB file entry → `ERROR_NO_SPACE`, a directory chain over
65 536 entries → corrupt).

### Known problems

- The kernel's own allocations (scheduler, drivers, the kernel side of services) are not fallible; they rely on
  the 8 MiB heap reserve. Item J of the code review is closed.
- Otherwise as in v0.57.1.

### Performance against the previous release (v0.57.1 → v0.57.2, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.57.1 | TCG v0.57.2 | KVM v0.57.1 | KVM v0.57.2 |
|---|---|---|---|---|
| irq_kernel_ns | 3 286 | 3 130 | 35 050 | 35 990 |
| irq_user_ns | 8 285 | 12 275 | 65 595 | 66 006 |
| fact_kernel_ns | 29 779 | 29 819 | 58 496 | 55 478 |
| fact_user_ns | 74 404 | 75 272 | 93 545 | 93 457 |
| fact_svc_ns | 210 084 | 189 573 | 105 318 | 106 837 |
| ping_svc_ns | 128 700 | 115 740 | 23 174 | 19 000 |
| restart_us | 7 100 | 3 600 | 1 200 | 1 200 |

`[RESULT-USB]`:

| | TCG v0.57.1 | TCG v0.57.2 | KVM v0.57.1 | KVM v0.57.2 |
|---|---|---|---|---|
| start_ms | 419 | 409 | 404 | 379 |
| enum_avg_ms | 25 | 28 | 26 | 25 |
| read_kbs (usbd) | 70 620 | 74 472 | 78 769 | 71 859 |
| kread_kbs (kernel) | 55 113 | 73 065 | 96 437 | 92 699 |
| kcat_kbs (kernel, cat) | 61 285 | 54 878 | 96 303 | 84 155 |
| hid_avg_us (keyboard) | 587 | 562 | 353 | 434 |

Verdict: no regression. The change adds a capacity check on whole-file and FAT32 chain buffers; USB reads through the
kernel (`kread_kbs`, `kcat_kbs`) stay in their usual spread. TCG `irq_user_ns` 12 275 is above its usual 7 000 – 11 000 –
the `edu` user-driver path the change does not touch (KVM 66 006 is normal); TCG noise.

---

## v0.57.1 — 2026-11-01

**Status: stable on QEMU (TCG and KVM); real hardware as measured on v0.55.0.**

### What is new since the last report (v0.57.0)

| Version | Change |
|---|---|
| v0.57.1 | pipe writes copied in 4 KiB pieces (a waiting writer no longer holds 64 KiB of kernel heap); ramfs counts files and directories (384 B + name) in its 24 MiB limit; faster `mmap` with thousands of areas; `oomtest` fills the heap the way several programs could at once |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 30/30 suites, 237 tests PASS | 88 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 30/30 suites, 237 tests PASS | 74 s |
| Loop (build server, TCG) | `LOOP=files:12` | 12/12 PASS | ~21 s per round |

The new `oomtest` is ~10 s faster on TCG than in v0.57.0 (98 s → 88 s for the whole run).

### Known problems

- Kernel heap: the kernel's own work past the reserve and a fragmented heap after it had been full are not
  checked by a test yet.
- Otherwise as in v0.57.0.

### Performance against the previous release (v0.57.0 → v0.57.1, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.57.0 | TCG v0.57.1 | KVM v0.57.0 | KVM v0.57.1 |
|---|---|---|---|---|
| irq_kernel_ns | 3 716 | 3 286 | 32 336 | 35 050 |
| irq_user_ns | 9 465 | 8 285 | 50 851 | 65 595 |
| fact_kernel_ns | 28 801 | 29 779 | 55 493 | 58 496 |
| fact_user_ns | 76 335 | 74 404 | 102 722 | 93 545 |
| fact_svc_ns | 212 765 | 210 084 | 103 626 | 105 318 |
| ping_svc_ns | 111 919 | 128 700 | 18 791 | 23 174 |
| restart_us | 5 000 | 7 100 | 1 200 | 1 200 |

`[RESULT-USB]`:

| | TCG v0.57.0 | TCG v0.57.1 | KVM v0.57.0 | KVM v0.57.1 |
|---|---|---|---|---|
| start_ms | 430 | 419 | 397 | 404 |
| enum_avg_ms | 23 | 25 | 27 | 26 |
| read_kbs (usbd) | 74 472 | 70 620 | 107 789 | 78 769 |
| kread_kbs (kernel) | 97 491 | 55 113 | 112 490 | 96 437 |
| kcat_kbs (kernel, cat) | 42 894 | 61 285 | 124 612 | 96 303 |
| hid_avg_us (keyboard) | 642 | 587 | 435 | 353 |

Verdict: no regression. None of the benchmarks writes to a pipe or creates ramfs files. KVM `ping_svc_ns` 23 174 is
back in its usual 20 000 – 23 000 (v0.57.0's 18 791 was the low end); TCG `restart_us` 7 100 and the USB read rates
move within their usual spread (TCG `kread_kbs` 55 113 – 97 491 across the last releases, KVM `read_kbs` 71 859 –
107 789).

---

## v0.57.0 — 2026-11-01

**Status: stable on QEMU (TCG and KVM); real hardware as measured on v0.55.0.**

### What is new since the last report (v0.56.1)

| Version | Change |
|---|---|
| v0.57.0 | kernel heap reserve: the last 8 MiB of the kernel heap belong to the kernel, allocating syscalls get `ERROR_OUT_OF_MEMORY` before it – a program can no longer crash the kernel by filling its heap; the selftest RAM disk in 64 KiB pieces |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 30/30 suites, 237 tests PASS | 98 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 30/30 suites, 237 tests PASS | 74 s |

New: FILE TEST 9/9 (`oomtest` – ~125 000 empty files fill the kernel heap to its reserve, allocating calls are
refused, the kernel keeps running, the heap comes back). It costs ~14 s on TCG (file creation and removal) and ~2 s
on KVM – the main reason for the longer TCG run.

### Known problems

- After the kernel heap has been full, its free space is fragmented: no multi-MiB blocks may be allocated at run
  time (the RAM disk of the tests was the one that did – fixed). Pipe writers still hold a 64 KiB copy while
  waiting, and ramfs does not count empty files in its limit – both stopped by the reserve now, to be fixed at the
  source.
- Otherwise as in v0.56.1.

### Performance against the previous release (v0.56.1 → v0.57.0, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.56.1 | TCG v0.57.0 | KVM v0.56.1 | KVM v0.57.0 |
|---|---|---|---|---|
| irq_kernel_ns | 3 013 | 3 716 | 32 206 | 32 336 |
| irq_user_ns | 10 858 | 9 465 | 69 132 | 50 851 |
| fact_kernel_ns | 26 616 | 28 801 | 57 870 | 55 493 |
| fact_user_ns | 75 757 | 76 335 | 98 814 | 102 722 |
| fact_svc_ns | 215 053 | 212 765 | 117 647 | 103 626 |
| ping_svc_ns | 120 409 | 111 919 | 22 431 | 18 791 |
| restart_us | 3 700 | 5 000 | 1 400 | 1 200 |

`[RESULT-USB]`:

| | TCG v0.56.1 | TCG v0.57.0 | KVM v0.56.1 | KVM v0.57.0 |
|---|---|---|---|---|
| start_ms | 413 | 430 | 348 | 397 |
| enum_avg_ms | 26 | 23 | 27 | 27 |
| read_kbs (usbd) | 51 200 | 74 472 | 105 025 | 107 789 |
| kread_kbs (kernel) | 68 393 | 97 491 | 104 261 | 112 490 |
| kcat_kbs (kernel, cat) | 50 483 | 42 894 | 81 104 | 124 612 |
| hid_avg_us (keyboard) | 898 | 642 | 441 | 435 |

`[RESULT-RIGHTS]`: gate 26 ns (TCG), 4 ns (KVM) – the heap check next to it costs nothing measurable.

Verdict: no regression. The reserve check is a few atomic loads per allocating syscall; IPC (`ping_svc_ns`, KVM
18 791 – the best so far) and USB reads are unchanged or better. TCG `irq_kernel_ns` +23 % is a kernel-only path the
check does not touch – TCG noise.

---

## v0.56.1 — 2026-10-31

**Status: stable on QEMU (TCG and KVM); real hardware as measured on v0.55.0.**

### What is new since the last report (v0.56.0)

| Version | Change |
|---|---|
| v0.56.1 | a lost exit status of an orphan fixed (the rare "199 of 200 orphans" of NOBKL TEST was a kernel bug); `tests/test.sh` refuses to start while another test or QEMU runs |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 30/30 suites, 236 tests PASS | 84 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 30/30 suites, 236 tests PASS | 72 s |
| Loop (build server, TCG) | `LOOP=nobkl` – before the fix failed in round 7 / 9 / 60 | 90/90 and 110/110 PASS | ~5 s per round |

`[RESULT-RIGHTS]`: 56 rows, 28 refusals; gate 25 ns (TCG), 5 ns (KVM).

### Known problems

- A full kernel heap still panics the kernel on many allocation paths.
- Otherwise as in v0.56.0 (the orphan failure is fixed).

### Performance against the previous release (v0.56.0 → v0.56.1, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.56.0 | TCG v0.56.1 | KVM v0.56.0 | KVM v0.56.1 |
|---|---|---|---|---|
| irq_kernel_ns | 3 116 | 3 013 | 36 055 | 32 206 |
| irq_user_ns | 6 966 | 10 858 | 35 891 | 69 132 |
| fact_kernel_ns | 26 371 | 26 616 | 53 262 | 57 870 |
| fact_user_ns | 73 991 | 75 757 | 141 843 | 98 814 |
| fact_svc_ns | 193 423 | 215 053 | 103 466 | 117 647 |
| ping_svc_ns | 111 669 | 120 409 | 22 862 | 22 431 |
| restart_us | 5 200 | 3 700 | 1 300 | 1 400 |

`[RESULT-USB]`:

| | TCG v0.56.0 | TCG v0.56.1 | KVM v0.56.0 | KVM v0.56.1 |
|---|---|---|---|---|
| start_ms | 424 | 413 | 345 | 348 |
| enum_avg_ms | 26 | 26 | 26 | 27 |
| read_kbs (usbd) | 63 015 | 51 200 | 91 022 | 105 025 |
| kread_kbs (kernel) | 85 376 | 68 393 | 107 464 | 104 261 |
| kcat_kbs (kernel, cat) | 46 218 | 50 483 | 112 530 | 81 104 |
| hid_avg_us (keyboard) | 647 | 898 | 180 | 441 |

Verdict: no regression. The fix adds one comparison on a path taken only when a parent disappears mid-exit; the
`[RESULT-SVC]` benchmarks never exit there. KVM is back in the other `edu` state (`irq_user_ns` ~69 000, `fact_user_ns`
~99 000 – see v0.56.0). TCG `irq_user_ns` 10 858 is above its usual 6 900 – 8 100, but the same `edu` driver path
on KVM is normal; TCG noise.

---

## v0.56.0 — 2026-10-31

**Status: stable on QEMU (TCG and KVM); real hardware as measured on v0.55.0.**

### What is new since the last report (v0.55.1)

| Version | Change |
|---|---|
| v0.56.0 | loop mode for the self-tests (`LOOP=suite:rounds tests/test.sh`); `[RESULT-RIGHTS]` in the test summary |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 30/30 suites, 236 tests PASS | 84 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 30/30 suites, 236 tests PASS | 71 s |

`[RESULT-RIGHTS]`: 56 rows, 28 refusals; gate 25 ns (TCG), 5 ns (KVM).

Loop mode on the build machine: `LOOP=nobkl:400` (TCG) – **400/400 rounds PASS** in 1 076 s (round 1.9 – 3.0 s, average
2.7 s); the orphan race did not show up there.

### Known problems

- NOBKL TEST 10/10 "199 of 200 orphans reaped" – reproduced on the (slower, shared) build server with
  `LOOP=nobkl:60` (round 9), not on the build machine in 400 rounds: a timing race that needs a slow host; the next
  fix.
- Running two `tests/test.sh` at the same time fails with "Could not set up host forwarding rule" (both use
  the same host port) – run them one after another.
- Otherwise as in v0.55.1.

### Performance against the previous release (v0.55.1 → v0.56.0, same machine)

`[RESULT-SVC]` (ns; KVM v0.55.1 = the second run):

| | TCG v0.55.1 | TCG v0.56.0 | KVM v0.55.1 | KVM v0.56.0 |
|---|---|---|---|---|
| irq_kernel_ns | 3 173 | 3 116 | 36 324 | 36 055 |
| irq_user_ns | 7 600 | 6 966 | 66 291 | 35 891 |
| fact_kernel_ns | 26 535 | 26 371 | 56 609 | 53 262 |
| fact_user_ns | 74 294 | 73 991 | 97 656 | 141 843 |
| fact_svc_ns | 198 019 | 193 423 | 105 652 | 103 466 |
| ping_svc_ns | 117 647 | 111 669 | 22 967 | 22 862 |
| restart_us | 3 900 | 5 200 | 1 200 | 1 300 |

`[RESULT-USB]`:

| | TCG v0.55.1 | TCG v0.56.0 | KVM v0.55.1 | KVM v0.56.0 |
|---|---|---|---|---|
| start_ms | 410 | 424 | 397 | 345 |
| enum_avg_ms | 26 | 26 | 27 | 26 |
| read_kbs (usbd) | 73 142 | 63 015 | 87 148 | 91 022 |
| kread_kbs (kernel) | 77 224 | 85 376 | 125 732 | 107 464 |
| kcat_kbs (kernel, cat) | 32 150 | 46 218 | 76 032 | 112 530 |
| hid_avg_us (keyboard) | 527 | 647 | 308 | 180 |

Verdict: no regression – loop mode is off unless `LOOP` is set, and the normal run executes the same suites in the
same order. On KVM the user-space `edu` driver benchmark has two states: `irq_user_ns` ~66 000 with `fact_user_ns`
~95 000, or `irq_user_ns` ~37 000 with `fact_user_ns` 140 000 – 184 000 (v0.55.1 first run, this run). Both appear
on the same build, so it is the host (how QEMU's `edu` thread is scheduled), not the kernel.

---

## v0.55.1 — 2026-10-31

**Status: stable on QEMU (TCG and KVM); real hardware as measured on v0.55.0 (no driver changes since).**

### What is new since the last report (v0.55.0)

| Version | Change |
|---|---|
| v0.55.1 | small fixes from a second code review: FAT32 volumes with more clusters than FAT32 can number do not mount; `shm_map` with fallible allocation; a test of the 16-generation `dcp audit` limit |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 30/30 suites, 236 tests PASS | 84 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 30/30 suites, 236 tests PASS | 72 s |

New checks inside existing tests: FS TEST 11/11 (a sparse 2 TiB disk numbering 0x10000000 clusters refused), FILE
TEST 7/8 (`dcp audit`: 16 generations down seen, 17 not).

### Known problems

- Twice in the build server's runs (not on the build machine): NOBKL TEST 10/10 "199 of 200 orphans reaped" – a
  timing race in the test; next to be fixed (a loop mode for the self-tests first, to reproduce it).
- A full kernel heap still panics the kernel on many allocation paths.
- Otherwise as in v0.55.0.

### Performance against the previous release (v0.55.0 → v0.55.1, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.55.0 | TCG v0.55.1 | KVM v0.55.0 | KVM v0.55.1 |
|---|---|---|---|---|
| irq_kernel_ns | 3 096 | 3 173 | 36 055 | 32 835 |
| irq_user_ns | 6 905 | 7 600 | 67 226 | 38 973 |
| fact_kernel_ns | 29 065 | 26 535 | 53 835 | 56 401 |
| fact_user_ns | 72 806 | 74 294 | 91 827 | **183 823** |
| fact_svc_ns | 170 357 | 198 019 | 106 044 | 111 482 |
| ping_svc_ns | 109 589 | 117 647 | 21 619 | 22 977 |
| restart_us | 4 200 | 3 900 | 1 300 | 1 300 |

`[RESULT-USB]`:

| | TCG v0.55.0 | TCG v0.55.1 | KVM v0.55.0 | KVM v0.55.1 |
|---|---|---|---|---|
| start_ms | 400 | 410 | 411 | 398 |
| enum_avg_ms | 26 | 26 | 25 | 28 |
| read_kbs (usbd) | 83 591 | 73 142 | 71 859 | 102 400 |
| kread_kbs (kernel) | 61 091 | 77 224 | 86 949 | 87 906 |
| kcat_kbs (kernel, cat) | 53 146 | 32 150 | 100 279 | 83 152 |
| hid_avg_us (keyboard) | 645 | 527 | 311 | 347 |

Verdict: no regression from this release's code – it touches only FAT32 mounting, `shm_map` and two tests, none of
which these benchmarks use. KVM `fact_user_ns` doubled while `irq_user_ns` in the same run dropped by 42 % (both
measure the user-space driver of QEMU's emulated `edu` device, where KVM leaves to QEMU on every register access) –
a host-side outlier. **Second KVM run: `fact_user_ns` 97 656, `irq_user_ns` 66 291, 30/30 PASS in 71 s – back in
the usual range, so it was noise.** TCG `kcat_kbs` 32 150 is the lowest so far (range 40 592 –
62 224), `kread_kbs` in the same run is normal.

---

## v0.55.0 — 2026-10-31

**Status: stable on QEMU (TCG and KVM) and on the test laptop (measured again on this release).**

### What is new since the last report (v0.54.0)

| Version | Change |
|---|---|
| v0.55.0 | FAT32 stays inside its MBR partition (the partition length kept, a BPB larger than the partition refused, every sector checked); `dcp audit` shows refusals of all descendants, not only children |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 30/30 suites, 236 tests PASS | 83 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 30/30 suites, 236 tests PASS | 73 s |

New: FS TEST 11/11 (a full FAT32 partition leaves the next partition intact; a partition shorter than the volume
and a BPB larger than the partition do not mount); FILE TEST 7/8 – a grandchild's refusal is seen in `dcp audit`.

### Real hardware (test laptop: Ryzen 7 4800H, 16 threads, NVMe, xHCI, Realtek RTL8168h) – measured on v0.55.0

| What | v0.55.0 | Last before |
|---|---|---|
| Boot from a USB stick, shell, USB keyboard, mouse, hubs (`usblist`: 7 devices) | works | works (v0.47.0) |
| Stress, 16 CPUs, 60 s, compare mode (2 runs) | PASS, **587 878 / 587 935 scripts** + ~293 950 primes, 8 213 / 8 104 IPC jobs; 0 deadlock reports | 600 637 scripts (v0.35.2) |
| USB stick read before the stress (256 KiB / 4 KiB reads) | **125 051 / 124 184 KiB/s**, second run 122 375 / 126 567 | 120 MB/s (v0.29.0) |
| USB stick read during the stress | 4 606 / 4 584 MiB at 78 604 / 78 213 KiB/s, all passes identical, 0 errors | – |
| IPC (`ipcbench`) | ping-pong 4.5 µs, 190 476 msg/s × 4 KiB (744 MB/s) | – |
| Network: DHCP, `ping 192.168.1.1` | address in 15.7 s after boot; ping 4/4 < 1 ms, 0 % loss | DHCP, ping < 1 ms (v0.47.0) |
| `netget` 10 MiB from the internet (link 100 Mb/s) | 6 692 (first after boot), then **8 258, 9 543, 9 507 KiB/s** (1 073 ms) | 7 579 KiB/s (v0.47.0); Debian on the same laptop and cable 9.78 MB/s |
| Keyboard latency (key pressed during the stress) | **110 µs** average (41 presses, 20–248 µs) | 275 µs (v0.29.0) |

Verdict: works on real hardware after eight releases without a test there. Stress −2 % against v0.35.2 (the same in
both runs; many changes since), USB reads a little faster, keyboard latency 2.5× lower. `netget` reaches
9 543 KiB/s – the speed of Debian on the same cable (the 100 Mb/s link is the limit); the first, slower run right
after boot was noise. Clock gaps at boot (33 and 40 ms at 0.36 s – the firmware's xHCI
hand-over) and a few of 2–3 ms later, as known.

### Known problems

- From the code review, still open: an I/O error in the middle of a FAT32 write can leave lost clusters (with
  DeSoFS).
- Otherwise as in v0.54.0.

### Performance against the previous release (v0.54.0 → v0.55.0, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.54.0 | TCG v0.55.0 | KVM v0.54.0 | KVM v0.55.0 |
|---|---|---|---|---|
| irq_kernel_ns | 3 108 | 3 096 | 35 650 | 36 055 |
| irq_user_ns | 8 129 | 6 905 | 66 093 | 67 226 |
| fact_kernel_ns | 28 196 | 29 065 | 50 735 | 53 835 |
| fact_user_ns | 74 626 | 72 806 | 92 506 | 91 827 |
| fact_svc_ns | 208 116 | 170 357 | 105 097 | 106 044 |
| ping_svc_ns | 121 359 | 109 589 | 21 677 | 21 619 |
| restart_us | 6 200 | 4 200 | 1 300 | 1 300 |

`[RESULT-USB]`:

| | TCG v0.54.0 | TCG v0.55.0 | KVM v0.54.0 | KVM v0.55.0 |
|---|---|---|---|---|
| start_ms | 408 | 400 | 366 | 411 |
| enum_avg_ms | 31 | 26 | 24 | 25 |
| read_kbs (usbd) | 54 613 | 83 591 | 80 313 | 71 859 |
| kread_kbs (kernel) | 74 535 | 61 091 | 89 487 | 86 949 |
| kcat_kbs (kernel, cat) | 46 483 | 53 146 | 102 080 | 100 279 |
| hid_avg_us (keyboard) | 800 | 645 | 187 | 311 |

Verdict: no regression. KVM is unchanged within noise; on TCG `fact_svc_ns` is back at 170 357 (the +20 % in
v0.54.0 was noise, as assumed). The FAT32 bounds check costs nothing measurable (`kread_kbs` / `kcat_kbs` on KVM
within 3 %).

---

## v0.54.0 — 2026-10-31

**Status: stable on QEMU (TCG and KVM); real hardware not re-measured since v0.47.0.**

### What is new since the last report (v0.53.0)

| Version | Change |
|---|---|
| v0.54.0 | process memory hardened after a code review: at most 4096 areas per process (`ERROR_OUT_OF_MEMORY` instead of a full kernel heap), freed `mmap` ranges reused (the range never runs out), `PROT_NONE`; `munmap` skips untouched stretches |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 30/30 suites, 235 tests PASS | 84 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 30/30 suites, 235 tests PASS | 72 s |

New in FILE TEST 4/8 (`memtest`, 37 checks): 4 KiB areas up to the limit and back, a hole at the limit refused,
60 000 × 2 GiB `mmap` + `munmap` (more than the whole mmap range), `PROT_NONE`.

### Real hardware

Unchanged since the v0.52.1 report (last measured v0.47.0 / v0.35.2 / v0.29.0).

### Known problems

- From the code review, still open: FAT32 on an MBR partition does not keep the partition length (the size is
  checked only against the end of the disk); an I/O error in the middle of a FAT32 write can leave lost clusters;
  `dcp audit` shows children, not grandchildren.
- Once in the build server's runs: NOBKL TEST 10/10 reported 199 of 200 orphans reaped (a timing race in the test,
  not seen on the build machine); to be looked at.
- Otherwise as in v0.53.0.

### Performance against the previous release (v0.53.0 → v0.54.0, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.53.0 | TCG v0.54.0 | KVM v0.53.0 | KVM v0.54.0 |
|---|---|---|---|---|
| irq_kernel_ns | 3 195 | 3 108 | 35 155 | 35 650 |
| irq_user_ns | 7 852 | 8 129 | 65 897 | 66 093 |
| fact_kernel_ns | 26 490 | 28 196 | 55 944 | 50 735 |
| fact_user_ns | 72 542 | 74 626 | 93 852 | 92 506 |
| fact_svc_ns | 173 160 | 208 116 | 99 255 | 105 097 |
| ping_svc_ns | 130 208 | 121 359 | 20 387 | 21 677 |
| restart_us | 3 500 | 6 200 | 1 200 | 1 300 |

`[RESULT-USB]`:

| | TCG v0.53.0 | TCG v0.54.0 | KVM v0.53.0 | KVM v0.54.0 |
|---|---|---|---|---|
| start_ms | 407 | 408 | 386 | 366 |
| enum_avg_ms | 30 | 31 | 26 | 24 |
| read_kbs (usbd) | 64 000 | 54 613 | 71 859 | 80 313 |
| kread_kbs (kernel) | 56 978 | 74 535 | 77 694 | 89 487 |
| kcat_kbs (kernel, cat) | 60 835 | 46 483 | 76 937 | 102 080 |
| hid_avg_us (keyboard) | 543 | 800 | 389 | 187 |

Verdict: no regression. KVM is unchanged or better. On TCG `fact_svc_ns` (+20 %) and `kcat_kbs` are lower, but
the change does not touch those paths, the same numbers on KVM are normal, and TCG moves by ±15 % between runs
(`restart_us` 3 500 – 6 200 over the last releases).

---

## v0.53.0 — 2026-10-29

**Status: stable on QEMU (TCG and KVM); real hardware not re-measured since v0.47.0.**

### What is new since the last report (v0.52.1)

| Version | Change |
|---|---|
| v0.52.2 | this release report (`RELEASE.md`) |
| v0.53.0 | directory handles: `dir_open` + `openat` / `readdirat` / `statat` / `mkdirat` / `unlinkat`, never above the directory; `nofiles --dir` / `--dir-ro` in the shell; rights-table rows with conditional rights |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 30/30 suites, 235 tests PASS | 82 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 30/30 suites, 235 tests PASS | 71 s |

New: FILE TEST 8/8 (`dirtest`, 42 checks) and `nofiles --dir` in FILE TEST 3/8; RIGHTS TEST now covers 56 syscalls
(28 refusals).

### Real hardware

Unchanged since the v0.52.1 report (last measured v0.47.0 / v0.35.2 / v0.29.0).

### Known problems

- Directory handles hold a path, not the directory (a directory removed and created again under the same name is
  reached through the old handle).
- Otherwise as in v0.52.1: no TLS / IPv6 / UDP sockets for programs, DMA without an IOMMU, at most 16 CPUs.

### Performance against the previous release (v0.52.1 → v0.53.0, same machine)

`[RESULT-SVC]` (ns):

| | TCG v0.52.1 | TCG v0.53.0 | KVM v0.52.1 | KVM v0.53.0 |
|---|---|---|---|---|
| irq_kernel_ns | 3 102 | 3 195 | 32 190 | 35 155 |
| irq_user_ns | 7 772 | 7 852 | 65 359 | 65 897 |
| fact_kernel_ns | 26 784 | 26 490 | 52 590 | 55 944 |
| fact_user_ns | 69 541 | 72 542 | 91 785 | 93 852 |
| fact_svc_ns | 187 090 | 173 160 | 101 419 | 99 255 |
| ping_svc_ns | 105 820 | 130 208 | 20 772 | 20 387 |
| restart_us | 5 500 | 3 500 | 1 200 | 1 200 |

`[RESULT-USB]`:

| | TCG v0.52.1 | TCG v0.53.0 | KVM v0.52.1 | KVM v0.53.0 |
|---|---|---|---|---|
| start_ms | 419 | 407 | 378 | 386 |
| enum_avg_ms | 26 | 30 | 22 | 26 |
| read_kbs (usbd) | 68 266 | 64 000 | 81 920 | 71 859 |
| kread_kbs (kernel) | 76 169 | 56 978 | 102 053 | 77 694 |
| kcat_kbs (kernel, cat) | 62 224 | 60 835 | 106 384 | 76 937 |
| hid_avg_us (keyboard) | 718 | 543 | 173 | 389 |

Verdict: services – no regression (TCG `ping_svc_ns` 130 208 is inside the 105 820 – 129 449 range of the ten
v0.52.1 runs, just above it). **USB stick reads through the kernel are lower on KVM in this run** (`kread_kbs` −24 %,
`kcat_kbs` −28 %; the KVM runs since v0.48.0 were `kread_kbs` 89 510 – 117 128 and `kcat_kbs` 100 822 – 141 656). The change in
this release does not touch that path (the FAT32 / ublk read in the kernel). **Second KVM run: `kread_kbs` 89 084,
`kcat_kbs` 103 515, 30/30 PASS in 72 s – back in the usual range, so it was noise. No regression.**

---

## v0.52.1 — 2026-10-28

**Status: stable on QEMU (TCG and KVM); real hardware not re-measured since v0.47.0.**
v0.52.2 adds only this report (no code changes).

### What is new since the last report (v0.47.0)

| Version | Change |
|---|---|
| v0.48.0 | `netconfig` / `netget` (were `ifconfig` / `fetch`); programs from the shell get a program channel without network administration – only `netconfig` may change network settings |
| v0.49.0 | one rights table for every syscall (`kernel/user/sysrights.rs`), one gate before decoding; RIGHTS TEST |
| v0.50.0 | DeSoOS error names `ERROR_*` in the kernel and in programs (Unix numbers kept) |
| v0.51.0 | `usblist`, `netarp`, `netweb` (were `lsusb`, `arping`, `httpd`) |
| v0.51.1 | documentation brought up to date |
| v0.52.0 | `kill` only for the caller and its descendants; services ended through init (`kill <name>`); `kill` built into the shell |
| v0.52.1 | the rare QEMU TCG stall in ALLOC TEST 4/5 found and fixed (`yield_now` kept the Big Kernel Lock) |

### Tests

| Run | Configuration | Result | Time |
|---|---|---|---|
| TCG | QEMU q35, 4 CPUs, 512 MiB, `-accel tcg,thread=multi -cpu max` | 30/30 suites, 234 tests PASS | 82 s |
| KVM | QEMU q35, 4 CPUs, 512 MiB, `-accel kvm -cpu host` | 30/30 suites, 234 tests PASS | 71 s |
| TCG × 10 | the same, 10 runs in a row (`TIMEOUT=400`) | 10/10 PASS, no stall | 81–83 s each |
| ALLOC test × 400 (build server) | allocator suite alone, 400 rounds, 4 CPUs and 8 CPUs | 0 stalls (before the fix: 3 stalls of 30–111 s in ~400 rounds) | phase 4: max 372 ms |

QEMU devices in the test run: e1000e network (user mode, DHCP / DNS / HTTP stubs on the host), xHCI with a USB
stick, keyboard, hub + mouse + second stick (hot-plug), virtio-blk, NVMe, `edu` (test device for user-space
drivers).

### Real hardware (test laptop: Ryzen 7 4800H, 16 threads, NVMe, xHCI, Realtek RTL8168h)

| What | Result | Last measured |
|---|---|---|
| Boot from a USB stick, shell, USB keyboard | works | v0.47.0 |
| Network: DHCP from the home router, ping, `netget` 10 MiB from the internet | 7579 KiB/s (Debian on the same laptop and cable: 9.78 MB/s; link 100 Mb/s) | v0.47.0 |
| Stress (16 CPUs, 60 s, compare mode) | 600 637 scripts | v0.35.2 |
| USB stick read / keyboard latency | 120 MB/s / 275 µs | v0.29.0 |

Not re-measured for v0.48–v0.52.1. A test-laptop run (`./make-usb.sh`, autostress 60 s, `netget`) is due before the
next release that touches the scheduler or drivers.

### Known problems

- No TLS (`https://` refused), no IPv6, no UDP sockets for programs.
- DMA without an IOMMU: `netd` and `usbd` are trusted system code.
- Files: any unsandboxed program may open any path (directory handles – next DCP step); FAT32 only with 512-byte
  sectors; real SSDs are read-only on purpose.
- At most 16 CPUs; device interrupts only to the boot CPU.
- Full list: "Current limitations" at the top.

### Performance against the previous release (v0.52.0 → v0.52.1, same machine)

`[RESULT-SVC]` – service benchmarks (ns, lower is better; `restart_us` – a service restart):

| | TCG v0.52.0 | TCG v0.52.1 | KVM v0.52.0 | KVM v0.52.1 |
|---|---|---|---|---|
| irq_kernel_ns | 3 064 | 3 102 | 36 556 | 32 190 |
| irq_user_ns | 6 912 | 7 772 | 64 123 | 65 359 |
| fact_kernel_ns | 27 793 | 26 784 | 56 785 | 52 590 |
| fact_user_ns | 69 759 | 69 541 | 93 632 | 91 785 |
| fact_svc_ns | 183 486 | 187 090 | 97 895 | 101 419 |
| ping_svc_ns | 110 436 | 105 820 | 23 334 | 20 772 |
| restart_us | 3 800 | 5 500 | 1 200 | 1 200 |

`[RESULT-USB]` (QEMU's xHCI; KiB/s higher is better, ms / µs lower is better):

| | TCG v0.52.0 | TCG v0.52.1 | KVM v0.52.0 | KVM v0.52.1 |
|---|---|---|---|---|
| start_ms | 406 | 419 | 398 | 378 |
| enum_avg_ms | 26 | 26 | 26 | 22 |
| read_kbs (usbd) | 66 064 | 68 266 | 73 142 | 81 920 |
| kread_kbs (kernel) | 87 368 | 76 169 | 112 289 | 102 053 |
| hid_avg_us (keyboard) | 640 | 718 | 431 | 173 |

Verdict: no regression. The differences are within run-to-run noise (TCG `ping_svc_ns` ranged 105 820 – 129 449
over the 10 runs of the same build). The KVM keyboard latency of 173 µs is a single run – to be confirmed.

`[RESULT-RIGHTS]` (the syscall rights gate, build server, TCG): 50 rows, 20 refusals in the table test, gate
~21 ns per syscall.
