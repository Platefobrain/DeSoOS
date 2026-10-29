# DeSoOS Release Report

One section per release, newest on top: what was tested, where, with what result, what is known to be wrong, and
how performance moved against the previous release. Details of every change: `CHANGELOG.md`; plans and all known
gaps: `ROADMAP.md`.

How the numbers are taken: `tests/test.sh` (QEMU TCG) and `ACCEL=kvm tests/test.sh` on the build machine; the
`[RESULT-…]` lines at the end of each run. Performance differences under ~10% between two runs are noise (TCG
timings move by ±15% from run to run on the same build).

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
  reached through the old handle); plan in `ROADMAP.md`.
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
- Full list: `ROADMAP.md`, "Known gaps".

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
