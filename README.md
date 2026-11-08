# DeSoOS v0.73.1

DeSoOS is a hobby operating system for x86_64 PCs and laptops with UEFI firmware, written in
Rust. It uses a hybrid design: a small kernel, with drivers and services running as ordinary
user-space processes that talk to the kernel and to each other over IPC (handles, channels and
shared memory).

Boot chain:

```
UEFI firmware (OVMF in QEMU) -> DSB (DeSoOS boot loader) -> DeSoOS kernel
```

More documentation:

- `CHANGELOG.md` - every change, version by version.
- `docs/` - the documentation of the whole system (index: `docs/README.md`): `docs/ARCHITECTURE.md` (what lives in
  the kernel, what runs in user space, syscalls and IPC), `docs/RELEASE.md` (tests, real hardware, performance and
  current limitations per release), `docs/desofs/` (the DeSoFS file system and its on-disk format).
- A `README.md` in the main code folders (`kernel/`, `kernel/fs/desofs/`, `user/`, `common/desocrypto/`, `tests/`)
  – what the folder holds and where to start reading.

## Features

- UEFI boot through its own loader (DSB); higher-half kernel, ELF loading, guard-paged stack.
- Memory management: physical frame allocator, 4-level paging with a direct map, kernel heap,
  per-process address spaces, NX and SMEP.
- Preemptive scheduler with SMP support (up to 16 CPUs), Local APIC timer, IPIs, TLB shootdown,
  and adaptive idle polling before `hlt` for faster wake-ups.
- User processes in ring 3: static Rust ELF programs, syscalls, FPU/SSE state per process,
  faults that kill only the offending process, background jobs, Ctrl+C.
- IPC: handles, channels and shared memory; drivers and services run in user space and are
  supervised by `init`, each with exactly what its manifest (`/etc/services/*.svc`) grants – the
  drivers have no file access at all.
- ACPI (MADT etc.), PCI enumeration.
- Storage: virtio-blk, NVMe (read-only on real hardware), GPT partitions, block layer with
  read-only enforcement.
- USB: xHCI driver in a user-space service (`usbd`) with keyboard, mouse, read-only mass storage
  and hubs (nested up to 5 levels).
- Network: a user-space service (`netd`, one per card) with drivers for Intel e1000/e1000e (QEMU) and
  Realtek RTL8111/8168 (real hardware), ARP, IPv4, ICMP, UDP, DHCP, DNS, TCP client and server, loopback;
  tools `netconfig`, `ping`, `host`, `netarp`, `netget` (HTTP), `netweb` (a small web server).
- Permissions (DCP): a process may do exactly what its handles allow; one rights table checked before every
  syscall; a file sandbox (`nofiles`) with directory handles (a program sees one directory only); network
  administration only for `netconfig`.
- Cryptography: DeSoCrypto, DeSoOS's own library (`common/desocrypto`) for the kernel and programs – SHA-256/384/512,
  HMAC and HKDF over them, ChaCha20, Poly1305, ChaCha20-Poly1305 (AEAD), X25519, AES-128-GCM (AES-NI and PCLMULQDQ
  in programs, a bitsliced fallback without tables), RSA (PKCS#1 v1.5, PSS) and ECDSA (P-256, P-384) signature
  verification, tested with Wycheproof (no heap, no syscalls; not audited – not for production use);
  tools `sha256sum`, `random`.
- Random numbers: the kernel's generator (ChaCha20 with fast key erasure) fed by the firmware's RNG, RDSEED,
  RDRAND, TSC jitter and interrupt times, with health checks and careful entropy counting; the kernel waits at boot
  until 256 bits are counted; `getrandom` for programs (no right needed, never blocks); `netd` uses it for TCP
  sequence numbers, ports and DNS ids.
- File systems: VFS with ramfs (`/`), DeSoFS or FAT32 at `/disk` (recognised at start), FAT32 on `/usb0` and the EFI partition at `/esp`; DeSoFS, DeSoOS's own
  copy-on-write file system with SHA-256 over every block, is being built – format 1 is specified
  (`docs/desofs/FORMAT.md`); volumes can be formatted, mounted with files and directories, fully checked (every block's
  checksum, directories, relations) and repaired back to a whole sound state (kernel shell `desofs`); every
  operation is tested against power loss at each write. A block cache keeps verified blocks between operations
  (every hit checked by its SHA-256 again; at most 1/16 of memory, 64 MiB).
- Framebuffer console with scrollback, PS/2 and USB keyboards, mouse wheel scrolling.
- User-space shell (`sh`) with history, Tab completion, redirection and job control; a kernel
  emergency shell as a fallback.
- Built-in self-tests (34 suites, a restart phase and a short soak, 288 tests), stress tests and a long soak test
  (`tests/soak.sh` – everything at once for hours with leak and file system checkpoints), runnable automatically in
  QEMU or on real hardware.

It has been tested in QEMU and on a real 16-thread AMD laptop with xHCI USB, an NVMe SSD and Realtek
Ethernet.

## Requirements

- Linux host (scripts use bash, `lsblk`, `findmnt`, etc.).
- Rust toolchain with edition 2024 support (`rustc`, `cargo`, `rustup`). `build.sh` adds the
  targets `x86_64-unknown-none` and `x86_64-unknown-uefi` automatically if they are missing.
- binutils (`objcopy`, `readelf`).
- For QEMU: `qemu-system-x86` and OVMF (`sudo apt install ovmf qemu-system-x86`).
- `python3` for the test scripts (creates FAT32 test images).
- Optional: `mtools` to access `disk.img` from the host; `/dev/kvm` for hardware acceleration.

## Building

```bash
./build.sh                  # regular kernel (no self-tests)
./build.sh --selftest       # kernel with self-tests (results on the serial console)
./build.sh --autostress=60  # runs a 60 s stress test by itself 5 s after boot
./build.sh --autosoak=3600  # runs a 1-hour soak test on a RAM disk before init (real hardware)
```

Do not run `build.sh` with sudo.

Build-time environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `DESOOS_AUTOSTRESS=S` | `0` (off) | Same as `--autostress=S`: stress test for S seconds 5 s after boot. |
| `DESOOS_AUTOSOAK=S` | `0` (off) | Same as `--autosoak=S`: the soak test for S seconds (at least 60) on a RAM disk before init. Not together with `DESOOS_AUTOSTRESS`. |
| `DESOOS_TRUST_CPU=0/1` | `1` | Whether RDSEED counts entropy in the kernel's random number generator (0: still mixed in, counts nothing). |
| `DESOOS_TRUST_BOOTLOADER=0/1` | `1` | Whether the firmware's RNG (RAW algorithm) counts entropy (0: still mixed in, counts nothing). |
| `DESOOS_STRESS_POOL=P` | `0` | Stress with P processes per CPU (full load). `0` = comparison mode (3 per CPU, at most 48). |
| `DESOOS_IDLE_POLL_US=N` | `200` | Upper bound (us) for spinning an idle CPU before `hlt`; `0` = `hlt` immediately. |
| `DESOOS_IDLE_POLL_ADAPT=0/1` | `1` | `1` = the polling window adapts per CPU; `0` = fixed N. |

Outputs:

- `build/kernel.elf` - optimized kernel with symbols (for gdb).
- `build/kernel.boot.elf` - stripped copy embedded in the boot loader.
- `build/EFI/BOOT/BOOTX64.EFI` - the whole system as a single UEFI executable.

DSB loads the kernel's ELF segments at `0xffffffff80000000`, sets up its own page tables,
allocates a stack with a guard page, calls ExitBootServices and jumps to the kernel.

Virtual memory layout: the lower half is reserved for processes; physical memory is mapped at
`0xffff800000000000 + address` (direct map); kernel heap at `0xffffc00000000000`; kernel at
`0xffffffff80000000`; kernel stack below `0xffffffffc0041000`. The `mem` command shows where the
kernel is located physically.

User programs live in `user/bin/*.rs` and are embedded in the kernel image as `/bin/<name>`.
To add one, create `user/bin/<name>.rs` (see `user/bin/hello.rs`) and run `./build.sh`. The
user library `user/lib/desoos.rs` provides `println!`, files, directories, `spawn`/`wait`/`kill`,
`sleep_ms`, `readkey`, arguments, and `Vec`/`String` via `extern crate alloc;`.

## Running in QEMU

```bash
./run-qemu.sh
```

The kernel starts `/bin/init`, which starts the user-space shell (`desoos:/$`). Output appears
both in the QEMU window and in the terminal; you can type in either (the QEMU window uses a PS/2
keyboard). Type `help` for the command list. If `/bin/init` is missing or keeps crashing, the
kernel emergency shell (`desoos>`) starts instead.

Note: in the terminal (`-serial stdio`) Ctrl+C quits QEMU; in the QEMU window it goes to the shell.

Options (environment variables):

- `ACCEL=kvm` - hardware virtualization (Linux with `/dev/kvm`; faster and truly parallel).
  Needs access to `/dev/kvm`: `sudo usermod -aG kvm $USER`, then log out and back in.
  Default: `ACCEL=tcg` (multi-threaded emulation).
- `SMP=N` - number of CPUs (default 4).
- `USB=1` - no PS/2 controller (like many laptops): keyboard and mouse only via USB, handled by
  the user-space `usbd` service.
- `HUB=1` - adds a USB hub on port 3; with `USB=1` the keyboard and mouse are behind it
  (ports 3.1, 3.2) and `usb.img` on port 3.3.

Disks attached by `run-qemu.sh`:

- `disk.img` - virtio-blk data disk (64 MiB, created on first run), DeSoFS or FAT32 at `/disk`.
- `nvme.img` - disk on QEMU's emulated NVMe controller (created on first run). This is the only
  NVMe device DeSoOS ever writes to.
- `build/` - presented as a read-only USB stick, like a real boot from a USB stick.
- `usb.img` (optional, in the repository root) - a second, read-only USB stick, mounted at
  `/usb0`. Create one with your own files: `python3 tests/mkfat32.py usb.img file1 file2`.

## Self-tests and stress tests

```bash
tests/test.sh                # build --selftest + run tests in headless QEMU
tests/test.sh --no-build     # run only (after your own ./build.sh --selftest)
tests/test.sh --verbose      # show the whole log live
TIMEOUT=300 tests/test.sh    # change the timeout (default 240 s)
ACCEL=kvm tests/test.sh      # with KVM; SMP=N also works (default 4)
LOOP=nobkl:400 tests/test.sh # loop mode: one suite 400 times, stops at the first failure
```

**Loop mode** is for rare failures that show up once in hundreds of runs. The boot suites run once, then only the
named suite runs round after round (USB, network, stress and the other suites are skipped); the default timeout
becomes 3600 s. Suites: `smp`, `lock`, `tlb`, `alloc`, `nobkl`, `files`, `ipc`, `rights`. The summary shows
`[RESULT-LOOP] suite=… rounds=… passed=… min_ms=… avg_ms=… max_ms=…` and the failed round, if any.

After the tests QEMU starts a second time on the same test disk (the restart phase – DeSoFS written by the first
start must be there), then a short soak runs for 2 minutes (see below).

Result and exit code: `PASS` (0), `FAIL` (1, with a list of failures), `TIMEOUT` (2, hang) or a
QEMU/build error (3). Full logs: `logs/test.log`, `logs/test-restart.log`, `logs/test-soak.log`. Tests use separate, temporary disk images, so
`disk.img` is left untouched. Do not run `test.sh` at the same time as `run-qemu.sh` or another `test.sh` (they
share `build/` and a host port) – `test.sh` checks this and stops with "another test or QEMU is already running".

How it works: QEMU receives the fw_cfg file `opt/desoos/autotest` and an `isa-debug-exit`
device; after the tests (or on a panic / critical exception) the kernel powers QEMU off with the
result code. A `--selftest` build started with plain `./run-qemu.sh` runs the tests and then
starts the shell as usual. Test code is marked `#[cfg(selftest)]` and is not compiled into a
regular build at all. When adding new test-only functions, mark them `#[cfg(selftest)]` as well.

Soak test – everything at once for a long time (files on DeSoFS with snapshots, services killed and checked to come
back, network downloads, processes and IPC), with a checkpoint every 30 minutes (leaks against a baseline,
`desofs check`):

```bash
tests/soak.sh                     # 1 hour with KVM
DURATION=8h tests/soak.sh         # for the night (90s, 30m, 8h ...)
SEED=1234 tests/soak.sh           # the same run again (the seed is printed at the start)
ACCEL=tcg tests/soak.sh           # without KVM
```

Exit codes: 0 PASS, 1 FAIL (the first error with the last 64 operations of that worker), 2 HANG (no line for 5
minutes), 3 QEMU ended by itself, 4 took too long. Log: `logs/soak.log`; the summary is the `[RESULT-SOAK]` line.
It uses its own disk images and needs the same host ports as `test.sh`, so not both at once.

Stress test in QEMU (the same autostress as on real hardware, before writing a USB stick):

```bash
tests/stress-qemu.sh              # build with autostress + QEMU, result on screen
tests/stress-qemu.sh --no-build   # run only (after ./build.sh --autostress=S)
SECS=120 SMP=8 tests/stress-qemu.sh
```

`SECS` = stress duration (default 60), `SMP` = CPUs (default: host cores, at most 16),
`ACCEL` = `kvm` (default if `/dev/kvm` is available) or `tcg`. Exit codes: 0 PASS, 1 FAIL,
2 timeout/hang, 3 error. Log: `logs/stress-qemu.log`. Afterwards `build/` contains an
autostress kernel; `make-usb.sh` and `test.sh` rebuild their own anyway.

Logs of `make-usb.sh` builds go to `logs/build-usb.log`.

## Real hardware

DeSoOS boots on a PC or laptop from a USB stick in UEFI mode.

### Is my data safe?

Yes. On real hardware DeSoOS **does not write to any disk**:

1. **NVMe driver**: only QEMU's emulated controller (PCI `1b36:0010`) is writable. Every real
   SSD is read-only: a write fails before anything reaches the device. Only read and queue
   setup commands are ever sent (no Write, TRIM, Format, Sanitize or firmware update).
2. **Block layer** (`kernel/block.rs`) independently rejects every write to a read-only disk,
   including `desofs format`, `disk write` and writing files on `/esp`.
3. **USB sticks are read-only**, with four independent locks: `usbd` contains no SCSI write
   command (checked at compile time), the kernel-`usbd` protocol has no write operation, the
   USB disk is read-only in the block layer, and FAT32 / `open` refuse writes (`ERROR_READ_ONLY`).
4. Verified in QEMU on a copy of a typical Linux disk layout (GPT: ESP + swap + ext4) with a
   controller posing as a real SSD and NVMe command tracing: **0 write commands** after boot,
   despite attempts such as `echo > /esp/...`, `rm`, `mkfs` and `disk write` (`mkfs` was the FAT32 formatter, removed in v0.64.1).

The only change outside the USB stick is the Secure Boot setting in the firmware (see below).

### 1. Prepare the USB stick

Any FAT32 USB stick works (for example a new, empty one). The whole system is a single file:
`EFI/BOOT/BOOTX64.EFI`.

```bash
./make-usb.sh --list                 # list USB disks (system disks are marked and never touched)
./make-usb.sh /media/$USER/<LABEL>   # build and copy DeSoOS to the mounted stick
```

The script **does not format anything**. It checks that the target is FAT32 on a USB disk (not
a system disk) and refuses to overwrite another boot loader (e.g. an OS installer) unless you
add `--overwrite`. Sticks formatted as exFAT/NTFS (common for large, new ones) must be
reformatted to FAT32 once, which **erases** the stick: `./make-usb.sh --format /dev/sdX` (checks
that it is USB and asks you to retype the device name), or use your desktop's disk utility.

To run a stress test without a keyboard: `DESOOS_AUTOSTRESS=60 ./make-usb.sh /media/$USER/<LABEL>`
(see [Stress test on real hardware](#stress-test-on-real-hardware)). A plain `./make-usb.sh`
builds a regular kernel.

### 2. Firmware settings

Open the firmware setup (usually F2 or Del at the vendor logo):

- **Secure Boot -> Disabled** (DSB is not signed). You can re-enable it after testing.
- **If the machine also runs Windows with BitLocker**: changing Secure Boot may trigger a
  BitLocker recovery key prompt. Save the recovery key first (Microsoft account or BitLocker
  settings).

### 3. Boot

Insert the stick, power on, open your firmware boot menu (usually F12, F11, F9 or Esc at the
vendor logo) and choose the USB stick (`EFI USB Device`). You will see boot logs, then
`desoos:/$`. Useful checks:

- `disk` - NVMe disks and GPT partitions (all `read-only`)
- `ls /esp` - the disk's EFI partition (read-only), e.g. `ls /esp/EFI`
- `ls /usb0` - the boot USB stick (read-only)
- `cpus` - CPUs online (a 16-thread CPU should show 16)
- `lspci`, `acpi`, `mem`, `ps`, `usblist`, `services`
- Shift+PgUp - scroll back through the boot log

Most laptops have no serial port, so everything is visible only on screen (take a photo if
something goes wrong). To shut down: `k halt` and then hold the power button, or just hold the
power button. Remove the stick and the computer boots normally from its disk.

Internal laptop keyboards are often USB devices rather than PS/2 (no 8042 controller); they
work through `usbd`. If no keyboard works, DeSoOS still boots and shows its logs.

### Stress test on real hardware

Build with `DESOOS_AUTOSTRESS=S` (or `./build.sh --autostress=S`). 5 s after boot the kernel
measures USB reads of the largest file on `/usb0` (256 KiB and 4 KiB buffers, KiB/s) and USB
keyboard latency (interrupt to character, in us; press a few keys meanwhile), printing a
`[RESULT-USB]` line. It then runs the stress test for S seconds, continuously reading that file
from `/usb0` (a `usb:` line with MiB, KiB/s, per-pass checksums and errors), and finally prints
`[AUTOSTRESS] PASS/FAIL`, `cpus` and `mem`. Use `DESOOS_STRESS_POOL=P` for full load.

### Soak test on real hardware

Build with `DESOOS_AUTOSOAK=S` (`DESOOS_AUTOSOAK=3600 ./make-usb.sh /media/$USER/<LABEL>`). Before `init` the
kernel runs the same soak test as `tests/soak.sh`, but on a RAM disk it makes itself (`desofs ramdisk`, 256 MiB
when there is enough memory) – nothing is written to the computer's own disks. The services it kills are whatever
runs (network cards, USB controllers, `echo`); the network check is a ping of the router (and 60 s for a service to
come back – a real DHCP server takes ~16 s); the USB check reads `EFI/BOOT/BOOTX64.EFI` of the boot stick and
compares it with its first reading. Heartbeat lines every minute, a checkpoint every 30 minutes; at the end
`[RESULT-SOAK] …` and a green `[AUTOSOAK] PASS` or red `FAIL`, then the system starts as usual (Shift+PgUp scrolls
back to the result). The USB keyboard and stick drop out for a moment whenever their controller is killed.

`cpus` also lists long gaps between clock (PIT) interrupts as `clock gap N: from X ms, Y us, ...`.
A few during boot are expected on laptops: when `usbd` takes each xHCI controller over from the
firmware (`usblist -v` shows `BIOS: handed over (from X ms, Y ms; ...)`), the firmware stops the
machine for tens of milliseconds (SMI). Lost ticks are caught up from the HPET, so time stays
correct; an occasional ~2 ms gap later on is also firmware.

## Using the shell

The user-space shell (`user/bin/sh.rs`, ring 3):

- Run programs by name (`ls /bin`, `primes 50000`, `args "one two" three`) or by path
  (`cd /bin`, `./hello`).
- Redirection `> file`, `>> file`, `< file`; a trailing `&` runs in the background (`ps`,
  `kill <pid>`, `wait`). Quote names containing spaces: `cat "my file.txt"`.
- Built-ins: `cd`, `pwd`, `echo`, `exit`, `help`, `history`, `clear`, `wait`, `kill`, `sync`, `reboot`,
  `halt`, `stress`.
- `kill <pid>` ends a program started from this shell (the kernel lets a process end only its own
  descendants); `kill <service>` (e.g. `kill net0`) asks init to end a service, which init then restarts.
- Kernel information (read-only): `mem`, `cpus`, `irq`, `lspci`, `acpi`, `disk`, `mount`, `df`,
  `date`, `ver`, `uptime`.
- `services` - state of services started by `init`, including USB controllers (`usb0`,
  `usb1`, ...).
- `usblist` - USB devices: port (`3.2` = controller port 3, hub port 2), VID:PID, speed, type
  (keyboard, mouse, mass storage, hub, ...), interface classes, manufacturer and product.
  `usblist -v` also prints each controller (version, ports, BIOS handoff and its timing).
- `dcp` - permissions (DCP, DeSoOS Capability Permissions): what every process may do (devices,
  system powers, files). `dcp inspect <pid>` - every capability of one process with its rights;
  `dcp audit` - the last refused attempts. DeSoOS has no users or `rwx` bits: a program may do
  exactly what its capabilities allow (see docs/ARCHITECTURE.md, "Syscalls and handles").
- `netconfig` - network cards: driver, MAC address, link, IPv4 address, gateway and DNS servers (from
  DHCP), lease time, frame counters. `netconfig renew` - renew the DHCP lease now. `netconfig set
  192.168.1.50/24 gw 192.168.1.1 dns 192.168.1.1` - an address by hand (for a cable without a DHCP server;
  checked first - an address another machine uses is refused); `netconfig dhcp` - back to DHCP. The address comes from the
  network's DHCP server a few milliseconds after the card starts (in QEMU: 10.0.2.15/24, gateway 10.0.2.2,
  DNS 10.0.2.3). Only `netconfig` may change network settings; other programs started from the shell can use
  the network but not reconfigure it. `netarp <a.b.c.d>` - send one ARP request and show who answered.
- `ping <address or name> [count]` - ICMP echo, one per second (default 4), each answer with its time, then a
  summary (in QEMU: `ping 10.0.2.2`, or `ping example.com` when the host is online). DeSoOS also answers pings
  to its own address. Several programs can use the network at the same time.
- `netget [-o file] [-v] http://host[:port]/path` - download a page over HTTP (TCP through netd); the body to the
  console or to a file, a summary with the speed to stderr. `https://` needs TLS - not supported yet.
- `netweb [-n count] <port> < page` - a minimal web server; the page comes from stdin, so it runs without any
  file access: `nofiles --listen netweb 8080 < /index.html`. `run-qemu.sh` forwards the host's 127.0.0.1:18080 to
  port 8080 of DeSoOS: `curl http://127.0.0.1:18080/` on the host (`HOSTFWD=port` changes it, `HOSTFWD=0` turns it
  off). Connections to 127.0.0.1 or to DeSoOS's own address stay inside (loopback).
- `host <name>` - the IPv4 addresses of a name (DNS; answers are cached). `netconfig dns <a.b.c.d[:port]>` uses
  another DNS server, `netconfig dns auto` the one from DHCP.
- `nofiles <program> [args]` - run a program in the file sandbox: it cannot open any path, only
  use what the shell hands it (`nofiles cat < notes.txt` works, `nofiles cat notes.txt` is refused).
  `nofiles --net <program>` - plus network connections; `nofiles --listen <program>` - plus servers. Such a
  program reaches no other service and cannot change network settings (DNS server, DHCP).
  `nofiles --dir <dir> <program>` - plus one directory (read and write), `--dir-ro <dir>` - read only: the
  program's relative paths work inside it and nowhere else (`nofiles --dir-ro /notes cat todo.txt` works,
  `nofiles --dir-ro /notes cat ../secret.txt` is refused).
- Ctrl+C ends the foreground program, not the shell. `exit` or killing the shell makes `init`
  start a new one.
- `sync`, `reboot`, `halt`, `stress` and `desofs` work only in the shell started by `init` (it holds the system
  control handle; programs it starts do not get it). Disk writes (`disk write`) and `run` are available only in the
  kernel emergency shell.

Line editing and console:

- Arrows, Home/End, Backspace/Delete edit the line; Up/Down browse history; Tab completes.
- Ctrl+C abandons the line, Ctrl+U clears it, Ctrl+L clears the screen.
- Scrollback (1000 lines, in the QEMU window / on screen): Shift+Up/Down by a line,
  Shift+PgUp/PgDn by a screen, mouse wheel by 3 lines; also Shift + keypad 8/2 and 9/3. Typing
  returns to the bottom. In QEMU click the window to capture the mouse; Ctrl+Alt+G releases it.
- Polish characters on PS/2 keyboards: right Alt (AltGr) + a/c/e/l/n/o/s/x/z, AltGr+u = euro sign.

### Files

- `/` is a ramfs (in memory, lost on reboot); `/disk` is the disk `disk.img` (persistent). At start the kernel
  looks at it: the DeSoFS marker → DeSoFS (read-write, or read-only with a message if a tree is damaged, or not
  mounted – never FAT32 instead); otherwise FAT32.
- A new `disk.img` is empty: format it once in DeSoOS with `desofs format 0 yes` (DeSoFS; DeSoOS no longer creates FAT32);
  it is mounted at `/disk` immediately and at every start. Until then `/disk` does not exist. `df` then shows two
  lines (`/` and `/disk`).
- Commands: `ls`, `cd`, `pwd`, `cat`, `touch`, `mkdir`, `rm`, `cp`, `mv`, `stat`, `sha256sum`, `mount`, `df`,
  `sync`, `date`, `desofs info <disk>` (read-only check of a
  DeSoFS volume: which superblock, generation, nodes, snapshots, whether it could be mounted read-write),
  `desofs format <disk> [yes]` (erases the disk; refused on a read-only disk or a whole disk with a partition table),
  `desofs mount <disk>` (disk 0 at `/disk`, others at `/desofs` until reboot), `desofs unmount`, `desofs check <disk>` (unmounted
  volume: every block's checksum, directories, relations; errors with file names) and `desofs repair <disk> [yes]`
  (a volume left read-only by a damaged tree goes back to the other superblock's whole state). In QEMU: `desofs format 0 yes`
  turns `disk.img` into DeSoFS (your FAT32 files on it are gone – copy them first). `mv` inside DeSoFS is one atomic
  step (also directories). A mount that a program still uses (an open file or directory, its current directory)
  is not unmounted or formatted: "in use (N open files / directories) - nothing changed".
- Snapshots (DeSoFS): `desofs snapshot create <disk> <name>` freezes the whole volume in a moment without copying
  anything (up to 31; a name has 1-24 bytes, no `/`, spaces or control characters); `desofs snapshot list <disk>`
  shows each with the blocks only it holds (what deleting it gives back); `desofs snapshot mount <disk> <name>` shows
  it read-only at `/snap/<name>`; `desofs snapshot restore <disk> <name> [yes]` brings every file back to it (disk
  unmounted first; all snapshots stay); `desofs snapshot delete <disk> <name> [yes]` frees its space.
- A RAM disk: `desofs ramdisk <MiB>` (1-1024; at least a quarter of the free memory stays free) adds a writable disk
  in memory – on a computer whose own disks are read-only this is where DeSoFS can be tried: `desofs format N yes`,
  `desofs mount N` (at `/desofs`). It stays until power-off (up to 4 of them, not removable).
- The disk is Linux-compatible; with QEMU stopped you can use mtools on the host:
  `mdir -i disk.img ::`, `mcopy -i disk.img file.txt ::/`.
- Low level: `lspci`, `disk`, `disk read 0 <sector>`, `disk write 0 <sector> <text>`.

### Processes, SMP and stress

- `ps` lists tasks (state, CPU time, CPU; `~2` = not running now, last ran on CPU 2).
- `cpus` shows processors, per-CPU tasks, timer ticks, IPIs, Big Kernel Lock contention and
  TLB shootdown statistics.
- Example: run `primes 3000000 &` twice, then `ps` - both compute in parallel on different CPUs.
- `stress` (10 s) or `stress 300` - many processes, files and spinlocks on all CPUs at once;
  ends with `stress PASS: ...`.

### Kernel emergency shell test programs

In the kernel shell (`desoos>`), `run` lists programs from `/bin` plus built-in assembly test
programs; `run <program> <n>` starts n copies (1..16), e.g. `run xmm 16 &`.

- `run sum` (prints 5050); `run pf` / `gp` / `ud` / `nx` / `sse` - faults that end only the
  process; `run loop` - endless loop (Ctrl+C or `&` + `kill`).
- Syscalls: `run hello`, `run cat`, `run files` (then `cat /tmp/ring3.txt`), `run ticker &`,
  `run regs` (100k syscalls), `run badptr` (bad pointer -> -14). Syscall list:
  `kernel/user/syscalls.rs` and `docs/ARCHITECTURE.md`.
- FPU/SSE: `run sse` (42), `run x87` (3), `run xmm 3` (3 processes checking xmm0-15 2 million
  times; 1 = no corruption), `run fpuclean` (new processes start with clean registers).
- Kernel tasks: `spawn spin`, `spawn tick`, `kill <id>`.

## Project layout

- `boot/` - DSB, the UEFI boot loader (`dsb.rs`).
- `kernel/` - the kernel: `arch/`, `memory/`, `sched/`, `drivers/`, `fs/`, `user/` (processes,
  syscalls), ACPI, GPT, block layer, console, kernel shell, self-tests.
- `user/` - user-space programs (`bin/`), library (`lib/desoos.rs`) and linker script.
- `common/` - code shared by different parts of DeSoOS: ELF parsing (boot loader, kernel) and DeSoCrypto
  (`common/desocrypto/`, kernel and programs).
- `tests/` - `test.sh`, `soak.sh`, `stress-qemu.sh`, `mkfat32.py`, `mkdesofs.py` (DeSoFS reference image), `qemu-hotplug.py`.
- `docs/` - documentation of the whole system: architecture, release reports, DeSoFS (`docs/desofs/FORMAT.md` – the
  on-disk format).
- `build.sh`, `run-qemu.sh`, `make-usb.sh` - build, run in QEMU, write a USB stick.
- `ab-usb.sh`, `ab/` - write an older kernel version to a USB stick for A/B comparisons.
- `build/` - build output; `logs/` - test and build logs.

## License

DeSoOS is licensed under the GNU General Public License v3 or later (`GPL-3.0-or-later`); full
text in `LICENSE`.

Exception: `kernel/drivers/font.rs` is a modified subset of Terminus Font (Copyright (c) 2020
Dimitar Toshkov Zhekov), licensed solely under the SIL Open Font License 1.1 (`OFL-1.1`); the full license text is
in the header of that file.

When distributing DeSoOS (including `BOOTX64.EFI`), include `LICENSE` and the font license from
`kernel/drivers/font.rs`.
