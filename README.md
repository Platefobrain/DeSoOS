# DeSoOS v0.47.0

DeSoOS is a hobby operating system for x86_64 PCs and laptops with UEFI firmware, written in
Rust. It uses a hybrid design: a small kernel, with drivers and services running as ordinary
user-space processes that talk to the kernel and to each other over IPC (handles, channels and
shared memory).

Boot chain:

```
UEFI firmware (OVMF in QEMU) -> DSB (DeSoOS boot loader) -> DeSoOS kernel
```

More documentation:

- `ARCHITECTURE.md` - architecture: what lives in the kernel, what runs in user space, syscalls
  and IPC.
- `CHANGELOG.md` and `ROADMAP.md` - detailed development history and plans.

## Features

- UEFI boot through its own loader (DSB); higher-half kernel, ELF loading, guard-paged stack.
- Memory management: physical frame allocator, 4-level paging with a direct map, kernel heap,
  per-process address spaces, NX and SMEP.
- Preemptive scheduler with SMP support (up to 16 CPUs), Local APIC timer, IPIs, TLB shootdown,
  and adaptive idle polling before `hlt` for faster wake-ups.
- User processes in ring 3: static Rust ELF programs, syscalls, FPU/SSE state per process,
  faults that kill only the offending process, background jobs, Ctrl+C.
- IPC: handles, channels and shared memory; drivers and services run in user space and are
  supervised by `init`.
- ACPI (MADT etc.), PCI enumeration.
- Storage: virtio-blk, NVMe (read-only on real hardware), GPT partitions, block layer with
  read-only enforcement.
- USB: xHCI driver in a user-space service (`usbd`) with keyboard, mouse, read-only mass storage
  and hubs (nested up to 5 levels).
- File systems: VFS with ramfs (`/`) and FAT32 (`/disk`, `/usb0`, the EFI partition at `/esp`).
- Framebuffer console with scrollback, PS/2 and USB keyboards, mouse wheel scrolling.
- User-space shell (`sh`) with history, Tab completion, redirection and job control; a kernel
  emergency shell as a fallback.
- Built-in self-tests and stress tests, runnable automatically in QEMU or on real hardware.

It has been tested in QEMU and on a real 16-thread AMD laptop with xHCI USB and an NVMe SSD.

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
```

Do not run `build.sh` with sudo.

Build-time environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `DESOOS_AUTOSTRESS=S` | `0` (off) | Same as `--autostress=S`: stress test for S seconds 5 s after boot. |
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

- `disk.img` - virtio-blk data disk (64 MiB, created on first run), FAT32 at `/disk`.
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
TIMEOUT=300 tests/test.sh    # change the timeout (default 180 s)
ACCEL=kvm tests/test.sh      # with KVM; SMP=N also works (default 4)
```

Result and exit code: `PASS` (0), `FAIL` (1, with a list of failures), `TIMEOUT` (2, hang) or a
QEMU/build error (3). Full log: `logs/test.log`. Tests use separate, temporary disk images, so
`disk.img` is left untouched. Do not run `test.sh` at the same time as `run-qemu.sh` (both use
`build/`).

How it works: QEMU receives the fw_cfg file `opt/desoos/autotest` and an `isa-debug-exit`
device; after the tests (or on a panic / critical exception) the kernel powers QEMU off with the
result code. A `--selftest` build started with plain `./run-qemu.sh` runs the tests and then
starts the shell as usual. Test code is marked `#[cfg(selftest)]` and is not compiled into a
regular build at all. When adding new test-only functions, mark them `#[cfg(selftest)]` as well.

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
   including `mkfs`, `disk write` and writing files on `/esp`.
3. **USB sticks are read-only**, with four independent locks: `usbd` contains no SCSI write
   command (checked at compile time), the kernel-`usbd` protocol has no write operation, the
   USB disk is read-only in the block layer, and FAT32 / `open` refuse writes (`ERROR_READ_ONLY`).
4. Verified in QEMU on a copy of a typical Linux disk layout (GPT: ESP + swap + ext4) with a
   controller posing as a real SSD and NVMe command tracing: **0 write commands** after boot,
   despite attempts such as `echo > /esp/...`, `rm`, `mkfs` and `disk write`.

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
- Built-ins: `cd`, `pwd`, `echo`, `exit`, `help`, `history`, `clear`, `wait`, `sync`, `reboot`,
  `halt`, `stress`.
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
  exactly what its capabilities allow (see ARCHITECTURE.md, "Syscalls and handles").
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
- Ctrl+C ends the foreground program, not the shell. `exit` or killing the shell makes `init`
  start a new one.
- `mkfs`, disk writes (`disk write`) and `run` are available only in the kernel emergency shell.

Line editing and console:

- Arrows, Home/End, Backspace/Delete edit the line; Up/Down browse history; Tab completes.
- Ctrl+C abandons the line, Ctrl+U clears it, Ctrl+L clears the screen.
- Scrollback (1000 lines, in the QEMU window / on screen): Shift+Up/Down by a line,
  Shift+PgUp/PgDn by a screen, mouse wheel by 3 lines; also Shift + keypad 8/2 and 9/3. Typing
  returns to the bottom. In QEMU click the window to capture the mouse; Ctrl+Alt+G releases it.
- Polish characters on PS/2 keyboards: right Alt (AltGr) + a/c/e/l/n/o/s/x/z, AltGr+u = euro sign.

### Files

- `/` is a ramfs (in memory, lost on reboot); `/disk` is the FAT32 disk `disk.img` (persistent).
- A new `disk.img` is empty: format it once in DeSoOS with `mkfs 0`, then `mkfs 0 yes` (it is
  mounted at `/disk` immediately). Until then `/disk` does not exist. `df` then shows two lines
  (`/` and `/disk`).
- Commands: `ls`, `cd`, `pwd`, `cat`, `touch`, `mkdir`, `rm`, `cp`, `mv`, `stat`, plus kernel
  commands `hexdump`, `write`, `mount`, `df`, `mkfs`, `sync`, `date`.
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
  `kernel/user/syscalls.rs` and `ARCHITECTURE.md`.
- FPU/SSE: `run sse` (42), `run x87` (3), `run xmm 3` (3 processes checking xmm0-15 2 million
  times; 1 = no corruption), `run fpuclean` (new processes start with clean registers).
- Kernel tasks: `spawn spin`, `spawn tick`, `kill <id>`.

## Project layout

- `boot/` - DSB, the UEFI boot loader (`dsb.rs`).
- `kernel/` - the kernel: `arch/`, `memory/`, `sched/`, `drivers/`, `fs/`, `user/` (processes,
  syscalls), ACPI, GPT, block layer, console, kernel shell, self-tests.
- `user/` - user-space programs (`bin/`), library (`lib/desoos.rs`) and linker script.
- `common/` - code shared by the boot loader and kernel (ELF parsing).
- `tests/` - `test.sh`, `stress-qemu.sh`, `mkfat32.py`, `qemu-hotplug.py`.
- `build.sh`, `run-qemu.sh`, `make-usb.sh` - build, run in QEMU, write a USB stick.
- `ab-usb.sh`, `ab/` - write an older kernel version to a USB stick for A/B comparisons.
- `build/` - build output; `logs/` - test and build logs.

## License

DeSoOS is licensed under the GNU General Public License v3 or later (`GPL-3.0-or-later`); full
text in `LICENSE`.

Exception: `kernel/drivers/font.rs` is a modified subset of Terminus Font (Copyright (c) 2020
Dimitar Toshkov Zhekov), licensed solely under the SIL Open Font License 1.1 (`OFL-1.1`); see
`FONT-LICENSE.txt`.

When distributing DeSoOS (including `BOOTX64.EFI`), include `LICENSE` and `FONT-LICENSE.txt`.
