# tests – running the self-tests

The tests themselves are built into the kernel (`--cfg selftest`); this folder starts them in QEMU and holds the
helper scripts.

```
tests/test.sh              build --selftest and run all suites in QEMU (TCG); result PASS / FAIL
ACCEL=kvm tests/test.sh    the same with KVM
tests/test.sh --no-build   run only
LOOP=desofs:20 tests/test.sh   loop mode: one suite many times (smp lock tlb alloc nobkl files ipc rights abi crypto rng certs desofs)
tests/make-usb-test.sh     make-usb.sh --with-disk on the host (V080 gate C): its refusals against a fake /sys,
                           the image, and an update from build v1 to v2 started in QEMU (two builds)
tests/soak.sh              the soak test: everything at once, 1 hour with KVM (DURATION=8h, SEED=, ACCEL=tcg,
                           SOAK_DISK=ram – on a RAM disk as on real hardware)
```

Before anything is built, `test.sh` runs the ABI host test – `python3 tools/abigen.py --test`: the locks, the
description `abi/abi.toml`, the generator, the kernel's syscall numbers and argument registers, `libdeso` taking its
constants only from the generated `abi.rs`, every test and argument-order reference in `abi.toml` pointing at something
that exists, and 25 mutations that must all be caught (`docs/abi/README.md`; `logs/test-abi.log`).
A failure stops the run there.  In QEMU, ABI TEST is the kernel's half: its rights table and constants against the
generated `kernel/user/abi_generated.rs` and its gate on every handle argument of every row, `/bin/abiprobe` on the
generated constants and the argument order of 32 calls, and the loader's ELF ABI note
rules (every `/bin` program carries ABI 1.0; 26 hand-built ELF files; exec of 1.0, no note, 1.1).

After a passing run QEMU starts a second time on the same test disk (RESTART TEST: DeSoFS data must survive a real
restart), a third time without the virtio and NVMe disks (USB RESTART TEST: the writable USB stick becomes /disk by
itself, with its last known good time; `logs/test-usbrestart.log`), twice from an image made by `tools/mkusb.py` – the
code of `make-usb.sh --with-disk` – with nothing else attached (ONE STICK TEST: UEFI boots the image's ESP, `/usb0` is
that ESP read-only, `/disk` its "DeSo system" partition read-write; the second start finds the first one's file and
last known good time, and the ESP is unchanged byte for byte; `logs/test-onestick.log`), then a short soak runs (2 minutes, `soak.sh` on a RAM disk). The end of the output has the summary and the `[RESULT-…]`
lines (services, USB, rights, crypto, random numbers, certificates, TLS, DeSoFS, soak) copied into `docs/RELEASE.md`. Logs: `logs/test.log`,
`logs/test-restart.log`, `logs/test-soak.log`. Exit code: 0 PASS, 1 FAIL, 2 timeout, 3 QEMU stopped otherwise or a host test server could not get its ports.

`soak.sh` starts QEMU with the fw_cfg phase `soak <seconds> <seed>`: the boot tests are skipped and `/bin/soak`
(`user/bin/soak.rs`) runs its workers (files and snapshots on DeSoFS, services killed and checked, network, processes
and IPC) with a checkpoint every 30 minutes (leaks, `desofs check`). Log `logs/soak.log`; exit code 0 PASS, 1 FAIL, 2
HANG (no line for 5 minutes), 3 QEMU ended by itself, 4 too long.

| File | What |
|---|---|
| `test.sh` | the test run (above) |
| `soak.sh` | the long soak test (above) |
| `stress-qemu.sh` | the same stress test as on real hardware, in QEMU |
| `make-usb-test.sh` | `make-usb.sh --with-disk` on the host (above): 16 refusals and checks against a fake `/sys`, `/proc`, `lsblk` and `findmnt` (`DESO_SYS`, `DESO_PROC`); `tools/mkusb.py`'s identity check of the opened device on a fake udev directory (11 cases) and on this computer's USB disks; `tools/mkdesofs.py` – image files only (8 cases); the image (`fsck.vfat` when installed; too small refused, a 70000 MiB stick gets a 64 GiB partition 2); build `v1` → start → the ESP updated to `v2` (`DESO_BUILD_TAG`) → partition 2 unchanged → start: `ver` = v2, the file and the LKG kept. Log `logs/test-make-usb.log` |
| `mkdesofs.py` | DeSoFS in Python: the reference image for the kernel tests; `--format` = `tools/mkdesofs.py` (the production formatter) with a fixed uuid / time |
| `mkfat32.py` | the FAT32 image of the emulated USB stick |
| `mkgpt.py` | the writable test USB stick of USB WRITE TEST: GPT with an ESP (a marker in every sector – the test checks nothing in it changes) and a "DeSo system" partition, primary and backup GPT |
| `dns-stub.py`, `http-stub.py` | small DNS and HTTP servers on the host for the network tests and the soak |
| `udp-stub.py` | a UDP echo server on the host for NET TEST (`/bin/udptest`, nettest's address-change checks) and the soak: echo, 1472-byte answer, bursts, an answer from a foreign port, silence, a per-sender count |
| `ntp-stub.py` | 32 NTP servers on the host (one per port) for NTP TEST (`/bin/ntptest net`): correct, shifted, silent, Kiss-o'-Death, forged, late and malformed answers, servers in 1960 and 2040; checks every query byte for byte, counts packets and repeated Transmit values |
| `http_pages.py` | the HTTP/1.1 answers both `http-stub.py` and `tls-stub.py` serve: chunked bodies, 1xx, 204 / 205 / 304, trailers, Connection, refused answers, the end after a whole answer |
| `tls-stub.py` | HTTPS servers on the host for TLS TEST (Python `ssl` = OpenSSL): good and bad certificates, TLS 1.2 only, no X25519, the framing pages, and men in the middle that change, replay, cut, join or re-key records with the server's keys or break the record with close_notify; port 58471 never answers a SYN (a dead server for nettime's NTS-KE limit) |
| `nts-server/` | a test server on the host in Rust on **rustls** and RustCrypto **aes-siv** (independent of DeSoTLS / DeSoCrypto) – built by `test.sh` (`cargo build`, its own `Cargo.lock`; the first build downloads its crates): the TLS exporter and ALPN for TLS TEST (58500–58502), 27 NTS-KE responses (58510–58536), 15 kinds of NTP-with-NTS answers (58540–58554, reached through NTS-KE at 58570–58584), counters at 58539; for NTS TEST 15 time servers – NTS-KE at 58600–58614 with a chosen certificate, NTP at 58630–58644 with a chosen time (the host's, shifted, or fixed) |
| `stubnet.py` | shared by the Python servers above: a busy port is retried for 5 s (our ports lie in Linux's range for outgoing ports, 32768–60999), and `$STUB_READY/<name>` tells `test.sh` that all ports are bound – QEMU starts only after all host servers (these five and `nts-server/`; in `soak.sh` its three) are listening, otherwise the script stops with exit code 3 and shows who holds the ports |
| `tls/` | the test certificates and keys of `tls-stub.py` and `nts-server/` (`gen-test-certs.py` makes them; `gen-nts-certs.py` the chain with intermediates of the time service's tests – `nts-root`, `nts-good`, `nts-intshort`; test keys only) |
| `qemu-hotplug.py` | plugs and unplugs USB devices during the test (QEMU monitor); the monitor's replies go to `logs/hotplug-monitor.log` |
