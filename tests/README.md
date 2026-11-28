# tests – running the self-tests

The tests themselves are built into the kernel (`--cfg selftest`); this folder starts them in QEMU and holds the
helper scripts.

```
tests/test.sh              build --selftest and run all suites in QEMU (TCG); result PASS / FAIL
ACCEL=kvm tests/test.sh    the same with KVM
tests/test.sh --no-build   run only
LOOP=desofs:20 tests/test.sh   loop mode: one suite many times (smp lock tlb alloc nobkl files ipc rights abi startup crypto rng certs desofs)
tests/make-usb-test.sh     make-usb.sh --with-disk on the host (V080 gate C): its refusals against a fake /sys,
                           the image, and an update from build v1 to v2 started in QEMU (two builds)
tests/sdk-test.sh          the SDK outside the repository: a copy of sdk/ alone builds the template offline, the
                           frozen SDK of ABI 1.0 builds its program, both run on /disk/bin in QEMU (SDK TEST);
                           ACCEL=kvm for KVM
tests/repo-build-test.sh   tools/deso-repo.sh build on the host with the test key, offline: serials (same minute,
                           clock behind), refusals (damaged index, unknown file or empty folder, build failure),
                           the swap killed half-way and put back, the lock (two builds at once, a stale lock);
                           REPO_TEST_FAKE_SDK=1 without the SDK's target
tests/soak.sh              the soak test: everything at once, 1 hour with KVM (DURATION=8h, SEED=, ACCEL=tcg,
                           SOAK_DISK=ram – on a RAM disk as on real hardware)
```

Before anything is built, `test.sh` runs the ABI host test – `python3 tools/abigen.py --test`: the locks, the
description `abi/abi.toml`, the generator, the kernel's syscall numbers and argument registers, `libdeso` taking its
constants only from the generated `abi.rs`, every test and argument-order reference in `abi.toml` pointing at something
that exists, the frozen SDK `sdk/compat/abi-1.0` equal to its lock, and 28 mutations that must all be caught (`docs/abi/README.md`; `logs/test-abi.log`).
A failure stops the run there.  In QEMU, ABI TEST is the kernel's half: its rights table and constants against the
generated `kernel/user/abi_generated.rs` and its gate on every handle argument of every row, `/bin/abiprobe` on the
generated constants and the argument order of 32 calls, and the loader's ELF ABI note
rules (every `/bin` program carries ABI 1.0; 32 hand-built ELF files; exec of 1.0, no note, 1.1).  STARTUP TEST checks
the start contract from the program's side (`docs/abi/STARTUP.md`: `/bin/starttest` and a program in plain machine
code at the edges of the load range, the argument and file limits); SERVICES TEST the service protocols' versions
through the real init (`docs/abi/SERVICES.md`: `/bin/prototest` against init, netd and fake services).  PKG FORMAT TEST checks desopkg's formats
(`docs/pkg/FORMAT.md`): `/bin/pkgtest` judges the vectors `tools/desopkg.py` made at build time with
`user/lib/pkgfmt.rs` – the same verdict and reason for each – reads the image's `/etc/desopkg` and runs every `/bin`
program through `common/elf.rs` against the kernel loader; before QEMU, PKG HOST TEST does the same on the host
(`tools/desopkg.py --test`, `tests/pkg/pkgfmt-host.sh`, `logs/test-pkg.log`).

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
| `sdk-test.sh` | the SDK (`docs/abi/SDK.md`): `sdk/` alone copied to an empty temporary directory, an empty environment (new `HOME`, only `PATH`, working directory `/`) – `deso-build.sh new` + `build` of the template, a static ELF with the ABI 1.0 note, no repository path in the program or the log and no build path in the program, nothing in `HOME`, 4 refusals and a program with an interpreter (`PT_INTERP`) refused; the frozen SDK `sdk/compat/abi-1.0` alone builds `programs/compat10.rs` with its own `deso-build.sh`; then QEMU (`./build.sh --selftest` first) with a fresh DeSoFS volume, a network card and the programs in the fw_cfg files `opt/deso/sdkprog` and `opt/deso/compatprog` – SDK TEST copies the first to `/disk/bin` through the shell and runs it by name (1/2), then runs compat10 from `/disk/bin` through the real init (2/2) (13 checks, `logs/test-sdk.log`) |
| `make-usb-test.sh` | `make-usb.sh --with-disk` on the host (above): 16 refusals and checks against a fake `/sys`, `/proc`, `lsblk` and `findmnt` (`DESO_SYS`, `DESO_PROC`), the model line shown before the question (5 cases: lsblk model, vendor, both, udev's `ID_VENDOR` / `ID_MODEL` from a fake `DESO_UDEV`, nothing → `?`); `tools/mkusb.py`'s identity check of the opened device on a fake udev directory (11 cases) and on this computer's USB disks; `tools/mkdesofs.py` – image files only (8 cases); the image (`fsck.vfat` when installed; too small refused, a 70000 MiB stick gets a 64 GiB partition 2); build `v1` → start → the ESP updated to `v2` (`DESO_BUILD_TAG`) → partition 2 unchanged → start: `ver` = v2, the file and the LKG kept. Log `logs/test-make-usb.log` |
| `repo-build-test.sh` | the repository build (`tools/deso-repo.sh build`, `docs/pkg/README.md` "Publishing") on the host, offline: `DESO_REPO_TEST=1` (the test key `tests/pkg/test-key.pem` and `user/etc/desopkg/keys.test`, never `~/.deso-keys`), a fresh `OUT` in `/tmp`, the clock set by `DESO_REPO_NOW` – 12 checks: the first build (a file beside `stable/` left alone), two builds in one minute, a clock behind the published serial, a later clock, a damaged index and a missing signature refused, a file the script did not make refused and kept, a failed SDK build leaves the publication, a build killed between the two renames (`DESO_REPO_STOP=swap`) is put back by the next one, a published serial of 2^64−1 refused, an empty unknown folder refused, two builds at once (the second refused while the first holds `OUT/.deso-repo.lock`), a lock left by a gone build taken over. Packages built with the SDK; `REPO_TEST_FAKE_SDK=1` uses a stand-in program instead |
| `pkg-test.sh` | PKG TEST (`docs/pkg/README.md`): the normal image holds nothing of the self-test image; witaj built with the SDK for 6 versions, `pkg/make-repo.py` signs the test repositories; seven starts of QEMU (`./build.sh --selftest`) on one DeSoFS volume with `repo-stub.py` and `dns-stub.py` – phase `pkg b1` (part 1 on a fresh volume), `pkg b2` (desopkg killed at every crash point, the lock, the shell paused before exec while `gc` removes its program, damaged indexes and generations), `pkg p1`…`p4` (desopkg hangs at K2h, K6, K7h, K9, the kernel says POWER OFF and the script kills QEMU) and `pkg p5`; `/bin/pkgtest` drives desopkg through init and the shell (`logs/test-pkg-b.log`).  `--mutants`: six self-test builds with one check of desopkg off (`DESO_PKG_MUTANT`), each must fail the phase `pkg m` a normal build passes |
| `repo-stub.py` | the package repository of PKG TEST: HTTPS at tls.deso:58480 (test CA), control at 58481 (`/scenario?name=`, `/hits`, `/reset`); scenarios from `pkg/make-repo.py` (also `evil` – a package with a bad path – and `s50`…`s59`, the same index with higher serials) and transfer modes `long`, `short`, `badlen`, `redirect` |
| `pkg/` | desopkg's formats on the host (PKG HOST TEST): `pkgfmt-host.rs` – `user/lib/pkgfmt.rs` compiled for this computer, `pkgfmt-host.sh` builds it and judges 3294 vectors of `tools/desopkg.py` (294 written by hand, 3000 random mutations) – the same verdict and reason id or FAIL – and `pkgsolve-host.rs` (the dependency solver, 31 cases); `witaj/` – the test package (an SDK program), `make-repo.py` – the test repositories; `test-key.pem`, `other-key.pem` – **test keys only** (the self-test image trusts `deso-test-1`) |
| `mkdesofs.py` | DeSoFS in Python: the reference image for the kernel tests; `--format` = `tools/mkdesofs.py` (the production formatter) with a fixed uuid / time |
| `mkfat32.py` | the FAT32 image of the emulated USB stick |
| `mkgpt.py` | the writable test USB stick of USB WRITE TEST: GPT with an ESP (a marker in every sector – the test checks nothing in it changes) and a "DeSo system" partition, primary and backup GPT |
| `dns-stub.py`, `http-stub.py` | small DNS and HTTP servers on the host for the network tests and the soak |
| `udp-stub.py` | a UDP echo server on the host for NET TEST (`/bin/udptest`, nettest's address-change checks) and the soak: echo, 1472-byte answer, bursts, an answer from a foreign port, silence, a per-sender count |
| `ntp-stub.py` | 32 NTP servers on the host (one per port) for NTP TEST (`/bin/ntptest net`): correct, shifted, silent, Kiss-o'-Death, forged, late and malformed answers, servers in 1960 and 2040; checks every query byte for byte, counts packets (in all and per server) and repeated Transmit values |
| `http_pages.py` | the HTTP/1.1 answers both `http-stub.py` and `tls-stub.py` serve: chunked bodies, 1xx, 204 / 205 / 304, trailers, Connection, refused answers, the end after a whole answer |
| `tls-stub.py` | HTTPS servers on the host for TLS TEST (Python `ssl` = OpenSSL): good and bad certificates, TLS 1.2 only, no X25519, the framing pages, and men in the middle that change, replay, cut, join or re-key records with the server's keys or break the record with close_notify; port 58471 never answers a SYN (a dead server for nettime's NTS-KE limit) |
| `nts-server/` | a test server on the host in Rust on **rustls** and RustCrypto **aes-siv** (independent of DeSoTLS / DeSoCrypto) – built by `test.sh` (`cargo build`, its own `Cargo.lock`; the first build downloads its crates): the TLS exporter and ALPN for TLS TEST (58500–58502), 27 NTS-KE responses (58510–58536), 15 kinds of NTP-with-NTS answers (58540–58554, reached through NTS-KE at 58570–58584), counters at 58539; for NTS TEST 15 time servers – NTS-KE at 58600–58614 with a chosen certificate, NTP at 58630–58644 with a chosen time (the host's, shifted, or fixed) |
| `stubnet.py` | shared by the Python servers above: a busy port is retried for 5 s (our ports lie in Linux's range for outgoing ports, 32768–60999), and `$STUB_READY/<name>` tells `test.sh` that all ports are bound – QEMU starts only after all host servers (these five and `nts-server/`; in `soak.sh` its three) are listening, otherwise the script stops with exit code 3 and shows who holds the ports |
| `tls/` | the test certificates and keys of `tls-stub.py` and `nts-server/` (`gen-test-certs.py` makes them; `gen-nts-certs.py` the chain with intermediates of the time service's tests – `nts-root`, `nts-good`, `nts-intshort`; test keys only) |
| `qemu-hotplug.py` | plugs and unplugs USB devices during the test (QEMU monitor); the monitor's replies go to `logs/hotplug-monitor.log` |
