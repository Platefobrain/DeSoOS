# user – user-space programs

Everything that runs in ring 3: the first process, the shell, drivers and services, tools and test programs. They
are built by `build.sh` into ELF files and put into the kernel image (`/bin`); no libc – the library is
`libdeso` (`sdk/libdeso`, one crate every program links to).

Start reading at `bin/init.rs` (the first process: starts the services and the shell) and `../sdk/libdeso/src/lib.rs`
(syscalls, handles, errors).

| Path | What |
|---|---|
| `bin/init.rs` | the first process and the service manager (services from `etc/services/`) |
| `bin/sh.rs` | the user shell (programs by name from `/bin`, then – never instead of a system name – from `/disk/bin`) |
| `bin/netd.rs`, `bin/usbd.rs`, `bin/edud.rs`, `bin/echod.rs` | services: network card driver + TCP/IP, xHCI USB driver, the QEMU `edu` device, an echo test service |
| tools | `ls`, `cat`, `cp`, `mv`, `rm`, `mkdir`, `touch`, `stat`, `ps`, `sleep`, `sha256sum`, `random`, `certcheck`, `services`, `usblist`, `netconfig`, `netget` (http / https), `udpsend`, `nettime` (NTP, read only), `netweb`, `ping`, `host`, `netarp`, ... |
| `bin/timekeeper.rs` | the time service (init's `time`): NTS from three operators of a built-in list, the quorum, `SYS_TIME_SET` – the only program that sets the clock (`docs/time/TIMEKEEPER.md`) |
| `bin/*test.rs`, `ipcbench`, `svcbench`, `sysfuzz` | test and benchmark programs run by the kernel self-tests (`blktest` / `blkwtest` / `blkdtest` – fake USB sticks for the ublk protocol: reading, writing, /disk with a write cache and power loss; `timetest protect` – a program trying every way to change `/.deso`, LKG TEST; `timetest set / bound / clock` and `synctest` – the time service's syscalls and arithmetic, NTS TEST; `privtest` – the handles a program got, SYSCTL and SYS_TIME_SET refused; `privtest send` – a message on slot 3, which channel the shell gave it; USB DISK TEST; `abiprobe` – the ABI description against the running kernel through raw syscalls with the generated constants, including the argument order of 32 calls, ABI TEST; `starttest` – the start contract seen from a libdeso program (stack, slots, 7 MiB of stack, exit codes, a panic), STARTUP TEST; `prototest` – the service protocols' versions against init, netd and fake services (itself in `fake` mode), SERVICES TEST) |
| `bin/desopkg.rs` | the package manager (`docs/pkg/README.md`): programs from DecodeSoft's signed repository onto `/disk/pkg`, run by name through the shell |
| `bin/pkgtest.rs` | PKG FORMAT TEST: `vectors` (pkgfmt.rs against the Python tool's vectors), `etc` (`/etc/desopkg` of the image), `elf` (every `/bin` program through `common/elf.rs` `check_program`); `b1-notime`, `b1` – PKG TEST part 1 (desopkg, the shell and netget against tests/repo-stub.py) |
| `bin/soak.rs` | the soak test (`tests/soak.sh`): a controller and its workers – files and snapshots, services, network, processes – with checkpoints |
| `lib/*.rs` | shared pure code: TCP, DHCP, DNS, packet parsing (`netproto.rs`), HTTP/1.1 answers (`http.rs` – netget's parser, chunked, trailers), NTP (`ntp.rs` – nettime's query, checks and arithmetic), NTS (`nts.rs` – NTS-KE records, the NTS fields, cookies; `ntske.rs` – NTS-KE over a netd connection, shared by nettime and the time service), the time service's arithmetic (`timesync.rs` – intervals, quorum, envelope, backoff), USB descriptors, file copying, the `edu` protocol; desopkg (v0.82): `cmdnames.rs` – the names the system keeps (the shell's lists, shared with desopkg), `pkgfmt.rs` – every desopkg file format (`docs/pkg/FORMAT.md`), `pkgvec.rs` – the test vectors, `pkgstate.rs` – the state on the disk (current generation, indexes, `gc`; shared by desopkg and sh), `pkgsolve.rs` – dependencies; `fetch.rs` – the HTTP(S) client of netget and desopkg |
| `etc/services/*.svc` | service manifests: what each service is given (devices, grants, file access) |
| `etc/desopkg/keys`, `keys.test`, `repo`, `repo.test` | desopkg's trusted keys (a normal image; empty until DecodeSoft's key, V082 stage C), the self-test image's key store (the test key only) and the repository (`/etc/desopkg/`, sealed at boot) |
| `etc/certs/roots`, `etc/certs/gen-roots.py` | the trusted CA store (`/etc/certs/roots`, sealed at boot) and the script that makes it from Mozilla's root store (NSS `certdata.txt`, pinned tag and SHA-256) |

A new program: add `bin/<name>.rs` (`#![no_std]`, `#![no_main]`, `#[macro_use] extern crate libdeso;`,
`use libdeso as deso;`, `entry!(main)`); `build.sh` builds it against `libdeso` with `sdk/libdeso/link.ld` (the ABI
note in its own PT_NOTE) and it appears as `/bin/<name>`. A program that is not part of the system: the SDK (`sdk/deso-build.sh`,
`docs/abi/SDK.md`) builds it outside the repository, and it goes to `/disk/bin`.
