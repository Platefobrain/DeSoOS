# user – user-space programs

Everything that runs in ring 3: the first process, the shell, drivers and services, tools and test programs. They
are built by `build.sh` into ELF files and put into the kernel image (`/bin`); no libc – the library is
`lib/desoos.rs`.

Start reading at `bin/init.rs` (the first process: starts the services and the shell) and `lib/desoos.rs` (syscalls,
handles, errors).

| Path | What |
|---|---|
| `bin/init.rs` | the first process and the service manager (services from `etc/services/`) |
| `bin/sh.rs` | the user shell |
| `bin/netd.rs`, `bin/usbd.rs`, `bin/edud.rs`, `bin/echod.rs` | services: network card driver + TCP/IP, xHCI USB driver, the QEMU `edu` device, an echo test service |
| tools | `ls`, `cat`, `cp`, `mv`, `rm`, `mkdir`, `touch`, `stat`, `ps`, `sleep`, `sha256sum`, `random`, `certcheck`, `services`, `usblist`, `netconfig`, `netget` (http / https), `netweb`, `ping`, `host`, `netarp`, ... |
| `bin/*test.rs`, `ipcbench`, `svcbench`, `sysfuzz` | test and benchmark programs run by the kernel self-tests |
| `bin/soak.rs` | the soak test (`tests/soak.sh`): a controller and its workers – files and snapshots, services, network, processes – with checkpoints |
| `lib/desoos.rs` | the library every program includes: syscalls, handles, errors, output |
| `lib/*.rs` | shared pure code: TCP, DHCP, DNS, packet parsing (`netproto.rs`), HTTP/1.1 answers (`http.rs` – netget's parser, chunked, trailers), USB descriptors, file copying, the `edu` protocol |
| `etc/services/*.svc` | service manifests: what each service is given (devices, grants, file access) |
| `etc/certs/roots`, `etc/certs/gen-roots.py` | the trusted CA store (`/etc/certs/roots`, sealed at boot) and the script that makes it from Mozilla's root store (NSS `certdata.txt`, pinned tag and SHA-256) |
| `user.ld` | the linker script for all programs |

A new program: add `bin/<name>.rs` (`#![no_std]`, `#![no_main]`, the library through `#[path = "../lib/desoos.rs"]`,
`entry!(main)`); `build.sh` picks it up and it appears as `/bin/<name>`.
