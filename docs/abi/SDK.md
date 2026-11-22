# The DeSo OS SDK – a program from zero to `/disk/bin`

The directory `sdk/` is the whole SDK: the program library `libdeso`, its linker script, a template and one script,
`deso-build.sh`. Copy it anywhere – it needs nothing else from the DeSo OS repository and nothing from the
network. What a program may rely on (the system calls, handles, constants, the loader): [README.md](README.md).

| Path in `sdk/` | What |
|---|---|
| `deso-build.sh` | `new DIR` – a new program from the template; `build FILE.rs` – the program |
| `template/main.rs` | the template: prints a greeting with the ABI version and its arguments |
| `libdeso/src/` | the library (`abi.rs` – the ABI constants, generated from `abi/abi.toml` in the repository; never edited by hand) |
| `libdeso/link.ld` | the linker script: a static ELF at 0x400000, W^X segments, the ABI note in its own `PT_NOTE` |

## What it needs (Linux Mint / Ubuntu)

```
curl https://sh.rustup.rs -sSf | sh
rustup target add x86_64-unknown-none
sudo apt install binutils
```

`rustc` 1.85 or newer (edition 2024), the `x86_64-unknown-none` target, `objcopy` and `readelf`. No cargo project and
no packages: `deso-build.sh` calls `rustc` itself. The library is compiled from `libdeso/` with the same `rustc`
as the program every time, so any `rustc` that builds it fits – the system's ABI is its system calls, not Rust's
own ABI (a program built with another compiler than the system runs the same).

## A program

```
cp -r sdk ~/deso-sdk            # in the DeSo OS repository
~/deso-sdk/deso-build.sh new ~/programs/witaj2
~/deso-sdk/deso-build.sh build ~/programs/witaj2/main.rs
```

The result is `~/programs/witaj2/build/witaj2` (about 17 KB) – the name comes from the file, or from its directory
for `main.rs` (`-n NAME` gives another; 1–32 characters `a-z 0-9 _ -`; `-o DIR` another output directory).
`witaj2.full` next to it keeps the symbols (for `objdump`). The script refuses a program that is not a static ELF or
has no ABI note for the library's ABI version (1.0), and the paths of the SDK and of the program do not end up in the
file (`--remap-path-prefix`).

The program is `no_std` Rust with `libdeso`:

```rust
#![no_std]
#![no_main]

#[macro_use]
extern crate libdeso;
use libdeso as deso;

entry!(main);

fn main(args: deso::Args) -> i32 {
    println!("Hello from {}", args.get(0).unwrap_or("?"));
    0
}
```

`main` gets the arguments and returns the exit code. Everything of the library is at the crate root: `deso::open`,
`deso::read`, `deso::spawn`, `deso::ERROR_NOT_FOUND`, … (modules `sys`, `errors`, `handles`, `fs`, `chan`, `svc`,
`net`, `time`, `dev`). `Vec` / `String` with `extern crate alloc;` – the library has the allocator. There is no `std`.

## Onto DeSo OS

On a stick made with `./make-usb.sh --with-disk` (an ESP DeSo OS reads, `/usb0`, and the DeSoFS volume `/disk`):

1. Copy the program onto the stick's ESP (label `DESO`). The desktop usually mounts it when the stick is plugged
   in; when it does not (`lsblk -o NAME,LABEL,MOUNTPOINT` shows no mount point for the `DESO` partition), mount it
   yourself – for a stick at `/dev/sda`:

```
udisksctl mount -b /dev/sda1
cp ~/programs/witaj2/build/witaj2 /media/$USER/DESO/
udisksctl unmount -b /dev/sda1
```

2. Start DeSo OS from the stick and in its shell:

```
mkdir /disk/bin
cp /usb0/witaj2 /disk/bin/witaj2
witaj2 one two
```

The shell finds programs in `/disk/bin` after the built-in commands and `/bin` – a program on the disk never
replaces a system command of the same name (`help` lists the programs from the disk separately). DeSo OS never
writes the ESP; updating the stick (`./make-usb.sh /media/$USER/DESO`) replaces only `BOOTX64.EFI`, the program stays
in `/disk/bin`.

The loader reads the program's ABI note before anything is mapped: a program built for ABI 1.0 runs on every DeSo
OS with ABI 1.x; one built for a newer ABI is refused with "needs DeSo OS ABI 1.1, this system 1.0".

## Tests

`tests/sdk-test.sh` (`ACCEL=kvm` for KVM) copies `sdk/` alone into an empty temporary directory and runs it with an
empty environment (a new `HOME`, only `PATH`, working directory `/`): `new` and `build` of the template, a static
ELF with the ABI 1.0 note, no path of the repository in the program or the log and no build path in the program,
nothing written to `HOME`, the refusals (an existing directory, a bad name, no such file, not a `.rs` file); then
QEMU with a fresh DeSoFS volume and the program handed over in a fw_cfg file – SDK TEST copies it to `/disk/bin`
through the shell, runs it by name with two arguments and finds it in `help` (`logs/test-sdk.log`).

## Compared with other systems

| | SDK | Build | What a program states |
|---|---|---|---|
| Linux | headers + glibc | gcc / rustc, distribution packages | glibc symbol versions |
| Windows | Windows SDK | MSVC, a project | the subsystem version in the header |
| macOS | Xcode SDK | Xcode / clang | the minimum system version (LC_BUILD_VERSION) |
| Redox | relibc | cookbook (recipes, cargo) | – |
| **DeSo OS** | `sdk/`: `libdeso` + template | `deso-build.sh` – `rustc` alone, offline | the ABI note: major.minor, the loader checks it |
