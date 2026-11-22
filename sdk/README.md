# sdk – building programs for DeSo OS

This directory is the whole SDK: copy it anywhere and build programs outside the repository
(`docs/abi/SDK.md` – from zero to a program on `/disk/bin`).

| Path | What |
|---|---|
| `deso-build.sh` | `new DIR` (a new program from the template) and `build FILE.rs [-o DIR] [-n NAME]` (the program: `rustc` alone, offline; refuses a program that is not a static ELF or has no ABI note; the SDK's and the program's paths are not kept in the file) |
| `template/main.rs` | the template: a greeting with the ABI version and the arguments |
| `libdeso/src/` | the program library `libdeso` (ABI 1.0): `lib.rs` (the crate and how a program uses it), `sys.rs` (the raw system call, `_start`, the ABI note, processes, memory, keys, the heap, output), `errors.rs`, `handles.rs`, `fs.rs`, `chan.rs`, `svc.rs`, `net.rs`, `time.rs`, `dev.rs`, `abi.rs` (the constants – generated from `abi/abi.toml` by `tools/abigen.py`, never edited by hand), `unstable.rs` (no promise; empty) |
| `libdeso/link.ld` | the linker script: a static ELF at 0x400000, code / constants / data in separate W^X segments, the ABI note in its own PT_NOTE |

In the repository `build.sh` builds the library once (`build/user/liblibdeso.rlib`) and every program in `user/bin/`
against it with the same options as `deso-build.sh` (`--extern libdeso=…`, `-T sdk/libdeso/link.ld`) and refuses a
program without the ABI note. `abi/abi.toml` stays the one source of the ABI – the SDK has only the generated
`abi.rs`. What the library and the note promise: `docs/abi/README.md`. Test: `tests/sdk-test.sh`.
