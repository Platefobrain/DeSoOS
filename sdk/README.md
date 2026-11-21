# sdk – building programs for DeSo OS

| Path | What |
|---|---|
| `libdeso/src/` | the program library `libdeso` (ABI 1.0): `lib.rs` (the crate and how a program uses it), `sys.rs` (the raw system call, `_start`, the ABI note, processes, memory, keys, the heap, output), `errors.rs`, `handles.rs`, `fs.rs`, `chan.rs`, `svc.rs`, `net.rs`, `time.rs`, `dev.rs`, `abi.rs` (the constants – generated from `abi/abi.toml` by `tools/abigen.py`, never edited by hand), `unstable.rs` (no promise; empty) |
| `libdeso/link.ld` | the linker script: a static ELF at 0x400000, code / constants / data in separate W^X segments, the ABI note in its own PT_NOTE |

`build.sh` builds the library once (`build/user/liblibdeso.rlib`) and every program in `user/bin/` against it
(`--extern libdeso=…`, `-T sdk/libdeso/link.ld`) and refuses a program without the ABI note. What the library and the
note promise: `docs/abi/README.md`. Building a program outside this repository (a template, `tools/sdk-build.sh`)
comes in stage C of v0.81.
