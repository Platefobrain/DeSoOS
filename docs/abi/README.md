# DeSo OS ABI

What a program may rely on, written down once and guarded by tests, so that a program built today keeps working on
later systems without being rebuilt (programs live on `/disk/bin` since v0.80; packages come later).

| File | What |
|---|---|
| [`abi/abi.toml`](../../abi/abi.toml) | **the one source of truth** – every system call (number, arguments in order with types, result, errors, rights, status, since, how it is tested) and every constant (errors, handle kinds and rights, flags, slots, loader limits) |
| [`abi/abi-1.0.lock`](../../abi/abi-1.0.lock) | the frozen ABI 1.0 – one readable line per entry with its SHA-256, and a total; written once, never edited |
| [`SYSCALLS.md`](SYSCALLS.md) | the system calls and constants for people – generated |
| `sdk/libdeso/src/abi.rs` | the constants of the program library `libdeso` – generated; the library defines no other public constant |
| `kernel/user/abi_generated.rs` | the kernel's half of ABI TEST: the rights table as text and every constant with its kernel path – generated |
| [`tools/abigen.py`](../../tools/abigen.py) | checks the description, generates the three files, guards the locks; Python 3 standard library only |

Never edit a generated file – change `abi/abi.toml` and run `python3 tools/abigen.py`.

## What ABI 1.0 is

- **System calls**: number in `rax`, arguments in `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`, the instruction `syscall`;
  the result in `rax` as i64 – `>= 0` a value, `< 0` an `ERROR_*` code. Numbers 0–61; 21 is reserved (a call removed
  before ABI 1.0 – it gives `ERROR_NOT_IMPLEMENTED` and is never used again), and so is every number past the table.
- **The rights gate**: every handle argument is checked before the call runs – a handle that does not exist or is of
  the wrong kind gives `ERROR_INVALID_HANDLE`, a missing right `ERROR_ACCESS_DENIED`. Which arguments are handles, of
  which kinds, and which rights they need is part of the ABI (the `handles` of each call).
- **Errors**: the `ERROR_*` values, the same in the kernel and in programs (Unix numbers, DeSo OS names; DeSo-only codes
  from -200: `ERROR_ABI` – the program needs an ABI the system does not give). The errors listed for a call are the
  ones ABI 1.0 documents; a program treats any other negative value as a failure too.
- **Handles**: the kinds (`KIND_*`, what `handle_info` returns in bits 32–63) and the rights (`R_*`, bits 0–31).
- **Constants**: open, mapping, seek, spawn, wait, channel and `wait_many` flags; the slots a program finds its handles in;
  `sysctl` operations; limits (`MSG_MAX`, `GETRANDOM_MAX`, …).
- **The loader's limits** (`lib = false` – not constants for programs, but promised): a program is loaded only in
  `[USER_LOAD_MIN, USER_LOAD_MAX]` = `[0x100000, 0xFFF80000000]` – below its largest heap (`BRK_MAX` above the image)
  and a 1 GiB gap before the `mmap` area (`MMAP_BASE`), so a program anywhere in the range never meets its heap,
  `mmap` or stack; a program file at most `MAX_PROGRAM_FILE` (8 MiB), all segments together at most `MAX_IMAGE`
  (64 MiB); at most `MAX_ARGS` (32) arguments and `MAX_ARG_BYTES` (4096) bytes of them; the stack at `USER_STACK_TOP`,
  16 KiB at the start, growing to `STACK_MAX` (8 MiB). The whole start contract (registers, stack layout, slots, exit
  codes) gets its own page, `STARTUP.md`, in stage D of v0.81.

Service protocols (the service manager, the network, time) get their own versions in stage D (`SERVICES.md`).

## The program library and the ABI note

Every program links to **`libdeso`** (`sdk/libdeso`, one crate): modules `sys` (the raw system call, start and end,
processes, memory, keys, the heap, output), `errors`, `handles`, `fs`, `chan`, `svc`, `net`, `time`, `dev`, and
`abi` – the constants, generated from `abi/abi.toml`; everything is also at the crate root (`deso::open`,
`deso::ERROR_NOT_FOUND`). The library defines no constant of its own (the host test refuses one). `unstable`
(`--cfg feature="unstable"`) promises nothing and is empty in 1.0.

The library puts **an ABI note** into every program, and `sdk/libdeso/link.ld` gives it its own `PT_NOTE` header (in
the read-only segment; `strip` keeps it):

| Field | Value |
|---|---|
| `namesz`, `descsz`, `type` | 5, 8, 1 (`NT_DESO_ABI`) – little-endian u32 |
| name | `DeSo\0` + 3 bytes of padding |
| description | u16 major, u16 minor, u32 flags (0 in 1.0) |

The kernel reads it from the program headers alone, before anything is mapped:

| The program has | Result |
|---|---|
| no `DeSo` note of type 1 | a program from before ABI 1.0 – runs as 1.0 |
| exactly one valid note, the same major, minor ≤ the system's | runs |
| a newer minor / another major | refused: `ERROR_ABI`, "needs DeSo OS ABI 1.3, this system 1.0" |
| flags ≠ 0 | refused (`ERROR_ABI`) |
| the note twice (also in two `PT_NOTE`s) | refused (`ERROR_ABI`) |
| a damaged note – ours or another owner's: a length past its `PT_NOTE`, bytes left over, our note with `descsz` ≠ 8 | refused (`ERROR_ABI`) |
| a `PT_NOTE` outside the file, with an overflowing offset + size, misaligned, over 4 KiB, on the ELF or program headers, overlapping another `PT_NOTE`; more than 4 of them | refused (`ERROR_ABI`) |

A parse error is never "no note". Notes of other owners (a GNU build-id) are skipped but checked the same way; the
order of headers and sections in the file does not matter. The loader also refuses overlapping `PT_LOAD` segments.
`ver` shows the ABI the system gives.

## The rules

1. **Within one major version only add.** Nothing is renumbered, changed or removed: not a number, an argument (its
   position, name or type), a right, a constant's type or value, whether a call names a path. A call that should go
   becomes `status = "deprecated"` and keeps working until the next major version.
2. **Every addition is a new minor version.** The new entry gets `since = "1.1"` (the next minor), `[abi] version`
   becomes `"1.1"`, and `python3 tools/abigen.py --new-lock` writes `abi/abi-1.1.lock`. The ABI version is not the
   DeSo OS version.
3. **Locks are never rewritten.** `--new-lock` refuses an existing lock and refuses to write a new one while an older
   lock fails – a lock update can never approve a break. Every lock is checked on every test run.
4. **Every stable entry is tested** or names where it is checked: `test_class` – `normal` (a known result), `stateful`
   (state set up and cleaned), `blocking` (a controlled event: another process, a time limit), `hardware` (a particular
   device – the test set that has it, e.g. USB TEST), `terminal` (ends the process – a child process) – and `test`,
   where.
5. `status = "unstable"` entries never go into a lock and promise nothing.

A broken rule is reported in plain words:

```
ABI BREAK: SYS_READ argument 1: lock 'buf:ptr_out', now 'len:len'
ABI BREAK: ERROR_INVALID_HANDLE value: lock '-9', now '-6'
ABI ADD WITHOUT VERSION: SEEK_DATA (since 1.0, but not in lock 1.0 - a new entry needs the next minor and its lock)
ABI 1.0 lock: FAILED (1 changes)
```

## Adding a system call (example)

1. The kernel: the call in `kernel/user/syscalls.rs` (a new number = the next free one), its row in
   `kernel/user/sysrights.rs`.
2. `abi/abi.toml`: a `[[syscall]]` with `since = "1.1"`, its arguments, errors, `handles` (the same as the row),
   `test_class` and `test`; `[abi] version = "1.1"`.
3. `python3 tools/abigen.py` (the generated files), `python3 tools/abigen.py --new-lock` (`abi/abi-1.1.lock`).
4. The library wrapper in the fitting module of `sdk/libdeso/src/` and a probe in `user/bin/abiprobe.rs`.
5. `tests/test.sh` – the host checks and ABI TEST must pass.

## Tests

`tests/test.sh` runs `python3 tools/abigen.py --test` on the host before it builds anything (`logs/test-abi.log`):

| | What |
|---|---|
| 1 locks | every `abi/abi-*.lock` is intact (each line's SHA-256 and the total) and matches the description – the human diff above on any difference |
| 2 description | `abi.toml` is complete: no holes in the numbers, every argument typed, handle arguments match the rights rows, errors are `ERROR_*` constants, every stable entry has a test, no value outside its type |
| 3 generator | two runs give the same bytes, and they are the files in the tree |
| 4 code = description | the syscall numbers in `kernel/user/syscalls.rs`; the argument registers each dispatch arm reads = the number of arguments; `libdeso` defines no constant by hand (only the generated `abi.rs`) and re-exports `abi` |
| 5 mutations | 19 changes, each must be caught: renumbered call, arguments swapped, argument type changed / added, right changed, error value changed, entry removed, added without a new minor, added as 1.1 without its lock, a hole in the numbers, an entry without a test, a lock line edited / removed, a generated file edited, a constant copied by hand into the library, a library constant not described, the library not re-exporting `abi`, the kernel renumbered, the kernel reading another argument |

ABI TEST in QEMU is the kernel's half: `1/3` the kernel's rights table (`sysinfo rights`) byte for byte, the table's size,
the reserved numbers without a row, and every syscall number and constant value through its kernel path; `2/3`
`/bin/abiprobe` – built on the generated constants, it calls every row of the rights table with a handle that does not
exist (`ERROR_INVALID_HANDLE`), uses a handle without rights (`ERROR_ACCESS_DENIED`), the reserved numbers
(`ERROR_NOT_IMPLEMENTED`), bad pointers (`ERROR_INVALID_ADDRESS`) and the ordinary calls with known results, and starts
a child that exits with 7; `3/3` the ABI note – every `/bin` program carries 1.0, 26 hand-built ELF files (every row
of the table above, the note at the end of the file and before the code, between foreign notes), overlapping
segments, and through `exec`: a 1.0 program and one without a note run, a 1.1 program is refused with `ERROR_ABI` and
the reason.

## Compared with other systems

| | What is stable | How it is guarded |
|---|---|---|
| Linux | the system calls ("we do not break user space") + glibc | review; per-architecture syscall tables; glibc symbol versions |
| Windows | the Win32 libraries; system call numbers change between builds | the libraries are the contract |
| Redox | relibc; the kernel's ABI still moves | – |
| **DeSo OS** | system calls, handles and rights, constants, loader limits (ABI 1.0) | one description, generated files, locks with SHA-256, mutations, the kernel and a program tested against the description |
