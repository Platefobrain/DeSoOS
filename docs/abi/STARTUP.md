# How a program starts – the start contract of ABI 1.0

What the kernel gives a program at its first instruction and what the end of a program means. This page is part of
ABI 1.0 ([README.md](README.md)): it changes only with a new major version. The numbers in it are the loader's
limits from `abi/abi.toml` (`lib = false` – promised, not constants for programs). STARTUP TEST checks it in QEMU
from the program's side – a `libdeso` program and one in plain machine code.

## The file

| Rule | ABI 1.0 |
|---|---|
| Format | ELF64, little-endian, x86-64 (`EM_X86_64`), `ET_EXEC` – a static program at fixed addresses |
| Interpreter | none: DeSo OS has no dynamic loader. A program must not have a `PT_INTERP` header – `deso-build.sh` refuses one; what the system does with one is not defined in 1.0 (the 1.0 loader does not read it and starts the program at `e_entry` without an interpreter) |
| Segments | `PT_LOAD`, W^X – never writable and executable at once (refused); pages without `PF_X` are not executable; segments do not overlap; `.bss` (`p_memsz > p_filesz`) is zeroed |
| Where | every segment inside `[USER_LOAD_MIN, USER_LOAD_MAX]` = `[0x100000, 0xFFF80000000]` – any address in it, not only the SDK's 0x400000; the first 1 MiB stays empty (a null pointer faults) |
| Entry | `e_entry` inside an executable segment |
| Sizes | the file at most `MAX_PROGRAM_FILE` = 8 MiB (exec reads it whole); all segments together at most `MAX_IMAGE` = 64 MiB |
| ABI note | the `DeSo` note in its own `PT_NOTE` ([README.md](README.md)); no note = a program from before ABI 1.0 = 1.0 |

## The first instruction

| | ABI 1.0 |
|---|---|
| `rip` | `e_entry` |
| `rsp` | 16-byte aligned (`rsp % 16 == 0`) and pointing at `argc` |
| Other registers | not defined – a program must not rely on their values |
| `rflags` | DF = 0 (string instructions go up); interrupts on |
| x87 / SSE | available; a clean state: FCW 0x37F, MXCSR 0x1F80 (all exceptions masked) |

The stack, from `rsp` up (8-byte words):

| At | Word |
|---|---|
| `rsp` | `argc` (1 or more – `argv[0]` is the program's name or path as the starter gave it) |
| `rsp + 8` | `argv[0]` … `argv[argc - 1]` – pointers to UTF-8 strings ending with 0 |
| | `NULL` – the end of `argv` |
| | `NULL` – the end of `envp`: ABI 1.0 gives no environment variables |
| | `AT_NULL` (0), 0 – the end of `auxv`: ABI 1.0 gives no auxiliary values |
| above | the strings themselves, below `USER_STACK_TOP` |

At most `MAX_ARGS` = 32 arguments (with `argv[0]`) and `MAX_ARG_BYTES` = 4096 bytes of them (each with its 0); more
and exec fails (`ERROR_TOO_MANY_ARGUMENTS`), the program never starts.

The stack's top is `USER_STACK_TOP` = 0x7FFF_FFFF_0000. 16 KiB are there at the start; below that the stack grows on
demand (a touch of the next page down) to `STACK_MAX` = 8 MiB; under it is an empty guard page – going past it is a
page fault. A program that needs more makes its own memory (`mmap`). The heap (`brk`) starts one page after the
image and grows to `BRK_MAX` = 1 GiB; `mmap` areas lie from `MMAP_BASE` up – none of them ever meets the image,
wherever it is in the load range.

## Handles

| Slot | What |
|---|---|
| 0, 1, 2 | input, output, errors – whatever the starter gave (the console, a file, a pipe) |
| 3 (`SVC`) | the service channel ([SERVICES.md](SERVICES.md)) **or nothing**: the shell gives its programs a channel to the service manager, a sandboxed program (`nofiles`) gets none; check with `handle_info(SVC)` |
| 4 and up | only what the starter handed over by name (`spawn_ex`'s map) – a program assumes nothing there |

The system programs' own slots (`HW_ROOT`, `SYSCTL`, `INPUT`, `BLK`, `SETTIME`, the shell's program channel) are
given by init to init's children only; they are listed in [SYSCALLS.md](SYSCALLS.md).

## The end

| How | The parent sees (`wait` status) |
|---|---|
| `SYS_EXIT(code)` | `code & 0xFF` – 0 = success |
| `main` returns n (`libdeso`) | the same as `exit(n)` |
| a panic (`libdeso`) | "panic: …" on slot 2, then `exit(101)` |
| killed (`kill`, Ctrl+C) | `STATUS_SIGNALED` (0x100) \| 9 |
| a CPU exception | `STATUS_SIGNALED` \| the vector: 3 `int3`, 6 invalid instruction, 7 x87/SSE unavailable, 13 general protection, 14 page fault, 19 SIMD exception, others by their number |
| a `syscall` returning to a non-canonical address | `STATUS_SIGNALED` \| 0xFF |

Everything a process holds – handles, memory, mapped devices, interrupts, DMA buffers – is released by the kernel
at its end, however it ended. Until its parent calls `wait` it stays a zombie (only its status); `wait` returns the
status only once the child is gone from every task list (`ps`, `dcp`) – also when it ended on another CPU a moment
before, as on Linux.

## With libdeso

`libdeso`'s `_start` keeps this contract for the program: `entry!(main)` gets `Args` (`args.get(i)`,
`args.argv()` – the `argv` array itself, `argc` is the word before it) and `main`'s result is the exit code.
A program without `libdeso` (assembler, another language) starts from the stack as above.

## Tests

STARTUP TEST (`tests/test.sh`, `[STARTUP TEST]`):

| Part | What |
|---|---|
| 1/3 | `/bin/starttest` (`libdeso`) checks its own start: `rsp % 16`, `argc`, `argv[]` (with UTF-8), `argv[argc]`, `envp`, `auxv`, the strings between the vectors and the stack top, slots 0–2, slot 3 a channel – and empty when none is given, 4–15 empty, the stack grown to 7 MiB; `main` returning 42 = exit code 42; a panic = "panic: …" + 101 |
| 2/3 | a program in plain machine code (no `libdeso`, no note) checks the stack and DF = 0 itself – loaded at 0x100000, at 0x400000 and ending exactly at `USER_LOAD_MAX`; one page below or past the range refused |
| 3/3 | 32 arguments and 4096 bytes start, 33 / 4097 are refused; a file of exactly 8 MiB starts, one byte more is refused |

ELF TEST checks the loader's refusals (magic, class, machine, `ET_DYN`, W^X, overlaps, ranges) and the page rights.

## Compared with other systems

| | Start stack | Interpreter | Environment |
|---|---|---|---|
| Linux | SysV: argc, argv, envp, auxv (many `AT_*`) | `PT_INTERP` (ld.so) | `envp` |
| Windows | no stack contract – the loader calls the entry; arguments from the PEB | the system loader resolves DLLs | the PEB |
| Redox | SysV-like, relibc's own start | `PT_INTERP` (relibc ld.so) | `envp` |
| **DeSo OS** | SysV: argc, argv, empty envp, auxv = `AT_NULL` only | none – static programs only | none in 1.0; handles in slots instead |
