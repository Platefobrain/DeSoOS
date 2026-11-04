# DeSoOS documentation

The documentation of the whole system. Change history is in `../CHANGELOG.md`; each main code folder has its own
`README.md` (what it holds and where to start reading).

| Document | What it describes |
|---|---|
| `ARCHITECTURE.md` | How DeSoOS is built and how its parts work together: boot, memory, scheduler, syscalls and handles, IPC, user-space services and drivers, permissions (DCP), files, DeSoFS, network, USB, cryptography |
| `RELEASE.md` | One report per release: tests passed (QEMU TCG / KVM), real hardware, performance against the previous release, known problems; at the top – the current limitations of the system |
| `desofs/README.md` | DeSoFS – DeSoOS's own copy-on-write file system: what it does, the `desofs` commands, where the code and the tests are |
| `desofs/FORMAT.md` | The DeSoFS on-disk format 1, byte by byte (closed specification) |
