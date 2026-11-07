# kernel/fs/desofs – DeSoFS code

The DeSoFS file system in the kernel. What DeSoFS is: `docs/desofs/README.md`; the on-disk format:
`docs/desofs/FORMAT.md`.

| File | Responsibility |
|---|---|
| `layout.rs` | on-disk structures (superblock, pointer, block header, root entries, nodes, directory blocks) and their checks – start here |
| `mod.rs` | reading a volume without writing: the walk over both superblocks, the mount decision (read-write / read-only / refused), `probe` (`desofs info`), snapshot usage |
| `vol.rs` | a mounted volume (`Volume`, the VFS `FileSystem`): copy-on-write transactions, the commit, files, directories, rename, snapshots |
| `format.rs` | `desofs format` |
| `check.rs` | `desofs check` and `desofs repair` |
| `cache.rs` | the block cache of a volume: key (address, checksum), Clock, one global memory budget |
| `restart.rs` | RESTART TEST – data on `/disk` across a real restart, `[RESULT-FS]` and `[RESULT-FS-PROF]` (where the time goes) |
| `test*.rs` | DESOFS TEST 1–32 (built only with `--cfg selftest`): `test.rs` reading and the step list, `test_write.rs` writing, `test_crash.rs` power loss, `test_check.rs` check / repair / mounting, `test_snap.rs` snapshots, `test_cache.rs` the block cache |

The `desofs` commands themselves live in the kernel shell (`kernel/shell.rs`, `cmd_desofs`, `cmd_snapshot`); the
user shell reaches them through the `sysctl` syscall.
