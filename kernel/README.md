# kernel – the DeSoOS kernel

A hybrid kernel: memory, scheduling, syscalls, handles and IPC, plus the drivers the system needs before user space
runs; other drivers and services (network, USB) are user-space programs in `user/bin/`. Design:
`docs/ARCHITECTURE.md`.

Start reading at `kernel.rs` – `kernel_main`, called by the boot loader (`boot/dsb.rs`) with `bootinfo.rs`, brings
the parts up in order and starts `/bin/init`.

| Path | What |
|---|---|
| `arch/x86_64/` | CPU setup: GDT / IDT, exceptions, interrupts (PIC, I/O APIC, LAPIC, MSI), SMP, `syscall.rs` (entry), TLB shootdown, FPU |
| `memory/` | frames, page tables, the kernel heap, demand paging |
| `sched/` | the scheduler, the Big Kernel Lock, spin locks and sleeping locks (lock order in `spin.rs`) |
| `user/` | processes and ring 3: `syscalls.rs` (every syscall), `sysrights.rs` (the rights table), `process.rs` (handles), `channel.rs` / `pipe.rs` / `shm.rs` (IPC), `vm.rs` (process memory), `dcp.rs` (permissions), `stress.rs` / `soak.rs` (starting the stress and soak tests, also from `DESOOS_AUTOSTRESS` / `DESOOS_AUTOSOAK` builds); `test_*.rs` – self-tests |
| `fs/` | the VFS (`mod.rs`), `ramfs.rs` (`/`), `fat32.rs`, `desofs/` (own README) |
| `drivers/` | framebuffer console, font (own license – see its header), PS/2 keyboard and mouse, PCI, NVMe, virtio-blk, serial, RTC |
| `block.rs`, `gpt.rs` | the block layer (disks, partitions, read-only disks, RAM disks) and GPT |
| `shell.rs` | the kernel shell (emergency shell, and the code behind `sysinfo` / `sysctl`, including `desofs`) |
| `initrd.rs` | the programs from `user/bin/` built into the kernel image |
| `selftest.rs` | self-test support (`--cfg selftest`, run by `tests/test.sh`) |
