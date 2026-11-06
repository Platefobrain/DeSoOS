# tests – running the self-tests

The tests themselves are built into the kernel (`--cfg selftest`); this folder starts them in QEMU and holds the
helper scripts.

```
tests/test.sh              build --selftest and run all suites in QEMU (TCG); result PASS / FAIL
ACCEL=kvm tests/test.sh    the same with KVM
tests/test.sh --no-build   run only
LOOP=desofs:20 tests/test.sh   loop mode: one suite many times (smp lock tlb alloc nobkl files ipc rights crypto desofs)
tests/soak.sh              the soak test: everything at once, 1 hour with KVM (DURATION=8h, SEED=, ACCEL=tcg)
```

After a passing run QEMU starts a second time on the same test disk (RESTART TEST: DeSoFS data must survive a real
restart), then a short soak runs (2 minutes, `soak.sh`). The end of the output has the summary and the `[RESULT-…]`
lines (services, USB, rights, crypto, DeSoFS, soak) copied into `docs/RELEASE.md`. Logs: `logs/test.log`,
`logs/test-restart.log`, `logs/test-soak.log`. Exit code: 0 PASS, 1 FAIL, 2 timeout, 3 QEMU stopped otherwise.

`soak.sh` starts QEMU with the fw_cfg phase `soak <seconds> <seed>`: the boot tests are skipped and `/bin/soak`
(`user/bin/soak.rs`) runs its workers (files and snapshots on DeSoFS, services killed and checked, network, processes
and IPC) with a checkpoint every 30 minutes (leaks, `desofs check`). Log `logs/soak.log`; exit code 0 PASS, 1 FAIL, 2
HANG (no line for 5 minutes), 3 QEMU ended by itself, 4 too long.

| File | What |
|---|---|
| `test.sh` | the test run (above) |
| `soak.sh` | the long soak test (above) |
| `stress-qemu.sh` | the same stress test as on real hardware, in QEMU |
| `mkdesofs.py` | DeSoFS in Python: the reference image for the kernel tests, `--format` for a disk image |
| `mkfat32.py` | the FAT32 image of the emulated USB stick |
| `dns-stub.py`, `http-stub.py` | small DNS and HTTP servers on the host for the network tests and the soak |
| `qemu-hotplug.py` | plugs and unplugs USB devices during the test (QEMU monitor) |
