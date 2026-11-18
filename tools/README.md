# tools – host tools for real hardware

Python 3 only, no extra packages; they write only the target named on the command line.

| File | What |
|---|---|
| `mkusb.py` | the layout of a DeSoOS USB stick with a disk – called by `make-usb.sh --with-disk` (after its safety checks) and, for an image file, by `make-usb.sh --with-disk --image`, `tests/test.sh` and `tests/make-usb-test.sh`: GPT (protective MBR, both headers with CRC32), partition 1 = ESP (128 MiB, FAT32 `DESOOS` with `EFI/BOOT/BOOTX64.EFI`), partition 2 = "DeSoOS system" (`1A0E2E7D-DE32-4C13-9442-9FCB2649CA02`, the rest, at most 64 GiB) with an empty DeSoFS; the old tables cleared first, the GPT written last, then everything read back (caches dropped). A device is opened with `O_EXCL` and must still have the major:minor and size `make-usb.sh` asked about; 512-byte sectors only |
| `mkdesofs.py` | an empty DeSoFS volume (format 1, `docs/desofs/FORMAT.md` chapter 14) – the same bytes as the kernel's `desofs format` (DESOFS TEST compares them through `tests/mkdesofs.py --format`); random uuid and the current time unless given; writes only the blocks of the format in the kernel's order; refuses over 64 GiB or under 64 blocks |
