#!/usr/bin/env python3
# Test USB stick image for ./test.sh (QEMU usb-storage, read-
# only) – no mtools and no sudo: an MBR with one FAT32 partition (type 0x0C, starting
# at sector 2048, as on a real USB stick), 512 B clusters, root directory:
#   DESOOS.TST  – marker (text),
#   DATA.BIN    – 4 MiB pattern: 32-bit word no. k = (k * 2654435761) mod 2^32
#                 (the kernel / usbtest check every byte and measure MB/s),
#   files from the arguments (8.3 name = file name in upper case).
#
#   python3 tests/mkfat32.py image.img [file ...]
import struct
import sys
import os

SECTOR = 512
SIZE_MB = 48
PART_START = 2048
RESERVED = 32
NUM_FATS = 2
LABEL = b"DESOOSTEST "


def pattern(size):
    out = bytearray(size)
    for k in range(size // 4):
        struct.pack_into("<I", out, k * 4, (k * 2654435761) & 0xFFFFFFFF)
    return bytes(out)


def short_name(name):
    base, _, ext = name.upper().partition(".")
    if not base or len(base) > 8 or len(ext) > 3:
        raise SystemExit("mkfat32: name not 8.3: " + name)
    return base.ljust(8).encode() + ext.ljust(3).encode()


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: mkfat32.py image.img [file ...]")
    image = sys.argv[1]
    files = [("DESOOS.TST", b"DeSoOS USB test disk - read-only\n"), ("DATA.BIN", pattern(4 * 1024 * 1024))]
    for path in sys.argv[2:]:
        with open(path, "rb") as f:
            files.append((os.path.basename(path), f.read()))

    total = SIZE_MB * 1024 * 1024 // SECTOR
    part = total - PART_START
    # FAT size: clusters = (part - reserved - FATs) / 1; 4 B per entry.
    fat = 1
    while True:
        clusters = part - RESERVED - NUM_FATS * fat
        need = ((clusters + 2) * 4 + SECTOR - 1) // SECTOR
        if need <= fat:
            break
        fat = need
    data_start = RESERVED + NUM_FATS * fat

    img = bytearray(total * SECTOR)

    # MBR: one FAT32 LBA partition (0x0C).
    mbr = bytearray(SECTOR)
    mbr[446:462] = struct.pack("<B3sB3sII", 0x80, b"\xfe\xff\xff", 0x0C, b"\xfe\xff\xff", PART_START, part)
    mbr[510:512] = b"\x55\xaa"
    img[0:SECTOR] = mbr

    # Clusters: 2 = root directory, then the files (contiguous).
    fat_entries = [0x0FFFFFF8, 0x0FFFFFFF, 0x0FFFFFFF]
    next_cluster = 3
    root = bytearray(SECTOR)
    root[0:11] = LABEL
    root[11] = 0x08  # volume label
    entries = 1
    for name, data in files:
        n = max(1, (len(data) + SECTOR - 1) // SECTOR) if data else 0
        first = next_cluster if n else 0
        for i in range(n):
            fat_entries.append(next_cluster + 1 if i + 1 < n else 0x0FFFFFFF)
            next_cluster += 1
        e = bytearray(32)
        e[0:11] = short_name(name)
        e[11] = 0x20
        struct.pack_into("<HHI", e, 20, first >> 16, 0, 0)
        struct.pack_into("<HI", e, 26, first & 0xFFFF, len(data))
        root[entries * 32:entries * 32 + 32] = e
        entries += 1
        if entries * 32 > SECTOR:
            raise SystemExit("mkfat32: too many files")
        off = (PART_START + data_start + (first - 2)) * SECTOR
        img[off:off + len(data)] = data
    if next_cluster - 2 > clusters:
        raise SystemExit("mkfat32: files too large")
    off = (PART_START + data_start) * SECTOR
    img[off:off + SECTOR] = root

    fat_bytes = bytearray(fat * SECTOR)
    for i, v in enumerate(fat_entries):
        struct.pack_into("<I", fat_bytes, i * 4, v)
    for c in range(NUM_FATS):
        off = (PART_START + RESERVED + c * fat) * SECTOR
        img[off:off + len(fat_bytes)] = fat_bytes

    # FAT32 boot sector (+ a copy in sector 6) and FSInfo (sector 1, copy in 7).
    bs = bytearray(SECTOR)
    bs[0:3] = b"\xeb\x58\x90"
    bs[3:11] = b"DESOOS  "
    struct.pack_into("<HBHBHHBHHHII", bs, 11, SECTOR, 1, RESERVED, NUM_FATS, 0, 0, 0xF8, 0, 32, 64, PART_START, part)
    struct.pack_into("<IHHIHH", bs, 36, fat, 0, 0, 2, 1, 6)
    bs[64] = 0x80
    bs[66] = 0x29
    struct.pack_into("<I", bs, 67, 0x20262013)
    bs[71:82] = LABEL
    bs[82:90] = b"FAT32   "
    bs[510:512] = b"\x55\xaa"
    fsinfo = bytearray(SECTOR)
    struct.pack_into("<I", fsinfo, 0, 0x41615252)
    struct.pack_into("<III", fsinfo, 484, 0x61417272, clusters - (next_cluster - 2), next_cluster)
    struct.pack_into("<I", fsinfo, 508, 0xAA550000)
    # The primary FSInfo is deliberately STALE („everything free” – like a USB stick
    # written by a system that does not update it); the copy in sector 7 has the
    # real number.  The kernel must count free clusters from the FAT (the test compares with the copy).
    stale = bytearray(fsinfo)
    struct.pack_into("<I", stale, 488, clusters)
    for s, data in ((0, bs), (1, stale), (6, bs), (7, fsinfo)):
        off = (PART_START + s) * SECTOR
        img[off:off + SECTOR] = data

    with open(image, "wb") as f:
        f.write(img)


if __name__ == "__main__":
    main()
