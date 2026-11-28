#!/usr/bin/env python3
# The layout of a DeSo OS USB stick with a disk – one code path for a real stick
# (make-usb.sh --with-disk /dev/sdX, after its safety checks) and for an image file
# (make-usb.sh --with-disk --image, tests/test.sh, tests/make-usb-test.sh):
#
#   GPT (protective MBR, primary and backup header with their CRC32 sums, random GUIDs)
#   partition 1  "EFI System" (C12A7328-F81F-11D2-BA4B-00A0C93EC93B), 128 MiB from 1 MiB,
#                FAT32 "DESO" with EFI/BOOT/BOOTX64.EFI – never written by DeSo OS
#   partition 2  "DeSo system" (1A0E2E7D-DE32-4C13-9442-9FCB2649CA02) – the rest, at most
#                64 GiB (the format-1 limit of this DeSoFS), at least 64 MiB; an empty DeSoFS
#                from tools/mkdesofs.py (random uuid, the current time)
#   the rest     unallocated (reported)
#
#   python3 tools/mkusb.py --image FILE --size-mib N --efi BOOTX64.EFI
#   python3 tools/mkusb.py --device /dev/sdX --expect-rdev MAJ:MIN --expect-bytes N
#                          --expect-serial S --efi ...
#   python3 tools/mkusb.py --update-esp FILE --efi BOOTX64.EFI    (tests: a new BOOTX64.EFI,
#                                                                  partition 2 untouched)
#   python3 tools/mkusb.py --verify FILE --efi BOOTX64.EFI
#
# Order of the writes (an interrupted run leaves no partition table pointing at half-written
# data): the old table areas zeroed (sectors 0-2047, the last 33) → the ESP → the DeSoFS
# volume (in the kernel's order, flushed) → the GPT and the protective MBR → flush.  Then a
# read-back check (caches dropped on a device): both GPT headers and their tables, the types
# and ranges, BOOTX64.EFI read back through the FAT equal to the built file, both DeSoFS
# superblocks.  Any mismatch – an error.  Only the regions above are written.
#
# --device: the device is opened with O_EXCL (Linux refuses while anything on it is mounted or
# held) and must still be the device make-usb.sh asked about – the same major:minor (of the
# open descriptor), size and serial number (the udev record of that major:minor – what lsblk
# shows; missing, empty or unclear = refused, never just the device number); 512-byte logical
# sectors only (what DeSo OS reads).
import argparse
import fcntl
import os
import stat
import struct
import sys
import time
import uuid as uuidlib
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mkdesofs  # noqa: E402

SECTOR = 512
ESP_TYPE = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
DESO_SYSTEM = "1A0E2E7D-DE32-4C13-9442-9FCB2649CA02"
ENTRIES = 128
ENTRY_SIZE = 128
TABLE_SECTORS = ENTRIES * ENTRY_SIZE // SECTOR  # 32
P1_START = 2048
ESP_SECTORS = 128 * 2048
P2_START = P1_START + ESP_SECTORS
P2_MAX = (64 << 30) // SECTOR
P2_MIN = (64 << 20) // SECTOR
ALIGN = 2048  # 1 MiB
MAX_DEVICE = 256 << 30

BLKSSZGET = 0x1268
BLKFLSBUF = 0x1261
BLKRRPART = 0x125F


class Fail(Exception):
    pass


# ---------------------------------------------------------------- layout

def layout(total_sectors):
    """(p1 first, p1 last, p2 first, p2 last, unallocated sectors) for a disk of this size."""
    last_usable = total_sectors - 1 - TABLE_SECTORS - 1
    room = last_usable - P2_START + 1
    p2_len = min(room, P2_MAX) // ALIGN * ALIGN
    if p2_len < P2_MIN:
        raise Fail("too small: %d MiB - needs at least %d MiB (ESP 128 MiB + DeSo system 64 MiB)"
                   % (total_sectors * SECTOR >> 20, (P2_START + P2_MIN + ALIGN) * SECTOR >> 20))
    return P1_START, P2_START - 1, P2_START, P2_START + p2_len - 1, room - p2_len


# ---------------------------------------------------------------- GPT

def guid_bytes(text):
    return uuidlib.UUID(text).bytes_le


def gpt_entry(type_guid, unique, first, last, name):
    e = guid_bytes(type_guid) + unique + struct.pack("<QQQ", first, last, 0)
    e += name.encode("utf-16-le").ljust(72, b"\0")
    return e


def gpt_header(my_lba, alt_lba, first_usable, last_usable, disk_guid, table_lba, table_crc):
    h = struct.pack("<8sIIIIQQQQ16sQIII", b"EFI PART", 0x00010000, 92, 0, 0, my_lba, alt_lba,
                    first_usable, last_usable, disk_guid, table_lba, ENTRIES, ENTRY_SIZE, table_crc)
    crc = zlib.crc32(h) & 0xFFFFFFFF
    return (h[:16] + struct.pack("<I", crc) + h[20:]).ljust(SECTOR, b"\0")


def gpt(total, p1, p2):
    """[(byte offset, bytes)] – protective MBR, primary header + table, backup table + header."""
    table = gpt_entry(ESP_TYPE, os.urandom(16), p1[0], p1[1], "EFI system partition")
    table += gpt_entry(DESO_SYSTEM, os.urandom(16), p2[0], p2[1], "DeSo system")
    table = table.ljust(ENTRIES * ENTRY_SIZE, b"\0")
    tcrc = zlib.crc32(table) & 0xFFFFFFFF
    disk_guid = os.urandom(16)
    first_usable = 2 + TABLE_SECTORS
    last_usable = total - 1 - TABLE_SECTORS - 1
    mbr = bytearray(SECTOR)
    mbr[446 + 1:446 + 4] = b"\x00\x02\x00"
    mbr[446 + 4] = 0xEE
    mbr[446 + 5:446 + 8] = b"\xff\xff\xff"
    mbr[446 + 8:446 + 12] = struct.pack("<I", 1)
    mbr[446 + 12:446 + 16] = struct.pack("<I", min(total - 1, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"
    return [
        (0, bytes(mbr) + gpt_header(1, total - 1, first_usable, last_usable, disk_guid, 2, tcrc) + table),
        ((total - 1 - TABLE_SECTORS) * SECTOR, table + gpt_header(total - 1, 1, first_usable, last_usable, disk_guid, total - 1 - TABLE_SECTORS, tcrc)),
    ]


def read_gpt(rd, total):
    """Both GPT headers and tables checked; [(type guid text, first, last)] of the used entries."""
    if rd(0, SECTOR)[510:512] != b"\x55\xaa" or rd(0, SECTOR)[446 + 4] != 0xEE:
        raise Fail("no protective MBR")
    result = None
    for lba in (1, total - 1):
        h = rd(lba * SECTOR, SECTOR)
        if h[:8] != b"EFI PART":
            raise Fail("GPT header at sector %d missing" % lba)
        hs = struct.unpack_from("<I", h, 12)[0]
        crc = struct.unpack_from("<I", h, 16)[0]
        if zlib.crc32(h[:16] + b"\0\0\0\0" + h[20:hs]) & 0xFFFFFFFF != crc:
            raise Fail("GPT header at sector %d: bad CRC32" % lba)
        my, alt = struct.unpack_from("<QQ", h, 24)
        tlba, n, esz, tcrc = struct.unpack_from("<QIII", h, 72)
        if my != lba or alt != (total - 1 if lba == 1 else 1) or n != ENTRIES or esz != ENTRY_SIZE:
            raise Fail("GPT header at sector %d: wrong fields" % lba)
        table = rd(tlba * SECTOR, n * esz)
        if zlib.crc32(table) & 0xFFFFFFFF != tcrc:
            raise Fail("GPT table of the header at sector %d: bad CRC32" % lba)
        parts = []
        for i in range(n):
            e = table[i * esz:(i + 1) * esz]
            if e[:16] != bytes(16):
                parts.append((str(uuidlib.UUID(bytes_le=e[:16])).upper(), *struct.unpack_from("<QQ", e, 32)))
        if result is not None and parts != result:
            raise Fail("primary and backup GPT differ")
        result = parts
    return result


# ---------------------------------------------------------------- FAT32 (the ESP)

def dos_time(t):
    lt = time.localtime(t)
    d = ((max(lt.tm_year, 1980) - 1980) << 9) | (lt.tm_mon << 5) | lt.tm_mday
    tm = (lt.tm_hour << 11) | (lt.tm_min << 5) | (lt.tm_sec // 2)
    return d, tm


def dir_entry(name11, attr, cluster, size, t):
    d, tm = dos_time(t)
    return struct.pack("<11sBBBHHHHHHHI", name11, attr, 0, 0, tm, d, d, cluster >> 16, tm, d, cluster & 0xFFFF, size)


def fat32_esp(efi, sectors, hidden, now):
    """A FAT32 file system of `sectors` 512-byte sectors holding EFI/BOOT/BOOTX64.EFI: the
    bytes from its start to the end of the last used cluster (the rest of the partition is
    free space and may hold anything)."""
    spc, reserved, nfats = 1, 32, 2
    fatsz = -(-(sectors - reserved) // ((256 * spc + nfats) // 2))
    clusters = (sectors - reserved - nfats * fatsz) // spc
    if clusters < 65525 or (clusters + 2) * 4 > fatsz * SECTOR:
        raise Fail("ESP geometry")
    n = max(1, -(-len(efi) // (spc * SECTOR)))
    root, efi_dir, boot_dir, file0 = 2, 3, 4, 5
    used = 3 + n
    if used > clusters:
        raise Fail("BOOTX64.EFI does not fit into the ESP")
    volid = struct.unpack("<I", os.urandom(4))[0]
    bs = bytearray(SECTOR)
    bs[0:3] = b"\xEB\x58\x90"
    bs[3:11] = b"MSWIN4.1"
    struct.pack_into("<HBHBHHBHHHII", bs, 11, SECTOR, spc, reserved, nfats, 0, 0, 0xF8, 0, 32, 64, hidden, sectors)
    struct.pack_into("<IHHIHH", bs, 36, fatsz, 0, 0, root, 1, 6)
    struct.pack_into("<BBBI11s8s", bs, 64, 0x80, 0, 0x29, volid, b"DESO       ", b"FAT32   ")
    bs[510:512] = b"\x55\xaa"
    fsinfo = bytearray(SECTOR)
    struct.pack_into("<I", fsinfo, 0, 0x41615252)
    struct.pack_into("<III", fsinfo, 484, 0x61417272, clusters - used, file0 + n)
    struct.pack_into("<I", fsinfo, 508, 0xAA550000)
    fat = bytearray((2 + used) * 4)
    struct.pack_into("<II", fat, 0, 0x0FFFFFF8, 0x0FFFFFFF)
    for c in (root, efi_dir, boot_dir):
        struct.pack_into("<I", fat, c * 4, 0x0FFFFFFF)
    for i in range(n):
        struct.pack_into("<I", fat, (file0 + i) * 4, 0x0FFFFFFF if i == n - 1 else file0 + i + 1)
    cl = spc * SECTOR

    def dir_cluster(entries):
        return b"".join(entries).ljust(cl, b"\0")

    data = dir_cluster([dir_entry(b"DESO       ", 0x08, 0, 0, now), dir_entry(b"EFI        ", 0x10, efi_dir, 0, now)])
    data += dir_cluster([dir_entry(b".          ", 0x10, efi_dir, 0, now), dir_entry(b"..         ", 0x10, 0, 0, now), dir_entry(b"BOOT       ", 0x10, boot_dir, 0, now)])
    data += dir_cluster([dir_entry(b".          ", 0x10, boot_dir, 0, now), dir_entry(b"..         ", 0x10, efi_dir, 0, now), dir_entry(b"BOOTX64 EFI", 0x20, file0, len(efi), now)])
    data += efi.ljust(n * cl, b"\0")
    fat_area = bytes(fat).ljust(fatsz * SECTOR, b"\0")
    res = bytearray(reserved * SECTOR)
    res[0:SECTOR] = bs
    res[SECTOR:2 * SECTOR] = fsinfo
    res[6 * SECTOR:7 * SECTOR] = bs
    res[7 * SECTOR:8 * SECTOR] = fsinfo
    return bytes(res) + fat_area * nfats + data


def fat32_read_file(rd, base, path):
    """Reads `path` (8.3 names, e.g. EFI/BOOT/BOOTX64.EFI) from the FAT32 at byte `base`."""
    bs = rd(base, SECTOR)
    if bs[510:512] != b"\x55\xaa" or bs[82:90] != b"FAT32   ":
        raise Fail("ESP: no FAT32 boot sector")
    bps, spc, reserved, nfats = struct.unpack_from("<HBHB", bs, 11)
    fatsz, root = struct.unpack_from("<I", bs, 36)[0], struct.unpack_from("<I", bs, 44)[0]
    if bps != SECTOR or spc == 0:
        raise Fail("ESP: bad geometry")
    fat0 = base + reserved * SECTOR
    data0 = fat0 + nfats * fatsz * SECTOR
    cl = spc * SECTOR

    def chain(c):
        out = []
        while 2 <= c < 0x0FFFFFF8:
            out.append(c)
            if len(out) > 1 << 20:
                raise Fail("ESP: cluster loop")
            c = struct.unpack("<I", rd(fat0 + c * 4, 4))[0] & 0x0FFFFFFF
        return out

    def read_chain(c):
        return b"".join(rd(data0 + (x - 2) * cl, cl) for x in chain(c))

    cur = root
    names = path.upper().split("/")
    for k, name in enumerate(names):
        base_, _, ext = name.partition(".")
        want = base_.ljust(8).encode() + ext.ljust(3).encode()
        d = read_chain(cur)
        hit = None
        for i in range(0, len(d), 32):
            e = d[i:i + 32]
            if e[0] == 0:
                break
            if e[0] == 0xE5 or e[11] == 0x0F:
                continue
            if e[:11] == want:
                hit = e
                break
        if hit is None:
            raise Fail("ESP: %s not found" % "/".join(names[:k + 1]))
        cur = (struct.unpack_from("<H", hit, 20)[0] << 16) | struct.unpack_from("<H", hit, 26)[0]
        if k == len(names) - 1:
            size = struct.unpack_from("<I", hit, 28)[0]
            return read_chain(cur)[:size]
    raise Fail("ESP: empty path")


# ---------------------------------------------------------------- target access

class Target:
    def __init__(self, fd, size, device):
        self.fd, self.size, self.device = fd, size, device

    def write(self, off, data):
        if off < 0 or off + len(data) > self.size:
            raise Fail("write outside the target")
        done = 0
        while done < len(data):
            k = os.pwrite(self.fd, data[done:done + (8 << 20)], off + done)
            if k <= 0:
                raise Fail("short write at byte %d" % (off + done))
            done += k

    def read(self, off, n):
        b = os.pread(self.fd, n, off)
        if len(b) != n:
            raise Fail("short read at byte %d" % off)
        return b

    def flush(self):
        os.fsync(self.fd)

    def drop_cache(self):
        if self.device:
            fcntl.ioctl(self.fd, BLKFLSBUF, 0)


UDEV_DATA = "/run/udev/data"


def udev_serial(major, minor, udev_dir=UDEV_DATA):
    """The serial number of block device major:minor, as lsblk shows it: udev's
    ID_SCSI_SERIAL, else ID_SERIAL_SHORT, from the udev record of THAT device number (never
    looked up by a /dev name).  Missing record, missing or empty field, or a field given
    twice – Fail (no fallback to the device number alone)."""
    rec = os.path.join(udev_dir, "b%d:%d" % (major, minor))
    try:
        with open(rec, "r", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        raise Fail("no udev record for device %d:%d (%s) - its serial number is unknown; nothing written" % (major, minor, rec))
    for key in ("ID_SCSI_SERIAL", "ID_SERIAL_SHORT"):
        vals = [l[len("E:" + key + "="):] for l in lines if l.startswith("E:" + key + "=")]
        if len(vals) > 1:
            raise Fail("device %d:%d: %s given %d times - serial number unclear; nothing written" % (major, minor, key, len(vals)))
        if vals:
            if not vals[0].strip():
                raise Fail("device %d:%d: empty %s - serial number unknown; nothing written" % (major, minor, key))
            return vals[0].strip()
    raise Fail("device %d:%d has no serial number in udev - refusing (the device cannot be told apart); nothing written" % (major, minor))


def check_identity(st_rdev, size, udev_dir, expect_rdev, expect_bytes, expect_serial):
    """The opened device is the one make-usb.sh asked about: the same major:minor (from the
    OPEN descriptor), size and serial number (udev record of that major:minor).  Fail
    otherwise – before anything is written."""
    major, minor = os.major(st_rdev), os.minor(st_rdev)
    if "%d:%d" % (major, minor) != expect_rdev:
        raise Fail("the device is now %d:%d, not %s - it changed; nothing written" % (major, minor, expect_rdev))
    if size != expect_bytes:
        raise Fail("the device has %d bytes, not %d - it changed; nothing written" % (size, expect_bytes))
    if not expect_serial:
        raise Fail("no expected serial number given - refusing")
    serial = udev_serial(major, minor, udev_dir)
    if serial != expect_serial:
        raise Fail("the device's serial number is now %r, not %r - another stick; nothing written" % (serial, expect_serial))


def open_device(path, rdev, nbytes, serial):
    # 1. Exclusively (Linux refuses while anything on it is mounted or held), 2. what the
    # descriptor really is, 3. major:minor + size + serial against the expected, 4. only then
    # any write.
    try:
        fd = os.open(path, os.O_RDWR | os.O_EXCL | os.O_CLOEXEC)
    except OSError as e:
        raise Fail("cannot open %s exclusively (%s) - something on it is mounted or in use" % (path, e.strerror))
    st = os.fstat(fd)
    if not stat.S_ISBLK(st.st_mode):
        raise Fail("%s is not a block device" % path)
    size = os.lseek(fd, 0, os.SEEK_END)
    check_identity(st.st_rdev, size, UDEV_DATA, rdev, nbytes, serial)
    ssz = struct.unpack("<I", fcntl.ioctl(fd, BLKSSZGET, b"\0" * 4))[0]
    if ssz != SECTOR:
        raise Fail("%s has %d-byte sectors - DeSo OS reads 512-byte sectors only" % (path, ssz))
    if size > MAX_DEVICE:
        raise Fail("%s is larger than 256 GiB" % path)
    return Target(fd, size, True)


def open_image(path, mib, create):
    if create:
        if mib * (1 << 20) > MAX_DEVICE:
            raise Fail("image larger than 256 GiB")
        if os.path.exists(path) and not stat.S_ISREG(os.stat(path).st_mode):
            raise Fail("%s exists and is not a regular file" % path)
        with open(path, "wb") as f:
            f.truncate(mib << 20)
    fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        raise Fail("%s is not a regular file" % path)
    size = os.lseek(fd, 0, os.SEEK_END)
    if size % SECTOR:
        raise Fail("image size not a multiple of 512")
    return Target(fd, size, False)


# ---------------------------------------------------------------- the work

def build(t, efi, label):
    total = t.size // SECTOR
    p1a, p1b, p2a, p2b, rest = layout(total)
    now = int(time.time())
    esp = fat32_esp(efi, p1b - p1a + 1, p1a, now)
    # 1. Old partition tables and signatures in the gap gone first.
    t.write(0, bytes(P1_START * SECTOR))
    t.write((total - 1 - TABLE_SECTORS) * SECTOR, bytes((TABLE_SECTORS + 1) * SECTOR))
    t.flush()
    # 2. The ESP, 3. the DeSoFS volume (flushed in the kernel's order).
    t.write(p1a * SECTOR, esp)
    t.flush()
    blocks = (p2b - p2a + 1) * SECTOR // mkdesofs.BLOCK
    mkdesofs.format_fd(t.fd, p2a * SECTOR, blocks, os.urandom(16), now, label)
    # 4. The partition table last.
    for off, data in gpt(total, (p1a, p1b), (p2a, p2b)):
        t.write(off, data)
    t.flush()
    return (p1a, p1b, p2a, p2b, rest, blocks)


def verify(t, efi):
    t.drop_cache()
    total = t.size // SECTOR
    parts = read_gpt(t.read, total)
    p1a, p1b, p2a, p2b, _ = layout(total)
    want = [(ESP_TYPE, p1a, p1b), (DESO_SYSTEM, p2a, p2b)]
    if parts != want:
        raise Fail("partitions %s, expected %s" % (parts, want))
    got = fat32_read_file(t.read, p1a * SECTOR, "EFI/BOOT/BOOTX64.EFI")
    if got != efi:
        raise Fail("BOOTX64.EFI on the ESP differs from the built file (faulty stick?)")
    blocks = (p2b - p2a + 1) * SECTOR // mkdesofs.BLOCK
    import hashlib
    for slot in (1, 2):
        sb = t.read(p2a * SECTOR + slot * mkdesofs.BLOCK, mkdesofs.BLOCK)
        if sb[:8] != b"DESOFS01" or hashlib.sha256(sb[:-32]).digest() != sb[-32:] or struct.unpack_from("<Q", sb, 40)[0] != blocks:
            raise Fail("DeSoFS superblock %s wrong" % "AB"[slot - 1])
    return blocks


def update_esp(t, efi):
    """Tests (tests/make-usb-test.sh): the ESP rebuilt with a new BOOTX64.EFI – what
    `make-usb.sh /media/.../DESO` does on a mounted stick; partition 2 is not touched."""
    total = t.size // SECTOR
    parts = read_gpt(t.read, total)
    if len(parts) != 2 or parts[0][0] != ESP_TYPE:
        raise Fail("not a DeSo OS stick image")
    _, a, b = parts[0]
    t.write(a * SECTOR, fat32_esp(efi, b - a + 1, a, int(time.time())))
    t.flush()


def main():
    ap = argparse.ArgumentParser(description="DeSo OS USB stick with a disk: GPT, ESP, DeSoFS.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--image")
    g.add_argument("--device")
    g.add_argument("--update-esp")
    g.add_argument("--verify")
    ap.add_argument("--size-mib", type=int)
    ap.add_argument("--expect-rdev")
    ap.add_argument("--expect-bytes", type=int)
    ap.add_argument("--expect-serial")
    ap.add_argument("--efi", required=True)
    ap.add_argument("--label", default="DESO")
    a = ap.parse_args()
    try:
        with open(a.efi, "rb") as f:
            efi = f.read()
        if not efi:
            raise Fail("%s is empty" % a.efi)
        if a.image:
            if not a.size_mib:
                raise Fail("--image needs --size-mib")
            t = open_image(a.image, a.size_mib, True)
        elif a.device:
            if not a.expect_rdev or a.expect_bytes is None or not a.expect_serial:
                raise Fail("--device needs --expect-rdev, --expect-bytes and --expect-serial")
            t = open_device(a.device, a.expect_rdev, a.expect_bytes, a.expect_serial)
        elif a.update_esp:
            t = open_image(a.update_esp, 0, False)
            update_esp(t, efi)
            verify(t, efi)
            print("mkusb: %s: ESP updated, read back OK" % a.update_esp)
            return
        else:
            t = open_image(a.verify, 0, False)
            blocks = verify(t, efi)
            print("mkusb: %s: GPT, ESP (BOOTX64.EFI), DeSoFS (%d blocks) OK" % (a.verify, blocks))
            return
        p1a, p1b, p2a, p2b, rest, blocks = build(t, efi, a.label)
        verify(t, efi)
        if t.device:
            try:
                fcntl.ioctl(t.fd, BLKRRPART)
            except OSError:
                pass
        os.close(t.fd)
        print("mkusb: partition 1 ESP %d MiB (BOOTX64.EFI %d B), partition 2 DeSo system %d MiB (DeSoFS %d blocks)"
              % ((p1b - p1a + 1) * SECTOR >> 20, len(efi), (p2b - p2a + 1) * SECTOR >> 20, blocks))
        if rest >= ALIGN:
            print("mkusb: %d MiB left unallocated (a DeSoFS volume of this version holds at most 64 GiB)" % (rest * SECTOR >> 20))
        print("mkusb: read back OK (GPT, BOOTX64.EFI, DeSoFS superblocks)")
    except (Fail, ValueError) as e:
        raise SystemExit("mkusb: ERROR: %s" % e)


if __name__ == "__main__":
    main()
