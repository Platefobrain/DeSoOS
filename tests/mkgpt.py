#!/usr/bin/env python3
# A GPT image for the writable test USB stick (USB WRITE TEST): partition 1 "EFI System",
# partition 2 "DeSoOS system" (type 1A0E2E7D-DE32-4C13-9442-9FCB2649CA02 – the only
# partition type DeSoOS ever writes on a USB disk), primary and backup GPT with their CRC32
# sums, 512-byte sectors.
#
#   python3 tests/mkgpt.py IMAGE SIZE_MIB [ESP_MIB]
#
# The ESP is filled with a marker pattern (every sector: "DESOOS-ESP", its LBA) so the test
# can check that nothing in it changed; partition 2 is left zero.  Never writes anything
# but the named image file.
import struct
import sys
import uuid
import zlib

SECTOR = 512
ESP = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
DESOOS_SYSTEM = "1A0E2E7D-DE32-4C13-9442-9FCB2649CA02"
ENTRIES = 128
ENTRY_SIZE = 128


def guid_bytes(text):
    return uuid.UUID(text).bytes_le


def entry(type_guid, unique, first, last, name):
    e = guid_bytes(type_guid) + unique + struct.pack("<QQQ", first, last, 0)
    e += name.encode("utf-16-le").ljust(72, b"\0")
    assert len(e) == ENTRY_SIZE
    return e


def header(my_lba, alt_lba, first_usable, last_usable, disk_guid, table_lba, table_crc):
    h = struct.pack("<8sIIIIQQQQ16sQIII", b"EFI PART", 0x00010000, 92, 0, 0, my_lba, alt_lba, first_usable, last_usable, disk_guid, table_lba, ENTRIES, ENTRY_SIZE, table_crc)
    crc = zlib.crc32(h) & 0xFFFFFFFF
    h = h[:16] + struct.pack("<I", crc) + h[20:]
    return h.ljust(SECTOR, b"\0")


def esp_sector(lba):
    return (b"DESOOS-ESP" + struct.pack("<Q", lba)).ljust(SECTOR, b"\xe5")


def main():
    if len(sys.argv) not in (3, 4):
        raise SystemExit("usage: mkgpt.py IMAGE SIZE_MIB [ESP_MIB]")
    path, mib = sys.argv[1], int(sys.argv[2])
    esp_mib = int(sys.argv[3]) if len(sys.argv) == 4 else 8
    total = mib * 1024 * 1024 // SECTOR
    table_sectors = ENTRIES * ENTRY_SIZE // SECTOR
    first_usable = 2 + table_sectors
    last_usable = total - 1 - table_sectors - 1
    p1 = (2048, 2048 + esp_mib * 2048 - 1)
    p2 = (p1[1] + 1, last_usable)
    if p2[0] >= p2[1]:
        raise SystemExit("image too small")
    table = entry(ESP, bytes([0x51] * 16), p1[0], p1[1], "EFI system partition")
    table += entry(DESOOS_SYSTEM, bytes([0x52] * 16), p2[0], p2[1], "DeSoOS system")
    table = table.ljust(ENTRIES * ENTRY_SIZE, b"\0")
    tcrc = zlib.crc32(table) & 0xFFFFFFFF
    disk_guid = bytes([0x5D] * 16)
    mbr = bytearray(SECTOR)
    mbr[446 + 4] = 0xEE
    mbr[446 + 8:446 + 12] = struct.pack("<I", 1)
    mbr[446 + 12:446 + 16] = struct.pack("<I", min(total - 1, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"
    with open(path, "wb") as f:
        f.truncate(total * SECTOR)
        f.seek(0)
        f.write(bytes(mbr))
        f.write(header(1, total - 1, first_usable, last_usable, disk_guid, 2, tcrc))
        f.write(table)
        f.seek(p1[0] * SECTOR)
        f.write(b"".join(esp_sector(lba) for lba in range(p1[0], p1[1] + 1)))
        f.seek((total - 1 - table_sectors) * SECTOR)
        f.write(table)
        f.write(header(total - 1, 1, first_usable, last_usable, disk_guid, total - 1 - table_sectors, tcrc))
    print("mkgpt: %s %d MiB: ESP %d-%d, DeSoOS system %d-%d" % (path, mib, p1[0], p1[1], p2[0], p2[1]))


if __name__ == "__main__":
    main()
