#!/usr/bin/env python3
# DeSoFS formatter for the host (production; docs/desofs/FORMAT.md chapter 14) – an empty
# DeSoFS volume, the same bytes `desofs format` writes in the kernel (DESOFS TEST compares them
# byte for byte through tests/mkdesofs.py --format).
#
#   python3 tools/mkdesofs.py TARGET [--offset BYTES] [--blocks N] [--label TEXT]
#                                    [--uuid 32-HEX] [--time UNIX-SECONDS]
#
# TARGET is an image file or a block device; the volume starts --offset bytes into it (a
# partition, e.g. from tools/mkusb.py) and is --blocks 4 KiB blocks long (default: to the end
# of TARGET).  A random uuid and the current time unless given (tests give fixed ones).
#
# Writes ONLY the blocks of the format, in the kernel's order, each step flushed: blocks
# 0-15 zeroed (an older volume's superblocks gone first), the node block (16), the node-table
# pointer block (17), the root block (18), superblock B (2), then A (1).  Nothing else on
# TARGET is touched – an interrupted format leaves a volume that is not recognised or has one
# valid superblock with a complete tree.  Refuses a volume over 64 GiB (the format-1 limit of
# this implementation) or under 64 blocks: never cut to size, never a partial format.
import argparse
import hashlib
import os
import struct
import sys
import time as _time

BLOCK = 4096
RESERVED = 16
MIN_BLOCKS = 64
MAX_BLOCKS_V1 = (64 << 30) // BLOCK
HDR_SIZE = 64
NODE_SIZE = 256
TYPE_DIR = 2
ROOT_LIVE = 1


def _header(kind, level, count, gen, addr, uuid):
    h = kind + bytes([level, 0]) + struct.pack("<HQQ", count, gen, addr) + uuid
    return h + bytes(HDR_SIZE - len(h))


def _ptr(addr, birth, block):
    return struct.pack("<QQ", addr, birth) + hashlib.sha256(block).digest()


def format_blocks(total, uuid, now, label):
    """The blocks `desofs format` writes: [(block number, 4096 bytes)] in write order, with
    the points after which the kernel flushes (None)."""
    if len(uuid) != 16:
        raise ValueError("uuid must be 16 bytes")
    lab = label.encode()
    if len(lab) > 32 or b"\0" in lab:
        raise ValueError("label longer than 32 bytes")
    # Node block: node 1 (the root directory) in slot 1.
    nd = bytearray(BLOCK)
    nd[:HDR_SIZE] = _header(b"DSND", 0, 1, 1, 16, uuid)
    n1 = HDR_SIZE + NODE_SIZE
    struct.pack_into("<Q", nd, n1, 1)
    nd[n1 + 8] = TYPE_DIR
    struct.pack_into("<I", nd, n1 + 12, 1)
    struct.pack_into("<QQQQ", nd, n1 + 24, now, now, 1, 1)
    nd = bytes(nd)
    pt = bytearray(BLOCK)
    pt[:HDR_SIZE] = _header(b"DSPT", 1, 1, 1, 17, uuid)
    pt[HDR_SIZE:HDR_SIZE + 48] = _ptr(16, 1, nd)
    pt = bytes(pt)
    rt = bytearray(BLOCK)
    rt[:HDR_SIZE] = _header(b"DSRT", 0, 1, 1, 18, uuid)
    rt[HDR_SIZE:HDR_SIZE + 48] = _ptr(17, 1, pt)
    rt[HDR_SIZE + 48] = 1
    rt[HDR_SIZE + 49] = ROOT_LIVE
    struct.pack_into("<Q", rt, HDR_SIZE + 56, 2)
    rt = bytes(rt)
    sb = bytearray(BLOCK)
    sb[0:8] = b"DESOFS01"
    struct.pack_into("<II", sb, 8, 1, BLOCK)
    sb[16:32] = uuid
    struct.pack_into("<QQQQ", sb, 32, 1, total, 3, now)
    sb[80:128] = _ptr(18, 1, rt)
    sb[128:128 + len(lab)] = lab
    sb[BLOCK - 32:] = hashlib.sha256(bytes(sb[:BLOCK - 32])).digest()
    sb = bytes(sb)
    steps = [(b, bytes(BLOCK)) for b in range(RESERVED)]
    steps += [None, (16, nd), (17, pt), (18, rt), None, (2, sb), None, (1, sb), None]
    return steps


def check_size(blocks):
    if blocks < MIN_BLOCKS:
        raise ValueError("volume smaller than 256 KiB (64 blocks)")
    if blocks > MAX_BLOCKS_V1:
        raise ValueError("volume larger than 64 GiB - not supported by this DeSoFS version (nothing written)")


def format_fd(fd, offset, blocks, uuid, now, label):
    """Formats the volume at `offset` of an open file / device (os.open, write access)."""
    check_size(blocks)
    for step in format_blocks(blocks, uuid, now, label):
        if step is None:
            os.fsync(fd)
            continue
        n, data = step
        if os.pwrite(fd, data, offset + n * BLOCK) != BLOCK:
            raise OSError("short write at block %d" % n)


def format_image(path, blocks, uuid, now, label):
    """A new image file holding just the volume (tests/mkdesofs.py --format)."""
    with open(path, "wb") as f:
        f.truncate(blocks * BLOCK)
    fd = os.open(path, os.O_WRONLY)
    try:
        format_fd(fd, 0, blocks, uuid, now, label)
    finally:
        os.close(fd)


def target_size(fd):
    return os.lseek(fd, 0, os.SEEK_END)


def main():
    ap = argparse.ArgumentParser(description="An empty DeSoFS volume (format 1).")
    ap.add_argument("target")
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--blocks", type=int)
    ap.add_argument("--label", default="DESOOS")
    ap.add_argument("--uuid")
    ap.add_argument("--time", type=int)
    a = ap.parse_args()
    uuid = bytes.fromhex(a.uuid) if a.uuid else os.urandom(16)
    now = a.time if a.time is not None else int(_time.time())
    if a.offset < 0 or a.offset % 512:
        raise SystemExit("mkdesofs: --offset must be a multiple of 512")
    fd = os.open(a.target, os.O_RDWR)
    try:
        room = (target_size(fd) - a.offset) // BLOCK
        blocks = a.blocks if a.blocks is not None else room
        if blocks > room:
            raise SystemExit("mkdesofs: %d blocks do not fit (room for %d)" % (blocks, room))
        try:
            format_fd(fd, a.offset, blocks, uuid, now, a.label)
        except ValueError as e:
            raise SystemExit("mkdesofs: %s" % e)
    finally:
        os.close(fd)
    print("mkdesofs: %s: DeSoFS, %d blocks (%d MiB), uuid %s, label %r" % (a.target, blocks, blocks * BLOCK >> 20, uuid.hex(), a.label))


if __name__ == "__main__":
    main()
