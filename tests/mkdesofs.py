#!/usr/bin/env python3
# DeSoFS reference image (format 1, docs/desofs/FORMAT.md) – an independent
# implementation of the on-disk format, written from the specification, used by
# DESOFS TEST: the kernel must accept exactly this image, and the test then breaks
# copies of it in every way the specification forbids.
#
#   python3 tests/mkdesofs.py image.img                  reference image (below)
#   python3 tests/mkdesofs.py --format BLOCKS image.img  what `desofs format` writes
#                                                         (chapter 14; fixed uuid / time)
#
# Contents (fixed uuid and times, so the image is the same on every build):
#   superblock A (block 1): generation 4 -> tree v4
#   superblock B (block 2): generation 5 -> tree v5 (hello.txt changed) + snapshot "before-v5" = tree v4
#   /hello.txt   13 / 16 bytes (v4 / v5), depth 0
#   /big.bin     100 KiB = 25 blocks, depth 1, blocks 5-9 a hole; its DSPT is shared by v4 and v5
#   /sub/a.txt   4 bytes
# Never writes anything but the named image file.
import hashlib
import struct
import sys

BLOCK = 4096
TOTAL = 128
UUID = bytes(range(0x10, 0x20))
LABEL = b"DESOFS-TEST"
TIME = 1_700_000_000
FANOUT = 84
NODES_PER_BLOCK = 15

img = bytearray(TOTAL * BLOCK)
next_free = 16


def alloc():
    global next_free
    n = next_free
    next_free += 1
    assert n < TOTAL
    return n


def put(n, data):
    assert len(data) == BLOCK
    img[n * BLOCK:(n + 1) * BLOCK] = data


def get(n):
    return bytes(img[n * BLOCK:(n + 1) * BLOCK])


def ptr(addr, birth):
    """48-byte pointer: addr, birth, SHA-256 of the block (already written)."""
    return struct.pack("<QQ", addr, birth) + hashlib.sha256(get(addr)).digest()


EMPTY = bytes(48)


def header(kind, level, count, gen, addr):
    h = kind + bytes([level, 0]) + struct.pack("<HQQ", count, gen, addr) + UUID
    return h + bytes(64 - len(h))


def data_block(content):
    b = bytearray(BLOCK)
    b[:len(content)] = content
    n = alloc()
    put(n, bytes(b))
    return n


def dspt(level, ptrs, gen):
    n = alloc()
    count = sum(1 for p in ptrs if p != EMPTY)
    body = b"".join(ptrs) + EMPTY * (FANOUT - len(ptrs))
    put(n, header(b"DSPT", level, count, gen, n) + body)
    return n


def node(number, typ, depth, size, parent, node_gen, data):
    raw = struct.pack("<QBBHIQQQQQ", number, typ, depth, 0, 1, size, TIME, TIME, parent, node_gen)
    raw += data + bytes(192 - len(data))
    raw += bytes(8)
    assert len(raw) == 256
    return raw


def dsnd(nodes, gen):
    """nodes: dict slot -> 256 B (one DSND block = nodes 0..14)."""
    n = alloc()
    body = b"".join(nodes.get(i, bytes(256)) for i in range(NODES_PER_BLOCK))
    put(n, header(b"DSND", 0, len(nodes), gen, n) + body + bytes(BLOCK - 64 - len(body)))
    return n


def dir_block(entries):
    """entries: list of (node, type, name). The last entry runs to the end of the block."""
    b = bytearray()
    for i, (nd, typ, name) in enumerate(entries):
        name = name.encode()
        rec = (12 + len(name) + 7) // 8 * 8
        if i == len(entries) - 1:
            rec = BLOCK - len(b)
        e = struct.pack("<QBBH", nd, typ, len(name), rec) + name
        b += e + bytes(rec - len(e))
    assert len(b) == BLOCK
    n = alloc()
    put(n, bytes(b))
    return n


def root_block(entries, gen):
    """entries: list of (kind, nodes_ptr, depth, next_node, created_gen, name)."""
    n = alloc()
    body = b""
    for kind, nodes_ptr, depth, next_node, created_gen, name in entries:
        e = nodes_ptr + bytes([depth, kind]) + bytes(6) + struct.pack("<QQ", next_node, created_gen)
        e += name + bytes(24 - len(name))
        assert len(e) == 96
        body += e
    body += bytes(96 * (32 - len(entries)))
    put(n, header(b"DSRT", 0, len(entries), gen, n) + body + bytes(BLOCK - 64 - len(body)))
    return n


def superblock(slot, gen, root_ptr, used):
    sb = b"DESOFS01" + struct.pack("<II", 1, BLOCK) + UUID
    sb += struct.pack("<QQQQ", gen, TOTAL, used, TIME + gen)
    sb += struct.pack("<IIII", 0, 0, 0, 0)
    sb += root_ptr + LABEL + bytes(32 - len(LABEL))
    sb += bytes(4064 - len(sb))
    put(slot, sb + hashlib.sha256(sb).digest())


def reach(addr, seen):
    """Distinct blocks reachable from a metadata block (to fill used_blocks)."""
    if addr in seen:
        return
    seen.add(addr)
    b = get(addr)
    kind = b[:4]
    if kind == b"DSRT":
        for i in range(32):
            e = b[64 + 96 * i:64 + 96 * (i + 1)]
            if e[49]:
                reach(struct.unpack_from("<Q", e, 0)[0], seen)
    elif kind == b"DSPT":
        level = b[4]
        for i in range(FANOUT):
            a = struct.unpack_from("<Q", b, 64 + 48 * i)[0]
            if not a:
                continue
            if level == 1 and get(a)[:4] not in (b"DSND", b"DSPT"):
                seen.add(a)
            else:
                reach(a, seen)
    elif kind == b"DSND":
        for i in range(NODES_PER_BLOCK):
            nd = b[64 + 256 * i:64 + 256 * (i + 1)]
            if not nd[8]:
                continue
            depth = nd[9]
            data = nd[56:248]
            if depth == 0:
                for k in range(4):
                    a = struct.unpack_from("<Q", data, 48 * k)[0]
                    if a:
                        seen.add(a)
            else:
                a = struct.unpack_from("<Q", data, 0)[0]
                if a:
                    reach(a, seen)


def pattern(k):
    return bytes(((k * 31 + i * 7) & 0xFF) for i in range(BLOCK))


FMT_UUID = bytes(range(0xA0, 0xB0))
FMT_LABEL = b"DESOFS-FMT"


def format_image(blocks, path):
    """docs/desofs/FORMAT.md chapter 14: the state right after `desofs format`."""
    global img, TOTAL, next_free, UUID
    TOTAL = blocks
    img = bytearray(TOTAL * BLOCK)
    next_free = 16
    UUID = FMT_UUID
    n1 = node(1, 2, 0, 0, 1, 1, b"")
    nd = dsnd({1: n1}, 1)           # block 16
    nt = dspt(1, [ptr(nd, 1)], 1)   # block 17
    rt = root_block([(1, ptr(nt, 1), 1, 2, 0, b"")], 1)  # block 18
    sb = b"DESOFS01" + struct.pack("<II", 1, BLOCK) + UUID
    sb += struct.pack("<QQQQ", 1, TOTAL, 3, TIME)
    sb += struct.pack("<IIII", 0, 0, 0, 0)
    sb += ptr(rt, 1) + FMT_LABEL + bytes(32 - len(FMT_LABEL))
    sb += bytes(4064 - len(sb))
    sb += hashlib.sha256(sb).digest()
    put(1, sb)
    put(2, sb)
    with open(path, "wb") as f:
        f.write(img)


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--format":
        format_image(int(sys.argv[2]), sys.argv[3])
        return
    if len(sys.argv) != 2:
        raise SystemExit("usage: mkdesofs.py image.img | --format BLOCKS image.img")

    # ---- tree v4 (generation 4) ----
    G4 = 4
    hello4 = data_block(b"Hello DeSoFS\n")
    a_txt = data_block(b"abc\n")
    big_ptrs = []
    for k in range(25):
        if 5 <= k <= 9:
            big_ptrs.append(EMPTY)  # a hole
        else:
            big_ptrs.append(ptr(data_block(pattern(k)), G4))
    big_tree = dspt(1, big_ptrs, G4)
    sub_dir = dir_block([(5, 1, "a.txt")])
    root_dir = dir_block([(2, 1, "hello.txt"), (3, 1, "big.bin"), (4, 2, "sub")])

    def nodes(hello_block, hello_size, hello_gen):
        return {
            1: node(1, 2, 0, BLOCK, 1, 1, ptr(root_dir, G4)),
            2: node(2, 1, 0, hello_size, 1, 2, ptr(hello_block, hello_gen)),
            3: node(3, 1, 1, 25 * BLOCK, 1, 3, ptr(big_tree, G4)),
            4: node(4, 2, 0, BLOCK, 1, 4, ptr(sub_dir, G4)),
            5: node(5, 1, 0, 4, 4, 4, ptr(a_txt, G4)),
        }

    nd4 = dsnd(nodes(hello4, 13, G4), G4)
    nt4 = dspt(1, [ptr(nd4, G4)], G4)
    rt4 = root_block([(1, ptr(nt4, G4), 1, 6, 0, b"")], G4)

    # ---- tree v5 (generation 5): hello.txt rewritten; v4 kept as a snapshot ----
    G5 = 5
    hello5 = data_block(b"Hello DeSoFS v5\n")
    nd5 = dsnd(nodes(hello5, 16, G5), G5)
    nt5 = dspt(1, [ptr(nd5, G5)], G5)
    rt5 = root_block([(1, ptr(nt5, G5), 1, 6, 0, b""), (2, ptr(nt4, G4), 1, 6, 4, b"before-v5")], G5)

    s4, s5 = set(), set()
    reach(rt4, s4)
    reach(rt5, s5)
    superblock(1, G4, ptr(rt4, G4), len(s4))
    superblock(2, G5, ptr(rt5, G5), len(s5))

    with open(sys.argv[1], "wb") as f:
        f.write(img)


if __name__ == "__main__":
    main()
