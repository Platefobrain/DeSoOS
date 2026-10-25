#!/usr/bin/env python3
# Small DNS server for the self-tests (tests/test.sh starts it).  It listens on
# 127.0.0.1:<port> (default 53530); in QEMU's user network the guest reaches it
# as 10.0.2.2:<port>.  It answers a fixed set of names under ".desoos" - correct
# answers, errors and deliberately broken ones - so the network test does not
# depend on the internet.  Garbage in is ignored, never a crash.
import socket
import struct
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 53530


def labels(name):
    out = b""
    for part in name.split("."):
        out += bytes([len(part)]) + part.encode()
    return out + b"\0"


def header(qid, flags, an):
    return struct.pack(">HHHHHH", qid, flags, 1, an, 0, 0)


def rr_a(name_bytes, ip, ttl=300):
    return name_bytes + struct.pack(">HHIH", 1, 1, ttl, 4) + bytes(int(x) for x in ip.split("."))


def answer(qid, question, name):
    """List of datagrams to send back (possibly none)."""
    ok = 0x8180  # response, recursion desired + available
    q = b"\xc0\x0c"  # pointer to the question name
    if name == "router.desoos":
        return [header(qid, ok, 1) + question + rr_a(q, "10.0.2.2")]
    if name == "multi.desoos":
        return [header(qid, ok, 2) + question + rr_a(q, "10.0.2.2", 60) + rr_a(q, "10.0.2.77", 60)]
    if name == "big.desoos":
        rrs = b"".join(rr_a(q, "10.0.3.%d" % i) for i in range(1, 7))
        return [header(qid, ok, 6) + question + rrs]
    if name == "alias.desoos":
        target = labels("router.desoos")
        cname = q + struct.pack(">HHIH", 5, 1, 300, len(target)) + target
        # The A record names the CNAME target by a pointer to its rdata.
        target_at = 12 + len(question) + 12
        return [header(qid, ok, 2) + question + cname + rr_a(struct.pack(">H", 0xC000 | target_at), "10.0.2.2")]
    if name == "ttl0.desoos":
        return [header(qid, ok, 1) + question + rr_a(q, "10.0.2.2", 0)]
    if name == "noaddr.desoos":
        return [header(qid, ok, 0) + question]
    if name == "nx.desoos":
        return [header(qid, ok | 3, 0) + question]
    if name == "fail.desoos":
        return [header(qid, ok | 2, 0) + question]
    if name == "trunc.desoos":
        return [header(qid, ok | 0x0200, 0) + question]
    if name == "loop.desoos":
        # An answer whose name is a pointer to itself.
        at = 12 + len(question)
        return [header(qid, ok, 1) + question + struct.pack(">H", 0xC000 | at) + struct.pack(">HHIH", 1, 1, 300, 4) + bytes([10, 0, 2, 2])]
    if name == "spoof.desoos":
        # A forged answer with the wrong id first, then the real one.
        return [header(qid ^ 0x5555, ok, 1) + question + rr_a(q, "10.6.6.6"), header(qid, ok, 1) + question + rr_a(q, "10.0.2.2")]
    if name == "silent.desoos":
        return []
    return [header(qid, ok | 5, 0) + question]  # REFUSED


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", PORT))
    except OSError as e:
        print("dns-stub: cannot listen on 127.0.0.1:%d: %s" % (PORT, e), file=sys.stderr)
        return 1
    while True:
        data, peer = s.recvfrom(2048)
        try:
            qid, flags, qd = struct.unpack(">HHH", data[:6])
            if flags & 0x8000 or qd != 1:
                continue
            i, parts = 12, []
            while data[i] != 0:
                n = data[i]
                parts.append(data[i + 1:i + 1 + n].decode("ascii"))
                i += 1 + n
            question = data[12:i + 5]
            for d in answer(qid, question, ".".join(parts).lower()):
                s.sendto(d, peer)
        except (IndexError, UnicodeDecodeError, struct.error):
            continue


if __name__ == "__main__":
    sys.exit(main())
