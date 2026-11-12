#!/usr/bin/env python3
# NTP servers for NTP TEST (tests/test.sh starts it).  One process listens on
# 127.0.0.1:<base>..<base+30> (default base 58123); in QEMU's user network the guest
# reaches them as 10.0.2.2:<port>.  Every port is one server with its own behaviour
# (base + n):
#    0  a correct answer (stratum 2, the host's time)
#    1  correct, the time 3600 s ahead        2  10 s ahead        3  20 s ahead
#    4  silence
#    5  Kiss-o'-Death RATE (timestamps zero)  6  DENY (timestamps garbage)  7  RSTR
#    8  stratum 0 with an unknown code "XXXX"
#    9  a wrong Origin, always
#   10  a wrong Origin, then the correct answer to the same query
#   11  the correct answer twice
#   12  first query of a sender: DENY with a wrong Origin; second query: correct
#   13  first query: silence; second query: an answer to the FIRST one (late), then the
#       correct one
#   14  correct, but the server's clock says 2040-06-01 12:00:00 UTC (NTP era 1)
#   15  correct with 16 bytes of extension field after the header
#   16  LI = 3            17  stratum 16         18  mode 3 (the query echoed)
#   19  version 2         20  47 bytes           21  an empty datagram
#   22  root dispersion 16 s                     23  root delay 0.2 s + dispersion 1.5 s
#   24  root delay 0.2 s + dispersion 1.3 s (accepted)
#   25  root delay negative                      26  transmit before receive
#   27  transmit 0        28  receive 0          29  version 5
#   30  not NTP: "reset" zeroes the query counter (bad and dup count for the whole run), anything answers
#       "queries=N bad=N dup=N" - queries seen on ports 0-29, queries that are not the
#       minimal client packet (48 bytes: 0x23, 0, 0, 0x20, zeros, a Transmit value),
#       Transmit values seen more than once.
# A query that is not the minimal client packet gets no answer.  Garbage in is never a
# crash.
import select
import socket
import struct
import sys
import time

BASE = int(sys.argv[1]) if len(sys.argv) > 1 else 58123
NTP_UNIX = 2208988800
STATS = 30


def ts(unix):
    secs = int(unix)
    return struct.pack(">II", (secs + NTP_UNIX) & 0xFFFFFFFF, int((unix - secs) * (1 << 32)) & 0xFFFFFFFF)


def fixed(seconds):
    return struct.pack(">I", int(seconds * 65536) & 0xFFFFFFFF)


def packet(origin, now, li=0, vn=4, mode=4, stratum=2, delay=0.01, disp=0.01, refid=b"STUB", receive=None, transmit=None):
    head = bytes([(li << 6) | (vn << 3) | mode, stratum, 0, 0xEC])
    return (head + fixed(delay) + fixed(disp) + refid + ts(now) + origin
            + (ts(now) if receive is None else receive) + (ts(now) if transmit is None else transmit))


def answers(n, query, origin, first, state, peer):
    """The datagrams server n sends back for this query."""
    now = time.time()
    other = bytes(b ^ 0x55 for b in origin)
    zero = b"\0" * 8
    if n == 0:
        return [packet(origin, now)]
    if n in (1, 2, 3):
        return [packet(origin, now + (3600, 10, 20)[n - 1])]
    if n == 4:
        return []
    if n == 5:
        return [packet(origin, now, li=3, stratum=0, refid=b"RATE", receive=zero, transmit=zero)]
    if n == 6:
        return [packet(origin, now, li=3, stratum=0, refid=b"DENY", receive=b"\xff" * 8, transmit=b"\x01" * 8)]
    if n == 7:
        return [packet(origin, now, li=3, stratum=0, refid=b"RSTR", receive=zero, transmit=zero)]
    if n == 8:
        return [packet(origin, now, li=3, stratum=0, refid=b"XXXX")]
    if n == 9:
        return [packet(other, now)]
    if n == 10:
        return [packet(other, now), packet(origin, now)]
    if n == 11:
        return [packet(origin, now), packet(origin, now)]
    if n == 12:
        if first:
            return [packet(other, now, li=3, stratum=0, refid=b"DENY", receive=zero, transmit=zero)]
        return [packet(origin, now)]
    if n == 13:
        if first:
            state[peer] = origin
            return []
        return [packet(state.get(peer, other), now), packet(origin, now)]
    if n == 14:
        return [packet(origin, 2222164800.0)]  # 2040-06-01 12:00:00 UTC
    if n == 15:
        return [packet(origin, now) + struct.pack(">HH", 0x0104, 16) + b"\0" * 12]
    if n == 16:
        return [packet(origin, now, li=3)]
    if n == 17:
        return [packet(origin, now, stratum=16)]
    if n == 18:
        return [query]
    if n == 19:
        return [packet(origin, now, vn=2)]
    if n == 20:
        return [packet(origin, now)[:47]]
    if n == 21:
        return [b""]
    if n == 22:
        return [packet(origin, now, disp=16)]
    if n == 23:
        return [packet(origin, now, delay=0.2, disp=1.5)]
    if n == 24:
        return [packet(origin, now, delay=0.2, disp=1.3)]
    if n == 25:
        return [packet(origin, now, delay=-0.5)]
    if n == 26:
        return [packet(origin, now, receive=ts(now), transmit=ts(now - 5))]
    if n == 27:
        return [packet(origin, now, transmit=zero)]
    if n == 28:
        return [packet(origin, now, receive=zero)]
    if n == 29:
        return [packet(origin, now, vn=5)]
    return []


def main():
    socks = {}
    for n in range(STATS + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind(("127.0.0.1", BASE + n))
        except OSError as e:
            print("ntp-stub: cannot listen on 127.0.0.1:%d: %s" % (BASE + n, e), file=sys.stderr)
            return 1
        socks[s] = n
    count = {"queries": 0, "bad": 0, "dup": 0}
    seen = set()
    senders = set()
    late = {}
    while True:
        ready, _, _ = select.select(list(socks), [], [])
        for s in ready:
            n = socks[s]
            try:
                data, peer = s.recvfrom(65535)
            except OSError:
                continue
            try:
                if n == STATS:
                    if data == b"reset":
                        count["queries"] = 0
                    s.sendto(b"queries=%d bad=%d dup=%d" % (count["queries"], count["bad"], count["dup"]), peer)
                    continue
                count["queries"] += 1
                if len(data) != 48 or data[:4] != b"\x23\x00\x00\x20" or any(data[4:40]) or not any(data[40:]):
                    count["bad"] += 1
                    continue
                origin = data[40:48]
                if origin in seen:
                    count["dup"] += 1
                seen.add(origin)
                key = (n, peer)
                first = key not in senders
                senders.add(key)
                for i, d in enumerate(answers(n, data, origin, first, late, key)):
                    if i:
                        time.sleep(0.05)
                    s.sendto(d, peer)
            except (OSError, ValueError, struct.error):
                pass


if __name__ == "__main__":
    sys.exit(main())
