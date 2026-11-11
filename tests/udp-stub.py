#!/usr/bin/env python3
# Small UDP server for the self-tests (tests/test.sh starts it).  It listens on
# 127.0.0.1:<port> (default 58090); in QEMU's user network the guest reaches it as
# 10.0.2.2:<port>.  What a datagram asks for (anything else is echoed back as it is):
#   "big"         – an answer of 1472 bytes (the most one datagram carries through netd)
#   "burst N"     – N datagrams "b0", "b1", ... sent at once (N <= 500)
#   "foreign"     – "foreign" from another port of this host (must not reach the
#                   guest's socket), then "real" from this port
#   "silent"      – no answer
#   "count"       – how many datagrams came from this sender before (not counting itself)
# Garbage in is never a crash.
import socket
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 58090


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", PORT))
    except OSError as e:
        print("udp-stub: cannot listen on 127.0.0.1:%d: %s" % (PORT, e), file=sys.stderr)
        return 1
    other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    other.bind(("127.0.0.1", 0))
    seen = {}
    while True:
        try:
            data, peer = s.recvfrom(65535)
        except OSError:
            continue
        try:
            if data == b"count":
                s.sendto(b"%d" % seen.get(peer, 0), peer)
                continue
            seen[peer] = seen.get(peer, 0) + 1
            if data == b"big":
                s.sendto(bytes((i * 7) & 0xFF for i in range(1472)), peer)
            elif data.startswith(b"burst "):
                n = min(int(data[6:]), 500)
                for i in range(n):
                    s.sendto(b"b%d" % i, peer)
            elif data == b"foreign":
                other.sendto(b"foreign", peer)
                time.sleep(0.1)
                s.sendto(b"real", peer)
            elif data == b"silent":
                pass
            else:
                s.sendto(data, peer)
        except (OSError, ValueError):
            pass


if __name__ == "__main__":
    sys.exit(main())
