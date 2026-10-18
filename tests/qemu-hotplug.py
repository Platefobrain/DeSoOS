#!/usr/bin/env python3
# USB hot-plugging in ./test.sh.  Reads the QEMU log (kernel serial) and
# sends every „[HOTPLUG] <command>” line to the QEMU monitor (HMP over a unix
# socket) – e.g. „device_del hubdisk”.  The kernel self-test (USB TEST 6/6) prints these
# lines and checks whether the disk / hub really disappeared and came back.
#
#   python3 tests/qemu-hotplug.py logs/test.log /tmp/desoos-monitor.sock
#
# Exits by itself when QEMU closes the monitor (end of the tests).
import os
import socket
import sys
import time

MARK = "[HOTPLUG] "


def connect(path):
    for _ in range(600):  # QEMU is starting – up to 60 s
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(path)
            return s
        except OSError:
            time.sleep(0.1)
    return None


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: qemu-hotplug.py LOG MONITOR_SOCKET")
    log, sock = sys.argv[1], sys.argv[2]
    mon = connect(sock)
    if mon is None:
        print("qemu-hotplug: no QEMU monitor at " + sock, file=sys.stderr)
        return 1
    mon.setblocking(False)
    pos = 0
    rest = b""
    while True:
        # We only drain monitor replies (otherwise the socket buffer fills up).
        try:
            if mon.recv(65536) == b"":
                return 0  # QEMU closed the monitor
        except BlockingIOError:
            pass
        except OSError:
            return 0
        try:
            size = os.path.getsize(log)
        except OSError:
            size = 0
        if size > pos:
            with open(log, "rb") as f:
                f.seek(pos)
                data = f.read(size - pos)
            pos = size
            rest += data
            *lines, rest = rest.split(b"\n")
            for raw in lines:
                line = raw.decode("utf-8", "replace")
                i = line.find(MARK)
                if i >= 0:
                    cmd = line[i + len(MARK):].strip()
                    try:
                        mon.sendall((cmd + "\n").encode())
                    except OSError:
                        return 0
        time.sleep(0.05)


if __name__ == "__main__":
    sys.exit(main())
