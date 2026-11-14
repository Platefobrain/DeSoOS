# Shared by the host-side test servers (dns-, http-, udp-, ntp-, tls-stub.py).
#
# bind():   our ports (53530, 58080-58590) lie inside Linux's default range for outgoing
#           ports (32768-60999), so any program on the host can hold one of them for a
#           moment as the source port of its own connection.  A busy port is tried again
#           for up to RETRY_S seconds before the server gives up.
# ready():  when tests/test.sh sets STUB_READY (a directory), a server creates the file
#           STUB_READY/<name> once all its ports are bound; test.sh starts QEMU only after
#           every server has done so.
import errno
import os
import sys
import time

RETRY_S = 5.0


def bind(sock, port, name):
    end = time.monotonic() + RETRY_S
    while True:
        try:
            sock.bind(("127.0.0.1", port))
            return
        except OSError as e:
            if e.errno != errno.EADDRINUSE or time.monotonic() >= end:
                print("%s: cannot listen on 127.0.0.1:%d: %s" % (name, port, e), file=sys.stderr)
                sys.exit(1)
            time.sleep(0.1)


def tcp_server(cls, port, handler, name):
    """A socketserver.TCPServer subclass on 127.0.0.1:port, bound with bind()'s retries."""
    srv = cls(("127.0.0.1", port), handler, bind_and_activate=False)
    if getattr(srv, "allow_reuse_address", False):
        import socket
        srv.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind(srv.socket, port, name)
    srv.server_address = srv.socket.getsockname()
    srv.server_activate()
    return srv


def ready(name):
    d = os.environ.get("STUB_READY")
    if d:
        try:
            open(os.path.join(d, name), "w").close()
        except OSError:
            pass   # nobody waits any more (the directory is gone): keep serving
