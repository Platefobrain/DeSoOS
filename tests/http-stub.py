#!/usr/bin/env python3
# Small HTTP server for the self-tests (tests/test.sh starts it).  It listens on
# 127.0.0.1:<port> (default 58080); in QEMU's user network the guest reaches it
# as 10.0.2.2:<port>.  Fixed pages exercise the guest's TCP: a short page, 1 MiB
# with a known pattern, a page sent in slow pieces, a page cut short, a page
# ended with a reset, a page without a length, an error status.
import socket
import socketserver
import struct
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 58080
BIG = 1024 * 1024


def pattern(n):
    """Byte i = (i * 7 + i // 251) mod 256 - the guest checks the same formula."""
    return bytes(((i * 7 + i // 251) & 0xFF) for i in range(n))


BIG_BODY = None  # built at the first request, not at start (the guest boots meanwhile)


class Handler(socketserver.BaseRequestHandler):
    def send_page(self, body, status="200 OK", length=True):
        head = "HTTP/1.0 %s\r\nServer: desoos-test\r\n" % status
        if length:
            head += "Content-Length: %d\r\n" % len(body)
        self.request.sendall(head.encode() + b"\r\n" + body)

    def handle(self):
        s = self.request
        s.settimeout(10)
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 8192:
                chunk = s.recv(4096)
                if not chunk:
                    return
                data += chunk
        except OSError:
            return
        line = data.split(b"\r\n", 1)[0].decode("latin-1")
        parts = line.split()
        path = parts[1] if len(parts) >= 2 else "/"
        try:
            if path == "/hello":
                self.send_page(b"Hello from the host\n")
            elif path == "/big":
                global BIG_BODY
                if BIG_BODY is None:
                    BIG_BODY = pattern(BIG)
                self.send_page(BIG_BODY)
            elif path == "/slow":
                s.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 1000\r\n\r\n")
                for _ in range(10):
                    time.sleep(0.1)
                    s.sendall(b"s" * 100)
            elif path == "/short":
                s.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 100000\r\n\r\n" + b"x" * 5000)
            elif path == "/reset":
                s.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 100000\r\n\r\n" + b"r" * 3000)
                time.sleep(0.2)
                # Close with a RST instead of a FIN.
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            elif path.startswith("/connect?"):
                # From the host into the guest: connect to 127.0.0.1:<port> (QEMU
                # forwards it to a server in DeSoOS), GET <path>, return what came.
                q = dict(kv.split("=", 1) for kv in path.split("?", 1)[1].split("&") if "=" in kv)
                try:
                    c = socket.create_connection(("127.0.0.1", int(q.get("port", "0"))), timeout=5)
                    c.sendall(("GET %s HTTP/1.0\r\nHost: desoos\r\n\r\n" % q.get("path", "/")).encode())
                    got = b""
                    while True:
                        chunk = c.recv(65536)
                        if not chunk:
                            break
                        got += chunk
                    c.close()
                    self.send_page(got)
                except (OSError, ValueError) as e:
                    self.send_page(("host could not connect: %s\n" % e).encode(), status="502 Bad Gateway")
            elif path == "/nolength":
                self.send_page(b"n" * 5000, length=False)
            else:
                self.send_page(b"not here\n", status="404 Not Found")
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    try:
        srv = Server(("127.0.0.1", PORT), Handler)
    except OSError as e:
        print("http-stub: cannot listen on 127.0.0.1:%d: %s" % (PORT, e), file=sys.stderr)
        return 1
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
