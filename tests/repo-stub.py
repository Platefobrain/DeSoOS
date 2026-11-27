#!/usr/bin/env python3
"""The package repository of PKG TEST (tests/pkg-test.sh starts it) – Python standard library
only (ssl = OpenSSL).  The guest reaches it as tls.deso = 10.0.2.2 (tests/dns-stub.py).

  repo-stub.py REPO_DIR        (REPO_DIR: what tests/pkg/make-repo.py made)

  58480  HTTPS (tests/tls/ecdsa.pem, issued for tls.deso by tests/tls/ca.pem – the self-test
         image's /etc/desopkg/ca): GET /deso/<channel>/<arch>/index | index.sig |
         packages/<file> from REPO_DIR/<scenario>/deso/...  (HTTP/1.1, Content-Length,
         close_notify at the end)
  58481  plain HTTP, control (the guest asks with netget):
           /scenario?name=X   serve scenario X from now on ("ok X")
           /hits              "index=N sig=N pkg=N" – requests since the last /reset
           /reset             the counters to 0

Scenarios: every directory of REPO_DIR, plus transfer modes on top of `tx` that change how
packages/witaj-1.1.1.pkg is sent:
  long      Content-Length = the file's size, then 64 more bytes
  short     Content-Length = the file's size, half of it, then the connection is closed
  badlen    Content-Length one byte more than the file (and the file)
  redirect  302 Found, Location: https://tls.deso:58480/deso/stable/x86_64/packages/witaj-1.1.0.pkg
"""
import os
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time

import stubnet

T = os.path.dirname(os.path.abspath(__file__))
CERTS = os.path.join(T, "tls")
REPO = sys.argv[1] if len(sys.argv) > 1 else "."
MODES = ("long", "short", "badlen", "redirect")
STATE = {"scenario": "v100", "hits": {"index": 0, "sig": 0, "pkg": 0}}
LOCK = threading.Lock()


def answer(status, body, extra=b""):
    head = b"HTTP/1.1 %s\r\nContent-Length: %d\r\nConnection: close\r\n%s\r\n" % (status, len(body), extra)
    return head + body


def repo_answer(path):
    """(bytes to send, how to end: notify | close)."""
    with LOCK:
        scen = STATE["scenario"]
    mode = scen if scen in MODES else None
    base = "tx" if mode else scen
    prefix = "/deso/"
    if not path.startswith(prefix) or ".." in path:
        return answer(b"404 Not Found", b"not found\n"), "notify"
    rel = path[len(prefix):]
    full = os.path.join(REPO, base, "deso", rel)
    kind = "pkg" if "/packages/" in rel else ("sig" if rel.endswith("index.sig") else ("index" if rel.endswith("/index") else None))
    if kind:
        with LOCK:
            STATE["hits"][kind] += 1
    try:
        data = open(full, "rb").read()
    except OSError:
        return answer(b"404 Not Found", b"not found\n"), "notify"
    if mode and rel.endswith("packages/witaj-1.1.1.pkg"):
        if mode == "long":
            return answer(b"200 OK", data)[: -len(data)] + data + b"\0" * 64, "notify"
        if mode == "short":
            whole = answer(b"200 OK", data)
            return whole[: len(whole) - len(data) // 2], "close"
        if mode == "badlen":
            return answer(b"200 OK", data + b"\0"), "notify"
        if mode == "redirect":
            loc = b"Location: https://tls.deso:58480/deso/stable/x86_64/packages/witaj-1.1.0.pkg\r\n"
            return answer(b"302 Found", b"moved\n", loc), "notify"
    return answer(b"200 OK", data), "notify"


def read_request(s):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 8192:
        chunk = s.recv(4096)
        if not chunk:
            return None
        data += chunk
    try:
        return data.split(b"\r\n", 1)[0].split()[1].decode("latin-1")
    except IndexError:
        return None


class Repo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(60)
        try:
            s = CTX.wrap_socket(self.request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            path = read_request(s)
            if path is None:
                return
            out, end = repo_answer(path)
            for i in range(0, len(out), 65536):
                s.sendall(out[i : i + 65536])
            if end == "notify":
                try:
                    s.unwrap()
                except (ssl.SSLError, OSError):
                    pass
            else:
                # Cut: the TCP connection reset, no close_notify.
                time.sleep(0.3)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                s.close()
        except (ssl.SSLError, OSError):
            pass


class Control(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            path = read_request(self.request)
            if path is None:
                return
            if path.startswith("/scenario?name="):
                name = path.split("=", 1)[1]
                if name in MODES or os.path.isdir(os.path.join(REPO, name)):
                    with LOCK:
                        STATE["scenario"] = name
                    body = ("ok %s\n" % name).encode()
                else:
                    body = ("no scenario %s\n" % name).encode()
            elif path == "/hits":
                with LOCK:
                    h = STATE["hits"]
                    body = ("index=%d sig=%d pkg=%d\n" % (h["index"], h["sig"], h["pkg"])).encode()
            elif path == "/reset":
                with LOCK:
                    STATE["hits"] = {"index": 0, "sig": 0, "pkg": 0}
                body = b"ok reset\n"
            else:
                body = b"unknown\n"
            self.request.sendall(answer(b"200 OK", body))
            self.request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
CTX.load_cert_chain(os.path.join(CERTS, "ecdsa.pem"), os.path.join(CERTS, "ecdsa.key"))
CTX.minimum_version = ssl.TLSVersion.TLSv1_3
CTX.num_tickets = 0

for port, handler in ((58480, Repo), (58481, Control)):
    srv = stubnet.tcp_server(S, port, handler, "repo-stub")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
stubnet.ready("repo")
while True:
    time.sleep(3600)
