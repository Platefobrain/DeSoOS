#!/usr/bin/env python3
# HTTPS servers for the self-tests (tests/test.sh starts it; /bin/tlstest in DeSoOS talks
# to them as tls.desoos = 10.0.2.2).  Only the Python standard library (ssl = OpenSSL).
#
#   58443  TLS 1.3, RSA certificate (tests/tls/rsa.pem) – the pages below
#   58444  TLS 1.3, ECDSA P-256 certificate
#   58445  expired certificate      58446  not yet valid      58447  issued for other.desoos
#   58448  certificate with a broken signature                58449  issued by another CA
#   58450  TLS 1.2 only             58451  key exchange P-256 only (no X25519)
#   58460-58466  a man in the middle in front of a 58443-like server (each its own):
#          60 changes the server's Finished, 61 its CertificateVerify signature, 62 one byte
#          of the first record after the handshake, 63 sends that record twice, 64 hands the
#          server's bytes over in 1-7 byte pieces, 65 several records at once, 66 inserts three
#          KeyUpdates from the server (the first asking for one back)
#   58470  plain HTTP: /seen?port=N – how many HTTP requests the server behind port N got
#          (a refused handshake must leave it at 0)
#
# The changing middles (60-63, 66) decrypt and encrypt TLS records with the server's keys:
# the backend writes them to a keylog (as SSLKEYLOGFILE), the middle reads the line for the
# connection's client random.  They implement ChaCha20-Poly1305 only – the guest is asked to
# offer that suite (netget --cipher chacha).
#
# Pages (any server): /hello, /big (1 MiB, byte i = (i*7 + i/251) mod 256), /cl0 (empty
# body), /dupcl (two different Content-Length), /dupsame (the same one twice), /te
# (Transfer-Encoding: chunked), /extra (Content-Length 5, then 3 more bytes in a later
# record), /nocl-notify (no length, close_notify at the end), /nocl-fin (no length, TCP closed
# without close_notify), /cut (Content-Length 100000, 5000 bytes, no close_notify),
# /cl-fin (complete by Content-Length, then no close_notify), /reset (Content-Length 100000,
# 3000 bytes, then a TCP reset), /cl-reset (complete by Content-Length, then a reset),
# /nocl-reset (no length, then a reset), /404, /badhdr (a header line without ':').
import hashlib
import hmac
import os
import socket
import socketserver
import ssl
import struct
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CERTS = os.path.join(HERE, "tls")
KEYLOG_DIR = tempfile.mkdtemp(prefix="desoos-tls-")
BIG = 1024 * 1024
BIG_BODY = None
SEEN = {}
SEEN_LOCK = threading.Lock()


def pattern(n):
    return bytes(((i * 7 + i // 251) & 0xFF) for i in range(n))


# ---- the pages ----

def page(path):
    """(bytes to send in pieces, how to end: 'notify' | 'fin' | 'reset')."""
    global BIG_BODY
    def ok(body, extra=""):
        return [("HTTP/1.0 200 OK\r\nServer: desoos-tls-test\r\n%sContent-Length: %d\r\n\r\n" % (extra, len(body))).encode() + body]
    if path == "/hello":
        return ok(b"Hello over TLS\n"), "notify"
    if path == "/big":
        if BIG_BODY is None:
            BIG_BODY = pattern(BIG)
        return ok(BIG_BODY), "notify"
    if path == "/cl0":
        return ok(b""), "notify"
    if path == "/dupcl":
        return [b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nabcd"], "notify"
    if path == "/dupsame":
        return [b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nabcd"], "notify"
    if path == "/te":
        return [b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n"], "notify"
    if path == "/extra":
        return [b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello", b"xyz"], "notify"
    if path == "/nocl-notify":
        return [b"HTTP/1.0 200 OK\r\n\r\n", b"until the end\n"], "notify"
    if path == "/nocl-fin":
        return [b"HTTP/1.0 200 OK\r\n\r\n", b"until the end\n"], "fin"
    if path == "/cut":
        return [b"HTTP/1.0 200 OK\r\nContent-Length: 100000\r\n\r\n" + b"x" * 5000], "fin"
    if path == "/cl-fin":
        return ok(b"complete\n"), "fin"
    if path == "/reset":
        return [b"HTTP/1.0 200 OK\r\nContent-Length: 100000\r\n\r\n" + b"r" * 3000], "reset"
    if path == "/cl-reset":
        return ok(b"whole\n"), "reset"
    if path == "/nocl-reset":
        return [b"HTTP/1.0 200 OK\r\n\r\n", b"part of a page"], "reset"
    if path == "/badhdr":
        return [b"HTTP/1.0 200 OK\r\nno colon here\r\nContent-Length: 2\r\n\r\nok"], "notify"
    return [b"HTTP/1.0 404 Not Found\r\nContent-Length: 10\r\n\r\nnot found\n"], "notify"


def context(cert, keyfile, keylog=None, max_version=None, groups=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERTS, cert), os.path.join(CERTS, keyfile))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = max_version or ssl.TLSVersion.TLSv1_3
    if groups:
        ctx.set_ecdh_curve(groups)
    if keylog:
        ctx.keylog_filename = keylog
    # No session tickets: nothing extra after the handshake (the guest ignores them anyway).
    ctx.num_tickets = 0
    return ctx


def serve_tls(port, ctx, force_end=None):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            raw = self.request
            raw.settimeout(15)
            try:
                s = ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError):
                return
            try:
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 8192:
                    chunk = s.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                with SEEN_LOCK:
                    SEEN[port] = SEEN.get(port, 0) + 1
                path = data.split(b"\r\n", 1)[0].split()[1].decode("latin-1")
                parts, end = page(path)
                for i, p in enumerate(parts):
                    if i:
                        time.sleep(0.05)
                    s.sendall(p)
                end = force_end or end
                if end == "notify":
                    try:
                        s.unwrap()
                    except (ssl.SSLError, OSError):
                        pass
                elif end == "reset":
                    time.sleep(0.5)
                    raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    raw.close()
                else:
                    # "fin": the TCP connection ends without close_notify.
                    raw.shutdown(socket.SHUT_RDWR)
            except (ssl.SSLError, OSError, IndexError):
                pass

    class S(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = S(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ---- ChaCha20-Poly1305 and the TLS 1.3 key derivation (for the middles) ----

def _rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _quarter(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl(x[b] ^ x[c], 7)


def chacha_block(key, counter, nonce):
    st = list(struct.unpack("<4I", b"expand 32-byte k")) + list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    x = st[:]
    for _ in range(10):
        _quarter(x, 0, 4, 8, 12); _quarter(x, 1, 5, 9, 13); _quarter(x, 2, 6, 10, 14); _quarter(x, 3, 7, 11, 15)
        _quarter(x, 0, 5, 10, 15); _quarter(x, 1, 6, 11, 12); _quarter(x, 2, 7, 8, 13); _quarter(x, 3, 4, 9, 14)
    return struct.pack("<16I", *[(x[i] + st[i]) & 0xFFFFFFFF for i in range(16)])


def chacha_xor(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)


def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + b"\x01", "little")
        acc = (acc + n) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b):
    return b"\x00" * (-len(b) % 16)


def aead_tag(key, nonce, aad, ct):
    otk = chacha_block(key, 0, nonce)[:32]
    mac = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    return poly1305(otk, mac)


def seal(key, nonce, aad, pt):
    ct = chacha_xor(key, 1, nonce, pt)
    return ct + aead_tag(key, nonce, aad, ct)


def open_(key, nonce, aad, data):
    ct, tag = data[:-16], data[-16:]
    if not hmac.compare_digest(aead_tag(key, nonce, aad, ct), tag):
        raise ValueError("bad tag")
    return chacha_xor(key, 1, nonce, ct)


def expand_label(secret, label, length):
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full + b"\x00"
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


class Keys:
    """One direction's ChaCha20-Poly1305 keys."""
    def __init__(self, secret):
        self.secret = secret
        self.key = expand_label(secret, b"key", 32)
        self.iv = expand_label(secret, b"iv", 12)
        self.seq = 0

    def nonce(self):
        n = bytearray(self.iv)
        for i, b in enumerate(self.seq.to_bytes(8, "big")):
            n[4 + i] ^= b
        return bytes(n)

    def open(self, rec):
        pt = open_(self.key, self.nonce(), rec[:5], rec[5:])
        self.seq += 1
        pt = pt.rstrip(b"\x00")
        return pt[-1], pt[:-1]

    def seal(self, ty, content):
        body = content + bytes([ty])
        hdr = b"\x17\x03\x03" + struct.pack(">H", len(body) + 16)
        rec = hdr + seal(self.key, self.nonce(), hdr, body)
        self.seq += 1
        return rec

    def next(self):
        return Keys(expand_label(self.secret, b"traffic upd", 32))


def read_record(sock, buf):
    while len(buf) < 5 or len(buf) < 5 + struct.unpack(">H", buf[3:5])[0]:
        chunk = sock.recv(65536)
        if not chunk:
            return None, buf
        buf += chunk
    n = 5 + struct.unpack(">H", buf[3:5])[0]
    return buf[:n], buf[n:]


def keylog_secret(path, client_random, label):
    want = client_random.hex()
    for _ in range(100):
        try:
            with open(path) as f:
                for line in f:
                    p = line.split()
                    if len(p) == 3 and p[0] == label and p[1] == want:
                        return bytes.fromhex(p[2])
        except OSError:
            pass
        time.sleep(0.02)
    raise ValueError("no keylog line")


def middle(port, backend, keylog, mode):
    """A man in the middle on `port` in front of the TLS server on `backend`."""
    def handle(c):
        c.settimeout(15)
        try:
            b = socket.create_connection(("127.0.0.1", backend), timeout=15)
        except OSError:
            c.close()
            return
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        state = {"cr": None}

        def up():
            # Client to server: as it is; remember the ClientHello's random.
            first = True
            try:
                while True:
                    d = c.recv(65536)
                    if not d:
                        break
                    if first and len(d) > 43 and d[0] == 22:
                        state["cr"] = d[11:43]
                        first = False
                    b.sendall(d)
            except OSError:
                pass
            try:
                b.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        threading.Thread(target=up, daemon=True).start()
        try:
            down(c, b, state, keylog, mode)
        except (OSError, ValueError, struct.error):
            pass
        for s in (b, c):
            try:
                s.close()
            except OSError:
                pass

    def down(c, b, state, keylog, mode):
        if mode == "pieces":
            while True:
                d = b.recv(65536)
                if not d:
                    return
                i = 0
                while i < len(d):
                    k = 1 + (i % 7)
                    c.sendall(d[i:i + k])
                    i += k
                    time.sleep(0.0005)
        if mode == "merge":
            buf = b""
            b.settimeout(0.2)
            while True:
                try:
                    d = b.recv(65536)
                except socket.timeout:
                    d = None
                if d:
                    buf += d
                    continue
                if buf:
                    c.sendall(buf)
                    buf = b""
                if d == b"":
                    return
        buf = b""
        hs = None
        app = None
        out_app = None
        changed = False
        updates = 0
        while True:
            rec, buf = read_record(b, buf)
            if rec is None:
                return
            if rec[0] != 23:
                c.sendall(rec)
                continue
            if hs is None:
                hs = Keys(keylog_secret(keylog, state["cr"], "SERVER_HANDSHAKE_TRAFFIC_SECRET"))
            if app is None:
                ty, pt = hs.open(rec)
                if ty == 22 and mode in ("finished", "verify") and not changed:
                    m = bytearray(pt)
                    i = 0
                    while i + 4 <= len(m):
                        t = m[i]
                        n = int.from_bytes(m[i + 1:i + 4], "big")
                        if mode == "finished" and t == 20:
                            m[i + 4 + 5] ^= 0x01
                            changed = True
                        if mode == "verify" and t == 15:
                            m[i + 4 + n - 1] ^= 0x01
                            changed = True
                        i += 4 + n
                    pt = bytes(m)
                    hs.seq -= 1
                    rec = hs.seal(ty, pt)
                # The server's Finished ends its handshake keys (messages walked one by one).
                types = []
                j = 0
                while ty == 22 and j + 4 <= len(pt):
                    types.append(pt[j])
                    j += 4 + int.from_bytes(pt[j + 1:j + 4], "big")
                if 20 in types:
                    app = Keys(keylog_secret(keylog, state["cr"], "SERVER_TRAFFIC_SECRET_0"))
                    out_app = Keys(app.secret)
                c.sendall(rec)
                continue
            # After the handshake.
            if mode == "tag" and not changed:
                r = bytearray(rec)
                r[8] ^= 0x01
                c.sendall(bytes(r))
                changed = True
                continue
            if mode == "replay" and not changed:
                c.sendall(rec)
                c.sendall(rec)
                changed = True
                continue
            if mode == "keyupdate":
                ty, pt = app.open(rec)
                while updates < 3:
                    c.sendall(out_app.seal(22, bytes([24, 0, 0, 1, 1 if updates == 0 else 0])))
                    out_app = out_app.next()
                    updates += 1
                c.sendall(out_app.seal(ty, pt))
                continue
            c.sendall(rec)

    class H(socketserver.BaseRequestHandler):
        def handle(self):
            handle(self.request)

    class S(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = S(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def control(port):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            s = self.request
            s.settimeout(5)
            data = b""
            try:
                while b"\r\n\r\n" not in data and len(data) < 4096:
                    d = s.recv(4096)
                    if not d:
                        return
                    data += d
                path = data.split(b"\r\n", 1)[0].split()[1].decode()
                n = 0
                if path.startswith("/seen?port="):
                    p = int(path.split("=", 1)[1])
                    with SEEN_LOCK:
                        n = SEEN.get(SEEN_ALIAS.get(p, p), 0)
                body = ("%d\n" % n).encode()
                s.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
            except (OSError, IndexError, ValueError):
                pass

    class S(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = S(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def main():
    base = int(sys.argv[1]) if len(sys.argv) > 1 else 58443
    serve_tls(base, context("rsa.pem", "rsa.key"))
    serve_tls(base + 1, context("ecdsa.pem", "ecdsa.key"))
    serve_tls(base + 2, context("expired.pem", "expired.key"))
    serve_tls(base + 3, context("future.pem", "future.key"))
    serve_tls(base + 4, context("wrongname.pem", "wrongname.key"))
    serve_tls(base + 5, context("badsig.pem", "rsa.key"))
    serve_tls(base + 6, context("mitm.pem", "mitm.key"))
    serve_tls(base + 7, context("rsa.pem", "rsa.key", max_version=ssl.TLSVersion.TLSv1_2))
    serve_tls(base + 8, context("rsa.pem", "rsa.key", groups="prime256v1"))
    for i, mode in enumerate(["finished", "verify", "tag", "replay", "pieces", "merge", "keyupdate"]):
        front = base + 17 + i      # 58460 + i
        back = base + 117 + i      # 58560 + i
        keylog = os.path.join(KEYLOG_DIR, "%d.keys" % back)
        serve_tls(back, context("rsa.pem", "rsa.key", keylog=keylog))
        middle(front, back, keylog, mode)
        # /seen reports a middle's requests under its front port.
        SEEN_ALIAS[front] = back
    control(base + 27)            # 58470
    while True:
        time.sleep(3600)


SEEN_ALIAS = {}

if __name__ == "__main__":
    main()
