# HTTP/1.1 answers for netget's tests – shared by tests/http-stub.py (NET TEST, plain HTTP)
# and tests/tls-stub.py (TLS TEST, over TLS).  page11(path) -> (parts, end) or None:
# parts are sent one by one with a short pause (separate TCP segments / TLS records), end is
#   "close"   the normal end: FIN (http) or close_notify, then FIN (https)
#   "fin"     the TCP connection ends (https: without close_notify)
#   "reset"   a TCP reset after 0.5 s
#   "linger"  the answer is whole, but the server keeps the connection open for 6 s
# The guest's expected exit codes are in user/bin/tlstest.rs and user/bin/nettest.rs.
import random

H11 = b"HTTP/1.1 200 OK\r\nServer: desoos-test\r\n"
CHUNKED = H11 + b"Transfer-Encoding: chunked\r\n\r\n"
CHUNKED_BODY = [CHUNKED, b"7;lang=en\r\nchu", b"nked\r\n1\r\n \r\n6\r\nwo", b"rks\n\r\n0\r\n\r\n"]
BIG = 1024 * 1024
_big = None


def pattern(n):
    return bytes(((i * 7 + i // 251) & 0xFF) for i in range(n))


def big_chunked():
    """1 MiB of the /big pattern in chunks of random sizes (fixed seed), in 64 KiB pieces."""
    global _big
    if _big is None:
        body = pattern(BIG)
        rnd = random.Random(76)
        out = bytearray(CHUNKED)
        i = 0
        while i < len(body):
            k = min(rnd.randint(1, 20000), len(body) - i)
            out += b"%x\r\n" % k + body[i:i + k] + b"\r\n"
            i += k
        out += b"0\r\n\r\n"
        _big = [bytes(out[j:j + 65536]) for j in range(0, len(out), 65536)]
    return _big


def chunked(*lines):
    return [CHUNKED + b"".join(lines)]


PAGES = {
    # Whole answers (exit 0).
    "/chunked": (CHUNKED_BODY, "close"),
    "/chunked-trailer": (chunked(b"3\r\nabc\r\n0\r\nX-Checksum: 99\r\n\r\n"), "close"),
    "/chunked-quoted": (chunked(b"2;q=\"a \\\"b\\\" ;c\"\r\nhi\r\n0\r\n\r\n"), "close"),
    "/chunked-ext0": (chunked(b"2\r\nhi\r\n0;a=b\r\n\r\n"), "close"),
    "/chunked-hex16": (chunked(b"0000000000000002\r\nhi\r\n0\r\n\r\n"), "close"),
    "/continue": ([b"HTTP/1.1 100 Continue\r\n\r\n", H11 + b"Content-Length: 15\r\n\r\nafter continue\n"], "close"),
    "/204-empty": ([b"HTTP/1.1 204 No Content\r\n\r\n"], "close"),
    "/205-empty": ([b"HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n"], "close"),
    "/205-chunked0": ([b"HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"], "close"),
    # 304: accepted (its fields are metadata), but not 2xx – exit 4 with "HTTP 304".
    "/304-cl": ([b"HTTP/1.1 304 Not Modified\r\nContent-Length: 1234\r\n\r\n"], "close"),
    "/304-meta": ([b"HTTP/1.1 304 Not Modified\r\nContent-Encoding: gzip\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"], "close"),
    "/304-te-params": ([b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: gzip;q=1, chunked\r\n\r\n"], "close"),
    # Content-Encoding is a list of plain tokens (RFC 9110 §8.4) – parameters refused, also in 304.
    "/ce-params": ([H11 + b"Content-Encoding: identity;level=1\r\nContent-Length: 1\r\n\r\nx"], "close"),
    "/304-ce-params": ([b"HTTP/1.1 304 Not Modified\r\nContent-Encoding: gzip;q=1\r\n\r\n"], "close"),
    # The end of the connection after a whole answer.
    "/chunked-rst-after": (CHUNKED_BODY, "reset"),
    "/chunked-fin-after": (CHUNKED_BODY, "fin"),
    "/linger": (CHUNKED_BODY, "linger"),
    # Cut short (exit 3).
    "/chunked-cut": (chunked(b"5\r\nhello\r\n"), "fin"),
    "/chunked-reset": (chunked(b"5\r\nhello\r\n"), "reset"),
    # Refused (exit 4).
    "/chunked-badsize": (chunked(b"zz\r\nab\r\n0\r\n\r\n"), "close"),
    "/chunked-overflow": (chunked(b"1\r\na\r\nffffffffffffffff\r\n"), "close"),
    "/chunked-nocrlf": (chunked(b"2\r\nabc\r\n0\r\n\r\n"), "close"),
    "/chunked-lf": (chunked(b"2\nab\r\n0\r\n\r\n"), "close"),
    "/chunked-extra": ([CHUNKED + b"2\r\nhi\r\n0\r\n\r\n", b"X"], "close"),
    "/chunked-hex17": (chunked(b"00000000000000002\r\nhi\r\n0\r\n\r\n"), "close"),
    "/chunked-badext": (chunked(b"2 junk\r\nhi\r\n0\r\n\r\n"), "close"),
    "/chunked-badquote": (chunked(b"2;a=\"b\r\nhi\r\n0\r\n\r\n"), "close"),
    "/chunked-badbackslash": (chunked(b"2;a=\"b\\\r\nhi\r\n0\r\n\r\n"), "close"),
    "/te-gzip": ([H11 + b"Transfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"], "close"),
    "/te-cl": ([H11 + b"Transfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n2\r\nhi\r\n0\r\n\r\n"], "close"),
    "/te-http10": ([b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n"], "close"),
    "/te-twice": ([H11 + b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"], "close"),
    "/ce-gzip": ([H11 + b"Content-Encoding: gzip\r\nContent-Length: 3\r\n\r\nabc"], "close"),
    "/ce-br": ([H11 + b"Content-Encoding: br\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"], "close"),
    "/ce-gzip-empty": ([H11 + b"Content-Encoding: gzip\r\nContent-Length: 0\r\n\r\n"], "close"),
    "/204-body": ([b"HTTP/1.1 204 No Content\r\n\r\n", b"X"], "close"),
    "/204-te": ([b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n"], "close"),
    "/204-cl": ([b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"], "close"),
    "/205-body": ([b"HTTP/1.1 205 Reset Content\r\n\r\n", b"X"], "close"),
    "/100-cl": ([b"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n", H11 + b"Content-Length: 0\r\n\r\n"], "close"),
    "/early5": ([b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\n" * 5 + H11 + b"Content-Length: 0\r\n\r\n"], "close"),
    "/switching": ([b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n"], "close"),
    "/trailer-cl": (chunked(b"0\r\nContent-Length: 5\r\n\r\n"), "close"),
    "/trailer-te": (chunked(b"0\r\ntransfer-encoding: chunked\r\n\r\n"), "close"),
    "/trailer-connection": ([H11 + b"Connection: close, X-Foo\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nx-foo: 1\r\n\r\n"], "close"),
    "/trailer-connection2": ([H11 + b"Connection: close\r\nConnection: X-Bar\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Bar: 1\r\n\r\n"], "close"),
    "/connection-bad": ([H11 + b"Connection: close, x y\r\nContent-Length: 0\r\n\r\n"], "close"),
    "/connection-cl": ([H11 + b"Connection: close, Content-Length\r\nContent-Length: 0\r\n\r\n"], "close"),
}


def page11(path):
    if path == "/chunked-big":
        return big_chunked(), "close"
    return PAGES.get(path)
