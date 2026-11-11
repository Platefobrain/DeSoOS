// HTTP answer parser test without a network (NET TEST 5): user/lib/http.rs on a table of
// answers – valid ones, every rule netget refuses, the connection's end – each fed whole, byte
// by byte and in random pieces: the result (head, body, trailers, error, outcome) must be the
// same for every split.  Then random mutations of the valid answers: never a panic, the body
// the sink got always matches the parser's count.  "httptest: N checks OK".
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../lib/http.rs"]
mod http;

use desoos::*;
use http::{End, Error, Outcome, Parser, Sink};

entry!(main);

static mut P: Parser = Parser::new();

/// What one run gave.
#[derive(PartialEq, Eq, Clone, Copy)]
struct Result_ {
    err: Option<&'static str>,
    status: u32,
    outcome: Outcome,
    body_len: u64,
    body_sum: u64,
    trailers: u64,
    heads: u32,
}

struct Collect {
    len: u64,
    sum: u64,
    trailers: u64,
    heads: u32,
}

impl Sink for Collect {
    fn head(&mut self, _raw: &[u8], _interim: bool) {
        self.heads += 1;
    }
    fn body(&mut self, data: &[u8]) -> Result<(), ()> {
        for &b in data {
            self.sum = self.sum.wrapping_mul(31).wrapping_add(b as u64 + 1);
        }
        self.len += data.len() as u64;
        Ok(())
    }
    fn trailers(&mut self, raw: &[u8]) {
        self.trailers = raw.len() as u64 + 1;
    }
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Feeds `input` in pieces given by `cut` (piece sizes), then ends the connection.
fn run(input: &[u8], end: End, cut: &mut dyn FnMut() -> usize) -> (Result_, u64) {
    let p = unsafe { &mut *core::ptr::addr_of_mut!(P) };
    p.reset();
    let mut c = Collect { len: 0, sum: 0, trailers: 0, heads: 0 };
    let mut err = None;
    let mut i = 0;
    while i < input.len() {
        let k = cut().clamp(1, input.len() - i);
        if let Err(e) = p.feed(&input[i..i + k], &mut c) {
            err = Some(match e {
                Error::Malformed(w) => w,
                Error::Sink => "sink",
            });
            break;
        }
        i += k;
    }
    let outcome = if err.is_some() { Outcome::Cut } else { p.finish(end) };
    let status = p.answer.map(|a| a.status).unwrap_or(0);
    (Result_ { err, status, outcome, body_len: c.len, body_sum: c.sum, trailers: c.trailers, heads: c.heads }, p.body)
}

/// Expected: Ok(status, body) with the outcome, or an error containing the text.
enum Want {
    Ok(u32, &'static [u8], Outcome),
    Err(&'static str),
}

fn sum(b: &[u8]) -> u64 {
    let mut s = 0u64;
    for &x in b {
        s = s.wrapping_mul(31).wrapping_add(x as u64 + 1);
    }
    s
}

const CASES: &[(&str, &[u8], End, Want)] = &[
    // Valid.
    ("length", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", End::Clean, Want::Ok(200, b"hello", Outcome::Complete)),
    ("http/1.0 length", b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok", End::Unclean, Want::Ok(200, b"ok", Outcome::Complete)),
    ("close-delimited", b"HTTP/1.1 200 OK\r\n\r\nuntil the end", End::Clean, Want::Ok(200, b"until the end", Outcome::Complete)),
    ("close-delimited unclean", b"HTTP/1.1 200 OK\r\n\r\npart", End::Unclean, Want::Ok(200, b"part", Outcome::Cut)),
    ("chunked", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5;name=value\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n", End::Clean, Want::Ok(200, b"Wikipedia in\r\n\r\nchunks.", Outcome::Complete)),
    ("chunked, upper case", b"HTTP/1.1 200 OK\r\ntransfer-encoding: CHUNKED\r\n\r\na\r\n0123456789\r\n0\r\n\r\n", End::Unclean, Want::Ok(200, b"0123456789", Outcome::Complete)),
    ("chunked trailer", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Checksum: 1234\r\nX-Other: a\r\n\r\n", End::Clean, Want::Ok(200, b"abc", Outcome::Complete)),
    ("chunked ext on 0", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0;a=b\r\n\r\n", End::Clean, Want::Ok(200, b"hi", Outcome::Complete)),
    ("chunked quoted ext", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2 ; q=\"a \\\"b\\\" ;c\"\r\nhi\r\n0\r\n\r\n", End::Clean, Want::Ok(200, b"hi", Outcome::Complete)),
    ("chunked 16 hex digits", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0000000000000003\r\nabc\r\n0\r\n\r\n", End::Clean, Want::Ok(200, b"abc", Outcome::Complete)),
    ("100 continue", b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", End::Clean, Want::Ok(200, b"ok", Outcome::Complete)),
    ("204", b"HTTP/1.1 204 No Content\r\n\r\n", End::Clean, Want::Ok(204, b"", Outcome::Complete)),
    ("304 metadata", b"HTTP/1.1 304 Not Modified\r\nContent-Length: 1234\r\nContent-Encoding: gzip\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", End::Clean, Want::Ok(304, b"", Outcome::Complete)),
    ("205 empty", b"HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n", End::Clean, Want::Ok(205, b"", Outcome::Complete)),
    ("205 chunked 0", b"HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", End::Clean, Want::Ok(205, b"", Outcome::Complete)),
    ("content-encoding identity", b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: 1\r\n\r\nx", End::Clean, Want::Ok(200, b"x", Outcome::Complete)),
    ("connection list", b"HTTP/1.1 200 OK\r\nConnection: close, , X-Foo\r\nConnection: keep-alive\r\nContent-Length: 1\r\n\r\nx", End::Clean, Want::Ok(200, b"x", Outcome::Complete)),
    ("404 framed", b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nno\n", End::Clean, Want::Ok(404, b"no\n", Outcome::Complete)),
    // Cut short.
    ("length cut", b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello", End::Clean, Want::Ok(200, b"hello", Outcome::Cut)),
    ("chunked cut", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n", End::Clean, Want::Ok(200, b"hello", Outcome::Cut)),
    ("chunked cut in trailers", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-A: 1\r\n", End::Clean, Want::Ok(200, b"", Outcome::Cut)),
    ("head cut", b"HTTP/1.1 200 OK\r\nContent-Le", End::Clean, Want::Ok(0, b"", Outcome::NoAnswer)),
    // Refused.
    ("TE + CL", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n3\r\nabc\r\n0\r\n\r\n", End::Clean, Want::Err("both Transfer-Encoding and Content-Length")),
    ("TE gzip", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n", End::Clean, Want::Err("unsupported transfer coding")),
    ("TE twice", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", End::Clean, Want::Err("Transfer-Encoding more than once")),
    ("TE in 1.0", b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", End::Clean, Want::Err("HTTP/1.0 answer")),
    ("CE gzip", b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\n\r\nabc", End::Clean, Want::Err("unsupported content coding")),
    ("CE gzip empty", b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n", End::Clean, Want::Err("unsupported content coding")),
    ("CE br", b"HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", End::Clean, Want::Err("unsupported content coding")),
    ("CL twice", b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nabcd", End::Clean, Want::Err("more than once")),
    ("CL not a number", b"HTTP/1.1 200 OK\r\nContent-Length: 4a\r\n\r\nabcd", End::Clean, Want::Err("not a number")),
    ("extra after length", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokxyz", End::Clean, Want::Err("after the end")),
    ("extra after chunked", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX", End::Clean, Want::Err("after the end")),
    ("204 body", b"HTTP/1.1 204 No Content\r\n\r\nX", End::Clean, Want::Err("after the end")),
    ("204 TE", b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n", End::Clean, Want::Err("204")),
    ("204 CL", b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", End::Clean, Want::Err("204")),
    ("205 body", b"HTTP/1.1 205 Reset Content\r\n\r\nX", End::Clean, Want::Err("205")),
    ("205 chunked body", b"HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nX\r\n0\r\n\r\n", End::Clean, Want::Err("205")),
    ("205 length", b"HTTP/1.1 205 Reset Content\r\nContent-Length: 1\r\n\r\nX", End::Clean, Want::Err("205")),
    ("100 with CL", b"HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", End::Clean, Want::Err("1xx")),
    ("101", b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n", End::Clean, Want::Err("101")),
    ("5 interim", b"HTTP/1.1 100 A\r\n\r\nHTTP/1.1 100 A\r\n\r\nHTTP/1.1 100 A\r\n\r\nHTTP/1.1 100 A\r\n\r\nHTTP/1.1 100 A\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", End::Clean, Want::Err("more than 4")),
    ("bad size", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", End::Clean, Want::Err("not hexadecimal")),
    ("17 hex digits", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n00000000000000003\r\nabc\r\n0\r\n\r\n", End::Clean, Want::Err("16 hex digits")),
    ("overflow", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nab", End::Clean, Want::Ok(200, b"ab", Outcome::Cut)),
    ("overflow total", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\nffffffffffffffff\r\n", End::Clean, Want::Err("overflows")),
    ("no CRLF after data", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabc\r\n0\r\n\r\n", End::Clean, Want::Err("no CRLF after")),
    ("bare LF size", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\nab\r\n0\r\n\r\n", End::Clean, Want::Err("without CRLF")),
    ("bad ext", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2 junk\r\nab\r\n0\r\n\r\n", End::Clean, Want::Err("chunk extension")),
    ("unclosed quote", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;a=\"b\r\nab\r\n0\r\n\r\n", End::Clean, Want::Err("chunk extension")),
    ("backslash at end", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;a=\"b\\\r\nab\r\n0\r\n\r\n", End::Clean, Want::Err("chunk extension")),
    ("empty ext name", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;=b\r\nab\r\n0\r\n\r\n", End::Clean, Want::Err("chunk extension")),
    ("trailer CL", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 5\r\n\r\n", End::Clean, Want::Err("may not be a trailer")),
    ("trailer TE", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\ntransfer-encoding: chunked\r\n\r\n", End::Clean, Want::Err("may not be a trailer")),
    ("trailer named by Connection", b"HTTP/1.1 200 OK\r\nConnection: close, X-Foo\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nx-foo: 1\r\n\r\n", End::Clean, Want::Err("named by Connection")),
    ("trailer named by 2nd Connection", b"HTTP/1.1 200 OK\r\nConnection: close\r\nConnection: X-Bar\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Bar: 1\r\n\r\n", End::Clean, Want::Err("named by Connection")),
    ("Connection syntax", b"HTTP/1.1 200 OK\r\nConnection: close, x y\r\nContent-Length: 0\r\n\r\n", End::Clean, Want::Err("bad Connection")),
    ("Connection names CL", b"HTTP/1.1 200 OK\r\nConnection: close, Content-Length\r\nContent-Length: 0\r\n\r\n", End::Clean, Want::Err("end-to-end")),
    ("status line", b"HTTP/2 200 OK\r\n\r\n", End::Clean, Want::Err("status line")),
    ("folded", b"HTTP/1.1 200 OK\r\nX-A: 1\r\n  2\r\nContent-Length: 0\r\n\r\n", End::Clean, Want::Err("folded")),
    ("no colon", b"HTTP/1.1 200 OK\r\nno colon here\r\nContent-Length: 2\r\n\r\nok", End::Clean, Want::Err("without ':'")),
    ("NUL in value", b"HTTP/1.1 200 OK\r\nX-A: a\x00b\r\nContent-Length: 0\r\n\r\n", End::Clean, Want::Err("control character")),
    ("space in name", b"HTTP/1.1 200 OK\r\nX A: 1\r\nContent-Length: 0\r\n\r\n", End::Clean, Want::Err("header name")),
];

fn check_case(name: &str, input: &[u8], end: End, want: &Want, n: &mut u32) -> Result<(), ()> {
    let (whole, _) = run(input, end, &mut || usize::MAX);
    let ok = match *want {
        Want::Ok(status, body, outcome) => whole.err.is_none() && whole.status == status && whole.outcome == outcome && whole.body_len == body.len() as u64 && whole.body_sum == sum(body),
        Want::Err(text) => whole.err.is_some_and(|e| e.contains(text)),
    };
    *n += 1;
    if !ok {
        println!("httptest: FAIL {}: error {:?}, status {}, body {} bytes", name, whole.err, whole.status, whole.body_len);
        return Err(());
    }
    // Byte by byte, and random pieces with several seeds – the same result.
    let (bytes, _) = run(input, end, &mut || 1);
    *n += 1;
    if bytes != whole {
        println!("httptest: FAIL {}: byte by byte differs (error {:?})", name, bytes.err);
        return Err(());
    }
    for seed in 1..=8u64 {
        let mut rng = Rng(seed * 0x9e37_79b9_7f4a_7c15);
        let (pieces, _) = run(input, end, &mut || 1 + rng.below(9));
        *n += 1;
        if pieces != whole {
            println!("httptest: FAIL {}: pieces (seed {}) differ (error {:?})", name, seed, pieces.err);
            return Err(());
        }
    }
    Ok(())
}

fn main(_args: Args) -> i32 {
    let mut n = 0u32;
    for (name, input, end, want) in CASES {
        if check_case(name, input, *end, want, &mut n).is_err() {
            return 1;
        }
    }
    // A chunked body of 40 000 bytes in chunks of 1..300 bytes, split anywhere.
    let mut big = [0u8; 48 * 1024];
    let mut len = 0;
    let mut put = |b: &[u8], len: &mut usize| {
        big[*len..*len + b.len()].copy_from_slice(b);
        *len += b.len();
    };
    put(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", &mut len);
    let mut rng = Rng(42);
    let mut want = 0u64;
    let mut want_len = 0u64;
    let mut i = 0u32;
    while want_len < 40_000 {
        let k = 1 + rng.below(300);
        let mut hex = [0u8; 8];
        let mut h = 8;
        let mut v = k;
        loop {
            h -= 1;
            hex[h] = b"0123456789abcdef"[v & 15];
            v >>= 4;
            if v == 0 {
                break;
            }
        }
        put(&hex[h..], &mut len);
        put(b"\r\n", &mut len);
        for _ in 0..k {
            let b = (i * 7 + i / 251) as u8;
            put(&[b], &mut len);
            want = want.wrapping_mul(31).wrapping_add(b as u64 + 1);
            i += 1;
        }
        want_len += k as u64;
        put(b"\r\n", &mut len);
    }
    put(b"0\r\n\r\n", &mut len);
    let input = &big[..len];
    let (whole, _) = run(input, End::Clean, &mut || usize::MAX);
    n += 1;
    if whole.err.is_some() || whole.body_len != want_len || whole.body_sum != want || whole.outcome != Outcome::Complete {
        println!("httptest: FAIL big chunked: {:?} {} bytes", whole.err, whole.body_len);
        return 1;
    }
    for seed in 1..=4u64 {
        let mut r = Rng(seed);
        let (p, _) = run(input, End::Clean, &mut || 1 + r.below(1500));
        n += 1;
        if p != whole {
            println!("httptest: FAIL big chunked, pieces seed {}", seed);
            return 1;
        }
    }
    // Mutations of the valid answers: change, delete or insert a byte – never a panic, the
    // body the sink got matches the parser's count.
    let mut rng = Rng(7);
    let mut buf = [0u8; 512];
    let mut mutations = 0;
    for _ in 0..200 {
        for (_, input, end, want) in CASES {
            if !matches!(want, Want::Ok(..)) || input.len() + 1 > buf.len() {
                continue;
            }
            let mut l = input.len();
            buf[..l].copy_from_slice(input);
            let at = rng.below(l);
            match rng.below(3) {
                0 => buf[at] = rng.next() as u8,
                1 => {
                    buf.copy_within(at + 1..l, at);
                    l -= 1;
                }
                _ => {
                    buf.copy_within(at..l, at + 1);
                    buf[at] = b"\r\n:;\"\\0 9aF"[rng.below(11)];
                    l += 1;
                }
            }
            let mut r = Rng(rng.next() | 1);
            let (res, counted) = run(&buf[..l], *end, &mut || 1 + r.below(7));
            mutations += 1;
            if res.body_len != counted {
                println!("httptest: FAIL mutation: sink got {} bytes, parser counted {}", res.body_len, counted);
                return 1;
            }
        }
    }
    n += 1;
    println!("httptest: {} checks OK ({} answers, every split; {} mutations)", n, CASES.len() + 1, mutations);
    0
}
