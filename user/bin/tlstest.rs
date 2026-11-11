// tlstest – the HTTPS tests of DeSoTLS (the kernel TLS TEST runs it).
//
//   tlstest       common/desotls/tls_tests.rs: RFC 8448's handshake byte for byte, records,
//                 KeyUpdate, HelloRetryRequest, changed server messages – no network:
//                 "tlstest: N checks OK (DeSoTLS x.y.z)"
//   tlstest net   (through `init test`, net0 running) /bin/netget https:// against
//                 tests/tls-stub.py on the host (tls.desoos = 10.0.2.2, names from
//                 tests/dns-stub.py): every case below must end with its exit code, the
//                 pages must arrive whole, and a refused handshake must not let the request
//                 reach the server (tls-stub's /seen counter); HTTP/1.1 answers from
//                 tests/http_pages.py (chunked, 1xx, 204 / 205 / 304, trailers, the end after
//                 a whole answer): "tlstest net: N cases OK"
//
// A failure prints "tlstest: FAIL ..." and exits with 1.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;
#[path = "../../common/desotls/mod.rs"]
mod desotls;
#[path = "../../common/desotls/tls_tests.rs"]
mod tls_tests;

use desoos::*;

entry!(main);

/// The test CA (tests/tls/ca.pem) – the guest trusts it only through --anchor.
const TEST_CA: &[u8] = include_bytes!("../../tests/tls/ca.pem");
const CA_PATH: &str = "/tls-ca.pem";
const OUT: &str = "/tls.out";
/// netget's stderr, for the cases that check its words.
const ERR: &str = "/tls.err";

static mut FILE: [u8; 1 << 20 | 4096] = [0; 1 << 20 | 4096];
static mut REPLY: [u8; 4096] = [0; 4096];
static mut ERRBUF: [u8; 4096] = [0; 4096];

macro_rules! fail {
    ($($a:tt)*) => {{
        println!("tlstest: FAIL {}", format_args!($($a)*));
        return 1;
    }};
}

fn offline() -> i32 {
    match tls_tests::run() {
        Ok(n) => {
            println!("tlstest: {} checks OK (DeSoTLS {})", n, desotls::VERSION);
            0
        }
        Err(f) => fail!("{} case {}", f.group, f.case),
    }
}

/// netd's admin request (as nettest does).
fn ask(req: &str) -> &'static str {
    let Ok(c) = svc_connect("net0") else { return "" };
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(REPLY) };
    let mut info = RecvInfo::default();
    let r = if chan_send(c, req.as_bytes(), 0) == 0 { chan_recv(c, buf, 0, &mut info) } else { -1 };
    close(c);
    if r < 0 { "" } else { core::str::from_utf8(&buf[..r as usize]).unwrap_or("") }
}

/// The number of TCP connections netd holds (closing ones wait in TIME_WAIT for 2 s).
fn tcp_in_use() -> u32 {
    let st = ask("status");
    let line = st.lines().find(|l| l.starts_with("netd-status")).unwrap_or("");
    line.split_whitespace().find_map(|w| w.strip_prefix("tcp=")).and_then(|v| v.parse().ok()).unwrap_or(0)
}

fn netget(args: &[&str]) -> u64 {
    netget_to(args, 1)
}

/// netget with its stderr on handle `err`.
fn netget_to(args: &[&str], err: u64) -> u64 {
    // netd has 8 TCP connections; earlier ones may still be closing – wait for room.
    let t = uptime_ms();
    while tcp_in_use() >= 6 && uptime_ms() - t < 8000 {
        sleep_ms(50);
    }
    let pid = spawn_ex("/bin/netget", args, &[(1, 1), (err, 2), (SVC, SVC)], 0);
    if pid <= 0 {
        return 999;
    }
    wait(pid as u64, 0).map(|(_, code)| code).unwrap_or(998)
}

/// The file netget wrote (-o).
fn read_out() -> &'static [u8] {
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(FILE) };
    let fd = open(OUT, O_READ);
    if fd < 0 {
        return &[];
    }
    let mut n = 0;
    loop {
        let r = read(fd as u64, &mut buf[n..]);
        if r <= 0 {
            break;
        }
        n += r as usize;
        if n == buf.len() {
            break;
        }
    }
    close(fd as u64);
    &buf[..n]
}

/// tls-stub's count of HTTP requests that reached the server behind `port`.
fn seen(port: u16) -> Option<u64> {
    let mut url = [0u8; 64];
    let mut n = 0;
    for p in [b"http://tls.desoos:58470/seen?port=".as_slice()] {
        url[n..n + p.len()].copy_from_slice(p);
        n += p.len();
    }
    let mut digits = [0u8; 5];
    let mut v = port;
    for i in (0..5).rev() {
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    url[n..n + 5].copy_from_slice(&digits);
    n += 5;
    let url = core::str::from_utf8(&url[..n]).ok()?;
    if netget(&["netget", "-o", OUT, url]) != 0 {
        return None;
    }
    core::str::from_utf8(read_out()).ok()?.trim().parse().ok()
}

fn url(port: u16, path: &str, out: &mut [u8; 96]) -> usize {
    let mut n = 0;
    let mut put = |b: &[u8]| {
        out[n..n + b.len()].copy_from_slice(b);
        n += b.len();
    };
    put(b"https://tls.desoos:");
    let mut d = [0u8; 5];
    let mut v = port;
    for i in (0..5).rev() {
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    put(&d);
    put(path.as_bytes());
    n
}

/// netget https://tls.desoos:<port><path> with --anchor and the extra options; its code.
fn get(port: u16, path: &str, extra: &[&str]) -> u64 {
    get_to(port, path, extra, 1)
}

/// The same with netget's stderr captured: (code, what it wrote there).
fn get_err(port: u16, path: &str, extra: &[&str]) -> (u64, &'static str) {
    let fd = open(ERR, O_WRITE | O_CREATE | O_TRUNC);
    if fd < 0 {
        return (997, "");
    }
    let code = get_to(port, path, extra, fd as u64);
    close(fd as u64);
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(ERRBUF) };
    let fd = open(ERR, O_READ);
    let n = if fd >= 0 { read(fd as u64, buf).max(0) as usize } else { 0 };
    if fd >= 0 {
        close(fd as u64);
    }
    unlink(ERR);
    (code, core::str::from_utf8(&buf[..n]).unwrap_or(""))
}

fn get_to(port: u16, path: &str, extra: &[&str], err: u64) -> u64 {
    let mut u = [0u8; 96];
    let n = url(port, path, &mut u);
    let u = core::str::from_utf8(&u[..n]).unwrap_or("");
    let mut args: [&str; 12] = [""; 12];
    let mut k = 0;
    for a in ["netget", "-o", OUT, "--anchor", CA_PATH] {
        args[k] = a;
        k += 1;
    }
    for a in extra {
        args[k] = a;
        k += 1;
    }
    args[k] = u;
    k += 1;
    unlink(OUT);
    netget_to(&args[..k], err)
}

fn net() -> i32 {
    // init starts services right before this program – wait for net0's DHCP address.
    let t = uptime_ms();
    while !ask("status").lines().any(|l| l.starts_with("netd-status") && l.split_whitespace().any(|w| w == "dhcp=bound")) {
        if uptime_ms() - t > 10_000 {
            fail!("net0 has no DHCP address after 10 s");
        }
        sleep_ms(50);
    }
    let r = ask("dns 10.0.2.2:53530");
    if !r.starts_with("DNS server 10.0.2.2:53530") {
        fail!("dns set: {:?}", r.trim());
    }
    let fd = open(CA_PATH, O_WRITE | O_CREATE | O_TRUNC);
    if fd < 0 || write(fd as u64, TEST_CA) != TEST_CA.len() as i64 {
        fail!("cannot write {}", CA_PATH);
    }
    close(fd as u64);
    let mut cases = 0;

    // Pages that must arrive whole.
    let ok: [(u16, &str, &[&str], &[u8]); 7] = [
        (58443, "/hello", &["--cipher", "aes"], b"Hello over TLS\n"),
        (58443, "/hello", &["--cipher", "chacha"], b"Hello over TLS\n"),
        (58444, "/hello", &[], b"Hello over TLS\n"),
        (58443, "/hello", &["--key-update"], b"Hello over TLS\n"),
        (58443, "/cl0", &[], b""),
        (58443, "/nocl-notify", &[], b"until the end\n"),
        (58443, "/cl-fin", &[], b"complete\n"),
    ];
    let mut hello_ms = 0;
    for (port, path, extra, body) in ok {
        let t0 = uptime_ms();
        let code = get(port, path, extra);
        if hello_ms == 0 {
            hello_ms = uptime_ms() - t0;
        }
        let got = read_out();
        if code != 0 || got != body {
            fail!("{}{} {:?}: exit {}, {} bytes (expected 0, {} bytes)", port, path, extra, code, got.len(), body.len());
        }
        cases += 1;
    }
    // 1 MiB with a pattern.
    let t0 = uptime_ms();
    let code = get(58443, "/big", &[]);
    let big_ms = (uptime_ms() - t0).max(1);
    let got = read_out();
    let good = got.len() == 1 << 20 && got.iter().enumerate().all(|(i, &b)| b == ((i * 7 + i / 251) & 0xff) as u8);
    if code != 0 || !good {
        fail!("/big: exit {}, {} bytes, pattern {}", code, got.len(), good);
    }
    cases += 1;
    // The middles that only cut and join records, or insert KeyUpdates (ChaCha20).
    for port in [58464u16, 58465, 58466] {
        let code = get(port, "/hello", &["--cipher", "chacha"]);
        if code != 0 || read_out() != b"Hello over TLS\n" {
            fail!("{}: exit {}", port, code);
        }
        cases += 1;
    }

    // HTTP framing.
    let framing: [(&str, u64); 8] = [
        ("/dupcl", 4),
        ("/dupsame", 4),
        ("/te-http10", 4),
        ("/extra", 4),
        ("/badhdr", 4),
        ("/404", 4),
        ("/nocl-fin", 3),
        ("/cut", 3),
    ];
    for (path, want) in framing {
        let code = get(58443, path, &[]);
        if code != want {
            fail!("{}: exit {} (expected {})", path, code, want);
        }
        cases += 1;
    }
    // Resets (netd's empty message): in the middle, without a length – cut (3); after the
    // whole answer by its Content-Length – a warning only (0, as curl and Go).
    for (path, want) in [("/reset", 3u64), ("/nocl-reset", 3), ("/cl-reset", 0)] {
        let code = get(58443, path, &[]);
        if code != want {
            fail!("{}: exit {} (expected {})", path, code, want);
        }
        cases += 1;
    }

    // HTTP/1.1 (tests/http_pages.py): whole answers, chunked or not.
    let whole: [(&str, &[u8]); 9] = [
        ("/chunked", b"chunked works\n"),
        ("/chunked-trailer", b"abc"),
        ("/chunked-quoted", b"hi"),
        ("/chunked-ext0", b"hi"),
        ("/chunked-hex16", b"hi"),
        ("/continue", b"after continue\n"),
        ("/204-empty", b""),
        ("/205-empty", b""),
        ("/205-chunked0", b""),
    ];
    for (path, body) in whole {
        let code = get(58443, path, &[]);
        let got = read_out();
        if code != 0 || got != body {
            fail!("{}: exit {}, {} bytes (expected 0, {} bytes)", path, code, got.len(), body.len());
        }
        cases += 1;
    }
    let code = get(58443, "/chunked-big", &[]);
    let got = read_out();
    let good = got.len() == 1 << 20 && got.iter().enumerate().all(|(i, &b)| b == ((i * 7 + i / 251) & 0xff) as u8);
    if code != 0 || !good {
        fail!("/chunked-big: exit {}, {} bytes, pattern {}", code, got.len(), good);
    }
    cases += 1;
    // Records cut, joined, KeyUpdates in between: the same chunked answer.
    for port in [58464u16, 58465, 58466] {
        let code = get(port, "/chunked", &["--cipher", "chacha"]);
        if code != 0 || read_out() != b"chunked works\n" {
            fail!("{} /chunked: exit {}", port, code);
        }
        cases += 1;
    }
    // 304: accepted (its Content-Length / Transfer-Encoding / Content-Encoding describe the
    // 200 not sent), but not 2xx.
    for path in ["/304-cl", "/304-meta", "/304-te-params"] {
        let (code, err) = get_err(58443, path, &[]);
        if code != 4 || !err.contains("netget: HTTP 304") {
            fail!("{}: exit {}, {:?}", path, code, err.trim());
        }
        cases += 1;
    }
    // Content-Encoding with parameters (RFC 9110 §8.4: plain tokens) – malformed, also in 304.
    for path in ["/ce-params", "/304-ce-params"] {
        let (code, err) = get_err(58443, path, &[]);
        if code != 4 || !err.contains("bad Content-Encoding") {
            fail!("{}: exit {}, {:?}", path, code, err.trim());
        }
        cases += 1;
    }
    // After a whole answer: a reset or FIN without close_notify – a warning; a server that
    // keeps the connection open – a warning after 2 s, not a hang.
    let after: [(&str, &str); 3] = [
        ("/chunked-rst-after", "reset after the whole answer"),
        ("/chunked-fin-after", "without close_notify"),
        ("/linger", "did not close the connection"),
    ];
    for (path, words) in after {
        let t0 = uptime_ms();
        let (code, err) = get_err(58443, path, &[]);
        let ms = uptime_ms() - t0;
        if code != 0 || !err.contains(words) || read_out() != b"chunked works\n" || ms > 4000 {
            fail!("{}: exit {} in {} ms, {:?}", path, code, ms, err.trim());
        }
        cases += 1;
    }
    // Cut short before the last chunk, and every refused answer.
    let bad: [(&str, u64); 30] = [
        ("/chunked-cut", 3),
        ("/chunked-reset", 3),
        ("/chunked-badsize", 4),
        ("/chunked-overflow", 4),
        ("/chunked-nocrlf", 4),
        ("/chunked-lf", 4),
        ("/chunked-extra", 4),
        ("/chunked-hex17", 4),
        ("/chunked-badext", 4),
        ("/chunked-badquote", 4),
        ("/chunked-badbackslash", 4),
        ("/te-gzip", 4),
        ("/te-cl", 4),
        ("/te-twice", 4),
        ("/ce-gzip", 4),
        ("/ce-br", 4),
        ("/ce-gzip-empty", 4),
        ("/204-body", 4),
        ("/204-te", 4),
        ("/204-cl", 4),
        ("/205-body", 4),
        ("/100-cl", 4),
        ("/early5", 4),
        ("/switching", 4),
        ("/trailer-cl", 4),
        ("/trailer-te", 4),
        ("/trailer-connection", 4),
        ("/trailer-connection2", 4),
        ("/connection-bad", 4),
        ("/connection-cl", 4),
    ];
    for (path, want) in bad {
        let code = get(58443, path, &[]);
        if code != want {
            fail!("{}: exit {} (expected {})", path, code, want);
        }
        cases += 1;
    }
    // A broken record after the whole answer (the one with close_notify): refused, never
    // taken for a missing close_notify.
    let code = get(58467, "/chunked", &["--cipher", "chacha"]);
    if code != 5 {
        fail!("58467 broken record after the answer: exit {} (expected 5)", code);
    }
    cases += 1;

    // Refusals: exit 5, and the request never reached the server.
    let before = seen(58443);
    // Without --anchor: the system store does not know the test CA.
    let code = netget(&["netget", "-o", OUT, "https://tls.desoos:58443/hello"]);
    if code != 5 {
        fail!("unknown CA: exit {} (expected 5)", code);
    }
    if seen(58443) != before || before.is_none() {
        fail!("unknown CA: the request reached the server ({:?} -> {:?})", before, seen(58443));
    }
    cases += 1;
    let refused: [(u16, &[&str], &str); 10] = [
        (58445, &[], "expired"),
        (58446, &[], "not yet valid"),
        (58447, &[], "other name"),
        (58448, &[], "broken signature"),
        (58449, &[], "another CA (man in the middle)"),
        (58450, &[], "TLS 1.2 only"),
        (58451, &[], "P-256 only"),
        (58460, &["--cipher", "chacha"], "changed Finished"),
        (58461, &["--cipher", "chacha"], "changed CertificateVerify"),
        (58447, &["--cipher", "chacha"], "other name, ChaCha20"),
    ];
    for (port, extra, what) in refused {
        let code = get(port, "/hello", extra);
        if code != 5 {
            fail!("{} ({}): exit {} (expected 5)", what, port, code);
        }
        if seen(port) != Some(0) {
            fail!("{} ({}): the request reached the server ({:?})", what, port, seen(port));
        }
        cases += 1;
    }
    // A changed or replayed record after the handshake: refused (the request had gone).
    for port in [58462u16, 58463] {
        let code = get(port, "/hello", &["--cipher", "chacha"]);
        if code != 5 {
            fail!("record {}: exit {} (expected 5)", port, code);
        }
        cases += 1;
    }

    let r = ask("dns auto");
    if !r.starts_with("DNS server 10.0.2.3") {
        fail!("dns auto: {:?}", r.trim());
    }
    unlink(OUT);
    unlink(CA_PATH);
    println!("tlstest net: {} cases OK, hello_ms={} big_kbs={}", cases, hello_ms, (1u64 << 20) * 1000 / big_ms / 1024);
    0
}

fn main(args: Args) -> i32 {
    match args.get(1) {
        None => offline(),
        Some("net") => net(),
        Some(_) => {
            eprintln!("usage: tlstest [net]");
            2
        }
    }
}
