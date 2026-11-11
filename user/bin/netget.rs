// netget [-o file] [-v] [--cipher aes|chacha] [--anchor ca.pem] [--key-update]
//        http[s]://host[:port]/path [netN] – downloads a page over HTTP/1.1 through netd's
// TCP: "tcp host port", then (https) the TLS 1.3 handshake with DeSoTLS, then the request,
// then the answer.  The body goes to the console (or to a file with -o); a summary
// (status, bytes, time, speed – and for https the TLS parameters) to stderr.  -v also
// prints the headers.
//
// https: the server's certificate chain is checked against /etc/certs/roots (or only the
// CA in --anchor) at the wall clock's time – a clock that is not plausible refuses before
// anything is sent.  No "insecure" switch: any certificate, handshake or record problem
// ends the connection.  --cipher offers one cipher suite only (both by default);
// --key-update sends a KeyUpdate asking the server to update too, before the request.
//
// One request per connection ("Connection: close", "Accept-Encoding: identity").  The answer
// must be framed correctly (user/lib/http.rs; docs/desotls/HANDSHAKE.md, "netget"):
// Content-Length once, or "Transfer-Encoding: chunked" (not both), nothing after the end;
// without either, https needs the server's close_notify to know the answer is whole.  After
// a whole answer netget waits at most 2 s for the connection's end: close_notify or FIN –
// fine, no close_notify or a reset – a warning, silence – a warning and netget closes;
// more data – a malformed answer; a broken TLS record – refused, never "just no close_notify".
//
// Exit code: 0 = 2xx and complete, 1 = usage (or a file problem), 2 = connection failed,
// 3 = cut short (fewer bytes than Content-Length, before the last chunk, or https ended
// without close_notify before the answer was complete), 4 = HTTP error status or a malformed
// answer, 5 = TLS refused (certificate, clock, handshake, record, server alert).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;
#[path = "../../common/desotls/mod.rs"]
mod desotls;
#[path = "../lib/http.rs"]
mod http;

use desoos::*;
use desotls::client::{self, Client, Config, Random, TlsError, Transport};
use desotls::record::Suite;
use desotls::roots::{AnchorList, Anchors, Roots};
use desotls::{pem, x509};

entry!(main);

/// How long a whole answer waits for the connection's end.
const LINGER_MS: u64 = 2000;
const STORE_MAX: usize = 256 * 1024;
const ANCHOR_MAX: usize = 16 * 1024;
const ROOTS: &str = "/etc/certs/roots";

static mut MSG: [u8; MSG_MAX] = [0; MSG_MAX];
static mut PARSER: http::Parser = http::Parser::new();
static mut BODY: [u8; MSG_MAX] = [0; MSG_MAX];
/// What the TLS transport received from netd and has not handed over yet.
static mut CHAN_BUF: [u8; MSG_MAX] = [0; MSG_MAX];
static mut TLS: Client = Client::new();
static mut STORE: [u8; STORE_MAX] = [0; STORE_MAX];
static mut ANCHOR_FILE: [u8; ANCHOR_MAX] = [0; ANCHOR_MAX];
static mut ANCHOR_DER: [u8; ANCHOR_MAX] = [0; ANCHOR_MAX];

const EXIT_USAGE: i32 = 1;
const EXIT_CONNECT: i32 = 2;
const EXIT_CUT: i32 = 3;
const EXIT_HTTP: i32 = 4;
const EXIT_TLS: i32 = 5;

struct Url<'a> {
    tls: bool,
    host: &'a str,
    port: u16,
    path: &'a str,
}

fn parse_url(u: &str) -> Result<Url<'_>, &'static str> {
    let (tls, rest) = if let Some(r) = u.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = u.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("the address must start with http:// or https://");
    };
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok().filter(|&p| p != 0).ok_or("bad port")?),
        None => (hostport, if tls { 443 } else { 80 }),
    };
    if host.is_empty() || host.len() > 253 || path.len() > 1024 || path.bytes().any(|b| b <= b' ' || b == 0x7F) {
        return Err("bad host or path");
    }
    Ok(Url { tls, host, port, path })
}

/// netd's TCP connection as the TLS transport: messages of up to MSG_MAX bytes.  With a
/// deadline (after a whole answer) a receive waits only until then.
struct Chan {
    c: u64,
    pos: usize,
    len: usize,
    deadline: Option<u64>,
    timed_out: bool,
}

impl Chan {
    /// Waits for the channel until the deadline; false = it passed.
    fn ready(&mut self) -> bool {
        let Some(d) = self.deadline else { return true };
        let now = uptime_ms();
        let left = d.saturating_sub(now);
        if left > 0 && matches!(wait_many(&[(self.c, W_READABLE)], left), Ok(m) if m != 0) {
            return true;
        }
        self.timed_out = true;
        false
    }
}

impl Transport for Chan {
    fn send(&mut self, data: &[u8]) -> Result<(), ()> {
        for part in data.chunks(MSG_MAX) {
            if chan_send(self.c, part, 0) != 0 {
                return Err(());
            }
        }
        Ok(())
    }
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        let msg = unsafe { &mut *core::ptr::addr_of_mut!(CHAN_BUF) };
        if self.pos == self.len {
            if !self.ready() {
                return Err(());
            }
            let mut info = RecvInfo::default();
            let r = chan_recv(self.c, msg, 0, &mut info);
            if r == 0 {
                // An empty message: netd's "the connection was reset" (or timed out).
                return Err(());
            }
            if r < 0 {
                // The channel closed: the TCP connection ended with the peer's FIN.
                return Ok(0);
            }
            self.pos = 0;
            self.len = r as usize;
        }
        let k = (self.len - self.pos).min(buf.len());
        buf[..k].copy_from_slice(&msg[self.pos..self.pos + k]);
        self.pos += k;
        Ok(k)
    }
}

/// What one read of the answer gave.
enum Got {
    Data(usize),
    /// A clean end: the peer's FIN for http, the server's close_notify for https.
    End,
    /// https ended without close_notify (FIN or reset).
    Cut,
    /// The TCP connection was reset (or timed out) – netd's empty message.
    Reset,
    /// After a whole answer the server did not end the connection in LINGER_MS.
    Linger,
    Refused(TlsError),
}

/// The parser's output: the body to the file / console, heads and trailers with -v.
struct Out {
    fd: u64,
    verbose: bool,
}

impl http::Sink for Out {
    fn head(&mut self, raw: &[u8], _interim: bool) {
        if self.verbose {
            eprintln!("{}", core::str::from_utf8(raw).unwrap_or("(headers not text)"));
        }
    }
    fn body(&mut self, data: &[u8]) -> Result<(), ()> {
        if write(self.fd, data) < 0 { Err(()) } else { Ok(()) }
    }
    fn trailers(&mut self, raw: &[u8]) {
        if self.verbose && !raw.is_empty() {
            eprintln!("netget: trailers:\n{}", core::str::from_utf8(raw).unwrap_or("(not text)"));
        }
    }
}

fn read_file(path: &str, buf: &mut [u8]) -> Result<usize, i64> {
    let fd = open(path, O_READ);
    if fd < 0 {
        return Err(fd);
    }
    let mut n = 0;
    loop {
        if n == buf.len() {
            close(fd as u64);
            return Err(ERROR_NO_SPACE);
        }
        let r = read(fd as u64, &mut buf[n..]);
        if r < 0 {
            close(fd as u64);
            return Err(r);
        }
        if r == 0 {
            close(fd as u64);
            return Ok(n);
        }
        n += r as usize;
    }
}

fn main(args: Args) -> i32 {
    let mut out_path: Option<&str> = None;
    let mut verbose = false;
    let mut url = None;
    let mut card = "net0";
    let mut anchor: Option<&str> = None;
    let mut suites: &[Suite] = &[Suite::Aes128Gcm, Suite::Chacha20Poly1305];
    let mut key_update = false;
    let usage = "usage: netget [-o file] [-v] [--cipher aes|chacha] [--anchor ca.pem] [--key-update] http[s]://host[:port]/path [net0]";
    let mut i = 1;
    while let Some(a) = args.get(i) {
        match a {
            "-o" => {
                i += 1;
                out_path = args.get(i);
            }
            "-v" => verbose = true,
            "--anchor" => {
                i += 1;
                anchor = args.get(i);
            }
            "--cipher" => {
                i += 1;
                suites = match args.get(i) {
                    Some("aes") => &[Suite::Aes128Gcm],
                    Some("chacha") => &[Suite::Chacha20Poly1305],
                    _ => {
                        eprintln!("{}", usage);
                        return EXIT_USAGE;
                    }
                };
            }
            "--key-update" => key_update = true,
            _ if url.is_none() => url = Some(a),
            _ => card = a,
        }
        i += 1;
    }
    let Some(url) = url else {
        eprintln!("{}", usage);
        return EXIT_USAGE;
    };
    let u = match parse_url(url) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("netget: {}", e);
            return EXIT_USAGE;
        }
    };

    // https: the clock and the trusted CAs first – nothing goes out without them.
    let mut now = 0i64;
    let store_buf = unsafe { &mut *core::ptr::addr_of_mut!(STORE) };
    let anchor_der = unsafe { &mut *core::ptr::addr_of_mut!(ANCHOR_DER) };
    let mut anchor_len = 0;
    let mut store_len = 0;
    if u.tls {
        match time_unix() {
            Ok(c) if c.plausible() => now = c.secs as i64,
            Ok(c) => {
                eprintln!("netget: TLS refused: clock not plausible: {} - nothing sent", clock_reason(c.status));
                return EXIT_TLS;
            }
            Err(e) => {
                eprintln!("netget: TLS refused: no clock: {}", strerror(e));
                return EXIT_TLS;
            }
        }
        match anchor {
            Some(p) => {
                let file = unsafe { &mut *core::ptr::addr_of_mut!(ANCHOR_FILE) };
                let n = match read_file(p, file) {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("netget: {}: {}", p, strerror(e));
                        return EXIT_USAGE;
                    }
                };
                if file[..n].starts_with(&[0x30]) {
                    anchor_der[..n].copy_from_slice(&file[..n]);
                    anchor_len = n;
                } else {
                    let mut spans = [(0usize, 0usize); 1];
                    match pem::certificates(&file[..n], anchor_der, &mut spans) {
                        Ok(1) => anchor_len = spans[0].1,
                        _ => {
                            eprintln!("netget: {}: not one certificate", p);
                            return EXIT_USAGE;
                        }
                    }
                }
            }
            None => match read_file(ROOTS, store_buf) {
                Ok(n) => store_len = n,
                Err(e) => {
                    eprintln!("netget: TLS refused: trusted CA store missing or damaged ({}: {})", ROOTS, strerror(e));
                    return EXIT_TLS;
                }
            },
        }
    }
    let store = if u.tls && anchor.is_none() {
        match Roots::parse(&store_buf[..store_len]) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("netget: TLS refused: {}", e.as_str());
                return EXIT_TLS;
            }
        }
    } else {
        None
    };
    let one: [&[u8]; 1] = [&anchor_der[..anchor_len]];
    let list = AnchorList(&one);
    let anchors: &dyn Anchors = match &store {
        Some(r) => r,
        None => &list,
    };

    let out_fd = match out_path {
        Some(p) => {
            let fd = open(p, O_WRITE | O_CREATE | O_TRUNC);
            if fd < 0 {
                eprintln!("netget: cannot create {}: {}", p, strerror(fd));
                return EXIT_USAGE;
            }
            fd as u64
        }
        None => 1,
    };
    let code = fetch(&u, card, out_fd, verbose, anchors, now, suites, key_update);
    if out_fd != 1 {
        close(out_fd);
    }
    code
}

#[allow(clippy::too_many_arguments)]
fn fetch(u: &Url<'_>, card: &str, out_fd: u64, verbose: bool, anchors: &dyn Anchors, now: i64, suites: &[Suite], key_update: bool) -> i32 {
    let Ok(c) = svc_connect(card) else {
        eprintln!("netget: no service {}", card);
        return EXIT_CONNECT;
    };
    let msg = unsafe { &mut *core::ptr::addr_of_mut!(MSG) };
    let mut info = RecvInfo::default();
    let t0 = uptime_ms();

    // 1. The TCP connection.
    let mut n = 0;
    let put = |b: &[u8], buf: &mut [u8], n: &mut usize| {
        let k = b.len().min(buf.len() - *n);
        buf[*n..*n + k].copy_from_slice(&b[..k]);
        *n += k;
    };
    let mut port_txt = [0u8; 6];
    let port_s = num_text(u.port as u64, &mut port_txt);
    put(b"tcp ", msg, &mut n);
    put(u.host.as_bytes(), msg, &mut n);
    put(b" ", msg, &mut n);
    put(port_s, msg, &mut n);
    if chan_send(c, &msg[..n], 0) != 0 {
        eprintln!("netget: {} is not running", card);
        return EXIT_CONNECT;
    }
    let r = chan_recv(c, msg, 0, &mut info);
    let reply = if r > 0 { core::str::from_utf8(&msg[..r as usize]).unwrap_or("") } else { "" };
    if !reply.starts_with("connected ") {
        eprintln!("netget: {}", if reply.is_empty() { "no answer from netd" } else { reply.trim().trim_start_matches("tcp: ") });
        close(c);
        return EXIT_CONNECT;
    }
    if verbose {
        eprintln!("netget: {}", reply.trim());
    }

    // 2. TLS (https).
    let tls = unsafe { &mut *core::ptr::addr_of_mut!(TLS) };
    let mut chan = Chan { c, pos: 0, len: 0, deadline: None, timed_out: false };
    if u.tls {
        let mut random = Random { client_random: [0; 32], session_id: [0; 32], x25519_secret: [0; 32] };
        if getrandom(&mut random.client_random).is_err() || getrandom(&mut random.session_id).is_err() || getrandom(&mut random.x25519_secret).is_err() {
            eprintln!("netget: no random numbers");
            close(c);
            return EXIT_CONNECT;
        }
        let cfg = Config { host: u.host, anchors, now, suites };
        match tls.connect(&mut chan, &cfg, &random) {
            Ok(i) => {
                let mut ca = [0u8; 64];
                let mut ca_len = 0;
                let mut k = 0;
                anchors.each(&mut |der, _| {
                    if k == i.path.anchor_index {
                        if let Some(cn) = x509::Cert::parse(der, true).ok().and_then(|c| c.subject_cn()) {
                            ca_len = cn.len().min(64);
                            ca[..ca_len].copy_from_slice(&cn.as_bytes()[..ca_len]);
                        }
                        return false;
                    }
                    k += 1;
                    true
                });
                eprintln!(
                    "netget: TLS 1.3, {}, {}, {}, {} certificates up to {}",
                    i.suite.name(),
                    client::group_name(i.group).unwrap_or("?"),
                    client::signature_name(i.signature),
                    i.path.certs,
                    core::str::from_utf8(&ca[..ca_len]).unwrap_or("?")
                );
            }
            Err(e) => {
                close(c);
                return tls_failed(&e, false);
            }
        }
        if key_update {
            if let Err(e) = tls.key_update(&mut chan, true) {
                close(c);
                return tls_failed(&e, false);
            }
        }
    }

    // 3. The request.
    let mut n = 0;
    put(b"GET ", msg, &mut n);
    put(u.path.as_bytes(), msg, &mut n);
    put(b" HTTP/1.1\r\nHost: ", msg, &mut n);
    put(u.host.as_bytes(), msg, &mut n);
    if u.port != if u.tls { 443 } else { 80 } {
        put(b":", msg, &mut n);
        put(port_s, msg, &mut n);
    }
    put(b"\r\nUser-Agent: DeSoOS-netget\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", msg, &mut n);
    let sent = if u.tls {
        let mut req = [0u8; 1400];
        req[..n].copy_from_slice(&msg[..n]);
        tls.write(&mut chan, &req[..n]).map_err(|e| Some(e))
    } else if chan_send(c, &msg[..n], 0) != 0 {
        Err(None)
    } else {
        Ok(())
    };
    match sent {
        Ok(()) => {}
        Err(Some(e)) => {
            close(c);
            return tls_failed(&e, false);
        }
        Err(None) => {
            eprintln!("netget: connection closed before the request was sent");
            close(c);
            return EXIT_CONNECT;
        }
    }

    // 4. The answer (user/lib/http.rs), then the connection's end – at most LINGER_MS after a
    // whole answer.
    let p = unsafe { &mut *core::ptr::addr_of_mut!(PARSER) };
    p.reset();
    let body_buf = unsafe { &mut *core::ptr::addr_of_mut!(BODY) };
    let mut out = Out { fd: out_fd, verbose };
    // When the answer was whole (the time and speed do not count the wait for the end).
    let mut done_at = 0;
    let end = loop {
        if p.done() && chan.deadline.is_none() {
            done_at = uptime_ms();
            chan.deadline = Some(done_at + LINGER_MS);
        }
        let got = if u.tls {
            match tls.read(&mut chan, body_buf) {
                Ok(0) => Got::End,
                Ok(k) => Got::Data(k),
                Err(e) if e.is_security() => Got::Refused(e),
                Err(_) if chan.timed_out => Got::Linger,
                Err(TlsError { kind: client::Kind::Reset, .. }) => Got::Reset,
                Err(_) => Got::Cut,
            }
        } else if !chan.ready() {
            Got::Linger
        } else {
            let r = chan_recv(c, body_buf, 0, &mut info);
            match r {
                0 => Got::Reset,
                r if r < 0 => Got::End,
                r => Got::Data(r as usize),
            }
        };
        let k = match got {
            Got::Data(k) => k,
            other => break other,
        };
        match p.feed(&body_buf[..k], &mut out) {
            Ok(()) => {}
            Err(http::Error::Malformed(why)) => {
                eprintln!("netget: malformed answer: {}", why);
                finish(u.tls, tls, &mut chan, c);
                return EXIT_HTTP;
            }
            Err(http::Error::Sink) => {
                eprintln!("netget: write failed");
                finish(u.tls, tls, &mut chan, c);
                return EXIT_USAGE;
            }
        }
    };
    let ms = (if done_at > 0 { done_at } else { uptime_ms() } - t0).max(1);
    if let Got::Refused(e) = end {
        close(c);
        return tls_failed(&e, true);
    }
    let clean = matches!(end, Got::End);
    let outcome = p.finish(if clean { http::End::Clean } else { http::End::Unclean });
    let body = p.body;
    let Some(a) = p.answer else {
        finish(u.tls, tls, &mut chan, c);
        eprintln!("netget: the server closed without an answer");
        return EXIT_CONNECT;
    };
    if outcome != http::Outcome::Complete {
        let how = match end {
            Got::Reset => "the connection was reset",
            Got::Cut => "the connection ended without close_notify",
            _ => "the connection ended",
        };
        match a.framing {
            http::Framing::Length(len) => eprintln!("netget: cut short - {} of {} bytes, then {}", body, len, how),
            http::Framing::Chunked => eprintln!("netget: cut short - {} bytes before the last chunk, then {}", body, how),
            _ => eprintln!("netget: cut short - {} after {} bytes", how, body),
        }
        if matches!(end, Got::Reset | Got::Cut) {
            close(c);
        } else {
            finish(u.tls, tls, &mut chan, c);
        }
        return EXIT_CUT;
    }
    // A whole answer (by its Content-Length or last chunk – for https inside the authenticated
    // stream): a missing close_notify or a reset after it is only a warning, as curl and Go.
    let by = match a.framing {
        http::Framing::Chunked => "its last chunk",
        http::Framing::Nothing => "its status",
        _ => "its Content-Length",
    };
    match end {
        Got::Cut => eprintln!("netget: warning: the server ended TLS without close_notify (the answer is complete by {})", by),
        Got::Reset => eprintln!("netget: warning: the connection was reset after the whole answer (complete by {})", by),
        Got::Linger => eprintln!("netget: warning: the server did not close the connection {} s after the whole answer (complete by {})", LINGER_MS / 1000, by),
        _ => {}
    }
    if matches!(end, Got::Reset | Got::Cut) {
        close(c);
    } else {
        finish(u.tls, tls, &mut chan, c);
    }
    let kbs = body * 1000 / ms / 1024;
    eprintln!("netget: HTTP {}, {} bytes in {} ms ({} KiB/s)", a.status, body, ms, kbs);
    if (200..300).contains(&a.status) { 0 } else { EXIT_HTTP }
}

/// Our close_notify (https) and the channel.
fn finish(tls_used: bool, tls: &mut Client, chan: &mut Chan, c: u64) {
    if tls_used {
        tls.close(chan);
    }
    close(c);
}

/// The message and exit code of a TLS failure.
fn tls_failed(e: &TlsError, after_request: bool) -> i32 {
    if e.is_security() {
        eprintln!("netget: TLS refused: {}", e);
        EXIT_TLS
    } else if after_request {
        eprintln!("netget: cut short - {}", e);
        EXIT_CUT
    } else {
        eprintln!("netget: connection failed: {}", e);
        EXIT_CONNECT
    }
}

fn num_text(mut v: u64, buf: &mut [u8; 6]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 || i == 0 {
            break;
        }
    }
    &buf[i..]
}
