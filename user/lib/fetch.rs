// One HTTP(S) GET through netd – the client of /bin/netget, shared with /bin/desopkg.  TCP through netd ("tcp host port"), the TLS 1.3 handshake with DeSoTLS for https,
// one request ("Connection: close", "Accept-Encoding: identity"), the answer parsed by
// user/lib/http.rs into a sink, the connection's end (docs/desotls/HANDSHAKE.md, "netget").
// The behaviour, every message and every exit code are netget's (TLS TEST); the messages
// start with `Options::prog`.  What desopkg adds: `quiet` (no TLS / speed summary lines),
// `expect_len` (the answer must have exactly this Content-Length – checked as soon as the head
// is parsed, the connection ends otherwise) and a sink that refuses bytes past its buffer.
//
// The crate root declares `desocrypto`, `desotls` and `http` (#[path]) and links libdeso.

#![allow(dead_code)]

use crate::desotls::client::{self, Client, Config, Random, TlsError, Transport};
use crate::desotls::record::Suite;
use crate::desotls::roots::Anchors;
use crate::desotls::x509;
use crate::http;
use libdeso::*;

/// How long a whole answer waits for the connection's end.
pub const LINGER_MS: u64 = 2000;

static mut MSG: [u8; MSG_MAX] = [0; MSG_MAX];
static mut PARSER: http::Parser = http::Parser::new();
static mut BODY: [u8; MSG_MAX] = [0; MSG_MAX];
/// What the TLS transport received from netd and has not handed over yet.
static mut CHAN_BUF: [u8; MSG_MAX] = [0; MSG_MAX];
static mut TLS: Client = Client::new();

pub const EXIT_USAGE: i32 = 1;
pub const EXIT_CONNECT: i32 = 2;
pub const EXIT_CUT: i32 = 3;
pub const EXIT_HTTP: i32 = 4;
pub const EXIT_TLS: i32 = 5;

/// What a GET is done with.
pub struct Options<'a> {
    /// The start of every message ("netget", "desopkg").
    pub prog: &'a str,
    /// The network card's service (net0).
    pub card: &'a str,
    /// netget -v: the connection line.
    pub verbose: bool,
    /// No summary lines (TLS parameters, bytes and speed); errors and warnings still go out.
    pub quiet: bool,
    pub anchors: &'a dyn Anchors,
    /// The wall clock's Unix seconds (https: the certificates' validity).
    pub now: i64,
    pub suites: &'a [Suite],
    pub key_update: bool,
    /// The exact Content-Length a 2xx answer must announce (desopkg: the index's `size`).
    pub expect_len: Option<u64>,
}

/// A whole answer.
#[derive(Clone, Copy, Debug)]
pub struct Done {
    pub status: u32,
    /// Bytes of body handed to the sink.
    pub body: u64,
}

pub struct Url<'a> {
    pub tls: bool,
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
}

pub fn parse_url(u: &str) -> Result<Url<'_>, &'static str> {
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

/// One GET: the TCP connection through netd (`o.card`), TLS for https, the request, the answer
/// into `sink` (user/lib/http.rs), the connection's end.  Returns the exit code netget gives
/// (0 = 2xx and complete, 2 connection, 3 cut short, 4 HTTP error / malformed / length, 5 TLS
/// refused; 1 = the sink refused data) and, for a whole answer, its status and body length.
pub fn fetch(u: &Url<'_>, o: &Options<'_>, sink: &mut dyn http::Sink) -> (i32, Option<Done>) {
    let (card, verbose, anchors, now, suites, key_update) = (o.card, o.verbose, o.anchors, o.now, o.suites, o.key_update);
    let Ok(c) = svc_connect(card) else {
        eprintln!("{}: no service {}", o.prog, card);
        return (EXIT_CONNECT, None);
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
        eprintln!("{}: {} is not running", o.prog, card);
        return (EXIT_CONNECT, None);
    }
    let r = chan_recv(c, msg, 0, &mut info);
    let reply = if r > 0 { core::str::from_utf8(&msg[..r as usize]).unwrap_or("") } else { "" };
    if !reply.starts_with("connected ") {
        eprintln!("{}: {}", o.prog, if reply.is_empty() { "no answer from netd" } else { reply.trim().trim_start_matches("tcp: ") });
        close(c);
        return (EXIT_CONNECT, None);
    }
    if verbose {
        eprintln!("{}: {}", o.prog, reply.trim());
    }

    // 2. TLS (https).
    let tls = unsafe { &mut *core::ptr::addr_of_mut!(TLS) };
    let mut chan = Chan { c, pos: 0, len: 0, deadline: None, timed_out: false };
    if u.tls {
        let mut random = Random { client_random: [0; 32], session_id: [0; 32], x25519_secret: [0; 32] };
        if getrandom(&mut random.client_random).is_err() || getrandom(&mut random.session_id).is_err() || getrandom(&mut random.x25519_secret).is_err() {
            eprintln!("{}: no random numbers", o.prog);
            close(c);
            return (EXIT_CONNECT, None);
        }
        let cfg = Config { host: u.host, anchors, now, suites, alpn: None, bootstrap: None };
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
                if !o.quiet { eprintln!(
                    "{}: TLS 1.3, {}, {}, {}, {} certificates up to {}",
                    o.prog,
                    i.suite.name(),
                    client::group_name(i.group).unwrap_or("?"),
                    client::signature_name(i.signature),
                    i.path.certs,
                    core::str::from_utf8(&ca[..ca_len]).unwrap_or("?")
                ); }
            }
            Err(e) => {
                close(c);
                return (tls_failed(o.prog, &e, false), None);
            }
        }
        if key_update {
            if let Err(e) = tls.key_update(&mut chan, true) {
                close(c);
                return (tls_failed(o.prog, &e, false), None);
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
    put(b"\r\nUser-Agent: DeSo-", msg, &mut n);
    put(o.prog.as_bytes(), msg, &mut n);
    put(b"\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", msg, &mut n);
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
            return (tls_failed(o.prog, &e, false), None);
        }
        Err(None) => {
            eprintln!("{}: connection closed before the request was sent", o.prog);
            close(c);
            return (EXIT_CONNECT, None);
        }
    }

    // 4. The answer (user/lib/http.rs), then the connection's end – at most LINGER_MS after a
    // whole answer.
    let p = unsafe { &mut *core::ptr::addr_of_mut!(PARSER) };
    p.reset();
    let body_buf = unsafe { &mut *core::ptr::addr_of_mut!(BODY) };
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
        match p.feed(&body_buf[..k], sink) {
            Ok(()) => {}
            Err(http::Error::Malformed(why)) => {
                eprintln!("{}: malformed answer: {}", o.prog, why);
                finish(u.tls, tls, &mut chan, c);
                return (EXIT_HTTP, None);
            }
            Err(http::Error::Sink) => {
                if !o.quiet {
                    eprintln!("{}: write failed", o.prog);
                }
                finish(u.tls, tls, &mut chan, c);
                return (EXIT_USAGE, None);
            }
        }
        // desopkg: the answer must announce exactly the size the signed index gives – a
        // different Content-Length (or none) ends the connection at once.
        if let (Some(want), Some(a)) = (o.expect_len, p.answer) {
            if (200..300).contains(&a.status) && a.framing != http::Framing::Length(want) {
                match a.framing {
                    http::Framing::Length(len) => eprintln!("{}: Content-Length {} differs from the expected {} bytes", o.prog, len, want),
                    _ => eprintln!("{}: no Content-Length (expected {} bytes)", o.prog, want),
                }
                finish(u.tls, tls, &mut chan, c);
                return (EXIT_HTTP, None);
            }
        }
    };
    let ms = (if done_at > 0 { done_at } else { uptime_ms() } - t0).max(1);
    if let Got::Refused(e) = end {
        close(c);
        return (tls_failed(o.prog, &e, true), None);
    }
    let clean = matches!(end, Got::End);
    let outcome = p.finish(if clean { http::End::Clean } else { http::End::Unclean });
    let body = p.body;
    let Some(a) = p.answer else {
        finish(u.tls, tls, &mut chan, c);
        eprintln!("{}: the server closed without an answer", o.prog);
        return (EXIT_CONNECT, None);
    };
    if outcome != http::Outcome::Complete {
        let how = match end {
            Got::Reset => "the connection was reset",
            Got::Cut => "the connection ended without close_notify",
            _ => "the connection ended",
        };
        match a.framing {
            http::Framing::Length(len) => eprintln!("{}: cut short - {} of {} bytes, then {}", o.prog, body, len, how),
            http::Framing::Chunked => eprintln!("{}: cut short - {} bytes before the last chunk, then {}", o.prog, body, how),
            _ => eprintln!("{}: cut short - {} after {} bytes", o.prog, how, body),
        }
        if matches!(end, Got::Reset | Got::Cut) {
            close(c);
        } else {
            finish(u.tls, tls, &mut chan, c);
        }
        return (EXIT_CUT, None);
    }
    // A whole answer (by its Content-Length or last chunk – for https inside the authenticated
    // stream): a missing close_notify or a reset after it is only a warning, as curl and Go.
    let by = match a.framing {
        http::Framing::Chunked => "its last chunk",
        http::Framing::Nothing => "its status",
        _ => "its Content-Length",
    };
    match end {
        Got::Cut => eprintln!("{}: warning: the server ended TLS without close_notify (the answer is complete by {})", o.prog, by),
        Got::Reset => eprintln!("{}: warning: the connection was reset after the whole answer (complete by {})", o.prog, by),
        Got::Linger => eprintln!("{}: warning: the server did not close the connection {} s after the whole answer (complete by {})", o.prog, LINGER_MS / 1000, by),
        _ => {}
    }
    if matches!(end, Got::Reset | Got::Cut) {
        close(c);
    } else {
        finish(u.tls, tls, &mut chan, c);
    }
    let kbs = body * 1000 / ms / 1024;
    if !o.quiet { eprintln!("{}: HTTP {}, {} bytes in {} ms ({} KiB/s)", o.prog, a.status, body, ms, kbs); }
    let done = Some(Done { status: a.status, body });
    (if (200..300).contains(&a.status) { 0 } else { EXIT_HTTP }, done)
}

/// Our close_notify (https) and the channel.
fn finish(tls_used: bool, tls: &mut Client, chan: &mut Chan, c: u64) {
    if tls_used {
        tls.close(chan);
    }
    close(c);
}

/// The message and exit code of a TLS failure.
fn tls_failed(prog: &str, e: &TlsError, after_request: bool) -> i32 {
    if e.is_security() {
        eprintln!("{}: TLS refused: {}", prog, e);
        EXIT_TLS
    } else if after_request {
        eprintln!("{}: cut short - {}", prog, e);
        EXIT_CUT
    } else {
        eprintln!("{}: connection failed: {}", prog, e);
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
