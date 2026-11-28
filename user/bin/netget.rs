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
//
// The client itself (TCP through netd, TLS, the request, the answer) is user/lib/fetch.rs, shared
// with /bin/desopkg – the same messages and exit codes.
#![no_std]
#![no_main]

#[macro_use]
#[allow(unused_imports)]
extern crate libdeso;
#[allow(unused_imports)]
use libdeso as deso;
#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;
#[path = "../../common/desotls/mod.rs"]
mod desotls;
#[path = "../lib/http.rs"]
mod http;
#[path = "../lib/fetch.rs"]
mod fetch;

use deso::*;
use desotls::pem;
use desotls::record::Suite;
use desotls::roots::{AnchorList, Anchors, Roots};
use fetch::{EXIT_TLS, EXIT_USAGE};

entry!(main);

const STORE_MAX: usize = 256 * 1024;
const ANCHOR_MAX: usize = 16 * 1024;
const ROOTS: &str = "/etc/certs/roots";

static mut STORE: [u8; STORE_MAX] = [0; STORE_MAX];
static mut ANCHOR_FILE: [u8; ANCHOR_MAX] = [0; ANCHOR_MAX];
static mut ANCHOR_DER: [u8; ANCHOR_MAX] = [0; ANCHOR_MAX];

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
    let u = match fetch::parse_url(url) {
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
    let opts = fetch::Options { prog: "netget", card, verbose, quiet: false, anchors, now, suites, key_update, expect_len: None };
    let mut out = Out { fd: out_fd, verbose };
    let (code, _) = fetch::fetch(&u, &opts, &mut out);
    if out_fd != 1 {
        close(out_fd);
    }
    code
}
