// nts-server – a test server on the host for DeSoOS (tests/test.sh builds and starts it).
// Built on rustls (TLS 1.3 independent of DeSoTLS) and RustCrypto's aes-siv (independent
// of DeSoCrypto), so the guest's TLS exporter, ALPN, NTS-KE and NTS are checked against a
// real other side, not against a copy of our own code.
//
//   nts-server <dir with tests/tls> <base port>     (default base 58500)
//
// Certificate: tests/tls/rsa.pem ("tls.desoos").  Ports (base + n):
//
// TLS exporter (TLS TEST):
//   +0  ALPN "ntske/1": after the handshake the server sends the 64 bytes of NTS keys it
//       exported itself (label "EXPORTER-network-time-security", context 00 00 00 0f 00 /
//       01), then close_notify      +1  the same without ALPN      +2  ALPN, 32 bytes
//       exported with label "test", context "abc"
//
// NTS-KE (TCP, TLS 1.3, ALPN "ntske/1"), +10 + k – the response:
//    0 correct: Next Protocol {0}, AEAD {15}, Port Negotiation = NTP +40, 8 cookies
//    1 no End of Message      2 a record after End of Message     3 no close_notify (TCP
//    closed after End of Message)       4 Next Protocol twice     5 AEAD twice
//    6 no AEAD record         7 AEAD {17}                         8 Next Protocol {1}
//    9 Error record (code 1)  10 Warning record (code 0)          11 an unknown critical
//    record (type 50)         12 an unknown non-critical record (accepted)
//    13 Next Protocol with an empty body                          14 a response of exactly
//    65 536 bytes (accepted)  15 65 537 bytes                     16 no cookie
//    17 nine cookies (8 kept) 18 Server Negotiation "ntp.desoos" + Port Negotiation (NTP
//    through the name)        19 a record cut short, then close_notify
//    20 only cookies of 98 bytes (not divisible by 4)             21 one cookie of 300
//    bytes (fewer placeholders)                                   22 no ALPN (TLS level)
//    23 one 98-byte cookie and seven good ones (accepted)         24 Port Negotiation 0
//    25 Server Negotiation "bad host!"                            26 one cookie only (7
//    placeholders)
// NTS-KE, +70 + m: correct, NTP at +40 + m (the NTP behaviours below).
//
// NTP with NTS (UDP), +40 + m – the cookie is decrypted with the server's master key, the
// request's Authenticator checked with C2S (a bad one: no answer, counted); the answer:
//    0 correct (stratum 2, the host's time, Unique Identifier, Authenticator with S2C over
//      everything before it, 1 + placeholders new cookies encrypted)
//    1 the SIV changed        2 no Authenticator      3 another Unique Identifier
//    4 first query of a sender: silence; second: the answer for the first query's Unique
//      Identifier, then the correct one       5 the correct answer twice
//    6 an extension field after the Authenticator (accepted)
//    7 first query: NTS NAK (Kiss code NTSN, our Unique Identifier); second: correct
//    8 NTSN with another Unique Identifier, then the correct answer
//    9 an unauthenticated DENY, then the correct answer    10 a plain NTP answer
//   11 correct NTS, stratum 16 inside    12 Authenticator with C2S instead of S2C
//   13 two Authenticators    14 NTSN to every query
// +39 (UDP): "reset" zeroes the counters, anything else answers "requests=N dup=N bad=N
//   maxlen=N placeholders=N" – NTS requests seen, cookies seen twice, requests whose
//   Authenticator did not verify, the longest request, placeholders in the last request.
use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_siv::siv::Aes128Siv;
use aes_siv::KeyInit;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

const LABEL: &[u8] = b"EXPORTER-network-time-security";
const KE_BASE: u16 = 10;
const NTP_BASE: u16 = 40;
const STATS: u16 = 39;
const KE_FOR_NTP: u16 = 60;
const NTP_KINDS: u16 = 15;

fn config(dir: &str, alpn: bool) -> Arc<ServerConfig> {
    let certs: Vec<CertificateDer> = CertificateDer::pem_file_iter(format!("{}/rsa.pem", dir)).expect("rsa.pem").map(|c| c.expect("certificate")).collect();
    let key = PrivateKeyDer::from_pem_file(format!("{}/rsa.key", dir)).expect("rsa.key");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("certificate and key");
    if alpn {
        cfg.alpn_protocols = vec![b"ntske/1".to_vec()];
    }
    Arc::new(cfg)
}

#[derive(Default)]
struct Stats {
    requests: u64,
    dup: u64,
    bad: u64,
    maxlen: usize,
    placeholders: usize,
    seen: HashSet<Vec<u8>>,
}

struct Shared {
    master: [u8; 32],
    base: u16,
    stats: Mutex<Stats>,
    /// Behaviour 4 / 7: senders already seen once and the first Unique Identifier.
    first: Mutex<std::collections::HashMap<(u16, SocketAddr), Vec<u8>>>,
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).expect("urandom");
    b
}

/// A cookie: nonce (16) || AES-SIV(master, [nonce], c2s || s2c) – 96 bytes; `pad` zeros after.
fn make_cookie(master: &[u8; 32], c2s: &[u8], s2c: &[u8], pad: usize) -> Vec<u8> {
    let nonce: [u8; 16] = random();
    let mut keys = c2s.to_vec();
    keys.extend_from_slice(s2c);
    let mut siv = Aes128Siv::new_from_slice(master).unwrap();
    let ct = siv.encrypt([&nonce[..]], &keys).unwrap();
    let mut c = nonce.to_vec();
    c.extend_from_slice(&ct);
    c.resize(c.len() + pad, 0);
    c
}

fn open_cookie(master: &[u8; 32], cookie: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if cookie.len() < 96 {
        return None;
    }
    let mut siv = Aes128Siv::new_from_slice(master).unwrap();
    let keys = siv.decrypt([&cookie[..16]], &cookie[16..96]).ok()?;
    Some((keys[..32].to_vec(), keys[32..].to_vec()))
}

fn rec(ty: u16, critical: bool, body: &[u8]) -> Vec<u8> {
    let mut r = (ty | if critical { 0x8000 } else { 0 }).to_be_bytes().to_vec();
    r.extend_from_slice(&(body.len() as u16).to_be_bytes());
    r.extend_from_slice(body);
    r
}

/// The NTS-KE response of behaviour `k` (and whether to skip close_notify).
fn ke_response(sh: &Shared, k: u16, c2s: &[u8], s2c: &[u8]) -> (Vec<u8>, bool) {
    let ntp_port = if k >= KE_FOR_NTP { sh.base + NTP_BASE + (k - KE_FOR_NTP) } else { sh.base + NTP_BASE };
    let next = rec(1, true, &[0, 0]);
    let aead = rec(4, true, &[0, 15]);
    let port = rec(7, false, &ntp_port.to_be_bytes());
    let end = rec(0, true, &[]);
    let cookie = |pad: usize| rec(5, false, &make_cookie(&sh.master, c2s, s2c, pad));
    let cookies = |n: usize| -> Vec<u8> { (0..n).flat_map(|_| cookie(0)).collect() };
    let mut out = Vec::new();
    let mut no_close = false;
    match k {
        1 => out = [next, aead, port, cookies(8)].concat(),
        2 => out = [next, aead, port, cookies(8), end, rec(50, false, &[1, 2])].concat(),
        3 => {
            out = [next, aead, port, cookies(8), end].concat();
            no_close = true;
        }
        4 => out = [next.clone(), next, aead, port, cookies(8), end].concat(),
        5 => out = [next, aead.clone(), aead, port, cookies(8), end].concat(),
        6 => out = [next, port, cookies(8), end].concat(),
        7 => out = [next, rec(4, true, &[0, 17]), port, cookies(8), end].concat(),
        8 => out = [rec(1, true, &[0, 1]), aead, port, cookies(8), end].concat(),
        9 => out = [rec(2, true, &[0, 1]), end].concat(),
        10 => out = [next, aead, port, cookies(8), rec(3, true, &[0, 0]), end].concat(),
        11 => out = [next, aead, port, cookies(8), rec(50, true, &[0; 4]), end].concat(),
        12 => out = [next, aead, port, cookies(8), rec(50, false, &[0; 4]), end].concat(),
        13 => out = [rec(1, true, &[]), aead, port, cookies(8), end].concat(),
        14 | 15 => {
            let head = [next, aead, port, cookies(8)].concat();
            let want = 65_536 + if k == 15 { 1 } else { 0 };
            let mut pad = want - head.len() - end.len();
            out = head;
            // Unknown non-critical records of at most 65 535 bytes fill the gap.
            while pad > 0 {
                let body = (pad - 4).min(60_000);
                out.extend(rec(50, false, &vec![0u8; body]));
                pad -= 4 + body;
            }
            out.extend(end);
        }
        16 => out = [next, aead, port, end].concat(),
        17 => out = [next, aead, port, cookies(9), end].concat(),
        18 => out = [next, aead, rec(6, false, b"ntp.desoos"), port, cookies(8), end].concat(),
        19 => {
            let full = [next, aead, port, cookies(8), end].concat();
            out = full[..full.len() - 30].to_vec();
        }
        20 => out = [next, aead, port, (0..8).flat_map(|_| rec(5, false, &vec![7u8; 98])).collect(), end].concat(),
        21 => out = [next, aead, port, cookie(204), end].concat(),
        23 => out = [next, aead, port, rec(5, false, &[7u8; 98]), cookies(7), end].concat(),
        24 => out = [next, aead, rec(7, false, &[0, 0]), cookies(8), end].concat(),
        25 => out = [next, aead, rec(6, false, b"bad host!"), port, cookies(8), end].concat(),
        26 => out = [next, aead, port, cookies(1), end].concat(),
        _ => out.extend([next, aead, port, cookies(8), end].concat()),
    }
    (out, no_close)
}

fn handshake(sock: TcpStream, cfg: Arc<ServerConfig>) -> Option<StreamOwned<ServerConnection, TcpStream>> {
    let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
    let conn = ServerConnection::new(cfg).ok()?;
    let mut tls = StreamOwned::new(conn, sock);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).ok()?;
    }
    Some(tls)
}

fn finish(mut tls: StreamOwned<ServerConnection, TcpStream>, close: bool) {
    if close {
        tls.conn.send_close_notify();
    }
    let _ = tls.flush();
    let _ = tls.conn.complete_io(&mut tls.sock);
    if !close {
        let _ = tls.sock.shutdown(std::net::Shutdown::Both);
        return;
    }
    let mut sink = [0u8; 256];
    let _ = tls.read(&mut sink);
}

fn serve_exporter(sock: TcpStream, cfg: Arc<ServerConfig>, kind: u16) {
    let Some(mut tls) = handshake(sock, cfg) else { return };
    let mut out = Vec::new();
    if kind == 2 {
        let mut k = [0u8; 32];
        if tls.conn.export_keying_material(&mut k, b"test", Some(b"abc")).is_err() {
            return;
        }
        out.extend_from_slice(&k);
    } else {
        for dir in [0u8, 1] {
            let mut k = [0u8; 32];
            if tls.conn.export_keying_material(&mut k, LABEL, Some(&[0, 0, 0, 15, dir])).is_err() {
                return;
            }
            out.extend_from_slice(&k);
        }
    }
    let _ = tls.write_all(&out);
    finish(tls, true);
}

fn serve_ke(sock: TcpStream, cfg: Arc<ServerConfig>, sh: Arc<Shared>, k: u16) {
    let Some(mut tls) = handshake(sock, cfg) else { return };
    // The client's request: records up to End of Message.
    let mut req = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tls.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => req.extend_from_slice(&buf[..n]),
        }
        if req.len() >= 4 && req.ends_with(&[0x80, 0, 0, 0]) {
            break;
        }
    }
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    if tls.conn.export_keying_material(&mut c2s, LABEL, Some(&[0, 0, 0, 15, 0])).is_err() || tls.conn.export_keying_material(&mut s2c, LABEL, Some(&[0, 0, 0, 15, 1])).is_err() {
        return;
    }
    let (resp, no_close) = ke_response(&sh, k, &c2s, &s2c);
    let _ = tls.write_all(&resp);
    finish(tls, !no_close);
}

fn ef(ty: u16, body: &[u8]) -> Vec<u8> {
    let mut e = ty.to_be_bytes().to_vec();
    e.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    e.extend_from_slice(body);
    e
}

fn ntp_ts() -> [u8; 8] {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let s = (d.as_secs() + 2_208_988_800) as u32;
    let f = ((d.subsec_nanos() as u64) << 32) / 1_000_000_000;
    let mut b = [0u8; 8];
    b[..4].copy_from_slice(&s.to_be_bytes());
    b[4..].copy_from_slice(&(f as u32).to_be_bytes());
    b
}

fn header(origin: &[u8], stratum: u8, refid: &[u8; 4]) -> Vec<u8> {
    let mut h = vec![4 << 3 | 4, stratum, 0, 0xEC];
    h.extend_from_slice(&0x0000_0290u32.to_be_bytes());
    h.extend_from_slice(&0x0000_0290u32.to_be_bytes());
    h.extend_from_slice(refid);
    h.extend_from_slice(&ntp_ts());
    h.extend_from_slice(origin);
    h.extend_from_slice(&ntp_ts());
    h.extend_from_slice(&ntp_ts());
    h
}

/// Header + Unique Identifier + Authenticator (key `key`) over everything before it,
/// encrypting `plain` (the new cookies); `after` = fields appended after the Authenticator.
fn nts_answer(head: Vec<u8>, uid: &[u8], key: &[u8], plain: &[u8], corrupt: bool, after: &[u8]) -> Vec<u8> {
    let mut pkt = head;
    pkt.extend(ef(0x0104, uid));
    let nonce: [u8; 16] = random();
    let mut siv = Aes128Siv::new_from_slice(key).unwrap();
    let mut ct = siv.encrypt([&pkt[..], &nonce[..]], plain).unwrap();
    if corrupt {
        ct[3] ^= 1;
    }
    let mut body = (16u16).to_be_bytes().to_vec();
    body.extend_from_slice(&(ct.len() as u16).to_be_bytes());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ct);
    while body.len() % 4 != 0 {
        body.push(0);
    }
    pkt.extend(ef(0x0404, &body));
    pkt.extend_from_slice(after);
    pkt
}

fn serve_ntp(sock: UdpSocket, sh: Arc<Shared>, m: u16) {
    let mut buf = [0u8; 2048];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf) else { continue };
        let d = &buf[..n];
        if n < 48 {
            continue;
        }
        // Fields: Unique Identifier, cookie, placeholders, Authenticator.
        let mut p = 48;
        let (mut uid, mut cookie, mut ph, mut auth_at) = (Vec::new(), Vec::new(), 0usize, None);
        while p + 4 <= n {
            let ty = u16::from_be_bytes([d[p], d[p + 1]]);
            let len = u16::from_be_bytes([d[p + 2], d[p + 3]]) as usize;
            if len < 4 || p + len > n {
                break;
            }
            let body = &d[p + 4..p + len];
            match ty {
                0x0104 => uid = body.to_vec(),
                0x0204 => cookie = body.to_vec(),
                0x0304 => ph += 1,
                0x0404 => {
                    auth_at = Some(p);
                    break;
                }
                _ => {}
            }
            p += len;
        }
        let Some(at) = auth_at else { continue };
        let Some((c2s, s2c)) = open_cookie(&sh.master, &cookie) else { continue };
        // The request's Authenticator: nonce length, ciphertext length, nonce, SIV.
        let body = &d[at + 4..];
        let nlen = u16::from_be_bytes([body[0], body[1]]) as usize;
        let clen = u16::from_be_bytes([body[2], body[3]]) as usize;
        let nonce = &body[4..4 + nlen];
        let ct = &body[4 + ((nlen + 3) / 4) * 4..][..clen];
        let ok = Aes128Siv::new_from_slice(&c2s).unwrap().decrypt([&d[..at], nonce], ct).is_ok();
        {
            let mut st = sh.stats.lock().unwrap();
            st.requests += 1;
            if !st.seen.insert(cookie.clone()) {
                st.dup += 1;
            }
            if !ok {
                st.bad += 1;
            }
            st.maxlen = st.maxlen.max(n);
            st.placeholders = ph;
        }
        if !ok {
            continue;
        }
        let origin = &d[40..48];
        // New cookies (1 + placeholders), encrypted in the answer.
        let mut plain = Vec::new();
        for _ in 0..1 + ph {
            plain.extend(ef(0x0204, &make_cookie(&sh.master, &c2s, &s2c, 0)));
        }
        let good = || nts_answer(header(origin, 2, b"STUB"), &uid, &s2c, &plain, false, &[]);
        let nak = |u: &[u8]| {
            let mut h = header(origin, 0, b"NTSN");
            h.extend(ef(0x0104, u));
            h
        };
        let key = (m, peer);
        let first = {
            let mut f = sh.first.lock().unwrap();
            if f.contains_key(&key) {
                Some(f.remove(&key).unwrap())
            } else {
                f.insert(key, uid.clone());
                None
            }
        };
        let mut out: Vec<Vec<u8>> = Vec::new();
        let other: Vec<u8> = uid.iter().map(|b| b ^ 0x5A).collect();
        match m {
            1 => out.push(nts_answer(header(origin, 2, b"STUB"), &uid, &s2c, &plain, true, &[])),
            2 => {
                let mut h = header(origin, 2, b"STUB");
                h.extend(ef(0x0104, &uid));
                out.push(h);
            }
            3 => out.push(nts_answer(header(origin, 2, b"STUB"), &other, &s2c, &plain, false, &[])),
            4 => {
                if let Some(old) = first {
                    out.push(nts_answer(header(origin, 2, b"STUB"), &old, &s2c, &plain, false, &[]));
                    out.push(good());
                }
            }
            5 => {
                out.push(good());
                out.push(good());
            }
            6 => out.push(nts_answer(header(origin, 2, b"STUB"), &uid, &s2c, &plain, false, &ef(0x0F04, &[9u8; 12]))),
            7 => {
                if first.is_none() {
                    out.push(nak(&uid));
                } else {
                    out.push(good());
                }
            }
            8 => {
                out.push(nak(&other));
                out.push(good());
            }
            9 => {
                let mut h = header(origin, 0, b"DENY");
                h.extend(ef(0x0104, &uid));
                out.push(h);
                out.push(good());
            }
            10 => out.push(header(origin, 2, b"STUB")),
            11 => out.push(nts_answer(header(origin, 16, b"STUB"), &uid, &s2c, &plain, false, &[])),
            12 => out.push(nts_answer(header(origin, 2, b"STUB"), &uid, &c2s, &plain, false, &[])),
            13 => {
                let a = good();
                // The Authenticator field follows the header (48) and the Unique Identifier (36).
                let second_auth = a[48 + 36..].to_vec();
                let mut x = a;
                x.extend(second_auth);
                out.push(x);
            }
            14 => out.push(nak(&uid)),
            _ => out.push(good()),
        }
        if m != 4 && m != 7 {
            sh.first.lock().unwrap().remove(&key);
        }
        for (i, pkt) in out.iter().enumerate() {
            if i > 0 {
                thread::sleep(Duration::from_millis(50));
            }
            let _ = sock.send_to(pkt, peer);
        }
    }
}

fn serve_stats(sock: UdpSocket, sh: Arc<Shared>) {
    let mut buf = [0u8; 64];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf) else { continue };
        let mut st = sh.stats.lock().unwrap();
        if &buf[..n] == b"reset" {
            *st = Stats::default();
        }
        let t = format!("requests={} dup={} bad={} maxlen={} placeholders={}", st.requests, st.dup, st.bad, st.maxlen, st.placeholders);
        let _ = sock.send_to(t.as_bytes(), peer);
    }
}

/// Binds 127.0.0.1:port.  Our ports lie inside Linux's default range for outgoing ports
/// (32768-60999), so another program may hold one for a moment as the source port of its
/// own connection: a busy port is tried again for up to 5 s (as tests/stubnet.py does).
fn bind_retry<T>(port: u16, what: &str, bind: impl Fn(u16) -> std::io::Result<T>) -> T {
    let end = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match bind(port) {
            Ok(s) => return s,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && std::time::Instant::now() < end => {
                thread::sleep(Duration::from_millis(100))
            }
            Err(e) => {
                eprintln!("nts-server: cannot listen on 127.0.0.1:{} ({}): {}", port, what, e);
                std::process::exit(1)
            }
        }
    }
}

fn listen_tcp(port: u16) -> TcpListener {
    bind_retry(port, "tcp", |p| TcpListener::bind(("127.0.0.1", p)))
}

fn listen_udp(port: u16) -> UdpSocket {
    bind_retry(port, "udp", |p| UdpSocket::bind(("127.0.0.1", p)))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = args.get(1).cloned().unwrap_or_else(|| "tests/tls".into());
    let base: u16 = args.get(2).and_then(|p| p.parse().ok()).unwrap_or(58500);
    let sh = Arc::new(Shared { master: random(), base, stats: Mutex::new(Stats::default()), first: Mutex::new(Default::default()) });
    let with_alpn = config(&dir, true);
    let without = config(&dir, false);
    let mut handles = Vec::new();
    for kind in 0u16..3 {
        let l = listen_tcp(base + kind);
        let cfg = if kind == 1 { without.clone() } else { with_alpn.clone() };
        handles.push(thread::spawn(move || {
            for s in l.incoming().flatten() {
                let cfg = cfg.clone();
                thread::spawn(move || serve_exporter(s, cfg, kind));
            }
        }));
    }
    let ke_kinds: Vec<u16> = (0..27).chain(KE_FOR_NTP..KE_FOR_NTP + NTP_KINDS).collect();
    for k in ke_kinds {
        let l = listen_tcp(base + KE_BASE + k);
        let cfg = if k == 22 { without.clone() } else { with_alpn.clone() };
        let sh = sh.clone();
        handles.push(thread::spawn(move || {
            for s in l.incoming().flatten() {
                let (cfg, sh) = (cfg.clone(), sh.clone());
                thread::spawn(move || serve_ke(s, cfg, sh, k));
            }
        }));
    }
    for m in 0..NTP_KINDS {
        let s = listen_udp(base + NTP_BASE + m);
        let sh = sh.clone();
        handles.push(thread::spawn(move || serve_ntp(s, sh, m)));
    }
    let s = listen_udp(base + STATS);
    let sh2 = sh.clone();
    handles.push(thread::spawn(move || serve_stats(s, sh2)));
    // All ports bound: tell tests/test.sh (see tests/stubnet.py).
    if let Some(d) = std::env::var_os("STUB_READY") {
        let _ = std::fs::File::create(std::path::Path::new(&d).join("nts"));
    }
    for h in handles {
        let _ = h.join();
    }
}
