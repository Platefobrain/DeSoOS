// NTS-KE over a netd TCP connection (RFC 8915 §4) – shared by /bin/nettime and the time
// service (/bin/timekeeper).  One server at a time: TCP to name:port through the card's
// network service (lookup and connection within 3 x wait), TLS 1.3 with DeSoTLS and ALPN
// "ntske/1", the request, the response up to End of Message and the server's close_notify,
// the records checked (nts.rs), the keys from the TLS exporter.  The session's secrets and
// buffers are wiped before it returns, and so is the decrypted response (the cookies live on
// only in the pool).
//
// A bootstrap (the time service while the clock is not plausible): `cfg.bootstrap` = the
// kernel's bound and `chain` = where the server's certificate chain from this handshake goes
// (DeSoTLS keeps it only then) for the second check over T +- U.
//
// Messages go to stderr as "<tag>: <name>: NTS-KE: ..." (tag = the program); `say` false – none
// (the time service after the first of several failures in a row).

use super::desocrypto;
use super::desoos::*;
use super::desotls::chain::PeerChain;
use super::desotls::client::{Client, Config, Random, Transport};
use super::nts;

/// A netd TCP connection as the TLS transport, with a deadline for every wait.
pub struct Chan<'a> {
    pub c: u64,
    pub pos: usize,
    pub len: usize,
    pub deadline: u64,
    pub msg: &'a mut [u8; MSG_MAX],
}

impl Transport for Chan<'_> {
    fn send(&mut self, data: &[u8]) -> Result<(), ()> {
        for part in data.chunks(MSG_MAX) {
            if chan_send(self.c, part, 0) != 0 {
                return Err(());
            }
        }
        Ok(())
    }
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        if self.pos == self.len {
            let left = self.deadline.saturating_sub(uptime_ms());
            if left == 0 || !matches!(wait_many(&[(self.c, W_READABLE)], left), Ok(m) if m != 0) {
                return Err(());
            }
            let mut info = RecvInfo::default();
            let r = chan_recv(self.c, self.msg, 0, &mut info);
            if r == 0 {
                return Err(());
            }
            if r < 0 {
                return Ok(0);
            }
            self.pos = 0;
            self.len = r as usize;
        }
        let k = (self.len - self.pos).min(buf.len());
        buf[..k].copy_from_slice(&self.msg[self.pos..self.pos + k]);
        self.pos += k;
        Ok(k)
    }
}

/// What a successful NTS-KE gives (besides the cookies in the pool).
pub struct Done {
    pub neg: nts::Negotiated,
    pub c2s: [u8; 32],
    pub s2c: [u8; 32],
}

impl Done {
    pub fn wipe(&mut self) {
        desocrypto::wipe(&mut self.c2s);
        desocrypto::wipe(&mut self.s2c);
    }
}

/// The buffers one exchange uses (statics of the program).
pub struct Buffers<'a> {
    pub tls: &'a mut Client,
    pub msg: &'a mut [u8; MSG_MAX],
    pub ke: &'a mut [u8],
}

/// NTS-KE with one server (`cfg.host` = its name, `port` = the KE port).  `addr` gets the KE
/// server's address ("a.b.c.d").  Err – what to tell (the server is then left out).
pub fn key_exchange(tag: &str, say: bool, cfg: &Config<'_>, port: u16, card: &str, pool: &mut nts::Pool, wait_ms: u64, buf: Buffers<'_>, addr: &mut [u8; 24], addr_len: &mut usize, chain: Option<&mut PeerChain>) -> Result<Done, &'static str> {
    let name = cfg.host;
    macro_rules! tell {
        ($($a:tt)*) => {
            if say {
                eprintln!($($a)*);
            }
        };
    }
    let Ok(c) = svc_connect(card) else { return Err("no network service") };
    let mut req = [0u8; 300];
    let mut n = 0;
    let mut put = |b: &[u8], n: &mut usize| {
        let k = b.len().min(req.len() - *n);
        req[*n..*n + k].copy_from_slice(&b[..k]);
        *n += k;
    };
    let mut d = [0u8; 5];
    let mut v = port;
    let mut dl = 0;
    loop {
        d[4 - dl] = b'0' + (v % 10) as u8;
        v /= 10;
        dl += 1;
        if v == 0 {
            break;
        }
    }
    put(b"tcp ", &mut n);
    put(name.as_bytes(), &mut n);
    put(b" ", &mut n);
    put(&d[5 - dl..], &mut n);
    let mut info = RecvInfo::default();
    // The name lookup and the TCP connection get 3 x wait like the TLS part: netd alone would
    // wait for a SYN-ACK 1 + 2 + 4 + 8 = 15 s, and the next servers wait behind this one.
    // Closing the channel ends the connection attempt in netd.
    let limit = 3 * wait_ms;
    let r = if chan_send(c, &req[..n], 0) != 0 {
        -1
    } else if !matches!(wait_many(&[(c, W_READABLE)], limit), Ok(m) if m != 0) {
        close(c);
        tell!("{}: {}: NTS-KE: no connection within {} ms", tag, name, limit);
        return Err("NTS-KE connection failed");
    } else {
        chan_recv(c, buf.msg, CHAN_NONBLOCK, &mut info)
    };
    let reply = if r > 0 { core::str::from_utf8(&buf.msg[..r as usize]).unwrap_or("") } else { "" };
    if !reply.starts_with("connected ") {
        close(c);
        tell!("{}: {}: NTS-KE: {}", tag, name, if reply.is_empty() { "no answer from netd" } else { reply.trim().trim_start_matches("tcp: ") });
        return Err("NTS-KE connection failed");
    }
    // "connected a.b.c.d:port from ..." – the KE server's address (the default for NTP).
    let ip = reply.strip_prefix("connected ").and_then(|t| t.split(':').next()).unwrap_or("?");
    *addr_len = ip.len().min(addr.len());
    addr[..*addr_len].copy_from_slice(&ip.as_bytes()[..*addr_len]);
    let mut rnd = [0u8; 96];
    if getrandom(&mut rnd).is_err() {
        close(c);
        return Err("no random numbers");
    }
    let mut random = Random { client_random: [0; 32], session_id: [0; 32], x25519_secret: [0; 32] };
    random.client_random.copy_from_slice(&rnd[..32]);
    random.session_id.copy_from_slice(&rnd[32..64]);
    random.x25519_secret.copy_from_slice(&rnd[64..]);
    desocrypto::wipe(&mut rnd);
    let cl = buf.tls;
    let ke = buf.ke;
    let mut t = Chan { c, pos: 0, len: 0, deadline: uptime_ms() + 3 * wait_ms, msg: buf.msg };
    let result = (|| -> Result<Done, &'static str> {
        if let Err(e) = cl.connect(&mut t, cfg, &random) {
            tell!("{}: {}: NTS-KE: TLS refused: {}", tag, name, e);
            return Err("NTS-KE: TLS refused");
        }
        if cl.write(&mut t, &nts::KE_REQUEST).is_err() {
            return Err("NTS-KE: could not send the request");
        }
        // The response until End of Message, then the server's close_notify (RFC 8915 §4).
        let mut len = 0;
        let end = loop {
            match nts::ke_complete(&ke[..len]) {
                Ok(0) => {}
                Ok(e) => break e,
                Err(e) => {
                    tell!("{}: {}: NTS-KE: {}", tag, name, e.as_str());
                    return Err("NTS-KE refused");
                }
            }
            if len == ke.len() {
                return Err("NTS-KE refused");
            }
            match cl.read(&mut t, &mut ke[len..]) {
                Ok(0) => {
                    // The server closed before End of Message: a cut record or none at all.
                    let why = nts::parse_ke(&ke[..len], pool).err().unwrap_or(nts::KeError::NoEnd);
                    tell!("{}: {}: NTS-KE: {}", tag, name, why.as_str());
                    return Err("NTS-KE refused");
                }
                Ok(k) => len += k,
                Err(e) => {
                    tell!("{}: {}: NTS-KE: {}", tag, name, e);
                    return Err("NTS-KE: connection ended before End of Message");
                }
            }
        };
        // Nothing may follow End of Message but the close_notify.
        loop {
            if len > end {
                tell!("{}: {}: NTS-KE: {}", tag, name, nts::KeError::AfterEnd.as_str());
                return Err("NTS-KE refused");
            }
            match cl.read(&mut t, &mut ke[len..]) {
                Ok(0) => break,
                Ok(k) => len += k,
                Err(e) => {
                    tell!("{}: {}: NTS-KE: no close_notify after End of Message: {}", tag, name, e);
                    return Err("NTS-KE refused (no close_notify)");
                }
            }
        }
        let neg = match nts::parse_ke(&ke[..end], pool) {
            Ok(n) => n,
            Err(e) => {
                tell!("{}: {}: NTS-KE: {}", tag, name, e.as_str());
                return Err("NTS-KE refused");
            }
        };
        let mut done = Done { neg, c2s: [0; 32], s2c: [0; 32] };
        if cl.export(nts::EXPORTER_LABEL, &nts::CONTEXT_C2S, &mut done.c2s).is_err() || cl.export(nts::EXPORTER_LABEL, &nts::CONTEXT_S2C, &mut done.s2c).is_err() {
            done.wipe();
            return Err("NTS-KE: no keys from the TLS exporter");
        }
        // A bootstrap: the chain this server sent in this handshake, for the second check.
        if let Some(ch) = chain {
            if cl.take_chain(ch).is_err() {
                done.wipe();
                return Err("NTS-KE: the certificate chain was not kept");
            }
        }
        Ok(done)
    })();
    if result.is_err() {
        pool.clear();
    }
    cl.close(&mut t);
    // The session is done: its secrets, keys and buffers go (the client is a static), and so
    // does the decrypted NTS-KE response (the cookies live on only in the pool).
    cl.wipe();
    desocrypto::wipe(ke);
    close(c);
    result
}
