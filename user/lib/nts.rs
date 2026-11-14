// NTS – Network Time Security for NTP (RFC 8915) without any input or output: the NTS-KE
// records (the key exchange over TLS 1.3, ALPN "ntske/1", port 4460), the NTS extension
// fields of an NTP packet, the cookie pool.  /bin/nettime (--nts) carries the bytes: TCP and
// DeSoTLS for NTS-KE, a UDP socket for NTP.  The NTP header and its checks are ntp.rs.
//
// NTS-KE (RFC 8915 §4).  A record: u16 type (top bit = critical), u16 body length, body.
//   request (ours): Next Protocol {0 = NTPv4} (critical), AEAD {15 = AEAD_AES_SIV_CMAC_256}
//                   (critical), End of Message (critical)
//   response – accepted only when: Next Protocol exactly once and exactly {0}; AEAD exactly
//   once and exactly 15; at least one usable cookie (New Cookie: 16-1024 bytes and a length
//   divisible by 4 – the NTP extension field must be a multiple of 4 and the server needs its
//   exact bytes back, so a cookie is never padded: other cookies are skipped); at most 8
//   cookies kept; Server Negotiation (at most once, 1-253 bytes of host name or IPv4
//   address) and Port Negotiation (at most once, port != 0) are used for NTP – without them
//   the KE server's address and port 123 (§4.1.7, §4.1.8); Error → refused with its code;
//   Warning → refused (§4.1.4: unknown warning codes are errors, none are defined); a
//   repeated one-time record, a missing mandatory one, an unknown critical record → refused;
//   an unknown non-critical record → skipped; a body shorter than its type needs → refused;
//   no End of Message, a cut record, anything after End of Message, a message longer than
//   65 536 bytes (decrypted TLS application data, §4) → refused.
//
// Keys (§5.1): the TLS exporter, label "EXPORTER-network-time-security", context
// 00 00 | 00 0f | 00 (C2S) / 01 (S2C), 32 bytes each.
//
// NTP with NTS (§5).  Extension fields (RFC 7822): u16 type, u16 length (whole field, a
// multiple of 4, at least 16), body.
//   request: the 48-byte header (ntp::build_query – random Transmit, Precision 0x20)
//            + Unique Identifier (0x0104, 32 random bytes) + NTS Cookie (0x0204, one unused
//            cookie) + Cookie Placeholder × p (0x0304, as long as the cookie, zeros) + NTS
//            Authenticator (0x0404: nonce length, ciphertext length, 16-byte random nonce,
//            the 16-byte SIV of AES-SIV-CMAC-256 under C2S over everything before this field
//            with an empty plaintext)
//   p = min(7, 7 - r), r = unused cookies after taking the one sent (the server returns
//   1 + p, so the pool stays <= 8); fewer while the request would be longer than `limit`
//   (1200 bytes by default – paths with a smaller MTU, no PMTU discovery here), never
//   longer than 1469 bytes (1472 - 3: an answer may be up to 3 bytes longer).
//   response – the order of the checks (`check_response`):
//     1. length >= 48, mode 4, version 3 / 4, Origin = our Transmit; the extension fields
//        well formed;
//     2. stratum 0: only an NTS NAK (Kiss code "NTSN") with our Unique Identifier means
//        something – `Answer::Nak` (a control message, never a time: send the next query,
//        a new NTS-KE when that fails too); any other stratum-0 answer – ignored (`Reject::
//        UnauthenticatedKod` – not authenticated, RFC 8915 §5.7);
//     3. our Unique Identifier (exactly one), the Authenticator exactly once and valid
//        (S2C, everything before it as associated data); fields after it are ignored – they
//        are not authenticated (§5.7) and nothing in them is used; new cookies come only
//        from the encrypted part;
//     4. then every check of ntp.rs on the header (LI, stratum, timestamps, root delay /
//        dispersion, distance).
//
// Cookies are used once (each query takes a new one, also when its answer never comes – a
// cookie never goes out twice) – that keeps queries unlinkable (§5.7).  They and the keys
// stay in memory only; nothing is written to a file or a log (RFC 8915 recommends keeping
// one across restarts – DeSoOS does not yet: after a restart, always a new NTS-KE).
#![allow(dead_code)]

use super::desocrypto::aes_siv::{self, AesSiv};
use super::ntp;

pub const KE_PORT: u16 = 4460;
pub const ALPN: &[u8] = b"ntske/1";
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-network-time-security";
pub const AEAD_AES_SIV_CMAC_256: u16 = 15;
pub const NEXT_PROTOCOL_NTPV4: u16 = 0;
/// The longest NTS-KE response message taken (RFC 8915 §4: at least 65 536 octets).
pub const KE_MAX: usize = 65_536;
pub const COOKIE_MIN: usize = 16;
pub const COOKIE_MAX: usize = 1024;
pub const POOL: usize = 8;
pub const UID_LEN: usize = 32;
pub const NONCE_LEN: usize = 16;
/// Default and absolute limits of a request (see the file comment).
pub const REQUEST_LIMIT: usize = 1200;
pub const REQUEST_MAX: usize = 1469;
/// The biggest answer read (UDP_MAX).
pub const RESPONSE_MAX: usize = 1472;

// NTS-KE record types.
const KE_END: u16 = 0;
const KE_NEXT_PROTOCOL: u16 = 1;
const KE_ERROR: u16 = 2;
const KE_WARNING: u16 = 3;
const KE_AEAD: u16 = 4;
const KE_COOKIE: u16 = 5;
const KE_SERVER: u16 = 6;
const KE_PORT_NEG: u16 = 7;
const CRITICAL: u16 = 0x8000;

// NTP extension field types.
const EF_UID: u16 = 0x0104;
const EF_COOKIE: u16 = 0x0204;
const EF_PLACEHOLDER: u16 = 0x0304;
const EF_AUTH: u16 = 0x0404;

/// The NTS-KE request: Next Protocol {0}, AEAD {15}, End of Message – all critical.
pub const KE_REQUEST: [u8; 16] = [0x80, 0x01, 0x00, 0x02, 0x00, 0x00, 0x80, 0x04, 0x00, 0x02, 0x00, 0x0f, 0x80, 0x00, 0x00, 0x00];

/// The exporter contexts (Protocol ID 0, AEAD 15, direction).
pub const CONTEXT_C2S: [u8; 5] = [0, 0, 0, 15, 0];
pub const CONTEXT_S2C: [u8; 5] = [0, 0, 0, 15, 1];

/// Why an NTS-KE response was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeError {
    TooLong,
    Cut,
    NoEnd,
    AfterEnd,
    Error(u16),
    Warning(u16),
    Repeated(u16),
    MissingNextProtocol,
    MissingAead,
    BadNextProtocol,
    BadAead,
    NoCookies,
    BadServer,
    BadPort,
    UnknownCritical(u16),
    Short(u16),
}

impl KeError {
    pub fn as_str(self) -> &'static str {
        match self {
            KeError::TooLong => "NTS-KE response longer than 65536 bytes",
            KeError::Cut => "NTS-KE record cut short",
            KeError::NoEnd => "NTS-KE response without End of Message",
            KeError::AfterEnd => "data after End of Message",
            KeError::Error(_) => "the server sent an NTS-KE Error record",
            KeError::Warning(_) => "the server sent an NTS-KE Warning record (treated as an error)",
            KeError::Repeated(_) => "a one-time NTS-KE record came twice",
            KeError::MissingNextProtocol => "no Next Protocol record",
            KeError::MissingAead => "no AEAD record",
            KeError::BadNextProtocol => "Next Protocol is not exactly NTPv4",
            KeError::BadAead => "AEAD is not AEAD_AES_SIV_CMAC_256",
            KeError::NoCookies => "no usable cookie (16-1024 bytes, length divisible by 4)",
            KeError::BadServer => "bad NTPv4 Server Negotiation record",
            KeError::BadPort => "bad NTPv4 Port Negotiation record",
            KeError::UnknownCritical(_) => "unknown critical NTS-KE record",
            KeError::Short(_) => "NTS-KE record body too short",
        }
    }
}

/// One cookie.
#[derive(Clone, Copy)]
pub struct Cookie {
    pub len: usize,
    pub data: [u8; COOKIE_MAX],
}

impl Cookie {
    pub const EMPTY: Cookie = Cookie { len: 0, data: [0; COOKIE_MAX] };
    pub fn bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Unused cookies.
pub struct Pool {
    pub cookies: [Cookie; POOL],
    pub n: usize,
    /// Cookies skipped (unusable length) and dropped because the pool was full.
    pub skipped: usize,
    pub overflow: usize,
}

impl Pool {
    pub const fn new() -> Pool {
        Pool { cookies: [Cookie::EMPTY; POOL], n: 0, skipped: 0, overflow: 0 }
    }

    /// A cookie of the right shape joins the pool (false: skipped or the pool is full).
    pub fn add(&mut self, c: &[u8]) -> bool {
        if c.len() < COOKIE_MIN || c.len() > COOKIE_MAX || c.len() % 4 != 0 {
            self.skipped += 1;
            return false;
        }
        if self.n == POOL {
            self.overflow += 1;
            return false;
        }
        self.cookies[self.n].len = c.len();
        self.cookies[self.n].data[..c.len()].copy_from_slice(c);
        self.n += 1;
        true
    }

    /// Takes one cookie out (the oldest); it is gone from the pool for good.
    pub fn take(&mut self) -> Option<Cookie> {
        if self.n == 0 {
            return None;
        }
        let c = self.cookies[0];
        self.cookies.copy_within(1..self.n, 0);
        self.n -= 1;
        self.cookies[self.n] = Cookie::EMPTY;
        Some(c)
    }

    pub fn clear(&mut self) {
        for c in self.cookies.iter_mut() {
            *c = Cookie::EMPTY;
        }
        self.n = 0;
    }
}

impl Default for Pool {
    fn default() -> Pool {
        Pool::new()
    }
}

/// Where NTP goes after NTS-KE: a host from Server Negotiation (or None = the KE server's
/// address) and the port (123 unless negotiated).
#[derive(Clone, Copy)]
pub struct Negotiated {
    pub server: [u8; 253],
    pub server_len: usize,
    pub port: u16,
}

impl Negotiated {
    pub fn server(&self) -> Option<&str> {
        if self.server_len == 0 {
            None
        } else {
            core::str::from_utf8(&self.server[..self.server_len]).ok()
        }
    }
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

/// Is the whole NTS-KE response in `data`?  Ok(len) = it ends at `len` (End of Message);
/// Ok(0) = not yet; Err – it can never become valid (too long).
pub fn ke_complete(data: &[u8]) -> Result<usize, KeError> {
    let mut p = 0;
    while p + 4 <= data.len() {
        let ty = be16(&data[p..]) & !CRITICAL;
        let len = be16(&data[p + 2..]) as usize;
        if p + 4 + len > KE_MAX {
            return Err(KeError::TooLong);
        }
        if p + 4 + len > data.len() {
            return Ok(0);
        }
        p += 4 + len;
        if ty == KE_END {
            return Ok(p);
        }
    }
    if data.len() > KE_MAX {
        return Err(KeError::TooLong);
    }
    Ok(0)
}

/// Checks a whole NTS-KE response (`data` = everything the server sent before its
/// close_notify).  Cookies go into `pool` (which is cleared first).
pub fn parse_ke(data: &[u8], pool: &mut Pool) -> Result<Negotiated, KeError> {
    pool.clear();
    pool.skipped = 0;
    pool.overflow = 0;
    if data.len() > KE_MAX {
        return Err(KeError::TooLong);
    }
    let mut neg = Negotiated { server: [0; 253], server_len: 0, port: ntp::PORT };
    let (mut next, mut aead, mut server, mut port) = (false, false, false, false);
    let mut p = 0;
    loop {
        if p == data.len() {
            return Err(KeError::NoEnd);
        }
        if p + 4 > data.len() {
            return Err(KeError::Cut);
        }
        let raw = be16(&data[p..]);
        let critical = raw & CRITICAL != 0;
        let ty = raw & !CRITICAL;
        let len = be16(&data[p + 2..]) as usize;
        if p + 4 + len > data.len() {
            return Err(KeError::Cut);
        }
        let body = &data[p + 4..p + 4 + len];
        p += 4 + len;
        match ty {
            KE_END => {
                if p != data.len() {
                    return Err(KeError::AfterEnd);
                }
                break;
            }
            KE_NEXT_PROTOCOL => {
                if next {
                    return Err(KeError::Repeated(ty));
                }
                next = true;
                if body.is_empty() {
                    return Err(KeError::Short(ty));
                }
                if body.len() != 2 || be16(body) != NEXT_PROTOCOL_NTPV4 {
                    return Err(KeError::BadNextProtocol);
                }
            }
            KE_ERROR => return Err(KeError::Error(if body.len() >= 2 { be16(body) } else { 0xFFFF })),
            KE_WARNING => return Err(KeError::Warning(if body.len() >= 2 { be16(body) } else { 0xFFFF })),
            KE_AEAD => {
                if aead {
                    return Err(KeError::Repeated(ty));
                }
                aead = true;
                if body.is_empty() {
                    return Err(KeError::Short(ty));
                }
                if body.len() != 2 || be16(body) != AEAD_AES_SIV_CMAC_256 {
                    return Err(KeError::BadAead);
                }
            }
            KE_COOKIE => {
                pool.add(body);
            }
            KE_SERVER => {
                if server {
                    return Err(KeError::Repeated(ty));
                }
                server = true;
                let ok = !body.is_empty() && body.len() <= 253 && body.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
                if !ok {
                    return Err(KeError::BadServer);
                }
                neg.server[..body.len()].copy_from_slice(body);
                neg.server_len = body.len();
            }
            KE_PORT_NEG => {
                if port {
                    return Err(KeError::Repeated(ty));
                }
                port = true;
                if body.len() != 2 || be16(body) == 0 {
                    return Err(KeError::BadPort);
                }
                neg.port = be16(body);
            }
            _ => {
                if critical {
                    return Err(KeError::UnknownCritical(ty));
                }
            }
        }
    }
    if !next {
        return Err(KeError::MissingNextProtocol);
    }
    if !aead {
        return Err(KeError::MissingAead);
    }
    if pool.n == 0 {
        return Err(KeError::NoCookies);
    }
    Ok(neg)
}

/// The two keys of one NTS-KE session.
pub struct Keys {
    pub c2s: [u8; 32],
    pub s2c: [u8; 32],
}

impl Drop for Keys {
    fn drop(&mut self) {
        super::desocrypto::wipe(&mut self.c2s);
        super::desocrypto::wipe(&mut self.s2c);
    }
}

/// How many Cookie Placeholders go with a request that sends one cookie of `cookie_len`
/// bytes while `remaining` unused cookies stay in the pool: min(7, 7 - remaining), then
/// fewer while the request would exceed `limit` (never above REQUEST_MAX).  None: even
/// without placeholders the request would be longer than REQUEST_MAX.
pub fn placeholders(remaining: usize, cookie_len: usize, limit: usize) -> Option<usize> {
    let limit = limit.min(REQUEST_MAX);
    let base = request_len(cookie_len, 0);
    if base > REQUEST_MAX {
        return None;
    }
    let mut p = 7usize.saturating_sub(remaining.min(7));
    while p > 0 && request_len(cookie_len, p) > limit {
        p -= 1;
    }
    Some(p)
}

/// The length of a request with one cookie and `p` placeholders.
pub fn request_len(cookie_len: usize, p: usize) -> usize {
    ntp::PACKET + (4 + UID_LEN) + (4 + cookie_len) * (1 + p) + AUTH_LEN
}

/// The Authenticator field: header 4 + lengths 4 + nonce 16 + SIV 16.
const AUTH_LEN: usize = 4 + 4 + NONCE_LEN + aes_siv::TAG_LEN;

/// Builds an NTS request into `out`: the header with `xmit`, our `uid`, `cookie`, `p`
/// placeholders, the Authenticator with `nonce` under `c2s`.  Returns the length (Err when
/// `out` is too small or the cookie unusable).
pub fn build_request(out: &mut [u8], xmit: u64, uid: &[u8; UID_LEN], cookie: &Cookie, p: usize, nonce: &[u8; NONCE_LEN], c2s: &[u8; 32]) -> Result<usize, ()> {
    let len = request_len(cookie.len, p);
    if len > out.len() || len > REQUEST_MAX || cookie.len < COOKIE_MIN || cookie.len % 4 != 0 {
        return Err(());
    }
    out[..ntp::PACKET].copy_from_slice(&ntp::build_query(xmit));
    let mut n = ntp::PACKET;
    let ef = |ty: u16, body_len: usize, n: &mut usize, out: &mut [u8]| {
        out[*n..*n + 2].copy_from_slice(&ty.to_be_bytes());
        out[*n + 2..*n + 4].copy_from_slice(&((4 + body_len) as u16).to_be_bytes());
        *n += 4;
    };
    ef(EF_UID, UID_LEN, &mut n, out);
    out[n..n + UID_LEN].copy_from_slice(uid);
    n += UID_LEN;
    ef(EF_COOKIE, cookie.len, &mut n, out);
    out[n..n + cookie.len].copy_from_slice(cookie.bytes());
    n += cookie.len;
    for _ in 0..p {
        ef(EF_PLACEHOLDER, cookie.len, &mut n, out);
        for b in out[n..n + cookie.len].iter_mut() {
            *b = 0;
        }
        n += cookie.len;
    }
    let ad_end = n;
    ef(EF_AUTH, 4 + NONCE_LEN + aes_siv::TAG_LEN, &mut n, out);
    out[n..n + 2].copy_from_slice(&(NONCE_LEN as u16).to_be_bytes());
    out[n + 2..n + 4].copy_from_slice(&(aes_siv::TAG_LEN as u16).to_be_bytes());
    n += 4;
    out[n..n + NONCE_LEN].copy_from_slice(nonce);
    n += NONCE_LEN;
    let siv = AesSiv::new(c2s).seal(&[&out[..ad_end], nonce], &mut []).map_err(|_| ())?;
    out[n..n + aes_siv::TAG_LEN].copy_from_slice(&siv);
    n += aes_siv::TAG_LEN;
    debug_assert!(n == len);
    Ok(n)
}

/// Why an NTS answer was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// The header failed a check of ntp.rs.
    Ntp(ntp::Reject),
    /// An extension field with a bad length, or the fields do not fill the packet.
    BadField,
    /// Stratum 0 that is not an NTS NAK with our Unique Identifier – not authenticated,
    /// ignored.
    UnauthenticatedKod,
    NoUid,
    WrongUid,
    NoAuthenticator,
    TwoAuthenticators,
    BadAuthenticator,
    /// The Authenticator does not verify (wrong key, changed packet).
    AuthFailed,
}

impl Reject {
    pub fn as_str(self) -> &'static str {
        match self {
            Reject::Ntp(r) => r.as_str(),
            Reject::BadField => "malformed NTP extension field",
            Reject::UnauthenticatedKod => "unauthenticated kiss-o'-death (ignored)",
            Reject::NoUid => "no Unique Identifier",
            Reject::WrongUid => "Unique Identifier does not match the query",
            Reject::NoAuthenticator => "no NTS Authenticator (plain NTP answer)",
            Reject::TwoAuthenticators => "two NTS Authenticators",
            Reject::BadAuthenticator => "malformed NTS Authenticator",
            Reject::AuthFailed => "NTS Authenticator does not verify",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// An authenticated time; `cookies` new ones went into the pool.
    Time { reply: ntp::Reply, cookies: usize },
    /// NTS NAK with our Unique Identifier: the server did not take our cookie.
    Nak,
}

/// The extension fields after the header: (type, body, offset of the field).  Err when a
/// field is malformed (length not a multiple of 4, below 16, past the end).
fn fields(data: &[u8], mut f: impl FnMut(u16, &[u8], usize) -> bool) -> Result<(), Reject> {
    let mut p = ntp::PACKET;
    while p < data.len() {
        if p + 4 > data.len() {
            return Err(Reject::BadField);
        }
        let ty = be16(&data[p..]);
        let len = be16(&data[p + 2..]) as usize;
        if len < 16 || len % 4 != 0 || p + len > data.len() {
            return Err(Reject::BadField);
        }
        if !f(ty, &data[p + 4..p + len], p) {
            return Ok(());
        }
        p += len;
    }
    Ok(())
}

/// Checks an answer to the query with `xmit` and `uid` (the order is in the file comment);
/// new cookies from its encrypted part go into `pool`.
pub fn check_response(data: &[u8], xmit: u64, uid: &[u8; UID_LEN], s2c: &[u8; 32], pool: &mut Pool) -> Result<Answer, Reject> {
    // 1. The header's form and our Origin (ntp.rs checks the rest later).
    if data.len() < ntp::PACKET {
        return Err(Reject::Ntp(ntp::Reject::Short));
    }
    if data[0] & 7 != 4 {
        return Err(Reject::Ntp(ntp::Reject::Mode));
    }
    let version = data[0] >> 3 & 7;
    if version != 3 && version != 4 {
        return Err(Reject::Ntp(ntp::Reject::Version));
    }
    if data[24..32] != xmit.to_be_bytes() {
        return Err(Reject::Ntp(ntp::Reject::Origin));
    }
    // The fields up to (and including) the first Authenticator; what follows it is not
    // authenticated and not looked at except to count a second Authenticator.
    let mut uids = 0;
    let mut uid_ok = false;
    let mut auth: Option<(usize, usize, usize)> = None; // (field offset, body start, body len)
    let mut auths = 0;
    let r = fields(data, |ty, body, at| {
        match ty {
            EF_UID if auth.is_none() => {
                uids += 1;
                uid_ok = body.len() >= UID_LEN && body[..UID_LEN] == uid[..] && body.len() == UID_LEN;
            }
            EF_AUTH => {
                auths += 1;
                if auth.is_none() {
                    auth = Some((at, at + 4, body.len()));
                }
            }
            _ => {}
        }
        true
    });
    // A malformed field after the Authenticator does not spoil the authenticated part.
    if r.is_err() && auth.is_none() {
        return Err(Reject::BadField);
    }
    // 2. Stratum 0: only an NTS NAK with our Unique Identifier counts.
    if data[1] == 0 {
        if &data[12..16] == b"NTSN" && uids == 1 && uid_ok {
            return Ok(Answer::Nak);
        }
        return Err(Reject::UnauthenticatedKod);
    }
    // 3. Unique Identifier and Authenticator.
    if uids == 0 {
        return Err(Reject::NoUid);
    }
    if uids != 1 || !uid_ok {
        return Err(Reject::WrongUid);
    }
    let Some((at, b, blen)) = auth else { return Err(Reject::NoAuthenticator) };
    if auths > 1 {
        return Err(Reject::TwoAuthenticators);
    }
    if blen < 4 {
        return Err(Reject::BadAuthenticator);
    }
    let nlen = be16(&data[b..]) as usize;
    let clen = be16(&data[b + 2..]) as usize;
    let npad = nlen.div_ceil(4) * 4;
    let cpad = clen.div_ceil(4) * 4;
    if nlen == 0 || clen < aes_siv::TAG_LEN || 4 + npad + cpad > blen || clen - aes_siv::TAG_LEN > RESPONSE_MAX {
        return Err(Reject::BadAuthenticator);
    }
    let nonce = &data[b + 4..b + 4 + nlen];
    let ct = &data[b + 4 + npad..b + 4 + npad + clen];
    let mut siv = [0u8; aes_siv::TAG_LEN];
    siv.copy_from_slice(&ct[..aes_siv::TAG_LEN]);
    let mut plain = [0u8; RESPONSE_MAX];
    let plen = clen - aes_siv::TAG_LEN;
    plain[..plen].copy_from_slice(&ct[aes_siv::TAG_LEN..]);
    if AesSiv::new(s2c).open(&[&data[..at], nonce], &mut plain[..plen], &siv).is_err() {
        return Err(Reject::AuthFailed);
    }
    // 4. The header's time checks (ntp.rs) – only for an authenticated answer.
    let reply = match ntp::check_reply(data, xmit) {
        Ok(ntp::Answer::Time(r)) => r,
        Ok(ntp::Answer::Kod(_)) => return Err(Reject::UnauthenticatedKod),
        Err(e) => return Err(Reject::Ntp(e)),
    };
    // New cookies from the encrypted fields (a malformed inner list: none taken).
    let mut inner = [0u8; RESPONSE_MAX + ntp::PACKET];
    inner[ntp::PACKET..ntp::PACKET + plen].copy_from_slice(&plain[..plen]);
    let mut got = 0;
    let mut cand = [(0usize, 0usize); POOL * 2];
    let mut nc = 0;
    let ok = fields(&inner[..ntp::PACKET + plen], |ty, body, at| {
        if ty == EF_COOKIE && nc < cand.len() {
            cand[nc] = (at + 4, body.len());
            nc += 1;
        }
        true
    });
    if ok.is_ok() {
        for &(s, l) in cand[..nc].iter() {
            if pool.add(&inner[s..s + l]) {
                got += 1;
            }
        }
    }
    super::desocrypto::wipe(&mut plain);
    super::desocrypto::wipe(&mut inner);
    Ok(Answer::Time { reply, cookies: got })
}
