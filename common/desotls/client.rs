// The TLS 1.3 client (RFC 8446): the handshake, then application data, KeyUpdate and the
// end of the connection.  Only what the profile allows (docs/desotls/HANDSHAKE.md):
// X25519, TLS_AES_128_GCM_SHA256 and TLS_CHACHA20_POLY1305_SHA256, server certificates
// checked by verify.rs, CertificateVerify with ECDSA P-256 / P-384 or RSA-PSS; no PSK, no
// 0-RTT, no HelloRetryRequest, no client certificate.
//
//   let mut c = Client::new();                       // ~120 KiB – keep it in a static
//   c.connect(&mut transport, &config, &random)?;    // the whole handshake
//   c.write(&mut transport, b"GET / HTTP/1.0\r\n\r\n")?;
//   let n = c.read(&mut transport, &mut buf)?;        // 0 = the server's close_notify
//   c.close(&mut transport);
//
// The rule above all: either the server is fully authenticated (certificate chain,
// CertificateVerify, Finished) or no application data is sent – `connect` returns only
// after the server's Finished verified and ours was sent.  Every error sends an alert (when
// it can), and the connection is dead from then on: every later call returns the same
// error.  `Transport` is whatever carries the bytes (netd's TCP for netget, a script in the
// tests); the library makes no syscalls.

use core::fmt;

use super::crypto::ecdsa::{self, Curve};
use super::crypto::hash::HashAlg;
use super::crypto::rsa::{self, PssParams};
use super::crypto::sha256::Sha256;
use super::crypto::{wipe, x25519};
use super::name;
use super::record::{self, Protection, RecordError, Suite, HEADER_LEN, MAX_PLAINTEXT, MAX_RECORD, TAG_LEN};
use super::roots::Anchors;
use super::schedule::{self, Secret, HASH_LEN};
use super::verify;
use super::x509::{self, Key};
use super::Error;

/// Whatever carries the bytes.
pub trait Transport {
    /// Sends all of `data`; Err = the connection is gone.
    fn send(&mut self, data: &[u8]) -> Result<(), ()>;
    /// Receives some bytes into `buf` (at least 1); Ok(0) = the peer closed (FIN),
    /// Err = reset or another failure.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, ()>;
}

// Handshake message types.
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const NEW_SESSION_TICKET: u8 = 4;
const ENCRYPTED_EXTENSIONS: u8 = 8;
const CERTIFICATE: u8 = 11;
const CERTIFICATE_REQUEST: u8 = 13;
const CERTIFICATE_VERIFY: u8 = 15;
const FINISHED: u8 = 20;
const KEY_UPDATE: u8 = 24;

// Extensions.
const EXT_SERVER_NAME: u16 = 0;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_RECORD_SIZE_LIMIT: u16 = 28;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_COOKIE: u16 = 44;
const EXT_SIGNATURE_ALGORITHMS_CERT: u16 = 50;
const EXT_KEY_SHARE: u16 = 51;

const GROUP_X25519: u16 = 0x001d;
const TLS13: u16 = 0x0304;

/// signature_algorithms – what CertificateVerify may use (no PKCS#1 – RFC 8446 4.2.3).
const SIG_ALGS: [u16; 5] = [0x0403, 0x0503, 0x0804, 0x0805, 0x0806];
/// signature_algorithms_cert – what certificates may be signed with (verify.rs decides).
const SIG_ALGS_CERT: [u16; 8] = [0x0403, 0x0503, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601];

/// SHA-256("HelloRetryRequest") – the ServerHello.random of a HelloRetryRequest.
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

// Alerts (RFC 8446 6.2).
pub const ALERT_CLOSE_NOTIFY: u8 = 0;
pub const ALERT_UNEXPECTED_MESSAGE: u8 = 10;
pub const ALERT_BAD_RECORD_MAC: u8 = 20;
pub const ALERT_RECORD_OVERFLOW: u8 = 22;
pub const ALERT_HANDSHAKE_FAILURE: u8 = 40;
pub const ALERT_BAD_CERTIFICATE: u8 = 42;
pub const ALERT_UNSUPPORTED_CERTIFICATE: u8 = 43;
pub const ALERT_CERTIFICATE_EXPIRED: u8 = 45;
pub const ALERT_ILLEGAL_PARAMETER: u8 = 47;
pub const ALERT_UNKNOWN_CA: u8 = 48;
pub const ALERT_DECODE_ERROR: u8 = 50;
pub const ALERT_DECRYPT_ERROR: u8 = 51;
pub const ALERT_PROTOCOL_VERSION: u8 = 70;
pub const ALERT_INTERNAL_ERROR: u8 = 80;
pub const ALERT_MISSING_EXTENSION: u8 = 109;
pub const ALERT_UNSUPPORTED_EXTENSION: u8 = 110;

pub fn alert_name(a: u8) -> &'static str {
    match a {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        22 => "record_overflow",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name",
        113 => "bad_certificate_status_response",
        115 => "unknown_psk_identity",
        116 => "certificate_required",
        120 => "no_application_protocol",
        _ => "unknown alert",
    }
}

pub fn group_name(g: u16) -> Option<&'static str> {
    match g {
        0x0017 => Some("secp256r1"),
        0x0018 => Some("secp384r1"),
        0x0019 => Some("secp521r1"),
        0x001d => Some("x25519"),
        0x001e => Some("x448"),
        0x0100 => Some("ffdhe2048"),
        0x0101 => Some("ffdhe3072"),
        0x0102 => Some("ffdhe4096"),
        0x11ec => Some("X25519MLKEM768"),
        _ => None,
    }
}

/// How a connection failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The server's certificate chain was refused (verify.rs); we sent the matching alert.
    Certificate(Error),
    /// We found a problem and sent this alert.
    Local(u8),
    /// The server sent this fatal alert.
    PeerAlert(u8),
    /// The connection ended without close_notify (FIN or reset) – the data may be cut.
    Truncated,
    /// The connection is gone (reset or a failed send).
    Transport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsError {
    pub kind: Kind,
    /// What happened, for people.
    pub what: &'static str,
    /// A number the message refers to (a group), 0 = none.
    pub arg: u32,
}

impl TlsError {
    fn local(alert: u8, what: &'static str) -> TlsError {
        TlsError { kind: Kind::Local(alert), what, arg: 0 }
    }

    /// The alert this error sends to the server (None: nothing to send).
    fn alert(&self) -> Option<u8> {
        match self.kind {
            Kind::Local(a) => Some(a),
            Kind::Certificate(e) => Some(cert_alert(e)),
            _ => None,
        }
    }

    /// A security refusal (certificate, protocol, alert) – not a broken connection.
    pub fn is_security(&self) -> bool {
        matches!(self.kind, Kind::Certificate(_) | Kind::Local(_) | Kind::PeerAlert(_))
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            Kind::Certificate(e) => write!(f, "certificate refused: {}", e.as_str()),
            Kind::Local(a) => {
                f.write_str(self.what)?;
                if self.arg != 0 {
                    match group_name(self.arg as u16) {
                        Some(n) => write!(f, " {}", n)?,
                        None => write!(f, " 0x{:04x}", self.arg)?,
                    }
                }
                write!(f, " (alert {})", alert_name(a))
            }
            Kind::PeerAlert(a) => write!(f, "server refused: alert {} ({})", alert_name(a), a),
            Kind::Truncated => f.write_str(self.what),
            Kind::Transport => f.write_str(self.what),
        }
    }
}

/// The alert for a refused certificate.
fn cert_alert(e: Error) -> u8 {
    match e {
        Error::Expired | Error::NotYetValid => ALERT_CERTIFICATE_EXPIRED,
        Error::UnknownIssuer | Error::Distrusted => ALERT_UNKNOWN_CA,
        Error::UnsupportedKey | Error::UnsupportedSignatureAlgorithm | Error::UnsupportedVersion | Error::UnsupportedNameConstraint => ALERT_UNSUPPORTED_CERTIFICATE,
        _ => ALERT_BAD_CERTIFICATE,
    }
}

pub struct Config<'a> {
    /// The server's DNS name (SNI and the certificate check).
    pub host: &'a str,
    pub anchors: &'a dyn Anchors,
    /// Unix seconds – from a plausible clock (the caller checks; syscall 59).
    pub now: i64,
    /// Cipher suites to offer, in order of preference (one or both).
    pub suites: &'a [Suite],
}

/// The fresh randomness one connection needs (from getrandom): the client random, the
/// legacy session id (compatibility mode – RFC 8446 D.4) and the X25519 secret.
pub struct Random {
    pub client_random: [u8; 32],
    pub session_id: [u8; 32],
    pub x25519_secret: [u8; 32],
}

impl Drop for Random {
    fn drop(&mut self) {
        wipe(&mut self.x25519_secret);
    }
}

/// What was agreed – for the summary line.
#[derive(Clone, Copy, Debug)]
pub struct Info {
    pub suite: Suite,
    pub group: u16,
    /// The CertificateVerify algorithm.
    pub signature: u16,
    /// verify.rs's answer: certificates in the path, which anchor.
    pub path: verify::Verified,
}

pub fn signature_name(s: u16) -> &'static str {
    match s {
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        _ => "?",
    }
}

/// The biggest handshake message accepted: Certificate 64 KiB, the others 16 KiB.
const HS_MAX: usize = 64 * 1024;
const HS_MAX_OTHER: usize = 16 * 1024;
/// Room for a record and one more chunk of whatever the transport hands over.
const RBUF: usize = MAX_RECORD + 8192;
const WBUF: usize = HEADER_LEN + MAX_PLAINTEXT + 1 + TAG_LEN;
/// KeyUpdates / empty records in a row without application data.
const MAX_KEY_UPDATES: u32 = 16;
const MAX_EMPTY: u32 = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Start,
    WaitServerHello,
    WaitEncryptedExtensions,
    WaitCertificate,
    WaitCertificateVerify,
    WaitFinished,
    Connected,
    Failed,
}

/// The server's key from its certificate, copied out of the Certificate message.
#[derive(Clone, Copy)]
enum LeafKey {
    None,
    Rsa { n: [u8; rsa::MAX_BYTES], n_len: usize, e: [u8; 4], e_len: usize },
    Ec { curve: Curve, point: [u8; 97], len: usize },
}

/// Hooks for the tests (RFC 8448 and scripted servers) – only in test builds.
#[cfg(any(selftest, desotls_test))]
#[derive(Clone, Copy)]
pub struct TestHooks<'a> {
    /// Send exactly this ClientHello message (handshake header included) instead of
    /// building one; the session id and the offered extensions are read from it.
    pub client_hello: Option<&'a [u8]>,
    /// Skip verify.rs and take the server's key from the first certificate (RFC 8448's
    /// certificate is self-signed with a 1024-bit key); also allows RSA keys from 1024 bits.
    pub skip_chain_check: bool,
}

struct Io {
    rbuf: [u8; RBUF],
    rpos: usize,
    rlen: usize,
    wbuf: [u8; WBUF],
}

struct HsBuf {
    buf: [u8; HS_MAX + 4],
    len: usize,
}

struct AppBuf {
    buf: [u8; MAX_PLAINTEXT],
    pos: usize,
    len: usize,
}

struct Engine {
    state: State,
    suite: Suite,
    transcript: Sha256,
    read: Option<Protection>,
    write: Option<Protection>,
    handshake_secret: Secret,
    c_hs: Secret,
    s_hs: Secret,
    c_ap: Secret,
    s_ap: Secret,
    leaf: LeafKey,
    session_id: [u8; 32],
    session_id_len: usize,
    /// Extensions we sent (bit = extension number, for those under 64).
    offered: u64,
    offered_suites: [Option<Suite>; 2],
    group: u16,
    signature: u16,
    path: verify::Verified,
    key_updates: u32,
    empty: u32,
    got_close: bool,
    sent_close: bool,
    failed: Option<TlsError>,
    /// The server's ChangeCipherSpec may still come (until its Finished).
    ccs_allowed: bool,
    skip_chain_check: bool,
}

pub struct Client {
    io: Io,
    hs: HsBuf,
    app: AppBuf,
    st: Engine,
}

/// A small reader for handshake structures; every error is decode_error.
struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

const DECODE: TlsError = TlsError { kind: Kind::Local(ALERT_DECODE_ERROR), what: "malformed handshake message", arg: 0 };

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Cur<'a> {
        Cur { b, p: 0 }
    }
    fn left(&self) -> usize {
        self.b.len() - self.p
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        if self.left() < n {
            return Err(DECODE);
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, TlsError> {
        Ok(self.bytes(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, TlsError> {
        let b = self.bytes(2)?;
        Ok((b[0] as u16) << 8 | b[1] as u16)
    }
    fn u24(&mut self) -> Result<usize, TlsError> {
        let b = self.bytes(3)?;
        Ok((b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize)
    }
    fn vec8(&mut self) -> Result<&'a [u8], TlsError> {
        let n = self.u8()? as usize;
        self.bytes(n)
    }
    fn vec16(&mut self) -> Result<&'a [u8], TlsError> {
        let n = self.u16()? as usize;
        self.bytes(n)
    }
    fn vec24(&mut self) -> Result<&'a [u8], TlsError> {
        let n = self.u24()?;
        self.bytes(n)
    }
    fn end(&self) -> Result<(), TlsError> {
        if self.left() != 0 {
            return Err(DECODE);
        }
        Ok(())
    }
}

/// Walks an extension list: (type, data) for each, refusing a duplicate of any type.
fn for_each_ext<'a>(list: &'a [u8], mut f: impl FnMut(u16, &'a [u8]) -> Result<(), TlsError>) -> Result<(), TlsError> {
    let mut c = Cur::new(list);
    // Seen types: the ones under 64 in a bit mask, the rest compared pairwise (at most 64).
    let mut seen: u64 = 0;
    let mut others = [0u16; 64];
    let mut n_others = 0;
    while c.left() > 0 {
        let t = c.u16()?;
        let d = c.vec16()?;
        if t < 64 {
            if seen & (1 << t) != 0 {
                return Err(TlsError::local(ALERT_ILLEGAL_PARAMETER, "duplicate extension"));
            }
            seen |= 1 << t;
        } else {
            if others[..n_others].contains(&t) {
                return Err(TlsError::local(ALERT_ILLEGAL_PARAMETER, "duplicate extension"));
            }
            if n_others == others.len() {
                return Err(DECODE);
            }
            others[n_others] = t;
            n_others += 1;
        }
        f(t, d)?;
    }
    Ok(())
}

fn put(buf: &mut [u8], n: &mut usize, data: &[u8]) {
    buf[*n..*n + data.len()].copy_from_slice(data);
    *n += data.len();
}

fn put16(buf: &mut [u8], n: &mut usize, v: u16) {
    put(buf, n, &v.to_be_bytes());
}

fn rec_err(e: RecordError) -> TlsError {
    match e {
        RecordError::BadMac => TlsError::local(ALERT_BAD_RECORD_MAC, "record does not authenticate (bad tag, wrong order or replayed)"),
        RecordError::Overflow => TlsError::local(ALERT_RECORD_OVERFLOW, "record too long"),
        RecordError::NoContentType => TlsError::local(ALERT_UNEXPECTED_MESSAGE, "record without a content type"),
        RecordError::SequenceExhausted => TlsError::local(ALERT_INTERNAL_ERROR, "record numbers used up"),
    }
}

impl Io {
    /// Sends one record of `len` plaintext bytes already at wbuf[HEADER_LEN..]: protected
    /// with `prot`, or plain with `plain_type` when there is no protection yet.
    fn send_record<T: Transport>(&mut self, t: &mut T, prot: &mut Option<Protection>, content_type: u8, len: usize) -> Result<(), TlsError> {
        let total = match prot {
            Some(p) => p.seal(content_type, len, &mut self.wbuf).map_err(rec_err)?,
            None => {
                self.wbuf[0] = content_type;
                // The first ClientHello carries 0x0301 (RFC 8446 5.1); nothing else is plain.
                self.wbuf[1] = 0x03;
                self.wbuf[2] = 0x01;
                self.wbuf[3..5].copy_from_slice(&(len as u16).to_be_bytes());
                HEADER_LEN + len
            }
        };
        let r = t.send(&self.wbuf[..total]);
        // Nothing of the plaintext stays behind.
        wipe(&mut self.wbuf[..total]);
        r.map_err(|_| TlsError { kind: Kind::Transport, what: "connection lost while sending", arg: 0 })
    }

    /// Reads until a whole record is in rbuf[rpos..]; its length (header included).
    /// `protected`: the length limit of a protected record, else of a plain one.
    fn next_record<T: Transport>(&mut self, t: &mut T, protected: bool) -> Result<usize, TlsError> {
        loop {
            let have = self.rlen - self.rpos;
            if have >= HEADER_LEN {
                let h = &self.rbuf[self.rpos..self.rpos + HEADER_LEN];
                // TLS 1.3 records say 0x0303; before the ServerHello an alert of a server
                // that speaks only older versions may say 0x0301 / 0x0302.
                let version_ok = h[1] == 0x03 && (h[2] == 0x03 || (!protected && (h[2] == 0x01 || h[2] == 0x02)));
                if !version_ok {
                    return Err(TlsError::local(ALERT_PROTOCOL_VERSION, "record with a version other than TLS 1.2/1.3 framing"));
                }
                let len = (h[3] as usize) << 8 | h[4] as usize;
                let limit = if protected { record::MAX_CIPHERTEXT } else { record::MAX_PLAIN_RECORD };
                if len > limit {
                    return Err(TlsError::local(ALERT_RECORD_OVERFLOW, "record too long"));
                }
                if have >= HEADER_LEN + len {
                    return Ok(HEADER_LEN + len);
                }
            }
            if self.rpos > 0 && self.rlen == RBUF {
                self.rbuf.copy_within(self.rpos..self.rlen, 0);
                self.rlen -= self.rpos;
                self.rpos = 0;
            } else if self.rpos == self.rlen {
                self.rpos = 0;
                self.rlen = 0;
            }
            if self.rlen == RBUF {
                // Cannot happen: a record is at most MAX_RECORD < RBUF.
                return Err(TlsError::local(ALERT_INTERNAL_ERROR, "receive buffer full"));
            }
            match t.recv(&mut self.rbuf[self.rlen..]) {
                Ok(0) => return Err(TlsError { kind: Kind::Truncated, what: "connection closed without close_notify (truncated)", arg: 0 }),
                Ok(n) => self.rlen += n.min(RBUF - self.rlen),
                Err(()) => return Err(TlsError { kind: Kind::Truncated, what: "connection reset (truncated)", arg: 0 }),
            }
        }
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub const fn new() -> Client {
        Client {
            io: Io { rbuf: [0; RBUF], rpos: 0, rlen: 0, wbuf: [0; WBUF] },
            hs: HsBuf { buf: [0; HS_MAX + 4], len: 0 },
            app: AppBuf { buf: [0; MAX_PLAINTEXT], pos: 0, len: 0 },
            st: Engine {
                state: State::Start,
                suite: Suite::Aes128Gcm,
                transcript: Sha256::new(),
                read: None,
                write: None,
                handshake_secret: Secret::zero(),
                c_hs: Secret::zero(),
                s_hs: Secret::zero(),
                c_ap: Secret::zero(),
                s_ap: Secret::zero(),
                leaf: LeafKey::None,
                session_id: [0; 32],
                session_id_len: 0,
                offered: 0,
                offered_suites: [None, None],
                group: 0,
                signature: 0,
                path: verify::Verified { certs: 0, anchor_index: 0 },
                key_updates: 0,
                empty: 0,
                got_close: false,
                sent_close: false,
                failed: None,
                ccs_allowed: false,
                skip_chain_check: false,
            },
        }
    }

    /// Back to the state of `new` (a Client can be used for one connection at a time).
    fn reset(&mut self) {
        self.io.rpos = 0;
        self.io.rlen = 0;
        self.hs.len = 0;
        self.app.pos = 0;
        self.app.len = 0;
        let s = &mut self.st;
        s.state = State::Start;
        s.transcript = Sha256::new();
        s.read = None;
        s.write = None;
        s.handshake_secret = Secret::zero();
        s.c_hs = Secret::zero();
        s.s_hs = Secret::zero();
        s.c_ap = Secret::zero();
        s.s_ap = Secret::zero();
        s.leaf = LeafKey::None;
        s.offered = 0;
        s.offered_suites = [None, None];
        s.key_updates = 0;
        s.empty = 0;
        s.got_close = false;
        s.sent_close = false;
        s.failed = None;
        s.ccs_allowed = false;
        s.skip_chain_check = false;
    }

    /// The whole handshake.  Returns only when the server is authenticated and our
    /// Finished is sent; on any error the alert is sent and the connection is dead.
    pub fn connect<T: Transport>(&mut self, t: &mut T, cfg: &Config<'_>, random: &Random) -> Result<Info, TlsError> {
        self.reset();
        let r = self.handshake(t, cfg, random, None);
        self.fail_on(t, r)
    }

    /// `connect` with test hooks.
    #[cfg(any(selftest, desotls_test))]
    pub fn connect_for_test<T: Transport>(&mut self, t: &mut T, cfg: &Config<'_>, random: &Random, hooks: &TestHooks<'_>) -> Result<Info, TlsError> {
        self.reset();
        self.st.skip_chain_check = hooks.skip_chain_check;
        let r = self.handshake(t, cfg, random, hooks.client_hello);
        self.fail_on(t, r)
    }

    /// On an error: the alert (if any) and the dead state.
    fn fail_on<T: Transport, R>(&mut self, t: &mut T, r: Result<R, TlsError>) -> Result<R, TlsError> {
        if let Err(e) = &r {
            if self.st.failed.is_none() {
                if let Some(a) = e.alert() {
                    self.send_alert(t, a);
                }
                self.st.failed = Some(*e);
                self.st.state = State::Failed;
                // Keys are of no use any more.
                self.st.read = None;
                self.st.write = None;
                wipe(&mut self.app.buf);
                self.app.len = 0;
            }
        }
        r
    }

    fn send_alert<T: Transport>(&mut self, t: &mut T, alert: u8) {
        self.io.wbuf[HEADER_LEN] = 2; // fatal (close_notify: warning, below)
        self.io.wbuf[HEADER_LEN + 1] = alert;
        if alert == ALERT_CLOSE_NOTIFY {
            self.io.wbuf[HEADER_LEN] = 1;
        }
        let _ = self.io.send_record(t, &mut self.st.write, record::ALERT, 2);
    }

    fn handshake<T: Transport>(&mut self, t: &mut T, cfg: &Config<'_>, random: &Random, hello: Option<&[u8]>) -> Result<Info, TlsError> {
        name::check_host(cfg.host).map_err(|e| TlsError { kind: Kind::Certificate(e), what: "", arg: 0 })?;
        // 1. ClientHello.
        let n = match hello {
            Some(h) => {
                self.io.wbuf[HEADER_LEN..HEADER_LEN + h.len()].copy_from_slice(h);
                self.st.read_client_hello(h)?;
                self.st.x25519_secret_store(&random.x25519_secret);
                h.len()
            }
            None => self.build_client_hello(cfg, random),
        };
        self.st.transcript.update(&self.io.wbuf[HEADER_LEN..HEADER_LEN + n]);
        self.io.send_record(t, &mut None, record::HANDSHAKE, n)?;
        self.st.state = State::WaitServerHello;
        self.st.ccs_allowed = true;

        // 2. The server's messages, record by record, until its Finished.
        while self.st.state != State::Connected {
            let protected = self.st.read.is_some();
            let len = self.io.next_record(t, protected)?;
            let start = self.io.rpos;
            let ty = self.io.rbuf[start];
            let (inner, from, plen) = if ty == record::CHANGE_CIPHER_SPEC {
                // Compatibility mode: one byte 0x01, unprotected, before the server's Finished.
                if !self.st.ccs_allowed || len != HEADER_LEN + 1 || self.io.rbuf[start + HEADER_LEN] != 1 {
                    return Err(TlsError::local(ALERT_UNEXPECTED_MESSAGE, "unexpected ChangeCipherSpec"));
                }
                self.st.empty += 1;
                if self.st.empty > MAX_EMPTY {
                    return Err(TlsError::local(ALERT_UNEXPECTED_MESSAGE, "too many empty records"));
                }
                self.io.rpos += len;
                continue;
            } else if let Some(p) = &mut self.st.read {
                if ty != record::APPLICATION_DATA {
                    return Err(TlsError::local(ALERT_UNEXPECTED_MESSAGE, "unprotected record after ServerHello"));
                }
                let (it, f, l) = p.open(&mut self.io.rbuf[start..start + len]).map_err(rec_err)?;
                (it, start + f, l)
            } else {
                if ty != record::HANDSHAKE && ty != record::ALERT {
                    return Err(TlsError::local(ALERT_UNEXPECTED_MESSAGE, "unexpected record before ServerHello"));
                }
                (ty, start + HEADER_LEN, len - HEADER_LEN)
            };
            match inner {
                record::HANDSHAKE => {
                    if plen == 0 {
                        return Err(TlsError::local(ALERT_UNEXPECTED_MESSAGE, "empty handshake record"));
                    }
                    if self.hs.len + plen > self.hs.buf.len() {
                        return Err(TlsError::local(ALERT_DECODE_ERROR, "handshake message too long"));
                    }
                    self.hs.buf[self.hs.len..self.hs.len + plen].copy_from_slice(&self.io.rbuf[from..from + plen]);
                    self.hs.len += plen;
                    self.io.rpos += len;
                    self.handshake_messages(t, cfg)?;
                }
                record::ALERT => {
                    let a = self.alert_record(from, plen)?;
                    self.io.rpos += len;
                    return Err(a);
                }
                _ => return Err(TlsError::local(ALERT_UNEXPECTED_MESSAGE, "application data before the handshake ended")),
            }
        }
        Ok(Info { suite: self.st.suite, group: self.st.group, signature: self.st.signature, path: self.st.path })
    }

    /// An alert record: close_notify or the server's error.
    fn alert_record(&mut self, from: usize, len: usize) -> Result<TlsError, TlsError> {
        if len != 2 {
            return Err(TlsError::local(ALERT_DECODE_ERROR, "malformed alert"));
        }
        let code = self.io.rbuf[from + 1];
        Ok(TlsError { kind: Kind::PeerAlert(code), what: "", arg: 0 })
    }

    /// Handles every whole handshake message in hs.buf (during the handshake).
    fn handshake_messages<T: Transport>(&mut self, t: &mut T, cfg: &Config<'_>) -> Result<(), TlsError> {
        let mut off = 0;
        while self.hs.len - off >= 4 {
            let ty = self.hs.buf[off];
            let mlen = (self.hs.buf[off + 1] as usize) << 16 | (self.hs.buf[off + 2] as usize) << 8 | self.hs.buf[off + 3] as usize;
            let limit = if ty == CERTIFICATE { HS_MAX } else { HS_MAX_OTHER };
            if mlen > limit {
                return Err(TlsError::local(ALERT_DECODE_ERROR, "handshake message too long"));
            }
            if self.hs.len - off < 4 + mlen {
                break;
            }
            let whole = off..off + 4 + mlen;
            off += 4 + mlen;
            let keys_change = {
                let msg = &self.hs.buf[whole.clone()];
                self.st.message(msg, cfg)?
            };
            if keys_change {
                // A message must not run across a change of keys (RFC 8446 5.1).
                if off != self.hs.len {
                    return Err(TlsError::local(ALERT_UNEXPECTED_MESSAGE, "handshake data across a key change"));
                }
                if self.st.state == State::Connected {
                    self.send_finished(t)?;
                }
            }
        }
        self.hs.buf.copy_within(off..self.hs.len, 0);
        self.hs.len -= off;
        Ok(())
    }

    /// Our Finished (with the client handshake key), then the application keys.
    fn send_finished<T: Transport>(&mut self, t: &mut T) -> Result<(), TlsError> {
        let th = schedule::transcript_hash(&self.st.transcript);
        let mut vd = schedule::finished(&self.st.c_hs, &th);
        let b = &mut self.io.wbuf;
        b[HEADER_LEN] = FINISHED;
        b[HEADER_LEN + 1..HEADER_LEN + 4].copy_from_slice(&[0, 0, HASH_LEN as u8]);
        b[HEADER_LEN + 4..HEADER_LEN + 4 + HASH_LEN].copy_from_slice(&vd);
        wipe(&mut vd);
        self.io.send_record(t, &mut self.st.write, record::HANDSHAKE, 4 + HASH_LEN)?;
        self.st.write = Some(Protection::new(self.st.suite, &self.st.c_ap));
        self.st.c_hs = Secret::zero();
        self.st.s_hs = Secret::zero();
        self.st.handshake_secret = Secret::zero();
        Ok(())
    }

    fn build_client_hello(&mut self, cfg: &Config<'_>, random: &Random) -> usize {
        let st = &mut self.st;
        let b = &mut self.io.wbuf[HEADER_LEN..];
        let mut n = 4; // the handshake header comes last
        put16(b, &mut n, 0x0303);
        put(b, &mut n, &random.client_random);
        b[n] = 32;
        n += 1;
        put(b, &mut n, &random.session_id);
        st.session_id = random.session_id;
        st.session_id_len = 32;
        let suites = &cfg.suites[..cfg.suites.len().min(2)];
        put16(b, &mut n, (suites.len() * 2) as u16);
        for (i, s) in suites.iter().enumerate() {
            put16(b, &mut n, s.code());
            st.offered_suites[i] = Some(*s);
        }
        put(b, &mut n, &[1, 0]); // compression: null only
        let ext_len_at = n;
        n += 2;
        // server_name
        let host = cfg.host.as_bytes();
        put16(b, &mut n, EXT_SERVER_NAME);
        put16(b, &mut n, (host.len() + 5) as u16);
        put16(b, &mut n, (host.len() + 3) as u16);
        b[n] = 0;
        n += 1;
        put16(b, &mut n, host.len() as u16);
        put(b, &mut n, host);
        // supported_groups: x25519 only
        put16(b, &mut n, EXT_SUPPORTED_GROUPS);
        put(b, &mut n, &[0, 4, 0, 2]);
        put16(b, &mut n, GROUP_X25519);
        // signature_algorithms / signature_algorithms_cert
        for (ext, list) in [(EXT_SIGNATURE_ALGORITHMS, &SIG_ALGS[..]), (EXT_SIGNATURE_ALGORITHMS_CERT, &SIG_ALGS_CERT[..])] {
            put16(b, &mut n, ext);
            put16(b, &mut n, (list.len() * 2 + 2) as u16);
            put16(b, &mut n, (list.len() * 2) as u16);
            for a in list {
                put16(b, &mut n, *a);
            }
        }
        // supported_versions: TLS 1.3 only
        put16(b, &mut n, EXT_SUPPORTED_VERSIONS);
        put(b, &mut n, &[0, 3, 2]);
        put16(b, &mut n, TLS13);
        // key_share: one X25519 share
        let public = x25519::public_key(&random.x25519_secret);
        put16(b, &mut n, EXT_KEY_SHARE);
        put(b, &mut n, &[0, 38, 0, 36]);
        put16(b, &mut n, GROUP_X25519);
        put16(b, &mut n, 32);
        put(b, &mut n, &public);
        let ext_len = n - ext_len_at - 2;
        b[ext_len_at..ext_len_at + 2].copy_from_slice(&(ext_len as u16).to_be_bytes());
        b[0] = CLIENT_HELLO;
        let body = n - 4;
        b[1..4].copy_from_slice(&[(body >> 16) as u8, (body >> 8) as u8, body as u8]);
        st.offered = 1 << EXT_SERVER_NAME | 1 << EXT_SUPPORTED_GROUPS | 1 << EXT_SIGNATURE_ALGORITHMS | 1 << EXT_SIGNATURE_ALGORITHMS_CERT | 1 << EXT_SUPPORTED_VERSIONS | 1 << EXT_KEY_SHARE;
        st.x25519_secret_store(&random.x25519_secret);
        n
    }

    /// Sends application data (split into records of at most 16 KiB).
    pub fn write<T: Transport>(&mut self, t: &mut T, data: &[u8]) -> Result<(), TlsError> {
        self.usable()?;
        if self.st.sent_close {
            return Err(TlsError { kind: Kind::Transport, what: "connection already closed", arg: 0 });
        }
        for chunk in data.chunks(MAX_PLAINTEXT) {
            self.io.wbuf[HEADER_LEN..HEADER_LEN + chunk.len()].copy_from_slice(chunk);
            let r = self.io.send_record(t, &mut self.st.write, record::APPLICATION_DATA, chunk.len());
            self.fail_on(t, r)?;
        }
        Ok(())
    }

    fn usable(&self) -> Result<(), TlsError> {
        if let Some(e) = self.st.failed {
            return Err(e);
        }
        if self.st.state != State::Connected {
            return Err(TlsError { kind: Kind::Transport, what: "not connected", arg: 0 });
        }
        Ok(())
    }

    /// Reads application data: Ok(0) = the server's close_notify (a clean end); an end
    /// without it is Err(Truncated).
    pub fn read<T: Transport>(&mut self, t: &mut T, out: &mut [u8]) -> Result<usize, TlsError> {
        self.usable()?;
        loop {
            if self.app.len > 0 {
                let k = self.app.len.min(out.len());
                out[..k].copy_from_slice(&self.app.buf[self.app.pos..self.app.pos + k]);
                wipe(&mut self.app.buf[self.app.pos..self.app.pos + k]);
                self.app.pos += k;
                self.app.len -= k;
                return Ok(k);
            }
            if self.st.got_close {
                return Ok(0);
            }
            let r = self.read_record(t);
            self.fail_on(t, r)?;
        }
    }

    /// One record after the handshake.
    fn read_record<T: Transport>(&mut self, t: &mut T) -> Result<(), TlsError> {
        let len = self.io.next_record(t, true)?;
        let start = self.io.rpos;
        if self.io.rbuf[start] != record::APPLICATION_DATA {
            return Err(TlsError::local(ALERT_UNEXPECTED_MESSAGE, "unprotected record after the handshake"));
        }
        let Some(p) = &mut self.st.read else { return Err(TlsError::local(ALERT_INTERNAL_ERROR, "no read key")) };
        let (inner, f, plen) = p.open(&mut self.io.rbuf[start..start + len]).map_err(rec_err)?;
        let from = start + f;
        let result = match inner {
            record::APPLICATION_DATA => {
                if plen == 0 {
                    self.st.empty += 1;
                    if self.st.empty > MAX_EMPTY {
                        Err(TlsError::local(ALERT_UNEXPECTED_MESSAGE, "too many empty records"))
                    } else {
                        Ok(())
                    }
                } else if self.hs.len != 0 {
                    Err(TlsError::local(ALERT_UNEXPECTED_MESSAGE, "application data inside a handshake message"))
                } else {
                    self.st.empty = 0;
                    self.st.key_updates = 0;
                    self.app.buf[..plen].copy_from_slice(&self.io.rbuf[from..from + plen]);
                    self.app.pos = 0;
                    self.app.len = plen;
                    Ok(())
                }
            }
            record::ALERT => match self.alert_record(from, plen) {
                Ok(TlsError { kind: Kind::PeerAlert(ALERT_CLOSE_NOTIFY), .. }) => {
                    self.st.got_close = true;
                    Ok(())
                }
                Ok(e) => Err(e),
                Err(e) => Err(e),
            },
            record::HANDSHAKE => {
                if plen == 0 {
                    Err(TlsError::local(ALERT_UNEXPECTED_MESSAGE, "empty handshake record"))
                } else if self.hs.len + plen > HS_MAX_OTHER + 4 {
                    Err(TlsError::local(ALERT_DECODE_ERROR, "handshake message too long"))
                } else {
                    self.hs.buf[self.hs.len..self.hs.len + plen].copy_from_slice(&self.io.rbuf[from..from + plen]);
                    self.hs.len += plen;
                    Ok(())
                }
            }
            _ => Err(TlsError::local(ALERT_UNEXPECTED_MESSAGE, "unknown record type")),
        };
        wipe(&mut self.io.rbuf[start..start + len]);
        self.io.rpos += len;
        result?;
        self.post_handshake(t)
    }

    /// NewSessionTicket (ignored – no resumption) and KeyUpdate.
    fn post_handshake<T: Transport>(&mut self, t: &mut T) -> Result<(), TlsError> {
        let mut off = 0;
        while self.hs.len - off >= 4 {
            let ty = self.hs.buf[off];
            let mlen = (self.hs.buf[off + 1] as usize) << 16 | (self.hs.buf[off + 2] as usize) << 8 | self.hs.buf[off + 3] as usize;
            if mlen > HS_MAX_OTHER {
                return Err(TlsError::local(ALERT_DECODE_ERROR, "handshake message too long"));
            }
            if self.hs.len - off < 4 + mlen {
                break;
            }
            let body = off + 4..off + 4 + mlen;
            off += 4 + mlen;
            match ty {
                NEW_SESSION_TICKET => {
                    // ticket_lifetime, ticket_age_add, nonce<0..255>, ticket<1..>, extensions.
                    let mut c = Cur::new(&self.hs.buf[body]);
                    c.bytes(8)?;
                    c.vec8()?;
                    if c.vec16()?.is_empty() {
                        return Err(DECODE);
                    }
                    c.vec16()?;
                    c.end()?;
                }
                KEY_UPDATE => {
                    if mlen != 1 {
                        return Err(DECODE);
                    }
                    let request = self.hs.buf[off - 1];
                    if request > 1 {
                        return Err(TlsError::local(ALERT_ILLEGAL_PARAMETER, "KeyUpdate with a value other than 0 or 1"));
                    }
                    if off != self.hs.len {
                        return Err(TlsError::local(ALERT_UNEXPECTED_MESSAGE, "KeyUpdate not at the end of a record"));
                    }
                    self.st.key_updates += 1;
                    if self.st.key_updates > MAX_KEY_UPDATES {
                        return Err(TlsError::local(ALERT_UNEXPECTED_MESSAGE, "too many KeyUpdates without data"));
                    }
                    // Only the sender's direction: our receive key.
                    self.st.s_ap = schedule::next_traffic(&self.st.s_ap);
                    self.st.read = Some(Protection::new(self.st.suite, &self.st.s_ap));
                    if request == 1 && !self.st.sent_close {
                        self.send_key_update(t, false)?;
                    }
                }
                _ => return Err(TlsError::local(ALERT_UNEXPECTED_MESSAGE, "unexpected handshake message after the handshake")),
            }
        }
        self.hs.buf.copy_within(off..self.hs.len, 0);
        self.hs.len -= off;
        Ok(())
    }

    fn send_key_update<T: Transport>(&mut self, t: &mut T, request: bool) -> Result<(), TlsError> {
        let b = &mut self.io.wbuf;
        b[HEADER_LEN..HEADER_LEN + 5].copy_from_slice(&[KEY_UPDATE, 0, 0, 1, request as u8]);
        self.io.send_record(t, &mut self.st.write, record::HANDSHAKE, 5)?;
        self.st.c_ap = schedule::next_traffic(&self.st.c_ap);
        self.st.write = Some(Protection::new(self.st.suite, &self.st.c_ap));
        Ok(())
    }

    /// Sends a KeyUpdate and moves our sending key on; `request`: ask the server to do the
    /// same with its key.
    pub fn key_update<T: Transport>(&mut self, t: &mut T, request: bool) -> Result<(), TlsError> {
        self.usable()?;
        let r = self.send_key_update(t, request);
        self.fail_on(t, r)
    }

    /// Sends close_notify (once).  Reading can go on until the server's close_notify.
    pub fn close<T: Transport>(&mut self, t: &mut T) {
        if self.usable().is_ok() && !self.st.sent_close {
            self.send_alert(t, ALERT_CLOSE_NOTIFY);
            self.st.sent_close = true;
        }
    }

    /// The record numbers of the current keys (send, receive) and how many KeyUpdates moved
    /// them – for the tests.
    pub fn sequences(&self) -> (u64, u64) {
        (self.st.write.as_ref().map_or(0, |p| p.sequence()), self.st.read.as_ref().map_or(0, |p| p.sequence()))
    }

    /// The current application traffic secrets (client, server) – for the tests, which check
    /// them against values computed independently.
    #[cfg(any(selftest, desotls_test))]
    pub fn traffic_secrets_for_test(&self) -> ([u8; 32], [u8; 32]) {
        (self.st.c_ap.0, self.st.s_ap.0)
    }
}

impl Engine {
    fn x25519_secret_store(&mut self, s: &[u8; 32]) {
        // Kept in handshake_secret's storage until the ServerHello replaces it with the
        // Handshake Secret – no separate copy to wipe.
        self.handshake_secret.0 = *s;
    }

    /// Reads the session id and offered extensions of a ClientHello given by a test.
    #[cfg(any(selftest, desotls_test))]
    fn read_client_hello(&mut self, h: &[u8]) -> Result<(), TlsError> {
        let mut c = Cur::new(h);
        c.bytes(4 + 2 + 32)?;
        let sid = c.vec8()?;
        self.session_id[..sid.len()].copy_from_slice(sid);
        self.session_id_len = sid.len();
        let suites = c.vec16()?;
        let mut k = 0;
        for s in suites.chunks(2) {
            if let Some(su) = Suite::from_code((s[0] as u16) << 8 | s[1] as u16) {
                if k < 2 {
                    self.offered_suites[k] = Some(su);
                    k += 1;
                }
            }
        }
        c.vec8()?;
        let exts = c.vec16()?;
        let mut offered = 0u64;
        for_each_ext(exts, |ty, _| {
            if ty < 64 {
                offered |= 1 << ty;
            }
            Ok(())
        })?;
        self.offered = offered;
        Ok(())
    }

    #[cfg(not(any(selftest, desotls_test)))]
    fn read_client_hello(&mut self, _h: &[u8]) -> Result<(), TlsError> {
        Err(TlsError::local(ALERT_INTERNAL_ERROR, "no test hooks"))
    }

    /// One handshake message during the handshake.  Returns true when the keys change after
    /// it (ServerHello, the server's Finished).
    fn message(&mut self, msg: &[u8], cfg: &Config<'_>) -> Result<bool, TlsError> {
        let ty = msg[0];
        let body = &msg[4..];
        match (self.state, ty) {
            (State::WaitServerHello, SERVER_HELLO) => {
                self.server_hello(body)?;
                self.transcript.update(msg);
                self.handshake_keys()?;
                self.state = State::WaitEncryptedExtensions;
                Ok(true)
            }
            (State::WaitEncryptedExtensions, ENCRYPTED_EXTENSIONS) => {
                self.encrypted_extensions(body)?;
                self.transcript.update(msg);
                self.state = State::WaitCertificate;
                Ok(false)
            }
            (State::WaitCertificate, CERTIFICATE_REQUEST) => Err(TlsError::local(ALERT_HANDSHAKE_FAILURE, "the server asks for a client certificate (not supported)")),
            (State::WaitCertificate, CERTIFICATE) => {
                self.certificate(body, cfg)?;
                self.transcript.update(msg);
                self.state = State::WaitCertificateVerify;
                Ok(false)
            }
            (State::WaitCertificateVerify, CERTIFICATE_VERIFY) => {
                let th = schedule::transcript_hash(&self.transcript);
                self.certificate_verify(body, &th)?;
                self.transcript.update(msg);
                self.state = State::WaitFinished;
                Ok(false)
            }
            (State::WaitFinished, FINISHED) => {
                let th = schedule::transcript_hash(&self.transcript);
                if body.len() != HASH_LEN {
                    return Err(DECODE);
                }
                if !schedule::finished_ok(&self.s_hs, &th, body) {
                    return Err(TlsError::local(ALERT_DECRYPT_ERROR, "server Finished does not verify"));
                }
                self.transcript.update(msg);
                // The application secrets: transcript up to the server's Finished.
                let th = schedule::transcript_hash(&self.transcript);
                let master = schedule::master_secret(&self.handshake_secret);
                self.c_ap = schedule::derive_secret(&master.0, b"c ap traffic", &th);
                self.s_ap = schedule::derive_secret(&master.0, b"s ap traffic", &th);
                self.read = Some(Protection::new(self.suite, &self.s_ap));
                self.ccs_allowed = false;
                self.state = State::Connected;
                // Our Finished (transcript including the server's Finished) is sent by the
                // caller with the client handshake key; c_hs stays until then.
                self.empty = 0;
                Ok(true)
            }
            _ => Err(TlsError::local(ALERT_UNEXPECTED_MESSAGE, "handshake message out of order")),
        }
    }

    fn server_hello(&mut self, body: &[u8]) -> Result<(), TlsError> {
        let mut c = Cur::new(body);
        let version = c.u16()?;
        let random = c.bytes(32)?;
        let sid = c.vec8()?;
        let suite = c.u16()?;
        let compression = c.u8()?;
        let exts = c.vec16()?;
        c.end()?;
        if random == HRR_RANDOM {
            return Err(hello_retry(exts));
        }
        let mut versions: Option<u16> = None;
        let mut share: Option<&[u8]> = None;
        for_each_ext(exts, |ty, d| {
            match ty {
                EXT_SUPPORTED_VERSIONS => {
                    if d.len() != 2 {
                        return Err(DECODE);
                    }
                    versions = Some((d[0] as u16) << 8 | d[1] as u16);
                }
                EXT_KEY_SHARE => share = Some(d),
                _ => return Err(TlsError::local(ALERT_UNSUPPORTED_EXTENSION, "ServerHello with an extension we did not offer")),
            }
            Ok(())
        })?;
        match versions {
            Some(TLS13) => {}
            Some(_) => return Err(TlsError::local(ALERT_ILLEGAL_PARAMETER, "ServerHello selects a version we did not offer")),
            None => return Err(TlsError::local(ALERT_PROTOCOL_VERSION, "server offers TLS 1.2 or older (TLS 1.3 only)")),
        }
        if version != 0x0303 {
            return Err(TlsError::local(ALERT_ILLEGAL_PARAMETER, "ServerHello legacy_version is not 0x0303"));
        }
        if sid != &self.session_id[..self.session_id_len] {
            return Err(TlsError::local(ALERT_ILLEGAL_PARAMETER, "ServerHello does not echo our session id"));
        }
        let Some(s) = Suite::from_code(suite).filter(|s| self.offered_suites.contains(&Some(*s))) else {
            return Err(TlsError::local(ALERT_ILLEGAL_PARAMETER, "ServerHello selects a cipher suite we did not offer"));
        };
        if compression != 0 {
            return Err(TlsError::local(ALERT_ILLEGAL_PARAMETER, "ServerHello with compression"));
        }
        let Some(share) = share else {
            return Err(TlsError::local(ALERT_MISSING_EXTENSION, "ServerHello without key_share"));
        };
        let mut k = Cur::new(share);
        let group = k.u16()?;
        let key = k.vec16()?;
        k.end()?;
        if group != GROUP_X25519 {
            return Err(TlsError { kind: Kind::Local(ALERT_ILLEGAL_PARAMETER), what: "ServerHello key share of a group we did not offer", arg: group as u32 });
        }
        if key.len() != 32 {
            return Err(TlsError::local(ALERT_ILLEGAL_PARAMETER, "X25519 key share of a wrong length"));
        }
        let mut theirs = [0u8; 32];
        theirs.copy_from_slice(key);
        // An all-zero result (a low-order point) is refused by x25519.
        let mut shared = x25519::x25519(&self.handshake_secret.0, &theirs).map_err(|_| TlsError::local(ALERT_ILLEGAL_PARAMETER, "X25519 key share of low order"))?;
        self.handshake_secret = schedule::handshake_secret(&shared);
        wipe(&mut shared);
        self.suite = s;
        self.group = group;
        Ok(())
    }

    fn handshake_keys(&mut self) -> Result<(), TlsError> {
        let th = schedule::transcript_hash(&self.transcript);
        self.c_hs = schedule::derive_secret(&self.handshake_secret.0, b"c hs traffic", &th);
        self.s_hs = schedule::derive_secret(&self.handshake_secret.0, b"s hs traffic", &th);
        self.read = Some(Protection::new(self.suite, &self.s_hs));
        self.write = Some(Protection::new(self.suite, &self.c_hs));
        Ok(())
    }

    fn encrypted_extensions(&mut self, body: &[u8]) -> Result<(), TlsError> {
        let mut c = Cur::new(body);
        let exts = c.vec16()?;
        c.end()?;
        let offered = self.offered;
        for_each_ext(exts, |ty, d| {
            let ok = match ty {
                // The server used our name: an empty extension.
                EXT_SERVER_NAME => offered & (1 << EXT_SERVER_NAME) != 0 && d.is_empty(),
                // Its own preference – allowed, not used.
                EXT_SUPPORTED_GROUPS => true,
                EXT_RECORD_SIZE_LIMIT => offered & (1 << EXT_RECORD_SIZE_LIMIT) != 0 && d.len() == 2,
                _ => false,
            };
            if !ok {
                return Err(TlsError::local(ALERT_UNSUPPORTED_EXTENSION, "EncryptedExtensions with an extension we did not offer"));
            }
            Ok(())
        })
    }

    fn certificate(&mut self, body: &[u8], cfg: &Config<'_>) -> Result<(), TlsError> {
        let mut c = Cur::new(body);
        if !c.vec8()?.is_empty() {
            return Err(TlsError::local(ALERT_ILLEGAL_PARAMETER, "Certificate with a request context"));
        }
        let list = c.vec24()?;
        c.end()?;
        let mut chain: [&[u8]; verify::MAX_CHAIN + 1] = [&[]; verify::MAX_CHAIN + 1];
        let mut n = 0;
        let mut l = Cur::new(list);
        while l.left() > 0 {
            let der = l.vec24()?;
            let exts = l.vec16()?;
            if der.is_empty() {
                return Err(DECODE);
            }
            if !exts.is_empty() {
                return Err(TlsError::local(ALERT_UNSUPPORTED_EXTENSION, "certificate entry with an extension we did not ask for"));
            }
            if n == chain.len() {
                return Err(TlsError { kind: Kind::Certificate(Error::ChainTooLong), what: "", arg: 0 });
            }
            chain[n] = der;
            n += 1;
        }
        if n == 0 {
            return Err(TlsError::local(ALERT_DECODE_ERROR, "the server sent no certificate"));
        }
        if !self.skip_chain_check {
            self.path = verify::server(&chain[..n], cfg.anchors, cfg.host, cfg.now).map_err(|e| TlsError { kind: Kind::Certificate(e), what: "", arg: 0 })?;
        }
        // The key for CertificateVerify, copied (the message buffer is reused).
        let leaf = x509::Cert::parse(chain[0], false).map_err(|e| TlsError { kind: Kind::Certificate(e), what: "", arg: 0 })?;
        self.leaf = match leaf.key.map_err(|e| TlsError { kind: Kind::Certificate(e), what: "", arg: 0 })? {
            Key::Rsa { n, e } => {
                if n.len() > rsa::MAX_BYTES || e.len() > 4 {
                    return Err(TlsError { kind: Kind::Certificate(Error::BadKey), what: "", arg: 0 });
                }
                let mut nb = [0u8; rsa::MAX_BYTES];
                nb[..n.len()].copy_from_slice(n);
                let mut eb = [0u8; 4];
                eb[..e.len()].copy_from_slice(e);
                LeafKey::Rsa { n: nb, n_len: n.len(), e: eb, e_len: e.len() }
            }
            Key::Ec { curve, point } => {
                let mut p = [0u8; 97];
                p[..point.len()].copy_from_slice(point);
                LeafKey::Ec { curve, point: p, len: point.len() }
            }
        };
        Ok(())
    }

    fn certificate_verify(&mut self, body: &[u8], th: &[u8; HASH_LEN]) -> Result<(), TlsError> {
        let mut c = Cur::new(body);
        let alg = c.u16()?;
        let sig = c.vec16()?;
        c.end()?;
        if !SIG_ALGS.contains(&alg) {
            return Err(TlsError::local(ALERT_ILLEGAL_PARAMETER, "CertificateVerify with an algorithm we did not offer"));
        }
        // The signed content (RFC 8446 4.4.3).
        let mut content = [0u8; 64 + 33 + 1 + HASH_LEN];
        content[..64].fill(0x20);
        content[64..97].copy_from_slice(b"TLS 1.3, server CertificateVerify");
        content[97] = 0;
        content[98..].copy_from_slice(th);
        let bad = TlsError::local(ALERT_DECRYPT_ERROR, "server CertificateVerify signature does not verify");
        let mismatch = TlsError::local(ALERT_ILLEGAL_PARAMETER, "CertificateVerify algorithm does not fit the server's key");
        match (alg, &self.leaf) {
            (0x0403, LeafKey::Ec { curve: Curve::P256, point, len }) | (0x0503, LeafKey::Ec { curve: Curve::P384, point, len }) => {
                let curve = if alg == 0x0403 { Curve::P256 } else { Curve::P384 };
                ecdsa::verify(curve, &point[..*len], &content, sig).map_err(|_| bad)?;
            }
            (0x0804 | 0x0805 | 0x0806, LeafKey::Rsa { n, n_len, e, e_len }) => {
                let hash = match alg {
                    0x0804 => HashAlg::Sha256,
                    0x0805 => HashAlg::Sha384,
                    _ => HashAlg::Sha512,
                };
                let key = self.rsa_key(&n[..*n_len], &e[..*e_len])?;
                key.verify_pss(&PssParams::tls(hash), &content, sig).map_err(|_| bad)?;
            }
            _ => return Err(mismatch),
        }
        self.signature = alg;
        Ok(())
    }

    fn rsa_key(&self, n: &[u8], e: &[u8]) -> Result<rsa::PublicKey, TlsError> {
        let bad = TlsError { kind: Kind::Certificate(Error::BadKey), what: "", arg: 0 };
        #[cfg(any(selftest, desotls_test))]
        if self.skip_chain_check {
            return rsa::PublicKey::new_for_test(n, e).map_err(|_| bad);
        }
        rsa::PublicKey::new(n, e).map_err(|_| bad)
    }
}

/// A HelloRetryRequest – never accepted; the reason by RFC 8446 4.1.4 / 4.2.8.
fn hello_retry(exts: &[u8]) -> TlsError {
    let malformed = TlsError::local(ALERT_DECODE_ERROR, "malformed HelloRetryRequest");
    let mut group: Option<u16> = None;
    let mut cookie = false;
    let r = for_each_ext(exts, |ty, d| {
        match ty {
            EXT_KEY_SHARE => {
                if d.len() != 2 {
                    return Err(malformed);
                }
                group = Some((d[0] as u16) << 8 | d[1] as u16);
            }
            EXT_COOKIE => {
                let mut c = Cur::new(d);
                if c.vec16().map_or(true, |v| v.is_empty()) || c.end().is_err() {
                    return Err(malformed);
                }
                cookie = true;
            }
            EXT_SUPPORTED_VERSIONS => {
                if d != [0x03, 0x04] {
                    return Err(malformed);
                }
            }
            _ => {}
        }
        Ok(())
    });
    if r.is_err() {
        return malformed;
    }
    match (group, cookie) {
        (Some(GROUP_X25519), _) => TlsError::local(ALERT_ILLEGAL_PARAMETER, "HRR asks for group already offered"),
        (Some(g), _) => TlsError { kind: Kind::Local(ALERT_ILLEGAL_PARAMETER), what: "server asked for undeclared group", arg: g as u32 },
        (None, true) => TlsError::local(ALERT_HANDSHAKE_FAILURE, "HelloRetryRequest unsupported"),
        (None, false) => TlsError::local(ALERT_ILLEGAL_PARAMETER, "HRR changes nothing"),
    }
}
