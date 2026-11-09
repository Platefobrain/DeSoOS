// DeSoTLS handshake and record tests – no network: the server's side is a script of
// bytes.  Included only by /bin/tlstest, the kernel TLS TEST and the host harness, as a
// sibling of `desotls` and `desocrypto`:
//
//   #[path = ".../common/desotls/tls_tests.rs"] mod tls_tests;
//
// 1. RFC 8448 §3 (the simple 1-RTT handshake): the published ClientHello is sent, the
//    published ServerHello, EncryptedExtensions, Certificate, CertificateVerify (an RSA-PSS
//    signature by the RFC's 1024-bit key) and server Finished are received – every secret,
//    key and iv the RFC lists must come out, the record we send must be the RFC's byte for
//    byte, and our Finished must carry the RFC's client verify_data (a8ec436d…).  The
//    vectors were taken from the tlslite-ng test suite (its copy of RFC 8448); the client
//    verify_data was computed from them with Python's hashlib/hmac – not with this code.
// 2. On that session: application data, KeyUpdate in both directions and several times,
//    record numbers, records cut into 1–7 byte pieces and several in one piece, the end with
//    and without close_notify, and every refusal (bad tag, replay, KeyUpdate values and
//    position, too many KeyUpdates / empty records, oversized records, alerts).
// 3. HelloRetryRequest (each row of the table in docs/desotls/HANDSHAKE.md) and broken
//    ServerHellos; a changed server Finished, CertificateVerify, algorithm, order and
//    extensions.
//
// `run()` stops at the first failed check (group and case); on success the number of
// checks.  No heap; the Client and the buffers are statics (one test at a time).

#![allow(dead_code)]

use super::desotls::client::{self, Client, Config, Kind, Random, TestHooks, TlsError, Transport};
use super::desotls::record::{self, Protection, Suite};
use super::desotls::roots::AnchorList;
use super::desotls::schedule::{self, Secret};

#[derive(Clone, Copy, Debug)]
pub struct Failure {
    pub group: &'static str,
    pub case: usize,
}

struct Checks {
    group: &'static str,
    case: usize,
    passed: usize,
}

impl Checks {
    fn group(&mut self, name: &'static str) {
        self.group = name;
        self.case = 0;
    }
    fn check(&mut self, ok: bool) -> Result<(), Failure> {
        self.case += 1;
        if ok {
            self.passed += 1;
            Ok(())
        } else {
            Err(Failure { group: self.group, case: self.case })
        }
    }
}

// RFC 8448 §3 messages (via tlslite-ng's unit_tests/test_tls1_3_vectors.py).
const CLIENT_X25519_SECRET: &str = concat!(
    "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005",
);
const CLIENT_HELLO: &str = concat!(
    "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece700000613011303130201",
    "0000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400",
    "230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b00",
    "03020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c",
    "00024001",
);
const CLIENT_HELLO_RECORD: &str = concat!(
    "16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece70000061301",
    "13031302010000910000000b0009000006736572766572ff01000100000a00140012001d001700180019010001010102",
    "0103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529a",
    "af2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00",
    "020101001c00024001",
);
const SERVER_HELLO_RECORD: &str = concat!(
    "160303005a020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e269280013010000",
    "2e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304",
);
const ENCRYPTED_EXTENSIONS: &str = concat!(
    "080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000",
);
const CERTIFICATE: &str = concat!(
    "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a",
    "06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a",
    "0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d98",
    "0836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced4312",
    "0998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d0",
    "3e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b060355",
    "1d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f",
    "8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102",
    "702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8",
    "f8961229ac9187b42b4de10000",
);
const CERTIFICATE_VERIFY: &str = concat!(
    "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d3",
    "3a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c",
    "9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3",
);

// Values RFC 8448 §3 lists (secrets, keys, ivs, verify_data).
const SHARED: &str = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";
const HANDSHAKE_SECRET: &str = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";
const MASTER_SECRET: &str = "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919";
const C_HS: &str = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
const S_HS: &str = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
const S_HS_KEY: &str = "3fce516009c21727d0f2e4e86ee403bc";
const S_HS_IV: &str = "5d313eb2671276ee13000b30";
const C_HS_KEY: &str = "dbfaa693d1762c5b666af5d950258d01";
const C_HS_IV: &str = "5bd3c71b836e0b76bb73265f";
const C_AP: &str = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
const S_AP: &str = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";
const S_AP_KEY: &str = "9f02283b6c9c07efc26bb9f2ac92e356";
const S_AP_IV: &str = "cf782b88dd83549aadf1e984";
// The application secrets after KeyUpdates – computed from S_AP / C_AP with Python's
// hashlib/hmac (HKDF-Expand-Label "traffic upd"), not with this code.
const S_AP_GEN3: &str = "e24ebfc0e41811ace7370dddc0739ff4ec02a318493626096dfebf8439ba974b";
const C_AP_GEN1: &str = "fcdfcc72725aaee48bf64e4fd8b749cdbdbab39d90da0b26e2245ca6ea167207";
const SERVER_FINISHED: &str = "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718";
const CLIENT_FINISHED: &str = "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61";

/// Hex (spaces allowed) into `out`; the length.
fn hex(s: &str, out: &mut [u8]) -> usize {
    let mut n = 0;
    let mut hi: Option<u8> = None;
    for c in s.bytes() {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => continue,
        };
        match hi {
            None => hi = Some(v),
            Some(h) => {
                out[n] = h << 4 | v;
                n += 1;
                hi = None;
            }
        }
    }
    n
}

fn h32(s: &str) -> [u8; 32] {
    let mut b = [0u8; 32];
    hex(s, &mut b);
    b
}

const RX_MAX: usize = 96 * 1024;
const TX_MAX: usize = 64 * 1024;

static mut CLIENT: Client = Client::new();
static mut RX: [u8; RX_MAX] = [0; RX_MAX];
static mut TX: [u8; TX_MAX] = [0; TX_MAX];
static mut TMP: [u8; record::MAX_RECORD + 64] = [0; record::MAX_RECORD + 64];

/// The server's side: bytes to hand over (in pieces of `chunk`, or cycling 1..=7 when
/// `chunk` is 0) and what the client sent.
struct Script {
    rx: &'static mut [u8; RX_MAX],
    rx_len: usize,
    rx_pos: usize,
    chunk: usize,
    turn: usize,
    /// After the bytes: Ok(0) (FIN) or, with `reset`, Err.
    reset: bool,
    tx: &'static mut [u8; TX_MAX],
    tx_len: usize,
    /// Where the next unread client record starts in tx.
    tx_read: usize,
}

impl Transport for Script {
    fn send(&mut self, data: &[u8]) -> Result<(), ()> {
        if self.tx_len + data.len() > TX_MAX {
            return Err(());
        }
        self.tx[self.tx_len..self.tx_len + data.len()].copy_from_slice(data);
        self.tx_len += data.len();
        Ok(())
    }
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        let left = self.rx_len - self.rx_pos;
        if left == 0 {
            return if self.reset { Err(()) } else { Ok(0) };
        }
        let piece = if self.chunk == 0 {
            self.turn += 1;
            1 + self.turn % 7
        } else {
            self.chunk
        };
        let k = left.min(piece).min(buf.len());
        buf[..k].copy_from_slice(&self.rx[self.rx_pos..self.rx_pos + k]);
        self.rx_pos += k;
        Ok(k)
    }
}

impl Script {
    fn push(&mut self, b: &[u8]) {
        self.rx[self.rx_len..self.rx_len + b.len()].copy_from_slice(b);
        self.rx_len += b.len();
    }
    fn push_hex(&mut self, s: &str) {
        let n = hex(s, &mut self.rx[self.rx_len..]);
        self.rx_len += n;
    }
    /// A protected record of `content` with inner type `ty`.
    fn push_sealed(&mut self, p: &mut Protection, ty: u8, content: &[u8]) {
        let tmp = unsafe { &mut *core::ptr::addr_of_mut!(TMP) };
        tmp[record::HEADER_LEN..record::HEADER_LEN + content.len()].copy_from_slice(content);
        let n = p.seal(ty, content.len(), &mut tmp[..]).unwrap_or(0);
        self.push(&tmp[..n]);
    }
    /// The next record the client sent (whole, header included).
    fn next_sent(&mut self) -> Option<&mut [u8]> {
        if self.tx_len - self.tx_read < record::HEADER_LEN {
            return None;
        }
        let len = record::HEADER_LEN + ((self.tx[self.tx_read + 3] as usize) << 8 | self.tx[self.tx_read + 4] as usize);
        if self.tx_len - self.tx_read < len {
            return None;
        }
        let r = &mut self.tx[self.tx_read..self.tx_read + len];
        self.tx_read += len;
        Some(r)
    }
}

fn fresh() -> (&'static mut Client, Script) {
    // SAFETY: the tests run one at a time; each takes the statics once.
    let c = unsafe { &mut *core::ptr::addr_of_mut!(CLIENT) };
    let rx = unsafe { &mut *core::ptr::addr_of_mut!(RX) };
    let tx = unsafe { &mut *core::ptr::addr_of_mut!(TX) };
    (c, Script { rx, rx_len: 0, rx_pos: 0, chunk: 4096, turn: 0, reset: false, tx, tx_len: 0, tx_read: 0 })
}

const NO_ANCHORS: AnchorList<'static> = AnchorList(&[]);
const AES: [Suite; 1] = [Suite::Aes128Gcm];

fn cfg() -> Config<'static> {
    Config { host: "server", anchors: &NO_ANCHORS, now: 0, suites: &AES }
}

fn rfc_random() -> Random {
    Random { client_random: [0; 32], session_id: [0; 32], x25519_secret: h32(CLIENT_X25519_SECRET) }
}

/// Ways to change the RFC's server flight.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Change {
    None,
    /// One bit of the server's verify_data.
    Finished,
    /// One bit of the CertificateVerify signature.
    Signature,
    /// The CertificateVerify algorithm.
    Algorithm(u16),
    /// The CertificateVerify signed with the client's context string – reproduced by
    /// sending the RFC signature after a Certificate the signature does not cover.
    CertificateChanged,
    /// An extra extension (ALPN) in EncryptedExtensions.
    ExtraExtension,
    /// A non-empty certificate_request_context.
    CertificateContext,
    /// A CertificateRequest before the Certificate.
    CertificateRequest,
    /// CertificateVerify before Certificate.
    Order,
    /// The Certificate twice.
    CertificateTwice,
    /// Application data before the server's Finished.
    EarlyData,
    /// One more byte of handshake data in the ServerHello's record (across the key change).
    AcrossKeyChange,
    /// An unprotected handshake record after the ServerHello.
    Unprotected,
    /// The Certificate message left out of the flight.
    NoCertificate,
}

/// The RFC's ServerHello record and its encrypted flight (with a change), into `s`.
fn push_flight(s: &mut Script, change: Change) {
    let mut sh = [0u8; 128];
    let n = hex(SERVER_HELLO_RECORD, &mut sh);
    if change == Change::AcrossKeyChange {
        sh[4] += 1;
        sh[n] = 0x08;
        s.push(&sh[..n + 1]);
    } else {
        s.push(&sh[..n]);
    }
    if change == Change::Unprotected {
        s.push(&[22, 3, 3, 0, 4, 8, 0, 0, 0]);
    }
    let mut prot = Protection::new(Suite::Aes128Gcm, &Secret(h32(S_HS)));
    let mut flight = [0u8; 2048];
    let mut f = 0;
    let mut ee = [0u8; 64];
    let mut en = hex(ENCRYPTED_EXTENSIONS, &mut ee);
    if change == Change::ExtraExtension {
        // + ALPN "h2": 00 10 00 05 00 03 02 68 32
        let extra = [0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32];
        ee[en..en + 9].copy_from_slice(&extra);
        en += 9;
        ee[3] += 9;
        ee[5] += 9;
    }
    flight[f..f + en].copy_from_slice(&ee[..en]);
    f += en;
    if change == Change::CertificateRequest {
        // context "", extensions: signature_algorithms [0x0804]
        let cr = [13, 0, 0, 11, 0, 0, 8, 0, 13, 0, 4, 0, 2, 8, 4];
        flight[f..f + cr.len()].copy_from_slice(&cr);
        f += cr.len();
    }
    let mut cert = [0u8; 512];
    let mut cn = hex(CERTIFICATE, &mut cert);
    if change == Change::CertificateContext {
        // context of one byte: the message and its length grow by 1.
        cert.copy_within(5..cn, 6);
        cert[4] = 1;
        cert[5] = 0xaa;
        cn += 1;
        cert[3] += 1;
    }
    if change == Change::CertificateChanged {
        // One byte inside the certificate's signature: the chain is not checked (RFC hooks),
        // but the transcript the RFC's CertificateVerify signed is no longer the same.
        cert[cn - 10] ^= 1;
    }
    let mut cv = [0u8; 160];
    let vn = hex(CERTIFICATE_VERIFY, &mut cv);
    if change == Change::Signature {
        cv[vn - 1] ^= 1;
    }
    if let Change::Algorithm(a) = change {
        cv[4..6].copy_from_slice(&a.to_be_bytes());
    }
    if change == Change::Order {
        flight[f..f + vn].copy_from_slice(&cv[..vn]);
        f += vn;
        flight[f..f + cn].copy_from_slice(&cert[..cn]);
        f += cn;
    } else {
        if change != Change::NoCertificate {
            flight[f..f + cn].copy_from_slice(&cert[..cn]);
            f += cn;
        }
        if change == Change::CertificateTwice {
            flight[f..f + cn].copy_from_slice(&cert[..cn]);
            f += cn;
        }
        flight[f..f + vn].copy_from_slice(&cv[..vn]);
        f += vn;
    }
    let mut fin = [0u8; 36];
    fin[..4].copy_from_slice(&[20, 0, 0, 32]);
    hex(SERVER_FINISHED, &mut fin[4..]);
    if change == Change::Finished {
        fin[10] ^= 0x40;
    }
    if change == Change::EarlyData {
        s.push_sealed(&mut prot, record::HANDSHAKE, &flight[..f]);
        s.push_sealed(&mut prot, record::APPLICATION_DATA, b"too early");
        s.push_sealed(&mut prot, record::HANDSHAKE, &fin);
        return;
    }
    flight[f..f + 36].copy_from_slice(&fin);
    f += 36;
    s.push_sealed(&mut prot, record::HANDSHAKE, &flight[..f]);
}

fn hooks(ch: &[u8]) -> TestHooks<'_> {
    TestHooks { client_hello: Some(ch), skip_chain_check: true }
}

fn rfc_connect(c: &mut Client, s: &mut Script) -> Result<client::Info, TlsError> {
    let mut ch = [0u8; 256];
    let n = hex(CLIENT_HELLO, &mut ch);
    let r = c.connect_for_test(s, &cfg(), &rfc_random(), &hooks(&ch[..n]));
    r
}

fn is_local(r: &Result<impl Sized, TlsError>, alert: u8) -> bool {
    matches!(r, Err(TlsError { kind: Kind::Local(a), .. }) if *a == alert)
}

fn is_local_what<T>(r: &Result<T, TlsError>, alert: u8, what: &str) -> bool {
    matches!(r, Err(TlsError { kind: Kind::Local(a), what: w, .. }) if *a == alert && *w == what)
}

/// The client's records after the handshake are checked with the RFC's client keys.
struct ClientKeys {
    secret: Secret,
    prot: Protection,
}

impl ClientKeys {
    fn new(s: &str) -> ClientKeys {
        let secret = Secret(h32(s));
        let prot = Protection::new(Suite::Aes128Gcm, &secret);
        ClientKeys { secret, prot }
    }
    fn update(&mut self) {
        self.secret = schedule::next_traffic(&self.secret);
        self.prot = Protection::new(Suite::Aes128Gcm, &self.secret);
    }
}

fn rfc_checks(c: &mut Checks) -> Result<(), Failure> {
    c.group("RFC 8448 key schedule");
    let hs = schedule::handshake_secret(&h32(SHARED));
    c.check(hs.0 == h32(HANDSHAKE_SECRET))?;
    c.check(schedule::master_secret(&hs).0 == h32(MASTER_SECRET))?;
    let mut k = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut want_k = [0u8; 16];
    let mut want_iv = [0u8; 12];
    for (secret, key, ivs) in [(S_HS, S_HS_KEY, S_HS_IV), (C_HS, C_HS_KEY, C_HS_IV), (S_AP, S_AP_KEY, S_AP_IV)] {
        schedule::expand_label(&h32(secret), b"key", b"", &mut k);
        schedule::expand_label(&h32(secret), b"iv", b"", &mut iv);
        hex(key, &mut want_k);
        hex(ivs, &mut want_iv);
        c.check(k == want_k && iv == want_iv)?;
    }

    c.group("RFC 8448 handshake");
    let (cl, mut s) = fresh();
    push_flight(&mut s, Change::None);
    let r = rfc_connect(cl, &mut s);
    c.check(r.is_ok())?;
    let info = r.ok();
    c.check(info.is_some_and(|i| i.suite == Suite::Aes128Gcm && i.group == 0x001d && i.signature == 0x0804))?;
    // Our first record is the RFC's ClientHello record, byte for byte.
    let mut want = [0u8; 256];
    let n = hex(CLIENT_HELLO_RECORD, &mut want);
    let first = s.next_sent().map(|r| r == &want[..n]);
    c.check(first == Some(true))?;
    // Our Finished, under the RFC's client handshake key: the RFC's verify_data.
    let mut ck = ClientKeys::new(C_HS);
    let fin = s.next_sent().and_then(|r| ck.prot.open(r).ok().map(|(t, f, l)| (t, r[f..f + l].to_vec_arr())));
    let mut wf = [0u8; 36];
    wf[..4].copy_from_slice(&[20, 0, 0, 32]);
    hex(CLIENT_FINISHED, &mut wf[4..]);
    c.check(matches!(fin, Some((22, (b, 36))) if b[..36] == wf))?;
    let (cap, sap) = cl.traffic_secrets_for_test();
    c.check(cap == h32(C_AP) && sap == h32(S_AP))?;
    // The same with the flight cut into 1..7-byte pieces.
    let (cl, mut s) = fresh();
    s.chunk = 0;
    push_flight(&mut s, Change::None);
    c.check(rfc_connect(cl, &mut s).is_ok())?;
    Ok(())
}

/// A copy of up to 64 bytes of a slice, with its length (no heap).
trait ToArr {
    fn to_vec_arr(&self) -> ([u8; 64], usize);
}

impl ToArr for [u8] {
    fn to_vec_arr(&self) -> ([u8; 64], usize) {
        let mut a = [0u8; 64];
        let k = self.len().min(64);
        a[..k].copy_from_slice(&self[..k]);
        (a, self.len())
    }
}

fn flight_checks(c: &mut Checks) -> Result<(), Failure> {
    c.group("changed server flight");
    let cases: [(Change, u8, &str); 12] = [
        (Change::Finished, client::ALERT_DECRYPT_ERROR, "server Finished does not verify"),
        (Change::Signature, client::ALERT_DECRYPT_ERROR, "server CertificateVerify signature does not verify"),
        (Change::CertificateChanged, client::ALERT_DECRYPT_ERROR, "server CertificateVerify signature does not verify"),
        (Change::Algorithm(0x0401), client::ALERT_ILLEGAL_PARAMETER, "CertificateVerify with an algorithm we did not offer"),
        (Change::Algorithm(0x0403), client::ALERT_ILLEGAL_PARAMETER, "CertificateVerify algorithm does not fit the server's key"),
        (Change::ExtraExtension, client::ALERT_UNSUPPORTED_EXTENSION, "EncryptedExtensions with an extension we did not offer"),
        (Change::CertificateContext, client::ALERT_ILLEGAL_PARAMETER, "Certificate with a request context"),
        (Change::CertificateRequest, client::ALERT_HANDSHAKE_FAILURE, "the server asks for a client certificate (not supported)"),
        (Change::Order, client::ALERT_UNEXPECTED_MESSAGE, "handshake message out of order"),
        (Change::EarlyData, client::ALERT_UNEXPECTED_MESSAGE, "application data before the handshake ended"),
        (Change::AcrossKeyChange, client::ALERT_UNEXPECTED_MESSAGE, "handshake data across a key change"),
        (Change::Unprotected, client::ALERT_UNEXPECTED_MESSAGE, "unprotected record after ServerHello"),
    ];
    for (change, alert, what) in cases {
        let (cl, mut s) = fresh();
        push_flight(&mut s, change);
        let r = rfc_connect(cl, &mut s);
        c.check(is_local_what(&r, alert, what))?;
        // Nothing after the ClientHello but the alert: no Finished, no application data.
        s.next_sent();
        let rest = s.next_sent().map(|r| r.len());
        c.check(rest == Some(record::HEADER_LEN + 2 + 1 + record::TAG_LEN) && s.next_sent().is_none())?;
        // The connection is dead: writing gives the same error.
        c.check(cl.write(&mut s, b"GET").err() == r.err())?;
    }
    let (cl, mut s) = fresh();
    push_flight(&mut s, Change::CertificateTwice);
    c.check(is_local_what(&rfc_connect(cl, &mut s), client::ALERT_UNEXPECTED_MESSAGE, "handshake message out of order"))?;
    let (cl, mut s) = fresh();
    push_flight(&mut s, Change::NoCertificate);
    c.check(is_local(&rfc_connect(cl, &mut s), client::ALERT_UNEXPECTED_MESSAGE))?;
    // The flight ends early: the server closed.
    let (cl, mut s) = fresh();
    let mut sh = [0u8; 128];
    let n = hex(SERVER_HELLO_RECORD, &mut sh);
    s.push(&sh[..n]);
    c.check(matches!(rfc_connect(cl, &mut s), Err(TlsError { kind: Kind::Truncated, .. })))?;
    Ok(())
}

/// A ServerHello (plain record) with the RFC's key share and the given parts.
fn push_server_hello(s: &mut Script, random: &[u8; 32], sid: &[u8], suite: u16, exts: &[u8]) {
    let mut b = [0u8; 256];
    let mut n = 9;
    b[n..n + 2].copy_from_slice(&[3, 3]);
    n += 2;
    b[n..n + 32].copy_from_slice(random);
    n += 32;
    b[n] = sid.len() as u8;
    n += 1;
    b[n..n + sid.len()].copy_from_slice(sid);
    n += sid.len();
    b[n..n + 2].copy_from_slice(&suite.to_be_bytes());
    n += 2;
    b[n] = 0;
    n += 1;
    b[n..n + 2].copy_from_slice(&(exts.len() as u16).to_be_bytes());
    n += 2;
    b[n..n + exts.len()].copy_from_slice(exts);
    n += exts.len();
    let body = n - 9;
    b[0..5].copy_from_slice(&[22, 3, 3, ((body + 4) >> 8) as u8, (body + 4) as u8]);
    b[5..9].copy_from_slice(&[2, 0, (body >> 8) as u8, body as u8]);
    s.push(&b[..n]);
}

const HRR: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

fn hello_checks(c: &mut Checks) -> Result<(), Failure> {
    c.group("HelloRetryRequest");
    let sv = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
    let mut e = [0u8; 64];
    // (extensions after supported_versions, alert, message, group)
    let cases: [(&[u8], u8, &str, u32); 5] = [
        (&[0x00, 0x2c, 0x00, 0x06, 0x00, 0x04, 1, 2, 3, 4], client::ALERT_HANDSHAKE_FAILURE, "HelloRetryRequest unsupported", 0),
        (&[0x00, 0x33, 0x00, 0x02, 0x00, 0x1d], client::ALERT_ILLEGAL_PARAMETER, "HRR asks for group already offered", 0),
        (&[0x00, 0x33, 0x00, 0x02, 0x00, 0x17], client::ALERT_ILLEGAL_PARAMETER, "server asked for undeclared group", 0x17),
        (&[], client::ALERT_ILLEGAL_PARAMETER, "HRR changes nothing", 0),
        (&[0x00, 0x33, 0x00, 0x03, 0x00, 0x17, 0x00], client::ALERT_DECODE_ERROR, "malformed HelloRetryRequest", 0),
    ];
    for (extra, alert, what, arg) in cases {
        let (cl, mut s) = fresh();
        e[..6].copy_from_slice(&sv);
        e[6..6 + extra.len()].copy_from_slice(extra);
        push_server_hello(&mut s, &HRR, &[], 0x1301, &e[..6 + extra.len()]);
        let r = rfc_connect(cl, &mut s);
        c.check(is_local_what(&r, alert, what) && r.err().map(|x| x.arg) == Some(arg))?;
    }

    c.group("broken ServerHello");
    let mut share = [0u8; 40];
    share[..8].copy_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    let mut sh = [0u8; 128];
    hex(SERVER_HELLO_RECORD, &mut sh);
    // the server's X25519 key in the RFC's ServerHello record
    share[8..40].copy_from_slice(&sh[5 + 4 + 2 + 32 + 1 + 2 + 1 + 2 + 8..5 + 4 + 2 + 32 + 1 + 2 + 1 + 2 + 8 + 32]);
    let random = [7u8; 32];
    let mut ok_ext = [0u8; 46];
    ok_ext[..40].copy_from_slice(&share);
    ok_ext[40..].copy_from_slice(&sv);
    // (session id, suite, extensions, alert)
    let mut dup = [0u8; 52];
    dup[..46].copy_from_slice(&ok_ext);
    dup[46..].copy_from_slice(&sv);
    let mut p256 = ok_ext;
    p256[5] = 0x17;
    let mut sni = [0u8; 50];
    sni[..46].copy_from_slice(&ok_ext);
    sni[46..].copy_from_slice(&[0, 0, 0, 0]);
    let mut tls12 = [0u8; 52];
    tls12[..46].copy_from_slice(&ok_ext);
    tls12[44..46].copy_from_slice(&[3, 3]);
    let cases: [(&[u8], u16, &[u8], u8); 7] = [
        (&[], 0x1301, &share, client::ALERT_PROTOCOL_VERSION),
        (&[], 0x1301, &tls12[..46], client::ALERT_ILLEGAL_PARAMETER),
        (&[1], 0x1301, &ok_ext, client::ALERT_ILLEGAL_PARAMETER),
        (&[], 0x1302, &ok_ext, client::ALERT_ILLEGAL_PARAMETER),
        (&[], 0x1301, &sni, client::ALERT_UNSUPPORTED_EXTENSION),
        (&[], 0x1301, &p256, client::ALERT_ILLEGAL_PARAMETER),
        (&[], 0x1301, &dup, client::ALERT_ILLEGAL_PARAMETER),
    ];
    for (sid, suite, exts, alert) in cases {
        let (cl, mut s) = fresh();
        push_server_hello(&mut s, &random, sid, suite, exts);
        c.check(is_local(&rfc_connect(cl, &mut s), alert))?;
    }
    // The same ServerHello as the RFC's, rebuilt: accepted up to the encrypted flight.
    let (cl, mut s) = fresh();
    push_server_hello(&mut s, &random, &[], 0x1301, &ok_ext);
    c.check(matches!(rfc_connect(cl, &mut s), Err(TlsError { kind: Kind::Truncated, .. })))?;
    // A server alert instead of a ServerHello.
    let (cl, mut s) = fresh();
    s.push(&[21, 3, 3, 0, 2, 2, 40]);
    c.check(matches!(rfc_connect(cl, &mut s), Err(TlsError { kind: Kind::PeerAlert(40), .. })))?;
    Ok(())
}

/// After the RFC handshake: the server's application key (generation 0).
fn server_app() -> (Secret, Protection) {
    let s = Secret(h32(S_AP));
    let p = Protection::new(Suite::Aes128Gcm, &s);
    (s, p)
}

fn connected(c: &mut Checks) -> Result<(&'static mut Client, Script), Failure> {
    let (cl, mut s) = fresh();
    push_flight(&mut s, Change::None);
    c.check(rfc_connect(cl, &mut s).is_ok())?;
    s.next_sent();
    s.next_sent();
    Ok((cl, s))
}

fn connected_again(c: &mut Checks) -> Result<(&'static mut Client, Script), Failure> {
    connected(c)
}

fn read_all(cl: &mut Client, s: &mut Script, out: &mut [u8]) -> Result<usize, TlsError> {
    let mut n = 0;
    loop {
        let k = cl.read(s, &mut out[n..])?;
        if k == 0 {
            return Ok(n);
        }
        n += k;
    }
}

fn record_checks(c: &mut Checks) -> Result<(), Failure> {
    let mut out = [0u8; 4096];
    c.group("application data");
    let (cl, mut s) = connected(c)?;
    let (_, mut sp) = server_app();
    s.push_sealed(&mut sp, record::APPLICATION_DATA, b"hello ");
    s.push_sealed(&mut sp, record::APPLICATION_DATA, b"");
    s.push_sealed(&mut sp, record::APPLICATION_DATA, b"world");
    s.push_sealed(&mut sp, record::ALERT, &[1, 0]);
    let r = read_all(cl, &mut s, &mut out);
    c.check(r == Ok(11) && &out[..11] == b"hello world")?;
    // TLSInnerPlaintext with zero padding: the padding is not data.
    let (cl2, mut s2) = connected(c)?;
    let (_, mut sp2) = server_app();
    let tmp = unsafe { &mut *core::ptr::addr_of_mut!(TMP) };
    tmp[5..10].copy_from_slice(b"pad\x17\x00");
    tmp[8] = record::APPLICATION_DATA;
    tmp[9..13].fill(0);
    let n = sp2.seal(0, 8, &mut tmp[..]).unwrap_or(0);
    let mut rec = [0u8; 64];
    rec[..n].copy_from_slice(&tmp[..n]);
    s2.push(&rec[..n]);
    c.check(cl2.read(&mut s2, &mut out) == Ok(3) && &out[..3] == b"pad")?;
    // Protection itself refuses a record longer than the limit.
    let mut big = [0u8; record::MAX_RECORD + 1];
    c.check(sp2.open(&mut big).err() == Some(record::RecordError::Overflow))?;
    let (cl, mut s) = connected_again(c)?;
    let (_, mut sp) = server_app();
    s.push_sealed(&mut sp, record::APPLICATION_DATA, b"hello ");
    s.push_sealed(&mut sp, record::APPLICATION_DATA, b"");
    s.push_sealed(&mut sp, record::APPLICATION_DATA, b"world");
    s.push_sealed(&mut sp, record::ALERT, &[1, 0]);
    let r = read_all(cl, &mut s, &mut out);
    c.check(r == Ok(11) && &out[..11] == b"hello world")?;
    // After close_notify: 0 again.
    c.check(cl.read(&mut s, &mut out) == Ok(0))?;
    // We write under the RFC's client application key, numbers 0, 1, …
    let mut ck = ClientKeys::new(C_AP);
    c.check(cl.write(&mut s, b"GET /").is_ok() && cl.write(&mut s, b" HTTP/1.0").is_ok())?;
    for want in [&b"GET /"[..], b" HTTP/1.0"] {
        let got = s.next_sent().and_then(|r| ck.prot.open(r).ok().map(|(t, f, l)| (t, r[f..f + l].to_vec_arr())));
        c.check(matches!(got, Some((23, (b, l))) if &b[..l] == want))?;
    }
    c.check(cl.sequences() == (2, 4))?;
    cl.close(&mut s);
    let got = s.next_sent().and_then(|r| ck.prot.open(r).ok().map(|(t, f, l)| (t, r[f..f + l].to_vec_arr())));
    c.check(matches!(got, Some((21, (b, 2))) if b[..2] == [1, 0]))?;

    // Records in 1..7-byte pieces; several records in one piece.
    for chunk in [0usize, 65536] {
        let (cl, mut s) = connected(c)?;
        let (_, mut sp) = server_app();
        s.chunk = chunk;
        let mut big = [0u8; 3000];
        for (i, b) in big.iter_mut().enumerate() {
            *b = (i * 7 + i / 251) as u8;
        }
        for part in big.chunks(700) {
            s.push_sealed(&mut sp, record::APPLICATION_DATA, part);
        }
        s.push_sealed(&mut sp, record::ALERT, &[1, 0]);
        let r = read_all(cl, &mut s, &mut out);
        c.check(r == Ok(3000) && out[..3000] == big)?;
    }
    // A full 16 KiB record with padding up to the limit.
    let (cl, mut s) = connected(c)?;
    let (_, mut sp) = server_app();
    let mut full = [0u8; record::MAX_PLAINTEXT];
    full[100] = 1;
    s.push_sealed(&mut sp, record::APPLICATION_DATA, &full);
    let mut sum = 0usize;
    let mut total = 0;
    while total < record::MAX_PLAINTEXT {
        match cl.read(&mut s, &mut out) {
            Ok(k) if k > 0 => {
                sum += out[..k].iter().map(|&b| b as usize).sum::<usize>();
                total += k;
            }
            _ => break,
        }
    }
    c.check(total == record::MAX_PLAINTEXT && sum == 1)?;

    c.group("end of the connection");
    // FIN without close_notify: truncated – also with data before it.
    let (cl, mut s) = connected(c)?;
    let (_, mut sp) = server_app();
    s.push_sealed(&mut sp, record::APPLICATION_DATA, b"part");
    let r = read_all(cl, &mut s, &mut out);
    c.check(matches!(r, Err(TlsError { kind: Kind::Truncated, .. })))?;
    let (cl, mut s) = connected(c)?;
    s.reset = true;
    c.check(matches!(cl.read(&mut s, &mut out), Err(TlsError { kind: Kind::Truncated, .. })))?;
    // A fatal alert from the server.
    let (cl, mut s) = connected(c)?;
    let (_, mut sp) = server_app();
    s.push_sealed(&mut sp, record::ALERT, &[2, 80]);
    c.check(matches!(cl.read(&mut s, &mut out), Err(TlsError { kind: Kind::PeerAlert(80), .. })))?;

    c.group("refused records");
    // A changed byte, a replayed record, a record with the wrong number.
    for case in 0..3 {
        let (cl, mut s) = connected(c)?;
        let (_, mut sp) = server_app();
        let at = s.rx_len;
        s.push_sealed(&mut sp, record::APPLICATION_DATA, b"0123456789");
        match case {
            0 => s.rx[at + 8] ^= 1,
            1 => {
                let len = s.rx_len - at;
                let mut copy = [0u8; 64];
                copy[..len].copy_from_slice(&s.rx[at..s.rx_len]);
                s.push(&copy[..len]);
            }
            _ => {
                // Record 1 sent where record 0 is expected.
                s.rx_len = at;
                let mut skipped = [0u8; 64];
                skipped[..10].copy_from_slice(b"skipped...");
                let tmp_at = s.rx_len;
                s.push_sealed(&mut sp, record::APPLICATION_DATA, &skipped[..10]);
                s.rx_len = tmp_at;
                s.push_sealed(&mut sp, record::APPLICATION_DATA, b"0123456789");
            }
        }
        let r = read_all(cl, &mut s, &mut out);
        c.check(is_local(&r, client::ALERT_BAD_RECORD_MAC))?;
    }
    // A record longer than 2^14 + 256.
    let (cl, mut s) = connected(c)?;
    s.push(&[23, 3, 3, 0x41, 0x01]);
    c.check(is_local(&cl.read(&mut s, &mut out), client::ALERT_RECORD_OVERFLOW))?;
    // An unprotected record after the handshake.
    let (cl, mut s) = connected(c)?;
    s.push(&[22, 3, 3, 0, 5, 24, 0, 0, 1, 0]);
    c.check(is_local(&cl.read(&mut s, &mut out), client::ALERT_UNEXPECTED_MESSAGE))?;
    // 33 empty records in a row.
    let (cl, mut s) = connected(c)?;
    let (_, mut sp) = server_app();
    for _ in 0..33 {
        s.push_sealed(&mut sp, record::APPLICATION_DATA, b"");
    }
    c.check(is_local_what(&cl.read(&mut s, &mut out), client::ALERT_UNEXPECTED_MESSAGE, "too many empty records"))?;
    // Only padding (no content type).
    let (cl, mut s) = connected(c)?;
    let (_, mut sp) = server_app();
    let tmp = unsafe { &mut *core::ptr::addr_of_mut!(TMP) };
    tmp[5..9].fill(0);
    let n = sp.seal(0, 3, &mut tmp[..]).unwrap_or(0);
    let mut rec = [0u8; 64];
    rec[..n].copy_from_slice(&tmp[..n]);
    s.push(&rec[..n]);
    c.check(is_local(&cl.read(&mut s, &mut out), client::ALERT_UNEXPECTED_MESSAGE))?;
    Ok(())
}

fn key_update_checks(c: &mut Checks) -> Result<(), Failure> {
    let mut out = [0u8; 256];
    c.group("KeyUpdate from the server");
    // update_requested: we answer once with update_not_requested under the old key, then use
    // the new one; three generations of the server's key.
    let (cl, mut s) = connected(c)?;
    let (mut ss, mut sp) = server_app();
    s.push_sealed(&mut sp, record::HANDSHAKE, &[24, 0, 0, 1, 1]);
    ss = schedule::next_traffic(&ss);
    sp = Protection::new(Suite::Aes128Gcm, &ss);
    s.push_sealed(&mut sp, record::APPLICATION_DATA, b"gen1");
    for g in 2..=3u8 {
        s.push_sealed(&mut sp, record::HANDSHAKE, &[24, 0, 0, 1, 0]);
        ss = schedule::next_traffic(&ss);
        sp = Protection::new(Suite::Aes128Gcm, &ss);
        s.push_sealed(&mut sp, record::APPLICATION_DATA, &[b'g', b'e', b'n', b'0' + g]);
    }
    s.push_sealed(&mut sp, record::ALERT, &[1, 0]);
    let r = read_all(cl, &mut s, &mut out);
    c.check(r == Ok(12) && &out[..12] == b"gen1gen2gen3")?;
    // The server's key is at generation 3, record 2 (gen3 data + close_notify).
    c.check(cl.traffic_secrets_for_test().1 == h32(S_AP_GEN3) && ss.0 == h32(S_AP_GEN3) && cl.sequences().1 == 2)?;
    let mut ck = ClientKeys::new(C_AP);
    let got = s.next_sent().and_then(|r| ck.prot.open(r).ok().map(|(t, f, l)| (t, r[f..f + l].to_vec_arr())));
    c.check(matches!(got, Some((22, (b, 5))) if b[..5] == [24, 0, 0, 1, 0]) && s.next_sent().is_none())?;
    ck.update();
    c.check(cl.write(&mut s, b"after").is_ok())?;
    let got = s.next_sent().and_then(|r| ck.prot.open(r).ok().map(|(t, f, l)| (t, r[f..f + l].to_vec_arr())));
    c.check(matches!(got, Some((23, (b, 5))) if &b[..5] == b"after"))?;
    c.check(cl.sequences().0 == 1 && cl.traffic_secrets_for_test().0 == h32(C_AP_GEN1))?;

    c.group("KeyUpdate from us");
    for request in [false, true] {
        let (cl, mut s) = connected(c)?;
        let mut ck = ClientKeys::new(C_AP);
        c.check(cl.write(&mut s, b"a").is_ok() && cl.key_update(&mut s, request).is_ok() && cl.write(&mut s, b"b").is_ok())?;
        let a = s.next_sent().and_then(|r| ck.prot.open(r).ok().map(|(t, f, l)| (t, r[f..f + l].to_vec_arr())));
        let ku = s.next_sent().and_then(|r| ck.prot.open(r).ok().map(|(t, f, l)| (t, r[f..f + l].to_vec_arr())));
        ck.update();
        let b = s.next_sent().and_then(|r| ck.prot.open(r).ok().map(|(t, f, l)| (t, r[f..f + l].to_vec_arr())));
        c.check(matches!(a, Some((23, (x, 1))) if x[0] == b'a'))?;
        c.check(matches!(ku, Some((22, (x, 5))) if x[..5] == [24, 0, 0, 1, request as u8]))?;
        c.check(matches!(b, Some((23, (x, 1))) if x[0] == b'b'))?;
        c.check(cl.sequences().0 == 1)?;
    }

    c.group("refused KeyUpdate");
    // value 2; wrong length; not at the end of its record; 17 in a row without data.
    let bad: [(&[u8], u8); 3] = [
        (&[24, 0, 0, 1, 2], client::ALERT_ILLEGAL_PARAMETER),
        (&[24, 0, 0, 2, 0, 0], client::ALERT_DECODE_ERROR),
        (&[24, 0, 0, 1, 0, 4, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0], client::ALERT_UNEXPECTED_MESSAGE),
    ];
    for (msg, alert) in bad {
        let (cl, mut s) = connected(c)?;
        let (_, mut sp) = server_app();
        s.push_sealed(&mut sp, record::HANDSHAKE, msg);
        c.check(is_local(&cl.read(&mut s, &mut out), alert))?;
    }
    let (cl, mut s) = connected(c)?;
    let (mut ss, mut sp) = server_app();
    for _ in 0..17 {
        s.push_sealed(&mut sp, record::HANDSHAKE, &[24, 0, 0, 1, 0]);
        ss = schedule::next_traffic(&ss);
        sp = Protection::new(Suite::Aes128Gcm, &ss);
    }
    c.check(is_local_what(&cl.read(&mut s, &mut out), client::ALERT_UNEXPECTED_MESSAGE, "too many KeyUpdates without data"))?;
    // A KeyUpdate split over two records is fine (it ends its second record).
    let (cl, mut s) = connected(c)?;
    let (mut ss, mut sp) = server_app();
    s.push_sealed(&mut sp, record::HANDSHAKE, &[24, 0]);
    s.push_sealed(&mut sp, record::HANDSHAKE, &[0, 1, 0]);
    ss = schedule::next_traffic(&ss);
    sp = Protection::new(Suite::Aes128Gcm, &ss);
    s.push_sealed(&mut sp, record::APPLICATION_DATA, b"ok");
    c.check(cl.read(&mut s, &mut out) == Ok(2) && &out[..2] == b"ok")?;
    // A NewSessionTicket is read and ignored.
    let (cl, mut s) = connected(c)?;
    let (_, mut sp) = server_app();
    s.push_sealed(&mut sp, record::HANDSHAKE, &[4, 0, 0, 16, 0, 0, 0, 60, 1, 2, 3, 4, 1, 9, 0, 2, 7, 7, 0, 0]);
    s.push_sealed(&mut sp, record::APPLICATION_DATA, b"x");
    c.check(cl.read(&mut s, &mut out) == Ok(1))?;
    Ok(())
}

/// Every test; the number of checks.
pub fn run() -> Result<usize, Failure> {
    let mut c = Checks { group: "", case: 0, passed: 0 };
    rfc_checks(&mut c)?;
    flight_checks(&mut c)?;
    hello_checks(&mut c)?;
    record_checks(&mut c)?;
    key_update_checks(&mut c)?;
    Ok(c.passed)
}
