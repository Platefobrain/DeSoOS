// The TLS 1.3 key schedule (RFC 8446 §7.1) for the two cipher suites DeSoTLS offers – both
// use SHA-256, so every secret here is 32 bytes.
//
//   0 ──HKDF-Extract── Early Secret ──Derive-Secret(., "derived", "")
//                                     │
//   (EC)DHE ──HKDF-Extract── Handshake Secret ──> c/s hs traffic (transcript CH..SH)
//                                     │
//                                     └─Derive-Secret(., "derived", "")
//   0 ──HKDF-Extract── Master Secret ──> c/s ap traffic (transcript CH..server Finished)
//
// From a traffic secret: key = HKDF-Expand-Label(secret, "key", "", key length),
// iv = HKDF-Expand-Label(secret, "iv", "", 12), finished key = HKDF-Expand-Label(secret,
// "finished", "", 32), and after a KeyUpdate the next secret = HKDF-Expand-Label(secret,
// "traffic upd", "", 32) (§7.2).  No PSK, no 0-RTT: the early secret always comes from zeros.
//
// Every secret lives in a `Secret`, wiped when dropped.

use super::crypto::hkdf;
use super::crypto::hmac::HmacSha256;
use super::crypto::sha256::{self, Sha256};
use super::crypto::{equal_ct, wipe};

pub const HASH_LEN: usize = 32;

/// A 32-byte secret, wiped when dropped.
pub struct Secret(pub [u8; HASH_LEN]);

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl Secret {
    pub const fn zero() -> Secret {
        Secret([0; HASH_LEN])
    }
}

/// HKDF-Expand-Label(secret, label, context, out.len()) with the "tls13 " prefix.
pub fn expand_label(secret: &[u8; HASH_LEN], label: &[u8], context: &[u8], out: &mut [u8]) {
    // HkdfLabel: u16 length, opaque label<7..255> = "tls13 " + label, opaque context<0..255>.
    let mut info = [0u8; 2 + 1 + 6 + 32 + 1 + HASH_LEN];
    let n = 2 + 1 + 6 + label.len();
    debug_assert!(label.len() <= 32 && context.len() <= HASH_LEN && out.len() <= 255);
    info[0..2].copy_from_slice(&(out.len() as u16).to_be_bytes());
    info[2] = (6 + label.len()) as u8;
    info[3..9].copy_from_slice(b"tls13 ");
    info[9..n].copy_from_slice(label);
    info[n] = context.len() as u8;
    info[n + 1..n + 1 + context.len()].copy_from_slice(context);
    // A 32-byte PRK and at most 255 bytes of output are inside HKDF's limits.
    let _ = hkdf::expand(secret, &info[..n + 1 + context.len()], out);
}

/// Derive-Secret(secret, label, transcript hash).
pub fn derive_secret(secret: &[u8; HASH_LEN], label: &[u8], transcript: &[u8; HASH_LEN]) -> Secret {
    let mut s = Secret::zero();
    expand_label(secret, label, transcript, &mut s.0);
    s
}

/// SHA-256 of nothing – the transcript of the "derived" steps.
fn empty_hash() -> [u8; HASH_LEN] {
    sha256::sha256(b"")
}

/// The hash of a transcript so far (the running hash is cloned, not finished).
pub fn transcript_hash(t: &Sha256) -> [u8; HASH_LEN] {
    // A transcript of at most a few hundred KiB is far below SHA-256's length limit.
    t.clone().finish().unwrap_or([0; HASH_LEN])
}

/// Handshake Secret from the (EC)DHE shared secret.
pub fn handshake_secret(shared: &[u8; 32]) -> Secret {
    let early = Secret(hkdf::extract(&[0u8; HASH_LEN], &[0u8; HASH_LEN]));
    let derived = derive_secret(&early.0, b"derived", &empty_hash());
    Secret(hkdf::extract(&derived.0, shared))
}

/// Master Secret from the Handshake Secret.
pub fn master_secret(handshake: &Secret) -> Secret {
    let derived = derive_secret(&handshake.0, b"derived", &empty_hash());
    Secret(hkdf::extract(&derived.0, &[0u8; HASH_LEN]))
}

/// The verify_data of a Finished message: HMAC(finished key, transcript hash).
pub fn finished(traffic: &Secret, transcript: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut key = Secret::zero();
    expand_label(&traffic.0, b"finished", b"", &mut key.0);
    HmacSha256::new(&key.0).chain(transcript).finish().unwrap_or([0; HASH_LEN])
}

/// Checks a received verify_data in constant time.
pub fn finished_ok(traffic: &Secret, transcript: &[u8; HASH_LEN], got: &[u8]) -> bool {
    let mut want = finished(traffic, transcript);
    let ok = equal_ct(&want, got);
    wipe(&mut want);
    ok
}

/// The secret after a KeyUpdate.
pub fn next_traffic(secret: &Secret) -> Secret {
    let mut s = Secret::zero();
    expand_label(&secret.0, b"traffic upd", b"", &mut s.0);
    s
}
