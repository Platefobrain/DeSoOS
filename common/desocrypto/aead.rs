// ChaCha20-Poly1305 (RFC 8439 section 2.8): authenticated encryption with associated data.
//
//   seal(key, nonce, aad, buf) -> tag     encrypts `buf` in place, authenticates buf + aad
//   open(key, nonce, aad, buf, tag)       checks the tag FIRST; only a correct tag decrypts
//
// WARNING – the nonce: a (key, nonce) pair must never encrypt two messages.  Reusing a
// nonce with the same key is a serious security failure: the XOR of the two plaintexts
// leaks, and the Poly1305 key repeats, which lets an attacker forge tags.  This module
// does not choose nonces for you (no generator, no counter) – the caller must, e.g. a
// counter per key that never wraps, or a fresh key per message.
//
// How (RFC 8439 2.8): the one-time Poly1305 key = the first 32 bytes of the ChaCha20
// block with counter 0; the data is encrypted from counter 1; the tag covers
// aad ‖ zero padding to 16 ‖ ciphertext ‖ zero padding to 16 ‖ len(aad) ‖ len(ciphertext)
// (64-bit little-endian each).
//
// `open` with a wrong tag leaves `buf` exactly as it was (no byte decrypted or changed)
// and returns Error::Mismatch; the tag is compared in constant time.  `buf` is one
// &mut slice and `aad` / `tag` are & slices, so Rust does not allow them to overlap.
//
// Secrets wiped (volatile writes): the counter-0 block, the Poly1305 key taken from it,
// the computed tag in `open`, the Poly1305 state (its Drop).  The key itself is the
// caller's (taken by reference, never copied here); copies the compiler keeps in
// registers or on the stack are not covered.  The code avoids branches and table look-ups
// that depend on secrets; it has not been formally verified or audited for timing.

use super::chacha20::{self, KEY_LEN, NONCE_LEN};
use super::poly1305::{Poly1305, TAG_LEN};
use super::{Error, equal_ct};

/// Largest message: the 32-bit block counter starts at 1 (RFC 8439: 2^38 - 64 bytes).
pub const MAX_LEN: u64 = (1 << 38) - 64;

/// The tag of (aad, ciphertext) under the one-time key from block 0.
fn tag_of(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], ct: &[u8]) -> [u8; TAG_LEN] {
    let mut block0 = [0u8; 64];
    chacha20::block(key, 0, nonce, &mut block0);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);
    super::wipe(&mut block0);
    let mut mac = Poly1305::new(&otk);
    super::wipe(&mut otk);
    const ZEROS: [u8; 16] = [0; 16];
    mac.update(aad);
    mac.update(&ZEROS[..(16 - aad.len() % 16) % 16]);
    mac.update(ct);
    mac.update(&ZEROS[..(16 - ct.len() % 16) % 16]);
    mac.update(&(aad.len() as u64).to_le_bytes());
    mac.update(&(ct.len() as u64).to_le_bytes());
    mac.finish()
}

/// Encrypts `buf` in place and returns the tag.  Err(LengthOverflow) for more than
/// MAX_LEN bytes (`buf` unchanged).  The nonce must be unique for the key (see the top).
pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) -> Result<[u8; TAG_LEN], Error> {
    if buf.len() as u64 > MAX_LEN {
        return Err(Error::LengthOverflow);
    }
    chacha20::xor_stream(key, 1, nonce, buf)?;
    Ok(tag_of(key, nonce, aad, buf))
}

/// Checks the tag over (aad, `buf`) and, only when it matches, decrypts `buf` in place.
/// Err(Mismatch): wrong tag, aad, nonce, key or ciphertext – `buf` untouched.
pub fn open(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<(), Error> {
    if buf.len() as u64 > MAX_LEN {
        return Err(Error::LengthOverflow);
    }
    let mut want = tag_of(key, nonce, aad, buf);
    let ok = equal_ct(&want, tag);
    super::wipe(&mut want);
    if !ok {
        return Err(Error::Mismatch);
    }
    chacha20::xor_stream(key, 1, nonce, buf)
}
