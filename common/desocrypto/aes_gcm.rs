// AES-128-GCM (NIST SP 800-38D): authenticated encryption with associated data.
//
//   AesGcm::new(key)               AES-NI / PCLMULQDQ where the CPU has them
//   AesGcm::with_features(key, f)  the same, but only the features in `f` (off only)
//   gcm.seal(nonce, aad, buf)      encrypts `buf` in place, returns the 16-byte tag
//   gcm.open(nonce, aad, buf, tag) checks the tag FIRST; only a correct tag decrypts
//
// WARNING – the nonce: a (key, nonce) pair must never encrypt two messages.  Reusing a
// nonce with the same key reveals the XOR of the plaintexts and, under certain
// conditions, can make it possible to recover H and forge tags.  This module does not
// choose nonces (no generator, no counter) – the caller must.
//
// Fixed choices: 96-bit nonce (J0 = nonce ‖ 0x00000001, data from counter 2), 16-byte tag
// (no truncation), at most 2^36 - 32 bytes per message.  The tag:
// E_K(J0) xor GHASH_H(aad ‖ pad ‖ ciphertext ‖ pad ‖ [len(aad)]_64 ‖ [len(ct)]_64), lengths
// in bits, big-endian.
//
// `open` with a wrong tag leaves `buf` exactly as it was and returns Error::Mismatch (the
// tag compared in constant time).  `buf` is one &mut slice, aad and tag & slices – Rust does
// not let them overlap.  Wiped: H, E_K(J0), every key-stream block, the computed tag in
// `open`, the round keys and the GHASH state (their Drop).  The implementation avoids
// branches and table look-ups that depend on secrets; it has not been formally verified or
// audited for timing.

use super::aes::{Aes128, Features, KEY_LEN};
use super::ghash::Ghash;
use super::{Error, equal_ct};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// Largest message: 2^39 - 256 bits.
pub const MAX_LEN: u64 = (1 << 36) - 32;

pub struct AesGcm {
    aes: Aes128,
    h: [u8; 16],
    features: Features,
}

impl AesGcm {
    pub fn new(key: &[u8; KEY_LEN]) -> AesGcm {
        AesGcm::with_features(key, Features { aes: true, pclmul: true })
    }

    /// Only the features in `wanted` that the CPU really has (the software paths: NONE).
    pub fn with_features(key: &[u8; KEY_LEN], wanted: Features) -> AesGcm {
        let features = Features::limit(wanted);
        let aes = Aes128::new(key, features);
        let mut h = [[0u8; 16]];
        aes.encrypt_blocks(&mut h);
        AesGcm { aes, h: h[0], features }
    }

    /// Which instructions this object really uses.
    pub fn features(&self) -> Features {
        self.features
    }

    /// buf XOR the key stream from counter 2 (counter blocks 4 at a time).
    fn ctr(&self, nonce: &[u8; NONCE_LEN], buf: &mut [u8]) {
        let mut counter: u32 = 2;
        let mut ks = [[0u8; 16]; 4];
        for chunk in buf.chunks_mut(64) {
            let n = chunk.len().div_ceil(16);
            for b in ks.iter_mut().take(n) {
                b[..12].copy_from_slice(nonce);
                b[12..].copy_from_slice(&counter.to_be_bytes());
                counter = counter.wrapping_add(1);
            }
            self.aes.encrypt_blocks(&mut ks[..n]);
            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= ks[i / 16][i % 16];
            }
        }
        for b in ks.iter_mut() {
            super::wipe(b);
        }
    }

    fn tag(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], ct: &[u8]) -> [u8; TAG_LEN] {
        let mut g = Ghash::new(&self.h, self.features);
        g.update(aad);
        g.pad();
        g.update(ct);
        g.pad();
        let mut lens = [0u8; 16];
        lens[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
        lens[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
        g.update(&lens);
        let s = g.finish();
        let mut j0 = [[0u8; 16]];
        j0[0][..12].copy_from_slice(nonce);
        j0[0][15] = 1;
        self.aes.encrypt_blocks(&mut j0);
        let mut t = [0u8; TAG_LEN];
        for i in 0..16 {
            t[i] = s[i] ^ j0[0][i];
        }
        super::wipe(&mut j0[0]);
        t
    }

    fn check_len(aad: &[u8], buf: &[u8]) -> Result<(), Error> {
        if buf.len() as u64 > MAX_LEN || aad.len() as u64 >= 1 << 61 {
            return Err(Error::LengthOverflow);
        }
        Ok(())
    }

    /// Encrypts `buf` in place and returns the tag.  The nonce must be unique for the key.
    pub fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) -> Result<[u8; TAG_LEN], Error> {
        Self::check_len(aad, buf)?;
        self.ctr(nonce, buf);
        Ok(self.tag(nonce, aad, buf))
    }

    /// Checks the tag over (aad, `buf`); only when it matches, decrypts `buf` in place.
    pub fn open(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<(), Error> {
        Self::check_len(aad, buf)?;
        let mut want = self.tag(nonce, aad, buf);
        let ok = equal_ct(&want, tag);
        super::wipe(&mut want);
        if !ok {
            return Err(Error::Mismatch);
        }
        self.ctr(nonce, buf);
        Ok(())
    }
}

impl Drop for AesGcm {
    fn drop(&mut self) {
        super::wipe(&mut self.h);
    }
}

/// One-shot `seal` (a fresh key schedule every call).
pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) -> Result<[u8; TAG_LEN], Error> {
    AesGcm::new(key).seal(nonce, aad, buf)
}

/// One-shot `open`.
pub fn open(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<(), Error> {
    AesGcm::new(key).open(nonce, aad, buf, tag)
}
