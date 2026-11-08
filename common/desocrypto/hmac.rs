// HMAC (RFC 2104; test vectors RFC 4231) over any hash in `hash::Digest`.
//
//   let tag = hmac_sha256(key, msg);                 // one piece, SHA-256
//
//   let mut m = HmacSha256::new(key);                // streaming, SHA-256
//   m.update(part1);
//   m.update(part2);
//   let tag = m.finish()?;                           // [u8; 32]
//
//   HmacSha256::new(key).chain(msg).verify(&tag)?;   // check a received tag
//
//   let tag = Hmac::<Sha384>::new(key).chain(msg).finish()?;   // any hash: hash::Output
//
// Any key length works, also an empty key: keys longer than the hash block are hashed
// first, shorter ones are padded with zeros (RFC 2104).

use super::hash::{Digest, MAX_BLOCK, MAX_OUT, Output};
use super::sha256::{OUT_LEN, Sha256};
use super::{Error, equal_ct};

/// The shortest tag `verify` accepts (RFC 2104 section 5: not less than half the hash).
pub const MIN_TAG_LEN: usize = 16;

/// HMAC with the hash `D`.
#[derive(Clone)]
pub struct Hmac<D: Digest> {
    inner: D,
    /// The key XOR opad (first D::BLOCK_LEN bytes), kept for the outer hash.
    okey: [u8; MAX_BLOCK],
}

impl<D: Digest> Hmac<D> {
    pub fn new(key: &[u8]) -> Self {
        let bl = D::BLOCK_LEN;
        let mut k = [0u8; MAX_BLOCK];
        if key.len() > bl {
            let mut h = D::new();
            h.update(key);
            let mut d = [0u8; MAX_OUT];
            // A key in memory is below every length limit.
            let _ = h.finish_into(&mut d);
            k[..D::OUT_LEN].copy_from_slice(&d[..D::OUT_LEN]);
            wipe(&mut d);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ikey = [0u8; MAX_BLOCK];
        let mut okey = [0u8; MAX_BLOCK];
        for i in 0..bl {
            ikey[i] = k[i] ^ 0x36;
            okey[i] = k[i] ^ 0x5c;
        }
        let mut inner = D::new();
        inner.update(&ikey[..bl]);
        wipe(&mut k);
        wipe(&mut ikey);
        Hmac { inner, okey }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn chain(mut self, data: &[u8]) -> Self {
        self.update(data);
        self
    }

    /// The tag (D::OUT_LEN bytes); Error::LengthOverflow if the message passed the hash limit.
    pub fn finish(self) -> Result<Output, Error> {
        let mut ihash = [0u8; MAX_OUT];
        self.inner.clone().finish_into(&mut ihash)?;
        let mut outer = D::new();
        outer.update(&self.okey[..D::BLOCK_LEN]);
        outer.update(&ihash[..D::OUT_LEN]);
        wipe(&mut ihash);
        let mut out = [0u8; MAX_OUT];
        outer.finish_into(&mut out)?;
        let r = Output::from_parts(out, D::OUT_LEN);
        wipe(&mut out);
        Ok(r)
    }

    /// Checks a received tag: full length or truncated to at least MIN_TAG_LEN bytes;
    /// constant-time comparison.
    pub fn verify(self, tag: &[u8]) -> Result<(), Error> {
        if tag.len() < MIN_TAG_LEN || tag.len() > D::OUT_LEN {
            return Err(Error::InvalidLength);
        }
        let full = self.finish()?;
        if equal_ct(&full.as_bytes()[..tag.len()], tag) { Ok(()) } else { Err(Error::Mismatch) }
    }
}

impl<D: Digest> Drop for Hmac<D> {
    fn drop(&mut self) {
        wipe(&mut self.okey);
    }
}

/// HMAC-SHA256 with fixed 32-byte results (the API from before the generic `Hmac`).
#[derive(Clone)]
pub struct HmacSha256(Hmac<Sha256>);

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        HmacSha256(Hmac::new(key))
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn chain(mut self, data: &[u8]) -> Self {
        self.update(data);
        self
    }

    pub fn finish(self) -> Result<[u8; OUT_LEN], Error> {
        let t = self.0.finish()?;
        let mut out = [0u8; OUT_LEN];
        out.copy_from_slice(t.as_bytes());
        Ok(out)
    }

    pub fn verify(self, tag: &[u8]) -> Result<(), Error> {
        self.0.verify(tag)
    }

    /// Tests only: see Sha256::assume_length (counts the 64-byte key block too).
    #[cfg(any(selftest, desocrypto_test))]
    pub fn assume_length(&mut self, bytes: u64) {
        self.0.inner.assume_length(bytes);
    }
}

/// HMAC-SHA256 of one slice (cannot fail – a slice is far below the limit).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; OUT_LEN] {
    HmacSha256::new(key).chain(data).finish().unwrap_or([0; OUT_LEN])
}

/// Zeroes key material in a way the compiler does not remove.
pub(super) fn wipe(buf: &mut [u8]) {
    super::wipe(buf);
}
