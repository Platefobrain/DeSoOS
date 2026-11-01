// HMAC-SHA256 (RFC 2104; test vectors RFC 4231).
//
//   let tag = hmac_sha256(key, msg);                 // one piece
//
//   let mut m = HmacSha256::new(key);                // streaming
//   m.update(part1);
//   m.update(part2);
//   let tag = m.finish()?;                           // [u8; 32]
//
//   HmacSha256::new(key).chain(msg).verify(&tag)?;   // check a received tag
//
// Any key length works, also an empty key: keys longer than the 64-byte block
// are hashed first, shorter ones are padded with zeros (RFC 2104).

use super::sha256::{BLOCK_LEN, OUT_LEN, Sha256, sha256};
use super::{Error, equal_ct};

/// The shortest tag `verify` accepts (RFC 2104 section 5: not less than half the hash).
pub const MIN_TAG_LEN: usize = 16;

#[derive(Clone)]
pub struct HmacSha256 {
    inner: Sha256,
    /// The key XOR opad, kept for the outer hash.
    okey: [u8; BLOCK_LEN],
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; BLOCK_LEN];
        if key.len() > BLOCK_LEN {
            k[..OUT_LEN].copy_from_slice(&sha256(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ikey = [0u8; BLOCK_LEN];
        let mut okey = [0u8; BLOCK_LEN];
        for i in 0..BLOCK_LEN {
            ikey[i] = k[i] ^ 0x36;
            okey[i] = k[i] ^ 0x5c;
        }
        let mut inner = Sha256::new();
        inner.update(&ikey);
        // Do not leave the key on the stack longer than needed.
        wipe(&mut k);
        wipe(&mut ikey);
        HmacSha256 { inner, okey }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// `update` that returns self – for one-line use.
    pub fn chain(mut self, data: &[u8]) -> Self {
        self.update(data);
        self
    }

    /// The tag; Error::LengthOverflow if the message passed the SHA-256 limit.
    pub fn finish(mut self) -> Result<[u8; OUT_LEN], Error> {
        let ihash = self.inner.clone().finish()?;
        let mut outer = Sha256::new();
        outer.update(&self.okey);
        outer.update(&ihash);
        wipe(&mut self.okey);
        outer.finish()
    }

    /// Checks a received tag: the full 32 bytes or a truncated one of at least
    /// MIN_TAG_LEN bytes (compared with the start of the computed tag).  The
    /// comparison takes the same time wherever the bytes differ.
    pub fn verify(self, tag: &[u8]) -> Result<(), Error> {
        if tag.len() < MIN_TAG_LEN || tag.len() > OUT_LEN {
            return Err(Error::InvalidLength);
        }
        let full = self.finish()?;
        if equal_ct(&full[..tag.len()], tag) { Ok(()) } else { Err(Error::Mismatch) }
    }

    /// For tests only: see Sha256::assume_length (counts the 64-byte key block too).
    #[doc(hidden)]
    pub fn assume_length(&mut self, bytes: u64) {
        self.inner.assume_length(bytes);
    }
}

/// HMAC-SHA256 of one slice (cannot fail – a slice is far below the limit).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; OUT_LEN] {
    HmacSha256::new(key).chain(data).finish().unwrap_or([0; OUT_LEN])
}

/// Zeroes key material in a way the compiler does not remove.
pub(super) fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned &mut u8.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}
