// SHA-256 (FIPS 180-4).
//
//   let mut h = Sha256::new();
//   h.update(b"ab");
//   h.update(b"c");               // any number of pieces, any sizes, also empty
//   let digest = h.finish()?;     // [u8; 32]
//
//   let digest = sha256(b"abc");  // one piece
//
// The message length goes into the padding as a 64-bit count of bits, so at most
// 2^64 - 1 bits = 2^61 - 1 whole bytes can be hashed.  More than that is not cut
// silently: `finish` returns Error::LengthOverflow.

use super::Error;

pub const BLOCK_LEN: usize = 64;
pub const OUT_LEN: usize = 32;
/// The most bytes one hash can take (2^61 - 1).
pub const MAX_BYTES: u64 = (1 << 61) - 1;

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    /// Bytes waiting for a full block.
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    /// Bytes hashed so far (whole message).
    total: u64,
    /// Set once `total` would pass MAX_BYTES; `finish` then refuses.
    overflow: bool,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub const fn new() -> Self {
        Sha256 { state: H0, buf: [0; BLOCK_LEN], buf_len: 0, total: 0, overflow: false }
    }

    /// Adds data; can be called any number of times, also with an empty slice.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.overflow {
            return;
        }
        match self.total.checked_add(data.len() as u64) {
            Some(t) if t <= MAX_BYTES => self.total = t,
            _ => {
                // Too long: remember it, hash nothing more (the result is refused anyway).
                self.overflow = true;
                return;
            }
        }
        // Top up a partial block first.
        if self.buf_len > 0 {
            let take = (BLOCK_LEN - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < BLOCK_LEN {
                return;
            }
            compress(&mut self.state, &self.buf);
            self.buf_len = 0;
        }
        // Whole blocks straight from the input.
        let mut chunks = data.chunks_exact(BLOCK_LEN);
        for block in &mut chunks {
            compress(&mut self.state, block);
        }
        let rest = chunks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    /// The digest; Error::LengthOverflow if more than MAX_BYTES were given.
    pub fn finish(mut self) -> Result<[u8; OUT_LEN], Error> {
        if self.overflow {
            return Err(Error::LengthOverflow);
        }
        // total <= 2^61 - 1, so the bit count fits in 64 bits.
        let bits = self.total << 3;
        // Padding: 0x80, zeros up to 56 bytes into a block, then the bit count (big-endian).
        let mut pad = [0u8; BLOCK_LEN * 2];
        pad[0] = 0x80;
        let zeros = if self.buf_len < 56 { 55 - self.buf_len } else { 119 - self.buf_len };
        let len = 1 + zeros + 8;
        pad[1 + zeros..len].copy_from_slice(&bits.to_be_bytes());
        // The padding is not message data: feed it past the length counter.
        let mut data = &pad[..len];
        let take = BLOCK_LEN - self.buf_len;
        self.buf[self.buf_len..].copy_from_slice(&data[..take]);
        compress(&mut self.state, &self.buf);
        data = &data[take..];
        if !data.is_empty() {
            // Exactly one more block.
            compress(&mut self.state, data);
        }
        let mut out = [0u8; OUT_LEN];
        for (i, w) in self.state.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
        Ok(out)
    }

    /// Zeroes the whole state (volatile writes the compiler keeps).  Called on drop;
    /// a wiped hasher must not be used again.
    pub fn wipe(&mut self) {
        for w in self.state.iter_mut() {
            // SAFETY: `w` is a valid, aligned &mut u32.
            unsafe { core::ptr::write_volatile(w, 0) };
        }
        super::hmac::wipe(&mut self.buf);
        // SAFETY: valid, aligned fields of self.
        unsafe {
            core::ptr::write_volatile(&mut self.buf_len, 0);
            core::ptr::write_volatile(&mut self.total, 0);
        }
    }

    /// Tests only (not in the normal kernel or programs – `selftest` / `desocrypto_test`
    /// builds): pretends `bytes` were already hashed, so the length limit can be
    /// checked without hashing 2 EiB.
    #[cfg(any(selftest, desocrypto_test))]
    pub fn assume_length(&mut self, bytes: u64) {
        self.total = bytes;
    }
}

/// The state can hold key material (HMAC keys pass through it): cleared when dropped.
impl Drop for Sha256 {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// SHA-256 of one slice.  A slice is far below 2^61 bytes, so this cannot fail.
pub fn sha256(data: &[u8]) -> [u8; OUT_LEN] {
    let mut h = Sha256::new();
    h.update(data);
    match h.finish() {
        Ok(d) => d,
        // Unreachable: a slice in memory is shorter than 2^61 bytes.
        Err(_) => [0; OUT_LEN],
    }
}

/// One 64-byte block into the state.  Only wrapping arithmetic – correct also in
/// builds with overflow checks (the kernel).
fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}
