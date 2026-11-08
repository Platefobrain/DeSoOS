// SHA-512 and SHA-384 (FIPS 180-4) – one core with 64-bit words, two starting values.
//
//   let mut h = Sha512::new();     // or Sha384::new()
//   h.update(b"ab");
//   h.update(b"c");                // any number of pieces, any sizes, also empty
//   let digest = h.finish()?;      // [u8; 64] (Sha384: [u8; 48])
//
//   let digest = sha512(b"abc");   // one piece (sha384 likewise)
//
// The padding holds a 128-bit count of bits; the count of bytes is kept in a u64, so at
// most 2^64 - 1 bytes can be hashed.  More than that is not cut silently: `finish`
// returns Error::LengthOverflow.  The state is wiped when dropped (HMAC keys pass through).

use super::Error;

pub const BLOCK_LEN: usize = 128;
pub const OUT_LEN: usize = 64;
pub const OUT_LEN_384: usize = 48;
/// The most bytes one hash can take.
pub const MAX_BYTES: u64 = u64::MAX;

const H512: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

const H384: [u64; 8] = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
];

const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// The common state; Sha512 and Sha384 differ only in the starting value and the output length.
#[derive(Clone)]
struct Core {
    state: [u64; 8],
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    total: u64,
    overflow: bool,
}

impl Core {
    const fn new(h0: [u64; 8]) -> Core {
        Core { state: h0, buf: [0; BLOCK_LEN], buf_len: 0, total: 0, overflow: false }
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.overflow {
            return;
        }
        match self.total.checked_add(data.len() as u64) {
            Some(t) => self.total = t,
            None => {
                self.overflow = true;
                return;
            }
        }
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
        let mut chunks = data.chunks_exact(BLOCK_LEN);
        for block in &mut chunks {
            compress(&mut self.state, block);
        }
        let rest = chunks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    /// All 64 bytes of the final state (Sha384 keeps the first 48).
    fn finish(&mut self) -> Result<[u8; OUT_LEN], Error> {
        if self.overflow {
            return Err(Error::LengthOverflow);
        }
        let bits = (self.total as u128) << 3;
        // 0x80, zeros up to 112 bytes into a block, then the 128-bit bit count.
        let mut pad = [0u8; BLOCK_LEN * 2];
        pad[0] = 0x80;
        let zeros = if self.buf_len < 112 { 111 - self.buf_len } else { 239 - self.buf_len };
        let len = 1 + zeros + 16;
        pad[1 + zeros..len].copy_from_slice(&bits.to_be_bytes());
        let mut data = &pad[..len];
        let take = BLOCK_LEN - self.buf_len;
        self.buf[self.buf_len..].copy_from_slice(&data[..take]);
        compress(&mut self.state, &self.buf);
        data = &data[take..];
        if !data.is_empty() {
            compress(&mut self.state, data);
        }
        let mut out = [0u8; OUT_LEN];
        for (i, w) in self.state.iter().enumerate() {
            out[8 * i..8 * i + 8].copy_from_slice(&w.to_be_bytes());
        }
        Ok(out)
    }

    fn wipe(&mut self) {
        super::wipe_words64(&mut self.state);
        super::wipe(&mut self.buf);
        // SAFETY: valid, aligned fields of self.
        unsafe {
            core::ptr::write_volatile(&mut self.buf_len, 0);
            core::ptr::write_volatile(&mut self.total, 0);
        }
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[derive(Clone)]
pub struct Sha512(Core);

#[derive(Clone)]
pub struct Sha384(Core);

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    pub const fn new() -> Self {
        Sha512(Core::new(H512))
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    pub fn finish(mut self) -> Result<[u8; OUT_LEN], Error> {
        self.0.finish()
    }
    /// Tests only: pretends `bytes` were already hashed (see Sha256::assume_length).
    #[cfg(any(selftest, desocrypto_test))]
    pub fn assume_length(&mut self, bytes: u64) {
        self.0.total = bytes;
    }
}

impl Sha384 {
    pub const fn new() -> Self {
        Sha384(Core::new(H384))
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    pub fn finish(mut self) -> Result<[u8; OUT_LEN_384], Error> {
        let mut full = self.0.finish()?;
        let mut out = [0u8; OUT_LEN_384];
        out.copy_from_slice(&full[..OUT_LEN_384]);
        super::wipe(&mut full);
        Ok(out)
    }
    #[cfg(any(selftest, desocrypto_test))]
    pub fn assume_length(&mut self, bytes: u64) {
        self.0.total = bytes;
    }
}

/// SHA-512 of one slice (cannot fail – a slice is shorter than 2^64 bytes).
pub fn sha512(data: &[u8]) -> [u8; OUT_LEN] {
    let mut h = Sha512::new();
    h.update(data);
    h.finish().unwrap_or([0; OUT_LEN])
}

/// SHA-384 of one slice.
pub fn sha384(data: &[u8]) -> [u8; OUT_LEN_384] {
    let mut h = Sha384::new();
    h.update(data);
    h.finish().unwrap_or([0; OUT_LEN_384])
}

/// One 128-byte block into the state (wrapping arithmetic only).
fn compress(state: &mut [u64; 8], block: &[u8]) {
    let mut w = [0u64; 80];
    for i in 0..16 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&block[8 * i..8 * i + 8]);
        w[i] = u64::from_be_bytes(b);
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
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
