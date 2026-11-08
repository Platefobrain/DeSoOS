// Poly1305 (RFC 8439 section 2.5): a one-time authenticator.  A 32-byte key (r, s)
// authenticates ONE message: the tag is (sum of 16-byte blocks times r^k, mod 2^130 - 5)
// + s, mod 2^128.  A key used for two messages lets an attacker forge tags – the AEAD
// (aead.rs) derives a fresh key for every (key, nonce).
//
// Arithmetic: the accumulator h and r in three limbs of 44 / 44 / 42 bits, products in
// u128.  The implementation avoids branches and table look-ups that depend on the key or
// the message (the final "subtract p if h >= p" uses a mask).  It has not been formally
// verified or audited for timing.
//
// Bounds (asserted in test builds by `bound!`):
//   after the clamp r0, r1 < 2^44, r2 < 2^42; s1 = 20 r1 < 2^49, s2 = 20 r2 < 2^47
//   between blocks h0 < 2^44, h1 < 2^44 + 2^20, h2 < 2^42
//   with a block added: h0, h1 < 2^45, h2 < 2^42 + 2^42 + 2^40 < 2^44
//   products: h0 r0 < 2^89, h1 s2 < 2^92, h2 s1 < 2^93 – each d_i < 2^94 (asserted
//   < 2^97), far below 2^128: no u128 overflow; the carry out of d2 is < 2^55, times 5
//   still fits a u64.

use super::{Error, equal_ct};

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

const M44: u64 = (1 << 44) - 1;
const M42: u64 = (1 << 42) - 1;

/// Test builds: an arithmetic bound that must hold (see the top of the file).
macro_rules! bound {
    ($cond:expr) => {
        #[cfg(any(selftest, desocrypto_test))]
        assert!($cond, "poly1305 bound: {}", stringify!($cond));
    };
}

pub struct Poly1305 {
    r: [u64; 3],
    s: [u64; 2],
    h: [u64; 3],
    buf: [u8; 16],
    buf_len: usize,
}

fn le64(b: &[u8]) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[..8]);
    u64::from_le_bytes(w)
}

impl Poly1305 {
    /// A new authenticator for one message (the key by reference – no copy of it is kept
    /// besides r and s inside, wiped on drop).
    pub fn new(key: &[u8; KEY_LEN]) -> Poly1305 {
        let t0 = le64(&key[0..8]);
        let t1 = le64(&key[8..16]);
        // The clamp of RFC 8439 2.5.1 in limb form (r & 0x0ffffffc0ffffffc0ffffffc0fffffff).
        let r = [t0 & 0xffc_0fff_ffff, ((t0 >> 44) | (t1 << 20)) & 0xfff_ffc0_ffff, (t1 >> 24) & 0x00f_ffff_fc0f];
        Poly1305 { r, s: [le64(&key[16..24]), le64(&key[24..32])], h: [0; 3], buf: [0; 16], buf_len: 0 }
    }

    /// One 16-byte block; `hibit` = 2^128 in limb 2 (1 << 40) for a full block, 0 for the
    /// padded last one (its 0x01 byte is already in `m`).
    fn block(&mut self, m: &[u8; 16], hibit: u64) {
        let [r0, r1, r2] = self.r;
        bound!(r0 <= M44 && r1 <= M44 && r2 <= M42);
        let s1 = r1 * (5 << 2);
        let s2 = r2 * (5 << 2);
        let t0 = le64(&m[0..8]);
        let t1 = le64(&m[8..16]);
        let mut h0 = self.h[0] + (t0 & M44);
        let mut h1 = self.h[1] + (((t0 >> 44) | (t1 << 20)) & M44);
        let mut h2 = self.h[2] + (((t1 >> 24) & M42) | hibit);
        bound!(h0 < 1 << 45 && h1 < 1 << 45 && h2 < 1 << 44);
        let d0 = h0 as u128 * r0 as u128 + h1 as u128 * s2 as u128 + h2 as u128 * s1 as u128;
        let mut d1 = h0 as u128 * r1 as u128 + h1 as u128 * r0 as u128 + h2 as u128 * s2 as u128;
        let mut d2 = h0 as u128 * r2 as u128 + h1 as u128 * r1 as u128 + h2 as u128 * r0 as u128;
        bound!(d0 < 1 << 97 && d1 < 1 << 97 && d2 < 1 << 97);
        // Carry: limbs back to 44 / 44 / 42 bits; the part above 2^130 times 5 into h0.
        let c = (d0 >> 44) as u64;
        h0 = d0 as u64 & M44;
        d1 += c as u128;
        let c = (d1 >> 44) as u64;
        h1 = d1 as u64 & M44;
        d2 += c as u128;
        let c = (d2 >> 42) as u64;
        h2 = d2 as u64 & M42;
        bound!(c < 1 << 56);
        h0 += c * 5;
        let c = h0 >> 44;
        h0 &= M44;
        h1 += c;
        bound!(h0 <= M44 && h1 < (1 << 44) + (1 << 20) && h2 <= M42);
        self.h = [h0, h1, h2];
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (16 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 16 {
                return;
            }
            let b = self.buf;
            self.block(&b, 1 << 40);
            self.buf_len = 0;
        }
        while data.len() >= 16 {
            let mut b = [0u8; 16];
            b.copy_from_slice(&data[..16]);
            self.block(&b, 1 << 40);
            data = &data[16..];
        }
        self.buf[..data.len()].copy_from_slice(data);
        self.buf_len = data.len();
    }

    /// The tag; the state is wiped (Drop).
    pub fn finish(mut self) -> [u8; TAG_LEN] {
        if self.buf_len > 0 {
            let mut b = [0u8; 16];
            b[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            b[self.buf_len] = 1;
            self.block(&b, 0);
            super::wipe(&mut b);
        }
        let h = self.h;
        let s = self.s;
        freeze_add(h, s)
    }

    /// Checks a tag in constant time (16 bytes; any other length is a mismatch).
    pub fn verify(self, tag: &[u8]) -> Result<(), Error> {
        let mut t = self.finish();
        let ok = tag.len() == TAG_LEN && equal_ct(&t, tag);
        super::wipe(&mut t);
        if ok { Ok(()) } else { Err(Error::Mismatch) }
    }
}

/// h fully reduced mod 2^130 - 5 (no branch: the "h >= p" choice is a mask), plus s,
/// mod 2^128, as 16 bytes.
fn freeze_add(h: [u64; 3], s: [u64; 2]) -> [u8; TAG_LEN] {
    let [mut h0, mut h1, mut h2] = h;
    // Two full carry rounds: h0, h1 < 2^44, h2 < 2^42 (h < 2^130, maybe still >= p).
    for _ in 0..2 {
        let c = h1 >> 44;
        h1 &= M44;
        h2 += c;
        let c = h2 >> 42;
        h2 &= M42;
        h0 += c * 5;
        let c = h0 >> 44;
        h0 &= M44;
        h1 += c;
    }
    let c = h1 >> 44;
    h1 &= M44;
    h2 += c;
    // g = h + 5 - 2^130: non-negative exactly when h >= p.
    let mut g0 = h0 + 5;
    let c = g0 >> 44;
    g0 &= M44;
    let mut g1 = h1 + c;
    let c = g1 >> 44;
    g1 &= M44;
    let mut g2 = h2.wrapping_add(c).wrapping_sub(1 << 42);
    // mask = all ones when g2 did not go negative (h >= p): take g; else keep h.
    let mask = (g2 >> 63).wrapping_sub(1);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    let keep = !mask;
    h0 = (h0 & keep) | g0;
    h1 = (h1 & keep) | g1;
    h2 = (h2 & keep) | g2;
    // + s (mod 2^128).
    let (t0, t1) = (s[0], s[1]);
    h0 += t0 & M44;
    let c = h0 >> 44;
    h0 &= M44;
    h1 += (((t0 >> 44) | (t1 << 20)) & M44) + c;
    let c = h1 >> 44;
    h1 &= M44;
    h2 += ((t1 >> 24) & M42) + c;
    h2 &= M42;
    let lo = h0 | (h1 << 44);
    let hi = (h1 >> 20) | (h2 << 24);
    let mut out = [0u8; TAG_LEN];
    out[..8].copy_from_slice(&lo.to_le_bytes());
    out[8..].copy_from_slice(&hi.to_le_bytes());
    out
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        super::wipe_words64(&mut self.r);
        super::wipe_words64(&mut self.s);
        super::wipe_words64(&mut self.h);
        super::wipe(&mut self.buf);
    }
}

/// The tag of `msg` under a one-time `key`.
pub fn poly1305(key: &[u8; KEY_LEN], msg: &[u8]) -> [u8; TAG_LEN] {
    let mut p = Poly1305::new(key);
    p.update(msg);
    p.finish()
}

/// Test only: the final reduction of a raw accumulator `h` (17 bytes, < 2^131) with s = 0
/// – to check h = p - 1, p, p + 1, 2^130 - 1, ... directly.
#[cfg(any(selftest, desocrypto_test))]
pub fn freeze_for_test(h: &[u8; 17]) -> [u8; TAG_LEN] {
    let lo = le64(&h[0..8]);
    let mid = le64(&h[8..16]);
    let top = h[16] as u64;
    let h0 = lo & M44;
    let h1 = ((lo >> 44) | (mid << 20)) & M44;
    let h2 = (mid >> 24) | (top << 40);
    freeze_add([h0, h1, h2], [0, 0])
}
