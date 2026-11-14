// AES-CMAC (RFC 4493) and AES-SIV (RFC 5297) with AES-128 – AEAD_AES_SIV_CMAC_256, the one
// AEAD every NTS server must support (RFC 8915).
//
//   cmac(&aes, msg)                       the 16-byte CMAC tag of `msg` under `aes`
//   AesSiv::new(key)                      key = 32 bytes: K1 (first 16) for S2V / CMAC,
//                                         K2 (last 16) for CTR – two AES-128 keys
//   siv.seal(ad, buf)                     ad = the associated-data components (0 to
//                                         MAX_AD), encrypts `buf` in place, returns the
//                                         synthetic IV (the tag, 16 bytes)
//   siv.open(ad, buf, siv)                decrypts, recomputes the IV; only when it
//                                         matches the plaintext stays – otherwise `buf`
//                                         is put back exactly as it was (no plaintext out)
//   aead_seal / aead_open(key, nonce, aad, buf)  the RFC 5297 §6 AEAD interface: the
//                                         components are [aad, nonce] (as NTS uses it)
//
// S2V (RFC 5297 §2.4): D = CMAC(<zero>); for every component but the last
// D = dbl(D) xor CMAC(Si); the last one (the plaintext): length >= 16 – CMAC(Sn xorend
// D), shorter – CMAC(dbl(D) xor pad(Sn)).  CTR (§2.5): the counter starts at
// Q = V with bit 63 and bit 31 cleared (the top bit of bytes 8 and 12), 128-bit
// big-endian, adding one per block (mod 2^128).
//
// AES-SIV is deterministic: the same key, components and plaintext give the same output
// – nonce misuse reveals only that two messages were equal, nothing more (the point of
// SIV).  NTS still puts a fresh random nonce in every packet.
//
// AES comes from aes.rs: AES-NI where the CPU has it (programs), otherwise the bitsliced
// circuit (no table look-ups – the kernel always, being built with desocrypto_no_simd).
// The tag is compared in constant time; dbl() has no branch on secret bits.  Wiped: D,
// the CMAC subkeys and state, every key-stream block, the recomputed IV in `open`.  Not
// audited.

use super::aes::{Aes128, BLOCK, Features, KEY_LEN};
use super::{Error, equal_ct, wipe};

pub const SIV_KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
/// Associated-data components S2V takes besides the plaintext (RFC 5297 §7: at most 126).
pub const MAX_AD: usize = 126;
/// Longest plaintext: the 32-bit CTR counter halves were cleared, so 2^32 blocks stay
/// safe; we keep far below (and below what NTS ever sends).
pub const MAX_LEN: usize = 1 << 24;

/// Doubling in GF(2^128) (RFC 5297 §2.3): shift left one bit, xor 0x87 into the last byte
/// when the top bit was set – without a branch on it.
fn dbl(b: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut o = [0u8; BLOCK];
    for i in 0..BLOCK {
        let next = if i + 1 < BLOCK { b[i + 1] >> 7 } else { 0 };
        o[i] = (b[i] << 1) | next;
    }
    // 0xFF when the top bit of b[0] was set, 0x00 otherwise.
    let mask = 0u8.wrapping_sub(b[0] >> 7);
    o[BLOCK - 1] ^= 0x87 & mask;
    o
}

fn enc(aes: &Aes128, b: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut blk = [*b];
    aes.encrypt_blocks(&mut blk);
    blk[0]
}

/// CMAC computed as the bytes come (any split).  The last block is held back until
/// `finish`, which decides between subkey K1 (whole last block) and K2 (padded).
struct Cmac<'a> {
    aes: &'a Aes128,
    x: [u8; BLOCK],
    buf: [u8; BLOCK],
    n: usize,
}

impl<'a> Cmac<'a> {
    fn new(aes: &'a Aes128) -> Cmac<'a> {
        Cmac { aes, x: [0; BLOCK], buf: [0; BLOCK], n: 0 }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.n == BLOCK {
                // A whole block is waiting and more data follows: it was not the last one.
                for i in 0..BLOCK {
                    self.x[i] ^= self.buf[i];
                }
                self.x = enc(self.aes, &self.x);
                self.n = 0;
            }
            let k = (BLOCK - self.n).min(data.len());
            self.buf[self.n..self.n + k].copy_from_slice(&data[..k]);
            self.n += k;
            data = &data[k..];
        }
    }

    fn finish(mut self) -> [u8; BLOCK] {
        let mut l = enc(self.aes, &[0; BLOCK]);
        let mut k1 = dbl(&l);
        let mut k2 = dbl(&k1);
        let mut last = [0u8; BLOCK];
        if self.n == BLOCK {
            for i in 0..BLOCK {
                last[i] = self.buf[i] ^ k1[i];
            }
        } else {
            last[..self.n].copy_from_slice(&self.buf[..self.n]);
            last[self.n] = 0x80;
            for i in 0..BLOCK {
                last[i] ^= k2[i];
            }
        }
        for i in 0..BLOCK {
            self.x[i] ^= last[i];
        }
        let t = enc(self.aes, &self.x);
        wipe(&mut l);
        wipe(&mut k1);
        wipe(&mut k2);
        wipe(&mut last);
        t
    }
}

impl Drop for Cmac<'_> {
    fn drop(&mut self) {
        wipe(&mut self.x);
        wipe(&mut self.buf);
    }
}

/// AES-CMAC (RFC 4493) of `msg`.
pub fn cmac(aes: &Aes128, msg: &[u8]) -> [u8; BLOCK] {
    let mut c = Cmac::new(aes);
    c.update(msg);
    c.finish()
}

pub struct AesSiv {
    mac: Aes128,
    ctr: Aes128,
}

impl AesSiv {
    pub fn new(key: &[u8; SIV_KEY_LEN]) -> AesSiv {
        AesSiv::with_features(key, Features { aes: true, pclmul: true })
    }

    /// Only the features in `wanted` that the CPU really has (the software path: NONE).
    pub fn with_features(key: &[u8; SIV_KEY_LEN], wanted: Features) -> AesSiv {
        let features = Features::limit(wanted);
        let mut k1 = [0u8; KEY_LEN];
        let mut k2 = [0u8; KEY_LEN];
        k1.copy_from_slice(&key[..KEY_LEN]);
        k2.copy_from_slice(&key[KEY_LEN..]);
        let s = AesSiv { mac: Aes128::new(&k1, features), ctr: Aes128::new(&k2, features) };
        wipe(&mut k1);
        wipe(&mut k2);
        s
    }

    pub fn uses_aesni(&self) -> bool {
        self.mac.uses_aesni()
    }

    fn check(ad: &[&[u8]], len: usize) -> Result<(), Error> {
        if ad.len() > MAX_AD || len > MAX_LEN {
            return Err(Error::InvalidLength);
        }
        Ok(())
    }

    /// S2V over the components and the plaintext `p` (RFC 5297 §2.4).
    fn s2v(&self, ad: &[&[u8]], p: &[u8]) -> [u8; BLOCK] {
        let mut d = cmac(&self.mac, &[0u8; BLOCK]);
        for s in ad {
            let mut m = cmac(&self.mac, s);
            let dd = dbl(&d);
            for i in 0..BLOCK {
                d[i] = dd[i] ^ m[i];
            }
            wipe(&mut m);
        }
        let v = if p.len() >= BLOCK {
            // CMAC(Sn xorend D): the last 16 bytes of the plaintext xor D.
            let split = p.len() - BLOCK;
            let mut tail = [0u8; BLOCK];
            for i in 0..BLOCK {
                tail[i] = p[split + i] ^ d[i];
            }
            let mut c = Cmac::new(&self.mac);
            c.update(&p[..split]);
            c.update(&tail);
            wipe(&mut tail);
            c.finish()
        } else {
            let mut t = dbl(&d);
            for i in 0..p.len() {
                t[i] ^= p[i];
            }
            t[p.len()] ^= 0x80;
            let v = cmac(&self.mac, &t);
            wipe(&mut t);
            v
        };
        wipe(&mut d);
        v
    }

    /// buf XOR the key stream from Q (V with bits 63 and 31 cleared).
    fn ctr_xor(&self, v: &[u8; BLOCK], buf: &mut [u8]) {
        let mut q = *v;
        q[8] &= 0x7F;
        q[12] &= 0x7F;
        let mut counter = u128::from_be_bytes(q);
        let mut ks = [[0u8; BLOCK]; 4];
        for chunk in buf.chunks_mut(64) {
            let n = chunk.len().div_ceil(BLOCK);
            for b in ks.iter_mut().take(n) {
                *b = counter.to_be_bytes();
                counter = counter.wrapping_add(1);
            }
            self.ctr.encrypt_blocks(&mut ks[..n]);
            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= ks[i / BLOCK][i % BLOCK];
            }
        }
        for b in ks.iter_mut() {
            wipe(b);
        }
        wipe(&mut q);
    }

    /// Encrypts `buf` in place; the synthetic IV (16 bytes) – the tag to send in front.
    pub fn seal(&self, ad: &[&[u8]], buf: &mut [u8]) -> Result<[u8; TAG_LEN], Error> {
        Self::check(ad, buf.len())?;
        let v = self.s2v(ad, buf);
        self.ctr_xor(&v, buf);
        Ok(v)
    }

    /// Decrypts `buf` in place and checks the IV.  Wrong: Error::Mismatch and `buf` is the
    /// ciphertext again (encrypted back) – no byte of the plaintext stays.
    pub fn open(&self, ad: &[&[u8]], buf: &mut [u8], siv: &[u8; TAG_LEN]) -> Result<(), Error> {
        Self::check(ad, buf.len())?;
        self.ctr_xor(siv, buf);
        let mut want = self.s2v(ad, buf);
        let ok = equal_ct(&want, siv);
        wipe(&mut want);
        if !ok {
            self.ctr_xor(siv, buf);
            return Err(Error::Mismatch);
        }
        Ok(())
    }
}

/// AEAD_AES_SIV_CMAC_256 (RFC 5297 §6): components [aad, nonce], then the plaintext.
pub fn aead_seal(key: &[u8; SIV_KEY_LEN], nonce: &[u8], aad: &[u8], buf: &mut [u8]) -> Result<[u8; TAG_LEN], Error> {
    AesSiv::new(key).seal(&[aad, nonce], buf)
}

pub fn aead_open(key: &[u8; SIV_KEY_LEN], nonce: &[u8], aad: &[u8], buf: &mut [u8], siv: &[u8; TAG_LEN]) -> Result<(), Error> {
    AesSiv::new(key).open(&[aad, nonce], buf, siv)
}

/// dbl() for the tests (RFC 5297 A.1 lists the intermediate values).
pub fn dbl_for_test(b: &[u8; BLOCK]) -> [u8; BLOCK] {
    dbl(b)
}
