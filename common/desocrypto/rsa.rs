// RSA signature VERIFICATION (RFC 8017) – PKCS#1 v1.5 and PSS.  No signing, no decryption:
// DeSoOS only checks signatures made by others (certificates, TLS CertificateVerify).
//
//   let key = PublicKey::new(n_be, e_be)?;                        // n 2048-4096 bits
//   key.verify_pkcs1(HashAlg::Sha256, msg, sig)?;                  // RSASSA-PKCS1-v1_5
//   key.verify_pss(&PssParams::tls(HashAlg::Sha256), msg, sig)?;   // RSASSA-PSS, TLS 1.3 rule
//   key.verify_pss(&PssParams { hash, mgf_hash, salt_len }, msg, sig)?;  // parameters from X.509
//
// Errors: InvalidKey (n or e outside the rules below), InvalidSignature (wrong length or
// s >= n), Mismatch (well-formed, but not a signature of `msg` by this key).
//
// Rules:
// * n: 2048..=4096 bits, odd, given without a leading zero byte; e: odd, 3 <= e < 2^32,
//   minimal bytes.  (The DER parsing of a key is the X.509 code's job.)
// * the signature has exactly k = byte length of n bytes and s < n (RFC 8017 8.2.2 / 8.1.2).
// * PKCS#1 v1.5: the whole encoded block 00 01 FF..FF 00 DigestInfo H is built and compared
//   with the result – nothing is parsed out of it (no "lenient" parser: Bleichenbacher 2006).
//   Only the DigestInfo with the NULL parameters is accepted (Wycheproof "MissingNull" is
//   refused – strict).
// * PSS: the parameters are given explicitly – the hash, the MGF1 hash and the salt length –
//   never guessed.  `PssParams::tls(h)` is the TLS 1.3 rule (MGF1 with the same hash, salt =
//   hash length); a certificate's id-RSASSA-PSS parameters are read by the X.509 code and
//   passed as they are.
//
// Public data only (the key and the signature are public), so the arithmetic is not
// constant time – see bignum.rs.  The cost is bounded: at most 4096-bit numbers, e < 2^32.

use super::Error;
use super::bignum::{self, MAX_LIMBS, Modulus};
use super::hash::{HashAlg, Hasher, MAX_OUT};

pub const MIN_BITS: usize = 2048;
pub const MAX_BITS: usize = 4096;
/// The largest k (signature length).
pub const MAX_BYTES: usize = MAX_BITS / 8;

const PREFIX_SHA256: [u8; 19] = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
const PREFIX_SHA384: [u8; 19] = [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30];
const PREFIX_SHA512: [u8; 19] = [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40];

/// DER DigestInfo prefix (AlgorithmIdentifier with NULL parameters) for a hash.
fn digest_info_prefix(h: HashAlg) -> &'static [u8; 19] {
    match h {
        HashAlg::Sha256 => &PREFIX_SHA256,
        HashAlg::Sha384 => &PREFIX_SHA384,
        HashAlg::Sha512 => &PREFIX_SHA512,
    }
}

/// RSASSA-PSS parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PssParams {
    pub hash: HashAlg,
    pub mgf_hash: HashAlg,
    pub salt_len: usize,
}

impl PssParams {
    /// TLS 1.3 (RFC 8446 4.2.3): MGF1 with the same hash, salt length = hash length.
    pub fn tls(hash: HashAlg) -> PssParams {
        PssParams { hash, mgf_hash: hash, salt_len: hash.out_len() }
    }
}

pub struct PublicKey {
    n: Modulus<MAX_LIMBS>,
    /// Byte length of n.
    k: usize,
    bits: usize,
    e: [u8; 4],
}

impl PublicKey {
    pub fn new(n_be: &[u8], e_be: &[u8]) -> Result<PublicKey, Error> {
        if n_be.is_empty() || n_be[0] == 0 || n_be.len() > MAX_BYTES {
            return Err(Error::InvalidKey);
        }
        let n = Modulus::<MAX_LIMBS>::new(n_be).map_err(|_| Error::InvalidKey)?;
        let bits = n.bits();
        if !(MIN_BITS..=MAX_BITS).contains(&bits) {
            return Err(Error::InvalidKey);
        }
        if e_be.is_empty() || e_be[0] == 0 || e_be.len() > 4 {
            return Err(Error::InvalidKey);
        }
        let mut e = [0u8; 4];
        e[4 - e_be.len()..].copy_from_slice(e_be);
        let ev = u32::from_be_bytes(e);
        if ev < 3 || ev & 1 == 0 {
            return Err(Error::InvalidKey);
        }
        Ok(PublicKey { n, k: n_be.len(), bits, e })
    }

    pub fn bits(&self) -> usize {
        self.bits
    }

    /// m = s^e mod n as k big-endian bytes into out[..k] (RSAVP1 with the length checks).
    fn open(&self, sig: &[u8], out: &mut [u8; MAX_BYTES]) -> Result<(), Error> {
        if sig.len() != self.k {
            return Err(Error::InvalidSignature);
        }
        let s = bignum::from_be::<MAX_LIMBS>(sig).map_err(|_| Error::InvalidSignature)?;
        if !self.n.is_reduced(&s) {
            return Err(Error::InvalidSignature);
        }
        let m = self.n.pow(&s, &self.e);
        bignum::to_be(&m, &mut out[..self.k]).map_err(|_| Error::InvalidSignature)
    }

    /// RSASSA-PKCS1-v1_5 verification (RFC 8017 8.2.2) with `hash` over `msg`.
    pub fn verify_pkcs1(&self, hash: HashAlg, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let mut em = [0u8; MAX_BYTES];
        self.open(sig, &mut em)?;
        let h = hash.digest(msg);
        let prefix = digest_info_prefix(hash);
        let t_len = prefix.len() + h.as_bytes().len();
        let k = self.k;
        // k >= 256 and t_len <= 83, so the padding is far above the 8-byte minimum.
        let mut want = [0u8; MAX_BYTES];
        want[1] = 0x01;
        for b in want.iter_mut().take(k - t_len - 1).skip(2) {
            *b = 0xff;
        }
        want[k - t_len - 1] = 0x00;
        want[k - t_len..k - h.as_bytes().len()].copy_from_slice(prefix);
        want[k - h.as_bytes().len()..k].copy_from_slice(h.as_bytes());
        if em[..k] == want[..k] { Ok(()) } else { Err(Error::Mismatch) }
    }

    /// RSASSA-PSS verification (RFC 8017 8.1.2 / 9.1.2) with explicit parameters.
    pub fn verify_pss(&self, p: &PssParams, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let mut m = [0u8; MAX_BYTES];
        self.open(sig, &mut m)?;
        let em_bits = self.bits - 1;
        let em_len = em_bits.div_ceil(8);
        // When emBits is a multiple of 8 the encoded message is one byte shorter than k:
        // the first byte of m must then be zero.
        let skip = self.k - em_len;
        if skip == 1 && m[0] != 0 {
            return Err(Error::Mismatch);
        }
        let em = &m[skip..self.k];
        let h_len = p.hash.out_len();
        let m_hash = p.hash.digest(msg);
        if p.salt_len > em_len || em_len < h_len + p.salt_len + 2 {
            return Err(Error::Mismatch);
        }
        if em[em_len - 1] != 0xbc {
            return Err(Error::Mismatch);
        }
        let db_len = em_len - h_len - 1;
        let masked_db = &em[..db_len];
        let hh = &em[db_len..db_len + h_len];
        // The leftmost 8·emLen - emBits bits of maskedDB must be zero.
        let top_bits = 8 * em_len - em_bits;
        let top_mask = (0xffu16 << (8 - top_bits)) as u8;
        if masked_db[0] & top_mask != 0 {
            return Err(Error::Mismatch);
        }
        let mut db = [0u8; MAX_BYTES];
        mgf1(p.mgf_hash, hh, &mut db[..db_len]);
        for i in 0..db_len {
            db[i] ^= masked_db[i];
        }
        db[0] &= !top_mask;
        let ps_len = em_len - h_len - p.salt_len - 2;
        if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 0x01 {
            return Err(Error::Mismatch);
        }
        let salt = &db[db_len - p.salt_len..db_len];
        let mut h2 = Hasher::new(p.hash);
        h2.update(&[0u8; 8]);
        h2.update(m_hash.as_bytes());
        h2.update(salt);
        let h2 = h2.finish().map_err(|_| Error::Mismatch)?;
        if h2.as_bytes() == hh { Ok(()) } else { Err(Error::Mismatch) }
    }
}

/// MGF1 (RFC 8017 B.2.1): out = Hash(seed ‖ 0) ‖ Hash(seed ‖ 1) ‖ … cut to out.len().
fn mgf1(hash: HashAlg, seed: &[u8], out: &mut [u8]) {
    let mut done = 0;
    let mut counter: u32 = 0;
    while done < out.len() {
        let mut h = Hasher::new(hash);
        h.update(seed);
        h.update(&counter.to_be_bytes());
        let mut block = [0u8; MAX_OUT];
        let d = h.finish().unwrap_or_else(|_| hash.digest(&[]));
        let take = (out.len() - done).min(d.as_bytes().len());
        block[..d.as_bytes().len()].copy_from_slice(d.as_bytes());
        out[done..done + take].copy_from_slice(&block[..take]);
        done += take;
        counter += 1;
    }
}
