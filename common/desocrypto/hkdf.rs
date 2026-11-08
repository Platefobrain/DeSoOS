// HKDF (RFC 5869) – turns a secret (e.g. a shared key) into one or more keys of the
// needed length.  SHA-256 by default; any hash in `hash::Digest` with the `_with` forms.
//
//   let prk = extract(salt, ikm);              // step 1: [u8; 32]
//   expand(&prk, info, &mut okm)?;             // step 2: okm = any length up to 8160
//   hkdf(salt, ikm, info, &mut okm)?;          // both steps
//
//   let prk = extract_with::<Sha384>(salt, ikm);           // hash::Output (48 bytes)
//   expand_with::<Sha384>(prk.as_bytes(), info, &mut okm)?; // up to 255 × 48 bytes
//
// Edge cases from the RFC:
// * an empty salt means HashLen zero bytes (the same key for HMAC);
// * at most 255 × HashLen bytes of output – more is Error::OutputTooLong, never a
//   repeating or shortened key; an empty output is allowed;
// * the PRK given to expand must be at least HashLen bytes (Error::KeyTooShort).

use super::Error;
use super::hash::{Digest, MAX_OUT, Output};
use super::hmac::{Hmac, wipe};
use super::sha256::{OUT_LEN, Sha256};

/// The most output one SHA-256 expand can give.
pub const MAX_OUTPUT: usize = 255 * OUT_LEN;

/// Step 1 with hash D: PRK = HMAC(salt, ikm).  Empty salt = D::OUT_LEN zero bytes.
pub fn extract_with<D: Digest>(salt: &[u8], ikm: &[u8]) -> Output {
    let zero = [0u8; MAX_OUT];
    let salt = if salt.is_empty() { &zero[..D::OUT_LEN] } else { salt };
    // A slice in memory is below every length limit.
    Hmac::<D>::new(salt).chain(ikm).finish().unwrap_or(Output::from_parts([0; MAX_OUT], D::OUT_LEN))
}

/// Step 2 with hash D: okm = T(1) | T(2) | …, T(i) = HMAC(prk, T(i-1) | info | i).
pub fn expand_with<D: Digest>(prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), Error> {
    let hl = D::OUT_LEN;
    if prk.len() < hl {
        return Err(Error::KeyTooShort);
    }
    if okm.len() > 255 * hl {
        return Err(Error::OutputTooLong);
    }
    let mut t = [0u8; MAX_OUT];
    let mut t_len = 0;
    let mut done = 0;
    let mut counter: u8 = 1;
    while done < okm.len() {
        let mut m = Hmac::<D>::new(prk);
        m.update(&t[..t_len]);
        m.update(info);
        m.update(&[counter]);
        let r = m.finish()?;
        t[..hl].copy_from_slice(r.as_bytes());
        t_len = hl;
        let take = (okm.len() - done).min(hl);
        okm[done..done + take].copy_from_slice(&t[..take]);
        done += take;
        // At most 255 blocks (checked above): the counter does not wrap inside the loop.
        counter = counter.wrapping_add(1);
    }
    wipe(&mut t);
    Ok(())
}

/// Extract and expand in one call, hash D.
pub fn hkdf_with<D: Digest>(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), Error> {
    if okm.len() > 255 * D::OUT_LEN {
        return Err(Error::OutputTooLong);
    }
    let prk = extract_with::<D>(salt, ikm);
    let mut p = [0u8; MAX_OUT];
    p[..D::OUT_LEN].copy_from_slice(prk.as_bytes());
    let r = expand_with::<D>(&p[..D::OUT_LEN], info, okm);
    wipe(&mut p);
    r
}

/// Step 1, SHA-256.
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; OUT_LEN] {
    let mut out = [0u8; OUT_LEN];
    out.copy_from_slice(extract_with::<Sha256>(salt, ikm).as_bytes());
    out
}

/// Step 2, SHA-256.
pub fn expand(prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), Error> {
    expand_with::<Sha256>(prk, info, okm)
}

/// Both steps, SHA-256.
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), Error> {
    hkdf_with::<Sha256>(salt, ikm, info, okm)
}
