// HKDF-SHA256 (RFC 5869) – turns a secret (e.g. a shared key) into one or more
// keys of the needed length.
//
//   let prk = extract(salt, ikm);              // step 1: [u8; 32]
//   expand(&prk, info, &mut okm)?;             // step 2: okm = any length up to 8160
//
//   hkdf(salt, ikm, info, &mut okm)?;          // both steps
//
// Edge cases from the RFC:
// * an empty salt means 32 zero bytes (the same key for HMAC);
// * at most 255 × 32 = 8160 bytes of output – more is Error::OutputTooLong, never a
//   repeating or shortened key; an empty output is allowed;
// * the PRK given to expand must be at least 32 bytes (Error::KeyTooShort).

use super::Error;
use super::hmac::{HmacSha256, wipe};
use super::sha256::OUT_LEN;

/// The most output one expand can give.
pub const MAX_OUTPUT: usize = 255 * OUT_LEN;

/// Step 1: PRK = HMAC(salt, ikm).  Empty salt = 32 zero bytes (RFC 5869 2.2).
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; OUT_LEN] {
    let zero = [0u8; OUT_LEN];
    let salt = if salt.is_empty() { &zero[..] } else { salt };
    super::hmac::hmac_sha256(salt, ikm)
}

/// Step 2: fills `okm` with T(1) | T(2) | …, T(i) = HMAC(prk, T(i-1) | info | i).
pub fn expand(prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), Error> {
    if prk.len() < OUT_LEN {
        return Err(Error::KeyTooShort);
    }
    if okm.len() > MAX_OUTPUT {
        return Err(Error::OutputTooLong);
    }
    let mut t = [0u8; OUT_LEN];
    let mut t_len = 0;
    let mut done = 0;
    let mut counter: u8 = 1;
    while done < okm.len() {
        let mut m = HmacSha256::new(prk);
        m.update(&t[..t_len]);
        m.update(info);
        m.update(&[counter]);
        t = m.finish()?;
        t_len = OUT_LEN;
        let take = (okm.len() - done).min(OUT_LEN);
        okm[done..done + take].copy_from_slice(&t[..take]);
        done += take;
        // At most 255 blocks (checked above), so the counter never wraps to 0
        // inside the loop; wrapping_add keeps the last step from overflowing.
        counter = counter.wrapping_add(1);
    }
    wipe(&mut t);
    Ok(())
}

/// Extract and expand in one call.
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), Error> {
    if okm.len() > MAX_OUTPUT {
        return Err(Error::OutputTooLong);
    }
    let mut prk = extract(salt, ikm);
    let r = expand(&prk, info, okm);
    wipe(&mut prk);
    r
}
