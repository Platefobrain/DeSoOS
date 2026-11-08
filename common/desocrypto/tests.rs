// DeSoCrypto tests – official vectors, edge cases, wrong input.
//
// Not part of the library (mod.rs does not include it): included only by
// /bin/cryptotest and the kernel CRYPTO TEST, as a sibling of `desocrypto`:
//
//   #[path = ".../common/desocrypto/mod.rs"]   mod desocrypto;
//   #[path = ".../common/desocrypto/tests.rs"] mod desocrypto_tests;
//
// `run()` stops at the first failed check and says which one; on success it
// returns how many checks passed.  No heap, no printing – the caller reports.
//
// Sources of the vectors:
//   SHA-256  FIPS 180-4 / NIST examples ("abc", 448- and 896-bit messages, a million 'a')
//   HMAC     RFC 4231 test cases 1-7
//   HKDF     RFC 5869 test cases 1-3 (SHA-256)
//   ChaCha20 RFC 8439 sections 2.3.2, 2.4.2, appendix A.1 (1-5) and A.2 (2)
//   rng      the fast-key-erasure generator against the same construction in Python
//   Poly1305 RFC 8439 2.5.2; the A.3 edge cases #1, #5-#9 (their structure) and limbs at
//            their maximum, the final reduction of h = p - 1, p, p + 1, 2^130 - 1, ...;
//            expected values from Python big integers (the RFC formula, no limbs), each
//            also checked against the `cryptography` library
//   AEAD     RFC 8439 2.8.2; lengths 0-1000 with and without aad (Python `cryptography`);
//            a wrong tag / aad / nonce / key / ciphertext bit leaves the buffer untouched
//   X25519   RFC 7748 5.2 (two vectors), the iteration 1 and 1000 times, 6.1 Alice / Bob;
//            the seven low-order points (also with the top bit set) refused; field
//            operations on edge values (1, 2, p - 1, p, 2^255 - 20, 2^255 - 1) against
//            Python big integers; cswap for 0 and 1
//   AES      FIPS-197 C.1 and A.1, the circuit S-box for all 256 inputs, 1-5 blocks
//   GHASH    products and hashes against SP 800-38D written on Python integers
//   AES-GCM  NIST (McGrew-Viega) Test Cases 1-4; lengths 0-95 and 1000 (in the middle of a
//            larger array with guard bytes), aad of 1 / 15 / 16 / 17 bytes; a wrong tag
//            leaves the buffer untouched.  Every check runs with each combination of
//            AES-NI / PCLMULQDQ the CPU allows (in the kernel: software only) – all equal.
//   SHA-384/512  FIPS 180-4 / NIST examples ("abc", "", 896-bit, a million 'a'); lengths at
//            the padding edges against Python hashlib
//   HMAC/HKDF SHA-384/512  RFC 4231 cases 1-7; HKDF against Python `cryptography`
//   bignum   modular powers of 64- to 4096-bit numbers against Python integers
//   RSA      keys and signatures (PKCS#1 v1.5, PSS with several parameter sets, a 2049-bit
//            key) from Python `cryptography`; tampered messages and signatures, s = 0 / n,
//            wrong lengths, keys outside the rules, a DigestInfo without NULL
//   ECDSA    P-256 / P-384 from Python `cryptography` (also the key with private value 1,
//            digests e > n, e = n, e = 0); DER variants (non-minimal, long form, negative,
//            trailing bytes), r / s = 0 or n, high s, public keys off the curve (also
//            check_public_key alone)
//   Wycheproof  vectors/wycheproof.bin (gen-wycheproof.py, pinned commit): ECDSA P-256 and
//            P-384, RSA PKCS#1 2048/SHA-256, PSS 2048/SHA-256 and the PSS "misc" sets
// The other expected values (block-edge lengths, empty key, 8160-byte output) were
// computed with an independent implementation (Python hashlib / hmac).

#![allow(dead_code)]

use super::desocrypto::hkdf::{self, MAX_OUTPUT};
use super::desocrypto::hmac::{HmacSha256, MIN_TAG_LEN, hmac_sha256};
use super::desocrypto::chacha20;
use super::desocrypto::aead;
use super::desocrypto::aes::{self, Aes128, Features};
use super::desocrypto::aes_gcm::AesGcm;
use super::desocrypto::ghash::{self, Ghash};
use super::desocrypto::poly1305::{self, Poly1305};
use super::desocrypto::rng::KeyErasureRng;
use super::desocrypto::sha256::{MAX_BYTES, Sha256, sha256};
use super::desocrypto::x25519;
use super::desocrypto::bignum::{self, MAX_LIMBS, Modulus};
use super::desocrypto::ecdsa::{self, Curve};
use super::desocrypto::hash::HashAlg;
use super::desocrypto::hmac::Hmac;
use super::desocrypto::rsa::{self, PssParams};
use super::desocrypto::sha512::{Sha384, Sha512, sha384, sha512};
use super::desocrypto::{Error, equal_ct, hex};

/// The first failed check: group and case number (1-based).
#[derive(Clone, Copy, Debug)]
pub struct Failure {
    pub group: &'static str,
    pub case: usize,
}

struct Checks {
    group: &'static str,
    case: usize,
    passed: usize,
}

impl Checks {
    fn group(&mut self, name: &'static str) {
        self.group = name;
        self.case = 0;
    }
    fn check(&mut self, ok: bool) -> Result<(), Failure> {
        self.case += 1;
        if ok {
            self.passed += 1;
            Ok(())
        } else {
            Err(Failure { group: self.group, case: self.case })
        }
    }
}

/// Hex text -> bytes into `out`; the number of bytes.
fn unhex(s: &str, out: &mut [u8]) -> usize {
    let b = s.as_bytes();
    let val = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    };
    let n = b.len() / 2;
    for i in 0..n {
        out[i] = (val(b[2 * i]) << 4) | val(b[2 * i + 1]);
    }
    n
}

fn same(got: &[u8], want_hex: &str) -> bool {
    let mut want = [0u8; 128];
    let n = unhex(want_hex, &mut want);
    got.len() == n && got == &want[..n]
}

/// The test pattern: byte i = i*7 + 3.
fn pattern(out: &mut [u8]) {
    for (i, b) in out.iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(7).wrapping_add(3) as u8;
    }
}

fn range(from: u8, out: &mut [u8]) {
    for (i, b) in out.iter_mut().enumerate() {
        *b = from.wrapping_add(i as u8);
    }
}

const SHA_EDGES: &[(usize, &str)] = &[
    (1, "084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5"),
    (55, "e7313d333c272e639f790978283f9eb392e843d0f29b7016828bb1daa4aac70b"),
    (56, "4324d65f3c103567f5589c710bc08f8523f929a9272e3af36fc968e52abc6c27"),
    (57, "35df609437dcfea3279283ab79fd554e2bf78f8f7ae2de532d8ee300b09e8f73"),
    (63, "81c80242132f230c3bd41b3e63bbcff16107339549214a99614ff26664625055"),
    (64, "39e3d7b6b5d075d37d053ad89b24b41bef4f3c29760c84447cab3f3be1882241"),
    (65, "aacca6ff74fdbb296d165a45cecfa04e5127bc008770fbbdd48006f2d2fae95e"),
    (111, "67d9492e628fd376e0b2efec8ca2b99b123e202cf620deb270728df979b2f73e"),
    (112, "96b928cff8528dbb99602c709a65b846cb6467acb8b722f0d758e4dc27bfc508"),
    (119, "9ce7368e4daf32341631b492e80359dc9f594b48453cd0dd5bf0b19279cc177e"),
    (120, "7836b787757e95e58b3ca5aec90b1b004e8deba1e50e9675af9cabf1a13a04b5"),
    (127, "a8d23e75d936f303d248888d9b165ee543f4cbafcad3c9dd2a79bd84faa11d07"),
    (128, "d2742f1f4ac6bb7ca2b239ee18402ba8b3f9f8e652d2a72973c2b9ba11c08cf6"),
    (129, "307f8fc2c1622b92762e818d39a185d4d667ad49a4b07ceae1f4afa008a93ec4"),
    (1000, "1e9bc38cbf860b9ec31918b065f9b52476c549a782e0e7990bed8ce3868d2371"),
];

pub fn run() -> Result<usize, Failure> {
    let mut c = Checks { group: "", case: 0, passed: 0 };
    sha_vectors(&mut c)?;
    sha_edges(&mut c)?;
    sha_limit(&mut c)?;
    hmac_vectors(&mut c)?;
    hmac_edges(&mut c)?;
    hkdf_vectors(&mut c)?;
    hkdf_edges(&mut c)?;
    chacha_vectors(&mut c)?;
    chacha_edges(&mut c)?;
    rng_checks(&mut c)?;
    wipe_checks(&mut c)?;
    poly_vectors(&mut c)?;
    poly_ranges(&mut c)?;
    aead_vectors(&mut c)?;
    aead_tamper(&mut c)?;
    x25519_field(&mut c)?;
    x25519_vectors(&mut c)?;
    x25519_low_order(&mut c)?;
    aes_checks(&mut c)?;
    ghash_checks(&mut c)?;
    gcm_vectors(&mut c)?;
    gcm_tamper(&mut c)?;
    misc(&mut c)?;
    sha512_all(&mut c)?;
    hmac_hkdf_generic(&mut c)?;
    bignum_checks(&mut c)?;
    rsa_checks(&mut c)?;
    ecdsa_checks(&mut c)?;
    wycheproof_sets(&mut c, WYCHEPROOF)?;
    Ok(c.passed)
}

/// FIPS 180-4 / NIST examples, one-shot and streamed.
fn sha_vectors(c: &mut Checks) -> Result<(), Failure> {
    c.group("sha256 vectors");
    c.check(same(&sha256(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))?;
    c.check(same(&sha256(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))?;
    c.check(same(
        &sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ))?;
    c.check(same(
        &sha256(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    ))?;
    // A million 'a', fed in pieces of 1000 (and the empty slice between them).
    let a = [b'a'; 1000];
    let mut h = Sha256::new();
    for _ in 0..1000 {
        h.update(&a);
        h.update(&[]);
    }
    c.check(h.finish().is_ok_and(|d| same(&d, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")))?;
    // The empty message as new() + finish() with no update at all.
    c.check(Sha256::new().finish().is_ok_and(|d| d == sha256(b"")))?;
    Ok(())
}

/// Lengths around the padding edges (55/56 bytes into a block, block ends),
/// one-shot, byte by byte and split at every point.
fn sha_edges(c: &mut Checks) -> Result<(), Failure> {
    c.group("sha256 edges");
    let mut buf = [0u8; 1000];
    pattern(&mut buf);
    for &(n, want) in SHA_EDGES {
        let msg = &buf[..n];
        c.check(same(&sha256(msg), want))?;
        let mut h = Sha256::new();
        for b in msg {
            h.update(core::slice::from_ref(b));
        }
        c.check(h.finish().is_ok_and(|d| same(&d, want)))?;
    }
    // Every split of 200 bytes into two and three pieces gives the same digest.
    let msg = &buf[..200];
    let whole = sha256(msg);
    let mut ok = true;
    for i in 0..=msg.len() {
        let mut h = Sha256::new();
        h.update(&msg[..i]);
        h.update(&msg[i..]);
        ok &= h.finish() == Ok(whole);
        let j = (i + 61).min(msg.len());
        let mut h = Sha256::new();
        h.update(&msg[..i]);
        h.update(&msg[i..j]);
        h.update(&msg[j..]);
        ok &= h.finish() == Ok(whole);
    }
    c.check(ok)?;
    // A copy taken in the middle continues on its own.
    let mut h = Sha256::new();
    h.update(&msg[..70]);
    let mut h2 = h.clone();
    h.update(&msg[70..]);
    h2.update(&msg[70..]);
    c.check(h.finish() == Ok(whole) && h2.finish() == Ok(whole))?;
    // Different data -> different digest (one bit changed).
    let mut other = [0u8; 200];
    other.copy_from_slice(msg);
    other[199] ^= 1;
    c.check(sha256(&other) != whole)?;
    Ok(())
}

/// The 2^61 - 1 byte limit (the length counter is pretended, not hashed).
fn sha_limit(c: &mut Checks) -> Result<(), Failure> {
    c.group("sha256 length limit");
    // Exactly at the limit: accepted.
    let mut h = Sha256::new();
    h.assume_length(MAX_BYTES - 3);
    h.update(b"abc");
    c.check(h.finish().is_ok())?;
    // One byte past it: refused, not wrapped around.
    let mut h = Sha256::new();
    h.assume_length(MAX_BYTES - 3);
    h.update(b"abcd");
    c.check(h.finish() == Err(Error::LengthOverflow))?;
    // Once refused, more (even empty) data does not bring it back.
    let mut h = Sha256::new();
    h.assume_length(MAX_BYTES);
    h.update(b"x");
    h.update(b"");
    c.check(h.finish() == Err(Error::LengthOverflow))?;
    // A count that would wrap the 64-bit counter itself.
    let mut h = Sha256::new();
    h.assume_length(u64::MAX - 1);
    h.update(b"xyz");
    c.check(h.finish() == Err(Error::LengthOverflow))?;
    // HMAC passes the refusal on.
    let mut m = HmacSha256::new(b"key");
    m.assume_length(MAX_BYTES);
    m.update(b"x");
    c.check(m.clone().finish() == Err(Error::LengthOverflow))?;
    c.check(m.verify(&[0u8; 32]) == Err(Error::LengthOverflow))?;
    Ok(())
}

/// RFC 4231 test cases 1-7.
fn hmac_vectors(c: &mut Checks) -> Result<(), Failure> {
    c.group("hmac rfc4231");
    let mut k = [0u8; 131];
    let mut d = [0u8; 50];
    c.check(same(&hmac_sha256(&[0x0b; 20], b"Hi There"), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"))?;
    c.check(same(
        &hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    ))?;
    c.check(same(&hmac_sha256(&[0xaa; 20], &[0xdd; 50]), "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"))?;
    range(1, &mut k[..25]);
    d.fill(0xcd);
    c.check(same(&hmac_sha256(&k[..25], &d), "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"))?;
    // Test case 5: the tag truncated to 128 bits.
    let t5 = hmac_sha256(&[0x0c; 20], b"Test With Truncation");
    c.check(same(&t5[..16], "a3b6167473100ee06e0c796c2955552b"))?;
    k.fill(0xaa);
    c.check(same(
        &hmac_sha256(&k, b"Test Using Larger Than Block-Size Key - Hash Key First"),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    ))?;
    let msg7: &[u8] = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
    c.check(same(&hmac_sha256(&k, msg7), "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"))?;
    // The same, streamed in uneven pieces.
    let mut m = HmacSha256::new(&k);
    for piece in msg7.chunks(13) {
        m.update(piece);
    }
    c.check(m.finish().is_ok_and(|t| same(&t, "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2")))?;
    Ok(())
}

/// Empty key and data, key length at the block edge, tag checking.
fn hmac_edges(c: &mut Checks) -> Result<(), Failure> {
    c.group("hmac edges");
    c.check(same(&hmac_sha256(b"", b""), "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"))?;
    let mut k = [0u8; 65];
    pattern(&mut k);
    c.check(same(&hmac_sha256(&k[..64], b"x"), "3a92153363b5af62dcd816b1c67d8bb765978639630a9815c66ef0f5868938d9"))?;
    c.check(same(&hmac_sha256(&k, b"x"), "abd235b487258b1d16adb9284e7d4996809c87323100ca8786f75c3fa320eeeb"))?;
    // A key over 64 bytes is the same as its SHA-256 (RFC 2104).
    c.check(hmac_sha256(&k, b"x") == hmac_sha256(&sha256(&k), b"x"))?;
    // Trailing zeros in a short key do not matter (the key is zero-padded) – known HMAC property.
    c.check(hmac_sha256(b"ab", b"m") == hmac_sha256(b"ab\0\0", b"m"))?;
    // verify: right tag, truncated tag, wrong byte anywhere, bad lengths.
    let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    let v = || HmacSha256::new(b"Jefe").chain(b"what do ya want for nothing?");
    c.check(v().verify(&tag).is_ok())?;
    c.check(v().verify(&tag[..MIN_TAG_LEN]).is_ok())?;
    let mut ok = true;
    for i in 0..32 {
        let mut bad = tag;
        bad[i] ^= 0x80;
        ok &= v().verify(&bad) == Err(Error::Mismatch);
    }
    c.check(ok)?;
    c.check(v().verify(&tag[..MIN_TAG_LEN - 1]) == Err(Error::InvalidLength))?;
    c.check(v().verify(&[]) == Err(Error::InvalidLength))?;
    let mut long = [0u8; 33];
    long[..32].copy_from_slice(&tag);
    c.check(v().verify(&long) == Err(Error::InvalidLength))?;
    // Another key or message gives another tag.
    c.check(hmac_sha256(b"Jefe", b"what do ya want for nothing!") != tag)?;
    c.check(hmac_sha256(b"Jeff", b"what do ya want for nothing?") != tag)?;
    Ok(())
}

/// RFC 5869 test cases 1-3 (PRK and OKM).
fn hkdf_vectors(c: &mut Checks) -> Result<(), Failure> {
    c.group("hkdf rfc5869");
    let mut salt = [0u8; 80];
    let mut ikm = [0u8; 80];
    let mut info = [0u8; 80];
    let mut okm = [0u8; 82];
    // Case 1.
    range(0, &mut salt[..13]);
    range(0xf0, &mut info[..10]);
    let prk = hkdf::extract(&salt[..13], &[0x0b; 22]);
    c.check(same(&prk, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"))?;
    c.check(hkdf::expand(&prk, &info[..10], &mut okm[..42]).is_ok())?;
    c.check(same(&okm[..42], "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))?;
    // Case 2: long inputs.
    range(0x00, &mut ikm);
    range(0x60, &mut salt);
    range(0xb0, &mut info);
    let prk = hkdf::extract(&salt, &ikm);
    c.check(same(&prk, "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"))?;
    c.check(hkdf::hkdf(&salt, &ikm, &info, &mut okm).is_ok())?;
    c.check(same(
        &okm,
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    ))?;
    // Case 3: empty salt and info.
    let prk = hkdf::extract(&[], &[0x0b; 22]);
    c.check(same(&prk, "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"))?;
    c.check(hkdf::expand(&prk, &[], &mut okm[..42]).is_ok())?;
    c.check(same(&okm[..42], "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"))?;
    // Empty salt = 32 zero bytes (RFC 5869 2.2).
    c.check(hkdf::extract(&[], b"ikm") == hkdf::extract(&[0u8; 32], b"ikm"))?;
    Ok(())
}

/// Output length limits and wrong parameters.
fn hkdf_edges(c: &mut Checks) -> Result<(), Failure> {
    c.group("hkdf limits");
    let mut big = [0u8; MAX_OUTPUT + 1];
    // Exactly 255 blocks: allowed, and the whole output is right.
    c.check(hkdf::hkdf(b"salt", b"ikm", b"info", &mut big[..MAX_OUTPUT]).is_ok())?;
    c.check(same(&sha256(&big[..MAX_OUTPUT]), "e3963f0e8b66c425fb6879cf9bdaf9aac0ffdbac3093b9857871bb35b0056dce"))?;
    // A shorter output is the start of the longer one.
    let mut short = [0u8; 42];
    c.check(hkdf::hkdf(b"salt", b"ikm", b"info", &mut short).is_ok() && short[..] == big[..42])?;
    // One byte more: refused, and the buffer is not touched.
    big.fill(0x5a);
    c.check(hkdf::hkdf(b"salt", b"ikm", b"info", &mut big) == Err(Error::OutputTooLong))?;
    let prk = hkdf::extract(b"salt", b"ikm");
    c.check(hkdf::expand(&prk, b"info", &mut big) == Err(Error::OutputTooLong))?;
    c.check(big.iter().all(|&b| b == 0x5a))?;
    // Empty output: allowed, nothing written.
    c.check(hkdf::hkdf(b"salt", b"ikm", b"info", &mut []).is_ok())?;
    // PRK shorter than 32 bytes: refused; 32 and longer: fine.
    c.check(hkdf::expand(&prk[..31], b"info", &mut short) == Err(Error::KeyTooShort))?;
    c.check(hkdf::expand(&[], b"info", &mut short) == Err(Error::KeyTooShort))?;
    let mut long_prk = [7u8; 64];
    long_prk[..32].copy_from_slice(&prk);
    c.check(hkdf::expand(&long_prk, b"info", &mut short).is_ok())?;
    // Other info -> other key.
    let mut other = [0u8; 42];
    c.check(hkdf::hkdf(b"salt", b"ikm", b"inf0", &mut other).is_ok() && other != short)?;
    Ok(())
}

const RFC_2_4_2_TEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
const RFC_A_2_2_TEXT: &[u8] = b"Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";

fn key_from(hex_key: &str) -> [u8; 32] {
    let mut k = [0u8; 32];
    unhex(hex_key, &mut k);
    k
}

fn nonce_from(hex_nonce: &str) -> [u8; 12] {
    let mut n = [0u8; 12];
    unhex(hex_nonce, &mut n);
    n
}

/// RFC 8439: the block function (2.3.2, A.1) and encryption (2.4.2, A.2).
fn chacha_vectors(c: &mut Checks) -> Result<(), Failure> {
    c.group("chacha20 vectors");
    let mut k = [0u8; 32];
    range(0, &mut k);
    let mut blk = [0u8; 64];
    chacha20::block(&k, 1, &nonce_from("000000090000004a00000000"), &mut blk);
    c.check(same(&blk, "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"))?;
    // 2.4.2: 114 bytes of text, counter 1.
    let mut buf = [0u8; 400];
    let t = &mut buf[..RFC_2_4_2_TEXT.len()];
    t.copy_from_slice(RFC_2_4_2_TEXT);
    c.check(chacha20::xor_stream(&k, 1, &nonce_from("000000000000004a00000000"), t).is_ok())?;
    c.check(same(t, "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"))?;
    // Decryption = the same operation.
    c.check(chacha20::xor_stream(&k, 1, &nonce_from("000000000000004a00000000"), t).is_ok() && t == RFC_2_4_2_TEXT)?;
    // A.1: test vectors 1-5 for the block function.
    let a1: [(&str, u32, &str, &str); 5] = [
        ("0000000000000000000000000000000000000000000000000000000000000000", 0, "000000000000000000000000", "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"),
        ("0000000000000000000000000000000000000000000000000000000000000000", 1, "000000000000000000000000", "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f"),
        ("0000000000000000000000000000000000000000000000000000000000000001", 1, "000000000000000000000000", "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0"),
        ("00ff000000000000000000000000000000000000000000000000000000000000", 2, "000000000000000000000000", "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096"),
        ("0000000000000000000000000000000000000000000000000000000000000000", 0, "000000000000000000000002", "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d"),
    ];
    for (key, ctr, nonce, want) in a1.iter() {
        chacha20::block(&key_from(key), *ctr, &nonce_from(nonce), &mut blk);
        c.check(same(&blk, want))?;
    }
    // A.2 test vector 2: 375 bytes (checked through the SHA-256 of the ciphertext).
    let t = &mut buf[..RFC_A_2_2_TEXT.len()];
    t.copy_from_slice(RFC_A_2_2_TEXT);
    c.check(chacha20::xor_stream(&key_from("0000000000000000000000000000000000000000000000000000000000000001"), 1, &nonce_from("000000000000000000000002"), t).is_ok())?;
    c.check(same(&t[..16], "a3fbf07df3fa2fde4f376ca23e827370"))?;
    c.check(same(&sha256(t), A_2_2_SHA))?;
    Ok(())
}

/// SHA-256 of the A.2 test vector 2 ciphertext (RFC 8439, also computed with Python).
const A_2_2_SHA: &str = "8eac94947838712fa057586d21640ecda364b38f811a40af7272d1e9556e6386";

/// SHA-256 of the pattern (byte i = i*7 + 3) XOR the stream (key 00..1f, nonce 01..0c,
/// counter 5) – computed with Python's `cryptography`.
const CHACHA_LENS: [(usize, &str); 9] = [
    (0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (1, "333e0a1e27815d0ceee55c473fe3dc93d56c63e3bee2b3b4aee8eed6d70191a3"),
    (63, "726214b5ddb99b657918ec4af5d987f1c5ed2c9a0aa204550b2cfbd0dcad1089"),
    (64, "8644e08681a7151e5bda7049df3612399685dc06c3f4f3b6be648d5a1f97bd6e"),
    (65, "ac63298322349a196d28f236b506f4fd1a6d0881e68d6af9982a2d5201bc415b"),
    (127, "ab87496ee8316ce6adf843a42c70c1eb6d9e3562db5d094d1b1c27963c6c3665"),
    (128, "954c40c3ce0ded13b8e0cc46bf514ececc6b77b70d50b58d8f2fb8dab115355f"),
    (129, "2cecb2164a4f313911f9879d68e8f79606f6646b62d501ffd9619ef4accaa7c6"),
    (1000, "c0a8d534a9bf94018a7165868bc3e81376b9ed3cfb914d03a6e99d6d65f712a0"),
];

/// Lengths around the block size, the last counter value, refusing a wrapping counter.
fn chacha_edges(c: &mut Checks) -> Result<(), Failure> {
    c.group("chacha20 edges");
    let mut k = [0u8; 32];
    range(0, &mut k);
    let n = nonce_from("0102030405060708090a0b0c");
    let lens = CHACHA_LENS;
    let mut buf = [0u8; 1000];
    for (len, want) in lens.iter() {
        let d = &mut buf[..*len];
        pattern(d);
        c.check(chacha20::xor_stream(&k, 5, &n, d).is_ok() && same(&sha256(d), want))?;
    }
    // Pieces: the stream from block 5 in two calls (5..6 and 7..) equals one call.
    let mut whole = [0u8; 256];
    pattern(&mut whole);
    let mut parts = whole;
    c.check(chacha20::xor_stream(&k, 5, &n, &mut whole).is_ok())?;
    c.check(chacha20::xor_stream(&k, 5, &n, &mut parts[..128]).is_ok() && chacha20::xor_stream(&k, 7, &n, &mut parts[128..]).is_ok() && parts == whole)?;
    // The last counter value: one block is fine, two would wrap.
    let mut blk = [0u8; 64];
    c.check(chacha20::xor_stream(&k, u32::MAX, &[0; 12], &mut blk).is_ok())?;
    c.check(same(&blk, "1ce0deb8925fccea2d5587e850054559edcbbeb1a6c8e1c02c1e89abba08b01cad6048fe5ab5242ed6befbef6b4040fcb666a5f3858d942a912c4e8800301a42"))?;
    let mut two = [7u8; 65];
    c.check(chacha20::xor_stream(&k, u32::MAX, &[0; 12], &mut two) == Err(Error::LengthOverflow) && two == [7u8; 65])?;
    c.check(chacha20::xor_stream(&k, u32::MAX, &[0; 12], &mut []).is_ok())?;
    Ok(())
}

/// The fast-key-erasure generator: exact output for a known seed, the key replaced on
/// every call, reseeding.
fn rng_checks(c: &mut Checks) -> Result<(), Failure> {
    c.group("rng");
    let mut seed = [0u8; 32];
    range(0, &mut seed);
    let mut r = KeyErasureRng::new(&seed);
    let mut out = [0u8; 100];
    r.fill(&mut out);
    c.check(same(&out, "2b23cce7a26023ab3f0eef693ac87f64258235eab1f7a32dc22762a0485b410c18b84231ade6a6d113615c61af434e27f8b1f3f5e1ad5b5cecf8fc122a35755c7208086dd1ee3c5d9d815824640e003c9ba0f65ede5d59ce0d2a4a7f31955acd42f22ddc"))?;
    let mut five = [0u8; 5];
    r.fill(&mut five);
    c.check(same(&five, "2d41a59c90"))?;
    r.reseed(b"fresh");
    let mut o = [0u8; 32];
    r.fill(&mut o);
    c.check(same(&o, "37a0a805278c330f2236bb5465bfbf9f11fb62c59aa530c97f6a43f47fe6640a"))?;
    // An empty request still replaces the key (and gives nothing).
    let mut a = KeyErasureRng::new(&seed);
    let mut b = KeyErasureRng::new(&seed);
    a.fill(&mut []);
    let (mut x, mut y) = ([0u8; 16], [0u8; 16]);
    a.fill(&mut x);
    b.fill(&mut y);
    c.check(x != y)?;
    // A long request is cut into pieces, each a call of its own (new key) – checked with
    // 64-byte pieces against separate calls.
    let mut c1 = KeyErasureRng::new(&seed);
    let mut c2 = KeyErasureRng::new(&seed);
    let (mut long, mut parts) = ([0u8; 200], [0u8; 200]);
    c1.fill_with_piece(&mut long, 64);
    for ch in parts.chunks_mut(64) {
        c2.fill(ch);
    }
    c.check(long == parts && c1.key_for_test() == c2.key_for_test())?;
    // Two calls never give the same bytes.
    let (mut p, mut q) = ([0u8; 64], [0u8; 64]);
    b.fill(&mut p);
    b.fill(&mut q);
    c.check(p != q)?;
    Ok(())
}

/// `wipe` on any length (also 0) zeroes everything.
fn wipe_checks(c: &mut Checks) -> Result<(), Failure> {
    c.group("wipe");
    let mut buf = [0u8; 4096];
    for len in [0usize, 1, 31, 32, 33, 4096] {
        for b in buf.iter_mut() {
            *b = 0xA5;
        }
        super::desocrypto::wipe(&mut buf[..len]);
        c.check(buf[..len].iter().all(|&b| b == 0) && buf[len..].iter().all(|&b| b == 0xA5))?;
    }
    let mut w = [u64::MAX; 5];
    super::desocrypto::wipe_words64(&mut w);
    c.check(w == [0; 5])?;
    Ok(())
}

fn key32(h: &str) -> [u8; 32] {
    let mut k = [0u8; 32];
    unhex(h, &mut k);
    k
}

/// RFC 8439 2.5.2 and the structure of A.3 #1, #5-#9 (expected values from Python).
fn poly_vectors(c: &mut Checks) -> Result<(), Failure> {
    c.group("poly1305 vectors");
    let k = key32("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    c.check(same(&poly1305::poly1305(&k, b"Cryptographic Forum Research Group"), "a8061dc1305136c6c22b8baf0c0127a9"))?;
    // In pieces = at once; verify accepts the tag and refuses a changed one.
    let mut p = Poly1305::new(&k);
    p.update(b"Cryptographic ");
    p.update(b"");
    p.update(b"Forum Research Group");
    c.check(same(&p.finish(), "a8061dc1305136c6c22b8baf0c0127a9"))?;
    let mut tag = [0u8; 16];
    unhex("a8061dc1305136c6c22b8baf0c0127a9", &mut tag);
    let mut p = Poly1305::new(&k);
    p.update(b"Cryptographic Forum Research Group");
    c.check(p.verify(&tag).is_ok())?;
    tag[15] ^= 1;
    let mut p = Poly1305::new(&k);
    p.update(b"Cryptographic Forum Research Group");
    c.check(p.verify(&tag) == Err(Error::Mismatch))?;
    let mut p = Poly1305::new(&k);
    p.update(b"Cryptographic Forum Research Group");
    c.check(p.verify(&tag[..15]) == Err(Error::Mismatch))?;
    // A.3 #1: zero key, 64 zero bytes.
    let mut m = [0u8; 256];
    c.check(same(&poly1305::poly1305(&[0; 32], &m[..64]), "00000000000000000000000000000000"))?;
    // #5: r = 2, msg ff*16 -> 3 (h reaches 2^130 + ... and wraps).
    let r2 = key32("0200000000000000000000000000000000000000000000000000000000000000");
    c.check(same(&poly1305::poly1305(&r2, &[0xff; 16]), "03000000000000000000000000000000"))?;
    // #6: r = 2, s = ff*16, msg 02 -> 3 (h + s carries out of 128 bits).
    let mut m6 = [0u8; 16];
    m6[0] = 2;
    c.check(same(&poly1305::poly1305(&key32("02000000000000000000000000000000ffffffffffffffffffffffffffffffff"), &m6), "03000000000000000000000000000000"))?;
    // #7, #8: r = 1, three blocks around 2^130 - 5.
    let r1 = key32("0100000000000000000000000000000000000000000000000000000000000000");
    m[..16].copy_from_slice(&[0xff; 16]);
    m[16] = 0xf0;
    m[17..32].copy_from_slice(&[0xff; 15]);
    m[32] = 0x11;
    m[33..48].copy_from_slice(&[0; 15]);
    c.check(same(&poly1305::poly1305(&r1, &m[..48]), "05000000000000000000000000000000"))?;
    m[16] = 0xfb;
    m[17..32].copy_from_slice(&[0xfe; 15]);
    m[32..48].copy_from_slice(&[0x01; 16]);
    c.check(same(&poly1305::poly1305(&r1, &m[..48]), "00000000000000000000000000000000"))?;
    // #9: r = 2, msg fd ff*15 -> fa ff*15 (h = p - ... after reduction).
    let mut m9 = [0xffu8; 16];
    m9[0] = 0xfd;
    c.check(same(&poly1305::poly1305(&r2, &m9), "faffffffffffffffffffffffffffffff"))?;
    // A pattern key over lengths around the block size.
    let mut pk = [0u8; 32];
    for (i, b) in pk.iter_mut().enumerate() {
        *b = (i as u32 * 13 + 7) as u8;
    }
    let mut long = [0u8; 1000];
    pattern(&mut long);
    for (len, want) in POLY_LENS.iter() {
        c.check(same(&poly1305::poly1305(&pk, &long[..*len]), want))?;
    }
    Ok(())
}

/// Python: the pattern message (byte i = i*7 + 3) under the key byte i = i*13 + 7.
const POLY_LENS: [(usize, &str); 13] = [
    (0, "d7e4f1fe0b1825323f4c596673808d9a"),
    (1, "f627694ac2286d8e852d72035a327778"),
    (15, "8f615a36a2a6e823246193b8338f9864"),
    (16, "cc826591634f0b956c91295c0347a264"),
    (17, "c47f392194cc28e85b0f05dc8a2dceb6"),
    (31, "d230ab5e752edaf168c2818fa713df79"),
    (32, "09697061b57a4374bc22abb60e88c88f"),
    (33, "043338b382f6608520ed0edd571db2f6"),
    (63, "263504faf64783e15efda1b0633a9db0"),
    (64, "3842943aee408f8341e2c5d6310bd9e4"),
    (65, "12fcf03054ed21b35bca4c0e2132ed4e"),
    (100, "6e155d384ae5aba2f58f42e6885ccbbd"),
    (1000, "291d147b27e60a79c87775a838c65ba8"),
];

/// Limbs at their maximum (every key bit the clamp allows, s = all ones, blocks of all
/// ones – the largest products and carries), and the final reduction around p.
fn poly_ranges(c: &mut Checks) -> Result<(), Failure> {
    c.group("poly1305 ranges");
    let kmax = [0xffu8; 32];
    let ones = [0xffu8; 256];
    c.check(same(&poly1305::poly1305(&kmax, &ones), "c30c8c6a3af35fc6645a7e3a51df3f04"))?;
    c.check(same(&poly1305::poly1305(&kmax, &ones[..17]), "7cfe7ff768f81f2763f8bf565df85f86"))?;
    c.check(same(&poly1305::poly1305(&kmax, &ones[..1]), "23feffef23f8ffef23f8ffef23f8ffef"))?;
    // The same 256 bytes fed one byte at a time (every carry path of the buffer).
    let mut p = Poly1305::new(&kmax);
    for b in ones.chunks(1) {
        p.update(b);
    }
    c.check(same(&p.finish(), "c30c8c6a3af35fc6645a7e3a51df3f04"))?;
    // Final reduction: (h mod p) mod 2^128 for h around p = 2^130 - 5 and the limits.
    for (h, want) in POLY_FREEZE.iter() {
        let mut hb = [0u8; 17];
        unhex(h, &mut hb);
        c.check(same(&poly1305::freeze_for_test(&hb), want))?;
    }
    Ok(())
}

/// Python: (h mod (2^130 - 5)) mod 2^128 – h as 17 little-endian bytes.
const POLY_FREEZE: [(&str, &str); 8] = [
    ("faffffffffffffffffffffffffffffff03", "faffffffffffffffffffffffffffffff"), // p - 1
    ("fbffffffffffffffffffffffffffffff03", "00000000000000000000000000000000"), // p
    ("fcffffffffffffffffffffffffffffff03", "01000000000000000000000000000000"), // p + 1
    ("ffffffffffffffffffffffffffffffff03", "04000000000000000000000000000000"), // 2^130 - 1
    ("0000000000000000000000000000000004", "05000000000000000000000000000000"), // 2^130
    ("ffffffffffffffffffffffffffffffff07", "09000000000000000000000000000000"), // 2^131 - 1
    ("0000000000000000000000000000000000", "00000000000000000000000000000000"), // 0
    ("f5ffffffffffffffffffffffffffffff07", "faffffffffffffffffffffffffffffff"), // 2p - 1
];

/// RFC 8439 2.8.2 (encryption and back) and lengths around the block sizes.
fn aead_vectors(c: &mut Checks) -> Result<(), Failure> {
    c.group("aead vectors");
    let mut k = [0u8; 32];
    range(0x80, &mut k);
    let n = nonce_from("070000004041424344454647");
    let mut aad = [0u8; 12];
    unhex("50515253c0c1c2c3c4c5c6c7", &mut aad);
    let mut buf = [0u8; 1000];
    let t = &mut buf[..RFC_2_4_2_TEXT.len()];
    t.copy_from_slice(RFC_2_4_2_TEXT);
    let tag = aead::seal(&k, &n, &aad, t);
    c.check(matches!(tag, Ok(tg) if same(&tg, "1ae10b594f09e26a7e902ecbd0600691")))?;
    c.check(same(&t[..16], "d31a8d34648e60db7b86afbc53ef7ec2") && same(&sha256(t)[..], AEAD_282_CT_SHA))?;
    let tag = tag.unwrap_or([0; 16]);
    c.check(aead::open(&k, &n, &aad, t, &tag).is_ok() && t == RFC_2_4_2_TEXT)?;
    // Lengths 0..1000, aad "header" (6 bytes: padding) and none.
    let mut ak = [0u8; 32];
    for (i, b) in ak.iter_mut().enumerate() {
        *b = (i as u32 * 11 + 5) as u8;
    }
    let an = nonce_from("000000000102030405060708");
    for (len, with_aad, ct_sha, want_tag) in AEAD_LENS.iter() {
        let a: &[u8] = if *with_aad { b"header" } else { b"" };
        let m = &mut buf[..*len];
        pattern(m);
        let tag = aead::seal(&ak, &an, a, m);
        c.check(matches!(tag, Ok(tg) if same(&tg, want_tag)) && same(&sha256(m), ct_sha))?;
        let tag = tag.unwrap_or([0; 16]);
        c.check(aead::open(&ak, &an, a, m, &tag).is_ok())?;
        let mut want = [0u8; 1000];
        pattern(&mut want[..*len]);
        c.check(m == &want[..*len])?;
    }
    Ok(())
}

/// SHA-256 of the RFC 8439 2.8.2 ciphertext (114 bytes, computed with Python).
const AEAD_282_CT_SHA: &str = "eaf0adc045b86e7b8107ed2d6a8c2466cfb1c1f1a943dd5d37c578ee75a06829";

/// Python `cryptography` ChaCha20Poly1305: (length, aad "header"?, SHA-256 of the
/// ciphertext, tag) for the pattern message, key byte i = i*11 + 5, nonce 00000000 01..08.
const AEAD_LENS: [(usize, bool, &str, &str); 18] = [
    (0, true, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "3a15a269de9fa0385b6fa22cee562c3d"),
    (0, false, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "15c019332f0abd145816dddb2034cf33"),
    (1, true, "30a5bfa58e128af9e5a4955725d8ad26d4d574a537b58b7dc6d357acad578572", "df216f5879f2276bb4955c80135317af"),
    (1, false, "30a5bfa58e128af9e5a4955725d8ad26d4d574a537b58b7dc6d357acad578572", "d36bdd0dd25f5bdd92ac2ef20eab6451"),
    (15, true, "f0c297c80b821dac88746348373b7bb9389727153a2cdc55bcc677531396b8d4", "a552feec9fffd095250458a452d3712d"),
    (15, false, "f0c297c80b821dac88746348373b7bb9389727153a2cdc55bcc677531396b8d4", "949c6ca2f86c0408041b2a164e2bbfcf"),
    (16, true, "b6d9e2d19079502e897f28db38cf3bc6e12846ca21e79f66c4798c78e5762886", "28e222f82b162b2c9bc268fe32442574"),
    (16, false, "b6d9e2d19079502e897f28db38cf3bc6e12846ca21e79f66c4798c78e5762886", "1c2c91ad84835e9e79d93a702e9c7216"),
    (17, true, "7e5f23ffab0205c184cb35dc054ca17b4768a5babde23373bc70dc46545a0d5a", "3534c9c20f9fe5b62b4be3f9428560a8"),
    (17, false, "7e5f23ffab0205c184cb35dc054ca17b4768a5babde23373bc70dc46545a0d5a", "1d48a329be8a484d4a6975d74b1a18ee"),
    (63, true, "d74ad6af975cd81a9fc9ed6b0f1dd80e60f084a16b7c05ccd1340e080a023c89", "bb2cf81c5fadbfd2a02a0889064ad06f"),
    (63, false, "d74ad6af975cd81a9fc9ed6b0f1dd80e60f084a16b7c05ccd1340e080a023c89", "d7089afe3b7739a35a97544a89493acd"),
    (64, true, "0f354e5f4bac32829b571be2e339419f1698a75a0a868b1ab604a59302895e8f", "90a4c8fd5aae96fa57ae622afb30cb41"),
    (64, false, "0f354e5f4bac32829b571be2e339419f1698a75a0a868b1ab604a59302895e8f", "a7806adf377810cb111bafeb7d30359f"),
    (65, true, "a5355571cd21f6c840312b1c38ed23457b1b1dd6e42d6fd012db66ad9bef4f9c", "8f687bd90db5aff7a8a4e2546e1346d0"),
    (65, false, "a5355571cd21f6c840312b1c38ed23457b1b1dd6e42d6fd012db66ad9bef4f9c", "37297d4b69c6f8995ff0b66e22618167"),
    (1000, true, "0d5cacd5975c407db388815d7d4c3a0e37c145ba137b4f4c3892a2fecc15d795", "4c4b3a78f74addeba3fc155b57fe46ec"),
    (1000, false, "0d5cacd5975c407db388815d7d4c3a0e37c145ba137b4f4c3892a2fecc15d795", "519f318c480740f7f77e05b44013e3d7"),
];

/// A wrong tag, aad, nonce, key or one flipped ciphertext bit (first, middle, last byte):
/// Err(Mismatch) and the buffer byte for byte as before; inside a larger array the bytes
/// before and after the slice stay untouched too.
fn aead_tamper(c: &mut Checks) -> Result<(), Failure> {
    c.group("aead tamper");
    let mut k = [0u8; 32];
    range(0x40, &mut k);
    let n = nonce_from("0a0b0c0d0e0f101112131415");
    let aad = b"associated";
    for len in [0usize, 1, 15, 16, 17, 63, 64, 65, 1000] {
        // The message sits in the middle of a larger array (guards of 0xEE on both sides).
        let mut arr = [0xEEu8; 1100];
        let (start, end) = (50, 50 + len);
        pattern(&mut arr[start..end]);
        let tag = match aead::seal(&k, &n, aad, &mut arr[start..end]) {
            Ok(t) => t,
            Err(_) => return c.check(false),
        };
        let sealed = arr;
        let mut bad_tag = tag;
        bad_tag[0] ^= 0x80;
        let mut bad_n = n;
        bad_n[11] ^= 1;
        let mut bad_k = k;
        bad_k[31] ^= 1;
        let cases: [(&[u8; 32], &[u8; 12], &[u8], &[u8; 16]); 4] = [(&k, &n, aad, &bad_tag), (&k, &n, b"associatee", &tag), (&k, &bad_n, aad, &tag), (&bad_k, &n, aad, &tag)];
        for (kk, nn, aa, tt) in cases.iter() {
            let r = aead::open(kk, nn, aa, &mut arr[start..end], tt);
            c.check(r == Err(Error::Mismatch) && arr == sealed)?;
        }
        // One ciphertext bit flipped at the start, the middle and the end.
        if len > 0 {
            for pos in [start, start + len / 2, end - 1] {
                arr[pos] ^= 0x01;
                let flipped = arr;
                let r = aead::open(&k, &n, aad, &mut arr[start..end], &tag);
                c.check(r == Err(Error::Mismatch) && arr == flipped)?;
                arr[pos] ^= 0x01;
            }
        }
        // The right tag opens it; the guards are still 0xEE.
        c.check(aead::open(&k, &n, aad, &mut arr[start..end], &tag).is_ok())?;
        let mut want = [0u8; 1000];
        pattern(&mut want[..len]);
        c.check(arr[start..end] == want[..len] && arr[..start].iter().all(|&b| b == 0xEE) && arr[end..].iter().all(|&b| b == 0xEE))?;
    }
    c.check(aead::MAX_LEN == (1u64 << 38) - 64)?;
    Ok(())
}

/// Field operations mod 2^255 - 19 on edge values (expected: Python `a * b % p`, ...).
fn x25519_field(c: &mut Checks) -> Result<(), Failure> {
    c.group("x25519 field");
    let get = |name: &str| FE_IN.iter().find(|(n, _)| *n == name).map(|(_, v)| key32(v)).unwrap_or([0; 32]);
    for (op, a, b, want) in FE_OPS.iter() {
        let fb = if *b == "-" { [0u8; 32] } else { get(b) };
        c.check(same(&x25519::field_for_test(*op, &get(a), &fb), want))?;
    }
    // cswap: 0 keeps, 1 swaps (both values canonical afterwards).
    let (a, b) = (get("two"), get("big"));
    let (a0, b0) = x25519::cswap_for_test(0, &a, &b);
    let (a1, b1) = x25519::cswap_for_test(1, &a, &b);
    c.check(a0 == a && b0 == b && a1 == b && b1 == a)?;
    Ok(())
}

const FE_IN: [(&str, &str); 7] = [
    ("one", "0100000000000000000000000000000000000000000000000000000000000000"),
    ("two", "0200000000000000000000000000000000000000000000000000000000000000"),
    ("pm1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    ("p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    ("t255m20", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    ("t255m1", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    ("big", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
];
const FE_OPS: [(u8, &str, &str, &str); 160] = [
    (0, "one", "one", "0100000000000000000000000000000000000000000000000000000000000000"),
    (3, "one", "one", "0200000000000000000000000000000000000000000000000000000000000000"),
    (4, "one", "one", "0000000000000000000000000000000000000000000000000000000000000000"),
    (0, "one", "two", "0200000000000000000000000000000000000000000000000000000000000000"),
    (3, "one", "two", "0300000000000000000000000000000000000000000000000000000000000000"),
    (4, "one", "two", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (0, "one", "pm1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (3, "one", "pm1", "0000000000000000000000000000000000000000000000000000000000000000"),
    (4, "one", "pm1", "0200000000000000000000000000000000000000000000000000000000000000"),
    (0, "one", "p", "0000000000000000000000000000000000000000000000000000000000000000"),
    (3, "one", "p", "0100000000000000000000000000000000000000000000000000000000000000"),
    (4, "one", "p", "0100000000000000000000000000000000000000000000000000000000000000"),
    (0, "one", "t255m20", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (3, "one", "t255m20", "0000000000000000000000000000000000000000000000000000000000000000"),
    (4, "one", "t255m20", "0200000000000000000000000000000000000000000000000000000000000000"),
    (0, "one", "t255m1", "1200000000000000000000000000000000000000000000000000000000000000"),
    (3, "one", "t255m1", "1300000000000000000000000000000000000000000000000000000000000000"),
    (4, "one", "t255m1", "dcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (0, "one", "big", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (3, "one", "big", "abaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (4, "one", "big", "4455555555555555555555555555555555555555555555555555555555555555"),
    (1, "one", "-", "0100000000000000000000000000000000000000000000000000000000000000"),
    (2, "one", "-", "0100000000000000000000000000000000000000000000000000000000000000"),
    (0, "two", "one", "0200000000000000000000000000000000000000000000000000000000000000"),
    (3, "two", "one", "0300000000000000000000000000000000000000000000000000000000000000"),
    (4, "two", "one", "0100000000000000000000000000000000000000000000000000000000000000"),
    (0, "two", "two", "0400000000000000000000000000000000000000000000000000000000000000"),
    (3, "two", "two", "0400000000000000000000000000000000000000000000000000000000000000"),
    (4, "two", "two", "0000000000000000000000000000000000000000000000000000000000000000"),
    (0, "two", "pm1", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (3, "two", "pm1", "0100000000000000000000000000000000000000000000000000000000000000"),
    (4, "two", "pm1", "0300000000000000000000000000000000000000000000000000000000000000"),
    (0, "two", "p", "0000000000000000000000000000000000000000000000000000000000000000"),
    (3, "two", "p", "0200000000000000000000000000000000000000000000000000000000000000"),
    (4, "two", "p", "0200000000000000000000000000000000000000000000000000000000000000"),
    (0, "two", "t255m20", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (3, "two", "t255m20", "0100000000000000000000000000000000000000000000000000000000000000"),
    (4, "two", "t255m20", "0300000000000000000000000000000000000000000000000000000000000000"),
    (0, "two", "t255m1", "2400000000000000000000000000000000000000000000000000000000000000"),
    (3, "two", "t255m1", "1400000000000000000000000000000000000000000000000000000000000000"),
    (4, "two", "t255m1", "ddffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (0, "two", "big", "5455555555555555555555555555555555555555555555555555555555555555"),
    (3, "two", "big", "acaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (4, "two", "big", "4555555555555555555555555555555555555555555555555555555555555555"),
    (1, "two", "-", "0400000000000000000000000000000000000000000000000000000000000000"),
    (2, "two", "-", "f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f"),
    (0, "pm1", "one", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (3, "pm1", "one", "0000000000000000000000000000000000000000000000000000000000000000"),
    (4, "pm1", "one", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (0, "pm1", "two", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (3, "pm1", "two", "0100000000000000000000000000000000000000000000000000000000000000"),
    (4, "pm1", "two", "eaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (0, "pm1", "pm1", "0100000000000000000000000000000000000000000000000000000000000000"),
    (3, "pm1", "pm1", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (4, "pm1", "pm1", "0000000000000000000000000000000000000000000000000000000000000000"),
    (0, "pm1", "p", "0000000000000000000000000000000000000000000000000000000000000000"),
    (3, "pm1", "p", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (4, "pm1", "p", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (0, "pm1", "t255m20", "0100000000000000000000000000000000000000000000000000000000000000"),
    (3, "pm1", "t255m20", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (4, "pm1", "t255m20", "0000000000000000000000000000000000000000000000000000000000000000"),
    (0, "pm1", "t255m1", "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (3, "pm1", "t255m1", "1100000000000000000000000000000000000000000000000000000000000000"),
    (4, "pm1", "t255m1", "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (0, "pm1", "big", "4355555555555555555555555555555555555555555555555555555555555555"),
    (3, "pm1", "big", "a9aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (4, "pm1", "big", "4255555555555555555555555555555555555555555555555555555555555555"),
    (1, "pm1", "-", "0100000000000000000000000000000000000000000000000000000000000000"),
    (2, "pm1", "-", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (0, "p", "one", "0000000000000000000000000000000000000000000000000000000000000000"),
    (3, "p", "one", "0100000000000000000000000000000000000000000000000000000000000000"),
    (4, "p", "one", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (0, "p", "two", "0000000000000000000000000000000000000000000000000000000000000000"),
    (3, "p", "two", "0200000000000000000000000000000000000000000000000000000000000000"),
    (4, "p", "two", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (0, "p", "pm1", "0000000000000000000000000000000000000000000000000000000000000000"),
    (3, "p", "pm1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (4, "p", "pm1", "0100000000000000000000000000000000000000000000000000000000000000"),
    (0, "p", "p", "0000000000000000000000000000000000000000000000000000000000000000"),
    (3, "p", "p", "0000000000000000000000000000000000000000000000000000000000000000"),
    (4, "p", "p", "0000000000000000000000000000000000000000000000000000000000000000"),
    (0, "p", "t255m20", "0000000000000000000000000000000000000000000000000000000000000000"),
    (3, "p", "t255m20", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (4, "p", "t255m20", "0100000000000000000000000000000000000000000000000000000000000000"),
    (0, "p", "t255m1", "0000000000000000000000000000000000000000000000000000000000000000"),
    (3, "p", "t255m1", "1200000000000000000000000000000000000000000000000000000000000000"),
    (4, "p", "t255m1", "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (0, "p", "big", "0000000000000000000000000000000000000000000000000000000000000000"),
    (3, "p", "big", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (4, "p", "big", "4355555555555555555555555555555555555555555555555555555555555555"),
    (1, "p", "-", "0000000000000000000000000000000000000000000000000000000000000000"),
    (0, "t255m20", "one", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (3, "t255m20", "one", "0000000000000000000000000000000000000000000000000000000000000000"),
    (4, "t255m20", "one", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (0, "t255m20", "two", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (3, "t255m20", "two", "0100000000000000000000000000000000000000000000000000000000000000"),
    (4, "t255m20", "two", "eaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (0, "t255m20", "pm1", "0100000000000000000000000000000000000000000000000000000000000000"),
    (3, "t255m20", "pm1", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (4, "t255m20", "pm1", "0000000000000000000000000000000000000000000000000000000000000000"),
    (0, "t255m20", "p", "0000000000000000000000000000000000000000000000000000000000000000"),
    (3, "t255m20", "p", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (4, "t255m20", "p", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (0, "t255m20", "t255m20", "0100000000000000000000000000000000000000000000000000000000000000"),
    (3, "t255m20", "t255m20", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (4, "t255m20", "t255m20", "0000000000000000000000000000000000000000000000000000000000000000"),
    (0, "t255m20", "t255m1", "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (3, "t255m20", "t255m1", "1100000000000000000000000000000000000000000000000000000000000000"),
    (4, "t255m20", "t255m1", "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (0, "t255m20", "big", "4355555555555555555555555555555555555555555555555555555555555555"),
    (3, "t255m20", "big", "a9aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (4, "t255m20", "big", "4255555555555555555555555555555555555555555555555555555555555555"),
    (1, "t255m20", "-", "0100000000000000000000000000000000000000000000000000000000000000"),
    (2, "t255m20", "-", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (0, "t255m1", "one", "1200000000000000000000000000000000000000000000000000000000000000"),
    (3, "t255m1", "one", "1300000000000000000000000000000000000000000000000000000000000000"),
    (4, "t255m1", "one", "1100000000000000000000000000000000000000000000000000000000000000"),
    (0, "t255m1", "two", "2400000000000000000000000000000000000000000000000000000000000000"),
    (3, "t255m1", "two", "1400000000000000000000000000000000000000000000000000000000000000"),
    (4, "t255m1", "two", "1000000000000000000000000000000000000000000000000000000000000000"),
    (0, "t255m1", "pm1", "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (3, "t255m1", "pm1", "1100000000000000000000000000000000000000000000000000000000000000"),
    (4, "t255m1", "pm1", "1300000000000000000000000000000000000000000000000000000000000000"),
    (0, "t255m1", "p", "0000000000000000000000000000000000000000000000000000000000000000"),
    (3, "t255m1", "p", "1200000000000000000000000000000000000000000000000000000000000000"),
    (4, "t255m1", "p", "1200000000000000000000000000000000000000000000000000000000000000"),
    (0, "t255m1", "t255m20", "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    (3, "t255m1", "t255m20", "1100000000000000000000000000000000000000000000000000000000000000"),
    (4, "t255m1", "t255m20", "1300000000000000000000000000000000000000000000000000000000000000"),
    (0, "t255m1", "t255m1", "4401000000000000000000000000000000000000000000000000000000000000"),
    (3, "t255m1", "t255m1", "2400000000000000000000000000000000000000000000000000000000000000"),
    (4, "t255m1", "t255m1", "0000000000000000000000000000000000000000000000000000000000000000"),
    (0, "t255m1", "big", "6600000000000000000000000000000000000000000000000000000000000000"),
    (3, "t255m1", "big", "bcaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (4, "t255m1", "big", "5555555555555555555555555555555555555555555555555555555555555555"),
    (1, "t255m1", "-", "4401000000000000000000000000000000000000000000000000000000000000"),
    (2, "t255m1", "-", "89e3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388e23"),
    (0, "big", "one", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (3, "big", "one", "abaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (4, "big", "one", "a9aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (0, "big", "two", "5455555555555555555555555555555555555555555555555555555555555555"),
    (3, "big", "two", "acaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (4, "big", "two", "a8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (0, "big", "pm1", "4355555555555555555555555555555555555555555555555555555555555555"),
    (3, "big", "pm1", "a9aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (4, "big", "pm1", "abaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (0, "big", "p", "0000000000000000000000000000000000000000000000000000000000000000"),
    (3, "big", "p", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (4, "big", "p", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (0, "big", "t255m20", "4355555555555555555555555555555555555555555555555555555555555555"),
    (3, "big", "t255m20", "a9aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (4, "big", "t255m20", "abaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (0, "big", "t255m1", "6600000000000000000000000000000000000000000000000000000000000000"),
    (3, "big", "t255m1", "bcaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (4, "big", "t255m1", "98aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a"),
    (0, "big", "big", "32c7711cc7711cc7711cc7711cc7711cc7711cc7711cc7711cc7711cc7711c47"),
    (3, "big", "big", "5455555555555555555555555555555555555555555555555555555555555555"),
    (4, "big", "big", "0000000000000000000000000000000000000000000000000000000000000000"),
    (1, "big", "-", "32c7711cc7711cc7711cc7711cc7711cc7711cc7711cc7711cc7711cc7711c47"),
    (2, "big", "-", "0d0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"),
];

/// RFC 7748 5.2 and 6.1 (expected values computed again with Python integers and the
/// `cryptography` library).
fn x25519_vectors(c: &mut Checks) -> Result<(), Failure> {
    c.group("x25519 vectors");
    let v = [
        ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
        ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
    ];
    for (s, u, want) in v.iter() {
        c.check(matches!(x25519::x25519(&key32(s), &key32(u)), Ok(r) if same(&r, want)))?;
    }
    // The top bit of u is ignored.
    let mut u = key32(v[0].1);
    u[31] |= 0x80;
    c.check(matches!(x25519::x25519(&key32(v[0].0), &u), Ok(r) if same(&r, v[0].2)))?;
    // Iterations: k = u = 9; (k, u) = (x25519(k, u), k).
    let mut k = [0u8; 32];
    k[0] = 9;
    let mut uu = k;
    for i in 1..=1000 {
        let r = match x25519::x25519(&k, &uu) {
            Ok(r) => r,
            Err(_) => return c.check(false),
        };
        uu = k;
        k = r;
        if i == 1 {
            c.check(same(&k, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"))?;
        }
    }
    c.check(same(&k, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"))?;
    // 6.1: Alice and Bob.
    let a = key32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let b = key32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let (pa, pb) = (x25519::public_key(&a), x25519::public_key(&b));
    c.check(same(&pa, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a") && same(&pb, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))?;
    let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    c.check(matches!(x25519::x25519(&a, &pb), Ok(r) if same(&r, shared)) && matches!(x25519::x25519(&b, &pa), Ok(r) if same(&r, shared)))?;
    Ok(())
}

/// The seven points of low order (0, 1, two of order 8, p - 1, p, p + 1), also with the
/// top bit set: the result is all zeros – always refused.
fn x25519_low_order(c: &mut Checks) -> Result<(), Failure> {
    c.group("x25519 low order");
    let low = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];
    let s = key32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    for u in low.iter() {
        let mut p = key32(u);
        c.check(x25519::x25519(&s, &p) == Err(Error::Mismatch))?;
        p[31] |= 0x80;
        c.check(x25519::x25519(&s, &p) == Err(Error::Mismatch))?;
    }
    Ok(())
}

/// Every combination of AES-NI / PCLMULQDQ: `Features::limit` drops what the CPU (or a
/// `desocrypto_no_simd` build) does not have, so on such a machine some are the software
/// path again – never an instruction the CPU lacks.
const COMBOS: [Features; 4] = [
    Features { aes: true, pclmul: true },
    Features { aes: true, pclmul: false },
    Features { aes: false, pclmul: true },
    Features::NONE,
];

fn key16(h: &str) -> [u8; 16] {
    let mut k = [0u8; 16];
    unhex(h, &mut k);
    k
}

/// FIPS-197 C.1 / A.1, the S-box (all 256), 1-5 blocks – each AES path.
fn aes_checks(c: &mut Checks) -> Result<(), Failure> {
    c.group("aes");
    let mut sb = [0u8; 256];
    unhex(AES_SBOX, &mut sb);
    let mut all = true;
    for x in 0..=255u8 {
        all &= aes::sbox_for_test(x) == sb[x as usize];
    }
    c.check(all)?;
    let a1 = Aes128::new(&key16("2b7e151628aed2a6abf7158809cf4f3c"), Features::NONE);
    let rk = a1.round_keys_for_test();
    let mut ok = true;
    for r in 0..11 {
        ok &= same(&rk[r], AES_A1[r]);
    }
    c.check(ok)?;
    let mut pk = [0u8; 16];
    for (i, b) in pk.iter_mut().enumerate() {
        *b = (i as u32 * 13 + 7) as u8;
    }
    for f in COMBOS.iter() {
        let a = Aes128::new(&key16("000102030405060708090a0b0c0d0e0f"), Features::limit(*f));
        let mut b = [key16("00112233445566778899aabbccddeeff")];
        a.encrypt_blocks(&mut b);
        c.check(same(&b[0], "69c4e0d86a7b0430d8cdb78070b4c55a"))?;
        // 1-5 blocks (bitsliced: a full group of 4, and 1, 2, 3 left over).
        let a = Aes128::new(&pk, Features::limit(*f));
        for (n, want) in AES_EB.iter() {
            let mut blocks = [[0u8; 16]; 5];
            let mut flat = [0u8; 80];
            pattern(&mut flat[..16 * n]);
            for j in 0..*n {
                blocks[j].copy_from_slice(&flat[16 * j..16 * j + 16]);
            }
            a.encrypt_blocks(&mut blocks[..*n]);
            for j in 0..*n {
                flat[16 * j..16 * j + 16].copy_from_slice(&blocks[j]);
            }
            c.check(same(&flat[..16 * n], want))?;
        }
    }
    Ok(())
}

/// GF(2^128) products and hashes, each multiplication.
fn ghash_checks(c: &mut Checks) -> Result<(), Failure> {
    c.group("ghash");
    let val = |n: &str| GH_VALS.iter().find(|(k, _)| *k == n).map(|(_, v)| key16(v)).unwrap_or([0; 16]);
    for f in COMBOS.iter() {
        let lim = Features::limit(*f);
        for (a, b, want) in GH_MUL.iter() {
            c.check(same(&ghash::mul_for_test(&val(a), &val(b), lim), want))?;
        }
        let h = val("pat");
        let mut data = [0u8; 1000];
        pattern(&mut data);
        for (len, want) in GH_LENS.iter() {
            let mut g = Ghash::new(&h, lim);
            g.update(&data[..*len]);
            c.check(same(&g.finish(), want))?;
        }
        // In pieces of 7 bytes = at once.
        let mut g = Ghash::new(&h, lim);
        for piece in data[..100].chunks(7) {
            g.update(piece);
        }
        c.check(same(&g.finish(), GH_LENS[7].1))?;
    }
    Ok(())
}

/// NIST Test Cases 1-4, lengths 0-95 / 1000 with guard bytes, aad 1 / 15 / 16 / 17.
fn gcm_vectors(c: &mut Checks) -> Result<(), Failure> {
    c.group("aes-gcm vectors");
    let k = key16("feffe9928665731c6d6a8f9467308308");
    let iv = nonce_from("cafebabefacedbaddecaf888");
    let mut p = [0u8; 64];
    unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", &mut p);
    let mut a = [0u8; 20];
    unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2", &mut a);
    let mut gk = [0u8; 16];
    for (i, b) in gk.iter_mut().enumerate() {
        *b = (i as u32 * 11 + 5) as u8;
    }
    let gn = nonce_from("000000000102030405060708");
    for f in COMBOS.iter() {
        // Test Case 1 and 2: the zero key and nonce.
        let z = AesGcm::with_features(&[0; 16], *f);
        c.check(matches!(z.seal(&[0; 12], b"", &mut []), Ok(t) if same(&t, "58e2fccefa7e3061367f1d57a4e7455a")))?;
        let mut b = [0u8; 16];
        let t = z.seal(&[0; 12], b"", &mut b);
        c.check(same(&b, "0388dace60b6a392f328c2b971b2fe78") && matches!(t, Ok(t) if same(&t, "ab6e47d42cec13bdf53a67b21257bddf")))?;
        // Test Case 3 (64 bytes) and 4 (60 bytes + 20 bytes of aad).
        let g = AesGcm::with_features(&k, *f);
        let mut b = p;
        let t = g.seal(&iv, b"", &mut b);
        c.check(same(&b, GCM_TC3_CT) && matches!(t, Ok(t) if same(&t, GCM_TC3_TAG)))?;
        let mut b = p;
        let t = g.seal(&iv, &a, &mut b[..60]);
        let mut want = [0u8; 64];
        unhex(GCM_TC3_CT, &mut want);
        c.check(b[..60] == want[..60] && b[60..] == p[60..] && matches!(t, Ok(t) if same(&t, GCM_TC4_TAG)))?;
        let t = t.unwrap_or([0; 16]);
        c.check(g.open(&iv, &a, &mut b[..60], &t).is_ok() && b == p)?;
        // Lengths 0-95 and 1000 in the middle of a larger array (guards of 0xEE).
        let g = AesGcm::with_features(&gk, *f);
        for (len, with_aad, ct_sha, want_tag) in GCM_LENS.iter() {
            let aad: &[u8] = if *with_aad { b"hdr" } else { b"" };
            let mut arr = [0xEEu8; 1100];
            let (s, e) = (37, 37 + len);
            pattern(&mut arr[s..e]);
            let t = g.seal(&gn, aad, &mut arr[s..e]);
            c.check(matches!(t, Ok(t) if same(&t, want_tag)) && same(&sha256(&arr[s..e]), ct_sha) && arr[..s].iter().all(|&x| x == 0xEE) && arr[e..].iter().all(|&x| x == 0xEE))?;
            let t = t.unwrap_or([0; 16]);
            let mut back = [0u8; 1000];
            pattern(&mut back[..*len]);
            c.check(g.open(&gn, aad, &mut arr[s..e], &t).is_ok() && arr[s..e] == back[..*len] && arr[e..].iter().all(|&x| x == 0xEE))?;
        }
        // aad of 1, 15, 16, 17 bytes (GHASH padding).
        for (alen, len, ct_sha, want_tag) in GCM_AAD.iter() {
            let mut aad = [0u8; 17];
            for (i, x) in aad.iter_mut().enumerate() {
                *x = (i as u32 * 3 + 1) as u8;
            }
            let mut m = [0u8; 17];
            pattern(&mut m[..*len]);
            let t = g.seal(&gn, &aad[..*alen], &mut m[..*len]);
            c.check(matches!(t, Ok(t) if same(&t, want_tag)) && same(&sha256(&m[..*len]), ct_sha))?;
        }
    }
    Ok(())
}

/// A wrong tag / aad / nonce / key / one ciphertext bit: Mismatch, the buffer (and the guard
/// bytes around it) unchanged – the hardware and the software path.
fn gcm_tamper(c: &mut Checks) -> Result<(), Failure> {
    c.group("aes-gcm tamper");
    let k = key16("404142434445464748494a4b4c4d4e4f");
    let mut bad_k = k;
    bad_k[15] ^= 1;
    let n = nonce_from("0a0b0c0d0e0f101112131415");
    let aad = b"associated";
    for f in [COMBOS[0], COMBOS[3]] {
        let g = AesGcm::with_features(&k, f);
        let gb = AesGcm::with_features(&bad_k, f);
        for len in [0usize, 1, 15, 16, 17, 63, 64, 65, 1000] {
            let mut arr = [0xEEu8; 1100];
            let (start, end) = (50, 50 + len);
            pattern(&mut arr[start..end]);
            let tag = match g.seal(&n, aad, &mut arr[start..end]) {
                Ok(t) => t,
                Err(_) => return c.check(false),
            };
            let sealed = arr;
            let mut bad_tag = tag;
            bad_tag[15] ^= 0x01;
            let mut bad_n = n;
            bad_n[0] ^= 0x80;
            let cases: [(&AesGcm, &[u8; 12], &[u8], &[u8; 16]); 4] = [(&g, &n, aad, &bad_tag), (&g, &n, b"associatee", &tag), (&g, &bad_n, aad, &tag), (&gb, &n, aad, &tag)];
            for (gg, nn, aa, tt) in cases.iter() {
                let r = gg.open(nn, aa, &mut arr[start..end], tt);
                c.check(r == Err(Error::Mismatch) && arr == sealed)?;
            }
            if len > 0 {
                for pos in [start, start + len / 2, end - 1] {
                    arr[pos] ^= 0x01;
                    let flipped = arr;
                    let r = g.open(&n, aad, &mut arr[start..end], &tag);
                    c.check(r == Err(Error::Mismatch) && arr == flipped)?;
                    arr[pos] ^= 0x01;
                }
            }
            c.check(g.open(&n, aad, &mut arr[start..end], &tag).is_ok())?;
            let mut want = [0u8; 1000];
            pattern(&mut want[..len]);
            c.check(arr[start..end] == want[..len] && arr[..start].iter().all(|&b| b == 0xEE) && arr[end..].iter().all(|&b| b == 0xEE))?;
        }
    }
    c.check(super::desocrypto::aes_gcm::MAX_LEN == (1u64 << 36) - 32)?;
    Ok(())
}

const AES_SBOX: &str = "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16";
const AES_A1: [&str; 11] = ["2b7e151628aed2a6abf7158809cf4f3c", "a0fafe1788542cb123a339392a6c7605", "f2c295f27a96b9435935807a7359f67f", "3d80477d4716fe3e1e237e446d7a883b", "ef44a541a8525b7fb671253bdb0bad00", "d4d1c6f87c839d87caf2b8bc11f915bc", "6d88a37a110b3efddbf98641ca0093fd", "4e54f70e5f5fc9f384a64fb24ea6dc4f", "ead27321b58dbad2312bf5607f8d292f", "ac7766f319fadc2128d12941575c006e", "d014f9a8c9ee2589e13f0cc8b6630ca6"];
const AES_EB: [(usize, &str); 5] = [
    (1, "d32b5fc90f11dd9f31d5ecc21e2772d1"),
    (2, "d32b5fc90f11dd9f31d5ecc21e2772d11169179d74dde7f1c3d38da54af79742"),
    (3, "d32b5fc90f11dd9f31d5ecc21e2772d11169179d74dde7f1c3d38da54af797426d9c3f482fc5dc23516bffc10809d8f6"),
    (4, "d32b5fc90f11dd9f31d5ecc21e2772d11169179d74dde7f1c3d38da54af797426d9c3f482fc5dc23516bffc10809d8f6cb96d44afd702b9c78a904d8abb851c6"),
    (5, "d32b5fc90f11dd9f31d5ecc21e2772d11169179d74dde7f1c3d38da54af797426d9c3f482fc5dc23516bffc10809d8f6cb96d44afd702b9c78a904d8abb851c695201b207590c8dc4132deb1dcba0a01"),
];
const GH_VALS: [(&str, &str); 5] = [("zero", "00000000000000000000000000000000"), ("one", "80000000000000000000000000000000"), ("ones", "ffffffffffffffffffffffffffffffff"), ("pat", "0b2845627f9cb9d6f3102d4a6784a1be"), ("pat2", "659acf04396ea3d80d4277ace1164b80")];
const GH_MUL: [(&str, &str, &str); 25] = [
    ("zero", "zero", "00000000000000000000000000000000"),
    ("zero", "one", "00000000000000000000000000000000"),
    ("zero", "ones", "00000000000000000000000000000000"),
    ("zero", "pat", "00000000000000000000000000000000"),
    ("zero", "pat2", "00000000000000000000000000000000"),
    ("one", "zero", "00000000000000000000000000000000"),
    ("one", "one", "80000000000000000000000000000000"),
    ("one", "ones", "ffffffffffffffffffffffffffffffff"),
    ("one", "pat", "0b2845627f9cb9d6f3102d4a6784a1be"),
    ("one", "pat2", "659acf04396ea3d80d4277ace1164b80"),
    ("ones", "zero", "00000000000000000000000000000000"),
    ("ones", "one", "ffffffffffffffffffffffffffffffff"),
    ("ones", "ones", "f402aaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    ("ones", "pat", "d2dfbdbdb89b8d49b0cc29362b485ea2"),
    ("ones", "pat2", "8c40be961314386926b23c9c1e08ed25"),
    ("pat", "zero", "00000000000000000000000000000000"),
    ("pat", "one", "0b2845627f9cb9d6f3102d4a6784a1be"),
    ("pat", "ones", "d2dfbdbdb89b8d49b0cc29362b485ea2"),
    ("pat", "pat", "b8f39f042ee8d4a70ccfb7982591ca6b"),
    ("pat", "pat2", "ee4565a16d728e90e29b0a298bb024c9"),
    ("pat2", "zero", "00000000000000000000000000000000"),
    ("pat2", "one", "659acf04396ea3d80d4277ace1164b80"),
    ("pat2", "ones", "8c40be961314386926b23c9c1e08ed25"),
    ("pat2", "pat", "ee4565a16d728e90e29b0a298bb024c9"),
    ("pat2", "pat2", "28f87ec6854b3be99dd1af1ae0a6d780"),
];
const GH_LENS: [(usize, &str); 9] = [
    (0, "00000000000000000000000000000000"),
    (1, "e632f19f4d014b94f62a60efbd511bc5"),
    (15, "08120413a18d3fd5b0a23330eba02319"),
    (16, "f34bd4c1b8b01e9be55ff0055837902f"),
    (17, "90b9d09fede6e575849050c324edb387"),
    (32, "13fbaa051df69f53127d94a5564a15f3"),
    (33, "56cd9bcf1fd1fad2eaaaa88c72eeac06"),
    (100, "ee715bc4383194fd544113d659de6931"),
    (1000, "67c5627b4f89d6e363af4bd3f07ad20d"),
];
const GCM_LENS: [(usize, bool, &str, &str); 194] = [
    (0, true, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "3103efa1eda16ee10b1e4938091cf800"),
    (0, false, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "99d0278f6f933c0d54875e9440ff722c"),
    (1, true, "cdb4ee2aea69cc6a83331bbe96dc2caa9a299d21329efb0336fc02a82e1839a8", "3c3fa3266531120abf79fe4d2bbb5bf3"),
    (1, false, "cdb4ee2aea69cc6a83331bbe96dc2caa9a299d21329efb0336fc02a82e1839a8", "c74555919588fbd3a8e57e616381bf5d"),
    (2, true, "ac16c41b6c7c63a4728540450912f0268bd7aa1db786f9d4c0e9e9af559ef22e", "1742c963c855bdd2a6d47ad0d29972c1"),
    (2, false, "ac16c41b6c7c63a4728540450912f0268bd7aa1db786f9d4c0e9e9af559ef22e", "ec383fd438ec540bb148fafc9aa3966f"),
    (3, true, "d0d44dcd7e8e03e73ae5bfb71ef097ec7cc43ec57ac2737a315856446cd9e4e8", "00ac0e4ab2af0ede33e8d676207cdc4f"),
    (3, false, "d0d44dcd7e8e03e73ae5bfb71ef097ec7cc43ec57ac2737a315856446cd9e4e8", "fbd6f8fd4216e7072474565a684638e1"),
    (4, true, "4b44844f6a77d7aec2731128ec2e7da6703abed246cd82a2678da69056c2b886", "1d878f034a0cc8eb341e3467aa900b01"),
    (4, false, "4b44844f6a77d7aec2731128ec2e7da6703abed246cd82a2678da69056c2b886", "e6fd79b4bab521322382b44be2aaefaf"),
    (5, true, "b7e0d812903b5b5d4b72045016bbd3c32bbd99ae5fb25a1b160f69581963dcb4", "38e0f7fd081ac67d6c725eba4bcfaa33"),
    (5, false, "b7e0d812903b5b5d4b72045016bbd3c32bbd99ae5fb25a1b160f69581963dcb4", "c39a014af8a32fa47beede9603f54e9d"),
    (6, true, "a26351397c214f205f69241c7e531393fdadb86525d2f2968357c8ba84969bab", "c64dd5994b6568321c9dd80a847e8a3f"),
    (6, false, "a26351397c214f205f69241c7e531393fdadb86525d2f2968357c8ba84969bab", "3d37232ebbdc81eb0b015826cc446e91"),
    (7, true, "8dcfd05caf9b0c1116cbe8560579cbfea3a4a80c83343731d0a21080202c3e0c", "b70dc9234db1a29aa2c6f5a38dbb2706"),
    (7, false, "8dcfd05caf9b0c1116cbe8560579cbfea3a4a80c83343731d0a21080202c3e0c", "4c773f94bd084b43b55a758fc581c3a8"),
    (8, true, "883191048c6ad4f8d819bbdc231e871abb2f3c33134a1339e95d1c64e1f95899", "f62440fb05151778a3898c72a5d4bb52"),
    (8, false, "883191048c6ad4f8d819bbdc231e871abb2f3c33134a1339e95d1c64e1f95899", "0d5eb64cf5acfea1b4150c5eedee5ffc"),
    (9, true, "af0e9e0bbc82e4cf0265d9e43b111d44e44343d55b65371f65a8327cc9212413", "68433cb26432585465710b65eac4720f"),
    (9, false, "af0e9e0bbc82e4cf0265d9e43b111d44e44343d55b65371f65a8327cc9212413", "9339ca05948bb18d72ed8b49a2fe96a1"),
    (10, true, "1ce8bb1d11d2aec8c9dbd4acb178744135437e0a2271d62b2ba196e0124fd150", "f7b27bfd3b54f9b02b93347a6a25e29f"),
    (10, false, "1ce8bb1d11d2aec8c9dbd4acb178744135437e0a2271d62b2ba196e0124fd150", "0cc88d4acbed10693c0fb456221f0631"),
    (11, true, "3040c302bc3ead3d681e0933789c45149af14e5b32f189a04aa189c12063be86", "e74e63df571f44831fa49b023a5ce017"),
    (11, false, "3040c302bc3ead3d681e0933789c45149af14e5b32f189a04aa189c12063be86", "1c349568a7a6ad5a08381b2e726604b9"),
    (12, true, "0f3f294716e9a720e414b63ae8f74c358f334be52f8a0af9d8dc74ae6f81aeb2", "100d1fda9fa1c07021fe132b83914de0"),
    (12, false, "0f3f294716e9a720e414b63ae8f74c358f334be52f8a0af9d8dc74ae6f81aeb2", "eb77e96d6f1829a936629307cbaba94e"),
    (13, true, "7a3251a74a1c666e323cd0444e96f6d1248fa314b1cf1db6ec21b5c8c0529316", "13b8ecd8ba9d50c560be838e41fc104f"),
    (13, false, "7a3251a74a1c666e323cd0444e96f6d1248fa314b1cf1db6ec21b5c8c0529316", "e8c21a6f4a24b91c772203a209c6f4e1"),
    (14, true, "dc65b19d72129f3f7be5cb53aea470abc492f35743f5a5da7ab3c020bef510e7", "c8ef45dcab40237cf3a7e66534f3c7fe"),
    (14, false, "dc65b19d72129f3f7be5cb53aea470abc492f35743f5a5da7ab3c020bef510e7", "3395b36b5bf9caa5e43b66497cc92350"),
    (15, true, "7afd30c78fb5d8d975cfbc4ddea2b744e135b9a3781e5391d0034d81eeb7b5b9", "b9a5026cd35c3ca082088a8fe36e76bb"),
    (15, false, "7afd30c78fb5d8d975cfbc4ddea2b744e135b9a3781e5391d0034d81eeb7b5b9", "42dff4db23e5d57995940aa3ab549215"),
    (16, true, "3052568cdf22dfaf9a9fdc02dff9c0f033c6fd681c6a9c32128e7e0ccfedadf1", "9be53e251b6c4b188e36b4e710912f1a"),
    (16, false, "3052568cdf22dfaf9a9fdc02dff9c0f033c6fd681c6a9c32128e7e0ccfedadf1", "609fc892ebd5a2c199aa34cb58abcbb4"),
    (17, true, "00469192b9ee4755dd704f65e70247a6e1ebcff25eaec876edfd4141aa72bd66", "a98a459d86be9073b2fd262959493e30"),
    (17, false, "00469192b9ee4755dd704f65e70247a6e1ebcff25eaec876edfd4141aa72bd66", "b04c504686e80dba9224ac7a1d9868b9"),
    (18, true, "8719fcc17e62f2eea0b7d0e5924a12a0ab52b0aabe1c2a9bf1f5f500be28d761", "d9f9d112cb2a6719d62e6ca618060239"),
    (18, false, "8719fcc17e62f2eea0b7d0e5924a12a0ab52b0aabe1c2a9bf1f5f500be28d761", "c03fc4c9cb7cfad0f6f7e6f55cd754b0"),
    (19, true, "948bc050fe3e7c4b7a04b5fa95f551cc36d34104e3fc85ee9544d87f47ac27e6", "8250484b4d24f013c1b8091728689227"),
    (19, false, "948bc050fe3e7c4b7a04b5fa95f551cc36d34104e3fc85ee9544d87f47ac27e6", "9b965d904d726ddae16183446cb9c4ae"),
    (20, true, "4bdd61ebaa6b6fd93dfe358c39e517c67dd32c85e13ebc79592aded4be63c65a", "1ac35fbe9f10e98c4c6083386c8c04eb"),
    (20, false, "4bdd61ebaa6b6fd93dfe358c39e517c67dd32c85e13ebc79592aded4be63c65a", "03054a659f4674456cb9096b285d5262"),
    (21, true, "a28678406c327ae35b9a4d3f6aada159896d79fb37438fc2319bad9845db3d9b", "9c5ad749881f215f0f1b154033855293"),
    (21, false, "a28678406c327ae35b9a4d3f6aada159896d79fb37438fc2319bad9845db3d9b", "859cc2928849bc962fc29f137754041a"),
    (22, true, "087388e5afc7d20424e70edbbce0c58502b642c6208752c28668bc3d50a6bd76", "1db00ac18694070e36043da0202d293e"),
    (22, false, "087388e5afc7d20424e70edbbce0c58502b642c6208752c28668bc3d50a6bd76", "04761f1a86c29ac716ddb7f364fc7fb7"),
    (23, true, "a00fe145b0b201d2796c17c2ac2dc38a2691025ec9be009feb1c752dd93cb192", "2c3ec67abe6e9d0bd34294966a4a81f1"),
    (23, false, "a00fe145b0b201d2796c17c2ac2dc38a2691025ec9be009feb1c752dd93cb192", "35f8d3a1be3800c2f39b1ec52e9bd778"),
    (24, true, "83ba0824d0e62c0efd348a1c3c4d2bc3b47dae5de9c671bd9384d81dc78d7401", "f93f6c8508a2bf00a78665575d113b41"),
    (24, false, "83ba0824d0e62c0efd348a1c3c4d2bc3b47dae5de9c671bd9384d81dc78d7401", "e0f9795e08f422c9875fef0419c06dc8"),
    (25, true, "57f82f148930a222e834dd879ee8f751b2efc732b8105d581b0e76020e011053", "dced3adcd9854ad82c2e2c9c762fd544"),
    (25, false, "57f82f148930a222e834dd879ee8f751b2efc732b8105d581b0e76020e011053", "c52b2f07d9d3d7110cf7a6cf32fe83cd"),
    (26, true, "5484e2a3b32ef0ae498f143919fe3083b3569da06796434a8ad24371e88dd0c7", "4a1eacf2e08beab0226da136f3753d0b"),
    (26, false, "5484e2a3b32ef0ae498f143919fe3083b3569da06796434a8ad24371e88dd0c7", "53d8b929e0dd777902b42b65b7a46b82"),
    (27, true, "d19fc6d1e910dc58e9b7c6be8a80763a6cb2928773de0ae6fac549eb96135548", "5dd09413cc5ef7825ffe35383caabde4"),
    (27, false, "d19fc6d1e910dc58e9b7c6be8a80763a6cb2928773de0ae6fac549eb96135548", "441681c8cc086a4b7f27bf6b787beb6d"),
    (28, true, "f0ec469c73bd3ceca6ab11c368274227ac1ff4fb24f981bd5599efd22d52906c", "8b418035a61ea99e9e1a99ebd0deb043"),
    (28, false, "f0ec469c73bd3ceca6ab11c368274227ac1ff4fb24f981bd5599efd22d52906c", "928795eea6483457bec313b8940fe6ca"),
    (29, true, "28b3216d0693e9352827cef57c2d518b14e6cfec8cdec23b8e3b8f5caf41da72", "62e336c4a9e48c87e8a481de04042f95"),
    (29, false, "28b3216d0693e9352827cef57c2d518b14e6cfec8cdec23b8e3b8f5caf41da72", "7b25231fa9b2114ec87d0b8d40d5791c"),
    (30, true, "a864ca55712c3153d2ffea365549e068cb4e07916d2ea4036b36f7ce8b5da4b7", "c28d02419d656e4991821b571eafb8d6"),
    (30, false, "a864ca55712c3153d2ffea365549e068cb4e07916d2ea4036b36f7ce8b5da4b7", "db4b179a9d33f380b15b91045a7eee5f"),
    (31, true, "fc5f0a4501038876c831dd5b7a5458063659967db71bdbcb9ccec88a6fdf61ea", "02fdfe14f3884256beb8c842d3c4ee7d"),
    (31, false, "fc5f0a4501038876c831dd5b7a5458063659967db71bdbcb9ccec88a6fdf61ea", "1b3bebcff3dedf9f9e6142119715b8f4"),
    (32, true, "d37019f64a53ba1d3b9e814bdd4ed40d4a355dedcfb5cb541d3b62b74223ce48", "df1c71cb4e4817387d800f5655c5e13e"),
    (32, false, "d37019f64a53ba1d3b9e814bdd4ed40d4a355dedcfb5cb541d3b62b74223ce48", "c6da64104e1e8af15d5985051114b7b7"),
    (33, true, "257f4ed3335dd149781ac435af4c5208623784a5459f50c9437199332bfa8fc4", "5c18c7272038990464963ab11f23c907"),
    (33, false, "257f4ed3335dd149781ac435af4c5208623784a5459f50c9437199332bfa8fc4", "e20000646128c2430b23596a5215bba4"),
    (34, true, "7f6243fc40bbb188531e70d7c5836e7a6922215bc297543b29bf9565a37c292b", "05afe77e3ab1773785aac3abcb146eab"),
    (34, false, "7f6243fc40bbb188531e70d7c5836e7a6922215bc297543b29bf9565a37c292b", "bbb7203d7ba12c70ea1fa07086221c08"),
    (35, true, "bbff67406c4a8619ce6dc403203aec06dee00de799ecc2470337a311859a385b", "617d0dd0c78668bf9bde0026536fd48c"),
    (35, false, "bbff67406c4a8619ce6dc403203aec06dee00de799ecc2470337a311859a385b", "df65ca93869633f8f46b63fd1e59a62f"),
    (36, true, "288be083c56dbb6e6392ba6119519184056666b78486ff3639f64b25d901a466", "6e9ac96df1e1f5dbb09ed54add597874"),
    (36, false, "288be083c56dbb6e6392ba6119519184056666b78486ff3639f64b25d901a466", "d0820e2eb0f1ae9cdf2bb691906f0ad7"),
    (37, true, "7952e82608a30b32bba4743d08cf5d19b8c7bef251911f3e734bdf2fe41b9e69", "75fd8545ae6fd997f9004ef317ea3a9d"),
    (37, false, "7952e82608a30b32bba4743d08cf5d19b8c7bef251911f3e734bdf2fe41b9e69", "cbe54206ef7f82d096b52d285adc483e"),
    (38, true, "7607027f058447c0e3e04da925e7b2ef8eaf8be05654ab8c434719d2bb2eecf1", "b008a66fc0bf3ba76ca4e82ea930f668"),
    (38, false, "7607027f058447c0e3e04da925e7b2ef8eaf8be05654ab8c434719d2bb2eecf1", "0e10612c81af60e003118bf5e40684cb"),
    (39, true, "65edf502f22357973022b603f89378fa702ab186d89981ad2ab3e323bc784479", "1e852d2af66d5b928759e06ce71d5d6d"),
    (39, false, "65edf502f22357973022b603f89378fa702ab186d89981ad2ab3e323bc784479", "a09dea69b77d00d5e8ec83b7aa2b2fce"),
    (40, true, "31908506e3ed5eacae759407b0656f8e3aff98507aa3037b9ba54fc77625bf45", "3f8adefd4198de5d64264fe0086c1780"),
    (40, false, "31908506e3ed5eacae759407b0656f8e3aff98507aa3037b9ba54fc77625bf45", "819219be0088851a0b932c3b455a6523"),
    (41, true, "9bba9178bc65a0d603dabd593914fce5ff49fcbb8fbcbed081316f20b44ee411", "f493654378bf3d39032aa7e05d86e73a"),
    (41, false, "9bba9178bc65a0d603dabd593914fce5ff49fcbb8fbcbed081316f20b44ee411", "4a8ba20039af667e6c9fc43b10b09599"),
    (42, true, "25fbff88fd84271d18a19a553984e6aaf322bc8718cde399953aa7794c520e30", "3706c50f48e99c1f20c666353d972f18"),
    (42, false, "25fbff88fd84271d18a19a553984e6aaf322bc8718cde399953aa7794c520e30", "891e024c09f9c7584f7305ee70a15dbb"),
    (43, true, "967adce28e5ca13198cd1bf93505e316d845081cd9f9ba1c9a00bcf08d4268c1", "b08475deb41b292d0f3cfce655a10f6e"),
    (43, false, "967adce28e5ca13198cd1bf93505e316d845081cd9f9ba1c9a00bcf08d4268c1", "0e9cb29df50b726a60899f3d18977dcd"),
    (44, true, "9844b42ed93f90256d9969111562305dd952031d20107ed339b196e504659725", "380dc6b044c6f821ce3857ca7b9cf356"),
    (44, false, "9844b42ed93f90256d9969111562305dd952031d20107ed339b196e504659725", "861501f305d6a366a18d341136aa81f5"),
    (45, true, "9a5930ed83e86ffb0b2935651126c226ebe6a9aea54fae8cfae28171dc1e6f45", "3adbb88bff1033b060869b2e4d1c07ab"),
    (45, false, "9a5930ed83e86ffb0b2935651126c226ebe6a9aea54fae8cfae28171dc1e6f45", "84c37fc8be0068f70f33f8f5002a7508"),
    (46, true, "162a0a6e25158a54164d91d2ac606301e0da54784b66a43ab252281eef4a776d", "535b5de1be870bf51ae7ffa97f4da0e6"),
    (46, false, "162a0a6e25158a54164d91d2ac606301e0da54784b66a43ab252281eef4a776d", "ed439aa2ff9750b275529c72327bd245"),
    (47, true, "cfb0c34c9efd51f198424ef814d68e8039f909523d6963376dbffc94d1770afd", "77fc2b0a3542f440667e8b42531adbca"),
    (47, false, "cfb0c34c9efd51f198424ef814d68e8039f909523d6963376dbffc94d1770afd", "c9e4ec497452af0709cbe8991e2ca969"),
    (48, true, "740bf82dfd560b5e1aeb8baf1c0fd1ddabbea00f5c89b09012bf50b1082cc455", "d4dc5671caf7ad1ad22ce55aa0920800"),
    (48, false, "740bf82dfd560b5e1aeb8baf1c0fd1ddabbea00f5c89b09012bf50b1082cc455", "6ac491328be7f65dbd998681eda47aa3"),
    (49, true, "4b67d7aacb1494b74762d1cbc645a7f944aeead7578bf84ae4c9a199fdd88ad4", "7cbc67c4dcf8ae8821ef5cb4d548dc26"),
    (49, false, "4b67d7aacb1494b74762d1cbc645a7f944aeead7578bf84ae4c9a199fdd88ad4", "7b29db3786838f21d139b42d0e96f6cc"),
    (50, true, "d758b2e757374ed82971c41b9c5842e18cd7024e3679cf5e66d68b172ce4b64f", "c950e64b713b8d13f3776230c1562aca"),
    (50, false, "d758b2e757374ed82971c41b9c5842e18cd7024e3679cf5e66d68b172ce4b64f", "cec55ab82b40acba03a18aa91a880020"),
    (51, true, "92c2c5f43ce4f627fc2f27ef517e10bf9b30e7ca5cc5deab2ca974273b2f3ca6", "c69adb37b2616e28f79f1b2c3ddba0b7"),
    (51, false, "92c2c5f43ce4f627fc2f27ef517e10bf9b30e7ca5cc5deab2ca974273b2f3ca6", "c10f67c4e81a4f810749f3b5e6058a5d"),
    (52, true, "3ae0c9ba4a1409bbe351bc22d7d2d8eaf9b3a5c773eccd0f73ae3da009c3cf1d", "5607e438505bcc160e43db00b3f7f5a0"),
    (52, false, "3ae0c9ba4a1409bbe351bc22d7d2d8eaf9b3a5c773eccd0f73ae3da009c3cf1d", "519258cb0a20edbffe9533996829df4a"),
    (53, true, "d366c44c6caef5ba4a04cb821162f3ee1c02d12bd6eac74b6e3bd66a4508ae55", "13603f9d9bcc6d10de5b5a9e93014f76"),
    (53, false, "d366c44c6caef5ba4a04cb821162f3ee1c02d12bd6eac74b6e3bd66a4508ae55", "14f5836ec1b74cb92e8db20748df659c"),
    (54, true, "5fc2fb5fed6e0f31b2bd4d3992147fc62f4017b71e63fbaca09dfbeabf41dd0e", "531ae27c397c7b045367979c48feed1c"),
    (54, false, "5fc2fb5fed6e0f31b2bd4d3992147fc62f4017b71e63fbaca09dfbeabf41dd0e", "548f5e8f63075aada3b17f059320c7f6"),
    (55, true, "f3ac3572d5b839e9c986f9eb44cf9fb9a14e3788c8b00a4e07c247a7944c6438", "92894938cfa1e4b52b79a122bd9efe73"),
    (55, false, "f3ac3572d5b839e9c986f9eb44cf9fb9a14e3788c8b00a4e07c247a7944c6438", "951cf5cb95dac51cdbaf49bb6640d499"),
    (56, true, "a096a0f2db2542b3d9f0a41264fbc978ffd63098e4df26479e7c591de3ec8b9d", "73d3c7288731874ab21402e26700060c"),
    (56, false, "a096a0f2db2542b3d9f0a41264fbc978ffd63098e4df26479e7c591de3ec8b9d", "74467bdbdd4aa6e342c2ea7bbcde2ce6"),
    (57, true, "9a67a9bcbe5d17623ce2fd2b987d4fda5d29009348f58f4fb83fac2288e7e0f4", "bd8cc63f0617c517ade31c71743a14c5"),
    (57, false, "9a67a9bcbe5d17623ce2fd2b987d4fda5d29009348f58f4fb83fac2288e7e0f4", "ba197acc5c6ce4be5d35f4e8afe43e2f"),
    (58, true, "6fa369e8bc84c2bac68b61ca5d333b27127c711f4c0fd787f9e5995fd824c1bf", "16d572e0e07965e82e348856bbf97a90"),
    (58, false, "6fa369e8bc84c2bac68b61ca5d333b27127c711f4c0fd787f9e5995fd824c1bf", "1140ce13ba024441dee260cf6027507a"),
    (59, true, "28329a997520cfb5cd9af15b5731bd1ed7d15bcb9bca0cccd73c5ca6213f6ddc", "b5f8da8428907f24e868834d74c6adab"),
    (59, false, "28329a997520cfb5cd9af15b5731bd1ed7d15bcb9bca0cccd73c5ca6213f6ddc", "b26d667772eb5e8d18be6bd4af188741"),
    (60, true, "f448822635b284e9ac97bdfaea62100b5780663eb8305748ff8c4857027a727a", "4b222495ebc49ef829b0633f4fb0be46"),
    (60, false, "f448822635b284e9ac97bdfaea62100b5780663eb8305748ff8c4857027a727a", "4cb79866b1bfbf51d9668ba6946e94ac"),
    (61, true, "9bd0ba651b69de69ebb38bfaec454eb2dc0ec81ce20c508ac5b9855a54221160", "94c07b50f5efc48c28f1a418e640fd40"),
    (61, false, "9bd0ba651b69de69ebb38bfaec454eb2dc0ec81ce20c508ac5b9855a54221160", "9355c7a3af94e525d8274c813d9ed7aa"),
    (62, true, "dbcb46b9600d1d4ed90b9637564af3fd0bbcf6c01d6e5083916def63164c623a", "94ba77ab2110a5144320c13677d5eedb"),
    (62, false, "dbcb46b9600d1d4ed90b9637564af3fd0bbcf6c01d6e5083916def63164c623a", "932fcb587b6b84bdb3f629afac0bc431"),
    (63, true, "deb149e0c921c397cecca12127c192a7d6ba15641349036798708a4c6471cb30", "14769caa47eaf5595b6e8ddd91752746"),
    (63, false, "deb149e0c921c397cecca12127c192a7d6ba15641349036798708a4c6471cb30", "13e320591d91d4f0abb865444aab0dac"),
    (64, true, "6c127fb48148e33401f3ced62c20fd0800838643186f3044769e29ca0d704dee", "754d8e13d6d096a7d2edf1ee00300629"),
    (64, false, "6c127fb48148e33401f3ced62c20fd0800838643186f3044769e29ca0d704dee", "72d832e08cabb70e223b1977dbee2cc3"),
    (65, true, "3b2139ed1b07ccde8febe1fbb2e3942cbcf3a044455d154ff42c3b2063344b2c", "b4a560fa0807d893886ff30b7dfd51bd"),
    (65, false, "3b2139ed1b07ccde8febe1fbb2e3942cbcf3a044455d154ff42c3b2063344b2c", "1693933c0d7933309475705562ce78ab"),
    (66, true, "827f6d54a345e6d7f71d7adf13102347f5e8c4be6374d06ed2f2c68db7c8157a", "13ae6a34cd24bc8e016dc419e8482ba5"),
    (66, false, "827f6d54a345e6d7f71d7adf13102347f5e8c4be6374d06ed2f2c68db7c8157a", "b19899f2c85a572d1d774747f77b02b3"),
    (67, true, "0d747036cfb997997ed250895888ee2023dd1e34007bfc38237de4cc21c739d5", "ae9eb0c34f16bff283de270c82440a54"),
    (67, false, "0d747036cfb997997ed250895888ee2023dd1e34007bfc38237de4cc21c739d5", "0ca843054a6854519fc4a4529d772342"),
    (68, true, "d35684495edc01f8f055eba9b0950c658a3a91d5ed4466d07286d4d37027c61c", "b4bfc9c782ccbe52e99a03331226ac39"),
    (68, false, "d35684495edc01f8f055eba9b0950c658a3a91d5ed4466d07286d4d37027c61c", "16893a0187b255f1f580806d0d15852f"),
    (69, true, "cd493a78cfc4838ec10f1aa5a9a75950b43eda2cdcd015006f9b1e89b07397fd", "d626589f511217cd46bb595074eca97f"),
    (69, false, "cd493a78cfc4838ec10f1aa5a9a75950b43eda2cdcd015006f9b1e89b07397fd", "7410ab59546cfc6e5aa1da0e6bdf8069"),
    (70, true, "5fe561ad5c7e9399f0539c5fa13ac3e618fba629eed97d3bc323978973c94ff2", "07eb7a6c9ff9a00f7ccd59fa9cb7cc8b"),
    (70, false, "5fe561ad5c7e9399f0539c5fa13ac3e618fba629eed97d3bc323978973c94ff2", "a5dd89aa9a874bac60d7daa48384e59d"),
    (71, true, "56b5c3ea9e16443f05e7e35e26b8e9c303acfde5243121dcc845b1b55d78da48", "ee98f1284b4ece8287c20062860c7d1f"),
    (71, false, "56b5c3ea9e16443f05e7e35e26b8e9c303acfde5243121dcc845b1b55d78da48", "4cae02ee4e3025219bd8833c993f5409"),
    (72, true, "2f9c6f8626dfdc051d46507c762c8e296832353d1001aee0ee42f182bb4303cb", "9c733ef8020084d271bd4fb9bd8c81b9"),
    (72, false, "2f9c6f8626dfdc051d46507c762c8e296832353d1001aee0ee42f182bb4303cb", "3e45cd3e077e6f716da7cce7a2bfa8af"),
    (73, true, "fd06335d5501f12e8067ad2324253dfe6de2b6b955cc2544f78b0de5a347b4d4", "41be1112c4d92ac29ac24f635e18c3ac"),
    (73, false, "fd06335d5501f12e8067ad2324253dfe6de2b6b955cc2544f78b0de5a347b4d4", "e388e2d4c1a7c16186d8cc3d412beaba"),
    (74, true, "be55e9da2c1f3ca9fec9dd0dac2012f2d5537343f65f583a27f2a4cd7d3bf357", "f432b4b5cd078a76dfdfd78234976ef4"),
    (74, false, "be55e9da2c1f3ca9fec9dd0dac2012f2d5537343f65f583a27f2a4cd7d3bf357", "56044773c87961d5c3c554dc2ba447e2"),
    (75, true, "bc8d5a0ae856ee2eb8824e1b5cc273ae6247074d68d138a808122324dacb3926", "fd4a898e74dacf44ff3665249c26dc0c"),
    (75, false, "bc8d5a0ae856ee2eb8824e1b5cc273ae6247074d68d138a808122324dacb3926", "5f7c7a4871a424e7e32ce67a8315f51a"),
    (76, true, "3197e64922c21ded49c7244ff38f2110d05851d702ffe33b87a09d0483b16b55", "14cd23fdeba60dbfc08612bfd2db47f1"),
    (76, false, "3197e64922c21ded49c7244ff38f2110d05851d702ffe33b87a09d0483b16b55", "b6fbd03beed8e61cdc9c91e1cde86ee7"),
    (77, true, "0aa211cdfc2ee1839b4de46f0345b6fd563893fcbab948bf56b2dd9b020010d9", "3cdd2f3aec88bcf249c647fe8a7230fd"),
    (77, false, "0aa211cdfc2ee1839b4de46f0345b6fd563893fcbab948bf56b2dd9b020010d9", "9eebdcfce9f6575155dcc4a0954119eb"),
    (78, true, "5fbe3930f87f9107bc2ef4a6e408dec4bf755fddcf300fadc98823fcda85c9d7", "2705edd9d0597195a45f237e31b7ad50"),
    (78, false, "5fbe3930f87f9107bc2ef4a6e408dec4bf755fddcf300fadc98823fcda85c9d7", "85331e1fd5279a36b845a0202e848446"),
    (79, true, "cb35e346aff93703f2ac884714b2f60b12103816d649328cfae575cfef2c3cd6", "494b62b7bcfee4a864b18f953803b37a"),
    (79, false, "cb35e346aff93703f2ac884714b2f60b12103816d649328cfae575cfef2c3cd6", "eb7d9171b9800f0b78ab0ccb27309a6c"),
    (80, true, "6bc4ab5c32b591eafd253561b8b879b6c5256a7ffc1c207414dfab76adef6c06", "c1176a0ae25908190cc4c725caca5e37"),
    (80, false, "6bc4ab5c32b591eafd253561b8b879b6c5256a7ffc1c207414dfab76adef6c06", "632199cce727e3ba10de447bd5f97721"),
    (81, true, "11141f50a19f2932655b9db780b8658921e73adce7d4f2fcef2547d65d7fd5d6", "30672d173227430cf12b8046b57d07ee"),
    (81, false, "11141f50a19f2932655b9db780b8658921e73adce7d4f2fcef2547d65d7fd5d6", "d713a5587803db5d1c350c4baa3f33e1"),
    (82, true, "ae359f2c610273c4b69a49ec59d5f078e39515ba049518c15bacc41e5c3268c4", "c6740b66758a5d5f1bb9fb2d1b0596a6"),
    (82, false, "ae359f2c610273c4b69a49ec59d5f078e39515ba049518c15bacc41e5c3268c4", "210083293faec50ef6a777200447a2a9"),
    (83, true, "dbd4b399b19c723478a797ac2b8700cc6def8dfc963e5ebaf7c6c8809dcc01f8", "18874ee14043f8b4fd22853cbcf71963"),
    (83, false, "dbd4b399b19c723478a797ac2b8700cc6def8dfc963e5ebaf7c6c8809dcc01f8", "fff3c6ae0a6760e5103c0931a3b52d6c"),
    (84, true, "8c29b4692a4b25883174565a2227bd2d37a585a5f08823c78f9a546869cf4e89", "1caf968b8777017ca40bb9588c18dafe"),
    (84, false, "8c29b4692a4b25883174565a2227bd2d37a585a5f08823c78f9a546869cf4e89", "fbdb1ec4cd53992d49153555935aeef1"),
    (85, true, "d0e663c21486319fdad1b0952570967d6a3c6d06a71e973b3948894fd56bee4c", "1dc9b16d12b3318700d4c919d7d61f3a"),
    (85, false, "d0e663c21486319fdad1b0952570967d6a3c6d06a71e973b3948894fd56bee4c", "fabd39225897a9d6edca4514c8942b35"),
    (86, true, "86071a7b071535c21f8ca09e3bc50b6593eff89b32db2f90a0a5fbde3a1052b2", "3fe49380fa086dc43587d41676ecd3d8"),
    (86, false, "86071a7b071535c21f8ca09e3bc50b6593eff89b32db2f90a0a5fbde3a1052b2", "d8901bcfb02cf595d899581b69aee7d7"),
    (87, true, "2fc6ed8cab885c8d93af43272cacefb8569f0b0a89abc2336c0c07289d92e123", "d22c573a280d4536e0f77733d3eb8938"),
    (87, false, "2fc6ed8cab885c8d93af43272cacefb8569f0b0a89abc2336c0c07289d92e123", "3558df756229dd670de9fb3ecca9bd37"),
    (88, true, "d1490bfb39f7f562169169103063a60c9afa777acf85f7999274444b85344f0a", "1940f11260a6e3fc947889707556b1dc"),
    (88, false, "d1490bfb39f7f562169169103063a60c9afa777acf85f7999274444b85344f0a", "fe34795d2a827bad7966057d6a1485d3"),
    (89, true, "b3f67af9928535352b435268db550a4ba15c2af9ec838b76a907a36bc7e195fd", "c96f36ae1e7e1de780a07740f8ff3bf1"),
    (89, false, "b3f67af9928535352b435268db550a4ba15c2af9ec838b76a907a36bc7e195fd", "2e1bbee1545a85b66dbefb4de7bd0ffe"),
    (90, true, "ab70a11d79cb925c726c214c4c6bf3a9c548bd13bd954c054116c71e9c72d66a", "f505412f6daf4202f5900d91442d51b7"),
    (90, false, "ab70a11d79cb925c726c214c4c6bf3a9c548bd13bd954c054116c71e9c72d66a", "1271c960278bda53188e819c5b6f65b8"),
    (91, true, "36b662c778b6f36646f6366a91ebd61e802b9faef3bb4eda454d4c8d4a64f713", "1620b9640cd2e7303a6d688065eaeebf"),
    (91, false, "36b662c778b6f36646f6366a91ebd61e802b9faef3bb4eda454d4c8d4a64f713", "f154312b46f67f61d773e48d7aa8dab0"),
    (92, true, "afb02904fa6cf59c41c5f99317cc31abdc1bd97297855c98776c11d51d5921b7", "fcdfb26e1b0c590cfbabaea2b51df277"),
    (92, false, "afb02904fa6cf59c41c5f99317cc31abdc1bd97297855c98776c11d51d5921b7", "1bab3a215128c15d16b522afaa5fc678"),
    (93, true, "acd72daa820bb936c86e6160ad38b346dfdd98c272b053e241752a53a045dde0", "15ccc203db835187faea98b79bb1b908"),
    (93, false, "acd72daa820bb936c86e6160ad38b346dfdd98c272b053e241752a53a045dde0", "f2b84a4c91a7c9d617f414ba84f38d07"),
    (94, true, "ecd22d3fec142e38c828811c5823d1be295960d7b7f29f8da37edcefb0faed9a", "4ab0778cfda1f5f32a74039fb862d5bd"),
    (94, false, "ecd22d3fec142e38c828811c5823d1be295960d7b7f29f8da37edcefb0faed9a", "adc4ffc3b7856da2c76a8f92a720e1b2"),
    (95, true, "de8fb732bc6a09ae519d2b4124e2e003340f2ef80561b8dec3e11f1c0f8501cb", "8422264ca00797cdb38dd7743ff49b5f"),
    (95, false, "de8fb732bc6a09ae519d2b4124e2e003340f2ef80561b8dec3e11f1c0f8501cb", "6356ae03ea230f9c5e935b7920b6af50"),
    (1000, true, "35891f50c637e90644c60f799f6e410a695d43816294d0f65be2876deaac5bc9", "308668a44f075dfb8c51e36e2b239725"),
    (1000, false, "35891f50c637e90644c60f799f6e410a695d43816294d0f65be2876deaac5bc9", "b75c2421174b77644c88e19b0ac9391c"),
];
const GCM_AAD: [(usize, usize, &str, &str); 12] = [
    (1, 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "f286a4a4b4f560751b09e594c0cddc7b"),
    (1, 16, "3052568cdf22dfaf9a9fdc02dff9c0f033c6fd681c6a9c32128e7e0ccfedadf1", "7657a9ace614dd84e886f54b089d2423"),
    (1, 17, "00469192b9ee4755dd704f65e70247a6e1ebcff25eaec876edfd4141aa72bd66", "018a8b93e93258eab3cb0d7696dcd3a5"),
    (15, 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "00bd58cc1d1c27e3898e95dd2a27232d"),
    (15, 16, "3052568cdf22dfaf9a9fdc02dff9c0f033c6fd681c6a9c32128e7e0ccfedadf1", "65b2ec37cadf6f5789c841e632ac810a"),
    (15, 17, "00469192b9ee4755dd704f65e70247a6e1ebcff25eaec876edfd4141aa72bd66", "e7cb573a249faf132adc11db5484aaaf"),
    (16, 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "b9f9b457e43eed1e4961a9824071a34f"),
    (16, 16, "3052568cdf22dfaf9a9fdc02dff9c0f033c6fd681c6a9c32128e7e0ccfedadf1", "9cfafa8594615cf779341d4d5f1a093a"),
    (16, 17, "00469192b9ee4755dd704f65e70247a6e1ebcff25eaec876edfd4141aa72bd66", "f9521007a9ce9f509eb0e9dcd6832f10"),
    (17, 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "cd4d928f5f370b667d33967076939a35"),
    (17, 16, "3052568cdf22dfaf9a9fdc02dff9c0f033c6fd681c6a9c32128e7e0ccfedadf1", "4cd58e36e3d28e3f5cde129872a5c347"),
    (17, 17, "00469192b9ee4755dd704f65e70247a6e1ebcff25eaec876edfd4141aa72bd66", "8609a1f11db04dd9aa2176ee20e608d7"),
];
const GCM_TC3_CT: &str = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985";
const GCM_TC3_TAG: &str = "4d5c2af327cd64a62cf35abd2ba6fab4";
const GCM_TC4_TAG: &str = "5bc94fbc3221a5db94fae95ae7121a47";


fn misc(c: &mut Checks) -> Result<(), Failure> {
    c.group("helpers");
    let mut out = [0u8; 64];
    c.check(hex(&sha256(b"abc"), &mut out) == Ok("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))?;
    c.check(hex(&[0x00, 0xff], &mut out[..4]) == Ok("00ff"))?;
    c.check(hex(&[1, 2, 3], &mut out[..5]) == Err(Error::BufferTooSmall))?;
    c.check(hex(&[], &mut []) == Ok(""))?;
    c.check(equal_ct(b"abc", b"abc") && !equal_ct(b"abc", b"abd") && !equal_ct(b"abc", b"ab") && equal_ct(b"", b""))?;
    Ok(())
}

// ---- SHA-384/512, generic HMAC/HKDF, bignum, RSA, ECDSA (DeSoCrypto 0.5.0) ----

/// Hex into `buf`, the bytes as a slice.
fn bytes<'a>(h: &str, buf: &'a mut [u8]) -> &'a [u8] {
    let n = unhex(h, buf);
    &buf[..n]
}

fn sha512_all(c: &mut Checks) -> Result<(), Failure> {
    c.group("sha384/512 vectors");
    c.check(same(&sha384(b"abc"), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"))?;
    c.check(same(&sha512(b"abc"), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"))?;
    c.check(same(&sha384(b""), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"))?;
    c.check(same(&sha512(b""), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"))?;
    let m896: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    c.check(same(&sha384(m896), "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"))?;
    c.check(same(&sha512(m896), "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"))?;
    let a = [b'a'; 1000];
    let (mut h3, mut h5) = (Sha384::new(), Sha512::new());
    for _ in 0..1000 {
        h3.update(&a);
        h5.update(&a);
        h5.update(&[]);
    }
    c.check(h3.finish().is_ok_and(|d| same(&d, "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985")))?;
    c.check(h5.finish().is_ok_and(|d| same(&d, "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b")))?;

    c.group("sha384/512 edges");
    let mut buf = [0u8; 1000];
    pattern(&mut buf);
    for &(n, w384, w512) in SHA512_EDGES {
        let msg = &buf[..n];
        c.check(same(&sha384(msg), w384) && same(&sha512(msg), w512))?;
        let (mut a, mut b) = (Sha384::new(), Sha512::new());
        for byte in msg {
            a.update(core::slice::from_ref(byte));
            b.update(core::slice::from_ref(byte));
        }
        c.check(a.finish().is_ok_and(|d| same(&d, w384)) && b.finish().is_ok_and(|d| same(&d, w512)))?;
        // The run-time choice gives the same.
        c.check(same(HashAlg::Sha384.digest(msg).as_bytes(), w384) && same(HashAlg::Sha512.digest(msg).as_bytes(), w512))?;
    }
    let msg = &buf[..300];
    let whole = sha512(msg);
    let mut ok = true;
    for i in 0..=msg.len() {
        let mut h = Sha512::new();
        h.update(&msg[..i]);
        h.update(&msg[i..]);
        ok &= h.finish() == Ok(whole);
    }
    c.check(ok)?;
    c.check(same(HashAlg::Sha256.digest(b"abc").as_bytes(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))?;
    c.check(HashAlg::Sha256.out_len() == 32 && HashAlg::Sha384.out_len() == 48 && HashAlg::Sha512.out_len() == 64)?;

    c.group("sha512 length limit");
    let mut h = Sha512::new();
    h.assume_length(u64::MAX - 3);
    h.update(b"abc");
    c.check(h.finish().is_ok())?;
    let mut h = Sha512::new();
    h.assume_length(u64::MAX - 3);
    h.update(b"abcd");
    c.check(h.finish() == Err(Error::LengthOverflow))?;
    let mut h = Sha384::new();
    h.assume_length(u64::MAX);
    h.update(b"x");
    h.update(b"");
    c.check(h.finish() == Err(Error::LengthOverflow))?;
    Ok(())
}

fn hmac_hkdf_generic(c: &mut Checks) -> Result<(), Failure> {
    c.group("hmac sha384/512 rfc4231");
    let k6 = [0xaau8; 131];
    let mut k4 = [0u8; 25];
    range(1, &mut k4);
    let msgs: [(&[u8], &[u8]); 7] = [
        (&[0x0b; 20], b"Hi There"),
        (b"Jefe", b"what do ya want for nothing?"),
        (&[0xaa; 20], &[0xdd; 50]),
        (&k4, &[0xcd; 50]),
        (&[0x0c; 20], b"Test With Truncation"),
        (&k6, b"Test Using Larger Than Block-Size Key - Hash Key First"),
        (&k6, b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."),
    ];
    for (i, (k, m)) in msgs.iter().enumerate() {
        let (w384, w512) = HMAC_4231[i];
        let t384 = Hmac::<Sha384>::new(k).chain(m).finish();
        let t512 = Hmac::<Sha512>::new(k).chain(m).finish();
        let n = if i == 4 { 16 } else { 64 };
        c.check(t384.is_ok_and(|t| same(&t.as_bytes()[..n.min(48)], w384)))?;
        c.check(t512.is_ok_and(|t| same(&t.as_bytes()[..n], w512)))?;
    }
    // Streamed in uneven pieces.
    let mut m = Hmac::<Sha512>::new(&k6);
    for piece in msgs[6].1.chunks(17) {
        m.update(piece);
    }
    c.check(m.finish().is_ok_and(|t| same(t.as_bytes(), HMAC_4231[6].1)))?;

    c.group("hmac generic");
    let mut k = [0u8; 129];
    pattern(&mut k);
    for &(n, w384, w512) in HMAC_512_EDGES.iter() {
        c.check(Hmac::<Sha384>::new(&k[..n]).chain(b"x").finish().is_ok_and(|t| same(t.as_bytes(), w384)))?;
        c.check(Hmac::<Sha512>::new(&k[..n]).chain(b"x").finish().is_ok_and(|t| same(t.as_bytes(), w512)))?;
    }
    // A key over the 128-byte block = its hash.
    let hk = sha512(&k);
    c.check(Hmac::<Sha512>::new(&k).chain(b"m").finish().is_ok_and(|a| Hmac::<Sha512>::new(&hk).chain(b"m").finish().is_ok_and(|b| a.as_bytes() == b.as_bytes())))?;
    // The generic SHA-256 is the old HmacSha256.
    c.check(Hmac::<Sha256>::new(b"Jefe").chain(b"what do ya want for nothing?").finish().is_ok_and(|t| t.as_bytes() == hmac_sha256(b"Jefe", b"what do ya want for nothing?")))?;
    // verify: full, truncated to half the hash (SHA-384: 24), one byte shorter, too long, wrong byte.
    let tag = Hmac::<Sha384>::new(b"k").chain(b"m").finish().unwrap_or_else(|_| HashAlg::Sha384.digest(b""));
    let v = || Hmac::<Sha384>::new(b"k").chain(b"m");
    c.check(Hmac::<Sha256>::MIN_TAG_LEN == 16 && Hmac::<Sha384>::MIN_TAG_LEN == 24 && Hmac::<Sha512>::MIN_TAG_LEN == 32)?;
    c.check(v().verify(tag.as_bytes()).is_ok() && v().verify(&tag.as_bytes()[..24]).is_ok())?;
    c.check(v().verify(&tag.as_bytes()[..23]) == Err(Error::InvalidLength))?;
    c.check(v().verify(&tag.as_bytes()[..16]) == Err(Error::InvalidLength))?;
    // SHA-512: 32 bytes (half) accepted, 31 refused, 64 accepted, 65 refused.
    let t5 = Hmac::<Sha512>::new(b"k").chain(b"m").finish().unwrap_or_else(|_| HashAlg::Sha512.digest(b""));
    let v5 = || Hmac::<Sha512>::new(b"k").chain(b"m");
    c.check(v5().verify(t5.as_bytes()).is_ok() && v5().verify(&t5.as_bytes()[..32]).is_ok())?;
    c.check(v5().verify(&t5.as_bytes()[..31]) == Err(Error::InvalidLength))?;
    let mut l5 = [0u8; 65];
    l5[..64].copy_from_slice(t5.as_bytes());
    c.check(v5().verify(&l5) == Err(Error::InvalidLength))?;
    // SHA-256 generic = HmacSha256: 16 accepted, 15 refused.
    let t2 = hmac_sha256(b"k", b"m");
    c.check(Hmac::<Sha256>::new(b"k").chain(b"m").verify(&t2[..16]).is_ok())?;
    c.check(Hmac::<Sha256>::new(b"k").chain(b"m").verify(&t2[..15]) == Err(Error::InvalidLength))?;
    let mut long = [0u8; 49];
    long[..48].copy_from_slice(tag.as_bytes());
    c.check(v().verify(&long) == Err(Error::InvalidLength))?;
    let mut bad = [0u8; 48];
    bad.copy_from_slice(tag.as_bytes());
    bad[47] ^= 1;
    c.check(v().verify(&bad) == Err(Error::Mismatch))?;
    // The length limit passes through the generic HMAC.
    let mut h = Sha512::new();
    h.assume_length(u64::MAX);
    h.update(b"x");
    c.check(h.finish() == Err(Error::LengthOverflow))?;

    c.group("hkdf sha384/512");
    let mut salt = [0u8; 13];
    range(0, &mut salt);
    let mut info = [0u8; 10];
    range(0xf0, &mut info);
    let mut okm = [0u8; 42];
    for (i, &(_, wprk, wokm)) in HKDF_512.iter().enumerate() {
        if i == 0 {
            let prk = hkdf::extract_with::<Sha384>(&salt, &[0x0b; 22]);
            c.check(same(prk.as_bytes(), wprk))?;
            c.check(hkdf::expand_with::<Sha384>(prk.as_bytes(), &info, &mut okm).is_ok() && same(&okm, wokm))?;
        } else {
            let prk = hkdf::extract_with::<Sha512>(&salt, &[0x0b; 22]);
            c.check(same(prk.as_bytes(), wprk))?;
            c.check(hkdf::hkdf_with::<Sha512>(&salt, &[0x0b; 22], &info, &mut okm).is_ok() && same(&okm, wokm))?;
        }
    }
    let mut big = [0u8; 255 * 48 + 1];
    c.check(hkdf::hkdf_with::<Sha384>(b"salt", b"ikm", b"info", &mut big[..255 * 48]).is_ok())?;
    c.check(same(&sha256(&big[..255 * 48]), HKDF_384_MAX_SHA256))?;
    c.check(hkdf::hkdf_with::<Sha384>(b"salt", b"ikm", b"info", &mut big) == Err(Error::OutputTooLong))?;
    let prk = hkdf::extract_with::<Sha384>(b"salt", b"ikm");
    c.check(hkdf::expand_with::<Sha384>(&prk.as_bytes()[..47], b"info", &mut okm) == Err(Error::KeyTooShort))?;
    let mut o50 = [0u8; 50];
    c.check(hkdf::hkdf_with::<Sha384>(b"", b"ikm", b"info", &mut o50).is_ok() && same(&o50, HKDF_384_EMPTY_SALT))?;
    // The SHA-256 forms are the generic SHA-256.
    let mut a = [0u8; 40];
    let mut b = [0u8; 40];
    c.check(hkdf::hkdf(b"s", b"i", b"n", &mut a).is_ok() && hkdf::hkdf_with::<Sha256>(b"s", b"i", b"n", &mut b).is_ok() && a == b)?;
    Ok(())
}

fn bignum_checks(c: &mut Checks) -> Result<(), Failure> {
    c.group("bignum");
    // Moduli that are refused: empty, even, leading zero byte, 1, too long.
    c.check(Modulus::<4>::new(&[]).is_err())?;
    c.check(Modulus::<4>::new(&[0x10]).is_err())?;
    c.check(Modulus::<4>::new(&[0x00, 0x11]).is_err())?;
    c.check(Modulus::<4>::new(&[0x01]).is_err())?;
    c.check(Modulus::<1>::new(&[1, 2, 3, 4, 5, 6, 7, 8, 9]).is_err())?;
    c.check(Modulus::<4>::new(&[0x03]).is_ok())?;
    // from_be / to_be.
    let v = bignum::from_be::<2>(&[0, 0, 1, 2, 3]);
    c.check(v == Ok([0x010203, 0]))?;
    c.check(bignum::from_be::<1>(&[1, 0, 0, 0, 0, 0, 0, 0, 0]).is_err())?;
    c.check(bignum::from_be::<1>(&[0, 0xff, 0, 0, 0, 0, 0, 0, 0]).is_ok())?;
    let mut o = [0u8; 3];
    c.check(bignum::to_be(&[0x010203, 0], &mut o).is_ok() && o == [1, 2, 3])?;
    let mut o = [0u8; 2];
    c.check(bignum::to_be(&[0x010203, 0], &mut o) == Err(Error::InvalidLength))?;
    // pow against Python big integers (64 to 4096 bits, also exponent 0, base 0, base m - 1).
    let mut mb = [0u8; 512];
    let mut bb = [0u8; 512];
    let mut eb = [0u8; 512];
    let mut rb = [0u8; 512];
    for &(m, b, e, r) in BN_POW {
        let m = bytes(m, &mut mb);
        let Ok(md) = Modulus::<MAX_LIMBS>::new(m) else {
            return c.check(false);
        };
        let base = bignum::from_be::<MAX_LIMBS>(bytes(b, &mut bb));
        let want = bignum::from_be::<MAX_LIMBS>(bytes(r, &mut rb));
        let e = bytes(e, &mut eb);
        c.check(base.is_ok_and(|bv| want.is_ok_and(|w| md.pow(&bv, e) == w)))?;
    }
    // Montgomery round trip, add / sub at the edges (m - 1 + 1 = 0, 0 - 1 = m - 1).
    let md = Modulus::<4>::new(&[0xff; 32]);
    let Ok(md) = md else { return c.check(false) };
    let mut m1 = *md.modulus();
    m1[0] -= 1;
    let one = [1u64, 0, 0, 0];
    let zero = [0u64; 4];
    c.check(md.add(&m1, &one) == zero && md.sub(&zero, &one) == m1)?;
    c.check(md.from_mont(&md.to_mont(&m1)) == m1)?;
    c.check(md.from_mont(&md.mul(&md.to_mont(&m1), &md.to_mont(&m1))) == one)?;
    c.check(md.reduce(&[u64::MAX; 4]) == zero)?;
    c.check(md.is_reduced(&m1) && !md.is_reduced(md.modulus()))?;
    Ok(())
}

const RSA_MSG: &[u8] = b"DeSoOS signature test";

fn rsa_checks(c: &mut Checks) -> Result<(), Failure> {
    c.group("rsa");
    let mut nb = [0u8; 512];
    let mut eb = [0u8; 4];
    let mut sb = [0u8; 512];
    for &(ki, kind, h, mgf, salt, sig) in RSA_SIGS {
        let (n, e) = RSA_KEYS[ki];
        let Ok(key) = rsa::PublicKey::new(bytes(n, &mut nb), bytes(e, &mut eb)) else {
            return c.check(false);
        };
        let s = bytes(sig, &mut sb);
        let k = s.len();
        let p = PssParams { hash: h, mgf_hash: mgf, salt_len: salt };
        let verify = |m: &[u8], s: &[u8]| if kind == 0 { key.verify_pkcs1(h, m, s) } else { key.verify_pss(&p, m, s) };
        c.check(verify(RSA_MSG, s).is_ok())?;
        // Another message, a flipped signature bit (low byte: stays below n), a flipped top byte.
        c.check(verify(b"DeSoOS signature tesu", s) == Err(Error::Mismatch))?;
        let mut t = [0u8; 513];
        t[..k].copy_from_slice(s);
        t[k - 1] ^= 1;
        c.check(verify(RSA_MSG, &t[..k]) == Err(Error::Mismatch))?;
        // Wrong length either way.
        c.check(verify(RSA_MSG, &s[..k - 1]) == Err(Error::InvalidSignature))?;
        t[..k].copy_from_slice(s);
        c.check(verify(RSA_MSG, &t[..k + 1]) == Err(Error::InvalidSignature))?;
        // The other scheme / another hash does not accept it.
        if kind == 0 {
            c.check(key.verify_pss(&PssParams::tls(h), RSA_MSG, s) == Err(Error::Mismatch))?;
            let other = if h == HashAlg::Sha256 { HashAlg::Sha384 } else { HashAlg::Sha256 };
            c.check(key.verify_pkcs1(other, RSA_MSG, s) == Err(Error::Mismatch))?;
        } else {
            c.check(key.verify_pkcs1(h, RSA_MSG, s) == Err(Error::Mismatch))?;
            let wrong_salt = PssParams { salt_len: if salt == 0 { 1 } else { salt - 1 }, ..p };
            c.check(key.verify_pss(&wrong_salt, RSA_MSG, s) == Err(Error::Mismatch))?;
            let wrong_mgf = PssParams { mgf_hash: if mgf == HashAlg::Sha256 { HashAlg::Sha512 } else { HashAlg::Sha256 }, ..p };
            c.check(key.verify_pss(&wrong_mgf, RSA_MSG, s) == Err(Error::Mismatch))?;
        }
        // s = n and s = 0.
        let n_bytes = bytes(n, &mut nb);
        c.check(verify(RSA_MSG, n_bytes) == Err(Error::InvalidSignature))?;
        let z = [0u8; 512];
        c.check(verify(RSA_MSG, &z[..k]) == Err(Error::Mismatch))?;
    }
    // PKCS#1 without the NULL in the DigestInfo: refused (strict).
    let Ok(key0) = rsa::PublicKey::new(bytes(RSA_KEYS[0].0, &mut nb), bytes(RSA_KEYS[0].1, &mut eb)) else {
        return c.check(false);
    };
    c.check(key0.verify_pkcs1(HashAlg::Sha256, RSA_MSG, bytes(RSA_NO_NULL, &mut sb)) == Err(Error::Mismatch))?;
    // A 2049-bit key: emBits = 2048, the PSS block one byte shorter than the signature.
    let mut nb2 = [0u8; 512];
    let Ok(k2049) = rsa::PublicKey::new(bytes(RSA_2049.0, &mut nb2), &[1, 0, 1]) else {
        return c.check(false);
    };
    c.check(k2049.bits() == 2049)?;
    c.check(k2049.verify_pss(&PssParams::tls(HashAlg::Sha256), RSA_MSG, bytes(RSA_2049.1, &mut sb)).is_ok())?;
    c.check(k2049.verify_pss(&PssParams::tls(HashAlg::Sha256), RSA_MSG, bytes(RSA_2049_TOP, &mut sb)) == Err(Error::Mismatch))?;
    // Crafted PKCS#1 blocks: the first (control) is right, the others almost.
    let Ok(kc) = rsa::PublicKey::new(bytes(RSA_CRAFT_KEY, &mut nb2), &[1, 0, 1]) else {
        return c.check(false);
    };
    for (i, sig) in RSA_PKCS1_BAD.iter().enumerate() {
        let r = kc.verify_pkcs1(HashAlg::Sha256, RSA_MSG, bytes(sig, &mut sb));
        c.check(if i == 0 { r.is_ok() } else { r == Err(Error::Mismatch) })?;
    }
    // PSS: the bit above emBits set in maskedDB.
    c.check(kc.verify_pss(&PssParams::tls(HashAlg::Sha256), RSA_MSG, bytes(RSA_PSS_TOPBIT, &mut sb)) == Err(Error::Mismatch))?;

    c.group("rsa keys");
    let n = bytes(RSA_KEYS[0].0, &mut nb);
    let mut t = [0u8; 513];
    // e: even, 1, 2^32 + 1 (5 bytes), leading zero, empty.
    c.check(rsa::PublicKey::new(n, &[1, 0, 0]).err() == Some(Error::InvalidKey))?;
    c.check(rsa::PublicKey::new(n, &[1]).err() == Some(Error::InvalidKey))?;
    c.check(rsa::PublicKey::new(n, &[1, 0, 0, 0, 1]).err() == Some(Error::InvalidKey))?;
    c.check(rsa::PublicKey::new(n, &[0, 1, 0, 1]).err() == Some(Error::InvalidKey))?;
    c.check(rsa::PublicKey::new(n, &[]).err() == Some(Error::InvalidKey))?;
    c.check(rsa::PublicKey::new(n, &[0xff, 0xff, 0xff, 0xff]).is_ok())?;
    // n: leading zero, even, 2047 bits, 4097 bits.
    t[0] = 0;
    t[1..257].copy_from_slice(n);
    c.check(rsa::PublicKey::new(&t[..257], &[1, 0, 1]).err() == Some(Error::InvalidKey))?;
    t[..256].copy_from_slice(n);
    t[255] &= 0xfe;
    c.check(rsa::PublicKey::new(&t[..256], &[1, 0, 1]).err() == Some(Error::InvalidKey))?;
    t[..256].copy_from_slice(n);
    t[0] = 0x7f;
    c.check(rsa::PublicKey::new(&t[..256], &[1, 0, 1]).err() == Some(Error::InvalidKey))?;
    t.fill(0xff);
    t[0] = 0x01;
    c.check(rsa::PublicKey::new(&t[..513], &[1, 0, 1]).err() == Some(Error::InvalidKey))?;
    c.check(rsa::PublicKey::new(&t[1..513], &[1, 0, 1]).is_ok())?;
    Ok(())
}

/// Builds DER SEQUENCE { INTEGER r, INTEGER s } from big-endian r and s (adds the sign byte).
fn der_sig(r: &[u8], s: &[u8], out: &mut [u8; 160]) -> usize {
    let mut n = 2;
    for v in [r, s] {
        let mut start = 0;
        while start + 1 < v.len() && v[start] == 0 {
            start += 1;
        }
        let v = &v[start..];
        let pad = v[0] & 0x80 != 0;
        out[n] = 0x02;
        out[n + 1] = (v.len() + pad as usize) as u8;
        n += 2;
        if pad {
            out[n] = 0;
            n += 1;
        }
        out[n..n + v.len()].copy_from_slice(v);
        n += v.len();
    }
    out[0] = 0x30;
    out[1] = (n - 2) as u8;
    n
}

const N256: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const N384: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
const P256_P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
const P384_P: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";

fn ecdsa_checks(c: &mut Checks) -> Result<(), Failure> {
    c.group("ecdsa");
    let mut pk = [0u8; 97];
    let mut sg = [0u8; 160];
    for &(curve, key, sig) in EC_SIGS {
        let key = bytes(key, &mut pk);
        let mut sb = [0u8; 160];
        let s = bytes(sig, &mut sb);
        c.check(ecdsa::verify(curve, key, RSA_MSG, s).is_ok())?;
        c.check(ecdsa::check_public_key(curve, key).is_ok())?;
        c.check(ecdsa::verify(curve, key, b"DeSoOS signature tesu", s) == Err(Error::Mismatch))?;
        // The other curve refuses the key (wrong length).
        let other = if curve == Curve::P256 { Curve::P384 } else { Curve::P256 };
        c.check(ecdsa::verify(other, key, RSA_MSG, s) == Err(Error::InvalidKey))?;
        // Trailing byte after the DER, truncated DER.
        let n = s.len();
        sg[..n].copy_from_slice(s);
        sg[n] = 0;
        c.check(ecdsa::verify(curve, key, RSA_MSG, &sg[..n + 1]) == Err(Error::InvalidSignature))?;
        c.check(ecdsa::verify(curve, key, RSA_MSG, &s[..n - 1]) == Err(Error::InvalidSignature))?;
    }
    // Edge digests: e > n, e = n (u1 = 0), e = 0, e = n + 1.
    let mut db = [0u8; 48];
    for &(curve, key, dg, sig) in EC_DIGESTS {
        let key = bytes(key, &mut pk);
        let mut sb = [0u8; 160];
        let s = bytes(sig, &mut sb);
        let d = bytes(dg, &mut db);
        c.check(ecdsa::verify_digest(curve, key, d, s).is_ok())?;
    }

    c.group("ecdsa encodings");
    let mut rb = [0u8; 48];
    let mut sbb = [0u8; 48];
    let mut nbuf = [0u8; 48];
    let mut pbuf = [0u8; 48];
    for &(curve, key, r, s) in EC_RS {
        let key = bytes(key, &mut pk);
        let r = bytes(r, &mut rb);
        let s = bytes(s, &mut sbb);
        let fl = curve.field_len();
        let order = bytes(if curve == Curve::P256 { N256 } else { N384 }, &mut nbuf);
        let n = der_sig(r, s, &mut sg);
        c.check(ecdsa::verify(curve, key, RSA_MSG, &sg[..n]).is_ok())?;
        // High s (n - s) is a valid signature too – ECDSA has no low-s rule.
        let mut hs = [0u8; 48];
        let mut borrow = 0i16;
        for i in (0..fl).rev() {
            let v = order[i] as i16 - s[i] as i16 - borrow;
            hs[i] = v.rem_euclid(256) as u8;
            borrow = (v < 0) as i16;
        }
        let n = der_sig(r, &hs[..fl], &mut sg);
        c.check(ecdsa::verify(curve, key, RSA_MSG, &sg[..n]).is_ok())?;
        // r = 0, s = 0, r = n, s = n: out of range.
        let zero = [0u8; 1];
        let n = der_sig(&zero, s, &mut sg);
        c.check(ecdsa::verify(curve, key, RSA_MSG, &sg[..n]) == Err(Error::InvalidSignature))?;
        let n = der_sig(r, &zero, &mut sg);
        c.check(ecdsa::verify(curve, key, RSA_MSG, &sg[..n]) == Err(Error::InvalidSignature))?;
        let n = der_sig(order, s, &mut sg);
        c.check(ecdsa::verify(curve, key, RSA_MSG, &sg[..n]) == Err(Error::InvalidSignature))?;
        let n = der_sig(r, order, &mut sg);
        c.check(ecdsa::verify(curve, key, RSA_MSG, &sg[..n]) == Err(Error::InvalidSignature))?;
        // A needless leading zero byte in r (non-minimal DER).
        let n = der_sig(r, s, &mut sg);
        let mut bad = [0u8; 160];
        bad[0] = 0x30;
        bad[1] = sg[1] + 1;
        bad[2] = 0x02;
        bad[3] = sg[3] + 1;
        bad[4] = 0;
        bad[5..n + 1].copy_from_slice(&sg[4..n]);
        c.check(ecdsa::verify(curve, key, RSA_MSG, &bad[..n + 1]) == Err(Error::InvalidSignature))?;
        // Long-form length of the SEQUENCE (0x81 0xNN) – not DER for lengths < 128.
        bad[0] = 0x30;
        bad[1] = 0x81;
        bad[2] = sg[1];
        bad[3..3 + n - 2].copy_from_slice(&sg[2..n]);
        c.check(ecdsa::verify(curve, key, RSA_MSG, &bad[..n + 1]) == Err(Error::InvalidSignature))?;
        // A negative r (sign bit set, no zero byte) and a wrong tag.
        let n = der_sig(r, s, &mut sg);
        let mut neg = sg;
        if neg[3] == fl as u8 + 1 {
            // r had a sign byte: drop it so r looks negative.
            neg[1] -= 1;
            neg[3] -= 1;
            neg.copy_within(5..n, 4);
            c.check(ecdsa::verify(curve, key, RSA_MSG, &neg[..n - 1]) == Err(Error::InvalidSignature))?;
        }
        let mut tag = sg;
        tag[0] = 0x31;
        c.check(ecdsa::verify(curve, key, RSA_MSG, &tag[..n]) == Err(Error::InvalidSignature))?;
        tag[0] = 0x30;
        tag[2] = 0x03;
        c.check(ecdsa::verify(curve, key, RSA_MSG, &tag[..n]) == Err(Error::InvalidSignature))?;

        // Public keys: compressed prefix, y + 1 (not on the curve), x = p, wrong length.
        let n = der_sig(r, s, &mut sg);
        let kl = key.len();
        let mut k2 = [0u8; 97];
        k2[..kl].copy_from_slice(key);
        k2[0] = 0x02;
        c.check(ecdsa::verify(curve, &k2[..kl], RSA_MSG, &sg[..n]) == Err(Error::InvalidKey))?;
        k2[0] = 0x04;
        k2[kl - 1] ^= 1;
        c.check(ecdsa::verify(curve, &k2[..kl], RSA_MSG, &sg[..n]) == Err(Error::InvalidKey))?;
        k2[..kl].copy_from_slice(key);
        let p = bytes(if curve == Curve::P256 { P256_P } else { P384_P }, &mut pbuf);
        k2[1..1 + fl].copy_from_slice(p);
        c.check(ecdsa::verify(curve, &k2[..kl], RSA_MSG, &sg[..n]) == Err(Error::InvalidKey))?;
        c.check(ecdsa::verify(curve, &key[..kl - 1], RSA_MSG, &sg[..n]) == Err(Error::InvalidKey))?;
        // A point with a small x: accepted as a key (the signature is not its), but the same
        // point written with x + p (still fits in the field length) is refused.
        let (good, big) = if curve == Curve::P256 { P256_SMALL_X } else { P384_SMALL_X };
        let r1 = ecdsa::verify(curve, bytes(good, &mut k2), RSA_MSG, &sg[..n]);
        c.check(r1 == Err(Error::Mismatch))?;
        c.check(ecdsa::check_public_key(curve, bytes(good, &mut k2)).is_ok())?;
        c.check(ecdsa::verify(curve, bytes(big, &mut k2), RSA_MSG, &sg[..n]) == Err(Error::InvalidKey))?;
        c.check(ecdsa::check_public_key(curve, bytes(big, &mut k2)) == Err(Error::InvalidKey))?;
        // The key alone: off the curve, compressed prefix, short.
        k2[..kl].copy_from_slice(key);
        k2[kl - 1] ^= 1;
        c.check(ecdsa::check_public_key(curve, &k2[..kl]) == Err(Error::InvalidKey))?;
        k2[kl - 1] ^= 1;
        k2[0] = 0x03;
        c.check(ecdsa::check_public_key(curve, &k2[..kl]) == Err(Error::InvalidKey))?;
        c.check(ecdsa::check_public_key(curve, &key[..kl - 1]) == Err(Error::InvalidKey))?;
    }
    Ok(())
}

/// cryptotest speed runs: `iterations` verifications of one stored signature (0 = RSA-2048
/// PKCS#1 v1.5 SHA-256, 1 = ECDSA P-256, 2 = ECDSA P-384); false if one does not verify.
pub fn sig_bench(kind: u8, iterations: u32) -> bool {
    let mut kb = [0u8; 512];
    let mut sb = [0u8; 512];
    if kind == 0 {
        let (n, e) = RSA_KEYS[0];
        let mut eb = [0u8; 4];
        let Ok(key) = rsa::PublicKey::new(bytes(n, &mut kb), bytes(e, &mut eb)) else { return false };
        let (_, _, h, _, _, sig) = RSA_SIGS[0];
        let s = bytes(sig, &mut sb);
        return (0..iterations).all(|_| key.verify_pkcs1(h, RSA_MSG, s).is_ok());
    }
    let (curve, key, sig) = EC_SIGS[if kind == 1 { 1 } else { 4 }];
    let key = bytes(key, &mut kb);
    let s = bytes(sig, &mut sb);
    (0..iterations).all(|_| ecdsa::verify(curve, key, RSA_MSG, s).is_ok())
}

/// The Wycheproof sets in vectors/wycheproof.bin (see gen-wycheproof.py for the format):
/// "valid" must verify, "invalid" and "acceptable" (only MissingNull here) must not.
/// The failing case is reported by its Wycheproof tcId.
pub fn wycheproof(data: &[u8]) -> Result<usize, Failure> {
    let mut c = Checks { group: "wycheproof", case: 0, passed: 0 };
    wycheproof_sets(&mut c, data)?;
    Ok(c.passed)
}

struct Reader<'a> {
    d: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.d.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<usize> {
        self.take(2).map(|b| (b[0] as usize) << 8 | b[1] as usize)
    }
    fn blob(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(n)
    }
}

fn hash_id(v: u8) -> Option<HashAlg> {
    match v {
        1 => Some(HashAlg::Sha256),
        2 => Some(HashAlg::Sha384),
        3 => Some(HashAlg::Sha512),
        _ => None,
    }
}

fn wycheproof_sets(c: &mut Checks, data: &[u8]) -> Result<(), Failure> {
    c.group("wycheproof");
    let mut r = Reader { d: data, pos: 0 };
    let head_ok = r.take(4) == Some(b"DSWP") && r.u16() == Some(1);
    c.check(head_ok)?;
    let Some(sets) = r.u16() else { return c.check(false) };
    for _ in 0..sets {
        let (Some(kind), Some(h), Some(mgf), Some(salt), Some(a), Some(b), Some(cases)) = (r.u8(), r.u8(), r.u8(), r.u16(), r.blob(), r.blob(), r.u16()) else {
            return c.check(false);
        };
        let hash = hash_id(h);
        let rsa_key = if kind == 3 { None } else { rsa::PublicKey::new(a, b).ok() };
        for _ in 0..cases {
            let (Some(tc), Some(expect), Some(msg), Some(sig)) = (r.u16(), r.u8(), r.blob(), r.blob()) else {
                return c.check(false);
            };
            let ok = match (kind, hash, &rsa_key) {
                (1, Some(h), Some(k)) => k.verify_pkcs1(h, msg, sig).is_ok(),
                (2, Some(h), Some(k)) => {
                    let Some(m) = hash_id(mgf) else { return c.check(false) };
                    k.verify_pss(&PssParams { hash: h, mgf_hash: m, salt_len: salt }, msg, sig).is_ok()
                }
                (3, Some(HashAlg::Sha256), _) => ecdsa::verify(Curve::P256, a, msg, sig).is_ok(),
                (3, Some(HashAlg::Sha384), _) => ecdsa::verify(Curve::P384, a, msg, sig).is_ok(),
                _ => return c.check(false),
            };
            // Report the Wycheproof tcId as the case number.
            c.case = tc.saturating_sub(1);
            c.check(ok == (expect == 1))?;
        }
    }
    c.check(r.pos == data.len())
}

// ---- expected values (Python hashlib / hmac / cryptography) ----

const WYCHEPROOF: &[u8] = include_bytes!("vectors/wycheproof.bin");

const SHA512_EDGES: &[(usize, &str, &str)] = &[
    (1, "8a6c69af6fb6247635f837958446fb8f10e39bd5fbc244f7e635176339a3be614f6394247f01dbe1126c178c7bd48cb5", "e45bf5817ddf94aa2f7a407071f0eedc6beb98f768b4cd33d1176d44d1563a45a5d7212290eb7670c6786b13591aedac86478993895e8b24e612014abaa6ba04"),
    (111, "341388a9dc2275074e90cf394323761919761c805fd9e370977c9966a0e8c81a52135f02577670b0071638a4a26dbc31", "68cffa6d0d76f309c9ce0d35280939f8e25990c43b7b086ccdf709be35b07d4ddba599541ff2b1c19d34ea49aeafb9659adb7ac3c0b078bb30a22d57fc6687ef"),
    (112, "619cc5d06138526d70659eccf602d197e63e1050e22039a7feb40a30a5b2b08fb03729e291df12f8c576e6f1cd8af22a", "d0865c524d1dddf7c23b799c413f5adcd7caefd3f66a9b49750ec81066012c25a8bcf94ddea6dc525691673097ca40e0101e897fc97218cfdb0704084e2bef4b"),
    (113, "484a92d02b61b620ccae687fce4cd073eb995294a777d5deb5356bc8c1e2ce984f63f16420058ac5da666fda410a4feb", "606314353bd419f9f7720e8297f2af8a9ed5f0bb0bed29b716bf18e34577623ae7effa46f496bd4282134e7e895284a4760a910d2ad8ec11e9dd75863058cd9c"),
    (127, "f8234ab81f5f9641c656680825a9bbb3c2616bcc80b65d5e479a4d96742e1b8742330c9e8256ef5f03caa932487044ca", "e0b6a20f1c0c88970a9340152cd5a1c1ecf3d3b8de55102741879438079473540133b812706e5dbec322c8c9523b6fc8c6d16ee626e87ad5fe3d2916afedc369"),
    (128, "e8480e9c4dd90f88104a79cbaccec48edbd798a142b4f241d726dc252f1502350e824c7d18dadd59d7d716919fb8f9bf", "99b16f17aa0b969a5b8f08f367719d516e330ccd2660b6f0688ec031dbc783de50a1cd185a2568dba75070a2403d17d4741d163578515dfd2ff756ddfe4d47b1"),
    (129, "430173387764874661acba1e914e50f6d0fbac534809e859b1da4396fad3d5f24c25c6a2d02486d8fbda3994713d981a", "a1556e29185778aa5991e34b8884c840d589f0fbb4b8ed590e51e9ac4eb03a008125000db2671f8fe7f485b59a77b518670078ecb41a54b4cd02a7f1d2ca4c6d"),
    (239, "fc75ded15c6080ff96ac03391fc1302ca180128e4b6a4a2f17782f2ec016fc3f79b48b5fed3305fb7fdff9fd29434525", "18ee83f30261c3c645d52aee6a209105b25bba39d33845ef48984cc238e4f21661fb7bd7dd4336f71c40fe87d95e5115d6c7be52e0d3e7e7877d24500b5b58df"),
    (240, "4c4bc5dae174dd68cb5a62e066e01e339e4980e4a35531b732dcf88e9c579e66f7c0d044779e2eda8a597684ca7cffd6", "9d60ee60d29ec4fa0b9690c04c1c29413bbe3ed345639182d9d53dcc05926b77b04f4fec1562fb85182954c96b7cbb5d5e4410251ff4f352d09a2da90419fb13"),
    (255, "15f3347894a150a64eb82a7044bb5ec8b1d33488716fce4932ba73beb97eabd1ad796bc0a569129ba98120ae1ed7edce", "c2e3bb67012f9eb526202efa59997933f7d3e75e7ded738818bc27d94977f4573afddb1b2793745701e62affa3b7a1c8262c992a321f488a6b1942a4795bab98"),
    (256, "23f0634552ba15289fa02c8a37e3a391e79e230dca05db03a7696630c5ba3a3352d1624f52832e4d6183c0eb70198e9a", "e49c208e41556e859d1a52d14784a061c2d5ae2c8690a5360e9f9344f60861c1362a9ec05a9f08a4167b3da41bdd122a387413dd06976470e4beff5053f2ac71"),
    (1000, "94c38db521ca733b8904c2d14b6e82d33dcfcc26e1318c579dbee1fc2f472019034e792263b9d46e90e700de2f6e7e91", "00e36fccf193e59697a92b5ab24666ce6326d7fa16bf10832d0991ddc591112e9dfa6a636950ed9c4d67344a760654c2ff7785e1d60094d651038735b5dccabd"),
];
const HMAC_4231: [(&str, &str); 7] = [
    ("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6", "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),
    ("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649", "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"),
    ("88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27", "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"),
    ("3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb", "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"),
    ("3abf34c3503b2a23a46efc619baef897", "415fad6271580a531d4179bc891d87a6"),
    ("4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952", "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"),
    ("6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e", "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"),
];
const HMAC_512_EDGES: [(usize, &str, &str); 3] = [
    (0, "962166748e08ee8bc8f622dae1e1d50ddf5a91701a0651de95eb3a520419a6e0a3ea84a0a8989de07ce29906b8892e5f", "aee650458ddcbcd4557531b27f1cded4c577f576079b086f57f3c6b9e037a7c0b3cdf7ff58afa09fe279076d1107d5d554f4d34fc6f03d8fd12f93d892802ac3"),
    (128, "72a22e9ebcc6a94b499849f469ea197279396bd26fda49d9536a319f72f9f3d5ebc0bc7fd910ba558dd16fdb89bfa75a", "ec34d7168687da0580e5356f05fae4ff03bc68cbef844dabd9259f3b2e330293b9df812f98dc42119324a449bdaa22435dfed1dab7c47c00bfbed91c5368a4e5"),
    (129, "c2a91ba1f1ff2ce24a2eef235f76b5359a8be2b927ad88b663a9b60d06cbee1d51b387971d46dc0487ec293db7cf3fb2", "e20ad36395957b307b7fd625b8ce91af5331c3a519ef627db890c13953a3517696ff237bef9ac4bea933fcc7dcf29abdcfd011663b46e736ea4c858ee523d043"),
];
const HKDF_512: [(&str, &str, &str); 2] = [
    ("384", "704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade", "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5"),
    ("512", "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237", "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb"),
];
const HKDF_384_MAX_SHA256: &str = "54d1725121d8a835a8b7007b936d9b526b6edde2db50331bddb594cfc8a1732a";
const HKDF_384_EMPTY_SALT: &str = "63d28c560efc8cbe4bdc3f288766fd915740592c873b7a4063d237761454b17cdae9288eb91ecc048996537868d25ca1cfd2";
const BN_POW: &[(&str, &str, &str, &str)] = &[
    ("9f492fba47a1fca7", "7aeff54e808c46a6", "677cbb5a6d12d9b29d96345e044c3396cf760198b72ee2002f", "9aab92c8c5449b37"),
    ("0180212c2684950c17", "1c42d0fe736d4796", "d2bc", "545a89cf66fa293c"),
    ("7532b37906813a3cdaaf12a5c7a20213", "3fc5a1b86c1fb2918ec411835a28ede2", "43eff197220e54e30ddafc13092e2aa17d6efba0f4fdb48b3f", "0db63e725c3c7e57c908302e3d1bc9cf"),
    ("c990de4c33d5e11798477fdb9196d3df", "173f70c7db0c5225b64c807ce00347ce", "cc475e68b77f9295", "157a553e6836a0953449d4bcdc91eb85"),
    ("ba9eca13215a4348f36f7cdd4bb5c20ee26799f4597c9683", "455a45c6cdf6fd5ccd804afcde2d841437a14fe006230f06", "016a87", "63e8c0f22817c2d2881646fb0baea389a7e47a4a8d12fb3b"),
    ("740f64312b8a29f081332e623ca58fe7daaa2a0dc31ffcfced853d3b0c86a0c3", "536bb0f814f8b2f8adf634b6c8cedf09152e4cfd1593411d6e0a309a9d087986", "00", "01"),
    ("fcb2331fe51a3914c40cdc95c4ad705476567a56706c7724247ec6198e75f0c3", "33efc9314dc922f0dba670fa598007ba3de789868f7fb9a1b569a803d0b727e3", "00", "01"),
    ("e917c3f05c99387e16fc55d7f9210155b80c9b59a9a24bf10f191b2ad7ccac0964894f116d9cc45acd9f53b01bc2e777", "8c594afff6c04a88d008402e1f9e5536ec8c3c0f3d977f2522f2ca1417be4b547d44c6f8c782313257d923532ae9c601", "01b61c", "e7b5f1e67ec42b1f5d5ef04a5193625abd6eee2d0f90454fd918c97aa5885d291d64842eaaa716db381f92bc02c9c14c"),
    ("011142fc419ee5b9cdfaa230bfceeedd230c1acc2ba9186f58fac4a61af4bfce4ca20892c1c77d12210f14bded0f6855931ab6523db242488f8c6989291762cf9f87", "2d11d45593ac3eb6875e046e704503fdee1121c24db6ff4226a2d54230867ba5475d2d85554ce5f5657ee3006ce51e1f472bbb3e07637bda7d7886c2db689b75ca", "5fa1de012fb782afc0cb151db689b46c1d7db2473083277565", "e611aa39b306fe336c58efb46d641a61859b0d852bf2f371924f69c4395e3f418a304af206e4fdb05e5871df1fee2bc641c7c54c34b465782d10fe8dffdfffef31"),
    ("9997eb0053f2180dab31fa83c60ca2df82f22cca7bd868a447c2684ccf56477a368ef2b05ee3ff990cdd2bc91f0dd59aa0c9e6039346b715badcc8bd3366b66e0bc3057700362d3bc5e1f4a469a83d6976fdfe40741bde51b2d8584362e1d357e629660b86daf3e6d96b757e51c9c7e4f93e07a5a04a1b3d157fb4da84dae8d1", "26b1f7adbeb926a42b94d16464dee4b194ede011af06f4e0c128ad2496fefbcb72515bf1a62387bbce24f819a32bddeab393881c30463b9a1e8c0281b9bae9c88559ae92eee2c941e84dcf815de18d1400ca786cdbf39a460076d3bf5c093cfea1c3b4117b9ec332cd980245c2061acb5d2aaa48716017be80d4f4bc0009d05b", "1d9a81c41b5c1d5f40c2e9d7c20173d2b3c87c0d2706f47ad0", "2614af3d31fdf7f66f889df2e2a1cee08e5f70b1b6646e2ade3e329fde7520c7f4ad0011713099fb4070e4705468b438dd9e115d4faf54fe0442b54c91bb3f16a5fb8694dcc4fb4875b975c8f7be4a8a71201d7c365446b9867a2db8ed4c15ee7b7b540158407e6d6110758e3526ae8ed3944d26288024d1b299705c113dc543"),
    ("b9e2e6f93e40ebc6523cd508f54a6b09ab0fb6400fb66e30374c7bcb2c9b87993e886cca1cc1fdd70449684eafd49de68b3292acbd925ab4320b6ac0452a5779f04310346ff41fe77f45017426d84158be318a5f36e49cbddcddea89dab3a09bb7a27d83657e02c5d7777262a10ad5683b30e4536424b729805b62f2084bc5cdb2d10021c776216047482b553528d496353e7341d3e8832f410f628ddbbf502296eb7ea3365004a1573518e822431b8ba43b6cc1e4fc6741b4d2c3c6dce4d8fa37f342d5dc58512ed82f7c547f21c92dfca02edf5f3d17d2a42b29217ebdd20516c875107d45456fadbe585d181822daf62c257a39947bab6a02849488071d6f", "5e2625e64f19e56357282d9791a284314552a9fcc2864031057e85744e9e82a6437fcada2be05f17540728c90de8f62b18077fa7d7ade0ba06cac9c3d36cfde58bfc881fff9e0de33a95c3e5880dda901e693c4008276bed2af5489a765fcf976eb6c1ad9af31a39a8bb9cd9d614ff4672d0e1f06543591f329bd9590345073a941c979349519dc03c7c915df6495a48f582c6852a5a2c72bcbe8720eca1b980eccaded66947b8dc418bb05052ead0a867bf4625b3e9f967276311e38c1831fd6de73c00f6ae92d31a32c13157d37185bef1d29381cff9709c4ece84b49e505c375e26bf28b5d9f9cc709f8a6ee21836d1e4111e4b1902c5119d81aa2cde8350", "00", "01"),
    ("dfef6f41f6bef33af8f0c414a2efd915a8bbe4fe1ae232b988cec47f18823f53233e9a546edfedb66a8bdd923b8837b863fcbeab9c3936cc4caac4f3c080078b83fe7ac8fc04220ef79ce76d9ad2640bf11c34a9c005411f85f7ab91424f4d26658953a6de1b8f1397df2fc88155e0749c68d467bf8004979bce7e5e44560d40539331f309661d690511f2802413e313c3f47183c6f6a32a6b63db846c536eaaa560aba43f8820dc5f7ce8cef5c56afbff854cffa07e50c088cb407041e4098726684a6f0aed4fa2d24671edff790c33cc85d209410b77f0aebe130551b118b484471622fa50a29e80cac2afa302739e401c103892b331579dff754705b0f6cbe45f5c996989254ff77dbd7862c21a492f8033ace4cb63a30850430bbe2c8053273a5b4488b79d57e76b7f93c696a29bd92b23d649cc1437da4dd0381df7219f12b6873f509c153d96bbb69d005dfadefcb32c52b323d00951d878ef989dbdc64b886e30ecc42a5caa5ae81c9d066e4453ac691ea5c7fea5e7e5a79f4dea58dd", "2cbbfea8c8eaec7300a2dfdf7a624dc7252d1dad23182cfd3b120b0b10b8546e746364d6863fb15e6e9da4e97666353099eee301f6d542972e9d4b70958a76655622bc38e60be6dd3a5158c6d266e0c62f90955c845c85fa2f5b94c22bde772d5de4883fa676b7ee35846932058b91e841401766f9352b1a699879e8525320155b4e31c99cdd181c9290d0bdc6d3dfb8faef9df3e35c4f1b7b99cc35b6c16489b6bfb36435107c904eccd7d95b6c6a4d672ca3e85801c2e1ad15ebdd9836ec046adbd126b9eb3cb7f70abce8828d272f084cccdde8ea08d251b02926ce55217be5adc8d563fac6723b80d9486192d16a51c9472ee4a563a3a9e7da43868cc7ae7dbc3df020bfe6854c7ec6eee36ee5398d29a31c54a8633abfc14a43843223785f4b7a0037dab83cfcb084a8051b7e024fb208aef27eea20382de15a3d78b220ac4635cd6186c283276acd901ce47cb6a2fde162ec9d194ef5fb6456fa01d02b72d2395bcda5ae14d73b2b17bc3fd9b83148e00e48b9403df5771ccb8ce92d75", "c91e", "8217f65f77c47c04501b4859849a6d9d587299a58fa4225617853100f726878a444f11902368221ca2d93f02f714156d8ce596d3a73a615468fd946373171ea03d08b0b01cf336ce0c73f02eeeb24e5ca2bce01bb8f785fe1cc928e12d8363f29a12d8d03b83b70f3dc5093f68c20950973ce83f4e5b13f080524b878e0bf3365c02a02bb0a8405ed0110492aa8e37d209ce727821b1a2934ea8b5b64402f631ef89d57da7a96b85a991c00eaaf06de20d7eff877bd29261a4f86d99e2aae857541c5ca28d32666d968b654287cdc1a43badfc81810cba30ec2914302d8b35e7ec48c2bd59210c69dc6b2f6bb1ce2f63be95f19978c404183795b5c09b459234297ffa4e92a65d8090922943f92ca9ae5aa61818a61df1e006092af677fbc0f661198a0bb7680f4c08b55486c79017faf06918c4bb62e99e64749526cc6ba396d146c5a30b0a9169e1b6d04d64bcabd31b257aaae22a886a3db9c830def9aab09094f030c18acdbad80128467db4cf94b401cadefff0c5a0db491873419abbb7"),
    ("afcf2144a03351a9179b6a299c849367462ae66b66b102482435c618674450ac564953d3fd9cc36944c5e7b283dd427ed93932081f7cdf36edc1e6a7b296f7ba6915e2a78f110dddb3e7cb5bc8953a0c3847aedf82f418f7b74959ea09ff7b5ea62382ec8141df9ed0f5d49f2ddebf85acbdceb78071ee168f4181b3ba3c3cf7acfe7aa454d1bf727d3609bd788ca6a4801d63a7e1c40f4dda43e68f099e9d9d1a1f7b04d8b78b7611e00328f14db95954a6cf1388d7511c169bb75be264978bca555c4e796a699a6c074ad4b1380ce8ea09d39c354fdc898358956ae575138651974a3077a9f5c6aabae10e6426f1ef9be493e4b89611bda0e625244a21df32882f0edec45b450e166101fa656505c2b6b980d9ddca38ea309d16e6c2b0bbdae713b9947ede6a101bedd71fcd925c62a09233abfa1192f467a5801e2dfe23d588703b97da7b6e4a87e82ec6ce956868af519e6d577e730d25aa05fc9864c932a302a4a32b4eb248b47e6ff2603c4ebfbdf1ddac645c902b54e271da1f9a92fa8c1d606fc64b86441a439fa29a268b145a7627ecb7b5baa94984b0acc9b6745b9858f6718895cc7f7d3258bb687fc2d5afb9588fbf773693a424da669d754347247b01bff6d50476bb9422b080e9eaf05d0b4985d8388ba02ab6bf4519ce894d44582922c1b7f01a849cf28871df442c1477e9347c082f98f0dfcf76df4970b5", "6e40baa31355290aaf03a73fccab6b07ae67e9385d9d21de293cff5ce37e763113f1a080c48c4a67d6a232f7021ecb0a74f4dfebf70f65f9694a34dbe9d7b872d91c6b637918e6896f84df3996c9d1782e0076cd4b7b96dd2d06f1ff77da6638c76c545b8ade42d5f3656836df23b4de06e00a141b311dd533be893a6fac7bf231dab0e0cd36067d26f93838e2bb8796fe883ddb0004b4d2b1082834a533287f53ee43f1f194194582d7402cd0400bb27b2f283dfb8cf5c31ebb441c3d7190d4c8f2a8eb4e5ae36a475e5485141b536df0629e78b3d1dae4ffbd6e0dbd3a7c66c6992ecbdc1d34f2b7db3cc664e7959de766b006b3a267828bf2185b32a51c2ce5594f83eda01b9dc15664a0c2f078381a22b091c0d15ca1c8421f4316d34fa53ee656f8ec36771d85933e0159834b3737a8dc37f538c046e393964dacf85e6974dce4507e51d71c7ed8bc44b4cab1c344412f674e2d038704ad97a12830a0c519510e3d8d6eb4dd43c2ba5de134904f1a6a069a0bd44d34f949696eb08ef9f406531ab4fdb4da34e77a6a2fb3754c27abb178c1cb95fbdff20c8870cc8b250f0599b7e65b97164795e649746725322ff5ae6a070a97d63bd1c6a9d57e005a47d9e28822e4c51bf500507ef2f413b9014b3b36800b6adfd861dae8e9da4ca945d825795fd7da96e97b77a4bf60b233bfb7368141ceff6bafce0f09347ee1916a", "00", "01"),
    ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff42", "02", "01"),
    ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43", "00", "05", "00"),
    ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43", "1234", "00", "01"),
];
/// RSA keys (n, e) made with Python `cryptography`: 2048/e=65537, 2048/e=3, 3072, 4096.
const RSA_KEYS: [(&str, &str); 4] = [
    ("8b11fa6310a4ad612a5581e71c112db0c4a8cb2d764a1d65302638df639ebab4cdc79cb361a1245f0cd71948f1ad328196d7840f7626de6558e53d860706ae6c47b8fc1d6fa74cc327d6be967400ae976d138446b8aa90c3acb04802eb8f11b11c90bd44a9ef993d1512d6927c1bd2134af4d56a1bbe0d63d7cf594fbdad6bb64e39b9dc5684c50f43c92976ac1368e0130bc3c7508a066a12c40b9470975cf477e591f2e9a32fd356708e81d17b86da25f7286ac88ca7a2ff02e9ca30630bb1e67f8a544143b04c1c4b0ebdd4b8c44016654785f90637e4e102fa906c444e26aecfe85c3d9ac7c0f0d30b9f9d73f7f4f47bbd8f63c06fe29071fa260320f425", "010001"),
    ("e33730b2a7760c6ca6a55375c8cc8fb7dfd86df9256cad0ce6ba358b6db6e289073987fe57101b835712379aa17b82e5b66f2edb5e47cead3e19e7b4aa773b987742a89cc53b9f68915a14b2f1a9291b7fd02a10bcad2873c65c9479a0d10638565b17411c920cddd3a58b9ff6f1693b76c4dc408ed4f0e49c8ba316f5d999e44f85ccdc109ac32879f69bcdb0e0c4cd5e43ef282636f3a161eb96ae4918809454e971efddb2ed2567caa8d3477495f792d96cb4108a5c9e9387f78576ab3ad9a6fd91ffcf2e47550cd1f36b53e74d92f48f241464c2b869531ae1798ffc753036376741de203e59caa526535f2412797bf8cdb59a1f283903406983fa932be3", "03"),
    ("9c24a63abe9f1fea3af55a76c7be16dacd2887b2770472f22b8a14ab061e35fcf144e714e310a143cca9a4935a852fa6b199abfb20743cac3eda43a47e2611cf3da38402d0119d52d4a57d1ab700d46e9fa6f58420f6fe1ff89d208f4ae4abbf329c26ed4e00f0bace298f687abadae553d378b5107a9510e1ed9f7f98f93a26f6237032c794a59a8790bb080c70446fa6684784b2d2e1fc85f21a01765b88d8cf5444556d41ab0ed7cc61fbda8f5c60f9a7717bb62b2fe282dd3aaafda62c1cb45b13d51f915796d1024878e6ab5653e1647402d7017efc49919c953e7aa27bab94b3b377972eec6ab34c2121158d502d5c4e5386fbba04377a7e9cb373dc7ec78d9d161fbdde9dd5fb86be89b7d67d501bc816c2d2f0c65016181ce6ab39ad50a1e503960440b0fa6ac2084ee5ecbf5ee0620738024a101b8927f9e3d5116811e03c3aa6ab6dbe504a3ecb3e5e6a6ad05a7e3b4816f1b98822e448d94fdee87c3e5f22d2505916b6b4036a318c99366269c5da68901c48c3bf4dc279c198b5", "010001"),
    ("9397d0248cacc453e04e55c5cbb4e6c54bf2e4946a9048cdb83927ea4f3842392e6c94c5d52de619ed8f9cef62fbe5414ce5890e66cdcc5c795d9c3239d3a5a4f030be54ca2b7d17fe1c6846af55f62cd562b7cbaff6ffd1cf9e40b226eeabdca1fee9d28679bd8db8cdfc6457b5e7063fac0df3597c1da3106e45b10db0288625bf7c95eb012bcf3377873e61b071fa754953b06bf170421366e93c9478151467d1bc605ed9ae9faa25179d7dcae3833b455a871b815f41d9451bc2aa7b42918ee883a4232a5000039e3440e24b6a65e70ba84b8192278661415b1904b59a304bebac4c989ff9e0658ae77cce9fcde7ddf43847553881080cf5ea83940047926e6fc6d089565c6e73f25c9e6a094cc02e313f4cb2d2d5e4e544987ff0683622c4956cb26b9ccb3005419e6fd4bc22cf5acf8c69c92548e4b2be49001e5d208286d960c6dd398fad3b0d883041a6761d5acb37fb8aaec935e0a694ac347905529ec2d52f1c137c86645e1a8e1e87813a93544c47f7ccfed1854384f3d202103fc466fe3731dca0b81e1029a44e02417ff803b21c8e031e373ed7573634e0efdb8167b54897e2bcdc842b7289ed4a5e00e5cc2aa950795ef96c52ff10ddda95d9d11ab9c2be6b14624efe83c310d3a3667a1a0afdd2249a506073a442fc5c3ed5eb80a2cee5081b896e4e6497e9c60b1dced526461ec3d3b8b18660121b167de3", "010001"),
];
/// (key, PKCS#1 = 0 / PSS = 1, hash, MGF1 hash, salt length, signature of RSA_MSG).
const RSA_SIGS: &[(usize, u8, HashAlg, HashAlg, usize, &str)] = &[
    (0, 0, HashAlg::Sha256, HashAlg::Sha256, 0, "6ce1a3ec81abcc4c771f190ba98bb14ee86e66437b85310d5354514d3dc9184e4bf4238f6d33f224d92d3f0559becd3e6104ec5280246b9a5d86fc6a0a9724782a375b3217e2204d023ddfae5065eaa40a8a5e5c38039f93f188c0c34e6f762c1acaba87c944a18008174b99866af281687f8b215a1125a7a07390ac5cc3d34f9561d69b0e60efff697d94590632ef26102eda316374b9133b0a8cbf260448087fe9c6286ae8d58ecd4e68d6a9ade9fc652d6e1a8abb12b391da637a4be2ef99d87efcd62d233ff83764456c4f5ce5f0693736ded70984ec5334b96786b1a8a0ae1b6eac9dbd4d998c4296a7f80f5bfae3a349a6c176d45898bfba2e00ba7802"),
    (0, 0, HashAlg::Sha384, HashAlg::Sha384, 0, "86dbb6bf535ba93e070611fc1f69c31b37ae60b72066afb8103a37266d6e47ac86b3710272c6011b93f5339f84fadcf634cb03cfd70cc718affbb145f9ad9e8e15d686d225e8aaa02d3d54b13c722152889ea9526ee319de7115d3e584f3111ace0941ea8befc4d7a246138a4c1363be85eb5087e40d3a7ae8830e0dddc61cd5702044b5d1662458754466c67391f75ed486f8458dd8a3d781ed16c1064ef0a01d98a71a70212f978f7bb116182f2a4beed6bfa8236c015fbab28ad84e4c14b2f32d10a7cc36edc20b6e90161de1472e5dd4097365c255758453b45d2f0a277fd1bee414d9563df7f56a5c3a597312ce08da2166b5392f13697ada0fde424684"),
    (0, 0, HashAlg::Sha512, HashAlg::Sha512, 0, "48c864b63278927a76bde4c7353e3859813b4402c27519dd7b4711802d38198c50a18585ffa9013a66fbeaac7183e2bc22b0f8b6fff09225133caf836afaaad60f00b82080fcb20a232b37cd88eaa2be9111afef504646a055689088c84c4886af0191939516bf0589e4fdb22129e3e8d1fb4231b0c17f003cb3cd056dd1642769fd0dfaded916571e1edb6342b55e05030b23a8921d8c71d817840411e96913606180ea392809f38ae6e903115dd17bde71cc960c5ed07a8e3a06552549b8295999fff5217a353b78877197552d8150704da3dbd16a93d1976eaa54040450ce3deccb45705357054ce12ea563a6789b2af82aba29eb6c9cb7b77824b6e54c2d"),
    (0, 1, HashAlg::Sha256, HashAlg::Sha256, 32, "70d029416e75de5b993d921b52e67e8757ae8dfcf9f1c13bf4b32da45367e19678cccb15566e4dcb80e618747a813736621ad0ded2b611140e454b3850336894534ea690192158a9666d06bee704f0900402865a72810ed2d2bedc24d93dd7f40785ac169473ad068916421a92891d098fdd913645b02febedd72c28caadbe07a19ad2c83965a33fd2e0d8929c3c486d4a8e216646ef625d42518210ab21e570367cee77425dde7b57d18629149d90e0434afe730d0061b3e16250956616c9d67bb40a1a86a098431a4cb58f811efa9edfb9d5b194aaa67509b449cd709570d3919b21e7fd03564eeed4cedbdb0dfa196063741bff96853b4dc4b392855f4543"),
    (0, 1, HashAlg::Sha384, HashAlg::Sha384, 48, "4723302387e7d666c607c0ed84b200520c031b37b20ac86bfa765ce896535fc114b2ec6fa0c6d0f5fa9073f1876ef54a47dec9f1ace451d7c78e076ea81540eb0948c267a253bc38b0d5815f27071d191e225c8eea8df6a88b7443b3e68aba405efa84be0e54c3a0463b15dfec6789900ecc3bf001c8ce14f650e865fb071b3b56d77abb882148199d0b43aa0a6b3a27d397484c28c50dffcf1f47ffba156031626aa76d0df686851dde3f9a50a4b7100d412bbc181a01d9e40500709b153f1db1711dfc1279615ba411417ef554b76008308a4134174a13c2b4c534a3a470f33ad283e96dc4cd6c90707303ebae4f92982185af4441548e5346702164c49d55"),
    (0, 1, HashAlg::Sha512, HashAlg::Sha512, 64, "65d6beda41803c8a451493eda302648777ade5c7047c1ce9bda6884d0086078d51ae1539931a70b3995800f1fb4b3d1d6d399675cc72958b64fc3621732b2990fee689e48c1b8aec30e7963e066c5b8a65ba3a350b05ac6b6a33d027bb9c8ef00efa9186fd51d6f72b9166ce53391b5360e10b2f5d02d3db6214a859afe640f63be964ca52f88e42de0277301316a78ec089dcb18258e2f444a9dd9212d5ca9c0f07eaf476e28bf40d126d6e69aac348ae81111624e5dd5c1188e0b1c250768c6ce296c67d97c903c5c9b4ec34ed6fc32fc2812a0e5f84bca4257a775560222669cf4dbfe2c79ac2212f06f71fc40e32a4d2d9ec671b046740f570ab1ebe39b5"),
    (1, 0, HashAlg::Sha256, HashAlg::Sha256, 0, "365347c2c559ef115801578190c0620863fb9266c96143e0ca1180493e273eba0f3a7c9225bd9f379b63b005890966996c3086ffbcee061308d369ade22caa5efa807c903b1ec24e2702e68739c21345750ebdb17102331a6308273ce568ddc55676f5b04831e3af0f047cafed5ea402c3847eb7cf17d32391478abaa2c46fc6644130e27f37727668d319ddd559b50be850a9b0b3661d1786c0923706204856aeb5d8845a668fd2c248b2561eeb0d88f07e4e0c1294316ba14d649f9026ccb221e2fbb310501855b7ec6791bc1cb4e16b39f03a8ce362ae3b244d1f09f2a716359151a1c31465d77e3d2178408b997d0e14d7092a6fa0d5e94032f5be0d039d"),
    (1, 1, HashAlg::Sha256, HashAlg::Sha256, 32, "b1b47a1831f34a82ada023879a8c6b118a4ab74f57c64d93e84126bb947dc35b3367852944d7e65ac388ede079eb642fc6284f36cc28e19b7a8c28cc085456451c6aadd54b3b63111486da68d9a8e1247fa68532d539c511f8eefc9c23e80d121e7dd3ef99f983e4ab948ea8d93ac0d267b5b51f5bbfb603a6dabc412f102ff79be021ccae1204272c346594386b212c5069b26aa1cd0deceef5142bd168f9106a2af972f4a658bf682b2449cdcf02c4749ea79832deb67fe4277d6cba95e1cdf83bdb106c6858dd8fe92ddcb12da97b67f9611df384bb21ee5dd0d103c564c41edc019943b250858198a42eb204f265ae90939970be7643d1e8829726c2ec15"),
    (2, 0, HashAlg::Sha384, HashAlg::Sha384, 0, "665ef4504a71467ef75af632a503d354d5e4fe70e28d749a54931e5b01b8b356b2ffb3c2d09bef514eb1454f92a26203a242de75eb6f7d6e2e243437d620546be3949fb453fcac088f25881cb20cde5e95aef7ca8df11639ab12f94ce958015732b7ba1826ed904a1cd38d307e203c3c084872ffef392d04c931afce60327c8ade4eb948e9559ee2aed6218fc92f41725fae41f024aea3c06505fb4cef1d299a6f1f7ea659b3a717f1801f3d4f27c98d3346cac3d520c2d605dac23cdf957df1903e70e359fe4517ac161f97f9462b277846e5ced3547703119560f03c5110cff966666ed8faf861f70492c9bc68e7d7ee8720c1f62e7e85ceb725d5889e6544b92437ece04cd15c80f8a7f87ff810538caaa9db10381e8e01c0973b968b08414792ce86b55995ea7c0ef3f926af6255a26ba326f6ec7ebcc226961bf6181c5cc096f9d022ec427433756e0efe8fb391d645d1f69541e214d0f1e2844c65068f7a30343fa5eddf2dd18190647e0a4c56f474a72e205cd73b55ac6550b05c0682"),
    (2, 1, HashAlg::Sha384, HashAlg::Sha384, 48, "28e45c1c1294e5ee2843cd388630d271907bba784a1f75cabffb0ca2242663ac3176845d6a9895a34f5c01f75e154ea26ff0e6256a8610403b7fe8038ce926c407e182c6916c72490b24c62e20e7fcbbf8df8c274e766c51cd556dadf20b6513bc257a7b6c0bee8ed58d6e7e7c84493683aeec03b8877b46eed47ec35767eab60ce0459867edbba6310721ac2dde1ff1e12d15921e488ae3c100aeec863e2f7e31b7a085d9ad7c8972b9b9674aa813d8d565f0704cddd68f01193b1f2393ad3f0ae0b7856f6eb8fe26fdb76e081b64124dc8c33c7abd8c64b52fc6913ffbd635068e2836467739fe42401bbe72999a7eaab9315255376a196b324fd9f1e54a12b037e9bbf33e0c3c11db0f9042183b38409d9243274d1aa41ed93e1f93c2382df8c83462892aedd20f6e0e4e08acb7f6b5b08a599f00c7c461bd6f16e9b6348c1fdc2f48bd42405d873f18992cf6eb9901b5f1bbafd1b23c2e5c56f350c3f50b32b126fe91e9ab56acce794d7f15850d44f794b5dabcc8b13bd695ea78e6757e"),
    (3, 0, HashAlg::Sha512, HashAlg::Sha512, 0, "06802501981e7e0b176e127ff75370c3be64ac9357eb5516286f18d876a3631a235d815194b573719a8ae4365021edf3d08c5a20b7b77183e33d0dda2d3111639522386816f4cbc7b89021d1f1a461728e2fe249f1ee0cde22c61855c9202f4afddf6e37383dfc457aef0a52a7aa57a30387aca0cdb1145babed20afc143b5d727fc57c7ccec6468c232cdb006ad7b6cf665cc996d3fb237f57389c75aea368bb2eae6642a655aa77b791f985858da976a51f86ff98bd91607052eeaa640b2f04eb2def2f9feb335910d119dc561dc89bcfd99b53f935e48ace13a8fbadc581c9165cf441dd3ebcd3b5fd0651ef0aefebb1d62deb7ca1bcd28e01b8c1d155afb023713a09e0e15323f8fc3a3fef9757892af65485200d4dcda13159196d4a3c103fe12597120ecce47ba1d8b8ab03f5491b8d1f9d854337cfe2027c0d06862bdec9f6d58c7cc8fea906f92d29165284b9c8fd421ec480187fc72aa5c55f21ad72ac7a28212ebd45a13c36758459ebf9818b3b325afe10c55f5b91b30383615425c6fade4439bd583fa8283feb0abde177e51bc3d4a24b1fe83cc745e963fe0c6bac6a38656c9c7df85df1f869b3329d7d1ea31c4cd7e54cbda1873fd091bf34c9d93125d3ec3536515a37e876a65875061bebd2b0a0cf8b2ec3df16bb82924d53f4a029634e15f82586282db4d457c20de07957277502a13bf0203ab50fc324f"),
    (3, 1, HashAlg::Sha512, HashAlg::Sha512, 64, "1ae1a25f62ad59771f474bd8e92b4131190fdc7c4c36c254ee70a33f1e5e0e2f7c582d9993c8a73db878960aeaf77c611cd0636d271d3c0138e4e220d3da61dc091634253030e81e004e0458693f71046bf02dd02497ba8d7e9fed69c807347730ec14f1ce58d7db1beaf48e10d15ddbf3609c0741b580aedc601f0e7b362e9b3cc801141db69577f782fe55666a5c7322317cf6a93282c97ebf16573c03b8e60dcc6c74a867537e978914ed530e80f61fdc9748e91e004b45d3437d4f7be5058c2b1cf594bea66c9526e3ad174f86d8cd63f9f00f0e9f29299f1614d0e3b68290f78897c0b58b7ce82c4648464a26a6c1fbbeee5aa3fb28e2778dfa179ec05f8fc2f931fd8b4921c0b1203e41a917c44ee2c0b731ad2975407b5138ea649ac2f119859d46b47bdc9a2342100c54bbca0adbc724c5dc7efd038976d1bf5a541d291fde9ad363a03e6e8d5ac4762c8fbb0e559363532858b307970c94b7c913a387376bf10874dc3414e1a6ab1e467fd2f7fa22c4fb75a11c5190a2dec53d71e08217f57c11afa1c13db5b98affedb3c91777f8228fce3e5beb3e937a12385125b84b361310395fdc4a7ddba15abf0a4610d575bab8381d7929615f827b166e3f17b9cc0615255ff1a24874757a6011769731da0d3674a5514b5c342c26b7c5f0e2c3e762d222dfe4151ca984f9e714fc6fcd9e87ae19d6e23fad4eb92b86719d"),
    (3, 1, HashAlg::Sha256, HashAlg::Sha256, 32, "648f0d5dc786b5b38269a940ef701785c4c6972051b9c9c06dcc6178f04ac739aa0da7c516ba1e946d1fa3ca8b219e526b69ab140a398ea2d2947b8545ed5ddcf3a8056ec8ded39fbbf3aed62a1247b7e021e02689471059ba1c7ff66cf9f187ed4519125506dd11d34ee1662e4ba74ad9376a683c2da15708a7802c358ac51e3e7eb4690426ae2a34c1cd57a30cffb87ff96f1a6b16f2efd0fff9916f5ccb147e46fa228c63bc90785e012b5ac2eb2cc465786508aa4418dbebe9f8795ff3c7fa1d7898d0062f012f718efe2298ad0311d414ee59c18d5096c94e608470bedc7327596df087c6ccdc828a827d002d8712bdd51a23dcf2253dcca2c0af17ebc2b5412b7d91f24afabec97c3ff999a6e60fc5f6f6b65182d33446c406495c93e96d15258b644be6ac21eaeec7ae8a111f6218f602654ed9d8ecf482026c6162f11d098c3d322d8c1d82f9762b2e428c7deff2c50344df0f12315ce2ca018f2a27a6f890b04d0e839a37ed8f36d923749246aecae7536e431bcfa34e70bff08f6f23db76753c0d4502b735b45dd911d96c9836bd04fcab3a0059bbaa39e344920c32f94dd223b0b842a296beaf67861da8b71bb6b64622ee133c3361015f1c69af0ec23e2c1f4552d9f2d748b6a894d6eaf5b4827fe7cb356203fa0389e75bb7af4f45b7a1d78adfd0f1f74b1d9696189ec0a05119f2acdcfd6cea6d3a947303a1"),
    (0, 1, HashAlg::Sha256, HashAlg::Sha256, 0, "1ee4328282f09bfb667fe4d739e0d3d7eb12cb83b0ce88360b41eb7a5d4f9dcc1b9b7fc320876e8f0520ab2da756ba9cf511d1332e37deb2294a545ad03c7272cff68d56cb40a9136034fc833ce648b8ac5ed20578605210a00c0876f1ea1dc38b37f068a4614a34fa0794b1e31b3caf7e3f3f1ffdd60d37631a1cbc5d798b4d4597cc2e052803d57d8377c67a5caf9d144b5e4c22133c9e0fca15039e0b179187782beab2b991d8dc6861fcbf4324a6c7e21b9b3e710b605ea4972d2a7d1f4c0d2e7ac7e5b44780ae545d2cf4b63a292baea67bef9888bdb72c306f5aa3ea57bc5b510bf2ed7fac449f6ac7931f37baca53d3a68077da0115841e5dc0e70ba8"),
    (0, 1, HashAlg::Sha256, HashAlg::Sha256, 20, "0c99e794220dd4972e78c63b91d40344c9dc0f1e0863965f90b0c3c22cd6488b68a4df0e326ccd90c64d06084c4c113e3ec6bf02a66c44f862b3598479f17bf7d05680aef6a8584b9853f2b918dbb051aa26b9c0adbc41c537bb5735dbab1360f6ecc392cd3c3998f96afe98524c79979903652127e018ea4e2018d372c7df13c6da2084076b1cee3991f56e10df65d7d86680daef38dc31f8917aa30129f68cd6e66538c0f4ea1b75acdb396e33cce6e954733df0dc12f80c486e5756a80f12875f08e109a0409b0c61467fe9b2519c59069e9fecbce0e9690c25e1f1c5e7e70b3cc46c9a0228ca609d21778fe8e3d7a419718eb709bbd872b44fc09dd32db8"),
    (0, 1, HashAlg::Sha256, HashAlg::Sha384, 0, "2ac133dba8c235afb0340ca18acc0cee643e908d57ebd1afc7db1f1a195f4b0ea9a1129ad1e2e800a624868e6ddb2aea491ce83ebfd479b7cdc82a8351ba4b38f8dec4c0b2c7934acccfd477cfebe89ee738ab6de3db4c8f4327e51d52c9aa1e959dd74f4933171c84fd07b2934fbf41023e3c4ea0911a076e6419505f136a1be0e61a5eef14c9cbfd2da0347e589fdc2972644f3d4452bb9303b137cfca220848ec43f62ee3f86d6cbb4c0c121bca2b1518aca0bdf7b4ef4fb9fee34207489c523d1a9ea8a881a98f9f67c70ed788c6b171247a1576a8e9e21a68f20b15aab0a9bfedb099123ebf564d4fb4cef4488b30daf491d29547c50c3990b932074802"),
    (0, 1, HashAlg::Sha512, HashAlg::Sha512, 100, "5888de6496ec11fca05ddcb9ac2883f3a4b9294cd2df166f861ec01f9b2b8e30bda4a9a71f593de4cd108c8a262215193506b3299df72260ce3a4a0cb75b69212b017df41e7f8570208a19d970cd09a911881ac65ab084945d1625dfa0da4ebcf7c7d0f31e0d752d5cbf710128857a55dce94fdd68de354492d2c7694558199c0fddcbce7a6964b5e1f89077e2fe359dc7d4c637ff0ef02ee25a64286c7130fc430188cee52f7b11af05abd5150d34d6386db37837e6ffcf70e2cba9fc785b5e682fa91fdf7d6a67fc23823986669d0b17f100d8f2c35e572376b2bf26dca54a0526eb7402e3d1ef8662fd289086449211b3f2b4b853e1ab5973531f1118c4ad"),
];
const RSA_NO_NULL: &str = "17af52c91de38dc86b2b26a240b5e5a849f0aa07ec2295fe59012a2cc6660ab04f2b166e3ae331c58374dd60722e34188093f738eb8361ea38e98ff81a26a1b20a7b0486c73a934ffa90b3f7d9010531f6d0454190f119acbb1886513e980bfcd700fe850097a7daf2cf86ed8b346e38b1c8657f385932829dc2c2013a6ba7aa83463aa8125dc310134b63b562021aca73d34201e6aa799a630e3fdb77b2343dda74acfd71b458ed5236613fe73c97b696c8ab63a6e52fc8e668eb2b13eaecf454226b81881ae1fadfb71df9d2a013f3f766380c541c53f9fca3ffa983fde074abbc294d5b5ae9c5875d49dbaf8d1db4ef2cdebebfce5a188a30f56a977fad2f";
const RSA_2049: (&str, &str) = ("0150e20da1a60a58707863b5294a7b1ea8d27af332685fe8ad27a2bae4d1ef4f8c0acc03c4bd8a38220c11576a022541cc082bf7882af7e2cbee824f71be074f5b3afda40636762d5b29a8be63febe303b85f505ede82a7060bf66de9c3aea6af5ab17fadbbbd06fc82fd7ebdce2f8ff1e1d35f0f030fea5e9c3f0d3918d978b88627286b67e57cfcac88f30485c96fbfaecc33bd222b43acbe39d76ce5fcf15c8682ca20e8ac579015922f32d1ebba86da3120977de0f073cbc85cfa5a2a66e6b67927e930cf4bcc539d0db8846f950120a7cca50f56a2f3f7ebd984de99b97e7dae73f69f5e3738c97db443baae47ec9d1bc0b69b1bd62cbb017adcc4c086ac1", "007acd4e02750c3980122a89e88d8378679dabee4d6f78ec9c561b917eb0761deb2832ff08f327e22ada4f88ab73778e38f467a08deb4e3e488d832760023281a1b9436c7801c7306782e0e91d6fbef6df551bd2ecb70015591ca83071b93f85b3993c079020d6bb709b0e99c315b236cee506f63fc88b3099fc6ddad446ab934ce1108a8dd55528e22a4af8a514f3f1d16ecbb764367c78bc2260d8ddf598089392cfba63cd4525774c5af0ed3a5cadf0aed9931519ff131f13fa63ad08038daf24aea3b1babdea6016b6e5771a1faa65eec4c3de66bc662908811c3d1f2d5137ff6d463ae3bb8369e34dada6fb054dab4fa4d6054fa6d5c4ae125e4889ae4dba");
/// A PSS block that is right in its last 256 bytes, but m has a non-zero byte above them
/// (m = 2^2048 + EM) – must be refused.
const RSA_2049_TOP: &str = "000700a639f463f8e8b36a2db98a0c43ff41ba73e353817112957f435b05d621f33e9ea77d91d1c3f40499ced6544b2ceb691997564450ccf848d30230eefe515a0bcb22d0947468d099bb57e855793806afcda61cbe244a19069faec320dba9ad1f4a1c64da16c87ba3b184b2bb75312532c24a24fad2d060f18397cb9cb6f31a37c7d90f8d616b3f20a1406e4e75ac81b0172ecb4a67eab887d2dfd645fe653c8386913a8abc4548a5489d057980c8dfc2af17934de9af680f87242c9261e1b58fe06b192154852833866ba70293d5b3283917c663cf63231c66d5651340b40db0c92e29ba4e3bbbb40eb22fd9141e9f588019e3c7c2b99d451016ed2f94d1cf";
/// ECDSA: (curve, public key, DER signature of RSA_MSG) – Python `cryptography`; the key
/// of private value 1 (public key = G) and random keys.
const EC_SIGS: &[(Curve, &str, &str)] = &[
    (Curve::P256, "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", "304402205609aafce0bf574ba5fbee1c0e970b22485157272f3695c0abe89f75e22bbda70220082ad555a6eb37e2f4f6dfdef5cd6e00cac6a20c109697ec6d9fbe4a51c2f46c"),
    (Curve::P256, "04a527a172ecee7d0fc64664b36a789634d0a29e3aed8068cc73315a0ae1cd7744fb0a93385f8efe80057e5605d37f427c520ceba677a1fb955bb00d9b48596056", "30450221009d90a7145d3b018a6b1aea000fefa3e851975e1c535e0ec7f38620042351d91b02201713be4a5bd167ecae4c6c244f7e99f253d2ce204d09c8a56faa2e60d04b1e6b"),
    (Curve::P256, "04b49217886e296800b74f1013f8563b3d8617a58d3fa87b025342e150b7013a9cf134c36b73c2c9fd8baf3cf1e1c85a566c5149b02bbfafdf489a8bd7169461da", "30450220442de0c978b21abbbb30002131fe27c3da580ed30f7251d1c891df3d89e5cd28022100cc3761a80e20559ce6aa5cbce7385285549032aaea0f43715e68f07bef2db1f5"),
    (Curve::P384, "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", "30640230723436f981e9de99d2cf069279cdea24d805c931d3b2b071f22d301f681cb3c0a92e7ace1193ea5ee7b4ab0d973579ef023062e5c0f3740cf07d30d894994d1276b8fbf27b59fa39a07fac0cd417ab0c5c2c30957da7b5f8cf97c216b7bc11f6cb8f"),
    (Curve::P384, "047ebda0f1f4dd81325f0da070b3a0900eba7fd7f13d7a104f99f3074e3edd0cdce163dcb72dd5938a1845d0c2ab8d444548bd9ebe59a2f0c5475a29df397fd56fec41e1d454af8cc0638613e33ddcc61f661e5155658c06a634dfee96e2baae90", "306502300e09d933040cb8bcb46dcdc7f5043abc6cace0efc6fb89532fb76689ffbd41f801e0fce4827747077b9ac3c8563035fe023100eca7f3554aa6b4a10ebdb726e3b7bf920e32bce3026909b633a485e8c84f59912f45404e9286dea66d11c5affce99e9c"),
    (Curve::P384, "0455947cc9ee5642e04443e6be1844a8961c54b3b3df1ac34ee2f050b84c89b42c85b513aa0c22f42cb7d33cb79140e8ef5a944a489b45a1dcf5432de8c273139e0069214d54ee5b33a48d00ebae84d7a36bdd4a8a06a42841ed4ab432690167ee", "3065023100c72f4c935f00f98649ebc1893570600e9ffb1fbf2987887e33d09d0e8727eb4b62fbd069a62104b1c07dc2bcfa8e4506023054b9af258bdc56bd93cd3279c27ec9321c3c33bc725ac2a86f0fd173e40cc22785a27120c213e7ead723668e1e881411"),
];
/// (curve, public key, digest, DER signature) – edge digests: all ones (e > n), e = n
/// (u1 = 0), e = 0, e = n + 1; signed as pre-hashed digests.
const EC_DIGESTS: &[(Curve, &str, &str, &str)] = &[
    (Curve::P256, "04a527a172ecee7d0fc64664b36a789634d0a29e3aed8068cc73315a0ae1cd7744fb0a93385f8efe80057e5605d37f427c520ceba677a1fb955bb00d9b48596056", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "3045022100da9503137fa28bf04692a9aa3dbeddaa4fbdbb6a104857e3b2ad5c9aee88442b02205fcc510fe4c922210a10291860bd9409fbd55c8f88e56952a7fea952ce6e4d97"),
    (Curve::P256, "04a527a172ecee7d0fc64664b36a789634d0a29e3aed8068cc73315a0ae1cd7744fb0a93385f8efe80057e5605d37f427c520ceba677a1fb955bb00d9b48596056", "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", "304502206d0dd0445e4d501d2585113a1ab0b88189b29c909617f27efc94537b2e6fc3ae022100b720eaf5fda1b1ba4576607a65cd9f82ed8654a43cd5cf98fe0885b50624c4a4"),
    (Curve::P256, "04a527a172ecee7d0fc64664b36a789634d0a29e3aed8068cc73315a0ae1cd7744fb0a93385f8efe80057e5605d37f427c520ceba677a1fb955bb00d9b48596056", "0000000000000000000000000000000000000000000000000000000000000000", "3045022100d3465e17a1d4344d158cd26a5cfedf7bdb3a54f332433dc69b39f6d21d69475102200183ad86f54b26889ad314fe7cc0fd9a1730d54047414c8e02af88a1d317d262"),
    (Curve::P256, "04a527a172ecee7d0fc64664b36a789634d0a29e3aed8068cc73315a0ae1cd7744fb0a93385f8efe80057e5605d37f427c520ceba677a1fb955bb00d9b48596056", "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552", "3046022100913e1a63457061ceabe247e9987e0cf65b57828ae45279aa7c49ee162f151ed2022100dc756a54b5018575fa8de3b8caf960499305fc85d71ce41f722733a17e958731"),
    (Curve::P384, "047ebda0f1f4dd81325f0da070b3a0900eba7fd7f13d7a104f99f3074e3edd0cdce163dcb72dd5938a1845d0c2ab8d444548bd9ebe59a2f0c5475a29df397fd56fec41e1d454af8cc0638613e33ddcc61f661e5155658c06a634dfee96e2baae90", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "306502303af50d51cb3b3fbbe5623f4532a9b33e17ef2c0a663b863e53417b9eb5815c3340fbf483f1b507eb0be4631b093ec5f5023100ab9f056cd7559d5ceeeb8caee84b7335f29875af7f0dc6f09ad107e0ebd6441cc3a970441d1b9210b515c58199c962ac"),
    (Curve::P384, "047ebda0f1f4dd81325f0da070b3a0900eba7fd7f13d7a104f99f3074e3edd0cdce163dcb72dd5938a1845d0c2ab8d444548bd9ebe59a2f0c5475a29df397fd56fec41e1d454af8cc0638613e33ddcc61f661e5155658c06a634dfee96e2baae90", "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", "3065023100d0390fd0517322d20eefb9a6dc44fa2b5fb2a3aa9a1f37beb55dd0c8082b8d95a3b754053678b39f760282b791f9027902305a9b88229615c7eaadf6dd6cee4d87f23e966a393b9c70082b75fe5e8d43b45ad6a79d7372c70ce55f40d25fea29daff"),
    (Curve::P384, "047ebda0f1f4dd81325f0da070b3a0900eba7fd7f13d7a104f99f3074e3edd0cdce163dcb72dd5938a1845d0c2ab8d444548bd9ebe59a2f0c5475a29df397fd56fec41e1d454af8cc0638613e33ddcc61f661e5155658c06a634dfee96e2baae90", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "3066023100f9636dc5e99001068080bd9d85d9f1da4497e9a05df5e518b32be4b1e1343a36ae35b8b9947761941913f1fba5b7b662023100f71af115559766b6df3fba8aa824687e72bc89929b8af873ac6166cd7b9a22fe4cc47f07469671a711af5e34473201d5"),
    (Curve::P384, "047ebda0f1f4dd81325f0da070b3a0900eba7fd7f13d7a104f99f3074e3edd0cdce163dcb72dd5938a1845d0c2ab8d444548bd9ebe59a2f0c5475a29df397fd56fec41e1d454af8cc0638613e33ddcc61f661e5155658c06a634dfee96e2baae90", "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52974", "3065023036cc41a0437142e2c63c59913d7048d52da3f2d97f8e28493cdfdf20981f18a47ad9f22bb145d1596d396837e700bb93023100c93e0afeb84d473a5eaefcde183a27664a9d1c87f4ffa0fdf6b99b121c3c495f3e8391999ac939c30b5623385b54ea06"),
];
/// (curve, public key, r, s) of a valid signature – the tests build DER variants from it.
const EC_RS: &[(Curve, &str, &str, &str)] = &[
    (Curve::P256, "04a527a172ecee7d0fc64664b36a789634d0a29e3aed8068cc73315a0ae1cd7744fb0a93385f8efe80057e5605d37f427c520ceba677a1fb955bb00d9b48596056", "8afa7cfd53ef10c3a80ff1cb711d0db6061aa31f993323ee69aab30b7f1d8563", "f5b0b590cd0aa58240658a42722ce985294c93f1074b64f396ad1541e8113dfc"),
    (Curve::P384, "047ebda0f1f4dd81325f0da070b3a0900eba7fd7f13d7a104f99f3074e3edd0cdce163dcb72dd5938a1845d0c2ab8d444548bd9ebe59a2f0c5475a29df397fd56fec41e1d454af8cc0638613e33ddcc61f661e5155658c06a634dfee96e2baae90", "21941a90958ba7794063e1ecc1e286925acc66ee70b2fa38fd6a8322e20a4b6bf5437836a054591e72db8764747dc8c0", "744c79bf5ac5b2be3463c2ac4b89db256109a47f953b8fdc05e3914a9eed18609d35caf5f1d250ba7ea650c4c26c5a53"),
];
const RSA_CRAFT_KEY: &str = "d33e702fa9d478a16080fb1278e81472c4617bc9622021db688aeabf914f4d7b23084d9d73e90e59cb82d8f64e2b999a146f1ee7bf1158eb58b8d186771c5bb3ffff598e6dc0529d5786bdaeafc4de1238a41f7b0b763ada7d6bf51636eca1ef4175ad5d7853a111f39e4a9acff1f366d21ed125c24fde48bcae04d31b7831a2a86bb13a1a88bb9d1a7970a1a7c5c0f4151d5bc22eb3c5176501c54bc34fe948afa8502ec4b8f0742554dd43808fddbb11eabe3988aa8c465e4b9828cd6b26c4a7b8a0d7b63755c96e755cdf3a054ec66cac80d26e4ebbc3fb50dfd0ba5c399312454f85839166fbed66c4d58227cb0fa9f4b7853d4374f627477e2a23c38d87";
/// PKCS#1 v1.5 blocks that are almost right (raw RSA with the private key of RSA_CRAFT_KEY).
const RSA_PKCS1_BAD: &[&str] = &[
    // correct (control)
    "14f32994836c1c0d8af720a79087f4c04b68f5ef998c71acc280cedd5901b9fbdfb344c7eaafe00c247da2b44fcac7819f18ecbf7f487a92b3b3cf4114f789f3e5b65591f72c300c3a125c1ea10aa6201e90c217f7197415a6169c424f11a864d946810e15a8aa1ae033a52d9acb2c7583b54a6d2f739415726c7c5cadc5ab3e5588a2d2b22b9130f3affb41003cdfbbfac02bef48fff65de61d126c5325a0f19a56ee66cf13d326953bdc917abc825aa4d9a49fb7062eed496dec0ca0b9fb7186a96aa887a7f157e95a6729b091a75bc2f2f3231b173fa7e19a16a34b812159af1fc42ddfb57769f1a3ea97aa9429d9c182e914d64b2b5873b677ec64816747",
    // padding bytes 0xfe
    "263c25375ed46e5b8eed2896b97188b381727ca47d0bf03d72a1bd423b69d318e32f0f18437e79a6c716014c9b3992ad2c6fd05e8ea0ab4827a8d8a74f3507edf92fc15d04bca02027e528a7c8e8ea9513bc3a795f36d715d6f565068c509ca57b3e571e9bcf2a7b50f39c79b2966d8365e5adddfd270cfd53187d97b40cf06fc0f3246225a21ab4d51b10445899a41b76dfc823167d7ebd8ea6abaada92fd3f8bbb66ca151068feca8f83020af9182a466af1a2c4e03705a83102c55e2de69d02018367afa612a81132367930cb7a4d65d3d0e7e955071bdf962f3c5917e59bf246d36f4f45299e43ab12423d24855b5f231d28262e37c40865d55867e0b01d",
    // block type 2
    "364c5378dd4f547280825753577b2074dede6610d4fbc060e3a24bceffdd1170d73dfbea38e33b41af93e084e0b5afc2b9494048797ed0f7737dce4db408d0cda7d8dd5150193613986112ff7873a6a75045b5cf0e1c8a0dd59fa1c7277d659fa8645fbf0c0c4b347150203424884ae652f6271ec08420f91f8bfebb42044ed7962503af8662779992c9faaa39c6a9a0b7a4e06d0e99406fe3a474bd04a2e150347991b1e79af20396b4c0b64d2728dc4de40858ac263cf699f9f7535a66eea03520e5522926f2d248a8584add02338431cbfcbb6729f4e2886f832d63dc443610d39ab13c3f20d5dafc19c9a8eb8f5610d29754141d8940d27927a7e1127628",
    // no zero separator
    "b1e328ff54b1fb48417d768168d393a5435dcb9dc89cb2fd16e3e61c63cff9c4f07c6b23d881eff8f9a2682382fcdb0e52483f72978aaf71e4c67d792106735deb0ee11ac507e701435a6830dd49e14506ed879aad903377dc503b6218cea0a5ff0528eba5cc03afd3a0a6fbfbf45507f64f92bc9e54be98188e154c1364fe8e24a907dbe554f4e5782eeecdf201ae9a9f4fd2425d67e09241bcbbe81b33978f2907f6e4d28d28041dc97ec8b1564971298814a6626b5e57c08e2ad576b9aa6616733bf7d656fe7a2baca2a6385752dd82be3f51e3b6fbc44faec9d6fdcbe3e7abf453ce0ba196135607879da5ee8ed42dbcf7e13ced42a85fece7116545bf66",
    // one 0xff short, extra byte after the hash
    "afa87914b2e351326bc0455d0861a529bc63e4a107a4bf73087201455a5bc7e907ac4530b4ba3aa86d0c0a403c645d708d76fdad2e791b9d10094869635abb02c0ac6211496f1b6b2fead4c789a9d31b7a365459c2bd98817dc0cbdfea78fd7a2615d5cda583ab84a0cae999b59b0d56632d23bf0cda2a71b720c47431aed9e73f503dbb7985ba049996cf520206078be95b17dadcc96127a675feacfb31a7e9f165b02dde91fe6a0ee3f997318028e51284a04723a4704f0a8459268217c7f5505fe53d365668337ab108f15228e90f59903b267cd1910f7ef048d6acec226d04738b63ff088e0dd7bdd0ae47c072a9ffacea4506013114e31dab6abbd19e72",
    // first byte 1
    "693bb203e14f4698981bed143bd5f36f36df0aee8da05fc78536b4531388b1b72c5dd20c136a28411294c232b110381fcaf18feeba05ce1784c04a526bf9318dcc24d5d96ae9969364bcce1a9193dfdb73da0144f80720015880197136a421fe8d042349763b24658df2afbb6ff344d6d755f65047d67b9909c98397c811352bcda6701a88b3f9015600573fb21de7b5ffcbc43ef36a76aa595073aa512c84ba5d83e168096614cee84f498345bfe0c30d7b52fff3237968f2308d4ef2c3db1596013383ec95ba8c8eb1462d6f84fda8f7fd144b22a4d032197d20c37d75ded9d38529085ced63960c69ed3663275533c14725d2094a7a7ac14270fe6e4cc4a1",
];
/// A PSS block, right except that the top bit of maskedDB (above emBits = 2047) is set.
const RSA_PSS_TOPBIT: &str = "6ef722fa252db061b3f7e763a5514736aee0bb70706e33f08532be06e184847ea8fe03b5417312808ad345bb7d9ee22c22bb5294501f91932d413d0fd8716b21f735026d1f61808e01615acdd11067e84451f2b5f29dbf2e8b935b2185d5e0f8095670a0ab94359bfbfc05bd4b79d330de46b2c9b19d8a903b8a60c712b0247875e735f9559316038b9ca231bf5f8a9673edaf9031029ec084e25493869a009fc7e4cbdeb5ee8de2943c67ceb9cc8bbffec6e598e2c1d5dba135b75f87a756a08e57b3654ecd1644db67a9a09496f21e83f4a25c11b73d6d0e1fa9c590dc838c151b9081f2297da37ca2158e973fe5a465578cf98db4f569fa4c2553b3f9f6a6";
/// P256: a point with a small x (0): (x, y) and the same with x + p (> p, refused).
const P256_SMALL_X: (&str, &str) = ("04000000000000000000000000000000000000000000000000000000000000000066485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4", "04ffffffff00000001000000000000000000000000ffffffffffffffffffffffff66485c780e2f83d72433bd5d84a06bb6541c2af31dae871728bf856a174f93f4");
/// P384: a point with a small x (0): (x, y) and the same with x + p (> p, refused).
const P384_SMALL_X: (&str, &str) = ("04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c306610fb0ae5a159cf45c06069f22a6c5eb3641c602d42dea2c4b4f75550793406d80d2b91ad54f9048bd487af1ade1", "04fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffc306610fb0ae5a159cf45c06069f22a6c5eb3641c602d42dea2c4b4f75550793406d80d2b91ad54f9048bd487af1ade1");
