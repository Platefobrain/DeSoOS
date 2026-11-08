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
