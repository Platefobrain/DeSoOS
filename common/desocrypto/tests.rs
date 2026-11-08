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
// The other expected values (block-edge lengths, empty key, 8160-byte output) were
// computed with an independent implementation (Python hashlib / hmac).

#![allow(dead_code)]

use super::desocrypto::hkdf::{self, MAX_OUTPUT};
use super::desocrypto::hmac::{HmacSha256, MIN_TAG_LEN, hmac_sha256};
use super::desocrypto::chacha20;
use super::desocrypto::aead;
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
