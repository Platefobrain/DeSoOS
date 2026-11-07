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
// The other expected values (block-edge lengths, empty key, 8160-byte output) were
// computed with an independent implementation (Python hashlib / hmac).

#![allow(dead_code)]

use super::desocrypto::hkdf::{self, MAX_OUTPUT};
use super::desocrypto::hmac::{HmacSha256, MIN_TAG_LEN, hmac_sha256};
use super::desocrypto::chacha20;
use super::desocrypto::rng::KeyErasureRng;
use super::desocrypto::sha256::{MAX_BYTES, Sha256, sha256};
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
