// DeSoTLS tests – DER edge cases, times, host names and wildcards, PEM, the CA store
// format, and certificate chains (vectors/certs.bin – made by gen-certs.py – and real server
// chains in vectors/real.bin – gen-real.py).
//
// Not part of the library: included only by /bin/certtest and the kernel CERT TEST, as a
// sibling of `desotls` and `desocrypto`:
//
//   #[path = ".../common/desotls/tests.rs"] mod desotls_tests;
//
// `run()` stops at the first failed check (group and case – for a chain case its number in
// the file, 1-based); on success the number of checks.  No heap, no printing.

#![allow(dead_code)]

use super::desotls::der::{self, Reader};
use super::desotls::roots::{Anchors, DatedAnchors, Roots};
use super::desotls::{name, pem, verify, x509, Error};

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

const CERTS: &[u8] = include_bytes!("vectors/certs.bin");
const REAL: &[u8] = include_bytes!("vectors/real.bin");

pub fn run() -> Result<usize, Failure> {
    let mut c = Checks { group: "", case: 0, passed: 0 };
    der_checks(&mut c)?;
    time_checks(&mut c)?;
    host_checks(&mut c)?;
    constraint_checks(&mut c)?;
    pem_checks(&mut c)?;
    store_checks(&mut c)?;
    chain_cases(&mut c, "chains", CERTS, None)?;
    chain_cases(&mut c, "real chains", REAL, None)?;
    Ok(c.passed)
}

/// The Error's name as written in the vector files.
pub fn error_name(e: Error) -> &'static str {
    match e {
        Error::BadDer => "BadDer",
        Error::UnsupportedVersion => "UnsupportedVersion",
        Error::UnsupportedSignatureAlgorithm => "UnsupportedSignatureAlgorithm",
        Error::AlgorithmMismatch => "AlgorithmMismatch",
        Error::UnsupportedKey => "UnsupportedKey",
        Error::BadKey => "BadKey",
        Error::BadSignature => "BadSignature",
        Error::Expired => "Expired",
        Error::NotYetValid => "NotYetValid",
        Error::UnknownIssuer => "UnknownIssuer",
        Error::NotCa => "NotCa",
        Error::BasicConstraintsNotCritical => "BasicConstraintsNotCritical",
        Error::CaAsLeaf => "CaAsLeaf",
        Error::PathLenExceeded => "PathLenExceeded",
        Error::KeyUsage => "KeyUsage",
        Error::ExtKeyUsage => "ExtKeyUsage",
        Error::NoSubjectAltName => "NoSubjectAltName",
        Error::NameMismatch => "NameMismatch",
        Error::NameConstraintViolation => "NameConstraintViolation",
        Error::UnsupportedNameConstraint => "UnsupportedNameConstraint",
        Error::UnknownCriticalExtension => "UnknownCriticalExtension",
        Error::DuplicateExtension => "DuplicateExtension",
        Error::BadExtension => "BadExtension",
        Error::ChainTooLong => "ChainTooLong",
        Error::TooManySignatureChecks => "TooManySignatureChecks",
        Error::TooManyNames => "TooManyNames",
        Error::Distrusted => "Distrusted",
        Error::CertTooLarge => "CertTooLarge",
        Error::InvalidHost => "InvalidHost",
        Error::IpHostUnsupported => "IpHostUnsupported",
        Error::BadRootStore => "BadRootStore",
        Error::Empty => "Empty",
    }
}

/// One element of `b` as Ok(tag, value length) or the error.
fn tlv(b: &[u8]) -> Result<(u8, usize), Error> {
    let mut r = Reader::new(b);
    let t = r.any()?;
    r.finish()?;
    Ok((t.tag, t.value.len()))
}

fn der_checks(c: &mut Checks) -> Result<(), Failure> {
    c.group("der");
    c.check(tlv(&[0x04, 0x00]) == Ok((0x04, 0)))?;
    c.check(tlv(&[0x04, 0x01, 0xaa]) == Ok((0x04, 1)))?;
    // Length forms: long form only from 128, minimal, at most three bytes; indefinite refused.
    let mut l128 = [0u8; 3 + 128];
    l128[..3].copy_from_slice(&[0x04, 0x81, 0x80]);
    c.check(tlv(&l128) == Ok((0x04, 128)))?;
    c.check(tlv(&[0x04, 0x81, 0x01, 0xaa]) == Err(Error::BadDer))?;
    let mut l256 = [0u8; 4 + 256];
    l256[..4].copy_from_slice(&[0x04, 0x82, 0x01, 0x00]);
    c.check(tlv(&l256) == Ok((0x04, 256)))?;
    l256[..4].copy_from_slice(&[0x04, 0x82, 0x00, 0xff]);
    c.check(tlv(&l256[..4 + 255]) == Err(Error::BadDer))?;
    c.check(tlv(&[0x30, 0x80, 0x00, 0x00]) == Err(Error::BadDer))?;
    c.check(tlv(&[0x04, 0x84, 0x00, 0x00, 0x00, 0x01, 0xaa]) == Err(Error::BadDer))?;
    // Past the end, left over, high tag number, empty input.
    c.check(tlv(&[0x04, 0x02, 0xaa]) == Err(Error::BadDer))?;
    c.check(tlv(&[0x04, 0x00, 0x00]) == Err(Error::BadDer))?;
    c.check(tlv(&[0x1f, 0x01, 0x00]) == Err(Error::BadDer))?;
    c.check(tlv(&[]) == Err(Error::BadDer))?;
    c.check(tlv(&[0x04]) == Err(Error::BadDer))?;
    c.check(tlv(&[0x04, 0x83, 0xff, 0xff, 0xff]) == Err(Error::BadDer))?;
    // BOOLEAN, INTEGER, BIT STRING, NULL, OID.
    let one = |b: &[u8], f: fn(&mut Reader<'_>) -> bool| {
        let mut r = Reader::new(b);
        f(&mut r)
    };
    c.check(one(&[0x01, 0x01, 0xff], |r| r.boolean() == Ok(true)))?;
    c.check(one(&[0x01, 0x01, 0x00], |r| r.boolean() == Ok(false)))?;
    c.check(one(&[0x01, 0x01, 0x01], |r| r.boolean() == Err(Error::BadDer)))?;
    c.check(one(&[0x01, 0x02, 0xff, 0xff], |r| r.boolean() == Err(Error::BadDer)))?;
    c.check(one(&[0x02, 0x01, 0x00], |r| r.integer() == Ok(&[0x00][..])))?;
    c.check(one(&[0x02, 0x02, 0x00, 0x7f], |r| r.integer() == Err(Error::BadDer)))?;
    c.check(one(&[0x02, 0x02, 0x00, 0x80], |r| r.unsigned() == Ok(&[0x80][..])))?;
    c.check(one(&[0x02, 0x02, 0xff, 0x80], |r| r.integer() == Err(Error::BadDer)))?;
    c.check(one(&[0x02, 0x01, 0x80], |r| r.unsigned() == Err(Error::BadDer)))?;
    c.check(one(&[0x02, 0x00], |r| r.integer() == Err(Error::BadDer)))?;
    c.check(one(&[0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00], |r| r.small() == Err(Error::BadDer)))?;
    c.check(one(&[0x02, 0x04, 0x7f, 0xff, 0xff, 0xff], |r| r.small() == Ok(0x7fff_ffff)))?;
    c.check(one(&[0x03, 0x02, 0x00, 0xaa], |r| r.bit_string_bytes() == Ok(&[0xaa][..])))?;
    c.check(one(&[0x03, 0x02, 0x01, 0xaa], |r| r.bit_string_bytes() == Err(Error::BadDer)))?;
    c.check(one(&[0x03, 0x00], |r| r.bit_string_bytes() == Err(Error::BadDer)))?;
    c.check(one(&[0x05, 0x00], |r| r.null().is_ok()))?;
    c.check(one(&[0x05, 0x01, 0x00], |r| r.null() == Err(Error::BadDer)))?;
    c.check(one(&[0x06, 0x03, 0x55, 0x1d, 0x0f], |r| r.oid().is_ok()))?;
    c.check(one(&[0x06, 0x02, 0x80, 0x01], |r| r.oid() == Err(Error::BadDer)))?;
    c.check(one(&[0x06, 0x02, 0x55, 0x81], |r| r.oid() == Err(Error::BadDer)))?;
    c.check(one(&[0x06, 0x00], |r| r.oid() == Err(Error::BadDer)))?;
    // Nesting: 16 levels inside the top one accepted, 17 refused.
    let mut deep = [0u8; 2 * 18];
    for i in 0..18 {
        deep[2 * i] = 0x30;
        deep[2 * i + 1] = (2 * (17 - i)) as u8;
    }
    let depth_ok = |levels: usize, b: &[u8]| -> bool {
        let mut r = Reader::new(b);
        let mut cur = match r.nested(0x30) {
            Ok(x) => x,
            Err(_) => return false,
        };
        for _ in 0..levels {
            cur = match cur.nested(0x30) {
                Ok(x) => x,
                Err(_) => return false,
            };
        }
        true
    };
    c.check(depth_ok(der::MAX_DEPTH as usize - 1, &deep))?;
    c.check(!depth_ok(der::MAX_DEPTH as usize, &deep))?;
    // check_tree walks constructed elements.
    let mut r = Reader::new(&[0x30, 0x03, 0x04, 0x02, 0xaa]);
    c.check(der::check_tree(&mut r) == Err(Error::BadDer))?;
    let mut r = Reader::new(&[0x30, 0x03, 0x04, 0x01, 0xaa]);
    c.check(der::check_tree(&mut r).is_ok())?;
    Ok(())
}

fn t(tag: u8, s: &[u8]) -> Result<i64, Error> {
    der::time(&der::Tlv { tag, value: s, raw: s })
}

fn time_checks(c: &mut Checks) -> Result<(), Failure> {
    c.group("time");
    c.check(t(der::UTC_TIME, b"700101000000Z") == Ok(0))?;
    c.check(t(der::UTC_TIME, b"260601000000Z") == Ok(1_780_272_000))?;
    // UTCTime: 49 -> 2049, 50 -> 1950.
    c.check(t(der::UTC_TIME, b"491231235959Z") == Ok(2_524_607_999))?;
    c.check(t(der::UTC_TIME, b"500101000000Z") == Ok(-631_152_000))?;
    c.check(t(der::GENERALIZED_TIME, b"20510101000000Z") == Ok(2_556_144_000))?;
    // 29 February: 2028 yes, 2100 no, 2000 yes.
    c.check(t(der::UTC_TIME, b"280229120000Z").is_ok())?;
    c.check(t(der::GENERALIZED_TIME, b"21000229120000Z") == Err(Error::BadDer))?;
    c.check(t(der::GENERALIZED_TIME, b"20000229120000Z").is_ok())?;
    c.check(t(der::UTC_TIME, b"270229120000Z") == Err(Error::BadDer))?;
    // Ranges, the Z, the length, fractions, a leap second, the wrong tag.
    for bad in [&b"261301000000Z"[..], b"260001000000Z", b"260132000000Z", b"260431000000Z", b"260601240000Z", b"260601006000Z", b"260601000060Z", b"2606010000Z", b"260601000000", b"260601000000+0100", b"2606010000000Z", b"260601000000X"] {
        c.check(t(der::UTC_TIME, bad) == Err(Error::BadDer))?;
    }
    c.check(t(der::GENERALIZED_TIME, b"20260601000000.5Z") == Err(Error::BadDer))?;
    c.check(t(der::GENERALIZED_TIME, b"260601000000Z") == Err(Error::BadDer))?;
    c.check(t(der::UTC_TIME, b"20260601000000Z") == Err(Error::BadDer))?;
    c.check(t(der::OCTET_STRING, b"260601000000Z") == Err(Error::BadDer))?;
    c.check(t(der::UTC_TIME, b"26o601000000Z") == Err(Error::BadDer))?;
    Ok(())
}

fn host_checks(c: &mut Checks) -> Result<(), Failure> {
    c.group("host names");
    for good in ["example.com", "a.b.c.example.com", "localhost", "xn--bcher-kva.example", "a-b.example", "1a.example", "test.desoos"] {
        c.check(name::check_host(good).is_ok())?;
    }
    for bad in ["", "-a.example", "a-.example", "a..example", ".example", "example.", "exa mple.com", "ex_ample.com", "*.example.com", "é.example"] {
        c.check(name::check_host(bad) == Err(Error::InvalidHost))?;
    }
    let mut long = [b'a'; 254];
    for i in (63..254).step_by(64) {
        long[i] = b'.';
    }
    c.check(name::check_host(core::str::from_utf8(&long[..253]).unwrap_or("")).is_ok())?;
    c.check(name::check_host(core::str::from_utf8(&long).unwrap_or("")) == Err(Error::InvalidHost))?;
    let label64 = [b'a'; 64];
    c.check(name::check_host(core::str::from_utf8(&label64).unwrap_or("")) == Err(Error::InvalidHost))?;
    for ip in ["192.0.2.1", "10.0.0.1", "::1", "fe80::1", "1.2.3.400", "example.123"] {
        c.check(name::check_host(ip) == Err(Error::IpHostUnsupported))?;
    }

    c.group("name matching");
    let m = |n: &str, h: &str| name::matches(n.as_bytes(), h);
    c.check(m("example.com", "example.com") && m("EXAMPLE.com", "example.COM"))?;
    c.check(!m("example.com", "www.example.com") && !m("www.example.com", "example.com"))?;
    c.check(m("*.example.com", "www.example.com") && m("*.EXAMPLE.com", "WWW.example.com"))?;
    c.check(!m("*.example.com", "example.com") && !m("*.example.com", "a.b.example.com"))?;
    c.check(!m("*.com", "example.com") && !m("*.a", "b.a"))?;
    c.check(!m("f*.example.com", "foo.example.com") && !m("*o.example.com", "foo.example.com"))?;
    c.check(!m("www.*.com", "www.example.com") && !m("*", "example") && !m("*.", "a."))?;
    c.check(!m("*.*.example.com", "a.b.example.com"))?;
    c.check(!m("example.com.", "example.com") && !m("", "example.com"))?;
    c.check(m("xn--bcher-kva.example", "xn--bcher-kva.example") && !m("bücher.example", "xn--bcher-kva.example"))?;
    Ok(())
}

/// A list of excluded / permitted subtrees (GeneralSubtree SEQUENCEs with dNSName bases)
/// written into `out`; its length.
fn subtrees(names: &[&str], out: &mut [u8; 256]) -> usize {
    let mut n = 0;
    for name in names {
        let b = name.as_bytes();
        out[n] = 0x30;
        out[n + 1] = (b.len() + 2) as u8;
        out[n + 2] = 0x82;
        out[n + 3] = b.len() as u8;
        out[n + 4..n + 4 + b.len()].copy_from_slice(b);
        n += 4 + b.len();
    }
    n
}

/// Name constraints on a wildcard, each of the two checks on its own (a change to one cannot
/// hide behind the other), and the same subtrees against plain names.
fn constraint_checks(c: &mut Checks) -> Result<(), Failure> {
    c.group("name constraints");
    let mut buf = [0u8; 256];
    // (excluded subtree, any_subtree on "*.example.com", wildcard_covers_any, check_constraints refuses)
    let wild: [(&str, bool, bool, bool); 8] = [
        ("example.com", true, false, true),
        ("com", true, false, true),
        ("EXAMPLE.COM", true, false, true),
        ("foo.example.com", false, true, true),
        ("Foo.Example.Com", false, true, true),
        ("a.foo.example.com", false, false, false),
        ("notexample.com", false, false, false),
        ("example.org", false, false, false),
    ];
    for (ex, sub, cover, refused) in wild {
        let n = subtrees(&[ex], &mut buf);
        let list = &buf[..n];
        c.check(name::any_subtree(list, b"*.example.com") == Ok(sub))?;
        c.check(name::wildcard_covers_any(list, b"*.example.com") == Ok(cover))?;
        let nc = x509::NameConstraints { permitted: None, excluded: Some(list) };
        let san = [0x82, 13, b'*', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm'];
        let r = name::check_constraints(&nc, Some(&san));
        c.check(r == if refused { Err(Error::NameConstraintViolation) } else { Ok(()) })?;
    }
    // Plain names: (name, excluded subtree, refused) – the wildcard rule never applies.
    let plain: [(&str, &str, bool); 9] = [
        ("www.example.com", "example.com", true),
        ("example.com", "example.com", true),
        ("www.example.com", "com", true),
        ("www.example.com", "www.example.com", true),
        ("www.example.com", "foo.example.com", false),
        ("www.example.com", "a.www.example.com", false),
        ("foo.example.com", "a.foo.example.com", false),
        ("notexample.com", "example.com", false),
        ("example.com", "www.example.com", false),
    ];
    for (host, ex, refused) in plain {
        let n = subtrees(&[ex], &mut buf);
        let list = &buf[..n];
        c.check(name::wildcard_covers_any(list, host.as_bytes()) == Ok(false))?;
        let mut san = [0u8; 64];
        san[0] = 0x82;
        san[1] = host.len() as u8;
        san[2..2 + host.len()].copy_from_slice(host.as_bytes());
        let nc = x509::NameConstraints { permitted: None, excluded: Some(list) };
        let r = name::check_constraints(&nc, Some(&san[..2 + host.len()]));
        c.check(r == if refused { Err(Error::NameConstraintViolation) } else { Ok(()) })?;
    }
    // Two subtrees: the wildcard is hit by the second.
    let n = subtrees(&["a.foo.example.com", "bar.example.com"], &mut buf);
    c.check(name::wildcard_covers_any(&buf[..n], b"*.example.com") == Ok(true))?;
    Ok(())
}

const PEM_ONE: &[u8] = b"text before\n-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\nbetween\n-----BEGIN CERTIFICATE-----\r\nBAEC\r\nAw==\r\n-----END CERTIFICATE-----\n";

fn pem_checks(c: &mut Checks) -> Result<(), Failure> {
    c.group("pem");
    let mut out = [0u8; 64];
    let mut spans = [(0usize, 0usize); 4];
    let n = pem::certificates(PEM_ONE, &mut out, &mut spans);
    c.check(n == Ok(2))?;
    c.check(&out[spans[0].0..spans[0].0 + spans[0].1] == [0x30, 0x00])?;
    c.check(&out[spans[1].0..spans[1].0 + spans[1].1] == [0x04, 0x01, 0x02, 0x03])?;
    let b64 = |s: &[u8], out: &mut [u8; 64]| pem::base64(s, out);
    c.check(b64(b"YWJj", &mut out) == Ok(3) && &out[..3] == b"abc")?;
    c.check(b64(b"YWI=", &mut out) == Ok(2) && &out[..2] == b"ab")?;
    c.check(b64(b"YQ==", &mut out) == Ok(1) && out[0] == b'a')?;
    for bad in [&b"YWJ"[..], b"YW=j", b"Y===", b"A===", b"YWJj*", b"YR==", b"YWJ=YWJj"] {
        c.check(b64(bad, &mut out) == Err(Error::BadDer))?;
    }
    c.check(pem::certificates(b"-----BEGIN CERTIFICATE-----\nMAA=\n", &mut out, &mut spans) == Err(Error::BadDer))?;
    c.check(pem::certificates(b"no certificate here", &mut out, &mut spans) == Ok(0))?;
    let mut small = [0u8; 1];
    c.check(pem::certificates(PEM_ONE, &mut small, &mut spans) == Err(Error::CertTooLarge))?;
    let mut one = [(0usize, 0usize); 1];
    c.check(pem::certificates(PEM_ONE, &mut out, &mut one) == Err(Error::ChainTooLong))?;
    Ok(())
}

/// A small store: two anchors (the second with a distrust date).
fn make_store(out: &mut [u8; 96]) -> usize {
    let mut n = 0;
    let mut put = |b: &[u8]| {
        out[n..n + b.len()].copy_from_slice(b);
        n += b.len();
    };
    put(b"DSCR");
    put(&[0, 1, 0, 2, 3]);
    put(b"T11");
    put(&[0xab; 32]);
    put(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0x30, 0x00]);
    put(&[0, 0, 0, 0, 0x60, 0, 0, 0, 0, 3, 0x04, 0x01, 0x07]);
    n
}

fn store_checks(c: &mut Checks) -> Result<(), Failure> {
    c.group("ca store");
    let mut buf = [0u8; 96];
    let n = make_store(&mut buf);
    let r = Roots::parse(&buf[..n]);
    c.check(r.as_ref().is_ok_and(|r| r.len() == 2 && r.nss_tag == "T11" && r.certdata_sha256 == [0xab; 32]))?;
    if let Ok(r) = &r {
        let mut seen = [(0usize, 0i64); 2];
        let mut i = 0;
        r.each(&mut |der, when| {
            seen[i] = (der.len(), when);
            i += 1;
            true
        });
        c.check(i == 2 && seen[0] == (2, 0) && seen[1] == (3, 0x6000_0000))?;
    }
    // Damaged stores: magic, version, count, a length past the end, bytes left over, empty.
    let damaged = |f: &dyn Fn(&mut [u8; 96]), len: usize| {
        let mut b = buf;
        f(&mut b);
        Roots::parse(&b[..len]).err() == Some(Error::BadRootStore)
    };
    c.check(damaged(&|b| b[0] = b'X', n))?;
    c.check(damaged(&|b| b[5] = 2, n))?;
    c.check(damaged(&|b| b[7] = 3, n))?;
    c.check(damaged(&|b| b[7] = 0, n))?;
    c.check(damaged(&|_| {}, n - 1))?;
    c.check(damaged(&|_| {}, n + 1))?;
    c.check(damaged(&|_| {}, 8))?;
    c.check(damaged(&|b| b[8] = 60, n))?;
    Ok(())
}

/// The real Mozilla store (the kernel test reads /etc/certs/roots): it parses, every anchor
/// but the known unsupported ones parses as a certificate with a usable key, and the real
/// chains whose CA is still in it verify against it.  Returns (anchors, usable).
pub fn real_store(data: &[u8]) -> Result<(usize, usize), Failure> {
    let mut c = Checks { group: "mozilla store", case: 0, passed: 0 };
    let r = Roots::parse(data);
    c.check(r.is_ok())?;
    let Ok(r) = r else { return Err(Failure { group: "mozilla store", case: 1 }) };
    let mut usable = 0;
    let mut broken = 0;
    r.each(&mut |der, _| {
        match x509::Cert::parse(der, true) {
            Ok(cert) if cert.key.is_ok() => usable += 1,
            Ok(_) => {}
            Err(_) => broken += 1,
        }
        true
    });
    c.check(broken == 0 && usable + 2 >= r.len())?;
    chain_cases(&mut c, "real chains, Mozilla store", REAL, Some(&r))?;
    Ok((r.len(), usable))
}

fn be16(b: &[u8]) -> usize {
    (b[0] as usize) << 8 | b[1] as usize
}

/// Runs every case of a vector file.  With `store`, the anchors come from it instead of the
/// case – then only cases whose answer does not depend on the anchor set are run (OK cases
/// whose anchor is in the store, and the name / time failures).
fn chain_cases(c: &mut Checks, group: &'static str, data: &[u8], store: Option<&Roots<'_>>) -> Result<(), Failure> {
    c.group(group);
    let bad = Failure { group, case: 0 };
    if data.len() < 8 || &data[..4] != b"DSCC" || be16(&data[4..6]) != 1 {
        return Err(bad);
    }
    let count = be16(&data[6..8]);
    let mut p = 8;
    let take = |p: &mut usize, n: usize| -> Result<&[u8], Failure> {
        let s = data.get(*p..*p + n).ok_or(bad)?;
        *p += n;
        Ok(s)
    };
    for k in 0..count {
        let ln = take(&mut p, 1)?[0] as usize;
        let _name = take(&mut p, ln)?;
        let le = take(&mut p, 1)?[0] as usize;
        let expected = take(&mut p, le)?;
        let lh = take(&mut p, 1)?[0] as usize;
        let host = core::str::from_utf8(take(&mut p, lh)?).map_err(|_| bad)?;
        let mut now = [0u8; 8];
        now.copy_from_slice(take(&mut p, 8)?);
        let now = i64::from_be_bytes(now);
        let na = take(&mut p, 1)?[0] as usize;
        let mut anchors: [(&[u8], i64); 40] = [(&[], 0); 40];
        if na > anchors.len() {
            return Err(bad);
        }
        for a in anchors.iter_mut().take(na) {
            let mut w = [0u8; 8];
            w.copy_from_slice(take(&mut p, 8)?);
            let l = be16(take(&mut p, 2)?);
            *a = (take(&mut p, l)?, i64::from_be_bytes(w));
        }
        let nc = take(&mut p, 1)?[0] as usize;
        let mut chain: [&[u8]; 12] = [&[]; 12];
        if nc > chain.len() {
            return Err(bad);
        }
        for cc in chain.iter_mut().take(nc) {
            let l = be16(take(&mut p, 2)?);
            *cc = take(&mut p, l)?;
        }
        let list = DatedAnchors(&anchors[..na]);
        let r = match store {
            Some(s) => verify::server(&chain[..nc], s, host, now),
            None => verify::server(&chain[..nc], &list, host, now),
        };
        let got = match r {
            Ok(_) => "OK",
            Err(e) => error_name(e),
        };
        let mut want = expected;
        if let Some(s) = store {
            // Against the store: an OK case whose CA left it becomes UnknownIssuer.
            if want == b"OK" && got == "UnknownIssuer" && !anchor_in(s, anchors[0].0) {
                want = b"UnknownIssuer";
            }
            if want == b"UnknownIssuer" && got == "OK" {
                // "wrong root" cases: the store may hold the right one.
                want = b"OK";
            }
        }
        c.case = k;
        c.check(got.as_bytes() == want)?;
    }
    c.check(p == data.len())
}

/// One case of real.bin (0-based): (host, time, anchor, chain, chain length) – for the kernel
/// test that feeds a real chain to /bin/certcheck.
pub fn real_case(index: usize) -> Option<(&'static str, i64, &'static [u8], [&'static [u8]; 4], usize)> {
    let d = REAL;
    let mut p = 8;
    let mut take = |n: usize| -> Option<&'static [u8]> {
        let s = d.get(p..p + n)?;
        p += n;
        Some(s)
    };
    let count = be16(d.get(6..8)?);
    for k in 0..count {
        let ln = take(1)?[0] as usize;
        take(ln)?;
        let le = take(1)?[0] as usize;
        take(le)?;
        let lh = take(1)?[0] as usize;
        let host = core::str::from_utf8(take(lh)?).ok()?;
        let mut now = [0u8; 8];
        now.copy_from_slice(take(8)?);
        let na = take(1)?[0] as usize;
        let mut anchor: &[u8] = &[];
        for _ in 0..na {
            take(8)?;
            let l = be16(take(2)?);
            anchor = take(l)?;
        }
        let nc = take(1)?[0] as usize;
        let mut chain: [&[u8]; 4] = [&[]; 4];
        for i in 0..nc {
            let l = be16(take(2)?);
            let c = take(l)?;
            if i < 4 {
                chain[i] = c;
            }
        }
        if k == index {
            return Some((host, i64::from_be_bytes(now), anchor, chain, nc.min(4)));
        }
    }
    None
}

fn anchor_in(s: &Roots<'_>, der: &[u8]) -> bool {
    let mut found = false;
    s.each(&mut |a, _| {
        found |= a == der;
        !found
    });
    found
}
