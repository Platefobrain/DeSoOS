// One X.509 certificate (RFC 5280), read strictly – the DeSoTLS profile:
//
//   version      v3 (a v1 certificate only as a trust anchor; v2 never)
//   keys         rsaEncryption (NULL parameters; n and e checked by desocrypto::rsa when used),
//                id-ecPublicKey on P-256 / P-384 (uncompressed point); anything else is
//                UnsupportedKey – an RSASSA-PSS key in the SPKI too
//   signatures   sha256/384/512WithRSAEncryption (NULL or absent parameters – RFC 4055 §5), id-RSASSA-PSS with
//                explicit parameters (hash SHA-256/384/512, MGF1 with the same hash, salt
//                >= 20, trailer 1 – default values must not be written out: DER), ECDSA with
//                SHA-256 (P-256 issuer) or SHA-384 (P-384 issuer); the inner and outer
//                algorithm identifiers must be byte-identical
//   extensions   basicConstraints, keyUsage, extKeyUsage, subjectAltName, nameConstraints,
//                authority / subject key identifiers are understood; any other critical
//                extension is refused, a non-critical one ignored; a duplicate, an empty or a
//                malformed one is refused; "critical FALSE" written out is not DER (refused)
//   names        issuer and subject kept as their DER bytes (compared byte for byte),
//                walked once to know they are well-formed
//
// A trust anchor may carry a key or a self-signature algorithm outside the list (an old
// root signed with SHA-1, a P-521 root): `key` / `sig_alg` keep the error, which only
// matters if the anchor is actually used.

use super::crypto::ecdsa::Curve;
use super::crypto::hash::HashAlg;
use super::crypto::rsa::PssParams;
use super::der::{self, Reader, Tlv};
use super::Error;

const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];
const OID_RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const OID_RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_RSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const OID_EC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
const OID_EXT_SKI: &[u8] = &[0x55, 0x1d, 0x0e];
const OID_EXT_KU: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_EXT_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_EXT_BC: &[u8] = &[0x55, 0x1d, 0x13];
const OID_EXT_NC: &[u8] = &[0x55, 0x1d, 0x1e];
const OID_EXT_AKI: &[u8] = &[0x55, 0x1d, 0x23];
const OID_EXT_EKU: &[u8] = &[0x55, 0x1d, 0x25];
pub const OID_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
pub const OID_ANY_EKU: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];

/// keyUsage bits (bit 0 = the first, most significant bit).
pub const KU_DIGITAL_SIGNATURE: u16 = 1 << 0;
pub const KU_KEY_CERT_SIGN: u16 = 1 << 5;

/// The most extensions in one certificate (far above real ones – a bound on the work).
const MAX_EXTENSIONS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key<'a> {
    /// n and e without sign bytes.
    Rsa { n: &'a [u8], e: &'a [u8] },
    /// 04 ‖ X ‖ Y.
    Ec { curve: Curve, point: &'a [u8] },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigAlg {
    RsaPkcs1(HashAlg),
    RsaPss(PssParams),
    /// The curve the issuer's key must be on (its one hash: P-256/SHA-256, P-384/SHA-384).
    Ecdsa(Curve),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BasicConstraints {
    pub ca: bool,
    pub path_len: Option<u32>,
    pub critical: bool,
}

/// The contents of the two GeneralSubtrees (each a list of GeneralSubtree SEQUENCEs, only
/// dNSName bases – checked when parsed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameConstraints<'a> {
    pub permitted: Option<&'a [u8]>,
    pub excluded: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Debug)]
pub struct Cert<'a> {
    pub der: &'a [u8],
    /// The signed part (tbsCertificate, whole encoding).
    pub tbs: &'a [u8],
    pub sig_alg: Result<SigAlg, Error>,
    /// The signature bytes (for ECDSA: the DER Ecdsa-Sig-Value).
    pub signature: &'a [u8],
    pub version: u8,
    pub serial: &'a [u8],
    /// Issuer and subject Name, whole DER encodings.
    pub issuer: &'a [u8],
    pub subject: &'a [u8],
    pub not_before: i64,
    pub not_after: i64,
    pub key: Result<Key<'a>, Error>,
    pub basic: Option<BasicConstraints>,
    pub key_usage: Option<u16>,
    /// extKeyUsage: the contents of the SEQUENCE OF OID.
    pub eku: Option<&'a [u8]>,
    /// subjectAltName: the contents of the SEQUENCE OF GeneralName.
    pub san: Option<&'a [u8]>,
    pub name_constraints: Option<Result<NameConstraints<'a>, Error>>,
    pub ski: Option<&'a [u8]>,
    pub aki: Option<&'a [u8]>,
}

impl<'a> Cert<'a> {
    /// Parses one certificate.  `anchor`: a trust anchor from the store (v1 allowed).
    pub fn parse(der: &'a [u8], anchor: bool) -> Result<Cert<'a>, Error> {
        let mut top = Reader::new(der);
        let cert = top.read(der::SEQUENCE)?;
        top.finish()?;
        let mut c = top.enter(&cert)?;
        let tbs = c.read(der::SEQUENCE)?;
        let outer_alg = c.read(der::SEQUENCE)?;
        let signature = c.bit_string_bytes()?;
        c.finish()?;

        let mut t = c.enter(&tbs)?;
        let version = match t.optional(der::context(0))? {
            Some(v) => {
                let mut vr = t.enter(&v)?;
                let n = vr.small()?;
                vr.finish()?;
                // v1 must not be written out (DEFAULT); v2 is not supported.
                if n != 2 {
                    return Err(Error::UnsupportedVersion);
                }
                3
            }
            None => 1,
        };
        if version == 1 && !anchor {
            return Err(Error::UnsupportedVersion);
        }
        let serial = t.integer()?;
        if serial.len() > 21 {
            return Err(Error::BadDer);
        }
        let inner_alg = t.read(der::SEQUENCE)?;
        let issuer = t.read(der::SEQUENCE)?;
        check_name(&t, &issuer)?;
        // RFC 5280 4.1.2.4: the issuer must not be empty.
        if issuer.value.is_empty() {
            return Err(Error::BadDer);
        }
        let mut validity = t.nested(der::SEQUENCE)?;
        let nb = validity.any()?;
        let na = validity.any()?;
        validity.finish()?;
        let not_before = der::time(&nb)?;
        let not_after = der::time(&na)?;
        let subject = t.read(der::SEQUENCE)?;
        check_name(&t, &subject)?;
        let spki = t.read(der::SEQUENCE)?;
        let key = parse_key(&t, &spki)?;

        // Unique identifiers ([1], [2]) are not part of the profile.
        if matches!(t.peek_tag(), Some(0x81) | Some(0x82) | Some(0xa1) | Some(0xa2)) {
            return Err(Error::BadDer);
        }
        let mut cert = Cert {
            der,
            tbs: tbs.raw,
            sig_alg: Err(Error::UnsupportedSignatureAlgorithm),
            signature,
            version,
            serial,
            issuer: issuer.raw,
            subject: subject.raw,
            not_before,
            not_after,
            key,
            basic: None,
            key_usage: None,
            eku: None,
            san: None,
            name_constraints: None,
            ski: None,
            aki: None,
        };
        if let Some(exts) = t.optional(der::context(3))? {
            if version != 3 {
                return Err(Error::BadDer);
            }
            let mut wrapper = t.enter(&exts)?;
            let seq = wrapper.read(der::SEQUENCE)?;
            wrapper.finish()?;
            parse_extensions(&wrapper, &seq, &mut cert)?;
        }
        t.finish()?;
        // A CA must have a subject; an empty subject needs subjectAltName (RFC 5280 4.1.2.6).
        if subject.value.is_empty() && (cert.basic.is_some_and(|b| b.ca) || cert.san.is_none()) {
            return Err(Error::BadDer);
        }

        if inner_alg.raw != outer_alg.raw {
            return Err(Error::AlgorithmMismatch);
        }
        cert.sig_alg = parse_sig_alg(&c, &outer_alg);
        if !anchor {
            cert.sig_alg?;
        }
        Ok(cert)
    }

    /// Issuer and subject are the same bytes (the strict reading of RFC 5280 §7.1 – see
    /// verify.rs).
    pub fn self_issued(&self) -> bool {
        self.issuer == self.subject
    }

    pub fn has_eku(&self, oid: &[u8]) -> bool {
        let Some(list) = self.eku else { return false };
        let mut r = Reader::new(list);
        while let Ok(o) = r.oid() {
            if o == oid {
                return true;
            }
        }
        false
    }

    /// The first commonName of the subject, if it is printable text (for messages only).
    pub fn subject_cn(&self) -> Option<&'a str> {
        name_cn(self.subject)
    }
}

/// The first commonName in a Name (PrintableString / UTF8String / IA5String), for messages.
pub fn name_cn(name: &[u8]) -> Option<&str> {
    let mut top = Reader::new(name);
    let mut rdns = top.nested(der::SEQUENCE).ok()?;
    while !rdns.is_empty() {
        let mut set = rdns.nested(der::SET).ok()?;
        while !set.is_empty() {
            let mut atv = set.nested(der::SEQUENCE).ok()?;
            let oid = atv.oid().ok()?;
            let v = atv.any().ok()?;
            if oid == OID_CN && matches!(v.tag, der::PRINTABLE_STRING | der::UTF8_STRING | der::IA5_STRING) {
                return core::str::from_utf8(v.value).ok();
            }
        }
    }
    None
}

/// A Name: SEQUENCE OF SET OF SEQUENCE { OID, value } – walked, so it is well-formed.
fn check_name(r: &Reader<'_>, name: &Tlv<'_>) -> Result<(), Error> {
    let mut rdns = r.enter(name)?;
    while !rdns.is_empty() {
        let mut set = rdns.nested(der::SET)?;
        if set.is_empty() {
            return Err(Error::BadDer);
        }
        while !set.is_empty() {
            let mut atv = set.nested(der::SEQUENCE)?;
            atv.oid()?;
            let v = atv.any()?;
            if v.tag & 0x20 != 0 {
                let mut inner = atv.enter(&v)?;
                der::check_tree(&mut inner)?;
            }
            atv.finish()?;
        }
    }
    Ok(())
}

fn hash_from_oid(oid: &[u8]) -> Option<HashAlg> {
    match oid {
        OID_SHA256 => Some(HashAlg::Sha256),
        OID_SHA384 => Some(HashAlg::Sha384),
        OID_SHA512 => Some(HashAlg::Sha512),
        _ => None,
    }
}

/// SubjectPublicKeyInfo.  A malformed SPKI is BadDer (the certificate is broken); a
/// well-formed one of an unsupported type is kept as Err(UnsupportedKey).
fn parse_key<'a>(r: &Reader<'a>, spki: &Tlv<'a>) -> Result<Result<Key<'a>, Error>, Error> {
    let mut s = r.enter(spki)?;
    let mut alg = s.nested(der::SEQUENCE)?;
    let key_bits = s.bit_string_bytes()?;
    s.finish()?;
    let oid = alg.oid()?;
    if oid == OID_RSA {
        alg.null()?;
        alg.finish()?;
        let mut kr = Reader::new(key_bits);
        let mut seq = kr.nested(der::SEQUENCE)?;
        kr.finish()?;
        let n = seq.unsigned()?;
        let e = seq.unsigned()?;
        seq.finish()?;
        return Ok(Ok(Key::Rsa { n, e }));
    }
    if oid == OID_EC_KEY {
        let curve_oid = alg.oid()?;
        alg.finish()?;
        let curve = match curve_oid {
            OID_P256 => Curve::P256,
            OID_P384 => Curve::P384,
            _ => return Ok(Err(Error::UnsupportedKey)),
        };
        if key_bits.len() != 1 + 2 * curve.field_len() || key_bits[0] != 0x04 {
            return Ok(Err(Error::BadKey));
        }
        return Ok(Ok(Key::Ec { curve, point: key_bits }));
    }
    let mut rest = alg;
    der::check_tree(&mut rest)?;
    Ok(Err(Error::UnsupportedKey))
}

/// The signature AlgorithmIdentifier.
fn parse_sig_alg(r: &Reader<'_>, alg: &Tlv<'_>) -> Result<SigAlg, Error> {
    let mut a = r.enter(alg)?;
    let oid = a.oid()?;
    // RFC 4055 §5: the parameters MUST be NULL, and implementations MUST accept them absent
    // too (real certificates are issued that way).
    let pkcs1 = |h: HashAlg, a: &mut Reader<'_>| -> Result<SigAlg, Error> {
        if !a.is_empty() {
            a.null()?;
        }
        a.finish()?;
        Ok(SigAlg::RsaPkcs1(h))
    };
    match oid {
        OID_RSA_SHA256 => pkcs1(HashAlg::Sha256, &mut a),
        OID_RSA_SHA384 => pkcs1(HashAlg::Sha384, &mut a),
        OID_RSA_SHA512 => pkcs1(HashAlg::Sha512, &mut a),
        OID_ECDSA_SHA256 => {
            a.finish()?;
            Ok(SigAlg::Ecdsa(Curve::P256))
        }
        OID_ECDSA_SHA384 => {
            a.finish()?;
            Ok(SigAlg::Ecdsa(Curve::P384))
        }
        OID_RSA_PSS => {
            let mut p = a.nested(der::SEQUENCE)?;
            a.finish()?;
            parse_pss(&mut p)
        }
        _ => Err(Error::UnsupportedSignatureAlgorithm),
    }
}

/// A hash AlgorithmIdentifier inside the PSS parameters (parameters absent or NULL – RFC 4055
/// asks to accept both).
fn pss_hash(r: &mut Reader<'_>) -> Result<HashAlg, Error> {
    let mut a = r.nested(der::SEQUENCE)?;
    let oid = a.oid()?;
    if !a.is_empty() {
        a.null()?;
    }
    a.finish()?;
    hash_from_oid(oid).ok_or(Error::UnsupportedSignatureAlgorithm)
}

/// RSASSA-PSS-params (RFC 4055 / 8017): every field read from the encoding, nothing guessed.
fn parse_pss(p: &mut Reader<'_>) -> Result<SigAlg, Error> {
    // [0] hashAlgorithm – the default (SHA-1) is not allowed, so it must be there.
    let mut h = p.optional(der::context(0))?.ok_or(Error::UnsupportedSignatureAlgorithm).and_then(|t| p.enter(&t))?;
    let hash = pss_hash(&mut h)?;
    h.finish()?;
    // [1] maskGenAlgorithm = MGF1 with the same hash.
    let mut m = p.optional(der::context(1))?.ok_or(Error::UnsupportedSignatureAlgorithm).and_then(|t| p.enter(&t))?;
    let mut mgf = m.nested(der::SEQUENCE)?;
    m.finish()?;
    if mgf.oid()? != OID_MGF1 {
        return Err(Error::UnsupportedSignatureAlgorithm);
    }
    let mgf_hash = pss_hash(&mut mgf)?;
    mgf.finish()?;
    if mgf_hash != hash {
        return Err(Error::UnsupportedSignatureAlgorithm);
    }
    // [2] saltLength, default 20 (a written-out 20 is not DER).
    let salt_len = match p.optional(der::context(2))? {
        Some(t) => {
            let mut s = p.enter(&t)?;
            let v = s.small()?;
            s.finish()?;
            if v == 20 {
                return Err(Error::BadDer);
            }
            v as usize
        }
        None => 20,
    };
    if !(20..=512).contains(&salt_len) {
        return Err(Error::UnsupportedSignatureAlgorithm);
    }
    // [3] trailerField: only the default 1, which DER does not write.
    if p.peek_tag().is_some() {
        return Err(Error::UnsupportedSignatureAlgorithm);
    }
    Ok(SigAlg::RsaPss(PssParams { hash, mgf_hash, salt_len }))
}

fn parse_extensions<'a>(r: &Reader<'a>, seq: &Tlv<'a>, c: &mut Cert<'a>) -> Result<(), Error> {
    let mut list = r.enter(seq)?;
    if list.is_empty() {
        return Err(Error::BadExtension);
    }
    let mut seen: [&[u8]; MAX_EXTENSIONS] = [&[]; MAX_EXTENSIONS];
    let mut n = 0;
    let mut san_critical = false;
    while !list.is_empty() {
        let mut e = list.nested(der::SEQUENCE)?;
        let oid = e.oid()?;
        let critical = if e.peek_tag() == Some(der::BOOLEAN) {
            // DEFAULT FALSE: only TRUE may be written.
            if !e.boolean()? {
                return Err(Error::BadDer);
            }
            true
        } else {
            false
        };
        let value = e.read(der::OCTET_STRING)?;
        e.finish()?;
        if n == MAX_EXTENSIONS {
            return Err(Error::BadExtension);
        }
        if seen[..n].contains(&oid) {
            return Err(Error::DuplicateExtension);
        }
        seen[n] = oid;
        n += 1;
        let mut v = e.enter(&value)?;
        match oid {
            OID_EXT_BC => c.basic = Some(parse_basic(&mut v, critical)?),
            OID_EXT_KU => c.key_usage = Some(parse_key_usage(&mut v)?),
            OID_EXT_EKU => {
                let mut l = v.nested(der::SEQUENCE).map_err(|_| Error::BadExtension)?;
                if l.is_empty() {
                    return Err(Error::BadExtension);
                }
                let contents = l.rest();
                while !l.is_empty() {
                    l.oid().map_err(|_| Error::BadExtension)?;
                }
                c.eku = Some(contents);
            }
            OID_EXT_SAN => {
                let mut l = v.nested(der::SEQUENCE).map_err(|_| Error::BadExtension)?;
                if l.is_empty() {
                    return Err(Error::BadExtension);
                }
                let contents = l.rest();
                let mut count = 0;
                while !l.is_empty() {
                    let g = l.any().map_err(|_| Error::BadExtension)?;
                    if g.tag & 0x20 != 0 {
                        let mut inner = l.enter(&g)?;
                        der::check_tree(&mut inner).map_err(|_| Error::BadExtension)?;
                    }
                    count += 1;
                    if count > super::name::MAX_NAMES {
                        return Err(Error::TooManyNames);
                    }
                }
                c.san = Some(contents);
                san_critical = critical;
            }
            OID_EXT_NC => c.name_constraints = Some(parse_nc(&mut v)),
            OID_EXT_SKI => {
                // RFC 5280 4.2.1.2: never critical.
                if critical {
                    return Err(Error::BadExtension);
                }
                let k = v.read(der::OCTET_STRING).map_err(|_| Error::BadExtension)?;
                c.ski = Some(k.value);
            }
            OID_EXT_AKI => {
                // RFC 5280 4.2.1.1: never critical.
                if critical {
                    return Err(Error::BadExtension);
                }
                let mut s = v.nested(der::SEQUENCE).map_err(|_| Error::BadExtension)?;
                if let Some(k) = s.optional(der::context_primitive(0))? {
                    c.aki = Some(k.value);
                }
                der::check_tree(&mut s).map_err(|_| Error::BadExtension)?;
            }
            _ => {
                if critical {
                    return Err(Error::UnknownCriticalExtension);
                }
                der::check_tree(&mut v).map_err(|_| Error::BadExtension)?;
            }
        }
        if !v.is_empty() {
            return Err(Error::BadExtension);
        }
    }
    // Rules between extensions (RFC 5280 4.2.1.9, 4.2.1.10, 4.2.1.6):
    let ca = c.basic.is_some_and(|b| b.ca);
    // keyCertSign only with cA = TRUE.
    if c.key_usage.is_some_and(|ku| ku & KU_KEY_CERT_SIGN != 0) && !ca {
        return Err(Error::BadExtension);
    }
    // nameConstraints only in a CA certificate.
    if c.name_constraints.is_some() && !ca {
        return Err(Error::BadExtension);
    }
    // An empty subject needs a critical subjectAltName.
    if c.subject == [0x30, 0x00] && c.san.is_some() && !san_critical {
        return Err(Error::BadExtension);
    }
    Ok(())
}

fn parse_basic(v: &mut Reader<'_>, critical: bool) -> Result<BasicConstraints, Error> {
    let mut s = v.nested(der::SEQUENCE).map_err(|_| Error::BadExtension)?;
    let ca = if s.peek_tag() == Some(der::BOOLEAN) {
        if !s.boolean()? {
            return Err(Error::BadDer);
        }
        true
    } else {
        false
    };
    let path_len = if s.peek_tag() == Some(der::INTEGER) { Some(s.small().map_err(|_| Error::BadExtension)?) } else { None };
    s.finish().map_err(|_| Error::BadExtension)?;
    if path_len.is_some() && !ca {
        return Err(Error::BadExtension);
    }
    Ok(BasicConstraints { ca, path_len, critical })
}

/// keyUsage: a BIT STRING in its minimal form (no trailing zero bits), at least one bit set.
fn parse_key_usage(v: &mut Reader<'_>) -> Result<u16, Error> {
    let t = v.read(der::BIT_STRING).map_err(|_| Error::BadExtension)?;
    let (&unused, bits) = t.value.split_first().ok_or(Error::BadExtension)?;
    let Some(&last) = bits.last() else { return Err(Error::BadExtension) };
    if unused > 7 || bits.len() > 2 || (last >> unused) & 1 == 0 {
        return Err(Error::BadExtension);
    }
    let mut ku = 0u16;
    for (i, b) in bits.iter().enumerate() {
        for bit in 0..8 {
            if b & (0x80 >> bit) != 0 {
                ku |= 1 << (8 * i + bit);
            }
        }
    }
    if ku == 0 {
        return Err(Error::BadExtension);
    }
    Ok(ku)
}

/// nameConstraints: only dNSName bases, minimum / maximum not written (RFC 5280: 0 and
/// absent), at least one of the two lists, each list not empty.  A well-formed extension with
/// another name type is UnsupportedNameConstraint – refused when that CA is used.
fn parse_nc<'a>(v: &mut Reader<'a>) -> Result<NameConstraints<'a>, Error> {
    let mut s = v.nested(der::SEQUENCE).map_err(|_| Error::BadExtension)?;
    let mut out = NameConstraints { permitted: None, excluded: None };
    let mut total = 0;
    let mut unsupported = false;
    for (tag, slot) in [(der::context(0), 0), (der::context(1), 1)] {
        if let Some(t) = s.optional(tag).map_err(|_| Error::BadExtension)? {
            let mut l = s.enter(&t)?;
            if l.is_empty() {
                return Err(Error::BadExtension);
            }
            while !l.is_empty() {
                let mut sub = l.nested(der::SEQUENCE).map_err(|_| Error::BadExtension)?;
                let base = sub.any().map_err(|_| Error::BadExtension)?;
                if !sub.is_empty() {
                    return Err(Error::BadExtension);
                }
                if base.tag & 0x20 != 0 {
                    let mut inner = sub.enter(&base)?;
                    der::check_tree(&mut inner).map_err(|_| Error::BadExtension)?;
                }
                if base.tag != der::context_primitive(2) {
                    unsupported = true;
                } else if !base.value.is_empty() && !super::name::dns_ok(base.value) {
                    // A leading period, a wildcard or other non-DNS text: not RFC 5280.
                    return Err(Error::BadExtension);
                }
                total += 1;
                if total > super::name::MAX_SUBTREES {
                    return Err(Error::TooManyNames);
                }
            }
            if slot == 0 {
                out.permitted = Some(t.value);
            } else {
                out.excluded = Some(t.value);
            }
        }
    }
    s.finish().map_err(|_| Error::BadExtension)?;
    if out.permitted.is_none() && out.excluded.is_none() {
        return Err(Error::BadExtension);
    }
    if unsupported {
        return Err(Error::UnsupportedNameConstraint);
    }
    Ok(out)
}

/// Checks `cert`'s signature with `issuer_key` (the issuer's public key).
pub fn check_signature(cert: &Cert<'_>, issuer_key: &Key<'_>) -> Result<(), Error> {
    use super::crypto::{ecdsa, rsa};
    let alg = cert.sig_alg?;
    let r = match (alg, issuer_key) {
        (SigAlg::RsaPkcs1(h), Key::Rsa { n, e }) => {
            let k = rsa::PublicKey::new(n, e).map_err(|_| Error::BadKey)?;
            k.verify_pkcs1(h, cert.tbs, cert.signature)
        }
        (SigAlg::RsaPss(p), Key::Rsa { n, e }) => {
            let k = rsa::PublicKey::new(n, e).map_err(|_| Error::BadKey)?;
            k.verify_pss(&p, cert.tbs, cert.signature)
        }
        (SigAlg::Ecdsa(c), Key::Ec { curve, point }) if c == *curve => ecdsa::verify(c, point, cert.tbs, cert.signature),
        _ => return Err(Error::BadSignature),
    };
    r.map_err(|e| if e == super::crypto::Error::InvalidKey { Error::BadKey } else { Error::BadSignature })
}
