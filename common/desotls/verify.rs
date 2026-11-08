// Checking a server's certificate chain (RFC 5280 path validation, the DeSoTLS profile).
//
//   verify::server(&chain, &anchors, "example.com", now)?   // chain[0] = the server's own
//
// Order of the checks (the first failure is the answer):
//   1. limits: 1..=MAX_CHAIN certificates, each at most MAX_CERT_LEN bytes; the host valid
//   2. the server certificate parses (x509.rs); a presented intermediate that does not
//      parse is left out (it may be unrelated) – if no path is found, its error is the answer
//   3. the server certificate: valid at `now`, not a CA, keyUsage (if present) with
//      digitalSignature, extKeyUsage (if present) with serverAuth, a key within the rules
//      (RSA 2048-4096 bits, EC point on the curve), a
//      subjectAltName dNSName matching the host (name.rs)
//   4. a path up to a trust anchor, depth first: for the certificate on top, each anchor and
//      then each presented certificate whose subject is byte-for-byte its issuer becomes a
//      candidate.  A candidate must be valid at `now` (anchors too), be a CA (basicConstraints
//      cA = TRUE – for an intermediate present and critical; a v1 anchor without extensions
//      counts as a CA), have keyCertSign if it has keyUsage, serverAuth or anyExtendedKeyUsage
//      if it has extKeyUsage, a supported key that verifies the signature, keep its
//      pathLenConstraint and its name constraints over everything below it, and – for an
//      anchor with a Mozilla distrust-after date – the server certificate must have been
//      issued (notBefore) before that date.  The same certificate never appears twice in a
//      path.
//
// When no path is found, the failure reported is the one of the attempt that got furthest
// (a candidate whose signature verified, or the path above it) – otherwise the first
// candidate's, otherwise UnknownIssuer.
//
// pathLenConstraint n: at most n intermediate CAs below, not counting the server
// certificate and not counting self-issued ones.  Name constraints apply to every
// certificate below the CA except self-issued intermediates (RFC 5280 6.1.3 b); the server
// certificate always.  "Self-issued" = issuer and subject are identical bytes – a strict
// subset of RFC 5280 §7.1: names equal only after normalisation count as different, so
// such a certificate is counted and constrained (it can refuse a rare valid chain, never
// accept a bad one).
//
// Limits (no input can make this run long): MAX_CHAIN presented, MAX_PATH certificates in a
// path, MAX_SIGNATURE_CHECKS signature checks for the whole search.

use super::Error;
use super::name;
use super::roots::Anchors;
use super::x509::{self, Cert, KU_DIGITAL_SIGNATURE, KU_KEY_CERT_SIGN, OID_ANY_EKU, OID_SERVER_AUTH};

pub const MAX_CHAIN: usize = 8;
pub const MAX_PATH: usize = 8;
pub const MAX_CERT_LEN: usize = 16 * 1024;
pub const MAX_SIGNATURE_CHECKS: u32 = 32;

/// A chain that passed: how many certificates the path has (with the anchor) and which
/// anchor (its position in the Anchors list) ended it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    pub certs: usize,
    pub anchor_index: usize,
}

struct Search<'a, 'b> {
    /// The presented certificates; None for one that did not parse (an intermediate that is
    /// broken can still not be part of the path – see `first_error`).
    presented: [Option<Cert<'a>>; MAX_CHAIN],
    /// Why the first broken intermediate did not parse (reported if no path is found).
    first_error: Option<Error>,
    count: usize,
    anchors: &'b dyn Anchors,
    now: i64,
    signature_checks: u32,
    /// Set when the signature budget ran out – the search stops everywhere.
    exhausted: bool,
}

/// The more useful of two failures: anything beats UnknownIssuer, otherwise the first.
fn pick(best: Option<Error>, e: Error) -> Option<Error> {
    match best {
        None | Some(Error::UnknownIssuer) => Some(e),
        b => b,
    }
}

/// A candidate's failure, and whether it came after the candidate's signature had verified
/// (then the path got further, and that failure is the one to report).
struct Refused {
    error: Error,
    after_signature: bool,
}

impl From<Error> for Refused {
    fn from(error: Error) -> Refused {
        Refused { error, after_signature: false }
    }
}

fn valid_at(c: &Cert<'_>, now: i64) -> Result<(), Error> {
    if now < c.not_before {
        return Err(Error::NotYetValid);
    }
    if now > c.not_after {
        return Err(Error::Expired);
    }
    Ok(())
}

/// Checks the chain of a server certificate for `host` at `now` (Unix seconds).
pub fn server(chain: &[&[u8]], anchors: &dyn Anchors, host: &str, now: i64) -> Result<Verified, Error> {
    if chain.is_empty() {
        return Err(Error::Empty);
    }
    if chain.len() > MAX_CHAIN {
        return Err(Error::ChainTooLong);
    }
    if chain.iter().any(|c| c.len() > MAX_CERT_LEN) {
        return Err(Error::CertTooLarge);
    }
    name::check_host(host)?;
    let mut s = Search { presented: [None; MAX_CHAIN], first_error: None, count: chain.len(), anchors, now, signature_checks: 0, exhausted: false };
    s.presented[0] = Some(Cert::parse(chain[0], false)?);
    for (i, der) in chain.iter().enumerate().skip(1) {
        match Cert::parse(der, false) {
            Ok(c) => s.presented[i] = Some(c),
            Err(e) => {
                s.first_error.get_or_insert(e);
            }
        }
    }
    let Some(leaf) = s.presented[0] else { return Err(Error::Empty) };
    valid_at(&leaf, now)?;
    if leaf.basic.is_some_and(|b| b.ca) {
        return Err(Error::CaAsLeaf);
    }
    if leaf.key_usage.is_some_and(|ku| ku & KU_DIGITAL_SIGNATURE == 0) {
        return Err(Error::KeyUsage);
    }
    if leaf.eku.is_some() && !leaf.has_eku(OID_SERVER_AUTH) {
        return Err(Error::ExtKeyUsage);
    }
    // The server's key is checked now, not first in the handshake.
    match leaf.key? {
        x509::Key::Rsa { n, e } => {
            super::crypto::rsa::PublicKey::new(n, e).map_err(|_| Error::BadKey)?;
        }
        x509::Key::Ec { curve, point } => super::crypto::ecdsa::check_public_key(curve, point).map_err(|_| Error::BadKey)?,
    }
    let san = leaf.san.ok_or(Error::NoSubjectAltName)?;
    if !name::san_matches(san, host)? {
        return Err(Error::NameMismatch);
    }
    let mut path: [usize; MAX_PATH] = [0; MAX_PATH];
    let r = build(&mut s, &mut path, 1);
    if s.exhausted {
        return Err(Error::TooManySignatureChecks);
    }
    // No path and nothing more specific than "unknown issuer": a broken intermediate may be
    // why – say what was wrong with it.
    match (r, s.first_error) {
        (Err(Error::UnknownIssuer), Some(e)) => Err(e),
        (r, _) => r,
    }
}

/// The path so far: indexes into `presented`, path[0] = 0 (the server certificate), the
/// last one (path[len - 1]) is the certificate whose issuer is sought.
fn build(s: &mut Search<'_, '_>, path: &mut [usize; MAX_PATH], len: usize) -> Result<Verified, Error> {
    let Some(top) = s.presented[path[len - 1]] else { return Err(Error::Empty) };
    // Failures of candidates whose signature did not verify, and of those that got further.
    let mut best: Option<Error> = None;
    let mut deep: Option<Error> = None;

    // 1. A trust anchor.
    let mut found: Option<usize> = None;
    let mut index = 0usize;
    {
        let anchors = s.anchors;
        let mut each = |der: &[u8], distrust_after: i64| -> bool {
            let i = index;
            index += 1;
            let Ok(a) = Cert::parse(der, true) else { return true };
            if a.subject != top.issuer {
                return true;
            }
            match candidate(s, path, len, &a, true, distrust_after) {
                Ok(()) => {
                    found = Some(i);
                    false
                }
                Err(r) => {
                    if r.after_signature {
                        deep = pick(deep, r.error);
                    } else {
                        best = pick(best, r.error);
                    }
                    !s.exhausted
                }
            }
        };
        anchors.each(&mut each);
    }
    if let Some(i) = found {
        return Ok(Verified { certs: len + 1, anchor_index: i });
    }
    if s.exhausted {
        return Err(Error::TooManySignatureChecks);
    }

    // 2. A presented intermediate, then further up from it.
    for i in 1..s.count {
        if path[..len].contains(&i) {
            continue;
        }
        let Some(c) = s.presented[i] else { continue };
        if c.subject != top.issuer {
            continue;
        }
        // Room for it and for an anchor above it.
        if len + 2 > MAX_PATH {
            best = pick(best, Error::ChainTooLong);
            continue;
        }
        if let Err(r) = candidate(s, path, len, &c, false, 0) {
            if r.after_signature {
                deep = pick(deep, r.error);
            } else {
                best = pick(best, r.error);
            }
            if s.exhausted {
                return Err(Error::TooManySignatureChecks);
            }
            continue;
        }
        path[len] = i;
        match build(s, path, len + 1) {
            Ok(v) => return Ok(v),
            Err(e) => {
                deep = pick(deep, e);
                if s.exhausted {
                    return Err(Error::TooManySignatureChecks);
                }
            }
        }
    }
    Err(deep.or(best).unwrap_or(Error::UnknownIssuer))
}

/// Can `issuer` issue the certificate on top of the path, with everything the path below it
/// requires?
fn candidate(s: &mut Search<'_, '_>, path: &[usize; MAX_PATH], len: usize, issuer: &Cert<'_>, anchor: bool, distrust_after: i64) -> Result<(), Refused> {
    let below = |k: usize| s.presented[path[k]];
    // The same certificate twice is a loop, not a path.
    for k in 0..len {
        if below(k).is_some_and(|c| c.der == issuer.der) {
            return Err(Error::UnknownIssuer.into());
        }
    }
    valid_at(issuer, s.now)?;
    match issuer.basic {
        Some(b) if !b.ca => return Err(Error::NotCa.into()),
        Some(b) if !anchor && !b.critical => return Err(Error::BasicConstraintsNotCritical.into()),
        Some(_) => {}
        None if anchor && issuer.version == 1 => {}
        None if anchor => return Err(Error::NotCa.into()),
        None => return Err(Error::BasicConstraintsNotCritical.into()),
    }
    if issuer.key_usage.is_some_and(|ku| ku & KU_KEY_CERT_SIGN == 0) {
        return Err(Error::KeyUsage.into());
    }
    if issuer.eku.is_some() && !issuer.has_eku(OID_SERVER_AUTH) && !issuer.has_eku(OID_ANY_EKU) {
        return Err(Error::ExtKeyUsage.into());
    }
    let key = issuer.key?;
    let Some(top) = below(len - 1) else { return Err(Error::Empty.into()) };
    s.signature_checks += 1;
    if s.signature_checks > MAX_SIGNATURE_CHECKS {
        s.exhausted = true;
        return Err(Error::TooManySignatureChecks.into());
    }
    x509::check_signature(&top, &key)?;
    let after = |error: Error| Refused { error, after_signature: true };
    // pathLenConstraint: intermediate CAs below the issuer, without the server certificate
    // and without self-issued ones.
    if let Some(n) = issuer.basic.and_then(|b| b.path_len) {
        let count = (1..len).filter(|&k| below(k).is_some_and(|c| !c.self_issued())).count();
        if count > n as usize {
            return Err(after(Error::PathLenExceeded));
        }
    }
    // Name constraints over everything below, except self-issued intermediates.
    if let Some(nc) = issuer.name_constraints {
        let nc = nc.map_err(after)?;
        for k in 0..len {
            let Some(c) = below(k) else { continue };
            if k > 0 && c.self_issued() {
                continue;
            }
            name::check_constraints(&nc, c.san).map_err(after)?;
        }
    }
    if anchor && distrust_after != 0 {
        if let Some(leaf) = below(0) {
            if leaf.not_before > distrust_after {
                return Err(after(Error::Distrusted));
            }
        }
    }
    Ok(())
}
