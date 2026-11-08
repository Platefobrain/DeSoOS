// Names: the host a program connects to, the DNS names a certificate holds
// (subjectAltName dNSName) and name constraints on DNS names.
//
// * The host: a DNS name of 1-253 characters, labels of 1-63 letters, digits and '-' (not
//   at either end of a label), no trailing dot; upper / lower case do not matter.  An IP
//   address (the last label all digits, or a ':') is refused – IpHostUnsupported.
// * Matching (RFC 6125 / the CA/B Forum rules, as browsers do): only subjectAltName dNSName
//   entries count – the subject's commonName is ignored; ASCII case-insensitive; a wildcard
//   only as the whole leftmost label "*." standing for exactly one non-empty label, and
//   only with at least two labels after it ("*.com" and "*.a" never match); "f*.example.com"
//   or "*" anywhere else never matches.  IDNs are compared in their A-label form (xn--…)
//   byte for byte.
// * Name constraints (RFC 5280 4.2.1.10) on dNSName: "example.com" covers example.com and
//   every name under it; "" everything (a leading period or a wildcard in a constraint is not
//   RFC 5280 – the extension is refused when parsed).  A name inside an excluded subtree is
//   refused; with permitted subtrees a name must be inside one.  A wildcard name is refused
//   when any name it stands for is excluded (wildcard_covers_any).

use super::Error;
use super::der::{self, Reader};
use super::x509::NameConstraints;

/// The most names in one subjectAltName and subtrees in one nameConstraints (limit C).
pub const MAX_NAMES: usize = 256;
pub const MAX_SUBTREES: usize = 64;
pub const MAX_HOST: usize = 253;

fn label_ok(l: &[u8]) -> bool {
    !l.is_empty() && l.len() <= 63 && l[0] != b'-' && l[l.len() - 1] != b'-' && l.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

/// Every label valid (no wildcard), 1-253 characters.
pub fn dns_ok(n: &[u8]) -> bool {
    !n.is_empty() && n.len() <= MAX_HOST && n.split(|&c| c == b'.').all(label_ok)
}

/// Checks the host a program wants to reach.
pub fn check_host(host: &str) -> Result<(), Error> {
    let h = host.as_bytes();
    if h.contains(&b':') {
        return Err(Error::IpHostUnsupported);
    }
    if !dns_ok(h) {
        return Err(Error::InvalidHost);
    }
    let last = h.rsplit(|&c| c == b'.').next().unwrap_or(h);
    if last.iter().all(|c| c.is_ascii_digit()) {
        return Err(Error::IpHostUnsupported);
    }
    Ok(())
}

fn eq_ci(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn ends_with_ci(n: &[u8], suffix: &[u8]) -> bool {
    n.len() >= suffix.len() && eq_ci(&n[n.len() - suffix.len()..], suffix)
}

/// Does the certificate name `name` (a dNSName) match `host` (already checked by check_host)?
pub fn matches(name: &[u8], host: &str) -> bool {
    let h = host.as_bytes();
    if let Some(rest) = name.strip_prefix(b"*.") {
        // At least two labels after the wildcard; the host has exactly one more label.
        if !dns_ok(rest) || !rest.contains(&b'.') {
            return false;
        }
        let Some(dot) = h.iter().position(|&c| c == b'.') else { return false };
        return dot > 0 && eq_ci(&h[dot + 1..], rest);
    }
    dns_ok(name) && eq_ci(name, h)
}

/// Calls `f` for each dNSName in a subjectAltName (the contents of its SEQUENCE).
pub fn for_each_dns(san: &[u8], mut f: impl FnMut(&[u8]) -> Result<(), Error>) -> Result<(), Error> {
    let mut r = Reader::new(san);
    while !r.is_empty() {
        let g = r.any()?;
        if g.tag == der::context_primitive(2) {
            f(g.value)?;
        }
    }
    Ok(())
}

/// Some dNSName of the subjectAltName matches the host.
pub fn san_matches(san: &[u8], host: &str) -> Result<bool, Error> {
    let mut found = false;
    for_each_dns(san, |n| {
        found |= matches(n, host);
        Ok(())
    })?;
    Ok(found)
}

/// Is `name` inside the subtree `base` (both dNSName)?
fn in_subtree(name: &[u8], base: &[u8]) -> bool {
    if base.is_empty() {
        return true;
    }
    if eq_ci(name, base) {
        return true;
    }
    name.len() > base.len() + 1 && ends_with_ci(name, base) && name[name.len() - base.len() - 1] == b'.'
}

/// Some subtree of the list (GeneralSubtree SEQUENCEs with dNSName bases) contains `name`.
fn any_subtree(list: &[u8], name: &[u8]) -> Result<bool, Error> {
    let mut r = Reader::new(list);
    while !r.is_empty() {
        let mut sub = r.nested(der::SEQUENCE)?;
        let base = sub.read(der::context_primitive(2))?;
        if in_subtree(name, base.value) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A wildcard name ("*.example.com") stands for every one-label name under it: an excluded
/// subtree that is such a name (bar.example.com) or lies under one is hit too (RFC 9525 vs
/// RFC 5280 – the safe reading; CVE-2025-61727).
fn wildcard_covers_any(list: &[u8], wildcard: &[u8]) -> Result<bool, Error> {
    let rest = &wildcard[2..];
    let mut r = Reader::new(list);
    while !r.is_empty() {
        let mut sub = r.nested(der::SEQUENCE)?;
        let base = sub.read(der::context_primitive(2))?.value;
        // base = label.rest, or anything under such a name (a.label.rest).
        if base.len() > rest.len() + 1 && ends_with_ci(base, rest) && base[base.len() - rest.len() - 1] == b'.' {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Every dNSName of `san` obeys the constraints.
pub fn check_constraints(nc: &NameConstraints<'_>, san: Option<&[u8]>) -> Result<(), Error> {
    let Some(san) = san else { return Ok(()) };
    for_each_dns(san, |n| {
        if let Some(ex) = nc.excluded {
            if any_subtree(ex, n)? || (n.starts_with(b"*.") && wildcard_covers_any(ex, n)?) {
                return Err(Error::NameConstraintViolation);
            }
        }
        if let Some(pe) = nc.permitted {
            if !any_subtree(pe, n)? {
                return Err(Error::NameConstraintViolation);
            }
        }
        Ok(())
    })
}
