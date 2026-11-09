// DeSoTLS – the DeSoOS TLS library (version: VERSION below): a TLS 1.3 client and the
// checking of a server's X.509 certificate chain.
//
// Plain code over DeSoCrypto, like it: no heap, no syscalls, only `core`; whoever uses it
// includes both (`#[path]`) as siblings:
//
//   #[path = ".../common/desocrypto/mod.rs"] mod desocrypto;
//   #[path = ".../common/desotls/mod.rs"]    mod desotls;
//
//   client  the TLS 1.3 client: handshake, application data, KeyUpdate, close
//   record  records: protection with the two AEADs, TLSInnerPlaintext, limits
//   schedule  the TLS 1.3 key schedule (HKDF-Expand-Label, traffic secrets, Finished)
//   der     strict DER reading
//   x509    one certificate: fields, algorithms, keys, extensions (RFC 5280 profile below)
//   name    host names, subjectAltName matching (one-label wildcards), name constraints
//   verify  the chain from a server certificate to a trust anchor (path building, limits)
//   roots   the trusted CA store file (/etc/certs/roots, made from Mozilla's root store)
//   pem     "-----BEGIN CERTIFICATE-----" text to DER
//
// The rules (docs/desotls/HANDSHAKE.md, CERTIFICATES.md): fail closed – anything not understood is
// refused; no switch turns a check off.  Not checked: revocation (CRL, OCSP) and
// Certificate Transparency.  Not audited.
#![allow(dead_code)]

use super::desocrypto as crypto;

pub mod client;
pub mod der;
pub mod name;
pub mod pem;
pub mod record;
pub mod roots;
pub mod schedule;
pub mod verify;
pub mod x509;

pub const VERSION: &str = "0.2.0";

/// Why a certificate or chain was refused.  `as_str` gives the text `certcheck` prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not well-formed DER, or a structure that breaks the X.509 grammar.
    BadDer,
    /// Not X.509 v3 (v1 only for a trust anchor; v2 never).
    UnsupportedVersion,
    /// A signature algorithm outside the list (SHA-1, P-521, Ed25519, odd PSS parameters).
    UnsupportedSignatureAlgorithm,
    /// The signature algorithm inside the signed part differs from the outer one.
    AlgorithmMismatch,
    /// A public key type outside the list (RSA, EC P-256 / P-384).
    UnsupportedKey,
    /// A key of a supported type but outside the rules (RSA size, exponent, EC point).
    BadKey,
    /// The signature does not verify, or the key type does not fit the algorithm.
    BadSignature,
    Expired,
    NotYetValid,
    /// No trust anchor (and no presented intermediate) issued it.
    UnknownIssuer,
    /// An issuer without basicConstraints cA = TRUE.
    NotCa,
    /// basicConstraints of an intermediate CA is missing or not critical.
    BasicConstraintsNotCritical,
    /// A server certificate that says cA = TRUE.
    CaAsLeaf,
    PathLenExceeded,
    /// keyUsage forbids the use (keyCertSign for a CA, digitalSignature for the server).
    KeyUsage,
    /// extKeyUsage without serverAuth (or anyExtendedKeyUsage for a CA).
    ExtKeyUsage,
    /// The server certificate has no subjectAltName with a DNS name.
    NoSubjectAltName,
    /// No DNS name of the certificate matches the host.
    NameMismatch,
    /// A name outside the permitted or inside the excluded subtrees of an issuing CA.
    NameConstraintViolation,
    /// Name constraints with a name type other than DNS (refused – fail closed).
    UnsupportedNameConstraint,
    UnknownCriticalExtension,
    DuplicateExtension,
    /// An extension that is malformed, empty or contradicts itself.
    BadExtension,
    /// More than verify::MAX_CHAIN certificates presented, or no path within MAX_PATH.
    ChainTooLong,
    /// The path search would check more than verify::MAX_SIGNATURE_CHECKS signatures.
    TooManySignatureChecks,
    /// More names / subtrees than the limits (name::MAX_NAMES, name::MAX_SUBTREES).
    TooManyNames,
    /// The anchor is distrusted for server certificates issued after a date (Mozilla).
    Distrusted,
    /// A certificate larger than verify::MAX_CERT_LEN.
    CertTooLarge,
    /// The host is not a valid DNS name.
    InvalidHost,
    /// The host is an IP address (not supported yet).
    IpHostUnsupported,
    /// The trusted CA store is missing or damaged.
    BadRootStore,
    /// No certificate in the input.
    Empty,
}

impl Error {
    pub fn as_str(self) -> &'static str {
        match self {
            Error::BadDer => "malformed certificate (DER)",
            Error::UnsupportedVersion => "unsupported certificate version",
            Error::UnsupportedSignatureAlgorithm => "unsupported signature algorithm",
            Error::AlgorithmMismatch => "signature algorithm mismatch",
            Error::UnsupportedKey => "unsupported public key",
            Error::BadKey => "public key outside the rules",
            Error::BadSignature => "bad signature",
            Error::Expired => "certificate expired",
            Error::NotYetValid => "certificate not yet valid",
            Error::UnknownIssuer => "unknown issuer (no trusted CA)",
            Error::NotCa => "issuer is not a CA",
            Error::BasicConstraintsNotCritical => "CA basicConstraints missing or not critical",
            Error::CaAsLeaf => "server certificate is a CA",
            Error::PathLenExceeded => "path length constraint exceeded",
            Error::KeyUsage => "key usage does not allow it",
            Error::ExtKeyUsage => "extended key usage without serverAuth",
            Error::NoSubjectAltName => "no DNS name (subjectAltName)",
            Error::NameMismatch => "host name does not match",
            Error::NameConstraintViolation => "name constraints violated",
            Error::UnsupportedNameConstraint => "unsupported name constraint type",
            Error::UnknownCriticalExtension => "unknown critical extension",
            Error::DuplicateExtension => "duplicate extension",
            Error::BadExtension => "malformed extension",
            Error::ChainTooLong => "chain too long",
            Error::TooManySignatureChecks => "too many signature checks",
            Error::TooManyNames => "too many names",
            Error::Distrusted => "CA distrusted for certificates issued after a date",
            Error::CertTooLarge => "certificate too large",
            Error::InvalidHost => "invalid host name",
            Error::IpHostUnsupported => "IP address hosts not supported",
            Error::BadRootStore => "trusted CA store missing or damaged",
            Error::Empty => "no certificate",
        }
    }
}
