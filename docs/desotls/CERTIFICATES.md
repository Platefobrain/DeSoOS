# DeSoTLS – certificates, the CA store and the clock

The detailed description of what DeSoTLS 0.1 (`common/desotls/`) checks before it trusts a server: the X.509
profile, path building, every refusal, the trusted CA store file, the wall clock, and how it was tested. What the
library is: `README.md` in this folder; how it fits into the system: `../ARCHITECTURE.md`, section "DeSoTLS".

DeSoOS's own TLS library, over DeSoCrypto and like it a library (`core` only, no heap, no syscalls) included by the
programs that use it. So far it checks certificate chains; the TLS 1.3 handshake and record layer are
v0.75. Client only. The rule above all: **either the certificate is fully checked and the
connection is safe, or no application data is sent** – no "insecure" switch, no fallback, nothing that turns a check
off.

## Compared with other systems

| | Linux | Windows | RedoxOS | DeSoOS |
|---|---|---|---|---|
| TLS | a library in the program (OpenSSL, GnuTLS, rustls); kTLS for records | Schannel in LSASS | rustls in the program | `common/desotls` in the program; the kernel has no TLS |
| CA store | shared files `/etc/ssl/certs` (Mozilla), root-only | system store + Windows Update | webpki-roots compiled into each program | one shared file `/etc/certs/roots` (Mozilla), sealed in ramfs |
| Mozilla trust | ca-certificates: serverAuth, distrust-after varies | Microsoft's own programme | serverAuth, no distrust-after | serverAuth + distrust-after from `certdata.txt` |
| clock | `CLOCK_REALTIME` (NTP); systemd: the build time as a floor | system time (NTP) | `clock_gettime` | syscall 59: the RTC + "plausible" (a heuristic), the build date − 24 h as a floor |

## The profile

`x509.rs`, `verify.rs`, `name.rs` – fail closed: what is not understood is refused.

- strict DER (`der.rs`): minimal lengths (long form only from 128, at most 3 bytes), no indefinite length, no
  high tag numbers, BOOLEAN only 00 / FF, minimal INTEGER, BIT STRING keys and signatures without unused bits,
  depth at most 16, nothing after the last element; a Name is walked once, then compared byte for byte;
- X.509 v3 (v1 only as a trust anchor), no unique identifiers, the issuer not empty, a CA's subject not empty, an
  empty subject only with a critical subjectAltName; the inner and outer signature algorithm byte-identical;
- keys: RSA (rsaEncryption, NULL parameters; 2048–4096 bits, odd e with 3 ≤ e < 2^32), EC P-256 / P-384
  (uncompressed, on the curve – the server's key is checked at once, not only in the handshake); an RSASSA-PSS key
  in the SPKI, P-521, Ed25519 are refused;
- signatures: RSA PKCS#1 v1.5 with SHA-256/384/512 (parameters NULL or absent – RFC 4055 §5 asks to accept both),
  RSA-PSS with parameters read from the certificate (hash SHA-256/384/512, MGF1 with the same hash, salt ≥ 20 and
  ≤ 512, the default values not written out – DER), ECDSA P-256 / SHA-256 and P-384 / SHA-384 only (the pairs TLS
  1.3 names); SHA-1 never;
- extensions: basicConstraints, keyUsage (minimal BIT STRING, at least one bit), extKeyUsage, subjectAltName,
  nameConstraints, authority / subject key identifiers (never critical) are understood; another critical one is
  refused, a non-critical one ignored; duplicates, an empty list, "critical FALSE" written out (not DER) refused;
  keyCertSign only with cA = TRUE, nameConstraints only in a CA;
- the server certificate: valid now, not a CA, digitalSignature if keyUsage is present, serverAuth if extKeyUsage
  is present, a subjectAltName dNSName matching the host (the commonName is ignored); case-insensitive; a
  wildcard only as the whole leftmost label for exactly one label, with at least two labels after it; IDN in
  A-label form compared as bytes; an IP address as the host is refused (not yet supported);
- each CA on the path: valid now (anchors too), cA = TRUE (an intermediate's basicConstraints present and
  critical – not required of an anchor; a v1 anchor counts as a CA), keyCertSign if keyUsage is present, serverAuth
  or anyExtendedKeyUsage if extKeyUsage is present, its signature verified, pathLenConstraint (not counting the
  server certificate and self-issued intermediates), name constraints over everything below it (not over
  self-issued intermediates, always over the server certificate; dNSName only – any other name type in the
  constraints refuses the CA; a leading period or a wildcard in a constraint refuses it; non-critical constraints
  are enforced too; a wildcard name – see "Wildcards and excluded subtrees" below), and an
  anchor's Mozilla distrust-after date (a server certificate issued after it is refused);
- "self-issued" = issuer and subject byte-identical: a strict subset of RFC 5280 §7.1 (names equal only after
  normalisation count as different – counted and constrained; never more lenient).

## Wildcards and excluded subtrees

A wildcard name in a server certificate is checked against the excluded subtrees twice (`name.rs`,
`check_constraints`):

1. **as written** – `any_subtree`: "*.example.com" lies under example.com and com like any name;
2. **for the names it stands for** – `wildcard_covers_any`: "*.example.com" stands for every name with exactly one
   label before example.com (foo.example.com), so an excluded foo.example.com is hit too (CVE-2025-61727 – RFC
   5280 does not say how wildcards meet name constraints; the safe reading).

| Excluded subtree | "*.example.com" | Which check | A plain www.example.com |
|---|---|---|---|
| example.com | refused | 1 | refused |
| com | refused | 1 | refused |
| foo.example.com | refused | 2 | allowed |
| a.foo.example.com | allowed – no name the wildcard stands for lies inside it | – | allowed |
| notexample.com | allowed | – | allowed |

Until v0.74.3 check 2 also refused a.foo.example.com (any subtree under a name the wildcard stands for) – safe,
but a valid certificate was refused. The tests check each of the two functions on its own, so a change to one
cannot hide behind the other, and the same subtrees against plain names.

## The order of the checks

`verify::server(chain, anchors, host, now)` – `chain[0]` is the server's own certificate; the first failure is the
answer:

1. limits: 1–8 certificates, each at most 16 KiB; the host a valid DNS name (an IP address is refused);
2. the server certificate parses; a presented intermediate that does not parse is left out (it may be unrelated) –
   if no path is found, its error is the answer;
3. the server certificate: valid at `now`, not a CA, keyUsage (if present) with digitalSignature, extKeyUsage (if
   present) with serverAuth, its key within the rules (RSA 2048–4096 bits, an EC point on the curve), a
   subjectAltName dNSName matching the host;
4. a path up to a trust anchor (below).

## Path building

Depth first from the server certificate; for the certificate on top, the trust
anchors whose subject equals its issuer, then the presented certificates (any order) – the same certificate never
twice in a path. When nothing works, the failure of the attempt that got furthest is reported (a candidate whose
signature verified beats one that did not; anything beats "unknown issuer"). A presented intermediate that does not
parse is skipped (it may be unrelated); if no path is found, its error is the answer. Limits: at most 8 presented
certificates of 16 KiB each, 8 in a path, 32 signature checks for the whole search, 256 names in a subjectAltName,
64 subtrees in name constraints – no input makes it run long.

## Refusals

Every refusal is one `desotls::Error`; `certcheck` prints its text after `certcheck: REFUSED - `.

| Error | Text | When |
|---|---|---|
| `BadDer` | malformed certificate (DER) | Not well-formed DER, or a structure that breaks the X.509 grammar. |
| `UnsupportedVersion` | unsupported certificate version | Not X.509 v3 (v1 only for a trust anchor; v2 never). |
| `UnsupportedSignatureAlgorithm` | unsupported signature algorithm | A signature algorithm outside the list (SHA-1, P-521, Ed25519, odd PSS parameters). |
| `AlgorithmMismatch` | signature algorithm mismatch | The signature algorithm inside the signed part differs from the outer one. |
| `UnsupportedKey` | unsupported public key | A public key type outside the list (RSA, EC P-256 / P-384). |
| `BadKey` | public key outside the rules | A key of a supported type but outside the rules (RSA size, exponent, EC point). |
| `BadSignature` | bad signature | The signature does not verify, or the key type does not fit the algorithm. |
| `Expired` | certificate expired | `now` is after notAfter (of the server certificate, an intermediate or an anchor). |
| `NotYetValid` | certificate not yet valid | `now` is before notBefore. |
| `UnknownIssuer` | unknown issuer (no trusted CA) | No trust anchor (and no presented intermediate) issued it. |
| `NotCa` | issuer is not a CA | An issuer without basicConstraints cA = TRUE. |
| `BasicConstraintsNotCritical` | CA basicConstraints missing or not critical | basicConstraints of an intermediate CA is missing or not critical. |
| `CaAsLeaf` | server certificate is a CA | A server certificate that says cA = TRUE. |
| `PathLenExceeded` | path length constraint exceeded | More intermediate CAs below a CA than its pathLenConstraint allows (self-issued ones not counted). |
| `KeyUsage` | key usage does not allow it | keyUsage forbids the use (keyCertSign for a CA, digitalSignature for the server). |
| `ExtKeyUsage` | extended key usage without serverAuth | extKeyUsage without serverAuth (or anyExtendedKeyUsage for a CA). |
| `NoSubjectAltName` | no DNS name (subjectAltName) | The server certificate has no subjectAltName with a DNS name. |
| `NameMismatch` | host name does not match | No DNS name of the certificate matches the host. |
| `NameConstraintViolation` | name constraints violated | A name outside the permitted or inside the excluded subtrees of an issuing CA. |
| `UnsupportedNameConstraint` | unsupported name constraint type | Name constraints with a name type other than DNS (refused – fail closed). |
| `UnknownCriticalExtension` | unknown critical extension | A critical extension outside the understood list. |
| `DuplicateExtension` | duplicate extension | The same extension twice in one certificate. |
| `BadExtension` | malformed extension | An extension that is malformed, empty or contradicts itself. |
| `ChainTooLong` | chain too long | More than `verify::MAX_CHAIN` certificates presented, or no path within `MAX_PATH`. |
| `TooManySignatureChecks` | too many signature checks | The path search would check more than `verify::MAX_SIGNATURE_CHECKS` signatures. |
| `TooManyNames` | too many names | More names / subtrees than the limits (`name::MAX_NAMES`, `name::MAX_SUBTREES`). |
| `Distrusted` | CA distrusted for certificates issued after a date | The anchor is distrusted for server certificates issued after a date (Mozilla). |
| `CertTooLarge` | certificate too large | A certificate larger than `verify::MAX_CERT_LEN`. |
| `InvalidHost` | invalid host name | The host is not a valid DNS name. |
| `IpHostUnsupported` | IP address hosts not supported | The host is an IP address (not supported yet). |
| `BadRootStore` | trusted CA store missing or damaged | The trusted CA store is missing or damaged. |
| `Empty` | no certificate | No certificate in the input. |

## The CA store

`roots.rs`, `user/etc/certs/`. `gen-roots.py` reads Mozilla's `certdata.txt` (NSS tag pinned, its
SHA-256 checked), keeps the certificates trusted for server authentication (`CKT_NSS_TRUSTED_DELEGATOR`) with their
`CKA_NSS_SERVER_DISTRUST_AFTER` date, and writes `roots` ("DSCR", NSS tag, SHA-256 of the source, then distrust date
+ DER per anchor) – NSS_3_133_RTM: 118 anchors, 117 usable (one P-521 root), 128 KiB. `build.sh` puts it into the
image; the kernel writes it to `/etc/certs/roots` at boot and seals it (`../ARCHITECTURE.md`, section "Files"). `Roots::parse` walks the whole
file once – a damaged store is refused as a whole, never trusted in part. Updating it = a new `certdata.txt` and the
script, no code change – but still a new image (DeSoOS has no live updates; loading a newer store from disk later).

The file, numbers big-endian:

| Bytes | What |
|---|---|
| 4 | `DSCR` |
| 2 | version (1) |
| 2 | number of anchors |
| 1 + n | length and the NSS tag (ASCII), e.g. `NSS_3_133_RTM` |
| 32 | SHA-256 of the `certdata.txt` it was made from |
| per anchor: 8 | distrust-after, Unix seconds as a signed number (0 = none) |
| per anchor: 2 + n | length and the certificate (DER) |

A wrong magic, version, count or length, or bytes after the last anchor, refuse the whole file (`BadRootStore`). An
anchor whose certificate cannot be parsed or whose key is not supported (the P-521 root) is never matched – it
cannot make a chain valid. Installed: 118 anchors, 117 usable, 128 337 bytes, SHA-256
`d26a720c309baed4b66b1ee1ea20f184dbbecaac3e34ffd9847f880c26d4b9ca` (`certtest` prints it).

## The clock

`drivers/rtc.rs`, syscall 59. The RTC is read once at boot (two readings that agree), later time =
that + uptime – it only moves on. The verdict "plausible" needs status register D bit 7 (VRT – the RTC kept power),
stable readings, every field in range (29 February only in leap years) and a time not earlier than the build date
− 24 h and not later than 2099. The build date comes from `build.sh` – `SOURCE_DATE_EPOCH` when someone sets it
on purpose (Linux distributions do, for reproducible builds), otherwise the build time (as Android: the most recent
date possible, the strongest floor); no git, so it never depends on a repository; `build.sh` prints which,
`date` / `sysinfo date` show it. Linux (systemd) has three layers – the build date, the last known time saved on
disk, NTP; DeSoOS has the first, the other two are a later step (NTP preferably with NTS – plain NTP can be faked
by anyone on the network). It is a heuristic, not proof: it refuses a lost battery, a
broken reading and dates older than the image, but anyone with access to the firmware can set any date inside the
range (and so make an expired certificate "valid" again); an RTC kept in local time (Windows next to it) cannot be
detected. Without NTP the check of a certificate's dates is as good as the RTC. TLS (v0.75) refuses to connect
without a plausible clock – before sending ClientHello.

Why the clock is not plausible (the status of syscall 59, `date` and `certcheck` print the text):

| Status | Text |
|---|---|
| 0 | plausible |
| 1 | RTC not read yet |
| 2 | RTC lost power (VRT clear) |
| 3 | RTC readings do not agree |
| 4 | RTC date or time out of range |
| 5 | clock earlier than the build date |
| 6 | clock later than 2099 |

Syscall 59 `time(out)` writes 24 bytes (little-endian): Unix seconds (u64), the status (u64), the build date in Unix
seconds (u64). No right is needed. In programs: `time_unix()` (`WallClock` with `plausible()`), `clock_reason()`,
`format_utc()`.

## Tools

`certcheck <chain.pem|cert.der> [host] [--time S] [--anchor ca.pem]` checks a chain offline with the same
code (exit 0 OK, 1 refused with the reason, 2 usage / file / clock). `/bin/certtest` runs the tests in user space and
attacks the sealed store.

## Tests

`common/desotls/tests.rs` – 307 checks: DER edge cases, times (leap years, 2049 / 1950, 2100), host names
and wildcards, name constraints on a wildcard with each of the two checks on its own (below), PEM, the store format and damaged stores, `vectors/certs.bin` (122 chains made with Python
`cryptography`, the impossible ones by editing DER and signing again – every rule of the profile right and wrong,
each limit at and past its value) and `vectors/real.bin` (12 real server chains from the rustls/webpki test data:
Amazon's four roots, Cloudflare, Netflix, Sanofi, an expired one). CERT TEST runs them in the kernel and in
`/bin/certtest`, checks `/etc/certs/roots` (= the image's, sealed, real chains against it), attacks the seal (21 ways
from a program, 15 from the kernel – the SHA-256 stays the same), judges made-up clock readings, compares syscall 59
with the kernel and runs `certcheck` on a real chain (`[RESULT-CERTS]`). On the host before the release: the
x509-limbo suite (5341 server / DNS cases; the differences in the table below), 3 million mutated certificates
(no panic, nothing accepted) and 56 hand-made mutations of the rules (55 caught, 1 equivalent – a check the next one repeats).

x509-limbo (5341 server / DNS cases, run on the host before v0.74.0):

| Result | Cases | Why |
|---|---|---|
| agree | 4 944 | – |
| accepted, the suite expects a refusal | 44 | CRL and CA/B Forum conformance rules that browsers do not check either (`../RELEASE.md`, "Current limitations") |
| refused, the suite expects success | 353 | 339 name constraints with a type other than DNS (refused by policy – fail closed), 9 the chain limit, 3 ML-DSA, 2 a CA certificate as the server's own |

CERT TEST steps: 1. every DeSoTLS test in the kernel; 2. the store as installed (the image's bytes, sealed, the
anchors usable, real chains against it); 3. the same in user space (`/bin/certtest`); 4. the seal – a program tries
every way, then the kernel itself; 5. the clock – the verdict on made-up readings, then the real one, syscall 59
against the kernel; 6. `/bin/certcheck` on a real chain.

## Not checked

Revocation (CRL, OCSP) and Certificate Transparency – a revoked certificate still within its dates is
accepted (as in most clients that are not browsers). Not audited, not for production use.
