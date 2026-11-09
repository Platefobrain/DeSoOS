# DeSoTLS v0.2.0

DeSoOS's own TLS library, used only inside DeSoOS: a TLS 1.3 client and the check of a server's X.509 certificate
chain. Plain Rust over DeSoCrypto, like it: `core` only, no heap, no syscalls. Client only; there is no switch that
turns a check off.

| File | What |
|---|---|
| `mod.rs` | the entry point: `Error` (why a chain was refused, `as_str` for messages), version |
| `client.rs` | `Client`: the TLS 1.3 handshake, application data, KeyUpdate, close; `Transport` (what carries the bytes), `TlsError` |
| `record.rs` | records: header, `Protection` (one direction's AEAD key, iv, record number), TLSInnerPlaintext, limits |
| `schedule.rs` | the TLS 1.3 key schedule: HKDF-Expand-Label, Derive-Secret, traffic secrets, Finished, KeyUpdate |
| `der.rs` | strict DER reading: minimal lengths, no indefinite form, BOOLEAN 00/FF, minimal INTEGER, depth limit 16 |
| `x509.rs` | one certificate: version, names, validity, keys (RSA, EC P-256/P-384), signature algorithms (PKCS#1, PSS with explicit parameters, ECDSA with its curve's hash), extensions |
| `name.rs` | host names, subjectAltName matching (one-label wildcards), DNS name constraints |
| `verify.rs` | `verify::server(chain, anchors, host, now)` – path building to a trust anchor with every check and the limits |
| `roots.rs` | the trusted CA store file (`/etc/certs/roots`) and other anchor lists |
| `pem.rs` | PEM text to DER (for `certcheck` and the tests) |
| `tests.rs` | certificate tests – included only by `/bin/certtest` and the kernel's CERT TEST |
| `tls_tests.rs` | connection tests (RFC 8448 byte for byte, scripted servers) – included only by `/bin/tlstest` |
| `vectors/` | `certs.bin` (122 made-up chains: every rule right and wrong, the limits) from `gen-certs.py`; `real.bin` (12 real server chains from the rustls/webpki test data) from `gen-real.py` |

Use it from a program:

```rust
#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;
#[path = "../../common/desotls/mod.rs"]
mod desotls;

let roots = desotls::roots::Roots::parse(&store_bytes)?;
let v = desotls::verify::server(&[leaf, intermediate], &roots, "example.com", now)?;

// A connection: a Transport (send / recv) and fresh randomness from getrandom.
let cfg = desotls::client::Config { host: "example.com", anchors: &roots, now, suites: &[Suite::Aes128Gcm, Suite::Chacha20Poly1305] };
CLIENT.connect(&mut transport, &cfg, &random)?;      // static CLIENT: Client = Client::new();
CLIENT.write(&mut transport, request)?;
let n = CLIENT.read(&mut transport, &mut buf)?;     // 0 = the server's close_notify
```

Users: `/bin/netget` (https://), `/bin/certcheck` (checks a chain offline), `/bin/certtest`, `/bin/tlstest`, CERT TEST
and TLS TEST.

The connection: `docs/desotls/HANDSHAKE.md`. What is checked in a chain, in what order, and why each refusal:
`docs/desotls/CERTIFICATES.md`. Not checked: revocation
(CRL, OCSP) and Certificate Transparency – a revoked certificate that is still within its dates is accepted. Not
audited, not for production use.
