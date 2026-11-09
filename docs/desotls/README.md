# DeSoTLS

DeSoOS's own TLS library (`common/desotls/`, v0.2.0), over DeSoCrypto and like it a library: `core` only, no heap,
no syscalls, included by the programs that use it. Client only. The rule above all: **either the server is fully
authenticated – certificate chain, CertificateVerify, Finished – or no application data is sent** – no "insecure"
switch, no fallback to an older version.

What it does:

- **TLS 1.3 connections** (details: `HANDSHAKE.md`) – X25519, TLS_AES_128_GCM_SHA256 and
  TLS_CHACHA20_POLY1305_SHA256, CertificateVerify with ECDSA P-256 / P-384 or RSA-PSS; HelloRetryRequest, PSK,
  0-RTT and client certificates refused; KeyUpdate both ways, close_notify, a TCP end without it reported as
  truncated; every refusal with its alert;
- **checks a server's X.509 certificate chain** for a host at a time (details: `CERTIFICATES.md`) – strict DER, the
  RFC 5280 profile (keys, signature algorithms, extensions, name constraints, path length), path building to a trust
  anchor, Mozilla's distrust dates, limits so that no input makes it run long;
- reads the trusted CA store `/etc/certs/roots` – Mozilla's roots for server certificates, built into the image and
  sealed at boot (no program can change it);
- `netget https://` refuses when the wall clock is not plausible (syscall 59: RTC battery, readings, not before the
  build date) – before anything is sent;
- `certcheck` checks a chain offline with the same code.

Where things are:

| Path | What |
|---|---|
| `common/desotls/` | the code (file map in its `README.md`) |
| `common/desotls/tls_tests.rs` | 134 checks of the connection: RFC 8448 byte for byte, scripted servers |
| `common/desotls/tests.rs`, `vectors/` | 307 checks of certificates, 122 made-up chains, 12 real ones |
| `user/etc/certs/` | the CA store `roots` and `gen-roots.py`, which makes it from Mozilla's `certdata.txt` |
| `kernel/drivers/rtc.rs` | the wall clock and its verdict |
| `user/bin/netget.rs` | `netget https://` |
| `user/bin/certcheck.rs`, `certtest.rs`, `tlstest.rs` | the tools and test programs |
| `tests/tls-stub.py`, `tests/tls/` | the HTTPS servers of TLS TEST (OpenSSL through Python `ssl`) and their test certificates |
| `HANDSHAKE.md` | the handshake, the key schedule, records, KeyUpdate, the end of a connection, netget https://, the tests |
| `CERTIFICATES.md` | the profile, the order of the checks, path building, every refusal, the store format, the clock, the tests |

Tests: TLS TEST (3 steps: the library without a network, `netget https://` against OpenSSL with every refusal and a
man in the middle, the clock; `[RESULT-TLS]`), CERT TEST (6 steps: certificates in the kernel and in user space, the
installed store, the seal, the clock, `certcheck`; `[RESULT-CERTS]`); on the host x509-limbo, fuzzing and mutations.

| | Linux | Windows | RedoxOS | DeSoOS |
|---|---|---|---|---|
| TLS library | OpenSSL, GnuTLS, rustls in the program | Schannel (LSASS) | rustls in the program | DeSoTLS in the program |
| versions | TLS 1.2 and 1.3 | TLS 1.2 and 1.3 | TLS 1.2 and 1.3 | TLS 1.3 only |
| CA store | `/etc/ssl/certs` | system store | compiled into each program | `/etc/certs/roots`, sealed |

Not checked: revocation (CRL, OCSP) and Certificate Transparency. Not audited, not for production use.
