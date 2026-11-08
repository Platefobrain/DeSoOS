# DeSoTLS

DeSoOS's own TLS library (`common/desotls/`, v0.1.0), over DeSoCrypto and like it a library: `core` only, no heap,
no syscalls, included by the programs that use it. Client only. The rule above all: **either the certificate is
fully checked and the connection is safe, or no application data is sent** – no "insecure" switch, no fallback.

What it does so far (details: `CERTIFICATES.md`):

- checks a server's X.509 certificate chain for a host at a time – strict DER, the RFC 5280 profile (keys, signature
  algorithms, extensions, name constraints, path length), path building to a trust anchor, Mozilla's distrust
  dates, limits so that no input makes it run long;
- reads the trusted CA store `/etc/certs/roots` – Mozilla's roots for server certificates, built into the image and
  sealed at boot (no program can change it);
- refuses to trust dates when the wall clock is not plausible (syscall 59: RTC battery, readings, not before the
  build date);
- `certcheck` checks a chain offline with the same code.

Next (v0.75): the TLS 1.3 handshake (X25519; AES-128-GCM and ChaCha20-Poly1305; RSA-PSS and ECDSA signatures) and
the record layer, `netget https://`. Its description will be a new document here.

Where things are:

| Path | What |
|---|---|
| `common/desotls/` | the code (file map in its `README.md`) |
| `common/desotls/tests.rs`, `vectors/` | 257 checks, 115 made-up chains, 12 real ones |
| `user/etc/certs/` | the CA store `roots` and `gen-roots.py`, which makes it from Mozilla's `certdata.txt` |
| `kernel/drivers/rtc.rs` | the wall clock and its verdict |
| `user/bin/certcheck.rs`, `user/bin/certtest.rs` | the tools |
| `CERTIFICATES.md` | the profile, the order of the checks, path building, every refusal, the store format, the clock, the tests |

Tests: CERT TEST (6 steps: the library in the kernel and in user space, the installed store, the seal, the clock,
`certcheck`; `[RESULT-CERTS]`); on the host x509-limbo, fuzzing and mutations.

Not checked: revocation (CRL, OCSP) and Certificate Transparency. Not audited, not for production use.
