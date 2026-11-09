# DeSoCrypto

DeSoOS's own cryptographic library (`common/desocrypto/`, v0.6.1): hashes, MACs, key derivation, two AEADs, X25519,
signature verification and the random number generator's core. Written for DeSoOS only – no Cargo crate, no outside
code. It is a library, not a service: whoever needs it includes the files (`#[path]`) and calls them directly – the
kernel and programs alike. `core` only: no heap, no syscalls.

What it has (every module, its API and the rules: `ALGORITHMS.md`):

| Group | Algorithms |
|---|---|
| hashes | SHA-256, SHA-384, SHA-512 (no SHA-1, no SHA-224) |
| MAC and key derivation | HMAC and HKDF over any of the hashes |
| encryption | ChaCha20-Poly1305, AES-128-GCM (AES-NI and PCLMULQDQ in programs, a bitsliced fallback without tables) |
| key exchange | X25519 |
| signatures – verification only | RSA PKCS#1 v1.5 and PSS (2048–4096 bits), ECDSA P-256 / SHA-256 and P-384 / SHA-384 |
| random numbers | ChaCha20 with fast key erasure – the kernel's generator (`kernel/random.rs`) and programs' own |

Who uses it: DeSoTLS (certificate and CertificateVerify signatures; the AEADs, X25519 and HKDF in TLS 1.3), the kernel (DeSoFS block checksums, the random number generator, CRYPTO
TEST), `netd` (its own generator keyed from `getrandom`), `/bin/sha256sum`, `/bin/cryptotest`.

How it compares:

| | Linux | Windows | RedoxOS | DeSoOS |
|---|---|---|---|---|
| in the kernel | the kernel crypto API (`crypto/`) | CNG kernel mode (`cng.sys`) | – | the same library as in programs (no SIMD paths) |
| in programs | a library per program (OpenSSL, libsodium, …) | CNG (`bcrypt.dll`) | Rust crates (ring, RustCrypto) | `common/desocrypto` included in the program |
| outside code | yes | – | yes | none |

Where things are:

| Path | What |
|---|---|
| `common/desocrypto/` | the code (file map in its `README.md`) |
| `common/desocrypto/tests.rs` | 4204 checks – only in `/bin/cryptotest` and the kernel's selftest build |
| `common/desocrypto/vectors/` | Wycheproof signature vectors and the script that builds them from a pinned commit |
| `ALGORITHMS.md` | modules, rules of the code, AES-GCM and the CPU, tests, speed |

Tests: CRYPTO TEST (all checks in the kernel and in user space, XMM state across task switches, `sha256sum` against
the kernel, `[RESULT-CRYPTO]` speed figures), RNG TEST for the generator.

Status: not audited, not for production use. The code avoids branches and table look-ups that depend on secrets but
has not been verified for timing; the signature code is not constant time on purpose (it sees only public data).
