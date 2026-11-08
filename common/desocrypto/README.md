# DeSoCrypto v0.6.0

DeSoOS's own cryptographic library, used only inside DeSoOS – by the kernel and by user programs. Plain Rust with
`core` only: no heap, no syscalls, no outside code.

| File | What |
|---|---|
| `mod.rs` | the entry point: errors, hex, constant-time compare, `wipe`, version |
| `sha256.rs` | SHA-256 (FIPS 180-4), streaming and one-shot |
| `sha512.rs` | SHA-512 and SHA-384 (FIPS 180-4), streaming and one-shot |
| `hash.rs` | the hashes behind one interface: `Digest` (for generic code), `HashAlg` / `Hasher` (chosen at run time) |
| `hmac.rs` | HMAC (RFC 2104 / RFC 4231) over any of the hashes – `HmacSha256` as before, `Hmac<Sha384>` etc.; tag check in constant time, a truncated tag at least half the hash |
| `hkdf.rs` | HKDF (RFC 5869) – SHA-256 as before, any hash with `extract_with` / `expand_with` / `hkdf_with` |
| `chacha20.rs` | ChaCha20 (RFC 8439): the block function and the stream XOR |
| `poly1305.rs` | Poly1305 (RFC 8439 §2.5) – one-time authenticator |
| `aead.rs` | ChaCha20-Poly1305 (RFC 8439 §2.8) – `seal` / `open` in place; **never reuse a nonce with the same key** |
| `x25519.rs` | X25519 (RFC 7748) – shared secrets, public keys; an all-zero result refused |
| `aes.rs` | AES-128 encryption (FIPS-197): AES-NI in programs, bitsliced without tables everywhere |
| `ghash.rs` | GHASH (SP 800-38D): PCLMULQDQ in programs, bit by bit with masks everywhere |
| `aes_gcm.rs` | AES-128-GCM – `seal` / `open` in place; **never reuse a nonce with the same key** |
| `bignum.rs` | big numbers (up to 4096 bits, Montgomery) for signature checks – **public data only, not constant time** |
| `rsa.rs` | RSA signature **verification**: PKCS#1 v1.5 and PSS with explicit parameters; n 2048–4096 bits |
| `ecdsa.rs` | ECDSA signature **verification**: P-256 with SHA-256, P-384 with SHA-384; strict DER, every range check; `check_public_key` for a key alone |
| `rng.rs` | a generator with fast key erasure (ChaCha20) – the kernel's CSPRNG, and programs' own generators keyed from `getrandom` |
| `tests.rs` | test vectors and edge cases – included only by `/bin/cryptotest` and the kernel's CRYPTO TEST |
| `vectors/` | `wycheproof.bin` (Wycheproof signature vectors used by `tests.rs`) and `gen-wycheproof.py`, which builds it from a pinned Wycheproof commit (every JSON file checked by SHA-256) |

Use it from a program:

```rust
#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;

let digest = desocrypto::sha256::sha256(b"abc");
```

Users: DeSoTLS (`common/desotls` – certificate signatures), the kernel (DeSoFS block checksums, the random number generator `kernel/random.rs`, CRYPTO TEST),
`netd` (its own generator keyed from `getrandom`), `/bin/sha256sum`, `/bin/cryptotest`.

Signatures: only verification – DeSoOS checks signatures made by others (certificates, TLS); it does not sign
and has no RSA decryption. `bignum`, `rsa` and `ecdsa` are not constant time on purpose: they only ever see public
keys, public signatures and public data. The cost of each check is bounded (at most 4096-bit numbers, e < 2^32, a
fixed curve), so no input can make it run long. They must not be used for anything secret.

Status: not audited, not for production use. The code avoids branches and table look-ups that depend on secret
data; it has not been formally verified or audited for timing. Passing the RFC vectors shows agreement with chosen
cases, not security. Keys are wiped when objects are dropped (volatile writes), but copies in registers and on the
stack are not, and wiping a structure does not wipe its copies. AEAD nonces are the caller's job – reusing one with
the same key is a serious security failure. Test-only code (`assume_length`, `key_for_test`, `freeze_for_test`,
`field_for_test`, `cswap_for_test`, `round_keys_for_test`, `sbox_for_test`, `ghash::mul_for_test`,
`ecdsa::verify_digest`, the `bound!` asserts) exists only in `--cfg selftest` / `--cfg desocrypto_test` builds. The kernel is built with
`--cfg desocrypto_no_simd`, so it contains no AES-NI / PCLMULQDQ paths.

Full description: `docs/desocrypto/` (`ALGORITHMS.md` – every module, the rules, the tests); its place in the system:
`docs/ARCHITECTURE.md`, section "Cryptography – DeSoCrypto".
