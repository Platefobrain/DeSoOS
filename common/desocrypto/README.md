# DeSoCrypto v0.3.0

DeSoOS's own cryptographic library, used only inside DeSoOS – by the kernel and by user programs. Plain Rust with
`core` only: no heap, no syscalls, no outside code.

| File | What |
|---|---|
| `mod.rs` | the entry point: errors, hex, constant-time compare, `wipe`, version |
| `sha256.rs` | SHA-256 (FIPS 180-4), streaming and one-shot |
| `hmac.rs` | HMAC-SHA256 (RFC 2104 / RFC 4231), tag check in constant time |
| `hkdf.rs` | HKDF-SHA256 (RFC 5869) |
| `chacha20.rs` | ChaCha20 (RFC 8439): the block function and the stream XOR |
| `poly1305.rs` | Poly1305 (RFC 8439 §2.5) – one-time authenticator |
| `aead.rs` | ChaCha20-Poly1305 (RFC 8439 §2.8) – `seal` / `open` in place; **never reuse a nonce with the same key** |
| `x25519.rs` | X25519 (RFC 7748) – shared secrets, public keys; an all-zero result refused |
| `rng.rs` | a generator with fast key erasure (ChaCha20) – the kernel's CSPRNG, and programs' own generators keyed from `getrandom` |
| `tests.rs` | test vectors and edge cases – included only by `/bin/cryptotest` and the kernel's CRYPTO TEST |

Use it from a program:

```rust
#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;

let digest = desocrypto::sha256::sha256(b"abc");
```

Users: the kernel (DeSoFS block checksums, the random number generator `kernel/random.rs`, CRYPTO TEST),
`netd` (its own generator keyed from `getrandom`), `/bin/sha256sum`, `/bin/cryptotest`.

Status: not audited, not for production use. The code avoids branches and table look-ups that depend on secret
data; it has not been formally verified or audited for timing. Passing the RFC vectors shows agreement with chosen
cases, not security. Keys are wiped when objects are dropped (volatile writes), but copies in registers and on the
stack are not, and wiping a structure does not wipe its copies. AEAD nonces are the caller's job – reusing one with
the same key is a serious security failure. Test-only code (`assume_length`, `key_for_test`, `freeze_for_test`,
`field_for_test`, `cswap_for_test`, the `bound!` asserts) exists only in `--cfg selftest` / `--cfg desocrypto_test`
builds.

Design: `docs/ARCHITECTURE.md`, section "Cryptography – DeSoCrypto".
