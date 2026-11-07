# DeSoCrypto v0.2.0

DeSoOS's own cryptographic library, used only inside DeSoOS – by the kernel and by user programs. Plain Rust with
`core` only: no heap, no syscalls, no outside code.

| File | What |
|---|---|
| `mod.rs` | the entry point: errors, hex, constant-time compare, `wipe`, version |
| `sha256.rs` | SHA-256 (FIPS 180-4), streaming and one-shot |
| `hmac.rs` | HMAC-SHA256 (RFC 2104 / RFC 4231), tag check in constant time |
| `hkdf.rs` | HKDF-SHA256 (RFC 5869) |
| `chacha20.rs` | ChaCha20 (RFC 8439): the block function and the stream XOR |
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

Status: not audited. SHA-256 and ChaCha20 use no tables and no branches on secret data; the tag check is constant
time. Keys are wiped when HMAC / SHA-256 / generator objects are dropped, but copies in registers and on the stack
are not. Test-only code (`assume_length`, `key_for_test`) exists only in `--cfg selftest` / `--cfg desocrypto_test`
builds.

Design: `docs/ARCHITECTURE.md`, section "Cryptography – DeSoCrypto".
