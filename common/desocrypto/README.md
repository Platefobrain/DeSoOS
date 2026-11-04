# DeSoCrypto v0.1.1

DeSoOS's own cryptographic library, used only inside DeSoOS – by the kernel and by user programs. Plain Rust with
`core` only: no heap, no syscalls, no outside code.

| File | What |
|---|---|
| `mod.rs` | the entry point: errors, hex, constant-time compare, version |
| `sha256.rs` | SHA-256 (FIPS 180-4), streaming and one-shot |
| `hmac.rs` | HMAC-SHA256 (RFC 2104 / RFC 4231), tag check in constant time |
| `hkdf.rs` | HKDF-SHA256 (RFC 5869) |
| `tests.rs` | test vectors and edge cases – included only by `/bin/cryptotest` and the kernel's CRYPTO TEST |

Use it from a program:

```rust
#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;

let digest = desocrypto::sha256::sha256(b"abc");
```

Users: the kernel (DeSoFS block checksums, CRYPTO TEST), `/bin/sha256sum`, `/bin/cryptotest`.

Status: not audited and not hardened against timing side channels (beyond the tag check). Keys are wiped when HMAC /
SHA-256 objects are dropped, but stack temporaries are not. Fine for checksums; not yet for protecting secrets.
Test-only code (`assume_length`) exists only in `--cfg selftest` / `--cfg desocrypto_test` builds.

Design: `docs/ARCHITECTURE.md`, section "Cryptography – DeSoCrypto".
