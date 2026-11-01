# DeSoCrypto v0.1.0

DeSoOS's own cryptographic library (DecodeSoft), used only inside DeSoOS – by the
kernel and by user programs. Plain Rust with `core` only: no heap, no syscalls,
no outside code.

| Module | Contents |
|---|---|
| `sha256.rs` | SHA-256 (FIPS 180-4), streaming and one-shot |
| `hmac.rs` | HMAC-SHA256 (RFC 2104 / RFC 4231), tag check in constant time |
| `hkdf.rs` | HKDF-SHA256 (RFC 5869) |
| `mod.rs` | errors, hex, constant-time compare, version |
| `tests.rs` | vectors and edge cases – included only by `/bin/cryptotest` and CRYPTO TEST |

Use it from a program:

```rust
#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;

let digest = desocrypto::sha256::sha256(b"abc");
```

Status: not audited and not hardened against timing side channels (beyond the
tag check). Fine for checksums; not yet for protecting secrets.
Details: `ARCHITECTURE.md`, section "Cryptography – DeSoCrypto".
