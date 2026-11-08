# DeSoCrypto – algorithms and rules

The detailed description of DeSoCrypto 0.6.0 (`common/desocrypto/`): every module, the rules the code keeps, the CPU
paths and the tests. What it is and where it is used: `README.md` in this folder; how it fits into the system:
`../ARCHITECTURE.md`, section "Cryptography – DeSoCrypto".

## Modules

| Module | What | Standard |
|---|---|---|
| `sha256` | `Sha256::new / update / finish`, `sha256(data)` | FIPS 180-4 |
| `sha512` | `Sha512`, `Sha384` (one core, two starting values), `sha512(data)`, `sha384(data)` | FIPS 180-4 |
| `hash` | `Digest` (trait for generic code), `HashAlg` (chosen at run time: digest, length), `Hasher` (streaming) – SHA-1 / SHA-224 deliberately absent | – |
| `hmac` | `Hmac<D>` over any `Digest`; `HmacSha256::new / update / finish / verify`, `hmac_sha256(key, data)` as before | RFC 2104, vectors RFC 4231 |
| `hkdf` | `extract`, `expand`, `hkdf` (SHA-256); `extract_with / expand_with / hkdf_with::<D>` | RFC 5869 |
| `chacha20` | `block`, `xor_stream` (refuses a wrapping counter) | RFC 8439 |
| `rng` | `KeyErasureRng::new / fill / reseed` – ChaCha20 with fast key erasure | – |
| `poly1305` | `Poly1305::new / update / finish / verify`, `poly1305(key, msg)` – one-time authenticator, limbs 44/44/42 bits | RFC 8439 §2.5 |
| `aead` | `seal(key, nonce, aad, buf) -> tag`, `open(key, nonce, aad, buf, tag)` – ChaCha20-Poly1305 in place | RFC 8439 §2.8 |
| `x25519` | `x25519(secret, their_public)`, `public_key(secret)` – Montgomery ladder, five 51-bit limbs; an all-zero result refused | RFC 7748 (+ RFC 8446 §7.4.2) |
| `aes` | `Aes128::new(key, features)`, `encrypt_blocks` – AES-NI or bitsliced (4 blocks in 8 planes, Boyar–Peralta S-box circuit); `Features::detect / limit` | FIPS-197 |
| `ghash` | `Ghash::new(h, features)`, `update / pad / finish` – PCLMULQDQ or bit by bit with masks | SP 800-38D §6.4 |
| `aes_gcm` | `AesGcm::new / with_features`, `seal / open` in place; 12-byte nonce, 16-byte tag | SP 800-38D |
| `bignum` | `Modulus<N>` (odd, Montgomery CIOS): `pow`, `mul / add / sub / to_mont / from_mont / pow_mont`; up to 4096 bits – **public data only, not constant time** | – |
| `rsa` | `PublicKey::new(n, e)`, `verify_pkcs1(hash, msg, sig)`, `verify_pss(&PssParams, msg, sig)`; `PssParams::tls(h)` | RFC 8017 |
| `ecdsa` | `verify(Curve::P256 / P384, public_key, msg, der_sig)` – each curve with its one hash; `check_public_key(curve, key)` – the key alone | FIPS 186-5, SEC 1 |
| `mod.rs` | `Error`, `hex`, `equal_ct` (constant-time compare), `wipe`, `VERSION` | – |

## Rules of the code

- **Only `core`:** no heap, no syscalls, no `std`. Results go into memory the caller owns (an array returned by
  value or a slice passed in). The same files build in the kernel (code model `kernel`, overflow checks on) and in
  ring-3 programs.
- **No silent wrong results:** SHA-256 counts the message length and refuses past 2^61 − 1 bytes
  (`Error::LengthOverflow`) instead of wrapping; HKDF refuses more than 255 × 32 = 8160 bytes (`OutputTooLong`) and a
  PRK under 32 bytes (`KeyTooShort`) without touching the output; `verify` accepts a tag of at least half the hash and at most
  the full hash (RFC 2104 §5: SHA-256 16–32, SHA-384 24–48, SHA-512 32–64 bytes – `Hmac::<D>::MIN_TAG_LEN`).
- **Arithmetic** is explicitly wrapping (`wrapping_add`, `rotate_right`) – correct with or without overflow checks.
- **Keys** are wiped (volatile writes): `Sha256` and `HmacSha256` clear their whole state when dropped (also
  without `finish`, e.g. on an error path) – the inner SHA-256 state of HMAC is a hash of the key and as good as the
  key; HKDF wipes its PRK and blocks; ChaCha20 wipes its state and key stream, the generator its key; Poly1305 its
  r, s, accumulator and buffer; the AEAD the counter-0 block and the one-time Poly1305 key cut from it; X25519 the
  clamped scalar and the ladder state (x2, z2, x3, z3, the inverse, the product before encoding), and a refused
  all-zero result. Keys come by reference and are not copied by the API. Wiping a structure does not wipe its
  copies: copies in registers or on the stack (the message schedule in `compress`, values the compiler spills) are
  not covered – no full guarantee.
- **Timing:** the implementation avoids branches and table look-ups that depend on secrets (the conditional swap of
  X25519 and the final reduction of Poly1305 use masks; the X25519 inverse uses a fixed public exponent; the zero
  check ORs all bytes first). It has not been formally verified or audited for timing. Tags are compared with
  `equal_ct`.
- **Arithmetic ranges:** every product and sum of Poly1305 and X25519 has its upper bound written next to it, and in
  test builds (`--cfg selftest` / `desocrypto_test`) the bounds are asserted (`bound!`) – far below 2^128.
- **Signatures – verification only, public data only:** `rsa` and `ecdsa` check signatures made by others
  (certificates, TLS CertificateVerify); nothing signs and nothing decrypts with RSA. Their arithmetic (`bignum`,
  Jacobian points, Shamir's trick) is not constant time on purpose – every input is public (the key, the signature,
  the signed data), so there is no secret to leak; it must not be used for anything secret. Every input is bounded:
  RSA n 2048–4096 bits (odd, no leading zero byte), e odd with 3 ≤ e < 2^32, the signature exactly as long as n and
  below it; ECDSA keys must be uncompressed points on the curve with coordinates below p, signatures strict DER
  (short lengths, minimal integers, nothing after them) with 1 ≤ r, s < n. So one check costs at most a 4096-bit
  power with a 32-bit exponent or ~384 point doublings and additions. PKCS#1 v1.5 builds the whole expected block and
  compares it (no parsing of the decrypted block – the Bleichenbacher 2006 forgery needs a lenient parser); the
  DigestInfo without NULL parameters is refused. PSS takes its parameters explicitly (hash, MGF1 hash, salt length):
  `PssParams::tls(h)` is TLS 1.3's rule (same hash, salt = hash length), a certificate's parameters are read by the
  X.509 code and passed as they are – never guessed. ECDSA has exactly one hash per curve (P-256 / SHA-256, P-384 /
  SHA-384) – the pairs TLS 1.3 names and DeSoTLS will announce; no low-s rule (ECDSA has none).
- **AEAD nonces:** reusing a (key, nonce) pair is a serious security failure (the XOR of the plaintexts leaks, the
  Poly1305 key repeats and tags can be forged). DeSoCrypto does not choose nonces – there is no generator or counter
  for them until there is key management to keep them safe. `open` checks the tag before decrypting: with a wrong
  tag the buffer stays exactly as it was.
- **Test-only code stays out:** `assume_length` (a pretended length counter for the limit tests) exists only with
  `--cfg selftest` (the kernel's test build) or `--cfg desocrypto_test` (`build.sh` gives it to `cryptotest` only);
  ordinary programs and the normal kernel do not have it.

## AES-GCM and the CPU

AES-NI (CPUID 1 ECX bit 25) and PCLMULQDQ (bit 1) are detected separately and chosen
separately: hardware AES with software GHASH and the reverse are possible; `Features::limit` can only switch a feature
off (the tests run all four combinations; one the CPU lacks is never forced). The hardware paths use inline assembly
(programs are built for the soft-float target, where LLVM cannot handle 128-bit vector values in Rust code) and clear
the XMM registers they used before returning. They exist only in programs: the kernel is built with
`--cfg desocrypto_no_simd` and has no AES-NI / PCLMULQDQ code at all, because its own code runs with CR0.TS = 1 and
never saves XMM for itself – a process's XMM state is saved and restored with FXSAVE / FXRSTOR on every task switch
(`fpu.rs`), and CRYPTO TEST 5 checks it with four processes at once (a pattern in xmm0–xmm15 checked after every
yield, hardware AES-GCM compared with the software result). The fallback is bitsliced AES (four blocks at once; a
last group of 1–3 blocks and a tail under 16 bytes go through a local array – nothing outside the slice is touched)
and bit-by-bit GHASH; both avoid tables and branches on secrets. GCM nonce reuse: it reveals the XOR of the plaintexts
and, under certain conditions, can make it possible to recover H and forge tags – the caller must keep nonces unique.

## Tests

`common/desocrypto/tests.rs` (4204 checks; signatures: SHA-384/512 FIPS 180-4 examples and padding edges,
RFC 4231 for HMAC-SHA384/512, HKDF-SHA384/512 against Python `cryptography`; modular powers of 64–4096-bit numbers
against Python integers; RSA keys and signatures from `cryptography` – PKCS#1 v1.5 and PSS with several parameter
sets, a 2049-bit key (the PSS block one byte shorter than the signature), crafted almost-right blocks (padding 0xfe,
block type 2, no separator, a bit above emBits), s = 0 / n, wrong lengths, keys outside the rules; ECDSA P-256 /
P-384 including the key with private value 1, digests e > n / e = n / e = 0, high s, DER variants and public keys off
the curve or with x + p; Wycheproof (`vectors/wycheproof.bin`, built by `vectors/gen-wycheproof.py` from a pinned
commit – ECDSA P-256 and P-384, RSA PKCS#1 2048/SHA-256, PSS 2048/SHA-256 and the PSS "misc" sets: every "valid" case
verifies, every "invalid" and "acceptable" case is refused; the RSA 3072 / 4096 sets were checked on the host, not
shipped); 36 hand-made mutations of the new code were run on the host – 33 caught, 3 equivalent (a check that a later
check repeats); AES-GCM: FIPS-197 C.1 / A.1, the circuit S-box for all 256 inputs,
1–5 blocks, GF(2^128) products and GHASH against SP 800-38D written on Python integers, NIST Test Cases 1–4, every
length 0–95 and 1000 inside guard bytes, aad of 1 / 15 / 16 / 17 bytes, a wrong tag leaving the buffer untouched –
each with every AES-NI / PCLMULQDQ combination the CPU allows; before that: FIPS 180-4 / NIST, RFC 4231, RFC 5869, RFC 8439, RFC 7748 vectors;
Poly1305 limbs at their maximum and the final reduction around 2^130 − 5; X25519 field operations on edge values,
`cswap`, the seven low-order points; AEAD with a wrong tag / aad / nonce / key / ciphertext bit leaving the buffer
untouched; expected values from Python big integers – the RFC formulas, not the limb code – and the `cryptography`
library; the generator against the same construction in Python; block-edge lengths;
every split of a message; length limits with a pretended counter; wrong tags and parameters). `mod.rs` does not
include it, so it is not in the kernel or ordinary programs: only `/bin/cryptotest` and CRYPTO TEST (selftest build)
include it. CRYPTO TEST runs it in the kernel and in user space, checks `sha256sum` against the kernel's own result
and measures the speed (`[RESULT-CRYPTO]`).

Speed (`[RESULT-CRYPTO]`, v0.74.2, QEMU on the test machine, 4 CPUs):

| | TCG | KVM |
|---|---|---|
| SHA-256 kernel / user (KiB/s) | 49 425 / 51 582 | 174 080 / 216 320 |
| SHA-512 user (KiB/s) | 102 720 | 355 840 |
| HMAC-SHA256 user (KiB/s) | 52 160 | 216 640 |
| ChaCha20-Poly1305 user (KiB/s) | 70 080 | 354 240 |
| AES-128-GCM hardware / software (KiB/s) | 49 920 / 8 960 | 529 280 / 26 427 |
| X25519 (operations / s) | 1 395 | 9 745 |
| RSA-2048 / P-256 / P-384 verifications / s | 2 180 / 448 / 180 | 13 100 / 3 820 / 1 366 |

## What the tests prove

Passing the RFC and Wycheproof vectors shows agreement with chosen cases of the standards; it does not prove the
implementation secure. DeSoCrypto is not for production use without an audit. The signature checks are used by DeSoTLS
(certificate chains, since v0.74); the AEADs and X25519 not yet – they are for the TLS 1.3 handshake and records
(v0.75).
