// DeSoCrypto – the DeSoOS cryptographic library (version: VERSION below).
//
// Plain code, no system behind it: no syscalls, no heap, no `std` – only `core`.
// Every result goes into memory the caller owns (an array returned by value or a
// slice passed in).  So the same files can be included (`#[path]`) by the kernel
// and by user programs; it is a library, not a service and not a kernel module.
//
//   sha256  SHA-256 (FIPS 180-4) – streaming (new / update / finish) and one-shot
//   hmac    HMAC-SHA256 (RFC 2104, vectors RFC 4231) – tags and their checking
//   hkdf    HKDF-SHA256 (RFC 5869) – keys derived from a secret
//   chacha20  ChaCha20 (RFC 8439) – the stream cipher (no tables: constant time)
//   rng     a generator with fast key erasure (ChaCha20) – the kernel's CSPRNG and
//           programs' own generators seeded from `getrandom`
//
// Not included on purpose: tests.rs (official vectors, edge cases) – only
// /bin/cryptotest and the kernel CRYPTO TEST include it, next to this module.
//
// Limits: not audited.  SHA-256, HMAC and ChaCha20 use no tables and no branches on
// secret data; the tag comparison is constant-time.  Key material is wiped when the
// HMAC / SHA-256 / generator objects are dropped (volatile writes), but Rust may leave
// temporary copies in registers or on the stack (e.g. the message schedule in
// `compress`) – no full guarantee.
#![allow(dead_code)]

pub mod aead;
pub mod chacha20;
pub mod hkdf;
pub mod hmac;
pub mod poly1305;
pub mod rng;
pub mod sha256;
pub mod x25519;

pub const VERSION: &str = "0.3.0";

/// Zeroes secret bytes with volatile writes the compiler keeps (keys, key streams).
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned &mut u8.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// The same for 64-bit words (limbs of Poly1305 / X25519).
pub fn wipe_words64(buf: &mut [u64]) {
    for w in buf.iter_mut() {
        // SAFETY: `w` is a valid, aligned &mut u64.
        unsafe { core::ptr::write_volatile(w, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// The same for 32-bit words (cipher states).
pub fn wipe_words(buf: &mut [u32]) {
    for w in buf.iter_mut() {
        // SAFETY: `w` is a valid, aligned &mut u32.
        unsafe { core::ptr::write_volatile(w, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// What can go wrong.  Every function returns one of these instead of panicking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// More data than the algorithm can count (SHA-256: 2^61 - 1 bytes).
    LengthOverflow,
    /// HKDF: more output than 255 × 32 = 8160 bytes asked for.
    OutputTooLong,
    /// HKDF expand: the pseudorandom key is shorter than 32 bytes.
    KeyTooShort,
    /// A length outside the allowed range (e.g. an HMAC tag under 16 bytes).
    InvalidLength,
    /// The output buffer is too small.
    BufferTooSmall,
    /// A tag did not match.
    Mismatch,
}

impl Error {
    pub fn as_str(self) -> &'static str {
        match self {
            Error::LengthOverflow => "length overflow",
            Error::OutputTooLong => "output too long",
            Error::KeyTooShort => "key too short",
            Error::InvalidLength => "invalid length",
            Error::BufferTooSmall => "buffer too small",
            Error::Mismatch => "mismatch",
        }
    }
}

/// Lower-case hex of `src` into `dst` (2 bytes per input byte); the written text.
pub fn hex<'a>(src: &[u8], dst: &'a mut [u8]) -> Result<&'a str, Error> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let n = src.len().checked_mul(2).ok_or(Error::LengthOverflow)?;
    if dst.len() < n {
        return Err(Error::BufferTooSmall);
    }
    for (i, b) in src.iter().enumerate() {
        dst[2 * i] = DIGITS[(b >> 4) as usize];
        dst[2 * i + 1] = DIGITS[(b & 15) as usize];
    }
    // Only ASCII digits were written.
    core::str::from_utf8(&dst[..n]).map_err(|_| Error::InvalidLength)
}

/// Compares two byte strings in time that depends only on their length (not on
/// where the first difference is) – for tags, so a forger cannot guess byte by byte.
pub fn equal_ct(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    // black_box keeps the compiler from turning the loop into an early exit.
    core::hint::black_box(diff) == 0
}
