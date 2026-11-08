// X25519 (RFC 7748): Diffie-Hellman on Curve25519 – the u coordinate only, the Montgomery
// ladder.
//
//   public_key(secret)          the public key (u = 9 times the clamped secret)
//   x25519(secret, their_pub)   the shared secret; Err(Mismatch) when it is all zeros
//
// An all-zero result means the other side sent a point of low order (it contributes
// nothing secret).  RFC 7748 (section 6.1) leaves checking it to the protocol; TLS 1.3
// (RFC 8446 section 7.4.2) requires rejecting it – this API always does.
//
// Field arithmetic mod p = 2^255 - 19 in five 51-bit limbs (products in u128).  The ladder
// runs 255 steps for every scalar; the conditional swap uses a mask, never a branch; the
// inverse is z^(p-2) with a fixed (public) exponent; the zero check ORs all bytes before
// one comparison (it reveals only that the result is zero, which the error says anyway).
// The implementation avoids branches and table look-ups that depend on secrets; it has not
// been formally verified or audited for timing.
//
// Wiped (volatile writes): the clamped scalar, the ladder state (x2, z2, x3, z3 and the
// temporaries of the last step), the result before the zero check when it is refused.  The
// secret comes by reference and is not copied except the clamped scalar; copies the
// compiler keeps in registers or on the stack are not covered.

use super::Error;

type Fe = [u64; 5];
const M51: u64 = (1 << 51) - 1;

/// Test builds: a bound that must hold.
macro_rules! bound {
    ($cond:expr) => {
        #[cfg(any(selftest, desocrypto_test))]
        assert!($cond, "x25519 bound: {}", stringify!($cond));
    };
}

fn load(b: &[u8; 32]) -> Fe {
    let w = |i: usize| {
        let mut x = [0u8; 8];
        x.copy_from_slice(&b[i..i + 8]);
        u64::from_le_bytes(x)
    };
    let (a0, a1, a2, a3) = (w(0), w(8), w(16), w(24));
    // The top bit (bit 255) is ignored (RFC 7748 section 5).
    [a0 & M51, ((a0 >> 51) | (a1 << 13)) & M51, ((a1 >> 38) | (a2 << 26)) & M51, ((a2 >> 25) | (a3 << 39)) & M51, (a3 >> 12) & M51]
}

/// Limbs back under 2^51 (the carry out of the top limb times 19 into limb 0); the value
/// is unchanged mod p.  Input limbs < 2^63.
fn carry(a: &mut Fe) {
    for _ in 0..2 {
        let c = a[0] >> 51;
        a[0] &= M51;
        a[1] += c;
        let c = a[1] >> 51;
        a[1] &= M51;
        a[2] += c;
        let c = a[2] >> 51;
        a[2] &= M51;
        a[3] += c;
        let c = a[3] >> 51;
        a[3] &= M51;
        a[4] += c;
        let c = a[4] >> 51;
        a[4] &= M51;
        a[0] += c * 19;
    }
}

/// The canonical value (0 <= v < p) as 32 bytes.
fn store(a: &Fe) -> [u8; 32] {
    let mut t = *a;
    carry(&mut t);
    // q = 1 when t >= p (t + 19 carries out of 2^255).
    let mut q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51;
    q = (t[2] + q) >> 51;
    q = (t[3] + q) >> 51;
    q = (t[4] + q) >> 51;
    t[0] += 19 * q;
    let c = t[0] >> 51;
    t[0] &= M51;
    t[1] += c;
    let c = t[1] >> 51;
    t[1] &= M51;
    t[2] += c;
    let c = t[2] >> 51;
    t[2] &= M51;
    t[3] += c;
    let c = t[3] >> 51;
    t[3] &= M51;
    t[4] += c;
    t[4] &= M51;
    let mut out = [0u8; 32];
    let lo = [t[0] | (t[1] << 51), (t[1] >> 13) | (t[2] << 38), (t[2] >> 26) | (t[3] << 25), (t[3] >> 39) | (t[4] << 12)];
    for i in 0..4 {
        out[8 * i..8 * i + 8].copy_from_slice(&lo[i].to_le_bytes());
    }
    super::wipe_words64(&mut t);
    out
}

fn add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]];
    carry(&mut r);
    r
}

/// a - b + 4p (every limb of 4p is above any carried limb, so nothing goes negative).
fn sub(a: &Fe, b: &Fe) -> Fe {
    bound!(b.iter().all(|&l| l < 1 << 52));
    const P4: [u64; 5] = [0x1f_ffff_ffff_ffb4, 0x1f_ffff_ffff_fffc, 0x1f_ffff_ffff_fffc, 0x1f_ffff_ffff_fffc, 0x1f_ffff_ffff_fffc];
    let mut r = [a[0] + P4[0] - b[0], a[1] + P4[1] - b[1], a[2] + P4[2] - b[2], a[3] + P4[3] - b[3], a[4] + P4[4] - b[4]];
    carry(&mut r);
    r
}

/// a * b mod p.  Inputs carried (limbs < 2^52): b_i * 19 < 2^57, each product < 2^109, a
/// sum of five < 2^112 – no u128 overflow; the carry out of r4 is < 2^61 (times 19 done
/// in u128).
fn mul(a: &Fe, b: &Fe) -> Fe {
    bound!(a.iter().all(|&l| l < 1 << 52) && b.iter().all(|&l| l < 1 << 52));
    let m = |x: u64, y: u64| x as u128 * y as u128;
    let b19 = [b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19];
    let r0 = m(a[0], b[0]) + m(a[1], b19[3]) + m(a[2], b19[2]) + m(a[3], b19[1]) + m(a[4], b19[0]);
    let r1 = m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b19[3]) + m(a[3], b19[2]) + m(a[4], b19[1]);
    let r2 = m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b19[3]) + m(a[4], b19[2]);
    let r3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b19[3]);
    let r4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);
    bound!(r0 < 1 << 115 && r1 < 1 << 115 && r2 < 1 << 115 && r3 < 1 << 115 && r4 < 1 << 115);
    let mut r = [0u64; 5];
    let c = r0 >> 51;
    r[0] = r0 as u64 & M51;
    let r1 = r1 + c;
    let c = r1 >> 51;
    r[1] = r1 as u64 & M51;
    let r2 = r2 + c;
    let c = r2 >> 51;
    r[2] = r2 as u64 & M51;
    let r3 = r3 + c;
    let c = r3 >> 51;
    r[3] = r3 as u64 & M51;
    let r4 = r4 + c;
    let c = r4 >> 51;
    r[4] = r4 as u64 & M51;
    // The part above 2^255, times 19, back into limb 0 (in u128: c < 2^61).
    let v = r[0] as u128 + c * 19;
    r[0] = v as u64 & M51;
    r[1] += (v >> 51) as u64;
    carry(&mut r);
    r
}

fn sq(a: &Fe) -> Fe {
    mul(a, a)
}

/// a * 121665 (the curve constant (A - 2) / 4).
fn mul_a24(a: &Fe) -> Fe {
    let mut r = [0u64; 5];
    let mut c: u128 = 0;
    for i in 0..5 {
        let v = a[i] as u128 * 121_665 + c;
        r[i] = v as u64 & M51;
        c = v >> 51;
    }
    r[0] += c as u64 * 19;
    carry(&mut r);
    r
}

/// a^(p-2) = 1/a (0 for 0).  The exponent is public, so its bits may steer the loop.
fn invert(a: &Fe) -> Fe {
    // p - 2 = 2^255 - 21: bits 254..5 set, then 01011 (21 = 10101 -> p-2 low bits 01011).
    let mut r = [1u64, 0, 0, 0, 0];
    let e: [u8; 32] = {
        let mut e = [0xffu8; 32];
        e[0] = 0xeb;
        e[31] = 0x7f;
        e
    };
    for i in (0..255).rev() {
        r = sq(&r);
        if (e[i / 8] >> (i % 8)) & 1 == 1 {
            r = mul(&r, a);
        }
    }
    r
}

/// Swaps a and b when `swap` is 1, without a branch.
fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..5 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/// The ladder (RFC 7748 section 5): k (already clamped) times u.
fn ladder(k: &[u8; 32], u: &Fe) -> [u8; 32] {
    let x1 = *u;
    let mut x2: Fe = [1, 0, 0, 0, 0];
    let mut z2: Fe = [0; 5];
    let mut x3 = *u;
    let mut z3: Fe = [1, 0, 0, 0, 0];
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let kt = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swap ^= kt;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = kt;
        let a = add(&x2, &z2);
        let aa = sq(&a);
        let b = sub(&x2, &z2);
        let bb = sq(&b);
        let e = sub(&aa, &bb);
        let c = add(&x3, &z3);
        let d = sub(&x3, &z3);
        let da = mul(&d, &a);
        let cb = mul(&c, &b);
        x3 = sq(&add(&da, &cb));
        z3 = mul(&x1, &sq(&sub(&da, &cb)));
        x2 = mul(&aa, &bb);
        z2 = mul(&e, &add(&aa, &mul_a24(&e)));
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);
    let mut zi = invert(&z2);
    let mut r = mul(&x2, &zi);
    let out = store(&r);
    for v in [&mut x2, &mut z2, &mut x3, &mut z3, &mut zi, &mut r] {
        super::wipe_words64(v);
    }
    out
}

/// The scalar after the RFC 7748 clamp (bits 0-2 and 255 cleared, bit 254 set).
fn clamp(secret: &[u8; 32]) -> [u8; 32] {
    let mut k = *secret;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// The shared secret of `secret` and the other side's public key `u`.  Err(Mismatch)
/// when it is all zeros (a low-order point – see the top).
pub fn x25519(secret: &[u8; 32], u: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut k = clamp(secret);
    let mut out = ladder(&k, &load(u));
    super::wipe(&mut k);
    let mut acc = 0u8;
    for b in out.iter() {
        acc |= *b;
    }
    // 1 when every byte was 0 – computed without a branch on the bytes themselves.
    let zero = ((acc as u32).wrapping_sub(1) >> 8) & 1;
    if zero == 1 {
        super::wipe(&mut out);
        return Err(Error::Mismatch);
    }
    Ok(out)
}

/// The public key of `secret` (the base point u = 9).
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    let mut nine = [0u8; 32];
    nine[0] = 9;
    // The base point has prime order: the result is never zero.
    x25519(secret, &nine).unwrap_or([0; 32])
}

/// Test only: field operations on 32-byte little-endian values (top bit ignored), the
/// result canonical.  `op`: 0 = a*b, 1 = a^2, 2 = 1/a, 3 = a + b, 4 = a - b.
#[cfg(any(selftest, desocrypto_test))]
pub fn field_for_test(op: u8, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (fa, fb) = (load(a), load(b));
    let r = match op {
        0 => mul(&fa, &fb),
        1 => sq(&fa),
        2 => invert(&fa),
        3 => add(&fa, &fb),
        _ => sub(&fa, &fb),
    };
    store(&r)
}

/// Test only: `cswap` on two values – (a', b').
#[cfg(any(selftest, desocrypto_test))]
pub fn cswap_for_test(swap: u64, a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let (mut fa, mut fb) = (load(a), load(b));
    cswap(swap, &mut fa, &mut fb);
    (store(&fa), store(&fb))
}
