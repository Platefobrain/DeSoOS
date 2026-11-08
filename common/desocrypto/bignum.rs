// Big unsigned integers for signature VERIFICATION – PUBLIC DATA ONLY.
//
//   Modulus::<N>::new(m_be)     an odd modulus of up to 64·N bits (big-endian bytes)
//   m.pow(base, exp_be)         base^exp mod m (RSA: s^e mod n)
//   m.to_mont / mul / add / sub / from_mont / pow_mont   Montgomery arithmetic (ECDSA)
//   from_be / to_be / lt / is_zero                       conversions and comparisons
//
// Numbers are little-endian arrays of 64-bit limbs, [u64; N]; a Modulus uses its first
// `n` limbs (n <= N – RSA keeps N = 64 for every key size, the curves N = n = 4 or 6).
// Multiplication is Montgomery's (CIOS, R = 2^(64·n)).
//
// NOT constant time: loops stop early, branches depend on the values (the final
// subtraction, the exponent bits).  That is fine for the only use here – checking a
// signature with a public key on public data (a certificate, a TLS transcript) – and
// wrong for anything secret (a private key, a key exchange).  The cost of every
// operation is bounded by N (at most 4096 bits: RSA keys and moduli are limited by the
// callers), so no input can make it run long.

use super::Error;

/// Limbs of the largest number (4096 bits – the RSA limit).
pub const MAX_LIMBS: usize = 64;

#[inline]
fn mac(acc: u64, a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = acc as u128 + (a as u128) * (b as u128) + carry as u128;
    (t as u64, (t >> 64) as u64)
}

/// a < b on the first n limbs.
pub fn lt(a: &[u64], b: &[u64], n: usize) -> bool {
    for i in (0..n).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

pub fn is_zero(a: &[u64]) -> bool {
    a.iter().all(|&w| w == 0)
}

/// a -= b on the first n limbs; the borrow out.
fn sub_in_place(a: &mut [u64], b: &[u64], n: usize) -> bool {
    let mut borrow = false;
    for i in 0..n {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow as u64);
        a[i] = d2;
        borrow = b1 || b2;
    }
    borrow
}

/// a += b on the first n limbs; the carry out.
fn add_in_place(a: &mut [u64], b: &[u64], n: usize) -> bool {
    let mut carry = false;
    for i in 0..n {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry as u64);
        a[i] = s2;
        carry = c1 || c2;
    }
    carry
}

/// Big-endian bytes -> limbs.  Error::InvalidLength if the bytes do not fit in N limbs.
/// Leading zero bytes are allowed here (callers that need minimal encodings check them).
pub fn from_be<const N: usize>(bytes: &[u8]) -> Result<[u64; N], Error> {
    let mut start = 0;
    while start < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    let b = &bytes[start..];
    if b.len() > 8 * N {
        return Err(Error::InvalidLength);
    }
    let mut out = [0u64; N];
    for (i, byte) in b.iter().rev().enumerate() {
        out[i / 8] |= (*byte as u64) << (8 * (i % 8));
    }
    Ok(out)
}

/// Limbs -> exactly `out.len()` big-endian bytes.  Error::InvalidLength if the value does
/// not fit.
pub fn to_be(a: &[u64], out: &mut [u8]) -> Result<(), Error> {
    let k = out.len();
    for (i, w) in a.iter().enumerate() {
        for j in 0..8 {
            let byte = (w >> (8 * j)) as u8;
            let pos = 8 * i + j;
            if pos < k {
                out[k - 1 - pos] = byte;
            } else if byte != 0 {
                return Err(Error::InvalidLength);
            }
        }
    }
    Ok(())
}

/// Number of significant bits.
pub fn bit_len(a: &[u64]) -> usize {
    for i in (0..a.len()).rev() {
        if a[i] != 0 {
            return 64 * i + 64 - a[i].leading_zeros() as usize;
        }
    }
    0
}

/// An odd modulus m > 1 with the Montgomery constants.
pub struct Modulus<const N: usize> {
    m: [u64; N],
    n: usize,
    /// -m^-1 mod 2^64.
    m0inv: u64,
    /// R^2 mod m (R = 2^(64·n)).
    rr: [u64; N],
}

impl<const N: usize> Modulus<N> {
    /// From big-endian bytes without a leading zero byte; odd, at least 3, at most 64·N bits.
    pub fn new(be: &[u8]) -> Result<Self, Error> {
        if be.is_empty() || be[0] == 0 || be.len() > 8 * N || be[be.len() - 1] & 1 == 0 {
            return Err(Error::InvalidLength);
        }
        let m = from_be::<N>(be)?;
        let n = be.len().div_ceil(8);
        if n == 1 && m[0] < 3 {
            return Err(Error::InvalidLength);
        }
        // Newton: x = m0^-1 mod 2^64 (x = m0 is right to 3 bits; each step doubles them).
        let mut x = m[0];
        for _ in 0..6 {
            x = x.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(x)));
        }
        let mut md = Modulus { m, n, m0inv: x.wrapping_neg(), rr: [0; N] };
        // R^2 mod m by doubling 1 2·64·n times (x < m before each step, so one subtraction).
        let mut r = [0u64; N];
        r[0] = 1;
        for _ in 0..128 * n {
            md.double(&mut r);
        }
        md.rr = r;
        Ok(md)
    }

    pub fn limbs(&self) -> usize {
        self.n
    }

    pub fn bits(&self) -> usize {
        bit_len(&self.m[..self.n])
    }

    pub fn modulus(&self) -> &[u64; N] {
        &self.m
    }

    /// a = 2a mod m (a < m).
    fn double(&self, a: &mut [u64; N]) {
        let n = self.n;
        let mut carry = 0u64;
        for w in a.iter_mut().take(n) {
            let top = *w >> 63;
            *w = (*w << 1) | carry;
            carry = top;
        }
        if carry != 0 || !lt(a, &self.m, n) {
            sub_in_place(a, &self.m, n);
        }
    }

    /// a < m?
    pub fn is_reduced(&self, a: &[u64; N]) -> bool {
        a[self.n..].iter().all(|&w| w == 0) && lt(a, &self.m, self.n)
    }

    /// Montgomery product a·b·R^-1 mod m.  a < R and b < m (or the reverse) gives a result
    /// below m.
    pub fn mul(&self, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let n = self.n;
        // t = n + 2 limbs: t[..n] and the two top limbs in t_hi (N + 2 cannot be an array
        // length with a const generic).
        let mut t = [0u64; N];
        let mut t_hi = [0u64; 2];
        for i in 0..n {
            let mut c = 0u64;
            for j in 0..n {
                let (lo, hi) = mac(t[j], a[i], b[j], c);
                t[j] = lo;
                c = hi;
            }
            let (s, c2) = t_hi[0].overflowing_add(c);
            t_hi[0] = s;
            t_hi[1] = c2 as u64;
            let q = t[0].wrapping_mul(self.m0inv);
            let (_, mut c) = mac(t[0], q, self.m[0], 0);
            for j in 1..n {
                let (lo, hi) = mac(t[j], q, self.m[j], c);
                t[j - 1] = lo;
                c = hi;
            }
            let (s, c3) = t_hi[0].overflowing_add(c);
            t[n - 1] = s;
            t_hi[0] = t_hi[1] + c3 as u64;
            t_hi[1] = 0;
        }
        if t_hi[0] != 0 || !lt(&t, &self.m, n) {
            sub_in_place(&mut t, &self.m, n);
        }
        t
    }

    /// a·R mod m for any a < R (also a >= m: reduces it).
    pub fn to_mont(&self, a: &[u64; N]) -> [u64; N] {
        self.mul(a, &self.rr)
    }

    /// a·R^-1 mod m – back from the Montgomery form.
    pub fn from_mont(&self, a: &[u64; N]) -> [u64; N] {
        let mut one = [0u64; N];
        one[0] = 1;
        self.mul(a, &one)
    }

    /// a mod m for any a < R.
    pub fn reduce(&self, a: &[u64; N]) -> [u64; N] {
        self.from_mont(&self.to_mont(a))
    }

    /// (a + b) mod m, a and b < m.
    pub fn add(&self, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let mut s = *a;
        let carry = add_in_place(&mut s, b, self.n);
        if carry || !lt(&s, &self.m, self.n) {
            sub_in_place(&mut s, &self.m, self.n);
        }
        s
    }

    /// (a - b) mod m, a and b < m.
    pub fn sub(&self, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        let mut d = *a;
        if sub_in_place(&mut d, b, self.n) {
            add_in_place(&mut d, &self.m, self.n);
        }
        d
    }

    /// a^exp in the Montgomery form (a in Montgomery form; exp big-endian bytes).
    pub fn pow_mont(&self, a: &[u64; N], exp: &[u8]) -> [u64; N] {
        let mut one = [0u64; N];
        one[0] = 1;
        let mut x = self.to_mont(&one);
        let mut started = false;
        for byte in exp {
            for bit in (0..8).rev() {
                if started {
                    x = self.mul(&x, &x);
                }
                if (byte >> bit) & 1 == 1 {
                    x = if started { self.mul(&x, a) } else { *a };
                    started = true;
                }
            }
        }
        x
    }

    /// base^exp mod m (base < m, normal form; exp big-endian bytes).
    pub fn pow(&self, base: &[u64; N], exp: &[u8]) -> [u64; N] {
        let b = self.to_mont(base);
        self.from_mont(&self.pow_mont(&b, exp))
    }
}
