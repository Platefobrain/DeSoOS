// ECDSA signature VERIFICATION (FIPS 186-5, SEC 1) on NIST P-256 and P-384.
//
//   ecdsa::verify(Curve::P256, public_key, msg, der_signature)?   // hash SHA-256
//   ecdsa::verify(Curve::P384, public_key, msg, der_signature)?   // hash SHA-384
//   ecdsa::check_public_key(Curve::P256, public_key)?             // the key alone
//
// Each curve has exactly one hash – the pairs TLS 1.3 names (ecdsa_secp256r1_sha256,
// ecdsa_secp384r1_sha384) and DeSoTLS announces.  P-384 with SHA-256 or P-256 with SHA-384
// cannot even be asked for.
//
// Checks, all of them:
// * the public key: uncompressed 04 ‖ X ‖ Y of the right length, X and Y < p, the point
//   on the curve y² = x³ - 3x + b (cofactor 1, so on the curve = in the group; the point at
//   infinity has no uncompressed form);
// * the signature: strict DER SEQUENCE { INTEGER r, INTEGER s } – short-form lengths, no
//   leading zero bytes that are not needed, no negative numbers, nothing after it;
//   1 <= r, s < n;
// * the result: u1·G + u2·Q is not the point at infinity, and its x mod n == r.
//
// Errors: InvalidKey (bad public key), InvalidSignature (bad encoding or r, s out of
// range), Mismatch (not a signature of `msg` by this key).
//
// Public data only: the arithmetic (bignum.rs, Jacobian coordinates, Shamir's trick) is
// not constant time.  The cost is fixed by the curve (at most 384 doublings + additions).

use super::Error;
use super::bignum::{self, Modulus};
use super::hash::HashAlg;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
}

impl Curve {
    /// The one hash used with the curve.
    pub fn hash(self) -> HashAlg {
        match self {
            Curve::P256 => HashAlg::Sha256,
            Curve::P384 => HashAlg::Sha384,
        }
    }

    /// Length of a field element / scalar in bytes.
    pub fn field_len(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Curve::P256 => "P-256",
            Curve::P384 => "P-384",
        }
    }
}

struct Params {
    p: &'static str,
    n: &'static str,
    b: &'static str,
    gx: &'static str,
    gy: &'static str,
}

/// FIPS 186-5 / SP 800-186 domain parameters (a = -3 for both).
const P256: Params = Params {
    p: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    n: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    b: "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    gx: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    gy: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
};

const P384: Params = Params {
    p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    n: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    b: "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    gx: "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    gy: "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
};

/// A constant's hex into out[..len/2] (the constants above are well-formed).
fn unhex(s: &str, out: &mut [u8; 48]) -> usize {
    let v = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    };
    let b = s.as_bytes();
    for i in 0..b.len() / 2 {
        out[i] = (v(b[2 * i]) << 4) | v(b[2 * i + 1]);
    }
    b.len() / 2
}

/// Big-endian bytes minus 2 (for the Fermat inverse exponents p - 2 and n - 2).
fn minus_two(be: &[u8], out: &mut [u8; 48]) {
    out[..be.len()].copy_from_slice(be);
    let mut borrow = 2u16;
    for i in (0..be.len()).rev() {
        let v = out[i] as u16;
        if v >= borrow {
            out[i] = (v - borrow) as u8;
            break;
        }
        out[i] = (v + 256 - borrow) as u8;
        borrow = 1;
    }
}

/// Verifies a DER signature of `msg` (hashed with `curve.hash()`) by `public_key`.
pub fn verify(curve: Curve, public_key: &[u8], msg: &[u8], sig_der: &[u8]) -> Result<(), Error> {
    let h = curve.hash().digest(msg);
    match curve {
        Curve::P256 => verify_n::<4>(&P256, public_key, h.as_bytes(), sig_der),
        Curve::P384 => verify_n::<6>(&P384, public_key, h.as_bytes(), sig_der),
    }
}

/// Test only: the same with a ready digest (Python-made vectors on edge-case digests).
#[cfg(any(selftest, desocrypto_test))]
pub fn verify_digest(curve: Curve, public_key: &[u8], digest: &[u8], sig_der: &[u8]) -> Result<(), Error> {
    if digest.len() != curve.field_len() {
        return Err(Error::InvalidLength);
    }
    match curve {
        Curve::P256 => verify_n::<4>(&P256, public_key, digest, sig_der),
        Curve::P384 => verify_n::<6>(&P384, public_key, digest, sig_der),
    }
}

/// One DER INTEGER at the start of `b`: (value without the sign byte, rest).  Strict:
/// short-form length, at least one byte, not negative, no needless leading zero.
fn der_uint(b: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    if b.len() < 2 || b[0] != 0x02 || b[1] & 0x80 != 0 {
        return Err(Error::InvalidSignature);
    }
    let len = b[1] as usize;
    if len == 0 || b.len() < 2 + len {
        return Err(Error::InvalidSignature);
    }
    let v = &b[2..2 + len];
    if v[0] & 0x80 != 0 {
        return Err(Error::InvalidSignature);
    }
    if v[0] == 0 && len > 1 && v[1] & 0x80 == 0 {
        return Err(Error::InvalidSignature);
    }
    let v = if v[0] == 0 && len > 1 { &v[1..] } else { v };
    Ok((v, &b[2 + len..]))
}

/// DER ECDSA-Sig-Value -> (r, s) as big-endian bytes without leading zeros (except a lone 0).
fn parse_sig(sig: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    // The longest P-384 signature is 104 bytes: the length always has the short form.
    if sig.len() < 2 || sig[0] != 0x30 || sig[1] & 0x80 != 0 || sig[1] as usize != sig.len() - 2 {
        return Err(Error::InvalidSignature);
    }
    let (r, rest) = der_uint(&sig[2..])?;
    let (s, rest) = der_uint(rest)?;
    if !rest.is_empty() {
        return Err(Error::InvalidSignature);
    }
    Ok((r, s))
}

/// A point in Jacobian coordinates (x = X/Z², y = Y/Z³), Montgomery form; Z = 0 is infinity.
#[derive(Clone, Copy)]
struct Point<const N: usize> {
    x: [u64; N],
    y: [u64; N],
    z: [u64; N],
}

struct Field<const N: usize> {
    m: Modulus<N>,
}

impl<const N: usize> Field<N> {
    fn mul(&self, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        self.m.mul(a, b)
    }
    fn sqr(&self, a: &[u64; N]) -> [u64; N] {
        self.m.mul(a, a)
    }
    fn add(&self, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        self.m.add(a, b)
    }
    fn sub(&self, a: &[u64; N], b: &[u64; N]) -> [u64; N] {
        self.m.sub(a, b)
    }

    /// 2P (a = -3: dbl-2001-b).
    fn double(&self, p: &Point<N>) -> Point<N> {
        if bignum::is_zero(&p.z) || bignum::is_zero(&p.y) {
            return Point { x: [0; N], y: [0; N], z: [0; N] };
        }
        let delta = self.sqr(&p.z);
        let gamma = self.sqr(&p.y);
        let beta = self.mul(&p.x, &gamma);
        let t = self.mul(&self.sub(&p.x, &delta), &self.add(&p.x, &delta));
        let alpha = self.add(&self.add(&t, &t), &t);
        let beta2 = self.add(&beta, &beta);
        let beta4 = self.add(&beta2, &beta2);
        let beta8 = self.add(&beta4, &beta4);
        let x3 = self.sub(&self.sqr(&alpha), &beta8);
        let yz = self.add(&p.y, &p.z);
        let z3 = self.sub(&self.sub(&self.sqr(&yz), &gamma), &delta);
        let gg = self.sqr(&gamma);
        let gg2 = self.add(&gg, &gg);
        let gg4 = self.add(&gg2, &gg2);
        let gg8 = self.add(&gg4, &gg4);
        let y3 = self.sub(&self.mul(&alpha, &self.sub(&beta4, &x3)), &gg8);
        Point { x: x3, y: y3, z: z3 }
    }

    /// P + Q, all cases (infinity, P = Q, P = -Q).
    fn add_points(&self, p: &Point<N>, q: &Point<N>) -> Point<N> {
        if bignum::is_zero(&p.z) {
            return *q;
        }
        if bignum::is_zero(&q.z) {
            return *p;
        }
        let z1z1 = self.sqr(&p.z);
        let z2z2 = self.sqr(&q.z);
        let u1 = self.mul(&p.x, &z2z2);
        let u2 = self.mul(&q.x, &z1z1);
        let s1 = self.mul(&self.mul(&p.y, &q.z), &z2z2);
        let s2 = self.mul(&self.mul(&q.y, &p.z), &z1z1);
        let h = self.sub(&u2, &u1);
        let r = self.sub(&s2, &s1);
        if bignum::is_zero(&h) {
            if bignum::is_zero(&r) {
                return self.double(p);
            }
            return Point { x: [0; N], y: [0; N], z: [0; N] };
        }
        let hh = self.sqr(&h);
        let hhh = self.mul(&h, &hh);
        let v = self.mul(&u1, &hh);
        let x3 = self.sub(&self.sub(&self.sqr(&r), &hhh), &self.add(&v, &v));
        let y3 = self.sub(&self.mul(&r, &self.sub(&v, &x3)), &self.mul(&s1, &hhh));
        let z3 = self.mul(&self.mul(&p.z, &q.z), &h);
        Point { x: x3, y: y3, z: z3 }
    }
}

/// Checks a public key alone (uncompressed, coordinates < p, on the curve) – for a
/// certificate's key before it is ever used.
pub fn check_public_key(curve: Curve, public_key: &[u8]) -> Result<(), Error> {
    fn check<const N: usize>(c: &Params, public_key: &[u8]) -> Result<(), Error> {
        let mut buf = [0u8; 48];
        let len = unhex(c.p, &mut buf);
        let f = Field { m: Modulus::<N>::new(&buf[..len]).map_err(|_| Error::InvalidKey)? };
        key_point(c, &f, public_key).map(|_| ())
    }
    match curve {
        Curve::P256 => check::<4>(&P256, public_key),
        Curve::P384 => check::<6>(&P384, public_key),
    }
}

/// The public key as a point (x, y in Montgomery form), after every check.
fn key_point<const N: usize>(c: &Params, f: &Field<N>, public_key: &[u8]) -> Result<([u64; N], [u64; N]), Error> {
    let flen = 8 * N;
    if public_key.len() != 1 + 2 * flen || public_key[0] != 0x04 {
        return Err(Error::InvalidKey);
    }
    let qx = bignum::from_be::<N>(&public_key[1..1 + flen]).map_err(|_| Error::InvalidKey)?;
    let qy = bignum::from_be::<N>(&public_key[1 + flen..]).map_err(|_| Error::InvalidKey)?;
    if !f.m.is_reduced(&qx) || !f.m.is_reduced(&qy) {
        return Err(Error::InvalidKey);
    }
    let mut buf = [0u8; 48];
    let len = unhex(c.b, &mut buf);
    let b = f.m.to_mont(&bignum::from_be::<N>(&buf[..len]).map_err(|_| Error::InvalidKey)?);
    let xm = f.m.to_mont(&qx);
    let ym = f.m.to_mont(&qy);
    let x3 = f.mul(&f.sqr(&xm), &xm);
    let three_x = f.add(&f.add(&xm, &xm), &xm);
    let rhs = f.add(&f.sub(&x3, &three_x), &b);
    if f.sqr(&ym) != rhs {
        return Err(Error::InvalidKey);
    }
    Ok((xm, ym))
}

fn verify_n<const N: usize>(c: &Params, public_key: &[u8], digest: &[u8], sig_der: &[u8]) -> Result<(), Error> {
    let flen = 8 * N;
    let mut buf = [0u8; 48];
    let len = unhex(c.p, &mut buf);
    let fm = Modulus::<N>::new(&buf[..len]).map_err(|_| Error::InvalidKey)?;
    let mut p_minus_2 = [0u8; 48];
    minus_two(&buf[..len], &mut p_minus_2);
    let len = unhex(c.n, &mut buf);
    let nm = Modulus::<N>::new(&buf[..len]).map_err(|_| Error::InvalidKey)?;
    let mut n_minus_2 = [0u8; 48];
    minus_two(&buf[..len], &mut n_minus_2);
    let f = Field { m: fm };

    // The public key.
    let (xm, ym) = key_point(c, &f, public_key)?;

    // The signature.
    let (r_be, s_be) = parse_sig(sig_der)?;
    if r_be.len() > flen || s_be.len() > flen {
        return Err(Error::InvalidSignature);
    }
    let r = bignum::from_be::<N>(r_be).map_err(|_| Error::InvalidSignature)?;
    let s = bignum::from_be::<N>(s_be).map_err(|_| Error::InvalidSignature)?;
    if bignum::is_zero(&r) || bignum::is_zero(&s) || !nm.is_reduced(&r) || !nm.is_reduced(&s) {
        return Err(Error::InvalidSignature);
    }

    // e = the digest as an integer (same bit length as n for both curves), then mod n.
    if digest.len() != flen {
        return Err(Error::InvalidLength);
    }
    let e = bignum::from_be::<N>(digest).map_err(|_| Error::InvalidLength)?;
    let em = nm.to_mont(&e);
    let w = nm.pow_mont(&nm.to_mont(&s), &n_minus_2[..flen]);
    let u1 = nm.from_mont(&nm.mul(&em, &w));
    let u2 = nm.from_mont(&nm.mul(&nm.to_mont(&r), &w));

    // u1·G + u2·Q with one pass over the bits (Shamir's trick).
    let mut one = [0u64; N];
    one[0] = 1;
    let one_m = f.m.to_mont(&one);
    let len = unhex(c.gx, &mut buf);
    let gx = f.m.to_mont(&bignum::from_be::<N>(&buf[..len]).map_err(|_| Error::InvalidKey)?);
    let len = unhex(c.gy, &mut buf);
    let gy = f.m.to_mont(&bignum::from_be::<N>(&buf[..len]).map_err(|_| Error::InvalidKey)?);
    let g = Point { x: gx, y: gy, z: one_m };
    let q = Point { x: xm, y: ym, z: one_m };
    let gq = f.add_points(&g, &q);
    let mut acc = Point { x: [0; N], y: [0; N], z: [0; N] };
    let bits = bignum::bit_len(&u1).max(bignum::bit_len(&u2));
    for i in (0..bits).rev() {
        acc = f.double(&acc);
        let b1 = (u1[i / 64] >> (i % 64)) & 1;
        let b2 = (u2[i / 64] >> (i % 64)) & 1;
        match (b1, b2) {
            (1, 0) => acc = f.add_points(&acc, &g),
            (0, 1) => acc = f.add_points(&acc, &q),
            (1, 1) => acc = f.add_points(&acc, &gq),
            _ => {}
        }
    }
    if bignum::is_zero(&acc.z) {
        return Err(Error::Mismatch);
    }
    // Affine x = X / Z², then x mod n == r.
    let zinv = f.m.pow_mont(&acc.z, &p_minus_2[..flen]);
    let x = f.m.from_mont(&f.mul(&acc.x, &f.sqr(&zinv)));
    let xn = nm.reduce(&x);
    if xn == r { Ok(()) } else { Err(Error::Mismatch) }
}
