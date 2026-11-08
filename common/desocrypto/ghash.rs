// GHASH (NIST SP 800-38D 6.4): Y = (Y xor X) * H in GF(2^128) for every 16-byte block, with
// the field polynomial x^128 + x^7 + x^2 + x + 1 and GCM's bit order (bit 0 = the most
// significant bit of byte 0 = the coefficient of x^0).
//
// Two multiplications, the same results:
//   * PCLMULQDQ (CPUID leaf 1, ECX bit 1) – carry-less 64x64 products on the bit-reversed
//     values (then bit k = the coefficient of x^k), the 256-bit product reduced with
//     x^128 = x^7 + x^2 + x + 1 using shifts.  Not in `desocrypto_no_simd` builds (the kernel).
//   * software – the SP 800-38D algorithm 1 bit by bit: 128 steps, each a conditional XOR
//     done with a mask (no table, no branch on H or the data).
//
// H is the authentication key – as secret as the AES key.  The implementation avoids
// branches and table look-ups that depend on secrets; it has not been formally verified or
// audited for timing.  H and Y are wiped on drop.

use super::aes::Features;

const R: u128 = 0xe1 << 120;

/// X * Y in GCM's convention (values as big-endian 128-bit integers), software.
fn mul_soft(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    for i in 0..128 {
        let bit = (x >> (127 - i)) & 1;
        z ^= v & 0u128.wrapping_sub(bit);
        let lsb = v & 1;
        v = (v >> 1) ^ (R & 0u128.wrapping_sub(lsb));
    }
    z
}

pub struct Ghash {
    /// H as a big-endian integer (software) and bit-reversed (PCLMULQDQ).
    h: u128,
    h_rev: u128,
    /// Y – kept bit-reversed when PCLMULQDQ is used.
    y: u128,
    hw: bool,
    buf: [u8; 16],
    buf_len: usize,
}

impl Ghash {
    /// GHASH under `h` (16 bytes – AES_K(0^128) in GCM).
    pub fn new(h: &[u8; 16], features: Features) -> Ghash {
        let hv = u128::from_be_bytes(*h);
        let hw = cfg!(not(desocrypto_no_simd)) && features.pclmul && Features::detect().pclmul;
        Ghash { h: hv, h_rev: hv.reverse_bits(), y: 0, hw, buf: [0; 16], buf_len: 0 }
    }

    pub fn uses_pclmul(&self) -> bool {
        self.hw
    }

    fn block(&mut self, b: &[u8; 16]) {
        let x = u128::from_be_bytes(*b);
        #[cfg(not(desocrypto_no_simd))]
        if self.hw {
            // SAFETY: `hw` is true only when CPUID reported PCLMULQDQ.
            self.y = unsafe { hw::mul_rev(self.y ^ x.reverse_bits(), self.h_rev) };
            return;
        }
        self.y = mul_soft(self.y ^ x, self.h);
    }

    /// Adds data; a last partial block is padded with zeros only by `pad` / `finish`.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (16 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 16 {
                return;
            }
            let b = self.buf;
            self.block(&b);
            self.buf_len = 0;
        }
        while data.len() >= 16 {
            let mut b = [0u8; 16];
            b.copy_from_slice(&data[..16]);
            self.block(&b);
            data = &data[16..];
        }
        self.buf[..data.len()].copy_from_slice(data);
        self.buf_len = data.len();
    }

    /// Ends a field (aad or ciphertext) – a partial block is completed with zeros.
    pub fn pad(&mut self) {
        if self.buf_len > 0 {
            for b in self.buf[self.buf_len..].iter_mut() {
                *b = 0;
            }
            let b = self.buf;
            self.block(&b);
            self.buf_len = 0;
        }
    }

    /// The hash (after a final `pad`).
    pub fn finish(mut self) -> [u8; 16] {
        self.pad();
        let y = if self.hw { self.y.reverse_bits() } else { self.y };
        y.to_be_bytes()
    }
}

impl Drop for Ghash {
    fn drop(&mut self) {
        for v in [&mut self.h, &mut self.h_rev, &mut self.y] {
            // SAFETY: a valid &mut u128.
            unsafe { core::ptr::write_volatile(v, 0) };
        }
        super::wipe(&mut self.buf);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Test only: X * Y in GCM's convention with the chosen multiplication.
#[cfg(any(selftest, desocrypto_test))]
pub fn mul_for_test(x: &[u8; 16], y: &[u8; 16], features: Features) -> [u8; 16] {
    let (xv, yv) = (u128::from_be_bytes(*x), u128::from_be_bytes(*y));
    #[cfg(not(desocrypto_no_simd))]
    if features.pclmul && Features::detect().pclmul {
        // SAFETY: PCLMULQDQ checked just above.
        return unsafe { hw::mul_rev(xv.reverse_bits(), yv.reverse_bits()) }.reverse_bits().to_be_bytes();
    }
    let _ = features;
    mul_soft(xv, yv).to_be_bytes()
}

#[cfg(not(desocrypto_no_simd))]
mod hw {
    /// 64 x 64 -> 128 carry-less product with PCLMULQDQ (inline assembly – see aes.rs `hw`
    /// for why; xmm0 and xmm1 are cleared before the block ends).
    unsafe fn clmul(a: u64, b: u64) -> u128 {
        let mut out = [0u64; 2];
        // SAFETY: writes 16 bytes of `out`; PCLMULQDQ checked by the caller.
        unsafe {
            core::arch::asm!(
                "movq xmm0, {a}",
                "movq xmm1, {b}",
                "pclmulqdq xmm0, xmm1, 0",
                "movdqu [{o}], xmm0",
                "pxor xmm0, xmm0",
                "pxor xmm1, xmm1",
                a = in(reg) a,
                b = in(reg) b,
                o = in(reg) out.as_mut_ptr(),
                options(nostack, preserves_flags)
            );
        }
        let r = out[0] as u128 | ((out[1] as u128) << 64);
        super::super::wipe_words64(&mut out);
        r
    }

    /// a * b mod x^128 + x^7 + x^2 + x + 1, on values where bit k = the coefficient of x^k.
    pub unsafe fn mul_rev(a: u128, b: u128) -> u128 {
        let (a0, a1) = (a as u64, (a >> 64) as u64);
        let (b0, b1) = (b as u64, (b >> 64) as u64);
        // SAFETY: PCLMULQDQ checked by the caller.
        let (lo, hi, m1, m2) = unsafe { (clmul(a0, b0), clmul(a1, b1), clmul(a0, b1), clmul(a1, b0)) };
        let mid = m1 ^ m2;
        // The 256-bit product: low 128 bits L, high 128 bits T (coefficients x^128..x^255).
        let l = lo ^ (mid << 64);
        let t = hi ^ (mid >> 64);
        // T * x^128 = T * (x^7 + x^2 + x + 1): up to 135 bits – the part above 2^128 again.
        let over = (t >> 127) ^ (t >> 126) ^ (t >> 121);
        let folded = t ^ (t << 1) ^ (t << 2) ^ (t << 7);
        let again = over ^ (over << 1) ^ (over << 2) ^ (over << 7);
        l ^ folded ^ again
    }
}
