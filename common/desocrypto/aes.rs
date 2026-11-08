// AES-128 encryption (FIPS-197) – only the forward cipher: GCM (aes_gcm.rs) never decrypts
// a block.
//
// Two implementations, the same results:
//   * AES-NI (`aesenc` / `aesenclast`) – used when CPUID says the CPU has it (leaf 1, ECX
//     bit 25).  Compiled only into programs: the kernel gets `--cfg desocrypto_no_simd`
//     (its own code runs with CR0.TS = 1 and never saves XMM for itself, see
//     kernel/arch/x86_64/fpu.rs), so there the code below does not exist at all.
//   * bitsliced (like BearSSL's aes_ct64): four blocks at once in eight 64-bit planes –
//     plane i holds bit i of all 64 bytes; SubBytes is the Boyar-Peralta circuit (113
//     logic gates, no table), ShiftRows and MixColumns are fixed shifts and masks.
//     A last group of 1-3 blocks is copied into a local 4-block array (the rest zeros);
//     nothing outside the caller's slice is read or written.
//
// The key schedule (both paths) is computed with the same circuit – no table indexed by
// key bytes.  The implementation avoids branches and table look-ups that depend on
// secrets; it has not been formally verified or audited for timing.  Round keys (bytes
// and planes) are wiped on drop; copies in registers (also XMM) or on the stack are not
// covered.

pub const KEY_LEN: usize = 16;
pub const BLOCK: usize = 16;

/// CPU instructions the AES-GCM code may use.  `detect()` asks CPUID; `limit` can only
/// switch features OFF (tests: every combination on a CPU that has both) – a feature the
/// CPU lacks can never be turned on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Features {
    pub aes: bool,
    pub pclmul: bool,
}

impl Features {
    pub const NONE: Features = Features { aes: false, pclmul: false };

    /// What this CPU has (always NONE in a `desocrypto_no_simd` build – the kernel).
    pub fn detect() -> Features {
        #[cfg(not(desocrypto_no_simd))]
        {
            // CPUID leaf 1 exists on every x86_64 CPU.
            let ecx = core::arch::x86_64::__cpuid(1).ecx;
            Features { aes: ecx & (1 << 25) != 0, pclmul: ecx & (1 << 1) != 0 }
        }
        #[cfg(desocrypto_no_simd)]
        {
            Features::NONE
        }
    }

    /// The detected features, minus whatever `wanted` switches off.
    pub fn limit(wanted: Features) -> Features {
        let have = Features::detect();
        Features { aes: have.aes && wanted.aes, pclmul: have.pclmul && wanted.pclmul }
    }
}

// ------------------------------------------------------------
// The S-box circuit on bit planes
// ------------------------------------------------------------

/// SubBytes on 64 bytes at once: q[i] = bit i of every byte (Boyar & Peralta, "A depth-16
/// circuit for the AES S-box", 2011; the same gate list as BearSSL).
fn sbox(q: &mut [u64; 8]) {
    let (x0, x1, x2, x3, x4, x5, x6, x7) = (q[7], q[6], q[5], q[4], q[3], q[2], q[1], q[0]);
    // Top linear transformation.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;
    // Non-linear section.
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;
    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;
    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;
    // Bottom linear transformation.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;
    *q = [s7, s6, s5, s4, s3, s2, s1, s0];
}

/// Bytes -> planes (bit i of byte j -> bit j of plane i).
fn to_planes(bytes: &[u8; 64]) -> [u64; 8] {
    let mut q = [0u64; 8];
    for (j, &b) in bytes.iter().enumerate() {
        for (i, plane) in q.iter_mut().enumerate() {
            *plane |= (((b >> i) & 1) as u64) << j;
        }
    }
    q
}

fn from_planes(q: &[u64; 8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (j, byte) in out.iter_mut().enumerate() {
        let mut b = 0u8;
        for (i, plane) in q.iter().enumerate() {
            b |= (((plane >> j) & 1) as u8) << i;
        }
        *byte = b;
    }
    out
}

/// A 16-bit value in every 16-bit lane of a u64.
const fn lanes(v: u64) -> u64 {
    v * 0x0001_0001_0001_0001
}

/// ShiftRows on one plane: byte r + 4c of each block (bit r + 4c of its 16-bit lane) takes
/// byte r + 4((c + r) mod 4) – row r rotates right by 4r bits inside the lane.
fn shift_rows_plane(x: u64) -> u64 {
    let row = |r: u32| x & lanes(0x1111 << r);
    let rot = |v: u64, s: u32| if s == 0 { v } else { ((v >> s) & lanes((1u64 << (16 - s)) - 1)) | ((v << (16 - s)) & lanes(((1u64 << s) - 1) << (16 - s))) };
    row(0) | rot(row(1), 4) | rot(row(2), 8) | rot(row(3), 12)
}

/// Inside every column (4-bit nibble), row r takes row r + 1 (mod 4).
fn rot_col(x: u64) -> u64 {
    ((x >> 1) & 0x7777_7777_7777_7777) | ((x << 3) & 0x8888_8888_8888_8888)
}

/// Multiplication by 2 in GF(2^8) (x^8 = x^4 + x^3 + x + 1) on all 64 bytes.
fn xtime(a: &[u64; 8]) -> [u64; 8] {
    [a[7], a[0] ^ a[7], a[1], a[2] ^ a[7], a[3] ^ a[7], a[4], a[5], a[6]]
}

/// MixColumns: b_r = 2 a_r + 3 a_(r+1) + a_(r+2) + a_(r+3).
fn mix_columns(q: &mut [u64; 8]) {
    let mut r1 = [0u64; 8];
    let mut r2 = [0u64; 8];
    let mut r3 = [0u64; 8];
    let mut t = [0u64; 8];
    for i in 0..8 {
        r1[i] = rot_col(q[i]);
        r2[i] = rot_col(r1[i]);
        r3[i] = rot_col(r2[i]);
        t[i] = q[i] ^ r1[i];
    }
    let x = xtime(&t);
    for i in 0..8 {
        q[i] = x[i] ^ r1[i] ^ r2[i] ^ r3[i];
    }
}

/// S-box of four bytes (key schedule) through the circuit.
fn sub_word(w: [u8; 4]) -> [u8; 4] {
    let mut bytes = [0u8; 64];
    bytes[..4].copy_from_slice(&w);
    let mut q = to_planes(&bytes);
    sbox(&mut q);
    let out = from_planes(&q);
    super::wipe(&mut bytes);
    super::wipe_words64(&mut q);
    [out[0], out[1], out[2], out[3]]
}

/// FIPS-197 5.2: 11 round keys of 16 bytes.
fn expand_key(key: &[u8; KEY_LEN]) -> [[u8; 16]; 11] {
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    let mut w = [[0u8; 4]; 44];
    for i in 0..4 {
        w[i].copy_from_slice(&key[4 * i..4 * i + 4]);
    }
    for i in 4..44 {
        let mut t = w[i - 1];
        if i % 4 == 0 {
            // i is public: the branch depends on the position, not on the key.
            t = sub_word([t[1], t[2], t[3], t[0]]);
            t[0] ^= RCON[i / 4 - 1];
        }
        for k in 0..4 {
            w[i][k] = w[i - 4][k] ^ t[k];
        }
    }
    let mut rk = [[0u8; 16]; 11];
    for r in 0..11 {
        for c in 0..4 {
            rk[r][4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
        }
    }
    for x in w.iter_mut() {
        super::wipe(x);
    }
    rk
}

pub struct Aes128 {
    rk: [[u8; 16]; 11],
    /// The round keys as planes (each repeated for the four block positions).
    planes: [[u64; 8]; 11],
    hw: bool,
}

impl Aes128 {
    /// AES-NI when the CPU has it (and `features.aes`), otherwise bitsliced.
    pub fn new(key: &[u8; KEY_LEN], features: Features) -> Aes128 {
        let rk = expand_key(key);
        let mut planes = [[0u64; 8]; 11];
        for r in 0..11 {
            let mut rep = [0u8; 64];
            for j in 0..4 {
                rep[16 * j..16 * j + 16].copy_from_slice(&rk[r]);
            }
            planes[r] = to_planes(&rep);
            super::wipe(&mut rep);
        }
        // `features` comes from `Features::detect` / `limit`: AES-NI only on a CPU that has it.
        let hw = cfg!(not(desocrypto_no_simd)) && features.aes && Features::detect().aes;
        Aes128 { rk, planes, hw }
    }

    /// Whether this object uses AES-NI.
    pub fn uses_aesni(&self) -> bool {
        self.hw
    }

    /// Encrypts every block in place (ECB – only for counter blocks, never for data).
    pub fn encrypt_blocks(&self, blocks: &mut [[u8; BLOCK]]) {
        #[cfg(not(desocrypto_no_simd))]
        if self.hw {
            for b in blocks.iter_mut() {
                // SAFETY: `hw` is true only when CPUID reported AES-NI.
                unsafe { hw::encrypt(&self.rk, b) };
            }
            return;
        }
        for group in blocks.chunks_mut(4) {
            let mut bytes = [0u8; 64];
            for (j, b) in group.iter().enumerate() {
                bytes[16 * j..16 * j + 16].copy_from_slice(b);
            }
            let mut q = to_planes(&bytes);
            self.encrypt_planes(&mut q);
            let out = from_planes(&q);
            for (j, b) in group.iter_mut().enumerate() {
                b.copy_from_slice(&out[16 * j..16 * j + 16]);
            }
            super::wipe(&mut bytes);
            super::wipe_words64(&mut q);
        }
    }

    fn encrypt_planes(&self, q: &mut [u64; 8]) {
        for i in 0..8 {
            q[i] ^= self.planes[0][i];
        }
        for r in 1..11 {
            sbox(q);
            for p in q.iter_mut() {
                *p = shift_rows_plane(*p);
            }
            if r != 10 {
                mix_columns(q);
            }
            for i in 0..8 {
                q[i] ^= self.planes[r][i];
            }
        }
    }

    /// Test only: the round keys (FIPS-197 A.1).
    #[cfg(any(selftest, desocrypto_test))]
    pub fn round_keys_for_test(&self) -> [[u8; 16]; 11] {
        self.rk
    }
}

impl Drop for Aes128 {
    fn drop(&mut self) {
        for r in self.rk.iter_mut() {
            super::wipe(r);
        }
        for p in self.planes.iter_mut() {
            super::wipe_words64(p);
        }
    }
}

/// Test only: the circuit S-box of one byte (all 256 are compared with FIPS-197).
#[cfg(any(selftest, desocrypto_test))]
pub fn sbox_for_test(x: u8) -> u8 {
    sub_word([x, 0, 0, 0])[0]
}

#[cfg(not(desocrypto_no_simd))]
mod hw {
    /// One block with AES-NI.  Callers make sure the CPU has AES (CPUID).
    ///
    /// Inline assembly instead of `core::arch` intrinsics: programs are built for the
    /// soft-float target, where LLVM cannot handle 128-bit vector values in Rust code (the
    /// build stops with "Do not know how to split the result of this operator").  The
    /// compiler itself never keeps anything in XMM in this build, so the registers used
    /// here (xmm0, xmm1) hold nothing it relies on; both are cleared before the block ends
    /// (no round key or state left in them).
    pub unsafe fn encrypt(rk: &[[u8; 16]; 11], b: &mut [u8; 16]) {
        // SAFETY: reads 176 bytes of round keys and 16 bytes of `b`, writes 16 bytes of `b`;
        // AES-NI checked by the caller.
        unsafe {
            core::arch::asm!(
                "movdqu xmm0, [{b}]",
                "movdqu xmm1, [{k}]",
                "pxor xmm0, xmm1",
                "movdqu xmm1, [{k} + 16]", "aesenc xmm0, xmm1",
                "movdqu xmm1, [{k} + 32]", "aesenc xmm0, xmm1",
                "movdqu xmm1, [{k} + 48]", "aesenc xmm0, xmm1",
                "movdqu xmm1, [{k} + 64]", "aesenc xmm0, xmm1",
                "movdqu xmm1, [{k} + 80]", "aesenc xmm0, xmm1",
                "movdqu xmm1, [{k} + 96]", "aesenc xmm0, xmm1",
                "movdqu xmm1, [{k} + 112]", "aesenc xmm0, xmm1",
                "movdqu xmm1, [{k} + 128]", "aesenc xmm0, xmm1",
                "movdqu xmm1, [{k} + 144]", "aesenc xmm0, xmm1",
                "movdqu xmm1, [{k} + 160]", "aesenclast xmm0, xmm1",
                "movdqu [{b}], xmm0",
                "pxor xmm0, xmm0",
                "pxor xmm1, xmm1",
                b = in(reg) b.as_mut_ptr(),
                k = in(reg) rk.as_ptr(),
                options(nostack, preserves_flags)
            );
        }
    }
}
