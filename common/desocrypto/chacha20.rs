// ChaCha20 (RFC 8439): a 256-bit key, a 96-bit nonce and a 32-bit block counter give
// a stream of 64-byte blocks; the cipher is the stream XOR the data.
//
// Only additions, rotations and XORs on 32-bit words – no tables, no branches on the
// key or the data, so the time does not depend on secrets.
//
// The caller must never use the same (key, nonce, counter) twice for different data:
// the stream would repeat.  The counter wraps after 2^32 blocks (256 GiB per nonce) –
// `xor_stream` refuses data that would need more.

use super::Error;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const BLOCK_LEN: usize = 64;

const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]; // "expand 32-byte k"

#[inline(always)]
fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn word(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]])
}

/// One 64-byte block of the stream (RFC 8439 section 2.3).
pub fn block(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN], out: &mut [u8; BLOCK_LEN]) {
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&SIGMA);
    for i in 0..8 {
        init[4 + i] = word(key, i);
    }
    init[12] = counter;
    for i in 0..3 {
        init[13 + i] = word(nonce, i);
    }
    let mut s = init;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    super::wipe_words(&mut s);
    super::wipe_words(&mut init);
}

/// `data` XOR the stream starting at block `counter` (encryption and decryption are
/// the same operation).  Err(LengthOverflow) when the data would need the counter
/// past 2^32 - 1 (the stream would repeat); `data` is then unchanged.
pub fn xor_stream(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN], data: &mut [u8]) -> Result<(), Error> {
    let blocks = (data.len() as u64).div_ceil(BLOCK_LEN as u64);
    if blocks > (1u64 << 32) - counter as u64 {
        return Err(Error::LengthOverflow);
    }
    let mut ks = [0u8; BLOCK_LEN];
    for (i, chunk) in data.chunks_mut(BLOCK_LEN).enumerate() {
        block(key, counter.wrapping_add(i as u32), nonce, &mut ks);
        for (d, k) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= k;
        }
    }
    super::wipe(&mut ks);
    Ok(())
}
