// A random number generator with fast key erasure (ChaCha20).
//
// The whole state is one 32-byte key – no buffer of ready bytes.  Every `fill`:
//   1. ChaCha20 with the current key, nonce 0, counter from 0 – enough blocks for
//      32 + len bytes;
//   2. the first 32 bytes become the new key AT ONCE (the old one is overwritten);
//   3. the rest is the output; the temporary block is wiped.
// Every key is used for exactly one `fill`, so no (key, counter) pair and no block of
// the stream is ever used twice, and no output byte is handed out twice.
//
// What a stolen state gives away: whoever reads the key knows every output up to the
// next `reseed` with fresh entropy – but nothing produced before (that key is gone).
// Hashing the old key alone would not help after a theft; only new, unknown input
// does.  Where the seed and the new input come from is the caller's business (the
// kernel's pool, or `getrandom` in a program).
//
// Wiping uses volatile writes; copies the compiler keeps in registers or spills on
// the stack are not covered (see mod.rs).

use super::chacha20::{self, BLOCK_LEN, KEY_LEN, NONCE_LEN};
use super::sha256::Sha256;

const NONCE: [u8; NONCE_LEN] = [0; NONCE_LEN];
/// Largest output of one key: 1 GiB – with the 32 bytes of the next key 2^24 + 1 blocks,
/// far below the counter's 2^32.
pub const MAX_PIECE: usize = 1 << 30;

pub struct KeyErasureRng {
    key: [u8; KEY_LEN],
}

impl KeyErasureRng {
    /// A generator from a 32-byte seed (it must be secret and unpredictable).
    pub fn new(seed: &[u8; KEY_LEN]) -> KeyErasureRng {
        KeyErasureRng { key: *seed }
    }

    /// Fills `out` with random bytes (any length).  The ChaCha20 block counter is 32
    /// bits, so one key covers at most 2^32 blocks; a longer request is cut into pieces
    /// of MAX_PIECE bytes, each one a separate call with its own key – no counter ever
    /// wraps.
    pub fn fill(&mut self, out: &mut [u8]) {
        self.fill_pieces(out, MAX_PIECE);
    }

    fn fill_pieces(&mut self, out: &mut [u8], piece: usize) {
        if out.is_empty() {
            self.fill_one(out);
            return;
        }
        for chunk in out.chunks_mut(piece) {
            self.fill_one(chunk);
        }
    }

    /// Test only: `fill` with a small piece size (to check the cutting without GiBs).
    #[cfg(any(selftest, desocrypto_test))]
    pub fn fill_with_piece(&mut self, out: &mut [u8], piece: usize) {
        self.fill_pieces(out, piece.max(1));
    }

    /// One call: blocks ceil((32 + len) / 64) <= 2^32 (len <= MAX_PIECE).
    fn fill_one(&mut self, out: &mut [u8]) {
        // The key of this call, on the stack only for its duration.
        let mut k = self.key;
        let mut blk = [0u8; BLOCK_LEN];
        chacha20::block(&k, 0, &NONCE, &mut blk);
        // The new key first: from here on the state no longer holds the old one.
        self.key.copy_from_slice(&blk[..KEY_LEN]);
        let first = (BLOCK_LEN - KEY_LEN).min(out.len());
        out[..first].copy_from_slice(&blk[KEY_LEN..KEY_LEN + first]);
        for (i, chunk) in out[first..].chunks_mut(BLOCK_LEN).enumerate() {
            chacha20::block(&k, 1 + i as u32, &NONCE, &mut blk);
            chunk.copy_from_slice(&blk[..chunk.len()]);
        }
        super::wipe(&mut blk);
        super::wipe(&mut k);
    }

    /// Mixes new input into the key: key = SHA-256(key ‖ input).  Restores security
    /// after a stolen state only when `input` holds entropy the thief does not know.
    pub fn reseed(&mut self, input: &[u8]) {
        let mut h = Sha256::new();
        h.update(&self.key);
        h.update(input);
        match h.finish() {
            Ok(k) => self.key = k,
            // Only more than 2^61 bytes could fail; the old key stays (never happens).
            Err(_) => {}
        }
    }

    /// Test only: the current key (to check that it changes and to play the thief).
    #[cfg(any(selftest, desocrypto_test))]
    pub fn key_for_test(&self) -> [u8; KEY_LEN] {
        self.key
    }
}

impl Drop for KeyErasureRng {
    fn drop(&mut self) {
        super::wipe(&mut self.key);
    }
}
