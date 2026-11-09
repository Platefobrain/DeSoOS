// The TLS 1.3 record layer (RFC 8446 §5): record headers, record protection with the two
// AEADs, the per-record nonce, TLSInnerPlaintext (content type and zero padding).
//
//   record = type (1) ‖ legacy_version 0x0303 (2) ‖ length (2) ‖ fragment
//   protected: type = application_data (23), fragment = AEAD(plaintext ‖ real type ‖ zeros)
//   nonce = iv XOR (64-bit record number, big-endian, left-padded to 12 bytes)
//   additional data = the 5-byte record header
//
// Each direction has its own key, iv and record number; the number starts at 0 for each new
// key and never wraps (at 2^64 − 1 the connection must end – far beyond any real one).
// Limits: a protected fragment at most 2^14 + 256 bytes, a plaintext at most 2^14 bytes.

use super::crypto::aead;
use super::crypto::aes_gcm::AesGcm;
use super::crypto::wipe;
use super::schedule::{expand_label, Secret};

pub const HEADER_LEN: usize = 5;
pub const TAG_LEN: usize = 16;
/// The most plaintext in one record.
pub const MAX_PLAINTEXT: usize = 1 << 14;
/// The most bytes after the header of a protected record.
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;
/// The most bytes after the header of an unprotected record (ServerHello, alerts before it).
pub const MAX_PLAIN_RECORD: usize = MAX_PLAINTEXT;
/// Room for the largest record we accept, header included.
pub const MAX_RECORD: usize = HEADER_LEN + MAX_CIPHERTEXT;

pub const CHANGE_CIPHER_SPEC: u8 = 20;
pub const ALERT: u8 = 21;
pub const HANDSHAKE: u8 = 22;
pub const APPLICATION_DATA: u8 = 23;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite {
    /// TLS_AES_128_GCM_SHA256 (0x1301).
    Aes128Gcm,
    /// TLS_CHACHA20_POLY1305_SHA256 (0x1303).
    Chacha20Poly1305,
}

impl Suite {
    pub fn code(self) -> u16 {
        match self {
            Suite::Aes128Gcm => 0x1301,
            Suite::Chacha20Poly1305 => 0x1303,
        }
    }

    pub fn from_code(c: u16) -> Option<Suite> {
        match c {
            0x1301 => Some(Suite::Aes128Gcm),
            0x1303 => Some(Suite::Chacha20Poly1305),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Suite::Aes128Gcm => "TLS_AES_128_GCM_SHA256",
            Suite::Chacha20Poly1305 => "TLS_CHACHA20_POLY1305_SHA256",
        }
    }

    fn key_len(self) -> usize {
        match self {
            Suite::Aes128Gcm => 16,
            Suite::Chacha20Poly1305 => 32,
        }
    }
}

enum Cipher {
    Aes(AesGcm),
    Chacha([u8; 32]),
}

impl Drop for Cipher {
    fn drop(&mut self) {
        if let Cipher::Chacha(k) = self {
            wipe(k);
        }
        // AesGcm wipes its round keys and GHASH key itself.
    }
}

/// Why a record was refused (the caller turns it into an alert).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The tag did not match (bad_record_mac).
    BadMac,
    /// A protected record outside the length limits (record_overflow).
    Overflow,
    /// Only zeros inside – no content type (unexpected_message).
    NoContentType,
    /// The record number would wrap.
    SequenceExhausted,
}

/// One direction's record protection.
pub struct Protection {
    cipher: Cipher,
    iv: [u8; 12],
    seq: u64,
}

impl Drop for Protection {
    fn drop(&mut self) {
        wipe(&mut self.iv);
    }
}

impl Protection {
    /// The key and iv of a traffic secret; record number 0.
    pub fn new(suite: Suite, secret: &Secret) -> Protection {
        let mut key = [0u8; 32];
        let kl = suite.key_len();
        expand_label(&secret.0, b"key", b"", &mut key[..kl]);
        let mut iv = [0u8; 12];
        expand_label(&secret.0, b"iv", b"", &mut iv);
        let cipher = match suite {
            Suite::Aes128Gcm => {
                let mut k = [0u8; 16];
                k.copy_from_slice(&key[..16]);
                let c = Cipher::Aes(AesGcm::new(&k));
                wipe(&mut k);
                c
            }
            Suite::Chacha20Poly1305 => Cipher::Chacha(key),
        };
        wipe(&mut key);
        Protection { cipher, iv, seq: 0 }
    }

    /// The record number of the next record.
    pub fn sequence(&self) -> u64 {
        self.seq
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let s = self.seq.to_be_bytes();
        for i in 0..8 {
            n[4 + i] ^= s[i];
        }
        n
    }

    /// Protects one record in place.  `buf[HEADER_LEN..HEADER_LEN + len]` holds the
    /// plaintext (at most MAX_PLAINTEXT); `buf` must have room for the type byte and the
    /// tag.  Writes the header and returns the whole record's length.
    pub fn seal(&mut self, content_type: u8, len: usize, buf: &mut [u8]) -> Result<usize, RecordError> {
        if len > MAX_PLAINTEXT || buf.len() < HEADER_LEN + len + 1 + TAG_LEN {
            return Err(RecordError::Overflow);
        }
        if self.seq == u64::MAX {
            return Err(RecordError::SequenceExhausted);
        }
        buf[HEADER_LEN + len] = content_type;
        let body = len + 1 + TAG_LEN;
        buf[0] = APPLICATION_DATA;
        buf[1] = 0x03;
        buf[2] = 0x03;
        buf[3..5].copy_from_slice(&(body as u16).to_be_bytes());
        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&buf[..HEADER_LEN]);
        let nonce = self.nonce();
        let text = &mut buf[HEADER_LEN..HEADER_LEN + len + 1];
        let tag = match &self.cipher {
            Cipher::Aes(c) => c.seal(&nonce, &header, text),
            Cipher::Chacha(k) => aead::seal(k, &nonce, &header, text),
        }
        .map_err(|_| RecordError::Overflow)?;
        buf[HEADER_LEN + len + 1..HEADER_LEN + body].copy_from_slice(&tag);
        self.seq += 1;
        Ok(HEADER_LEN + body)
    }

    /// Removes the protection of one whole record (header included) in place.  Returns the
    /// real content type and the plaintext's range in `rec`.  The record number moves on
    /// only for a record that verified.
    pub fn open(&mut self, rec: &mut [u8]) -> Result<(u8, usize, usize), RecordError> {
        if rec.len() < HEADER_LEN + 1 + TAG_LEN || rec.len() > MAX_RECORD {
            return Err(RecordError::Overflow);
        }
        if self.seq == u64::MAX {
            return Err(RecordError::SequenceExhausted);
        }
        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&rec[..HEADER_LEN]);
        let end = rec.len() - TAG_LEN;
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&rec[end..]);
        let nonce = self.nonce();
        let text = &mut rec[HEADER_LEN..end];
        match &self.cipher {
            Cipher::Aes(c) => c.open(&nonce, &header, text, &tag),
            Cipher::Chacha(k) => aead::open(k, &nonce, &header, text, &tag),
        }
        .map_err(|_| RecordError::BadMac)?;
        self.seq += 1;
        // TLSInnerPlaintext: content ‖ type ‖ zeros – the type is the last byte not zero.
        let mut i = end;
        while i > HEADER_LEN && rec[i - 1] == 0 {
            i -= 1;
        }
        if i == HEADER_LEN {
            return Err(RecordError::NoContentType);
        }
        let len = i - 1 - HEADER_LEN;
        if len > MAX_PLAINTEXT {
            return Err(RecordError::Overflow);
        }
        Ok((rec[i - 1], HEADER_LEN, len))
    }
}
