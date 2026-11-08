// The hash functions behind one interface – for HMAC, HKDF and the signatures.
//
//   Digest            trait of Sha256 / Sha384 / Sha512 (block and output length, streaming)
//   HashAlg           which hash, chosen at run time (a signature's algorithm, a TLS suite)
//   HashAlg::digest   one slice -> Output (up to 64 bytes, `as_bytes()` the real length)
//   Hasher            streaming with a HashAlg chosen at run time
//
// SHA-1 and SHA-224 are not here on purpose: nothing in DeSoOS may use them.

use super::Error;
use super::sha256::{self, Sha256};
use super::sha512::{self, Sha384, Sha512};

/// The largest block (SHA-384/512) and output (SHA-512) of the hashes here.
pub const MAX_BLOCK: usize = 128;
pub const MAX_OUT: usize = 64;

pub trait Digest: Clone {
    const BLOCK_LEN: usize;
    const OUT_LEN: usize;
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    /// The digest into out[..OUT_LEN] (the rest of `out` untouched).
    fn finish_into(self, out: &mut [u8; MAX_OUT]) -> Result<(), Error>;
}

impl Digest for Sha256 {
    const BLOCK_LEN: usize = sha256::BLOCK_LEN;
    const OUT_LEN: usize = sha256::OUT_LEN;
    fn new() -> Self {
        Sha256::new()
    }
    fn update(&mut self, data: &[u8]) {
        Sha256::update(self, data);
    }
    fn finish_into(self, out: &mut [u8; MAX_OUT]) -> Result<(), Error> {
        let mut d = self.finish()?;
        out[..sha256::OUT_LEN].copy_from_slice(&d);
        super::wipe(&mut d);
        Ok(())
    }
}

impl Digest for Sha384 {
    const BLOCK_LEN: usize = sha512::BLOCK_LEN;
    const OUT_LEN: usize = sha512::OUT_LEN_384;
    fn new() -> Self {
        Sha384::new()
    }
    fn update(&mut self, data: &[u8]) {
        Sha384::update(self, data);
    }
    fn finish_into(self, out: &mut [u8; MAX_OUT]) -> Result<(), Error> {
        let mut d = self.finish()?;
        out[..sha512::OUT_LEN_384].copy_from_slice(&d);
        super::wipe(&mut d);
        Ok(())
    }
}

impl Digest for Sha512 {
    const BLOCK_LEN: usize = sha512::BLOCK_LEN;
    const OUT_LEN: usize = sha512::OUT_LEN;
    fn new() -> Self {
        Sha512::new()
    }
    fn update(&mut self, data: &[u8]) {
        Sha512::update(self, data);
    }
    fn finish_into(self, out: &mut [u8; MAX_OUT]) -> Result<(), Error> {
        let mut d = self.finish()?;
        out.copy_from_slice(&d);
        super::wipe(&mut d);
        Ok(())
    }
}

/// A digest of up to 64 bytes and its real length.  Wiped when dropped (an HMAC tag or an
/// HKDF PRK is secret).
#[derive(Clone)]
pub struct Output {
    bytes: [u8; MAX_OUT],
    len: usize,
}

impl Output {
    pub(super) fn from_parts(bytes: [u8; MAX_OUT], len: usize) -> Output {
        Output { bytes, len }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        super::wipe(&mut self.bytes);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub fn out_len(self) -> usize {
        match self {
            HashAlg::Sha256 => sha256::OUT_LEN,
            HashAlg::Sha384 => sha512::OUT_LEN_384,
            HashAlg::Sha512 => sha512::OUT_LEN,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            HashAlg::Sha256 => "SHA-256",
            HashAlg::Sha384 => "SHA-384",
            HashAlg::Sha512 => "SHA-512",
        }
    }

    /// The digest of one slice (cannot fail – a slice is below every length limit).
    pub fn digest(self, data: &[u8]) -> Output {
        let mut h = Hasher::new(self);
        h.update(data);
        h.finish().unwrap_or(Output { bytes: [0; MAX_OUT], len: self.out_len() })
    }
}

/// Streaming hash with the algorithm chosen at run time.
#[derive(Clone)]
pub enum Hasher {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    pub fn new(alg: HashAlg) -> Hasher {
        match alg {
            HashAlg::Sha256 => Hasher::Sha256(Sha256::new()),
            HashAlg::Sha384 => Hasher::Sha384(Sha384::new()),
            HashAlg::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }

    pub fn alg(&self) -> HashAlg {
        match self {
            Hasher::Sha256(_) => HashAlg::Sha256,
            Hasher::Sha384(_) => HashAlg::Sha384,
            Hasher::Sha512(_) => HashAlg::Sha512,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha384(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
        }
    }

    pub fn finish(self) -> Result<Output, Error> {
        let len = self.alg().out_len();
        let mut bytes = [0u8; MAX_OUT];
        match self {
            Hasher::Sha256(h) => h.finish_into(&mut bytes)?,
            Hasher::Sha384(h) => h.finish_into(&mut bytes)?,
            Hasher::Sha512(h) => h.finish_into(&mut bytes)?,
        }
        Ok(Output { bytes, len })
    }
}
