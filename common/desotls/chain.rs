// A server's certificate chain kept after the handshake, for the second check of a bootstrap.
//
// The time service (/bin/timekeeper) talks NTS-KE while the clock is not plausible: the first
// check of the chain can only use a lower bound for "now" (verify::When::Bootstrap).  Once NTS
// has given a time T +- U, the same chain – the bytes that very server sent in that very
// handshake, not a result and not a certificate fetched again – is checked once more, fully,
// over [T - U, T + U] (verify::server_over).  The client copies the chain into a PeerChain
// while it handles the Certificate message (only when the configuration asks for a bootstrap),
// wipes the copy when the handshake fails, and hands it over with `Client::take_chain` after a
// successful one.
//
// Limits: at most verify::MAX_CHAIN certificates (the handshake refuses more anyway), at most
// MAX_BYTES bytes together – a bigger chain is refused for a bootstrap (real NTS servers send
// 2-5 KiB).

use super::verify;
use super::Error;

/// Bytes of all certificates together.
pub const MAX_BYTES: usize = 24 * 1024;
/// Certificates.
pub const MAX_CERTS: usize = verify::MAX_CHAIN;

pub struct PeerChain {
    buf: [u8; MAX_BYTES],
    /// End of each certificate in `buf`.
    ends: [usize; MAX_CERTS],
    n: usize,
}

impl PeerChain {
    pub const fn new() -> PeerChain {
        PeerChain { buf: [0; MAX_BYTES], ends: [0; MAX_CERTS], n: 0 }
    }

    /// Keeps a copy of `chain` (in the order the server sent it).  Too many or too big:
    /// nothing is kept.
    pub fn store(&mut self, chain: &[&[u8]]) -> Result<(), Error> {
        self.clear();
        if chain.is_empty() || chain.len() > MAX_CERTS {
            return Err(Error::ChainTooLong);
        }
        if chain.iter().map(|c| c.len()).sum::<usize>() > MAX_BYTES {
            return Err(Error::CertTooLarge);
        }
        let mut at = 0;
        for (i, c) in chain.iter().enumerate() {
            self.buf[at..at + c.len()].copy_from_slice(c);
            at += c.len();
            self.ends[i] = at;
        }
        self.n = chain.len();
        Ok(())
    }

    /// The certificates (chain[0] = the server's own) – `out[..n]`.
    pub fn certs<'a>(&'a self, out: &mut [&'a [u8]; MAX_CERTS]) -> usize {
        let mut start = 0;
        for i in 0..self.n {
            out[i] = &self.buf[start..self.ends[i]];
            start = self.ends[i];
        }
        self.n
    }

    pub fn count(&self) -> usize {
        self.n
    }

    pub fn bytes(&self) -> usize {
        if self.n == 0 { 0 } else { self.ends[self.n - 1] }
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Moves the chain into `to` (`to` gets exactly these bytes; this one is wiped).
    pub fn move_to(&mut self, to: &mut PeerChain) {
        to.clear();
        let len = self.bytes();
        to.buf[..len].copy_from_slice(&self.buf[..len]);
        to.ends = self.ends;
        to.n = self.n;
        self.clear();
    }

    /// Nothing kept: every byte zero.
    pub fn clear(&mut self) {
        super::crypto::wipe(&mut self.buf);
        self.ends = [0; MAX_CERTS];
        self.n = 0;
    }

    /// Every byte zero (tests).
    pub fn wiped(&self) -> bool {
        self.n == 0 && self.buf.iter().all(|&b| b == 0)
    }
}
