// Trust anchors: the CA store file and anything else that can supply anchors to verify.rs.
//
// The store (/etc/certs/roots, built by user/etc/certs/gen-roots.py from Mozilla's root
// store – only the CAs trusted for server certificates):
//
//   "DSCR" u16 version (1) u16 number of anchors
//   u8 len + NSS tag (ASCII), 32 bytes SHA-256 of the certdata.txt it came from
//   per anchor: i64 distrust-after (Unix seconds, 0 = none), u16 len + certificate (DER)
//
// numbers big-endian.  `Roots::parse` walks the whole file once: a wrong magic, version,
// count or length – or bytes after the last anchor – is BadRootStore (a damaged store means
// no trust at all, never a partial one).  An anchor whose certificate cannot be parsed or
// uses an unsupported key (one P-256/P-384/RSA rule broken, a P-521 root) is simply never
// matched – it cannot make a chain valid.

use super::Error;

/// Something that lists trust anchors: (certificate DER, distrust-after or 0).
pub trait Anchors {
    /// Calls `f` for each anchor until it returns false.
    fn each(&self, f: &mut dyn FnMut(&[u8], i64) -> bool);
}

/// A plain list of anchors without distrust dates (tests, `certcheck --anchor`).
pub struct AnchorList<'a>(pub &'a [&'a [u8]]);

impl Anchors for AnchorList<'_> {
    fn each(&self, f: &mut dyn FnMut(&[u8], i64) -> bool) {
        for der in self.0 {
            if !f(der, 0) {
                return;
            }
        }
    }
}

/// A list with distrust dates.
pub struct DatedAnchors<'a>(pub &'a [(&'a [u8], i64)]);

impl Anchors for DatedAnchors<'_> {
    fn each(&self, f: &mut dyn FnMut(&[u8], i64) -> bool) {
        for (der, when) in self.0 {
            if !f(der, *when) {
                return;
            }
        }
    }
}

pub struct Roots<'a> {
    count: usize,
    /// The anchor records (after the header).
    body: &'a [u8],
    pub nss_tag: &'a str,
    pub certdata_sha256: &'a [u8],
}

fn be16(b: &[u8]) -> usize {
    (b[0] as usize) << 8 | b[1] as usize
}

impl<'a> Roots<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Roots<'a>, Error> {
        let bad = Error::BadRootStore;
        if data.len() < 9 || &data[..4] != b"DSCR" || be16(&data[4..6]) != 1 {
            return Err(bad);
        }
        let count = be16(&data[6..8]);
        let tag_len = data[8] as usize;
        let head = 9 + tag_len + 32;
        if count == 0 || data.len() < head {
            return Err(bad);
        }
        let nss_tag = core::str::from_utf8(&data[9..9 + tag_len]).map_err(|_| bad)?;
        let body = &data[head..];
        let mut pos = 0;
        for _ in 0..count {
            let rec = body.get(pos..pos + 10).ok_or(bad)?;
            let len = be16(&rec[8..10]);
            if len == 0 || len > super::verify::MAX_CERT_LEN {
                return Err(bad);
            }
            pos = pos.checked_add(10 + len).filter(|&p| p <= body.len()).ok_or(bad)?;
        }
        if pos != body.len() {
            return Err(bad);
        }
        Ok(Roots { count, body, nss_tag, certdata_sha256: &data[9 + tag_len..head] })
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Anchors for Roots<'_> {
    fn each(&self, f: &mut dyn FnMut(&[u8], i64) -> bool) {
        let mut pos = 0;
        for _ in 0..self.count {
            // `parse` checked every record.
            let mut when = [0u8; 8];
            when.copy_from_slice(&self.body[pos..pos + 8]);
            let len = be16(&self.body[pos + 8..pos + 10]);
            let der = &self.body[pos + 10..pos + 10 + len];
            pos += 10 + len;
            if !f(der, i64::from_be_bytes(when)) {
                return;
            }
        }
    }
}
