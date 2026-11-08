// PEM (RFC 7468) to DER – for `certcheck` and the tests; TLS itself gets DER.
//
//   let n = pem::certificates(text, &mut out, &mut spans)?;   // spans[i] = (start, len) in out
//
// Only "-----BEGIN CERTIFICATE-----" … "-----END CERTIFICATE-----" blocks are taken; text
// between blocks is skipped.  Inside a block: base64 with line breaks (CR, LF, spaces and
// tabs are skipped), '=' padding only at the very end, no other character – anything else
// is Error::BadDer.  A block without its END line is an error too.

use super::Error;

const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
const END: &[u8] = b"-----END CERTIFICATE-----";

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if hay.len() < needle.len() {
        return None;
    }
    (from..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

fn sextet(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    } as u32)
}

/// Base64 (standard alphabet, padded) into `out`; the number of bytes.
pub fn base64(text: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut acc = 0u32;
    let mut bits = 0;
    let mut n = 0;
    let mut pad = 0;
    let mut chars = 0usize;
    for &c in text {
        if matches!(c, b'\r' | b'\n' | b' ' | b'\t') {
            continue;
        }
        chars += 1;
        if c == b'=' {
            pad += 1;
            if pad > 2 {
                return Err(Error::BadDer);
            }
            continue;
        }
        if pad > 0 {
            return Err(Error::BadDer);
        }
        let v = sextet(c).ok_or(Error::BadDer)?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(n).ok_or(Error::CertTooLarge)? = (acc >> bits) as u8;
            n += 1;
        }
    }
    // Whole groups of four, and the bits left over by padding must be zero.
    if chars % 4 != 0 || (pad == 1 && bits != 2) || (pad == 2 && bits != 4) || (pad == 0 && bits != 0) || acc & ((1 << bits) - 1) != 0 {
        return Err(Error::BadDer);
    }
    Ok(n)
}

/// Every certificate block of `text`, decoded one after another into `out`; their positions
/// in `spans`.  The number of certificates (Error::ChainTooLong past spans.len()).
pub fn certificates(text: &[u8], out: &mut [u8], spans: &mut [(usize, usize)]) -> Result<usize, Error> {
    let mut pos = 0;
    let mut used = 0;
    let mut count = 0;
    while let Some(b) = find(text, BEGIN, pos) {
        let body = b + BEGIN.len();
        let e = find(text, END, body).ok_or(Error::BadDer)?;
        if count == spans.len() {
            return Err(Error::ChainTooLong);
        }
        let n = base64(&text[body..e], &mut out[used..])?;
        spans[count] = (used, n);
        used += n;
        count += 1;
        pos = e + END.len();
    }
    Ok(count)
}
