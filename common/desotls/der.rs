// Strict DER reading (X.690) – only what X.509 needs, nothing lenient.
//
//   let mut r = Reader::new(bytes)?;         // depth 0
//   let seq = r.read(SEQUENCE)?;            // one TLV with the expected tag
//   let mut inner = r.enter(&seq)?;         // its contents, one level deeper (limit MAX_DEPTH)
//   r.finish()?;                            // nothing may be left over
//
// Refused: a tag in the high-number form (low 5 bits = 31), the indefinite length (0x80),
// long-form lengths that are not minimal (0x81 for < 128, 0x82 for < 256, …) or longer than
// three bytes (16 MiB – far above any certificate), a length past the end of the data,
// nesting deeper than MAX_DEPTH, data left after the last element; BOOLEAN other than
// 00 / FF; INTEGER with a needless leading byte; BIT STRING with unused bits that are not
// zero.  Every error is Error::BadDer – the input never makes this code panic or read out of
// bounds (fuzzed on the host).

use super::Error;

pub const BOOLEAN: u8 = 0x01;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const UTF8_STRING: u8 = 0x0c;
pub const PRINTABLE_STRING: u8 = 0x13;
pub const IA5_STRING: u8 = 0x16;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;
pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
/// [n] EXPLICIT / constructed context tag.
pub const fn context(n: u8) -> u8 {
    0xa0 | n
}
/// [n] IMPLICIT primitive context tag.
pub const fn context_primitive(n: u8) -> u8 {
    0x80 | n
}

/// Deepest nesting accepted (plan limit C: 16).
pub const MAX_DEPTH: u8 = 16;

/// One element: its tag, its contents and its whole encoding (tag, length, contents).
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    pub raw: &'a [u8],
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    depth: u8,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0, depth: 0 }
    }

    /// The bytes not read yet.
    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.pos.min(self.data.len())..]
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// The tag of the next element, if any (does not move).
    pub fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// The next element, whatever its tag.
    pub fn any(&mut self) -> Result<Tlv<'a>, Error> {
        let start = self.pos;
        let d = self.data;
        let tag = *d.get(start).ok_or(Error::BadDer)?;
        if tag & 0x1f == 0x1f {
            return Err(Error::BadDer);
        }
        let first = *d.get(start + 1).ok_or(Error::BadDer)?;
        let (len, head) = if first < 0x80 {
            (first as usize, 2)
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 3 {
                return Err(Error::BadDer);
            }
            let bytes = d.get(start + 2..start + 2 + n).ok_or(Error::BadDer)?;
            if bytes[0] == 0 {
                return Err(Error::BadDer);
            }
            let mut len = 0usize;
            for &b in bytes {
                len = (len << 8) | b as usize;
            }
            if len < 0x80 {
                return Err(Error::BadDer);
            }
            (len, 2 + n)
        };
        let end = start.checked_add(head).and_then(|h| h.checked_add(len)).ok_or(Error::BadDer)?;
        if end > d.len() {
            return Err(Error::BadDer);
        }
        self.pos = end;
        Ok(Tlv { tag, value: &d[start + head..end], raw: &d[start..end] })
    }

    /// The next element, which must have `tag`.
    pub fn read(&mut self, tag: u8) -> Result<Tlv<'a>, Error> {
        let t = self.any()?;
        if t.tag != tag {
            return Err(Error::BadDer);
        }
        Ok(t)
    }

    /// The next element if it has `tag`, otherwise nothing (and no move).
    pub fn optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>, Error> {
        if self.peek_tag() == Some(tag) { self.read(tag).map(Some) } else { Ok(None) }
    }

    /// A reader over the contents of `t`, one level deeper.
    pub fn enter(&self, t: &Tlv<'a>) -> Result<Reader<'a>, Error> {
        if self.depth >= MAX_DEPTH {
            return Err(Error::BadDer);
        }
        Ok(Reader { data: t.value, pos: 0, depth: self.depth + 1 })
    }

    /// Reads a constructed element with `tag` and returns a reader over its contents.
    pub fn nested(&mut self, tag: u8) -> Result<Reader<'a>, Error> {
        let t = self.read(tag)?;
        self.enter(&t)
    }

    /// Nothing may be left.
    pub fn finish(&self) -> Result<(), Error> {
        if self.is_empty() { Ok(()) } else { Err(Error::BadDer) }
    }

    /// BOOLEAN: exactly one byte, 00 or FF.
    pub fn boolean(&mut self) -> Result<bool, Error> {
        let t = self.read(BOOLEAN)?;
        match t.value {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(Error::BadDer),
        }
    }

    /// INTEGER, minimal encoding; the contents (two's complement, may be negative).
    pub fn integer(&mut self) -> Result<&'a [u8], Error> {
        let t = self.read(INTEGER)?;
        integer_ok(t.value)?;
        Ok(t.value)
    }

    /// A non-negative INTEGER without the sign byte (a lone 0 stays [0]).
    pub fn unsigned(&mut self) -> Result<&'a [u8], Error> {
        let v = self.integer()?;
        if v[0] & 0x80 != 0 {
            return Err(Error::BadDer);
        }
        Ok(if v.len() > 1 && v[0] == 0 { &v[1..] } else { v })
    }

    /// A small non-negative INTEGER (fits in u32).
    pub fn small(&mut self) -> Result<u32, Error> {
        let v = self.unsigned()?;
        if v.len() > 4 {
            return Err(Error::BadDer);
        }
        Ok(v.iter().fold(0u32, |a, &b| (a << 8) | b as u32))
    }

    /// BIT STRING whose unused-bits count is 0 (keys, signatures); the bytes after it.
    pub fn bit_string_bytes(&mut self) -> Result<&'a [u8], Error> {
        let t = self.read(BIT_STRING)?;
        match t.value.split_first() {
            Some((0, rest)) => Ok(rest),
            _ => Err(Error::BadDer),
        }
    }

    /// NULL (empty contents).
    pub fn null(&mut self) -> Result<(), Error> {
        let t = self.read(NULL)?;
        if t.value.is_empty() { Ok(()) } else { Err(Error::BadDer) }
    }

    /// OBJECT IDENTIFIER contents, checked for a well-formed encoding.
    pub fn oid(&mut self) -> Result<&'a [u8], Error> {
        let t = self.read(OID)?;
        oid_ok(t.value)?;
        Ok(t.value)
    }
}

/// Minimal two's-complement INTEGER contents.
pub fn integer_ok(v: &[u8]) -> Result<(), Error> {
    match v {
        [] => Err(Error::BadDer),
        [0x00, b, ..] if b & 0x80 == 0 => Err(Error::BadDer),
        [0xff, b, ..] if b & 0x80 != 0 => Err(Error::BadDer),
        _ => Ok(()),
    }
}

/// OID contents: not empty, every arc minimal (no leading 0x80), the last byte ends an arc.
pub fn oid_ok(v: &[u8]) -> Result<(), Error> {
    if v.is_empty() || v[v.len() - 1] & 0x80 != 0 {
        return Err(Error::BadDer);
    }
    let mut start = true;
    for &b in v {
        if start && b == 0x80 {
            return Err(Error::BadDer);
        }
        start = b & 0x80 == 0;
    }
    Ok(())
}

/// Walks every element of `data` recursively (constructed tags), so a structure that is
/// only compared byte for byte (a Name) is still known to be well-formed DER.
pub fn check_tree(r: &mut Reader<'_>) -> Result<(), Error> {
    while !r.is_empty() {
        let t = r.any()?;
        if t.tag & 0x20 != 0 {
            let mut inner = r.enter(&t)?;
            check_tree(&mut inner)?;
        }
    }
    Ok(())
}

/// UTCTime ("YYMMDDHHMMSSZ") or GeneralizedTime ("YYYYMMDDHHMMSSZ") -> Unix seconds (RFC 5280
/// 4.1.2.5: always "Z", seconds always, no fractions; UTCTime years 50-99 are 19xx).
pub fn time(t: &Tlv<'_>) -> Result<i64, Error> {
    let s = t.value;
    let digits = |a: &[u8]| -> Result<i64, Error> {
        let mut v = 0i64;
        for &c in a {
            if !c.is_ascii_digit() {
                return Err(Error::BadDer);
            }
            v = v * 10 + (c - b'0') as i64;
        }
        Ok(v)
    };
    let (year, rest) = match (t.tag, s.len()) {
        (UTC_TIME, 13) => {
            let y = digits(&s[..2])?;
            (if y < 50 { 2000 + y } else { 1900 + y }, &s[2..])
        }
        (GENERALIZED_TIME, 15) => (digits(&s[..4])?, &s[4..]),
        _ => return Err(Error::BadDer),
    };
    if rest[10] != b'Z' {
        return Err(Error::BadDer);
    }
    let (mo, d, h, mi, se) = (digits(&rest[0..2])?, digits(&rest[2..4])?, digits(&rest[4..6])?, digits(&rest[6..8])?, digits(&rest[8..10])?);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let mdays = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&mo) || d < 1 || d > mdays[(mo - 1) as usize] || h > 23 || mi > 59 || se > 59 {
        return Err(Error::BadDer);
    }
    Ok(days_from_civil(year, mo, d) * 86400 + h * 3600 + mi * 60 + se)
}

/// Days since 1970-01-01 (H. Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}
