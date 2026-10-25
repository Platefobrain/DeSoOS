// DNS resolver pieces (RFC 1035) – pure code: names, the query, the answer
// parser, the cache.  No clock, no network, no allocation, no panics.  Answers
// come from the network, so they are untrusted: names are decoded with every
// length and pointer checked (only backward pointers, at most 16 jumps), the
// question must be ours, and only A records for the asked name – or for the
// target of a CNAME chain (at most 8 links) – are used.  Tests without a network:
// /bin/dnstest (NET TEST).
#![allow(dead_code)]

use crate::netproto::NetError;

pub const DNS_PORT: u16 = 53;
/// Longest name in text form (without a final dot).
pub const NAME_MAX: usize = 253;
/// Addresses kept per answer.
pub const ADDRS_MAX: usize = 4;
pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const CLASS_IN: u16 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
const CNAME_MAX: u8 = 8;
const JUMPS_MAX: u8 = 16;
/// Cached answers live at most this long, whatever the server says.
pub const TTL_MAX_S: u32 = 3600;
/// "No such name" / "no address" is remembered this long.
pub const NEGATIVE_TTL_S: u32 = 30;

/// A host name in text form, lower case, no final dot.
#[derive(Clone, Copy)]
pub struct Name {
    b: [u8; NAME_MAX],
    len: usize,
}

impl PartialEq for Name {
    fn eq(&self, o: &Name) -> bool {
        self.as_bytes() == o.as_bytes()
    }
}

impl core::fmt::Debug for Name {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}

impl core::fmt::Display for Name {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Name {
    pub const EMPTY: Name = Name { b: [0; NAME_MAX], len: 0 };

    /// A name typed by a user: labels of 1–63 letters, digits, '-' or '_',
    /// separated by dots, at most 253 characters; one final dot is allowed.
    /// Upper case is folded.  None for anything else (also for an empty name).
    pub fn parse(s: &str) -> Option<Name> {
        let s = s.strip_suffix('.').unwrap_or(s).as_bytes();
        if s.is_empty() || s.len() > NAME_MAX {
            return None;
        }
        let mut n = Name::EMPTY;
        let mut label = 0;
        for &c in s {
            match c {
                b'.' => {
                    if label == 0 {
                        return None;
                    }
                    label = 0;
                }
                b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => label += 1,
                b'A'..=b'Z' => label += 1,
                _ => return None,
            }
            if label > 63 {
                return None;
            }
            n.b[n.len] = c.to_ascii_lowercase();
            n.len += 1;
        }
        if label == 0 {
            return None;
        }
        // The last label (top-level domain) is never all digits – "10.0.2.300" is a
        // mistyped address, not a name.
        if n.as_bytes().rsplit(|&c| c == b'.').next().is_some_and(|l| l.iter().all(u8::is_ascii_digit)) {
            return None;
        }
        Some(n)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.b[..self.len]
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("?")
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// The query: header (id, recursion desired, one question) + name + type A,
/// class IN.  `buf` – at least 12 + 255 + 4 bytes; returns the length.
pub fn build_query(buf: &mut [u8], id: u16, name: &Name) -> usize {
    buf[..12].fill(0);
    buf[0..2].copy_from_slice(&id.to_be_bytes());
    buf[2] = 0x01; // RD
    buf[5] = 1; // QDCOUNT
    let mut i = 12;
    for label in name.as_bytes().split(|&c| c == b'.') {
        buf[i] = label.len() as u8;
        buf[i + 1..i + 1 + label.len()].copy_from_slice(label);
        i += 1 + label.len();
    }
    buf[i] = 0;
    i += 1;
    buf[i..i + 2].copy_from_slice(&TYPE_A.to_be_bytes());
    buf[i + 2..i + 4].copy_from_slice(&CLASS_IN.to_be_bytes());
    i + 4
}

fn be16(p: &[u8], at: usize) -> Result<u16, NetError> {
    if at + 2 > p.len() {
        return Err(NetError::Short);
    }
    Ok(u16::from_be_bytes([p[at], p[at + 1]]))
}

/// Decodes the name at `at` (labels and compression pointers) into text form.
/// Returns the name and the offset after it in the message.
pub fn read_name(p: &[u8], at: usize) -> Result<(Name, usize), NetError> {
    let mut n = Name::EMPTY;
    let mut i = at;
    let mut end = None;
    let mut jumps = 0;
    // A pointer must go strictly backwards from the start of the label sequence
    // it interrupts – no loops possible, and JUMPS_MAX limits the work anyway.
    let mut floor = at;
    loop {
        let Some(&l) = p.get(i) else { return Err(NetError::Short) };
        match l >> 6 {
            0 => {
                let l = l as usize;
                if l == 0 {
                    break;
                }
                if i + 1 + l > p.len() {
                    return Err(NetError::Short);
                }
                let extra = if n.len == 0 { l } else { l + 1 };
                if n.len + extra > NAME_MAX {
                    return Err(NetError::BadHeader);
                }
                if n.len > 0 {
                    n.b[n.len] = b'.';
                    n.len += 1;
                }
                for &c in &p[i + 1..i + 1 + l] {
                    // Printable, no dot inside a label (it would change the name).
                    if !(0x21..=0x7E).contains(&c) || c == b'.' {
                        return Err(NetError::BadHeader);
                    }
                    n.b[n.len] = c.to_ascii_lowercase();
                    n.len += 1;
                }
                i += 1 + l;
            }
            3 => {
                let Some(&lo) = p.get(i + 1) else { return Err(NetError::Short) };
                let target = ((l as usize & 0x3F) << 8) | lo as usize;
                if target >= floor || jumps == JUMPS_MAX {
                    return Err(NetError::BadHeader);
                }
                jumps += 1;
                if end.is_none() {
                    end = Some(i + 2);
                }
                floor = target;
                i = target;
            }
            _ => return Err(NetError::BadHeader),
        }
    }
    Ok((n, end.unwrap_or(i + 1)))
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Answer {
    /// Response code: 0 ok, 3 no such name, others server errors.
    pub rcode: u8,
    pub addrs: [[u8; 4]; ADDRS_MAX],
    pub n: usize,
    /// Smallest TTL of the records used (s).
    pub ttl: u32,
    /// The name the addresses belong to after CNAMEs (empty = no CNAME).
    pub cname: Name,
}

/// The transaction id of a response (to match it before parsing).
pub fn response_id(p: &[u8]) -> Option<u16> {
    be16(p, 0).ok()
}

/// Parses the answer to our query `id` for `name`.
pub fn parse_response(p: &[u8], id: u16, name: &Name) -> Result<Answer, NetError> {
    if p.len() < 12 {
        return Err(NetError::Short);
    }
    let flags = be16(p, 2)?;
    if be16(p, 0)? != id || flags & 0x8000 == 0 || (flags >> 11) & 0xF != 0 {
        return Err(NetError::Unsupported);
    }
    if flags & 0x0200 != 0 {
        return Err(NetError::Truncated);
    }
    let qd = be16(p, 4)?;
    let an = be16(p, 6)?;
    if qd != 1 {
        return Err(NetError::BadHeader);
    }
    let (q, mut i) = read_name(p, 12)?;
    if q != *name || be16(p, i)? != TYPE_A || be16(p, i + 2)? != CLASS_IN {
        return Err(NetError::BadHeader);
    }
    i += 4;
    let mut a = Answer { rcode: (flags & 0xF) as u8, addrs: [[0; 4]; ADDRS_MAX], n: 0, ttl: u32::MAX, cname: Name::EMPTY };
    if a.rcode != 0 {
        a.ttl = 0;
        return Ok(a);
    }
    let mut want = *name;
    let mut hops = 0;
    for _ in 0..an {
        let (owner, j) = read_name(p, i)?;
        let kind = be16(p, j)?;
        let class = be16(p, j + 2)?;
        let ttl = (be16(p, j + 4)? as u32) << 16 | be16(p, j + 6)? as u32;
        let rdlen = be16(p, j + 8)? as usize;
        let rd = j + 10;
        if rd + rdlen > p.len() {
            return Err(NetError::Short);
        }
        if class == CLASS_IN && owner == want {
            match kind {
                TYPE_A => {
                    if rdlen != 4 {
                        return Err(NetError::BadHeader);
                    }
                    if a.n < ADDRS_MAX {
                        a.addrs[a.n].copy_from_slice(&p[rd..rd + 4]);
                        a.n += 1;
                        a.ttl = a.ttl.min(ttl);
                    }
                }
                TYPE_CNAME => {
                    let (target, after) = read_name(p, rd)?;
                    if after > rd + rdlen || target.is_empty() {
                        return Err(NetError::BadHeader);
                    }
                    hops += 1;
                    if hops > CNAME_MAX {
                        return Err(NetError::BadHeader);
                    }
                    want = target;
                    a.cname = target;
                    a.ttl = a.ttl.min(ttl);
                }
                _ => {}
            }
        }
        i = rd + rdlen;
    }
    if a.ttl == u32::MAX {
        a.ttl = 0;
    }
    Ok(a)
}

// ------------------------------------------------------------
// Cache
// ------------------------------------------------------------

pub const CACHE: usize = 16;

#[derive(Clone, Copy)]
struct Entry {
    name: Name,
    addrs: [[u8; 4]; ADDRS_MAX],
    n: usize,
    rcode: u8,
    until_ms: u64,
}

/// Recent answers.  An answer with no address (no such name, no IPv4) is kept
/// NEGATIVE_TTL_S; TTL 0 is not kept; nothing longer than TTL_MAX_S.
pub struct Cache {
    e: [Entry; CACHE],
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Cached {
    pub addrs: [[u8; 4]; ADDRS_MAX],
    pub n: usize,
    pub rcode: u8,
}

impl Cache {
    pub const fn new() -> Cache {
        Cache { e: [Entry { name: Name::EMPTY, addrs: [[0; 4]; ADDRS_MAX], n: 0, rcode: 0, until_ms: 0 }; CACHE] }
    }

    pub fn get(&self, name: &Name, now: u64) -> Option<Cached> {
        self.e.iter().find(|e| e.name == *name && now < e.until_ms).map(|e| Cached { addrs: e.addrs, n: e.n, rcode: e.rcode })
    }

    pub fn put(&mut self, name: &Name, a: &Answer, now: u64) {
        let ttl = if a.n == 0 && (a.rcode == 0 || a.rcode == RCODE_NXDOMAIN) {
            NEGATIVE_TTL_S
        } else if a.rcode != 0 {
            0 // server errors are not remembered
        } else {
            a.ttl.min(TTL_MAX_S)
        };
        if ttl == 0 {
            return;
        }
        // Same name, else an expired slot, else the one expiring first.
        let k = self
            .e
            .iter()
            .position(|e| e.name == *name)
            .or_else(|| self.e.iter().position(|e| now >= e.until_ms))
            .unwrap_or_else(|| (0..CACHE).min_by_key(|&k| self.e[k].until_ms).unwrap_or(0));
        self.e[k] = Entry { name: *name, addrs: a.addrs, n: a.n, rcode: a.rcode, until_ms: now + ttl as u64 * 1000 };
    }

    pub fn len(&self, now: u64) -> usize {
        self.e.iter().filter(|e| now < e.until_ms && !e.name.is_empty()).count()
    }

    pub fn clear(&mut self) {
        *self = Cache::new();
    }
}
