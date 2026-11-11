// HTTP/1.1 answers (RFC 9110, RFC 9112) – the parser of `netget`, without I/O and without a
// heap: bytes go in as they come from the transport (`Parser::feed`, any split), the head,
// the body and the trailers come out through a `Sink`, then `Parser::finish` says how the
// connection's end relates to the answer.  The same input gives the same result whatever
// the pieces are – `/bin/httptest` checks every split.
//
// Strict on purpose (an answer comes from anyone on the network):
//   - status line "HTTP/1.x NNN ...", header names are tokens, values without control
//     characters, no folded lines, at most HEAD_MAX bytes of head;
//   - 1xx answers (except 101) are skipped, at most MAX_INTERIM; 101 is refused (we never ask
//     for an upgrade); 1xx and 204 with Content-Length or Transfer-Encoding are refused;
//   - 204 and 304 end with their head; in 304 Content-Length, Transfer-Encoding and
//     Content-Encoding describe the 200 that was not sent – only their syntax is checked;
//   - Transfer-Encoding: exactly "chunked", in one field, and not in an HTTP/1.0 answer;
//     together with Content-Length – refused (RFC 9112 §6.3: a sign of request smuggling);
//   - Content-Length once, decimal; Content-Encoding other than identity in an answer with
//     content – refused (netget asks with "Accept-Encoding: identity" and decodes nothing);
//   - chunked: 1-16 hex digits, extensions skipped but their syntax checked, CRLF exactly,
//     trailers kept apart from the head (never merged, never framing) – fields needed before
//     the content and fields named by Connection are refused there;
//   - Connection: a list of tokens (several fields add up), at most MAX_CONN_NAMES, and none
//     of them an end-to-end field the answer depends on;
//   - any byte after the end of the answer is an error (one request per connection).

pub const HEAD_MAX: usize = 8192;
/// The longest chunk-size line and the whole trailer section.
pub const LINE_MAX: usize = 4096;
pub const TRAILER_MAX: usize = 8192;
pub const MAX_INTERIM: u32 = 4;
pub const MAX_CONN_NAMES: usize = 32;
const NAME_MAX: usize = 64;

/// How the answer's body is delimited.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Framing {
    /// No body (204, 304).
    Nothing,
    Length(u64),
    Chunked,
    /// Until the connection ends (no length, no chunked).
    Close,
}

/// The final answer's head.
#[derive(Clone, Copy, Debug)]
pub struct Head {
    pub status: u32,
    #[allow(dead_code)]
    pub framing: Framing,
}

/// Where the parser's output goes.  `body` may fail (a file write) – the parser stops.
pub trait Sink {
    /// A head (also skipped 1xx ones: `interim`), without its final empty line.
    fn head(&mut self, raw: &[u8], interim: bool);
    fn body(&mut self, data: &[u8]) -> Result<(), ()>;
    /// The trailer section of a chunked body (without its final empty line; may be empty).
    fn trailers(&mut self, raw: &[u8]);
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The answer breaks the rules – the message says which one.
    Malformed(&'static str),
    /// The sink refused data.
    Sink,
}

/// How the connection ended (for `finish`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum End {
    /// The peer's FIN (http) or close_notify (https).
    Clean,
    /// https without close_notify, a reset, or the wait after the answer ran out.
    Unclean,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Not even a head.
    NoAnswer,
    /// The answer is incomplete.
    Cut,
    Complete,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Head,
    Length(u64),
    Close,
    /// Collecting a chunk-size line in `line`.
    Size,
    Data(u64),
    DataCr,
    DataLf,
    /// Collecting the trailer section in `line`.
    Trailers,
    Done,
}

pub struct Parser {
    state: State,
    head: [u8; HEAD_MAX],
    hlen: usize,
    interim: u32,
    pub answer: Option<Head>,
    /// 205: content not allowed.
    no_content: bool,
    line: [u8; TRAILER_MAX],
    llen: usize,
    pub body: u64,
    conn: [[u8; NAME_MAX]; MAX_CONN_NAMES],
    conn_len: [u8; MAX_CONN_NAMES],
    conn_n: usize,
}

fn bad(why: &'static str) -> Error {
    Error::Malformed(why)
}

fn tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

fn is_token(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|&c| tchar(c))
}

fn ows(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [f, rest @ ..] = s {
        if ows(*f) { s = rest } else { break }
    }
    while let [rest @ .., l] = s {
        if ows(*l) { s = rest } else { break }
    }
    s
}

fn eq_ci(a: &[u8], b: &str) -> bool {
    a.eq_ignore_ascii_case(b.as_bytes())
}

/// A field value: HTAB, SP, VCHAR, obs-text (no other control characters).
fn value_ok(v: &[u8]) -> bool {
    v.iter().all(|&c| c == b'\t' || (b' '..=b'~').contains(&c) || c >= 0x80)
}

/// A quoted-string at the start of `s` (RFC 9110 §5.6.4); the bytes it took.
fn quoted(s: &[u8]) -> Option<usize> {
    if s.first() != Some(&b'"') {
        return None;
    }
    let mut i = 1;
    while i < s.len() {
        match s[i] {
            b'"' => return Some(i + 1),
            b'\\' => {
                let c = *s.get(i + 1)?;
                if !(c == b'\t' || (b' '..=b'~').contains(&c) || c >= 0x80) {
                    return None;
                }
                i += 2;
            }
            c if c == b'\t' || c == b' ' || c == 0x21 || (0x23..=0x5b).contains(&c) || (0x5d..=0x7e).contains(&c) || c >= 0x80 => i += 1,
            _ => return None,
        }
    }
    None
}

fn token_len(s: &[u8]) -> usize {
    s.iter().take_while(|&&c| tchar(c)).count()
}

/// `*( BWS ";" BWS token [ BWS "=" BWS ( token / quoted-string ) ] )` – chunk extensions
/// (RFC 9112 §7.1.1) and transfer / content coding parameters.  The whole input must match.
pub fn params_ok(mut s: &[u8]) -> bool {
    let skip = |s: &mut &[u8]| {
        while let [c, rest @ ..] = *s {
            if ows(*c) { *s = rest } else { break }
        }
    };
    loop {
        skip(&mut s);
        if s.is_empty() {
            return true;
        }
        if s[0] != b';' {
            return false;
        }
        s = &s[1..];
        skip(&mut s);
        let n = token_len(s);
        if n == 0 {
            return false;
        }
        s = &s[n..];
        let mut t = s;
        skip(&mut t);
        if t.first() == Some(&b'=') {
            t = &t[1..];
            skip(&mut t);
            let n = if t.first() == Some(&b'"') { quoted(t) } else { Some(token_len(t)).filter(|&n| n > 0) };
            let Some(n) = n else { return false };
            s = &t[n..];
        }
    }
}

/// Splits a comma list (RFC 9110 §5.6.1: empty elements allowed) and calls `f` on each
/// trimmed non-empty element; false if `f` says so.
fn each_element(v: &[u8], f: &mut dyn FnMut(&[u8]) -> bool) -> bool {
    // Commas inside quoted strings belong to the element.
    let mut start = 0;
    let mut i = 0;
    while i <= v.len() {
        if i == v.len() || v[i] == b',' {
            let e = trim(&v[start..i]);
            if !e.is_empty() && !f(e) {
                return false;
            }
            start = i + 1;
            i += 1;
        } else if v[i] == b'"' {
            match quoted(&v[i..]) {
                Some(n) => i += n,
                None => return false,
            }
        } else {
            i += 1;
        }
    }
    true
}

/// A coding list element: token with optional parameters.
fn coding_ok(e: &[u8]) -> bool {
    let n = token_len(e);
    n > 0 && params_ok(&e[n..])
}

/// Fields that may not come in trailers (DeSoOS policy from the categories of RFC 9110
/// §6.5.1: framing, routing, authentication, control, content coding – needed before the
/// content).
const NOT_IN_TRAILERS: &[&str] = &[
    "content-length", "transfer-encoding", "host", "content-encoding", "content-type", "content-range", "trailer",
    "connection", "keep-alive", "te", "upgrade", "cache-control", "expires", "set-cookie", "authorization",
    "www-authenticate",
];

/// End-to-end fields Connection may not name (RFC 9110 §7.6.1).
const NOT_IN_CONNECTION: &[&str] = &[
    "content-length", "content-encoding", "content-type", "content-range", "host", "trailer", "cache-control",
    "expires", "set-cookie", "authorization", "www-authenticate",
];

/// Splits a field section into (name, value) lines; Err on a bad line.
fn each_field(block: &[u8], f: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), Error>) -> Result<(), Error> {
    if block.is_empty() {
        return Ok(());
    }
    let mut rest = block;
    loop {
        let (l, next) = match find(rest, b"\r\n") {
            Some(i) => (&rest[..i], Some(&rest[i + 2..])),
            None => (rest, None),
        };
        if l.contains(&b'\r') || l.contains(&b'\n') {
            return Err(bad("a bare CR or LF in a header line"));
        }
        if l.first().is_some_and(|&c| ows(c)) {
            return Err(bad("folded header line"));
        }
        let Some(colon) = l.iter().position(|&c| c == b':') else { return Err(bad("header line without ':'")) };
        let (k, v) = (&l[..colon], trim(&l[colon + 1..]));
        if !is_token(k) {
            return Err(bad("bad header name"));
        }
        if !value_ok(v) {
            return Err(bad("control character in a header value"));
        }
        f(k, v)?;
        match next {
            Some(n) => rest = n,
            None => return Ok(()),
        }
    }
}

pub fn find(h: &[u8], pat: &[u8]) -> Option<usize> {
    h.windows(pat.len()).position(|w| w == pat)
}

impl Parser {
    pub const fn new() -> Self {
        Parser {
            state: State::Head,
            head: [0; HEAD_MAX],
            hlen: 0,
            interim: 0,
            answer: None,
            no_content: false,
            line: [0; TRAILER_MAX],
            llen: 0,
            body: 0,
            conn: [[0; NAME_MAX]; MAX_CONN_NAMES],
            conn_len: [0; MAX_CONN_NAMES],
            conn_n: 0,
        }
    }

    pub fn reset(&mut self) {
        self.state = State::Head;
        self.hlen = 0;
        self.interim = 0;
        self.answer = None;
        self.no_content = false;
        self.llen = 0;
        self.body = 0;
        self.conn_n = 0;
    }

    /// The whole answer has arrived (by its framing).
    #[allow(dead_code)]
    pub fn done(&self) -> bool {
        self.state == State::Done
    }

    /// The next bytes from the transport.
    pub fn feed(&mut self, mut data: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        while !data.is_empty() {
            match self.state {
                State::Head => {
                    let old = self.hlen;
                    let take = data.len().min(HEAD_MAX - old);
                    self.head[old..old + take].copy_from_slice(&data[..take]);
                    self.hlen += take;
                    let from = old.saturating_sub(3);
                    match find(&self.head[from..self.hlen], b"\r\n\r\n") {
                        Some(i) => {
                            let e = from + i;
                            data = &data[e + 4 - old..];
                            self.head_done(e, sink)?;
                        }
                        None => {
                            if self.hlen == HEAD_MAX {
                                return Err(bad("headers longer than 8192 bytes"));
                            }
                            data = &[];
                        }
                    }
                }
                State::Length(left) => {
                    let k = (data.len() as u64).min(left) as usize;
                    self.give(&data[..k], sink)?;
                    data = &data[k..];
                    self.state = if left == k as u64 { State::Done } else { State::Length(left - k as u64) };
                }
                State::Close => {
                    self.give(data, sink)?;
                    data = &[];
                }
                State::Size | State::Trailers => {
                    // Up to the line's LF.
                    let limit = if self.state == State::Size { LINE_MAX } else { TRAILER_MAX };
                    let (k, lf) = match data.iter().position(|&c| c == b'\n') {
                        Some(i) => (i + 1, true),
                        None => (data.len(), false),
                    };
                    if self.llen + k > limit {
                        return Err(bad(if self.state == State::Size { "chunk-size line too long" } else { "trailers longer than 8192 bytes" }));
                    }
                    self.line[self.llen..self.llen + k].copy_from_slice(&data[..k]);
                    self.llen += k;
                    data = &data[k..];
                    if lf {
                        if self.state == State::Size {
                            self.size_line()?;
                        } else {
                            self.trailer_line(sink)?;
                        }
                    }
                }
                State::Data(left) => {
                    let k = (data.len() as u64).min(left) as usize;
                    self.give(&data[..k], sink)?;
                    data = &data[k..];
                    self.state = if left == k as u64 { State::DataCr } else { State::Data(left - k as u64) };
                }
                State::DataCr => {
                    if data[0] != b'\r' {
                        return Err(bad("no CRLF after the chunk's data"));
                    }
                    data = &data[1..];
                    self.state = State::DataLf;
                }
                State::DataLf => {
                    if data[0] != b'\n' {
                        return Err(bad("no CRLF after the chunk's data"));
                    }
                    data = &data[1..];
                    self.state = State::Size;
                }
                State::Done => return Err(bad("data after the end of the answer")),
            }
        }
        Ok(())
    }

    fn give(&mut self, data: &[u8], sink: &mut dyn Sink) -> Result<(), Error> {
        if data.is_empty() {
            return Ok(());
        }
        if self.no_content {
            return Err(bad("content in an answer that may not have any (205)"));
        }
        self.body = self.body.checked_add(data.len() as u64).ok_or(bad("body length overflows"))?;
        sink.body(data).map_err(|_| Error::Sink)
    }

    /// One head ended at `e` (the empty line at e..e+4).
    fn head_done(&mut self, e: usize, sink: &mut dyn Sink) -> Result<(), Error> {
        let h = &self.head[..e];
        let (first, fields) = match find(h, b"\r\n") {
            Some(i) => (&h[..i], &h[i + 2..]),
            None => (h, &h[e..e]),
        };
        let ok = first.len() >= 12
            && first.starts_with(b"HTTP/1.")
            && first[7].is_ascii_digit()
            && first[8] == b' '
            && first[9..12].iter().all(|c| c.is_ascii_digit())
            && (first.len() == 12 || first[12] == b' ')
            && value_ok(first);
        if !ok {
            return Err(bad("not an HTTP answer (status line)"));
        }
        let minor = first[7] - b'0';
        let status = (first[9] - b'0') as u32 * 100 + (first[10] - b'0') as u32 * 10 + (first[11] - b'0') as u32;
        if status < 100 {
            return Err(bad("bad status"));
        }

        let mut cl: Option<u64> = None;
        let mut cl_seen = false;
        let mut cl_bad = false;
        let mut te_fields = 0;
        let mut te_chunked = false;
        let mut te_syntax = true;
        let mut ce_identity = true;
        let mut ce_syntax = true;
        let mut cl_twice = false;
        let mut conn_n = 0usize;
        let mut conn_err: Option<&'static str> = None;
        let mut conn = [[0u8; NAME_MAX]; MAX_CONN_NAMES];
        let mut conn_len = [0u8; MAX_CONN_NAMES];
        each_field(fields, &mut |k, v| {
            if eq_ci(k, "content-length") {
                if cl_seen {
                    cl_twice = true;
                }
                cl_seen = true;
                if v.is_empty() || v.len() > 18 || !v.iter().all(|c| c.is_ascii_digit()) {
                    cl_bad = true;
                } else {
                    cl = core::str::from_utf8(v).ok().and_then(|s| s.parse().ok());
                }
            } else if eq_ci(k, "transfer-encoding") {
                te_fields += 1;
                let mut n = 0;
                let mut only_chunked = true;
                te_syntax &= each_element(v, &mut |el| {
                    n += 1;
                    if !eq_ci(el, "chunked") {
                        only_chunked = false;
                    }
                    coding_ok(el)
                });
                te_chunked = n == 1 && only_chunked;
            } else if eq_ci(k, "content-encoding") {
                ce_syntax &= each_element(v, &mut |el| {
                    if !eq_ci(el, "identity") {
                        ce_identity = false;
                    }
                    coding_ok(el)
                });
            } else if eq_ci(k, "connection") {
                let ok = each_element(v, &mut |el| {
                    if !is_token(el) {
                        conn_err = Some("bad Connection field");
                        return false;
                    }
                    if NOT_IN_CONNECTION.iter().any(|f| eq_ci(el, f)) {
                        conn_err = Some("Connection names an end-to-end field");
                        return false;
                    }
                    if el.len() > NAME_MAX {
                        conn_err = Some("Connection option name too long");
                        return false;
                    }
                    if conn_n == MAX_CONN_NAMES {
                        conn_err = Some("too many Connection options");
                        return false;
                    }
                    conn[conn_n][..el.len()].copy_from_slice(el);
                    conn_len[conn_n] = el.len() as u8;
                    conn_n += 1;
                    true
                });
                if !ok && conn_err.is_none() {
                    conn_err = Some("bad Connection field");
                }
            }
            Ok(())
        })?;
        if let Some(why) = conn_err {
            return Err(bad(why));
        }
        sink.head(h, (100..200).contains(&status) && status != 101);

        let has_framing = cl_seen || te_fields > 0;
        if (100..200).contains(&status) {
            if status == 101 {
                return Err(bad("101 Switching Protocols - no upgrade was asked for"));
            }
            if has_framing {
                return Err(bad("Content-Length or Transfer-Encoding in a 1xx answer"));
            }
            self.interim += 1;
            if self.interim > MAX_INTERIM {
                return Err(bad("more than 4 interim (1xx) answers"));
            }
            self.hlen = 0;
            return Ok(());
        }
        if status == 204 && has_framing {
            return Err(bad("Content-Length or Transfer-Encoding in a 204 answer"));
        }
        if cl_bad {
            return Err(bad("Content-Length is not a number"));
        }
        if cl_twice {
            return Err(bad("Content-Length more than once"));
        }
        if !te_syntax {
            return Err(bad("bad Transfer-Encoding field"));
        }
        if !ce_syntax {
            return Err(bad("bad Content-Encoding field"));
        }
        let framing = if status == 204 || status == 304 {
            // 304: the fields describe the 200 that was not sent – syntax only (checked above).
            Framing::Nothing
        } else {
            if te_fields > 0 && cl_seen {
                return Err(bad("both Transfer-Encoding and Content-Length"));
            }
            if te_fields > 1 {
                return Err(bad("Transfer-Encoding more than once"));
            }
            if te_fields == 1 {
                if minor == 0 {
                    return Err(bad("Transfer-Encoding in an HTTP/1.0 answer"));
                }
                if !te_chunked {
                    return Err(bad("unsupported transfer coding (only chunked)"));
                }
                Framing::Chunked
            } else {
                match cl {
                    Some(n) => Framing::Length(n),
                    None if cl_seen => return Err(bad("Content-Length is not a number")),
                    None => Framing::Close,
                }
            }
        };
        if status == 205 {
            if matches!(framing, Framing::Length(n) if n > 0) {
                return Err(bad("content in an answer that may not have any (205)"));
            }
            self.no_content = true;
        } else if framing != Framing::Nothing && !ce_identity {
            return Err(bad("unsupported content coding (only identity)"));
        }
        self.conn = conn;
        self.conn_len = conn_len;
        self.conn_n = conn_n;
        self.answer = Some(Head { status, framing });
        self.state = match framing {
            Framing::Nothing | Framing::Length(0) => State::Done,
            Framing::Length(n) => State::Length(n),
            Framing::Close => State::Close,
            Framing::Chunked => State::Size,
        };
        self.llen = 0;
        Ok(())
    }

    /// A chunk-size line in `line` (ending in LF).
    fn size_line(&mut self) -> Result<(), Error> {
        let l = &self.line[..self.llen];
        if l.len() < 2 || l[l.len() - 2] != b'\r' {
            return Err(bad("chunk-size line without CRLF"));
        }
        let l = &l[..l.len() - 2];
        if l.contains(&b'\r') {
            return Err(bad("a bare CR in a chunk-size line"));
        }
        let digits = l.iter().take_while(|c| c.is_ascii_hexdigit()).count();
        if digits == 0 {
            return Err(bad("chunk size is not hexadecimal"));
        }
        if digits > 16 {
            return Err(bad("chunk size longer than 16 hex digits"));
        }
        if !params_ok(&l[digits..]) {
            return Err(bad("bad chunk extension"));
        }
        let mut size: u64 = 0;
        for &c in &l[..digits] {
            size = size << 4 | (c as char).to_digit(16).unwrap_or(0) as u64;
        }
        self.llen = 0;
        if size == 0 {
            self.state = State::Trailers;
        } else {
            if self.no_content {
                return Err(bad("content in an answer that may not have any (205)"));
            }
            self.body.checked_add(size).ok_or(bad("body length overflows"))?;
            self.state = State::Data(size);
        }
        Ok(())
    }

    /// A trailer line arrived in `line`; the section ends with an empty line.
    fn trailer_line(&mut self, sink: &mut dyn Sink) -> Result<(), Error> {
        let l = &self.line[..self.llen];
        // The section so far ends in "\r\n" (a line) – the empty line is "\r\n" alone at the
        // section's start or "\r\n\r\n" at its end.
        if l.len() < 2 || l[l.len() - 2] != b'\r' {
            return Err(bad("trailer line without CRLF"));
        }
        let empty = l.len() == 2 || l.ends_with(b"\r\n\r\n");
        if !empty {
            return Ok(());
        }
        let section = &l[..l.len() - 2];
        let section = section.strip_suffix(b"\r\n").unwrap_or(section);
        let conn = &self.conn[..self.conn_n];
        let conn_len = &self.conn_len[..self.conn_n];
        each_field(section, &mut |k, _| {
            if NOT_IN_TRAILERS.iter().any(|f| eq_ci(k, f)) {
                return Err(bad("a field that may not be a trailer"));
            }
            if conn.iter().zip(conn_len).any(|(n, &len)| n[..len as usize].eq_ignore_ascii_case(k)) {
                return Err(bad("a trailer named by Connection"));
            }
            Ok(())
        })?;
        sink.trailers(section);
        self.llen = 0;
        self.state = State::Done;
        Ok(())
    }

    /// The connection ended: is the answer whole?
    pub fn finish(&self, end: End) -> Outcome {
        match self.state {
            State::Done => Outcome::Complete,
            State::Head if self.answer.is_none() => Outcome::NoAnswer,
            State::Close if end == End::Clean => Outcome::Complete,
            _ => Outcome::Cut,
        }
    }
}
