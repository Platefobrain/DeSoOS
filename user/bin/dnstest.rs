// DNS resolver test without a network (NET TEST 3/5): names, the query bytes,
// the answer parser on valid and malicious answers (compression loops, forward
// pointers, oversized names, CNAME chains, wrong question, truncation...), the
// cache (TTL, negative answers, eviction) and 20 000 mutations of valid answers
// (no panic, results within limits).
// Result: "dnstest: N checks OK" and code 0.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../lib/netproto.rs"]
mod netproto;
#[path = "../lib/dns.rs"]
mod dns;

use desoos::*;
use dns::*;
use netproto::NetError;

entry!(main);

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("dnstest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

/// A DNS message under construction.
struct B {
    b: [u8; 1024],
    n: usize,
}

impl B {
    fn new() -> B {
        B { b: [0; 1024], n: 0 }
    }
    fn put(&mut self, d: &[u8]) -> &mut B {
        self.b[self.n..self.n + d.len()].copy_from_slice(d);
        self.n += d.len();
        self
    }
    fn u16(&mut self, v: u16) -> &mut B {
        self.put(&v.to_be_bytes())
    }
    fn u32(&mut self, v: u32) -> &mut B {
        self.put(&v.to_be_bytes())
    }
    fn name(&mut self, s: &str) -> &mut B {
        for l in s.split('.') {
            self.put(&[l.len() as u8]);
            self.put(l.as_bytes());
        }
        self.put(&[0])
    }
    /// Header: id, flags, 1 question, `an` answers.
    fn head(&mut self, id: u16, flags: u16, qd: u16, an: u16) -> &mut B {
        self.u16(id).u16(flags).u16(qd).u16(an).u16(0).u16(0)
    }
    /// Question for `name`, type A, class IN.
    fn question(&mut self, name: &str) -> &mut B {
        self.name(name).u16(TYPE_A).u16(CLASS_IN)
    }
    /// A record; `owner` already written.
    fn a(&mut self, ttl: u32, ip: [u8; 4]) -> &mut B {
        self.u16(TYPE_A).u16(CLASS_IN).u32(ttl).u16(4).put(&ip)
    }
    fn bytes(&self) -> &[u8] {
        &self.b[..self.n]
    }
}

const ID: u16 = 0x1234;
const OK: u16 = 0x8180;
const PTR_Q: [u8; 2] = [0xC0, 12];

fn name(s: &str) -> Name {
    Name::parse(s).unwrap_or(Name::EMPTY)
}

/// The usual answer: router.desoos A 10.0.2.2, TTL 300.
fn simple() -> B {
    let mut b = B::new();
    b.head(ID, OK, 1, 1).question("router.desoos").put(&PTR_Q).a(300, [10, 0, 2, 2]);
    b
}

/// www.desoos -> CNAME web.desoos -> CNAME srv.desoos -> A, with pointers.
fn chain() -> B {
    let mut b = B::new();
    b.head(ID, OK, 1, 3).question("www.desoos");
    // CNAME 1: owner = question; target "web" + pointer to "desoos" in the question.
    let q_desoos = 12 + 4; // after "\x03www"
    b.put(&PTR_Q).u16(TYPE_CNAME).u16(CLASS_IN).u32(600).u16(6).put(&[3, b'w', b'e', b'b', 0xC0, q_desoos as u8]);
    let web_at = b.n - 6;
    // CNAME 2: owner = pointer to "web.desoos"; target "srv" + pointer.
    b.put(&[0xC0, web_at as u8]).u16(TYPE_CNAME).u16(CLASS_IN).u32(120).u16(6).put(&[3, b's', b'r', b'v', 0xC0, q_desoos as u8]);
    let srv_at = b.n - 6;
    b.put(&[0xC0, srv_at as u8]).a(900, [10, 0, 2, 9]);
    b
}

fn main(_args: Args) -> i32 {
    let mut n = 0;

    // 1. Names typed by users.
    let good = ["example.com", "A.B.C", "x", "my-host_1.lan", "example.com.", "1.example", "xn--bcher-kva.example"];
    check!(n, good.iter().all(|s| Name::parse(s).is_some()), "valid name refused: {:?}", good.iter().find(|s| Name::parse(s).is_none()));
    check!(n, name("WWW.Example.COM.").as_str() == "www.example.com", "case / final dot: {:?}", name("WWW.Example.COM."));
    let mut long = [b'a'; 300];
    for i in (63..300).step_by(64) {
        long[i] = b'.';
    }
    let s253 = core::str::from_utf8(&long[..253]).unwrap_or("");
    let s254 = core::str::from_utf8(&long[..254]).unwrap_or("");
    let s63 = core::str::from_utf8(&[b'b'; 63]).unwrap_or("");
    let s64 = core::str::from_utf8(&[b'b'; 64]).unwrap_or("");
    check!(n, Name::parse(s253).is_some() && Name::parse(s254).is_none(), "253 / 254 characters");
    check!(n, Name::parse(s63).is_some() && Name::parse(s64).is_none(), "63 / 64-character label");
    let bad = ["", ".", "..", "a..b", ".a", "a b", "a/b", "ä.com", "a.b..", "10.0.2.300", "1.2.3.4", "host.123", "a\0b"];
    check!(n, bad.iter().all(|s| Name::parse(s).is_none()), "invalid name accepted: {:?}", bad.iter().find(|s| Name::parse(s).is_some()));

    // 2. The query, byte for byte.
    let mut q = [0u8; 300];
    let len = build_query(&mut q, ID, &name("router.desoos"));
    let want: [u8; 31] = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6, b'r', b'o', b'u', b't', b'e', b'r', 6, b'd', b'e', b's', b'o', b'o', b's', 0, 0, 1, 0, 1];
    check!(n, q[..len] == want, "query bytes {:?}", &q[..len]);
    let len = build_query(&mut q, 1, &name(s253));
    check!(n, len == 12 + 255 + 4, "longest query {} bytes", len);

    // 3. Valid answers.
    let r = parse_response(simple().bytes(), ID, &name("router.desoos"));
    check!(n, matches!(r, Ok(a) if a.rcode == 0 && a.n == 1 && a.addrs[0] == [10, 0, 2, 2] && a.ttl == 300 && a.cname.is_empty()), "simple answer {:?}", r);
    let r = parse_response(chain().bytes(), ID, &name("www.desoos"));
    check!(n, matches!(r, Ok(a) if a.n == 1 && a.addrs[0] == [10, 0, 2, 9] && a.ttl == 120 && a.cname.as_str() == "srv.desoos"), "CNAME chain with pointers {:?}", r);
    let mut b = B::new();
    b.head(ID, OK, 1, 2).question("h.desoos").name("other.desoos").a(60, [6, 6, 6, 6]).name("H.DESOOS").a(60, [10, 0, 2, 5]);
    let r = parse_response(b.bytes(), ID, &name("h.desoos"));
    check!(n, matches!(r, Ok(a) if a.n == 1 && a.addrs[0] == [10, 0, 2, 5]), "a record for another name must be ignored, case folded: {:?}", r);
    let mut b = B::new();
    b.head(ID, OK, 1, 3).question("h.desoos");
    b.put(&PTR_Q).u16(28).u16(CLASS_IN).u32(60).u16(16).put(&[0x20; 16]); // AAAA
    b.put(&PTR_Q).u16(TYPE_A).u16(3).u32(60).u16(4).put(&[7, 7, 7, 7]); // class CH
    b.put(&PTR_Q).a(30, [10, 0, 2, 6]);
    let r = parse_response(b.bytes(), ID, &name("h.desoos"));
    check!(n, matches!(r, Ok(a) if a.n == 1 && a.addrs[0] == [10, 0, 2, 6] && a.ttl == 30), "other types and classes skipped: {:?}", r);
    let mut b = B::new();
    b.head(ID, OK, 1, 6).question("big.desoos");
    for i in 1..=6u8 {
        b.put(&PTR_Q).a(100 - i as u32, [10, 0, 3, i]);
    }
    let r = parse_response(b.bytes(), ID, &name("big.desoos"));
    check!(n, matches!(r, Ok(a) if a.n == ADDRS_MAX && a.addrs[3] == [10, 0, 3, 4] && a.ttl == 96), "six addresses: four kept {:?}", r);
    let mut b = B::new();
    b.head(ID, OK | 3, 1, 0).question("nx.desoos");
    let r = parse_response(b.bytes(), ID, &name("nx.desoos"));
    check!(n, matches!(r, Ok(a) if a.rcode == RCODE_NXDOMAIN && a.n == 0), "no such name {:?}", r);

    // 4. Malicious answers: (what, message, expected error).
    let q = name("router.desoos");
    let mut cases: [(&str, B, NetError); 19] = core::array::from_fn(|_| ("", B::new(), NetError::Short));
    let mut k = 0;
    let mut add = |what: &'static str, b: B, e: NetError| {
        cases[k] = (what, b, e);
        k += 1;
    };
    let mut b = simple();
    b.n = 11;
    add("11 bytes", b, NetError::Short);
    let mut b = B::new();
    b.head(ID ^ 1, OK, 1, 0).question("router.desoos");
    add("another id", b, NetError::Unsupported);
    let mut b = B::new();
    b.head(ID, 0x0100, 1, 0).question("router.desoos");
    add("a query, not an answer", b, NetError::Unsupported);
    let mut b = B::new();
    b.head(ID, OK | 0x0800, 1, 0).question("router.desoos");
    add("opcode 1", b, NetError::Unsupported);
    let mut b = B::new();
    b.head(ID, OK | 0x0200, 1, 0).question("router.desoos");
    add("truncated (TC)", b, NetError::Truncated);
    let mut b = B::new();
    b.head(ID, OK, 0, 0);
    add("no question", b, NetError::BadHeader);
    let mut b = B::new();
    b.head(ID, OK, 2, 0).question("router.desoos").question("router.desoos");
    add("two questions", b, NetError::BadHeader);
    let mut b = B::new();
    b.head(ID, OK, 1, 1).question("evil.desoos").put(&PTR_Q).a(300, [6, 6, 6, 6]);
    add("answer to another question", b, NetError::BadHeader);
    let mut b = B::new();
    b.head(ID, OK, 1, 0).name("router.desoos").u16(28).u16(CLASS_IN);
    add("question for AAAA", b, NetError::BadHeader);
    let mut b = B::new();
    b.head(ID, OK, 1, 1).question("router.desoos");
    let at = b.n as u8;
    b.put(&[0xC0, at]).a(300, [6, 6, 6, 6]);
    add("pointer to itself", b, NetError::BadHeader);
    let mut b = B::new();
    b.head(ID, OK, 1, 1).question("router.desoos");
    let at = b.n as u8 + 2 + 10 + 4;
    b.put(&[0xC0, at]).a(300, [6, 6, 6, 6]).put(&[1, b'x', 0]);
    add("forward pointer", b, NetError::BadHeader);
    let mut b = B::new();
    b.head(ID, OK, 1, 1).question("router.desoos").put(&[0xC3, 0xFF]).a(300, [6, 6, 6, 6]);
    add("pointer past the end", b, NetError::BadHeader);
    let mut b = B::new();
    b.head(ID, OK, 1, 1).question("router.desoos").put(&[0x40, b'x', 0]).a(300, [6, 6, 6, 6]);
    add("label type 01 (64+)", b, NetError::BadHeader);
    let mut b = B::new();
    b.head(ID, OK, 1, 1).question("router.desoos").put(&[3, b'w', b'.', b'x', 0]).a(300, [6, 6, 6, 6]);
    add("dot inside a label", b, NetError::BadHeader);
    let mut b = B::new();
    b.head(ID, OK, 1, 1).question("router.desoos").put(&PTR_Q).u16(TYPE_A).u16(CLASS_IN).u32(1).u16(200).put(&[10, 0, 2, 2]);
    add("record length past the end", b, NetError::Short);
    let mut b = B::new();
    b.head(ID, OK, 1, 3).question("router.desoos").put(&PTR_Q).a(300, [10, 0, 2, 2]);
    add("more answers announced than sent", b, NetError::Short);
    let mut b = B::new();
    b.head(ID, OK, 1, 1).question("router.desoos").put(&PTR_Q).u16(TYPE_A).u16(CLASS_IN).u32(1).u16(5).put(&[10, 0, 2, 2, 2]);
    add("A record of 5 bytes", b, NetError::BadHeader);
    // A name of 4 × 63 characters through pointers: 255 > 253.
    // The name pieces sit in the data of an unknown record type (skipped).
    let mut b = B::new();
    b.head(ID, OK, 1, 2).question("router.desoos").put(&PTR_Q).u16(99).u16(CLASS_IN).u32(1).u16(2 * 129 + 1);
    let l1 = b.n;
    b.put(&[63]).put(&[b'a'; 63]).put(&[63]).put(&[b'b'; 63]).put(&[0]);
    let l2 = b.n;
    b.put(&[63]).put(&[b'c'; 63]).put(&[63]).put(&[b'd'; 63]).put(&[0xC0 | (l1 >> 8) as u8, l1 as u8]);
    b.put(&[0xC0 | (l2 >> 8) as u8, l2 as u8]).a(1, [6, 6, 6, 6]);
    add("name longer than 253 through pointers", b, NetError::BadHeader);
    // CNAME chain of 9 links.
    let mut b = B::new();
    b.head(ID, OK, 1, 9).question("router.desoos");
    let mut owner = 12usize;
    for i in 0..9u8 {
        b.put(&[0xC0 | (owner >> 8) as u8, owner as u8]).u16(TYPE_CNAME).u16(CLASS_IN).u32(60).u16(3).put(&[1, b'a' + i, 0]);
        owner = b.n - 3;
    }
    add("CNAME chain of 9", b, NetError::BadHeader);
    for (what, b, want) in &cases {
        let r = parse_response(b.bytes(), ID, &q).map(|_| ());
        check!(n, r == Err(*want), "{}: expected {:?}, got {:?}", what, want, r);
    }

    // 5. Cache.
    let mut c = Cache::new();
    let t = 1_000_000u64;
    let a = parse_response(simple().bytes(), ID, &q).unwrap_or_else(|_| exit(90));
    c.put(&q, &a, t);
    check!(n, matches!(c.get(&q, t + 299_999), Some(x) if x.n == 1 && x.addrs[0] == [10, 0, 2, 2]) && c.get(&q, t + 300_000).is_none(), "TTL 300 s");
    check!(n, c.get(&name("ROUTER.desoos"), t).is_some() && c.get(&name("other.desoos"), t).is_none(), "lookup by name");
    let mut zero = a;
    zero.ttl = 0;
    let z = name("zero.desoos");
    c.put(&z, &zero, t);
    check!(n, c.get(&z, t).is_none(), "TTL 0 cached");
    let mut long = a;
    long.ttl = 7 * 86400;
    let l = name("long.desoos");
    c.put(&l, &long, t);
    check!(n, c.get(&l, t + TTL_MAX_S as u64 * 1000 - 1).is_some() && c.get(&l, t + TTL_MAX_S as u64 * 1000).is_none(), "TTL capped at {} s", TTL_MAX_S);
    let nx = Answer { rcode: RCODE_NXDOMAIN, addrs: [[0; 4]; ADDRS_MAX], n: 0, ttl: 0, cname: Name::EMPTY };
    let nn = name("nx.desoos");
    c.put(&nn, &nx, t);
    check!(n, matches!(c.get(&nn, t + 29_000), Some(x) if x.rcode == RCODE_NXDOMAIN && x.n == 0) && c.get(&nn, t + 30_000).is_none(), "no such name remembered 30 s");
    let sf = Answer { rcode: RCODE_SERVFAIL, ..nx };
    let sn = name("fail.desoos");
    c.put(&sn, &sf, t);
    check!(n, c.get(&sn, t).is_none(), "server failure cached");
    // Full: 16 more names push out the one expiring first; the cache stays 16.
    let mut namebuf = *b"host00.desoos";
    for i in 0..CACHE as u8 {
        namebuf[4] = b'a' + i / 10;
        namebuf[5] = b'0' + i % 10;
        let nm = name(core::str::from_utf8(&namebuf).unwrap_or(""));
        let mut x = a;
        x.ttl = 1000 + i as u32;
        c.put(&nm, &x, t);
    }
    check!(n, c.len(t) == CACHE && c.get(&nn, t).is_none(), "eviction: {} entries", c.len(t));
    c.clear();
    check!(n, c.len(t) == 0 && c.get(&q, t).is_none(), "clear");

    // 6. Mutations of valid answers.
    let samples = [simple(), chain()];
    let names = [q, name("www.desoos")];
    let mut x = 0x646E_7374_6573_7431u64;
    let mut rnd = |m: usize| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x % m.max(1) as u64) as usize
    };
    let (mut ok, mut refused) = (0u32, 0u32);
    const MUTATIONS: u32 = 20_000;
    for i in 0..MUTATIONS {
        let s = (i % 2) as usize;
        let mut b = B::new();
        b.put(samples[s].bytes());
        for _ in 0..1 + rnd(4) {
            match rnd(5) {
                0 => b.b[rnd(b.n)] ^= 1 << rnd(8),
                1 => b.b[rnd(b.n)] = [0, 0xFF, 0xC0, 0x3F, 0x40, 63, 1][rnd(7)],
                2 if b.n > 12 => b.b[12 + rnd(b.n - 12)] = 0xC0, // pointers
                3 => b.b[rnd(12)] = rnd(256) as u8, // header
                _ => b.n = rnd(b.n + 1),
            }
        }
        match parse_response(b.bytes(), ID, &names[s]) {
            Ok(a) => {
                if a.n > ADDRS_MAX || a.cname.as_bytes().len() > NAME_MAX {
                    println!("dnstest: FAIL mutation {}: out of limits {:?}", i, a);
                    return 1;
                }
                ok += 1;
            }
            Err(_) => refused += 1,
        }
    }
    n += 1;
    println!(
        "dnstest: {} checks OK ({} malicious answers refused with the right error, cache TTL / negative / eviction, {} mutations: {} accepted within limits, {} refused)",
        n,
        cases.len(),
        MUTATIONS,
        ok,
        refused
    );
    0
}
