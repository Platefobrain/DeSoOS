// timekeeper – the time service (init's `time`, user/etc/services/time.svc).  It asks NTS
// servers of three different operators what time it is, and when at least two operators agree
// it gives the kernel the time (SYS_TIME_SET, the SETTIME handle in slot 7): the wall clock is
// corrected and the last known good time raised.  It is the only program with that right.
//
// The servers come only from the list built into this program – one entry per server, each
// with its operator_id; the operator decides the vote, never a name, an address or anything
// a server sends (an NTS-KE that moves NTP elsewhere does not change whose vote it is).  No
// argument, message or file can add a server.  (`nettime --nts host` is a separate program
// without the right; it never bootstraps and never sets anything.)
//
// A round (at the start, then every hour; after a failed round again when the next server's
// NTS-KE backoff allows, at the latest in 60 s).  Before a round the service waits, without a
// word, until net0 has an address and a DNS server (netd's "status") – at boot the lease takes
// seconds (15 s on the Legion), and NTS-KE attempts before it would only fill the screen and
// the backoff.
//   1. SYS_TIME_BOUND: the bound B and the state of the LKG file; syscall 59: is the clock
//      plausible?
//   2. NTS-KE (user/lib/ntske.rs) with every server that has no cookies left and whose backoff
//      allows (10 s, x 1.5, at most 5 days; reset only by an NTS-KE followed by a good NTS
//      answer).  Clock plausible – the ordinary certificate check at its time.  Not plausible
//      – a bootstrap: the certificates need only notAfter >= B (B = the LKG in memory or the
//      build date, computed by the kernel; with an unreadable LKG file it is recovery mode,
//      the same rule), and DeSoTLS keeps the chain that server sent in that handshake.
//   3. NTS queries (user/lib/nts.rs), every server at once, at most two queries each,
//      2 s each; an answer counts only authenticated.  Each good answer is an interval
//      T +- U (user/lib/timesync.rs).
//   4. Bootstrap only: the second check – the kept chain checked again, fully (signatures,
//      CAs, the name from the list, key usages, every certificate valid over the whole
//      [T - U, T + U] of that server's own answer).  A failure wipes that server's keys,
//      cookies and chain, and it has no vote.
//   5. The quorum (timesync::quorum): at least two operators whose intervals (+-1 s) meet,
//      the largest such group, a tie = nothing; the envelope of their intervals = T +- U.
//   6. SYS_TIME_SET(T, U, operators): the kernel checks the numbers, raises the LKG (and
//      writes an unreadable LKG file anew), and sets the wall clock.
//
// The kernel trusts this service's word that the time came from NTS and from different
// operators – it cannot check that; it enforces the numbers and that the LKG never goes down.
//
// Self-test build only: `timekeeper test:<case>` uses a test list (tests/nts-server on the
// host, the test CAs built in) and does one round – the kernel's NTS TEST.  The normal build
// has no test list and takes no argument.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;
#[path = "../../common/desotls/mod.rs"]
mod desotls;
#[path = "../lib/ntp.rs"]
mod ntp;
#[path = "../lib/nts.rs"]
mod nts;
#[path = "../lib/ntske.rs"]
mod ntske;
#[path = "../lib/timesync.rs"]
mod timesync;

use desoos::*;
use desotls::chain::{self, PeerChain};
use desotls::client::{Client, Config};
use desotls::record::Suite;
use desotls::roots::{Anchors, Roots};
use timesync::{Backoff, Quorum, Sample};

entry!(main);

/// One server of the list.
#[derive(Clone, Copy)]
struct Entry {
    host: &'static str,
    /// The NTS-KE port.
    port: u16,
    operator: &'static str,
}

/// The list in the image (D6): three operators.
const IMAGE: [Entry; 3] = [
    Entry { host: "time.cloudflare.com", port: nts::KE_PORT, operator: "cloudflare" },
    Entry { host: "nts.netnod.se", port: nts::KE_PORT, operator: "netnod" },
    Entry { host: "ptbtime1.ptb.de", port: nts::KE_PORT, operator: "ptb" },
];
const MAX: usize = 3;
const CARD: &str = "net0";
/// Waiting for an NTS answer (each of the two queries).
const WAIT_MS: u64 = 2000;
const RESYNC_MS: u64 = 3_600_000;
const RETRY_MS: u64 = 60_000;
const ROOTS_SLOT: u64 = 8;
const STORE_MAX: usize = 256 * 1024;

static mut TLS: Client = Client::new();
static mut STORE: [u8; STORE_MAX] = [0; STORE_MAX];
static mut CHAN_BUF: [u8; MSG_MAX] = [0; MSG_MAX];
static mut KE_BUF: [u8; nts::KE_MAX + 4096] = [0; nts::KE_MAX + 4096];
static mut POOLS: [nts::Pool; MAX] = [const { nts::Pool::new() }; MAX];
static mut CHAINS: [PeerChain; MAX] = [const { PeerChain::new() }; MAX];

/// What the service knows about one server between rounds.
struct Source {
    /// Keys and cookies from an NTS-KE (none: the next round starts with one).
    keyed: bool,
    c2s: [u8; 32],
    s2c: [u8; 32],
    /// Where NTP goes (NTS-KE's Server / Port Negotiation, else the KE server and 123).
    host: [u8; 253],
    host_len: usize,
    port: u16,
    addr: [u8; 24],
    addr_len: usize,
    /// The NTS-KE was a bootstrap: its chain waits in CHAINS for the second check.
    needs_check: bool,
    backoff: Backoff,
    /// NTS-KE failures in a row (only the first one is told on the console).
    fails: u32,
}

impl Source {
    const fn new() -> Source {
        Source { keyed: false, c2s: [0; 32], s2c: [0; 32], host: [0; 253], host_len: 0, port: 0, addr: [0; 24], addr_len: 0, needs_check: false, backoff: Backoff::new(), fails: 0 }
    }
    /// Keys, cookies and the kept chain gone; the next round needs a new NTS-KE.
    fn forget(&mut self, pool: &mut nts::Pool, chain: &mut PeerChain) {
        self.keyed = false;
        self.needs_check = false;
        desocrypto::wipe(&mut self.c2s);
        desocrypto::wipe(&mut self.s2c);
        pool.clear();
        chain.clear();
    }
}

/// How a round ended (the test case's exit code).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The kernel took the time.
    Set = 0,
    /// No quorum (too few answers, no agreement, a tie) – nothing given to the kernel.
    NoQuorum = 3,
    /// The kernel refused SYS_TIME_SET.
    Refused = 4,
}

fn date(secs: u64, buf: &mut [u8; 19]) -> &str {
    format_utc(secs, buf)
}

/// One round (see the file comment).  `list` = the entries, `ops[i]` = the operator index of
/// entry i.  `last` – how the previous round ended (None: the first round, or a test): the
/// console hears only what changed – a steady hourly synchronisation says nothing, a server
/// that keeps failing is told once, the same result twice is told once (the kernel log has
/// every SYS_TIME_SET anyway).
fn round(list: &[Entry], ops: &[usize], src: &mut [Source], anchors: &dyn Anchors, last: Option<Outcome>) -> Outcome {
    let loud = last != Some(Outcome::Set);
    let pools = unsafe { &mut *core::ptr::addr_of_mut!(POOLS) };
    let chains = unsafe { &mut *core::ptr::addr_of_mut!(CHAINS) };
    let mut d1 = [0u8; 19];
    let tb = match time_bound() {
        Ok(t) => t,
        Err(e) => {
            println!("timekeeper: time_bound: {} - no round", strerror(e));
            return Outcome::NoQuorum;
        }
    };
    let Ok(clock) = time_unix() else {
        println!("timekeeper: cannot read the clock - no round");
        return Outcome::NoQuorum;
    };
    let bootstrap = !clock.plausible();
    if bootstrap && loud {
        println!(
            "timekeeper: clock not plausible ({}) - bootstrap: certificates need notAfter >= {} UTC ({}), then the full check over each answer's T +- U",
            clock_reason(clock.status),
            date(tb.bound, &mut d1),
            if tb.lkg >= tb.build { "the last known good time in memory" } else { "the build date" }
        );
        if tb.recovery() {
            println!("timekeeper: recovery: last known good time unreadable - bootstrap bound = {} UTC (max of the LKG in memory and the build date)", date(tb.bound, &mut d1));
        }
    }
    let suites = [Suite::Aes128Gcm, Suite::Chacha20Poly1305];

    // 2. NTS-KE where there are no cookies left.
    for (i, e) in list.iter().enumerate() {
        let s = &mut src[i];
        if s.keyed && pools[i].n > 0 {
            continue;
        }
        if s.keyed {
            s.forget(&mut pools[i], &mut chains[i]);
        }
        // Due within 2 s: servers that failed together try again together.
        if !s.backoff.due(uptime_ms() + 2000) {
            continue;
        }
        let cfg = Config { host: e.host, anchors, now: clock.secs as i64, suites: &suites, alpn: Some(nts::ALPN), bootstrap: if bootstrap { Some(tb.bound as i64) } else { None } };
        let buf = ntske::Buffers {
            tls: unsafe { &mut *core::ptr::addr_of_mut!(TLS) },
            msg: unsafe { &mut *core::ptr::addr_of_mut!(CHAN_BUF) },
            ke: unsafe { &mut *core::ptr::addr_of_mut!(KE_BUF) },
        };
        let chain = if bootstrap { Some(&mut chains[i]) } else { None };
        match ntske::key_exchange("timekeeper", s.fails == 0 || last.is_none(), &cfg, e.port, CARD, &mut pools[i], WAIT_MS, buf, &mut s.addr, &mut s.addr_len, chain) {
            Ok(mut done) => {
                s.keyed = true;
                s.c2s = done.c2s;
                s.s2c = done.s2c;
                done.wipe();
                let target = match done.neg.server() {
                    Some(h) => h.as_bytes(),
                    None => &s.addr[..s.addr_len],
                };
                s.host_len = target.len().min(s.host.len());
                let n = s.host_len;
                let mut tmp = [0u8; 253];
                tmp[..n].copy_from_slice(&target[..n]);
                s.host[..n].copy_from_slice(&tmp[..n]);
                s.port = done.neg.port;
                s.needs_check = bootstrap;
            }
            Err(why) => {
                s.backoff.failed(uptime_ms());
                s.fails += 1;
                if s.fails == 1 || last.is_none() {
                    println!("timekeeper: {}:{} ({}): {} - next NTS-KE in {} s{}", e.host, e.port, e.operator, why, (s.backoff.next.saturating_sub(uptime_ms()) + 999) / 1000, if last.is_some() { " (later failures in a row are not shown)" } else { "" });
                }
            }
        }
    }

    // 3. The queries, every keyed server at once.
    #[derive(Clone, Copy)]
    struct Q {
        chan: u64,
        xmit: u64,
        uid: [u8; nts::UID_LEN],
        sent: u64,
        deadline: u64,
        tries: u32,
        done: bool,
        t: i64,
        u: u64,
        /// Uptime when the answer came.
        arrived: u64,
        got: bool,
        why: Option<&'static str>,
    }
    let blank = Q { chan: 0, xmit: 0, uid: [0; nts::UID_LEN], sent: 0, deadline: 0, tries: 0, done: true, t: 0, u: 0, arrived: 0, got: false, why: None };
    let mut q = [blank, blank, blank];
    let ask = |s: &Source, q: &mut Q, pool: &mut nts::Pool| -> bool {
        let mut r = [0u8; 8 + nts::UID_LEN + nts::NONCE_LEN];
        if getrandom(&mut r).is_err() {
            return false;
        }
        q.xmit = u64::from_be_bytes([r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]]);
        q.uid.copy_from_slice(&r[8..8 + nts::UID_LEN]);
        let mut nonce = [0u8; nts::NONCE_LEN];
        nonce.copy_from_slice(&r[8 + nts::UID_LEN..]);
        q.tries += 1;
        q.sent = uptime_ms();
        q.deadline = q.sent + WAIT_MS;
        // The cookie leaves the pool now – it is never sent twice, answer or not.
        let Some(cookie) = pool.take() else {
            q.why = Some("no NTS cookie left");
            return false;
        };
        let Some(p) = nts::placeholders(pool.n, cookie.len, nts::REQUEST_LIMIT) else {
            q.why = Some("NTS cookie too long for one packet");
            return false;
        };
        let mut pkt = [0u8; nts::REQUEST_MAX];
        match nts::build_request(&mut pkt, q.xmit, &q.uid, &cookie, p, &nonce, &s.c2s) {
            Ok(n) => udp_send(q.chan, &pkt[..n]) == 0,
            Err(()) => false,
        }
    };
    for i in 0..list.len() {
        let s = &src[i];
        if !s.keyed {
            continue;
        }
        let host = core::str::from_utf8(&s.host[..s.host_len]).unwrap_or("?");
        let mut reply = [0u8; 256];
        match udp_open_via(SVC, CARD, host, s.port, &mut reply) {
            Ok(c) => {
                q[i].chan = c;
                q[i].done = false;
                if !ask(s, &mut q[i], &mut pools[i]) {
                    q[i].done = true;
                }
            }
            Err(k) => {
                q[i].why = Some("the NTP server from NTS-KE is not reachable");
                println!("timekeeper: {}:{}: {}", list[i].host, list[i].port, core::str::from_utf8(&reply[..k]).unwrap_or("?").trim());
            }
        }
    }
    let mut buf = [0u8; MSG_MAX];
    let mut info = RecvInfo::default();
    loop {
        let now = uptime_ms();
        for i in 0..list.len() {
            if !q[i].done && now >= q[i].deadline {
                if q[i].tries < 2 && ask(&src[i], &mut q[i], &mut pools[i]) {
                    continue;
                }
                q[i].done = true;
                q[i].why.get_or_insert("no answer");
            }
        }
        let mut wl = [(0u64, 0u64); MAX];
        let mut who = [0usize; MAX];
        let mut k = 0;
        let mut next = u64::MAX;
        for i in 0..list.len() {
            if !q[i].done {
                wl[k] = (q[i].chan, W_READABLE);
                who[k] = i;
                k += 1;
                next = next.min(q[i].deadline);
            }
        }
        if k == 0 {
            break;
        }
        let ready = wait_many(&wl[..k], next.saturating_sub(uptime_ms()).max(1)).unwrap_or(0);
        for e in 0..k {
            if ready & (1 << e) == 0 {
                continue;
            }
            let i = who[e];
            let r = chan_recv(q[i].chan, &mut buf, CHAN_NONBLOCK, &mut info);
            let received = uptime_ms();
            if r == ERROR_WOULD_BLOCK {
                continue;
            }
            if r < 0 {
                q[i].done = true;
                q[i].why = Some("the socket was closed (address changed?)");
                continue;
            }
            match nts::check_response(&buf[..r as usize], q[i].xmit, &q[i].uid, &src[i].s2c, &mut pools[i]) {
                Ok(nts::Answer::Time { reply, .. }) => match timesync::measure(&reply, q[i].sent, received, clock.build_epoch) {
                    Ok((t, u)) => {
                        q[i].t = t;
                        q[i].u = u;
                        q[i].arrived = received;
                        q[i].got = true;
                        q[i].done = true;
                    }
                    Err(why) => q[i].why = Some(why.as_str()),
                },
                Ok(nts::Answer::Nak) => {
                    // The server did not take the cookie: the retry with the next one now.
                    if !(q[i].tries < 2 && ask(&src[i], &mut q[i], &mut pools[i])) {
                        q[i].done = true;
                        q[i].why = Some("NTS NAK - a new NTS-KE is needed");
                        pools[i].clear();
                    }
                }
                Err(why) => q[i].why = Some(why.as_str()),
            }
        }
    }
    for x in q.iter() {
        if x.chan != 0 {
            close(x.chan);
        }
    }

    // 4. The second check (bootstrap) and 5. the samples.
    let mut samples = [Sample { off: 0, u: 0, op: 0, entry: 0 }; MAX];
    let mut ns = 0;
    let mut d2 = [0u8; 19];
    for (i, e) in list.iter().enumerate() {
        let s = &mut src[i];
        if !q[i].got {
            if s.keyed && loud {
                if let Some(w) = q[i].why {
                    println!("timekeeper: {}:{} ({}): {}", e.host, e.port, e.operator, w);
                }
            }
            continue;
        }
        let (t, u) = (q[i].t, q[i].u);
        if s.needs_check {
            let (from, to) = timesync::cert_span(t, u);
            let mut certs: [&[u8]; chain::MAX_CERTS] = [&[]; chain::MAX_CERTS];
            let n = chains[i].certs(&mut certs);
            let r = desotls::verify::server_over(&certs[..n], anchors, e.host, from, to);
            if let Err(err) = r {
                println!(
                    "timekeeper: {}:{} ({}): second check over [{}, {}] UTC failed: {} - keys, cookies and chain wiped, no vote",
                    e.host,
                    e.port,
                    e.operator,
                    date(from.max(0) as u64, &mut d1),
                    date(to.max(0) as u64, &mut d2),
                    err.as_str()
                );
                s.forget(&mut pools[i], &mut chains[i]);
                s.backoff.failed(uptime_ms());
                continue;
            }
            println!("timekeeper: {}:{} ({}): second check over [{}, {}] UTC passed ({} certificates)", e.host, e.port, e.operator, date(from.max(0) as u64, &mut d1), date(to.max(0) as u64, &mut d2), n);
            s.needs_check = false;
            chains[i].clear();
        }
        // An NTS-KE followed by a good NTS answer: the backoff starts again.
        s.backoff.succeeded();
        s.fails = 0;
        if loud {
            println!("timekeeper: {}:{} ({}): {}.{:03} UTC +-{} ms", e.host, e.port, e.operator, date((t.max(0) / 1000) as u64, &mut d1), t.rem_euclid(1000), u);
        }
        samples[ns] = Sample { off: t - q[i].arrived as i64, u, op: ops[i], entry: i };
        ns += 1;
    }

    // 5. The quorum, 6. the kernel.
    let tell = last != Some(Outcome::NoQuorum);
    match timesync::quorum(&samples[..ns]) {
        Quorum::TooFew if !tell => Outcome::NoQuorum,
        Quorum::NoAgreement | Quorum::Ambiguous if !tell => Outcome::NoQuorum,
        Quorum::TooFew => {
            let ops_seen = (0..ns).filter(|&k| !samples[..k].iter().any(|x| x.op == samples[k].op)).count();
            println!("timekeeper: result: no quorum - {} operator(s) answered, at least 2 needed; nothing given to the kernel", ops_seen);
            Outcome::NoQuorum
        }
        Quorum::NoAgreement => {
            println!("timekeeper: result: no quorum - no two operators agree (2 s tolerance); nothing given to the kernel");
            Outcome::NoQuorum
        }
        Quorum::Ambiguous => {
            println!("timekeeper: result: ambiguous quorum - two different groups of operators agree; nothing given to the kernel");
            Outcome::NoQuorum
        }
        Quorum::Agreed { members, n, off, u } => {
            let t = off + uptime_ms() as i64;
            let r = time_set(SETTIME, t.max(0) as u64, u, n as u64);
            let mut who = [0u8; 64];
            let mut wl = 0;
            for (j, &m) in members[..n].iter().enumerate() {
                for b in (if j > 0 { ", " } else { "" }).bytes().chain(list[m].operator.bytes()) {
                    if wl < who.len() {
                        who[wl] = b;
                        wl += 1;
                    }
                }
            }
            let who = core::str::from_utf8(&who[..wl]).unwrap_or("?");
            if r < 0 {
                println!("timekeeper: result: refused by the kernel: {} ({} operators: {}; {}.{:03} UTC +-{} ms)", strerror(r), n, who, date((t.max(0) / 1000) as u64, &mut d1), t.rem_euclid(1000), u);
                return Outcome::Refused;
            }
            if !loud {
                return Outcome::Set;
            }
            println!(
                "timekeeper: result: set from {} operators ({}): {}.{:03} UTC +-{} ms{}{}{}{}",
                n,
                who,
                date((t.max(0) / 1000) as u64, &mut d1),
                t.rem_euclid(1000),
                u,
                if r & TIME_SET_RAISED != 0 { "; last known good time raised" } else { "" },
                if r & TIME_SET_REPAIR != 0 { "; unreadable LKG file written anew" } else { "" },
                if r & TIME_SET_SAVED != 0 { "; saved" } else { "" },
                if r & TIME_SET_NOT_SAVED != 0 { "; LKG NOT saved" } else { "" }
            );
            Outcome::Set
        }
    }
}

/// The operator index of every entry (the first entry with the same operator_id).
fn operators(list: &[Entry], out: &mut [usize; MAX]) {
    for (i, e) in list.iter().enumerate() {
        out[i] = list.iter().position(|x| x.operator == e.operator).unwrap_or(i);
    }
}

#[cfg(selftest)]
mod test_list {
    use super::{Entry, MAX};
    /// tests/nts-server: the time service's servers, NTS-KE at 58600 + j.
    const fn e(j: u16, operator: &'static str) -> Entry {
        Entry { host: "tls.desoos", port: 58600 + j, operator }
    }
    /// The cases of NTS TEST (kernel/user/test_nts.rs).  The test CAs (tests/tls/ca.pem and
    /// nts-root.pem) are the only anchors.
    pub fn get(name: &str) -> Option<([Entry; MAX], usize)> {
        let none = e(0, "-");
        let t = |v: &[Entry]| {
            let mut a = [none; MAX];
            a[..v.len()].copy_from_slice(v);
            Some((a, v.len()))
        };
        match name {
            // Three operators, the third 30 s off.
            "three" => t(&[e(0, "alpha"), e(1, "beta"), e(4, "gamma")]),
            // Second check: a server certificate not valid yet / a time after the CA expired /
            // an intermediate that ends inside T +- U / an intermediate expired at T.
            "notyet" => t(&[e(7, "alpha"), e(0, "beta"), e(1, "gamma")]),
            "late" => t(&[e(10, "alpha"), e(0, "beta"), e(1, "gamma")]),
            "edge" => t(&[e(11, "alpha"), e(0, "beta"), e(1, "gamma")]),
            "intexpired" => t(&[e(12, "alpha"), e(0, "beta"), e(1, "gamma")]),
            // Refused in the first step: expired before B, a wrong name, another CA.
            "refused" => t(&[e(8, "alpha"), e(9, "beta"), e(0, "gamma")]),
            // The quorum.
            "one" => t(&[e(0, "alpha")]),
            "two" => t(&[e(0, "alpha"), e(1, "beta")]),
            "apart" => t(&[e(0, "alpha"), e(3, "beta")]),
            "disagree" => t(&[e(0, "alpha"), e(4, "beta")]),
            "sameop" => t(&[e(0, "alpha"), e(1, "alpha")]),
            "tie" => t(&[e(0, "alpha"), e(5, "beta"), e(6, "gamma")]),
            // NTS-KE that sends NTP to entry 0's server: still its own entry's vote.
            "redirect" => t(&[e(0, "alpha"), e(13, "alpha")]),
            // A chain ending at the test CA only (the CA expires 2045): for a bound above it.
            "rsa" => t(&[e(14, "alpha"), e(0, "beta"), e(1, "gamma")]),
            _ => None,
        }
    }
    pub const ROOTS: [&[u8]; 2] = [include_bytes!("../../tests/tls/nts-root.pem"), include_bytes!("../../tests/tls/ca.pem")];
}

/// `test:<case>` – the test list (self-test build only).
#[cfg(selftest)]
fn test_case(a: &str) -> Option<([Entry; MAX], usize)> {
    a.strip_prefix("test:").and_then(test_list::get)
}

#[cfg(not(selftest))]
fn test_case(_: &str) -> Option<([Entry; MAX], usize)> {
    None
}

/// The test CAs as DER (self-test build only).
#[cfg(selftest)]
fn test_roots(der: &mut [u8; 4096], spans: &mut [(usize, usize); 2]) -> bool {
    let mut at = 0;
    for (k, pem) in test_list::ROOTS.iter().enumerate() {
        let mut sp = [(0usize, 0usize); 1];
        if desotls::pem::certificates(pem, &mut der[at..], &mut sp) != Ok(1) {
            return false;
        }
        spans[k] = (at + sp[0].0, sp[0].1);
        at += sp[0].0 + sp[0].1;
    }
    true
}

/// Test mode: init has just started netd – wait for net0's DHCP address and point DNS at
/// tests/dns-stub.py (tls.desoos = the host).
#[cfg(selftest)]
fn test_network() -> bool {
    static mut REPLY: [u8; MSG_MAX] = [0; MSG_MAX];
    let ask = |req: &str| -> bool {
        let Ok(c) = svc_connect(CARD) else { return false };
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(REPLY) };
        let mut info = RecvInfo::default();
        let r = if chan_send(c, req.as_bytes(), 0) == 0 { chan_recv(c, buf, 0, &mut info) } else { -1 };
        close(c);
        let text = if r < 0 { "" } else { core::str::from_utf8(&buf[..r as usize]).unwrap_or("") };
        if req == "status" {
            text.lines().any(|l| l.starts_with("netd-status") && l.split_whitespace().any(|w| w == "dhcp=bound"))
        } else {
            text.starts_with("DNS server")
        }
    };
    let t = uptime_ms();
    while !ask("status") {
        if uptime_ms() - t > 10_000 {
            println!("timekeeper: test: net0 has no DHCP address after 10 s");
            return false;
        }
        sleep_ms(50);
    }
    ask("dns 10.0.2.2:53530")
}

#[cfg(not(selftest))]
fn test_network() -> bool {
    false
}

#[cfg(not(selftest))]
fn test_roots(_: &mut [u8; 4096], _: &mut [(usize, usize); 2]) -> bool {
    false
}

/// net0 has an address and a DNS server (netd's "status" – any client may ask).
fn network_ready() -> bool {
    static mut REPLY: [u8; MSG_MAX] = [0; MSG_MAX];
    let Ok(c) = svc_connect(CARD) else { return false };
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(REPLY) };
    let mut info = RecvInfo::default();
    let r = if chan_send(c, b"status", 0) == 0 { chan_recv(c, buf, 0, &mut info) } else { -1 };
    close(c);
    let text = if r < 0 { "" } else { core::str::from_utf8(&buf[..r as usize]).unwrap_or("") };
    let Some(line) = text.lines().find(|l| l.starts_with("netd-status")) else { return false };
    let set = |key: &str| line.split_whitespace().find_map(|w| w.strip_prefix(key)).is_some_and(|v| !v.starts_with("0.0.0.0"));
    set("ip=") && set("dns=")
}

fn main(args: Args) -> i32 {
    let case = match args.get(1) {
        None => None,
        Some(a) => match test_case(a) {
            Some(c) => Some(c),
            None => {
                eprintln!("timekeeper: takes no arguments (the servers are built in)");
                return 2;
            }
        },
    };
    let test = case.is_some();
    let (entries, n) = case.unwrap_or((IMAGE, IMAGE.len()));
    let list = &entries[..n];
    if !matches!(handle_info(SETTIME), Ok((k, _)) if k == KIND_SETTIME) {
        eprintln!("timekeeper: no SETTIME handle in slot 7 - start it as init's time service (grant settime)");
        return 2;
    }
    // The anchors: the CA store from init (slot 8), or the test CAs.
    let store = unsafe { &mut *core::ptr::addr_of_mut!(STORE) };
    let mut test_der = [0u8; 4096];
    let mut test_spans = [(0usize, 0usize); 2];
    let roots;
    let test_anchors: [&[u8]; 2];
    let list_anchors;
    let anchors: &dyn Anchors = if test {
        if !test_roots(&mut test_der, &mut test_spans) {
            eprintln!("timekeeper: the test CAs are unreadable");
            return 2;
        }
        test_anchors = [&test_der[test_spans[0].0..test_spans[0].0 + test_spans[0].1], &test_der[test_spans[1].0..test_spans[1].0 + test_spans[1].1]];
        list_anchors = desotls::roots::AnchorList(&test_anchors);
        &list_anchors
    } else {
        let mut n = 0;
        loop {
            let r = read(ROOTS_SLOT, &mut store[n..]);
            if r < 0 {
                eprintln!("timekeeper: the CA store (slot 8, grant roots): {}", strerror(r));
                return 2;
            }
            if r == 0 {
                break;
            }
            n += r as usize;
            if n == store.len() {
                eprintln!("timekeeper: the CA store is too big");
                return 2;
            }
        }
        roots = match Roots::parse(&store[..n]) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("timekeeper: the CA store: {}", e.as_str());
                return 2;
            }
        };
        &roots
    };
    let mut ops = [0usize; MAX];
    operators(list, &mut ops);
    let mut src = [const { Source::new() }; MAX];
    if test {
        if !test_network() {
            return 2;
        }
        return round(list, &ops[..list.len()], &mut src[..list.len()], anchors, None) as i32;
    }
    // Messages of the NTS-KE code go to stderr: the service has only the console in slot 1.
    dup2(1, 2);
    println!("timekeeper: started - NTS servers: {} ({}), {} ({}), {} ({})", IMAGE[0].host, IMAGE[0].operator, IMAGE[1].host, IMAGE[1].operator, IMAGE[2].host, IMAGE[2].operator);
    let mut last: Option<Outcome> = None;
    loop {
        let t0 = uptime_ms();
        let mut told = false;
        while !network_ready() {
            if !told && uptime_ms() - t0 > 60_000 {
                println!("timekeeper: waiting for net0 to get an address and a DNS server");
                told = true;
            }
            sleep_ms(1000);
        }
        let out = round(list, &ops[..list.len()], &mut src[..list.len()], anchors, last);
        last = Some(out);
        let now = uptime_ms();
        let wait = if out == Outcome::Set {
            RESYNC_MS
        } else {
            // The next NTS-KE the backoff allows, at the latest in a minute.
            let mut next = now + RETRY_MS;
            for s in src.iter() {
                if !s.keyed {
                    next = next.min(s.backoff.next.max(now + 1000));
                }
            }
            next - now
        };
        sleep_ms(wait);
    }
}
