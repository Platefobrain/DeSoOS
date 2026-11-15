// nettime [-t ms] [--nts [--anchor ca.pem]] [server[:port] ...] [netN] – asks one to four
// NTP servers (default: time.cloudflare.com) what time it is and tells how far this
// machine's clock is from the answer.  The clock is what `date` shows: the RTC as read at
// boot plus the time since (whole seconds).  It reads only: nothing here sets the RTC or the
// clock, changes whether the clock counts as plausible, or raises any lower bound for it –
// also not with --nts (only the time service may, v0.79 stage D).  Exit code 0 means "a
// well-formed answer came", not "the time is trusted".
//
// Plain NTP (user/lib/ntp.rs): all servers are asked at once, each over its own UDP socket
// of netd (the "udp" right); an answer is waited for -t ms (100-10000, default 2000), then
// the query is sent once more with a new random Transmit value (an answer to the first one
// is no longer taken) – so the whole run takes at most 2 x -t however many servers.  A
// wrong answer is skipped and the wait goes on; a Kiss-o'-Death ends the questions to that
// server.  At most 2 packets per server.
//
// --nts (RFC 8915, user/lib/nts.rs): first, one server after the other, NTS-KE – TCP to
// server[:port] (default port 4460, the "net" right), TLS 1.3 with DeSoTLS, ALPN "ntske/1",
// the server's certificate checked against /etc/certs/roots (or only the CA in --anchor) at
// the wall clock's time: a clock that is not plausible refuses before anything is sent (the
// way out of that – the time service, stage D).  The keys come from the TLS exporter, the
// cookies and the NTP server (Server / Port Negotiation, otherwise the KE server and 123)
// from the KE records.  Then NTP exactly as above, but every query carries a fresh Unique
// Identifier, an unused cookie and the Authenticator, and an answer counts only when it is
// authenticated; an NTS NAK uses the retry with the next cookie.  The result says
// "authenticated (NTS)" – and still changes nothing.
//
// With two to four servers: every answer, the median, and who is more than 2 s from it.
//
// Exit code: 0 = at least one good answer, 2 = usage, no udp / net right, unknown name, no
// random numbers, --nts with a clock that is not plausible or without the CA store,
// 3 = no good answer (silence, everything refused, Kiss-o'-Death, NTS-KE failed),
// 4 = three or more answered and fewer than half are within 2 s of the median.
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

use desoos::*;
use desotls::client::{Client, Config};
use desotls::record::Suite;
use desotls::roots::{AnchorList, Anchors, Roots};

entry!(main);

const DEFAULT_SERVER: &str = "time.cloudflare.com";
const MAX_SERVERS: usize = 4;
/// Further than this from the median (ms): "disagrees".
const AGREE_MS: i64 = 2000;
const ROOTS: &str = "/etc/certs/roots";
const STORE_MAX: usize = 256 * 1024;
const ANCHOR_MAX: usize = 16 * 1024;

static mut TLS: Client = Client::new();
static mut STORE: [u8; STORE_MAX] = [0; STORE_MAX];
static mut ANCHOR_FILE: [u8; ANCHOR_MAX] = [0; ANCHOR_MAX];
static mut ANCHOR_DER: [u8; ANCHOR_MAX] = [0; ANCHOR_MAX];
static mut CHAN_BUF: [u8; MSG_MAX] = [0; MSG_MAX];
static mut KE_BUF: [u8; nts::KE_MAX + 4096] = [0; nts::KE_MAX + 4096];
static mut POOLS: [nts::Pool; MAX_SERVERS] = [const { nts::Pool::new() }; MAX_SERVERS];

#[derive(Clone, Copy)]
enum State {
    /// The socket could not be opened (told already).
    NoSocket,
    Waiting,
    Good { stratum: u8, delay: u64, server_ms: i64, rtc: u64 },
    Kod(ntp::Kod),
    Failed(&'static str),
}

#[derive(Clone, Copy)]
struct Server {
    name: &'static str,
    port: u16,
    chan: u64,
    addr: [u8; 24],
    addr_len: usize,
    xmit: u64,
    sent_ms: u64,
    deadline: u64,
    tries: u32,
    ignored: u32,
    last: Option<&'static str>,
    state: State,
    /// --nts: the keys, the Unique Identifier of the query out, NTS NAKs seen.
    nts: bool,
    c2s: [u8; 32],
    s2c: [u8; 32],
    uid: [u8; nts::UID_LEN],
    naks: u32,
}

impl Server {
    fn addr(&self) -> &str {
        core::str::from_utf8(&self.addr[..self.addr_len]).unwrap_or("?")
    }

    /// The clock minus the server's time, ms (the clock counts whole seconds: taken at
    /// the middle of its second).
    fn offset_ms(&self) -> Option<i64> {
        match self.state {
            State::Good { server_ms, rtc, .. } => Some(rtc as i64 * 1000 + 500 - server_ms),
            _ => None,
        }
    }
}

fn usage() -> i32 {
    eprintln!("usage: nettime [-t ms] [--nts [--anchor ca.pem]] [server[:port] ...] [net0]  (1-4 servers, default {}; -t: 100-10000 ms; --nts: port = NTS-KE, default 4460)", DEFAULT_SERVER);
    2
}

/// "netN": the card's service name.
fn is_card(a: &str) -> bool {
    a.len() > 3 && a.starts_with("net") && a[3..].bytes().all(|b| b.is_ascii_digit())
}

fn read_file(path: &str, buf: &mut [u8]) -> Result<usize, i64> {
    let fd = open(path, O_READ);
    if fd < 0 {
        return Err(fd);
    }
    let mut n = 0;
    loop {
        if n == buf.len() {
            close(fd as u64);
            return Err(ERROR_NO_SPACE);
        }
        let r = read(fd as u64, &mut buf[n..]);
        if r < 0 {
            close(fd as u64);
            return Err(r);
        }
        if r == 0 {
            close(fd as u64);
            return Ok(n);
        }
        n += r as usize;
    }
}

/// A new query to the server: fresh random Transmit (and for NTS a fresh Unique Identifier,
/// nonce and an unused cookie), the time, the deadline.  Err = no random numbers (the caller
/// gives up: no weaker stand-in).
fn ask(s: &mut Server, pool: &mut nts::Pool, wait_ms: u64) -> Result<(), i64> {
    let mut r = [0u8; 8 + nts::UID_LEN + nts::NONCE_LEN];
    getrandom(&mut r)?;
    s.xmit = u64::from_be_bytes([r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]]);
    s.tries += 1;
    s.sent_ms = uptime_ms();
    s.deadline = s.sent_ms + wait_ms;
    if !s.nts {
        if udp_send(s.chan, &ntp::build_query(s.xmit)) != 0 {
            s.state = State::Failed("could not send");
        }
        return Ok(());
    }
    s.uid.copy_from_slice(&r[8..8 + nts::UID_LEN]);
    let mut nonce = [0u8; nts::NONCE_LEN];
    nonce.copy_from_slice(&r[8 + nts::UID_LEN..]);
    // The cookie leaves the pool now – it is never sent twice, answer or not.
    let Some(cookie) = pool.take() else {
        s.state = State::Failed("no NTS cookie left (a new NTS-KE is needed)");
        return Ok(());
    };
    let Some(p) = nts::placeholders(pool.n, cookie.len, nts::REQUEST_LIMIT) else {
        s.state = State::Failed("NTS cookie too long for one packet");
        return Ok(());
    };
    let mut pkt = [0u8; nts::REQUEST_MAX];
    match nts::build_request(&mut pkt, s.xmit, &s.uid, &cookie, p, &nonce, &s.c2s) {
        Ok(n) => {
            if udp_send(s.chan, &pkt[..n]) != 0 {
                s.state = State::Failed("could not send");
            }
        }
        Err(()) => s.state = State::Failed("could not build the NTS request"),
    }
    Ok(())
}

/// NTS-KE with one server (user/lib/ntske.rs): keys, cookies (into `pool`) and where NTP
/// goes.  Err – what to tell (the server is then left out).
fn key_exchange(s: &mut Server, pool: &mut nts::Pool, card: &str, anchors: &dyn Anchors, now: i64, wait_ms: u64) -> Result<nts::Negotiated, &'static str> {
    let suites = [Suite::Aes128Gcm, Suite::Chacha20Poly1305];
    let cfg = Config { host: s.name, anchors, now, suites: &suites, alpn: Some(nts::ALPN), bootstrap: None };
    let buf = ntske::Buffers {
        tls: unsafe { &mut *core::ptr::addr_of_mut!(TLS) },
        msg: unsafe { &mut *core::ptr::addr_of_mut!(CHAN_BUF) },
        ke: unsafe { &mut *core::ptr::addr_of_mut!(KE_BUF) },
    };
    let mut done = ntske::key_exchange("nettime", true, &cfg, s.port, card, pool, wait_ms, buf, &mut s.addr, &mut s.addr_len, None)?;
    s.c2s = done.c2s;
    s.s2c = done.s2c;
    done.wipe();
    Ok(done.neg)
}

/// A difference in ms as whole seconds (half a second away from zero, both signs).
fn whole_secs(ms: i64) -> i64 {
    ntp::round_secs(ms)
}

/// "-t ms": digits only ("2000abc", "-5", "" and numbers too long for u64 fail the parse).
fn parse_ms(t: Option<&str>) -> Option<u64> {
    t.filter(|t| t.bytes().all(|b| b.is_ascii_digit())).and_then(|t| t.parse::<u64>().ok()).filter(|t| (100..=10_000).contains(t))
}

fn main(args: Args) -> i32 {
    let mut i = 1;
    let mut wait_ms: u64 = 2000;
    let mut use_nts = false;
    let mut anchor: Option<&str> = None;
    loop {
        match args.get(i) {
            Some("-t") => {
                match parse_ms(args.get(i + 1)) {
                    Some(t) => wait_ms = t,
                    None => return usage(),
                }
                i += 2;
            }
            Some("--nts") => {
                use_nts = true;
                i += 1;
            }
            Some("--anchor") => {
                match args.get(i + 1).filter(|a| !a.is_empty()) {
                    Some(a) => anchor = Some(a),
                    None => return usage(),
                }
                i += 2;
            }
            _ => break,
        }
    }
    if anchor.is_some() && !use_nts {
        return usage();
    }
    let mut n_args = args.len();
    let mut card = "net0";
    if n_args > i {
        if let Some(a) = args.get(n_args - 1).filter(|a| is_card(a)) {
            card = a;
            n_args -= 1;
        }
    }
    let default_port = if use_nts { nts::KE_PORT } else { ntp::PORT };
    let blank = Server {
        name: DEFAULT_SERVER,
        port: default_port,
        chan: 0,
        addr: [0; 24],
        addr_len: 0,
        xmit: 0,
        sent_ms: 0,
        deadline: 0,
        tries: 0,
        ignored: 0,
        last: None,
        state: State::NoSocket,
        nts: use_nts,
        c2s: [0; 32],
        s2c: [0; 32],
        uid: [0; nts::UID_LEN],
        naks: 0,
    };
    let mut servers = [blank; MAX_SERVERS];
    let mut n = 0;
    while i < n_args {
        let Some(a) = args.get(i) else { return usage() };
        if n == MAX_SERVERS || a.is_empty() || a.starts_with('-') {
            return usage();
        }
        let (name, port) = match a.rsplit_once(':') {
            Some((h, p)) => match Some(p).filter(|p| !h.is_empty() && p.bytes().all(|b| b.is_ascii_digit())).and_then(|p| p.parse::<u16>().ok()).filter(|&p| p != 0) {
                Some(p) => (h, p),
                None => return usage(),
            },
            None => (a, default_port),
        };
        servers[n].name = name;
        servers[n].port = port;
        n += 1;
        i += 1;
    }
    if n == 0 {
        n = 1;
    }
    let servers = &mut servers[..n];
    let pools = unsafe { &mut *core::ptr::addr_of_mut!(POOLS) };
    let Ok(clock) = time_unix() else {
        eprintln!("nettime: cannot read the clock");
        return 2;
    };

    // --nts: the clock and the trusted CAs first, then NTS-KE with each server.
    let store_buf = unsafe { &mut *core::ptr::addr_of_mut!(STORE) };
    let anchor_der = unsafe { &mut *core::ptr::addr_of_mut!(ANCHOR_DER) };
    let mut anchor_len = 0;
    let mut store_len = 0;
    if use_nts {
        if !clock.plausible() {
            eprintln!("nettime: NTS refused: clock not plausible: {} - the certificate of an NTS-KE server cannot be checked; nothing sent", clock_reason(clock.status));
            return 2;
        }
        match anchor {
            Some(p) => {
                let file = unsafe { &mut *core::ptr::addr_of_mut!(ANCHOR_FILE) };
                let k = match read_file(p, file) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("nettime: {}: {}", p, strerror(e));
                        return 2;
                    }
                };
                let mut spans = [(0usize, 0usize); 1];
                match desotls::pem::certificates(&file[..k], anchor_der, &mut spans) {
                    Ok(1) => anchor_len = spans[0].1,
                    _ => {
                        eprintln!("nettime: {}: not one certificate", p);
                        return 2;
                    }
                }
            }
            None => match read_file(ROOTS, store_buf) {
                Ok(k) => store_len = k,
                Err(e) => {
                    eprintln!("nettime: NTS refused: trusted CA store missing or damaged ({}: {})", ROOTS, strerror(e));
                    return 2;
                }
            },
        }
    }
    let store = if use_nts && anchor.is_none() {
        match Roots::parse(&store_buf[..store_len]) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("nettime: NTS refused: {}", e.as_str());
                return 2;
            }
        }
    } else {
        None
    };
    let one: [&[u8]; 1] = [&anchor_der[..anchor_len]];
    let list = AnchorList(&one);
    let anchors: &dyn Anchors = match &store {
        Some(r) => r,
        None => &list,
    };

    // Sockets (netd resolves the name), then all the queries at once.
    let mut opened = 0;
    for (j, s) in servers.iter_mut().enumerate() {
        // Where NTP goes: the server itself, or (NTS) what NTS-KE negotiated – its Server
        // Negotiation or else the KE server's address, its port or else 123.
        let mut host = [0u8; 253];
        let mut hl = s.name.len().min(host.len());
        host[..hl].copy_from_slice(&s.name.as_bytes()[..hl]);
        let mut port = s.port;
        if use_nts {
            match key_exchange(s, &mut pools[j], card, anchors, clock.secs as i64, wait_ms) {
                Ok(neg) => {
                    if neg.server_len > 0 {
                        hl = neg.server_len;
                        host[..hl].copy_from_slice(&neg.server[..hl]);
                    } else {
                        hl = s.addr_len;
                        host[..hl].copy_from_slice(&s.addr[..hl]);
                    }
                    port = neg.port;
                }
                Err(why) => {
                    s.state = State::Failed(why);
                    continue;
                }
            }
        }
        let host = core::str::from_utf8(&host[..hl]).unwrap_or("?");
        let mut reply = [0u8; 256];
        match udp_open_via(SVC, card, host, port, &mut reply) {
            Ok(c) => {
                // "udp a.b.c.d:port from ..."
                let text = core::str::from_utf8(&reply).unwrap_or("");
                let ip = text.strip_prefix("udp ").and_then(|t| t.split(':').next()).unwrap_or("?");
                s.addr_len = ip.len().min(s.addr.len());
                s.addr[..s.addr_len].copy_from_slice(&ip.as_bytes()[..s.addr_len]);
                s.chan = c;
                s.state = State::Waiting;
                opened += 1;
            }
            Err(k) => {
                eprintln!("nettime: {}: {}", s.name, core::str::from_utf8(&reply[..k]).unwrap_or("?").trim());
                if use_nts {
                    s.state = State::Failed("NTP server from NTS-KE not reachable");
                }
            }
        }
    }
    if opened == 0 && !use_nts {
        return 2;
    }
    for (j, s) in servers.iter_mut().enumerate() {
        if matches!(s.state, State::Waiting) {
            if let Err(e) = ask(s, &mut pools[j], wait_ms) {
                eprintln!("nettime: no random numbers for the query ({}) - nothing sent", strerror(e));
                return 2;
            }
        }
    }

    let mut buf = [0u8; MSG_MAX];
    let mut info = RecvInfo::default();
    loop {
        // Deadlines: one more query with a new Transmit value, then give up.
        let now = uptime_ms();
        for (j, s) in servers.iter_mut().enumerate() {
            if matches!(s.state, State::Waiting) && now >= s.deadline {
                if s.tries < 2 {
                    if let Err(e) = ask(s, &mut pools[j], wait_ms) {
                        eprintln!("nettime: no random numbers for the query ({}) - nothing sent", strerror(e));
                        return 2;
                    }
                } else {
                    s.state = State::Failed("no answer");
                }
            }
        }
        let mut list = [(0u64, 0u64); MAX_SERVERS];
        let mut who = [0usize; MAX_SERVERS];
        let mut k = 0;
        let mut next = u64::MAX;
        for (j, s) in servers.iter().enumerate() {
            if matches!(s.state, State::Waiting) {
                list[k] = (s.chan, W_READABLE);
                who[k] = j;
                k += 1;
                next = next.min(s.deadline);
            }
        }
        if k == 0 {
            break;
        }
        let ready = wait_many(&list[..k], next.saturating_sub(uptime_ms()).max(1)).unwrap_or(0);
        for e in 0..k {
            if ready & (1 << e) == 0 {
                continue;
            }
            let j = who[e];
            let s = &mut servers[j];
            let r = chan_recv(s.chan, &mut buf, CHAN_NONBLOCK, &mut info);
            let received = uptime_ms();
            if r == ERROR_WOULD_BLOCK {
                continue;
            }
            if r < 0 {
                s.state = State::Failed("the socket was closed (address changed?)");
                continue;
            }
            let data = &buf[..r as usize];
            let answer = if s.nts {
                match nts::check_response(data, s.xmit, &s.uid, &s.s2c, &mut pools[j]) {
                    Ok(nts::Answer::Time { reply, .. }) => Ok(ntp::Answer::Time(reply)),
                    Ok(nts::Answer::Nak) => {
                        // The server did not take our cookie: the retry with the next one
                        // now (RFC 8915 §5.7); after that, a new NTS-KE would be needed.
                        s.naks += 1;
                        if s.tries < 2 {
                            if let Err(e) = ask(s, &mut pools[j], wait_ms) {
                                eprintln!("nettime: no random numbers for the query ({}) - nothing sent", strerror(e));
                                return 2;
                            }
                        } else {
                            s.state = State::Failed("NTS NAK - the server did not take the cookie (a new NTS-KE is needed)");
                        }
                        continue;
                    }
                    Err(why) => Err(why.as_str()),
                }
            } else {
                ntp::check_reply(data, s.xmit).map_err(ntp::Reject::as_str)
            };
            match answer {
                Ok(ntp::Answer::Kod(kod)) => s.state = State::Kod(kod),
                Ok(ntp::Answer::Time(reply)) => match ntp::delay_ms(&reply, s.sent_ms, received) {
                    Ok(delay) => {
                        // The clock right now, for the comparison (never written).
                        let rtc = time_unix().map(|c| c.secs).unwrap_or(clock.secs);
                        s.state = State::Good { stratum: reply.stratum, delay, server_ms: ntp::server_time_ms(&reply, delay, clock.build_epoch), rtc };
                    }
                    Err(why) => {
                        s.ignored += 1;
                        s.last = Some(why.as_str());
                    }
                },
                Err(why) => {
                    s.ignored += 1;
                    s.last = Some(why);
                }
            }
        }
    }
    for s in servers.iter_mut() {
        if s.chan != 0 {
            close(s.chan);
        }
        desocrypto::wipe(&mut s.c2s);
        desocrypto::wipe(&mut s.s2c);
    }
    for p in pools.iter_mut() {
        p.clear();
    }

    // What every server said.
    let mut offsets = [0i64; MAX_SERVERS];
    let mut good = 0;
    for s in servers.iter() {
        if let Some(o) = s.offset_ms() {
            offsets[good] = o;
            good += 1;
        }
    }
    let center = ntp::median(&mut offsets[..good]);
    let agree = ntp::agreeing(&offsets[..good], center, AGREE_MS);
    let mut date = [0u8; 19];
    let auth = if use_nts { ", authenticated (NTS)" } else { "" };
    for s in servers.iter() {
        match s.state {
            State::NoSocket => {}
            State::Waiting => {}
            State::Good { stratum, delay, server_ms, .. } => {
                let o = s.offset_ms().unwrap_or(0);
                let off = if good > 1 && (o - center).abs() > AGREE_MS { " - disagrees with the median" } else { "" };
                println!(
                    "nettime: {} ({}): stratum {}, delay {} ms, server time {}.{:03} UTC, clock {:+} s{}{}",
                    s.name,
                    s.addr(),
                    stratum,
                    delay,
                    format_utc_signed(server_ms.div_euclid(1000), &mut date),
                    server_ms.rem_euclid(1000),
                    whole_secs(o),
                    auth,
                    off
                );
            }
            State::Kod(kod) => eprintln!("nettime: {} ({}): kiss-o'-death {} - not asked again, no time taken from it", s.name, s.addr(), kod.as_str()),
            State::Failed(why) => {
                // No address (NTS-KE failed before one was known) – no "()"; nothing sent – no
                // "(0 queries ...)".
                use core::fmt::Write;
                let mut line = Out::new(2);
                let _ = write!(line, "nettime: {}", s.name);
                if s.addr_len > 0 {
                    let _ = write!(line, " ({})", s.addr());
                }
                let _ = write!(line, ": {}", why);
                if s.tries > 0 {
                    let _ = write!(line, " ({} quer{} of {} ms)", s.tries, if s.tries == 1 { "y" } else { "ies" }, wait_ms);
                }
                let _ = line.write_str("\n");
            }
        }
        if s.naks > 0 {
            eprintln!("nettime: {} ({}): {} NTS NAK(s)", s.name, s.addr(), s.naks);
        }
        if s.ignored > 0 {
            eprintln!("nettime: {} ({}): {} answer(s) ignored (the last: {})", s.name, s.addr(), s.ignored, s.last.unwrap_or("?"));
        }
    }
    if good == 0 {
        eprintln!("nettime: no usable answer - the clock was not compared (and never changed)");
        return 3;
    }
    if ntp::disagree(good, agree) {
        println!("nettime: the servers do not agree (only {} of {} within 2 s of the median) - no verdict; clock not changed", agree, good);
        return 4;
    }
    if good == 2 && agree < 2 {
        println!("nettime: the 2 servers differ by {} s - two cannot settle which is right; clock not changed", whole_secs((offsets[1] - offsets[0]).abs()));
        return 0;
    }
    // The server at the median: the clock's reading and its delay for the summary.
    let Some(m) = servers.iter().find(|s| s.offset_ms() == Some(center)) else { return 0 };
    let State::Good { delay, rtc, .. } = m.state else { return 0 };
    let against = if good == 1 { ntp::Against::Server(m.name) } else { ntp::Against::Median(good) };
    print!("nettime: the clock ({} UTC) {}", format_utc(rtc, &mut date), ntp::OffsetText { ms: center, against });
    if use_nts {
        println!(" (the clock counts whole seconds; path asymmetry bound +-{} ms) - authenticated (NTS), but not changed: only the time service may set the clock", (delay + 1) / 2);
    } else {
        println!(" (the clock counts whole seconds; path asymmetry bound +-{} ms) - not changed: plain NTP is not authenticated", (delay + 1) / 2);
    }
    if clock.status != 0 {
        println!("nettime: the clock counts as not plausible ({}) - this answer does not change that", clock_reason(clock.status));
    }
    0
}
