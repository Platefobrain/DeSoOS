// nettime [-t ms] [server[:port] ...] [netN] – asks one to four NTP servers (default:
// time.cloudflare.com) what time it is and tells how far this machine's clock is from the
// answer.  The clock is what `date` shows: the RTC as read at boot plus the time since
// (whole seconds).  It reads only: plain NTP is not authenticated, so nothing here sets
// the RTC or the clock, changes whether the clock counts as plausible, or raises any
// lower bound for it.  Exit code 0
// means "a well-formed answer came", not "the time is trusted".
//
// All servers are asked at once, each over its own UDP socket of netd (the "udp" right);
// an answer is waited for -t ms (100-10000, default 2000), then the query is sent once
// more with a new random Transmit value (an answer to the first one is no longer taken) –
// so the whole run takes at most 2 x -t however many servers.  A wrong answer (see
// user/lib/ntp.rs) is skipped and the wait goes on; a Kiss-o'-Death ends the questions to
// that server.  At most 2 packets per server.
//
// With two to four servers: every answer, the median, and who is more than 2 s from it.
//
// Exit code: 0 = at least one good answer, 2 = usage, no udp right, unknown name, no
// random numbers, 3 = no good answer (silence, everything refused, Kiss-o'-Death),
// 4 = three or more answered and fewer than half are within 2 s of the median.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../lib/ntp.rs"]
mod ntp;

use desoos::*;

entry!(main);

const DEFAULT_SERVER: &str = "time.cloudflare.com";
const MAX_SERVERS: usize = 4;
/// Further than this from the median (ms): "disagrees".
const AGREE_MS: i64 = 2000;

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
    last: Option<ntp::Reject>,
    state: State,
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
    eprintln!("usage: nettime [-t ms] [server[:port] ...] [net0]  (1-4 servers, default {}; -t: 100-10000 ms)", DEFAULT_SERVER);
    2
}

/// "netN": the card's service name.
fn is_card(a: &str) -> bool {
    a.len() > 3 && a.starts_with("net") && a[3..].bytes().all(|b| b.is_ascii_digit())
}

/// A new query to the server: fresh random Transmit, the time, the deadline.  Err = no
/// random numbers (the caller gives up: no weaker stand-in).
fn ask(s: &mut Server, wait_ms: u64) -> Result<(), i64> {
    let mut r = [0u8; 8];
    getrandom(&mut r)?;
    s.xmit = u64::from_be_bytes(r);
    s.tries += 1;
    s.sent_ms = uptime_ms();
    s.deadline = s.sent_ms + wait_ms;
    if udp_send(s.chan, &ntp::build_query(s.xmit)) != 0 {
        s.state = State::Failed("could not send");
    }
    Ok(())
}

/// A difference in ms as whole seconds (half a second away from zero, both signs).
fn whole_secs(ms: i64) -> i64 {
    ntp::round_secs(ms)
}

fn main(args: Args) -> i32 {
    let mut i = 1;
    let mut wait_ms: u64 = 2000;
    if args.get(1) == Some("-t") {
        // Digits only: "2000abc", "-5", "" and numbers too long for u64 fail the parse.
        match args.get(2).filter(|t| t.bytes().all(|b| b.is_ascii_digit())).and_then(|t| t.parse::<u64>().ok()).filter(|t| (100..=10_000).contains(t)) {
            Some(t) => wait_ms = t,
            None => return usage(),
        }
        i = 3;
    }
    let mut n_args = args.len();
    let mut card = "net0";
    if n_args > i {
        if let Some(a) = args.get(n_args - 1).filter(|a| is_card(a)) {
            card = a;
            n_args -= 1;
        }
    }
    let blank = Server { name: DEFAULT_SERVER, port: ntp::PORT, chan: 0, addr: [0; 24], addr_len: 0, xmit: 0, sent_ms: 0, deadline: 0, tries: 0, ignored: 0, last: None, state: State::NoSocket };
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
            None => (a, ntp::PORT),
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
    let Ok(clock) = time_unix() else {
        eprintln!("nettime: cannot read the clock");
        return 2;
    };

    // Sockets (netd resolves the name), then all the queries at once.
    let mut opened = 0;
    for s in servers.iter_mut() {
        let mut reply = [0u8; 256];
        match udp_open_via(SVC, card, s.name, s.port, &mut reply) {
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
            Err(k) => eprintln!("nettime: {}: {}", s.name, core::str::from_utf8(&reply[..k]).unwrap_or("?").trim()),
        }
    }
    if opened == 0 {
        return 2;
    }
    for s in servers.iter_mut().filter(|s| matches!(s.state, State::Waiting)) {
        if let Err(e) = ask(s, wait_ms) {
            eprintln!("nettime: no random numbers for the query ({}) - nothing sent", strerror(e));
            return 2;
        }
    }

    let mut buf = [0u8; MSG_MAX];
    let mut info = RecvInfo::default();
    loop {
        // Deadlines: one more query with a new Transmit value, then give up.
        let now = uptime_ms();
        for s in servers.iter_mut().filter(|s| matches!(s.state, State::Waiting)) {
            if now >= s.deadline {
                if s.tries < 2 {
                    if let Err(e) = ask(s, wait_ms) {
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
            let s = &mut servers[who[e]];
            let r = chan_recv(s.chan, &mut buf, CHAN_NONBLOCK, &mut info);
            let received = uptime_ms();
            if r == ERROR_WOULD_BLOCK {
                continue;
            }
            if r < 0 {
                s.state = State::Failed("the socket was closed (address changed?)");
                continue;
            }
            match ntp::check_reply(&buf[..r as usize], s.xmit) {
                Ok(ntp::Answer::Kod(kod)) => s.state = State::Kod(kod),
                Ok(ntp::Answer::Time(reply)) => match ntp::delay_ms(&reply, s.sent_ms, received) {
                    Ok(delay) => {
                        // The clock right now, for the comparison (never written).
                        let rtc = time_unix().map(|c| c.secs).unwrap_or(clock.secs);
                        s.state = State::Good { stratum: reply.stratum, delay, server_ms: ntp::server_time_ms(&reply, delay, clock.build_epoch), rtc };
                    }
                    Err(why) => {
                        s.ignored += 1;
                        s.last = Some(why);
                    }
                },
                Err(why) => {
                    s.ignored += 1;
                    s.last = Some(why);
                }
            }
        }
    }
    for s in servers.iter() {
        if s.chan != 0 {
            close(s.chan);
        }
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
    for s in servers.iter() {
        match s.state {
            State::NoSocket => {}
            State::Waiting => {}
            State::Good { stratum, delay, server_ms, .. } => {
                let o = s.offset_ms().unwrap_or(0);
                let off = if good > 1 && (o - center).abs() > AGREE_MS { " - disagrees with the median" } else { "" };
                println!(
                    "nettime: {} ({}): stratum {}, delay {} ms, server time {}.{:03} UTC, clock {:+} s{}",
                    s.name,
                    s.addr(),
                    stratum,
                    delay,
                    format_utc_signed(server_ms.div_euclid(1000), &mut date),
                    server_ms.rem_euclid(1000),
                    whole_secs(o),
                    off
                );
            }
            State::Kod(kod) => eprintln!("nettime: {} ({}): kiss-o'-death {} - not asked again, no time taken from it", s.name, s.addr(), kod.as_str()),
            State::Failed(why) => eprintln!("nettime: {} ({}): {} ({} quer{} of {} ms)", s.name, s.addr(), why, s.tries, if s.tries == 1 { "y" } else { "ies" }, wait_ms),
        }
        if s.ignored > 0 {
            eprintln!("nettime: {} ({}): {} answer(s) ignored (the last: {})", s.name, s.addr(), s.ignored, s.last.map_or("?", ntp::Reject::as_str));
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
    println!(" (the clock counts whole seconds; path asymmetry bound +-{} ms) - not changed: plain NTP is not authenticated", (delay + 1) / 2);
    if clock.status != 0 {
        println!("nettime: the clock counts as not plausible ({}) - this answer does not change that", clock_reason(clock.status));
    }
    0
}
