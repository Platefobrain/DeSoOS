// DHCP client state machine (RFC 2131) – pure code: no clock, no card, no
// allocation.  The caller (netd) passes the time in, sends the messages it
// returns and applies the events.  That way every path – lost answers, NAK,
// renewal, rebinding with another server, lease end – is tested without waiting
// for real timers: /bin/dhcptest (NET TEST).
//
//   Selecting  --OFFER-->  Requesting  --ACK-->  Checking  --no answer-->  Bound
//                                                  | someone has the address (ARP):
//                                                  +-- DECLINE, start over after 10 s
//      ^  DISCOVER (1, 2, 4, 8, 16, 16... s)  |     | T1 (half the lease)
//      |                                       |     v
//      +------ NAK / 4 REQUESTs unanswered ----+  Renewing (REQUEST to the server)
//      |                                             | T2 (7/8 of the lease)
//      +------------- lease end / NAK -----------  Rebinding (REQUEST to everyone)
//
// Messages from servers are untrusted: a reply must carry our transaction id
// and MAC, the offered address must be a single-machine address, a server
// identifier is required in an offer, and the gateway is used only when it is
// on the leased subnet.  Very short leases are stretched to 30 s so a server
// cannot make us send in a loop.
//
// Checking (RFC 5227, shortened): before an offered address is used, the caller
// sends ARP probes for it (Event::Probe, twice, 300 ms apart); if another machine
// answers, the caller reports `conflict` – DECLINE to the server, a new attempt
// after 10 s.  `release` gives the address back (RELEASE) and stops the client
// (State::Off – an address set by hand); `start` asks again.
#![allow(dead_code)]

use crate::netproto::*;

pub const BROADCAST_IP: [u8; 4] = [255; 4];
/// Lease value meaning "forever".
pub const INFINITE: u32 = u32::MAX;
const MIN_LEASE_S: u32 = 30;
const DEFAULT_LEASE_S: u32 = 3600;
const DISCOVER_FIRST_MS: u64 = 1000;
const DISCOVER_MAX_MS: u64 = 16_000;
/// REQUESTs after an offer before starting over.
const REQUEST_TRIES: u32 = 4;
/// Renewing / rebinding: resend after half the remaining time, but not more
/// often than this (RFC 2131 4.4.5).
const RENEW_MIN_MS: u64 = 60_000;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum State {
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    /// An ACK came; the address is being checked with ARP probes.
    Checking,
    /// Stopped (an address set by hand, or released).
    Off,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Selecting => "selecting",
            State::Requesting => "requesting",
            State::Bound => "bound",
            State::Renewing => "renewing",
            State::Rebinding => "rebinding",
            State::Checking => "checking",
            State::Off => "off",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Lease {
    pub ip: [u8; 4],
    pub prefix: u8,
    pub gw: Option<[u8; 4]>,
    pub dns: [[u8; 4]; 2],
    pub dns_n: u8,
    pub server: [u8; 4],
    /// Seconds as granted (INFINITE = forever; short leases already stretched).
    pub lease_s: u32,
    /// Times in ms (the caller's clock); u64::MAX for a lease without end.
    pub start_ms: u64,
    pub t1_ms: u64,
    pub t2_ms: u64,
    pub end_ms: u64,
}

/// A message for the caller to send (from 0.0.0.0 while `ciaddr` is 0).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Msg {
    pub kind: u8,
    pub xid: u32,
    pub ciaddr: [u8; 4],
    pub requested: Option<[u8; 4]>,
    pub server: Option<[u8; 4]>,
    /// BROADCAST_IP or the server (renewing).
    pub dst: [u8; 4],
    pub secs: u16,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Event {
    None,
    /// An address after having none.
    Bound,
    /// The same address, a new lease.
    Renewed,
    /// A renewal gave a different address.
    Changed,
    /// The address is gone (lease ended or refused) – stop using it.
    Lost,
    /// Send an ARP probe for `checking()` now.
    Probe,
}

pub struct Client {
    pub state: State,
    pub xid: u32,
    mac: [u8; 6],
    rng: u64,
    /// Selecting -> Requesting: the address and server we asked for.
    offer: Option<([u8; 4], [u8; 4])>,
    pub lease: Option<Lease>,
    next_ms: u64,
    wait_ms: u64,
    tries: u32,
    started_ms: u64,
    /// The lease being checked (Checking) and the probes sent so far.
    pending: Option<Lease>,
    probes: u32,
    // Counters.
    pub sent: u32,
    pub offers: u32,
    pub acks: u32,
    pub naks: u32,
    pub ignored: u32,
    pub declined: u32,
    pub released: u32,
}

/// ARP probes before an address is used, and the time between them (RFC 5227
/// says 3 probes 1-2 s apart; a home network answers within milliseconds).
const PROBES: u32 = 2;
const PROBE_GAP_MS: u64 = 300;
/// After a DECLINE: wait before asking again (RFC 2131).
const DECLINE_WAIT_MS: u64 = 10_000;

impl Client {
    /// `seed` – anything that differs between runs (the transaction ids).
    pub fn new(mac: [u8; 6], seed: u64) -> Client {
        let mut rng = seed ^ u64::from_be_bytes([0, 0, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]);
        if rng == 0 {
            rng = 0x9E37_79B9_7F4A_7C15;
        }
        Client {
            state: State::Selecting,
            xid: 0,
            mac,
            rng,
            offer: None,
            lease: None,
            next_ms: 0,
            wait_ms: 0,
            tries: 0,
            started_ms: 0,
            sent: 0,
            offers: 0,
            acks: 0,
            naks: 0,
            ignored: 0,
            pending: None,
            probes: 0,
            declined: 0,
            released: 0,
        }
    }

    /// When `tick` has something to do next (ms; u64::MAX = nothing).
    pub fn deadline(&self) -> u64 {
        self.next_ms
    }

    fn new_xid(&mut self) -> u32 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        (x >> 16) as u32
    }

    fn msg(&mut self, now: u64, kind: u8, ciaddr: [u8; 4], requested: Option<[u8; 4]>, server: Option<[u8; 4]>, dst: [u8; 4]) -> Option<Msg> {
        self.sent += 1;
        let secs = (now.saturating_sub(self.started_ms) / 1000).min(u16::MAX as u64) as u16;
        Some(Msg { kind, xid: self.xid, ciaddr, requested, server, dst, secs })
    }

    /// Start over: a new transaction, DISCOVER now.
    fn restart(&mut self, now: u64) -> Option<Msg> {
        self.state = State::Selecting;
        self.offer = None;
        self.tries = 0;
        self.started_ms = now;
        self.xid = self.new_xid();
        self.discover(now)
    }

    fn discover(&mut self, now: u64) -> Option<Msg> {
        self.wait_ms = if self.tries == 0 { DISCOVER_FIRST_MS } else { (self.wait_ms * 2).min(DISCOVER_MAX_MS) };
        self.tries += 1;
        self.next_ms = now + self.wait_ms;
        self.msg(now, DHCP_DISCOVER, [0; 4], None, None, BROADCAST_IP)
    }

    fn request(&mut self, now: u64) -> Option<Msg> {
        let (ip, server) = self.offer?;
        self.tries += 1;
        self.next_ms = now + (DISCOVER_FIRST_MS << (self.tries - 1).min(4));
        self.msg(now, DHCP_REQUEST, [0; 4], Some(ip), Some(server), BROADCAST_IP)
    }

    /// Next resend while renewing / rebinding: half the time left until `limit`,
    /// at least RENEW_MIN_MS, never past `limit`.
    fn renew_next(now: u64, limit: u64) -> u64 {
        (now + (limit.saturating_sub(now) / 2).max(RENEW_MIN_MS)).min(limit)
    }

    fn renew_msg(&mut self, now: u64) -> Option<Msg> {
        let l = self.lease?;
        let dst = if self.state == State::Renewing { l.server } else { BROADCAST_IP };
        self.msg(now, DHCP_REQUEST, l.ip, None, None, dst)
    }

    fn lose(&mut self, now: u64) -> (Option<Msg>, Event) {
        self.lease = None;
        (self.restart(now), Event::Lost)
    }

    /// Timers: resends, T1, T2, lease end.  Call whenever `deadline()` passed
    /// (calling more often is harmless).
    pub fn tick(&mut self, now: u64) -> (Option<Msg>, Event) {
        match self.state {
            State::Checking if now >= self.next_ms => {
                if self.probes < PROBES {
                    self.probes += 1;
                    self.next_ms = now + PROBE_GAP_MS;
                    return (None, Event::Probe);
                }
                // Nobody answered: the address is ours; the lease times count
                // from now.
                let Some(mut l) = self.pending.take() else { return (self.restart(now), Event::None) };
                let shift = now.saturating_sub(l.start_ms);
                l.start_ms = now;
                for t in [&mut l.t1_ms, &mut l.t2_ms, &mut l.end_ms] {
                    if *t != u64::MAX {
                        *t += shift;
                    }
                }
                self.bind(l);
                (None, Event::Bound)
            }
            State::Selecting if now >= self.next_ms => {
                if self.tries == 0 {
                    return (self.restart(now), Event::None);
                }
                (self.discover(now), Event::None)
            }
            State::Requesting if now >= self.next_ms => {
                if self.tries >= REQUEST_TRIES {
                    return (self.restart(now), Event::None);
                }
                (self.request(now), Event::None)
            }
            State::Bound => {
                let Some(l) = self.lease else { return self.lose(now) };
                if now < l.t1_ms {
                    self.next_ms = l.t1_ms;
                    return (None, Event::None);
                }
                self.state = State::Renewing;
                self.xid = self.new_xid();
                self.started_ms = now;
                self.next_ms = Self::renew_next(now, l.t2_ms);
                (self.renew_msg(now), Event::None)
            }
            State::Renewing | State::Rebinding => {
                let Some(l) = self.lease else { return self.lose(now) };
                if now >= l.end_ms {
                    return self.lose(now);
                }
                if self.state == State::Renewing && now >= l.t2_ms {
                    self.state = State::Rebinding;
                    self.next_ms = Self::renew_next(now, l.end_ms);
                    return (self.renew_msg(now), Event::None);
                }
                if now < self.next_ms {
                    return (None, Event::None);
                }
                let limit = if self.state == State::Renewing { l.t2_ms } else { l.end_ms };
                self.next_ms = Self::renew_next(now, limit);
                (self.renew_msg(now), Event::None)
            }
            _ => (None, Event::None),
        }
    }

    /// Renew now (the `renew` request): REQUEST to the server.  None without an
    /// address.
    pub fn renew_now(&mut self, now: u64) -> Option<Msg> {
        let l = self.lease?;
        self.state = State::Renewing;
        self.xid = self.new_xid();
        self.started_ms = now;
        self.next_ms = Self::renew_next(now, l.t2_ms.max(now));
        self.renew_msg(now)
    }

    /// A lease from an ACK, or None when its contents are unusable.
    fn lease_from(&self, now: u64, d: &Dhcp, server: [u8; 4]) -> Option<Lease> {
        let ip = d.yiaddr;
        if !unicast(ip) {
            return None;
        }
        let prefix = d.prefix.unwrap_or(24);
        if !(1..=30).contains(&prefix) {
            return None;
        }
        let gw = d.router.filter(|&r| unicast(r) && r != ip && same_subnet(r, ip, prefix));
        let mut dns = [[0u8; 4]; 2];
        let mut dns_n = 0;
        for &a in &d.dns[..d.dns_n as usize] {
            if unicast(a) {
                dns[dns_n] = a;
                dns_n += 1;
            }
        }
        let lease_s = match d.lease.unwrap_or(DEFAULT_LEASE_S) {
            INFINITE => INFINITE,
            s => s.max(MIN_LEASE_S),
        };
        let (t1_ms, t2_ms, end_ms) = if lease_s == INFINITE {
            (u64::MAX, u64::MAX, u64::MAX)
        } else {
            let lease = lease_s as u64;
            let t1 = d.t1.map(|t| t as u64).filter(|&t| t > 0 && t < lease).unwrap_or(lease / 2);
            let t2 = d.t2.map(|t| t as u64).filter(|&t| t > t1 && t < lease).unwrap_or(lease * 7 / 8).max(t1);
            (now + t1 * 1000, now + t2 * 1000, now + lease * 1000)
        };
        Some(Lease { ip, prefix, gw, dns, dns_n: dns_n as u8, server, lease_s, start_ms: now, t1_ms, t2_ms, end_ms })
    }

    /// A DHCP message received on port 68.
    pub fn on_message(&mut self, now: u64, d: &Dhcp) -> (Option<Msg>, Event) {
        if d.op != 2 || d.xid != self.xid || d.chaddr != self.mac {
            self.ignored += 1;
            return (None, Event::None);
        }
        match (self.state, d.kind) {
            (State::Selecting, DHCP_OFFER) => {
                let server = match d.server {
                    Some(s) if unicast(s) => s,
                    _ => {
                        self.ignored += 1;
                        return (None, Event::None);
                    }
                };
                if !unicast(d.yiaddr) {
                    self.ignored += 1;
                    return (None, Event::None);
                }
                self.offers += 1;
                self.offer = Some((d.yiaddr, server));
                self.state = State::Requesting;
                self.tries = 0;
                (self.request(now), Event::None)
            }
            (State::Requesting, DHCP_ACK | DHCP_NAK) => {
                let Some((_, chosen)) = self.offer else { return (None, Event::None) };
                if d.server.is_some_and(|s| s != chosen) {
                    self.ignored += 1;
                    return (None, Event::None);
                }
                if d.kind == DHCP_NAK {
                    self.naks += 1;
                    return (self.restart(now), Event::None);
                }
                let Some(l) = self.lease_from(now, d, chosen) else {
                    self.ignored += 1;
                    return (None, Event::None);
                };
                self.acks += 1;
                // Check the address before using it.
                self.pending = Some(l);
                self.offer = None;
                self.state = State::Checking;
                self.probes = 1;
                self.next_ms = now + PROBE_GAP_MS;
                (None, Event::Probe)
            }
            (State::Renewing | State::Rebinding, DHCP_ACK | DHCP_NAK) => {
                let Some(old) = self.lease else { return self.lose(now) };
                // Renewing talks to our server only; rebinding accepts any.
                if self.state == State::Renewing && d.server.is_some_and(|s| s != old.server) {
                    self.ignored += 1;
                    return (None, Event::None);
                }
                if d.kind == DHCP_NAK {
                    self.naks += 1;
                    return self.lose(now);
                }
                let Some(l) = self.lease_from(now, d, d.server.unwrap_or(old.server)) else {
                    self.ignored += 1;
                    return (None, Event::None);
                };
                self.acks += 1;
                let ev = if l.ip == old.ip { Event::Renewed } else { Event::Changed };
                self.bind(l);
                (None, ev)
            }
            _ => {
                self.ignored += 1;
                (None, Event::None)
            }
        }
    }

    /// The address being checked (State::Checking).
    pub fn checking(&self) -> Option<[u8; 4]> {
        if self.state == State::Checking { self.pending.map(|l| l.ip) } else { None }
    }

    /// Another machine answered for the address being checked: DECLINE to the
    /// server, a new attempt after 10 s.
    pub fn conflict(&mut self, now: u64) -> Option<Msg> {
        let l = self.pending.take()?;
        if self.state != State::Checking {
            return None;
        }
        self.declined += 1;
        let m = self.msg(now, DHCP_DECLINE, [0; 4], Some(l.ip), Some(l.server), BROADCAST_IP);
        self.state = State::Selecting;
        self.tries = 0;
        self.next_ms = now + DECLINE_WAIT_MS;
        m
    }

    /// Gives the address back (RELEASE to the server, when there is a lease) and
    /// stops: no timers, no messages until `start`.
    pub fn release(&mut self, now: u64) -> Option<Msg> {
        let m = match self.lease.take() {
            Some(l) => {
                self.released += 1;
                self.xid = self.new_xid();
                self.msg(now, DHCP_RELEASE, l.ip, None, Some(l.server), l.server)
            }
            None => None,
        };
        self.pending = None;
        self.offer = None;
        self.state = State::Off;
        self.next_ms = u64::MAX;
        m
    }

    /// Starts asking for an address (after `release`).
    pub fn start(&mut self, now: u64) {
        self.state = State::Selecting;
        self.tries = 0;
        self.next_ms = now;
    }

    fn bind(&mut self, l: Lease) {
        self.lease = Some(l);
        self.state = State::Bound;
        self.offer = None;
        self.tries = 0;
        self.next_ms = l.t1_ms;
    }
}
