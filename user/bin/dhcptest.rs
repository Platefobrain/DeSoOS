// DHCP client test without a network (NET TEST 2/5).  The state machine
// (user/lib/dhcp.rs) gets the time from the test, so a whole day of lease – lost
// answers, renewal, rebinding with another server, refusals, lease end – runs in
// a fraction of a second.  Server answers are built as bytes and go through the
// real parser (parse_dhcp), like in netd.
// Result: "dhcptest: N checks OK" and code 0.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../lib/netproto.rs"]
mod netproto;
#[path = "../lib/dhcp.rs"]
mod dhcp;

use desoos::*;
use dhcp::*;
use netproto::*;

entry!(main);

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("dhcptest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
const IP: [u8; 4] = [10, 0, 2, 15];
const SRV: [u8; 4] = [10, 0, 2, 2];
const SRV2: [u8; 4] = [10, 0, 2, 9];
const S: u64 = 1000;
const LEASE: u64 = 86_400;

/// A server message as bytes → parse_dhcp.  `opts`: extra (code, value) pairs;
/// the message type and (if given) the server identifier come first.
fn reply(kind: u8, xid: u32, mac: [u8; 6], yi: [u8; 4], server: Option<[u8; 4]>, opts: &[(u8, &[u8])]) -> Option<Dhcp> {
    let mut b = [0u8; 400];
    b[0] = 2;
    b[1] = 1;
    b[2] = 6;
    b[4..8].copy_from_slice(&xid.to_be_bytes());
    b[16..20].copy_from_slice(&yi);
    b[28..34].copy_from_slice(&mac);
    b[236..240].copy_from_slice(&[99, 130, 83, 99]);
    let mut i = 240;
    let mut put = |code: u8, v: &[u8], b: &mut [u8; 400]| {
        b[i] = code;
        b[i + 1] = v.len() as u8;
        b[i + 2..i + 2 + v.len()].copy_from_slice(v);
        i += 2 + v.len();
    };
    put(53, &[kind], &mut b);
    if let Some(s) = server {
        put(54, &s, &mut b);
    }
    for (c, v) in opts {
        put(*c, v, &mut b);
    }
    b[i] = 255;
    parse_dhcp(&b[..i + 1]).ok()
}

const STD: [(u8, &[u8]); 4] = [(1, &[255, 255, 255, 0]), (3, &[10, 0, 2, 2]), (6, &[10, 0, 2, 3, 8, 8, 8, 8]), (51, &[0, 1, 0x51, 0x80])];

/// The usual answer (mask /24, gateway, two DNS servers, 24 h).
fn srv(kind: u8, xid: u32, yi: [u8; 4], server: [u8; 4]) -> Dhcp {
    reply(kind, xid, MAC, yi, Some(server), &STD).unwrap_or_else(|| exit(90))
}

/// After an ACK: the two ARP probes pass without an answer – bound.  Returns the
/// time the lease starts (t + 600 ms), or 0 when something else happened.
fn settle(c: &mut Client, t: u64) -> u64 {
    if c.state != State::Checking || c.tick(t + 300).1 != Event::Probe || c.tick(t + 600).1 != Event::Bound {
        return 0;
    }
    t + 600
}

/// Selecting → Requesting → Checking → Bound at `t` with the standard answers.
fn bind(c: &mut Client, t: u64) -> bool {
    let (m, _) = c.tick(t);
    if m.map(|m| m.kind) != Some(DHCP_DISCOVER) {
        return false;
    }
    let (m, _) = c.on_message(t, &srv(DHCP_OFFER, c.xid, IP, SRV));
    if m.map(|m| m.kind) != Some(DHCP_REQUEST) {
        return false;
    }
    c.on_message(t, &srv(DHCP_ACK, c.xid, IP, SRV)).1 == Event::Probe && settle(c, t) != 0
}

fn main(_args: Args) -> i32 {
    let mut n = 0;
    let t0 = 10 * S;

    // 1. Start: DISCOVER to everyone, from no address.
    let mut c = Client::new(MAC, 42);
    let (m, ev) = c.tick(t0);
    check!(n, ev == Event::None && matches!(m, Some(m) if m.kind == DHCP_DISCOVER && m.dst == BROADCAST_IP && m.ciaddr == [0; 4] && m.xid == c.xid), "first DISCOVER: {:?}", m);
    let x1 = c.xid;
    // The message bytes as netd sends them parse back the same.
    let mut b = [0u8; 300];
    let len = build_dhcp(&mut b, DHCP_DISCOVER, x1, MAC, [0; 4], None, None, 0);
    let d = parse_dhcp(&b[..len]);
    check!(n, matches!(d, Ok(d) if d.op == 1 && d.xid == x1 && d.chaddr == MAC && d.kind == DHCP_DISCOVER) && b[10] == 0x80, "DISCOVER bytes: {:?}", d);
    let len = build_dhcp(&mut b, DHCP_REQUEST, x1, MAC, [0; 4], Some(IP), Some(SRV), 3);
    let d = parse_dhcp(&b[..len]);
    check!(n, matches!(d, Ok(d) if d.kind == DHCP_REQUEST && d.requested == Some(IP) && d.server == Some(SRV)), "REQUEST bytes: {:?}", d);

    // 2. Answers that are not for us or not usable are ignored.
    let bad = [
        reply(DHCP_OFFER, x1 ^ 1, MAC, IP, Some(SRV), &STD),                      // another transaction
        reply(DHCP_OFFER, x1, [0x52, 0x54, 0, 0, 0, 1], IP, Some(SRV), &STD),       // another machine
        reply(DHCP_OFFER, x1, MAC, IP, None, &STD),                                 // no server identifier
        reply(DHCP_OFFER, x1, MAC, [0; 4], Some(SRV), &STD),                        // address 0.0.0.0
        reply(DHCP_OFFER, x1, MAC, [127, 0, 0, 1], Some(SRV), &STD),                // loopback
        reply(DHCP_OFFER, x1, MAC, [224, 0, 0, 1], Some(SRV), &STD),                // multicast
        reply(DHCP_OFFER, x1, MAC, [255; 4], Some(SRV), &STD),                      // broadcast
        reply(DHCP_OFFER, x1, MAC, IP, Some([0; 4]), &STD),                         // server 0.0.0.0
        reply(DHCP_ACK, x1, MAC, IP, Some(SRV), &STD),                              // ACK without asking
        reply(DHCP_NAK, x1, MAC, [0; 4], Some(SRV), &[]),                           // NAK without asking
    ];
    check!(n, bad.iter().all(|d| d.is_some()), "building the ignored answers");
    for d in bad.iter().flatten() {
        let (m, ev) = c.on_message(t0 + 10, d);
        if m.is_some() || ev != Event::None {
            println!("dhcptest: FAIL: answered an unusable message {:?}", d);
            return 1;
        }
    }
    // A client message (op 1) – someone else's DISCOVER seen on the network.
    let mut own = srv(DHCP_OFFER, x1, IP, SRV);
    own.op = 1;
    c.on_message(t0 + 10, &own);
    check!(n, c.state == State::Selecting && c.ignored == 11 && c.offers == 0, "state after junk: {:?}, ignored {}", c.state, c.ignored);

    // 3. No answer: DISCOVER again after 1, 2, 4, 8, 16, 16 s, same transaction.
    let mut t = t0;
    let mut gaps = [0u64; 6];
    for g in gaps.iter_mut() {
        let d = c.deadline();
        check!(n, c.tick(d - 1).0.is_none(), "sent before its time");
        let (m, _) = c.tick(d);
        check!(n, matches!(m, Some(m) if m.kind == DHCP_DISCOVER && m.xid == x1), "resend: {:?}", m);
        *g = (d - t) / S;
        t = d;
    }
    check!(n, gaps == [1, 2, 4, 8, 16, 16], "resend intervals {:?}", gaps);

    // 4. Offer → REQUEST for it, to everyone, naming the server.
    let (m, _) = c.on_message(t, &srv(DHCP_OFFER, x1, IP, SRV));
    check!(n, matches!(m, Some(m) if m.kind == DHCP_REQUEST && m.requested == Some(IP) && m.server == Some(SRV) && m.dst == BROADCAST_IP && m.ciaddr == [0; 4] && m.xid == x1), "REQUEST after OFFER: {:?}", m);
    check!(n, c.state == State::Requesting && c.offers == 1, "state {:?}", c.state);
    // A second offer (another server) does not change the choice.
    let (m, _) = c.on_message(t, &srv(DHCP_OFFER, x1, [10, 0, 2, 16], SRV2));
    check!(n, m.is_none() && c.state == State::Requesting, "second offer answered");
    // An ACK from the server we did not choose, or with an unusable address.
    check!(n, c.on_message(t, &srv(DHCP_ACK, x1, IP, SRV2)).1 == Event::None, "ACK from another server accepted");
    check!(n, c.on_message(t, &srv(DHCP_ACK, x1, [0; 4], SRV)).1 == Event::None, "ACK with address 0 accepted");
    let narrow = reply(DHCP_ACK, x1, MAC, IP, Some(SRV), &[(1, &[255, 255, 255, 254])]).unwrap_or_else(|| exit(90));
    check!(n, c.on_message(t, &narrow).1 == Event::None && c.lease.is_none(), "a /31 subnet accepted");

    // 5. ACK → the address is checked (ARP probes: now and after 300 ms) → bound
    //    after 600 ms: address, prefix, gateway, DNS, times from then.
    let (m, ev) = c.on_message(t, &srv(DHCP_ACK, x1, IP, SRV));
    check!(n, m.is_none() && ev == Event::Probe && c.state == State::Checking && c.checking() == Some(IP) && c.lease.is_none(), "ACK: {:?} {:?}", ev, c.state);
    check!(n, c.tick(t + 299).1 == Event::None && c.tick(t + 300).1 == Event::Probe && c.tick(t + 599).1 == Event::None, "probe timing");
    let (m, ev) = c.tick(t + 600);
    let t = t + 600;
    let l = c.lease;
    check!(n, m.is_none() && ev == Event::Bound && c.state == State::Bound && c.checking().is_none(), "bound after the probes: {:?} {:?}", ev, c.state);
    check!(
        n,
        matches!(l, Some(l) if l.ip == IP && l.prefix == 24 && l.gw == Some(SRV) && l.dns_n == 2 && l.dns == [[10, 0, 2, 3], [8, 8, 8, 8]] && l.server == SRV && l.lease_s == 86400),
        "lease {:?}",
        l
    );
    let Some(l) = l else { return 1 };
    check!(n, l.t1_ms == t + LEASE / 2 * S && l.t2_ms == t + LEASE * 7 / 8 * S && l.end_ms == t + LEASE * S, "times {:?}", l);
    check!(n, c.deadline() == l.t1_ms && c.tick(l.t1_ms - 1).0.is_none(), "nothing to do before T1");

    // 6. T1: REQUEST to the server only, from our address, a new transaction.
    let (m, _) = c.tick(l.t1_ms);
    check!(n, matches!(m, Some(m) if m.kind == DHCP_REQUEST && m.ciaddr == IP && m.dst == SRV && m.requested.is_none() && m.server.is_none() && m.xid != x1), "renew at T1: {:?}", m);
    check!(n, c.state == State::Renewing, "state {:?}", c.state);
    // Resend after half the time to T2.
    check!(n, c.deadline() == l.t1_ms + (l.t2_ms - l.t1_ms) / 2, "renew resend at {} (T1 {}, T2 {})", c.deadline(), l.t1_ms, l.t2_ms);
    // An ACK from another server is not taken while renewing.
    check!(n, c.on_message(l.t1_ms + 5, &srv(DHCP_ACK, c.xid, IP, SRV2)).1 == Event::None, "renewal ACK from another server");
    let tr = l.t1_ms + 5 * S;
    let (_, ev) = c.on_message(tr, &srv(DHCP_ACK, c.xid, IP, SRV));
    let l2 = c.lease.unwrap_or(l);
    check!(n, ev == Event::Renewed && c.state == State::Bound && l2.t1_ms == tr + LEASE / 2 * S && c.acks == 2, "renewed: {:?} {:?}", ev, l2);

    // 7. The server does not answer: resends while renewing get rarer, at T2 we
    // ask everyone; another server confirms the address.
    let mut c2 = Client::new(MAC, 7);
    check!(n, bind(&mut c2, t0), "bind 2");
    let Some(l) = c2.lease else { return 1 };
    let mut sent = 0;
    let mut t = l.t1_ms;
    loop {
        let (m, _) = c2.tick(t);
        if let Some(m) = m {
            sent += 1;
            if c2.state == State::Renewing && m.dst != SRV {
                println!("dhcptest: FAIL: renewing must ask the server only: {:?}", m);
                return 1;
            }
        }
        if c2.state == State::Rebinding || sent > 1000 {
            break;
        }
        t = c2.deadline();
    }
    // 43 200 s to 75 600 s, halves down to 60 s: about 10 messages, not thousands.
    check!(n, (6..=14).contains(&sent) && t == l.t2_ms, "renewal messages before T2: {} (rebinding at {}, T2 {})", sent, t, l.t2_ms);
    let (m, _) = c2.tick(t);
    check!(n, m.is_none(), "a second message at T2");
    let (_, ev) = c2.on_message(t + 1, &srv(DHCP_ACK, c2.xid, IP, SRV2));
    check!(n, ev == Event::Renewed && c2.lease.map(|l| l.server) == Some(SRV2), "rebinding with another server: {:?} {:?}", ev, c2.lease);

    // 8. Nobody answers until the lease ends: the address is given up, DISCOVER.
    let mut c3 = Client::new(MAC, 9);
    check!(n, bind(&mut c3, t0), "bind 3");
    let Some(l) = c3.lease else { return 1 };
    let mut t = l.t1_ms;
    let mut msgs = 0;
    let mut lost_at = 0;
    while lost_at == 0 && msgs < 1000 {
        let (m, ev) = c3.tick(t);
        msgs += m.is_some() as u32;
        if ev == Event::Lost {
            lost_at = t;
            check!(n, matches!(m, Some(m) if m.kind == DHCP_DISCOVER && m.ciaddr == [0; 4]), "DISCOVER after the lease: {:?}", m);
        }
        t = c3.deadline();
    }
    check!(n, lost_at == l.end_ms && c3.lease.is_none() && c3.state == State::Selecting, "lease end at {} (expected {}), state {:?}", lost_at, l.end_ms, c3.state);
    check!(n, msgs < 30, "{} messages from T1 to the lease end", msgs);

    // 9. NAK while renewing (from our server): the address is given up at once.
    let mut c4 = Client::new(MAC, 11);
    check!(n, bind(&mut c4, t0), "bind 4");
    let m = c4.renew_now(t0 + S);
    check!(n, matches!(m, Some(m) if m.dst == SRV && m.ciaddr == IP), "renew now: {:?}", m);
    check!(n, c4.on_message(t0 + S, &srv(DHCP_NAK, c4.xid, [0; 4], SRV2)).1 == Event::None, "NAK from another server while renewing");
    let x = c4.xid;
    let (m, ev) = c4.on_message(t0 + S, &srv(DHCP_NAK, x, [0; 4], SRV));
    check!(n, ev == Event::Lost && c4.lease.is_none() && matches!(m, Some(m) if m.kind == DHCP_DISCOVER && m.xid != x) && c4.naks == 1, "NAK: {:?} {:?}", ev, m);

    // 10. NAK in Requesting: start over; REQUEST unanswered 4 times: start over.
    let mut c5 = Client::new(MAC, 13);
    c5.tick(t0);
    c5.on_message(t0, &srv(DHCP_OFFER, c5.xid, IP, SRV));
    let x = c5.xid;
    let (m, ev) = c5.on_message(t0, &srv(DHCP_NAK, x, [0; 4], SRV));
    check!(n, ev == Event::None && c5.state == State::Selecting && matches!(m, Some(m) if m.kind == DHCP_DISCOVER && m.xid != x), "NAK while requesting: {:?}", m);
    c5.on_message(t0, &srv(DHCP_OFFER, c5.xid, IP, SRV));
    let mut kinds = [0u8; 5];
    for k in kinds.iter_mut() {
        let d = c5.deadline();
        *k = c5.tick(d).0.map(|m| m.kind).unwrap_or(0);
    }
    check!(n, kinds == [3, 3, 3, 1, 1], "unanswered REQUESTs, then DISCOVER: {:?}", kinds);

    // 11. A renewal with a different address: Changed (netd forgets its ARP cache).
    let mut c6 = Client::new(MAC, 15);
    check!(n, bind(&mut c6, t0), "bind 6");
    c6.renew_now(t0 + S);
    let (_, ev) = c6.on_message(t0 + S, &srv(DHCP_ACK, c6.xid, [10, 0, 2, 16], SRV));
    check!(n, ev == Event::Changed && c6.lease.map(|l| l.ip) == Some([10, 0, 2, 16]), "changed address: {:?}", ev);

    // 12. Odd leases: 5 s is stretched to 30 s, wrong T1/T2 replaced by the
    // defaults; a lease forever never renews; a gateway off the subnet, our own
    // address as gateway and a loopback DNS server are dropped.
    let short = [(51u8, &[0u8, 0, 0, 5][..]), (58, &[0, 0, 1, 0][..]), (59, &[0, 0, 0, 1][..])];
    let mut c7 = Client::new(MAC, 17);
    c7.tick(t0);
    c7.on_message(t0, &srv(DHCP_OFFER, c7.xid, IP, SRV));
    let d = reply(DHCP_ACK, c7.xid, MAC, IP, Some(SRV), &short).unwrap_or_else(|| exit(90));
    c7.on_message(t0, &d);
    let tb = settle(&mut c7, t0);
    let l = c7.lease;
    check!(n, tb != 0 && matches!(l, Some(l) if l.lease_s == 30 && l.t1_ms == tb + 15 * S && l.t2_ms == tb + 26 * S && l.end_ms == tb + 30 * S), "short lease {:?}", l);
    let odd = [(51u8, &[0xFFu8, 0xFF, 0xFF, 0xFF][..]), (3, &[192, 168, 1, 1][..]), (6, &[127, 0, 0, 1, 10, 0, 2, 3][..])];
    let mut c8 = Client::new(MAC, 19);
    c8.tick(t0);
    c8.on_message(t0, &srv(DHCP_OFFER, c8.xid, IP, SRV));
    let d = reply(DHCP_ACK, c8.xid, MAC, IP, Some(SRV), &odd).unwrap_or_else(|| exit(90));
    c8.on_message(t0, &d);
    settle(&mut c8, t0);
    let l = c8.lease;
    check!(n, matches!(l, Some(l) if l.lease_s == INFINITE && l.gw.is_none() && l.dns_n == 1 && l.dns[0] == [10, 0, 2, 3] && l.prefix == 24), "lease forever {:?}", l);
    check!(n, c8.deadline() == u64::MAX && c8.tick(u64::MAX - 1).0.is_none() && c8.state == State::Bound, "a lease forever must not renew");
    let own_gw = [(3u8, &IP[..])];
    let mut c9 = Client::new(MAC, 21);
    c9.tick(t0);
    c9.on_message(t0, &srv(DHCP_OFFER, c9.xid, IP, SRV));
    let d = reply(DHCP_ACK, c9.xid, MAC, IP, Some(SRV), &own_gw).unwrap_or_else(|| exit(90));
    c9.on_message(t0, &d);
    settle(&mut c9, t0);
    check!(n, matches!(c9.lease, Some(l) if l.gw.is_none() && l.lease_s == 3600 && l.dns_n == 0), "own address as gateway, no lease option: {:?}", c9.lease);

    // 13. Someone answers the ARP probe: DECLINE, a new attempt after 10 s; the
    //     address is given back with RELEASE; stopped and started again.
    let mut ca = Client::new(MAC, 23);
    ca.tick(t0);
    ca.on_message(t0, &srv(DHCP_OFFER, ca.xid, IP, SRV));
    ca.on_message(t0, &srv(DHCP_ACK, ca.xid, IP, SRV));
    let xa = ca.xid;
    let m = ca.conflict(t0 + 50);
    check!(n, matches!(m, Some(m) if m.kind == DHCP_DECLINE && m.requested == Some(IP) && m.server == Some(SRV) && m.ciaddr == [0; 4] && m.dst == BROADCAST_IP), "DECLINE: {:?}", m);
    check!(n, ca.state == State::Selecting && ca.lease.is_none() && ca.checking().is_none() && ca.declined == 1 && ca.deadline() == t0 + 50 + 10_000, "after DECLINE: {:?}", ca.state);
    check!(n, ca.tick(t0 + 50 + 9_999).0.is_none(), "asked again before 10 s");
    let (m, _) = ca.tick(t0 + 50 + 10_000);
    check!(n, matches!(m, Some(m) if m.kind == DHCP_DISCOVER && m.xid != xa), "DISCOVER 10 s after the DECLINE: {:?}", m);
    check!(n, ca.conflict(t0 + 20_000).is_none(), "a conflict outside checking must do nothing");
    let mut b = [0u8; 300];
    let len = build_dhcp(&mut b, DHCP_DECLINE, 5, MAC, [0; 4], Some(IP), Some(SRV), 0);
    let d = parse_dhcp(&b[..len]);
    check!(n, matches!(d, Ok(d) if d.kind == DHCP_DECLINE && d.requested == Some(IP) && d.server == Some(SRV)), "DECLINE bytes: {:?}", d);
    let mut cb = Client::new(MAC, 25);
    check!(n, bind(&mut cb, t0), "bind b");
    let m = cb.release(t0 + 1000);
    check!(n, matches!(m, Some(m) if m.kind == DHCP_RELEASE && m.ciaddr == IP && m.server == Some(SRV) && m.dst == SRV), "RELEASE: {:?}", m);
    check!(n, cb.state == State::Off && cb.lease.is_none() && cb.released == 1 && cb.deadline() == u64::MAX && cb.tick(u64::MAX - 1).0.is_none(), "stopped after RELEASE: {:?}", cb.state);
    check!(n, cb.on_message(t0 + 2000, &srv(DHCP_ACK, cb.xid, IP, SRV)).1 == Event::None && cb.lease.is_none(), "an ACK while stopped must be ignored");
    check!(n, cb.release(t0 + 3000).is_none(), "RELEASE without a lease");
    cb.start(t0 + 4000);
    let (m, _) = cb.tick(t0 + 4000);
    check!(n, cb.state == State::Selecting && matches!(m, Some(m) if m.kind == DHCP_DISCOVER), "started again: {:?}", m);

    // 14. Transaction ids differ between clients and transactions.
    let ids = [x1, c2.xid, c3.xid, c4.xid, c5.xid, c6.xid];
    let distinct = (0..ids.len()).all(|i| (i + 1..ids.len()).all(|j| ids[i] != ids[j]));
    check!(n, distinct, "transaction ids repeat: {:?}", ids);

    println!("dhcptest: {} checks OK (DISCOVER / OFFER / REQUEST / ACK, 11 unusable answers ignored, resends 1-16 s, address checked with ARP before use, DECLINE on a conflict, RELEASE, renewal at T1, rebinding at T2 with another server, lease end, NAK, changed address, odd leases)", n);
    0
}
