// UDP sockets of programs through netd (NET TEST 6, started by /bin/nettest with its
// service channel; tests/udp-stub.py on the host at 10.0.2.2:58090, names from
// tests/dns-stub.py).  UDP promises neither order nor delivery – the checks that need a
// datagram retry it; the burst is only measured.
//   1. echo of text, all 256 byte values, an empty datagram; a name (router.desoos);
//   2. 1472 bytes both ways; 1473 through the library – refused, nothing sent; 1473
//      straight into the channel – netd does not send it (udp_toolong +1, the stub got
//      nothing);
//   3. 100 numbered datagrams, each after the echo of the one before; a burst of 200
//      (received / lost reported, no threshold);
//   4. a full channel: 80 datagrams while the program does not read – 64 arrive (the
//      channel's queue), the rest dropped (udp_dropped);
//   5. a datagram from another port of the peer is dropped (udp_foreign), the real one
//      after it arrives;
//   6. 8 sockets at once (netd's limit) with distinct random ports in 49152-65535, the
//      9th refused, all freed when closed; a killed program's socket freed;
//   7. refused destinations: 255.255.255.255, this subnet's broadcast, multicast,
//      0.0.0.0, port 0, an unknown name;
//   8. rights: a narrowed channel without "udp" refused, with it allowed; `udpsend` exit
//      codes 0 / 3 / 2.
// "udptest: N checks OK" – or "udptest: FAIL check N: ..." and exit 1.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const STUB: &str = "10.0.2.2";
const PORT: u16 = 58090;

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("udptest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

static mut OUT: [u8; 4096] = [0; 4096];
static mut BUF: [u8; MSG_MAX] = [0; MSG_MAX];

fn ask(req: &str) -> &'static str {
    let Ok(c) = svc_connect("net0") else { return "" };
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
    let mut info = RecvInfo::default();
    let r = if chan_send(c, req.as_bytes(), 0) == 0 { chan_recv(c, buf, 0, &mut info) } else { -1 };
    close(c);
    if r < 0 { "" } else { core::str::from_utf8(&buf[..r as usize]).unwrap_or("") }
}

fn num(k: &str) -> u64 {
    let st = ask("status");
    let line = st.lines().find(|l| l.starts_with("netd-status")).unwrap_or("");
    line.split_whitespace().find_map(|w| w.strip_prefix(k).and_then(|v| v.strip_prefix('='))).and_then(|v| v.parse().ok()).unwrap_or(u64::MAX)
}

/// A socket; Err = netd's text.
fn open(host: &str, port: u16) -> Result<(u64, u16), &'static str> {
    open_via(SVC, host, port)
}

fn open_via(svc: u64, host: &str, port: u16) -> Result<(u64, u16), &'static str> {
    let reply = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
    match udp_open_via(svc, "net0", host, port, reply) {
        Ok(c) => {
            // "udp a.b.c.d:port from a.b.c.d:lport"
            let t = core::str::from_utf8(reply).unwrap_or("");
            let lport = t.split(" from ").nth(1).and_then(|r| r.split(':').nth(1)).and_then(|p| p.trim_end_matches(|c: char| !c.is_ascii_digit()).split(|c: char| !c.is_ascii_digit()).next()).and_then(|p| p.parse().ok()).unwrap_or(0);
            Ok((c, lport))
        }
        Err(n) => Err(core::str::from_utf8(&reply[..n]).unwrap_or("?")),
    }
}

/// The next datagram within `ms` (None = nothing).
fn recv(c: u64, ms: u64) -> Option<&'static [u8]> {
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
    if !matches!(wait_many(&[(c, W_READABLE)], ms), Ok(m) if m != 0) {
        return None;
    }
    let mut info = RecvInfo::default();
    let r = chan_recv(c, buf, CHAN_NONBLOCK, &mut info);
    if r < 0 { None } else { Some(&buf[..r as usize]) }
}

/// Sends `data`, expects exactly `want` back – up to 3 tries (UDP may lose either way).
fn round(c: u64, data: &[u8], want: &[u8]) -> bool {
    for _ in 0..3 {
        if udp_send(c, data) != 0 {
            return false;
        }
        let t = uptime_ms();
        while uptime_ms() - t < 1000 {
            match recv(c, 1000 - (uptime_ms() - t)) {
                Some(got) if got == want => return true,
                Some(_) => continue,
                None => break,
            }
        }
    }
    false
}

/// The stub's count of datagrams from this socket.
fn count(c: u64) -> Option<u64> {
    for _ in 0..3 {
        udp_send(c, b"count");
        if let Some(g) = recv(c, 1000) {
            if let Some(v) = core::str::from_utf8(g).ok().and_then(|t| t.parse().ok()) {
                return Some(v);
            }
        }
    }
    None
}

fn drain(c: u64) -> u32 {
    let mut k = 0;
    while recv(c, 0).is_some() {
        k += 1;
    }
    k
}

fn run(args: &[&str]) -> u64 {
    let pid = spawn_ex("/bin/udpsend", args, &[(1, 1), (1, 2), (SVC, SVC)], 0);
    if pid <= 0 {
        return 999;
    }
    wait(pid as u64, 0).map(|(_, code)| code).unwrap_or(998)
}

fn main(_args: Args) -> i32 {
    let mut n = 0;
    let made0 = num("udpmade");

    // 1. Echo.
    let s = open(STUB, PORT);
    check!(n, s.is_ok(), "udp {}:{}: {:?}", STUB, PORT, s.err());
    let (c, lport) = s.unwrap();
    check!(n, (49152..=65535).contains(&lport), "local port {} outside 49152-65535", lport);
    check!(n, round(c, b"hello over udp", b"hello over udp"), "echo of a text");
    let mut all = [0u8; 256];
    for (i, b) in all.iter_mut().enumerate() {
        *b = i as u8;
    }
    check!(n, round(c, &all, &all), "echo of all 256 byte values");
    check!(n, round(c, b"", b""), "an empty datagram and its echo");
    let named = open("router.desoos", PORT);
    check!(n, matches!(named, Ok((nc, _)) if { let ok = round(nc, b"by name", b"by name"); close(nc); ok }), "a socket by name: {:?}", named.err());

    // 2. The size limit, in the library and in netd.
    let big: [u8; 1472] = core::array::from_fn(|i| (i * 7) as u8);
    check!(n, round(c, b"big", &big), "an answer of 1472 bytes");
    check!(n, round(c, &big, &big), "1472 bytes out and back");
    let before = count(c);
    let toolong0 = num("udp_toolong");
    let mut over = [0x55u8; 1473];
    over[0] = b'x';
    check!(n, udp_send(c, &over) == ERROR_MESSAGE_TOO_LARGE, "the library sent 1473 bytes");
    check!(n, chan_send(c, &over, 0) == 0, "1473 bytes straight into the channel");
    let t = uptime_ms();
    while num("udp_toolong") == toolong0 && uptime_ms() - t < 2000 {
        sleep_ms(20);
    }
    check!(n, num("udp_toolong") == toolong0 + 1, "netd did not count the 1473-byte message ({} -> {})", toolong0, num("udp_toolong"));
    let after = count(c);
    check!(n, before.is_some() && after == before, "the stub got the 1473 bytes ({:?} -> {:?} datagrams)", before, after);

    // 3. 100 numbered datagrams, each after the echo of the one before; a burst.
    let mut ok = 0;
    for i in 0..100u32 {
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(b"seq ");
        b[4] = b'0' + (i / 100 % 10) as u8;
        b[5] = b'0' + (i / 10 % 10) as u8;
        b[6] = b'0' + (i % 10) as u8;
        if round(c, &b[..7], &b[..7]) {
            ok += 1;
        }
    }
    check!(n, ok == 100, "numbered datagrams: {} of 100", ok);
    drain(c);
    udp_send(c, b"burst 200");
    let t = uptime_ms();
    let mut burst = 0;
    while uptime_ms() - t < 2000 {
        match recv(c, 300) {
            Some(_) => burst += 1,
            None => break,
        }
    }
    println!("udptest: burst of 200: {} received, {} lost", burst, 200 - burst.min(200));

    // 4. A full channel: the program does not read while 80 arrive.
    let full = open(STUB, PORT);
    check!(n, full.is_ok(), "socket for the full channel: {:?}", full.err());
    let (fc, _) = full.unwrap();
    let dropped0 = num("udp_dropped");
    udp_send(fc, b"burst 80");
    sleep_ms(800);
    let got = drain(fc);
    let dropped = num("udp_dropped") - dropped0;
    // 64 = the channel's queue; the rest dropped by netd (16 if the network lost none).
    check!(n, got == 64 && (1..=16).contains(&dropped), "full channel: {} arrived, {} dropped (expected 64 and 1-16)", got, dropped);
    close(fc);

    // 5. Another port of the peer: dropped; the real answer after it arrives.
    let foreign0 = num("udp_foreign");
    drain(c);
    check!(n, round(c, b"foreign", b"real"), "the real answer after a foreign one");
    check!(n, drain(c) == 0, "the foreign datagram reached the socket");
    check!(n, num("udp_foreign") >= foreign0 + 1, "udp_foreign did not count it");
    close(c);

    // 6. 8 sockets with distinct random ports, the 9th refused, all freed.
    let t = uptime_ms();
    while num("udp") != 0 && uptime_ms() - t < 2000 {
        sleep_ms(20);
    }
    check!(n, num("udp") == 0, "sockets left after closing: {}", num("udp"));
    let mut socks = [(0u64, 0u16); 8];
    for (i, s) in socks.iter_mut().enumerate() {
        let r = open(STUB, PORT);
        check!(n, r.is_ok(), "socket {} of 8: {:?}", i + 1, r.err());
        *s = r.unwrap();
    }
    let distinct = (0..8).all(|i| (i + 1..8).all(|j| socks[i].1 != socks[j].1)) && socks.iter().all(|s| (49152..=65535).contains(&s.1));
    check!(n, distinct, "8 ports not distinct or outside 49152-65535: {:?}", socks.map(|s| s.1));
    let r = open(STUB, PORT);
    check!(n, matches!(r, Err(t) if t.contains("too many sockets")), "9th socket: {:?}", r.map(|s| s.1));
    for s in socks {
        close(s.0);
    }
    let t = uptime_ms();
    while num("udp") != 0 && uptime_ms() - t < 2000 {
        sleep_ms(20);
    }
    check!(n, num("udp") == 0, "8 sockets not freed: {}", num("udp"));
    let pid = spawn_ex("/bin/udpsend", &["udpsend", "-t", "10000", STUB, "58090", "silent"], &[(1, 1), (1, 2), (SVC, SVC)], 0);
    let t = uptime_ms();
    while num("udp") != 1 && uptime_ms() - t < 3000 {
        sleep_ms(20);
    }
    check!(n, pid > 0 && num("udp") == 1, "udpsend's socket not open");
    check!(n, kill(pid as u64) == 0, "kill udpsend");
    let _ = wait(pid as u64, 0);
    let t = uptime_ms();
    while num("udp") != 0 && uptime_ms() - t < 2000 {
        sleep_ms(20);
    }
    check!(n, num("udp") == 0, "a killed program's socket not freed");

    // 7. Refused destinations.
    for (host, port, why) in [
        ("255.255.255.255", PORT, "broadcast"),
        ("10.0.2.255", PORT, "broadcast"),
        ("224.0.0.1", PORT, "multicast"),
        ("239.255.255.250", PORT, "multicast"),
        ("0.0.0.0", PORT, "0.0.0.0"),
        (STUB, 0, "port 1-65535"),
        ("nx.desoos", PORT, "no such name"),
    ] {
        let r = open(host, port);
        check!(n, matches!(r, Err(t) if t.contains(why)), "udp {} {}: {:?}", host, port, r.map(|s| s.1));
    }

    // 8. Rights and the tool.
    let net_only = svc_narrow("net").unwrap_or(0);
    let r = open_via(net_only, STUB, PORT);
    close(net_only);
    check!(n, matches!(r, Err(t) if t.contains("needs the udp right")), "narrowed channel without udp: {:?}", r.map(|s| s.1));
    let with_udp = svc_narrow("net udp").unwrap_or(0);
    let r = open_via(with_udp, STUB, PORT);
    close(with_udp);
    check!(n, matches!(r, Ok((uc, _)) if { let ok = round(uc, b"sandboxed", b"sandboxed"); close(uc); ok }), "narrowed channel with udp: {:?}", r.err());
    check!(n, run(&["udpsend", "router.desoos", "58090", "hello"]) == 0, "udpsend with an answer must exit 0");
    check!(n, run(&["udpsend", "-t", "300", STUB, "58090", "silent"]) == 3, "udpsend without an answer must exit 3");
    check!(n, run(&["udpsend", "255.255.255.255", "58090", "x"]) == 2, "udpsend to broadcast must exit 2");
    check!(n, run(&["udpsend", STUB]) == 2, "udpsend usage must exit 2");

    let made = num("udpmade") - made0;
    println!("udptest: {} checks OK ({} sockets made, 8 at once with random ports, burst {}/200, 7 destinations refused)", n, made, burst);
    0
}
