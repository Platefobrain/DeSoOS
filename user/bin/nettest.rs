// Network card test (run by the self-tests through `init test /bin/nettest`):
// init must have found the card and started net0 (/bin/netd).  Checks:
//   - status: the QEMU MAC address, link up,
//   - ARP: one frame out, the answer from QEMU's virtual router 10.0.2.2
//     (52:55:0a:00:02:02) back; an address nobody has – "no reply",
//   - DHCP: address 10.0.2.15/24, gateway 10.0.2.2, DNS 10.0.2.3, lease 24 h
//     from QEMU's server; a renewal gets the same address,
//   - DNS against tests/dns-stub.py (10.0.2.2:53530): names, cache, CNAME,
//     several addresses, no such name, no address, server failure, truncated,
//     a pointer loop, a forged answer, TTL 0, a silent server; ping by name,
//   - TCP against tests/http-stub.py (10.0.2.2:58080): a page, 1 MiB with a
//     pattern, two slow downloads at once, a page cut short, a server reset,
//     refused / unreachable / unknown, a program leaving mid-download; /bin/fetch
//     to a file, an error status, a cut page, https refused,
//   - rights: a narrowed service channel (nofiles --net) – no listen, no DNS
//     change, no other services, cannot widen itself,
//   - listening + loopback: 127.0.0.1 and our own address, 200 KiB / 100 KiB
//     both ways, close seen by the server, refused port, ping to ourselves,
//   - a sandboxed httpd (nofiles --listen, page through stdin) reached over
//     loopback and from the host through QEMU's port forwarding,
//   - an address by hand: the router's address refused (ARP answer), bad input,
//     a free one (lease released, ping works), not for narrowed programs, back
//     to DHCP,
//   - nothing blocks: status during two pings, two pings at once, a program
//     leaving mid-ping,
//   - ICMP: ping 10.0.2.2 (3 answers), an unused address –
//     "host unreachable", a bad address refused, no malformed packets,
//   - counters: frames sent and received, interrupts, no receive errors,
//   - kill netd: init restarts it, the new instance gets its address again and
//     answers ping.
// Result: "nettest: N checks OK, ..." and exit code 0.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("nettest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

static mut OUT: [u8; MSG_MAX] = [0; MSG_MAX];

/// One request to net0 (new connection each time – survives restarts).
fn ask(req: &str) -> &'static str {
    let Ok(c) = svc_connect("net0") else { return "" };
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
    let mut info = RecvInfo::default();
    let r = if chan_send(c, req.as_bytes(), 0) == 0 { chan_recv(c, buf, 0, &mut info) } else { -1 };
    close(c);
    if r < 0 { "" } else { core::str::from_utf8(&buf[..r as usize]).unwrap_or("") }
}

static mut ALL: [u8; 4096] = [0; 4096];

/// A streamed request (ping): all messages until the "ping-end" line.
fn ask_stream(req: &str) -> &'static str {
    let Ok(c) = svc_connect("net0") else { return "" };
    let all = unsafe { &mut *core::ptr::addr_of_mut!(ALL) };
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
    let mut len = 0;
    let mut info = RecvInfo::default();
    if chan_send(c, req.as_bytes(), 0) == 0 {
        loop {
            let r = chan_recv(c, buf, 0, &mut info);
            if r <= 0 {
                break;
            }
            let k = (r as usize).min(all.len() - len);
            all[len..len + k].copy_from_slice(&buf[..k]);
            len += k;
            if buf[..r as usize].ends_with(b"ping-end\n") || len == all.len() {
                break;
            }
        }
    }
    close(c);
    core::str::from_utf8(&all[..len]).unwrap_or("")
}

/// Opens a connection and sends a request without reading (concurrency test).
fn open_req(req: &str) -> i64 {
    let Ok(c) = svc_connect("net0") else { return -1 };
    if chan_send(c, req.as_bytes(), 0) != 0 {
        close(c);
        return -1;
    }
    c as i64
}

static mut ALL_A: [u8; 4096] = [0; 4096];
static mut ALL_B: [u8; 4096] = [0; 4096];

/// Reads a socket to its end (EPIPE); the number of bytes.
fn drain_socket(c: u64) -> u64 {
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
    let mut info = RecvInfo::default();
    let mut total = 0;
    loop {
        let r = chan_recv(c, buf, 0, &mut info);
        if r < 0 {
            break;
        }
        total += r as u64;
    }
    close(c);
    total
}

/// Reads a streamed answer to the end ("ping-end") into buffer A or B and closes
/// the connection.
fn read_stream(c: u64, second: bool) -> &'static str {
    let all = unsafe { &mut *if second { core::ptr::addr_of_mut!(ALL_B) } else { core::ptr::addr_of_mut!(ALL_A) } };
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
    let mut len = 0;
    let mut info = RecvInfo::default();
    loop {
        let r = chan_recv(c, buf, 0, &mut info);
        if r <= 0 {
            break;
        }
        let k = (r as usize).min(all.len() - len);
        all[len..len + k].copy_from_slice(&buf[..k]);
        len += k;
        if buf[..r as usize].ends_with(b"ping-end\n") || len == all.len() {
            break;
        }
    }
    close(c);
    core::str::from_utf8(&all[..len]).unwrap_or("")
}

/// What a TCP GET brought back.
struct Got {
    status: u32,
    body: u64,
    /// The body matched the /big pattern so far.
    pattern: bool,
    head: [u8; 32],
    ms: u64,
}

/// HTTP GET over netd's TCP (the socket protocol, without /bin/fetch).
/// Err = netd's reply instead of "connected".  `leave_after` > 0: close the
/// socket after that many messages (a program leaving mid-download).
fn tcp_get(host: &str, port: &str, path: &str, leave_after: u32) -> Result<Got, &'static str> {
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
    let Ok(c) = svc_connect("net0") else { return Err("no net0") };
    let t0 = uptime_ms();
    let mut req = [0u8; 300];
    let mut n = 0;
    for p in [b"tcp ".as_slice(), host.as_bytes(), b" ", port.as_bytes()] {
        req[n..n + p.len()].copy_from_slice(p);
        n += p.len();
    }
    let mut info = RecvInfo::default();
    let r = if chan_send(c, &req[..n], 0) == 0 { chan_recv(c, buf, 0, &mut info) } else { -1 };
    if r <= 0 || !buf.starts_with(b"connected ") {
        let all = unsafe { &mut *core::ptr::addr_of_mut!(ALL) };
        let k = (r.max(0) as usize).min(all.len());
        all[..k].copy_from_slice(&buf[..k]);
        close(c);
        return Err(core::str::from_utf8(&all[..k]).unwrap_or("?"));
    }
    let mut n = 0;
    for p in [b"GET ".as_slice(), path.as_bytes(), b" HTTP/1.0\r\nHost: test\r\n\r\n"] {
        req[n..n + p.len()].copy_from_slice(p);
        n += p.len();
    }
    chan_send(c, &req[..n], 0);
    let mut g = Got { status: 0, body: 0, pattern: true, head: [0; 32], ms: 0 };
    let mut header = true;
    let mut hb = [0u8; 4];
    let mut msgs = 0;
    loop {
        let r = chan_recv(c, buf, 0, &mut info);
        if r < 0 {
            break;
        }
        msgs += 1;
        let mut data = &buf[..r as usize];
        if header {
            // Status code from the first message; the header ends at CRLFCRLF.
            if g.status == 0 && data.len() > 12 && data.starts_with(b"HTTP/1.") {
                g.status = core::str::from_utf8(&data[9..12]).ok().and_then(|x| x.parse().ok()).unwrap_or(0);
            }
            let mut k = 0;
            while k < data.len() && header {
                hb = [hb[1], hb[2], hb[3], data[k]];
                k += 1;
                if &hb == b"\r\n\r\n" {
                    header = false;
                }
            }
            data = &data[k..];
        }
        for &b in data {
            let i = g.body as usize;
            if i < g.head.len() {
                g.head[i] = b;
            }
            if b != (i * 7 + i / 251) as u8 {
                g.pattern = false;
            }
            g.body += 1;
        }
        if leave_after > 0 && msgs >= leave_after {
            break;
        }
    }
    close(c);
    g.ms = uptime_ms() - t0;
    Ok(g)
}

/// Runs /bin/fetch with the arguments; its exit code.
fn run_fetch(args: &[&str]) -> u64 {
    let pid = spawn_ex("/bin/fetch", args, &[(1, 1), (1, 2), (SVC, SVC)], 0);
    if pid <= 0 {
        return 999;
    }
    wait(pid as u64, 0).map(|(_, code)| code).unwrap_or(998)
}

/// One request on an existing connection; the reply.
fn req_on(c: u64, req: &str) -> &'static str {
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
    let mut info = RecvInfo::default();
    let r = if chan_send(c, req.as_bytes(), 0) == 0 { chan_recv(c, buf, 0, &mut info) } else { -1 };
    if r < 0 { "" } else { core::str::from_utf8(&buf[..r as usize]).unwrap_or("") }
}

/// A request to net0 through another service channel (a narrowed one).
fn ask_via(svc: u64, req: &str) -> &'static str {
    let Ok(c) = svc_connect_via(svc, "net0") else { return "" };
    let r = req_on(c, req);
    close(c);
    r
}

fn pat2(i: usize) -> u8 {
    (i * 13 + i / 509) as u8
}

/// Sends `len` pattern bytes into socket `a` while reading them from socket `b`
/// (both without blocking – one program plays both sides); true when all
/// arrived intact within 20 s.
fn pump(a: u64, b: u64, len: usize) -> bool {
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
    let mut chunk = [0u8; 4096];
    let (mut sent, mut got) = (0usize, 0usize);
    let t0 = uptime_ms();
    let mut info = RecvInfo::default();
    while got < len && uptime_ms() - t0 < 20_000 {
        if sent < len {
            let k = (len - sent).min(chunk.len());
            for (i, c) in chunk[..k].iter_mut().enumerate() {
                *c = pat2(sent + i);
            }
            let r = chan_send(a, &chunk[..k], CHAN_NONBLOCK);
            if r == 0 {
                sent += k;
            } else if r != EAGAIN {
                return false;
            }
        }
        let r = chan_recv(b, buf, CHAN_NONBLOCK, &mut info);
        if r > 0 {
            if buf[..r as usize].iter().enumerate().any(|(i, &x)| x != pat2(got + i)) {
                return false;
            }
            got += r as usize;
        } else if r == EAGAIN {
            if sent < len {
                let _ = wait_many(&[(a, W_WRITABLE), (b, W_READABLE)], 100);
            } else {
                let _ = wait_many(&[(b, W_READABLE)], 100);
            }
        } else {
            return false;
        }
    }
    got == len
}

/// The next "accepted ..." on listening connection `l` (3 s): (text, socket).
fn accept_on(l: u64) -> Option<(&'static str, u64)> {
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(ALL) };
    if wait_many(&[(l, W_READABLE)], 3000) != Ok(1) {
        return None;
    }
    let mut hs = [0u64; 1];
    let mut info = RecvInfo::default();
    let r = chan_recv_h(l, buf, &mut hs, CHAN_NONBLOCK, &mut info);
    if r < 0 || info.handles != 1 {
        return None;
    }
    Some((core::str::from_utf8(&buf[..r as usize]).unwrap_or(""), hs[0]))
}

/// Value of key `k` in the "netd-status k=v ..." line.
fn field<'a>(t: &'a str, k: &str) -> &'a str {
    let line = t.lines().find(|l| l.starts_with("netd-status")).unwrap_or("");
    for w in line.split_whitespace() {
        if let Some(v) = w.strip_prefix(k) {
            if let Some(v) = v.strip_prefix('=') {
                return v;
            }
        }
    }
    ""
}

fn num(t: &str, k: &str) -> u64 {
    field(t, k).parse().unwrap_or(0)
}

/// pid of net0 from the service list (0 = not running).
fn net0_pid() -> u64 {
    let mut buf = [0u8; 2048];
    let Ok(n) = svc_list(&mut buf) else { return 0 };
    let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
    for l in text.lines() {
        let w: [&str; 4] = {
            let mut it = l.split_whitespace();
            [it.next().unwrap_or(""), it.next().unwrap_or(""), it.next().unwrap_or(""), it.next().unwrap_or("")]
        };
        // "name state pid N ..."
        if w[0] == "net0" && w[1] == "running" {
            return if w[2] == "pid" { w[3].parse().unwrap_or(0) } else { w[2].parse().unwrap_or(0) };
        }
    }
    0
}

/// Waits up to 5 s for net0 to get its DHCP address; the last status.
fn wait_bound() -> &'static str {
    let t = uptime_ms();
    loop {
        let st = ask("status");
        if field(st, "dhcp") == "bound" || uptime_ms() - t > 5000 {
            return st;
        }
        sleep_ms(20);
    }
}

fn main(_args: Args) -> i32 {
    let mut n = 0;
    // init starts services right before this program – give net0 a moment.
    let t = uptime_ms();
    while net0_pid() == 0 && uptime_ms() - t < 3000 {
        sleep_ms(20);
    }
    let pid1 = net0_pid();
    check!(n, pid1 != 0, "net0 is not running (init did not find the card?)");

    let st = wait_bound();
    check!(n, field(st, "mac") == "52:54:00:12:34:56", "MAC address: {:?}", field(st, "mac"));
    check!(n, field(st, "link") == "1", "link is down: {:?}", st.lines().next());

    // DHCP from QEMU's built-in server: address, mask, gateway, DNS, lease.
    check!(n, field(st, "dhcp") == "bound" && num(st, "acks") == 1, "no DHCP address in 5 s: {:?}", st.trim());
    check!(n, field(st, "ip") == "10.0.2.15" && field(st, "prefix") == "24", "DHCP address: {:?}/{:?}", field(st, "ip"), field(st, "prefix"));
    check!(n, field(st, "gw") == "10.0.2.2" && field(st, "dns") == "10.0.2.3", "DHCP gateway / DNS: {:?} {:?}", field(st, "gw"), field(st, "dns"));
    check!(n, num(st, "lease") == 86400, "DHCP lease: {:?} s", field(st, "lease"));
    check!(n, st.contains("from DHCP server 10.0.2.2, lease 24 h (renew in "), "ifconfig text: {:?}", st.lines().nth(3));
    // Renewal (normally after 12 h): a REQUEST to the server, the same address back.
    let r = ask("renew");
    check!(n, r.starts_with("renewed 10.0.2.15 for 24 h from 10.0.2.2"), "DHCP renew: {:?}", r.trim());
    let st = ask("status");
    check!(n, field(st, "dhcp") == "bound" && num(st, "acks") == 2 && num(st, "naks") == 0 && field(st, "ip") == "10.0.2.15", "after renew: {:?}", st.lines().last());

    let a = ask("arp 10.0.2.2");
    check!(n, a.contains("is-at 52:55:0a:00:02:02"), "ARP for the virtual router: {:?}", a.trim());
    let none = ask("arp 10.0.2.77");
    check!(n, none.contains("no reply"), "ARP for an unused address: {:?}", none.trim());

    // ICMP: ping to the router (3 answers), an unused address, a bad address.
    let p = ask_stream("ping 10.0.2.2 3");
    let replies = p.lines().filter(|l| l.starts_with("64 bytes from 10.0.2.2: seq=")).count();
    check!(n, replies == 3 && p.contains("3 sent, 3 received, 0% loss"), "ping 10.0.2.2: {:?}", p.trim());
    let p = ask_stream("ping 10.0.2.77 1");
    check!(n, p.contains("host unreachable") && p.ends_with("ping-end\n"), "ping to an unused address: {:?}", p.trim());
    let p = ask_stream("ping 10.0.2.300");
    check!(n, p.contains("bad address"), "ping with a bad address: {:?}", p.trim());

    // DNS against the test server (tests/dns-stub.py on the host, 10.0.2.2:53530).
    let r = ask("dns 10.0.2.2:53530");
    check!(n, r.starts_with("DNS server 10.0.2.2:53530 (set by hand)"), "dns set: {:?}", r.trim());
    let r = ask("resolve router.desoos");
    check!(n, r.starts_with("router.desoos is 10.0.2.2 (DNS 10.0.2.2:53530, "), "resolve: {:?} (is tests/dns-stub.py running?)", r.trim());
    let r = ask("resolve ROUTER.desoos.");
    check!(n, r.starts_with("router.desoos is 10.0.2.2 (cached)"), "second resolve (cache, case, final dot): {:?}", r.trim());
    let r = ask("resolve alias.desoos");
    check!(n, r.starts_with("alias.desoos is 10.0.2.2 (DNS"), "CNAME: {:?}", r.trim());
    let r = ask("resolve multi.desoos");
    check!(n, r.starts_with("multi.desoos is 10.0.2.2, 10.0.2.77 (DNS"), "two addresses: {:?}", r.trim());
    let r = ask("resolve big.desoos");
    check!(n, r.starts_with("big.desoos is 10.0.3.1, 10.0.3.2, 10.0.3.3, 10.0.3.4 (DNS"), "six addresses (four kept): {:?}", r.trim());
    let r = ask("resolve nx.desoos");
    check!(n, r.trim() == "nx.desoos: no such name", "no such name: {:?}", r.trim());
    let r = ask("resolve noaddr.desoos");
    check!(n, r.trim() == "noaddr.desoos: has no IPv4 address", "no address: {:?}", r.trim());
    let r = ask("resolve fail.desoos");
    check!(n, r.contains("SERVFAIL"), "server failure: {:?}", r.trim());
    let r = ask("resolve trunc.desoos");
    check!(n, r.contains("would need TCP"), "truncated answer: {:?}", r.trim());
    let before = num(ask("status"), "dnsbad");
    let r = ask("resolve loop.desoos");
    check!(n, r.contains("malformed answer"), "pointer loop in the answer: {:?}", r.trim());
    let r = ask("resolve spoof.desoos");
    check!(n, r.starts_with("spoof.desoos is 10.0.2.2 (DNS"), "forged answer (wrong id) must be ignored: {:?}", r.trim());
    check!(n, num(ask("status"), "dnsbad") == before + 2, "bad answers not counted");
    ask("resolve ttl0.desoos");
    let r = ask("resolve ttl0.desoos");
    check!(n, r.starts_with("ttl0.desoos is 10.0.2.2 (DNS"), "TTL 0 must not be cached: {:?}", r.trim());
    let t = uptime_ms();
    let r = ask("resolve silent.desoos");
    let waited = uptime_ms() - t;
    check!(n, r.contains("no answer from DNS server 10.0.2.2:53530") && (3500..8000).contains(&waited), "silent server: {:?} after {} ms", r.trim(), waited);
    let r = ask("resolve bad..name");
    check!(n, r.contains("not a valid name"), "invalid name: {:?}", r.trim());
    let p = ask_stream("ping router.desoos 2");
    check!(n, p.starts_with("router.desoos is 10.0.2.2 (cached)") && p.contains("2 sent, 2 received"), "ping by name: {:?}", p.trim());
    let p = ask_stream("ping nx.desoos");
    check!(n, p.contains("ping: nx.desoos: no such name") && p.ends_with("ping-end\n"), "ping to an unknown name: {:?}", p.trim());

    // Nothing blocks: while a 3 s ping runs, status answers at once; two pings at
    // the same time take 3 s, not 6; a program that leaves mid-ping is forgotten.
    let a = open_req("ping 10.0.2.2 3");
    let b = open_req("ping 10.0.2.2 3");
    let t = uptime_ms();
    let st = ask("status");
    let quick = uptime_ms() - t;
    check!(n, a > 0 && b > 0 && quick < 500 && num(st, "conns") >= 3, "status during pings took {} ms (conns {:?})", quick, field(st, "conns"));
    let gone = open_req("ping 10.0.2.2 5");
    close(gone as u64);
    let (pa, pb) = (read_stream(a as u64, false), read_stream(b as u64, true));
    let both = uptime_ms() - t;
    check!(n, pa.contains("3 sent, 3 received") && pb.contains("3 sent, 3 received") && both < 4500, "two pings at once: {} ms, {:?} / {:?}", both, pa.lines().last(), pb.lines().last());
    let st = ask("status");
    check!(n, num(st, "conns") == 1, "connections left behind: {:?}", field(st, "conns"));
    // TCP against tests/http-stub.py (10.0.2.2:58080, as router.desoos via DNS).
    let g = tcp_get("router.desoos", "58080", "/hello", 0);
    check!(n, matches!(&g, Ok(g) if g.status == 200 && g.body == 20 && &g.head[..20] == b"Hello from the host\n"), "GET /hello: {:?}", g.as_ref().map(|g| (g.status, g.body)));
    let g = tcp_get("10.0.2.2", "58080", "/big", 0);
    let (big_ms, big_ok) = match &g {
        Ok(g) => (g.ms, g.status == 200 && g.body == 1 << 20 && g.pattern),
        Err(_) => (0, false),
    };
    check!(n, big_ok, "GET /big (1 MiB, pattern): {:?}", g.as_ref().map(|g| (g.status, g.body, g.pattern)));
    let a = open_req("tcp 10.0.2.2 58080");
    let b = open_req("tcp 10.0.2.2 58080");
    let t = uptime_ms();
    let both = [a, b].iter().all(|&c| {
        let mut info = RecvInfo::default();
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
        c > 0 && chan_recv(c as u64, buf, 0, &mut info) > 0 && buf.starts_with(b"connected") && chan_send(c as u64, b"GET /slow HTTP/1.0\r\n\r\n", 0) == 0
    });
    let (sa, sb) = (drain_socket(a as u64), drain_socket(b as u64));
    let slow_ms = uptime_ms() - t;
    check!(n, both && sa >= 1000 && sb >= 1000 && slow_ms < 1800, "two slow downloads at once: {} + {} bytes in {} ms", sa, sb, slow_ms);
    let g = tcp_get("10.0.2.2", "58080", "/short", 0);
    check!(n, matches!(&g, Ok(g) if g.body == 5000), "page cut short by the server: {:?}", g.as_ref().map(|g| g.body));
    let g = tcp_get("10.0.2.2", "58080", "/reset", 0);
    check!(n, matches!(&g, Ok(g) if g.body <= 3000 && g.ms < 3000), "server reset: {:?}", g.as_ref().map(|g| (g.body, g.ms)));
    let g = tcp_get("10.0.2.2", "58081", "/", 0);
    check!(n, matches!(g, Err(e) if e.contains("connection refused")), "closed port: {:?}", g.err());
    let g = tcp_get("10.0.2.77", "80", "/", 0);
    check!(n, matches!(g, Err(e) if e.contains("host unreachable")), "unreachable host: {:?}", g.err());
    let g = tcp_get("nx.desoos", "80", "/", 0);
    check!(n, matches!(g, Err(e) if e.contains("no such name")), "unknown name: {:?}", g.err());
    let g = tcp_get("10.0.2.2", "0", "/", 0);
    check!(n, matches!(g, Err(e) if e.contains("port 1-65535")), "port 0: {:?}", g.err());
    // A program leaving mid-download: netd resets the connection and frees it.
    let g = tcp_get("10.0.2.2", "58080", "/big", 2);
    check!(n, matches!(&g, Ok(g) if g.body < 1 << 20), "leaving mid-download: {:?}", g.as_ref().map(|g| g.body));
    let t = uptime_ms();
    while num(ask("status"), "tcp") != 0 && uptime_ms() - t < 3000 {
        sleep_ms(20);
    }
    let st = ask("status");
    check!(n, num(st, "tcp") == 0 && num(st, "tcpmade") == 8, "connections left after the downloads: {:?} (made {:?})", field(st, "tcp"), field(st, "tcpmade"));
    // The fetch tool: a file, an error status, a page cut short.
    unlink("/fetch.out");
    let code = run_fetch(&["fetch", "-o", "/fetch.out", "http://router.desoos:58080/hello"]);
    let mut fb = [0u8; 64];
    let fd = open("/fetch.out", O_READ);
    let k = if fd >= 0 { read(fd as u64, &mut fb) } else { -1 };
    if fd >= 0 {
        close(fd as u64);
    }
    unlink("/fetch.out");
    check!(n, code == 0 && k == 20 && &fb[..20] == b"Hello from the host\n", "fetch -o: code {}, {} bytes", code, k);
    check!(n, run_fetch(&["fetch", "http://10.0.2.2:58080/missing"]) == 4, "fetch of a missing page must exit 4");
    check!(n, run_fetch(&["fetch", "http://10.0.2.2:58080/short"]) == 3, "fetch of a cut page must exit 3");
    check!(n, run_fetch(&["fetch", "https://example.com/"]) == 1, "fetch https must be refused");

    let r = ask("dns auto");
    check!(n, r.starts_with("DNS server 10.0.2.3 (from DHCP)"), "dns auto: {:?}", r.trim());

    let st = ask("status");
    check!(n, num(st, "echo") == 0 && num(st, "bad") == 0, "malformed packets from QEMU or unexpected echo answers: {:?}", st.lines().last());
    check!(n, num(st, "tx") >= 2 && num(st, "rx") >= 1 && num(st, "arp") >= 1, "counters: {:?}", st.lines().last());
    check!(n, num(st, "irq") >= 1, "no interrupts counted: {:?}", st.lines().last());
    check!(n, num(st, "errors") == 0, "receive errors: {:?}", st.lines().last());
    let (rx1, tx1) = (num(st, "rx"), num(st, "tx"));

    // Rights: a narrowed service channel – what `nofiles --net` gives a program.
    let net_only = svc_narrow("net");
    check!(n, net_only.is_ok(), "init refused to narrow: {:?}", net_only);
    let net_only = net_only.unwrap_or(0);
    let r = ask_via(net_only, "status");
    check!(n, field(r, "ip") == "10.0.2.15", "status through a narrowed channel: {:?}", r.lines().last());
    let r = ask_via(net_only, "listen 9000");
    check!(n, r.contains("not allowed"), "listen without the listen right: {:?}", r.trim());
    let r = ask_via(net_only, "dns auto");
    check!(n, r.contains("administrator request"), "DNS change without admin: {:?}", r.trim());
    let reached = match svc_connect_via(net_only, "echo") {
        Ok(c) => {
            let mut info = RecvInfo::default();
            let buf = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
            let _ = wait_many(&[(c, W_READABLE)], 2000);
            let r = chan_recv(c, buf, CHAN_NONBLOCK, &mut info);
            close(c);
            r != EPIPE
        }
        Err(_) => false,
    };
    check!(n, !reached, "a narrowed channel reached another service (echo)");
    let r = match svc_narrow_via(net_only, "net listen") {
        Ok(h) => {
            let r = ask_via(h, "listen 9001");
            close(h);
            r
        }
        Err(_) => "refused",
    };
    check!(n, r.contains("not allowed") || r == "refused", "a narrowed channel widened itself: {:?}", r.trim());
    close(net_only);

    // Listening and loopback: client and server inside this machine.
    let l = svc_connect("net0").unwrap_or(0);
    let r = req_on(l, "listen 8080");
    check!(n, r.starts_with("listening on port 8080"), "listen 8080: {:?}", r.trim());
    let r = ask("listen 8080");
    check!(n, r.contains("already in use"), "a second listener on 8080: {:?}", r.trim());
    let mut moved = 0usize;
    for host in ["127.0.0.1", "10.0.2.15"] {
        let mut req = [0u8; 32];
        let k = {
            let parts = [b"tcp ".as_slice(), host.as_bytes(), b" 8080"];
            let mut k = 0;
            for p in parts {
                req[k..k + p.len()].copy_from_slice(p);
                k += p.len();
            }
            k
        };
        let c = open_req(core::str::from_utf8(&req[..k]).unwrap_or(""));
        let mut info = RecvInfo::default();
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
        let r = if c > 0 { chan_recv(c as u64, buf, 0, &mut info) } else { -1 };
        let connected = r > 0 && buf.starts_with(b"connected ") && buf[10..10 + host.len()] == *host.as_bytes();
        check!(n, connected, "tcp {} 8080 over loopback: {:?}", host, core::str::from_utf8(&buf[..r.max(0) as usize]).unwrap_or(""));
        let acc = accept_on(l);
        check!(n, matches!(acc, Some((t, _)) if t.starts_with("accepted ") && t.contains(host) && t.contains("to port 8080")), "accept from {}: {:?}", host, acc.map(|a| a.0));
        let sock = acc.map(|a| a.1).unwrap_or(0);
        check!(n, pump(c as u64, sock, 200 * 1024) && pump(sock, c as u64, 100 * 1024), "{}: 200 KiB client -> server and 100 KiB back", host);
        moved += 300 * 1024;
        close(c as u64);
        let t = uptime_ms();
        let mut eof = false;
        while uptime_ms() - t < 3000 {
            let r = chan_recv(sock, buf, CHAN_NONBLOCK, &mut info);
            if r == EPIPE {
                eof = true;
                break;
            }
            let _ = wait_many(&[(sock, W_READABLE)], 100);
        }
        close(sock);
        check!(n, eof, "{}: the server did not see the client close", host);
    }
    let g = tcp_get("127.0.0.1", "8099", "/", 0);
    check!(n, matches!(g, Err(e) if e.contains("connection refused")), "loopback to a port nobody listens on: {:?}", g.err());
    close(l);
    let p = ask_stream("ping 127.0.0.1 2");
    check!(n, p.contains("2 sent, 2 received"), "ping 127.0.0.1: {:?}", p.trim());
    let p = ask_stream("ping 10.0.2.15 1");
    check!(n, p.contains("1 sent, 1 received"), "ping to our own address: {:?}", p.trim());
    let st = ask("status");
    check!(n, num(st, "echo") == 3 && num(st, "tcpacc") >= 2 && num(st, "loop") > 0, "loopback counters: {:?}", st.lines().last());

    // A sandboxed server: httpd with no file access and a narrowed channel with
    // the listen right, its page through stdin; reached over loopback and from
    // the host (tests/http-stub.py connects to 127.0.0.1:58082, which QEMU
    // forwards to port 8081 of this machine).
    const PAGE: &[u8] = b"<h1>DeSoOS sandboxed httpd</h1>\n";
    let h = svc_narrow("net listen").unwrap_or(0);
    let (pr, pw) = pipe().unwrap_or((0, 0));
    write(pw, PAGE);
    close(pw);
    let pid = spawn_ex("/bin/httpd", &["httpd", "-n", "2", "8081"], &[(pr, 0), (1, 1), (1, 2), (h, SVC)], SPAWN_NO_FILES);
    close(pr);
    close(h);
    check!(n, pid > 0, "spawn sandboxed httpd: {}", pid);
    let t = uptime_ms();
    while !ask("status").contains("listening on port 8081") && uptime_ms() - t < 3000 {
        sleep_ms(20);
    }
    let g = tcp_get("127.0.0.1", "8081", "/", 0);
    check!(n, matches!(&g, Ok(g) if g.status == 200 && g.body == PAGE.len() as u64 && g.head[..] == PAGE[..32]), "sandboxed httpd over loopback: {:?}", g.as_ref().map(|g| (g.status, g.body)));
    let g = tcp_get("10.0.2.2", "58080", "/connect?port=58082&path=/", 0);
    check!(n, matches!(&g, Ok(g) if g.status == 200 && g.head.starts_with(b"HTTP/1.0 200 OK")), "from the host into DeSoOS (hostfwd 58082 -> 8081): {:?}", g.as_ref().map(|g| (g.status, g.body, core::str::from_utf8(&g.head).unwrap_or("?"))));
    let code = wait(pid as u64, 0).map(|(_, c)| c).unwrap_or(999);
    check!(n, code == 0, "httpd exit code {}", code);

    // An address by hand: checked with ARP first (QEMU's router answers for
    // 10.0.2.2 – refused), then a free one (the DHCP lease is released), back
    // to DHCP.
    let r = ask("set 10.0.2.2/24 gw 10.0.2.3");
    check!(n, r.contains("10.0.2.2 is already used by 52:55:0a:00:02:02"), "set to the router's address: {:?}", r.trim());
    check!(n, field(ask("status"), "ip") == "10.0.2.15", "the address changed after a refused set");
    let r = ask("set 10.0.2.300/24");
    check!(n, r.starts_with("set: bad address"), "set with a bad address: {:?}", r.trim());
    let r = ask("set 10.0.2.20/24 gw 10.0.3.1");
    check!(n, r.contains("same subnet"), "set with a gateway off the subnet: {:?}", r.trim());
    let r = ask("set 10.0.2.20/24 gw 10.0.2.2 dns 10.0.2.3");
    check!(n, r.starts_with("address 10.0.2.20/24 set by hand, gateway 10.0.2.2, DNS 10.0.2.3"), "set 10.0.2.20: {:?}", r.trim());
    let st = ask("status");
    check!(n, field(st, "ip") == "10.0.2.20" && field(st, "dhcp") == "off" && num(st, "byhand") == 1 && num(st, "released") == 1, "after set: {:?}", st.lines().last());
    check!(n, st.contains("IPv4 10.0.2.20/24 set by hand (DHCP off)"), "ifconfig text after set");
    let p = ask_stream("ping 10.0.2.2 1");
    check!(n, p.contains("1 sent, 1 received"), "ping from the address set by hand: {:?}", p.trim());
    let narrowed = svc_narrow("net").unwrap_or(0);
    let r = ask_via(narrowed, "set 10.0.2.21/24");
    close(narrowed);
    check!(n, r.contains("administrator request"), "set without admin: {:?}", r.trim());
    let r = ask("dhcp");
    check!(n, r.starts_with("DHCP on"), "back to DHCP: {:?}", r.trim());
    let st = wait_bound();
    check!(n, field(st, "ip") == "10.0.2.15" && num(st, "byhand") == 0 && num(st, "declined") == 0 && num(st, "conflicts") == 0, "DHCP address again: {:?}", st.lines().last());

    // Kill the driver: init restarts it, the new instance works.
    check!(n, kill(pid1) == 0, "kill netd {}", pid1);
    let t = uptime_ms();
    let mut pid2 = 0;
    while uptime_ms() - t < 5000 {
        pid2 = net0_pid();
        if pid2 != 0 && pid2 != pid1 {
            break;
        }
        sleep_ms(20);
    }
    check!(n, pid2 != 0 && pid2 != pid1, "net0 not restarted after kill ({} -> {})", pid1, pid2);
    let st = wait_bound();
    check!(n, field(st, "ip") == "10.0.2.15" && num(st, "acks") == 1, "no DHCP address after the restart: {:?}", st.lines().last());
    let p = ask_stream("ping 10.0.2.2 1");
    check!(n, p.contains("1 sent, 1 received"), "ping after the restart: {:?}", p.trim());
    let st = ask("status");
    check!(n, num(st, "tx") < tx1 && num(st, "rx") >= 1, "the restarted netd must start from zero: {:?}", st.lines().last());

    println!(
        "nettest: {} checks OK, card 52:54:00:12:34:56 link up, DHCP 10.0.2.15/24 (renewed), DNS (13 kinds of answers), TCP (1 MiB in {} ms), narrowed rights, loopback ({} KiB), sandboxed httpd reached from the host, concurrent pings, ARP and ping to 10.0.2.2 answered ({} frames out, {} in), netd killed and restarted (pid {} -> {})",
        n, big_ms, moved / 1024, tx1, rx1, pid1, pid2
    );
    0
}
