// The service protocols' versions (docs/abi/SERVICES.md) – SERVICES TEST runs it through the
// real init (`init test /bin/prototest`, the service channel in slot 3, net0 = netd on the
// test card).  Old and new clients against the real services, and libdeso's version helpers
// against fake services (this program again, `prototest fake svc|net KIND`, the other end of
// a channel in slot 3) that answer like an old service, a newer one, with garbage, with a
// handle, close the channel half-way or never answer.
// Result: "prototest: N checks OK, ..." and exit code 0.
#![no_std]
#![no_main]

#[macro_use]
#[allow(unused_imports)]
extern crate libdeso;
#[allow(unused_imports)]
use libdeso as deso;

use deso::*;

entry!(main);

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("prototest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

/// One request on a channel to init with a reply channel; (answer, then closed?).
fn svc_raw(req: &[u8], buf: &mut [u8]) -> (Result<usize, i64>, bool) {
    let Ok((mine, theirs)) = channel_create() else { return (Err(ERROR_OUT_OF_MEMORY), false) };
    if chan_send_h(SVC, req, &[theirs], 0) != 0 {
        close(mine);
        close(theirs);
        return (Err(ERROR_CLOSED), false);
    }
    let mut info = RecvInfo::default();
    let r = chan_recv(mine, buf, 0, &mut info);
    let first = if r < 0 { Err(r) } else { Ok(r as usize) };
    let closed = r == ERROR_CLOSED || chan_recv(mine, buf, 0, &mut info) == ERROR_CLOSED;
    close(mine);
    (first, closed)
}

/// A request to netd on `c`; the answer as text into `buf`.
fn net_ask<'a>(c: u64, req: &str, buf: &'a mut [u8]) -> Option<&'a str> {
    if chan_send(c, req.as_bytes(), 0) != 0 {
        return None;
    }
    if wait_many(&[(c, W_READABLE)], 10_000) != Ok(1) {
        return None;
    }
    let mut info = RecvInfo::default();
    let r = chan_recv(c, buf, 0, &mut info);
    if r <= 0 {
        return None;
    }
    core::str::from_utf8(&buf[..r as usize]).ok()
}

/// A fake service: this program in slot-3 mode with the other end of a new channel;
/// (our end, its pid).
fn fake(proto: &str, kind: &str) -> Option<(u64, u64)> {
    let (mine, theirs) = channel_create().ok()?;
    let pid = spawn_ex("/bin/prototest", &["prototest", "fake", proto, kind], &[(0, 0), (1, 1), (2, 2), (theirs, 3)], 0);
    close(theirs);
    if pid < 0 {
        close(mine);
        return None;
    }
    Some((mine, pid as u64))
}

fn end_fake(c: u64, pid: u64) {
    close(c);
    kill(pid);
    let _ = wait(pid, 0);
}

/// The fake's side.  svc: one request with a reply handle; net: one request on the
/// connection.  Then, by kind: old, newer, major, garbage, bad, handle, close, silent.
fn serve_fake(proto: &str, kind: &str) -> i32 {
    let mut msg = [0u8; 256];
    let mut hs = [0u64; MSG_HANDLES];
    let mut info = RecvInfo::default();
    let r = chan_recv_h(3, &mut msg, &mut hs, 0, &mut info);
    if r < 0 {
        return 3;
    }
    let svc = proto == "svc";
    // svc answers on the reply handle, net on the connection itself.
    let out = if svc && info.handles == 1 { hs[0] } else { 3 };
    let text: &[u8] = match (svc, kind) {
        (true, "old") => {
            // A manager from before `version`: the reply channel closed, no answer.
            close(out);
            sleep_ms(60_000);
            return 0;
        }
        (false, "old") => b"netd: unknown request \"version\" (status, ping host [count], resolve name, tcp host port, udp host port, listen port, arp a.b.c.d, dns server|auto, renew, set a.b.c.d/nn, dhcp)\n",
        (true, "newer") => b"svc 1.7",
        (false, "newer") => b"net 1.3\n",
        (true, "major") => b"svc 2.0",
        (false, "major") => b"net 2.0\n",
        (_, "garbage") => b"\xff\xfe\x00 not a version \x01",
        (true, "bad") => b"svc 01.0",
        (false, "bad") => b"net 1.x\n",
        (_, "handle") => {
            let (a, b) = channel_create().unwrap_or((0, 0));
            chan_send_h(out, if svc { b"svc 1.0" } else { b"net 1.0\n" }, &[b], 0);
            close(a);
            sleep_ms(60_000);
            return 0;
        }
        (_, "close") => {
            // Half-way: the service's own channel goes first, then the reply.
            close(3);
            sleep_ms(50);
            if out != 3 {
                close(out);
            }
            sleep_ms(60_000);
            return 0;
        }
        _ => {
            // silent: holds everything, never answers.
            sleep_ms(60_000);
            return 0;
        }
    };
    chan_send(out, text, 0);
    sleep_ms(60_000);
    0
}

/// libdeso's version helper against one fake.
fn fake_version(proto: &str, kind: &str, timeout_ms: u64) -> Result<(u16, u16), i64> {
    let Some((c, pid)) = fake(proto, kind) else { return Err(ERROR_NOT_FOUND) };
    let r = if proto == "svc" { svc_version_via(c, timeout_ms) } else { net_version(c, timeout_ms) };
    end_fake(c, pid);
    r
}

fn main(args: Args) -> i32 {
    if args.get(1) == Some("fake") {
        return serve_fake(args.get(2).unwrap_or(""), args.get(3).unwrap_or(""));
    }
    let mut n = 0;
    let mut buf = [0u8; MSG_MAX];

    // The service manager.  An old client: list and connect as before.
    let mut list = [0u8; 2048];
    let l = svc_list(&mut list).unwrap_or(0);
    let text = core::str::from_utf8(&list[..l]).unwrap_or("");
    check!(n, text.contains("net0 ") && text.contains("echo "), "svc list: {:?}", text);
    // A new client: version.
    check!(n, svc_version() == Ok((1, 0)), "svc version: {:?}", svc_version());
    // An unknown request: answered "unknown request", the reply channel closed, the service
    // channel still works.
    let (r, closed) = svc_raw(b"bogus", &mut buf);
    check!(n, r.map(|k| &buf[..k] == b"unknown request") == Ok(true) && closed, "unknown request: {:?} closed {}", r, closed);
    check!(n, svc_version() == Ok((1, 0)), "the service channel after an unknown request");
    // An unknown field: "version 2" is not "version"; connect with an extra word finds no
    // service (closed without an answer, as for any unknown name).
    let (r, closed) = svc_raw(b"version 2", &mut buf);
    check!(n, r.map(|k| &buf[..k] == b"unknown request") == Ok(true) && closed, "\"version 2\": {:?}", r);
    let (r, closed) = svc_raw(b"connect net0 extra", &mut buf);
    check!(n, r == Err(ERROR_CLOSED) && closed, "\"connect net0 extra\": {:?}", r);
    check!(n, svc_list(&mut list).is_ok_and(|k| k == l), "the service list after the bad requests");

    // Fake managers.
    check!(n, fake_version("svc", "old", 2000) == Ok((1, 0)), "an old manager (reply channel closed, no answer) = 1.0: {:?}", fake_version("svc", "old", 2000));
    check!(n, fake_version("svc", "newer", 2000) == Ok((1, 7)), "svc 1.7");
    check!(n, fake_version("svc", "major", 2000) == Ok((2, 0)), "svc 2.0");
    check!(n, fake_version("svc", "garbage", 2000) == Err(ERROR_IO), "garbage: {:?}", fake_version("svc", "garbage", 2000));
    check!(n, fake_version("svc", "bad", 2000) == Err(ERROR_IO), "\"svc 01.0\"");
    check!(n, fake_version("svc", "handle", 2000) == Err(ERROR_IO), "an answer with a handle");
    check!(n, fake_version("svc", "close", 2000) == Err(ERROR_CLOSED), "closed half-way: {:?}", fake_version("svc", "close", 2000));
    let t0 = uptime_ms();
    let r = fake_version("svc", "silent", 500);
    let took = uptime_ms() - t0;
    check!(n, r == Err(ERROR_TIMED_OUT) && (450..5000).contains(&took), "a silent manager: {:?} after {} ms", r, took);

    // The network service (net0 starts with init – wait for it).
    let t0 = uptime_ms();
    let c = loop {
        if let Ok(c) = svc_connect("net0") {
            if net_ask(c, "status", &mut buf).is_some_and(|s| s.starts_with("net0: ")) {
                break c;
            }
            close(c);
        }
        if uptime_ms() - t0 > 30_000 {
            println!("prototest: FAIL: net0 does not answer status");
            return 1;
        }
        sleep_ms(200);
    };
    n += 1; // an old client: status
    check!(n, net_version(c, 2000) == Ok((1, 0)), "net version: {:?}", net_version(c, 2000));
    check!(n, net_ask(c, "status", &mut buf).is_some_and(|s| s.starts_with("net0: ")), "status after version");
    check!(n, net_ask(c, "bogus", &mut buf).is_some_and(|s| s.starts_with("netd: unknown request \"bogus\"")), "unknown request");
    check!(n, net_ask(c, "status extra", &mut buf).is_some_and(|s| s.starts_with("netd: unknown request")), "unknown field");
    check!(n, net_ask(c, "version", &mut buf) == Some("net 1.0\n"), "the connection after the bad requests");
    close(c);

    // Fake netds.
    check!(n, fake_version("net", "old", 2000) == Ok((1, 0)), "an old netd (unknown request) = 1.0");
    check!(n, fake_version("net", "newer", 2000) == Ok((1, 3)), "net 1.3");
    check!(n, fake_version("net", "major", 2000) == Ok((2, 0)), "net 2.0");
    check!(n, fake_version("net", "garbage", 2000) == Err(ERROR_IO), "garbage");
    check!(n, fake_version("net", "bad", 2000) == Err(ERROR_IO), "\"net 1.x\"");
    check!(n, fake_version("net", "handle", 2000) == Err(ERROR_IO), "an answer with a handle");
    check!(n, fake_version("net", "close", 2000) == Err(ERROR_CLOSED), "closed half-way");
    let t0 = uptime_ms();
    let r = fake_version("net", "silent", 500);
    let took = uptime_ms() - t0;
    check!(n, r == Err(ERROR_TIMED_OUT) && (450..5000).contains(&took), "a silent netd: {:?} after {} ms", r, took);

    println!(
        "prototest: {} checks OK, svc 1.0 and net 1.0; old clients unchanged; unknown request / field answered, channels alive; fakes: old = 1.0, 1.7 / 1.3 / 2.0 read, garbage / bad / a handle = ERROR_IO, closed half-way = ERROR_CLOSED, silent = ERROR_TIMED_OUT",
        n
    );
    0
}
