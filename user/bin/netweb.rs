// netweb [-n count] <port> [netN] < page – a minimal web server: the page comes
// from standard input (read once at start, at most 64 KiB), so it also runs in
// the sandbox without any file access:
//     nofiles --listen netweb 8080 < /index.html
// GET / or /index.html -> the page, anything else -> 404.  One request at a
// time (5 s to send it), one log line per request.  -n: exit after that many
// requests (tests).  In QEMU, run-qemu.sh forwards the host's 127.0.0.1:8080 to
// port 8080 of DeSoOS: `curl http://127.0.0.1:8080/` on the host.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const PAGE_MAX: usize = 64 * 1024;
static mut PAGE: [u8; PAGE_MAX] = [0; PAGE_MAX];
static mut MSG: [u8; MSG_MAX] = [0; MSG_MAX];

fn main(args: Args) -> i32 {
    let mut limit = 0u64;
    let mut i = 1;
    if args.get(1) == Some("-n") {
        limit = args.get(2).and_then(|n| n.parse().ok()).unwrap_or(0);
        i = 3;
    }
    let Some(port) = args.get(i).and_then(|p| p.parse::<u16>().ok()) else {
        eprintln!("usage: netweb [-n count] <port> [net0] < page   (e.g. nofiles --listen netweb 8080 < /index.html)");
        return 1;
    };
    let card = args.get(i + 1).unwrap_or("net0");
    let page = unsafe { &mut *core::ptr::addr_of_mut!(PAGE) };
    let mut len = 0;
    while len < PAGE_MAX {
        let r = read(0, &mut page[len..]);
        if r <= 0 {
            break;
        }
        len += r as usize;
    }
    let page = &page[..len];
    let html = page.first() == Some(&b'<');

    let Ok(l) = svc_connect(card) else {
        eprintln!("netweb: no service {}", card);
        return 1;
    };
    let msg = unsafe { &mut *core::ptr::addr_of_mut!(MSG) };
    let mut info = RecvInfo::default();
    let mut req = [0u8; 32];
    let n = put_all(&mut req, &[b"listen ", args.get(i).unwrap_or("0").as_bytes()]);
    let r = if chan_send(l, &req[..n], 0) == 0 { chan_recv(l, msg, 0, &mut info) } else { -1 };
    let reply = if r > 0 { core::str::from_utf8(&msg[..r as usize]).unwrap_or("") } else { "" };
    if !reply.starts_with("listening on port") {
        eprintln!("netweb: {}", if reply.is_empty() { "no answer from netd" } else { reply.trim() });
        return 1;
    }
    println!("netweb: {}, page of {} bytes", reply.trim(), len);
    let _ = port;

    let mut served = 0u64;
    let mut hs = [0u64; 1];
    loop {
        let r = chan_recv_h(l, msg, &mut hs, 0, &mut info);
        if r < 0 {
            eprintln!("netweb: netd closed the listening connection");
            return 1;
        }
        if info.handles != 1 {
            continue;
        }
        let sock = hs[0];
        let who = core::str::from_utf8(&msg[..r as usize]).unwrap_or("").trim().trim_start_matches("accepted ").split(" to ").next().unwrap_or("?");
        let mut who_buf = [0u8; 32];
        let wn = who.len().min(32);
        who_buf[..wn].copy_from_slice(&who.as_bytes()[..wn]);
        let (status, sent) = serve(sock, page, html, msg);
        close(sock);
        served += 1;
        println!("netweb: {} -> {} ({} bytes)", core::str::from_utf8(&who_buf[..wn]).unwrap_or("?"), status, sent);
        if limit > 0 && served >= limit {
            return 0;
        }
    }
}

/// One request on socket `s`; (status text, body bytes sent).
fn serve(s: u64, page: &[u8], html: bool, buf: &mut [u8; MSG_MAX]) -> (&'static str, usize) {
    let mut head = [0u8; 2048];
    let mut hlen = 0;
    let t0 = uptime_ms();
    let mut info = RecvInfo::default();
    while !head[..hlen].windows(4).any(|w| w == b"\r\n\r\n") {
        let left = 5000u64.saturating_sub(uptime_ms() - t0);
        if left == 0 || hlen == head.len() || wait_many(&[(s, W_READABLE)], left) != Ok(1) {
            return ("timeout / bad request", 0);
        }
        let r = chan_recv(s, buf, CHAN_NONBLOCK, &mut info);
        if r < 0 {
            return ("closed", 0);
        }
        let k = (r as usize).min(head.len() - hlen);
        head[hlen..hlen + k].copy_from_slice(&buf[..k]);
        hlen += k;
    }
    let line = head[..hlen].split(|&b| b == b'\r').next().unwrap_or(b"");
    let mut w = line.split(|&b| b == b' ');
    let method = w.next().unwrap_or(b"");
    let path = w.next().unwrap_or(b"");
    let ok = method == b"GET" && (path == b"/" || path == b"/index.html");
    let body: &[u8] = if ok { page } else { b"not here\n" };
    let mut len_txt = [0u8; 20];
    let lt = num(body.len() as u64, &mut len_txt);
    let n = put_all(
        buf,
        &[
            if ok { b"HTTP/1.0 200 OK\r\n".as_slice() } else { b"HTTP/1.0 404 Not Found\r\n" },
            b"Server: DeSoOS-netweb\r\nContent-Type: ",
            if ok && html { b"text/html".as_slice() } else { b"text/plain" },
            b"\r\nContent-Length: ",
            lt,
            b"\r\nConnection: close\r\n\r\n",
        ],
    );
    if chan_send(s, &buf[..n], 0) != 0 {
        return ("closed", 0);
    }
    for c in body.chunks(MSG_MAX) {
        if chan_send(s, c, 0) != 0 {
            return ("closed", 0);
        }
    }
    (if ok { "200" } else { "404" }, body.len())
}

fn put_all(buf: &mut [u8], parts: &[&[u8]]) -> usize {
    let mut n = 0;
    for p in parts {
        let k = p.len().min(buf.len() - n);
        buf[n..n + k].copy_from_slice(&p[..k]);
        n += k;
    }
    n
}

fn num(mut v: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut i = 20;
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    &buf[i..]
}
