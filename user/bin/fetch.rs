// fetch [-o file] [-v] http://host[:port]/path [netN] – downloads a page over
// HTTP/1.0 through netd's TCP: "tcp host port", then the request, then everything
// until the server closes.  The body goes to the console (or to a file with -o);
// a summary (status, bytes, time, speed) to stderr.  -v also prints the headers.
// Exit code: 0 = 2xx and complete, 2 = connection failed, 3 = cut short (fewer
// bytes than Content-Length), 4 = HTTP error status, 1 = usage.
// https:// is refused – it needs TLS, which DeSoOS does not have yet.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const HEAD_MAX: usize = 8192;

static mut MSG: [u8; MSG_MAX] = [0; MSG_MAX];
static mut HEAD: [u8; HEAD_MAX] = [0; HEAD_MAX];

struct Url<'a> {
    host: &'a str,
    port: u16,
    path: &'a str,
}

fn parse_url(u: &str) -> Result<Url<'_>, &'static str> {
    if u.starts_with("https://") {
        return Err("https needs TLS - not supported yet (use http://)");
    }
    let Some(rest) = u.strip_prefix("http://") else { return Err("the address must start with http://") };
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok().filter(|&p| p != 0).ok_or("bad port")?),
        None => (hostport, 80),
    };
    if host.is_empty() || host.len() > 253 || path.len() > 1024 || path.bytes().any(|b| b <= b' ' || b == 0x7F) {
        return Err("bad host or path");
    }
    Ok(Url { host, port, path })
}

fn main(args: Args) -> i32 {
    let mut out_path: Option<&str> = None;
    let mut verbose = false;
    let mut url = None;
    let mut card = "net0";
    let mut i = 1;
    while let Some(a) = args.get(i) {
        match a {
            "-o" => {
                i += 1;
                out_path = args.get(i);
            }
            "-v" => verbose = true,
            _ if url.is_none() => url = Some(a),
            _ => card = a,
        }
        i += 1;
    }
    let Some(url) = url else {
        eprintln!("usage: fetch [-o file] [-v] http://host[:port]/path [net0]");
        return 1;
    };
    let u = match parse_url(url) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("fetch: {}", e);
            return 1;
        }
    };
    let out_fd = match out_path {
        Some(p) => {
            let fd = open(p, O_WRITE | O_CREATE | O_TRUNC);
            if fd < 0 {
                eprintln!("fetch: cannot create {}: {}", p, strerror(fd));
                return 1;
            }
            fd as u64
        }
        None => 1,
    };
    let Ok(c) = svc_connect(card) else {
        eprintln!("fetch: no service {}", card);
        return 2;
    };
    let msg = unsafe { &mut *core::ptr::addr_of_mut!(MSG) };
    let head = unsafe { &mut *core::ptr::addr_of_mut!(HEAD) };
    let mut info = RecvInfo::default();
    let t0 = uptime_ms();

    // 1. The connection.
    let mut n = 0;
    let put = |b: &[u8], buf: &mut [u8], n: &mut usize| {
        let k = b.len().min(buf.len() - *n);
        buf[*n..*n + k].copy_from_slice(&b[..k]);
        *n += k;
    };
    let mut port_txt = [0u8; 6];
    let port_s = num_text(u.port as u64, &mut port_txt);
    put(b"tcp ", msg, &mut n);
    put(u.host.as_bytes(), msg, &mut n);
    put(b" ", msg, &mut n);
    put(port_s, msg, &mut n);
    if chan_send(c, &msg[..n], 0) != 0 {
        eprintln!("fetch: {} is not running", card);
        return 2;
    }
    let r = chan_recv(c, msg, 0, &mut info);
    let reply = if r > 0 { core::str::from_utf8(&msg[..r as usize]).unwrap_or("") } else { "" };
    if !reply.starts_with("connected ") {
        eprintln!("fetch: {}", if reply.is_empty() { "no answer from netd" } else { reply.trim().trim_start_matches("tcp: ") });
        close(c);
        return 2;
    }
    if verbose {
        eprintln!("fetch: {}", reply.trim());
    }

    // 2. The request.
    let mut n = 0;
    put(b"GET ", msg, &mut n);
    put(u.path.as_bytes(), msg, &mut n);
    put(b" HTTP/1.0\r\nHost: ", msg, &mut n);
    put(u.host.as_bytes(), msg, &mut n);
    if u.port != 80 {
        put(b":", msg, &mut n);
        put(port_s, msg, &mut n);
    }
    put(b"\r\nUser-Agent: DeSoOS-fetch\r\nConnection: close\r\n\r\n", msg, &mut n);
    if chan_send(c, &msg[..n], 0) != 0 {
        eprintln!("fetch: connection closed before the request was sent");
        close(c);
        return 2;
    }

    // 3. The answer: headers, then the body until the server closes.
    let mut hlen = 0;
    let mut in_body = false;
    let mut status = 0u32;
    let mut length: Option<u64> = None;
    let mut body = 0u64;
    loop {
        let r = chan_recv(c, msg, 0, &mut info);
        if r < 0 {
            break; // EPIPE: the server closed (or the connection ended)
        }
        let mut data = &msg[..r as usize];
        if !in_body {
            let k = data.len().min(HEAD_MAX - hlen);
            head[hlen..hlen + k].copy_from_slice(&data[..k]);
            let end = find(&head[..hlen + k], b"\r\n\r\n");
            match end {
                Some(e) => {
                    let used = e + 4 - hlen; // bytes of this message that were header
                    let h = core::str::from_utf8(&head[..e]).unwrap_or("");
                    if verbose {
                        eprintln!("{}", h);
                    }
                    let mut lines = h.split("\r\n");
                    let first = lines.next().unwrap_or("");
                    status = first.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    if !first.starts_with("HTTP/1.") || status == 0 {
                        eprintln!("fetch: not an HTTP answer: {:?}", first);
                        close(c);
                        return 4;
                    }
                    for l in lines {
                        if let Some((k, v)) = l.split_once(':') {
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                length = v.trim().parse().ok();
                            }
                        }
                    }
                    in_body = true;
                    data = &data[used..];
                }
                None => {
                    hlen += k;
                    if hlen == HEAD_MAX {
                        eprintln!("fetch: headers longer than {} bytes", HEAD_MAX);
                        close(c);
                        return 4;
                    }
                    continue;
                }
            }
        }
        if !data.is_empty() {
            body += data.len() as u64;
            if write(out_fd, data) < 0 {
                eprintln!("fetch: write failed");
                close(c);
                return 1;
            }
        }
    }
    close(c);
    if out_fd != 1 {
        close(out_fd);
    }
    let ms = (uptime_ms() - t0).max(1);
    if !in_body {
        eprintln!("fetch: the server closed without an answer");
        return 2;
    }
    let kbs = body * 1000 / ms / 1024;
    if let Some(len) = length {
        if body < len {
            eprintln!("fetch: cut short - {} of {} bytes, then the connection ended", body, len);
            return 3;
        }
    }
    eprintln!("fetch: HTTP {}, {} bytes in {} ms ({} KiB/s)", status, body, ms, kbs);
    if (200..300).contains(&status) { 0 } else { 4 }
}

fn find(h: &[u8], pat: &[u8]) -> Option<usize> {
    h.windows(pat.len()).position(|w| w == pat)
}

fn num_text(mut v: u64, buf: &mut [u8; 6]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 || i == 0 {
            break;
        }
    }
    &buf[i..]
}
