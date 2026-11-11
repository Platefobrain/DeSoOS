// udpsend [-t ms] host port text [netN] – one UDP datagram through netd, then the answers
// until the time runs out (default 2000 ms): each answer to stdout (as it came, with a line
// end), a summary to stderr.  Needs the "udp" right (programs of the shell have it;
// sandboxed ones only with `nofiles --udp`).
//
// Exit code: 0 = at least one answer, 2 = usage, no udp right, unknown name, refused
// destination or a local send error, 3 = no answer in time (also a closed port – netd
// ignores ICMP errors, they are easy to forge).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

fn main(args: Args) -> i32 {
    let usage = "usage: udpsend [-t ms] host port text [net0]";
    let mut i = 1;
    let mut wait_ms: u64 = 2000;
    if args.get(1) == Some("-t") {
        match args.get(2).and_then(|t| t.parse::<u64>().ok()).filter(|&t| (1..=60_000).contains(&t)) {
            Some(t) => wait_ms = t,
            None => {
                eprintln!("{} (-t: 1-60000 ms)", usage);
                return 2;
            }
        }
        i = 3;
    }
    let (Some(host), Some(port), Some(text)) = (args.get(i), args.get(i + 1).and_then(|p| p.parse::<u16>().ok()).filter(|&p| p != 0), args.get(i + 2)) else {
        eprintln!("{}", usage);
        return 2;
    };
    let card = args.get(i + 3).unwrap_or("net0");
    if text.len() > UDP_MAX {
        eprintln!("udpsend: the text is longer than {} bytes (one datagram)", UDP_MAX);
        return 2;
    }
    let mut reply = [0u8; 512];
    let c = match udp_open_via(SVC, card, host, port, &mut reply) {
        Ok(c) => c,
        Err(n) => {
            eprintln!("udpsend: {}", core::str::from_utf8(&reply[..n]).unwrap_or("?").trim());
            return 2;
        }
    };
    let t0 = uptime_ms();
    if udp_send(c, text.as_bytes()) != 0 {
        eprintln!("udpsend: could not send");
        close(c);
        return 2;
    }
    let mut got = 0u32;
    let mut first_ms = 0;
    let mut buf = [0u8; MSG_MAX];
    let mut info = RecvInfo::default();
    loop {
        let left = (t0 + wait_ms).saturating_sub(uptime_ms());
        if left == 0 || !matches!(wait_many(&[(c, W_READABLE)], left), Ok(m) if m != 0) {
            break;
        }
        let r = chan_recv(c, &mut buf, CHAN_NONBLOCK, &mut info);
        if r < 0 {
            break;
        }
        if got == 0 {
            first_ms = uptime_ms() - t0;
        }
        got += 1;
        write(1, &buf[..r as usize]);
        write(1, b"\n");
    }
    close(c);
    if got == 0 {
        eprintln!("udpsend: no answer in {} ms", wait_ms);
        return 3;
    }
    eprintln!("udpsend: {} answer(s), the first in {} ms", got, first_ms);
    0
}
