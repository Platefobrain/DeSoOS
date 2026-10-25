// ping <address or name> [count] [netN] – asks netd to send ICMP echo requests
// (one per second, default 4) and prints each answer as it comes, then a
// summary.  A name is looked up first (DNS, through netd).
// Exit code: 0 = at least one answer, 2 = none, 1 = usage / no service.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

fn main(args: Args) -> i32 {
    let Some(ip) = args.get(1) else {
        eprintln!("usage: ping <address or name> [count] [net0]   (in QEMU: ping 10.0.2.2 - the virtual router)");
        return 1;
    };
    let count = args.get(2).unwrap_or("4");
    if count.parse::<u16>().is_err() {
        eprintln!("ping: count must be a number 1-100, not {:?}", count);
        return 1;
    }
    let card = args.get(3).unwrap_or("net0");
    let Ok(c) = svc_connect(card) else {
        eprintln!("ping: no service {}", card);
        return 1;
    };
    let mut req = [0u8; 300];
    let mut n = 0;
    for part in [b"ping ".as_slice(), ip.as_bytes(), b" ", count.as_bytes()] {
        let k = part.len().min(req.len() - n);
        req[n..n + k].copy_from_slice(&part[..k]);
        n += k;
    }
    if chan_send(c, &req[..n], 0) != 0 {
        eprintln!("ping: {} is not running", card);
        close(c);
        return 1;
    }
    // netd streams lines as answers come; the last message ends with "ping-end".
    let mut answers = 0;
    let mut out = [0u8; 1024];
    let mut info = RecvInfo::default();
    loop {
        let r = chan_recv(c, &mut out, 0, &mut info);
        if r < 0 {
            eprintln!("ping: {}: {}", card, strerror(r));
            close(c);
            return 1;
        }
        let t = core::str::from_utf8(&out[..r as usize]).unwrap_or("");
        let mut end = false;
        for l in t.lines() {
            if l == "ping-end" {
                end = true;
                continue;
            }
            if l.contains(" bytes from ") {
                answers += 1;
            }
            println!("{}", l);
        }
        if end {
            break;
        }
    }
    close(c);
    if answers > 0 { 0 } else { 2 }
}
