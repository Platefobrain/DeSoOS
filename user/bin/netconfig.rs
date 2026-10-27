// netconfig – network cards: for every netN service (via init, svc channel in
// slot 3) asks netd for "status" and prints its description: card, MAC address,
// link, IPv4 address from DHCP, frame counters.  `netconfig -v` also prints the
// machine line (tests); `netconfig renew [netN]` renews the DHCP lease now;
// `netconfig dns <a.b.c.d[:port]|auto> [netN]` sets the DNS server by hand / back
// to the one from DHCP; `netconfig set a.b.c.d/nn [gw a.b.c.d] [dns a.b.c.d]` – an
// address by hand (checked with ARP first, DHCP off); `netconfig dhcp` – back to DHCP;
// `netconfig rxrestart` – (diagnosis, some cards) set the receive ring up again.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

fn main(args: Args) -> i32 {
    let cmd = args.get(1).unwrap_or("");
    if cmd == "renew" || cmd == "dns" || cmd == "set" || cmd == "dhcp" || cmd == "rxrestart" {
        let mut req = [0u8; 160];
        let mut n = 0;
        // The rest of the words go to netd as they are; a last word "netN" picks
        // the card.
        let mut words = [""; 8];
        let mut nw = 0;
        let mut i = 2;
        while let Some(a) = args.get(i) {
            if nw < words.len() {
                words[nw] = a;
                nw += 1;
            }
            i += 1;
        }
        let card = if nw > 0 && words[nw - 1].starts_with("net") {
            nw -= 1;
            words[nw]
        } else {
            "net0"
        };
        if (cmd == "dns" || cmd == "set") && nw == 0 {
            eprintln!("usage: netconfig dns <a.b.c.d[:port] | auto>   |   netconfig set a.b.c.d/nn [gw a.b.c.d] [dns a.b.c.d]   |   netconfig dhcp   |   netconfig renew");
            return 1;
        }
        let mut put = |b: &[u8], req: &mut [u8; 160]| {
            let k = b.len().min(req.len() - n);
            req[n..n + k].copy_from_slice(&b[..k]);
            n += k;
        };
        put(cmd.as_bytes(), &mut req);
        for w in &words[..nw] {
            put(b" ", &mut req);
            put(w.as_bytes(), &mut req);
        }
        let Ok(c) = svc_connect(card) else {
            eprintln!("netconfig: no service {}", card);
            return 1;
        };
        let mut out = [0u8; 512];
        let mut info = RecvInfo::default();
        let r = if chan_send(c, &req[..n], 0) == 0 { chan_recv(c, &mut out, 0, &mut info) } else { -1 };
        close(c);
        if r < 0 {
            eprintln!("netconfig: {} is not running", card);
            return 1;
        }
        let t = core::str::from_utf8(&out[..r as usize]).unwrap_or("");
        print!("{}", t);
        let ok = t.starts_with("renewed") || t.starts_with("DNS server ") || t.starts_with("address ") || t.starts_with("DHCP on") || t.starts_with("rx restarted");
        return if ok { 0 } else { 2 };
    }
    let verbose = args.get(1) == Some("-v");
    let mut buf = [0u8; 2048];
    let n = match svc_list(&mut buf) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("netconfig: {} (run from the shell started by init)", strerror(e));
            return 1;
        }
    };
    let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
    let mut cards = 0;
    let mut out = [0u8; MSG_MAX];
    for line in text.lines() {
        let mut w = line.split_whitespace();
        let name = w.next().unwrap_or("");
        if !name.starts_with("net") {
            continue;
        }
        cards += 1;
        let state = w.next().unwrap_or("?");
        if state != "running" {
            println!("{}: {}", name, line[name.len()..].trim());
            continue;
        }
        let Ok(c) = svc_connect(name) else {
            println!("{}: no connection", name);
            continue;
        };
        let mut info = RecvInfo::default();
        if chan_send(c, b"status", 0) == 0 {
            let r = chan_recv(c, &mut out, 0, &mut info);
            if r >= 0 {
                let t = core::str::from_utf8(&out[..r as usize]).unwrap_or("");
                for l in t.lines() {
                    if verbose || !l.starts_with("netd-status") {
                        println!("{}", l);
                    }
                }
            } else {
                println!("{}: no answer", name);
            }
        }
        close(c);
    }
    if cards == 0 {
        println!("netconfig: no network cards (no netN services)");
    }
    0
}
