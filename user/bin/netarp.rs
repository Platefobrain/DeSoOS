// netarp <a.b.c.d> [netN] – asks netd to send an ARP request for the address and
// prints the answer (the MAC address of the machine with that IP) or "no reply".
// The lowest-level network test: one frame out, one frame back.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

fn main(args: Args) -> i32 {
    let Some(ip) = args.get(1) else {
        eprintln!("usage: netarp <a.b.c.d> [net0]   (in QEMU: netarp 10.0.2.2 - the virtual router)");
        return 1;
    };
    let card = args.get(2).unwrap_or("net0");
    let Ok(c) = svc_connect(card) else {
        eprintln!("netarp: no service {}", card);
        return 1;
    };
    let mut req = [0u8; 64];
    let p = b"arp ";
    let n = (p.len() + ip.len()).min(req.len());
    req[..p.len()].copy_from_slice(p);
    req[p.len()..n].copy_from_slice(&ip.as_bytes()[..n - p.len()]);
    let mut out = [0u8; 512];
    let mut info = RecvInfo::default();
    if chan_send(c, &req[..n], 0) != 0 {
        eprintln!("netarp: {} is not running", card);
        return 1;
    }
    let r = chan_recv(c, &mut out, 0, &mut info);
    close(c);
    if r < 0 {
        eprintln!("netarp: {}: {}", card, strerror(r));
        return 1;
    }
    let t = core::str::from_utf8(&out[..r as usize]).unwrap_or("");
    print!("{}", t);
    if t.contains("is-at") { 0 } else { 2 }
}
