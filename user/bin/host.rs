// host <name> [netN] – the IPv4 addresses of a name, asked from netd's DNS
// resolver (answers are cached by netd).
// Exit code: 0 = found, 2 = not found / no answer, 1 = usage / no service.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

fn main(args: Args) -> i32 {
    let Some(name) = args.get(1) else {
        eprintln!("usage: host <name> [net0]   (e.g. host example.com)");
        return 1;
    };
    let card = args.get(2).unwrap_or("net0");
    let Ok(c) = svc_connect(card) else {
        eprintln!("host: no service {}", card);
        return 1;
    };
    let mut req = [0u8; 300];
    let p = b"resolve ";
    let n = (p.len() + name.len()).min(req.len());
    req[..p.len()].copy_from_slice(p);
    req[p.len()..n].copy_from_slice(&name.as_bytes()[..n - p.len()]);
    let mut out = [0u8; 1024];
    let mut info = RecvInfo::default();
    let r = if chan_send(c, &req[..n], 0) == 0 { chan_recv(c, &mut out, 0, &mut info) } else { -1 };
    close(c);
    if r < 0 {
        eprintln!("host: {} is not running", card);
        return 1;
    }
    let t = core::str::from_utf8(&out[..r as usize]).unwrap_or("");
    print!("{}", t);
    if t.contains(" is ") { 0 } else { 2 }
}
