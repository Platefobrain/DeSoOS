// usblist – USB devices on all controllers.  Sends a "list" request to every
// usbN service (via init, svc channel in slot 3); usbd replies with one line per
// device: port, VID:PID, speed, USB version, address, kind, interface
// classes, manufacturer and product (from the device's strings).
// `usblist -v`: also the controller line (version, ports, BIOS handoff and its timing).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

fn main(args: Args) -> i32 {
    let verbose = args.get(1) == Some("-v");
    if handle_info(SVC).map(|(k, _)| k) != Ok(KIND_CHANNEL) {
        eprintln!("usblist: no service manager channel (slot 3) - run from the shell started by init");
        return 1;
    }
    let mut buf = [0u8; 2048];
    let n = match svc_list(&mut buf) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("usblist: {}", strerror(e));
            return 1;
        }
    };
    let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
    let mut controllers = 0;
    let mut devices = 0;
    let mut out = [0u8; MSG_MAX];
    for line in text.lines() {
        let mut w = line.split(' ');
        let name = w.next().unwrap_or("");
        if !name.starts_with("usb") {
            continue;
        }
        controllers += 1;
        if w.next() != Some("running") {
            println!("{}: not running ({})", name, line);
            continue;
        }
        let Ok(c) = svc_connect(name) else {
            println!("{}: no connection", name);
            continue;
        };
        if verbose && chan_send(c, b"status", 0) == 0 {
            let mut info = RecvInfo::default();
            let r = chan_recv(c, &mut out, 0, &mut info);
            if r >= 0 {
                let t = core::str::from_utf8(&out[..r as usize]).unwrap_or("");
                // The first line is the description; the rest is for tests.
                println!("{}", t.lines().next().unwrap_or(""));
            }
        }
        let mut ok = false;
        if chan_send(c, b"list", 0) == 0 {
            let mut info = RecvInfo::default();
            let r = chan_recv(c, &mut out, 0, &mut info);
            if r >= 0 {
                ok = true;
                let t = core::str::from_utf8(&out[..r as usize]).unwrap_or("");
                for l in t.lines() {
                    println!("{}", l);
                    devices += 1;
                }
            }
        }
        if !ok {
            println!("{}: no answer", name);
        }
        close(c);
    }
    if controllers == 0 {
        println!("usblist: no USB controllers (no usbN services)");
    } else if devices == 0 {
        println!("usblist: {} controller(s), no devices", controllers);
    }
    0
}
