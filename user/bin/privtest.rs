// privtest – what a program got from whoever started it (V080 stage D: a program run from
// /disk/bin must get exactly what a /bin program typed by hand gets).
//
//   privtest send   one message on slot 3 (which channel the shell gave it – USB DISK TEST)
//   privtest        one line: the kind of every handle in slots 0-15, then the result of a
//                   SYSCTL call (sync, slot 4) and of SYS_TIME_SET (slot 7) – both must be
//                   refused for a program started by the shell
//
// Output: "privtest: handles <slot>:<kind> ...; sysctl refused (<error>); time_set refused
// (<error>)" and code 0; code 1 when either call was allowed.  The line holds nothing that
// differs between two runs (no pid), so USB DISK TEST compares a /bin and a /disk/bin run.
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../lib/deso.rs"]
#[macro_use]
mod deso;

entry!(main);

fn main(args: deso::Args) -> i32 {
    // `privtest send`: one message "privtest" on slot 3 – the test sees on which of the
    // shell's channels it arrives (the administration one or the program one).
    if args.get(1) == Some("send") {
        let r = deso::chan_send(3, b"privtest", 0);
        println!("privtest: send on slot 3: {}", if r == 0 { "sent" } else { deso::strerror(r) });
        return if r == 0 { 0 } else { 1 };
    }
    let mut line = alloc::string::String::from("privtest: handles");
    for slot in 0..16u64 {
        if let Ok((kind, _)) = deso::handle_info(slot) {
            line.push_str(&alloc::format!(" {}:{}", slot, kind));
        }
    }
    let sc = deso::sysctl(deso::SYSCTL, deso::SYSCTL_SYNC, 0, 1);
    let ts = deso::time_set(deso::SETTIME, 1, 1, 0);
    let verdict = |r: i64| if r < 0 { alloc::format!("refused ({})", deso::strerror(r)) } else { alloc::format!("ALLOWED ({})", r) };
    line.push_str(&alloc::format!("; sysctl {}; time_set {}", verdict(sc), verdict(ts)));
    println!("{}", line);
    if sc < 0 && ts < 0 { 0 } else { 1 }
}
