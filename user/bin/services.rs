// M19.g: services – stan usług uruchomionych przez init (menedżer usług).
// Pyta init przez kanał w slocie 3 ("list") i wypisuje odpowiedź:
//   nazwa  stan  pid  restarty  program
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

fn main(_args: Args) -> i32 {
    if handle_info(SVC).map(|(k, _)| k) != Ok(KIND_CHANNEL) {
        eprintln!("services: no service manager channel (slot 3) - run from the shell started by init");
        return 1;
    }
    let mut buf = [0u8; 2048];
    let n = match svc_list(&mut buf) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("services: {}", strerror(e));
            return 1;
        }
    };
    let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
    println!("{:<8} {:<11} {:>5} {:>8}  {}", "SERVICE", "STATE", "PID", "RESTARTS", "PROGRAM");
    for line in text.lines() {
        // "nazwa stan pid N restarts N (program)"; stan może mieć spację ("no device").
        let Some((head, prog)) = line.rsplit_once(" (") else { continue };
        let prog = prog.trim_end_matches(')');
        let Some((head, restarts)) = head.rsplit_once(" restarts ") else { continue };
        let Some((head, pid)) = head.rsplit_once(" pid ") else { continue };
        let Some((name, state)) = head.split_once(' ') else { continue };
        let pid = if pid == "0" { "-" } else { pid };
        println!("{:<8} {:<11} {:>5} {:>8}  {}", name, state, pid, restarts, prog);
    }
    0
}
