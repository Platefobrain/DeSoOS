// M16: init – pierwszy proces.  Kernel uruchamia tylko /bin/init; init
// uruchamia shell (/bin/sh) i:
//   * zbiera zakończone procesy (wait) – także sieroty, które kernel
//     przekazuje mu, gdy kończy się ich rodzic,
//   * gdy shell się skończy (exit, kill, błąd), uruchamia go od nowa.
// Init nie czyta klawiatury i nie da się go zabić z user space (kill -> EPERM).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::{STDIO, WAIT_ANY, describe_status, sleep_ms, spawn, strerror, uptime_ms, wait};

entry!(main);

const SHELL: &str = "/bin/sh";

fn start_shell() -> u64 {
    loop {
        let pid = spawn(SHELL, &["sh"], 0, STDIO);
        if pid > 0 {
            return pid as u64;
        }
        eprintln!("init: cannot start {}: {} - retrying in 1 s", SHELL, strerror(pid));
        sleep_ms(1000);
    }
}

fn main(_: desoos::Args) -> i32 {
    println!("init: started (pid {}), starting {}", desoos::getpid(), SHELL);
    let mut shell = start_shell();
    let mut started_at = uptime_ms();
    loop {
        match wait(WAIT_ANY, 0) {
            Ok((pid, status)) if pid == shell => {
                // Shell padający od razu po starcie (np. uszkodzony plik)
                // nie może zająć CPU w kółko.
                if uptime_ms().saturating_sub(started_at) < 1000 {
                    sleep_ms(1000);
                }
                println!("init: shell {} {} - starting a new one", pid, describe_status(status));
                shell = start_shell();
                started_at = uptime_ms();
            }
            Ok(_) => {} // sierota przekazana przez kernel – już sprzątnięta
            Err(e) => {
                // Brak dzieci (nie powinno się zdarzyć – zawsze jest shell).
                eprintln!("init: wait: {}", strerror(e));
                shell = start_shell();
                started_at = uptime_ms();
            }
        }
    }
}
