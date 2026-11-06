// Starting the soak test (/bin/soak, see user/bin/soak.rs): `init test /bin/soak
// <seconds>:<seed>[:ram]` with the handles the real init gets (services, SYSCTL, input,
// USB disks), so everything goes through the real paths.  Its lines go straight to the
// console (serial + screen; not captured – an 8-hour log would not fit in memory).
//
// * tests/soak.sh (QEMU): the fw_cfg phase "soak …" – `test_soak.rs` calls `run` instead of
//   the self-tests.
// * Real hardware: a build with `DESOOS_AUTOSOAK=<seconds>` (`./build.sh --autosoak=S`,
//   `DESOOS_AUTOSOAK=3600 ./make-usb.sh …`) runs it before init, always on a RAM disk – the
//   computer's own disks are not touched; then the system starts as usual and the result
//   stays on the screen.

use super::*;

/// Runs the soak; true = /bin/soak ended with code 0 in time.
#[cfg_attr(not(selftest), allow(dead_code))]
pub fn run(secs: u64, seed: u64, ram: bool) -> bool {
    run_mode(secs, seed, if ram { ":ram" } else { "" })
}

/// `mode`: "" (virtio disk 0), ":ram" (a RAM disk, QEMU), ":hw" (a RAM disk, real hardware).
fn run_mode(secs: u64, seed: u64, mode: &str) -> bool {
    let arg = alloc::format!("{}:{}{}", secs, seed, mode);
    let opts = SpawnOptions { hw_root: true, sysctl: true, input: true, blk: true, ..SpawnOptions::default() };
    let id = match exec("/bin/init", &["init", "test", "/bin/soak", &arg], "/", &opts) {
        Ok(id) => id,
        Err(e) => {
            serial_println!("[SOAK] cannot start /bin/init: {:?}", e);
            return false;
        }
    };
    procs::set_init_pid(id);
    // /bin/soak ends by itself after `secs` (+ the final checkpoint and audit); a margin of
    // 10 minutes plus 5 % for slow machines, then it counts as a hang.
    let deadline = crate::time::uptime_ms() + secs * 1000 + secs * 50 + 600_000;
    let mut hung = false;
    while sched::task_info(id).is_some() {
        if crate::time::uptime_ms() > deadline {
            serial_println!("[SOAK] /bin/soak did not finish in time - stopped");
            let _ = sched::request_exit(id);
            hung = true;
            crate::time::sleep_ms(2000);
            break;
        }
        crate::time::sleep_ms(100);
    }
    procs::set_init_pid(0);
    let kind = exit_info(id).map(|i| i.kind);
    if hung || kind != Some(ExitKind::Exit(0)) {
        serial_println!("[SOAK] init / soak ended with {:?}", kind);
        return false;
    }
    true
}

/// Seconds from the build (`DESOOS_AUTOSOAK`); 0 = off.  At most a week.
pub fn auto_seconds() -> u64 {
    match option_env!("DESOOS_AUTOSOAK") {
        Some(s) => s.trim().parse::<u64>().unwrap_or(0).min(7 * 24 * 3600),
        None => 0,
    }
}

/// A `DESOOS_AUTOSOAK` build: the soak on a RAM disk before init (the seed from the
/// clock, printed by the soak), the verdict in colour at the end; then boot goes on.
pub fn run_auto_from_build() {
    let secs = auto_seconds();
    if secs == 0 {
        return;
    }
    let secs = secs.max(60);
    let seed = crate::drivers::rtc::now().to_unix() as u64 ^ crate::time::uptime_ms();
    crate::console::print_fmt(format_args!("\x1b[1;36m[AUTOSOAK v{}] soak test of {} s on a RAM disk starts in 5 s\x1b[0m\n", crate::shell::VERSION, secs));
    serial_println!("[AUTOSOAK v{}] soak test of {} s on a RAM disk, seed {}", crate::shell::VERSION, secs, seed);
    // Services (netd: DHCP) start with init inside the soak; it waits for them itself.
    crate::time::sleep_ms(5000);
    let ok = run_mode(secs, seed, ":hw");
    crate::console::print_fmt(format_args!(
        "{}[AUTOSOAK v{}] {} - the [RESULT-SOAK] line above; scroll back with Shift+PageUp\x1b[0m\n",
        if ok { "\x1b[1;32m" } else { "\x1b[1;31m" },
        crate::shell::VERSION,
        if ok { "PASS" } else { "FAIL" }
    ));
    serial_println!("[AUTOSOAK v{}] {}", crate::shell::VERSION, if ok { "PASS" } else { "FAIL" });
}
