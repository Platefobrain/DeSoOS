// The soak start (tests/soak.sh, fw_cfg phase "soak <seconds> <seed>"): instead of the
// self-tests the kernel starts `init test /bin/soak <seconds>:<seed>` with the handles the
// real init gets.  init starts the services from /etc/services, /bin/soak runs its workers
// and checkpoints and prints its lines straight to the serial port (not captured – an
// 8-hour log would not fit in memory).  PASS = /bin/soak ended with code 0 in time.

use super::*;

pub fn run(secs: u64, seed: u64) -> bool {
    serial_println!("[SOAK TEST] Starting the soak test: {} s, seed {}", secs, seed);
    crate::selftest::begin();
    if secs == u64::MAX {
        return false; // bad phase – already reported
    }
    let arg = alloc::format!("{}:{}", secs, seed);
    let opts = SpawnOptions { hw_root: true, sysctl: true, input: true, blk: true, ..SpawnOptions::default() };
    let id = match exec("/bin/init", &["init", "test", "/bin/soak", &arg], "/", &opts) {
        Ok(id) => id,
        Err(e) => {
            serial_println!("[SOAK TEST] FAIL: cannot start /bin/init: {:?}", e);
            return false;
        }
    };
    procs::set_init_pid(id);
    // /bin/soak ends by itself after `secs` (+ the final checkpoint and audit); a margin of
    // 10 minutes plus 5 % for slow hosts, then it counts as a hang.
    let deadline = crate::time::uptime_ms() + secs * 1000 + secs * 50 + 600_000;
    while sched::task_info(id).is_some() {
        if crate::time::uptime_ms() > deadline {
            serial_println!("[SOAK TEST] FAIL: /bin/soak did not finish in time");
            let _ = sched::request_exit(id);
            return false;
        }
        crate::time::sleep_ms(100);
    }
    procs::set_init_pid(0);
    let kind = exit_info(id).map(|i| i.kind);
    if kind != Some(ExitKind::Exit(0)) {
        serial_println!("[SOAK TEST] FAIL: init / soak ended with {:?}", kind);
        return false;
    }
    serial_println!("[SOAK TEST] soak ended with code 0 PASS");
    crate::selftest::pass();
    true
}
