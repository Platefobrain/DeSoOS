// The soak start (tests/soak.sh, fw_cfg phase "soak <seconds> <seed> [ram]"): instead of
// the self-tests the kernel runs the soak (`soak.rs`) and counts it as one suite.

pub fn run(secs: u64, seed: u64, ram: bool) -> bool {
    crate::serial_println!("[SOAK TEST] Starting the soak test: {} s, seed {}{}", secs, seed, if ram { ", RAM disk" } else { "" });
    crate::selftest::begin();
    if secs == u64::MAX {
        return false; // bad phase – already reported
    }
    if !super::soak::run(secs, seed, ram) {
        crate::serial_println!("[SOAK TEST] FAIL: the soak did not pass");
        return false;
    }
    crate::serial_println!("[SOAK TEST] soak ended with code 0 PASS");
    crate::selftest::pass();
    true
}
