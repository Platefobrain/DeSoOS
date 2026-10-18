// Common self-test support (only in builds with `--cfg selftest`).
//
// * Each test suite calls `begin()` at the start and `pass()` at the end –
//   `pass()` is reachable only if no `check!` failed
//   (every failure ends the suite early).  `finish()` compares the counters.
// * Automatic mode (./test.sh): QEMU gets the fw_cfg file
//   `opt/desoos/autotest` and the `isa-debug-exit` device (port 0xf4).
//   After the tests (or on a panic / critical exception) the kernel shuts
//   QEMU down itself with an exit code: PASS -> 33, FAIL -> 35 ((value << 1) | 1).
//   Without that file (plain ./run-qemu.sh, real hardware) nothing
//   changes – the shell starts after the tests.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::arch::x86_64::port::{inb, outb, outw};
use crate::serial_println;

static STARTED: AtomicU32 = AtomicU32::new(0);
static PASSED: AtomicU32 = AtomicU32::new(0);
static AUTOTEST: AtomicBool = AtomicBool::new(false);

pub fn begin() {
    STARTED.fetch_add(1, Ordering::SeqCst);
}

pub fn pass() {
    PASSED.fetch_add(1, Ordering::SeqCst);
}

/// Free frames after the processes from previous tests are cleaned up – the
/// baseline for the leak test.  Processes of the previous suite (e.g. killed by
/// #PF) are cleaned up by reap in the idle loop shortly after they end; measuring before
/// the cleanup finished gave MORE free frames at the end of the suite than at the start
/// (a false "frames leaked" in IPC TEST).
/// Waits until the count stays unchanged for 10 consecutive samples 5 ms apart (max 2 s).
/// 3 samples (15 ms) were sometimes too short (IPC TEST ended with MORE free frames
/// than at the start), and the end of a suite checks "no fewer than
/// at the start" – freeing leftovers of the previous suite is not a leak.
pub fn settled_free_frames() -> u64 {
    let mut last = u64::MAX;
    let mut stable = 0;
    for _ in 0..400 {
        crate::sched::reap();
        let now = crate::sched::stack::free_frames_flushed();
        if now == last {
            stable += 1;
            if stable >= 10 {
                return now;
            }
        } else {
            stable = 0;
            last = now;
        }
        crate::time::sleep_ms(5);
    }
    last
}

/// Summary; `true` if all started suites passed.
pub fn finish() -> bool {
    let started = STARTED.load(Ordering::SeqCst);
    let passed = PASSED.load(Ordering::SeqCst);
    let ok = started > 0 && started == passed;
    serial_println!(
        "[DeSoOS] Self-tests: {}/{} suites passed - {}",
        passed,
        started,
        if ok { "ALL PASSED" } else { "FAILED" }
    );
    ok
}

// ------------------------------------------------------------
// QEMU: fw_cfg (automatic mode detection) + isa-debug-exit
// ------------------------------------------------------------

const FW_CFG_SELECTOR: u16 = 0x510;
const FW_CFG_DATA: u16 = 0x511;
const FW_CFG_SIGNATURE: u16 = 0x0000;
const FW_CFG_FILE_DIR: u16 = 0x0019;
const AUTOTEST_FILE: &[u8] = b"opt/desoos/autotest";

const DEBUG_EXIT_PORT: u16 = 0xf4;
const EXIT_PASS: u8 = 0x10; // QEMU exits with code 33
const EXIT_FAIL: u8 = 0x11; // QEMU exits with code 35

fn fw_cfg_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = unsafe { inb(FW_CFG_DATA) };
    }
}

/// Whether QEMU has a fw_cfg file with this name.  On real hardware ports
/// 0x510/0x511 do not exist – the "QEMU" signature will not match.
fn fw_cfg_has_file(name: &[u8]) -> bool {
    let mut sig = [0u8; 4];
    unsafe { outw(FW_CFG_SELECTOR, FW_CFG_SIGNATURE) };
    fw_cfg_bytes(&mut sig);
    if &sig != b"QEMU" {
        return false;
    }

    unsafe { outw(FW_CFG_SELECTOR, FW_CFG_FILE_DIR) };
    let mut count = [0u8; 4];
    fw_cfg_bytes(&mut count);
    let count = u32::from_be_bytes(count).min(1024);
    for _ in 0..count {
        // u32 size, u16 select, u16 reserved, char name[56] (big-endian)
        let mut entry = [0u8; 64];
        fw_cfg_bytes(&mut entry);
        let file = &entry[8..];
        let len = file.iter().position(|&b| b == 0).unwrap_or(file.len());
        if &file[..len] == name {
            return true;
        }
    }
    false
}

/// Checks for automatic mode (once, at startup).
pub fn detect_autotest() {
    let on = fw_cfg_has_file(AUTOTEST_FILE);
    AUTOTEST.store(on, Ordering::SeqCst);
    if on {
        serial_println!("[TEST] Automatic test mode (QEMU will exit after the self-tests)");
    }
}

pub fn autotest() -> bool {
    AUTOTEST.load(Ordering::SeqCst)
}

/// In automatic mode exits QEMU with the result; otherwise does nothing.
pub fn exit_if_autotest(ok: bool) {
    if !autotest() {
        return;
    }
    serial_println!("[TEST] Exiting QEMU: {}", if ok { "PASS" } else { "FAIL" });
    unsafe { outb(DEBUG_EXIT_PORT, if ok { EXIT_PASS } else { EXIT_FAIL }) };
    // Should the device be missing – halt (test.sh will report a timeout).
    loop {
        unsafe { core::arch::asm!("cli; hlt") };
    }
}
