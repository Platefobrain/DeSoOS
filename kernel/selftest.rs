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
// * Restart phase: tests/test.sh starts QEMU a second time on the same test disk with
//   the fw_cfg file `opt/desoos/phase` = "restart"; then only RESTART TEST part 2 runs
//   (DeSoFS written in the first start must be there, mounted at /disk by itself).
// * Soak phase (tests/soak.sh): `opt/desoos/phase` = "soak <seconds> <seed> [ram]"; the boot
//   tests are skipped and `init test /bin/soak <seconds>:<seed>[:ram]` runs instead – all workers
//   at once for hours, checkpoints for leaks and DeSoFS (user/bin/soak.rs).
// * Loop mode (`LOOP=nobkl:400 tests/test.sh`): the fw_cfg file `opt/desoos/loop`
//   holds "suite:rounds".  The suites up to SMP start run once (the system needs
//   them), then only the named suite runs, round after round, until a round fails;
//   the others are skipped.  Result: "[RESULT-LOOP] suite=… rounds=… passed=… …".
//   For rare failures that show up once in hundreds of runs.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::arch::x86_64::port::{inb, outb, outw};
use crate::serial_println;

static STARTED: AtomicU32 = AtomicU32::new(0);
static PASSED: AtomicU32 = AtomicU32::new(0);
static AUTOTEST: AtomicBool = AtomicBool::new(false);
static RESTART: AtomicBool = AtomicBool::new(false);
/// Soak phase: its length in seconds (0 = not a soak start) and the seed.
static SOAK_SECS: AtomicU64 = AtomicU64::new(0);
static SOAK_SEED: AtomicU64 = AtomicU64::new(0);
static SOAK_RAM: AtomicBool = AtomicBool::new(false);

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
const LOOP_FILE: &[u8] = b"opt/desoos/loop";
/// "restart": the second start of tests/test.sh – only RESTART TEST part 2 runs.
const PHASE_FILE: &[u8] = b"opt/desoos/phase";

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
    fw_cfg_find(name).is_some()
}

/// (size, selector) of a fw_cfg file.
fn fw_cfg_find(name: &[u8]) -> Option<(u32, u16)> {
    let mut sig = [0u8; 4];
    unsafe { outw(FW_CFG_SELECTOR, FW_CFG_SIGNATURE) };
    fw_cfg_bytes(&mut sig);
    if &sig != b"QEMU" {
        return None;
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
            let size = u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let select = u16::from_be_bytes([entry[4], entry[5]]);
            return Some((size, select));
        }
    }
    None
}

// ------------------------------------------------------------
// Loop mode
// ------------------------------------------------------------

/// The suite to repeat (name, at most 15 bytes) and the number of rounds.
#[derive(Clone, Copy)]
struct LoopSpec {
    name: [u8; 16],
    len: usize,
    rounds: u32,
}

static mut LOOP: Option<LoopSpec> = None;

/// Reads `opt/desoos/loop` ("suite:rounds") – once, at startup, on one CPU.
fn detect_loop() {
    let Some((size, select)) = fw_cfg_find(LOOP_FILE) else { return };
    let mut buf = [0u8; 32];
    let n = (size as usize).min(buf.len());
    unsafe { outw(FW_CFG_SELECTOR, select) };
    fw_cfg_bytes(&mut buf[..n]);
    let text = core::str::from_utf8(&buf[..n]).unwrap_or("").trim_matches(|c: char| c == '\0' || c.is_whitespace());
    let (name, rounds) = text.split_once(':').unwrap_or((text, "100"));
    let rounds = rounds.parse::<u32>().unwrap_or(0);
    if name.is_empty() || name.len() > 15 || rounds == 0 {
        serial_println!("[LOOP] bad loop request {:?} (expected suite:rounds, e.g. nobkl:400)", text);
        return;
    }
    let mut spec = LoopSpec { name: [0; 16], len: name.len(), rounds };
    spec.name[..name.len()].copy_from_slice(name.as_bytes());
    unsafe { LOOP = Some(spec) };
    serial_println!("[LOOP] loop mode: suite {} x {}", name, rounds);
}

fn loop_spec() -> Option<LoopSpec> {
    unsafe { *core::ptr::addr_of!(LOOP) }
}

/// Whether loop mode is on (the boot suites still run once).
pub fn looping() -> bool {
    loop_spec().is_some()
}

/// The suite names loop mode accepts (they run after SMP start and can repeat).  SVC TEST
/// is not among them: the `edu` test device keeps state from the first round.
pub const LOOPABLE: &[&str] = &["smp", "lock", "tlb", "alloc", "nobkl", "files", "ipc", "rights", "crypto", "desofs"];

/// Runs a repeatable suite: once normally; in loop mode only the named suite,
/// `rounds` times, stopping at the first failed round.
pub fn suite(name: &str, run: fn()) {
    let Some(spec) = loop_spec() else {
        run();
        return;
    };
    let wanted = core::str::from_utf8(&spec.name[..spec.len]).unwrap_or("");
    if wanted != name {
        return;
    }
    let (mut min, mut max, mut total) = (u64::MAX, 0u64, 0u64);
    let (mut passed, mut ran) = (0u32, 0u32);
    for round in 1..=spec.rounds {
        serial_println!("[LOOP] {} round {}/{}", name, round, spec.rounds);
        let before = PASSED.load(Ordering::SeqCst);
        let t0 = crate::time::uptime_ms();
        run();
        let ms = crate::time::uptime_ms() - t0;
        (min, max, total) = (min.min(ms), max.max(ms), total + ms);
        ran += 1;
        if PASSED.load(Ordering::SeqCst) == before {
            serial_println!("[LOOP] {} FAILED in round {}/{}", name, round, spec.rounds);
            break;
        }
        passed += 1;
    }
    let avg = if ran > 0 { total / ran as u64 } else { 0 };
    serial_println!(
        "[RESULT-LOOP] suite={} rounds={} passed={} min_ms={} avg_ms={} max_ms={}",
        name,
        spec.rounds,
        passed,
        if min == u64::MAX { 0 } else { min },
        avg,
        max
    );
}

/// Loop mode with a name no suite has – a failure (called after the suites).
pub fn check_loop_name() {
    if let Some(spec) = loop_spec() {
        let wanted = core::str::from_utf8(&spec.name[..spec.len]).unwrap_or("");
        if !LOOPABLE.contains(&wanted) {
            serial_println!("[LOOP] unknown suite {:?} - repeatable suites: {}", wanted, LOOPABLE.join(", "));
            STARTED.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Checks for automatic mode (once, at startup).
pub fn detect_autotest() {
    let on = fw_cfg_has_file(AUTOTEST_FILE);
    AUTOTEST.store(on, Ordering::SeqCst);
    if on {
        serial_println!("[TEST] Automatic test mode (QEMU will exit after the self-tests)");
        detect_loop();
        detect_phase();
    }
}

/// Reads `opt/desoos/phase` – "restart" = the second start (tests/test.sh), "soak <seconds>
/// <seed>" = the long test (tests/soak.sh).
fn detect_phase() {
    let Some((size, select)) = fw_cfg_find(PHASE_FILE) else { return };
    let mut buf = [0u8; 48];
    let n = (size as usize).min(buf.len());
    unsafe { outw(FW_CFG_SELECTOR, select) };
    fw_cfg_bytes(&mut buf[..n]);
    let text = core::str::from_utf8(&buf[..n]).unwrap_or("").trim_matches(|c: char| c == '\0' || c.is_whitespace());
    if text == "restart" {
        RESTART.store(true, Ordering::SeqCst);
        serial_println!("[TEST] Restart phase: only RESTART TEST part 2 (the disk from the first start)");
        return;
    }
    let mut w = text.split_whitespace();
    if w.next() == Some("soak") {
        let secs = w.next().and_then(|s| s.parse::<u64>().ok()).filter(|&s| (60..=7 * 24 * 3600).contains(&s));
        let seed = w.next().and_then(|s| s.parse::<u64>().ok());
        let ram = match w.next() {
            None => Some(false),
            Some("ram") => Some(true),
            Some(_) => None,
        };
        match (secs, seed, ram, w.next()) {
            (Some(secs), Some(seed), Some(ram), None) => {
                SOAK_SECS.store(secs, Ordering::SeqCst);
                SOAK_SEED.store(seed, Ordering::SeqCst);
                SOAK_RAM.store(ram, Ordering::SeqCst);
                serial_println!("[TEST] Soak phase: {} s, seed {}{} (the boot tests are skipped)", secs, seed, if ram { ", on a RAM disk" } else { "" });
            }
            // A bad phase must not quietly run the normal tests instead: it fails.
            _ => {
                serial_println!("[TEST] bad soak phase {:?} - expected \"soak <60..604800 seconds> <seed> [ram]\"", text);
                STARTED.fetch_add(1, Ordering::SeqCst);
                SOAK_SECS.store(u64::MAX, Ordering::SeqCst);
            }
        }
    }
}

/// The second start of tests/test.sh: the other self-tests are skipped.
pub fn restart() -> bool {
    RESTART.load(Ordering::SeqCst)
}

/// The soak start: Some((seconds, seed, on a RAM disk)); u64::MAX seconds = a bad phase
/// (fails at once).
pub fn soak() -> Option<(u64, u64, bool)> {
    match SOAK_SECS.load(Ordering::SeqCst) {
        0 => None,
        s => Some((s, SOAK_SEED.load(Ordering::SeqCst), SOAK_RAM.load(Ordering::SeqCst))),
    }
}

/// Restart or soak start: the boot self-tests are skipped.
pub fn skip_boot() -> bool {
    restart() || soak().is_some()
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
