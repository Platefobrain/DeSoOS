// M11: wspólna obsługa samotestów (tylko build z `--cfg selftest`).
//
// * Każdy zestaw testów woła `begin()` na starcie i `pass()` na końcu –
//   `pass()` jest osiągalne tylko wtedy, gdy żaden `check!` nie zawiódł
//   (każdy błąd kończy zestaw wcześniej).  `finish()` porównuje liczniki.
// * Tryb automatyczny (./test.sh): QEMU dostaje plik fw_cfg
//   `opt/desoos/autotest` i urządzenie `isa-debug-exit` (port 0xf4).
//   Kernel po testach (albo przy panice / krytycznym wyjątku) sam wyłącza
//   QEMU z kodem wyjścia: PASS -> 33, FAIL -> 35 ((wartość << 1) | 1).
//   Bez tego pliku (zwykłe ./run-qemu.sh, prawdziwy sprzęt) nic się nie
//   zmienia – po testach startuje shell.

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

/// M19.c: wolne ramki po sprzątnięciu procesów z poprzednich testów – punkt
/// odniesienia testu wycieku.  Procesy poprzedniego zestawu (np. zabite przez
/// #PF) sprząta reap w pętli idle chwilę po ich końcu; pomiar przed końcem
/// sprzątania dawał na końcu zestawu WIĘCEJ wolnych ramek niż na starcie
/// (fałszywy "frames leaked", IPC TEST u Dawida: 115418 -> 115478).
/// Czeka, aż liczba się nie zmienia przez 10 kolejnych próbek co 5 ms (max 2 s).
/// v0.26.1: 3 próbki (15 ms) bywały za krótkie (IPC TEST u Dawida: 111523 ->
/// 111933 – na końcu WIĘCEJ wolnych), a koniec zestawu sprawdza „nie mniej niż
/// na starcie” – zwolnienie resztek po poprzednim zestawie to nie wyciek.
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

/// Podsumowanie; `true` gdy wszystkie rozpoczęte zestawy przeszły.
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
// QEMU: fw_cfg (wykrycie trybu automatycznego) + isa-debug-exit
// ------------------------------------------------------------

const FW_CFG_SELECTOR: u16 = 0x510;
const FW_CFG_DATA: u16 = 0x511;
const FW_CFG_SIGNATURE: u16 = 0x0000;
const FW_CFG_FILE_DIR: u16 = 0x0019;
const AUTOTEST_FILE: &[u8] = b"opt/desoos/autotest";

const DEBUG_EXIT_PORT: u16 = 0xf4;
const EXIT_PASS: u8 = 0x10; // QEMU kończy się kodem 33
const EXIT_FAIL: u8 = 0x11; // QEMU kończy się kodem 35

fn fw_cfg_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = unsafe { inb(FW_CFG_DATA) };
    }
}

/// Czy QEMU ma plik fw_cfg o tej nazwie.  Na prawdziwym sprzęcie porty
/// 0x510/0x511 nie istnieją – sygnatura "QEMU" się nie zgodzi.
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

/// Sprawdza tryb automatyczny (raz, na starcie).
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

/// W trybie automatycznym kończy QEMU z wynikiem; inaczej nic nie robi.
pub fn exit_if_autotest(ok: bool) {
    if !autotest() {
        return;
    }
    serial_println!("[TEST] Exiting QEMU: {}", if ok { "PASS" } else { "FAIL" });
    unsafe { outb(DEBUG_EXIT_PORT, if ok { EXIT_PASS } else { EXIT_FAIL }) };
    // Gdyby urządzenia nie było – zatrzymaj się (test.sh zgłosi timeout).
    loop {
        unsafe { core::arch::asm!("cli; hlt") };
    }
}
