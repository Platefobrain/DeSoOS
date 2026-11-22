// SERVICES TEST – the service protocols' versions (docs/abi/SERVICES.md): /bin/prototest
// through the real init (`init test /bin/prototest`, net0 = netd on the test card).
//   1/2 the service manager (svc 1.0) and netd (net 1.0): old clients unchanged, `version`,
//       unknown requests and fields answered with the channel alive; libdeso's version helpers
//       against fake services – an old one (1.0), newer ones, garbage, a bad number, an answer
//       with a handle, a channel closed half-way, no answer (timeout) – never a panic
//   2/2 afterwards: the card free, its MSI vector back

use alloc::string::String;

use super::*;
use crate::drivers::pci;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[SERVICES TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

fn run_init(program: &str, ms: u64) -> Option<(ExitKind, String)> {
    let opts = SpawnOptions { stdin: Some(alloc::vec::Vec::new()), capture: true, hw_root: true, sysctl: true, input: true, blk: true, ..SpawnOptions::default() };
    let id = exec("/bin/init", &["init", "test", program], "/", &opts).ok()?;
    let end = crate::time::ticks() + ms;
    while sched::task_info(id).is_some() {
        if crate::time::ticks() > end {
            let _ = sched::request_exit(id);
            return None;
        }
        crate::time::sleep_ms(5);
    }
    let kind = exit_info(id)?.kind;
    Some((kind, String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned()))
}

pub fn self_test() {
    serial_println!("[SERVICES TEST] Starting tests of the service protocols' versions (docs/abi/SERVICES.md)...");
    crate::selftest::begin();
    let nic = pci::devices().iter().position(|d| d.class == 0x02 && d.subclass == 0x00);
    check!(nic.is_some(), "no network card (QEMU needs -device e1000e)");
    let nic = nic.unwrap();
    let vectors0 = crate::arch::x86_64::msi::free_count();

    let r = run_init("/bin/prototest", 120_000);
    check!(r.is_some(), "init test /bin/prototest did not finish");
    let (kind, out) = r.unwrap();
    let line = out.lines().find(|l| l.starts_with("prototest:")).unwrap_or("").trim();
    check!(kind == ExitKind::Exit(0) && line.contains("checks OK"), "prototest: {:?} {:?}", kind, out.trim());
    check!(!out.contains("panic"), "a panic in a client or a service: {:?}", out.trim());
    serial_println!("[SERVICES TEST] 1/2 {} PASS", line);

    check!(pci::owner(nic) == pci::OWNER_FREE, "network card still claimed after netd ended");
    check!(crate::arch::x86_64::msi::free_count() == vectors0, "MSI vectors leaked");
    serial_println!("[SERVICES TEST] 2/2 after init: the card free, its MSI vector back PASS");
    crate::selftest::pass();
}
