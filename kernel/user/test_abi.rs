// ABI TEST – the kernel against the ABI description (abi/abi.toml, docs/abi/README.md; tests 4
// and 5 of the V081 plan).  tools/abigen.py generates kernel/user/abi_generated.rs from the
// description: the rights table as text and every constant with its kernel path.
//   1/2 the kernel = the description: sysrights::text() byte for byte, the table's size, the
//       reserved numbers without a row, every syscall number and constant value
//   2/2 /bin/abiprobe: the constants generated for programs, through real syscalls

use alloc::string::String;

use super::abi_generated as abi;
use super::sysrights::{text, TABLE};
use super::*;
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[ABI TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

pub fn self_test() {
    serial_println!("[ABI TEST] Starting ABI description tests...");
    crate::selftest::begin();

    // 1. The rights table and the constants.
    let have = text();
    if have != abi::RIGHTS_TEXT {
        let mut a = have.lines();
        let mut b = abi::RIGHTS_TEXT.lines();
        loop {
            match (a.next(), b.next()) {
                (None, None) => break,
                (x, y) if x == y => continue,
                (x, y) => {
                    serial_println!("[ABI TEST] kernel:      {:?}", x.unwrap_or("(end)"));
                    serial_println!("[ABI TEST] description: {:?}", y.unwrap_or("(end)"));
                    break;
                }
            }
        }
        check!(false, "the rights table differs from abi/abi.toml (sysrights.rs or abi.toml changed - tools/abigen.py)");
    }
    check!(TABLE.len() == abi::SYSCALL_COUNT, "the table has {} numbers, the description {}", TABLE.len(), abi::SYSCALL_COUNT);
    for &r in abi::RESERVED.iter() {
        check!(TABLE[r].is_none(), "reserved number {} has a row", r);
    }
    let n = match abi::check() {
        Ok(n) => n,
        Err(name) => {
            check!(false, "{}: the kernel's value differs from abi/abi.toml", name);
            return;
        }
    };
    let rows = TABLE.iter().flatten().count();
    serial_println!("[ABI TEST] 1/2 kernel = description: ABI {}.{}, rights table ({} rows, {} numbers, {} reserved) byte for byte, {} syscall numbers and constants equal PASS",
        abi::ABI_MAJOR, abi::ABI_MINOR, rows, abi::SYSCALL_COUNT, abi::RESERVED.len(), n);

    // 2. abiprobe – the program side of the same description.
    let opts = SpawnOptions { stdin: Some(alloc::vec::Vec::new()), capture: true, ..SpawnOptions::default() };
    let id = exec("/bin/abiprobe", &["abiprobe"], "/", &opts);
    check!(id.is_ok(), "cannot start /bin/abiprobe: {:?}", id.err());
    let id = id.unwrap();
    let end = ticks() + 30_000;
    while sched::task_info(id).is_some() {
        if ticks() > end {
            let _ = sched::request_exit(id);
            check!(false, "abiprobe did not finish");
        }
        crate::time::sleep_ms(1);
    }
    let kind = exit_info(id).map(|e| e.kind);
    let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
    let last = out.lines().filter(|l| l.starts_with("abiprobe: ABI")).last().unwrap_or("").trim();
    if kind != Some(ExitKind::Exit(0)) || !last.ends_with(" 0 failed") {
        for l in out.lines().take(20) {
            serial_println!("[ABI TEST] {}", l);
        }
        check!(false, "abiprobe: {:?}", kind);
    }
    serial_println!("[ABI TEST] 2/2 {} PASS", last);
    crate::selftest::pass();
}
