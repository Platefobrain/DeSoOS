// RIGHTS TEST – the syscall rights table (sysrights.rs): the table itself, every
// right taken away through real syscalls (/bin/rightstest), the gate's cost.

use alloc::string::String;

use super::syscalls::{ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, ERROR_NOT_IMPLEMENTED};
use super::sysrights::{check_with, TABLE};
use super::*;
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[RIGHTS TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

fn wait_for(ms: u64, cond: impl Fn() -> bool) -> bool {
    let end = ticks() + ms;
    while !cond() {
        if ticks() > end {
            return false;
        }
        crate::time::sleep_ms(1);
    }
    true
}

pub fn self_test() {
    serial_println!("[RIGHTS TEST] Starting syscall rights table tests...");
    crate::selftest::begin();

    // 1. The table: names unique, handle arguments in registers 0..5 with a kind,
    // a mapping's write condition points to another argument; checked by the
    // gate alone (a synthetic handle table): missing right -> ERROR_ACCESS_DENIED, wrong
    // kind -> ERROR_INVALID_HANDLE, no handle -> ERROR_INVALID_HANDLE, full rights -> through.
    let mut rows = 0;
    let mut refused = 0;
    for (nr, r) in TABLE.iter().enumerate() {
        let Some(r) = r else { continue };
        rows += 1;
        let dup = TABLE.iter().flatten().filter(|o| o.name == r.name).count();
        check!(dup == 1, "syscall name {:?} appears {} times", r.name, dup);
        for a in r.args {
            check!(a.reg < 6 && a.kinds != 0, "{}: bad argument {} / kinds {:#x}", r.name, a.reg, a.kinds);
            for c in &a.conds {
                check!(c.reg == 0 || (c.reg <= 6 && !r.args.iter().any(|b| b.reg + 1 == c.reg) && c.bit != 0 && c.right != 0), "{}: bad condition", r.name);
            }
            // Argument values: handle numbers 10 + register; the rest 0.
            let mut args = [0u64; 6];
            for b in r.args {
                args[b.reg as usize] = 10 + b.reg as u64;
            }
            let kind_of = |k: u16| (1..16u64).find(|&i| k & (1 << i) != 0).unwrap_or(1);
            let full = |n: u64| -> Result<(u64, u32), i64> {
                let b = r.args.iter().find(|b| 10 + b.reg as u64 == n).ok_or(ERROR_INVALID_HANDLE)?;
                Ok((kind_of(b.kinds), 0xFF))
            };
            check!(check_with(nr as u64, &args, full).is_ok(), "{}: full rights refused", r.name);
            // The base rights, then each condition switched on alone.
            let mut variants = alloc::vec![args];
            for c in a.conds.iter().filter(|c| c.reg != 0) {
                let mut v = args;
                v[(c.reg - 1) as usize] = c.bit;
                variants.push(v);
            }
            for wargs in variants {
                let need = super::sysrights::need_of(a, &wargs);
                for bit in 0..8 {
                    let right = 1u32 << bit;
                    if need & right == 0 {
                        continue;
                    }
                    let less = |n: u64| full(n).map(|(k, rt)| if n == 10 + a.reg as u64 { (k, rt & !right) } else { (k, rt) });
                    check!(check_with(nr as u64, &wargs, less) == Err(ERROR_ACCESS_DENIED), "{}: without right {:#x} not refused", r.name, right);
                    refused += 1;
                }
            }
            if a.kinds != 0xFFFE {
                let wrong = (1..16u64).find(|&i| a.kinds & (1 << i) == 0).unwrap_or(15);
                let other = |n: u64| full(n).map(|(k, rt)| if n == 10 + a.reg as u64 { (wrong, rt) } else { (k, rt) });
                check!(check_with(nr as u64, &args, other) == Err(ERROR_INVALID_HANDLE), "{}: wrong kind not refused", r.name);
            }
            let none = |n: u64| if n == 10 + a.reg as u64 { Err(ERROR_INVALID_HANDLE) } else { full(n) };
            check!(check_with(nr as u64, &args, none) == Err(ERROR_INVALID_HANDLE), "{}: missing handle not refused", r.name);
        }
    }
    check!(check_with(TABLE.len() as u64, &[0; 6], |_| Err(ERROR_INVALID_HANDLE)) == Err(ERROR_NOT_IMPLEMENTED), "a number past the table must be ERROR_NOT_IMPLEMENTED");
    check!(rows >= 40, "only {} rows", rows);
    serial_println!("[RIGHTS TEST] 1/3 table: {} syscalls, names unique, every right of every handle argument taken away in turn - {} refused (ERROR_ACCESS_DENIED), wrong kind and missing handle ERROR_INVALID_HANDLE, no row ERROR_NOT_IMPLEMENTED PASS", rows, refused);

    // 2. Through real syscalls – every kind of object (like init: HW_ROOT,
    // SYSCTL, INPUT, BLK; the edu device and its interrupt).
    let edu = 6u64 << 3;
    let opts = SpawnOptions { stdin: Some(alloc::vec::Vec::new()), capture: true, hw_root: true, sysctl: true, input: true, blk: true, ..SpawnOptions::default() };
    let arg = alloc::format!("{}", edu);
    let id = exec("/bin/rightstest", &["rightstest", &arg], "/", &opts);
    check!(id.is_ok(), "cannot start /bin/rightstest");
    let id = id.unwrap();
    if !wait_for(30_000, || sched::task_info(id).is_none()) {
        let _ = sched::request_exit(id);
        check!(false, "rightstest did not finish");
    }
    let kind = exit_info(id).map(|e| e.kind);
    let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
    check!(kind == Some(ExitKind::Exit(0)) && out.contains("refused (ERROR_ACCESS_DENIED)"), "rightstest: {:?} {:?}", kind, out.trim());
    check!(crate::drivers::pci::index_of(crate::drivers::pci::Address { bus: 0, device: 6, function: 0 })
        .map_or(true, |i| crate::drivers::pci::owner(i) == crate::drivers::pci::OWNER_FREE), "edu still claimed after rightstest");
    serial_println!("[RIGHTS TEST] 2/3 real syscalls: {} PASS", out.trim());

    // 3. The gate's cost: a channel send's row (one handle) against a handle table.
    let args = [3u64, 0, 0, 0, 0, 0];
    let lookup = |n: u64| if n == 3 { Ok((super::process::kind::CHANNEL, 0xFFu32)) } else { Err(ERROR_INVALID_HANDLE) };
    const N: u64 = 200_000;
    let t0 = crate::arch::x86_64::clock::stamp();
    let mut ok = 0u64;
    for _ in 0..N {
        ok += check_with(core::hint::black_box(super::syscalls::SYS_CHAN_SEND), core::hint::black_box(&args), lookup).is_ok() as u64;
    }
    let us = crate::arch::x86_64::clock::us_between(t0, crate::arch::x86_64::clock::stamp());
    check!(ok == N, "gate refused a valid send");
    let ns = us * 1000 / N;
    serial_println!("[RIGHTS TEST] 3/3 gate cost: {} ns per syscall ({} checks in {} us) PASS", ns, N, us);
    serial_println!("[RESULT-RIGHTS] ver={} rows={} refused={} gate_ns={}", crate::shell::VERSION, rows, refused, ns);
    crate::selftest::pass();
}
