// The start contract (docs/abi/STARTUP.md) seen from inside a libdeso program – STARTUP TEST
// part 1 runs it.  `starttest MODE ARGS...`:
//   starttest svc ARGS...    the start stack (RSP % 16 == 0 at argc, argv[], argv[argc] = NULL,
//                            envp NULL, auxv AT_NULL 0, the strings above it below the stack
//                            top), slots 0-2 open, slot 3 a channel, 4-15 empty; the stack
//                            grown to 7 MiB; exit 0
//   starttest none ARGS...   the same with nothing in slot 3
//   starttest exit N         main returns N (the exit code)
//   starttest panic          a panic: "panic: ..." on slot 2, exit code 101
// Result: "starttest: N checks OK, ..." and exit code 0; a failed check: its number as the code.
#![no_std]
#![no_main]

#[macro_use]
#[allow(unused_imports)]
extern crate libdeso;
#[allow(unused_imports)]
use libdeso as deso;

use deso::*;

entry!(main);

/// USER_STACK_TOP (docs/abi/README.md, the loader's limits).
const STACK_TOP: u64 = 0x0000_7fff_ffff_0000;
/// How deep the stack test goes – 1 MiB short of STACK_MAX (8 MiB).
const DEEP: usize = 7 << 20;
const FRAME: usize = 64 * 1024;

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("starttest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 100 + $n;
        }
    };
}

/// Recursion with 64 KiB frames: every frame is written, so each page of the stack is touched
/// in order down to `left` bytes below the first frame; returns the sum of the frames' bytes.
#[inline(never)]
fn deep(left: usize) -> u64 {
    let mut frame = [0u8; FRAME];
    for (i, b) in frame.iter_mut().enumerate().step_by(4096) {
        *b = (i >> 12) as u8 | 1;
    }
    let frame = core::hint::black_box(frame);
    let mine: u64 = frame.iter().step_by(4096).map(|&b| b as u64).sum();
    if left <= FRAME { mine } else { mine + deep(left - FRAME) }
}

fn main(args: Args) -> i32 {
    let mut n = 0;
    match args.get(1) {
        Some("exit") => return args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1),
        Some("panic") => {
            let v: Option<u32> = core::hint::black_box(None);
            v.expect("starttest asked to panic");
            return 1;
        }
        Some("svc") | Some("none") => {}
        _ => {
            println!("starttest: usage: starttest svc|none ARGS... | exit N | panic");
            return 2;
        }
    }
    let svc = args.get(1) == Some("svc");

    // The stack as the kernel built it.
    let argv = args.argv();
    let argc = args.len();
    let sp = argv as u64 - 8;
    let word = |i: usize| unsafe { *(sp as *const u64).add(i) };
    check!(n, sp % 16 == 0, "RSP at the start {:#x} is not 16-byte aligned", sp);
    check!(n, word(0) == argc as u64 && argc >= 2, "[RSP] = {} is not argc ({})", word(0), argc);
    check!(n, word(1 + argc) == 0, "argv[argc] = {:#x}, not NULL", word(1 + argc));
    check!(n, word(2 + argc) == 0, "envp[0] = {:#x} - ABI 1.0 gives no environment", word(2 + argc));
    check!(n, word(3 + argc) == 0 && word(4 + argc) == 0, "auxv = ({:#x}, {:#x}), not (AT_NULL, 0)", word(3 + argc), word(4 + argc));
    let mut bytes = 0;
    for i in 0..argc {
        let p = word(1 + i);
        check!(n, p > sp + 8 * (5 + argc as u64) && p < STACK_TOP, "argv[{}] = {:#x} is not in the strings above the vectors", i, p);
        let s = args.get(i);
        check!(n, s.is_some(), "argv[{}] is not UTF-8", i);
        let len = s.map(|s| s.len()).unwrap_or(0);
        check!(n, unsafe { *((p + len as u64) as *const u8) } == 0, "argv[{}] is not NUL-terminated", i);
        bytes += len + 1;
    }
    check!(n, args.get(0).is_some_and(|a| a.ends_with("starttest")), "argv[0] = {:?}", args.get(0));

    // The slots: 0 / 1 / 2 open, 3 a channel or nothing, 4-15 nothing.
    for s in 0..3 {
        check!(n, handle_info(s).is_ok(), "slot {} (stdio) is not open: {:?}", s, handle_info(s));
    }
    let s3 = handle_info(3);
    if svc {
        check!(n, s3.map(|(k, _)| k) == Ok(KIND_CHANNEL), "slot 3 is not a channel: {:?}", s3);
    } else {
        check!(n, s3 == Err(ERROR_INVALID_HANDLE), "slot 3 must be empty: {:?}", s3);
    }
    for s in 4..16 {
        check!(n, handle_info(s) == Err(ERROR_INVALID_HANDLE), "slot {} must be empty: {:?}", s, handle_info(s));
    }

    // The stack grows on demand to 7 MiB.
    let sum = deep(DEEP);
    check!(n, sum > 0, "the deep stack lost its contents");
    let here = &sum as *const u64 as u64;
    check!(n, here > STACK_TOP - (1 << 20) && here < STACK_TOP, "a local at {:#x} is not on the stack below {:#x}", here, STACK_TOP);

    println!(
        "starttest: {} checks OK, RSP {:#x} (16-aligned), argc {}, {} bytes of arguments, argv/envp/auxv ends, slots 0-2{}, 7 MiB of stack",
        n,
        sp,
        argc,
        bytes,
        if svc { " + 3 (channel)" } else { ", slot 3 empty" }
    );
    0
}
