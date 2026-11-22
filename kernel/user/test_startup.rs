// STARTUP TEST – the start contract of ABI 1.0 (docs/abi/STARTUP.md), from the program's side.
//   1/3 /bin/starttest (libdeso): the start stack it finds (RSP % 16 == 0 at argc, argv[],
//       argv[argc] = NULL, envp NULL, auxv AT_NULL 0, the strings), slots 0-2 open, slot 3 a
//       channel or empty, 4-15 empty, the stack grown to 7 MiB; main's result is the exit code;
//       a panic is "panic: ..." on slot 2 and exit code 101
//   2/3 a program in plain machine code (no libdeso, no ABI note = 1.0) checking the same
//       stack and DF = 0 itself, loaded at the bottom of the load range (0x100000), at 0x400000
//       and ending exactly at its top (USER_LOAD_MAX); one page below / past the range refused
//   3/3 the limits: 32 arguments and 4096 bytes of them start, 33 / 4097 refused; a file of
//       MAX_PROGRAM_FILE (8 MiB) starts – read into frames, no big kernel-heap block – one byte
//       more refused

use alloc::string::String;
use alloc::vec::Vec;

use super::elf_loader::{LoadError, MAX_ARGS, MAX_ARG_BYTES, USER_MAX, USER_MIN};
use super::*;
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[STARTUP TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

/// Runs a program; (how it ended, output) or the exec error.
fn run(path: &str, args: &[&str], chans: Vec<(usize, alloc::sync::Arc<channel::ChanEnd>)>) -> Result<(ExitKind, String), ExecError> {
    let opts = SpawnOptions { stdin: Some(Vec::new()), capture: true, chans, ..SpawnOptions::default() };
    let id = exec(path, args, "/", &opts)?;
    let end = ticks() + 30_000;
    while sched::task_info(id).is_some() && ticks() < end {
        crate::time::sleep_ms(2);
    }
    if sched::task_info(id).is_some() {
        let _ = sched::request_exit(id);
    }
    let kind = exit_info(id).map(|e| e.kind).unwrap_or(ExitKind::Killed);
    Ok((kind, String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned()))
}

/// The machine code of the plain program (position independent): exit 1 RSP not 16-aligned,
/// 2 argc 0 or over 32, 3 argv[argc] not NULL, 4 envp not NULL, 5 auxv not (AT_NULL, 0),
/// 6 an argv pointer NULL / not above RSP / an empty string, 7 argv[0] not starting with 's',
/// 8 DF set; 0 when all hold.
const STARTASM: [u8; 149] = [
    0xbf, 0x01, 0x00, 0x00, 0x00, 0x40, 0xf6, 0xc4, 0x0f, 0x0f, 0x85, 0x80, 0x00, 0x00, 0x00, 0x48, //
    0x8b, 0x0c, 0x24, 0xbf, 0x02, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc9, 0x74, 0x72, 0x48, 0x83, 0xf9, //
    0x20, 0x77, 0x6c, 0xbf, 0x03, 0x00, 0x00, 0x00, 0x48, 0x83, 0x7c, 0xcc, 0x08, 0x00, 0x75, 0x5f, //
    0xbf, 0x04, 0x00, 0x00, 0x00, 0x48, 0x83, 0x7c, 0xcc, 0x10, 0x00, 0x75, 0x52, 0xbf, 0x05, 0x00, //
    0x00, 0x00, 0x48, 0x83, 0x7c, 0xcc, 0x18, 0x00, 0x75, 0x45, 0x48, 0x83, 0x7c, 0xcc, 0x20, 0x00, //
    0x75, 0x3d, 0xbf, 0x06, 0x00, 0x00, 0x00, 0x31, 0xd2, 0x48, 0x8b, 0x74, 0xd4, 0x08, 0x48, 0x39, //
    0xe6, 0x76, 0x2c, 0x80, 0x3e, 0x00, 0x74, 0x27, 0x48, 0xff, 0xc2, 0x48, 0x39, 0xca, 0x72, 0xe9, //
    0xbf, 0x07, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x74, 0x24, 0x08, 0x80, 0x3e, 0x73, 0x75, 0x10, 0xbf, //
    0x08, 0x00, 0x00, 0x00, 0x9c, 0x58, 0xa9, 0x00, 0x04, 0x00, 0x00, 0x75, 0x02, 0x31, 0xff, 0x31, //
    0xc0, 0x0f, 0x05, 0x0f, 0x0b,
];

/// A static ELF with one R+X segment of `size` bytes at `va` holding STARTASM, entry at `va`;
/// the file is `file_len` bytes (the rest zeros).
fn asm_elf(va: u64, size: u64, file_len: usize) -> Vec<u8> {
    let mut b = alloc::vec![0u8; file_len.max(0x1000 + STARTASM.len())];
    let put = |b: &mut [u8], at: usize, v: &[u8]| b[at..at + v.len()].copy_from_slice(v);
    put(&mut b, 0, b"\x7fELF\x02\x01\x01");
    put(&mut b, 16, &2u16.to_le_bytes());
    put(&mut b, 18, &62u16.to_le_bytes());
    put(&mut b, 20, &1u32.to_le_bytes());
    put(&mut b, 24, &va.to_le_bytes());
    put(&mut b, 32, &64u64.to_le_bytes());
    put(&mut b, 52, &64u16.to_le_bytes());
    put(&mut b, 54, &56u16.to_le_bytes());
    put(&mut b, 56, &1u16.to_le_bytes());
    let p = 64;
    put(&mut b, p, &1u32.to_le_bytes());
    put(&mut b, p + 4, &5u32.to_le_bytes());
    put(&mut b, p + 8, &0x1000u64.to_le_bytes());
    put(&mut b, p + 16, &va.to_le_bytes());
    put(&mut b, p + 24, &va.to_le_bytes());
    put(&mut b, p + 32, &(STARTASM.len() as u64).to_le_bytes());
    put(&mut b, p + 40, &size.to_le_bytes());
    put(&mut b, p + 48, &0x1000u64.to_le_bytes());
    put(&mut b, 0x1000, &STARTASM);
    b
}

/// Writes the file to /tmp, runs it as `startasm` with `args` after argv[0], removes it.
fn run_asm(bytes: &[u8], args: &[&str]) -> Result<ExitKind, ExecError> {
    let path = "/tmp/startasm";
    let _ = crate::fs::write_file(path, bytes);
    let mut all: Vec<&str> = alloc::vec!["startasm"];
    all.extend_from_slice(args);
    let r = run(path, &all, Vec::new()).map(|(k, _)| k);
    let _ = crate::fs::remove(path);
    r
}

pub fn self_test() {
    serial_println!("[STARTUP TEST] Starting tests of the start contract (docs/abi/STARTUP.md)...");
    crate::selftest::begin();

    // 1. The libdeso program.
    let (a, _peer) = channel::new();
    let r = run("/bin/starttest", &["/bin/starttest", "svc", "first", "zażółć", "x y"], alloc::vec![(3, a)]);
    check!(r.is_ok(), "exec /bin/starttest: {:?}", r.as_ref().err().map(|e| alloc::format!("{}", e)));
    let (kind, out) = r.unwrap_or((ExitKind::Killed, String::new()));
    let line = out.lines().find(|l| l.starts_with("starttest:")).unwrap_or("").trim();
    check!(kind == ExitKind::Exit(0) && line.contains("checks OK"), "starttest svc: {:?} {:?}", kind, out.trim());
    let r = run("/bin/starttest", &["starttest", "none", "one"], Vec::new());
    let (kind, out) = r.unwrap_or((ExitKind::Killed, String::new()));
    check!(kind == ExitKind::Exit(0) && out.contains("slot 3 empty"), "starttest none: {:?} {:?}", kind, out.trim());
    let r = run("/bin/starttest", &["starttest", "exit", "42"], Vec::new());
    check!(matches!(r, Ok((ExitKind::Exit(42), _))), "main returning 42: {:?}", r.map(|x| x.0));
    let r = run("/bin/starttest", &["starttest", "panic"], Vec::new());
    let (kind, out) = r.unwrap_or((ExitKind::Killed, String::new()));
    check!(kind == ExitKind::Exit(101) && out.contains("panic: ") && out.contains("starttest asked to panic"), "a panic must be exit 101 with \"panic: ...\": {:?} {:?}", kind, out.trim());
    check!(super::procs::status_of(kind) == 101, "wait status of a panic: {:#x}", super::procs::status_of(kind));
    serial_println!("[STARTUP TEST] 1/3 libdeso program: {}; slot 3 empty without a channel; main's 42 = exit code 42; a panic = \"panic: ...\" + exit code 101 PASS", line);

    // 2. Plain machine code at the edges of the load range.
    let page = 0x1000u64;
    let places = [("bottom", USER_MIN), ("SDK address", 0x40_0000), ("top", USER_MAX - page)];
    for (what, va) in places {
        let r = run_asm(&asm_elf(va, page, 0x2000), &["two", "three"]);
        check!(matches!(r, Ok(ExitKind::Exit(0))), "plain program at {:#x} ({}): {:?} (exit 1-8 = the failed check)", va, what, r);
    }
    let r = run_asm(&asm_elf(USER_MIN - page, page, 0x2000), &[]);
    check!(matches!(r, Err(ExecError::Load(LoadError::OutsideUserSpace))), "a segment one page below the load range must be refused: {:?}", r);
    let r = run_asm(&asm_elf(USER_MAX - page, 2 * page, 0x2000), &[]);
    check!(matches!(r, Err(ExecError::Load(LoadError::OutsideUserSpace))), "a segment one page past USER_LOAD_MAX must be refused: {:?}", r);
    serial_println!(
        "[STARTUP TEST] 2/3 plain machine code (no libdeso, no note): RSP % 16, argc, argv[], argv[argc] = NULL, envp NULL, auxv AT_NULL, DF = 0 at {:#x}, 0x400000 and {:#x} (ending at USER_LOAD_MAX); a page outside refused PASS",
        USER_MIN,
        USER_MAX - page
    );

    // 3. The limits.
    let prog = asm_elf(0x40_0000, page, 0x2000);
    let names: Vec<String> = (1..MAX_ARGS).map(|i| alloc::format!("a{}", i)).collect();
    let mut many: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    check!(matches!(run_asm(&prog, &many), Ok(ExitKind::Exit(0))), "{} arguments must start", MAX_ARGS);
    many.push("over");
    check!(matches!(run_asm(&prog, &many), Err(ExecError::Load(LoadError::TooManyArgs))), "{} arguments must be refused", MAX_ARGS + 1);
    // "startasm" + NUL = 9 bytes; the rest in one argument up to exactly MAX_ARG_BYTES.
    let fill = "s".repeat(MAX_ARG_BYTES - 9 - 1);
    check!(matches!(run_asm(&prog, &[&fill]), Ok(ExitKind::Exit(0))), "{} bytes of arguments must start", MAX_ARG_BYTES);
    let over = "s".repeat(MAX_ARG_BYTES - 9);
    check!(matches!(run_asm(&prog, &[&over]), Err(ExecError::Load(LoadError::TooManyArgs))), "{} bytes of arguments must be refused", MAX_ARG_BYTES + 1);
    // The file limit: a file of exactly MAX_PROGRAM_FILE and one byte more, made without an
    // 8 MiB buffer – the program's first page, then one byte at the end (a hole between on a
    // DeSoFS /disk; ramfs at / when there is none).
    let dir = if crate::fs::mounted_disk("/disk").is_some() && !crate::fs::is_read_only("/disk/x") { "/disk" } else { "/tmp" };
    let big = |len: usize| -> Result<ExitKind, ExecError> {
        let path = alloc::format!("{}/startbig", dir);
        let _ = crate::fs::remove(&path);
        let head = asm_elf(0x40_0000, page, 0x2000);
        let made = crate::fs::write_file(&path, &head).and_then(|_| crate::fs::write(&path, len as u64 - 1, &[0]).map(|_| ()));
        let r = match made {
            Err(e) => Err(ExecError::Fs(e)),
            Ok(()) => run(&path, &["startasm"], Vec::new()).map(|(k, _)| k),
        };
        let _ = crate::fs::remove(&path);
        r
    };
    crate::memory::heap::largest_reset();
    let exact = big(MAX_PROGRAM_FILE);
    let largest = crate::memory::heap::largest();
    check!(matches!(exact, Ok(ExitKind::Exit(0))), "a file of exactly MAX_PROGRAM_FILE in {} must start: {:?}", dir, exact.map_err(|e| alloc::format!("{}", e)));
    // exec reads the file into frames: no kernel-heap block anywhere near its size.
    check!(largest < 1 << 20, "exec of an 8 MiB file took a {} KiB block of the kernel heap", largest >> 10);
    let over = big(MAX_PROGRAM_FILE + 1);
    check!(matches!(over, Err(ExecError::TooBig)), "a file over MAX_PROGRAM_FILE must be refused: {:?}", over.map_err(|e| alloc::format!("{}", e)));
    serial_println!(
        "[STARTUP TEST] 3/3 limits: {} arguments and {} bytes start, one more refused; a {} MiB file ({}) starts – read into frames, the largest heap block {} KiB – one byte more refused PASS",
        MAX_ARGS,
        MAX_ARG_BYTES,
        MAX_PROGRAM_FILE >> 20,
        dir,
        largest >> 10
    );

    crate::sched::reap();
    crate::selftest::pass();
}
