// ABI TEST – the kernel against the ABI description (abi/abi.toml, docs/abi/README.md).
// tools/abigen.py generates kernel/user/abi_generated.rs from the
// description: the rights table as text and every constant with its kernel path.
//   1/3 the kernel = the description: sysrights::text() byte for byte, the table's size, the
//       reserved numbers without a row, every syscall number and constant value; the kernel's
//       gate (sysrights::check_with) driven with every handle argument of every row in turn
//       missing, of a wrong kind and short of each right it needs, the other handles valid
//   2/3 /bin/abiprobe: the constants generated for programs, through real syscalls, and the
//       argument order of every call abi.toml gives to abiprobe
//   3/3 the ELF ABI note: every /bin program carries the 1.0 note; the loader's note rules on
//       hand-built ELF files (versions, flags, every length, twice, outside the file, overflow,
//       overlap, alignment, foreign notes, order in the file) and through exec

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
    let gate = match gate_cases() {
        Ok(g) => g,
        Err(e) => {
            check!(false, "the gate: {}", e);
            return;
        }
    };
    serial_println!("[ABI TEST] 1/3 kernel = description: ABI {}.{}, rights table ({} rows, {} numbers, {} reserved) byte for byte, {} syscall numbers and constants equal; the gate: {} handle arguments, {} cases PASS",
        abi::ABI_MAJOR, abi::ABI_MINOR, rows, abi::SYSCALL_COUNT, abi::RESERVED.len(), n, abi::GATE.len(), gate);

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
    for name in abi::ORDER_ABIPROBE.iter() {
        let line = alloc::format!("abiprobe: order ok {}", name);
        check!(out.lines().any(|l| l.trim() == line), "abiprobe did not check the argument order of {}", name);
    }
    serial_println!("[ABI TEST] 2/3 {} PASS", last);

    // 3. The ELF ABI note.
    if let Err(e) = notes() {
        check!(false, "{}", e);
    }
    crate::selftest::pass();
}

/// The gate against the description, one handle argument at a time.  Handle numbers 100 + register
/// exist (kind: the first one the row allows, all rights); every other number does not.  For each
/// handle argument of a row: all valid -> Ok; this one missing -> INVALID_HANDLE; of a kind the row
/// does not allow -> INVALID_HANDLE; without one of the rights it always needs -> ACCESS_DENIED; with
/// a condition's flag set: the right present -> Ok, missing -> ACCESS_DENIED.  A gate that checks
/// only some of a row's handles, a wrong kind or a missing right fails here.
fn gate_cases() -> Result<usize, String> {
    use super::sysrights::check_with;
    use super::syscalls::{ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE};
    const ALL: u32 = 0xFFFF_FFFF;
    let mut cases = 0;
    for (i, &(nr, reg, kinds, need, conds)) in abi::GATE.iter().enumerate() {
        // The row's handle arguments (all entries with this number).
        let row: alloc::vec::Vec<(usize, u16)> = abi::GATE.iter().filter(|g| g.0 == nr).map(|g| (g.1, g.2)).collect();
        let first_kind = |mask: u16| (1..16u64).find(|k| mask & (1 << k) != 0).unwrap_or(0);
        let base = |args: &mut [u64; 6]| {
            for &(r, _) in &row {
                args[r] = 100 + r as u64;
            }
        };
        // `this`: (kind, rights) of the argument under test, or None = the handle does not exist.
        let run = |args: &[u64; 6], this: Option<(u64, u32)>| {
            check_with(nr, args, |h| {
                for &(r, mask) in &row {
                    if h == 100 + r as u64 {
                        if r == reg {
                            return this.ok_or(ERROR_INVALID_HANDLE);
                        }
                        return Ok((first_kind(mask), ALL));
                    }
                }
                Err(ERROR_INVALID_HANDLE)
            })
        };
        let what = |c: &str| alloc::format!("syscall {} argument {} (row entry {}): {}", nr, reg, i, c);
        let mut args = [0u64; 6];
        base(&mut args);
        let good = Some((first_kind(kinds), ALL));
        if run(&args, good) != Ok(()) {
            return Err(what("refused with every handle valid"));
        }
        if run(&args, None) != Err(ERROR_INVALID_HANDLE) {
            return Err(what("a missing handle not refused"));
        }
        cases += 2;
        if let Some(wrong) = (1..16u64).find(|k| kinds & (1 << k) == 0) {
            if run(&args, Some((wrong, ALL))) != Err(ERROR_INVALID_HANDLE) {
                return Err(what("a handle of the wrong kind not refused"));
            }
            cases += 1;
        }
        for bit in 0..32 {
            let r = 1u32 << bit;
            if need & r != 0 {
                if run(&args, Some((first_kind(kinds), ALL & !r))) != Err(ERROR_ACCESS_DENIED) {
                    return Err(what(&alloc::format!("a handle without right 0x{:x} not refused", r)));
                }
                cases += 1;
            }
        }
        for &(creg, cbit, right) in conds.iter().filter(|c| c.0 != 0) {
            let mut a = args;
            a[creg - 1] |= cbit;
            if run(&a, Some((first_kind(kinds), ALL))) != Ok(()) {
                return Err(what("refused with the condition's right present"));
            }
            if run(&a, Some((first_kind(kinds), ALL & !right))) != Err(ERROR_ACCESS_DENIED) {
                return Err(what(&alloc::format!("flag 0x{:x} set, right 0x{:x} missing, not refused", cbit, right)));
            }
            cases += 2;
        }
    }
    Ok(cases)
}

use super::elf_loader::{abi_of, AbiError, LoadError};

const FILE: usize = 0x3000;

fn put(b: &mut [u8], at: usize, v: &[u8]) {
    b[at..at + v.len()].copy_from_slice(v);
}

/// A note: name (with its NUL), type, description – lengths as given, padded to 4.
fn note(name: &[u8], kind: u32, desc: &[u8]) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    v.extend_from_slice(&(name.len() as u32).to_le_bytes());
    v.extend_from_slice(&(desc.len() as u32).to_le_bytes());
    v.extend_from_slice(&kind.to_le_bytes());
    v.extend_from_slice(name);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v.extend_from_slice(desc);
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}

fn deso(major: u16, minor: u16, flags: u32) -> alloc::vec::Vec<u8> {
    let mut d = [0u8; 8];
    put(&mut d, 0, &major.to_le_bytes());
    put(&mut d, 2, &minor.to_le_bytes());
    put(&mut d, 4, &flags.to_le_bytes());
    note(b"DeSo\0", 1, &d)
}

fn gnu() -> alloc::vec::Vec<u8> {
    note(b"GNU\0", 3, &[0x5a; 20])
}

/// A static ELF: code at 0x400000 (exit 0) + the extra program headers (type, offset, filesz,
/// vaddr) + bytes placed at file offsets.
fn elf(extra: &[(u32, u64, u64, u64)], blobs: &[(usize, &[u8])]) -> alloc::vec::Vec<u8> {
    let mut b = alloc::vec![0u8; FILE];
    put(&mut b, 0, b"\x7fELF\x02\x01\x01");
    put(&mut b, 16, &2u16.to_le_bytes());
    put(&mut b, 18, &62u16.to_le_bytes());
    put(&mut b, 20, &1u32.to_le_bytes());
    put(&mut b, 24, &0x40_0000u64.to_le_bytes());
    put(&mut b, 32, &64u64.to_le_bytes());
    put(&mut b, 52, &64u16.to_le_bytes());
    put(&mut b, 54, &56u16.to_le_bytes());
    put(&mut b, 56, &(1 + extra.len() as u16).to_le_bytes());
    let mut ph = |i: usize, kind: u32, flags: u32, off: u64, size: u64, va: u64| {
        let p = 64 + i * 56;
        put(&mut b, p, &kind.to_le_bytes());
        put(&mut b, p + 4, &flags.to_le_bytes());
        put(&mut b, p + 8, &off.to_le_bytes());
        put(&mut b, p + 16, &va.to_le_bytes());
        put(&mut b, p + 24, &va.to_le_bytes());
        put(&mut b, p + 32, &size.to_le_bytes());
        put(&mut b, p + 40, &size.to_le_bytes());
        put(&mut b, p + 48, &4u64.to_le_bytes());
    };
    ph(0, 1, 5, 0x1000, 8, 0x40_0000);
    for (i, &(kind, off, size, va)) in extra.iter().enumerate() {
        ph(i + 1, kind, 4, off, size, va);
    }
    // xor edi, edi; xor eax, eax (SYS_EXIT); syscall; jmp $
    put(&mut b, 0x1000, &[0x31, 0xff, 0x31, 0xc0, 0x0f, 0x05, 0xeb, 0xfe]);
    for &(at, bytes) in blobs {
        put(&mut b, at, bytes);
    }
    b
}

/// One PT_NOTE at `off` holding `bytes` (its filesz = their length).
fn one(off: usize, bytes: &[u8]) -> alloc::vec::Vec<u8> {
    elf(&[(4, off as u64, bytes.len() as u64, 0)], &[(off, bytes)])
}

/// Runs a built ELF from /tmp; Ok(exit kind) or the exec error.
fn run_file(name: &str, bytes: &[u8]) -> Result<ExitKind, ExecError> {
    let path = alloc::format!("/tmp/{}", name);
    let _ = crate::fs::write_file(&path, bytes);
    let opts = SpawnOptions { stdin: Some(alloc::vec::Vec::new()), capture: true, ..SpawnOptions::default() };
    let r = exec(&path, &[name], "/", &opts);
    let r = match r {
        Ok(id) => {
            let end = ticks() + 10_000;
            while sched::task_info(id).is_some() && ticks() < end {
                crate::time::sleep_ms(1);
            }
            Ok(exit_info(id).map(|e| e.kind).unwrap_or(ExitKind::Killed))
        }
        Err(e) => Err(e),
    };
    let _ = crate::fs::remove(&path);
    r
}

/// Whether the file has a PT_NOTE holding the DeSo OS note.
fn has_note(b: &[u8]) -> bool {
    let n = u16::from_le_bytes([b[56], b[57]]) as usize;
    let phoff = u64::from_le_bytes(b[32..40].try_into().unwrap()) as usize;
    (0..n).any(|i| {
        let p = phoff + i * 56;
        let off = u64::from_le_bytes(b[p + 8..p + 16].try_into().unwrap()) as usize;
        b[p..p + 4] == 4u32.to_le_bytes() && b.get(off + 12..off + 17) == Some(b"DeSo\0".as_slice())
    })
}

fn notes() -> Result<(), String> {
    use alloc::format;
    // Every program in /bin is built with libdeso: the 1.0 note.
    let bin = crate::fs::read_dir("/bin").unwrap_or_default();
    for e in &bin {
        let b = crate::fs::read_file(&format!("/bin/{}", e.name)).unwrap_or_default();
        if !has_note(&b) || abi_of(&b) != Ok((1, 0)) {
            return Err(format!("/bin/{}: no ABI 1.0 note ({:?})", e.name, abi_of(&b)));
        }
    }
    let n10 = deso(1, 0, 0);
    let two = [deso(1, 0, 0), deso(1, 0, 0)].concat();
    let both = [gnu(), deso(1, 0, 0), gnu()].concat();
    let mut namesz = deso(1, 0, 0);
    put(&mut namesz, 0, &0xFFFF_FFF0u32.to_le_bytes());
    let mut desc7 = deso(1, 0, 0);
    put(&mut desc7, 4, &7u32.to_le_bytes());
    let mut deschuge = deso(1, 0, 0);
    put(&mut deschuge, 4, &0xFFFF_FFFFu32.to_le_bytes());
    let mut badgnu = gnu();
    put(&mut badgnu, 4, &0x1000u32.to_le_bytes());
    let junk = [deso(1, 0, 0), alloc::vec![0u8; 4]].concat();
    let bad = Err(AbiError::BadNote);
    let ok = Ok((1, 0));
    let cases: alloc::vec::Vec<(&str, alloc::vec::Vec<u8>, Result<(u16, u16), AbiError>)> = alloc::vec![
        ("1.0", one(0x2000, &n10), ok),
        ("1.1 (a newer minor)", one(0x2000, &deso(1, 1, 0)), Err(AbiError::Newer(1, 1))),
        ("2.0 (another major)", one(0x2000, &deso(2, 0, 0)), Err(AbiError::OtherMajor(2, 0))),
        ("0.9 (another major)", one(0x2000, &deso(0, 9, 0)), Err(AbiError::OtherMajor(0, 9))),
        ("no note (a program from before ABI 1.0)", elf(&[], &[]), ok),
        ("an empty PT_NOTE", elf(&[(4, 0x2000, 0, 0)], &[]), ok),
        ("flags 1", one(0x2000, &deso(1, 0, 1)), Err(AbiError::Flags(1))),
        ("namesz past the PT_NOTE", one(0x2000, &namesz), bad),
        ("descsz 7", one(0x2000, &desc7), bad),
        ("descsz past the PT_NOTE", one(0x2000, &deschuge), bad),
        ("the note longer than its PT_NOTE", elf(&[(4, 0x2000, 24, 0)], &[(0x2000, &n10)]), bad),
        ("4 bytes after the last note", one(0x2000, &junk), bad),
        ("twice in one PT_NOTE", one(0x2000, &two), Err(AbiError::Twice)),
        ("twice in two PT_NOTEs", elf(&[(4, 0x2000, 28, 0), (4, 0x2100, 28, 0)], &[(0x2000, &n10), (0x2100, &n10)]), Err(AbiError::Twice)),
        ("a PT_NOTE past the end of the file", elf(&[(4, (FILE - 16) as u64, 28, 0)], &[]), bad),
        ("p_offset + p_filesz overflows", elf(&[(4, u64::MAX - 3, 28, 0)], &[]), bad),
        ("two PT_NOTEs overlapping", elf(&[(4, 0x2000, 28, 0), (4, 0x2010, 28, 0)], &[(0x2000, &n10)]), bad),
        ("a PT_NOTE on the ELF header", elf(&[(4, 0, 28, 0)], &[]), bad),
        ("a PT_NOTE on the program headers", elf(&[(4, 64, 28, 0)], &[]), bad),
        ("a misaligned PT_NOTE", one(0x2002, &n10), bad),
        ("a PT_NOTE over 4 KiB", elf(&[(4, 0x1000, 4100, 0)], &[]), bad),
        ("five PT_NOTEs", elf(&[(4, 0x2000, 0, 0); 5], &[]), bad),
        ("the note between foreign GNU notes", one(0x2000, &both), ok),
        ("a damaged foreign note", one(0x2000, &badgnu), bad),
        ("the note at the very end of the file", one(FILE - 28, &n10), ok),
        ("the note before the code", one(0x800, &n10), ok),
    ];
    for (what, b, want) in &cases {
        let got = abi_of(b);
        if got != *want {
            return Err(format!("note {}: {:?}, want {:?}", what, got, want));
        }
    }
    // Overlapping PT_LOAD segments are refused before anything is mapped.
    let ov = elf(&[(1, 0x1000, 8, 0x40_0004)], &[]);
    let got = super::elf_loader::load(&ov, &["x"]).err();
    if got != Some(LoadError::Overlap) {
        return Err(format!("overlapping segments: {:?}", got));
    }
    // Through exec: 1.0 and a program without a note run; 1.1 is refused with ERROR_ABI and the reason.
    for (name, b) in [("abinote10", one(0x2000, &n10)), ("abinone", elf(&[], &[]))] {
        let r = run_file(name, &b);
        if !matches!(r, Ok(ExitKind::Exit(0))) {
            return Err(format!("{}: {:?}", name, r.map_err(|e| format!("{}", e))));
        }
    }
    match run_file("abinote11", &one(0x2000, &deso(1, 1, 0))) {
        Err(e) => {
            let text = format!("{}", e);
            let code = super::syscalls::exec_error(e);
            if code != super::syscalls::ERROR_ABI || text != "needs DeSo OS ABI 1.1, this system 1.0" {
                return Err(format!("1.1 through exec: {} ({})", text, code));
            }
        }
        Ok(k) => return Err(format!("1.1 ran: {:?}", k)),
    }
    serial_println!(
        "[ABI TEST] 3/3 ELF ABI note: {} /bin programs carry ABI 1.0; {} note cases (1.0, 1.1, 2.0, none, flags, every length, twice, outside, overflow, overlap, alignment, foreign notes, order), overlapping segments refused; exec: 1.0 and no note run, 1.1 refused with ERROR_ABI PASS",
        bin.len(),
        cases.len()
    );
    Ok(())
}
