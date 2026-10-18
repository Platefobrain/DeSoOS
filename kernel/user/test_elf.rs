// Self-tests of ELF program loading (selftest build only, --cfg selftest).

use alloc::string::String;
use alloc::vec::Vec;

use super::elf_loader::{self, LoadError};
use super::*;
use crate::elf::ElfError;
use crate::memory::NO_EXECUTE;
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[ELF TEST] FAIL: {}", format_args!($($msg)*));
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

/// `exec` with captured output; (how it ended, output).
fn run(path: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<(ExitKind, String), String> {
    let opts = SpawnOptions { stdin: stdin.map(|s| s.to_vec()), capture: true, ..SpawnOptions::default() };
    let id = exec(path, args, "/tmp", &opts).map_err(|e| alloc::format!("exec: {}", e))?;
    if !wait_for(10_000, || sched::task_info(id).is_none()) {
        let _ = sched::request_exit(id);
        return Err(String::from("timeout"));
    }
    let kind = exit_info(id).ok_or("no exit info")?.kind;
    Ok((kind, String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned()))
}

fn put_u16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn get_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// Offset of program header number `i`.
fn phdr(b: &[u8], i: usize) -> usize {
    get_u64(b, 32) as usize + i * 56
}

/// Index of the first PT_LOAD segment with the given flags (PF_*).
fn find_load(b: &[u8], flags: u32) -> usize {
    let n = u16::from_le_bytes([b[56], b[57]]) as usize;
    (0..n)
        .find(|&i| {
            let p = phdr(b, i);
            b[p..p + 4] == 1u32.to_le_bytes() && b[p + 4..p + 8] == flags.to_le_bytes()
        })
        .unwrap_or(0)
}

/// Reads a qword from the process address space (via the direct map).
fn peek(space: &AddressSpace, va: u64) -> Option<u64> {
    let (phys, _) = space.translate(va)?;
    Some(unsafe { core::ptr::read(crate::memory::phys_to_virt(phys) as *const u64) })
}

fn peek_str(space: &AddressSpace, va: u64) -> String {
    let mut s = String::new();
    for i in 0..64 {
        let Some((phys, _)) = space.translate(va + i) else { break };
        let c = unsafe { *(crate::memory::phys_to_virt(phys) as *const u8) };
        if c == 0 {
            break;
        }
        s.push(c as char);
    }
    s
}

pub fn self_test() {
    use crate::elf::{PF_R, PF_W, PF_X};
    serial_println!("[ELF TEST] Starting ELF loader tests...");
    crate::selftest::begin();
    let frames = crate::selftest::settled_free_frames();

    // 1. /bin from the initrd: every file is a valid ELF for a process.
    let bin = crate::fs::read_dir("/bin").unwrap_or_default();
    check!(bin.len() >= 5, "/bin has {} files", bin.len());
    for e in &bin {
        let path = alloc::format!("/bin/{}", e.name);
        let bytes = crate::fs::read_file(&path).unwrap_or_default();
        let r = elf_loader::load(&bytes, &[&e.name]);
        check!(r.is_ok(), "{}: {:?}", path, r.err());
    }
    serial_println!("[ELF TEST] 1/9 /bin ({} programs from the initrd) parse and load PASS", bin.len());

    // 2. Corrupted files are rejected (before a process is created).
    let good = crate::fs::read_file("/bin/hello").unwrap_or_default();
    check!(good.len() > 4096, "/bin/hello missing");
    let text = phdr(&good, find_load(&good, PF_R | PF_X));
    let data = phdr(&good, find_load(&good, PF_R | PF_W));
    let rodata = phdr(&good, find_load(&good, PF_R));
    type Mutate = fn(&mut Vec<u8>, usize, usize);
    let cases: [(&str, Mutate, LoadError); 12] = [
        ("bad magic", |b, _, _| b[0] = 0, LoadError::Elf(ElfError::BadMagic)),
        ("32-bit class", |b, _, _| b[4] = 1, LoadError::Elf(ElfError::Not64Bit)),
        ("big-endian", |b, _, _| b[5] = 2, LoadError::Elf(ElfError::NotLittleEndian)),
        ("machine i386", |b, _, _| put_u16(b, 18, 3), LoadError::Elf(ElfError::NotX86_64)),
        ("ET_DYN", |b, _, _| put_u16(b, 16, 3), LoadError::Elf(ElfError::NotExecutable)),
        ("truncated header", |b, _, _| b.truncate(40), LoadError::Elf(ElfError::TooSmall)),
        ("truncated data", |b, _, _| b.truncate(0x1800), LoadError::Elf(ElfError::DataOutsideFile)),
        ("segment in the kernel", |b, t, _| put_u64(b, t + 16, 0xffff_ffff_8000_0000), LoadError::OutsideUserSpace),
        ("segment at 0 (null page)", |b, t, _| put_u64(b, t + 16, 0x1000), LoadError::OutsideUserSpace),
        ("W+X text", |b, t, _| put_u32(b, t + 4, PF_R | PF_W | PF_X), LoadError::WriteAndExecute),
        ("filesz > memsz", |b, _, d| { let m = get_u64(b, d + 40); put_u64(b, d + 32, m + 1) }, LoadError::Elf(ElfError::FileSizeTooBig)),
        ("entry in data", |b, _, d| { let v = get_u64(b, d + 16); put_u64(b, 24, v) }, LoadError::EntryNotInCode),
    ];
    for (what, mutate, want) in cases {
        let mut b = good.clone();
        mutate(&mut b, text, data);
        let got = elf_loader::load(&b, &["x"]).err();
        check!(got == Some(want), "{}: {:?} (want {:?})", what, got, want);
    }
    // Data offset beyond the file; too many arguments.
    let mut b = good.clone();
    put_u64(&mut b, rodata + 8, 0x10_0000);
    check!(
        elf_loader::load(&b, &["x"]).err() == Some(LoadError::Elf(ElfError::DataOutsideFile)),
        "offset outside file"
    );
    let many = ["a"; 40];
    check!(elf_loader::load(&good, &many).err() == Some(LoadError::TooManyArgs), "40 args accepted");
    serial_println!("[ELF TEST] 2/9 14 broken files rejected (magic, class, machine, ET_DYN, W^X, ranges...) PASS");

    // 3. Page permissions: text RX, rodata R+NX, data RW+NX, stack RW+NX, .bss zeroed.
    let mut b = good.clone();
    let filesz = get_u64(&b, data + 32);
    put_u64(&mut b, data + 40, filesz + 0x2000); // + 8 KiB .bss
    let l = match elf_loader::load(&b, &["hello", "first", "second arg"]) {
        Ok(l) => l,
        Err(e) => {
            serial_println!("[ELF TEST] FAIL: load with .bss: {:?}", e);
            return;
        }
    };
    let nx = crate::memory::nx_flag();
    let flags = |va: u64| l.space.translate(va).map(|(_, f)| f);
    let w = crate::memory::WRITABLE;
    let tv = get_u64(&b, text + 16);
    let rv = get_u64(&b, rodata + 16);
    let dv = get_u64(&b, data + 16);
    check!(matches!(flags(tv), Some(f) if f & w == 0 && f & NO_EXECUTE == 0), "text {:?}", flags(tv));
    check!(matches!(flags(rv), Some(f) if f & w == 0 && f & NO_EXECUTE == nx), "rodata {:?}", flags(rv));
    check!(matches!(flags(dv), Some(f) if f & w != 0 && f & NO_EXECUTE == nx), "data {:?}", flags(dv));
    check!(matches!(flags(USER_STACK_TOP - 8), Some(f) if f & w != 0 && f & NO_EXECUTE == nx), "stack");
    check!(flags(USER_STACK_TOP - USER_STACK_SIZE - 8).is_none(), "stack guard page mapped");
    check!(flags(0).is_none() && flags(elf_loader::USER_MIN - 4096).is_none(), "low memory mapped");
    let bss = (dv + filesz + 7) & !7;
    check!(peek(&l.space, bss) == Some(0) && peek(&l.space, dv + filesz + 0x1ff0) == Some(0), ".bss not zero");
    check!(peek(&l.space, dv) == Some(get_u64(&b, get_u64(&b, data + 8) as usize)), "data not copied");
    // 4. Stack: RSP % 16 == 0, argc, argv[], NULL, envp NULL.
    check!(l.rsp % 16 == 0, "rsp {:#x} not aligned", l.rsp);
    check!(peek(&l.space, l.rsp) == Some(3), "argc {:?}", peek(&l.space, l.rsp));
    let argv: Vec<String> = (0..3).map(|i| peek_str(&l.space, peek(&l.space, l.rsp + 8 + i * 8).unwrap_or(0))).collect();
    check!(argv == ["hello", "first", "second arg"], "argv {:?}", argv);
    check!(peek(&l.space, l.rsp + 32) == Some(0) && peek(&l.space, l.rsp + 40) == Some(0), "argv/envp terminators");
    check!(l.entry == get_u64(&b, 24), "entry {:#x}", l.entry);
    drop(l);
    serial_println!("[ELF TEST] 3/9 page rights: text RX, rodata R+NX, data RW+NX, stack RW+NX, .bss zeroed PASS");
    serial_println!("[ELF TEST] 4/9 SysV stack: argc, argv[], NULL, envp NULL, RSP % 16 == 0 PASS");

    // 5. exec: hello + args.
    let r = run("/bin/hello", &["hello"], None);
    check!(
        matches!(&r, Ok((ExitKind::Exit(0), o)) if o.starts_with("Hello from an ELF program! (pid ") && o.ends_with(")\n")),
        "hello: {:?}",
        r
    );
    let r = run("/bin/args", &["args", "one", "two words"], None);
    check!(
        r == Ok((ExitKind::Exit(0), String::from("argc = 3\nargv[0] = args\nargv[1] = one\nargv[2] = two words\n"))),
        "args: {:?}",
        r
    );
    serial_println!("[ELF TEST] 5/9 exec /bin/hello, /bin/args (argv passed) PASS");

    // 6. Files: save (path relative to cwd /tmp) + cat; ENOENT error.
    let _ = crate::fs::remove("/tmp/elf.txt");
    let r = run("/bin/save", &["save", "elf.txt", "written", "by", "save"], None);
    check!(r == Ok((ExitKind::Exit(0), String::from("saved elf.txt\n"))), "save: {:?}", r);
    check!(
        crate::fs::read_file("/tmp/elf.txt").ok().as_deref() == Some(&b"written by save\n"[..]),
        "/tmp/elf.txt content"
    );
    let r = run("/bin/cat", &["cat", "/tmp/elf.txt"], None);
    check!(r == Ok((ExitKind::Exit(0), String::from("written by save\n"))), "cat file: {:?}", r);
    let r = run("/bin/cat", &["cat", "/nope.txt"], None);
    check!(
        r == Ok((ExitKind::Exit(1), String::from("cat: /nope.txt: no such file or directory\n"))),
        "cat missing: {:?}",
        r
    );
    let r = run("/bin/cat", &["cat"], Some(b"from stdin\n"));
    check!(r == Ok((ExitKind::Exit(0), String::from("from stdin\n"))), "cat stdin: {:?}", r);
    let r = run("/bin/save", &["save"], None);
    check!(matches!(&r, Ok((ExitKind::Exit(2), o)) if o.starts_with("usage")), "save usage: {:?}", r);
    let _ = crate::fs::remove("/tmp/elf.txt");
    serial_println!("[ELF TEST] 6/9 save + cat (relative path, cwd), ENOENT, stdin, exit codes PASS");

    // 7. Computation in Rust in ring 3.
    let r = run("/bin/primes", &["primes", "10000"], None);
    check!(
        matches!(&r, Ok((ExitKind::Exit(0), o)) if o.starts_with("1229 primes below 10000 (")),
        "primes: {:?}",
        r
    );
    serial_println!("[ELF TEST] 7/9 primes 10000 = 1229 PASS");

    // 8. exec errors: missing file, directory, non-ELF.
    check!(matches!(exec("/bin/nope", &["nope"], "/", &SpawnOptions::default()), Err(ExecError::Fs(_))), "missing file");
    check!(matches!(exec("/bin", &["bin"], "/", &SpawnOptions::default()), Err(ExecError::Fs(_))), "directory");
    let _ = crate::fs::write_file("/tmp/notelf", b"#!/bin/sh\necho hi\n");
    check!(
        matches!(
            exec("/tmp/notelf", &["notelf"], "/", &SpawnOptions::default()),
            Err(ExecError::Load(LoadError::Elf(ElfError::TooSmall | ElfError::BadMagic)))
        ),
        "text file accepted"
    );
    let _ = crate::fs::remove("/tmp/notelf");
    serial_println!("[ELF TEST] 8/9 exec errors: missing file, directory, not an ELF PASS");

    // 9. No frame leak after all processes.
    let back = wait_for(500, || {
        sched::reap();
        crate::sched::stack::free_frames_flushed() == frames
    });
    check!(back, "frames leaked ({} -> {})", frames, crate::sched::stack::free_frames_flushed());
    serial_println!("[ELF TEST] 9/9 no frame leak after loads and processes PASS");
    crate::selftest::pass();
    serial_println!("[ELF TEST] All ELF loader tests passed");
}
