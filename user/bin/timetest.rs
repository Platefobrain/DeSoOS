// timetest – LKG TEST from a program (the kernel's LKG TEST runs it).
//
//   timetest protect <root>   <root> is a DeSoFS volume holding <root>/.deso/lkg (the last
//                             known good time).  Tries to change it every way a program can –
//                             open for writing / truncate / create / append, unlink of the file
//                             and the directory, mkdir and create inside, relative paths, "."
//                             and "..", directory handles (openat, unlinkat, mkdirat) – every
//                             attempt must be refused (ERROR_NOT_PERMITTED); the file must stay
//                             readable and the same, and the rest of <root> writable:
//                             "timetest protect: K attempts refused, lkg readable (56 bytes),
//                             <root> writable"
//   timetest stale <file> <opened> <go>
//                             a handle opened before a DeSoFS volume is mounted over the path:
//                             opens <file> for writing (still on ramfs), creates <opened>, waits
//                             (at most 20 s) for <go> – the kernel mounts the volume in between –
//                             then writes through the old handle: it must be refused
//                             (ERROR_NOT_PERMITTED), as the handle keeps a path and every write
//                             picks the volume again: "timetest stale: the write through a handle
//                             opened before the mount was refused"
//   timetest set             SYS_TIME_SET without the right and with numbers out of range
//                            (the program holds a SETTIME handle – the kernel test gives it):
//                            no handle, another kind of handle, SETTIME without WRITE,
//                            servers 0 / 1 / 4 / u64::MAX, u above 10 s, t - u before the
//                            build date, t + u after 2099, overflows, t + u below the LKG –
//                            each refused with its error and SYS_TIME_BOUND unchanged after
//                            all of them: "timetest set: K refusals, nothing changed"
//   timetest bound           SYS_TIME_BOUND's buffer: len 39 refused and nothing written, 40 /
//                            41 / 4096 – exactly 40 bytes written (the rest untouched),
//                            NULL, a kernel address, an unmapped one, a read-only page, a
//                            buffer running into the gap after a mapping – ERROR_INVALID_ADDRESS:
//                            "timetest bound: K cases OK (B=..., file=..., flags=...)"
//   timetest clock <a> <b> <ms>  while the kernel moves the wall clock back and forth between
//                            the times a and b (Unix seconds): for <ms> ms every reading of
//                            syscall 59 must be one of the two clocks (never a mix), and a
//                            sleep of 200 ms must take 200 ms of uptime (the steps do not
//                            touch it): "timetest clock: N readings (A at a, B at b), sleep
//                            200 ms took T ms"
//
// A failure prints "timetest: FAIL ..." and exits with 1.
#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
#[allow(unused_imports)]
extern crate libdeso;
#[allow(unused_imports)]
use libdeso as deso;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use deso::*;

entry!(main);

fn read_file(path: &str) -> Result<Vec<u8>, i64> {
    let fd = open(path, O_READ);
    if fd < 0 {
        return Err(fd);
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = read(fd as u64, &mut buf);
        if n < 0 {
            close(fd as u64);
            return Err(n);
        }
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    close(fd as u64);
    Ok(out)
}

fn protect(root: &str) -> i32 {
    let dir = format!("{}/.deso", root);
    let file = format!("{}/.deso/lkg", root);
    let before = match read_file(&file) {
        Ok(d) => d,
        Err(e) => {
            println!("timetest: FAIL cannot read {}: {}", file, strerror(e));
            return 1;
        }
    };
    let mut refused = 0;
    let mut ok = true;
    let mut fail = |what: &str, r: i64| {
        if r >= 0 {
            close(r as u64);
            println!("timetest: FAIL {}: allowed", what);
            ok = false;
        } else if r != ERROR_NOT_PERMITTED {
            println!("timetest: FAIL {}: {} (expected {})", what, error_name(r), error_name(ERROR_NOT_PERMITTED));
            ok = false;
        } else {
            refused += 1;
        }
    };
    // Opening the file for writing, every way.
    fail("open write", open(&file, O_WRITE));
    fail("open read+write", open(&file, O_READ | O_WRITE));
    fail("open truncate", open(&file, O_WRITE | O_TRUNC));
    fail("open create (exists)", open(&file, O_WRITE | O_CREATE));
    fail("open append", open(&file, O_WRITE | O_APPEND));
    // Removing the file and the directory; new entries inside.
    fail("unlink lkg", unlink(&file));
    fail("unlink .deso", unlink(&dir));
    fail("mkdir .deso/x", mkdir(&format!("{}/x", dir)));
    fail("create .deso/extra", open(&format!("{}/extra", dir), O_WRITE | O_CREATE));
    fail("create .deso/lkg.new", open(&format!("{}/lkg.new", dir), O_WRITE | O_CREATE));
    fail("mkdir .deso (exists)", mkdir(&dir));
    // Other spellings of the same node: ".", "..", doubled slashes, relative paths.
    fail("open ./.deso/./lkg", open(&format!("{}/./.deso/./lkg", root), O_WRITE));
    fail("unlink //.deso//lkg", unlink(&format!("{}//.deso//lkg", root)));
    let sub = format!("{}/timetest-sub", root);
    let _ = mkdir(&sub);
    fail("open sub/../.deso/lkg", open(&format!("{}/../.deso/lkg", sub), O_WRITE | O_TRUNC));
    let _ = chdir(&dir);
    fail("relative unlink lkg", unlink("lkg"));
    fail("relative open lkg write", open("lkg", O_WRITE | O_TRUNC));
    fail("relative create here", open("new", O_WRITE | O_CREATE));
    let _ = chdir(&sub);
    fail("unlink ../.deso/lkg", unlink("../.deso/lkg"));
    fail("open ../.deso/lkg write", open("../.deso/lkg", O_WRITE));
    let _ = chdir(root);
    fail("relative unlink .deso/lkg", unlink(".deso/lkg"));
    fail("relative mkdir .deso/y", mkdir(".deso/y"));
    let _ = chdir("/");
    // Through directory handles.
    let d = dir_open(&dir, O_READ | O_WRITE);
    if d < 0 {
        println!("timetest: FAIL dir_open {}: {}", dir, error_name(d));
        return 1;
    }
    fail("unlinkat lkg", unlinkat(d as u64, "lkg"));
    fail("openat lkg write", openat(d as u64, "lkg", O_WRITE));
    fail("openat lkg truncate", openat(d as u64, "lkg", O_WRITE | O_TRUNC));
    fail("openat create", openat(d as u64, "new", O_WRITE | O_CREATE));
    fail("mkdirat", mkdirat(d as u64, "x"));
    close(d as u64);
    let r = dir_open(root, O_READ | O_WRITE);
    if r < 0 {
        println!("timetest: FAIL dir_open {}: {}", root, error_name(r));
        return 1;
    }
    fail("unlinkat .deso/lkg from the root", unlinkat(r as u64, ".deso/lkg"));
    fail("unlinkat .deso from the root", unlinkat(r as u64, ".deso"));
    fail("openat .deso/lkg write from the root", openat(r as u64, ".deso/lkg", O_WRITE));
    fail("mkdirat .deso/z from the root", mkdirat(r as u64, ".deso/z"));
    close(r as u64);
    // Still readable and the same.
    let after = match read_file(&file) {
        Ok(d) => d,
        Err(e) => {
            println!("timetest: FAIL {} unreadable after the attempts: {}", file, strerror(e));
            return 1;
        }
    };
    if after != before || after.len() != 56 {
        println!("timetest: FAIL {} changed or not 56 bytes ({} bytes)", file, after.len());
        return 1;
    }
    // The protection is not wider than it should be: the rest of the volume is writable,
    // also names that only start like it.
    for p in [format!("{}/timetest-ok", root), format!("{}/.desox", root), format!("{}/.deso", sub)] {
        let is_dir = p.ends_with("/.deso");
        let made = if is_dir {
            mkdir(&p)
        } else {
            let f = open(&p, O_WRITE | O_CREATE);
            if f >= 0 {
                let w = write(f as u64, b"x");
                close(f as u64);
                if w == 1 { 0 } else { -1 }
            } else {
                f
            }
        };
        if made < 0 || unlink(&p) < 0 {
            println!("timetest: FAIL {} is not writable: {}", p, error_name(made));
            return 1;
        }
    }
    let _ = unlink(&sub);
    if !ok {
        return 1;
    }
    println!("timetest protect: {} attempts refused, lkg readable ({} bytes), {} writable", refused, after.len(), root);
    0
}

fn stale(file: &str, opened: &str, go: &str) -> i32 {
    let fd = open(file, O_WRITE);
    if fd < 0 {
        println!("timetest: FAIL open {} before the mount: {}", file, error_name(fd));
        return 1;
    }
    let m = open(opened, O_WRITE | O_CREATE);
    if m < 0 {
        println!("timetest: FAIL create {}: {}", opened, error_name(m));
        return 1;
    }
    close(m as u64);
    let mut waited = 0;
    while stat(go).is_err() {
        if waited >= 20_000 {
            println!("timetest: FAIL {} never came", go);
            return 1;
        }
        sleep_ms(10);
        waited += 10;
    }
    let r = write(fd as u64, b"evil");
    close(fd as u64);
    if r != ERROR_NOT_PERMITTED {
        println!("timetest: FAIL the write through the old handle: {} (expected {})", if r >= 0 { "allowed" } else { error_name(r) }, error_name(ERROR_NOT_PERMITTED));
        return 1;
    }
    println!("timetest stale: the write through a handle opened before the mount was refused");
    0
}

/// The first SETTIME handle this process holds.
fn settime_handle() -> Option<u64> {
    (0..64u64).find(|&h| matches!(handle_info(h), Ok((k, _)) if k == KIND_SETTIME))
}

fn set() -> i32 {
    let Some(h) = settime_handle() else {
        println!("timetest: FAIL no SETTIME handle");
        return 1;
    };
    let Ok(before) = time_bound() else {
        println!("timetest: FAIL time_bound");
        return 1;
    };
    let build_ms = before.build * 1000;
    let ok_t = build_ms + 86_400_000;
    let mut n = 0;
    let mut bad = false;
    let mut expect = |what: &str, r: i64, want: i64| {
        n += 1;
        if r != want {
            println!("timetest: FAIL {}: {} (expected {})", what, if r >= 0 { "accepted" } else { error_name(r) }, error_name(want));
            bad = true;
        }
    };
    // The right.
    expect("no handle", time_set(60, ok_t, 1000, 2), ERROR_INVALID_HANDLE);
    expect("the console instead", time_set(1, ok_t, 1000, 2), ERROR_INVALID_HANDLE);
    let weak = handle_dup(h, R_DUP);
    if weak < 0 {
        println!("timetest: FAIL handle_dup: {}", error_name(weak));
        return 1;
    }
    expect("SETTIME without WRITE", time_set(weak as u64, ok_t, 1000, 2), ERROR_ACCESS_DENIED);
    close(weak as u64);
    // The numbers.
    for servers in [0u64, 1, 4, u32::MAX as u64, u64::MAX] {
        expect("servers out of 2..=3", time_set(h, ok_t, 1000, servers), ERROR_INVALID_ARGUMENT);
    }
    expect("u above 10 s", time_set(h, ok_t, 10_001, 2), ERROR_INVALID_ARGUMENT);
    expect("u = u64::MAX", time_set(h, ok_t, u64::MAX, 2), ERROR_INVALID_ARGUMENT);
    expect("t - u before the build date", time_set(h, build_ms + 999, 1000, 2), ERROR_INVALID_ARGUMENT);
    expect("t = 0", time_set(h, 0, 0, 2), ERROR_INVALID_ARGUMENT);
    expect("t - u below 0", time_set(h, 500, 1000, 3), ERROR_INVALID_ARGUMENT);
    expect("t + u after 2099", time_set(h, 4_102_444_799_000, 1000, 2), ERROR_INVALID_ARGUMENT);
    expect("t + u overflows", time_set(h, u64::MAX - 10, 1000, 2), ERROR_INVALID_ARGUMENT);
    expect("t = u64::MAX", time_set(h, u64::MAX, 0, 2), ERROR_INVALID_ARGUMENT);
    // Lowering the LKG: an interval wholly below it.
    if before.lkg > before.build + 60 {
        expect("t + u below the LKG", time_set(h, (before.lkg - 30) * 1000, 1000, 2), ERROR_NOT_PERMITTED);
        expect("t + u one ms below the LKG", time_set(h, before.lkg * 1000 - 1001, 1000, 3), ERROR_NOT_PERMITTED);
    }
    let after = time_bound().unwrap_or_default();
    if bad {
        return 1;
    }
    if after != before {
        println!("timetest: FAIL something changed: {:?} -> {:?}", before, after);
        return 1;
    }
    println!("timetest set: {} refusals, nothing changed (LKG {}, file state {})", n, before.lkg, before.file);
    0
}

fn bound() -> i32 {
    let mut n = 0;
    let mut buf = [0xAAu8; 4096];
    let p = buf.as_mut_ptr() as u64;
    macro_rules! case {
        ($cond:expr, $($msg:tt)*) => {
            n += 1;
            if !$cond {
                println!("timetest: FAIL bound case {}: {}", n, format_args!($($msg)*));
                return 1;
            }
        };
    }
    let r = time_bound_raw(p, 39);
    case!(r == ERROR_INVALID_ARGUMENT && buf.iter().all(|&b| b == 0xAA), "len 39: {} and nothing written", r);
    let r = time_bound_raw(p, 0);
    case!(r == ERROR_INVALID_ARGUMENT && buf.iter().all(|&b| b == 0xAA), "len 0: {}", r);
    for len in [40u64, 41, 4096] {
        buf.fill(0xAA);
        let r = time_bound_raw(p, len);
        case!(r == 40 && buf[40..].iter().all(|&b| b == 0xAA) && buf[32..40] == [0; 8], "len {}: {} - exactly 40 bytes, the last 8 zero", len, r);
    }
    let mut first = [0u8; 40];
    first.copy_from_slice(&buf[..40]);
    let tb = TimeBound::parse(&first);
    case!(tb.bound == tb.lkg.max(tb.build) && tb.build > 0, "B = max(LKG, build date): {:?}", tb);
    case!(tb.recovery() == (tb.file == 4), "recovery flag = file unreadable: {:?}", tb);
    for (what, addr) in [("NULL", 0u64), ("a kernel address", 0xFFFF_8000_0000_0000), ("an unmapped address", 0x7000_0000_0000), ("the last bytes of the address space", u64::MAX - 20)] {
        let r = time_bound_raw(addr, 40);
        case!(r == ERROR_INVALID_ADDRESS, "{}: {}", what, error_name(r));
    }
    // A read-only page, and a buffer that runs from a mapping into the gap after it.
    match (mmap(4096, PROT_READ), mmap(4096, PROT_READ | PROT_WRITE)) {
        (Ok(ro), Ok(rw)) => {
            let r = time_bound_raw(ro, 40);
            case!(r == ERROR_INVALID_ADDRESS, "a read-only page: {}", error_name(r));
            unsafe { core::ptr::write_bytes((rw + 4096 - 20) as *mut u8, 0x55, 20) };
            let r = time_bound_raw(rw + 4096 - 20, 40);
            let tail = unsafe { core::slice::from_raw_parts((rw + 4096 - 20) as *const u8, 20) };
            case!(r == ERROR_INVALID_ADDRESS && tail.iter().all(|&b| b == 0x55), "across the end of a mapping: {} (nothing written)", error_name(r));
            let r = time_bound_raw(rw + 4096 - 40, 40);
            case!(r == 40, "the last 40 bytes of a mapping: {}", r);
            munmap(ro, 4096);
            munmap(rw, 4096);
        }
        _ => {
            println!("timetest: FAIL mmap");
            return 1;
        }
    }
    println!("timetest bound: {} cases OK (B={}, LKG={}, file={}, flags={})", n, tb.bound, tb.lkg, tb.file, tb.flags);
    0
}

fn clock(a: u64, b: u64, ms: u64) -> i32 {
    let slack = ms / 1000 + 3;
    let t0 = uptime_ms();
    sleep_ms(200);
    let slept = uptime_ms() - t0;
    if !(200..600).contains(&slept) {
        println!("timetest: FAIL sleep 200 ms took {} ms of uptime", slept);
        return 1;
    }
    let (mut n, mut at_a, mut at_b) = (0u64, 0u64, 0u64);
    let start = uptime_ms();
    while uptime_ms() - start < ms {
        let Ok(c) = time_unix() else {
            println!("timetest: FAIL syscall 59");
            return 1;
        };
        n += 1;
        // One second below as well: the uptime of two CPUs may differ by a few ms, so right
        // after a step made on another CPU a reading can fall just before the second.
        if (a - 1..=a + slack).contains(&c.secs) {
            at_a += 1;
        } else if (b - 1..=b + slack).contains(&c.secs) {
            at_b += 1;
        } else {
            println!("timetest: FAIL reading {}: {} is neither clock ({} / {})", n, c.secs, a, b);
            return 1;
        }
    }
    println!("timetest clock: {} readings ({} at a, {} at b), sleep 200 ms took {} ms", n, at_a, at_b, slept);
    0
}

fn main(args: Args) -> i32 {
    if args.get(1) == Some("clock") {
        let num = |i| args.get(i).and_then(|x: &str| x.parse::<u64>().ok());
        return match (num(2), num(3), num(4)) {
            (Some(a), Some(b), Some(ms)) => clock(a, b, ms),
            _ => 2,
        };
    }
    match (args.get(1), args.get(2)) {
        (Some("set"), None) => set(),
        (Some("bound"), None) => bound(),
        (Some("stale"), Some(file)) => match (args.get(3), args.get(4)) {
            (Some(opened), Some(go)) => stale(file, opened, go),
            _ => 2,
        },
        (Some("protect"), Some(root)) => protect(root),
        _ => {
            let usage: String = String::from("usage: timetest protect <root> | stale <file> <opened> <go> | set | bound");
            println!("{}", usage);
            2
        }
    }
}
