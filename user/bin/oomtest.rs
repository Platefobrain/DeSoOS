// Kernel heap test: programs fill the kernel heap by every budgeted way at once, and
// the kernel must refuse in time and keep working.
//   1. empty files until ramfs says ERROR_NO_SPACE (nodes and names count in its limit –
//      they no longer grow the heap without bound),
//   2. channel queues full of 4 KiB messages – as many as this process's handles allow
//      (~15 MiB) or until the IPC buffer budget (16 MiB) says ERROR_OUT_OF_MEMORY,
//   3. children that each map 4 KiB areas until refused, then wait: they are started
//      until the kernel heap reaches its reserve – a child stopped short of the area limit,
//      or spawn refused with ERROR_OUT_OF_MEMORY,
//   4. with the heap at its reserve (this process maps areas until refused, then at
//      once): pipe, channel, spawn are refused with ERROR_OUT_OF_MEMORY; getpid, uptime,
//      sleep, close still work,
//   5. everything released (children end, messages and files gone): the heap comes back,
//      pipe / channel / spawn work again.
// Result: "oomtest: N checks OK, ..." and code 0, or the first failure and code 1.
// Child mode: `oomtest areas <slot>` – fd 3 = a shared memory page where it reports its
// area count (plain memory, no syscall: at the reserve read / write are refused too).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

/// Files per directory (directories keep the name maps small).
const PER_DIR: u32 = 4096;
/// Safety stops.
const MAX_FILES: u32 = 500_000;
const MAX_KIDS: usize = 600;
/// The per-process area limit (vm.rs MAX_VMAS) minus the areas every process has.
const AREA_LIMIT_NEAR: u32 = 4000;

static mut KIDS: [u64; MAX_KIDS] = [0; MAX_KIDS];

/// Everything the test holds, released by `cleanup` on every way out.
struct Held {
    files: u32,
    chans: [u64; 64],
    nchans: usize,
    kids: usize,
    shm: u64,
}

/// Report slots in the shared page: 0 = not yet, otherwise DONE | area count.
const DONE: u32 = 1 << 31;

/// A failure inside a loop (not counted as a check).
macro_rules! fail_if {
    ($h:expr, $cond:expr, $($msg:tt)*) => {
        if $cond {
            cleanup(&mut $h);
            println!("oomtest: FAIL: {}", format_args!($($msg)*));
            return 1;
        }
    };
}

macro_rules! check {
    ($n:ident, $h:expr, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            // Cleanup first: with a full heap even this message could not be written.
            cleanup(&mut $h);
            println!("oomtest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

/// "/oom/dK" or "/oom/dK/fI" into `buf`.
fn name(buf: &mut [u8; 48], dir: u32, file: Option<u32>) -> &str {
    let mut n = 0;
    let mut put = |s: &[u8], n: &mut usize| {
        for &c in s {
            buf[*n] = c;
            *n += 1;
        }
    };
    put(b"/oom/d", &mut n);
    let mut num = [0u8; 10];
    put(digits(dir, &mut num), &mut n);
    if let Some(f) = file {
        put(b"/f", &mut n);
        put(digits(f, &mut num), &mut n);
    }
    core::str::from_utf8(&buf[..n]).unwrap_or("")
}

fn digits(mut v: u32, buf: &mut [u8; 10]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    &buf[i..]
}

/// Releases everything (none of these calls allocates, so they work with a full heap).
fn cleanup(h: &mut Held) {
    // Children (they only sleep) – killed and reaped.
    let kids = unsafe { &*core::ptr::addr_of!(KIDS) };
    for &pid in kids[..h.kids].iter().filter(|&&p| p != 0) {
        kill(pid);
        let _ = wait(pid, 0);
    }
    h.kids = 0;
    if h.shm != 0 {
        close(h.shm);
        h.shm = 0;
    }
    for &c in h.chans[..h.nchans].iter() {
        close(c);
    }
    h.nchans = 0;
    let mut b = [0u8; 48];
    for i in 0..h.files {
        unlink(name(&mut b, i / PER_DIR, Some(i % PER_DIR)));
    }
    for d in 0..=h.files / PER_DIR {
        unlink(name(&mut b, d, None));
    }
    h.files = 0;
    unlink("/oom");
}

/// The child: maps the report page, then 4 KiB areas until refused; writes the count
/// to its slot and sleeps until killed (sleep allocates nothing).
fn areas(slot: usize) -> i32 {
    let Ok(page) = shm_map(3, PROT_READ | PROT_WRITE) else { return 3 };
    let mut count: u32 = 0;
    let err = loop {
        match mmap(4096, PROT_READ) {
            Ok(_) => count += 1,
            Err(e) => break e,
        }
    };
    let report = if err == ERROR_OUT_OF_MEMORY { DONE | count } else { DONE | 0x7fff_ffff };
    unsafe { core::ptr::write_volatile((page as *mut u32).add(slot), report) };
    loop {
        sleep_ms(1000);
    }
}

fn main(args: Args) -> i32 {
    if args.get(1) == Some("areas") {
        return areas(args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0).min(MAX_KIDS - 1));
    }
    let mut n = 0;
    let mut h = Held { files: 0, chans: [0; 64], nchans: 0, kids: 0, shm: 0 };
    let mut b = [0u8; 48];
    cleanup(&mut h);
    check!(n, h, mkdir("/oom") == 0, "mkdir /oom");
    let s = shm_create(4096);
    check!(n, h, s >= 0, "shm for the children's reports");
    h.shm = s as u64;
    let page = shm_map(h.shm, PROT_READ | PROT_WRITE).unwrap_or(0);
    check!(n, h, page != 0, "map the report page");

    // 1. Empty files until the ramfs limit.
    let t0 = uptime_ms();
    let stop = loop {
        if h.files == MAX_FILES {
            break 0;
        }
        if h.files % PER_DIR == 0 {
            let r = mkdir(name(&mut b, h.files / PER_DIR, None));
            if r < 0 {
                break r;
            }
        }
        let fd = open(name(&mut b, h.files / PER_DIR, Some(h.files % PER_DIR)), O_WRITE | O_CREATE);
        if fd < 0 {
            break fd;
        }
        close(fd as u64);
        h.files += 1;
    };
    let files_ms = uptime_ms() - t0;
    check!(n, h, stop == ERROR_NO_SPACE, "after {} empty files: {} instead of ERROR_NO_SPACE (ramfs limit)", h.files, error_name(stop));
    check!(n, h, h.files > 20_000, "only {} empty files fit in ramfs", h.files);

    // 2. Channel queues full of 4 KiB messages until the IPC buffer budget.
    static MSG: [u8; 4096] = [0x6f; 4096];
    let mut sent = 0u32;
    let mut ipc_stop = 0;
    // At most 40 handles – the rest stays free for the checks below.
    'fill: while h.nchans + 2 <= 40 {
        let (a, z) = match channel_create() {
            Ok(pair) => pair,
            Err(e) => {
                ipc_stop = e;
                break;
            }
        };
        h.chans[h.nchans] = a;
        h.chans[h.nchans + 1] = z;
        h.nchans += 2;
        for end in [a, z] {
            loop {
                let r = chan_send(end, &MSG, CHAN_NONBLOCK);
                if r == ERROR_WOULD_BLOCK {
                    break; // this queue is full
                }
                if r < 0 {
                    ipc_stop = r;
                    break 'fill;
                }
                sent += 1;
            }
        }
    }
    check!(
        n,
        h,
        sent >= 2000 && matches!(ipc_stop, 0 | ERROR_OUT_OF_MEMORY | ERROR_TOO_MANY_HANDLES),
        "after {} messages: {} (expected the IPC budget or the handle limit)",
        sent,
        error_name(ipc_stop)
    );

    // 3. Children with thousands of areas until the kernel heap reaches its reserve.
    // (The report page was made before the files: shm and its mapping need heap too.)
    let t1 = uptime_ms();
    let mut why = "";
    let mut last_areas = 0u32;
    let mut num = [0u8; 10];
    while h.kids < MAX_KIDS {
        let slot = h.kids;
        let arg = core::str::from_utf8(digits(slot as u32, &mut num)).unwrap_or("0");
        let pid = spawn_ex("/bin/oomtest", &["oomtest", "areas", arg], &[(1, 1), (1, 2), (h.shm, 3)], 0);
        if pid == ERROR_OUT_OF_MEMORY {
            why = "spawn refused";
            break;
        }
        fail_if!(h, pid <= 0, "spawn child {}: {}", slot, error_name(pid));
        unsafe { (*core::ptr::addr_of_mut!(KIDS))[slot] = pid as u64 };
        h.kids += 1;
        // Wait for its report (or its end: it could not even map the report page).
        let t = uptime_ms();
        let rep = loop {
            let v = unsafe { core::ptr::read_volatile((page as *const u32).add(slot)) };
            if v & DONE != 0 {
                break Some(v & !DONE);
            }
            if matches!(wait(pid as u64, WNOHANG), Ok((p, _)) if p == pid as u64) {
                unsafe { (*core::ptr::addr_of_mut!(KIDS))[slot] = 0 };
                break None;
            }
            fail_if!(h, uptime_ms() - t >= 30_000, "child {} gave no report", slot);
            sleep_ms(1);
        };
        match rep {
            None => {
                why = "a child could not map its report page";
                break;
            }
            Some(c) => {
                last_areas = c;
                fail_if!(h, c == 0x7fff_ffff, "child {}: mmap failed with an error other than ERROR_OUT_OF_MEMORY", slot);
                if c < AREA_LIMIT_NEAR {
                    why = "a child stopped short of the area limit";
                    break;
                }
            }
        }
    }
    let kids_ms = uptime_ms() - t1;
    check!(n, h, !why.is_empty(), "{} children with {} areas each and the heap never reached its reserve", h.kids, last_areas);

    // 4. At the reserve.  The heap moves a little all the time (other tasks free and
    // allocate a few hundred bytes), so before each call this process maps areas itself
    // until refused – the heap is then exactly at the reserve – and the call right after
    // must be refused too.  A call that still got through (the heap moved down in
    // between) is kept, the push repeated, and the call tried again: at most 8 times.
    let mut own = 0u32;
    let push = |own: &mut u32| -> i64 {
        loop {
            match mmap(4096, PROT_READ) {
                Ok(_) => *own += 1,
                Err(e) => return e,
            }
            if *own >= 3 * AREA_LIMIT_NEAR {
                return 0;
            }
        }
    };
    let own_stop = push(&mut own);
    check!(n, h, own_stop == ERROR_OUT_OF_MEMORY, "own areas: {} after {}", error_name(own_stop), own);
    let mut extra: [u64; 32] = [0; 32];
    let mut nextra = 0;
    let refused = |what: &str, call: &mut dyn FnMut() -> Result<(u64, u64), i64>, own: &mut u32, extra: &mut [u64; 32], nextra: &mut usize| -> Result<u32, ()> {
        for attempt in 1..=8u32 {
            if push(own) != ERROR_OUT_OF_MEMORY {
                return Err(());
            }
            match call() {
                Err(ERROR_OUT_OF_MEMORY) => return Ok(attempt),
                Ok((a, b)) if *nextra + 2 <= extra.len() => {
                    extra[*nextra] = a;
                    extra[*nextra + 1] = b;
                    *nextra += 2;
                }
                _ => return Err(()),
            }
        }
        let _ = what;
        Err(())
    };
    let rp = refused("pipe", &mut || pipe(), &mut own, &mut extra, &mut nextra);
    let rc = refused("channel", &mut || channel_create(), &mut own, &mut extra, &mut nextra);
    let rs = refused(
        "spawn",
        &mut || {
            let r = spawn("/bin/hello", &["hello"], 0, STDIO);
            if r == ERROR_OUT_OF_MEMORY {
                Err(r)
            } else if r > 0 {
                let _ = wait(r as u64, 0);
                Ok((0, 0))
            } else {
                Err(r)
            }
        },
        &mut own,
        &mut extra,
        &mut nextra,
    );
    for &fd in extra[..nextra].iter().filter(|&&f| f != 0) {
        close(fd);
    }
    check!(n, h, rp.is_ok(), "pipe with a full heap not refused ({}, last child {} areas)", why, last_areas);
    check!(n, h, rc.is_ok(), "channel with a full heap not refused");
    check!(n, h, rs.is_ok(), "spawn with a full heap not refused");
    let me = getpid();
    let t = uptime_ms();
    sleep_ms(5);
    check!(n, h, me > 0 && uptime_ms() >= t + 5, "getpid / uptime / sleep with a full heap");

    // 5. Everything released: the heap comes back.
    let (files, kids) = (h.files, h.kids);
    let t2 = uptime_ms();
    cleanup(&mut h);
    let free_ms = uptime_ms() - t2;
    check!(n, h, stat("/oom").is_err(), "cleanup");
    let p = pipe();
    check!(n, h, p.is_ok(), "pipe after cleanup: {:?}", p);
    if let Ok((r, w)) = p {
        close(r);
        close(w);
    }
    let c = channel_create();
    check!(n, h, c.is_ok(), "channel after cleanup");
    if let Ok((a, z)) = c {
        close(a);
        close(z);
    }
    let pid = spawn("/bin/hello", &["hello"], 0, 0);
    check!(n, h, pid > 0 && matches!(wait(pid as u64, 0), Ok((_, 0))), "spawn after cleanup: {}", pid);
    println!(
        "oomtest: {} checks OK ({} empty files up to the ramfs limit in {} ms, {} IPC messages of 4 KiB queued, {} children with thousands of areas each (the last: {}) until the heap reserve ({}) in {} ms; then mmap / pipe / channel / spawn got ERROR_OUT_OF_MEMORY and the system kept running; released in {} ms, everything works again)",
        n, files, files_ms, sent, kids, last_areas, why, kids_ms, free_ms
    );
    0
}
