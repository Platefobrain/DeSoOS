// Limits test – one program tries to take the resources of the whole system,
// and the kernel must answer with an error (or kill only that program) and keep running:
//   1. process bomb: spawn until ERROR_WOULD_BLOCK (process limit), then kill them all
//      and spawn works again,
//   2. shared memory: shm_create(16 MiB) until ERROR_OUT_OF_MEMORY (kernel reserve),
//   3. memory hog: a child touches mmap pages until the kernel kills it (no
//      frames beyond the reserve) – the parent and the rest of the system survive,
//   4. ramfs: 1 MiB files until ERROR_NO_SPACE; far seek + write – ERROR_NO_SPACE, not a panic,
//   5. IPC buffers: channel queues full of 4 KiB messages until ERROR_OUT_OF_MEMORY; a write
//      to a pipe meanwhile – ERROR_OUT_OF_MEMORY; after closing everything comes back.
// Result: "limtest: N checks OK, ..." and exit code 0.  Child modes: `limtest sleep`,
// `limtest hog`.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("limtest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

const MAX_KIDS: usize = 1100;
static mut KIDS: [u64; MAX_KIDS] = [0; MAX_KIDS];
static mut MSG: [u8; 4096] = [0x5a; 4096];

/// Fills channel queues (up to `max` handles, starting at handle `first`) with
/// 4 KiB messages; returns (sent, error other than ERROR_WOULD_BLOCK or 0).
fn fill_queues(ch: &mut [u64; 64], max: usize) -> (usize, usize, i64) {
    let mut c = 0;
    while c + 2 <= max {
        match channel_create() {
            Ok((a, b)) => {
                ch[c] = a;
                ch[c + 1] = b;
                c += 2;
            }
            Err(_) => break,
        }
    }
    let msg = unsafe { &*core::ptr::addr_of!(MSG) };
    let mut sent = 0;
    for &e in ch[..c].iter() {
        loop {
            let r = chan_send(e, msg, CHAN_NONBLOCK);
            if r == ERROR_WOULD_BLOCK {
                break; // this queue is full – next one
            }
            if r < 0 {
                return (c, sent, r);
            }
            sent += 1;
        }
    }
    (c, sent, 0)
}

/// Helper: takes part of the IPC budget, reports on handle 0 and waits.
fn filler() -> i32 {
    let mut ch = [0u64; 64];
    let _ = fill_queues(&mut ch, 56);
    chan_send(0, b"ok", 0);
    sleep_ms(120_000);
    0
}

/// spawn of /bin/limtest that waits for resources freed by the previous check:
/// after `wait` the kernel may still be tearing the process down on another CPU
/// (process slot, its memory frames are released by the idle reaper), so
/// ERROR_WOULD_BLOCK / ERROR_OUT_OF_MEMORY right after a limit test is retried for up to 2 s.
fn spawn_retry(argv: &[&str], map: &[(u64, u64)]) -> i64 {
    let t = uptime_ms();
    loop {
        let pid = spawn_ex("/bin/limtest", argv, map, 0);
        if (pid != ERROR_WOULD_BLOCK && pid != ERROR_OUT_OF_MEMORY) || uptime_ms() - t > 2000 {
            return pid;
        }
        sleep_ms(10);
    }
}

fn hog() -> i32 {
    // 4 GiB region, touched page by page – the kernel eventually refuses a frame
    // (reserve) and kills the process.  If it did not: exit code 0 = test failure.
    let Ok(base) = mmap(4 << 30, PROT_READ | PROT_WRITE) else { return 2 };
    let mut off = 0u64;
    while off < (4 << 30) {
        unsafe { core::ptr::write_volatile((base + off) as *mut u8, 1) };
        off += 4096;
    }
    0
}

fn main(args: Args) -> i32 {
    match args.get(1) {
        Some("sleep") => {
            sleep_ms(120_000);
            return 0;
        }
        Some("hog") => return hog(),
        Some("fill") => return filler(),
        _ => {}
    }
    let mut n = 0;
    let kids = unsafe { &mut *core::ptr::addr_of_mut!(KIDS) };

    // 1. Process bomb.
    let mut k = 0;
    let err = loop {
        if k == MAX_KIDS {
            break 0;
        }
        let pid = spawn_ex("/bin/limtest", &["limtest", "sleep"], &[], 0);
        if pid <= 0 {
            break pid;
        }
        kids[k] = pid as u64;
        k += 1;
    };
    let procs = k;
    check!(n, err == ERROR_WOULD_BLOCK, "process bomb must end with ERROR_WOULD_BLOCK, got {} after {} processes", err, k);
    check!(n, k > 500, "too few processes before the limit: {}", k);
    for &pid in kids[..k].iter() {
        kill(pid);
    }
    for &pid in kids[..k].iter() {
        let _ = wait(pid, 0);
    }
    let pid = spawn_retry(&["limtest", "sleep"], &[]);
    check!(n, pid > 0, "spawn must work again after the bomb: {}", pid);
    kill(pid as u64);
    let _ = wait(pid as u64, 0);

    // 2. Shared memory until ERROR_OUT_OF_MEMORY (at most ~60 handles).
    let mut shm = [0u64; 64];
    let mut s = 0;
    let serr = loop {
        if s == 60 {
            break 0;
        }
        let h = shm_create(16 << 20);
        if h < 0 {
            break h;
        }
        shm[s] = h as u64;
        s += 1;
    };
    check!(n, serr == ERROR_OUT_OF_MEMORY, "shared memory must end with ERROR_OUT_OF_MEMORY (kernel reserve), got {} after {} x 16 MiB", serr, s);
    for &h in shm[..s].iter() {
        close(h);
    }
    let h = shm_create(16 << 20);
    check!(n, h >= 0, "shm_create must work again after closing: {}", h);
    close(h as u64);

    // 3. Memory hog – it dies, not the system.
    let pid = spawn_retry(&["limtest", "hog"], &[]);
    check!(n, pid > 0, "spawn hog: {}", pid);
    let st = wait(pid as u64, 0);
    check!(n, matches!(st, Ok((_, s)) if s & STATUS_SIGNALED != 0), "memory hog must be killed by the kernel: {:?}", st);

    // 4. ramfs until ERROR_NO_SPACE.
    let _ = mkdir("/limt");
    let mut files = 0;
    let mut name = *b"/limt/f00";
    let ferr = loop {
        if files == 99 {
            break 0;
        }
        name[7] = b'0' + (files / 10) as u8;
        name[8] = b'0' + (files % 10) as u8;
        let path = core::str::from_utf8(&name).unwrap();
        let fd = open(path, O_WRITE | O_CREATE | O_TRUNC);
        if fd < 0 {
            break fd;
        }
        let msg = unsafe { &*core::ptr::addr_of!(MSG) };
        let mut r = 0;
        for _ in 0..256 {
            r = write(fd as u64, msg);
            if r < 0 {
                break;
            }
        }
        close(fd as u64);
        files += 1;
        if r < 0 {
            break r;
        }
    };
    check!(n, ferr == ERROR_NO_SPACE, "ramfs must end with ERROR_NO_SPACE, got {} after {} file(s)", ferr, files);
    for i in 0..files {
        name[7] = b'0' + (i / 10) as u8;
        name[8] = b'0' + (i % 10) as u8;
        unlink(core::str::from_utf8(&name).unwrap());
    }
    let fd = open("/limt/far", O_WRITE | O_CREATE);
    check!(n, fd >= 0, "open /limt/far: {}", fd);
    check!(n, seek(fd as u64, 1 << 40, SEEK_SET) == 1 << 40, "seek to 1 TiB");
    let r = write(fd as u64, b"x");
    check!(n, r == ERROR_NO_SPACE, "write at 1 TiB must be ERROR_NO_SPACE, not a kernel panic: {}", r);
    close(fd as u64);
    unlink("/limt/far");
    unlink("/limt");

    // 5. IPC buffers until ERROR_OUT_OF_MEMORY.  One process has 64 handles (~16 MiB of queues),
    // so part of the budget is taken by a helper (`limtest fill`), the rest by us.
    let (p, q) = channel_create().unwrap_or((0, 0));
    let fpid = spawn_retry(&["limtest", "fill"], &[(q, 0)]);
    check!(n, fpid > 0, "spawn filler: {}", fpid);
    close(q);
    let mut info = RecvInfo::default();
    let mut ok = [0u8; 8];
    check!(n, chan_recv(p, &mut ok, 0, &mut info) == 2, "filler ready");
    let mut ch = [0u64; 64];
    let (c, sent, cerr) = fill_queues(&mut ch, 56);
    check!(n, cerr == ERROR_OUT_OF_MEMORY, "channel queues must end with ERROR_OUT_OF_MEMORY (IPC buffer budget), got {} after {} messages", cerr, sent);
    let pr = pipe();
    check!(n, pr.is_ok(), "pipe");
    let (pr_r, pr_w) = pr.unwrap_or((0, 0));
    // Leftover budget (< one 4 KiB message) – the pipe takes as much as fits,
    // then ERROR_OUT_OF_MEMORY.
    let msg = unsafe { &*core::ptr::addr_of!(MSG) };
    let mut piped = 0i64;
    let r = loop {
        let r = write(pr_w, &msg[..1024]);
        if r <= 0 || piped > 65536 {
            break r;
        }
        piped += r;
    };
    check!(n, r == ERROR_OUT_OF_MEMORY && piped < 4096 + 64, "pipe write with the budget used up must be ERROR_OUT_OF_MEMORY: {} after {} bytes", r, piped);
    for &e in ch[..c].iter() {
        close(e);
    }
    kill(fpid as u64);
    let _ = wait(fpid as u64, 0);
    close(p);
    check!(n, write(pr_w, b"hello") == 5, "pipe write works again after closing the channels");
    close(pr_r);
    close(pr_w);

    println!(
        "limtest: {} checks OK, {} processes before ERROR_WOULD_BLOCK, {} x 16 MiB shm before ERROR_OUT_OF_MEMORY, hog killed, {} MiB in ramfs before ERROR_NO_SPACE, {} x 4 KiB messages before ERROR_OUT_OF_MEMORY",
        n, procs, s, files, sent
    );
    0
}
