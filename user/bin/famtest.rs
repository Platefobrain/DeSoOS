// Test of the process family after zombies were moved into their parents
// (no global ZOMBIES table).  The kernel runs it via
// `init test /bin/famtest` (registered as init – orphans go to
// it) on several CPUs:
//   1. 200 children exit at once – wait(ANY) reaps each exactly once,
//      with the right code; then ECHILD (also with WNOHANG),
//   2. wait for a specific pid in reverse order,
//   3. WNOHANG with a live child -> (0, 0), then a plain wait,
//   4. 8 "middle" processes (each with 25 grandchildren: half exit immediately, half
//      after a while) exit without waiting – init adopts the grandchildren (live and zombie);
//      famtest reaps only its own 8 children,
//   5. 4 processes with 50 children each, in parallel, each counting its own statuses
//      (parents do not see other parents' zombies).
// Result: "famtest: N checks OK, ..." and exit code 0.
//
// Child modes: `famtest exit <code>`, `famtest sleep <ms> <code>`,
// `famtest middle <n>`, `famtest parent <n>`.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const ECHILD: i64 = -10;

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("famtest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

fn num(args: &Args, i: usize) -> u64 {
    args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn child(args: &[&str]) -> i64 {
    spawn_ex("/bin/famtest", args, &[(1, 1)], 0)
}

fn text(v: u64, buf: &mut [u8; 20]) -> &str {
    let mut n = 0;
    let mut d = [0u8; 20];
    let mut v = v;
    loop {
        d[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..n {
        buf[i] = d[n - 1 - i];
    }
    core::str::from_utf8(&buf[..n]).unwrap_or("0")
}

/// `famtest middle n`: n grandchildren (even ones exit immediately, odd ones after
/// 30 ms), itself exits with code 7 without waiting.
fn middle(n: u64) -> i32 {
    for i in 0..n {
        if i % 2 == 0 {
            child(&["famtest", "exit", "1"]);
        } else {
            child(&["famtest", "sleep", "30", "2"]);
        }
    }
    7
}

static mut TASKS: [u8; 32768] = [0; 32768];

/// Is any famtest process other than this one still in the task list?
fn others_alive() -> bool {
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(TASKS) };
    let n = tasks(buf);
    if n < 0 {
        return false;
    }
    let me = getpid();
    let text = core::str::from_utf8(&buf[..n as usize]).unwrap_or("");
    text.lines().any(|l| {
        let f: [&str; 7] = {
            let mut it = l.split('\t');
            core::array::from_fn(|_| it.next().unwrap_or(""))
        };
        f[5] == "user" && f[6] == "famtest" && f[0].parse::<u64>().ok() != Some(me)
    })
}

/// `famtest parent n`: n children, reaps all of them; code 0 = the sum of codes matches.
fn parent(n: u64) -> i32 {
    let mut want = 0u64;
    let mut b = [0u8; 20];
    for i in 0..n {
        let code = (i * 7 + getpid()) % 200;
        want += code;
        if child(&["famtest", "exit", text(code, &mut b)]) <= 0 {
            return 20;
        }
    }
    let mut got = 0u64;
    for _ in 0..n {
        match wait(WAIT_ANY, 0) {
            Ok((_, s)) if s & STATUS_SIGNALED == 0 => got += s,
            _ => return 21,
        }
    }
    if wait(WAIT_ANY, 0) != Err(ECHILD) {
        return 22;
    }
    if got == want { 0 } else { 23 }
}

fn main(args: Args) -> i32 {
    match args.get(1) {
        Some("exit") => return num(&args, 2) as i32,
        Some("sleep") => {
            sleep_ms(num(&args, 2));
            return num(&args, 3) as i32;
        }
        Some("middle") => return middle(num(&args, 2)),
        Some("parent") => return parent(num(&args, 2)),
        _ => {}
    }
    let mut n = 0;
    let mut b = [0u8; 20];

    // 1. 200 children at once, each reaped exactly once.
    const N: usize = 200;
    let mut pids = [0u64; N];
    for (i, p) in pids.iter_mut().enumerate() {
        let r = child(&["famtest", "exit", text(i as u64, &mut b)]);
        *p = if r > 0 { r as u64 } else { 0 };
    }
    check!(n, pids.iter().all(|&p| p != 0), "spawn 200 children");
    let mut seen = [false; N];
    let mut ok = true;
    for _ in 0..N {
        match wait(WAIT_ANY, 0) {
            Ok((pid, st)) => match pids.iter().position(|&p| p == pid) {
                Some(i) if !seen[i] && st == i as u64 => seen[i] = true,
                _ => ok = false,
            },
            Err(_) => ok = false,
        }
    }
    check!(n, ok && seen.iter().all(|&s| s), "200 statuses, each once with its own code");
    check!(n, wait(WAIT_ANY, 0) == Err(ECHILD) && wait(WAIT_ANY, WNOHANG) == Err(ECHILD), "no children left -> ECHILD");

    // 2. Specific pids in reverse order.
    let mut few = [0u64; 20];
    for (i, p) in few.iter_mut().enumerate() {
        *p = child(&["famtest", "exit", text(100 + i as u64, &mut b)]).max(0) as u64;
    }
    let mut ok = true;
    for i in (0..20).rev() {
        ok &= wait(few[i], 0) == Ok((few[i], 100 + i as u64));
    }
    check!(n, ok, "wait(pid) in reverse order");
    check!(n, wait(few[0], 0) == Err(ECHILD), "wait on a reaped pid -> ECHILD");

    // 3. WNOHANG with a live child.
    let s = child(&["famtest", "sleep", "50", "9"]).max(0) as u64;
    check!(n, wait(WAIT_ANY, WNOHANG) == Ok((0, 0)) && wait(s, WNOHANG) == Ok((0, 0)), "WNOHANG with a live child -> (0, 0)");
    check!(n, wait(s, 0) == Ok((s, 9)), "then a blocking wait returns it");

    // 4. Orphans: 8 x middle (25 grandchildren) – init adopts the grandchildren.
    let mut mids = [0u64; 8];
    for m in mids.iter_mut() {
        *m = child(&["famtest", "middle", "25"]).max(0) as u64;
    }
    let mut ok = mids.iter().all(|&m| m != 0);
    for _ in 0..8 {
        match wait(WAIT_ANY, 0) {
            Ok((pid, 7)) if mids.contains(&pid) => {}
            _ => ok = false,
        }
    }
    check!(n, ok, "8 middle processes reaped (exit 7), grandchildren not ours");
    check!(n, wait(WAIT_ANY, WNOHANG) == Err(ECHILD), "orphans went to init, not to us");

    // 5. 4 parents with 50 children each, in parallel.
    let mut ps = [0u64; 4];
    for p in ps.iter_mut() {
        *p = child(&["famtest", "parent", "50"]).max(0) as u64;
    }
    let mut ok = true;
    for &p in &ps {
        ok &= wait(p, 0) == Ok((p, 0));
    }
    check!(n, ok, "4 parents x 50 children in parallel, each got exactly its own");

    // The orphans from step 4 must disappear (init reaps them).  They sleep 30 ms,
    // but on a busy host that can take longer – wait until no famtest process
    // other than us is left (at most 10 s), instead of a fixed pause.
    let t = uptime_ms();
    while others_alive() && uptime_ms() - t < 10_000 {
        sleep_ms(20);
    }
    sleep_ms(50);
    println!("famtest: {} checks OK, 200 + 20 + 1 children, 8 x 25 orphans to init, 4 x 50 parallel", n);
    0
}
