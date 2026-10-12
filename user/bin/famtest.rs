// P1 (po M19): test rodziny procesów po przeniesieniu zombie do rodziców
// (koniec globalnej tablicy ZOMBIES).  Uruchamia go jądro przez
// `init test /bin/famtest` (init zarejestrowany jako init – sieroty idą do
// niego) na kilku CPU:
//   1. 200 dzieci kończy się naraz – wait(ANY) odbiera każde dokładnie raz,
//      z właściwym kodem; potem ECHILD (także z WNOHANG),
//   2. wait na konkretny pid w odwrotnej kolejności,
//   3. WNOHANG przy żywym dziecku -> (0, 0), potem zwykłe wait,
//   4. 8 procesów "middle" (każdy 25 wnuków: połowa kończy się od razu, połowa
//      po chwili) kończy się bez wait – wnuki (żywe i zombie) przejmuje init;
//      famtest odbiera tylko swoje 8 dzieci,
//   5. 4 procesy po 50 dzieci każdy, równolegle, każdy liczy swoje statusy
//      (rodzice nie widzą cudzych zombie).
// Wynik: "famtest: N checks OK, ..." i kod 0.
//
// Tryby dziecka: `famtest exit <kod>`, `famtest sleep <ms> <kod>`,
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

/// `famtest middle n`: n wnuków (parzyste kończą się od razu, nieparzyste po
/// 30 ms), sam kończy się kodem 7 bez czekania.
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

/// `famtest parent n`: n dzieci, odbiera wszystkie; kod 0 = suma kodów zgodna.
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

    // 1. 200 dzieci naraz, każde odebrane dokładnie raz.
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

    // 2. Konkretne pid w odwrotnej kolejności.
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

    // 3. WNOHANG przy żywym dziecku.
    let s = child(&["famtest", "sleep", "50", "9"]).max(0) as u64;
    check!(n, wait(WAIT_ANY, WNOHANG) == Ok((0, 0)) && wait(s, WNOHANG) == Ok((0, 0)), "WNOHANG with a live child -> (0, 0)");
    check!(n, wait(s, 0) == Ok((s, 9)), "then a blocking wait returns it");

    // 4. Sieroty: 8 x middle (25 wnuków) – wnuki przejmuje init.
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

    // 5. 4 rodziców po 50 dzieci równolegle.
    let mut ps = [0u64; 4];
    for p in ps.iter_mut() {
        *p = child(&["famtest", "parent", "50"]).max(0) as u64;
    }
    let mut ok = true;
    for &p in &ps {
        ok &= wait(p, 0) == Ok((p, 0));
    }
    check!(n, ok, "4 parents x 50 children in parallel, each got exactly its own");

    // Sieroty z punktu 4 muszą zniknąć (init je odbiera) – po 30 ms + zapas.
    sleep_ms(200);
    println!("famtest: {} checks OK, 200 + 20 + 1 children, 8 x 25 orphans to init, 4 x 50 parallel", n);
    0
}
