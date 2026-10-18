// wait_many test – waiting on many handles at once: list errors
// (EINVAL / EBADF / EACCES), check only (timeout 0), timeout,
// channel and pipe readiness for read / write, closing the other side,
// wakeup by a message from a child, a server handling 4 clients at once
// (the user-space service pattern), full queue, kill of a process waiting in wait_many.
// Result: "waittest: N checks OK, ..." and exit code 0, or a description of the first error and
// exit code 1.  Run by SVC TEST (self-tests).
//
// Child modes (handle 0 = channel end):
//   waittest sender <ms>  – sleeps <ms>, sends one message, exit code 0
//   waittest client <n>   – n times: sends a number, waits for number + 1
//   waittest drain        – receives 64 messages, exit code 0
//   waittest waiter       – wait_many without a timeout (until killed)
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const CLIENTS: usize = 4;
const ROUNDS: u64 = 500;
const KILLED: u64 = 0x100 | 9;

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("waittest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

fn sender(ms: u64) -> i32 {
    sleep_ms(ms);
    if chan_send(0, b"wake", 0) != 0 { 2 } else { 0 }
}

fn client(rounds: u64) -> i32 {
    let mut buf = [0u8; 8];
    let mut info = RecvInfo::default();
    let base = getpid() * 1_000_000;
    for i in 0..rounds {
        let v = base + i;
        if chan_send(0, &v.to_le_bytes(), 0) != 0 {
            return 3;
        }
        if chan_recv(0, &mut buf, 0, &mut info) != 8 || u64::from_le_bytes(buf) != v + 1 {
            return 4;
        }
    }
    0
}

fn drain() -> i32 {
    let mut buf = [0u8; 8];
    let mut info = RecvInfo::default();
    for _ in 0..64 {
        if chan_recv(0, &mut buf, 0, &mut info) < 0 {
            return 5;
        }
    }
    0
}

fn waiter() -> i32 {
    let _ = wait_many(&[(0, W_READABLE)], FOREVER);
    6 // never reached – the process is meant to die in wait_many
}

fn spawn_child(mode: &[&str], ch: u64) -> i64 {
    let mut args = [""; 3];
    args[0] = "waittest";
    args[1..1 + mode.len()].copy_from_slice(mode);
    spawn_ex("/bin/waittest", &args[..1 + mode.len()], &[(ch, 0), (1, 1)], 0)
}

fn main(args: Args) -> i32 {
    match args.get(1) {
        Some("sender") => return sender(args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0)),
        Some("client") => return client(args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0)),
        Some("drain") => return drain(),
        Some("waiter") => return waiter(),
        _ => {}
    }
    let mut n = 0;
    let mut buf = [0u8; 64];
    let mut info = RecvInfo::default();

    // 1. List errors: empty / too long, bad handle, no signals, unknown
    //    signal, console, IRQ on a channel, missing RECV / SEND right.
    let (a, b) = channel_create().unwrap_or((0, 0));
    let r = syscall3(SYS_WAIT_MANY, 0, 0, 0);
    check!(n, r == -22, "n = 0 must be EINVAL ({})", r);
    let big = [(a, W_READABLE); WAIT_MAX + 1];
    let mut flat = [0u64; 2 * (WAIT_MAX + 1)];
    for (i, &(h, s)) in big.iter().enumerate() {
        flat[2 * i] = h;
        flat[2 * i + 1] = s;
    }
    let r = syscall3(SYS_WAIT_MANY, flat.as_ptr() as u64, (WAIT_MAX + 1) as u64, 0);
    check!(n, r == -22, "n = 17 must be EINVAL ({})", r);
    check!(n, wait_many(&[(a, W_READABLE), (60, W_READABLE)], 0) == Err(-9), "bad handle must be EBADF");
    check!(n, wait_many(&[(a, 0)], 0) == Err(-22) && wait_many(&[(a, 64)], 0) == Err(-22), "no / unknown signal must be EINVAL");
    check!(n, wait_many(&[(1, W_WRITABLE)], 0) == Err(-22), "console must be EINVAL");
    check!(n, wait_many(&[(a, W_IRQ)], 0) == Err(-22), "IRQ on a channel must be EINVAL");
    let send_only = handle_dup(a, R_SEND | R_DUP) as u64;
    let recv_only = handle_dup(a, R_RECV | R_DUP) as u64;
    check!(n, wait_many(&[(send_only, W_READABLE)], 0) == Err(-13), "READABLE without R_RECV must be EACCES");
    check!(n, wait_many(&[(recv_only, W_WRITABLE)], 0) == Err(-13), "WRITABLE without R_SEND must be EACCES");
    check!(n, syscall3(SYS_WAIT_MANY, 8, 1, 0) == -14, "bad list pointer must be EFAULT");

    // 2. Check only and timeout; an empty channel for writing – ready immediately.
    check!(n, wait_many(&[(a, W_READABLE)], 0) == Ok(0), "empty channel must not be readable");
    let t0 = uptime_ms();
    let r = wait_many(&[(a, W_READABLE), (b, W_READABLE)], 50);
    let dt = uptime_ms() - t0;
    check!(n, r == Ok(0) && (45..1000).contains(&dt), "timeout 50 ms: {:?} after {} ms", r, dt);
    check!(n, wait_many(&[(a, W_WRITABLE)], FOREVER) == Ok(1), "empty peer queue must be writable");
    check!(n, wait_many(&[(a, W_READABLE | W_WRITABLE)], 0) == Ok(1), "READABLE | WRITABLE: one bit");

    // 3. A message in the queue – the right bit; the same handle twice – both bits.
    let (c, d) = channel_create().unwrap_or((0, 0));
    chan_send(d, b"x", 0);
    check!(n, wait_many(&[(a, W_READABLE), (c, W_READABLE), (b, W_READABLE)], FOREVER) == Ok(0b010), "only entry 1 readable");
    check!(n, wait_many(&[(c, W_READABLE), (c, W_READABLE)], 0) == Ok(0b11), "same handle twice: both bits");
    chan_recv(c, &mut buf, 0, &mut info);
    check!(n, wait_many(&[(c, W_READABLE)], 0) == Ok(0), "after recv: not readable");

    // 4. Other side closed – ready for read (recv gives EPIPE) and for write (EPIPE).
    close(d);
    check!(n, wait_many(&[(c, W_READABLE), (c, W_WRITABLE)], FOREVER) == Ok(0b11), "closed peer: readable + writable");
    check!(n, chan_recv(c, &mut buf, CHAN_NONBLOCK, &mut info) == EPIPE, "closed peer: recv EPIPE");
    close(c);

    // 5. Wakeup: after 40 ms a child sends on the second of three channels.
    let (s1, s1c) = channel_create().unwrap_or((0, 0));
    let (s2, s2c) = channel_create().unwrap_or((0, 0));
    let (s3, s3c) = channel_create().unwrap_or((0, 0));
    let pid = spawn_child(&["sender", "40"], s2c);
    check!(n, pid > 0, "spawn sender: {}", strerror(pid));
    let t0 = uptime_ms();
    let r = wait_many(&[(s1, W_READABLE), (s2, W_READABLE), (s3, W_READABLE)], FOREVER);
    let dt = uptime_ms() - t0;
    check!(n, r == Ok(0b010) && dt >= 30, "woken by the child: {:?} after {} ms", r, dt);
    check!(n, chan_recv(s2, &mut buf, 0, &mut info) == 4 && info.sender == pid as u64, "message from the sender");
    check!(n, wait(pid as u64, 0) == Ok((pid as u64, 0)), "sender exit");
    for h in [s1, s1c, s2, s2c, s3, s3c] {
        close(h);
    }

    // 6. Server: 4 clients, each with its own channel, ROUNDS requests each; one
    //    process serves all of them via wait_many (the user-space service pattern).
    let mut ends = [0u64; CLIENTS];
    let mut pids = [0i64; CLIENTS];
    for i in 0..CLIENTS {
        let (srv, cl) = channel_create().unwrap_or((0, 0));
        let mut num = [0u8; 8];
        let rounds = fmt_u64(ROUNDS, &mut num);
        pids[i] = spawn_child(&["client", rounds], cl);
        close(cl);
        ends[i] = srv;
    }
    check!(n, pids.iter().all(|&p| p > 0), "spawn clients: {:?}", pids);
    let t0 = uptime_ms();
    let mut served = 0u64;
    let mut wakeups = 0u64;
    let mut open = CLIENTS;
    let mut bad = 0;
    while open > 0 {
        let mut list = [(0u64, 0u64); CLIENTS];
        let mut idx = [0usize; CLIENTS];
        let mut k = 0;
        for i in 0..CLIENTS {
            if ends[i] != 0 {
                list[k] = (ends[i], W_READABLE);
                idx[k] = i;
                k += 1;
            }
        }
        let Ok(mask) = wait_many(&list[..k], 5000) else {
            bad += 1;
            break;
        };
        if mask == 0 {
            bad += 1; // 5 s without any request – something got stuck
            break;
        }
        wakeups += 1;
        for j in 0..k {
            if mask & (1 << j) == 0 {
                continue;
            }
            let i = idx[j];
            let r = chan_recv(ends[i], &mut buf, CHAN_NONBLOCK, &mut info);
            if r == 8 {
                if info.sender != pids[i] as u64 {
                    bad += 1;
                }
                let v = u64::from_le_bytes(buf[..8].try_into().unwrap()) + 1;
                chan_send(ends[i], &v.to_le_bytes(), 0);
                served += 1;
            } else if r == EPIPE {
                close(ends[i]);
                ends[i] = 0;
                open -= 1;
            } else {
                bad += 1;
            }
        }
    }
    let srv_ms = uptime_ms() - t0;
    let mut clients_ok = true;
    for &p in &pids {
        clients_ok &= wait(p as u64, 0) == Ok((p as u64, 0));
    }
    check!(n, bad == 0 && served == CLIENTS as u64 * ROUNDS && clients_ok, "server: served {} of {}, bad {}, clients ok {}", served, CLIENTS as u64 * ROUNDS, bad, clients_ok);

    // 7. Pipe: read ready after a write, write ready immediately, read ready after
    //    the writer closes; wrong direction – EINVAL.
    let (pr, pw) = pipe().unwrap_or((0, 0));
    check!(n, wait_many(&[(pr, W_READABLE)], 0) == Ok(0) && wait_many(&[(pw, W_WRITABLE)], 0) == Ok(1), "empty pipe");
    check!(n, wait_many(&[(pr, W_WRITABLE)], 0) == Err(-22) && wait_many(&[(pw, W_READABLE)], 0) == Err(-22), "wrong pipe direction must be EINVAL");
    write(pw, b"abc");
    check!(n, wait_many(&[(a, W_READABLE), (pr, W_READABLE)], FOREVER) == Ok(0b10), "pipe readable after write");
    read(pr, &mut buf);
    close(pw);
    check!(n, wait_many(&[(pr, W_READABLE)], FOREVER) == Ok(1), "pipe readable after the writer closed (EOF)");
    close(pr);

    // 8. Full queue: 64 messages – write not ready; a child receives them –
    //    wait_many wakes up.
    let (f, fc) = channel_create().unwrap_or((0, 0));
    let mut sent = 0;
    while chan_send(f, b"fill", CHAN_NONBLOCK) == 0 {
        sent += 1;
    }
    check!(n, sent == 64 && wait_many(&[(f, W_WRITABLE)], 0) == Ok(0), "full queue: {} sent, must not be writable", sent);
    let pid = spawn_child(&["drain"], fc);
    close(fc);
    check!(n, wait_many(&[(f, W_WRITABLE)], FOREVER) == Ok(1), "writable after the child drained the queue");
    check!(n, wait(pid as u64, 0) == Ok((pid as u64, 0)), "drain exit");
    close(f);

    // 9. Kill of a process waiting in wait_many.
    let (k1, k1c) = channel_create().unwrap_or((0, 0));
    let pid = spawn_child(&["waiter"], k1c);
    close(k1c);
    sleep_ms(20);
    check!(n, kill(pid as u64) == 0, "kill waiter");
    check!(n, wait(pid as u64, 0) == Ok((pid as u64, KILLED)), "waiter status after kill");
    check!(n, wait_many(&[(k1, W_READABLE)], FOREVER) == Ok(1), "killed waiter's channel end closed");
    close(k1);
    close(a);
    close(b);
    close(send_only);
    close(recv_only);

    println!(
        "waittest: {} checks OK, server: {} requests from {} clients in {} ms, {} wake-ups",
        n,
        served,
        CLIENTS,
        srv_ms,
        wakeups
    );
    0
}

fn fmt_u64(mut v: u64, buf: &mut [u8; 8]) -> &str {
    let mut tmp = [0u8; 8];
    let mut k = 0;
    loop {
        tmp[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 || k == 8 {
            break;
        }
    }
    for i in 0..k {
        buf[i] = tmp[k - 1 - i];
    }
    core::str::from_utf8(&buf[..k]).unwrap_or("0")
}
