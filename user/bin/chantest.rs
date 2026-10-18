// Channel test – messages in both directions, sender filled in by
// the kernel, full / empty queue (EAGAIN), buffer too small (EMSGSIZE, the message
// stays), message too large, SEND / RECV rights, closing the other side
// (EPIPE after receiving the rest), ping-pong with a child process, kill of a child
// waiting for a message.  Result: "chantest: N checks OK, ..." and exit code 0,
// or a description of the first error and exit code 1.  Run by IPC TEST (self-tests).
//
// Child modes (handle 0 = channel end):
//   chantest echo  – sends back every message with number + 1, until EPIPE (exit code 0)
//   chantest block – waits for a message forever (until killed)
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const ROUNDS: u64 = 10_000;

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("chantest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

fn echo() -> i32 {
    let mut buf = [0u8; 8];
    let mut info = RecvInfo::default();
    loop {
        let r = chan_recv(0, &mut buf, 0, &mut info);
        if r == EPIPE {
            return 0;
        }
        if r != 8 {
            return 3;
        }
        let v = u64::from_le_bytes(buf) + 1;
        if chan_send(0, &v.to_le_bytes(), 0) != 0 {
            return 4;
        }
    }
}

fn block() -> i32 {
    let mut buf = [0u8; 8];
    let mut info = RecvInfo::default();
    chan_recv(0, &mut buf, 0, &mut info);
    5 // never reached – the process is meant to die in recv
}

fn main(args: Args) -> i32 {
    match args.get(1) {
        Some("echo") => return echo(),
        Some("block") => return block(),
        _ => {}
    }
    let mut n = 0;
    let mut buf = [0u8; MSG_MAX];
    let mut info = RecvInfo::default();
    let me = getpid();

    // 1. A pair of ends, rights, a message in both directions, sender = my pid.
    let (a, b) = match channel_create() {
        Ok(p) => p,
        Err(e) => {
            println!("chantest: FAIL channel_create: {}", strerror(e));
            return 1;
        }
    };
    check!(n, handle_info(a) == Ok((KIND_CHANNEL, R_SEND | R_RECV | R_DUP | R_TRANSFER)), "rights: {:?}", handle_info(a));
    check!(n, chan_send(a, b"ping", 0) == 0, "send a->b");
    let r = chan_recv(b, &mut buf, 0, &mut info);
    check!(n, r == 4 && &buf[..4] == b"ping", "recv on b: {} {:?}", r, &buf[..4]);
    check!(n, info == RecvInfo { len: 4, handles: 0, sender: me }, "info: {:?} (pid {})", info, me);
    check!(n, chan_send(b, b"pong!", 0) == 0 && chan_recv(a, &mut buf, 0, &mut info) == 5 && &buf[..5] == b"pong!", "b->a");
    check!(n, chan_send(a, b"", 0) == 0 && chan_recv(b, &mut buf, 0, &mut info) == 0 && info.len == 0, "empty message");

    // 2. Empty queue without waiting – EAGAIN; full (64) – EAGAIN; FIFO order.
    check!(n, chan_recv(b, &mut buf, CHAN_NONBLOCK, &mut info) == EAGAIN, "empty queue must be EAGAIN");
    let mut sent = 0u64;
    while chan_send(a, &sent.to_le_bytes(), CHAN_NONBLOCK) == 0 {
        sent += 1;
        if sent > 1000 {
            break;
        }
    }
    check!(n, sent == 64, "queue holds {} messages (want 64)", sent);
    check!(n, chan_send(a, b"x", CHAN_NONBLOCK) == EAGAIN, "full queue must be EAGAIN");
    let mut fifo = true;
    for i in 0..64u64 {
        let r = chan_recv(b, &mut buf, 0, &mut info);
        fifo &= r == 8 && u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]) == i;
    }
    check!(n, fifo, "messages out of order or lost");

    // 3. Buffer too small – EMSGSIZE, required size in info, the message stays;
    //    message too large – EMSGSIZE; a MSG_MAX message goes through.
    check!(n, chan_send(a, b"0123456789", 0) == 0, "send 10");
    let mut small = [0u8; 4];
    check!(n, chan_recv(b, &mut small, 0, &mut info) == EMSGSIZE && info.len == 10, "small buffer: info {:?}", info);
    check!(n, chan_recv(b, &mut buf, 0, &mut info) == 10 && &buf[..10] == b"0123456789", "message must stay after EMSGSIZE");
    let big = [7u8; MSG_MAX + 1];
    check!(n, chan_send(a, &big, 0) == EMSGSIZE, "message > 4096 must be EMSGSIZE");
    check!(n, chan_send(a, &big[..MSG_MAX], 0) == 0 && chan_recv(b, &mut buf, 0, &mut info) == MSG_MAX as i64 && buf.iter().all(|&x| x == 7), "4096-byte message");

    // 4. Rights: without SEND it cannot send, without RECV it cannot receive (EACCES); read / write on a channel – EBADF.
    let recv_only = handle_dup(a, R_RECV | R_DUP);
    let send_only = handle_dup(b, R_SEND);
    check!(n, recv_only >= 0 && chan_send(recv_only as u64, b"x", 0) == -13, "send without R_SEND must be EACCES");
    check!(n, send_only >= 0 && chan_recv(send_only as u64, &mut buf, CHAN_NONBLOCK, &mut info) == -13, "recv without R_RECV must be EACCES");
    check!(n, write(a, b"x") == -9 && read(a, &mut buf) == -9, "read / write on a channel must be EBADF");
    check!(n, chan_send(1, b"x", 0) == -9, "chan_send on the console must be EBADF");
    close(recv_only as u64);
    close(send_only as u64);

    // 5. Close: b sends 3 and disappears – a receives 3, then EPIPE; sending to a closed end – EPIPE.
    for i in 0..3u64 {
        chan_send(b, &i.to_le_bytes(), 0);
    }
    close(b);
    let mut got = 0;
    while chan_recv(a, &mut buf, 0, &mut info) == 8 {
        got += 1;
    }
    check!(n, got == 3, "messages sent before close: got {}", got);
    check!(n, chan_recv(a, &mut buf, 0, &mut info) == EPIPE && chan_send(a, b"x", 0) == EPIPE, "closed peer must be EPIPE");
    close(a);

    // 6. Ping-pong with a child (waiting and wakeups across two processes / CPUs).
    let (p, c) = channel_create().unwrap_or((0, 0));
    let pid = spawn("/bin/chantest", &["chantest", "echo"], 0, fds(c, 1, 2));
    check!(n, pid > 0, "spawn echo: {}", strerror(pid));
    close(c);
    let t0 = uptime_ms();
    let mut ok = true;
    for i in 0..ROUNDS {
        if chan_send(p, &i.to_le_bytes(), 0) != 0 || chan_recv(p, &mut buf, 0, &mut info) != 8 {
            ok = false;
            break;
        }
        ok &= u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]) == i + 1 && info.sender == pid as u64;
    }
    let ms = (uptime_ms() - t0).max(1);
    check!(n, ok, "ping-pong with the child failed");
    close(p);
    check!(n, wait(pid as u64, 0) == Ok((pid as u64, 0)), "echo child did not end with EPIPE / code 0");

    // 7. Kill of a process waiting in recv – it exits, its end disappears (EPIPE on our side).
    let (p, c) = channel_create().unwrap_or((0, 0));
    let pid = spawn("/bin/chantest", &["chantest", "block"], 0, fds(c, 1, 2));
    check!(n, pid > 0, "spawn block: {}", strerror(pid));
    close(c);
    sleep_ms(50);
    check!(n, kill(pid as u64) == 0, "kill blocked child");
    let st = wait(pid as u64, 0);
    check!(n, matches!(st, Ok((x, s)) if x == pid as u64 && s != 5), "killed child: {:?}", st);
    check!(n, chan_send(p, b"x", 0) == EPIPE, "end of a killed process must be closed (EPIPE)");
    close(p);

    println!("chantest: {} checks OK, ping-pong {} round trips in {} ms ({} us each)", n, ROUNDS, ms, ms * 1000 / ROUNDS);
    0
}
