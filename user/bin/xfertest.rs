// Test of passing handles in messages and of spawn_ex – a handle
// travels through a channel (gone from the sender, works at the receiver, rights
// unchanged), without R_TRANSFER – EACCES and the handle stays, a channel end cannot
// travel through its own channel (EINVAL), too little room for handles (EMSGSIZE)
// or a full table (EMFILE) – the message stays, handles in a message sent to a
// closed end are released, spawn_ex gives the child only the listed
// handles, and the child receives a read-only file through a channel.
// Result: "xfertest: N checks OK" and exit code 0, or a description of the first error and code 1.
// Started by IPC TEST (self-tests).
//
// `xfertest child` – mode of a child started by spawn_ex with a single
// handle: 0 = channel end.  Exit code 0 = everything matches, 10+ = number
// of the failed check.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const PATH: &str = "/xfertest.tmp";

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("xfertest: FAIL check {}: {}", $n, format_args!($($msg)*));
            unlink(PATH);
            return 1;
        }
    };
}

/// Child: has ONLY handle 0 (channel).  Receives a read-only file through the
/// channel, reads it, cannot write, sends back the number of bytes read.
fn child() -> i32 {
    // Nothing besides handle 0 – no console, nothing from the parent.
    if handle_info(0).map(|(k, _)| k) != Ok(KIND_CHANNEL) {
        return 10;
    }
    for h in 1..64 {
        if handle_info(h).is_ok() {
            return 11;
        }
    }
    let mut buf = [0u8; 64];
    let mut hs = [0u64; MSG_HANDLES];
    let mut info = RecvInfo::default();
    let r = chan_recv_h(0, &mut buf, &mut hs, 0, &mut info);
    if r != 4 || &buf[..4] != b"file" || info.handles != 1 || info.sender != getppid() {
        return 12;
    }
    let f = hs[0];
    if handle_info(f) != Ok((KIND_FILE, R_READ | R_TRANSFER)) {
        return 13;
    }
    let n = read(f, &mut buf);
    if n != 7 || &buf[..7] != b"content" {
        return 14;
    }
    if write(f, b"x") != -9 {
        return 15;
    }
    if chan_send(0, &(n as u64).to_le_bytes(), 0) != 0 {
        return 16;
    }
    0
}

fn main(args: Args) -> i32 {
    if args.get(1) == Some("child") {
        return child();
    }
    let mut n = 0;
    let mut buf = [0u8; 64];
    let mut hs = [0u64; MSG_HANDLES];
    let mut info = RecvInfo::default();
    unlink(PATH);
    let fd = open(PATH, O_READ | O_WRITE | O_CREATE | O_TRUNC);
    check!(n, fd >= 3, "open: {}", strerror(fd));
    let fd = fd as u64;
    check!(n, write(fd, b"content") == 7, "write");
    let (a, b) = match channel_create() {
        Ok(p) => p,
        Err(e) => {
            println!("xfertest: FAIL channel_create: {}", strerror(e));
            return 1;
        }
    };

    // 1. Handle through a channel: gone from the sender, works at the receiver, shared object.
    let ro = handle_dup(fd, R_READ | R_TRANSFER) as u64;
    check!(n, chan_send_h(a, b"file", &[ro], 0) == 0, "send with a handle");
    check!(n, handle_info(ro) == Err(-9), "sent handle must leave the sender's table");
    let r = chan_recv_h(b, &mut buf, &mut hs, 0, &mut info);
    check!(n, r == 4 && info.handles == 1, "recv: {} {:?}", r, info);
    let got = hs[0];
    check!(n, handle_info(got) == Ok((KIND_FILE, R_READ | R_TRANSFER)), "rights after transfer: {:?}", handle_info(got));
    seek(got, 0, SEEK_SET);
    check!(n, read(got, &mut buf) == 7 && &buf[..7] == b"content", "read via received handle");
    check!(n, write(got, b"x") == -9, "received read-only handle must not write");
    close(got);

    // 2. Without R_TRANSFER – EACCES, the handle stays with the sender; duplicated handle – EINVAL.
    let nt = handle_dup(fd, R_READ | R_DUP) as u64;
    check!(n, chan_send_h(a, b"x", &[nt], 0) == -13, "send without R_TRANSFER must be EACCES");
    check!(n, handle_info(nt).is_ok(), "handle must stay after a refused send");
    close(nt);
    let t = handle_dup(fd, R_READ | R_TRANSFER) as u64;
    check!(n, chan_send_h(a, b"x", &[t, t], 0) == -22, "same handle twice must be EINVAL");
    check!(n, chan_send_h(a, b"x", &[99], 0) == -9, "bad handle in the list must be EBADF");
    check!(n, handle_info(t).is_ok(), "handle must stay after EINVAL");

    // 3. A channel end does not travel through its own channel (neither end) – EINVAL; through another one it does.
    check!(n, chan_send_h(a, b"x", &[a], 0) == -22 && chan_send_h(a, b"x", &[b], 0) == -22, "own channel end must be EINVAL");
    let (c, d) = channel_create().unwrap_or((0, 0));
    check!(n, chan_send_h(a, b"end", &[d], 0) == 0, "send another channel's end");
    let r = chan_recv_h(b, &mut buf, &mut hs, 0, &mut info);
    let d2 = hs[0];
    check!(n, r == 3 && handle_info(d2).map(|(k, _)| k) == Ok(KIND_CHANNEL), "received channel end: {:?}", handle_info(d2));
    check!(n, chan_send(c, b"hi", 0) == 0 && chan_recv(d2, &mut buf, 0, &mut info) == 2 && &buf[..2] == b"hi", "transferred channel end works");
    close(c);
    close(d2);

    // 4. Too little room for handles – EMSGSIZE (info.handles = 1), the message stays.
    check!(n, chan_send_h(a, b"x", &[t], 0) == 0, "send t");
    let mut none: [u64; 0] = [];
    check!(n, chan_recv_h(b, &mut buf, &mut none, 0, &mut info) == EMSGSIZE && info.handles == 1, "no room for handles: {:?}", info);
    check!(n, chan_recv_h(b, &mut buf, &mut hs, 0, &mut info) == 1 && info.handles == 1, "message must stay after EMSGSIZE");
    let t = hs[0];

    // 5. Receiver's handle table full – EMFILE, the message stays; after freeing a slot – it goes through.
    check!(n, chan_send_h(a, b"y", &[t], 0) == 0, "send for EMFILE test");
    let mut extra = [0u64; 64];
    let mut k = 0;
    loop {
        let h = dup(fd);
        if h < 0 {
            break;
        }
        extra[k] = h as u64;
        k += 1;
    }
    check!(n, chan_recv_h(b, &mut buf, &mut hs, 0, &mut info) == -24, "full handle table must be EMFILE");
    close(extra[k - 1]);
    check!(n, chan_recv_h(b, &mut buf, &mut hs, 0, &mut info) == 1 && info.handles == 1, "message must stay after EMFILE");
    for &h in extra[..k - 1].iter() {
        close(h);
    }
    close(hs[0]);

    // 6. Handles in a message sent to a closed end are released (including a channel end inside).
    let (e, g) = channel_create().unwrap_or((0, 0));
    check!(n, chan_send_h(a, b"z", &[g], 0) == 0, "send g");
    close(b);
    check!(n, chan_send(e, b"x", 0) == EPIPE, "end inside a dropped message must be closed (EPIPE)");
    close(e);
    close(a);

    // 7. spawn_ex: the child gets only handle 0 (channel), the file through the channel.
    let (p, q) = channel_create().unwrap_or((0, 0));
    check!(n, spawn_ex("/bin/xfertest", &["xfertest", "child"], &[(q, 0), (q, 0)], 0) == -22, "duplicate child slot must be EINVAL");
    check!(n, spawn_ex("/bin/xfertest", &["xfertest", "child"], &[(q, 64)], 0) == -22, "child slot >= 64 must be EINVAL");
    let nodup = handle_dup(q, R_SEND | R_RECV) as u64;
    check!(n, spawn_ex("/bin/xfertest", &["xfertest", "child"], &[(nodup, 0)], 0) == -13, "handle without R_DUP must be EACCES");
    close(nodup);
    let pid = spawn_ex("/bin/xfertest", &["xfertest", "child"], &[(q, 0)], 0);
    check!(n, pid > 0, "spawn_ex: {}", strerror(pid));
    close(q);
    let ro = handle_dup(fd, R_READ | R_TRANSFER) as u64;
    seek(ro, 0, SEEK_SET);
    check!(n, chan_send_h(p, b"file", &[ro], 0) == 0, "send file to child");
    let r = chan_recv(p, &mut buf, 0, &mut info);
    check!(n, r == 8 && u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]) == 7 && info.sender == pid as u64, "child reply: {} {:?}", r, info);
    let st = wait(pid as u64, 0);
    check!(n, st == Ok((pid as u64, 0)), "child result: {:?} (10+ = failed child check)", st);
    close(p);
    close(t);

    // 8. No cycles: a channel end whose queue holds another channel end
    // cannot travel (EBUSY) – otherwise two channels would keep each other alive
    // after all handles are closed and the memory would never come back.
    let (x0, x1) = channel_create().unwrap_or((0, 0));
    let (y0, y1) = channel_create().unwrap_or((0, 0));
    let (z0, z1) = channel_create().unwrap_or((0, 0));
    check!(n, chan_send_h(x0, b"y0", &[y0], 0) == 0, "y0 into the queue of x1");
    check!(n, chan_send_h(y1, b"x1", &[x1], 0) == EBUSY, "x1 (a channel in its queue) must not travel: cycle x1 <-> y0");
    check!(n, handle_info(x1).is_ok(), "x1 must stay after EBUSY");
    check!(n, chan_send_h(z1, b"x1", &[x1], 0) == EBUSY, "x1 must not travel through any channel");
    check!(n, chan_send_h(x0, b"data", &[], 0) == 0 && chan_send_h(y1, b"data", &[], 0) == 0, "plain messages still pass");
    // After receiving y0, x1's queue holds no channels – x1 may travel; now it is
    // y0 (x1 lies in its queue) that cannot.
    let r = chan_recv_h(x1, &mut buf, &mut hs, 0, &mut info);
    check!(n, r == 2 && info.handles == 1, "x1 receives y0: {} {:?}", r, info);
    let y0b = hs[0];
    check!(n, chan_recv(x1, &mut buf, 0, &mut info) == 4, "x1 receives the plain message");
    check!(n, chan_send_h(y1, b"x1", &[x1], 0) == 0, "x1 travels once its queue holds no channel");
    check!(n, chan_send_h(x0, b"y0", &[y0b], 0) == EBUSY, "y0 (x1 in its queue) must not travel: cycle refused");
    check!(n, chan_send_h(z1, b"y0", &[y0b], 0) == EBUSY, "y0 must not travel through a third channel either");
    // A chain without a cycle still works: z0 (empty queue) in the queue of x1, which is in transit.
    check!(n, chan_send_h(x0, b"z0", &[z0], 0) == 0, "a chain without a cycle is allowed");
    close(x0);
    close(y0b);
    close(y1);
    close(z1);

    unlink(PATH);
    println!("xfertest: {} checks OK", n);
    0
}
