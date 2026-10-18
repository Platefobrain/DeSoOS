// Test of the edud service – starts it the way the service manager does (claiming the
// device via HW_ROOT, spawn_ex with handles 3 = device, 4 = connection channel),
// connects as a client: PING, factorial, DMA copy, bad request,
// 4 clients at once (separate processes), statistics; then kills the service while
// a client is working – the client gets EPIPE, the device comes back, a new service instance
// works and the client reconnects; finally shutdown – the service exits
// by itself (code 0).  Result: "edutest: N checks OK, ..." and code 0.
// Started by SVC TEST with the HW_ROOT handle (QEMU with `-device edu,addr=06`).
//
// Child mode: `edutest client <n>` (handle 4 = the service's connection channel) –
// connects and makes n factorial requests.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../lib/edu_proto.rs"]
mod edu_proto;

use desoos::*;
use edu_proto::*;

entry!(main);

const EDU: u64 = bdf(0, 6, 0);
const FACTS: [u64; 13] = [1, 1, 2, 6, 24, 120, 720, 5040, 40320, 362880, 3628800, 39916800, 479001600];
const CLIENTS: usize = 4;
const CLIENT_ROUNDS: u64 = 50;
const KILLED: u64 = 0x100 | 9;

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("edutest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

/// Connects to the service via its connection channel – returns the end of our own channel.
fn connect(listen: u64) -> Result<u64, i64> {
    let (mine, theirs) = channel_create()?;
    let r = chan_send_h(listen, b"edu", &[theirs], 0);
    if r != 0 {
        close(mine);
        close(theirs);
        return Err(r);
    }
    Ok(mine)
}

/// Request and reply: (status, value, length of data in `out`).
fn call(c: u64, op: u32, arg: u64, data: &[u8], out: &mut [u8]) -> Result<(i32, u64, usize), i64> {
    let mut req = [0u8; MSG_MAX];
    let n = request(op, arg, data, &mut req);
    let r = chan_send(c, &req[..n], 0);
    if r != 0 {
        return Err(r);
    }
    let mut info = RecvInfo::default();
    let mut msg = [0u8; MSG_MAX];
    let r = chan_recv(c, &mut msg, 0, &mut info);
    if r < 0 {
        return Err(r);
    }
    let r = r as usize;
    if r < HDR {
        return Err(-5);
    }
    out[..r - HDR].copy_from_slice(&msg[HDR..r]);
    Ok((u32_at(&msg, 0) as i32, u64_at(&msg, 8), r - HDR))
}

fn client(rounds: u64) -> i32 {
    let Ok(c) = connect(4) else { return 20 };
    let mut out = [0u8; 64];
    for i in 0..rounds {
        let k = (i + getpid()) % 13;
        match call(c, OP_FACT, k, &[], &mut out) {
            Ok((0, v, _)) if v == FACTS[k as usize] => {}
            _ => return 21,
        }
    }
    0
}

/// Starts the service: claim edu, connection channel, spawn_ex.  (pid, connection channel)
fn start_edud() -> Result<(i64, u64), &'static str> {
    let dev = dev_claim(HW_ROOT, EDU);
    if dev < 0 {
        return Err("claim edu");
    }
    let Ok((listen, listen_srv)) = channel_create() else { return Err("channel") };
    let pid = spawn_ex("/bin/edud", &["edud"], &[(1, 1), (dev as u64, 3), (listen_srv, 4)], 0);
    close(dev as u64);
    close(listen_srv);
    if pid <= 0 { Err("spawn edud") } else { Ok((pid, listen)) }
}

fn main(args: Args) -> i32 {
    if args.get(1) == Some("client") {
        return client(args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1));
    }
    let mut n = 0;
    let mut out = [0u8; MSG_MAX];

    // 1. Service start; the device now belongs to it.
    let (pid, listen) = match start_edud() {
        Ok(x) => x,
        Err(e) => {
            println!("edutest: FAIL start edud: {} (QEMU needs -device edu,addr=06)", e);
            return 1;
        }
    };
    check!(n, dev_claim(HW_ROOT, EDU) == EBUSY, "device must belong to the service");

    // 2. Client: PING, factorial, DMA copy, bad request.
    let c = connect(listen);
    check!(n, c.is_ok(), "connect: {:?}", c);
    let c = c.unwrap_or(0);
    check!(n, matches!(call(c, OP_PING, 0, &[], &mut out), Ok((0, 0x010000ed, 0))), "PING");
    let mut facts_ok = true;
    for k in 0..13u64 {
        facts_ok &= matches!(call(c, OP_FACT, k, &[], &mut out), Ok((0, v, 0)) if v == FACTS[k as usize]);
    }
    check!(n, facts_ok, "factorials 0..12 by the device");
    check!(n, matches!(call(c, OP_FACT, 13, &[], &mut out), Ok((-22, _, _))), "13! must be EINVAL (does not fit)");
    let mut data = [0u8; COPY_MAX];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(31).wrapping_add(3) as u8;
    }
    let r = call(c, OP_COPY, 0, &data, &mut out);
    check!(n, matches!(r, Ok((0, v, l)) if v == COPY_MAX as u64 && l == COPY_MAX) && out[..COPY_MAX] == data[..], "COPY {} B via DMA: {:?}", COPY_MAX, r);
    check!(n, matches!(call(c, 99, 0, &[], &mut out), Ok((-22, 0, _))), "unknown op must be EINVAL");
    check!(n, chan_send(c, b"x", 0) == 0, "short request");
    let mut info = RecvInfo::default();
    let r = chan_recv(c, &mut out, 0, &mut info);
    check!(n, r == HDR as i64 && u32_at(&out, 0) as i32 == -22, "short request must be answered with EINVAL");

    // 3. 4 clients at once (separate processes) – 50 factorials each.
    let mut pids = [0i64; CLIENTS];
    for p in pids.iter_mut() {
        *p = spawn_ex("/bin/edutest", &["edutest", "client", "50"], &[(1, 1), (listen, 4)], 0);
    }
    let mut clients_ok = pids.iter().all(|&p| p > 0);
    for &p in &pids {
        clients_ok &= wait(p as u64, 0) == Ok((p as u64, 0));
    }
    check!(n, clients_ok, "{} clients x {} requests", CLIENTS, CLIENT_ROUNDS);
    let r = call(c, OP_STATS, 0, &[], &mut out);
    let served = r.map(|(_, v, _)| v).unwrap_or(0);
    check!(n, served >= 18 + CLIENTS as u64 * CLIENT_ROUNDS, "stats: {} requests served", served);

    // 4. Service killed – the client gets EPIPE, the device comes back; a new instance
    //    (as on a restart by the service manager) works, the client reconnects.
    check!(n, kill(pid as u64) == 0 && wait(pid as u64, 0) == Ok((pid as u64, KILLED)), "kill edud");
    let r = call(c, OP_PING, 0, &[], &mut out);
    check!(n, r == Err(EPIPE), "client of a killed service must get EPIPE: {:?}", r);
    close(c);
    close(listen);
    let (pid, listen) = match start_edud() {
        Ok(x) => x,
        Err(e) => {
            println!("edutest: FAIL restart edud: {}", e);
            return 1;
        }
    };
    let c = connect(listen).unwrap_or(0);
    check!(n, matches!(call(c, OP_FACT, 12, &[], &mut out), Ok((0, 479001600, 0))), "restarted service answers");

    // 5. Shutdown: connection channel and client closed – the service exits by itself.
    close(c);
    close(listen);
    check!(n, wait(pid as u64, 0) == Ok((pid as u64, 0)), "edud exits when nobody can reach it");
    let d = dev_claim(HW_ROOT, EDU);
    check!(n, d >= 0, "device free after the service ended: {}", strerror(d));
    close(d as u64);

    println!("edutest: {} checks OK, {} requests served by edud (factorials, DMA copy of {} B, {} clients), restart after kill", n, served, COPY_MAX, CLIENTS);
    0
}
