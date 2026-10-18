// Benchmark of user-space services on the `edu` device (QEMU).
//
// With HW_ROOT (kernel self-test, SVC TEST 7/7):
//   1. interrupt -> driver wakeup: write "raise", wait_many (W_IRQ),
//      status, ack – driver inside the process, no IPC,
//   2. factorial completed by an interrupt – driver inside the process,
//   3. the same driver as a service (/bin/edud): PING and factorial over a channel
//      (client -> service -> device -> reply),
//   4. service restart: kill -> device returns -> new instance -> first
//      reply (without the 100 ms delay added by the manager in init).
// Without HW_ROOT (e.g. from the shell, slot 3 = channel to init): only item 3 – via
// the `edu` service started by init (`svc_connect`).
//
// Each measurement lasts at least MIN_MS (ms clock; average of many rounds).
// Result: a human-readable sentence and a "svcbench-result k=v ..." line for the kernel.
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
const MIN_MS: u64 = 200;
const RESTARTS: u64 = 10;
const REG_FACT: u64 = 0x08;
const REG_STATUS: u64 = 0x20;
const REG_IRQ_STATUS: u64 = 0x24;
const REG_IRQ_RAISE: u64 = 0x60;
const REG_IRQ_ACK: u64 = 0x64;
const STATUS_IRQ_FACT: u32 = 0x80;
const IRQ_FACT: u32 = 0x1;
const IRQ_TEST: u32 = 0x100;

fn rd(base: u64, reg: u64) -> u32 {
    unsafe { core::ptr::read_volatile((base + reg) as *const u32) }
}

fn wr(base: u64, reg: u64, v: u32) {
    unsafe { core::ptr::write_volatile((base + reg) as *mut u32, v) }
}

/// Repeats `round` for at least MIN_MS; ns per round or None (error).
fn timed(mut round: impl FnMut() -> bool) -> Option<u64> {
    let t0 = uptime_ms();
    let mut n = 0u64;
    loop {
        if !round() {
            return None;
        }
        n += 1;
        let e = uptime_ms() - t0;
        if e >= MIN_MS {
            return Some(e * 1_000_000 / n);
        }
    }
}

/// Waits until the device raises `bit` (interrupt wakeup), then acks.
fn wait_bit(m: u64, irq: u64, bit: u32) -> bool {
    while rd(m, REG_IRQ_STATUS) & bit == 0 {
        match wait_many(&[(irq, W_IRQ)], 1000) {
            Ok(1) => {
                irq_read(irq);
            }
            _ => return false,
        }
    }
    wr(m, REG_IRQ_ACK, bit);
    true
}

fn call(c: u64, op: u32, arg: u64) -> Option<u64> {
    let mut req = [0u8; 32];
    let n = request(op, arg, &[], &mut req);
    if chan_send(c, &req[..n], 0) != 0 {
        return None;
    }
    let mut msg = [0u8; 64];
    let mut info = RecvInfo::default();
    let r = chan_recv(c, &mut msg, 0, &mut info);
    if r < HDR as i64 || u32_at(&msg, 0) != 0 {
        return None;
    }
    Some(u64_at(&msg, 8))
}

fn connect(listen: u64) -> Option<u64> {
    let (mine, theirs) = channel_create().ok()?;
    if chan_send_h(listen, b"edu", &[theirs], 0) != 0 {
        close(mine);
        close(theirs);
        return None;
    }
    Some(mine)
}

/// The edud service with the device from HW_ROOT: (pid, connection channel).
fn start_edud() -> Option<(u64, u64)> {
    let dev = dev_claim(HW_ROOT, EDU);
    if dev < 0 {
        return None;
    }
    let (listen, listen_srv) = channel_create().ok()?;
    let pid = spawn_ex("/bin/edud", &["edud"], &[(1, 1), (dev as u64, 3), (listen_srv, 4)], 0);
    close(dev as u64);
    close(listen_srv);
    if pid <= 0 {
        close(listen);
        return None;
    }
    Some((pid as u64, listen))
}

/// PING and factorial via the service: (ns PING, ns factorial).
fn via_service(c: u64) -> Option<(u64, u64)> {
    let ping = timed(|| call(c, OP_PING, 0) == Some(0x010000ed))?;
    let fact = timed(|| call(c, OP_FACT, 12) == Some(479_001_600))?;
    Some((ping, fact))
}

fn us(ns: u64) -> (u64, u64) {
    (ns / 1000, ns % 1000 / 100)
}

fn main(_args: Args) -> i32 {
    let hw = handle_info(HW_ROOT).map(|(k, _)| k) == Ok(KIND_HW_ROOT);
    if !hw {
        // From the shell: the edu service started by init.
        let Ok(c) = svc_connect("edu") else {
            eprintln!("svcbench: no service manager channel (slot 3)");
            return 1;
        };
        let Some((ping, fact)) = via_service(c) else {
            eprintln!("svcbench: service 'edu' not available (see 'services'; QEMU needs -device edu,addr=06)");
            return 1;
        };
        close(c);
        let (p, pd) = us(ping);
        let (f, fd) = us(fact);
        println!("svcbench: via edud service: PING {}.{} us, 12! by interrupt {}.{} us per request", p, pd, f, fd);
        return 0;
    }

    // 1-2. Driver inside the process: interrupt and factorial.
    let dev = dev_claim(HW_ROOT, EDU);
    if dev < 0 {
        println!("svcbench: FAIL claim edu: {} (QEMU needs -device edu,addr=06)", strerror(dev));
        return 1;
    }
    let dev = dev as u64;
    let Ok(m) = dev_map(dev, 0, PROT_READ | PROT_WRITE) else {
        println!("svcbench: FAIL dev_map");
        return 1;
    };
    let irq = irq_bind(dev);
    if irq < 0 {
        println!("svcbench: FAIL irq_bind: {}", strerror(irq));
        return 1;
    }
    let irq = irq as u64;
    let irq_ns = timed(|| {
        wr(m, REG_IRQ_RAISE, IRQ_TEST);
        wait_bit(m, irq, IRQ_TEST)
    });
    wr(m, REG_STATUS, STATUS_IRQ_FACT);
    let fact_ns = timed(|| {
        wr(m, REG_FACT, 12);
        wait_bit(m, irq, IRQ_FACT) && rd(m, REG_FACT) == 479_001_600
    });
    wr(m, REG_STATUS, 0);
    close(irq);
    munmap(m, 1024 * 1024);
    close(dev);
    let (Some(irq_ns), Some(fact_ns)) = (irq_ns, fact_ns) else {
        println!("svcbench: FAIL in-process driver: interrupt lost (1 s timeout)");
        return 1;
    };

    // 3. The edud service: PING and factorial over a channel.
    let Some((mut pid, mut listen)) = start_edud() else {
        println!("svcbench: FAIL start edud");
        return 1;
    };
    let Some(c) = connect(listen) else { return 1 };
    let Some((ping_ns, fact_svc_ns)) = via_service(c) else {
        println!("svcbench: FAIL requests via edud");
        return 1;
    };
    close(c);

    // 4. Restart: kill -> new instance -> first reply.
    let t0 = uptime_ms();
    for _ in 0..RESTARTS {
        kill(pid);
        let _ = wait(pid, 0);
        close(listen);
        let Some((p, l)) = start_edud() else {
            println!("svcbench: FAIL restart edud (device not released?)");
            return 1;
        };
        (pid, listen) = (p, l);
        let c = connect(listen).unwrap_or(0);
        if call(c, OP_PING, 0) != Some(0x010000ed) {
            println!("svcbench: FAIL restarted edud does not answer");
            return 1;
        }
        close(c);
    }
    let restart_us = (uptime_ms() - t0) * 1000 / RESTARTS;
    close(listen);
    if wait(pid, 0).map(|(_, s)| s) != Ok(0) {
        println!("svcbench: FAIL edud did not exit cleanly");
        return 1;
    }

    let (a, ad) = us(irq_ns);
    let (b, bd) = us(fact_ns);
    let (p, pd) = us(ping_ns);
    let (f, fd) = us(fact_svc_ns);
    println!(
        "svcbench: in-process driver: interrupt -> woken {}.{} us, 12! {}.{} us; via edud: PING {}.{} us, 12! {}.{} us; restart {} us",
        a, ad, b, bd, p, pd, f, fd, restart_us
    );
    println!(
        "svcbench-result irq_user_ns={} fact_user_ns={} ping_svc_ns={} fact_svc_ns={} restart_us={}",
        irq_ns, fact_ns, ping_ns, fact_svc_ns, restart_us
    );
    0
}
