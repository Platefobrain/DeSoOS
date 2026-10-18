// Test of device interrupts in user space – irq_bind (rights, EBUSY),
// an interrupt from `edu` wakes wait_many (W_IRQ), the irq_read counter, several
// interrupts before handling = one wakeup with a counter, factorial completed
// by an interrupt, an interrupt together with a channel on one list, closing
// the handle releases the vector (20 times more than there are vectors), killing
// a process with a bound interrupt – the device and the vector come back.
// Result: "irqtest: N checks OK, ..." and exit code 0, or an error description and exit code 1.
// Run by SVC TEST with the HW_ROOT handle (QEMU with `-device edu,addr=06`).
//
// Child mode: `irqtest holder` (handle 0 = device) – binds the
// interrupt and waits in wait_many (until killed).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const EDU: u64 = bdf(0, 6, 0);
const REG_FACT: u64 = 0x08;
const REG_STATUS: u64 = 0x20;
const REG_IRQ_STATUS: u64 = 0x24;
const REG_IRQ_RAISE: u64 = 0x60;
const REG_IRQ_ACK: u64 = 0x64;
/// Status: interrupt after the factorial completes; the factorial interrupt bit.
const STATUS_IRQ_FACT: u32 = 0x80;
const IRQ_FACT: u32 = 0x1;
const KILLED: u64 = 0x100 | 9;

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("irqtest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

fn rd(base: u64, reg: u64) -> u32 {
    unsafe { core::ptr::read_volatile((base + reg) as *const u32) }
}

fn wr(base: u64, reg: u64, v: u32) {
    unsafe { core::ptr::write_volatile((base + reg) as *mut u32, v) }
}

fn holder() -> i32 {
    let irq = irq_bind(0);
    if irq < 0 {
        return 30;
    }
    let _ = wait_many(&[(irq as u64, W_IRQ)], FOREVER);
    31 // never reached – the process is meant to die in wait_many
}

fn main(args: Args) -> i32 {
    if args.get(1) == Some("holder") {
        return holder();
    }
    let mut n = 0;
    let dev = dev_claim(HW_ROOT, EDU);
    if dev < 0 {
        println!("irqtest: FAIL claim edu: {} (QEMU needs -device edu,addr=06)", strerror(dev));
        return 1;
    }
    let dev = dev as u64;
    let m = match dev_map(dev, 0, PROT_READ | PROT_WRITE) {
        Ok(m) => m,
        Err(e) => {
            println!("irqtest: FAIL dev_map: {}", strerror(e));
            return 1;
        }
    };

    // 1. irq_bind: rights, handle kind, a second bind – EBUSY.
    let ro = handle_dup(dev, R_MAP_READ | R_DUP) as u64;
    check!(n, irq_bind(ro) == -13, "irq_bind without R_MAP_WRITE must be EACCES");
    check!(n, irq_bind(1) == -9, "irq_bind on the console must be EBADF");
    close(ro);
    let irq = irq_bind(dev);
    check!(n, irq >= 0, "irq_bind: {}", strerror(irq));
    let irq = irq as u64;
    check!(n, handle_info(irq) == Ok((KIND_IRQ, R_RECV | R_DUP | R_TRANSFER)), "rights: {:?}", handle_info(irq));
    check!(n, irq_bind(dev) == EBUSY, "second irq_bind must be EBUSY");
    check!(n, irq_read(irq) == 0 && wait_many(&[(irq, W_IRQ)], 0) == Ok(0), "no interrupt yet");
    check!(n, wait_many(&[(irq, W_READABLE)], 0) == Err(-22), "READABLE on an IRQ must be EINVAL");
    check!(n, irq_read(dev) == -9, "irq_read on a device must be EBADF");

    // 2. Interrupt on demand: write to the "raise" register – wakeup, counter,
    //    status in the device; acknowledgement (ack).
    wr(m, REG_IRQ_RAISE, 0x100);
    let r = wait_many(&[(irq, W_IRQ)], 2000);
    check!(n, r == Ok(1), "woken by the interrupt: {:?}", r);
    check!(n, irq_read(irq) == 1, "one interrupt counted");
    check!(n, rd(m, REG_IRQ_STATUS) == 0x100, "device status {:#x}", rd(m, REG_IRQ_STATUS));
    wr(m, REG_IRQ_ACK, 0x100);
    check!(n, rd(m, REG_IRQ_STATUS) == 0 && irq_read(irq) == 0, "acknowledged");

    // 3. 10 interrupts before handling – a wakeup (one or several) with a counter.
    //    The counter may be LESS than 10: interrupts of the same vector that
    //    arrive before the CPU has handled the previous ones are merged by the APIC (in QEMU
    //    9 out of 10 has been seen).  That is why a service always checks the device status
    //    – here: all 10 bits in the edu interrupt status register.
    let all = 0x3FFu32 << 8;
    for i in 0..10u32 {
        wr(m, REG_IRQ_RAISE, 1 << (8 + i));
    }
    let t0 = uptime_ms();
    let mut total = 0;
    let mut wakeups = 0;
    while (total == 0 || rd(m, REG_IRQ_STATUS) & all != all) && uptime_ms() - t0 < 2000 {
        if wait_many(&[(irq, W_IRQ)], 500) == Ok(1) {
            wakeups += 1;
            total += irq_read(irq);
        }
    }
    total += irq_read(irq);
    check!(
        n,
        (1..=10).contains(&total) && wakeups >= 1 && rd(m, REG_IRQ_STATUS) & all == all,
        "10 interrupts: counted {}, {} wake-up(s), status {:#x}",
        total,
        wakeups,
        rd(m, REG_IRQ_STATUS)
    );
    wr(m, REG_IRQ_ACK, all);
    sleep_ms(5);
    irq_read(irq);

    // 4. Factorial completed by an interrupt (instead of polling the status).
    wr(m, REG_STATUS, STATUS_IRQ_FACT);
    wr(m, REG_FACT, 12);
    let r = wait_many(&[(irq, W_IRQ)], 2000);
    check!(n, r == Ok(1) && rd(m, REG_IRQ_STATUS) & IRQ_FACT != 0, "factorial interrupt: {:?}, status {:#x}", r, rd(m, REG_IRQ_STATUS));
    check!(n, rd(m, REG_FACT) == 479_001_600, "12! = {}", rd(m, REG_FACT));
    wr(m, REG_IRQ_ACK, IRQ_FACT);
    wr(m, REG_STATUS, 0);
    irq_read(irq);

    // 5. Interrupt and channel on one list (the service pattern): the right bit.
    let (a, b) = channel_create().unwrap_or((0, 0));
    wr(m, REG_IRQ_RAISE, 0x1);
    check!(n, wait_many(&[(a, W_READABLE), (irq, W_IRQ)], 2000) == Ok(0b10), "IRQ bit in a mixed list");
    irq_read(irq);
    wr(m, REG_IRQ_ACK, 0x1);
    chan_send(b, b"req", 0);
    check!(n, wait_many(&[(a, W_READABLE), (irq, W_IRQ)], 2000) == Ok(0b01), "channel bit in a mixed list");
    close(a);
    close(b);

    // 6. Closing the handle releases the vector: 20 rounds of bind / close
    //    (there are 16 vectors – without releasing we would run out).
    close(irq);
    let mut binds = 0;
    for _ in 0..20 {
        let q = irq_bind(dev);
        if q < 0 {
            break;
        }
        binds += 1;
        close(q as u64);
    }
    check!(n, binds == 20, "bind / close 20 times: {} succeeded", binds);
    let q = irq_bind(dev) as u64;
    wr(m, REG_IRQ_RAISE, 0x2);
    check!(n, wait_many(&[(q, W_IRQ)], 2000) == Ok(1) && irq_read(q) == 1, "interrupts work after re-binding");
    wr(m, REG_IRQ_ACK, 0x2);
    close(q);

    // 7. A killed process with a bound interrupt – the device and the vector come back.
    check!(n, munmap(m, 1024 * 1024) == 0, "munmap");
    let pid = spawn_ex("/bin/irqtest", &["irqtest", "holder"], &[(dev, 0), (1, 1)], 0);
    check!(n, pid > 0, "spawn holder: {}", strerror(pid));
    close(dev);
    sleep_ms(30);
    check!(n, dev_claim(HW_ROOT, EDU) == EBUSY, "device busy while the holder runs");
    check!(n, kill(pid as u64) == 0 && wait(pid as u64, 0) == Ok((pid as u64, KILLED)), "kill holder");
    let dev = dev_claim(HW_ROOT, EDU);
    check!(n, dev >= 0, "device free after kill: {}", strerror(dev));
    let q = irq_bind(dev as u64);
    check!(n, q >= 0, "irq_bind after kill: {}", strerror(q));
    close(q as u64);
    close(dev as u64);

    println!("irqtest: {} checks OK, 10 interrupts: counter {} in {} wake-up(s), 12! = 479001600 via interrupt", n, total, wakeups);
    0
}
