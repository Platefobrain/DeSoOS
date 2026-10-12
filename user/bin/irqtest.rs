// M19.d: test przerwań urządzenia w user space – irq_bind (prawa, EBUSY),
// przerwanie z `edu` budzi wait_many (W_IRQ), licznik irq_read, kilka
// przerwań przed obsługą = jedna pobudka z licznikiem, silnia zakończona
// przerwaniem, przerwanie razem z kanałem na jednej liście, zamknięcie
// uchwytu zwalnia wektor (20 razy więcej niż jest wektorów), zabicie
// procesu z przypiętym przerwaniem – urządzenie i wektor wracają.
// Wynik: "irqtest: N checks OK, ..." i kod 0, albo opis błędu i kod 1.
// Uruchamia go SVC TEST z uchwytem HW_ROOT (QEMU z `-device edu,addr=06`).
//
// Tryb dziecka: `irqtest holder` (uchwyt 0 = urządzenie) – przypina
// przerwanie i czeka w wait_many (do kill).
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
/// Status: przerwanie po skończonej silni; bit przerwania silni.
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
    31 // tu nie dochodzi – proces ma zginąć w wait_many
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

    // 1. irq_bind: prawa, rodzaj uchwytu, drugie przypięcie – EBUSY.
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

    // 2. Przerwanie na żądanie: zapis do rejestru "raise" – pobudka, licznik,
    //    status w urządzeniu; potwierdzenie (ack).
    wr(m, REG_IRQ_RAISE, 0x100);
    let r = wait_many(&[(irq, W_IRQ)], 2000);
    check!(n, r == Ok(1), "woken by the interrupt: {:?}", r);
    check!(n, irq_read(irq) == 1, "one interrupt counted");
    check!(n, rd(m, REG_IRQ_STATUS) == 0x100, "device status {:#x}", rd(m, REG_IRQ_STATUS));
    wr(m, REG_IRQ_ACK, 0x100);
    check!(n, rd(m, REG_IRQ_STATUS) == 0 && irq_read(irq) == 0, "acknowledged");

    // 3. 10 przerwań przed obsługą – pobudka (jedna albo kilka) z licznikiem.
    //    Licznik może być MNIEJSZY niż 10: przerwania tego samego wektora, które
    //    przyjdą, zanim procesor obsłuży poprzednie, APIC łączy w jedno (w QEMU
    //    zdarzyło się 9 z 10).  Dlatego usługa zawsze sprawdza status urządzenia
    //    – tu: wszystkie 10 bitów w rejestrze statusu przerwań edu.
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

    // 4. Silnia zakończona przerwaniem (zamiast odpytywania statusu).
    wr(m, REG_STATUS, STATUS_IRQ_FACT);
    wr(m, REG_FACT, 12);
    let r = wait_many(&[(irq, W_IRQ)], 2000);
    check!(n, r == Ok(1) && rd(m, REG_IRQ_STATUS) & IRQ_FACT != 0, "factorial interrupt: {:?}, status {:#x}", r, rd(m, REG_IRQ_STATUS));
    check!(n, rd(m, REG_FACT) == 479_001_600, "12! = {}", rd(m, REG_FACT));
    wr(m, REG_IRQ_ACK, IRQ_FACT);
    wr(m, REG_STATUS, 0);
    irq_read(irq);

    // 5. Przerwanie i kanał na jednej liście (wzór usługi): właściwy bit.
    let (a, b) = channel_create().unwrap_or((0, 0));
    wr(m, REG_IRQ_RAISE, 0x1);
    check!(n, wait_many(&[(a, W_READABLE), (irq, W_IRQ)], 2000) == Ok(0b10), "IRQ bit in a mixed list");
    irq_read(irq);
    wr(m, REG_IRQ_ACK, 0x1);
    chan_send(b, b"req", 0);
    check!(n, wait_many(&[(a, W_READABLE), (irq, W_IRQ)], 2000) == Ok(0b01), "channel bit in a mixed list");
    close(a);
    close(b);

    // 6. Zamknięcie uchwytu zwalnia wektor: 20 razy przypięcie / zamknięcie
    //    (wektorów jest 16 – bez zwalniania zabrakłoby ich).
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

    // 7. Zabity proces z przypiętym przerwaniem – urządzenie i wektor wracają.
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
