// M19.c: test przejmowania urządzeń – HW_ROOT (slot 3, bez praw kopiowania),
// dev_claim (odmowa: sterownik w jądrze, dysk, grafika, mostek; EBUSY;
// ENODEV), dev_info, dev_map rejestrów urządzenia `edu` z QEMU (identyfikacja,
// rejestr "żywotności", silnia), prawa mapowania, munmap w całości, przejęcie
// trzymane przez mapowanie, zapis przez mapowanie tylko do odczytu (#PF),
// zabicie procesu z zamapowanym urządzeniem – urządzenie wraca.
// Wynik: "devtest: N checks OK, ..." i kod 0, albo opis błędu i kod 1.
// Uruchamia go SVC TEST z uchwytem HW_ROOT (QEMU z `-device edu,addr=06`).
//
// Tryby dziecka (uchwyt 0 = urządzenie):
//   devtest rowrite – mapuje tylko do odczytu i pisze -> #PF
//   devtest holder  – mapuje rejestry i czeka (do kill)
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

/// `edu` (PCI 1234:11e8) – urządzenie QEMU do nauki sterowników.
const EDU: u64 = bdf(0, 6, 0);
const EDU_ID: u32 = 0x010000ed;
const REG_ID: u64 = 0x00;
const REG_LIVE: u64 = 0x04;
const REG_FACT: u64 = 0x08;
const REG_STATUS: u64 = 0x20;
const BAR0: u64 = 1024 * 1024;
const PF_KILLED: u64 = 0x100 | 14;
const KILLED: u64 = 0x100 | 9;

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("devtest: FAIL check {}: {}", $n, format_args!($($msg)*));
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

fn rowrite() -> i32 {
    let Ok(m) = dev_map(0, 0, PROT_READ) else { return 10 };
    wr(m, REG_LIVE, 1); // #PF – proces ma tu zginąć
    11
}

fn holder() -> i32 {
    let Ok(m) = dev_map(0, 0, PROT_READ | PROT_WRITE) else { return 20 };
    let _ = rd(m, REG_ID);
    close(0); // samo mapowanie trzyma przejęcie
    loop {
        sleep_ms(1000);
    }
}

fn main(args: Args) -> i32 {
    match args.get(1) {
        Some("rowrite") => return rowrite(),
        Some("holder") => return holder(),
        _ => {}
    }
    let mut n = 0;

    // 1. HW_ROOT w slocie 3: bez praw – nie da się go skopiować, przekazać
    //    dziecku ani wysłać; read / write – EBADF.
    check!(n, handle_info(HW_ROOT) == Ok((KIND_HW_ROOT, 0)), "slot 3: {:?}", handle_info(HW_ROOT));
    check!(n, handle_dup(HW_ROOT, R_ALL) == -13, "handle_dup(HW_ROOT) must be EACCES");
    let (a, b) = channel_create().unwrap_or((0, 0));
    check!(n, chan_send_h(a, b"", &[HW_ROOT], 0) == -13, "sending HW_ROOT must be EACCES");
    check!(n, spawn_ex("/bin/hello", &["hello"], &[(HW_ROOT, 3)], 0) == -13, "giving HW_ROOT to a child must be EACCES");
    let mut buf = [0u8; 4];
    check!(n, read(HW_ROOT, &mut buf) == -9 && write(HW_ROOT, b"x") == -9, "read / write on HW_ROOT must be EBADF");
    close(a);
    close(b);

    // 2. dev_claim: tylko z HW_ROOT, zły adres, brak urządzenia; urządzenia,
    //    których usługa nie dostanie (topologia q35 z test.sh).
    check!(n, dev_claim(1, EDU) == -9, "dev_claim from the console must be EBADF");
    check!(n, dev_claim(HW_ROOT, 0x10000) == -22, "bad address must be EINVAL");
    check!(n, dev_claim(HW_ROOT, bdf(0, 0x1e, 0)) == ENODEV, "no device must be ENODEV");
    let forbidden = [
        (bdf(0, 0, 0), "host bridge"),
        (bdf(0, 1, 0), "VGA (console framebuffer)"),
        (bdf(0, 4, 0), "virtio-blk (kernel driver)"),
        (bdf(0, 5, 0), "NVMe (kernel driver)"),
        (bdf(0, 0x1f, 0), "ISA bridge"),
        (bdf(0, 0x1f, 2), "SATA (disk, no driver)"),
    ];
    for (addr, what) in forbidden {
        let r = dev_claim(HW_ROOT, addr);
        check!(n, r == -13, "{} must be EACCES ({})", what, r);
    }

    // 3. edu: przejęcie, prawa, drugie przejęcie – EBUSY, opis.
    let h = dev_claim(HW_ROOT, EDU);
    if h == ENODEV {
        println!("devtest: FAIL no edu device at 00:06.0 (QEMU needs -device edu,addr=06)");
        return 1;
    }
    check!(n, h >= 0, "claim edu: {}", strerror(h));
    let h = h as u64;
    check!(n, handle_info(h) == Ok((KIND_DEVICE, R_MAP_READ | R_MAP_WRITE | R_DUP | R_TRANSFER)), "rights: {:?}", handle_info(h));
    check!(n, dev_claim(HW_ROOT, EDU) == EBUSY, "second claim must be EBUSY");
    let info = dev_info(h);
    check!(
        n,
        matches!(info, Ok(i) if i.vendor == 0x1234 && i.device == 0x11e8 && i.bars[0] == BAR0 && i.io_mask == 0 && i.msi),
        "dev_info: {:?}",
        info
    );
    check!(n, dev_info(1).is_err_and(|e| e == -9), "dev_info on the console must be EBADF");

    // 4. Rejestry: identyfikacja, "żywotność" (urządzenie odwraca bity), silnia.
    let m = match dev_map(h, 0, PROT_READ | PROT_WRITE) {
        Ok(m) => m,
        Err(e) => {
            println!("devtest: FAIL dev_map: {}", strerror(e));
            return 1;
        }
    };
    check!(n, rd(m, REG_ID) == EDU_ID, "identification {:#x}", rd(m, REG_ID));
    wr(m, REG_LIVE, 0x1234_5678);
    check!(n, rd(m, REG_LIVE) == !0x1234_5678u32, "liveness {:#x}", rd(m, REG_LIVE));
    wr(m, REG_FACT, 10);
    let t0 = uptime_ms();
    while rd(m, REG_STATUS) & 1 != 0 && uptime_ms() - t0 < 1000 {}
    check!(n, rd(m, REG_FACT) == 3_628_800, "10! = {}", rd(m, REG_FACT));

    // 5. Błędy mapowania i prawa.
    check!(n, dev_map(h, 1, PROT_READ) == Err(-22), "BAR 1 (none) must be EINVAL");
    check!(n, dev_map(h, 0, PROT_WRITE) == Err(-22) && dev_map(h, 9, PROT_READ) == Err(-22), "bad prot / BAR must be EINVAL");
    let ro = handle_dup(h, R_MAP_READ | R_DUP) as u64;
    check!(n, dev_map(ro, 0, PROT_READ | PROT_WRITE) == Err(-13), "write mapping without R_MAP_WRITE must be EACCES");
    let rm = dev_map(ro, 0, PROT_READ);
    check!(n, rm.is_ok() && rd(rm.unwrap_or(m), REG_ID) == EDU_ID, "read-only mapping");
    check!(n, munmap(rm.unwrap_or(0), BAR0) == 0, "munmap read-only mapping");
    check!(n, munmap(m, 4096) == -22, "partial munmap must be EINVAL");

    // 6. Zapis przez mapowanie tylko do odczytu – #PF kończy dziecko.
    let pid = spawn_ex("/bin/devtest", &["devtest", "rowrite"], &[(ro, 0), (1, 1)], 0);
    check!(n, pid > 0, "spawn rowrite: {}", strerror(pid));
    check!(n, wait(pid as u64, 0) == Ok((pid as u64, PF_KILLED)), "write to a read-only register mapping must be #PF");
    close(ro);

    // 7. Mapowanie trzyma przejęcie: po zamknięciu uchwytu urządzenie wciąż
    //    zajęte; po munmap – wolne.
    close(h);
    check!(n, dev_claim(HW_ROOT, EDU) == EBUSY, "mapping must keep the claim");
    check!(n, munmap(m, BAR0) == 0, "munmap");
    let h = dev_claim(HW_ROOT, EDU);
    check!(n, h >= 0, "claim after the last mapping is gone: {}", strerror(h));

    // 8. Proces z zamapowanym urządzeniem zabity – urządzenie wraca.
    let pid = spawn_ex("/bin/devtest", &["devtest", "holder"], &[(h as u64, 0), (1, 1)], 0);
    check!(n, pid > 0, "spawn holder: {}", strerror(pid));
    close(h as u64);
    sleep_ms(30);
    check!(n, dev_claim(HW_ROOT, EDU) == EBUSY, "device busy while the holder runs");
    check!(n, kill(pid as u64) == 0 && wait(pid as u64, 0) == Ok((pid as u64, KILLED)), "kill holder");
    let h = dev_claim(HW_ROOT, EDU);
    check!(n, h >= 0, "device free after the holder was killed: {}", strerror(h));
    close(h as u64);

    println!("devtest: {} checks OK, edu 1234:11e8 at 00:06.0, 10! = 3628800 via MMIO", n);
    0
}
