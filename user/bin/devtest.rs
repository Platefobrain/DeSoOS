// Device claiming test – HW_ROOT (slot 3, without copy rights),
// dev_claim (refusals: in-kernel driver, disk, graphics, bridge; ERROR_BUSY;
// ERROR_NO_DEVICE), dev_info, dev_map of the registers of QEMU's `edu` device (identification,
// "liveness" register, factorial), mapping rights, munmap as a whole, the claim
// held by a mapping, writing through a read-only mapping (#PF),
// killing a process with a mapped device – the device comes back.
// Result: "devtest: N checks OK, ..." and exit code 0, or an error description and code 1.
// Started by SVC TEST with the HW_ROOT handle (QEMU with `-device edu,addr=06`).
//
// Child modes (handle 0 = the device):
//   devtest rowrite – maps read-only and writes -> #PF
//   devtest holder  – maps the registers and waits (until killed)
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

/// `edu` (PCI 1234:11e8) – QEMU's educational device for learning driver writing.
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
    wr(m, REG_LIVE, 1); // #PF – the process is supposed to die here
    11
}

fn holder() -> i32 {
    let Ok(m) = dev_map(0, 0, PROT_READ | PROT_WRITE) else { return 20 };
    let _ = rd(m, REG_ID);
    close(0); // the mapping alone holds the claim
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

    // 1. HW_ROOT in slot 3: no rights – it cannot be copied, passed to a
    //    child or sent; read / write – ERROR_INVALID_HANDLE.
    check!(n, handle_info(HW_ROOT) == Ok((KIND_HW_ROOT, 0)), "slot 3: {:?}", handle_info(HW_ROOT));
    check!(n, handle_dup(HW_ROOT, R_ALL) == ERROR_ACCESS_DENIED, "handle_dup(HW_ROOT) must be ERROR_ACCESS_DENIED");
    let (a, b) = channel_create().unwrap_or((0, 0));
    check!(n, chan_send_h(a, b"", &[HW_ROOT], 0) == ERROR_ACCESS_DENIED, "sending HW_ROOT must be ERROR_ACCESS_DENIED");
    check!(n, spawn_ex("/bin/hello", &["hello"], &[(HW_ROOT, 3)], 0) == ERROR_ACCESS_DENIED, "giving HW_ROOT to a child must be ERROR_ACCESS_DENIED");
    let mut buf = [0u8; 4];
    check!(n, read(HW_ROOT, &mut buf) == ERROR_INVALID_HANDLE && write(HW_ROOT, b"x") == ERROR_INVALID_HANDLE, "read / write on HW_ROOT must be ERROR_INVALID_HANDLE");
    close(a);
    close(b);

    // 2. dev_claim: only with HW_ROOT, bad address, no device; devices
    //    a service must not get (q35 topology from test.sh).
    check!(n, dev_claim(1, EDU) == ERROR_INVALID_HANDLE, "dev_claim from the console must be ERROR_INVALID_HANDLE");
    check!(n, dev_claim(HW_ROOT, 0x10000) == ERROR_INVALID_ARGUMENT, "bad address must be ERROR_INVALID_ARGUMENT");
    check!(n, dev_claim(HW_ROOT, bdf(0, 0x1e, 0)) == ERROR_NO_DEVICE, "no device must be ERROR_NO_DEVICE");
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
        check!(n, r == ERROR_ACCESS_DENIED, "{} must be ERROR_ACCESS_DENIED ({})", what, r);
    }

    // 3. edu: claim, rights, second claim – ERROR_BUSY, description.
    let h = dev_claim(HW_ROOT, EDU);
    if h == ERROR_NO_DEVICE {
        println!("devtest: FAIL no edu device at 00:06.0 (QEMU needs -device edu,addr=06)");
        return 1;
    }
    check!(n, h >= 0, "claim edu: {}", strerror(h));
    let h = h as u64;
    check!(n, handle_info(h) == Ok((KIND_DEVICE, R_MAP_READ | R_MAP_WRITE | R_DUP | R_TRANSFER)), "rights: {:?}", handle_info(h));
    check!(n, dev_claim(HW_ROOT, EDU) == ERROR_BUSY, "second claim must be ERROR_BUSY");
    let info = dev_info(h);
    check!(
        n,
        matches!(info, Ok(i) if i.vendor == 0x1234 && i.device == 0x11e8 && i.bars[0] == BAR0 && i.io_mask == 0 && i.msi),
        "dev_info: {:?}",
        info
    );
    check!(n, dev_info(1).is_err_and(|e| e == ERROR_INVALID_HANDLE), "dev_info on the console must be ERROR_INVALID_HANDLE");

    // 4. Registers: identification, "liveness" (the device inverts bits), factorial.
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

    // 5. Mapping errors and rights.
    check!(n, dev_map(h, 1, PROT_READ) == Err(ERROR_INVALID_ARGUMENT), "BAR 1 (none) must be ERROR_INVALID_ARGUMENT");
    check!(n, dev_map(h, 0, PROT_WRITE) == Err(ERROR_INVALID_ARGUMENT) && dev_map(h, 9, PROT_READ) == Err(ERROR_INVALID_ARGUMENT), "bad prot / BAR must be ERROR_INVALID_ARGUMENT");
    let ro = handle_dup(h, R_MAP_READ | R_DUP) as u64;
    check!(n, dev_map(ro, 0, PROT_READ | PROT_WRITE) == Err(ERROR_ACCESS_DENIED), "write mapping without R_MAP_WRITE must be ERROR_ACCESS_DENIED");
    let rm = dev_map(ro, 0, PROT_READ);
    check!(n, rm.is_ok() && rd(rm.unwrap_or(m), REG_ID) == EDU_ID, "read-only mapping");
    check!(n, munmap(rm.unwrap_or(0), BAR0) == 0, "munmap read-only mapping");
    check!(n, munmap(m, 4096) == ERROR_INVALID_ARGUMENT, "partial munmap must be ERROR_INVALID_ARGUMENT");

    // 6. Writing through a read-only mapping – #PF terminates the child.
    let pid = spawn_ex("/bin/devtest", &["devtest", "rowrite"], &[(ro, 0), (1, 1)], 0);
    check!(n, pid > 0, "spawn rowrite: {}", strerror(pid));
    check!(n, wait(pid as u64, 0) == Ok((pid as u64, PF_KILLED)), "write to a read-only register mapping must be #PF");
    close(ro);

    // 7. A mapping holds the claim: after closing the handle the device is still
    //    taken; after munmap – free.
    close(h);
    check!(n, dev_claim(HW_ROOT, EDU) == ERROR_BUSY, "mapping must keep the claim");
    check!(n, munmap(m, BAR0) == 0, "munmap");
    let h = dev_claim(HW_ROOT, EDU);
    check!(n, h >= 0, "claim after the last mapping is gone: {}", strerror(h));

    // 8. A process with a mapped device is killed – the device comes back.
    let pid = spawn_ex("/bin/devtest", &["devtest", "holder"], &[(h as u64, 0), (1, 1)], 0);
    check!(n, pid > 0, "spawn holder: {}", strerror(pid));
    close(h as u64);
    sleep_ms(30);
    check!(n, dev_claim(HW_ROOT, EDU) == ERROR_BUSY, "device busy while the holder runs");
    check!(n, kill(pid as u64) == 0 && wait(pid as u64, 0) == Ok((pid as u64, KILLED)), "kill holder");
    let h = dev_claim(HW_ROOT, EDU);
    check!(n, h >= 0, "device free after the holder was killed: {}", strerror(h));
    close(h as u64);

    println!("devtest: {} checks OK, edu 1234:11e8 at 00:06.0, 10! = 3628800 via MMIO", n);
    0
}
