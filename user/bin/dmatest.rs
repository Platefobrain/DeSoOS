// User-space DMA test – dma_alloc (rights, sizes, address bus width,
// 16 MiB per-device limit), dma_phys, the `edu` device itself reads the
// service's buffer (RAM -> edu) and writes into it (edu -> RAM), transfer completion
// signalled by an interrupt, killing a process that holds a DMA buffer and a bound
// interrupt – the device comes back (the kernel checks frames and bus mastering).
// Result: "dmatest: N checks OK, ..." and exit code 0, or an error description and code 1.
// Started by SVC TEST with the HW_ROOT handle (QEMU with `-device edu,addr=06`).
//
// Child mode: `dmatest holder` (handle 0 = device) – 1 MiB DMA buffer,
// interrupt, waits in wait_many (until killed).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const EDU: u64 = bdf(0, 6, 0);
const REG_IRQ_STATUS: u64 = 0x24;
const REG_IRQ_ACK: u64 = 0x64;
const REG_DMA_SRC: u64 = 0x80;
const REG_DMA_DST: u64 = 0x88;
const REG_DMA_COUNT: u64 = 0x90;
const REG_DMA_CMD: u64 = 0x98;
/// DMA command: start, direction edu -> RAM, interrupt on completion.
const DMA_START: u64 = 1;
const DMA_TO_RAM: u64 = 2;
const DMA_IRQ: u64 = 4;
const IRQ_DMA: u32 = 0x100;
/// Buffer inside edu (4 KiB) – address in the device's address space.
const EDU_BUF: u64 = 0x40000;
/// edu sees only 28 address bits (QEMU: dma_mask) – higher bits are truncated.
const EDU_BITS: u64 = 28;
const MIB: u64 = 1024 * 1024;
const KILLED: u64 = 0x100 | 9;

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("dmatest: FAIL check {}: {}", $n, format_args!($($msg)*));
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

fn wr64(base: u64, reg: u64, v: u64) {
    unsafe { core::ptr::write_volatile((base + reg) as *mut u64, v) }
}

/// One edu DMA transfer finished by an interrupt; true – the interrupt arrived.
fn dma(m: u64, irq: u64, src: u64, dst: u64, len: u64, to_ram: bool) -> bool {
    wr64(m, REG_DMA_SRC, src);
    wr64(m, REG_DMA_DST, dst);
    wr64(m, REG_DMA_COUNT, len);
    wr64(m, REG_DMA_CMD, DMA_START | DMA_IRQ | if to_ram { DMA_TO_RAM } else { 0 });
    let ok = wait_many(&[(irq, W_IRQ)], 2000) == Ok(1) && rd(m, REG_IRQ_STATUS) & IRQ_DMA != 0;
    irq_read(irq);
    wr(m, REG_IRQ_ACK, IRQ_DMA);
    ok
}

fn holder() -> i32 {
    let buf = dma_alloc(0, MIB, EDU_BITS);
    let irq = irq_bind(0);
    if buf < 0 || irq < 0 {
        return 30;
    }
    let _ = shm_map(buf as u64, PROT_READ | PROT_WRITE);
    let _ = wait_many(&[(irq as u64, W_IRQ)], FOREVER);
    31 // never reached – the process is supposed to die in wait_many
}

fn main(args: Args) -> i32 {
    if args.get(1) == Some("holder") {
        return holder();
    }
    let mut n = 0;
    let dev = dev_claim(HW_ROOT, EDU);
    if dev < 0 {
        println!("dmatest: FAIL claim edu: {} (QEMU needs -device edu,addr=06)", strerror(dev));
        return 1;
    }
    let dev = dev as u64;
    let m = dev_map(dev, 0, PROT_READ | PROT_WRITE).unwrap_or(0);
    let irq = irq_bind(dev);
    check!(n, m != 0 && irq >= 0, "map / irq_bind: {:#x} {}", m, irq);
    let irq = irq as u64;

    // 1. Errors: rights, size, address bus; dma_phys only for DMA buffers.
    let ro = handle_dup(dev, R_MAP_READ | R_DUP) as u64;
    check!(n, dma_alloc(ro, 4096, EDU_BITS) == -13, "dma_alloc without R_MAP_WRITE must be EACCES");
    close(ro);
    check!(n, dma_alloc(1, 4096, EDU_BITS) == -9, "dma_alloc on the console must be EBADF");
    check!(n, dma_alloc(dev, 0, EDU_BITS) == -22 && dma_alloc(dev, 2 * MIB + 1, EDU_BITS) == -22, "bad size must be EINVAL");
    check!(n, dma_alloc(dev, 4096, 20) == -22 && dma_alloc(dev, 4096, 65) == -22, "bad address bits must be EINVAL");
    let plain = shm_create(4096) as u64;
    check!(n, dma_phys(plain) == Err(-22), "dma_phys on plain shared memory must be EINVAL");
    close(plain);

    // 2. Buffer: shared-memory handle, physical address within edu's reach.
    let buf = dma_alloc(dev, 5000, EDU_BITS);
    check!(n, buf >= 0, "dma_alloc: {}", strerror(buf));
    let buf = buf as u64;
    check!(n, handle_info(buf) == Ok((KIND_SHM, R_MAP_READ | R_MAP_WRITE | R_DUP | R_TRANSFER)), "rights: {:?}", handle_info(buf));
    check!(n, shm_size(buf) == 8192, "size rounded to pages: {}", shm_size(buf));
    let phys = dma_phys(buf).unwrap_or(u64::MAX);
    check!(n, phys % 4096 == 0 && phys + 8192 <= 1 << EDU_BITS, "physical address {:#x} below 2^28", phys);
    let a = shm_map(buf, PROT_READ | PROT_WRITE).unwrap_or(0);
    let mem = unsafe { core::slice::from_raw_parts_mut(a as *mut u8, 8192) };
    check!(n, a != 0 && mem.iter().all(|&b| b == 0), "new DMA buffer mapped and zeroed");

    // 3. edu reads the buffer (RAM -> edu), then writes it back into the second
    //    half (edu -> RAM); every transfer ends with an interrupt.
    for (i, b) in mem[..4096].iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(13).wrapping_add(7) as u8;
    }
    check!(n, dma(m, irq, phys, EDU_BUF, 4096, false), "DMA RAM -> edu: no interrupt");
    check!(n, dma(m, irq, EDU_BUF, phys + 4096, 4096, true), "DMA edu -> RAM: no interrupt");
    let same = mem[..4096] == mem[4096..];
    check!(n, same, "device copied the buffer: first difference at {:?}", (0..4096).find(|&i| mem[i] != mem[4096 + i]));
    // Second pass with a different pattern – edu really reads memory, not a stale buffer.
    for b in mem[..4096].iter_mut() {
        *b = !*b;
    }
    check!(n, dma(m, irq, phys, EDU_BUF, 4096, false) && dma(m, irq, EDU_BUF, phys + 4096, 4096, true), "second DMA round trip");
    check!(n, mem[..4096] == mem[4096..], "second pattern copied");

    // 3b. Closing the handle does not free the buffer (the device could still
    //     write to it): a new buffer must not get the same frames.
    munmap(a, 8192);
    close(buf);
    let b2 = dma_alloc(dev, 4096, EDU_BITS);
    let p2 = if b2 >= 0 { dma_phys(b2 as u64).unwrap_or(phys) } else { phys };
    check!(n, b2 >= 0 && (p2 + 4096 <= phys || p2 >= phys + 8192), "closed buffer reused while the device is claimed: {:#x} in {:#x}+8 KiB", p2, phys);
    close(b2 as u64);

    // 4. 16 MiB per-device limit: 12 KiB is already used, so 2 MiB fits 7 times.
    let mut big = 0;
    loop {
        let b = dma_alloc(dev, 2 * MIB, EDU_BITS);
        if b < 0 {
            check!(n, b == -12, "over the per-device limit must be ENOMEM ({})", b);
            break;
        }
        big += 1;
        close(b as u64); // the buffer stays (lives with the claim) – still counted against the limit
        if big > 8 {
            break;
        }
    }
    check!(n, big == 7, "2 MiB buffers within 16 MiB: {}", big);

    // 5. Killed process holding a DMA buffer and a bound interrupt – the device comes back.
    close(irq);
    munmap(m, MIB);
    let pid = spawn_ex("/bin/dmatest", &["dmatest", "holder"], &[(dev, 0), (1, 1)], 0);
    check!(n, pid > 0, "spawn holder: {}", strerror(pid));
    close(dev); // the child now holds the last claim – the 15 MiB of buffers are freed
    sleep_ms(30);
    check!(n, dev_claim(HW_ROOT, EDU) == EBUSY, "device busy while the holder runs");
    check!(n, kill(pid as u64) == 0 && wait(pid as u64, 0) == Ok((pid as u64, KILLED)), "kill holder");
    let d = dev_claim(HW_ROOT, EDU);
    check!(n, d >= 0, "device free after kill: {}", strerror(d));
    close(d as u64);

    println!("dmatest: {} checks OK, edu DMA RAM -> device -> RAM 2 x 4 KiB with interrupts, buffer at {:#x}", n, phys);
    0
}
