// M19.f: edud – sterownik urządzenia `edu` (QEMU) jako usługa w user space.
// Pierwsza prawdziwa usługa DeSoOS: rejestry przez dev_map, przerwania przez
// irq_bind + wait_many, DMA przez dma_alloc; klienci przez kanały.
//
// Uchwyty na starcie (daje je ten, kto uruchamia usługę – w 19.g menedżer w init):
//   1 = konsola (komunikaty), 3 = urządzenie (DEVICE), 4 = kanał połączeń.
// Protokół: user/lib/edu_proto.rs.  Usługa obsługuje prośby po kolei (urządzenie
// jest jedno); czekając na urządzenie, inne prośby czekają w kolejkach kanałów.
// Koniec: kanał połączeń zamknięty i żaden klient nie został -> kod 0.
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

const DEV: u64 = 3;
const LISTEN: u64 = 4;
/// wait_many: kanał połączeń + przerwanie + klienci.
const MAX_CLIENTS: usize = WAIT_MAX - 2;

const REG_ID: u64 = 0x00;
const REG_FACT: u64 = 0x08;
const REG_STATUS: u64 = 0x20;
const REG_IRQ_STATUS: u64 = 0x24;
const REG_IRQ_ACK: u64 = 0x64;
const REG_DMA_SRC: u64 = 0x80;
const REG_DMA_DST: u64 = 0x88;
const REG_DMA_COUNT: u64 = 0x90;
const REG_DMA_CMD: u64 = 0x98;
const STATUS_IRQ_FACT: u32 = 0x80;
const IRQ_FACT: u32 = 0x1;
const IRQ_DMA: u32 = 0x100;
const EDU_BUF: u64 = 0x40000;
const EDU_BITS: u64 = 28;
const EIO: i64 = -5;

struct Edu {
    regs: u64,
    irq: u64,
    buf: &'static mut [u8],
    phys: u64,
    irqs: u64,
}

impl Edu {
    fn rd(&self, reg: u64) -> u32 {
        unsafe { core::ptr::read_volatile((self.regs + reg) as *const u32) }
    }

    fn wr(&self, reg: u64, v: u32) {
        unsafe { core::ptr::write_volatile((self.regs + reg) as *mut u32, v) }
    }

    fn wr64(&self, reg: u64, v: u64) {
        unsafe { core::ptr::write_volatile((self.regs + reg) as *mut u64, v) }
    }

    /// Czeka, aż urządzenie zgłosi `bit` w statusie przerwań (pobudka przez
    /// przerwanie; licznik to tylko „coś przyszło” – decyduje status).
    fn wait_dev(&mut self, bit: u32) -> Result<(), i64> {
        let t0 = uptime_ms();
        while self.rd(REG_IRQ_STATUS) & bit == 0 {
            let left = 1000u64.saturating_sub(uptime_ms() - t0);
            if left == 0 {
                return Err(EIO);
            }
            if wait_many(&[(self.irq, W_IRQ)], left) == Ok(1) {
                self.irqs += irq_read(self.irq) as u64;
            }
        }
        self.wr(REG_IRQ_ACK, bit);
        Ok(())
    }

    fn fact(&mut self, n: u64) -> Result<u64, i64> {
        if n > 12 {
            return Err(-22); // 13! nie mieści się w 32-bitowym rejestrze edu
        }
        self.wr(REG_FACT, n as u32);
        self.wait_dev(IRQ_FACT)?;
        Ok(self.rd(REG_FACT) as u64)
    }

    fn dma(&mut self, src: u64, dst: u64, len: u64, to_ram: bool) -> Result<(), i64> {
        self.wr64(REG_DMA_SRC, src);
        self.wr64(REG_DMA_DST, dst);
        self.wr64(REG_DMA_COUNT, len);
        self.wr64(REG_DMA_CMD, 1 | 4 | if to_ram { 2 } else { 0 });
        self.wait_dev(IRQ_DMA)
    }

    /// Dane klienta -> bufor DMA -> urządzenie -> druga połowa bufora.
    fn copy(&mut self, data: &[u8]) -> Result<usize, i64> {
        let n = data.len();
        self.buf[..n].copy_from_slice(data);
        self.buf[4096..4096 + n].fill(0);
        self.dma(self.phys, EDU_BUF, n as u64, false)?;
        self.dma(EDU_BUF, self.phys + 4096, n as u64, true)?;
        Ok(n)
    }
}

fn main(_args: Args) -> i32 {
    // Urządzenie: rejestry, przerwanie (silnia kończy się przerwaniem), bufor DMA.
    let Ok(regs) = dev_map(DEV, 0, PROT_READ | PROT_WRITE) else {
        println!("edud: no device in slot 3");
        return 2;
    };
    let irq = irq_bind(DEV);
    let buf = dma_alloc(DEV, 8192, EDU_BITS);
    if irq < 0 || buf < 0 {
        println!("edud: irq_bind / dma_alloc failed: {} {}", strerror(irq), strerror(buf));
        return 3;
    }
    let phys = dma_phys(buf as u64).unwrap_or(0);
    let Ok(a) = shm_map(buf as u64, PROT_READ | PROT_WRITE) else { return 4 };
    close(buf as u64);
    let mut edu = Edu {
        regs,
        irq: irq as u64,
        buf: unsafe { core::slice::from_raw_parts_mut(a as *mut u8, 8192) },
        phys,
        irqs: 0,
    };
    edu.wr(REG_STATUS, STATUS_IRQ_FACT);

    let mut clients = [0u64; MAX_CLIENTS];
    let mut nclients = 0usize;
    let mut listening = true;
    let mut requests = 0u64;
    let mut msg = [0u8; MSG_MAX];
    let mut out = [0u8; MSG_MAX];
    let mut info = RecvInfo::default();
    loop {
        if !listening && nclients == 0 {
            return 0;
        }
        let mut list = [(0u64, 0u64); WAIT_MAX];
        let mut k = 0;
        if listening {
            list[k] = (LISTEN, W_READABLE);
            k += 1;
        }
        let irq_at = k;
        list[k] = (edu.irq, W_IRQ);
        k += 1;
        let first_client = k;
        for &c in &clients[..nclients] {
            list[k] = (c, W_READABLE);
            k += 1;
        }
        let Ok(ready) = wait_many(&list[..k], FOREVER) else { return 5 };

        // Przerwanie bez prośby (spóźnione) – tylko zdejmij licznik.
        if ready & (1 << irq_at) != 0 {
            edu.irqs += irq_read(edu.irq) as u64;
        }
        // Nowy klient: komunikat z końcem jego kanału.
        if listening && ready & 1 != 0 {
            let mut hs = [0u64; 1];
            let r = chan_recv_h(LISTEN, &mut msg, &mut hs, CHAN_NONBLOCK, &mut info);
            if r == EPIPE {
                listening = false;
            } else if r >= 0 && info.handles == 1 {
                if nclients < MAX_CLIENTS {
                    clients[nclients] = hs[0];
                    nclients += 1;
                } else {
                    close(hs[0]); // za dużo klientów – klient dostanie EPIPE
                }
            }
        }
        // Prośby klientów (od końca – usuwanie zamkniętych nie psuje indeksów).
        for j in (0..nclients).rev() {
            if ready & (1 << (first_client + j)) == 0 {
                continue;
            }
            let c = clients[j];
            let r = chan_recv(c, &mut msg, CHAN_NONBLOCK, &mut info);
            if r == EPIPE {
                close(c);
                clients[j] = clients[nclients - 1];
                nclients -= 1;
                continue;
            }
            if r < 0 {
                continue;
            }
            requests += 1;
            let r = r as usize;
            let len = if r < HDR {
                reply(-22, 0, 0, &[], &mut out)
            } else {
                let op = u32_at(&msg, 0);
                let arg = u64_at(&msg, 8);
                match op {
                    OP_PING => reply(0, op, edu.rd(REG_ID) as u64, &[], &mut out),
                    OP_FACT => match edu.fact(arg) {
                        Ok(v) => reply(0, op, v, &[], &mut out),
                        Err(e) => reply(e as i32, op, 0, &[], &mut out),
                    },
                    OP_COPY if r - HDR <= COPY_MAX => match edu.copy(&msg[HDR..r]) {
                        Ok(n) => {
                            let data = [0u8; 0];
                            let l = reply(0, op, n as u64, &data, &mut out);
                            out[l..l + n].copy_from_slice(&edu.buf[4096..4096 + n]);
                            l + n
                        }
                        Err(e) => reply(e as i32, op, 0, &[], &mut out),
                    },
                    OP_STATS => {
                        let mut d = [0u8; 24];
                        d[..8].copy_from_slice(&requests.to_le_bytes());
                        d[8..16].copy_from_slice(&edu.irqs.to_le_bytes());
                        d[16..].copy_from_slice(&(nclients as u64).to_le_bytes());
                        reply(0, op, requests, &d, &mut out)
                    }
                    _ => reply(-22, op, 0, &[], &mut out),
                }
            };
            chan_send(c, &out[..len], CHAN_NONBLOCK);
        }
    }
}
