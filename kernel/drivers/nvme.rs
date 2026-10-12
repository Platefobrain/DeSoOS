// M16b: sterownik dysków NVMe (PCIe, klasa 01:08:02).
//
// Jak rozmawia się z NVMe:
//   * Rejestry w BAR0: CAP (możliwości), CC (konfiguracja / włączenie),
//     CSTS (stan), AQA/ASQ/ACQ (kolejki administracyjne) i "dzwonki"
//     (doorbells) – po jednym na koniec kolejki zgłoszeń i początek kolejki
//     odpowiedzi.
//   * Polecenia (64 B) kernel wpisuje do kolejki zgłoszeń (SQ) w RAM-ie
//     i "dzwoni"; kontroler czyta je sam (DMA), wykonuje i wpisuje odpowiedź
//     (16 B) do kolejki odpowiedzi (CQ).  Bit fazy w odpowiedzi mówi, czy
//     wpis jest nowy (zmienia się przy każdym obiegu kolejki).
//   * Kolejka administracyjna (0): Identify, tworzenie kolejek I/O.
//     Kolejka I/O (1): Read / Write.  Dane przez PRP – listę adresów
//     fizycznych stron bufora.
//   * Przerwanie: MSI-X (albo MSI) na wektor z arch/msi.rs.  Bez nich –
//     odpytywanie.  Czekające zadanie i tak sprawdza kolejkę samo; przerwanie
//     tylko je budzi.
//
// "Kolejka wielu żądań": jeden odczyt/zapis dzielony jest na polecenia po
// max MAX_CMD bajtów, wszystkie trafiają do kolejki naraz (jeden dzwonek),
// a odpowiedzi zbieramy, gdy kontroler je kończy (w dowolnej kolejności).
//
// BEZPIECZEŃSTWO DANYCH (M16b – test na prawdziwym sprzęcie):
//   * zapis jest dozwolony TYLKO dla kontrolera emulowanego przez QEMU
//     (PCI 1b36:0010); każdy inny (prawdziwy SSD) jest "tylko do odczytu":
//     write() zwraca ReadOnly, zanim cokolwiek trafi do urządzenia, a warstwa
//     block i tak nie przepuszcza zapisu na taki dysk,
//   * sterownik nie wysyła żadnych poleceń zmieniających nośnik (Write,
//     Write Zeroes, DSM/TRIM, Format, Sanitize, Firmware) do prawdziwego SSD
//     – tylko Identify, Get/Set Features (liczba kolejek – ustawienie
//     ulotne), tworzenie kolejek i Read,
//   * reset kontrolera (CC.EN = 0) przy starcie robi każdy system (Linux
//     też) – niczego nie zapisuje na nośnik.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, AtomicBool, AtomicU64, Ordering};

use super::pci::{self, Bar, Device};
use crate::arch::x86_64::{interrupts, msi};
use crate::block::{self, BlockDevice, BlockError, SECTOR_SIZE};
use crate::memory::{alloc_frames, map_mmio, phys_to_virt};
use crate::serial_println;

/// Kontroler NVMe emulowany przez QEMU – jedyny, do którego wolno pisać.
pub const QEMU_VENDOR: u16 = 0x1B36;
pub const QEMU_DEVICE: u16 = 0x0010;

const REG_CAP: u64 = 0x00;
const REG_VS: u64 = 0x08;
const REG_CC: u64 = 0x14;
const REG_CSTS: u64 = 0x1C;
const REG_AQA: u64 = 0x24;
const REG_ASQ: u64 = 0x28;
const REG_ACQ: u64 = 0x30;
const DOORBELLS: u64 = 0x1000;

const CC_EN: u32 = 1;
const CC_IOSQES: u32 = 6 << 16; // 64 B
const CC_IOCQES: u32 = 4 << 20; // 16 B
const CSTS_RDY: u32 = 1;
const CSTS_CFS: u32 = 2;

// Polecenia administracyjne.
const ADM_CREATE_SQ: u8 = 0x01;
const ADM_CREATE_CQ: u8 = 0x05;
const ADM_IDENTIFY: u8 = 0x06;
const ADM_SET_FEATURES: u8 = 0x09;
// Polecenia I/O.
const IO_FLUSH: u8 = 0x00;
const IO_WRITE: u8 = 0x01;
const IO_READ: u8 = 0x02;

const PAGE: usize = 4096;
const QUEUE_ENTRIES: u16 = 64;
/// Bufor danych DMA (fizycznie ciągły): 128 KiB.
const DATA_FRAMES: usize = 32;
const DATA_BUFFER: usize = DATA_FRAMES * PAGE;
/// Największe pojedyncze polecenie (mniejsze, jeśli kontroler ma niższe MDTS).
const MAX_CMD: usize = 32 * 1024;
const PRP_SLOT: usize = 64; // bajtów listy PRP na polecenie (do 8 stron)
const ADMIN_TIMEOUT_MS: u64 = 5000;
const IO_TIMEOUT_MS: u64 = 10_000;

/// Zadania czekające na odpowiedź z dowolnego kontrolera (budzi MSI).
static NVME_WAIT: crate::sched::sync::WaitQueue = crate::sched::sync::WaitQueue::new();
static IRQS: AtomicU64 = AtomicU64::new(0);
static COMMANDS: AtomicU64 = AtomicU64::new(0);
static MAX_IN_FLIGHT: AtomicU64 = AtomicU64::new(0);
/// Testy: wymuś "tylko do odczytu" także dla QEMU.
static FORCE_READ_ONLY: AtomicBool = AtomicBool::new(false);

fn on_msi(_vector: u8) {
    IRQS.fetch_add(1, Ordering::Relaxed);
    NVME_WAIT.wake_all();
}

fn r32(a: u64) -> u32 {
    unsafe { read_volatile(a as *const u32) }
}
fn w32(a: u64, v: u32) {
    unsafe { write_volatile(a as *mut u32, v) }
}
fn r64(a: u64) -> u64 {
    (r32(a) as u64) | ((r32(a + 4) as u64) << 32)
}
fn w64(a: u64, v: u64) {
    w32(a, v as u32);
    w32(a + 4, (v >> 32) as u32);
}

/// Wyzerowany, fizycznie ciągły blok `frames` stron.
fn dma(frames: usize) -> Option<u64> {
    let p = alloc_frames(frames, 1)?;
    unsafe { core::ptr::write_bytes(phys_to_virt(p) as *mut u8, 0, frames * PAGE) };
    Some(p)
}

struct Queue {
    sq: u64, // adresy fizyczne
    cq: u64,
    size: u16,
    sq_tail: u16,
    cq_head: u16,
    phase: bool,
    sq_doorbell: u64,
    cq_doorbell: u64,
}

impl Queue {
    fn new(regs: u64, stride: u64, qid: u16, size: u16) -> Option<Queue> {
        let sq_pages = (size as usize * 64).div_ceil(PAGE);
        let cq_pages = (size as usize * 16).div_ceil(PAGE);
        Some(Queue {
            sq: dma(sq_pages)?,
            cq: dma(cq_pages)?,
            size,
            sq_tail: 0,
            cq_head: 0,
            phase: true,
            sq_doorbell: regs + DOORBELLS + (2 * qid as u64) * stride,
            cq_doorbell: regs + DOORBELLS + (2 * qid as u64 + 1) * stride,
        })
    }

    /// Wpisuje polecenie (bez dzwonka).
    fn push(&mut self, cmd: &[u32; 16]) {
        let slot = phys_to_virt(self.sq) + self.sq_tail as u64 * 64;
        for (i, &dw) in cmd.iter().enumerate() {
            unsafe { write_volatile((slot + i as u64 * 4) as *mut u32, dw) };
        }
        self.sq_tail = (self.sq_tail + 1) % self.size;
    }

    fn ring(&self) {
        fence(Ordering::SeqCst);
        w32(self.sq_doorbell, self.sq_tail as u32);
    }

    /// Adres DW3 bieżącego wpisu CQ.
    fn head_dw3(&self) -> u64 {
        phys_to_virt(self.cq) + self.cq_head as u64 * 16 + 12
    }

    fn has_completion(&self) -> bool {
        let dw3 = unsafe { read_volatile(self.head_dw3() as *const u32) };
        (dw3 >> 16 & 1 == 1) == self.phase
    }

    /// Zdejmuje odpowiedź: (CID, status, DW0).
    fn pop(&mut self) -> (u16, u16, u32) {
        let e = phys_to_virt(self.cq) + self.cq_head as u64 * 16;
        fence(Ordering::SeqCst);
        let dw0 = unsafe { read_volatile(e as *const u32) };
        let dw3 = unsafe { read_volatile((e + 12) as *const u32) };
        self.cq_head += 1;
        if self.cq_head == self.size {
            self.cq_head = 0;
            self.phase = !self.phase;
        }
        w32(self.cq_doorbell, self.cq_head as u32);
        (dw3 as u16, (dw3 >> 17) as u16 & 0x7FFF, dw0)
    }
}

pub struct Nvme {
    name: String,
    pci: pci::Address,
    vendor: u16,
    device: u16,
    regs: u64,
    admin: Queue,
    io: Option<Queue>,
    next_cid: u16,
    model: String,
    serial: String,
    firmware: String,
    version: u32,
    nsid: u32,
    /// Rozmiar bloku przestrzeni nazw (512 albo 4096) i liczba bloków.
    lba_size: usize,
    lba_count: u64,
    max_cmd: usize,
    data: u64, // bufor DMA (fizyczny)
    prp: u64,  // strona list PRP (fizyczna)
    vector: Option<u8>,
    irq_kind: &'static str,
    write_allowed: bool,
}

impl Nvme {
    fn cmd_id(&mut self) -> u16 {
        self.next_cid = self.next_cid.wrapping_add(1);
        if self.next_cid == 0xFFFF {
            self.next_cid = 1;
        }
        self.next_cid
    }

    /// Czeka, aż w kolejce będzie odpowiedź (przerwanie albo odpytywanie).
    fn wait_completion(&self, admin: bool, deadline: u64) -> Result<(), BlockError> {
        let q = if admin { &self.admin } else { self.io.as_ref().unwrap() };
        loop {
            if q.has_completion() {
                return Ok(());
            }
            if r32(self.regs + REG_CSTS) & CSTS_CFS != 0 {
                serial_println!("[NVMe] {}: controller fatal status", self.name);
                return Err(BlockError::Io);
            }
            if crate::time::ticks() > deadline {
                return Err(BlockError::Timeout);
            }
            if interrupts::are_enabled() && crate::sched::can_block() {
                // Śpimy do przerwania (MSI) albo najwyżej 10 ms – gdyby MSI
                // nie dochodziło, i tak sprawdzimy kolejkę.
                let cq = q.head_dw3();
                let phase = q.phase;
                NVME_WAIT.wait_until(
                    || ((unsafe { read_volatile(cq as *const u32) } >> 16 & 1) == 1) == phase,
                    Some(if self.vector.is_some() { 10 } else { 1 }),
                );
            } else {
                core::hint::spin_loop();
            }
        }
    }

    /// Wysyła polecenia naraz (jeden dzwonek) i czeka na wszystkie.
    /// Zwraca DW0 odpowiedzi (w kolejności poleceń).
    fn run(&mut self, admin: bool, cmds: &mut [[u32; 16]], timeout_ms: u64) -> Result<Vec<u32>, BlockError> {
        let n = cmds.len();
        let mut cids = Vec::with_capacity(n);
        for c in cmds.iter_mut() {
            let cid = self.cmd_id();
            c[0] = (c[0] & 0xFFFF) | (cid as u32) << 16;
            cids.push(cid);
        }
        {
            let q = if admin { &mut self.admin } else { self.io.as_mut().ok_or(BlockError::Io)? };
            if n >= q.size as usize {
                return Err(BlockError::Io);
            }
            for c in cmds.iter() {
                q.push(c);
            }
            q.ring();
        }
        COMMANDS.fetch_add(n as u64, Ordering::Relaxed);
        MAX_IN_FLIGHT.fetch_max(n as u64, Ordering::Relaxed);

        let deadline = crate::time::ticks() + timeout_ms;
        let mut results = alloc::vec![None::<u32>; n];
        let mut error = None;
        let mut done = 0;
        while done < n {
            if let Err(e) = self.wait_completion(admin, deadline) {
                serial_println!("[NVMe] {}: {} of {} commands not finished ({})", self.name, n - done, n, e);
                return Err(e);
            }
            let q = if admin { &mut self.admin } else { self.io.as_mut().unwrap() };
            while q.has_completion() {
                let (cid, status, dw0) = q.pop();
                if let Some(i) = cids.iter().position(|&c| c == cid) {
                    if results[i].is_none() {
                        done += 1;
                    }
                    results[i] = Some(dw0);
                    if status != 0 && error.is_none() {
                        error = Some(status);
                    }
                }
            }
        }
        if let Some(status) = error {
            serial_println!(
                "[NVMe] {}: command failed, status type {} code {:#x}",
                self.name,
                (status >> 8) & 7,
                status & 0xFF
            );
            return Err(BlockError::Io);
        }
        Ok(results.into_iter().map(|r| r.unwrap_or(0)).collect())
    }

    fn admin(&mut self, cmd: [u32; 16]) -> Result<u32, BlockError> {
        let mut c = [cmd];
        Ok(self.run(true, &mut c, ADMIN_TIMEOUT_MS)?[0])
    }

    /// Identify do pierwszej strony bufora danych.
    fn identify(&mut self, cns: u32, nsid: u32) -> Result<&'static [u8], BlockError> {
        let mut c = [0u32; 16];
        c[0] = ADM_IDENTIFY as u32;
        c[1] = nsid;
        c[6] = self.data as u32;
        c[7] = (self.data >> 32) as u32;
        c[10] = cns;
        self.admin(c)?;
        Ok(unsafe { core::slice::from_raw_parts(phys_to_virt(self.data) as *const u8, PAGE) })
    }

    /// Polecenie I/O na `bytes` bajtów od offsetu `buf_off` w buforze DMA.
    fn io_cmd(&self, opcode: u8, lba: u64, bytes: usize, buf_off: usize, slot: usize) -> [u32; 16] {
        let mut c = [0u32; 16];
        c[0] = opcode as u32;
        c[1] = self.nsid;
        let addr = self.data + buf_off as u64;
        c[6] = addr as u32;
        c[7] = (addr >> 32) as u32;
        let pages = bytes.div_ceil(PAGE);
        let prp2 = if pages <= 1 {
            0
        } else if pages == 2 {
            addr + PAGE as u64
        } else {
            // Lista PRP: adresy stron 2..n tego polecenia.
            let list = self.prp + (slot * PRP_SLOT) as u64;
            for p in 1..pages {
                unsafe { write_volatile((phys_to_virt(list) + (p as u64 - 1) * 8) as *mut u64, addr + (p * PAGE) as u64) };
            }
            list
        };
        c[8] = prp2 as u32;
        c[9] = (prp2 >> 32) as u32;
        c[10] = lba as u32;
        c[11] = (lba >> 32) as u32;
        c[12] = (bytes / self.lba_size - 1) as u32; // liczba bloków - 1
        c
    }

    /// Odczyt/zapis całych bloków NVMe przez bufor DMA (do DATA_BUFFER bajtów
    /// naraz), polecenia po max_cmd bajtów – wszystkie w kolejce naraz.
    fn transfer(&mut self, opcode: u8, lba: u64, bytes: usize) -> Result<(), BlockError> {
        debug_assert!(bytes <= DATA_BUFFER && bytes % self.lba_size == 0);
        let mut cmds = Vec::new();
        let mut off = 0;
        while off < bytes {
            let len = (bytes - off).min(self.max_cmd);
            let slot = cmds.len();
            cmds.push(self.io_cmd(opcode, lba + (off / self.lba_size) as u64, len, off, slot));
            off += len;
        }
        self.run(false, &mut cmds, IO_TIMEOUT_MS).map(|_| ())
    }

    fn data_ptr(&self) -> *mut u8 {
        phys_to_virt(self.data) as *mut u8
    }

    fn new(dev: &Device, index: usize) -> Result<Nvme, &'static str> {
        let Bar::Memory { base, size, .. } = dev.bars[0] else {
            return Err("BAR0 is not a memory BAR");
        };
        if base == 0 {
            return Err("BAR0 not assigned by the firmware");
        }
        dev.enable(true, false); // pamięć + DMA, bez INTx
        let regs = map_mmio(base, size.clamp(0x2000, 0x10000)).ok_or("cannot map NVMe registers")?;

        let cap = r64(regs + REG_CAP);
        let mqes = (cap & 0xFFFF) as u16 + 1;
        let timeout_ms = ((cap >> 24) & 0xFF).max(1) * 500;
        let stride = 4u64 << ((cap >> 32) & 0xF);
        let css_nvm = (cap >> 37) & 1 == 1;
        let mps_min = (cap >> 48) & 0xF;
        if !css_nvm {
            return Err("controller does not support the NVM command set");
        }
        if mps_min != 0 {
            return Err("controller needs pages larger than 4 KiB");
        }
        let version = r32(regs + REG_VS);

        // 1. Reset: wyłącz kontroler i poczekaj, aż przestanie być gotowy.
        let cc = r32(regs + REG_CC);
        if cc & CC_EN != 0 {
            w32(regs + REG_CC, cc & !CC_EN);
        }
        let deadline = crate::time::ticks() + timeout_ms;
        while r32(regs + REG_CSTS) & CSTS_RDY != 0 {
            if crate::time::ticks() > deadline {
                return Err("timeout while disabling the controller");
            }
            crate::time::sleep_ms(1);
        }

        // 2. Kolejki administracyjne.
        let qsize = QUEUE_ENTRIES.min(mqes);
        let admin = Queue::new(regs, stride, 0, qsize).ok_or("out of memory (admin queues)")?;
        w32(regs + REG_AQA, ((qsize as u32 - 1) << 16) | (qsize as u32 - 1));
        w64(regs + REG_ASQ, admin.sq);
        w64(regs + REG_ACQ, admin.cq);

        // 3. Włącz (NVM, strony 4 KiB, SQE 64 B, CQE 16 B).
        w32(regs + REG_CC, CC_IOCQES | CC_IOSQES | CC_EN);
        let deadline = crate::time::ticks() + timeout_ms;
        loop {
            let csts = r32(regs + REG_CSTS);
            if csts & CSTS_CFS != 0 {
                return Err("controller fatal status after enable");
            }
            if csts & CSTS_RDY != 0 {
                break;
            }
            if crate::time::ticks() > deadline {
                return Err("timeout while enabling the controller");
            }
            crate::time::sleep_ms(1);
        }

        let data = dma(DATA_FRAMES).ok_or("out of memory (128 KiB DMA buffer)")?;
        let prp = dma(1).ok_or("out of memory (PRP list)")?;
        let write_allowed = dev.vendor == QEMU_VENDOR && dev.device == QEMU_DEVICE;
        let mut me = Nvme {
            name: format!("nvme{}n1", index),
            pci: dev.address,
            vendor: dev.vendor,
            device: dev.device,
            regs,
            admin,
            io: None,
            next_cid: 0,
            model: String::new(),
            serial: String::new(),
            firmware: String::new(),
            version,
            nsid: 1,
            lba_size: SECTOR_SIZE,
            lba_count: 0,
            max_cmd: MAX_CMD,
            data,
            prp,
            vector: None,
            irq_kind: "polling",
            write_allowed,
        };

        // 4. Przerwania: MSI-X, inaczej MSI, inaczej odpytywanie.
        if let Some(v) = msi::alloc(on_msi) {
            if dev.enable_msix(0, v).is_ok() {
                me.vector = Some(v);
                me.irq_kind = "MSI-X";
            } else if dev.enable_msi(v).is_ok() {
                me.vector = Some(v);
                me.irq_kind = "MSI";
            }
        }

        // 5. Identify Controller.
        let text = |b: &[u8]| String::from(core::str::from_utf8(b).unwrap_or("?").trim());
        let id = me.identify(1, 0).map_err(|_| "Identify Controller failed")?;
        me.serial = text(&id[4..24]);
        me.model = text(&id[24..64]);
        me.firmware = text(&id[64..72]);
        let mdts = id[77];
        if mdts != 0 {
            me.max_cmd = MAX_CMD.min(PAGE << mdts.min(20));
        }
        let namespaces = u32::from_le_bytes(id[516..520].try_into().unwrap());

        // 6. Pierwsza aktywna przestrzeń nazw (lista aktywnych, CNS 2).
        if namespaces > 0 {
            if let Ok(list) = me.identify(2, 0) {
                let first = u32::from_le_bytes(list[0..4].try_into().unwrap());
                if first != 0 {
                    me.nsid = first;
                }
            }
        }
        let ns = me.identify(0, me.nsid).map_err(|_| "Identify Namespace failed")?;
        let nsze = u64::from_le_bytes(ns[0..8].try_into().unwrap());
        let flbas = (ns[26] & 0xF) as usize;
        let lbaf = &ns[128 + flbas * 4..128 + flbas * 4 + 4];
        let ms = u16::from_le_bytes([lbaf[0], lbaf[1]]);
        let lbads = lbaf[2];
        if nsze == 0 {
            return Err("namespace is empty");
        }
        if ms != 0 {
            return Err("namespace uses metadata (not supported)");
        }
        if !(9..=12).contains(&lbads) {
            return Err("unsupported block size (only 512 B .. 4 KiB)");
        }
        me.lba_size = 1 << lbads;
        me.lba_count = nsze;
        me.max_cmd = me.max_cmd.max(me.lba_size) / me.lba_size * me.lba_size;

        // 7. Jedna para kolejek I/O (Set Features: Number of Queues – ulotne).
        let mut c = [0u32; 16];
        c[0] = ADM_SET_FEATURES as u32;
        c[10] = 0x07;
        c[11] = 0; // 1 SQ + 1 CQ (wartości od zera)
        let _ = me.admin(c);

        let io = Queue::new(regs, stride, 1, qsize).ok_or("out of memory (I/O queues)")?;
        let mut c = [0u32; 16];
        c[0] = ADM_CREATE_CQ as u32;
        c[6] = io.cq as u32;
        c[7] = (io.cq >> 32) as u32;
        c[10] = ((qsize as u32 - 1) << 16) | 1;
        // PC = fizycznie ciągła; IEN + wektor 0 (MSI-X wpis 0 / MSI).
        c[11] = 1 | if me.vector.is_some() { 2 } else { 0 };
        me.admin(c).map_err(|_| "Create I/O Completion Queue failed")?;
        let mut c = [0u32; 16];
        c[0] = ADM_CREATE_SQ as u32;
        c[6] = io.sq as u32;
        c[7] = (io.sq >> 32) as u32;
        c[10] = ((qsize as u32 - 1) << 16) | 1;
        c[11] = (1 << 16) | 1; // CQ 1, fizycznie ciągła
        me.admin(c).map_err(|_| "Create I/O Submission Queue failed")?;
        me.io = Some(io);
        Ok(me)
    }

    fn read_only_now(&self) -> bool {
        !self.write_allowed || FORCE_READ_ONLY.load(Ordering::Relaxed)
    }

    /// Bloki NVMe pokrywające sektory 512 B [lba, lba+count).
    fn span(&self, lba: u64, count: u64) -> (u64, u64, usize) {
        let spb = (self.lba_size / SECTOR_SIZE) as u64;
        let first = lba / spb;
        let last = (lba + count - 1) / spb;
        let skip = ((lba % spb) as usize) * SECTOR_SIZE;
        (first, last - first + 1, skip)
    }
}

impl BlockDevice for Nvme {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> String {
        format!(
            "NVMe {} ({}, fw {}) at PCI {} [{:04x}:{:04x}], NVMe {}.{}, {} MiB, {} B blocks, {}{}",
            self.model,
            self.serial,
            self.firmware,
            self.pci,
            self.vendor,
            self.device,
            self.version >> 16,
            (self.version >> 8) & 0xFF,
            self.lba_count * self.lba_size as u64 / (1024 * 1024),
            self.lba_size,
            self.irq_kind,
            if self.read_only_now() { ", READ-ONLY (write protection)" } else { "" }
        )
    }

    fn sector_count(&self) -> u64 {
        self.lba_count * (self.lba_size / SECTOR_SIZE) as u64
    }

    fn read_only(&self) -> bool {
        self.read_only_now()
    }

    fn logical_block_size(&self) -> usize {
        self.lba_size
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        let count = block::check_range(self.sector_count(), lba, buf.len())?;
        let per = (DATA_BUFFER / self.lba_size) as u64; // bloków NVMe na bufor
        let (mut first, mut blocks, mut skip) = self.span(lba, count);
        let mut out = 0;
        while blocks > 0 {
            let n = blocks.min(per);
            let bytes = n as usize * self.lba_size;
            self.transfer(IO_READ, first, bytes)?;
            let take = (bytes - skip).min(buf.len() - out);
            unsafe { core::ptr::copy_nonoverlapping(self.data_ptr().add(skip), buf[out..].as_mut_ptr(), take) };
            out += take;
            first += n;
            blocks -= n;
            skip = 0;
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        let count = block::check_range(self.sector_count(), lba, buf.len())?;
        // Ochrona danych: prawdziwy SSD – nic nie wysyłamy.
        if self.read_only_now() {
            return Err(BlockError::ReadOnly);
        }
        let per = (DATA_BUFFER / self.lba_size) as u64;
        let (mut first, mut blocks, mut skip) = self.span(lba, count);
        let mut done = 0;
        while blocks > 0 {
            let n = blocks.min(per);
            let bytes = n as usize * self.lba_size;
            let take = (bytes - skip).min(buf.len() - done);
            // Blok 4 KiB zapisywany częściowo: najpierw odczyt (read-modify-write).
            if skip != 0 || take != bytes {
                self.transfer(IO_READ, first, bytes)?;
            }
            unsafe { core::ptr::copy_nonoverlapping(buf[done..].as_ptr(), self.data_ptr().add(skip), take) };
            self.transfer(IO_WRITE, first, bytes)?;
            done += take;
            first += n;
            blocks -= n;
            skip = 0;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        if self.read_only_now() {
            return Ok(());
        }
        let mut c = [[0u32; 16]];
        c[0][0] = IO_FLUSH as u32;
        c[0][1] = self.nsid;
        self.run(false, &mut c, IO_TIMEOUT_MS).map(|_| ())
    }
}

/// Liczba przerwań MSI/MSI-X od NVMe (testy).
#[allow(dead_code)]
pub fn irq_count() -> u64 {
    IRQS.load(Ordering::Relaxed)
}

/// Liczba wysłanych poleceń i największa liczba naraz w kolejce (testy).
#[allow(dead_code)]
pub fn stats() -> (u64, u64) {
    (COMMANDS.load(Ordering::Relaxed), MAX_IN_FLIGHT.load(Ordering::Relaxed))
}

#[allow(dead_code)]
pub fn set_force_read_only(on: bool) {
    FORCE_READ_ONLY.store(on, Ordering::Relaxed);
}

/// Szuka kontrolerów NVMe (klasa 01:08, interfejs 02), rejestruje dyski
/// i ich partycje GPT.  Zwraca liczbę dysków.
pub fn init() -> usize {
    let mut added = 0;
    for dev in pci::devices() {
        if dev.class != 0x01 || dev.subclass != 0x08 || dev.prog_if != 0x02 {
            continue;
        }
        match Nvme::new(dev, added) {
            Ok(d) => {
                pci::set_kernel_owner(dev.address); // M19.c: usługa go nie przejmie
                serial_println!("[NVMe] {}: {}", d.name, d.description());
                if !d.write_allowed {
                    serial_println!("[NVMe] {}: real SSD - write protection ON (nothing is ever written)", d.name);
                }
                let index = block::register(alloc::boxed::Box::new(d));
                block::scan_partitions(index);
                added += 1;
            }
            Err(e) => serial_println!("[NVMe] controller at {} [{:04x}:{:04x}]: {}", dev.address, dev.vendor, dev.device, e),
        }
    }
    if added == 0 {
        serial_println!("[NVMe] no NVMe disk");
    }
    added
}

// ------------------------------------------------------------
// TEST (tylko build z --cfg selftest)
// ------------------------------------------------------------

#[cfg(selftest)]
macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[NVME TEST] FAIL: {}", format_args!($($msg)*));
            set_force_read_only(false);
            return;
        }
    };
}

#[cfg(selftest)]
pub fn self_test() {
    use alloc::vec;
    use crate::arch::x86_64::lapic;

    serial_println!("[NVME TEST] Starting ACPI / ECAM / MSI-X / NVMe / GPT tests...");
    crate::selftest::begin();

    // 1. ACPI: RSDP -> XSDT, MCFG z ECAM (QEMU q35: 0xB0000000).
    let tables = crate::acpi::tables();
    check!(!tables.is_empty(), "no ACPI tables (RSDP from DSB missing?)");
    let names: Vec<&str> = tables.iter().map(|t| t.name()).collect();
    check!(names.contains(&"FACP") && names.contains(&"MCFG"), "tables {:?}", names);
    let mcfg = crate::acpi::mcfg();
    check!(mcfg.iter().any(|e| e.segment == 0 && e.base != 0), "MCFG without segment 0: {:?}", mcfg);
    serial_println!("[NVME TEST] 1/9 ACPI: {} tables ({}), MCFG ECAM {:#x} PASS", tables.len(), names.join(" "), mcfg[0].base);

    // 2. ECAM włączone i zgodne z portami; rozszerzona konfiguracja czytelna.
    check!(pci::ecam_enabled(), "ECAM not enabled");
    for d in pci::devices() {
        for off in [0u8, 8, 0x2C] {
            let (e, p) = (pci::read32(d.address, off), pci::read32_port(d.address, off));
            check!(e == p, "{} reg {:#x}: ECAM {:#x} != port {:#x}", d.address, off, e, p);
        }
    }
    let nvme_dev = pci::devices().iter().find(|d| d.class == 1 && d.subclass == 8);
    check!(nvme_dev.is_some(), "no NVMe controller on PCI (QEMU needs -device nvme, see test.sh)");
    let nvme_dev = nvme_dev.unwrap();
    check!(pci::read32_ext(nvme_dev.address, 0x100).is_some(), "extended config space (0x100) not readable");
    serial_println!("[NVME TEST] 2/9 ECAM == ports for {} devices, extended config 0x100 readable PASS", pci::devices().len());

    // 3. LAPIC + MSI-X.
    check!(lapic::available(), "local APIC not available");
    check!(lapic::msi_address() & 0xFFF0_0000 == 0xFEE0_0000, "MSI address {:#x}", lapic::msi_address());
    let msix = nvme_dev.find_capability(pci::CAP_MSIX);
    check!(msix.is_some(), "QEMU NVMe without MSI-X capability");
    let ctrl = pci::read16(nvme_dev.address, msix.unwrap() + 2);
    check!(ctrl & (1 << 15) != 0 && ctrl & (1 << 14) == 0, "MSI-X not enabled / masked (ctrl {:#x})", ctrl);
    check!(nvme_dev.command() & pci::CMD_INTX_DISABLE != 0, "INTx still enabled");
    serial_println!("[NVME TEST] 3/9 local APIC id {}, MSI-X enabled, INTx off PASS", lapic::id());

    // 4. Dysk NVMe zarejestrowany, QEMU = zapis dozwolony.
    let disk = block::find("nvme0n1");
    check!(disk.is_some(), "nvme0n1 not registered");
    let disk = disk.unwrap();
    let (desc, sectors, ro, bs) =
        block::with_device(disk, |d| (d.description(), d.sector_count(), d.read_only(), d.logical_block_size())).unwrap();
    check!(desc.contains("QEMU"), "model: {}", desc);
    check!(desc.contains("MSI-X"), "not using MSI-X: {}", desc);
    check!(!ro, "QEMU NVMe should be writable");
    check!(sectors >= 64 * 2048 - 1, "capacity {} sectors", sectors);
    serial_println!("[NVME TEST] 4/9 {}: {} PASS", "nvme0n1", desc);

    // 5. Zapis + odczyt kontrolny (przywrócenie danych), z przerwaniami.
    let irq0 = irq_count();
    let lba = sectors - 300;
    let mut original = vec![0u8; 200 * SECTOR_SIZE];
    check!(block::read(disk, lba, &mut original).is_ok(), "read original");
    let pattern: Vec<u8> = (0..200 * SECTOR_SIZE).map(|i| (i * 13 + i / 512) as u8).collect();
    check!(block::write(disk, lba, &pattern).is_ok(), "write pattern");
    check!(block::flush(disk).is_ok(), "flush");
    let mut back = vec![0u8; 200 * SECTOR_SIZE];
    check!(block::read(disk, lba, &mut back).is_ok(), "read back");
    let same = back == pattern;
    check!(block::write(disk, lba, &original).is_ok(), "restore");
    check!(same, "data read back differs");
    // Nierówne do bloku: 3 sektory od nieparzystego LBA.
    let mut three = [0u8; 3 * SECTOR_SIZE];
    check!(block::read(disk, lba + 1, &mut three).is_ok() && three[..] == original[512..2048], "unaligned read");
    check!(irq_count() > irq0, "no MSI-X interrupt from NVMe");
    serial_println!("[NVME TEST] 5/9 write + flush + read-back of 100 KiB (restored), {} interrupts PASS", irq_count() - irq0);

    // 6. Kolejka: 256 KiB = polecenia po max 32 KiB, kilka naraz w kolejce.
    let (c0, _) = stats();
    let mut big = vec![0u8; 512 * SECTOR_SIZE];
    check!(block::read(disk, 0, &mut big).is_ok(), "256 KiB read");
    let (c1, inflight) = stats();
    check!(c1 - c0 >= 8, "256 KiB took {} commands", c1 - c0);
    check!(inflight >= 4, "max {} commands in flight (want >= 4)", inflight);
    serial_println!("[NVME TEST] 6/9 256 KiB read = {} commands, up to {} in the queue at once PASS", c1 - c0, inflight);

    // 7. Ochrona zapisu (tak zachowuje się prawdziwy SSD).
    set_force_read_only(true);
    check!(block::is_read_only(disk), "force read-only not visible");
    check!(block::write(disk, lba, &pattern[..SECTOR_SIZE]) == Err(BlockError::ReadOnly), "write allowed on read-only");
    check!(block::with_device(disk, |d| d.write(lba, &pattern[..SECTOR_SIZE])).unwrap() == Err(BlockError::ReadOnly), "driver write allowed");
    check!(matches!(crate::fs::fat32::mkfs(disk, "X", false), Err(crate::fs::FsError::ReadOnly)), "mkfs allowed on read-only");
    let mut one = [0u8; SECTOR_SIZE];
    check!(block::read(disk, lba, &mut one).is_ok() && one[..] == original[..SECTOR_SIZE], "read on read-only disk / data changed");
    set_force_read_only(false);
    serial_println!("[NVME TEST] 7/9 write protection: block layer + driver + mkfs refuse, reads work PASS");

    // 8. GPT: partycja EFI System -> dysk nvme0n1p1 -> FAT32 -> /esp.
    let (first, len) = match crate::gpt::write_test_gpt(disk, crate::gpt::ESP, "DESOOS ESP") {
        Ok(v) => v,
        Err(e) => {
            check!(false, "write GPT: {}", e);
            return;
        }
    };
    check!(block::scan_partitions(disk) == 1, "partition not found after writing GPT");
    let part = block::find("nvme0n1p1");
    check!(part.is_some(), "nvme0n1p1 not registered");
    let part = part.unwrap();
    check!(block::partition_kind(part) == Some("EFI System"), "kind {:?}", block::partition_kind(part));
    check!(block::with_device(part, |d| d.sector_count()).unwrap() == len, "partition length");
    check!(crate::fs::fat32::mkfs(part, "DESOOSESP", true).is_ok(), "mkfs on the partition");
    let mut bs0 = [0u8; SECTOR_SIZE];
    check!(block::read(disk, first, &mut bs0).is_ok() && bs0[510] == 0x55 && bs0[511] == 0xAA, "FAT boot sector not at partition start");
    check!(crate::fs::mount_esp() == Some(part), "/esp not mounted");
    check!(crate::fs::write_file("/esp/hello.txt", b"from DeSoOS\n").is_ok(), "write /esp/hello.txt");
    check!(crate::fs::read_file("/esp/hello.txt").ok().as_deref() == Some(b"from DeSoOS\n".as_slice()), "read /esp/hello.txt");
    serial_println!("[NVME TEST] 8/9 GPT -> nvme0n1p1 (EFI System, {} MiB) -> FAT32 -> /esp PASS", len / 2048);

    // 9. Ta sama partycja przy ochronie zapisu: czyta, nie zapisuje.
    set_force_read_only(true);
    check!(crate::fs::read_file("/esp/hello.txt").is_ok(), "read on read-only /esp");
    check!(
        matches!(crate::fs::write_file("/esp/new.txt", b"x"), Err(crate::fs::FsError::ReadOnly)),
        "write on read-only /esp: {:?}",
        crate::fs::write_file("/esp/new.txt", b"x")
    );
    set_force_read_only(false);
    let _ = crate::fs::unmount("/esp");
    let _ = crate::fs::remove("/esp");
    let _ = bs;
    serial_println!("[NVME TEST] 9/9 read-only partition: files readable, writes refused PASS");

    crate::selftest::pass();
    serial_println!("[NVME TEST] All ACPI / ECAM / MSI-X / NVMe / GPT tests passed");
}
