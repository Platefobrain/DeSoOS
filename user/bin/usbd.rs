// M20: usbd – sterownik kontrolera USB xHCI jako usługa w user space.
// Projekt: ARCHITEKTURA.md, „USB (M20 – projekt 20.a)”.  Jedna instancja na
// kontroler; init znajduje kontrolery po klasie (dev_find 0C0330) i uruchamia
// usb0, usb1, …
//
// Uchwyty na starcie (daje je init): 1 = konsola, 3 = urządzenie (DEVICE),
// 4 = kanał połączeń, 5 = INPUT (klawiatura do jądra), 6 = BLK (dyski do jądra).
//
// Krok b (v0.23.0) – start kontrolera:
//   rejestry (dev_map BAR0), przejęcie od BIOS-u (USB Legacy Support: OS Owned,
//   wyłączenie SMI), zatrzymanie i reset (HCRST), DCBAA, bufory scratchpad,
//   pierścień komend, pierścień zdarzeń (interrupter 0), MSI (irq_bind), Run,
//   komendy No-Op.
// Krok c (v0.24.0) – urządzenia na portach kontrolera (maszyna stanów portu):
//   Wolny -> Debounce (100 ms) -> reset portu (USB 2; USB 3 trenuje łącze sam)
//   -> Enable Slot -> Address Device -> deskryptor urządzenia (8 B: rozmiar
//   pakietu EP0, Evaluate Context; potem całe 18 B) -> konfiguracja (9 B, potem
//   wTotalLength ≤ 4 KiB) -> napisy (producent, produkt) -> Działa.
//   Błąd: Disable Slot, ponowna próba za 500 ms, po 3 – port ignorowany do
//   odłączenia.  Odłączenie w dowolnym stanie: Disable Slot, strony wracają.
//   Każda komenda i transfer z timeoutem 1 s; STALL -> Reset Endpoint + Set TR
//   Dequeue.  Deskryptory parsuje user/lib/usb_desc.rs (obce dane – limity).
//   Urządzenia NIE są konfigurowane (Set Configuration / endpointy – krok e i f);
//   do urządzeń idą wyłącznie prośby o odczyt deskryptorów.
// Krok e (v0.25.0) – klawiatura i mysz HID (boot protocol):
//   urządzenie z interfejsem 03/01/01 (klawiatura) albo 03/01/02 (mysz) z
//   endpointem przerwań IN: Configure Endpoint, Set Configuration, Set
//   Protocol (boot), Set Idle (0); 8 TRB czeka na raporty.  Raport klawiatury
//   (8 B: modyfikatory + 6 klawiszy) -> różnica z poprzednim -> zdarzenia HID
//   usage -> syscall input_inject (uchwyt INPUT w slocie 5 od init) -> jądro
//   (KeyCode, autorepeat, konsola).  Stan diod z jądra -> Set Report do
//   klawiatury.  Mysz: kółko przewija konsolę.  Odłączenie -> puszczenie
//   klawiszy tego urządzenia; koniec usbd -> puszcza je jądro.
// Krok f (v0.26.0) – pamięć masowa (pendrive) TYLKO DO ODCZYTU:
//   interfejs 08/06/50 (SCSI, Bulk-Only) z endpointami bulk IN i OUT:
//   Configure Endpoint, Set Configuration, INQUIRY (tylko dysk – typ 0), TEST
//   UNIT READY (do 10 prób z REQUEST SENSE), READ CAPACITY(10).  Bufor DMA
//   256 KiB (4 sloty po 64 KiB) i kanał -> syscall blk_attach (uchwyt BLK w
//   slocie 6 od init) -> jądro widzi dysk „sdX” i samo montuje FAT32 w /usbN.
//   Żądania jądra (READ: lba, bloki, slot) -> READ(10) prosto do slotu bufora
//   (DMA) -> odpowiedź (id, status, bloki).  Błąd transferu: STALL -> Clear
//   Halt; timeout / zły CSW -> Bulk-Only Reset (reset recovery).  Odłączenie ->
//   kanał zamknięty (jądro: dysk znika, odmontowany).
//   ZAPISU NIE MA: jedyne komendy SCSI to te z SCSI_ALLOWED (sprawdzane przed
//   wysłaniem każdej komendy; asercja przy kompilacji – żadnej komendy zapisu).
// Krok d (v0.27.0) – huby USB 2 i USB 3 (także huby za hubami, do 5 poziomów):
//   urządzenie klasy 09: Configure Endpoint (przerwania IN – mapa zmian portów),
//   Set Configuration, Set Hub Depth (USB 3), deskryptor huba (liczba portów,
//   TT think time, czas włączenia zasilania), drugi Configure Endpoint z polami
//   huba w kontekście slotu, zasilanie portów.  Porty huba – ta sama maszyna
//   stanów co porty kontrolera (debounce, reset portu huba, 3 próby, ignorowany
//   do odłączenia); stan portu: GET_STATUS, zmiany kasowane CLEAR_FEATURE.
//   Urządzenie za hubem: route string (port huba na każdym poziomie), port
//   kontrolera najwyższego huba, prędkość z portu huba, TT (slot i port
//   najbliższego huba high speed) dla klawiatur / myszy low / full speed za hubem
//   USB 2.  Odłączenie huba = odłączenie wszystkiego, co za nim.  lsusb: „port 3.2”
//   (port kontrolera . port huba).
// Klienci (kanał "usbN" przez init): "status" – opis + linia "usbd-status k=v";
// "list" – urządzenia (lsusb); "noop N" – N komend No-Op, "noop N <ns>";
// "idle MS" – raporty HID co MS ms także bez zmian (test potoku przerwań w QEMU).
//
// DMA bez IOMMU (ARCHITEKTURA.md): usbd sam wpisuje adresy fizyczne do struktur
// kontrolera – jądro ich nie sprawdzi.  Izolacja procesu chroni przed crashem i
// zawieszeniem, nie przed błędnym DMA; dlatego usbd jest kodem systemu (initrd).
//
// Koniec: kanał połączeń zamknięty i żaden klient nie został -> kontroler
// zatrzymany, kod 0.  Błąd kontrolera (HSE / HCE) -> kod 3 (init restartuje,
// nowa instancja robi pełny reset).  Kill w dowolnym momencie – sprząta jądro
// (bus mastering off -> wektor -> ramki DMA -> przejęcie).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../lib/usb_desc.rs"]
mod usb_desc;

use desoos::*;
use usb_desc::*;

entry!(main);

const DEV: u64 = 3;
const LISTEN: u64 = 4;
const MAX_CLIENTS: usize = WAIT_MAX - 2 - STOR_MAX;
const EIO: i64 = -5;

/// Limit czasu na każdą operację na kontrolerze (reset, komenda, transfer).
const TIMEOUT_MS: u64 = 1000;
/// M20.a: najwyżej 32 urządzenia na kontroler.
const SLOTS_MAX: u32 = 32;
const DEVS_MAX: usize = 32;
const PORTS_MAX: usize = 64;
/// TRB na pierścień (jedna strona 4 KiB: 256 × 16 B).
const RING: usize = 256;
const DEBOUNCE_MS: u64 = 100;
const PORT_RESET_MS: u64 = 500;
const RETRY_MS: u64 = 500;
const TRIES: u32 = 3;
const NAME_MAX: usize = 40;
/// M20.e: TRB czekających na raporty HID i bufor na raport (w stronie danych).
const HID_TRBS: usize = 8;
const HID_BUF: u64 = 256;
/// M20.d: huby – najwięcej portów na hub, głębokość (route string ma 5 poziomów),
/// najdłuższe czekanie na reset portu huba.
const HUB_PORTS_MAX: usize = 15;
const HUB_DEPTH_MAX: u32 = 5;
const HUB_RESET_MS: u64 = 500;
// Żądania i funkcje portu huba (USB 2.0 rozdz. 11, USB 3.2 rozdz. 10).
const HUB_PORT_RESET: u16 = 4;
const HUB_PORT_POWER: u16 = 8;
/// M20.f: pamięć masowa – najwięcej urządzeń, sloty bufora (po 64 KiB),
/// limit czasu transferu bulk (jądro czeka 5 s – odpowiadamy wcześniej).
const STOR_MAX: usize = 4;
const STOR_SLOTS: usize = 4;
const STOR_SLOT: u64 = 64 * 1024;
const BULK_TIMEOUT_MS: u64 = 4000;
const ENODEV_REPLY: i32 = -19;
const EIO_REPLY: i32 = -5;
/// Jedyne komendy SCSI, jakie usbd wysyła: TEST UNIT READY, REQUEST SENSE,
/// INQUIRY, READ CAPACITY(10), READ(10).  Brak zapisu – patrz asercja niżej.
const SCSI_ALLOWED: [u8; 5] = [0x00, 0x03, 0x12, 0x25, 0x28];
const _: () = {
    // WRITE(6/10/12/16), WRITE AND VERIFY, WRITE SAME, FORMAT UNIT, MODE SELECT
    // (6/10), SYNCHRONIZE CACHE (10/16), WRITE BUFFER, UNMAP, START STOP UNIT.
    const WRITES: [u8; 16] = [0x0A, 0x2A, 0xAA, 0x8A, 0x2E, 0xAE, 0x8E, 0x41, 0x93, 0x04, 0x15, 0x55, 0x35, 0x91, 0x3B, 0x42];
    let mut i = 0;
    while i < SCSI_ALLOWED.len() {
        let mut j = 0;
        while j < WRITES.len() {
            assert!(SCSI_ALLOWED[i] != WRITES[j], "usbd must never send a writing SCSI command");
            j += 1;
        }
        i += 1;
    }
};

// Rejestry możliwości (od początku BAR0).
const CAPLENGTH: u64 = 0x00;
const HCSPARAMS1: u64 = 0x04;
const HCSPARAMS2: u64 = 0x08;
const HCCPARAMS1: u64 = 0x10;
const DBOFF: u64 = 0x14;
const RTSOFF: u64 = 0x18;
// Rejestry operacyjne (od CAPLENGTH).
const USBCMD: u64 = 0x00;
const USBSTS: u64 = 0x04;
const PAGESIZE: u64 = 0x08;
const CRCR: u64 = 0x18;
const DCBAAP: u64 = 0x30;
const CONFIG: u64 = 0x38;
const PORTSC: u64 = 0x400;
const CMD_RUN: u32 = 1 << 0;
const CMD_HCRST: u32 = 1 << 1;
const CMD_INTE: u32 = 1 << 2;
const STS_HCH: u32 = 1 << 0;
const STS_HSE: u32 = 1 << 2;
const STS_EINT: u32 = 1 << 3;
const STS_CNR: u32 = 1 << 11;
const STS_HCE: u32 = 1 << 12;
// Interrupter 0 (rejestry runtime + 0x20).
const IR0: u64 = 0x20;
const IMAN: u64 = 0x00;
const IMOD: u64 = 0x04;
const ERSTSZ: u64 = 0x08;
const ERSTBA: u64 = 0x10;
const ERDP: u64 = 0x18;
const IMAN_IP: u32 = 1 << 0;
const IMAN_IE: u32 = 1 << 1;
const ERDP_EHB: u64 = 1 << 3;
// PORTSC: bity zachowywane przy zapisie (tylko do odczytu + RWS) i bity zmian
// (RW1C) – zapis 1 do PED wyłączyłby port, więc nigdy go nie przepisujemy.
const PORT_CCS: u32 = 1 << 0;
const PORT_PED: u32 = 1 << 1;
const PORT_PR: u32 = 1 << 4;
const PORT_PP: u32 = 1 << 9;
const PORT_CSC: u32 = 1 << 17;
const PORT_KEEP: u32 = 0x4E00_FFE9 & !PORT_PED;
const PORT_CHANGES: u32 = 0x00FE_0000;
// Typy TRB.
const TRB_SETUP: u32 = 2;
const TRB_DATA: u32 = 3;
const TRB_STATUS: u32 = 4;
const TRB_LINK: u32 = 6;
const TRB_NORMAL: u32 = 1;
const TRB_ENABLE_SLOT: u32 = 9;
const TRB_DISABLE_SLOT: u32 = 10;
const TRB_ADDRESS_DEVICE: u32 = 11;
const TRB_CONFIGURE_EP: u32 = 12;
const TRB_EVALUATE_CONTEXT: u32 = 13;
const TRB_RESET_EP: u32 = 14;
const TRB_STOP_EP: u32 = 15;
const TRB_SET_DEQUEUE: u32 = 16;
const TRB_NOOP_CMD: u32 = 23;
const TRB_TRANSFER: u32 = 32;
const TRB_CMD_DONE: u32 = 33;
const TRB_PORT_CHANGE: u32 = 34;
const TRB_HC_EVENT: u32 = 37;
const TRB_ISP: u32 = 1 << 2;
const TRB_CH: u32 = 1 << 4;
const TRB_IOC: u32 = 1 << 5;
const TRB_IDT: u32 = 1 << 6;
const CC_SUCCESS: u32 = 1;
const CC_STALL: u32 = 6;
const CC_SHORT: u32 = 13;

fn rd32(a: u64) -> u32 {
    unsafe { core::ptr::read_volatile(a as *const u32) }
}

fn wr32(a: u64, v: u32) {
    unsafe { core::ptr::write_volatile(a as *mut u32, v) }
}

/// Rejestry 64-bitowe jako dwa zapisy 32-bitowe (najpierw młodsza połowa) –
/// działa też na kontrolerach bez 64-bitowego dostępu do MMIO.
fn wr64(a: u64, v: u64) {
    wr32(a, v as u32);
    wr32(a + 4, (v >> 32) as u32);
}

/// Czeka (≤ TIMEOUT_MS), aż `cond` będzie prawdą.
fn wait_until(mut cond: impl FnMut() -> bool) -> bool {
    let t0 = uptime_ms();
    loop {
        if cond() {
            return true;
        }
        if uptime_ms() - t0 >= TIMEOUT_MS {
            return false;
        }
        sleep_ms(1);
    }
}

/// Strony DMA: bufory z dma_alloc dzielone po stronie; strony urządzeń wracają
/// na listę wolnych (wyzerowane) po odłączeniu.
struct Pool {
    bits: u64,
    va: u64,
    pa: u64,
    pages: u64,
    used: u64,
    total: u64,
    free: [(u64, u64); 128],
    nfree: usize,
}

impl Pool {
    fn chunk(&mut self, pages: u64) -> Result<(), i64> {
        let h = dma_alloc(DEV, pages * 4096, self.bits);
        if h < 0 {
            return Err(h);
        }
        let pa = dma_phys(h as u64)?;
        let va = shm_map(h as u64, PROT_READ | PROT_WRITE)?;
        close(h as u64); // bufor żyje z przejęciem urządzenia
        (self.va, self.pa, self.pages, self.used) = (va, pa, pages, 0);
        self.total += pages;
        Ok(())
    }

    /// Jedna wyzerowana strona (adres w procesie, adres fizyczny).
    fn page(&mut self) -> Result<(u64, u64), i64> {
        if self.nfree > 0 {
            self.nfree -= 1;
            return Ok(self.free[self.nfree]);
        }
        if self.used == self.pages {
            self.chunk(16)?;
        }
        let off = self.used * 4096;
        self.used += 1;
        Ok((self.va + off, self.pa + off))
    }

    fn release(&mut self, p: (u64, u64)) {
        if self.nfree < self.free.len() {
            unsafe { core::ptr::write_bytes(p.0 as *mut u8, 0, 4096) };
            self.free[self.nfree] = p;
            self.nfree += 1;
        }
    }
}

struct Ring {
    va: u64,
    pa: u64,
    idx: usize,
    cycle: u32,
}

impl Ring {
    fn trb(&self, i: usize) -> *mut u32 {
        (self.va + i as u64 * 16) as *mut u32
    }

    /// Pierścień komend / transferów: ostatni TRB to Link na początek (Toggle Cycle).
    fn new_linked(va: u64, pa: u64) -> Ring {
        let r = Ring { va, pa, idx: 0, cycle: 1 };
        let l = r.trb(RING - 1);
        unsafe {
            l.write_volatile(pa as u32);
            l.add(1).write_volatile((pa >> 32) as u32);
            l.add(2).write_volatile(0);
            l.add(3).write_volatile(TRB_LINK << 10 | 1 << 1);
        }
        r
    }

    /// Adres fizyczny następnego wolnego TRB | bit cyklu (Set TR Dequeue).
    fn enqueue_ptr(&self) -> u64 {
        (self.pa + self.idx as u64 * 16) | self.cycle as u64
    }

    /// Wpisuje TRB (`ctl` = typ << 10 | flagi; bit cyklu na końcu); zwraca
    /// jego adres fizyczny.
    fn push(&mut self, dw: [u32; 3], ctl: u32) -> u64 {
        let t = self.trb(self.idx);
        let pa = self.pa + self.idx as u64 * 16;
        unsafe {
            t.write_volatile(dw[0]);
            t.add(1).write_volatile(dw[1]);
            t.add(2).write_volatile(dw[2]);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            t.add(3).write_volatile(ctl | self.cycle);
        }
        self.idx += 1;
        if self.idx == RING - 1 {
            let l = self.trb(RING - 1);
            unsafe { l.add(3).write_volatile(TRB_LINK << 10 | 1 << 1 | self.cycle) };
            self.cycle ^= 1;
            self.idx = 0;
        }
        pa
    }

    /// Pierścień zdarzeń: następne zdarzenie (bit cyklu zgodny) albo None.
    fn pop(&mut self) -> Option<[u32; 4]> {
        let t = self.trb(self.idx);
        let d3 = unsafe { t.add(3).read_volatile() };
        if d3 & 1 != self.cycle {
            return None;
        }
        let ev = unsafe { [t.read_volatile(), t.add(1).read_volatile(), t.add(2).read_volatile(), d3] };
        self.idx += 1;
        if self.idx == RING {
            self.idx = 0;
            self.cycle ^= 1;
        }
        Some(ev)
    }
}

/// M20.e: klawiatura / mysz w boot protocol.
struct Hid {
    mouse: bool,
    iface: u8,
    /// Indeks kontekstu endpointu (DCI = numer * 2 + 1 dla IN).
    dci: u32,
    mps: u16,
    ring: Ring,
    ring_page: (u64, u64),
    data_page: (u64, u64),
    /// Poprzedni raport klawiatury (różnica = zdarzenia).
    prev: [u8; 8],
    leds: u8,
    reports: u64,
    errors: u64,
}

/// M20.f: pendrive (Bulk-Only + SCSI) – tylko odczyt.
struct Storage {
    iface: u8,
    dci_in: u32,
    dci_out: u32,
    ep_in: u8,
    ep_out: u8,
    mps_in: u16,
    mps_out: u16,
    ring_in: Ring,
    ring_out: Ring,
    ring_in_page: (u64, u64),
    ring_out_page: (u64, u64),
    /// CBW (0), CSW (512), dane komend (1024: INQUIRY, sense, pojemność).
    cmd_page: (u64, u64),
    /// Bufor wspólny z jądrem (indeks w Hc.stor_bufs).
    buf: usize,
    blocks: u64,
    bs: u32,
    tag: u32,
    /// Producent + produkt z INQUIRY.
    name: [u8; 40],
    nlen: usize,
    /// Kanał do jądra (nasz koniec) i numer dysku (0 = sda) po blk_attach.
    chan: u64,
    disk: Option<u64>,
    attach_error: i64,
    reads: u64,
    errors: u64,
    /// M20.g: transfer przerwany (zmiana portu huba) – przed następną komendą
    /// reset recovery (jeśli urządzenie jeszcze jest).
    needs_recovery: bool,
}

/// M20.h: tyle prób INQUIRY przy starcie pendrive'a (przerwy 200, 400, 600 ms).
const INQUIRY_TRIES: u32 = 4;

#[derive(Clone, Copy, Debug)]
enum StorError {
    Xfer(XferError),
    /// CSW: komenda nie wyszła (status 1).
    Failed,
    /// Zły / brak CSW albo status 2 (phase error) – po reset recovery.
    Phase,
    /// Komenda spoza SCSI_ALLOWED – nie wysłana.
    Refused,
}

/// M20.d: gdzie jest urządzenie – port kontrolera i droga przez huby.
#[derive(Clone, Copy, Default)]
struct Loc {
    /// Route string (xHCI): numer portu huba na kolejnych poziomach (4 bity każdy).
    route: u32,
    /// 0 – bezpośrednio w porcie kontrolera; 1 – za jednym hubem itd.
    depth: u32,
    /// Porty hubów po kolei (lsusb: „3.2.1”).
    path: [u8; 5],
    /// M20.g: hub-rodzic (indeks w `devs`) i jego port – zmiana na tym porcie
    /// przerywa transfer bulk (pendrive wyjęty z huba).
    parent: Option<usize>,
    hub_port: u32,
    /// Translator transakcji (urządzenie low / full speed za hubem high speed):
    /// (slot huba, port huba); (0, 0) – bez TT.
    tt: (u32, u32),
}

/// M20.d: hub USB 2 / USB 3.
struct Hub {
    usb3: bool,
    nports: u32,
    /// TT think time (USB 2, pole 2-bitowe) i czas włączenia zasilania portu (ms).
    think: u32,
    power_ms: u64,
    /// Endpoint przerwań IN: mapa zmian (bit 0 hub, bit n – port n).
    dci: u32,
    mps: u16,
    ring: Ring,
    ring_page: (u64, u64),
    data_page: (u64, u64),
    ports: [Port; HUB_PORTS_MAX],
    /// Porty do sprawdzenia (bit n – port n).
    pending: u32,
    last_error: [&'static str; HUB_PORTS_MAX],
    errors: u64,
}

/// Urządzenie z przydzielonym slotem.
struct Dev {
    /// Port kontrolera (dla urządzeń za hubem – port najwyższego huba).
    port: u32,
    slot: u32,
    speed: u32,
    addr: u32,
    input: (u64, u64),
    output: (u64, u64),
    ring_page: (u64, u64),
    ring: Ring,
    mps0: u16,
    desc: DeviceDesc,
    cfg: Config,
    manufacturer: [u8; NAME_MAX],
    mlen: usize,
    product: [u8; NAME_MAX],
    plen: usize,
    hid: Option<Hid>,
    /// Konfiguracja HID nie wyszła – powód (lsusb).
    hid_error: &'static str,
    /// M20.f: pamięć masowa (albo powód, dla którego nie działa).
    stor: Option<Storage>,
    stor_error: &'static str,
    /// M20.d: położenie, hub (jeśli urządzenie nim jest) albo powód błędu.
    loc: Loc,
    hub: Option<Hub>,
    hub_error: &'static str,
    /// M20.h: ms od resetu portu do gotowości (sterowniki klas skonfigurowane).
    enum_ms: u32,
}

#[derive(Clone, Copy, PartialEq)]
enum Port {
    Free,
    /// Podłączone – czekamy do chwili (ms), aż styki się ustalą.
    Debounce(u64),
    /// Działa: indeks w `devs`.
    Working(usize),
    /// Błąd: liczba prób, następna próba (ms).
    Failed(u32, u64),
    /// 3 nieudane próby – do odłączenia.
    Ignored,
}

#[derive(Clone, Copy, Debug)]
enum XferError {
    Stall,
    Timeout,
    Code,
    Command,
    Gone,
    /// M20.g: hub zgłosił zmianę na porcie urządzenia w trakcie transferu.
    Interrupted,
}

impl XferError {
    fn text(self) -> &'static str {
        match self {
            XferError::Stall => "STALL",
            XferError::Timeout => "timeout (1 s)",
            XferError::Code => "transfer error",
            XferError::Command => "command failed",
            XferError::Gone => "device disconnected",
            XferError::Interrupted => "port change during the transfer",
        }
    }
}

struct Hc {
    name: &'static str,
    cap: u64,
    op: u64,
    rt: u64,
    db: u64,
    info: DevInfo,
    version: u16,
    max_slots: u32,
    slots: u32,
    max_ports: u32,
    scratch: u32,
    ac64: bool,
    /// Rozmiar kontekstu: 32 albo 64 B (HCCPARAMS1.CSZ).
    ctx: u64,
    /// Porty USB 2 / USB 3 z „Supported Protocol”: (pierwszy, liczba).
    usb2: (u32, u32),
    usb3: (u32, u32),
    bios: &'static str,
    irq: u64,
    pool: Pool,
    dcbaa: u64,
    /// Strona na dane transferów sterujących (deskryptory).
    buf: (u64, u64),
    cmd: Ring,
    ev: Ring,
    /// Zakończona komenda: (adres TRB, kod, slot).
    done: Option<(u64, u32, u32)>,
    /// Zdarzenia transferu: (adres TRB, kod, reszta, slot, endpoint).
    xfers: [(u64, u32, u32, u32, u32); 16],
    nxfers: usize,
    ports: [Port; PORTS_MAX],
    dirty: [bool; PORTS_MAX],
    csc: [bool; PORTS_MAX],
    last_error: [&'static str; PORTS_MAX],
    devs: [Option<Dev>; DEVS_MAX],
    noops: u64,
    polled: u64,
    irqs: u64,
    events: u64,
    port_events: u64,
    errors: u64,
    enumerated: u64,
    /// M20.h: czasy enumeracji (ms) – liczba, suma, najdłuższy.
    enum_count: u64,
    enum_sum: u64,
    enum_max: u64,
    failures: u64,
    /// M20.e: uchwyt INPUT (slot 5) jest – zdarzenia idą do jądra.
    input: bool,
    hid_reports: u64,
    hid_events: u64,
    hid_errors: u64,
    /// Diody do wysłania klawiaturom (Set Report poza obsługą zdarzeń).
    leds_wanted: Option<u8>,
    /// M20.f: uchwyt BLK (slot 6) jest – dyski idą do jądra.
    blk: bool,
    /// Bufory DMA dla pendrive'ów: (adres w procesie, fizyczny, uchwyt SHM,
    /// zajęty).  Żyją z przejęciem kontrolera – po odłączeniu wracają do puli.
    stor_bufs: [(u64, u64, u64, bool); STOR_MAX],
    stor_reads: u64,
    stor_bytes: u64,
    stor_errors: u64,
    stor_requests_bad: u64,
    /// M20.h: ponowione INQUIRY przy starcie pendrive'ów.
    stor_retries: u64,
    /// v0.27.1: kod zakończenia ostatniej nieudanej komendy (diagnostyka) i
    /// prędkość ostatnio enumerowanego portu huba.
    last_cc: u32,
    last_speed: u32,
    /// M20.d: raporty zmian portów od hubów, błędy hubów.
    hub_events: u64,
    hub_errors: u64,
}

impl Hc {
    fn op_rd(&self, r: u64) -> u32 {
        rd32(self.op + r)
    }

    fn op_wr(&self, r: u64, v: u32) {
        wr32(self.op + r, v)
    }

    fn ir(&self, r: u64) -> u64 {
        self.rt + IR0 + r
    }

    fn portsc(&self, port: u32) -> u64 {
        self.op + PORTSC + 0x10 * (port as u64 - 1)
    }

    fn ports(&self) -> u32 {
        self.max_ports.min(PORTS_MAX as u32)
    }

    fn is_usb3(&self, port: u32) -> bool {
        let (a, n) = self.usb3;
        n > 0 && port >= a && port < a + n
    }

    fn failed(&self) -> bool {
        self.op_rd(USBSTS) & (STS_HSE | STS_HCE) != 0
    }

    /// Zdarzenia z pierścienia: zakończenia komend, transferów, zmiany portów.
    fn poll_events(&mut self) {
        let mut any = false;
        while let Some(ev) = self.ev.pop() {
            any = true;
            self.events += 1;
            let ty = (ev[3] >> 10) & 0x3F;
            let ptr = ev[0] as u64 | (ev[1] as u64) << 32;
            match ty {
                TRB_CMD_DONE => self.done = Some((ptr, ev[2] >> 24, ev[3] >> 24)),
                TRB_TRANSFER if self.is_hid_ep(ev[3] >> 24, (ev[3] >> 16) & 0x1F) => {
                    // M20.e: raport HID – obsłużony od razu (nie czeka na transfer sterujący).
                    self.hid_event(ptr, ev[2] >> 24, ev[2] & 0xFF_FFFF, ev[3] >> 24, (ev[3] >> 16) & 0x1F);
                }
                TRB_TRANSFER if self.is_hub_ep(ev[3] >> 24, (ev[3] >> 16) & 0x1F) => {
                    // M20.d: hub zgłasza zmianę portów – sprawdzimy je w pętli głównej.
                    self.hub_event(ptr, ev[2] >> 24, ev[2] & 0xFF_FFFF, ev[3] >> 24, (ev[3] >> 16) & 0x1F);
                }
                TRB_TRANSFER => {
                    if self.nxfers == self.xfers.len() {
                        self.xfers.copy_within(1.., 0);
                        self.nxfers -= 1;
                    }
                    self.xfers[self.nxfers] = (ptr, ev[2] >> 24, ev[2] & 0xFF_FFFF, ev[3] >> 24, (ev[3] >> 16) & 0x1F);
                    self.nxfers += 1;
                }
                TRB_PORT_CHANGE => {
                    self.port_events += 1;
                    let port = ev[0] >> 24;
                    if port >= 1 && port <= self.ports() {
                        // Zapamiętaj podłączenie / odłączenie, skasuj bity zmian (RW1C),
                        // nie ruszając PED.
                        let a = self.portsc(port);
                        let v = rd32(a);
                        if v & PORT_CSC != 0 {
                            self.csc[port as usize - 1] = true;
                        }
                        self.dirty[port as usize - 1] = true;
                        wr32(a, (v & PORT_KEEP) | (v & PORT_CHANGES));
                    }
                }
                TRB_HC_EVENT => self.errors += 1,
                _ => {}
            }
        }
        if any {
            let deq = self.ev.pa + self.ev.idx as u64 * 16;
            wr64(self.ir(ERDP), deq | ERDP_EHB);
        }
        wr32(self.ir(IMAN), IMAN_IE | IMAN_IP);
        self.op_wr(USBSTS, STS_EINT);
    }

    fn is_hub_ep(&self, slot: u32, ep: u32) -> bool {
        ep != 1 && self.devs.iter().any(|x| matches!(x, Some(d) if d.slot == slot && matches!(&d.hub, Some(h) if h.dci == ep)))
    }

    fn is_hid_ep(&self, slot: u32, ep: u32) -> bool {
        ep != 1 && self.devs.iter().any(|x| matches!(x, Some(d) if d.slot == slot && matches!(&d.hid, Some(h) if h.dci == ep)))
    }

    /// Czeka na przerwanie najwyżej `ms` (co najwyżej 10 ms – potem i tak
    /// sprawdzamy pierścień); true = przyszło przerwanie.
    fn wait_irq(&mut self, ms: u64) -> bool {
        match wait_many(&[(self.irq, W_IRQ)], ms.min(10).max(1)) {
            Ok(1) => {
                self.irqs += irq_read(self.irq) as u64;
                true
            }
            _ => false,
        }
    }

    /// Komenda -> czeka na jej zdarzenie zakończenia (przerwanie; co 10 ms
    /// sprawdza też pierścień – gdyby przerwania nie dochodziły, licznik
    /// `polled` to pokaże).  Wynik: (kod zakończenia, slot).
    fn command(&mut self, dw: [u32; 3], ctl: u32) -> Result<(u32, u32), i64> {
        let pa = self.cmd.push(dw, ctl);
        wr32(self.db, 0); // dzwonek 0 = kontroler (pierścień komend)
        let t0 = uptime_ms();
        let mut by_poll = false;
        loop {
            self.poll_events();
            if let Some((p, code, slot)) = self.done.take() {
                if p == pa {
                    if by_poll {
                        self.polled += 1;
                    }
                    return Ok((code, slot));
                }
            }
            if self.failed() {
                return Err(EIO);
            }
            let spent = uptime_ms() - t0;
            if spent >= TIMEOUT_MS {
                self.errors += 1;
                return Err(EIO);
            }
            by_poll = !self.wait_irq(TIMEOUT_MS - spent);
        }
    }

    fn noop(&mut self) -> Result<(), i64> {
        match self.command([0; 3], TRB_NOOP_CMD << 10)?.0 {
            CC_SUCCESS => {
                self.noops += 1;
                Ok(())
            }
            _ => {
                self.errors += 1;
                Err(EIO)
            }
        }
    }

    /// n komend No-Op; ns na komendę.
    fn noop_bench(&mut self, n: u64) -> Result<u64, i64> {
        let t0 = uptime_ms();
        for _ in 0..n {
            self.noop()?;
        }
        Ok((uptime_ms() - t0) * 1_000_000 / n.max(1))
    }

    fn slot_command(&mut self, ty: u32, slot: u32, extra: u32, dw: [u32; 3]) -> Result<(), XferError> {
        match self.command(dw, ty << 10 | slot << 24 | extra) {
            Ok((CC_SUCCESS, _)) => Ok(()),
            Ok((cc, _)) => {
                self.last_cc = cc;
                Err(XferError::Command)
            }
            Err(_) => {
                self.last_cc = 0;
                Err(XferError::Timeout)
            }
        }
    }

    /// Po STALL / błędzie: endpoint 0 z powrotem w stanie Running (Reset
    /// Endpoint) i kolejka za nieudanym transferem (Set TR Dequeue).
    fn reset_ep0(&mut self, d: usize) {
        let Some(dev) = self.devs[d].as_ref() else { return };
        let (slot, deq) = (dev.slot, dev.ring.enqueue_ptr());
        let _ = self.slot_command(TRB_RESET_EP, slot, 1 << 16, [0; 3]);
        let _ = self.slot_command(TRB_SET_DEQUEUE, slot, 1 << 16, [deq as u32, (deq >> 32) as u32, 0]);
    }

    /// Transfer sterujący na EP0; dane (IN) w `self.buf`.  Wynik: bajty danych.
    fn control(&mut self, d: usize, req_type: u8, req: u8, value: u16, index: u16, len: u16) -> Result<usize, XferError> {
        self.control_data(d, req_type, req, value, index, len, &[])
    }

    /// Transfer sterujący; `out` – dane do urządzenia (prośby OUT, np. Set Report).
    fn control_data(&mut self, d: usize, req_type: u8, req: u8, value: u16, index: u16, len: u16, out: &[u8]) -> Result<usize, XferError> {
        let len = len.min(4096);
        if req_type & 0x80 == 0 && !out.is_empty() {
            let n = out.len().min(len as usize);
            unsafe { core::ptr::copy_nonoverlapping(out.as_ptr(), self.buf.0 as *mut u8, n) };
        }
        let buf_pa = self.buf.1;
        let Some(dev) = self.devs[d].as_mut() else { return Err(XferError::Gone) };
        let slot = dev.slot;
        let input = req_type & 0x80 != 0;
        let trt = if len == 0 { 0 } else if input { 3 } else { 2 };
        let setup = [req_type as u32 | (req as u32) << 8 | (value as u32) << 16, index as u32 | (len as u32) << 16, 8];
        dev.ring.push(setup, TRB_SETUP << 10 | TRB_IDT | trt << 16);
        if len > 0 {
            dev.ring.push([buf_pa as u32, (buf_pa >> 32) as u32, len as u32], TRB_DATA << 10 | TRB_ISP | (input as u32) << 16);
        }
        let status_in = !(len > 0 && input);
        let status = dev.ring.push([0; 3], TRB_STATUS << 10 | TRB_IOC | (status_in as u32) << 16);
        wr32(self.db + 4 * slot as u64, 1); // dzwonek urządzenia, cel 1 = EP0
        let t0 = uptime_ms();
        let mut residual = 0u32;
        loop {
            self.poll_events();
            let mut result: Option<Result<usize, XferError>> = None;
            while self.nxfers > 0 && result.is_none() {
                let (ptr, code, rest, s, ep) = self.xfers[0];
                self.xfers.copy_within(1.., 0);
                self.nxfers -= 1;
                if s != slot || ep != 1 {
                    continue; // nie nasze (inne urządzenie)
                }
                match code {
                    CC_SHORT => residual = rest,
                    CC_SUCCESS if ptr == status => result = Some(Ok(len.saturating_sub(residual as u16) as usize)),
                    CC_SUCCESS => {}
                    CC_STALL => result = Some(Err(XferError::Stall)),
                    _ => result = Some(Err(XferError::Code)),
                }
            }
            if let Some(r) = result {
                if r.is_err() {
                    self.reset_ep0(d);
                }
                return r;
            }
            if self.failed() {
                return Err(XferError::Code);
            }
            let spent = uptime_ms() - t0;
            if spent >= TIMEOUT_MS {
                return Err(XferError::Timeout);
            }
            self.wait_irq(TIMEOUT_MS - spent);
        }
    }

    /// GET_DESCRIPTOR (standardowe, do urządzenia).
    fn get_descriptor(&mut self, d: usize, ty: u8, index: u8, lang: u16, len: u16) -> Result<usize, XferError> {
        self.control(d, 0x80, 6, (ty as u16) << 8 | index as u16, lang, len)
    }

    fn buf(&self, n: usize) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.buf.0 as *const u8, n.min(4096)) }
    }

    /// Napis (producent / produkt) jako ASCII.
    fn string(&mut self, d: usize, index: u8, lang: u16, out: &mut [u8; NAME_MAX]) -> usize {
        if index == 0 {
            return 0;
        }
        match self.get_descriptor(d, DESC_STRING, index, lang, 255) {
            Ok(n) => {
                let mut tmp = [0u8; 256];
                tmp[..n.min(256)].copy_from_slice(self.buf(n.min(256)));
                string_ascii(&tmp[..n.min(256)], out)
            }
            Err(_) => 0,
        }
    }

    /// Reset portu USB 2 (urządzenie high speed ujawnia się dopiero tu).
    fn port_reset(&mut self, port: u32) -> Result<(), &'static str> {
        let a = self.portsc(port);
        let v = rd32(a);
        wr32(a, (v & PORT_KEEP) | PORT_PR);
        let t0 = uptime_ms();
        loop {
            sleep_ms(5);
            let v = rd32(a);
            if v & PORT_CCS == 0 {
                return Err("device disconnected during port reset");
            }
            if v & PORT_PR == 0 {
                break;
            }
            if uptime_ms() - t0 > PORT_RESET_MS {
                return Err("port reset timed out");
            }
        }
        sleep_ms(10); // czas na powrót urządzenia po resecie (USB 2: 10 ms)
        let v = rd32(a);
        wr32(a, (v & PORT_KEEP) | (v & PORT_CHANGES));
        if v & PORT_PED == 0 {
            return Err("port not enabled after reset");
        }
        Ok(())
    }

    fn ctx_w(&self, base: u64, index: u64, dword: u64, v: u32) {
        wr32(base + index * self.ctx + dword * 4, v);
    }

    /// Kontekst slotu w kontekście wejściowym: liczba wpisów, prędkość, route
    /// string, port kontrolera, TT; dla huba – bit Hub, liczba portów, think time.
    fn slot_ctx(&self, input: u64, d: usize, entries: u32) {
        let dev = self.devs[d].as_ref().unwrap();
        let l = &dev.loc;
        let hub = dev.hub.as_ref();
        let mut dw0 = entries << 27 | dev.speed << 20 | (l.route & 0xF_FFFF);
        let mut dw1 = dev.port << 16;
        let mut dw2 = l.tt.0 | l.tt.1 << 8;
        if let Some(h) = hub {
            dw0 |= 1 << 26;
            dw1 |= h.nports << 24;
            if dev.speed == 3 {
                dw2 |= h.think << 16;
            }
        }
        self.ctx_w(input, 1, 0, dw0);
        self.ctx_w(input, 1, 1, dw1);
        self.ctx_w(input, 1, 2, dw2);
    }

    /// Port kontrolera -> urządzenie w stanie „Działa”; Err = powód (port do
    /// ponownej próby).
    fn enumerate(&mut self, port: u32) -> Result<usize, &'static str> {
        let t0 = uptime_ms();
        let v = rd32(self.portsc(port));
        if v & PORT_CCS == 0 {
            return Err("disconnected");
        }
        if !(self.is_usb3(port) && v & PORT_PED != 0) {
            self.port_reset(port)?;
        }
        let speed = (rd32(self.portsc(port)) >> 10) & 0xF;
        self.enumerate_at(port, speed, Loc::default(), t0)
    }

    /// Wspólne dla portu kontrolera i portu huba: slot, adres, deskryptory,
    /// sterowniki klas (HID, pamięć masowa, hub).
    /// `t0` – początek enumeracji (przed resetem portu) – M20.h: czas do „gotowe”.
    fn enumerate_at(&mut self, port: u32, speed: u32, loc: Loc, t0: u64) -> Result<usize, &'static str> {
        let usb3 = speed >= 4; // SuperSpeed: bMaxPacketSize0 jako wykładnik
        let mps0: u16 = match speed {
            1 | 2 => 8,
            3 => 64,
            4 | 5 => 512,
            _ => return Err("unknown port speed"),
        };
        let Some(d) = self.devs.iter().position(|x| x.is_none()) else { return Err("too many devices (32)") };
        let pages = (self.pool.page(), self.pool.page(), self.pool.page());
        let (Ok(input), Ok(output), Ok(ring_page)) = pages else {
            for p in [pages.0, pages.1, pages.2].into_iter().flatten() {
                self.pool.release(p);
            }
            return Err("out of DMA memory");
        };
        let slot = match self.command([0; 3], TRB_ENABLE_SLOT << 10) {
            Ok((CC_SUCCESS, s)) if s >= 1 && s <= self.slots => s,
            _ => {
                for p in [input, output, ring_page] {
                    self.pool.release(p);
                }
                return Err("Enable Slot failed (no free slot?)");
            }
        };
        self.devs[d] = Some(Dev {
            port,
            slot,
            speed,
            addr: 0,
            input,
            output,
            ring_page,
            ring: Ring::new_linked(ring_page.0, ring_page.1),
            mps0,
            desc: DeviceDesc::default(),
            cfg: Config::default(),
            manufacturer: [0; NAME_MAX],
            mlen: 0,
            product: [0; NAME_MAX],
            plen: 0,
            hid: None,
            hid_error: "",
            stor: None,
            stor_error: "",
            loc,
            hub: None,
            hub_error: "",
            enum_ms: 0,
        });
        match self.describe_device(d, slot, mps0, usb3) {
            Ok(()) => {
                self.enumerated += 1;
                // M20.e: klawiatura / mysz – błąd konfiguracji nie odłącza urządzenia.
                if let Err(e) = self.setup_hid(d) {
                    self.devs[d].as_mut().unwrap().hid_error = e;
                }
                // M20.f: pendrive – błąd nie odłącza urządzenia (widać go w lsusb).
                if let Err(e) = self.setup_storage(d) {
                    if let Some(dev) = self.devs[d].as_mut() {
                        dev.stor_error = e;
                    }
                }
                // M20.d: hub – błąd: hub widoczny w lsusb, porty za nim nieobsługiwane.
                if let Err(e) = self.setup_hub(d) {
                    if let Some(dev) = self.devs[d].as_mut() {
                        dev.hub_error = e;
                    }
                }
                // M20.h: czas enumeracji (reset portu -> sterownik klasy gotowy).
                let ms = uptime_ms().saturating_sub(t0);
                if let Some(dev) = self.devs[d].as_mut() {
                    dev.enum_ms = ms as u32;
                }
                self.enum_count += 1;
                self.enum_sum += ms;
                self.enum_max = self.enum_max.max(ms);
                Ok(d)
            }
            Err(e) => {
                self.detach(d);
                Err(e)
            }
        }
    }

    /// Address Device, deskryptory, napisy.
    fn describe_device(&mut self, d: usize, slot: u32, mps0: u16, usb3: bool) -> Result<(), &'static str> {
        let (input, output, ring_pa) = {
            let dev = self.devs[d].as_ref().unwrap();
            (dev.input, dev.output, dev.ring.pa)
        };
        // Kontekst wejściowy: dodaj slot i EP0.
        self.ctx_w(input.0, 0, 1, 0b11);
        self.slot_ctx(input.0, d, 1); // 1 wpis kontekstu, prędkość, trasa, TT
        self.ctx_w(input.0, 2, 1, 3 << 1 | 4 << 3 | (mps0 as u32) << 16); // CErr 3, typ: sterujący
        self.ctx_w(input.0, 2, 2, ring_pa as u32 | 1);
        self.ctx_w(input.0, 2, 3, (ring_pa >> 32) as u32);
        self.ctx_w(input.0, 2, 4, 8); // średnia długość TRB
        unsafe { ((self.dcbaa + slot as u64 * 8) as *mut u64).write_volatile(output.1) };
        self.slot_command(TRB_ADDRESS_DEVICE, slot, 0, [input.1 as u32, (input.1 >> 32) as u32, 0])
            .map_err(|_| address_error(self.last_cc))?;
        let addr = rd32(output.0 + 3 * 4) & 0xFF;

        // Pierwsze 8 B: prawdziwy rozmiar pakietu EP0 (full speed: 8..64).
        let n = self.get_descriptor(d, DESC_DEVICE, 0, 0, 8).map_err(|e| e.text())?;
        let real = max_packet0(self.buf(n), usb3).map_err(|e| e.name())?;
        if real != mps0 {
            self.ctx_w(input.0, 0, 0, 0);
            self.ctx_w(input.0, 0, 1, 0b10);
            self.ctx_w(input.0, 2, 1, 3 << 1 | 4 << 3 | (real as u32) << 16);
            self.slot_command(TRB_EVALUATE_CONTEXT, slot, 0, [input.1 as u32, (input.1 >> 32) as u32, 0])
                .map_err(|_| "Evaluate Context failed")?;
        }
        let n = self.get_descriptor(d, DESC_DEVICE, 0, 0, 18).map_err(|e| e.text())?;
        let desc = parse_device(self.buf(n), usb3).map_err(|e| e.name())?;

        // Konfiguracja 1: nagłówek (wTotalLength), potem całość.
        let n = self.get_descriptor(d, DESC_CONFIG, 0, 0, 9).map_err(|e| e.text())?;
        let total = config_total(self.buf(n)).map_err(|e| e.name())?;
        let n = self.get_descriptor(d, DESC_CONFIG, 0, 0, total).map_err(|e| e.text())?;
        let mut tmp = [0u8; CONFIG_MAX];
        tmp[..n].copy_from_slice(self.buf(n));
        let cfg = parse_config(&tmp[..n]).map_err(|e| e.name())?;

        // Napisy – nieobowiązkowe (błąd = brak nazwy).
        let lang = match self.get_descriptor(d, DESC_STRING, 0, 0, 255) {
            Ok(n) => first_langid(self.buf(n)).unwrap_or(0x0409),
            Err(_) => 0x0409,
        };
        let mut m = [0u8; NAME_MAX];
        let mlen = self.string(d, desc.i_manufacturer, lang, &mut m);
        let mut p = [0u8; NAME_MAX];
        let plen = self.string(d, desc.i_product, lang, &mut p);

        let dev = self.devs[d].as_mut().unwrap();
        dev.addr = addr;
        dev.mps0 = real;
        dev.desc = desc;
        dev.cfg = cfg;
        (dev.manufacturer, dev.mlen, dev.product, dev.plen) = (m, mlen, p, plen);
        Ok(())
    }


    // --------------------------------------------------------------
    // M20.e: klawiatura i mysz HID (boot protocol)
    // --------------------------------------------------------------

    /// Interfejs boot HID z endpointem przerwań IN: (indeks interfejsu, mysz?, endpoint).
    fn hid_interface(cfg: &Config) -> Option<(u8, bool, Endpoint)> {
        for f in &cfg.ifaces[..cfg.n_ifaces] {
            if f.class == 3 && f.subclass == 1 && matches!(f.protocol, 1 | 2) {
                if let Some(e) = f.eps[..f.n_eps].iter().find(|e| e.kind() == 3 && e.is_in()) {
                    return Some((f.number, f.protocol == 2, *e));
                }
            }
        }
        None
    }

    /// Klawiatura / mysz: Configure Endpoint, Set Configuration, Set Protocol
    /// (boot), Set Idle, TRB czekające na raporty.
    fn setup_hid(&mut self, d: usize) -> Result<(), &'static str> {
        let (slot, speed, input, cfg_value, found) = {
            let dev = self.devs[d].as_ref().unwrap();
            (dev.slot, dev.speed, dev.input, dev.cfg.value, Self::hid_interface(&dev.cfg))
        };
        let Some((iface, mouse, ep)) = found else { return Ok(()) };
        let dci = (ep.address & 0x0F) as u32 * 2 + 1;
        let mps = (ep.max_packet & 0x7FF).clamp(1, 64);
        let interval = if speed >= 3 {
            (ep.interval.clamp(1, 16) - 1) as u32
        } else {
            let v = (ep.interval.max(1) as u32) * 8; // ms -> mikroramki 125 us
            (31 - v.leading_zeros()).clamp(3, 10)
        };
        let (Ok(ring_page), Ok(data_page)) = (self.pool.page(), self.pool.page()) else {
            return Err("out of DMA memory");
        };
        let mut hid = Hid {
            mouse,
            iface,
            dci,
            mps,
            ring: Ring::new_linked(ring_page.0, ring_page.1),
            ring_page,
            data_page,
            prev: [0; 8],
            leds: 0,
            reports: 0,
            errors: 0,
        };
        // Kontekst wejściowy: slot (liczba kontekstów = dci) + endpoint dci.
        unsafe { core::ptr::write_bytes(input.0 as *mut u8, 0, 4096) };
        self.ctx_w(input.0, 0, 1, 1 | 1 << dci);
        self.slot_ctx(input.0, d, dci);
        let e = dci as u64 + 1;
        self.ctx_w(input.0, e, 0, interval << 16);
        self.ctx_w(input.0, e, 1, 3 << 1 | 7 << 3 | (mps as u32) << 16); // CErr 3, typ: przerwania IN
        self.ctx_w(input.0, e, 2, hid.ring.pa as u32 | 1);
        self.ctx_w(input.0, e, 3, (hid.ring.pa >> 32) as u32);
        self.ctx_w(input.0, e, 4, mps as u32 | (mps as u32) << 16);
        let r = self
            .slot_command(TRB_CONFIGURE_EP, slot, 0, [input.1 as u32, (input.1 >> 32) as u32, 0])
            .map_err(|_| "Configure Endpoint failed")
            .and_then(|_| self.control(d, 0x00, 9, cfg_value as u16, 0, 0).map(|_| ()).map_err(|_| "Set Configuration failed"));
        if let Err(e) = r {
            self.pool.release(ring_page);
            self.pool.release(data_page);
            return Err(e);
        }
        // Boot protocol i raport tylko przy zmianie – nieobowiązkowe (część urządzeń odmawia).
        let _ = self.control(d, 0x21, 0x0B, 0, iface as u16, 0);
        let _ = self.control(d, 0x21, 0x0A, 0, iface as u16, 0);
        for _ in 0..HID_TRBS {
            Self::hid_queue(&mut hid);
        }
        self.devs[d].as_mut().unwrap().hid = Some(hid);
        wr32(self.db + 4 * slot as u64, dci);
        Ok(())
    }

    /// Jeden TRB czekający na raport (bufor = indeks TRB % 16 w stronie danych).
    fn hid_queue(h: &mut Hid) {
        let pa = h.data_page.1 + (h.ring.idx as u64 % 16) * HID_BUF;
        h.ring.push([pa as u32, (pa >> 32) as u32, h.mps as u32], TRB_NORMAL << 10 | TRB_IOC | TRB_ISP);
    }

    /// Zdarzenie transferu na endpoincie HID (z poll_events).
    fn hid_event(&mut self, ptr: u64, code: u32, rest: u32, slot: u32, ep: u32) {
        let Some(d) = self.devs.iter().position(|x| matches!(x, Some(dev) if dev.slot == slot && matches!(&dev.hid, Some(h) if h.dci == ep)))
        else {
            return;
        };
        let db = self.db;
        let dev = self.devs[d].as_mut().unwrap();
        let h = dev.hid.as_mut().unwrap();
        if ptr < h.ring.pa || ptr >= h.ring.pa + 4096 {
            return;
        }
        if !matches!(code, CC_SUCCESS | CC_SHORT) {
            // Endpoint zatrzymany (STALL, błąd transmisji) – reset w pętli głównej.
            h.errors += 1;
            self.hid_errors += 1;
            return;
        }
        let idx = ((ptr - h.ring.pa) / 16) as u64;
        let len = (h.mps as u32).saturating_sub(rest).min(64) as usize;
        let mut report = [0u8; 64];
        unsafe { core::ptr::copy_nonoverlapping((h.data_page.0 + (idx % 16) * HID_BUF) as *const u8, report.as_mut_ptr(), len) };
        h.reports += 1;
        let mouse = h.mouse;
        Self::hid_queue(h);
        wr32(db + 4 * slot as u64, ep);
        self.hid_reports += 1;
        if mouse {
            self.mouse_report(&report[..len]);
        } else {
            self.kbd_report(d, &report[..len]);
        }
    }

    /// Raport klawiatury (boot: modyfikatory, zarezerwowany, 6 klawiszy) ->
    /// różnica z poprzednim -> zdarzenia do jądra.
    fn kbd_report(&mut self, d: usize, r: &[u8]) {
        if r.len() < 3 {
            return;
        }
        let mut new = [0u8; 8];
        new[..r.len().min(8)].copy_from_slice(&r[..r.len().min(8)]);
        // ErrorRollOver / POSTFail / ErrorUndefined – za dużo klawiszy naraz: bez zmian.
        if new[2..].iter().any(|&k| matches!(k, 1..=3)) {
            return;
        }
        let h = self.devs[d].as_mut().unwrap().hid.as_mut().unwrap();
        let prev = h.prev;
        h.prev = new;
        let mut ev = [[0u8; 8]; 32];
        let mut n = 0;
        for b in 0..8u8 {
            let (o, w) = (prev[0] >> b & 1, new[0] >> b & 1);
            if o != w {
                ev[n] = key_event(0xE0 + b, w == 1);
                n += 1;
            }
        }
        for &k in &prev[2..8] {
            if k > 3 && !new[2..8].contains(&k) {
                ev[n] = key_event(k, false);
                n += 1;
            }
        }
        for &k in &new[2..8] {
            if k > 3 && !prev[2..8].contains(&k) {
                ev[n] = key_event(k, true);
                n += 1;
            }
        }
        if n == 0 {
            return;
        }
        self.hid_events += n as u64;
        if self.input {
            let leds = input_inject(INPUT, &ev[..n]);
            if leds >= 0 && leds as u8 != h.leds {
                self.leds_wanted = Some(leds as u8);
            }
        }
    }

    /// Raport myszy (boot: przyciski, dx, dy[, kółko]) – kółko przewija konsolę.
    fn mouse_report(&mut self, r: &[u8]) {
        if r.len() < 4 || r[3] == 0 {
            return;
        }
        self.hid_events += 1;
        if self.input {
            // USB: dodatnie = od siebie (w górę); jądro (jak PS/2): dodatnie = w dół.
            let _ = input_inject(INPUT, &[mouse_event(r[0], (r[3] as i8).saturating_neg())]);
        }
    }

    /// Pętla główna: diody klawiatur, endpointy HID po błędzie.
    fn hid_maintenance(&mut self) {
        if let Some(l) = self.leds_wanted.take() {
            for d in 0..DEVS_MAX {
                let Some((iface, leds)) = self.devs[d].as_ref().and_then(|x| x.hid.as_ref()).filter(|h| !h.mouse).map(|h| (h.iface, h.leds)) else {
                    continue;
                };
                if leds != l {
                    let _ = self.control_data(d, 0x21, 0x09, 0x0200, iface as u16, 1, &[l]);
                    if let Some(h) = self.devs[d].as_mut().and_then(|x| x.hid.as_mut()) {
                        h.leds = l;
                    }
                }
            }
        }
        for d in 0..DEVS_MAX {
            let Some((slot, dci, errors)) = self.devs[d].as_ref().and_then(|x| x.hid.as_ref().map(|h| (x.slot, h.dci, h.errors))) else {
                continue;
            };
            if errors == 0 {
                continue;
            }
            // Reset endpointu, kolejka za nieudanymi TRB, nowe TRB.
            let deq = self.devs[d].as_ref().unwrap().hid.as_ref().unwrap().ring.enqueue_ptr();
            let _ = self.slot_command(TRB_RESET_EP, slot, dci << 16, [0; 3]);
            let _ = self.slot_command(TRB_SET_DEQUEUE, slot, dci << 16, [deq as u32, (deq >> 32) as u32, 0]);
            let h = self.devs[d].as_mut().unwrap().hid.as_mut().unwrap();
            h.errors = 0;
            for _ in 0..HID_TRBS {
                Self::hid_queue(h);
            }
            wr32(self.db + 4 * slot as u64, dci);
        }
    }

    /// "idle MS": raporty co MS ms także bez zmian (Set Idle) – test potoku.
    fn hid_idle(&mut self, ms: u16) -> usize {
        let mut n = 0;
        for d in 0..DEVS_MAX {
            let Some(iface) = self.devs[d].as_ref().and_then(|x| x.hid.as_ref()).map(|h| h.iface) else { continue };
            if self.control(d, 0x21, 0x0A, (ms / 4).min(255) << 8, iface as u16, 0).is_ok() {
                n += 1;
            }
        }
        n
    }

    // --------------------------------------------------------------
    // M20.f: pamięć masowa (Bulk-Only + SCSI) – TYLKO ODCZYT
    // --------------------------------------------------------------

    /// Interfejs 08/06/50 (SCSI transparent, Bulk-Only) z bulk IN i OUT.
    fn storage_interface(cfg: &Config) -> Option<(u8, Endpoint, Endpoint)> {
        for f in &cfg.ifaces[..cfg.n_ifaces] {
            if f.class == 8 && f.subclass == 6 && f.protocol == 0x50 {
                let i = f.eps[..f.n_eps].iter().find(|e| e.kind() == 2 && e.is_in());
                let o = f.eps[..f.n_eps].iter().find(|e| e.kind() == 2 && !e.is_in());
                if let (Some(i), Some(o)) = (i, o) {
                    return Some((f.number, *i, *o));
                }
            }
        }
        None
    }

    /// Czeka `ms`, obsługując zdarzenia (klawiatura działa dalej).
    fn pause(&mut self, ms: u64) {
        let t0 = uptime_ms();
        loop {
            self.poll_events();
            let spent = uptime_ms() - t0;
            if spent >= ms {
                return;
            }
            self.wait_irq(ms - spent);
        }
    }

    /// Bufor DMA na dane pendrive'a (wspólny z jądrem): wolny z puli albo nowy.
    fn stor_buf(&mut self) -> Result<usize, &'static str> {
        if let Some(i) = self.stor_bufs.iter().position(|b| b.2 != 0 && !b.3) {
            self.stor_bufs[i].3 = true;
            return Ok(i);
        }
        let Some(i) = self.stor_bufs.iter().position(|b| b.2 == 0) else { return Err("too many storage devices (4)") };
        let h = dma_alloc(DEV, STOR_SLOTS as u64 * STOR_SLOT, self.pool.bits);
        if h < 0 {
            return Err("out of DMA memory (storage buffer)");
        }
        let h = h as u64;
        let (Ok(pa), Ok(va)) = (dma_phys(h), shm_map(h, PROT_READ | PROT_WRITE)) else {
            close(h);
            return Err("cannot map the storage buffer");
        };
        self.stor_bufs[i] = (va, pa, h, true);
        Ok(i)
    }

    /// Transfer bulk: `len` bajtów (1..128 KiB) z / do `pa`; TRB dzielone na
    /// granicach 64 KiB (wymóg xHCI), połączone w łańcuch.  Wynik: przesłane
    /// bajty (krótki pakiet IN – mniej).
    fn bulk(&mut self, d: usize, input: bool, pa: u64, len: usize) -> Result<usize, XferError> {
        let db = self.db;
        let Some(dev) = self.devs[d].as_mut() else { return Err(XferError::Gone) };
        let (slot, port) = (dev.slot, dev.port);
        let Some(st) = dev.stor.as_mut() else { return Err(XferError::Gone) };
        let (ring, dci, mps) = if input { (&mut st.ring_in, st.dci_in, st.mps_in) } else { (&mut st.ring_out, st.dci_out, st.mps_out) };
        if len == 0 || len > 2 * STOR_SLOT as usize {
            return Err(XferError::Code);
        }
        let mut pieces = [(0u64, 0usize); 4];
        let mut n = 0;
        let mut off = 0usize;
        while off < len && n < pieces.len() {
            let a = pa + off as u64;
            let k = ((0x1_0000 - (a & 0xFFFF)) as usize).min(len - off);
            pieces[n] = (a, k);
            n += 1;
            off += k;
        }
        let mut trbs = [(0u64, 0usize); 4];
        let mut sent = 0;
        for i in 0..n {
            let (a, k) = pieces[i];
            let last = i + 1 == n;
            let after = len - sent - k;
            let td = if last { 0 } else { after.div_ceil(mps.max(1) as usize).min(31) as u32 };
            let ctl = TRB_NORMAL << 10 | if input { TRB_ISP } else { 0 } | if last { TRB_IOC } else { TRB_CH };
            trbs[i] = (ring.push([a as u32, (a >> 32) as u32, k as u32 | td << 17], ctl), k);
            sent += k;
        }
        wr32(db + 4 * slot as u64, dci);
        let t0 = uptime_ms();
        loop {
            self.poll_events();
            let mut result: Option<Result<usize, XferError>> = None;
            while self.nxfers > 0 && result.is_none() {
                let (ptr, code, rest, s, ep) = self.xfers[0];
                self.xfers.copy_within(1.., 0);
                self.nxfers -= 1;
                if s != slot || ep != dci {
                    continue;
                }
                // Zdarzenie spoza tego transferu (np. po Stop Endpoint) – pomijane.
                let Some(i) = trbs[..n].iter().position(|t| t.0 == ptr) else { continue };
                if code == CC_SUCCESS && i + 1 != n {
                    continue;
                }
                let before: usize = trbs[..i].iter().map(|t| t.1).sum();
                result = Some(match code {
                    CC_SUCCESS | CC_SHORT => Ok(before + trbs[i].1 - (rest as usize).min(trbs[i].1)),
                    CC_STALL => Err(XferError::Stall),
                    _ => Err(XferError::Code),
                });
            }
            if let Some(r) = result {
                return r;
            }
            if self.failed() {
                return Err(XferError::Code);
            }
            if rd32(self.portsc(port)) & PORT_CCS == 0 {
                return Err(XferError::Gone);
            }
            // M20.g: za hubem – zmiana na porcie huba (np. pendrive wyjęty) przerywa
            // czekanie od razu (bez tego: 4 s timeoutu + reset recovery > 5 s jądra).
            if self.port_change_pending(d) {
                return Err(XferError::Interrupted);
            }
            let spent = uptime_ms() - t0;
            if spent >= BULK_TIMEOUT_MS {
                return Err(XferError::Timeout);
            }
            self.wait_irq(BULK_TIMEOUT_MS - spent);
        }
    }

    /// Hub-rodzic zgłosił zmianę na porcie urządzenia `d` (jeszcze nieobsłużoną).
    fn port_change_pending(&self, d: usize) -> bool {
        let Some(dev) = self.devs[d].as_ref() else { return true };
        match dev.loc.parent.and_then(|p| self.devs[p].as_ref()).and_then(|x| x.hub.as_ref()) {
            Some(h) => h.pending & (1 << dev.loc.hub_port) != 0,
            None => false,
        }
    }

    /// Endpoint bulk po błędzie: zatrzymany (Stop – gdy działał z porzuconym
    /// TRB) albo zresetowany (Reset – gdy STALL), kolejka za porzuconymi TRB
    /// (Set TR Dequeue), Clear Feature(ENDPOINT_HALT) w urządzeniu.
    fn bulk_recover(&mut self, d: usize, input: bool) {
        let Some((slot, dci, addr, deq)) = self.devs[d].as_ref().and_then(|x| {
            x.stor.as_ref().map(|s| {
                if input { (x.slot, s.dci_in, s.ep_in, s.ring_in.enqueue_ptr()) } else { (x.slot, s.dci_out, s.ep_out, s.ring_out.enqueue_ptr()) }
            })
        }) else {
            return;
        };
        let _ = self.slot_command(TRB_STOP_EP, slot, dci << 16, [0; 3]);
        let _ = self.slot_command(TRB_RESET_EP, slot, dci << 16, [0; 3]);
        let _ = self.slot_command(TRB_SET_DEQUEUE, slot, dci << 16, [deq as u32, (deq >> 32) as u32, 0]);
        let _ = self.control(d, 0x02, 1, 0, addr as u16, 0);
    }

    /// Bulk-Only Mass Storage Reset + oba endpointy od nowa (reset recovery).
    fn reset_recovery(&mut self, d: usize) {
        let Some(iface) = self.devs[d].as_ref().and_then(|x| x.stor.as_ref()).map(|s| s.iface) else { return };
        let _ = self.control(d, 0x21, 0xFF, 0, iface as u16, 0);
        self.bulk_recover(d, true);
        self.bulk_recover(d, false);
    }

    /// Komenda SCSI przez Bulk-Only: CBW, dane IN (`len` bajtów do `data_pa`),
    /// CSW.  Wysyła WYŁĄCZNIE komendy z SCSI_ALLOWED (brak zapisu).
    fn bot(&mut self, d: usize, cdb: &[u8], len: usize, data_pa: u64) -> Result<usize, StorError> {
        if cdb.is_empty() || cdb.len() > 16 || !SCSI_ALLOWED.contains(&cdb[0]) {
            return Err(StorError::Refused);
        }
        // M20.g: poprzedni transfer przerwany zmianą portu – urządzenie nadal jest
        // (hub nie odłączył go w pętli głównej), więc najpierw reset recovery.
        if self.devs[d].as_ref().and_then(|x| x.stor.as_ref()).map_or(false, |s| s.needs_recovery) {
            if self.port_change_pending(d) {
                return Err(StorError::Xfer(XferError::Interrupted));
            }
            self.devs[d].as_mut().unwrap().stor.as_mut().unwrap().needs_recovery = false;
            self.reset_recovery(d);
        }
        let Some(st) = self.devs[d].as_mut().and_then(|x| x.stor.as_mut()) else { return Err(StorError::Xfer(XferError::Gone)) };
        st.tag = st.tag.wrapping_add(1);
        let tag = st.tag;
        let (cva, cpa) = st.cmd_page;
        let mut cbw = [0u8; 31];
        cbw[0..4].copy_from_slice(&0x4342_5355u32.to_le_bytes());
        cbw[4..8].copy_from_slice(&tag.to_le_bytes());
        cbw[8..12].copy_from_slice(&(len as u32).to_le_bytes());
        cbw[12] = if len > 0 { 0x80 } else { 0 };
        cbw[14] = cdb.len() as u8;
        cbw[15..15 + cdb.len()].copy_from_slice(cdb);
        unsafe { core::ptr::copy_nonoverlapping(cbw.as_ptr(), cva as *mut u8, 31) };
        match self.bulk(d, false, cpa, 31) {
            Ok(31) => {}
            Err(XferError::Gone) => return Err(StorError::Xfer(XferError::Gone)),
            Err(XferError::Interrupted) => return Err(self.interrupted(d)),
            Ok(_) => {
                self.reset_recovery(d);
                return Err(StorError::Phase);
            }
            Err(e) => {
                self.reset_recovery(d);
                return Err(StorError::Xfer(e));
            }
        }
        let mut got = 0;
        if len > 0 {
            match self.bulk(d, true, data_pa, len) {
                Ok(n) => got = n,
                // Urządzenie odmówiło danych – CSW i tak przychodzi (po Clear Halt).
                Err(XferError::Stall) => self.bulk_recover(d, true),
                Err(XferError::Gone) => return Err(StorError::Xfer(XferError::Gone)),
                Err(XferError::Interrupted) => return Err(self.interrupted(d)),
                Err(e) => {
                    self.reset_recovery(d);
                    return Err(StorError::Xfer(e));
                }
            }
        }
        let mut csw_ok = false;
        for attempt in 0..2 {
            unsafe { core::ptr::write_bytes((cva + 512) as *mut u8, 0, 13) };
            match self.bulk(d, true, cpa + 512, 13) {
                Ok(13) => {
                    csw_ok = true;
                    break;
                }
                Err(XferError::Stall) if attempt == 0 => self.bulk_recover(d, true),
                Err(XferError::Gone) => return Err(StorError::Xfer(XferError::Gone)),
                Err(XferError::Interrupted) => return Err(self.interrupted(d)),
                _ => break,
            }
        }
        let mut csw = [0u8; 13];
        unsafe { core::ptr::copy_nonoverlapping((cva + 512) as *const u8, csw.as_mut_ptr(), 13) };
        let sig = u32::from_le_bytes([csw[0], csw[1], csw[2], csw[3]]);
        let ctag = u32::from_le_bytes([csw[4], csw[5], csw[6], csw[7]]);
        if !csw_ok || sig != 0x5342_5355 || ctag != tag {
            self.reset_recovery(d);
            return Err(StorError::Phase);
        }
        match csw[12] {
            0 => Ok(got),
            1 => Err(StorError::Failed),
            _ => {
                self.reset_recovery(d);
                Err(StorError::Phase)
            }
        }
    }

    /// Transfer przerwany zmianą portu huba: bez reset recovery teraz (urządzenie
    /// mogło zniknąć – każda komenda czekałaby na timeout), tylko znacznik.
    fn interrupted(&mut self, d: usize) -> StorError {
        if let Some(st) = self.devs[d].as_mut().and_then(|x| x.stor.as_mut()) {
            st.needs_recovery = true;
        }
        StorError::Xfer(XferError::Interrupted)
    }

    /// Komenda z danymi do strony komend (offset 1024); dane w `out`.
    fn scsi_in(&mut self, d: usize, cdb: &[u8], len: usize, out: &mut [u8; 64]) -> Result<usize, StorError> {
        let Some((va, pa)) = self.devs[d].as_ref().and_then(|x| x.stor.as_ref()).map(|s| (s.cmd_page.0 + 1024, s.cmd_page.1 + 1024)) else {
            return Err(StorError::Xfer(XferError::Gone));
        };
        let n = self.bot(d, cdb, len.min(64), pa)?;
        unsafe { core::ptr::copy_nonoverlapping(va as *const u8, out.as_mut_ptr(), n.min(64)) };
        Ok(n)
    }

    /// Pendrive: endpointy bulk, INQUIRY, TEST UNIT READY, READ CAPACITY.
    /// Dysk trafia do jądra później (attach_pending – z pętli głównej, gdy
    /// usbd już odpowiada na żądania).
    fn setup_storage(&mut self, d: usize) -> Result<(), &'static str> {
        let found = self.devs[d].as_ref().and_then(|dev| Self::storage_interface(&dev.cfg));
        if found.is_none() {
            return Ok(());
        }
        let r = self.setup_storage_inner(d, found.unwrap());
        if r.is_err() {
            self.drop_storage(d);
        }
        r
    }

    fn setup_storage_inner(&mut self, d: usize, found: (u8, Endpoint, Endpoint)) -> Result<(), &'static str> {
        let (iface, ei, eo) = found;
        let (slot, input, cfg_value, hid_dci) = {
            let dev = self.devs[d].as_ref().unwrap();
            (dev.slot, dev.input, dev.cfg.value, dev.hid.as_ref().map(|h| h.dci))
        };
        let buf = self.stor_buf()?;
        let pages = (self.pool.page(), self.pool.page(), self.pool.page());
        let (Ok(rin), Ok(rout), Ok(cmd)) = pages else {
            for p in [pages.0, pages.1, pages.2].into_iter().flatten() {
                self.pool.release(p);
            }
            self.stor_bufs[buf].3 = false;
            return Err("out of DMA memory");
        };
        let dci_in = (ei.address & 0x0F) as u32 * 2 + 1;
        let dci_out = (eo.address & 0x0F) as u32 * 2;
        let st = Storage {
            iface,
            dci_in,
            dci_out,
            ep_in: ei.address,
            ep_out: eo.address,
            mps_in: (ei.max_packet & 0x7FF).max(8),
            mps_out: (eo.max_packet & 0x7FF).max(8),
            ring_in: Ring::new_linked(rin.0, rin.1),
            ring_out: Ring::new_linked(rout.0, rout.1),
            ring_in_page: rin,
            ring_out_page: rout,
            cmd_page: cmd,
            buf,
            blocks: 0,
            bs: 0,
            tag: 0,
            name: [0; 40],
            nlen: 0,
            chan: 0,
            disk: None,
            attach_error: 0,
            reads: 0,
            errors: 0,
            needs_recovery: false,
        };
        // Kontekst wejściowy: slot (liczba kontekstów – największy DCI, także
        // endpointu HID, jeśli urządzenie ma oba) + oba endpointy bulk.
        unsafe { core::ptr::write_bytes(input.0 as *mut u8, 0, 4096) };
        let entries = dci_in.max(dci_out).max(hid_dci.unwrap_or(0));
        self.ctx_w(input.0, 0, 1, 1 | 1 << dci_in | 1 << dci_out);
        self.slot_ctx(input.0, d, entries);
        for (dci, ty, ring_pa, mps) in [(dci_in, 6u32, st.ring_in.pa, st.mps_in), (dci_out, 2u32, st.ring_out.pa, st.mps_out)] {
            let e = dci as u64 + 1;
            self.ctx_w(input.0, e, 1, 3 << 1 | ty << 3 | (mps as u32) << 16); // CErr 3, typ: bulk IN / OUT
            self.ctx_w(input.0, e, 2, ring_pa as u32 | 1);
            self.ctx_w(input.0, e, 3, (ring_pa >> 32) as u32);
            self.ctx_w(input.0, e, 4, 3072); // średnia długość TRB (bulk)
        }
        self.devs[d].as_mut().unwrap().stor = Some(st);
        self.slot_command(TRB_CONFIGURE_EP, slot, 0, [input.1 as u32, (input.1 >> 32) as u32, 0])
            .map_err(|_| "Configure Endpoint (bulk) failed")?;
        if hid_dci.is_none() {
            self.control(d, 0x00, 9, cfg_value as u16, 0, 0).map_err(|_| "Set Configuration failed")?;
        }
        // INQUIRY: tylko dysk (typ 0) – nie CD-ROM, nie inne urządzenia SCSI.
        let mut data = [0u8; 64];
        // M20.h: kilka prób – pendrive SuperSpeed za hubem USB 3 (Legion, port 5.1)
        // raz nie odpowiedział na pierwsze INQUIRY tuż po Configure Endpoint.
        let mut n = 0;
        let mut last = None;
        for attempt in 0..INQUIRY_TRIES {
            match self.scsi_in(d, &[0x12, 0, 0, 0, 36, 0], 36, &mut data) {
                Ok(k) => {
                    n = k;
                    last = None;
                    if attempt > 0 {
                        self.stor_retries += attempt as u64;
                    }
                    break;
                }
                Err(StorError::Xfer(XferError::Gone)) => return Err("device disconnected"),
                Err(e) => {
                    last = Some(e);
                    if attempt + 1 < INQUIRY_TRIES {
                        self.pause(200 * (attempt as u64 + 1));
                    }
                }
            }
        }
        if let Some(e) = last {
            self.stor_retries += INQUIRY_TRIES as u64;
            return Err(match e {
                StorError::Xfer(XferError::Stall) => "INQUIRY failed 4 times (STALL)",
                StorError::Xfer(XferError::Timeout) => "INQUIRY failed 4 times (no answer)",
                StorError::Xfer(XferError::Interrupted) => "INQUIRY failed 4 times (port change)",
                StorError::Xfer(_) => "INQUIRY failed 4 times (transfer error)",
                StorError::Failed => "INQUIRY failed 4 times (command failed)",
                StorError::Phase => "INQUIRY failed 4 times (bad CSW)",
                StorError::Refused => "INQUIRY refused",
            });
        }
        if n < 8 {
            return Err("INQUIRY: short answer");
        }
        if data[0] & 0x1F != 0 {
            return Err("not a direct-access disk (CD-ROM or other SCSI device)");
        }
        let mut name = [0u8; 40];
        let mut nlen = 0;
        for part in [&data[8..16], &data[16..32]] {
            let t = trim_ascii(part);
            if t.is_empty() {
                continue;
            }
            if nlen > 0 && nlen < name.len() {
                name[nlen] = b' ';
                nlen += 1;
            }
            for &c in t {
                if nlen < name.len() {
                    name[nlen] = if (0x20..0x7F).contains(&c) { c } else { b'?' };
                    nlen += 1;
                }
            }
        }
        // TEST UNIT READY: pendrive po podłączeniu zgłasza zwykle UNIT ATTENTION
        // (REQUEST SENSE ją kasuje); czytnik bez karty – nigdy gotowy.
        let mut ready = false;
        for _ in 0..10 {
            match self.bot(d, &[0, 0, 0, 0, 0, 0], 0, 0) {
                Ok(_) => {
                    ready = true;
                    break;
                }
                Err(StorError::Xfer(XferError::Gone)) => return Err("device disconnected"),
                Err(StorError::Failed) => {
                    let _ = self.scsi_in(d, &[0x03, 0, 0, 0, 18, 0], 18, &mut data);
                    self.pause(100);
                }
                Err(_) => self.pause(100),
            }
        }
        if !ready {
            return Err("medium not ready (no card in the reader?)");
        }
        let mut cap = None;
        for _ in 0..3 {
            match self.scsi_in(d, &[0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8, &mut data) {
                Ok(8) => {
                    cap = Some((u32::from_be_bytes([data[0], data[1], data[2], data[3]]), u32::from_be_bytes([data[4], data[5], data[6], data[7]])));
                    break;
                }
                Err(StorError::Failed) => {
                    let _ = self.scsi_in(d, &[0x03, 0, 0, 0, 18, 0], 18, &mut data);
                    self.pause(50);
                }
                _ => self.pause(50),
            }
        }
        let Some((last, bs)) = cap else { return Err("READ CAPACITY failed") };
        if last == u32::MAX {
            return Err("disk larger than 2 TiB (READ CAPACITY(16) not supported)");
        }
        if bs != 512 && bs != 4096 {
            return Err("unsupported block size (512 or 4096 only)");
        }
        let st = self.devs[d].as_mut().unwrap().stor.as_mut().unwrap();
        st.blocks = last as u64 + 1;
        st.bs = bs;
        st.name = name;
        st.nlen = nlen;
        Ok(())
    }

    /// Strony i bufor pendrive'a wracają do puli, kanał do jądra zamknięty
    /// (jądro: dysk znika).
    fn drop_storage(&mut self, d: usize) {
        let Some(st) = self.devs[d].as_mut().and_then(|x| x.stor.take()) else { return };
        self.release_storage(st);
    }

    fn release_storage(&mut self, st: Storage) {
        if st.chan != 0 {
            close(st.chan);
        }
        for p in [st.ring_in_page, st.ring_out_page, st.cmd_page] {
            self.pool.release(p);
        }
        self.stor_bufs[st.buf].3 = false;
    }

    /// Pendrive'y gotowe, a jeszcze nie w jądrze: kanał + blk_attach.
    fn attach_pending(&mut self) {
        if !self.blk {
            return;
        }
        let name = self.name;
        for d in 0..DEVS_MAX {
            let Some(dev) = self.devs[d].as_mut() else { continue };
            let port = dev.port;
            let Some(st) = dev.stor.as_mut() else { continue };
            if st.chan != 0 || st.attach_error != 0 {
                continue;
            }
            let Ok((mine, theirs)) = channel_create() else {
                st.attach_error = -12;
                continue;
            };
            let mut info = BlkInfo { blocks: st.blocks, block_size: st.bs, slots: STOR_SLOTS as u32, timeout_ms: 0, desc: [0; 40] };
            info.desc[..st.nlen].copy_from_slice(&st.name[..st.nlen]);
            let r = blk_attach(BLK, theirs, self.stor_bufs[st.buf].2, &info);
            close(theirs);
            if r < 0 {
                close(mine);
                st.attach_error = r;
                println!("{}: port {}: blk_attach failed: {}", name, port, strerror(r));
            } else {
                st.chan = mine;
                st.disk = Some(r as u64);
            }
        }
    }

    /// Żądania jądra z kanału pendrive'a (READ -> READ(10) do slotu bufora).
    fn serve_storage(&mut self, d: usize) {
        let mut msg = [0u8; 64];
        let mut info = RecvInfo::default();
        loop {
            let Some(chan) = self.devs[d].as_ref().and_then(|x| x.stor.as_ref()).map(|s| s.chan).filter(|&c| c != 0) else { return };
            let r = chan_recv(chan, &mut msg, CHAN_NONBLOCK, &mut info);
            if r == EPIPE || r == EMSGSIZE {
                // Jądro odłączyło dysk (3 timeouty) – bez ponownej rejestracji.
                if let Some(st) = self.devs[d].as_mut().and_then(|x| x.stor.as_mut()) {
                    close(st.chan);
                    st.chan = 0;
                    st.disk = None;
                    st.attach_error = EPIPE;
                }
                return;
            }
            if r < 0 {
                return;
            }
            let (id, status, count) = self.storage_request(d, &msg[..r as usize]);
            let mut rep = [0u8; 16];
            rep[0..4].copy_from_slice(&id.to_le_bytes());
            rep[4..8].copy_from_slice(&status.to_le_bytes());
            rep[8..12].copy_from_slice(&count.to_le_bytes());
            chan_send(chan, &rep, CHAN_NONBLOCK);
        }
    }

    /// Jedno żądanie: (id, status, bloki).
    fn storage_request(&mut self, d: usize, m: &[u8]) -> (u32, i32, u32) {
        let le32 = |i: usize| u32::from_le_bytes([m[i], m[i + 1], m[i + 2], m[i + 3]]);
        if m.len() < 24 {
            self.stor_requests_bad += 1;
            return (0, EIO_REPLY, 0);
        }
        let (id, op, n, slot) = (le32(0), le32(4), le32(16), le32(20));
        let lba = le32(8) as u64 | (le32(12) as u64) << 32;
        let Some((blocks, bs, buf)) = self.devs[d].as_ref().and_then(|x| x.stor.as_ref()).map(|s| (s.blocks, s.bs as u64, s.buf)) else {
            return (id, ENODEV_REPLY, 0);
        };
        let end = lba.checked_add(n as u64);
        if op != 1 || slot as usize >= STOR_SLOTS || n == 0 || n as u64 * bs > STOR_SLOT || end.map_or(true, |e| e > blocks || e > 1 << 32) {
            self.stor_requests_bad += 1;
            return (id, EIO_REPLY, 0);
        }
        let pa = self.stor_bufs[buf].1 + slot as u64 * STOR_SLOT;
        let l = lba as u32;
        let cdb = [0x28, 0, (l >> 24) as u8, (l >> 16) as u8, (l >> 8) as u8, l as u8, 0, (n >> 8) as u8, n as u8, 0];
        let len = (n as u64 * bs) as usize;
        let r = self.bot(d, &cdb, len, pa);
        let st = self.devs[d].as_mut().and_then(|x| x.stor.as_mut());
        match r {
            Ok(got) if got == len => {
                if let Some(st) = st {
                    st.reads += 1;
                }
                self.stor_reads += 1;
                self.stor_bytes += len as u64;
                (id, 0, n)
            }
            Err(StorError::Xfer(XferError::Gone)) => (id, ENODEV_REPLY, 0),
            _ => {
                if let Some(st) = st {
                    st.errors += 1;
                }
                self.stor_errors += 1;
                (id, EIO_REPLY, 0)
            }
        }
    }

    // --------------------------------------------------------------
    // M20.d: huby USB 2 i USB 3
    // --------------------------------------------------------------

    /// Interfejs huba (klasa 09) z endpointem przerwań IN (mapa zmian portów).
    fn hub_interface(cfg: &Config) -> Option<Endpoint> {
        cfg.ifaces[..cfg.n_ifaces]
            .iter()
            .filter(|f| f.class == 9)
            .find_map(|f| f.eps[..f.n_eps].iter().find(|e| e.kind() == 3 && e.is_in()).copied())
    }

    /// Hub: Configure Endpoint + Set Configuration, Set Hub Depth (USB 3),
    /// deskryptor huba, drugi Configure Endpoint (pola huba w kontekście slotu),
    /// zasilanie portów, TRB na mapę zmian.  Porty sprawdza potem service_hubs.
    fn setup_hub(&mut self, d: usize) -> Result<(), &'static str> {
        let (found, depth, speed, slot, input, cfg_value, configured) = {
            let dev = self.devs[d].as_ref().unwrap();
            (Self::hub_interface(&dev.cfg), dev.loc.depth, dev.speed, dev.slot, dev.input, dev.cfg.value, dev.hid.is_some() || dev.stor.is_some())
        };
        let Some(ep) = found else { return Ok(()) };
        if depth >= HUB_DEPTH_MAX {
            return Err("hub too deep (5 levels of hubs)");
        }
        let usb3 = speed >= 4;
        let dci = (ep.address & 0x0F) as u32 * 2 + 1;
        let mps = (ep.max_packet & 0x7FF).clamp(1, 64);
        let interval = if speed >= 3 {
            (ep.interval.clamp(1, 16) - 1) as u32
        } else {
            let v = (ep.interval.max(1) as u32) * 8;
            (31 - v.leading_zeros()).clamp(3, 10)
        };
        let (Ok(ring_page), Ok(data_page)) = (self.pool.page(), self.pool.page()) else {
            return Err("out of DMA memory");
        };
        let hub = Hub {
            usb3,
            nports: 0,
            think: 0,
            power_ms: 0,
            dci,
            mps,
            ring: Ring::new_linked(ring_page.0, ring_page.1),
            ring_page,
            data_page,
            ports: [Port::Free; HUB_PORTS_MAX],
            pending: 0,
            last_error: [""; HUB_PORTS_MAX],
            errors: 0,
        };
        let ring_pa = hub.ring.pa;
        self.devs[d].as_mut().unwrap().hub = Some(hub);
        let r = self.setup_hub_inner(d, slot, input, dci, mps, interval, ring_pa, cfg_value, configured, usb3, depth);
        if r.is_err() {
            if let Some(h) = self.devs[d].as_mut().and_then(|x| x.hub.take()) {
                self.pool.release(h.ring_page);
                self.pool.release(h.data_page);
            }
        }
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn setup_hub_inner(
        &mut self,
        d: usize,
        slot: u32,
        input: (u64, u64),
        dci: u32,
        mps: u16,
        interval: u32,
        ring_pa: u64,
        cfg_value: u8,
        configured: bool,
        usb3: bool,
        depth: u32,
    ) -> Result<(), &'static str> {
        // 1. Endpoint mapy zmian (kontekst slotu jeszcze bez pól huba – nie znamy
        // liczby portów) + Set Configuration.
        unsafe { core::ptr::write_bytes(input.0 as *mut u8, 0, 4096) };
        self.ctx_w(input.0, 0, 1, 1 | 1 << dci);
        self.slot_ctx_plain(input.0, d, dci);
        let e = dci as u64 + 1;
        self.ctx_w(input.0, e, 0, interval << 16);
        self.ctx_w(input.0, e, 1, 3 << 1 | 7 << 3 | (mps as u32) << 16); // CErr 3, typ: przerwania IN
        self.ctx_w(input.0, e, 2, ring_pa as u32 | 1);
        self.ctx_w(input.0, e, 3, (ring_pa >> 32) as u32);
        self.ctx_w(input.0, e, 4, mps as u32 | (mps as u32) << 16);
        self.slot_command(TRB_CONFIGURE_EP, slot, 0, [input.1 as u32, (input.1 >> 32) as u32, 0])
            .map_err(|_| "Configure Endpoint (hub) failed")?;
        if !configured {
            self.control(d, 0x00, 9, cfg_value as u16, 0, 0).map_err(|_| "Set Configuration failed")?;
        }
        // 2. USB 3: głębokość huba (route string dla urządzeń za nim).
        if usb3 {
            self.control(d, 0x20, 12, depth as u16, 0, 0).map_err(|_| "Set Hub Depth failed")?;
        }
        // 3. Deskryptor huba: liczba portów, cechy (TT think time), zasilanie.
        let ty: u8 = if usb3 { 0x2A } else { 0x29 };
        let n = self.control(d, 0xA0, 6, (ty as u16) << 8, 0, 12).map_err(|_| "hub descriptor failed")?;
        let mut b = [0u8; 12];
        b[..n.min(12)].copy_from_slice(self.buf(n.min(12)));
        if n < 7 || b[1] != ty || (b[0] as usize) < 7 {
            return Err("bad hub descriptor");
        }
        if b[2] == 0 {
            return Err("hub with 0 ports");
        }
        let nports = (b[2] as u32).min(HUB_PORTS_MAX as u32);
        let chars = u16::from_le_bytes([b[3], b[4]]) as u32;
        let power_ms = (b[5] as u64 * 2).clamp(20, 1000);
        {
            let h = self.devs[d].as_mut().unwrap().hub.as_mut().unwrap();
            h.nports = nports;
            h.think = if usb3 { 0 } else { (chars >> 5) & 3 };
            h.power_ms = power_ms;
        }
        // 4. Kontekst slotu z polami huba (bit Hub, liczba portów, TT think time).
        unsafe { core::ptr::write_bytes(input.0 as *mut u8, 0, 4096) };
        self.ctx_w(input.0, 0, 1, 1);
        self.slot_ctx(input.0, d, dci);
        self.slot_command(TRB_CONFIGURE_EP, slot, 0, [input.1 as u32, (input.1 >> 32) as u32, 0])
            .map_err(|_| "Configure Endpoint (hub slot fields) failed")?;
        // 5. Zasilanie portów i czas na jego ustalenie.
        for p in 1..=nports {
            let _ = self.control(d, 0x23, 3, HUB_PORT_POWER, p as u16, 0);
        }
        self.pause(power_ms + 10);
        // 6. TRB czekające na mapę zmian; na start sprawdzamy wszystkie porty.
        let h = self.devs[d].as_mut().unwrap().hub.as_mut().unwrap();
        for _ in 0..2 {
            Self::hub_queue(h);
        }
        h.pending = ((1u32 << (nports + 1)) - 1) & !1;
        wr32(self.db + 4 * slot as u64, dci);
        Ok(())
    }

    /// Kontekst slotu bez pól huba (pierwszy Configure Endpoint huba).
    fn slot_ctx_plain(&self, input: u64, d: usize, entries: u32) {
        let dev = self.devs[d].as_ref().unwrap();
        let l = &dev.loc;
        self.ctx_w(input, 1, 0, entries << 27 | dev.speed << 20 | (l.route & 0xF_FFFF));
        self.ctx_w(input, 1, 1, dev.port << 16);
        self.ctx_w(input, 1, 2, l.tt.0 | l.tt.1 << 8);
    }

    fn hub_queue(h: &mut Hub) {
        let pa = h.data_page.1 + (h.ring.idx as u64 % 16) * HID_BUF;
        h.ring.push([pa as u32, (pa >> 32) as u32, h.mps as u32], TRB_NORMAL << 10 | TRB_IOC | TRB_ISP);
    }

    /// Mapa zmian od huba (z poll_events): porty do sprawdzenia w pętli głównej.
    fn hub_event(&mut self, ptr: u64, code: u32, rest: u32, slot: u32, ep: u32) {
        let Some(d) = self.devs.iter().position(|x| matches!(x, Some(dev) if dev.slot == slot && matches!(&dev.hub, Some(h) if h.dci == ep)))
        else {
            return;
        };
        let db = self.db;
        let h = self.devs[d].as_mut().unwrap().hub.as_mut().unwrap();
        if ptr < h.ring.pa || ptr >= h.ring.pa + 4096 {
            return;
        }
        if !matches!(code, CC_SUCCESS | CC_SHORT) {
            h.errors += 1;
            self.hub_errors += 1;
            return;
        }
        let idx = (ptr - h.ring.pa) / 16;
        let len = (h.mps as u32).saturating_sub(rest).min(4) as usize;
        let mut bits = 0u32;
        for i in 0..len {
            let b = unsafe { ((h.data_page.0 + (idx % 16) * HID_BUF) as *const u8).add(i).read_volatile() };
            bits |= (b as u32) << (8 * i);
        }
        h.pending |= bits;
        Self::hub_queue(h);
        wr32(db + 4 * slot as u64, ep);
        self.hub_events += 1;
    }

    /// GET_STATUS portu huba: (stan, zmiany).
    fn hub_port_status(&mut self, d: usize, p: u32) -> Result<(u16, u16), XferError> {
        let n = self.control(d, 0xA3, 0, 0, p as u16, 4)?;
        if n < 4 {
            return Err(XferError::Code);
        }
        let b = self.buf(4);
        Ok((u16::from_le_bytes([b[0], b[1]]), u16::from_le_bytes([b[2], b[3]])))
    }

    /// Kasuje bity zmian portu (CLEAR_FEATURE C_PORT_*).
    fn hub_clear_changes(&mut self, d: usize, p: u32, ch: u16, usb3: bool) {
        for bit in 0..8u16 {
            if ch & (1 << bit) == 0 {
                continue;
            }
            let feature = match (usb3, bit) {
                (false, 0..=4) => 16 + bit,
                (true, 0) => 16,
                (true, 3) => 19,
                (true, 4) => 20,
                (true, 5) => 29,
                (true, 6) => 25,
                (true, 7) => 26,
                _ => continue,
            };
            let _ = self.control(d, 0x23, 1, feature, p as u16, 0);
        }
    }

    /// Reset portu huba; wynik: stan portu po resecie (włączony).
    fn hub_port_reset(&mut self, d: usize, p: u32, usb3: bool) -> Result<u16, &'static str> {
        self.control(d, 0x23, 3, HUB_PORT_RESET, p as u16, 0).map_err(|_| "hub port reset request failed")?;
        let t0 = uptime_ms();
        loop {
            self.pause(10);
            let (st, ch) = self.hub_port_status(d, p).map_err(|_| "hub port status failed")?;
            if st & 1 == 0 {
                return Err("device disconnected during port reset");
            }
            if ch & (1 << 4) != 0 || (st & (1 << 4) == 0 && uptime_ms() - t0 >= 20) {
                self.hub_clear_changes(d, p, ch, usb3);
                break;
            }
            if uptime_ms() - t0 > HUB_RESET_MS {
                return Err("hub port reset timed out");
            }
        }
        self.pause(10); // powrót urządzenia po resecie
        let (st, _) = self.hub_port_status(d, p).map_err(|_| "hub port status failed")?;
        if st & 2 == 0 {
            return Err("hub port not enabled after reset");
        }
        Ok(st)
    }

    /// Port huba -> urządzenie: reset, prędkość, położenie (route, TT), enumeracja.
    fn enumerate_hub_port(&mut self, d: usize, p: u32) -> Result<usize, &'static str> {
        let t0 = uptime_ms();
        let (usb3, ploc, pspeed, pslot, root) = {
            let dev = self.devs[d].as_ref().ok_or("hub gone")?;
            let h = dev.hub.as_ref().ok_or("hub gone")?;
            (h.usb3, dev.loc, dev.speed, dev.slot, dev.port)
        };
        if ploc.depth >= HUB_DEPTH_MAX {
            return Err("too deep (5 levels of hubs)");
        }
        let st = self.hub_port_reset(d, p, usb3)?;
        // Prędkość: hub USB 3 – SuperSpeed; USB 2 – bity low (9) / high speed (10).
        let speed = if usb3 {
            4
        } else if st & (1 << 9) != 0 {
            2
        } else if st & (1 << 10) != 0 {
            3
        } else {
            1
        };
        self.last_speed = speed;
        let mut loc = Loc {
            route: ploc.route | (p.min(15) << (4 * ploc.depth)),
            depth: ploc.depth + 1,
            path: ploc.path,
            tt: (0, 0),
            parent: Some(d),
            hub_port: p,
        };
        loc.path[ploc.depth as usize] = p as u8;
        // Low / full speed: TT najbliższego huba high speed.
        if speed <= 2 {
            loc.tt = if pspeed == 3 { (pslot, p) } else { ploc.tt };
        }
        self.enumerate_at(root, speed, loc, t0)
    }

    fn try_enumerate_hub(&mut self, d: usize, p: u32, attempt: u32) -> Port {
        self.last_speed = 0;
        match self.enumerate_hub_port(d, p) {
            Ok(c) => {
                let mut t = Text::new();
                self.device_line(&mut t, c);
                write(1, t.as_bytes());
                Port::Working(c)
            }
            Err(e) => {
                self.failures += 1;
                let mut t = Text::new();
                self.port_name(&mut t, d, p);
                if let Some(h) = self.devs[d].as_mut().and_then(|x| x.hub.as_mut()) {
                    h.last_error[p as usize - 1] = e;
                }
                let name = core::str::from_utf8(t.as_bytes()).unwrap_or("?");
                let sp = if self.last_speed == 0 { "speed unknown" } else { speed_name(self.last_speed) };
                if attempt >= TRIES {
                    println!("{}: enumeration failed {} times ({}, {}) - ignoring the port until it is unplugged", name, attempt, e, sp);
                    Port::Ignored
                } else {
                    println!("{}: enumeration failed ({}, {}), retry {}/{}", name, e, sp, attempt, TRIES);
                    Port::Failed(attempt, uptime_ms() + RETRY_MS)
                }
            }
        }
    }

    /// "usb2 port 1.3" – port `p` huba `d`.
    fn port_name(&self, out: &mut Text, d: usize, p: u32) {
        use core::fmt::Write;
        if let Some(dev) = self.devs[d].as_ref() {
            let _ = write!(out, "{} port {}.{}", self.name, PortPath(dev.port, dev.loc), p);
        }
    }

    /// Porty hubów: zmiany zgłoszone mapą, terminy debounce / ponownych prób.
    /// Zwraca czas (ms) do najbliższego terminu.
    fn service_hubs(&mut self) -> u64 {
        let mut next = 1000u64;
        for d in 0..DEVS_MAX {
            let Some((nports, usb3, slot, dci, errors)) = self.devs[d].as_ref().and_then(|x| x.hub.as_ref().map(|h| (h.nports, h.usb3, x.slot, h.dci, h.errors))) else {
                continue;
            };
            if errors > 0 {
                // Endpoint mapy zmian po błędzie: reset, kolejka, nowe TRB, wszystkie porty do sprawdzenia.
                let deq = self.devs[d].as_ref().unwrap().hub.as_ref().unwrap().ring.enqueue_ptr();
                let _ = self.slot_command(TRB_RESET_EP, slot, dci << 16, [0; 3]);
                let _ = self.slot_command(TRB_SET_DEQUEUE, slot, dci << 16, [deq as u32, (deq >> 32) as u32, 0]);
                let h = self.devs[d].as_mut().unwrap().hub.as_mut().unwrap();
                h.errors = 0;
                for _ in 0..2 {
                    Self::hub_queue(h);
                }
                h.pending |= ((1u32 << (nports + 1)) - 1) & !1;
                wr32(self.db + 4 * slot as u64, dci);
            }
            // Bit 0: zmiana samego huba (zasilanie / przeciążenie) – skasuj.
            if self.devs[d].as_ref().and_then(|x| x.hub.as_ref()).map_or(false, |h| h.pending & 1 != 0) {
                self.devs[d].as_mut().unwrap().hub.as_mut().unwrap().pending &= !1;
                if let Ok(n) = self.control(d, 0xA0, 0, 0, 0, 4) {
                    if n >= 4 {
                        let ch = u16::from_le_bytes([self.buf(4)[2], self.buf(4)[3]]);
                        for f in 0..2u16 {
                            if ch & (1 << f) != 0 {
                                let _ = self.control(d, 0x20, 1, f, 0, 0);
                            }
                        }
                    }
                }
            }
            for p in 1..=nports {
                let i = p as usize - 1;
                let now = uptime_ms();
                let Some((state, pend)) = self.devs[d].as_ref().and_then(|x| x.hub.as_ref()).map(|h| (h.ports[i], h.pending & (1 << p) != 0)) else {
                    break; // hub zniknął w trakcie
                };
                let due = pend || matches!(state, Port::Debounce(t) | Port::Failed(_, t) if now >= t);
                if !due {
                    if let Port::Debounce(t) | Port::Failed(_, t) = state {
                        next = next.min(t.saturating_sub(now).max(1));
                    }
                    continue;
                }
                self.devs[d].as_mut().unwrap().hub.as_mut().unwrap().pending &= !(1 << p);
                let Ok((st, ch)) = self.hub_port_status(d, p) else {
                    self.hub_errors += 1;
                    continue;
                };
                self.hub_clear_changes(d, p, ch, usb3);
                let ccs = st & 1 != 0;
                let replug = ch & 1 != 0;
                let new = match state {
                    Port::Free if ccs => Port::Debounce(now + DEBOUNCE_MS),
                    Port::Free => Port::Free,
                    Port::Debounce(_) | Port::Failed(..) | Port::Ignored if !ccs => Port::Free,
                    Port::Debounce(t) if now < t => state,
                    Port::Debounce(_) => self.try_enumerate_hub(d, p, 1),
                    Port::Failed(_, t) if now < t => state,
                    Port::Failed(n, _) => self.try_enumerate_hub(d, p, n + 1),
                    Port::Ignored => state,
                    Port::Working(c) if !ccs || replug => {
                        let mut t = Text::new();
                        self.port_name(&mut t, d, p);
                        self.detach(c);
                        println!("{}: device disconnected", core::str::from_utf8(t.as_bytes()).unwrap_or("?"));
                        if ccs { Port::Debounce(now + DEBOUNCE_MS) } else { Port::Free }
                    }
                    Port::Working(_) => state,
                };
                let Some(h) = self.devs[d].as_mut().and_then(|x| x.hub.as_mut()) else { break };
                h.ports[i] = new;
                if let Port::Debounce(t) | Port::Failed(_, t) = new {
                    next = next.min(t.saturating_sub(uptime_ms()).max(1));
                }
            }
        }
        next
    }

    /// Porty hubów czekają na coś (start usbd: enumeracja do 5 s).
    fn hubs_busy(&self) -> bool {
        self.devs.iter().flatten().filter_map(|x| x.hub.as_ref()).any(|h| {
            h.pending != 0 || h.ports[..h.nports as usize].iter().any(|p| matches!(p, Port::Debounce(_) | Port::Failed(..)))
        })
    }

    fn hub_count(&self) -> usize {
        self.devs.iter().filter(|x| matches!(x, Some(d) if d.hub.is_some())).count()
    }

    /// Porty huba `d` w lsusb (rekurencyjnie – huby za hubami).
    fn list_hub(&self, out: &mut Text, d: usize) {
        use core::fmt::Write;
        let Some(dev) = self.devs[d].as_ref() else { return };
        let Some(h) = dev.hub.as_ref() else { return };
        for p in 1..=h.nports {
            let i = p as usize - 1;
            let at = PortPath(dev.port, dev.loc);
            match h.ports[i] {
                Port::Working(c) => {
                    self.device_line(out, c);
                    self.list_hub(out, c);
                }
                Port::Failed(n, _) => {
                    let _ = writeln!(out, "{} port {}.{}: enumeration failed ({}), attempt {}/{}", self.name, at, p, h.last_error[i], n, TRIES);
                }
                Port::Ignored => {
                    let _ = writeln!(out, "{} port {}.{}: ignored after {} failures ({})", self.name, at, p, TRIES, h.last_error[i]);
                }
                Port::Debounce(_) => {
                    let _ = writeln!(out, "{} port {}.{}: device connected, waiting", self.name, at, p);
                }
                Port::Free => {}
            }
        }
    }

    fn storage_count(&self) -> (usize, usize) {
        let st = self.devs.iter().filter_map(|x| x.as_ref().and_then(|d| d.stor.as_ref()));
        let n = st.clone().count();
        (n, st.filter(|s| s.disk.is_some()).count())
    }

    fn hid_count(&self) -> usize {
        self.devs.iter().filter(|x| matches!(x, Some(d) if d.hid.is_some())).count()
    }

    /// Odłączenie / błąd: Disable Slot, strony wracają do puli.
    fn detach(&mut self, d: usize) {
        // M20.d: hub – najpierw wszystko, co za nim (rekurencyjnie).
        let children: [Option<usize>; HUB_PORTS_MAX] = match self.devs[d].as_ref().and_then(|x| x.hub.as_ref()) {
            Some(h) => core::array::from_fn(|i| if let Port::Working(c) = h.ports[i] { Some(c) } else { None }),
            None => [None; HUB_PORTS_MAX],
        };
        for c in children.into_iter().flatten() {
            if c != d {
                self.detach(c);
            }
        }
        let Some(mut dev) = self.devs[d].take() else { return };
        if let Some(h) = dev.hub.take() {
            self.pool.release(h.ring_page);
            self.pool.release(h.data_page);
        }
        if let Some(st) = dev.stor.take() {
            self.release_storage(st);
        }
        if let Some(h) = &dev.hid {
            // Klawisze tego urządzenia puszczone (jądro puszcza je samo dopiero po końcu usbd).
            if !h.mouse && self.input {
                let mut ev = [[0u8; 8]; 16];
                let mut n = 0;
                for b in 0..8u8 {
                    if h.prev[0] >> b & 1 != 0 {
                        ev[n] = key_event(0xE0 + b, false);
                        n += 1;
                    }
                }
                for &k in &h.prev[2..8] {
                    if k > 3 {
                        ev[n] = key_event(k, false);
                        n += 1;
                    }
                }
                if n > 0 {
                    let _ = input_inject(INPUT, &ev[..n]);
                }
            }
            self.pool.release(h.ring_page);
            self.pool.release(h.data_page);
        }
        let _ = self.slot_command(TRB_DISABLE_SLOT, dev.slot, 0, [0; 3]);
        unsafe { ((self.dcbaa + dev.slot as u64 * 8) as *mut u64).write_volatile(0) };
        for p in [dev.input, dev.output, dev.ring_page] {
            self.pool.release(p);
        }
    }

    /// Maszyna stanów portów; zwraca czas (ms) do następnego terminu.
    fn service_ports(&mut self) -> u64 {
        let now = uptime_ms();
        let mut next = 1000u64;
        for port in 1..=self.ports() {
            let i = port as usize - 1;
            let ccs = rd32(self.portsc(port)) & PORT_CCS != 0;
            let replug = core::mem::replace(&mut self.csc[i], false);
            self.dirty[i] = false;
            let state = self.ports[i];
            let new = match state {
                Port::Free if ccs => Port::Debounce(now + DEBOUNCE_MS),
                Port::Free => Port::Free,
                Port::Debounce(_) | Port::Failed(..) | Port::Ignored if !ccs => Port::Free,
                Port::Debounce(t) if now < t => state,
                Port::Debounce(_) => self.try_enumerate(port, 1),
                Port::Failed(_, t) if now < t => state,
                Port::Failed(n, _) => self.try_enumerate(port, n + 1),
                Port::Ignored => state,
                Port::Working(d) if !ccs || replug => {
                    self.detach(d);
                    println!("{}: port {}: device disconnected", self.name, port);
                    if ccs { Port::Debounce(now + DEBOUNCE_MS) } else { Port::Free }
                }
                Port::Working(_) => state,
            };
            self.ports[i] = new;
            match new {
                Port::Debounce(t) | Port::Failed(_, t) => next = next.min(t.saturating_sub(uptime_ms()).max(1)),
                _ => {}
            }
        }
        next
    }

    fn try_enumerate(&mut self, port: u32, attempt: u32) -> Port {
        match self.enumerate(port) {
            Ok(d) => {
                let mut t = Text::new();
                self.device_line(&mut t, d);
                write(1, t.as_bytes());
                Port::Working(d)
            }
            Err(e) => {
                self.failures += 1;
                self.last_error[port as usize - 1] = e;
                if attempt >= TRIES {
                    println!("{}: port {}: enumeration failed {} times ({}) - ignoring the port until it is unplugged", self.name, port, attempt, e);
                    Port::Ignored
                } else {
                    println!("{}: port {}: enumeration failed ({}), retry {}/{}", self.name, port, e, attempt, TRIES);
                    Port::Failed(attempt, uptime_ms() + RETRY_MS)
                }
            }
        }
    }

    fn connected(&self) -> u32 {
        (1..=self.ports()).filter(|&p| rd32(self.portsc(p)) & PORT_CCS != 0).count() as u32
    }

    fn working(&self) -> usize {
        self.devs.iter().filter(|d| d.is_some()).count()
    }

    fn stop(&self) {
        self.op_wr(USBCMD, self.op_rd(USBCMD) & !(CMD_RUN | CMD_INTE));
        let _ = wait_until(|| self.op_rd(USBSTS) & STS_HCH != 0);
    }

    /// Linia urządzenia (lsusb i konsola).
    fn device_line(&self, out: &mut Text, d: usize) {
        use core::fmt::Write;
        let Some(dev) = self.devs[d].as_ref() else { return };
        let s = &dev.desc;
        let _ = write!(
            out,
            "{} port {}: {:04x}:{:04x} {}, USB {:x}.{:02x}, address {}, {}, class {:02x}/{:02x}/{:02x}, interfaces",
            self.name,
            PortPath(dev.port, dev.loc),
            s.vendor,
            s.product,
            speed_name(dev.speed),
            s.usb >> 8,
            s.usb & 0xFF,
            dev.addr,
            kind_name(s, &dev.cfg),
            s.class,
            s.subclass,
            s.protocol
        );
        for f in &dev.cfg.ifaces[..dev.cfg.n_ifaces] {
            let _ = write!(out, " {:02x}/{:02x}/{:02x}", f.class, f.subclass, f.protocol);
        }
        if dev.cfg.truncated {
            let _ = write!(out, " +more");
        }
        let m = core::str::from_utf8(&dev.manufacturer[..dev.mlen]).unwrap_or("?");
        let p = core::str::from_utf8(&dev.product[..dev.plen]).unwrap_or("?");
        let _ = write!(out, ", \"{}\" \"{}\"", m, p);
        if let Some(h) = &dev.hid {
            let _ = write!(out, ", {} ready ({})", if h.mouse { "mouse" } else { "keyboard" }, if self.input { "input to kernel" } else { "no INPUT handle" });
        } else if !dev.hid_error.is_empty() {
            let _ = write!(out, ", HID setup failed: {}", dev.hid_error);
        }
        if let Some(st) = &dev.stor {
            let name = core::str::from_utf8(&st.name[..st.nlen]).unwrap_or("?");
            let mib = st.blocks * st.bs as u64 / (1024 * 1024);
            match st.disk {
                Some(n) => {
                    let mut nb = [0u8; 8];
                    let _ = write!(out, ", disk {} ready ({} MiB, {}-byte blocks, read-only, \"{}\")", disk_name(n, &mut nb), mib, st.bs, name);
                }
                None if !self.blk => {
                    let _ = write!(out, ", storage ready ({} MiB, \"{}\", no BLK handle)", mib, name);
                }
                None if st.attach_error != 0 => {
                    let _ = write!(out, ", storage ({} MiB) not attached: {}", mib, strerror(st.attach_error));
                }
                None => {
                    let _ = write!(out, ", storage ({} MiB) attaching", mib);
                }
            }
        } else if !dev.stor_error.is_empty() {
            let _ = write!(out, ", storage setup failed: {}", dev.stor_error);
        }
        if let Some(h) = &dev.hub {
            let _ = write!(out, ", hub ready ({} ports, USB {})", h.nports, if h.usb3 { 3 } else { 2 });
        } else if !dev.hub_error.is_empty() {
            let _ = write!(out, ", hub setup failed: {}", dev.hub_error);
        }
        let _ = write!(out, ", ready in {} ms", dev.enum_ms);
        let _ = writeln!(out);
    }

    /// Opis dla `status` (i dla konsoli przy starcie).
    fn describe(&self, out: &mut Text, machine: bool) {
        use core::fmt::Write;
        let _ = writeln!(
            out,
            "{}: xHCI {:04x}:{:04x} v{:x}.{:02x}, {} slots ({} used), {} ports (USB2 {}, USB3 {}), scratchpad {}, {}-bit DMA, {}-byte contexts, BIOS: {}",
            self.name,
            self.info.vendor,
            self.info.device,
            self.version >> 8,
            self.version & 0xFF,
            self.max_slots,
            self.slots,
            self.max_ports,
            Range(self.usb2),
            Range(self.usb3),
            self.scratch,
            if self.ac64 { 64 } else { 32 },
            self.ctx,
            self.bios
        );
        if !machine {
            return;
        }
        self.list(out);
        let _ = writeln!(
            out,
            "usbd-status name={} noops={} polled={} irqs={} events={} port_events={} ports={} connected={} devices={} enumerated={} failures={} errors={} input={} hid={} hid_reports={} hid_events={} hid_errors={} hubs={} hub_events={} hub_errors={} blk={} storage={} disks={} stor_reads={} stor_bytes={} stor_errors={} stor_bad={} stor_retries={} enum_count={} enum_avg_ms={} enum_max_ms={}",
            self.name,
            self.noops,
            self.polled,
            self.irqs,
            self.events,
            self.port_events,
            self.max_ports,
            self.connected(),
            self.working(),
            self.enumerated,
            self.failures,
            self.errors,
            self.input as u8,
            self.hid_count(),
            self.hid_reports,
            self.hid_events,
            self.hid_errors,
            self.hub_count(),
            self.hub_events,
            self.hub_errors,
            self.blk as u8,
            self.storage_count().0,
            self.storage_count().1,
            self.stor_reads,
            self.stor_bytes,
            self.stor_errors,
            self.stor_requests_bad,
            self.stor_retries,
            self.enum_count,
            self.enum_sum / self.enum_count.max(1),
            self.enum_max
        );
    }

    /// Urządzenia i porty z błędem.
    fn list(&self, out: &mut Text) {
        use core::fmt::Write;
        for port in 1..=self.ports() {
            match self.ports[port as usize - 1] {
                Port::Working(d) => {
                    self.device_line(out, d);
                    self.list_hub(out, d);
                }
                Port::Failed(n, _) => {
                    let _ = writeln!(out, "{} port {}: enumeration failed ({}), attempt {}/{}", self.name, port, self.last_error[port as usize - 1], n, TRIES);
                }
                Port::Ignored => {
                    let _ = writeln!(out, "{} port {}: ignored after {} failures ({})", self.name, port, TRIES, self.last_error[port as usize - 1]);
                }
                Port::Debounce(_) => {
                    let _ = writeln!(out, "{} port {}: device connected, waiting", self.name, port);
                }
                Port::Free => {}
            }
        }
    }
}

/// v0.27.1: Address Device nie wyszło – z kodem zakończenia xHCI (diagnostyka
/// z prawdziwego sprzętu: Legion, port huba 1.1).
fn address_error(cc: u32) -> &'static str {
    match cc {
        0 => "Address Device failed: command timeout",
        3 => "Address Device failed: data buffer error",
        4 => "Address Device failed: USB transaction error",
        5 => "Address Device failed: TRB error",
        6 => "Address Device failed: STALL",
        11 => "Address Device failed: slot not enabled",
        17 => "Address Device failed: parameter error",
        19 => "Address Device failed: context state error",
        22 => "Address Device failed: split transaction error",
        _ => "Address Device failed: other completion code",
    }
}

fn speed_name(speed: u32) -> &'static str {
    match speed {
        1 => "full speed",
        2 => "low speed",
        3 => "high speed",
        4 => "SuperSpeed",
        5 => "SuperSpeed+",
        _ => "unknown speed",
    }
}

/// Czym jest urządzenie (dla ludzi): klasa urządzenia albo pierwszego interfejsu.
fn kind_name(d: &DeviceDesc, c: &Config) -> &'static str {
    let (class, sub, proto) = if d.class != 0 && d.class != 0xEF {
        (d.class, d.subclass, d.protocol)
    } else if c.n_ifaces > 0 {
        let f = &c.ifaces[0];
        (f.class, f.subclass, f.protocol)
    } else {
        (0, 0, 0)
    };
    match (class, sub, proto) {
        (3, _, 1) => "keyboard",
        (3, _, 2) => "mouse",
        (3, ..) => "HID",
        (8, ..) => "mass storage",
        (9, ..) => "hub",
        (0xE0, 1, 1) => "Bluetooth",
        (0xE0, ..) => "wireless",
        (0x0E, ..) => "video",
        (1, ..) => "audio",
        (2, ..) | (0x0A, ..) => "communication",
        (0x0B, ..) => "smart card",
        (0x0D, ..) => "security",
        (0xFF, ..) => "vendor-specific",
        _ => "device",
    }
}

/// Bez spacji (i zer) na początku i końcu – pola INQUIRY są dopełniane spacjami.
fn trim_ascii(b: &[u8]) -> &[u8] {
    let mut s = 0;
    let mut e = b.len();
    while s < e && matches!(b[s], b' ' | 0) {
        s += 1;
    }
    while e > s && matches!(b[e - 1], b' ' | 0) {
        e -= 1;
    }
    &b[s..e]
}

/// M20.d: „3” (port kontrolera) albo „3.2.1” (porty hubów po drodze).
struct PortPath(u32, Loc);

impl core::fmt::Display for PortPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)?;
        for i in 0..self.1.depth as usize {
            write!(f, ".{}", self.1.path[i])?;
        }
        Ok(())
    }
}

struct Range((u32, u32));

impl core::fmt::Display for Range {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            (_, 0) => write!(f, "-"),
            (a, n) => write!(f, "{}-{}", a, a + n - 1),
        }
    }
}

/// Tekst w buforze (bez alokacji; komunikat kanału ≤ 4 KiB).
struct Text {
    buf: [u8; MSG_MAX],
    len: usize,
}

impl Text {
    fn new() -> Text {
        Text { buf: [0; MSG_MAX], len: 0 }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl core::fmt::Write for Text {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let b = s.as_bytes();
        let n = b.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
        Ok(())
    }
}

/// Przejęcie od BIOS-u (USB Legacy Support) i lista portów USB 2 / USB 3.
fn extended_caps(hc: &mut Hc, bar: u64, hcc1: u32) {
    let mut off = ((hcc1 >> 16) & 0xFFFF) as u64 * 4;
    let mut guard = 0;
    while off != 0 && off + 8 <= bar && guard < 64 {
        guard += 1;
        let a = hc.cap + off;
        let v = rd32(a);
        match v & 0xFF {
            1 => {
                // USB Legacy Support: bit 16 – BIOS Owned, bit 24 – OS Owned.
                if v & (1 << 16) != 0 {
                    unsafe { core::ptr::write_volatile((a + 3) as *mut u8, 1) };
                    if wait_until(|| rd32(a) & (1 << 16) == 0) {
                        hc.bios = "handed over";
                    } else {
                        // Jak Linux: BIOS nie oddał w 1 s – zabieramy siłą.
                        wr32(a, rd32(a) & !(1 << 16) | 1 << 24);
                        hc.bios = "TIMEOUT - taken over";
                    }
                } else {
                    unsafe { core::ptr::write_volatile((a + 3) as *mut u8, 1) };
                    hc.bios = "not owned";
                }
                // Wyłącz SMI od USB, skasuj zgłoszone (jak Linux: XHCI_LEGACY_DISABLE_SMI).
                let ctl = rd32(a + 4);
                wr32(a + 4, (ctl & ((0x7 << 1) | (0xFF << 5) | (0x7 << 17))) | (0x7 << 29));
            }
            2 => {
                // Supported Protocol: wersja (bity 31..24) i zakres portów.
                let d2 = rd32(a + 8);
                let range = (d2 & 0xFF, (d2 >> 8) & 0xFF);
                match v >> 24 {
                    2 => hc.usb2 = range,
                    3 => hc.usb3 = range,
                    _ => {}
                }
            }
            _ => {}
        }
        let next = ((v >> 8) & 0xFF) as u64;
        if next == 0 {
            break;
        }
        off += next * 4;
    }
}

/// Start kontrolera; Err = komunikat dla konsoli.
fn start(name: &'static str) -> Result<Hc, &'static str> {
    let info = dev_info(DEV).map_err(|_| "no device in slot 3")?;
    if (info.class, info.subclass, info.prog_if) != (0x0C, 0x03, 0x30) {
        return Err("device is not an xHCI controller (class 0C0330)");
    }
    if info.bars[0] == 0 || info.io_mask & 1 != 0 {
        return Err("BAR0 is not a memory BAR");
    }
    let bar = info.bars[0];
    let cap = dev_map(DEV, 0, PROT_READ | PROT_WRITE).map_err(|_| "dev_map BAR0 failed")?;
    let caplen = (rd32(cap + CAPLENGTH) & 0xFF) as u64;
    let version = (rd32(cap + CAPLENGTH) >> 16) as u16;
    let hcs1 = rd32(cap + HCSPARAMS1);
    let hcs2 = rd32(cap + HCSPARAMS2);
    let hcc1 = rd32(cap + HCCPARAMS1);
    let dboff = (rd32(cap + DBOFF) & !3) as u64;
    let rtsoff = (rd32(cap + RTSOFF) & !0x1F) as u64;
    if hcs1 == u32::MAX || caplen < 0x20 || caplen + PORTSC >= bar || dboff + 4 * 33 > bar || rtsoff + IR0 + 0x20 > bar {
        return Err("registers out of range (controller absent or not responding)");
    }
    let max_slots = hcs1 & 0xFF;
    let max_ports = (hcs1 >> 24) & 0xFF;
    let scratch = ((hcs2 >> 21) & 0x1F) << 5 | (hcs2 >> 27) & 0x1F;
    let ac64 = hcc1 & 1 != 0;
    if max_slots == 0 || max_ports == 0 || caplen + PORTSC + 0x10 * max_ports as u64 > bar {
        return Err("bad controller parameters (slots / ports)");
    }
    let mut pool = Pool { bits: if ac64 { 64 } else { 32 }, va: 0, pa: 0, pages: 0, used: 0, total: 0, free: [(0, 0); 128], nfree: 0 };
    pool.chunk(16).map_err(|_| "dma_alloc failed")?;
    let (cmd_va, cmd_pa) = pool.page().map_err(|_| "dma")?;
    let (ev_va, ev_pa) = pool.page().map_err(|_| "dma")?;
    let (dcbaa_va, dcbaa_pa) = pool.page().map_err(|_| "dma")?;
    let buf = pool.page().map_err(|_| "dma")?;
    let mut hc = Hc {
        name,
        cap,
        op: cap + caplen,
        rt: cap + rtsoff,
        db: cap + dboff,
        info,
        version,
        max_slots,
        slots: max_slots.min(SLOTS_MAX),
        max_ports,
        scratch,
        ac64,
        ctx: if hcc1 & (1 << 2) != 0 { 64 } else { 32 },
        usb2: (0, 0),
        usb3: (0, 0),
        bios: "no legacy support capability",
        irq: 0,
        pool,
        dcbaa: dcbaa_va,
        buf,
        cmd: Ring::new_linked(cmd_va, cmd_pa),
        ev: Ring { va: ev_va, pa: ev_pa, idx: 0, cycle: 1 },
        done: None,
        xfers: [(0, 0, 0, 0, 0); 16],
        nxfers: 0,
        ports: [Port::Free; PORTS_MAX],
        dirty: [false; PORTS_MAX],
        csc: [false; PORTS_MAX],
        last_error: [""; PORTS_MAX],
        devs: [const { None }; DEVS_MAX],
        noops: 0,
        polled: 0,
        irqs: 0,
        events: 0,
        port_events: 0,
        errors: 0,
        enumerated: 0,
        enum_count: 0,
        enum_sum: 0,
        enum_max: 0,
        failures: 0,
        input: handle_info(INPUT).map(|(k, _)| k) == Ok(KIND_INPUT),
        hid_reports: 0,
        hid_events: 0,
        hid_errors: 0,
        leds_wanted: None,
        blk: handle_info(BLK).map(|(k, _)| k) == Ok(KIND_BLK),
        stor_bufs: [(0, 0, 0, false); STOR_MAX],
        stor_reads: 0,
        stor_bytes: 0,
        stor_errors: 0,
        stor_requests_bad: 0,
        stor_retries: 0,
        hub_events: 0,
        hub_errors: 0,
        last_cc: 0,
        last_speed: 0,
    };

    // BIOS -> system.
    extended_caps(&mut hc, bar, hcc1);

    // Zatrzymanie i reset.
    if hc.op_rd(USBSTS) & STS_HCH == 0 {
        hc.op_wr(USBCMD, hc.op_rd(USBCMD) & !CMD_RUN);
        if !wait_until(|| hc.op_rd(USBSTS) & STS_HCH != 0) {
            return Err("controller does not halt");
        }
    }
    hc.op_wr(USBCMD, CMD_HCRST);
    sleep_ms(1); // niektóre kontrolery nie odpowiadają tuż po HCRST
    if !wait_until(|| hc.op_rd(USBCMD) & CMD_HCRST == 0 && hc.op_rd(USBSTS) & STS_CNR == 0) {
        return Err("controller reset timed out");
    }
    if hc.op_rd(PAGESIZE) & 1 == 0 {
        return Err("controller does not support 4 KiB pages");
    }

    // Struktury w pamięci DMA.
    hc.op_wr(CONFIG, hc.slots);
    if scratch > 0 {
        if scratch > 1023 {
            return Err("too many scratchpad buffers");
        }
        let (arr_va, arr_pa) = hc.pool.page().map_err(|_| "dma")?;
        let mut left = scratch as u64;
        let mut i = 0u64;
        while left > 0 {
            let n = left.min(512); // bufor DMA ≤ 2 MiB
            hc.pool.chunk(n).map_err(|_| "dma_alloc (scratchpad) failed")?;
            for k in 0..n {
                let pa = hc.pool.pa + k * 4096;
                unsafe { ((arr_va + (i + k) * 8) as *mut u64).write_volatile(pa) };
            }
            hc.pool.used = n;
            i += n;
            left -= n;
        }
        unsafe { (dcbaa_va as *mut u64).write_volatile(arr_pa) };
    }
    wr64(hc.op + DCBAAP, dcbaa_pa);
    wr64(hc.op + CRCR, cmd_pa | 1);
    // Tablica segmentów pierścienia zdarzeń (jeden segment) – w stronie DCBAA,
    // za 33 wpisami (wyrównanie 64 B).
    let erst_off = 0x400u64;
    unsafe {
        ((dcbaa_va + erst_off) as *mut u64).write_volatile(ev_pa);
        ((dcbaa_va + erst_off + 8) as *mut u32).write_volatile(RING as u32);
    }
    wr32(hc.ir(ERSTSZ), 1);
    wr64(hc.ir(ERDP), ev_pa);
    wr64(hc.ir(ERSTBA), dcbaa_pa + erst_off);
    wr32(hc.ir(IMOD), 0);
    wr32(hc.ir(IMAN), IMAN_IE | IMAN_IP);

    let irq = irq_bind(DEV);
    if irq < 0 {
        return Err("irq_bind failed (no free MSI vector?)");
    }
    hc.irq = irq as u64;
    hc.op_wr(USBCMD, CMD_RUN | CMD_INTE);
    if !wait_until(|| hc.op_rd(USBSTS) & STS_HCH == 0) {
        return Err("controller does not start");
    }
    if hc.failed() {
        return Err("host controller error after start");
    }

    // Zasilanie portów (gdy kontroler nim steruje – HCCPARAMS1.PPC).
    if hcc1 & (1 << 3) != 0 {
        for p in 1..=hc.ports() {
            let a = hc.portsc(p);
            let v = rd32(a);
            if v & PORT_PP == 0 {
                wr32(a, (v & PORT_KEEP) | PORT_PP);
            }
        }
    }

    // Pierwsze komendy.
    for _ in 0..3 {
        if hc.noop().is_err() {
            return Err("No-Op command not completed (command ring / event ring / interrupts)");
        }
    }
    Ok(hc)
}

fn handle(hc: &mut Hc, c: u64, req: &[u8]) -> Result<(), i64> {
    use core::fmt::Write;
    let text = core::str::from_utf8(req).unwrap_or("");
    let mut out = Text::new();
    if text == "status" {
        hc.poll_events();
        hc.describe(&mut out, true);
    } else if text == "list" {
        hc.poll_events();
        hc.list(&mut out);
    } else if let Some(ms) = text.strip_prefix("idle ") {
        let ms: u16 = ms.trim().parse().unwrap_or(0);
        let n = hc.hid_idle(ms);
        let _ = write!(out, "idle {} {}", ms, n);
    } else if let Some(n) = text.strip_prefix("noop ") {
        let n: u64 = n.trim().parse().unwrap_or(0);
        if n == 0 || n > 1_000_000 {
            let _ = write!(out, "error invalid count");
        } else {
            match hc.noop_bench(n) {
                Ok(ns) => {
                    let _ = write!(out, "noop {} {}", n, ns);
                }
                Err(e) => {
                    let _ = write!(out, "error {}", strerror(e));
                }
            }
        }
    } else {
        let _ = write!(out, "error unknown request (status, list, noop N, idle MS)");
    }
    chan_send(c, out.as_bytes(), CHAN_NONBLOCK);
    if hc.failed() {
        return Err(EIO);
    }
    Ok(())
}

fn main(args: Args) -> i32 {
    let name = args.get(0).unwrap_or("usbd");
    let mut hc = match start(name) {
        Ok(x) => x,
        Err(msg) => {
            println!("{}: {}", name, msg);
            return 2;
        }
    };
    let ns = hc.noop_bench(200).unwrap_or(0);
    let mut t = Text::new();
    hc.describe(&mut t, false);
    write(1, t.as_bytes());
    // Urządzenia podłączone od startu: debounce liczony od teraz.
    let t0 = uptime_ms();
    for p in 1..=hc.ports() {
        if rd32(hc.portsc(p)) & PORT_CCS != 0 {
            hc.ports[p as usize - 1] = Port::Debounce(t0 + DEBOUNCE_MS);
        }
    }
    // Enumeracja na starcie (do 5 s – potem reszta w pętli głównej).
    while uptime_ms() - t0 < 5000 {
        hc.poll_events();
        let wait = hc.service_ports().min(hc.service_hubs());
        let pending = hc.ports.iter().any(|p| matches!(p, Port::Debounce(_) | Port::Failed(..))) || hc.hubs_busy();
        if !pending {
            break;
        }
        hc.wait_irq(wait);
    }
    println!(
        "{}: controller running, No-Op {}.{} us, {} device(s) working of {} connected, {} DMA pages",
        name,
        ns / 1000,
        ns % 1000 / 100,
        hc.working(),
        hc.connected(),
        hc.pool.total
    );

    let mut clients = [0u64; MAX_CLIENTS];
    let mut nclients = 0usize;
    let mut listening = true;
    let mut msg = [0u8; 256];
    let mut info = RecvInfo::default();
    let mut timeout = 1000;
    loop {
        if !listening && nclients == 0 {
            hc.stop();
            return 0;
        }
        // M20.f: pendrive'y do jądra (dopiero tu – usbd już odpowiada na żądania).
        hc.attach_pending();
        let mut list = [(0u64, 0u64); WAIT_MAX];
        let mut k = 0;
        if listening {
            list[k] = (LISTEN, W_READABLE);
            k += 1;
        }
        let irq_at = k;
        list[k] = (hc.irq, W_IRQ);
        k += 1;
        // Kanały dysków (żądania odczytu od jądra).
        let stor_at = k;
        let mut stor_dev = [0usize; STOR_MAX];
        let mut nstor = 0;
        for d in 0..DEVS_MAX {
            if let Some(c) = hc.devs[d].as_ref().and_then(|x| x.stor.as_ref()).map(|s| s.chan).filter(|&c| c != 0) {
                if nstor < STOR_MAX {
                    list[k] = (c, W_READABLE);
                    stor_dev[nstor] = d;
                    nstor += 1;
                    k += 1;
                }
            }
        }
        let first = k;
        for &c in &clients[..nclients] {
            list[k] = (c, W_READABLE);
            k += 1;
        }
        let Ok(ready) = wait_many(&list[..k], timeout) else { return 5 };
        if ready & (1 << irq_at) != 0 {
            hc.irqs += irq_read(hc.irq) as u64;
        }
        hc.poll_events();
        if hc.failed() {
            println!("{}: host controller error (USBSTS {:#x}) - exiting for a restart", name, hc.op_rd(USBSTS));
            return 3;
        }
        for j in 0..nstor {
            if ready & (1 << (stor_at + j)) != 0 {
                hc.serve_storage(stor_dev[j]);
            }
        }
        // Podłączenia / odłączenia (zdarzenia portów) i terminy maszyny stanów.
        timeout = hc.service_ports().min(hc.service_hubs());
        hc.hid_maintenance();
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
                    close(hs[0]);
                }
            }
        }
        for j in (0..nclients).rev() {
            if ready & (1 << (first + j)) == 0 {
                continue;
            }
            let c = clients[j];
            let r = chan_recv(c, &mut msg, CHAN_NONBLOCK, &mut info);
            if r == EPIPE || r == EMSGSIZE {
                close(c);
                clients[j] = clients[nclients - 1];
                nclients -= 1;
                continue;
            }
            if r < 0 {
                continue;
            }
            if handle(&mut hc, c, &msg[..r as usize]).is_err() {
                println!("{}: host controller error - exiting for a restart", name);
                return 3;
            }
        }
    }
}
