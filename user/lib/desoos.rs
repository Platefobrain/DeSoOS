// M15: mała biblioteka dla programów użytkownika DeSoOS (odpowiednik libc).
//
// Program dołącza ją przez:
//     #[path = "../lib/desoos.rs"]
//     #[macro_use]
//     mod desoos;
//     desoos::entry!(main);
//     fn main(args: desoos::Args) -> i32 { println!("..."); 0 }
//
// _start (kernel skacze tu z RSP wskazującym na argc, argv[], NULL, envp
// NULL, auxv AT_NULL – układ SysV) -> main(args) -> exit(kod).
// Syscalle: numery z kernel/user/syscalls.rs (tabela w ARCHITEKTURA.md).
//
// M16: procesy (spawn/wait/kill), katalogi, klawisze dla edytora linii
// i sterta: program, który chce Vec/String, pisze w korzeniu
// `extern crate alloc;` – alokator (niżej) bierze pamięć przez brk / mmap (M17b).

#![allow(dead_code)]

use core::arch::{asm, global_asm};

pub const SYS_EXIT: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_READ: u64 = 2;
pub const SYS_OPEN: u64 = 3;
pub const SYS_CLOSE: u64 = 4;
pub const SYS_GETPID: u64 = 5;
pub const SYS_SLEEP: u64 = 6;
pub const SYS_YIELD: u64 = 7;
pub const SYS_UPTIME: u64 = 8;
pub const SYS_SPAWN: u64 = 9;
pub const SYS_WAIT: u64 = 10;
pub const SYS_GETPPID: u64 = 11;
pub const SYS_KILL: u64 = 12;
pub const SYS_CHDIR: u64 = 13;
pub const SYS_GETCWD: u64 = 14;
pub const SYS_READDIR: u64 = 15;
pub const SYS_STAT: u64 = 16;
pub const SYS_MKDIR: u64 = 17;
pub const SYS_UNLINK: u64 = 18;
pub const SYS_READKEY: u64 = 19;
pub const SYS_TASKS: u64 = 20;
pub const SYS_DUP: u64 = 22;
pub const SYS_DUP2: u64 = 23;
pub const SYS_SEEK: u64 = 24;
pub const SYS_PIPE: u64 = 25;
pub const SYS_BRK: u64 = 26;
pub const SYS_MMAP: u64 = 27;
pub const SYS_MUNMAP: u64 = 28;
pub const SYS_HANDLE_DUP: u64 = 29;
pub const SYS_HANDLE_INFO: u64 = 30;
pub const SYS_CHANNEL_CREATE: u64 = 31;
pub const SYS_CHAN_SEND: u64 = 32;
pub const SYS_CHAN_RECV: u64 = 33;
pub const SYS_SHM_CREATE: u64 = 34;
pub const SYS_SHM_MAP: u64 = 35;
pub const SYS_SPAWN_EX: u64 = 36;
pub const SYS_SHM_SIZE: u64 = 37;
pub const SYS_WAIT_MANY: u64 = 38;
pub const SYS_DEV_CLAIM: u64 = 39;
pub const SYS_DEV_INFO: u64 = 40;
pub const SYS_DEV_MAP: u64 = 41;
pub const SYS_IRQ_BIND: u64 = 42;
pub const SYS_IRQ_READ: u64 = 43;
pub const SYS_DMA_ALLOC: u64 = 44;
pub const SYS_DMA_PHYS: u64 = 45;
pub const SYS_SYSINFO: u64 = 46;
pub const SYS_SYSCTL: u64 = 47;
/// M20.b: dev_find(hw_root, klasa, nr) – urządzenie PCI po klasie.
pub const SYS_DEV_FIND: u64 = 48;
/// M20.e: input_inject(INPUT, zdarzenia, n) – klawiatura / mysz z usbd.
pub const SYS_INPUT_INJECT: u64 = 49;
/// M20.f: blk_attach(BLK, kanał, bufor, info) – usbd rejestruje pendrive.
pub const SYS_BLK_ATTACH: u64 = 50;

/// M19.b: sygnały wait_many.
pub const W_READABLE: u64 = 1;
pub const W_WRITABLE: u64 = 2;
pub const W_IRQ: u64 = 4;
/// M19.b: najwięcej wpisów w wait_many; bez limitu czasu.
pub const WAIT_MAX: usize = 16;
pub const FOREVER: u64 = u64::MAX;
/// M18: najwięcej uchwytów w komunikacie.
pub const MSG_HANDLES: usize = 8;
/// M18: nie czekaj na miejsce / komunikat (EAGAIN).
pub const CHAN_NONBLOCK: u64 = 1;
/// M18: największy komunikat (bajty).
pub const MSG_MAX: usize = 4096;
pub const EAGAIN: i64 = -11;
pub const EPIPE: i64 = -32;
pub const EMSGSIZE: i64 = -90;

/// M18: prawa uchwytu (bity) – prawa można tylko zmniejszyć (`handle_dup`).
pub const R_READ: u64 = 1;
pub const R_WRITE: u64 = 2;
pub const R_SEND: u64 = 4;
pub const R_RECV: u64 = 8;
pub const R_MAP_READ: u64 = 16;
pub const R_MAP_WRITE: u64 = 32;
pub const R_DUP: u64 = 64;
pub const R_TRANSFER: u64 = 128;
pub const R_ALL: u64 = 0xFF;

/// M18: rodzaj obiektu z `handle_info`.
pub const KIND_CONSOLE: u64 = 1;
pub const KIND_FILE: u64 = 2;
pub const KIND_PIPE: u64 = 3;
pub const KIND_CHANNEL: u64 = 4;
pub const KIND_SHM: u64 = 5;
/// M19.c: dostęp do sprzętu (tylko init, slot 3) i przejęte urządzenie PCI.
pub const KIND_HW_ROOT: u64 = 6;
pub const KIND_DEVICE: u64 = 7;
pub const KIND_IRQ: u64 = 8;
/// M19.i: prawo do akcji systemowych (reboot, halt, sync, stress) – init slot 4,
/// shell od init też slot 4 (programom go nie przekazuje).
pub const KIND_SYSCTL: u64 = 9;
/// M20.e: uchwyt INPUT (jądro -> init slot 5 -> usbd slot 5).
pub const KIND_INPUT: u64 = 10;
pub const INPUT: u64 = 5;
/// M20.f: uchwyt BLK (rejestracja dysku USB) – u init i usbd w slocie 6.
pub const KIND_BLK: u64 = 11;
pub const BLK: u64 = 6;
pub const ETIMEDOUT: i64 = -110;
pub const HW_ROOT: u64 = 3;
pub const SYSCTL: u64 = 4;
pub const SYSCTL_REBOOT: u64 = 1;
pub const SYSCTL_HALT: u64 = 2;
pub const SYSCTL_SYNC: u64 = 3;
pub const SYSCTL_STRESS: u64 = 4;
/// M19.c: błędy dev_claim.
pub const EBUSY: i64 = -16;
pub const ENODEV: i64 = -19;

/// mmap: prawa obszaru.
pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;

/// seek: od początku / od bieżącej pozycji / od końca.
pub const SEEK_SET: u64 = 0;
pub const SEEK_CUR: u64 = 1;
pub const SEEK_END: u64 = 2;

/// spawn: Ctrl+C kończy dziecko (proces na pierwszym planie).
pub const SPAWN_FOREGROUND: u64 = 1;
/// spawn: dziecko dostaje 0, 1, 2 rodzica.
pub const STDIO: u64 = fds(0, 1, 2);
/// wait: dowolne dziecko / nie czekaj.
pub const WAIT_ANY: u64 = u64::MAX;
pub const WNOHANG: u64 = 1;
/// Status z wait: zakończony przez kernel (kill, wyjątek) + powód w bitach 0..7.
pub const STATUS_SIGNALED: u64 = 0x100;

pub const ENOENT: i64 = -2;
pub const EBADF: i64 = -9;
pub const ECHILD: i64 = -10;
pub const ERANGE: i64 = -34;
pub const ENOMEM: i64 = -12;
pub const ENOSPC: i64 = -28;

/// Deskryptory rodzica, które dziecko dostanie jako 0, 1, 2.
pub const fn fds(stdin: u64, stdout: u64, stderr: u64) -> u64 {
    stdin | (stdout << 16) | (stderr << 32)
}

pub const O_READ: u64 = 1;
pub const O_WRITE: u64 = 2;
pub const O_CREATE: u64 = 4;
pub const O_TRUNC: u64 = 8;
pub const O_APPEND: u64 = 16;

#[inline(always)]
pub fn syscall3(n: u64, a: u64, b: u64, c: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n as i64 => ret,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub fn syscall6(n: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n as i64 => ret,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            in("r10") d,
            in("r8") e,
            in("r9") f,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

pub fn exit(code: i32) -> ! {
    syscall3(SYS_EXIT, code as i64 as u64, 0, 0);
    loop {}
}

pub fn write(fd: u64, data: &[u8]) -> i64 {
    syscall3(SYS_WRITE, fd, data.as_ptr() as u64, data.len() as u64)
}

pub fn read(fd: u64, buf: &mut [u8]) -> i64 {
    syscall3(SYS_READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64)
}

pub fn open(path: &str, flags: u64) -> i64 {
    syscall3(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, flags)
}

pub fn close(fd: u64) -> i64 {
    syscall3(SYS_CLOSE, fd, 0, 0)
}

/// M17b: nowy deskryptor na ten sam obiekt (wspólna pozycja).
pub fn dup(fd: u64) -> i64 {
    syscall3(SYS_DUP, fd, 0, 0)
}

/// M18: nowy uchwyt na ten sam obiekt z prawami `stare & mask` (wymaga R_DUP).
pub fn handle_dup(h: u64, mask: u64) -> i64 {
    syscall3(SYS_HANDLE_DUP, h, mask, 0)
}

/// M18: (rodzaj, prawa) uchwytu.
pub fn handle_info(h: u64) -> Result<(u64, u64), i64> {
    let r = syscall3(SYS_HANDLE_INFO, h, 0, 0);
    if r < 0 { Err(r) } else { Ok(((r as u64) >> 32, (r as u64) & 0xFFFF_FFFF)) }
}

/// M18: kanał – (koniec 0, koniec 1); komunikaty w obie strony.
pub fn channel_create() -> Result<(u64, u64), i64> {
    let mut out = [0u64; 2];
    let r = syscall3(SYS_CHANNEL_CREATE, out.as_mut_ptr() as u64, 0, 0);
    if r < 0 { Err(r) } else { Ok((out[0], out[1])) }
}

/// M18: wysyła komunikat (do MSG_MAX bajtów); flags: 0 albo CHAN_NONBLOCK.
pub fn chan_send(h: u64, data: &[u8], flags: u64) -> i64 {
    syscall6(SYS_CHAN_SEND, h, data.as_ptr() as u64, data.len() as u64, 0, 0, flags)
}

/// M18: wysyła komunikat z uchwytami – uchwyty są PRZENOSZONE (znikają u
/// nadawcy, wymagają R_TRANSFER); przy błędzie zostają u nadawcy.
pub fn chan_send_h(h: u64, data: &[u8], handles: &[u64], flags: u64) -> i64 {
    syscall6(SYS_CHAN_SEND, h, data.as_ptr() as u64, data.len() as u64, handles.as_ptr() as u64, handles.len() as u64, flags)
}

/// M18: wynik odbioru – długość, liczba uchwytów, nadawca (pid wpisany przez jądro).
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct RecvInfo {
    pub len: u64,
    pub handles: u64,
    pub sender: u64,
}

/// M18: odbiera komunikat do `buf`.  Err(EMSGSIZE) – bufor za mały, w `info`
/// wymagany rozmiar, komunikat zostaje w kolejce.
pub fn chan_recv(h: u64, buf: &mut [u8], flags: u64, info: &mut RecvInfo) -> i64 {
    let mut raw = [0u64; 3];
    let r = syscall6(SYS_CHAN_RECV, h, buf.as_mut_ptr() as u64, buf.len() as u64, 0, flags << 32, raw.as_mut_ptr() as u64);
    *info = RecvInfo { len: raw[0], handles: raw[1], sender: raw[2] };
    r
}

/// M18: odbiera komunikat z uchwytami – numery nowych uchwytów w `handles`
/// (info.handles sztuk).  EMSGSIZE – za mały bufor albo `handles`; EMFILE –
/// brak miejsca w tablicy uchwytów; w obu przypadkach komunikat zostaje.
pub fn chan_recv_h(h: u64, buf: &mut [u8], handles: &mut [u64], flags: u64, info: &mut RecvInfo) -> i64 {
    let mut raw = [0u64; 3];
    let hcap = handles.len().min(MSG_HANDLES) as u64;
    let r = syscall6(SYS_CHAN_RECV, h, buf.as_mut_ptr() as u64, buf.len() as u64, handles.as_mut_ptr() as u64, hcap | flags << 32, raw.as_mut_ptr() as u64);
    *info = RecvInfo { len: raw[0], handles: raw[1], sender: raw[2] };
    r
}

/// M18: uruchamia program; dziecko dostaje TYLKO uchwyty z `map`
/// [(uchwyt rodzica, numer u dziecka)] – kopie z tymi samymi prawami (R_DUP).
pub fn spawn_ex(path: &str, args: &[&str], map: &[(u64, u64)], flags: u64) -> i64 {
    let mut buf = [0u8; 4096];
    let mut n = 0;
    for a in args {
        let b = a.as_bytes();
        if n + b.len() + 1 > buf.len() {
            return -7; // E2BIG
        }
        buf[n..n + b.len()].copy_from_slice(b);
        n += b.len() + 1;
    }
    let mut flat = [0u64; 32];
    if map.len() > 16 {
        return -22;
    }
    for (i, &(from, to)) in map.iter().enumerate() {
        flat[2 * i] = from;
        flat[2 * i + 1] = to;
    }
    syscall6(SYS_SPAWN_EX, path.as_ptr() as u64, path.len() as u64, buf.as_ptr() as u64, n as u64, flat.as_ptr() as u64, map.len() as u64 | flags << 32)
}

/// M18: obiekt pamięci współdzielonej (`size` bajtów, zaokrąglone do 4 KiB,
/// wyzerowany) – uchwyt albo -errno.
pub fn shm_create(size: u64) -> i64 {
    syscall3(SYS_SHM_CREATE, size, 0, 0)
}

/// M18: mapuje cały obiekt (PROT_READ, PROT_READ | PROT_WRITE) – adres.
/// Odmapowanie: munmap(adres, shm_size(h)).  Pamięć nigdy nie jest wykonywalna.
pub fn shm_map(h: u64, prot: u64) -> Result<u64, i64> {
    let r = syscall3(SYS_SHM_MAP, h, prot, 0);
    if r < 0 { Err(r) } else { Ok(r as u64) }
}

/// M18: rozmiar obiektu pamięci współdzielonej w bajtach.
pub fn shm_size(h: u64) -> i64 {
    syscall3(SYS_SHM_SIZE, h, 0, 0)
}

/// M19.b: czeka, aż któryś uchwyt z listy [(uchwyt, sygnały)] będzie gotowy
/// (W_READABLE: recv / read nie będzie czekać; W_WRITABLE: send / write).
/// Ok(maska) – bit i = wpis i gotowy; Ok(0) – minęło `timeout_ms`
/// (FOREVER = bez limitu, 0 = tylko sprawdź).
pub fn wait_many(list: &[(u64, u64)], timeout_ms: u64) -> Result<u64, i64> {
    let mut flat = [0u64; 2 * WAIT_MAX];
    if list.len() > WAIT_MAX {
        return Err(-22);
    }
    for (i, &(h, sig)) in list.iter().enumerate() {
        flat[2 * i] = h;
        flat[2 * i + 1] = sig;
    }
    let r = syscall3(SYS_WAIT_MANY, flat.as_ptr() as u64, list.len() as u64, timeout_ms);
    if r < 0 { Err(r) } else { Ok(r as u64) }
}

/// M19.c: adres PCI urządzenia (bus, urządzenie, funkcja) dla dev_claim.
pub const fn bdf(bus: u64, dev: u64, func: u64) -> u64 {
    bus << 8 | dev << 3 | func
}

/// M19.c: przejmuje urządzenie PCI (z uchwytu HW_ROOT) – uchwyt DEVICE albo
/// -errno (EACCES: sterownik w jądrze / dysk / grafika / mostek; EBUSY: ma je
/// inna usługa; ENODEV: brak urządzenia).
pub fn dev_claim(root: u64, bdf: u64) -> i64 {
    syscall3(SYS_DEV_CLAIM, root, bdf, 0)
}

/// M20.b: klasa PCI kontrolera xHCI (USB 3): 0C (szyna szeregowa), 03 (USB), 30 (xHCI).
pub const CLASS_XHCI: u64 = 0x0C_03_30;

/// M20.b: adres (bdf) `nr`-tego urządzenia PCI o klasie `class` (24 bity:
/// klasa << 16 | podklasa << 8 | prog_if) – tylko z HW_ROOT.  ENOENT: nie ma
/// dalszych; EBADF: uchwyt nie jest HW_ROOT.  Nie przejmuje urządzenia.
pub fn dev_find(root: u64, class: u64, nr: u64) -> i64 {
    syscall3(SYS_DEV_FIND, root, class, nr)
}

/// M20.e: zdarzenie dla input_inject (8 B): rodzaj 1 = klawisz (wciśnięty,
/// HID usage), 2 = mysz (kółko, przyciski).
pub fn key_event(usage: u8, pressed: bool) -> [u8; 8] {
    [1, pressed as u8, usage, 0, 0, 0, 0, 0]
}

pub fn mouse_event(buttons: u8, wheel: i8) -> [u8; 8] {
    [2, wheel as u8, buttons, 0, 0, 0, 0, 0]
}

/// M20.e: zdarzenia do podsystemu wejścia jądra (≤ 64) – stan diod (bit 0
/// Num, 1 Caps, 2 Scroll) albo -errno (EBADF / EACCES / EINVAL).
pub fn input_inject(h: u64, events: &[[u8; 8]]) -> i64 {
    syscall3(SYS_INPUT_INJECT, h, events.as_ptr() as u64, events.len() as u64)
}

/// M20.f: opis dysku dla blk_attach (64 B).
pub struct BlkInfo {
    pub blocks: u64,
    pub block_size: u32,
    /// Sloty po 64 KiB w buforze (1..8).
    pub slots: u32,
    /// 0 = domyślny (5 s).
    pub timeout_ms: u32,
    pub desc: [u8; 40],
}

/// M20.f: rejestracja dysku USB (tylko odczyt) – numer (0 = sda) albo -errno.
/// Jądro wysyła kanałem żądania 32 B (id, op 1 = READ, lba u64, bloki u32,
/// slot u32), odpowiedź ≥ 12 B (id, status, bloki); dane – w slocie bufora.
pub fn blk_attach(h: u64, chan: u64, buf: u64, info: &BlkInfo) -> i64 {
    let mut raw = [0u8; 64];
    raw[0..8].copy_from_slice(&info.blocks.to_le_bytes());
    raw[8..12].copy_from_slice(&info.block_size.to_le_bytes());
    raw[12..16].copy_from_slice(&info.slots.to_le_bytes());
    raw[16..20].copy_from_slice(&info.timeout_ms.to_le_bytes());
    raw[24..64].copy_from_slice(&info.desc);
    syscall6(SYS_BLK_ATTACH, h, chan, buf, raw.as_ptr() as u64, 0, 0)
}

/// Nazwa dysku USB w jądrze: 0 -> sda, 26 -> sdaa.
pub fn disk_name(mut n: u64, out: &mut [u8; 8]) -> &str {
    let mut tmp = [0u8; 6];
    let mut k = 0;
    loop {
        tmp[k] = b'a' + (n % 26) as u8;
        k += 1;
        if n < 26 || k == tmp.len() {
            break;
        }
        n = n / 26 - 1;
    }
    out[0] = b's';
    out[1] = b'd';
    for i in 0..k {
        out[2 + i] = tmp[k - 1 - i];
    }
    core::str::from_utf8(&out[..2 + k]).unwrap_or("sd?")
}

/// M19.c: opis przejętego urządzenia.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DevInfo {
    pub vendor: u16,
    pub device: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    /// Rozmiary BAR-ów (0 = brak); BAR-y I/O w `io_mask`.
    pub bars: [u64; 6],
    pub io_mask: u8,
    pub msi: bool,
    pub msix: bool,
}

pub fn dev_info(h: u64) -> Result<DevInfo, i64> {
    let mut v = [0u64; 10];
    let r = syscall3(SYS_DEV_INFO, h, v.as_mut_ptr() as u64, 0);
    if r < 0 {
        return Err(r);
    }
    let mut bars = [0u64; 6];
    bars.copy_from_slice(&v[2..8]);
    Ok(DevInfo {
        vendor: v[0] as u16,
        device: (v[0] >> 16) as u16,
        class: (v[1] >> 16) as u8,
        subclass: (v[1] >> 8) as u8,
        prog_if: v[1] as u8,
        bars,
        io_mask: v[8] as u8,
        msi: v[9] & 1 != 0,
        msix: v[9] & 2 != 0,
    })
}

/// M19.c: mapuje rejestry BAR-u (PROT_READ albo PROT_READ | PROT_WRITE) – bez
/// cache, nigdy wykonywalne.  Odmapowanie: munmap(adres, rozmiar BAR-u).
pub fn dev_map(h: u64, bar: u64, prot: u64) -> Result<u64, i64> {
    let r = syscall3(SYS_DEV_MAP, h, bar, prot);
    if r < 0 { Err(r) } else { Ok(r as u64) }
}

/// M19.d: przypina przerwanie urządzenia (wymaga R_MAP_WRITE) – uchwyt IRQ.
/// Czekanie: wait_many z W_IRQ; odczyt licznika: irq_read.
pub fn irq_bind(dev: u64) -> i64 {
    syscall3(SYS_IRQ_BIND, dev, 0, 0)
}

/// M19.d: przerwania od ostatniego odczytu (zeruje licznik).
pub fn irq_read(irq: u64) -> i64 {
    syscall3(SYS_IRQ_READ, irq, 0, 0)
}

/// M19.e: bufor DMA urządzenia – uchwyt pamięci współdzielonej (mapowanie:
/// shm_map) z ciągłych ramek poniżej 2^bits (szyna adresów urządzenia).  Bufor
/// żyje tak długo jak przejęcie urządzenia (zamknięcie uchwytu go nie zwalnia).
pub fn dma_alloc(dev: u64, size: u64, bits: u64) -> i64 {
    syscall3(SYS_DMA_ALLOC, dev, size, bits)
}

/// M19.e: adres fizyczny bufora DMA (do wpisania w urządzenie).
pub fn dma_phys(buf: u64) -> Result<u64, i64> {
    let r = syscall3(SYS_DMA_PHYS, buf, 0, 0);
    if r < 0 { Err(r) } else { Ok(r as u64) }
}

/// M19.g: kanał do menedżera usług (init) – programy uruchomione z shella mają
/// go w slocie 3 (tylko wysyłanie).  Init ma w slocie 3 HW_ROOT.
pub const SVC: u64 = 3;

/// M19.g: połączenie z usługą po nazwie (np. "edu") – zwraca koniec kanału do
/// rozmowy z usługą.  Usługa nieznana / niedziałająca: kanał zamknięty przez
/// init, pierwsza operacja na nim da EPIPE.
pub fn svc_connect(name: &str) -> Result<u64, i64> {
    let mut msg = [0u8; 64];
    let p = b"connect ";
    if p.len() + name.len() > msg.len() {
        return Err(-22);
    }
    msg[..p.len()].copy_from_slice(p);
    msg[p.len()..p.len() + name.len()].copy_from_slice(name.as_bytes());
    let (mine, theirs) = channel_create()?;
    let r = chan_send_h(SVC, &msg[..p.len() + name.len()], &[theirs], 0);
    if r != 0 {
        close(mine);
        close(theirs);
        return Err(r);
    }
    Ok(mine)
}

/// M19.g: lista usług od init (wiersze "nazwa stan pid N restarts N (program)")
/// do `buf`; zwraca długość.
pub fn svc_list(buf: &mut [u8]) -> Result<usize, i64> {
    let (mine, theirs) = channel_create()?;
    let r = chan_send_h(SVC, b"list", &[theirs], 0);
    if r != 0 {
        close(mine);
        close(theirs);
        return Err(r);
    }
    let mut msg = [0u8; MSG_MAX];
    let mut info = RecvInfo::default();
    let r = chan_recv(mine, &mut msg, 0, &mut info);
    close(mine);
    if r < 0 {
        return Err(r);
    }
    let n = (r as usize).min(buf.len());
    buf[..n].copy_from_slice(&msg[..n]);
    Ok(n)
}

/// M17b: `new` wskazuje obiekt `old` (poprzedni `new` zamknięty).
pub fn dup2(old: u64, new: u64) -> i64 {
    syscall3(SYS_DUP2, old, new, 0)
}

/// M17b: potok – (fd do odczytu, fd do zapisu).
pub fn pipe() -> Result<(u64, u64), i64> {
    let mut out = [0u64; 2];
    let r = syscall3(SYS_PIPE, out.as_mut_ptr() as u64, 0, 0);
    if r < 0 { Err(r) } else { Ok((out[0], out[1])) }
}

/// M17b: koniec sterty (0 = zapytanie); przy błędzie – dotychczasowy.
pub fn brk(addr: u64) -> u64 {
    syscall3(SYS_BRK, addr, 0, 0) as u64
}

/// M17b: anonimowy obszar pamięci (wyzerowany, strony przy pierwszym dostępie).
pub fn mmap(len: u64, prot: u64) -> Result<u64, i64> {
    let r = syscall3(SYS_MMAP, len, prot, 0);
    if r < 0 { Err(r) } else { Ok(r as u64) }
}

pub fn munmap(addr: u64, len: u64) -> i64 {
    syscall3(SYS_MUNMAP, addr, len, 0)
}

/// M17b: nowa pozycja (SEEK_SET / SEEK_CUR / SEEK_END); wynik – pozycja.
pub fn seek(fd: u64, offset: i64, whence: u64) -> i64 {
    syscall3(SYS_SEEK, fd, offset as u64, whence)
}

pub fn getpid() -> u64 {
    syscall3(SYS_GETPID, 0, 0, 0) as u64
}

pub fn sleep_ms(ms: u64) {
    syscall3(SYS_SLEEP, ms, 0, 0);
}

pub fn uptime_ms() -> u64 {
    syscall3(SYS_UPTIME, 0, 0, 0) as u64
}

// ------------------------------------------------------------
// M16: procesy
// ------------------------------------------------------------

/// Uruchamia program `path` (względem katalogu bieżącego) z argumentami
/// `args` (args[0] = nazwa).  Zwraca pid albo -errno.
pub fn spawn(path: &str, args: &[&str], flags: u64, fds: u64) -> i64 {
    let mut buf = [0u8; 4096];
    let mut n = 0;
    for a in args {
        let b = a.as_bytes();
        if n + b.len() + 1 > buf.len() {
            return -7; // E2BIG
        }
        buf[n..n + b.len()].copy_from_slice(b);
        n += b.len() + 1; // bajt 0 już jest
    }
    syscall6(SYS_SPAWN, path.as_ptr() as u64, path.len() as u64, buf.as_ptr() as u64, n as u64, flags, fds)
}

/// Czeka na dziecko `pid` (WAIT_ANY = dowolne).  Ok((pid, status)); przy
/// WNOHANG Ok((0, 0)), gdy nikt się jeszcze nie skończył.
pub fn wait(pid: u64, flags: u64) -> Result<(u64, u64), i64> {
    let mut status: u64 = 0;
    let r = syscall3(SYS_WAIT, pid, &mut status as *mut u64 as u64, flags);
    if r < 0 { Err(r) } else { Ok((r as u64, status)) }
}

pub fn getppid() -> u64 {
    syscall3(SYS_GETPPID, 0, 0, 0) as u64
}

pub fn kill(pid: u64) -> i64 {
    syscall3(SYS_KILL, pid, 0, 0)
}

pub fn chdir(path: &str) -> i64 {
    syscall3(SYS_CHDIR, path.as_ptr() as u64, path.len() as u64, 0)
}

/// Katalog bieżący do `buf`; zwraca go jako &str.
pub fn getcwd(buf: &mut [u8]) -> &str {
    let n = syscall3(SYS_GETCWD, buf.as_mut_ptr() as u64, buf.len() as u64, 0);
    if n <= 0 {
        return "/";
    }
    core::str::from_utf8(&buf[..n as usize]).unwrap_or("/")
}

/// Zawartość katalogu: linie "d|f\t<rozmiar>\t<nazwa>\n".  ERANGE = za mały bufor.
pub fn readdir(path: &str, buf: &mut [u8]) -> i64 {
    syscall6(SYS_READDIR, path.as_ptr() as u64, path.len() as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0)
}

#[derive(Clone, Copy)]
pub struct Stat {
    pub is_dir: bool,
    pub size: u64,
}

pub fn stat(path: &str) -> Result<Stat, i64> {
    let mut out = [0u64; 2];
    let r = syscall3(SYS_STAT, path.as_ptr() as u64, path.len() as u64, out.as_mut_ptr() as u64);
    if r < 0 { Err(r) } else { Ok(Stat { is_dir: out[0] == 1, size: out[1] }) }
}

pub fn mkdir(path: &str) -> i64 {
    syscall3(SYS_MKDIR, path.as_ptr() as u64, path.len() as u64, 0)
}

pub fn unlink(path: &str) -> i64 {
    syscall3(SYS_UNLINK, path.as_ptr() as u64, path.len() as u64, 0)
}

/// Lista zadań: linie "pid\tppid\tstan\tms\tprzełączenia\ttyp\tnazwa\n".
pub fn tasks(buf: &mut [u8]) -> i64 {
    syscall3(SYS_TASKS, buf.as_mut_ptr() as u64, buf.len() as u64, 0)
}

/// M19.i: tekst tylko do odczytu od jądra ("mem", "lspci -v", "cpus", "disk"...)
/// do `buf`.  Err(ENOENT) – nieznany temat; Err(ERANGE) – bufor za mały.
pub fn sysinfo(topic: &str, buf: &mut [u8]) -> Result<usize, i64> {
    let r = syscall6(SYS_SYSINFO, topic.as_ptr() as u64, topic.len() as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0);
    if r < 0 { Err(r) } else { Ok(r as usize) }
}

/// M19.i: akcja systemowa z uchwytem SYSCTL (`h`); wynik tekstem na `fd`.
pub fn sysctl(h: u64, op: u64, arg: u64, fd: u64) -> i64 {
    syscall6(SYS_SYSCTL, h, op, arg, fd, 0, 0)
}

/// Opis statusu z wait.
pub fn describe_status(status: u64) -> &'static str {
    if status & STATUS_SIGNALED == 0 {
        return if status == 0 { "done" } else { "exited with an error" };
    }
    match status & 0xFF {
        9 => "killed",
        14 => "crashed (page fault)",
        13 => "crashed (general protection)",
        6 => "crashed (invalid instruction)",
        19 => "crashed (SIMD exception)",
        3 => "ended (int3)",
        _ => "crashed",
    }
}

// ------------------------------------------------------------
// M16: klawisze (readkey) – dla edytora linii
// ------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    Char(char),
    /// Ctrl + litera (mała).
    Ctrl(char),
    Enter,
    Backspace,
    Delete,
    Tab,
    Escape,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    /// Koniec wejścia (bufor testowy wyczerpany).
    Eof,
}

/// Czeka na klawisz.  `line` = to, co kernel narysuje ponownie, jeśli
/// w trakcie czekania coś wypisze proces w tle (prompt + wpisany tekst).
pub fn readkey(line: &str) -> Result<Key, i64> {
    let r = syscall3(SYS_READKEY, line.as_ptr() as u64, line.len() as u64, 0);
    if r < 0 {
        return Err(r);
    }
    let r = r as u64;
    const SPECIAL: u64 = 0x11_0000;
    const CTRL: u64 = 0x12_0000;
    Ok(match r {
        0 => Key::Eof,
        r if r >= CTRL => Key::Ctrl(char::from_u32((r - CTRL) as u32).unwrap_or('?')),
        r if r > SPECIAL => match r - SPECIAL {
            1 => Key::Enter,
            2 => Key::Backspace,
            3 => Key::Delete,
            4 => Key::Tab,
            5 => Key::Escape,
            6 => Key::Left,
            7 => Key::Right,
            8 => Key::Up,
            9 => Key::Down,
            10 => Key::Home,
            _ => Key::End,
        },
        r => Key::Char(char::from_u32(r as u32).unwrap_or('?')),
    })
}

// ------------------------------------------------------------
// Sterta procesu – M17b: na brk / mmap (wcześniej tablica 256 KiB w .bss)
// ------------------------------------------------------------
//
// Klasy rozmiarów 16 B .. 64 KiB (potęgi dwójki), każda z własną listą
// wolnych bloków; nowe bloki z kawałka sterty [next, end), który rośnie przez
// brk o co najmniej 64 KiB.  Większe bloki – własny obszar mmap (zwalniany
// przez munmap).  Strony przydziela kernel przy pierwszym dostępie, więc
// rezerwa nic nie kosztuje.  Proces jest jednowątkowy – bez blokad.

const CLASSES: usize = 13; // 16 << 12 = 64 KiB
const GROW: usize = 64 * 1024;

struct Heap {
    next: core::cell::Cell<usize>,
    end: core::cell::Cell<usize>,
    free: [core::cell::Cell<usize>; CLASSES],
}
unsafe impl Sync for Heap {}

static HEAP: Heap = Heap {
    next: core::cell::Cell::new(0),
    end: core::cell::Cell::new(0),
    free: [const { core::cell::Cell::new(0) }; CLASSES],
};

fn class_of(layout: core::alloc::Layout) -> Option<(usize, usize)> {
    let size = layout.size().max(layout.align()).max(16).next_power_of_two();
    let class = size.trailing_zeros() as usize - 4;
    if class < CLASSES { Some((class, size)) } else { None }
}

fn page_up(x: usize) -> usize {
    (x + 4095) & !4095
}

/// Blok `size` (wyrównany do `size`) z kawałka sterty; brak – sterta rośnie.
fn carve(size: usize) -> *mut u8 {
    if HEAP.end.get() == 0 {
        let b = brk(0) as usize;
        HEAP.next.set(b);
        HEAP.end.set(b);
    }
    let start = (HEAP.next.get() + size - 1) & !(size - 1);
    if start + size > HEAP.end.get() {
        let want = (start + size).max(HEAP.end.get() + GROW);
        let got = brk(want as u64) as usize;
        if got < start + size {
            return core::ptr::null_mut();
        }
        HEAP.end.set(got);
    }
    HEAP.next.set(start + size);
    start as *mut u8
}

pub struct ArenaAlloc;

unsafe impl core::alloc::GlobalAlloc for ArenaAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let Some((class, size)) = class_of(layout) else {
            // Duże bloki: własny obszar (wyrównanie do strony wystarcza).
            if layout.align() > 4096 {
                return core::ptr::null_mut();
            }
            return match mmap(page_up(layout.size()) as u64, PROT_READ | PROT_WRITE) {
                Ok(a) => a as *mut u8,
                Err(_) => core::ptr::null_mut(),
            };
        };
        let head = HEAP.free[class].get();
        if head != 0 {
            HEAP.free[class].set(unsafe { *(head as *const usize) });
            return head as *mut u8;
        }
        carve(size)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        match class_of(layout) {
            Some((class, _)) => {
                unsafe { *(ptr as *mut usize) = HEAP.free[class].get() };
                HEAP.free[class].set(ptr as usize);
            }
            None => {
                munmap(ptr as u64, page_up(layout.size()) as u64);
            }
        }
    }
}

#[global_allocator]
static ALLOCATOR: ArenaAlloc = ArenaAlloc;

/// Opis kodu błędu (-errno).
pub fn strerror(e: i64) -> &'static str {
    match e {
        -1 => "operation not permitted",
        -2 => "no such file or directory",
        -3 => "no such process",
        -7 => "argument list too long",
        -8 => "not an executable (bad ELF file)",
        -10 => "no child processes",
        -12 => "out of memory",
        -4 => "interrupted",
        -5 => "I/O error",
        -9 => "bad file descriptor",
        -13 => "permission denied",
        -14 => "bad address",
        -17 => "already exists",
        -20 => "not a directory",
        -21 => "is a directory",
        -22 => "invalid argument",
        -24 => "too many open files",
        -28 => "no space left",
        -29 => "illegal seek",
        -32 => "broken pipe",
        -30 => "read-only file system",
        -34 => "buffer too small",
        -11 => "try again (would block)",
        -90 => "message too long",
        -16 => "device or resource busy",
        -19 => "no such device",
        -38 => "unknown syscall",
        -39 => "directory not empty",
        _ => "error",
    }
}

/// Bufor wyjścia dla print!/println!: cały tekst jednego wywołania idzie
/// jednym `write` (linia z procesu w tle nie miesza się z promptem shella).
/// Opróżniany, gdy się zapełni, i na końcu (drop).
pub struct Out {
    fd: u64,
    len: usize,
    buf: [u8; 256],
}

impl Out {
    pub fn new(fd: u64) -> Self {
        Out { fd, len: 0, buf: [0; 256] }
    }
    pub fn flush(&mut self) {
        if self.len > 0 {
            write(self.fd, &self.buf[..self.len]);
            self.len = 0;
        }
    }
}

impl core::fmt::Write for Out {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &b in s.as_bytes() {
            if self.len == self.buf.len() {
                self.flush();
            }
            self.buf[self.len] = b;
            self.len += 1;
        }
        Ok(())
    }
}

impl Drop for Out {
    fn drop(&mut self) {
        self.flush();
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        let _ = core::fmt::Write::write_fmt(&mut $crate::desoos::Out::new(1), format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {{
        let mut o = $crate::desoos::Out::new(1);
        let _ = core::fmt::Write::write_fmt(&mut o, format_args!($($arg)*));
        let _ = core::fmt::Write::write_str(&mut o, "\n");
    }};
}

#[macro_export]
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        let mut o = $crate::desoos::Out::new(2);
        let _ = core::fmt::Write::write_fmt(&mut o, format_args!($($arg)*));
        let _ = core::fmt::Write::write_str(&mut o, "\n");
    }};
}

/// Argumenty programu (argv) – wskaźniki na stos procesu.
#[derive(Clone, Copy)]
pub struct Args {
    argc: usize,
    argv: *const *const u8,
}

impl Args {
    pub fn len(&self) -> usize {
        self.argc
    }

    pub fn get(&self, i: usize) -> Option<&'static str> {
        if i >= self.argc {
            return None;
        }
        unsafe {
            let p = *self.argv.add(i);
            // read_volatile: kompilator nie zamieni pętli na wywołanie strlen
            // (programy nie mają libc).
            let mut n = 0;
            while core::ptr::read_volatile(p.add(n)) != 0 {
                n += 1;
            }
            core::str::from_utf8(core::slice::from_raw_parts(p, n)).ok()
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &'static str> + '_ {
        (0..self.argc).filter_map(move |i| self.get(i))
    }
}

global_asm!(r#"
    .section .text._start, "ax"
    .global _start
    _start:
        xor ebp, ebp
        mov rdi, rsp
        and rsp, -16
        call desoos_start
        ud2
"#);

unsafe extern "Rust" {
    fn desoos_main(args: Args) -> i32;
}

#[unsafe(no_mangle)]
extern "sysv64" fn desoos_start(sp: *const u64) -> ! {
    let args = unsafe { Args { argc: *sp as usize, argv: sp.add(1) as *const *const u8 } };
    let code = unsafe { desoos_main(args) };
    exit(code)
}

/// Łączy `fn main(args: Args) -> i32` programu z _start.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[unsafe(no_mangle)]
        pub fn desoos_main(args: $crate::desoos::Args) -> i32 {
            $main(args)
        }
    };
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let _ = core::fmt::Write::write_fmt(&mut Out::new(2), format_args!("panic: {}\n", info));
    exit(101)
}
