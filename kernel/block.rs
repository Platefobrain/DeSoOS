// M8: warstwa urządzeń blokowych – wspólny interfejs dysków.
//
// Każdy sterownik dysku (virtio-blk teraz, NVMe / AHCI później) implementuje
// `BlockDevice` i rejestruje się przez `register()`.  Wyżej (system plików
// w M9, shell) używa się tylko tego interfejsu – nie wie, jaki to dysk.
//
// Jedno żądanie naraz na dysk (wywołanie czeka na zakończenie).  M12: dostęp
// pod blokadą (od M20.f – osobna dla każdego dysku); zadanie czekające na
// dysk śpi (virtio: BLK_WAIT).
//
// M16b:
//   * Dysk tylko do odczytu jest pilnowany TUTAJ (niezależnie od sterownika
//     i systemu plików): `write` na takim dysku kończy się ReadOnly, zanim
//     cokolwiek trafi do sterownika.  Prawdziwe dyski NVMe są zawsze tylko
//     do odczytu (drivers/nvme.rs).
//   * Partycje (GPT – gpt.rs) są osobnymi dyskami, np. "nvme0n1p1": mają
//     przesunięcie i długość, dziedziczą "tylko do odczytu" po dysku.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

pub const SECTOR_SIZE: usize = 512;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockError {
    /// LBA lub długość poza dyskiem.
    OutOfRange,
    /// Bufor nie jest wielokrotnością rozmiaru sektora.
    BadBuffer,
    /// Dysk tylko do odczytu.
    ReadOnly,
    /// Urządzenie zgłosiło błąd I/O.
    Io,
    /// Operacja nieobsługiwana przez urządzenie.
    Unsupported,
    /// Urządzenie nie odpowiedziało w czasie.
    Timeout,
    /// Nie ma dysku o takim numerze.
    NoDevice,
}

impl core::fmt::Display for BlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            BlockError::OutOfRange => "sector out of range",
            BlockError::BadBuffer => "buffer is not a multiple of the sector size",
            BlockError::ReadOnly => "device is read-only",
            BlockError::Io => "I/O error",
            BlockError::Unsupported => "operation not supported",
            BlockError::Timeout => "device timeout",
            BlockError::NoDevice => "no such disk",
        };
        f.write_str(s)
    }
}

pub trait BlockDevice {
    /// Krótka nazwa, np. "vda".
    fn name(&self) -> &str;
    /// Opis dla ludzi (typ, model).
    fn description(&self) -> String;
    /// Liczba sektorów po 512 B.
    fn sector_count(&self) -> u64;
    fn read_only(&self) -> bool;
    /// M16b: natywny rozmiar bloku urządzenia (512 albo 4096) – interfejs i tak
    /// liczy w sektorach po 512 B, ale GPT podaje adresy w blokach urządzenia.
    fn logical_block_size(&self) -> usize {
        SECTOR_SIZE
    }
    /// M16b: typ partycji GPT (None: cały dysk, nie partycja).
    fn partition_kind(&self) -> Option<&'static str> {
        None
    }
    /// M20.f: numer dysku-rodzica (partycja) albo None.
    fn parent(&self) -> Option<usize> {
        None
    }
    /// Czyta `buf.len() / 512` sektorów od `lba`.
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError>;
    /// Zapisuje `buf.len() / 512` sektorów od `lba`.
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError>;
    /// Wymusza zapis z cache urządzenia na nośnik.
    fn flush(&mut self) -> Result<(), BlockError>;
}

/// Sprawdzenie zakresu wspólne dla sterowników.
pub fn check_range(dev_sectors: u64, lba: u64, len: usize) -> Result<u64, BlockError> {
    if len == 0 || len % SECTOR_SIZE != 0 {
        return Err(BlockError::BadBuffer);
    }
    let count = (len / SECTOR_SIZE) as u64;
    match lba.checked_add(count) {
        Some(end) if end <= dev_sectors => Ok(count),
        _ => Err(BlockError::OutOfRange),
    }
}

// M20.f: blokada PER DYSK (dawniej jedna globalna „block layer”) – odczyt z
// pendrive'a może czekać na usbd do 5 s, a nie może przy tym zatrzymać NVMe
// ani virtio.  Lista dysków pod krótką blokadą (wyszukanie wpisu, Arc),
// operacja pod blokadą dysku (KMutex – reentrant, usypiająca).  Partycja
// bierze swoją blokadę, potem blokadę dysku-rodzica (zawsze w tej kolejności).
// Kolejność: FS_LOCK -> blokada partycji -> blokada dysku.
//
// Usuwanie (M20.f, dysk USB zniknął): wpis listy = None, numer wraca do puli
// dopiero, gdy nic już go nie używa – usuwający najpierw odmontowuje systemy
// plików z dysku i jego partycji (ublk.rs).  Operacja w toku trzyma Arc.

struct Disk {
    /// Kopia nazwy – `find` bez brania blokady dysku.
    name: String,
    /// Dysk-rodzic (partycja) – `partitions_of` bez blokad dysków.
    parent: Option<usize>,
    lock: crate::sched::sync::KMutex,
    dev: core::cell::UnsafeCell<Box<dyn BlockDevice>>,
}

// Urządzenie zmienia się tylko pod `lock` (KMutex – jedno zadanie naraz).
unsafe impl Sync for Disk {}
unsafe impl Send for Disk {}

static DISKS: crate::sched::spin::SpinLock<Vec<Option<Arc<Disk>>>> =
    crate::sched::spin::SpinLock::new("block list", crate::sched::spin::level::BLOCK, Vec::new());

fn disk(index: usize) -> Option<Arc<Disk>> {
    DISKS.lock().get(index).cloned().flatten()
}

/// Dodaje dysk; zwraca jego numer (pierwszy wolny – po usuniętym dysku USB).
pub fn register(device: Box<dyn BlockDevice>) -> usize {
    let d = Arc::new(Disk {
        name: String::from(device.name()),
        parent: device.parent(),
        lock: crate::sched::sync::KMutex::new(),
        dev: core::cell::UnsafeCell::new(device),
    });
    let mut list = DISKS.lock();
    if list.capacity() == 0 {
        // Bez przenoszenia tablicy przy kolejnych dyskach (testy liczą ramki).
        list.reserve(32);
    }
    if let Some(i) = list.iter().position(|e| e.is_none()) {
        list[i] = Some(d);
        return i;
    }
    list.push(Some(d));
    list.len() - 1
}

/// M20.f: usuwa dysk (wpis wolny).  Wołający odmontował już systemy plików z
/// niego i z jego partycji.
pub fn remove(index: usize) {
    let old = {
        let mut list = DISKS.lock();
        match list.get_mut(index) {
            Some(e) => e.take(),
            None => None,
        }
    };
    drop(old); // Drop urządzenia poza blokadą listy
}

/// Liczba wpisów (numery 0..count; usunięte dają NoDevice).
pub fn count() -> usize {
    DISKS.lock().len()
}

/// Operacja na dysku o numerze `index` (pod blokadą tego dysku).
pub fn with_device<R>(index: usize, f: impl FnOnce(&mut dyn BlockDevice) -> R) -> Result<R, BlockError> {
    let d = disk(index).ok_or(BlockError::NoDevice)?;
    let _g = d.lock.lock();
    Ok(f(unsafe { &mut **d.dev.get() }))
}

pub fn read(index: usize, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
    with_device(index, |d| d.read(lba, buf))?
}

pub fn write(index: usize, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
    with_device(index, |d| {
        // M16b: druga linia obrony – dysk tylko do odczytu nie dostaje zapisu.
        if d.read_only() {
            return Err(BlockError::ReadOnly);
        }
        d.write(lba, buf)
    })?
}

pub fn flush(index: usize) -> Result<(), BlockError> {
    with_device(index, |d| if d.read_only() { Ok(()) } else { d.flush() })?
}

#[allow(dead_code)]
pub fn is_read_only(index: usize) -> bool {
    with_device(index, |d| d.read_only()).unwrap_or(true)
}

/// Numer dysku o nazwie `name`.
#[allow(dead_code)]
pub fn find(name: &str) -> Option<usize> {
    DISKS.lock().iter().position(|d| matches!(d, Some(d) if d.name == name))
}

/// M20.f: numery partycji dysku `parent` (rejestruje je scan_partitions).
pub fn partitions_of(parent: usize) -> Vec<usize> {
    let list = DISKS.lock();
    (0..list.len()).filter(|&i| matches!(&list[i], Some(d) if d.parent == Some(parent))).collect()
}

// ------------------------------------------------------------
// M16b: partycje jako osobne dyski
// ------------------------------------------------------------

pub struct Partition {
    name: String,
    parent: usize,
    /// Początek i długość w sektorach po 512 B.
    start: u64,
    sectors: u64,
    read_only: bool,
    block_size: usize,
    kind: &'static str,
    label: String,
}

impl BlockDevice for Partition {
    fn name(&self) -> &str {
        &self.name
    }
    fn description(&self) -> String {
        alloc::format!(
            "partition of disk {} at sector {}, {} MiB, {}{}{}",
            self.parent,
            self.start,
            self.sectors * SECTOR_SIZE as u64 / (1024 * 1024),
            self.kind,
            if self.label.is_empty() { String::new() } else { alloc::format!(" \"{}\"", self.label) },
            if self.read_only { ", read-only" } else { "" }
        )
    }
    fn sector_count(&self) -> u64 {
        self.sectors
    }
    fn read_only(&self) -> bool {
        self.read_only
    }
    fn logical_block_size(&self) -> usize {
        self.block_size
    }
    fn partition_kind(&self) -> Option<&'static str> {
        Some(self.kind)
    }
    fn parent(&self) -> Option<usize> {
        Some(self.parent)
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        check_range(self.sectors, lba, buf.len())?;
        read(self.parent, self.start + lba, buf)
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        check_range(self.sectors, lba, buf.len())?;
        if self.read_only {
            return Err(BlockError::ReadOnly);
        }
        write(self.parent, self.start + lba, buf)
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        flush(self.parent)
    }
}

/// Czyta GPT dysku `disk` i rejestruje jego partycje jako dyski
/// "<nazwa>p<n>" (albo "<nazwa><n>", gdy nazwa kończy się cyfrą... jak w
/// Linuksie: nvme0n1 -> nvme0n1p1, vda -> vda1).  Zwraca liczbę partycji.
pub fn scan_partitions(disk: usize) -> usize {
    let Ok((name, read_only, block_size)) =
        with_device(disk, |d| (String::from(d.name()), d.read_only(), d.logical_block_size()))
    else {
        return 0;
    };
    let parts = match crate::gpt::read(disk) {
        Ok(Some(p)) => p,
        Ok(None) => return 0,
        Err(e) => {
            crate::serial_println!("[BLK] {}: GPT: {}", name, e);
            return 0;
        }
    };
    let sep = if name.ends_with(|c: char| c.is_ascii_digit()) { "p" } else { "" };
    let mut n = 0;
    for p in &parts {
        let pname = alloc::format!("{}{}{}", name, sep, p.index);
        if find(&pname).is_some() {
            continue; // już zarejestrowana
        }
        let part = Partition {
            name: pname.clone(),
            parent: disk,
            start: p.first_sector,
            sectors: p.sectors,
            read_only,
            block_size,
            kind: p.kind,
            label: p.name.clone(),
        };
        let index = register(Box::new(part));
        crate::serial_println!(
            "[BLK]   disk {}: {} = {} MiB, {}{}",
            index,
            pname,
            p.sectors * SECTOR_SIZE as u64 / (1024 * 1024),
            p.kind,
            if p.name.is_empty() { String::new() } else { alloc::format!(" \"{}\"", p.name) }
        );
        n += 1;
    }
    n
}

/// Typ partycji dysku `index` (None: to nie partycja).
#[allow(dead_code)]
pub fn partition_kind(index: usize) -> Option<&'static str> {
    with_device(index, |d| d.partition_kind()).ok().flatten()
}

// ------------------------------------------------------------
// Dysk w pamięci (testy systemu plików bez ruszania prawdziwego dysku)
// ------------------------------------------------------------

#[cfg(selftest)]
pub struct RamDisk {
    name: String,
    data: Vec<u8>,
}

#[cfg(selftest)]
impl RamDisk {
    pub fn new(name: &str, sectors: u64) -> Self {
        RamDisk { name: String::from(name), data: alloc::vec![0u8; sectors as usize * SECTOR_SIZE] }
    }
}

#[cfg(selftest)]
impl BlockDevice for RamDisk {
    fn name(&self) -> &str {
        &self.name
    }
    fn description(&self) -> String {
        alloc::format!("RAM disk, {} KiB", self.data.len() / 1024)
    }
    fn sector_count(&self) -> u64 {
        (self.data.len() / SECTOR_SIZE) as u64
    }
    fn read_only(&self) -> bool {
        false
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        check_range(self.sector_count(), lba, buf.len())?;
        let o = lba as usize * SECTOR_SIZE;
        buf.copy_from_slice(&self.data[o..o + buf.len()]);
        Ok(())
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        check_range(self.sector_count(), lba, buf.len())?;
        let o = lba as usize * SECTOR_SIZE;
        self.data[o..o + buf.len()].copy_from_slice(buf);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
}


