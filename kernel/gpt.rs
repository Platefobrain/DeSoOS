// M16b: tablica partycji GPT – tylko odczyt.
//
// Dysk z GPT: sektor 0 = "ochronny" MBR (typ 0xEE), blok 1 = nagłówek
// "EFI PART" (adres tablicy wpisów, ich liczba i rozmiar, sumy CRC32),
// dalej wpisy po 128 B: GUID typu, początek i koniec (w blokach urządzenia
// – 512 albo 4096 B), nazwa w UTF-16.  Obie sumy CRC32 są sprawdzane;
// uszkodzony nagłówek = brak partycji (nic nie zgadujemy).
//
// Używa tego block::scan_partitions – partycje stają się osobnymi dyskami.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::block::{self, BlockError, SECTOR_SIZE};

pub struct GptPartition {
    /// Numer wpisu w tablicy (od 1, jak w Linuksie).
    pub index: usize,
    /// Początek i długość w sektorach po 512 B.
    pub first_sector: u64,
    pub sectors: u64,
    #[allow(dead_code)]
    pub type_guid: [u8; 16],
    pub name: String,
    pub kind: &'static str,
}

/// GUID w zapisie tekstowym -> bajty jak na dysku (pierwsze 3 pola little-endian).
const fn guid(s: &[u8; 36]) -> [u8; 16] {
    const fn hex(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }
    const fn byte(s: &[u8; 36], i: usize) -> u8 {
        hex(s[i]) << 4 | hex(s[i + 1])
    }
    // Pozycje par cyfr w "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
    let p = [6, 4, 2, 0, 11, 9, 16, 14, 19, 21, 24, 26, 28, 30, 32, 34];
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = byte(s, p[i]);
        i += 1;
    }
    out
}

pub const ESP: [u8; 16] = guid(b"C12A7328-F81F-11D2-BA4B-00A0C93EC93B");

/// Znane typy partycji: (GUID, nazwa).
pub const KINDS: &[([u8; 16], &str)] = &[
    (ESP, "EFI System"),
    (guid(b"0FC63DAF-8483-4772-8E79-3D69D8477DE4"), "Linux filesystem"),
    (guid(b"0657FD6D-A4AB-43C4-84E5-0933C84B4F4F"), "Linux swap"),
    (guid(b"E6D6D379-F507-44C2-A23C-238F2A3DF928"), "Linux LVM"),
    (guid(b"A19D880F-05FC-4D3B-A006-743F0F84911E"), "Linux RAID"),
    (guid(b"4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709"), "Linux root (x86-64)"),
    (guid(b"BC13C2FF-59E6-4262-A352-B275FD6F7172"), "Linux /boot (XBOOTLDR)"),
    (guid(b"EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"), "Microsoft basic data"),
    (guid(b"E3C9E316-0B5C-4DB8-817D-F92DF00215AE"), "Microsoft reserved"),
    (guid(b"DE94BBA4-06D1-4D40-A16A-BFD50179D6AC"), "Windows recovery"),
    (guid(b"21686148-6449-6E6F-744E-656564454649"), "BIOS boot"),
];

pub fn kind_name(type_guid: &[u8; 16]) -> &'static str {
    KINDS.iter().find(|(g, _)| g == type_guid).map(|(_, n)| *n).unwrap_or("unknown type")
}

// ------------------------------------------------------------
// CRC32 (IEEE, jak w GPT / zip)
// ------------------------------------------------------------

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Partycje GPT dysku; Ok(None) = dysk bez GPT (albo z uszkodzonym).
pub fn read(disk: usize) -> Result<Option<Vec<GptPartition>>, BlockError> {
    let (bs, total) = block::with_device(disk, |d| (d.logical_block_size(), d.sector_count()))?;
    if bs < SECTOR_SIZE || bs % SECTOR_SIZE != 0 {
        return Ok(None);
    }
    let spb = (bs / SECTOR_SIZE) as u64; // sektorów 512 B na blok urządzenia
    if total < 3 * spb {
        return Ok(None);
    }

    // Ochronny MBR: wpis typu 0xEE.
    let mut mbr = [0u8; SECTOR_SIZE];
    block::read(disk, 0, &mut mbr)?;
    let protective = mbr[510] == 0x55 && mbr[511] == 0xAA && (0..4).any(|i| mbr[446 + i * 16 + 4] == 0xEE);
    if !protective {
        return Ok(None);
    }

    let mut hdr = vec![0u8; bs];
    block::read(disk, spb, &mut hdr)?;
    if &hdr[0..8] != b"EFI PART" {
        return Ok(None);
    }
    let hsize = u32_at(&hdr, 12) as usize;
    if !(92..=bs).contains(&hsize) {
        return Ok(None);
    }
    let mut check = hdr[..hsize].to_vec();
    check[16..20].fill(0);
    if crc32(&check) != u32_at(&hdr, 16) {
        crate::serial_println!("[GPT] disk {}: header CRC mismatch - partitions ignored", disk);
        return Ok(None);
    }
    let entries_lba = u64_at(&hdr, 72);
    let count = u32_at(&hdr, 80) as usize;
    let esize = u32_at(&hdr, 84) as usize;
    if esize < 128 || esize % 8 != 0 || count == 0 || count > 1024 {
        return Ok(None);
    }
    let bytes = count * esize;
    let sectors = bytes.div_ceil(SECTOR_SIZE);
    let first = entries_lba.checked_mul(spb).ok_or(BlockError::OutOfRange)?;
    if first + sectors as u64 > total {
        return Ok(None);
    }
    let mut table = vec![0u8; sectors * SECTOR_SIZE];
    block::read(disk, first, &mut table)?;
    if crc32(&table[..bytes]) != u32_at(&hdr, 88) {
        crate::serial_println!("[GPT] disk {}: partition table CRC mismatch - partitions ignored", disk);
        return Ok(None);
    }

    let mut out = Vec::new();
    for i in 0..count {
        let e = &table[i * esize..(i + 1) * esize];
        let mut type_guid = [0u8; 16];
        type_guid.copy_from_slice(&e[0..16]);
        if type_guid == [0u8; 16] {
            continue; // pusty wpis
        }
        let (lo, hi) = (u64_at(e, 32), u64_at(e, 40));
        if hi < lo {
            continue;
        }
        let (Some(start), Some(len)) = (lo.checked_mul(spb), (hi - lo + 1).checked_mul(spb)) else { continue };
        if start.checked_add(len).map_or(true, |end| end > total) {
            continue; // poza dyskiem – pomijamy
        }
        let units: Vec<u16> = e[56..128].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
        out.push(GptPartition {
            index: i + 1,
            first_sector: start,
            sectors: len,
            type_guid,
            name: String::from_utf16_lossy(&units),
            kind: kind_name(&type_guid),
        });
    }
    Ok(Some(out))
}

/// Testy: zapisuje GPT z jedną partycją `type_guid` od bloku 2048 do końca
/// (minus kopia zapasowa), na dysku o blokach 512 B.
#[cfg(selftest)]
pub fn write_test_gpt(disk: usize, type_guid: [u8; 16], name: &str) -> Result<(u64, u64), BlockError> {
    let total = block::with_device(disk, |d| d.sector_count())?;
    let last_usable = total - 34;
    let (first, last) = (2048u64, last_usable);
    // Ochronny MBR.
    let mut mbr = [0u8; SECTOR_SIZE];
    mbr[446 + 4] = 0xEE;
    mbr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    mbr[446 + 12..446 + 16].copy_from_slice(&((total - 1).min(0xFFFF_FFFF) as u32).to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    block::write(disk, 0, &mbr)?;
    // Tablica: 128 wpisów x 128 B = 32 sektory od LBA 2.
    let mut table = vec![0u8; 128 * 128];
    table[0..16].copy_from_slice(&type_guid);
    table[16..32].copy_from_slice(&[0x5a; 16]);
    table[32..40].copy_from_slice(&first.to_le_bytes());
    table[40..48].copy_from_slice(&last.to_le_bytes());
    for (i, u) in name.encode_utf16().take(36).enumerate() {
        table[56 + i * 2..58 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    block::write(disk, 2, &table)?;
    let mut hdr = [0u8; SECTOR_SIZE];
    hdr[0..8].copy_from_slice(b"EFI PART");
    hdr[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    hdr[12..16].copy_from_slice(&92u32.to_le_bytes());
    hdr[24..32].copy_from_slice(&1u64.to_le_bytes());
    hdr[32..40].copy_from_slice(&(total - 1).to_le_bytes());
    hdr[40..48].copy_from_slice(&34u64.to_le_bytes());
    hdr[48..56].copy_from_slice(&last_usable.to_le_bytes());
    hdr[56..72].copy_from_slice(&[0x11; 16]);
    hdr[72..80].copy_from_slice(&2u64.to_le_bytes());
    hdr[80..84].copy_from_slice(&128u32.to_le_bytes());
    hdr[84..88].copy_from_slice(&128u32.to_le_bytes());
    hdr[88..92].copy_from_slice(&crc32(&table).to_le_bytes());
    let c = crc32(&hdr[..92]);
    hdr[16..20].copy_from_slice(&c.to_le_bytes());
    block::write(disk, 1, &hdr)?;
    Ok((first, last - first + 1))
}
