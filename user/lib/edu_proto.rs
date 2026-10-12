// M19.f: protokół usługi `edud` (sterownik urządzenia `edu` w user space).
//
// Klient rozmawia z usługą przez własny kanał.  Każda prośba i odpowiedź to
// jeden komunikat: nagłówek 16 B (little-endian) + dane.
//
//   prośba:     [op: u32, 0: u32, arg: u64] + dane
//   odpowiedź:  [status: i32, op: u32, wartość: u64] + dane   (status < 0 = -errno)
//
// Połączenie: kanał „połączeń” usługi (slot 4) przyjmuje komunikat z jednym
// uchwytem – końcem kanału klienta (dane: nazwa usługi, np. "edu").
#![allow(dead_code)]

/// Identyfikacja urządzenia (rejestr 0x00 edu) – wartość: 0x010000ed.
pub const OP_PING: u32 = 1;
/// Silnia `arg` liczona przez urządzenie (koniec zgłoszony przerwaniem).
pub const OP_FACT: u32 = 2;
/// Dane przez DMA: bufor usługi -> urządzenie -> bufor (urządzenie kopiuje).
pub const OP_COPY: u32 = 3;
/// Statystyka usługi – wartość: prośby; dane: [prośby, przerwania, klienci].
pub const OP_STATS: u32 = 4;

pub const HDR: usize = 16;
/// Najwięcej danych w OP_COPY (komunikat ≤ 4096 B razem z nagłówkiem).
pub const COPY_MAX: usize = 4000;

pub fn request(op: u32, arg: u64, data: &[u8], out: &mut [u8]) -> usize {
    out[..4].copy_from_slice(&op.to_le_bytes());
    out[4..8].copy_from_slice(&0u32.to_le_bytes());
    out[8..16].copy_from_slice(&arg.to_le_bytes());
    out[HDR..HDR + data.len()].copy_from_slice(data);
    HDR + data.len()
}

pub fn reply(status: i32, op: u32, value: u64, data: &[u8], out: &mut [u8]) -> usize {
    out[..4].copy_from_slice(&status.to_le_bytes());
    out[4..8].copy_from_slice(&op.to_le_bytes());
    out[8..16].copy_from_slice(&value.to_le_bytes());
    out[HDR..HDR + data.len()].copy_from_slice(data);
    HDR + data.len()
}

pub fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

pub fn u64_at(b: &[u8], i: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[i..i + 8]);
    u64::from_le_bytes(a)
}
