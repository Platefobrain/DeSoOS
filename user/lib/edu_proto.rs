// Protocol of the `edud` service (user-space driver for the `edu` device).
//
// A client talks to the service over its own channel.  Each request and reply is
// one message: a 16 B header (little-endian) + data.
//
//   request:  [op: u32, 0: u32, arg: u64] + data
//   reply:    [status: i32, op: u32, value: u64] + data   (status < 0 = -errno)
//
// Connecting: the service's "connections" channel (slot 4) accepts a message with one
// handle – the client's end of a channel (data: service name, e.g. "edu").
#![allow(dead_code)]

/// Device identification (edu register 0x00) – value: 0x010000ed.
pub const OP_PING: u32 = 1;
/// Factorial of `arg` computed by the device (completion signalled by an interrupt).
pub const OP_FACT: u32 = 2;
/// Data via DMA: service buffer -> device -> buffer (the device copies).
pub const OP_COPY: u32 = 3;
/// Service statistics – value: requests; data: [requests, interrupts, clients].
pub const OP_STATS: u32 = 4;

pub const HDR: usize = 16;
/// Maximum data in OP_COPY (message ≤ 4096 B including the header).
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
