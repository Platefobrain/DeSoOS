// Test of the ublk protocol without hardware (kernel self-test USB TEST 3/5).
//
// The program pretends to be usbd with a USB stick: using the BLK handle it registers a disk
// (blk_attach – plain shared memory instead of a DMA buffer, 1 s timeout)
// and serves kernel requests, deliberately breaking the protocol for chosen sectors:
//   lba 100 – first a reply with someone else's id, then with a wrong block count
//             (the kernel must reject them), finally a correct one,
//   lba 200 – no reply (timeout, slot quarantined); the late
//             reply arrives before lba 201 is served (the slot comes back),
//   lba 300 – status ERROR_IO,
//   lba 400..402 – no reply (3 timeouts = the disk disappears),
//   the rest – pattern data (the kernel checks every byte).
// First the blk_attach errors: bad handle, missing rights, bad block size,
// 0 blocks / slots, buffer too small.  End: the kernel closes the channel (the disk
// disappeared) -> ERROR_CLOSED -> exit code 0 and "blktest: N checks OK".
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const SLOT: u64 = 64 * 1024;

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("blktest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

/// Data pattern – the kernel computes the same.
fn pat(sector: u64, i: usize) -> u8 {
    ((sector.wrapping_mul(13) as usize + i) ^ (sector >> 3) as usize) as u8
}

fn info(blocks: u64, bs: u32, slots: u32) -> BlkInfo {
    let mut desc = [0u8; 40];
    desc[..7].copy_from_slice(b"blktest");
    BlkInfo { blocks, block_size: bs, slots, timeout_ms: 1000, desc }
}

fn reply(c: u64, id: u32, status: i32, n: u32) {
    let mut r = [0u8; 16];
    r[0..4].copy_from_slice(&id.to_le_bytes());
    r[4..8].copy_from_slice(&status.to_le_bytes());
    r[8..12].copy_from_slice(&n.to_le_bytes());
    chan_send(c, &r, 0);
}

fn main(_args: Args) -> i32 {
    let mut n = 0;
    let blk = (3..16).find(|&h| handle_info(h).map(|(k, _)| k) == Ok(KIND_BLK));
    check!(n, blk.is_some(), "no BLK handle");
    let blk = blk.unwrap();
    let Ok((mine, theirs)) = channel_create() else { return 2 };
    let small = shm_create(SLOT);
    let buf = shm_create(4 * SLOT);
    check!(n, small >= 0 && buf >= 0, "shm_create");
    let (small, buf) = (small as u64, buf as u64);

    // Registration errors.
    check!(n, blk_attach(1, theirs, buf, &info(1024, 512, 4)) == ERROR_INVALID_HANDLE, "blk_attach with the console handle must be ERROR_INVALID_HANDLE");
    check!(n, blk_attach(blk, buf, buf, &info(1024, 512, 4)) == ERROR_INVALID_HANDLE, "blk_attach with SHM as the channel must be ERROR_INVALID_HANDLE");
    check!(n, blk_attach(blk, theirs, small, &info(1024, 512, 4)) == ERROR_INVALID_ARGUMENT, "buffer smaller than 4 slots must be ERROR_INVALID_ARGUMENT");
    check!(n, blk_attach(blk, theirs, buf, &info(1024, 1000, 4)) == ERROR_INVALID_ARGUMENT, "block size 1000 must be ERROR_INVALID_ARGUMENT");
    check!(n, blk_attach(blk, theirs, buf, &info(0, 512, 4)) == ERROR_INVALID_ARGUMENT, "0 blocks must be ERROR_INVALID_ARGUMENT");
    check!(n, blk_attach(blk, theirs, buf, &info(1024, 512, 0)) == ERROR_INVALID_ARGUMENT, "0 slots must be ERROR_INVALID_ARGUMENT");
    check!(n, blk_attach(blk, theirs, buf, &info(1024, 512, 9)) == ERROR_INVALID_ARGUMENT, "9 slots must be ERROR_INVALID_ARGUMENT");
    let weak = handle_dup(theirs, R_SEND | R_RECV);
    check!(n, weak >= 0 && blk_attach(blk, weak as u64, buf, &info(1024, 512, 4)) == ERROR_ACCESS_DENIED, "channel without TRANSFER must be ERROR_ACCESS_DENIED");
    close(weak as u64);
    let nodup = handle_dup(blk, R_DUP);
    check!(n, nodup >= 0 && blk_attach(nodup as u64, theirs, buf, &info(1024, 512, 4)) == ERROR_ACCESS_DENIED, "BLK without WRITE must be ERROR_ACCESS_DENIED");
    close(nodup as u64);
    close(small);

    let va = match shm_map(buf, PROT_READ | PROT_WRITE) {
        Ok(v) => v,
        Err(_) => return 2,
    };
    let disk = blk_attach(blk, theirs, buf, &info(1024, 512, 4));
    check!(n, disk >= 0, "blk_attach: {}", disk);
    close(theirs);

    // Serve requests until the kernel closes the channel.
    let mut msg = [0u8; 64];
    let mut ri = RecvInfo::default();
    let mut late: Option<(u32, u32)> = None;
    let mut served = 0u64;
    let mut bad = 0u64;
    loop {
        let r = chan_recv(mine, &mut msg, 0, &mut ri);
        if r == ERROR_CLOSED {
            break;
        }
        if r < 32 {
            bad += 1;
            continue;
        }
        let le32 = |i: usize| u32::from_le_bytes([msg[i], msg[i + 1], msg[i + 2], msg[i + 3]]);
        let (id, op, cnt, slot) = (le32(0), le32(4), le32(16), le32(20));
        let lba = le32(8) as u64 | (le32(12) as u64) << 32;
        if op != 1 || slot >= 4 || cnt == 0 || cnt as u64 * 512 > SLOT || lba + cnt as u64 > 1024 {
            bad += 1;
            reply(mine, id, -5, 0);
            continue;
        }
        served += 1;
        let fill = || {
            for s in 0..cnt as u64 {
                for i in 0..512usize {
                    unsafe { ((va + slot as u64 * SLOT + s * 512 + i as u64) as *mut u8).write_volatile(pat(lba + s, i)) };
                }
            }
        };
        match lba {
            100 => {
                reply(mine, id.wrapping_add(1000), 0, cnt);
                reply(mine, id, 0, cnt + 1);
                fill();
                reply(mine, id, 0, cnt);
            }
            200 => late = Some((id, cnt)),
            201 => {
                if let Some((lid, lcnt)) = late.take() {
                    reply(mine, lid, 0, lcnt);
                }
                fill();
                reply(mine, id, 0, cnt);
            }
            300 => reply(mine, id, -5, 0),
            400..=402 => {}
            _ => {
                fill();
                reply(mine, id, 0, cnt);
            }
        }
    }
    check!(n, bad == 0, "{} malformed requests from the kernel", bad);
    println!("blktest: {} checks OK, disk {} attached, {} requests served, kernel closed the channel", n, disk, served);
    0
}
