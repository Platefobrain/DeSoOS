// M20.f: test protokołu ublk bez sprzętu (samotest jądra USB TEST 3/5).
//
// Program udaje usbd z pendrive'em: z uchwytem BLK rejestruje dysk
// (blk_attach – zwykła pamięć współdzielona zamiast bufora DMA, timeout 1 s)
// i obsługuje żądania jądra, celowo psując protokół dla wybranych sektorów:
//   lba 100 – najpierw odpowiedź z cudzym id, potem ze złą liczbą bloków
//             (jądro ma je odrzucić), na końcu poprawna,
//   lba 200 – brak odpowiedzi (timeout, slot w kwarantannie); spóźniona
//             odpowiedź przychodzi przed obsługą lba 201 (slot wraca),
//   lba 300 – status EIO,
//   lba 400..402 – brak odpowiedzi (3 timeouty = dysk znika),
//   reszta – dane wzoru (jądro sprawdza każdy bajt).
// Najpierw błędy blk_attach: zły uchwyt, brak praw, zły rozmiar bloku,
// 0 bloków / slotów, za mały bufor.  Koniec: jądro zamyka kanał (dysk
// zniknął) -> EPIPE -> kod 0 i "blktest: N checks OK".
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const EINVAL: i64 = -22;
const EACCES: i64 = -13;
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

/// Wzór danych – to samo liczy jądro.
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

    // Błędy rejestracji.
    check!(n, blk_attach(1, theirs, buf, &info(1024, 512, 4)) == EBADF, "blk_attach with the console handle must be EBADF");
    check!(n, blk_attach(blk, buf, buf, &info(1024, 512, 4)) == EBADF, "blk_attach with SHM as the channel must be EBADF");
    check!(n, blk_attach(blk, theirs, small, &info(1024, 512, 4)) == EINVAL, "buffer smaller than 4 slots must be EINVAL");
    check!(n, blk_attach(blk, theirs, buf, &info(1024, 1000, 4)) == EINVAL, "block size 1000 must be EINVAL");
    check!(n, blk_attach(blk, theirs, buf, &info(0, 512, 4)) == EINVAL, "0 blocks must be EINVAL");
    check!(n, blk_attach(blk, theirs, buf, &info(1024, 512, 0)) == EINVAL, "0 slots must be EINVAL");
    check!(n, blk_attach(blk, theirs, buf, &info(1024, 512, 9)) == EINVAL, "9 slots must be EINVAL");
    let weak = handle_dup(theirs, R_SEND | R_RECV);
    check!(n, weak >= 0 && blk_attach(blk, weak as u64, buf, &info(1024, 512, 4)) == EACCES, "channel without TRANSFER must be EACCES");
    close(weak as u64);
    let nodup = handle_dup(blk, R_DUP);
    check!(n, nodup >= 0 && blk_attach(nodup as u64, theirs, buf, &info(1024, 512, 4)) == EACCES, "BLK without WRITE must be EACCES");
    close(nodup as u64);
    close(small);

    let va = match shm_map(buf, PROT_READ | PROT_WRITE) {
        Ok(v) => v,
        Err(_) => return 2,
    };
    let disk = blk_attach(blk, theirs, buf, &info(1024, 512, 4));
    check!(n, disk >= 0, "blk_attach: {}", disk);
    close(theirs);

    // Obsługa żądań do zamknięcia kanału przez jądro.
    let mut msg = [0u8; 64];
    let mut ri = RecvInfo::default();
    let mut late: Option<(u32, u32)> = None;
    let mut served = 0u64;
    let mut bad = 0u64;
    loop {
        let r = chan_recv(mine, &mut msg, 0, &mut ri);
        if r == EPIPE {
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
