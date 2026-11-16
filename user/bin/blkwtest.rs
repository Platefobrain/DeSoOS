// A writable fake USB stick for the kernel's write protocol tests (USB WRITE TEST 1/3) –
// the kernel side of the write rules without hardware.
//
// Like /bin/blktest it pretends to be usbd: with the BLK handle it registers disks
// (blk_attach – plain shared memory instead of a DMA buffer, 1 s timeout) and serves the
// kernel's requests from a 4 MiB medium in memory with a GPT on it:
//   partition 1 "EFI System"     blocks   40 – 2047
//   partition 2 "DeSoOS system"  blocks 2048 – 7999 (blocks 8000 – 8191: outside every partition)
// It accepts every WRITE / FLUSH inside the medium – it is NOT a lock: the kernel's own two
// locks (the partition, ublk) are what is tested; the medium shows what got through.  It
// does check that what the kernel sends is well formed: a probe without a range and with
// a FLUSH limit of 1, rw with a range and session 0, format with a session, every WRITE /
// FLUSH with the generation of the last registration; anything else counts as "bad".
// Test flags (op 9, `blocks`): 2 – fail the k-th WRITE from now (k in bits 8..15), 4 – hold
// the next FLUSH reply, 8 – fail the next FLUSH, 16 – hold the next WRITE reply (a held
// reply goes out before the next request is served – late), 0x40 – replug (the stick goes and
// comes back as a new instance with the same medium), 0x80 – reply and exit.
// A second disk ("blkwtest-wp", 64 blocks, write protection unknown) shows the kernel
// refusing every registration on such a disk.
//   blkwtest            the two disks, until flag 0x80 – "blkwtest: N checks OK, ..."
//   blkwtest overflow   one blk_attach that must fail (the kernel's generation counter is
//                       used up) – "blkwtest: overflow refused"
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const SLOT: u64 = 64 * 1024;
const BLOCKS: u64 = 8192;
const P1: (u64, u64) = (40, 2047);
const P2: (u64, u64) = (2048, 7999);

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("blkwtest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

fn info(blocks: u64, wp: u32, name: &[u8]) -> BlkInfo {
    let mut desc = [0u8; 40];
    desc[..name.len()].copy_from_slice(name);
    BlkInfo { blocks, block_size: 512, slots: 4, timeout_ms: 1000, wp, desc }
}

fn reply(c: u64, id: u32, status: i32, n: u32) {
    let mut r = [0u8; 16];
    r[0..4].copy_from_slice(&id.to_le_bytes());
    r[4..8].copy_from_slice(&status.to_le_bytes());
    r[8..12].copy_from_slice(&n.to_le_bytes());
    chan_send(c, &r, 0);
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}

/// GUID text -> bytes as on disk.
fn guid(s: &str) -> [u8; 16] {
    let h: [u8; 32] = {
        let mut out = [0u8; 32];
        let mut k = 0;
        for c in s.bytes().filter(|c| *c != b'-') {
            out[k] = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => c - b'A' + 10,
            };
            k += 1;
        }
        out
    };
    let byte = |i: usize| h[2 * i] << 4 | h[2 * i + 1];
    let order = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];
    let mut g = [0u8; 16];
    for (k, &i) in order.iter().enumerate() {
        g[k] = byte(i);
    }
    g
}

/// The protective MBR, the GPT header and its table at the start of the medium.
fn write_gpt(m: &mut [u8]) {
    m[446 + 4] = 0xEE;
    m[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    m[446 + 12..446 + 16].copy_from_slice(&((BLOCKS - 1) as u32).to_le_bytes());
    m[510] = 0x55;
    m[511] = 0xAA;
    let t = 2 * 512;
    for (i, (g, (lo, hi), name)) in [(guid("C12A7328-F81F-11D2-BA4B-00A0C93EC93B"), P1, "EFI"), (guid("1A0E2E7D-DE32-4C13-9442-9FCB2649CA02"), P2, "DeSoOS system")].iter().enumerate() {
        let e = t + i * 128;
        m[e..e + 16].copy_from_slice(g);
        m[e + 16..e + 32].copy_from_slice(&[0x40 + i as u8; 16]);
        m[e + 32..e + 40].copy_from_slice(&lo.to_le_bytes());
        m[e + 40..e + 48].copy_from_slice(&hi.to_le_bytes());
        for (k, u) in name.encode_utf16().enumerate() {
            m[e + 56 + 2 * k..e + 58 + 2 * k].copy_from_slice(&u.to_le_bytes());
        }
    }
    let table_crc = crc32(&m[t..t + 128 * 128]);
    let h = 512;
    m[h..h + 8].copy_from_slice(b"EFI PART");
    m[h + 8..h + 12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    m[h + 12..h + 16].copy_from_slice(&92u32.to_le_bytes());
    m[h + 24..h + 32].copy_from_slice(&1u64.to_le_bytes());
    m[h + 32..h + 40].copy_from_slice(&(BLOCKS - 1).to_le_bytes());
    m[h + 40..h + 48].copy_from_slice(&34u64.to_le_bytes());
    m[h + 48..h + 56].copy_from_slice(&(BLOCKS - 34).to_le_bytes());
    m[h + 56..h + 72].copy_from_slice(&[0x33; 16]);
    m[h + 72..h + 80].copy_from_slice(&2u64.to_le_bytes());
    m[h + 80..h + 84].copy_from_slice(&128u32.to_le_bytes());
    m[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes());
    m[h + 88..h + 92].copy_from_slice(&table_crc.to_le_bytes());
    let c = crc32(&m[h..h + 92]);
    m[h + 16..h + 20].copy_from_slice(&c.to_le_bytes());
}

struct Dev {
    chan: u64,
    va: u64,
    blocks: u64,
    /// The last registration: kind, generation.
    reg: (u32, u64),
    fail_in: Option<u32>,
    hold_flush: bool,
    fail_flush: bool,
    hold_write: bool,
    held: Option<(u32, i32, u32)>,
}

fn main(args: Args) -> i32 {
    let mut n = 0;
    let blk = (3..16).find(|&h| handle_info(h).map(|(k, _)| k) == Ok(KIND_BLK));
    check!(n, blk.is_some(), "no BLK handle");
    let blk = blk.unwrap();
    if args.get(1) == Some("overflow") {
        let Ok((_, theirs)) = channel_create() else { return 2 };
        let buf = shm_create(4 * SLOT);
        check!(n, buf >= 0, "shm_create");
        let r = blk_attach(blk, theirs, buf as u64, &info(64, 1, b"blkwtest-overflow"));
        check!(n, r == ERROR_NO_SPACE, "blk_attach with the generation counter used up: {} (want ERROR_NO_SPACE)", r);
        println!("blkwtest: overflow refused");
        return 0;
    }
    let Ok(mem) = mmap(BLOCKS * 512, PROT_READ | PROT_WRITE) else { return 2 };
    let medium = unsafe { core::slice::from_raw_parts_mut(mem as *mut u8, (BLOCKS * 512) as usize) };
    write_gpt(medium);
    let mut devs: [Option<Dev>; 2] = [None, None];
    for (k, (blocks, wp, name)) in [(BLOCKS, 1u32, &b"blkwtest"[..]), (64, 0, &b"blkwtest-wp"[..])].iter().enumerate() {
        let Ok((mine, theirs)) = channel_create() else { return 2 };
        let buf = shm_create(4 * SLOT);
        check!(n, buf >= 0, "shm_create");
        let Ok(va) = shm_map(buf as u64, PROT_READ | PROT_WRITE) else { return 2 };
        let disk = blk_attach(blk, theirs, buf as u64, &info(*blocks, *wp, name));
        check!(n, disk >= 0, "blk_attach {:?}: {}", core::str::from_utf8(name), disk);
        close(theirs);
        devs[k] = Some(Dev { chan: mine, va, blocks: *blocks, reg: (0, 0), fail_in: None, hold_flush: false, fail_flush: false, hold_write: false, held: None });
    }
    let mut msg = [0u8; 64];
    let mut ri = RecvInfo::default();
    let (mut bad, mut writes, mut flushes, mut regs, mut replugs) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut done = false;
    while !done {
        let list = [(devs[0].as_ref().unwrap().chan, W_READABLE), (devs[1].as_ref().unwrap().chan, W_READABLE)];
        let Ok(ready) = wait_many(&list, 60_000) else { break };
        if ready == 0 {
            println!("blkwtest: FAIL no request from the kernel in 60 s");
            return 1;
        }
        for k in 0..2 {
            if ready & (1 << k) == 0 {
                continue;
            }
            let d = devs[k].as_mut().unwrap();
            let r = chan_recv(d.chan, &mut msg, CHAN_NONBLOCK, &mut ri);
            if r == ERROR_CLOSED {
                done = true;
                break;
            }
            if r < 0 {
                continue;
            }
            if let Some((hid, hst, hn)) = d.held.take() {
                reply(d.chan, hid, hst, hn);
            }
            if r < 48 {
                bad += 1;
                continue;
            }
            let le32 = |i: usize| u32::from_le_bytes([msg[i], msg[i + 1], msg[i + 2], msg[i + 3]]);
            let le64 = |i: usize| le32(i) as u64 | (le32(i + 4) as u64) << 32;
            let (id, op, cnt, slot) = (le32(0), le32(4), le32(16), le32(20));
            let (lba, generation, session, len) = (le64(8), le64(24), le64(32), le64(40));
            let inside = cnt > 0 && slot < 4 && cnt as u64 * 512 <= SLOT && lba.checked_add(cnt as u64).map_or(false, |e| e <= d.blocks);
            match op {
                1 if inside => {
                    for s in 0..cnt as u64 {
                        for i in 0..512u64 {
                            let b = if d.blocks == BLOCKS { medium[((lba + s) * 512 + i) as usize] } else { 0 };
                            unsafe { ((d.va + slot as u64 * SLOT + s * 512 + i) as *mut u8).write_volatile(b) };
                        }
                    }
                    reply(d.chan, id, 0, cnt);
                }
                2 if inside => {
                    writes += 1;
                    if d.reg.0 == 0 || generation != d.reg.1 {
                        bad += 1;
                    }
                    let fail = match d.fail_in {
                        Some(0) => {
                            d.fail_in = None;
                            true
                        }
                        Some(x) => {
                            d.fail_in = Some(x - 1);
                            false
                        }
                        None => false,
                    };
                    if fail {
                        reply(d.chan, id, -5, 0);
                        continue;
                    }
                    for s in 0..cnt as u64 {
                        for i in 0..512u64 {
                            medium[((lba + s) * 512 + i) as usize] = unsafe { ((d.va + slot as u64 * SLOT + s * 512 + i) as *const u8).read_volatile() };
                        }
                    }
                    if d.hold_write {
                        d.hold_write = false;
                        d.held = Some((id, 0, cnt));
                    } else {
                        reply(d.chan, id, 0, cnt);
                    }
                }
                3 => {
                    flushes += 1;
                    if d.reg.0 == 0 || generation != d.reg.1 {
                        bad += 1;
                    }
                    if d.reg.0 == 1 {
                        d.reg = (0, 0); // a probe is used up by its FLUSH
                    }
                    let st = if d.fail_flush { -5 } else { 0 };
                    d.fail_flush = false;
                    if d.hold_flush {
                        d.hold_flush = false;
                        d.held = Some((id, st, 0));
                    } else {
                        reply(d.chan, id, st, 0);
                    }
                }
                4 => {
                    regs += 1;
                    let ok = generation != 0
                        && match cnt {
                            0 => true,
                            1 => lba == 0 && len == 0 && session == 0 && slot == 1,
                            2 => len > 0 && session == 0 && lba.checked_add(len).map_or(false, |e| e <= d.blocks),
                            3 => len > 0 && session != 0 && lba.checked_add(len).map_or(false, |e| e <= d.blocks),
                            _ => false,
                        };
                    if !ok {
                        bad += 1;
                        reply(d.chan, id, -5, 0);
                        continue;
                    }
                    d.reg = if cnt == 0 { (0, 0) } else { (cnt, generation) };
                    reply(d.chan, id, 0, cnt);
                }
                9 => {
                    if cnt & 2 != 0 {
                        d.fail_in = Some((cnt >> 8) & 0xFF);
                    }
                    d.hold_flush = cnt & 4 != 0;
                    d.fail_flush = cnt & 8 != 0;
                    d.hold_write = cnt & 16 != 0;
                    reply(d.chan, id, 0, 0);
                    if cnt & 0x80 != 0 {
                        done = true;
                        break;
                    }
                    if cnt & 0x40 != 0 && k == 0 {
                        // Replug: this stick goes (its channel closes) and comes back as a new
                        // instance with the same medium and layout.
                        close(d.chan);
                        sleep_ms(300);
                        let Ok((mine, theirs)) = channel_create() else { return 2 };
                        let buf = shm_create(4 * SLOT);
                        let Ok(va) = shm_map(buf as u64, PROT_READ | PROT_WRITE) else { return 2 };
                        let disk = blk_attach(blk, theirs, buf as u64, &info(BLOCKS, 1, b"blkwtest"));
                        close(theirs);
                        if disk < 0 {
                            println!("blkwtest: FAIL replug blk_attach: {}", disk);
                            return 1;
                        }
                        d.chan = mine;
                        d.va = va;
                        d.reg = (0, 0);
                        d.held = None;
                        replugs += 1;
                    }
                }
                _ => {
                    bad += 1;
                    reply(d.chan, id, -5, 0);
                }
            }
        }
    }
    println!("blkwtest: {} checks OK, writes {} flushes {} registrations {} replugs {} bad {}", n, writes, flushes, regs, replugs, bad);
    if bad != 0 {
        return 1;
    }
    0
}
