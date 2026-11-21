// Fake writable USB sticks with a device cache for USB DISK TEST (v0.80 stage B): a stick's
// "DeSo system" partition as /disk, the choice between sticks, the last known good time on a
// stick, power loss under ublk.
//
// Like /bin/blkwtest it pretends to be usbd (blk_attach with plain shared memory, 1 s
// timeout), but every stick has its own 4 MiB medium and a WRITE CACHE: a write lands in the
// cache (reads see it), only a confirmed FLUSH makes it durable.  Two sticks:
//   1 "blkd-1": partition 1 "EFI System" 40–2047, partition 2 "DeSo system" 2048–7999
//   2 "blkd-2": "EFI System" 40–2047, two "DeSo system" partitions 2048–4999 and 5000–7999
// At start only stick 1 is attached.  Test flags (op 9, `blocks`, sent to a stick):
//   0x20 detach this stick (it stays away; its media are kept)
//   0x40 replug this stick (it goes and comes back at once as a new instance, from its
//        DURABLE medium – what a stick unplugged without a FLUSH keeps)
//   0x80 exit (after the reply)
//   0x100 POWER LOSS at the k-th WRITE from now (k = bits 16..23, 0 = the next one): that write
//        and everything after it is lost, of the writes since the last FLUSH a random subset
//        (seed = bits 24..31) still reaches the medium – then the stick replugs
//   0x200 attach stick 2 (if away)
//   0x400 detach stick 2 (sent to stick 1)
//   0x800 attach stick 1 (if away; sent to stick 2)
//   0x1000 no power loss after all (disarm 0x100)
//   0x2000 damage sector s (bits 16..31) on the medium (a bad block)
//   0x4000 / 0x8000 this stick refuses every FLUSH from now on / not any more (kept over replugs)
// Ends when told to (0x80) or when no request came for 120 s: "blkdtest: N checks OK, ...".
#![no_std]
#![no_main]

#[path = "../lib/deso.rs"]
#[macro_use]
mod deso;

use deso::*;

entry!(main);

const SLOT: u64 = 64 * 1024;
const BLOCKS: u64 = 8192;
const BYTES: usize = (BLOCKS * 512) as usize;
const ESP: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
const SYS: &str = "1A0E2E7D-DE32-4C13-9442-9FCB2649CA02";

fn info(name: &[u8]) -> BlkInfo {
    let mut desc = [0u8; 40];
    desc[..name.len()].copy_from_slice(name);
    BlkInfo { blocks: BLOCKS, block_size: 512, slots: 4, timeout_ms: 1000, wp: 1, desc }
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

fn guid(s: &str) -> [u8; 16] {
    let mut h = [0u8; 32];
    let mut k = 0;
    for c in s.bytes().filter(|c| *c != b'-') {
        h[k] = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => c - b'A' + 10,
        };
        k += 1;
    }
    let byte = |i: usize| h[2 * i] << 4 | h[2 * i + 1];
    let order = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];
    let mut g = [0u8; 16];
    for (k, &i) in order.iter().enumerate() {
        g[k] = byte(i);
    }
    g
}

fn write_gpt(m: &mut [u8], parts: &[(&str, u64, u64)]) {
    m[446 + 4] = 0xEE;
    m[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    m[446 + 12..446 + 16].copy_from_slice(&((BLOCKS - 1) as u32).to_le_bytes());
    m[510] = 0x55;
    m[511] = 0xAA;
    let t = 2 * 512;
    for (i, (g, lo, hi)) in parts.iter().enumerate() {
        let e = t + i * 128;
        m[e..e + 16].copy_from_slice(&guid(g));
        m[e + 16..e + 32].copy_from_slice(&[0x60 + i as u8; 16]);
        m[e + 32..e + 40].copy_from_slice(&lo.to_le_bytes());
        m[e + 40..e + 48].copy_from_slice(&hi.to_le_bytes());
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
    m[h + 56..h + 72].copy_from_slice(&[0x44; 16]);
    m[h + 72..h + 80].copy_from_slice(&2u64.to_le_bytes());
    m[h + 80..h + 84].copy_from_slice(&128u32.to_le_bytes());
    m[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes());
    m[h + 88..h + 92].copy_from_slice(&table_crc.to_le_bytes());
    let c = crc32(&m[h..h + 92]);
    m[h + 16..h + 20].copy_from_slice(&c.to_le_bytes());
}

struct Stick {
    name: &'static [u8],
    /// What reads see (durable + the cache) and what survives a power loss.
    cached: &'static mut [u8],
    durable: &'static mut [u8],
    /// Sectors written since the last FLUSH.
    pending: &'static mut [u32],
    npending: usize,
    /// Present: (channel, buffer address).
    att: Option<(u64, u64)>,
    reg: (u32, u64),
    /// Power loss: (writes left before it, seed).
    crash: Option<(u32, u32)>,
    /// Every FLUSH refused (a stick whose cache cannot be flushed).
    bad_flush: bool,
}

impl Stick {
    fn attach(&mut self, blk: u64) -> bool {
        let Ok((mine, theirs)) = channel_create() else { return false };
        let buf = shm_create(4 * SLOT);
        if buf < 0 {
            return false;
        }
        let Ok(va) = shm_map(buf as u64, PROT_READ | PROT_WRITE) else { return false };
        let r = blk_attach(blk, theirs, buf as u64, &info(self.name));
        close(theirs);
        close(buf as u64);
        if r < 0 {
            println!("blkdtest: blk_attach {:?}: {}", core::str::from_utf8(self.name), r);
            return false;
        }
        self.att = Some((mine, va));
        self.reg = (0, 0);
        true
    }

    fn detach(&mut self) {
        if let Some((c, _)) = self.att.take() {
            close(c);
        }
    }

    /// The cache is lost: the medium is what was durable (plus `keep` of the pending writes).
    fn lose_cache(&mut self, seed: u32) {
        let mut x = seed.wrapping_mul(2654435761) | 1;
        for k in 0..self.npending {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            if x & 1 == 1 {
                let s = self.pending[k] as usize * 512;
                let (c, d) = (&self.cached[s..s + 512], &mut self.durable[s..s + 512]);
                d.copy_from_slice(c);
            }
        }
        self.cached.copy_from_slice(self.durable);
        self.npending = 0;
    }

    fn flush(&mut self) {
        for k in 0..self.npending {
            let s = self.pending[k] as usize * 512;
            let src = &self.cached[s..s + 512];
            self.durable[s..s + 512].copy_from_slice(src);
        }
        self.npending = 0;
    }
}

fn medium() -> Option<&'static mut [u8]> {
    let a = mmap(BYTES as u64, PROT_READ | PROT_WRITE).ok()?;
    Some(unsafe { core::slice::from_raw_parts_mut(a as *mut u8, BYTES) })
}

fn main(_args: Args) -> i32 {
    let Some(blk) = (3..16).find(|&h| handle_info(h).map(|(k, _)| k) == Ok(KIND_BLK)) else {
        println!("blkdtest: FAIL no BLK handle");
        return 1;
    };
    let mut sticks: [Stick; 2] = core::array::from_fn(|k| {
        let (c, d) = (medium().unwrap(), medium().unwrap());
        let p = mmap(16384 * 4, PROT_READ | PROT_WRITE).unwrap();
        let pending = unsafe { core::slice::from_raw_parts_mut(p as *mut u32, 16384) };
        Stick { name: if k == 0 { b"blkd-1" } else { b"blkd-2" }, cached: c, durable: d, pending, npending: 0, att: None, reg: (0, 0), crash: None, bad_flush: false }
    });
    write_gpt(sticks[0].durable, &[(ESP, 40, 2047), (SYS, 2048, 7999)]);
    write_gpt(sticks[1].durable, &[(ESP, 40, 2047), (SYS, 2048, 4999), (SYS, 5000, 7999)]);
    for s in sticks.iter_mut() {
        s.cached.copy_from_slice(s.durable);
    }
    if !sticks[0].attach(blk) {
        return 1;
    }
    let mut msg = [0u8; 64];
    let mut ri = RecvInfo::default();
    let (mut bad, mut writes, mut flushes, mut losses, mut replugs) = (0u64, 0u64, 0u64, 0u64, 0u64);
    'run: loop {
        let mut list = [(0u64, W_READABLE); 2];
        let mut who = [0usize; 2];
        let mut n = 0;
        for (k, s) in sticks.iter().enumerate() {
            if let Some((c, _)) = s.att {
                list[n] = (c, W_READABLE);
                who[n] = k;
                n += 1;
            }
        }
        if n == 0 {
            sleep_ms(50);
            continue;
        }
        let Ok(ready) = wait_many(&list[..n], 120_000) else { break };
        if ready == 0 {
            println!("blkdtest: FAIL no request from the kernel in 120 s");
            return 1;
        }
        for i in 0..n {
            if ready & (1 << i) == 0 {
                continue;
            }
            let k = who[i];
            let Some((chan, va)) = sticks[k].att else { continue };
            let r = chan_recv(chan, &mut msg, CHAN_NONBLOCK, &mut ri);
            if r == ERROR_CLOSED {
                sticks[k].att = None;
                continue;
            }
            if r < 48 {
                if r >= 0 {
                    bad += 1;
                }
                continue;
            }
            let le32 = |i: usize| u32::from_le_bytes([msg[i], msg[i + 1], msg[i + 2], msg[i + 3]]);
            let le64 = |i: usize| le32(i) as u64 | (le32(i + 4) as u64) << 32;
            let (id, op, cnt, slot) = (le32(0), le32(4), le32(16), le32(20));
            let (lba, generation) = (le64(8), le64(24));
            let inside = cnt > 0 && slot < 4 && cnt as u64 * 512 <= SLOT && lba.checked_add(cnt as u64).map_or(false, |e| e <= BLOCKS);
            let s = &mut sticks[k];
            match op {
                1 if inside => {
                    for b in 0..cnt as usize * 512 {
                        unsafe { ((va + slot as u64 * SLOT + b as u64) as *mut u8).write_volatile(s.cached[lba as usize * 512 + b]) };
                    }
                    reply(chan, id, 0, cnt);
                }
                2 if inside => {
                    if s.reg.0 == 0 || generation != s.reg.1 {
                        bad += 1;
                    }
                    if let Some((left, seed)) = s.crash {
                        if left == 0 {
                            // Power loss: this write and the rest never happen.
                            s.crash = None;
                            s.lose_cache(seed);
                            s.detach();
                            losses += 1;
                            sleep_ms(200);
                            if !s.attach(blk) {
                                return 1;
                            }
                            continue;
                        }
                        s.crash = Some((left - 1, seed));
                    }
                    writes += 1;
                    for b in 0..cnt as usize * 512 {
                        s.cached[lba as usize * 512 + b] = unsafe { ((va + slot as u64 * SLOT + b as u64) as *const u8).read_volatile() };
                    }
                    for sec in lba..lba + cnt as u64 {
                        if s.npending == s.pending.len() {
                            s.flush(); // a full cache writes itself back (a real stick does too)
                        }
                        s.pending[s.npending] = sec as u32;
                        s.npending += 1;
                    }
                    reply(chan, id, 0, cnt);
                }
                3 => {
                    if s.reg.0 == 0 || generation != s.reg.1 {
                        bad += 1;
                    }
                    if s.reg.0 == 1 {
                        s.reg = (0, 0);
                    }
                    if s.bad_flush {
                        reply(chan, id, -5, 0);
                        continue;
                    }
                    flushes += 1;
                    s.flush();
                    reply(chan, id, 0, 0);
                }
                4 => {
                    s.reg = if cnt == 0 { (0, 0) } else { (cnt, generation) };
                    reply(chan, id, 0, cnt);
                }
                9 => {
                    reply(chan, id, 0, 0);
                    if cnt & 0x80 != 0 {
                        break 'run;
                    }
                    if cnt & 0x100 != 0 {
                        s.crash = Some(((cnt >> 16) & 0xFF, (cnt >> 24) & 0xFF));
                    }
                    if cnt & 0x1000 != 0 {
                        s.crash = None;
                    }
                    if cnt & 0x4000 != 0 {
                        s.bad_flush = true;
                    }
                    if cnt & 0x8000 != 0 {
                        s.bad_flush = false;
                    }
                    if cnt & 0x2000 != 0 {
                        let sec = (cnt >> 16) as usize * 512;
                        s.durable[sec + 100] ^= 0xFF;
                        s.cached[sec + 100] ^= 0xFF;
                    }
                    if cnt & 0x20 != 0 {
                        s.detach();
                    }
                    if cnt & 0x40 != 0 {
                        // Unplugged without a FLUSH: the cache is lost.
                        s.lose_cache(0);
                        s.detach();
                        sleep_ms(200);
                        if !s.attach(blk) {
                            return 1;
                        }
                        replugs += 1;
                    }
                    if cnt & 0x200 != 0 && sticks[1].att.is_none() && !sticks[1].attach(blk) {
                        return 1;
                    }
                    if cnt & 0x400 != 0 {
                        sticks[1].detach();
                    }
                    if cnt & 0x800 != 0 && sticks[0].att.is_none() && !sticks[0].attach(blk) {
                        return 1;
                    }
                }
                _ => {
                    bad += 1;
                    reply(chan, id, -5, 0);
                }
            }
        }
    }
    println!("blkdtest: 1 checks OK, writes {} flushes {} power losses {} replugs {} bad {}", writes, flushes, losses, replugs, bad);
    if bad != 0 {
        return 1;
    }
    0
}
