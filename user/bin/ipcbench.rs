// M18.f: pomiar IPC – opóźnienie wymiany (ping-pong 8 B), przepustowość
// kanału (komunikaty 4 KiB w jedną stronę) i te same dane przez kanał
// (kopiowanie przez jądro) kontra pamięć współdzielona (dzwonek przez kanał).
// Wynik: linia "ipcbench: ..." dla ludzi i "ipcbench-result k=v ..." dla
// [RESULT] w autostressie; kod 0.  Dziecko: `ipcbench echo|sink|shm`
// (0 = kanał, 1 = pamięć w trybie shm).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const PINGPONG: u64 = 20_000;
const SINK_MSGS: u64 = 20_000;
/// Dane do porównania kanał / pamięć: 16 MiB w kawałkach 1 MiB.
const CHUNK: u64 = 1024 * 1024;
const CHUNKS: u64 = 16;

fn u64_of(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_le_bytes(a)
}

fn echo() -> i32 {
    let mut buf = [0u8; 8];
    let mut info = RecvInfo::default();
    while chan_recv(0, &mut buf, 0, &mut info) == 8 {
        if chan_send(0, &buf, 0) != 0 {
            return 2;
        }
    }
    0
}

/// Odbiera komunikaty (4 KiB albo kawałki danych) i sumuje bajty; pusty
/// komunikat = "podaj sumę".
fn sink() -> i32 {
    let mut buf = [0u8; MSG_MAX];
    let mut info = RecvInfo::default();
    let mut sum = 0u64;
    loop {
        let r = chan_recv(0, &mut buf, 0, &mut info);
        if r < 0 {
            return 0;
        }
        if r == 0 {
            chan_send(0, &sum.to_le_bytes(), 0);
            sum = 0;
            continue;
        }
        sum += buf[..r as usize].iter().map(|&b| b as u64).sum::<u64>();
    }
}

/// Na każdy dzwonek sumuje cały kawałek wspólnej pamięci i odpowiada.
fn shm_reader() -> i32 {
    let Ok(a) = shm_map(1, PROT_READ) else { return 3 };
    let m = unsafe { core::slice::from_raw_parts(a as *const u8, CHUNK as usize) };
    let mut buf = [0u8; 8];
    let mut info = RecvInfo::default();
    while chan_recv(0, &mut buf, 0, &mut info) == 8 {
        let sum: u64 = m.iter().map(|&b| b as u64).sum();
        chan_send(0, &sum.to_le_bytes(), 0);
    }
    0
}

fn start(mode: &str, extra: Option<u64>) -> Option<(u64, i64)> {
    let (p, c) = channel_create().ok()?;
    let pid = match extra {
        Some(h) => spawn_ex("/bin/ipcbench", &["ipcbench", mode], &[(c, 0), (h, 1)], 0),
        None => spawn_ex("/bin/ipcbench", &["ipcbench", mode], &[(c, 0)], 0),
    };
    close(c);
    if pid <= 0 { None } else { Some((p, pid)) }
}

fn stop(p: u64, pid: i64) {
    close(p);
    let _ = wait(pid as u64, 0);
}

fn main(args: Args) -> i32 {
    match args.get(1) {
        Some("echo") => return echo(),
        Some("sink") => return sink(),
        Some("shm") => return shm_reader(),
        _ => {}
    }
    let mut buf = [0u8; MSG_MAX];
    let mut info = RecvInfo::default();

    // 1. Ping-pong: komunikat 8 B tam i z powrotem.
    let Some((p, pid)) = start("echo", None) else {
        println!("ipcbench: FAIL spawn");
        return 1;
    };
    let t0 = uptime_ms();
    for i in 0..PINGPONG {
        chan_send(p, &i.to_le_bytes(), 0);
        chan_recv(p, &mut buf, 0, &mut info);
    }
    let pp_ms = (uptime_ms() - t0).max(1);
    stop(p, pid);
    let pp_ns = pp_ms * 1_000_000 / PINGPONG;

    // 2. Przepustowość kanału: komunikaty 4 KiB w jedną stronę.
    let Some((p, pid)) = start("sink", None) else { return 1 };
    let block = [0x5Au8; MSG_MAX];
    let t0 = uptime_ms();
    for _ in 0..SINK_MSGS {
        chan_send(p, &block, 0);
    }
    chan_send(p, b"", 0);
    chan_recv(p, &mut buf, 0, &mut info);
    let sink_ms = (uptime_ms() - t0).max(1);
    let sink_ok = u64_of(&buf) == SINK_MSGS * MSG_MAX as u64 * 0x5A;
    let chan_mbs = SINK_MSGS * MSG_MAX as u64 / 1024 * 1000 / 1024 / sink_ms;
    let msgs_s = SINK_MSGS * 1000 / sink_ms;

    // 3a. 16 MiB przez kanał (4 KiB komunikaty, suma na końcu kawałka).
    let t0 = uptime_ms();
    let mut via_chan_ok = true;
    for c in 0..CHUNKS {
        let fill = [(c as u8).wrapping_add(1); MSG_MAX];
        for _ in 0..CHUNK / MSG_MAX as u64 {
            chan_send(p, &fill, 0);
        }
        chan_send(p, b"", 0);
        chan_recv(p, &mut buf, 0, &mut info);
        via_chan_ok &= u64_of(&buf) == CHUNK * ((c as u8).wrapping_add(1) as u64);
    }
    let chan_data_ms = (uptime_ms() - t0).max(1);
    stop(p, pid);

    // 3b. 16 MiB przez pamięć współdzieloną: kawałek 1 MiB, dzwonek, suma.
    let shm = shm_create(CHUNK) as u64;
    let Ok(a) = shm_map(shm, PROT_READ | PROT_WRITE) else { return 1 };
    let m = unsafe { core::slice::from_raw_parts_mut(a as *mut u8, CHUNK as usize) };
    let ro = handle_dup(shm, R_MAP_READ | R_DUP) as u64;
    let Some((p, pid)) = start("shm", Some(ro)) else { return 1 };
    let t0 = uptime_ms();
    let mut via_shm_ok = true;
    for c in 0..CHUNKS {
        let v = (c as u8).wrapping_add(1);
        m.fill(v);
        chan_send(p, &c.to_le_bytes(), 0);
        chan_recv(p, &mut buf, 0, &mut info);
        via_shm_ok &= u64_of(&buf) == CHUNK * v as u64;
    }
    let shm_data_ms = (uptime_ms() - t0).max(1);
    stop(p, pid);
    let total_mib = CHUNK * CHUNKS / (1024 * 1024);

    if !(sink_ok && via_chan_ok && via_shm_ok) {
        println!("ipcbench: FAIL data mismatch (sink {}, channel {}, shm {})", sink_ok, via_chan_ok, via_shm_ok);
        return 1;
    }
    println!(
        "ipcbench: ping-pong {}.{} us, channel {} msg/s x 4 KiB ({} MB/s), {} MiB via channel {} ms / via shared memory {} ms",
        pp_ns / 1000,
        pp_ns % 1000 / 100,
        msgs_s,
        chan_mbs,
        total_mib,
        chan_data_ms,
        shm_data_ms
    );
    println!(
        "ipcbench-result pingpong_ns={} chan_msgs={} chan_mbs={} chan16_ms={} shm16_ms={}",
        pp_ns, msgs_s, chan_mbs, chan_data_ms, shm_data_ms
    );
    0
}
