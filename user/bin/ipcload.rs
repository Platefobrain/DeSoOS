// M18.f: zadanie IPC do stressu – rodzic i dziecko (spawn_ex: kanał + pamięć
// współdzielona tylko do odczytu) wymieniają dane: rodzic pisze 4 KiB wzoru
// do wspólnej pamięci i dzwoni przez kanał, dziecko liczy sumę i odpowiada.
// Na koniec dziecko czeka na komunikat, a rodzic je zabija (kill w trakcie
// czekania, z zamapowaną pamięcią współdzieloną) – koniec dziecka znika (EPIPE).
// Wynik: "ipcload: OK <n> round trips" i kod 0; błąd – opis i kod 1.
//
// `ipcload child` – 0 = kanał, 1 = pamięć (tylko do odczytu).
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const ROUNDS: u64 = 200;
const DATA: usize = 4096;
const KILLED: u64 = 0x100 | 9;

fn byte(round: u64, i: usize) -> u8 {
    (i as u64).wrapping_mul(31).wrapping_add(round.wrapping_mul(7)) as u8
}

fn child() -> i32 {
    let Ok(a) = shm_map(1, PROT_READ) else { return 10 };
    let m = unsafe { core::slice::from_raw_parts(a as *const u8, DATA) };
    let mut buf = [0u8; 8];
    let mut info = RecvInfo::default();
    loop {
        let r = chan_recv(0, &mut buf, 0, &mut info);
        if r == EPIPE {
            return 0;
        }
        if r != 8 {
            return 11;
        }
        let sum: u64 = m.iter().map(|&b| b as u64).sum();
        if chan_send(0, &sum.to_le_bytes(), 0) != 0 {
            return 12;
        }
    }
}

fn fail(what: &str) -> i32 {
    println!("ipcload: FAIL {}", what);
    1
}

fn main(args: Args) -> i32 {
    if args.get(1) == Some("child") {
        return child();
    }
    let shm = shm_create(DATA as u64);
    if shm < 0 {
        return fail("shm_create");
    }
    let shm = shm as u64;
    let Ok(a) = shm_map(shm, PROT_READ | PROT_WRITE) else { return fail("shm_map") };
    let m = unsafe { core::slice::from_raw_parts_mut(a as *mut u8, DATA) };
    let ro = handle_dup(shm, R_MAP_READ | R_DUP);
    let Ok((p, c)) = channel_create() else { return fail("channel_create") };
    let pid = spawn_ex("/bin/ipcload", &["ipcload", "child"], &[(c, 0), (ro as u64, 1)], 0);
    if pid <= 0 {
        return fail("spawn_ex");
    }
    close(c);
    close(ro as u64);
    let mut buf = [0u8; 8];
    let mut info = RecvInfo::default();
    for round in 0..ROUNDS {
        let mut want = 0u64;
        for (i, b) in m.iter_mut().enumerate() {
            *b = byte(round, i);
            want += *b as u64;
        }
        if chan_send(p, &round.to_le_bytes(), 0) != 0 {
            return fail("send doorbell");
        }
        if chan_recv(p, &mut buf, 0, &mut info) != 8 || info.sender != pid as u64 {
            return fail("recv reply");
        }
        if u64::from_le_bytes(buf) != want {
            return fail("child saw different shared memory");
        }
    }
    // Dziecko czeka w chan_recv – kill.
    sleep_ms(1);
    if kill(pid as u64) != 0 {
        return fail("kill");
    }
    match wait(pid as u64, 0) {
        Ok((x, s)) if x == pid as u64 && (s == KILLED || s == 0) => {}
        _ => return fail("child status after kill"),
    }
    if chan_send(p, b"x", 0) != EPIPE {
        return fail("killed child's channel end must be closed");
    }
    println!("ipcload: OK {} round trips", ROUNDS);
    0
}
