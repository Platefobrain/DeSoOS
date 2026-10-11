// M18.e: test pamięci współdzielonej – obiekt widziany przez dwa mapowania i
// dwa procesy (te same strony), dane od dziecka + "dzwonek" przez kanał,
// mapowanie tylko do odczytu (bez MAP_WRITE – EACCES, zapis = #PF), nigdy
// wykonywalne (skok = #PF), munmap tylko w całości, obiekt żyje po
// zamknięciu uchwytu, dopóki jest zamapowany.  Wynik: "shmtest: N checks
// OK" i kod 0, albo opis pierwszego błędu i kod 1.  Uruchamia go IPC TEST.
//
// Tryby dziecka (uruchamiane przez spawn_ex):
//   shmtest writer  – 0 = kanał; dostaje przez kanał uchwyt shm (RW), zapisuje
//                     wzór, odsyła dzwonek; kod 0
//   shmtest reader  – 0 = shm tylko do odczytu, 1 = kanał; czyta wzór, odsyła sumę
//   shmtest writero – 0 = shm tylko do odczytu; mapuje i pisze -> #PF
//   shmtest exec    – 0 = shm RW; zapisuje `ret` i skacze tam -> #PF (NX)
//   shmtest after   – 0 = shm RW; mapuje, munmap, czyta -> #PF
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const SIZE: u64 = 64 * 1024;
const PF_KILLED: u64 = 0x100 | 14;

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("shmtest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

fn pattern(i: u64) -> u8 {
    (i.wrapping_mul(7) ^ (i >> 8)) as u8
}

fn mem(addr: u64, len: u64) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, len as usize) }
}

fn writer() -> i32 {
    let mut buf = [0u8; 16];
    let mut hs = [0u64; MSG_HANDLES];
    let mut info = RecvInfo::default();
    if chan_recv_h(0, &mut buf, &mut hs, 0, &mut info) != 0 || info.handles != 1 {
        return 10;
    }
    let Ok(a) = shm_map(hs[0], PROT_READ | PROT_WRITE) else { return 11 };
    let m = mem(a, SIZE);
    for (i, b) in m.iter_mut().enumerate() {
        *b = pattern(i as u64);
    }
    // Dzwonek: dane gotowe.
    if chan_send(0, b"ready", 0) != 0 {
        return 12;
    }
    0
}

fn reader() -> i32 {
    let Ok(a) = shm_map(0, PROT_READ) else { return 20 };
    let sum: u64 = mem(a, SIZE).iter().map(|&b| b as u64).sum();
    if chan_send(1, &sum.to_le_bytes(), 0) != 0 {
        return 21;
    }
    0
}

fn writero() -> i32 {
    let Ok(a) = shm_map(0, PROT_READ) else { return 30 };
    mem(a, 1)[0] = 1; // #PF – proces ma tu zginąć
    31
}

fn exec() -> i32 {
    let Ok(a) = shm_map(0, PROT_READ | PROT_WRITE) else { return 40 };
    mem(a, 1)[0] = 0xC3; // ret
    let f: extern "C" fn() = unsafe { core::mem::transmute(a as usize) };
    f(); // #PF (NX) – proces ma tu zginąć
    41
}

fn after() -> i32 {
    let Ok(a) = shm_map(0, PROT_READ | PROT_WRITE) else { return 50 };
    if munmap(a, SIZE) != 0 {
        return 51;
    }
    let x = unsafe { core::ptr::read_volatile(a as *const u8) }; // #PF
    x as i32 + 52
}

fn child_status(mode: &str, map: &[(u64, u64)]) -> Result<u64, i64> {
    let pid = spawn_ex("/bin/shmtest", &["shmtest", mode], map, 0);
    if pid < 0 {
        return Err(pid);
    }
    wait(pid as u64, 0).map(|(_, s)| s)
}

fn main(args: Args) -> i32 {
    match args.get(1) {
        Some("writer") => return writer(),
        Some("reader") => return reader(),
        Some("writero") => return writero(),
        Some("exec") => return exec(),
        Some("after") => return after(),
        _ => {}
    }
    let mut n = 0;
    let mut buf = [0u8; 16];
    let mut info = RecvInfo::default();

    // 1. Tworzenie: rozmiar zaokrąglony, prawa, błędy rozmiaru, read / write – EBADF.
    check!(n, shm_create(0) == -22 && shm_create(16 * 1024 * 1024 + 1) == -22, "bad sizes must be EINVAL");
    let odd = shm_create(5000);
    check!(n, odd >= 0 && shm_size(odd as u64) == 8192, "5000 bytes -> {}", shm_size(odd as u64));
    close(odd as u64);
    let h = shm_create(SIZE);
    check!(n, h >= 0, "shm_create: {}", strerror(h));
    let h = h as u64;
    check!(n, handle_info(h) == Ok((KIND_SHM, R_MAP_READ | R_MAP_WRITE | R_DUP | R_TRANSFER)), "rights: {:?}", handle_info(h));
    check!(n, read(h, &mut buf) == -9 && write(h, b"x") == -9, "read / write on shm must be EBADF");
    check!(n, shm_size(1) == -9, "shm_size on the console must be EBADF");

    // 2. Dwa mapowania w jednym procesie – te same strony; nowa pamięć wyzerowana.
    let rw = match shm_map(h, PROT_READ | PROT_WRITE) {
        Ok(a) => a,
        Err(e) => {
            println!("shmtest: FAIL shm_map: {}", strerror(e));
            return 1;
        }
    };
    check!(n, mem(rw, SIZE).iter().all(|&b| b == 0), "new shared memory must be zeroed");
    let ro = shm_map(h, PROT_READ).unwrap_or(0);
    check!(n, ro != 0 && ro != rw, "second mapping: {:#x}", ro);
    mem(rw, SIZE)[12345] = 0x5A;
    check!(n, mem(ro, SIZE)[12345] == 0x5A, "write through one mapping must be visible through the other");
    check!(n, shm_map(h, 4) == Err(-22), "bad prot must be EINVAL");

    // 3. Uchwyt bez MAP_WRITE: mapowanie do odczytu tak, do zapisu – EACCES.
    let rh = handle_dup(h, R_MAP_READ | R_DUP | R_TRANSFER) as u64;
    check!(n, shm_map(rh, PROT_READ | PROT_WRITE) == Err(-13), "write mapping without R_MAP_WRITE must be EACCES");
    let r2 = shm_map(rh, PROT_READ);
    check!(n, r2.is_ok() && mem(r2.unwrap_or(0), SIZE)[12345] == 0x5A, "read mapping via read-only handle");
    check!(n, munmap(r2.unwrap_or(0), SIZE) == 0, "munmap read-only mapping");

    // 4. munmap tylko w całości: część – EINVAL; całość – OK.
    check!(n, munmap(ro, 4096) == -22 && munmap(ro + 4096, 4096) == -22, "partial munmap must be EINVAL");
    check!(n, munmap(ro, SIZE) == 0, "full munmap");

    // 5. Dziecko-pisarz: uchwyt RW przez kanał, wzór w pamięci, dzwonek przez kanał.
    let (p, c) = channel_create().unwrap_or((0, 0));
    let wh = handle_dup(h, R_MAP_READ | R_MAP_WRITE | R_TRANSFER) as u64;
    let pid = spawn_ex("/bin/shmtest", &["shmtest", "writer"], &[(c, 0)], 0);
    check!(n, pid > 0, "spawn writer: {}", strerror(pid));
    close(c);
    check!(n, chan_send_h(p, b"", &[wh], 0) == 0, "send shm handle to the writer");
    check!(n, chan_recv(p, &mut buf, 0, &mut info) == 5 && &buf[..5] == b"ready" && info.sender == pid as u64, "doorbell from the writer");
    let ok = mem(rw, SIZE).iter().enumerate().all(|(i, &b)| b == pattern(i as u64));
    check!(n, ok, "pattern written by the child not visible in the parent");
    check!(n, wait(pid as u64, 0) == Ok((pid as u64, 0)), "writer exit");
    close(p);

    // 6. Dziecko-czytelnik z uchwytem tylko do odczytu: widzi te same dane.
    let want: u64 = (0..SIZE).map(|i| pattern(i) as u64).sum();
    let (p, c) = channel_create().unwrap_or((0, 0));
    let pid = spawn_ex("/bin/shmtest", &["shmtest", "reader"], &[(rh, 0), (c, 1)], 0);
    check!(n, pid > 0, "spawn reader: {}", strerror(pid));
    close(c);
    let r = chan_recv(p, &mut buf, 0, &mut info);
    check!(n, r == 8 && u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]) == want, "reader sum");
    check!(n, wait(pid as u64, 0) == Ok((pid as u64, 0)), "reader exit");
    close(p);

    // 7. Ochrona: zapis do mapowania tylko do odczytu, wykonanie, dostęp po munmap – #PF kończy dziecko.
    check!(n, child_status("writero", &[(rh, 0)]) == Ok(PF_KILLED), "write to read-only mapping must be #PF");
    check!(n, child_status("exec", &[(h, 0)]) == Ok(PF_KILLED), "executing shared memory must be #PF (NX)");
    check!(n, child_status("after", &[(h, 0)]) == Ok(PF_KILLED), "access after munmap must be #PF");
    check!(n, mem(rw, SIZE)[0] == 0xC3, "data written by a killed child stays in the object");

    // 8. Obiekt żyje po zamknięciu uchwytów, dopóki jest zamapowany.
    close(rh);
    close(h);
    check!(n, mem(rw, SIZE)[12345] == pattern(12345), "memory must stay after closing the handles");
    check!(n, munmap(rw, SIZE) == 0, "last munmap");

    println!("shmtest: {} checks OK", n);
    0
}
