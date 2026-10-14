// M20.b/c: test kontrolera USB (xHCI) i usługi usbd – samotest jądra USB TEST.
//
// Z HW_ROOT w slocie 3 (USB TEST 1/2):
//   - dev_find: tylko z HW_ROOT (EBADF), klasa > 24 bity (EINVAL), kontrolery
//     xHCI po klasie 0C0330, ENOENT za ostatnim i dla klasy, której nie ma,
//   - usbd na pierwszym kontrolerze: start (reset, pierścienie, przerwanie),
//     "status" (No-Op zakończone, porty, podłączony pendrive startowy QEMU),
//     "noop 2000", zła prośba,
//   - kill usbd w trakcie serii komend -> nowa instancja robi pełny reset i
//     działa (kontroler przerwany w połowie pracy),
//   - samodzielny koniec usbd, gdy nikt nie może go już wywołać; urządzenie wolne.
// Z kanałem svc w slocie 3 (USB TEST 2/2, `init test /bin/usbtest`): init sam
// znalazł kontroler po klasie i uruchomił usługę usb0 – rozmowa przez svc.
// Wynik: "usbtest: N checks OK, ..." i linia "usbtest-result k=v".
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const EINVAL: i64 = -22;

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("usbtest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

/// Wartość `klucz=` z linii "usbd-status".
fn field(text: &str, key: &str) -> Option<u64> {
    let line = text.lines().find(|l| l.starts_with("usbd-status"))?;
    let v = line.split(' ').find_map(|w| w.strip_prefix(key)?.strip_prefix('='))?;
    v.parse().ok()
}

/// Prośba do usbd i odpowiedź (tekst w `out`).
fn ask<'a>(c: u64, req: &str, out: &'a mut [u8]) -> Option<&'a str> {
    if chan_send(c, req.as_bytes(), 0) != 0 {
        return None;
    }
    let mut info = RecvInfo::default();
    let r = chan_recv(c, out, 0, &mut info);
    if r < 0 {
        return None;
    }
    core::str::from_utf8(&out[..r as usize]).ok()
}

/// usbd na urządzeniu `bdf`: (pid, kanał połączeń).  EBUSY (poprzednia
/// instancja jeszcze się kończy) – ponawia do 2 s.
fn start_usbd(bdf: u64) -> Option<(u64, u64)> {
    let t0 = uptime_ms();
    let dev = loop {
        let d = dev_claim(HW_ROOT, bdf);
        if d >= 0 {
            break d as u64;
        }
        if d != EBUSY || uptime_ms() - t0 > 2000 {
            return None;
        }
        sleep_ms(5);
    };
    let (listen, srv) = channel_create().ok()?;
    // M20.e: kopia uchwytu INPUT (jeśli jądro go dało) – w slocie 5, jak od init.
    let input = (3..16).find(|&h| handle_info(h).map(|(k, _)| k) == Ok(KIND_INPUT));
    // M20.f: i kopia BLK (slot 6) – pendrive'y jako dyski jądra.
    let blk = (3..16).find(|&h| handle_info(h).map(|(k, _)| k) == Ok(KIND_BLK));
    let mut map = [(1u64, 1u64), (dev, 3), (srv, 4), (0, 0), (0, 0)];
    let mut n = 3;
    if let Some(h) = input {
        map[n] = (h, 5);
        n += 1;
    }
    if let Some(h) = blk {
        map[n] = (h, 6);
        n += 1;
    }
    let pid = spawn_ex("/bin/usbd", &["usbt"], &map[..n], 0);
    close(dev);
    close(srv);
    if pid <= 0 {
        close(listen);
        return None;
    }
    Some((pid as u64, listen))
}

/// M20.f: katalog /usbN z testowym pendrive'em (plik DESOOS.TST); czeka do `ms`.
fn find_disk(ms: u64) -> Option<(u8, u64)> {
    let t0 = uptime_ms();
    loop {
        for n in 0..4u8 {
            let mut p = [0u8; 20];
            let path = usb_path(&mut p, n, "DESOOS.TST");
            if stat(path).is_ok() {
                return Some((n, uptime_ms() - t0));
            }
        }
        if uptime_ms() - t0 > ms {
            return None;
        }
        sleep_ms(20);
    }
}

/// "/usbN/plik" w buforze.
fn usb_path<'a>(buf: &'a mut [u8; 20], n: u8, file: &str) -> &'a str {
    let mut k = 0;
    for &c in b"/usb" {
        buf[k] = c;
        k += 1;
    }
    buf[k] = b'0' + n;
    k += 1;
    if !file.is_empty() {
        buf[k] = b'/';
        k += 1;
        for &c in file.as_bytes() {
            if k < buf.len() {
                buf[k] = c;
                k += 1;
            }
        }
    }
    core::str::from_utf8(&buf[..k]).unwrap_or("/")
}

/// Cały plik do `buf` (≤ rozmiar bufora); -errno albo długość.
fn read_file(path: &str, buf: &mut [u8]) -> i64 {
    let fd = open(path, O_READ);
    if fd < 0 {
        return fd;
    }
    let mut len = 0usize;
    loop {
        if len == buf.len() {
            break;
        }
        let r = read(fd as u64, &mut buf[len..]);
        if r < 0 {
            close(fd as u64);
            return r;
        }
        if r == 0 {
            break;
        }
        len += r as usize;
    }
    close(fd as u64);
    len as i64
}

fn connect(listen: u64) -> Option<u64> {
    let (mine, theirs) = channel_create().ok()?;
    if chan_send_h(listen, b"usb", &[theirs], 0) != 0 {
        close(mine);
        close(theirs);
        return None;
    }
    Some(mine)
}

/// Tryb usługi: init uruchomił usb0 – status przez kanał svc.
fn via_init() -> i32 {
    let mut n = 0;
    let mut out = [0u8; 2048];
    let t0 = uptime_ms();
    let mut status: Option<usize> = None;
    // usbd startuje równolegle z testem – ponawiaj do 3 s.
    while status.is_none() && uptime_ms() - t0 < 3000 {
        if let Ok(c) = svc_connect("usb0") {
            if let Some(t) = ask(c, "status", &mut out) {
                if t.contains("usbd-status") {
                    status = Some(t.len());
                }
            }
            close(c);
        }
        if status.is_none() {
            sleep_ms(20);
        }
    }
    check!(n, status.is_some(), "no answer from service usb0 via init (svc_connect)");
    let text = core::str::from_utf8(&out[..status.unwrap()]).unwrap_or("");
    check!(n, field(text, "noops").unwrap_or(0) >= 203 && field(text, "errors") == Some(0), "usb0 status: {:?}", text);
    check!(n, field(text, "connected").unwrap_or(0) >= 1, "usb0 sees no connected device: {:?}", text);
    check!(n, field(text, "devices") == Some(5) && field(text, "hubs") == Some(1), "usb0 devices (want 5, 1 hub): {:?}", text);
    // lsusb przez kanał svc (jak z shella).
    let mut l = [0u8; 4096];
    let mut len = 0;
    if let Ok((r, w)) = pipe() {
        let pid = spawn_ex("/bin/lsusb", &["lsusb"], &[(w, 1), (w, 2), (SVC, 3)], 0);
        close(w);
        while pid > 0 && len < l.len() {
            let k = read(r, &mut l[len..]);
            if k <= 0 {
                break;
            }
            len += k as usize;
        }
        close(r);
        if pid > 0 {
            let _ = wait(pid as u64, 0);
        }
    }
    let lt = core::str::from_utf8(&l[..len]).unwrap_or("");
    check!(n, lt.contains("usb0 port") && lt.contains("03/01/01") && lt.contains("08/06/50"), "lsusb output: {:?}", lt);
    check!(n, lt.contains("keyboard ready (input to kernel)"), "init did not give usbd the INPUT handle: {:?}", lt);

    // M20.f: pendrive testowy (obraz FAT32 z test.sh) – jądro zamontowało go
    // samo; pliki czytane przez VFS -> FAT32 -> ublk -> usbd -> xHCI.
    let disk = find_disk(10_000);
    check!(n, disk.is_some(), "test USB disk (DESOOS.TST) not mounted in /usb0..3");
    let (u, mount_ms) = disk.unwrap();
    let l2 = ask_lsusb(&mut l);
    check!(n, l2.matches("disk sd").count() == 2 && l2.contains("read-only"), "lsusb: 2 disks ready, read-only: {:?}", l2);
    // Pliki identyczne z /bin (te same programy wgrane do obrazu).
    // Bufory na stercie (stos procesu jest mały).
    let (Ok(av), Ok(bv)) = (mmap(131072, PROT_READ | PROT_WRITE), mmap(131072, PROT_READ | PROT_WRITE)) else { return 2 };
    let a = unsafe { core::slice::from_raw_parts_mut(av as *mut u8, 131072) };
    let b = unsafe { core::slice::from_raw_parts_mut(bv as *mut u8, 131072) };
    for (usb, bin) in [("SH", "/bin/sh"), ("USBD", "/bin/usbd"), ("CAT", "/bin/cat")] {
        let mut p = [0u8; 20];
        let la = read_file(usb_path(&mut p, u, usb), a);
        let lb = read_file(bin, b);
        check!(n, la > 0 && la == lb && a[..la as usize] == b[..lb as usize], "/usb{}/{} differs from {} ({} vs {} bytes)", u, usb, bin, la, lb);
    }
    // 4 MiB wzoru: każde słowo sprawdzone, czas -> KiB/s.
    let mut p = [0u8; 20];
    let fd = open(usb_path(&mut p, u, "DATA.BIN"), O_READ);
    check!(n, fd >= 0, "open DATA.BIN: {}", fd);
    let t0 = uptime_ms();
    let mut total = 0u64;
    let mut bad = 0u64;
    loop {
        let r = read(fd as u64, &mut a[..65536]);
        if r <= 0 {
            break;
        }
        for k in (0..r as usize).step_by(4) {
            let w = u32::from_le_bytes([a[k], a[k + 1], a[k + 2], a[k + 3]]);
            if w != ((total + k as u64) / 4).wrapping_mul(2654435761) as u32 {
                bad += 1;
            }
        }
        total += r as u64;
    }
    let ms = (uptime_ms() - t0).max(1);
    close(fd as u64);
    check!(n, total == 4 * 1024 * 1024 && bad == 0, "DATA.BIN: {} bytes, {} bad words", total, bad);
    let kbs = total * 1000 / 1024 / ms;
    // Zapis: każda próba odrzucona, nic się nie zmienia.
    let mut p = [0u8; 20];
    let newf = usb_path(&mut p, u, "NEW.TXT");
    let w = open(newf, O_WRITE | O_CREATE);
    if w >= 0 {
        close(w as u64);
    }
    check!(n, w == -30, "create on the USB disk must be EROFS: {}", w);
    check!(n, stat(newf).is_err(), "NEW.TXT appeared on a read-only disk");
    let mut p = [0u8; 20];
    let w = open(usb_path(&mut p, u, "SH"), O_WRITE);
    if w >= 0 {
        close(w as u64);
    }
    check!(n, w < 0, "open for writing on the USB disk must fail: {}", w);
    let mut p = [0u8; 20];
    check!(n, unlink(usb_path(&mut p, u, "CAT")) == -30, "unlink on the USB disk must be EROFS");
    let mut p = [0u8; 20];
    check!(n, mkdir(usb_path(&mut p, u, "DIR")) == -30, "mkdir on the USB disk must be EROFS");
    let mut p = [0u8; 20];
    check!(n, stat(usb_path(&mut p, u, "CAT")).map(|s| s.size) == stat("/bin/cat").map(|s| s.size), "CAT changed after the refused unlink");
    println!("usbtest: {} checks OK, usb0 started by init (found by class), 5 devices (hub), keyboard -> kernel, lsusb via svc, /usb{} mounted in {} ms, files = /bin, 4 MiB pattern at {} KiB/s, writes refused", n, u, mount_ms, kbs);
    println!("usbtest-disk mount_ms={} read_kbs={}", mount_ms, kbs);
    0
}

/// lsusb (przez kanał svc) do bufora.
fn ask_lsusb(l: &mut [u8; 4096]) -> &str {
    let mut len = 0;
    if let Ok((r, w)) = pipe() {
        let pid = spawn_ex("/bin/lsusb", &["lsusb"], &[(w, 1), (w, 2), (SVC, 3)], 0);
        close(w);
        while pid > 0 && len < l.len() {
            let k = read(r, &mut l[len..]);
            if k <= 0 {
                break;
            }
            len += k as usize;
        }
        close(r);
        if pid > 0 {
            let _ = wait(pid as u64, 0);
        }
    }
    core::str::from_utf8(&l[..len]).unwrap_or("")
}

/// M20.d: `init test /bin/usbtest hotplug` – jądro (USB TEST 6/6) każe QEMU
/// odłączyć dysk za hubem, podłączyć go z powrotem i odłączyć cały hub; tu
/// obserwujemy usb0: urządzeń 5 -> 4 -> 5 -> 2, bez błędów enumeracji.
fn hotplug() -> i32 {
    let mut n = 0;
    let mut out = [0u8; 2048];
    let t0 = uptime_ms();
    let mut c = 0;
    while c == 0 && uptime_ms() - t0 < 5000 {
        if let Ok(h) = svc_connect("usb0") {
            c = h;
        } else {
            sleep_ms(20);
        }
    }
    check!(n, c != 0, "no usb0 service");
    // Kolejne liczby urządzeń, jakie mamy zobaczyć.
    let want = [5u64, 4, 5, 2];
    let mut seen = 0usize;
    let mut last = 0u64;
    let mut hubs_end = u64::MAX;
    let mut stat = [0u64; 3];
    while seen < want.len() && uptime_ms() - t0 < 90_000 {
        let Some(st) = ask(c, "status", &mut out) else { break };
        let dev = field(st, "devices").unwrap_or(0);
        if dev != last {
            last = dev;
            if dev == want[seen] {
                seen += 1;
                hubs_end = field(st, "hubs").unwrap_or(u64::MAX);
                stat = [field(st, "failures").unwrap_or(99), field(st, "errors").unwrap_or(99), field(st, "hub_events").unwrap_or(0)];
            }
        }
        sleep_ms(30);
    }
    check!(n, seen == want.len(), "device count sequence 5 -> 4 -> 5 -> 2: reached step {} (last count {})", seen, last);
    check!(n, hubs_end == 0, "hub still listed after it was unplugged: hubs={}", hubs_end);
    check!(n, stat[0] == 0 && stat[1] == 0, "failures {} errors {} during hot-plug", stat[0], stat[1]);
    check!(n, stat[2] >= 2, "hub change reports: {} (want >= 2)", stat[2]);
    let mut l = [0u8; 4096];
    let lt = ask_lsusb(&mut l);
    check!(n, !lt.contains("hub") && !lt.contains("mouse") && lt.contains("keyboard"), "lsusb after unplugging the hub: {:?}", lt);
    close(c);
    println!("usbtest: {} checks OK, hot-plug behind the hub: disk out / in, hub out (hub + mouse + disk gone), {} hub change reports", n, stat[2]);
    0
}

/// M20.g: `usbtest reader PLIK` – czyta plik w kółko, aż odczyt się nie uda;
/// kod 0 = błąd przyszedł (z czasem od ostatniego udanego odczytu), 1 = 30 s bez
/// błędu albo zawieszenie (rodzic i tak zmierzy czas).
fn reader(path: &str) -> i32 {
    let Ok(buf) = mmap(65536, PROT_READ | PROT_WRITE) else { return 2 };
    let buf = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, 65536) };
    let t0 = uptime_ms();
    let mut total = 0u64;
    loop {
        let fd = open(path, O_READ);
        if fd < 0 {
            println!("reader: {} bytes, open: {}", total, strerror(fd));
            return 0;
        }
        loop {
            let t = uptime_ms();
            let r = read(fd as u64, buf);
            if r < 0 {
                println!("reader: {} bytes, read: {} after {} ms", total, strerror(r), uptime_ms() - t);
                close(fd as u64);
                return 0;
            }
            if r == 0 {
                break;
            }
            total += r as u64;
        }
        close(fd as u64);
        if uptime_ms() - t0 > 30_000 {
            println!("reader: {} bytes, no error in 30 s", total);
            return 1;
        }
    }
}

/// pid usługi z listy init ("usb0 running pid 12 restarts 0 (/bin/usbd)").
fn service(name: &str) -> Option<(u64, bool)> {
    let mut b = [0u8; 1024];
    let n = svc_list(&mut b).ok()?;
    let t = core::str::from_utf8(&b[..n]).ok()?;
    let line = t.lines().find(|l| l.split(' ').next() == Some(name))?;
    let pid = line.split(" pid ").nth(1)?.split(' ').next()?.parse().ok()?;
    Some((pid, line.contains(" broken ")))
}

/// Czeka na działającą instancję usługi z pid innym niż `old`.
fn new_instance(name: &str, old: u64, ms: u64) -> Option<u64> {
    let t0 = uptime_ms();
    while uptime_ms() - t0 < ms {
        if let Some((pid, _)) = service(name) {
            if pid != 0 && pid != old {
                return Some(pid);
            }
        }
        sleep_ms(10);
    }
    None
}

/// M20.g: `init test /bin/usbtest robust` – kill usbd w trakcie odczytu
/// pliku z pendrive'a (czytający dostaje błąd, nie wisi), restart przez init
/// (dysk i klawiatura wracają, pliki dalej poprawne), 5 awarii w 30 s → broken.
fn robust() -> i32 {
    let mut n = 0;
    let disk = find_disk(15_000);
    check!(n, disk.is_some(), "test disk not mounted");
    let (u, _) = disk.unwrap();
    let pid0 = service("usb0").map(|x| x.0).unwrap_or(0);
    check!(n, pid0 != 0, "usb0 pid not known (svc list)");
    // 1. Kill w trakcie odczytu.
    let mut p = [0u8; 20];
    let path = usb_path(&mut p, u, "DATA.BIN");
    let rd = match pipe() {
        Ok(x) => x,
        Err(_) => return 2,
    };
    let child = spawn_ex("/bin/usbtest", &["usbtest", "reader", path], &[(0, 0), (rd.1, 1), (rd.1, 2)], 0);
    close(rd.1);
    check!(n, child > 0, "cannot start the reader");
    sleep_ms(300);
    let t_kill = uptime_ms();
    check!(n, kill(pid0) == 0, "kill usb0");
    let w = wait(child as u64, 0);
    let t_err = uptime_ms() - t_kill;
    let mut out = [0u8; 256];
    let k = read(rd.0, &mut out);
    close(rd.0);
    let rtext = core::str::from_utf8(&out[..k.max(0) as usize]).unwrap_or("").trim();
    check!(n, w.map(|(_, s)| s) == Ok(0) && t_err < 3000, "reader after kill: {:?} in {} ms: {:?}", w, t_err, rtext);
    check!(n, rtext.contains("bytes") && !rtext.starts_with("reader: 0 bytes"), "reader read nothing before the kill: {:?}", rtext);
    // 2. Restart: nowa instancja, dysk z powrotem, pliki poprawne, klawiatura gotowa.
    let t_restart = uptime_ms();
    let pid1 = new_instance("usb0", pid0, 5000);
    check!(n, pid1.is_some(), "usb0 not restarted by init");
    let disk = find_disk(15_000);
    check!(n, disk.is_some(), "test disk not mounted again after the restart");
    let back_ms = uptime_ms() - t_restart;
    let (u, _) = disk.unwrap();
    let (Ok(av), Ok(bv)) = (mmap(131072, PROT_READ | PROT_WRITE), mmap(131072, PROT_READ | PROT_WRITE)) else { return 2 };
    let a = unsafe { core::slice::from_raw_parts_mut(av as *mut u8, 131072) };
    let b = unsafe { core::slice::from_raw_parts_mut(bv as *mut u8, 131072) };
    let mut p = [0u8; 20];
    let la = read_file(usb_path(&mut p, u, "SH"), a);
    let lb = read_file("/bin/sh", b);
    check!(n, la > 0 && la == lb && a[..la as usize] == b[..lb as usize], "SH after the restart differs ({} vs {})", la, lb);
    let mut l = [0u8; 4096];
    let mut kbd = false;
    for _ in 0..100 {
        if ask_lsusb(&mut l).contains("keyboard ready (input to kernel)") {
            kbd = true;
            break;
        }
        sleep_ms(50);
    }
    check!(n, kbd, "keyboard not back after the restart");
    // 3. Jeszcze 4 awarie (kill zaraz po starcie) – razem 5 w 30 s → broken.
    let mut last = pid1.unwrap();
    for i in 0..4 {
        if i > 0 {
            match new_instance("usb0", last, 8000) {
                Some(p) => last = p,
                None => {
                    check!(n, false, "usb0 not restarted after failure {}", i + 1);
                }
            }
        }
        let _ = kill(last);
        sleep_ms(20);
    }
    let t0 = uptime_ms();
    let mut broken = false;
    while uptime_ms() - t0 < 3000 {
        if service("usb0").map_or(false, |x| x.1) {
            broken = true;
            break;
        }
        sleep_ms(20);
    }
    check!(n, broken, "usb0 not broken after 5 failures in 30 s: {:?}", service("usb0"));
    println!("usbtest: {} checks OK, robust: reader got an error {} ms after kill ({}), disk + keyboard back in {} ms, broken after 5 failures", n, t_err, rtext, back_ms);
    0
}

fn main(args: Args) -> i32 {
    if args.get(1) == Some("reader") {
        return reader(args.get(2).unwrap_or("/usb0/DATA.BIN"));
    }
    if args.get(1) == Some("robust") {
        return robust();
    }
    if args.get(1) == Some("hotplug") {
        return hotplug();
    }
    if handle_info(HW_ROOT).map(|(k, _)| k) != Ok(KIND_HW_ROOT) {
        return via_init();
    }
    let mut n = 0;
    let mut out = [0u8; 2048];

    // dev_find.
    check!(n, dev_find(1, CLASS_XHCI, 0) == EBADF, "dev_find without HW_ROOT: {}", dev_find(1, CLASS_XHCI, 0));
    check!(n, dev_find(HW_ROOT, 0x0100_0000, 0) == EINVAL, "dev_find class > 24 bits");
    check!(n, dev_find(HW_ROOT, 0xFF_FFFF, 0) == ENOENT, "dev_find of a class nobody has");
    let bdf = dev_find(HW_ROOT, CLASS_XHCI, 0);
    check!(n, bdf >= 0, "no xHCI controller found by class 0C0330: {}", bdf);
    let mut count = 0u64;
    while dev_find(HW_ROOT, CLASS_XHCI, count) >= 0 && count < 64 {
        count += 1;
    }
    check!(n, count >= 1 && dev_find(HW_ROOT, CLASS_XHCI, count) == ENOENT, "ENOENT after the last controller ({})", count);
    let bdf = bdf as u64;

    // usbd: start, status, No-Op.
    let t0 = uptime_ms();
    let s = start_usbd(bdf);
    check!(n, s.is_some(), "cannot start usbd on {:#x}", bdf);
    let (pid, listen) = s.unwrap();
    let c = connect(listen).unwrap_or(0);
    let st = ask(c, "status", &mut out).unwrap_or("");
    let start_ms = uptime_ms() - t0;
    check!(n, st.contains("usbd-status"), "usbd status: {:?}", st);
    check!(n, field(st, "noops").unwrap_or(0) >= 203 && field(st, "errors") == Some(0), "No-Op commands not completed: {:?}", st);
    check!(n, field(st, "ports").unwrap_or(0) >= 1, "no ports: {:?}", st);
    // QEMU: pendrive startowy (usb-storage) wisi na tym kontrolerze.
    check!(n, field(st, "connected").unwrap_or(0) >= 1, "boot USB stick not seen on any port: {:?}", st);
    // M20.c: urządzenia rozpoznane.
    check!(n, field(st, "devices") == Some(5) && field(st, "failures") == Some(0) && field(st, "hubs") == Some(1), "QEMU USB devices not enumerated (want 5: 2 storage, keyboard, hub, mouse behind it): {:?}", st);
    let (hid_n, inp, r0) = (field(st, "hid"), field(st, "input"), field(st, "hid_reports").unwrap_or(0));
    let mut lbuf = [0u8; 4096];
    let l = ask(c, "list", &mut lbuf).unwrap_or("");
    check!(n, l.contains("08/06/50") && l.contains("mass storage"), "list: no mass storage interface 08/06/50: {:?}", l);
    check!(n, l.contains("03/01/01") && l.contains("keyboard") && l.contains("QEMU USB Keyboard"), "list: no HID boot keyboard 03/01/01: {:?}", l);
    check!(n, l.contains("03/01/02") && l.contains("mouse"), "list: no HID boot mouse 03/01/02: {:?}", l);
    let lines = l.lines().filter(|x| x.contains(": ")).count();
    check!(n, lines == 5 && l.contains("0627:0001") && l.contains("address "), "list: {} lines: {:?}", lines, l);
    // M20.d: hub i urządzenia za nim (port „N.1”, „N.2”).
    check!(n, l.contains("hub ready (8 ports, USB 2)") && l.contains(".1: 0627:0001") && l.contains(".2: 46f4:0001"), "list: hub with mouse (.1) and disk (.2) behind it: {:?}", l);
    // M20.f: oba pendrive'y w jądrze (sdX), testowy zamontowany przez jądro.
    let disk = find_disk(10_000);
    check!(n, disk.is_some(), "test USB disk not mounted (blk_attach / usb-disks)");
    let mount_ms = disk.unwrap().1;
    let st3 = ask(c, "status", &mut out).unwrap_or("");
    check!(n, field(st3, "storage") == Some(2) && field(st3, "disks") == Some(2) && field(st3, "blk") == Some(1) && field(st3, "stor_errors") == Some(0) && field(st3, "stor_reads").unwrap_or(0) > 0, "storage status: {:?}", st3);
    // M20.e: klawiatura i mysz skonfigurowane, raporty płyną (Set Idle 16 ms –
    // QEMU wysyła wtedy raport co 16 ms także bez wciśniętych klawiszy).
    check!(n, hid_n == Some(2) && inp == Some(1), "HID keyboard + mouse not configured: hid {:?} input {:?}", hid_n, inp);
    check!(n, l.contains("keyboard ready (input to kernel)") && l.contains("mouse ready"), "list: HID not ready: {:?}", l);
    let r = ask(c, "idle 16", &mut out).unwrap_or("");
    check!(n, r == "idle 16 2", "Set Idle on keyboard + mouse: {:?}", r);
    sleep_ms(400);
    let r = ask(c, "idle 0", &mut out).unwrap_or("");
    check!(n, r == "idle 0 2", "Set Idle 0: {:?}", r);
    let st2 = ask(c, "status", &mut out).unwrap_or("");
    let reports = field(st2, "hid_reports").unwrap_or(0).saturating_sub(r0);
    check!(n, reports >= 10 && field(st2, "hid_errors") == Some(0) && field(st2, "hid_events") == Some(0), "HID reports via interrupt endpoints: {} in 400 ms: {:?}", reports, st2);
    let r = ask(c, "noop 2000", &mut out).unwrap_or("");
    let ns: u64 = r.strip_prefix("noop 2000 ").and_then(|v| v.parse().ok()).unwrap_or(0);
    check!(n, ns > 0, "noop 2000: {:?}", r);
    let st = ask(c, "status", &mut out).unwrap_or("");
    let polled = field(st, "polled").unwrap_or(u64::MAX);
    check!(n, field(st, "noops").unwrap_or(0) >= 2203 && field(st, "errors") == Some(0), "after noop 2000: {:?}", st);
    let r = ask(c, "format c:", &mut out).unwrap_or("");
    check!(n, r.starts_with("error"), "unknown request must fail: {:?}", r);

    // Kill w trakcie serii komend -> nowa instancja (pełny reset) działa.
    check!(n, chan_send(c, b"noop 100000", 0) == 0, "send noop 100000");
    sleep_ms(30);
    kill(pid);
    let w = wait(pid, 0);
    check!(n, matches!(w, Ok((_, s)) if s & STATUS_SIGNALED != 0), "usbd not killed: {:?}", w);
    close(c);
    close(listen);
    let t1 = uptime_ms();
    let s = start_usbd(bdf);
    check!(n, s.is_some(), "usbd does not start again after kill (device not released?)");
    let (pid, listen) = s.unwrap();
    let c = connect(listen).unwrap_or(0);
    let st = ask(c, "status", &mut out).unwrap_or("");
    let restart_ms = uptime_ms() - t1;
    check!(n, field(st, "noops").unwrap_or(0) >= 203 && field(st, "errors") == Some(0), "restarted usbd: {:?}", st);
    check!(n, field(st, "devices") == Some(5), "devices after restart: {:?}", st);
    // Dysk zniknął razem z poprzednim usbd i wrócił z nowym.
    check!(n, find_disk(10_000).is_some(), "test USB disk not mounted again after the usbd restart");

    // Kill w trakcie enumeracji (start + debounce 100 ms) -> nowa instancja działa.
    close(c);
    close(listen);
    kill(pid);
    let _ = wait(pid, 0);
    let s = start_usbd(bdf);
    check!(n, s.is_some(), "usbd does not start (before kill during enumeration)");
    let (pid, listen) = s.unwrap();
    sleep_ms(115);
    kill(pid);
    let w = wait(pid, 0);
    check!(n, matches!(w, Ok((_, s)) if s & STATUS_SIGNALED != 0), "usbd not killed during enumeration: {:?}", w);
    close(listen);
    let s = start_usbd(bdf);
    check!(n, s.is_some(), "usbd does not start after kill during enumeration");
    let (pid, listen) = s.unwrap();
    let c = connect(listen).unwrap_or(0);
    let st = ask(c, "status", &mut out).unwrap_or("");
    check!(n, field(st, "devices") == Some(5) && field(st, "errors") == Some(0), "after kill during enumeration: {:?}", st);
    // M20.h: czas enumeracji (reset portu -> urządzenie gotowe) – 5 urządzeń tej instancji.
    let enum_avg = field(st, "enum_avg_ms").unwrap_or(0);
    let enum_max = field(st, "enum_max_ms").unwrap_or(0);
    check!(n, field(st, "enum_count") == Some(5) && enum_max >= enum_avg, "enumeration times: {:?}", st);

    // Koniec: nikt nie może już wywołać usbd -> kończy się sam (kod 0).
    close(c);
    close(listen);
    let w = wait(pid, 0);
    check!(n, w.map(|(_, s)| s) == Ok(0), "usbd did not exit cleanly: {:?}", w);
    let d = dev_claim(HW_ROOT, bdf);
    check!(n, d >= 0, "controller not released after usbd ended: {}", d);
    close(d as u64);

    println!(
        "usbtest: {} checks OK, {} xHCI controller(s), start {} ms, No-Op {}.{} us, polled {}, restart after kill {} ms, HID reports {} in 400 ms, disk mounted {} ms after start, enumeration avg {} ms / max {} ms",
        n,
        count,
        start_ms,
        ns / 1000,
        ns % 1000 / 100,
        polled,
        restart_ms,
        reports,
        mount_ms,
        enum_avg,
        enum_max
    );
    println!("usbtest-result controllers={} start_ms={} noop_ns={} polled={} restart_ms={} enum_avg_ms={} enum_max_ms={}", count, start_ms, ns, polled, restart_ms, enum_avg, enum_max);
    0
}
