// M16: init – pierwszy proces.  Kernel uruchamia tylko /bin/init; init
// uruchamia shell (/bin/sh) i:
//   * zbiera zakończone procesy (wait) – także sieroty, które kernel
//     przekazuje mu, gdy kończy się ich rodzic,
//   * gdy shell się skończy (exit, kill, błąd), uruchamia go od nowa.
// Init nie czyta klawiatury i nie da się go zabić z user space (kill -> EPERM).
//
// M19.g: menedżer usług (wariant A – w init; wariant B, osobny /bin/svcmgr,
// opisany w ARCHITEKTURA.md na później).
//   * Tabela usług niżej: nazwa, program, urządzenie PCI (albo brak).  Usługa
//     dostaje: 1 konsola, 3 urządzenie (dev_claim z HW_ROOT – slot 3 init),
//     4 kanał połączeń.
//   * Restart po końcu z odstępem 100 ms, podwajanym do 5 s (po 10 s pracy –
//     znowu od 100 ms); 5 awarii w 30 s -> usługa zepsuta (bez restartów).
//     Brak urządzenia (ENODEV) -> "no device", bez restartów.
//   * Kanał `svc`: shell i jego programy mają w slocie 3 koniec tylko do
//     wysyłania (SEND | DUP).  Prośba = komunikat z jednym uchwytem (koniec
//     kanału klienta): "connect <nazwa>" – init przekazuje uchwyt do kanału
//     połączeń usługi; "list" – init odpisuje listę usług i zamyka uchwyt.
//     Nieznana / niedziałająca usługa – uchwyt zamknięty (klient: EPIPE).
//   * Init czeka na kanał svc (wait_many, 100 ms) i zbiera dzieci (WNOHANG).
//
// M19.i: jądro daje init uchwyt SYSCTL (slot 4: reboot, halt, sync, stress);
// init przekazuje go tylko shellowi.
//
// `init test <program>` (samotesty jądra): zamiast shella uruchamia <program>
// (z kanałem svc w slocie 3), a gdy ten się skończy – zamyka usługi, czeka na
// nie i kończy się kodem programu.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const SHELL: &str = "/bin/sh";

struct Def {
    name: &'static str,
    path: &'static str,
    /// Urządzenie PCI (bus, urz., fn) albo brak.
    dev: Option<(u64, u64, u64)>,
}

/// M19.g: usługi uruchamiane przez init.
const SERVICES: [Def; 2] = [
    Def { name: "edu", path: "/bin/edud", dev: Some((0, 6, 0)) },
    Def { name: "echo", path: "/bin/echod", dev: None },
];

const FAIL_WINDOW_MS: u64 = 30_000;
const FAIL_LIMIT: usize = 5;
const STABLE_MS: u64 = 10_000;

#[derive(Clone, Copy, PartialEq)]
enum State {
    Running,
    Waiting,
    NoDevice,
    Broken,
    Stopped,
}

struct Svc {
    pid: u64,
    /// Koniec kanału połączeń po stronie init (0 = brak).
    listen: u64,
    state: State,
    restarts: u64,
    started_at: u64,
    next_start: u64,
    delay: u64,
    fails: [u64; FAIL_LIMIT],
    nfails: usize,
}

impl Svc {
    const fn new() -> Svc {
        Svc { pid: 0, listen: 0, state: State::Waiting, restarts: 0, started_at: 0, next_start: 0, delay: 100, fails: [0; FAIL_LIMIT], nfails: 0 }
    }
}

fn start_service(d: &Def, s: &mut Svc) {
    let mut dev = 0u64;
    if let Some((b, dv, f)) = d.dev {
        let h = dev_claim(HW_ROOT, bdf(b, dv, f));
        if h == ENODEV {
            s.state = State::NoDevice;
            println!("init: service {}: no device {:02x}:{:02x}.{} - not started", d.name, b, dv, f);
            return;
        }
        if h < 0 {
            // EBUSY: poprzednia instancja jeszcze się kończy – spróbuj za chwilę.
            s.state = State::Waiting;
            s.next_start = uptime_ms() + 100;
            return;
        }
        dev = h as u64;
    }
    let Ok((listen, listen_srv)) = channel_create() else {
        s.next_start = uptime_ms() + 1000;
        return;
    };
    let mut map = [(1u64, 1u64), (listen_srv, 4), (0, 0)];
    let n = if dev != 0 {
        map[2] = (dev, 3);
        3
    } else {
        2
    };
    let pid = spawn_ex(d.path, &[d.name], &map[..n], 0);
    if dev != 0 {
        close(dev);
    }
    close(listen_srv);
    if pid <= 0 {
        close(listen);
        println!("init: service {}: cannot start {}: {}", d.name, d.path, strerror(pid));
        s.state = State::Broken;
        return;
    }
    s.pid = pid as u64;
    s.listen = listen;
    s.state = State::Running;
    s.started_at = uptime_ms();
    if s.restarts == 0 {
        println!("init: service {} started (pid {})", d.name, pid);
    } else {
        println!("init: service {} restarted (pid {}, restart {})", d.name, pid, s.restarts);
    }
}

/// Usługa się skończyła – restart z odstępem albo "zepsuta".
fn service_ended(d: &Def, s: &mut Svc, status: u64) {
    if s.listen != 0 {
        close(s.listen);
        s.listen = 0;
    }
    s.pid = 0;
    if s.state == State::Stopped {
        return;
    }
    let now = uptime_ms();
    if now.saturating_sub(s.started_at) >= STABLE_MS {
        s.delay = 100;
    }
    // Lista ostatnich awarii (okno 30 s).
    let mut k = 0;
    for i in 0..s.nfails {
        if now.saturating_sub(s.fails[i]) < FAIL_WINDOW_MS {
            s.fails[k] = s.fails[i];
            k += 1;
        }
    }
    s.nfails = k;
    if s.nfails < FAIL_LIMIT {
        s.fails[s.nfails] = now;
        s.nfails += 1;
    }
    if s.nfails >= FAIL_LIMIT {
        s.state = State::Broken;
        println!("init: service {} {} - {} failures in 30 s, not restarting", d.name, describe_status(status), FAIL_LIMIT);
        return;
    }
    println!("init: service {} {} - restart in {} ms", d.name, describe_status(status), s.delay);
    s.state = State::Waiting;
    s.next_start = now + s.delay;
    s.delay = (s.delay * 2).min(5000);
    s.restarts += 1;
}

fn state_name(s: State) -> &'static str {
    match s {
        State::Running => "running",
        State::Waiting => "restarting",
        State::NoDevice => "no device",
        State::Broken => "broken",
        State::Stopped => "stopped",
    }
}

/// Prośby na kanale svc (bez czekania – wszystkie, które są).
fn serve_svc(svc: u64, svcs: &[Svc]) {
    let mut msg = [0u8; 128];
    let mut hs = [0u64; 1];
    let mut info = RecvInfo::default();
    loop {
        let r = chan_recv_h(svc, &mut msg, &mut hs, CHAN_NONBLOCK, &mut info);
        if r < 0 {
            if r == EMSGSIZE {
                // Za długa / z za wieloma uchwytami – zdejmij i odrzuć.
                let mut big = [0u8; MSG_MAX];
                let mut many = [0u64; MSG_HANDLES];
                if chan_recv_h(svc, &mut big, &mut many, CHAN_NONBLOCK, &mut info) >= 0 {
                    for &h in &many[..info.handles as usize] {
                        close(h);
                    }
                }
                continue;
            }
            return;
        }
        if info.handles != 1 {
            continue;
        }
        let h = hs[0];
        let text = core::str::from_utf8(&msg[..r as usize]).unwrap_or("");
        if let Some(name) = text.strip_prefix("connect ") {
            let found = SERVICES.iter().position(|d| d.name == name);
            match found {
                Some(i) if svcs[i].state == State::Running && svcs[i].listen != 0 => {
                    // Uchwyt klienta idzie dalej; błąd – wraca do nas i go zamykamy.
                    if chan_send_h(svcs[i].listen, name.as_bytes(), &[h], CHAN_NONBLOCK) != 0 {
                        close(h);
                    }
                }
                _ => {
                    close(h);
                }
            }
        } else if text == "list" {
            let mut out = [0u8; 1024];
            let mut n = 0;
            for (d, s) in SERVICES.iter().zip(svcs.iter()) {
                let mut line = Out2::new(&mut out[n..]);
                let _ = core::fmt::write(
                    &mut line,
                    format_args!("{} {} pid {} restarts {} ({})\n", d.name, state_name(s.state), s.pid, s.restarts, d.path),
                );
                n += line.len;
            }
            chan_send(h, &out[..n], CHAN_NONBLOCK);
            close(h);
        } else {
            close(h);
        }
    }
}

/// Zapis sformatowanego tekstu do bufora (bez alokacji).
struct Out2<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Out2<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Out2 { buf, len: 0 }
    }
}

impl core::fmt::Write for Out2<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let b = s.as_bytes();
        let n = b.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
        Ok(())
    }
}

/// Shell (albo program testowy) z kanałem svc w slocie 3 i SYSCTL w slocie 4.
fn start_shell(path: &str, svc_client: u64) -> u64 {
    loop {
        let name = path.rsplit('/').next().unwrap_or(path);
        // M19.i: shell dostaje też uchwyt SYSCTL (slot 4) – reboot, halt, sync, stress.
        let map = [(0, 0), (1, 1), (2, 2), (svc_client, 3), (SYSCTL, 4)];
        let n = if handle_info(SYSCTL).map(|(k, _)| k) == Ok(KIND_SYSCTL) { 5 } else { 4 };
        let pid = spawn_ex(path, &[name], &map[..n], 0);
        if pid > 0 {
            return pid as u64;
        }
        eprintln!("init: cannot start {}: {} - retrying in 1 s", path, strerror(pid));
        sleep_ms(1000);
    }
}

fn main(args: Args) -> i32 {
    let test = if args.get(1) == Some("test") { args.get(2) } else { None };
    let shell_path = test.unwrap_or(SHELL);
    println!("init: started (pid {}), starting {}", getpid(), shell_path);

    // Kanał svc: init odbiera, klienci (shell i jego programy) tylko wysyłają.
    let (svc, svc_any) = channel_create().unwrap_or((0, 0));
    let svc_client = handle_dup(svc_any, R_SEND | R_DUP) as u64;
    close(svc_any);

    let mut svcs = [const { Svc::new() }; SERVICES.len()];
    for (d, s) in SERVICES.iter().zip(svcs.iter_mut()) {
        start_service(d, s);
    }

    let mut shell = start_shell(shell_path, svc_client);
    let mut started_at = uptime_ms();
    let mut orphans = 0u64;
    loop {
        // Usługi czekające na restart.
        let now = uptime_ms();
        let mut timeout = 100;
        for (d, s) in SERVICES.iter().zip(svcs.iter_mut()) {
            if s.state == State::Waiting {
                if now >= s.next_start {
                    start_service(d, s);
                } else {
                    timeout = timeout.min(s.next_start - now);
                }
            }
        }
        if wait_many(&[(svc, W_READABLE)], timeout.max(1)) == Ok(1) {
            serve_svc(svc, &svcs);
        }
        // Zakończone dzieci: shell, usługi, sieroty.
        loop {
            let Ok((pid, status)) = wait(WAIT_ANY, WNOHANG) else { break };
            if pid == 0 {
                break;
            }
            if pid == shell {
                if let Some(_) = test {
                    // Sieroty, które jeszcze czekają – policzone w raporcie.
                    while let Ok((p, _)) = wait(WAIT_ANY, WNOHANG) {
                        if p == 0 {
                            break;
                        }
                        if !svcs.iter().any(|s| s.pid == p) {
                            orphans += 1;
                        }
                    }
                    println!("init: test program ended, {} orphans reaped", orphans);
                    // Tryb testowy: koniec programu = koniec init (po usługach).
                    for (d, s) in SERVICES.iter().zip(svcs.iter_mut()) {
                        s.state = State::Stopped;
                        if s.listen != 0 {
                            close(s.listen);
                            s.listen = 0;
                        }
                        if s.pid != 0 {
                            kill(s.pid);
                            let _ = wait(s.pid, 0);
                            s.pid = 0;
                        }
                        let _ = d;
                    }
                    return if status & STATUS_SIGNALED != 0 { 100 } else { status as i32 };
                }
                // Shell padający od razu po starcie (np. uszkodzony plik)
                // nie może zająć CPU w kółko.
                if uptime_ms().saturating_sub(started_at) < 1000 {
                    sleep_ms(1000);
                }
                println!("init: shell {} {} - starting a new one", pid, describe_status(status));
                shell = start_shell(shell_path, svc_client);
                started_at = uptime_ms();
                continue;
            }
            if let Some(i) = svcs.iter().position(|s| s.pid == pid && pid != 0) {
                service_ended(&SERVICES[i], &mut svcs[i], status);
            } else {
                // Sierota przekazana przez kernel – już sprzątnięta.
                orphans += 1;
            }
        }
    }
}
