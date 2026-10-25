// init – the first process.  The kernel starts only /bin/init; init
// starts the shell (/bin/sh) and:
//   * reaps finished processes (wait) – including orphans, which the kernel
//     hands over to it when their parent exits,
//   * when the shell exits (exit, kill, error), starts it again.
// Init does not read the keyboard and cannot be killed from user space (kill -> EPERM).
//
// Service manager (variant A – inside init; variant B, a separate /bin/svcmgr,
// is described in ARCHITECTURE.md for later).
//   * Service table below: name, program, PCI device (or none).  A service
//     gets: 1 console, 3 device (dev_claim from HW_ROOT – init's slot 3),
//     4 connection channel.
//   * Restart after exit with a 100 ms delay, doubled up to 5 s (after 10 s of running –
//     back to 100 ms); 5 failures within 30 s -> service broken (no more restarts).
//     No device (ENODEV) -> "no device", no restarts.
//   * The `svc` channel: the shell and its programs hold a send-only end in slot 3
//     (SEND | DUP).  A request = a message with one handle (the client's channel
//     end): "connect <name>" – init forwards the handle to the service's connection
//     channel; "list" – init replies with the service list and closes the handle.
//     Unknown / non-running service – handle closed (client: EPIPE).
//   * Init waits on the svc channel (wait_many, 100 ms) and reaps children (WNOHANG).
//
// USB xHCI controllers are found by class (dev_find 0C0330), and for
// each one a service usb0, usb1, … is added (/bin/usbd with that controller).
// Network cards likewise (class 020000) – net0, net1 (/bin/netd); a card netd has
// no driver for ends with exit code 78 and is not restarted ("no driver").
//
// The kernel gives init an INPUT handle (slot 5) – init passes it only to usbd.
// And a BLK handle (slot 6: USB disk registration) – also only for usbd.
//
// The kernel gives init a SYSCTL handle (slot 4: reboot, halt, sync, stress);
// init passes it only to the shell.
//
// `init test <program>` (kernel self-tests): runs <program> instead of the shell
// (with the svc channel in slot 3), and when it finishes – shuts down services, waits for
// them and exits with the program's exit code.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const SHELL: &str = "/bin/sh";

#[derive(Clone, Copy)]
struct Def {
    name: &'static str,
    path: &'static str,
    /// PCI device (bus, dev, fn) or none.
    dev: Option<(u64, u64, u64)>,
}

/// Services started by init (fixed).
const SERVICES: [Def; 2] = [
    Def { name: "edu", path: "/bin/edud", dev: Some((0, 6, 0)) },
    Def { name: "echo", path: "/bin/echod", dev: None },
];

/// Maximum number of USB controllers (services usb0..usb3).
const USB_NAMES: [&str; 4] = ["usb0", "usb1", "usb2", "usb3"];
/// Maximum number of network cards (services net0, net1).
const NET_NAMES: [&str; 2] = ["net0", "net1"];
const MAX_SERVICES: usize = SERVICES.len() + USB_NAMES.len() + NET_NAMES.len();
/// Exit code of a service that has no driver for its device – not restarted.
const EXIT_NO_DRIVER: u64 = 78;

/// Service table: fixed services + one usbd per xHCI controller.
fn service_table(defs: &mut [Def; MAX_SERVICES]) -> usize {
    let mut n = 0;
    for d in SERVICES {
        defs[n] = d;
        n += 1;
    }
    for (i, name) in USB_NAMES.iter().enumerate() {
        let bdf = dev_find(HW_ROOT, CLASS_XHCI, i as u64);
        if bdf < 0 {
            break;
        }
        let b = bdf as u64;
        let dev = (b >> 8, (b >> 3) & 31, b & 7);
        println!("init: {} = xHCI USB controller {:02x}:{:02x}.{}", name, dev.0, dev.1, dev.2);
        defs[n] = Def { name, path: "/bin/usbd", dev: Some(dev) };
        n += 1;
    }
    for (i, name) in NET_NAMES.iter().enumerate() {
        let bdf = dev_find(HW_ROOT, CLASS_ETHERNET, i as u64);
        if bdf < 0 {
            break;
        }
        let b = bdf as u64;
        let dev = (b >> 8, (b >> 3) & 31, b & 7);
        println!("init: {} = network card {:02x}:{:02x}.{}", name, dev.0, dev.1, dev.2);
        defs[n] = Def { name, path: "/bin/netd", dev: Some(dev) };
        n += 1;
    }
    n
}

const FAIL_WINDOW_MS: u64 = 30_000;
const FAIL_LIMIT: usize = 5;
const STABLE_MS: u64 = 10_000;

#[derive(Clone, Copy, PartialEq)]
enum State {
    Running,
    Waiting,
    NoDevice,
    NoDriver,
    Broken,
    Stopped,
}

struct Svc {
    pid: u64,
    /// Init's end of the connection channel (0 = none).
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
            // EBUSY: the previous instance is still exiting – try again shortly.
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
    let mut map = [(1u64, 1u64), (listen_srv, 4), (0, 0), (0, 0), (0, 0)];
    let mut n = 2;
    if dev != 0 {
        map[n] = (dev, 3);
        n += 1;
    }
    // usbd gets a copy of the INPUT handle (slot 5) – keyboard /
    // mouse events to the kernel.  Each copy is a separate source (usbd exiting releases keys).
    if d.path == "/bin/usbd" && handle_info(INPUT).map(|(k, _)| k) == Ok(KIND_INPUT) {
        map[n] = (INPUT, 5);
        n += 1;
    }
    // And a copy of the BLK handle (slot 6) – USB flash drives as kernel disks.
    if d.path == "/bin/usbd" && handle_info(BLK).map(|(k, _)| k) == Ok(KIND_BLK) {
        map[n] = (BLK, 6);
        n += 1;
    }
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
        if d.path == "/bin/usbd" {
            // What the user sees – the USB keyboard will come back after enumeration.
            println!("init: {}: USB keyboard and disks back in a moment", d.name);
        }
    }
}

/// A service has exited – restart with a delay or mark it "broken".
fn service_ended(d: &Def, s: &mut Svc, status: u64) {
    if s.listen != 0 {
        close(s.listen);
        s.listen = 0;
    }
    s.pid = 0;
    if s.state == State::Stopped {
        return;
    }
    if status == EXIT_NO_DRIVER {
        s.state = State::NoDriver;
        println!("init: service {}: no driver for this device - not restarting", d.name);
        return;
    }
    let now = uptime_ms();
    if now.saturating_sub(s.started_at) >= STABLE_MS {
        s.delay = 100;
    }
    // List of recent failures (30 s window).
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
        if d.path == "/bin/usbd" {
            // A clear message – without it a laptop without PS/2 "just" loses its keyboard.
            println!("init: USB controller {} disabled after {} failures - its USB keyboard and disks are unavailable until reboot (PS/2 still works)", d.name, FAIL_LIMIT);
        }
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
        State::NoDriver => "no driver",
        State::Broken => "broken",
        State::Stopped => "stopped",
    }
}

/// Requests on the svc channel (non-blocking – all that are pending).
/// What a service channel may do: the shell's channel everything; a narrowed
/// one (for sandboxed programs, `svc_narrow`) only network connections.
const G_ALL: u8 = 0xFF;
const G_NET: u8 = 1;
const G_LISTEN: u8 = 2;
/// Narrowed channels at once.
const NARROW_MAX: usize = 12;

/// Narrowed service channels: (init's receiving end, grants); handle 0 = free.
struct Narrowed {
    ch: [(u64, u8); NARROW_MAX],
}

impl Narrowed {
    const fn new() -> Narrowed {
        Narrowed { ch: [(0, 0); NARROW_MAX] }
    }
}

/// The text init hands to a network service with a client connection: the
/// service name and what this client may do ("admin" – DNS server, DHCP;
/// "listen" – servers; "client" – connections only).
fn net_kind(name: &str, grants: u8, out: &mut [u8; 64]) -> usize {
    let mut n = 0;
    let mut put = |b: &[u8], out: &mut [u8; 64]| {
        let k = b.len().min(64 - n);
        out[n..n + k].copy_from_slice(&b[..k]);
        n += k;
    };
    put(name.as_bytes(), out);
    if grants == G_ALL {
        put(b" admin listen", out);
    } else {
        put(b" client", out);
        if grants & G_LISTEN != 0 {
            put(b" listen", out);
        }
    }
    n
}

/// Serves the queued requests; true when nobody holds the sending end any more.
fn serve_svc(svc: u64, grants: u8, defs: &[Def], svcs: &[Svc], narrowed: &mut Narrowed) -> bool {
    let mut msg = [0u8; 128];
    let mut hs = [0u64; 1];
    let mut info = RecvInfo::default();
    loop {
        let r = chan_recv_h(svc, &mut msg, &mut hs, CHAN_NONBLOCK, &mut info);
        if r < 0 {
            if r == EMSGSIZE {
                // Too long / with too many handles – dequeue and reject.
                let mut big = [0u8; MSG_MAX];
                let mut many = [0u64; MSG_HANDLES];
                if chan_recv_h(svc, &mut big, &mut many, CHAN_NONBLOCK, &mut info) >= 0 {
                    for &h in &many[..info.handles as usize] {
                        close(h);
                    }
                }
                continue;
            }
            return r == EPIPE;
        }
        if info.handles != 1 {
            continue;
        }
        let h = hs[0];
        let text = core::str::from_utf8(&msg[..r as usize]).unwrap_or("");
        if let Some(name) = text.strip_prefix("connect ") {
            let found = defs.iter().position(|d| d.name == name);
            let net = name.starts_with("net");
            // A narrowed channel reaches network services only.
            let allowed = grants == G_ALL || (net && grants & G_NET != 0);
            match found {
                Some(i) if allowed && svcs[i].state == State::Running && svcs[i].listen != 0 => {
                    let mut kind = [0u8; 64];
                    let msg: &[u8] = if net {
                        let n = net_kind(name, grants, &mut kind);
                        &kind[..n]
                    } else {
                        name.as_bytes()
                    };
                    // The client's handle is passed on; on error it comes back to us and we close it.
                    if chan_send_h(svcs[i].listen, msg, &[h], CHAN_NONBLOCK) != 0 {
                        close(h);
                    }
                }
                _ => {
                    close(h);
                }
            }
        } else if let Some(tokens) = text.strip_prefix("narrow ") {
            // A new service channel with fewer rights; never more than this one has.
            let mut want = 0u8;
            for t in tokens.split_whitespace() {
                match t {
                    "net" => want |= G_NET,
                    "listen" => want |= G_NET | G_LISTEN,
                    _ => {}
                }
            }
            let want = want & grants;
            let slot = narrowed.ch.iter().position(|c| c.0 == 0);
            match (want != 0, slot, channel_create()) {
                (true, Some(k), Ok((srv, cli_any))) => {
                    let cli = handle_dup(cli_any, R_SEND | R_DUP | R_TRANSFER);
                    close(cli_any);
                    if cli >= 0 && chan_send_h(h, b"narrowed", &[cli as u64], CHAN_NONBLOCK) == 0 {
                        narrowed.ch[k] = (srv, want);
                    } else {
                        close(srv);
                        if cli >= 0 {
                            close(cli as u64);
                        }
                    }
                }
                (_, _, Ok((a, b))) => {
                    close(a);
                    close(b);
                }
                _ => {}
            }
            close(h);
        } else if text == "list" {
            let mut out = [0u8; 1024];
            let mut n = 0;
            for (d, s) in defs.iter().zip(svcs.iter()) {
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

/// Writes formatted text into a buffer (no allocation).
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

/// Shell (or test program) with the svc channel in slot 3 and SYSCTL in slot 4.
fn start_shell(path: &str, extra: Option<&str>, svc_client: u64) -> u64 {
    loop {
        let name = path.rsplit('/').next().unwrap_or(path);
        // The shell also gets the SYSCTL handle (slot 4) – reboot, halt, sync, stress.
        let map = [(0, 0), (1, 1), (2, 2), (svc_client, 3), (SYSCTL, 4)];
        let n = if handle_info(SYSCTL).map(|(k, _)| k) == Ok(KIND_SYSCTL) { 5 } else { 4 };
        // Test mode – one argument for the program (`init test /bin/x arg`).
        let pid = match extra {
            Some(a) => spawn_ex(path, &[name, a], &map[..n], 0),
            None => spawn_ex(path, &[name], &map[..n], 0),
        };
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
    let test_arg = if test.is_some() { args.get(3) } else { None };
    println!("init: started (pid {}), starting {}", getpid(), shell_path);

    // svc channel: init receives, clients (the shell and its programs) only send.
    let (svc, svc_any) = channel_create().unwrap_or((0, 0));
    let svc_client = handle_dup(svc_any, R_SEND | R_DUP) as u64;
    close(svc_any);

    let mut table = [SERVICES[0]; MAX_SERVICES];
    let nsvc = service_table(&mut table);
    let defs = &table[..nsvc];
    let mut svcs_all = [const { Svc::new() }; MAX_SERVICES];
    let svcs = &mut svcs_all[..nsvc];
    for (d, s) in defs.iter().zip(svcs.iter_mut()) {
        start_service(d, s);
    }

    let mut narrowed = Narrowed::new();
    let mut shell = start_shell(shell_path, test_arg, svc_client);
    let mut started_at = uptime_ms();
    let mut orphans = 0u64;
    loop {
        // Services waiting for a restart.
        let now = uptime_ms();
        let mut timeout = 100;
        for (d, s) in defs.iter().zip(svcs.iter_mut()) {
            if s.state == State::Waiting {
                if now >= s.next_start {
                    start_service(d, s);
                } else {
                    timeout = timeout.min(s.next_start - now);
                }
            }
        }
        // The shell's service channel and the narrowed ones.
        let mut list = [(svc, W_READABLE); 1 + NARROW_MAX];
        let mut which = [usize::MAX; 1 + NARROW_MAX];
        let mut k = 1;
        for (i, c) in narrowed.ch.iter().enumerate() {
            if c.0 != 0 {
                list[k] = (c.0, W_READABLE);
                which[k] = i;
                k += 1;
            }
        }
        let ready = wait_many(&list[..k], timeout.max(1)).unwrap_or(0);
        if ready & 1 != 0 {
            serve_svc(svc, G_ALL, defs, svcs, &mut narrowed);
        }
        for e in 1..k {
            if ready & (1 << e) != 0 {
                let i = which[e];
                let (ch, grants) = narrowed.ch[i];
                // Nobody holds the other end any more: forget the channel.
                if serve_svc(ch, grants, defs, svcs, &mut narrowed) {
                    close(ch);
                    narrowed.ch[i] = (0, 0);
                }
            }
        }
        // Finished children: shell, services, orphans.
        loop {
            let Ok((pid, status)) = wait(WAIT_ANY, WNOHANG) else { break };
            if pid == 0 {
                break;
            }
            if pid == shell {
                if let Some(_) = test {
                    // Orphans still waiting – counted in the report.
                    while let Ok((p, _)) = wait(WAIT_ANY, WNOHANG) {
                        if p == 0 {
                            break;
                        }
                        if !svcs.iter().any(|s| s.pid == p) {
                            orphans += 1;
                        }
                    }
                    println!("init: test program ended, {} orphans reaped", orphans);
                    // Test mode: end of the program = end of init (after services).
                    for (d, s) in defs.iter().zip(svcs.iter_mut()) {
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
                // A shell that dies immediately after start (e.g. a corrupted file)
                // must not hog the CPU in a loop.
                if uptime_ms().saturating_sub(started_at) < 1000 {
                    sleep_ms(1000);
                }
                println!("init: shell {} {} - starting a new one", pid, describe_status(status));
                shell = start_shell(shell_path, test_arg, svc_client);
                started_at = uptime_ms();
                continue;
            }
            if let Some(i) = svcs.iter().position(|s| s.pid == pid && pid != 0) {
                service_ended(&defs[i], &mut svcs[i], status);
            } else {
                // Orphan handed over by the kernel – already reaped.
                orphans += 1;
            }
        }
    }
}
