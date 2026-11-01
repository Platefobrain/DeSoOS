// init – the first process.  The kernel starts only /bin/init; init
// starts the shell (/bin/sh) and:
//   * reaps finished processes (wait) – including orphans, which the kernel
//     hands over to it when their parent exits,
//   * when the shell exits (exit, kill, error), starts it again.
// Init does not read the keyboard and cannot be killed from user space (kill -> ERROR_NOT_PERMITTED).
//
// Service manager (variant A – inside init; variant B, a separate /bin/svcmgr,
// is described in ARCHITECTURE.md for later).
//   * Services come from manifests, /etc/services/*.svc (read once, at init's start –
//     a file changed later has no effect; every boot writes them anew from the image).  A manifest says exactly what
//     a service gets; nothing else is given:
//         name       usb                 service name (usb0, usb1… with `instances`)
//         title      xHCI USB controller what the device is (messages only)
//         program    /bin/usbd
//         device     class 0c0330        every device of a PCI class (dev_find) …
//         device     pci 00:06.0         … or one PCI device, or no line – no device
//         instances  4                   at most this many devices of the class (default 1)
//         grant      input               the INPUT handle (slot 5: keyboard / mouse events)
//         grant      blk                 the BLK handle (slot 6: USB disk registration)
//         files      none                no file access at all (SPAWN_NO_FILES) | all
//     An unknown key or grant, a missing name / program / files line: the manifest is
//     refused ("bad manifest") and the service is not started.
//   * A service gets: 1 console, 3 device (dev_claim from HW_ROOT – init's slot 3),
//     4 connection channel, and the grants of its manifest.
//   * Restart after exit with a 100 ms delay, doubled up to 5 s (after 10 s of running –
//     back to 100 ms); 5 failures within 30 s -> service broken (no more restarts).
//     No device (ERROR_NO_DEVICE) -> "no device", no restarts.
//   * The `svc` channel: the shell and its programs hold a send-only end in slot 3
//     (SEND | DUP).  A request = a message with one handle (the client's channel
//     end): "connect <name>" – init forwards the handle to the service's connection
//     channel; "list" – init replies with the service list and closes the handle.
//     Unknown / non-running service – handle closed (client: ERROR_CLOSED).
//   * Init waits on the svc channel (wait_many, 100 ms) and reaps children (WNOHANG).
//
// USB xHCI controllers (usb.svc: class 0C0330) give usb0, usb1, … and network cards
// (net.svc: class 020000) net0, net1; a card netd has no driver for ends with exit
// code 78 and is not restarted ("no driver").
//
// The kernel gives init an INPUT handle (slot 5) and a BLK handle (slot 6: USB disk
// registration) – init passes them only to services whose manifest grants them.
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

/// Grants a manifest can give (bits of `Def::grants`).
const G_INPUT: u8 = 1;
const G_BLK: u8 = 2;

/// A short text kept in place (no heap in init).
#[derive(Clone, Copy)]
struct Text<const N: usize> {
    b: [u8; N],
    n: u8,
}

impl<const N: usize> Text<N> {
    const EMPTY: Self = Text { b: [0; N], n: 0 };
    fn from(s: &str) -> Option<Self> {
        if s.is_empty() || s.len() > N {
            return None;
        }
        let mut t = Self::EMPTY;
        t.b[..s.len()].copy_from_slice(s.as_bytes());
        t.n = s.len() as u8;
        Some(t)
    }
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.b[..self.n as usize]).unwrap_or("")
    }
}

/// One service instance, from a manifest.
#[derive(Clone, Copy)]
struct Def {
    name: Text<16>,
    path: Text<48>,
    title: Text<32>,
    /// PCI device (bus, dev, fn) or none.
    dev: Option<(u64, u64, u64)>,
    grants: u8,
    /// `files all` – otherwise the service is started without file access.
    files: bool,
}

impl Def {
    const EMPTY: Def = Def { name: Text::EMPTY, path: Text::EMPTY, title: Text::EMPTY, dev: None, grants: 0, files: false };
    fn name(&self) -> &str {
        self.name.as_str()
    }
    fn path(&self) -> &str {
        self.path.as_str()
    }
}

/// Where the manifests are.
const MANIFESTS: &str = "/etc/services";
/// At most this many service instances.
const MAX_SERVICES: usize = 16;
/// Exit code of a service that has no driver for its device – not restarted.
const EXIT_NO_DRIVER: u64 = 78;

enum Device {
    None,
    Pci(u64, u64, u64),
    Class(u64),
}

/// A parsed manifest.
struct Manifest {
    def: Def,
    device: Device,
    instances: u64,
}

fn hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s, 16).ok()
}

/// Parses a manifest; Err((line, what is wrong)).
fn parse_manifest(text: &str) -> Result<Manifest, (usize, &'static str)> {
    let mut m = Manifest { def: Def::EMPTY, device: Device::None, instances: 1 };
    let (mut has_name, mut has_files) = (false, false);
    // Keys allowed once (bit per key).
    let mut seen = 0u32;
    const ONCE: [&str; 6] = ["name", "title", "program", "device", "instances", "files"];
    for (i, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let err = |what| Err((i + 1, what));
        let (key, rest) = line.split_once(char::is_whitespace).map_or((line, ""), |(k, r)| (k, r.trim()));
        if let Some(k) = ONCE.iter().position(|&o| o == key) {
            if seen & (1 << k) != 0 {
                return err("key given twice");
            }
            seen |= 1 << k;
        }
        match key {
            "name" => match Text::from(rest) {
                Some(t) if rest.len() <= 14 && rest.bytes().all(|c| c.is_ascii_alphanumeric()) => {
                    m.def.name = t;
                    has_name = true;
                }
                _ => return err("name: 1-14 letters or digits"),
            },
            "title" => m.def.title = Text::from(rest).ok_or((i + 1, "title: 1-32 characters"))?,
            "program" => match Text::from(rest) {
                Some(t) if rest.starts_with('/') => m.def.path = t,
                _ => return err("program: an absolute path of at most 48 characters"),
            },
            "device" => {
                m.device = match rest.split_once(char::is_whitespace).map(|(a, b)| (a, b.trim())) {
                    Some(("class", c)) if c.len() == 6 => Device::Class(hex(c).ok_or((i + 1, "device class: 6 hex digits"))?),
                    Some(("pci", a)) => {
                        // bb:dd.f
                        let p = a.split_once(':').and_then(|(b, df)| df.split_once('.').map(|(d, f)| (b, d, f)));
                        match p.and_then(|(b, d, f)| Some((hex(b)?, hex(d)?, hex(f)?))) {
                            Some((b, d, f)) if b < 256 && d < 32 && f < 8 => Device::Pci(b, d, f),
                            _ => return err("device pci: bus:device.function, e.g. 00:06.0"),
                        }
                    }
                    _ => return err("device: class <6 hex digits> or pci <bb:dd.f>"),
                }
            }
            "instances" => match rest.parse::<u64>() {
                Ok(n) if (1..=8).contains(&n) => m.instances = n,
                _ => return err("instances: 1-8"),
            },
            "grant" => {
                let g = match rest {
                    "input" => G_INPUT,
                    "blk" => G_BLK,
                    _ => return err("unknown grant (known: input, blk)"),
                };
                if m.def.grants & g != 0 {
                    return err("grant given twice");
                }
                m.def.grants |= g;
            }
            "files" => match rest {
                "none" => (m.def.files, has_files) = (false, true),
                "all" => (m.def.files, has_files) = (true, true),
                _ => return err("files: none or all"),
            },
            _ => return err("unknown key"),
        }
    }
    if !has_name {
        return Err((0, "no name"));
    }
    if m.def.path.n == 0 {
        return Err((0, "no program"));
    }
    if !has_files {
        return Err((0, "no files line (none or all)"));
    }
    if m.instances > 1 && !matches!(m.device, Device::Class(_)) {
        return Err((0, "instances need a device class"));
    }
    Ok(m)
}

/// Service table from the manifests in /etc/services (in name order): one entry per
/// service, or per device of its class.
fn service_table(defs: &mut [Def; MAX_SERVICES]) -> usize {
    static mut LIST: [u8; 4096] = [0; 4096];
    let list = unsafe { &mut *core::ptr::addr_of_mut!(LIST) };
    let len = readdir(MANIFESTS, list);
    if len < 0 {
        println!("init: {}: {} - no services", MANIFESTS, strerror(len));
        return 0;
    }
    let mut n = 0;
    let text = core::str::from_utf8(&list[..len as usize]).unwrap_or("");
    for line in text.lines() {
        let file = line.rsplit('\t').next().unwrap_or("");
        if !line.starts_with('f') || !file.ends_with(".svc") {
            continue;
        }
        let mut path = [0u8; 80];
        let p = {
            let mut o = Out2::new(&mut path);
            let _ = core::fmt::write(&mut o, format_args!("{}/{}", MANIFESTS, file));
            o.len
        };
        let path = core::str::from_utf8(&path[..p]).unwrap_or("");
        let mut buf = [0u8; 2048];
        let fd = open(path, O_READ);
        let r = if fd >= 0 { read(fd as u64, &mut buf) } else { fd };
        if fd >= 0 {
            close(fd as u64);
        }
        if r < 0 || r as usize == buf.len() {
            println!("init: {}: cannot read ({}) - not started", path, if r < 0 { strerror(r) } else { "too long" });
            continue;
        }
        let m = match parse_manifest(core::str::from_utf8(&buf[..r as usize]).unwrap_or("")) {
            Ok(m) => m,
            Err((line, what)) => {
                println!("init: {}: bad manifest (line {}: {}) - not started", path, line, what);
                continue;
            }
        };
        // Names must be unique – also against the instances of class services (usb0…).
        let taken = |defs: &[Def], name: &str| defs.iter().any(|d| d.name() == name);
        match m.device {
            Device::None | Device::Pci(..) => {
                if taken(&defs[..n], m.def.name()) {
                    println!("init: {}: bad manifest (service name {} already used) - not started", path, m.def.name());
                    continue;
                }
                if n == MAX_SERVICES {
                    println!("init: {}: more than {} services - not started", path, MAX_SERVICES);
                    continue;
                }
                defs[n] = m.def;
                if let Device::Pci(b, d, f) = m.device {
                    defs[n].dev = Some((b, d, f));
                }
                n += 1;
            }
            Device::Class(class) => {
                // All its devices first: the whole manifest fits or none of it is started
                // (no device silently left without its driver).
                let found = (0..m.instances).take_while(|&i| dev_find(HW_ROOT, class, i) >= 0).count();
                if n + found > MAX_SERVICES {
                    println!("init: {}: {} devices would exceed {} services - not started", path, found, MAX_SERVICES);
                    continue;
                }
                let more = dev_find(HW_ROOT, class, m.instances);
                if more >= 0 {
                    println!("init: {}: more than {} devices of class {:06x} - only the first {} get a service", path, m.instances, class, m.instances);
                }
                let first = n;
                let mut clash = false;
                for i in 0..found as u64 {
                    let bdf = dev_find(HW_ROOT, class, i);
                    if bdf < 0 {
                        break;
                    }
                    let b = bdf as u64;
                    let dev = (b >> 8, (b >> 3) & 31, b & 7);
                    let mut d = m.def;
                    let mut nm = [0u8; 16];
                    let k = {
                        let mut o = Out2::new(&mut nm);
                        let _ = core::fmt::write(&mut o, format_args!("{}{}", m.def.name(), i));
                        o.len
                    };
                    d.name = Text::from(core::str::from_utf8(&nm[..k]).unwrap_or("")).unwrap_or(m.def.name);
                    if taken(&defs[..n], d.name()) {
                        clash = true;
                        break;
                    }
                    d.dev = Some(dev);
                    let title = if d.title.n > 0 { d.title.as_str() } else { "device" };
                    println!("init: {} = {} {:02x}:{:02x}.{}", d.name(), title, dev.0, dev.1, dev.2);
                    defs[n] = d;
                    n += 1;
                }
                if clash {
                    n = first;
                    println!("init: {}: bad manifest (a service name it makes is already used) - not started", path);
                }
            }
        }
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
        if h == ERROR_NO_DEVICE {
            s.state = State::NoDevice;
            println!("init: service {}: no device {:02x}:{:02x}.{} - not started", d.name(), b, dv, f);
            return;
        }
        if h == ERROR_BUSY {
            // The previous instance is still exiting – try again shortly.
            s.state = State::Waiting;
            s.next_start = uptime_ms() + 100;
            return;
        }
        if h < 0 {
            // Anything else (refused, invalid address...) will not go away by retrying.
            s.state = State::Broken;
            println!("init: service {}: cannot claim device {:02x}:{:02x}.{}: {} - not started", d.name(), b, dv, f, error_name(h));
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
    // `grant input`: a copy of the INPUT handle (slot 5) – keyboard / mouse events to the
    // kernel.  Each copy is a separate source (the service exiting releases its keys).
    if d.grants & G_INPUT != 0 && handle_info(INPUT).map(|(k, _)| k) == Ok(KIND_INPUT) {
        map[n] = (INPUT, 5);
        n += 1;
    }
    // `grant blk`: a copy of the BLK handle (slot 6) – USB flash drives as kernel disks.
    if d.grants & G_BLK != 0 && handle_info(BLK).map(|(k, _)| k) == Ok(KIND_BLK) {
        map[n] = (BLK, 6);
        n += 1;
    }
    // `files none`: no file access at all – only the handles above.
    let flags = if d.files { 0 } else { SPAWN_NO_FILES };
    let pid = spawn_ex(d.path(), &[d.name()], &map[..n], flags);
    if dev != 0 {
        close(dev);
    }
    close(listen_srv);
    if pid <= 0 {
        close(listen);
        println!("init: service {}: cannot start {}: {}", d.name(), d.path(), strerror(pid));
        s.state = State::Broken;
        return;
    }
    s.pid = pid as u64;
    s.listen = listen;
    s.state = State::Running;
    s.started_at = uptime_ms();
    if s.restarts == 0 {
        println!("init: service {} started (pid {})", d.name(), pid);
    } else {
        println!("init: service {} restarted (pid {}, restart {})", d.name(), pid, s.restarts);
        if d.grants & G_INPUT != 0 {
            // What the user sees – the USB keyboard will come back after enumeration.
            println!("init: {}: USB keyboard and disks back in a moment", d.name());
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
        println!("init: service {}: no driver for this device - not restarting", d.name());
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
        println!("init: service {} {} - {} failures in 30 s, not restarting", d.name(), describe_status(status), FAIL_LIMIT);
        if d.grants & G_INPUT != 0 {
            // A clear message – without it a laptop without PS/2 "just" loses its keyboard.
            println!("init: USB controller {} disabled after {} failures - its USB keyboard and disks are unavailable until reboot (PS/2 still works)", d.name(), FAIL_LIMIT);
        }
        return;
    }
    println!("init: service {} {} - restart in {} ms", d.name(), describe_status(status), s.delay);
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

/// What a service channel may do.  The shell's own channel: everything.  The
/// program channel (slot 5 of the shell, for the programs it starts): everything
/// but network administration – only netconfig gets the shell's own channel.
/// A narrowed one (sandboxed programs, `svc_narrow`): network connections only.
const G_ALL: u8 = 0xFF;
const G_NET: u8 = 1;
const G_LISTEN: u8 = 2;
/// Services other than the network ones.
const G_OTHER: u8 = 4;
/// Network administration (addresses, DNS servers, DHCP).
const G_NETADMIN: u8 = 8;
/// Ending a service ("kill <name>"; init restarts it by its rules).  Programs
/// cannot kill services themselves – the kernel lets a process end only its own
/// descendants, and services are init's children.
const G_SVCADMIN: u8 = 16;
const G_PROGRAMS: u8 = G_NET | G_LISTEN | G_OTHER;
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
    put(if grants & G_NETADMIN != 0 { b" admin" } else { b" client" }, out);
    if grants & G_LISTEN != 0 {
        put(b" listen", out);
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
            if r == ERROR_MESSAGE_TOO_LARGE {
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
            return r == ERROR_CLOSED;
        }
        if info.handles != 1 {
            continue;
        }
        let h = hs[0];
        let text = core::str::from_utf8(&msg[..r as usize]).unwrap_or("");
        if let Some(name) = text.strip_prefix("connect ") {
            let found = defs.iter().position(|d| d.name() == name);
            let net = name.starts_with("net");
            let allowed = grants & if net { G_NET } else { G_OTHER } != 0;
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
        } else if let Some(name) = text.strip_prefix("kill ") {
            let reply = match defs.iter().position(|d| d.name() == name.trim()) {
                _ if grants & G_SVCADMIN == 0 => Reply::Denied,
                None => Reply::Unknown,
                Some(i) if svcs[i].pid == 0 || svcs[i].state != State::Running => Reply::NotRunning,
                Some(i) => {
                    if kill(svcs[i].pid) == 0 { Reply::Killed(svcs[i].pid) } else { Reply::NotRunning }
                }
            };
            let mut out = [0u8; 64];
            let mut line = Out2::new(&mut out);
            let _ = match reply {
                Reply::Killed(pid) => core::fmt::write(&mut line, format_args!("killed {} (pid {})", name.trim(), pid)),
                Reply::Denied => core::fmt::write(&mut line, format_args!("not allowed")),
                Reply::Unknown => core::fmt::write(&mut line, format_args!("no such service")),
                Reply::NotRunning => core::fmt::write(&mut line, format_args!("not running")),
            };
            let n = line.len;
            chan_send(h, &out[..n], CHAN_NONBLOCK);
            close(h);
        } else if text == "list" {
            let mut out = [0u8; 1024];
            let mut n = 0;
            for (d, s) in defs.iter().zip(svcs.iter()) {
                let mut line = Out2::new(&mut out[n..]);
                let _ = core::fmt::write(
                    &mut line,
                    format_args!("{} {} pid {} restarts {} ({})\n", d.name(), state_name(s.state), s.pid, s.restarts, d.path()),
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

/// Answer to "kill <name>".
enum Reply {
    Killed(u64),
    Denied,
    Unknown,
    NotRunning,
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

/// Shell (or test program) with the svc channel in slot 3, SYSCTL in slot 4
/// and the program channel (for the programs it starts) in slot 5.
fn start_shell(path: &str, extra: Option<&str>, svc_client: u64, prog_client: u64) -> u64 {
    loop {
        let name = path.rsplit('/').next().unwrap_or(path);
        // The shell also gets the SYSCTL handle (slot 4) – reboot, halt, sync, stress.
        let mut map = [(0, 0), (1, 1), (2, 2), (svc_client, 3), (prog_client, 5), (0, 0)];
        let mut n = 4;
        if prog_client != 0 {
            n += 1;
        }
        if handle_info(SYSCTL).map(|(k, _)| k) == Ok(KIND_SYSCTL) {
            map[n] = (SYSCTL, 4);
            n += 1;
        }
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
    // The program channel: what the shell hands to the programs it starts.
    let (psvc, psvc_any) = channel_create().unwrap_or((0, 0));
    let prog_client = if psvc_any != 0 { handle_dup(psvc_any, R_SEND | R_DUP) as u64 } else { 0 };
    close(psvc_any);

    let mut table = [Def::EMPTY; MAX_SERVICES];
    let nsvc = service_table(&mut table);
    let defs = &table[..nsvc];
    let mut svcs_all = [const { Svc::new() }; MAX_SERVICES];
    let svcs = &mut svcs_all[..nsvc];
    for (d, s) in defs.iter().zip(svcs.iter_mut()) {
        start_service(d, s);
    }

    let mut narrowed = Narrowed::new();
    let mut shell = start_shell(shell_path, test_arg, svc_client, prog_client);
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
        // The shell's service channel, the program channel and the narrowed ones.
        let mut list = [(svc, W_READABLE); 2 + NARROW_MAX];
        let mut which = [usize::MAX; 2 + NARROW_MAX];
        list[1] = (psvc, W_READABLE);
        let mut k = 2;
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
        if ready & 2 != 0 {
            serve_svc(psvc, G_PROGRAMS, defs, svcs, &mut narrowed);
        }
        for e in 2..k {
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
                shell = start_shell(shell_path, test_arg, svc_client, prog_client);
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
