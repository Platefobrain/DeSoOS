// soak <seconds>:<seed> – the long "everything at once" test (tests/soak.sh).  The kernel
// starts it as `init test /bin/soak <seconds>:<seed>` (fw_cfg phase "soak"), so it gets
// what the shell gets from init: the service channel (slot 3), the SYSCTL handle (slot 4),
// the program channel (slot 5).  It refuses to run without them, and only on a virtio
// disk 0 (QEMU) – it FORMATS that disk.
//
// Workers (separate processes, the same program with a worker name) run all the time:
//   files   – files on DeSoFS (/disk): create, append, overwrite, patch, truncate, move
//             (copy + delete), delete, read, directories; every file is checked against
//             a model (size + seed – the content is computed from the seed, SHA-256 from
//             DeSoCrypto); snapshots with their own frozen copy of the model
//   svcnet  – kills net0 / usb0 / echo at random times; a service is back only when it
//             works again (ping + download / a file read from the USB stick / an echo
//             answer) within 30 s; between kills: downloads (size + SHA-256), ping, echo,
//             USB reads
//   procs   – spawn / wait / kill, pipes, channels, shared memory, mmap / munmap
// Checkpoints (paused workers – each finishes its operation first and checks everything
// it owns): zombies, kernel counters (`sysinfo counters`) and handles against a baseline,
// `desofs unmount` -> `desofs check` (0 errors, 0 warnings, complete) -> `desofs mount`.
// A heartbeat line every minute.  Every error: "[SOAK] ERROR worker=… seq=… …" plus the
// last 64 operations of that worker.  End: "[RESULT-SOAK] …" and code 0 (PASS) or 1.
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write as _;
use desocrypto::sha256::Sha256;
use desoos::*;

entry!(main);

/// The disk the soak formats: QEMU's virtio disk 0 (mounted at /disk), or a RAM disk it
/// makes itself (another number, mounted at /desofs).  Set once at the start of every process.
static VOL_DISK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn disk() -> u64 {
    VOL_DISK.load(core::sync::atomic::Ordering::Relaxed)
}

/// Real hardware (DESOOS_AUTOSOAK): the network and USB checks take what is there.
static HW: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn hw() -> bool {
    HW.load(core::sync::atomic::Ordering::Relaxed)
}

fn root() -> &'static str {
    if disk() == 0 { "/disk" } else { "/desofs" }
}
/// The control channel in a worker.
const CTL: u64 = 7;
/// Below this length the soak is "short" (tests/test.sh): everything happens more often.
const SHORT: u64 = 600;

fn main(args: Args) -> i32 {
    match args.get(1) {
        Some("files") => worker(args, "files"),
        Some("svcnet") => worker(args, "svcnet"),
        Some("procs") => worker(args, "procs"),
        Some("child") => child(args),
        Some(spec) if spec.contains(':') => controller(spec),
        _ => {
            eprintln!("usage: soak <seconds>:<seed>   (only from tests/soak.sh - it formats disk 0)");
            1
        }
    }
}

// ------------------------------------------------------------
// Repeatable randomness, content from a seed
// ------------------------------------------------------------

fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        mix(self.0)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
    fn range(&mut self, a: u64, b: u64) -> u64 {
        a + self.below(b - a + 1)
    }
}

/// Bytes `off..off + buf.len()` of the content with this seed.
fn fill(seed: u64, off: u64, buf: &mut [u8]) {
    let mut word = u64::MAX;
    let mut w = 0u64;
    for (k, b) in buf.iter_mut().enumerate() {
        let i = off + k as u64;
        if i >> 3 != word {
            word = i >> 3;
            w = mix(seed ^ word.wrapping_mul(0xD6E8_FEB8_6659_FD93));
        }
        *b = (w >> ((i & 7) * 8)) as u8;
    }
}

fn sha_text(d: &[u8; 32]) -> String {
    let mut t = [0u8; 64];
    String::from(desocrypto::hex(d, &mut t).unwrap_or("?"))
}

// ------------------------------------------------------------
// Operation log: the last 64 operations of a worker (shown on an error)
// ------------------------------------------------------------

const RING: usize = 64;
const LINE: usize = 120;

struct Fixed<'a> {
    buf: &'a mut [u8],
    n: usize,
}

impl core::fmt::Write for Fixed<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &b in s.as_bytes() {
            if self.n < self.buf.len() {
                self.buf[self.n] = b;
                self.n += 1;
            }
        }
        Ok(())
    }
}

struct Log {
    name: &'static str,
    seq: u64,
    lines: Box<[[u8; LINE]; RING]>,
    lens: [u8; RING],
}

impl Log {
    fn new(name: &'static str) -> Log {
        Log { name, seq: 0, lines: Box::new([[0; LINE]; RING]), lens: [0; RING] }
    }

    /// A new operation: its number and description go to the ring.
    fn op(&mut self, what: core::fmt::Arguments) {
        self.seq += 1;
        let i = (self.seq % RING as u64) as usize;
        let mut f = Fixed { buf: &mut self.lines[i], n: 0 };
        let _ = write!(f, "seq={} {}", self.seq, what);
        self.lens[i] = f.n as u8;
    }

    fn dump(&self) {
        let first = self.seq.saturating_sub(RING as u64 - 1).max(1);
        println!("[SOAK] last {} operations of worker {}:", self.seq + 1 - first, self.name);
        for s in first..=self.seq {
            let i = (s % RING as u64) as usize;
            println!("[SOAK]   {}", core::str::from_utf8(&self.lines[i][..self.lens[i] as usize]).unwrap_or("?"));
        }
    }

    fn fail(&self, what: core::fmt::Arguments) -> ! {
        println!("[SOAK] ERROR worker={} seq={} {}", self.name, self.seq, what);
        self.dump();
        exit(1)
    }
}

macro_rules! fail {
    ($log:expr, $($a:tt)*) => { $log.fail(format_args!($($a)*)) };
}

// ------------------------------------------------------------
// Small helpers
// ------------------------------------------------------------

/// Number of valid handles of this process.
fn handle_count() -> u64 {
    (0..1024).filter(|&h| handle_info(h).is_ok()).count() as u64
}

/// Reads everything from `fd` until the end.
fn read_all(fd: u64) -> Vec<u8> {
    let mut v = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = read(fd, &mut buf);
        if n <= 0 {
            return v;
        }
        v.extend_from_slice(&buf[..n as usize]);
    }
}

/// A sysctl action; its text output through a pipe.
fn sysctl_text(sys: u64, op: u64, arg: u64, name: Option<&str>) -> Result<String, i64> {
    let (r, w) = pipe()?;
    let rc = match name {
        Some(n) => sysctl_name(sys, op, arg, w, n),
        None => sysctl(sys, op, arg, w),
    };
    close(w);
    let out = read_all(r);
    close(r);
    if rc < 0 {
        return Err(rc);
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn info_text(topic: &str) -> String {
    let mut buf = vec![0u8; 64 * 1024];
    match sysinfo(topic, &mut buf) {
        Ok(n) => String::from_utf8_lossy(&buf[..n]).into_owned(),
        Err(_) => String::new(),
    }
}

/// `sysinfo counters` as (name, value) pairs.
fn counters() -> Vec<(String, u64)> {
    info_text("counters")
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(' ')?;
            Some((String::from(k), v.trim().parse().ok()?))
        })
        .collect()
}

fn counter(c: &[(String, u64)], name: &str) -> u64 {
    c.iter().find(|(k, _)| k == name).map(|(_, v)| *v).unwrap_or(u64::MAX)
}

/// Service state from init's list: (state, pid, restarts).
fn svc_status(name: &str) -> Option<(String, u64, u64)> {
    let mut buf = [0u8; 2048];
    let n = svc_list(&mut buf).ok()?;
    let text = core::str::from_utf8(&buf[..n]).ok()?;
    for line in text.lines() {
        let Some((head, _)) = line.rsplit_once(" (") else { continue };
        let Some((head, restarts)) = head.rsplit_once(" restarts ") else { continue };
        let Some((head, pid)) = head.rsplit_once(" pid ") else { continue };
        let Some((nm, state)) = head.split_once(' ') else { continue };
        if nm == name {
            return Some((String::from(state), pid.parse().ok()?, restarts.parse().ok()?));
        }
    }
    None
}

/// Handles (capabilities) a process holds, from `sysinfo dcp inspect <pid>`.
fn handles_of(pid: u64) -> u64 {
    info_text(&format!("dcp inspect {}", pid))
        .lines()
        .filter(|l| l.trim_start().bytes().next().is_some_and(|b| b.is_ascii_digit()))
        .count() as u64
}

// ------------------------------------------------------------
// Workers: the common loop and the control channel
// ------------------------------------------------------------

enum Cmd {
    Pause,
    Resume,
    Stop,
}

fn poll_cmd(block: bool) -> Option<Cmd> {
    let mut buf = [0u8; 64];
    let mut info = RecvInfo::default();
    let r = chan_recv(CTL, &mut buf, if block { 0 } else { CHAN_NONBLOCK }, &mut info);
    if r == ERROR_WOULD_BLOCK {
        return None;
    }
    if r < 0 {
        exit(1); // the controller is gone
    }
    match &buf[..r as usize] {
        b"pause" => Some(Cmd::Pause),
        b"resume" => Some(Cmd::Resume),
        b"stop" => Some(Cmd::Stop),
        _ => None,
    }
}

fn tell(text: &str, flags: u64) {
    let b = text.as_bytes();
    chan_send(CTL, &b[..b.len().min(MSG_MAX)], flags);
}

trait Work {
    /// One operation (checked by itself).
    fn step(&mut self, log: &mut Log);
    /// Counters for the heartbeat and the result ("key=value ...").
    fn stats(&self) -> String;
    /// Paused: checks everything this worker owns; text for the checkpoint line.
    fn audit(&mut self, log: &mut Log) -> String;
}

fn worker(args: Args, name: &'static str) -> i32 {
    let seed = args.get(2).and_then(|s| s.parse::<u64>().ok()).unwrap_or(1);
    let secs = args.get(3).and_then(|s| s.parse::<u64>().ok()).unwrap_or(3600);
    VOL_DISK.store(args.get(4).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0), core::sync::atomic::Ordering::Relaxed);
    HW.store(args.get(5) == Some("hw"), core::sync::atomic::Ordering::Relaxed);
    if handle_info(CTL).map(|(k, _)| k) != Ok(KIND_CHANNEL) {
        eprintln!("soak {}: no control channel - only the soak controller starts workers", name);
        return 1;
    }
    let mut log = Log::new(name);
    let short = secs < SHORT;
    let mut w: Box<dyn Work> = match name {
        "files" => Box::new(Files::new(seed, short, &mut log)),
        "svcnet" => Box::new(SvcNet::new(seed, short, &mut log)),
        _ => Box::new(Procs::new(seed)),
    };
    let mut last = uptime_ms();
    loop {
        match poll_cmd(false) {
            Some(Cmd::Pause) => {
                let a = w.audit(&mut log);
                tell(&format!("paused {} handles={} heap_end={} {}", a, handle_count(), brk(0), w.stats()), 0);
                loop {
                    match poll_cmd(true) {
                        Some(Cmd::Resume) => break,
                        Some(Cmd::Stop) => {
                            tell(&format!("stopped {}", w.stats()), 0);
                            return 0;
                        }
                        _ => {}
                    }
                }
            }
            Some(Cmd::Stop) => {
                tell(&format!("stopped {}", w.stats()), 0);
                return 0;
            }
            _ => {}
        }
        if uptime_ms() - last >= 10_000 {
            last = uptime_ms();
            tell(&format!("stats {}", w.stats()), CHAN_NONBLOCK);
        }
        w.step(&mut log);
    }
}

// ------------------------------------------------------------
// files: DeSoFS against a model
// ------------------------------------------------------------

const NFILES: usize = 500;
const MAX_FILE: u64 = 256 * 1024;
/// Dynamic (empty) directories: 4 in each of the 8 top directories.
const NDIRS: usize = 32;
const KEEP_SNAPSHOTS: usize = 6;

#[derive(Clone, Copy, Default)]
struct Ent {
    live: bool,
    size: u32,
    seed: u64,
}

#[derive(Clone)]
struct Model {
    e: Vec<Ent>,
    dirs: u32,
}

struct Snap {
    name: String,
    model: Model,
}

struct Files {
    rng: Rng,
    sys: u64,
    m: Model,
    snaps: Vec<Snap>,
    snap_no: u64,
    snap_every: u64,
    last_snap: u64,
    budget: u64,
    buf: Vec<u8>,
    exp: Vec<u8>,
    ops: u64,
    written: u64,
    made: u64,
    deleted: u64,
}

/// Directory of file slot `s` (3 levels: soak/dN/eM or soak/dN).
fn file_path(root: &str, s: usize) -> String {
    let d = s % 40;
    if d % 5 == 4 {
        format!("{}/soak/d{}/f{:03}", root, d / 5, s)
    } else {
        format!("{}/soak/d{}/e{}/f{:03}", root, d / 5, d % 5, s)
    }
}

fn dir_path(root: &str, k: usize) -> String {
    format!("{}/soak/d{}/t{}", root, k / 4, k % 4)
}

impl Files {
    fn new(seed: u64, short: bool, log: &mut Log) -> Files {
        let sys = 4;
        if handle_info(sys).map(|(k, _)| k) != Ok(KIND_SYSCTL) {
            fail!(log, "no SYSCTL handle in slot 4");
        }
        let f = Files {
            rng: Rng(mix(seed ^ 0x6669_6c65)),
            sys,
            m: Model { e: vec![Ent::default(); NFILES], dirs: 0 },
            snaps: Vec::new(),
            snap_no: 0,
            snap_every: if short { 15_000 } else { 300_000 },
            last_snap: uptime_ms(),
            budget: if short { 1 << 20 } else { 16 << 20 },
            buf: vec![0; 32 * 1024],
            exp: vec![0; 32 * 1024],
            ops: 0,
            written: 0,
            made: 0,
            deleted: 0,
        };
        log.op(format_args!("setup directories"));
        let mut dirs = vec![format!("{}/soak", root())];
        for t in 0..8 {
            dirs.push(format!("{}/soak/d{}", root(), t));
            for e in 0..4 {
                dirs.push(format!("{}/soak/d{}/e{}", root(), t, e));
            }
        }
        for d in &dirs {
            let r = mkdir(d);
            if r != 0 {
                fail!(log, "op=mkdir path={} error={}", d, error_name(r));
            }
        }
        f
    }

    fn used(&self) -> u64 {
        self.m.e.iter().filter(|e| e.live).map(|e| e.size as u64).sum()
    }

    fn pick(&mut self, live: bool) -> Option<usize> {
        let start = self.rng.below(NFILES as u64) as usize;
        (0..NFILES).map(|k| (start + k) % NFILES).find(|&s| self.m.e[s].live == live)
    }

    fn new_size(&mut self) -> u64 {
        match self.rng.below(100) {
            0..=49 => self.rng.range(0, 4096),
            50..=84 => self.rng.range(4097, 64 * 1024),
            _ => self.rng.range(64 * 1024 + 1, MAX_FILE),
        }
    }

    /// Writes content bytes `from..to` of `seed` at the current position, in random pieces.
    fn write_range(&mut self, log: &Log, fd: u64, path: &str, seed: u64, from: u64, to: u64) {
        let mut off = from;
        while off < to {
            let n = (self.rng.range(1, self.buf.len() as u64)).min(to - off) as usize;
            fill(seed, off, &mut self.buf[..n]);
            let r = write(fd, &self.buf[..n]);
            if r != n as i64 {
                fail!(log, "op=write path={} off={} len={} result={}", path, off, n, if r < 0 { error_name(r) } else { "short" });
            }
            off += n as u64;
            self.written += n as u64;
        }
    }

    fn open_or_fail(log: &Log, path: &str, flags: u64) -> u64 {
        let fd = open(path, flags);
        if fd < 0 {
            fail!(log, "op=open path={} flags={} error={}", path, flags, error_name(fd));
        }
        fd as u64
    }

    fn seek_or_fail(log: &Log, fd: u64, path: &str, off: u64) {
        let r = seek(fd, off as i64, SEEK_SET);
        if r != off as i64 {
            fail!(log, "op=seek path={} off={} result={}", path, off, r);
        }
    }

    /// The file at `path` must be exactly `e` (size and content).
    fn verify(&mut self, log: &Log, path: &str, e: Ent) {
        match stat(path) {
            Ok(st) if !st.is_dir && st.size == e.size as u64 => {}
            Ok(st) => fail!(log, "op=stat path={} expected_size={} actual_size={} dir={}", path, e.size, st.size, st.is_dir),
            Err(r) => fail!(log, "op=stat path={} expected_size={} error={}", path, e.size, error_name(r)),
        }
        let fd = Self::open_or_fail(log, path, O_READ);
        let (mut got, mut want) = (Sha256::new(), Sha256::new());
        let mut off = 0u64;
        let mut same = true;
        loop {
            let n = read(fd, &mut self.buf);
            if n < 0 {
                close(fd);
                fail!(log, "op=read path={} off={} error={}", path, off, error_name(n));
            }
            if n == 0 {
                break;
            }
            let n = n as usize;
            let k = n.min((e.size as u64).saturating_sub(off) as usize);
            fill(e.seed, off, &mut self.exp[..k]);
            if self.buf[..k] != self.exp[..k] || k != n {
                same = false;
            }
            got.update(&self.buf[..n]);
            want.update(&self.exp[..k]);
            off += n as u64;
        }
        close(fd);
        if off < e.size as u64 {
            let mut tail = e.size as u64 - off;
            let mut o = off;
            while tail > 0 {
                let k = tail.min(self.exp.len() as u64) as usize;
                fill(e.seed, o, &mut self.exp[..k]);
                want.update(&self.exp[..k]);
                o += k as u64;
                tail -= k as u64;
            }
            same = false;
        }
        if !same || off != e.size as u64 {
            let (g, w) = (got.finish().unwrap_or([0; 32]), want.finish().unwrap_or([0; 32]));
            fail!(log, "op=read path={} size={} read={} expected_sha={} actual_sha={}", path, e.size, off, sha_text(&w), sha_text(&g));
        }
    }

    fn absent(log: &Log, path: &str) {
        match stat(path) {
            Err(ERROR_NOT_FOUND) => {}
            Ok(st) => fail!(log, "op=stat path={} expected=absent size={} dir={}", path, st.size, st.is_dir),
            Err(r) => fail!(log, "op=stat path={} expected=absent error={}", path, error_name(r)),
        }
    }

    /// Every directory of `root` listed in parts (readdir_part) against the model `m`.
    fn verify_listing(log: &Log, root: &str, m: &Model) {
        let mut buf = [0u8; 512];
        let mut tops = vec![(format!("{}/soak", root), 8usize)];
        for t in 0..8 {
            tops.push((format!("{}/soak/d{}", root, t), t));
            for e in 0..4 {
                tops.push((format!("{}/soak/d{}/e{}", root, t, e), 100 + t * 4 + e));
            }
        }
        for (dir, which) in tops {
            // Expected entries: (name, size or None for a directory).
            let mut want: Vec<(String, Option<u64>)> = Vec::new();
            if which == 8 {
                for t in 0..8 {
                    want.push((format!("d{}", t), None));
                }
            } else {
                let base = if which >= 100 { which - 100 } else { which };
                for s in 0..NFILES {
                    let d = s % 40;
                    let here = if which >= 100 { d / 5 == base / 4 && d % 5 == base % 4 } else { d / 5 == base && d % 5 == 4 };
                    if here && m.e[s].live {
                        want.push((format!("f{:03}", s), Some(m.e[s].size as u64)));
                    }
                }
                if which < 100 {
                    for e in 0..4 {
                        want.push((format!("e{}", e), None));
                    }
                    for k in 0..4 {
                        if m.dirs & (1 << (base * 4 + k)) != 0 {
                            want.push((format!("t{}", k), None));
                        }
                    }
                }
            }
            let (h, rel, own) = match dir_for_listing(&dir) {
                Ok(x) => x,
                Err(r) => fail!(log, "op=dir_open path={} error={}", dir, error_name(r)),
            };
            let mut got: Vec<(String, Option<u64>)> = Vec::new();
            let mut cursor = 0u64;
            while cursor != DIR_END {
                let n = readdir_part(h, rel, &mut buf, &mut cursor);
                if n < 0 {
                    fail!(log, "op=readdir_part path={} error={}", dir, error_name(n));
                }
                for l in core::str::from_utf8(&buf[..n as usize]).unwrap_or("").lines() {
                    let mut p = l.splitn(3, '\t');
                    let (kind, size, name) = (p.next().unwrap_or(""), p.next().unwrap_or(""), p.next().unwrap_or(""));
                    got.push((String::from(name), if kind == "d" { None } else { size.parse().ok() }));
                }
            }
            if own {
                close(h);
            }
            want.sort();
            got.sort();
            if want != got {
                let extra: Vec<&String> = got.iter().filter(|g| !want.contains(g)).map(|g| &g.0).collect();
                let missing: Vec<&String> = want.iter().filter(|w| !got.contains(w)).map(|w| &w.0).collect();
                fail!(log, "op=readdir path={} missing={:?} extra={:?}", dir, missing, extra);
            }
        }
    }

    /// The whole tree under `root` against model `m`.
    fn verify_all(&mut self, log: &Log, root: &str, m: &Model) {
        Self::verify_listing(log, root, m);
        for s in 0..NFILES {
            let p = file_path(root, s);
            if m.e[s].live {
                self.verify(log, &p, m.e[s]);
            }
        }
    }

    fn snapshot(&mut self, log: &mut Log) {
        self.snap_no += 1;
        let name = format!("soak{}", self.snap_no);
        log.op(format_args!("op=snapshot_create name={}", name));
        match sysctl_text(self.sys, SYSCTL_SNAPSHOT_CREATE, disk(), Some(&name)) {
            Ok(t) if t.contains("created") => {}
            r => fail!(log, "op=snapshot_create name={} result={:?}", name, r),
        }
        self.snaps.push(Snap { name, model: self.m.clone() });
        self.made += 1;
        if self.snaps.len() > KEEP_SNAPSHOTS {
            let old = self.snaps.remove(0);
            log.op(format_args!("op=snapshot_delete name={}", old.name));
            match sysctl_text(self.sys, SYSCTL_SNAPSHOT_DELETE, disk() | SYSCTL_YES, Some(&old.name)) {
                Ok(t) if t.contains("deleted") => {}
                r => fail!(log, "op=snapshot_delete name={} result={:?}", old.name, r),
            }
            self.deleted += 1;
        }
        // The list holds exactly the snapshots the model has.
        log.op(format_args!("op=snapshot_list"));
        let t = match sysctl_text(self.sys, SYSCTL_SNAPSHOT_LIST, disk(), None) {
            Ok(t) => t,
            Err(r) => fail!(log, "op=snapshot_list error={}", error_name(r)),
        };
        // The list is in slot order (a deleted snapshot's slot is reused) – compared as sets.
        let mut listed: Vec<&str> = t.lines().filter_map(|l| l.split_whitespace().next()).filter(|w| w.starts_with("soak")).collect();
        let mut want: Vec<&str> = self.snaps.iter().map(|s| s.name.as_str()).collect();
        listed.sort();
        want.sort();
        if listed != want {
            fail!(log, "op=snapshot_list expected={:?} listed={:?}", want, listed);
        }
    }
}

impl Work for Files {
    fn step(&mut self, log: &mut Log) {
        if uptime_ms() - self.last_snap >= self.snap_every {
            self.last_snap = uptime_ms();
            self.snapshot(log);
            return;
        }
        self.ops += 1;
        let over = self.used() > self.budget;
        // Over the budget: only delete (70) or truncate (55).
        let kind = if over { [70u64, 55, 70][self.rng.below(3) as usize] } else { self.rng.below(100) };
        match kind {
            // create
            0..=19 => {
                let Some(s) = self.pick(false) else { return };
                let p = file_path(root(), s);
                let e = Ent { live: true, size: self.new_size() as u32, seed: self.rng.next() };
                log.op(format_args!("op=create path={} size={} seed={:x}", p, e.size, e.seed));
                let fd = Self::open_or_fail(log, &p, O_WRITE | O_CREATE | O_TRUNC);
                self.write_range(log, fd, &p, e.seed, 0, e.size as u64);
                close(fd);
                self.m.e[s] = e;
                self.verify(log, &p, e);
            }
            // append
            20..=34 => {
                let Some(s) = self.pick(true) else { return };
                let mut e = self.m.e[s];
                let p = file_path(root(), s);
                let add = self.rng.range(1, 32 * 1024).min(MAX_FILE - (e.size as u64).min(MAX_FILE));
                if add == 0 {
                    return;
                }
                log.op(format_args!("op=append path={} size={} add={}", p, e.size, add));
                let fd = Self::open_or_fail(log, &p, O_WRITE | O_APPEND);
                self.write_range(log, fd, &p, e.seed, e.size as u64, e.size as u64 + add);
                close(fd);
                e.size += add as u32;
                self.m.e[s] = e;
                self.verify(log, &p, e);
            }
            // overwrite: a new seed for the whole file, the second half written first
            35..=44 => {
                let Some(s) = self.pick(true) else { return };
                let mut e = self.m.e[s];
                let p = file_path(root(), s);
                e.seed = self.rng.next();
                log.op(format_args!("op=overwrite path={} size={} seed={:x}", p, e.size, e.seed));
                let fd = Self::open_or_fail(log, &p, O_WRITE);
                let half = e.size as u64 / 2;
                Self::seek_or_fail(log, fd, &p, half);
                self.write_range(log, fd, &p, e.seed, half, e.size as u64);
                Self::seek_or_fail(log, fd, &p, 0);
                self.write_range(log, fd, &p, e.seed, 0, half);
                close(fd);
                self.m.e[s] = e;
                self.verify(log, &p, e);
            }
            // patch: the same bytes written again in the middle (a real copy-on-write)
            45..=54 => {
                let Some(s) = self.pick(true) else { return };
                let e = self.m.e[s];
                if e.size == 0 {
                    return;
                }
                let p = file_path(root(), s);
                let off = self.rng.below(e.size as u64);
                let len = self.rng.range(1, 64 * 1024).min(e.size as u64 - off);
                log.op(format_args!("op=patch path={} off={} len={}", p, off, len));
                let fd = Self::open_or_fail(log, &p, O_WRITE);
                Self::seek_or_fail(log, fd, &p, off);
                self.write_range(log, fd, &p, e.seed, off, off + len);
                close(fd);
                self.verify(log, &p, e);
            }
            // truncate: O_TRUNC, then the shorter prefix again
            55..=62 => {
                let Some(s) = self.pick(true) else { return };
                let mut e = self.m.e[s];
                let p = file_path(root(), s);
                let new = self.rng.below(e.size as u64 + 1);
                log.op(format_args!("op=truncate path={} size={} new={}", p, e.size, new));
                let fd = Self::open_or_fail(log, &p, O_WRITE | O_TRUNC);
                self.write_range(log, fd, &p, e.seed, 0, new);
                close(fd);
                e.size = new as u32;
                self.m.e[s] = e;
                self.verify(log, &p, e);
            }
            // move: copy to a free slot (another directory), then delete
            63..=69 => {
                let (Some(from), Some(to)) = (self.pick(true), self.pick(false)) else { return };
                let e = self.m.e[from];
                let (pf, pt) = (file_path(root(), from), file_path(root(), to));
                log.op(format_args!("op=move from={} to={} size={}", pf, pt, e.size));
                let src = Self::open_or_fail(log, &pf, O_READ);
                let dst = Self::open_or_fail(log, &pt, O_WRITE | O_CREATE | O_TRUNC);
                loop {
                    let n = read(src, &mut self.buf);
                    if n < 0 {
                        fail!(log, "op=read path={} error={}", pf, error_name(n));
                    }
                    if n == 0 {
                        break;
                    }
                    let w = write(dst, &self.buf[..n as usize]);
                    if w != n {
                        fail!(log, "op=write path={} result={}", pt, w);
                    }
                    self.written += n as u64;
                }
                close(src);
                close(dst);
                let r = unlink(&pf);
                if r != 0 {
                    fail!(log, "op=unlink path={} error={}", pf, error_name(r));
                }
                self.m.e[to] = e;
                self.m.e[from] = Ent::default();
                self.verify(log, &pt, e);
                Self::absent(log, &pf);
            }
            // delete
            70..=79 => {
                let Some(s) = self.pick(true) else { return };
                let p = file_path(root(), s);
                log.op(format_args!("op=delete path={}", p));
                let r = unlink(&p);
                if r != 0 {
                    fail!(log, "op=unlink path={} error={}", p, error_name(r));
                }
                self.m.e[s] = Ent::default();
                Self::absent(log, &p);
            }
            // read
            80..=94 => {
                let Some(s) = self.pick(true) else { return };
                let p = file_path(root(), s);
                let e = self.m.e[s];
                log.op(format_args!("op=read path={} size={}", p, e.size));
                self.verify(log, &p, e);
            }
            // an empty directory: create or delete
            _ => {
                let k = self.rng.below(NDIRS as u64) as usize;
                let p = dir_path(root(), k);
                let bit = 1u32 << k;
                if self.m.dirs & bit == 0 {
                    log.op(format_args!("op=mkdir path={}", p));
                    let r = mkdir(&p);
                    if r != 0 {
                        fail!(log, "op=mkdir path={} error={}", p, error_name(r));
                    }
                    match stat(&p) {
                        Ok(st) if st.is_dir => {}
                        r => fail!(log, "op=stat path={} expected=directory ok={}", p, r.is_ok()),
                    }
                } else {
                    log.op(format_args!("op=rmdir path={}", p));
                    let r = unlink(&p);
                    if r != 0 {
                        fail!(log, "op=rmdir path={} error={}", p, error_name(r));
                    }
                    Self::absent(log, &p);
                }
                self.m.dirs ^= bit;
            }
        }
    }

    fn stats(&self) -> String {
        format!(
            "ops_files={} written_mib={} files={} used_kib={} snapshots={} snapshots_deleted={}",
            self.ops,
            self.written >> 20,
            self.m.e.iter().filter(|e| e.live).count(),
            self.used() / 1024,
            self.made,
            self.deleted
        )
    }

    /// Paused: every live file, then every snapshot through a read-only view (the
    /// controller's `desofs unmount` takes the views away again).
    fn audit(&mut self, log: &mut Log) -> String {
        log.op(format_args!("op=audit files"));
        let m = self.m.clone();
        self.verify_all(log, root(), &m);
        let names: Vec<String> = self.snaps.iter().map(|s| s.name.clone()).collect();
        for (i, name) in names.iter().enumerate() {
            log.op(format_args!("op=snapshot_mount name={}", name));
            match sysctl_text(self.sys, SYSCTL_SNAPSHOT_MOUNT, disk(), Some(name)) {
                Ok(t) if t.contains("mounted at") => {}
                r => fail!(log, "op=snapshot_mount name={} result={:?}", name, r),
            }
            let root = format!("/snap/{}", name);
            let sm = self.snaps[i].model.clone();
            log.op(format_args!("op=audit snapshot={}", name));
            self.verify_all(log, &root, &sm);
            println!("[SOAK] files: snapshot {} matches its model ({} files)", name, sm.e.iter().filter(|e| e.live).count());
            // A view is read-only.
            let p = format!("{}/soak/x", root);
            let fd = open(&p, O_WRITE | O_CREATE);
            if fd >= 0 {
                close(fd as u64);
                fail!(log, "op=create path={} expected=refused (read-only view)", p);
            }
        }
        format!("files_ok={} snapshots_ok={}", self.m.e.iter().filter(|e| e.live).count(), names.len())
    }
}

// ------------------------------------------------------------
// svcnet: services killed and brought back, network, echo, USB stick
// ------------------------------------------------------------

const HOST: &str = "10.0.2.2";
const HTTP_PORT: &str = "58080";
/// tests/udp-stub.py (echo).
const UDP_PORT: u16 = 58090;
const BIG: usize = 1024 * 1024;
const USB_FILE: &str = "DATA.BIN";
const USB_SIZE: u64 = 4 * 1024 * 1024;
const RECOVER_MS: u64 = 30_000;

/// The file the USB checks read: the test stick's pattern file (QEMU), or a file of the
/// boot stick (real hardware) compared with its first reading (SHA-256 of the first 256 KiB
/// and of the whole file).
enum UsbFile {
    Pattern,
    Known { rel: &'static str, size: u64, head: [u8; 32], whole: [u8; 32] },
}

struct SvcNet {
    rng: Rng,
    big_sha: [u8; 32],
    /// The services killed: network cards, USB controllers, echo – whatever runs here.
    targets: Vec<String>,
    /// The first network card (pings and downloads go through it), its gateway, and
    /// whether the host's test HTTP server is there (QEMU: gateway 10.0.2.2).
    net: Option<String>,
    gw: String,
    downloads: bool,
    usb: Option<UsbFile>,
    next_kill: u64,
    gap: (u64, u64),
    kills: u64,
    rec: Vec<u64>,
    /// Per service: (name, recovery times of all kills, of this checkpoint period, the
    /// average of the first period that had a kill of it).  Each service is compared only
    /// with itself – a network card waiting for a real DHCP server (16–32 s) must not make
    /// the USB controllers (0.2 s) look slower.
    per: Vec<(String, Vec<u64>, Vec<u64>, Option<u64>)>,
    net_bytes: u64,
    pings: u64,
    echoes: u64,
    udp_echoes: u64,
    usb_reads: u64,
    ops: u64,
    buf: Vec<u8>,
}

/// The /big page of tests/http-stub.py: byte i = (i * 7 + i / 251) mod 256.
fn big_byte(i: usize) -> u8 {
    ((i * 7 + i / 251) & 0xFF) as u8
}

impl SvcNet {
    fn new(seed: u64, short: bool, log: &mut Log) -> SvcNet {
        let mut h = Sha256::new();
        let mut chunk = [0u8; 4096];
        for base in (0..BIG).step_by(4096) {
            for (k, b) in chunk.iter_mut().enumerate() {
                *b = big_byte(base + k);
            }
            h.update(&chunk);
        }
        let gap = if short { (10_000, 20_000) } else { (30_000, 90_000) };
        let mut s = SvcNet {
            rng: Rng(mix(seed ^ 0x7376_636e)),
            big_sha: h.finish().unwrap_or([0; 32]),
            targets: Vec::new(),
            net: None,
            gw: String::new(),
            downloads: false,
            usb: None,
            next_kill: 0,
            gap,
            kills: 0,
            rec: Vec::new(),
            per: Vec::new(),
            net_bytes: 0,
            pings: 0,
            echoes: 0,
            udp_echoes: 0,
            usb_reads: 0,
            ops: 0,
            buf: vec![0; MSG_MAX],
        };
        s.next_kill = uptime_ms() + s.rng.range(gap.0, gap.1);
        // What runs here: init's list (edu is a QEMU test device – not killed).
        let mut list = [0u8; 2048];
        let n = svc_list(&mut list).unwrap_or(0);
        for line in core::str::from_utf8(&list[..n]).unwrap_or("").lines() {
            let mut w = line.split_whitespace();
            if let (Some(name), Some("running")) = (w.next(), w.next()) {
                if name.starts_with("net") || name.starts_with("usb") || name == "echo" {
                    s.targets.push(String::from(name));
                }
            }
        }
        s.net = s.targets.iter().find(|t| t.starts_with("net")).cloned();
        // Everything must work before the first kill (netd may still be getting its address).
        log.op(format_args!("op=wait_ready services={:?}", s.targets));
        let t0 = uptime_ms();
        loop {
            if s.net.is_some() && (s.gw.is_empty() || s.gw == "0.0.0.0") {
                s.gw = s.gateway();
                // QEMU's test server; on real hardware only if it answers (it does not
                // when a DESOOS_AUTOSOAK build runs in plain QEMU without tests/soak.sh).
                s.downloads = s.gw == HOST && (!hw() || s.download().is_ok());
            }
            if s.usb.is_none() {
                s.usb = s.find_usb_file();
            }
            let targets = s.targets.clone();
            let mut bad = None;
            for t in &targets {
                if let Err(e) = s.check(t, false) {
                    bad = Some((t.clone(), e));
                    break;
                }
            }
            // tests/soak.sh: the test stick and the test server must be there.
            if bad.is_none() && !hw() && (!matches!(s.usb, Some(UsbFile::Pattern)) || (s.net.is_some() && !s.downloads)) {
                bad = Some((String::from("setup"), String::from("no test stick (DATA.BIN) or no test server at 10.0.2.2")));
            }
            // A stick needs a moment after usbd starts: looked for during the first 20 s.
            if bad.is_none() && s.usb.is_none() && uptime_ms() - t0 < 20_000 {
                bad = Some((String::from("usb"), String::from("no USB stick yet")));
            }
            let Some((t, e)) = bad else { break };
            if uptime_ms() - t0 > 60_000 {
                fail!(log, "op=wait_ready service={} error={:?}", t, e);
            }
            sleep_ms(500);
        }
        println!(
            "[SOAK] svcnet: killing {:?}; network: {}; USB check: {}",
            s.targets,
            match (&s.net, s.downloads) {
                (None, _) => String::from("none"),
                (Some(n), true) => format!("{} - ping {} + 1 MiB downloads from the test server", n, s.gw),
                (Some(n), false) => format!("{} - ping of the gateway {} (no test server here)", n, s.gw),
            },
            match &s.usb {
                None => String::from("none (no stick found)"),
                Some(UsbFile::Pattern) => format!("/usbN/{} pattern", USB_FILE),
                Some(UsbFile::Known { rel, size, .. }) => format!("/usbN/{} ({} B, SHA-256 of its first reading)", rel, size),
            }
        );
        s
    }

    /// The gateway netd got ("gw=" in its status line); "0.0.0.0" while it has none.
    fn gateway(&mut self) -> String {
        let Some(net) = self.net.clone() else { return String::new() };
        let Ok(c) = svc_connect(&net) else { return String::new() };
        let mut out = String::new();
        if chan_send(c, b"status", 0) == 0 {
            let mut info = RecvInfo::default();
            let r = chan_recv(c, &mut self.buf, 0, &mut info);
            if r > 0 {
                out = String::from_utf8_lossy(&self.buf[..r as usize]).into_owned();
            }
        }
        close(c);
        String::from(out.split_whitespace().find_map(|w| w.strip_prefix("gw=")).unwrap_or(""))
    }

    /// Which USB file to check: the test stick's pattern file, else a boot stick's loader.
    fn find_usb_file(&mut self) -> Option<UsbFile> {
        if (0..8).any(|n| stat(&format!("/usb{}/{}", n, USB_FILE)).map(|s| s.size) == Ok(USB_SIZE)) {
            return Some(UsbFile::Pattern);
        }
        let rel = "EFI/BOOT/BOOTX64.EFI";
        let path = (0..8).map(|n| format!("/usb{}/{}", n, rel)).find(|p| stat(p).is_ok())?;
        let size = stat(&path).ok()?.size;
        let head = self.file_sha(&path, 256 * 1024).ok()?;
        let whole = self.file_sha(&path, size).ok()?;
        Some(UsbFile::Known { rel, size, head, whole })
    }

    /// SHA-256 of the first `len` bytes of a file.
    fn file_sha(&mut self, path: &str, len: u64) -> Result<[u8; 32], String> {
        let fd = open(path, O_READ);
        if fd < 0 {
            return Err(format!("open {}: {}", path, error_name(fd)));
        }
        let mut h = Sha256::new();
        let mut off = 0u64;
        let mut chunk = vec![0u8; 64 * 1024];
        while off < len {
            let want = (len - off).min(chunk.len() as u64) as usize;
            let n = read(fd as u64, &mut chunk[..want]);
            if n < 0 {
                close(fd as u64);
                return Err(format!("read {} at {}: {}", path, off, error_name(n)));
            }
            if n == 0 {
                break;
            }
            h.update(&chunk[..n as usize]);
            off += n as u64;
        }
        close(fd as u64);
        h.finish().map_err(|_| String::from("sha"))
    }

    /// One download of /big through netd: size and SHA-256.
    fn download(&mut self) -> Result<(), String> {
        let net = self.net.clone().unwrap_or_default();
        let c = svc_connect(&net).map_err(|e| format!("connect {}: {}", net, error_name(e)))?;
        let r = self.download_on(c);
        close(c);
        r
    }

    fn download_on(&mut self, c: u64) -> Result<(), String> {
        let mut info = RecvInfo::default();
        let req = format!("tcp {} {}", HOST, HTTP_PORT);
        if chan_send(c, req.as_bytes(), 0) != 0 {
            return Err(String::from("netd not running"));
        }
        let r = chan_recv(c, &mut self.buf, 0, &mut info);
        let reply = if r > 0 { String::from_utf8_lossy(&self.buf[..r as usize]).into_owned() } else { String::new() };
        if !reply.starts_with("connected ") {
            return Err(format!("tcp: {:?}", reply.trim()));
        }
        let get = format!("GET /big HTTP/1.0\r\nHost: {}:{}\r\nConnection: close\r\n\r\n", HOST, HTTP_PORT);
        if chan_send(c, get.as_bytes(), 0) != 0 {
            return Err(String::from("closed before the request"));
        }
        let mut head: Vec<u8> = Vec::new();
        let mut in_body = false;
        let mut body = 0usize;
        let mut h = Sha256::new();
        loop {
            let r = chan_recv(c, &mut self.buf, 0, &mut info);
            if r < 0 {
                break;
            }
            let mut data = &self.buf[..r as usize];
            if !in_body {
                head.extend_from_slice(data);
                let Some(e) = head.windows(4).position(|w| w == b"\r\n\r\n") else {
                    if head.len() > 8192 {
                        return Err(String::from("headers too long"));
                    }
                    continue;
                };
                let first = String::from_utf8_lossy(&head[..e]).into_owned();
                if !first.starts_with("HTTP/1.0 200") && !first.starts_with("HTTP/1.1 200") {
                    return Err(format!("status {:?}", first.lines().next().unwrap_or("")));
                }
                let rest = head[e + 4..].to_vec();
                h.update(&rest);
                body += rest.len();
                in_body = true;
                data = &[];
            }
            h.update(data);
            body += data.len();
        }
        let got = h.finish().unwrap_or([0; 32]);
        if body != BIG || got != self.big_sha {
            return Err(format!("size={} expected_size={} expected_sha={} actual_sha={}", body, BIG, sha_text(&self.big_sha), sha_text(&got)));
        }
        self.net_bytes += body as u64;
        Ok(())
    }

    fn ping(&mut self) -> Result<(), String> {
        let net = self.net.clone().unwrap_or_default();
        let c = svc_connect(&net).map_err(|e| format!("connect {}: {}", net, error_name(e)))?;
        let req = format!("ping {} 1", self.gw);
        if chan_send(c, req.as_bytes(), 0) != 0 {
            close(c);
            return Err(String::from("netd not running"));
        }
        let mut answers = 0;
        let mut info = RecvInfo::default();
        loop {
            let r = chan_recv(c, &mut self.buf, 0, &mut info);
            if r < 0 {
                close(c);
                return Err(format!("ping: {}", error_name(r)));
            }
            let t = String::from_utf8_lossy(&self.buf[..r as usize]).into_owned();
            let end = t.lines().any(|l| l == "ping-end");
            answers += t.lines().filter(|l| l.contains(" bytes from ")).count();
            if end {
                break;
            }
        }
        close(c);
        if answers == 0 {
            return Err(String::from("no ping answer"));
        }
        self.pings += 1;
        Ok(())
    }

    /// A UDP datagram to tests/udp-stub.py and its echo (3 tries – UDP may lose one).
    fn udp_echo(&mut self) -> Result<(), String> {
        let card = self.net.clone().unwrap_or_default();
        let mut reply = [0u8; 256];
        let c = udp_open_via(SVC, &card, HOST, UDP_PORT, &mut reply).map_err(|n| format!("udp open: {}", core::str::from_utf8(&reply[..n]).unwrap_or("?").trim()))?;
        let n = self.rng.range(1, UDP_MAX as u64) as usize;
        let seed = self.rng.next();
        let mut msg = vec![0u8; n];
        fill(seed, 0, &mut msg);
        let mut info = RecvInfo::default();
        let mut ok = false;
        'tries: for _ in 0..3 {
            if udp_send(c, &msg) != 0 {
                break;
            }
            let t = uptime_ms();
            while uptime_ms() - t < 1000 {
                if !matches!(wait_many(&[(c, W_READABLE)], 1000 - (uptime_ms() - t)), Ok(m) if m != 0) {
                    break;
                }
                let got = chan_recv(c, &mut self.buf, CHAN_NONBLOCK, &mut info);
                if got == n as i64 && self.buf[..n] == msg[..] {
                    ok = true;
                    break 'tries;
                }
            }
        }
        close(c);
        if !ok {
            return Err(format!("udp echo: no echo of {} bytes in 3 tries", n));
        }
        self.udp_echoes += 1;
        Ok(())
    }

    fn echo(&mut self) -> Result<(), String> {
        let c = svc_connect("echo").map_err(|e| format!("connect echo: {}", error_name(e)))?;
        let n = self.rng.range(1, 512) as usize;
        let seed = self.rng.next();
        let mut msg = vec![0u8; n];
        fill(seed, 0, &mut msg);
        let r = chan_send(c, &msg, 0);
        let mut info = RecvInfo::default();
        let got = if r == 0 { chan_recv(c, &mut self.buf, 0, &mut info) } else { r };
        close(c);
        if got != n as i64 || self.buf[..n] != msg[..] {
            return Err(format!("echo: sent {} bytes, answer {}", n, got));
        }
        self.echoes += 1;
        Ok(())
    }

    /// The USB file (on /usbN – the number can change after a USB controller restarts):
    /// DATA.BIN of the test stick against its pattern (32-bit word k = k * 2654435761), or
    /// the boot stick's file against the SHA-256 of its first reading.  `full`: the whole file.
    fn usb_read(&mut self, full: bool) -> Result<(), String> {
        let (rel, size) = match &self.usb {
            None => return Ok(()),
            Some(UsbFile::Pattern) => (USB_FILE, USB_SIZE),
            Some(UsbFile::Known { rel, size, .. }) => (*rel, *size),
        };
        let path = (0..8).map(|n| format!("/usb{}/{}", n, rel)).find(|p| stat(p).map(|s| s.size) == Ok(size)).ok_or_else(|| format!("no USB stick with {} mounted", rel))?;
        let len = if full { size } else { size.min(256 * 1024) };
        if let Some(UsbFile::Known { head, whole, .. }) = &self.usb {
            let want = if full { *whole } else { *head };
            let got = self.file_sha(&path, len)?;
            if got != want {
                return Err(format!("{}: SHA-256 of {} bytes {} - first reading {}", path, len, sha_text(&got), sha_text(&want)));
            }
            self.usb_reads += 1;
            return Ok(());
        }
        let fd = open(&path, O_READ);
        if fd < 0 {
            return Err(format!("open {}: {}", path, error_name(fd)));
        }
        let mut off = 0u64;
        let mut chunk = vec![0u8; 64 * 1024];
        while off < len {
            let want = (len - off).min(chunk.len() as u64) as usize;
            let n = read(fd as u64, &mut chunk[..want]);
            if n <= 0 {
                close(fd as u64);
                return Err(format!("read {} at {}: {}", path, off, if n < 0 { error_name(n) } else { "end of file" }));
            }
            for (k, &b) in chunk[..n as usize].iter().enumerate() {
                let i = off + k as u64;
                let w = ((i / 4) as u32).wrapping_mul(2_654_435_761);
                if b != (w >> ((i % 4) * 8)) as u8 {
                    close(fd as u64);
                    return Err(format!("{}: wrong byte at {}", path, i));
                }
            }
            off += n as u64;
        }
        close(fd as u64);
        self.usb_reads += 1;
        Ok(())
    }

    /// Whether service `name` really works.  `full`: the long version (audit).
    fn check(&mut self, name: &str, full: bool) -> Result<(), String> {
        if name.starts_with("net") {
            if self.gw.is_empty() || self.gw == "0.0.0.0" {
                return Err(String::from("no address / gateway yet"));
            }
            self.ping()?;
            if self.downloads {
                self.download()?;
            }
            Ok(())
        } else if name.starts_with("usb") {
            self.usb_read(full)
        } else {
            self.echo()
        }
    }

    fn kill_one(&mut self, log: &mut Log) {
        if self.targets.is_empty() {
            self.next_kill = u64::MAX;
            return;
        }
        let name = self.targets[self.rng.below(self.targets.len() as u64) as usize].clone();
        let name = name.as_str();
        let Some((state, pid0, r0)) = svc_status(name) else { fail!(log, "op=kill service={} not in the service list", name) };
        if state != "running" {
            fail!(log, "op=kill service={} state={} before the kill (expected running)", name, state);
        }
        log.op(format_args!("op=kill service={} pid={} restarts={}", name, pid0, r0));
        let mut buf = [0u8; 256];
        match svc_kill(name, &mut buf) {
            Ok(t) if t.starts_with("killed ") => {}
            Ok(t) => fail!(log, "op=kill service={} answer={:?}", name, t),
            Err(e) => fail!(log, "op=kill service={} error={}", name, error_name(e)),
        }
        let t0 = uptime_ms();
        // Back = (1) a new state in init's list, (2) a new pid, (3) it works.
        let mut last = String::from("no answer yet");
        loop {
            if let Some((st, pid, r)) = svc_status(name) {
                if st == "running" && pid != pid0 && r > r0 {
                    match self.check(name, false) {
                        Ok(()) => break,
                        Err(e) => last = e,
                    }
                } else {
                    last = format!("state {} pid {} restarts {}", st, pid, r);
                }
            }
            // Real hardware: a real DHCP server can take ~16 s – 60 s allowed there.
            let limit = if hw() { 2 * RECOVER_MS } else { RECOVER_MS };
            if uptime_ms() - t0 > limit {
                fail!(log, "op=recover service={} not working {} ms after the kill: {}", name, limit, last);
            }
            sleep_ms(100);
        }
        let ms = uptime_ms() - t0;
        log.op(format_args!("op=recovered service={} ms={}", name, ms));
        let c = counters();
        println!("[SOAK] svcnet: {} killed and working again in {} ms (kernel heap {} KiB + console {} KiB, free frames {})", name, ms, counter(&c, "heap_used").saturating_sub(counter(&c, "heap_console")) / 1024, counter(&c, "heap_console") / 1024, counter(&c, "frames_free"));
        self.kills += 1;
        self.rec.push(ms);
        match self.per.iter_mut().find(|p| p.0 == name) {
            Some(p) => {
                p.1.push(ms);
                p.2.push(ms);
            }
            None => self.per.push((String::from(name), vec![ms], vec![ms], None)),
        }
        self.next_kill = uptime_ms() + self.rng.range(self.gap.0, self.gap.1);
    }
}

impl Work for SvcNet {
    fn step(&mut self, log: &mut Log) {
        if uptime_ms() >= self.next_kill {
            self.kill_one(log);
            return;
        }
        self.ops += 1;
        let (what, r) = match self.rng.below(100) {
            0..=29 if self.downloads => ("download", self.download()),
            0..=39 if self.net.is_some() => ("ping", self.ping()),
            40..=49 if self.downloads => ("udp_echo", self.udp_echo()),
            80..=99 if self.usb.is_some() => ("usb_read", self.usb_read(false)),
            _ => ("echo", self.echo()),
        };
        log.op(format_args!("op={}", what));
        if let Err(e) = r {
            fail!(log, "op={} {}", what, e);
        }
        sleep_ms(20);
    }

    fn stats(&self) -> String {
        let (min, max) = (self.rec.iter().min().copied().unwrap_or(0), self.rec.iter().max().copied().unwrap_or(0));
        let avg = if self.rec.is_empty() { 0 } else { self.rec.iter().sum::<u64>() / self.rec.len() as u64 };
        format!(
            "kills={} recover_ms={}/{}/{} net_mib={} pings={} echoes={} udp_echoes={} usb_reads={}",
            self.kills,
            min,
            avg,
            max,
            self.net_bytes >> 20,
            self.pings,
            self.echoes,
            self.udp_echoes,
            self.usb_reads
        )
    }

    /// Paused: every service answers (long USB read), and the average recovery time of
    /// this period is not far above the first period's – per service.
    fn audit(&mut self, log: &mut Log) -> String {
        for n in self.targets.clone() {
            log.op(format_args!("op=audit service={}", n));
            if let Err(e) = self.check(&n, true) {
                fail!(log, "op=audit service={} {}", n, e);
            }
        }
        let avg = |v: &[u64]| if v.is_empty() { 0 } else { v.iter().sum::<u64>() / v.len() as u64 };
        let mut text = Vec::new();
        for (name, all, cp, first) in self.per.iter_mut() {
            if !cp.is_empty() {
                let now = avg(cp);
                match *first {
                    None => *first = Some(now),
                    Some(f) if now > 3 * f + 2000 => {
                        fail!(log, "op=audit {} recovery average {} ms this period, {} ms in its first one - it keeps growing", name, now, f);
                    }
                    Some(_) => {}
                }
                cp.clear();
            }
            text.push(format!("{}:{}/{}/{}", name, all.iter().min().copied().unwrap_or(0), avg(all), all.iter().max().copied().unwrap_or(0)));
        }
        println!("[SOAK] svcnet: recovery per service, min/avg/max ms: {}", if text.is_empty() { String::from("no kills yet") } else { text.join(", ") });
        format!("services_ok={}", self.targets.len())
    }
}

// ------------------------------------------------------------
// procs: processes and IPC
// ------------------------------------------------------------

struct Procs {
    rng: Rng,
    spawned: u64,
    ipc_bytes: u64,
    maps: u64,
    ops: u64,
}

fn spawn_child(log: &Log, args: &[&str], map: &[(u64, u64)]) -> u64 {
    let pid = spawn_ex("/bin/soak", args, map, 0);
    if pid <= 0 {
        fail!(log, "op=spawn args={:?} error={}", args, error_name(pid));
    }
    pid as u64
}

fn wait_child(log: &Log, pid: u64) -> u64 {
    match wait(pid, 0) {
        Ok((p, status)) if p == pid => status,
        r => fail!(log, "op=wait pid={} result={:?}", pid, r),
    }
}

impl Procs {
    fn new(seed: u64) -> Procs {
        Procs { rng: Rng(mix(seed ^ 0x7072_6f63)), spawned: 0, ipc_bytes: 0, maps: 0, ops: 0 }
    }

    fn one(&mut self, log: &mut Log, kind: u64) {
        match kind {
            // exit code
            0 => {
                let code = self.rng.range(0, 120);
                let c = format!("{}", code);
                log.op(format_args!("op=spawn_exit code={}", code));
                let pid = spawn_child(log, &["soak", "child", "exit", &c], &[(1, 1), (2, 2)]);
                let st = wait_child(log, pid);
                if st != code {
                    fail!(log, "op=wait pid={} expected_status={} status={:#x}", pid, code, st);
                }
            }
            // pipes there and back
            1 => {
                let n = self.rng.range(1, 32 * 1024) as usize;
                let seed = self.rng.next();
                log.op(format_args!("op=pipe len={}", n));
                let (Ok((r1, w1)), Ok((r2, w2))) = (pipe(), pipe()) else { fail!(log, "op=pipe no pipe") };
                let pid = spawn_child(log, &["soak", "child", "echo"], &[(r1, 0), (w2, 1), (2, 2)]);
                close(r1);
                close(w2);
                let mut data = vec![0u8; n];
                fill(seed, 0, &mut data);
                let w = write(w1, &data);
                close(w1);
                let back = read_all(r2);
                close(r2);
                let st = wait_child(log, pid);
                if w != n as i64 || back != data || st != 0 {
                    fail!(log, "op=pipe len={} written={} back={} status={:#x}", n, w, back.len(), st);
                }
                self.ipc_bytes += 2 * n as u64;
            }
            // channel: messages there and back reversed
            2 => {
                let count = self.rng.range(1, 50);
                log.op(format_args!("op=channel messages={}", count));
                let Ok((mine, theirs)) = channel_create() else { fail!(log, "op=channel_create failed") };
                let pid = spawn_child(log, &["soak", "child", "chan"], &[(theirs, 3), (2, 2)]);
                close(theirs);
                let mut back = vec![0u8; MSG_MAX];
                let mut info = RecvInfo::default();
                for k in 0..count {
                    let n = self.rng.range(1, MSG_MAX as u64) as usize;
                    let mut msg = vec![0u8; n];
                    fill(self.rng.next(), 0, &mut msg);
                    let r = chan_send(mine, &msg, 0);
                    let got = if r == 0 { chan_recv(mine, &mut back, 0, &mut info) } else { r };
                    msg.reverse();
                    if got != n as i64 || back[..n] != msg[..] {
                        fail!(log, "op=channel message={} len={} answer={}", k, n, got);
                    }
                    self.ipc_bytes += 2 * n as u64;
                }
                chan_send(mine, b"bye", 0);
                let st = wait_child(log, pid);
                close(mine);
                if st != 0 {
                    fail!(log, "op=channel child status={:#x}", st);
                }
            }
            // shared memory: the child sums what the parent wrote
            3 => {
                let size = self.rng.range(1, 64) * 4096;
                let seed = self.rng.next();
                log.op(format_args!("op=shm size={}", size));
                let h = shm_create(size);
                if h < 0 {
                    fail!(log, "op=shm_create size={} error={}", size, error_name(h));
                }
                let h = h as u64;
                let addr = match shm_map(h, PROT_READ | PROT_WRITE) {
                    Ok(a) => a,
                    Err(e) => fail!(log, "op=shm_map error={}", error_name(e)),
                };
                let mem = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, size as usize) };
                fill(seed, 0, mem);
                let want = mem.iter().fold(0u64, |a, &b| a.wrapping_mul(31).wrapping_add(b as u64));
                let Ok((mine, theirs)) = channel_create() else { fail!(log, "op=channel_create failed") };
                let pid = spawn_child(log, &["soak", "child", "shm"], &[(h, 3), (theirs, 4), (2, 2)]);
                close(theirs);
                let mut back = [0u8; 8];
                let mut info = RecvInfo::default();
                let r = chan_recv(mine, &mut back, 0, &mut info);
                let st = wait_child(log, pid);
                close(mine);
                munmap(addr, size);
                close(h);
                if r != 8 || u64::from_le_bytes(back) != want || st != 0 {
                    fail!(log, "op=shm size={} answer={} status={:#x}", size, r, st);
                }
                self.ipc_bytes += size;
            }
            // mmap / munmap
            4 => {
                let pages = self.rng.range(1, 256);
                log.op(format_args!("op=mmap pages={}", pages));
                let len = pages * 4096;
                let addr = match mmap(len, PROT_READ | PROT_WRITE) {
                    Ok(a) => a,
                    Err(e) => fail!(log, "op=mmap len={} error={}", len, error_name(e)),
                };
                let mem = unsafe { core::slice::from_raw_parts_mut(addr as *mut u64, (len / 8) as usize) };
                for p in 0..pages as usize {
                    mem[p * 512] = addr ^ p as u64;
                }
                for p in 0..pages as usize {
                    if mem[p * 512] != addr ^ p as u64 {
                        fail!(log, "op=mmap page {} lost its value", p);
                    }
                }
                if munmap(addr, len) != 0 {
                    fail!(log, "op=munmap addr={:#x} len={}", addr, len);
                }
                self.maps += 1;
            }
            // kill a sleeping child
            _ => {
                log.op(format_args!("op=kill_child"));
                let pid = spawn_child(log, &["soak", "child", "sleep"], &[(2, 2)]);
                sleep_ms(self.rng.range(0, 20));
                if kill(pid) != 0 {
                    fail!(log, "op=kill pid={}", pid);
                }
                let st = wait_child(log, pid);
                if st & STATUS_SIGNALED == 0 {
                    fail!(log, "op=kill pid={} status={:#x} (expected killed)", pid, st);
                }
            }
        }
    }
}

impl Work for Procs {
    fn step(&mut self, log: &mut Log) {
        self.ops += 1;
        let kind = self.rng.below(6);
        if kind != 4 {
            self.spawned += 1;
        }
        self.one(log, kind);
    }

    fn stats(&self) -> String {
        format!("procs={} ipc_mib={} maps={}", self.spawned, self.ipc_bytes >> 20, self.maps)
    }

    fn audit(&mut self, log: &mut Log) -> String {
        for k in 0..6 {
            self.one(log, k);
        }
        // Nothing of ours may be left: no child to wait for.
        match wait(WAIT_ANY, WNOHANG) {
            Err(ERROR_NO_CHILD) => {}
            r => fail!(log, "op=audit a child is still there: {:?}", r),
        }
        String::from("procs_ok=1")
    }
}

/// Child processes of the procs worker.
fn child(args: Args) -> i32 {
    match args.get(2) {
        Some("exit") => args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1),
        Some("echo") => {
            let mut buf = [0u8; 4096];
            loop {
                let n = read(0, &mut buf);
                if n <= 0 {
                    return if n == 0 { 0 } else { 1 };
                }
                if write(1, &buf[..n as usize]) != n {
                    return 1;
                }
            }
        }
        Some("chan") => {
            let mut buf = vec![0u8; MSG_MAX];
            let mut info = RecvInfo::default();
            loop {
                let n = chan_recv(3, &mut buf, 0, &mut info);
                if n < 0 {
                    return 1;
                }
                if &buf[..n as usize] == b"bye" {
                    return 0;
                }
                buf[..n as usize].reverse();
                if chan_send(3, &buf[..n as usize], 0) != 0 {
                    return 1;
                }
            }
        }
        Some("shm") => {
            let size = shm_size(3);
            let Ok(addr) = shm_map(3, PROT_READ) else { return 1 };
            if size <= 0 {
                return 1;
            }
            let mem = unsafe { core::slice::from_raw_parts(addr as *const u8, size as usize) };
            let sum = mem.iter().fold(0u64, |a, &b| a.wrapping_mul(31).wrapping_add(b as u64));
            if chan_send(4, &sum.to_le_bytes(), 0) != 0 { 1 } else { 0 }
        }
        Some("sleep") => {
            sleep_ms(60_000);
            0
        }
        _ => 1,
    }
}

// ------------------------------------------------------------
// The controller
// ------------------------------------------------------------

struct Worker {
    name: &'static str,
    pid: u64,
    ctl: u64,
    stats: String,
    handles: u64,
    heap_end: u64,
}

/// One kernel measurement at a checkpoint.
#[derive(Clone)]
struct Point {
    c: Vec<(String, u64)>,
    own_handles: u64,
    svc_handles: Vec<(String, u64)>,
}

struct Ctl {
    sys: u64,
    secs: u64,
    seed: u64,
    t0: u64,
    workers: Vec<Worker>,
    base: Option<Point>,
    heap_series: Vec<u64>,
    frames_series: Vec<u64>,
    checks: u64,
}

fn field<'a>(text: &'a str, key: &str) -> &'a str {
    text.split_whitespace().find_map(|w| w.strip_prefix(key).and_then(|r| r.strip_prefix('='))).unwrap_or("0")
}

impl Ctl {
    fn t(&self) -> u64 {
        (uptime_ms() - self.t0) / 1000
    }

    fn result(&self, ok: bool, leaks: u64) {
        let all: String = self.workers.iter().map(|w| w.stats.clone()).collect::<Vec<_>>().join(" ");
        println!(
            "[RESULT-SOAK] seconds={} seed={} ops_files={} snapshots={} kills={} recover_ms={} net_mib={} procs={} checks={} leaks={} errors={}",
            self.t(),
            self.seed,
            field(&all, "ops_files"),
            field(&all, "snapshots"),
            field(&all, "kills"),
            field(&all, "recover_ms"),
            field(&all, "net_mib"),
            field(&all, "procs"),
            self.checks,
            leaks,
            if ok { 0 } else { 1 }
        );
    }

    /// Ends the soak with FAIL: the workers are killed and reaped first.
    fn fail(&self, what: core::fmt::Arguments) -> ! {
        println!("[SOAK] ERROR worker=controller t={}s {}", self.t(), what);
        for w in &self.workers {
            kill(w.pid);
        }
        for w in &self.workers {
            let _ = wait(w.pid, 0);
        }
        self.result(false, 0);
        println!("[SOAK] FAIL");
        exit(1)
    }

    /// Messages from the workers (stats); a worker that ended or closed its channel = FAIL.
    fn drain(&mut self, wait_ms: u64) {
        let list: Vec<(u64, u64)> = self.workers.iter().map(|w| (w.ctl, W_READABLE)).collect();
        let ready = wait_many(&list, wait_ms).unwrap_or(0);
        let mut buf = vec![0u8; MSG_MAX];
        for i in 0..self.workers.len() {
            if ready & (1 << i) == 0 {
                continue;
            }
            loop {
                let mut info = RecvInfo::default();
                let r = chan_recv(self.workers[i].ctl, &mut buf, CHAN_NONBLOCK, &mut info);
                if r == ERROR_WOULD_BLOCK {
                    break;
                }
                if r < 0 {
                    self.worker_gone(i);
                }
                let t = String::from_utf8_lossy(&buf[..r as usize]).into_owned();
                match t.strip_prefix("stats ") {
                    Some(s) => self.workers[i].stats = String::from(s),
                    None => self.fail(format_args!("unexpected message from {}: {:?}", self.workers[i].name, t)),
                }
            }
        }
    }

    fn worker_gone(&self, i: usize) -> ! {
        let w = &self.workers[i];
        let st = wait(w.pid, 0).map(|(_, s)| s).unwrap_or(u64::MAX);
        self.fail(format_args!("worker {} (pid {}) ended: {} (status {:#x})", w.name, w.pid, describe_status(st), st))
    }

    /// Pauses every worker (each finishes its operation and checks what it owns) and
    /// returns their "paused …" texts.
    fn pause_all(&mut self) {
        for w in &self.workers {
            if chan_send(w.ctl, b"pause", 0) != 0 {
                self.fail(format_args!("cannot pause {}", w.name));
            }
        }
        let deadline = uptime_ms() + 900_000;
        let mut waiting: Vec<usize> = (0..self.workers.len()).collect();
        let mut buf = vec![0u8; MSG_MAX];
        while !waiting.is_empty() {
            if uptime_ms() > deadline {
                let names: Vec<&str> = waiting.iter().map(|&i| self.workers[i].name).collect();
                self.fail(format_args!("workers {:?} did not pause within 900 s", names));
            }
            let list: Vec<(u64, u64)> = waiting.iter().map(|&i| (self.workers[i].ctl, W_READABLE)).collect();
            let ready = wait_many(&list, 1000).unwrap_or(0);
            let mut done = Vec::new();
            for (k, &i) in waiting.iter().enumerate() {
                if ready & (1 << k) == 0 {
                    continue;
                }
                loop {
                    let mut info = RecvInfo::default();
                    let r = chan_recv(self.workers[i].ctl, &mut buf, CHAN_NONBLOCK, &mut info);
                    if r == ERROR_WOULD_BLOCK {
                        break;
                    }
                    if r < 0 {
                        self.worker_gone(i);
                    }
                    let t = String::from_utf8_lossy(&buf[..r as usize]).into_owned();
                    if let Some(s) = t.strip_prefix("stats ") {
                        self.workers[i].stats = String::from(s);
                    } else if let Some(s) = t.strip_prefix("paused ") {
                        let w = &mut self.workers[i];
                        w.handles = field(s, "handles").parse().unwrap_or(0);
                        w.heap_end = field(s, "heap_end").parse().unwrap_or(0);
                        // The stats part of the text (after heap_end=…).
                        w.stats = String::from(s.split_once(" heap_end=").and_then(|(_, r)| r.split_once(' ')).map(|(_, r)| r).unwrap_or(""));
                        done.push(i);
                        break;
                    } else {
                        self.fail(format_args!("unexpected message from {}: {:?}", self.workers[i].name, t));
                    }
                }
            }
            waiting.retain(|i| !done.contains(i));
        }
    }

    fn resume_all(&self) {
        for w in &self.workers {
            if chan_send(w.ctl, b"resume", 0) != 0 {
                self.fail(format_args!("cannot resume {}", w.name));
            }
        }
    }

    fn measure(&self) -> Point {
        // Zombies go away within moments (init reaps its services' and orphans' ends).
        let mut c = counters();
        for _ in 0..50 {
            if counter(&c, "zombies") == 0 && counter(&c, "tasks_dead") == 0 {
                break;
            }
            sleep_ms(100);
            c = counters();
        }
        let mut list = [0u8; 2048];
        let n = svc_list(&mut list).unwrap_or(0);
        let names: Vec<String> = core::str::from_utf8(&list[..n]).unwrap_or("").lines().filter_map(|l| l.split_whitespace().next()).map(String::from).collect();
        let svc_handles = names.iter().filter_map(|n| svc_status(n).filter(|(st, _, _)| st == "running").map(|(_, pid, _)| (n.clone(), handles_of(pid)))).collect();
        Point { c, own_handles: handle_count(), svc_handles }
    }

    fn checkpoint(&mut self, label: &str) {
        let tc = uptime_ms();
        println!("[SOAK] checkpoint {}: pausing the workers", label);
        self.pause_all();
        println!("[SOAK] checkpoint {}: workers paused and audited in {} ms; desofs unmount / check / mount", label, uptime_ms() - tc);
        let p = self.measure();
        let mut problems: Vec<String> = Vec::new();
        for k in ["zombies", "tasks_dead"] {
            if counter(&p.c, k) != 0 {
                problems.push(format!("{}={}", k, counter(&p.c, k)));
            }
        }
        // DeSoFS: unmount (also the snapshot views), check, mount again.
        let t = sysctl_text(self.sys, SYSCTL_DESOFS_UNMOUNT, 0, None).unwrap_or_default();
        if !t.contains(&format!("{} unmounted", root())) || t.contains("nothing changed") {
            self.fail(format_args!("desofs unmount at the checkpoint: {:?}", t.trim()));
        }
        // The empty mount points of the views (/snap/<name>) go too, and /snap when empty.
        let mut list = vec![0u8; 16 * 1024];
        let n = readdir("/snap", &mut list);
        if n > 0 {
            let names: Vec<String> = String::from_utf8_lossy(&list[..n as usize]).lines().filter_map(|l| l.rsplit('\t').next()).filter(|n| n.starts_with("soak")).map(String::from).collect();
            for n in names {
                unlink(&format!("/snap/{}", n));
            }
        }
        // And /snap itself (ramfs), made by the first view – it would count as ramfs growth.
        unlink("/snap");
        let check = sysctl_text(self.sys, SYSCTL_DESOFS_CHECK, disk(), None).unwrap_or_default();
        if !check.lines().any(|l| l.trim() == "result: 0 errors, 0 warnings") {
            println!("[SOAK] desofs check:\n{}", check);
            self.fail(format_args!("desofs check at the checkpoint is not clean"));
        }
        let m = sysctl_text(self.sys, SYSCTL_DESOFS_MOUNT, disk(), None).unwrap_or_default();
        if !m.contains(&format!("mounted at {} (DeSoFS, read-write)", root())) {
            self.fail(format_args!("desofs mount at the checkpoint: {:?}", m.trim()));
        }
        // After the remount: the counters again (the volume is back in memory).
        let p = Point { c: counters(), ..p };
        // Kernel heap without the console scrollback (a cache that fills up to its limit).
        let heap_of = |c: &[(String, u64)]| counter(c, "heap_used").saturating_sub(counter(c, "heap_console"));
        // Free frames with the scrollback's share added back (the heap maps frames for it).
        let frames_of = |c: &[(String, u64)]| counter(c, "frames_free") + counter(c, "heap_console") / 4096;
        let (frames, heap) = (frames_of(&p.c), heap_of(&p.c));
        let mut leaks = 0;
        match &self.base {
            None => {
                self.base = Some(p.clone());
            }
            Some(b) => {
                for k in ["tasks", "processes", "ipc_bytes", "ramfs_bytes"] {
                    if counter(&p.c, k) != counter(&b.c, k) {
                        problems.push(format!("{} {} -> {}", k, counter(&b.c, k), counter(&p.c, k)));
                        leaks += 1;
                    }
                }
                let (bf, bh) = (frames_of(&b.c), heap_of(&b.c));
                if bf > frames && bf - frames > 256 {
                    problems.push(format!("free frames {} -> {} (more than 1 MiB fewer)", bf, frames));
                    leaks += 1;
                }
                if heap > bh && heap - bh > 512 * 1024 {
                    problems.push(format!("kernel heap {} -> {} (more than 512 KiB more)", bh, heap));
                    leaks += 1;
                }
                if p.own_handles != b.own_handles {
                    problems.push(format!("controller handles {} -> {}", b.own_handles, p.own_handles));
                    leaks += 1;
                }
                for (n, h) in &p.svc_handles {
                    if let Some((_, bh)) = b.svc_handles.iter().find(|(bn, _)| bn == n) {
                        if h != bh {
                            problems.push(format!("service {} handles {} -> {}", n, bh, h));
                            leaks += 1;
                        }
                    }
                }
            }
        }
        // Workers: handles and their own heap compared with their first checkpoint.
        for w in &mut self.workers {
            let key = format!("{}_handles", w.name);
            let hkey = format!("{}_heap", w.name);
            match self.base.as_mut() {
                Some(b) if b.c.iter().any(|(k, _)| *k == key) => {
                    let (bh, bheap) = (counter(&b.c, &key), counter(&b.c, &hkey));
                    if w.handles != bh {
                        problems.push(format!("worker {} handles {} -> {}", w.name, bh, w.handles));
                        leaks += 1;
                    }
                    if w.heap_end > bheap + 1024 * 1024 {
                        problems.push(format!("worker {} heap end {:#x} -> {:#x} (grew more than 1 MiB)", w.name, bheap, w.heap_end));
                        leaks += 1;
                    }
                }
                Some(b) => {
                    b.c.push((key, w.handles));
                    b.c.push((hkey, w.heap_end));
                }
                None => {}
            }
        }
        // A trend: three checkpoints in a row with more heap / fewer free frames.
        self.heap_series.push(heap);
        self.frames_series.push(frames);
        let up3 = |s: &[u64], more: bool| s.len() >= 4 && s[s.len() - 4..].windows(2).all(|w| if more { w[1] > w[0] } else { w[1] < w[0] });
        if up3(&self.heap_series, true) {
            problems.push(format!("kernel heap grew at 3 checkpoints in a row: {:?}", &self.heap_series[self.heap_series.len() - 4..]));
            leaks += 1;
        }
        if up3(&self.frames_series, false) {
            problems.push(format!("free frames fell at 3 checkpoints in a row: {:?}", &self.frames_series[self.frames_series.len() - 4..]));
            leaks += 1;
        }
        self.checks += 1;
        let heaps: String = self
            .workers
            .iter()
            .map(|w| {
                let b = self.base.as_ref().map(|b| counter(&b.c, &format!("{}_heap", w.name))).unwrap_or(w.heap_end);
                format!("{}:{}", w.name, w.heap_end.saturating_sub(b) / 1024)
            })
            .collect::<Vec<_>>()
            .join(",");
        let all: String = self.workers.iter().map(|w| w.stats.clone()).collect::<Vec<_>>().join(" ");
        // Memory of every process (heap + areas, KiB) – where to look when frames go.
        let procmem: String = p
            .c
            .iter()
            .filter_map(|(k, v)| k.strip_prefix("mem_").map(|r| format!("{}:{}", r.split_once('_').map(|(_, n)| n).unwrap_or(r), v / 1024)))
            .collect::<Vec<_>>()
            .join(",");
        println!("[SOAK] checkpoint {} process memory KiB: {}", label, procmem);
        println!(
            "[SOAK] checkpoint {} t={}s ({} ms): frames_free={} (with console {}) heap_used={} (without console {}) heap_mapped={} worker_heaps_kib={} tasks={} processes={} ipc_bytes={} ramfs_bytes={} handles={} check OK | {}",
            label,
            self.t(),
            uptime_ms() - tc,
            counter(&p.c, "frames_free"),
            frames,
            counter(&p.c, "heap_used"),
            heap,
            counter(&p.c, "heap_mapped"),
            heaps,
            counter(&p.c, "tasks"),
            counter(&p.c, "processes"),
            counter(&p.c, "ipc_bytes"),
            counter(&p.c, "ramfs_bytes"),
            p.own_handles,
            all
        );
        if !problems.is_empty() {
            for pr in &problems {
                println!("[SOAK] ERROR worker=controller checkpoint={} {}", label, pr);
            }
            for w in &self.workers {
                kill(w.pid);
            }
            for w in &self.workers {
                let _ = wait(w.pid, 0);
            }
            self.result(false, leaks);
            println!("[SOAK] FAIL");
            exit(1);
        }
    }
}

fn controller(spec: &str) -> i32 {
    // <seconds>:<seed>, or <seconds>:<seed>:ram – on a RAM disk instead of the virtio disk 0,
    // or <seconds>:<seed>:hw – a RAM disk on real hardware (DESOOS_AUTOSOAK): no test server
    // and no test stick expected (downloads only if the host's test server answers).
    let mut parts = spec.split(':');
    let (secs, seed) = (parts.next().and_then(|s| s.parse::<u64>().ok()), parts.next().and_then(|s| s.parse::<u64>().ok()));
    let ram = match parts.next() {
        None => false,
        Some("ram") => true,
        Some("hw") => {
            HW.store(true, core::sync::atomic::Ordering::Relaxed);
            true
        }
        Some(_) => {
            eprintln!("soak: expected <seconds>:<seed>[:ram], got {:?}", spec);
            return 1;
        }
    };
    let (Some(secs), Some(seed)) = (secs, seed) else {
        eprintln!("soak: expected <seconds>:<seed>[:ram], got {:?}", spec);
        return 1;
    };
    // Only where the kernel started it for this: init's channels and the SYSCTL handle.
    let sys = 4;
    if handle_info(sys).map(|(k, _)| k) != Ok(KIND_SYSCTL) || handle_info(SVC).map(|(k, _)| k) != Ok(KIND_CHANNEL) {
        eprintln!("soak: needs the SYSCTL handle and the service channel (tests/soak.sh or a DESOOS_AUTOSOAK build starts it)");
        return 1;
    }
    println!("[SOAK] {}", info_text("ver").trim());
    // The volume: a RAM disk the soak makes (real hardware: nothing on the computer's own
    // disks is touched), or QEMU's virtio disk 0 – only that one, never another disk 0.
    let vol = if ram {
        let free = counter(&counters(), "frames_free") / 256;
        let mib = if free >= 1536 { 256 } else { 96 };
        let t = match sysctl_text(sys, SYSCTL_RAMDISK, mib, None) {
            Ok(t) => t,
            Err(e) => {
                println!("[SOAK] ERROR worker=controller desofs ramdisk {}: {}", mib, error_name(e));
                return 1;
            }
        };
        let Some(n) = t.strip_prefix("disk ").and_then(|r| r.split_whitespace().next()).and_then(|n| n.parse::<u64>().ok()) else {
            println!("[SOAK] ERROR worker=controller desofs ramdisk {}: {:?}", mib, t.trim());
            return 1;
        };
        VOL_DISK.store(n, core::sync::atomic::Ordering::Relaxed);
        format!("disk {} - RAM disk, {} MiB", n, mib)
    } else {
        let disks = info_text("disk");
        let d0 = String::from(disks.lines().find(|l| l.starts_with("0: ")).unwrap_or(""));
        if !d0.contains("virtio") || d0.contains("read-only") {
            eprintln!("soak: disk 0 is not a writable virtio disk ({:?}) - without :ram the soak runs only in QEMU", d0);
            return 1;
        }
        format!("disk {}", d0)
    };
    println!("[SOAK] start: {} s, SEED={} (workers: files {}, svcnet {}, procs {}), {}", secs, seed, mix(seed ^ 1), mix(seed ^ 2), mix(seed ^ 3), vol);
    match sysctl_text(sys, SYSCTL_DESOFS_FORMAT, disk() | SYSCTL_YES, None) {
        Ok(t) if disk() == 0 && t.contains("mounted at /disk") => {}
        Ok(t) if disk() != 0 && t.contains("DeSoFS,") => match sysctl_text(sys, SYSCTL_DESOFS_MOUNT, disk(), None) {
            Ok(m) if m.contains("mounted at /desofs (DeSoFS, read-write)") => {}
            r => {
                println!("[SOAK] ERROR worker=controller desofs mount {}: {:?}", disk(), r);
                return 1;
            }
        },
        r => {
            println!("[SOAK] ERROR worker=controller desofs format: {:?}", r);
            return 1;
        }
    }
    let mut ctl = Ctl { sys, secs, seed, t0: uptime_ms(), workers: Vec::new(), base: None, heap_series: Vec::new(), frames_series: Vec::new(), checks: 0 };
    let secs_s = format!("{}", secs);
    let disk_s = format!("{}", disk());
    let mode_s = if hw() { "hw" } else { "test" };
    for (i, name) in ["files", "svcnet", "procs"].iter().enumerate() {
        let wseed = format!("{}", mix(seed ^ (i as u64 + 1)));
        let Ok((mine, theirs)) = channel_create() else {
            ctl.fail(format_args!("no channel for {}", name));
        };
        let map: &[(u64, u64)] = match *name {
            "files" => &[(1, 1), (2, 2), (sys, 4), (theirs, CTL)],
            "svcnet" => &[(1, 1), (2, 2), (SVC, 3), (theirs, CTL)],
            _ => &[(1, 1), (2, 2), (theirs, CTL)],
        };
        let pid = spawn_ex("/bin/soak", &["soak", name, &wseed, &secs_s, &disk_s, mode_s], map, 0);
        close(theirs);
        if pid <= 0 {
            ctl.fail(format_args!("cannot start worker {}: {}", name, error_name(pid)));
        }
        ctl.workers.push(Worker { name, pid: pid as u64, ctl: mine, stats: String::new(), handles: 0, heap_end: 0 });
    }
    // Schedule: a baseline after the warm-up, then a checkpoint every 30 min (short soak:
    // halfway), and the last one at the end (it is also the final audit).
    let end = ctl.t0 + secs * 1000;
    let base_at = ctl.t0 + (secs / 4).clamp(20, 300) * 1000;
    let every = if secs < SHORT { (secs / 2).max(30) * 1000 } else { 1_800_000 };
    let mut next_cp = base_at;
    let mut next_hb = ctl.t0 + 60_000;
    let mut cp_no = 0;
    loop {
        let now = uptime_ms();
        if now >= end {
            break;
        }
        if now >= next_cp {
            let label = if cp_no == 0 { String::from("baseline") } else { format!("{}", cp_no) };
            ctl.checkpoint(&label);
            ctl.resume_all();
            cp_no += 1;
            next_cp = if cp_no == 1 { ctl.t0 + every } else { next_cp + every };
            // Not right before the end – the final checkpoint comes then anyway.
            if next_cp + every / 2 > end && cp_no > 1 {
                next_cp = u64::MAX;
            }
            continue;
        }
        if now >= next_hb {
            next_hb += 60_000;
            let all: String = ctl.workers.iter().map(|w| format!("{}: {}", w.name, w.stats)).collect::<Vec<_>>().join(" | ");
            let c = counters();
            println!("[SOAK] heartbeat t={}s of {} s | kernel heap {} KiB + console {} KiB, free frames {} | {}", ctl.t(), secs, counter(&c, "heap_used").saturating_sub(counter(&c, "heap_console")) / 1024, counter(&c, "heap_console") / 1024, counter(&c, "frames_free"), all);
        }
        let wake = end.min(next_cp).min(next_hb);
        ctl.drain((wake.saturating_sub(uptime_ms())).clamp(1, 1000));
    }
    ctl.checkpoint("final");
    // Final: the workers stop (each reports its totals) and are reaped.
    let mut buf = vec![0u8; MSG_MAX];
    for i in 0..ctl.workers.len() {
        if chan_send(ctl.workers[i].ctl, b"stop", 0) != 0 {
            ctl.fail(format_args!("cannot stop {}", ctl.workers[i].name));
        }
        loop {
            let mut info = RecvInfo::default();
            let r = chan_recv(ctl.workers[i].ctl, &mut buf, 0, &mut info);
            if r < 0 {
                ctl.worker_gone(i);
            }
            let t = String::from_utf8_lossy(&buf[..r as usize]).into_owned();
            if let Some(s) = t.strip_prefix("stopped ") {
                ctl.workers[i].stats = String::from(s);
                break;
            }
        }
        let st = wait(ctl.workers[i].pid, 0).map(|(_, s)| s).unwrap_or(u64::MAX);
        if st != 0 {
            ctl.fail(format_args!("worker {} ended with status {:#x}", ctl.workers[i].name, st));
        }
        close(ctl.workers[i].ctl);
    }
    if !matches!(wait(WAIT_ANY, WNOHANG), Err(ERROR_NO_CHILD)) {
        ctl.fail(format_args!("a child of the controller is still there after the end"));
    }
    let _ = ctl.secs;
    ctl.result(true, 0);
    println!("[SOAK] PASS");
    0
}
