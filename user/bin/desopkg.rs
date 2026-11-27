// desopkg – programs from the internet (V082 plan ver 4.6, V082-B plan; formats: docs/pkg/FORMAT.md).
//
//   desopkg refresh                      fetch and check the signed index
//   desopkg [-y] install <name>[=<ver>]… install (a lower version than installed: a downgrade)
//   desopkg [-y] update [<name>…]        everything with a newer version, or only the named ones
//   desopkg [-y] remove <name>…          remove
//   desopkg [-y] reinstall <name>…       the same version again (repair after verify)
//   desopkg list                         installed packages, newer versions available
//   desopkg search <phrase>              the accepted index: names and summaries
//   desopkg info <name>                  one package: installed, available, dependencies, size
//   desopkg verify [<name>]              every installed file against its manifest
//
// How a change is made (V082 plan §5): the new package directories are built next to the old
// ones, then one new generation file `gen/<m>` names the new set – the highest valid generation
// is the current one (like the DeSoFS superblock).  A crash anywhere leaves the old or the new
// generation whole; `gc` removes what nothing points to, also after a crash.
//
// Trust: the index is signed (P-256, /etc/desopkg/keys), every package pinned by its size and
// SHA-256 in the index; HTTPS to exactly the host of /etc/desopkg/repo (no redirects), the CA
// store /etc/certs/roots, the time from the time service (NTS).  The self-test image (built
// with --cfg selftest) instead trusts /etc/desopkg/ca and the self-test time – that code does not
// exist in a normal image.
//
// Exit codes: 0 OK, 1 usage, 2 refused (signature, rules, dependencies), 3 network / time,
// 4 disk / lock / memory, 5 aborted by the user.
#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
#[allow(unused_imports)]
extern crate libdeso;
#[allow(unused_imports)]
use libdeso as deso;

#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;
#[path = "../../common/desotls/mod.rs"]
mod desotls;
#[path = "../../common/elf.rs"]
mod elf;
#[path = "../lib/cmdnames.rs"]
mod cmdnames;
#[path = "../lib/fetch.rs"]
mod fetch;
#[path = "../lib/http.rs"]
mod http;
#[path = "../lib/pkgfmt.rs"]
mod pkgfmt;
#[path = "../lib/pkgsolve.rs"]
mod pkgsolve;
#[path = "../lib/pkgstate.rs"]
mod pkgstate;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use desotls::record::Suite;
use desotls::roots::Anchors;
#[cfg(not(selftest))]
use desotls::roots::Roots;
use pkgfmt::{GenEntry, Index, IndexEntry, InstallReason, Key, RepoConfig, Version};
use pkgsolve::{Action, Installed, Plan, Request};
use pkgstate::{Current, ROOT};

entry!(main);

const EXIT_USAGE: i32 = 1;
const EXIT_REFUSED: i32 = 2;
const EXIT_NET: i32 = 3;
const EXIT_DISK: i32 = 4;
const EXIT_ABORTED: i32 = 5;

const KEYS: &str = "/etc/desopkg/keys";
const REPO: &str = "/etc/desopkg/repo";
#[cfg(not(selftest))]
const ROOTS: &str = "/etc/certs/roots";
/// The self-test image: the test CA of tests/tls (tls.deso, repo-stub).
#[cfg(selftest)]
const ROOTS: &str = "/etc/desopkg/ca";
const LOCK: &str = "/tmp/desopkg.lock";
const STORE_MAX: usize = 256 * 1024;
/// Spare room on the disk beyond the packages' sizes.
const SPARE: u64 = 1024 * 1024;

const USAGE: &str = "usage: desopkg [-y] refresh | install <name>[=<version>]... | update [<name>...] | remove <name>... | reinstall <name>... | list | search <phrase> | info <name> | verify [<name>]";

/// A failure: its exit code and message (printed as "desopkg: <message>").
struct Fail(i32, String);

type Res<T> = Result<T, Fail>;

fn fail<T>(code: i32, msg: impl Into<String>) -> Res<T> {
    Err(Fail(code, msg.into()))
}

fn system_name(n: &str) -> bool {
    cmdnames::system_name(n, &|x| deso::stat(&format!("/bin/{}", x)).is_ok())
}

// ------------------------------------------------------------------ crash points (self-test)

/// V082-B §3 / D-B4: in the self-test image only – /tmp/desopkg-crash names a point: "K5" ends
/// the process at once (as killed: nothing after it runs, the lock stays), "K5:hang" prints
/// "desopkg: HANG K5" and waits for ever (tests/pkg-test.sh then kills QEMU – a power loss).
#[cfg(selftest)]
fn crash_point(at: &str) {
    let Ok(b) = pkgstate::read_file("/tmp/desopkg-crash", 64) else { return };
    let s = core::str::from_utf8(&b).unwrap_or("").trim();
    let (point, hang) = match s.split_once(':') {
        Some((p, "hang")) => (p, true),
        _ => (s, false),
    };
    if point != at {
        return;
    }
    if hang {
        eprintln!("desopkg: HANG {}", at);
        loop {
            deso::sleep_ms(1000);
        }
    }
    deso::exit(99);
}

#[cfg(not(selftest))]
fn crash_point(_: &str) {}

/// Self-test image only: one line per step into /tmp/desopkg-trace (PKG TEST shows it when a
/// command fails).
#[cfg(selftest)]
fn trace(what: &str) {
    let fd = deso::open("/tmp/desopkg-trace", deso::O_WRITE | deso::O_CREATE | deso::O_APPEND);
    if fd >= 0 {
        let _ = deso::write(fd as u64, what.as_bytes());
        let _ = deso::write(fd as u64, b"\n");
        deso::close(fd as u64);
    }
}

#[cfg(not(selftest))]
fn trace(_: &str) {}

/// V082-B P2-1: in the self-test image only – /tmp/desopkg-nomem makes the package buffer's
/// allocation fail.
#[cfg(selftest)]
fn force_nomem() -> bool {
    deso::stat("/tmp/desopkg-nomem").is_ok()
}

#[cfg(not(selftest))]
fn force_nomem() -> bool {
    false
}

// ------------------------------------------------------------------ the lock (§6.3)

/// Other living desopkg processes (SYS_TASKS).
fn other_desopkg() -> bool {
    let mut buf = vec![0u8; 8192];
    let n = loop {
        let n = deso::tasks(&mut buf);
        if n == deso::ERROR_BUFFER_TOO_SMALL && buf.len() < 256 * 1024 {
            let l = buf.len() * 2;
            buf.resize(l, 0);
            continue;
        }
        break n;
    };
    if n < 0 {
        // Unknown – treat as running: never remove a lock that may be someone else's.
        return true;
    }
    let me = deso::getpid();
    core::str::from_utf8(&buf[..n as usize]).unwrap_or("").lines().any(|l| {
        let f: Vec<&str> = l.split('\t').collect();
        f.len() >= 7 && f[6] == "desopkg" && f[0].parse::<u64>().ok() != Some(me)
    })
}

/// The lock is the directory itself: mkdir is "only one".  An existing lock with no other
/// desopkg alive was left by a dead one: removed and taken again (one of two new ones wins;
/// two new ones at once both see each other and both refuse – safe, repeat the command).
fn take_lock() -> Res<()> {
    for _ in 0..2 {
        let r = deso::mkdir(LOCK);
        if r >= 0 {
            return Ok(());
        }
        if r != deso::ERROR_ALREADY_EXISTS {
            return fail(EXIT_DISK, format!("cannot take the lock {}: {}", LOCK, deso::strerror(r)));
        }
        if other_desopkg() {
            return fail(EXIT_DISK, "another desopkg is running");
        }
        let _ = deso::unlink(LOCK);
    }
    fail(EXIT_DISK, "another desopkg is running")
}

fn drop_lock() {
    let _ = deso::unlink(LOCK);
}

// ------------------------------------------------------------------ disk, configuration, time

/// /disk must be a writable DeSoFS volume; /disk/pkg and its gen/ and index/ exist after this.
fn disk_ready() -> Res<()> {
    let mut buf = vec![0u8; 4096];
    let n = deso::sysinfo("mount", &mut buf).unwrap_or(0);
    let mounts = core::str::from_utf8(&buf[..n]).unwrap_or("");
    let desofs = mounts.lines().any(|l| {
        let mut w = l.split_whitespace();
        w.next() == Some("/disk") && w.next() == Some("desofs")
    });
    if !desofs {
        return fail(EXIT_DISK, "no writable DeSoFS volume at /disk");
    }
    for d in [ROOT, pkgstate::GEN_DIR, pkgstate::INDEX_DIR] {
        let r = deso::mkdir(d);
        if r < 0 && r != deso::ERROR_ALREADY_EXISTS {
            return fail(EXIT_DISK, format!("no writable DeSoFS volume at /disk ({}: {})", d, deso::strerror(r)));
        }
    }
    Ok(())
}

fn keys() -> Res<Vec<Key>> {
    let b = pkgstate::read_file(KEYS, 64 * 1024).map_err(|e| Fail(EXIT_REFUSED, format!("{}: {}", KEYS, deso::strerror(e))))?;
    pkgfmt::parse_keys(&b).map_err(|r| Fail(EXIT_REFUSED, format!("{} refused: {}", KEYS, r)))
}

fn repo() -> Res<RepoConfig> {
    let b = pkgstate::read_file(REPO, 4096).map_err(|e| Fail(EXIT_REFUSED, format!("{}: {}", REPO, deso::strerror(e))))?;
    pkgfmt::parse_repo_config(&b).map_err(|r| Fail(EXIT_REFUSED, format!("{} refused: {}", REPO, r)))
}

/// The time desopkg trusts (V082 plan §4 step 1): a plausible clock set by the time service
/// (NTS) in this boot; the self-test image also takes the self-test time (source 3).
fn trusted_now() -> Res<u64> {
    let c = deso::time_unix().map_err(|e| Fail(EXIT_NET, format!("no clock: {} - nothing sent", deso::strerror(e))))?;
    if !c.plausible() {
        return fail(EXIT_NET, format!("the clock is not plausible ({}) - nothing sent", deso::clock_reason(c.status)));
    }
    let mut buf = vec![0u8; 2048];
    let n = deso::sysinfo("date", &mut buf).unwrap_or(0);
    let nts = core::str::from_utf8(&buf[..n]).unwrap_or("").contains("authenticated time from the time service, NTS");
    #[cfg(selftest)]
    let nts = nts || deso::time_bound().is_ok_and(|b| b.source == 3);
    if !nts {
        return fail(EXIT_NET, "the time is not set by the time service (NTS) yet - nothing sent (try again in a minute)");
    }
    Ok(c.secs)
}

fn read_roots() -> Res<Vec<u8>> {
    pkgstate::read_file(ROOTS, STORE_MAX).map_err(|e| Fail(EXIT_NET, format!("TLS refused: trusted CA store missing or damaged ({}: {})", ROOTS, deso::strerror(e))))
}

/// `f` with the trust anchors: the CA store /etc/certs/roots.
#[cfg(not(selftest))]
fn with_anchors<R>(f: impl FnOnce(&dyn Anchors) -> Res<R>) -> Res<R> {
    let b = read_roots()?;
    let store = Roots::parse(&b).map_err(|e| Fail(EXIT_NET, format!("TLS refused: {}", e.as_str())))?;
    f(&store)
}

/// The self-test image: only the test CA /etc/desopkg/ca (one PEM certificate, as netget --anchor).
#[cfg(selftest)]
fn with_anchors<R>(f: impl FnOnce(&dyn Anchors) -> Res<R>) -> Res<R> {
    let b = read_roots()?;
    let mut der = vec![0u8; b.len()];
    let mut spans = [(0usize, 0usize); 1];
    let n = match desotls::pem::certificates(&b, &mut der, &mut spans) {
        Ok(1) => spans[0].1,
        _ => return fail(EXIT_NET, format!("TLS refused: {}: not one certificate", ROOTS)),
    };
    let one: [&[u8]; 1] = [&der[..n]];
    f(&desotls::roots::AnchorList(&one))
}

// ------------------------------------------------------------------ downloads

/// The body into memory: never more than `max` bytes (the connection is ended at once when the
/// answer goes past it – V082-B P2-2), the buffer reserved up front.
struct Mem {
    buf: Vec<u8>,
    max: usize,
    over: bool,
}

impl http::Sink for Mem {
    fn head(&mut self, _raw: &[u8], _interim: bool) {}
    fn body(&mut self, data: &[u8]) -> Result<(), ()> {
        match self.buf.len().checked_add(data.len()) {
            Some(n) if n <= self.max => {
                self.buf.extend_from_slice(data);
                Ok(())
            }
            _ => {
                self.over = true;
                Err(())
            }
        }
    }
    fn trailers(&mut self, _raw: &[u8]) {}
}

/// GET `url` into memory: at most `max` bytes; `exact` – the answer must be exactly that long
/// (Content-Length and the bytes received).
fn download(url: &str, max: usize, exact: Option<u64>, now: u64) -> Res<Vec<u8>> {
    let u = fetch::parse_url(url).map_err(|e| Fail(EXIT_REFUSED, format!("{}: {}", url, e)))?;
    if !u.tls {
        return fail(EXIT_REFUSED, format!("{}: not https", url));
    }
    let mut buf = Vec::new();
    if force_nomem() || buf.try_reserve_exact(max).is_err() {
        return fail(EXIT_DISK, format!("not enough memory for {} ({} B)", url.rsplit('/').next().unwrap_or(url), max));
    }
    let mut sink = Mem { buf, max, over: false };
    let (code, done) = with_anchors(|anchors| {
        let opts = fetch::Options {
            prog: "desopkg",
            card: "net0",
            verbose: false,
            quiet: true,
            anchors,
            now: now as i64,
            suites: &[Suite::Aes128Gcm, Suite::Chacha20Poly1305],
            key_update: false,
            expect_len: exact,
        };
        Ok(fetch::fetch(&u, &opts, &mut sink))
    })?;
    if sink.over {
        return fail(EXIT_NET, format!("{}: the answer is longer than {} bytes - stopped", url, max));
    }
    match (code, done) {
        (0, Some(_)) => {}
        (_, Some(d)) if !(200..300).contains(&d.status) => {
            let why = if (300..400).contains(&d.status) { " (redirects are not followed)" } else { "" };
            return fail(EXIT_NET, format!("{}: HTTP {}{}", url, d.status, why));
        }
        (fetch::EXIT_TLS, _) => return fail(EXIT_NET, format!("{}: TLS refused", url)),
        (fetch::EXIT_CUT, _) => return fail(EXIT_NET, format!("{}: incomplete transfer", url)),
        _ => return fail(EXIT_NET, format!("{}: download failed", url)),
    }
    if let Some(n) = exact {
        if sink.buf.len() as u64 != n {
            return fail(EXIT_NET, format!("{}: incomplete transfer ({} of {} bytes)", url, sink.buf.len(), n));
        }
    }
    Ok(sink.buf)
}

fn base_url(r: &RepoConfig) -> String {
    format!("{}{}/{}/", r.url, r.channel, r.arch)
}

// ------------------------------------------------------------------ refresh (§4)

/// The accepted index in force (highest valid), if any.
fn accepted_now(keys: &[Key]) -> Option<pkgstate::Accepted> {
    pkgstate::accepted(keys).0.into_iter().next()
}

/// Fetches and accepts a new index: signature first, then grammar, repo/channel/arch, time,
/// serial; written as a new file, read back and checked again; old indexes swept (two kept).
/// Ok(serial in force).
fn refresh(keys: &[Key], cfg: &RepoConfig, verbose: bool) -> Res<u64> {
    let now = trusted_now()?;
    let base = base_url(cfg);
    let index = download(&format!("{}index", base), pkgfmt::MAX_INDEX, None, now)?;
    let sig = download(&format!("{}index.sig", base), pkgfmt::MAX_SIG, None, now)?;
    pkgfmt::verify_index(&index, &sig, keys).map_err(|r| Fail(EXIT_REFUSED, format!("index refused: signature: {}", r)))?;
    let idx = pkgfmt::parse_index(&index).map_err(|r| Fail(EXIT_REFUSED, format!("index refused: {}", r)))?;
    pkgfmt::check_index_repo(&idx, cfg).map_err(|_| Fail(EXIT_REFUSED, format!("index refused: it is for {}/{}/{}, this system uses {}/{}/{}", idx.repo, idx.channel, idx.arch, cfg.repo, cfg.channel, cfg.arch)))?;
    pkgfmt::check_index_time(&idx, now).map_err(|r| {
        Fail(EXIT_REFUSED, match r {
            "expired" => format!("index refused: expired (serial {})", idx.serial),
            _ => format!("index refused: issued in the future (serial {}) - check the clock", idx.serial),
        })
    })?;
    let (good, _) = pkgstate::accepted(keys);
    if let Some(cur) = good.first() {
        if idx.serial < cur.serial {
            return fail(EXIT_REFUSED, format!("index refused: serial {} is older than the accepted {} (an old index)", idx.serial, cur.serial));
        }
        if idx.serial == cur.serial {
            let on_disk = pkgstate::read_file(&format!("{}/{}", pkgstate::INDEX_DIR, cur.serial), pkgfmt::MAX_INDEX + pkgfmt::MAX_SIG + 64).unwrap_or_default();
            if on_disk == pkgfmt::make_accepted(&index, &sig) {
                if verbose {
                    println!("index serial {} is up to date ({} packages, valid until {})", cur.serial, cur.index.packages.len(), date(cur.index.expires));
                }
                return Ok(cur.serial);
            }
            return fail(EXIT_REFUSED, format!("index refused: serial {} again, but with other contents", idx.serial));
        }
    }
    // Step 7: a new file; a leftover with this name (an unfinished write) is removed first.
    let path = format!("{}/{}", pkgstate::INDEX_DIR, idx.serial);
    if deso::stat(&path).is_ok() {
        pkgstate::remove_tree(&path);
    }
    let file = pkgfmt::make_accepted(&index, &sig);
    crash_point("K2");
    write_file_new(&path, &file, "K2h")?;
    crash_point("K3");
    // Step 8: read back and checked in full before it counts.
    let back = pkgstate::read_file(&path, file.len() + 1).map_err(|e| Fail(EXIT_DISK, format!("{}: {}", path, deso::strerror(e))))?;
    if back != file || pkgfmt::check_accepted(&back, keys).is_err() {
        pkgstate::remove_tree(&path);
        return fail(EXIT_DISK, format!("{}: the index did not read back correctly - the previous one stays", path));
    }
    if verbose {
        println!("index serial {} accepted ({} packages, valid until {})", idx.serial, idx.packages.len(), date(idx.expires));
    }
    Ok(idx.serial)
}

/// A new file; in the self-test image `half_point` writes it in two parts with a crash point
/// between them (a power loss in the middle of the write).
fn write_file_new(path: &str, data: &[u8], half_point: &str) -> Res<()> {
    let half = data.len() / 2;
    #[cfg(selftest)]
    let split = pkgstate::read_file("/tmp/desopkg-crash", 64).is_ok_and(|b| b.starts_with(half_point.as_bytes()));
    #[cfg(not(selftest))]
    let split = {
        let _ = half_point;
        false
    };
    let r = if split {
        pkgstate::write_new(path, &[&data[..half]]).and_then(|_| {
            crash_point(half_point);
            let fd = deso::open(path, deso::O_WRITE | deso::O_APPEND);
            if fd < 0 {
                return Err(fd);
            }
            let n = deso::write(fd as u64, &data[half..]);
            deso::close(fd as u64);
            if n as usize == data.len() - half { Ok(()) } else { Err(deso::ERROR_IO) }
        })
    } else {
        pkgstate::write_new(path, &[data])
    };
    r.map_err(|e| Fail(EXIT_DISK, format!("{}: {}", path, deso::strerror(e))))
}

/// The index `install` uses (§4 table): none or expired – refresh first; a damaged newest file –
/// the previous valid one (`accepted` skips it); refresh needed but impossible – refused.
fn index_for_change(keys: &[Key], cfg: &RepoConfig, always_refresh: bool) -> Res<Index> {
    let now_ok = deso::time_unix().ok().filter(|c| c.plausible()).map(|c| c.secs);
    let cur = accepted_now(keys);
    let need = always_refresh || cur.as_ref().is_none_or(|a| now_ok.is_none_or(|t| a.index.expires <= t));
    if need {
        let why = if always_refresh {
            ""
        } else if cur.is_none() {
            " (no accepted index yet)"
        } else {
            " (the accepted index expired)"
        };
        if !why.is_empty() {
            println!("refreshing the index{}...", why);
        }
        refresh(keys, cfg, false)?;
        return accepted_now(keys).map(|a| a.index).ok_or_else(|| Fail(EXIT_DISK, String::from("the accepted index cannot be read back")));
    }
    Ok(cur.map(|a| a.index).unwrap())
}

// ------------------------------------------------------------------ the change itself

fn installed_of(cur: Option<&Current>) -> Vec<Installed> {
    let Some(c) = cur else { return Vec::new() };
    c.generation
        .packages
        .iter()
        .zip(c.manifests.iter())
        .map(|(e, m)| Installed { name: e.name.clone(), version: e.version, reason: e.reason, depends: m.depends.clone(), conflicts: m.conflicts.clone() })
        .collect()
}

fn reason_text(r: InstallReason) -> &'static str {
    if r == InstallReason::Explicit { "explicit" } else { "dependency" }
}

/// The plan on the screen and the y/N question (`-y` skips it).  false = not confirmed.
fn confirm(plan: &Plan, idx: &Index, yes: bool) -> bool {
    trace(&format!("confirm: {} steps", plan.steps.len()));
    let mut bytes = 0u64;
    for s in &plan.steps {
        trace(&format!("step {} {} {:?}", s.name, s.version, s.action));
        let line = match s.action {
            Action::Keep => continue,
            Action::Install => format!("  install    {} {}{}", s.name, s.version, if s.reason == InstallReason::Dependency { " (dependency)" } else { "" }),
            Action::Upgrade(f) => format!("  upgrade    {} {} -> {}", s.name, f, s.version),
            Action::Downgrade(f) => format!("  downgrade  {} {} -> {}  (WARNING: an older version)", s.name, f, s.version),
            Action::Reinstall => format!("  reinstall  {} {}", s.name, s.version),
        };
        if let Some(e) = idx.find(&s.name, s.version) {
            bytes += e.size;
        }
        println!("{}", line);
    }
    for (n, v) in &plan.removed {
        println!("  remove     {} {}", n, v);
    }
    for n in &plan.unneeded {
        println!("  no longer needed: {} (installed as a dependency; desopkg remove {})", n, n);
    }
    for (n, from, to) in plan.downgrades() {
        println!("warning: downgrade {} {} -> {}", n, from, to);
    }
    if bytes > 0 {
        println!("download: {} bytes", bytes);
    }
    if yes {
        return true;
    }
    print!("Continue? [y/N] ");
    let mut b = [0u8; 16];
    let n = deso::read(0, &mut b);
    let ans = if n > 0 { core::str::from_utf8(&b[..n as usize]).unwrap_or("").trim() } else { "" };
    if n <= 0 {
        println!();
    }
    matches!(ans, "y" | "Y" | "yes")
}

/// Free bytes on /disk (sysinfo df: "<mount> <size> <used> <free>", sizes "N B", "N.N KiB",
/// "N.N MiB" – the lower bound).
fn free_on_disk() -> Option<u64> {
    let mut buf = vec![0u8; 4096];
    let n = deso::sysinfo("df", &mut buf).ok()?;
    let text = core::str::from_utf8(&buf[..n]).ok()?;
    let line = text.lines().find(|l| l.split_whitespace().next() == Some("/disk"))?;
    let w: Vec<&str> = line.split_whitespace().collect();
    let (num, unit) = (w.get(w.len().checked_sub(2)?)?, w.last()?);
    let (whole, tenth) = match num.split_once('.') {
        Some((a, b)) => (a.parse::<u64>().ok()?, b.parse::<u64>().ok()?),
        None => (num.parse::<u64>().ok()?, 0),
    };
    let mul = match *unit {
        "B" => 1,
        "KiB" => 1024,
        "MiB" => 1024 * 1024,
        _ => return None,
    };
    Some(whole * mul + tenth * mul / 10)
}

/// Random 16 hex digits for a new version directory.
fn dir_id() -> Res<String> {
    let mut r = [0u8; 8];
    deso::getrandom(&mut r).map_err(|_| Fail(EXIT_DISK, String::from("no random numbers")))?;
    let mut s = String::with_capacity(16);
    for b in r {
        s.push_str(&format!("{:02x}", b));
    }
    Ok(s)
}

/// Every directory of `path` that does not exist yet (an existing one – a mount point like
/// /disk included – is left alone).
fn mkdirs(path: &str) -> Result<(), i64> {
    let mut end = 0;
    loop {
        end = match path[end + 1..].find('/') {
            Some(i) => end + 1 + i,
            None => path.len(),
        };
        let p = &path[..end];
        match deso::stat(p) {
            Ok(st) if st.is_dir => {}
            Ok(_) => return Err(deso::ERROR_NOT_DIRECTORY),
            Err(_) => {
                let r = deso::mkdir(p);
                if r < 0 && r != deso::ERROR_ALREADY_EXISTS {
                    return Err(r);
                }
            }
        }
        if end == path.len() {
            return Ok(());
        }
    }
}

/// One package: download (exactly `size` bytes), every check of FORMAT.md §3 against its index
/// entry, programs not in /disk/bin, then a new version directory – files first, `package` last.
/// Returns (dir, SHA-256 of the manifest, programs).
fn build_package(e: &IndexEntry, cfg: &RepoConfig, now: u64) -> Res<(String, [u8; 32], Vec<String>)> {
    trace(&format!("build {} {}", e.name, e.version));
    println!("downloading {} {} ({} bytes)...", e.name, e.version, e.size);
    let url = format!("{}packages/{}-{}.pkg", base_url(cfg), e.name, e.version);
    crash_point("K4");
    let bytes = download(&url, e.size as usize, Some(e.size), now)?;
    let pkg = pkgfmt::check_pkg_against_index(&bytes, e, &system_name).map_err(|r| Fail(EXIT_REFUSED, format!("{} {} refused: {}", e.name, e.version, r)))?;
    let programs: Vec<String> = pkg.manifest.programs().iter().map(|s| s.to_string()).collect();
    for p in &programs {
        if deso::stat(&format!("/disk/bin/{}", p)).is_ok() {
            return fail(EXIT_REFUSED, format!("{} {} refused: its program {} is already in /disk/bin (copied by hand) - remove that copy first", e.name, e.version, p));
        }
    }
    crash_point("K5");
    let dir = format!("{}-{}", e.version, dir_id()?);
    let vdir = pkgstate::version_dir(&e.name, &dir);
    mkdirs(&vdir).map_err(|r| Fail(EXIT_DISK, format!("{}: {}", vdir, deso::strerror(r))))?;
    for (i, f) in pkg.manifest.files.iter().enumerate() {
        let path = format!("{}/{}", vdir, f.path);
        if let Some((parent, _)) = path.rsplit_once('/') {
            mkdirs(parent).map_err(|r| Fail(EXIT_DISK, format!("{}: {}", parent, deso::strerror(r))))?;
        }
        let data = &pkg.data[f.offset as usize..(f.offset + f.size) as usize];
        pkgstate::write_new(&path, &[data]).map_err(|r| Fail(EXIT_DISK, format!("{}: {}", path, deso::strerror(r))))?;
        if i == 0 {
            crash_point("K6");
        }
    }
    // The package file last: a directory with it is complete.
    let mpath = format!("{}/package", vdir);
    pkgstate::write_new(&mpath, &[pkg.manifest_bytes]).map_err(|r| Fail(EXIT_DISK, format!("{}: {}", mpath, deso::strerror(r))))?;
    Ok((dir, desocrypto::sha256::sha256(pkg.manifest_bytes), programs))
}

/// Carries out a plan: packages built, then the new generation (the moment of change), then gc.
fn apply(plan: &Plan, op: &str, cur: Option<&Current>, idx: Option<&Index>, cfg: Option<&RepoConfig>) -> Res<u64> {
    trace("apply");
    let now = if plan.fetches().is_empty() { 0 } else { trusted_now()? };
    // Space (§6.4): the packages' sizes + spare.
    let need: u64 = plan.fetches().iter().filter_map(|s| idx.and_then(|i| i.find(&s.name, s.version))).map(|e| e.size).sum::<u64>();
    if need > 0 {
        if let Some(free) = free_on_disk() {
            if free < need + SPARE {
                return fail(EXIT_DISK, format!("not enough space on /disk: {} bytes needed, {} free", need + SPARE, free));
            }
        }
    }
    let mut entries: Vec<GenEntry> = Vec::new();
    for s in &plan.steps {
        let kept = cur.and_then(|c| c.generation.packages.iter().find(|p| p.name == s.name && p.version == s.version));
        let e = match (s.action, kept) {
            (Action::Keep, Some(k)) => {
                let mut k = k.clone();
                k.reason = s.reason;
                k
            }
            _ => {
                let (Some(idx), Some(cfg)) = (idx, cfg) else {
                    return fail(EXIT_DISK, format!("{}: no index to download it from", s.name));
                };
                let ie = idx.find(&s.name, s.version).ok_or_else(|| Fail(EXIT_REFUSED, format!("{} {} is not in the index", s.name, s.version)))?;
                let (dir, manifest, programs) = build_package(ie, cfg, now)?;
                GenEntry { name: s.name.clone(), version: s.version, dir, reason: s.reason, manifest, depends_raw: ie.depends_raw.clone(), conflicts: ie.conflicts.clone(), programs }
            }
        };
        entries.push(e);
    }
    // Program names: one owner in the whole generation.
    for (i, a) in entries.iter().enumerate() {
        for p in &a.programs {
            if let Some(b) = entries[i + 1..].iter().find(|b| b.programs.contains(p)) {
                return fail(EXIT_REFUSED, format!("{} and {} both have the program {}", a.name, b.name, p));
            }
        }
    }
    crash_point("K7");
    let g = pkgstate::generations(&system_name);
    let m = g.highest.checked_add(1).ok_or_else(|| Fail(EXIT_DISK, String::from("generation counter exhausted")))?;
    let bytes = pkgfmt::make_generation(m, op, &entries);
    let path = format!("{}/{}", pkgstate::GEN_DIR, m);
    write_file_new(&path, &bytes, "K7h")?;
    // The moment of change: generation m counts once it reads back whole and valid.
    let now_cur = pkgstate::load_generation(m, &system_name).map_err(|r| Fail(EXIT_DISK, format!("{}: the new generation does not read back ({}) - the previous one stays", path, r)))?;
    crash_point("K8");
    sweep(Some(&now_cur));
    Ok(m)
}

/// gc (§6.2) with what is in force now.
fn sweep(cur_hint: Option<&Current>) -> pkgstate::Swept {
    let g = pkgstate::generations(&system_name);
    let cur = g.current.as_ref().or(cur_hint);
    let keep_index: Vec<u64> = match keys() {
        Ok(k) => pkgstate::accepted(&k).0.iter().map(|a| a.serial).collect(),
        // No key store: keep every index (nothing can be checked, nothing is deleted).
        Err(_) => pkgstate::numbered(pkgstate::INDEX_DIR).0,
    };
    crash_point("K9");
    pkgstate::gc(cur, g.previous, &keep_index, &system_name)
}

// ------------------------------------------------------------------ commands

fn parse_name_ver(a: &str) -> Res<(String, Option<Version>)> {
    let (n, v) = match a.split_once('=') {
        Some((n, v)) => (n, Some(Version::parse(v).ok_or_else(|| Fail(EXIT_USAGE, format!("{}: a version is A.B.C", a)))?)),
        None => (a, None),
    };
    if !pkgfmt::valid_name(n) {
        return fail(EXIT_USAGE, format!("{}: not a package name", n));
    }
    Ok((n.to_string(), v))
}

fn change(req: Request, op: &str, yes: bool) -> Res<()> {
    let keys = keys()?;
    let cfg = repo()?;
    let g = pkgstate::generations(&system_name);
    let cur = g.current.as_ref();
    let needs_index = !matches!(req, Request::Remove(_));
    let idx = if needs_index { Some(index_for_change(&keys, &cfg, matches!(req, Request::Update(_)))?) } else { None };
    let empty = Index { repo: String::new(), channel: String::new(), arch: String::new(), serial: 0, issued: 0, expires: 0, packages: Vec::new() };
    let plan = pkgsolve::solve(&installed_of(cur), idx.as_ref().unwrap_or(&empty), &req).map_err(|r| Fail(EXIT_REFUSED, r.msg))?;
    if !plan.changes() {
        println!("{}", if matches!(req, Request::Update(_)) { "nothing to update" } else { "nothing to do" });
        for n in &plan.unneeded {
            println!("  no longer needed: {} (installed as a dependency; desopkg remove {})", n, n);
        }
        return Ok(());
    }
    if !confirm(&plan, idx.as_ref().unwrap_or(&empty), yes) {
        return fail(EXIT_ABORTED, "aborted - nothing changed");
    }
    let m = apply(&plan, op, cur, idx.as_ref(), Some(&cfg))?;
    println!("generation {} is now current", m);
    Ok(())
}

/// YYYY-MM-DD of Unix seconds (Howard Hinnant's civil_from_days).
fn date(t: u64) -> String {
    let z = (t / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn cmd_list() -> Res<()> {
    let g = pkgstate::generations(&system_name);
    let idx = keys().ok().and_then(|k| accepted_now(&k)).map(|a| a.index);
    let Some(c) = g.current else {
        println!("no packages installed");
        return Ok(());
    };
    for (e, m) in c.generation.packages.iter().zip(c.manifests.iter()) {
        let newer = idx.as_ref().and_then(|i| pkgsolve::newest(i, &e.name)).filter(|n| n.version > e.version).map(|n| format!("{} -> {}", e.version, n.version)).unwrap_or_default();
        println!("{:<20} {:<10} {:<11} {:<20} {}", e.name, e.version.to_string(), reason_text(e.reason), newer, m.summary);
    }
    println!("generation {}", c.number);
    Ok(())
}

fn cmd_search(phrase: &str) -> Res<()> {
    let k = keys()?;
    let Some(a) = accepted_now(&k) else {
        return fail(EXIT_REFUSED, "no accepted index - desopkg refresh first");
    };
    let p = phrase.to_ascii_lowercase();
    let mut seen: Vec<&str> = Vec::new();
    let mut found = 0;
    for e in &a.index.packages {
        if seen.contains(&e.name.as_str()) {
            continue;
        }
        seen.push(&e.name);
        let Some(n) = pkgsolve::newest(&a.index, &e.name) else { continue };
        if n.name.contains(&p) || n.summary.to_ascii_lowercase().contains(&p) {
            println!("{:<20} {:<10} {}", n.name, n.version.to_string(), n.summary);
            found += 1;
        }
    }
    if found == 0 {
        println!("nothing found for {:?}", phrase);
    }
    Ok(())
}

fn cmd_info(name: &str) -> Res<()> {
    let g = pkgstate::generations(&system_name);
    let inst = g.current.as_ref().and_then(|c| c.generation.packages.iter().find(|p| p.name == name).cloned());
    let idx = keys().ok().and_then(|k| accepted_now(&k)).map(|a| a.index);
    let versions: Vec<&IndexEntry> = idx.as_ref().map(|i| i.packages.iter().filter(|e| e.name == name).collect()).unwrap_or_default();
    if inst.is_none() && versions.is_empty() {
        return fail(EXIT_REFUSED, format!("no package {}", name));
    }
    println!("package    {}", name);
    match &inst {
        Some(p) => println!("installed  {} ({}, {})", p.version, reason_text(p.reason), pkgstate::version_dir(&p.name, &p.dir)),
        None => println!("installed  -"),
    }
    let newest = idx.as_ref().and_then(|i| pkgsolve::newest(i, name));
    if let Some(n) = newest {
        println!("available  {}", n.version);
        println!("summary    {}", n.summary);
        println!("size       {} bytes", n.size);
        println!("depends    {}", if n.depends_raw.is_empty() { String::from("-") } else { n.depends_raw.join(", ") });
        println!("conflicts  {}", if n.conflicts.is_empty() { String::from("-") } else { n.conflicts.join(", ") });
    }
    if versions.len() > 1 {
        let mut v: Vec<Version> = versions.iter().map(|e| e.version).collect();
        v.sort();
        let list: Vec<String> = v.iter().map(|x| x.to_string()).collect();
        println!("versions   {}", list.join(" "));
    }
    if let Some(p) = &inst {
        println!("programs   {}", if p.programs.is_empty() { String::from("-") } else { p.programs.join(" ") });
    }
    Ok(())
}

/// §6.5: every file of every package (or of one) against its manifest; statuses OK, MISSING,
/// MODIFIED, UNEXPECTED, SHADOWED, DAMAGED; nothing repaired.
fn cmd_verify(only: Option<&str>) -> Res<()> {
    let (nums, _) = pkgstate::numbered(pkgstate::GEN_DIR);
    let g = pkgstate::generations(&system_name);
    let mut bad = 0;
    // A newer generation file that is not valid because of a damaged package file: its packages
    // are reported DAMAGED (the system runs the previous one).
    if let Some(&top) = nums.first() {
        if g.current.as_ref().is_none_or(|c| c.number < top) {
            if let Ok(raw) = pkgstate::read_file(&format!("{}/{}", pkgstate::GEN_DIR, top), pkgfmt::MAX_GENERATION) {
                if let Ok(gen_top) = pkgfmt::parse_generation(&raw, top, &system_name) {
                    for e in gen_top.packages.iter().filter(|e| only.is_none_or(|o| o == e.name)) {
                        let path = format!("{}/package", pkgstate::version_dir(&e.name, &e.dir));
                        let ok = pkgstate::read_file(&path, pkgfmt::MAX_MANIFEST).ok().is_some_and(|m| pkgfmt::check_generation_package(e, &m, &system_name).is_ok());
                        if !ok {
                            println!("DAMAGED     {} {}: {}", e.name, e.version, path);
                            bad += 1;
                        }
                    }
                }
            }
            if let Some(c) = &g.current {
                println!("note: generation {} is not valid - the system uses generation {}", top, c.number);
            }
        }
    }
    let Some(c) = g.current else {
        if bad == 0 {
            println!("no packages installed");
            return Ok(());
        }
        return Err(Fail(EXIT_REFUSED, format!("{} problems", bad)));
    };
    if let Some(o) = only {
        if !c.generation.packages.iter().any(|p| p.name == o) && bad == 0 {
            return fail(EXIT_REFUSED, format!("{} is not installed", o));
        }
    }
    let mut files = 0;
    for (e, m) in c.generation.packages.iter().zip(c.manifests.iter()) {
        if only.is_some_and(|o| o != e.name) {
            continue;
        }
        let vdir = pkgstate::version_dir(&e.name, &e.dir);
        let mut expect: Vec<String> = vec![format!("{}/package", vdir)];
        for f in &m.files {
            let path = format!("{}/{}", vdir, f.path);
            expect.push(path.clone());
            files += 1;
            match pkgstate::read_file(&path, pkgfmt::MAX_DATA as usize + 1) {
                Err(_) => {
                    println!("MISSING     {}", path);
                    bad += 1;
                }
                Ok(b) if b.len() as u64 != f.size || desocrypto::sha256::sha256(&b) != f.sha256 => {
                    println!("MODIFIED    {}", path);
                    bad += 1;
                }
                Ok(_) => {}
            }
        }
        // Files outside the manifest (empty directories are not looked at).
        let mut stack = vec![vdir.clone()];
        while let Some(d) = stack.pop() {
            for (is_dir, n) in pkgstate::list(&d).unwrap_or_default() {
                let p = format!("{}/{}", d, n);
                if is_dir {
                    stack.push(p);
                } else if !expect.contains(&p) {
                    println!("UNEXPECTED  {}", p);
                    bad += 1;
                }
            }
        }
        for p in &e.programs {
            if deso::stat(&format!("/disk/bin/{}", p)).is_ok() {
                println!("SHADOWED    {}/bin/{} (a copy in /disk/bin/{} runs instead)", vdir, p, p);
                bad += 1;
            }
        }
    }
    if bad > 0 {
        return Err(Fail(EXIT_REFUSED, format!("{} problems in generation {} - desopkg reinstall <name> repairs a package", bad, c.number)));
    }
    println!("OK - {} files of {} packages, generation {}", files, if only.is_some() { 1 } else { c.generation.packages.len() }, c.number);
    Ok(())
}

fn run(args: &[&str]) -> Res<()> {
    let mut yes = false;
    let mut words: Vec<&str> = Vec::new();
    for a in args {
        match *a {
            "-y" | "--yes" => yes = true,
            _ => words.push(a),
        }
    }
    let Some((&cmd, rest)) = words.split_first() else {
        return fail(EXIT_USAGE, USAGE);
    };
    // Usage errors before the lock and the disk.
    let names = || -> Res<Vec<String>> {
        rest.iter()
            .map(|a| if pkgfmt::valid_name(a) { Ok(a.to_string()) } else { fail(EXIT_USAGE, format!("{}: not a package name", a)) })
            .collect()
    };
    let req = match cmd {
        "install" if !rest.is_empty() => Some(Request::Install(rest.iter().map(|a| parse_name_ver(a)).collect::<Res<Vec<_>>>()?)),
        "update" => Some(Request::Update(names()?)),
        "remove" if !rest.is_empty() => Some(Request::Remove(names()?)),
        "reinstall" if !rest.is_empty() => Some(Request::Reinstall(names()?)),
        "refresh" | "list" if rest.is_empty() => None,
        "search" if rest.len() == 1 => None,
        "info" if rest.len() == 1 && pkgfmt::valid_name(rest[0]) => None,
        "verify" if rest.len() <= 1 => None,
        _ => return fail(EXIT_USAGE, USAGE),
    };
    disk_ready()?;
    take_lock()?;
    crash_point("K1");
    let r = (|| -> Res<()> {
        // Whatever an earlier, interrupted run left behind is swept first.
        if matches!(cmd, "install" | "update" | "remove" | "reinstall" | "refresh") {
            sweep(None);
        }
        match (cmd, req) {
            (_, Some(req)) => change(req, cmd, yes),
            ("refresh", _) => {
                let k = keys()?;
                let c = repo()?;
                refresh(&k, &c, true).map(|_| ())
            }
            ("list", _) => cmd_list(),
            ("search", _) => cmd_search(rest[0]),
            ("info", _) => cmd_info(rest[0]),
            ("verify", _) => cmd_verify(rest.first().copied()),
            _ => fail(EXIT_USAGE, USAGE),
        }
    })();
    crash_point("K10");
    drop_lock();
    r
}

fn main(args: deso::Args) -> i32 {
    let a: Vec<&str> = args.iter().skip(1).collect();
    match run(&a) {
        Ok(()) => 0,
        Err(Fail(code, msg)) => {
            trace(&format!("fail {}: {}", code, msg));
            eprintln!("desopkg: {}", msg);
            code
        }
    }
}
