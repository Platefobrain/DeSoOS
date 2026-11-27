// pkgtest – desopkg's formats (user/lib/pkgfmt.rs) in user space; the kernel PKG FORMAT TEST
// runs it.
//
//   pkgtest vectors <file>   the vectors tools/desopkg.py made (build.sh --selftest): every one
//                            judged by pkgfmt.rs must get the verdict and reason the Python tool
//                            gave – "pkgtest: N vectors OK"; system names: user/lib/cmdnames.rs +
//                            /bin of this system, asked live
//   pkgtest etc              /etc/desopkg/keys and /etc/desopkg/repo of the image parse:
//                            "pkgtest etc: K keys (<ids>), repo <url> <repo>/<channel>/<arch>"
//   pkgtest elf              every program in /bin accepted by common/elf.rs `check_program` –
//                            the rules desopkg checks a package's programs with are the kernel's
//                            own: "pkgtest elf: N programs accepted, ABI 1.0"
//   pkgtest b1-notime        PKG TEST (tests/pkg-test.sh): without the time service's
//                            time desopkg refuses before connecting (repo-stub saw nothing)
//   pkgtest b1:s1 … b1:s8    PKG TEST part 1 in 8 segments: desopkg against tests/repo-stub.py
//                            through the real init – install, list / search / info, update,
//                            downgrade, dependencies and refusals, remove, verify and reinstall,
//                            refused indexes and transfers, no memory, a big package:
//                            "pkgtest b1 sN: K checks OK (…)"  (`init test /bin/pkgtest b1:sN` –
//                            init passes one argument).  Between segments the kernel runs
//                            the shell (only the kernel can feed its keyboard input) and checks
//                            what the installed programs print.
//   pkgtest b2:k1 … b2:k7    PKG TEST part 2: desopkg killed at
//                            every crash point K1–K10, the lock (a living holder, a dead one,
//                            two new ones at once), a damaged newest index, generations that must
//                            not count
//   pkgtest b2:pa … b2:pd    with the kernel: the shell paused before exec while an
//                            update and its gc remove the program (it looks again); a bad ELF in
//                            a valid generation (no second try)
//   pkgtest ph:N / pc:N      power losses: desopkg hangs at a crash point (the kernel then says
//                            POWER OFF and tests/pkg-test.sh kills QEMU); after the next start
//                            pc:N checks what the disk holds
//   pkgtest m                the short sequence tests/pkg-test.sh --mutants runs against each
//                            desopkg with one check switched off (every one must fail it)
//
// A failure prints "pkgtest: FAIL ..." and exits with 1.
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
#[path = "../../common/elf.rs"]
mod elf;
#[path = "../lib/cmdnames.rs"]
mod cmdnames;
#[path = "../lib/pkgfmt.rs"]
mod pkgfmt;
#[path = "../lib/pkgvec.rs"]
mod pkgvec;
#[path = "../lib/pkgstate.rs"]
mod pkgstate;

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use deso::{ERROR_BUFFER_TOO_SMALL, O_READ, close, open, read, strerror};

entry!(main);

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    let fd = open(path, O_READ);
    if fd < 0 {
        return Err(format!("{}: {}", path, strerror(fd)));
    }
    let mut v = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = read(fd as u64, &mut buf);
        if n < 0 {
            close(fd as u64);
            return Err(format!("{}: {}", path, strerror(n)));
        }
        if n == 0 {
            close(fd as u64);
            return Ok(v);
        }
        v.extend_from_slice(&buf[..n as usize]);
    }
}

/// File names in a directory (readdir: "kind\tsize\tname" lines).
fn dir_files(dir: &str) -> Vec<String> {
    let mut buf = vec![0u8; 4096];
    loop {
        let n = deso::readdir(dir, &mut buf);
        if n == ERROR_BUFFER_TOO_SMALL && buf.len() < 256 * 1024 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if n < 0 {
            return Vec::new();
        }
        let text = core::str::from_utf8(&buf[..n as usize]).unwrap_or("");
        return text
            .lines()
            .filter_map(|l| {
                let mut parts = l.splitn(3, '\t');
                let kind = parts.next()?;
                let _size = parts.next()?;
                let name = parts.next()?;
                if kind == "f" { Some(String::from(name)) } else { None }
            })
            .collect();
    }
}

/// The shell's rule (user/bin/sh.rs `system_name`): the lists + /bin/<name> exists.
fn system_name(name: &str) -> bool {
    cmdnames::system_name(name, &|n| deso::stat(&format!("/bin/{}", n)).is_ok())
}

/// Every system name this side knows: the lists + the files of /bin, sorted, without repeats.
fn system_names() -> Vec<String> {
    let mut v = dir_files("/bin");
    v.extend(cmdnames::BUILTINS.iter().map(|(n, _)| String::from(*n)));
    for l in [cmdnames::SYSCTL_BUILTINS, cmdnames::INFO_COMMANDS, cmdnames::KERNEL_ONLY] {
        v.extend(l.iter().map(|n| String::from(*n)));
    }
    v.sort();
    v.dedup();
    v
}

fn vectors(path: &str) -> i32 {
    let data = match read_file(path) {
        Ok(d) => d,
        Err(e) => {
            println!("pkgtest: FAIL {}", e);
            return 1;
        }
    };
    let names = system_names();
    match pkgvec::run(&data, &system_name, &names) {
        Ok((n, fails)) if fails.is_empty() => {
            println!("pkgtest: {} vectors OK ({} system names)", n, names.len());
            0
        }
        Ok((n, fails)) => {
            for f in fails.iter().take(20) {
                println!("pkgtest: FAIL {}", f);
            }
            println!("pkgtest: FAIL {} of {} vectors differ from tools/desopkg.py", fails.len(), n);
            1
        }
        Err(e) => {
            println!("pkgtest: FAIL bad vector file: {}", e);
            1
        }
    }
}

fn etc() -> i32 {
    let keys = match read_file("/etc/desopkg/keys").map(|b| pkgfmt::parse_keys(&b)) {
        Ok(Ok(k)) => k,
        Ok(Err(r)) => {
            println!("pkgtest: FAIL /etc/desopkg/keys refused: {}", r);
            return 1;
        }
        Err(e) => {
            println!("pkgtest: FAIL {}", e);
            return 1;
        }
    };
    let repo = match read_file("/etc/desopkg/repo").map(|b| pkgfmt::parse_repo_config(&b)) {
        Ok(Ok(r)) => r,
        Ok(Err(r)) => {
            println!("pkgtest: FAIL /etc/desopkg/repo refused: {}", r);
            return 1;
        }
        Err(e) => {
            println!("pkgtest: FAIL {}", e);
            return 1;
        }
    };
    let ids: Vec<&str> = keys.iter().map(|k| k.keyid.as_str()).collect();
    println!("pkgtest etc: {} keys ({}), repo {} {}/{}/{}", keys.len(), ids.join(","), repo.url, repo.repo, repo.channel, repo.arch);
    0
}

fn elf_all() -> i32 {
    let mut n = 0;
    for name in dir_files("/bin") {
        let path = format!("/bin/{}", name);
        let b = match read_file(&path) {
            Ok(b) => b,
            Err(e) => {
                println!("pkgtest: FAIL {}", e);
                return 1;
            }
        };
        match elf::check_program_bytes(&b, pkgfmt::SYSTEM_ABI) {
            Ok((_, abi)) if abi == pkgfmt::SYSTEM_ABI => n += 1,
            Ok((_, abi)) => {
                println!("pkgtest: FAIL {}: ABI {}.{}", path, abi.0, abi.1);
                return 1;
            }
            Err(e) => {
                println!("pkgtest: FAIL {}: {}", path, e.as_str());
                return 1;
            }
        }
    }
    println!("pkgtest elf: {} programs accepted, ABI {}.{}", n, pkgfmt::SYSTEM_ABI.0, pkgfmt::SYSTEM_ABI.1);
    if n == 0 { 1 } else { 0 }
}

fn main(args: deso::Args) -> i32 {
    let a: Vec<&str> = args.iter().collect();
    match a.as_slice() {
        [_, "vectors", path] => vectors(path),
        [_, "etc"] => etc(),
        [_, "elf"] => elf_all(),
        [_, "b1-notime"] => b1::notime(),
        [_, m] if m.starts_with("b1:") => b1::main(&m[3..]),
        [_, m] if m.starts_with("b2:") => b1::b2_main(&m[3..]),
        [_, m] if m.starts_with("pc:") => b1::power_check(&m[3..]),
        [_, m] if m.starts_with("ph:") => b1::power_hang(&m[3..]),
        [_, "m"] => b1::mutants(),
        _ => {
            eprintln!("usage: pkgtest vectors <file> | etc | elf | b1-notime | b1:s1 .. b1:s8 | b2:<segment> | pc:<n> | ph:<n> | m");
            1
        }
    }
}

/// PKG TEST part 1.
mod b1 {
    use super::*;
    use alloc::string::ToString;
    use deso::{O_CREATE, O_TRUNC, O_WRITE, SVC, chan_recv, chan_send, sleep_ms, spawn_ex, svc_connect, uptime_ms, wait, write, RecvInfo};

    const IN: &str = "/tmp/pt-in";
    const OUT: &str = "/tmp/pt-out";
    static mut CHECKS: u32 = 0;

    macro_rules! check {
        ($cond:expr, $($msg:tt)*) => {
            if !$cond {
                println!("pkgtest: FAIL {}", format!($($msg)*));
                return Err(());
            }
            unsafe { CHECKS += 1 };
        };
    }

    fn put(path: &str, data: &[u8]) -> bool {
        let fd = deso::open(path, O_WRITE | O_CREATE | O_TRUNC);
        if fd < 0 {
            return false;
        }
        let ok = data.is_empty() || write(fd as u64, data) == data.len() as i64;
        close(fd as u64);
        ok
    }

    /// netd's answer to an administration request (dns, status).
    fn ask(req: &str) -> String {
        let Ok(c) = svc_connect("net0") else { return String::new() };
        let mut buf = vec![0u8; 4096];
        let mut info = RecvInfo::default();
        let r = if chan_send(c, req.as_bytes(), 0) == 0 { chan_recv(c, &mut buf, 0, &mut info) } else { -1 };
        close(c);
        if r < 0 { String::new() } else { String::from_utf8_lossy(&buf[..r as usize]).into_owned() }
    }

    /// netd has 8 TCP connections and closing ones wait 2 s: room for a whole command.
    fn tcp_room() {
        let t = uptime_ms();
        loop {
            let st = ask("status");
            let n: u32 = st.lines().find(|l| l.starts_with("netd-status")).and_then(|l| l.split_whitespace().find_map(|w| w.strip_prefix("tcp="))).and_then(|v| v.parse().ok()).unwrap_or(0);
            if n <= 2 || uptime_ms() - t > 10_000 {
                return;
            }
            sleep_ms(100);
        }
    }

    const ERR: &str = "/tmp/pt-err";
    const TRACE: &str = "/tmp/desopkg-trace";

    /// A program with `input` on stdin, stdout and stderr into separate files: (exit code,
    /// stdout followed by stderr).
    fn run(path: &str, args: &[&str], input: &str) -> (u64, String) {
        if !put(IN, input.as_bytes()) || !put(OUT, b"") || !put(ERR, b"") {
            return (997, String::from("cannot write /tmp"));
        }
        let fin = deso::open(IN, deso::O_READ);
        let fout = deso::open(OUT, O_WRITE);
        let ferr = deso::open(ERR, O_WRITE);
        if fin < 0 || fout < 0 || ferr < 0 {
            return (996, String::from("cannot open /tmp files"));
        }
        let pid = spawn_ex(path, args, &[(fin as u64, 0), (fout as u64, 1), (ferr as u64, 2), (SVC, SVC)], 0);
        close(fin as u64);
        close(fout as u64);
        close(ferr as u64);
        if pid <= 0 {
            return (999, format!("spawn {}: {}", path, deso::strerror(pid)));
        }
        let code = wait(pid as u64, 0).map(|(_, c)| c).unwrap_or(998);
        let out = read_file(OUT).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
        let err = read_file(ERR).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
        (code, format!("{}{}", out, err))
    }

    /// desopkg; a non-zero exit adds the self-test build's step trace (/tmp/desopkg-trace).
    fn desopkg(args: &[&str], input: &str) -> (u64, String) {
        tcp_room();
        let mut a = vec!["desopkg"];
        a.extend_from_slice(args);
        let _ = deso::unlink(TRACE);
        let (code, mut out) = run("/bin/desopkg", &a, input);
        if code != 0 {
            let t = read_file(TRACE).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
            out.push_str(&format!("\n[out {} B, trace: {}]", out.len(), t.trim().replace('\n', " > ")));
        }
        (code, out)
    }

    /// The output on one line (the kernel's test collects whole FAIL lines), the end kept – where
    /// the error message is.
    fn short(s: &str) -> String {
        let t: String = s.trim().replace('\n', " | ");
        if t.len() <= 900 {
            return t;
        }
        let mut start = t.len() - 900;
        while !t.is_char_boundary(start) {
            start += 1;
        }
        format!("...{}", &t[start..])
    }

    fn control(path: &str) -> String {
        tcp_room();
        let url = format!("http://tls.deso:58481{}", path);
        let (code, _) = run("/bin/netget", &["netget", "-o", "/tmp/pt-ctl", &url], "");
        if code != 0 {
            return String::new();
        }
        read_file("/tmp/pt-ctl").map(|b| String::from_utf8_lossy(&b).trim().to_string()).unwrap_or_default()
    }

    fn scenario(name: &str) -> Result<(), ()> {
        let r = control(&format!("/scenario?name={}", name));
        check!(r == format!("ok {}", name), "repo-stub scenario {}: {:?}", name, r);
        Ok(())
    }

    /// The current generation's number from `desopkg list` (0 – none).
    fn generation() -> u64 {
        let (_, out) = desopkg(&["list"], "");
        out.lines().find_map(|l| l.strip_prefix("generation ")).and_then(|n| n.trim().parse().ok()).unwrap_or(0)
    }

    /// The one version directory of `pkg` currently in use (from `desopkg info`).
    fn vdir(pkg: &str) -> String {
        let (_, out) = desopkg(&["info", pkg], "");
        out.lines().find_map(|l| l.strip_prefix("installed  ")).and_then(|l| l.split_once(", ").map(|(_, r)| r.trim_end_matches(')').to_string())).unwrap_or_default()
    }

    /// Entries of a directory (files and directories).
    fn files_in(dir: &str) -> usize {
        entries(dir).len()
    }

    fn entries(dir: &str) -> Vec<String> {
        let mut buf = vec![0u8; 8192];
        let n = deso::readdir(dir, &mut buf);
        if n < 0 {
            return Vec::new();
        }
        core::str::from_utf8(&buf[..n as usize]).unwrap_or("").lines().filter_map(|l| l.splitn(3, '\t').nth(2).map(String::from)).collect()
    }

    fn net_ready() -> Result<(), ()> {
        let t = uptime_ms();
        while !ask("status").lines().any(|l| l.starts_with("netd-status") && l.split_whitespace().any(|w| w == "dhcp=bound")) {
            check!(uptime_ms() - t < 15_000, "net0 has no DHCP address after 15 s");
            sleep_ms(50);
        }
        let r = ask("dns 10.0.2.2:53530");
        check!(r.starts_with("DNS server 10.0.2.2:53530"), "dns set: {:?}", r.trim());
        Ok(())
    }

    pub fn notime() -> i32 {
        let r = (|| -> Result<(), ()> {
            net_ready()?;
            scenario("v100")?;
            check!(control("/reset") == "ok reset", "repo-stub reset");
            let (code, out) = desopkg(&["refresh"], "");
            check!(code == 3 && out.contains("not set by the time service"), "refresh without the time service's time: {} {}", code, short(&out));
            let h = control("/hits");
            check!(h == "index=0 sig=0 pkg=0", "repo-stub was contacted: {}", h);
            Ok(())
        })();
        match r {
            Ok(()) => {
                println!("pkgtest b1-notime: refused before connecting (exit 3, repo-stub saw nothing) OK");
                0
            }
            Err(()) => 1,
        }
    }

    /// The highest generation file number (valid or not).
    fn top_generation() -> u64 {
        entries("/disk/pkg/gen").iter().filter_map(|n| n.parse::<u64>().ok()).max().unwrap_or(0)
    }

    /// The shell checks between segments are the kernel's (kernel/user/test_pkgb.rs): only a
    /// process the kernel starts can feed the shell's keyboard input.
    fn segment(seg: &str) -> Result<String, ()> {
        net_ready()?;
        match seg {
            // 1. An empty system, the first index, install with a dependency.
            "s1" => {
                scenario("v100")?;
                let (code, out) = desopkg(&["list"], "");
                check!(code == 0 && out.contains("no packages installed"), "list on an empty system: {} {}", code, short(&out));
                let (code, out) = desopkg(&["refresh"], "");
                check!(code == 0 && out.contains("index serial 10 accepted"), "refresh v100: {} {}", code, short(&out));
                let (code, out) = desopkg(&["refresh"], "");
                check!(code == 0 && out.contains("index serial 10 is up to date"), "refresh again: {} {}", code, short(&out));
                let (code, out) = desopkg(&["-y", "install", "witaj"], "");
                check!(code == 0 && out.contains("install    witaj 1.0.0") && out.contains("install    fonts 1.0.0 (dependency)") && out.contains("generation 1 is now current"), "install witaj: {} {}", code, short(&out));
            }
            // 2. list, search, info; a newer index; update everything in one generation.
            "s2" => {
                let (code, out) = desopkg(&["list"], "");
                check!(code == 0 && out.lines().any(|l| l.starts_with("witaj") && l.contains("1.0.0") && l.contains("explicit")) && out.lines().any(|l| l.starts_with("fonts") && l.contains("dependency")) && out.contains("generation 1"), "list: {}", short(&out));
                let (code, out) = desopkg(&["search", "greet"], "");
                check!(code == 0 && out.contains("witaj") && !out.contains("fonts"), "search: {} {}", code, short(&out));
                let (code, out) = desopkg(&["info", "witaj"], "");
                check!(code == 0 && out.contains("installed  1.0.0 (explicit, /disk/pkg/witaj/1.0.0-") && out.contains("depends    fonts>=1.0.0"), "info: {} {}", code, short(&out));
                scenario("v101")?;
                let (code, out) = desopkg(&["refresh"], "");
                check!(code == 0 && out.contains("index serial 11 accepted"), "refresh v101: {} {}", code, short(&out));
                let (_, out) = desopkg(&["list"], "");
                check!(out.lines().any(|l| l.starts_with("witaj") && l.contains("1.0.0 -> 1.1.0")) && out.lines().any(|l| l.starts_with("fonts") && l.contains("1.0.0 -> 1.1.0")), "list with newer versions: {}", short(&out));
                let (code, out) = desopkg(&["update"], "n\n");
                check!(code == 5 && out.contains("aborted") && generation() == 1, "update answered n: {} {}", code, short(&out));
                let (code, out) = desopkg(&["-y", "update"], "");
                check!(code == 0 && out.contains("upgrade    witaj 1.0.0 -> 1.1.0") && out.contains("upgrade    fonts 1.0.0 -> 1.1.0") && out.contains("generation 2 is now current"), "update: {} {}", code, short(&out));
            }
            // 3. Nothing newer; a downgrade on request (a warning and y/N).
            "s3" => {
                let (code, out) = desopkg(&["-y", "update"], "");
                check!(code == 0 && out.contains("nothing to update") && generation() == 2, "update with nothing newer: {} {}", code, short(&out));
                let (code, out) = desopkg(&["install", "witaj=1.0.1"], "\n");
                check!(code == 5 && out.contains("downgrade  witaj 1.1.0 -> 1.0.1") && out.contains("warning: downgrade") && generation() == 2, "downgrade without y: {} {}", code, short(&out));
                let (code, out) = desopkg(&["-y", "install", "witaj=1.0.1"], "");
                check!(code == 0 && out.contains("generation 3 is now current"), "downgrade: {} {}", code, short(&out));
            }
            // 4. Dependencies never lowered; refusals; remove.
            "s4" => {
                let (_, out) = desopkg(&["list"], "");
                check!(out.lines().any(|l| l.starts_with("fonts") && l.contains("1.1.0")), "fonts kept at 1.1.0: {}", short(&out));
                let (code, out) = desopkg(&["-y", "update", "witaj"], "");
                check!(code == 0 && out.contains("upgrade    witaj 1.0.1 -> 1.1.0") && !out.contains("fonts") && out.contains("generation 4 is now current"), "update witaj: {} {}", code, short(&out));
                let (code, out) = desopkg(&["-y", "install", "edytor"], "");
                check!(code == 0 && out.contains("generation 5 is now current"), "install edytor: {} {}", code, short(&out));
                let (code, out) = desopkg(&["-y", "install", "witaj=1.0.1"], "");
                check!(code == 2 && out.contains("would break edytor") && generation() == 5, "downgrade breaking edytor: {} {}", code, short(&out));
                let (code, out) = desopkg(&["-y", "install", "witaj=9.9.9"], "");
                check!(code == 2 && out.contains("not in the repository"), "install witaj=9.9.9: {} {}", code, short(&out));
                let (code, out) = desopkg(&["-y", "remove", "fonts"], "");
                check!(code == 2 && out.contains("needed by"), "remove fonts: {} {}", code, short(&out));
                let (code, out) = desopkg(&["-y", "install", "oldwitaj"], "");
                check!(code == 2 && out.contains("conflicts with"), "install oldwitaj: {} {}", code, short(&out));
                let (code, out) = desopkg(&["-y", "install", "ls"], "");
                check!(code == 2 && out.contains("reserved_name") && deso::stat("/disk/pkg/ls").is_err() && generation() == 5, "install ls: {} {}", code, short(&out));
                let (code, out) = desopkg(&["install"], "");
                check!(code == 1 && out.contains("usage"), "install without a name: {} {}", code, short(&out));
                let (code, out) = desopkg(&["-y", "remove", "edytor"], "");
                check!(code == 0 && out.contains("generation 6 is now current"), "remove edytor: {} {}", code, short(&out));
                let (code, out) = desopkg(&["-y", "remove", "witaj"], "");
                check!(code == 0 && out.contains("no longer needed: fonts") && out.contains("generation 7 is now current"), "remove witaj: {} {}", code, short(&out));
            }
            // 5. verify: MODIFIED, MISSING, UNEXPECTED, SHADOWED (a copy in /disk/bin).
            "s5" => {
                let (code, out) = desopkg(&["-y", "install", "witaj"], "");
                check!(code == 0 && out.contains("generation 8 is now current"), "install witaj again: {} {}", code, short(&out));
                let (code, out) = desopkg(&["verify"], "");
                check!(code == 0 && out.contains("OK - "), "verify: {} {}", code, short(&out));
                let w = vdir("witaj");
                check!(w.starts_with("/disk/pkg/witaj/1.1.0-"), "witaj's directory: {:?}", w);
                let hello = format!("{}/share/witaj/hello.txt", w);
                check!(put(&hello, b"changed\n"), "change {}", hello);
                let (code, out) = desopkg(&["verify"], "");
                check!(code == 2 && out.contains("MODIFIED") && out.contains("hello.txt"), "verify a changed file: {} {}", code, short(&out));
                check!(deso::unlink(&hello) >= 0, "remove {}", hello);
                let (code, out) = desopkg(&["verify", "witaj"], "");
                check!(code == 2 && out.contains("MISSING"), "verify a missing file: {} {}", code, short(&out));
                check!(put(&format!("{}/share/witaj/extra.txt", w), b"x\n"), "extra file");
                let (code, out) = desopkg(&["verify"], "");
                check!(code == 2 && out.contains("UNEXPECTED") && out.contains("extra.txt"), "verify an extra file: {} {}", code, short(&out));
                let _ = deso::mkdir("/disk/bin");
                let hello_bin = read_file("/bin/hello").unwrap_or_default();
                check!(put("/disk/bin/witaj", &hello_bin), "copy to /disk/bin/witaj");
                let (code, out) = desopkg(&["verify"], "");
                check!(code == 2 && out.contains("SHADOWED"), "verify a shadowed program: {} {}", code, short(&out));
            }
            // 6. reinstall repairs; a damaged package file: the previous generation is in force.
            "s6" => {
                check!(deso::unlink("/disk/bin/witaj") >= 0, "remove /disk/bin/witaj");
                let g = generation();
                let (code, out) = desopkg(&["-y", "reinstall", "witaj"], "");
                check!(code == 0 && out.contains("reinstall  witaj 1.1.0") && generation() == g + 1, "reinstall: {} {}", code, short(&out));
                let (code, out) = desopkg(&["verify"], "");
                check!(code == 0 && out.contains("OK - "), "verify after reinstall: {} {}", code, short(&out));
                let g = generation();
                let w = vdir("witaj");
                let mut m = read_file(&format!("{}/package", w)).unwrap_or_default();
                m.push(b'\n');
                check!(put(&format!("{}/package", w), &m), "damage the package file");
                let (code, out) = desopkg(&["verify"], "");
                check!(code == 2 && out.contains("DAMAGED") && generation() == g - 1, "verify a damaged package file: {} {} (generation {})", code, short(&out), generation());
            }
            // 7. Repaired; refused indexes and transfers change nothing; a good transfer.
            "s7" => {
                let top = top_generation();
                let (code, out) = desopkg(&["-y", "reinstall", "witaj"], "");
                let (code2, out2) = desopkg(&["verify"], "");
                check!(code == 0 && code2 == 0 && generation() == top + 1, "repaired by reinstall: {} {} {} {}", code, code2, short(&out), short(&out2));
                let before = files_in("/disk/pkg/index");
                for (sc, why) in [("old", "older than the accepted"), ("expired", "expired"), ("future", "in the future"), ("badsig", "signature"), ("otherkey", "signature"), ("testing", "this system uses")] {
                    scenario(sc)?;
                    let (code, out) = desopkg(&["refresh"], "");
                    check!(code == 2 && out.contains(why), "refresh {}: {} {}", sc, code, short(&out));
                    check!(files_in("/disk/pkg/index") == before, "{}: index files changed", sc);
                }
                scenario("tx")?;
                let (code, out) = desopkg(&["refresh"], "");
                check!(code == 0 && out.contains("index serial 20 accepted"), "refresh tx: {} {}", code, short(&out));
                let g = generation();
                let dirs = files_in("/disk/pkg/witaj");
                for (ver, want, why) in [("1.1.2", 2, "pkg_sha_mismatch"), ("1.1.3", 3, "Content-Length"), ("1.1.4", 3, "Content-Length")] {
                    let (code, out) = desopkg(&["-y", "install", &format!("witaj={}", ver)], "");
                    check!(code == want && out.contains(why), "install witaj={}: {} {}", ver, code, short(&out));
                }
                for (sc, why) in [("long", "malformed"), ("short", "incomplete"), ("badlen", "Content-Length"), ("redirect", "HTTP 302")] {
                    scenario(sc)?;
                    let (code, out) = desopkg(&["-y", "install", "witaj=1.1.1"], "");
                    check!(code == 3 && out.contains(why), "transfer {}: {} {}", sc, code, short(&out));
                }
                check!(generation() == g && files_in("/disk/pkg/witaj") == dirs, "refused transfers changed the disk");
                scenario("tx")?;
                let (code, out) = desopkg(&["-y", "install", "witaj=1.1.1"], "");
                check!(code == 0 && out.contains("upgrade    witaj 1.1.0 -> 1.1.1"), "install witaj=1.1.1: {} {}", code, short(&out));
            }
            // 8. No memory for a package; a big package.
            "s8" => {
                check!(put("/tmp/desopkg-nomem", b""), "nomem switch");
                let g = generation();
                let (code, out) = desopkg(&["-y", "install", "edytor"], "");
                let _ = deso::unlink("/tmp/desopkg-nomem");
                check!(code == 4 && out.contains("not enough memory") && generation() == g && deso::stat("/tmp/desopkg.lock").is_err(), "no memory: {} {}", code, short(&out));
                scenario("big")?;
                let (code, out) = desopkg(&["refresh"], "");
                check!(code == 0 && out.contains("index serial 40 accepted"), "refresh big: {} {}", code, short(&out));
                let tb = uptime_ms();
                let (code, out) = desopkg(&["-y", "install", "big"], "");
                let big_ms = uptime_ms() - tb;
                check!(code == 0 && out.contains("is now current"), "install big: {} {}", code, short(&out));
                let (code, out) = desopkg(&["verify", "big"], "");
                check!(code == 0 && out.contains("OK - 1 files"), "verify big: {} {}", code, short(&out));
                let (code, out) = desopkg(&["-y", "remove", "big"], "");
                check!(code == 0, "remove big: {} {}", code, short(&out));
                let g = generation();
                println!("pkgtest result: generation={} big_ms={}", g, big_ms);
                return Ok(format!("generation {}, a 30 MiB package installed in {} ms", g, big_ms));
            }
            _ => {
                println!("pkgtest: FAIL unknown segment {}", seg);
                return Err(());
            }
        }
        Ok(format!("generation {}", generation()))
    }

    pub fn main(seg: &str) -> i32 {
        let t0 = uptime_ms();
        match segment(seg) {
            Ok(summary) => {
                println!("pkgtest b1 {}: {} checks OK ({}, {} ms)", seg, unsafe { CHECKS }, summary, uptime_ms() - t0);
                0
            }
            Err(()) => 1,
        }
    }
    // ============================================================== part 2

    const LOCK: &str = "/tmp/desopkg.lock";
    const CRASH: &str = "/tmp/desopkg-crash";
    const WITAJ: &str = "/disk/pkg/witaj";

    fn crash(at: &str) -> bool {
        put(CRASH, at.as_bytes())
    }

    fn no_crash() {
        let _ = deso::unlink(CRASH);
    }

    fn locked() -> bool {
        deso::stat(LOCK).is_ok()
    }

    fn sys_name(n: &str) -> bool {
        super::system_name(n)
    }

    /// The current generation straight from the disk (no desopkg, no lock).
    fn gen_now() -> u64 {
        pkgstate::generations(&sys_name).current.map(|c| c.number).unwrap_or(0)
    }

    /// The installed version of a package in the current generation ("" – none).
    fn version_of(pkg: &str) -> String {
        pkgstate::generations(&sys_name).current.and_then(|c| c.generation.packages.iter().find(|p| p.name == pkg).map(|p| p.version.to_string())).unwrap_or_default()
    }

    /// The version directory of a package in the current generation.
    fn dir_of(pkg: &str) -> String {
        pkgstate::generations(&sys_name).current.and_then(|c| c.generation.packages.iter().find(|p| p.name == pkg).map(|p| pkgstate::version_dir(&p.name, &p.dir))).unwrap_or_default()
    }

    fn keys() -> Vec<pkgfmt::Key> {
        read_file("/etc/desopkg/keys").ok().and_then(|b| pkgfmt::parse_keys(&b).ok()).unwrap_or_default()
    }

    /// The serial of the accepted index in force (0 – none).
    fn accepted_serial() -> u64 {
        pkgstate::accepted(&keys()).0.first().map(|a| a.serial).unwrap_or(0)
    }

    /// desopkg stopped at `point` as if killed: exit 99, the lock left behind.
    fn killed_at(point: &str, args: &[&str]) -> Result<(), ()> {
        check!(crash(point), "write {}", CRASH);
        let (code, out) = desopkg(args, "");
        no_crash();
        check!(code == 99, "{}: desopkg {:?} was not stopped there: {} {}", point, args, code, short(&out));
        check!(locked(), "{}: the killed desopkg's lock must stay", point);
        Ok(())
    }

    /// A program in the background: stdout and stderr into /tmp/pt-out-<tag> / /tmp/pt-err-<tag>.
    fn start(args: &[&str], tag: &str) -> i64 {
        let (o, e) = (format!("/tmp/pt-out-{}", tag), format!("/tmp/pt-err-{}", tag));
        if !put(IN, b"") || !put(&o, b"") || !put(&e, b"") {
            return -1;
        }
        let fin = deso::open(IN, deso::O_READ);
        let fout = deso::open(&o, O_WRITE);
        let ferr = deso::open(&e, O_WRITE);
        if fin < 0 || fout < 0 || ferr < 0 {
            return -1;
        }
        let mut a = vec!["desopkg"];
        a.extend_from_slice(args);
        let pid = spawn_ex("/bin/desopkg", &a, &[(fin as u64, 0), (fout as u64, 1), (ferr as u64, 2), (SVC, SVC)], 0);
        close(fin as u64);
        close(fout as u64);
        close(ferr as u64);
        pid
    }

    fn err_of(tag: &str) -> String {
        read_file(&format!("/tmp/pt-err-{}", tag)).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default()
    }

    /// Waits until the background desopkg `tag` says "HANG <point>".
    fn hung(tag: &str, point: &str, ms: u64) -> bool {
        let want = format!("desopkg: HANG {}", point);
        let t = uptime_ms();
        while uptime_ms() - t < ms {
            if err_of(tag).contains(&want) {
                return true;
            }
            sleep_ms(50);
        }
        false
    }

    fn sweep_by_refresh(what: &str) -> Result<(), ()> {
        let (code, out) = desopkg(&["refresh"], "");
        check!(code == 0, "{}: refresh (which sweeps first): {} {}", what, code, short(&out));
        Ok(())
    }

    /// A generation file written by hand (the rules of what counts, not desopkg's writing).
    fn put_generation(n: u64, bytes: &[u8]) -> Result<(), ()> {
        let path = format!("{}/{}", pkgstate::GEN_DIR, n);
        let _ = deso::unlink(&path);
        check!(put(&path, bytes), "write {}", path);
        Ok(())
    }

    /// Generation `n` with its packages, then "op=update" changed to "op=remove" after the hash
    /// was made: every line valid, only the hash wrong (empty – no op line found).
    fn wrong_hash(packages: &[pkgfmt::GenEntry], n: u64) -> Vec<u8> {
        let mut b = pkgfmt::make_generation(n, "update", packages);
        match b.windows(10).position(|x| x == b"op=update\n") {
            Some(at) => {
                b[at + 3..at + 9].copy_from_slice(b"remove");
                b
            }
            None => Vec::new(),
        }
    }

    fn b2_segment(seg: &str) -> Result<String, ()> {
        net_ready()?;
        let inst = |v: &str| -> String { format!("witaj={}", v) };
        match seg {
            // 11. The crash points of refresh (K2 before the index file, K2h in the middle of it,
            //     K3 after it) and K1 (right after taking the lock).
            "k1" => {
                scenario("s50")?;
                let a0 = accepted_serial();
                killed_at("K2", &["refresh"])?;
                check!(accepted_serial() == a0 && deso::stat("/disk/pkg/index/50").is_err(), "K2: nothing may change (accepted {}, before {})", accepted_serial(), a0);
                let (code, out) = desopkg(&["refresh"], "");
                check!(code == 0 && out.contains("index serial 50 accepted") && !locked(), "after K2 the next refresh takes the dead one's lock: {} {}", code, short(&out));
                scenario("s51")?;
                killed_at("K2h", &["refresh"])?;
                check!(deso::stat("/disk/pkg/index/51").is_ok() && accepted_serial() == 50, "K2h: a half-written index/51 must not count (accepted {})", accepted_serial());
                let (code, out) = desopkg(&["refresh"], "");
                check!(code == 0 && out.contains("index serial 51 accepted"), "after K2h: {} {}", code, short(&out));
                scenario("s52")?;
                killed_at("K3", &["refresh"])?;
                check!(accepted_serial() == 52, "K3: the whole index/52 is valid by its signature and counts (accepted {})", accepted_serial());
                let (code, out) = desopkg(&["refresh"], "");
                check!(code == 0 && out.contains("index serial 52 is up to date"), "after K3: {} {}", code, short(&out));
                let g = gen_now();
                killed_at("K1", &["-y", "install", &inst("1.1.0")])?;
                check!(gen_now() == g, "K1 changed the generation");
                let (code, out) = desopkg(&["list"], "");
                check!(code == 0 && !locked(), "list after K1 (the dead one's lock taken over): {} {}", code, short(&out));
            }
            // 11. The crash points of a change before its generation: nothing changes in force,
            //     the next command sweeps what was left.
            "k2" => {
                let g = gen_now();
                let top = top_generation();
                let before = entries(WITAJ);
                let d0 = before.len();
                for point in ["K4", "K5"] {
                    killed_at(point, &["-y", "install", &inst("1.1.0")])?;
                    check!(gen_now() == g && top_generation() == top && files_in(WITAJ) == d0, "{} changed the disk (generation {} top {} dirs {})", point, gen_now(), top_generation(), files_in(WITAJ));
                }
                killed_at("K6", &["-y", "install", &inst("1.1.0")])?;
                let new: Vec<String> = entries(WITAJ).into_iter().filter(|d| !before.contains(d)).collect();
                check!(gen_now() == g && top_generation() == top && new.len() == 1, "K6: generation {} top {} new dirs {:?}", gen_now(), top_generation(), new);
                check!(deso::stat(&format!("{}/{}/package", WITAJ, new[0])).is_err(), "K6: the unfinished directory has no package file");
                sweep_by_refresh("after K6")?;
                check!(files_in(WITAJ) == d0, "after K6 gc left {} dirs (want {})", files_in(WITAJ), d0);
                killed_at("K7", &["-y", "install", &inst("1.1.0")])?;
                let new: Vec<String> = entries(WITAJ).into_iter().filter(|d| !before.contains(d)).collect();
                check!(gen_now() == g && top_generation() == top && new.len() == 1 && deso::stat(&format!("{}/{}/package", WITAJ, new[0])).is_ok(), "K7: a complete directory no generation points to: generation {} top {} new {:?}", gen_now(), top_generation(), new);
                sweep_by_refresh("after K7")?;
                check!(files_in(WITAJ) == d0, "after K7 gc left {} dirs (want {})", files_in(WITAJ), d0);
                killed_at("K7h", &["-y", "install", &inst("1.1.0")])?;
                check!(gen_now() == g && top_generation() == top + 1 && files_in(WITAJ) == d0 + 1, "K7h: a half-written gen/{} must not count: generation {} top {} dirs {}", top + 1, gen_now(), top_generation(), files_in(WITAJ));
                sweep_by_refresh("after K7h")?;
                check!(files_in(WITAJ) == d0 && top_generation() == top + 1, "after K7h: dirs {} top {} (the highest file stays until a newer one)", files_in(WITAJ), top_generation());
                let (code, out) = desopkg(&["-y", "install", &inst("1.1.0")], "");
                check!(code == 0 && out.contains(&format!("generation {} is now current", top + 2)) && deso::stat(&format!("{}/{}", pkgstate::GEN_DIR, top + 1)).is_err(), "install after K7h: {} {}", code, short(&out));
            }
            // 11. K8 – after the generation, before gc: the new one is in force whole.
            "k3" => {
                let g = gen_now();
                killed_at("K8", &["-y", "install", &inst("1.0.1")])?;
                check!(gen_now() > g && gen_now() == top_generation() && version_of("witaj") == "1.0.1", "K8: generation {} (before {}), witaj {}", gen_now(), g, version_of("witaj"));
                sweep_by_refresh("after K8")?;
                check!(files_in(WITAJ) <= 2, "after K8 gc left {} witaj dirs", files_in(WITAJ));
            }
            // 11. K9 – inside gc, after the generation files, before the directories.
            "k4" => {
                let g = gen_now();
                let d0 = files_in(WITAJ);
                killed_at("K9", &["-y", "install", &inst("1.1.1")])?;
                check!(gen_now() > g && version_of("witaj") == "1.1.1" && files_in(pkgstate::GEN_DIR) == 2 && files_in(WITAJ) == d0 + 1, "K9: generation {} witaj {} gen files {} dirs {} (before {})", gen_now(), version_of("witaj"), files_in(pkgstate::GEN_DIR), files_in(WITAJ), d0);
                sweep_by_refresh("after K9")?;
                check!(files_in(WITAJ) == 2, "after K9 gc left {} witaj dirs", files_in(WITAJ));
            }
            // 11. K10 – everything done, the lock not given back.
            "k5" => {
                let g = gen_now();
                killed_at("K10", &["-y", "install", &inst("1.1.0")])?;
                check!(gen_now() > g && version_of("witaj") == "1.1.0", "K10: generation {} witaj {}", gen_now(), version_of("witaj"));
                let (code, out) = desopkg(&["list"], "");
                check!(code == 0 && !locked(), "list after K10: {} {}", code, short(&out));
            }
            // 13. The lock.
            "k6" => {
                // A living holder (stopped at K5): another desopkg refuses with code 4.
                check!(crash("K5:hang"), "write {}", CRASH);
                let pid = start(&["-y", "install", &inst("1.0.1")], "h");
                check!(pid > 0, "start the holder: {}", deso::strerror(pid));
                let got = hung("h", "K5", 120_000);
                no_crash();
                check!(got, "the holder never reached K5: {}", short(&err_of("h")));
                let (code, out) = desopkg(&["list"], "");
                check!(code == 4 && out.contains("another desopkg is running") && locked(), "a second desopkg beside a living one: {} {}", code, short(&out));
                check!(deso::kill(pid as u64) >= 0, "kill the holder");
                let _ = wait(pid as u64, 0);
                check!(locked(), "the killed holder's lock stays");
                let (code, out) = desopkg(&["list"], "");
                check!(code == 0 && !locked(), "the dead holder's lock taken over: {} {}", code, short(&out));
                // Two new ones at once beside a stale lock: never both inside (the one inside
                // stops at K1); the other refuses and does not remove the lock.
                let mut both_refused = 0;
                for round in 0..3 {
                    let r = deso::mkdir(LOCK);
                    check!(r >= 0, "make a stale lock: {}", deso::strerror(r));
                    check!(crash("K1:hang"), "write {}", CRASH);
                    let a = start(&["list"], "a");
                    let b = start(&["list"], "b");
                    check!(a > 0 && b > 0, "start two");
                    let mut code = [None, None];
                    let t = uptime_ms();
                    while uptime_ms() - t < 20_000 {
                        for (i, pid) in [a, b].iter().enumerate() {
                            if code[i].is_none() {
                                if let Ok((p, c)) = wait(*pid as u64, deso::WNOHANG) {
                                    if p != 0 {
                                        code[i] = Some(c);
                                    }
                                }
                            }
                        }
                        let inside = [err_of("a").contains("HANG K1"), err_of("b").contains("HANG K1")];
                        let done = (0..2).all(|i| code[i].is_some() || inside[i]);
                        if done && uptime_ms() - t > 2_000 {
                            break;
                        }
                        sleep_ms(50);
                    }
                    no_crash();
                    let inside = [err_of("a").contains("HANG K1"), err_of("b").contains("HANG K1")];
                    check!(!(inside[0] && inside[1]), "round {}: both new desopkg took the lock", round);
                    for i in 0..2 {
                        check!(inside[i] || code[i] == Some(4), "round {}: desopkg {} neither inside nor refused (code {:?}: {})", round, i, code[i], short(&err_of(if i == 0 { "a" } else { "b" })));
                    }
                    check!(locked(), "round {}: the lock was removed", round);
                    for (i, pid) in [a, b].iter().enumerate() {
                        if inside[i] {
                            let _ = deso::kill(*pid as u64);
                            let _ = wait(*pid as u64, 0);
                        }
                    }
                    if !inside[0] && !inside[1] {
                        both_refused += 1;
                    }
                    let (code, out) = desopkg(&["list"], "");
                    check!(code == 0 && !locked(), "round {}: the stale lock taken over afterwards: {} {}", round, code, short(&out));
                }
                return Ok(format!("generation {}, two at once: {} of 3 rounds both refused", generation(), both_refused));
            }
            // 15. A damaged newest index: the previous valid one; generations that must not count.
            "k7" => {
                let k = keys();
                let good: Vec<u64> = pkgstate::accepted(&k).0.iter().map(|a| a.serial).collect();
                check!(good.len() == 2, "two accepted indexes expected: {:?}", good);
                let newest = format!("{}/{}", pkgstate::INDEX_DIR, good[0]);
                let mut b = read_file(&newest).unwrap_or_default();
                b.push(b'x');
                check!(put(&newest, &b), "damage {}", newest);
                check!(accepted_serial() == good[1], "a damaged index/{} must give way to index/{} (got {})", good[0], good[1], accepted_serial());
                let (code, out) = desopkg(&["info", "witaj"], "");
                check!(code == 0 && out.contains("available"), "info with the previous index: {} {}", code, short(&out));
                scenario(&format!("s{}", good[0]))?;
                let (code, out) = desopkg(&["refresh"], "");
                check!(code == 0 && out.contains(&format!("index serial {} accepted", good[0])), "refresh replaces the damaged file: {} {}", code, short(&out));
                let cur = pkgstate::generations(&sys_name).current;
                check!(cur.is_some(), "no current generation");
                let cur = cur.unwrap();
                let m = cur.number;
                let raw = read_file(&format!("{}/{}", pkgstate::GEN_DIR, m)).unwrap_or_default();
                let w = cur.generation.packages.iter().position(|p| p.name == "witaj");
                check!(w.is_some(), "witaj not in generation {}", m);
                let w = w.unwrap();
                // a. a copy: `generation=` is not its name
                put_generation(m + 1, &raw)?;
                check!(gen_now() == m, "a copy of gen/{} as gen/{} must not count", m, m + 1);
                // b. another version
                let mut e = cur.generation.packages.clone();
                e[w].version = pkgfmt::Version::parse("1.0.0").unwrap();
                put_generation(m + 1, &pkgfmt::make_generation(m + 1, "install", &e))?;
                check!(gen_now() == m, "a generation with another version of witaj must not count");
                // c. a program the manifest does not have
                let mut e = cur.generation.packages.clone();
                e[w].programs.push(String::from("inny"));
                put_generation(m + 1, &pkgfmt::make_generation(m + 1, "install", &e))?;
                check!(gen_now() == m, "a generation with a program outside the manifest must not count");
                // d. a byte under the hash changed (a valid op, so only the hash is wrong)
                let bytes = wrong_hash(&cur.generation.packages, m + 1);
                check!(!bytes.is_empty(), "no op= line");
                put_generation(m + 1, &bytes)?;
                check!(gen_now() == m, "a generation with a changed byte (its hash) must not count");
                // e. the same, unchanged: counts (the refusals above are the rules')
                put_generation(m + 1, &pkgfmt::make_generation(m + 1, "install", &cur.generation.packages))?;
                check!(gen_now() == m + 1, "a valid generation written by hand must count (got {})", gen_now());
            }
            // 14. The shell paused before exec (kernel/user/test_pkgb.rs drives it).
            "pa" => {
                check!(version_of("witaj") == "1.1.0", "witaj 1.1.0 expected, got {:?}", version_of("witaj"));
                let d = dir_of("witaj");
                check!(put("/disk/pt-pause", d.as_bytes()), "write /disk/pt-pause");
                let _ = deso::unlink("/tmp/sh-pause-log");
                let _ = deso::unlink("/tmp/sh-paused");
                check!(put("/tmp/sh-pause", b""), "write /tmp/sh-pause");
                return Ok(format!("the shell will pause before {}", d));
            }
            "pb" => {
                let old = read_file("/disk/pt-pause").map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
                for v in ["1.0.1", "1.1.1"] {
                    let (code, out) = desopkg(&["-y", "install", &inst(v)], "");
                    check!(code == 0, "install witaj={} while the shell waits: {} {}", v, code, short(&out));
                }
                check!(!old.is_empty() && deso::stat(&old).is_err(), "gc must have removed {}", old);
                let _ = deso::unlink("/tmp/sh-pause");
                return Ok(format!("{} removed by gc, witaj {}", old, version_of("witaj")));
            }
            // A bad ELF in a valid generation: the shell reports it at once.
            "pc" => {
                let g = gen_now();
                let prog = format!("{}/bin/witaj", dir_of("witaj"));
                let _ = deso::unlink(&prog);
                check!(put(&prog, b"not an ELF program\n"), "overwrite {}", prog);
                let _ = deso::unlink("/tmp/sh-pause-log");
                let (code, out) = desopkg(&["verify", "witaj"], "");
                check!(code == 2 && out.contains("MODIFIED") && gen_now() == g, "verify the bad program: {} {}", code, short(&out));
                return Ok(format!("{} is not an ELF, generation {} still valid", prog, g));
            }
            "pd" => {
                let (code, out) = desopkg(&["-y", "reinstall", "witaj"], "");
                let (code2, out2) = desopkg(&["verify"], "");
                check!(code == 0 && code2 == 0, "reinstall repairs the program: {} {} {} {}", code, code2, short(&out), short(&out2));
                let _ = deso::unlink("/disk/pt-pause");
            }
            _ => {
                println!("pkgtest: FAIL unknown segment b2:{}", seg);
                return Err(());
            }
        }
        Ok(format!("generation {}, witaj {}", generation(), version_of("witaj")))
    }

    pub fn b2_main(seg: &str) -> i32 {
        let t0 = uptime_ms();
        match b2_segment(seg) {
            Ok(summary) => {
                println!("pkgtest b2 {}: {} checks OK ({}, {} ms)", seg, unsafe { CHECKS }, summary, uptime_ms() - t0);
                0
            }
            Err(()) => {
                no_crash();
                1
            }
        }
    }

    // ------------------------------------------------------------ 12. power loss

    const POWER: &str = "/disk/pt-power";

    /// Numbers kept on /disk across a power loss: generation, top generation file, witaj dirs.
    fn save_power(at: &str) -> Result<(), ()> {
        let s = format!("{} {} {} {}", at, gen_now(), top_generation(), files_in(WITAJ));
        let _ = deso::unlink(POWER);
        check!(put(POWER, s.as_bytes()), "write {}", POWER);
        Ok(())
    }

    fn load_power() -> (String, u64, u64, usize) {
        let s = read_file(POWER).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
        let w: Vec<&str> = s.split_whitespace().collect();
        let n = |i: usize| w.get(i).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
        (String::from(w.first().copied().unwrap_or("")), n(1), n(2), n(3) as usize)
    }

    /// ph:N – desopkg stopped at the N-th power-loss point (hangs there; the kernel then says
    /// POWER OFF and tests/pkg-test.sh kills QEMU).
    pub fn power_hang(n: &str) -> i32 {
        let r = (|| -> Result<String, ()> {
            net_ready()?;
            let (point, args): (&str, Vec<&str>) = match n {
                "1" => {
                    scenario("s53")?;
                    ("K2h", vec!["refresh"])
                }
                "2" => ("K6", vec!["-y", "install", "witaj=1.1.0"]),
                "3" => ("K7h", vec!["-y", "install", "witaj=1.1.0"]),
                "4" => ("K9", vec!["-y", "install", "witaj=1.1.0"]),
                _ => {
                    println!("pkgtest: FAIL unknown power step {}", n);
                    return Err(());
                }
            };
            save_power(point)?;
            check!(crash(&format!("{}:hang", point)), "write {}", CRASH);
            let pid = start(&args, "p");
            check!(pid > 0, "start desopkg: {}", deso::strerror(pid));
            check!(hung("p", point, 300_000), "desopkg never reached {}: {}", point, short(&err_of("p")));
            Ok(String::from(point))
        })();
        match r {
            Ok(point) => {
                println!("pkgtest ph {}: HANG {}", n, point);
                0
            }
            Err(()) => 1,
        }
    }

    /// pc:N – after the start that followed the power loss at step N−1: what the disk holds.
    /// Prints "shell: <text>" – what `witaj` must print now (the kernel runs the shell).
    pub fn power_check(n: &str) -> i32 {
        let r = (|| -> Result<String, ()> {
            net_ready()?;
            check!(!locked() && deso::stat(CRASH).is_err(), "a fresh /tmp expected after the start");
            let (point, g, top, d0) = load_power();
            match (n, point.as_str()) {
                ("2", "K2h") => {
                    check!(deso::stat("/disk/pkg/index/53").is_ok() && accepted_serial() == 52, "power loss at K2h: a half-written index/53 must not count (accepted {})", accepted_serial());
                    let (code, out) = desopkg(&["refresh"], "");
                    check!(code == 0 && out.contains("index serial 53 accepted"), "refresh after the power loss: {} {}", code, short(&out));
                    Ok(String::from("witaj 1.1.1 "))
                }
                ("3", "K6") => {
                    check!(gen_now() == g && top_generation() == top && files_in(WITAJ) == d0 + 1, "power loss at K6: generation {} (was {}), top {} (was {}), dirs {} (was {})", gen_now(), g, top_generation(), top, files_in(WITAJ), d0);
                    sweep_by_refresh("after the power loss at K6")?;
                    check!(files_in(WITAJ) == d0, "after K6 gc left {} dirs (want {})", files_in(WITAJ), d0);
                    Ok(String::from("witaj 1.1.1 "))
                }
                ("4", "K7h") => {
                    check!(gen_now() == g && top_generation() == top + 1 && files_in(WITAJ) == d0 + 1, "power loss at K7h: generation {} (was {}), top {} (was {}), dirs {} (was {})", gen_now(), g, top_generation(), top, files_in(WITAJ), d0);
                    sweep_by_refresh("after the power loss at K7h")?;
                    check!(files_in(WITAJ) == d0, "after K7h gc left {} dirs (want {})", files_in(WITAJ), d0);
                    Ok(String::from("witaj 1.1.1 "))
                }
                ("5", "K9") => {
                    check!(gen_now() > g && gen_now() == top_generation() && version_of("witaj") == "1.1.0" && files_in(pkgstate::GEN_DIR) == 2, "power loss at K9: generation {} (was {}), top {}, witaj {}, gen files {}", gen_now(), g, top_generation(), version_of("witaj"), files_in(pkgstate::GEN_DIR));
                    sweep_by_refresh("after the power loss at K9")?;
                    let (code, out) = desopkg(&["verify"], "");
                    check!(code == 0 && files_in(WITAJ) == 2, "verify after the power losses: {} {} (witaj dirs {})", code, short(&out), files_in(WITAJ));
                    let _ = deso::unlink(POWER);
                    Ok(String::from("witaj 1.1.0 "))
                }
                _ => {
                    println!("pkgtest: FAIL power check {}: the disk says the last step was {:?}", n, point);
                    Err(())
                }
            }
        })();
        match r {
            Ok(want) => {
                println!("pkgtest pc {}: {} checks OK (shell: {})", n, unsafe { CHECKS }, want);
                0
            }
            Err(()) => 1,
        }
    }

    // ------------------------------------------------------------ 16. the mutants' sequence

    /// What tests/pkg-test.sh --mutants runs on a fresh volume: each check one mutant switches
    /// off (signature, serial, expires, paths, "directories before the generation", the
    /// generation's hash) is met once – a normal desopkg passes, every mutant fails.
    pub fn mutants() -> i32 {
        let t0 = uptime_ms();
        let r = (|| -> Result<(), ()> {
            net_ready()?;
            scenario("v100")?;
            let (code, out) = desopkg(&["refresh"], "");
            check!(code == 0 && out.contains("index serial 10 accepted"), "refresh v100: {} {}", code, short(&out));
            let (code, out) = desopkg(&["-y", "install", "witaj"], "");
            check!(code == 0 && out.contains("generation 1 is now current"), "install witaj: {} {}", code, short(&out));
            for (sc, why) in [("old", "older than the accepted"), ("expired", "expired"), ("badsig", "signature")] {
                scenario(sc)?;
                let (code, out) = desopkg(&["refresh"], "");
                check!(code == 2 && out.contains(why), "[mutant {}] refresh {}: {} {}", if sc == "old" { "serial" } else if sc == "expired" { "expires" } else { "sig" }, sc, code, short(&out));
            }
            scenario("evil")?;
            let (code, out) = desopkg(&["refresh"], "");
            check!(code == 0 && out.contains("index serial 21 accepted"), "refresh evil: {} {}", code, short(&out));
            let (code, out) = desopkg(&["-y", "install", "zly"], "");
            check!(code == 2 && out.contains("bad_path") && deso::stat("/disk/pkg/zly").is_err(), "[mutant paths] install zly: {} {}", code, short(&out));
            let g = gen_now();
            let top = top_generation();
            killed_at("K6", &["-y", "install", "witaj=1.1.1"])?;
            check!(gen_now() == g && top_generation() == top, "[mutant order] a crash at K6 left a generation file (top {} was {})", top_generation(), top);
            sweep_by_refresh("after K6")?;
            let cur = pkgstate::generations(&sys_name).current;
            check!(cur.is_some(), "no current generation");
            let cur = cur.unwrap();
            let m = cur.number;
            let bytes = wrong_hash(&cur.generation.packages, m + 1);
            check!(!bytes.is_empty(), "no op= line");
            put_generation(m + 1, &bytes)?;
            let (code, out) = desopkg(&["list"], "");
            check!(code == 0 && out.contains(&format!("generation {}", m)) && !out.contains(&format!("generation {}", m + 1)), "[mutant hash] a generation with a wrong hash counted: {} {}", code, short(&out));
            put_generation(m + 1, &pkgfmt::make_generation(m + 1, "install", &cur.generation.packages))?;
            let (code, out) = desopkg(&["list"], "");
            check!(code == 0 && out.contains(&format!("generation {}", m + 1)), "a valid generation written by hand must count: {} {}", code, short(&out));
            Ok(())
        })();
        match r {
            Ok(()) => {
                println!("pkgtest m: {} checks OK ({} ms)", unsafe { CHECKS }, uptime_ms() - t0);
                0
            }
            Err(()) => {
                no_crash();
                1
            }
        }
    }
}
