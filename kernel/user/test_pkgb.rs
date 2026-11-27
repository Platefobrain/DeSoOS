// PKG TEST part 1 (V082-B plan §5, points 1–10) – tests/pkg-test.sh starts QEMU with the phase
// "pkg b1", a fresh DeSoFS volume on the virtio disk and a network card; tests/repo-stub.py and
// tests/dns-stub.py run on the host.  /bin/pkgtest drives desopkg, the shell and netget through
// the real init (`init test /bin/pkgtest b1…`):
//
//   1/2  without the time service's time desopkg refuses before connecting (repo-stub saw no
//        request)
//   2/2  with the self-test time (the LKG raised as an authenticated time would, source 3):
//        install, run by name, list / search / info, update, downgrade, dependencies and
//        refusals, remove, verify and reinstall, refused indexes and transfers, no memory, a big
//        package

use alloc::string::String;
use alloc::vec::Vec;

use super::*;
use crate::time::ticks;

fn wait_for(ms: u64, cond: impl Fn() -> bool) -> bool {
    let end = ticks() + ms;
    while !cond() {
        if ticks() > end {
            return false;
        }
        crate::time::sleep_ms(5);
    }
    true
}

/// `init test /bin/pkgtest <mode>` (one argument: "b1-notime", "b1:s1" …): (how it ended, output).
fn pkgtest(mode: &str, ms: u64) -> Result<(ExitKind, String), String> {
    let opts = SpawnOptions { stdin: Some(Vec::new()), capture: true, hw_root: true, sysctl: true, input: true, blk: true, ..SpawnOptions::default() };
    let id = exec("/bin/init", &["init", "test", "/bin/pkgtest", mode], "/", &opts).map_err(|_| String::from("cannot start /bin/init"))?;
    if !wait_for(ms, || sched::task_info(id).is_none()) {
        let _ = sched::request_exit(id);
        let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
        return Err(alloc::format!("pkgtest {} did not finish in {} s: {}", mode, ms / 1000, tail(&out)));
    }
    let kind = exit_info(id).map(|e| e.kind).ok_or_else(|| String::from("no exit status"))?;
    Ok((kind, String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned()))
}

fn tail(out: &str) -> String {
    let lines: Vec<&str> = out.lines().collect();
    lines[lines.len().saturating_sub(12)..].join(" | ")
}

/// The shell with a script on stdin – only the kernel can give the shell keyboard input (the
/// buffer of SpawnOptions::stdin; readkey refuses a file or a pipe).  Its output.
fn shell(script: &str) -> Result<String, String> {
    let opts = SpawnOptions { stdin: Some(script.as_bytes().to_vec()), capture: true, ..SpawnOptions::default() };
    let id = exec("/bin/sh", &["sh"], "/", &opts).map_err(|_| String::from("cannot start /bin/sh"))?;
    if !wait_for(30_000, || sched::task_info(id).is_none()) {
        let _ = sched::request_exit(id);
        return Err(String::from("the shell did not finish"));
    }
    Ok(String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned())
}

/// After each segment: what the shell must print (all of `want`, none of `not`).
struct ShellCheck {
    what: &'static str,
    script: &'static str,
    want: &'static [&'static str],
    not: &'static [&'static str],
}

const SEGMENTS: &[(&str, Option<ShellCheck>)] = &[
    ("s1", Some(ShellCheck { what: "witaj 1.0.0 by name, argv[0] and ../share, help lists it", script: "witaj\nhelp\n", want: &["witaj 1.0.0 argv0=/disk/pkg/witaj/1.0.0-", "witaj data: Witaj w DeSo OS - wersja 1.0.0", "Programs from packages"], not: &[] })),
    ("s2", Some(ShellCheck { what: "witaj 1.1.0 after update", script: "witaj\n", want: &["witaj 1.1.0 argv0=/disk/pkg/witaj/1.1.0-", "wersja 1.1.0"], not: &[] })),
    ("s3", Some(ShellCheck { what: "witaj 1.0.1 after the downgrade", script: "witaj\n", want: &["witaj 1.0.1 "], not: &[] })),
    ("s4", Some(ShellCheck { what: "witaj gone after remove", script: "witaj\n", want: &["witaj: command not found"], not: &["witaj 1."] })),
    ("s5", Some(ShellCheck { what: "a copy in /disk/bin wins over the package", script: "witaj\n", want: &["Hello"], not: &["witaj 1.1.0"] })),
    ("s6", Some(ShellCheck { what: "witaj from the previous generation (the newest has a damaged package file)", script: "witaj\n", want: &["witaj 1.1.0 "], not: &[] })),
    ("s7", Some(ShellCheck { what: "witaj 1.1.1 after the refused transfers", script: "witaj\n", want: &["witaj 1.1.1 "], not: &[] })),
    ("s8", None),
];

fn fail_detail(out: &str) -> String {
    // Everything from the first FAIL line on (a long line may arrive wrapped).
    match out.find("pkgtest: FAIL") {
        Some(i) => {
            let rest: Vec<&str> = out[i..].lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
            let mut d = rest.join(" ");
            if d.len() > 4000 {
                let mut cut = 4000;
                while !d.is_char_boundary(cut) {
                    cut -= 1;
                }
                d.truncate(cut);
            }
            d
        }
        None => tail(out),
    }
}

fn part1() -> Result<(String, u32, String), String> {
    if !wait_for(10_000, || crate::fs::mounted_disk("/disk").is_some()) || crate::fs::is_read_only("/disk/x") {
        return Err(String::from("/disk is not a read-write volume"));
    }
    // 1. No time from the time service yet.
    let (kind, out) = pkgtest("b1-notime", 180_000)?;
    let l1 = out.lines().find(|l| l.starts_with("pkgtest b1-notime:")).unwrap_or("").trim();
    if kind != ExitKind::Exit(0) || l1.is_empty() {
        return Err(alloc::format!("b1-notime: {:?} {}", kind, fail_detail(&out)));
    }
    let l1 = String::from(l1);
    // 2. The self-test time: what desopkg's self-test build accepts instead of NTS.
    let now = crate::drivers::rtc::time_status().0;
    let _ = crate::time_lkg::raise_for_test(now);
    let mut checks = 0u32;
    let mut last = String::new();
    for (seg, sh) in SEGMENTS {
        let (kind, out) = pkgtest(&alloc::format!("b1:{}", seg), 900_000)?;
        let prefix = alloc::format!("pkgtest b1 {}:", seg);
        let line = out.lines().find(|l| l.starts_with(&prefix)).unwrap_or("").trim();
        if kind != ExitKind::Exit(0) || line.is_empty() {
            return Err(alloc::format!("b1 {}: {:?} {}", seg, kind, fail_detail(&out)));
        }
        checks += line[prefix.len()..].trim().split(' ').next().and_then(|n| n.parse::<u32>().ok()).unwrap_or(0);
        last = String::from(line);
        if let Some(c) = sh {
            let o = shell(c.script)?;
            if !c.want.iter().all(|w| o.contains(w)) || c.not.iter().any(|n| o.contains(n)) {
                return Err(alloc::format!("after {}: the shell ({}): {:?}", seg, c.what, o.trim()));
            }
            checks += 1;
        }
    }
    Ok((l1, checks, last))
}

pub fn run(part: &str) {
    serial_println!("[PKG TEST] Starting: desopkg against tests/repo-stub.py ({})...", part);
    crate::selftest::begin();
    if part != "b1" {
        serial_println!("[PKG TEST] FAIL: bad phase (expected \"pkg b1\")");
        return;
    }
    let t0 = ticks();
    match part1() {
        Ok((l1, checks, last)) => {
            serial_println!("[PKG TEST] 1/2 without the time service's time: {} PASS", l1.trim_start_matches("pkgtest b1-notime: "));
            let tail = last.split_once('(').map(|(_, r)| r.trim_end_matches(')')).unwrap_or("");
            serial_println!(
                "[PKG TEST] 2/2 {} checks in 8 segments: install, run by name through the shell (argv[0], ../share, help), list / search / info, update in one generation, downgrade with y/N, dependencies, conflicts, a system name, remove, verify (MODIFIED, MISSING, UNEXPECTED, SHADOWED, DAMAGED) and reinstall, refused indexes (old, expired, future, bad signature, other key, other channel) and transfers (SHA-256, size, long, short, Content-Length, redirect), no memory, a big package ({}) PASS",
                checks, tail
            );
            serial_println!("[RESULT-PKGB] checks={} {} ms={}", checks, tail, ticks() - t0);
            crate::selftest::pass();
        }
        Err(e) => serial_println!("[PKG TEST] FAIL: {}", e),
    }
}
