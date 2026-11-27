// PKG TEST – tests/pkg-test.sh starts QEMU with the phase "pkg <part>", a
// DeSoFS volume on the virtio disk and a network card; tests/repo-stub.py and tests/dns-stub.py
// run on the host.  /bin/pkgtest drives desopkg, the shell and netget through the real init
// (`init test /bin/pkgtest <mode>`):
//
//   b1   part 1 on a fresh volume:
//        1/2  without the time service's time desopkg refuses before connecting (repo-stub saw
//             no request)
//        2/2  with the self-test time (the LKG raised as an authenticated time would, source 3):
//             install, run by name, list / search / info, update, downgrade, dependencies and
//             refusals, remove, verify and reinstall, refused indexes and transfers, no memory,
//             a big package
//   b2   part 2 on the same volume:
//        1/3  desopkg killed at every crash point K1–K10; the lock; damaged files
//        2/3  the shell paused between its lookup and exec while an update and its gc remove the
//             program: it looks again and starts the new one
//        3/3  a bad ELF in a valid generation: reported at once, no second try
//   p1…p5 power losses: p1–p4 stop desopkg at K2h, K6, K7h, K9 and say POWER OFF
//        (tests/pkg-test.sh kills QEMU); p2–p5 first check what the disk holds after that
//   m    the short sequence tests/pkg-test.sh --mutants runs

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

/// The shell with a script on stdin, started – only the kernel can give the shell keyboard
/// input (the buffer of SpawnOptions::stdin; readkey refuses a file or a pipe).
fn shell_start(script: &str) -> Result<TaskId, String> {
    let opts = SpawnOptions { stdin: Some(script.as_bytes().to_vec()), capture: true, ..SpawnOptions::default() };
    exec("/bin/sh", &["sh"], "/", &opts).map_err(|_| String::from("cannot start /bin/sh"))
}

/// Its output once it ended.
fn shell_end(id: TaskId, ms: u64) -> Result<String, String> {
    if !wait_for(ms, || sched::task_info(id).is_none()) {
        let _ = sched::request_exit(id);
        return Err(String::from("the shell did not finish"));
    }
    Ok(String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned())
}

fn shell(script: &str) -> Result<String, String> {
    let id = shell_start(script)?;
    shell_end(id, 30_000)
}

/// After a segment: what the shell must print (all of `want`, none of `not`).
struct ShellCheck {
    what: &'static str,
    script: &'static str,
    want: &'static [&'static str],
    not: &'static [&'static str],
}

impl ShellCheck {
    fn run(&self, after: &str) -> Result<(), String> {
        let o = shell(self.script)?;
        if !self.want.iter().all(|w| o.contains(w)) || self.not.iter().any(|n| o.contains(n)) {
            return Err(alloc::format!("after {}: the shell ({}): {:?}", after, self.what, o.trim()));
        }
        Ok(())
    }
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

/// Part 2, before the shell's pause: after each segment the version `witaj` must start.
const SEGMENTS_B2: &[(&str, Option<ShellCheck>)] = &[
    ("k1", Some(ShellCheck { what: "witaj 1.1.1 - the killed install changed nothing", script: "witaj\n", want: &["witaj 1.1.1 "], not: &[] })),
    ("k2", Some(ShellCheck { what: "witaj 1.1.0 after K4-K7h and the install that followed", script: "witaj\n", want: &["witaj 1.1.0 "], not: &[] })),
    ("k3", Some(ShellCheck { what: "witaj 1.0.1 - the generation written before K8 is in force", script: "witaj\n", want: &["witaj 1.0.1 "], not: &[] })),
    ("k4", Some(ShellCheck { what: "witaj 1.1.1 - gc interrupted at K9", script: "witaj\n", want: &["witaj 1.1.1 "], not: &[] })),
    ("k5", Some(ShellCheck { what: "witaj 1.1.0 - the lock left at K10", script: "witaj\n", want: &["witaj 1.1.0 "], not: &[] })),
    ("k6", Some(ShellCheck { what: "witaj 1.1.0 - the lock tests changed nothing", script: "witaj\n", want: &["witaj 1.1.0 "], not: &[] })),
    ("k7", Some(ShellCheck { what: "witaj 1.1.0 from the generation written by hand", script: "witaj\n", want: &["witaj 1.1.0 "], not: &[] })),
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

/// One pkgtest run that must end with 0 and print the line starting with `prefix`: the rest of
/// that line.
fn segment(mode: &str, prefix: &str, ms: u64) -> Result<String, String> {
    let (kind, out) = pkgtest(mode, ms)?;
    let line = out.lines().find(|l| l.starts_with(prefix)).unwrap_or("").trim();
    if kind != ExitKind::Exit(0) || line.is_empty() {
        return Err(alloc::format!("{}: {:?} {}", mode, kind, fail_detail(&out)));
    }
    Ok(String::from(line[prefix.len()..].trim()))
}

/// "K checks OK (...)" – K.
fn checks_of(rest: &str) -> u32 {
    rest.split(' ').next().and_then(|n| n.parse::<u32>().ok()).unwrap_or(0)
}

/// /disk must be a read-write volume and the clock what desopkg's self-test build trusts.
fn ready(raise_time: bool) -> Result<(), String> {
    if !wait_for(10_000, || crate::fs::mounted_disk("/disk").is_some()) || crate::fs::is_read_only("/disk/x") {
        return Err(String::from("/disk is not a read-write volume"));
    }
    if raise_time {
        // The self-test time: what desopkg's self-test build accepts instead of NTS.
        let now = crate::drivers::rtc::time_status().0;
        let _ = crate::time_lkg::raise_for_test(now);
    }
    Ok(())
}

/// Part 1: (line 1/2, checks, generation, big package ms).
fn part1() -> Result<(String, u32, String, String), String> {
    ready(false)?;
    // 1. No time from the time service yet.
    let l1 = segment("b1-notime", "pkgtest b1-notime:", 180_000)?;
    // 2. The self-test time.
    ready(true)?;
    let mut checks = 0u32;
    let mut result = String::new();
    for (seg, sh) in SEGMENTS {
        let mode = alloc::format!("b1:{}", seg);
        let (kind, out) = pkgtest(&mode, 900_000)?;
        let prefix = alloc::format!("pkgtest b1 {}:", seg);
        let line = out.lines().find(|l| l.starts_with(&prefix)).unwrap_or("").trim();
        if kind != ExitKind::Exit(0) || line.is_empty() {
            return Err(alloc::format!("b1 {}: {:?} {}", seg, kind, fail_detail(&out)));
        }
        checks += checks_of(line[prefix.len()..].trim());
        if let Some(r) = out.lines().find_map(|l| l.trim().strip_prefix("pkgtest result: ")) {
            result = String::from(r);
        }
        if let Some(c) = sh {
            c.run(seg)?;
            checks += 1;
        }
    }
    // "generation=G big_ms=X"
    let field = |k: &str| result.split_whitespace().find_map(|w| w.strip_prefix(k)).map(String::from).unwrap_or_default();
    // Line 1/2 without its own "OK" (the kernel adds PASS).
    let l1 = String::from(l1.trim_end_matches(" OK"));
    Ok((l1, checks, field("generation="), field("big_ms=")))
}

/// Part 2: (checks, the lock rounds' summary).
fn part2() -> Result<(u32, String, u32, u32), String> {
    ready(true)?;
    let mut checks = 0u32;
    let mut locks = String::new();
    for (seg, sh) in SEGMENTS_B2 {
        let rest = segment(&alloc::format!("b2:{}", seg), &alloc::format!("pkgtest b2 {}:", seg), 900_000)?;
        checks += checks_of(&rest);
        if *seg == "k6" {
            locks = String::from(rest.split_once("two at once: ").map(|(_, r)| r.split(',').next().unwrap_or("").trim_end_matches(')')).unwrap_or(""));
        }
        if let Some(c) = sh {
            c.run(seg)?;
            checks += 1;
        }
    }
    // 14. The shell between its lookup and exec: pkgtest makes /tmp/sh-pause, the shell stops
    //     before starting witaj (marked by /tmp/sh-paused), two installs and their gc remove the
    //     directory it found, the pause ends: the shell must look again and start the new one.
    let mut pause = 0u32;
    checks += checks_of(&segment("b2:pa", "pkgtest b2 pa:", 300_000)?);
    let sh = shell_start("witaj\n")?;
    if !wait_for(30_000, || crate::fs::stat("/tmp/sh-paused").is_ok()) {
        let _ = sched::request_exit(sh);
        return Err(String::from("the shell did not pause before starting witaj (/tmp/sh-paused)"));
    }
    let rest = segment("b2:pb", "pkgtest b2 pb:", 600_000);
    if rest.is_err() {
        let _ = crate::fs::remove("/tmp/sh-pause");
    }
    checks += checks_of(&rest?);
    let out = shell_end(sh, 30_000)?;
    let log = String::from_utf8_lossy(&crate::fs::read_file("/tmp/sh-pause-log").unwrap_or_default()).into_owned();
    let tries: Vec<&str> = log.lines().collect();
    if !out.contains("witaj 1.1.1 argv0=/disk/pkg/witaj/1.1.1-") || out.contains("sh: witaj") || tries.len() != 2 || !tries[0].starts_with("try 0 ") || !tries[1].starts_with("try 1 ") || tries[0][6..] == tries[1][6..] {
        return Err(alloc::format!("the shell after gc removed its program: {:?}, tries {:?}", out.trim(), tries));
    }
    pause += tries.len() as u32;
    checks += 1;
    // A bad ELF in a valid generation: an error other than "not found" – reported, no retry.
    checks += checks_of(&segment("b2:pc", "pkgtest b2 pc:", 300_000)?);
    let out = shell("witaj\n")?;
    let log = String::from_utf8_lossy(&crate::fs::read_file("/tmp/sh-pause-log").unwrap_or_default()).into_owned();
    if !out.contains("sh: witaj:") || out.contains("command not found") || log.lines().count() != 1 {
        return Err(alloc::format!("a bad ELF in the generation: {:?}, tries {:?}", out.trim(), log.trim()));
    }
    let bad = log.lines().count() as u32;
    checks += 1;
    checks += checks_of(&segment("b2:pd", "pkgtest b2 pd:", 600_000)?);
    Ok((checks, locks, pause, bad))
}

/// p1–p4: stops desopkg at a crash point; never returns (QEMU is killed from outside).
fn power_off(step: &str) -> ! {
    match segment(&alloc::format!("ph:{}", step), &alloc::format!("pkgtest ph {}:", step), 600_000) {
        Ok(rest) => {
            let point = rest.trim_start_matches("HANG ").trim();
            serial_println!("[PKG TEST] POWER OFF at {} - tests/pkg-test.sh kills QEMU now", point);
        }
        Err(e) => serial_println!("[PKG TEST] FAIL: {}", e),
    }
    // Nothing more may reach the disk: wait for the kill (or the script's time limit).
    loop {
        crate::time::sleep_ms(1000);
    }
}

pub fn run(part: &str) {
    serial_println!("[PKG TEST] Starting: desopkg against tests/repo-stub.py ({})...", part);
    crate::selftest::begin();
    let t0 = ticks();
    match part {
        "b1" => match part1() {
            Ok((l1, checks, generation, big_ms)) => {
                serial_println!("[PKG TEST] 1/2 without the time service's time: {} PASS", l1);
                serial_println!(
                    "[PKG TEST] 2/2 {} checks in 8 segments: install, run by name through the shell (argv[0], ../share, help), list / search / info, update in one generation, downgrade with y/N, dependencies, conflicts, a system name, remove, verify (MODIFIED, MISSING, UNEXPECTED, SHADOWED, DAMAGED) and reinstall, refused indexes (old, expired, future, bad signature, other key, other channel) and transfers (SHA-256, size, long, short, Content-Length, redirect), no memory, a big package (generation {}, 30 MiB in {} ms) PASS",
                    checks, generation, big_ms
                );
                serial_println!("[RESULT-PKGB] checks={} generation={} big_ms={} ms={}", checks, generation, big_ms, ticks() - t0);
                crate::selftest::pass();
            }
            Err(e) => serial_println!("[PKG TEST] FAIL: {}", e),
        },
        "b2" => match part2() {
            Ok((checks, locks, pause, bad)) => {
                serial_println!("[PKG TEST] 1/3 {} checks: desopkg killed at K1, K2, K2h, K3, K4, K5, K6, K7, K7h, K8, K9, K10 - the old or the new generation whole, the next command sweeps; the lock: a living holder (code 4), a dead one (taken over), two new ones at once ({}); a damaged newest index; generations that must not count (wrong number, version, program, hash) PASS", checks, locks);
                serial_println!("[PKG TEST] 2/3 the shell paused before exec while an update and gc removed witaj: looked again and started 1.1.1 ({} tries) PASS", pause);
                serial_println!("[PKG TEST] 3/3 a bad ELF in a valid generation: reported at once ({} try), reinstall repaired it PASS", bad);
                serial_println!("[RESULT-PKGB2] checks={} ms={}", checks, ticks() - t0);
                crate::selftest::pass();
            }
            Err(e) => serial_println!("[PKG TEST] FAIL: {}", e),
        },
        "p1" | "p2" | "p3" | "p4" | "p5" => {
            let n = &part[1..];
            let r = (|| -> Result<(), String> {
                ready(true)?;
                if n != "1" {
                    let rest = segment(&alloc::format!("pc:{}", n), &alloc::format!("pkgtest pc {}:", n), 600_000)?;
                    let want = rest.split_once("shell: ").map(|(_, w)| w.trim_end_matches(')')).unwrap_or("");
                    let o = shell("witaj\n")?;
                    if want.is_empty() || !o.contains(want) {
                        return Err(alloc::format!("after the power loss: the shell must print {:?}: {:?}", want, o.trim()));
                    }
                    serial_println!("[PKG TEST] {} after the power loss: {} checks, the shell starts {:?} PASS", part, checks_of(&rest) + 1, want.trim());
                }
                Ok(())
            })();
            if let Err(e) = r {
                serial_println!("[PKG TEST] FAIL: {}", e);
                return;
            }
            if n == "5" {
                serial_println!("[RESULT-PKGP] steps=4 ms={}", ticks() - t0);
                crate::selftest::pass();
                return;
            }
            power_off(n);
        }
        "m" => match ready(true).and_then(|_| segment("m", "pkgtest m:", 900_000)) {
            Ok(rest) => {
                serial_println!("[PKG TEST] mutant sequence: {} PASS", rest);
                crate::selftest::pass();
            }
            Err(e) => serial_println!("[PKG TEST] FAIL: {}", e),
        },
        _ => serial_println!("[PKG TEST] FAIL: bad phase (expected \"pkg\" and one of {:?})", crate::selftest::PKG_PARTS),
    }
}
