// SDK TEST – a program built outside the repository with the SDK (sdk/deso-build.sh, from a
// copy of sdk/ alone – tests/sdk-test.sh) on a running system: QEMU hands the file over in the
// fw_cfg file `opt/deso/sdkprog`; it must carry the ABI 1.0 note, the shell copies it to
// /disk/bin (a DeSoFS volume on the virtio disk) and runs it by name with two arguments, as a
// user would after copying it from a stick (1/2).  Then compat10, built with the frozen SDK of
// ABI 1.0 (sdk/compat/abi-1.0, fw_cfg `opt/deso/compatprog`), runs from /disk/bin through the
// real init with the network card – what a 1.0 program relies on still holds (2/2).

use alloc::string::String;
use alloc::vec::Vec;

use super::elf_loader::abi_of;
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

pub fn sdk(name: &str) {
    serial_println!("[SDK TEST] Starting: {} built with the SDK outside the repository...", name);
    crate::selftest::begin();
    let l = match run(name) {
        Ok(l) => l,
        Err(e) => {
            serial_println!("[SDK TEST] FAIL: {}", e);
            return;
        }
    };
    serial_println!("[SDK TEST] 1/2 {} PASS", l);
    match compat() {
        Ok(l) => {
            serial_println!("[SDK TEST] 2/2 {} PASS", l);
            crate::selftest::pass();
        }
        Err(e) => serial_println!("[SDK TEST] FAIL: {}", e),
    }
}

/// Test 6: compat10, built with the frozen SDK of ABI 1.0 (sdk/compat/abi-1.0) – fw_cfg file
/// `opt/deso/compatprog` – run from /disk/bin through the real init with the network card.
fn compat() -> Result<String, String> {
    let prog = crate::selftest::fw_cfg_file(b"opt/deso/compatprog", 8 << 20).ok_or_else(|| String::from("no fw_cfg file opt/deso/compatprog (or over 8 MiB)"))?;
    if abi_of(&prog) != Ok((1, 0)) {
        return Err(alloc::format!("compat10: not an ABI 1.0 program ({:?})", abi_of(&prog)));
    }
    crate::fs::write_file("/disk/bin/compat10", &prog).map_err(|e| alloc::format!("/disk/bin/compat10: {}", e))?;
    let opts = SpawnOptions { stdin: Some(Vec::new()), capture: true, hw_root: true, sysctl: true, input: true, blk: true, ..SpawnOptions::default() };
    let id = exec("/bin/init", &["init", "test", "/disk/bin/compat10"], "/", &opts).map_err(|_| String::from("cannot start /bin/init"))?;
    if !wait_for(120_000, || sched::task_info(id).is_none()) {
        let _ = sched::request_exit(id);
        return Err(String::from("init test /disk/bin/compat10 did not finish"));
    }
    let kind = exit_info(id).map(|e| e.kind);
    let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
    let line = out.lines().find(|l| l.starts_with("compat10:")).unwrap_or("").trim();
    if kind != Some(ExitKind::Exit(0)) || !line.contains("checks OK") {
        return Err(alloc::format!("compat10 via init: {:?} {:?}", kind, out.trim()));
    }
    Ok(alloc::format!("{} B, built with the frozen SDK of ABI 1.0, run from /disk/bin through init: {}", prog.len(), line))
}

fn run(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err(String::from("bad phase (expected \"sdk <name>\")"));
    }
    let prog = crate::selftest::fw_cfg_file(b"opt/deso/sdkprog", 8 << 20).ok_or_else(|| String::from("no fw_cfg file opt/deso/sdkprog (or over 8 MiB)"))?;
    if abi_of(&prog) != Ok((1, 0)) || !prog.windows(5).any(|w| w == b"DeSo\0") {
        return Err(alloc::format!("{}: not an ABI 1.0 program with the note ({:?})", name, abi_of(&prog)));
    }
    if !wait_for(10_000, || crate::fs::mounted_disk("/disk").is_some()) || crate::fs::is_read_only("/disk/x") {
        return Err(String::from("/disk is not a read-write volume"));
    }
    // Where a user would have it after plugging in a stick: a file outside /disk/bin.
    let staged = alloc::format!("/{}.new", name);
    crate::fs::write_file(&staged, &prog).map_err(|e| alloc::format!("{}: {}", staged, e))?;
    let script = alloc::format!("mkdir /disk/bin\ncp {staged} /disk/bin/{name}\n{name} first second\nhelp\n");
    let opts = SpawnOptions { stdin: Some(script.into_bytes()), capture: true, ..SpawnOptions::default() };
    let id = exec("/bin/sh", &["sh"], "/", &opts).map_err(|_| String::from("cannot start /bin/sh"))?;
    if !wait_for(20_000, || sched::task_info(id).is_none()) {
        let _ = sched::request_exit(id);
        return Err(String::from("the shell did not finish"));
    }
    let out = String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned();
    let _ = crate::fs::remove(&staged);
    let hello = alloc::format!("Hello from {}, built with the DeSo OS SDK (ABI 1.0)", name);
    let lines: Vec<&str> = out.lines().collect();
    let ok = lines.iter().any(|l| l.starts_with(&hello))
        && lines.iter().any(|l| l.trim() == "argument 1: first")
        && lines.iter().any(|l| l.trim() == "argument 2: second");
    if !ok {
        return Err(alloc::format!("the program's output: {:?}", out));
    }
    let on_disk = crate::fs::read_file(&alloc::format!("/disk/bin/{}", name)).map_err(|e| alloc::format!("/disk/bin/{}: {}", name, e))?;
    if on_disk != prog {
        return Err(String::from("/disk/bin holds other bytes than the program"));
    }
    if !lines.iter().any(|l| l.contains("Programs from the disk") && l.contains(name)) && !out.contains(&alloc::format!("  {}", name)) {
        return Err(alloc::format!("help does not list {} among the programs from the disk", name));
    }
    Ok(alloc::format!("{} ({} B, ABI 1.0 note): copied to /disk/bin by the shell, run by name with 2 arguments, listed by help", name, prog.len()))
}
