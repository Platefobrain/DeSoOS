// Test of the service manager in init.  The kernel runs it via
// `init test /bin/svctest` (init with HW_ROOT, svctest instead of the shell, with the svc
// channel in slot 3).  Checks: svc channel rights, the service list (edu and echo
// are running), talking to echo by name, restart after a crash (new pid, restart
// counter), edu through the manager (PING, factorial), restarting edud after kill,
// unknown service -> ERROR_CLOSED, a bad request does not break init, the shell passes
// slot 3 to programs (`sh -c services`), 5 crashes in 30 s -> "broken".
// Result: "svctest: N checks OK, ..." and exit code 0.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../lib/edu_proto.rs"]
mod edu_proto;

use desoos::*;
use edu_proto::*;

entry!(main);

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("svctest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

/// Service state from init's list: (state, pid, restarts).
fn status(name: &str) -> Option<([u8; 16], usize, u64, u64)> {
    let mut buf = [0u8; 2048];
    let n = svc_list(&mut buf).ok()?;
    let text = core::str::from_utf8(&buf[..n]).ok()?;
    for line in text.lines() {
        let (head, _) = line.rsplit_once(" (")?;
        let (head, restarts) = head.rsplit_once(" restarts ")?;
        let (head, pid) = head.rsplit_once(" pid ")?;
        let (nm, state) = head.split_once(' ')?;
        if nm == name {
            let mut s = [0u8; 16];
            let l = state.len().min(16);
            s[..l].copy_from_slice(&state.as_bytes()[..l]);
            return Some((s, l, pid.parse().ok()?, restarts.parse().ok()?));
        }
    }
    None
}

fn state_is(name: &str, want: &str) -> Option<(u64, u64)> {
    let (s, l, pid, restarts) = status(name)?;
    if &s[..l] == want.as_bytes() { Some((pid, restarts)) } else { None }
}

/// Waits (up to `ms`) until the service is in state `want` and satisfies `cond`.
fn wait_state(name: &str, want: &str, ms: u64, cond: impl Fn(u64, u64) -> bool) -> Option<(u64, u64)> {
    let t0 = uptime_ms();
    loop {
        if let Some((pid, r)) = state_is(name, want) {
            if cond(pid, r) {
                return Some((pid, r));
            }
        }
        if uptime_ms() - t0 > ms {
            return None;
        }
        sleep_ms(10);
    }
}

fn echo(c: u64, data: &[u8], out: &mut [u8]) -> Result<usize, i64> {
    let r = chan_send(c, data, 0);
    if r != 0 {
        return Err(r);
    }
    let mut info = RecvInfo::default();
    let r = chan_recv(c, out, 0, &mut info);
    if r < 0 { Err(r) } else { Ok(r as usize) }
}

fn edu_call(c: u64, op: u32, arg: u64) -> Result<(i32, u64), i64> {
    let mut req = [0u8; 64];
    let n = request(op, arg, &[], &mut req);
    let r = chan_send(c, &req[..n], 0);
    if r != 0 {
        return Err(r);
    }
    let mut msg = [0u8; MSG_MAX];
    let mut info = RecvInfo::default();
    let r = chan_recv(c, &mut msg, 0, &mut info);
    if r < HDR as i64 {
        return Err(if r < 0 { r } else { -5 });
    }
    Ok((u32_at(&msg, 0) as i32, u64_at(&msg, 8)))
}

/// `sh -c <cmd>` with output into a pipe; with or without the svc channel in slot 3.
fn shell_cmd(cmd: &str, with_svc: bool, out: &mut [u8]) -> (u64, usize) {
    let Ok((r, w)) = pipe() else { return (99, 0) };
    shell_cmd_map(cmd, if with_svc { &[(SVC, 3)] } else { &[] }, r, w, out)
}

/// `sh -c <cmd>` with extra handles `extra` (e.g. SYSCTL in slot 4).
fn shell_cmd_with(cmd: &str, extra: &[(u64, u64)], out: &mut [u8]) -> (u64, usize) {
    let Ok((r, w)) = pipe() else { return (99, 0) };
    shell_cmd_map(cmd, extra, r, w, out)
}

fn shell_cmd_map(cmd: &str, extra: &[(u64, u64)], r: u64, w: u64, out: &mut [u8]) -> (u64, usize) {
    let mut map = [(0u64, 0u64), (w, 1), (w, 2), (0, 0), (0, 0)];
    for (i, &e) in extra.iter().enumerate().take(2) {
        map[3 + i] = e;
    }
    let pid = spawn_ex("/bin/sh", &["sh", "-c", cmd], &map[..3 + extra.len().min(2)], 0);
    close(w);
    if pid <= 0 {
        close(r);
        return (98, 0);
    }
    let mut n = 0;
    while n < out.len() {
        let k = read(r, &mut out[n..]);
        if k <= 0 {
            break;
        }
        n += k as usize;
    }
    close(r);
    let st = wait(pid as u64, 0).map(|(_, s)| s).unwrap_or(97);
    (st, n)
}

fn main(_args: Args) -> i32 {
    let mut n = 0;
    let mut out = [0u8; MSG_MAX];

    // 1. svc channel: send only (+ duplicate), receiving is forbidden.
    check!(n, handle_info(SVC) == Ok((KIND_CHANNEL, R_SEND | R_DUP)), "slot 3 rights: {:?}", handle_info(SVC));
    let mut info = RecvInfo::default();
    check!(n, chan_recv(SVC, &mut out, CHAN_NONBLOCK, &mut info) == ERROR_ACCESS_DENIED, "recv on the svc channel must be ERROR_ACCESS_DENIED");

    // 2. List: edu and echo are running.
    let edu0 = wait_state("edu", "running", 3000, |p, _| p != 0);
    check!(n, edu0.is_some(), "edu service not running: {:?}", status("edu").map(|s| (s.2, s.3)));
    let echo0 = wait_state("echo", "running", 3000, |p, _| p != 0);
    check!(n, echo0.is_some(), "echo service not running");
    let (edu_pid, _) = edu0.unwrap_or((0, 0));
    let (echo_pid, echo_r0) = echo0.unwrap_or((0, 0));

    // 3. Echo by name: reflection, the service pid matches the list.
    let c = svc_connect("echo");
    check!(n, c.is_ok(), "svc_connect echo: {:?}", c);
    let c = c.unwrap_or(0);
    check!(n, matches!(echo(c, b"hello service", &mut out), Ok(13)) && &out[..13] == b"hello service", "echo");
    let r = echo(c, b"pid", &mut out);
    let pid_txt = r.map(|l| core::str::from_utf8(&out[..l]).unwrap_or("").parse::<u64>().unwrap_or(0));
    check!(n, pid_txt == Ok(echo_pid), "echo pid {:?} vs list {}", pid_txt, echo_pid);

    // 4. Service crash: the client gets ERROR_CLOSED, init restarts it (new pid, restarts+1).
    check!(n, chan_send(c, b"crash", 0) == 0, "send crash");
    let r = chan_recv(c, &mut out, 0, &mut info);
    check!(n, r == ERROR_CLOSED, "client of a crashed service must get ERROR_CLOSED: {}", r);
    close(c);
    let echo1 = wait_state("echo", "running", 3000, |p, r| p != echo_pid && p != 0 && r == echo_r0 + 1);
    check!(n, echo1.is_some(), "echo not restarted after crash: {:?}", status("echo").map(|s| (s.2, s.3)));
    let c = svc_connect("echo").unwrap_or(0);
    check!(n, matches!(echo(c, b"again", &mut out), Ok(5)), "restarted echo answers");
    close(c);

    // 5. edu through the service manager.
    let e = svc_connect("edu").unwrap_or(0);
    check!(n, edu_call(e, OP_PING, 0) == Ok((0, 0x010000ed)), "edu PING via svc");
    check!(n, edu_call(e, OP_FACT, 12) == Ok((0, 479001600)), "edu 12! via svc");
    // svcbench from the shell (without HW_ROOT) measures through the service from init.
    let (_st, l) = shell_cmd("svcbench", true, &mut out);
    let text = core::str::from_utf8(&out[..l]).unwrap_or("");
    check!(n, text.contains("via edud service: PING"), "svcbench from the shell: {:?}", text);

    // 6. edud killed – restart (the device comes back and the new instance claims it).
    check!(n, kill(edu_pid) == ERROR_ACCESS_DENIED, "a program killed a service it did not start (edud)");
    let mut kb = [0u8; 128];
    let r = svc_kill("edu", &mut kb);
    check!(n, matches!(r, Ok(t) if t.starts_with("killed edu")), "kill edu through init: {:?}", r);
    check!(n, matches!(edu_call(e, OP_PING, 0), Err(ERROR_CLOSED)), "client of killed edud must get ERROR_CLOSED");
    close(e);
    let edu1 = wait_state("edu", "running", 3000, |p, r| p != edu_pid && p != 0 && r == 1);
    check!(n, edu1.is_some(), "edud not restarted after kill: {:?}", status("edu").map(|s| (s.2, s.3)));
    let e = svc_connect("edu").unwrap_or(0);
    check!(n, edu_call(e, OP_FACT, 10) == Ok((0, 3628800)), "restarted edud answers");
    close(e);
    check!(n, dev_claim(HW_ROOT, bdf(0, 6, 0)) < 0, "svctest must not have HW_ROOT (slot 3 is the svc channel)");

    // 7. Unknown service -> channel closed; bad requests do not break init.
    let c = svc_connect("nope").unwrap_or(0);
    check!(n, chan_recv(c, &mut out, 0, &mut info) == ERROR_CLOSED, "unknown service must give ERROR_CLOSED");
    close(c);
    check!(n, chan_send(SVC, b"list", 0) == 0, "request without a handle is accepted (and ignored)");
    let (a, b) = channel_create().unwrap_or((0, 0));
    check!(n, chan_send_h(SVC, b"bogus", &[b], 0) == 0, "unknown request");
    check!(n, chan_recv(a, &mut out, 0, &mut info) == ERROR_CLOSED, "unknown request: handle closed by init");
    close(a);
    check!(n, state_is("echo", "running").is_some(), "init still answers after bad requests");

    // 8. The shell passes slot 3 to programs; without the channel `services` fails.
    let (st, l) = shell_cmd("services", true, &mut out);
    let text = core::str::from_utf8(&out[..l]).unwrap_or("");
    check!(n, st == 0 && text.contains("SERVICE") && text.contains("edu") && text.contains("running") && text.contains("/bin/echod"), "sh -c services: status {:#x} {:?}", st, text);
    let (_st, l) = shell_cmd("services", false, &mut out);
    let text2 = core::str::from_utf8(&out[..l]).unwrap_or("");
    check!(n, text2.contains("no service manager"), "services without slot 3: status {:#x} {:?}", _st, text2);

    // sysinfo (read-only) and SYSCTL (from init in slot 4, DUP only).
    let mut big = [0u8; 8192];
    let r = sysinfo("mem", &mut big);
    let mem_ok = matches!(r, Ok(l) if core::str::from_utf8(&big[..l]).unwrap_or("").contains("free frames"));
    check!(n, mem_ok, "sysinfo mem: {:?}", r);
    let r = sysinfo("lspci", &mut big);
    check!(n, matches!(r, Ok(l) if core::str::from_utf8(&big[..l]).unwrap_or("").contains("1234:11e8")), "sysinfo lspci: {:?}", r);
    check!(n, sysinfo("mem", &mut big[..4]) == Err(ERROR_BUFFER_TOO_SMALL), "sysinfo with a small buffer must be ERROR_BUFFER_TOO_SMALL");
    check!(n, sysinfo("mkfs 0", &mut big) == Err(ERROR_NOT_FOUND) && sysinfo("disk read 0 0", &mut big) == Err(ERROR_NOT_FOUND), "sysinfo must refuse mkfs / disk read");
    check!(n, syscall3(21, 0, 0, 0) == ERROR_NOT_IMPLEMENTED, "old kcmd (syscall 21) must be ERROR_NOT_IMPLEMENTED");
    check!(n, handle_info(SYSCTL) == Ok((KIND_SYSCTL, R_DUP)), "slot 4 SYSCTL from init: {:?}", handle_info(SYSCTL));
    check!(n, sysctl(SYSCTL, SYSCTL_SYNC, 0, 1) == 0, "sysctl sync");
    check!(n, sysctl(SYSCTL, 99, 0, 1) == ERROR_INVALID_ARGUMENT && sysctl(SYSCTL, SYSCTL_STRESS, 601, 1) == ERROR_INVALID_ARGUMENT, "sysctl: bad action / stress > 600 s must be ERROR_INVALID_ARGUMENT");
    check!(n, sysctl(SVC, SYSCTL_SYNC, 0, 1) == ERROR_INVALID_HANDLE && sysctl(60, SYSCTL_SYNC, 0, 1) == ERROR_INVALID_HANDLE, "sysctl without the SYSCTL handle must be ERROR_INVALID_HANDLE");
    let (a, b) = channel_create().unwrap_or((0, 0));
    check!(n, chan_send_h(a, b"x", &[SYSCTL], 0) == ERROR_ACCESS_DENIED && handle_info(SYSCTL).is_ok(), "SYSCTL cannot be sent in a message");
    close(a);
    close(b);
    let (_st, l) = shell_cmd("sync", true, &mut out);
    let t = core::str::from_utf8(&out[..l]).unwrap_or("");
    check!(n, t.contains("not allowed"), "shell without SYSCTL must refuse sync: {:?}", t);
    let (_st, l) = shell_cmd_with("sync", &[(SVC, 3), (SYSCTL, 4)], &mut out);
    let t = core::str::from_utf8(&out[..l]).unwrap_or("");
    check!(n, !t.contains("not allowed") && !t.contains("sync:"), "shell with SYSCTL: sync: {:?}", t);
    let (_st, l) = shell_cmd("mem", true, &mut out);
    let t = core::str::from_utf8(&out[..l]).unwrap_or("");
    check!(n, t.contains("free frames"), "sh -c mem via sysinfo: {:?}", t);

    // 9. 5 crashes in 30 s -> "broken", no restarts; connecting -> ERROR_CLOSED.
    //    (echo has already had 1 crash; intervals 200, 400, 800 ms.)
    let mut last = echo1.map(|x| x.0).unwrap_or(0);
    let mut crashes = 1;
    let mut broken = None;
    while crashes < 5 {
        let c = svc_connect("echo").unwrap_or(0);
        chan_send(c, b"crash", 0);
        let _ = chan_recv(c, &mut out, 0, &mut info);
        close(c);
        crashes += 1;
        if crashes == 5 {
            broken = wait_state("echo", "broken", 3000, |p, _| p == 0);
            break;
        }
        let prev = last;
        match wait_state("echo", "running", 5000, |p, _| p != prev && p != 0) {
            Some((p, _)) => last = p,
            None => break,
        }
    }
    check!(n, crashes == 5 && broken.is_some(), "echo broken after 5 crashes: {} crashes, {:?}", crashes, status("echo").map(|s| (s.2, s.3)));
    sleep_ms(300);
    check!(n, state_is("echo", "broken").is_some(), "broken service must not be restarted");
    let c = svc_connect("echo").unwrap_or(0);
    check!(n, chan_recv(c, &mut out, 0, &mut info) == ERROR_CLOSED, "connect to a broken service must give ERROR_CLOSED");
    close(c);

    println!(
        "svctest: {} checks OK, edu + echo started by init, restart after crash and kill, connect by name, 'services' via sh, broken after 5 failures, sysinfo + SYSCTL",
        n
    );
    0
}
