// rightstest <edu bdf> – the kernel's syscall rights table, tried through real
// syscalls.  The table comes from the kernel (sysinfo "rights"), so a new row is
// tested without changing this program.  For every handle argument that needs
// rights, and for every one of those rights: a real object of an allowed kind,
// a copy of its handle without exactly that right (handle_dup), the syscall with
// it – it must be refused with ERROR_ACCESS_DENIED; a handle of a wrong kind – ERROR_INVALID_HANDLE; the
// full handle – not refused by the gate (other arguments are invalid, so the
// call itself fails harmlessly: ERROR_INVALID_ARGUMENT / ERROR_INVALID_ADDRESS).  Also: a syscall number
// without a row is ERROR_NOT_IMPLEMENTED.
// Started by RIGHTS TEST with HW_ROOT, SYSCTL, INPUT and BLK (like init), so
// every kind of object exists.  Result: "rightstest: ..." and code 0, or the
// first failure and code 1.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const PATH: &str = "/rightstest.tmp";
/// Every argument that is not a handle: invalid for every call (no effect).
const JUNK: u64 = u64::MAX;

/// Full-rights handles, one per kind (index = kind); 0 = none.
struct Objects {
    by_kind: [u64; 16],
}

impl Objects {
    fn first_of(&self, kinds: u64) -> Option<u64> {
        (1..16).find(|&k| kinds & (1 << k) != 0 && self.by_kind[k] != 0).map(|k| self.by_kind[k])
    }
    /// A handle of a kind outside `kinds`.
    fn other_than(&self, kinds: u64) -> Option<u64> {
        (1..16).find(|&k| kinds & (1 << k) == 0 && self.by_kind[k] != 0).map(|k| self.by_kind[k])
    }
}

/// One handle argument of a row: register, kinds, rights always needed, and up
/// to two conditions (argument register, flag bit, the right it adds).
#[derive(Clone, Copy)]
struct Arg {
    reg: usize,
    kinds: u64,
    need: u64,
    conds: [(usize, u64, u64); 2],
    nc: usize,
}

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap_or(0)
}

fn call(nr: u64, a: &[u64; 6]) -> i64 {
    syscall6(nr, a[0], a[1], a[2], a[3], a[4], a[5])
}

fn main(args: Args) -> i32 {
    let edu = args.get(1).and_then(|s| s.parse::<u64>().ok());
    let mut objs = Objects { by_kind: [0; 16] };
    // What the kernel gave us (console, HW_ROOT, SYSCTL, INPUT, BLK).
    for h in 0..16 {
        if let Ok((k, _)) = handle_info(h) {
            if k < 16 && objs.by_kind[k as usize] == 0 {
                objs.by_kind[k as usize] = h;
            }
        }
    }
    let f = open(PATH, O_READ | O_WRITE | O_CREATE | O_TRUNC);
    if f >= 0 {
        objs.by_kind[KIND_FILE as usize] = f as u64;
    }
    if let Ok((r, _w)) = pipe() {
        objs.by_kind[KIND_PIPE as usize] = r;
    }
    if let Ok((a, _b)) = channel_create() {
        objs.by_kind[KIND_CHANNEL as usize] = a;
    }
    let s = shm_create(4096);
    if s >= 0 {
        objs.by_kind[KIND_SHM as usize] = s as u64;
    }
    let hw = objs.by_kind[KIND_HW_ROOT as usize];
    if let (true, Some(bdf)) = (hw != 0, edu) {
        let d = dev_claim(hw, bdf);
        if d >= 0 {
            objs.by_kind[KIND_DEVICE as usize] = d as u64;
            let q = irq_bind(d as u64);
            if q >= 0 {
                objs.by_kind[KIND_IRQ as usize] = q as u64;
            }
        }
    }
    let d = dir_open("/", O_READ | O_WRITE);
    if d >= 0 {
        objs.by_kind[KIND_DIR as usize] = d as u64;
    }
    for k in [KIND_CONSOLE, KIND_FILE, KIND_PIPE, KIND_CHANNEL, KIND_SHM, KIND_HW_ROOT, KIND_DEVICE, KIND_IRQ, KIND_SYSCTL, KIND_INPUT, KIND_BLK, KIND_DIR] {
        if objs.by_kind[k as usize] == 0 {
            println!("rightstest: FAIL no object of kind {}", k);
            unlink(PATH);
            return 1;
        }
    }

    static mut TEXT: [u8; 8192] = [0; 8192];
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(TEXT) };
    let n = match sysinfo("rights", buf) {
        Ok(n) => n,
        Err(e) => {
            println!("rightstest: FAIL sysinfo rights: {}", strerror(e));
            return 1;
        }
    };
    let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
    let (mut rows, mut with_handles, mut refused, mut wrong_kind, mut full_ok, mut in_call) = (0, 0, 0, 0, 0, 0);
    let mut fail = false;
    let mut max_nr = 0;
    for line in text.lines() {
        let (spec, note) = match line.split_once(" | ") {
            Some((a, b)) => (a, Some(b)),
            None => (line, None),
        };
        let mut w = spec.split_whitespace();
        let nr: u64 = w.next().and_then(|x| x.parse().ok()).unwrap_or(999);
        let name = w.next().unwrap_or("?");
        let _path = w.next();
        let mut hargs = [Arg { reg: 0, kinds: 0, need: 0, conds: [(0, 0, 0); 2], nc: 0 }; 6];
        let mut na = 0;
        for t in w {
            // "reg:kinds:need" then "+reg:bit:right" per condition.
            let mut parts = t.split('+');
            let mut p = parts.next().unwrap_or("").split(':');
            let (r, k, nd) = (p.next().unwrap_or("0"), p.next().unwrap_or("0"), p.next().unwrap_or("0"));
            if na < 6 {
                let mut a = Arg { reg: r.parse().unwrap_or(0), kinds: hex(k), need: hex(nd), conds: [(0, 0, 0); 2], nc: 0 };
                for c in parts {
                    let mut q = c.split(':');
                    let (cr, b, rt) = (q.next().unwrap_or("0"), q.next().unwrap_or("0"), q.next().unwrap_or("0"));
                    if a.nc < 2 {
                        a.conds[a.nc] = (cr.parse().unwrap_or(0), hex(b), hex(rt));
                        a.nc += 1;
                    }
                }
                hargs[na] = a;
                na += 1;
            }
        }
        rows += 1;
        max_nr = max_nr.max(nr);
        if note.is_some() {
            in_call += 1;
        }
        let hargs = &hargs[..na];
        if hargs.iter().all(|a| a.need == 0 && a.nc == 0) {
            continue;
        }
        with_handles += 1;
        // Every handle argument: a full handle of an allowed kind.
        let mut base = [JUNK; 6];
        let mut ok = true;
        for a in hargs {
            match objs.first_of(a.kinds) {
                Some(h) => base[a.reg] = h,
                None => ok = false,
            }
        }
        if !ok {
            println!("rightstest: FAIL {}: no object of an allowed kind", name);
            fail = true;
            break;
        }
        for (i, a) in hargs.iter().enumerate() {
            // The rights to take away: the base ones (every condition off), then each
            // condition switched on alone (e.g. a writable mapping, opening for writing).
            for v in 0..=a.nc {
                let mut args6 = base;
                for c in &a.conds[..a.nc] {
                    args6[c.0] = 0;
                }
                let mut need = a.need;
                if v > 0 {
                    let c = a.conds[v - 1];
                    args6[c.0] = c.1;
                    need |= c.2;
                }
                for bit in 0..8 {
                    let right = 1u64 << bit;
                    if need & right == 0 {
                        continue;
                    }
                    let reduced = handle_dup(base[a.reg], R_ALL & !right);
                    if reduced < 0 {
                        println!("rightstest: FAIL {}: handle_dup: {}", name, strerror(reduced));
                        fail = true;
                        break;
                    }
                    let mut t = args6;
                    t[a.reg] = reduced as u64;
                    let r = call(nr, &t);
                    close(reduced as u64);
                    if r != ERROR_ACCESS_DENIED {
                        println!("rightstest: FAIL {} (argument {}) without right {:#x}: {} instead of ERROR_ACCESS_DENIED", name, i, right, r);
                        fail = true;
                        break;
                    }
                    refused += 1;
                }
            }
            if fail {
                break;
            }
            // A handle of a kind the row does not allow.
            if let Some(other) = objs.other_than(a.kinds) {
                let mut t = base;
                t[a.reg] = other;
                let r = call(nr, &t);
                if r != ERROR_INVALID_HANDLE {
                    println!("rightstest: FAIL {} (argument {}) with a wrong kind: {} instead of ERROR_INVALID_HANDLE", name, i, r);
                    fail = true;
                    break;
                }
                wrong_kind += 1;
            }
        }
        if fail {
            break;
        }
        // Full rights: the gate lets it through (the call itself refuses the junk).
        let r = call(nr, &base);
        if r == ERROR_ACCESS_DENIED {
            println!("rightstest: FAIL {} with full rights refused (ERROR_ACCESS_DENIED)", name);
            fail = true;
            break;
        }
        full_ok += 1;
    }
    unlink(PATH);
    if fail {
        return 1;
    }
    // A number without a row.
    let r = call(max_nr + 1, &[0; 6]);
    if r != ERROR_NOT_IMPLEMENTED {
        println!("rightstest: FAIL syscall {} without a row: {} instead of ERROR_NOT_IMPLEMENTED", max_nr + 1, r);
        return 1;
    }
    if rows < 40 || with_handles < 10 {
        println!("rightstest: FAIL table too small: {} rows, {} with rights", rows, with_handles);
        return 1;
    }
    println!(
        "rightstest: {} syscalls in the table, {} need rights on handles: {} handles missing one right refused (ERROR_ACCESS_DENIED), {} of a wrong kind refused (ERROR_INVALID_HANDLE), {} with full rights let through, {} check a handle list themselves, no row = ERROR_NOT_IMPLEMENTED",
        rows, with_handles, refused, wrong_kind, full_ok, in_call
    );
    0
}
