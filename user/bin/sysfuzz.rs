// System call fuzzer: children invoke random syscalls with random and
// extreme arguments (0, -1, 2^64-1, kernel addresses, near-overflows,
// a real process buffer with a wrong length, random handle numbers...).
// The program may get any error or die (#PF in its own memory),
// but the KERNEL MUST NOT CRASH or hang.
//
// Children start without any handles (spawn_ex with an empty map): no console,
// HW_ROOT, SYSCTL, INPUT, BLK – they cannot break anything but themselves.
// Every other child runs in the file sandbox (SPAWN_NO_FILES) with one file
// handle from the parent – path calls must be refused, whatever the arguments.  Skipped:
// exit, spawn / spawn_ex (fork bomb – limits are handled separately), kill
// (could kill the parent or init).  A child stuck in a blocking
// call (sleep, wait_many, recv) is killed by the parent after a deadline – this also
// exercises cleanup of a process in the middle of a syscall.
//
// `sysfuzz [children] [calls]` – result: "sysfuzz: N children, M calls, ..."
// and exit code 0.  Child mode: `sysfuzz child <seed> <calls>`.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

/// Highest syscall number + a few nonexistent ones (ERROR_NOT_IMPLEMENTED).
const MAX_SYS: u64 = 56;
/// How many children at once (SMP: several CPUs in the kernel at the same time).
const PARALLEL: usize = 8;
/// Deadline for one child – then kill.
const CHILD_MS: u64 = 4000;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

static mut BUF: [u8; 16384] = [0; 16384];

fn buf_ptr() -> u64 {
    core::ptr::addr_of!(BUF) as u64
}

/// One argument: "boundary" values more often than fully random ones.
fn arg(r: &mut Rng) -> u64 {
    let b = buf_ptr();
    match r.below(20) {
        0 => 0,
        1 => 1,
        2 => u64::MAX,
        3 => u64::MAX - 4094,
        4 => 1 << 63,
        5 => 0x0000_7fff_ffff_f000,
        6 => 0xffff_8000_0000_0000,
        7 => 0xffff_ffff_8000_0000,
        8 => b,
        9 => b + r.below(16384),
        10 => b + 16384 - r.below(64),
        11 => r.below(70),        // handle numbers
        12 => r.below(8),         // existing handles (objects created at the start)
        13 => 4096,
        14 => 1 << 32,
        15 => r.below(1 << 20),
        16 => 0x0000_1000_0000_0000 + (r.below(1 << 16) << 12), // mmap area
        17 => (u32::MAX as u64) + r.below(16),
        _ => r.next(),
    }
}

fn child(seed: u64, calls: u64) -> i32 {
    let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    // Buffer: random bytes, sometimes a short ASCII string (paths, sysinfo names).
    unsafe {
        let p = core::ptr::addr_of_mut!(BUF) as *mut u8;
        for i in 0..16384 {
            *p.add(i) = match r.below(4) {
                0 => b'a' + r.below(26) as u8,
                1 => 0,
                _ => r.next() as u8,
            };
        }
    }
    // Real objects under small handle numbers – so that calls
    // get further than "bad handle" (pipes, channels, shared memory, a file).
    let _ = pipe();
    let _ = channel_create();
    let _ = channel_create();
    let _ = shm_create(8192);
    let _ = open("f", O_READ | O_WRITE | O_CREATE);
    let start = uptime_ms();
    // Which calls succeeded at least once (>= 0) – a measure of the fuzzer getting
    // further than the first argument check.
    let mut hit = [false; MAX_SYS as usize + 1];
    for _ in 0..calls {
        let n = r.below(MAX_SYS + 1);
        if matches!(n, SYS_EXIT | SYS_SPAWN | SYS_SPAWN_EX | SYS_KILL) {
            continue;
        }
        let mut a = [0u64; 6];
        for x in a.iter_mut() {
            *x = arg(&mut r);
        }
        // Do not sleep through the whole deadline in one sleep.
        if n == SYS_SLEEP && r.below(1000) != 0 {
            a[0] %= 20;
        }
        if syscall6(n, a[0], a[1], a[2], a[3], a[4], a[5]) >= 0 {
            hit[n as usize] = true;
        }
        if uptime_ms() - start > CHILD_MS / 2 {
            break;
        }
    }
    // Exit code = number of distinct successful calls (the parent sums them up).
    hit.iter().filter(|&&h| h).count() as i32
}

const ELF_PATH: &str = "/fuzz-elf";

static mut ELF: [u8; 65536] = [0; 65536];
static mut MUT: [u8; 65536] = [0; 65536];

/// Phase 2: corrupted ELF files.  A process can write any file and
/// run it, so the ELF parser and loader are also program input.  Copies of
/// /bin/hello with randomly changed bytes (mostly in the headers) –
/// spawn must reject or run them; the kernel must not crash.
/// (rejected, started, killed after the deadline)
fn elf_phase(rounds: u64, seed: u64) -> Result<(u64, u64, u64), &'static str> {
    let fd = open("/bin/hello", O_READ);
    if fd < 0 {
        return Err("cannot open /bin/hello");
    }
    let elf = unsafe { &mut *core::ptr::addr_of_mut!(ELF) };
    let m = unsafe { &mut *core::ptr::addr_of_mut!(MUT) };
    let mut len = 0usize;
    loop {
        let n = read(fd as u64, &mut elf[len..]);
        if n <= 0 {
            break;
        }
        len += n as usize;
    }
    close(fd as u64);
    if len < 64 {
        return Err("short /bin/hello");
    }
    let mut r = Rng(seed | 1);
    let (mut rejected, mut ran, mut killed) = (0, 0, 0);
    for _ in 0..rounds {
        m[..len].copy_from_slice(&elf[..len]);
        let mut mlen = len;
        for _ in 0..1 + r.below(8) {
            // 3/4 of the changes in the first 256 bytes (ELF header + program headers).
            let at = if r.below(4) != 0 { r.below(256) } else { r.below(len as u64) } as usize;
            m[at] = match r.below(4) {
                0 => 0,
                1 => 0xff,
                _ => r.next() as u8,
            };
        }
        if r.below(10) == 0 {
            mlen = r.below(len as u64) as usize; // truncated file
        }
        // Own path (children may have left a directory with this name in /fuzz).
        let fd = open(ELF_PATH, O_WRITE | O_CREATE | O_TRUNC);
        if fd < 0 {
            return Err("cannot create /fuzz-elf");
        }
        write(fd as u64, &m[..mlen]);
        close(fd as u64);
        let pid = spawn_ex(ELF_PATH, &["e"], &[], 0);
        if pid <= 0 {
            rejected += 1;
            continue;
        }
        ran += 1;
        let t = uptime_ms();
        loop {
            match wait(pid as u64, WNOHANG) {
                Ok((0, _)) if uptime_ms() - t > 300 => {
                    kill(pid as u64);
                    let _ = wait(pid as u64, 0);
                    killed += 1;
                    break;
                }
                Ok((0, _)) => sleep_ms(2),
                _ => break,
            }
        }
    }
    Ok((rejected, ran, killed))
}

fn num(args: &Args, i: usize, def: u64) -> u64 {
    args.get(i).and_then(|s| s.parse().ok()).unwrap_or(def)
}

fn main(args: Args) -> i32 {
    if args.get(1) == Some("child") {
        return child(num(&args, 2, 1), num(&args, 3, 1000));
    }
    let children = num(&args, 1, 32);
    let calls = num(&args, 2, 3000);
    let _ = mkdir("/fuzz");
    if chdir("/fuzz") < 0 {
        println!("sysfuzz: FAIL cannot chdir /fuzz");
        return 1;
    }
    let mut cbuf = [0u8; 24];
    let cstr = |v: u64, b: &mut [u8; 24]| -> usize {
        let mut t = [0u8; 24];
        let mut n = 0;
        let mut v = v;
        loop {
            t[n] = b'0' + (v % 10) as u8;
            n += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        for i in 0..n {
            b[i] = t[n - 1 - i];
        }
        n
    };
    let calls_s = {
        let mut b = [0u8; 24];
        let n = cstr(calls, &mut b);
        (b, n)
    };
    // (pid, start) of active children
    let mut live: [(i64, u64); PARALLEL] = [(0, 0); PARALLEL];
    let (mut started, mut done, mut killed, mut faulted, mut ok) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut kinds_max = 0u64;
    let mut sandboxed = 0u64;
    let shared = open("/fuzz/shared", O_READ | O_WRITE | O_CREATE);
    if shared < 0 {
        println!("sysfuzz: FAIL cannot create /fuzz/shared");
        return 1;
    }
    let shared = shared as u64;
    let t0 = uptime_ms();
    while done < children {
        // Fill the free slots.
        for slot in live.iter_mut() {
            if slot.0 == 0 && started < children {
                let n = cstr(started + 1, &mut cbuf);
                let seed = core::str::from_utf8(&cbuf[..n]).unwrap();
                let c = core::str::from_utf8(&calls_s.0[..calls_s.1]).unwrap();
                // Odd children: file sandbox, a shared file handle in slot 0.
                let sandbox = started % 2 == 1;
                let pid = if sandbox {
                    spawn_ex("/bin/sysfuzz", &["sysfuzz", "child", seed, c], &[(shared, 0)], SPAWN_NO_FILES)
                } else {
                    spawn_ex("/bin/sysfuzz", &["sysfuzz", "child", seed, c], &[], 0)
                };
                if sandbox && pid > 0 {
                    sandboxed += 1;
                }
                if pid <= 0 {
                    println!("sysfuzz: FAIL spawn: {}", pid);
                    return 1;
                }
                *slot = (pid, uptime_ms());
                started += 1;
            }
        }
        // Finished children; too long-running ones – kill.
        for slot in live.iter_mut() {
            if slot.0 == 0 {
                continue;
            }
            match wait(slot.0 as u64, WNOHANG) {
                Ok((0, _)) => {
                    if uptime_ms() - slot.1 > CHILD_MS {
                        kill(slot.0 as u64);
                        let _ = wait(slot.0 as u64, 0);
                        killed += 1;
                        done += 1;
                        *slot = (0, 0);
                    }
                }
                Ok((_, st)) => {
                    // Signal (kill by the kernel, #PF in its own memory) or
                    // a normal exit with the number of successful call kinds.
                    if st & STATUS_SIGNALED != 0 {
                        faulted += 1
                    } else {
                        ok += 1;
                        kinds_max = kinds_max.max(st);
                    }
                    done += 1;
                    *slot = (0, 0);
                }
                Err(e) => {
                    println!("sysfuzz: FAIL wait {}: {}", slot.0, e);
                    return 1;
                }
            }
        }
        sleep_ms(5);
    }
    // Randomly named files in /fuzz are cleaned up by the caller (the in-kernel test).
    let elf_rounds = num(&args, 3, 300);
    let (rej, ran, ek) = match elf_phase(elf_rounds, 0x5eed + children) {
        Ok(v) => v,
        Err(e) => {
            println!("sysfuzz: FAIL elf phase: {}", e);
            return 1;
        }
    };
    let _ = chdir("/");
    let _ = unlink(ELF_PATH);
    println!(
        "sysfuzz: {} children ({} in the file sandbox) x up to {} calls in {} ms: {} finished (up to {} syscall kinds succeeded), {} killed by the kernel (fault), {} stuck and killed; {} broken ELF files: {} rejected, {} ran ({} stuck and killed) - kernel survived",
        children,
        sandboxed,
        calls,
        uptime_ms() - t0,
        ok,
        kinds_max,
        faulted,
        killed,
        elf_rounds,
        rej,
        ran,
        ek
    );
    0
}
