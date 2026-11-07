// RNG TEST – the kernel's random number generator (random.rs): sources and how much
// they count (with substituted sources that fail on purpose), the generator (fast key
// erasure, reseeding, a stolen state), `getrandom` from user space (/bin/rngtest,
// /bin/random), several processes at once.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::desocrypto::rng::KeyErasureRng;
use crate::random::{self, Credit, Health, HwSource, Pool, State};
use crate::time::ticks;

macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[RNG TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

fn wait_for(ms: u64, cond: impl Fn() -> bool) -> bool {
    let end = ticks() + ms;
    while !cond() {
        if ticks() > end {
            return false;
        }
        crate::time::sleep_ms(1);
    }
    true
}

fn spawn(path: &str, args: &[&str]) -> Option<u64> {
    let opts = SpawnOptions { capture: true, ..SpawnOptions::default() };
    exec(path, args, "/", &opts).ok()
}

/// Waits for `id`; (how it ended, output).
fn finish(id: u64, ms: u64) -> Option<(ExitKind, String)> {
    if !wait_for(ms, || sched::task_info(id).is_none()) {
        let _ = sched::request_exit(id);
        return None;
    }
    let kind = exit_info(id)?.kind;
    Some((kind, String::from_utf8_lossy(&captured_output(id).unwrap_or_default()).into_owned()))
}

fn number_after(text: &str, key: &str) -> u64 {
    let Some(i) = text.find(key) else { return 0 };
    text[i + key.len()..].bytes().take_while(|b| b.is_ascii_digit()).fold(0, |v, b| v * 10 + (b - b'0') as u64)
}

// Substituted hardware sources (plain functions – `ReadFn` is a fn pointer).
static FAKE_N: AtomicU64 = AtomicU64::new(0);
fn fake_good() -> Option<u64> {
    // splitmix64 – different words, never 0 / all ones in practice.
    let mut z = FAKE_N.fetch_add(1, Ordering::Relaxed).wrapping_add(1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    Some(z ^ (z >> 31))
}
fn fake_const() -> Option<u64> {
    Some(0x0123_4567_89ab_cdef)
}
fn fake_zero() -> Option<u64> {
    Some(0)
}
fn fake_ones() -> Option<u64> {
    Some(u64::MAX)
}
fn fake_cycle() -> Option<u64> {
    // A sequence of 10 words over and over.
    Some(1 + FAKE_N.fetch_add(1, Ordering::Relaxed) % 10)
}
fn fake_fail() -> Option<u64> {
    None
}
static CLOCK: AtomicU64 = AtomicU64::new(0);
fn fake_clock() -> u64 {
    // Every reading 100 ticks later: every time difference the same.
    CLOCK.fetch_add(100, Ordering::Relaxed)
}

/// Takes up to `n` words; (words given, why the source was switched off).
fn drive(read: random::ReadFn, n: usize) -> (usize, Option<&'static str>) {
    let mut s = HwSource::new("fake", read, 3, true);
    let mut got = 0;
    for _ in 0..n {
        if s.take().is_some() {
            got += 1;
        }
    }
    (got, s.disabled)
}

fn good_state() -> State {
    State::new(HwSource::new("RDSEED", fake_good, 3, true), HwSource::new("RDRAND", fake_good, 3, true))
}

/// 1: sources and counting.
fn sources() -> bool {
    // The real machine (what `init` found at boot).
    let (st, src) = random::summary();
    let c = st.credit_at_ready;
    serial_println!(
        "[RNG TEST] this machine: ready after {} ms with {} bits (uefi {}, rdseed {}, jitter {}, irq {}); UEFI RNG {}, {} {}, {} {}",
        st.ready_ms,
        c.total(),
        c.uefi,
        c.rdseed,
        c.jitter,
        c.irq,
        if random::had_boot_seed() { "gave bytes" } else { "absent" },
        src[0].0,
        src[0].1,
        src[1].0,
        src[1].1
    );
    macro_rules! ck {
        ($cond:expr, $($msg:tt)*) => {
            if !$cond {
                serial_println!("[RNG TEST] FAIL: {}", format_args!($($msg)*));
                return false;
            }
        };
    }
    ck!(c.total() >= random::READY_BITS, "the generator started with {} counted bits", c.total());
    // Health checks.
    ck!(drive(fake_good, 300) == (300, None), "a good source was refused: {:?}", drive(fake_good, 300));
    let (n, why) = drive(fake_const, 10);
    ck!(n == 1 && why == Some("the same word twice in a row"), "a constant source: {} words, {:?}", n, why);
    let (n, why) = drive(fake_zero, 10);
    ck!(n == 0 && why == Some("word 0"), "a source of zeros: {} words, {:?}", n, why);
    let (n, why) = drive(fake_ones, 10);
    ck!(n == 0 && why == Some("word with all bits set"), "a source of ones: {} words, {:?}", n, why);
    FAKE_N.store(0, Ordering::Relaxed);
    let (n, why) = drive(fake_cycle, 30);
    ck!(n == 10 && why == Some("a word repeated within 64 words"), "a repeating sequence: {} words, {:?}", n, why);
    let (n, why) = drive(fake_fail, 10);
    ck!(n == 0 && why == Some("3 failed reads in a row"), "a source that never succeeds: {} words, {:?}", n, why);
    let mut h = Health::new();
    ck!(h.check(5).is_ok() && h.check(6).is_ok() && h.check(5).is_err(), "a word repeated after one other passed");
    // Counting: RDSEED 32 bits per word, RDRAND nothing.
    let mut s = good_state();
    s.collect_hw(8);
    ck!(s.pool.credit.rdseed == 256 && s.pool.credit.total() == 256, "8 good RDSEED words: {:?}", s.pool.credit);
    let mut s = State::new(HwSource::new("RDSEED", fake_const, 3, true), HwSource::new("RDRAND", fake_good, 3, true));
    s.collect_hw(8);
    ck!(s.pool.credit.total() == 0 && s.rdseed.disabled.is_some() && s.rdrand.words == 8 + random::STARTUP_WORDS as u64, "a broken RDSEED and a good RDRAND counted {:?}", s.pool.credit);
    // The start-up check: the first 16 words of a source count nothing.
    let mut s1 = HwSource::new("fake", fake_good, 3, true);
    let counted = (0..20).filter(|_| matches!(s1.take(), Some((_, true)))).count();
    ck!(counted == 4, "{} of the first 20 words counted (want 4 after 16 start-up words)", counted);
    ck!(!s.try_start(0) && s.generator.is_none(), "the generator started with nothing counted");
    let mut s = State::new(HwSource::new("RDSEED", fake_fail, 3, false), HwSource::new("RDRAND", fake_good, 3, true));
    s.collect_hw(64);
    ck!(s.pool.credit.total() == 0 && !s.try_start(0), "RDRAND alone made the generator ready");
    // Classes: sources that may share a generator count once (max, not sum).
    let c = Credit { uefi: 256, rdseed: 256, jitter: 200, irq: 200 };
    ck!(c.hardware() == 256 && c.timing() == 200 && c.total() == 456, "classes: {:?} -> {}", c, c.total());
    let c = Credit { uefi: 0, rdseed: 0, jitter: 255, irq: 255 };
    ck!(c.total() == 255 && c.total() < random::READY_BITS, "jitter + interrupts were added up: {}", c.total());
    // Timing checks and a coarse clock.
    let same = [7u64; 64];
    let mut run = [0u64; 64];
    for (i, v) in run.iter_mut().enumerate() {
        *v = if (10..18).contains(&i) { 5 } else { i as u64 + 100 };
    }
    let mut half = [0u64; 64];
    for (i, v) in half.iter_mut().enumerate() {
        *v = if i % 2 == 0 || i < 2 { 9 } else { i as u64 };
    }
    let mut varied = [0u64; 64];
    for (i, v) in varied.iter_mut().enumerate() {
        *v = 1000 + (i as u64 * 37) % 61;
    }
    ck!(!random::timing_window_ok(&same) && !random::timing_window_ok(&run) && !random::timing_window_ok(&half) && random::timing_window_ok(&varied), "the timing window check");
    let mut p = Pool::new();
    ck!(random::jitter(&mut p, 16, fake_clock) == 0 && p.mixed_bytes > 0, "a clock with equal steps was counted");
    // The firmware's bytes.
    let mut seed = [0u8; 64];
    let r = fake_good().unwrap_or(1);
    for (i, b) in seed.iter_mut().enumerate() {
        *b = (r >> ((i % 8) * 8)) as u8 ^ (i as u8).wrapping_mul(29);
    }
    let mut halves = seed;
    halves.copy_within(..32, 32);
    ck!(random::boot_seed_plausible(&seed) && !random::boot_seed_plausible(&[0; 64]) && !random::boot_seed_plausible(&[0xAB; 64]) && !random::boot_seed_plausible(&halves), "the firmware bytes check");
    serial_println!("[RNG TEST] 1/3 sources: 16 start-up words count nothing; health checks switch off a constant, zero, all-ones, repeating and never-succeeding source; RDSEED 32 bits/word, RDRAND 0; UEFI+RDSEED counted once (max), jitter+interrupts once (max); no start below 256 bits; equal clock steps count 0 PASS");
    true
}

/// 2: the generator.
fn generator() -> Option<u64> {
    macro_rules! ck {
        ($cond:expr, $($msg:tt)*) => {
            if !$cond {
                serial_println!("[RNG TEST] FAIL: {}", format_args!($($msg)*));
                return None;
            }
        };
    }
    let mut s = good_state();
    s.collect_hw(8);
    ck!(s.try_start(1000), "the generator did not start with 256 bits");
    ck!(s.pool.credit.total() == 0, "the pool kept its credit after starting the generator");
    // Fast key erasure: the key changes with every call; the thief.
    let k0 = s.generator.as_ref().map(|g| g.key_for_test()).unwrap_or([0; 32]);
    let mut a = [0u8; 48];
    s.fill(&mut a);
    let k1 = s.generator.as_ref().map(|g| g.key_for_test()).unwrap_or([0; 32]);
    ck!(k1 != k0, "the key did not change on a call");
    // Someone reads the state now: he predicts the next output exactly...
    let mut thief = KeyErasureRng::new(&k1);
    let (mut next, mut guess) = ([0u8; 64], [0u8; 64]);
    s.fill(&mut next);
    thief.fill(&mut guess);
    ck!(next == guess, "a copy of the key did not predict the output (the test is wrong)");
    // ...but not what came before (the key of that call is gone).
    let mut back = KeyErasureRng::new(&k1);
    let mut b2 = [0u8; 48];
    back.fill(&mut b2);
    ck!(b2 != a, "the stolen key gave an earlier output");
    // Reseed rules: not due -> nothing; due without 128 new bits -> no reseed, the
    // pool keeps collecting; with them -> a new key the thief does not know.
    let mut drain_none = |_: &mut Pool| 0u32;
    ck!(!s.maybe_reseed(2000, 0, &mut drain_none), "a reseed after 1 s without 1024 interrupts");
    s.rdseed = HwSource::new("RDSEED", fake_fail, 3, false);
    let mut drain_small = |p: &mut Pool| {
        p.mix(b"interrupt times");
        100u32
    };
    ck!(!s.maybe_reseed(70_000, 0, &mut drain_small), "a reseed with only 100 new bits");
    ck!(s.pool.credit.total() == 100 && s.stats.reseeds == 0, "the pool lost its 100 bits: {:?}", s.pool.credit);
    let key_before = s.generator.as_ref().map(|g| g.key_for_test()).unwrap_or([0; 32]);
    let mut drain_more = |p: &mut Pool| {
        p.mix(b"more interrupt times");
        40u32
    };
    // Due by interrupts (1024 since the last check), not by time.
    ck!(s.maybe_reseed(70_001, 1024, &mut drain_more), "no reseed with 140 bits after 1024 interrupts");
    let key_after = s.generator.as_ref().map(|g| g.key_for_test()).unwrap_or([0; 32]);
    ck!(key_after != key_before && s.pool.credit.total() == 0 && s.stats.reseeds == 1, "the reseed did not replace the key / empty the pool");
    let mut thief2 = KeyErasureRng::new(&key_before);
    let (mut o, mut g2) = ([0u8; 32], [0u8; 32]);
    s.fill(&mut o);
    thief2.fill(&mut g2);
    ck!(o != g2, "the old key still predicts the output after a reseed");
    // RDSEED words make a reseed by themselves (4 words = 128 bits).
    s.rdseed = HwSource::new("RDSEED", fake_good, 3, true);
    ck!(s.maybe_reseed(140_000, 1024, &mut drain_none) && s.stats.reseeds == 2, "4 RDSEED words did not reseed");
    // The kernel's generator: 1 MiB, no repeated 16-byte block, bits balanced.
    let mut blocks: Vec<u128> = Vec::new();
    blocks.reserve_exact(65536);
    let mut piece = [0u8; 4096];
    let mut ones = 0u64;
    let t0 = ticks();
    for _ in 0..256 {
        random::fill(&mut piece);
        for c in piece.chunks(16) {
            let mut w = [0u8; 16];
            w.copy_from_slice(c);
            let v = u128::from_le_bytes(w);
            ones += v.count_ones() as u64;
            blocks.push(v);
        }
    }
    let ms = (ticks() - t0).max(1);
    blocks.sort_unstable();
    let dup = blocks.windows(2).filter(|w| w[0] == w[1]).count();
    ck!(dup == 0, "{} repeated 16-byte blocks in 1 MiB", dup);
    let bits = 8 * 1024 * 1024u64;
    ck!(ones > bits / 2 - bits / 200 && ones < bits / 2 + bits / 200, "{} ones of {} bits", ones, bits);
    // Speed of the generator alone (ChaCha20) in the kernel.
    let mut g = KeyErasureRng::new(&[7; 32]);
    let start = ticks();
    let mut kib = 0u64;
    while ticks() - start < 200 {
        g.fill(&mut piece);
        kib += 4;
    }
    let chacha_kbs = kib * 1000 / (ticks() - start).max(1);
    serial_println!("[RNG TEST] 2/3 generator: the key replaced on every call, a stolen key predicts until a reseed and gives nothing earlier, no reseed below 128 new bits (due after 60 s or 1024 interrupts), 1 MiB in {} ms: 0 repeated blocks, {}.{:03}% ones PASS", ms, ones * 100 / bits, ones * 100_000 / bits % 1000);
    Some(chacha_kbs)
}

pub fn self_test() {
    serial_println!("[RNG TEST] Starting random number generator tests...");
    crate::selftest::begin();
    if !sources() {
        return;
    }
    let Some(chacha_kbs) = generator() else { return };

    // 3. getrandom from user space: one rngtest alone (its speed is the measurement),
    // then four at once, then /bin/random.
    let r = spawn("/bin/rngtest", &["rngtest"]).and_then(|id| finish(id, 60_000));
    check!(r.is_some(), "rngtest (alone) did not finish");
    let (kind, out) = r.unwrap_or((ExitKind::Exit(1), String::new()));
    check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "rngtest (alone): {:?} {:?}", kind, out.trim());
    let kbs = number_after(&out, "getrandom ");
    let mut ids = Vec::new();
    for _ in 0..4 {
        let id = spawn("/bin/rngtest", &["rngtest"]);
        check!(id.is_some(), "rngtest did not start");
        ids.push(id.unwrap_or(0));
    }
    let mut samples: Vec<String> = Vec::new();
    for id in ids {
        let r = finish(id, 60_000);
        check!(r.is_some(), "rngtest did not finish");
        let (kind, out) = r.unwrap_or((ExitKind::Exit(1), String::new()));
        check!(kind == ExitKind::Exit(0) && out.contains("checks OK"), "rngtest: {:?} {:?}", kind, out.trim());
        let s = out.split("samples").nth(1).unwrap_or("");
        let n = samples.len();
        samples.extend(s.split_whitespace().map(String::from));
        check!(samples.len() == n + 64, "rngtest gave {} samples", samples.len() - n);
    }
    samples.sort();
    let total = samples.len();
    samples.dedup();
    check!(samples.len() == total, "{} of {} samples from four processes were equal", total - samples.len(), total);
    let r = spawn("/bin/random", &["random", "16"]).and_then(|id| finish(id, 30_000));
    check!(r.is_some(), "random did not finish");
    let (kind, out) = r.unwrap_or((ExitKind::Exit(1), String::new()));
    let line = out.trim();
    check!(kind == ExitKind::Exit(0) && line.len() == 32 && line.bytes().all(|b| b.is_ascii_hexdigit()), "random 16: {:?} {:?}", kind, line);
    let r = spawn("/bin/random", &["random", "70000"]).and_then(|id| finish(id, 30_000));
    check!(matches!(r, Some((ExitKind::Exit(2), _))), "random 70000 was not refused: {:?}", r.map(|x| x.0));
    serial_println!("[RNG TEST] 3/3 getrandom: lengths 0 / 4096 / 4097, a wrong flag, null / kernel / code addresses refused; four processes at once: 256 samples, all different; /bin/random PASS");

    let (st, src) = random::summary();
    let c = st.credit_at_ready;
    serial_println!(
        "[RESULT-RNG] ver={} lib={} uefi={} rdseed={} rdrand={} credited={} hw_bits={} timing_bits={} ready_ms={} reseeds={} getrandom_kbs={} chacha20_kbs={}",
        crate::shell::VERSION,
        crate::desocrypto::VERSION,
        if random::had_boot_seed() { "yes" } else { "no" },
        src[0].1,
        src[1].1,
        c.total(),
        c.hardware(),
        c.timing(),
        st.ready_ms,
        st.reseeds,
        kbs,
        chacha_kbs
    );
    serial_println!("[RNG TEST] All random number generator tests passed!");
    crate::selftest::pass();
}
