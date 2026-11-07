// The kernel's random number generator (CSPRNG): a pool of entropy from several
// sources, a ChaCha20 generator with fast key erasure (desocrypto::rng), `getrandom`.
//
// Sources – everything is mixed into the pool (SHA-256); only DECLARED entropy counts
// towards readiness and reseeding.  The declared values are a TRUST POLICY, not
// something the health tests prove:
//
//   UEFI EFI_RNG_PROTOCOL  64 B from the loader, RAW algorithm: 1/2 bit per bit (hardware
//                          class); the firmware's default algorithm (a DRBG, usually
//                          fed by RDRAND): 0 – mixed only
//   RDSEED                 64-bit words             1/2 bit per bit   (hardware class)
//   RDRAND                 64-bit words             0 – mixed only
//   TSC jitter (boot)      time of a short loop     1 bit per 64 samples (timing class)
//   interrupt times        TSC at each interrupt    1 bit per 64 events  (timing class)
//
// The interrupt check is simpler than the jitter one (a time difference counts when it
// is not 0 and not equal to the previous one; the 64-difference window check would cost
// thousands of comparisons inside every interrupt handler) – that is why an interrupt
// counts 1/64 of a bit and why jitter and interrupts are one class (max).
//   RTC, HPET, CPUID, disk serial numbers           0 – they only tell machines apart
//
// Sources that may share a generator are not added up: the firmware's RNG often IS
// the CPU's RDRAND/RDSEED (OVMF does exactly that), so the hardware class counts
// max(UEFI, RDSEED); jitter and interrupt times both come from the TSC and can be
// correlated, so the timing class counts max(jitter, interrupts).  Counted entropy =
// hardware class + timing class.
//
// Ready = at least 256 counted bits.  `init` (at boot, before any process) waits for
// that – collecting jitter and interrupt times and saying so every second – and never
// pretends.  After it `fill` never blocks.
//
// Health checks on RDSEED / RDRAND (our own simple checks – not the NIST SP 800-90B
// tests, and passing them does not prove a source is good; they catch obvious
// failures): a start-up check (16 healthy words before any word counts), the carry
// flag of every instruction, a bounded number of retries;
// words 0 and all ones; the same word twice in a row; any word repeated within a
// window of the last 64 words (which also catches a repeated sequence of up to 32
// words).  A failed check or 3 failed reads in a row switch the source off until the
// next boot; the others carry on.
//
// Reseeding: checked inside `fill` every 60 s or after 1024 interrupts – whichever
// comes first.  A new key = SHA-256(key ‖ pool) only when the pool holds at least 128
// newly counted bits; less, and the pool keeps collecting (small reseeds would let
// someone who stole the state guess each small addition – the "catastrophic
// reseeding" idea from Fortuna).  After a reseed the pool starts empty.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::x86_64::cpu::MAX_CPUS;
use crate::arch::x86_64::percpu::PerCpu;
use crate::desocrypto::rng::KeyErasureRng;
use crate::desocrypto::sha256::Sha256;
use crate::sched::spin::{SpinLock, level};

/// Counted bits needed before the first output.
pub const READY_BITS: u32 = 256;
/// Newly counted bits needed for a reseed.
pub const RESEED_BITS: u32 = 128;
const RESEED_MS: u64 = 60_000;
const RESEED_IRQS: u64 = 1024;
/// Largest `getrandom` request.
pub const MAX_REQUEST: usize = 4096;

// ------------------------------------------------------------
// Hardware sources (RDSEED, RDRAND) and their health checks
// ------------------------------------------------------------

/// One read attempt: Some(word) when the instruction set the carry flag.
pub type ReadFn = fn() -> Option<u64>;

fn rdseed_once() -> Option<u64> {
    let v: u64;
    let ok: u8;
    // SAFETY: RDSEED has no side effects besides the result and the flags; only
    // called when CPUID says the CPU has it.
    unsafe { core::arch::asm!("rdseed {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok, options(nomem, nostack)) };
    (ok != 0).then_some(v)
}

fn rdrand_once() -> Option<u64> {
    let v: u64;
    let ok: u8;
    // SAFETY: as above (RDRAND).
    unsafe { core::arch::asm!("rdrand {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok, options(nomem, nostack)) };
    (ok != 0).then_some(v)
}

fn has_rdrand() -> bool {
    core::arch::x86_64::__cpuid(1).ecx & (1 << 30) != 0
}

fn has_rdseed() -> bool {
    // Leaf 7 exists when leaf 0 reports max >= 7.
    let max = core::arch::x86_64::__cpuid(0).eax;
    max >= 7 && core::arch::x86_64::__cpuid_count(7, 0).ebx & (1 << 18) != 0
}

const WINDOW: usize = 64;
/// Words a hardware source must pass before its words count.
pub const STARTUP_WORDS: u32 = 16;

/// Our own checks on a stream of 64-bit words (see the top of the file).
pub struct Health {
    window: [u64; WINDOW],
    filled: usize,
    pos: usize,
}

impl Health {
    pub const fn new() -> Health {
        Health { window: [0; WINDOW], filled: 0, pos: 0 }
    }

    /// Err(reason) when `w` fails a check; otherwise `w` joins the window.
    pub fn check(&mut self, w: u64) -> Result<(), &'static str> {
        if w == 0 {
            return Err("word 0");
        }
        if w == u64::MAX {
            return Err("word with all bits set");
        }
        let last = (self.pos + WINDOW - 1) % WINDOW;
        if self.filled > 0 && self.window[last] == w {
            return Err("the same word twice in a row");
        }
        if self.window[..self.filled.min(WINDOW)].contains(&w) {
            return Err("a word repeated within 64 words");
        }
        self.window[self.pos] = w;
        self.pos = (self.pos + 1) % WINDOW;
        self.filled = (self.filled + 1).min(WINDOW);
        Ok(())
    }
}

pub struct HwSource {
    pub name: &'static str,
    read: ReadFn,
    retries: u32,
    health: Health,
    failed_in_row: u32,
    /// Healthy words still to see before any word counts (a start-up check: the first
    /// word of a stuck source cannot be caught by comparing it with earlier ones).
    startup_left: u32,
    /// Why the source was switched off (None = working, or not present).
    pub disabled: Option<&'static str>,
    pub present: bool,
    pub words: u64,
}

impl HwSource {
    pub const fn new(name: &'static str, read: ReadFn, retries: u32, present: bool) -> HwSource {
        HwSource { name, read, retries, health: Health::new(), failed_in_row: 0, startup_left: STARTUP_WORDS, disabled: None, present, words: 0 }
    }

    pub fn usable(&self) -> bool {
        self.present && self.disabled.is_none()
    }

    fn disable(&mut self, why: &'static str) {
        if self.disabled.is_none() {
            self.disabled = Some(why);
            crate::serial_println!("[RNG] {} disabled until reboot: {}", self.name, why);
        }
    }

    /// A healthy word and whether it counts (false during the start-up check), or None
    /// (not present, switched off, the read failed).
    pub fn take(&mut self) -> Option<(u64, bool)> {
        if !self.usable() {
            return None;
        }
        let mut got = None;
        for _ in 0..self.retries.max(1) {
            if let Some(w) = (self.read)() {
                got = Some(w);
                break;
            }
            core::hint::spin_loop();
        }
        let Some(w) = got else {
            self.failed_in_row += 1;
            if self.failed_in_row >= 3 {
                self.disable("3 failed reads in a row");
            }
            return None;
        };
        self.failed_in_row = 0;
        if let Err(why) = self.health.check(w) {
            self.disable(why);
            return None;
        }
        self.words += 1;
        if self.startup_left > 0 {
            self.startup_left -= 1;
            return Some((w, false));
        }
        Some((w, true))
    }
}

// ------------------------------------------------------------
// The pool
// ------------------------------------------------------------

/// Classes of counted entropy (sources in one class may be correlated: max, not sum).
#[derive(Clone, Copy, Default, Debug)]
pub struct Credit {
    pub uefi: u32,
    pub rdseed: u32,
    pub jitter: u32,
    pub irq: u32,
}

impl Credit {
    pub fn hardware(&self) -> u32 {
        self.uefi.max(self.rdseed)
    }
    pub fn timing(&self) -> u32 {
        self.jitter.max(self.irq)
    }
    pub fn total(&self) -> u32 {
        self.hardware().saturating_add(self.timing())
    }
}

pub struct Pool {
    hash: Sha256,
    pub credit: Credit,
    pub mixed_bytes: u64,
}

impl Pool {
    pub fn new() -> Pool {
        Pool { hash: Sha256::new(), credit: Credit::default(), mixed_bytes: 0 }
    }

    /// Mixes data in (counts nothing).
    pub fn mix(&mut self, data: &[u8]) {
        self.hash.update(data);
        self.mixed_bytes += data.len() as u64;
    }

    /// The pool's 32 bytes; the pool starts empty again (its state wiped).
    pub fn extract(&mut self) -> [u8; 32] {
        let old = core::mem::replace(&mut self.hash, Sha256::new());
        self.credit = Credit::default();
        self.mixed_bytes = 0;
        old.finish().unwrap_or([0; 32])
    }

    /// Up to `words` healthy, counting words of `src` mixed in (the start-up words are
    /// mixed too, on top); how many counting words came.
    fn mix_hw(&mut self, src: &mut HwSource, words: usize) -> u32 {
        let mut got = 0;
        let mut tries = 0;
        while (got as usize) < words && tries < words + STARTUP_WORDS as usize {
            tries += 1;
            match src.take() {
                Some((w, counts)) => {
                    self.mix(&w.to_le_bytes());
                    if counts {
                        got += 1;
                    }
                }
                None => {
                    if !src.usable() {
                        break;
                    }
                }
            }
        }
        got
    }
}

// ------------------------------------------------------------
// TSC jitter and interrupt times
// ------------------------------------------------------------

/// Our own check of a window of 64 time differences: not counted when one value
/// makes up more than half the window, or repeats 8 times in a row (a stuck or coarse
/// clock).  Not the NIST tests; a passing window is merely not obviously bad.
pub fn timing_window_ok(d: &[u64]) -> bool {
    if d.len() < 2 {
        return false;
    }
    let mut run = 1;
    for i in 1..d.len() {
        if d[i] == d[i - 1] {
            run += 1;
            if run >= 8 {
                return false;
            }
        } else {
            run = 1;
        }
    }
    for i in 0..d.len() {
        let same = d.iter().filter(|&&x| x == d[i]).count();
        if same * 2 > d.len() {
            return false;
        }
    }
    true
}

fn rdtsc() -> u64 {
    // SAFETY: RDTSC has no side effects.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// `windows` windows of 64 samples of a short memory-touching loop; the differences
/// are mixed in; returns how many windows passed (1 counted bit each).
pub fn jitter(pool: &mut Pool, windows: usize, clock: fn() -> u64) -> u32 {
    let mut good = 0;
    let mut d = [0u64; 64];
    let mut idx = 0usize;
    // Scratch memory the loop touches (cache and TLB effects make its time vary).
    let mut scratch = [0u8; 4096];
    for _ in 0..windows {
        for slot in d.iter_mut() {
            let t0 = clock();
            for k in 0..16 {
                idx = (idx.wrapping_mul(31).wrapping_add(k + (t0 as usize & 63))) & 4095;
                let p = &mut scratch[idx];
                // SAFETY: `p` is a valid &mut u8 (volatile: the compiler keeps every access).
                unsafe {
                    let v = core::ptr::read_volatile(p);
                    core::ptr::write_volatile(p, v.wrapping_add(t0 as u8));
                }
            }
            *slot = clock().wrapping_sub(t0);
        }
        let mut bytes = [0u8; 64 * 8];
        for (i, v) in d.iter().enumerate() {
            bytes[8 * i..8 * i + 8].copy_from_slice(&v.to_le_bytes());
        }
        pool.mix(&bytes);
        if timing_window_ok(&d) {
            good += 1;
        }
    }
    good
}

/// Per-CPU interrupt times: two mixing words and counters, touched only by that CPU's
/// interrupt handler (atomic read-modify-write so the drain on another CPU loses no
/// event).
struct IrqMix {
    a: AtomicU64,
    b: AtomicU64,
    /// Events whose time difference passed the simple check (not 0, not the previous one).
    good: AtomicU64,
    /// All events (never reset – for "after 1024 interrupts").
    total: AtomicU64,
    last_tsc: AtomicU64,
    last_delta: AtomicU64,
}

static IRQ: PerCpu<IrqMix> = crate::per_cpu!(IrqMix {
    a: AtomicU64::new(0),
    b: AtomicU64::new(0),
    good: AtomicU64::new(0),
    total: AtomicU64::new(0),
    last_tsc: AtomicU64::new(0),
    last_delta: AtomicU64::new(0),
});

/// Called from the interrupt dispatchers (IRQ and MSI): a few tens of cycles.
#[inline]
pub fn irq_event(vector: u8) {
    let (t, c) = crate::arch::x86_64::clock::tsc_cpu();
    let m = &IRQ[(c as usize).min(MAX_CPUS - 1)];
    let n = m.total.fetch_add(1, Ordering::Relaxed);
    let v = t ^ ((vector as u64) << 56);
    m.a.fetch_xor(v.rotate_left((n.wrapping_mul(7) % 64) as u32), Ordering::Relaxed);
    m.b.fetch_add(v.wrapping_mul(0x9E37_79B9_7F4A_7C15), Ordering::Relaxed);
    let d = t.wrapping_sub(m.last_tsc.swap(t, Ordering::Relaxed));
    if d != 0 && d != m.last_delta.swap(d, Ordering::Relaxed) {
        m.good.fetch_add(1, Ordering::Relaxed);
    }
}

fn irq_total() -> u64 {
    IRQ.iter().map(|m| m.total.load(Ordering::Relaxed)).sum()
}

/// Takes what the interrupts collected into the pool; counted bits (good / 64).
fn drain_irq(pool: &mut Pool) -> u32 {
    let mut good = 0u64;
    let mut bytes = [0u8; 24];
    for m in IRQ.iter() {
        let g = m.good.swap(0, Ordering::Relaxed);
        if g == 0 && m.total.load(Ordering::Relaxed) == 0 {
            continue;
        }
        bytes[..8].copy_from_slice(&m.a.swap(0, Ordering::Relaxed).to_le_bytes());
        bytes[8..16].copy_from_slice(&m.b.swap(0, Ordering::Relaxed).to_le_bytes());
        bytes[16..].copy_from_slice(&g.to_le_bytes());
        pool.mix(&bytes);
        good += g;
    }
    (good / 64).min(u32::MAX as u64) as u32
}

// ------------------------------------------------------------
// The generator state
// ------------------------------------------------------------

#[derive(Clone, Copy, Default, Debug)]
pub struct Stats {
    pub ready_ms: u64,
    pub credit_at_ready: Credit,
    pub reseeds: u64,
    pub reseed_checks: u64,
    pub bytes_out: u64,
    pub calls: u64,
}

pub struct State {
    pub generator: Option<KeyErasureRng>,
    pub pool: Pool,
    pub rdseed: HwSource,
    pub rdrand: HwSource,
    last_check_ms: u64,
    last_check_irqs: u64,
    pub stats: Stats,
}

impl State {
    pub fn new(rdseed: HwSource, rdrand: HwSource) -> State {
        State { generator: None, pool: Pool::new(), rdseed, rdrand, last_check_ms: 0, last_check_irqs: 0, stats: Stats::default() }
    }

    /// Hardware words into the pool: RDSEED counted (32 bits per healthy word), RDRAND
    /// mixed only.
    pub fn collect_hw(&mut self, words: usize) {
        let got = self.pool.mix_hw(&mut self.rdseed, words);
        self.pool.credit.rdseed = self.pool.credit.rdseed.saturating_add(got * 32);
        let _ = self.pool.mix_hw(&mut self.rdrand, words);
    }

    /// Starts the generator from the pool once it holds READY_BITS (false: not yet).
    pub fn try_start(&mut self, now_ms: u64) -> bool {
        if self.generator.is_some() {
            return true;
        }
        if self.pool.credit.total() < READY_BITS {
            return false;
        }
        self.stats.credit_at_ready = self.pool.credit;
        let mut seed = self.pool.extract();
        self.generator = Some(KeyErasureRng::new(&seed));
        crate::desocrypto::wipe(&mut seed);
        self.stats.ready_ms = now_ms;
        self.last_check_ms = now_ms;
        true
    }

    /// The reseed rule (top of the file): due every 60 s or after 1024 interrupts;
    /// then the interrupt times (`drain` mixes them and returns their counted bits) and
    /// fresh RDSEED/RDRAND words; a reseed only with >= RESEED_BITS new bits.
    pub fn maybe_reseed(&mut self, now_ms: u64, irqs: u64, drain: &mut dyn FnMut(&mut Pool) -> u32) -> bool {
        let due = now_ms.wrapping_sub(self.last_check_ms) >= RESEED_MS || irqs.wrapping_sub(self.last_check_irqs) >= RESEED_IRQS;
        if !due {
            return false;
        }
        self.last_check_ms = now_ms;
        self.last_check_irqs = irqs;
        self.stats.reseed_checks += 1;
        let bits = drain(&mut self.pool);
        self.pool.credit.irq = self.pool.credit.irq.saturating_add(bits);
        self.collect_hw(4);
        if self.pool.credit.total() < RESEED_BITS {
            return false;
        }
        let mut fresh = self.pool.extract();
        if let Some(g) = self.generator.as_mut() {
            g.reseed(&fresh);
        }
        crate::desocrypto::wipe(&mut fresh);
        self.stats.reseeds += 1;
        true
    }

    /// Output bytes (the generator must be started).
    pub fn fill(&mut self, out: &mut [u8]) {
        if let Some(g) = self.generator.as_mut() {
            g.fill(out);
            self.stats.calls += 1;
            self.stats.bytes_out += out.len() as u64;
        }
    }
}

// ------------------------------------------------------------
// The kernel's instance
// ------------------------------------------------------------

static STATE: SpinLock<Option<State>> = SpinLock::new("random", level::RANDOM, None);
static READY: AtomicBool = AtomicBool::new(false);
/// 64 bytes from the firmware's RNG (copied from BootInfo at the very start).
static mut BOOT_SEED: [u8; 64] = [0; 64];
/// What the firmware gave (BootInfo `rng_seed_kind`): 0 none, 1 RAW, 2 its default algorithm.
static BOOT_SEED_KIND: AtomicU64 = AtomicU64::new(0);
pub const SEED_NONE: u64 = 0;
pub const SEED_RAW: u64 = 1;
pub const SEED_DEFAULT: u64 = 2;

/// At the very start of `kernel_main`: the firmware's bytes from BootInfo are copied
/// and wiped there (BootInfo memory is reused later).
pub fn take_boot_seed(boot: &crate::bootinfo::BootInfo) {
    let kind = boot.rng_seed_kind;
    // BootInfo is the loader's writable memory, handed over by address; the field is
    // read and wiped through a raw pointer (volatile) and never read again.
    let p = core::ptr::addr_of!(boot.rng_seed) as *mut [u8; 64];
    // SAFETY: BootInfo lives in writable loader memory; single CPU at this point.
    unsafe {
        let s = core::ptr::read_volatile(p);
        BOOT_SEED = s;
        core::ptr::write_volatile(p, [0; 64]);
    }
    BOOT_SEED_KIND.store(if kind <= SEED_DEFAULT { kind } else { SEED_NONE }, Ordering::SeqCst);
}

/// Our own check of the firmware's bytes: not one repeated byte, the halves differ.
pub fn boot_seed_plausible(s: &[u8; 64]) -> bool {
    !s.iter().all(|&b| b == s[0]) && s[..32] != s[32..]
}

/// Bits the firmware's bytes count (a trust policy, like RDSEED's): only the RAW
/// algorithm – entropy straight from the source – counts, ½ bit per bit (256 for 64
/// bytes), and only when the bytes look plausible.  The default algorithm is usually a
/// DRBG fed by RDRAND (OVMF, many PCs); its source cannot be told from here, so it is
/// mixed and counts 0 – exactly like RDRAND.
pub fn uefi_credit(kind: u64, seed: &[u8; 64]) -> u32 {
    if kind == SEED_RAW && boot_seed_plausible(seed) { 256 } else { 0 }
}

/// What the firmware's RNG gave at boot: "raw", "default" (a DRBG – not counted) or "no".
#[cfg_attr(not(selftest), allow(dead_code))]
pub fn boot_seed_kind() -> &'static str {
    match BOOT_SEED_KIND.load(Ordering::SeqCst) {
        SEED_RAW => "raw",
        SEED_DEFAULT => "default",
        _ => "no",
    }
}

pub fn is_ready() -> bool {
    READY.load(Ordering::Acquire)
}

/// Collects until READY_BITS are counted (boot, before any process).  Waits as long
/// as it must – with a line every second – instead of pretending.
pub fn init() {
    let t0 = crate::time::uptime_ms();
    let mut st = State::new(
        HwSource::new("RDSEED", rdseed_once, 100, has_rdseed()),
        HwSource::new("RDRAND", rdrand_once, 10, has_rdrand()),
    );
    // Not counted: they only tell machines and boots apart.
    let rtc = crate::drivers::rtc::now().to_unix();
    st.pool.mix(&rtc.to_le_bytes());
    st.pool.mix(&rdtsc().to_le_bytes());
    st.pool.mix(&crate::arch::x86_64::clock::stamp().to_le_bytes());
    for leaf in [0u32, 1, 0x8000_0002, 0x8000_0003, 0x8000_0004] {
        let r = core::arch::x86_64::__cpuid(leaf);
        for w in [r.eax, r.ebx, r.ecx, r.edx] {
            st.pool.mix(&w.to_le_bytes());
        }
    }
    // The firmware's RNG.
    // SAFETY: written once by take_boot_seed before this; single CPU at boot.
    let mut seed = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BOOT_SEED)) };
    let kind = BOOT_SEED_KIND.load(Ordering::SeqCst);
    if kind != SEED_NONE {
        st.pool.mix(&seed);
    }
    st.pool.credit.uefi = uefi_credit(kind, &seed);
    let uefi = match (kind, st.pool.credit.uefi) {
        (SEED_RAW, 0) => "RAW, implausible (not counted)",
        (SEED_RAW, _) => "RAW",
        (SEED_DEFAULT, _) => "default algorithm (a DRBG – mixed, not counted)",
        _ => "no",
    };
    crate::desocrypto::wipe(&mut seed);
    // SAFETY: as above.
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(BOOT_SEED), [0; 64]) };
    // RDSEED (8 words = 256 counted bits) and RDRAND (mixed).
    st.collect_hw(8);
    // Timing: always one round of jitter (4096 samples), more while not ready.
    st.pool.credit.jitter = jitter(&mut st.pool, 64, rdtsc);
    let mut said = t0;
    while st.pool.credit.total() < READY_BITS {
        let more = jitter(&mut st.pool, 64, rdtsc);
        st.pool.credit.jitter = st.pool.credit.jitter.saturating_add(more);
        let bits = drain_irq(&mut st.pool);
        st.pool.credit.irq = st.pool.credit.irq.saturating_add(bits);
        if st.rdseed.usable() {
            st.collect_hw(1);
        }
        let now = crate::time::uptime_ms();
        if now - said >= 1000 {
            said = now;
            crate::serial_println!(
                "[RNG] waiting for entropy: {}/{} bits (hardware {}: uefi {}, rdseed {}; timing {}: jitter {}, irq {})",
                st.pool.credit.total(),
                READY_BITS,
                st.pool.credit.hardware(),
                st.pool.credit.uefi,
                st.pool.credit.rdseed,
                st.pool.credit.timing(),
                st.pool.credit.jitter,
                st.pool.credit.irq
            );
        }
    }
    let c = st.pool.credit;
    let now = crate::time::uptime_ms();
    st.last_check_irqs = irq_total();
    st.try_start(now);
    crate::serial_println!(
        "[RNG] ready in {} ms: {} bits counted (hardware max(uefi {}, rdseed {}) + timing max(jitter {}, irq {})); UEFI RNG {}, RDSEED {}, RDRAND {} (mixed, 0 bits)",
        now - t0,
        c.total(),
        c.uefi,
        c.rdseed,
        c.jitter,
        c.irq,
        uefi,
        src_state(&st.rdseed),
        src_state(&st.rdrand)
    );
    st.stats.ready_ms = now - t0;
    // Tests: the first bytes of this start (tests/test.sh compares them with the
    // restart's – a new start must give new numbers).
    #[cfg(selftest)]
    {
        let mut b = [0u8; 16];
        st.fill(&mut b);
        let mut h = [0u8; 32];
        crate::serial_println!("[RNG] boot sample {}", crate::desocrypto::hex(&b, &mut h).unwrap_or("?"));
    }
    *STATE.lock() = Some(st);
    READY.store(true, Ordering::Release);
}

fn src_state(s: &HwSource) -> &'static str {
    match (s.present, s.disabled) {
        (false, _) => "absent",
        (true, None) => "on",
        (true, Some(_)) => "disabled",
    }
}

/// Random bytes for the kernel and for `getrandom`.  Never blocks after `init`.
pub fn fill(out: &mut [u8]) {
    if !is_ready() {
        init();
    }
    let mut g = STATE.lock();
    let Some(st) = g.as_mut() else { return };
    st.maybe_reseed(crate::time::uptime_ms(), irq_total(), &mut drain_irq);
    st.fill(out);
}

/// Data that only tells this machine apart (serial numbers): mixed, 0 bits counted.
pub fn mix_identity(data: &[u8]) {
    if let Some(st) = STATE.lock().as_mut() {
        st.pool.mix(data);
    }
}

/// For `sysinfo counters` and `[RESULT-RNG]`: (stats, sources text).
pub fn summary() -> (Stats, [(&'static str, &'static str); 2]) {
    match STATE.lock().as_ref() {
        Some(st) => (st.stats, [(st.rdseed.name, src_state(&st.rdseed)), (st.rdrand.name, src_state(&st.rdrand))]),
        None => (Stats::default(), [("RDSEED", "?"), ("RDRAND", "?")]),
    }
}


