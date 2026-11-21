// LKG – the last known good time: a lower bound for the wall clock that survives a restart.
//
// The wall clock is the RTC read at boot plus the uptime (drivers/rtc.rs).  Anyone with the
// firmware set-up can set the RTC to any date, and a dead battery resets it; the build date
// is only a weak lower bound.  The LKG is a better one: a time the system once knew to be
// true (v0.79 stage D: only an authenticated time from NTS raises it – never the RTC, plain
// NTP, an HTTP `Date` header, a certificate's notBefore or a time a program gives).  A clock
// earlier than the LKG is not plausible (reason 7), and TLS refuses to connect.
//
// Where: `/.deso/lkg` on the system volume – the DeSoFS volume mounted at /disk, written
// only by the kernel.  The VFS refuses every change under `/.deso` of a DeSoFS volume to
// everybody else (fs/mod.rs `is_reserved`: by the resolved volume and node, not by the text
// of a path).  No system volume (no disk, FAT32, read-only – a real SSD today): the LKG
// lives in memory only, from the build date on.
//
// The record (56 bytes, little-endian):
//   0  "DESOLKG1"      8  version (u16, 1)   10  source (u16: 2 NTS, 3 self-test)
//   12 0 (u32)         16 time (u64, Unix seconds UTC)
//   24 SHA-256 over bytes 0..24 – against an accident (a torn write, a bad sector), not
//      against a deliberate change by someone with the disk outside DeSo OS (out of scope,
//      docs/time/LKG.md).
//
// Reading (`load`, at boot after the system volume is mounted):
//   no file                                   -> the build date (nothing stored yet)
//   I/O error, wrong length, wrong magic,
//   wrong checksum, unknown version, > 2099  -> reason 8 "last known good time unreadable":
//                                                the clock is not plausible – never a quiet
//                                                fall-back to the build date
//   good                                      -> loaded
// A time in the record earlier than the build date is kept but never lowers the bound.
//
// Writing (`save_to`, atomic and durable): the whole record into `/.deso/lkg.new`, read
// back and compared, then `rename` onto `/.deso/lkg`.  Every DeSoFS operation is its own
// transaction (copy-on-write, flushed, one new superblock), so after a power loss at any
// point there is exactly the old record or the new one – never an empty or mixed file
// (LKG TEST cuts the power at every write of a save and checks).  A save that fails keeps
// the raised LKG in memory with `dirty` set; the next raise tries the save again first.
//
// The verdict on the clock (drivers/rtc.rs `time_status`) – the first reason that applies:
//   1-4, 6 (the RTC reading)  ->  8 (this file unreadable)  ->  5 (before the build date
//   minus 24 h)  ->  7 (earlier than the LKG – margin 0 s).
// Reason 7 compares with a stored or raised LKG; the build date keeps its 24 h tolerance
// as reason 5 (a clock kept in local time west of UTC).
//
// The time service (v0.79 stage D) – the only real source:
//   SYS_TIME_SET(t, u, servers) -> `set_time`: the kernel checks the numbers (servers 2..=3,
//   u <= 10 s, t - u >= the build date, t + u <= 2099, no overflow; t + u below the LKG is
//   refused), computes L = floor(T - U - 2 s) itself, raises the LKG to L when higher and
//   saves it, then sets the wall clock to max(T, LKG).  The LKG never goes down.
//   Repair write: while the file is unreadable (reason 8) every accepted call writes the
//   file anew with max(L, the LKG in memory) – also when that is not higher – and only a
//   write that succeeds makes the file good again.  A pending save (`dirty`) is retried by
//   every call.
//   SYS_TIME_BOUND -> `snapshot`: the bound for the time service's bootstrap,
//   B = max(the LKG in memory, the build date), with the LKG, its source, the file state and
//   the flags – one consistent picture, taken under the same lock as `set_time` and `load`.
//   Recovery mode = the file is unreadable (the same B rule; the flag only tells).

use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use crate::desocrypto::sha256::sha256;
use crate::drivers::rtc;
use crate::fs::{FileSystem, FsError};

pub const MAGIC: &[u8; 8] = b"DESOLKG1";
pub const VERSION: u16 = 1;
pub const RECORD_LEN: usize = 56;
/// Where the system volume is mounted, and the files on it (paths inside the volume).
pub const SYSTEM_MOUNT: &str = "/disk";
#[cfg_attr(not(selftest), allow(dead_code))]
pub const DIR: &str = "/.deso";
pub const FILE: &str = "/.deso/lkg";
#[cfg_attr(not(selftest), allow(dead_code))]
pub const TEMP: &str = "/.deso/lkg.new";

/// Who raised the LKG.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Source {
    /// Nothing stored: the build date.
    Build = 1,
    /// An authenticated time from NTS (v0.79 stage D).
    Nts = 2,
    /// The self-test switch (selftest builds only).
    Test = 3,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Build => "build date",
            Source::Nts => "NTS",
            Source::Test => "self-test",
        }
    }
    fn from_u16(v: u16) -> Option<Source> {
        match v {
            2 => Some(Source::Nts),
            3 => Some(Source::Test),
            _ => None,
        }
    }
}

/// Why a stored record is not usable (reason 8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Bad {
    Io = 1,
    Length = 2,
    Magic = 3,
    Version = 4,
    Checksum = 5,
    TooLate = 6,
    Source = 7,
}

impl Bad {
    pub fn as_str(self) -> &'static str {
        match self {
            Bad::Io => "read error",
            Bad::Length => "wrong length",
            Bad::Magic => "not an LKG record",
            Bad::Version => "unknown version",
            Bad::Checksum => "checksum does not match",
            Bad::TooLate => "time after 2099",
            Bad::Source => "unknown source",
        }
    }
    fn from_u8(v: u8) -> Option<Bad> {
        Some(match v {
            1 => Bad::Io,
            2 => Bad::Length,
            3 => Bad::Magic,
            4 => Bad::Version,
            5 => Bad::Checksum,
            6 => Bad::TooLate,
            7 => Bad::Source,
            _ => return None,
        })
    }
}

/// The state of the file on the system volume.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileState {
    /// Not looked at yet (before `load`).
    NotRead,
    /// No system volume: no DeSoFS mounted read-write at /disk.
    NoVolume,
    /// The volume has no LKG file yet.
    Missing,
    /// A good record was read (or written).
    Good,
    /// The file exists but cannot be used – reason 8.
    Unreadable(Bad),
}

// The state, readable from any CPU without a lock (time_status runs on every TLS check).
static SECS: AtomicU64 = AtomicU64::new(0); // stored / raised LKG; 0 = none
static SOURCE: AtomicU8 = AtomicU8::new(Source::Build as u8);
static FILE_STATE: AtomicU8 = AtomicU8::new(0); // encoded FileState
static DIRTY: AtomicBool = AtomicBool::new(false);
/// Tests: the next N saves fail (as a disk error would).
#[cfg(selftest)]
pub static FAIL_SAVES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
/// Raises, saves, set_time and snapshots run one at a time.
static LOCK: crate::sched::sync::KMutex = crate::sched::sync::KMutex::new_named("time lkg");

fn encode_state(s: FileState) -> u8 {
    match s {
        FileState::NotRead => 0,
        FileState::NoVolume => 1,
        FileState::Missing => 2,
        FileState::Good => 3,
        FileState::Unreadable(b) => 0x80 | b as u8,
    }
}

fn decode_state(v: u8) -> FileState {
    match v {
        1 => FileState::NoVolume,
        2 => FileState::Missing,
        3 => FileState::Good,
        v if v & 0x80 != 0 => FileState::Unreadable(Bad::from_u8(v & 0x7F).unwrap_or(Bad::Io)),
        _ => FileState::NotRead,
    }
}

// ---------------- the record ----------------

#[cfg_attr(not(selftest), allow(dead_code))]
pub fn encode(secs: u64, source: Source) -> [u8; RECORD_LEN] {
    let mut r = [0u8; RECORD_LEN];
    r[..8].copy_from_slice(MAGIC);
    r[8..10].copy_from_slice(&VERSION.to_le_bytes());
    r[10..12].copy_from_slice(&(source as u16).to_le_bytes());
    r[16..24].copy_from_slice(&secs.to_le_bytes());
    let h = sha256(&r[..24]);
    r[24..].copy_from_slice(&h);
    r
}

/// The time and source of a record; every field is checked, the checksum before the
/// fields it covers are trusted.
pub fn parse(r: &[u8]) -> Result<(u64, Source), Bad> {
    if r.len() != RECORD_LEN {
        return Err(Bad::Length);
    }
    if &r[..8] != MAGIC {
        return Err(Bad::Magic);
    }
    if sha256(&r[..24])[..] != r[24..] {
        return Err(Bad::Checksum);
    }
    if u16::from_le_bytes([r[8], r[9]]) != VERSION || r[12..16] != [0; 4] {
        return Err(Bad::Version);
    }
    let source = Source::from_u16(u16::from_le_bytes([r[10], r[11]])).ok_or(Bad::Source)?;
    let secs = u64::from_le_bytes(r[16..24].try_into().unwrap_or([0; 8]));
    if secs > rtc::LATEST {
        return Err(Bad::TooLate);
    }
    Ok((secs, source))
}

/// Reads the record from a mounted volume (paths inside it).
pub fn load_from(fs: &mut dyn FileSystem) -> Result<Option<(u64, Source)>, Bad> {
    let meta = match fs.stat(FILE) {
        Ok(m) => m,
        Err(FsError::NotFound) => return Ok(None),
        Err(_) => return Err(Bad::Io),
    };
    if meta.size != RECORD_LEN as u64 {
        return Err(Bad::Length);
    }
    let mut buf = [0u8; RECORD_LEN];
    let mut done = 0;
    while done < RECORD_LEN {
        match fs.read(FILE, done as u64, &mut buf[done..]) {
            Ok(0) => return Err(Bad::Length),
            Ok(n) => done += n,
            Err(_) => return Err(Bad::Io),
        }
    }
    parse(&buf).map(Some)
}

/// Writes the record atomically and durably: temporary file, read back, rename, sync.
#[cfg_attr(not(selftest), allow(dead_code))]
pub fn save_to(fs: &mut dyn FileSystem, secs: u64, source: Source) -> Result<(), FsError> {
    let rec = encode(secs, source);
    match fs.stat(DIR) {
        Ok(m) if m.kind == crate::fs::FileType::Directory => {}
        Ok(_) => return Err(FsError::NotADirectory),
        Err(FsError::NotFound) => fs.mkdir(DIR)?,
        Err(e) => return Err(e),
    }
    // A temporary file left by an interrupted save: start again.
    match fs.remove(TEMP) {
        Ok(()) | Err(FsError::NotFound) => {}
        Err(e) => return Err(e),
    }
    fs.create(TEMP)?;
    if fs.write(TEMP, 0, &rec)? != RECORD_LEN {
        return Err(FsError::Corrupt("short write of the LKG record"));
    }
    let mut back = [0u8; RECORD_LEN];
    if fs.read(TEMP, 0, &mut back)? != RECORD_LEN || back != rec {
        return Err(FsError::Corrupt("the LKG record read back differs"));
    }
    fs.sync()?;
    fs.rename(TEMP, FILE)?;
    fs.sync()
}

// ---------------- the verdict ----------------

/// The LKG reason 7 compares with: a stored or raised time (0 = none – the build date is
/// reason 5's business).
pub fn bound() -> u64 {
    SECS.load(Ordering::Acquire)
}

/// The verdict on the clock (pure – the tests call it with made-up states): the RTC's own
/// verdict, the time now, whether the LKG file is unreadable, the LKG.  Order: 1-4, 6, then
/// 8, then 5, then 7 (margin 0 s: one second below the LKG is too early).
pub fn verdict(rtc_verdict: Result<(), rtc::Implausible>, secs: u64, file_bad: bool, lkg: u64) -> Result<(), rtc::Implausible> {
    use rtc::Implausible as I;
    match rtc_verdict {
        Err(e) if e != I::BeforeBuild => return Err(e),
        _ => {}
    }
    if file_bad {
        return Err(I::LkgUnreadable);
    }
    rtc_verdict?;
    if secs < lkg {
        return Err(I::BeforeLkg);
    }
    Ok(())
}

pub fn file_state() -> FileState {
    decode_state(FILE_STATE.load(Ordering::Acquire))
}

pub fn file_bad() -> bool {
    matches!(file_state(), FileState::Unreadable(_))
}

pub fn source() -> Source {
    match SOURCE.load(Ordering::Acquire) {
        2 => Source::Nts,
        3 => Source::Test,
        _ => Source::Build,
    }
}

/// A raised LKG that could not be written yet.
pub fn dirty() -> bool {
    DIRTY.load(Ordering::Acquire)
}

// ---------------- the system volume ----------------

/// Saves the record on the system volume.  Err – no system volume, or the write failed.
fn save_system(secs: u64, source: Source) -> Result<(), ()> {
    #[cfg(selftest)]
    if FAIL_SAVES.load(Ordering::Acquire) > 0 {
        FAIL_SAVES.fetch_sub(1, Ordering::AcqRel);
        return Err(());
    }
    match on_system(|fs| save_to(fs, secs, source)) {
        Some(Ok(())) => Ok(()),
        _ => Err(()),
    }
}

/// Runs `f` on the system volume (the DeSoFS volume mounted at /disk, read-write) – the
/// kernel's own way in, past the VFS protection of /.deso.  None – no such volume.
fn on_system<R>(f: impl FnOnce(&mut dyn FileSystem) -> R) -> Option<R> {
    let mut f = Some(f);
    let mut out = None;
    crate::fs::with_desofs_at(SYSTEM_MOUNT, &mut |v| {
        if v.read_only_reason().is_none() {
            if let Some(f) = f.take() {
                out = Some(f(v));
            }
        }
    });
    out
}

/// Reads the LKG from the system volume (boot, after /disk is mounted; again whenever a
/// volume is mounted at /disk later).  It never lowers a bound already in memory: a later
/// mount of another volume, or of one without the file, keeps the higher time.
pub fn load() {
    let _g = LOCK.lock();
    let r = on_system(|fs| load_from(fs));
    let mem = SECS.load(Ordering::Acquire);
    let state = match r {
        None => FileState::NoVolume,
        Some(Ok(None)) => {
            // A volume without the file while memory holds a time (raised earlier in this
            // start, e.g. before a USB stick was plugged in): it must reach this volume – the
            // next accepted SYS_TIME_SET writes max(memory, its own L) (V080 rule D).
            if mem > 0 {
                DIRTY.store(true, Ordering::Release);
            }
            FileState::Missing
        }
        Some(Ok(Some((secs, src)))) => {
            // A stored time below the build date changes nothing (the build date bounds it
            // already); it is kept as it is.
            if secs > mem {
                SECS.store(secs, Ordering::Release);
                SOURCE.store(src as u8, Ordering::Release);
            } else if secs < mem {
                // An older file than memory (rule D): the higher time is written next time.
                DIRTY.store(true, Ordering::Release);
            }
            FileState::Good
        }
        // Not a quiet reset to the build date: the clock is not plausible until a new LKG
        // is written (stage D) or the volume is repaired.
        Some(Err(bad)) => FileState::Unreadable(bad),
    };
    FILE_STATE.store(encode_state(state), Ordering::Release);
    if let FileState::Unreadable(bad) = state {
        crate::serial_println!("[TIME] {}{}: {} - the clock is NOT plausible (reason 8) until a new last known good time is written", SYSTEM_MOUNT, FILE, bad.as_str());
    }
}

/// The system volume went away (a USB stick unplugged): the file state is "no volume" again;
/// the LKG stays in memory and a pending save waits for the next volume (rule D).
pub fn volume_gone() {
    let _g = LOCK.lock();
    FILE_STATE.store(encode_state(FileState::NoVolume), Ordering::Release);
}

/// What a raise did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(not(selftest), allow(dead_code))]
pub enum Raised {
    /// The LKG rose and is on the disk.
    Saved,
    /// Not above the current LKG – nothing changed (a pending save was retried).
    NotHigher,
    /// The LKG rose in memory only (no system volume, or the write failed – `dirty`).
    InMemory,
}

/// Raises the LKG to `secs` (never lowers it) and saves it at once.  Kernel only: the self-test
/// switch (`raise_for_test`); the time service goes through `set_time`.
#[cfg_attr(not(selftest), allow(dead_code))]
pub fn raise(secs: u64, source: Source) -> Raised {
    let _g = LOCK.lock();
    if secs > rtc::LATEST {
        return Raised::NotHigher;
    }
    let cur = SECS.load(Ordering::Acquire);
    let higher = secs > cur && secs > rtc::BUILD_EPOCH;
    if !higher && !DIRTY.load(Ordering::Acquire) {
        return Raised::NotHigher;
    }
    let (t, src) = if higher { (secs, source) } else { (cur, self::source()) };
    // Memory first: from now on the bound holds, whatever the disk does.
    SECS.store(t, Ordering::Release);
    SOURCE.store(src as u8, Ordering::Release);
    match save_system(t, src) {
        Ok(()) => {
            DIRTY.store(false, Ordering::Release);
            FILE_STATE.store(encode_state(FileState::Good), Ordering::Release);
            if higher { Raised::Saved } else { Raised::NotHigher }
        }
        Err(()) => {
            DIRTY.store(true, Ordering::Release);
            if higher { Raised::InMemory } else { Raised::NotHigher }
        }
    }
}

// ---------------- the time service ----------------

/// The largest uncertainty SYS_TIME_SET takes (ms).
pub const MAX_U_MS: u64 = 10_000;
/// L = floor(T - U - M): M = 2 s.
pub const MARGIN_MS: u64 = 2_000;

/// Why SYS_TIME_SET was refused (nothing changed).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused {
    /// servers not 2 or 3.
    Servers,
    /// u above 10 s.
    Uncertainty,
    /// t - u or t + u does not fit.
    Overflow,
    /// t - u before the build date.
    BeforeBuild,
    /// t + u after 2099.
    TooLate,
    /// t + u below the LKG – the whole interval is too early; the LKG never goes down.
    BelowLkg,
}

impl Refused {
    pub fn as_str(self) -> &'static str {
        match self {
            Refused::Servers => "servers must be 2 or 3",
            Refused::Uncertainty => "uncertainty above 10 s",
            Refused::Overflow => "t - u or t + u out of range",
            Refused::BeforeBuild => "t - u before the build date",
            Refused::TooLate => "t + u after 2099",
            Refused::BelowLkg => "t + u below the last known good time",
        }
    }
}

/// What an accepted SYS_TIME_SET did (the bits it returns).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SetDone {
    /// The LKG rose (to L).
    pub raised: bool,
    /// The file was written now (a raise, a repair or a retried save).
    pub saved: bool,
    /// The file was unreadable and the write was a repair (max(L, LKG)).
    pub repair: bool,
    /// The LKG is not on the disk (no system volume, or the write failed).
    pub not_saved: bool,
    /// The wall clock now (ms) and the LKG (s).
    pub clock_ms: u64,
    pub lkg: u64,
}

impl SetDone {
    pub const RAISED: u64 = 1;
    pub const SAVED: u64 = 2;
    pub const REPAIR: u64 = 4;
    pub const NOT_SAVED: u64 = 8;
    pub fn bits(&self) -> u64 {
        (if self.raised { Self::RAISED } else { 0 })
            | (if self.saved { Self::SAVED } else { 0 })
            | (if self.repair { Self::REPAIR } else { 0 })
            | (if self.not_saved { Self::NOT_SAVED } else { 0 })
    }
}

/// The numbers alone (pure – the tests call it): the interval [lo, hi] in ms, or why not.
pub fn check_set(t_ms: u64, u_ms: u64, servers: u64) -> Result<(u64, u64), Refused> {
    if !(2..=3).contains(&servers) {
        return Err(Refused::Servers);
    }
    if u_ms > MAX_U_MS {
        return Err(Refused::Uncertainty);
    }
    let (Some(lo), Some(hi)) = (t_ms.checked_sub(u_ms), t_ms.checked_add(u_ms)) else { return Err(Refused::Overflow) };
    if lo < rtc::BUILD_EPOCH * 1000 {
        return Err(Refused::BeforeBuild);
    }
    if hi > rtc::LATEST * 1000 + 999 {
        return Err(Refused::TooLate);
    }
    Ok((lo, hi))
}

/// SYS_TIME_SET after the right was checked (see the file comment).  In this order: the
/// numbers, L, the file (raise / repair / retried save), then the wall clock.
pub fn set_time(t_ms: u64, u_ms: u64, servers: u64) -> Result<SetDone, Refused> {
    let (lo, hi) = check_set(t_ms, u_ms, servers)?;
    let _g = LOCK.lock();
    let cur = SECS.load(Ordering::Acquire);
    if hi < cur.saturating_mul(1000) {
        return Err(Refused::BelowLkg);
    }
    let l = lo.saturating_sub(MARGIN_MS) / 1000;
    let unreadable = matches!(file_state(), FileState::Unreadable(_));
    let higher = l > cur && l > rtc::BUILD_EPOCH;
    let mut done = SetDone::default();
    // What to write, if anything: a raise; a repair of an unreadable file with
    // max(L, LKG) even when not higher; or the retry of a save that failed before.
    let write = if higher {
        Some((l, Source::Nts))
    } else if unreadable {
        // The value in memory when there is one (never lower); otherwise L itself – even below
        // the build date (it bounds nothing then, but it is what is certain).
        if cur > 0 { Some((cur, self::source())) } else { Some((l, Source::Nts)) }
    } else if DIRTY.load(Ordering::Acquire) {
        Some((cur, self::source()))
    } else {
        None
    };
    if let Some((t, src)) = write {
        // Memory first: from now on the bound holds, whatever the disk does.
        SECS.store(t, Ordering::Release);
        SOURCE.store(src as u8, Ordering::Release);
        done.raised = higher;
        done.repair = unreadable;
        match save_system(t, src) {
            Ok(()) => {
                DIRTY.store(false, Ordering::Release);
                FILE_STATE.store(encode_state(FileState::Good), Ordering::Release);
                done.saved = true;
            }
            // The file stays unreadable (reason 8) when it was; the next call tries again.
            Err(()) => DIRTY.store(true, Ordering::Release),
        }
    }
    done.not_saved = DIRTY.load(Ordering::Acquire);
    done.lkg = SECS.load(Ordering::Acquire);
    // The wall clock last – never below the LKG.
    let clock = t_ms.max(done.lkg.saturating_mul(1000));
    rtc::set_wall_ms(clock);
    done.clock_ms = clock;
    LAST_SET.store(t_ms, Ordering::Release);
    LAST_U.store(u_ms, Ordering::Release);
    LAST_AT.store(crate::time::uptime_ms(), Ordering::Release);
    LAST_SERVERS.store(servers as u8, Ordering::Release);
    Ok(done)
}

// The last accepted SYS_TIME_SET (for `date`).
static LAST_SET: AtomicU64 = AtomicU64::new(0);
static LAST_U: AtomicU64 = AtomicU64::new(0);
static LAST_AT: AtomicU64 = AtomicU64::new(0);
static LAST_SERVERS: AtomicU8 = AtomicU8::new(0);

/// SYS_TIME_BOUND's picture (40 bytes, little-endian – see `encode`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Snapshot {
    /// The bootstrap bound B = max(LKG in memory, build date).
    pub bound: u64,
    /// The LKG in memory (0 = nothing stored or raised).
    pub lkg: u64,
    pub build: u64,
    /// 0 none, 2 NTS, 3 self-test.
    pub source: u16,
    /// 0 not read, 1 no volume, 2 no file, 3 good, 4 unreadable.
    pub file: u16,
    /// Why unreadable (`Bad`), 0 otherwise.
    pub bad: u16,
    /// Bit 0 recovery mode (file unreadable), bit 1 not saved (dirty), bit 2 clock plausible.
    pub flags: u16,
}

pub const SNAPSHOT_LEN: usize = 40;
pub const FLAG_RECOVERY: u16 = 1;
pub const FLAG_NOT_SAVED: u16 = 2;
pub const FLAG_PLAUSIBLE: u16 = 4;

impl Snapshot {
    pub fn encode(&self) -> [u8; SNAPSHOT_LEN] {
        let mut b = [0u8; SNAPSHOT_LEN];
        b[0..8].copy_from_slice(&self.bound.to_le_bytes());
        b[8..16].copy_from_slice(&self.lkg.to_le_bytes());
        b[16..24].copy_from_slice(&self.build.to_le_bytes());
        b[24..26].copy_from_slice(&self.source.to_le_bytes());
        b[26..28].copy_from_slice(&self.file.to_le_bytes());
        b[28..30].copy_from_slice(&self.bad.to_le_bytes());
        b[30..32].copy_from_slice(&self.flags.to_le_bytes());
        b
    }
}

/// The bound rule (pure): B = max(LKG in memory, build date) – the same for a good file,
/// a missing one and an unreadable one (then it is recovery mode: the file's own value is
/// not known, so only what is in memory and the build date remain).
pub fn bootstrap_bound(lkg: u64, build: u64) -> u64 {
    lkg.max(build)
}

/// One consistent picture for SYS_TIME_BOUND (under the lock `set_time` and `load` take).
pub fn snapshot() -> Snapshot {
    let _g = LOCK.lock();
    let lkg = SECS.load(Ordering::Acquire);
    let state = file_state();
    let (file, bad) = match state {
        FileState::NotRead => (0, 0),
        FileState::NoVolume => (1, 0),
        FileState::Missing => (2, 0),
        FileState::Good => (3, 0),
        FileState::Unreadable(b) => (4, b as u16),
    };
    let source = if lkg == 0 { 0 } else { source() as u16 };
    let mut flags = 0;
    if file == 4 {
        flags |= FLAG_RECOVERY;
    }
    if DIRTY.load(Ordering::Acquire) {
        flags |= FLAG_NOT_SAVED;
    }
    if rtc::time_status().1.is_ok() {
        flags |= FLAG_PLAUSIBLE;
    }
    Snapshot { bound: bootstrap_bound(lkg, rtc::BUILD_EPOCH), lkg, build: rtc::BUILD_EPOCH, source, file, bad, flags }
}

/// One line for `date`: the last time the time service set the clock (or that it has not).
pub fn describe_sync() -> String {
    if !rtc::synced() {
        return String::from("not set by the time service in this boot (the clock is the RTC's)");
    }
    let ago = crate::time::uptime_ms().saturating_sub(LAST_AT.load(Ordering::Acquire)) / 1000;
    alloc::format!(
        "set by the time service {} s ago from {} NTS servers of different operators: {} UTC +-{} ms (correction {:+} ms)",
        ago,
        LAST_SERVERS.load(Ordering::Acquire),
        rtc::DateTime::from_unix(LAST_SET.load(Ordering::Acquire) / 1000),
        LAST_U.load(Ordering::Acquire),
        rtc::correction_ms()
    )
}

/// The self-test switch: the LKG raised like an authenticated time would (LKG TEST,
/// RESTART TEST).  Only in the self-test build.
#[cfg(selftest)]
pub fn raise_for_test(secs: u64) -> Raised {
    raise(secs, Source::Test)
}

/// Self-tests: the pending save forgotten – as when the time in memory came from a volume it
/// was already saved on (USB DISK TEST, rule D).
#[cfg(selftest)]
pub fn test_clear_dirty() {
    DIRTY.store(false, Ordering::Release);
}

/// Back to "nothing stored" in memory (LKG TEST, between its cases).
#[cfg(selftest)]
pub fn reset_for_test() {
    let _g = LOCK.lock();
    SECS.store(0, Ordering::Release);
    SOURCE.store(Source::Build as u8, Ordering::Release);
    DIRTY.store(false, Ordering::Release);
    FILE_STATE.store(encode_state(FileState::NotRead), Ordering::Release);
}

/// One line for `date` and sysinfo: the LKG, where it came from, and the file.
pub fn describe() -> String {
    let secs = bound();
    let state = file_state();
    let when = if secs > 0 { secs } else { rtc::BUILD_EPOCH };
    let file = match state {
        FileState::NotRead => String::from("not read yet"),
        FileState::NoVolume => alloc::format!("kept in memory only - no DeSoFS volume read-write at {}", SYSTEM_MOUNT),
        FileState::Missing => alloc::format!("nothing stored yet in {}{}", SYSTEM_MOUNT, FILE),
        FileState::Good => alloc::format!("{}{}", SYSTEM_MOUNT, FILE),
        FileState::Unreadable(b) => alloc::format!("{}{} UNREADABLE: {}", SYSTEM_MOUNT, FILE, b.as_str()),
    };
    // Without a system volume "kept in memory only" says it already.
    let saved = if dirty() && state != FileState::NoVolume { " - NOT SAVED (a write failed or this volume holds an older time; written with the next raise)" } else { "" };
    alloc::format!("last known good {} UTC ({}; {}){}", rtc::DateTime::from_unix(when), source().as_str(), file, saved)
}
