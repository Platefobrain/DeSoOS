// LKG – the last known good time: a lower bound for the wall clock that survives a restart.
//
// The wall clock is the RTC read at boot plus the uptime (drivers/rtc.rs).  Anyone with the
// firmware set-up can set the RTC to any date, and a dead battery resets it; the build date
// is only a weak lower bound.  The LKG is a better one: a time the system once knew to be
// true (v0.79 stage D: only an authenticated time from NTS raises it – never the RTC, plain
// NTP, an HTTP `Date` header, a certificate's notBefore or a time a program gives).  A clock
// earlier than the LKG is not plausible (reason 7), and TLS refuses to connect.
//
// Where: `/.desoos/lkg` on the system volume – the DeSoFS volume mounted at /disk, written
// only by the kernel.  The VFS refuses every change under `/.desoos` of a DeSoFS volume to
// everybody else (fs/mod.rs `is_reserved`: by the resolved volume and node, not by the text
// of a path).  No system volume (no disk, FAT32, read-only – a real SSD today): the LKG
// lives in memory only, from the build date on.
//
// The record (56 bytes, little-endian):
//   0  "DESOLKG1"      8  version (u16, 1)   10  source (u16: 2 NTS, 3 self-test)
//   12 0 (u32)         16 time (u64, Unix seconds UTC)
//   24 SHA-256 over bytes 0..24 – against an accident (a torn write, a bad sector), not
//      against a deliberate change by someone with the disk outside DeSoOS (out of scope,
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
// Writing (`save_to`, atomic and durable): the whole record into `/.desoos/lkg.new`, read
// back and compared, then `rename` onto `/.desoos/lkg`.  Every DeSoFS operation is its own
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
pub const DIR: &str = "/.desoos";
pub const FILE: &str = "/.desoos/lkg";
#[cfg_attr(not(selftest), allow(dead_code))]
pub const TEMP: &str = "/.desoos/lkg.new";

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
/// Raises and saves run one at a time.
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

/// Runs `f` on the system volume (the DeSoFS volume mounted at /disk, read-write) – the
/// kernel's own way in, past the VFS protection of /.desoos.  None – no such volume.
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
    let state = match r {
        None => FileState::NoVolume,
        Some(Ok(None)) => FileState::Missing,
        Some(Ok(Some((secs, src)))) => {
            // A stored time below the build date changes nothing (the build date bounds it
            // already); it is kept as it is.
            if secs > SECS.load(Ordering::Acquire) {
                SECS.store(secs, Ordering::Release);
                SOURCE.store(src as u8, Ordering::Release);
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

/// Raises the LKG to `secs` (never lowers it) and saves it at once.  Kernel only – no
/// syscall reaches this in stage C (stage D: the time service through SYS_TIME_SET).
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
    match on_system(|fs| save_to(fs, t, src)) {
        Some(Ok(())) => {
            DIRTY.store(false, Ordering::Release);
            FILE_STATE.store(encode_state(FileState::Good), Ordering::Release);
            if higher { Raised::Saved } else { Raised::NotHigher }
        }
        _ => {
            DIRTY.store(true, Ordering::Release);
            if higher { Raised::InMemory } else { Raised::NotHigher }
        }
    }
}

/// The self-test switch: the LKG raised like an authenticated time would (LKG TEST,
/// RESTART TEST).  Only in the self-test build.
#[cfg(selftest)]
pub fn raise_for_test(secs: u64) -> Raised {
    raise(secs, Source::Test)
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
    let saved = if dirty() { " - NOT SAVED (the write failed; retried with the next raise)" } else { "" };
    alloc::format!("last known good {} UTC ({}; {}){}", rtc::DateTime::from_unix(when), source().as_str(), file, saved)
}
