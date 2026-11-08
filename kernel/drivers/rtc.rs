// Real-time clock (CMOS RTC) – date and time.
//
// Used for file timestamps (FAT) and the `date` command.
// Registers: 0x00 s, 0x02 min, 0x04 h, 0x07 day, 0x08 month, 0x09 year
// (2 digits), 0x0B status B (bit 2 = binary instead of BCD, bit 1 = 24 h).
// RTC time is usually UTC (QEMU sets it that way by default; a machine that also runs
// Windows may keep local time – that cannot be detected).
// 0x0D status D (bit 7 = VRT: the RTC kept power, its contents are valid).

use crate::arch::x86_64::interrupts::without_interrupts;
use crate::arch::x86_64::port::{inb, outb};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl core::fmt::Display for DateTime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

fn cmos(reg: u8) -> u8 {
    without_interrupts(|| unsafe {
        outb(0x70, reg | 0x80); // bit 7: NMI disabled during the read
        let v = inb(0x71);
        outb(0x70, 0);
        v
    })
}

fn update_in_progress() -> bool {
    cmos(0x0A) & 0x80 != 0
}

fn raw() -> [u8; 6] {
    [cmos(0x00), cmos(0x02), cmos(0x04), cmos(0x07), cmos(0x08), cmos(0x09)]
}

// Reading the RTC takes ~45 port operations (two reads of six
// registers + the update flag; under KVM each one is an exit to QEMU, on hardware
// ~1 µs), and every file change calls it – also under the ramfs tree lock.
// We read the RTC once (at boot); afterwards time = boot reading + uptime.
use core::sync::atomic::{AtomicU64, Ordering};

/// Seconds since 1970-01-01 at the time of the RTC read (0 = not read yet).
static BASE_SECS: AtomicU64 = AtomicU64::new(0);
/// Uptime (ms) at that moment.
static BASE_MS: AtomicU64 = AtomicU64::new(0);

/// Days since 1970-01-01 ("days from civil" algorithm, H. Hinnant).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Inverse of `days_from_civil`: (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

impl DateTime {
    /// Seconds since 1970-01-01.
    pub fn to_unix(&self) -> u64 {
        let days = days_from_civil(self.year as i64, self.month.max(1) as u32, self.day.max(1) as u32);
        (days * 86400 + self.hour as i64 * 3600 + self.minute as i64 * 60 + self.second as i64).max(0) as u64
    }

    pub fn from_unix(secs: u64) -> DateTime {
        let (y, m, d) = civil_from_days((secs / 86400) as i64);
        let rem = secs % 86400;
        DateTime {
            year: y as u16,
            month: m as u8,
            day: d as u8,
            hour: (rem / 3600) as u8,
            minute: (rem / 60 % 60) as u8,
            second: (rem % 60) as u8,
        }
    }
}

/// Reads the RTC, stores the reference point and judges the clock (boot, single CPU).
pub fn init() {
    let (hw, stable) = read_hw_checked();
    let vrt = cmos(0x0D) & 0x80 != 0;
    BASE_MS.store(crate::time::uptime_ms(), Ordering::Relaxed);
    BASE_SECS.store(hw.to_unix().max(1), Ordering::Release);
    let v = match assess(&hw, vrt, stable, BUILD_EPOCH) {
        Ok(()) => 0,
        Err(e) => e as u8,
    };
    VERDICT.store(v, Ordering::Release);
    if v != 0 {
        crate::serial_println!("[RTC] {} UTC - clock not plausible: {}", hw, Implausible::from_u8(v).map_or("?", Implausible::as_str));
    }
}

/// Current date and time: RTC reading at boot + time since that moment
/// (no port access).  Before `init` – straight from the RTC.
pub fn now() -> DateTime {
    let base = BASE_SECS.load(Ordering::Acquire);
    if base == 0 {
        return read_hw();
    }
    let ms = crate::time::uptime_ms().saturating_sub(BASE_MS.load(Ordering::Relaxed));
    DateTime::from_unix(base + ms / 1000)
}

/// Date and time straight from the RTC (CMOS ports – slow; usually use `now`).
pub fn read_hw() -> DateTime {
    read_hw_checked().0
}

/// The RTC reading and whether two readings in a row agreed (within 6 tries).
fn read_hw_checked() -> (DateTime, bool) {
    // Read twice until both readings match (the RTC may have been updating).
    let mut last = [0xFFu8; 6];
    let mut r;
    let mut tries = 0;
    loop {
        let mut spins = 0;
        while update_in_progress() && spins < 100_000 {
            spins += 1;
        }
        r = raw();
        tries += 1;
        if r == last || tries > 5 {
            break;
        }
        last = r;
    }
    let stable = r == last;

    let status_b = cmos(0x0B);
    let bcd = status_b & 0x04 == 0;
    let conv = |v: u8| if bcd { (v & 0x0F) + (v >> 4) * 10 } else { v };

    let mut hour = r[2];
    let pm = hour & 0x80 != 0;
    hour = conv(hour & 0x7F);
    if status_b & 0x02 == 0 {
        // 12-hour mode
        if pm && hour != 12 {
            hour += 12;
        } else if !pm && hour == 12 {
            hour = 0;
        }
    }

    (
        DateTime {
            year: 2000 + conv(r[5]) as u16,
            month: conv(r[4]),
            day: conv(r[3]),
            hour,
            minute: conv(r[1]),
            second: conv(r[0]),
        },
        stable,
    )
}

// ---- Is the clock plausible? (the lower bound for certificate dates – DeSoTLS) ----
//
// `time_plausible` is a heuristic, not a guarantee: it refuses a lost battery, a broken
// reading and dates before the image was built, but anyone with access to the firmware can
// set any date inside the range – without NTP the RTC is all there is.

/// Seconds since 1970 when this image was built (build.sh: SOURCE_DATE_EPOCH when set, else
/// the build time) and where that came from.
pub const BUILD_EPOCH: u64 = parse_u64(env!("DESOOS_BUILD_EPOCH"));
pub const BUILD_EPOCH_SOURCE: &str = env!("DESOOS_BUILD_EPOCH_SOURCE");
/// The clock may be up to 24 h behind the build date (time zones, a build on a fast clock).
pub const BUILD_SLACK: u64 = 86_400;
/// 2099-12-31 23:59:59 – the RTC keeps two year digits (no century register read).
pub const LATEST: u64 = 4_102_444_799;

const fn parse_u64(s: &str) -> u64 {
    let b = s.as_bytes();
    let mut v = 0u64;
    let mut i = 0;
    while i < b.len() {
        assert!(b[i].is_ascii_digit(), "DESOOS_BUILD_EPOCH must be a number");
        v = v * 10 + (b[i] - b'0') as u64;
        i += 1;
    }
    v
}

/// Why the clock is not plausible.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Implausible {
    /// The RTC has not been read yet.
    NotRead = 1,
    /// Status register D bit 7 (VRT) clear: the RTC lost power, its contents are not valid.
    BatteryLost = 2,
    /// Two readings in a row never agreed.
    Unstable = 3,
    /// A field out of range (month 13, 31 April, hour 25, …).
    BadFields = 4,
    /// Earlier than the build date minus 24 h.
    BeforeBuild = 5,
    /// Later than 2099-12-31.
    TooLate = 6,
}

impl Implausible {
    pub fn as_str(self) -> &'static str {
        match self {
            Implausible::NotRead => "RTC not read yet",
            Implausible::BatteryLost => "RTC lost power (VRT clear)",
            Implausible::Unstable => "RTC readings do not agree",
            Implausible::BadFields => "RTC date or time out of range",
            Implausible::BeforeBuild => "clock earlier than the build date",
            Implausible::TooLate => "clock later than 2099",
        }
    }

    fn from_u8(v: u8) -> Option<Implausible> {
        Some(match v {
            1 => Implausible::NotRead,
            2 => Implausible::BatteryLost,
            3 => Implausible::Unstable,
            4 => Implausible::BadFields,
            5 => Implausible::BeforeBuild,
            6 => Implausible::TooLate,
            _ => return None,
        })
    }
}

/// The verdict on one reading (pure – the tests call it with made-up readings).
pub fn assess(dt: &DateTime, vrt: bool, stable: bool, build_epoch: u64) -> Result<(), Implausible> {
    if !vrt {
        return Err(Implausible::BatteryLost);
    }
    if !stable {
        return Err(Implausible::Unstable);
    }
    let leap = (dt.year % 4 == 0 && dt.year % 100 != 0) || dt.year % 400 == 0;
    let mdays = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&dt.month) || dt.day < 1 || dt.day > mdays[(dt.month - 1) as usize] || dt.hour > 23 || dt.minute > 59 || dt.second > 59 {
        return Err(Implausible::BadFields);
    }
    let secs = dt.to_unix();
    if secs + BUILD_SLACK < build_epoch {
        return Err(Implausible::BeforeBuild);
    }
    if secs > LATEST {
        return Err(Implausible::TooLate);
    }
    Ok(())
}

/// 0 = plausible, otherwise an Implausible (decided once at boot – the time only moves on
/// from there).
static VERDICT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(Implausible::NotRead as u8);

/// Unix seconds now, and whether the clock is plausible (syscall 59, DeSoTLS).
pub fn time_status() -> (u64, Result<(), Implausible>) {
    let secs = now().to_unix();
    let v = VERDICT.load(Ordering::Acquire);
    let verdict = match Implausible::from_u8(v) {
        None if secs > LATEST => Err(Implausible::TooLate),
        None => Ok(()),
        Some(e) => Err(e),
    };
    (secs, verdict)
}
