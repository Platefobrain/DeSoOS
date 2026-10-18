// Real-time clock (CMOS RTC) – date and time.
//
// Used for file timestamps (FAT) and the `date` command.
// Registers: 0x00 s, 0x02 min, 0x04 h, 0x07 day, 0x08 month, 0x09 year
// (2 digits), 0x0B status B (bit 2 = binary instead of BCD, bit 1 = 24 h).
// RTC time is usually UTC (QEMU sets it that way by default).

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

/// Reads the RTC and stores the reference point (boot, single CPU).
pub fn init() {
    let hw = read_hw();
    BASE_MS.store(crate::time::uptime_ms(), Ordering::Relaxed);
    BASE_SECS.store(hw.to_unix().max(1), Ordering::Release);
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

    DateTime {
        year: 2000 + conv(r[5]) as u16,
        month: conv(r[4]),
        day: conv(r[3]),
        hour,
        minute: conv(r[1]),
        second: conv(r[0]),
    }
}
