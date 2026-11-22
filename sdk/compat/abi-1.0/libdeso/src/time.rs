// libdeso::time – Time: the wall clock, the time service's calls, formatting.

#[allow(unused_imports)]
use crate::*;

/// The wall clock (syscall 59).
#[derive(Clone, Copy, Debug)]
pub struct WallClock {
    /// Unix seconds, UTC.
    pub secs: u64,
    /// 0 = plausible; otherwise why not (see `clock_reason`).
    pub status: u64,
    /// The build date the lower bound comes from.
    pub build_epoch: u64,
}

impl WallClock {
    pub fn plausible(&self) -> bool {
        self.status == 0
    }
}

pub fn time_unix() -> Result<WallClock, i64> {
    let mut out = [0u64; 3];
    let r = syscall3(SYS_TIME, out.as_mut_ptr() as u64, 0, 0);
    if r < 0 {
        return Err(r);
    }
    Ok(WallClock { secs: out[0], status: out[1], build_epoch: out[2] })
}

/// The time service gives the kernel the time T +- U (Unix ms) agreed by `servers` NTS
/// servers of different operators (syscall 60).  The bits above, or an error.
pub fn time_set(h: u64, t_ms: u64, u_ms: u64, servers: u64) -> i64 {
    syscall6(SYS_TIME_SET, h, t_ms, u_ms, servers, 0, 0)
}

/// SYS_TIME_BOUND's answer (syscall 61).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimeBound {
    /// The bootstrap bound B = max(LKG in memory, build date), computed by the kernel.
    pub bound: u64,
    /// The LKG in memory (0 = none).
    pub lkg: u64,
    pub build: u64,
    /// 0 none, 2 NTS, 3 self-test.
    pub source: u16,
    /// 0 not read, 1 no volume, 2 no file, 3 good, 4 unreadable.
    pub file: u16,
    pub bad: u16,
    /// TB_RECOVERY, TB_NOT_SAVED, TB_PLAUSIBLE.
    pub flags: u16,
}

impl TimeBound {
    pub fn recovery(&self) -> bool {
        self.flags & TB_RECOVERY != 0
    }
    pub fn parse(b: &[u8; TIME_BOUND_LEN]) -> TimeBound {
        let u64_at = |i: usize| u64::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3], b[i + 4], b[i + 5], b[i + 6], b[i + 7]]);
        let u16_at = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
        TimeBound { bound: u64_at(0), lkg: u64_at(8), build: u64_at(16), source: u16_at(24), file: u16_at(26), bad: u16_at(28), flags: u16_at(30) }
    }
}

/// The raw call: writes into `buf` (of any length – the kernel wants at least 40).
pub fn time_bound_raw(buf: u64, len: u64) -> i64 {
    syscall3(SYS_TIME_BOUND, buf, len, 0)
}

pub fn time_bound() -> Result<TimeBound, i64> {
    let mut b = [0u8; TIME_BOUND_LEN];
    let r = time_bound_raw(b.as_mut_ptr() as u64, b.len() as u64);
    if r < 0 {
        return Err(r);
    }
    Ok(TimeBound::parse(&b))
}

/// The text for a WallClock status (kernel drivers/rtc.rs Implausible).
pub fn clock_reason(status: u64) -> &'static str {
    match status {
        0 => "plausible",
        1 => "RTC not read yet",
        2 => "RTC lost power (VRT clear)",
        3 => "RTC readings do not agree",
        4 => "RTC date or time out of range",
        5 => "clock earlier than the build date",
        6 => "clock later than 2099",
        7 => "clock earlier than the last known good time",
        8 => "last known good time unreadable",
        _ => "unknown",
    }
}

/// "YYYY-MM-DD HH:MM:SS" of Unix seconds into `buf`.
pub fn format_utc(secs: u64, buf: &mut [u8; 19]) -> &str {
    format_utc_signed(secs.min(i64::MAX as u64) as i64, buf)
}

/// The same for signed Unix seconds – dates before 1970 too (years 0000-9999; outside
/// that the year is clamped).
pub fn format_utc_signed(secs: i64, buf: &mut [u8; 19]) -> &str {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400) as u64;
    // civil_from_days (H. Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    let put = |b: &mut [u8; 19], at: usize, v: u64, n: usize| {
        let mut v = v;
        for i in (0..n).rev() {
            b[at + i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    };
    *buf = *b"0000-00-00 00:00:00";
    put(buf, 0, y.clamp(0, 9999) as u64, 4);
    put(buf, 5, m as u64, 2);
    put(buf, 8, d as u64, 2);
    put(buf, 11, rem / 3600, 2);
    put(buf, 14, rem / 60 % 60, 2);
    put(buf, 17, rem % 60, 2);
    core::str::from_utf8(buf).unwrap_or("")
}
