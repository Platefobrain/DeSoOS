// LKG TEST helpers on DeSoFS volumes in RAM (kernel/user/test_time.rs – LKG TEST – runs them):
//
//   file_cases  – the LKG record on a volume: no file, a good one, a second save, a
//                 temporary file left by an interrupted save, every kind of bad record
//                 (length, magic, each covered byte, version, reserved bytes, source, after
//                 2099 – each with a correct checksum where the field is the fault), a read
//                 error and a stat error;
//   power_loss  – a save cut at every write: every 512-byte sector boundary of every write
//                 (the first k sectors landed, nothing after), and a write failing at each
//                 position; every image must mount and hold exactly the old record or the new
//                 one – never no file, an empty or a mixed one.  The same for the very first
//                 save (no file before: nothing or the new record).  A crash image with the
//                 temporary file left behind takes the next save.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use super::test_crash::{attach, build, sectors, snapshot, Ev, Log};
use super::test_write::{formatted, mount, read_all};
use super::vol::Volume;
use crate::block::{self, BlockError};
use crate::fs::{DirEntry, FileSystem, FsError, FsStats, Metadata};
use crate::time_lkg::{self as lkg, Bad, Source};

macro_rules! ensure {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            return Err(format!($($msg)*));
        }
    };
}

const BLOCKS: u64 = 512;
const T1: u64 = 1_800_000_000;
const T2: u64 = 1_800_086_400;
const T3: u64 = 1_800_172_800;

fn fe(what: &str, e: FsError) -> String {
    format!("{}: {}", what, e)
}

/// A record with its checksum computed again (for faults in the covered fields).
fn summed(mut r: [u8; lkg::RECORD_LEN]) -> [u8; lkg::RECORD_LEN] {
    let h = crate::desocrypto::sha256::sha256(&r[..24]);
    r[24..].copy_from_slice(&h);
    r
}

/// Replaces the LKG file's contents directly (as a torn write or a bad sector would).
fn put_file(v: &mut Volume, data: &[u8]) -> Result<(), String> {
    match v.stat(lkg::FILE) {
        Ok(_) => v.truncate(lkg::FILE, 0).map_err(|e| fe("truncate", e))?,
        Err(FsError::NotFound) => v.create(lkg::FILE).map_err(|e| fe("create", e))?,
        Err(e) => return Err(fe("stat", e)),
    }
    if !data.is_empty() {
        v.write(lkg::FILE, 0, data).map_err(|e| fe("write", e))?;
    }
    Ok(())
}

/// A volume whose reads (or stats) fail – an I/O error on an existing file.
struct Failing<'a> {
    v: &'a mut Volume,
    stat_fails: bool,
}

impl FileSystem for Failing<'_> {
    fn kind(&self) -> &'static str {
        "desofs"
    }
    fn source(&self) -> String {
        String::from("failing reads")
    }
    fn stat(&mut self, path: &str) -> crate::fs::Result<Metadata> {
        if self.stat_fails {
            return Err(FsError::Io(BlockError::Io));
        }
        self.v.stat(path)
    }
    fn read_dir(&mut self, path: &str) -> crate::fs::Result<Vec<DirEntry>> {
        self.v.read_dir(path)
    }
    fn read(&mut self, _path: &str, _offset: u64, _buf: &mut [u8]) -> crate::fs::Result<usize> {
        Err(FsError::Io(BlockError::Io))
    }
    fn write(&mut self, path: &str, offset: u64, data: &[u8]) -> crate::fs::Result<usize> {
        self.v.write(path, offset, data)
    }
    fn truncate(&mut self, path: &str, size: u64) -> crate::fs::Result<()> {
        self.v.truncate(path, size)
    }
    fn create(&mut self, path: &str) -> crate::fs::Result<()> {
        self.v.create(path)
    }
    fn mkdir(&mut self, path: &str) -> crate::fs::Result<()> {
        self.v.mkdir(path)
    }
    fn remove(&mut self, path: &str) -> crate::fs::Result<()> {
        self.v.remove(path)
    }
    fn stats(&mut self) -> Option<FsStats> {
        self.v.stats()
    }
    fn sync(&mut self) -> crate::fs::Result<()> {
        self.v.sync()
    }
}

pub(crate) fn file_cases() -> Result<String, String> {
    let d = formatted(BLOCKS)?;
    let r = (|| -> Result<String, String> {
        let mut v = mount(d)?;
        let mut n = 0;
        // No file yet.
        ensure!(lkg::load_from(&mut v) == Ok(None), "an empty volume: {:?}", lkg::load_from(&mut v));
        n += 1;
        // A save, read back byte for byte; no temporary file left; a second save replaces it.
        lkg::save_to(&mut v, T1, Source::Test).map_err(|e| fe("save", e))?;
        ensure!(lkg::load_from(&mut v) == Ok(Some((T1, Source::Test))), "after a save: {:?}", lkg::load_from(&mut v));
        ensure!(read_all(&mut v, lkg::FILE)? == lkg::encode(T1, Source::Test), "the file is not the record");
        ensure!(v.stat(lkg::TEMP).err() == Some(FsError::NotFound), "the temporary file is left");
        lkg::save_to(&mut v, T2, Source::Nts).map_err(|e| fe("save 2", e))?;
        ensure!(lkg::load_from(&mut v) == Ok(Some((T2, Source::Nts))), "after a second save: {:?}", lkg::load_from(&mut v));
        n += 3;
        // A temporary file from an interrupted save: the next save starts again.
        v.create(lkg::TEMP).map_err(|e| fe("create temp", e))?;
        v.write(lkg::TEMP, 0, b"half a record").map_err(|e| fe("write temp", e))?;
        lkg::save_to(&mut v, T3, Source::Test).map_err(|e| fe("save over a temp", e))?;
        ensure!(lkg::load_from(&mut v) == Ok(Some((T3, Source::Test))) && v.stat(lkg::TEMP).is_err(), "save over a left temporary file");
        n += 1;
        // Bad records.
        let good = lkg::encode(T1, Source::Test);
        let mut cases: Vec<(String, Vec<u8>, Bad)> = Vec::new();
        cases.push((String::from("empty"), Vec::new(), Bad::Length));
        cases.push((String::from("55 bytes"), good[..55].to_vec(), Bad::Length));
        let mut long = good.to_vec();
        long.push(0);
        cases.push((String::from("57 bytes"), long, Bad::Length));
        let mut m = good;
        m[0] ^= 1;
        cases.push((String::from("magic"), m.to_vec(), Bad::Magic));
        for i in 8..lkg::RECORD_LEN {
            let mut b = good;
            b[i] ^= 0x10;
            cases.push((format!("byte {} changed", i), b.to_vec(), Bad::Checksum));
        }
        let mut ver = good;
        ver[8] = 2;
        cases.push((String::from("version 2"), summed(ver).to_vec(), Bad::Version));
        let mut res = good;
        res[13] = 1;
        cases.push((String::from("reserved bytes"), summed(res).to_vec(), Bad::Version));
        for src in [0u8, 1, 4, 0xFF] {
            let mut s = good;
            s[10] = src;
            cases.push((format!("source {}", src), summed(s).to_vec(), Bad::Source));
        }
        let mut late = good;
        late[16..24].copy_from_slice(&(crate::drivers::rtc::LATEST + 1).to_le_bytes());
        cases.push((String::from("after 2099"), summed(late).to_vec(), Bad::TooLate));
        for (what, data, want) in cases.iter() {
            put_file(&mut v, data)?;
            let got = lkg::load_from(&mut v);
            ensure!(got == Err(*want), "{}: {:?}, expected {:?}", what, got, want);
            n += 1;
        }
        // The last second of 2099 is still a time.
        let mut last = good;
        last[16..24].copy_from_slice(&crate::drivers::rtc::LATEST.to_le_bytes());
        put_file(&mut v, &summed(last))?;
        ensure!(lkg::load_from(&mut v) == Ok(Some((crate::drivers::rtc::LATEST, Source::Test))), "2099-12-31 23:59:59 refused");
        n += 1;
        // A read error and a stat error on an existing file: reason 8, not "no file".
        put_file(&mut v, &good)?;
        ensure!(lkg::load_from(&mut Failing { v: &mut v, stat_fails: false }) == Err(Bad::Io), "a read error was not Io");
        ensure!(lkg::load_from(&mut Failing { v: &mut v, stat_fails: true }) == Err(Bad::Io), "a stat error was not Io");
        n += 2;
        // A good file again after all that.
        ensure!(lkg::load_from(&mut v) == Ok(Some((T1, Source::Test))), "the good record after the bad ones");
        n += 1;
        Ok(format!("{} cases", n))
    })();
    block::remove(d);
    r
}

/// What a crash image holds.
fn image_state(base: &super::test_crash::Image, over: BTreeMap<u64, Vec<u8>>, what: &str) -> Result<Option<u64>, String> {
    let d = attach(base, BLOCKS, over, None);
    let r = (|| -> Result<Option<u64>, String> {
        let mut v = mount(d).map_err(|e| format!("{}: {}", what, e))?;
        match lkg::load_from(&mut v) {
            Ok(Some((t, Source::Test))) => Ok(Some(t)),
            Ok(None) => Ok(None),
            other => Err(format!("{}: {:?}", what, other)),
        }
    })();
    block::remove(d);
    r
}

/// One recorded save from `start` (which holds `old`, or no file), cut at every sector and
/// failing at every write.  Returns (images, old seen, new seen).
fn cut_save(start: &super::test_crash::Image, old: Option<u64>, new: u64) -> Result<(usize, usize, usize), String> {
    let log = Rc::new(RefCell::new(Log::default()));
    let d = attach(start, BLOCKS, BTreeMap::new(), Some(log.clone()));
    let ev = (|| -> Result<Vec<Ev>, String> {
        let mut v = mount(d)?;
        log.borrow_mut().on = true;
        let r = lkg::save_to(&mut v, new, Source::Test);
        log.borrow_mut().on = false;
        r.map_err(|e| fe("recorded save", e))?;
        Ok(core::mem::take(&mut log.borrow_mut().ev))
    })();
    block::remove(d);
    let ev = ev?;
    let sw = sectors(&ev);
    ensure!(!sw.is_empty(), "the save wrote nothing");
    let (mut images, mut olds, mut news) = (0, 0, 0);
    // Every sector boundary: the first p sectors landed.
    for p in 0..=sw.len() {
        let over = build(start, &sw, |i| i < p);
        let got = image_state(start, over, &format!("cut after {} of {} sectors", p, sw.len()))?;
        images += 1;
        if got == Some(new) {
            news += 1;
        } else if got == old {
            olds += 1;
        } else {
            return Err(format!("cut after {} of {} sectors: {:?} (old {:?}, new {})", p, sw.len(), got, old, new));
        }
    }
    ensure!(news > 0 && olds > 0, "never saw both states ({} old, {} new)", olds, news);
    // A write failing at each position: the save fails, the volume goes read-only, and what
    // is on the disk is still exactly the old record or the new one.
    let writes = ev.iter().filter(|e| matches!(e, Ev::Write(..))).count() as u64;
    for k in 1..=writes {
        let mut l = Log::default();
        l.fail_write = k;
        let log = Rc::new(RefCell::new(l));
        let d = attach(start, BLOCKS, BTreeMap::new(), Some(log));
        let r = (|| -> Result<(), String> {
            let mut v = mount(d)?;
            ensure!(lkg::save_to(&mut v, new, Source::Test).is_err(), "write {} failing: the save reported success", k);
            Ok(())
        })();
        let after = r.and_then(|_| snapshot(d, BLOCKS));
        block::remove(d);
        let img = after?;
        let got = image_state(&img, BTreeMap::new(), &format!("write {} failing", k))?;
        images += 1;
        ensure!(got == old || got == Some(new), "write {} failing: {:?}", k, got);
    }
    Ok((images, olds, news))
}

pub(crate) fn power_loss() -> Result<String, String> {
    let d = formatted(BLOCKS)?;
    let empty = snapshot(d, BLOCKS);
    let with_old = (|| -> Result<super::test_crash::Image, String> {
        let mut v = mount(d)?;
        lkg::save_to(&mut v, T1, Source::Test).map_err(|e| fe("first save", e))?;
        drop(v);
        snapshot(d, BLOCKS)
    })();
    block::remove(d);
    let (empty, with_old) = (empty?, with_old?);
    // Replacing a record, and the very first save.
    let (i1, o1, n1) = cut_save(&with_old, Some(T1), T2)?;
    let (i2, o2, n2) = cut_save(&empty, None, T2)?;
    // A crash image with the temporary file left: the next save works.
    let log = Rc::new(RefCell::new(Log::default()));
    let d = attach(&with_old, BLOCKS, BTreeMap::new(), Some(log.clone()));
    let ev = (|| -> Result<Vec<Ev>, String> {
        let mut v = mount(d)?;
        log.borrow_mut().on = true;
        lkg::save_to(&mut v, T2, Source::Test).map_err(|e| fe("save", e))?;
        log.borrow_mut().on = false;
        Ok(core::mem::take(&mut log.borrow_mut().ev))
    })();
    block::remove(d);
    let ev = ev?;
    let sw = sectors(&ev);
    // The first point where the temporary file exists but the rename has not happened.
    let mut left = None;
    for p in 0..=sw.len() {
        let over = build(&with_old, &sw, |i| i < p);
        let d = attach(&with_old, BLOCKS, over, None);
        let has_temp = mount(d).map(|mut v| v.stat(lkg::TEMP).is_ok() && lkg::load_from(&mut v) == Ok(Some((T1, Source::Test)))).unwrap_or(false);
        if has_temp {
            let r = (|| -> Result<(), String> {
                let mut v = mount(d)?;
                lkg::save_to(&mut v, T3, Source::Test).map_err(|e| fe("save after a crash with the temporary file", e))?;
                ensure!(lkg::load_from(&mut v) == Ok(Some((T3, Source::Test))) && v.stat(lkg::TEMP).is_err(), "the save after the crash");
                Ok(())
            })();
            block::remove(d);
            r?;
            left = Some(p);
            break;
        }
        block::remove(d);
    }
    ensure!(left.is_some(), "no crash point with the temporary file left");
    Ok(format!(
        "{} crash images: replacing a record {} (old {} / new {}), the first save {} (none {} / new {}); a temporary file left by a crash is replaced by the next save",
        i1 + i2,
        i1,
        o1,
        n1,
        i2,
        o2,
        n2
    ))
}
