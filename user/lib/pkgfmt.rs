// desopkg's file formats (V082 plan §3–§5, docs/pkg/FORMAT.md): the package (.pkg) and its
// manifest, the repository index, its signature, the trusted keys, the repository
// configuration, an accepted index on the disk and a generation file.
//
// Pure code: no syscalls, only `core` + `alloc`, the crate's `desocrypto` (SHA-256, ECDSA P-256)
// and `elf` (common/elf.rs – the kernel's own program rules).  The crate that includes this
// file (`#[path]`) declares both modules at its root: /bin/desopkg, /bin/pkgtest and the host
// check (tests/pkgfmt-host.sh).
//
// One rule for every text file (§3.1) – exact bytes:
//   UTF-8; a line ends with `\n` only (CR = error); no control characters (bytes < 0x20 other
//   than `\n`, and 0x7f); a line at most 1024 bytes; the file ends with `\n` and nothing
//   follows the last line; `key=value` lines in a fixed order – a key that is unknown, repeated
//   (other than the lists), out of order or missing is `unexpected_key`; a value is everything
//   after the first `=` (a space at its end is part of it – and an error in fields with a
//   limited set of characters).  Sums and signatures are always over the raw bytes.
//
// Every refusal is a short reason id (`Reason`), the same strings tools/desopkg.py gives: the
// PKG FORMAT TEST runs both on the same files and compares the ids, not just "bad".  Checks run
// in the order the file is read, the first failure wins – so both implementations stop at the
// same place.

#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;

use crate::desocrypto;
use crate::elf;

/// Why something was refused – a stable id (docs/pkg/FORMAT.md, "Reasons").
pub type Reason = &'static str;

/// Limits (§3, §4, §5).
pub const MAX_LINE: usize = 1024;
pub const MAX_MANIFEST: usize = 64 * 1024;
pub const MAX_DATA: u64 = 32 * 1024 * 1024;
/// The largest possible .pkg: header (at most 32 bytes) + manifest + data.
pub const MAX_PKG: u64 = 32 + MAX_MANIFEST as u64 + MAX_DATA;
pub const MAX_PROGRAM: u64 = 8 * 1024 * 1024;
pub const MAX_FILES: usize = 256;
pub const MAX_DEPENDS: usize = 16;
pub const MAX_CONFLICTS: usize = 16;
pub const MAX_PATH: usize = 128;
pub const MAX_COMPONENT: usize = 64;
pub const MAX_SUMMARY: usize = 256;
pub const MAX_INDEX: usize = 1024 * 1024;
pub const MAX_INDEX_PACKAGES: usize = 4096;
pub const MAX_SIG: usize = 1024;
pub const MAX_KEYS: usize = 16;
pub const MAX_GENERATION: usize = 256 * 1024;
pub const MAX_GEN_PACKAGES: usize = 64;
pub const MAX_GEN_PROGRAMS: usize = 256;
/// An index is valid at most 30 days; `issued` at most one day ahead of the clock.
pub const MAX_INDEX_DAYS: u64 = 30;
pub const DAY: u64 = 86_400;

/// The ABI of the system desopkg runs on (ABI 1.0, abi/abi.toml).
pub const SYSTEM_ABI: (u16, u16) = (1, 0);
pub const ARCH: &str = "x86_64";

/// The signed message's domain line (§4).
pub const SIG_DOMAIN: &[u8] = b"DESO-INDEX-SIGNATURE-V1\n";

// ------------------------------------------------------------
// Small grammars
// ------------------------------------------------------------

/// A package or program name: `[a-z][a-z0-9-]{0,31}`.
pub fn valid_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 32 && b[0].is_ascii_lowercase() && b.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// A key id: `[a-z0-9][a-z0-9.-]{0,63}`.
pub fn valid_keyid(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
}

/// A decimal number without leading zeros ("0" itself is fine), at most `max`.
pub fn decimal(s: &str, max: u64) -> Option<u64> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 20 || !b.iter().all(|c| c.is_ascii_digit()) || (b[0] == b'0' && b.len() > 1) {
        return None;
    }
    let mut v: u64 = 0;
    for &c in b {
        v = v.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    if v > max { None } else { Some(v) }
}

/// Lower-case hex of exactly `n` bytes.
pub fn hex_bytes(s: &str, n: usize) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() != 2 * n {
        return None;
    }
    let v = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        out.push((v(b[2 * i])? << 4) | v(b[2 * i + 1])?);
    }
    Some(out)
}

pub fn sha256_hex(s: &str) -> Option<[u8; 32]> {
    let v = hex_bytes(s, 32)?;
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Some(a)
}

/// `A.B.C`, each 0–65535 without leading zeros; compared as numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u16, pub u16, pub u16);

impl Version {
    pub fn parse(s: &str) -> Option<Version> {
        let mut it = s.split('.');
        let a = decimal(it.next()?, 65535)? as u16;
        let b = decimal(it.next()?, 65535)? as u16;
        let c = decimal(it.next()?, 65535)? as u16;
        if it.next().is_some() {
            return None;
        }
        Some(Version(a, b, c))
    }
}

impl core::fmt::Display for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// `M.m` – an ABI version.
pub fn parse_abi(s: &str) -> Option<(u16, u16)> {
    let (a, b) = s.split_once('.')?;
    Some((decimal(a, 65535)? as u16, decimal(b, 65535)? as u16))
}

/// `RRRR-MM-DDTHH:MM:SSZ` (UTC, capital T and Z, a real calendar date, seconds 00–59) as Unix
/// seconds; years 1970–9999.
pub fn parse_date(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return None;
    }
    let num = |r: core::ops::Range<usize>| -> Option<u64> {
        let mut v = 0u64;
        for &c in &b[r] {
            if !c.is_ascii_digit() {
                return None;
            }
            v = v * 10 + (c - b'0') as u64;
        }
        Some(v)
    };
    let (y, mo, d, h, mi, se) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&mo) || d < 1 || h > 23 || mi > 59 || se > 59 {
        return None;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mdays = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if d > mdays[(mo - 1) as usize] {
        return None;
    }
    // Days from 1970-01-01 (Howard Hinnant's days_from_civil, years >= 1970 only).
    let (yy, m) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = yy / 400;
    let yoe = yy - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * DAY + h * 3600 + mi * 60 + se)
}

// ------------------------------------------------------------
// The text rule (§3.1)
// ------------------------------------------------------------

/// The file's lines after the whole-file checks (in this order): empty → `truncated`;
/// `not_utf8`; `cr`; `control`; `no_final_newline`; `line_too_long`.
pub fn text_lines(b: &[u8]) -> Result<Vec<&str>, Reason> {
    if b.is_empty() {
        return Err("truncated");
    }
    let s = core::str::from_utf8(b).map_err(|_| "not_utf8")?;
    if b.contains(&b'\r') {
        return Err("cr");
    }
    if b.iter().any(|&c| (c < 0x20 && c != b'\n') || c == 0x7f) {
        return Err("control");
    }
    if b[b.len() - 1] != b'\n' {
        return Err("no_final_newline");
    }
    let lines: Vec<&str> = s[..s.len() - 1].split('\n').collect();
    if lines.iter().any(|l| l.len() > MAX_LINE) {
        return Err("line_too_long");
    }
    Ok(lines)
}

/// Reads `key=value` lines in their fixed order.
pub struct Cursor<'a> {
    lines: Vec<&'a str>,
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(b: &'a [u8]) -> Result<Cursor<'a>, Reason> {
        Ok(Cursor { lines: text_lines(b)?, pos: 0 })
    }

    /// Whether the next line is `key=…`.
    pub fn next_is(&self, key: &str) -> bool {
        self.lines.get(self.pos).is_some_and(|l| l.len() > key.len() && l.starts_with(key) && l.as_bytes()[key.len()] == b'=')
    }

    /// The value of the next line, which must be `key=…`.
    pub fn kv(&mut self, key: &str) -> Result<&'a str, Reason> {
        let Some(line) = self.lines.get(self.pos) else { return Err("truncated") };
        if !self.next_is(key) {
            return Err("unexpected_key");
        }
        self.pos += 1;
        Ok(&line[key.len() + 1..])
    }

    /// The next line must be exactly `text`.
    pub fn lit(&mut self, text: &str) -> Result<(), Reason> {
        let Some(line) = self.lines.get(self.pos) else { return Err("truncated") };
        if *line != text {
            return Err("unexpected_key");
        }
        self.pos += 1;
        Ok(())
    }

    /// Up to `max` lines `key=…` (more = `too_many`), each handed to `each` as it is read.
    pub fn many(&mut self, key: &str, max: usize, mut each: impl FnMut(&'a str) -> Result<(), Reason>) -> Result<usize, Reason> {
        let mut n = 0;
        while self.next_is(key) {
            n += 1;
            if n > max {
                return Err("too_many");
            }
            let v = self.kv(key)?;
            each(v)?;
        }
        Ok(n)
    }

    /// Nothing may follow.
    pub fn done(&self) -> Result<(), Reason> {
        if self.pos < self.lines.len() { Err("trailing_bytes") } else { Ok(()) }
    }

    /// The byte offset of the next line in the file (`base` – the file).
    pub fn offset(&self, base: &[u8]) -> usize {
        match self.lines.get(self.pos) {
            Some(l) => l.as_ptr() as usize - base.as_ptr() as usize,
            None => base.len(),
        }
    }
}

// ------------------------------------------------------------
// depends / conflicts (manifest, index, generation)
// ------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dep {
    pub name: String,
    /// `name>=A.B.C`; None – any version.
    pub min: Option<Version>,
}

pub fn parse_dep(s: &str) -> Option<Dep> {
    match s.split_once(">=") {
        Some((n, v)) => {
            if !valid_name(n) {
                return None;
            }
            Some(Dep { name: String::from(n), min: Some(Version::parse(v)?) })
        }
        None => {
            if !valid_name(s) {
                return None;
            }
            Some(Dep { name: String::from(s), min: None })
        }
    }
}

/// The `depends=` and `conflicts=` lines of a package called `me`: each name valid, not `me`,
/// not twice; a conflict not also a dependency.
fn read_relations<'a>(c: &mut Cursor<'a>, me: &str) -> Result<(Vec<&'a str>, Vec<Dep>, Vec<&'a str>), Reason> {
    let mut raw = Vec::new();
    let mut deps: Vec<Dep> = Vec::new();
    c.many("depends", MAX_DEPENDS, |v| {
        let d = parse_dep(v).ok_or("bad_depends")?;
        if d.name == me || deps.iter().any(|x| x.name == d.name) {
            return Err("bad_depends");
        }
        deps.push(d);
        raw.push(v);
        Ok(())
    })?;
    let mut conflicts: Vec<&'a str> = Vec::new();
    c.many("conflicts", MAX_CONFLICTS, |v| {
        if !valid_name(v) || v == me || conflicts.contains(&v) || deps.iter().any(|x| x.name == v) {
            return Err("bad_conflicts");
        }
        conflicts.push(v);
        Ok(())
    })?;
    Ok((raw, deps, conflicts))
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| String::from(*s)).collect()
}

// ------------------------------------------------------------
// Manifest and package (§3)
// ------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Program,
    Data,
}

#[derive(Clone, Debug)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub sha256: [u8; 32],
    pub kind: Kind,
    /// Where its bytes start in the package's data.
    pub offset: u64,
}

#[derive(Clone, Debug)]
pub struct Manifest {
    pub name: String,
    pub version: Version,
    pub abi: (u16, u16),
    pub data: u64,
    pub summary: String,
    /// The `depends=` values exactly as written (compared with the index and the generation).
    pub depends_raw: Vec<String>,
    pub depends: Vec<Dep>,
    pub conflicts: Vec<String>,
    pub files: Vec<FileEntry>,
}

impl Manifest {
    /// Program names (`bin/<name>`), in manifest order.
    pub fn programs(&self) -> Vec<&str> {
        self.files.iter().filter(|f| f.kind == Kind::Program).map(|f| &f.path[4..]).collect()
    }
}

/// A relative path: at most 128 bytes, components `[a-z0-9._-]{1,64}` other than `.` and `..`;
/// `bin/<program>` (exactly two components) or `share/…` (at least two).
fn path_ok(p: &str) -> bool {
    if p.is_empty() || p.len() > MAX_PATH {
        return false;
    }
    let comps: Vec<&str> = p.split('/').collect();
    for c in &comps {
        let b = c.as_bytes();
        if b.is_empty()
            || b.len() > MAX_COMPONENT
            || *c == "."
            || *c == ".."
            || !b.iter().all(|&x| x.is_ascii_lowercase() || x.is_ascii_digit() || x == b'.' || x == b'_' || x == b'-')
        {
            return false;
        }
    }
    match comps[0] {
        "bin" => comps.len() == 2,
        "share" => comps.len() >= 2,
        _ => false,
    }
}

/// The manifest alone (no data): every field, the paths, the names, Σ sizes == `data`.
/// `system_name(n)` – n is a name the system keeps (user/lib/cmdnames.rs + /bin).
pub fn parse_manifest(b: &[u8], system_name: &dyn Fn(&str) -> bool) -> Result<Manifest, Reason> {
    if b.len() > MAX_MANIFEST {
        return Err("too_big");
    }
    let mut c = Cursor::new(b)?;
    if c.kv("format")? != "1" {
        return Err("bad_format");
    }
    let name = c.kv("name")?;
    if !valid_name(name) {
        return Err("bad_name");
    }
    if system_name(name) {
        return Err("reserved_name");
    }
    let version = Version::parse(c.kv("version")?).ok_or("bad_version")?;
    if c.kv("arch")? != ARCH {
        return Err("bad_arch");
    }
    let abi = parse_abi(c.kv("abi")?).ok_or("bad_abi")?;
    if abi.0 != SYSTEM_ABI.0 || abi.1 > SYSTEM_ABI.1 {
        return Err("bad_abi");
    }
    let data = decimal(c.kv("data")?, MAX_DATA).ok_or("bad_data")?;
    let summary = c.kv("summary")?;
    if summary.is_empty() || summary.len() > MAX_SUMMARY {
        return Err("bad_summary");
    }
    let (depends_raw, depends, conflicts) = read_relations(&mut c, name)?;
    let mut files: Vec<FileEntry> = Vec::new();
    let mut sum: u64 = 0;
    let n = c.many("file", MAX_FILES, |v| {
        let parts: Vec<&str> = v.split('|').collect();
        if parts.len() != 4 {
            return Err("bad_file");
        }
        let path = parts[0];
        if !path_ok(path) {
            return Err("bad_path");
        }
        let size = decimal(parts[1], MAX_DATA).ok_or("bad_size")?;
        let sha256 = sha256_hex(parts[2]).ok_or("bad_sha256")?;
        let kind = match (parts[3], path.starts_with("bin/")) {
            ("program", true) => Kind::Program,
            ("data", false) => Kind::Data,
            _ => return Err("bad_kind"),
        };
        if kind == Kind::Program {
            let prog = &path[4..];
            if !valid_name(prog) {
                return Err("bad_program_name");
            }
            if system_name(prog) {
                return Err("reserved_name");
            }
            if size > MAX_PROGRAM {
                return Err("program_too_big");
            }
        }
        for f in &files {
            if f.path == path {
                return Err("dup_path");
            }
            let (a, b) = (f.path.as_str(), path);
            if (a.len() > b.len() && a.starts_with(b) && a.as_bytes()[b.len()] == b'/')
                || (b.len() > a.len() && b.starts_with(a) && b.as_bytes()[a.len()] == b'/')
            {
                return Err("path_clash");
            }
        }
        files.push(FileEntry { path: String::from(path), size, sha256, kind, offset: sum });
        sum = sum.checked_add(size).ok_or("data_mismatch")?;
        Ok(())
    })?;
    if n == 0 {
        // At least one file: the line after the relations must be `file=`.
        return Err(if c.lines.get(c.pos).is_some() { "unexpected_key" } else { "truncated" });
    }
    c.lit("end")?;
    c.done()?;
    if sum != data {
        return Err("data_mismatch");
    }
    Ok(Manifest {
        name: String::from(name),
        version,
        abi,
        data,
        summary: String::from(summary),
        depends_raw: strings(&depends_raw),
        depends,
        conflicts: strings(&conflicts),
        files,
    })
}

/// A parsed package: the manifest, where it and the data are in the file.
pub struct Package<'a> {
    pub manifest: Manifest,
    pub manifest_bytes: &'a [u8],
    pub data: &'a [u8],
}

/// `DESOPKG 1 <M> <D>\n`: (header length, M, D).
fn parse_pkg_header(b: &[u8]) -> Result<(usize, usize, u64), Reason> {
    let nl = b.iter().take(32).position(|&c| c == b'\n').ok_or("bad_header")?;
    let line = core::str::from_utf8(&b[..nl]).map_err(|_| "bad_header")?;
    let mut it = line.split(' ');
    if it.next() != Some("DESOPKG") || it.next() != Some("1") {
        return Err("bad_header");
    }
    let m = it.next().and_then(|s| decimal(s, MAX_MANIFEST as u64)).filter(|&m| m > 0).ok_or("bad_header")?;
    let d = it.next().and_then(|s| decimal(s, MAX_DATA)).ok_or("bad_header")?;
    if it.next().is_some() {
        return Err("bad_header");
    }
    Ok((nl + 1, m as usize, d))
}

/// The whole package (§3): size limit, header, header + M + D == file size, the manifest,
/// `data` == D, then every file: its SHA-256 and, for programs, the kernel's own rules
/// (common/elf.rs) with the ABI note equal to the manifest's `abi`.
pub fn parse_pkg<'a>(b: &'a [u8], system_name: &dyn Fn(&str) -> bool) -> Result<Package<'a>, Reason> {
    if b.len() as u64 > MAX_PKG {
        return Err("too_big");
    }
    let (h, m, d) = parse_pkg_header(b)?;
    let total = (h as u64).checked_add(m as u64).and_then(|x| x.checked_add(d));
    if total != Some(b.len() as u64) {
        return Err("size_mismatch");
    }
    let manifest_bytes = &b[h..h + m];
    let data = &b[h + m..];
    let manifest = parse_manifest(manifest_bytes, system_name)?;
    if manifest.data != d {
        return Err("data_mismatch");
    }
    for f in &manifest.files {
        let bytes = &data[f.offset as usize..(f.offset + f.size) as usize];
        if desocrypto::sha256::sha256(bytes) != f.sha256 {
            return Err("file_sha_mismatch");
        }
        if f.kind == Kind::Program {
            let (_, abi) = elf::check_program_bytes(bytes, SYSTEM_ABI).map_err(|_| "bad_elf")?;
            if abi != manifest.abi {
                return Err("abi_mismatch");
            }
        }
    }
    Ok(Package { manifest, manifest_bytes, data })
}

// ------------------------------------------------------------
// Index (§4)
// ------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct IndexEntry {
    pub name: String,
    pub version: Version,
    pub abi: (u16, u16),
    pub size: u64,
    pub sha256: [u8; 32],
    pub depends_raw: Vec<String>,
    pub depends: Vec<Dep>,
    pub conflicts: Vec<String>,
    pub summary: String,
}

#[derive(Clone, Debug)]
pub struct Index {
    pub repo: String,
    pub channel: String,
    pub arch: String,
    pub serial: u64,
    pub issued: u64,
    pub expires: u64,
    pub packages: Vec<IndexEntry>,
}

impl Index {
    pub fn find(&self, name: &str, version: Version) -> Option<&IndexEntry> {
        self.packages.iter().find(|p| p.name == name && p.version == version)
    }
    /// The highest version of `name` (None – not in the index).
    pub fn newest(&self, name: &str) -> Option<&IndexEntry> {
        self.packages.iter().filter(|p| p.name == name).max_by_key(|p| p.version)
    }
}

/// The index's grammar and its own consistency (no clock): `issued` < `expires`, at most 30
/// days apart; (name, version) unique; at most 4096 packages.
pub fn parse_index(b: &[u8]) -> Result<Index, Reason> {
    if b.len() > MAX_INDEX {
        return Err("too_big");
    }
    let mut c = Cursor::new(b)?;
    if c.kv("format")? != "1" {
        return Err("bad_format");
    }
    let repo = c.kv("repo")?;
    if !valid_name(repo) {
        return Err("bad_repo");
    }
    let channel = c.kv("channel")?;
    if !valid_name(channel) {
        return Err("bad_channel");
    }
    let arch = c.kv("arch")?;
    if arch != ARCH {
        return Err("bad_arch");
    }
    let serial = decimal(c.kv("serial")?, u64::MAX).filter(|&s| s > 0).ok_or("bad_serial")?;
    let issued = parse_date(c.kv("issued")?).ok_or("bad_date")?;
    let expires = parse_date(c.kv("expires")?).ok_or("bad_date")?;
    if issued >= expires || expires - issued > MAX_INDEX_DAYS * DAY {
        return Err("bad_times");
    }
    let mut packages: Vec<IndexEntry> = Vec::new();
    while c.next_is("package") {
        if packages.len() == MAX_INDEX_PACKAGES {
            return Err("too_many");
        }
        let name = c.kv("package")?;
        if !valid_name(name) {
            return Err("bad_name");
        }
        let version = Version::parse(c.kv("version")?).ok_or("bad_version")?;
        if packages.iter().any(|p| p.name == name && p.version == version) {
            return Err("dup_package");
        }
        let abi = parse_abi(c.kv("abi")?).ok_or("bad_abi")?;
        let size = decimal(c.kv("size")?, MAX_PKG).filter(|&s| s > 0).ok_or("bad_size")?;
        let sha256 = sha256_hex(c.kv("sha256")?).ok_or("bad_sha256")?;
        let (depends_raw, depends, conflicts) = read_relations(&mut c, name)?;
        let summary = c.kv("summary")?;
        if summary.is_empty() || summary.len() > MAX_SUMMARY {
            return Err("bad_summary");
        }
        c.lit("endpackage")?;
        packages.push(IndexEntry {
            name: String::from(name),
            version,
            abi,
            size,
            sha256,
            depends_raw: strings(&depends_raw),
            depends,
            conflicts: strings(&conflicts),
            summary: String::from(summary),
        });
    }
    c.lit("end")?;
    c.done()?;
    Ok(Index { repo: String::from(repo), channel: String::from(channel), arch: String::from(arch), serial, issued, expires, packages })
}

/// Step 5 of `refresh` (§4) against the clock: `expires` > now, `issued` ≤ now + 1 day.
pub fn check_index_time(idx: &Index, now: u64) -> Result<(), Reason> {
    if idx.expires <= now {
        return Err("expired");
    }
    if idx.issued > now.saturating_add(DAY) {
        return Err("issued_in_future");
    }
    Ok(())
}

/// Step 4: repo, channel and arch == /etc/desopkg/repo.
pub fn check_index_repo(idx: &Index, cfg: &RepoConfig) -> Result<(), Reason> {
    if idx.repo != cfg.repo || idx.channel != cfg.channel || idx.arch != cfg.arch {
        return Err("repo_mismatch");
    }
    Ok(())
}

/// A downloaded package against its index entry (§3 order): exactly `size` bytes, SHA-256 of
/// the whole file, then the package itself, then name, version, abi, summary, depends and
/// conflicts == the entry.
pub fn check_pkg_against_index<'a>(b: &'a [u8], e: &IndexEntry, system_name: &dyn Fn(&str) -> bool) -> Result<Package<'a>, Reason> {
    if b.len() as u64 != e.size {
        return Err("pkg_size_mismatch");
    }
    if desocrypto::sha256::sha256(b) != e.sha256 {
        return Err("pkg_sha_mismatch");
    }
    let p = parse_pkg(b, system_name)?;
    let m = &p.manifest;
    if m.name != e.name || m.version != e.version || m.abi != e.abi || m.summary != e.summary || m.depends_raw != e.depends_raw || m.conflicts != e.conflicts {
        return Err("index_mismatch");
    }
    Ok(p)
}

// ------------------------------------------------------------
// Signature, keys, repository configuration (§4, §2)
// ------------------------------------------------------------

pub struct Signature {
    pub alg: String,
    pub keyid: String,
    pub der: Vec<u8>,
}

/// The order n of P-256 and ⌊n/2⌋ (low-S), big-endian.
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
    0xfc, 0x63, 0x25, 0x51,
];
const P256_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61,
    0x7e, 0x31, 0x92, 0xa8,
];

/// A big-endian integer (no leading zeros) as 32 bytes; None if longer.
fn be32(v: &[u8]) -> Option<[u8; 32]> {
    if v.len() > 32 {
        return None;
    }
    let mut a = [0u8; 32];
    a[32 - v.len()..].copy_from_slice(v);
    Some(a)
}

/// One strict DER INTEGER at `b[i..]`: (value without the sign byte, next index).
fn der_int(b: &[u8], i: usize) -> Option<(&[u8], usize)> {
    if *b.get(i)? != 0x02 {
        return None;
    }
    let len = *b.get(i + 1)? as usize;
    if len == 0 || len >= 0x80 {
        return None;
    }
    let v = b.get(i + 2..i + 2 + len)?;
    if v[0] & 0x80 != 0 {
        return None; // negative
    }
    if v[0] == 0 && len > 1 && v[1] & 0x80 == 0 {
        return None; // a leading zero that is not needed
    }
    let v = if v[0] == 0 && len > 1 { &v[1..] } else { v };
    Some((v, i + 2 + len))
}

/// Strict DER ECDSA-Sig-Value on P-256: SEQUENCE { INTEGER r, INTEGER s }, short-form lengths,
/// minimal integers, nothing after; 1 ≤ r, s < n (`sig_encoding`); s ≤ n/2 (`high_s`).
pub fn check_der_p256(der: &[u8]) -> Result<(), Reason> {
    let bad = "sig_encoding";
    if der.len() < 8 || der.len() > 72 || der[0] != 0x30 || der[1] as usize != der.len() - 2 || der[1] >= 0x80 {
        return Err(bad);
    }
    let (r, i) = der_int(der, 2).ok_or(bad)?;
    let (s, j) = der_int(der, i).ok_or(bad)?;
    if j != der.len() {
        return Err(bad);
    }
    let (r, s) = (be32(r).ok_or(bad)?, be32(s).ok_or(bad)?);
    let zero = [0u8; 32];
    if r == zero || s == zero || r >= P256_N || s >= P256_N {
        return Err(bad);
    }
    if s > P256_HALF_N {
        return Err("high_s");
    }
    Ok(())
}

/// `index.sig`: `SIGNATURE 1`, `alg=p256`, `keyid=…`, `signature=<hex DER>`, `end`.
pub fn parse_signature(b: &[u8]) -> Result<Signature, Reason> {
    if b.len() > MAX_SIG {
        return Err("too_big");
    }
    let mut c = Cursor::new(b)?;
    c.lit("SIGNATURE 1")?;
    let alg = c.kv("alg")?;
    if alg != "p256" {
        return Err("bad_alg");
    }
    let keyid = c.kv("keyid")?;
    if !valid_keyid(keyid) {
        return Err("bad_keyid");
    }
    let hex = c.kv("signature")?;
    if hex.is_empty() || hex.len() % 2 != 0 {
        return Err("sig_encoding");
    }
    let der = hex_bytes(hex, hex.len() / 2).ok_or("sig_encoding")?;
    check_der_p256(&der)?;
    c.lit("end")?;
    c.done()?;
    Ok(Signature { alg: String::from(alg), keyid: String::from(keyid), der })
}

/// What is signed: the domain line, `alg=…\n`, `keyid=…\n`, then the raw index bytes.
pub fn signed_message(alg: &str, keyid: &str, index: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIG_DOMAIN.len() + alg.len() + keyid.len() + 12 + index.len());
    m.extend_from_slice(SIG_DOMAIN);
    m.extend_from_slice(b"alg=");
    m.extend_from_slice(alg.as_bytes());
    m.extend_from_slice(b"\nkeyid=");
    m.extend_from_slice(keyid.as_bytes());
    m.push(b'\n');
    m.extend_from_slice(index);
    m
}

pub struct Key {
    pub keyid: String,
    /// Uncompressed P-256 point 04 ‖ X ‖ Y.
    pub point: Vec<u8>,
}

/// /etc/desopkg/keys: `DESOPKG-KEYS 1`, `key=<keyid>|p256|<130 hex: 04‖X‖Y>` (0–16, key ids
/// unique, the point on the curve), `end`.
pub fn parse_keys(b: &[u8]) -> Result<Vec<Key>, Reason> {
    let mut c = Cursor::new(b)?;
    c.lit("DESOPKG-KEYS 1")?;
    let mut keys: Vec<Key> = Vec::new();
    c.many("key", MAX_KEYS, |v| {
        let parts: Vec<&str> = v.split('|').collect();
        if parts.len() != 3 || !valid_keyid(parts[0]) || parts[1] != "p256" || keys.iter().any(|k| k.keyid == parts[0]) {
            return Err("bad_key");
        }
        let point = hex_bytes(parts[2], 65).ok_or("bad_key")?;
        desocrypto::ecdsa::check_public_key(desocrypto::ecdsa::Curve::P256, &point).map_err(|_| "bad_key")?;
        keys.push(Key { keyid: String::from(parts[0]), point });
        Ok(())
    })?;
    c.lit("end")?;
    c.done()?;
    Ok(keys)
}

/// Step 3 of `refresh`: the signature over the raw index bytes, before the index is read.
pub fn verify_index(index: &[u8], sig: &[u8], keys: &[Key]) -> Result<(), Reason> {
    let s = parse_signature(sig)?;
    let key = keys.iter().find(|k| k.keyid == s.keyid).ok_or("unknown_key")?;
    let msg = signed_message(&s.alg, &s.keyid, index);
    match desocrypto::ecdsa::verify(desocrypto::ecdsa::Curve::P256, &key.point, &msg, &s.der) {
        Ok(()) => Ok(()),
        Err(desocrypto::Error::Mismatch) => Err("bad_signature"),
        Err(desocrypto::Error::InvalidKey) => Err("bad_key"),
        Err(_) => Err("sig_encoding"),
    }
}

#[derive(Clone, Debug)]
pub struct RepoConfig {
    pub url: String,
    pub repo: String,
    pub channel: String,
    pub arch: String,
}

/// `https://<host>/<path>/`: host `[a-z0-9.-]+`, path of `[a-z0-9._/-]`, ending with `/`.
fn url_ok(u: &str) -> bool {
    let Some(rest) = u.strip_prefix("https://") else { return false };
    let Some((host, path)) = rest.split_once('/') else { return false };
    !host.is_empty()
        && host.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-')
        && (path.is_empty() || path.ends_with('/'))
        && path.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._/-".contains(&c))
        && !path.contains("//")
}

/// /etc/desopkg/repo: `format=1`, `url=`, `repo=`, `channel=`, `arch=`, `end`.
pub fn parse_repo_config(b: &[u8]) -> Result<RepoConfig, Reason> {
    let mut c = Cursor::new(b)?;
    if c.kv("format")? != "1" {
        return Err("bad_format");
    }
    let url = c.kv("url")?;
    if !url_ok(url) {
        return Err("bad_url");
    }
    let repo = c.kv("repo")?;
    if !valid_name(repo) {
        return Err("bad_repo");
    }
    let channel = c.kv("channel")?;
    if !valid_name(channel) {
        return Err("bad_channel");
    }
    let arch = c.kv("arch")?;
    if arch != ARCH {
        return Err("bad_arch");
    }
    c.lit("end")?;
    c.done()?;
    Ok(RepoConfig { url: String::from(url), repo: String::from(repo), channel: String::from(channel), arch: String::from(arch) })
}

// ------------------------------------------------------------
// An accepted index on the disk: /disk/pkg/index/<serial> (§4 step 7)
// ------------------------------------------------------------

/// `DESO-ACCEPTED-INDEX 1 <index size> <signature size>\n` + index + signature: (index, sig).
pub fn parse_accepted(b: &[u8]) -> Result<(&[u8], &[u8]), Reason> {
    let nl = b.iter().take(64).position(|&c| c == b'\n').ok_or("bad_header")?;
    let line = core::str::from_utf8(&b[..nl]).map_err(|_| "bad_header")?;
    let mut it = line.split(' ');
    if it.next() != Some("DESO-ACCEPTED-INDEX") || it.next() != Some("1") {
        return Err("bad_header");
    }
    let ni = it.next().and_then(|s| decimal(s, MAX_INDEX as u64)).filter(|&n| n > 0).ok_or("bad_header")? as usize;
    let ns = it.next().and_then(|s| decimal(s, MAX_SIG as u64)).filter(|&n| n > 0).ok_or("bad_header")? as usize;
    if it.next().is_some() {
        return Err("bad_header");
    }
    if nl + 1 + ni + ns != b.len() {
        return Err("size_mismatch");
    }
    Ok((&b[nl + 1..nl + 1 + ni], &b[nl + 1 + ni..]))
}

pub fn make_accepted(index: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(index.len() + sig.len() + 48);
    v.extend_from_slice(alloc::format!("DESO-ACCEPTED-INDEX 1 {} {}\n", index.len(), sig.len()).as_bytes());
    v.extend_from_slice(index);
    v.extend_from_slice(sig);
    v
}

/// An accepted index file in full: the header, the signature (before the index is read), the
/// index.  (The clock check is separate – an expired index still counts as accepted.)
pub fn check_accepted(b: &[u8], keys: &[Key]) -> Result<Index, Reason> {
    let (index, sig) = parse_accepted(b)?;
    verify_index(index, sig, keys)?;
    parse_index(index)
}

// ------------------------------------------------------------
// Generation file: /disk/pkg/gen/<n> (§5)
// ------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallReason {
    Explicit,
    Dependency,
}

#[derive(Clone, Debug)]
pub struct GenEntry {
    pub name: String,
    pub version: Version,
    pub dir: String,
    pub reason: InstallReason,
    pub manifest: [u8; 32],
    pub depends_raw: Vec<String>,
    pub conflicts: Vec<String>,
    pub programs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Generation {
    pub number: u64,
    pub op: String,
    pub packages: Vec<GenEntry>,
}

pub const OPS: &[&str] = &["install", "update", "remove", "reinstall"];

/// `<version>-<16 lower-case hex>` of the entry's own version.
fn dir_ok(dir: &str, version: Version) -> bool {
    match dir.rsplit_once('-') {
        Some((v, id)) => Version::parse(v) == Some(version) && v == alloc::format!("{}", version) && hex_bytes(id, 8).is_some(),
        None => false,
    }
}

/// A generation file's grammar and hash (`number` – from its file name).  The metadata
/// against the package directories is `check_generation_package`.
pub fn parse_generation(b: &[u8], number: u64, system_name: &dyn Fn(&str) -> bool) -> Result<Generation, Reason> {
    if b.len() > MAX_GENERATION {
        return Err("too_big");
    }
    let mut c = Cursor::new(b)?;
    if c.kv("format")? != "1" {
        return Err("bad_format");
    }
    let g = decimal(c.kv("generation")?, u64::MAX).filter(|&g| g > 0).ok_or("bad_generation")?;
    if g != number {
        return Err("generation_mismatch");
    }
    let op = c.kv("op")?;
    if !OPS.contains(&op) {
        return Err("bad_op");
    }
    let mut packages: Vec<GenEntry> = Vec::new();
    let mut all_programs: Vec<String> = Vec::new();
    while c.next_is("package") {
        if packages.len() == MAX_GEN_PACKAGES {
            return Err("too_many");
        }
        let name = c.kv("package")?;
        if !valid_name(name) {
            return Err("bad_name");
        }
        if system_name(name) {
            return Err("reserved_name");
        }
        if packages.iter().any(|p| p.name == name) {
            return Err("dup_package");
        }
        let version = Version::parse(c.kv("version")?).ok_or("bad_version")?;
        let dir = c.kv("dir")?;
        if !dir_ok(dir, version) {
            return Err("bad_dir");
        }
        let reason = match c.kv("reason")? {
            "explicit" => InstallReason::Explicit,
            "dependency" => InstallReason::Dependency,
            _ => return Err("bad_reason"),
        };
        let manifest = sha256_hex(c.kv("manifest")?).ok_or("bad_manifest")?;
        let (depends_raw, _, conflicts) = read_relations(&mut c, name)?;
        let mut programs: Vec<String> = Vec::new();
        c.many("program", MAX_GEN_PROGRAMS, |p| {
            if !valid_name(p) {
                return Err("bad_program_name");
            }
            if system_name(p) {
                return Err("reserved_name");
            }
            if all_programs.iter().any(|x| x == p) {
                return Err("dup_program");
            }
            if all_programs.len() == MAX_GEN_PROGRAMS {
                return Err("too_many");
            }
            all_programs.push(String::from(p));
            programs.push(String::from(p));
            Ok(())
        })?;
        c.lit("endpackage")?;
        packages.push(GenEntry {
            name: String::from(name),
            version,
            dir: String::from(dir),
            reason,
            manifest,
            depends_raw: strings(&depends_raw),
            conflicts: strings(&conflicts),
            programs,
        });
    }
    c.lit("end")?;
    let hashed = c.offset(b);
    let h = sha256_hex(c.kv("hash")?).ok_or("bad_hash")?;
    c.done()?;
    if desocrypto::sha256::sha256(&b[..hashed]) != h {
        return Err("bad_hash");
    }
    Ok(Generation { number: g, op: String::from(op), packages })
}

/// One package of a generation against its directory's `package` file (§5): SHA-256 of the
/// file == `manifest=`, the manifest valid, name, version, programs, depends and conflicts ==
/// the entry.
pub fn check_generation_package(e: &GenEntry, manifest_bytes: &[u8], system_name: &dyn Fn(&str) -> bool) -> Result<Manifest, Reason> {
    if desocrypto::sha256::sha256(manifest_bytes) != e.manifest {
        return Err("manifest_mismatch");
    }
    let m = parse_manifest(manifest_bytes, system_name)?;
    let progs = m.programs();
    if m.name != e.name
        || m.version != e.version
        || progs.len() != e.programs.len()
        || progs.iter().zip(e.programs.iter()).any(|(a, b)| *a != b.as_str())
        || m.depends_raw != e.depends_raw
        || m.conflicts != e.conflicts
    {
        return Err("entry_mismatch");
    }
    Ok(m)
}

/// A generation file's bytes (what desopkg writes; `hash` over everything before it).
pub fn make_generation(number: u64, op: &str, packages: &[GenEntry]) -> Vec<u8> {
    use core::fmt::Write;
    let mut s = String::new();
    let _ = write!(s, "format=1\ngeneration={}\nop={}\n", number, op);
    for p in packages {
        let mut hex = [0u8; 64];
        let h = desocrypto::hex(&p.manifest, &mut hex).unwrap_or("");
        let reason = if p.reason == InstallReason::Explicit { "explicit" } else { "dependency" };
        let _ = write!(s, "package={}\nversion={}\ndir={}\nreason={}\nmanifest={}\n", p.name, p.version, p.dir, reason, h);
        for d in &p.depends_raw {
            let _ = writeln!(s, "depends={}", d);
        }
        for d in &p.conflicts {
            let _ = writeln!(s, "conflicts={}", d);
        }
        for d in &p.programs {
            let _ = writeln!(s, "program={}", d);
        }
        s.push_str("endpackage\n");
    }
    s.push_str("end\n");
    let digest = desocrypto::sha256::sha256(s.as_bytes());
    let mut hex = [0u8; 64];
    let _ = write!(s, "hash={}\n", desocrypto::hex(&digest, &mut hex).unwrap_or(""));
    s.into_bytes()
}
