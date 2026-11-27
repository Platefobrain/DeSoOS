// desopkg's state on the disk (V082 plan §2, §5, §6.2; V082-B plan §2) – shared by /bin/desopkg
// and /bin/sh, so both pick the same current generation.
//
//   /disk/pkg/<package>/<version>-<16 hex>/bin/<program>, share/…, package   (package = last)
//   /disk/pkg/gen/<n>            generations: the highest VALID one is current (like the DeSoFS
//                                superblock) – an unfinished or damaged file does not count
//   /disk/pkg/index/<serial>     accepted indexes: the highest valid one is in force
//
// Validation is pkgfmt.rs (stage A): `parse_generation` + every package's `package` file
// (`check_generation_package`); `check_accepted` for an index.  Nothing here asks the user or
// the network.  The crate root declares `desocrypto`, `elf`, `pkgfmt` and links libdeso.

#![allow(dead_code)]

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::pkgfmt::{self, Generation, Index, Key, Manifest, Reason};
use libdeso::{ERROR_BUFFER_TOO_SMALL, O_CREATE, O_READ, O_TRUNC, O_WRITE};

pub const ROOT: &str = "/disk/pkg";
pub const GEN_DIR: &str = "/disk/pkg/gen";
pub const INDEX_DIR: &str = "/disk/pkg/index";
/// V082 plan §2 had a download cache here; V082-B (D-B2) downloads into memory – `gc` removes
/// the directory if an older desopkg left one.
pub const CACHE_DIR: &str = "/disk/pkg/cache";

/// The whole file (at most `max` bytes – a larger one is ERROR_NO_SPACE).
pub fn read_file(path: &str, max: usize) -> Result<Vec<u8>, i64> {
    let fd = libdeso::open(path, O_READ);
    if fd < 0 {
        return Err(fd);
    }
    let mut v = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = libdeso::read(fd as u64, &mut buf);
        if n < 0 {
            libdeso::close(fd as u64);
            return Err(n);
        }
        if n == 0 {
            libdeso::close(fd as u64);
            return Ok(v);
        }
        if v.len() + n as usize > max {
            libdeso::close(fd as u64);
            return Err(libdeso::ERROR_NO_SPACE);
        }
        v.extend_from_slice(&buf[..n as usize]);
    }
}

/// Writes a NEW file: an existing one with this name is never overwritten (ERROR_EXISTS).  The
/// data in `parts` one `write` each (a generation is one part: DeSoFS commits each write).
pub fn write_new(path: &str, parts: &[&[u8]]) -> Result<(), i64> {
    if libdeso::stat(path).is_ok() {
        return Err(libdeso::ERROR_ALREADY_EXISTS);
    }
    let fd = libdeso::open(path, O_WRITE | O_CREATE | O_TRUNC);
    if fd < 0 {
        return Err(fd);
    }
    for p in parts {
        let mut off = 0;
        while off < p.len() {
            let n = libdeso::write(fd as u64, &p[off..]);
            if n <= 0 {
                libdeso::close(fd as u64);
                return Err(if n < 0 { n } else { libdeso::ERROR_IO });
            }
            off += n as usize;
        }
    }
    libdeso::close(fd as u64);
    Ok(())
}

/// Entries of a directory: (is a directory, name).  None – no such directory.
pub fn list(dir: &str) -> Option<Vec<(bool, String)>> {
    let mut buf = vec![0u8; 4096];
    loop {
        let n = libdeso::readdir(dir, &mut buf);
        if n == ERROR_BUFFER_TOO_SMALL && buf.len() < 1024 * 1024 {
            let l = buf.len() * 2;
            buf.resize(l, 0);
            continue;
        }
        if n < 0 {
            return None;
        }
        let text = core::str::from_utf8(&buf[..n as usize]).unwrap_or("");
        return Some(
            text.lines()
                .filter_map(|l| {
                    let mut p = l.splitn(3, '\t');
                    let kind = p.next()?;
                    let _size = p.next()?;
                    let name = p.next()?;
                    Some((kind == "d", String::from(name)))
                })
                .collect(),
        );
    }
}

/// Numeric file names of a directory (decimal, no leading zeros, ≤ 2⁶⁴−1), highest first;
/// other names are returned apart (`gc` removes them).
pub fn numbered(dir: &str) -> (Vec<u64>, Vec<String>) {
    let mut nums = Vec::new();
    let mut other = Vec::new();
    for (is_dir, name) in list(dir).unwrap_or_default() {
        match pkgfmt::decimal(&name, u64::MAX).filter(|&n| n > 0) {
            Some(n) if !is_dir => nums.push(n),
            _ => other.push(name),
        }
    }
    nums.sort_unstable_by(|a, b| b.cmp(a));
    (nums, other)
}

pub fn version_dir(package: &str, dir: &str) -> String {
    format!("{}/{}/{}", ROOT, package, dir)
}

/// A valid generation with its packages' manifests (in the generation's order).
pub struct Current {
    pub number: u64,
    pub generation: Generation,
    pub manifests: Vec<Manifest>,
}

impl Current {
    /// (program, full path) of every program.
    pub fn programs(&self) -> Vec<(String, String)> {
        let mut v = Vec::new();
        for p in &self.generation.packages {
            for prog in &p.programs {
                v.push((prog.clone(), format!("{}/bin/{}", version_dir(&p.name, &p.dir), prog)));
            }
        }
        v
    }
}

/// Generation `n` in full (§5): the file's grammar and hash, then every package's `package`
/// file in its directory.
pub fn load_generation(n: u64, system_name: &dyn Fn(&str) -> bool) -> Result<Current, Reason> {
    let raw = read_file(&format!("{}/{}", GEN_DIR, n), pkgfmt::MAX_GENERATION).map_err(|_| "unreadable")?;
    let generation = pkgfmt::parse_generation(&raw, n, system_name)?;
    let mut manifests = Vec::with_capacity(generation.packages.len());
    for e in &generation.packages {
        let path = format!("{}/package", version_dir(&e.name, &e.dir));
        let m = read_file(&path, pkgfmt::MAX_MANIFEST).map_err(|_| "missing_package")?;
        manifests.push(pkgfmt::check_generation_package(e, &m, system_name)?);
    }
    Ok(Current { number: n, generation, manifests })
}

/// What the generations directory holds.
pub struct Generations {
    /// The highest valid one (None – nothing installed yet, or nothing valid).
    pub current: Option<Current>,
    /// The next valid one below it (kept by `gc` as a spare).
    pub previous: Option<u64>,
    /// The highest number present at all (valid or not) – the next one is this + 1.
    pub highest: u64,
    /// Numbers above the current one that are not valid (an unfinished write).
    pub broken_above: Vec<u64>,
}

pub fn generations(system_name: &dyn Fn(&str) -> bool) -> Generations {
    let (nums, _) = numbered(GEN_DIR);
    let mut g = Generations { current: None, previous: None, highest: nums.first().copied().unwrap_or(0), broken_above: Vec::new() };
    for n in nums {
        match load_generation(n, system_name) {
            Ok(c) if g.current.is_none() => g.current = Some(c),
            Ok(_) => {
                g.previous = Some(n);
                break;
            }
            Err(_) if g.current.is_none() => g.broken_above.push(n),
            Err(_) => {}
        }
    }
    g
}

/// Only the current generation's number and file size – the shell's cheap "anything new?".
pub fn newest_generation_stamp() -> Option<(u64, u64)> {
    let (nums, _) = numbered(GEN_DIR);
    let n = *nums.first()?;
    let size = libdeso::stat(&format!("{}/{}", GEN_DIR, n)).ok()?.size;
    Some((n, size))
}

/// An accepted index file that passes (signature, then grammar).
pub struct Accepted {
    pub serial: u64,
    pub index: Index,
}

/// The accepted indexes, highest serial first: (valid ones – at most two, invalid file names).
pub fn accepted(keys: &[Key]) -> (Vec<Accepted>, Vec<u64>) {
    let (nums, _) = numbered(INDEX_DIR);
    let mut good = Vec::new();
    let mut bad = Vec::new();
    for s in nums {
        if good.len() == 2 {
            break;
        }
        let ok = read_file(&format!("{}/{}", INDEX_DIR, s), pkgfmt::MAX_INDEX + pkgfmt::MAX_SIG + 64)
            .ok()
            .and_then(|b| pkgfmt::check_accepted(&b, keys).ok())
            .filter(|i| i.serial == s);
        match ok {
            Some(index) => good.push(Accepted { serial: s, index }),
            None => bad.push(s),
        }
    }
    (good, bad)
}

/// Removes a file or a whole directory tree (files first, then directories, deepest first).
/// Errors other than "not found" are counted, not stopped at – `gc` goes on with the rest.
pub fn remove_tree(path: &str) -> usize {
    let mut errors = 0;
    if let Ok(s) = libdeso::stat(path) {
        if s.is_dir {
            for (_, name) in list(path).unwrap_or_default() {
                errors += remove_tree(&format!("{}/{}", path, name));
            }
        }
        let r = libdeso::unlink(path);
        if r < 0 && r != libdeso::ERROR_NOT_FOUND {
            errors += 1;
        }
    }
    errors
}

/// What `gc` removed.
#[derive(Default, Debug)]
pub struct Swept {
    pub generations: usize,
    pub indexes: usize,
    pub dirs: usize,
    pub errors: usize,
}

/// §6.2: keeps the current generation and the previous valid one with the directories they
/// point to, and the two newest valid indexes; removes everything else under /disk/pkg.  Every
/// step stands alone – an interrupted `gc` is finished by the next one.
pub fn gc(current: Option<&Current>, previous: Option<u64>, keep_index: &[u64], system_name: &dyn Fn(&str) -> bool) -> Swept {
    let mut sw = Swept::default();
    let mut keep_gen: Vec<u64> = current.map(|c| c.number).into_iter().chain(previous).collect();
    // The highest generation file stays even when it is not valid (an unfinished write, a
    // damaged package file): the next generation gets a higher number, so numbers only grow
    // (the shell's cache compares the newest number); it goes once a newer one exists.
    if let Some(&top) = numbered(GEN_DIR).0.first() {
        if !keep_gen.contains(&top) {
            keep_gen.push(top);
        }
    }
    // The directories the kept generations point to.
    let mut keep_dirs: Vec<(String, String)> = Vec::new();
    if let Some(c) = current {
        keep_dirs.extend(c.generation.packages.iter().map(|p| (p.name.clone(), p.dir.clone())));
    }
    if let Some(p) = previous {
        if let Ok(g) = load_generation(p, system_name) {
            keep_dirs.extend(g.generation.packages.iter().map(|p| (p.name.clone(), p.dir.clone())));
        }
    }
    // 1. generations
    let (nums, other) = numbered(GEN_DIR);
    for n in nums.iter().filter(|n| !keep_gen.contains(n)) {
        sw.errors += remove_tree(&format!("{}/{}", GEN_DIR, n));
        sw.generations += 1;
    }
    for name in other {
        sw.errors += remove_tree(&format!("{}/{}", GEN_DIR, name));
    }
    // 2. indexes
    let (nums, other) = numbered(INDEX_DIR);
    for s in nums.iter().filter(|s| !keep_index.contains(s)) {
        sw.errors += remove_tree(&format!("{}/{}", INDEX_DIR, s));
        sw.indexes += 1;
    }
    for name in other {
        sw.errors += remove_tree(&format!("{}/{}", INDEX_DIR, name));
    }
    // 3. version directories nothing points to (unfinished ones included), then empty package
    //    directories; 4. the old download cache.
    for (is_dir, pkg) in list(ROOT).unwrap_or_default() {
        if matches!(pkg.as_str(), "gen" | "index") {
            continue;
        }
        let pdir = format!("{}/{}", ROOT, pkg);
        if !is_dir {
            sw.errors += remove_tree(&pdir);
            continue;
        }
        let mut left = 0;
        for (_, d) in list(&pdir).unwrap_or_default() {
            if keep_dirs.iter().any(|(p, k)| *p == pkg && *k == d) {
                left += 1;
                continue;
            }
            sw.errors += remove_tree(&format!("{}/{}", pdir, d));
            sw.dirs += 1;
        }
        if left == 0 {
            sw.errors += remove_tree(&pdir);
        }
    }
    sw
}
