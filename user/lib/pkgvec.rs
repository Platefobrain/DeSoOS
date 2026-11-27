// The PKG FORMAT TEST vectors (tools/desopkg.py `vectors`): files made and judged by the
// Python tool, judged again here by user/lib/pkgfmt.rs – the same verdict and the same reason
// id for every one, or the test fails.  Used by /bin/pkgtest (in QEMU) and the host check
// (tests/pkgfmt-host.sh).
//
// The container (docs/pkg/FORMAT.md, "Test vectors"):
//   DESOPKG-VECTORS 1 <count>\n
//   then <count> records:
//     REC <kind> <expect> <parts> <description>\n
//     then <parts> times:  <label> <length>\n<length bytes>\n
// `expect` is `ok` or a reason id (`lt` / `eq` / `gt` for `vercmp`).  Kinds and their parts:
//   manifest  manifest                 parse_manifest
//   pkg       pkg                      parse_pkg (header, manifest, data, SHA-256, ELF)
//   pkgidx    index pkg entry          the index entry "<name> <version>", check_pkg_against_index
//   index     index                    parse_index
//   repo      index repo               parse_index, parse_repo_config, check_index_repo
//   time      index now                parse_index, check_index_time (now: Unix seconds)
//   sig       index sig keys           parse_keys, verify_index
//   accepted  file keys                parse_keys, check_accepted
//   keys      keys                     parse_keys
//   repocfg   repo                     parse_repo_config
//   gen       gen n [manifest:<pkg>]…  parse_generation (n: the file name), then
//                                      check_generation_package for each package
//                                      (no manifest part = `missing_package`)
//   vercmp    a b                      Version order
//   reserved  names                    every system name (one per line, the Python side's: the
//                                      lists of user/lib/cmdnames.rs + the programs of /bin)
//                                      refused as a package name and as a program
//                                      (`reserved_name`), "Sh" refused by the grammar, and the
//                                      list equal to this side's own (`names_differ`)

#![allow(dead_code)]

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::pkgfmt::{self, Reason, Version};

pub struct Record<'a> {
    pub kind: &'a str,
    pub expect: &'a str,
    pub desc: &'a str,
    pub parts: Vec<(&'a str, &'a [u8])>,
}

impl<'a> Record<'a> {
    fn part(&self, label: &str) -> Result<&'a [u8], String> {
        self.parts.iter().find(|(l, _)| *l == label).map(|(_, b)| *b).ok_or_else(|| format!("no part {:?}", label))
    }
    fn text(&self, label: &str) -> Result<&'a str, String> {
        core::str::from_utf8(self.part(label)?).map_err(|_| format!("part {:?} not text", label))
    }
}

fn line<'a>(b: &'a [u8], pos: &mut usize) -> Result<&'a str, String> {
    let rest = b.get(*pos..).ok_or("past the end")?;
    let nl = rest.iter().position(|&c| c == b'\n').ok_or("no newline")?;
    let s = core::str::from_utf8(&rest[..nl]).map_err(|_| "header not text")?;
    *pos += nl + 1;
    Ok(s)
}

/// The records of a vector file.
pub fn parse(b: &[u8]) -> Result<Vec<Record<'_>>, String> {
    let mut pos = 0;
    let head = line(b, &mut pos)?;
    let count: usize = head.strip_prefix("DESOPKG-VECTORS 1 ").and_then(|n| n.parse().ok()).ok_or("bad vector file header")?;
    let mut out = Vec::new();
    for i in 0..count {
        let h = line(b, &mut pos)?;
        let mut it = h.splitn(5, ' ');
        if it.next() != Some("REC") {
            return Err(format!("record {}: no REC", i));
        }
        let kind = it.next().ok_or("no kind")?;
        let expect = it.next().ok_or("no expect")?;
        let n: usize = it.next().and_then(|n| n.parse().ok()).ok_or("no part count")?;
        let desc = it.next().unwrap_or("");
        let mut parts = Vec::new();
        for _ in 0..n {
            let p = line(b, &mut pos)?;
            let (label, len) = p.rsplit_once(' ').ok_or("bad part line")?;
            let len: usize = len.parse().map_err(|_| "bad part length")?;
            let end = pos.checked_add(len).filter(|&e| e < b.len()).ok_or("part past the end")?;
            if b[end] != b'\n' {
                return Err(format!("record {}: part {:?} not followed by a newline", i, label));
            }
            parts.push((label, &b[pos..end]));
            pos = end + 1;
        }
        out.push(Record { kind, expect, desc, parts });
    }
    if pos != b.len() {
        return Err(String::from("bytes after the last record"));
    }
    Ok(out)
}

fn verdict(r: Result<(), Reason>) -> String {
    String::from(match r {
        Ok(()) => "ok",
        Err(e) => e,
    })
}

/// One record's verdict (`ok`, a reason id, or `lt`/`eq`/`gt`).
/// `names` – every system name this side knows (the lists + /bin), sorted.
pub fn judge(r: &Record, system_name: &dyn Fn(&str) -> bool, names: &[String]) -> Result<String, String> {
    Ok(match r.kind {
        "manifest" => verdict(pkgfmt::parse_manifest(r.part("manifest")?, system_name).map(|_| ())),
        "pkg" => verdict(pkgfmt::parse_pkg(r.part("pkg")?, system_name).map(|_| ())),
        "pkgidx" => {
            let (name, ver) = r.text("entry")?.split_once(' ').ok_or("bad entry")?;
            let ver = Version::parse(ver).ok_or("bad entry version")?;
            let pkg = r.part("pkg")?;
            match pkgfmt::parse_index(r.part("index")?) {
                // A refused index is the verdict (tools/desopkg.py the same).
                Err(e) => String::from(e),
                Ok(idx) => match idx.find(name, ver) {
                    None => String::from("not_in_index"),
                    Some(e) => verdict(pkgfmt::check_pkg_against_index(pkg, e, system_name).map(|_| ())),
                },
            }
        }
        "index" => verdict(pkgfmt::parse_index(r.part("index")?).map(|_| ())),
        "repo" => {
            let (index, repo) = (r.part("index")?, r.part("repo")?);
            verdict(pkgfmt::parse_index(index).and_then(|idx| pkgfmt::parse_repo_config(repo).and_then(|cfg| pkgfmt::check_index_repo(&idx, &cfg))))
        }
        "time" => {
            let now: u64 = r.text("now")?.parse().map_err(|_| "bad now")?;
            verdict(pkgfmt::parse_index(r.part("index")?).and_then(|idx| pkgfmt::check_index_time(&idx, now)))
        }
        "sig" => {
            let (index, sig, keys) = (r.part("index")?, r.part("sig")?, r.part("keys")?);
            verdict(pkgfmt::parse_keys(keys).and_then(|k| pkgfmt::verify_index(index, sig, &k)))
        }
        "accepted" => {
            let (file, keys) = (r.part("file")?, r.part("keys")?);
            verdict(pkgfmt::parse_keys(keys).and_then(|k| pkgfmt::check_accepted(file, &k).map(|_| ())))
        }
        "keys" => verdict(pkgfmt::parse_keys(r.part("keys")?).map(|_| ())),
        "repocfg" => verdict(pkgfmt::parse_repo_config(r.part("repo")?).map(|_| ())),
        "gen" => {
            let n: u64 = r.text("n")?.parse().map_err(|_| "bad n")?;
            let mut res = pkgfmt::parse_generation(r.part("gen")?, n, system_name).map(|_| ());
            if let Ok(g) = pkgfmt::parse_generation(r.part("gen")?, n, system_name) {
                for e in &g.packages {
                    let label = format!("manifest:{}", e.name);
                    let Some((_, m)) = r.parts.iter().find(|(l, _)| *l == label) else {
                        res = Err("missing_package");
                        break;
                    };
                    if let Err(x) = pkgfmt::check_generation_package(e, m, system_name) {
                        res = Err(x);
                        break;
                    }
                }
            }
            verdict(res)
        }
        "vercmp" => {
            let a = Version::parse(r.text("a")?).ok_or("bad a")?;
            let b = Version::parse(r.text("b")?).ok_or("bad b")?;
            String::from(match a.cmp(&b) {
                core::cmp::Ordering::Less => "lt",
                core::cmp::Ordering::Equal => "eq",
                core::cmp::Ordering::Greater => "gt",
            })
        }
        "reserved" => judge_reserved(r.text("names")?, system_name, names),
        k => return Err(format!("unknown kind {:?}", k)),
    })
}

/// A manifest with `name=<n>` and one with the program `bin/<n>` (tools/desopkg.py
/// `reserved_manifests` – the same bytes).
pub fn reserved_manifests(n: &str) -> (Vec<u8>, Vec<u8>) {
    let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let a = format!("format=1\nname={}\nversion=1.0.0\narch=x86_64\nabi=1.0\ndata=0\nsummary=t\nfile=share/x|0|{}|data\nend\n", n, empty);
    let b = format!("format=1\nname=pkgtest-probe\nversion=1.0.0\narch=x86_64\nabi=1.0\ndata=0\nsummary=t\nfile=bin/{}|0|{}|program\nend\n", n, empty);
    (a.into_bytes(), b.into_bytes())
}

fn judge_reserved(text: &str, system_name: &dyn Fn(&str) -> bool, names: &[String]) -> String {
    let mut listed: Vec<&str> = text.split('\n').filter(|s| !s.is_empty()).collect();
    listed.sort();
    listed.dedup();
    if listed.len() != names.len() || listed.iter().zip(names.iter()).any(|(a, b)| *a != b.as_str()) {
        return String::from("names_differ");
    }
    for n in &listed {
        let (a, b) = reserved_manifests(n);
        for m in [a, b] {
            match pkgfmt::parse_manifest(&m, system_name) {
                Ok(_) => return format!("accepted:{}", n),
                Err(e) => {
                    let fine = if pkgfmt::valid_name(n) { e == "reserved_name" } else { matches!(e, "bad_name" | "bad_path" | "bad_program_name") };
                    if !fine {
                        return format!("wrong:{}:{}", n, e);
                    }
                }
            }
        }
    }
    match pkgfmt::parse_manifest(&reserved_manifests("Sh").0, system_name) {
        Ok(_) => String::from("accepted:Sh"),
        Err("bad_name") => String::from("ok"),
        Err(e) => format!("wrong:Sh:{}", e),
    }
}

/// Every record: (number checked, failures as lines).  `names` – this side's system names.
pub fn run(b: &[u8], system_name: &dyn Fn(&str) -> bool, names: &[String]) -> Result<(usize, Vec<String>), String> {
    let recs = parse(b)?;
    let mut fails = Vec::new();
    for (i, r) in recs.iter().enumerate() {
        match judge(r, system_name, names) {
            Ok(got) if got == r.expect => {}
            Ok(got) => fails.push(format!("#{} {} ({}): expected {} got {}", i, r.kind, r.desc, r.expect, got)),
            Err(e) => fails.push(format!("#{} {} ({}): {}", i, r.kind, r.desc, e)),
        }
    }
    Ok((recs.len(), fails))
}
