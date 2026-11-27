// desopkg's dependency solver – pure code: the installed
// packages (the current generation), the accepted index and one request in; the new set of
// packages (the plan) or a refusal out.  No syscalls – tests/pkg/pkgsolve-host.rs runs it on the
// host.
//
// The rules (a simple solver – no backtracking):
//   * requirements come from the NEW set (an updated package – its new version's, a removed
//     one – none);
//   * `install X` – X's highest available version, `install X=V` – exactly V (not in the index =
//     refused); a lower version than installed only when asked for by `X=V` (a downgrade – the
//     caller asks y/N);
//   * a dependency already installed that satisfies `>=` stays; otherwise the highest available
//     version – if that does not satisfy, refused (lower versions are never tried);
//     dependencies are never lowered by the solver;
//   * `update` – the highest available version of every installed package (or of the named
//     ones); the same version = kept;
//   * refused before any change: a package or version not in the index, nothing satisfies, a
//     cycle, a conflict (by name, both ways), a downgrade breaking another package's requirement
//     (named), `remove X` while another package needs X; depth at most 8, at most 64 packages;
//   * packages installed as a dependency that nothing needs any more – "no longer needed"
//     (listed, never removed by themselves);
//   * index entries for a newer ABI than the system's are not available.

#![allow(dead_code)]

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::pkgfmt::{Dep, Index, IndexEntry, InstallReason, SYSTEM_ABI, Version, parse_dep};

pub const MAX_DEPTH: usize = 8;
pub const MAX_PACKAGES: usize = 64;

/// One installed package (from the current generation).
#[derive(Clone, Debug)]
pub struct Installed {
    pub name: String,
    pub version: Version,
    pub reason: InstallReason,
    pub depends: Vec<Dep>,
    pub conflicts: Vec<String>,
}

#[derive(Clone, Debug)]
pub enum Request {
    /// (name, exact version or the highest).
    Install(Vec<(String, Option<Version>)>),
    /// Empty – every installed package.
    Update(Vec<String>),
    Remove(Vec<String>),
    Reinstall(Vec<String>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Keep,
    Install,
    Upgrade(Version),
    Downgrade(Version),
    Reinstall,
}

/// One package of the new set.
#[derive(Clone, Debug)]
pub struct Step {
    pub name: String,
    pub version: Version,
    pub action: Action,
    pub reason: InstallReason,
    /// The reason before (None – new): `install X` of a dependency makes it explicit.
    pub was_reason: Option<InstallReason>,
    pub depends: Vec<Dep>,
    pub conflicts: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Plan {
    /// The whole new set, sorted by name.
    pub steps: Vec<Step>,
    pub removed: Vec<(String, Version)>,
    /// Installed as a dependency, needed by nothing in the new set.
    pub unneeded: Vec<String>,
}

impl Plan {
    /// Whether anything changes (a step that is not Keep, or a removal).
    pub fn changes(&self) -> bool {
        !self.removed.is_empty() || self.steps.iter().any(|s| s.action != Action::Keep || s.was_reason.is_some_and(|r| r != s.reason))
    }
    pub fn downgrades(&self) -> Vec<(&str, Version, Version)> {
        self.steps.iter().filter_map(|s| if let Action::Downgrade(from) = s.action { Some((s.name.as_str(), from, s.version)) } else { None }).collect()
    }
    /// Packages to download: new, other version, reinstalled.
    pub fn fetches(&self) -> Vec<&Step> {
        self.steps.iter().filter(|s| s.action != Action::Keep).collect()
    }
}

/// A refusal: a short id (for tests) and the message for the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub id: &'static str,
    pub msg: String,
}

fn refuse(id: &'static str, msg: String) -> Refusal {
    Refusal { id, msg }
}

/// An index entry this system can run (its ABI: same major, minor not newer).
pub fn compatible(e: &IndexEntry) -> bool {
    e.abi.0 == SYSTEM_ABI.0 && e.abi.1 <= SYSTEM_ABI.1
}

/// The highest available version of `name`.
pub fn newest<'a>(idx: &'a Index, name: &str) -> Option<&'a IndexEntry> {
    idx.packages.iter().filter(|e| e.name == name && compatible(e)).max_by_key(|e| e.version)
}

fn satisfies(v: Version, d: &Dep) -> bool {
    d.min.is_none_or(|m| v >= m)
}

/// Where a package of the new set came from.
#[derive(Clone, Debug)]
struct Slot {
    name: String,
    version: Version,
    reason: InstallReason,
    depends: Vec<Dep>,
    conflicts: Vec<String>,
    /// The version and reason before (None – new).
    was: Option<Version>,
    was_reason: Option<InstallReason>,
    /// Set by the user (install X / X=V / update X / reinstall X) – the solver does not move it.
    pinned: bool,
    reinstall: bool,
    depth: usize,
}

fn from_entry(e: &IndexEntry) -> (Vec<Dep>, Vec<String>) {
    let deps = e.depends_raw.iter().filter_map(|d| parse_dep(d)).collect();
    (deps, e.conflicts.clone())
}

pub fn solve(installed: &[Installed], idx: &Index, req: &Request) -> Result<Plan, Refusal> {
    let mut set: Vec<Slot> = installed
        .iter()
        .map(|p| Slot {
            name: p.name.clone(),
            version: p.version,
            reason: p.reason,
            depends: p.depends.clone(),
            conflicts: p.conflicts.clone(),
            was: Some(p.version),
            was_reason: Some(p.reason),
            pinned: false,
            reinstall: false,
            depth: 0,
        })
        .collect();
    let mut removed: Vec<(String, Version)> = Vec::new();
    let find = |set: &Vec<Slot>, n: &str| set.iter().position(|s| s.name == n);

    // 1. The request.
    match req {
        Request::Install(list) => {
            for (name, want) in list {
                let e = match want {
                    Some(v) => idx.find(name, *v).filter(|e| compatible(e)).ok_or_else(|| {
                        if idx.packages.iter().any(|e| e.name == *name) {
                            refuse("no_version", format!("{} {} is not in the repository", name, v))
                        } else {
                            refuse("no_package", format!("no package {} in the repository", name))
                        }
                    })?,
                    None => newest(idx, name).ok_or_else(|| refuse("no_package", format!("no package {} in the repository", name)))?,
                };
                let (depends, conflicts) = from_entry(e);
                match find(&set, name) {
                    Some(i) => {
                        let s = &mut set[i];
                        if want.is_none() && s.version >= e.version {
                            // Already installed (the highest, or a newer one than the index has):
                            // only marked as asked for.
                            s.reason = InstallReason::Explicit;
                            s.pinned = true;
                            continue;
                        }
                        s.version = e.version;
                        s.depends = depends;
                        s.conflicts = conflicts;
                        s.reason = InstallReason::Explicit;
                        s.pinned = true;
                    }
                    None => set.push(Slot {
                        name: name.clone(),
                        version: e.version,
                        reason: InstallReason::Explicit,
                        depends,
                        conflicts,
                        was: None,
                        was_reason: None,
                        pinned: true,
                        reinstall: false,
                        depth: 0,
                    }),
                }
            }
        }
        Request::Update(names) => {
            for n in names {
                if find(&set, n).is_none() {
                    return Err(refuse("not_installed", format!("{} is not installed", n)));
                }
            }
            for s in set.iter_mut() {
                if !names.is_empty() && !names.contains(&s.name) {
                    continue;
                }
                if let Some(e) = newest(idx, &s.name) {
                    if e.version > s.version {
                        let (d, c) = from_entry(e);
                        s.version = e.version;
                        s.depends = d;
                        s.conflicts = c;
                    }
                }
                s.pinned = true;
            }
        }
        Request::Remove(names) => {
            for n in names {
                let Some(i) = find(&set, n) else {
                    return Err(refuse("not_installed", format!("{} is not installed", n)));
                };
                let s = set.remove(i);
                removed.push((s.name, s.version));
            }
        }
        Request::Reinstall(names) => {
            for n in names {
                let Some(i) = find(&set, n) else {
                    return Err(refuse("not_installed", format!("{} is not installed", n)));
                };
                if idx.find(n, set[i].version).is_none() {
                    return Err(refuse("no_version", format!("{} {} is no longer in the repository - cannot reinstall it", n, set[i].version)));
                }
                set[i].reinstall = true;
                set[i].pinned = true;
            }
        }
    }

    // 2. Dependencies until nothing changes.
    let mut rounds = 0;
    loop {
        rounds += 1;
        if rounds > MAX_PACKAGES * 4 {
            return Err(refuse("too_deep", String::from("dependencies do not settle")));
        }
        let mut changed = false;
        let mut i = 0;
        while i < set.len() {
            let parent = set[i].name.clone();
            let pdepth = set[i].depth;
            let deps = set[i].depends.clone();
            for d in &deps {
                match find(&set, &d.name) {
                    Some(j) => {
                        if satisfies(set[j].version, d) {
                            continue;
                        }
                        let min = d.min.unwrap_or(Version(0, 0, 0));
                        if set[j].pinned {
                            // The user chose this version (install X=V, update): never moved.
                            if let Some(was) = set[j].was.filter(|w| *w > set[j].version) {
                                return Err(refuse("breaks", format!("{} {} -> {} would break {} (it needs {}>={})", set[j].name, was, set[j].version, parent, d.name, min)));
                            }
                            return Err(refuse("unsatisfied", format!("{} needs {}>={} - the repository has {}", parent, d.name, min, set[j].version)));
                        }
                        match newest(idx, &d.name) {
                            Some(e) if satisfies(e.version, d) && e.version > set[j].version => {
                                let (dd, cc) = from_entry(e);
                                let s = &mut set[j];
                                s.version = e.version;
                                s.depends = dd;
                                s.conflicts = cc;
                                s.depth = s.depth.max(pdepth + 1);
                                changed = true;
                            }
                            _ => return Err(refuse("unsatisfied", format!("{} needs {}>={} - no such version in the repository", parent, d.name, min))),
                        }
                    }
                    None => {
                        if removed.iter().any(|(n, _)| *n == d.name) {
                            return Err(refuse("needed", format!("{} is needed by {}", d.name, parent)));
                        }
                        let Some(e) = newest(idx, &d.name) else {
                            return Err(refuse("unsatisfied", format!("{} needs {} - not in the repository", parent, d.name)));
                        };
                        if !satisfies(e.version, d) {
                            return Err(refuse("unsatisfied", format!("{} needs {}>={} - the repository has {}", parent, d.name, d.min.unwrap_or(Version(0, 0, 0)), e.version)));
                        }
                        if pdepth + 1 > MAX_DEPTH {
                            return Err(refuse("too_deep", format!("dependencies deeper than {} levels ({} -> {})", MAX_DEPTH, parent, d.name)));
                        }
                        if set.len() == MAX_PACKAGES {
                            return Err(refuse("too_many", format!("more than {} packages", MAX_PACKAGES)));
                        }
                        let (dd, cc) = from_entry(e);
                        set.push(Slot {
                            name: d.name.clone(),
                            version: e.version,
                            reason: InstallReason::Dependency,
                            depends: dd,
                            conflicts: cc,
                            was: None,
                            was_reason: None,
                            pinned: false,
                            reinstall: false,
                            depth: pdepth + 1,
                        });
                        changed = true;
                    }
                }
            }
            i += 1;
        }
        if !changed {
            break;
        }
    }

    // 3. Cycles (a dependency path back to itself).
    fn visit(set: &[Slot], i: usize, stack: &mut Vec<usize>, done: &mut Vec<bool>) -> Option<String> {
        if let Some(pos) = stack.iter().position(|&k| k == i) {
            let mut names: Vec<&str> = stack[pos..].iter().map(|&k| set[k].name.as_str()).collect();
            names.push(&set[i].name);
            return Some(names.join(" -> "));
        }
        if done[i] {
            return None;
        }
        stack.push(i);
        for d in &set[i].depends {
            if let Some(j) = set.iter().position(|s| s.name == d.name) {
                if let Some(c) = visit(set, j, stack, done) {
                    return Some(c);
                }
            }
        }
        stack.pop();
        done[i] = true;
        None
    }
    let mut done = alloc::vec![false; set.len()];
    for i in 0..set.len() {
        if let Some(c) = visit(&set, i, &mut Vec::new(), &mut done) {
            return Err(refuse("cycle", format!("dependency cycle: {}", c)));
        }
    }

    // 4. Conflicts, both ways.
    for a in &set {
        for b in &set {
            if a.name != b.name && a.conflicts.contains(&b.name) {
                return Err(refuse("conflict", format!("{} conflicts with {}", a.name, b.name)));
            }
        }
    }

    // 5. Removals: nothing left may need them (step 2 refuses a missing dependency already –
    //    this names the package for a plain `remove`).
    for (n, _) in &removed {
        if let Some(p) = set.iter().find(|s| s.depends.iter().any(|d| d.name == *n)) {
            return Err(refuse("needed", format!("{} is needed by {}", n, p.name)));
        }
    }

    // 6. No longer needed: dependencies not reachable from an explicit package.
    let mut need = alloc::vec![false; set.len()];
    let mut work: Vec<usize> = (0..set.len()).filter(|&i| set[i].reason == InstallReason::Explicit).collect();
    while let Some(i) = work.pop() {
        if need[i] {
            continue;
        }
        need[i] = true;
        for d in &set[i].depends {
            if let Some(j) = set.iter().position(|s| s.name == d.name) {
                work.push(j);
            }
        }
    }
    let mut unneeded: Vec<String> = set.iter().zip(need.iter()).filter(|(_, n)| !**n).map(|(s, _)| s.name.clone()).collect();
    unneeded.sort();

    let mut steps: Vec<Step> = set
        .into_iter()
        .map(|s| {
            let action = match s.was {
                None => Action::Install,
                Some(w) if s.reinstall && w == s.version => Action::Reinstall,
                Some(w) if s.version > w => Action::Upgrade(w),
                Some(w) if s.version < w => Action::Downgrade(w),
                Some(_) => Action::Keep,
            };
            Step { name: s.name, version: s.version, action, reason: s.reason, was_reason: s.was_reason, depends: s.depends, conflicts: s.conflicts }
        })
        .collect();
    steps.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Plan { steps, removed, unneeded })
}
