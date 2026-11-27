// desopkg's dependency solver (user/lib/pkgsolve.rs) on the host: every rule
// on its own, as a table – the request, the installed packages and the index in, the expected
// new set (or refusal id) out.  tests/pkg/pkgfmt-host.sh builds and runs it (PKG HOST TEST).
extern crate alloc;

#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;
#[path = "../../common/elf.rs"]
mod elf;
#[path = "../../user/lib/pkgfmt.rs"]
mod pkgfmt;
#[path = "../../user/lib/pkgsolve.rs"]
mod pkgsolve;

use pkgfmt::{Index, IndexEntry, InstallReason, Version, parse_dep};
use pkgsolve::{Action, Installed, Request, solve};

fn v(s: &str) -> Version {
    Version::parse(s).unwrap()
}

/// "name ver [abi=M.m] [dep ...] [!conflict ...]"
fn entry(spec: &str) -> IndexEntry {
    let mut w = spec.split_whitespace();
    let name = w.next().unwrap().to_string();
    let version = v(w.next().unwrap());
    let mut abi = (1, 0);
    let mut deps = Vec::new();
    let mut conf = Vec::new();
    for x in w {
        if let Some(a) = x.strip_prefix("abi=") {
            abi = pkgfmt::parse_abi(a).unwrap();
        } else if let Some(c) = x.strip_prefix('!') {
            conf.push(c.to_string());
        } else {
            deps.push(x.to_string());
        }
    }
    IndexEntry {
        name,
        version,
        abi,
        size: 1,
        sha256: [0; 32],
        depends: deps.iter().map(|d| parse_dep(d).unwrap()).collect(),
        depends_raw: deps,
        conflicts: conf,
        summary: String::from("s"),
    }
}

fn index(specs: &[&str]) -> Index {
    Index {
        repo: "decodesoft".into(),
        channel: "stable".into(),
        arch: "x86_64".into(),
        serial: 1,
        issued: 0,
        expires: 1,
        packages: specs.iter().map(|s| entry(s)).collect(),
    }
}

/// "name ver e|d [dep ...] [!conflict ...]"
fn installed(specs: &[&str]) -> Vec<Installed> {
    specs
        .iter()
        .map(|spec| {
            let mut w = spec.split_whitespace();
            let name = w.next().unwrap().to_string();
            let version = v(w.next().unwrap());
            let reason = if w.next().unwrap() == "e" { InstallReason::Explicit } else { InstallReason::Dependency };
            let mut deps = Vec::new();
            let mut conflicts = Vec::new();
            for x in w {
                match x.strip_prefix('!') {
                    Some(c) => conflicts.push(c.to_string()),
                    None => deps.push(parse_dep(x).unwrap()),
                }
            }
            Installed { name, version, reason, depends: deps, conflicts }
        })
        .collect()
}

fn inst(list: &[&str]) -> Request {
    Request::Install(
        list.iter()
            .map(|s| match s.split_once('=') {
                Some((n, ver)) => (n.to_string(), Some(v(ver))),
                None => (s.to_string(), None),
            })
            .collect(),
    )
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// The result as text: "a 1.0.0 install e, b 2.0.0 keep d; -c 1.0.0; unneeded x" or "refused <id>".
fn show(r: Result<pkgsolve::Plan, pkgsolve::Refusal>) -> String {
    match r {
        Err(e) => format!("refused {}", e.id),
        Ok(p) => {
            let mut parts: Vec<String> = p
                .steps
                .iter()
                .map(|s| {
                    let a = match s.action {
                        Action::Keep => "keep".to_string(),
                        Action::Install => "install".to_string(),
                        Action::Upgrade(f) => format!("up<{}", f),
                        Action::Downgrade(f) => format!("down<{}", f),
                        Action::Reinstall => "reinstall".to_string(),
                    };
                    format!("{} {} {} {}", s.name, s.version, a, if s.reason == InstallReason::Explicit { "e" } else { "d" })
                })
                .collect();
            let mut out = parts.join(", ");
            for (n, ver) in &p.removed {
                out.push_str(&format!("; -{} {}", n, ver));
            }
            if !p.unneeded.is_empty() {
                out.push_str(&format!("; unneeded {}", p.unneeded.join(" ")));
            }
            if !p.changes() {
                out.push_str("; nothing");
            }
            parts.clear();
            out
        }
    }
}

fn main() {
    let repo = index(&[
        "witaj 1.0.0 fonts>=1.0.0",
        "witaj 1.0.1 fonts>=1.0.0",
        "witaj 1.1.0 fonts>=1.1.0",
        "fonts 1.0.0",
        "fonts 1.1.0",
        "edytor 1.0.0 witaj>=1.1.0",
        "oldwitaj 1.0.0 !witaj",
        "lib 2.0.0 abi=1.1",
        "lib 1.0.0",
        "deep0 1.0.0 deep1",
        "deep1 1.0.0 deep2",
        "deep2 1.0.0 deep3",
        "deep3 1.0.0 deep4",
        "deep4 1.0.0 deep5",
        "deep5 1.0.0 deep6",
        "deep6 1.0.0 deep7",
        "deep7 1.0.0 deep8",
        "deep8 1.0.0 deep9",
        "deep9 1.0.0",
        "cyca 1.0.0 cycb",
        "cycb 1.0.0 cyca",
        "needsnew 1.0.0 fonts>=2.0.0",
        "needsx 1.0.0 nothere",
        "self 1.0.0",
    ]);
    let cases: Vec<(&str, Vec<Installed>, Request, &str)> = vec![
        ("install: the highest version with its dependency", installed(&[]), inst(&["witaj"]), "fonts 1.1.0 install d, witaj 1.1.0 install e"),
        ("install X=V: exactly that version", installed(&[]), inst(&["witaj=1.0.0"]), "fonts 1.1.0 install d, witaj 1.0.0 install e"),
        ("install: an installed dependency that satisfies >= stays", installed(&["fonts 1.0.0 d"]), inst(&["witaj=1.0.1"]), "fonts 1.0.0 keep d, witaj 1.0.1 install e"),
        ("install: a dependency that does not satisfy is raised to the highest", installed(&["fonts 1.0.0 d"]), inst(&["witaj"]), "fonts 1.1.0 up<1.0.0 d, witaj 1.1.0 install e"),
        ("install: already the highest – nothing", installed(&["fonts 1.1.0 d", "witaj 1.1.0 e fonts>=1.1.0"]), inst(&["witaj"]), "fonts 1.1.0 keep d, witaj 1.1.0 keep e; nothing"),
        ("install of a dependency makes it explicit", installed(&["fonts 1.1.0 d", "witaj 1.1.0 e fonts>=1.1.0"]), inst(&["fonts"]), "fonts 1.1.0 keep e, witaj 1.1.0 keep e"),
        ("install X=V lower than installed: a downgrade", installed(&["fonts 1.1.0 d", "witaj 1.1.0 e fonts>=1.1.0"]), inst(&["witaj=1.0.1"]), "fonts 1.1.0 keep d, witaj 1.0.1 down<1.1.0 e"),
        ("downgrade breaking another package's requirement: refused", installed(&["fonts 1.1.0 d", "witaj 1.1.0 e fonts>=1.1.0", "edytor 1.0.0 e witaj>=1.1.0"]), inst(&["witaj=1.0.1"]), "refused breaks"),
        ("install X=V not in the index: refused", installed(&[]), inst(&["witaj=9.9.9"]), "refused no_version"),
        ("install of an unknown package: refused", installed(&[]), inst(&["nope"]), "refused no_package"),
        ("a newer ABI is not available", installed(&[]), inst(&["lib"]), "lib 1.0.0 install e"),
        ("install X=V of a newer ABI: refused", installed(&[]), inst(&["lib=2.0.0"]), "refused no_version"),
        ("no version satisfies: refused, lower versions not tried", installed(&[]), inst(&["needsnew"]), "refused unsatisfied"),
        ("a dependency missing from the index: refused", installed(&[]), inst(&["needsx"]), "refused unsatisfied"),
        ("conflict with an installed package: refused", installed(&["fonts 1.1.0 d", "witaj 1.1.0 e fonts>=1.1.0"]), inst(&["oldwitaj"]), "refused conflict"),
        ("conflict the other way: refused", installed(&["oldwitaj 1.0.0 e !witaj"]), inst(&["witaj"]), "refused conflict"),
        ("a cycle: refused", installed(&[]), inst(&["cyca"]), "refused cycle"),
        ("depth over 8: refused", installed(&[]), inst(&["deep0"]), "refused too_deep"),
        ("depth 8: fine", installed(&[]), inst(&["deep1"]), "deep1 1.0.0 install e, deep2 1.0.0 install d, deep3 1.0.0 install d, deep4 1.0.0 install d, deep5 1.0.0 install d, deep6 1.0.0 install d, deep7 1.0.0 install d, deep8 1.0.0 install d, deep9 1.0.0 install d"),
        ("update: everything with a newer version", installed(&["fonts 1.0.0 d", "witaj 1.0.0 e fonts>=1.0.0"]), Request::Update(vec![]), "fonts 1.1.0 up<1.0.0 d, witaj 1.1.0 up<1.0.0 e"),
        ("update X: only X (and what its new version needs)", installed(&["fonts 1.0.0 d", "witaj 1.0.0 e fonts>=1.0.0", "lib 1.0.0 e"]), Request::Update(names(&["witaj"])), "fonts 1.1.0 up<1.0.0 d, lib 1.0.0 keep e, witaj 1.1.0 up<1.0.0 e"),
        ("update with nothing newer: nothing", installed(&["fonts 1.1.0 d", "witaj 1.1.0 e fonts>=1.1.0"]), Request::Update(vec![]), "fonts 1.1.0 keep d, witaj 1.1.0 keep e; nothing"),
        ("update of a package not installed: refused", installed(&[]), Request::Update(names(&["witaj"])), "refused not_installed"),
        ("update keeps a version newer than the index", installed(&["fonts 9.0.0 e"]), Request::Update(vec![]), "fonts 9.0.0 keep e; nothing"),
        ("remove: the package goes, its dependency is no longer needed", installed(&["fonts 1.1.0 d", "witaj 1.1.0 e fonts>=1.1.0"]), Request::Remove(names(&["witaj"])), "fonts 1.1.0 keep d; -witaj 1.1.0; unneeded fonts"),
        ("remove of a needed package: refused", installed(&["fonts 1.1.0 d", "witaj 1.1.0 e fonts>=1.1.0"]), Request::Remove(names(&["fonts"])), "refused needed"),
        ("remove of a package not installed: refused", installed(&[]), Request::Remove(names(&["witaj"])), "refused not_installed"),
        ("reinstall: the same version again", installed(&["fonts 1.1.0 d", "witaj 1.1.0 e fonts>=1.1.0"]), Request::Reinstall(names(&["witaj"])), "fonts 1.1.0 keep d, witaj 1.1.0 reinstall e"),
        ("reinstall of a version gone from the index: refused", installed(&["fonts 1.1.0 d", "witaj 1.0.5 e fonts>=1.0.0"]), Request::Reinstall(names(&["witaj"])), "refused no_version"),
        ("two packages in one request", installed(&[]), inst(&["witaj", "lib"]), "fonts 1.1.0 install d, lib 1.0.0 install e, witaj 1.1.0 install e"),
        ("a package installed alone stays explicit", installed(&[]), inst(&["self"]), "self 1.0.0 install e"),
    ];
    let mut fails = 0;
    for (desc, inst, req, want) in &cases {
        let got = show(solve(inst, &repo, req));
        if got != *want {
            println!("[PKG HOST TEST] FAIL solver: {}\n    want: {}\n    got:  {}", desc, want, got);
            fails += 1;
        }
    }
    if fails > 0 {
        println!("[PKG HOST TEST] FAIL solver: {} of {} cases", fails, cases.len());
        std::process::exit(1);
    }
    println!("[PKG HOST TEST] 6/6 solver (user/lib/pkgsolve.rs on the host): {} cases – every rule PASS", cases.len());
}
