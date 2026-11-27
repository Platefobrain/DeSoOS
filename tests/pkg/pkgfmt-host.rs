// The host half of the PKG FORMAT TEST's Rust side: user/lib/pkgfmt.rs compiled for Linux
// (std only for files and the exit code) judges the vectors tools/desopkg.py made – the same
// code /bin/pkgtest runs in QEMU.  tests/pkg/pkgfmt-host.sh builds and runs it.
//
//   pkgfmt-host <vectors> [<dir with the /bin programs>]
//
// System names: user/lib/cmdnames.rs plus the files in the directory (build/user/ – what goes
// into /bin); without it the few programs every image has (sh, ls, cat, init).
extern crate alloc;

#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;
#[path = "../../common/elf.rs"]
mod elf;
#[path = "../../user/lib/cmdnames.rs"]
mod cmdnames;
#[path = "../../user/lib/pkgfmt.rs"]
mod pkgfmt;
#[path = "../../user/lib/pkgvec.rs"]
mod pkgvec;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: pkgfmt-host <vectors> [<bin dir>]");
        std::process::exit(2);
    }
    let data = std::fs::read(&args[1]).expect("read vectors");
    let bin: Vec<String> = match args.get(2) {
        Some(d) => std::fs::read_dir(d)
            .expect("read bin dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.contains('.'))
            .collect(),
        None => ["sh", "ls", "cat", "init"].iter().map(|s| s.to_string()).collect(),
    };
    let system_name = |n: &str| cmdnames::system_name(n, &|x| bin.iter().any(|b| b == x));
    let mut names: Vec<String> = bin.clone();
    names.extend(cmdnames::BUILTINS.iter().map(|(n, _)| n.to_string()));
    for l in [cmdnames::SYSCTL_BUILTINS, cmdnames::INFO_COMMANDS, cmdnames::KERNEL_ONLY] {
        names.extend(l.iter().map(|n| n.to_string()));
    }
    names.sort();
    names.dedup();
    match pkgvec::run(&data, &system_name, &names) {
        Ok((n, fails)) if fails.is_empty() => println!(
            "[PKG HOST TEST] 5/5 Rust (user/lib/pkgfmt.rs on the host): {} vectors, the same verdict and reason as tools/desopkg.py ({} system names) PASS",
            n,
            names.len()
        ),
        Ok((n, fails)) => {
            for f in &fails {
                println!("[PKG HOST TEST] FAIL {}", f);
            }
            println!("[PKG HOST TEST] FAIL Rust: {} of {} vectors differ", fails.len(), n);
            std::process::exit(1);
        }
        Err(e) => {
            println!("[PKG HOST TEST] FAIL bad vector file: {}", e);
            std::process::exit(1);
        }
    }
}
