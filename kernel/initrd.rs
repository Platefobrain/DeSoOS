// User programs embedded in the kernel image (like an initramfs).
//
// build.sh compiles user/bin/*.rs into ELF files (build/user/<name>)
// and generates build/user/initrd.rs with a list of (name, bytes).  At boot
// the kernel writes them to ramfs as /bin/<name> – from then on they are ordinary
// files: `run hello` reads /bin/hello from the VFS and loads it with the ELF loader, and
// `cp /bin/hello /disk/` copies the program to disk.

include!("../build/user/initrd.rs");

/// Creates /bin and writes the programs, and /etc/services with the service manifests
/// (init reads them once at its start).  Returns the number of programs.
pub fn install() -> usize {
    use crate::fs;
    for (dir, files) in [("/etc", &[][..]), ("/etc/services", ETC_SERVICES)] {
        if fs::stat(dir).is_err() && fs::mkdir(dir).is_err() {
            continue;
        }
        for (name, data) in files {
            let _ = fs::write_file(&alloc::format!("{}/{}", dir, name), data);
        }
    }
    if fs::stat("/bin").is_err() && fs::mkdir("/bin").is_err() {
        return 0;
    }
    let mut n = 0;
    for (name, data) in FILES {
        let path = alloc::format!("/bin/{}", name);
        if fs::write_file(&path, data).is_ok() {
            n += 1;
        }
    }
    n
}
