// User programs embedded in the kernel image (like an initramfs).
//
// build.sh compiles user/bin/*.rs into ELF files (build/user/<name>)
// and generates build/user/initrd.rs with a list of (name, bytes).  At boot
// the kernel writes them to ramfs as /bin/<name> – from then on they are ordinary
// files: `run hello` reads /bin/hello from the VFS and loads it with the ELF loader, and
// `cp /bin/hello /disk/` copies the program to disk.

include!("../build/user/initrd.rs");

/// The trusted CA store: /etc/certs/roots, then sealed – the file, /etc/certs and /etc (no
/// process, not even the kernel's shell, can change, remove, rename or cover them; see
/// fs/ramfs.rs).  This is the only time it is written: updating it means a new image.
fn install_roots() {
    use crate::fs;
    let ok = (fs::stat("/etc/certs").is_ok() || fs::mkdir("/etc/certs").is_ok())
        && fs::write_file("/etc/certs/roots", ETC_CERTS_ROOTS).is_ok()
        && fs::seal("/etc/certs/roots").is_ok()
        && fs::seal("/etc/certs").is_ok()
        && fs::seal("/etc").is_ok();
    if !ok {
        crate::serial_println!("[FS] cannot install the CA store /etc/certs/roots - TLS will refuse every server");
    }
}

/// Creates /bin and writes the programs, and /etc/services with the service manifests
/// (init reads them once at its start).  Returns the number of programs.
pub fn install() -> usize {
    use crate::fs;
    for (dir, files) in [("/etc", &[][..]), ("/etc/services", ETC_SERVICES)] {
        if fs::stat(dir).is_err() {
            if let Err(e) = fs::mkdir(dir) {
                // Without the manifests init starts no services (no network, no USB) –
                // say why instead of booting quietly without them.
                crate::serial_println!("[FS] cannot create {}: {} - init will start no services", dir, e);
                continue;
            }
        }
        for (name, data) in files {
            let path = alloc::format!("{}/{}", dir, name);
            if let Err(e) = fs::write_file(&path, data) {
                crate::serial_println!("[FS] cannot write {}: {} - that service will not start", path, e);
            }
        }
    }
    install_roots();
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
