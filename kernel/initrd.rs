// User programs embedded in the kernel image (like an initramfs).
//
// build.sh compiles user/bin/*.rs into ELF files (build/user/<name>)
// and generates build/user/initrd.rs with a list of (name, bytes).  At boot
// the kernel writes them to ramfs as /bin/<name> – from then on they are ordinary
// files: `run hello` reads /bin/hello from the VFS and loads it with the ELF loader, and
// `cp /bin/hello /disk/` copies the program to disk.

include!("../build/user/initrd.rs");

/// Creates /bin and writes the programs.  Returns their count.
pub fn install() -> usize {
    use crate::fs;
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
