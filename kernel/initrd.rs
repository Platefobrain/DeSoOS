// M15: programy użytkownika wbudowane w obraz kernela (jak initramfs).
//
// build.sh kompiluje user/bin/*.rs do plików ELF (build/user/<nazwa>)
// i generuje build/user/initrd.rs z listą (nazwa, bajty).  Przy starcie
// kernel zapisuje je do ramfs jako /bin/<nazwa> – od tej chwili to zwykłe
// pliki: `run hello` czyta /bin/hello z VFS i ładuje go loaderem ELF, a
// `cp /bin/hello /disk/` kopiuje program na dysk.

include!("../build/user/initrd.rs");

/// Tworzy /bin i zapisuje programy.  Zwraca ich liczbę.
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
