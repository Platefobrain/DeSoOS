// M16: kopiowanie pliku (cp, mv) – po kawałku przez read/write.
#![allow(dead_code)]

use alloc::format;
use alloc::string::String;

use crate::desoos::{O_CREATE, O_READ, O_TRUNC, O_WRITE, close, open, read, stat, strerror, write};

/// Cel kopiowania: katalog -> katalog/<nazwa źródła>.
pub fn target(src: &str, dst: &str) -> String {
    match stat(dst) {
        Ok(s) if s.is_dir => {
            let name = src.trim_end_matches('/').rsplit('/').next().unwrap_or(src);
            if dst.ends_with('/') { format!("{}{}", dst, name) } else { format!("{}/{}", dst, name) }
        }
        _ => String::from(dst),
    }
}

/// Kopiuje plik; zwraca liczbę bajtów.
pub fn copy_file(src: &str, dst: &str) -> Result<u64, String> {
    let dst = target(src, dst);
    let s = stat(src).map_err(|e| format!("{}: {}", src, strerror(e)))?;
    if s.is_dir {
        return Err(format!("{}: is a directory", src));
    }
    let fin = open(src, O_READ);
    if fin < 0 {
        return Err(format!("{}: {}", src, strerror(fin)));
    }
    let fout = open(&dst, O_WRITE | O_CREATE | O_TRUNC);
    if fout < 0 {
        close(fin as u64);
        return Err(format!("{}: {}", dst, strerror(fout)));
    }
    let mut buf = alloc::vec![0u8; 16 * 1024];
    let mut total = 0u64;
    let result = loop {
        let n = read(fin as u64, &mut buf);
        if n < 0 {
            break Err(format!("{}: {}", src, strerror(n)));
        }
        if n == 0 {
            break Ok(total);
        }
        let w = write(fout as u64, &buf[..n as usize]);
        if w != n {
            break Err(format!("{}: {}", dst, if w < 0 { strerror(w) } else { "short write" }));
        }
        total += n as u64;
    };
    close(fin as u64);
    close(fout as u64);
    result
}
