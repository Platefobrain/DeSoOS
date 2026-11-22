// libdeso::fs – Files and directories: paths, directory handles, the file sandbox.

#[allow(unused_imports)]
use crate::*;

pub fn write(fd: u64, data: &[u8]) -> i64 {
    syscall3(SYS_WRITE, fd, data.as_ptr() as u64, data.len() as u64)
}

pub fn read(fd: u64, buf: &mut [u8]) -> i64 {
    syscall3(SYS_READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64)
}

/// Opens a file.  A program in the file sandbox that was given a directory handle
/// (`nofiles --dir`) opens relative paths inside that directory instead.
pub fn open(path: &str, flags: u64) -> i64 {
    let r = syscall3(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, flags);
    match in_dir(r, path) {
        Some(d) => openat(d, path, flags),
        None => r,
    }
}

// ------------------------------------------------------------
// Directory handles
// ------------------------------------------------------------

/// A handle to directory `path`: `O_READ` (read, list) and / or `O_WRITE`
/// (create, change, remove inside).  Refused in the file sandbox (a path call).
pub fn dir_open(path: &str, flags: u64) -> i64 {
    syscall3(SYS_DIR_OPEN, path.as_ptr() as u64, path.len() as u64, flags)
}

/// `open` relative to directory handle `dir` (never leaves it).
pub fn openat(dir: u64, path: &str, flags: u64) -> i64 {
    syscall6(SYS_OPENAT, dir, path.as_ptr() as u64, path.len() as u64, flags, 0, 0)
}

/// `readdir` inside `dir` ("" = the directory itself).
/// A directory in parts: entries ("d|f\t<size>\t<name>\n") from position `*cursor` (0 =
/// start) as far as they fit in `buf`; `*cursor` becomes the next position (DIR_END =
/// done).  `dir` is a directory handle (READ), `path` relative to it ("" = itself).
pub fn readdir_part(dir: u64, path: &str, buf: &mut [u8], cursor: &mut u64) -> i64 {
    syscall6(SYS_READDIR_PART, dir, path.as_ptr() as u64, path.len() as u64, buf.as_mut_ptr() as u64, buf.len() as u64, cursor as *mut u64 as u64)
}

/// A handle for reading directory `path` in parts: (handle, path relative to it, whether
/// the caller must close it).  Normally a new READ handle; in the file sandbox the
/// directory handle given to the program (a relative `path` inside it).
pub fn dir_for_listing(path: &str) -> Result<(u64, &str, bool), i64> {
    let h = dir_open(path, O_READ);
    if h >= 0 {
        return Ok((h as u64, "", true));
    }
    match in_dir(h, path) {
        Some(d) => Ok((d, path, false)),
        None => Err(h),
    }
}

pub fn readdirat(dir: u64, path: &str, buf: &mut [u8]) -> i64 {
    syscall6(SYS_READDIRAT, dir, path.as_ptr() as u64, path.len() as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0)
}

/// `stat` inside `dir` ("" = the directory itself).
pub fn statat(dir: u64, path: &str) -> Result<Stat, i64> {
    let mut out = [0u64; 2];
    let r = syscall6(SYS_STATAT, dir, path.as_ptr() as u64, path.len() as u64, out.as_mut_ptr() as u64, 0, 0);
    if r < 0 { Err(r) } else { Ok(Stat { is_dir: out[0] == 1, size: out[1] }) }
}

pub fn mkdirat(dir: u64, path: &str) -> i64 {
    syscall3(SYS_MKDIRAT, dir, path.as_ptr() as u64, path.len() as u64)
}

pub fn unlinkat(dir: u64, path: &str) -> i64 {
    syscall3(SYS_UNLINKAT, dir, path.as_ptr() as u64, path.len() as u64)
}

/// The first directory handle this process holds (`nofiles --dir` puts one in).
pub fn find_dir() -> Option<u64> {
    (0..64).find(|&h| handle_info(h).map(|(k, _)| k) == Ok(KIND_DIR))
}

/// After a path call was refused: the directory handle to retry through, when the
/// path is relative and the process holds one.
fn in_dir(r: i64, path: &str) -> Option<u64> {
    if r != ERROR_ACCESS_DENIED || path.starts_with('/') {
        return None;
    }
    find_dir()
}

/// New position (SEEK_SET / SEEK_CUR / SEEK_END); result – the position.
pub fn seek(fd: u64, offset: i64, whence: u64) -> i64 {
    syscall3(SYS_SEEK, fd, offset as u64, whence)
}

pub fn chdir(path: &str) -> i64 {
    syscall3(SYS_CHDIR, path.as_ptr() as u64, path.len() as u64, 0)
}

/// Current directory into `buf`; returns it as &str.
pub fn getcwd(buf: &mut [u8]) -> &str {
    let n = syscall3(SYS_GETCWD, buf.as_mut_ptr() as u64, buf.len() as u64, 0);
    if n <= 0 {
        return "/";
    }
    core::str::from_utf8(&buf[..n as usize]).unwrap_or("/")
}

/// Directory contents: lines "d|f\t<size>\t<name>\n".  ERROR_BUFFER_TOO_SMALL = buffer too small.
pub fn readdir(path: &str, buf: &mut [u8]) -> i64 {
    let r = syscall6(SYS_READDIR, path.as_ptr() as u64, path.len() as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0);
    match in_dir(r, path) {
        Some(d) => readdirat(d, path, buf),
        None => r,
    }
}

#[derive(Clone, Copy)]
pub struct Stat {
    pub is_dir: bool,
    pub size: u64,
}

pub fn stat(path: &str) -> Result<Stat, i64> {
    let mut out = [0u64; 2];
    let r = syscall3(SYS_STAT, path.as_ptr() as u64, path.len() as u64, out.as_mut_ptr() as u64);
    if let Some(d) = in_dir(r, path) {
        return statat(d, path);
    }
    if r < 0 { Err(r) } else { Ok(Stat { is_dir: out[0] == 1, size: out[1] }) }
}

pub fn mkdir(path: &str) -> i64 {
    let r = syscall3(SYS_MKDIR, path.as_ptr() as u64, path.len() as u64, 0);
    match in_dir(r, path) {
        Some(d) => mkdirat(d, path),
        None => r,
    }
}

pub fn unlink(path: &str) -> i64 {
    let r = syscall3(SYS_UNLINK, path.as_ptr() as u64, path.len() as u64, 0);
    match in_dir(r, path) {
        Some(d) => unlinkat(d, path),
        None => r,
    }
}
