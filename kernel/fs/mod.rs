// VFS – virtual file system.
//
// A single directory tree into which concrete file systems are "mounted":
//
//   /          ramfs (in memory; gone after a reboot)
//   /disk      FAT32 on the first disk (if it is formatted)
//
// Each file system implements `FileSystem` and gets paths relative to
// its mount point (always normalized, starting with '/').
// The VFS picks the file system by the longest matching mount point.
//
// The API here is path-based (no file descriptors) – the open file
// table belongs to processes and syscalls.

pub mod fat32;
pub mod ramfs;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::block::BlockError;
use crate::drivers::rtc::DateTime;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FsError {
    NotFound,
    NotADirectory,
    IsADirectory,
    AlreadyExists,
    NotEmpty,
    InvalidName,
    NoSpace,
    ReadOnly,
    /// Operation on a mount point (e.g. removing /disk).
    Busy,
    Unsupported,
    /// The disk has no (supported) file system.
    NoFileSystem,
    Corrupt(&'static str),
    Io(BlockError),
}

impl From<BlockError> for FsError {
    fn from(e: BlockError) -> Self {
        match e {
            // Read-only disk (e.g. a real SSD) = read-only file system.
            BlockError::ReadOnly => FsError::ReadOnly,
            e => FsError::Io(e),
        }
    }
}

impl core::fmt::Display for FsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FsError::NotFound => f.write_str("no such file or directory"),
            FsError::NotADirectory => f.write_str("not a directory"),
            FsError::IsADirectory => f.write_str("is a directory"),
            FsError::AlreadyExists => f.write_str("already exists"),
            FsError::NotEmpty => f.write_str("directory not empty"),
            FsError::InvalidName => f.write_str("invalid file name"),
            FsError::NoSpace => f.write_str("no space left on device"),
            FsError::ReadOnly => f.write_str("read-only file system"),
            FsError::Busy => f.write_str("mount point busy"),
            FsError::Unsupported => f.write_str("not supported"),
            FsError::NoFileSystem => f.write_str("no FAT32 file system"),
            FsError::Corrupt(what) => write!(f, "file system corrupt: {}", what),
            FsError::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

pub type Result<T> = core::result::Result<T, FsError>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileType {
    File,
    Directory,
}

#[derive(Clone, Debug)]
pub struct Metadata {
    pub kind: FileType,
    pub size: u64,
    pub modified: Option<DateTime>,
}

#[derive(Clone, Debug)]
pub struct DirEntry {
    pub name: String,
    pub kind: FileType,
    pub size: u64,
    pub modified: Option<DateTime>,
}

pub struct FsStats {
    pub total_bytes: u64,
    pub free_bytes: u64,
}

/// File system interface.  Paths are relative to the mount point,
/// normalized ("/", "/a/b").
pub trait FileSystem {
    /// Type, e.g. "ramfs", "fat32".
    fn kind(&self) -> &'static str;
    /// Description for `mount` (disk, label).
    fn source(&self) -> String;
    fn stat(&mut self, path: &str) -> Result<Metadata>;
    fn read_dir(&mut self, path: &str) -> Result<Vec<DirEntry>>;
    /// Reads from `offset`; returns the number of bytes read (0 = end of file).
    fn read(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize>;
    /// Writes from `offset` (the file grows as needed, holes are zero-filled).
    fn write(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<usize>;
    /// Sets the file size (truncates or zero-extends).
    fn truncate(&mut self, path: &str, size: u64) -> Result<()>;
    /// Creates an empty file (error if it exists).
    fn create(&mut self, path: &str) -> Result<()>;
    fn mkdir(&mut self, path: &str) -> Result<()>;
    /// Removes a file or an empty directory.
    fn remove(&mut self, path: &str) -> Result<()>;
    fn stats(&mut self) -> Option<FsStats>;
    /// Writes everything that is in buffers to disk.
    fn sync(&mut self) -> Result<()>;
    /// A file system with its own locks – the VFS calls it concurrently,
    /// holding FS_LOCK for reading only.  `None` (e.g. FAT32: buffers,
    /// disk reads) – every operation under FS_LOCK for writing.
    fn concurrent(&self) -> Option<&dyn ConcurrentFs> {
        None
    }
    /// Read-only file system (read-only disk) – opening for
    /// writing fails with EROFS immediately.
    fn read_only(&self) -> bool {
        false
    }
}

/// File system operations safe to call from many tasks at once
/// (`&self` – the file system does its own locking).  `read_all`, `write_whole`,
/// `append` – whole operations are atomic (read_file / write_file / >>).
pub trait ConcurrentFs {
    fn stat(&self, path: &str) -> Result<Metadata>;
    fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>>;
    fn read(&self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize>;
    fn read_all(&self, path: &str) -> Result<Vec<u8>>;
    fn write(&self, path: &str, offset: u64, data: &[u8]) -> Result<usize>;
    /// Creates a file or replaces its contents.
    fn write_whole(&self, path: &str, data: &[u8]) -> Result<()>;
    /// Appends (creates the file if missing).
    fn append(&self, path: &str, data: &[u8]) -> Result<()>;
    fn truncate(&self, path: &str, size: u64) -> Result<()>;
    fn create(&self, path: &str) -> Result<()>;
    fn mkdir(&self, path: &str) -> Result<()>;
    fn remove(&self, path: &str) -> Result<()>;
    fn stats(&self) -> FsStats;
}

// ------------------------------------------------------------
// File system with its own lock (USB disk)
// ------------------------------------------------------------

/// Wraps a file system without its own locks (FAT32) in a single sleeping
/// lock – the VFS calls it like a `ConcurrentFs`, i.e. under FS_LOCK for
/// reading only.  Why: a read from a USB stick may wait for usbd up to 5 s (ublk
/// timeout); under FS_LOCK for writing the WHOLE VFS (ramfs, /bin,
/// spawn) would be stuck meanwhile.  Now only this one file system waits.  Used for USB
/// disks (ublk.rs); /disk and /esp – unchanged.
pub struct Locked<F: FileSystem> {
    fs: crate::sched::sync::Mutex<F>,
    /// Copies taken at mount time – `mount` and `open` do not wait for the disk lock.
    kind: &'static str,
    source: String,
    read_only: bool,
}

impl<F: FileSystem + Send> Locked<F> {
    pub fn new(fs: F) -> Self {
        let (kind, source, read_only) = (fs.kind(), fs.source(), fs.read_only());
        Locked { fs: crate::sched::sync::Mutex::new(fs), kind, source, read_only }
    }
}

impl<F: FileSystem + Send> FileSystem for Locked<F> {
    fn kind(&self) -> &'static str {
        self.kind
    }
    fn source(&self) -> String {
        self.source.clone()
    }
    fn stat(&mut self, path: &str) -> Result<Metadata> {
        self.fs.lock().stat(path)
    }
    fn read_dir(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        self.fs.lock().read_dir(path)
    }
    fn read(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.fs.lock().read(path, offset, buf)
    }
    fn write(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<usize> {
        self.fs.lock().write(path, offset, data)
    }
    fn truncate(&mut self, path: &str, size: u64) -> Result<()> {
        self.fs.lock().truncate(path, size)
    }
    fn create(&mut self, path: &str) -> Result<()> {
        self.fs.lock().create(path)
    }
    fn mkdir(&mut self, path: &str) -> Result<()> {
        self.fs.lock().mkdir(path)
    }
    fn remove(&mut self, path: &str) -> Result<()> {
        self.fs.lock().remove(path)
    }
    fn stats(&mut self) -> Option<FsStats> {
        self.fs.lock().stats()
    }
    fn sync(&mut self) -> Result<()> {
        self.fs.lock().sync()
    }
    fn concurrent(&self) -> Option<&dyn ConcurrentFs> {
        Some(self)
    }
    fn read_only(&self) -> bool {
        self.read_only
    }
}

impl<F: FileSystem + Send> ConcurrentFs for Locked<F> {
    fn stat(&self, path: &str) -> Result<Metadata> {
        self.fs.lock().stat(path)
    }
    fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>> {
        self.fs.lock().read_dir(path)
    }
    fn read(&self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.fs.lock().read(path, offset, buf)
    }
    fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        let mut fs = self.fs.lock();
        let meta = fs.stat(path)?;
        if meta.kind == FileType::Directory {
            return Err(FsError::IsADirectory);
        }
        let mut data = alloc::vec![0u8; meta.size as usize];
        let mut done = 0;
        while done < data.len() {
            let n = fs.read(path, done as u64, &mut data[done..])?;
            if n == 0 {
                break;
            }
            done += n;
        }
        data.truncate(done);
        Ok(data)
    }
    fn write(&self, path: &str, offset: u64, data: &[u8]) -> Result<usize> {
        self.fs.lock().write(path, offset, data)
    }
    fn write_whole(&self, path: &str, data: &[u8]) -> Result<()> {
        let mut fs = self.fs.lock();
        match fs.stat(path) {
            Ok(m) if m.kind == FileType::Directory => return Err(FsError::IsADirectory),
            Ok(_) => fs.truncate(path, 0)?,
            Err(FsError::NotFound) => fs.create(path)?,
            Err(e) => return Err(e),
        }
        if !data.is_empty() {
            fs.write(path, 0, data)?;
        }
        fs.sync()
    }
    fn append(&self, path: &str, data: &[u8]) -> Result<()> {
        let mut fs = self.fs.lock();
        let end = match fs.stat(path) {
            Ok(m) if m.kind == FileType::Directory => return Err(FsError::IsADirectory),
            Ok(m) => m.size,
            Err(FsError::NotFound) => {
                fs.create(path)?;
                0
            }
            Err(e) => return Err(e),
        };
        if !data.is_empty() {
            fs.write(path, end, data)?;
        }
        fs.sync()
    }
    fn truncate(&self, path: &str, size: u64) -> Result<()> {
        self.fs.lock().truncate(path, size)
    }
    fn create(&self, path: &str) -> Result<()> {
        self.fs.lock().create(path)
    }
    fn mkdir(&self, path: &str) -> Result<()> {
        self.fs.lock().mkdir(path)
    }
    fn remove(&self, path: &str) -> Result<()> {
        self.fs.lock().remove(path)
    }
    fn stats(&self) -> FsStats {
        self.fs.lock().stats().unwrap_or(FsStats { total_bytes: 0, free_bytes: 0 })
    }
}

// ------------------------------------------------------------
// Paths
// ------------------------------------------------------------

/// Joins `cwd` and `path` and normalizes ("." and "..", double "/").
/// The result always starts with '/' and never ends with '/' (except "/" itself).
pub fn normalize(cwd: &str, path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let full: String = if path.starts_with('/') {
        path.to_string()
    } else {
        alloc::format!("{}/{}", cwd, path)
    };
    for part in full.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    let mut out = String::from("/");
    out.push_str(&parts.join("/"));
    out
}

/// ("/a/b", "c") for "/a/b/c"; ("/", "x") for "/x".
pub fn split_parent(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(0) => ("/", &path[1..]),
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("/", path),
    }
}

// ------------------------------------------------------------
// Mount table
// ------------------------------------------------------------

struct Mount {
    path: String,
    fs: Box<dyn FileSystem>,
}

static mut MOUNTS: Vec<Mount> = Vec::new();

/// The VFS is shared by all tasks – every operation takes
/// FS_LOCK (reentrant: write_file -> stat etc. in the same task).
/// Lock order: FS_LOCK, then the disk locks (block.rs).
///
/// A readers–writer lock.  stat / read / read_dir / read_file
/// on a file system that supports it (ramfs: `*_shared`) take it for
/// reading – many at once (with a single lock it was a heavily contended
/// hotspot).  Modifications and file systems without shared reads (FAT32)
/// – for writing.  Only a writer changes the mount table.
static FS_LOCK: crate::sched::sync::KRwLock = crate::sched::sync::KRwLock::new_named("vfs (FS_LOCK)");

/// For writing (like the former KMutex).
struct FsWrite;
impl FsWrite {
    fn lock() -> crate::sched::sync::KRwGuard<'static> {
        FS_LOCK.write()
    }
}

fn mounts() -> &'static mut Vec<Mount> {
    // Modified only under FS_LOCK for writing; read also under the read lock.
    unsafe { &mut *core::ptr::addr_of_mut!(MOUNTS) }
}

/// Mount index and relative path (under FS_LOCK – read or write).
fn find_mount(path: &str) -> Result<(usize, String)> {
    let path = normalize("/", path);
    let m = mounts();
    let mut best: Option<usize> = None;
    for (i, mount) in m.iter().enumerate() {
        let p = mount.path.as_str();
        let matches = p == "/" || path == p || path.starts_with(p) && path.as_bytes().get(p.len()) == Some(&b'/');
        if matches && best.map_or(true, |b| m[b].path.len() < p.len()) {
            best = Some(i);
        }
    }
    let i = best.ok_or(FsError::NotFound)?;
    let mp = m[i].path.as_str();
    let rel = if mp == "/" {
        path.clone()
    } else if path.len() == mp.len() {
        String::from("/")
    } else {
        String::from(&path[mp.len()..])
    };
    Ok((i, rel))
}

/// An operation on the path's file system – concurrently (FS_LOCK for
/// reading) if the file system has its own locks (`concurrent`), otherwise
/// exclusively (`excl`, FS_LOCK for writing).  A task holding FS_LOCK
/// for reading cannot upgrade to writing – then Busy (does not happen: the VFS
/// does not hold a read lock when calling an operation on a file system without locks).
fn with_fs<R>(
    path: &str,
    conc: impl FnOnce(&dyn ConcurrentFs, &str) -> Result<R>,
    excl: impl FnOnce(&mut dyn FileSystem, &str) -> Result<R>,
) -> Result<R> {
    {
        let _g = FS_LOCK.read();
        let (i, rel) = find_mount(path)?;
        if let Some(c) = mounts()[i].fs.concurrent() {
            return conc(c, &rel);
        }
    }
    if FS_LOCK.read_held() {
        return Err(FsError::Busy);
    }
    resolve(path, excl)
}

/// Mounts a file system at `path` (the directory must exist, except for "/").
pub fn mount(path: &str, fs: Box<dyn FileSystem>) -> Result<()> {
    let _g = FsWrite::lock();
    let path = normalize("/", path);
    if mounts().iter().any(|m| m.path == path) {
        return Err(FsError::Busy);
    }
    if path != "/" {
        match stat(&path) {
            Ok(m) if m.kind == FileType::Directory => {}
            Ok(_) => return Err(FsError::NotADirectory),
            Err(e) => return Err(e),
        }
    }
    mounts().push(Mount { path, fs });
    Ok(())
}

pub fn unmount(path: &str) -> Result<()> {
    let _g = FsWrite::lock();
    let path = normalize("/", path);
    if path == "/" {
        return Err(FsError::Busy);
    }
    let m = mounts();
    let i = m.iter().position(|m| m.path == path).ok_or(FsError::NotFound)?;
    m[i].fs.sync()?;
    m.remove(i);
    Ok(())
}

/// Unmount without flushing buffers – the disk is gone (USB stick removed,
/// usbd exited); a USB disk is read-only anyway.
pub fn unmount_lost(path: &str) -> Result<()> {
    let _g = FsWrite::lock();
    let path = normalize("/", path);
    if path == "/" {
        return Err(FsError::Busy);
    }
    let m = mounts();
    let i = m.iter().position(|m| m.path == path).ok_or(FsError::NotFound)?;
    m.remove(i);
    Ok(())
}

/// The path lies on a read-only file system.
pub fn is_read_only(path: &str) -> bool {
    let _g = FS_LOCK.read();
    match find_mount(path) {
        Ok((i, _)) => mounts()[i].fs.read_only(),
        Err(_) => false,
    }
}

/// (mount point, type, source)
pub fn mount_list() -> Vec<(String, &'static str, String)> {
    let _g = FS_LOCK.read();
    mounts().iter().map(|m| (m.path.clone(), m.fs.kind(), m.fs.source())).collect()
}

/// Statistics of the file system mounted exactly at `path`.
pub fn mount_stats(path: &str) -> Option<FsStats> {
    // A file system with its own lock (USB disk) – without locking the whole VFS.
    {
        let _g = FS_LOCK.read();
        if let Some(m) = mounts().iter().find(|m| m.path == path) {
            if let Some(c) = m.fs.concurrent() {
                return Some(c.stats());
            }
        }
    }
    let _g = FsWrite::lock();
    mounts().iter_mut().find(|m| m.path == path).and_then(|m| m.fs.stats())
}

fn is_mount_point(path: &str) -> bool {
    let _g = FS_LOCK.read();
    path != "/" && mounts().iter().any(|m| m.path == path)
}

/// Finds the file system for an absolute path; returns it and the relative path.
fn resolve<R>(path: &str, f: impl FnOnce(&mut dyn FileSystem, &str) -> Result<R>) -> Result<R> {
    let _g = FsWrite::lock();
    let (i, rel) = find_mount(path)?;
    f(mounts()[i].fs.as_mut(), &rel)
}

// ------------------------------------------------------------
// Operations (absolute paths)
// ------------------------------------------------------------

pub fn stat(path: &str) -> Result<Metadata> {
    with_fs(path, |c, p| c.stat(p), |fs, p| fs.stat(p))
}

pub fn read_dir(path: &str) -> Result<Vec<DirEntry>> {
    let mut entries = with_fs(path, |c, p| c.read_dir(p), |fs, p| fs.read_dir(p))?;
    entries.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(entries)
}

pub fn read(path: &str, offset: u64, buf: &mut [u8]) -> Result<usize> {
    // `buf` is needed in both branches – via a pointer (only one is used).
    let ptr = buf.as_mut_ptr();
    let len = buf.len();
    with_fs(
        path,
        |c, p| c.read(p, offset, unsafe { core::slice::from_raw_parts_mut(ptr, len) }),
        |fs, p| fs.read(p, offset, unsafe { core::slice::from_raw_parts_mut(ptr, len) }),
    )
}

pub fn write(path: &str, offset: u64, data: &[u8]) -> Result<usize> {
    with_fs(path, |c, p| c.write(p, offset, data), |fs, p| fs.write(p, offset, data))
}

pub fn create(path: &str) -> Result<()> {
    with_fs(path, |c, p| c.create(p), |fs, p| fs.create(p))
}

pub fn mkdir(path: &str) -> Result<()> {
    with_fs(path, |c, p| c.mkdir(p), |fs, p| fs.mkdir(p))
}

pub fn remove(path: &str) -> Result<()> {
    // FS_LOCK for reading during the whole operation – the mount table cannot
    // change between the check and the removal (mounting takes the write lock).
    let _g = FS_LOCK.read();
    if is_mount_point(&normalize("/", path)) {
        return Err(FsError::Busy);
    }
    let (i, rel) = find_mount(path)?;
    if let Some(c) = mounts()[i].fs.concurrent() {
        return c.remove(&rel);
    }
    drop(_g);
    let _w = FsWrite::lock();
    if is_mount_point(&normalize("/", path)) {
        return Err(FsError::Busy);
    }
    resolve(path, |fs, p| fs.remove(p))
}

pub fn truncate(path: &str, size: u64) -> Result<()> {
    with_fs(path, |c, p| c.truncate(p, size), |fs, p| fs.truncate(p, size))
}

/// The path's file system has its own locks – we call it under FS_LOCK
/// for reading (`Some(result)`); `None` – the old exclusive path is needed.
fn try_concurrent<R>(path: &str, f: impl FnOnce(&dyn ConcurrentFs, &str) -> Result<R>) -> Option<Result<R>> {
    let _g = FS_LOCK.read();
    let (i, rel) = match find_mount(path) {
        Ok(x) => x,
        Err(e) => return Some(Err(e)),
    };
    mounts()[i].fs.concurrent().map(|c| f(c, &rel))
}

/// Flushes the buffers of all file systems.
pub fn sync_all() -> Result<()> {
    let _g = FsWrite::lock();
    for m in mounts().iter_mut() {
        m.fs.sync()?;
    }
    Ok(())
}

/// A whole file into memory.
pub fn read_file(path: &str) -> Result<Vec<u8>> {
    // A file system with its own locks – one atomic read.
    if let Some(r) = try_concurrent(path, |c, p| c.read_all(p)) {
        return r;
    }
    let _g = FsWrite::lock(); // the whole read is consistent
    let meta = stat(path)?;
    if meta.kind == FileType::Directory {
        return Err(FsError::IsADirectory);
    }
    let mut data = alloc::vec![0u8; meta.size as usize];
    let mut done = 0;
    while done < data.len() {
        let n = read(path, done as u64, &mut data[done..])?;
        if n == 0 {
            break;
        }
        done += n;
    }
    data.truncate(done);
    Ok(data)
}

/// Creates a file or replaces its contents.
pub fn write_file(path: &str, data: &[u8]) -> Result<()> {
    if let Some(r) = try_concurrent(path, |c, p| c.write_whole(p, data)) {
        return r;
    }
    let _g = FsWrite::lock();
    match stat(path) {
        Ok(m) if m.kind == FileType::Directory => return Err(FsError::IsADirectory),
        Ok(_) => truncate(path, 0)?,
        Err(FsError::NotFound) => create(path)?,
        Err(e) => return Err(e),
    }
    if !data.is_empty() {
        write(path, 0, data)?;
    }
    resolve(path, |fs, _| fs.sync())
}

/// Appends to the end of a file (creates it if it does not exist).
pub fn append_file(path: &str, data: &[u8]) -> Result<()> {
    if let Some(r) = try_concurrent(path, |c, p| c.append(p, data)) {
        return r;
    }
    let _g = FsWrite::lock();
    let size = match stat(path) {
        Ok(m) if m.kind == FileType::Directory => return Err(FsError::IsADirectory),
        Ok(m) => m.size,
        Err(FsError::NotFound) => {
            create(path)?;
            0
        }
        Err(e) => return Err(e),
    };
    write(path, size, data)?;
    resolve(path, |fs, _| fs.sync())
}

// ------------------------------------------------------------
// Startup
// ------------------------------------------------------------

/// Mounts ramfs at "/" and FAT32 from the first disk at "/disk".
pub fn init() {
    use crate::serial_println;

    // /disk is created only when a disk is mounted – otherwise writes to
    // "/disk" would silently go to RAM and vanish after a reboot.
    // ramfs contains a KRwLock (the statistics registry keeps its address
    // from first use) – move it to the heap first, only then do the first operation.
    let _ = mount("/", Box::new(ramfs::RamFs::new()));
    let _ = mkdir("/tmp");

    // Programs built into the kernel -> /bin (ELF files).
    let programs = crate::initrd::install();
    serial_println!("[FS] /bin: {} programs (ELF, built from user/bin/*.rs)", programs);

    if crate::block::count() == 0 {
        serial_println!("[FS] / = ramfs (no disk)");
        return;
    }
    match fat32::Fat32::open(0) {
        Ok(fs) => {
            let desc = fs.source();
            let _ = mkdir("/disk");
            match mount("/disk", Box::new(fs)) {
                Ok(()) => serial_println!("[FS] / = ramfs, /disk = fat32 ({})", desc),
                Err(e) => serial_println!("[FS] mount /disk: {}", e),
            }
        }
        Err(e) => {
            if crate::block::is_read_only(0) {
                serial_println!("[FS] / = ramfs; disk 0 (read-only): {} - /disk not available", e);
            } else {
                serial_println!("[FS] / = ramfs; disk 0: {} - /disk not available, format it with 'mkfs 0'", e);
            }
        }
    }
    mount_esp();
}

/// The first "EFI System" partition (GPT) with FAT32 -> /esp.  On a
/// real SSD it is read-only (writes are blocked by the block layer).
pub fn mount_esp() -> Option<usize> {
    use crate::serial_println;
    if stat("/esp").is_ok() {
        return None; // already mounted
    }
    for i in 0..crate::block::count() {
        if crate::block::partition_kind(i) != Some("EFI System") {
            continue;
        }
        match fat32::Fat32::open(i) {
            Ok(fs) => {
                let desc = fs.source();
                let ro = crate::block::is_read_only(i);
                let _ = mkdir("/esp");
                match mount("/esp", Box::new(fs)) {
                    Ok(()) => {
                        serial_println!("[FS] /esp = fat32 ({}){}", desc, if ro { ", read-only" } else { "" });
                        return Some(i);
                    }
                    Err(e) => {
                        let _ = remove("/esp");
                        serial_println!("[FS] mount /esp: {}", e);
                    }
                }
            }
            Err(e) => serial_println!("[FS] EFI System partition (disk {}): {}", i, e),
        }
    }
    None
}

// ------------------------------------------------------------
// TEST (only in builds with --cfg selftest)
// ------------------------------------------------------------

#[cfg(selftest)]
macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            crate::serial_println!("[FS TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

#[cfg(selftest)]
fn ok<T>(r: Result<T>, what: &str) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(e) => {
            crate::serial_println!("[FS TEST] FAIL: {}: {}", what, e);
            None
        }
    }
}

#[cfg(selftest)]
pub fn self_test() {
    use crate::block::{self, RamDisk};
    use crate::serial_println;
    use alloc::format;

    macro_rules! t {
        ($e:expr, $what:expr) => {
            match ok($e, $what) {
                Some(v) => v,
                None => return,
            }
        };
    }

    serial_println!("[FS TEST] Starting VFS + ramfs + FAT32 tests...");
    crate::selftest::begin();

    // 1. Paths.
    check!(normalize("/", "a/b/../c/./d") == "/a/c/d", "normalize 1");
    check!(normalize("/x/y", "..") == "/x", "normalize 2");
    check!(normalize("/x", "/../..//z/") == "/z", "normalize 3");
    check!(split_parent("/a/b") == ("/a", "b") && split_parent("/a") == ("/", "a"), "split_parent");
    serial_println!("[FS TEST] 1/10 path normalization PASS");

    // 2. ramfs through the VFS: files, directories, errors.
    t!(mkdir("/tmp/t"), "mkdir /tmp/t");
    t!(write_file("/tmp/t/a.txt", b"hello"), "write a.txt");
    t!(append_file("/tmp/t/a.txt", b" world"), "append");
    check!(t!(read_file("/tmp/t/a.txt"), "read") == b"hello world", "content");
    check!(create("/tmp/t/a.txt") == Err(FsError::AlreadyExists), "create existing");
    check!(remove("/tmp/t") == Err(FsError::NotEmpty), "remove non-empty");
    check!(read_file("/tmp/t") .err() == Some(FsError::IsADirectory), "read dir");
    check!(stat("/tmp/nope").err() == Some(FsError::NotFound), "stat missing");
    check!(mkdir("/tmp/t/a.txt/x") == Err(FsError::NotADirectory), "mkdir under file");
    t!(remove("/tmp/t/a.txt"), "rm a.txt");
    t!(remove("/tmp/t"), "rmdir");
    // A mount point cannot be removed.
    t!(mkdir("/tmp/mp"), "mkdir mp");
    t!(mount("/tmp/mp", Box::new(ramfs::RamFs::new())), "mount ramfs");
    check!(remove("/tmp/mp") == Err(FsError::Busy), "remove mount point");
    t!(unmount("/tmp/mp"), "unmount mp");
    t!(remove("/tmp/mp"), "rm mp");
    serial_println!("[FS TEST] 2/10 ramfs: files, dirs, append, errors PASS");

    // 3. FAT32 on a RAM disk (8 MiB) – mkfs + mount.
    let disk = block::register(alloc::boxed::Box::new(RamDisk::new("ram0", 16384)));
    let info = t!(fat32::mkfs(disk, "TESTVOL", true), "mkfs");
    let fs = t!(fat32::Fat32::open(disk), "open fat32");
    t!(mkdir("/tmp/fat"), "mkdir mountpoint");
    t!(mount("/tmp/fat", Box::new(fs)), "mount");
    let free0 = mount_stats("/tmp/fat").map(|s| s.free_bytes).unwrap_or(0);
    check!(free0 > 7 * 1024 * 1024, "free after mkfs = {}", free0);
    check!(t!(read_dir("/tmp/fat"), "ls root").is_empty(), "fresh root not empty");
    serial_println!("[FS TEST] 3/10 mkfs + mount ({}) PASS", info);

    // 4. Names: 8.3, lowercase (NT), long names with Polish characters, letter case.
    t!(write_file("/tmp/fat/README.TXT", b"upper"), "8.3 upper");
    t!(write_file("/tmp/fat/notes.txt", b"lower"), "8.3 lower");
    t!(write_file("/tmp/fat/Zażółć gęślą jaźń.md", b"polski"), "LFN polish");
    t!(write_file("/tmp/fat/a very long file name with spaces.text", b"long"), "LFN long");
    let names: Vec<String> = t!(read_dir("/tmp/fat"), "ls").into_iter().map(|e| e.name).collect();
    for n in ["README.TXT", "notes.txt", "Zażółć gęślą jaźń.md", "a very long file name with spaces.text"] {
        check!(names.iter().any(|x| x == n), "missing {:?} in {:?}", n, names);
    }
    check!(t!(read_file("/tmp/fat/readme.txt"), "case-insensitive") == b"upper", "case");
    check!(t!(read_file("/tmp/fat/ZAŻÓŁĆ GĘŚLĄ JAŹŃ.MD"), "case polish") == b"polski", "case polish");
    check!(create("/tmp/fat/NOTES.TXT") == Err(FsError::AlreadyExists), "dup case");
    check!(create("/tmp/fat/bad:name") == Err(FsError::InvalidName), "invalid name");
    serial_println!("[FS TEST] 4/10 names: 8.3, lowercase, long + Polish, case-insensitive PASS");

    // 5. A large file spanning many clusters, reading at an offset, appending.
    let big: Vec<u8> = (0..5000u32).map(|i| (i * 31 % 251) as u8).collect();
    t!(write_file("/tmp/fat/big.bin", &big), "write big");
    check!(t!(read_file("/tmp/fat/big.bin"), "read big") == big, "big content");
    let mut part = [0u8; 700];
    let n = t!(read("/tmp/fat/big.bin", 1000, &mut part), "read offset");
    check!(n == 700 && part[..] == big[1000..1700], "offset read");
    t!(append_file("/tmp/fat/big.bin", &big[..300]), "append big");
    let mut expect = big.clone();
    expect.extend_from_slice(&big[..300]);
    check!(t!(read_file("/tmp/fat/big.bin"), "read appended") == expect, "append content");
    serial_println!("[FS TEST] 5/10 multi-cluster file, offset read, append PASS");

    // 6. Writing in the middle, a zero-filled hole, truncation.
    t!(write("/tmp/fat/big.bin", 10, b"XYZ"), "overwrite middle");
    expect[10..13].copy_from_slice(b"XYZ");
    check!(t!(read_file("/tmp/fat/big.bin"), "read mid") == expect, "middle write");
    t!(write_file("/tmp/fat/sparse", b"ab"), "sparse create");
    t!(write("/tmp/fat/sparse", 3000, b"cd"), "sparse write");
    let sp = t!(read_file("/tmp/fat/sparse"), "sparse read");
    check!(sp.len() == 3002 && &sp[..2] == b"ab" && sp[2..3000].iter().all(|&b| b == 0) && &sp[3000..] == b"cd", "hole not zeroed");
    t!(truncate("/tmp/fat/big.bin", 600), "truncate");
    check!(t!(read_file("/tmp/fat/big.bin"), "read truncated") == expect[..600], "truncate content");
    t!(truncate("/tmp/fat/big.bin", 1000), "grow");
    let g = t!(read_file("/tmp/fat/big.bin"), "read grown");
    check!(g.len() == 1000 && g[..600] == expect[..600] && g[600..].iter().all(|&b| b == 0), "grow zeroes");
    serial_println!("[FS TEST] 6/10 overwrite, sparse hole = zeros, truncate/grow PASS");

    // 7. Directories: nested, many entries (the directory grows by clusters), removal.
    t!(mkdir("/tmp/fat/dir"), "mkdir");
    t!(mkdir("/tmp/fat/dir/sub"), "mkdir nested");
    for i in 0..40 {
        t!(write_file(&format!("/tmp/fat/dir/file number {:02} with long name.txt", i), format!("{}", i).as_bytes()), "many files");
    }
    let listing = t!(read_dir("/tmp/fat/dir"), "ls dir");
    check!(listing.len() == 41, "dir has {} entries", listing.len());
    check!(t!(read_file("/tmp/fat/dir/file number 37 with long name.txt"), "read 37") == b"37", "file 37");
    check!(remove("/tmp/fat/dir") == Err(FsError::NotEmpty), "rmdir non-empty");
    for i in 0..40 {
        t!(remove(&format!("/tmp/fat/dir/file number {:02} with long name.txt", i)), "rm many");
    }
    t!(write_file("/tmp/fat/dir/reuse", b"slot"), "reuse deleted slots");
    t!(remove("/tmp/fat/dir/reuse"), "rm reuse");
    t!(remove("/tmp/fat/dir/sub"), "rmdir sub");
    t!(remove("/tmp/fat/dir"), "rmdir dir");
    serial_println!("[FS TEST] 7/10 nested dirs, 40 long names (dir grows), rm/rmdir PASS");

    // 8. No leaks: after removing everything the free space is as after mkfs.
    for f in ["README.TXT", "notes.txt", "Zażółć gęślą jaźń.md", "a very long file name with spaces.text", "big.bin", "sparse"] {
        t!(remove(&format!("/tmp/fat/{}", f)), "cleanup");
    }
    let free1 = mount_stats("/tmp/fat").map(|s| s.free_bytes).unwrap_or(0);
    check!(free1 == free0, "leaked clusters: free {} -> {}", free0, free1);
    serial_println!("[FS TEST] 8/10 no leaked clusters ({} KiB free) PASS", free1 / 1024);

    // 9. Persistence: unmount, reopen from disk, the data is there.
    t!(write_file("/tmp/fat/persist.txt", "zapisane na dysku ✓".as_bytes()), "persist write");
    t!(mkdir("/tmp/fat/Katalog"), "persist dir");
    t!(unmount("/tmp/fat"), "unmount");
    let fs2 = t!(fat32::Fat32::open(disk), "reopen");
    t!(mount("/tmp/fat", Box::new(fs2)), "remount");
    check!(t!(read_file("/tmp/fat/persist.txt"), "read after remount") == "zapisane na dysku ✓".as_bytes(), "persist");
    check!(t!(stat("/tmp/fat/Katalog"), "stat dir").kind == FileType::Directory, "dir persisted");
    check!(t!(stat("/tmp/fat/persist.txt"), "stat").modified.is_some(), "timestamp");
    serial_println!("[FS TEST] 9/10 unmount + reopen: data persists PASS");

    // 10. Across file systems + redirection in the shell.
    t!(write_file("/tmp/src.txt", b"from ramfs"), "ramfs src");
    let data = t!(read_file("/tmp/src.txt"), "read src");
    t!(write_file("/tmp/fat/Katalog/copy.txt", &data), "copy to fat");
    check!(t!(read_file("/tmp/fat/Katalog/copy.txt"), "read copy") == b"from ramfs", "cross copy");
    let mut cwd = String::from("/tmp/fat");
    let mut out = String::new();
    let mut ctx = crate::shell::Context { history: &[], cwd: &mut cwd };
    crate::shell::execute("echo line one > shell.txt", &mut out, &mut ctx);
    crate::shell::execute("echo line two >> shell.txt", &mut out, &mut ctx);
    check!(t!(read_file("/tmp/fat/shell.txt"), "read redirect") == b"line one\nline two\n", "redirection");
    check!(crate::shell::split_args(r#"a "b c" 'd e' f\ g"#) == ["a", "b c", "d e", "f g"], "split_args");
    crate::shell::execute("echo 'x > y' > \"z z.txt\"", &mut out, &mut ctx);
    check!(t!(read_file("/tmp/fat/z z.txt"), "quoted redirect") == b"x > y\n", "quotes + redirect");
    crate::shell::execute("cd Katalog", &mut out, &mut ctx);
    check!(ctx.cwd.as_str() == "/tmp/fat/Katalog", "cd -> {}", ctx.cwd);
    serial_println!("[FS TEST] 10/10 ramfs -> FAT32 copy, shell > >>, quotes, cd PASS");

    // Cleanup: unmount and remove the test disk.
    let _ = unmount("/tmp/fat");
    let _ = remove("/tmp/fat");
    let _ = remove("/tmp/src.txt");
    block::remove(disk);

    serial_println!("[FS TEST] =================================");
    crate::selftest::pass();
    serial_println!("[FS TEST] VFS + RAMFS + FAT32 TESTS PASSED");
    serial_println!("[FS TEST] =================================");
}
