// ramfs – an in-memory file system (heap).  Mounted as "/".
//
// Node tree: directory = name -> node map, file = Vec<u8>.
// Everything disappears on reboot – persistent data lives on /disk (FAT32).
//
// ramfs runs concurrently (the VFS calls it holding FS_LOCK for
// reading only – `ConcurrentFs`).  Its own locks:
//   * the tree (directories) – `KRwLock`: lookups take it for reading, structural
//     changes (create / mkdir / remove) for writing – briefly;
//     it is a `RwSpinLock` (spinning) – the sections last µs, while sleeping and
//     waking up cost more (hundreds of thousands of waits under stress).
//     File locks must NOT be taken under the tree (Mutex – sleeps): read_dir and
//     stats collect the files' Arcs and read them after releasing the tree.  No
//     nested reads (writer preference = deadlock).
//   * file contents – a separate `Mutex` per file (Arc): copying
//     data (e.g. a 70 KB program on exec) without holding the tree.
// Order: FS_LOCK -> tree -> file.  A file removed during a read
// lives on as long as the reader holds the Arc.
// A reader–writer VFS lock alone was not enough – hundreds of thousands of writes
// (mkdir/echo/rm in /stN) stalled the readers (exec from /bin) for minutes.
// Now readers of /bin and writers of /stN do not get in each other's way.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;

use super::{split_parent, ConcurrentFs, DirEntry, FileSystem, FileType, FsError, FsStats, Metadata, Result};
use crate::drivers::rtc::{self, DateTime};
use crate::sched::spin::RwSpinLock;
use crate::sched::sync::Mutex;

struct FileInner {
    data: Vec<u8>,
    modified: DateTime,
}

/// Limit on ramfs data.  Files live on the kernel heap (64 MiB) –
/// without a limit a single program could fill the heap by writing files (or by `seek` far
/// + writing 1 byte) and the kernel would crash on the next allocation.  Above the limit:
/// ENOSPC.
pub const RAMFS_MAX: u64 = 24 * 1024 * 1024;
static RAMFS_BYTES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Data bytes in ramfs (all files).
pub fn bytes_used() -> u64 {
    RAMFS_BYTES.load(core::sync::atomic::Ordering::Relaxed)
}

impl FileInner {
    /// Resizes the data to `new_len` – within the ramfs limit and without panicking when
    /// out of memory (try_reserve).  New bytes = 0.
    fn set_len(&mut self, new_len: usize) -> Result<()> {
        use core::sync::atomic::Ordering::SeqCst;
        let old = self.data.len();
        if new_len > old {
            let delta = (new_len - old) as u64;
            if RAMFS_BYTES.fetch_update(SeqCst, SeqCst, |u| u.checked_add(delta).filter(|&n| n <= RAMFS_MAX)).is_err() {
                return Err(FsError::NoSpace);
            }
            if self.data.try_reserve_exact(new_len - old).is_err() {
                RAMFS_BYTES.fetch_sub(delta, SeqCst);
                return Err(FsError::NoSpace);
            }
            self.data.resize(new_len, 0);
        } else {
            self.data.truncate(new_len);
            RAMFS_BYTES.fetch_sub((old - new_len) as u64, SeqCst);
        }
        Ok(())
    }
}

impl Drop for FileInner {
    fn drop(&mut self) {
        RAMFS_BYTES.fetch_sub(self.data.len() as u64, core::sync::atomic::Ordering::SeqCst);
    }
}

struct FileNode {
    inner: Mutex<FileInner>,
}

enum Node {
    File(Arc<FileNode>),
    Dir { children: BTreeMap<String, Node>, modified: DateTime },
}

pub struct RamFs {
    tree: RwSpinLock,
    root: UnsafeCell<Node>,
}

// The tree only under `tree`; file data under their Mutexes.
unsafe impl Sync for RamFs {}
unsafe impl Send for RamFs {}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && name.len() <= 255
}

fn new_file() -> Node {
    Node::File(Arc::new(FileNode { inner: Mutex::new(FileInner { data: Vec::new(), modified: rtc::now() }) }))
}

impl RamFs {
    pub fn new() -> Self {
        RamFs {
            tree: RwSpinLock::new("ramfs tree"),
            root: UnsafeCell::new(Node::Dir { children: BTreeMap::new(), modified: rtc::now() }),
        }
    }

    /// Only under `tree` (read or write).
    fn root(&self) -> &Node {
        unsafe { &*self.root.get() }
    }

    /// Only under `tree` for writing.
    #[allow(clippy::mut_from_ref)]
    fn root_mut(&self) -> &mut Node {
        unsafe { &mut *self.root.get() }
    }

    fn node<'a>(root: &'a Node, path: &str) -> Result<&'a Node> {
        let mut cur = root;
        for part in path.split('/').filter(|p| !p.is_empty()) {
            cur = match cur {
                Node::Dir { children, .. } => children.get(part).ok_or(FsError::NotFound)?,
                Node::File(_) => return Err(FsError::NotADirectory),
            };
        }
        Ok(cur)
    }

    fn node_mut<'a>(root: &'a mut Node, path: &str) -> Result<&'a mut Node> {
        let mut cur = root;
        for part in path.split('/').filter(|p| !p.is_empty()) {
            cur = match cur {
                Node::Dir { children, .. } => children.get_mut(part).ok_or(FsError::NotFound)?,
                Node::File(_) => return Err(FsError::NotADirectory),
            };
        }
        Ok(cur)
    }

    /// The file (Arc) – the tree only for the duration of the lookup.
    fn file(&self, path: &str) -> Result<Arc<FileNode>> {
        let _t = self.tree.read();
        match Self::node(self.root(), path)? {
            Node::File(f) => Ok(f.clone()),
            Node::Dir { .. } => Err(FsError::IsADirectory),
        }
    }

    fn insert(&self, path: &str, node: Node) -> Result<()> {
        let (parent, name) = split_parent(path);
        if !valid_name(name) {
            return Err(FsError::InvalidName);
        }
        let _t = self.tree.write();
        match Self::node_mut(self.root_mut(), parent)? {
            Node::Dir { children, modified } => {
                if children.contains_key(name) {
                    return Err(FsError::AlreadyExists);
                }
                children.insert(String::from(name), node);
                *modified = rtc::now();
                Ok(())
            }
            Node::File(_) => Err(FsError::NotADirectory),
        }
    }

    /// All files of the subtree (under `tree` – without file locks).
    fn collect_files(node: &Node, out: &mut Vec<Arc<FileNode>>) {
        match node {
            Node::File(f) => out.push(f.clone()),
            Node::Dir { children, .. } => children.values().for_each(|c| Self::collect_files(c, out)),
        }
    }

    /// The file at this path – existing or newly created (empty).
    fn file_or_create(&self, path: &str) -> Result<Arc<FileNode>> {
        match self.file(path) {
            Ok(f) => return Ok(f),
            Err(FsError::NotFound) => {}
            Err(e) => return Err(e),
        }
        match self.insert(path, new_file()) {
            Ok(()) | Err(FsError::AlreadyExists) => self.file(path),
            Err(e) => Err(e),
        }
    }
}

impl ConcurrentFs for RamFs {
    fn stat(&self, path: &str) -> Result<Metadata> {
        let f = {
            let _t = self.tree.read();
            match Self::node(self.root(), path)? {
                Node::File(f) => f.clone(),
                Node::Dir { modified, .. } => {
                    return Ok(Metadata { kind: FileType::Directory, size: 0, modified: Some(*modified) })
                }
            }
        };
        let i = f.inner.lock();
        Ok(Metadata { kind: FileType::File, size: i.data.len() as u64, modified: Some(i.modified) })
    }

    fn read_dir(&self, path: &str) -> Result<Vec<DirEntry>> {
        // Under the tree only copies of names and file Arcs – sizes after releasing it
        // (the file lock sleeps).
        let listed: Vec<(String, core::result::Result<Arc<FileNode>, DateTime>)> = {
            let _t = self.tree.read();
            let children = match Self::node(self.root(), path)? {
                Node::Dir { children, .. } => children,
                Node::File(_) => return Err(FsError::NotADirectory),
            };
            children
                .iter()
                .map(|(name, node)| match node {
                    Node::File(f) => (name.clone(), Ok(f.clone())),
                    Node::Dir { modified, .. } => (name.clone(), Err(*modified)),
                })
                .collect()
        };
        Ok(listed
            .into_iter()
            .map(|(name, node)| match node {
                Ok(f) => {
                    let i = f.inner.lock();
                    DirEntry { name, kind: FileType::File, size: i.data.len() as u64, modified: Some(i.modified) }
                }
                Err(modified) => DirEntry { name, kind: FileType::Directory, size: 0, modified: Some(modified) },
            })
            .collect())
    }

    fn read(&self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let f = self.file(path)?;
        let i = f.inner.lock();
        if offset >= i.data.len() as u64 {
            return Ok(0);
        }
        let start = offset as usize;
        let n = buf.len().min(i.data.len() - start);
        buf[..n].copy_from_slice(&i.data[start..start + n]);
        Ok(n)
    }

    fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        let f = self.file(path)?;
        let i = f.inner.lock();
        Ok(i.data.clone())
    }

    fn write(&self, path: &str, offset: u64, bytes: &[u8]) -> Result<usize> {
        let f = self.file(path)?;
        let mut i = f.inner.lock();
        // The offset from `seek` may be huge – no overflow, within the limit.
        let end = (offset as usize).checked_add(bytes.len()).ok_or(FsError::NoSpace)?;
        if i.data.len() < end {
            i.set_len(end)?;
        }
        i.data[offset as usize..end].copy_from_slice(bytes);
        i.modified = rtc::now();
        Ok(bytes.len())
    }

    fn write_whole(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let f = self.file_or_create(path)?;
        let mut i = f.inner.lock();
        i.set_len(0)?;
        i.set_len(bytes.len())?;
        i.data.copy_from_slice(bytes);
        i.modified = rtc::now();
        Ok(())
    }

    fn append(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let f = self.file_or_create(path)?;
        let mut i = f.inner.lock();
        let old = i.data.len();
        i.set_len(old.checked_add(bytes.len()).ok_or(FsError::NoSpace)?)?;
        i.data[old..].copy_from_slice(bytes);
        i.modified = rtc::now();
        Ok(())
    }

    fn truncate(&self, path: &str, size: u64) -> Result<()> {
        let f = self.file(path)?;
        let mut i = f.inner.lock();
        i.set_len(usize::try_from(size).map_err(|_| FsError::NoSpace)?)?;
        i.modified = rtc::now();
        Ok(())
    }

    fn create(&self, path: &str) -> Result<()> {
        self.insert(path, new_file())
    }

    fn mkdir(&self, path: &str) -> Result<()> {
        self.insert(path, Node::Dir { children: BTreeMap::new(), modified: rtc::now() })
    }

    fn remove(&self, path: &str) -> Result<()> {
        let (parent, name) = split_parent(path);
        if name.is_empty() {
            return Err(FsError::Busy); // "/"
        }
        // The removed node is dropped after releasing the tree (freeing the file's data).
        let _removed = {
            let _t = self.tree.write();
            let (children, modified) = match Self::node_mut(self.root_mut(), parent)? {
                Node::Dir { children, modified } => (children, modified),
                Node::File(_) => return Err(FsError::NotADirectory),
            };
            match children.get(name) {
                None => return Err(FsError::NotFound),
                Some(Node::Dir { children: c, .. }) if !c.is_empty() => return Err(FsError::NotEmpty),
                _ => {}
            }
            *modified = rtc::now();
            children.remove(name)
        };
        Ok(())
    }


    fn stats(&self) -> FsStats {
        let files = {
            let mut v = Vec::new();
            let _t = self.tree.read();
            Self::collect_files(self.root(), &mut v);
            v
        };
        let used: u64 = files.iter().map(|f| f.inner.lock().data.len() as u64).sum();
        let free = crate::memory::free_frame_count() * 4096;
        FsStats { total_bytes: used + free, free_bytes: free }
    }
}

impl FileSystem for RamFs {
    fn kind(&self) -> &'static str {
        "ramfs"
    }

    fn source(&self) -> String {
        String::from("memory")
    }

    fn concurrent(&self) -> Option<&dyn ConcurrentFs> {
        Some(self)
    }

    fn stat(&mut self, path: &str) -> Result<Metadata> {
        ConcurrentFs::stat(self, path)
    }

    fn read_dir(&mut self, path: &str) -> Result<Vec<DirEntry>> {
        ConcurrentFs::read_dir(self, path)
    }

    fn read(&mut self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize> {
        ConcurrentFs::read(self, path, offset, buf)
    }

    fn write(&mut self, path: &str, offset: u64, bytes: &[u8]) -> Result<usize> {
        ConcurrentFs::write(self, path, offset, bytes)
    }

    fn truncate(&mut self, path: &str, size: u64) -> Result<()> {
        ConcurrentFs::truncate(self, path, size)
    }

    fn create(&mut self, path: &str) -> Result<()> {
        ConcurrentFs::create(self, path)
    }

    fn mkdir(&mut self, path: &str) -> Result<()> {
        ConcurrentFs::mkdir(self, path)
    }

    fn remove(&mut self, path: &str) -> Result<()> {
        ConcurrentFs::remove(self, path)
    }

    fn stats(&mut self) -> Option<FsStats> {
        Some(ConcurrentFs::stats(self))
    }

    fn sync(&mut self) -> Result<()> {
        Ok(())
    }
}
