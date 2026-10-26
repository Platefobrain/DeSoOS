// ramfs – an in-memory file system (heap).  Mounted as "/".
//
// Node tree: directory = name -> node map, file = 64 KiB chunks (appending never
// copies the whole file – with one Vec every 4 KiB write reallocated and copied it:
// a 10 MiB download wrote ~13 GB through memcpy).
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
    /// Data in chunks: all full (CHUNK bytes) except the last; a chunk's capacity
    /// grows by doubling up to CHUNK (small files stay small).
    chunks: Vec<Vec<u8>>,
    len: usize,
    modified: DateTime,
}

const CHUNK: usize = 64 * 1024;

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
        let old = self.len;
        if new_len > old {
            let delta = (new_len - old) as u64;
            if RAMFS_BYTES.fetch_update(SeqCst, SeqCst, |u| u.checked_add(delta).filter(|&n| n <= RAMFS_MAX)).is_err() {
                return Err(FsError::NoSpace);
            }
            if self.grow(new_len).is_err() {
                self.shrink(old);
                RAMFS_BYTES.fetch_sub(delta, SeqCst);
                return Err(FsError::NoSpace);
            }
        } else {
            self.shrink(new_len);
            RAMFS_BYTES.fetch_sub((old - new_len) as u64, SeqCst);
        }
        Ok(())
    }

    /// Up to `new_len` (zeros), without the accounting.  Err = out of memory (the
    /// part already added stays; the caller shrinks back).
    fn grow(&mut self, new_len: usize) -> core::result::Result<(), ()> {
        while self.len < new_len {
            if self.chunks.last().is_none_or(|c| c.len() == CHUNK) {
                let mut c = Vec::new();
                c.try_reserve_exact((new_len - self.len).min(CHUNK)).map_err(|_| ())?;
                self.chunks.push(c);
            }
            let last = self.chunks.last_mut().unwrap();
            let target = (last.len() + (new_len - self.len)).min(CHUNK);
            if last.capacity() < target {
                // Double (at most CHUNK) – appends in small pieces copy little.
                let want = target.max(last.capacity() * 2).min(CHUNK);
                last.try_reserve_exact(want - last.len()).map_err(|_| ())?;
            }
            let added = target - last.len();
            last.resize(target, 0);
            self.len += added;
        }
        Ok(())
    }

    /// Down to `new_len`, without the accounting.
    fn shrink(&mut self, new_len: usize) {
        if new_len >= self.len {
            return;
        }
        let keep = new_len.div_ceil(CHUNK);
        self.chunks.truncate(keep);
        if let Some(last) = self.chunks.last_mut() {
            last.truncate(new_len - (keep - 1) * CHUNK);
        }
        self.len = new_len;
    }

    /// Bytes from `offset` (within the length).
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> usize {
        if offset >= self.len {
            return 0;
        }
        let n = buf.len().min(self.len - offset);
        let mut done = 0;
        while done < n {
            let pos = offset + done;
            let c = &self.chunks[pos / CHUNK];
            let at = pos % CHUNK;
            let k = (n - done).min(c.len() - at);
            buf[done..done + k].copy_from_slice(&c[at..at + k]);
            done += k;
        }
        n
    }

    /// Overwrites bytes at `offset` (the file must already be that long).
    fn write_at(&mut self, offset: usize, bytes: &[u8]) {
        let mut done = 0;
        while done < bytes.len() {
            let pos = offset + done;
            let c = &mut self.chunks[pos / CHUNK];
            let at = pos % CHUNK;
            let k = (bytes.len() - done).min(c.len() - at);
            c[at..at + k].copy_from_slice(&bytes[done..done + k]);
            done += k;
        }
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.len);
        for c in &self.chunks {
            v.extend_from_slice(c);
        }
        v
    }
}

impl Drop for FileInner {
    fn drop(&mut self) {
        RAMFS_BYTES.fetch_sub(self.len as u64, core::sync::atomic::Ordering::SeqCst);
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
    Node::File(Arc::new(FileNode { inner: Mutex::new(FileInner { chunks: Vec::new(), len: 0, modified: rtc::now() }) }))
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
        Ok(Metadata { kind: FileType::File, size: i.len as u64, modified: Some(i.modified) })
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
                    DirEntry { name, kind: FileType::File, size: i.len as u64, modified: Some(i.modified) }
                }
                Err(modified) => DirEntry { name, kind: FileType::Directory, size: 0, modified: Some(modified) },
            })
            .collect())
    }

    fn read(&self, path: &str, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let f = self.file(path)?;
        let i = f.inner.lock();
        if offset >= i.len as u64 {
            return Ok(0);
        }
        Ok(i.read_at(offset as usize, buf))
    }

    fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        let f = self.file(path)?;
        let i = f.inner.lock();
        Ok(i.to_vec())
    }

    fn write(&self, path: &str, offset: u64, bytes: &[u8]) -> Result<usize> {
        let f = self.file(path)?;
        let mut i = f.inner.lock();
        // The offset from `seek` may be huge – no overflow, within the limit.
        let end = (offset as usize).checked_add(bytes.len()).ok_or(FsError::NoSpace)?;
        if i.len < end {
            i.set_len(end)?;
        }
        i.write_at(offset as usize, bytes);
        i.modified = rtc::now();
        Ok(bytes.len())
    }

    fn write_whole(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let f = self.file_or_create(path)?;
        let mut i = f.inner.lock();
        i.set_len(0)?;
        i.set_len(bytes.len())?;
        i.write_at(0, bytes);
        i.modified = rtc::now();
        Ok(())
    }

    fn append(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let f = self.file_or_create(path)?;
        let mut i = f.inner.lock();
        let old = i.len;
        i.set_len(old.checked_add(bytes.len()).ok_or(FsError::NoSpace)?)?;
        i.write_at(old, bytes);
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
        let used: u64 = files.iter().map(|f| f.inner.lock().len as u64).sum();
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
