// User process – address space + file descriptors.
// Parent (ppid) and children inheriting input/output.
//
// Belongs to a scheduler task (Task.process).  Plain fields are changed only by
// that task (syscalls), so no locks.  `ppid` and `exiting` are atomic –
// they are also changed by an exiting parent (handing children to init) under
// the zombie table lock (procs.rs).

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use super::space::AddressSpace;
use super::syscalls::EBADF;
use crate::console::SerialDecoder;
use crate::sched::sync::Mutex;
use crate::sched::TaskId;

/// Tests: process input from a buffer instead of the keyboard (shared with children,
/// like a terminal).
pub type InBuf = Arc<Mutex<VecDeque<u8>>>;
/// Tests: process output to a buffer instead of the screen (shared with children).
/// SpinLock (not a sleeping Mutex) – `write` runs without the BKL.
pub type OutBuf = Arc<crate::sched::spin::IrqSpinLock<Vec<u8>>>;

/// Open file – an object shared by all descriptors that
/// point to it (dup, dup2, child descriptors on spawn): one
/// position, as in Unix (`echo a > f; echo b >> f` in one script,
/// `(cmd1; cmd2) > f`).  The position is under a (sleeping) Mutex – held for
/// the whole read / write, so two processes writing through a shared object do not
/// overwrite each other's data.
pub struct OpenFile {
    pub path: String,
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub offset: Mutex<u64>,
}

/// Handle rights (bits).  Rights can only be reduced (handle_dup);
/// missing READ / WRITE on read / write = EBADF (as in POSIX), missing
/// others = EACCES.  Design: ARCHITECTURE.md, "IPC".
pub mod rights {
    pub const READ: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const SEND: u32 = 4;
    pub const RECV: u32 = 8;
    pub const MAP_READ: u32 = 16;
    pub const MAP_WRITE: u32 = 32;
    pub const DUP: u32 = 64;
    pub const TRANSFER: u32 = 128;
    pub const ALL: u32 = 0xFF;
}

/// Object kind in `handle_info`.
pub mod kind {
    pub const CONSOLE: u64 = 1;
    pub const FILE: u64 = 2;
    pub const PIPE: u64 = 3;
    pub const CHANNEL: u64 = 4;
    pub const SHM: u64 = 5;
    /// Hardware access (init only) and a claimed PCI device.
    pub const HW_ROOT: u64 = 6;
    pub const DEVICE: u64 = 7;
    /// Device interrupt bound to a service.
    pub const IRQ: u64 = 8;
    /// System actions (reboot, halt, sync, stress) – sysctl syscall.
    pub const SYSCTL: u64 = 9;
    /// Input event injection (USB keyboard / mouse) – input_inject.
    pub const INPUT: u64 = 10;
    /// Registering a USB disk in the kernel (blk_attach) – usbd only.
    pub const BLK: u64 = 11;
}

/// Process handle table entry – object + rights.
#[derive(Clone)]
pub struct Handle {
    pub obj: Fd,
    pub rights: u32,
}

impl Handle {
    /// Handle with rights derived from the object (legacy default behavior).
    pub fn new(obj: Fd) -> Handle {
        use rights::*;
        let io = match &obj {
            Fd::Console => READ | WRITE,
            Fd::File(f) => (if f.read { READ } else { 0 }) | (if f.write { WRITE } else { 0 }),
            Fd::Pipe(e) => {
                if e.write {
                    WRITE
                } else {
                    READ
                }
            }
            Fd::Channel(_) => SEND | RECV,
            Fd::Shm(_) => MAP_READ | MAP_WRITE,
            Fd::Device(_) => MAP_READ | MAP_WRITE,
            Fd::Irq(_) => RECV,
            // No DUP and TRANSFER – it cannot be copied, passed
            // to a child or sent; it stays where the kernel put it (init).
            Fd::HwRoot => return Handle { obj, rights: 0 },
            // Only DUP – init gives a copy to the shell (spawn_ex), but it
            // cannot be sent in a message.
            Fd::Sysctl => return Handle { obj, rights: DUP },
            // WRITE (input_inject) + DUP (init gives copies to usbd); no
            // TRANSFER – it cannot be sent in a message.
            Fd::Input(_) => return Handle { obj, rights: WRITE | DUP },
            // Like INPUT – WRITE (blk_attach) + DUP (init gives copies to usbd).
            Fd::Blk => return Handle { obj, rights: WRITE | DUP },
        };
        Handle { obj, rights: io | DUP | TRANSFER }
    }

    pub fn kind(&self) -> u64 {
        match self.obj {
            Fd::Console => kind::CONSOLE,
            Fd::File(_) => kind::FILE,
            Fd::Pipe(_) => kind::PIPE,
            Fd::Channel(_) => kind::CHANNEL,
            Fd::Shm(_) => kind::SHM,
            Fd::HwRoot => kind::HW_ROOT,
            Fd::Device(_) => kind::DEVICE,
            Fd::Irq(_) => kind::IRQ,
            Fd::Sysctl => kind::SYSCTL,
            Fd::Input(_) => kind::INPUT,
            Fd::Blk => kind::BLK,
        }
    }
}

#[derive(Clone)]
pub enum Fd {
    /// Console (0 = input, 1/2 = output).
    Console,
    /// File from the VFS – an object shared by descriptor copies.
    File(Arc<OpenFile>),
    /// Pipe end (for reading or writing).
    Pipe(Arc<super::pipe::PipeEnd>),
    /// Channel end (messages in both directions).
    Channel(Arc<super::channel::ChanEnd>),
    /// Shared memory object.
    Shm(Arc<super::shm::ShmObj>),
    /// Hardware access – dev_claim goes through it; only init has it.
    HwRoot,
    /// PCI device claimed by a service.
    Device(Arc<super::device::DevClaim>),
    /// Device interrupt (counter + wake-up in wait_many).
    Irq(Arc<super::device::IrqObj>),
    /// Right to system actions (sysctl) – created only by the kernel for init.
    Sysctl,
    /// Input event source (input_inject) – created only by the kernel for
    /// init; every copy is a separate source (inputsrc.rs).
    Input(alloc::boxed::Box<super::inputsrc::InputEnd>),
    /// Right to register a disk (blk_attach) – created only by the kernel
    /// for init (slot 6), init gives a copy to every usbd.
    Blk,
}

/// Handle table: the slots plus a published summary of each slot (kind,
/// rights, a detail – `caps::summary`) in atomics.  Only the owning process
/// changes its table (no lock); other CPUs (`caps`, `secinfo`) read just the
/// summary, never the handles themselves – no locking on the hot path, no
/// shared references to objects being closed.  Every change goes through a
/// method here, so the summary cannot go stale.
pub struct FdTable {
    v: Vec<Option<Handle>>,
    summary: alloc::boxed::Box<[AtomicU64; super::caps::SLOTS]>,
}

impl FdTable {
    pub fn new() -> FdTable {
        FdTable { v: Vec::new(), summary: alloc::boxed::Box::new([const { AtomicU64::new(0) }; super::caps::SLOTS]) }
    }

    pub fn from_vec(v: Vec<Option<Handle>>) -> FdTable {
        let mut t = FdTable::new();
        t.v = v;
        for i in 0..t.v.len() {
            t.publish(i);
        }
        t
    }

    fn publish(&self, i: usize) {
        if let Some(s) = self.summary.get(i) {
            let val = self.v.get(i).and_then(|h| h.as_ref()).map_or(0, super::caps::summary);
            s.store(val, Ordering::Release);
        }
    }

    pub fn get(&self, i: usize) -> Option<&Option<Handle>> {
        self.v.get(i)
    }

    pub fn iter(&self) -> core::slice::Iter<'_, Option<Handle>> {
        self.v.iter()
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.v.len()
    }

    /// Puts `h` into slot `i` (the table grows as needed); returns the old
    /// handle – the caller drops it (closes the object).
    pub fn set(&mut self, i: usize, h: Option<Handle>) -> Option<Handle> {
        if self.v.len() <= i {
            if h.is_none() {
                return None;
            }
            self.v.resize_with(i + 1, || None);
        }
        let old = core::mem::replace(&mut self.v[i], h);
        self.publish(i);
        old
    }

    pub fn take(&mut self, i: usize) -> Option<Handle> {
        self.set(i, None)
    }

    pub fn push(&mut self, h: Option<Handle>) {
        self.v.push(h);
        self.publish(self.v.len() - 1);
    }

    pub fn clear(&mut self) {
        self.v.clear();
        for s in self.summary.iter() {
            s.store(0, Ordering::Release);
        }
    }

    /// Published summary of every slot (other CPUs; see `caps`).
    pub fn summary(&self) -> [u64; super::caps::SLOTS] {
        core::array::from_fn(|i| self.summary[i].load(Ordering::Acquire))
    }
}

pub struct Process {
    /// Child of init (shell, services) – may dip into the process reserve.
    pub(super) trusted: bool,
    /// File sandbox: no file system access by path (open, stat, readdir,
    /// mkdir, unlink, chdir, spawn) – only the handles it was given.  Set by
    /// `spawn` with SPAWN_NO_FILES, inherited by every child, never cleared.
    pub no_files: bool,
    pub space: AddressSpace,
    /// Memory areas (heap, mmap, stack) – lazy page allocation.
    pub mem: super::vm::ProcMem,
    /// Handle table (formerly descriptors) – number = index.
    pub(super) fds: FdTable,
    pub(super) stdin: Option<InBuf>,
    pub(super) stdout: Option<OutBuf>,
    /// This process created the stdout buffer (children only inherit it) –
    /// only it (or the last owner) writes the output to the log.
    pub(super) stdout_creator: bool,
    pub syscalls: u64,
    /// RSP at startup (ELF: points at argc) and the current directory
    /// (relative paths in open).
    pub initial_rsp: u64,
    pub cwd: String,
    /// Foreground process: Ctrl+C kills it; a normal exit prints no
    /// kernel message.
    pub foreground: bool,
    /// Parent (0 = kernel – kernel shell, tests, init supervisor).
    pub ppid: AtomicU64,
    /// The process is exiting (children handed over) – new zombies no
    /// longer go to it.
    pub exiting: AtomicBool,
    /// The process had (or received from an exiting parent) children –
    /// without this, process exit skips scanning the task list (reparent).
    pub has_children: AtomicBool,
    /// Live children (spawn +1, child exit −1, adopted in
    /// reparent +n).  A child's exit changes it under the parent's `zombies`
    /// lock together with the zombie entry – `wait` reads it under that lock.
    pub live_children: core::sync::atomic::AtomicU32,
    /// Finished children waiting for `wait` (formerly one global
    /// ZOMBIES table under a sleeping lock – minutes of waiting per
    /// minute of full load on a 16-thread machine).  Now every parent has its own list
    /// (procs::ChildList – a light lock, see the assertion below).
    pub(super) zombies: super::procs::ChildList,
    /// Incremented on every new zombie for this process (wait condition
    /// in `wait` without the lock).
    pub child_gen: AtomicU64,
    /// Key decoder for readkey from the stdin buffer (tests).
    pub(super) key_decoder: SerialDecoder,
}

/// Shared memory mappings are torn down BEFORE the fields are dropped
/// – the address space's Drop frees every mapped frame, but the object's frames
/// belong to the object (other processes may still be using it).
/// Limit on the number of processes.  Above MAX_PROCS − PROC_RESERVE spawn gets
/// EAGAIN; the last PROC_RESERVE slots are only for init and its direct
/// children (shell, services) – after a `spawn` bomb the shell can still run `ps`/`kill`,
/// and init can restart a service.  There are 4096 task stacks – the limit leaves room for
/// kernel tasks.
pub const MAX_PROCS: usize = 1024;
pub const PROC_RESERVE: usize = 64;
pub static LIVE_PROCS: AtomicUsize = AtomicUsize::new(0);

impl Drop for Process {
    fn drop(&mut self) {
        LIVE_PROCS.fetch_sub(1, Ordering::SeqCst);
        self.mem.release_shared(&mut self.space);
    }
}

// Process takes the heap fast path (classes up to 2 KiB, alignment
// to 16 B) – a field with 64-byte alignment (e.g. IrqSpinLock) would move every
// process onto the slow, global block list.
const _: () = assert!(core::mem::align_of::<Process>() <= 16 && core::mem::size_of::<Process>() <= 2048);

impl Process {
    pub fn new(space: AddressSpace) -> Self {
        let mut fds = FdTable::new();
        fds.push(Some(Handle::new(Fd::Console))); // 0 stdin
        fds.push(Some(Handle::new(Fd::Console))); // 1 stdout
        fds.push(Some(Handle::new(Fd::Console))); // 2 stderr
        Process {
            space,
            // asm programs (tests): heap after the data page; ELF – after the image
            // (spawn sets `mem` anew).
            mem: super::vm::ProcMem::new(super::USER_DATA + 4096),
            fds,
            stdin: None,
            stdout: None,
            stdout_creator: false,
            syscalls: 0,
            initial_rsp: super::USER_STACK_TOP,
            cwd: String::from("/"),
            foreground: false,
            ppid: AtomicU64::new(0),
            exiting: AtomicBool::new(false),
            has_children: AtomicBool::new(false),
            live_children: core::sync::atomic::AtomicU32::new(0),
            zombies: super::procs::ChildList::new(),
            child_gen: AtomicU64::new(0),
            key_decoder: SerialDecoder::new(),
            trusted: false,
            no_files: false,
        }
        .counted()
    }

    /// Process counter (live + not yet reaped).
    fn counted(self) -> Self {
        LIVE_PROCS.fetch_add(1, Ordering::SeqCst);
        self
    }

    pub fn ppid(&self) -> TaskId {
        self.ppid.load(Ordering::SeqCst)
    }

    pub(super) fn fd(&self, fd: u64) -> Result<&Fd, i64> {
        self.handle(fd).map(|h| &h.obj)
    }

    /// Handle (object + rights).
    pub(super) fn handle(&self, fd: u64) -> Result<&Handle, i64> {
        self.fds.get(fd as usize).and_then(|f| f.as_ref()).ok_or(EBADF)
    }

    pub(super) fn is_console(&self, fd: u64) -> bool {
        matches!(self.fds.get(fd as usize), Some(Some(Handle { obj: Fd::Console, .. })))
    }

    /// Published summary of the handle table (other CPUs – `caps`).
    pub fn handle_summary(&self) -> [u64; super::caps::SLOTS] {
        self.fds.summary()
    }

    /// Number of open files (3+).
    #[allow(dead_code)]
    pub fn open_files(&self) -> usize {
        self.fds.iter().skip(3).filter(|f| f.is_some()).count()
    }
}
