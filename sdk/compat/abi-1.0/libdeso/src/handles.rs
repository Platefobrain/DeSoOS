// libdeso::handles – Handles: copies, pipes, shared memory, waiting on many handles.

#[allow(unused_imports)]
use crate::*;

pub fn close(fd: u64) -> i64 {
    syscall3(SYS_CLOSE, fd, 0, 0)
}

/// New descriptor for the same object (shared position).
pub fn dup(fd: u64) -> i64 {
    syscall3(SYS_DUP, fd, 0, 0)
}

/// New handle for the same object with rights `old & mask` (requires R_DUP).
pub fn handle_dup(h: u64, mask: u64) -> i64 {
    syscall3(SYS_HANDLE_DUP, h, mask, 0)
}

/// (kind, rights) of a handle.
pub fn handle_info(h: u64) -> Result<(u64, u64), i64> {
    let r = syscall3(SYS_HANDLE_INFO, h, 0, 0);
    if r < 0 { Err(r) } else { Ok(((r as u64) >> 32, (r as u64) & 0xFFFF_FFFF)) }
}

/// Shared memory object (`size` bytes, rounded up to 4 KiB,
/// zeroed) – a handle or -errno.
pub fn shm_create(size: u64) -> i64 {
    syscall3(SYS_SHM_CREATE, size, 0, 0)
}

/// Maps the whole object (PROT_READ, PROT_READ | PROT_WRITE) – returns the address.
/// Unmap with munmap(address, shm_size(h)).  The memory is never executable.
pub fn shm_map(h: u64, prot: u64) -> Result<u64, i64> {
    let r = syscall3(SYS_SHM_MAP, h, prot, 0);
    if r < 0 { Err(r) } else { Ok(r as u64) }
}

/// Size of a shared memory object in bytes.
pub fn shm_size(h: u64) -> i64 {
    syscall3(SYS_SHM_SIZE, h, 0, 0)
}

/// Waits until one of the handles in the list [(handle, signals)] is ready
/// (W_READABLE: recv / read will not block; W_WRITABLE: send / write).
/// Ok(mask) – bit i = entry i is ready; Ok(0) – `timeout_ms` elapsed
/// (FOREVER = no limit, 0 = just check).
pub fn wait_many(list: &[(u64, u64)], timeout_ms: u64) -> Result<u64, i64> {
    let mut flat = [0u64; 2 * WAIT_MAX];
    if list.len() > WAIT_MAX {
        return Err(-22);
    }
    for (i, &(h, sig)) in list.iter().enumerate() {
        flat[2 * i] = h;
        flat[2 * i + 1] = sig;
    }
    let r = syscall3(SYS_WAIT_MANY, flat.as_ptr() as u64, list.len() as u64, timeout_ms);
    if r < 0 { Err(r) } else { Ok(r as u64) }
}

/// `new` refers to the object of `old` (the previous `new` is closed).
pub fn dup2(old: u64, new: u64) -> i64 {
    syscall3(SYS_DUP2, old, new, 0)
}

/// Pipe – (read fd, write fd).
pub fn pipe() -> Result<(u64, u64), i64> {
    let mut out = [0u64; 2];
    let r = syscall3(SYS_PIPE, out.as_mut_ptr() as u64, 0, 0);
    if r < 0 { Err(r) } else { Ok((out[0], out[1])) }
}
