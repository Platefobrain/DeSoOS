// libdeso::chan – Channels: messages with and without handles.

#[allow(unused_imports)]
use crate::*;

/// Channel – (end 0, end 1); messages flow both ways.
pub fn channel_create() -> Result<(u64, u64), i64> {
    let mut out = [0u64; 2];
    let r = syscall3(SYS_CHANNEL_CREATE, out.as_mut_ptr() as u64, 0, 0);
    if r < 0 { Err(r) } else { Ok((out[0], out[1])) }
}

/// Sends a message (up to MSG_MAX bytes); flags: 0 or CHAN_NONBLOCK.
pub fn chan_send(h: u64, data: &[u8], flags: u64) -> i64 {
    syscall6(SYS_CHAN_SEND, h, data.as_ptr() as u64, data.len() as u64, 0, 0, flags)
}

/// Sends a message with handles – the handles are MOVED (they disappear from
/// the sender, require R_TRANSFER); on error they stay with the sender.
pub fn chan_send_h(h: u64, data: &[u8], handles: &[u64], flags: u64) -> i64 {
    syscall6(SYS_CHAN_SEND, h, data.as_ptr() as u64, data.len() as u64, handles.as_ptr() as u64, handles.len() as u64, flags)
}

/// Receive result – length, number of handles, sender (pid filled in by the kernel).
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct RecvInfo {
    pub len: u64,
    pub handles: u64,
    pub sender: u64,
}

/// Receives a message into `buf`.  Err(ERROR_MESSAGE_TOO_LARGE) – buffer too small, `info` holds
/// the required size, the message stays in the queue.
pub fn chan_recv(h: u64, buf: &mut [u8], flags: u64, info: &mut RecvInfo) -> i64 {
    let mut raw = [0u64; 3];
    let r = syscall6(SYS_CHAN_RECV, h, buf.as_mut_ptr() as u64, buf.len() as u64, 0, flags << 32, raw.as_mut_ptr() as u64);
    *info = RecvInfo { len: raw[0], handles: raw[1], sender: raw[2] };
    r
}

/// Receives a message with handles – numbers of the new handles go to `handles`
/// (info.handles of them).  ERROR_MESSAGE_TOO_LARGE – `buf` or `handles` too small; ERROR_TOO_MANY_HANDLES –
/// no room in the handle table; in both cases the message stays queued.
pub fn chan_recv_h(h: u64, buf: &mut [u8], handles: &mut [u64], flags: u64, info: &mut RecvInfo) -> i64 {
    let mut raw = [0u64; 3];
    let hcap = handles.len().min(MSG_HANDLES) as u64;
    let r = syscall6(SYS_CHAN_RECV, h, buf.as_mut_ptr() as u64, buf.len() as u64, handles.as_mut_ptr() as u64, hcap | flags << 32, raw.as_mut_ptr() as u64);
    *info = RecvInfo { len: raw[0], handles: raw[1], sender: raw[2] };
    r
}
