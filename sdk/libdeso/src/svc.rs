// libdeso::svc – The service manager (init): connecting to services, narrowed channels, the service list.

#[allow(unused_imports)]
use crate::*;

/// Connects to a service by name (e.g. "edu") – returns a channel end for
/// talking to the service.  Unknown / not running service: the channel is closed by
/// init, the first operation on it gives ERROR_CLOSED.
pub fn svc_connect(name: &str) -> Result<u64, i64> {
    svc_connect_via(SVC, name)
}

/// `svc_connect` through another service channel (e.g. a narrowed one).
pub fn svc_connect_via(svc: u64, name: &str) -> Result<u64, i64> {
    let mut msg = [0u8; 64];
    let p = b"connect ";
    if p.len() + name.len() > msg.len() {
        return Err(-22);
    }
    msg[..p.len()].copy_from_slice(p);
    msg[p.len()..p.len() + name.len()].copy_from_slice(name.as_bytes());
    let (mine, theirs) = channel_create()?;
    let r = chan_send_h(svc, &msg[..p.len() + name.len()], &[theirs], 0);
    if r != 0 {
        close(mine);
        close(theirs);
        return Err(r);
    }
    Ok(mine)
}

/// A narrowed service channel from init (for a sandboxed program's slot 3): it
/// opens only network connections – `tokens` "net" (client: connect, resolve,
/// ping), plus "listen" (servers) and / or "udp" (UDP sockets).  No other services, no administrator
/// requests (DNS server, DHCP renew).  A narrowed channel can only narrow further.
pub fn svc_narrow(tokens: &str) -> Result<u64, i64> {
    svc_narrow_via(SVC, tokens)
}

/// `svc_narrow` through another service channel (narrowing a narrowed one).
pub fn svc_narrow_via(svc: u64, tokens: &str) -> Result<u64, i64> {
    let mut msg = [0u8; 64];
    let p = b"narrow ";
    if p.len() + tokens.len() > msg.len() {
        return Err(-22);
    }
    msg[..p.len()].copy_from_slice(p);
    msg[p.len()..p.len() + tokens.len()].copy_from_slice(tokens.as_bytes());
    let (mine, theirs) = channel_create()?;
    let r = chan_send_h(svc, &msg[..p.len() + tokens.len()], &[theirs], 0);
    if r != 0 {
        close(mine);
        close(theirs);
        return Err(r);
    }
    let mut buf = [0u8; 64];
    let mut hs = [0u64; 1];
    let mut info = RecvInfo::default();
    let r = chan_recv_h(mine, &mut buf, &mut hs, 0, &mut info);
    close(mine);
    if r < 0 {
        return Err(r);
    }
    if info.handles != 1 {
        return Err(-13);
    }
    Ok(hs[0])
}

/// Service list from init (lines "name state pid N restarts N (program)")
/// into `buf`; returns the length.
pub fn svc_list(buf: &mut [u8]) -> Result<usize, i64> {
    let (mine, theirs) = channel_create()?;
    let r = chan_send_h(SVC, b"list", &[theirs], 0);
    if r != 0 {
        close(mine);
        close(theirs);
        return Err(r);
    }
    let mut msg = [0u8; MSG_MAX];
    let mut info = RecvInfo::default();
    let r = chan_recv(mine, &mut msg, 0, &mut info);
    close(mine);
    if r < 0 {
        return Err(r);
    }
    let n = (r as usize).min(buf.len());
    buf[..n].copy_from_slice(&msg[..n]);
    Ok(n)
}

/// Ends a service through init ("kill <name>"; init restarts it by its rules) –
/// the answer: "killed <name> (pid N)", "not allowed", "no such service" or
/// "not running" (into `buf`).  Only with the shell's own service channel.
pub fn svc_kill<'a>(name: &str, buf: &'a mut [u8]) -> Result<&'a str, i64> {
    svc_kill_via(SVC, name, buf)
}

/// `svc_kill` through another service channel (the program channel: refused).
pub fn svc_kill_via<'a>(svc: u64, name: &str, buf: &'a mut [u8]) -> Result<&'a str, i64> {
    let mut msg = [0u8; 64];
    let p = b"kill ";
    if p.len() + name.len() > msg.len() {
        return Err(ERROR_INVALID_ARGUMENT);
    }
    msg[..p.len()].copy_from_slice(p);
    msg[p.len()..p.len() + name.len()].copy_from_slice(name.as_bytes());
    let (mine, theirs) = channel_create()?;
    let r = chan_send_h(svc, &msg[..p.len() + name.len()], &[theirs], 0);
    if r != 0 {
        close(mine);
        close(theirs);
        return Err(r);
    }
    let mut info = RecvInfo::default();
    let r = chan_recv(mine, buf, 0, &mut info);
    close(mine);
    if r < 0 {
        return Err(r);
    }
    Ok(core::str::from_utf8(&buf[..r as usize]).unwrap_or(""))
}
