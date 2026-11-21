// libdeso::net – The network service (netd): UDP sockets.

#[allow(unused_imports)]
use crate::*;

/// A connected UDP socket through `svc` (SVC or a narrowed channel) to card `card`:
/// Ok(channel) – every message is one datagram (`udp_send`), every received message one
/// datagram from exactly that peer; Err(n) – netd's (or the connection's) refusal is in
/// `reply[..n]`.
pub fn udp_open_via(svc: u64, card: &str, host: &str, port: u16, reply: &mut [u8]) -> Result<u64, usize> {
    let put = |t: &[u8], reply: &mut [u8]| {
        let n = t.len().min(reply.len());
        reply[..n].copy_from_slice(&t[..n]);
        n
    };
    let Ok(c) = svc_connect_via(svc, card) else { return Err(put(b"no network service", reply)) };
    let mut req = [0u8; 300];
    let mut n = 0;
    let mut digits = [0u8; 5];
    let mut d = 5;
    let mut v = port;
    loop {
        d -= 1;
        digits[d] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for part in [b"udp ".as_slice(), host.as_bytes(), b" ", &digits[d..]] {
        if n + part.len() > req.len() {
            close(c);
            return Err(put(b"host name too long", reply));
        }
        req[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    let mut info = RecvInfo::default();
    let r = if chan_send(c, &req[..n], 0) == 0 { chan_recv(c, reply, 0, &mut info) } else { -1 };
    if r <= 0 {
        close(c);
        return Err(put(b"no answer from the network service", reply));
    }
    if reply[..r as usize].starts_with(b"udp ") && reply[..r as usize].windows(6).any(|w| w == b" from ") {
        return Ok(c);
    }
    close(c);
    Err(r as usize)
}

/// One datagram on a UDP socket; ERROR_MESSAGE_TOO_LARGE above UDP_MAX (nothing sent).
pub fn udp_send(c: u64, data: &[u8]) -> i64 {
    if data.len() > UDP_MAX {
        return ERROR_MESSAGE_TOO_LARGE;
    }
    chan_send(c, data, 0)
}
