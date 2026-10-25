// Network protocol parsing and building – pure code (no MMIO, no allocation, no
// panics).  Frames come from the network, so they are untrusted: every malformed
// frame ends in Err, never in a read past the buffer or an overflow.  Hostile
// frame tests without hardware: /bin/netparse (NET TEST).
//
// Layers: Ethernet II, ARP (Ethernet / IPv4 only), IPv4 (no options needed, no
// fragments – a fragment is refused and counted), ICMP (echo only), UDP, TCP
// (the header and the MSS option; the connection logic is in tcp.rs), DHCP (the
// client side: the fixed BOOTP part and the options a client needs).
#![allow(dead_code)]

pub const ETH_HDR: usize = 14;
pub const ETH_ARP: u16 = 0x0806;
pub const ETH_IPV4: u16 = 0x0800;
pub const ETH_IPV6: u16 = 0x86DD;
pub const BROADCAST: [u8; 6] = [0xFF; 6];

pub const ARP_LEN: usize = 28;
pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;

pub const IP_HDR: usize = 20;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_ECHO_REQUEST: u8 = 8;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NetError {
    /// Shorter than the header or than the length it declares.
    Short,
    /// Not the protocol / version we handle (ARP for something else, IPv4 version ≠ 4).
    Unsupported,
    /// A header field out of range (IHL, total length, sizes in ARP).
    BadHeader,
    /// Header (IPv4) or message (ICMP) checksum wrong.
    BadChecksum,
    /// An IPv4 fragment – not reassembled.
    Fragment,
    /// A DNS answer cut short by the server (TC bit – would need TCP).
    Truncated,
}

/// Internet checksum (RFC 1071) of `data`, starting from `sum`.
pub fn checksum_add(mut sum: u32, data: &[u8]) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    sum
}

pub fn checksum_fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn checksum(data: &[u8]) -> u16 {
    checksum_fold(checksum_add(0, data))
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn arr<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(&b[at..at + N]);
    a
}

// ------------------------------------------------------------
// Ethernet
// ------------------------------------------------------------

pub struct Eth<'a> {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
    pub payload: &'a [u8],
}

pub fn parse_eth(f: &[u8]) -> Result<Eth<'_>, NetError> {
    if f.len() < ETH_HDR {
        return Err(NetError::Short);
    }
    Ok(Eth { dst: arr(f, 0), src: arr(f, 6), ethertype: be16(f, 12), payload: &f[ETH_HDR..] })
}

/// Writes an Ethernet header; returns its length.
pub fn put_eth(buf: &mut [u8], dst: [u8; 6], src: [u8; 6], ethertype: u16) -> usize {
    buf[0..6].copy_from_slice(&dst);
    buf[6..12].copy_from_slice(&src);
    buf[12..14].copy_from_slice(&ethertype.to_be_bytes());
    ETH_HDR
}

// ------------------------------------------------------------
// ARP
// ------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Arp {
    pub op: u16,
    pub sha: [u8; 6],
    pub spa: [u8; 4],
    pub tha: [u8; 6],
    pub tpa: [u8; 4],
}

pub fn parse_arp(p: &[u8]) -> Result<Arp, NetError> {
    if p.len() < ARP_LEN {
        return Err(NetError::Short);
    }
    if be16(p, 0) != 1 || be16(p, 2) != ETH_IPV4 {
        return Err(NetError::Unsupported);
    }
    if p[4] != 6 || p[5] != 4 {
        return Err(NetError::BadHeader);
    }
    let op = be16(p, 6);
    if op != ARP_REQUEST && op != ARP_REPLY {
        return Err(NetError::Unsupported);
    }
    Ok(Arp { op, sha: arr(p, 8), spa: arr(p, 14), tha: arr(p, 18), tpa: arr(p, 24) })
}

/// A whole ARP frame (Ethernet + ARP, 42 bytes); returns its length.
pub fn build_arp(buf: &mut [u8], eth_dst: [u8; 6], a: &Arp) -> usize {
    let n = put_eth(buf, eth_dst, a.sha, ETH_ARP);
    let p = &mut buf[n..n + ARP_LEN];
    p[0..2].copy_from_slice(&1u16.to_be_bytes());
    p[2..4].copy_from_slice(&ETH_IPV4.to_be_bytes());
    p[4] = 6;
    p[5] = 4;
    p[6..8].copy_from_slice(&a.op.to_be_bytes());
    p[8..14].copy_from_slice(&a.sha);
    p[14..18].copy_from_slice(&a.spa);
    p[18..24].copy_from_slice(&a.tha);
    p[24..28].copy_from_slice(&a.tpa);
    n + ARP_LEN
}

// ------------------------------------------------------------
// IPv4
// ------------------------------------------------------------

pub struct Ipv4<'a> {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub proto: u8,
    pub ttl: u8,
    pub id: u16,
    /// Data after the header, cut to the total length (Ethernet padding removed).
    pub payload: &'a [u8],
}

pub fn parse_ipv4(p: &[u8]) -> Result<Ipv4<'_>, NetError> {
    if p.len() < IP_HDR {
        return Err(NetError::Short);
    }
    if p[0] >> 4 != 4 {
        return Err(NetError::Unsupported);
    }
    let ihl = (p[0] & 0x0F) as usize * 4;
    let total = be16(p, 2) as usize;
    if ihl < IP_HDR || total < ihl {
        return Err(NetError::BadHeader);
    }
    if p.len() < total {
        return Err(NetError::Short);
    }
    if checksum(&p[..ihl]) != 0 {
        return Err(NetError::BadChecksum);
    }
    // More fragments, or an offset: a fragment.
    let frag = be16(p, 6);
    if frag & 0x2000 != 0 || frag & 0x1FFF != 0 {
        return Err(NetError::Fragment);
    }
    Ok(Ipv4 { src: arr(p, 12), dst: arr(p, 16), proto: p[9], ttl: p[8], id: be16(p, 4), payload: &p[ihl..total] })
}

/// Writes a 20-byte IPv4 header (don't fragment, given TTL) for `payload_len`
/// bytes of data; returns 20.
pub fn put_ipv4(buf: &mut [u8], src: [u8; 4], dst: [u8; 4], proto: u8, id: u16, ttl: u8, payload_len: usize) -> usize {
    let total = (IP_HDR + payload_len) as u16;
    let h = &mut buf[..IP_HDR];
    h[0] = 0x45;
    h[1] = 0;
    h[2..4].copy_from_slice(&total.to_be_bytes());
    h[4..6].copy_from_slice(&id.to_be_bytes());
    h[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    h[8] = ttl;
    h[9] = proto;
    h[10..12].copy_from_slice(&[0, 0]);
    h[12..16].copy_from_slice(&src);
    h[16..20].copy_from_slice(&dst);
    let c = checksum(h);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    IP_HDR
}

/// An address a single machine may have: not 0.x.x.x, not loopback 127.x.x.x,
/// not multicast / reserved (224 and up).
pub fn unicast(ip: [u8; 4]) -> bool {
    ip[0] != 0 && ip[0] != 127 && ip[0] < 224
}

/// Same subnet (prefix length `prefix`)?
pub fn same_subnet(a: [u8; 4], b: [u8; 4], prefix: u8) -> bool {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32) as u32) };
    u32::from_be_bytes(a) & mask == u32::from_be_bytes(b) & mask
}

// ------------------------------------------------------------
// ICMP
// ------------------------------------------------------------

pub struct Icmp<'a> {
    pub kind: u8,
    pub code: u8,
    /// Echo: identifier and sequence number.
    pub id: u16,
    pub seq: u16,
    pub data: &'a [u8],
}

pub fn parse_icmp(p: &[u8]) -> Result<Icmp<'_>, NetError> {
    if p.len() < 8 {
        return Err(NetError::Short);
    }
    if checksum(p) != 0 {
        return Err(NetError::BadChecksum);
    }
    Ok(Icmp { kind: p[0], code: p[1], id: be16(p, 4), seq: be16(p, 6), data: &p[8..] })
}

/// Writes an ICMP echo request / reply with `data`; returns its length.
pub fn put_echo(buf: &mut [u8], kind: u8, id: u16, seq: u16, data: &[u8]) -> usize {
    let n = 8 + data.len();
    let m = &mut buf[..n];
    m[0] = kind;
    m[1] = 0;
    m[2..4].copy_from_slice(&[0, 0]);
    m[4..6].copy_from_slice(&id.to_be_bytes());
    m[6..8].copy_from_slice(&seq.to_be_bytes());
    m[8..].copy_from_slice(data);
    let c = checksum(m);
    m[2..4].copy_from_slice(&c.to_be_bytes());
    n
}

/// A whole frame: Ethernet + IPv4 + ICMP echo; returns its length.
#[allow(clippy::too_many_arguments)]
pub fn build_echo_frame(buf: &mut [u8], eth_dst: [u8; 6], eth_src: [u8; 6], src: [u8; 4], dst: [u8; 4], ip_id: u16, kind: u8, id: u16, seq: u16, data: &[u8]) -> usize {
    let mut n = put_eth(buf, eth_dst, eth_src, ETH_IPV4);
    let icmp_len = 8 + data.len();
    n += put_ipv4(&mut buf[n..], src, dst, PROTO_ICMP, ip_id, 64, icmp_len);
    n += put_echo(&mut buf[n..], kind, id, seq, data);
    n
}

// ------------------------------------------------------------
// UDP
// ------------------------------------------------------------

pub const UDP_HDR: usize = 8;
pub const PORT_DHCP_SERVER: u16 = 67;
pub const PORT_DHCP_CLIENT: u16 = 68;

pub struct Udp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    /// Data, cut to the UDP length.
    pub data: &'a [u8],
}

/// UDP / TCP checksum over the pseudo-header (addresses, protocol, length) and
/// the segment.
pub fn l4_checksum(src: [u8; 4], dst: [u8; 4], proto: u8, seg: &[u8]) -> u16 {
    let mut sum = checksum_add(0, &src);
    sum = checksum_add(sum, &dst);
    sum += proto as u32 + seg.len() as u32;
    checksum_fold(checksum_add(sum, seg))
}

pub fn udp_checksum(src: [u8; 4], dst: [u8; 4], udp: &[u8]) -> u16 {
    l4_checksum(src, dst, PROTO_UDP, udp)
}

/// `src` / `dst` – from the IPv4 header (for the checksum).
pub fn parse_udp(src: [u8; 4], dst: [u8; 4], p: &[u8]) -> Result<Udp<'_>, NetError> {
    if p.len() < UDP_HDR {
        return Err(NetError::Short);
    }
    let len = be16(p, 4) as usize;
    if len < UDP_HDR {
        return Err(NetError::BadHeader);
    }
    if len > p.len() {
        return Err(NetError::Short);
    }
    // Checksum 0 = not computed by the sender (allowed in IPv4).
    if be16(p, 6) != 0 && udp_checksum(src, dst, &p[..len]) != 0 {
        return Err(NetError::BadChecksum);
    }
    Ok(Udp { src_port: be16(p, 0), dst_port: be16(p, 2), data: &p[UDP_HDR..len] })
}

/// A whole frame: Ethernet + IPv4 + UDP with `data`; returns its length.
#[allow(clippy::too_many_arguments)]
pub fn build_udp_frame(buf: &mut [u8], eth_dst: [u8; 6], eth_src: [u8; 6], src: [u8; 4], dst: [u8; 4], ip_id: u16, sport: u16, dport: u16, data: &[u8]) -> usize {
    let mut n = put_eth(buf, eth_dst, eth_src, ETH_IPV4);
    let ulen = UDP_HDR + data.len();
    n += put_ipv4(&mut buf[n..], src, dst, PROTO_UDP, ip_id, 64, ulen);
    let u = &mut buf[n..n + ulen];
    u[0..2].copy_from_slice(&sport.to_be_bytes());
    u[2..4].copy_from_slice(&dport.to_be_bytes());
    u[4..6].copy_from_slice(&(ulen as u16).to_be_bytes());
    u[6..8].copy_from_slice(&[0, 0]);
    u[8..].copy_from_slice(data);
    let c = match udp_checksum(src, dst, u) {
        0 => 0xFFFF,
        c => c,
    };
    u[6..8].copy_from_slice(&c.to_be_bytes());
    n + ulen
}

// ------------------------------------------------------------
// TCP (RFC 9293) – header only
// ------------------------------------------------------------

pub const TCP_HDR: usize = 20;
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

pub struct Tcp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    /// FIN, SYN, RST, PSH, ACK, URG (the 6 classic bits).
    pub flags: u8,
    pub window: u16,
    /// Maximum segment size option (SYN segments).
    pub mss: Option<u16>,
    /// Window scale option (SYN segments, RFC 7323).
    pub wscale: Option<u8>,
    pub data: &'a [u8],
}

/// `src` / `dst` – from the IPv4 header (for the checksum, which TCP requires).
pub fn parse_tcp(src: [u8; 4], dst: [u8; 4], p: &[u8]) -> Result<Tcp<'_>, NetError> {
    if p.len() < TCP_HDR {
        return Err(NetError::Short);
    }
    let off = (p[12] >> 4) as usize * 4;
    if off < TCP_HDR {
        return Err(NetError::BadHeader);
    }
    if off > p.len() {
        return Err(NetError::Short);
    }
    if l4_checksum(src, dst, PROTO_TCP, p) != 0 {
        return Err(NetError::BadChecksum);
    }
    // Options: end (0), no-op (1), others kind + length (>= 2) inside the header.
    let mut mss = None;
    let mut wscale = None;
    let mut i = TCP_HDR;
    while i < off {
        match p[i] {
            0 => break,
            1 => i += 1,
            kind => {
                if i + 2 > off {
                    return Err(NetError::BadHeader);
                }
                let l = p[i + 1] as usize;
                if l < 2 || i + l > off {
                    return Err(NetError::BadHeader);
                }
                if kind == 2 {
                    if l != 4 {
                        return Err(NetError::BadHeader);
                    }
                    mss = Some(be16(p, i + 2));
                }
                if kind == 3 {
                    if l != 3 {
                        return Err(NetError::BadHeader);
                    }
                    wscale = Some(p[i + 2]);
                }
                i += l;
            }
        }
    }
    Ok(Tcp {
        src_port: be16(p, 0),
        dst_port: be16(p, 2),
        seq: u32::from_be_bytes(arr(p, 4)),
        ack: u32::from_be_bytes(arr(p, 8)),
        flags: p[13] & 0x3F,
        window: be16(p, 14),
        mss,
        wscale,
        data: &p[off..],
    })
}

/// A whole frame: Ethernet + IPv4 + TCP (with the MSS and window scale options
/// when given) +
/// `data`; returns its length.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_frame(
    buf: &mut [u8],
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    src: [u8; 4],
    dst: [u8; 4],
    ip_id: u16,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    mss: Option<u16>,
    wscale: Option<u8>,
    data: &[u8],
) -> usize {
    let mut n = put_eth(buf, eth_dst, eth_src, ETH_IPV4);
    let hdr = TCP_HDR + if mss.is_some() { 4 } else { 0 } + if wscale.is_some() { 4 } else { 0 };
    let tlen = hdr + data.len();
    n += put_ipv4(&mut buf[n..], src, dst, PROTO_TCP, ip_id, 64, tlen);
    let t = &mut buf[n..n + tlen];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = ((hdr / 4) as u8) << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&window.to_be_bytes());
    t[16..20].copy_from_slice(&[0, 0, 0, 0]);
    let mut o = TCP_HDR;
    if let Some(m) = mss {
        t[o] = 2;
        t[o + 1] = 4;
        t[o + 2..o + 4].copy_from_slice(&m.to_be_bytes());
        o += 4;
    }
    if let Some(w) = wscale {
        // No-op, then kind 3, length 3, shift.
        t[o..o + 4].copy_from_slice(&[1, 3, 3, w]);
    }
    t[hdr..].copy_from_slice(data);
    let c = l4_checksum(src, dst, PROTO_TCP, t);
    t[16..18].copy_from_slice(&c.to_be_bytes());
    n + tlen
}

// ------------------------------------------------------------
// DHCP (RFC 2131 / 2132)
// ------------------------------------------------------------

pub const DHCP_DISCOVER: u8 = 1;
pub const DHCP_OFFER: u8 = 2;
pub const DHCP_REQUEST: u8 = 3;
pub const DHCP_DECLINE: u8 = 4;
pub const DHCP_ACK: u8 = 5;
pub const DHCP_NAK: u8 = 6;
pub const DHCP_RELEASE: u8 = 7;
/// Fixed BOOTP part (236 bytes) + magic cookie.
pub const DHCP_FIXED: usize = 240;
const DHCP_COOKIE: [u8; 4] = [99, 130, 83, 99];
const OPT_PAD: u8 = 0;
const OPT_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_HOSTNAME: u8 = 12;
const OPT_REQUESTED: u8 = 50;
const OPT_LEASE: u8 = 51;
const OPT_TYPE: u8 = 53;
const OPT_SERVER: u8 = 54;
const OPT_PARAMS: u8 = 55;
const OPT_T1: u8 = 58;
const OPT_T2: u8 = 59;
const OPT_CLIENT_ID: u8 = 61;
const OPT_END: u8 = 255;

/// A DHCP message (only what a client uses).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Dhcp {
    /// 1 = from a client, 2 = from a server.
    pub op: u8,
    pub xid: u32,
    pub ciaddr: [u8; 4],
    pub yiaddr: [u8; 4],
    pub chaddr: [u8; 6],
    /// Message type (DHCP_OFFER, DHCP_ACK...).
    pub kind: u8,
    pub server: Option<[u8; 4]>,
    /// Prefix length from the subnet mask option.
    pub prefix: Option<u8>,
    pub router: Option<[u8; 4]>,
    pub dns: [[u8; 4]; 2],
    pub dns_n: u8,
    pub lease: Option<u32>,
    pub t1: Option<u32>,
    pub t2: Option<u32>,
    pub requested: Option<[u8; 4]>,
}

/// Prefix length of a contiguous mask (255.255.255.0 -> 24); None for holes.
pub fn mask_prefix(m: [u8; 4]) -> Option<u8> {
    let v = u32::from_be_bytes(m);
    let p = v.leading_ones();
    (v.checked_shl(p).unwrap_or(0) == 0).then_some(p as u8)
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

pub fn parse_dhcp(p: &[u8]) -> Result<Dhcp, NetError> {
    if p.len() < DHCP_FIXED {
        return Err(NetError::Short);
    }
    if (p[0] != 1 && p[0] != 2) || p[1] != 1 || p[2] != 6 || p[236..240] != DHCP_COOKIE {
        return Err(NetError::Unsupported);
    }
    let mut d = Dhcp {
        op: p[0],
        xid: be32(p, 4),
        ciaddr: arr(p, 12),
        yiaddr: arr(p, 16),
        chaddr: arr(p, 28),
        kind: 0,
        server: None,
        prefix: None,
        router: None,
        dns: [[0; 4]; 2],
        dns_n: 0,
        lease: None,
        t1: None,
        t2: None,
        requested: None,
    };
    let mut i = DHCP_FIXED;
    // Options: code, length, value.  Every length is checked against the
    // message; a known option with a wrong length is an error.  No END is
    // tolerated (the message simply ends).
    while i < p.len() {
        let code = p[i];
        if code == OPT_PAD {
            i += 1;
            continue;
        }
        if code == OPT_END {
            break;
        }
        if i + 2 > p.len() {
            return Err(NetError::BadHeader);
        }
        let l = p[i + 1] as usize;
        let v = i + 2;
        if v + l > p.len() {
            return Err(NetError::BadHeader);
        }
        let ip4 = |need_exact: bool| if (need_exact && l != 4) || l < 4 || l % 4 != 0 { Err(NetError::BadHeader) } else { Ok(arr::<4>(p, v)) };
        match code {
            OPT_TYPE => {
                if l != 1 {
                    return Err(NetError::BadHeader);
                }
                d.kind = p[v];
            }
            OPT_MASK => d.prefix = Some(mask_prefix(ip4(true)?).ok_or(NetError::BadHeader)?),
            OPT_ROUTER => d.router = Some(ip4(false)?),
            OPT_DNS => {
                ip4(false)?;
                let n = (l / 4).min(2);
                for k in 0..n {
                    d.dns[k] = arr(p, v + 4 * k);
                }
                d.dns_n = n as u8;
            }
            OPT_SERVER => d.server = Some(ip4(true)?),
            OPT_REQUESTED => d.requested = Some(ip4(true)?),
            OPT_LEASE | OPT_T1 | OPT_T2 => {
                if l != 4 {
                    return Err(NetError::BadHeader);
                }
                let t = Some(be32(p, v));
                match code {
                    OPT_LEASE => d.lease = t,
                    OPT_T1 => d.t1 = t,
                    _ => d.t2 = t,
                }
            }
            _ => {}
        }
        i = v + l;
    }
    if d.kind == 0 {
        // Plain BOOTP (no message type) – not DHCP.
        return Err(NetError::Unsupported);
    }
    if !(DHCP_DISCOVER..=DHCP_RELEASE).contains(&d.kind) {
        return Err(NetError::Unsupported);
    }
    Ok(d)
}

/// A client message (DISCOVER / REQUEST / RELEASE) into `buf` (at least 300
/// bytes); returns its length.  `ciaddr` 0 = no address yet: the server is asked
/// to broadcast its answer.
#[allow(clippy::too_many_arguments)]
pub fn build_dhcp(buf: &mut [u8], kind: u8, xid: u32, mac: [u8; 6], ciaddr: [u8; 4], requested: Option<[u8; 4]>, server: Option<[u8; 4]>, secs: u16) -> usize {
    let b = &mut buf[..300];
    b.fill(0);
    b[0] = 1;
    b[1] = 1;
    b[2] = 6;
    b[4..8].copy_from_slice(&xid.to_be_bytes());
    b[8..10].copy_from_slice(&secs.to_be_bytes());
    if ciaddr == [0; 4] {
        b[10] = 0x80;
    }
    b[12..16].copy_from_slice(&ciaddr);
    b[28..34].copy_from_slice(&mac);
    b[236..240].copy_from_slice(&DHCP_COOKIE);
    let mut i = DHCP_FIXED;
    let mut opt = |code: u8, v: &[u8], b: &mut [u8]| {
        b[i] = code;
        b[i + 1] = v.len() as u8;
        b[i + 2..i + 2 + v.len()].copy_from_slice(v);
        i += 2 + v.len();
    };
    opt(OPT_TYPE, &[kind], b);
    let mut id = [1u8; 7];
    id[1..].copy_from_slice(&mac);
    opt(OPT_CLIENT_ID, &id, b);
    if let Some(r) = requested {
        opt(OPT_REQUESTED, &r, b);
    }
    if let Some(s) = server {
        opt(OPT_SERVER, &s, b);
    }
    if kind != DHCP_RELEASE && kind != DHCP_DECLINE {
        opt(OPT_PARAMS, &[OPT_MASK, OPT_ROUTER, OPT_DNS, OPT_LEASE, OPT_SERVER, OPT_T1, OPT_T2], b);
        opt(OPT_HOSTNAME, b"desoos", b);
    }
    b[i] = OPT_END;
    300
}

pub fn ip_text(ip: [u8; 4]) -> IpText {
    IpText(ip)
}

pub struct IpText(pub [u8; 4]);

impl core::fmt::Display for IpText {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

pub fn parse_ip(s: &str) -> Option<[u8; 4]> {
    let mut ip = [0u8; 4];
    let mut n = 0;
    for part in s.split('.') {
        if n == 4 || part.is_empty() || part.len() > 3 {
            return None;
        }
        ip[n] = part.parse().ok()?;
        n += 1;
    }
    (n == 4).then_some(ip)
}
