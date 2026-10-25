// Network packet parser test without hardware (NET TEST 1/5).
// Frames come from the network – anyone on the cable can send anything.  The
// parsers (user/lib/netproto.rs, used by netd) must reject malformed frames,
// never read past the buffer and never panic (panic = end of the process = the
// test fails).
//   1. checksum and address helpers on known values,
//   2. valid frames built by the same code netd sends with: ARP request / reply,
//      ICMP echo, Ethernet padding cut off,
//   3. a table of malicious frames with the expected error (IPv4, ARP, ICMP, UDP,
//      DHCP – a DHCP answer comes from anyone on the network before we even have
//      an address),
//   4. 20 000 random mutations of the valid frames (fixed seed): every result is
//      an error or a structure whose sizes agree with the frame.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../lib/netproto.rs"]
mod netproto;

use desoos::*;
use netproto::*;

entry!(main);

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("netparse: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

const MAC_A: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
const MAC_B: [u8; 6] = [0x52, 0x55, 10, 0, 2, 2];
const IP_A: [u8; 4] = [10, 0, 2, 15];
const IP_B: [u8; 4] = [10, 0, 2, 2];

/// xorshift64 – repeatable "random" mutations.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// The whole receive path of netd on one frame.  Err = rejected at some layer;
/// Ok = accepted (sizes checked against the frame).
fn parse_all(f: &[u8]) -> Result<u8, &'static str> {
    let Ok(eth) = parse_eth(f) else { return Ok(0) };
    if eth.payload.len() != f.len() - ETH_HDR {
        return Err("Ethernet payload size");
    }
    match eth.ethertype {
        ETH_ARP => {
            if let Ok(a) = parse_arp(eth.payload) {
                if a.op != ARP_REQUEST && a.op != ARP_REPLY {
                    return Err("ARP operation not request/reply");
                }
                return Ok(1);
            }
        }
        ETH_IPV4 => {
            if let Ok(ip) = parse_ipv4(eth.payload) {
                let p = eth.payload;
                let ihl = (p[0] & 0x0F) as usize * 4;
                let total = u16::from_be_bytes([p[2], p[3]]) as usize;
                if ip.payload.len() != total - ihl || total > p.len() || ihl < IP_HDR {
                    return Err("IPv4 sizes disagree with the header");
                }
                if checksum(&p[..ihl]) != 0 {
                    return Err("IPv4 accepted with a bad checksum");
                }
                if ip.proto == PROTO_UDP {
                    if let Ok(u) = parse_udp(ip.src, ip.dst, ip.payload) {
                        if u.data.len() + UDP_HDR > ip.payload.len() {
                            return Err("UDP data past the IPv4 payload");
                        }
                        if u.dst_port == PORT_DHCP_CLIENT {
                            if let Ok(d) = parse_dhcp(u.data) {
                                if d.dns_n > 2 || d.prefix.is_some_and(|p| p > 32) || d.kind == 0 {
                                    return Err("DHCP fields out of range");
                                }
                                return Ok(5);
                            }
                        }
                        return Ok(4);
                    }
                }
                if ip.proto == PROTO_ICMP {
                    if let Ok(m) = parse_icmp(ip.payload) {
                        if m.data.len() + 8 != ip.payload.len() || checksum(ip.payload) != 0 {
                            return Err("ICMP size or checksum");
                        }
                        return Ok(3);
                    }
                }
                return Ok(2);
            }
        }
        _ => {}
    }
    Ok(0)
}

fn echo_frame(buf: &mut [u8; 1514], data_len: usize) -> usize {
    let mut data = [0u8; 1400];
    for (k, b) in data.iter_mut().enumerate() {
        *b = k as u8;
    }
    build_echo_frame(buf, MAC_B, MAC_A, IP_A, IP_B, 7, ICMP_ECHO_REQUEST, 0x1234, 1, &data[..data_len])
}

/// A DHCP OFFER as QEMU's server sends it (bytes of the DHCP part); returns its length.
fn dhcp_offer(b: &mut [u8; 400]) -> usize {
    b.fill(0);
    b[0] = 2;
    b[1] = 1;
    b[2] = 6;
    b[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
    b[16..20].copy_from_slice(&IP_A);
    b[28..34].copy_from_slice(&MAC_A);
    b[236..240].copy_from_slice(&[99, 130, 83, 99]);
    let opts: [u8; 34] = [
        53, 1, 2, // OFFER
        54, 4, 10, 0, 2, 2, // server
        1, 4, 255, 255, 255, 0, // mask
        3, 4, 10, 0, 2, 2, // router
        6, 4, 10, 0, 2, 3, // DNS
        51, 4, 0, 1, 0x51, 0x80, // 86 400 s
        255,
    ];
    b[240..274].copy_from_slice(&opts);
    274
}

/// The OFFER in a whole frame (UDP 67 -> 68, to everyone).  `udp_sum` false =
/// checksum 0 (allowed), so mutations reach the DHCP parser.
fn dhcp_frame(f: &mut [u8; 1514], udp_sum: bool) -> usize {
    let mut d = [0u8; 400];
    let n = dhcp_offer(&mut d);
    let len = build_udp_frame(f, BROADCAST, MAC_B, IP_B, [255; 4], 9, PORT_DHCP_SERVER, PORT_DHCP_CLIENT, &d[..n]);
    if !udp_sum {
        f[ETH_HDR + IP_HDR + 6] = 0;
        f[ETH_HDR + IP_HDR + 7] = 0;
    }
    len
}

/// Recomputes the IPv4 header checksum (after a deliberate change, so the
/// malicious case tests the field, not the checksum).
fn fix_ip(f: &mut [u8]) {
    let ihl = ((f[ETH_HDR] & 0x0F) as usize * 4).max(IP_HDR).min(f.len() - ETH_HDR);
    f[ETH_HDR + 10] = 0;
    f[ETH_HDR + 11] = 0;
    let c = checksum(&f[ETH_HDR..ETH_HDR + ihl]);
    f[ETH_HDR + 10..ETH_HDR + 12].copy_from_slice(&c.to_be_bytes());
}

fn main(_args: Args) -> i32 {
    let mut n = 0;

    // 1. Checksum (RFC 1071 example) and address helpers.
    check!(n, checksum(&[0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7]) == 0x220D, "RFC 1071 checksum");
    check!(n, checksum(&[0xAB]) == !0xAB00u16, "checksum of an odd length");
    check!(n, parse_ip("10.0.2.2") == Some(IP_B) && parse_ip("255.255.255.255") == Some([255; 4]), "parse_ip valid");
    let bad_ips = ["", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1..2.3", "1.2.3.", "a.b.c.d", "1.2.3.4 ", "-1.2.3.4", "0001.2.3.4"];
    check!(n, bad_ips.iter().all(|s| parse_ip(s).is_none()), "parse_ip must refuse {:?}", bad_ips.iter().find(|s| parse_ip(s).is_some()));
    check!(n, same_subnet(IP_A, IP_B, 24) && !same_subnet(IP_A, [10, 0, 3, 2], 24) && same_subnet(IP_A, [1, 2, 3, 4], 0) && !same_subnet(IP_A, IP_B, 32), "same_subnet");

    // 2. Valid frames.
    let mut f = [0u8; 1514];
    let req = Arp { op: ARP_REQUEST, sha: MAC_A, spa: IP_A, tha: [0; 6], tpa: IP_B };
    let len = build_arp(&mut f, BROADCAST, &req);
    let eth = parse_eth(&f[..len]);
    check!(n, len == 42 && matches!(&eth, Ok(e) if e.dst == BROADCAST && e.src == MAC_A && e.ethertype == ETH_ARP), "ARP frame header");
    check!(n, eth.ok().map(|e| parse_arp(e.payload)) == Some(Ok(req)), "ARP request round trip");
    // Padded to the 60-byte minimum, as on the cable.
    let rep = Arp { op: ARP_REPLY, sha: MAC_B, spa: IP_B, tha: MAC_A, tpa: IP_A };
    let mut f = [0u8; 1514];
    build_arp(&mut f, MAC_A, &rep);
    check!(n, parse_eth(&f[..60]).ok().map(|e| parse_arp(e.payload)) == Some(Ok(rep)), "padded ARP reply");

    let mut f = [0u8; 1514];
    let len = echo_frame(&mut f, 56);
    check!(n, len == 14 + 20 + 8 + 56, "echo frame length {}", len);
    let ok = parse_eth(&f[..len]).and_then(|e| parse_ipv4(e.payload)).map(|ip| (ip.src, ip.dst, ip.proto, ip.ttl, ip.payload.len()));
    check!(n, ok == Ok((IP_A, IP_B, PROTO_ICMP, 64, 64)), "IPv4 of the echo frame");
    let m = parse_eth(&f[..len]).and_then(|e| parse_ipv4(e.payload)).and_then(|ip| parse_icmp(ip.payload).map(|m| (m.kind, m.id, m.seq, m.data.len(), m.data[55])));
    check!(n, m == Ok((ICMP_ECHO_REQUEST, 0x1234, 1, 56, 55)), "ICMP echo round trip: {:?}", m);
    // A small ping is padded on the cable: padding must not become ICMP data.
    let mut f = [0u8; 1514];
    let len = echo_frame(&mut f, 4);
    check!(n, len < 60, "small echo frame length {}", len);
    let m = parse_eth(&f[..60]).and_then(|e| parse_ipv4(e.payload)).and_then(|ip| parse_icmp(ip.payload).map(|m| m.data.len()));
    check!(n, m == Ok(4), "Ethernet padding was taken as data: {:?}", m);
    // The largest echo netd answers.
    let mut big = [0u8; 1514];
    let len = echo_frame(&mut big, 1400);
    check!(n, parse_all(&big[..len]) == Ok(3), "1400-byte echo");

    // 3. Malicious frames: (description, frame change, expected error at the layer).
    type Change = fn(&mut [u8; 1514]) -> usize;
    let ip_cases: [(&str, Change, NetError); 12] = [
        ("IPv4 shorter than its header", |f| { echo_frame(f, 0); ETH_HDR + 19 }, NetError::Short),
        ("IP version 6 in an IPv4 frame", |f| { let l = echo_frame(f, 8); f[14] = 0x65; fix_ip(f); l }, NetError::Unsupported),
        ("header length 16 (< 20)", |f| { let l = echo_frame(f, 8); f[14] = 0x44; fix_ip(f); l }, NetError::BadHeader),
        ("header length 60, total 40", |f| { let l = echo_frame(f, 8); f[14] = 0x4F; f[16] = 0; f[17] = 40; l }, NetError::BadHeader),
        ("total length 10 (< header)", |f| { let l = echo_frame(f, 8); f[16] = 0; f[17] = 10; fix_ip(f); l }, NetError::BadHeader),
        ("total length 0", |f| { let l = echo_frame(f, 8); f[16] = 0; f[17] = 0; fix_ip(f); l }, NetError::BadHeader),
        ("total length past the frame", |f| { let l = echo_frame(f, 8); f[16] = 0x05; f[17] = 0xDC; fix_ip(f); l }, NetError::Short),
        ("total length 65535", |f| { let l = echo_frame(f, 8); f[16] = 0xFF; f[17] = 0xFF; fix_ip(f); l }, NetError::Short),
        ("bad header checksum", |f| { let l = echo_frame(f, 8); f[24] ^= 0x55; l }, NetError::BadChecksum),
        ("first fragment (more fragments)", |f| { let l = echo_frame(f, 8); f[20] = 0x20; fix_ip(f); l }, NetError::Fragment),
        ("later fragment (offset)", |f| { let l = echo_frame(f, 8); f[20] = 0; f[21] = 0x10; fix_ip(f); l }, NetError::Fragment),
        ("header length 60 past the frame", |f| { echo_frame(f, 0); f[14] = 0x4F; ETH_HDR + 30 }, NetError::BadHeader),
    ];
    for (what, change, want) in ip_cases {
        let mut f = [0u8; 1514];
        let len = change(&mut f);
        let r = parse_eth(&f[..len]).and_then(|e| parse_ipv4(e.payload).map(|_| ()));
        check!(n, r == Err(want), "{}: expected {:?}, got {:?}", what, want, r);
    }
    let arp_cases: [(&str, Change, NetError); 5] = [
        ("ARP of 27 bytes", |f| { build_arp(f, BROADCAST, &Arp { op: 1, sha: MAC_A, spa: IP_A, tha: [0; 6], tpa: IP_B }) - 1 }, NetError::Short),
        ("ARP for token ring", |f| { let l = build_arp(f, BROADCAST, &Arp { op: 1, sha: MAC_A, spa: IP_A, tha: [0; 6], tpa: IP_B }); f[15] = 6; l }, NetError::Unsupported),
        ("ARP for IPv6", |f| { let l = build_arp(f, BROADCAST, &Arp { op: 1, sha: MAC_A, spa: IP_A, tha: [0; 6], tpa: IP_B }); f[16] = 0x86; f[17] = 0xDD; l }, NetError::Unsupported),
        ("ARP with 16-byte addresses", |f| { let l = build_arp(f, BROADCAST, &Arp { op: 1, sha: MAC_A, spa: IP_A, tha: [0; 6], tpa: IP_B }); f[19] = 16; l }, NetError::BadHeader),
        ("ARP operation 3", |f| build_arp(f, BROADCAST, &Arp { op: 3, sha: MAC_A, spa: IP_A, tha: [0; 6], tpa: IP_B }), NetError::Unsupported),
    ];
    for (what, change, want) in arp_cases {
        let mut f = [0u8; 1514];
        let len = change(&mut f);
        let r = parse_eth(&f[..len]).and_then(|e| parse_arp(e.payload).map(|_| ()));
        check!(n, r == Err(want), "{}: expected {:?}, got {:?}", what, want, r);
    }
    let icmp_cases: [(&str, Change, NetError); 3] = [
        ("ICMP of 7 bytes", |f| { echo_frame(f, 0); f[16] = 0; f[17] = 27; fix_ip(f); ETH_HDR + 27 }, NetError::Short),
        ("ICMP with a bad checksum", |f| { let l = echo_frame(f, 8); f[ETH_HDR + 20 + 9] ^= 1; l }, NetError::BadChecksum),
        ("garbage in the Ethernet padding", |f| { let l = echo_frame(f, 4); f[l] = 0xFF; f[l + 1] = 0xFF; 60 }, NetError::BadChecksum),
    ];
    for (k, (what, change, want)) in icmp_cases.into_iter().enumerate() {
        let mut f = [0u8; 1514];
        let len = change(&mut f);
        let r = parse_eth(&f[..len]).and_then(|e| parse_ipv4(e.payload)).and_then(|ip| parse_icmp(ip.payload).map(|_| ()));
        // The last case: garbage in the padding does not matter – the parser must
        // ignore it (the frame is valid).
        let want = if k == 2 { Ok(()) } else { Err(want) };
        check!(n, r == want, "{}: expected {:?}, got {:?}", what, want, r);
    }
    check!(n, parse_eth(&[0u8; 13]).is_err() && parse_eth(&[]).is_err(), "Ethernet frame shorter than 14 bytes");

    // UDP and DHCP: a valid OFFER first.
    let mut f = [0u8; 1514];
    let len = dhcp_frame(&mut f, true);
    let d = parse_eth(&f[..len]).and_then(|e| parse_ipv4(e.payload)).and_then(|ip| parse_udp(ip.src, ip.dst, ip.payload).map(|u| (u.src_port, u.dst_port, u.data.len(), parse_dhcp(u.data))));
    let ok = matches!(d, Ok((67, 68, 274, Ok(d))) if d.op == 2 && d.kind == DHCP_OFFER && d.xid == 0x1234_5678 && d.yiaddr == IP_A && d.chaddr == MAC_A
        && d.server == Some(IP_B) && d.prefix == Some(24) && d.router == Some(IP_B) && d.dns_n == 1 && d.dns[0] == [10, 0, 2, 3] && d.lease == Some(86400));
    check!(n, ok, "DHCP OFFER round trip: {:?}", d.map(|x| x.3));
    check!(n, mask_prefix([255, 255, 255, 0]) == Some(24) && mask_prefix([0; 4]) == Some(0) && mask_prefix([255; 4]) == Some(32) && mask_prefix([255, 0, 255, 0]).is_none() && mask_prefix([255, 255, 255, 1]).is_none(), "mask_prefix");
    check!(n, unicast(IP_A) && !unicast([0, 1, 2, 3]) && !unicast([127, 0, 0, 1]) && !unicast([224, 0, 0, 251]) && !unicast([255; 4]), "unicast");
    let udp_cases: [(&str, Change, Result<(), NetError>); 5] = [
        ("UDP of 7 bytes", |f| { let l = dhcp_frame(f, true); f[16] = 0; f[17] = 27; fix_ip(f); let _ = l; ETH_HDR + 27 }, Err(NetError::Short)),
        ("UDP length 4 (< header)", |f| { let l = dhcp_frame(f, false); f[ETH_HDR + IP_HDR + 4] = 0; f[ETH_HDR + IP_HDR + 5] = 4; l }, Err(NetError::BadHeader)),
        ("UDP length past the packet", |f| { let l = dhcp_frame(f, false); f[ETH_HDR + IP_HDR + 4] = 0x05; f[ETH_HDR + IP_HDR + 5] = 0xDC; l }, Err(NetError::Short)),
        ("UDP bad checksum", |f| { let l = dhcp_frame(f, true); f[ETH_HDR + IP_HDR + 8 + 50] ^= 4; l }, Err(NetError::BadChecksum)),
        ("UDP checksum 0 (not computed)", |f| dhcp_frame(f, false), Ok(())),
    ];
    for (what, change, want) in udp_cases {
        let mut f = [0u8; 1514];
        let len = change(&mut f);
        let r = parse_eth(&f[..len]).and_then(|e| parse_ipv4(e.payload)).and_then(|ip| parse_udp(ip.src, ip.dst, ip.payload).map(|_| ()));
        check!(n, r == want, "{}: expected {:?}, got {:?}", what, want, r);
    }
    type DChange = fn(&mut [u8; 400]) -> usize;
    let dhcp_cases: [(&str, DChange, Result<(), NetError>); 15] = [
        ("DHCP of 239 bytes", |b| { dhcp_offer(b); 239 }, Err(NetError::Short)),
        ("no magic cookie", |b| { let l = dhcp_offer(b); b[236] = 0; l }, Err(NetError::Unsupported)),
        ("hardware type 6", |b| { let l = dhcp_offer(b); b[1] = 6; l }, Err(NetError::Unsupported)),
        ("operation 3", |b| { let l = dhcp_offer(b); b[0] = 3; l }, Err(NetError::Unsupported)),
        ("option length past the end", |b| { let l = dhcp_offer(b); b[240 + 28] = 200; l }, Err(NetError::BadHeader)),
        ("option code as the last byte", |b| { let l = dhcp_offer(b); b[l - 1] = 3; l }, Err(NetError::BadHeader)),
        ("mask with a hole", |b| { let l = dhcp_offer(b); b[240 + 11..240 + 15].copy_from_slice(&[255, 0, 255, 0]); l }, Err(NetError::BadHeader)),
        ("lease of 3 bytes", |b| { let l = dhcp_offer(b); b[240 + 28] = 3; b[240 + 32] = 255; l - 1 }, Err(NetError::BadHeader)),
        ("message type of 2 bytes", |b| { let l = dhcp_offer(b); b[241] = 2; l }, Err(NetError::BadHeader)),
        ("server id of 5 bytes", |b| { let l = dhcp_offer(b); b[244] = 5; l }, Err(NetError::BadHeader)),
        ("DNS of 6 bytes", |b| { let l = dhcp_offer(b); b[240 + 22] = 6; l }, Err(NetError::BadHeader)),
        ("no message type (BOOTP)", |b| { let l = dhcp_offer(b); b[240] = 0; b[241] = 0; b[242] = 0; l }, Err(NetError::Unsupported)),
        ("message type 9", |b| { let l = dhcp_offer(b); b[242] = 9; l }, Err(NetError::Unsupported)),
        ("no END option", |b| dhcp_offer(b) - 1, Ok(())),
        ("only padding after the options", |b| { let l = dhcp_offer(b); b[l - 1] = 0; l + 40 }, Ok(())),
    ];
    for (what, change, want) in dhcp_cases {
        let mut b = [0u8; 400];
        let len = change(&mut b);
        let r = parse_dhcp(&b[..len]).map(|_| ());
        check!(n, r == want, "{}: expected {:?}, got {:?}", what, want, r);
    }

    // 4. Mutations: flip bits, overwrite bytes with edge values, cut the frame.
    let mut samples = [[0u8; 1514]; 5];
    let mut lens = [0usize; 5];
    lens[0] = echo_frame(&mut samples[0], 56);
    lens[1] = echo_frame(&mut samples[1], 4);
    lens[1] = lens[1].max(60);
    lens[2] = build_arp(&mut samples[2], BROADCAST, &req);
    lens[3] = echo_frame(&mut samples[3], 1400);
    lens[4] = dhcp_frame(&mut samples[4], false);
    let mut rng = Rng(0x6E65_7470_6172_7365);
    let (mut accepted, mut rejected) = (0u32, 0u32);
    const MUTATIONS: u32 = 20_000;
    for i in 0..MUTATIONS {
        let s = (i % 5) as usize;
        let mut f = samples[s];
        let mut len = lens[s];
        for _ in 0..1 + rng.below(4) {
            match rng.below(5) {
                0 => f[rng.below(len)] ^= 1 << rng.below(8),
                1 => f[rng.below(len)] = [0, 0xFF, 0x7F, 0x80, 0x45, 0x40][rng.below(6)],
                // Mostly in the headers, where the interesting fields are.
                2 => f[rng.below(len.min(ETH_HDR + IP_HDR + 8))] = rng.next() as u8,
                // DHCP options (sample 4): lengths and codes.
                3 if s == 4 => f[ETH_HDR + IP_HDR + UDP_HDR + 240 + rng.below(34)] = [0, 1, 2, 3, 4, 5, 6, 53, 54, 255][rng.below(10)],
                3 => f[rng.below(len)] = rng.next() as u8,
                _ => len = rng.below(len + 1),
            }
        }
        // Half of the time, a correct IPv4 checksum (so the deeper checks run).
        if i % 2 == 0 && len >= ETH_HDR + IP_HDR {
            fix_ip(&mut f[..len]);
        }
        match parse_all(&f[..len]) {
            Ok(0) => rejected += 1,
            Ok(_) => accepted += 1,
            Err(e) => {
                println!("netparse: FAIL mutation {} (sample {}, {} bytes): {}", i, s, len, e);
                return 1;
            }
        }
    }
    n += 1;
    println!(
        "netparse: {} checks OK ({} malicious frames and messages refused with the right error, {} mutations: {} accepted with consistent sizes, {} refused)",
        n,
        12 + 5 + 3 + 4 + 13,
        MUTATIONS,
        accepted,
        rejected
    );
    0
}
