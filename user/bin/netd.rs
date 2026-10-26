// netd – network card service (one per card), started by init as `net0`, `net1`…
// Design: ARCHITECTURE.md, "Network".  The driver (reset, MAC, rx/tx rings, MSI)
// and the protocols: ARP (cache, answers for our address), IPv4 (header checks,
// no fragments), ICMP echo (answers pings, `ping` for clients), UDP, and a DHCP
// client for the address, gateway and DNS servers (user/lib/dhcp.rs – a pure state
// machine, tested in /bin/dhcptest), a DNS resolver with a cache
// (user/lib/dns.rs, tested in /bin/dnstest) and TCP connections (user/lib/tcp.rs,
// tested in /bin/tcptest).  Frame parsing: user/lib/netproto.rs
// (untrusted data; hostile-frame tests in /bin/netparse).
//
// Nothing blocks: every client connection carries at most one operation (ping,
// arp, resolve, renew) that the event loop advances on frames and timers, so
// many programs use the network at once.
//
// Supported: Intel 8254x / 82574 family with legacy descriptors (e1000 and
// e1000e in QEMU), and Realtek RTL8111/8168 (written for the 8168g/8168h
// generation; registers in BAR 2).  Any other card: a message and exit code 78 –
// init marks the service "no driver" and does not restart it.
//
// Handles (from init): 1 console, 3 the claimed card, 4 connection channel.
// Clients (channel ends forwarded by init on "connect net0"):
//   "status"     – a description line + a "netd-status k=v ..." line (tests),
//   "arp a.b.c.d" – send an ARP request and wait up to 1 s for the answer:
//                  "arp a.b.c.d is-at xx:xx:xx:xx:xx:xx in N ms",
//   "ping host [count]" – ICMP echo to an address or a name, one reply line per
//                  answer (sent as they come), then a summary and "ping-end",
//   "resolve name" – the IPv4 addresses of a name (DNS, cached),
//   "dns a.b.c.d[:port]" / "dns auto" – use another DNS server / the one from DHCP,
//   "renew"      – renew the DHCP lease now and report the answer,
//   "set a.b.c.d/nn [gw a.b.c.d] [dns a.b.c.d]" – an address by hand (checked with
//                  ARP first; the DHCP lease is released), "dhcp" – back to DHCP,
//   "listen port" – a TCP server (needs the "listen" right): every accepted
//                  connection arrives as a message "accepted a.b.c.d:port to
//                  port N" carrying a new channel – that connection's socket,
//   "tcp host port" – open a TCP connection; after the reply
//                  "connected a.b.c.d:port from ..." the connection is the
//                  socket: every message is data to send, every message from netd
//                  is received data, and closing it closes the connection (the
//                  program sees the end as EPIPE when the peer closes).
// Rights per connection come from init with the connection ("net0 admin listen"
// for the shell's programs, "net0 client [listen]" for sandboxed ones with a
// narrowed service channel): "dns", "renew", "set" and "dhcp" need admin,
// "listen" needs listen.  Addresses are checked before use (ARP probes, RFC 5227);
// another machine claiming our address later is reported.
// Loopback: frames to 127.0.0.1 or to our own address never reach the card – they
// go through a queue back into the receive path (client and server inside one
// machine).
// Exit: the connection channel closed and no clients left.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../lib/netproto.rs"]
mod netproto;
#[path = "../lib/dhcp.rs"]
mod dhcp;
#[path = "../lib/dns.rs"]
mod dns;
#[path = "../lib/tcp.rs"]
mod tcp;

use core::fmt::Write;
use desoos::*;
use dhcp::{Client, Event, Msg, BROADCAST_IP, INFINITE};
use dns::{Name, DNS_PORT};
use tcp::Tcb;
use netproto::*;

entry!(main);

const DEV: u64 = 3;
const LISTEN: u64 = 4;
/// Exit code for "this card has no driver" – init does not restart the service.
const EXIT_NO_DRIVER: i32 = 78;

// Registers (Intel 8254x / 82574 – the common subset).
const CTRL: u64 = 0x0000;
const STATUS: u64 = 0x0008;
const EERD: u64 = 0x0014;
const ICR: u64 = 0x00C0;
const IMS: u64 = 0x00D0;
const IMC: u64 = 0x00D8;
const RCTL: u64 = 0x0100;
const TCTL: u64 = 0x0400;
const TIPG: u64 = 0x0410;
const RDBAL: u64 = 0x2800;
const RDBAH: u64 = 0x2804;
const RDLEN: u64 = 0x2808;
const RDH: u64 = 0x2810;
const RDT: u64 = 0x2818;
const TDBAL: u64 = 0x3800;
const TDBAH: u64 = 0x3804;
const TDLEN: u64 = 0x3808;
const TDH: u64 = 0x3810;
const TDT: u64 = 0x3818;
const MTA: u64 = 0x5200;
const RAL0: u64 = 0x5400;
const RAH0: u64 = 0x5404;

const CTRL_SLU: u32 = 1 << 6;
const CTRL_RST: u32 = 1 << 26;
const STATUS_LU: u32 = 1 << 1;
const RCTL_EN: u32 = 1 << 1;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_SECRC: u32 = 1 << 26;
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
// Interrupt causes: transmit done, link change, receive timer, receive overrun.
const INT_TXDW: u32 = 1 << 0;
const INT_LSC: u32 = 1 << 2;
const INT_RXDMT0: u32 = 1 << 4;
const INT_RXO: u32 = 1 << 6;
const INT_RXT0: u32 = 1 << 7;

/// Descriptors per ring and the buffer size (RCTL.BSIZE = 2048).
const RING: usize = 256;
const BUF: u64 = 2048;
/// DMA layout: page 0 rx descriptors, page 1 tx descriptors, then the rx and tx buffers.
const RX_DESC: u64 = 0;
const TX_DESC: u64 = 4096;
const RX_BUF: u64 = 8192;
const TX_BUF: u64 = RX_BUF + RING as u64 * BUF;
const DMA_SIZE: u64 = TX_BUF + RING as u64 * BUF;

// Registers (Realtek RTL8111/8168, 8168g and later).
const R_MAC0: u64 = 0x00;
const R_MAC4: u64 = 0x04;
const R_MAR0: u64 = 0x08;
const R_TX_DESC: u64 = 0x20;
const R_CHIPCMD: u64 = 0x37;
const R_TXPOLL: u64 = 0x38;
const R_INTR_MASK: u64 = 0x3C;
const R_INTR_STATUS: u64 = 0x3E;
const R_TXCONFIG: u64 = 0x40;
const R_RXCONFIG: u64 = 0x44;
const R_CFG9346: u64 = 0x50;
const R_CONFIG2: u64 = 0x53;
const R_CONFIG5: u64 = 0x56;
const R_PHYSTATUS: u64 = 0x6C;
const R_PMCH: u64 = 0x6F;
const R_ERIDR: u64 = 0x70;
const R_ERIAR: u64 = 0x74;
const R_MAC_OCP: u64 = 0xB0;
const R_GPHY_OCP: u64 = 0xB8;
const R_MCU: u64 = 0xD3;
const R_RXMAXSIZE: u64 = 0xDA;
const R_CPLUSCMD: u64 = 0xE0;
const R_INTR_MITIGATE: u64 = 0xE2;
const R_RX_DESC: u64 = 0xE4;
const R_MAXTXPKT: u64 = 0xEC;
const R_MISC: u64 = 0xF0;

const RT_CMD_RESET: u8 = 0x10;
const RT_CMD_RX: u8 = 0x08;
const RT_CMD_TX: u8 = 0x04;
const RT_TXPOLL_NORMAL: u8 = 0x40;
const RT_TXCFG_EMPTY: u32 = 1 << 11;
const RT_MCU_OOB: u8 = 1 << 7;
const RT_MCU_RXTX_EMPTY: u8 = 0x30;
const RT_MCU_LINK_LIST_RDY: u8 = 1 << 1;
const RT_MISC_RXDV_GATE: u32 = 1 << 19;
const RT_OCP_FLAG: u32 = 1 << 31;
/// Receive: interrupt per 128 frames off, multiple DMA, unlimited burst, early
/// receive off; accept broadcast and our own address.
const RT_RXCFG: u32 = 1 << 15 | 1 << 14 | 7 << 8 | 1 << 11 | 0x08 | 0x02;
/// Transmit: unlimited DMA burst, standard gap, automatic FIFO.
const RT_TXCFG: u32 = 7 << 8 | 3 << 24 | 1 << 7;
/// Interrupt causes: rx ok / error, tx ok / error, rx overflow, link change, system error.
const RT_INTS: u16 = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x8000;
// Descriptor first word.
const RT_OWN: u32 = 1 << 31;
const RT_EOR: u32 = 1 << 30;
const RT_FS: u32 = 1 << 29;
const RT_LS: u32 = 1 << 28;
const RT_RX_ERR: u32 = 1 << 21;
/// PHY registers through GPHY_OCP: standard registers start here, 2 bytes each.
const RT_PHY_BASE: u32 = 0xA400;
// Waits that ran out during start (shown in `ifconfig`).
const RT_NOTE_TXCFG: u32 = 1 << 0;
const RT_NOTE_RXTX: u32 = 1 << 1;
const RT_NOTE_LLRDY: u32 = 1 << 2;
const RT_NOTE_PHY: u32 = 1 << 3;
const RT_NOTE_ERI: u32 = 1 << 4;
const RT_NOTE_MAC_REG: u32 = 1 << 5;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Intel,
    Realtek,
}

/// Cards this driver knows (vendor, device, kind, name).
const CHIPS: [(u16, u16, Kind, &str); 7] = [
    (0x8086, 0x100e, Kind::Intel, "Intel 82540EM (e1000)"),
    (0x8086, 0x100f, Kind::Intel, "Intel 82545EM (e1000)"),
    (0x8086, 0x10d3, Kind::Intel, "Intel 82574L (e1000e)"),
    (0x8086, 0x10f5, Kind::Intel, "Intel 82567LM (e1000e)"),
    (0x8086, 0x1502, Kind::Intel, "Intel 82579LM (e1000e)"),
    (0x8086, 0x153a, Kind::Intel, "Intel I217-LM (e1000e)"),
    (0x10ec, 0x8168, Kind::Realtek, "Realtek RTL8111/8168"),
];

/// Realtek chip versions (bits 20.. of TxConfig, masked 0xfcf) this driver was written for.
fn rt_version(xid: u32) -> Option<&'static str> {
    Some(match xid {
        0x4c0 | 0x4c1 => "8168g",
        0x509 => "8168gu",
        0x541 => "8168h",
        0x501 | 0x502 => "8168ep",
        0x5c8 => "8411b",
        0x54a | 0x54b => "8168fp",
        _ => return None,
    })
}

fn rd32(a: u64) -> u32 {
    unsafe { core::ptr::read_volatile(a as *const u32) }
}

fn wr32(a: u64, v: u32) {
    unsafe { core::ptr::write_volatile(a as *mut u32, v) }
}

fn rd16(a: u64) -> u16 {
    unsafe { core::ptr::read_volatile(a as *const u16) }
}

fn wr16(a: u64, v: u16) {
    unsafe { core::ptr::write_volatile(a as *mut u16, v) }
}

fn rd8(a: u64) -> u8 {
    unsafe { core::ptr::read_volatile(a as *const u8) }
}

fn wr8(a: u64, v: u8) {
    unsafe { core::ptr::write_volatile(a as *mut u8, v) }
}

struct Text {
    buf: [u8; MSG_MAX],
    len: usize,
}

impl Text {
    fn new() -> Text {
        Text { buf: [0; MSG_MAX], len: 0 }
    }
    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl core::fmt::Write for Text {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let b = s.as_bytes();
        let n = b.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
        Ok(())
    }
}

struct Mac([u8; 6]);

impl core::fmt::Display for Mac {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let m = &self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
    }
}

struct Nic {
    name: &'static str,
    chip: &'static str,
    kind: Kind,
    /// Realtek: chip version from TxConfig, waits that ran out during start.
    xid: u32,
    notes: u32,
    /// Realtek: interrupt causes seen (count per status bit), when the last
    /// frame arrived, ethertypes of "other" frames (type, count).
    rt_causes: [u32; 16],
    last_rx_ms: u64,
    other_types: [(u16, u32); 4],
    /// The first "other" frame (its length and first bytes), frames whose
    /// header was all zeros (an empty buffer – the card wrote the data elsewhere).
    other_dump: [u8; 32],
    other_len: usize,
    zero_frames: u64,
    /// Receive ring set up again (at start, and when the card stops filling
    /// it while still signalling frames); "rx" interrupts at the last frame.
    rx_restarts: u64,
    rx_irqs_at_frame: u32,
    vendor: u16,
    device: u16,
    regs: u64,
    irq: u64,
    /// DMA area: virtual and physical address.
    va: u64,
    pa: u64,
    mac: [u8; 6],
    rx_next: usize,
    tx_next: usize,
    // Counters.
    rx_frames: u64,
    rx_bytes: u64,
    rx_arp: u64,
    rx_ipv4: u64,
    rx_ipv6: u64,
    rx_other: u64,
    rx_errors: u64,
    tx_frames: u64,
    tx_bytes: u64,
    irqs: u64,
    polled: u64,
    /// Malformed or unhandled packets (bad header / checksum, fragments).
    rx_bad: u64,
    /// ARP requests and pings for us that we answered.
    arp_answered: u64,
    echo_answered: u64,
    /// Our address (0.0.0.0 until DHCP gives one), prefix length, gateway
    /// (0.0.0.0 = none), DNS servers – copied from the DHCP lease.
    ip: [u8; 4],
    prefix: u8,
    gw: [u8; 4],
    dns: [[u8; 4]; 2],
    dns_n: usize,
    dhcp: Client,
    /// MAC of the DHCP server (from its last ACK) for renewals; 0 = unknown.
    dhcp_mac: [u8; 6],
    /// When we started asking (for the "address in N ms" message).
    dhcp_t0: u64,
    /// UDP packets for ports nobody listens on.
    udp_dropped: u64,
    /// ARP cache: (IP, MAC, uptime in ms when learned); IP 0 = empty.
    arp_cache: [([u8; 4], [u8; 6], u64); ARP_CACHE],
    ip_id: u16,
    /// Client connections and their operations.
    conns: [Conn; MAX_CONNS],
    nconns: usize,
    /// DNS: cache, a server set by hand (None = from DHCP), counters.
    dns_cache: dns::Cache,
    dns_set: Option<([u8; 4], u16)>,
    dns_queries: u64,
    dns_answers: u64,
    dns_bad: u64,
    /// Random numbers (DNS ids and ports, ping ids, TCP ports and sequence
    /// numbers) and the next local port.
    rng: u64,
    next_port: u16,
    /// TCP: addresses and owner of each block in TCBS, counters.
    tcp: [TcpMeta; TCP_MAX],
    tcp_made: u64,
    tcp_in: u64,
    tcp_out: u64,
    tcp_resets: u64,
    tcp_accepted: u64,
    /// The last connection that ended while a program used it: peer, port,
    /// why; segments the connections dropped (out of order / outside the window).
    tcp_last_end: Option<([u8; 4], u16, &'static str)>,
    /// That connection: window scale of the peer (None = not agreed), most data
    /// waiting for the program at once.
    tcp_last_scale: Option<u8>,
    tcp_last_peak: usize,
    tcp_dropped: u64,
    tcp_reordered: u64,
    /// Loopback queue: frame lengths, read / write positions; set while a
    /// looped frame is handled (only then are 127.x destinations accepted).
    loop_len: [usize; LOOPQ],
    loop_head: usize,
    loop_tail: usize,
    loop_frames: u64,
    from_loop: bool,
    /// `set` in progress: the address probed, and who answered for it.
    static_probe: [u8; 4],
    static_taken: Option<[u8; 6]>,
    static_probe_second: bool,
    /// The address was set by hand (DHCP off).
    by_hand: bool,
    /// Other machines that claimed our address.
    conflicts: u64,
}

/// TCP connections at once; their blocks (8 KiB send + 1 MiB receive buffers each) are static.
const TCP_MAX: usize = 8;
// All-zero blocks are valid (unused) ones – the table lands in .bss, not in the file.
static mut TCBS: [Tcb; TCP_MAX] = unsafe { core::mem::MaybeUninit::zeroed().assume_init() };

fn tcbs() -> &'static mut [Tcb; TCP_MAX] {
    // netd is single-threaded; the table is used only from Nic methods.
    unsafe { &mut *core::ptr::addr_of_mut!(TCBS) }
}

/// No client owns this TCP block (the program closed; netd finishes the closing).
const NO_OWNER: usize = usize::MAX;

#[derive(Clone, Copy)]
struct TcpMeta {
    used: bool,
    /// Our address for this connection (our IP, or 127.0.0.1 over loopback).
    lip: [u8; 4],
    lport: u16,
    rip: [u8; 4],
    rport: u16,
    mac: [u8; 6],
    owner: usize,
    /// Accepted on a listening port and not yet handed to the server program:
    /// the listening connection (else NO_OWNER).
    listener: usize,
    t0: u64,
    /// Most received data waiting for the program at once (bytes).
    peak: usize,
}

const TCP_FREE: TcpMeta = TcpMeta { used: false, lip: [0; 4], lport: 0, rip: [0; 4], rport: 0, mac: [0; 6], owner: NO_OWNER, listener: NO_OWNER, t0: 0, peak: 0 };

/// Accepted connections waiting for the server program, per listening port.
const BACKLOG: usize = 4;
/// Frames on their way back through the loopback queue.
const LOOPQ: usize = 32;
static mut LOOP_FRAMES: [[u8; 1600]; LOOPQ] = [[0; 1600]; LOOPQ];

fn loop_frames() -> &'static mut [[u8; 1600]; LOOPQ] {
    unsafe { &mut *core::ptr::addr_of_mut!(LOOP_FRAMES) }
}

/// 127.x.x.x – this machine.
fn loopback(ip: [u8; 4]) -> bool {
    ip[0] == 127
}

// ------------------------------------------------------------
// Client operations: one per connection, advanced by frames and timers.
// ------------------------------------------------------------

/// Connections at once (the wait list also holds the IRQ and the listen channel).
const MAX_CONNS: usize = WAIT_MAX - 2;
/// DNS: wait after each query before the next one; then "no answer".
const DNS_WAIT_MS: [u64; 3] = [1000, 1000, 2000];

#[derive(Clone, Copy, Default)]
struct ArpWait {
    tries: u8,
    next: u64,
}

/// What a resolved name is for.
#[derive(Clone, Copy)]
enum Then {
    Print,
    Ping(u16),
    Tcp(u16),
}

#[derive(Clone, Copy)]
struct Resolve {
    name: Name,
    server: [u8; 4],
    sport: u16,
    /// Our port and the query id (both random – an answer must match both).
    port: u16,
    id: u16,
    t0: u64,
    tries: u8,
    next: u64,
    hop: Option<[u8; 6]>,
    arp: ArpWait,
    then: Then,
}

#[derive(Clone, Copy)]
struct Ping {
    dst: [u8; 4],
    count: u16,
    seq: u16,
    sent: u16,
    got: u16,
    id: u16,
    t_sent: u64,
    waiting: bool,
    next: u64,
    tmin: u64,
    tmax: u64,
    tsum: u64,
    hop: Option<[u8; 6]>,
    arp: ArpWait,
}

#[derive(Clone, Copy)]
enum Op {
    Idle,
    Arp { ip: [u8; 4], t0: u64 },
    Renew { t0: u64, acks: u32 },
    Resolve(Resolve),
    Ping(Ping),
    /// TCP: finding the next hop, then the connection in TCBS[slot] (open =
    /// "connected" told, the connection is the socket now).
    TcpStart { ip: [u8; 4], port: u16, arp: ArpWait, t0: u64 },
    Tcp { slot: usize, open: bool },
    /// A TCP server on `port` (accepted connections go to this client).
    Listen { port: u16 },
    /// `set`: the address is being probed with ARP before it is used.
    SetStatic { ip: [u8; 4], prefix: u8, gw: [u8; 4], dns: [u8; 4], t0: u64 },
}

#[derive(Clone, Copy)]
struct Conn {
    chan: u64,
    op: Op,
    /// The client closed its end – removed at the end of the loop pass.
    dead: bool,
    /// K_ADMIN / K_LISTEN (from init with the connection; 0 for accepted sockets).
    kind: u8,
}

const NO_CONN: Conn = Conn { chan: 0, op: Op::Idle, dead: true, kind: 0 };
/// DNS server and DHCP renew.
const K_ADMIN: u8 = 1;
/// TCP servers.
const K_LISTEN: u8 = 2;

/// Rights from init's text: "net0 admin listen" / "net0 client [listen]".
/// A bare name (an older init) gets both.
fn kind_of(text: &str) -> u8 {
    let mut w = text.split_whitespace();
    let _name = w.next();
    let mut k = 0;
    let mut any = false;
    for t in w {
        any = true;
        match t {
            "admin" => k |= K_ADMIN,
            "listen" => k |= K_LISTEN,
            _ => {}
        }
    }
    if any { k } else { K_ADMIN | K_LISTEN }
}

const ARP_CACHE: usize = 16;
/// ARP entries older than this are refreshed.
const ARP_TTL_MS: u64 = 60_000;
/// Echo data in our pings (as `ping` on other systems: 56 bytes).
const PING_DATA: usize = 56;

impl Nic {
    fn reg(&self, r: u64) -> u32 {
        rd32(self.regs + r)
    }
    fn set(&self, r: u64, v: u32) {
        wr32(self.regs + r, v)
    }
    fn rx_desc(&self, i: usize) -> u64 {
        self.va + RX_DESC + i as u64 * 16
    }
    fn tx_desc(&self, i: usize) -> u64 {
        self.va + TX_DESC + i as u64 * 16
    }
    fn link(&self) -> (bool, u32) {
        if self.kind == Kind::Realtek {
            let s = rd8(self.regs + R_PHYSTATUS);
            let speed = if s & 0x10 != 0 { 1000 } else if s & 0x08 != 0 { 100 } else { 10 };
            return (s & 0x02 != 0, speed);
        }
        let s = self.reg(STATUS);
        let speed = match (s >> 6) & 3 {
            0 => 10,
            1 => 100,
            _ => 1000,
        };
        (s & STATUS_LU != 0, speed)
    }

    /// Reset, address, rings, interrupts.
    fn start(&mut self) -> Result<(), &'static str> {
        if self.kind == Kind::Realtek {
            return self.rt_start();
        }
        self.set(IMC, 0xFFFF_FFFF);
        self.set(CTRL, self.reg(CTRL) | CTRL_RST);
        sleep_ms(2);
        let t = uptime_ms();
        while self.reg(CTRL) & CTRL_RST != 0 {
            if uptime_ms() - t > 500 {
                return Err("card does not come out of reset");
            }
            sleep_ms(1);
        }
        self.set(IMC, 0xFFFF_FFFF);
        let _ = self.reg(ICR);
        self.read_mac()?;
        // Receive filter: own address in RA[0] (valid), no multicast.
        let m = &self.mac;
        self.set(RAL0, u32::from_le_bytes([m[0], m[1], m[2], m[3]]));
        self.set(RAH0, u16::from_le_bytes([m[4], m[5]]) as u32 | 1 << 31);
        for i in 0..128 {
            self.set(MTA + i * 4, 0);
        }
        // Rings: every rx descriptor owns a buffer; tx descriptors start empty.
        for i in 0..RING {
            let d = self.rx_desc(i);
            unsafe {
                core::ptr::write_volatile(d as *mut u64, self.pa + RX_BUF + i as u64 * BUF);
                core::ptr::write_volatile((d + 8) as *mut u64, 0);
            }
            let t = self.tx_desc(i);
            unsafe {
                core::ptr::write_volatile(t as *mut u64, self.pa + TX_BUF + i as u64 * BUF);
                core::ptr::write_volatile((t + 8) as *mut u64, 0);
            }
        }
        self.set(RDBAL, (self.pa + RX_DESC) as u32);
        self.set(RDBAH, ((self.pa + RX_DESC) >> 32) as u32);
        self.set(RDLEN, (RING * 16) as u32);
        self.set(RDH, 0);
        self.set(RDT, (RING - 1) as u32);
        self.set(TDBAL, (self.pa + TX_DESC) as u32);
        self.set(TDBAH, ((self.pa + TX_DESC) >> 32) as u32);
        self.set(TDLEN, (RING * 16) as u32);
        self.set(TDH, 0);
        self.set(TDT, 0);
        // Interrupt (MSI) before the card may write to memory (bus mastering).
        let irq = irq_bind(DEV);
        if irq < 0 {
            return Err("irq_bind failed (no free MSI vector?)");
        }
        self.irq = irq as u64;
        self.set(RCTL, RCTL_EN | RCTL_BAM | RCTL_SECRC);
        // Collision threshold 0x10, collision distance 0x40, recommended gaps.
        self.set(TCTL, TCTL_EN | TCTL_PSP | 0x10 << 4 | 0x40 << 12);
        self.set(TIPG, 0x0060_200A);
        self.set(CTRL, self.reg(CTRL) | CTRL_SLU);
        self.set(IMS, INT_RXT0 | INT_RXO | INT_RXDMT0 | INT_LSC | INT_TXDW);
        Ok(())
    }

    /// MAC from the receive-address register (loaded from the EEPROM at reset),
    /// otherwise from the EEPROM itself.
    fn read_mac(&mut self) -> Result<(), &'static str> {
        let lo = self.reg(RAL0);
        let hi = self.reg(RAH0);
        if hi & 1 << 31 != 0 && (lo != 0 || hi & 0xFFFF != 0) {
            let l = lo.to_le_bytes();
            let h = (hi as u16).to_le_bytes();
            self.mac = [l[0], l[1], l[2], l[3], h[0], h[1]];
            return Ok(());
        }
        // EERD: 82574 format (start bit 0, done bit 1, address from bit 2).
        for w in 0..3u32 {
            self.set(EERD, 1 | w << 2);
            let t = uptime_ms();
            let v = loop {
                let v = self.reg(EERD);
                if v & 2 != 0 {
                    break v;
                }
                if uptime_ms() - t > 50 {
                    return Err("cannot read the MAC address (EEPROM)");
                }
            };
            let word = (v >> 16) as u16;
            self.mac[w as usize * 2] = word as u8;
            self.mac[w as usize * 2 + 1] = (word >> 8) as u8;
        }
        Ok(())
    }

    /// After an interrupt: acknowledge its causes (before the ring is read, so
    /// a frame arriving meanwhile raises a new one).
    fn ack_irq(&mut self) {
        if self.kind == Kind::Realtek {
            // Interrupts masked while the causes are handled; `irq_rearm` opens
            // them again – with a cause still pending that raises a new
            // interrupt (a message interrupt comes only on a change, so a cause
            // left set would otherwise silence the card for good).
            self.w16(R_INTR_MASK, 0);
            let s = rd16(self.regs + R_INTR_STATUS);
            if s != 0 && s != 0xFFFF {
                wr16(self.regs + R_INTR_STATUS, s);
                for b in 0..16 {
                    if s & 1 << b != 0 {
                        self.rt_causes[b] += 1;
                    }
                }
                // Link came up: receive ring set up again (the card's receive
                // engine can lose its place across a link change).
                if s & 0x0020 != 0 && self.link().0 {
                    self.rt_rx_restart();
                }
            }
        } else {
            let _ = self.reg(ICR);
        }
    }

    /// After the rings were handled: interrupts on again (Realtek).
    fn irq_rearm(&mut self) {
        if self.kind == Kind::Realtek {
            self.w16(R_INTR_MASK, RT_INTS);
        }
    }

    /// Takes every received frame from the ring; returns how many.
    fn poll_rx(&mut self) -> usize {
        if self.kind == Kind::Realtek {
            return self.rt_poll_rx();
        }
        let mut n = 0;
        loop {
            let d = self.rx_desc(self.rx_next);
            let status = unsafe { core::ptr::read_volatile((d + 12) as *const u8) };
            if status & 1 == 0 {
                break; // DD – not yet written by the card
            }
            let len = unsafe { core::ptr::read_volatile((d + 8) as *const u16) } as usize;
            let errors = unsafe { core::ptr::read_volatile((d + 13) as *const u8) };
            let eop = status & 2 != 0;
            if errors != 0 || !eop || len < 14 || len > BUF as usize {
                self.rx_errors += 1;
            } else {
                let buf = self.va + RX_BUF + self.rx_next as u64 * BUF;
                let frame = unsafe { core::slice::from_raw_parts(buf as *const u8, len) };
                self.handle(frame);
            }
            // Give the descriptor back to the card.
            unsafe { core::ptr::write_volatile((d + 8) as *mut u64, 0) };
            self.set(RDT, self.rx_next as u32);
            self.rx_next = (self.rx_next + 1) % RING;
            n += 1;
        }
        n
    }

    /// One received frame: count it, answer what is for us.
    fn handle(&mut self, f: &[u8]) {
        self.rx_frames += 1;
        self.last_rx_ms = uptime_ms();
        if f.len() >= 14 && f[..14].iter().all(|&b| b == 0) {
            self.zero_frames += 1;
        }
        self.rx_bytes += f.len() as u64;
        let Ok(eth) = parse_eth(f) else {
            self.rx_bad += 1;
            return;
        };
        match eth.ethertype {
            ETH_ARP => {
                self.rx_arp += 1;
                match parse_arp(eth.payload) {
                    Ok(a) => self.on_arp(&a),
                    Err(_) => self.rx_bad += 1,
                }
            }
            ETH_IPV4 => {
                self.rx_ipv4 += 1;
                match parse_ipv4(eth.payload) {
                    Ok(ip) => self.on_ipv4(eth.src, &ip),
                    Err(_) => self.rx_bad += 1,
                }
            }
            ETH_IPV6 => self.rx_ipv6 += 1,
            t => {
                if self.rx_other == 0 {
                    let n = f.len().min(32);
                    self.other_dump[..n].copy_from_slice(&f[..n]);
                    self.other_len = f.len();
                }
                self.rx_other += 1;
                // Which kinds (for diagnosis): the first four seen, counted.
                if let Some(e) = self.other_types.iter_mut().find(|e| e.1 > 0 && e.0 == t) {
                    e.1 += 1;
                } else if let Some(e) = self.other_types.iter_mut().find(|e| e.1 == 0) {
                    *e = (t, 1);
                }
            }
        }
    }

    fn on_arp(&mut self, a: &Arp) {
        // Address checks (RFC 5227): another machine using the address we are
        // about to take – as the sender of any ARP, or probing for it itself.
        let other = a.sha != self.mac;
        let claims = |ip: [u8; 4]| ip != [0; 4] && other && (a.spa == ip || (a.op == ARP_REQUEST && a.spa == [0; 4] && a.tpa == ip));
        if let Some(ip) = self.dhcp.checking() {
            if claims(ip) {
                let mut t = Text::new();
                let _ = writeln!(t, "{}: DHCP offered {}, but {} already uses it - declined, asking again in 10 s", self.name, ip_text(ip), Mac(a.sha));
                write(1, t.as_bytes());
                let m = self.dhcp.conflict(uptime_ms());
                self.dhcp_apply((m, Event::None));
                return;
            }
        }
        if self.static_probe != [0; 4] && claims(self.static_probe) {
            self.static_taken = Some(a.sha);
        }
        // Someone else claims the address we use: report it (once per sender MAC
        // in a row – not on every frame).
        if self.has_ip() && other && a.spa == self.ip {
            self.conflicts += 1;
            if self.conflicts == 1 || self.conflicts % 100 == 0 {
                let mut t = Text::new();
                let _ = writeln!(t, "{}: address conflict - {} also uses {} (seen {} times)", self.name, Mac(a.sha), ip_text(self.ip), self.conflicts);
                write(1, t.as_bytes());
            }
            return;
        }
        // Learn the sender (also from requests – it is about to talk to us).
        if !self.has_ip() {
            return;
        }
        if a.spa != [0; 4] && (a.tpa == self.ip || self.cached(a.spa).is_some()) {
            self.learn(a.spa, a.sha);
        }
        if a.op == ARP_REPLY && a.tpa == self.ip {
            // Only answers to us – an unasked "is-at" for someone else is ignored.
            self.learn(a.spa, a.sha);
            self.arp_answer(a.spa, a.sha);
        } else if a.op == ARP_REQUEST && a.tpa == self.ip {
            let reply = Arp { op: ARP_REPLY, sha: self.mac, spa: self.ip, tha: a.sha, tpa: a.spa };
            let mut f = [0u8; 64];
            let n = build_arp(&mut f, a.sha, &reply);
            if self.send(&f[..n]).is_ok() {
                self.arp_answered += 1;
            }
        }
    }

    fn on_ipv4(&mut self, src_mac: [u8; 6], ip: &Ipv4) {
        let for_us = self.local(ip.dst) || ip.dst == BROADCAST_IP;
        match ip.proto {
            PROTO_UDP => {
                // Before we have an address a DHCP server may answer to the
                // offered one – the card already filtered on our MAC.
                if !for_us && self.has_ip() {
                    return;
                }
                let Ok(u) = parse_udp(ip.src, ip.dst, ip.payload) else {
                    self.rx_bad += 1;
                    return;
                };
                if u.dst_port != PORT_DHCP_CLIENT || u.src_port != PORT_DHCP_SERVER {
                    if !self.dns_packet(ip.src, &u) {
                        self.udp_dropped += 1;
                    }
                    return;
                }
                let Ok(d) = parse_dhcp(u.data) else {
                    self.rx_bad += 1;
                    return;
                };
                let r = self.dhcp.on_message(uptime_ms(), &d);
                if matches!(r.1, Event::Bound | Event::Renewed | Event::Changed) {
                    self.dhcp_mac = src_mac;
                }
                self.dhcp_apply(r);
            }
            PROTO_ICMP if for_us => self.on_icmp(src_mac, ip),
            PROTO_TCP if self.local(ip.dst) => self.on_tcp(src_mac, ip),
            _ => {}
        }
    }

    fn on_icmp(&mut self, src_mac: [u8; 6], ip: &Ipv4) {
        let Ok(m) = parse_icmp(ip.payload) else {
            self.rx_bad += 1;
            return;
        };
        // Not to a group sender address (bit 0 of the first byte) – a reply there
        // would go to many machines.
        if m.kind == ICMP_ECHO_REQUEST && self.local(ip.dst) && src_mac[0] & 1 == 0 && m.data.len() <= 1472 - 8 {
            // Answer straight back to the sender's MAC (it just reached us), from
            // the address it pinged (ours or 127.0.0.1).
            let mut f = [0u8; 1514];
            self.ip_id = self.ip_id.wrapping_add(1);
            let n = build_echo_frame(&mut f, src_mac, self.mac, ip.dst, ip.src, self.ip_id, ICMP_ECHO_REPLY, m.id, m.seq, m.data);
            if self.send(&f[..n]).is_ok() {
                self.echo_answered += 1;
            }
        } else if m.kind == ICMP_ECHO_REPLY {
            self.echo_reply(ip.src, m.id, m.seq, ip.ttl, m.data.len());
        }
    }

    fn has_ip(&self) -> bool {
        self.ip != [0; 4]
    }

    /// An address of this machine: ours, or 127.x for frames from the loopback
    /// queue (a frame from the cable to 127.x is dropped).
    fn local(&self, ip: [u8; 4]) -> bool {
        (self.has_ip() && ip == self.ip) || (loopback(ip) && self.from_loop)
    }

    /// Our source address towards `dst`.
    fn src_for(&self, dst: [u8; 4]) -> [u8; 4] {
        if loopback(dst) { [127, 0, 0, 1] } else { self.ip }
    }

    /// Handles the frames waiting in the loopback queue (they may queue more –
    /// at most LOOPQ * 4 per call; the rest waits for the next pass).
    fn run_loopback(&mut self) {
        let mut budget = LOOPQ * 4;
        let mut f = [0u8; 1600];
        while self.loop_head != self.loop_tail && budget > 0 {
            budget -= 1;
            let i = self.loop_head % LOOPQ;
            let n = self.loop_len[i];
            f[..n].copy_from_slice(&loop_frames()[i][..n]);
            self.loop_head = self.loop_head.wrapping_add(1);
            self.from_loop = true;
            self.handle(&f[..n]);
            self.from_loop = false;
        }
    }

    /// Sends a DHCP client message.
    fn dhcp_send(&mut self, m: Msg) {
        let mut d = [0u8; 300];
        let n = build_dhcp(&mut d, m.kind, m.xid, self.mac, m.ciaddr, m.requested, m.server, m.secs);
        let eth_dst = if m.dst == BROADCAST_IP {
            BROADCAST
        } else if self.dhcp_mac != [0; 6] {
            self.dhcp_mac
        } else {
            self.cached(m.dst).unwrap_or(BROADCAST)
        };
        let mut f = [0u8; 400];
        self.ip_id = self.ip_id.wrapping_add(1);
        let len = build_udp_frame(&mut f, eth_dst, self.mac, m.ciaddr, m.dst, self.ip_id, PORT_DHCP_CLIENT, PORT_DHCP_SERVER, &d[..n]);
        let _ = self.send(&f[..len]);
    }

    /// Sends what the DHCP client asked for and applies its event.
    fn dhcp_apply(&mut self, (msg, ev): (Option<Msg>, Event)) {
        match ev {
            Event::None => {}
            Event::Probe => {
                if let Some(ip) = self.dhcp.checking() {
                    self.arp_probe(ip);
                }
            }
            Event::Bound | Event::Renewed | Event::Changed => {
                let Some(l) = self.dhcp.lease else { return };
                if ev == Event::Changed {
                    self.arp_cache = [([0; 4], [0; 6], 0); ARP_CACHE];
                }
                self.ip = l.ip;
                self.prefix = l.prefix;
                self.gw = l.gw.unwrap_or([0; 4]);
                self.dns = l.dns;
                self.dns_n = l.dns_n as usize;
                if ev != Event::Renewed {
                    self.arp_announce();
                    let mut t = Text::new();
                    let _ = write!(t, "{}: address {}/{} from DHCP server {}", self.name, ip_text(l.ip), l.prefix, ip_text(l.server));
                    if ev == Event::Bound {
                        let _ = write!(t, " in {} ms", uptime_ms().saturating_sub(self.dhcp_t0));
                    }
                    let _ = writeln!(t, ", gateway {}, DNS {}", GwText(self.gw), DnsText(self.dns, self.dns_n));
                    write(1, t.as_bytes());
                }
            }
            Event::Lost => {
                let mut t = Text::new();
                let _ = writeln!(t, "{}: address {} given up (DHCP lease ended or refused) - asking again", self.name, ip_text(self.ip));
                write(1, t.as_bytes());
                self.ip = [0; 4];
                self.gw = [0; 4];
                self.dns_n = 0;
                self.arp_cache = [([0; 4], [0; 6], 0); ARP_CACHE];
                self.dhcp_mac = [0; 6];
                self.dhcp_t0 = uptime_ms();
            }
        }
        if let Some(m) = msg {
            self.dhcp_send(m);
        }
    }

    /// DHCP timers (resends, renewal, lease end).
    fn dhcp_tick(&mut self) {
        let now = uptime_ms();
        if now >= self.dhcp.deadline() {
            let r = self.dhcp.tick(now);
            self.dhcp_apply(r);
        }
    }

    fn cached(&self, ip: [u8; 4]) -> Option<[u8; 6]> {
        let now = uptime_ms();
        self.arp_cache.iter().find(|e| e.0 == ip && now.saturating_sub(e.2) < ARP_TTL_MS).map(|e| e.1)
    }

    fn learn(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        let now = uptime_ms();
        // Same IP, else an empty slot, else the oldest.
        let i = self
            .arp_cache
            .iter()
            .position(|e| e.0 == ip)
            .or_else(|| self.arp_cache.iter().position(|e| e.0 == [0; 4]))
            .unwrap_or_else(|| (0..ARP_CACHE).min_by_key(|&k| self.arp_cache[k].2).unwrap_or(0));
        self.arp_cache[i] = (ip, mac, now);
    }

    fn rand16(&mut self) -> u16 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        (x >> 24) as u16
    }

    /// A local port for a DNS query: random in 49152–65535, never the last one.
    fn new_port(&mut self) -> u16 {
        let step = 1 + (self.rand16() % 1000) as u32;
        let p = 49152 + (self.next_port as u32 + step - 49152) % 16384;
        self.next_port = p as u16;
        p as u16
    }

    /// A message to client `k`.  Never blocks: a client that does not read loses
    /// lines, a closed one is dropped.
    fn tell(&mut self, k: usize, t: &Text) {
        let c = &mut self.conns[k];
        if c.dead {
            return;
        }
        if chan_send(c.chan, t.as_bytes(), CHAN_NONBLOCK) == EPIPE {
            c.dead = true;
            c.op = Op::Idle;
        }
    }

    /// "Does anyone have `ip`?" from no address (RFC 5227 probe).
    fn arp_probe(&mut self, ip: [u8; 4]) {
        let req = Arp { op: ARP_REQUEST, sha: self.mac, spa: [0; 4], tha: [0; 6], tpa: ip };
        let mut f = [0u8; 64];
        let n = build_arp(&mut f, BROADCAST, &req);
        let _ = self.send(&f[..n]);
    }

    /// "`ip` is mine now" (gratuitous ARP – neighbours update their caches).
    fn arp_announce(&mut self) {
        let req = Arp { op: ARP_REQUEST, sha: self.mac, spa: self.ip, tha: [0; 6], tpa: self.ip };
        let mut f = [0u8; 64];
        let n = build_arp(&mut f, BROADCAST, &req);
        let _ = self.send(&f[..n]);
    }

    /// Gives the DHCP lease back (RELEASE) and stops the client.
    fn dhcp_release(&mut self) {
        let m = self.dhcp.release(uptime_ms());
        if let Some(m) = m {
            self.dhcp_send(m);
        }
    }

    fn arp_request(&mut self, ip: [u8; 4]) {
        let req = Arp { op: ARP_REQUEST, sha: self.mac, spa: self.ip, tha: [0; 6], tpa: ip };
        let mut f = [0u8; 64];
        let n = build_arp(&mut f, BROADCAST, &req);
        let _ = self.send(&f[..n]);
    }

    /// The MAC to send to `dst` through (itself on our subnet, else the
    /// gateway): from the cache, or by ARP (3 tries, 333 ms apart).  Ok(None) =
    /// still asking.
    fn hop(&mut self, now: u64, dst: [u8; 4], arp: &mut ArpWait) -> Result<Option<[u8; 6]>, &'static str> {
        // This machine: through the loopback queue, no ARP.
        if loopback(dst) || (self.has_ip() && dst == self.ip) {
            return Ok(Some(self.mac));
        }
        if !self.has_ip() {
            return Err("no address yet (waiting for DHCP)");
        }
        let hop = if same_subnet(dst, self.ip, self.prefix) {
            dst
        } else if self.gw != [0; 4] {
            self.gw
        } else {
            return Err("no gateway (DHCP gave none)");
        };
        if let Some(m) = self.cached(hop) {
            return Ok(Some(m));
        }
        if now < arp.next {
            return Ok(None);
        }
        if arp.tries == 3 {
            return Err(if hop == dst { "host unreachable (no ARP answer)" } else { "gateway unreachable (no ARP answer)" });
        }
        self.arp_request(hop);
        arp.tries += 1;
        arp.next = now + 333;
        Ok(None)
    }

    /// The earliest time an operation needs a step (u64::MAX = none).
    fn ops_deadline(&self) -> u64 {
        let mut d = u64::MAX;
        for c in &self.conns[..self.nconns] {
            let t = match c.op {
                Op::Idle => u64::MAX,
                Op::Arp { t0, .. } => t0 + 1000,
                Op::Renew { t0, .. } => t0 + 3000,
                Op::Resolve(r) => {
                    if r.hop.is_none() {
                        r.arp.next
                    } else {
                        r.next
                    }
                }
                Op::TcpStart { arp, .. } => arp.next,
                Op::Tcp { .. } | Op::Listen { .. } => u64::MAX,
                Op::SetStatic { t0, .. } => t0 + if self.static_probe_second { 2 * PROBE_WAIT_MS } else { PROBE_WAIT_MS },
                Op::Ping(p) => {
                    if p.hop.is_none() {
                        p.arp.next
                    } else if p.waiting {
                        p.t_sent + 1000
                    } else {
                        p.next
                    }
                }
            };
            d = d.min(t);
        }
        for (slot, m) in self.tcp.iter().enumerate() {
            if m.used {
                d = d.min(tcbs()[slot].deadline());
            }
        }
        d
    }

    /// A request from client `k` (which has no operation running).
    fn request(&mut self, k: usize, req: &str, now: u64) {
        let mut out = Text::new();
        if req == "status" {
            self.status(&mut out);
        } else if (req == "renew" || req == "dhcp" || req == "rxrestart" || req.starts_with("dns ") || req.starts_with("set ")) && self.conns[k].kind & K_ADMIN == 0 {
            let _ = writeln!(out, "netd: {:?} is an administrator request - not allowed for this program", req.split_whitespace().next().unwrap_or(""));
        } else if let Some(arg) = req.strip_prefix("listen ") {
            match arg.trim().parse::<u16>() {
                _ if self.conns[k].kind & K_LISTEN == 0 => {
                    let _ = writeln!(out, "listen: not allowed for this program (it needs the listen right - nofiles --listen)");
                }
                Ok(p) => {
                    let port = if p == 0 { self.tcp_port() } else { p };
                    let taken = self.conns[..self.nconns].iter().any(|c| matches!(c.op, Op::Listen { port: q } if q == port));
                    if taken {
                        let _ = writeln!(out, "listen: port {} is already in use", port);
                    } else {
                        let _ = writeln!(out, "listening on port {}", port);
                        self.tell(k, &out);
                        self.conns[k].op = Op::Listen { port };
                        return;
                    }
                }
                Err(_) => {
                    let _ = writeln!(out, "listen: expected a port 1-65535 (0 = any)");
                }
            }
        } else if let Some(arg) = req.strip_prefix("set ") {
            match parse_static(arg) {
                Ok((ip, prefix, gw, dns)) => {
                    // Check first: does another machine answer for this address?
                    self.static_probe = ip;
                    self.static_taken = None;
                    self.arp_probe(ip);
                    self.conns[k].op = Op::SetStatic { ip, prefix, gw, dns, t0: now };
                    return;
                }
                Err(e) => {
                    let _ = writeln!(out, "set: {} (expected a.b.c.d/nn [gw a.b.c.d] [dns a.b.c.d])", e);
                }
            }
        } else if req == "rxrestart" && self.kind == Kind::Realtek {
            self.rt_rx_restart();
            let _ = writeln!(out, "rx restarted ({} frames so far)", self.rx_frames);
        } else if req == "dhcp" {
            if self.by_hand || self.dhcp.state == dhcp::State::Off {
                self.by_hand = false;
                self.ip = [0; 4];
                self.gw = [0; 4];
                self.dns_n = 0;
                self.arp_cache = [([0; 4], [0; 6], 0); ARP_CACHE];
                self.dhcp_t0 = now;
                self.dhcp.start(now);
                self.dhcp_tick();
                let _ = writeln!(out, "DHCP on - asking for an address");
            } else {
                let _ = writeln!(out, "DHCP is already on ({})", self.dhcp.state.name());
            }
        } else if req == "renew" {
            match self.dhcp.renew_now(now) {
                Some(m) => {
                    let acks = self.dhcp.acks;
                    self.dhcp_send(m);
                    self.conns[k].op = Op::Renew { t0: now, acks };
                    return;
                }
                None => {
                    let _ = writeln!(out, "renew: no address yet (DHCP {})", self.dhcp.state.name());
                }
            }
        } else if let Some(arg) = req.strip_prefix("arp ") {
            match parse_ip(arg.trim()) {
                Some(_) if !self.has_ip() => {
                    let _ = writeln!(out, "arp: no address yet (waiting for DHCP)");
                }
                Some(ip) => {
                    self.arp_request(ip);
                    self.conns[k].op = Op::Arp { ip, t0: now };
                    return;
                }
                None => {
                    let _ = writeln!(out, "arp: bad address {:?}", arg.trim());
                }
            }
        } else if let Some(rest) = req.strip_prefix("ping ") {
            let mut w = rest.split_whitespace();
            let host = w.next().unwrap_or("");
            let count = w.next().and_then(|x| x.parse::<u16>().ok()).unwrap_or(4).clamp(1, 100);
            if let Some(ip) = parse_ip(host) {
                self.start_ping(k, ip, count, now);
            } else if let Some(name) = Name::parse(host) {
                self.start_resolve(k, name, Then::Ping(count), now);
            } else {
                let _ = writeln!(out, "ping: bad address or name {:?}\nping-end", host);
                self.tell(k, &out);
            }
            return;
        } else if let Some(rest) = req.strip_prefix("tcp ") {
            let mut w = rest.split_whitespace();
            let host = w.next().unwrap_or("");
            match w.next().and_then(|p| p.parse::<u16>().ok()).filter(|&p| p != 0) {
                None => {
                    let _ = writeln!(out, "tcp: expected a host and a port 1-65535");
                }
                Some(port) => {
                    if let Some(ip) = parse_ip(host) {
                        self.conns[k].op = Op::TcpStart { ip, port, arp: ArpWait::default(), t0: now };
                        return;
                    } else if let Some(name) = Name::parse(host) {
                        self.start_resolve(k, name, Then::Tcp(port), now);
                        return;
                    }
                    let _ = writeln!(out, "tcp: bad address or name {:?}", host);
                }
            }
        } else if let Some(arg) = req.strip_prefix("resolve ") {
            let arg = arg.trim();
            if let Some(ip) = parse_ip(arg) {
                let _ = writeln!(out, "{} is {} (an address, no DNS needed)", arg, ip_text(ip));
            } else if let Some(name) = Name::parse(arg) {
                self.start_resolve(k, name, Then::Print, now);
                return;
            } else {
                let _ = writeln!(out, "{:?}: not a valid name", arg);
            }
        } else if let Some(arg) = req.strip_prefix("dns ") {
            let arg = arg.trim();
            let set = if arg == "auto" {
                Some(None)
            } else {
                let (ip, port) = arg.split_once(':').unwrap_or((arg, "53"));
                match (parse_ip(ip), port.parse::<u16>()) {
                    (Some(ip), Ok(port)) if unicast(ip) && port != 0 => Some(Some((ip, port))),
                    _ => None,
                }
            };
            match set {
                Some(s) => {
                    self.dns_set = s;
                    self.dns_cache.clear();
                    match self.dns_server() {
                        Some(d) => {
                            let _ = writeln!(out, "DNS server {}{}", Server(d), if s.is_some() { " (set by hand)" } else { " (from DHCP)" });
                        }
                        None => {
                            let _ = writeln!(out, "DNS server: none yet (DHCP gave none)");
                        }
                    }
                }
                None => {
                    let _ = writeln!(out, "dns: expected a.b.c.d[:port] or auto, not {:?}", arg);
                }
            }
        } else {
            let _ = writeln!(out, "netd: unknown request {:?} (status, ping host [count], resolve name, tcp host port, listen port, arp a.b.c.d, dns server|auto, renew, set a.b.c.d/nn, dhcp)", req);
        }
        self.tell(k, &out);
    }

    /// Advances the operation of client `k`.
    fn step(&mut self, k: usize, now: u64) {
        let op = match self.conns[k].op {
            Op::Idle => return,
            Op::Arp { ip, t0 } => {
                if now - t0 < 1000 {
                    return;
                }
                let mut t = Text::new();
                let _ = writeln!(t, "arp {}: no reply in 1 s", ip_text(ip));
                self.tell(k, &t);
                Op::Idle
            }
            Op::Renew { t0, acks } => {
                let mut t = Text::new();
                match self.dhcp.lease {
                    Some(l) if self.dhcp.acks != acks => {
                        let _ = writeln!(t, "renewed {} for {} from {} in {} ms", ip_text(l.ip), Dur(l.lease_s), ip_text(l.server), now - t0);
                    }
                    None => {
                        let _ = writeln!(t, "renew: the server refused - address given up, asking again");
                    }
                    Some(_) if now - t0 >= 3000 => {
                        let _ = writeln!(t, "renew: no answer from the server in 3 s (address kept until the lease ends)");
                    }
                    Some(_) => return,
                }
                self.tell(k, &t);
                Op::Idle
            }
            Op::Resolve(r) => self.step_resolve(k, r, now),
            Op::Ping(p) => self.step_ping(k, p, now),
            Op::TcpStart { ip, port, mut arp, t0 } => match self.hop(now, ip, &mut arp) {
                Err(e) => {
                    let mut t = Text::new();
                    let _ = writeln!(t, "tcp: {}: {}", ip_text(ip), e);
                    self.tell(k, &t);
                    Op::Idle
                }
                Ok(None) => Op::TcpStart { ip, port, arp, t0 },
                Ok(Some(mac)) => self.tcp_open(k, ip, port, mac, t0, now),
            },
            Op::Tcp { .. } | Op::Listen { .. } => return,
            Op::SetStatic { ip, prefix, gw, dns, t0 } => {
                let mut t = Text::new();
                if let Some(mac) = self.static_taken {
                    let _ = writeln!(t, "set: {} is already used by {} - address not changed", ip_text(ip), Mac(mac));
                } else if now - t0 < 2 * PROBE_WAIT_MS {
                    if now - t0 >= PROBE_WAIT_MS && self.static_probe == ip && !self.static_probe_second {
                        self.static_probe_second = true;
                        self.arp_probe(ip);
                    }
                    return;
                } else {
                    // Free: the DHCP lease goes back, the new address is announced.
                    self.dhcp_release();
                    self.by_hand = true;
                    self.ip = ip;
                    self.prefix = prefix;
                    self.gw = gw;
                    self.dns = [dns, [0; 4]];
                    self.dns_n = if dns != [0; 4] { 1 } else { 0 };
                    self.arp_cache = [([0; 4], [0; 6], 0); ARP_CACHE];
                    self.arp_announce();
                    let _ = writeln!(
                        t,
                        "address {}/{} set by hand, gateway {}, DNS {} - DHCP off ('ifconfig dhcp' turns it back on)",
                        ip_text(ip),
                        prefix,
                        GwText(gw),
                        DnsText(self.dns, self.dns_n)
                    );
                    let mut m = Text::new();
                    let _ = writeln!(m, "{}: address {}/{} set by hand, gateway {}", self.name, ip_text(ip), prefix, GwText(gw));
                    write(1, m.as_bytes());
                }
                self.static_probe = [0; 4];
                self.static_probe_second = false;
                self.tell(k, &t);
                Op::Idle
            }
        };
        if !self.conns[k].dead {
            self.conns[k].op = op;
        }
    }

    // --- arp ---

    /// An ARP reply to us: finishes `arp` requests waiting for it.
    fn arp_answer(&mut self, ip: [u8; 4], mac: [u8; 6]) {
        let now = uptime_ms();
        for k in 0..self.nconns {
            if let Op::Arp { ip: want, t0 } = self.conns[k].op {
                if want == ip {
                    let mut t = Text::new();
                    let _ = writeln!(t, "arp {} is-at {} in {} ms", ip_text(ip), Mac(mac), now - t0);
                    self.tell(k, &t);
                    self.conns[k].op = Op::Idle;
                }
            }
        }
    }

    // --- ping ---

    fn start_ping(&mut self, k: usize, dst: [u8; 4], count: u16, now: u64) {
        let mut t = Text::new();
        let _ = writeln!(t, "PING {}: {} data bytes", ip_text(dst), PING_DATA);
        self.tell(k, &t);
        let id = self.rand16() | 1;
        self.conns[k].op = Op::Ping(Ping {
            dst,
            count,
            seq: 0,
            sent: 0,
            got: 0,
            id,
            t_sent: 0,
            waiting: false,
            next: now,
            tmin: u64::MAX,
            tmax: 0,
            tsum: 0,
            hop: None,
            arp: ArpWait::default(),
        });
    }

    fn step_ping(&mut self, k: usize, mut p: Ping, now: u64) -> Op {
        if p.hop.is_none() {
            match self.hop(now, p.dst, &mut p.arp) {
                Err(e) => {
                    let mut t = Text::new();
                    let _ = writeln!(t, "ping: {}: {}\nping-end", ip_text(p.dst), e);
                    self.tell(k, &t);
                    return Op::Idle;
                }
                Ok(None) => return Op::Ping(p),
                Ok(Some(m)) => p.hop = Some(m),
            }
        }
        if p.waiting && now >= p.t_sent + 1000 {
            let mut t = Text::new();
            let _ = writeln!(t, "no reply from {}: seq={}", ip_text(p.dst), p.seq);
            self.tell(k, &t);
            p.waiting = false;
        }
        if p.waiting {
            return Op::Ping(p);
        }
        if p.seq == p.count {
            self.ping_summary(k, &p);
            return Op::Idle;
        }
        if now >= p.next {
            let mut data = [0u8; PING_DATA];
            for (i, b) in data.iter_mut().enumerate() {
                *b = 0x10 + i as u8;
            }
            let mut f = [0u8; 128];
            p.seq += 1;
            self.ip_id = self.ip_id.wrapping_add(1);
            let src = self.src_for(p.dst);
            let n = build_echo_frame(&mut f, p.hop.unwrap_or(BROADCAST), self.mac, src, p.dst, self.ip_id, ICMP_ECHO_REQUEST, p.id, p.seq, &data);
            if self.send(&f[..n]).is_err() {
                self.ping_summary(k, &p);
                return Op::Idle;
            }
            p.sent += 1;
            p.waiting = true;
            p.t_sent = now;
            p.next = now + 1000;
        }
        Op::Ping(p)
    }

    /// An echo reply: the ping waiting for exactly this one (sender, id, sequence).
    fn echo_reply(&mut self, src: [u8; 4], id: u16, seq: u16, ttl: u8, len: usize) {
        let now = uptime_ms();
        for k in 0..self.nconns {
            let Op::Ping(mut p) = self.conns[k].op else { continue };
            if p.id != id || p.dst != src || !p.waiting || p.seq != seq {
                continue;
            }
            let ms = now - p.t_sent;
            p.got += 1;
            p.tmin = p.tmin.min(ms);
            p.tmax = p.tmax.max(ms);
            p.tsum += ms;
            p.waiting = false;
            self.conns[k].op = Op::Ping(p);
            let mut t = Text::new();
            let _ = writeln!(t, "{} bytes from {}: seq={} ttl={} time{}", len + 8, ip_text(src), seq, ttl, ms_text(ms).as_str());
            self.tell(k, &t);
            return;
        }
    }

    fn ping_summary(&mut self, k: usize, p: &Ping) {
        let mut t = Text::new();
        let loss = if p.sent == 0 { 100 } else { (p.sent - p.got) as u32 * 100 / p.sent as u32 };
        let _ = writeln!(t, "--- {} ping: {} sent, {} received, {}% loss", ip_text(p.dst), p.sent, p.got, loss);
        if p.got > 0 {
            let _ = writeln!(t, "time min/avg/max = {}/{}/{} ms (1 ms resolution)", p.tmin, p.tsum / p.got as u64, p.tmax);
        }
        let _ = writeln!(t, "ping-end");
        self.tell(k, &t);
    }

    // --- DNS ---

    /// The DNS server in use: set by hand, else the first from DHCP.
    fn dns_server(&self) -> Option<([u8; 4], u16)> {
        self.dns_set.or(if self.dns_n > 0 { Some((self.dns[0], DNS_PORT)) } else { None })
    }

    fn start_resolve(&mut self, k: usize, name: Name, then: Then, now: u64) {
        if let Some(c) = self.dns_cache.get(&name, now) {
            self.resolved(k, &name, c.rcode, &c.addrs[..c.n], None, then, now);
            return;
        }
        let Some((server, sport)) = self.dns_server() else {
            self.resolve_fail(k, &name, then, "no DNS server (DHCP gave none)");
            return;
        };
        let id = self.rand16();
        let port = self.new_port();
        self.conns[k].op = Op::Resolve(Resolve { name, server, sport, port, id, t0: now, tries: 0, next: now, hop: None, arp: ArpWait::default(), then });
    }

    fn step_resolve(&mut self, k: usize, mut r: Resolve, now: u64) -> Op {
        if r.hop.is_none() {
            match self.hop(now, r.server, &mut r.arp) {
                Err(e) => {
                    self.resolve_fail(k, &r.name, r.then, e);
                    return Op::Idle;
                }
                Ok(None) => return Op::Resolve(r),
                Ok(Some(m)) => r.hop = Some(m),
            }
        }
        if now < r.next {
            return Op::Resolve(r);
        }
        if r.tries as usize == DNS_WAIT_MS.len() {
            let mut msg = Text::new();
            let _ = write!(msg, "no answer from DNS server {}", Server((r.server, r.sport)));
            self.resolve_fail(k, &r.name, r.then, core::str::from_utf8(msg.as_bytes()).unwrap_or("no answer"));
            return Op::Idle;
        }
        let mut q = [0u8; 300];
        let n = dns::build_query(&mut q, r.id, &r.name);
        let mut f = [0u8; 400];
        self.ip_id = self.ip_id.wrapping_add(1);
        let len = build_udp_frame(&mut f, r.hop.unwrap_or(BROADCAST), self.mac, self.ip, r.server, self.ip_id, r.port, r.sport, &q[..n]);
        let _ = self.send(&f[..len]);
        self.dns_queries += 1;
        r.next = now + DNS_WAIT_MS[r.tries as usize];
        r.tries += 1;
        Op::Resolve(r)
    }

    /// A UDP packet that is not DHCP: the answer to a query in progress?  It must
    /// come from that server and port to our random port, with our random id.
    fn dns_packet(&mut self, src: [u8; 4], u: &Udp) -> bool {
        let now = uptime_ms();
        for k in 0..self.nconns {
            let Op::Resolve(r) = self.conns[k].op else { continue };
            if r.port != u.dst_port || r.server != src || r.sport != u.src_port {
                continue;
            }
            if dns::response_id(u.data) != Some(r.id) {
                // Stale or forged – keep waiting for the real one.
                self.dns_bad += 1;
                return true;
            }
            match dns::parse_response(u.data, r.id, &r.name) {
                Ok(a) => {
                    self.dns_answers += 1;
                    self.dns_cache.put(&r.name, &a, now);
                    self.resolved(k, &r.name, a.rcode, &a.addrs[..a.n], Some((r.server, r.sport, now - r.t0)), r.then, now);
                }
                Err(e) => {
                    self.dns_bad += 1;
                    let why = if e == NetError::Truncated { "answer too long for one packet (would need TCP)" } else { "malformed answer from the DNS server" };
                    self.resolve_fail(k, &r.name, r.then, why);
                    self.conns[k].op = Op::Idle;
                }
            }
            return true;
        }
        false
    }

    /// A name resolved (`via` = server, port and time; None = from the cache).
    #[allow(clippy::too_many_arguments)]
    fn resolved(&mut self, k: usize, name: &Name, rcode: u8, addrs: &[[u8; 4]], via: Option<([u8; 4], u16, u64)>, then: Then, now: u64) {
        let why = match rcode {
            0 if addrs.is_empty() => "has no IPv4 address",
            0 => "",
            dns::RCODE_NXDOMAIN => "no such name",
            dns::RCODE_SERVFAIL => "the DNS server failed to answer (SERVFAIL)",
            5 => "the DNS server refused to answer (REFUSED)",
            _ => "the DNS server reported an error",
        };
        if !why.is_empty() {
            self.resolve_fail(k, name, then, why);
            self.conns[k].op = Op::Idle;
            return;
        }
        if let Then::Tcp(port) = then {
            self.conns[k].op = Op::TcpStart { ip: addrs[0], port, arp: ArpWait::default(), t0: now };
            return;
        }
        let mut t = Text::new();
        let _ = write!(t, "{} is ", name);
        let list = match then {
            Then::Print => addrs,
            Then::Ping(_) | Then::Tcp(_) => &addrs[..1],
        };
        for (i, a) in list.iter().enumerate() {
            let _ = write!(t, "{}{}", if i > 0 { ", " } else { "" }, ip_text(*a));
        }
        match via {
            Some((server, port, ms)) => {
                let _ = writeln!(t, " (DNS {}, {})", Server((server, port)), ms_text(ms).as_str().trim_start_matches('='));
            }
            None => {
                let _ = writeln!(t, " (cached)");
            }
        }
        self.tell(k, &t);
        match then {
            Then::Print => self.conns[k].op = Op::Idle,
            Then::Ping(count) => self.start_ping(k, addrs[0], count, now),
            Then::Tcp(_) => {}
        }
    }

    fn resolve_fail(&mut self, k: usize, name: &Name, then: Then, why: &str) {
        let mut t = Text::new();
        match then {
            Then::Print => {
                let _ = writeln!(t, "{}: {}", name, why);
            }
            Then::Ping(_) => {
                let _ = writeln!(t, "ping: {}: {}\nping-end", name, why);
            }
            Then::Tcp(_) => {
                let _ = writeln!(t, "tcp: {}: {}", name, why);
            }
        }
        self.tell(k, &t);
    }

    // --- TCP ---

    fn rand32(&mut self) -> u32 {
        (self.rand16() as u32) << 16 | self.rand16() as u32
    }

    /// A random local port no TCP connection uses.
    fn tcp_port(&mut self) -> u16 {
        loop {
            let p = self.new_port();
            let listening = self.conns[..self.nconns].iter().any(|c| matches!(c.op, Op::Listen { port } if port == p));
            if !listening && !self.tcp.iter().any(|m| m.used && m.lport == p) {
                return p;
            }
        }
    }

    /// The next hop is known: a TCP block, the SYN.
    fn tcp_open(&mut self, k: usize, ip: [u8; 4], port: u16, mac: [u8; 6], t0: u64, now: u64) -> Op {
        let Some(slot) = self.tcp.iter().position(|m| !m.used) else {
            let mut t = Text::new();
            let _ = writeln!(t, "tcp: too many connections (at most {})", TCP_MAX);
            self.tell(k, &t);
            return Op::Idle;
        };
        let lport = self.tcp_port();
        let iss = self.rand32();
        tcbs()[slot].init_connect(iss, now);
        let lip = self.src_for(ip);
        self.tcp[slot] = TcpMeta { used: true, lip, lport, rip: ip, rport: port, mac, owner: k, listener: NO_OWNER, t0, peak: 0 };
        self.tcp_made += 1;
        self.tcp_flush(slot, now);
        Op::Tcp { slot, open: false }
    }

    /// Sends whatever the connection has to send.
    fn tcp_flush(&mut self, slot: usize, now: u64) {
        let m = self.tcp[slot];
        let mut data = [0u8; tcp::MSS as usize];
        let mut f = [0u8; 1600];
        while let Some(o) = tcbs()[slot].output(now, &mut data) {
            self.ip_id = self.ip_id.wrapping_add(1);
            let n = build_tcp_frame(&mut f, m.mac, self.mac, m.lip, m.rip, self.ip_id, m.lport, m.rport, o.seq, o.ack, o.flags, o.window, o.mss, o.wscale, &data[..o.len]);
            if self.send(&f[..n]).is_err() {
                break; // ring full – the retransmission timer sends it again
            }
            self.tcp_out += 1;
        }
    }

    /// A TCP segment to our address.
    fn on_tcp(&mut self, src_mac: [u8; 6], ip: &Ipv4) {
        let Ok(t) = parse_tcp(ip.src, ip.dst, ip.payload) else {
            self.rx_bad += 1;
            return;
        };
        self.tcp_in += 1;
        let seg = tcp::Seg { seq: t.seq, ack: t.ack, flags: t.flags, window: t.window, mss: t.mss, wscale: t.wscale, data: t.data };
        let now = uptime_ms();
        let found = self.tcp.iter().position(|m| m.used && m.lport == t.dst_port && m.lip == ip.dst && m.rip == ip.src && m.rport == t.src_port);
        // A new connection to a listening port.
        if found.is_none() && t.flags & (TCP_SYN | TCP_ACK | TCP_RST) == TCP_SYN && self.tcp_accept(src_mac, ip, &seg, t.src_port, t.dst_port, now) {
            return;
        }
        match found {
            Some(slot) => {
                tcbs()[slot].on_segment(now, &seg);
                // Data for a program that is gone: nobody will read it – reset.  (An
                // accepted connection not yet handed to the server is not "gone":
                // the request often arrives together with the handshake.)
                if self.tcp[slot].owner == NO_OWNER && self.tcp[slot].listener == NO_OWNER && tcbs()[slot].readable() > 0 {
                    tcbs()[slot].abort();
                }
                self.tcp_flush(slot, now);
            }
            None => {
                // No such connection: a RST (never for a RST, never to a group address).
                if let Some((seq, ack, flags)) = tcp::reset_for(&seg) {
                    if src_mac[0] & 1 == 0 && (unicast(ip.src) || self.from_loop) {
                        let mut f = [0u8; 80];
                        self.ip_id = self.ip_id.wrapping_add(1);
                        let n = build_tcp_frame(&mut f, src_mac, self.mac, ip.dst, ip.src, self.ip_id, t.dst_port, t.src_port, seq, ack, flags, 0, None, None, &[]);
                        if self.send(&f[..n]).is_ok() {
                            self.tcp_resets += 1;
                        }
                    }
                }
            }
        }
    }

    /// A SYN for `dport`: a new block in SynReceived when a client listens on
    /// that port and its backlog has room (else false – the caller answers RST).
    fn tcp_accept(&mut self, src_mac: [u8; 6], ip: &Ipv4, seg: &tcp::Seg, sport: u16, dport: u16, now: u64) -> bool {
        let Some(l) = self.conns[..self.nconns].iter().position(|c| !c.dead && matches!(c.op, Op::Listen { port } if port == dport)) else {
            return false;
        };
        let waiting = self.tcp.iter().filter(|m| m.used && m.listener == l).count();
        let Some(slot) = self.tcp.iter().position(|m| !m.used) else { return false };
        if waiting >= BACKLOG || (src_mac[0] & 1 != 0) {
            return false;
        }
        let iss = self.rand32();
        tcbs()[slot].init_accept(iss, now, seg);
        self.tcp[slot] = TcpMeta { used: true, lip: ip.dst, lport: dport, rip: ip.src, rport: sport, mac: src_mac, owner: NO_OWNER, listener: l, t0: now, peak: 0 };
        self.tcp_flush(slot, now);
        true
    }

    /// An accepted connection is open: a new channel for it, one end to the
    /// server program with "accepted ...", the other end netd's socket.
    fn tcp_hand_over(&mut self, slot: usize) {
        let m = self.tcp[slot];
        let l = m.listener;
        self.tcp[slot].listener = NO_OWNER;
        let port = match self.conns[l].op {
            Op::Listen { port } => port,
            _ => 0,
        };
        let ok = self.nconns < MAX_CONNS && port != 0;
        let pair = if ok { channel_create().ok() } else { None };
        let Some((mine, theirs)) = pair else {
            tcbs()[slot].abort();
            return;
        };
        let mut t = Text::new();
        let _ = writeln!(t, "accepted {}:{} to port {}", ip_text(m.rip), m.rport, port);
        if chan_send_h(self.conns[l].chan, t.as_bytes(), &[theirs], CHAN_NONBLOCK) != 0 {
            close(mine);
            close(theirs);
            tcbs()[slot].abort();
            return;
        }
        let k = self.nconns;
        self.conns[k] = Conn { chan: mine, op: Op::Tcp { slot, open: true }, dead: false, kind: 0 };
        self.nconns += 1;
        self.tcp[slot].owner = k;
        self.tcp_accepted += 1;
    }

    /// Received data to the program, as far as its channel takes it (the rest
    /// waits – the TCP window closes until the program reads).
    fn tcp_deliver(&mut self, k: usize, slot: usize) {
        self.tcp[slot].peak = self.tcp[slot].peak.max(tcbs()[slot].readable());
        let mut buf = [0u8; MSG_MAX];
        while tcbs()[slot].readable() > 0 && !self.conns[k].dead {
            let n = tcbs()[slot].peek(&mut buf);
            let r = chan_send(self.conns[k].chan, &buf[..n], CHAN_NONBLOCK);
            if r == EPIPE {
                self.conns[k].dead = true;
                break;
            }
            if r < 0 {
                break;
            }
            tcbs()[slot].consume(n);
        }
    }

    /// Timers, state changes the owner must hear about, delivery, freeing.
    fn tcp_sweep(&mut self, now: u64) {
        for slot in 0..TCP_MAX {
            if !self.tcp[slot].used {
                continue;
            }
            if now >= tcbs()[slot].deadline() {
                tcbs()[slot].tick(now);
            }
            if self.tcp[slot].listener != NO_OWNER {
                let st = tcbs()[slot].state;
                if st != tcp::State::SynReceived && st != tcp::State::Closed {
                    self.tcp_hand_over(slot);
                }
            }
            let owner = self.tcp[slot].owner;
            if owner != NO_OWNER {
                let open = match self.conns[owner].op {
                    Op::Tcp { slot: s, open } if s == slot => open,
                    _ => {
                        self.tcp[slot].owner = NO_OWNER;
                        continue;
                    }
                };
                let st = tcbs()[slot].state;
                let m = self.tcp[slot];
                if !open && st != tcp::State::SynSent && st != tcp::State::Closed {
                    let mut t = Text::new();
                    let _ = writeln!(t, "connected {}:{} from {}:{} in {} ms", ip_text(m.rip), m.rport, ip_text(self.ip), m.lport, now - m.t0);
                    self.tell(owner, &t);
                    self.conns[owner].op = Op::Tcp { slot, open: true };
                }
                let open = matches!(self.conns[owner].op, Op::Tcp { open: true, .. });
                if open {
                    self.tcp_deliver(owner, slot);
                }
                if st == tcp::State::Closed {
                    if !open {
                        let why = match tcbs()[slot].end {
                            tcp::End::Refused => "connection refused (nothing listens on that port)",
                            tcp::End::TimedOut => "timed out (no answer)",
                            tcp::End::Reset => "connection reset",
                            _ => "connection closed",
                        };
                        let mut t = Text::new();
                        let _ = writeln!(t, "tcp: {}:{}: {}", ip_text(m.rip), m.rport, why);
                        self.tell(owner, &t);
                    } else {
                        // The program sees the end of the data (EPIPE).
                        self.conns[owner].dead = true;
                        let why = match tcbs()[slot].end {
                            tcp::End::Reset => "reset by the peer",
                            tcp::End::TimedOut => "timed out (no answer to our data)",
                            tcp::End::Aborted => "aborted by us",
                            _ => "closed",
                        };
                        self.tcp_last_scale = tcbs()[slot].peer_shift();
                        self.tcp_last_peak = self.tcp[slot].peak;
                        self.tcp_last_end = Some((m.rip, m.rport, why));
                    }
                    self.conns[owner].op = Op::Idle;
                    self.tcp[slot].owner = NO_OWNER;
                } else if open && tcbs()[slot].peer_fin && tcbs()[slot].readable() == 0 && !self.conns[owner].dead {
                    // Everything delivered and the peer closed: end of data for the
                    // program; netd closes our side.
                    self.conns[owner].dead = true;
                    self.conns[owner].op = Op::Idle;
                    self.tcp[slot].owner = NO_OWNER;
                    tcbs()[slot].close();
                    self.tcp_last_scale = tcbs()[slot].peer_shift();
                        self.tcp_last_peak = self.tcp[slot].peak;
                        self.tcp_last_end = Some((m.rip, m.rport, "closed by the peer"));
                }
            }
            self.tcp_flush(slot, now);
            if tcbs()[slot].state == tcp::State::Closed && self.tcp[slot].owner == NO_OWNER {
                // (also a SynReceived block that timed out or was reset)
                self.tcp_dropped += tcbs()[slot].dropped as u64;
                self.tcp_reordered += tcbs()[slot].reordered as u64;
                self.tcp[slot] = TCP_FREE;
            }
        }
    }

    /// Connection `k` is going away: its TCP connection closes (FIN), or resets
    /// when received data was never read.
    fn tcp_detach(&mut self, k: usize, now: u64) {
        if let Op::Tcp { slot, .. } = self.conns[k].op {
            if self.tcp[slot].used && self.tcp[slot].owner == k {
                if tcbs()[slot].readable() > 0 {
                    tcbs()[slot].abort();
                } else {
                    tcbs()[slot].close();
                }
                self.tcp[slot].owner = NO_OWNER;
                self.tcp_flush(slot, now);
            }
        }
        self.conns[k].op = Op::Idle;
    }


    /// Sends one frame (shorter frames padded to 60 bytes).
    fn send(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        if frame.len() > BUF as usize {
            return Err("frame too long");
        }
        // IPv4 to this machine: back through the loopback queue, not to the card.
        if frame.len() >= ETH_HDR + IP_HDR && frame[12..14] == ETH_IPV4.to_be_bytes() {
            let dst = [frame[30], frame[31], frame[32], frame[33]];
            if loopback(dst) || (self.has_ip() && dst == self.ip) {
                if self.loop_tail.wrapping_sub(self.loop_head) >= LOOPQ {
                    return Err("loopback queue full");
                }
                let i = self.loop_tail % LOOPQ;
                loop_frames()[i][..frame.len()].copy_from_slice(frame);
                self.loop_len[i] = frame.len();
                self.loop_tail = self.loop_tail.wrapping_add(1);
                self.loop_frames += 1;
                return Ok(());
            }
        }
        if self.kind == Kind::Realtek {
            return self.rt_send(frame);
        }
        let i = self.tx_next;
        let d = self.tx_desc(i);
        // The descriptor is free when the card has written DD back (or it was never used).
        let st = unsafe { core::ptr::read_volatile((d + 12) as *const u8) };
        let cmd = unsafe { core::ptr::read_volatile((d + 11) as *const u8) };
        if cmd != 0 && st & 1 == 0 {
            return Err("transmit ring full");
        }
        let buf = self.va + TX_BUF + i as u64 * BUF;
        let len = frame.len().max(60);
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), buf as *mut u8, frame.len());
            core::ptr::write_bytes((buf + frame.len() as u64) as *mut u8, 0, len - frame.len());
            // length, cso 0, cmd EOP | IFCS | RS, status 0.
            core::ptr::write_volatile((d + 8) as *mut u64, len as u64 | (0x0B_u64 << 24));
        }
        self.tx_next = (i + 1) % RING;
        self.set(TDT, self.tx_next as u32);
        self.tx_frames += 1;
        self.tx_bytes += len as u64;
        Ok(())
    }

    fn status(&self, out: &mut Text) {
        let (up, speed) = self.link();
        let _ = writeln!(
            out,
            "{}: {} ({:04x}:{:04x}), MAC {}, link {}",
            self.name,
            self.chip,
            self.vendor,
            self.device,
            Mac(self.mac),
            if up { "up" } else { "down" }
        );
        if up {
            let _ = writeln!(out, "  speed {} Mb/s", speed);
        }
        if self.kind == Kind::Realtek {
            self.rt_regs(out);
        }
        let _ = writeln!(
            out,
            "  received {} frames ({} bytes: {} ARP, {} IPv4, {} IPv6, {} other; {} errors), sent {} frames ({} bytes)",
            self.rx_frames, self.rx_bytes, self.rx_arp, self.rx_ipv4, self.rx_ipv6, self.rx_other, self.rx_errors, self.tx_frames, self.tx_bytes
        );
        match self.dhcp.lease {
            Some(l) => {
                let now = uptime_ms();
                let _ = write!(out, "  IPv4 {}/{} from DHCP server {}, lease {}", ip_text(l.ip), l.prefix, ip_text(l.server), Dur(l.lease_s));
                if l.lease_s != INFINITE {
                    let left = |t: u64| (t.saturating_sub(now) / 1000) as u32;
                    match self.dhcp.state {
                        dhcp::State::Bound => {
                            let _ = write!(out, " (renew in {})", Dur(left(l.t1_ms)));
                        }
                        st => {
                            let _ = write!(out, " ({}, ends in {})", st.name(), Dur(left(l.end_ms)));
                        }
                    }
                }
                let _ = writeln!(out);
                match self.dns_set {
                    Some(d) => {
                        let _ = writeln!(out, "  gateway {}, DNS {} (set by hand; DHCP gave {})", GwText(self.gw), Server(d), DnsText(self.dns, self.dns_n));
                    }
                    None => {
                        let _ = writeln!(out, "  gateway {}, DNS {}", GwText(self.gw), DnsText(self.dns, self.dns_n));
                    }
                }
            }
            None if self.by_hand => {
                let _ = writeln!(out, "  IPv4 {}/{} set by hand (DHCP off)", ip_text(self.ip), self.prefix);
                let _ = writeln!(out, "  gateway {}, DNS {}", GwText(self.gw), DnsText(self.dns, self.dns_n));
            }
            None => {
                let _ = writeln!(
                    out,
                    "  IPv4: no address yet - DHCP {} ({} messages sent, {} offers, {} refusals)",
                    self.dhcp.state.name(),
                    self.dhcp.sent,
                    self.dhcp.offers,
                    self.dhcp.naks
                );
            }
        }
        let known = self.arp_cache.iter().filter(|e| e.0 != [0; 4]).count();
        let _ = writeln!(
            out,
            "  answered {} ARP requests and {} pings; {} malformed packets dropped; ARP cache {} of {}",
            self.arp_answered, self.echo_answered, self.rx_bad, known, ARP_CACHE
        );
        let now = uptime_ms();
        let _ = writeln!(
            out,
            "  DNS: {} queries, {} answers, {} bad answers; {} names cached (of {}); programs connected: {}",
            self.dns_queries,
            self.dns_answers,
            self.dns_bad,
            self.dns_cache.len(now),
            dns::CACHE,
            self.nconns
        );
        let open = self.tcp.iter().filter(|m| m.used).count();
        let _ = writeln!(
            out,
            "  TCP: {} connections (of {}), {} made; {} segments in, {} out, {} resent, {} resets sent",
            open,
            TCP_MAX,
            self.tcp_made,
            self.tcp_in,
            self.tcp_out,
            tcbs().iter().zip(self.tcp.iter()).filter(|(_, m)| m.used).map(|(t, _)| t.retransmits as u64).sum::<u64>(),
            self.tcp_resets
        );
        if let Some((ip, port, why)) = self.tcp_last_end {
            let _ = writeln!(out, "    last ended: {}:{} {}; {} segments kept ahead of a gap, {} dropped (outside the window)", ip_text(ip), port, why, self.tcp_reordered, self.tcp_dropped);
            match self.tcp_last_scale {
                Some(s) => {
                    let _ = write!(out, "      window scaling agreed (peer shift {})", s);
                }
                None => {
                    let _ = write!(out, "      no window scaling (the peer did not offer it - window at most 64 KiB)");
                }
            }
            let _ = writeln!(out, "; most data waiting for the program at once: {} KiB", self.tcp_last_peak / 1024);
        }
        for c in &self.conns[..self.nconns] {
            if let Op::Listen { port } = c.op {
                let waiting = self.tcp.iter().filter(|m| m.used && m.listener != NO_OWNER && matches!(self.conns[m.listener].op, Op::Listen { port: q } if q == port)).count();
                let _ = writeln!(out, "    listening on port {} ({} waiting to be accepted)", port, waiting);
            }
        }
        for (slot, m) in self.tcp.iter().enumerate() {
            if m.used {
                let t = &tcbs()[slot];
                let _ = writeln!(
                    out,
                    "    {}:{} -> {}:{} {}{}, rtt {} ms",
                    ip_text(m.lip),
                    m.lport,
                    ip_text(m.rip),
                    m.rport,
                    t.state.name(),
                    if m.owner == NO_OWNER { " (program gone)" } else { "" },
                    t.rtt_ms
                );
            }
        }
        let _ = writeln!(out, "  interrupts {}, frames found by polling {}", self.irqs, self.polled);
        let _ = writeln!(
            out,
            "netd-status mac={} link={} ip={} prefix={} gw={} dns={} dhcp={} lease={} acks={} naks={} ignored={} declined={} released={} conflicts={} byhand={} dnsq={} dnsa={} dnsbad={} cached={} conns={} tcp={} tcpacc={} loop={} tcpmade={} tcpin={} tcpout={} tcprst={} rx={} tx={} arp={} irq={} errors={} bad={} echo={}",
            Mac(self.mac),
            up as u8,
            ip_text(self.ip),
            self.prefix,
            ip_text(self.gw),
            Server(self.dns_server().unwrap_or(([0; 4], DNS_PORT))),
            self.dhcp.state.name(),
            self.dhcp.lease.map(|l| l.lease_s).unwrap_or(0),
            self.dhcp.acks,
            self.dhcp.naks,
            self.dhcp.ignored,
            self.dhcp.declined,
            self.dhcp.released,
            self.conflicts,
            self.by_hand as u8,
            self.dns_queries,
            self.dns_answers,
            self.dns_bad,
            self.dns_cache.len(now),
            self.nconns,
            open,
            self.tcp_accepted,
            self.loop_frames,
            self.tcp_made,
            self.tcp_in,
            self.tcp_out,
            self.tcp_resets,
            self.rx_frames,
            self.tx_frames,
            self.rx_arp,
            self.irqs,
            self.rx_errors,
            self.rx_bad,
            self.echo_answered
        );
    }
}

/// A lease time: "24 h", "1 h 30 min", "45 s", "forever".
struct Dur(u32);

impl core::fmt::Display for Dur {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let s = self.0;
        if s == INFINITE {
            write!(f, "forever")
        } else if s >= 3600 {
            let (h, m) = (s / 3600, s % 3600 / 60);
            if m == 0 { write!(f, "{} h", h) } else { write!(f, "{} h {} min", h, m) }
        } else if s >= 60 {
            write!(f, "{} min", s / 60)
        } else {
            write!(f, "{} s", s)
        }
    }
}

/// `set`: time after each of the 2 ARP probes before the address counts as free.
const PROBE_WAIT_MS: u64 = 300;

/// "a.b.c.d/nn [gw a.b.c.d] [dns a.b.c.d]" -> (address, prefix, gateway, DNS).
fn parse_static(arg: &str) -> Result<([u8; 4], u8, [u8; 4], [u8; 4]), &'static str> {
    let mut w = arg.split_whitespace();
    let addr = w.next().ok_or("no address")?;
    let (ip, prefix) = match addr.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().map_err(|_| "bad prefix length")?),
        None => (addr, 24),
    };
    let ip = parse_ip(ip).ok_or("bad address")?;
    if !unicast(ip) || !(1..=30).contains(&prefix) {
        return Err("not a usable address / prefix 1-30");
    }
    let (mut gw, mut dns) = ([0u8; 4], [0u8; 4]);
    while let Some(key) = w.next() {
        let v = w.next().and_then(parse_ip).ok_or("bad gateway / DNS address")?;
        match key {
            "gw" => {
                if !unicast(v) || v == ip || !same_subnet(v, ip, prefix) {
                    return Err("the gateway must be another address on the same subnet");
                }
                gw = v;
            }
            "dns" if unicast(v) => dns = v,
            _ => return Err("unknown option"),
        }
    }
    Ok((ip, prefix, gw, dns))
}

/// A DNS server: "a.b.c.d", or "a.b.c.d:port" for another port than 53.
struct Server(([u8; 4], u16));

impl core::fmt::Display for Server {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let (ip, port) = self.0;
        if port == DNS_PORT { write!(f, "{}", ip_text(ip)) } else { write!(f, "{}:{}", ip_text(ip), port) }
    }
}

struct GwText([u8; 4]);

impl core::fmt::Display for GwText {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        if self.0 == [0; 4] { write!(f, "none") } else { write!(f, "{}", ip_text(self.0)) }
    }
}

struct DnsText([[u8; 4]; 2], usize);

impl core::fmt::Display for DnsText {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        if self.1 == 0 {
            return write!(f, "none");
        }
        for k in 0..self.1.min(2) {
            write!(f, "{}{}", if k > 0 { ", " } else { "" }, ip_text(self.0[k]))?;
        }
        Ok(())
    }
}

/// "N ms" / "<1 ms" for ping lines (fixed buffers, no allocation).
struct Small {
    buf: [u8; 24],
    len: usize,
}

impl Small {
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl core::fmt::Write for Small {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let b = s.as_bytes();
        let n = b.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
        Ok(())
    }
}

/// "=N ms", or "<1 ms" below the 1 ms clock resolution.
fn ms_text(ms: u64) -> Small {
    let mut s = Small { buf: [0; 24], len: 0 };
    let _ = if ms == 0 { write!(s, "<1 ms") } else { write!(s, "={} ms", ms) };
    s
}

// Realtek RTL8111/8168 (8168g generation and later).  Registers of 8, 16 and 32
// bits in BAR 2; rings of 16-byte descriptors (first word: OWN, end of ring,
// first / last fragment, length; then a reserved word and the buffer address);
// the PHY behind an indirect register (GPHY_OCP), internal registers behind two
// more (MAC OCP, ERI).  The sequence follows the chip's documented bring-up:
// leave the firmware's out-of-band mode, gate reception while resetting, open
// the gate when the rings are in place.
impl Nic {
    fn r8(&self, r: u64) -> u8 {
        rd8(self.regs + r)
    }
    fn w8(&self, r: u64, v: u8) {
        wr8(self.regs + r, v)
    }
    fn r16(&self, r: u64) -> u16 {
        rd16(self.regs + r)
    }
    fn w16(&self, r: u64, v: u16) {
        wr16(self.regs + r, v)
    }

    /// Waits up to `ms` for `cond`; false (and a note) when it never held.
    fn rt_wait(&mut self, ms: u64, note: u32, cond: impl Fn(&Nic) -> bool) -> bool {
        let t = uptime_ms();
        loop {
            if cond(self) {
                return true;
            }
            if uptime_ms() - t > ms {
                self.notes |= note;
                return false;
            }
        }
    }

    fn rt_eri_read(&mut self, addr: u32) -> u32 {
        self.set(R_ERIAR, 0xF << 12 | addr);
        self.rt_wait(10, RT_NOTE_ERI, |n| n.reg(R_ERIAR) & RT_OCP_FLAG != 0);
        self.reg(R_ERIDR)
    }

    /// `mask`: which of the 4 bytes are written (bit per byte).
    fn rt_eri_write(&mut self, addr: u32, mask: u32, v: u32) {
        self.set(R_ERIDR, v);
        self.set(R_ERIAR, RT_OCP_FLAG | mask << 12 | addr);
        self.rt_wait(10, RT_NOTE_ERI, |n| n.reg(R_ERIAR) & RT_OCP_FLAG == 0);
    }

    fn rt_mac_ocp_modify(&mut self, reg: u32, clear: u16, set: u16) {
        self.set(R_MAC_OCP, reg << 15);
        let v = (self.reg(R_MAC_OCP) as u16 & !clear) | set;
        self.set(R_MAC_OCP, RT_OCP_FLAG | reg << 15 | v as u32);
    }

    /// Standard PHY register `r` (page 0).
    fn rt_phy_read(&mut self, r: u32) -> u16 {
        self.set(R_GPHY_OCP, (RT_PHY_BASE + r * 2) << 15);
        if !self.rt_wait(10, RT_NOTE_PHY, |n| n.reg(R_GPHY_OCP) & RT_OCP_FLAG != 0) {
            return 0xFFFF;
        }
        self.reg(R_GPHY_OCP) as u16
    }

    fn rt_phy_write(&mut self, r: u32, v: u16) {
        self.set(R_GPHY_OCP, RT_OCP_FLAG | (RT_PHY_BASE + r * 2) << 15 | v as u32);
        self.rt_wait(10, RT_NOTE_PHY, |n| n.reg(R_GPHY_OCP) & RT_OCP_FLAG == 0);
    }

    fn rt_start(&mut self) -> Result<(), &'static str> {
        if self.reg(R_TXCONFIG) == 0xFFFF_FFFF {
            return Err("card does not answer (registers read all ones)");
        }
        self.xid = (self.reg(R_TXCONFIG) >> 20) & 0xFCF;
        if rt_version(self.xid).is_none() {
            println!("{}: Realtek chip version {:03x} - this driver was written for the 8168g/8168h generation, trying anyway", self.name, self.xid);
        }
        self.w8(R_CFG9346, 0xC0);
        // Clocks on.
        self.w8(R_PMCH, self.r8(R_PMCH) | 0xC0);
        // Out of the firmware's (out-of-band) mode: gate reception, wait for the
        // FIFOs to drain, stop rx/tx, hand the chip to the driver.
        self.set(R_MISC, self.reg(R_MISC) | RT_MISC_RXDV_GATE);
        self.rt_wait(50, RT_NOTE_TXCFG, |n| n.reg(R_TXCONFIG) & RT_TXCFG_EMPTY != 0);
        self.rt_wait(50, RT_NOTE_RXTX, |n| n.r8(R_MCU) & RT_MCU_RXTX_EMPTY == RT_MCU_RXTX_EMPTY);
        self.w8(R_CHIPCMD, self.r8(R_CHIPCMD) & !(RT_CMD_RX | RT_CMD_TX));
        sleep_ms(1);
        self.w8(R_MCU, self.r8(R_MCU) & !RT_MCU_OOB);
        self.rt_mac_ocp_modify(0xE8DE, 1 << 14, 0);
        self.rt_wait(50, RT_NOTE_LLRDY, |n| n.r8(R_MCU) & RT_MCU_LINK_LIST_RDY != 0);
        self.rt_mac_ocp_modify(0xE8DE, 0, 1 << 15);
        self.rt_wait(50, RT_NOTE_LLRDY, |n| n.r8(R_MCU) & RT_MCU_LINK_LIST_RDY != 0);
        // Interrupts off, receive filter closed, reset.
        self.w16(R_INTR_MASK, 0);
        self.w16(R_INTR_STATUS, 0xFFFF);
        self.set(R_RXCONFIG, self.reg(R_RXCONFIG) & !0x3F);
        sleep_ms(2);
        self.w8(R_CHIPCMD, RT_CMD_RESET);
        let t = uptime_ms();
        while self.r8(R_CHIPCMD) & RT_CMD_RESET != 0 {
            if uptime_ms() - t > 500 {
                return Err("card does not come out of reset");
            }
            sleep_ms(1);
        }
        self.rt_read_mac();
        // Our address in the receive filter (config registers unlocked).
        self.w8(R_CFG9346, 0xC0);
        let m = self.mac;
        self.set(R_MAC4, u16::from_le_bytes([m[4], m[5]]) as u32);
        let _ = self.reg(R_MAC4);
        self.set(R_MAC0, u32::from_le_bytes([m[0], m[1], m[2], m[3]]));
        let _ = self.reg(R_MAC0);
        if self.reg(R_MAC0) != u32::from_le_bytes([m[0], m[1], m[2], m[3]]) {
            self.notes |= RT_NOTE_MAC_REG;
        }
        self.set(R_MAR0, 0);
        self.set(R_MAR0 + 4, 0);
        // Rings: every rx descriptor owns a buffer; tx descriptors start empty.
        for i in 0..RING {
            let eor = if i == RING - 1 { RT_EOR } else { 0 };
            let d = self.rx_desc(i);
            let t = self.tx_desc(i);
            unsafe {
                core::ptr::write_volatile((d + 8) as *mut u64, self.pa + RX_BUF + i as u64 * BUF);
                core::ptr::write_volatile((d + 4) as *mut u32, 0);
                core::ptr::write_volatile(d as *mut u32, RT_OWN | eor | BUF as u32);
                core::ptr::write_volatile((t + 8) as *mut u64, self.pa + TX_BUF + i as u64 * BUF);
                core::ptr::write_volatile((t + 4) as *mut u32, 0);
                core::ptr::write_volatile(t as *mut u32, eor);
            }
        }
        // Power saving on the PCIe link off (it can stall DMA), checksum and
        // VLAN offloads off, early transmit size, FIFO thresholds, packet filter
        // reset, then the receive gate opens.
        self.w8(R_CONFIG2, self.r8(R_CONFIG2) & !0x80);
        self.w8(R_CONFIG5, self.r8(R_CONFIG5) & !0x01);
        self.w16(R_CPLUSCMD, self.r16(R_CPLUSCMD) & 0x2003);
        self.w8(R_MAXTXPKT, 0x27);
        self.rt_eri_write(0xC8, 0xF, 0x08 << 16 | 0x10);
        self.rt_eri_write(0xE8, 0xF, 0x02 << 16 | 0x06);
        let f = self.rt_eri_read(0xDC);
        self.rt_eri_write(0xDC, 0xF, f & !1);
        self.rt_eri_write(0xDC, 0xF, f | 1);
        self.set(R_MISC, self.reg(R_MISC) & !RT_MISC_RXDV_GATE);
        self.w16(R_INTR_MITIGATE, 0);
        self.w16(R_RXMAXSIZE, BUF as u16);
        let (rx, tx) = (self.pa + RX_DESC, self.pa + TX_DESC);
        self.set(R_TX_DESC + 4, (tx >> 32) as u32);
        self.set(R_TX_DESC, tx as u32);
        self.set(R_RX_DESC + 4, (rx >> 32) as u32);
        self.set(R_RX_DESC, rx as u32);
        self.w8(R_CFG9346, 0);
        // Interrupt (MSI) before the card may write to memory.
        let irq = irq_bind(DEV);
        if irq < 0 {
            return Err("irq_bind failed (no free MSI vector?)");
        }
        self.irq = irq as u64;
        let _ = self.r8(R_CHIPCMD);
        // Transmit on now; reception only through rt_rx_restart (the sequence
        // that makes the card forget a stale receive ring).
        self.w8(R_CHIPCMD, RT_CMD_TX);
        self.set(R_TXCONFIG, RT_TXCFG);
        self.w16(R_INTR_STATUS, 0xFFFF);
        self.w16(R_INTR_MASK, RT_INTS);
        self.rt_rx_restart();
        // PHY: powered up, advertise 10/100/1000 full and 10/100 half,
        // auto-negotiation (re)started.
        let bmcr = self.rt_phy_read(0);
        if bmcr & 0x0800 != 0 {
            self.rt_phy_write(0, bmcr & !0x0800);
            sleep_ms(20);
        }
        self.rt_phy_write(4, 0x01E1);
        self.rt_phy_write(9, 0x0200);
        self.rt_phy_write(0, 0x1200);
        Ok(())
    }

    /// Receive ring from descriptor 0 again, the card told where it is, with
    /// reception off meanwhile.  Needed once after start: the card can keep a
    /// stale idea of the ring from the firmware's driver (frames reported in our
    /// descriptors, their data written elsewhere, reception stuck after one lap).
    fn rt_rx_restart(&mut self) {
        self.w8(R_CHIPCMD, RT_CMD_TX);
        sleep_ms(2);
        for i in 0..RING {
            let eor = if i == RING - 1 { RT_EOR } else { 0 };
            let d = self.rx_desc(i);
            unsafe {
                core::ptr::write_volatile((d + 8) as *mut u64, self.pa + RX_BUF + i as u64 * BUF);
                core::ptr::write_volatile((d + 4) as *mut u32, 0);
                core::ptr::write_volatile(d as *mut u32, RT_OWN | eor | BUF as u32);
            }
        }
        self.rx_next = 0;
        let rx = self.pa + RX_DESC;
        self.w8(R_CFG9346, 0xC0);
        self.set(R_RX_DESC + 4, (rx >> 32) as u32);
        self.set(R_RX_DESC, rx as u32);
        self.w8(R_CFG9346, 0);
        self.w8(R_CHIPCMD, RT_CMD_RX | RT_CMD_TX);
        self.set(R_RXCONFIG, RT_RXCFG);
        self.rx_restarts += 1;
        self.rx_irqs_at_frame = self.rt_causes[0];
    }

    /// The factory address from the chip's internal copy, otherwise what the
    /// firmware left in the receive filter.
    fn rt_read_mac(&mut self) {
        let lo = self.rt_eri_read(0xE0).to_le_bytes();
        let hi = self.rt_eri_read(0xE4).to_le_bytes();
        let m = [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1]];
        let valid = |m: &[u8; 6]| m[0] & 1 == 0 && *m != [0; 6];
        if valid(&m) {
            self.mac = m;
            return;
        }
        let lo = self.reg(R_MAC0).to_le_bytes();
        let hi = self.reg(R_MAC4).to_le_bytes();
        self.mac = [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1]];
    }

    fn rt_poll_rx(&mut self) -> usize {
        let mut n = 0;
        let mut empty = false;
        while n < RING {
            let d = self.rx_desc(self.rx_next);
            let st = unsafe { core::ptr::read_volatile(d as *const u32) };
            if st & RT_OWN != 0 {
                break; // still the card's
            }
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
            let len = (st & 0x3FFF) as usize;
            if st & RT_RX_ERR != 0 || st & (RT_FS | RT_LS) != RT_FS | RT_LS || len < 14 + 4 || len > BUF as usize {
                self.rx_errors += 1;
            } else {
                // The length includes the 4-byte frame checksum.
                let buf = self.va + RX_BUF + self.rx_next as u64 * BUF;
                let frame = unsafe { core::slice::from_raw_parts(buf as *const u8, len - 4) };
                // No real frame has an all-zero header: the data went elsewhere.
                empty |= frame[..14].iter().all(|&b| b == 0);
                self.handle(frame);
            }
            let eor = if self.rx_next == RING - 1 { RT_EOR } else { 0 };
            self.rx_irqs_at_frame = self.rt_causes[0];
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            unsafe {
                // The buffer address again too (in case the card wrote over it).
                core::ptr::write_volatile((d + 8) as *mut u64, self.pa + RX_BUF + self.rx_next as u64 * BUF);
                core::ptr::write_volatile((d + 4) as *mut u32, 0);
                core::ptr::write_volatile(d as *mut u32, RT_OWN | eor | BUF as u32);
            }
            self.rx_next = (self.rx_next + 1) % RING;
            n += 1;
        }
        // The card keeps signalling frames but none reaches the ring: set it up again.
        if empty || (n == 0 && self.rt_causes[0].wrapping_sub(self.rx_irqs_at_frame) >= 8) {
            self.rt_rx_restart();
        }
        n
    }

    fn rt_send(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        let i = self.tx_next;
        let d = self.tx_desc(i);
        if unsafe { core::ptr::read_volatile(d as *const u32) } & RT_OWN != 0 {
            return Err("transmit ring full");
        }
        let buf = self.va + TX_BUF + i as u64 * BUF;
        let len = frame.len().max(60);
        let eor = if i == RING - 1 { RT_EOR } else { 0 };
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), buf as *mut u8, frame.len());
            core::ptr::write_bytes((buf + frame.len() as u64) as *mut u8, 0, len - frame.len());
            core::ptr::write_volatile((d + 4) as *mut u32, 0);
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            core::ptr::write_volatile(d as *mut u32, RT_OWN | eor | RT_FS | RT_LS | len as u32);
        }
        self.tx_next = (i + 1) % RING;
        self.w8(R_TXPOLL, RT_TXPOLL_NORMAL);
        self.tx_frames += 1;
        self.tx_bytes += len as u64;
        Ok(())
    }

    /// Registers for diagnosis (`ifconfig`): chip version, command / interrupt
    /// state, filters, PHY, waits that ran out during start.
    fn rt_regs(&self, out: &mut Text) {
        let _ = writeln!(
            out,
            "  chip {} (version {:03x}); cmd {:02x} int {:04x}/{:04x} rxcfg {:08x} txcfg {:08x} misc {:08x} mcu {:02x} phy {:02x}",
            rt_version(self.xid).unwrap_or("unknown"),
            self.xid,
            self.r8(R_CHIPCMD),
            self.r16(R_INTR_STATUS),
            self.r16(R_INTR_MASK),
            self.reg(R_RXCONFIG),
            self.reg(R_TXCONFIG),
            self.reg(R_MISC),
            self.r8(R_MCU),
            self.r8(R_PHYSTATUS)
        );
        // Rings: descriptors still the card's (rx: free for it to fill; tx: not
        // yet sent), our next positions.
        let own = |base: u64| (0..RING).filter(|&i| unsafe { core::ptr::read_volatile((base + i as u64 * 16) as *const u32) } & RT_OWN != 0).count();
        let _ = write!(
            out,
            "  rings: rx {} of {} free for the card (next {}), tx {} waiting (next {}); last frame ",
            own(self.va + RX_DESC),
            RING,
            self.rx_next,
            own(self.va + TX_DESC),
            self.tx_next
        );
        if self.last_rx_ms == 0 {
            let _ = writeln!(out, "never");
        } else {
            let _ = writeln!(out, "{} ms ago", uptime_ms().saturating_sub(self.last_rx_ms));
        }
        let _ = write!(out, "  causes:");
        for (b, what) in [
            (0, "rx"),
            (1, "rx-err"),
            (2, "tx"),
            (3, "tx-err"),
            (4, "rx-no-desc"),
            (5, "link"),
            (6, "rx-fifo"),
            (7, "tx-no-desc"),
            (8, "sw"),
            (14, "timeout"),
            (15, "sys-err"),
        ] {
            if self.rt_causes[b] > 0 {
                let _ = write!(out, " {}={}", what, self.rt_causes[b]);
            }
        }
        if self.rx_other > 0 {
            let _ = write!(out, "; other frames:");
            for &(t, n) in self.other_types.iter().filter(|e| e.1 > 0) {
                let _ = write!(out, " {:04x}x{}", t, n);
            }
        }
        let _ = writeln!(out, "; DHCP answers ignored {}, acks {}", self.dhcp.ignored, self.dhcp.acks);
        // Where the card thinks the rings are, and the descriptors around our position.
        let desc = |base: u64, i: usize| unsafe {
            let d = base + i as u64 * 16;
            (core::ptr::read_volatile(d as *const u32), core::ptr::read_volatile((d + 4) as *const u32), core::ptr::read_volatile((d + 8) as *const u64))
        };
        let prev = (self.rx_next + RING - 1) % RING;
        let (a1, a2, a3) = desc(self.va + RX_DESC, prev);
        let (b1, b2, b3) = desc(self.va + RX_DESC, self.rx_next);
        let _ = writeln!(
            out,
            "  dma {:x}; card's rings rx {:08x}{:08x} tx {:08x}{:08x}; rx[{}] {:08x} {:08x} {:x}; rx[{}] {:08x} {:08x} {:x}; empty-buffer frames {}; rx restarts {}",
            self.pa,
            self.reg(R_RX_DESC + 4),
            self.reg(R_RX_DESC),
            self.reg(R_TX_DESC + 4),
            self.reg(R_TX_DESC),
            prev,
            a1,
            a2,
            a3,
            self.rx_next,
            b1,
            b2,
            b3,
            self.zero_frames,
            self.rx_restarts
        );
        if self.other_len > 0 {
            let _ = write!(out, "  first other frame ({} bytes):", self.other_len);
            for b in &self.other_dump[..self.other_len.min(32)] {
                let _ = write!(out, " {:02x}", b);
            }
            let _ = writeln!(out);
        }
        if self.notes != 0 {
            let _ = write!(out, "  start: waits that ran out:");
            for (bit, what) in [
                (RT_NOTE_TXCFG, "tx FIFO empty"),
                (RT_NOTE_RXTX, "rx/tx FIFO empty"),
                (RT_NOTE_LLRDY, "link list ready"),
                (RT_NOTE_PHY, "PHY access"),
                (RT_NOTE_ERI, "ERI access"),
                (RT_NOTE_MAC_REG, "MAC register write"),
            ] {
                if self.notes & bit != 0 {
                    let _ = write!(out, " {};", what);
                }
            }
            let _ = writeln!(out);
        }
    }
}

fn main(args: Args) -> i32 {
    let name: &'static str = match args.get(0) {
        Some("net1") => "net1",
        Some("net2") => "net2",
        Some("net3") => "net3",
        _ => "net0",
    };
    let Ok(info) = dev_info(DEV) else {
        println!("{}: no device in slot 3", name);
        return 2;
    };
    let Some(&(_, _, kind, chip)) = CHIPS.iter().find(|c| c.0 == info.vendor && c.1 == info.device) else {
        println!("{}: network card {:04x}:{:04x} has no driver yet - service not started", name, info.vendor, info.device);
        return EXIT_NO_DRIVER;
    };
    // Intel: registers in BAR 0; Realtek: BAR 0 is I/O ports, the registers are
    // the memory BAR 2.
    let bar = if kind == Kind::Realtek { 2 } else { 0 };
    if info.bars[bar] == 0 || info.io_mask & (1 << bar) != 0 {
        println!("{}: BAR{} is not a memory BAR", name, bar);
        return 2;
    }
    let Ok(regs) = dev_map(DEV, bar as u64, PROT_READ | PROT_WRITE) else {
        println!("{}: dev_map BAR{} failed", name, bar);
        return 2;
    };
    if kind == Kind::Realtek {
        // Before DMA is allowed (dma_alloc turns bus mastering on): the card may
        // still hold the firmware's receive ring – stop reception first.
        wr8(regs + R_CHIPCMD, 0);
        wr32(regs + R_RXCONFIG, rd32(regs + R_RXCONFIG) & !0x3F);
    }
    let h = dma_alloc(DEV, DMA_SIZE, 64);
    if h < 0 {
        println!("{}: dma_alloc failed: {}", name, strerror(h));
        return 2;
    }
    let (Ok(pa), Ok(va)) = (dma_phys(h as u64), shm_map(h as u64, PROT_READ | PROT_WRITE)) else {
        println!("{}: cannot map the DMA buffer", name);
        return 2;
    };
    let mut nic = Nic {
        name,
        chip,
        kind,
        xid: 0,
        notes: 0,
        rt_causes: [0; 16],
        last_rx_ms: 0,
        other_types: [(0, 0); 4],
        other_dump: [0; 32],
        other_len: 0,
        zero_frames: 0,
        rx_restarts: 0,
        rx_irqs_at_frame: 0,
        vendor: info.vendor,
        device: info.device,
        regs,
        irq: 0,
        va,
        pa,
        mac: [0; 6],
        rx_next: 0,
        tx_next: 0,
        rx_frames: 0,
        rx_bytes: 0,
        rx_arp: 0,
        rx_ipv4: 0,
        rx_ipv6: 0,
        rx_other: 0,
        rx_errors: 0,
        tx_frames: 0,
        tx_bytes: 0,
        irqs: 0,
        polled: 0,
        rx_bad: 0,
        arp_answered: 0,
        echo_answered: 0,
        ip: [0; 4],
        prefix: 0,
        gw: [0; 4],
        dns: [[0; 4]; 2],
        dns_n: 0,
        dhcp: Client::new([0; 6], 0),
        dhcp_mac: [0; 6],
        dhcp_t0: 0,
        udp_dropped: 0,
        arp_cache: [([0; 4], [0; 6], 0); ARP_CACHE],
        ip_id: 0,
        conns: [NO_CONN; MAX_CONNS],
        nconns: 0,
        dns_cache: dns::Cache::new(),
        dns_set: None,
        dns_queries: 0,
        dns_answers: 0,
        dns_bad: 0,
        rng: 0,
        next_port: 0,
        tcp: [TCP_FREE; TCP_MAX],
        tcp_made: 0,
        tcp_in: 0,
        tcp_out: 0,
        tcp_resets: 0,
        tcp_accepted: 0,
        tcp_last_end: None,
        tcp_last_scale: None,
        tcp_last_peak: 0,
        tcp_dropped: 0,
        tcp_reordered: 0,
        loop_len: [0; LOOPQ],
        loop_head: 0,
        loop_tail: 0,
        loop_frames: 0,
        from_loop: false,
        static_probe: [0; 4],
        static_taken: None,
        static_probe_second: false,
        by_hand: false,
        conflicts: 0,
    };
    if let Err(e) = nic.start() {
        println!("{}: {}", name, e);
        return 2;
    }
    let mut t = Text::new();
    nic.status(&mut t);
    // The first line only (the rest is for `ifconfig`).
    let first = t.as_bytes().split(|&b| b == b'\n').next().unwrap_or(b"");
    write(1, first);
    write(1, b"\n");
    // Ask for an address (DISCOVER now; the rest happens in the loop).
    nic.dhcp = Client::new(nic.mac, uptime_ms() ^ (getpid() << 32));
    nic.rng = (uptime_ms() << 20) ^ getpid() ^ u64::from_be_bytes([0, 0, nic.mac[0], nic.mac[1], nic.mac[2], nic.mac[3], nic.mac[4], nic.mac[5]]) | 1;
    nic.next_port = 49152 + nic.rand16() % 16384;
    nic.dhcp_t0 = uptime_ms();
    nic.dhcp_tick();

    // Event loop: interrupt, connection channel, clients.  Operations advance
    // on frames and on their timers; nothing waits inside a request.
    let mut listening = true;
    let mut msg = [0u8; MSG_MAX];
    let mut info = RecvInfo::default();
    loop {
        if !listening && nic.nconns == 0 && !nic.tcp.iter().any(|m| m.used) {
            // Leaving: the address goes back to the DHCP server (a moment for the
            // card to send it before the DMA buffer goes away).
            if nic.dhcp.lease.is_some() {
                nic.dhcp_release();
                sleep_ms(20);
            }
            return 0;
        }
        let mut list = [(0u64, 0u64); WAIT_MAX];
        // Which connection each wait entry belongs to.
        let mut map = [usize::MAX; WAIT_MAX];
        list[0] = (nic.irq, W_IRQ);
        let mut k = 1;
        if listening {
            list[k] = (LISTEN, W_READABLE);
            k += 1;
        }
        let first = k;
        let waiting = nic.nconns;
        for j in 0..waiting {
            let c = nic.conns[j];
            // A socket: read from the program only when its data fits, wait for
            // room in its channel when received data waits.
            let sig = match c.op {
                Op::Tcp { slot, open: true } => {
                    let t = &tcbs()[slot];
                    (if t.send_space() >= MSG_MAX { W_READABLE } else { 0 }) | (if t.readable() > 0 { W_WRITABLE } else { 0 })
                }
                _ => W_READABLE,
            };
            if sig != 0 {
                list[k] = (c.chan, sig);
                map[k] = j;
                k += 1;
            }
        }
        // At most 1 s without an interrupt (the ring is checked anyway), and no
        // later than the next DHCP, operation or TCP timer.
        let deadline = nic.dhcp.deadline().min(nic.ops_deadline());
        let timeout = if nic.loop_head != nic.loop_tail { 0 } else { deadline.saturating_sub(uptime_ms()).clamp(1, 1000) };
        let ready = wait_many(&list[..k], timeout).unwrap_or(0);
        if ready & 1 != 0 {
            nic.irqs += irq_read(nic.irq).max(0) as u64;
            nic.ack_irq();
            nic.poll_rx();
        } else {
            if nic.kind == Kind::Realtek {
                nic.ack_irq();
            }
            let n = nic.poll_rx();
            nic.polled += n as u64;
        }
        nic.irq_rearm();
        nic.dhcp_tick();
        if listening && ready & 2 != 0 {
            let mut hs = [0u64; 1];
            let r = chan_recv_h(LISTEN, &mut msg, &mut hs, CHAN_NONBLOCK, &mut info);
            if r == EPIPE {
                listening = false;
            } else if r >= 0 && info.handles == 1 {
                if nic.nconns < MAX_CONNS {
                    let kind = kind_of(core::str::from_utf8(&msg[..r as usize]).unwrap_or(""));
                    nic.conns[nic.nconns] = Conn { chan: hs[0], op: Op::Idle, dead: false, kind };
                    nic.nconns += 1;
                } else {
                    // Full: tell the program instead of leaving it waiting.
                    chan_send(hs[0], b"netd: too many programs connected, try again\nping-end\n", CHAN_NONBLOCK);
                    close(hs[0]);
                }
            }
        }
        let now = uptime_ms();
        for e in first..k {
            if ready & (1 << e) == 0 {
                continue;
            }
            let j = map[e];
            if nic.conns[j].dead {
                continue;
            }
            if let Op::Tcp { slot, open: true } = nic.conns[j].op {
                // Socket data from the program (only when it fits).
                if tcbs()[slot].send_space() < MSG_MAX {
                    continue;
                }
                let r = chan_recv(nic.conns[j].chan, &mut msg, CHAN_NONBLOCK, &mut info);
                if r == EPIPE {
                    nic.conns[j].dead = true;
                } else if r > 0 {
                    tcbs()[slot].send(&msg[..r as usize]);
                    nic.tcp_flush(slot, now);
                }
                continue;
            }
            let r = chan_recv(nic.conns[j].chan, &mut msg, CHAN_NONBLOCK, &mut info);
            if r == EPIPE {
                nic.conns[j].dead = true;
                continue;
            }
            if r < 0 {
                continue;
            }
            let req = core::str::from_utf8(&msg[..r as usize]).unwrap_or("").trim();
            if !matches!(nic.conns[j].op, Op::Idle) {
                let mut t = Text::new();
                let _ = writeln!(t, "netd: busy - one request at a time per connection");
                nic.tell(j, &t);
                continue;
            }
            nic.request(j, req, now);
        }
        let now = uptime_ms();
        for j in 0..nic.nconns {
            nic.step(j, now);
        }
        nic.run_loopback();
        nic.tcp_sweep(now);
        nic.run_loopback();
        // Closed clients: their operations end with them.
        let mut j = 0;
        while j < nic.nconns {
            if nic.conns[j].dead {
                nic.tcp_detach(j, now);
                // A listener going away: connections not yet accepted are reset.
                for slot in 0..TCP_MAX {
                    if nic.tcp[slot].used && nic.tcp[slot].listener == j {
                        nic.tcp[slot].listener = NO_OWNER;
                        tcbs()[slot].abort();
                        nic.tcp_flush(slot, now);
                    }
                }
                close(nic.conns[j].chan);
                nic.nconns -= 1;
                nic.conns[j] = nic.conns[nic.nconns];
                nic.conns[nic.nconns] = NO_CONN;
                // The moved connection keeps its TCP block / its accepted connections.
                if let Op::Tcp { slot, .. } = nic.conns[j].op {
                    if nic.tcp[slot].owner == nic.nconns {
                        nic.tcp[slot].owner = j;
                    }
                }
                for m in nic.tcp.iter_mut() {
                    if m.used && m.listener == nic.nconns {
                        m.listener = j;
                    }
                }
            } else {
                j += 1;
            }
        }
    }
}
