// One TCP connection (RFC 9293, both sides) – pure code: no clock, no card, no
// allocation.  The caller (netd) passes received segments and the time in, asks
// for segments to send with `output`, and moves data with `send` / `recv`.
// Tested without a network against a simulated peer: /bin/tcptest (NET TEST).
//
//   SynSent --SYN+ACK--> Established      (we connect: `init_connect`)
//   SynReceived --ACK--> Established      (a SYN to our listening port: `init_accept`)
//   SynSent --SYN+ACK--> Established --close--> FinWait1 --ACK--> FinWait2
//      |                     |                     |FIN            |FIN
//      | RST: refused        |FIN                  v               v
//      | 3 resends: timeout  v                  Closing --ACK--> TimeWait (2 s) -> Closed
//                        CloseWait --close--> LastAck --ACK--> Closed
//
// - Sending: a ring of SND_BUF bytes; segments of at most the peer's MSS, within
//   the peer's window and the congestion window (slow start, congestion
//   avoidance, fast retransmit after 3 duplicate ACKs).  Lost data is sent again
//   from the first unacknowledged byte after the retransmission timeout (RFC 6298:
//   measured RTT, 200 ms – 60 s, doubled on every loss, Karn's rule); 8 timeouts
//   in a row end the connection.  A zero window is probed (persist timer).
// - Receiving: a ring of RCV_BUF bytes; the advertised window is its free space
//   (window scaling, RFC 7323: we offer a shift of WSCALE in our SYN; used only
//   when the peer offers one too – then window fields outside SYN segments are
//   shifted both ways);
//   data that arrives ahead of a gap (a lost segment) is kept in its place in the
//   ring – up to OOO_MAX separate pieces – and the peer gets a duplicate ACK; when
//   the gap is filled the ACK jumps over everything kept.  Every data segment is
//   acknowledged at once.
// - Segments are untrusted: outside the window they are dropped with an ACK; a
//   RST counts only with exactly the next sequence number (anywhere else in the
//   window: a "challenge ACK", RFC 5961), a SYN on an open connection likewise;
//   an ACK for data never sent is dropped.  Challenge ACKs are rate limited.
#![allow(dead_code)]

use crate::netproto::{TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};

pub const SND_BUF: usize = 8192;
/// Receive buffer: the window that keeps a far server sending (1 MiB at 40 ms
/// round trip is about 25 MiB/s).
pub const RCV_BUF: usize = 1024 * 1024;
/// Our window scale shift (65535 << 5 covers RCV_BUF).
pub const WSCALE: u8 = 5;
/// Pieces of data kept ahead of gaps.
pub const OOO_MAX: usize = 8;
/// Our MSS (Ethernet 1500 - 40).
pub const MSS: u16 = 1460;
/// Peer MSS when it sends none (RFC 9293).
const MSS_DEFAULT: u16 = 536;
const MSS_MIN: u16 = 64;
const RTO_INIT_MS: u64 = 1000;
const RTO_MIN_MS: u64 = 200;
const RTO_MAX_MS: u64 = 60_000;
/// SYN resends before "timed out" (1 + 2 + 4 s), data timeouts in a row.
const SYN_TRIES: u8 = 3;
const DATA_TRIES: u8 = 8;
pub const TIME_WAIT_MS: u64 = 2000;
/// FinWait2 without the peer's FIN – give up (the program is gone already).
pub const FIN_WAIT2_MS: u64 = 10_000;
const CHALLENGE_GAP_MS: u64 = 100;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum State {
    SynSent,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
    /// A SYN came to a listening port, our SYN+ACK is out (last – an all-zero
    /// block stays a valid SynSent one).
    SynReceived,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::SynSent => "connecting",
            State::Established => "open",
            State::FinWait1 => "closing (FIN sent)",
            State::FinWait2 => "closing (waiting for FIN)",
            State::CloseWait => "peer closed",
            State::Closing => "closing (both)",
            State::LastAck => "closing (last ACK)",
            State::TimeWait => "time-wait",
            State::Closed => "closed",
            State::SynReceived => "accepting",
        }
    }
}

/// Why a connection ended.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum End {
    None,
    /// Both sides closed normally.
    Normal,
    /// RST answering our SYN – nobody listens on that port.
    Refused,
    /// RST on an open connection.
    Reset,
    /// No answer to our SYN / to our data.
    TimedOut,
    /// We sent a RST (abort).
    Aborted,
}

/// What a received segment changed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Event {
    None,
    Connected,
    /// New data to read, the peer's FIN, or both.
    Data,
    /// The connection is over (see `end`).
    Closed,
}

/// A received segment (from netproto::parse_tcp).
#[derive(Clone, Copy)]
pub struct Seg<'a> {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    /// Window scale option (SYN segments).
    pub wscale: Option<u8>,
    pub data: &'a [u8],
}

/// A segment to send; its data (len bytes) is in the caller's buffer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Out {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub len: usize,
}

fn lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
fn le(a: u32, b: u32) -> bool {
    a == b || lt(a, b)
}

/// The answer to a segment for no connection (RFC 9293 3.10.7.1): nothing for a
/// RST, else a RST that matches it.  (seq, ack, flags).
pub fn reset_for(s: &Seg) -> Option<(u32, u32, u8)> {
    if s.flags & TCP_RST != 0 {
        return None;
    }
    if s.flags & TCP_ACK != 0 {
        return Some((s.ack, 0, TCP_RST));
    }
    let len = s.data.len() as u32 + (s.flags & TCP_SYN != 0) as u32 + (s.flags & TCP_FIN != 0) as u32;
    Some((0, s.seq.wrapping_add(len), TCP_RST | TCP_ACK))
}

pub struct Tcb {
    pub state: State,
    pub end: End,
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    /// Highest sequence number sent so far (snd_nxt goes back on a resend).
    snd_max: u32,
    snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    rcv_nxt: u32,
    /// Peer MSS (bounded).
    pub mss: u16,
    /// Window scaling: the peer's shift (applied to its window fields) and ours
    /// (applied to the window we advertise); both 0 when not agreed.
    snd_shift: u8,
    rcv_shift: u8,
    sbuf: [u8; SND_BUF],
    s_start: usize,
    /// Bytes in the send ring, from snd_una (sent and not yet acknowledged + not sent).
    s_len: usize,
    rbuf: [u8; RCV_BUF],
    r_start: usize,
    r_len: usize,
    /// Data kept ahead of gaps: (first, end) sequence numbers, sorted, not
    /// touching each other or rcv_nxt; the bytes are already in rbuf at their place.
    ooo: [(u32, u32); OOO_MAX],
    ooo_n: usize,
    fin_queued: bool,
    fin_sent: bool,
    fin_acked: bool,
    pub peer_fin: bool,
    // Timers and congestion control.
    rto: u64,
    srtt: u64,
    rttvar: u64,
    rtt_seq: u32,
    rtt_t0: u64,
    rtt_on: bool,
    rexmit_at: u64,
    tries: u8,
    cwnd: u32,
    ssthresh: u32,
    dupacks: u8,
    persist_at: u64,
    persist_wait: u64,
    probe_due: bool,
    timer_end: u64,
    need_ack: bool,
    challenge: bool,
    last_challenge: u64,
    /// A RST to send: (seq, ack, flags) when `rst_due` (no Option – an all-zero
    /// block is valid, so a static table of them costs no space in the program).
    rst_due: bool,
    rst: (u32, u32, u8),
    syn_t0: u64,
    // Counters.
    pub retransmits: u32,
    pub dropped: u32,
    /// Segments kept ahead of a gap.
    pub reordered: u32,
    pub rtt_ms: u64,
}

impl Tcb {
    /// A new connection in this block: the SYN goes out with the first `output`
    /// call.  Set in place (the block holds the buffers – too big for a stack).
    pub fn init_connect(&mut self, iss: u32, now: u64) {
        self.state = State::SynSent;
        self.end = End::None;
        self.iss = iss;
        self.snd_una = iss;
        self.snd_nxt = iss;
        self.snd_max = iss;
        self.snd_wnd = 0;
        self.snd_wl1 = 0;
        self.snd_wl2 = 0;
        self.rcv_nxt = 0;
        self.mss = MSS_DEFAULT;
        self.snd_shift = 0;
        self.rcv_shift = 0;
        self.s_start = 0;
        self.s_len = 0;
        self.r_start = 0;
        self.r_len = 0;
        self.ooo_n = 0;
        self.fin_queued = false;
        self.fin_sent = false;
        self.fin_acked = false;
        self.peer_fin = false;
        self.rto = RTO_INIT_MS;
        self.srtt = 0;
        self.rttvar = 0;
        self.rtt_seq = 0;
        self.rtt_t0 = 0;
        self.rtt_on = false;
        self.rexmit_at = u64::MAX;
        self.tries = 0;
        self.cwnd = 0;
        self.ssthresh = 65535;
        self.dupacks = 0;
        self.persist_at = u64::MAX;
        self.persist_wait = RTO_INIT_MS;
        self.probe_due = false;
        self.timer_end = u64::MAX;
        self.need_ack = false;
        self.challenge = false;
        self.last_challenge = 0;
        self.rst_due = false;
        self.rst = (0, 0, 0);
        self.syn_t0 = now;
        self.retransmits = 0;
        self.dropped = 0;
        self.reordered = 0;
        self.rtt_ms = 0;
    }

    /// A SYN to a listening port: a new connection in SynReceived; our SYN+ACK
    /// goes out with the first `output` call.  (A SYN with data or other flags is
    /// taken only for its sequence number, MSS and window scale – the data comes again.)
    pub fn init_accept(&mut self, iss: u32, now: u64, syn: &Seg) {
        self.init_connect(iss, now);
        self.state = State::SynReceived;
        self.rcv_nxt = syn.seq.wrapping_add(1);
        self.mss = syn.mss.unwrap_or(MSS_DEFAULT).clamp(MSS_MIN, MSS);
        self.snd_wnd = syn.window as u32;
        self.snd_wl1 = syn.seq;
        self.agree_scale(syn);
    }

    /// Window scaling from the peer's SYN / SYN+ACK: on only when it offered it.
    fn agree_scale(&mut self, syn: &Seg) {
        match syn.wscale {
            Some(w) => {
                self.snd_shift = w.min(14);
                self.rcv_shift = WSCALE;
            }
            None => {
                self.snd_shift = 0;
                self.rcv_shift = 0;
            }
        }
    }

    /// The peer's window field of a non-SYN segment, in bytes.
    fn peer_window(&self, s: &Seg) -> u32 {
        (s.window as u32) << self.snd_shift
    }

    /// Window scaling agreed with the peer: its shift (None = not agreed).
    pub fn peer_shift(&self) -> Option<u8> {
        if self.rcv_shift != 0 { Some(self.snd_shift) } else { None }
    }

    pub fn rto(&self) -> u64 {
        self.rto
    }
    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }
    pub fn snd_wnd(&self) -> u32 {
        self.snd_wnd
    }

    fn in_flight(&self) -> u32 {
        self.snd_nxt.wrapping_sub(self.snd_una)
    }

    /// Data bytes sent and not acknowledged (without SYN / FIN).
    fn data_in_flight(&self) -> usize {
        let f = self.in_flight() as usize;
        let f = if matches!(self.state, State::SynSent | State::SynReceived) { 0 } else { f };
        f.min(self.s_len)
    }

    fn rcv_wnd(&self) -> u32 {
        (RCV_BUF - self.r_len) as u32
    }

    fn synchronized(&self) -> bool {
        !matches!(self.state, State::SynSent | State::Closed | State::SynReceived)
    }

    /// Bytes the program may still hand over now.
    pub fn send_space(&self) -> usize {
        match self.state {
            State::Established | State::CloseWait if !self.fin_queued => SND_BUF - self.s_len,
            _ => 0,
        }
    }

    /// Queues data for sending; returns how much was taken.
    pub fn send(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.send_space());
        for (k, &b) in data[..n].iter().enumerate() {
            self.sbuf[(self.s_start + self.s_len + k) % SND_BUF] = b;
        }
        self.s_len += n;
        n
    }

    /// Received bytes waiting for the program.
    pub fn readable(&self) -> usize {
        self.r_len
    }

    /// Copies received data out (without removing it).
    pub fn peek(&self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.r_len);
        for (k, b) in out[..n].iter_mut().enumerate() {
            *b = self.rbuf[(self.r_start + k) % RCV_BUF];
        }
        n
    }

    /// Removes `n` bytes the program has taken; may announce a reopened window.
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.r_len);
        let before = self.rcv_wnd();
        self.r_start = (self.r_start + n) % RCV_BUF;
        self.r_len -= n;
        // Window update when it grows from below one segment to at least one.
        if self.synchronized() && before < self.mss as u32 && self.rcv_wnd() >= self.mss as u32 {
            self.need_ack = true;
        }
    }

    pub fn recv(&mut self, out: &mut [u8]) -> usize {
        let n = self.peek(out);
        self.consume(n);
        n
    }

    /// The program closes: a FIN after the queued data.
    pub fn close(&mut self) {
        match self.state {
            State::SynSent => {
                self.state = State::Closed;
                self.end = End::Aborted;
            }
            State::SynReceived => self.abort(),
            State::Established | State::CloseWait => self.fin_queued = true,
            _ => {}
        }
    }

    /// Ends the connection at once with a RST.
    pub fn abort(&mut self) {
        if (self.synchronized() && self.state != State::TimeWait) || self.state == State::SynReceived {
            self.rst_due = true;
            self.rst = (self.snd_nxt, 0, TCP_RST);
        }
        self.state = State::Closed;
        if self.end == End::None {
            self.end = End::Aborted;
        }
    }

    /// The earliest time `tick` has work (u64::MAX = none).
    pub fn deadline(&self) -> u64 {
        self.rexmit_at.min(self.persist_at).min(self.timer_end)
    }

    fn arm_rexmit(&mut self, now: u64) {
        self.rexmit_at = now + self.rto;
    }

    /// Timers: retransmission, zero-window probe, TIME-WAIT / FIN-WAIT-2 end.
    pub fn tick(&mut self, now: u64) {
        if now >= self.timer_end {
            self.timer_end = u64::MAX;
            if matches!(self.state, State::TimeWait | State::FinWait2) {
                self.state = State::Closed;
                if self.end == End::None {
                    self.end = End::Normal;
                }
            }
        }
        if self.state == State::Closed {
            self.rexmit_at = u64::MAX;
            self.persist_at = u64::MAX;
            return;
        }
        if now >= self.rexmit_at {
            self.tries += 1;
            let limit = if matches!(self.state, State::SynSent | State::SynReceived) { SYN_TRIES } else { DATA_TRIES };
            if self.tries > limit {
                self.state = State::Closed;
                self.end = End::TimedOut;
                self.rexmit_at = u64::MAX;
                return;
            }
            self.rto = (self.rto * 2).min(RTO_MAX_MS);
            let flight = self.data_in_flight() as u32;
            self.ssthresh = (flight / 2).max(2 * self.mss as u32);
            self.cwnd = self.mss as u32;
            // Go back to the first unacknowledged byte.
            self.snd_nxt = self.snd_una;
            if self.fin_sent && !self.fin_acked {
                self.fin_sent = false;
            }
            self.rtt_on = false;
            self.dupacks = 0;
            self.retransmits += 1;
            self.arm_rexmit(now);
        }
        if now >= self.persist_at {
            self.probe_due = true;
            self.persist_wait = (self.persist_wait * 2).min(RTO_MAX_MS);
            self.persist_at = now + self.persist_wait;
        }
    }

    /// The next segment to send (call until None).  Its data is copied into `buf`.
    pub fn output(&mut self, now: u64, buf: &mut [u8]) -> Option<Out> {
        if self.rst_due {
            self.rst_due = false;
            let (seq, ack, flags) = self.rst;
            return Some(Out { seq, ack, flags, window: 0, mss: None, wscale: None, len: 0 });
        }
        let window = (self.rcv_wnd() >> self.rcv_shift).min(65535) as u16;
        // The window in a SYN is never scaled.
        let syn_window = self.rcv_wnd().min(65535) as u16;
        match self.state {
            State::Closed => return None,
            State::SynSent => {
                if self.snd_nxt == self.iss {
                    self.snd_nxt = self.iss.wrapping_add(1);
                    self.snd_max = self.snd_nxt;
                    if self.rexmit_at == u64::MAX {
                        self.arm_rexmit(now);
                    }
                    if self.tries == 0 {
                        self.syn_t0 = now;
                    }
                    return Some(Out { seq: self.iss, ack: 0, flags: TCP_SYN, window: syn_window, mss: Some(MSS), wscale: Some(WSCALE), len: 0 });
                }
                return None;
            }
            State::SynReceived => {
                if self.snd_nxt == self.iss {
                    self.snd_nxt = self.iss.wrapping_add(1);
                    self.snd_max = self.snd_nxt;
                    if self.rexmit_at == u64::MAX {
                        self.arm_rexmit(now);
                    }
                    if self.tries == 0 {
                        self.syn_t0 = now;
                    }
                    let wscale = if self.rcv_shift != 0 { Some(WSCALE) } else { None };
                    return Some(Out { seq: self.iss, ack: self.rcv_nxt, flags: TCP_SYN | TCP_ACK, window: syn_window, mss: Some(MSS), wscale, len: 0 });
                }
                let challenge = self.challenge && now.saturating_sub(self.last_challenge) >= CHALLENGE_GAP_MS;
                self.challenge = false;
                if challenge {
                    self.last_challenge = now;
                    return Some(Out { seq: self.snd_nxt, ack: self.rcv_nxt, flags: TCP_ACK, window, mss: None, wscale: None, len: 0 });
                }
                return None;
            }
            _ => {}
        }
        let ack = self.rcv_nxt;
        let can_data = matches!(self.state, State::Established | State::CloseWait | State::FinWait1 | State::LastAck | State::Closing);
        let sent = self.in_flight() as usize;
        let unsent = self.s_len.saturating_sub(sent.min(self.s_len));
        // Zero-window probe: one byte at snd_una, outside the window.
        if self.probe_due {
            self.probe_due = false;
            if can_data && self.s_len > 0 && self.snd_wnd == 0 {
                buf[0] = self.sbuf[self.s_start];
                return Some(Out { seq: self.snd_una, ack, flags: TCP_ACK, window, mss: None, wscale: None, len: 1 });
            }
        }
        if can_data && unsent > 0 && sent <= self.s_len {
            let wnd = self.snd_wnd.min(self.cwnd.max(self.mss as u32)) as usize;
            let room = wnd.saturating_sub(sent);
            let len = unsent.min(room).min(self.mss as usize).min(buf.len());
            if len > 0 {
                for (k, b) in buf[..len].iter_mut().enumerate() {
                    *b = self.sbuf[(self.s_start + sent + k) % SND_BUF];
                }
                let seq = self.snd_nxt;
                self.snd_nxt = self.snd_nxt.wrapping_add(len as u32);
                if lt(self.snd_max, self.snd_nxt) {
                    self.snd_max = self.snd_nxt;
                }
                if self.rexmit_at == u64::MAX {
                    self.arm_rexmit(now);
                }
                if !self.rtt_on && self.tries == 0 {
                    self.rtt_on = true;
                    self.rtt_seq = self.snd_nxt;
                    self.rtt_t0 = now;
                }
                self.need_ack = false;
                self.challenge = false;
                let psh = if len == unsent { TCP_PSH } else { 0 };
                return Some(Out { seq, ack, flags: TCP_ACK | psh, window, mss: None, wscale: None, len });
            }
            // Window closed with data waiting: start probing.
            if self.snd_wnd == 0 && sent == 0 && self.persist_at == u64::MAX {
                self.persist_at = now + self.persist_wait;
            }
        }
        // FIN after all data.
        if self.fin_queued && !self.fin_sent && sent >= self.s_len && can_data {
            let seq = self.snd_nxt;
            self.fin_sent = true;
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            if lt(self.snd_max, self.snd_nxt) {
                self.snd_max = self.snd_nxt;
            }
            if self.state == State::Established {
                self.state = State::FinWait1;
            } else if self.state == State::CloseWait {
                self.state = State::LastAck;
            }
            if self.rexmit_at == u64::MAX {
                self.arm_rexmit(now);
            }
            self.need_ack = false;
            self.challenge = false;
            return Some(Out { seq, ack, flags: TCP_FIN | TCP_ACK, window, mss: None, wscale: None, len: 0 });
        }
        let challenge = self.challenge && now.saturating_sub(self.last_challenge) >= CHALLENGE_GAP_MS;
        self.challenge = false;
        if self.need_ack || challenge {
            if challenge {
                self.last_challenge = now;
            }
            self.need_ack = false;
            return Some(Out { seq: self.snd_nxt, ack, flags: TCP_ACK, window, mss: None, wscale: None, len: 0 });
        }
        None
    }

    fn rtt_sample(&mut self, ms: u64) {
        self.rtt_ms = ms;
        if self.srtt == 0 {
            self.srtt = ms.max(1);
            self.rttvar = ms / 2;
        } else {
            let d = self.srtt.abs_diff(ms);
            self.rttvar = (3 * self.rttvar + d) / 4;
            self.srtt = (7 * self.srtt + ms) / 8;
        }
        self.rto = (self.srtt + (4 * self.rttvar).max(10)).clamp(RTO_MIN_MS, RTO_MAX_MS);
    }

    /// A segment for this connection.
    pub fn on_segment(&mut self, now: u64, s: &Seg) -> Event {
        match self.state {
            State::Closed => Event::None,
            State::SynSent => self.on_syn_sent(now, s),
            State::SynReceived => self.on_syn_received(now, s),
            _ => self.on_open(now, s),
        }
    }

    fn on_syn_sent(&mut self, now: u64, s: &Seg) -> Event {
        let syn_ack = self.iss.wrapping_add(1);
        if s.flags & TCP_ACK != 0 && s.ack != syn_ack {
            // Not an answer to our SYN.
            if s.flags & TCP_RST == 0 {
                self.rst_due = true;
                self.rst = (s.ack, 0, TCP_RST);
            }
            self.dropped += 1;
            return Event::None;
        }
        if s.flags & TCP_RST != 0 {
            if s.flags & TCP_ACK != 0 {
                self.state = State::Closed;
                self.end = End::Refused;
                self.rexmit_at = u64::MAX;
                return Event::Closed;
            }
            self.dropped += 1;
            return Event::None;
        }
        if s.flags & TCP_SYN == 0 || s.flags & TCP_ACK == 0 {
            // A plain SYN (simultaneous open) or junk – not supported.
            self.dropped += 1;
            return Event::None;
        }
        self.rcv_nxt = s.seq.wrapping_add(1);
        self.snd_una = syn_ack;
        self.snd_nxt = syn_ack;
        self.snd_max = syn_ack;
        self.mss = s.mss.unwrap_or(MSS_DEFAULT).clamp(MSS_MIN, MSS);
        self.agree_scale(s);
        // The SYN+ACK's own window is not scaled.
        self.snd_wnd = s.window as u32;
        self.snd_wl1 = s.seq;
        self.snd_wl2 = s.ack;
        self.state = State::Established;
        self.rexmit_at = u64::MAX;
        if self.tries == 0 {
            self.rtt_sample(now.saturating_sub(self.syn_t0));
        }
        self.tries = 0;
        // Initial window (RFC 3390).
        let m = self.mss as u32;
        self.cwnd = (4 * m).min((2 * m).max(4380));
        self.need_ack = true;
        Event::Connected
    }

    fn on_syn_received(&mut self, now: u64, s: &Seg) -> Event {
        let len = s.data.len() as u32 + (s.flags & TCP_SYN != 0) as u32 + (s.flags & TCP_FIN != 0) as u32;
        // The peer's SYN again (our SYN+ACK was lost): send it again.
        if s.flags & TCP_SYN != 0 && s.flags & TCP_ACK == 0 && s.seq.wrapping_add(1) == self.rcv_nxt {
            self.snd_nxt = self.iss;
            return Event::None;
        }
        if !self.acceptable(s, len) {
            if s.flags & TCP_RST == 0 {
                self.challenge = true;
            }
            self.dropped += 1;
            return Event::None;
        }
        if s.flags & TCP_RST != 0 {
            // The peer gave up (RFC 9293: back to LISTEN – here the block is freed).
            self.state = State::Closed;
            self.end = End::Reset;
            self.rexmit_at = u64::MAX;
            return Event::Closed;
        }
        if s.flags & TCP_SYN != 0 {
            self.challenge = true;
            self.dropped += 1;
            return Event::None;
        }
        if s.flags & TCP_ACK == 0 {
            self.dropped += 1;
            return Event::None;
        }
        let syn_ack = self.iss.wrapping_add(1);
        if s.ack != syn_ack {
            // Acknowledges something we never sent – a RST for that ACK.
            self.rst_due = true;
            self.rst = (s.ack, 0, TCP_RST);
            self.dropped += 1;
            return Event::None;
        }
        self.snd_una = syn_ack;
        self.snd_nxt = syn_ack;
        self.snd_max = syn_ack;
        self.snd_wnd = self.peer_window(s);
        self.snd_wl1 = s.seq;
        self.snd_wl2 = s.ack;
        self.state = State::Established;
        self.rexmit_at = u64::MAX;
        if self.tries == 0 {
            self.rtt_sample(now.saturating_sub(self.syn_t0));
        }
        self.tries = 0;
        let m = self.mss as u32;
        self.cwnd = (4 * m).min((2 * m).max(4380));
        // Data or a FIN may ride on the ACK.
        if !s.data.is_empty() || s.flags & TCP_FIN != 0 {
            self.on_open(now, s);
        }
        Event::Connected
    }

    /// Data at `seq` ahead of rcv_nxt: copied into its place in the ring (only the
    /// part inside the window) and recorded.  False when nothing could be kept
    /// (outside the window, or no free record and it touches no kept piece).
    fn keep_ahead(&mut self, seq: u32, data: &[u8]) -> bool {
        let off = seq.wrapping_sub(self.rcv_nxt) as usize;
        let room = RCV_BUF - self.r_len;
        if off >= room {
            return false;
        }
        let len = data.len().min(room - off);
        if len == 0 {
            return false;
        }
        let (a, b) = (seq, seq.wrapping_add(len as u32));
        // Merge with every kept piece it overlaps or touches.
        let (mut lo, mut hi) = (a, b);
        let mut keep = [(0u32, 0u32); OOO_MAX];
        let mut n = 0;
        for &(x, y) in &self.ooo[..self.ooo_n] {
            if le(x, hi) && le(lo, y) {
                if lt(x, lo) {
                    lo = x;
                }
                if lt(hi, y) {
                    hi = y;
                }
            } else {
                keep[n] = (x, y);
                n += 1;
            }
        }
        if n == OOO_MAX {
            return false;
        }
        let base = self.r_start + self.r_len + off;
        for (k, &v) in data[..len].iter().enumerate() {
            self.rbuf[(base + k) % RCV_BUF] = v;
        }
        // Insert sorted.
        let mut i = n;
        while i > 0 && lt(lo, keep[i - 1].0) {
            keep[i] = keep[i - 1];
            i -= 1;
        }
        keep[i] = (lo, hi);
        self.ooo = keep;
        self.ooo_n = n + 1;
        true
    }

    /// rcv_nxt moved: kept pieces it reached become readable.
    fn join_kept(&mut self) {
        while self.ooo_n > 0 && le(self.ooo[0].0, self.rcv_nxt) {
            let end = self.ooo[0].1;
            if lt(self.rcv_nxt, end) {
                let extra = end.wrapping_sub(self.rcv_nxt) as usize;
                self.r_len += extra;
                self.rcv_nxt = end;
            }
            self.ooo.copy_within(1..self.ooo_n, 0);
            self.ooo_n -= 1;
        }
    }

    fn acceptable(&self, s: &Seg, len: u32) -> bool {
        let wnd = self.rcv_wnd();
        let in_wnd = |x: u32| le(self.rcv_nxt, x) && lt(x, self.rcv_nxt.wrapping_add(wnd));
        match (len, wnd) {
            (0, 0) => s.seq == self.rcv_nxt,
            (0, _) => in_wnd(s.seq),
            (_, 0) => false,
            _ => in_wnd(s.seq) || in_wnd(s.seq.wrapping_add(len - 1)),
        }
    }

    fn on_open(&mut self, now: u64, s: &Seg) -> Event {
        let len = s.data.len() as u32 + (s.flags & TCP_SYN != 0) as u32 + (s.flags & TCP_FIN != 0) as u32;
        if !self.acceptable(s, len) {
            // Old duplicate or beyond the window: tell the peer where we are.
            if s.flags & TCP_RST == 0 {
                self.challenge = true;
            }
            self.dropped += 1;
            return Event::None;
        }
        if s.flags & TCP_RST != 0 {
            if s.seq == self.rcv_nxt {
                let was_tw = self.state == State::TimeWait;
                self.state = State::Closed;
                self.end = if was_tw { End::Normal } else { End::Reset };
                self.rexmit_at = u64::MAX;
                self.timer_end = u64::MAX;
                return Event::Closed;
            }
            self.challenge = true;
            self.dropped += 1;
            return Event::None;
        }
        if s.flags & TCP_SYN != 0 {
            self.challenge = true;
            self.dropped += 1;
            return Event::None;
        }
        if s.flags & TCP_ACK == 0 {
            self.dropped += 1;
            return Event::None;
        }
        // --- ACK ---
        if lt(self.snd_max, s.ack) {
            // Acknowledges data never sent.
            self.challenge = true;
            self.dropped += 1;
            return Event::None;
        }
        let mut ev = Event::None;
        if lt(self.snd_una, s.ack) {
            let acked = s.ack.wrapping_sub(self.snd_una) as usize;
            let data = acked.min(self.s_len);
            self.s_start = (self.s_start + data) % SND_BUF;
            self.s_len -= data;
            self.snd_una = s.ack;
            if lt(self.snd_nxt, self.snd_una) {
                self.snd_nxt = self.snd_una;
            }
            if self.fin_sent && s.ack == self.snd_max && acked > data {
                self.fin_acked = true;
            }
            if self.rtt_on && le(self.rtt_seq, s.ack) {
                self.rtt_on = false;
                self.rtt_sample(now.saturating_sub(self.rtt_t0));
            }
            self.tries = 0;
            self.dupacks = 0;
            self.rexmit_at = if self.snd_una == self.snd_max { u64::MAX } else { now + self.rto };
            let m = self.mss as u32;
            self.cwnd = if self.cwnd < self.ssthresh { self.cwnd + m } else { self.cwnd + (m * m / self.cwnd.max(1)).max(1) };
        } else if s.ack == self.snd_una && s.data.is_empty() && s.flags & TCP_FIN == 0 && self.peer_window(s) == self.snd_wnd && self.snd_una != self.snd_max {
            self.dupacks = self.dupacks.saturating_add(1);
            if self.dupacks == 3 {
                // Fast retransmit.
                let flight = self.data_in_flight() as u32;
                self.ssthresh = (flight / 2).max(2 * self.mss as u32);
                self.cwnd = self.ssthresh;
                self.snd_nxt = self.snd_una;
                if self.fin_sent && !self.fin_acked {
                    self.fin_sent = false;
                }
                self.rtt_on = false;
                self.retransmits += 1;
            }
        }
        // Window update (only from newer segments).
        if lt(self.snd_wl1, s.seq) || (self.snd_wl1 == s.seq && le(self.snd_wl2, s.ack)) {
            self.snd_wnd = self.peer_window(s);
            self.snd_wl1 = s.seq;
            self.snd_wl2 = s.ack;
            if self.snd_wnd > 0 {
                self.persist_at = u64::MAX;
                self.persist_wait = self.rto;
            }
        }
        if self.fin_acked {
            match self.state {
                State::FinWait1 => {
                    self.state = State::FinWait2;
                    self.timer_end = now + FIN_WAIT2_MS;
                }
                State::Closing => {
                    self.state = State::TimeWait;
                    self.timer_end = now + TIME_WAIT_MS;
                }
                State::LastAck => {
                    self.state = State::Closed;
                    self.end = End::Normal;
                    self.rexmit_at = u64::MAX;
                    return Event::Closed;
                }
                _ => {}
            }
        }
        // --- data and FIN ---
        let mut data = s.data;
        let mut seq = s.seq;
        let receiving = matches!(self.state, State::Established | State::FinWait1 | State::FinWait2);
        if receiving && !data.is_empty() {
            if lt(seq, self.rcv_nxt) {
                let skip = self.rcv_nxt.wrapping_sub(seq) as usize;
                data = if skip < data.len() { &data[skip..] } else { &[] };
                seq = self.rcv_nxt;
            }
            if seq != self.rcv_nxt {
                // Ahead of a gap: keep it in its place; a duplicate ACK says where
                // the gap starts (the peer sends that part again).
                self.need_ack = true;
                if self.keep_ahead(seq, data) {
                    self.reordered += 1;
                } else {
                    self.dropped += 1;
                }
                return ev;
            }
            let take = data.len().min(RCV_BUF - self.r_len);
            for (k, &b) in data[..take].iter().enumerate() {
                self.rbuf[(self.r_start + self.r_len + k) % RCV_BUF] = b;
            }
            self.r_len += take;
            self.rcv_nxt = self.rcv_nxt.wrapping_add(take as u32);
            self.need_ack = true;
            if take > 0 {
                ev = Event::Data;
                self.join_kept();
            }
            if take < data.len() {
                // Beyond the window: the rest (and a FIN after it) comes again.
                return ev;
            }
            if self.ooo_n > 0 {
                // A gap remains after this data: a FIN on it comes again too.
                return ev;
            }
        }
        if s.flags & TCP_FIN != 0 {
            let fin_seq = s.seq.wrapping_add(s.data.len() as u32);
            if self.state == State::TimeWait {
                self.need_ack = true;
                self.timer_end = now + TIME_WAIT_MS;
            } else if fin_seq == self.rcv_nxt && !self.peer_fin && receiving {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                self.peer_fin = true;
                self.need_ack = true;
                ev = Event::Data;
                match self.state {
                    State::Established => self.state = State::CloseWait,
                    State::FinWait1 => {
                        if self.fin_acked {
                            self.state = State::TimeWait;
                            self.timer_end = now + TIME_WAIT_MS;
                        } else {
                            self.state = State::Closing;
                        }
                    }
                    State::FinWait2 => {
                        self.state = State::TimeWait;
                        self.timer_end = now + TIME_WAIT_MS;
                    }
                    _ => {}
                }
            } else if self.peer_fin {
                // A resent FIN: acknowledge again.
                self.need_ack = true;
            }
        }
        ev
    }
}
