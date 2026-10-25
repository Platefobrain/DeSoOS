// TCP connection test without a network (NET TEST 4/6).  The state machine
// (user/lib/tcp.rs) talks to a simulated peer with a simulated clock: handshake,
// refused / timed-out connections, sending within the peer's window and the
// congestion window, retransmission and its timer, fast retransmit, zero-window
// probes, receiving in order / out of order / overlapping, a full receive buffer,
// all closing paths, sequence numbers wrapping around, hostile segments (outside
// the window, RST and SYN attacks, ACKs for unsent data), the server side (a
// SYN to a listening port) and 20 000 random segments.  Result: "tcptest: N checks OK" and code 0.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../lib/netproto.rs"]
mod netproto;
#[path = "../lib/tcp.rs"]
mod tcp;

use desoos::*;
use netproto::{TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};
use tcp::{reset_for, End, Event, Out, Seg, State, Tcb, FIN_WAIT2_MS, MSS, RCV_BUF, TIME_WAIT_MS, WSCALE};

entry!(main);

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("tcptest: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

const ISS: u32 = 1000;
const IRS: u32 = 50_000;

// All-zero is a valid (unused) block.
static mut BLOCK: Tcb = unsafe { core::mem::MaybeUninit::zeroed().assume_init() };

fn tcb() -> &'static mut Tcb {
    unsafe { &mut *core::ptr::addr_of_mut!(BLOCK) }
}

fn seg(seq: u32, ack: u32, flags: u8, window: u16, data: &[u8]) -> Seg<'_> {
    Seg { seq, ack, flags, window, mss: None, wscale: None, data }
}

/// Everything the connection sends now: up to 16 segments (their data in `d`).
struct Sent {
    o: [Out; 16],
    d: [[u8; 1460]; 16],
    n: usize,
}

static mut SENT: Sent = Sent { o: [Out { seq: 0, ack: 0, flags: 0, window: 0, mss: None, wscale: None, len: 0 }; 16], d: [[0; 1460]; 16], n: 0 };

fn drain(t: &mut Tcb, now: u64) -> &'static Sent {
    let s = unsafe { &mut *core::ptr::addr_of_mut!(SENT) };
    s.n = 0;
    while s.n < 16 {
        let Some(o) = t.output(now, &mut s.d[s.n]) else { break };
        s.o[s.n] = o;
        s.n += 1;
    }
    s
}

/// A connection in Established: peer window `wnd`, peer MSS `mss`, at time `t0`.
fn open(iss: u32, wnd: u16, mss: u16, t0: u64) -> &'static mut Tcb {
    let t = tcb();
    t.init_connect(iss, t0);
    drain(t, t0);
    let mut s = seg(IRS, iss.wrapping_add(1), TCP_SYN | TCP_ACK, wnd, &[]);
    s.mss = Some(mss);
    t.on_segment(t0 + 10, &s);
    drain(t, t0 + 10);
    t
}

fn pattern(i: usize) -> u8 {
    (i * 7 + i / 251) as u8
}

fn main(_args: Args) -> i32 {
    let mut n = 0;
    let t0 = 100_000u64;

    // 1. SYN: our MSS, our window, the timer.
    let t = tcb();
    t.init_connect(ISS, t0);
    let s = drain(t, t0);
    check!(n, s.n == 1 && s.o[0] == Out { seq: ISS, ack: 0, flags: TCP_SYN, window: 65535, mss: Some(MSS), wscale: Some(WSCALE), len: 0 }, "SYN {:?}", &s.o[..s.n]);
    check!(n, t.deadline() == t0 + 1000 && t.state == State::SynSent, "SYN timer {}", t.deadline());

    // 2. Answers that are not for our SYN.
    t.on_segment(t0 + 5, &seg(IRS, ISS + 7, TCP_SYN | TCP_ACK, 4000, &[]));
    let s = drain(t, t0 + 5);
    check!(n, s.n == 1 && s.o[0].flags == TCP_RST && s.o[0].seq == ISS + 7 && t.state == State::SynSent, "wrong ACK must get a RST: {:?}", &s.o[..s.n]);
    t.on_segment(t0 + 6, &seg(IRS, 0, TCP_RST, 0, &[]));
    t.on_segment(t0 + 6, &seg(IRS, ISS + 9, TCP_RST | TCP_ACK, 0, &[]));
    check!(n, t.state == State::SynSent && drain(t, t0 + 6).n == 0, "a RST without our ACK must be ignored");

    // 3. No answer: SYN again after 1, 2, 4, 8 s, then "timed out".
    let mut at = [0u64; 4];
    for a in at.iter_mut() {
        let d = t.deadline();
        t.tick(d);
        *a = (d - t0) / 1000;
        if t.state == State::SynSent {
            let s = drain(t, d);
            if s.n != 1 || s.o[0].flags != TCP_SYN || s.o[0].seq != ISS {
                println!("tcptest: FAIL: SYN resend {:?}", &s.o[..s.n]);
                return 1;
            }
        }
    }
    check!(n, at == [1, 3, 7, 15] && t.state == State::Closed && t.end == End::TimedOut, "SYN resends at {:?} s, then {:?}/{:?}", at, t.state, t.end);

    // 4. Refused: RST + ACK for our SYN.
    t.init_connect(ISS, t0);
    drain(t, t0);
    check!(n, t.on_segment(t0 + 3, &seg(0, ISS + 1, TCP_RST | TCP_ACK, 0, &[])) == Event::Closed && t.end == End::Refused, "refused: {:?}", t.end);

    // 5. Handshake: the peer's MSS and window, our ACK, an RTT sample.
    t.init_connect(ISS, t0);
    drain(t, t0);
    let mut sa = seg(IRS, ISS + 1, TCP_SYN | TCP_ACK, 4000, &[]);
    sa.mss = Some(1000);
    check!(n, t.on_segment(t0 + 40, &sa) == Event::Connected && t.state == State::Established, "SYN+ACK: {:?}", t.state);
    let s = drain(t, t0 + 40);
    check!(n, s.n == 1 && s.o[0].flags == TCP_ACK && s.o[0].seq == ISS + 1 && s.o[0].ack == IRS + 1, "ACK of the SYN+ACK {:?}", &s.o[..s.n]);
    check!(n, t.mss == 1000 && t.snd_wnd() == 4000 && t.rtt_ms == 40 && t.cwnd() == 4000, "mss {} wnd {} rtt {} cwnd {}", t.mss, t.snd_wnd(), t.rtt_ms, t.cwnd());
    let t2 = open(ISS, 4000, 9000, t0);
    check!(n, t2.mss == MSS, "peer MSS above ours must be cut to {}: {}", MSS, t2.mss);

    // 6. Sending: MSS-sized segments, no more than the window.
    let t = open(ISS, 4000, 1000, t0);
    let mut data = [0u8; 8192];
    for (i, b) in data.iter_mut().enumerate() {
        *b = pattern(i);
    }
    check!(n, t.send(&data[..5000]) == 5000, "send 5000");
    let s = drain(t, t0 + 20);
    let seqs: [u32; 4] = core::array::from_fn(|i| s.o[i].seq);
    check!(n, s.n == 4 && seqs == [ISS + 1, ISS + 1001, ISS + 2001, ISS + 3001] && s.o[..4].iter().all(|o| o.len == 1000 && o.flags == TCP_ACK), "window 4000: {:?}", &s.o[..s.n]);
    check!(n, (0..1000).all(|i| s.d[2][i] == pattern(2000 + i)), "segment data");
    // ACK 2000: the last 1000 bytes go out, with PSH.
    t.on_segment(t0 + 60, &seg(IRS + 1, ISS + 2001, TCP_ACK, 4000, &[]));
    let s = drain(t, t0 + 60);
    check!(n, s.n == 1 && s.o[0].seq == ISS + 4001 && s.o[0].len == 1000 && s.o[0].flags == TCP_ACK | TCP_PSH, "after ACK: {:?}", &s.o[..s.n]);
    check!(n, t.rtt_ms == 40 && t.rto() >= 200, "RTT {} ms, RTO {} ms", t.rtt_ms, t.rto());

    // 7. Loss: after the RTO everything from the first unacknowledged byte again.
    let rto = t.rto();
    let d = t.deadline();
    check!(n, d == t0 + 60 + rto, "retransmission timer at {} (rto {})", d, rto);
    t.tick(d);
    let s = drain(t, d);
    check!(n, s.n >= 1 && s.o[0].seq == ISS + 2001 && t.retransmits == 1 && t.rto() == 2 * rto && t.cwnd() == 1000, "resend: {:?} rto {} cwnd {}", &s.o[..s.n], t.rto(), t.cwnd());
    t.on_segment(d + 30, &seg(IRS + 1, ISS + 5001, TCP_ACK, 4000, &[]));
    check!(n, t.deadline() == u64::MAX && drain(t, d + 30).n == 0, "all acknowledged: timer off");

    // 8. Hostile segments on an open connection.
    let t = open(ISS, 4000, 1000, t0);
    let now = t0 + 1000;
    t.on_segment(now, &seg(IRS + 1 + 1_000_000, ISS + 1, TCP_ACK, 4000, b"far away"));
    let s = drain(t, now);
    check!(n, s.n == 1 && s.o[0].ack == IRS + 1 && t.readable() == 0, "data outside the window: ACK, not taken {:?}", &s.o[..s.n]);
    t.on_segment(now + 10, &seg(IRS + 1 + 1_000_000, ISS + 1, TCP_ACK, 4000, b"far away"));
    check!(n, drain(t, now + 10).n == 0, "challenge ACKs must be rate limited");
    t.on_segment(now + 200, &seg(IRS + 1 + 50, ISS + 1, TCP_RST, 0, &[]));
    let s = drain(t, now + 200);
    check!(n, t.state == State::Established && s.n == 1 && s.o[0].flags == TCP_ACK, "RST inside the window but not exact: challenge ACK, still open");
    t.on_segment(now + 400, &seg(IRS + 1, ISS + 1, TCP_SYN, 4000, &[]));
    let s = drain(t, now + 400);
    check!(n, t.state == State::Established && s.n == 1 && s.o[0].flags == TCP_ACK, "SYN on an open connection: challenge ACK");
    t.on_segment(now + 600, &seg(IRS + 1, ISS + 1 + 5000, TCP_ACK, 4000, &[]));
    check!(n, t.state == State::Established && drain(t, now + 600).n == 1, "ACK for data never sent: dropped, ACK sent");
    t.on_segment(now + 700, &seg(IRS + 1 + 9000, ISS + 1, TCP_RST, 0, &[]));
    check!(n, t.state == State::Established, "RST outside the window must be ignored");
    t.on_segment(now + 800, &seg(IRS + 1, ISS + 1, 0, 4000, b"no ack flag"));
    check!(n, t.readable() == 0, "segment without ACK must be dropped");
    check!(n, t.on_segment(now + 900, &seg(IRS + 1, ISS + 1, TCP_RST, 0, &[])) == Event::Closed && t.end == End::Reset, "exact RST: reset");

    // 9. Receiving: in order, out of order, overlapping, a FIN.
    let t = open(ISS, 4000, 1000, t0);
    let now = t0 + 100;
    let mut rx = [0u8; 4000];
    for (i, b) in rx.iter_mut().enumerate() {
        *b = pattern(i);
    }
    check!(n, t.on_segment(now, &seg(IRS + 1, ISS + 1, TCP_ACK, 4000, &rx[..1000])) == Event::Data && t.readable() == 1000, "in-order data");
    let s = drain(t, now);
    check!(n, s.n == 1 && s.o[0].ack == IRS + 1001 && s.o[0].window as usize == (RCV_BUF - 1000).min(65535), "ACK with the smaller window {:?}", &s.o[..s.n]);
    t.on_segment(now, &seg(IRS + 2001, ISS + 1, TCP_ACK, 4000, &rx[2000..3000]));
    let s = drain(t, now);
    check!(n, t.readable() == 1000 && s.n == 1 && s.o[0].ack == IRS + 1001, "out of order: dropped, duplicate ACK {:?}", &s.o[..s.n]);
    t.on_segment(now, &seg(IRS + 501, ISS + 1, TCP_ACK, 4000, &rx[500..2000]));
    check!(n, t.readable() == 2000, "overlap: only the new 1000 bytes, have {}", t.readable());
    let mut got = [0u8; 2000];
    let k = t.recv(&mut got);
    check!(n, k == 2000 && (0..2000).all(|i| got[i] == pattern(i)), "received bytes in order");
    t.on_segment(now, &seg(IRS + 2001, ISS + 1, TCP_ACK | TCP_FIN, 4000, &rx[2000..2500]));
    let s = drain(t, now);
    check!(n, t.state == State::CloseWait && t.peer_fin && t.readable() == 500 && s.o[0].ack == IRS + 2502, "data + FIN: {:?} ack {}", t.state, s.o[0].ack);
    t.on_segment(now, &seg(IRS + 2502, ISS + 1, TCP_ACK, 4000, b"after FIN"));
    check!(n, t.readable() == 500, "data after the FIN must be ignored");
    // Passive close.
    t.close();
    let s = drain(t, now + 5);
    check!(n, s.n == 1 && s.o[0].flags == TCP_FIN | TCP_ACK && t.state == State::LastAck, "our FIN: {:?}", t.state);
    check!(n, t.on_segment(now + 9, &seg(IRS + 2502, ISS + 2, TCP_ACK, 4000, &[])) == Event::Closed && t.end == End::Normal, "last ACK: {:?}", t.end);

    // 10. A full receive buffer: window 0, then a window update when read.
    let t = open(ISS, 4000, 1460, t0);
    let fill = [7u8; 1460];
    let mut seq = IRS + 1;
    let mut left = RCV_BUF;
    let mut last = None;
    while left > 0 {
        let c = &fill[..left.min(1460)];
        t.on_segment(t0 + 50, &seg(seq, ISS + 1, TCP_ACK, 4000, c));
        seq += c.len() as u32;
        left -= c.len();
        let s = drain(t, t0 + 50);
        if s.n > 0 {
            last = Some(s.o[s.n - 1]);
        }
    }
    check!(n, t.readable() == RCV_BUF && last.is_some_and(|o| o.window == 0 && o.ack == seq), "window 0 when full: {:?}", last);
    t.on_segment(t0 + 60, &seg(seq, ISS + 1, TCP_ACK, 4000, b"more"));
    check!(n, t.readable() == RCV_BUF, "data into a zero window taken");
    drain(t, t0 + 60);
    let mut sink = [0u8; 4096];
    t.recv(&mut sink);
    let s = drain(t, t0 + 70);
    check!(n, s.n == 1 && s.o[0].window == 4096, "window update after reading {:?}", &s.o[..s.n]);

    // 10b. Window scaling (RFC 7323): both sides offer a shift – windows outside
    // SYN segments are shifted; a peer that offers none gets plain windows (above).
    let t = tcb();
    t.init_connect(ISS, t0);
    drain(t, t0);
    let mut sa = seg(IRS, ISS + 1, TCP_SYN | TCP_ACK, 1000, &[]);
    sa.mss = Some(1460);
    sa.wscale = Some(2);
    t.on_segment(t0 + 10, &sa);
    let s = drain(t, t0 + 10);
    check!(n, t.snd_wnd() == 1000 && s.n == 1 && s.o[0].window as usize == RCV_BUF >> WSCALE, "scaled: SYN+ACK window as is, our ACK {:?}", &s.o[..s.n]);
    t.on_segment(t0 + 20, &seg(IRS + 1, ISS + 1, TCP_ACK, 1000, &[]));
    check!(n, t.snd_wnd() == 4000, "scaled: peer window 1000 << 2 = {}", t.snd_wnd());
    t.on_segment(t0 + 30, &seg(IRS + 1, ISS + 1, TCP_ACK, 1000, &[5u8; 1000]));
    let s = drain(t, t0 + 30);
    check!(n, s.n == 1 && s.o[0].window as usize == (RCV_BUF - 1000) >> WSCALE, "scaled: our window after data {:?}", &s.o[..s.n]);
    let mut syn = seg(IRS, 0, TCP_SYN, 100, &[]);
    syn.wscale = Some(5);
    tcb().init_accept(ISS, t0, &syn);
    let t = tcb();
    let s = drain(t, t0);
    check!(n, s.n == 1 && s.o[0].wscale == Some(WSCALE) && s.o[0].window == 65535, "scaled: SYN+ACK offers our shift {:?}", &s.o[..s.n]);
    t.on_segment(t0 + 5, &seg(IRS + 1, ISS + 1, TCP_ACK, 100, &[]));
    check!(n, t.state == State::Established && t.snd_wnd() == 3200, "scaled server: peer window 100 << 5 = {}", t.snd_wnd());

    // 11. The peer's window is 0: probes until it opens.
    let t = open(ISS, 0, 1000, t0);
    t.send(&data[..3000]);
    check!(n, drain(t, t0 + 20).n == 0, "nothing into a zero window");
    let d = t.deadline();
    t.tick(d);
    let s = drain(t, d);
    check!(n, s.n == 1 && s.o[0].len == 1 && s.o[0].seq == ISS + 1, "zero-window probe {:?}", &s.o[..s.n]);
    t.on_segment(d + 5, &seg(IRS + 1, ISS + 1, TCP_ACK, 3000, &[]));
    let s = drain(t, d + 5);
    check!(n, s.n == 3 && s.o[2].seq == ISS + 2001, "window opens: data flows {:?}", &s.o[..s.n]);

    // 12. Fast retransmit after 3 duplicate ACKs.
    let t = open(ISS, 8000, 1000, t0);
    t.send(&data[..4000]);
    drain(t, t0 + 20);
    for _ in 0..3 {
        t.on_segment(t0 + 30, &seg(IRS + 1, ISS + 1001, TCP_ACK, 8000, &[]));
    }
    // The first ACK moved snd_una; three more duplicates trigger the resend.
    t.on_segment(t0 + 31, &seg(IRS + 1, ISS + 1001, TCP_ACK, 8000, &[]));
    let s = drain(t, t0 + 31);
    check!(n, t.retransmits == 1 && s.n >= 1 && s.o[0].seq == ISS + 1001, "fast retransmit {:?} ({} resent)", &s.o[..s.n], t.retransmits);

    // 13. Active close, simultaneous close, FIN-WAIT-2 timeout, TIME-WAIT.
    let t = open(ISS, 4000, 1000, t0);
    t.send(b"bye");
    t.close();
    let s = drain(t, t0 + 20);
    check!(n, s.n == 2 && s.o[1].flags == TCP_FIN | TCP_ACK && s.o[1].seq == ISS + 4 && t.state == State::FinWait1, "data then FIN: {:?}", &s.o[..s.n]);
    t.on_segment(t0 + 30, &seg(IRS + 1, ISS + 5, TCP_ACK, 4000, &[]));
    check!(n, t.state == State::FinWait2, "FIN acknowledged: {:?}", t.state);
    t.on_segment(t0 + 40, &seg(IRS + 1, ISS + 5, TCP_ACK | TCP_FIN, 4000, &[]));
    let s = drain(t, t0 + 40);
    check!(n, t.state == State::TimeWait && s.n == 1 && s.o[0].ack == IRS + 2, "peer FIN: TIME-WAIT {:?}", t.state);
    t.tick(t0 + 40 + TIME_WAIT_MS);
    check!(n, t.state == State::Closed && t.end == End::Normal, "TIME-WAIT ends: {:?}", t.state);
    let t = open(ISS, 4000, 1000, t0);
    t.close();
    drain(t, t0 + 20);
    t.on_segment(t0 + 30, &seg(IRS + 1, ISS + 1, TCP_ACK | TCP_FIN, 4000, &[]));
    check!(n, t.state == State::Closing, "simultaneous close: {:?}", t.state);
    t.on_segment(t0 + 35, &seg(IRS + 2, ISS + 2, TCP_ACK, 4000, &[]));
    check!(n, t.state == State::TimeWait, "CLOSING -> TIME-WAIT: {:?}", t.state);
    let t = open(ISS, 4000, 1000, t0);
    t.close();
    drain(t, t0 + 20);
    t.on_segment(t0 + 30, &seg(IRS + 1, ISS + 2, TCP_ACK, 4000, &[]));
    t.tick(t0 + 30 + FIN_WAIT2_MS);
    check!(n, t.state == State::Closed, "FIN-WAIT-2 without a FIN ends: {:?}", t.state);

    // 14. 8 timeouts in a row end the connection.
    let t = open(ISS, 4000, 1000, t0);
    t.send(b"lost");
    drain(t, t0 + 20);
    let mut k = 0;
    while t.state != State::Closed && k < 20 {
        let d = t.deadline();
        t.tick(d);
        drain(t, d);
        k += 1;
    }
    check!(n, k == 9 && t.end == End::TimedOut, "gave up after {} timeouts: {:?}", k, t.end);

    // 15. Sequence numbers wrapping around 2^32.
    let iss = 0xFFFF_FE00u32;
    let t = open(iss, 8000, 1000, t0);
    t.send(&data[..2000]);
    let s = drain(t, t0 + 20);
    check!(n, s.n == 2 && s.o[1].seq == iss.wrapping_add(1001), "wrap: {:?}", &s.o[..s.n]);
    t.on_segment(t0 + 30, &seg(IRS + 1, iss.wrapping_add(2001), TCP_ACK, 8000, &[]));
    check!(n, t.deadline() == u64::MAX && drain(t, t0 + 30).n == 0, "wrapped ACK accepted");

    // 16. Abort and answers for no connection.
    let t = open(ISS, 4000, 1000, t0);
    t.abort();
    let s = drain(t, t0 + 20);
    check!(n, s.n == 1 && s.o[0].flags == TCP_RST && s.o[0].seq == ISS + 1 && t.end == End::Aborted, "abort: {:?}", &s.o[..s.n]);
    check!(n, reset_for(&seg(5, 9, TCP_RST, 0, &[])).is_none(), "no RST for a RST");
    check!(n, reset_for(&seg(5, 9, TCP_ACK, 0, b"xy")) == Some((9, 0, TCP_RST)), "RST for an ACK");
    check!(n, reset_for(&seg(5, 0, TCP_SYN, 0, &[])) == Some((0, 6, TCP_RST | TCP_ACK)), "RST+ACK for a SYN");

    // 17. The server side: a SYN to a listening port.
    let mut syn = seg(IRS, 0, TCP_SYN, 3000, &[]);
    syn.mss = Some(1000);
    tcb().init_accept(ISS, t0, &syn);
    let t = tcb();
    let s = drain(t, t0);
    check!(n, s.n == 1 && s.o[0] == Out { seq: ISS, ack: IRS + 1, flags: TCP_SYN | TCP_ACK, window: 65535, mss: Some(MSS), wscale: None, len: 0 } && t.state == State::SynReceived, "SYN+ACK {:?}", &s.o[..s.n]);
    t.on_segment(t0 + 5, &syn);
    let s = drain(t, t0 + 5);
    check!(n, s.n == 1 && s.o[0].flags == TCP_SYN | TCP_ACK && s.o[0].seq == ISS, "the SYN again: SYN+ACK again {:?}", &s.o[..s.n]);
    t.on_segment(t0 + 6, &seg(IRS + 1, ISS + 9, TCP_ACK, 3000, &[]));
    let s = drain(t, t0 + 6);
    check!(n, s.n == 1 && s.o[0].flags == TCP_RST && s.o[0].seq == ISS + 9 && t.state == State::SynReceived, "ACK for something never sent: RST {:?}", &s.o[..s.n]);
    check!(n, t.on_segment(t0 + 20, &seg(IRS + 1, ISS + 1, TCP_ACK | TCP_PSH, 3000, b"GET")) == Event::Connected, "the handshake ACK with data");
    let s = drain(t, t0 + 20);
    check!(n, t.state == State::Established && t.readable() == 3 && t.mss == 1000 && t.snd_wnd() == 3000 && s.n == 1 && s.o[0].ack == IRS + 4, "server open, request kept: {:?} {} {:?}", t.state, t.readable(), &s.o[..s.n]);
    t.send(b"HTTP/1.0 200 OK\r\n\r\nhi");
    t.close();
    let s = drain(t, t0 + 30);
    check!(n, s.n == 2 && s.o[0].len == 21 && s.o[1].flags == TCP_FIN | TCP_ACK, "answer and FIN {:?}", &s.o[..s.n]);
    // No ACK for the SYN+ACK: resent after 1, 2, 4 s, then given up.
    tcb().init_accept(ISS, t0, &syn);
    let t = tcb();
    drain(t, t0);
    let mut k = 0;
    while t.state == State::SynReceived && k < 10 {
        let d = t.deadline();
        t.tick(d);
        let s = drain(t, d);
        if t.state == State::SynReceived && (s.n != 1 || s.o[0].flags != TCP_SYN | TCP_ACK) {
            println!("tcptest: FAIL: SYN+ACK resend {:?}", &s.o[..s.n]);
            return 1;
        }
        k += 1;
    }
    check!(n, t.state == State::Closed && t.end == End::TimedOut && k == 4, "half-open connection given up after {} timeouts: {:?}", k, t.end);
    // RST while accepting: gone; abort while accepting: a RST; a segment outside
    // the window: a (rate-limited) ACK.
    tcb().init_accept(ISS, t0, &syn);
    let t = tcb();
    drain(t, t0);
    t.on_segment(t0 + 1, &seg(IRS + 1 + 1_000_000, ISS + 1, TCP_ACK, 3000, b"x"));
    let s = drain(t, t0 + 200);
    check!(n, t.state == State::SynReceived && s.n == 1 && s.o[0].flags == TCP_ACK, "outside the window while accepting: {:?}", &s.o[..s.n]);
    check!(n, t.on_segment(t0 + 300, &seg(IRS + 1, 0, TCP_RST, 0, &[])) == Event::Closed && t.end == End::Reset, "RST while accepting");
    tcb().init_accept(ISS, t0, &syn);
    let t = tcb();
    drain(t, t0);
    t.close();
    let s = drain(t, t0 + 1);
    check!(n, t.state == State::Closed && s.n == 1 && s.o[0].flags == TCP_RST, "closing while accepting: RST {:?}", &s.o[..s.n]);

    // 18. 20 000 random segments against an open connection (no panic, limits hold).
    let t = open(ISS, 4000, 1000, t0);
    let mut x = 0x7463_7074_6573_7421u64;
    let mut rnd = |m: u64| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x % m.max(1)
    };
    let mut now = t0 + 100;
    let mut payload = [0u8; 1500];
    let (mut taken, mut reopened) = (0usize, 0u32);
    for i in 0..20_000u32 {
        if t.state == State::Closed {
            t.init_connect(rnd(u32::MAX as u64) as u32, now);
            drain(t, now);
            let mut s = seg(IRS, t.deadline() as u32, TCP_SYN | TCP_ACK, 4000, &[]);
            s.mss = Some(1 + rnd(2000) as u16);
            // Most of these are refused (wrong ACK) – fine, the next round tries again.
            t.on_segment(now, &s);
            reopened += 1;
        }
        let len = rnd(4) as usize * rnd(1501) as usize / 3;
        for b in payload[..len].iter_mut() {
            *b = rnd(256) as u8;
        }
        let flags = [TCP_ACK, TCP_ACK, TCP_ACK | TCP_PSH, TCP_ACK | TCP_FIN, TCP_RST, TCP_SYN, rnd(64) as u8][rnd(7) as usize];
        let seq = IRS.wrapping_add(rnd(20_000) as u32).wrapping_sub(5_000);
        let ack = ISS.wrapping_add(rnd(20_000) as u32).wrapping_sub(5_000);
        t.on_segment(now, &seg(seq, ack, flags, rnd(65536) as u16, &payload[..len]));
        if rnd(3) == 0 {
            t.send(&data[..rnd(3000) as usize]);
        }
        if rnd(4) == 0 {
            taken += t.recv(&mut sink);
        }
        now += rnd(300);
        if now >= t.deadline() {
            t.tick(now);
        }
        let s = drain(t, now);
        for o in &s.o[..s.n] {
            if o.len > t.mss as usize || o.len > MSS as usize {
                println!("tcptest: FAIL random segment {}: segment of {} bytes, mss {}", i, o.len, t.mss);
                return 1;
            }
        }
        if t.readable() > RCV_BUF {
            println!("tcptest: FAIL random segment {}: {} bytes readable", i, t.readable());
            return 1;
        }
    }
    n += 1;
    println!(
        "tcptest: {} checks OK (handshake, refused, SYN resends 1/2/4/8 s, window and congestion window, window scaling, RTO and fast retransmit, zero-window probe, in-order / out-of-order / overlapping data, full buffer, all closing paths, wraparound, hostile segments, the server side (SYN+ACK, resends, half-open given up); 20 000 random segments: {} bytes read, {} new connections)",
        n, taken, reopened
    );
    0
}
