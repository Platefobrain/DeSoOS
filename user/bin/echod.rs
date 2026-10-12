// M19.g: echod – najprostsza usługa (bez urządzenia), do testów menedżera
// usług w init i jako wzór usługi.  Uchwyty: 1 = konsola, 4 = kanał połączeń.
// Każdy klient (koniec kanału z komunikatu na kanale połączeń) dostaje z
// powrotem to, co wysłał; "pid" -> numer procesu usługi (tekst);
// "crash" -> usługa kończy się kodem 7 (test restartu).
// Koniec: kanał połączeń zamknięty i żaden klient nie został -> kod 0.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

const LISTEN: u64 = 4;
const MAX_CLIENTS: usize = WAIT_MAX - 1;

fn main(_args: Args) -> i32 {
    let mut clients = [0u64; MAX_CLIENTS];
    let mut nclients = 0usize;
    let mut listening = true;
    let mut msg = [0u8; MSG_MAX];
    let mut info = RecvInfo::default();
    loop {
        if !listening && nclients == 0 {
            return 0;
        }
        let mut list = [(0u64, 0u64); WAIT_MAX];
        let mut k = 0;
        if listening {
            list[k] = (LISTEN, W_READABLE);
            k += 1;
        }
        let first = k;
        for &c in &clients[..nclients] {
            list[k] = (c, W_READABLE);
            k += 1;
        }
        let Ok(ready) = wait_many(&list[..k], FOREVER) else { return 5 };
        if listening && ready & 1 != 0 {
            let mut hs = [0u64; 1];
            let r = chan_recv_h(LISTEN, &mut msg, &mut hs, CHAN_NONBLOCK, &mut info);
            if r == EPIPE {
                listening = false;
            } else if r >= 0 && info.handles == 1 {
                if nclients < MAX_CLIENTS {
                    clients[nclients] = hs[0];
                    nclients += 1;
                } else {
                    close(hs[0]);
                }
            }
        }
        for j in (0..nclients).rev() {
            if ready & (1 << (first + j)) == 0 {
                continue;
            }
            let c = clients[j];
            let r = chan_recv(c, &mut msg, CHAN_NONBLOCK, &mut info);
            if r == EPIPE {
                close(c);
                clients[j] = clients[nclients - 1];
                nclients -= 1;
                continue;
            }
            if r < 0 {
                continue;
            }
            let r = r as usize;
            match &msg[..r] {
                b"crash" => return 7,
                b"pid" => {
                    let mut out = [0u8; 24];
                    let mut n = 0;
                    let mut v = getpid();
                    let mut digits = [0u8; 20];
                    loop {
                        digits[n] = b'0' + (v % 10) as u8;
                        n += 1;
                        v /= 10;
                        if v == 0 {
                            break;
                        }
                    }
                    for i in 0..n {
                        out[i] = digits[n - 1 - i];
                    }
                    chan_send(c, &out[..n], CHAN_NONBLOCK);
                }
                _ => {
                    chan_send(c, &msg[..r], CHAN_NONBLOCK);
                }
            }
        }
    }
}
