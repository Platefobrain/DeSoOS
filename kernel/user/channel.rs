// M18.c: kanały – `channel_create()` daje parę końców; każdy koniec ma swoją
// kolejkę przychodzących komunikatów (kanał jest dwukierunkowy).
// Projekt: ARCHITEKTURA.md, „IPC”.
//
// * Komunikat: do MSG_MAX bajtów danych + do MSG_HANDLES uchwytów (M18.d)
//   + nadawca (pid) wpisany przez jądro.  Kolejka: do QUEUE_MAX komunikatów.
// * Blokada per kolejka (SpinLock, poziom PROCESS – jak potok); pod nią tylko
//   operacje na kolejce.  Kopiowanie z / do procesu – w syscallu, poza blokadą.
// * Czekanie jak w potokach: warunek na atomikach (`len`, `closed`), pobudka
//   po zmianie – bez gubienia pobudek; przerywa kill / Ctrl+C (EINTR).
// * Koniec liczony przez Arc (uchwyty w tablicach i w komunikatach w drodze);
//   gdy znika ostatni – Drop: koniec zamknięty, jego kolejka opróżniona
//   (uchwyty w komunikatach zwolnione), druga strona budzona (EPIPE).

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::process::Handle;
use super::syscalls::{EAGAIN, EINTR, EPIPE};
use crate::sched::spin::{level, SpinLock};
use crate::sched::sync::WaitQueue;

/// Największy komunikat (bajty danych).
pub const MSG_MAX: usize = 4096;
/// Najwięcej uchwytów w komunikacie (M18.d).
pub const MSG_HANDLES: usize = 8;
/// Najwięcej komunikatów w kolejce jednego końca.
pub const QUEUE_MAX: usize = 64;

pub struct Message {
    pub data: Vec<u8>,
    pub handles: Vec<Handle>,
    /// Nadawca (pid) – wpisuje jądro, proces nie może go podać.
    pub sender: u64,
}

/// Kolejka przychodzących jednego końca.
struct Inbox {
    q: SpinLock<VecDeque<Message>>,
    len: AtomicUsize,
    /// Koniec-właściciel tej kolejki zamknięty (zniknął ostatni uchwyt).
    closed: AtomicBool,
    /// Odbiorcy czekają na komunikat / zamknięcie drugiej strony.
    readable: WaitQueue,
    /// Nadawcy (druga strona) czekają na miejsce / zamknięcie tego końca.
    writable: WaitQueue,
}

impl Inbox {
    fn new() -> Inbox {
        Inbox {
            q: SpinLock::new("channel", level::PROCESS, VecDeque::new()),
            len: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            readable: WaitQueue::new(),
            writable: WaitQueue::new(),
        }
    }
}

pub struct Channel {
    inbox: [Inbox; 2],
}

/// Koniec kanału: odbiera z `inbox[side]`, wysyła do `inbox[1 - side]`.
pub struct ChanEnd {
    ch: Arc<Channel>,
    side: usize,
}

/// Błąd odbioru: kod albo „za mały bufor” z wymaganym rozmiarem.
pub enum RecvError {
    Code(i64),
    /// (bajty, uchwyty) pierwszego komunikatu – zostaje w kolejce.
    TooSmall(usize, usize),
}

/// Nowy kanał: dwa końce.
pub fn new() -> (Arc<ChanEnd>, Arc<ChanEnd>) {
    let ch = Arc::new(Channel { inbox: [Inbox::new(), Inbox::new()] });
    (Arc::new(ChanEnd { ch: ch.clone(), side: 0 }), Arc::new(ChanEnd { ch, side: 1 }))
}

impl ChanEnd {
    fn mine(&self) -> &Inbox {
        &self.ch.inbox[self.side]
    }

    fn peer(&self) -> &Inbox {
        &self.ch.inbox[1 - self.side]
    }

    /// M18.d: ten sam kanał (którykolwiek koniec).  Żaden koniec kanału nie
    /// może podróżować przez ten kanał: koniec trafiłby do własnej kolejki
    /// (albo kolejki, którą sam trzyma) i nigdy by się nie zwolnił.
    pub fn same_channel(&self, other: &ChanEnd) -> bool {
        Arc::ptr_eq(&self.ch, &other.ch)
    }

    /// Wysyła komunikat drugiej stronie.  Błąd – komunikat wraca (uchwyty
    /// w nim wracają do nadawcy – M18.d).
    pub fn send(&self, msg: Message, nonblock: bool) -> Result<(), (i64, Message)> {
        let peer = self.peer();
        let mut msg = Some(msg);
        loop {
            if peer.closed.load(Ordering::SeqCst) {
                return Err((EPIPE, msg.take().unwrap()));
            }
            {
                let mut q = peer.q.lock();
                if q.len() < QUEUE_MAX {
                    q.push_back(msg.take().unwrap());
                    peer.len.store(q.len(), Ordering::SeqCst);
                    drop(q);
                    peer.readable.wake_all();
                    return Ok(());
                }
            }
            if nonblock {
                return Err((EAGAIN, msg.take().unwrap()));
            }
            peer.writable.wait_until(
                || {
                    peer.len.load(Ordering::SeqCst) < QUEUE_MAX
                        || peer.closed.load(Ordering::SeqCst)
                        || crate::sched::should_exit()
                },
                None,
            );
            if crate::sched::should_exit() {
                return Err((EINTR, msg.take().unwrap()));
            }
        }
    }

    /// Zdejmuje pierwszy komunikat, jeśli mieści się w `cap` bajtach i `hcap`
    /// uchwytach.  Pusta kolejka i druga strona zamknięta – EPIPE.
    /// `room` – wolne miejsca w tablicy uchwytów odbiorcy: więcej uchwytów w
    /// komunikacie = EMFILE, komunikat zostaje.
    pub fn recv(&self, cap: usize, hcap: usize, room: usize, nonblock: bool) -> Result<Message, RecvError> {
        let mine = self.mine();
        loop {
            {
                let mut q = mine.q.lock();
                if let Some(front) = q.front() {
                    if front.data.len() > cap || front.handles.len() > hcap {
                        return Err(RecvError::TooSmall(front.data.len(), front.handles.len()));
                    }
                    if front.handles.len() > room {
                        return Err(RecvError::Code(super::syscalls::EMFILE));
                    }
                    let m = q.pop_front().unwrap();
                    mine.len.store(q.len(), Ordering::SeqCst);
                    drop(q);
                    mine.writable.wake_all();
                    return Ok(m);
                }
            }
            if self.peer().closed.load(Ordering::SeqCst) {
                // Druga strona mogła wysłać tuż przed zamknięciem.
                if mine.len.load(Ordering::SeqCst) == 0 {
                    return Err(RecvError::Code(EPIPE));
                }
                continue;
            }
            if nonblock {
                return Err(RecvError::Code(EAGAIN));
            }
            let peer = self.peer();
            mine.readable.wait_until(
                || mine.len.load(Ordering::SeqCst) > 0 || peer.closed.load(Ordering::SeqCst) || crate::sched::should_exit(),
                None,
            );
            if crate::sched::should_exit() {
                return Err(RecvError::Code(EINTR));
            }
        }
    }
}

impl Drop for ChanEnd {
    fn drop(&mut self) {
        let mine = self.mine();
        mine.closed.store(true, Ordering::SeqCst);
        // Komunikaty do zamkniętego końca nikt już nie odbierze – zwalniamy je
        // (z uchwytami w środku) poza blokadą: Drop uchwytu może zamknąć inny
        // kanał i wziąć jego blokadę.
        let left: Vec<Message> = {
            let mut q = mine.q.lock();
            let v = q.drain(..).collect();
            mine.len.store(0, Ordering::SeqCst);
            v
        };
        drop(left);
        // Nadawcy do tego końca – EPIPE; odbiorca po drugiej stronie – EPIPE,
        // gdy jego kolejka pusta.
        mine.writable.wake_all();
        self.peer().readable.wake_all();
    }
}
