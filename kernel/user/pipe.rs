// M17b.b: potoki – `pipe()` daje dwa deskryptory: do odczytu i do zapisu.
//
// * Bufor w kernelu (PIPE_CAP bajtów) pod SpinLockiem (poziom PROCESS;
//   pod nim tylko kopiowanie bajtów i alokacja), długość także w atomiku –
//   warunek czekania (sprawdzany pod blokadą schedulera) nie bierze blokad.
// * read: czeka, aż będą dane; pusty potok bez piszących = koniec (0).
// * write: pisze wszystko, czekając na miejsce; bez czytających – EPIPE
//   (gdy nic nie zapisał; inaczej liczba zapisanych bajtów).
// * Końce (PipeEnd) liczone przez Arc: deskryptory z dup / spawn dzielą
//   jeden koniec; gdy znika ostatni – koniec się zamyka (Drop) i budzi
//   drugą stronę.  Proces zamyka deskryptory już w exit_current (nie
//   dopiero przy reap) – czytający dostaje koniec danych od razu.
// * Czekanie przerywa kill / Ctrl+C (EINTR).

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use super::syscalls::{EINTR, EPIPE};
use crate::sched::spin::{level, SpinLock};
use crate::sched::sync::WaitQueue;

/// Pojemność bufora (jak PIPE_BUF w Linuksie: 64 KiB).
pub const PIPE_CAP: usize = 64 * 1024;

pub struct Pipe {
    buf: SpinLock<VecDeque<u8>>,
    len: AtomicUsize,
    readers: AtomicU32,
    writers: AtomicU32,
    /// Czytający czekają na dane / koniec piszących.
    readable: WaitQueue,
    /// Piszący czekają na miejsce / koniec czytających.
    writable: WaitQueue,
}

pub struct PipeEnd {
    pipe: Arc<Pipe>,
    pub write: bool,
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        if self.write {
            self.pipe.writers.fetch_sub(1, Ordering::SeqCst);
            self.pipe.readable.wake_all();
        } else {
            self.pipe.readers.fetch_sub(1, Ordering::SeqCst);
            self.pipe.writable.wake_all();
        }
    }
}

/// Nowy potok: (koniec do odczytu, koniec do zapisu).
pub fn new() -> (Arc<PipeEnd>, Arc<PipeEnd>) {
    let pipe = Arc::new(Pipe {
        buf: SpinLock::new("pipe", level::PROCESS, VecDeque::new()),
        len: AtomicUsize::new(0),
        readers: AtomicU32::new(1),
        writers: AtomicU32::new(1),
        readable: WaitQueue::new(),
        writable: WaitQueue::new(),
    });
    (Arc::new(PipeEnd { pipe: pipe.clone(), write: false }), Arc::new(PipeEnd { pipe, write: true }))
}

impl PipeEnd {
    /// Do `max` bajtów; pusty wynik = koniec danych (nikt już nie pisze).
    pub fn read(&self, max: usize) -> Result<Vec<u8>, i64> {
        let p = &self.pipe;
        loop {
            {
                let mut b = p.buf.lock();
                if !b.is_empty() {
                    let n = max.min(b.len());
                    let out: Vec<u8> = b.drain(..n).collect();
                    p.len.store(b.len(), Ordering::SeqCst);
                    drop(b);
                    p.writable.wake_all();
                    return Ok(out);
                }
            }
            if p.writers.load(Ordering::SeqCst) == 0 {
                // Ostatni piszący mógł dopisać tuż przed zamknięciem.
                if p.len.load(Ordering::SeqCst) == 0 {
                    return Ok(Vec::new());
                }
                continue;
            }
            if max == 0 {
                return Ok(Vec::new());
            }
            p.readable.wait_until(
                || p.len.load(Ordering::SeqCst) > 0 || p.writers.load(Ordering::SeqCst) == 0 || crate::sched::should_exit(),
                None,
            );
            if crate::sched::should_exit() {
                return Err(EINTR);
            }
        }
    }

    /// Całe `data` (czeka na miejsce); EPIPE, gdy nikt nie czyta.
    pub fn write(&self, data: &[u8]) -> Result<usize, i64> {
        let p = &self.pipe;
        let mut done = 0;
        while done < data.len() {
            if p.readers.load(Ordering::SeqCst) == 0 {
                return if done > 0 { Ok(done) } else { Err(EPIPE) };
            }
            let wrote = {
                let mut b = p.buf.lock();
                let room = PIPE_CAP.saturating_sub(b.len());
                let n = room.min(data.len() - done);
                b.extend(&data[done..done + n]);
                p.len.store(b.len(), Ordering::SeqCst);
                n
            };
            if wrote > 0 {
                done += wrote;
                p.readable.wake_all();
                continue;
            }
            p.writable.wait_until(
                || p.len.load(Ordering::SeqCst) < PIPE_CAP || p.readers.load(Ordering::SeqCst) == 0 || crate::sched::should_exit(),
                None,
            );
            if crate::sched::should_exit() {
                return if done > 0 { Ok(done) } else { Err(EINTR) };
            }
        }
        Ok(done)
    }
}
