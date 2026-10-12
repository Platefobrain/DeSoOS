// M19.b: czekanie na wiele uchwytów naraz (`wait_many`).
// Projekt: ARCHITEKTURA.md, „Usługi w user space”.
//
// Każdy obiekt, na który da się czekać (kolejka końca kanału, potok, później
// przerwanie), ma `Observers` – listę kanałów WaitQueue zadań, które na niego
// czekają.  `wait_many`:
//   1. zapisuje swój kanał (adres lokalnej WaitQueue) u każdego obiektu,
//   2. sprawdza warunki i śpi na własnej WaitQueue (warunek pod blokadą
//      schedulera – sched::wait_event),
//   3. wypisuje się ze wszystkich obiektów.
// Obiekt po zmianie stanu (atomiki, SeqCst) czyta listę i budzi każdy kanał.
// Pobudka nie ginie: zapis do listy jest przed sprawdzeniem warunku, a zmiana
// stanu przed odczytem listy – albo czekający widzi nowy stan, albo jest już
// na liście i dostaje pobudkę (wake_channel bierze blokadę schedulera).
//
// Lista pod IrqSpinLock (poziom WAITERS: nad kolejkami kanałów i potoków,
// pod schedulerem) – będzie ją czytać handler przerwania (19.d).  Budzenie
// po zwolnieniu listy: kopia do tablicy na stosie, bez alokacji.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::sched::spin::{level, IrqSpinLock};

/// Najwięcej obserwatorów budzonych naraz bez alokacji (więcej – druga runda).
const BATCH: usize = 16;

pub struct Observers {
    list: IrqSpinLock<Vec<usize>>,
    /// Długość listy (zmieniana pod blokadą) – `notify` bez czekających nie
    /// bierze blokady (każdy send / recv woła notify).  SeqCst jak stan
    /// obiektów: czekający zwiększa licznik PRZED sprawdzeniem warunku, a
    /// obiekt zmienia stan PRZED odczytem licznika – jedno z nich widzi drugie.
    count: AtomicUsize,
}

impl Observers {
    pub const fn new() -> Observers {
        Observers { list: IrqSpinLock::new("waiters", level::WAITERS, Vec::new()), count: AtomicUsize::new(0) }
    }

    /// Zapisuje kanał czekającego (alokacja – nie z przerwania).
    pub fn add(&self, channel: usize) {
        let mut l = self.list.lock();
        l.push(channel);
        self.count.store(l.len(), Ordering::SeqCst);
    }

    /// Wypisuje kanał (jeden wpis – ten sam obiekt może być na liście
    /// `wait_many` kilka razy).
    pub fn remove(&self, channel: usize) {
        let mut l = self.list.lock();
        if let Some(i) = l.iter().position(|&c| c == channel) {
            l.swap_remove(i);
        }
        self.count.store(l.len(), Ordering::SeqCst);
    }

    /// Budzi wszystkich czekających (także z przerwania – bez alokacji).
    pub fn notify(&self) {
        if self.count.load(Ordering::SeqCst) == 0 {
            return;
        }
        let mut start = 0;
        loop {
            let mut buf = [0usize; BATCH];
            let (n, more) = {
                let l = self.list.lock();
                if start >= l.len() {
                    return;
                }
                let n = (l.len() - start).min(BATCH);
                buf[..n].copy_from_slice(&l[start..start + n]);
                (n, start + n < l.len())
            };
            for &c in &buf[..n] {
                crate::sched::wake_channel(c);
            }
            if !more {
                return;
            }
            start += n;
        }
    }
}
