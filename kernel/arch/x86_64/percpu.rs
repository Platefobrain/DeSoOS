// M17b.e: dane per CPU w osobnych liniach cache.
//
// Gęsta tablica `[AtomicU32; MAX_CPUS]` trzyma 16 liczników CPU w jednej-dwóch
// liniach cache (64 B): CPU piszący swój element unieważnia linię u
// pozostałych (false sharing).  Tak było z licznikiem wywłaszczania i
// trzymanych spinlocków (zapis przy każdym wzięciu / zwolnieniu), stanem
// blokady schedulera, kwantem, statystykami.  Do tego globalne liczniki
// statystyk (`fetch_add` z każdego CPU na tę samą linię).  Legion: drobna
// zmiana układu zmiennych (M17b.c – nowa tablica per CPU) zmieniała wynik
// stressu o ~7% – za dużo jak na kod, który się w nim nie wykonywał.
//
//   static X: PerCpu<AtomicU32> = crate::per_cpu!(AtomicU32::new(0));
//   X[cpu::id()].fetch_add(1, ...);          // jak tablica
//   static N: PerCpuCounter = PerCpuCounter::new();
//   N.add(1); N.get()                         // suma ze wszystkich CPU

use core::ops::{Deref, Index};
use core::sync::atomic::{AtomicU64, Ordering};

use super::cpu::MAX_CPUS;

/// Wartość w osobnej linii cache (64 B).
#[repr(C, align(64))]
pub struct CacheLine<T>(pub T);

impl<T> Deref for CacheLine<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

/// Element dla każdego CPU, każdy w osobnej linii cache.
pub struct PerCpu<T>(pub [CacheLine<T>; MAX_CPUS]);

impl<T> Index<usize> for PerCpu<T> {
    type Output = T;
    #[inline]
    fn index(&self, i: usize) -> &T {
        &self.0[i].0
    }
}

impl<T> PerCpu<T> {
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter().map(|c| &c.0)
    }
}

/// `per_cpu!(wyrażenie stałe)` – PerCpu z tą samą wartością początkową.
#[macro_export]
macro_rules! per_cpu {
    ($init:expr) => {
        $crate::arch::x86_64::percpu::PerCpu(
            [const { $crate::arch::x86_64::percpu::CacheLine($init) }; $crate::arch::x86_64::cpu::MAX_CPUS],
        )
    };
}

/// Licznik statystyki: każdy CPU dodaje do swojego, odczyt sumuje.
pub struct PerCpuCounter(PerCpu<AtomicU64>);

impl PerCpuCounter {
    pub const fn new() -> Self {
        PerCpuCounter(PerCpu([const { CacheLine(AtomicU64::new(0)) }; MAX_CPUS]))
    }

    #[inline]
    pub fn add(&self, n: u64) {
        self.0[super::cpu::id()].fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }
}
