// Per-CPU data in separate cache lines.
//
// A dense `[AtomicU32; MAX_CPUS]` array keeps 16 CPU counters in one or two
// cache lines (64 B): a CPU writing its element invalidates the line on the
// others (false sharing).  That was the case for the preemption counter and the
// held-spinlock counter (written on every acquire / release), the scheduler
// lock state, the quantum, statistics.  On top of that, global statistics
// counters (`fetch_add` from every CPU on the same line).  On real hardware a small
// change in variable layout (a new per-CPU array) changed the stress result
// by ~7% – too much for code that did not even run in it.
//
//   static X: PerCpu<AtomicU32> = crate::per_cpu!(AtomicU32::new(0));
//   X[cpu::id()].fetch_add(1, ...);          // like an array
//   static N: PerCpuCounter = PerCpuCounter::new();
//   N.add(1); N.get()                         // sum over all CPUs

use core::ops::{Deref, Index};
use core::sync::atomic::{AtomicU64, Ordering};

use super::cpu::MAX_CPUS;

/// A value in its own cache line (64 B).
#[repr(C, align(64))]
pub struct CacheLine<T>(pub T);

impl<T> Deref for CacheLine<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

/// One element per CPU, each in its own cache line.
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

/// `per_cpu!(const expression)` – PerCpu with the same initial value.
#[macro_export]
macro_rules! per_cpu {
    ($init:expr) => {
        $crate::arch::x86_64::percpu::PerCpu(
            [const { $crate::arch::x86_64::percpu::CacheLine($init) }; $crate::arch::x86_64::cpu::MAX_CPUS],
        )
    };
}

/// Statistics counter: each CPU adds to its own, reading sums them.
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
