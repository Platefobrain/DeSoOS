// M10: układ wirtualnej przestrzeni adresowej kernela.
//
//   0x0000_0000_0000_0000 .. 0x0000_7fff_ffff_ffff   dolna połowa – PUSTA
//                                                    (procesy użytkownika, M13)
//   0xffff_8000_0000_0000  PML4[256..384)  direct map: fizyczny adres X
//                                          widoczny pod DIRECT_MAP_BASE + X
//   0xffff_c000_0000_0000  PML4[384]       heap kernela (M3)
//   0xffff_d000_0000_0000  PML4[416]       obszar on-demand (M4)
//   0xffff_e000_0000_0000  PML4[448]       stosy zadań (M12): sloty po 1 MiB,
//                                          zamapowane tylko górne 64 KiB
//   0xffff_ff00_0000_0000  PML4[510]       mapowanie rekurencyjne (M2)
//   0xffff_ffff_8000_0000  PML4[511]       obraz kernela (ELF, -2 GiB)
//   0xffff_ffff_c000_0000                  strona-strażnik (niezamapowana)
//   0xffff_ffff_c000_1000 .. stack_top     stos kernela
//
// Adresy kernela i stosu podaje DSB w BootInfo (`init`), reszta jest stała.

use crate::bootinfo::BootInfo;

pub const DIRECT_MAP_BASE: u64 = 0xffff_8000_0000_0000;
/// Direct map zajmuje PML4[256..384) = 64 TiB fizycznej pamięci.
pub const DIRECT_MAP_MAX: u64 = 128 * 512 * 1024 * 1024 * 1024;
pub const KERNEL_BASE: u64 = 0xffff_ffff_8000_0000;
/// Pierwszy indeks PML4 górnej połowy (kernel).
pub const KERNEL_PML4_FIRST: usize = 256;
pub const KERNEL_PML4_INDEX: usize = 511;

#[derive(Clone, Copy)]
pub struct KernelLayout {
    pub kernel_phys: u64,
    pub kernel_virt: u64,
    pub kernel_size: u64,
    pub stack_phys: u64,
    pub stack_top: u64,
    pub stack_size: u64,
}

impl KernelLayout {
    pub const fn stack_bottom(&self) -> u64 {
        self.stack_top - self.stack_size
    }
    /// Strona-strażnik tuż pod stosem.
    pub const fn guard_page(&self) -> u64 {
        self.stack_bottom() - 4096
    }
}

static mut LAYOUT: KernelLayout = KernelLayout {
    kernel_phys: 0,
    kernel_virt: KERNEL_BASE,
    kernel_size: 0,
    stack_phys: 0,
    stack_top: 0,
    stack_size: 0,
};

/// Fizyczny -> wirtualny (direct map).  Działa od pierwszej instrukcji
/// kernela: DSB buduje direct map, potem `paging::init` buduje własny.
#[inline]
pub const fn phys_to_virt(physical: u64) -> u64 {
    DIRECT_MAP_BASE + physical
}

/// Wirtualny z direct mapy -> fizyczny (None dla innych adresów).
#[inline]
#[allow(dead_code)]
pub fn direct_to_phys(virtual_address: u64) -> Option<u64> {
    if (DIRECT_MAP_BASE..DIRECT_MAP_BASE + DIRECT_MAP_MAX).contains(&virtual_address) {
        Some(virtual_address - DIRECT_MAP_BASE)
    } else {
        None
    }
}

/// Zapamiętuje adresy kernela i stosu z BootInfo (wołane na samym początku).
pub fn init(boot: &BootInfo) {
    unsafe {
        *core::ptr::addr_of_mut!(LAYOUT) = KernelLayout {
            kernel_phys: boot.kernel_phys_base,
            kernel_virt: boot.kernel_virt_base,
            kernel_size: boot.kernel_size,
            stack_phys: boot.stack_phys_base,
            stack_top: boot.stack_top,
            stack_size: boot.stack_size,
        };
    }
}

pub fn kernel_layout() -> KernelLayout {
    unsafe { *core::ptr::addr_of!(LAYOUT) }
}

/// Czy adres leży na stronie-strażniku stosu kernela (przepełnienie stosu).
pub fn is_stack_guard(address: u64) -> bool {
    let l = kernel_layout();
    (l.stack_size != 0 && address >= l.guard_page() && address < l.stack_bottom())
        || crate::sched::stack::is_guard(address)
}

/// Wirtualny adres w obrazie kernela -> fizyczny.
#[allow(dead_code)]
pub fn kernel_virt_to_phys(virtual_address: u64) -> Option<u64> {
    let l = kernel_layout();
    if virtual_address >= l.kernel_virt && virtual_address < l.kernel_virt + l.kernel_size {
        Some(l.kernel_phys + (virtual_address - l.kernel_virt))
    } else {
        None
    }
}
