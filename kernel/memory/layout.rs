// Layout of the kernel's virtual address space.
//
//   0x0000_0000_0000_0000 .. 0x0000_7fff_ffff_ffff   lower half – EMPTY
//                                                    (user processes)
//   0xffff_8000_0000_0000  PML4[256..384)  direct map: physical address X
//                                          visible at DIRECT_MAP_BASE + X
//   0xffff_c000_0000_0000  PML4[384]       kernel heap
//   0xffff_d000_0000_0000  PML4[416]       on-demand area
//   0xffff_e000_0000_0000  PML4[448]       task stacks: 1 MiB slots,
//                                          only the top 64 KiB mapped
//   0xffff_ff00_0000_0000  PML4[510]       recursive mapping
//   0xffff_ffff_8000_0000  PML4[511]       kernel image (ELF, -2 GiB)
//   0xffff_ffff_c000_0000                  guard page (unmapped)
//   0xffff_ffff_c000_1000 .. stack_top     kernel stack
//
// Kernel and stack addresses are provided by DSB in BootInfo (`init`), the rest is fixed.

use crate::bootinfo::BootInfo;

pub const DIRECT_MAP_BASE: u64 = 0xffff_8000_0000_0000;
/// The direct map covers PML4[256..384) = 64 TiB of physical memory.
pub const DIRECT_MAP_MAX: u64 = 128 * 512 * 1024 * 1024 * 1024;
pub const KERNEL_BASE: u64 = 0xffff_ffff_8000_0000;
/// First PML4 index of the upper half (kernel).
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
    /// Guard page right below the stack.
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

/// Physical -> virtual (direct map).  Works from the kernel's very first
/// instruction: DSB builds a direct map, then `paging::init` builds its own.
#[inline]
pub const fn phys_to_virt(physical: u64) -> u64 {
    DIRECT_MAP_BASE + physical
}

/// Virtual from the direct map -> physical (None for other addresses).
#[inline]
#[allow(dead_code)]
pub fn direct_to_phys(virtual_address: u64) -> Option<u64> {
    if (DIRECT_MAP_BASE..DIRECT_MAP_BASE + DIRECT_MAP_MAX).contains(&virtual_address) {
        Some(virtual_address - DIRECT_MAP_BASE)
    } else {
        None
    }
}

/// Records the kernel and stack addresses from BootInfo (called at the very beginning).
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

/// Whether an address lies on the kernel stack's guard page (stack overflow).
pub fn is_stack_guard(address: u64) -> bool {
    let l = kernel_layout();
    (l.stack_size != 0 && address >= l.guard_page() && address < l.stack_bottom())
        || crate::sched::stack::is_guard(address)
}

/// Virtual address in the kernel image -> physical.
#[allow(dead_code)]
pub fn kernel_virt_to_phys(virtual_address: u64) -> Option<u64> {
    let l = kernel_layout();
    if virtual_address >= l.kernel_virt && virtual_address < l.kernel_virt + l.kernel_size {
        Some(l.kernel_phys + (virtual_address - l.kernel_virt))
    } else {
        None
    }
}
