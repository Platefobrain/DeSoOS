// Structure passed by DSB to the kernel (pointer in RDI).
// Must be identical to the copy in boot/dsb.rs.
//
// The kernel reads all physical addresses through the direct map
// (`memory::phys_to_virt`); DSB already passes the BootInfo pointer itself as
// a direct-map address.

/// "DSBOOT12" – changes together with the structure layout (last change: + rng_seed).
pub const BOOTINFO_MAGIC: u64 = u64::from_le_bytes(*b"DSBOOT12");

#[repr(C)]
pub struct BootInfo {
    pub magic: u64,
    pub framebuffer_addr: u64,
    pub framebuffer_size: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: u32,
    pub memory_map_addr: u64,
    pub memory_map_size: u64,
    pub memory_map_desc_size: u64,
    /// Kernel image: a contiguous physical block mapped at `kernel_virt_base`.
    pub kernel_phys_base: u64,
    pub kernel_virt_base: u64,
    pub kernel_size: u64,
    /// Boot stack: `stack_size` bytes physically from `stack_phys_base`,
    /// virtually it ends at `stack_top`; the page right below it is
    /// unmapped (guard).
    pub stack_phys_base: u64,
    pub stack_top: u64,
    pub stack_size: u64,
    /// Physical address of the RSDP (UEFI configuration table: ACPI 2.0,
    /// or ACPI 1.0 if that is missing); 0 = no ACPI.
    pub acpi_rsdp: u64,
    /// 64 bytes from the firmware's EFI_RNG_PROTOCOL (`rng_seed_ok` = 1 when it gave
    /// them); the kernel copies them at once and wipes this field (kernel/random.rs).
    pub rng_seed: [u8; 64],
    pub rng_seed_ok: u64,
}
