// Struktura przekazywana przez DSB do kernela (wskaźnik w RDI).
// Musi być identyczna z kopią w boot/dsb.rs.
//
// M10: wszystkie adresy fizyczne kernel czyta przez direct map
// (`memory::phys_to_virt`); sam wskaźnik na BootInfo DSB podaje już jako
// adres z direct mapy.

/// "DSBOOT11" – zmienia się razem z układem struktury (M16b: + acpi_rsdp).
pub const BOOTINFO_MAGIC: u64 = u64::from_le_bytes(*b"DSBOOT11");

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
    /// Obraz kernela: ciągły blok fizyczny zmapowany pod `kernel_virt_base`.
    pub kernel_phys_base: u64,
    pub kernel_virt_base: u64,
    pub kernel_size: u64,
    /// Stos startowy: `stack_size` bajtów fizycznie od `stack_phys_base`,
    /// wirtualnie kończy się na `stack_top`; strona tuż pod nim jest
    /// niezamapowana (strażnik).
    pub stack_phys_base: u64,
    pub stack_top: u64,
    pub stack_size: u64,
    /// M16b: adres fizyczny RSDP (tablica konfiguracyjna UEFI: ACPI 2.0,
    /// a gdy jej nie ma – ACPI 1.0); 0 = brak ACPI.
    pub acpi_rsdp: u64,
}
