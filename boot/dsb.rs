// DSB – DeSoOS Boot (loader UEFI).
//
// M10: kernel to ELF (segmenty PT_LOAD) zlinkowany pod 0xffff_ffff_8000_0000.
// DSB:
//   1. sprawdza ELF i kopiuje segmenty do ciągłego bloku fizycznego
//      (dowolny adres – ten, który da firmware),
//   2. alokuje stos kernela (strona tuż pod nim zostaje niezamapowana –
//      strażnik przepełnienia),
//   3. buduje własne tablice stron:
//        PML4[0]   identity (tylko na czas skoku – kod DSB działa pod
//                  adresami fizycznymi; kernel usuwa to mapowanie),
//        PML4[256] direct map: fizyczny X pod 0xffff_8000_0000_0000 + X,
//        PML4[511] obraz kernela (4 KiB, kod tylko do odczytu) + stos,
//   4. ExitBootServices, ładuje CR3, ustawia RSP i skacze do e_entry
//      z RDI = BootInfo (adres w direct mapie).
//
// Nie ma już stałego adresu 0x200000, limitu 512 KiB ani stosu pod 0x300000.

#![no_std]
#![no_main]

use core::arch::asm;
use uefi::boot::{self, AllocateType, MemoryType};
use uefi::mem::memory_map::MemoryMap;
use uefi::prelude::*;
use uefi::println;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};

/// Musi być identyczna z kernel/bootinfo.rs.
#[repr(C)]
#[derive(Clone, Copy)]
struct BootInfo {
    magic: u64,
    framebuffer_addr: u64,
    framebuffer_size: u64,
    width: u32,
    height: u32,
    stride: u32,
    pixel_format: u32,
    memory_map_addr: u64,
    memory_map_size: u64,
    memory_map_desc_size: u64,
    kernel_phys_base: u64,
    kernel_virt_base: u64,
    kernel_size: u64,
    stack_phys_base: u64,
    stack_top: u64,
    stack_size: u64,
    acpi_rsdp: u64,
}

const BOOTINFO_MAGIC: u64 = u64::from_le_bytes(*b"DSBOOT11");

const PAGE: u64 = 4096;
const HUGE_PAGE: u64 = 2 * 1024 * 1024;
const GIB: u64 = 1024 * 1024 * 1024;
/// Direct map kernela: PML4[256..384) = 64 TiB (kernel/memory/layout.rs).
const DIRECT_MAP_LIMIT: u64 = 128 * 512 * GIB;

// Układ adresów (musi się zgadzać z kernel/memory/layout.rs).
const DIRECT_MAP_BASE: u64 = 0xffff_8000_0000_0000;
const KERNEL_BASE: u64 = 0xffff_ffff_8000_0000;
/// Pierwszy adres za obszarem obrazu kernela; tu leży strona-strażnik.
const STACK_GUARD: u64 = 0xffff_ffff_c000_0000;
const STACK_SIZE: u64 = 256 * 1024;
const STACK_BOTTOM: u64 = STACK_GUARD + PAGE;
const STACK_TOP: u64 = STACK_BOTTOM + STACK_SIZE;

// Bity wpisów tablic stron.
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const HUGE: u64 = 1 << 7;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

// Typy pamięci UEFI, które trafiają do direct mapy (RAM, ACPI, firmware).
// Pomijamy Reserved (0), MMIO (11, 12) i PalCode (13) – potrafią leżeć
// bardzo wysoko (np. dziura HyperTransport przy 1 TiB) i nie są RAM-em.
const DIRECT_MAP_TYPES: [u32; 11] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 14];

static KERNEL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/kernel.elf"));

// M15: parser ELF wspólny z kernelem (ładowanie programów użytkownika).
#[path = "../common/elf.rs"]
mod elf;

fn page_down(x: u64) -> u64 {
    x & !(PAGE - 1)
}
fn page_up(x: u64) -> u64 {
    (x + PAGE - 1) & !(PAGE - 1)
}

/// Obraz kernela: segmenty z common/elf.rs + sprawdzenie, że wszystko leży
/// w obszarze kernela (-2 GiB .. strona-strażnik stosu).
struct KernelImage {
    elf: elf::Elf,
    start: u64, // pierwsza strona (wirtualnie)
    end: u64,   // koniec, wyrównany do strony
}

fn parse_elf(bytes: &[u8]) -> Result<KernelImage, &'static str> {
    let elf = elf::parse(bytes).map_err(|e| e.as_str())?;
    for seg in elf.segments() {
        if seg.vaddr < KERNEL_BASE || seg.end() > STACK_GUARD {
            return Err("ELF segment outside 0xffffffff80000000..0xffffffffc0000000");
        }
    }
    let (lo, hi) = elf.span();
    let (start, end) = (page_down(lo), page_up(hi));
    if elf.entry < start || elf.entry >= end {
        return Err("kernel entry point outside the image");
    }
    Ok(KernelImage { elf, start, end })
}

/// Ciągły blok stron (wyzerowany).  Adres fizyczny = wskaźnik (UEFI ma
/// identity map).
fn alloc_zeroed(pages: usize, ty: MemoryType) -> Result<u64, &'static str> {
    let p = boot::allocate_pages(AllocateType::AnyPages, ty, pages)
        .map_err(|_| "out of memory")?;
    unsafe { core::ptr::write_bytes(p.as_ptr(), 0, pages * PAGE as usize) };
    Ok(p.as_ptr() as u64)
}

fn alloc_table() -> Result<u64, &'static str> {
    alloc_zeroed(1, MemoryType::LOADER_DATA)
}

fn table(physical: u64) -> &'static mut [u64; 512] {
    unsafe { &mut *(physical as *mut [u64; 512]) }
}

/// Tabela następnego poziomu pod `entries[index]` (tworzy, gdy brak).
fn next_table(parent: u64, index: usize) -> Result<u64, &'static str> {
    let entries = table(parent);
    if entries[index] & PRESENT == 0 {
        entries[index] = alloc_table()? | PRESENT | WRITABLE;
    }
    if entries[index] & HUGE != 0 {
        return Err("page table conflict (huge page)");
    }
    Ok(entries[index] & ADDRESS_MASK)
}

fn map_4k(pml4: u64, va: u64, pa: u64, flags: u64) -> Result<(), &'static str> {
    let pdpt = next_table(pml4, ((va >> 39) & 0x1ff) as usize)?;
    let pd = next_table(pdpt, ((va >> 30) & 0x1ff) as usize)?;
    let pt = next_table(pd, ((va >> 21) & 0x1ff) as usize)?;
    let e = &mut table(pt)[((va >> 12) & 0x1ff) as usize];
    if *e & PRESENT != 0 {
        return Err("page mapped twice");
    }
    *e = (pa & ADDRESS_MASK) | flags | PRESENT;
    Ok(())
}

/// Strona 2 MiB: fizyczny `pa` pod wirtualnym `va` (tablice tworzone w razie
/// potrzeby; strona już zmapowana tak samo = OK).
fn map_2m(pml4: u64, va: u64, pa: u64) -> Result<(), &'static str> {
    let pdpt = next_table(pml4, ((va >> 39) & 0x1ff) as usize)?;
    let pd = next_table(pdpt, ((va >> 30) & 0x1ff) as usize)?;
    let e = &mut table(pd)[((va >> 21) & 0x1ff) as usize];
    let want = (pa & ADDRESS_MASK) | PRESENT | WRITABLE | HUGE;
    if *e & PRESENT != 0 {
        return if *e == want { Ok(()) } else { Err("page table conflict (2 MiB page)") };
    }
    *e = want;
    Ok(())
}

/// M16b: obszary fizyczne do zmapowania (identity + direct map), z mapy UEFI:
/// RAM, ACPI, firmware – plus framebuffer.  Bez dziur między nimi: na
/// laptopach z Ryzenem framebuffer zintegrowanej grafiki leży często powyżej
/// 512 GiB, choć RAM-u jest 16 GiB – dawny limit "cały zakres 0..koniec"
/// przerywał start.  Zwraca zakresy [start, end) wyrównane do 2 MiB.
fn direct_map_ranges(fb: u64, fb_size: u64) -> Result<Ranges, &'static str> {
    let map = boot::memory_map(MemoryType::LOADER_DATA).map_err(|_| "cannot read the memory map")?;
    let mut raw = Ranges::new();
    for d in map.entries() {
        if DIRECT_MAP_TYPES.contains(&d.ty.0) && d.page_count > 0 {
            raw.push(d.phys_start, d.phys_start + d.page_count * PAGE)?;
        }
    }
    if fb_size != 0 {
        raw.push(fb, fb + fb_size)?;
    }
    let items = &mut raw.items[..raw.len];
    for r in items.iter_mut() {
        r.0 &= !(HUGE_PAGE - 1);
        r.1 = (r.1 + HUGE_PAGE - 1) & !(HUGE_PAGE - 1);
    }
    items.sort_unstable();
    let mut merged = Ranges::new();
    for &(a, b) in items.iter() {
        if merged.len > 0 && a <= merged.items[merged.len - 1].1 {
            let last = &mut merged.items[merged.len - 1];
            last.1 = last.1.max(b);
        } else {
            merged.push(a, b)?;
        }
    }
    Ok(merged)
}

/// Lista zakresów bez alokacji (DSB nie ma globalnego alokatora).
struct Ranges {
    items: [(u64, u64); 512],
    len: usize,
}

impl Ranges {
    fn new() -> Self {
        Ranges { items: [(0, 0); 512], len: 0 }
    }
    fn push(&mut self, a: u64, b: u64) -> Result<(), &'static str> {
        if self.len == self.items.len() {
            return Err("UEFI memory map has too many regions");
        }
        self.items[self.len] = (a, b);
        self.len += 1;
        Ok(())
    }
    fn as_slice(&self) -> &[(u64, u64)] {
        &self.items[..self.len]
    }
}

struct Loaded {
    pml4: u64,
    entry: u64,
    kernel_phys: u64,
    kernel_virt: u64,
    kernel_size: u64,
    stack_phys: u64,
}

/// Kopiuje kernel, alokuje stos i buduje tablice stron.
fn load_kernel(ranges: &[(u64, u64)]) -> Result<Loaded, &'static str> {
    let image = parse_elf(KERNEL)?;
    let span = image.end - image.start;
    let span_pages = (span / PAGE) as usize;

    // 1. Obraz kernela: jeden ciągły blok, segment pod (vaddr - start).
    let kernel_phys = alloc_zeroed(span_pages, MemoryType::LOADER_CODE)?;
    for seg in image.elf.segments() {
        let dst = kernel_phys + (seg.vaddr - image.start);
        unsafe {
            core::ptr::copy_nonoverlapping(
                KERNEL.as_ptr().add(seg.offset as usize),
                dst as *mut u8,
                seg.filesz as usize,
            );
        }
        // Reszta (memsz - filesz, czyli .bss) jest już wyzerowana.
    }

    // 2. Stos.
    let stack_phys = alloc_zeroed((STACK_SIZE / PAGE) as usize, MemoryType::LOADER_DATA)?;

    // 3. Tablice stron.
    let pml4 = alloc_table()?;

    // Identity + direct map, strony 2 MiB – tylko obszary z mapy UEFI
    // (RAM, ACPI, firmware) i framebuffer; dziury zostają puste.
    for &(start, end) in ranges {
        if end > DIRECT_MAP_LIMIT {
            println!("DSB: region {:#x}..{:#x}", start, end);
            return Err("memory or framebuffer above 64 TiB (outside the kernel direct map)");
        }
        let mut pa = start;
        while pa < end {
            // Identity map tylko w dolnych 512 GiB (PML4[0]) – potrzebna tylko
            // na kilka instrukcji skoku do kernela (kod DSB leży nisko).
            if pa < 512 * GIB {
                map_2m(pml4, pa, pa)?;
            }
            map_2m(pml4, DIRECT_MAP_BASE + pa, pa)?;
            pa += HUGE_PAGE;
        }
    }

    // Kernel: strony 4 KiB; zapis tylko tam, gdzie segment ma PF_W
    // (strona dzielona przez dwa segmenty dostaje sumę uprawnień).
    for k in 0..span_pages as u64 {
        let va = image.start + k * PAGE;
        let writable = image
            .elf
            .segments()
            .iter()
            .any(|s| s.writable() && va < s.end() && va + PAGE > s.vaddr);
        let flags = if writable { WRITABLE } else { 0 };
        map_4k(pml4, va, kernel_phys + k * PAGE, flags)?;
    }

    // Stos: STACK_BOTTOM..STACK_TOP; STACK_GUARD (strona niżej) zostaje pusta.
    for k in 0..STACK_SIZE / PAGE {
        map_4k(pml4, STACK_BOTTOM + k * PAGE, stack_phys + k * PAGE, WRITABLE)?;
    }

    Ok(Loaded {
        pml4,
        entry: image.elf.entry,
        kernel_phys,
        kernel_virt: image.start,
        kernel_size: span,
        stack_phys,
    })
}

fn fail(what: &str, status: Status) -> Status {
    println!("DSB: ERROR: {}", what);
    println!("DSB: cannot start DeSoOS ({:?})", status);
    boot::stall(core::time::Duration::from_secs(10));
    status
}

#[entry]
fn dsb() -> Status {
    uefi::helpers::init().unwrap();

    let bootinfo_phys = match alloc_zeroed(1, MemoryType::LOADER_DATA) {
        Ok(p) => p,
        Err(e) => return fail(e, Status::OUT_OF_RESOURCES),
    };

    let gop_handle = match boot::get_handle_for_protocol::<GraphicsOutput>() {
        Ok(h) => h,
        Err(_) => return fail("no graphics output (GOP)", Status::UNSUPPORTED),
    };
    let mut gop = match boot::open_protocol_exclusive::<GraphicsOutput>(gop_handle) {
        Ok(g) => g,
        Err(_) => return fail("cannot open GOP", Status::DEVICE_ERROR),
    };

    let mode = gop.current_mode_info();
    let (width, height) = mode.resolution();
    let stride = mode.stride();
    let pixel_format = match mode.pixel_format() {
        PixelFormat::Rgb => 0,
        PixelFormat::Bgr => 1,
        _ => 2,
    };
    let mut framebuffer = gop.frame_buffer();
    let framebuffer_addr = framebuffer.as_mut_ptr() as u64;
    let framebuffer_size = framebuffer.size() as u64;

    // No boot-services protocol may remain alive across ExitBootServices.
    drop(framebuffer);
    drop(gop);

    // M16b: RSDP z tablicy konfiguracyjnej UEFI (ACPI 2.0, inaczej 1.0) –
    // kernel znajdzie przez nie MCFG (PCIe ECAM).  Tylko odczyt adresu.
    let acpi_rsdp = uefi::system::with_config_table(|tables| {
        use uefi::table::cfg::ConfigTableEntry;
        let find = |guid| tables.iter().find(|t| t.guid == guid).map(|t| t.address as u64);
        find(ConfigTableEntry::ACPI2_GUID).or_else(|| find(ConfigTableEntry::ACPI_GUID)).unwrap_or(0)
    });

    let ranges = match direct_map_ranges(framebuffer_addr, framebuffer_size) {
        Ok(r) => r,
        Err(e) => return fail(e, Status::LOAD_ERROR),
    };

    let loaded = match load_kernel(ranges.as_slice()) {
        Ok(l) => l,
        Err(e) => return fail(e, Status::LOAD_ERROR),
    };

    // uefi 0.41 performs the final memory-map retrieval and ExitBootServices
    // sequence for us. The returned map owns its backing buffer (LOADER_DATA)
    // and stays valid after boot services are gone.
    let memory_map = unsafe { boot::exit_boot_services(Some(MemoryType::LOADER_DATA)) };
    let map_meta = memory_map.meta();
    let map_buffer = memory_map.buffer();

    let info = BootInfo {
        magic: BOOTINFO_MAGIC,
        framebuffer_addr,
        framebuffer_size,
        width: width as u32,
        height: height as u32,
        stride: stride as u32,
        pixel_format,
        memory_map_addr: map_buffer.as_ptr() as u64,
        memory_map_size: map_meta.map_size as u64,
        memory_map_desc_size: map_meta.desc_size as u64,
        kernel_phys_base: loaded.kernel_phys,
        kernel_virt_base: loaded.kernel_virt,
        kernel_size: loaded.kernel_size,
        stack_phys_base: loaded.stack_phys,
        stack_top: STACK_TOP,
        stack_size: STACK_SIZE,
        acpi_rsdp,
    };
    unsafe { core::ptr::write(bootinfo_phys as *mut BootInfo, info) };

    // Bufor mapy pamięci ma żyć zawsze – kernel czyta go przez direct map.
    core::mem::forget(memory_map);

    // Skok: od `mov cr3` działają nasze tablice; ta sekwencja leży w
    // identity mapie (PML4[0]), więc wykona się do końca.
    unsafe {
        asm!(
            "cli",
            "mov cr3, {pml4}",
            "mov rsp, {stack}",
            "xor ebp, ebp",
            "jmp {entry}",
            pml4 = in(reg) loaded.pml4,
            stack = in(reg) STACK_TOP,
            entry = in(reg) loaded.entry,
            in("rdi") DIRECT_MAP_BASE + bootinfo_phys,
            options(noreturn)
        );
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
