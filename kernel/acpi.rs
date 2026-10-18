// ACPI – table parsing only (no AML interpreter).
//
// DSB passes the RSDP address from the UEFI configuration table.  The RSDP points to
// the XSDT (ACPI 2.0+, 64-bit addresses) or the RSDT (1.0, 32-bit); they hold the
// addresses of the remaining tables.  We need:
//
//   MCFG – where the PCIe ECAM lives (PCI configuration space as memory:
//          4 KiB per function instead of 256 B through ports 0xCF8/0xCFC).
//
// MADT – the list of cores (Local APIC), I/O APICs and ISA interrupt
// overrides (e.g. timer IRQ0 -> GSI 2).  The `acpi` shell command
// shows all tables found.  Each table has a checksum –
// corrupted ones are skipped.  Table memory is mapped read-only.

use alloc::vec::Vec;

use crate::memory::map_firmware;
use crate::serial_println;

#[derive(Clone, Copy, Debug)]
pub struct Table {
    pub signature: [u8; 4],
    pub phys: u64,
    pub length: u32,
    pub revision: u8,
    pub oem_id: [u8; 6],
}

impl Table {
    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.signature).unwrap_or("????")
    }
    pub fn oem(&self) -> &str {
        core::str::from_utf8(&self.oem_id).unwrap_or("").trim_end()
    }
}

/// MCFG entry: ECAM for a PCI segment and a range of buses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McfgEntry {
    pub base: u64,
    pub segment: u16,
    pub bus_start: u8,
    pub bus_end: u8,
}

/// MADT – interrupt hardware.
#[derive(Clone, Debug, Default)]
pub struct Madt {
    pub lapic_address: u64,
    /// Whether a legacy 8259 PIC is present too (PCAT_COMPAT flag).
    pub has_8259: bool,
    /// Local APIC IDs of cores that can be started (enabled or "online capable").
    pub cpus: Vec<u32>,
    pub ioapics: Vec<IoApicEntry>,
    pub overrides: Vec<IrqOverride>,
}

#[derive(Clone, Copy, Debug)]
pub struct IoApicEntry {
    pub id: u8,
    pub address: u64,
    pub gsi_base: u32,
}

/// ISA interrupt `source` connected to GSI `gsi` (MPS flags: polarity, trigger mode).
#[derive(Clone, Copy, Debug)]
pub struct IrqOverride {
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

struct Acpi {
    revision: u8,
    oem_id: [u8; 6],
    tables: Vec<Table>,
    mcfg: Vec<McfgEntry>,
    madt: Option<Madt>,
    /// HPET address (HPET table; interval timer – clock.rs).
    hpet: Option<u64>,
}

fn parse_madt(t: &[u8]) -> Madt {
    let mut m = Madt {
        lapic_address: u32_at(t, 36) as u64,
        has_8259: u32_at(t, 40) & 1 != 0,
        ..Madt::default()
    };
    let mut o = 44;
    while o + 2 <= t.len() {
        let (ty, len) = (t[o], t[o + 1] as usize);
        if len < 2 || o + len > t.len() {
            break;
        }
        let e = &t[o..o + len];
        match ty {
            0 if len >= 8 => {
                let flags = u32_at(e, 4);
                if flags & 3 != 0 {
                    m.cpus.push(e[3] as u32);
                }
            }
            1 if len >= 12 => m.ioapics.push(IoApicEntry { id: e[2], address: u32_at(e, 4) as u64, gsi_base: u32_at(e, 8) }),
            2 if len >= 10 && e[2] == 0 => m.overrides.push(IrqOverride {
                source: e[3],
                gsi: u32_at(e, 4),
                flags: u16::from_le_bytes([e[8], e[9]]),
            }),
            5 if len >= 12 => m.lapic_address = u64_at(e, 4),
            9 if len >= 16 => {
                let (id, flags) = (u32_at(e, 4), u32_at(e, 8));
                if flags & 3 != 0 && !m.cpus.contains(&id) {
                    m.cpus.push(id);
                }
            }
            _ => {}
        }
        o += len;
    }
    m
}

static mut ACPI: Option<Acpi> = None;

fn acpi() -> Option<&'static Acpi> {
    // Written once in init (before tasks start), read-only afterwards.
    unsafe { (*core::ptr::addr_of!(ACPI)).as_ref() }
}

/// Bytes from physical memory (mapped read-only).
fn bytes(phys: u64, len: usize) -> Option<&'static [u8]> {
    let v = map_firmware(phys, len as u64)?;
    Some(unsafe { core::slice::from_raw_parts(v as *const u8, len) })
}

fn checksum_ok(b: &[u8]) -> bool {
    b.iter().fold(0u8, |a, &x| a.wrapping_add(x)) == 0
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// SDT table at a physical address (36 B header + checksum).
fn read_table(phys: u64) -> Option<(Table, &'static [u8])> {
    if phys == 0 {
        return None;
    }
    let head = bytes(phys, 36)?;
    let length = u32_at(head, 4);
    if !(36..=16 * 1024 * 1024).contains(&length) {
        return None;
    }
    let all = bytes(phys, length as usize)?;
    if !checksum_ok(all) {
        serial_println!(
            "[ACPI] table {} at {:#x}: bad checksum - skipped",
            core::str::from_utf8(&all[0..4]).unwrap_or("????"),
            phys
        );
        return None;
    }
    let mut signature = [0u8; 4];
    signature.copy_from_slice(&all[0..4]);
    let mut oem_id = [0u8; 6];
    oem_id.copy_from_slice(&all[10..16]);
    Some((Table { signature, phys, length, revision: all[8], oem_id }, all))
}

fn parse_mcfg(t: &[u8]) -> Vec<McfgEntry> {
    let mut out = Vec::new();
    let mut o = 44; // 36-byte header + 8 reserved
    while o + 16 <= t.len() {
        let e = McfgEntry {
            base: u64_at(t, o),
            segment: u16::from_le_bytes([t[o + 8], t[o + 9]]),
            bus_start: t[o + 10],
            bus_end: t[o + 11],
        };
        if e.base != 0 && e.bus_end >= e.bus_start {
            out.push(e);
        }
        o += 16;
    }
    out
}

/// Reads the RSDP and the table list.  Call after memory setup (map_firmware),
/// before PCI.
pub fn init(rsdp_phys: u64) {
    if rsdp_phys == 0 {
        serial_println!("[ACPI] no RSDP from the firmware - ACPI not available");
        return;
    }
    let Some(rsdp) = bytes(rsdp_phys, 36) else {
        serial_println!("[ACPI] cannot map RSDP at {:#x}", rsdp_phys);
        return;
    };
    if &rsdp[0..8] != b"RSD PTR " || !checksum_ok(&rsdp[0..20]) {
        serial_println!("[ACPI] bad RSDP at {:#x} - ignored", rsdp_phys);
        return;
    }
    let revision = rsdp[15];
    let mut oem_id = [0u8; 6];
    oem_id.copy_from_slice(&rsdp[9..15]);

    // ACPI 2.0+: XSDT (64-bit addresses), otherwise RSDT (32-bit).
    let xsdt = if revision >= 2 && checksum_ok(&rsdp[0..36]) { u64_at(rsdp, 24) } else { 0 };
    let (root, entry_size) = match read_table(xsdt) {
        Some(t) if &t.0.signature == b"XSDT" => (t, 8),
        _ => match read_table(u32_at(rsdp, 16) as u64) {
            Some(t) if &t.0.signature == b"RSDT" => (t, 4),
            _ => {
                serial_println!("[ACPI] no valid XSDT/RSDT - ACPI not available");
                return;
            }
        },
    };

    let mut tables = Vec::new();
    let mut mcfg = Vec::new();
    let mut madt = None;
    let mut hpet = None;
    let (root_table, root_bytes) = root;
    tables.push(root_table);
    let mut o = 36;
    while o + entry_size <= root_bytes.len() {
        let phys = if entry_size == 8 { u64_at(root_bytes, o) } else { u32_at(root_bytes, o) as u64 };
        o += entry_size;
        if let Some((t, b)) = read_table(phys) {
            if &t.signature == b"MCFG" {
                mcfg = parse_mcfg(b);
            }
            if &t.signature == b"APIC" {
                madt = Some(parse_madt(b));
            }
            // HPET: address in a GAS structure from byte 40 (40 = address
            // space, 0 = memory; 64-bit address from byte 44).
            if &t.signature == b"HPET" && b.len() >= 52 && b[40] == 0 {
                let a = u64_at(b, 44);
                if a != 0 {
                    hpet = Some(a);
                }
            }
            tables.push(t);
        }
    }

    let names: Vec<&str> = tables.iter().map(|t| t.name()).collect();
    serial_println!(
        "[ACPI] RSDP rev {} ({}) at {:#x}: {}",
        revision,
        core::str::from_utf8(&oem_id).unwrap_or("").trim_end(),
        rsdp_phys,
        names.join(" ")
    );
    for e in &mcfg {
        serial_println!(
            "[ACPI] MCFG: PCIe ECAM at {:#x}, segment {}, buses {}-{}",
            e.base,
            e.segment,
            e.bus_start,
            e.bus_end
        );
    }
    if let Some(m) = &madt {
        serial_println!(
            "[ACPI] MADT: {} CPU(s) (APIC id {:?}), {} I/O APIC(s), {} IRQ override(s){}",
            m.cpus.len(),
            m.cpus,
            m.ioapics.len(),
            m.overrides.len(),
            if m.has_8259 { ", 8259 present" } else { "" }
        );
    }
    unsafe {
        *core::ptr::addr_of_mut!(ACPI) = Some(Acpi { revision, oem_id, tables, mcfg, madt, hpet });
    }
}

#[allow(dead_code)]
pub fn available() -> bool {
    acpi().is_some()
}

/// Tables found (the first one is the XSDT/RSDT).
#[allow(dead_code)]
pub fn tables() -> &'static [Table] {
    acpi().map(|a| a.tables.as_slice()).unwrap_or(&[])
}

/// ECAM regions from MCFG.
pub fn mcfg() -> &'static [McfgEntry] {
    acpi().map(|a| a.mcfg.as_slice()).unwrap_or(&[])
}

/// MADT (None – no ACPI or no APIC table).
pub fn madt() -> Option<&'static Madt> {
    acpi()?.madt.as_ref()
}

/// Physical HPET address (None – no table).
pub fn hpet_base() -> Option<u64> {
    acpi()?.hpet
}

/// Description for the `acpi` command.
pub fn describe() -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::new();
    let Some(a) = acpi() else {
        return alloc::string::String::from("ACPI not available\n");
    };
    let _ = writeln!(
        s,
        "ACPI revision {} (OEM {}), {} tables:",
        a.revision,
        core::str::from_utf8(&a.oem_id).unwrap_or("").trim_end(),
        a.tables.len()
    );
    for t in &a.tables {
        let _ = writeln!(s, "  {}  rev {:<2} {:>6} B  at {:#x}  {}", t.name(), t.revision, t.length, t.phys, t.oem());
    }
    for e in &a.mcfg {
        let _ = writeln!(s, "MCFG: ECAM {:#x}, segment {}, buses {}-{}", e.base, e.segment, e.bus_start, e.bus_end);
    }
    if let Some(m) = &a.madt {
        let _ = writeln!(s, "MADT: LAPIC at {:#x}, CPUs (APIC id): {:?}{}", m.lapic_address, m.cpus, if m.has_8259 { ", 8259 present" } else { "" });
        for io in &m.ioapics {
            let _ = writeln!(s, "  I/O APIC id {} at {:#x}, GSI base {}", io.id, io.address, io.gsi_base);
        }
        for ov in &m.overrides {
            let _ = writeln!(s, "  ISA IRQ {} -> GSI {} (flags {:#x})", ov.source, ov.gsi, ov.flags);
        }
    }
    s
}
