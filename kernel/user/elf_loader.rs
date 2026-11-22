// Loading ELF programs into a process address space.
//
// The same parser as in the bootloader (common/elf.rs) + rules for programs:
//   * segments only in the load range of ABI 1.0 (docs/abi/README.md): from USER_MIN
//     (the first 1 MiB is empty – null pointer) to USER_MAX – below the heap's largest
//     reach (image end + BRK_MAX) plus a 1 GiB gap before the mmap area (MMAP_BASE), so a
//     program anywhere in the range never meets its heap, mmap or stack,
//   * W^X: a segment cannot be both writable and executable; pages
//     without PF_X get NX,
//   * entry point in an executable segment, the whole image at most 64 MiB,
//   * .bss (memsz > filesz) = zeroed frames.
// Stack: 16 KiB below USER_STACK_TOP, and on it (SysV): argc, argv[], NULL,
// envp NULL, auxv AT_NULL; the argument strings at the very top.

use alloc::vec::Vec;

use super::space::AddressSpace;
use super::{USER_STACK_SIZE, USER_STACK_TOP};
use crate::elf::{self, ElfError};
use crate::memory::{nx_flag, NO_EXECUTE, USER, WRITABLE};

const PAGE: u64 = 4096;
pub const USER_MIN: u64 = 0x10_0000;
pub const USER_MAX: u64 = super::vm::MMAP_BASE - super::vm::BRK_MAX - (1 << 30);
pub const MAX_IMAGE: u64 = 64 * 1024 * 1024;
pub const MAX_ARGS: usize = 32;
pub const MAX_ARG_BYTES: usize = 4096;

/// The ABI this kernel gives (abi/abi.toml through kernel/user/abi_generated.rs).
pub const ABI_MAJOR: u16 = super::abi_generated::ABI_MAJOR;
pub const ABI_MINOR: u16 = super::abi_generated::ABI_MINOR;
/// The ABI note's owner and type (libdeso sys.rs, sdk/libdeso/link.ld).
const NOTE_NAME: &[u8; 5] = b"DeSo\0";
const NT_DESO_ABI: u32 = 1;
const PT_NOTE: u32 = 4;
/// At most this many PT_NOTE headers, each at most this long.
const MAX_NOTE_HEADERS: usize = 4;
const MAX_NOTE_BYTES: u64 = 4096;

/// Why a program's ABI note refuses it (exec: ERROR_ABI).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiError {
    /// A note (ours or another owner's) with a bad length or outside its PT_NOTE, a PT_NOTE
    /// outside the file, overlapping another one or the ELF headers, misaligned, too long,
    /// too many PT_NOTE headers.
    BadNote,
    /// The DeSo OS ABI note more than once.
    Twice,
    /// Flags this system does not know.
    Flags(u32),
    /// Another major version.
    OtherMajor(u16, u16),
    /// A newer minor version than this system gives.
    Newer(u16, u16),
}

impl core::fmt::Display for AbiError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            AbiError::BadNote => write!(f, "bad ABI note"),
            AbiError::Twice => write!(f, "ABI note given twice"),
            AbiError::Flags(x) => write!(f, "ABI note with unknown flags {:#x}", x),
            AbiError::OtherMajor(a, b) | AbiError::Newer(a, b) => {
                write!(f, "needs DeSo OS ABI {}.{}, this system {}.{}", a, b, ABI_MAJOR, ABI_MINOR)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    Elf(ElfError),
    Abi(AbiError),
    Overlap,
    OutsideUserSpace,
    WriteAndExecute,
    EntryNotInCode,
    TooBig,
    TooManyArgs,
    NoMemory,
}

impl LoadError {
    pub fn as_str(self) -> &'static str {
        match self {
            LoadError::Elf(e) => e.as_str(),
            LoadError::Abi(_) => "the program needs another DeSo OS ABI (its ELF ABI note)",
            LoadError::Overlap => "segments overlap",
            LoadError::OutsideUserSpace => "segment outside the user address space",
            LoadError::WriteAndExecute => "segment both writable and executable (W^X)",
            LoadError::EntryNotInCode => "entry point not in an executable segment",
            LoadError::TooBig => "program image too big (max 64 MiB)",
            LoadError::TooManyArgs => "too many / too long arguments",
            LoadError::NoMemory => "out of memory",
        }
    }
}

pub struct Loaded {
    pub space: AddressSpace,
    pub entry: u64,
    /// RSP at startup (points at argc).
    pub rsp: u64,
    /// First address after the image (heap – one page further).
    pub image_end: u64,
}

fn page_down(x: u64) -> u64 {
    x & !(PAGE - 1)
}
fn page_up(x: u64) -> u64 {
    (x + PAGE - 1) & !(PAGE - 1)
}

fn u32_at(b: &[u8], o: u64) -> Option<u32> {
    let o = usize::try_from(o).ok()?;
    Some(u32::from_le_bytes(b.get(o..o.checked_add(4)?)?.try_into().ok()?))
}
fn u16_at(b: &[u8], o: u64) -> Option<u16> {
    let o = usize::try_from(o).ok()?;
    Some(u16::from_le_bytes(b.get(o..o.checked_add(2)?)?.try_into().ok()?))
}
fn u64_at(b: &[u8], o: u64) -> Option<u64> {
    let o = usize::try_from(o).ok()?;
    Some(u64::from_le_bytes(b.get(o..o.checked_add(8)?)?.try_into().ok()?))
}

/// `x` rounded up to 4 – None on overflow.
fn align4(x: u64) -> Option<u64> {
    Some(x.checked_add(3)? & !3)
}

/// The ABI a program was built for, from its program headers alone (docs/abi/README.md):
/// every PT_NOTE inside the file (checked_add), at most 4 of them, each at most 4 KiB,
/// 4-aligned, not overlapping another PT_NOTE or the ELF / program headers; every note in it
/// (any owner) with lengths that stay inside its PT_NOTE; a name starting with "DeSo" exactly
/// "DeSo\0" with zero padding (types other than 1 skipped).  No DeSo OS note = a program from
/// before ABI 1.0 = 1.0; exactly one valid note = its version; a parse error is never "no
/// note".  Called on a header `elf::parse` has already checked.
pub fn abi_of(b: &[u8]) -> Result<(u16, u16), AbiError> {
    let bad = AbiError::BadNote;
    let len = b.len() as u64;
    let phoff = u64_at(b, 32).ok_or(bad)?;
    let phentsize = u16_at(b, 54).ok_or(bad)? as u64;
    let phnum = u16_at(b, 56).ok_or(bad)? as u64;
    let ph_end = phnum.checked_mul(phentsize).and_then(|n| n.checked_add(phoff)).ok_or(bad)?;
    let mut areas: [(u64, u64); MAX_NOTE_HEADERS] = [(0, 0); MAX_NOTE_HEADERS];
    let mut count = 0;
    let mut found: Option<(u16, u16, u32)> = None;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if u32_at(b, ph) != Some(PT_NOTE) {
            continue;
        }
        let off = u64_at(b, ph + 8).ok_or(bad)?;
        let size = u64_at(b, ph + 32).ok_or(bad)?;
        let end = off.checked_add(size).ok_or(bad)?;
        if count == MAX_NOTE_HEADERS || end > len || size > MAX_NOTE_BYTES || off % 4 != 0 {
            return Err(bad);
        }
        // Not on the ELF header or the program header table, not on another PT_NOTE
        // (an empty PT_NOTE overlaps nothing).
        let overlaps = |lo: u64, hi: u64| size != 0 && off < hi && lo < end;
        if overlaps(0, 64) || overlaps(phoff, ph_end) || areas[..count].iter().any(|&(lo, hi)| overlaps(lo, hi)) {
            return Err(bad);
        }
        areas[count] = (off, end);
        count += 1;
        let mut pos = off;
        while pos < end {
            if end - pos < 12 {
                return Err(bad);
            }
            let namesz = u32_at(b, pos).ok_or(bad)? as u64;
            let descsz = u32_at(b, pos + 4).ok_or(bad)? as u64;
            let kind = u32_at(b, pos + 8).ok_or(bad)?;
            let name = pos + 12;
            let desc = name.checked_add(align4(namesz).ok_or(bad)?).ok_or(bad)?;
            let next = desc.checked_add(align4(descsz).ok_or(bad)?).ok_or(bad)?;
            if next > end {
                return Err(bad);
            }
            // The owner "DeSo" is ours: a name that starts with it must be exactly "DeSo\0" with zero
            // padding – a damaged name of our note is refused, not taken for another owner's note.
            // (A changed letter, "DeSx\0", cannot be told from another owner; a signature covers that.)
            let start = name as usize;
            let deso_owner = namesz >= 4 && &b[start..start + 4] == &NOTE_NAME[..4];
            if deso_owner && (namesz != NOTE_NAME.len() as u64 || b[start + 4] != 0 || b[start + 5..desc as usize].iter().any(|&x| x != 0)) {
                return Err(bad);
            }
            // Other types of the "DeSo" owner are kept for later versions: checked for shape, skipped.
            let ours = deso_owner && kind == NT_DESO_ABI;
            if ours {
                if descsz != 8 {
                    return Err(bad);
                }
                if found.is_some() {
                    return Err(AbiError::Twice);
                }
                let major = u16_at(b, desc).ok_or(bad)?;
                let minor = u16_at(b, desc + 2).ok_or(bad)?;
                let flags = u32_at(b, desc + 4).ok_or(bad)?;
                found = Some((major, minor, flags));
            }
            pos = next;
        }
    }
    let Some((major, minor, flags)) = found else { return Ok((1, 0)) };
    if flags != 0 {
        return Err(AbiError::Flags(flags));
    }
    if major != ABI_MAJOR {
        return Err(AbiError::OtherMajor(major, minor));
    }
    if minor > ABI_MINOR {
        return Err(AbiError::Newer(major, minor));
    }
    Ok((major, minor))
}

/// Validates the file and builds the address space (the process is not running yet).
pub fn load(bytes: &[u8], args: &[&str]) -> Result<Loaded, LoadError> {
    let image = elf::parse(bytes).map_err(LoadError::Elf)?;
    // The ABI note before anything is mapped.
    abi_of(bytes).map_err(LoadError::Abi)?;
    // Segments do not overlap (pages may be shared – the rights are merged below).
    let segs = image.segments();
    for (i, a) in segs.iter().enumerate() {
        if segs[i + 1..].iter().any(|c| a.vaddr < c.end() && c.vaddr < a.end()) {
            return Err(LoadError::Overlap);
        }
    }
    for seg in image.segments() {
        if seg.vaddr < USER_MIN || seg.end() > USER_MAX {
            return Err(LoadError::OutsideUserSpace);
        }
        if seg.writable() && seg.executable() {
            return Err(LoadError::WriteAndExecute);
        }
    }
    let (lo, hi) = image.span();
    if hi - lo > MAX_IMAGE {
        return Err(LoadError::TooBig);
    }
    if !image.entry_in_code() {
        return Err(LoadError::EntryNotInCode);
    }
    if args.len() > MAX_ARGS || args.iter().map(|a| a.len() + 1).sum::<usize>() > MAX_ARG_BYTES {
        return Err(LoadError::TooManyArgs);
    }

    let mut space = AddressSpace::new().ok_or(LoadError::NoMemory)?;
    let nx = nx_flag();
    for seg in image.segments() {
        let mut flags = USER;
        if seg.writable() {
            flags |= WRITABLE;
        }
        if !seg.executable() {
            flags |= nx;
        }
        let mut page = page_down(seg.vaddr);
        while page < page_up(seg.end()) {
            match space.translate(page) {
                None => {
                    space.map_new(page, flags).ok_or(LoadError::NoMemory)?;
                }
                Some((_, old)) => {
                    // Page shared with the previous segment: union of rights,
                    // still W^X.
                    let w = (old | flags) & WRITABLE;
                    let exec = (old & NO_EXECUTE == 0 && nx != 0) || flags & nx == 0;
                    if w != 0 && exec && nx != 0 {
                        return Err(LoadError::WriteAndExecute);
                    }
                    let merged = USER | w | if exec { 0 } else { nx };
                    space.set_flags(page, merged);
                }
            }
            page += PAGE;
        }
        let data = &bytes[seg.offset as usize..(seg.offset + seg.filesz) as usize];
        if !space.write_bytes(seg.vaddr, data) {
            return Err(LoadError::NoMemory);
        }
    }

    // Stack (the page below it stays empty – guard).
    let mut va = USER_STACK_TOP - USER_STACK_SIZE;
    while va < USER_STACK_TOP {
        space.map_new(va, USER | WRITABLE | nx).ok_or(LoadError::NoMemory)?;
        va += PAGE;
    }
    let rsp = push_args(&mut space, args)?;
    Ok(Loaded { space, entry: image.entry, rsp, image_end: page_up(hi) })
}

/// SysV layout at the top of the stack; returns RSP (16-byte aligned, points at argc).
fn push_args(space: &mut AddressSpace, args: &[&str]) -> Result<u64, LoadError> {
    let mut sp = USER_STACK_TOP;
    let mut pointers = Vec::with_capacity(args.len());
    for a in args {
        sp -= a.len() as u64 + 1;
        let mut s = Vec::with_capacity(a.len() + 1);
        s.extend_from_slice(a.as_bytes());
        s.push(0);
        space.write_bytes(sp, &s);
        pointers.push(sp);
    }
    sp &= !15;
    // argc, argv[n], NULL, envp NULL, auxv (AT_NULL, 0)
    let mut words: Vec<u64> = Vec::with_capacity(args.len() + 5);
    words.push(args.len() as u64);
    words.extend_from_slice(&pointers);
    words.extend_from_slice(&[0, 0, 0, 0]);
    if words.len() % 2 == 1 {
        sp -= 8; // RSP % 16 == 0 at argc
    }
    sp -= words.len() as u64 * 8;
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    if !space.write_bytes(sp, &bytes) {
        return Err(LoadError::NoMemory);
    }
    Ok(sp)
}
