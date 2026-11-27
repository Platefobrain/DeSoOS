// ELF64 (x86_64) parser shared by DSB (loading the kernel), the kernel (loading user
// programs) and desopkg (checking a package's programs before they are installed, v0.82).
// No allocation and no dependencies – it only validates headers and returns the PT_LOAD
// segments.  WHERE the segments may live (kernel in the upper half, program in the lower
// half) is up to the caller; for user programs `check_program` below holds the rules of
// ABI 1.0, so the kernel's loader and desopkg accept exactly the same files.
//
// Checked: magic, 64-bit, little-endian, x86_64, type ET_EXEC (static
// executable, no relocations), program header table inside the file,
// filesz <= memsz, segment data inside the file, no address overflows.

#![allow(dead_code)]

pub const PT_LOAD: u32 = 1;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;
pub const MAX_SEGMENTS: usize = 16;

const EM_X86_64: u16 = 0x3E;
const ET_EXEC: u16 = 2;

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Segment {
    pub vaddr: u64,
    pub memsz: u64,
    pub offset: u64,
    pub filesz: u64,
    /// PF_R | PF_W | PF_X
    pub flags: u32,
}

impl Segment {
    pub fn end(&self) -> u64 {
        self.vaddr + self.memsz
    }
    pub fn writable(&self) -> bool {
        self.flags & PF_W != 0
    }
    pub fn executable(&self) -> bool {
        self.flags & PF_X != 0
    }
}

pub struct Elf {
    pub entry: u64,
    pub segments: [Segment; MAX_SEGMENTS],
    pub count: usize,
}

impl Elf {
    pub fn segments(&self) -> &[Segment] {
        &self.segments[..self.count]
    }
    /// Lowest and highest address (unaligned).
    pub fn span(&self) -> (u64, u64) {
        let start = self.segments().iter().map(|s| s.vaddr).min().unwrap_or(0);
        let end = self.segments().iter().map(|s| s.end()).max().unwrap_or(0);
        (start, end)
    }
    /// Whether the entry point lies in an executable segment.
    pub fn entry_in_code(&self) -> bool {
        self.segments().iter().any(|s| s.executable() && self.entry >= s.vaddr && self.entry < s.end())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    TooSmall,
    BadMagic,
    Not64Bit,
    NotLittleEndian,
    NotX86_64,
    NotExecutable,
    BadProgramHeaders,
    TooManySegments,
    FileSizeTooBig,
    DataOutsideFile,
    AddressOverflow,
    NoSegments,
}

impl ElfError {
    pub fn as_str(self) -> &'static str {
        match self {
            ElfError::TooSmall => "file too small for an ELF header",
            ElfError::BadMagic => "not an ELF file",
            ElfError::Not64Bit => "not a 64-bit ELF",
            ElfError::NotLittleEndian => "not little-endian",
            ElfError::NotX86_64 => "not an x86_64 program",
            ElfError::NotExecutable => "not a static executable (ET_EXEC)",
            ElfError::BadProgramHeaders => "program headers outside the file",
            ElfError::TooManySegments => "too many PT_LOAD segments",
            ElfError::FileSizeTooBig => "segment filesz > memsz",
            ElfError::DataOutsideFile => "segment data outside the file",
            ElfError::AddressOverflow => "segment address overflow",
            ElfError::NoSegments => "no PT_LOAD segments",
        }
    }
}

/// Bytes of the file at `o` – from a slice or from a file read piece by piece.
fn get<const N: usize>(read: &mut dyn FnMut(usize, &mut [u8]) -> bool, len: usize, o: usize) -> Option<[u8; N]> {
    if o.checked_add(N)? > len {
        return None;
    }
    let mut b = [0u8; N];
    if read(o, &mut b) { Some(b) } else { None }
}
fn u16_at(r: &mut dyn FnMut(usize, &mut [u8]) -> bool, len: usize, o: usize) -> Option<u16> {
    get::<2>(r, len, o).map(u16::from_le_bytes)
}
fn u32_at(r: &mut dyn FnMut(usize, &mut [u8]) -> bool, len: usize, o: usize) -> Option<u32> {
    get::<4>(r, len, o).map(u32::from_le_bytes)
}
fn u64_at(r: &mut dyn FnMut(usize, &mut [u8]) -> bool, len: usize, o: usize) -> Option<u64> {
    get::<8>(r, len, o).map(u64::from_le_bytes)
}

pub fn parse(elf: &[u8]) -> Result<Elf, ElfError> {
    parse_with(elf.len(), &mut |o, b| match elf.get(o..o + b.len()) {
        Some(s) => {
            b.copy_from_slice(s);
            true
        }
        None => false,
    })
}

/// `parse` on a file of `len` bytes read through `read(offset, buf)` (true = `buf` filled) –
/// the kernel loads programs from frames, not from one buffer.
pub fn parse_with(len: usize, read: &mut dyn FnMut(usize, &mut [u8]) -> bool) -> Result<Elf, ElfError> {
    if len < 64 {
        return Err(ElfError::TooSmall);
    }
    let head = get::<8>(read, len, 0).ok_or(ElfError::TooSmall)?;
    if &head[0..4] != b"\x7fELF" {
        return Err(ElfError::BadMagic);
    }
    if head[4] != 2 {
        return Err(ElfError::Not64Bit);
    }
    if head[5] != 1 {
        return Err(ElfError::NotLittleEndian);
    }
    if u16_at(read, len, 18) != Some(EM_X86_64) {
        return Err(ElfError::NotX86_64);
    }
    if u16_at(read, len, 16) != Some(ET_EXEC) {
        return Err(ElfError::NotExecutable);
    }
    let entry = u64_at(read, len, 24).ok_or(ElfError::TooSmall)?;
    let phoff = u64_at(read, len, 32).ok_or(ElfError::TooSmall)? as usize;
    let phentsize = u16_at(read, len, 54).ok_or(ElfError::TooSmall)? as usize;
    let phnum = u16_at(read, len, 56).ok_or(ElfError::TooSmall)? as usize;
    if phentsize < 56 || phnum > 256 {
        return Err(ElfError::BadProgramHeaders);
    }
    match phnum.checked_mul(phentsize).and_then(|n| n.checked_add(phoff)) {
        Some(end) if end <= len => {}
        _ => return Err(ElfError::BadProgramHeaders),
    }

    let mut out = Elf { entry, segments: [Segment::default(); MAX_SEGMENTS], count: 0 };
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if u32_at(read, len, ph) != Some(PT_LOAD) {
            continue;
        }
        let bad = ElfError::BadProgramHeaders;
        let seg = Segment {
            flags: u32_at(read, len, ph + 4).ok_or(bad)?,
            offset: u64_at(read, len, ph + 8).ok_or(bad)?,
            vaddr: u64_at(read, len, ph + 16).ok_or(bad)?,
            filesz: u64_at(read, len, ph + 32).ok_or(bad)?,
            memsz: u64_at(read, len, ph + 40).ok_or(bad)?,
        };
        if seg.memsz == 0 {
            continue;
        }
        if seg.filesz > seg.memsz {
            return Err(ElfError::FileSizeTooBig);
        }
        match seg.offset.checked_add(seg.filesz) {
            Some(e) if e <= len as u64 => {}
            _ => return Err(ElfError::DataOutsideFile),
        }
        if seg.vaddr.checked_add(seg.memsz).is_none() {
            return Err(ElfError::AddressOverflow);
        }
        if out.count == MAX_SEGMENTS {
            return Err(ElfError::TooManySegments);
        }
        out.segments[out.count] = seg;
        out.count += 1;
    }
    if out.count == 0 {
        return Err(ElfError::NoSegments);
    }
    Ok(out)
}

// ------------------------------------------------------------
// User programs: the ABI note and the load rules (ABI 1.0, docs/abi/README.md).
// Moved here from kernel/user/elf_loader.rs (v0.82) – the kernel's loader and desopkg call
// the same code.  Nothing here maps memory: it only says whether a file is a program the
// kernel would start.
// ------------------------------------------------------------

/// The load range of ABI 1.0: from 1 MiB (the first 1 MiB stays empty – null pointer) to below
/// the heap's largest reach plus a 1 GiB gap before the mmap area.  The kernel checks at
/// compile time that this is MMAP_BASE - BRK_MAX - 1 GiB (kernel/user/elf_loader.rs).
pub const PROGRAM_MIN: u64 = 0x10_0000;
pub const PROGRAM_MAX: u64 = 0x0000_1000_0000_0000 - (1 << 30) - (1 << 30);
/// The whole image (lowest to highest address) at most 64 MiB.
pub const PROGRAM_MAX_IMAGE: u64 = 64 * 1024 * 1024;

/// The ABI note's owner and type (libdeso sys.rs, sdk/libdeso/link.ld).
pub const NOTE_NAME: &[u8; 5] = b"DeSo\0";
pub const NT_DESO_ABI: u32 = 1;
pub const PT_NOTE: u32 = 4;
/// At most this many PT_NOTE headers, each at most this long.
pub const MAX_NOTE_HEADERS: usize = 4;
pub const MAX_NOTE_BYTES: u64 = 4096;

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

/// Why a file is not a program ABI 1.0 starts (everything `load` checks before mapping).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgramError {
    Elf(ElfError),
    Abi(AbiError),
    Overlap,
    OutsideUserSpace,
    WriteAndExecute,
    EntryNotInCode,
    TooBig,
}

impl ProgramError {
    pub fn as_str(self) -> &'static str {
        match self {
            ProgramError::Elf(e) => e.as_str(),
            ProgramError::Abi(_) => "the program needs another DeSo OS ABI (its ELF ABI note)",
            ProgramError::Overlap => "segments overlap",
            ProgramError::OutsideUserSpace => "segment outside the user address space",
            ProgramError::WriteAndExecute => "segment both writable and executable (W^X)",
            ProgramError::EntryNotInCode => "entry point not in an executable segment",
            ProgramError::TooBig => "program image too big (max 64 MiB)",
        }
    }
}

/// `x` rounded up to 4 – None on overflow.
fn align4(x: u64) -> Option<u64> {
    Some(x.checked_add(3)? & !3)
}

/// Bytes at a 64-bit offset (None outside the file or past usize).
fn at<const N: usize>(read: &mut dyn FnMut(usize, &mut [u8]) -> bool, len: usize, o: u64) -> Option<[u8; N]> {
    get::<N>(read, len, usize::try_from(o).ok()?)
}

/// The ABI a program was built for, from its program headers alone (docs/abi/README.md):
/// every PT_NOTE inside the file (checked_add), at most 4 of them, each at most 4 KiB,
/// 4-aligned, not overlapping another PT_NOTE or the ELF / program headers; every note in it
/// (any owner) with lengths that stay inside its PT_NOTE; a name starting with "DeSo" exactly
/// "DeSo\0" with zero padding (types other than 1 skipped).  No DeSo OS note = a program from
/// before ABI 1.0 = 1.0; exactly one valid note = its version; a parse error is never "no
/// note".  `system` – the ABI (major, minor) of the system that would run it.  Called on a
/// header `parse` has already checked.
pub fn abi_of_with(len: usize, read: &mut dyn FnMut(usize, &mut [u8]) -> bool, system: (u16, u16)) -> Result<(u16, u16), AbiError> {
    let bad = AbiError::BadNote;
    let len64 = len as u64;
    let phoff = at::<8>(read, len, 32).map(u64::from_le_bytes).ok_or(bad)?;
    let phentsize = at::<2>(read, len, 54).map(u16::from_le_bytes).ok_or(bad)? as u64;
    let phnum = at::<2>(read, len, 56).map(u16::from_le_bytes).ok_or(bad)? as u64;
    let ph_end = phnum.checked_mul(phentsize).and_then(|n| n.checked_add(phoff)).ok_or(bad)?;
    let mut areas: [(u64, u64); MAX_NOTE_HEADERS] = [(0, 0); MAX_NOTE_HEADERS];
    let mut count = 0;
    let mut found: Option<(u16, u16, u32)> = None;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if at::<4>(read, len, ph).map(u32::from_le_bytes) != Some(PT_NOTE) {
            continue;
        }
        let off = at::<8>(read, len, ph + 8).map(u64::from_le_bytes).ok_or(bad)?;
        let size = at::<8>(read, len, ph + 32).map(u64::from_le_bytes).ok_or(bad)?;
        let end = off.checked_add(size).ok_or(bad)?;
        if count == MAX_NOTE_HEADERS || end > len64 || size > MAX_NOTE_BYTES || off % 4 != 0 {
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
            let namesz = at::<4>(read, len, pos).map(u32::from_le_bytes).ok_or(bad)? as u64;
            let descsz = at::<4>(read, len, pos + 4).map(u32::from_le_bytes).ok_or(bad)? as u64;
            let kind = at::<4>(read, len, pos + 8).map(u32::from_le_bytes).ok_or(bad)?;
            let name = pos + 12;
            let desc = name.checked_add(align4(namesz).ok_or(bad)?).ok_or(bad)?;
            let next = desc.checked_add(align4(descsz).ok_or(bad)?).ok_or(bad)?;
            if next > end {
                return Err(bad);
            }
            // The owner "DeSo" is ours: a name that starts with it must be exactly "DeSo\0" with zero
            // padding – a damaged name of our note is refused, not taken for another owner's note.
            // (A changed letter, "DeSx\0", cannot be told from another owner; a signature covers that.)
            let deso_owner = namesz >= 4 && at::<4>(read, len, name).is_some_and(|o| o == NOTE_NAME[..4]);
            if deso_owner {
                // name + padding: 8 bytes for "DeSo\0" (desc - name = align4(namesz)).
                let pad = if desc - name == 8 { at::<8>(read, len, name) } else { None };
                match pad {
                    Some(p) if namesz == NOTE_NAME.len() as u64 && p[4..].iter().all(|&x| x == 0) => {}
                    _ => return Err(bad),
                }
            }
            // Other types of the "DeSo" owner are kept for later versions: checked for shape, skipped.
            if deso_owner && kind == NT_DESO_ABI {
                if descsz != 8 {
                    return Err(bad);
                }
                if found.is_some() {
                    return Err(AbiError::Twice);
                }
                let d = at::<8>(read, len, desc).ok_or(bad)?;
                let major = u16::from_le_bytes([d[0], d[1]]);
                let minor = u16::from_le_bytes([d[2], d[3]]);
                let flags = u32::from_le_bytes([d[4], d[5], d[6], d[7]]);
                found = Some((major, minor, flags));
            }
            pos = next;
        }
    }
    let Some((major, minor, flags)) = found else { return Ok((1, 0)) };
    if flags != 0 {
        return Err(AbiError::Flags(flags));
    }
    if major != system.0 {
        return Err(AbiError::OtherMajor(major, minor));
    }
    if minor > system.1 {
        return Err(AbiError::Newer(major, minor));
    }
    Ok((major, minor))
}

/// Every rule the kernel checks before it maps a program (kernel/user/elf_loader.rs `load`):
/// the ELF header (`parse_with`), the ABI note (`abi_of_with` against `system`), segments
/// that do not overlap, inside [PROGRAM_MIN, PROGRAM_MAX), W^X, the image at most 64 MiB,
/// the entry point in an executable segment.  Returns the parsed header and the ABI.
pub fn check_program(len: usize, read: &mut dyn FnMut(usize, &mut [u8]) -> bool, system: (u16, u16)) -> Result<(Elf, (u16, u16)), ProgramError> {
    let image = parse_with(len, read).map_err(ProgramError::Elf)?;
    // The ABI note before anything else.
    let abi = abi_of_with(len, read, system).map_err(ProgramError::Abi)?;
    // Segments do not overlap (pages may be shared – the loader merges the rights).
    let segs = image.segments();
    for (i, a) in segs.iter().enumerate() {
        if segs[i + 1..].iter().any(|c| a.vaddr < c.end() && c.vaddr < a.end()) {
            return Err(ProgramError::Overlap);
        }
    }
    for seg in segs {
        if seg.vaddr < PROGRAM_MIN || seg.end() > PROGRAM_MAX {
            return Err(ProgramError::OutsideUserSpace);
        }
        if seg.writable() && seg.executable() {
            return Err(ProgramError::WriteAndExecute);
        }
    }
    let (lo, hi) = image.span();
    if hi - lo > PROGRAM_MAX_IMAGE {
        return Err(ProgramError::TooBig);
    }
    if !image.entry_in_code() {
        return Err(ProgramError::EntryNotInCode);
    }
    Ok((image, abi))
}

/// `check_program` on a file in memory.
pub fn check_program_bytes(file: &[u8], system: (u16, u16)) -> Result<(Elf, (u16, u16)), ProgramError> {
    check_program(file.len(), &mut |o, b| match o.checked_add(b.len()).and_then(|e| file.get(o..e)) {
        Some(s) => {
            b.copy_from_slice(s);
            true
        }
        None => false,
    }, system)
}
