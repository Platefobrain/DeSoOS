// ELF64 (x86_64) parser shared by DSB (loading the kernel) and the kernel
// (loading user programs).  No allocation and no dependencies –
// it only validates headers and returns the PT_LOAD segments.  WHERE the segments
// may live (kernel in the upper half, program in the lower half) is up to the caller.
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

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o.checked_add(2)?)?.try_into().ok()?))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o.checked_add(4)?)?.try_into().ok()?))
}
fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o.checked_add(8)?)?.try_into().ok()?))
}

pub fn parse(elf: &[u8]) -> Result<Elf, ElfError> {
    if elf.len() < 64 {
        return Err(ElfError::TooSmall);
    }
    if &elf[0..4] != b"\x7fELF" {
        return Err(ElfError::BadMagic);
    }
    if elf[4] != 2 {
        return Err(ElfError::Not64Bit);
    }
    if elf[5] != 1 {
        return Err(ElfError::NotLittleEndian);
    }
    if u16_at(elf, 18) != Some(EM_X86_64) {
        return Err(ElfError::NotX86_64);
    }
    if u16_at(elf, 16) != Some(ET_EXEC) {
        return Err(ElfError::NotExecutable);
    }
    let entry = u64_at(elf, 24).ok_or(ElfError::TooSmall)?;
    let phoff = u64_at(elf, 32).ok_or(ElfError::TooSmall)? as usize;
    let phentsize = u16_at(elf, 54).ok_or(ElfError::TooSmall)? as usize;
    let phnum = u16_at(elf, 56).ok_or(ElfError::TooSmall)? as usize;
    if phentsize < 56 || phnum > 256 {
        return Err(ElfError::BadProgramHeaders);
    }
    match phnum.checked_mul(phentsize).and_then(|n| n.checked_add(phoff)) {
        Some(end) if end <= elf.len() => {}
        _ => return Err(ElfError::BadProgramHeaders),
    }

    let mut out = Elf { entry, segments: [Segment::default(); MAX_SEGMENTS], count: 0 };
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if u32_at(elf, ph) != Some(PT_LOAD) {
            continue;
        }
        let bad = ElfError::BadProgramHeaders;
        let seg = Segment {
            flags: u32_at(elf, ph + 4).ok_or(bad)?,
            offset: u64_at(elf, ph + 8).ok_or(bad)?,
            vaddr: u64_at(elf, ph + 16).ok_or(bad)?,
            filesz: u64_at(elf, ph + 32).ok_or(bad)?,
            memsz: u64_at(elf, ph + 40).ok_or(bad)?,
        };
        if seg.memsz == 0 {
            continue;
        }
        if seg.filesz > seg.memsz {
            return Err(ElfError::FileSizeTooBig);
        }
        match seg.offset.checked_add(seg.filesz) {
            Some(e) if e <= elf.len() as u64 => {}
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
