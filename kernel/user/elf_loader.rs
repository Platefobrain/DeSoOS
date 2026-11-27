// Loading ELF programs into a process address space.
//
// The rules a program must meet live in common/elf.rs (`check_program`, v0.82 – desopkg checks
// a package's programs with the same function before installing them):
//   * segments only in the load range of ABI 1.0 (docs/abi/README.md): from USER_MIN
//     (the first 1 MiB is empty – null pointer) to USER_MAX – below the heap's largest
//     reach (image end + BRK_MAX) plus a 1 GiB gap before the mmap area (MMAP_BASE), so a
//     program anywhere in the range never meets its heap, mmap or stack,
//   * the ABI note (`abi_of`),
//   * W^X: a segment cannot be both writable and executable; pages
//     without PF_X get NX,
//   * entry point in an executable segment, the whole image at most 64 MiB.
// Here: the arguments, the mapping, .bss (memsz > filesz) = zeroed frames.
// Stack: 16 KiB below USER_STACK_TOP, and on it (SysV): argc, argv[], NULL,
// envp NULL, auxv AT_NULL; the argument strings at the very top.

use alloc::vec::Vec;

use super::space::AddressSpace;
use super::{USER_STACK_SIZE, USER_STACK_TOP};
use crate::elf::{self, ElfError, ProgramError};
use crate::memory::{nx_flag, NO_EXECUTE, USER, WRITABLE};

const PAGE: u64 = 4096;
pub const USER_MIN: u64 = elf::PROGRAM_MIN;
pub const USER_MAX: u64 = elf::PROGRAM_MAX;
pub const MAX_IMAGE: u64 = elf::PROGRAM_MAX_IMAGE;
pub const MAX_ARGS: usize = 32;
pub const MAX_ARG_BYTES: usize = 4096;
// common/elf.rs writes the load range out as numbers (desopkg has no kernel constants): they
// must stay what the address space layout gives.
const _: () = assert!(USER_MAX == super::vm::MMAP_BASE - super::vm::BRK_MAX - (1 << 30));

/// The ABI this kernel gives (abi/abi.toml through kernel/user/abi_generated.rs).
pub const ABI_MAJOR: u16 = super::abi_generated::ABI_MAJOR;
pub const ABI_MINOR: u16 = super::abi_generated::ABI_MINOR;

/// Why a program's ABI note refuses it (exec: ERROR_ABI) – common/elf.rs.
pub use crate::elf::AbiError;

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

/// A program file: a slice in memory, or the frames exec read it into (`ProgramFile`).
pub trait Source {
    fn size(&self) -> u64;
    /// `buf.len()` bytes at `off`; false when they are not all inside the file.
    fn read_at(&self, off: u64, buf: &mut [u8]) -> bool;
}

impl Source for [u8] {
    fn size(&self) -> u64 {
        self.len() as u64
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> bool {
        let Ok(o) = usize::try_from(off) else { return false };
        match o.checked_add(buf.len()).and_then(|e| self.get(o..e)) {
            Some(s) => {
                buf.copy_from_slice(s);
                true
            }
            None => false,
        }
    }
}

impl Source for alloc::vec::Vec<u8> {
    fn size(&self) -> u64 {
        self.len() as u64
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> bool {
        self[..].read_at(off, buf)
    }
}

/// The ABI a program was built for (common/elf.rs `abi_of_with`, against this kernel's ABI) –
/// the self-tests ask it alone; `load` runs it inside `check_program`.
#[cfg_attr(not(selftest), allow(dead_code))]
pub fn abi_of<S: Source + ?Sized>(b: &S) -> Result<(u16, u16), AbiError> {
    let len = usize::try_from(b.size()).map_err(|_| AbiError::BadNote)?;
    elf::abi_of_with(len, &mut |o, buf| b.read_at(o as u64, buf), (ABI_MAJOR, ABI_MINOR))
}

/// Validates the file and builds the address space (the process is not running yet).
pub fn load<S: Source + ?Sized>(file: &S, args: &[&str]) -> Result<Loaded, LoadError> {
    let len = usize::try_from(file.size()).map_err(|_| LoadError::Elf(ElfError::TooSmall))?;
    // Every rule before anything is mapped: the same function desopkg runs on a package's programs.
    let (image, _abi) = elf::check_program(len, &mut |o, buf| file.read_at(o as u64, buf), (ABI_MAJOR, ABI_MINOR)).map_err(|e| match e {
        ProgramError::Elf(e) => LoadError::Elf(e),
        ProgramError::Abi(a) => LoadError::Abi(a),
        ProgramError::Overlap => LoadError::Overlap,
        ProgramError::OutsideUserSpace => LoadError::OutsideUserSpace,
        ProgramError::WriteAndExecute => LoadError::WriteAndExecute,
        ProgramError::EntryNotInCode => LoadError::EntryNotInCode,
        ProgramError::TooBig => LoadError::TooBig,
    })?;
    let (_, hi) = image.span();
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
        // The segment's bytes, a page at a time (the file may be in frames, not one buffer).
        let mut chunk = [0u8; PAGE as usize];
        let mut done = 0u64;
        while done < seg.filesz {
            let n = (seg.filesz - done).min(PAGE) as usize;
            if !file.read_at(seg.offset + done, &mut chunk[..n]) {
                return Err(LoadError::Elf(ElfError::DataOutsideFile));
            }
            if !space.write_bytes(seg.vaddr + done, &chunk[..n]) {
                return Err(LoadError::NoMemory);
            }
            done += n as u64;
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
