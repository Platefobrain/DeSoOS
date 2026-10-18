// Loading ELF programs into a process address space.
//
// The same parser as in the bootloader (common/elf.rs) + rules for programs:
//   * segments only in the lower half: from USER_MIN (the first 1 MiB is empty –
//     null pointer) to USER_MAX (below the stack, with a gap),
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
pub const USER_MAX: u64 = USER_STACK_TOP - USER_STACK_SIZE - 0x10_0000;
const MAX_IMAGE: u64 = 64 * 1024 * 1024;
const MAX_ARGS: usize = 32;
const MAX_ARG_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    Elf(ElfError),
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

/// Validates the file and builds the address space (the process is not running yet).
pub fn load(bytes: &[u8], args: &[&str]) -> Result<Loaded, LoadError> {
    let image = elf::parse(bytes).map_err(LoadError::Elf)?;
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
