// M15: ładowanie programów ELF do przestrzeni adresowej procesu.
//
// Ten sam parser co w DSB (common/elf.rs) + zasady dla programów:
//   * segmenty tylko w dolnej połowie: od USER_MIN (pierwsze 1 MiB puste –
//     null pointer) do USER_MAX (pod stosem, z odstępem),
//   * W^X: segment nie może być naraz zapisywalny i wykonywalny; strony
//     bez PF_X dostają NX,
//   * punkt wejścia w segmencie wykonywalnym, cały obraz max 64 MiB,
//   * .bss (memsz > filesz) = wyzerowane ramki.
// Stos: 16 KiB pod USER_STACK_TOP, a na nim (SysV): argc, argv[], NULL,
// envp NULL, auxv AT_NULL; napisy argumentów na samej górze.

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
    /// RSP na starcie (wskazuje argc).
    pub rsp: u64,
    /// M17b.d: pierwszy adres za obrazem (sterta – stronę dalej).
    pub image_end: u64,
}

fn page_down(x: u64) -> u64 {
    x & !(PAGE - 1)
}
fn page_up(x: u64) -> u64 {
    (x + PAGE - 1) & !(PAGE - 1)
}

/// Sprawdza plik i buduje przestrzeń adresową (proces jeszcze nie działa).
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
                    // Strona dzielona z poprzednim segmentem: suma praw,
                    // nadal W^X.
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

    // Stos (strona pod nim zostaje pusta – strażnik).
    let mut va = USER_STACK_TOP - USER_STACK_SIZE;
    while va < USER_STACK_TOP {
        space.map_new(va, USER | WRITABLE | nx).ok_or(LoadError::NoMemory)?;
        va += PAGE;
    }
    let rsp = push_args(&mut space, args)?;
    Ok(Loaded { space, entry: image.entry, rsp, image_end: page_up(hi) })
}

/// Układ SysV na szczycie stosu; zwraca RSP (wyrównany do 16, wskazuje argc).
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
        sp -= 8; // RSP % 16 == 0 przy argc
    }
    sp -= words.len() as u64 * 8;
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    if !space.write_bytes(sp, &bytes) {
        return Err(LoadError::NoMemory);
    }
    Ok(sp)
}
