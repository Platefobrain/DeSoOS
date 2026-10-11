// M4: mapowanie on-demand.
//
// Obszar DEMAND_START..DEMAND_START+DEMAND_SIZE jest "wirtualny": nie ma
// żadnych stron, dopóki ktoś się do niego nie odwoła.  Pierwszy dostęp
// (odczyt lub zapis) kończy się #PF; handler alokuje ramkę, zeruje ją
// i mapuje pod adresem, który spowodował błąd, po czym CPU ponawia
// instrukcję.
//
// Zwolnienie: unmap_page(addr) + free_frame(ramka).

use core::sync::atomic::{AtomicU64, Ordering};

use super::{alloc_frame, free_frame, map_page};

#[cfg(selftest)]
use crate::arch::x86_64::exceptions::probe_read;
#[cfg(selftest)]
use crate::serial_println;
#[cfg(selftest)]
use super::{free_frame_count, translate, unmap_page};

const PAGE_SIZE: u64 = 4096;

// PML4[416]; z dala od direct mapy (PML4[256..384)), heapa (PML4[384])
// i slotu rekurencyjnego (PML4[510]).
pub const DEMAND_START: u64 = 0xffff_d000_0000_0000;
pub const DEMAND_SIZE: u64 = 256 * 1024 * 1024;

// Bity kodu błędu #PF.
const PF_PROTECTION: u64 = 1 << 0;
const PF_USER: u64 = 1 << 2;
const PF_RESERVED: u64 = 1 << 3;
const PF_INSTRUCTION_FETCH: u64 = 1 << 4;

static FAULTS_HANDLED: AtomicU64 = AtomicU64::new(0);

pub fn in_demand_region(address: u64) -> bool {
    address >= DEMAND_START && address < DEMAND_START + DEMAND_SIZE
}

#[allow(dead_code)]
pub fn faults_handled() -> u64 {
    FAULTS_HANDLED.load(Ordering::SeqCst)
}

/// Wołane z handlera #PF.  `true` = fault obsłużony, instrukcję można
/// ponowić; `false` = to prawdziwy błąd.
pub fn handle_page_fault(address: u64, error_code: u64) -> bool {
    // Tylko dostęp do nieobecnej strony w trybie kernela, nie fetch instrukcji.
    if error_code & (PF_PROTECTION | PF_USER | PF_RESERVED | PF_INSTRUCTION_FETCH) != 0 {
        return false;
    }
    if !in_demand_region(address) {
        return false;
    }

    let page = address & !(PAGE_SIZE - 1);

    let Some(frame) = alloc_frame() else {
        return false;
    };

    // Nowa strona zawsze zerowa (ramka mogła zawierać cudze dane).
    // Pamięć fizyczna jest zmapowana identycznie, więc piszemy wprost.
    unsafe {
        core::ptr::write_bytes(super::phys_to_virt(frame) as *mut u8, 0, PAGE_SIZE as usize);
    }

    if !map_page(page, frame, super::kernel_data_flags()) {
        free_frame(frame);
        return false;
    }

    FAULTS_HANDLED.fetch_add(1, Ordering::SeqCst);
    true
}

// ------------------------------------------------------------
// TEST (tylko build z --cfg selftest)
// ------------------------------------------------------------

#[cfg(selftest)]
macro_rules! check {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            serial_println!("[MM TEST] FAIL: {}", format_args!($($msg)*));
            return;
        }
    };
}

#[cfg(selftest)]
pub fn self_test() {
    serial_println!("[MM TEST] Starting on-demand paging tests...");
    crate::selftest::begin();

    // Ramka z "śmieciami" trafia na szczyt listy wolnych, więc pierwszy
    // demand fault dostanie właśnie ją – test zerowania jest wtedy uczciwy.
    let dirty = match alloc_frame() {
        Some(f) => f,
        None => {
            serial_println!("[MM TEST] FAIL: alloc_frame");
            return;
        }
    };
    unsafe {
        core::ptr::write_bytes(super::phys_to_virt(dirty) as *mut u8, 0xAA, PAGE_SIZE as usize);
    }
    check!(free_frame(dirty), "free dirty frame");

    let free_start = free_frame_count();
    let faults_start = faults_handled();

    // 1. Region pusty, dopóki nikt go nie dotknie.
    check!(translate(DEMAND_START).is_none(), "demand region pre-mapped");
    check!(in_demand_region(DEMAND_START) && !in_demand_region(DEMAND_START + DEMAND_SIZE), "region bounds");
    serial_println!("[MM TEST] 1/7 demand region initially unmapped PASS");

    // 2. Pierwszy zapis: fault -> ramka + 2 tablice (PD, PT; PDPT górnej
    //    połowy istnieje od startu – M13a), dane zapisane, reszta zerowa.
    let p0 = DEMAND_START as *mut u64;
    unsafe {
        core::ptr::write_volatile(p0, 0x1234_5678_9abc_def0);
    }
    check!(faults_handled() == faults_start + 1, "fault not counted");
    check!(translate(DEMAND_START).is_some(), "page not mapped after fault");
    check!(
        free_start - free_frame_count() == 3,
        "expected page + 2 tables, got {}",
        free_start - free_frame_count()
    );
    unsafe {
        check!(core::ptr::read_volatile(p0) == 0x1234_5678_9abc_def0, "written value lost");
        for i in 1..512usize {
            check!(core::ptr::read_volatile(p0.add(i)) == 0, "word {} not zeroed", i);
        }
    }
    serial_println!("[MM TEST] 2/7 write fault maps a zeroed page PASS");

    // 3. Odczyt też mapuje (zerową stronę).
    let read_addr = DEMAND_START + 3 * PAGE_SIZE;
    let v = unsafe { core::ptr::read_volatile(read_addr as *const u64) };
    check!(v == 0, "read of fresh page = {:#x}", v);
    check!(faults_handled() == faults_start + 2, "read fault not counted");
    check!(translate(read_addr).is_some(), "read fault did not map");
    serial_println!("[MM TEST] 3/7 read fault maps a page PASS");

    // 4. Rzadki dostęp: inne PT (100 MiB dalej) i inny PD (2 GiB dalej).
    let far1 = DEMAND_START + 100 * 1024 * 1024;
    let far2 = DEMAND_START + 200 * 1024 * 1024;
    unsafe {
        core::ptr::write_volatile(far1 as *mut u64, 0x11);
        core::ptr::write_volatile(far2 as *mut u64, 0x22);
        check!(core::ptr::read_volatile(far1 as *const u64) == 0x11, "far1");
        check!(core::ptr::read_volatile(far2 as *const u64) == 0x22, "far2");
    }
    check!(faults_handled() == faults_start + 4, "sparse faults not counted");
    serial_println!("[MM TEST] 4/7 sparse access across page tables PASS");

    // 5. Ciągły zakres: 64 strony, każda z własnym wzorcem.
    let base = DEMAND_START + 8 * 1024 * 1024;
    for i in 0..64u64 {
        unsafe {
            core::ptr::write_volatile((base + i * PAGE_SIZE) as *mut u64, 0xC0DE_0000 + i);
        }
    }
    for i in 0..64u64 {
        let v = unsafe { core::ptr::read_volatile((base + i * PAGE_SIZE) as *const u64) };
        check!(v == 0xC0DE_0000 + i, "page {} holds {:#x}", i, v);
    }
    check!(faults_handled() == faults_start + 4 + 64, "range faults not counted");
    serial_println!("[MM TEST] 5/7 64-page range PASS");

    // 6. Adresy poza obszarem on-demand nadal kończą się prawdziwym błędem:
    //    strona 0 (pułapka na null z M2) i pierwszy bajt za obszarem.
    for address in [0u64, DEMAND_START + DEMAND_SIZE, DEMAND_START - PAGE_SIZE] {
        let faults_before = faults_handled();
        match probe_read(address) {
            Some(f) => {
                check!(f.vector == 14, "vector {} at {:#x}", f.vector, address);
                check!(f.cr2 == address, "CR2 {:#x} != {:#x}", f.cr2, address);
            }
            None => {
                serial_println!("[MM TEST] FAIL: read of {:#x} succeeded", address);
                return;
            }
        }
        check!(faults_handled() == faults_before, "{:#x} was demand-mapped", address);
        check!(translate(address).is_none(), "{:#x} got mapped", address);
    }
    serial_println!("[MM TEST] 6/7 faults outside the region stay errors PASS");

    // 7. Sprzątanie: unmap + free zwraca też opustoszałe tablice.
    let mut addresses = [0u64; 64 + 5];
    let mut n = 0;
    for a in [DEMAND_START, read_addr, far1, far2] {
        addresses[n] = a;
        n += 1;
    }
    for i in 0..64u64 {
        addresses[n] = base + i * PAGE_SIZE;
        n += 1;
    }
    for &a in &addresses[..n] {
        let Some(frame) = unmap_page(a) else {
            serial_println!("[MM TEST] FAIL: unmap {:#x}", a);
            return;
        };
        check!(free_frame(frame), "free frame of {:#x}", a);
    }
    check!(translate(DEMAND_START).is_none(), "page still mapped");
    check!(
        free_frame_count() == free_start,
        "frames leaked (start={}, now={})",
        free_start,
        free_frame_count()
    );
    serial_println!("[MM TEST] 7/7 cleanup returns every frame + table PASS");

    serial_println!("[MM TEST] =================================");
    crate::selftest::pass();
    serial_println!("[MM TEST] ON-DEMAND PAGING TESTS PASSED");
    serial_println!("[MM TEST] =================================");
}
