// M5: dostęp do portów I/O (in/out).  Wspólne dla PIC, PIT i CMOS/RTC.

use core::arch::asm;

#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[inline]
#[allow(dead_code)]
pub unsafe fn outw(port: u16, value: u16) {
    unsafe {
        asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline]
#[allow(dead_code)]
pub unsafe fn outl(port: u16, value: u32) {
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Krótkie opóźnienie (~1 µs) między kolejnymi zapisami do starych
/// kontrolerów (8259) – zapis do nieużywanego portu 0x80 (POST code).
#[inline]
pub fn io_wait() {
    unsafe {
        outb(0x80, 0);
    }
}
