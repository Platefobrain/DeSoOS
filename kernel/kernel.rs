#![no_std]
#![no_main]

extern crate alloc;

mod acpi;
mod arch;
mod block;
mod bootinfo;
mod console;
// M15: parser ELF wspólny z DSB.
#[path = "../common/elf.rs"]
mod elf;
mod initrd;
#[macro_use]
mod drivers;
mod fs;
mod gpt;
mod input;
mod memory;
mod sched;
#[cfg(selftest)]
mod selftest;
mod shell;
mod time;
mod user;

use bootinfo::BootInfo;
use core::arch::{asm, global_asm};
use core::panic::PanicInfo;

// M10: DSB skacze tu z gotowym stosem (RSP = BootInfo.stack_top, pod nim
// strona-strażnik) i RDI = BootInfo w direct mapie.  Kernel działa już pod
// 0xffff_ffff_8000_0000.
global_asm!(r#"
    .section .text.entry
    .global _start
    _start:
        cli
        cld
        xor rbp, rbp
        call kernel_main

1:
        cli
        hlt
        jmp 1b
"#);

#[unsafe(no_mangle)]
pub extern "sysv64" fn kernel_main(
    boot: &BootInfo
) -> ! {
    unsafe {
        clear_bss();
    }

    // M17: numer CPU (TSC_AUX = 0 dla BSP) i Big Kernel Lock – kod kernela
    // trzyma go zawsze, gdy działa (sched/bkl.rs).
    arch::x86_64::cpu::init_bsp();
    sched::bkl::acquire_tagged(&sched::bkl::tag::BOOT);

    // M10: adresy kernela i stosu z BootInfo (potrzebne m.in. dla TSS).
    memory::layout::init(boot);

    drivers::serial::init();

    if boot.magic != bootinfo::BOOTINFO_MAGIC {
        serial_println!("[DeSoOS] FATAL: BootInfo magic mismatch - DSB and kernel are from different builds");
        loop {
            unsafe { asm!("cli; hlt") };
        }
    }
    serial_println!(
        "[DeSoOS] Higher-half kernel at {:#x}, stack top {:#x}",
        boot.kernel_virt_base,
        boot.stack_top
    );

    // M11: ./test.sh – po testach QEMU wyłączy się z wynikiem.
    #[cfg(selftest)]
    selftest::detect_autotest();

    // M4: GDT/IDT jak najwcześniej – potem każdy błąd ma czytelny raport.
    arch::x86_64::init();
    #[cfg(selftest)]
    arch::x86_64::self_test();

    // M1
    memory::init(boot);
    #[cfg(selftest)]
    memory::self_test();

    // M2
    memory::paging_init();
    #[cfg(selftest)]
    memory::paging_self_test();

    // M3
    memory::heap_init();
    #[cfg(selftest)]
    memory::heap_self_test();
    // M17b.h: listy bloków per CPU – po samoteście (sprawdza dokładne liczniki).
    memory::heap::enable_cpu_caches();
    memory::enable_frame_caches(); // P3

    // M16: stosy IST ze stronami-strażnikami (zamiast tablic w .bss).
    arch::x86_64::gdt::move_ist_to_guarded_stacks();

    // M4: mapowanie on-demand (potrzebuje #PF + frame allocator + paging)
    // – działa zawsze, test uruchamiany tylko w buildzie selftest.
    #[cfg(selftest)]
    memory::demand_self_test();

    // M7: konsola na framebufferze (od teraz logi także na ekranie).
    console::init(boot);

    // M16b: tablice ACPI (MCFG -> PCIe ECAM) i Local APIC (przerwania MSI).
    acpi::init(boot.acpi_rsdp);
    arch::x86_64::lapic::init();
    // M17a: HPET – zegar odcinków czasu niezależny od TSC (watchdog, spinlocki).
    arch::x86_64::clock::init();

    // M5: PIC 8259 (remap) + PIT (IRQ0, 1000 Hz) -> ticki, potem sti.
    arch::x86_64::irq::init();
    time::init();
    // M17a.g14: punkt odniesienia zegara ściennego (dalej bez portów CMOS).
    crate::drivers::rtc::init();
    arch::x86_64::interrupts::enable();
    serial_println!("[ARCH] Interrupts enabled");
    #[cfg(selftest)]
    time::self_test();

    // M12: scheduler – od teraz ten kod to zadanie 1 ("kernel"), obok
    // zadanie idle; tick PIT wywłaszcza zadania.
    sched::init();
    #[cfg(selftest)]
    sched::self_test();

    // M13–M14: ring 3 (FPU/SSE, SMEP, SMAP, SYSCALL); testy procesów, FPU, syscalli.
    user::init();
    #[cfg(selftest)]
    user::self_test();
    #[cfg(selftest)]
    user::fpu_self_test();

    // M6: kontroler PS/2 + klawiatura (IRQ1) -> input (kolejka zdarzeń).
    let keyboard = drivers::keyboard::init();
    #[cfg(selftest)]
    if keyboard {
        drivers::keyboard::self_test();
    }
    // M11b: mysz PS/2 (kółko przewija konsolę).
    let mouse = keyboard && drivers::mouse::init();
    #[cfg(selftest)]
    if mouse {
        drivers::mouse::self_test();
    }
    let _ = mouse;

    // M7: odbiór z seriala (pisanie w terminalu) + shell.
    if !drivers::serial::enable_rx_interrupts() {
        serial_println!("[CON] WARNING: serial input not available");
    }
    #[cfg(selftest)]
    shell::self_test();

    // M8: PCI -> virtio-blk -> warstwa block.  M16b: + NVMe (prawdziwy SSD
    // tylko do odczytu) i partycje GPT.
    drivers::pci::init();
    drivers::virtio_blk::init();
    #[cfg(selftest)]
    drivers::virtio_blk::self_test();
    drivers::nvme::init();

    // M9: VFS – ramfs w "/", FAT32 z dysku w "/disk".
    fs::init();
    #[cfg(selftest)]
    fs::self_test();
    // M16b: ACPI, ECAM, MSI-X, NVMe, GPT (potrzebuje VFS – partycja /esp).
    #[cfg(selftest)]
    drivers::nvme::self_test();

    // M14: syscalle (potrzebują VFS – test plików); M15: programy ELF z /bin.
    #[cfg(selftest)]
    user::syscall_self_test();
    #[cfg(selftest)]
    user::elf_self_test();
    // M16: spawn/wait/rodzic, shell w user space, init.
    #[cfg(selftest)]
    user::init_self_test();

    // M17: pozostałe rdzenie (INIT-SIPI-SIPI); od teraz procesy działają
    // równolegle, kernel pod Big Kernel Lock.
    arch::x86_64::smp::init();
    #[cfg(selftest)]
    user::smp_self_test();
    // M17a: spinlocki i stress test SMP (odpalany po każdym kroku M17a).
    #[cfg(selftest)]
    user::lock_self_test();
    // M17a.b: TLB shootdown.
    #[cfg(selftest)]
    user::tlb_self_test();
    // M17a.c: heap i alokator ramek bez BKL.
    #[cfg(selftest)]
    user::alloc_self_test();
    // M17a.d: syscalle bez BKL.
    #[cfg(selftest)]
    user::nobkl_self_test();
    // M17b: obiekty plików, potoki, pamięć procesu.
    #[cfg(selftest)]
    user::files_self_test();
    // M18: IPC – uchwyty z prawami, kanały, pamięć współdzielona.
    #[cfg(selftest)]
    user::ipc_self_test();
    // M19: usługi w user space.
    #[cfg(selftest)]
    user::svc_self_test();
    // M20.e: autorepeat klawiatur USB (zadanie jądra; przed samotestami USB).
    input::start_repeat_task();
    // M20.f: zadanie usb-disks (montowanie dysków USB) – od startu, przed samotestami.
    user::ublk::start_monitor();
    // M20: USB – kontroler xHCI i usbd w user space.
    #[cfg(selftest)]
    user::usb_self_test();
    #[cfg(selftest)]
    user::stress_self_test();

    #[cfg(selftest)]
    {
        serial_println!("[DeSoOS] Self-tests finished");
        let ok = selftest::finish();
        selftest::exit_if_autotest(ok);
    }
    serial_println!("[DeSoOS] Kernel ready");
    if !keyboard {
        serial_println!("[DeSoOS] No PS/2 keyboard - type in the serial terminal");
    }

    // M16b: bez portu szeregowego (laptop) – pasek stanu w rogu ekranu
    // (czas, klawiatura): widać, czy system żyje i co dochodzi z 8042.
    if !drivers::serial::present() {
        drivers::keyboard::start_status_bar();
    }

    // M17a.b: automatyczny stress test po starcie (build z DESOOS_AUTOSTRESS=s,
    // np. na laptop bez działającej klawiatury) – wynik na ekranie.
    user::stress::start_auto_from_build();

    // M16: kernel uruchamia tylko /bin/init (resztą zarządza user space)
    // i pilnuje go; bez /bin/init albo gdy init ciągle pada – shell kernela.
    user::run_init()
}

unsafe fn clear_bss() {
    unsafe extern "C" {
        static mut __bss_start: u8;
        static mut __bss_end: u8;
    }

    let start =
        core::ptr::addr_of_mut!(
            __bss_start
        ) as usize;

    let end =
        core::ptr::addr_of_mut!(
            __bss_end
        ) as usize;

    if end > start {
        unsafe {
            core::ptr::write_bytes(
                start as *mut u8,
                0,
                end - start,
            );
        }
    }
}

#[panic_handler]
fn panic(
    info: &PanicInfo
) -> ! {
    // M17: pozostałe CPU stop (IPI), zanim zaczniemy raport.
    arch::x86_64::smp::halt_others();
    serial_println!(
        "[DeSoOS] PANIC: {}",
        info
    );
    #[cfg(selftest)]
    selftest::exit_if_autotest(false);

    loop {
        unsafe {
            asm!("cli; hlt");
        }
    }
}