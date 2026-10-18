#![no_std]
#![no_main]

extern crate alloc;

mod acpi;
mod arch;
mod block;
mod bootinfo;
mod console;
// ELF parser shared with DSB.
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

// DSB jumps here with a ready stack (RSP = BootInfo.stack_top, with a guard
// page below it) and RDI = BootInfo in the direct map.  The kernel already runs at
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

    // CPU number (TSC_AUX = 0 for the BSP) and the Big Kernel Lock – kernel code
    // always holds it while running (sched/bkl.rs).
    arch::x86_64::cpu::init_bsp();
    sched::bkl::acquire_tagged(&sched::bkl::tag::BOOT);

    // Kernel and stack addresses from BootInfo (needed e.g. for the TSS).
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

    // ./test.sh – after the tests QEMU shuts down with the result.
    #[cfg(selftest)]
    selftest::detect_autotest();

    // GDT/IDT as early as possible – after that every fault gets a readable report.
    arch::x86_64::init();
    #[cfg(selftest)]
    arch::x86_64::self_test();

    // Physical memory (frame allocator).
    memory::init(boot);
    #[cfg(selftest)]
    memory::self_test();

    // Paging.
    memory::paging_init();
    #[cfg(selftest)]
    memory::paging_self_test();

    // Kernel heap.
    memory::heap_init();
    #[cfg(selftest)]
    memory::heap_self_test();
    // Per-CPU block lists – after the self-test (it checks exact counters).
    memory::heap::enable_cpu_caches();
    memory::enable_frame_caches(); // per-CPU frame caches

    // IST stacks with guard pages (instead of arrays in .bss).
    arch::x86_64::gdt::move_ist_to_guarded_stacks();

    // On-demand mapping (needs #PF + frame allocator + paging)
    // – always active, the test runs only in the selftest build.
    #[cfg(selftest)]
    memory::demand_self_test();

    // Framebuffer console (from now on logs also go to the screen).
    console::init(boot);

    // ACPI tables (MCFG -> PCIe ECAM) and the Local APIC (MSI interrupts).
    acpi::init(boot.acpi_rsdp);
    arch::x86_64::lapic::init();
    // HPET – interval clock independent of the TSC (watchdog, spinlocks).
    arch::x86_64::clock::init();

    // PIC 8259 (remap) + PIT (IRQ0, 1000 Hz) -> ticks, then sti.
    arch::x86_64::irq::init();
    time::init();
    // Wall-clock reference point (no CMOS port access after this).
    crate::drivers::rtc::init();
    arch::x86_64::interrupts::enable();
    serial_println!("[ARCH] Interrupts enabled");
    #[cfg(selftest)]
    time::self_test();

    // Scheduler – from now on this code is task 1 ("kernel"), next to
    // the idle task; the PIT tick preempts tasks.
    sched::init();
    #[cfg(selftest)]
    sched::self_test();

    // Ring 3 (FPU/SSE, SMEP, SMAP, SYSCALL); process, FPU and syscall tests.
    user::init();
    #[cfg(selftest)]
    user::self_test();
    #[cfg(selftest)]
    user::fpu_self_test();

    // PS/2 controller + keyboard (IRQ1) -> input (event queue).
    let keyboard = drivers::keyboard::init();
    #[cfg(selftest)]
    if keyboard {
        drivers::keyboard::self_test();
    }
    // PS/2 mouse (the wheel scrolls the console).
    let mouse = keyboard && drivers::mouse::init();
    #[cfg(selftest)]
    if mouse {
        drivers::mouse::self_test();
    }
    let _ = mouse;

    // Serial input (typing in a terminal) + shell.
    if !drivers::serial::enable_rx_interrupts() {
        serial_println!("[CON] WARNING: serial input not available");
    }
    #[cfg(selftest)]
    shell::self_test();

    // PCI -> virtio-blk -> block layer, plus NVMe (a real SSD,
    // read-only) and GPT partitions.
    drivers::pci::init();
    drivers::virtio_blk::init();
    #[cfg(selftest)]
    drivers::virtio_blk::self_test();
    drivers::nvme::init();

    // VFS – ramfs at "/", FAT32 from disk at "/disk".
    fs::init();
    #[cfg(selftest)]
    fs::self_test();
    // ACPI, ECAM, MSI-X, NVMe, GPT (needs the VFS – the /esp partition).
    #[cfg(selftest)]
    drivers::nvme::self_test();

    // Syscalls (they need the VFS – file test); ELF programs from /bin.
    #[cfg(selftest)]
    user::syscall_self_test();
    #[cfg(selftest)]
    user::elf_self_test();
    // spawn/wait/parent, user-space shell, init.
    #[cfg(selftest)]
    user::init_self_test();

    // Remaining cores (INIT-SIPI-SIPI); from now on processes run
    // in parallel, the kernel under the Big Kernel Lock.
    arch::x86_64::smp::init();
    #[cfg(selftest)]
    user::smp_self_test();
    // Spinlocks and the SMP stress test.
    #[cfg(selftest)]
    user::lock_self_test();
    // TLB shootdown.
    #[cfg(selftest)]
    user::tlb_self_test();
    // Heap and frame allocator without the BKL.
    #[cfg(selftest)]
    user::alloc_self_test();
    // Syscalls without the BKL.
    #[cfg(selftest)]
    user::nobkl_self_test();
    // File objects, pipes, process memory.
    #[cfg(selftest)]
    user::files_self_test();
    // IPC – handles with rights, channels, shared memory.
    #[cfg(selftest)]
    user::ipc_self_test();
    // User-space services.
    #[cfg(selftest)]
    user::svc_self_test();
    // USB keyboard autorepeat (kernel task; before the USB self-tests).
    input::start_repeat_task();
    // usb-disks task (mounting USB disks) – from boot, before the self-tests.
    user::ublk::start_monitor();
    // USB – xHCI controller and usbd in user space.
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

    // No serial port (laptop) – status bar in the screen corner
    // (time, keyboard): shows whether the system is alive and what arrives from the 8042.
    if !drivers::serial::present() {
        drivers::keyboard::start_status_bar();
    }

    // Automatic stress test after boot (build with DESOOS_AUTOSTRESS=s,
    // e.g. on a laptop without a working keyboard) – result on screen.
    user::stress::start_auto_from_build();

    // The kernel starts only /bin/init (user space manages the rest)
    // and watches it; without /bin/init or when init keeps crashing – kernel shell.
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
    // Stop the other CPUs (IPI) before we start the report.
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