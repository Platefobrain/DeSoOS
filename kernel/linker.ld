/* Kernel in the upper half of the address space (PML4[511], -2 GiB).
 * The bootloader (DSB) reads the PT_LOAD segments of the ELF and maps them at
 * these addresses; physically the kernel lives wherever the firmware had free
 * memory.  Sections are 4 KiB aligned so every page has one set of rights
 * (code/rodata read-only, data/bss writable). */
ENTRY(_start)

KERNEL_BASE = 0xffffffff80000000;

SECTIONS
{
    . = KERNEL_BASE;
    __kernel_start = .;

    .text : ALIGN(4096)
    {
        KEEP(*(.text.entry))
        *(.text .text.*)
    }
    __text_end = .;

    .rodata : ALIGN(4096)
    {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4096)
    {
        *(.data .data.*)
    }

    .bss : ALIGN(4096)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    . = ALIGN(4096);
    __kernel_end = .;
}
