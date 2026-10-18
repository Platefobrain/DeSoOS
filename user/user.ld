/* User programs – a static ELF at 0x400000 (lower half).
 * Sections are 4 KiB aligned: code (R+X), constants (R), data and bss (R+W) on
 * separate pages – the kernel maps them W^X (nothing is writable and
 * executable at once). */
ENTRY(_start)

SECTIONS
{
    . = 0x400000;

    .text : ALIGN(4096)
    {
        KEEP(*(.text._start))
        *(.text .text.*)
    }

    .rodata : ALIGN(4096)
    {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4096)
    {
        *(.data .data.*)
        *(.got .got.*)
    }

    .bss : ALIGN(4096)
    {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}
