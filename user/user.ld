/* M15: programy użytkownika – statyczny ELF pod 0x400000 (dolna połowa).
 * Sekcje wyrównane do 4 KiB: kod (R+X), stałe (R), dane i bss (R+W) w osobnych
 * stronach – kernel mapuje je z prawami W^X (nic nie jest zapisywalne
 * i wykonywalne naraz). */
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
