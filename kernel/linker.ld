/* M10: kernel w górnej połowie przestrzeni adresowej (PML4[511], -2 GiB).
 * DSB czyta segmenty PT_LOAD z ELF-a i mapuje je pod tymi adresami;
 * fizycznie kernel leży tam, gdzie firmware dał wolną pamięć.
 * Sekcje wyrównane do 4 KiB – każda strona ma jedne prawa (kod/rodata
 * tylko do odczytu, data/bss do zapisu). */
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
