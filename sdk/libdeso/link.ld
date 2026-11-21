/* DeSo OS programs – a static ELF at 0x400000 (lower half; the kernel accepts any address in
 * the ABI 1.0 load range, docs/abi/README.md).
 * Code (R+X), constants (R) and data + bss (R+W) in separate 4 KiB-aligned segments – the kernel
 * maps them W^X.  The ABI note (.note.deso.abi, libdeso sys.rs) sits in the read-only segment and
 * in its own PT_NOTE header, so the loader finds it from the program headers alone (strip keeps
 * it).  Other notes are dropped. */
ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
    note PT_NOTE FLAGS(4);
}

SECTIONS
{
    . = 0x400000;

    .text : ALIGN(4096)
    {
        KEEP(*(.text._start))
        *(.text .text.*)
    } :text

    .rodata : ALIGN(4096)
    {
        *(.rodata .rodata.*)
    } :rodata

    .note.deso.abi : ALIGN(4)
    {
        KEEP(*(.note.deso.abi))
    } :rodata :note

    .data : ALIGN(4096)
    {
        *(.data .data.*)
        *(.got .got.*)
    } :data

    .bss : ALIGN(4096)
    {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}
