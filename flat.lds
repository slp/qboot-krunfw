OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
    . = 1024K - 64K;
    stext = .;
    .text : { *(.text.startup) *(.text) *(.text.*) }
    . = ALIGN(32);
    .data : { *(.data) }
    . = ALIGN(32);
    .rodata : { *(.rodata) }
    . = ALIGN(32);
    .bss : { *(.bss) }
    . = ALIGN(32);
    edata = .;
    . = 1024K - 512;
    sinit = .;
    .init : {
	*(.init);
	. = 512 - 16;
        *(.resetvector);
	. = 512;
    }
    einit = .;
}

ENTRY(main)
