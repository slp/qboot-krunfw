OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
    . = 1024K - 64K;
    stext = .;
    .text : { *(.text.startup) *(.text) *(.text.*) }
    . = ALIGN(16);
    .data : { *(.data) }
    . = ALIGN(16);
    .rodata : { *(.rodata) }
    . = ALIGN(16);
    .bss : { *(.bss) }
    . = ALIGN(16);
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
