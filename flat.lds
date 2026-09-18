OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
    /*
     * TDX loads qboot at FIRMWARE_START (0xffff0000). Link at that
     * address so absolute references to .rodata/.data/.bss hit the
     * firmware image rather than low guest RAM.
     */
    . = 0xffff0000;
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
    . = 0xfffffe00;
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
