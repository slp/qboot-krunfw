#include <asm/bootparam.h>
#include "string.h"
#include "mptable.h"
#include "ioport.h"

int __attribute__ ((section (".text.startup"))) main(void)
{
	struct boot_params *bp = (struct boot_params *) 0x7000;

	setup_mptable(bp->hdr.syssize);

	asm("xor %rsp, %rsp");
	asm("xor %rbp, %rbp");
	asm("xor %rsi, %rsi");
	asm("mov $0x8ff0, %rsp");
	asm("mov $0x8ff0, %rbp");
	asm("mov $0x7000, %rsi");
	asm("mov $0x1000000, %rax");
	asm("jmpq *%rax");

	// Not reached.
	return 0;
}
