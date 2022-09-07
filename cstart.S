.code32
#include "assembly.h"
.section .init
ENTRY(pm_entry)
        xor %eax, %eax
	xor %edx, %edx
        mov $0x8c00, %sp

	// Detect BSPs
	test %esi, %esi
	jnz park_ap

	/*
	 * Set up the initial page tables.
	 */
	 // Point to PDPTE_START in PML4_START
	mov $0xa003, %eax
	mov %eax, (0x9000)
	mov %edx, (0x9004)

	// Point to PDE_START in PDTTE_START 0-1GB
	mov $0xb003, %eax
	mov %eax, (0xa000)
	mov %edx, (0xa004)

	// Point to PDE_START in PDTTE_START 1-2GB
	mov $0xc003, %eax
	mov %eax, (0xa008)
	mov %edx, (0xa00c)

	// Point to PDE_START in PDTTE_START 2-3GB
	mov $0xd003, %eax
	mov %eax, (0xa010)
	mov %edx, (0xa014)

	// Point to PDE_START in PDTTE_START 2-3GB
	mov $0xe003, %eax
	mov %eax, (0xa018)
	mov %edx, (0xa01c)

	// Set up 2048 2MB entries
	mov $0xb000, %ebx
	mov $2048, %ecx
	xor %edi, %edi
l3:
	// Low PTE
	mov %edi, %eax
	shl $21, %eax
	add $0x83, %eax
	mov %eax, (%ebx,%edi,8)

	// High PTE (set SEV C-bit)
	mov %edx, 4(%ebx,%edi,8)

	inc %edi
	loop l3
	jmp switch_to_64

park_ap:
	mov (0x71e0), %eax
	cmp %esi, %eax
	jne park_ap

switch_to_64:
	/*
	 * Enable paging and switch to 64-bit
	 */
	// Point CR3 to PML4_START
	mov $0x9000, %eax
	mov %eax, %cr3

	// Enable PAE
	mov %cr4, %eax
	or  $0x20, %eax
	mov %eax, %cr4

	// READ EFER MSR
	mov $0xC0000080, %ecx
	rdmsr

	// Set LM-bit and write it
	//or  $0x100, %eax
	//wrmsr

	// Enable PG and PM
	mov %cr0, %eax
	orl $0x80000001, %eax
	mov %eax, %cr0

	lgdtl %cs:0xfffffe00 + gdt64_descr - pm_entry
	ljmpl $8, $0xfffffe00 + 3f - pm_entry

3:
	.code64
	/*
	 * Jump into C code (main)
	 */

	cli
	mov %rsi, %rax
	and $0xff, %rax
	mov %rax, %rdi
	mov $0x00000000ffff0000, %rax
	jmp *%rax
	hlt

gdt32:
	.quad 0
	.quad 0x00cf9b000000ffff // flat 32-bit code segment
	.quad 0x00cf93000000ffff // flat 32-bit data segment
	.quad 0x000f9b0f0000ffff // 64K 16-bit code segment at 0xF0000
	.quad 0x000f93000000ffff // 64K 16-bit data segment at 0x0
gdt32_end:

gdt32_descr:
	.word gdt32_end - gdt32 - 1
	.long 0xfffffe00 + gdt32 - pm_entry

gdt64:
	// NULL
	.quad 0
	// CS
	.word 0
	.word 0
	.byte 0
	.byte 0x9a
	.byte 0xaf
	.byte 0
	// DS
	.word 0
	.word 0
	.byte 0
	.byte 0x92
	.byte 0
	.byte 0
gdt64_end:

gdt64_descr:
	.word gdt64_end - gdt64 - 1
	.long 0xfffffe00 + gdt64 - pm_entry

	.code32
idt_descr:
	.word 256 * 8 - 1
	.long 0

idt_start:
	.word 0x800
	.word 0x0008
	.byte 0x00
	.byte 0xaf
	.word 0x0
idt_end:

vc_handler_start:
	// We only support the CPUID VMEXIT
	pop %eax
	cmp $0x072, %eax
	jne 4f

	// Fix up EIP to the instruction after CPUID
	pop %eax
	add $2, %eax
	push %eax

	// Read GHCB MSR
	mov $0xc0010130, %ecx
	rdmsr
	shr $24, %eax

	mov %eax, %ebx
	add $32, %ebx
	iret
4:
	// Request guest termination
	xor %edx, %edx
	mov $0x100, %eax
	mov $0xc0010130, %ecx
	wrmsr
	rep
	vmmcall
	// Not reached
	hlt
vc_handler_end:

ENTRY_END(pm_entry)

	.code32
	.section .resetvector
	jmp pm_entry
