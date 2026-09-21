# Copyright (c) 2020-2022 Intel Corporation
# SPDX-License-Identifier: BSD-2-Clause-Patent

.section .text

# Arguments offsets in TdVmcallArgs struct
.equ TDCALL_ARG_RAX, 0x0
.equ TDCALL_ARG_RCX, 0x8
.equ TDCALL_ARG_RDX, 0x10
.equ TDCALL_ARG_R8,  0x18
.equ TDCALL_ARG_R9,  0x20
.equ TDCALL_ARG_R10, 0x28
.equ TDCALL_ARG_R11, 0x30
.equ TDCALL_ARG_R12, 0x38
.equ TDCALL_ARG_R13, 0x40

# GHCI TDG.VP.VMCALL + Instruction.IO (EXIT_REASON_IO_INSTRUCTION)
.equ TDG_VP_VMCALL,			0
.equ TDX_HYPERCALL_STANDARD,		0
.equ EXIT_REASON_IO_INSTRUCTION,	0x1e
.equ TDX_IO_WRITE,			1
/*
 * RCX bitmap: which GPRs the TDX module exposes to the VMM for VMCALL.
 * Must include R10-R15 or the host never sees IO args (can hang).
 * Matches Linux TDVMCALL_EXPOSE_REGS_MASK.
 */
.equ TDVMCALL_EXPOSE_REGS_MASK,		0xfc00

# asm_td_call -> u64 (
#   args: *mut TdcallArgs,  //rcx
# )
.global asm_td_call
asm_td_call:
        # Save the registers accroding to MS x64 calling convention
        push %rbp
        mov %rsp, %rbp
        push %r15
        push %r14
        push %r13
        push %r12
        push %rbx
        push %rsi
        push %rdi

        # Use RDI to save RCX value
        #mov %rcx, %rdi

        # Test if input pointer is valid
        test %rdi, %rdi
        jz td_call_exit

        # Copy the input operands from memory to registers 
        mov TDCALL_ARG_RAX(%rdi), %rax
        mov TDCALL_ARG_RCX(%rdi), %rcx
        mov TDCALL_ARG_RDX(%rdi), %rdx
        mov TDCALL_ARG_R8(%rdi), %r8
        mov TDCALL_ARG_R9(%rdi), %r9
        mov TDCALL_ARG_R10(%rdi), %r10
        mov TDCALL_ARG_R11(%rdi), %r11
        mov TDCALL_ARG_R12(%rdi), %r12
        mov TDCALL_ARG_R13(%rdi), %r13

        # tdcall
        .byte 0x66,0x0f,0x01,0xcc

        /*
         * Always record outputs, including TDX error codes. Callers
         * (accept_page) must inspect RAX; swallowing failures here made
         * pending-page faults look like random KVM_EXIT_SHUTDOWN.
         */
        mov %rax, TDCALL_ARG_RAX(%rdi)
        mov %rcx, TDCALL_ARG_RCX(%rdi)
        mov %rdx, TDCALL_ARG_RDX(%rdi)
        mov %r8, TDCALL_ARG_R8(%rdi)
        mov %r9, TDCALL_ARG_R9(%rdi)
        mov %r10, TDCALL_ARG_R10(%rdi)
        mov %r11, TDCALL_ARG_R11(%rdi)
        mov %r12, TDCALL_ARG_R12(%rdi)
        mov %r13, TDCALL_ARG_R13(%rdi)

td_call_exit:
        # Pop out saved registers from stack
        pop %rdi
        pop %rsi
        pop %rbx
        pop %r12
        pop %r13
        pop %r14
        pop %r15
        pop %rbp

        ret

/*
 * TDX-safe port I/O via TDG.VP.VMCALL Instruction.IO.
 * Raw IN/OUT raise #VE with no handler in qboot → KVM_EXIT_SHUTDOWN.
 *
 * System V: rdi=port, rsi=value.
 * Hypercall status is returned in rax.
 */
.global asm_td_io_outb
asm_td_io_outb:
        push %r15
        push %r14
        push %r13
        push %r12

        mov $TDG_VP_VMCALL, %eax
        mov $TDVMCALL_EXPOSE_REGS_MASK, %ecx
        mov $TDX_HYPERCALL_STANDARD, %r10
        mov $EXIT_REASON_IO_INSTRUCTION, %r11
        mov $1, %r12			/* size = 1 */
        mov $TDX_IO_WRITE, %r13
        mov %rdi, %r14			/* port */
        movzbl %sil, %r15d		/* value */

        .byte 0x66,0x0f,0x01,0xcc	/* tdcall */

        mov %r10, %rax			/* GHCI status */

        pop %r12
        pop %r13
        pop %r14
        pop %r15
        ret

