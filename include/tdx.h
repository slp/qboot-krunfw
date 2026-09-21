#ifndef QBOOT_TDX_H
#define QBOOT_TDX_H

#include <stdint.h>

/*
 * TDX helpers required for functional SMP boot.
 *
 * Raw IN/OUT raises #VE with no handler in qboot. TDVMCALL Instruction.IO
 * is the only safe port I/O path, and is used here only to manufacture host
 * exits around TDACCEPT / AP release (empirical settle on libkrun/KVM —
 * not an architectural guarantee).
 */

#define TDX_PAGE_ALREADY_ACCEPTED	0x00000B0A00000000ULL
#define TDX_OPERAND_BUSY		0x8000020000000000ULL

/* Dummy port for TDVMCALL settle exits (value ignored by the host path). */
#define QBOOT_SETTLE_PORT		0x80

uint64_t asm_td_io_outb(uint16_t port, uint8_t value);

/* Host-exit settle via TDVMCALL OUT. Counts are host-validated minimums. */
static inline void bsp_settle(unsigned count)
{
	unsigned i;

	for (i = 0; i < count; i++)
		asm_td_io_outb(QBOOT_SETTLE_PORT, 0x00);
}

static inline void bsp_pause(unsigned count)
{
	unsigned i;

	for (i = 0; i < count; i++)
		asm volatile("pause");
}

/*
 * Fatal firmware error: raw OUT raises #VE with no handler in qboot, so the
 * host sees KVM_EXIT_SHUTDOWN. Prefer this over an opaque pause spin until a
 * POST/debug harness can report a reason code.
 */
static inline void boot_fail(void)
{
	asm volatile("outb %b0, %w1" : : "a"((uint8_t)0xff), "Nd"((uint16_t)0x80));
	for (;;)
		asm volatile("pause");
}

#endif /* QBOOT_TDX_H */
