#include <asm/bootparam.h>
#include <asm/e820.h>
#include "string.h"
#include "mptable.h"
#include "ioport.h"
#include "acpi.h"

struct tdcall_args {
	uint64_t rax;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;
	uint64_t r12;
	uint64_t r13;
};

void asm_td_call(struct tdcall_args *args);

static void accept_page(uint64_t page)
{
	struct tdcall_args args;

	memset(&args, 0, sizeof(struct tdcall_args));

	args.rax = 6; // TDCALL_TDACCEPTPAGE
	args.rcx = page;

	asm_td_call(&args);
}

static void accept_range(uint64_t start, uint64_t end)
{
	uint64_t addr = start & ~0xfffUL;

	while (addr < end) {
		accept_page(addr);
		addr += 4096;
	}
}

static int page_in_e820_ram(struct boot_params *bp, uint64_t addr)
{
	int i;

	for (i = 0; i < bp->e820_entries; i++) {
		struct boot_e820_entry *e = &bp->e820_table[i];
		uint64_t end;

		if (e->type != E820_RAM)
			continue;
		end = e->addr + e->size;
		if (addr >= e->addr && addr + 0xfffUL < end)
			return 1;
	}
	return 0;
}

static void boot_fail(void)
{
	for (;;)
		asm volatile("pause");
}

/*
 * Carve the Multiprocessor Wakeup mailbox page out of an e820 RAM
 * region and publish it as ACPI NVS so the guest OS will not reuse it.
 */
static int reserve_mailbox_nvs(struct boot_params *bp)
{
	uint64_t mb_start = MP_WAKEUP_MAILBOX_ADDR;
	uint64_t mb_end = mb_start + MP_WAKEUP_MAILBOX_SIZE;
	int i;

	for (i = 0; i < bp->e820_entries; i++) {
		struct boot_e820_entry *e = &bp->e820_table[i];
		uint64_t e_start;
		uint64_t e_end;
		uint64_t before_size;
		uint64_t after_size;
		int slots_needed;

		if (e->type != E820_RAM)
			continue;

		e_start = e->addr;
		e_end = e_start + e->size;
		if (mb_start < e_start || mb_end > e_end)
			continue;

		before_size = mb_start - e_start;
		after_size = e_end - mb_end;
		slots_needed = (before_size ? 1 : 0) + 1 + (after_size ? 1 : 0);
		/* Replacing one entry: need slots_needed - 1 additional slots. */
		if (bp->e820_entries + slots_needed - 1 > E820MAX)
			return -1;

		if (before_size)
			e->size = before_size;
		else {
			/* Overwrite this slot with the NVS entry below. */
			e->addr = mb_start;
			e->size = MP_WAKEUP_MAILBOX_SIZE;
			e->type = E820_NVS;

			if (after_size) {
				struct boot_e820_entry *a =
					&bp->e820_table[bp->e820_entries++];
				a->addr = mb_end;
				a->size = after_size;
				a->type = E820_RAM;
			}
			return 0;
		}

		{
			struct boot_e820_entry *nvs =
				&bp->e820_table[bp->e820_entries++];
			nvs->addr = mb_start;
			nvs->size = MP_WAKEUP_MAILBOX_SIZE;
			nvs->type = E820_NVS;
		}

		if (after_size) {
			struct boot_e820_entry *a =
				&bp->e820_table[bp->e820_entries++];
			a->addr = mb_end;
			a->size = after_size;
			a->type = E820_RAM;
		}
		return 0;
	}
	return -1;
}

int __attribute__ ((section (".text.startup"))) main(uint64_t cpuid)
{
	struct boot_params *bp = (struct boot_params *) 0x7000;
	uint64_t entry = 0x1000123;
	int i;
	int madt_rc;

	/*
	 * Only the BSP runs main(). APs park in the MADT mailbox wait
	 * loop in cstart.S until the guest OS wakes them.
	 */
	(void)cpuid;

	for (i = 0; i < bp->e820_entries; i++) {
		struct boot_e820_entry e820 = bp->e820_table[i];

		if (e820.type != E820_RAM)
			continue;

		accept_range(e820.addr, e820.addr + e820.size);
	}

	/*
	 * TDX low e820 RAM ends before EBDA. The MP table (0x9fc00) and
	 * ACPI tables (0xe0000..1MB) sit in that gap: populated by the VMM
	 * via INIT_MEM_REGION but left PENDING. Touching them first causes
	 * a #VE with no handler and KVM_EXIT_SHUTDOWN.
	 *
	 * Accept only pages not already covered by e820 RAM — a second
	 * TDACCEPTPAGE on an already-accepted page is unsafe.
	 *
	 * The previously-working syssize-based accept loop covered this
	 * same hole; e820-only accept does not.
	 */
	{
		uint64_t low_ram_end = 0;

		for (i = 0; i < bp->e820_entries; i++) {
			struct boot_e820_entry *e = &bp->e820_table[i];
			uint64_t end;

			if (e->type != E820_RAM || e->addr >= 0x100000UL)
				continue;
			end = e->addr + e->size;
			if (end > low_ram_end)
				low_ram_end = end;
		}
		low_ram_end = (low_ram_end + 0xfffUL) & ~0xfffUL;
		if (low_ram_end < 0x100000UL)
			accept_range(low_ram_end, 0x100000UL);
	}

	if (!page_in_e820_ram(bp, MP_WAKEUP_MAILBOX_ADDR))
		boot_fail();
	setup_mp_wakeup_mailbox();
	madt_rc = setup_madt_mailbox(MP_WAKEUP_MAILBOX_ADDR);
	if (madt_rc != 0)
		boot_fail();
	if (reserve_mailbox_nvs(bp) != 0)
		boot_fail();
	setup_mptable(bp->hdr.root_flags);

	/* APs may now leave the early park and enter the mailbox loop. */
	release_aps();

	asm("xor %rax, %rax");
	asm("mov %0, %%rax"
			: /* a */
			:"r"(entry)
			: "rax");
	asm("xor %rsp, %rsp");
	asm("xor %rbp, %rbp");
	asm("xor %rsi, %rsi");
	asm("mov $0x8ff0, %rsp");
	asm("mov $0x8ff0, %rbp");
	asm("mov $0x7000, %rsi");
	asm("jmpq *%rax");

	// Not reached.
	return 0;
}
