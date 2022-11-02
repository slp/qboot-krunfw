#include <stdbool.h>

#include "bootparam.h"
#include "ioport.h"
#include "mptable.h"
#include "string.h"

#define MSR_AMD64_GHCB 0xC0010130
#define MSR_AMD64_SEV 0xC0010131
#define MSR_AMD64_SEV_SNP_ENABLED_MASK 1 << 2

#define GB 0x40000000
#define PAGE_2MB 0x200000
#define PAGE_4KB 0x1000
#define PDTTE_BASE 0xA000
#define PTE_BASE 0xB000
#define PTE_FLAGS 0x83

#define CC_BLOB_BASE 0x4000
#define ZERO_PAGE_BASE 0x7000
#define SECRETS_PAGE_BASE 0x5000
#define CPUID_PAGE_BASE 0x6000

#define CC_BLOB_SEV_HDR_MAGIC 0x45444d41

struct cc_blob_sev_info
{
	uint32_t magic;
	uint16_t version;
	uint16_t reserved;
	uint64_t secrets_phys;
	uint32_t secrets_len;
	uint32_t rsvd1;
	uint64_t cpuid_phys;
	uint32_t cpuid_len;
	uint32_t rsvd2;
} __packed;

static inline uint64_t
rdmsr(uint64_t msr)
{
	uint32_t low;
	uint32_t high;

	asm volatile("rdmsr"
				 : "=a"(low), "=d"(high)
				 : "c"(msr));

	return ((uint64_t)high << 32) | low;
}

static inline int
pvalidate(uint64_t vaddr, bool size)
{
	bool validate = 1;
	int ret;

	// Linux wants to pvalidate this regions itself
	if (vaddr >= 0xc0000 && vaddr < 0x100000)
	{
		return 0;
	}

	asm(".byte 0xF2, 0x0F, 0x01, 0xFF;"
		: "=a"(ret)
		: "a"(vaddr), "c"(size), "d"(validate));

	return ret;
}

static void validate_region_4K(uint64_t start, uint64_t end)
{
	uint64_t offset;

	for (offset = start; offset < end; offset += 0x1000)
	{
		pvalidate(offset, 0);
	}
}

static void validate_region_2M(uint64_t start, uint64_t end)
{
	uint64_t offset = start;
	uint64_t remaining = end - start;

	while (remaining >= PAGE_2MB)
	{
		if (pvalidate(offset, 1) != 0)
		{
			validate_region_4K(offset, offset + PAGE_2MB);
		}

		offset += PAGE_2MB;
		remaining -= PAGE_2MB;
	}

	if (remaining > 0)
	{
		validate_region_4K(offset, offset + remaining);
	}
}

static void validate_region(uint64_t start, uint64_t end)
{
	if ((start & (PAGE_2MB - 1)) == 0 && ((end - start) >= PAGE_2MB))
	{
		validate_region_2M(start, end);
	}
	else
	{
		validate_region_4K(start, end);
	}
}

static inline void reload_cr3()
{
	uint64_t cr3 = 0x9000;
	asm volatile("mov %0,%%cr3"
				 :
				 : "r"(cr3)
				 : "memory");
}

static uint64_t pg_add_1gb(uint64_t cbit, uint64_t current_last_addr)
{
	uint32_t pt_index = current_last_addr / GB;
	uint32_t pte_start = PTE_BASE + pt_index * PAGE_4KB;
	uint64_t *p_entry;
	int i;

	p_entry = (uint64_t *)((uint64_t)(PDTTE_BASE + pt_index * 8));
	*p_entry = pte_start | cbit | 0x3;

	for (i = 0; i < 512; ++i)
	{
		uint64_t entry = (uint64_t)(512 * pt_index + i) << 21;
		p_entry = (uint64_t *)((uintptr_t)pte_start + i * 8);
		*p_entry = entry | cbit | PTE_FLAGS;
	}

	return current_last_addr + GB;
}

static int extend_pagetables(uint64_t cbit, uint64_t current_last_addr, uint64_t new_last_addr)
{
	do
	{
		current_last_addr = pg_add_1gb(cbit, current_last_addr);
	} while (current_last_addr < new_last_addr);

	reload_cr3();

	return current_last_addr;
}

int __attribute__((section(".text.startup"))) main(void)
{
	struct cc_blob_sev_info *cc = (struct cc_blob_sev_info *)CC_BLOB_BASE;
	struct boot_params *bp = (struct boot_params *)ZERO_PAGE_BASE;
	uint64_t last_addr = (uint64_t)1 << 32;
	uint64_t sev_msr;
	uint64_t cbit;
	int i;

	sev_msr = rdmsr(MSR_AMD64_SEV);
	if (sev_msr & MSR_AMD64_SEV_SNP_ENABLED_MASK)
	{
		cbit = (uint64_t)1 << ((rdmsr(MSR_AMD64_GHCB) >> 24) & 0x3f);
		for (i = 0; i < bp->e820_entries; ++i)
		{
			uint64_t start = bp->e820_table[i].addr;
			uint64_t end = bp->e820_table[i].addr + bp->e820_table[i].size - 1;

			if (end > last_addr)
			{
				last_addr = extend_pagetables(cbit, last_addr, end);
			}

			validate_region(start, end);
		}

		memset(cc, 0, sizeof(struct cc_blob_sev_info));

		cc->magic = CC_BLOB_SEV_HDR_MAGIC;
		cc->version = 1;
		cc->secrets_phys = SECRETS_PAGE_BASE;
		cc->secrets_len = PAGE_4KB;
		cc->cpuid_phys = CPUID_PAGE_BASE;
		cc->cpuid_len = PAGE_4KB;

		bp->cc_blob_address = CC_BLOB_BASE;
	}

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
