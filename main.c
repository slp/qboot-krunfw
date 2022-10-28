#include "bootparam.h"
#include "ioport.h"
#include "mptable.h"
#include "string.h"

#define MSR_AMD64_SEV 0xC0010131
#define MSR_AMD64_SEV_SNP_ENABLED_MASK 1 << 2

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

static inline int
pvalidate(int paddr)
{
	int size = 0;
	int validated = 1;
	int ret;

	// Linux wants to pvalidate this regions itself
	if (paddr >= 0xc0000 && paddr < 0x100000)
	{
		return 0;
	}

	asm(".byte 0xF2, 0x0F, 0x01, 0xFF;"
		: "=a"(ret)
		: "a"(paddr), "c"(size), "d"(validated));

	return ret;
}

int __attribute__((section(".text.startup"))) main(void)
{
	struct cc_blob_sev_info *cc = (struct cc_blob_sev_info *)0x4000;
	struct boot_params *bp = (struct boot_params *)0x7000;
	uint64_t sev_msr;
	int i;

	sev_msr = rdmsr(MSR_AMD64_SEV);
	if (sev_msr & MSR_AMD64_SEV_SNP_ENABLED_MASK)
	{
		for (i = 0; i < bp->e820_entries; ++i) {
			uint64_t offset = bp->e820_table[i].addr;
			uint64_t end = bp->e820_table[i].addr + bp->e820_table[i].size - 1;

			for (; offset < end; offset += 4096) {
				pvalidate(offset);
			}
		}

		memset(cc, 0, sizeof(struct cc_blob_sev_info));

		cc->magic = 0x45444d41;
		cc->version = 1;
		cc->secrets_phys = 0x5000;
		cc->secrets_len = 0x1000;
		cc->cpuid_phys = 0x6000;
		cc->cpuid_len = 0x1000;

		bp->cc_blob_address = 0x4000;
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
