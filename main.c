#include <asm/bootparam.h>
#include "string.h"
#include "mptable.h"
#include "ioport.h"

#define MMIO_MEM_START		0xd0000000
#define FIRST_ADDR_PAST_32BITS	0x100000000

struct cc_blob_sev_info {
        uint32_t magic;      /* 0x414d4445 (AMDE) */
        uint16_t version;
	uint16_t reserved;
        uint64_t secrets_phys; /* pointer to secrets page */
        uint32_t secrets_len;
        uint64_t cpuid_phys;   /* 32-bit pointer to cpuid page */
        uint32_t cpuid_len;
};

int pow(int base, unsigned int exp) {
	int i;
	int ret = 1;

	for (i = 0; i < exp; i++) {
		ret *= base;
	}

	return ret;
}

char * parse_number(char *number_str, int *number)
{
	int i, len;
	int num = 0;

	for (i = 0; number_str[i] > 47 && number_str[i] < 58; i++) {
		if (i == 7) {
			return NULL;
		}
	}

	if (i == 0) {
		return NULL;
	}

	len = i;

	for (i = 0; i < len; i++) {
		num += (number_str[i] - 48) * pow(10, len - 1 - i);
	}

	*number = num;

	return number_str + len;
}

int parse_config(int *num_cpus, int *ram_mib)
{
	char *cmdline = (char *) 0x20000;
	char cfgtag[] = "KRUN_CFG=";
	int i;

	for (i = 0; i < 8; i++) {
		if (cfgtag[i] != cmdline[i]) {
			return -1;
		}
	}

	cmdline = parse_number(cmdline + 9, num_cpus);
	if (cmdline == NULL) {
		return -1;
	}

	if (cmdline[0] != ':') {
		return -1;
	}

	cmdline = parse_number(cmdline + 1, ram_mib);
	if (cmdline == NULL) {
		return -1;
	}

	return 0;
}

int pvalidate(int paddr)
{
    int size = 0;
    int validated = 1;
    int ret = 0;

    asm(".byte 0xF2, 0x0F, 0x01, 0xFF;"
    //asm(".byte 0x85, 0xc0;"
        : "=a" (ret)
        : "a" (paddr), "c" (size), "d" (validated)
        );

    return ret;
}

int __attribute__ ((section (".text.startup"))) main(void)
{
	struct cc_blob_sev_info *cc = (struct cc_blob_sev_info *) 0x4000;
	struct boot_params *bp = (struct boot_params *) 0x7000;
	char *test = (char *) 0x4000;
	char *bpzone = (char *) 0x7000;
	unsigned long long mem_size;
	int num_cpus;
	int ram_mib;
	int i;

	//test[0] = 1;

	//if (parse_config(&num_cpus, &ram_mib) != 0) {
	num_cpus = 1;
	ram_mib = 2048;

	//}
	memset(cc, 0, sizeof(struct cc_blob_sev_info));

	cc->magic = 0x45444d41;
        cc->version = 1;
        cc->secrets_phys = 0x5000;
        cc->secrets_len = 0x1000;
        cc->cpuid_phys = 0x6000;
        cc->cpuid_len = 0x1000;

	for (i = 0; i < sizeof(struct boot_params); i++) {
		bpzone[i] = 0;
	}

	bp->cc_blob_address = 0x4000;

	bp->hdr.type_of_loader = 0xff;
	bp->hdr.boot_flag = 0xaa55;
	bp->hdr.header = 0x53726448;
	bp->hdr.cmd_line_ptr = 0x20000;
	bp->hdr.cmdline_size = 512;
	bp->hdr.kernel_alignment = 0x01000000;

	bp->hdr.ramdisk_image = 0xA00000;
	bp->hdr.ramdisk_size = 0x19E000;
	bp->ext_ramdisk_image = 0;
	bp->ext_ramdisk_size = 0;

	bp->e820_table[0].addr = 0;
	bp->e820_table[0].size = 0x9fc00;
	bp->e820_table[0].type = 1;

	mem_size = ((unsigned long long) ram_mib) * 1024 * 1024;
	if (mem_size <= MMIO_MEM_START) {
		bp->e820_table[1].addr = 0x100000;
		bp->e820_table[1].size = mem_size - 0x100000;
		bp->e820_table[1].type = 1;

		bp->e820_entries = 2;
	} else {
		bp->e820_table[1].addr = 0x100000;
		bp->e820_table[1].size = MMIO_MEM_START - 0x100000;
		bp->e820_table[1].type = 1;

		bp->e820_table[2].addr = FIRST_ADDR_PAST_32BITS;
		bp->e820_table[2].size = mem_size - MMIO_MEM_START;
		bp->e820_table[2].type = 1;

		bp->e820_entries = 3;
	}



#if 1
	for (i = 0; i < mem_size; i += 4096) {
		if (pvalidate(i) != 0) {
			//asm("hlt");
		}
	}
#endif

	//test[0] = 1;
	//asm("hlt");
	//setup_mptable(num_cpus);

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
