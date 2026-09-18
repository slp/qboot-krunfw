#include "acpi.h"
#include "string.h"

static uint8_t acpi_checksum(const uint8_t *buf, uint32_t len)
{
	uint8_t sum = 0;
	uint32_t i;

	for (i = 0; i < len; i++)
		sum += buf[i];

	return sum;
}

static int rsdp_valid(const struct acpi_rsdp *rsdp)
{
	/*
	 * An all-zero page checksums to 0, so it would otherwise look like
	 * a valid ACPI 1.0 RSDP. Require the signature's first character
	 * before doing any further work or pointer chasing.
	 */
	if (rsdp->signature[0] != 'R')
		return 0;
	if (memcmp((void *)rsdp->signature, ACPI_RSDP_SIG, 8) != 0)
		return 0;

	/* ACPI 1.0 checksum covers the first 20 bytes. */
	if (acpi_checksum((const uint8_t *)rsdp, 20) != 0)
		return 0;

	/* ACPI 2.0+ also checksums the full structure. */
	if (rsdp->revision >= 2) {
		if (rsdp->length < sizeof(*rsdp))
			return 0;
		if (acpi_checksum((const uint8_t *)rsdp, rsdp->length) != 0)
			return 0;
	}

	return 1;
}

/* ACPI tables from libkrun live in the RSDP..HIMEM window. */
static int acpi_ptr_in_window(uint64_t addr, uint32_t len)
{
	if (addr < ACPI_RSDP_ADDR)
		return 0;
	if (addr > 0x100000UL || len > 0x100000UL - addr)
		return 0;
	return 1;
}

static struct acpi_madt *find_madt(void)
{
	const struct acpi_rsdp *rsdp = (const struct acpi_rsdp *)ACPI_RSDP_ADDR;
	const struct acpi_sdt_header *xsdt;
	uint32_t xsdt_len;
	uint32_t nentries;
	uint32_t i;
	const uint64_t *entries;

	if (!rsdp_valid(rsdp))
		return NULL;

	if (rsdp->revision < 2 || rsdp->xsdt_address == 0)
		return NULL;
	if (!acpi_ptr_in_window(rsdp->xsdt_address, sizeof(*xsdt)))
		return NULL;

	xsdt = (const struct acpi_sdt_header *)(uintptr_t)rsdp->xsdt_address;
	if (memcmp((void *)xsdt->signature, ACPI_XSDT_SIG, 4) != 0)
		return NULL;
	if (xsdt->length < sizeof(*xsdt))
		return NULL;
	if (!acpi_ptr_in_window(rsdp->xsdt_address, xsdt->length))
		return NULL;
	if (acpi_checksum((const uint8_t *)xsdt, xsdt->length) != 0)
		return NULL;

	xsdt_len = xsdt->length;
	nentries = (xsdt_len - sizeof(*xsdt)) / sizeof(uint64_t);
	entries = (const uint64_t *)(xsdt + 1);

	for (i = 0; i < nentries; i++) {
		struct acpi_madt *madt =
			(struct acpi_madt *)(uintptr_t)entries[i];

		if (!madt)
			continue;
		if (!acpi_ptr_in_window(entries[i], sizeof(*madt)))
			continue;
		if (memcmp(madt->header.signature, ACPI_MADT_SIG, 4) != 0)
			continue;
		if (madt->header.length < sizeof(*madt))
			continue;
		if (!acpi_ptr_in_window(entries[i], madt->header.length))
			continue;
		if (acpi_checksum((const uint8_t *)madt,
				 madt->header.length) != 0)
			continue;

		return madt;
	}

	return NULL;
}

static int madt_has_mp_wakeup(const struct acpi_madt *madt)
{
	uint32_t offset = sizeof(*madt);

	while (offset + 2 <= madt->header.length) {
		const uint8_t *p = (const uint8_t *)madt + offset;
		uint8_t type = p[0];
		uint8_t length = p[1];

		if (length < 2)
			return 0;
		if (offset + length > madt->header.length)
			return 0;
		if (type == ACPI_MADT_TYPE_MULTIPROC_WAKEUP)
			return 1;
		offset += length;
	}

	return 0;
}

void setup_mp_wakeup_mailbox(void)
{
	volatile struct acpi_madt_multiproc_wakeup_mailbox *mailbox =
		(volatile struct acpi_madt_multiproc_wakeup_mailbox *)
			MP_WAKEUP_MAILBOX_ADDR;

	/* Only clear the architected header; avoid wiping the whole page. */
	mailbox->command = ACPI_MP_WAKE_COMMAND_NOOP;
	mailbox->reserved = 0;
	mailbox->apic_id = ACPI_MP_WAKE_APICID_INVALID;
	mailbox->wakeup_vector = 0;
}

/*
 * Flag in the firmware image (identity-mapped at 0xffffxxxx), so APs can
 * poll it before low RAM has been accepted.
 */
volatile uint32_t ap_ready_flag;

void release_aps(void)
{
	ap_ready_flag = 1;
	asm volatile("" ::: "memory");
}

int setup_madt_mailbox(uint64_t mailbox_addr)
{
	struct acpi_madt *madt;
	struct acpi_madt_multiproc_wakeup *mpwk;
	uint32_t old_len;
	uint32_t new_len;
	uint8_t *bytes;

	madt = find_madt();
	if (!madt)
		return -1;

	if (madt_has_mp_wakeup(madt))
		return 0;

	old_len = madt->header.length;
	new_len = old_len + sizeof(*mpwk);

	/*
	 * libkrun places MADT last in the RSDP..HIMEM window with a zero
	 * pad after it. Refuse to grow into the 1MB boundary or to clobber
	 * non-zero bytes that would indicate another table.
	 */
	if ((uintptr_t)madt + new_len > 0x100000UL)
		return -1;

	mpwk = (struct acpi_madt_multiproc_wakeup *)((uint8_t *)madt + old_len);
	{
		uint32_t i;

		for (i = 0; i < sizeof(*mpwk); i++) {
			if (((uint8_t *)mpwk)[i] != 0)
				return -1;
		}
	}

	memset(mpwk, 0, sizeof(*mpwk));
	mpwk->type = ACPI_MADT_TYPE_MULTIPROC_WAKEUP;
	mpwk->length = sizeof(*mpwk);
	mpwk->mailbox_version = ACPI_MADT_MP_WAKEUP_VERSION_V0;
	mpwk->reserved = 0;
	mpwk->mailbox_address = mailbox_addr;

	madt->header.length = new_len;
	madt->header.checksum = 0;
	bytes = (uint8_t *)madt;
	madt->header.checksum = (uint8_t)(0 - acpi_checksum(bytes, new_len));

	return 0;
}
