#ifndef QBOOT_ACPI_H
#define QBOOT_ACPI_H

#include <stdint.h>

/* RSDP lives here when the VMM (libkrun) installs ACPI tables. */
#define ACPI_RSDP_ADDR		0xe0000UL

/* 4K-aligned Multiprocessor Wakeup mailbox (ACPI NVS-style reserved RAM). */
#define MP_WAKEUP_MAILBOX_ADDR	0x5000UL
#define MP_WAKEUP_MAILBOX_SIZE	0x1000UL

#define ACPI_RSDP_SIG		"RSD PTR "
#define ACPI_MADT_SIG		"APIC"
#define ACPI_XSDT_SIG		"XSDT"

#define ACPI_MADT_TYPE_LOCAL_APIC		0
#define ACPI_MADT_TYPE_IO_APIC			1
#define ACPI_MADT_TYPE_MULTIPROC_WAKEUP		0x10

#define ACPI_MADT_MP_WAKEUP_SIZE_V0		16
#define ACPI_MADT_MP_WAKEUP_VERSION_V0		0

#define ACPI_MP_WAKE_COMMAND_NOOP		0
#define ACPI_MP_WAKE_COMMAND_WAKEUP		1
#define ACPI_MP_WAKE_COMMAND_TEST		2

#define ACPI_MP_WAKE_APICID_INVALID		0xffffffffU
#define ACPI_MP_WAKE_APICID_BROADCAST		0xfffffffeU

struct acpi_rsdp {
	char signature[8];
	uint8_t checksum;
	char oem_id[6];
	uint8_t revision;
	uint32_t rsdt_address;
	uint32_t length;
	uint64_t xsdt_address;
	uint8_t extended_checksum;
	uint8_t reserved[3];
} __attribute__((packed));

struct acpi_sdt_header {
	char signature[4];
	uint32_t length;
	uint8_t revision;
	uint8_t checksum;
	char oem_id[6];
	char oem_table_id[8];
	uint32_t oem_revision;
	uint32_t creator_id;
	uint32_t creator_revision;
} __attribute__((packed));

struct acpi_madt {
	struct acpi_sdt_header header;
	uint32_t local_apic_address;
	uint32_t flags;
} __attribute__((packed));

/* ACPI 6.4 Multiprocessor Wakeup Structure (version 0). */
struct acpi_madt_multiproc_wakeup {
	uint8_t type;
	uint8_t length;
	uint16_t mailbox_version;
	uint32_t reserved;
	uint64_t mailbox_address;
} __attribute__((packed));

/* Shared OS/firmware mailbox (OS-writable half starts at offset 0). */
struct acpi_madt_multiproc_wakeup_mailbox {
	uint16_t command;
	uint16_t reserved;
	uint32_t apic_id;
	uint64_t wakeup_vector;
} __attribute__((packed));

/*
 * Find the MADT installed by the VMM, append a Multiprocessor Wakeup
 * Structure pointing at @mailbox_addr, and recompute the MADT checksum.
 * Returns 0 on success, -1 if ACPI/MADT is missing or there is no room.
 */
int setup_madt_mailbox(uint64_t mailbox_addr);

/* Zero and initialize the wakeup mailbox at MP_WAKEUP_MAILBOX_ADDR. */
void setup_mp_wakeup_mailbox(void);

/*
 * Release APs from the early park so they enter the MADT mailbox wait
 * loop. The ready flag lives in the firmware image (already accepted).
 */
void release_aps(void);

#endif /* QBOOT_ACPI_H */
