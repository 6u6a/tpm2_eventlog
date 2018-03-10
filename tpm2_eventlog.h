
#ifndef __TPM_EVENTLOG_H__
#define __TPM_EVENTLOG_H__

#define TCG_EVENT_NAME_LEN_MAX	255
#define MAX_TEXT_EVENT		1000	/* Max event string length */
#define ACPI_TCPA_SIG		"TCPA"	/* 0x41504354 /'TCPA' */

enum bios_platform_class {
	BIOS_CLIENT = 0x00,
	BIOS_SERVER = 0x01,
};

struct tpm_bios_log {
	void *bios_event_log;
	void *bios_event_log_end;
};

struct tcpa_event {
	u32 pcr_index;
	u32 event_type;
	u8 pcr_value[20];	/* SHA1 */
	u32 event_size;
	u8 event_data[0];
};

//---------------------------------------------
#define TPM2_ALG_SHA1               0x0004
#define TPM2_ALG_SHA256             0x000b
#define TPM2_ALG_SHA384             0x000c
#define TPM2_ALG_SHA512             0x000d
#define TPM2_ALG_SM3_256            0x0012
//---------------------------------------------
#define SHA1_BUFSIZE                20
#define SHA256_BUFSIZE              32
#define SHA384_BUFSIZE              48
#define SHA512_BUFSIZE              64
#define SM3_256_BUFSIZE             32

typedef struct tpm2_digest_value{
	u16 hashAlg;
	u8 hash[0];
}tpm2_digest_value;

typedef struct tpm2_digest_values{
	u32 count;
	tpm2_digest_value value[0];
}tpm2_digest_values;

typedef struct tpm2_event{
	u32 pcr_index;
	u32 event_type;
	tpm2_digest_values digest[0];
}tpm2_event;

typedef struct tpm2_tail{
	u32 eventdatasize;
	u8 event[0];
}tpm2_tail;

enum tcpa_event_types {
	PREBOOT = 0,
	POST_CODE,
	UNUSED,
	NO_ACTION,
	SEPARATOR,
	ACTION,
	EVENT_TAG,
	SCRTM_CONTENTS,
	SCRTM_VERSION,
	CPU_MICROCODE,
	PLATFORM_CONFIG_FLAGS,
	TABLE_OF_DEVICES,
	COMPACT_HASH,
	IPL,
	IPL_PARTITION_DATA,
	NONHOST_CODE,
	NONHOST_CONFIG,
	NONHOST_INFO,
};

struct tcpa_pc_event {
	u32 event_id;
	u32 event_size;
	u8 event_data[0];
};

enum tcpa_pc_event_ids {
	SMBIOS = 1,
	BIS_CERT,
	POST_BIOS_ROM,
	ESCD,
	CMOS,
	NVRAM,
	OPTION_ROM_EXEC,
	OPTION_ROM_CONFIG,
	OPTION_ROM_MICROCODE = 10,
	S_CRTM_VERSION,
	S_CRTM_CONTENTS,
	POST_CONTENTS,
	HOST_TABLE_OF_DEVICES,
};

int read_log(struct tpm_bios_log *log);
int tpm20_get_hash_buffersize(u16 hashAlg);

extern struct dentry **tpm_bios_log_setup(char *);
extern void tpm_bios_log_teardown(struct dentry **);

#endif
