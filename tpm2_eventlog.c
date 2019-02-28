#include <linux/module.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/tpm.h>
#include <linux/acpi.h>
#include <linux/cdev.h>

#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "tpm2_eventlog.h"


static const char* tcpa_event_type_strings[] = {
	"PREBOOT",
	"POST CODE",
	"",
	"NO ACTION",
	"SEPARATOR",
	"ACTION",
	"EVENT TAG",
	"S-CRTM Contents",
	"S-CRTM Version",
	"CPU Microcode",
	"Platform Config Flags",
	"Table of Devices",
	"Compact Hash",
	"IPL",
	"IPL Partition Data",
	"Non-Host Code",
	"Non-Host Config",
	"Non-Host Info"
};

static const char* tcpa_pc_event_id_strings[] = {
	"",
	"SMBIOS",
	"BIS Certificate",
	"POST BIOS ",
	"ESCD ",
	"CMOS",
	"NVRAM",
	"Option ROM",
	"Option ROM config",
	"",
	"Option ROM microcode ",
	"S-CRTM Version",
	"S-CRTM Contents ",
	"POST Contents ",
	"Table of Devices",
};

struct acpi_tcpa {
	struct acpi_table_header hdr;
	u16 platform_class;
	union {
		struct client_hdr {
			u32 log_max_len __packed;
			u64 log_start_addr __packed;
		} client;
		struct server_hdr {
			u16 reserved;
			u64 log_max_len __packed;
			u64 log_start_addr __packed;
		} server;
	};
};

/* read binary bios log */
int read_log(struct tpm_bios_log *log)
{
	struct acpi_tcpa *buff;
	acpi_status status;
	void __iomem *virt;
	u64 len, start;

	if (log->bios_event_log != NULL) {
		printk(KERN_ERR
		       "%s: ERROR - Eventlog already initialized\n",
		       __func__);
		return -EFAULT;
	}

	/* Find TCPA entry in RSDT (ACPI_LOGICAL_ADDRESSING) */
	status = acpi_get_table(ACPI_SIG_TCPA, 1,
				(struct acpi_table_header **)&buff);

	if (ACPI_FAILURE(status)) {
		printk(KERN_ERR "%s: ERROR - Could not get TCPA table\n",
		       __func__);
		return -EIO;
	}

	switch(buff->platform_class) {
	case BIOS_SERVER:
		len = buff->server.log_max_len;
		start = buff->server.log_start_addr;
		break;
	case BIOS_CLIENT:
	default:
		len = buff->client.log_max_len;
		start = buff->client.log_start_addr;
		break;
	}
	if (!len) {
		printk(KERN_ERR "%s: ERROR - TCPA log area empty\n", __func__);
		return -EIO;
	}
	printk("6u6a: log length: 0x%llx\n", len);
	/* malloc EventLog space */
	log->bios_event_log = kmalloc(len, GFP_KERNEL);
	if (!log->bios_event_log) {
		printk("%s: ERROR - Not enough  Memory for BIOS measurements\n",
			__func__);
		return -ENOMEM;
	}

	log->bios_event_log_end = log->bios_event_log + len;

	virt = acpi_os_map_memory(start, len);
	if (!virt) {
		kfree(log->bios_event_log);
		printk("%s: ERROR - Unable to map memory\n", __func__);
		return -EIO;
	}

	memcpy_fromio(log->bios_event_log, virt, len);
	acpi_os_unmap_memory(virt, len);
	return 0;
}

int tpm20_get_hash_buffersize(u16 hashAlg){
    switch (hashAlg) {
    case TPM2_ALG_SHA1:
        return SHA1_BUFSIZE;
    case TPM2_ALG_SHA256:
        return SHA256_BUFSIZE;
    case TPM2_ALG_SHA384:
        return SHA384_BUFSIZE;
    case TPM2_ALG_SHA512:
        return SHA512_BUFSIZE;
    case TPM2_ALG_SM3_256:
        return SM3_256_BUFSIZE;
    default:
        return -1;
    }
}

/* returns pointer to start of pos. entry of tcg log */
static void *tpm2_binary_bios_measurements_start(struct seq_file *m, loff_t *pos)
{
	loff_t i, j;
	u32 bufsize;
	struct tpm_bios_log *log = m->private;
	void *addr = log->bios_event_log;
	void *limit = log->bios_event_log_end;
	tpm2_event *event;
	tpm2_digest_values *digest_values;
	tpm2_digest_value *digest_value;
    //跳过seabios给tpm2.0日志添加的头部，该头部的结构和tcpa的日志记录格式一样
    event = addr;
    if ((addr + sizeof(struct tcpa_event)) + ((struct tcpa_event *)event)->event_size < limit) {
        if (((struct tcpa_event *)event)->event_type == 0 && ((struct tcpa_event *)event)->event_size == 0)
            return NULL;
		if(*pos == 0){
			char *data = addr;
			for(i = 0; i < sizeof(struct tcpa_event) + ((struct tcpa_event *)event)->event_size; i ++){
				seq_putc(m, data[i]);
			}
		}
        addr += sizeof(struct tcpa_event) + ((struct tcpa_event *)event)->event_size;
    }

	/* read over *pos measurements */
	for (i = 0; i < *pos + 1; i++){//i=1是越过第一条记录; i<*pos+1是为了多检查一条记录，以保证用户获取的当前记录是有效的
		event = addr;
		if ((addr + sizeof(tpm2_event) + sizeof(tpm2_digest_values)) < limit){
            digest_values = event->digest;
            addr += sizeof(tpm2_event) + sizeof(tpm2_digest_values);
            for(j = 0; j < digest_values->count && (addr + sizeof(tpm2_digest_value)) < limit; j ++){
                digest_value = addr;
                addr += sizeof(tpm2_digest_value);
                bufsize = tpm20_get_hash_buffersize(digest_value->hashAlg);
                if(bufsize <= 0){//出现不支持的算法
                    return NULL;
                }
                if(addr + bufsize < limit){
                    addr += bufsize;
                }else{
                    printk("log is small!\n");
                    return NULL;
                }
            }
            if (event->event_type == 0 && ((tpm2_tail *)addr)->eventdatasize == 0)
				return NULL;
            addr += sizeof(tpm2_tail) + ((tpm2_tail *)addr)->eventdatasize;
            if(addr >= limit){
                printk("log is small!\n");
                return NULL;
            }
		}
	}
    addr = event;//退回到当前记录的最开始

	return addr;
}

static void *tpm2_bios_measurements_next(struct seq_file *m, void *v,
					loff_t *pos)
{
	struct tpm_bios_log *log = m->private;
	void *limit = log->bios_event_log_end;
	tpm2_event *event = v;
	tpm2_digest_values *digest_values;
	tpm2_digest_value *digest_value;
	int i, j, bufsize;
	void *addr = v;

	for (i = 0; i < 2; i++){//i<2是为了多检查一条记录，以保证用户获取的当前记录是有效的
		event = addr;
		if ((addr + sizeof(tpm2_event) + sizeof(tpm2_digest_values)) < limit){
            digest_values = event->digest;
            addr += sizeof(tpm2_event) + sizeof(tpm2_digest_values);
            for(j = 0; j < digest_values->count && (addr + sizeof(tpm2_digest_value)) < limit; j ++){
                digest_value = addr;
                addr += sizeof(tpm2_digest_value);
                bufsize = tpm20_get_hash_buffersize(digest_value->hashAlg);
                if(bufsize <= 0){//出现不支持的算法
                    return NULL;
                }
                if(addr + bufsize < limit){
                    addr += bufsize;
                }else{
                    printk("log is small!\n");
                    return NULL;
                }
            }

            if (event->event_type == 0 && ((tpm2_tail *)addr)->eventdatasize == 0)
				return NULL;
            addr += sizeof(tpm2_tail) + ((tpm2_tail *)addr)->eventdatasize;
            if(addr >= limit){
                printk("log is small!\n");
                return NULL;
            }
		}
	}
    addr = event;//退回到当前记录的最开始
    v = addr;
	(*pos)++;
	return v;
}

static void tpm2_bios_measurements_stop(struct seq_file *m, void *v)
{
}


static int tpm2_binary_bios_measurements_show(struct seq_file *m, void *v)
{
	struct tpm2_event *event = v;
	char *data = v;
	int i, j, bufsize;
	tpm2_digest_values *digest_values;
	tpm2_digest_value *digest_value;
    for(i = 0; i < sizeof(tpm2_event) + sizeof(tpm2_digest_values); i ++){
        seq_putc(m, data[i]);
    }
    data += i;
    digest_values = event->digest;
    for(j = 0; j < digest_values->count; j ++){
        digest_value = (void *)data;
        bufsize = tpm20_get_hash_buffersize(digest_value->hashAlg);
        if(bufsize <= 0){//出现不支持的算法
            return -1;
        }
        for(i = 0; i < sizeof(tpm2_digest_value) +  bufsize; i ++){
            seq_putc(m, data[i]);
        }
        data += i;
    }
    for(i = 0; i < sizeof(tpm2_tail) + ((tpm2_tail *)data)->eventdatasize; i ++){
        seq_putc(m, data[i]);
    }
    data += i;
	return 0;
}

static int get_event_name(char *dest, struct tpm2_tail *event,
			unsigned char * event_entry, u32 event_type)
{
	const char *name = "";
	/* 41 so there is room for 40 data and 1 nul */
	char data[41] = "";
	int i, n_len = 0, d_len = 0;
	struct tcpa_pc_event *pc_event;

	switch(event_type) {
	case PREBOOT:
	case POST_CODE:
	case UNUSED:
	case NO_ACTION:
	case SCRTM_CONTENTS:
	case SCRTM_VERSION:
	case CPU_MICROCODE:
	case PLATFORM_CONFIG_FLAGS:
	case TABLE_OF_DEVICES:
	case COMPACT_HASH:
	case IPL:
	case IPL_PARTITION_DATA:
	case NONHOST_CODE:
	case NONHOST_CONFIG:
	case NONHOST_INFO:
		name = tcpa_event_type_strings[event_type];
		n_len = strlen(name);
		break;
	case SEPARATOR:
	case ACTION:
		if (MAX_TEXT_EVENT > event->eventdatasize) {
			name = event_entry;
			n_len = event->eventdatasize;
		}
		break;
	case EVENT_TAG:
		pc_event = (struct tcpa_pc_event *)event_entry;

		/* ToDo Row data -> Base64 */

		switch (pc_event->event_id) {
		case SMBIOS:
		case BIS_CERT:
		case CMOS:
		case NVRAM:
		case OPTION_ROM_EXEC:
		case OPTION_ROM_CONFIG:
		case S_CRTM_VERSION:
			name = tcpa_pc_event_id_strings[pc_event->event_id];
			n_len = strlen(name);
			break;
		/* hash data */
		case POST_BIOS_ROM:
		case ESCD:
		case OPTION_ROM_MICROCODE:
		case S_CRTM_CONTENTS:
		case POST_CONTENTS:
			name = tcpa_pc_event_id_strings[pc_event->event_id];
			n_len = strlen(name);
			for (i = 0; i < 20; i++)
				d_len += sprintf(&data[2*i], "%02x",
						pc_event->event_data[i]);
			break;
		default:
			break;
		}
	default:
		break;
	}

	return snprintf(dest, MAX_TEXT_EVENT, "[%.*s%.*s] [%.*s]",
			n_len, name, d_len, data, event->eventdatasize, event_entry);

}

static int tpm2_ascii_bios_measurements_show(struct seq_file *m, void *v)
{
	int len = 0, i, j;
	char *eventname;
	tpm2_event *event = v;
	tpm2_digest_values *digest_values = event->digest;
	tpm2_digest_value *digest_value;
	void *event_entry = NULL, *p = v;//event data entry

	eventname = kmalloc(MAX_TEXT_EVENT, GFP_KERNEL);
	if (!eventname) {
		printk(KERN_ERR "%s: ERROR - No Memory for event name\n ",
		       __func__);
		return -EFAULT;
	}

	seq_printf(m, "%2d", event->pcr_index);

	/* 2nd: digest */
	p += sizeof(tpm2_event) + sizeof(tpm2_digest_values);
    for(i = 0; i < digest_values->count; i ++){
        digest_value = p;
        seq_printf(m, " %04x ", digest_value->hashAlg);
        len = tpm20_get_hash_buffersize(digest_value->hashAlg);
        //printk("%04x->%d\n", digest_value->hashAlg, len);
        for(j = 0; j < len; j ++){
            seq_printf(m, "%02x", 0xff & digest_value->hash[j]);
        }
        p += sizeof(tpm2_digest_value) + len;
    }

	/* 3rd: event type identifier */
	seq_printf(m, " %02x", event->event_type);

    event_entry = p + sizeof(tpm2_tail);
	len += get_event_name(eventname, (void *)p, event_entry, event->event_type);

	/* 4th: eventname <= max + \'0' delimiter */
	seq_printf(m, "%s\n", eventname);
	kfree(eventname);
	return 0;
}
/* returns pointer to start of pos. entry of tcg log */
static void *tpm2_ascii_bios_measurements_start(struct seq_file *m, loff_t *pos)
{
	loff_t i, j;
	u32 bufsize;
	struct tpm_bios_log *log = m->private;
	void *addr = log->bios_event_log;
	void *limit = log->bios_event_log_end;
	tpm2_event *event;
	tpm2_digest_values *digest_values;
	tpm2_digest_value *digest_value;
    //跳过seabios给tpm2.0日志添加的头部，该头部的结构和tcpa的日志记录格式一样
    event = addr;
    if ((addr + sizeof(struct tcpa_event)) + ((struct tcpa_event *)event)->event_size < limit) {
        if (((struct tcpa_event *)event)->event_type == 0 && ((struct tcpa_event *)event)->event_size == 0)
            return NULL;
        addr += sizeof(struct tcpa_event) + ((struct tcpa_event *)event)->event_size;
    }

	/* read over *pos measurements */
	for (i = 0; i < *pos + 1; i++){//i=1是越过第一条记录; i<*pos+1是为了多检查一条记录，以保证用户获取的当前记录是有效的
		event = addr;
		if ((addr + sizeof(tpm2_event) + sizeof(tpm2_digest_values)) < limit){
            digest_values = event->digest;
            addr += sizeof(tpm2_event) + sizeof(tpm2_digest_values);
            for(j = 0; j < digest_values->count && (addr + sizeof(tpm2_digest_value)) < limit; j ++){
                digest_value = addr;
                addr += sizeof(tpm2_digest_value);
                bufsize = tpm20_get_hash_buffersize(digest_value->hashAlg);
                if(bufsize <= 0){//出现不支持的算法
                    return NULL;
                }
                if(addr + bufsize < limit){
                    addr += bufsize;
                }else{
                    printk("log is small!\n");
                    return NULL;
                }
            }
            if (event->event_type == 0 && ((tpm2_tail *)addr)->eventdatasize == 0)
				return NULL;
            addr += sizeof(tpm2_tail) + ((tpm2_tail *)addr)->eventdatasize;
            if(addr >= limit){
                printk("log is small!\n");
                return NULL;
            }
		}
	}
    addr = event;//退回到当前记录的最开始

	return addr;
}

static const struct seq_operations tpm2_ascii_b_measurments_seqops = {
	.start = tpm2_ascii_bios_measurements_start,
	.next = tpm2_bios_measurements_next,
	.stop = tpm2_bios_measurements_stop,
	.show = tpm2_ascii_bios_measurements_show,
};

static const struct seq_operations tpm2_binary_b_measurments_seqops = {
	.start = tpm2_binary_bios_measurements_start,
	.next = tpm2_bios_measurements_next,
	.stop = tpm2_bios_measurements_stop,
	.show = tpm2_binary_bios_measurements_show,
};


static int tpm_ascii_bios_measurements_open(struct inode *inode,
					    struct file *file)
{
	int err;
	struct tpm_bios_log *log;
	struct seq_file *seq;

	log = kzalloc(sizeof(struct tpm_bios_log), GFP_KERNEL);
	if (!log)
		return -ENOMEM;

	if ((err = read_log(log)))
		goto out_free;

	/* now register seq file */
	err = seq_open(file, &tpm2_ascii_b_measurments_seqops);
	if (!err) {
		seq = file->private_data;
		seq->private = log;
	} else {
		goto out_free;
	}

out:
	return err;
out_free:
	kfree(log->bios_event_log);
	kfree(log);
	goto out;
}

static int tpm_bios_measurements_release(struct inode *inode,
					 struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct tpm_bios_log *log = seq->private;

	if (log) {
		kfree(log->bios_event_log);
		kfree(log);
	}

	return seq_release(inode, file);
}

static const struct file_operations tpm_ascii_bios_measurements_ops = {
	.open = tpm_ascii_bios_measurements_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = tpm_bios_measurements_release,
};

static int tpm_binary_bios_measurements_open(struct inode *inode,
					     struct file *file)
{
	int err;
	struct tpm_bios_log *log;
	struct seq_file *seq;

	log = kzalloc(sizeof(struct tpm_bios_log), GFP_KERNEL);
	if (!log)
		return -ENOMEM;

	if ((err = read_log(log)))
		goto out_free;

	/* now register seq file */
	err = seq_open(file, &tpm2_binary_b_measurments_seqops);
	if (!err) {
		seq = file->private_data;
		seq->private = log;
	} else {
		goto out_free;
	}

out:
	return err;
out_free:
	kfree(log->bios_event_log);
	kfree(log);
	goto out;
}

static const struct file_operations tpm_binary_bios_measurements_ops = {
	.open = tpm_binary_bios_measurements_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = tpm_bios_measurements_release,
};

static int is_bad(void *p)
{
	if (!p)
		return 1;
	if (IS_ERR(p) && (PTR_ERR(p) != -ENODEV))
		return 1;
	return 0;
}

struct dentry **tpm_bios_log_setup(char *name)
{
	struct dentry **ret = NULL, *tpm_dir, *bin_file, *ascii_file;

	tpm_dir = securityfs_create_dir(name, NULL);
	if (is_bad(tpm_dir))
		goto out;

	bin_file =
	    securityfs_create_file("binary_bios_measurements",
				   S_IRUSR | S_IRGRP, tpm_dir, NULL,
				   &tpm_binary_bios_measurements_ops);
	if (is_bad(bin_file))
		goto out_tpm;

	ascii_file =
	    securityfs_create_file("ascii_bios_measurements",
				   S_IRUSR | S_IRGRP, tpm_dir, NULL,
				   &tpm_ascii_bios_measurements_ops);
	if (is_bad(ascii_file))
		goto out_bin;

	ret = kmalloc(3 * sizeof(struct dentry *), GFP_KERNEL);
	if (!ret)
		goto out_ascii;

	ret[0] = ascii_file;
	ret[1] = bin_file;
	ret[2] = tpm_dir;

	return ret;

out_ascii:
	securityfs_remove(ascii_file);
out_bin:
	securityfs_remove(bin_file);
out_tpm:
	securityfs_remove(tpm_dir);
out:
	return NULL;
}

void tpm_bios_log_teardown(struct dentry **lst)
{
	int i;

	for (i = 0; i < 3; i++)
		securityfs_remove(lst[i]);
}
struct dentry **huha = NULL;
static int tpm2_eventlog_init(void)
{
    huha = tpm_bios_log_setup("huha");
    return 0;
}

static void tpm2_eventlog_exit(void)
{
    tpm_bios_log_teardown(huha);
}

MODULE_LICENSE("GPL");

module_init(tpm2_eventlog_init);
module_exit(tpm2_eventlog_exit);
