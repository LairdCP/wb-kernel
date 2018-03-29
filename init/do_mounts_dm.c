/*
 * do_mounts_dm.c
 * Copyright (C) 2017 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Based on do_mounts_md.c
 *
 * This file is released under the GPLv2.
 */
#include <linux/async.h>
#include <linux/ctype.h>
#include <linux/device-mapper.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/delay.h>

#include "do_mounts.h"

#define DM_MAX_DEVICES 256
#define DM_MAX_NAME 32
#define DM_MAX_UUID 129

#define DM_MSG_PREFIX "init"

#define is_even(a) (((a) & 1) == 0)

/* See Documentation/device-mapper/dm-boot.txt for dm="..." format details. */

struct target {
	sector_t start;
	sector_t length;
	char *type;
	char *params;
	/* simple singly linked list */
	struct target *next;
};

struct dm_device {
	int minor;
	int ro;
	char name[DM_MAX_NAME];
	char uuid[DM_MAX_UUID];
	struct target *table;
	int table_count;
	/* simple singly linked list */
	struct dm_device *next;
};

static struct {
	unsigned long num_devices;
	char *str;
} dm_setup_args __initdata;

static int dm_early_setup __initdata;

static void __init *_align(void *ptr, unsigned int a)
{
	register unsigned long agn = --a;

	return (void *) (((unsigned long) ptr + agn) & ~agn);
}

/*
 * Unescape characters in situ, it replaces all occurrences of "\c"
 * with 'c'. This is normally used to unescape colons and semi-colons used
 * in boot format.
 */
static char __init *_unescape_char(char *str, const char c)
{
	int i = 0, j = 0;
	int len = strlen(str);

	if (len < 2)
		return str;

	while (j < len - 1) {
		if (str[j] == '\\' && str[j + 1] == c) {
			j = j + 2;
			str[i++] = c;
			continue;
		}
		str[i++] = str[j++];
	}

	if (j == len - 1)
		str[i++] = str[j];

	str[i] = '\0';

	return str;
}

static void __init dm_setup_cleanup(struct dm_device *devices)
{
	struct dm_device *dev = devices;

	while (dev) {
		struct dm_device *old_dev = dev;
		struct target *table = dev->table;

		while (table) {
			struct target *old_table = table;

			kfree(table->type);
			kfree(table->params);
			table = table->next;
			kfree(old_table);
			dev->table_count--;
		}
		WARN_ON(dev->table_count);
		dev = dev->next;
		kfree(old_dev);
	}
}

/*
 * Splits a string into tokens ignoring escaped chars
 *
 * Updates @s to point after the token, ready for the next call.
 *
 * @str: The string to be searched
 * @c: The character to search for
 *
 * Returns:
 *   The string found or NULL.
 */
static char __init *dm_find_unescaped_char(char **str, const char c)
{
	char *s = *str;
	char *p = strchr(*str, c);

	/* loop through all the characters */
	while (p != NULL) {
		/* scan backwards through preceding escapes */
		char *q = p;

		while (q > s && *(q - 1) == '\\')
			--q;
		/* even number of escapes so c is a token */
		if (is_even(p - q)) {
			*p = '\0';
			*str = p + 1;
			return s;
		}
		/* else odd escapes so c is escaped, keep going */
		p = strchr(p + 1, c);
	}

	if (strlen(*str)) {
		*str += strlen(*str);
		return s;
	}

	return NULL;
}

static struct target __init *dm_parse_table(struct dm_device *dev, char *str)
{
	char type[DM_MAX_TYPE_NAME], *ptr;
	struct target *table;
	int n;

	/* trim trailing space */
	for (ptr = str + strlen(str) - 1; ptr >= str; ptr--)
		if (!isspace((int) *ptr))
			break;
	ptr++;
	*ptr = '\0';

	/* trim leading space */
	for (ptr = str; *ptr && isspace((int) *ptr); ptr++)
		;

	if (!*ptr)
		return NULL;

	table = kzalloc(sizeof(struct target), GFP_KERNEL);
	if (!table)
		return NULL;

	if (sscanf(ptr, "%llu %llu %s %n", &table->start, &table->length,
		   type, &n) < 3) {
		DMERR("invalid format of table \"%s\"", str);
		goto parse_fail;
	}

	table->type = kstrndup(type, strlen(type), GFP_KERNEL);
	if (!table->type) {
		DMERR("invalid type of table");
		goto parse_fail;
	}

	ptr += n;
	table->params = kstrndup(ptr, strlen(ptr), GFP_KERNEL);
	if (!table->params) {
		DMERR("invalid params for table");
		goto parse_fail;
	}

	dev->table_count++;

	return table;

parse_fail:
	kfree(table);
	return NULL;
}

static int __init dm_parse_device(struct dm_device *dev, char *dev_info)
{
	int field = 0;
	char *str = dev_info, *ptr = dev_info;
	struct target *table;
	struct target **tail = &dev->table;

	while ((str = dm_find_unescaped_char(&ptr, ',')) != NULL) {
		str = _unescape_char(str, ',');
		switch (field) {
		case 0: /* set device name */
			strncpy(dev->name, str, strlen(str));
			break;
		case 1: /* set uuid if any */
			strncpy(dev->uuid, str, strlen(str));
			break;
		case 2:
			/* set as read-only if flags = "ro" | "" */
			if (!strncmp(str, "ro", strlen(str)) || !strlen(str))
				dev->ro = 1;
			else if (!strncmp(str, "rw", strlen(str)))
				dev->ro = 0;
			else
				return -EINVAL;
			break;
		default:
			table = dm_parse_table(dev, str);
			if (!table)
				goto parse_fail;

			*tail = table;
			tail = &table->next;

			break;
		}
		field++;
	}

	if (field < 4)
		goto parse_fail;

	return 0;

parse_fail:
	return -EINVAL;
}

static struct dm_device __init *dm_parse_args(void)
{
	struct dm_device *devices = NULL;
	struct dm_device **tail = &devices;
	struct dm_device *dev;
	char *dev_info, *str = dm_setup_args.str;

	while ((dev_info = dm_find_unescaped_char(&str, ';')) != NULL) {
		dev_info = _unescape_char(dev_info, ';');
		dev = kzalloc(sizeof(*dev), GFP_KERNEL);
		if (!dev)
			goto error;

		if (dm_parse_device(dev, dev_info))
			goto error;

		*tail = dev;
		tail = &dev->next;
		/*
		 * devices are given minor numbers 0 - n-1 in the order they are
		 * found in the arg string.
		 */
		dev->minor = dm_setup_args.num_devices++;

		if (dm_setup_args.num_devices > DM_MAX_DEVICES) {
			DMERR("too many devices %lu > %d",
			      dm_setup_args.num_devices, DM_MAX_DEVICES);
			goto error;
		}
	}
	return devices;
error:
	dm_setup_cleanup(devices);
	return NULL;
}

/*
 * Parse the command-line parameters given our kernel, but do not
 * actually try to invoke the DM device now; that is handled by
 * dm_setup_drives after the low-level disk drivers have initialised.
 * dm format is described at the top of the file.
 *
 * Because dm minor numbers are assigned in ascending order starting with 0,
 * You can assume the first device is /dev/dm-0, the next device is /dev/dm-1,
 * and so forth.
 */
static int __init dm_setup(char *str)
{
	if (!str) {
		DMERR("Invalid arguments supplied to dm=.");
		return 0;
	}

	DMDEBUG("Want to parse \"%s\"", str);

	dm_setup_args.num_devices = 0;
	dm_setup_args.str = str;

	dm_early_setup = 1;

	return 1;
}

static char __init *dm_add_target(struct target *table, char *out, char *end)
{
	char *out_sp = out;
	struct dm_target_spec sp;
	size_t sp_size = sizeof(struct dm_target_spec);
	int len;
	char *pt;

	if (strlen(table->type) >= sizeof(sp.target_type)) {
		DMERR("target type name %s is too long.", table->type);
		return NULL;
	}

	sp.status = 0;
	sp.sector_start = table->start;
	sp.length = table->length;
	strncpy(sp.target_type, table->type, sizeof(sp.target_type) - 1);
	sp.target_type[sizeof(sp.target_type) - 1] = '\0';

	out += sp_size;
	pt = table->params;
	len = strlen(table->params);

	if ((out >= end) || (out + len + 1) >= end) {
		DMERR("ran out of memory building ioctl parameter");
		return NULL;
	}

	strcpy(out, table->params);
	out += len + 1;
	/* align next block */
	out = _align(out, 8);

	sp.next = out - out_sp;
	memcpy(out_sp, &sp, sp_size);

	return out;
}

static struct dm_ioctl __init *dm_setup_ioctl(struct dm_device *dev, int flags)
{
	const size_t min_size = 16 * 1024;
	size_t len = sizeof(struct dm_ioctl);
	struct dm_ioctl *dmi;
	struct target *table = dev->table;
	char *b, *e;

	if (len < min_size)
		len = min_size;

	dmi = kzalloc(len, GFP_KERNEL);
	if (!dmi)
		return NULL;

	dmi->version[0] = 4;
	dmi->version[1] = 0;
	dmi->version[2] = 0;
	dmi->data_size = len;
	dmi->data_start = sizeof(struct dm_ioctl);
	dmi->flags = flags;
	dmi->dev = dev->minor;
	dmi->target_count = dev->table_count;
	dmi->event_nr = 1;

	strncpy(dmi->name, dev->name, sizeof(dmi->name));

	b = (char *) (dmi + 1);
	e = (char *) dmi + len;

	while (table != NULL) {
		DMDEBUG("device %s adding table '%llu %llu %s %s'",
			dev->name,
			(unsigned long long) table->start,
			(unsigned long long) table->length,
			table->type, table->params);
		b = dm_add_target(table, b, e);
		if (!b)
			return NULL;
		table = table->next;
	}

	return dmi;
}

static void __init dm_setup_drives(void)
{
	struct dm_device *dev;
	int flags;
	struct dm_device *devices;
	struct dm_ioctl *io = NULL;

	devices = dm_parse_args();

	for (dev = devices; dev; dev = dev->next) {
		io = dm_setup_ioctl(dev, 0);
		if (!io)
			return;
		/* create a new device */
		if (dm_ioctl_cmd(DM_DEV_CREATE, io)) {
			DMERR("failed to create device %s", dev->name);
			goto out_free;
		}
		kfree(io);

		flags = DM_STATUS_TABLE_FLAG;
		if (dev->ro)
			flags |= DM_READONLY_FLAG;

		io = dm_setup_ioctl(dev, flags);
		if (!io)
			return;
		/* load a table into the 'inactive' slot for the device. */
		if (dm_ioctl_cmd(DM_TABLE_LOAD, io)) {
			DMERR("failed to load device %s tables", dev->name);
			goto out_free;
		}
		kfree(io);

		io = dm_setup_ioctl(dev, 0);
		if (!io)
			return;
		/* resume and the device should be ready. */
		if (dm_ioctl_cmd(DM_DEV_SUSPEND, io)) {
			DMERR("failed to resume device %s", dev->name);
			goto out_free;
		}

		DMINFO("dm-%d (%s) is ready", dev->minor, dev->name);
	}

out_free:
	kfree(io);
}

__setup("dm=", dm_setup);

void __init dm_run_setup(void)
{
	if (!dm_early_setup)
		return;
	DMINFO("attempting early device configuration.");
	dm_setup_drives();
}
