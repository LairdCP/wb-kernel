/*
 * Copyright (c) 2013 Laird, Inc.
 * Licensed under GPLv2.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>	/* error codes */
#include <linux/types.h>	/* size_t */
#include <linux/proc_fs.h>
#include <linux/fcntl.h>	/* O_ACCMODE */
#include <linux/seq_file.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/spinlock.h>

#include <asm/uaccess.h>	/* copy_*_user */

#include "moddebug.h"

#ifndef _printkhexs
static char _dnib2hex(int x)
{
	if (x < 10)
		return '0' + x;
	if (x < 16)
		return 'a' + (x - 10);
	return '?';
}

void _printkhexs(const char *psz, const char *pfx, const void *buf, int len)
{
	const char *src = buf;
	printk(KERN_ALERT "%s: %s 0x%x[%d]\n", psz, pfx, (unsigned int)buf,
	       len);
	if (len > 128)
		len = 128;
	while (len) {
		int thislen = len > 16 ? 16 : len;
		char hexs[16 * 3];
		char *dst = &hexs[0];
		len -= thislen;
		while (thislen) {
			*dst++ = _dnib2hex(*src >> 4);
			*dst++ = _dnib2hex(*src & 0xf);
			*dst++ = ' ';
			src++;
			thislen--;
		}
		*(dst - 1) = 0;
		printk(KERN_ALERT "%s: %s\n", pfx, hexs);
	}
}
#endif
