/*
 * Copyright (c) 2013 Laird, Inc.
 * Licensed under GPLv2.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include "laird_i.h"

extern int laird_txrx_init(void);

#define VERSION_STRING "1.1"

/* initialization */
static int __init laird_init(void)
{
	int ret;
	printk(KERN_INFO "ath6kl_laird.ko: version %s\n", VERSION_STRING);
	ret = laird_txrx_init();
	if (ret) {
		printk(KERN_ALERT "laird_txrx_init() return error (%d)\n",
		       -ret);
		return -1;
	}
	/* register with driver */
	if (ath6kl_laird_register(&register_data) < 0)
		return -1;
	return 0;
}

/* cleanup and exit */
static void __exit laird_exit(void)
{
	/* clear the driver specific registration */
	(void)ath6kl_laird_register(NULL);
	/* stop/flush transmit/receive for unloading */
	laird_stop_txrx();
}

module_init(laird_init);
module_exit(laird_exit);

MODULE_AUTHOR("Laird");
MODULE_DESCRIPTION("Laird fips support");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(VERSION_STRING);
