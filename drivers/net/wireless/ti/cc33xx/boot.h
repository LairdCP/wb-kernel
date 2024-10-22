/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * This file is part of cc33xx
 *
 * Copyright (C) 2008-2009 Nokia Corporation
 *
 * Contact: Luciano Coelho <luciano.coelho@nokia.com>
 */

#ifndef __BOOT_H__
#define __BOOT_H__

#include "wlcore.h"

int cc33xx_init_fw(struct cc33xx *wl);

void cc33xx_handle_boot_irqs(struct cc33xx *wl, u32 pending_interrupts);

#define SECOND_LOADER_NAME "ti-connectivity/cc33xx_2nd_loader.bin"
#define FW_NAME "ti-connectivity/cc33xx_fw.bin"


struct cc33xx_fw_download {
	atomic_t pending_irqs;
	struct completion wait_on_irq;
	size_t max_transfer_size;
};

/* number of times we try to read the INIT interrupt */
#define INIT_LOOP 20000

/* delay between retries */
#define INIT_LOOP_DELAY 50

#define WU_COUNTER_PAUSE_VAL 0x3FF
#define WELP_ARM_COMMAND_VAL 0x4

#endif
