/*
 * Copyright (c) 2013 Laird, Inc.
 * Licensed under GPLv2.
 */

#ifndef LAIRD_I_H
#define LAIRD_I_H

#include <linux/etherdevice.h>
#include "laird_common.h"

struct laird_wlanhdr {
	u8 fc[2];
#define FC0_FTYPE      (3<<2)
#define FC0_FTYPE_DATA (2<<2)
#define FC0_STYPE_QOS  (1<<7)
#define FC1_TODS       (1<<0)
#define FC1_FROMDS     (1<<1)
#define FC1_MOREFRAGS  (1<<2)
#define FC1_PROTECTED  (1<<6)
	__le16 dur;
	u8 addr1[6];
	u8 addr2[6];
	u8 addr3[6];
	u8 seq[2];
#define SEQ0_FRAG (0xF)
} __packed;

void laird_printhexs(const char *psz, const char *pf, const void *buf, int len);
int ecr_wlanhdr_len(struct laird_wlanhdr *hdr);

/* stopping the driver (rmmod) support */
extern int laird_stop_txrx(void);
extern const laird_register_data_t register_data;

#endif /* LAIRD_I_H */
