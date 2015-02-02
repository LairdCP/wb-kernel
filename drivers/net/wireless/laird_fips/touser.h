/*
 * Copyright (c) 2013 Laird, Inc.
 * Licensed under GPLv2.
 */

#ifndef _TOUSER_H_
#define _TOUSER_H_

typedef struct {
	int offset;		/* offset from beginning of cmd_hdr_t */
	int len;		/* length of item */
} item_t;

/* command structure */
#define MAXIT 10
typedef struct {
	int len;		/* total length including this field */
	int cmd;		/* command to execute -- set to zero when completed */
#define SDCCMD_CCM_ENCRYPT	3
#define SDCCMD_CCM_DECRYPT	4
#define SDCCMD_ECB_ENCRYPT	5
#define SDCCMD_DVR_RECEIVE  6
#define SDCCMD_DVR_TRANSMIT 7
#define SDCCMD_DVR_ADDKEY   8
#define SDCCMD_DVR_SETBSSID 9
	int res;		/* result of command */
	int numit;		/* number of items used */
	item_t it[MAXIT];
	/* items follow at offsets relative to beginning of cmd_hdt_t */
} cmd_hdr_t;

#define E_LRD_BASE  1000
#define E_LRD_RX_NO_MEMORY           (E_LRD_BASE+0)
#define E_LRD_RX_BAD_PACKET          (E_LRD_BASE+1)
#define E_LRD_RX_UNENCRYPTED         (E_LRD_BASE+2)
#define E_LRD_RX_DISCARD_AMSDU       (E_LRD_BASE+3)
#define E_LRD_RX_FRAGMENT            (E_LRD_BASE+4)
#define E_LRD_RX_DISCARD_UNENCRYPTED (E_LRD_BASE+5)
#define E_LRD_RX_DECRYPT_OK          (E_LRD_BASE+6)
#define E_LRD_RX_DECRYPT_FAIL        (E_LRD_BASE+7)
#define E_LRD_RX_DECRYPT_REPLAY      (E_LRD_BASE+8)
#define E_LRD_RX_DECRYPT_NO_KEY      (E_LRD_BASE+9)

#define E_LRD_TX_NO_MEMORY           (E_LRD_BASE+10)
#define E_LRD_TX_BAD_PACKET          (E_LRD_BASE+11)
#define E_LRD_TX_UNENCRYPTED_OK      (E_LRD_BASE+12)
#define E_LRD_TX_UNENCRYPTED_FAIL    (E_LRD_BASE+13)
#define E_LRD_TX_ENCRYPT_OK          (E_LRD_BASE+14)
#define E_LRD_TX_ENCRYPT_FAIL        (E_LRD_BASE+15)
#define E_LRD_TX_ENCRYPT_NO_KEY      (E_LRD_BASE+16)
#define E_LRD_TX_NOT_CONNECTED       (E_LRD_BASE+17)

#endif
