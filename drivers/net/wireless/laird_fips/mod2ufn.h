/*
 * Copyright (c) 2013 Laird, Inc.
 * Licensed under GPLv2.
 */

#ifndef _MOD2UFN_H_
#define _MOD2UFN_H_

/* defines the cmd -- number of parameters and handling for each
 * this will be constant for a given command
 */
typedef struct {		/* command control handling */
	int cmd;
	int numit;
	int flags[MAXIT];
#define ITEM_TO_HOST 1
#define ITEM_FROM_HOST 2
#define ITEM_SKB 4
} cmd_def_t;

typedef struct {
	void *p;		/* pointer to item */
	int len;		/* length of item */
	void *skb;		/* for socket buffers passed to/from user space */
} item_ptr_t;

extern int sdclkm_command(sdclkm_cb_t * cbd,
						  const cmd_def_t * def, item_ptr_t * itp);

#endif
