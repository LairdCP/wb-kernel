/*
 * Copyright (c) 2013 Laird, Inc.
 * Licensed under GPLv2.
 */
#include <linux/module.h>
#include "touser.h"
#include "mod2urw.h"
#include "mod2ufn.h"

static const cmd_def_t def_ecb = {
	SDCCMD_ECB_ENCRYPT, 2,
	{
	 ITEM_TO_HOST,			/* key */
	 ITEM_TO_HOST | ITEM_FROM_HOST,	/* data */
	 0}
};

int sdclkm_fnecbencrypt(sdclkm_cb_t * cbd,
			fips_ccm_key_t * pkey, void *text, int len)
{
	item_ptr_t it[2];
	it[0].p = pkey;
	it[0].len = sizeof(*pkey);
	it[1].p = text;
	it[1].len = len;
	return sdclkm_command(cbd, &def_ecb, it);
}

static const cmd_def_t def_ccmencrypt = {
	SDCCMD_CCM_ENCRYPT, 5,
	{
	 ITEM_TO_HOST,			/* key */
	 ITEM_TO_HOST,			/* n */
	 ITEM_TO_HOST,			/* a */
	 ITEM_TO_HOST | ITEM_FROM_HOST,	/* m */
	 ITEM_FROM_HOST,		/* t */
	 0}
};

int sdclkm_fnccmencrypt_ex(sdclkm_cb_t * cbd,
			   fips_ccm_key_t * pkey,
			   void *n, int ln,
			   void *a, int la, void *m, int lm, void *t, int lt)
{
	item_ptr_t it[5];
	it[0].p = pkey;
	it[0].len = sizeof(*pkey);
	it[1].p = n;
	it[1].len = ln;
	it[2].p = a;
	it[2].len = la;
	it[3].p = m;
	it[3].len = lm;
	it[4].p = t;
	it[4].len = lt;
	return sdclkm_command(cbd, &def_ccmencrypt, it);
}

static const cmd_def_t def_ccmdecrypt = {
	SDCCMD_CCM_DECRYPT, 5,
	{
	 ITEM_TO_HOST,			/* key */
	 ITEM_TO_HOST,			/* n */
	 ITEM_TO_HOST,			/* a */
	 ITEM_TO_HOST | ITEM_FROM_HOST,	/* m */
	 ITEM_TO_HOST,			/* t */
	 0}
};

int sdclkm_fnccmdecrypt_ex(sdclkm_cb_t * cbd,
			   fips_ccm_key_t * pkey,
			   void *n, int ln,
			   void *a, int la, void *m, int lm, void *t, int lt)
{
	item_ptr_t it[5];
	it[0].p = pkey;
	it[0].len = sizeof(*pkey);
	it[1].p = n;
	it[1].len = ln;
	it[2].p = a;
	it[2].len = la;
	it[3].p = m;
	it[3].len = lm;
	it[4].p = t;
	it[4].len = lt;
	return sdclkm_command(cbd, &def_ccmdecrypt, it);
}

EXPORT_SYMBOL(sdclkm_fnecbencrypt);
EXPORT_SYMBOL(sdclkm_fnccmencrypt_ex);
EXPORT_SYMBOL(sdclkm_fnccmdecrypt_ex);

/*======================================================================*/
#define DVR_HEADROOM 64
static const cmd_def_t def_skb_receive = {
	SDCCMD_DVR_RECEIVE, 2,
	{
	 0,			/* socket buffer wrapper (with head/tail) */
	 ITEM_TO_HOST | ITEM_FROM_HOST | ITEM_SKB,	/* socket buffer data */
	 0}
};

int sdclkm_skb_receive(sdclkm_cb_t * cbd, struct sk_buff *skb)
{
	item_ptr_t it[2];
	int headroom;
	headroom = (skb_headroom(skb) & 3) + DVR_HEADROOM;
	it[0].p = skb->data - headroom;
	it[0].len = 2048;
	it[1].p = skb->data;
	it[1].len = skb->len;
	it[1].skb = skb;
	return sdclkm_command(cbd, &def_skb_receive, it);
}

static const cmd_def_t def_skb_transmit = {
	SDCCMD_DVR_TRANSMIT, 3,
	{
	 0,			/* socket buffer wrapper (with head/tail) */
	 ITEM_TO_HOST | ITEM_FROM_HOST | ITEM_SKB,	/* socket buffer data */
	 ITEM_TO_HOST,		/* up (user priority) */
	 0}
};

int sdclkm_skb_transmit(sdclkm_cb_t * cbd, struct sk_buff *skb, int *up)
{
	item_ptr_t it[3];
	int headroom;
	headroom = (skb_headroom(skb) & 3) + DVR_HEADROOM;
	it[0].p = skb->data - headroom;
	it[0].len = 2048;
	it[1].p = skb->data;
	it[1].len = skb->len;
	it[1].skb = skb;
	it[2].p = up;
	it[2].len = sizeof(*up);
	return sdclkm_command(cbd, &def_skb_transmit, it);
}

static const cmd_def_t def_addkey = {
	SDCCMD_DVR_ADDKEY, 3,
	{
	 ITEM_TO_HOST,		/* key_index, pairwise */
	 ITEM_TO_HOST,		/* key */
	 ITEM_TO_HOST,		/* seq */
	 0}
};

int sdclkm_addkey(sdclkm_cb_t * cbd,
		  u32 * key_index, u8 * key, int keylen, u8 * seq, int seqlen)
{
	item_ptr_t it[3];
	it[0].p = key_index;
	it[0].len = sizeof(*key_index);
	it[1].p = key;
	it[1].len = keylen;
	it[2].p = seq;
	it[2].len = seqlen;
	return sdclkm_command(cbd, &def_addkey, it);
}

static const cmd_def_t def_setbssid = {
	SDCCMD_DVR_SETBSSID, 1,
	{
	 ITEM_TO_HOST,		/* bssid */
	 0}
};

int sdclkm_setbssid(sdclkm_cb_t * cbd, u8 * bssid, int bssidlen)
{
	item_ptr_t it[1];
	it[0].p = bssid;
	it[0].len = bssidlen;
	return sdclkm_command(cbd, &def_setbssid, it);
}

EXPORT_SYMBOL(sdclkm_skb_receive);
EXPORT_SYMBOL(sdclkm_skb_transmit);
EXPORT_SYMBOL(sdclkm_addkey);
EXPORT_SYMBOL(sdclkm_setbssid);
