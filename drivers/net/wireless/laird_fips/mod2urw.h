/*
 * Copyright (c) 2013 Laird, Inc.
 * Licensed under GPLv2.
 */

#ifndef _MOD2URW_H_
#define _MOD2URW_H_

#include <linux/skbuff.h>
typedef int FIPS_STATUS;
#define FIPS_STATUS_SUCCESS		0
#define FIPS_STATUS_FAILURE		(-1)

#ifndef fips_ccm_key_t
typedef struct {
	unsigned char key[16];	/* 128-bit aes key */
} fips_ccm_key_t;
#define fips_ccm_key_t fips_ccm_key_t
#endif

/* allocate items to be passed to sdclkm_xxx using sdclkm_alloc/free */
#define sdclkm_alloc(len) kmalloc(len, GFP_ATOMIC)
#define sdclkm_free(p)    kfree(p)

/* callback function to be used if context cannot wait (e.g. softirq/bh) */
typedef void (*sdclkm_callback_fn_ptr_t) (void *callback_data, int result);
typedef struct {
	sdclkm_callback_fn_ptr_t pfn;
	void *pdata;
} sdclkm_cb_t;
extern int sdclkm_fnecbencrypt(sdclkm_cb_t * cbd,
			       fips_ccm_key_t * pkey, void *m, int lm);
extern int sdclkm_fnccmencrypt_ex(sdclkm_cb_t * cbd,
				  fips_ccm_key_t * pkey,
				  void *n, int ln, void *a, int la,
				  void *m, int lm, void *t, int lt);
extern int sdclkm_fnccmdecrypt_ex(sdclkm_cb_t * cbd, fips_ccm_key_t * pkey,
				  void *n, int ln, void *a, int la,
				  void *m, int lm, void *t, int lt);
extern int sdclkm_skb_receive(sdclkm_cb_t * cbd, struct sk_buff *skb);
extern int sdclkm_skb_transmit(sdclkm_cb_t * cbd, struct sk_buff *skb, int *up);
extern int sdclkm_addkey(sdclkm_cb_t * cbd,
			 u32 * key_index,
			 u8 * key, int keylen, u8 * seq, int seqlen);
extern int sdclkm_setbssid(sdclkm_cb_t * cbd, u8 * bssid, int bssidlen);
#endif /* _MODLKM_H_ */
