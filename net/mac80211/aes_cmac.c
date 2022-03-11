// SPDX-License-Identifier: GPL-2.0-only
/*
 * AES-128-CMAC with TLen 16 for IEEE 802.11w BIP
 * Copyright 2008, Jouni Malinen <j@w1.fi>
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/export.h>
#include <linux/err.h>
#include <crypto/aes.h>

#include <net/mac80211.h>
#include "key.h"
#include "aes_cmac.h"

#if defined(CONFIG_LRDMWL_FIPS) && !defined(AHASH_REQUEST_ON_STACK)
#define AHASH_REQUEST_ON_STACK(name, ahash) \
	char __##name##_desc[sizeof(struct ahash_request) + \
		crypto_ahash_reqsize(ahash)] CRYPTO_MINALIGN_ATTR; \
	struct ahash_request *name = (void *)__##name##_desc
#endif

#define CMAC_TLEN 8 /* CMAC TLen = 64 bits (8 octets) */
#define CMAC_TLEN_256 16 /* CMAC TLen = 128 bits (16 octets) */
#define AAD_LEN 20

static const u8 zero[CMAC_TLEN_256] CRYPTO_MINALIGN_ATTR;

void ieee80211_aes_cmac(struct crypto_shash *tfm, const u8 *aad,
			const u8 *data, size_t data_len, u8 *mic)
{
#ifdef CONFIG_LRDMWL_FIPS
	struct crypto_ahash *tfma = (struct crypto_ahash *)tfm;
	struct scatterlist sg[4];
	AHASH_REQUEST_ON_STACK(ahreq, tfma);
	const __le16 *fc;

	fc = (const __le16 *)aad;
	if (ieee80211_is_beacon(*fc)) {
		sg_init_table(sg, 4);
		sg_set_buf(sg, aad, AAD_LEN);
		sg_set_buf(sg + 1, zero, 8);
		sg_set_buf(sg + 2, data + 8, data_len - 8 - CMAC_TLEN);
		sg_set_buf(sg + 3, zero, CMAC_TLEN);
	} else {
		sg_init_table(sg, 3);
		sg_set_buf(sg, aad, AAD_LEN);
		sg_set_buf(sg + 1, data, data_len - CMAC_TLEN);
		sg_set_buf(sg + 2, zero, CMAC_TLEN);
	}

	ahash_request_set_tfm(ahreq, tfma);
	ahash_request_set_crypt(ahreq, sg, mic, AAD_LEN + data_len);
	crypto_ahash_digest(ahreq);
	ahash_request_zero(ahreq);
#else
	SHASH_DESC_ON_STACK(desc, tfm);
	const __le16 *fc;

	desc->tfm = tfm;

	crypto_shash_init(desc);
	crypto_shash_update(desc, aad, AAD_LEN);
	fc = (const __le16 *)aad;
	if (ieee80211_is_beacon(*fc)) {
		/* mask Timestamp field to zero */
		crypto_shash_update(desc, zero, 8);
		crypto_shash_update(desc, data + 8, data_len - 8 - CMAC_TLEN);
	} else {
		crypto_shash_update(desc, data, data_len - CMAC_TLEN);
	}
	crypto_shash_finup(desc, zero, CMAC_TLEN, mic);
	shash_desc_zero(desc);
#endif
}

void ieee80211_aes_cmac_256(struct crypto_shash *tfm, const u8 *aad,
			    const u8 *data, size_t data_len, u8 *mic)
{
#ifdef CONFIG_LRDMWL_FIPS
	struct crypto_ahash *tfma = (struct crypto_ahash *)tfm;
	struct scatterlist sg[4];
	AHASH_REQUEST_ON_STACK(ahreq, tfma);

	if (ieee80211_is_beacon(*fc)) {
		sg_init_table(sg, 4);
		sg_set_buf(sg, aad, AAD_LEN);
		sg_set_buf(sg + 1, zero, 8);
		sg_set_buf(sg + 2, data + 8, data_len - 8 - CMAC_TLEN_256);
		sg_set_buf(sg + 3, zero, CMAC_TLEN_256);
	} else {
		sg_init_table(sg, 3);
		sg_set_buf(sg, aad, AAD_LEN);
		sg_set_buf(sg + 1, data, data_len - CMAC_TLEN_256);
		sg_set_buf(sg + 2, zero, CMAC_TLEN_256);
	}

	ahash_request_set_tfm(ahreq, tfma);
	ahash_request_set_crypt(ahreq, sg, mic, AAD_LEN + data_len);
	crypto_ahash_digest(ahreq);
	ahash_request_zero(ahreq);
#else
	SHASH_DESC_ON_STACK(desc, tfm);
	const __le16 *fc;

	desc->tfm = tfm;

	crypto_shash_init(desc);
	crypto_shash_update(desc, aad, AAD_LEN);
	fc = (const __le16 *)aad;
	if (ieee80211_is_beacon(*fc)) {
		/* mask Timestamp field to zero */
		crypto_shash_update(desc, zero, 8);
		crypto_shash_update(desc, data + 8,
				    data_len - 8 - CMAC_TLEN_256);
	} else {
		crypto_shash_update(desc, data, data_len - CMAC_TLEN_256);
	}
	crypto_shash_finup(desc, zero, CMAC_TLEN_256, mic);
	shash_desc_zero(desc);
#endif
}

struct crypto_shash *ieee80211_aes_cmac_key_setup(const u8 key[],
						  size_t key_len)
{
#ifdef CONFIG_LRDMWL_FIPS
	struct crypto_ahash *tfma;

	tfma = crypto_alloc_ahash("cmac(aes)", 0, CRYPTO_ALG_ASYNC);
	if (!IS_ERR(tfma))
		crypto_ahash_setkey(tfma, key, key_len);

	return (struct crypto_shash *)tfma;
#else
	struct crypto_shash *tfm;

	tfm = crypto_alloc_shash("cmac(aes)", 0, 0);
	if (!IS_ERR(tfm))
		crypto_shash_setkey(tfm, key, key_len);

	return tfm;
#endif
}

void ieee80211_aes_cmac_key_free(struct crypto_shash *tfm)
{
#ifdef CONFIG_LRDMWL_FIPS
	crypto_free_ahash((struct crypto_ahash *)tfm);
#else
	crypto_free_shash(tfm);
#endif
}
