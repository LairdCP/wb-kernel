// SPDX-License-Identifier: GPL-2.0
/*
 * Cryptographic API.
 *
 * Support for ATMEL AES HW acceleration.
 *
 * Copyright (c) 2012 Eukréa Electromatique - ATMEL
 * Author: Nicolas Royer <nicolas@eukrea.com>
 *
 * Some ideas are from omap-aes.c driver.
 */


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/clk.h>

#include <linux/device.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/dmaengine.h>
#include <linux/of_device.h>
#include <linux/delay.h>
#include <linux/fips.h>
#include <linux/crypto.h>
#include <crypto/scatterwalk.h>
#include <crypto/aes.h>
#include <crypto/gcm.h>
#include <crypto/xts.h>
#include <crypto/internal/aead.h>
#include <crypto/hash.h>
#include <crypto/internal/hash.h>
#include <linux/platform_data/crypto-atmel.h>
#include <dt-bindings/dma/at91.h>

#include "atmel-aes-regs.h"
#include "atmel-authenc.h"

#define ATMEL_AES_PRIORITY	300

#define ATMEL_AES_BUFFER_ORDER	2
#define ATMEL_AES_BUFFER_SIZE	(PAGE_SIZE << ATMEL_AES_BUFFER_ORDER)

#define CFB8_BLOCK_SIZE		1
#define CFB16_BLOCK_SIZE	2
#define CFB32_BLOCK_SIZE	4
#define CFB64_BLOCK_SIZE	8

#define SIZE_IN_WORDS(x)	((x) >> 2)

/* AES flags */
/* Reserve bits [18:16] [14:12] [1:0] for mode (same as for AES_MR) */
#define AES_FLAGS_ENCRYPT	AES_MR_CYPHER_ENC
#define AES_FLAGS_GTAGEN	AES_MR_GTAGEN
#define AES_FLAGS_OPMODE_MASK	(AES_MR_OPMOD_MASK | AES_MR_CFBS_MASK |\
				AES_MR_LOD)
#define AES_FLAGS_ECB		AES_MR_OPMOD_ECB
#define AES_FLAGS_CBC		AES_MR_OPMOD_CBC
#define AES_FLAGS_OFB		AES_MR_OPMOD_OFB
#define AES_FLAGS_CFB128	(AES_MR_OPMOD_CFB | AES_MR_CFBS_128b)
#define AES_FLAGS_CFB64		(AES_MR_OPMOD_CFB | AES_MR_CFBS_64b)
#define AES_FLAGS_CFB32		(AES_MR_OPMOD_CFB | AES_MR_CFBS_32b)
#define AES_FLAGS_CFB16		(AES_MR_OPMOD_CFB | AES_MR_CFBS_16b)
#define AES_FLAGS_CFB8		(AES_MR_OPMOD_CFB | AES_MR_CFBS_8b)
#define AES_FLAGS_CTR		AES_MR_OPMOD_CTR
#define AES_FLAGS_GCM		AES_MR_OPMOD_GCM
#define AES_FLAGS_XTS		AES_MR_OPMOD_XTS
#define AES_FLAGS_CBCMAC	(AES_MR_OPMOD_CBC | AES_MR_LOD)

#define AES_FLAGS_MODE_MASK	(AES_FLAGS_OPMODE_MASK |	\
				 AES_FLAGS_ENCRYPT |		\
				 AES_FLAGS_GTAGEN)

#define AES_FLAGS_BUSY		BIT(3)
#define AES_FLAGS_DUMP_REG	BIT(4)
#define AES_FLAGS_OWN_SHA	BIT(5)

#define AES_FLAGS_PERSISTENT	AES_FLAGS_BUSY

#define ATMEL_AES_QUEUE_LENGTH	50

#define ATMEL_AES_DMA_THRESHOLD 256
#define ATMEL_AES_SYNC_THRESHOLD 64

#define ATMEL_CRYPTO_ALG_FLAGS_SYNC (CRYPTO_ALG_KERN_DRIVER_ONLY)

#define ATMEL_CRYPTO_ALG_FLAGS_ASYNC (CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY)

struct atmel_aes_caps {
	bool			has_dualbuff;
	bool			has_cfb64;
	bool			has_ctr32;
	bool			has_gcm;
	bool			has_xts;
	bool			has_authenc;
	u32			max_burst_size;
};

struct atmel_aes_dev;


typedef int (*atmel_aes_fn_t)(struct atmel_aes_dev *);


struct atmel_aes_base_ctx {
	atmel_aes_fn_t		start;
	int			keylen;
	u32			key[AES_KEYSIZE_256 / sizeof(u32)];
	u16			block_size;
	bool			is_aead;
};

struct atmel_aes_ctx {
	struct atmel_aes_base_ctx	base;
};

struct atmel_aes_xts_ctx {
	struct atmel_aes_base_ctx	base;

	u32			key2[AES_KEYSIZE_256 / sizeof(u32)];
};

struct atmel_aes_cmac_ctx {
	struct atmel_aes_base_ctx	base;

	u32			k1[AES_BLOCK_SIZE / sizeof(u32)];
	u32			k2[AES_BLOCK_SIZE / sizeof(u32)];
	u32			bl[AES_BLOCK_SIZE / sizeof(u32)];
	bool			has_key;
};

#ifdef CONFIG_CRYPTO_DEV_ATMEL_AUTHENC
struct atmel_aes_authenc_ctx {
	struct atmel_aes_base_ctx	base;
	struct atmel_sha_authenc_ctx	*auth;
};
#endif

struct atmel_aes_reqctx {
	unsigned long		mode;
	u32			lastc[AES_BLOCK_SIZE / sizeof(u32)];
};

struct atmel_aes_ctr_reqctx {
	struct atmel_aes_reqctx	base;

	u32			iv[AES_BLOCK_SIZE / sizeof(u32)];
	size_t			offset;
	size_t			cryptlen;
	struct scatterlist	*rsrc;
	struct scatterlist	*rdst;
	struct scatterlist	src[2];
	struct scatterlist	dst[2];
};

struct atmel_aes_gcm_reqctx {
	struct atmel_aes_reqctx	base;

	struct scatterlist	src[2];
	struct scatterlist	dst[2];

	u32			j0[AES_BLOCK_SIZE / sizeof(u32)];
	u32			tag[AES_BLOCK_SIZE / sizeof(u32)];
	u32			ghash[AES_BLOCK_SIZE / sizeof(u32)];
	size_t			textlen;

	const u32		*ghash_in;
	u32			*ghash_out;
	atmel_aes_fn_t		ghash_resume;
};

struct atmel_aes_mac_reqctx {
	struct atmel_aes_reqctx	base;
	struct scatterlist	sg[2];
	size_t			residue_len;
	u32			residue[AES_BLOCK_SIZE / sizeof(u32)];
	bool			is_final;
	bool			is_finup;
};

struct atmel_aes_ccm_reqctx {
	struct atmel_aes_ctr_reqctx ctr;

	u32 odata[AES_BLOCK_SIZE / sizeof(u32)];
	u32 idata[AES_BLOCK_SIZE / sizeof(u32)];
	u32 auth_tag[16 / sizeof(u32)];
	u32 flags;
	struct scatterlist src[3];
	struct scatterlist dst[3];
	struct scatterlist sg[3];
	size_t sglen;
};

#ifdef CONFIG_CRYPTO_DEV_ATMEL_AUTHENC
struct atmel_aes_authenc_reqctx {
	struct atmel_aes_reqctx	base;

	struct scatterlist	src[2];
	struct scatterlist	dst[2];
	size_t			textlen;
	u32			digest[SHA512_DIGEST_SIZE / sizeof(u32)];

	/* auth_req MUST be place last. */
	struct ahash_request	auth_req;
};
#endif

struct atmel_aes_dma {
	struct dma_chan		*chan;
	struct scatterlist	*sg;
	int			nents;
	unsigned int		remainder;
	unsigned int		sg_len;
	dma_cookie_t		cookie;
};

struct atmel_aes_dev {
	unsigned long		phys_base;
	void __iomem		*io_base;

	struct crypto_async_request	*areq;
	struct atmel_aes_base_ctx	*ctx;

	bool			is_async;
	bool			force_sync;
	atmel_aes_fn_t		resume;
	atmel_aes_fn_t		cpu_transfer_complete;

	struct device		*dev;
	struct clk		*iclk;
	int			irq;

	unsigned long		flags;

	struct tasklet_struct	done_task;

	size_t			total;
	size_t			datalen;
	u32			*data;

	struct atmel_aes_dma	src;
	struct atmel_aes_dma	dst;

	size_t			buflen;
	void			*buf;
	struct scatterlist	aligned_sg;
	struct scatterlist	*real_dst;

	struct atmel_aes_caps	caps;

	u32			hw_version;
};

struct atmel_aes_drv {
	struct crypto_queue	queue;
	struct atmel_aes_dev	*dd;
	spinlock_t		lock;
	bool			sync_mode;
};

static struct atmel_aes_drv atmel_aes = {
	.lock = __SPIN_LOCK_UNLOCKED(atmel_aes.lock),
};

static int atmel_aes_handle_queue(struct crypto_async_request *new_areq);

#ifdef VERBOSE_DEBUG
static const char *atmel_aes_reg_name(u32 offset, char *tmp, size_t sz)
{
	switch (offset) {
	case AES_CR:
		return "CR";

	case AES_MR:
		return "MR";

	case AES_ISR:
		return "ISR";

	case AES_IMR:
		return "IMR";

	case AES_IER:
		return "IER";

	case AES_IDR:
		return "IDR";

	case AES_KEYWR(0):
	case AES_KEYWR(1):
	case AES_KEYWR(2):
	case AES_KEYWR(3):
	case AES_KEYWR(4):
	case AES_KEYWR(5):
	case AES_KEYWR(6):
	case AES_KEYWR(7):
		snprintf(tmp, sz, "KEYWR[%u]", (offset - AES_KEYWR(0)) >> 2);
		break;

	case AES_IDATAR(0):
	case AES_IDATAR(1):
	case AES_IDATAR(2):
	case AES_IDATAR(3):
		snprintf(tmp, sz, "IDATAR[%u]", (offset - AES_IDATAR(0)) >> 2);
		break;

	case AES_ODATAR(0):
	case AES_ODATAR(1):
	case AES_ODATAR(2):
	case AES_ODATAR(3):
		snprintf(tmp, sz, "ODATAR[%u]", (offset - AES_ODATAR(0)) >> 2);
		break;

	case AES_IVR(0):
	case AES_IVR(1):
	case AES_IVR(2):
	case AES_IVR(3):
		snprintf(tmp, sz, "IVR[%u]", (offset - AES_IVR(0)) >> 2);
		break;

	case AES_AADLENR:
		return "AADLENR";

	case AES_CLENR:
		return "CLENR";

	case AES_GHASHR(0):
	case AES_GHASHR(1):
	case AES_GHASHR(2):
	case AES_GHASHR(3):
		snprintf(tmp, sz, "GHASHR[%u]", (offset - AES_GHASHR(0)) >> 2);
		break;

	case AES_TAGR(0):
	case AES_TAGR(1):
	case AES_TAGR(2):
	case AES_TAGR(3):
		snprintf(tmp, sz, "TAGR[%u]", (offset - AES_TAGR(0)) >> 2);
		break;

	case AES_CTRR:
		return "CTRR";

	case AES_GCMHR(0):
	case AES_GCMHR(1):
	case AES_GCMHR(2):
	case AES_GCMHR(3):
		snprintf(tmp, sz, "GCMHR[%u]", (offset - AES_GCMHR(0)) >> 2);
		break;

	case AES_EMR:
		return "EMR";

	case AES_TWR(0):
	case AES_TWR(1):
	case AES_TWR(2):
	case AES_TWR(3):
		snprintf(tmp, sz, "TWR[%u]", (offset - AES_TWR(0)) >> 2);
		break;

	case AES_ALPHAR(0):
	case AES_ALPHAR(1):
	case AES_ALPHAR(2):
	case AES_ALPHAR(3):
		snprintf(tmp, sz, "ALPHAR[%u]", (offset - AES_ALPHAR(0)) >> 2);
		break;

	default:
		snprintf(tmp, sz, "0x%02x", offset);
		break;
	}

	return tmp;
}
#endif /* VERBOSE_DEBUG */

/* Shared functions */

static inline u32 atmel_aes_read(struct atmel_aes_dev *dd, u32 offset)
{
	u32 value = readl_relaxed(dd->io_base + offset);

#ifdef VERBOSE_DEBUG
	if (dd->flags & AES_FLAGS_DUMP_REG) {
		char tmp[16];

		dev_vdbg(dd->dev, "read 0x%08x from %s\n", value,
			 atmel_aes_reg_name(offset, tmp, sizeof(tmp)));
	}
#endif /* VERBOSE_DEBUG */

	return value;
}

static inline void atmel_aes_write(struct atmel_aes_dev *dd,
					u32 offset, u32 value)
{
#ifdef VERBOSE_DEBUG
	if (dd->flags & AES_FLAGS_DUMP_REG) {
		char tmp[16];

		dev_vdbg(dd->dev, "write 0x%08x into %s\n", value,
			 atmel_aes_reg_name(offset, tmp, sizeof(tmp)));
	}
#endif /* VERBOSE_DEBUG */

	writel_relaxed(value, dd->io_base + offset);
}

static void atmel_aes_read_n(struct atmel_aes_dev *dd, u32 offset,
					u32 *value, int count)
{
	for (; count--; value++, offset += 4)
		*value = atmel_aes_read(dd, offset);
}

static void atmel_aes_write_n(struct atmel_aes_dev *dd, u32 offset,
			      const u32 *value, int count)
{
	for (; count--; value++, offset += 4)
		atmel_aes_write(dd, offset, *value);
}

static inline void atmel_aes_read_block(struct atmel_aes_dev *dd, u32 offset,
					u32 *value)
{
	atmel_aes_read_n(dd, offset, value, SIZE_IN_WORDS(AES_BLOCK_SIZE));
}

static inline void atmel_aes_write_block(struct atmel_aes_dev *dd, u32 offset,
					 const u32 *value)
{
	atmel_aes_write_n(dd, offset, value, SIZE_IN_WORDS(AES_BLOCK_SIZE));
}

static int atmel_aes_wait_for_data_ready_nr(struct atmel_aes_dev *dd,
					    atmel_aes_fn_t resume)
{
	if (dd->force_sync) {
		while (!(atmel_aes_read(dd, AES_ISR) & AES_INT_DATARDY)) {}
		return 0;
	} else {
		u32 isr = atmel_aes_read(dd, AES_ISR);
		if (isr & AES_INT_DATARDY)
			return 0;

		dd->resume = resume;
		atmel_aes_write(dd, AES_IER, AES_INT_DATARDY);
		return -EINPROGRESS;
	}
}

static inline int atmel_aes_wait_for_data_ready(struct atmel_aes_dev *dd,
						atmel_aes_fn_t resume)
{
	int ret = atmel_aes_wait_for_data_ready_nr(dd, resume);
	return ret ? ret : resume(dd);
}

static int atmel_aes_wait_for_tag_ready_nr(struct atmel_aes_dev *dd,
					   atmel_aes_fn_t resume)
{
	if (dd->force_sync) {
		while (!(atmel_aes_read(dd, AES_ISR) & AES_INT_TAGRDY)) {}
		return 0;
	} else {
		u32 isr = atmel_aes_read(dd, AES_ISR);
		if (isr & AES_INT_TAGRDY)
			return 0;

		dd->resume = resume;
		atmel_aes_write(dd, AES_IER, AES_INT_TAGRDY);
		return -EINPROGRESS;
	}
}

static inline size_t atmel_aes_padlen(size_t len, size_t block_size)
{
	len &= block_size - 1;
	return len ? block_size - len : 0;
}

static void atmel_aes_hw_init(struct atmel_aes_dev *dd)
{
	atmel_aes_write(dd, AES_CR, AES_CR_SWRST);
	atmel_aes_write(dd, AES_MR, 0xE << AES_MR_CKEY_OFFSET);
}

static inline unsigned int atmel_aes_get_version(struct atmel_aes_dev *dd)
{
	return atmel_aes_read(dd, AES_HW_VERSION) & 0x00000fff;
}

static int atmel_aes_hw_version_init(struct atmel_aes_dev *dd)
{
	atmel_aes_hw_init(dd);

	dd->hw_version = atmel_aes_get_version(dd);

	dev_info(dd->dev, "version: 0x%x\n", dd->hw_version);

	return 0;
}

static inline void atmel_aes_set_mode(struct atmel_aes_dev *dd,
				      const struct atmel_aes_reqctx *rctx)
{
	/* Clear all but persistent flags and set request flags. */
	dd->flags = (dd->flags & AES_FLAGS_PERSISTENT) | rctx->mode;
}

static inline bool atmel_aes_is_encrypt(const struct atmel_aes_dev *dd)
{
	return (dd->flags & AES_FLAGS_ENCRYPT);
}

#ifdef CONFIG_CRYPTO_DEV_ATMEL_AUTHENC
static void atmel_aes_authenc_complete(struct atmel_aes_dev *dd, int err);
#endif

static int atmel_aes_complete(struct atmel_aes_dev *dd, int err)
{
#ifdef CONFIG_CRYPTO_DEV_ATMEL_AUTHENC
	if (dd->ctx->is_aead)
		atmel_aes_authenc_complete(dd, err);
#endif
	atmel_aes_write(dd, AES_CR, AES_CR_SWRST);

	if (dd->is_async)
		dd->areq->complete(dd->areq, err);

	atmel_aes_handle_queue(NULL);

	return err;
}

static void atmel_aes_write_ctrl_key(struct atmel_aes_dev *dd, bool use_dma,
				     const u32 *iv, const u32 *key, int keylen)
{
	u32 valmr = 0;

	/* MR register must be set before IV registers */
	if (keylen == AES_KEYSIZE_128)
		valmr |= AES_MR_KEYSIZE_128;
	else if (keylen == AES_KEYSIZE_192)
		valmr |= AES_MR_KEYSIZE_192;
	else
		valmr |= AES_MR_KEYSIZE_256;

	valmr |= dd->flags & AES_FLAGS_MODE_MASK;

	if (use_dma) {
		valmr |= AES_MR_SMOD_IDATAR0;
		if (dd->caps.has_dualbuff)
			valmr |= AES_MR_DUALBUFF;
	} else {
		valmr |= AES_MR_SMOD_AUTO;
	}

	atmel_aes_write(dd, AES_MR, valmr);

	atmel_aes_write_n(dd, AES_KEYWR(0), key, SIZE_IN_WORDS(keylen));

	if (iv && (valmr & AES_MR_OPMOD_MASK) != AES_MR_OPMOD_ECB) {
		/* Perform 4 byte alignment for iv if needed */
		if ((unsigned long)iv & 3) {
			u32 ivbuf[AES_BLOCK_SIZE / sizeof(u32)];
			memcpy(ivbuf, iv, AES_BLOCK_SIZE);

			atmel_aes_write_block(dd, AES_IVR(0), ivbuf);
		} else
			atmel_aes_write_block(dd, AES_IVR(0), iv);
	}
}

static inline void atmel_aes_write_ctrl(struct atmel_aes_dev *dd, bool use_dma,
					void *iv)
{
	atmel_aes_write_ctrl_key(dd, use_dma, iv,
				 dd->ctx->key, dd->ctx->keylen);
}

/* CPU transfer */

static int atmel_aes_cpu_transfer(struct atmel_aes_dev *dd)
{
	int err;

	for (;;) {
		if (dd->real_dst != NULL)
			atmel_aes_read_block(dd, AES_ODATAR(0), dd->data);

		dd->data += 4;
		dd->datalen -= AES_BLOCK_SIZE;

		if (dd->datalen < AES_BLOCK_SIZE)
			break;

		atmel_aes_write_block(dd, AES_IDATAR(0), dd->data);

		err = atmel_aes_wait_for_data_ready_nr(dd,
			atmel_aes_cpu_transfer);
		if (err)
			return err;
	}

	if (dd->real_dst != NULL) {
		if (!sg_copy_from_buffer(dd->real_dst, sg_nents(dd->real_dst),
					 dd->buf, dd->total))
			err = -EINVAL;
	}

	if (err)
		return atmel_aes_complete(dd, err);

	return dd->cpu_transfer_complete(dd);
}

static int atmel_aes_cpu_start(struct atmel_aes_dev *dd,
			       struct scatterlist *src,
			       struct scatterlist *dst,
			       size_t len,
			       atmel_aes_fn_t resume)
{
	size_t padlen = atmel_aes_padlen(len, AES_BLOCK_SIZE);

	if (unlikely(len == 0))
		return -EINVAL;

	sg_copy_to_buffer(src, sg_nents(src), dd->buf, len);
	memset(dd->buf + len, 0, padlen);

	dd->src.sg = NULL;
	dd->total = len;
	dd->real_dst = dst;
	dd->cpu_transfer_complete = resume;
	dd->datalen = len + padlen;
	dd->data = (u32 *)dd->buf;
	atmel_aes_write_block(dd, AES_IDATAR(0), dd->data);
	return atmel_aes_wait_for_data_ready(dd, atmel_aes_cpu_transfer);
}


/* DMA transfer */

static void atmel_aes_dma_callback(void *data);
static void atmel_aes_dma_src_callback(void *data);

static bool atmel_aes_check_aligned(struct atmel_aes_dev *dd,
				    struct scatterlist *sg,
				    size_t len,
				    struct atmel_aes_dma *dma)
{
	int nents;

	if (!IS_ALIGNED(len, dd->ctx->block_size))
		return false;

	for (nents = 0; sg; sg = sg_next(sg), ++nents) {
		if (!IS_ALIGNED(sg->offset, sizeof(u32)))
			return false;

		if (len <= sg->length) {
			if (!IS_ALIGNED(len, dd->ctx->block_size))
				return false;

			dma->nents = nents+1;
			dma->remainder = sg->length - len;
			sg->length = len;
			return true;
		}

		if (!IS_ALIGNED(sg->length, dd->ctx->block_size))
			return false;

		len -= sg->length;
	}

	return false;
}

static void atmel_aes_restore_sg(const struct atmel_aes_dma *dma)
{
	struct scatterlist *sg = dma->sg;
	int nents = dma->nents;

	if (!dma->remainder)
		return;

	while (--nents > 0 && sg)
		sg = sg_next(sg);

	if (!sg)
		return;

	sg->length += dma->remainder;
}

static int atmel_aes_map(struct atmel_aes_dev *dd,
			 struct scatterlist *src,
			 struct scatterlist *dst,
			 size_t len)
{
	bool src_aligned, dst_aligned;
	size_t padlen;

	dd->total = len;
	dd->src.sg = src;
	dd->dst.sg = dst;
	dd->real_dst = dst;

	src_aligned = atmel_aes_check_aligned(dd, src, len, &dd->src);
	if (src == dst || dst == NULL)
		dst_aligned = src_aligned;
	else
		dst_aligned = atmel_aes_check_aligned(dd, dst, len, &dd->dst);

	if (!src_aligned || !dst_aligned) {
		padlen = atmel_aes_padlen(len, dd->ctx->block_size);

		if (dd->buflen < len + padlen)
			return -ENOMEM;

		if (!src_aligned) {
			sg_copy_to_buffer(src, sg_nents(src), dd->buf, len);

			dd->src.sg = &dd->aligned_sg;
			dd->src.nents = 1;
			dd->src.remainder = 0;

			memset(dd->buf + len, 0, padlen);
		}

		if (!dst_aligned && dst != NULL) {
			dd->dst.sg = &dd->aligned_sg;
			dd->dst.nents = 1;
			dd->dst.remainder = 0;
		}

		sg_init_table(&dd->aligned_sg, 1);
		sg_set_buf(&dd->aligned_sg, dd->buf, len + padlen);
	}

	if (dd->src.sg == dd->dst.sg) {
		dd->src.sg_len = dma_map_sg(dd->dev, dd->src.sg, dd->src.nents,
					    DMA_BIDIRECTIONAL);
		dd->dst.sg_len = dd->src.sg_len;
		if (!dd->src.sg_len)
			return -EFAULT;
	} else {
		dd->src.sg_len = dma_map_sg(dd->dev, dd->src.sg, dd->src.nents,
					    DMA_TO_DEVICE);
		if (!dd->src.sg_len)
			return -EFAULT;

		if (dst != NULL) {
			dd->dst.sg_len = dma_map_sg(dd->dev, dd->dst.sg,
				dd->dst.nents, DMA_FROM_DEVICE);
			if (!dd->dst.sg_len) {
				dma_unmap_sg(dd->dev, dd->src.sg, dd->src.nents,
						 DMA_TO_DEVICE);
				return -EFAULT;
			}
		}
	}

	return 0;
}

static void atmel_aes_unmap(struct atmel_aes_dev *dd)
{
	if (!dd->src.sg)
		return;

	if (dd->src.sg == dd->dst.sg) {
		dma_unmap_sg(dd->dev, dd->src.sg, dd->src.nents,
			     DMA_BIDIRECTIONAL);

		if (dd->src.sg != &dd->aligned_sg)
			atmel_aes_restore_sg(&dd->src);
	} else {
		if (dd->dst.sg != NULL) {
			dma_unmap_sg(dd->dev, dd->dst.sg, dd->dst.nents,
					 DMA_FROM_DEVICE);

			if (dd->dst.sg != &dd->aligned_sg)
				atmel_aes_restore_sg(&dd->dst);
		}

		dma_unmap_sg(dd->dev, dd->src.sg, dd->src.nents,
			     DMA_TO_DEVICE);

		if (dd->src.sg != &dd->aligned_sg)
			atmel_aes_restore_sg(&dd->src);
	}

	if (dd->dst.sg == &dd->aligned_sg && dd->dst.sg != NULL)
		sg_copy_from_buffer(dd->real_dst, sg_nents(dd->real_dst),
				    dd->buf, dd->total);
}

static int atmel_aes_dma_transfer_start(struct atmel_aes_dev *dd,
					enum dma_slave_buswidth addr_width,
					enum dma_transfer_direction dir,
					u32 maxburst)
{
	struct dma_async_tx_descriptor *desc;
	struct dma_slave_config config;
	dma_async_tx_callback callback;
	struct atmel_aes_dma *dma;
	int err;

	memset(&config, 0, sizeof(config));
	config.direction = dir;
	config.src_addr_width = addr_width;
	config.dst_addr_width = addr_width;
	config.src_maxburst = maxburst;
	config.dst_maxburst = maxburst;

	switch (dir) {
	case DMA_MEM_TO_DEV:
		dma = &dd->src;
		callback = dd->dst.sg ? NULL : atmel_aes_dma_src_callback;
		config.dst_addr = dd->phys_base + AES_IDATAR(0);
		break;

	case DMA_DEV_TO_MEM:
		dma = &dd->dst;
		callback = atmel_aes_dma_callback;
		config.src_addr = dd->phys_base + AES_ODATAR(0);
		break;

	default:
		return -EINVAL;
	}

	if (dma->sg == NULL)
		return 0;

	err = dmaengine_slave_config(dma->chan, &config);
	if (err)
		return err;

	desc = dmaengine_prep_slave_sg(dma->chan, dma->sg, dma->sg_len, dir,
				       DMA_PREP_INTERRUPT | DMA_CTRL_ACK);
	if (!desc)
		return -ENOMEM;

	if (dd->force_sync) {
		desc->callback = NULL;
		desc->callback_param = NULL;
	} else {
		desc->callback = callback;
		desc->callback_param = dd;
	}

	dma->cookie = dmaengine_submit(desc);
	if (dma->cookie < 0)
		return dma->cookie;

	dma_async_issue_pending(dma->chan);

	return 0;
}

static inline void atmel_aes_dma_stop(struct atmel_aes_dev *dd)
{
	dmaengine_terminate_async(dd->src.chan);
	dmaengine_terminate_async(dd->dst.chan);
	atmel_aes_unmap(dd);
}

static void wait_dma_complete(struct atmel_aes_dma * dma)
{
	while (dmaengine_tx_status(dma->chan, dma->cookie, NULL) !=
		DMA_COMPLETE)
		cpu_relax();
}

static int atmel_aes_dma_start(struct atmel_aes_dev *dd,
			       struct scatterlist *src,
			       struct scatterlist *dst,
			       size_t len,
			       atmel_aes_fn_t resume)
{
	enum dma_slave_buswidth addr_width;
	u32 maxburst;
	int err;

	switch (dd->ctx->block_size) {
	case AES_BLOCK_SIZE:
		addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
		maxburst = dd->caps.max_burst_size;
		break;

	case CFB8_BLOCK_SIZE:
		addr_width = DMA_SLAVE_BUSWIDTH_1_BYTE;
		maxburst = 1;
		break;

	case CFB16_BLOCK_SIZE:
		addr_width = DMA_SLAVE_BUSWIDTH_2_BYTES;
		maxburst = 1;
		break;

	case CFB32_BLOCK_SIZE:
	case CFB64_BLOCK_SIZE:
		addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
		maxburst = 1;
		break;

	default:
		err = -EINVAL;
		goto exit;
	}

	err = atmel_aes_map(dd, src, dst, len);
	if (err)
		goto exit;

	dd->resume = resume;

	/* Set output DMA transfer first */
	err = atmel_aes_dma_transfer_start(dd, addr_width, DMA_DEV_TO_MEM,
					   maxburst);
	if (err)
		goto unmap;

	/* Then set input DMA transfer */
	err = atmel_aes_dma_transfer_start(dd, addr_width, DMA_MEM_TO_DEV,
					   maxburst);
	if (err)
		goto unmap;

	if (!dd->force_sync)
		return -EINPROGRESS;

	wait_dma_complete(&dd->src);

	if (dd->dst.sg == NULL)
		atmel_aes_wait_for_data_ready_nr(dd, NULL);
	 else
		wait_dma_complete(&dd->dst);

	atmel_aes_unmap(dd);

	return dd->resume(dd);

unmap:
	atmel_aes_dma_stop(dd);
exit:
	return atmel_aes_complete(dd, err);
}

static void atmel_aes_dma_callback(void *data)
{
	struct atmel_aes_dev *dd = data;

	tasklet_schedule(&dd->done_task);
}

static void atmel_aes_dma_src_callback(void *data)
{
	struct atmel_aes_dev *dd = data;

	atmel_aes_write(dd, AES_IER, AES_INT_DATARDY);
}

static int atmel_aes_handle_queue_sync(struct crypto_async_request *new_areq)
{
	struct atmel_aes_base_ctx *ctx;
	struct atmel_aes_dev *dd;
	int ret;

	if (!new_areq)
		return 0;

	ctx = crypto_tfm_ctx(new_areq->tfm);

	/* Synchronous mode we protect the whole transaction with spinlock */
	spin_lock_bh(&atmel_aes.lock);

	dd = atmel_aes.dd;

	if (dd) {
		dd->flags |= AES_FLAGS_BUSY;

		dd->areq = new_areq;
		dd->ctx = ctx;

		dd->is_async = false;
		dd->force_sync = true;

		ret = ctx->start(dd);

		dd->flags &= ~AES_FLAGS_BUSY;
	} else
		ret = -ENODEV;

	spin_unlock_bh(&atmel_aes.lock);

	return ret;
}

static int atmel_aes_handle_queue_async(struct crypto_async_request *new_areq)
{
	struct crypto_async_request *areq = NULL, *backlog = NULL;
	struct atmel_aes_base_ctx *ctx;
	struct atmel_aes_dev *dd;
	int ret = 0;

	spin_lock_bh(&atmel_aes.lock);

	dd = atmel_aes.dd;
	if (!dd)
		ret = -ENODEV;

	/* Add new request to queue if we are busy, assumption here that device
	 * will always stay busy while queue is not empty */
	else if (new_areq) {
		if (dd->flags & AES_FLAGS_BUSY) {
			ret = crypto_enqueue_request(&atmel_aes.queue, new_areq);
		} else {
			dd->flags |= AES_FLAGS_BUSY;
			areq = new_areq;
		}
	} else {
		backlog = crypto_get_backlog(&atmel_aes.queue);
		areq = crypto_dequeue_request(&atmel_aes.queue);

		if (!areq)
			dd->flags &= ~AES_FLAGS_BUSY;
	}

	spin_unlock_bh(&atmel_aes.lock);

	if (areq) {
		if (backlog)
			backlog->complete(backlog, -EINPROGRESS);

		ctx = crypto_tfm_ctx(areq->tfm);

		dd->areq = areq;
		dd->ctx = ctx;

		/* These flags could change later as crypto progresses */
		dd->is_async = false;
		dd->force_sync = false;

		ret = ctx->start(dd);
	}

	return ret;
}

static inline int atmel_aes_handle_queue(struct crypto_async_request *new_areq)
{
	return atmel_aes.sync_mode ?
		atmel_aes_handle_queue_sync(new_areq) :
		atmel_aes_handle_queue_async(new_areq);
}

/* AES async block ciphers */

static int atmel_aes_bc_transfer_complete(struct atmel_aes_dev *dd)
{
	struct skcipher_request *req = skcipher_request_cast(dd->areq);
	struct atmel_aes_reqctx *rctx = skcipher_request_ctx(req);

	if (rctx->mode & AES_FLAGS_ENCRYPT) {
		unsigned lbtail = req->cryptlen & (AES_BLOCK_SIZE - 1);
		unsigned lboff = req->cryptlen - lbtail;

		if (!lbtail)
			scatterwalk_map_and_copy(req->iv, req->dst,
				lboff - AES_BLOCK_SIZE, AES_BLOCK_SIZE, 0);
		else
			memcpy(req->iv, dd->buf + lboff, AES_BLOCK_SIZE);
	} else if (req->src == req->dst)
		memcpy(req->iv, rctx->lastc, AES_BLOCK_SIZE);
	else {
		unsigned lbtail = req->cryptlen & (AES_BLOCK_SIZE - 1);

		if (lbtail)
			memset(req->iv + lbtail, 0, AES_BLOCK_SIZE - lbtail);
		else
			lbtail = AES_BLOCK_SIZE;

		scatterwalk_map_and_copy(req->iv, req->src,
			req->cryptlen - lbtail, lbtail, 0);
	}

	return atmel_aes_complete(dd, 0);
}

static int atmel_aes_transfer_complete(struct atmel_aes_dev *dd)
{
	return atmel_aes_complete(dd, 0);
}

static int atmel_aes_bc_start(struct atmel_aes_dev *dd)
{
	struct skcipher_request *req = skcipher_request_cast(dd->areq);
	struct atmel_aes_reqctx *rctx = skcipher_request_ctx(req);

	bool use_dma = (req->cryptlen >= ATMEL_AES_DMA_THRESHOLD ||
			dd->ctx->block_size != AES_BLOCK_SIZE);

	dd->force_sync = atmel_aes.sync_mode ||
		(req->cryptlen <= ATMEL_AES_SYNC_THRESHOLD);

	atmel_aes_set_mode(dd, rctx);

	atmel_aes_hw_init(dd);

	atmel_aes_write_ctrl(dd, use_dma, req->iv);

	if (use_dma)
		return atmel_aes_dma_start(dd, req->src, req->dst,
			req->cryptlen, atmel_aes_bc_transfer_complete);
	else
		return atmel_aes_cpu_start(dd, req->src, req->dst,
			req->cryptlen, atmel_aes_bc_transfer_complete);
}

static int atmel_aes_start(struct atmel_aes_dev *dd)
{
	struct skcipher_request *req = skcipher_request_cast(dd->areq);
	struct atmel_aes_reqctx *rctx = skcipher_request_ctx(req);

	bool use_dma = (req->cryptlen >= ATMEL_AES_DMA_THRESHOLD);

	dd->force_sync = atmel_aes.sync_mode ||
		(req->cryptlen <= ATMEL_AES_SYNC_THRESHOLD);

	atmel_aes_set_mode(dd, rctx);

	atmel_aes_hw_init(dd);

	atmel_aes_write_ctrl(dd, use_dma, req->iv);

	if (use_dma)
		return atmel_aes_dma_start(dd, req->src, req->dst,
			req->cryptlen, atmel_aes_transfer_complete);
	else
		return atmel_aes_cpu_start(dd, req->src, req->dst,
			req->cryptlen, atmel_aes_transfer_complete);
}

static int atmel_aes_ccm_ctr_transfer_complete(struct atmel_aes_dev *dd);

static int atmel_aes_ctr_transfer(struct atmel_aes_dev *dd)
{
	struct atmel_aes_ctr_reqctx *rctx;
	struct scatterlist *src, *dst;
	u8* iv;
	size_t datalen;
	u32 ctr, blocks;
	bool use_dma, fragmented = false;

	if (dd->ctx->is_aead) {
		struct aead_request *req = aead_request_cast(dd->areq);
		rctx = aead_request_ctx(req);
		iv = req->iv;
	} else {
		struct skcipher_request *req = skcipher_request_cast(dd->areq);
		rctx = skcipher_request_ctx(req);
		iv = req->iv;
	}

	datalen = rctx->cryptlen;

	/* Check for transfer completion. */
	rctx->offset += dd->total;
	if (rctx->offset >= datalen) {
		if (dd->ctx->is_aead)
			return atmel_aes_ccm_ctr_transfer_complete(dd);
		else {
			memcpy(iv, rctx->iv, AES_BLOCK_SIZE);
			return atmel_aes_complete(dd, 0);
		}
	}

	/* Compute data length. */
	datalen -= rctx->offset;
	blocks = DIV_ROUND_UP(datalen, AES_BLOCK_SIZE);
	ctr = be32_to_cpu(rctx->iv[3]);
	if (dd->caps.has_ctr32) {
		/* Check 32bit counter overflow. */
		u32 start = ctr;
		u32 end = start + blocks - 1;

		if (end < start) {
			ctr = 0xffffffff;
			datalen = AES_BLOCK_SIZE * -start;
			fragmented = true;
		}
	} else {
		/* Check 16bit counter overflow. */
		u16 start = ctr & 0xffff;
		u16 end = start + (u16)blocks - 1;

		if (blocks >> 16 || end < start) {
			ctr |= 0xffff;
			datalen = AES_BLOCK_SIZE * (0x10000 - start);
			fragmented = !(ctr + 1);
		}
	}

	use_dma = (datalen >= ATMEL_AES_DMA_THRESHOLD);

	dd->force_sync = atmel_aes.sync_mode ||
		(datalen <= ATMEL_AES_SYNC_THRESHOLD);

	/* Jump to offset. */
	src = scatterwalk_ffwd(rctx->src, rctx->rsrc, rctx->offset);
	dst = ((rctx->rsrc == rctx->rdst) ? src :
	       scatterwalk_ffwd(rctx->dst, rctx->rdst, rctx->offset));

	/* Configure hardware. */
	atmel_aes_write_ctrl(dd, use_dma, rctx->iv);
	if (unlikely(fragmented)) {
		/*
		 * Increment the counter manually to cope with the hardware
		 * counter overflow
		 */
		rctx->iv[3] = cpu_to_be32(ctr);
		crypto_inc((u8 *)rctx->iv, AES_BLOCK_SIZE);
	} else {
		/* Update the counter for the next crypto operation */
		ctr += blocks;
		if (ctr)
			rctx->iv[3] = cpu_to_be32(ctr);
		else {
			rctx->iv[3] = cpu_to_be32(ctr - 1);
			crypto_inc((u8 *)rctx->iv, AES_BLOCK_SIZE);
		}
	}

	if (use_dma)
		return atmel_aes_dma_start(dd, src, dst, datalen,
					   atmel_aes_ctr_transfer);
	else
		return atmel_aes_cpu_start(dd, src, dst, datalen,
					   atmel_aes_ctr_transfer);
}

static int atmel_aes_ctr_start(struct atmel_aes_dev *dd)
{
	struct atmel_aes_ctr_reqctx *rctx;

	if (dd->ctx->is_aead) {
		struct aead_request *req = aead_request_cast(dd->areq);
		rctx = aead_request_ctx(req);

		memcpy(rctx->iv, req->iv, AES_BLOCK_SIZE);
	} else {
		struct skcipher_request *req = skcipher_request_cast(dd->areq);
		rctx = skcipher_request_ctx(req);

		memcpy(rctx->iv, req->iv, AES_BLOCK_SIZE);
		rctx->rsrc = req->src;
		rctx->rdst = req->dst;
		rctx->cryptlen = req->cryptlen;
	}

	atmel_aes_set_mode(dd, &rctx->base);

	atmel_aes_hw_init(dd);

	rctx->offset = 0;
	dd->total = 0;

	return atmel_aes_ctr_transfer(dd);
}

static int atmel_aes_bc_crypt(struct skcipher_request *req, unsigned long mode)
{
	struct atmel_aes_reqctx *rctx = skcipher_request_ctx(req);

	rctx->mode = mode;

	if (!(mode & AES_FLAGS_ENCRYPT) && (req->src == req->dst)) {
		unsigned lbtail = req->cryptlen & (AES_BLOCK_SIZE - 1);
		if (lbtail)
			memset(rctx->lastc + lbtail, 0, AES_BLOCK_SIZE - lbtail);
		else
			lbtail = AES_BLOCK_SIZE;

		scatterwalk_map_and_copy(rctx->lastc, req->src,
			req->cryptlen - lbtail, lbtail, 0);
	}

	return atmel_aes_handle_queue(&req->base);
}

static int atmel_aes_crypt(struct skcipher_request *req, unsigned long mode)
{
	struct atmel_aes_reqctx *rctx = skcipher_request_ctx(req);

	rctx->mode = mode;

	return atmel_aes_handle_queue(&req->base);
}

static int atmel_aes_setkey(struct crypto_skcipher *tfm, const u8 *key,
			   unsigned int keylen)
{
	struct atmel_aes_base_ctx *ctx = crypto_skcipher_ctx(tfm);

	if (keylen != AES_KEYSIZE_128 &&
	    keylen != AES_KEYSIZE_192 &&
	    keylen != AES_KEYSIZE_256) {
		crypto_skcipher_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}

	memcpy(ctx->key, key, keylen);
	ctx->keylen = keylen;

	return 0;
}

static int atmel_aes_ecb_encrypt(struct skcipher_request *req)
{
	return atmel_aes_crypt(req, AES_FLAGS_ECB | AES_FLAGS_ENCRYPT);
}

static int atmel_aes_ecb_decrypt(struct skcipher_request *req)
{
	return atmel_aes_crypt(req, AES_FLAGS_ECB);
}

static int atmel_aes_cbc_encrypt(struct skcipher_request *req)
{
	return atmel_aes_bc_crypt(req, AES_FLAGS_CBC | AES_FLAGS_ENCRYPT);
}

static int atmel_aes_cbc_decrypt(struct skcipher_request *req)
{
	return atmel_aes_bc_crypt(req, AES_FLAGS_CBC);
}

static int atmel_aes_ofb_encrypt(struct skcipher_request *req)
{
	return atmel_aes_bc_crypt(req, AES_FLAGS_OFB | AES_FLAGS_ENCRYPT);
}

static int atmel_aes_ofb_decrypt(struct skcipher_request *req)
{
	return atmel_aes_bc_crypt(req, AES_FLAGS_OFB);
}

static int atmel_aes_cfb_encrypt(struct skcipher_request *req)
{
	return atmel_aes_bc_crypt(req, AES_FLAGS_CFB128 | AES_FLAGS_ENCRYPT);
}

static int atmel_aes_cfb_decrypt(struct skcipher_request *req)
{
	return atmel_aes_bc_crypt(req, AES_FLAGS_CFB128);
}

static int atmel_aes_cfb64_encrypt(struct skcipher_request *req)
{
	return atmel_aes_bc_crypt(req, AES_FLAGS_CFB64 | AES_FLAGS_ENCRYPT);
}

static int atmel_aes_cfb64_decrypt(struct skcipher_request *req)
{
	return atmel_aes_bc_crypt(req, AES_FLAGS_CFB64);
}

static int atmel_aes_cfb32_encrypt(struct skcipher_request *req)
{
	return atmel_aes_bc_crypt(req, AES_FLAGS_CFB32 | AES_FLAGS_ENCRYPT);
}

static int atmel_aes_cfb32_decrypt(struct skcipher_request *req)
{
	return atmel_aes_bc_crypt(req, AES_FLAGS_CFB32);
}

static int atmel_aes_cfb16_encrypt(struct skcipher_request *req)
{
	return atmel_aes_bc_crypt(req, AES_FLAGS_CFB16 | AES_FLAGS_ENCRYPT);
}

static int atmel_aes_cfb16_decrypt(struct skcipher_request *req)
{
	return atmel_aes_bc_crypt(req, AES_FLAGS_CFB16);
}

static int atmel_aes_cfb8_encrypt(struct skcipher_request *req)
{
	return atmel_aes_bc_crypt(req, AES_FLAGS_CFB8 | AES_FLAGS_ENCRYPT);
}

static int atmel_aes_cfb8_decrypt(struct skcipher_request *req)
{
	return atmel_aes_bc_crypt(req, AES_FLAGS_CFB8);
}

static int atmel_aes_ctr_encrypt(struct skcipher_request *req)
{
	return atmel_aes_crypt(req, AES_FLAGS_CTR | AES_FLAGS_ENCRYPT);
}

static int atmel_aes_ctr_decrypt(struct skcipher_request *req)
{
	return atmel_aes_crypt(req, AES_FLAGS_CTR);
}

static int atmel_aes_cra_init(struct crypto_tfm *tfm)
{
	struct atmel_aes_base_ctx *ctx = crypto_tfm_ctx(tfm);

	ctx->start = atmel_aes_start;
	ctx->block_size = AES_BLOCK_SIZE;
	ctx->is_aead = false;

	crypto_skcipher_set_reqsize(__crypto_skcipher_cast(tfm),
		sizeof(struct atmel_aes_reqctx));

	return 0;
}

static int atmel_aes_bc_cra_init(struct crypto_tfm *tfm)
{
	struct atmel_aes_base_ctx *ctx = crypto_tfm_ctx(tfm);

	ctx->start = atmel_aes_bc_start;
	ctx->block_size = crypto_tfm_alg_blocksize(tfm);
	ctx->is_aead = false;

	crypto_skcipher_set_reqsize(__crypto_skcipher_cast(tfm),
		sizeof(struct atmel_aes_reqctx));

	return 0;
}

static int atmel_aes_ctr_cra_init(struct crypto_tfm *tfm)
{
	struct atmel_aes_base_ctx *ctx = crypto_tfm_ctx(tfm);

	ctx->start = atmel_aes_ctr_start;
	ctx->block_size = AES_BLOCK_SIZE;
	ctx->is_aead = false;

	crypto_skcipher_set_reqsize(__crypto_skcipher_cast(tfm),
		sizeof(struct atmel_aes_ctr_reqctx));

	return 0;
}

/* xts functions */

static inline struct atmel_aes_xts_ctx *
atmel_aes_xts_ctx_cast(struct atmel_aes_base_ctx *ctx)
{
	return container_of(ctx, struct atmel_aes_xts_ctx, base);
}

static int atmel_aes_xts_process_data(struct atmel_aes_dev *dd);

static int atmel_aes_xts_start(struct atmel_aes_dev *dd)
{
	struct atmel_aes_xts_ctx *ctx = atmel_aes_xts_ctx_cast(dd->ctx);
	struct skcipher_request *req = skcipher_request_cast(dd->areq);
	struct atmel_aes_reqctx *rctx = skcipher_request_ctx(req);
	unsigned long flags;

	atmel_aes_set_mode(dd, rctx);

	atmel_aes_hw_init(dd);

	/* Compute the tweak value from req->info with ecb(aes). */
	flags = dd->flags;
	dd->flags &= ~AES_FLAGS_MODE_MASK;
	dd->flags |= (AES_FLAGS_ECB | AES_FLAGS_ENCRYPT);
	atmel_aes_write_ctrl_key(dd, false, NULL,
				 ctx->key2, ctx->base.keylen);
	dd->flags = flags;

	atmel_aes_write_block(dd, AES_IDATAR(0), (u32*)req->iv);
	return atmel_aes_wait_for_data_ready(dd, atmel_aes_xts_process_data);
}

static int atmel_aes_xts_process_data(struct atmel_aes_dev *dd)
{
	struct skcipher_request *req = skcipher_request_cast(dd->areq);
	bool use_dma = (req->cryptlen >= ATMEL_AES_DMA_THRESHOLD);
	u32 tweak[AES_BLOCK_SIZE / sizeof(u32)];
	static const u32 one[AES_BLOCK_SIZE / sizeof(u32)] = {cpu_to_le32(1), };
	u8 *tweak_bytes = (u8 *)tweak;
	int i;

	/* Read the computed ciphered tweak value. */
	atmel_aes_read_block(dd, AES_ODATAR(0), tweak);
	/*
	 * Hardware quirk:
	 * the order of the ciphered tweak bytes need to be reversed before
	 * writing them into the ODATARx registers.
	 */
	for (i = 0; i < AES_BLOCK_SIZE/2; ++i) {
		u8 tmp = tweak_bytes[AES_BLOCK_SIZE - 1 - i];

		tweak_bytes[AES_BLOCK_SIZE - 1 - i] = tweak_bytes[i];
		tweak_bytes[i] = tmp;
	}

	/* Process the data. */
	atmel_aes_write_ctrl(dd, use_dma, NULL);
	atmel_aes_write_block(dd, AES_TWR(0), tweak);
	atmel_aes_write_block(dd, AES_ALPHAR(0), one);
	if (use_dma)
		return atmel_aes_dma_start(dd, req->src, req->dst, req->cryptlen,
					   atmel_aes_transfer_complete);

	return atmel_aes_cpu_start(dd, req->src, req->dst, req->cryptlen,
				   atmel_aes_transfer_complete);
}

static int atmel_aes_xts_setkey(struct crypto_skcipher *tfm, const u8 *key,
				unsigned int keylen)
{
	struct atmel_aes_xts_ctx *ctx = crypto_skcipher_ctx(tfm);
	int err;

	err = xts_check_key(crypto_skcipher_tfm(tfm), key, keylen);
	if (err)
		return err;

	memcpy(ctx->base.key, key, keylen/2);
	memcpy(ctx->key2, key + keylen/2, keylen/2);
	ctx->base.keylen = keylen/2;

	return 0;
}

static int atmel_aes_xts_encrypt(struct skcipher_request *req)
{
	return atmel_aes_crypt(req, AES_FLAGS_XTS | AES_FLAGS_ENCRYPT);
}

static int atmel_aes_xts_decrypt(struct skcipher_request *req)
{
	return atmel_aes_crypt(req, AES_FLAGS_XTS);
}

static int atmel_aes_xts_cra_init(struct crypto_tfm *tfm)
{
	struct atmel_aes_base_ctx *ctx = crypto_tfm_ctx(tfm);

	ctx->start = atmel_aes_xts_start;
	ctx->block_size = crypto_tfm_alg_blocksize(tfm);
	ctx->is_aead = false;

	crypto_skcipher_set_reqsize(__crypto_skcipher_cast(tfm),
		sizeof(struct atmel_aes_reqctx));

	return 0;
}

static struct skcipher_alg skcipher_aes_algs[] = {
{
	.min_keysize	= AES_MIN_KEY_SIZE,
	.max_keysize	= AES_MAX_KEY_SIZE,
	.setkey		= atmel_aes_setkey,
	.encrypt	= atmel_aes_ecb_encrypt,
	.decrypt	= atmel_aes_ecb_decrypt,
	.base = {
		.cra_name		= "ecb(aes)",
		.cra_driver_name	= "atmel-ecb-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= AES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_aes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_aes_cra_init,
	}
},
{
	.min_keysize	= AES_MIN_KEY_SIZE,
	.max_keysize	= AES_MAX_KEY_SIZE,
	.ivsize		= AES_BLOCK_SIZE,
	.setkey		= atmel_aes_setkey,
	.encrypt	= atmel_aes_cbc_encrypt,
	.decrypt	= atmel_aes_cbc_decrypt,
	.base = {
		.cra_name		= "cbc(aes)",
		.cra_driver_name	= "atmel-cbc-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= AES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_aes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_aes_bc_cra_init,
	}
},
{
	.min_keysize	= AES_MIN_KEY_SIZE,
	.max_keysize	= AES_MAX_KEY_SIZE,
	.ivsize		= AES_BLOCK_SIZE,
	.setkey		= atmel_aes_setkey,
	.encrypt	= atmel_aes_ofb_encrypt,
	.decrypt	= atmel_aes_ofb_decrypt,
	.base = {
		.cra_name		= "ofb(aes)",
		.cra_driver_name	= "atmel-ofb-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= AES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_aes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_aes_bc_cra_init,
	}
},
{
	.min_keysize	= AES_MIN_KEY_SIZE,
	.max_keysize	= AES_MAX_KEY_SIZE,
	.ivsize		= AES_BLOCK_SIZE,
	.setkey		= atmel_aes_setkey,
	.encrypt	= atmel_aes_cfb_encrypt,
	.decrypt	= atmel_aes_cfb_decrypt,
	.base = {
		.cra_name		= "cfb(aes)",
		.cra_driver_name	= "atmel-cfb-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= AES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_aes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_aes_bc_cra_init,
	}
},
{
	.min_keysize	= AES_MIN_KEY_SIZE,
	.max_keysize	= AES_MAX_KEY_SIZE,
	.ivsize		= AES_BLOCK_SIZE,
	.setkey		= atmel_aes_setkey,
	.encrypt	= atmel_aes_cfb32_encrypt,
	.decrypt	= atmel_aes_cfb32_decrypt,
	.base = {
		.cra_name		= "cfb32(aes)",
		.cra_driver_name	= "atmel-cfb32-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= CFB32_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_aes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_aes_bc_cra_init,
	}
},
{
	.min_keysize	= AES_MIN_KEY_SIZE,
	.max_keysize	= AES_MAX_KEY_SIZE,
	.ivsize		= AES_BLOCK_SIZE,
	.setkey		= atmel_aes_setkey,
	.encrypt	= atmel_aes_cfb16_encrypt,
	.decrypt	= atmel_aes_cfb16_decrypt,
	.base = {
		.cra_name		= "cfb16(aes)",
		.cra_driver_name	= "atmel-cfb16-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= CFB16_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_aes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_aes_bc_cra_init,
	}
},
{
	.min_keysize	= AES_MIN_KEY_SIZE,
	.max_keysize	= AES_MAX_KEY_SIZE,
	.ivsize		= AES_BLOCK_SIZE,
	.setkey		= atmel_aes_setkey,
	.encrypt	= atmel_aes_cfb8_encrypt,
	.decrypt	= atmel_aes_cfb8_decrypt,
	.base = {
		.cra_name		= "cfb8(aes)",
		.cra_driver_name	= "atmel-cfb8-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= CFB8_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_aes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_aes_bc_cra_init,
	}
},
{
	.min_keysize	= AES_MIN_KEY_SIZE,
	.max_keysize	= AES_MAX_KEY_SIZE,
	.ivsize		= AES_BLOCK_SIZE,
	.chunksize	= AES_BLOCK_SIZE,
	.setkey		= atmel_aes_setkey,
	.encrypt	= atmel_aes_ctr_encrypt,
	.decrypt	= atmel_aes_ctr_decrypt,
	.base = {
		.cra_name		= "ctr(aes)",
		.cra_driver_name	= "atmel-ctr-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= 1,
		.cra_ctxsize		= sizeof(struct atmel_aes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_aes_ctr_cra_init,
	}
},
{
	.min_keysize	= AES_MIN_KEY_SIZE,
	.max_keysize	= AES_MAX_KEY_SIZE,
	.ivsize		= AES_BLOCK_SIZE,
	.setkey		= atmel_aes_setkey,
	.encrypt	= atmel_aes_cfb64_encrypt,
	.decrypt	= atmel_aes_cfb64_decrypt,
	.base = {
		.cra_name		= "cfb64(aes)",
		.cra_driver_name	= "atmel-cfb64-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= CFB64_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_aes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_aes_bc_cra_init,
	}
},
{
	.min_keysize	= 2 * AES_MIN_KEY_SIZE,
	.max_keysize	= 2 * AES_MAX_KEY_SIZE,
	.ivsize		= AES_BLOCK_SIZE,
	.setkey		= atmel_aes_xts_setkey,
	.encrypt	= atmel_aes_xts_encrypt,
	.decrypt	= atmel_aes_xts_decrypt,
	.base = {
		.cra_name		= "xts(aes)",
		.cra_driver_name	= "atmel-xts-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= AES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_aes_xts_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_aes_xts_cra_init,
	}
},
};

static int atmel_aes_cbcmac_do_start(struct atmel_aes_dev *dd,
	struct scatterlist *src, u32 cryptlen, u32 *iv, atmel_aes_fn_t resume)
{
	bool use_dma = (cryptlen >= ATMEL_AES_DMA_THRESHOLD);

	dd->force_sync = atmel_aes.sync_mode ||
		(cryptlen <= ATMEL_AES_SYNC_THRESHOLD);

	dd->flags = (dd->flags & AES_FLAGS_PERSISTENT) |
		AES_FLAGS_CBCMAC | AES_FLAGS_ENCRYPT;

	atmel_aes_hw_init(dd);
	atmel_aes_write_ctrl(dd, use_dma, iv);

	return use_dma ?
		atmel_aes_dma_start(dd, src, NULL, cryptlen, resume) :
		atmel_aes_cpu_start(dd, src, NULL, cryptlen, resume);
}

static int atmel_aes_cbcmac_transfer_complete(struct atmel_aes_dev *dd)
{
	struct ahash_request *req = ahash_request_cast(dd->areq);
	struct atmel_aes_mac_reqctx *rctx = ahash_request_ctx(req);

	atmel_aes_read_block(dd, AES_ODATAR(0), rctx->base.lastc);

	if (!rctx->is_final) {
		size_t reqlen = dd->total - rctx->residue_len;
		size_t remlen = req->nbytes - reqlen;

		rctx->residue_len = sg_pcopy_to_buffer(req->src,
			sg_nents(req->src), rctx->residue, remlen, reqlen);
	} else if (req->result)
		memcpy(req->result, rctx->base.lastc, AES_BLOCK_SIZE);

	return atmel_aes_complete(dd, 0);
}

static int atmel_aes_cbcmac_start(struct atmel_aes_dev *dd)
{
	struct ahash_request *req = ahash_request_cast(dd->areq);
	struct atmel_aes_mac_reqctx *rctx = ahash_request_ctx(req);

	struct scatterlist *sg = req->src;
	size_t datalen = rctx->residue_len + req->nbytes;

	if (!rctx->is_final) {
		datalen &= ~(AES_BLOCK_SIZE - 1);
	} else if (!rctx->is_finup)
		datalen = rctx->residue_len;

	if (rctx->residue_len) {
		sg = rctx->sg;
		if (datalen > rctx->residue_len) {
			sg_init_table(sg, 2);
			sg_chain(sg, 2, req->src);
		} else
			sg_init_table(sg, 1);

		sg_set_buf(sg, rctx->residue, rctx->residue_len);
	}

	return atmel_aes_cbcmac_do_start(dd, sg, datalen, rctx->base.lastc,
		atmel_aes_cbcmac_transfer_complete);
}

static int atmel_aes_cbcmac_cra_init(struct crypto_tfm *tfm)
{
	struct atmel_aes_base_ctx *ctx = crypto_tfm_ctx(tfm);

	ctx->start = atmel_aes_cbcmac_start;
	ctx->block_size = AES_BLOCK_SIZE;
	ctx->is_aead = false;

	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
				 sizeof(struct atmel_aes_mac_reqctx));
	return 0;
}

static int atmel_aes_cbcmac_init(struct ahash_request *req)
{
	struct atmel_aes_mac_reqctx *rctx = ahash_request_ctx(req);

	memset(rctx, 0, sizeof(struct atmel_aes_mac_reqctx));

	rctx->base.mode = AES_FLAGS_CBCMAC | AES_FLAGS_ENCRYPT;

	return 0;
}

static int atmel_aes_cbcmac_update(struct ahash_request *req)
{
	struct atmel_aes_mac_reqctx *rctx = ahash_request_ctx(req);
	size_t datalen = rctx->residue_len + req->nbytes;

	if (datalen <= AES_BLOCK_SIZE) {
		sg_copy_to_buffer(req->src, sg_nents(req->src),
			(u8*)rctx->residue + rctx->residue_len,
			req->nbytes);
		rctx->residue_len = datalen;
		return 0;
	}

	return atmel_aes_handle_queue(&req->base);
}

static int atmel_aes_cbcmac_final(struct ahash_request *req)
{
	struct atmel_aes_mac_reqctx *rctx = ahash_request_ctx(req);

	rctx->is_final = true;

	if (rctx->residue_len)
		return atmel_aes_handle_queue(&req->base);

	if (req->result)
		memcpy(req->result, rctx->base.lastc, AES_BLOCK_SIZE);

	return 0;
}

static int atmel_aes_cbcmac_finup(struct ahash_request *req)
{
	struct atmel_aes_mac_reqctx *rctx = ahash_request_ctx(req);

	rctx->is_final = true;
	rctx->is_finup = true;

	if (rctx->residue_len || req->nbytes)
		return atmel_aes_handle_queue(&req->base);

	if (req->result)
		memcpy(req->result, rctx->base.lastc, AES_BLOCK_SIZE);

	return 0;
}

static int atmel_aes_cbcmac_digest(struct ahash_request *req)
{
	struct crypto_ahash *tfm = crypto_ahash_reqtfm(req);

	return tfm->init(req) ?: tfm->finup(req);
}

static int atmel_aes_cbcmac_export(struct ahash_request *req, void *out)
{
	const struct atmel_aes_mac_reqctx *rctx = ahash_request_ctx(req);

	memcpy(out, rctx, sizeof(*rctx));
	return 0;
}

static int atmel_aes_cbcmac_import(struct ahash_request *req, const void *in)
{
	struct atmel_aes_mac_reqctx *rctx = ahash_request_ctx(req);

	memcpy(rctx, in, sizeof(*rctx));
	return 0;
}

static int atmel_aes_cbcmac_setkey(struct crypto_ahash *tfm, const u8 *key,
			   unsigned int keylen)
{
	struct atmel_aes_base_ctx *ctx = crypto_ahash_ctx(tfm);

	if (keylen != AES_KEYSIZE_128 &&
	    keylen != AES_KEYSIZE_192 &&
	    keylen != AES_KEYSIZE_256) {
		crypto_ahash_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}

	memcpy(ctx->key, key, keylen);
	ctx->keylen = keylen;

	return 0;
}

static void atmel_aes_cmac_kd(u32 *k1t, const u32 *lt)
{
    int i;
    u8 *k1 = (u8*)k1t;
    const u8 *l = (const u8*)lt;
    u8 c = l[0], carry = c >> 7, cnext;

    /* Shift block to left, including carry */
    for (i = 0; i < AES_BLOCK_SIZE - 1; i++, c = cnext)
        k1[i] = (c << 1) | ((cnext = l[i + 1]) >> 7);

    /* If MSB set fixup with R */
    k1[i] = (c << 1) ^ ((0 - carry) & 0x87);
}

static int atmel_aes_cmac_transfer_complete_final(struct atmel_aes_dev *dd)
{
	struct ahash_request *req = ahash_request_cast(dd->areq);
	struct atmel_aes_mac_reqctx *rctx = ahash_request_ctx(req);

	atmel_aes_read_block(dd, AES_ODATAR(0), rctx->base.lastc);

	if (req->result)
		memcpy(req->result, rctx->base.lastc, AES_BLOCK_SIZE);

	return atmel_aes_complete(dd, 0);
}

static int atmel_aes_cmac_do_final(struct atmel_aes_dev *dd, bool do_init)
{
	struct ahash_request *req = ahash_request_cast(dd->areq);
	struct atmel_aes_mac_reqctx *rctx = ahash_request_ctx(req);
	struct atmel_aes_cmac_ctx *ctx = (struct atmel_aes_cmac_ctx *)dd->ctx;

	size_t datalen = rctx->residue_len;
	u8 *data = (u8*)rctx->residue;

	if (datalen == AES_BLOCK_SIZE)
		crypto_xor(data, (u8*)ctx->k1, AES_BLOCK_SIZE);
	else {
		data[datalen++] = 0x80;
		if (datalen < AES_BLOCK_SIZE)
		    memset(data + datalen, 0, AES_BLOCK_SIZE - datalen);
		crypto_xor(data, (u8*)ctx->k2, AES_BLOCK_SIZE);
	}

	if (do_init) {
		atmel_aes_set_mode(dd, &rctx->base);
		atmel_aes_hw_init(dd);
		atmel_aes_write_ctrl(dd, false, rctx->base.lastc);
	}

	dd->force_sync = true;

	atmel_aes_write_block(dd, AES_IDATAR(0), (u32*)data);

	return atmel_aes_wait_for_data_ready(dd,
		atmel_aes_cmac_transfer_complete_final);
}

static int atmel_aes_cmac_transfer_complete(struct atmel_aes_dev *dd)
{
	struct ahash_request *req = ahash_request_cast(dd->areq);
	struct atmel_aes_mac_reqctx *rctx = ahash_request_ctx(req);

	size_t reqlen = dd->total - rctx->residue_len;
	size_t remlen = req->nbytes - reqlen;

	rctx->residue_len = sg_pcopy_to_buffer(req->src, sg_nents(req->src),
		rctx->residue, remlen, reqlen);

	if (rctx->is_final)
		return atmel_aes_cmac_do_final(dd, false);

	atmel_aes_read_block(dd, AES_ODATAR(0), rctx->base.lastc);
	return atmel_aes_complete(dd, 0);
}

static int atmel_aes_cmac_start(struct atmel_aes_dev *dd);

static int atmel_aes_cmac_transfer_complete_keys(struct atmel_aes_dev *dd)
{
	struct atmel_aes_cmac_ctx *ctx = (struct atmel_aes_cmac_ctx *)dd->ctx;

	atmel_aes_read_block(dd, AES_ODATAR(0), ctx->bl);

	atmel_aes_cmac_kd(ctx->k1, ctx->bl);
	atmel_aes_cmac_kd(ctx->k2, ctx->k1);
	ctx->has_key = true;

	memset(ctx->bl, 0, AES_BLOCK_SIZE);

	return atmel_aes_cmac_start(dd);
}

static int atmel_aes_cmac_keys_start(struct atmel_aes_dev *dd)
{
	struct atmel_aes_cmac_ctx *ctx = (struct atmel_aes_cmac_ctx *)dd->ctx;

	dd->force_sync = true;

	dd->flags &= ~AES_FLAGS_MODE_MASK;
	dd->flags |= (AES_FLAGS_ECB | AES_FLAGS_ENCRYPT);

	atmel_aes_hw_init(dd);
	atmel_aes_write_ctrl(dd, false, NULL);

	atmel_aes_write_block(dd, AES_IDATAR(0), ctx->bl);

	return atmel_aes_wait_for_data_ready(dd,
		atmel_aes_cmac_transfer_complete_keys);
}

static int atmel_aes_cmac_start(struct atmel_aes_dev *dd)
{
	struct ahash_request *req = ahash_request_cast(dd->areq);
	struct atmel_aes_mac_reqctx *rctx = ahash_request_ctx(req);
	struct atmel_aes_cmac_ctx *ctx = (struct atmel_aes_cmac_ctx *)dd->ctx;

	struct scatterlist *sg = req->src;
	size_t datalen;

	if (!ctx->has_key)
		return atmel_aes_cmac_keys_start(dd);

	if (rctx->is_final && !rctx->is_finup)
		return atmel_aes_cmac_do_final(dd, true);

	if (rctx->residue_len) {
		sg = rctx->sg;
		sg_set_buf(sg, rctx->residue, rctx->residue_len);
		sg_chain(sg, 2, req->src);
	}

	datalen = ALIGN((rctx->residue_len + req->nbytes), AES_BLOCK_SIZE) -
		AES_BLOCK_SIZE;

	return atmel_aes_cbcmac_do_start(dd, sg, datalen, rctx->base.lastc,
		atmel_aes_cmac_transfer_complete);
}

static int atmel_aes_cmac_cra_init(struct crypto_tfm *tfm)
{
	struct atmel_aes_base_ctx *ctx = crypto_tfm_ctx(tfm);

	ctx->start = atmel_aes_cmac_start;
	ctx->block_size = AES_BLOCK_SIZE;
	ctx->is_aead = false;

	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
				 sizeof(struct atmel_aes_mac_reqctx));

	return 0;
}

static int atmel_aes_cmac_final(struct ahash_request *req)
{
	struct atmel_aes_mac_reqctx *rctx = ahash_request_ctx(req);

	rctx->is_final = true;

	return atmel_aes_handle_queue(&req->base);
}

static int atmel_aes_cmac_finup(struct ahash_request *req)
{
	struct atmel_aes_mac_reqctx *rctx = ahash_request_ctx(req);
	size_t datalen = rctx->residue_len + req->nbytes;

	if (datalen <= AES_BLOCK_SIZE) {
		sg_copy_to_buffer(req->src, sg_nents(req->src),
			(u8*)rctx->residue + rctx->residue_len,
			req->nbytes);
		rctx->residue_len = datalen;
	} else
		rctx->is_finup = true;

	rctx->is_final = true;

	return atmel_aes_handle_queue(&req->base);
}

static int atmel_aes_cmac_setkey(struct crypto_ahash *tfm, const u8 *key,
			   unsigned int keylen)
{
	struct atmel_aes_cmac_ctx *ctx = crypto_ahash_ctx(tfm);

	ctx->has_key = false;
	memset(ctx->bl, 0, AES_BLOCK_SIZE);
	memset(ctx->k1, 0, AES_BLOCK_SIZE);
	memset(ctx->k2, 0, AES_BLOCK_SIZE);

	return atmel_aes_cbcmac_setkey(tfm, key, keylen);;
}


static struct ahash_alg ahash_aes_algs[] = {
{
	.init		= atmel_aes_cbcmac_init,
	.update		= atmel_aes_cbcmac_update,
	.final		= atmel_aes_cbcmac_final,
	.finup		= atmel_aes_cbcmac_finup,
	.digest		= atmel_aes_cbcmac_digest,
	.export		= atmel_aes_cbcmac_export,
	.import		= atmel_aes_cbcmac_import,
	.setkey		= atmel_aes_cbcmac_setkey,
	.halg = {
		.digestsize	= AES_BLOCK_SIZE,
		.statesize	= sizeof(struct atmel_aes_mac_reqctx),
		.base	= {
			.cra_name	  = "cbcmac(aes)",
			.cra_driver_name  = "atmel-cbcmac-aes",
			.cra_priority	  = ATMEL_AES_PRIORITY,
			.cra_flags	  = ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
			.cra_blocksize	  = 1,
			.cra_ctxsize	  = sizeof(struct atmel_aes_ctx),
			.cra_alignmask	  = 0,
			.cra_module	  = THIS_MODULE,
			.cra_init	  = atmel_aes_cbcmac_cra_init,
		}
	}
},
{
	.init		= atmel_aes_cbcmac_init,
	.update		= atmel_aes_cbcmac_update,
	.final		= atmel_aes_cmac_final,
	.finup		= atmel_aes_cmac_finup,
	.digest		= atmel_aes_cbcmac_digest,
	.export		= atmel_aes_cbcmac_export,
	.import		= atmel_aes_cbcmac_import,
	.setkey		= atmel_aes_cmac_setkey,
	.halg = {
		.digestsize	= AES_BLOCK_SIZE,
		.statesize	= sizeof(struct atmel_aes_mac_reqctx),
		.base	= {
			.cra_name	  = "cmac(aes)",
			.cra_driver_name  = "atmel-cmac-aes",
			.cra_priority	  = ATMEL_AES_PRIORITY,
			.cra_flags	  = ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
			.cra_blocksize	  = 1,
			.cra_ctxsize	  = sizeof(struct atmel_aes_cmac_ctx),
			.cra_alignmask	  = 0,
			.cra_module	  = THIS_MODULE,
			.cra_init	  = atmel_aes_cmac_cra_init,
		}
	}
},
};

static int atmel_aes_ccm_set_msg_len(u8 *block, unsigned int msglen, int csize)
{
	__be32 data;

	memset(block, 0, csize);
	block += csize;

	if (csize >= 4)
		csize = 4;
	else if (msglen > (1 << (8 * csize)))
		return -EOVERFLOW;

	data = cpu_to_be32(msglen);
	memcpy(block - csize, (u8 *)&data + 4 - csize, csize);

	return 0;
}

static int atmel_aes_ccm_format_input(u8 *info, struct aead_request *req,
			unsigned int cryptlen)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	unsigned int lp = req->iv[0];
	unsigned int l = lp + 1;
	unsigned int m;

	m = crypto_aead_authsize(aead);

	memcpy(info, req->iv, AES_BLOCK_SIZE);

	/* format control info per RFC 3610 and
	 * NIST Special Publication 800-38C
	 */
	*info |= (8 * ((m - 2) / 2));
	if (req->assoclen)
		*info |= 64;

	return atmel_aes_ccm_set_msg_len(info + 16 - l, cryptlen, l);
}

static size_t atmel_aes_ccm_format_adata(u8 *adata, unsigned int a)
{
	size_t len = 0;

	/* add control info for associated data
	 * RFC 3610 and NIST Special Publication 800-38C
	 */
	if (a < 65280) {
		*(__be16 *)adata = cpu_to_be16(a);
		len = 2;
	} else  {
		*(__be16 *)adata = cpu_to_be16(0xfffe);
		*(__be32 *)&adata[2] = cpu_to_be32(a);
		len = 6;
	}

	return len;
}

static inline int atmel_aes_ccm_check_iv(const u8 *iv)
{
	/* 2 <= L <= 8, so 1 <= L' <= 7. */
	if (1 > iv[0] || iv[0] > 7)
		return -EINVAL;

	return 0;
}

static int atmel_aes_ccm_setauthsize(struct crypto_aead *tfm,
	unsigned int authsize)
{
	switch (authsize) {
	case 4:
	case 6:
	case 8:
	case 10:
	case 12:
	case 14:
	case 16:
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int atmel_aes_ccm_auth_transfer_complete2(struct atmel_aes_dev *dd)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_ccm_reqctx *rctx = aead_request_ctx(req);

	atmel_aes_read_block(dd, AES_ODATAR(0), rctx->odata);

	if (rctx->ctr.base.mode & AES_FLAGS_ENCRYPT) {
		return atmel_aes_ctr_start(dd);
	} else {
		struct crypto_aead *aead = crypto_aead_reqtfm(req);
		int err = 0;

		if (crypto_memneq(rctx->auth_tag, rctx->odata,
			crypto_aead_authsize(aead)))
			err = -EBADMSG;

		return atmel_aes_complete(dd, err);
	}
}

static int atmel_aes_ccm_auth_transfer_complete1(struct atmel_aes_dev *dd)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_ccm_reqctx *rctx = aead_request_ctx(req);
	struct scatterlist *sg;

	if (rctx->ctr.cryptlen <= AES_BLOCK_SIZE)
		return atmel_aes_ccm_auth_transfer_complete2(dd);

	atmel_aes_read_block(dd, AES_ODATAR(0), rctx->odata);

	sg = rctx->ctr.base.mode & AES_FLAGS_ENCRYPT ?
		rctx->src : rctx->ctr.rdst;

	return atmel_aes_cbcmac_do_start(dd, sg_next(sg),
		rctx->ctr.cryptlen - AES_BLOCK_SIZE, rctx->odata,
		atmel_aes_ccm_auth_transfer_complete2);
}

static int atmel_aes_ccm_auth(struct atmel_aes_dev *dd, size_t cryptlen)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_ccm_reqctx *rctx = aead_request_ctx(req);
	u32 iv[AES_BLOCK_SIZE /sizeof(u32)];

	/* format control data for input */
	int err = atmel_aes_ccm_format_input((u8*)rctx->odata, req, cryptlen);
	if (err)
		return err;

	memset(iv, 0, AES_BLOCK_SIZE);

	return atmel_aes_cbcmac_do_start(dd, rctx->sg, rctx->sglen, iv,
		atmel_aes_ccm_auth_transfer_complete1);
}

static int atmel_aes_ccm_ctr_transfer_complete(struct atmel_aes_dev *dd)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_ccm_reqctx *rctx = aead_request_ctx(req);
	struct crypto_aead *aead = crypto_aead_reqtfm(req);
	size_t authsize = crypto_aead_authsize(aead);

	if (rctx->ctr.base.mode & AES_FLAGS_ENCRYPT) {
		memcpy(req->iv, rctx->ctr.iv, AES_BLOCK_SIZE);
		scatterwalk_map_and_copy(rctx->odata, sg_next(rctx->ctr.rdst),
			req->cryptlen, authsize, 1);

		return atmel_aes_complete(dd, 0);
	} else
		return atmel_aes_ccm_auth(dd, req->cryptlen - authsize);
}

static int atmel_aes_ccm_init_crypt(struct aead_request *req, u32 *tag)
{
	struct atmel_aes_ccm_reqctx *rctx = aead_request_ctx(req);
	struct scatterlist *sg;
	u8 *iv = req->iv;
	int err;

	err = atmel_aes_ccm_check_iv(iv);
	if (err)
		return err;

	 /* Note: rfc 3610 and NIST 800-38C require counter of
	 * zero to encrypt auth tag.
	 */
	memset(iv + 15 - iv[0], 0, iv[0] + 1);

	sg_init_table(rctx->src, 3);
	sg_set_buf(rctx->src, tag, AES_BLOCK_SIZE);
	sg = scatterwalk_ffwd(rctx->src + 1, req->src, req->assoclen);
	if (sg != rctx->src + 1)
		sg_chain(rctx->src, 2, sg);

	if (req->src != req->dst) {
		sg_init_table(rctx->dst, 3);
		sg_set_buf(rctx->dst, tag, AES_BLOCK_SIZE);
		sg = scatterwalk_ffwd(rctx->dst + 1, req->dst, req->assoclen);
		if (sg != rctx->dst + 1)
			sg_chain(rctx->dst, 2, sg);
	}

	rctx->sglen = AES_BLOCK_SIZE;

	/* format associated data and compute into mac */
	if (req->assoclen) {
		size_t ilen = atmel_aes_ccm_format_adata((u8*)rctx->idata,
			req->assoclen);
		rctx->sglen += req->assoclen + ilen;

		sg_init_table(rctx->sg, 3);
		sg_set_buf(rctx->sg + 1, rctx->idata, ilen);
		sg_chain(rctx->sg, 3, req->src);
	} else
		sg_init_table(rctx->sg, 1);

	sg_set_buf(rctx->sg, rctx->odata, AES_BLOCK_SIZE);
	return 0;
}

static int atmel_aes_ccm_start(struct atmel_aes_dev *dd)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_ccm_reqctx *rctx = aead_request_ctx(req);

	if (rctx->ctr.base.mode & AES_FLAGS_ENCRYPT)
		return atmel_aes_ccm_auth(dd, req->cryptlen);
	else
		return atmel_aes_ctr_start(dd);
}

static int atmel_aes_ccm_crypt(struct aead_request *req,
			       unsigned long mode, size_t cryptlen)
{
	struct atmel_aes_ccm_reqctx *rctx = aead_request_ctx(req);

	rctx->ctr.base.mode = mode;

	rctx->ctr.rsrc = rctx->src;
	rctx->ctr.rdst = req->src == req->dst ? rctx->src : rctx->dst;
	rctx->ctr.cryptlen = cryptlen + AES_BLOCK_SIZE;

	return atmel_aes_handle_queue(&req->base);
}

static int atmel_aes_ccm_encrypt(struct aead_request *req)
{
	struct atmel_aes_ccm_reqctx *rctx = aead_request_ctx(req);
	int err;

	err = atmel_aes_ccm_init_crypt(req, rctx->odata);
	if (err)
		return err;

	return atmel_aes_ccm_crypt(req, AES_FLAGS_CTR | AES_FLAGS_ENCRYPT,
		req->cryptlen);
}

static int atmel_aes_ccm_decrypt(struct aead_request *req)
{
	struct atmel_aes_ccm_reqctx *rctx = aead_request_ctx(req);
	struct crypto_aead *aead = crypto_aead_reqtfm(req);

	size_t authsize = crypto_aead_authsize(aead);
	size_t cryptlen = req->cryptlen - authsize;

	int err;

	err = atmel_aes_ccm_init_crypt(req, rctx->auth_tag);
	if (err)
		return err;

	scatterwalk_map_and_copy(rctx->auth_tag, sg_next(rctx->src), cryptlen,
				 authsize, 0);

	return atmel_aes_ccm_crypt(req, AES_FLAGS_CTR, cryptlen);
}

static int atmel_aes_ccm_init(struct crypto_aead *tfm)
{
	struct atmel_aes_base_ctx *ctx = crypto_aead_ctx(tfm);

	ctx->start = atmel_aes_ccm_start;
	ctx->block_size = AES_BLOCK_SIZE;
	ctx->is_aead = true;

	crypto_aead_set_reqsize(tfm, sizeof(struct atmel_aes_ccm_reqctx));

	return 0;
}
/* gcm aead functions */

static int atmel_aes_gcm_ghash(struct atmel_aes_dev *dd,
			       const u32 *data, size_t datalen,
			       const u32 *ghash_in, u32 *ghash_out,
			       atmel_aes_fn_t resume);
static int atmel_aes_gcm_ghash_init(struct atmel_aes_dev *dd);
static int atmel_aes_gcm_ghash_finalize(struct atmel_aes_dev *dd);

static int atmel_aes_gcm_start(struct atmel_aes_dev *dd);
static int atmel_aes_gcm_process(struct atmel_aes_dev *dd);
static int atmel_aes_gcm_length(struct atmel_aes_dev *dd);
static int atmel_aes_gcm_data(struct atmel_aes_dev *dd);
static int atmel_aes_gcm_tag_init(struct atmel_aes_dev *dd);
static int atmel_aes_gcm_tag(struct atmel_aes_dev *dd);
static int atmel_aes_gcm_finalize(struct atmel_aes_dev *dd);

static int atmel_aes_gcm_ghash(struct atmel_aes_dev *dd,
			       const u32 *data, size_t datalen,
			       const u32 *ghash_in, u32 *ghash_out,
			       atmel_aes_fn_t resume)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_gcm_reqctx *rctx = aead_request_ctx(req);

	dd->data = (u32 *)data;
	dd->datalen = datalen;
	rctx->ghash_in = ghash_in;
	rctx->ghash_out = ghash_out;
	rctx->ghash_resume = resume;

	atmel_aes_write_ctrl(dd, false, NULL);
	return atmel_aes_wait_for_data_ready(dd, atmel_aes_gcm_ghash_init);
}

static int atmel_aes_gcm_ghash_init(struct atmel_aes_dev *dd)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_gcm_reqctx *rctx = aead_request_ctx(req);

	/* Set the data length. */
	atmel_aes_write(dd, AES_AADLENR, dd->total);
	atmel_aes_write(dd, AES_CLENR, 0);

	/* If needed, overwrite the GCM Intermediate Hash Word Registers */
	if (rctx->ghash_in)
		atmel_aes_write_block(dd, AES_GHASHR(0), rctx->ghash_in);

	return atmel_aes_gcm_ghash_finalize(dd);
}

static int atmel_aes_gcm_ghash_finalize(struct atmel_aes_dev *dd)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_gcm_reqctx *rctx = aead_request_ctx(req);
	int err;

	/* Write data into the Input Data Registers. */
	while (dd->datalen > 0) {
		atmel_aes_write_block(dd, AES_IDATAR(0), dd->data);
		dd->data += 4;
		dd->datalen -= AES_BLOCK_SIZE;

		err = atmel_aes_wait_for_data_ready_nr(dd,
			atmel_aes_gcm_ghash_finalize);
		if (err)
			return err;
	}

	/* Read the computed hash from GHASHRx. */
	atmel_aes_read_block(dd, AES_GHASHR(0), rctx->ghash_out);

	return rctx->ghash_resume(dd);
}


static int atmel_aes_gcm_start(struct atmel_aes_dev *dd)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_gcm_reqctx *rctx = aead_request_ctx(req);
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	size_t ivsize = crypto_aead_ivsize(tfm);
	size_t datalen, padlen;
	const void *iv = req->iv;
	u8 *data = dd->buf;

	atmel_aes_set_mode(dd, &rctx->base);

	atmel_aes_hw_init(dd);

	if (likely(ivsize == GCM_AES_IV_SIZE)) {
		memcpy(rctx->j0, iv, ivsize);
		rctx->j0[3] = cpu_to_be32(1);
		return atmel_aes_gcm_process(dd);
	}

	padlen = atmel_aes_padlen(ivsize, AES_BLOCK_SIZE);
	datalen = ivsize + padlen + AES_BLOCK_SIZE;
	if (datalen > dd->buflen)
		return atmel_aes_complete(dd, -EINVAL);

	memcpy(data, iv, ivsize);
	memset(data + ivsize, 0, padlen + sizeof(u64));
	((u64 *)(data + datalen))[-1] = cpu_to_be64(ivsize * 8);

	return atmel_aes_gcm_ghash(dd, (const u32 *)data, datalen,
				   NULL, rctx->j0, atmel_aes_gcm_process);
}

static int atmel_aes_gcm_process(struct atmel_aes_dev *dd)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct atmel_aes_gcm_reqctx *rctx = aead_request_ctx(req);
	bool enc = atmel_aes_is_encrypt(dd);
	u32 authsize;

	/* Compute text length. */
	authsize = crypto_aead_authsize(tfm);
	rctx->textlen = req->cryptlen - (enc ? 0 : authsize);

	/*
	 * According to tcrypt test suite, the GCM Automatic Tag Generation
	 * fails when both the message and its associated data are empty.
	 */
	if (likely(req->assoclen != 0 || rctx->textlen != 0))
		dd->flags |= AES_FLAGS_GTAGEN;

	atmel_aes_write_ctrl(dd, false, NULL);
	return atmel_aes_wait_for_data_ready(dd, atmel_aes_gcm_length);
}

static int atmel_aes_gcm_length(struct atmel_aes_dev *dd)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_gcm_reqctx *rctx = aead_request_ctx(req);
	u32 j0_lsw, *j0 = rctx->j0;
	size_t padlen;

	/* Write incr32(J0) into IV. */
	j0_lsw = j0[3];
	j0[3] = cpu_to_be32(be32_to_cpu(j0[3]) + 1);
	atmel_aes_write_block(dd, AES_IVR(0), j0);
	j0[3] = j0_lsw;

	/* Set aad and text lengths. */
	atmel_aes_write(dd, AES_AADLENR, req->assoclen);
	atmel_aes_write(dd, AES_CLENR, rctx->textlen);

	/* Check whether AAD are present. */
	if (unlikely(req->assoclen == 0)) {
		dd->datalen = 0;
		return atmel_aes_gcm_data(dd);
	}

	/* Copy assoc data and add padding. */
	padlen = atmel_aes_padlen(req->assoclen, AES_BLOCK_SIZE);
	if (unlikely(req->assoclen + padlen > dd->buflen))
		return atmel_aes_complete(dd, -EINVAL);
	sg_copy_to_buffer(req->src, sg_nents(req->src), dd->buf, req->assoclen);

	/* Write assoc data into the Input Data register. */
	dd->data = (u32 *)dd->buf;
	dd->datalen = req->assoclen + padlen;
	return atmel_aes_gcm_data(dd);
}

static int atmel_aes_gcm_data(struct atmel_aes_dev *dd)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_gcm_reqctx *rctx = aead_request_ctx(req);
	bool use_dma = (rctx->textlen >= ATMEL_AES_DMA_THRESHOLD);
	struct scatterlist *src, *dst;
	u32 mr;
	int err;

	/* Write AAD first. */
	while (dd->datalen > 0) {
		atmel_aes_write_block(dd, AES_IDATAR(0), dd->data);
		dd->data += 4;
		dd->datalen -= AES_BLOCK_SIZE;
		dd->force_sync = true;

		err = atmel_aes_wait_for_data_ready_nr(dd, atmel_aes_gcm_data);
		if (err)
			return err;
	}

	/* GMAC only. */
	if (unlikely(rctx->textlen == 0))
		return atmel_aes_gcm_tag_init(dd);

	/* Prepare src and dst scatter lists to transfer cipher/plain texts */
	src = scatterwalk_ffwd(rctx->src, req->src, req->assoclen);
	dst = ((req->src == req->dst) ? src :
	       scatterwalk_ffwd(rctx->dst, req->dst, req->assoclen));

	if (use_dma) {
		/* Update the Mode Register for DMA transfers. */
		mr = atmel_aes_read(dd, AES_MR);
		mr &= ~(AES_MR_SMOD_MASK | AES_MR_DUALBUFF);
		mr |= AES_MR_SMOD_IDATAR0;
		if (dd->caps.has_dualbuff)
			mr |= AES_MR_DUALBUFF;
		atmel_aes_write(dd, AES_MR, mr);

		return atmel_aes_dma_start(dd, src, dst, rctx->textlen,
					   atmel_aes_gcm_tag_init);
	}

	return atmel_aes_cpu_start(dd, src, dst, rctx->textlen,
				   atmel_aes_gcm_tag_init);
}

static int atmel_aes_gcm_tag_init(struct atmel_aes_dev *dd)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_gcm_reqctx *rctx = aead_request_ctx(req);
	u64 *data = dd->buf;

	if (likely(dd->flags & AES_FLAGS_GTAGEN)) {
		int ret = atmel_aes_wait_for_tag_ready_nr(dd,
			atmel_aes_gcm_tag_init);

		return ret ? ret : atmel_aes_gcm_finalize(dd);
	}

	/* Read the GCM Intermediate Hash Word Registers. */
	atmel_aes_read_block(dd, AES_GHASHR(0), rctx->ghash);

	data[0] = cpu_to_be64(req->assoclen * 8);
	data[1] = cpu_to_be64(rctx->textlen * 8);

	return atmel_aes_gcm_ghash(dd, (const u32 *)data, AES_BLOCK_SIZE,
				   rctx->ghash, rctx->ghash, atmel_aes_gcm_tag);
}

static int atmel_aes_gcm_tag(struct atmel_aes_dev *dd)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_gcm_reqctx *rctx = aead_request_ctx(req);
	unsigned long flags;

	/*
	 * Change mode to CTR to complete the tag generation.
	 * Use J0 as Initialization Vector.
	 */
	flags = dd->flags;
	dd->flags &= ~(AES_FLAGS_OPMODE_MASK | AES_FLAGS_GTAGEN);
	dd->flags |= AES_FLAGS_CTR;
	atmel_aes_write_ctrl(dd, false, rctx->j0);
	dd->flags = flags;

	atmel_aes_write_block(dd, AES_IDATAR(0), rctx->ghash);
	return atmel_aes_wait_for_data_ready(dd, atmel_aes_gcm_finalize);
}

static int atmel_aes_gcm_finalize(struct atmel_aes_dev *dd)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_gcm_reqctx *rctx = aead_request_ctx(req);
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	bool enc = atmel_aes_is_encrypt(dd);
	u32 offset, authsize, itag[4], *otag = rctx->tag;
	int err;

	/* Read the computed tag. */
	if (likely(dd->flags & AES_FLAGS_GTAGEN))
		atmel_aes_read_block(dd, AES_TAGR(0), rctx->tag);
	else
		atmel_aes_read_block(dd, AES_ODATAR(0), rctx->tag);

	offset = req->assoclen + rctx->textlen;
	authsize = crypto_aead_authsize(tfm);
	if (enc) {
		scatterwalk_map_and_copy(otag, req->dst, offset, authsize, 1);
		err = 0;
	} else {
		scatterwalk_map_and_copy(itag, req->src, offset, authsize, 0);
		err = crypto_memneq(itag, otag, authsize) ? -EBADMSG : 0;
	}

	return atmel_aes_complete(dd, err);
}

static int atmel_aes_gcm_crypt(struct aead_request *req,
			       unsigned long mode)
{
	struct atmel_aes_reqctx *rctx = aead_request_ctx(req);

	rctx->mode = AES_FLAGS_GCM | mode;

	return atmel_aes_handle_queue(&req->base);
}

static int atmel_aes_gcm_setkey(struct crypto_aead *tfm, const u8 *key,
				unsigned int keylen)
{
	struct atmel_aes_base_ctx *ctx = crypto_aead_ctx(tfm);

	if (keylen != AES_KEYSIZE_256 &&
	    keylen != AES_KEYSIZE_192 &&
	    keylen != AES_KEYSIZE_128) {
		crypto_aead_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
		return -EINVAL;
	}

	memcpy(ctx->key, key, keylen);
	ctx->keylen = keylen;

	return 0;
}

static int atmel_aes_gcm_setauthsize(struct crypto_aead *tfm,
				     unsigned int authsize)
{
	/* Same as crypto_gcm_authsize() from crypto/gcm.c */
	switch (authsize) {
	case 4:
	case 8:
	case 12:
	case 13:
	case 14:
	case 15:
	case 16:
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int atmel_aes_gcm_encrypt(struct aead_request *req)
{
	return atmel_aes_gcm_crypt(req, AES_FLAGS_ENCRYPT);
}

static int atmel_aes_gcm_decrypt(struct aead_request *req)
{
	return atmel_aes_gcm_crypt(req, 0);
}

static int atmel_aes_gcm_init(struct crypto_aead *tfm)
{
	struct atmel_aes_base_ctx *ctx = crypto_aead_ctx(tfm);

	ctx->start = atmel_aes_gcm_start;
	ctx->block_size = AES_BLOCK_SIZE;
	ctx->is_aead = true;

	crypto_aead_set_reqsize(tfm, sizeof(struct atmel_aes_gcm_reqctx));

	return 0;
}

static int atmel_aes_xts_encrypt(struct ablkcipher_request *req)
{
	return atmel_aes_crypt(req, AES_FLAGS_XTS | AES_FLAGS_ENCRYPT);
}

static int atmel_aes_xts_decrypt(struct ablkcipher_request *req)
{
	return atmel_aes_crypt(req, AES_FLAGS_XTS);
}

static int atmel_aes_xts_cra_init(struct crypto_tfm *tfm)
{
	struct atmel_aes_xts_ctx *ctx = crypto_tfm_ctx(tfm);

	tfm->crt_ablkcipher.reqsize = sizeof(struct atmel_aes_reqctx);
	ctx->base.start = atmel_aes_xts_start;

	return 0;
}

static struct crypto_alg aes_xts_alg = {
	.cra_name		= "xts(aes)",
	.cra_driver_name	= "atmel-xts-aes",
	.cra_priority		= ATMEL_AES_PRIORITY,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct atmel_aes_xts_ctx),
	.cra_alignmask		= 0xf,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= atmel_aes_xts_cra_init,
	.cra_u.ablkcipher = {
		.min_keysize	= 2 * AES_MIN_KEY_SIZE,
		.max_keysize	= 2 * AES_MAX_KEY_SIZE,
		.ivsize		= AES_BLOCK_SIZE,
		.setkey		= atmel_aes_xts_setkey,
		.encrypt	= atmel_aes_xts_encrypt,
		.decrypt	= atmel_aes_xts_decrypt,
	}
};

#ifdef CONFIG_CRYPTO_DEV_ATMEL_AUTHENC
/* authenc aead functions */

static int atmel_aes_authenc_start(struct atmel_aes_dev *dd);
static int atmel_aes_authenc_init(struct atmel_aes_dev *dd, int err,
				  bool is_async);
static int atmel_aes_authenc_transfer(struct atmel_aes_dev *dd, int err,
				      bool is_async);
static int atmel_aes_authenc_digest(struct atmel_aes_dev *dd);
static int atmel_aes_authenc_final(struct atmel_aes_dev *dd, int err,
				   bool is_async);

static void atmel_aes_authenc_complete(struct atmel_aes_dev *dd, int err)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_authenc_reqctx *rctx = aead_request_ctx(req);

	if (err && (dd->flags & AES_FLAGS_OWN_SHA))
		atmel_sha_authenc_abort(&rctx->auth_req);
	dd->flags &= ~AES_FLAGS_OWN_SHA;
}

static int atmel_aes_authenc_start(struct atmel_aes_dev *dd)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_authenc_reqctx *rctx = aead_request_ctx(req);
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct atmel_aes_authenc_ctx *ctx = crypto_aead_ctx(tfm);

	atmel_aes_set_mode(dd, &rctx->base);

	atmel_aes_hw_init(dd);

	return atmel_sha_authenc_schedule(&rctx->auth_req, ctx->auth,
					  atmel_aes_authenc_init, dd);
}

static int atmel_aes_authenc_init(struct atmel_aes_dev *dd, int err,
				  bool is_async)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_authenc_reqctx *rctx = aead_request_ctx(req);

	if (is_async)
		dd->is_async = true;
	if (err)
		return atmel_aes_complete(dd, err);

	/* If here, we've got the ownership of the SHA device. */
	dd->flags |= AES_FLAGS_OWN_SHA;

	/* Configure the SHA device. */
	return atmel_sha_authenc_init(&rctx->auth_req,
				      req->src, req->assoclen,
				      rctx->textlen,
				      atmel_aes_authenc_transfer, dd);
}

static int atmel_aes_authenc_transfer(struct atmel_aes_dev *dd, int err,
				      bool is_async)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_authenc_reqctx *rctx = aead_request_ctx(req);
	bool enc = atmel_aes_is_encrypt(dd);
	struct scatterlist *src, *dst;
	u32 iv[AES_BLOCK_SIZE / sizeof(u32)];
	u32 emr;

	if (is_async)
		dd->is_async = true;
	if (err)
		return atmel_aes_complete(dd, err);

	/* Prepare src and dst scatter-lists to transfer cipher/plain texts. */
	src = scatterwalk_ffwd(rctx->src, req->src, req->assoclen);
	dst = src;

	if (req->src != req->dst)
		dst = scatterwalk_ffwd(rctx->dst, req->dst, req->assoclen);

	/* Configure the AES device. */
	memcpy(iv, req->iv, sizeof(iv));

	/*
	 * Here we always set the 2nd parameter of atmel_aes_write_ctrl() to
	 * 'true' even if the data transfer is actually performed by the CPU (so
	 * not by the DMA) because we must force the AES_MR_SMOD bitfield to the
	 * value AES_MR_SMOD_IDATAR0. Indeed, both AES_MR_SMOD and SHA_MR_SMOD
	 * must be set to *_MR_SMOD_IDATAR0.
	 */
	atmel_aes_write_ctrl(dd, true, iv);
	emr = AES_EMR_PLIPEN;
	if (!enc)
		emr |= AES_EMR_PLIPD;
	atmel_aes_write(dd, AES_EMR, emr);

	/* Transfer data. */
	return atmel_aes_dma_start(dd, src, dst, rctx->textlen,
				   atmel_aes_authenc_digest);
}

static int atmel_aes_authenc_digest(struct atmel_aes_dev *dd)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_authenc_reqctx *rctx = aead_request_ctx(req);

	/* atmel_sha_authenc_final() releases the SHA device. */
	dd->flags &= ~AES_FLAGS_OWN_SHA;
	return atmel_sha_authenc_final(&rctx->auth_req,
				       rctx->digest, sizeof(rctx->digest),
				       atmel_aes_authenc_final, dd);
}

static int atmel_aes_authenc_final(struct atmel_aes_dev *dd, int err,
				   bool is_async)
{
	struct aead_request *req = aead_request_cast(dd->areq);
	struct atmel_aes_authenc_reqctx *rctx = aead_request_ctx(req);
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	bool enc = atmel_aes_is_encrypt(dd);
	u32 idigest[SHA512_DIGEST_SIZE / sizeof(u32)], *odigest = rctx->digest;
	u32 offs, authsize;

	if (is_async)
		dd->is_async = true;
	if (err)
		goto complete;

	offs = req->assoclen + rctx->textlen;
	authsize = crypto_aead_authsize(tfm);
	if (enc) {
		scatterwalk_map_and_copy(odigest, req->dst, offs, authsize, 1);
	} else {
		scatterwalk_map_and_copy(idigest, req->src, offs, authsize, 0);
		if (crypto_memneq(idigest, odigest, authsize))
			err = -EBADMSG;
	}

complete:
	return atmel_aes_complete(dd, err);
}

static int atmel_aes_authenc_setkey(struct crypto_aead *tfm, const u8 *key,
				    unsigned int keylen)
{
	struct atmel_aes_authenc_ctx *ctx = crypto_aead_ctx(tfm);
	struct crypto_authenc_keys keys;
	u32 flags;
	int err;

	if (crypto_authenc_extractkeys(&keys, key, keylen) != 0)
		goto badkey;

	if (keys.enckeylen > sizeof(ctx->base.key))
		goto badkey;

	/* Save auth key. */
	flags = crypto_aead_get_flags(tfm);
	err = atmel_sha_authenc_setkey(ctx->auth,
				       keys.authkey, keys.authkeylen,
				       &flags);
	crypto_aead_set_flags(tfm, flags & CRYPTO_TFM_RES_MASK);
	if (err) {
		memzero_explicit(&keys, sizeof(keys));
		return err;
	}

	/* Save enc key. */
	ctx->base.keylen = keys.enckeylen;
	memcpy(ctx->base.key, keys.enckey, keys.enckeylen);

	memzero_explicit(&keys, sizeof(keys));
	return 0;

badkey:
	crypto_aead_set_flags(tfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
	memzero_explicit(&keys, sizeof(keys));
	return -EINVAL;
}

static int atmel_aes_authenc_init_tfm(struct crypto_aead *tfm,
				      unsigned long auth_mode)
{
	struct atmel_aes_authenc_ctx *ctx = crypto_aead_ctx(tfm);
	unsigned int auth_reqsize = atmel_sha_authenc_get_reqsize();

	ctx->auth = atmel_sha_authenc_spawn(auth_mode);
	if (IS_ERR(ctx->auth))
		return PTR_ERR(ctx->auth);

	ctx->base.start = atmel_aes_authenc_start;
	ctx->base.block_size = AES_BLOCK_SIZE;
	ctx->base.is_aead = true;

	crypto_aead_set_reqsize(tfm, (sizeof(struct atmel_aes_authenc_reqctx) +
				      auth_reqsize));

	return 0;
}

static int atmel_aes_authenc_hmac_sha1_init_tfm(struct crypto_aead *tfm)
{
	return atmel_aes_authenc_init_tfm(tfm, SHA_FLAGS_HMAC_SHA1);
}

static int atmel_aes_authenc_hmac_sha224_init_tfm(struct crypto_aead *tfm)
{
	return atmel_aes_authenc_init_tfm(tfm, SHA_FLAGS_HMAC_SHA224);
}

static int atmel_aes_authenc_hmac_sha256_init_tfm(struct crypto_aead *tfm)
{
	return atmel_aes_authenc_init_tfm(tfm, SHA_FLAGS_HMAC_SHA256);
}

static int atmel_aes_authenc_hmac_sha384_init_tfm(struct crypto_aead *tfm)
{
	return atmel_aes_authenc_init_tfm(tfm, SHA_FLAGS_HMAC_SHA384);
}

static int atmel_aes_authenc_hmac_sha512_init_tfm(struct crypto_aead *tfm)
{
	return atmel_aes_authenc_init_tfm(tfm, SHA_FLAGS_HMAC_SHA512);
}

static void atmel_aes_authenc_exit_tfm(struct crypto_aead *tfm)
{
	struct atmel_aes_authenc_ctx *ctx = crypto_aead_ctx(tfm);

	atmel_sha_authenc_free(ctx->auth);
}

static int atmel_aes_authenc_crypt(struct aead_request *req,
				   unsigned long mode)
{
	struct atmel_aes_authenc_reqctx *rctx = aead_request_ctx(req);
	u32 authsize = crypto_aead_authsize(tfm);
	bool enc = (mode & AES_FLAGS_ENCRYPT);

	/* Compute text length. */
	if (!enc && req->cryptlen < authsize)
		return -EINVAL;
	rctx->textlen = req->cryptlen - (enc ? 0 : authsize);

	/*
	 * Currently, empty messages are not supported yet:
	 * the SHA auto-padding can be used only on non-empty messages.
	 * Hence a special case needs to be implemented for empty message.
	 */
	if (!rctx->textlen && !req->assoclen)
		return -EINVAL;

	rctx->base.mode = mode;

	return atmel_aes_handle_queue(&req->base);
}

static int atmel_aes_authenc_cbc_aes_encrypt(struct aead_request *req)
{
	return atmel_aes_authenc_crypt(req, AES_FLAGS_CBC | AES_FLAGS_ENCRYPT);
}

static int atmel_aes_authenc_cbc_aes_decrypt(struct aead_request *req)
{
	return atmel_aes_authenc_crypt(req, AES_FLAGS_CBC);
}

#endif /* CONFIG_CRYPTO_DEV_ATMEL_AUTHENC */

static struct aead_alg aead_aes_algs[] = {
{
	.setkey		= atmel_aes_gcm_setkey,
	.setauthsize	= atmel_aes_ccm_setauthsize,
	.encrypt	= atmel_aes_ccm_encrypt,
	.decrypt	= atmel_aes_ccm_decrypt,
	.init		= atmel_aes_ccm_init,
	.ivsize		= AES_BLOCK_SIZE,
	.chunksize	= AES_BLOCK_SIZE,
	.maxauthsize	= AES_BLOCK_SIZE,

	.base = {
		.cra_name		= "ccm(aes)",
		.cra_driver_name	= "atmel-ccm-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= 1,
		.cra_ctxsize		= sizeof(struct atmel_aes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
	},
},
{
	.setkey		= atmel_aes_gcm_setkey,
	.setauthsize	= atmel_aes_gcm_setauthsize,
	.encrypt	= atmel_aes_gcm_encrypt,
	.decrypt	= atmel_aes_gcm_decrypt,
	.init		= atmel_aes_gcm_init,
	.ivsize		= GCM_AES_IV_SIZE,
	.chunksize	= AES_BLOCK_SIZE,
	.maxauthsize	= AES_BLOCK_SIZE,

	.base = {
		.cra_name		= "gcm(aes)",
		.cra_driver_name	= "atmel-gcm-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= 1,
		.cra_ctxsize		= sizeof(struct atmel_aes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
	},
},
#ifdef CONFIG_CRYPTO_DEV_ATMEL_AUTHENC
{
	.setkey		= atmel_aes_authenc_setkey,
	.encrypt	= atmel_aes_authenc_cbc_aes_encrypt,
	.decrypt	= atmel_aes_authenc_cbc_aes_decrypt,
	.init		= atmel_aes_authenc_hmac_sha1_init_tfm,
	.exit		= atmel_aes_authenc_exit_tfm,
	.ivsize		= AES_BLOCK_SIZE,
	.maxauthsize	= SHA1_DIGEST_SIZE,

	.base = {
		.cra_name		= "authenc(hmac(sha1),cbc(aes))",
		.cra_driver_name	= "atmel-authenc-hmac-sha1-cbc-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= AES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_aes_authenc_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
	},
},
{
	.setkey		= atmel_aes_authenc_setkey,
	.encrypt	= atmel_aes_authenc_cbc_aes_encrypt,
	.decrypt	= atmel_aes_authenc_cbc_aes_decrypt,
	.init		= atmel_aes_authenc_hmac_sha224_init_tfm,
	.exit		= atmel_aes_authenc_exit_tfm,
	.ivsize		= AES_BLOCK_SIZE,
	.maxauthsize	= SHA224_DIGEST_SIZE,

	.base = {
		.cra_name		= "authenc(hmac(sha224),cbc(aes))",
		.cra_driver_name	= "atmel-authenc-hmac-sha224-cbc-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= AES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_aes_authenc_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
	},
},
{
	.setkey		= atmel_aes_authenc_setkey,
	.encrypt	= atmel_aes_authenc_cbc_aes_encrypt,
	.decrypt	= atmel_aes_authenc_cbc_aes_decrypt,
	.init		= atmel_aes_authenc_hmac_sha256_init_tfm,
	.exit		= atmel_aes_authenc_exit_tfm,
	.ivsize		= AES_BLOCK_SIZE,
	.maxauthsize	= SHA256_DIGEST_SIZE,

	.base = {
		.cra_name		= "authenc(hmac(sha256),cbc(aes))",
		.cra_driver_name	= "atmel-authenc-hmac-sha256-cbc-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= AES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_aes_authenc_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
	},
},
{
	.setkey		= atmel_aes_authenc_setkey,
	.encrypt	= atmel_aes_authenc_cbc_aes_encrypt,
	.decrypt	= atmel_aes_authenc_cbc_aes_decrypt,
	.init		= atmel_aes_authenc_hmac_sha384_init_tfm,
	.exit		= atmel_aes_authenc_exit_tfm,
	.ivsize		= AES_BLOCK_SIZE,
	.maxauthsize	= SHA384_DIGEST_SIZE,

	.base = {
		.cra_name		= "authenc(hmac(sha384),cbc(aes))",
		.cra_driver_name	= "atmel-authenc-hmac-sha384-cbc-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= AES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_aes_authenc_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
	},
},
{
	.setkey		= atmel_aes_authenc_setkey,
	.encrypt	= atmel_aes_authenc_cbc_aes_encrypt,
	.decrypt	= atmel_aes_authenc_cbc_aes_decrypt,
	.init		= atmel_aes_authenc_hmac_sha512_init_tfm,
	.exit		= atmel_aes_authenc_exit_tfm,
	.ivsize		= AES_BLOCK_SIZE,
	.maxauthsize	= SHA512_DIGEST_SIZE,

	.base = {
		.cra_name		= "authenc(hmac(sha512),cbc(aes))",
		.cra_driver_name	= "atmel-authenc-hmac-sha512-cbc-aes",
		.cra_priority		= ATMEL_AES_PRIORITY,
		.cra_flags		= ATMEL_CRYPTO_ALG_FLAGS_ASYNC,
		.cra_blocksize		= AES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_aes_authenc_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
	},
},
#endif
};

static void atmel_aes_cia_blk(struct atmel_aes_base_ctx *ctx, u8 *dst,
	const u8 *src, unsigned long mode)
{
	struct atmel_aes_dev *dd;

	spin_lock_bh(&atmel_aes.lock);

	dd = atmel_aes.dd;

	if (dd) {
		dd->flags = AES_FLAGS_BUSY | mode;

		atmel_aes_hw_init(dd);

		atmel_aes_write_ctrl_key(dd, false, NULL, ctx->key,
			ctx->keylen);

		atmel_aes_write_block(dd, AES_IDATAR(0), (u32*)src);

		while (!(atmel_aes_read(dd, AES_ISR) & AES_INT_DATARDY)) {}

		atmel_aes_read_block(dd, AES_ODATAR(0), (u32*)dst);

		atmel_aes_write(dd, AES_CR, AES_CR_SWRST);

		dd->flags = 0;
	}

	spin_unlock_bh(&atmel_aes.lock);
}

static void atmel_aes_cia_encrypt(struct crypto_tfm *tfm, u8 *dst,
	const u8 *src)
{
	atmel_aes_cia_blk(crypto_tfm_ctx(tfm), dst, src, AES_FLAGS_ECB |
		AES_FLAGS_ENCRYPT);
}

static void atmel_aes_cia_decrypt(struct crypto_tfm *tfm, u8 *dst,
	const u8 *src)
{
	atmel_aes_cia_blk(crypto_tfm_ctx(tfm), dst, src, AES_FLAGS_ECB);
}

static int atmel_aes_cia_setkey(struct crypto_tfm *tfm, const u8 *in_key,
		unsigned int key_len)
{
	struct atmel_aes_base_ctx * ctx =
		(struct atmel_aes_base_ctx*) crypto_tfm_ctx(tfm);

	if (key_len != AES_KEYSIZE_128 &&
	    key_len != AES_KEYSIZE_192 &&
	    key_len != AES_KEYSIZE_256) {
		tfm->crt_flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
		return -EINVAL;
	}

	memcpy(ctx->key, in_key, key_len);
	ctx->keylen = key_len;

	return 0;
}

static struct crypto_alg aes_alg = {
	.cra_name		= "aes",
	.cra_driver_name	= "atmel-aes",
	.cra_priority		= ATMEL_AES_PRIORITY,
	.cra_flags		= CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct atmel_aes_ctx),
	.cra_alignmask		= 3,
	.cra_module		= THIS_MODULE,
	.cra_u.cipher = {
		.cia_min_keysize	= AES_MIN_KEY_SIZE,
		.cia_max_keysize	= AES_MAX_KEY_SIZE,
		.cia_setkey		= atmel_aes_cia_setkey,
		.cia_encrypt		= atmel_aes_cia_encrypt,
		.cia_decrypt		= atmel_aes_cia_decrypt,
	}
};

/* Probe functions */

static int atmel_aes_buff_init(struct atmel_aes_dev *dd)
{
	dd->buf = (void *)__get_free_pages(GFP_KERNEL, ATMEL_AES_BUFFER_ORDER);
	dd->buflen = ATMEL_AES_BUFFER_SIZE;
	dd->buflen &= ~(AES_BLOCK_SIZE - 1);

	if (!dd->buf) {
		dev_err(dd->dev, "unable to alloc pages.\n");
		return -ENOMEM;
	}

	return 0;
}

static void atmel_aes_buff_cleanup(struct atmel_aes_dev *dd)
{
	free_page((unsigned long)dd->buf);
}

static bool atmel_aes_filter(struct dma_chan *chan, void *slave)
{
	struct at_dma_slave	*sl = slave;

	if (sl && sl->dma_dev == chan->device->dev) {
		chan->private = sl;
		return true;
	} else {
		return false;
	}
}

static int atmel_aes_dma_init(struct atmel_aes_dev *dd,
			      struct crypto_platform_data *pdata)
{
	struct at_dma_slave *slave;
	dma_cap_mask_t mask;

	dma_cap_zero(mask);
	dma_cap_set(DMA_SLAVE, mask);

	/* Try to grab 2 DMA channels */
	slave = &pdata->dma_slave->rxdata;
	dd->src.chan = dma_request_slave_channel_compat(mask, atmel_aes_filter,
							slave, dd->dev, "tx");
	if (!dd->src.chan)
		goto err_dma_in;

	slave = &pdata->dma_slave->txdata;
	dd->dst.chan = dma_request_slave_channel_compat(mask, atmel_aes_filter,
							slave, dd->dev, "rx");
	if (!dd->dst.chan)
		goto err_dma_out;

	return 0;

err_dma_out:
	dma_release_channel(dd->src.chan);
err_dma_in:
	dev_warn(dd->dev, "no DMA channel available\n");
	return -ENODEV;
}

static void atmel_aes_dma_cleanup(struct atmel_aes_dev *dd)
{
	dma_release_channel(dd->dst.chan);
	dma_release_channel(dd->src.chan);
}

static void atmel_aes_done_task(unsigned long data)
{
	struct atmel_aes_dev *dd = (struct atmel_aes_dev *)data;

	atmel_aes_unmap(dd);

	dd->is_async = true;

	dd->resume(dd);
}

static irqreturn_t atmel_aes_irq(int irq, void *dev_id)
{
	struct atmel_aes_dev *dd = dev_id;
	u32 reg;

	reg = atmel_aes_read(dd, AES_ISR);
	if (reg & atmel_aes_read(dd, AES_IMR)) {
		atmel_aes_write(dd, AES_IDR, reg);
		if (AES_FLAGS_BUSY & dd->flags)
			tasklet_schedule(&dd->done_task);
		else
			dev_err(dd->dev, "AES interrupt when no active requests.\n");
		return IRQ_HANDLED;
	}

	return IRQ_NONE;
}

static void atmel_aes_unregister_algs(struct atmel_aes_dev *dd)
{
	int len_skciphers = ARRAY_SIZE(skcipher_aes_algs) - 2 +
		dd->caps.has_cfb64 + dd->caps.has_xts;

	int len_aeads = 1 + dd->caps.has_gcm;

#ifdef CONFIG_CRYPTO_DEV_ATMEL_AUTHENC
	if (dd->caps.has_authenc)
		len_aeads += 5;
#endif

	if (atmel_aes.sync_mode)
		crypto_unregister_alg(&aes_alg);

	crypto_unregister_aeads(aead_aes_algs, len_aeads);
	crypto_unregister_ahashes(ahash_aes_algs, ARRAY_SIZE(ahash_aes_algs));
	crypto_unregister_skciphers(skcipher_aes_algs, len_skciphers);
}

static int atmel_aes_register_algs(struct atmel_aes_dev *dd)
{
	int err, i;

	int len_skciphers = ARRAY_SIZE(skcipher_aes_algs) - 2 +
		dd->caps.has_cfb64 + dd->caps.has_xts;

	int len_aeads = 1 + dd->caps.has_gcm;

#ifdef CONFIG_CRYPTO_DEV_ATMEL_AUTHENC
	if (dd->caps.has_authenc)
		len_aeads += 5;
#endif

	for (i = 0; i < len_skciphers; ++i) {
		skcipher_aes_algs[i].base.cra_flags = atmel_aes.sync_mode ?
			ATMEL_CRYPTO_ALG_FLAGS_SYNC :
			ATMEL_CRYPTO_ALG_FLAGS_ASYNC;
	}

	err = crypto_register_skciphers(skcipher_aes_algs, len_skciphers);
	if (err)
		goto err_aes_skciphers;

	for (i = 0; i < ARRAY_SIZE(ahash_aes_algs); ++i) {
		ahash_aes_algs[i].halg.base.cra_flags = atmel_aes.sync_mode ?
			ATMEL_CRYPTO_ALG_FLAGS_SYNC :
			ATMEL_CRYPTO_ALG_FLAGS_ASYNC;
	}

	err = crypto_register_ahashes(ahash_aes_algs,
		ARRAY_SIZE(ahash_aes_algs));
	if (err)
		goto err_aes_ahashes;

	for (i = 0; i < len_aeads; ++i) {
		aead_aes_algs[i].base.cra_flags = atmel_aes.sync_mode ?
			ATMEL_CRYPTO_ALG_FLAGS_SYNC :
			ATMEL_CRYPTO_ALG_FLAGS_ASYNC;
	}

	err = crypto_register_aeads(aead_aes_algs, len_aeads);
	if (err)
		goto err_aes_aeads;

	if (atmel_aes.sync_mode) {
		err = crypto_register_alg(&aes_alg);
		if (err)
			goto err_aes_block;
	}

	return 0;

err_aes_block:
	crypto_unregister_aeads(aead_aes_algs, len_aeads);

err_aes_aeads:
	crypto_unregister_ahashes(ahash_aes_algs, ARRAY_SIZE(ahash_aes_algs));

err_aes_ahashes:
	crypto_unregister_skciphers(skcipher_aes_algs, len_skciphers);

err_aes_skciphers:
	return err;
}

static void atmel_aes_get_cap(struct atmel_aes_dev *dd)
{
	dd->caps.has_dualbuff = 0;
	dd->caps.has_cfb64 = 0;
	dd->caps.has_ctr32 = 0;
	dd->caps.has_gcm = 0;
	dd->caps.has_xts = 0;
	dd->caps.has_authenc = 0;
	dd->caps.max_burst_size = 1;

	/* keep only major version number */
	switch (dd->hw_version & 0xff0) {
	case 0x500:
		dd->caps.has_dualbuff = 1;
		dd->caps.has_cfb64 = 1;
		dd->caps.has_ctr32 = 1;
		dd->caps.has_gcm = 1;
		dd->caps.has_xts = 1;
		dd->caps.has_authenc = 1;
		dd->caps.max_burst_size = 4;
		break;
	case 0x200:
		dd->caps.has_dualbuff = 1;
		dd->caps.has_cfb64 = 1;
		dd->caps.has_ctr32 = 1;
		dd->caps.has_gcm = 1;
		dd->caps.max_burst_size = 4;
		break;
	case 0x130:
		dd->caps.has_dualbuff = 1;
		dd->caps.has_cfb64 = 1;
		dd->caps.max_burst_size = 4;
		break;
	case 0x120:
		break;
	default:
		dev_warn(dd->dev,
				"Unmanaged aes version, set minimum capabilities\n");
		break;
	}
}

#if defined(CONFIG_OF)
static const struct of_device_id atmel_aes_dt_ids[] = {
	{ .compatible = "atmel,at91sam9g46-aes" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, atmel_aes_dt_ids);

static struct crypto_platform_data *atmel_aes_of_init(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct crypto_platform_data *pdata;

	if (!np) {
		dev_err(&pdev->dev, "device node not found\n");
		return ERR_PTR(-EINVAL);
	}

	pdata = devm_kzalloc(&pdev->dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return ERR_PTR(-ENOMEM);

	pdata->dma_slave = devm_kzalloc(&pdev->dev,
					sizeof(*(pdata->dma_slave)),
					GFP_KERNEL);
	if (!pdata->dma_slave) {
		devm_kfree(&pdev->dev, pdata);
		return ERR_PTR(-ENOMEM);
	}

	return pdata;
}
#else
static inline struct crypto_platform_data *atmel_aes_of_init(struct platform_device *pdev)
{
	return ERR_PTR(-EINVAL);
}
#endif

static inline void atmel_aes_dev_register(struct atmel_aes_dev *dd)
{
	spin_lock_bh(&atmel_aes.lock);
	atmel_aes.dd = dd;
	atmel_aes.sync_mode = fips_enabled && fips_wifi_enabled;
	spin_unlock_bh(&atmel_aes.lock);
}

static int atmel_aes_probe(struct platform_device *pdev)
{
	struct atmel_aes_dev *dd;
	struct crypto_platform_data *pdata;
	struct device *dev = &pdev->dev;
	struct resource *aes_res;
	int err;

	pdata = pdev->dev.platform_data;
	if (!pdata) {
		pdata = atmel_aes_of_init(pdev);
		if (IS_ERR(pdata)) {
			err = PTR_ERR(pdata);
			goto aes_dd_err;
		}
	}

	if (!pdata->dma_slave) {
		err = -ENXIO;
		goto aes_dd_err;
	}

	dd = devm_kzalloc(&pdev->dev, sizeof(*dd), GFP_KERNEL);
	if (dd == NULL) {
		err = -ENOMEM;
		goto aes_dd_err;
	}

	dd->dev = dev;

	platform_set_drvdata(pdev, dd);

	tasklet_init(&dd->done_task, atmel_aes_done_task, (unsigned long)dd);

	crypto_init_queue(&atmel_aes.queue, ATMEL_AES_QUEUE_LENGTH);

	/* Get the base address */
	aes_res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!aes_res) {
		dev_err(dev, "no MEM resource info\n");
		err = -ENODEV;
		goto res_err;
	}
	dd->phys_base = aes_res->start;

	/* Get the IRQ */
	dd->irq = platform_get_irq(pdev,  0);
	if (dd->irq < 0) {
		dev_err(dev, "no IRQ resource info\n");
		err = dd->irq;
		goto res_err;
	}

	err = devm_request_irq(&pdev->dev, dd->irq, atmel_aes_irq,
			       IRQF_SHARED, "atmel-aes", dd);
	if (err) {
		dev_err(dev, "unable to request aes irq.\n");
		goto res_err;
	}

	/* Initializing the clock */
	dd->iclk = devm_clk_get(&pdev->dev, "aes_clk");
	if (IS_ERR(dd->iclk)) {
		dev_err(dev, "clock initialization failed.\n");
		err = PTR_ERR(dd->iclk);
		goto res_err;
	}

	dd->io_base = devm_ioremap_resource(&pdev->dev, aes_res);
	if (IS_ERR(dd->io_base)) {
		dev_err(dev, "can't ioremap\n");
		err = PTR_ERR(dd->io_base);
		goto res_err;
	}

	err = clk_prepare_enable(dd->iclk);
	if (err)
		goto res_err;

	err = atmel_aes_hw_version_init(dd);
	if (err)
		goto iclk_unprepare;

	atmel_aes_get_cap(dd);

#ifdef CONFIG_CRYPTO_DEV_ATMEL_AUTHENC
	if (dd->caps.has_authenc && !atmel_sha_authenc_is_ready()) {
		err = -EPROBE_DEFER;
		goto iclk_unprepare;
	}
#endif

	err = atmel_aes_buff_init(dd);
	if (err)
		goto err_aes_buff;

	err = atmel_aes_dma_init(dd, pdata);
	if (err)
		goto err_aes_dma;

	atmel_aes_dev_register(dd);

	err = atmel_aes_register_algs(dd);
	if (err)
		goto err_algs;

	dev_info(dev, "Atmel AES - Using %s, %s for DMA transfers\n",
			dma_chan_name(dd->src.chan),
			dma_chan_name(dd->dst.chan));

	return 0;

err_algs:
	atmel_aes_dev_register(NULL);

	atmel_aes_dma_cleanup(dd);
err_aes_dma:
	atmel_aes_buff_cleanup(dd);
err_aes_buff:
iclk_unprepare:
	clk_disable_unprepare(dd->iclk);
res_err:
	tasklet_kill(&dd->done_task);
aes_dd_err:
	if (err != -EPROBE_DEFER)
		dev_err(dev, "initialization failed.\n");

	return err;
}

static int atmel_aes_remove(struct platform_device *pdev)
{
	struct crypto_async_request *areq;
	struct atmel_aes_dev *dd = platform_get_drvdata(pdev);
	if (!dd)
		return -ENODEV;

	atmel_aes_dev_register(NULL);

	do {
		areq = crypto_dequeue_request(&atmel_aes.queue);
		if (areq && areq->complete)
			areq->complete(areq, -ENODEV);
	} while (areq);

	while (dd->flags & AES_FLAGS_BUSY)
		mdelay(1);

	atmel_aes_unregister_algs(dd);

	tasklet_kill(&dd->done_task);

	atmel_aes_dma_cleanup(dd);
	atmel_aes_buff_cleanup(dd);

	clk_disable_unprepare(dd->iclk);

	return 0;
}

#ifdef CONFIG_PM
static int atmel_aes_suspend(struct device *dev)
{
	struct atmel_aes_dev *dd = dev_get_drvdata(dev);

	clk_disable_unprepare(dd->iclk);

	return 0;
}

static int atmel_aes_resume(struct device *dev)
{
	struct atmel_aes_dev *dd = dev_get_drvdata(dev);

	clk_prepare_enable(dd->iclk);

	return 0;
}
#endif

static SIMPLE_DEV_PM_OPS(atmel_aes_pm_ops, atmel_aes_suspend, atmel_aes_resume);

static struct platform_driver atmel_aes_driver = {
	.probe		= atmel_aes_probe,
	.remove		= atmel_aes_remove,
	.driver		= {
		.name	= "atmel_aes",
		.of_match_table = of_match_ptr(atmel_aes_dt_ids),
		.pm	= &atmel_aes_pm_ops,
	},
};

static int __init atmel_aes_init(void)
{
	return platform_driver_register(&atmel_aes_driver);
}

static void __exit atmel_aes_exit(void)
{
	platform_driver_unregister(&atmel_aes_driver);
}

subsys_initcall(atmel_aes_init);
module_exit(atmel_aes_exit);

MODULE_DESCRIPTION("Atmel AES hw acceleration support.");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Nicolas Royer - Eukréa Electromatique");
