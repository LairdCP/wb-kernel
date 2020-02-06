// SPDX-License-Identifier: GPL-2.0
/*
 * Cryptographic API.
 *
 * Support for ATMEL DES/TDES HW acceleration.
 *
 * Copyright (c) 2012 Eukréa Electromatique - ATMEL
 * Author: Nicolas Royer <nicolas@eukrea.com>
 *
 * Some ideas are from omap-aes.c drivers.
 */


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/platform_device.h>

#include <linux/device.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/of_device.h>
#include <linux/crypto.h>
#include <crypto/scatterwalk.h>
#include <crypto/algapi.h>
#include <crypto/internal/des.h>
#include <crypto/internal/skcipher.h>
#include <linux/platform_data/crypto-atmel.h>
#include "atmel-tdes-regs.h"

#define ATMEL_TDES_PRIORITY	300

/* TDES flags  */
#define TDES_FLAGS_MODE_MASK		0x00ff
#define TDES_FLAGS_ENCRYPT	BIT(0)
#define TDES_FLAGS_CBC		BIT(1)
#define TDES_FLAGS_CFB		BIT(2)
#define TDES_FLAGS_CFB8		BIT(3)
#define TDES_FLAGS_CFB16	BIT(4)
#define TDES_FLAGS_CFB32	BIT(5)
#define TDES_FLAGS_CFB64	BIT(6)
#define TDES_FLAGS_OFB		BIT(7)

#define TDES_FLAGS_FAST		BIT(17)
#define TDES_FLAGS_BUSY		BIT(18)
#define TDES_FLAGS_DMA		BIT(19)

#define ATMEL_TDES_QUEUE_LENGTH	50

#define CFB8_BLOCK_SIZE		1
#define CFB16_BLOCK_SIZE	2
#define CFB32_BLOCK_SIZE	4

struct atmel_tdes_caps {
	bool	has_dma;
	bool	has_cfb_3keys;
};

struct atmel_tdes_ctx {
	unsigned long	flags;

	int		keylen;
	u32		key[3*DES_KEY_SIZE / sizeof(u32)];

	u16		block_size;
};

struct atmel_tdes_reqctx {
	unsigned long mode;
	u32		lastc[DES_BLOCK_SIZE / sizeof(u32)];
};

struct atmel_tdes_dma {
	struct dma_chan			*chan;
	struct dma_slave_config dma_conf;
};

struct atmel_tdes_dev {
	struct list_head	list;
	unsigned long		phys_base;
	void __iomem		*io_base;

	struct atmel_tdes_ctx	*ctx;
	struct device		*dev;
	struct clk		*iclk;
	int			irq;

	unsigned long		flags;

	struct tasklet_struct	done_task;

	struct skcipher_request	*req;
	size_t			total;

	struct scatterlist	*in_sg;
	unsigned int		nb_in_sg;
	size_t			in_offset;
	struct scatterlist	*out_sg;
	unsigned int		nb_out_sg;
	size_t			out_offset;

	size_t			buflen;
	size_t			dma_size;

	void			*buf_in;
	int			dma_in;
	dma_addr_t		dma_addr_in;
	struct atmel_tdes_dma	dma_lch_in;

	void			*buf_out;
	int			dma_out;
	dma_addr_t		dma_addr_out;
	struct atmel_tdes_dma	dma_lch_out;

	struct atmel_tdes_caps	caps;

	u32	hw_version;
};

struct atmel_tdes_drv {
	struct crypto_queue	queue;
	struct atmel_tdes_dev	*dd;
	spinlock_t		lock;
};

static struct atmel_tdes_drv atmel_tdes = {
	.lock = __SPIN_LOCK_UNLOCKED(atmel_tdes.lock),
};

static int atmel_tdes_sg_copy(struct scatterlist **sg, size_t *offset,
			void *buf, size_t buflen, size_t total, int out)
{
	size_t count, off = 0;

	while (buflen && total) {
		count = min((*sg)->length - *offset, total);
		count = min(count, buflen);

		if (!count)
			return off;

		scatterwalk_map_and_copy(buf + off, *sg, *offset, count, out);

		off += count;
		buflen -= count;
		*offset += count;
		total -= count;

		if (*offset == (*sg)->length) {
			*sg = sg_next(*sg);
			if (*sg)
				*offset = 0;
			else
				total = 0;
		}
	}

	return off;
}

static inline u32 atmel_tdes_read(struct atmel_tdes_dev *dd, u32 offset)
{
	return readl_relaxed(dd->io_base + offset);
}

static inline void atmel_tdes_write(struct atmel_tdes_dev *dd,
					u32 offset, u32 value)
{
	writel_relaxed(value, dd->io_base + offset);
}

static void atmel_tdes_write_n(struct atmel_tdes_dev *dd, u32 offset,
					u32 *value, int count)
{
	for (; count--; value++, offset += 4)
		atmel_tdes_write(dd, offset, *value);
}

static inline void atmel_tdes_hw_init(struct atmel_tdes_dev *dd)
{
	atmel_tdes_write(dd, TDES_CR, TDES_CR_SWRST);
}

static inline unsigned int atmel_tdes_get_version(struct atmel_tdes_dev *dd)
{
	return atmel_tdes_read(dd, TDES_HW_VERSION) & 0x00000fff;
}

static void atmel_tdes_hw_version_init(struct atmel_tdes_dev *dd)
{
	atmel_tdes_hw_init(dd);

	dd->hw_version = atmel_tdes_get_version(dd);

	dev_info(dd->dev, "version: 0x%x\n", dd->hw_version);
}

static void atmel_tdes_dma_callback(void *data)
{
	struct atmel_tdes_dev *dd = data;

	/* dma_lch_out - completed */
	tasklet_schedule(&dd->done_task);
}

static void atmel_tdes_write_ctrl(struct atmel_tdes_dev *dd)
{
	u32 valcr = 0, valmr = TDES_MR_SMOD_PDC;

	atmel_tdes_hw_init(dd);

	if (!dd->caps.has_dma)
		atmel_tdes_write(dd, TDES_PTCR,
			TDES_PTCR_TXTDIS | TDES_PTCR_RXTDIS);

	/* MR register must be set before IV registers */
	if (dd->ctx->keylen > (DES_KEY_SIZE << 1)) {
		valmr |= TDES_MR_KEYMOD_3KEY;
		valmr |= TDES_MR_TDESMOD_TDES;
	} else if (dd->ctx->keylen > DES_KEY_SIZE) {
		valmr |= TDES_MR_KEYMOD_2KEY;
		valmr |= TDES_MR_TDESMOD_TDES;
	} else {
		valmr |= TDES_MR_TDESMOD_DES;
	}

	if (dd->flags & TDES_FLAGS_CBC) {
		valmr |= TDES_MR_OPMOD_CBC;
	} else if (dd->flags & TDES_FLAGS_CFB) {
		valmr |= TDES_MR_OPMOD_CFB;

		if (dd->flags & TDES_FLAGS_CFB8)
			valmr |= TDES_MR_CFBS_8b;
		else if (dd->flags & TDES_FLAGS_CFB16)
			valmr |= TDES_MR_CFBS_16b;
		else if (dd->flags & TDES_FLAGS_CFB32)
			valmr |= TDES_MR_CFBS_32b;
		else if (dd->flags & TDES_FLAGS_CFB64)
			valmr |= TDES_MR_CFBS_64b;
	} else if (dd->flags & TDES_FLAGS_OFB) {
		valmr |= TDES_MR_OPMOD_OFB;
	}

	if ((dd->flags & TDES_FLAGS_ENCRYPT) || (dd->flags & TDES_FLAGS_OFB))
		valmr |= TDES_MR_CYPHER_ENC;

	atmel_tdes_write(dd, TDES_CR, valcr);
	atmel_tdes_write(dd, TDES_MR, valmr);

	atmel_tdes_write_n(dd, TDES_KEY1W1R, dd->ctx->key,
						dd->ctx->keylen >> 2);

	if ((dd->flags & (TDES_FLAGS_CBC | TDES_FLAGS_CFB | TDES_FLAGS_OFB)) &&
		dd->req->iv) {
		if ((unsigned long)dd->req->iv & 3) {
			u32 ivbuf[DES_KEY_SIZE / sizeof(u32)];
			memcpy(ivbuf, dd->req->iv, DES_KEY_SIZE);
			atmel_tdes_write_n(dd, TDES_IV1R, ivbuf,
				DES_KEY_SIZE / sizeof(u32));
		} else
			atmel_tdes_write_n(dd, TDES_IV1R, (u32*)dd->req->iv,
				DES_KEY_SIZE / sizeof(u32));
	}
}

static int atmel_tdes_crypt_pdc_stop(struct atmel_tdes_dev *dd)
{
	int err = 0;
	size_t count;

	atmel_tdes_write(dd, TDES_PTCR, TDES_PTCR_TXTDIS|TDES_PTCR_RXTDIS);

	if (dd->flags & TDES_FLAGS_FAST) {
		dma_unmap_sg(dd->dev, dd->out_sg, 1, DMA_FROM_DEVICE);
		dma_unmap_sg(dd->dev, dd->in_sg, 1, DMA_TO_DEVICE);
	} else {
		dma_sync_single_for_cpu(dd->dev, dd->dma_addr_out,
					   dd->dma_size, DMA_FROM_DEVICE);

		/* copy data */
		count = atmel_tdes_sg_copy(&dd->out_sg, &dd->out_offset,
				dd->buf_out, dd->buflen, dd->dma_size, 1);
		if (count != dd->dma_size) {
			err = -EINVAL;
			pr_err("not all data converted: %zu\n", count);
		}
	}

	return err;
}

static int atmel_tdes_buff_init(struct atmel_tdes_dev *dd)
{
	int err = -ENOMEM;

	dd->buf_in = (void *)__get_free_pages(GFP_KERNEL, 0);
	dd->buf_out = (void *)__get_free_pages(GFP_KERNEL, 0);
	dd->buflen = PAGE_SIZE;
	dd->buflen &= ~(DES_BLOCK_SIZE - 1);

	if (!dd->buf_in || !dd->buf_out) {
		dev_err(dd->dev, "unable to alloc pages.\n");
		goto err_alloc;
	}

	/* MAP here */
	dd->dma_addr_in = dma_map_single(dd->dev, dd->buf_in,
					dd->buflen, DMA_TO_DEVICE);
	if (dma_mapping_error(dd->dev, dd->dma_addr_in)) {
		dev_err(dd->dev, "dma %zd bytes error\n", dd->buflen);
		err = -EINVAL;
		goto err_map_in;
	}

	dd->dma_addr_out = dma_map_single(dd->dev, dd->buf_out,
					dd->buflen, DMA_FROM_DEVICE);
	if (dma_mapping_error(dd->dev, dd->dma_addr_out)) {
		dev_err(dd->dev, "dma %zd bytes error\n", dd->buflen);
		err = -EINVAL;
		goto err_map_out;
	}

	return 0;

err_map_out:
	dma_unmap_single(dd->dev, dd->dma_addr_in, dd->buflen,
		DMA_TO_DEVICE);
err_map_in:
err_alloc:
	free_page((unsigned long)dd->buf_out);
	free_page((unsigned long)dd->buf_in);
	if (err)
		pr_err("error: %d\n", err);
	return err;
}

static void atmel_tdes_buff_cleanup(struct atmel_tdes_dev *dd)
{
	dma_unmap_single(dd->dev, dd->dma_addr_out, dd->buflen,
			 DMA_FROM_DEVICE);
	dma_unmap_single(dd->dev, dd->dma_addr_in, dd->buflen,
		DMA_TO_DEVICE);
	free_page((unsigned long)dd->buf_out);
	free_page((unsigned long)dd->buf_in);
}

static int atmel_tdes_crypt_pdc(struct atmel_tdes_dev *dd,
	dma_addr_t dma_addr_in, dma_addr_t dma_addr_out, int length)
{
	int len32;

	dd->dma_size = length;

	if (!(dd->flags & TDES_FLAGS_FAST)) {
		dma_sync_single_for_device(dd->dev, dma_addr_in, length,
					   DMA_TO_DEVICE);
	}

	if ((dd->flags & TDES_FLAGS_CFB) && (dd->flags & TDES_FLAGS_CFB8))
		len32 = DIV_ROUND_UP(length, sizeof(u8));
	else if ((dd->flags & TDES_FLAGS_CFB) && (dd->flags & TDES_FLAGS_CFB16))
		len32 = DIV_ROUND_UP(length, sizeof(u16));
	else
		len32 = DIV_ROUND_UP(length, sizeof(u32));

	atmel_tdes_write(dd, TDES_PTCR, TDES_PTCR_TXTDIS|TDES_PTCR_RXTDIS);
	atmel_tdes_write(dd, TDES_TPR, dma_addr_in);
	atmel_tdes_write(dd, TDES_TCR, len32);
	atmel_tdes_write(dd, TDES_RPR, dma_addr_out);
	atmel_tdes_write(dd, TDES_RCR, len32);

	/* Enable Interrupt */
	atmel_tdes_write(dd, TDES_IER, TDES_INT_ENDRX);

	/* Start DMA transfer */
	atmel_tdes_write(dd, TDES_PTCR, TDES_PTCR_TXTEN | TDES_PTCR_RXTEN);

	return -EINPROGRESS;
}

static int atmel_tdes_crypt_dma(struct atmel_tdes_dev *dd,
	dma_addr_t dma_addr_in, dma_addr_t dma_addr_out, int length)
{
	struct scatterlist sg[2];
	struct dma_async_tx_descriptor	*in_desc, *out_desc;

	dd->dma_size = length;

	if (!(dd->flags & TDES_FLAGS_FAST)) {
		dma_sync_single_for_device(dd->dev, dma_addr_in, length,
					   DMA_TO_DEVICE);
	}

	if (dd->flags & TDES_FLAGS_CFB8) {
		dd->dma_lch_in.dma_conf.dst_addr_width =
			DMA_SLAVE_BUSWIDTH_1_BYTE;
		dd->dma_lch_out.dma_conf.src_addr_width =
			DMA_SLAVE_BUSWIDTH_1_BYTE;
	} else if (dd->flags & TDES_FLAGS_CFB16) {
		dd->dma_lch_in.dma_conf.dst_addr_width =
			DMA_SLAVE_BUSWIDTH_2_BYTES;
		dd->dma_lch_out.dma_conf.src_addr_width =
			DMA_SLAVE_BUSWIDTH_2_BYTES;
	} else {
		dd->dma_lch_in.dma_conf.dst_addr_width =
			DMA_SLAVE_BUSWIDTH_4_BYTES;
		dd->dma_lch_out.dma_conf.src_addr_width =
			DMA_SLAVE_BUSWIDTH_4_BYTES;
	}

	dmaengine_slave_config(dd->dma_lch_in.chan, &dd->dma_lch_in.dma_conf);
	dmaengine_slave_config(dd->dma_lch_out.chan, &dd->dma_lch_out.dma_conf);

	dd->flags |= TDES_FLAGS_DMA;

	sg_init_table(&sg[0], 1);
	sg_dma_address(&sg[0]) = dma_addr_in;
	sg_dma_len(&sg[0]) = length;

	sg_init_table(&sg[1], 1);
	sg_dma_address(&sg[1]) = dma_addr_out;
	sg_dma_len(&sg[1]) = length;

	in_desc = dmaengine_prep_slave_sg(dd->dma_lch_in.chan, &sg[0],
				1, DMA_MEM_TO_DEV,
				DMA_PREP_INTERRUPT  |  DMA_CTRL_ACK);
	if (!in_desc)
		return -EINVAL;

	out_desc = dmaengine_prep_slave_sg(dd->dma_lch_out.chan, &sg[1],
				1, DMA_DEV_TO_MEM,
				DMA_PREP_INTERRUPT | DMA_CTRL_ACK);
	if (!out_desc)
		return -EINVAL;

	out_desc->callback = atmel_tdes_dma_callback;
	out_desc->callback_param = dd;

	dmaengine_submit(out_desc);
	dma_async_issue_pending(dd->dma_lch_out.chan);

	in_desc->callback = NULL;
	in_desc->callback_param = NULL;

	dmaengine_submit(in_desc);
	dma_async_issue_pending(dd->dma_lch_in.chan);

	return -EINPROGRESS;
}

static int atmel_tdes_crypt_start(struct atmel_tdes_dev *dd)
{
	int err, fast = 0, in, out;
	size_t count;
	dma_addr_t addr_in, addr_out;

	if ((!dd->in_offset) && (!dd->out_offset)) {
		/* check for alignment */
		in = IS_ALIGNED((u32)dd->in_sg->offset, sizeof(u32)) &&
			IS_ALIGNED(dd->in_sg->length, dd->ctx->block_size);
		out = IS_ALIGNED((u32)dd->out_sg->offset, sizeof(u32)) &&
			IS_ALIGNED(dd->out_sg->length, dd->ctx->block_size);
		fast = in && out;

		if (sg_dma_len(dd->in_sg) != sg_dma_len(dd->out_sg))
			fast = 0;
	}

	if (fast)  {
		count = min_t(size_t, dd->total, sg_dma_len(dd->in_sg));
		count = min_t(size_t, count, sg_dma_len(dd->out_sg));

		err = dma_map_sg(dd->dev, dd->in_sg, 1, DMA_TO_DEVICE);
		if (!err) {
			dev_err(dd->dev, "dma_map_sg() error\n");
			return -EINVAL;
		}

		err = dma_map_sg(dd->dev, dd->out_sg, 1, DMA_FROM_DEVICE);
		if (!err) {
			dev_err(dd->dev, "dma_map_sg() error\n");
			dma_unmap_sg(dd->dev, dd->in_sg, 1, DMA_TO_DEVICE);
			return -EINVAL;
		}

		addr_in = sg_dma_address(dd->in_sg);
		addr_out = sg_dma_address(dd->out_sg);

		dd->flags |= TDES_FLAGS_FAST;
		dd->total -= count;
	} else {
		/* use cache buffers */
		count = atmel_tdes_sg_copy(&dd->in_sg, &dd->in_offset,
				dd->buf_in, dd->buflen, dd->total, 0);

		addr_in = dd->dma_addr_in;
		addr_out = dd->dma_addr_out;

		dd->flags &= ~TDES_FLAGS_FAST;
		dd->total -= count;
	}

	if (dd->flags & (TDES_FLAGS_CBC | TDES_FLAGS_CFB | TDES_FLAGS_OFB)) {
		struct skcipher_request *req = dd->req;

		if (!dd->total && !(dd->flags & TDES_FLAGS_ENCRYPT) &&
			(req->src == req->dst)) {
			struct atmel_tdes_reqctx *rctx =
				skcipher_request_ctx(req);

			scatterwalk_map_and_copy(rctx->lastc, req->src,
				req->cryptlen - DES_BLOCK_SIZE,
				DES_BLOCK_SIZE, 0);
		}
	}

	if (dd->caps.has_dma)
		err = atmel_tdes_crypt_dma(dd, addr_in, addr_out, count);
	else
		err = atmel_tdes_crypt_pdc(dd, addr_in, addr_out, count);

	if (err != -EINPROGRESS && (dd->flags & TDES_FLAGS_FAST)) {
		dma_unmap_sg(dd->dev, dd->in_sg, 1, DMA_TO_DEVICE);
		dma_unmap_sg(dd->dev, dd->out_sg, 1, DMA_FROM_DEVICE);
	}

	return err;
}

static void atmel_tdes_finish_req(struct atmel_tdes_dev *dd, int err)
{
	struct skcipher_request *req = dd->req;

	if ((dd->flags & (TDES_FLAGS_CBC | TDES_FLAGS_CFB | TDES_FLAGS_OFB)) &&
		req->iv) {
		if (dd->flags & TDES_FLAGS_ENCRYPT) {
			scatterwalk_map_and_copy(req->iv, req->dst,
				req->cryptlen - DES_BLOCK_SIZE,
				DES_BLOCK_SIZE, 0);
		} else if (req->src == req->dst) {
			struct atmel_tdes_reqctx *rctx = skcipher_request_ctx(req);
			memcpy(req->iv, rctx->lastc, DES_BLOCK_SIZE);
		} else {
			scatterwalk_map_and_copy(req->iv, req->src,
				req->cryptlen - DES_BLOCK_SIZE,
				DES_BLOCK_SIZE, 0);
		}
	}

	req->base.complete(&req->base, err);
}

static int atmel_tdes_handle_queue(struct skcipher_request *new_areq)
{
	struct atmel_tdes_dev *dd;
	struct skcipher_request *areq = NULL;
	struct crypto_async_request *req, *backlog = NULL;
	struct atmel_tdes_ctx *ctx;
	struct atmel_tdes_reqctx *rctx;
	int ret = 0;

retry:
	spin_lock_bh(&atmel_tdes.lock);

	dd = atmel_tdes.dd;
	if (!dd)
		ret = -ENODEV;

	/* Add new request to queue if we are busy, assumption here that device
	 * will always stay busy while queue is not empty */
	else if (new_areq) {
		if (dd->flags & TDES_FLAGS_BUSY) {
			ret = crypto_enqueue_request(&atmel_tdes.queue, &new_areq->base);
		} else {
			dd->flags |= TDES_FLAGS_BUSY;
			areq = new_areq;
		}
	} else {
		backlog = crypto_get_backlog(&atmel_tdes.queue);
		req = crypto_dequeue_request(&atmel_tdes.queue);

		if (!req)
			dd->flags &= ~TDES_FLAGS_BUSY;
		else
			areq = skcipher_request_cast(req);
	}

	spin_unlock_bh(&atmel_tdes.lock);

	if (areq) {
		if (backlog)
			backlog->complete(backlog, -EINPROGRESS);

		/* assign new request to device */
		dd->req = areq;
		dd->total = areq->cryptlen;
		dd->in_offset = 0;
		dd->in_sg = areq->src;
		dd->out_offset = 0;
		dd->out_sg = areq->dst;

		rctx = skcipher_request_ctx(areq);
		ctx = crypto_skcipher_ctx(crypto_skcipher_reqtfm(areq));
		dd->flags &= TDES_FLAGS_BUSY;
		dd->flags |= (rctx->mode & TDES_FLAGS_MODE_MASK);
		dd->ctx = ctx;

		atmel_tdes_write_ctrl(dd);

		ret = atmel_tdes_crypt_start(dd);
		if (ret != -EINPROGRESS && !new_areq) {
			areq->base.complete(&areq->base, ret);
			goto retry;
		}
	} else if (!new_areq)
		atmel_tdes_hw_init(dd);

	return ret;
}

static int atmel_tdes_crypt_dma_stop(struct atmel_tdes_dev *dd)
{
	int err = -EINVAL;
	size_t count;


	if (dd->flags & TDES_FLAGS_DMA) {
		err = 0;

		if  (dd->flags & TDES_FLAGS_FAST) {
			dma_unmap_sg(dd->dev, dd->in_sg, 1, DMA_TO_DEVICE);
			dma_unmap_sg(dd->dev, dd->out_sg, 1, DMA_FROM_DEVICE);
		} else {
			dma_sync_single_for_cpu(dd->dev, dd->dma_addr_out,
				dd->dma_size, DMA_FROM_DEVICE);

			/* copy data */
			count = atmel_tdes_sg_copy(&dd->out_sg, &dd->out_offset,
				dd->buf_out, dd->buflen, dd->dma_size, 1);
			if (count != dd->dma_size) {
				err = -EINVAL;
				pr_err("not all data converted: %zu\n", count);
			}
		}
	}
	return err;
}

static int atmel_tdes_crypt(struct skcipher_request *req, unsigned long mode)
{
	struct atmel_tdes_ctx *ctx = crypto_skcipher_ctx(
			crypto_skcipher_reqtfm(req));
	struct atmel_tdes_reqctx *rctx = skcipher_request_ctx(req);

	if (mode & TDES_FLAGS_CFB8) {
		if (!IS_ALIGNED(req->cryptlen, CFB8_BLOCK_SIZE)) {
			pr_err("request size is not exact amount of CFB8 blocks\n");
			return -EINVAL;
		}
		ctx->block_size = CFB8_BLOCK_SIZE;
	} else if (mode & TDES_FLAGS_CFB16) {
		if (!IS_ALIGNED(req->cryptlen, CFB16_BLOCK_SIZE)) {
			pr_err("request size is not exact amount of CFB16 blocks\n");
			return -EINVAL;
		}
		ctx->block_size = CFB16_BLOCK_SIZE;
	} else if (mode & TDES_FLAGS_CFB32) {
		if (!IS_ALIGNED(req->cryptlen, CFB32_BLOCK_SIZE)) {
			pr_err("request size is not exact amount of CFB32 blocks\n");
			return -EINVAL;
		}
		ctx->block_size = CFB32_BLOCK_SIZE;
	} else {
		if (!IS_ALIGNED(req->cryptlen, DES_BLOCK_SIZE)) {
			pr_err("request size is not exact amount of DES blocks\n");
			return -EINVAL;
		}
		ctx->block_size = DES_BLOCK_SIZE;
	}

	rctx->mode = mode;

	return atmel_tdes_handle_queue(req);
}

static bool atmel_tdes_filter(struct dma_chan *chan, void *slave)
{
	struct at_dma_slave	*sl = slave;

	if (sl && sl->dma_dev == chan->device->dev) {
		chan->private = sl;
		return true;
	} else {
		return false;
	}
}

static int atmel_tdes_dma_init(struct atmel_tdes_dev *dd,
			struct crypto_platform_data *pdata)
{
	dma_cap_mask_t mask;

	dma_cap_zero(mask);
	dma_cap_set(DMA_SLAVE, mask);

	/* Try to grab 2 DMA channels */
	dd->dma_lch_in.chan = dma_request_slave_channel_compat(mask,
		atmel_tdes_filter, &pdata->dma_slave->rxdata, dd->dev, "tx");
	if (!dd->dma_lch_in.chan)
		goto err_dma_in;

	dd->dma_lch_in.dma_conf.direction = DMA_MEM_TO_DEV;
	dd->dma_lch_in.dma_conf.dst_addr = dd->phys_base +
		TDES_IDATA1R;
	dd->dma_lch_in.dma_conf.src_maxburst = 1;
	dd->dma_lch_in.dma_conf.src_addr_width =
		DMA_SLAVE_BUSWIDTH_4_BYTES;
	dd->dma_lch_in.dma_conf.dst_maxburst = 1;
	dd->dma_lch_in.dma_conf.dst_addr_width =
		DMA_SLAVE_BUSWIDTH_4_BYTES;
	dd->dma_lch_in.dma_conf.device_fc = false;

	dd->dma_lch_out.chan = dma_request_slave_channel_compat(mask,
		atmel_tdes_filter, &pdata->dma_slave->txdata, dd->dev, "rx");
	if (!dd->dma_lch_out.chan)
		goto err_dma_out;

	dd->dma_lch_out.dma_conf.direction = DMA_DEV_TO_MEM;
	dd->dma_lch_out.dma_conf.src_addr = dd->phys_base +
		TDES_ODATA1R;
	dd->dma_lch_out.dma_conf.src_maxburst = 1;
	dd->dma_lch_out.dma_conf.src_addr_width =
		DMA_SLAVE_BUSWIDTH_4_BYTES;
	dd->dma_lch_out.dma_conf.dst_maxburst = 1;
	dd->dma_lch_out.dma_conf.dst_addr_width =
		DMA_SLAVE_BUSWIDTH_4_BYTES;
	dd->dma_lch_out.dma_conf.device_fc = false;

	return 0;

err_dma_out:
	dma_release_channel(dd->dma_lch_in.chan);
err_dma_in:
	dev_warn(dd->dev, "no DMA channel available\n");
	return -ENODEV;
}

static void atmel_tdes_dma_cleanup(struct atmel_tdes_dev *dd)
{
	dma_release_channel(dd->dma_lch_in.chan);
	dma_release_channel(dd->dma_lch_out.chan);
}

static int atmel_des_setkey(struct crypto_skcipher *tfm, const u8 *key,
			   unsigned int keylen)
{
	struct atmel_tdes_ctx *ctx = crypto_skcipher_ctx(tfm);
	int err;

	err = verify_skcipher_des_key(tfm, key);
	if (err)
		return err;

	memcpy(ctx->key, key, keylen);
	ctx->keylen = keylen;

	return 0;
}

static int atmel_tdes_setkey(struct crypto_skcipher *tfm, const u8 *key,
			   unsigned int keylen)
{
	struct atmel_tdes_ctx *ctx = crypto_skcipher_ctx(tfm);
	int err;

	err = verify_skcipher_des3_key(tfm, key);
	if (err)
		return err;

	memcpy(ctx->key, key, keylen);
	ctx->keylen = keylen;

	return 0;
}

static int atmel_tdes_ecb_encrypt(struct skcipher_request *req)
{
	return atmel_tdes_crypt(req, TDES_FLAGS_ENCRYPT);
}

static int atmel_tdes_ecb_decrypt(struct skcipher_request *req)
{
	return atmel_tdes_crypt(req, 0);
}

static int atmel_tdes_cbc_encrypt(struct skcipher_request *req)
{
	return atmel_tdes_crypt(req, TDES_FLAGS_ENCRYPT | TDES_FLAGS_CBC);
}

static int atmel_tdes_cbc_decrypt(struct skcipher_request *req)
{
	return atmel_tdes_crypt(req, TDES_FLAGS_CBC);
}
static int atmel_tdes_cfb_encrypt(struct skcipher_request *req)
{
	return atmel_tdes_crypt(req, TDES_FLAGS_ENCRYPT | TDES_FLAGS_CFB);
}

static int atmel_tdes_cfb_decrypt(struct skcipher_request *req)
{
	return atmel_tdes_crypt(req, TDES_FLAGS_CFB);
}

static int atmel_tdes_cfb8_encrypt(struct skcipher_request *req)
{
	return atmel_tdes_crypt(req, TDES_FLAGS_ENCRYPT | TDES_FLAGS_CFB |
						TDES_FLAGS_CFB8);
}

static int atmel_tdes_cfb8_decrypt(struct skcipher_request *req)
{
	return atmel_tdes_crypt(req, TDES_FLAGS_CFB | TDES_FLAGS_CFB8);
}

static int atmel_tdes_cfb16_encrypt(struct skcipher_request *req)
{
	return atmel_tdes_crypt(req, TDES_FLAGS_ENCRYPT | TDES_FLAGS_CFB |
						TDES_FLAGS_CFB16);
}

static int atmel_tdes_cfb16_decrypt(struct skcipher_request *req)
{
	return atmel_tdes_crypt(req, TDES_FLAGS_CFB | TDES_FLAGS_CFB16);
}

static int atmel_tdes_cfb32_encrypt(struct skcipher_request *req)
{
	return atmel_tdes_crypt(req, TDES_FLAGS_ENCRYPT | TDES_FLAGS_CFB |
						TDES_FLAGS_CFB32);
}

static int atmel_tdes_cfb32_decrypt(struct skcipher_request *req)
{
	return atmel_tdes_crypt(req, TDES_FLAGS_CFB | TDES_FLAGS_CFB32);
}

static int atmel_tdes_ofb_encrypt(struct skcipher_request *req)
{
	return atmel_tdes_crypt(req, TDES_FLAGS_ENCRYPT | TDES_FLAGS_OFB);
}

static int atmel_tdes_ofb_decrypt(struct skcipher_request *req)
{
	return atmel_tdes_crypt(req, TDES_FLAGS_OFB);
}

static int atmel_tdes_cra_init(struct crypto_tfm *tfm)
{
	crypto_skcipher_set_reqsize(__crypto_skcipher_cast(tfm),
		sizeof(struct atmel_tdes_reqctx));

	return 0;
}

static struct skcipher_alg tdes_algs[] = {
{
	.min_keysize	= DES_KEY_SIZE,
	.max_keysize	= DES_KEY_SIZE,
	.setkey		= atmel_des_setkey,
	.encrypt	= atmel_tdes_ecb_encrypt,
	.decrypt	= atmel_tdes_ecb_decrypt,
	.base = {
		.cra_name		= "ecb(des)",
		.cra_driver_name	= "atmel-ecb-des",
		.cra_priority		= ATMEL_TDES_PRIORITY,
		.cra_flags		= CRYPTO_ALG_KERN_DRIVER_ONLY | CRYPTO_ALG_ASYNC,
		.cra_blocksize		= DES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_tdes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_tdes_cra_init,
	}
},
{
	.min_keysize	= DES_KEY_SIZE,
	.max_keysize	= DES_KEY_SIZE,
	.ivsize		= DES_BLOCK_SIZE,
	.setkey		= atmel_des_setkey,
	.encrypt	= atmel_tdes_cbc_encrypt,
	.decrypt	= atmel_tdes_cbc_decrypt,
	.base = {
		.cra_name		= "cbc(des)",
		.cra_driver_name	= "atmel-cbc-des",
		.cra_priority		= ATMEL_TDES_PRIORITY,
		.cra_flags		= CRYPTO_ALG_KERN_DRIVER_ONLY | CRYPTO_ALG_ASYNC,
		.cra_blocksize		= DES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_tdes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_tdes_cra_init,
	}
},
{
	.min_keysize	= DES_KEY_SIZE,
	.max_keysize	= DES_KEY_SIZE,
	.ivsize		= DES_BLOCK_SIZE,
	.setkey		= atmel_des_setkey,
	.encrypt	= atmel_tdes_cfb_encrypt,
	.decrypt	= atmel_tdes_cfb_decrypt,
	.base = {
		.cra_name		= "cfb(des)",
		.cra_driver_name	= "atmel-cfb-des",
		.cra_priority		= ATMEL_TDES_PRIORITY,
		.cra_flags		= CRYPTO_ALG_KERN_DRIVER_ONLY | CRYPTO_ALG_ASYNC,
		.cra_blocksize		= DES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_tdes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_tdes_cra_init,
	}
},
{
	.min_keysize	= DES_KEY_SIZE,
	.max_keysize	= DES_KEY_SIZE,
	.ivsize		= DES_BLOCK_SIZE,
	.setkey		= atmel_des_setkey,
	.encrypt	= atmel_tdes_cfb8_encrypt,
	.decrypt	= atmel_tdes_cfb8_decrypt,
	.base = {
		.cra_name		= "cfb8(des)",
		.cra_driver_name	= "atmel-cfb8-des",
		.cra_priority		= ATMEL_TDES_PRIORITY,
		.cra_flags		= CRYPTO_ALG_KERN_DRIVER_ONLY | CRYPTO_ALG_ASYNC,
		.cra_blocksize		= CFB8_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_tdes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_tdes_cra_init,
	}
},
{
	.min_keysize	= DES_KEY_SIZE,
	.max_keysize	= DES_KEY_SIZE,
	.ivsize		= DES_BLOCK_SIZE,
	.setkey		= atmel_des_setkey,
	.encrypt	= atmel_tdes_cfb16_encrypt,
	.decrypt	= atmel_tdes_cfb16_decrypt,
	.base = {
		.cra_name		= "cfb16(des)",
		.cra_driver_name	= "atmel-cfb16-des",
		.cra_priority		= ATMEL_TDES_PRIORITY,
		.cra_flags		= CRYPTO_ALG_KERN_DRIVER_ONLY | CRYPTO_ALG_ASYNC,
		.cra_blocksize		= CFB16_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_tdes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_tdes_cra_init,
	}
},
{
	.min_keysize	= DES_KEY_SIZE,
	.max_keysize	= DES_KEY_SIZE,
	.ivsize		= DES_BLOCK_SIZE,
	.setkey		= atmel_des_setkey,
	.encrypt	= atmel_tdes_cfb32_encrypt,
	.decrypt	= atmel_tdes_cfb32_decrypt,
	.base = {
		.cra_name		= "cfb32(des)",
		.cra_driver_name	= "atmel-cfb32-des",
		.cra_priority		= ATMEL_TDES_PRIORITY,
		.cra_flags		= CRYPTO_ALG_KERN_DRIVER_ONLY | CRYPTO_ALG_ASYNC,
		.cra_blocksize		= CFB32_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_tdes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_tdes_cra_init,
	}
},
{
	.min_keysize	= DES_KEY_SIZE,
	.max_keysize	= DES_KEY_SIZE,
	.ivsize		= DES_BLOCK_SIZE,
	.setkey		= atmel_des_setkey,
	.encrypt	= atmel_tdes_ofb_encrypt,
	.decrypt	= atmel_tdes_ofb_decrypt,
	.base = {
		.cra_name		= "ofb(des)",
		.cra_driver_name	= "atmel-ofb-des",
		.cra_priority		= ATMEL_TDES_PRIORITY,
		.cra_flags		= CRYPTO_ALG_KERN_DRIVER_ONLY | CRYPTO_ALG_ASYNC,
		.cra_blocksize		= DES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_tdes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_tdes_cra_init,
	}
},
{
	.min_keysize	= 2*DES_KEY_SIZE,
	.max_keysize	= 3*DES_KEY_SIZE,
	.setkey		= atmel_tdes_setkey,
	.encrypt	= atmel_tdes_ecb_encrypt,
	.decrypt	= atmel_tdes_ecb_decrypt,
	.base = {
		.cra_name		= "ecb(des3_ede)",
		.cra_driver_name	= "atmel-ecb-tdes",
		.cra_priority		= ATMEL_TDES_PRIORITY,
		.cra_flags		= CRYPTO_ALG_KERN_DRIVER_ONLY | CRYPTO_ALG_ASYNC,
		.cra_blocksize		= DES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_tdes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_tdes_cra_init,
	}
},
{
	.min_keysize	= 2*DES_KEY_SIZE,
	.max_keysize	= 3*DES_KEY_SIZE,
	.ivsize		= DES_BLOCK_SIZE,
	.setkey		= atmel_tdes_setkey,
	.encrypt	= atmel_tdes_cbc_encrypt,
	.decrypt	= atmel_tdes_cbc_decrypt,
	.base = {
		.cra_name		= "cbc(des3_ede)",
		.cra_driver_name	= "atmel-cbc-tdes",
		.cra_priority		= ATMEL_TDES_PRIORITY,
		.cra_flags		= CRYPTO_ALG_KERN_DRIVER_ONLY | CRYPTO_ALG_ASYNC,
		.cra_blocksize		= DES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_tdes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_tdes_cra_init,
	}
},
{
	.min_keysize	= 2*DES_KEY_SIZE,
	.max_keysize	= 2*DES_KEY_SIZE,
	.ivsize		= DES_BLOCK_SIZE,
	.setkey		= atmel_tdes_setkey,
	.encrypt	= atmel_tdes_cfb_encrypt,
	.decrypt	= atmel_tdes_cfb_decrypt,
	.base = {
		.cra_name		= "cfb(des3_ede)",
		.cra_driver_name	= "atmel-cfb-tdes",
		.cra_priority		= ATMEL_TDES_PRIORITY,
		.cra_flags		= CRYPTO_ALG_KERN_DRIVER_ONLY | CRYPTO_ALG_ASYNC,
		.cra_blocksize		= DES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_tdes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_tdes_cra_init,
	}
},
{
	.min_keysize	= 2*DES_KEY_SIZE,
	.max_keysize	= 2*DES_KEY_SIZE,
	.ivsize		= DES_BLOCK_SIZE,
	.setkey		= atmel_tdes_setkey,
	.encrypt	= atmel_tdes_cfb8_encrypt,
	.decrypt	= atmel_tdes_cfb8_decrypt,
	.base = {
		.cra_name		= "cfb8(des3_ede)",
		.cra_driver_name	= "atmel-cfb8-tdes",
		.cra_priority		= ATMEL_TDES_PRIORITY,
		.cra_flags		= CRYPTO_ALG_KERN_DRIVER_ONLY | CRYPTO_ALG_ASYNC,
		.cra_blocksize		= CFB8_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_tdes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_tdes_cra_init,
	}
},
{
	.min_keysize	= 2*DES_KEY_SIZE,
	.max_keysize	= 2*DES_KEY_SIZE,
	.ivsize		= DES_BLOCK_SIZE,
	.setkey		= atmel_tdes_setkey,
	.encrypt	= atmel_tdes_cfb16_encrypt,
	.decrypt	= atmel_tdes_cfb16_decrypt,
	.base = {
		.cra_name		= "cfb16(des3_ede)",
		.cra_driver_name	= "atmel-cfb16-tdes",
		.cra_priority		= ATMEL_TDES_PRIORITY,
		.cra_flags		= CRYPTO_ALG_KERN_DRIVER_ONLY | CRYPTO_ALG_ASYNC,
		.cra_blocksize		= CFB16_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_tdes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_tdes_cra_init,
	}
},
{
	.min_keysize	= 2*DES_KEY_SIZE,
	.max_keysize	= 2*DES_KEY_SIZE,
	.ivsize		= DES_BLOCK_SIZE,
	.setkey		= atmel_tdes_setkey,
	.encrypt	= atmel_tdes_cfb32_encrypt,
	.decrypt	= atmel_tdes_cfb32_decrypt,
	.base = {
		.cra_name		= "cfb32(des3_ede)",
		.cra_driver_name	= "atmel-cfb32-tdes",
		.cra_priority		= ATMEL_TDES_PRIORITY,
		.cra_flags		= CRYPTO_ALG_KERN_DRIVER_ONLY | CRYPTO_ALG_ASYNC,
		.cra_blocksize		= CFB32_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_tdes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_tdes_cra_init,
	}
},
{
	.min_keysize	= 2*DES_KEY_SIZE,
	.max_keysize	= 3*DES_KEY_SIZE,
	.ivsize		= DES_BLOCK_SIZE,
	.setkey		= atmel_tdes_setkey,
	.encrypt	= atmel_tdes_ofb_encrypt,
	.decrypt	= atmel_tdes_ofb_decrypt,
	.base = {
		.cra_name		= "ofb(des3_ede)",
		.cra_driver_name	= "atmel-ofb-tdes",
		.cra_priority		= ATMEL_TDES_PRIORITY,
		.cra_flags		= CRYPTO_ALG_KERN_DRIVER_ONLY | CRYPTO_ALG_ASYNC,
		.cra_blocksize		= DES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct atmel_tdes_ctx),
		.cra_alignmask		= 0,
		.cra_module		= THIS_MODULE,
		.cra_init		= atmel_tdes_cra_init,
	}
},
};

static void atmel_tdes_done_task(unsigned long data)
{
	struct atmel_tdes_dev *dd = (struct atmel_tdes_dev *) data;
	int err;

	if (!(dd->flags & TDES_FLAGS_DMA))
		err = atmel_tdes_crypt_pdc_stop(dd);
	else
		err = atmel_tdes_crypt_dma_stop(dd);

	if (err || !dd->total)
		goto failed;

	if (dd->flags & TDES_FLAGS_FAST) {
		dd->in_sg = sg_next(dd->in_sg);
		dd->out_sg = sg_next(dd->out_sg);

		if (!dd->in_sg || !dd->out_sg) {
			err = -EINVAL;
			goto failed;
		}
	}

	err = atmel_tdes_crypt_start(dd);
	if (err == -EINPROGRESS)
		return; /* DMA started. Not finishing. */

failed:
	atmel_tdes_finish_req(dd, err);
	atmel_tdes_handle_queue(NULL);
}

static irqreturn_t atmel_tdes_irq(int irq, void *dev_id)
{
	struct atmel_tdes_dev *tdes_dd = dev_id;
	u32 reg;

	reg = atmel_tdes_read(tdes_dd, TDES_ISR);
	if (reg & atmel_tdes_read(tdes_dd, TDES_IMR)) {
		atmel_tdes_write(tdes_dd, TDES_IDR, reg);
		if (TDES_FLAGS_BUSY & tdes_dd->flags)
			tasklet_schedule(&tdes_dd->done_task);
		else
			dev_warn(tdes_dd->dev, "TDES interrupt when no active requests.\n");
		return IRQ_HANDLED;
	}

	return IRQ_NONE;
}

static inline void atmel_tdes_unregister_algs(struct atmel_tdes_dev *dd)
{
	crypto_unregister_skciphers(tdes_algs, ARRAY_SIZE(tdes_algs));
}

static inline int atmel_tdes_register_algs(struct atmel_tdes_dev *dd)
{
	return crypto_register_skciphers(tdes_algs, ARRAY_SIZE(tdes_algs));
}

static void atmel_tdes_get_cap(struct atmel_tdes_dev *dd)
{

	dd->caps.has_dma = 0;
	dd->caps.has_cfb_3keys = 0;

	/* keep only major version number */
	switch (dd->hw_version & 0xf00) {
	case 0x700:
		dd->caps.has_dma = 1;
		dd->caps.has_cfb_3keys = 1;
		break;
	case 0x600:
		break;
	default:
		dev_warn(dd->dev,
				"Unmanaged tdes version, set minimum capabilities\n");
		break;
	}
}

#if defined(CONFIG_OF)
static const struct of_device_id atmel_tdes_dt_ids[] = {
	{ .compatible = "atmel,at91sam9g46-tdes" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, atmel_tdes_dt_ids);

static struct crypto_platform_data *atmel_tdes_of_init(struct platform_device *pdev)
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
	if (!pdata->dma_slave)
		return ERR_PTR(-ENOMEM);

	return pdata;
}
#else /* CONFIG_OF */
static inline struct crypto_platform_data *atmel_tdes_of_init(struct platform_device *pdev)
{
	return ERR_PTR(-EINVAL);
}
#endif

static void atmel_tdes_dev_register(struct atmel_tdes_dev *dd)
{
	spin_lock_bh(&atmel_tdes.lock);
	atmel_tdes.dd = dd;
	spin_unlock_bh(&atmel_tdes.lock);
}

static int atmel_tdes_probe(struct platform_device *pdev)
{
	struct atmel_tdes_dev *tdes_dd;
	struct crypto_platform_data	*pdata;
	struct device *dev = &pdev->dev;
	struct resource *tdes_res;
	int err;

	tdes_dd = devm_kzalloc(&pdev->dev, sizeof(*tdes_dd), GFP_KERNEL);
	if (tdes_dd == NULL) {
		err = -ENOMEM;
		goto tdes_dd_err;
	}

	tdes_dd->dev = dev;

	platform_set_drvdata(pdev, tdes_dd);

	tasklet_init(&tdes_dd->done_task, atmel_tdes_done_task,
					(unsigned long)tdes_dd);

	crypto_init_queue(&atmel_tdes.queue, ATMEL_TDES_QUEUE_LENGTH);

	/* Get the base address */
	tdes_res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!tdes_res) {
		dev_err(dev, "no MEM resource info\n");
		err = -ENODEV;
		goto res_err;
	}
	tdes_dd->phys_base = tdes_res->start;

	/* Get the IRQ */
	tdes_dd->irq = platform_get_irq(pdev,  0);
	if (tdes_dd->irq < 0) {
		dev_err(dev, "no IRQ resource info\n");
		err = tdes_dd->irq;
		goto res_err;
	}

	err = devm_request_irq(&pdev->dev, tdes_dd->irq, atmel_tdes_irq,
			       IRQF_SHARED, "atmel-tdes", tdes_dd);
	if (err) {
		dev_err(dev, "unable to request tdes irq.\n");
		goto res_err;
	}

	/* Initializing the clock */
	tdes_dd->iclk = devm_clk_get(&pdev->dev, "tdes_clk");
	if (IS_ERR(tdes_dd->iclk)) {
		dev_err(dev, "clock initialization failed.\n");
		err = PTR_ERR(tdes_dd->iclk);
		goto res_err;
	}

	err = clk_prepare_enable(tdes_dd->iclk);
	if (err)
		goto res_err;

	tdes_dd->io_base = devm_ioremap_resource(&pdev->dev, tdes_res);
	if (IS_ERR(tdes_dd->io_base)) {
		dev_err(dev, "can't ioremap\n");
		err = PTR_ERR(tdes_dd->io_base);
		goto res_err;
	}

	atmel_tdes_hw_version_init(tdes_dd);

	atmel_tdes_get_cap(tdes_dd);

	err = atmel_tdes_buff_init(tdes_dd);
	if (err)
		goto err_tdes_buff;

	if (tdes_dd->caps.has_dma) {
		pdata = pdev->dev.platform_data;
		if (!pdata) {
			pdata = atmel_tdes_of_init(pdev);
			if (IS_ERR(pdata)) {
				dev_err(&pdev->dev, "platform data not available\n");
				err = PTR_ERR(pdata);
				goto err_pdata;
			}
		}
		if (!pdata->dma_slave) {
			err = -ENXIO;
			goto err_pdata;
		}
		err = atmel_tdes_dma_init(tdes_dd, pdata);
		if (err)
			goto err_tdes_dma;

		dev_info(dev, "using %s, %s for DMA transfers\n",
				dma_chan_name(tdes_dd->dma_lch_in.chan),
				dma_chan_name(tdes_dd->dma_lch_out.chan));
	}

	atmel_tdes_dev_register(tdes_dd);

	err = atmel_tdes_register_algs(tdes_dd);
	if (err)
		goto err_algs;

	dev_info(dev, "Atmel DES/TDES\n");

	return 0;

err_algs:
	atmel_tdes_dev_register(NULL);

	if (tdes_dd->caps.has_dma)
		atmel_tdes_dma_cleanup(tdes_dd);
err_tdes_dma:
err_pdata:
	atmel_tdes_buff_cleanup(tdes_dd);
err_tdes_buff:
res_err:
	tasklet_kill(&tdes_dd->done_task);
tdes_dd_err:
	dev_err(dev, "initialization failed.\n");

	return err;
}

static int atmel_tdes_remove(struct platform_device *pdev)
{
	struct atmel_tdes_dev *tdes_dd;

	tdes_dd = platform_get_drvdata(pdev);
	if (!tdes_dd)
		return -ENODEV;

	atmel_tdes_dev_register(tdes_dd);

	atmel_tdes_unregister_algs(tdes_dd);

	tasklet_kill(&tdes_dd->done_task);

	if (tdes_dd->caps.has_dma)
		atmel_tdes_dma_cleanup(tdes_dd);

	clk_disable_unprepare(tdes_dd->iclk);

	atmel_tdes_buff_cleanup(tdes_dd);

	return 0;
}

#ifdef CONFIG_PM
static int atmel_tdes_suspend(struct device *dev)
{
	struct atmel_tdes_dev *dd = dev_get_drvdata(dev);

	clk_disable_unprepare(dd->iclk);

	return 0;
}

static int atmel_tdes_resume(struct device *dev)
{
	struct atmel_tdes_dev *dd = dev_get_drvdata(dev);

	clk_prepare_enable(dd->iclk);

	return 0;
}
#endif

static SIMPLE_DEV_PM_OPS(atmel_tdes_pm_ops, atmel_tdes_suspend,
	atmel_tdes_resume);

static struct platform_driver atmel_tdes_driver = {
	.probe		= atmel_tdes_probe,
	.remove		= atmel_tdes_remove,
	.driver		= {
		.name	= "atmel_tdes",
		.of_match_table = of_match_ptr(atmel_tdes_dt_ids),
		.pm	= &atmel_tdes_pm_ops,
	},
};

module_platform_driver(atmel_tdes_driver);

MODULE_DESCRIPTION("Atmel DES/TDES hw acceleration support.");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Nicolas Royer - Eukréa Electromatique");
