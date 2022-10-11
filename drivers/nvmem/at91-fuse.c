/*
 * at91 OTP fusebox driver
 * compatibility:  atsama5d3
 *
 * Copyright (C) 2022 Laird Connectivity
 * Erik Strack <erik.strack@lairdconnect.com>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 *
 * Write support is not implemented.
 */

#include <linux/device.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/nvmem-provider.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/delay.h>

static DEFINE_MUTEX(at91_fuse_mutex);

struct at91_fuse_priv {
	struct device *dev;
	void __iomem *base;
	const struct at91_fuse_params *params;
	struct nvmem_config *config;
};

struct at91_fuse_reg {
	u32	fcr;		/* 0x00 Fuse Control Register */
	u32	fmr;		/* 0x04 Fuse Mode Register */
	u32	fir;		/* 0x08 Fuse Index Register */
	u32	fdr;		/* 0x0C Fuse Data Register */
	u32	fsr[8];		/* 0x10 Fuse Status Register 0 */
	u32	reserved1[44];	/* 0x30 ~ 0xDC */
	u32	reserved2[8];	/* 0xE0 ~ 0xFC */
};

struct at91_fuse_params {
	unsigned int nregs;
};

static int at91_fuse_read(void *context, unsigned int offset,
			  void *val, size_t bytes)
{
	struct at91_fuse_priv *priv = context;
	struct at91_fuse_reg *fuse = (struct at91_fuse_reg *) priv->base;
	unsigned int count;
	u8 *buf;
	int i, ret = 0;
	u32 index, num_bytes, bytes_remaining, bytes_copy;
	u32 temp;
	u8 *cpy_start;

	index = offset >> 2;
	num_bytes = round_up((offset % 4) + bytes, 4);
	count = num_bytes >> 2;

	if (count > (priv->params->nregs - index))
		count = priv->params->nregs - index;

	mutex_lock(&at91_fuse_mutex);

	buf = val;

	cpy_start = ((u8 *) &temp) + (offset % 4);
	bytes_remaining = bytes;
	bytes_copy = min_t(u32, bytes_remaining, 4 - (offset % 4));
	for (i = index; i < (index + count); i++) {
		temp = readl(&fuse->fsr[i]);
		memcpy(buf, cpy_start, bytes_copy);
		buf += bytes_copy;
		bytes_remaining -= bytes_copy;
		cpy_start = (u8 *) &temp;
		bytes_copy = min_t(u32, bytes_remaining, 4);
	}

	mutex_unlock(&at91_fuse_mutex);

	return ret;
}

static struct nvmem_config at91_fuse_nvmem_config = {
	.name = "at91_fuse",
	.read_only = true,
	.word_size = 4,
	.stride = 1,
	.reg_read = at91_fuse_read,
};

static const struct at91_fuse_params atsama5d3_params = {
	.nregs = 7,
};

static const struct of_device_id at91_fuse_dt_ids[] = {
	{ .compatible = "atmel,sama5d3-fuse", .data = &atsama5d3_params },
	{ },
};
MODULE_DEVICE_TABLE(of, at91_fuse_dt_ids);

static int at91_fuse_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct at91_fuse_priv *priv;
	struct nvmem_device *nvmem;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->dev = dev;

	priv->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(priv->base))
		return PTR_ERR(priv->base);

	priv->params = of_device_get_match_data(&pdev->dev);
	at91_fuse_nvmem_config.size = 4 * priv->params->nregs;
	at91_fuse_nvmem_config.dev = dev;
	at91_fuse_nvmem_config.priv = priv;
	priv->config = &at91_fuse_nvmem_config;

	nvmem = devm_nvmem_register(dev, &at91_fuse_nvmem_config);

	return PTR_ERR_OR_ZERO(nvmem);
}

static struct platform_driver at91_fuse_driver = {
	.probe	= at91_fuse_probe,
	.driver = {
		.name           = "at91_fuse",
		.of_match_table = at91_fuse_dt_ids,
	},
};
module_platform_driver(at91_fuse_driver);

MODULE_AUTHOR("Erik Strack <erik.strack@lairdconnect.com>");
MODULE_DESCRIPTION("at91 fusebox (OTP) driver");
MODULE_LICENSE("GPL v2");
