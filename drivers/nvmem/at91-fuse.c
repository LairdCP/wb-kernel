/*
 * at91 OTP fusebox driver
 * compatibility:  atsama5d3
 *
 * Copyright (C) 2022 Laird Connectivity
 * Erik Strack <erik.strack@lairdconnect.com>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 *
 * Write support based on the fsl_otp driver,
 * Copyright (C) 2010-2013 Freescale Semiconductor, Inc
 */

#include <linux/clk.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/nvmem-provider.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/delay.h>

#ifdef CONFIG_SYSFS
#include <linux/nvmem-consumer.h>
#include <linux/fs.h>
#include <linux/list.h>

struct cell_meta {
	struct list_head nvmem_cell_sysfs_list;
	struct bin_attribute bin_attr_cell;
	struct nvmem_cell *cell;
};
#endif

static DEFINE_MUTEX(at91_fuse_mutex);

struct at91_fuse_priv {
	struct device *dev;
	struct clk_bulk_data *clks;
	int num_clks;
	void __iomem *base;
	const struct at91_fuse_params *params;
	struct nvmem_config *config;
#ifdef CONFIG_SYSFS
	struct list_head nvmem_cell_sysfs_head;
#endif
};

/* Fuse control register (fcr, write-only) */
/* WRQ: Write Request */
#define AT91_FUSE_FCR_WRQ_OFFSET	(0)
#define AT91_FUSE_FCR_WRQ		(1 << AT91_FUSE_FCR_WRQ_OFFSET)
/* RRQ: Read Request */
#define AT91_FUSE_FCR_RRQ_OFFSET	(1)
#define AT91_FUSE_FCR_RRQ		(1 << AT91_FUSE_FCR_RRQ_OFFSET)
/* Valid code used to unlock write in fcr */
#define AT91_FUSE_FCR_KEY_OFFSET	(8)
#define AT91_FUSE_FCR_VALID_KEY_CODE	((0xfb) << AT91_FUSE_FCR_KEY_OFFSET)
/* FMR: Fuse Mode Register */
#define AT91_FUSE_FMR_MSK_OFFSET	(0)
#define AT91_FUSE_FMR_MSK		(1 << AT91_FUSE_FMR_MSK_OFFSET)
/* FIR: Fuse Index Register */
#define AT91_FUSE_FIR_WS_OFFSET		(0)
#define AT91_FUSE_FIR_WS		(1 << AT91_FUSE_FIR_WS_OFFSET)
#define AT91_FUSE_FIR_RS_OFFSET		(1)
#define AT91_FUSE_FIR_RS		(1 << AT91_FUSE_FIR_RS_OFFSET)
/* WSEL: Word Selection (0-15: Selects the word to write) */
#define AT91_FUSE_FIR_WSEL_OFFSET	(8)
/* Fuse status register 5 */
#define AT91_FUSE_W_WORD		(5)
#define AT91_FUSE_FSR5_W_OFFSET		(0)
#define AT91_FUSE_FSR5_W		(1 << AT91_FUSE_FSR5_W_OFFSET)
#define AT91_FUSE_FSR5_J_OFFSET		(1)
#define AT91_FUSE_FSR5_B_OFFSET		(2)

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

static int at91_fuse_wait_for_busy(struct at91_fuse_reg *fuse)
{
	int i;

	for(i = 0; i < 100; i++)
	{
		 mdelay(1);
		 if ((readl(&fuse->fir)
			& (AT91_FUSE_FIR_WS | AT91_FUSE_FIR_RS)) ==
			(AT91_FUSE_FIR_WS | AT91_FUSE_FIR_RS))
		 return 0;
	}

	printk(KERN_ERR "timeout in at91_fuse_wait_for_busy\n");
	return -EBUSY;
}

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

static int write_word(struct at91_fuse_reg *fuse, int word, int val)
{
	int ret;

	writel(word << AT91_FUSE_FIR_WSEL_OFFSET, &fuse->fir);
	writel(val, &fuse->fdr);

	if ((ret = at91_fuse_wait_for_busy(fuse)))
		return ret;

	writel(AT91_FUSE_FCR_WRQ | AT91_FUSE_FCR_VALID_KEY_CODE, &fuse->fcr);
	return at91_fuse_wait_for_busy(fuse);
}

static int at91_fuse_write(void *context, unsigned int offset, void *val,
			   size_t bytes)
{
	struct at91_fuse_priv *priv = context;
	struct at91_fuse_reg *fuse = (struct at91_fuse_reg *) priv->base;
	unsigned int count;
	u8 *buf;
	int i, ret = 0;
	u32 index, num_bytes, bytes_remaining, bytes_copy;
	u32 temp;
	u8 *cpy_start;

	ret = clk_bulk_prepare_enable(priv->num_clks, priv->clks);
	if (ret) {
		mutex_unlock(&at91_fuse_mutex);
		printk(KERN_ERR "failed to prepare/enable bulk clks, error %d\n", ret);
		return ret;
	}

	index = offset >> 2;
	num_bytes = round_up((offset % 4) + bytes, 4);
	count = num_bytes >> 2;

	if (count > (priv->params->nregs - index))
		count = priv->params->nregs - index;

	buf = val;

	cpy_start = ((u8 *) &temp) + (offset % 4);
	bytes_remaining = bytes;
	bytes_copy = min_t(u32, bytes_remaining, 4 - (offset % 4));
	for (i = index; i < (index + count); i++) {
		temp = 0;
		memcpy(cpy_start, buf, bytes_copy);
		if ((ret = write_word(fuse, i, temp)))
			goto write_end;
		buf += bytes_copy;
		bytes_remaining -= bytes_copy;
		cpy_start = (u8 *) &temp;
		bytes_copy = min_t(u32, bytes_remaining, 4);
	}

	/* Update cache by hitting RRQ in FUSE_CR, wait for RS & WS of FUSE_IR to be at level 1 */
	writel(AT91_FUSE_FCR_RRQ | AT91_FUSE_FCR_VALID_KEY_CODE, &fuse->fcr);

	/* Do not turn clocks off until no longer busy */
	ret = at91_fuse_wait_for_busy(fuse);

write_end:
	clk_bulk_disable_unprepare(priv->num_clks, priv->clks);
	mutex_unlock(&at91_fuse_mutex);
	return ret;
}

static struct nvmem_config at91_fuse_nvmem_config = {
	.name = "at91_fuse",
	.read_only = false,
	// Pretend word size is 1, such that a single byte can be read/written.
	.word_size = 1,
	.stride = 1,
	.reg_read = at91_fuse_read,
	.reg_write = at91_fuse_write,
};

static const struct at91_fuse_params atsama5d3_params = {
	.nregs = 7,
};

static const struct of_device_id at91_fuse_dt_ids[] = {
	{ .compatible = "atmel,sama5d3-fuse", .data = &atsama5d3_params },
	{ },
};
MODULE_DEVICE_TABLE(of, at91_fuse_dt_ids);

#ifdef CONFIG_SYSFS
static ssize_t cell_read(struct file *filp, struct kobject *kobj,
			 struct bin_attribute *attr, char *buf,
			 loff_t pos, size_t count)
{
	void *cell_buf;
	struct cell_meta *cell_meta;
	size_t cell_len;
	size_t read_bytes;

	if (attr->private)
		cell_meta = attr->private;
	else {
		printk(KERN_ERR "%s couldn't get private struct\n", __FUNCTION__);
		return 0;
	}
	if (!cell_meta->cell) {
		printk(KERN_ERR "%s couldn't get private cell\n", __FUNCTION__);
		return 0;
	}

	/* Stop the user from reading */
	if (pos >= cell_meta->bin_attr_cell.size)
		return 0;

	if (pos + count > cell_meta->bin_attr_cell.size)
		count = cell_meta->bin_attr_cell.size - pos;

	cell_buf = nvmem_cell_read(cell_meta->cell, &cell_len);

	if (IS_ERR(cell_buf)) {
		printk(KERN_ERR "%s error %d\n", __FUNCTION__, (int) PTR_ERR(cell_buf));
		return 0;
	}
	else {
		read_bytes = min_t(size_t, count, cell_len);
		memcpy(buf, cell_buf + pos, read_bytes);
	}

	kfree(cell_buf);

	return read_bytes;
}

static ssize_t cell_write(struct file *filp, struct kobject *kobj,
			  struct bin_attribute *attr, char *buf,
			  loff_t pos, size_t count)
{
	void *cell_sized_buf;
	struct cell_meta *cell_meta;
	size_t cell_len;
	int ret;

	if (attr->private)
		cell_meta = attr->private;
	else {
		printk(KERN_ERR "%s couldn't get private struct\n", __FUNCTION__);
		return -EFAULT;
	}
	if (!cell_meta->cell) {
		printk(KERN_ERR "%s couldn't get private cell\n", __FUNCTION__);
		return -EFAULT;
	}

	cell_len = cell_meta->bin_attr_cell.size;

	/* Stop the user from writing */
	if (pos >= cell_len)
		return -EFBIG;

	if (pos + count > cell_len)
		count = cell_len - pos;

	if (pos != 0 || count != cell_len)
	{
		/* Assume that in underlying fuse HW, writing a 0 byte is a no-op */
		cell_sized_buf = kzalloc(cell_len, GFP_KERNEL);
		memcpy(cell_sized_buf + pos, buf, count);
		ret = nvmem_cell_write(cell_meta->cell, cell_sized_buf, cell_len);
		kfree(cell_sized_buf);
	}
	else
		ret = nvmem_cell_write(cell_meta->cell, buf, cell_len);

	if (ret < 0) {
		printk(KERN_ERR "%s error %d\n", __FUNCTION__, ret);
		return ret;
	}

	return count;
}

/*
 * cell_attribute - nvram cell sysfs-node attributes
 *
 * NOTE Size and name will be changed according to underlying cell.
 */
static BIN_ATTR_RW(cell, 0);

static int register_cells_sysfs(struct at91_fuse_priv *priv)
{
	struct device *dev = priv->dev;
	struct nvmem_cell *cell;
	const char *cell_name = NULL;
	int ret;

	struct cell_meta *cell_meta;

	struct of_phandle_iterator it;
	struct device_node *np;
	int i = 0;
	const __be32 *addr;
	int len;

	INIT_LIST_HEAD(&priv->nvmem_cell_sysfs_head);

	of_for_each_phandle(&it, ret, dev->of_node, "nvmem-cells", NULL, 0) {
		int bytes = 0;
		np = it.node;

		addr = of_get_property(np, "reg", &len);
		if (!addr) {
			printk(KERN_ERR "failed to get reg property\n");
		}
		else {
			if (len < 2 * sizeof(u32)) {
				printk(KERN_ERR "at91-fuse: invalid reg on %pOF\n", np);
			}
			else
				bytes = be32_to_cpup(++addr);
		}

		of_node_put(np);

		ret = of_property_read_string_index(dev->of_node, "nvmem-cell-names",
								i++, &cell_name);
		if (ret != 0)
			continue;

		cell = nvmem_cell_get(dev, cell_name);
		if (IS_ERR(cell)) {
			printk(KERN_ERR "nvmem_cell_get %s error %ld\n", cell_name, PTR_ERR(cell));
			continue;
		}

		cell_meta = devm_kzalloc(dev, sizeof(struct cell_meta *), GFP_KERNEL);

		/* Copy the declared attr structure to change some fields */
		memcpy(&cell_meta->bin_attr_cell, &bin_attr_cell, sizeof(cell_meta->bin_attr_cell));

		cell_meta->cell = cell;
		cell_meta->bin_attr_cell.attr.name = cell_name;
		cell_meta->bin_attr_cell.size = bytes;
		cell_meta->bin_attr_cell.private = cell_meta;

		ret = device_create_bin_file(dev, &cell_meta->bin_attr_cell);
		if (ret) {
			printk(KERN_ERR
				"Failed to create sysfs file %s\n", cell_name);
			return ret;
		}

		list_add(&cell_meta->nvmem_cell_sysfs_list, &priv->nvmem_cell_sysfs_head);
	}

	return 0;
}
#endif

static int at91_fuse_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct at91_fuse_priv *priv;
	struct nvmem_device *nvmem;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	dev_set_drvdata(dev, priv);
	priv->dev = dev;

	priv->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(priv->base))
		return PTR_ERR(priv->base);

	priv->num_clks = devm_clk_bulk_get_all(dev, &priv->clks);
	if (priv->num_clks < 0) {
		printk(KERN_ERR "devm_clk_bulk_get_all failed with %d\n", priv->num_clks);
		return priv->num_clks;
	}

	priv->params = of_device_get_match_data(dev);
	at91_fuse_nvmem_config.size = 4 * priv->params->nregs;
	at91_fuse_nvmem_config.dev = dev;
	at91_fuse_nvmem_config.priv = priv;
	priv->config = &at91_fuse_nvmem_config;

	nvmem = devm_nvmem_register(dev, &at91_fuse_nvmem_config);

#ifdef CONFIG_SYSFS
	register_cells_sysfs(priv);
#endif

	return PTR_ERR_OR_ZERO(nvmem);
}

static int at91_fuse_remove(struct platform_device *pdev)
{
#ifdef CONFIG_SYSFS
	struct device *dev = &pdev->dev;
	struct at91_fuse_priv *priv = dev_get_drvdata(dev);
	struct list_head *ptr;
	struct cell_meta *entry;

	list_for_each(ptr, &priv->nvmem_cell_sysfs_head){
		entry = list_entry(ptr, struct cell_meta, nvmem_cell_sysfs_list);
		device_remove_bin_file(dev, &entry->bin_attr_cell);
		nvmem_cell_put(entry->cell);
	}
#endif

	return 0;
}

static struct platform_driver at91_fuse_driver = {
	.probe	= at91_fuse_probe,
	.remove = at91_fuse_remove,
	.driver = {
		.name           = "at91_fuse",
		.of_match_table = at91_fuse_dt_ids,
	},
};
module_platform_driver(at91_fuse_driver);

MODULE_AUTHOR("Erik Strack <erik.strack@lairdconnect.com>");
MODULE_DESCRIPTION("at91 fusebox (OTP) driver");
MODULE_LICENSE("GPL v2");
