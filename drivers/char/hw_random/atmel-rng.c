/*
 * Copyright (c) 2011 Peter Korsgaard <jacmet@sunsite.dk>
 *
 * This file is licensed under  the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/of_device.h>
#include <linux/hw_random.h>
#include <crypto/rng.h>
#include <crypto/internal/rng.h>

#define TRNG_CR		0x00
#define TRNG_MR		0x04
#define TRNG_ISR	0x1c
#define TRNG_ODATA	0x50

#define TRNG_KEY	0x524e4700 /* RNG */

#define TRNG_HALFR	BIT(0) /* generate RN every 168 cycles */

struct atmel_trng_data {
	bool has_half_rate;
};

struct atmel_trng {
	struct clk *clk;
	void __iomem *base;
	struct hwrng rng;
	u32 last;
};

static struct atmel_trng * g_trng;
static DEFINE_MUTEX(trng_mutex);

static int atmel_trng_read_entropy(struct atmel_trng *trng, void *buf,
	size_t max, bool wait)
{
	u32 *data = buf, curr;
	size_t len = 0;
	int ret;

	mutex_lock(&trng_mutex);

	if (!trng) {
		ret = -ENODEV;
		goto exit;
	}

	for (;;) {
		if (!(readl(trng->base + TRNG_ISR) & 1)) {
			if (!wait)
				break;

			cpu_relax();
			continue;
		}

		curr = readl(trng->base + TRNG_ODATA);

		/* Clear ready flag again in case it have changed */
		readl(trng->base + TRNG_ISR);

		if (curr == trng->last)
			panic("atmel-rng: Duplicate output detected\n");

		trng->last = curr;
		*(data++) = curr;
		len += sizeof(u32);

		if (len >= max)
			break;
	}

	ret = (int) len;

exit:
	mutex_unlock(&trng_mutex);

	return ret;
}


static int atmel_trng_read(struct hwrng *rng, void *buf, size_t max, bool wait)
{
	return atmel_trng_read_entropy(g_trng, buf, max, wait);
}

static int atmel_trng_generate(struct crypto_rng *tfm,
	const u8 *src, unsigned int slen, u8 *rdata, unsigned int dlen)
{
	int ret = atmel_trng_read_entropy(g_trng, rdata, dlen, true);
	if (ret < 0)
		return ret;

	return ret == dlen ? 0 : -EFAULT;
}

static int atmel_trng_seed(struct crypto_rng *tfm,
			   const u8 *seed, unsigned int slen)
{
	return 0;
}

static void atmel_trng_enable(struct atmel_trng *trng)
{
	writel(TRNG_KEY | 1, trng->base + TRNG_CR);
}

static void atmel_trng_disable(struct atmel_trng *trng)
{
	writel(TRNG_KEY, trng->base + TRNG_CR);
}

static struct rng_alg atmel_trng_alg = {
	.generate	= atmel_trng_generate,
	.seed		= atmel_trng_seed,
	.seedsize	= 0,
	.base		= {
		.cra_name		= "jitterentropy_rng",
		.cra_driver_name	= "atmel-trng",
		.cra_flags		= CRYPTO_ALG_TYPE_RNG,
		.cra_priority		= 300,
		.cra_module		= THIS_MODULE,
	}
};

static int atmel_trng_probe(struct platform_device *pdev)
{
	struct atmel_trng *trng;
	const struct atmel_trng_data *data;
	int ret;

	trng = devm_kzalloc(&pdev->dev, sizeof(*trng), GFP_KERNEL);
	if (!trng)
		return -ENOMEM;

	trng->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(trng->base))
		return PTR_ERR(trng->base);

	trng->clk = devm_clk_get(&pdev->dev, NULL);
	if (IS_ERR(trng->clk))
		return PTR_ERR(trng->clk);
	data = of_device_get_match_data(&pdev->dev);
	if (!data)
		return -ENODEV;

	if (data->has_half_rate) {
		unsigned long rate = clk_get_rate(trng->clk);

		/* if peripheral clk is above 100MHz, set HALFR */
		if (rate > 100000000)
			writel(TRNG_HALFR, trng->base + TRNG_MR);
	}

	ret = clk_prepare_enable(trng->clk);
	if (ret)
		return ret;

	atmel_trng_enable(trng);

	g_trng = trng;

	trng->rng.name = pdev->name;
	trng->rng.read = atmel_trng_read;
	trng->rng.quality = 921;
	trng->rng.priv = (unsigned long)trng;

	ret = devm_hwrng_register(&pdev->dev, &trng->rng);
	if (ret)
		goto err_register;

	ret = crypto_register_rng(&atmel_trng_alg);
	if (ret)
		goto err_register_crypto;

	platform_set_drvdata(pdev, trng);

	return 0;

err_register_crypto:
	hwrng_unregister(&trng->rng);

err_register:
	clk_disable_unprepare(trng->clk);
	atmel_trng_disable(trng);
	return ret;
}

static int atmel_trng_remove(struct platform_device *pdev)
{
	struct atmel_trng *trng = platform_get_drvdata(pdev);

	mutex_lock(&trng_mutex);
	g_trng = NULL;
	mutex_unlock(&trng_mutex);

	crypto_unregister_rng(&atmel_trng_alg);
	hwrng_unregister(&trng->rng);

	atmel_trng_disable(trng);
	clk_disable_unprepare(trng->clk);

	return 0;
}

#ifdef CONFIG_PM
static int atmel_trng_suspend(struct device *dev)
{
	struct atmel_trng *trng = dev_get_drvdata(dev);

	atmel_trng_disable(trng);
	clk_disable_unprepare(trng->clk);

	return 0;
}

static int atmel_trng_resume(struct device *dev)
{
	struct atmel_trng *trng = dev_get_drvdata(dev);
	int ret;

	ret = clk_prepare_enable(trng->clk);
	if (ret)
		return ret;

	atmel_trng_enable(trng);

	return 0;
}
#endif /* CONFIG_PM */

static SIMPLE_DEV_PM_OPS(atmel_trng_pm_ops, atmel_trng_suspend,
	atmel_trng_resume);

static const struct atmel_trng_data at91sam9g45_config = {
	.has_half_rate = false,
};

static const struct atmel_trng_data sam9x60_config = {
	.has_half_rate = true,
};

static const struct of_device_id atmel_trng_dt_ids[] = {
	{
		.compatible = "atmel,at91sam9g45-trng",
		.data = &at91sam9g45_config,
	}, {
		.compatible = "microchip,sam9x60-trng",
		.data = &sam9x60_config,
	}, {
		/* sentinel */
	}
};
MODULE_DEVICE_TABLE(of, atmel_trng_dt_ids);

static struct platform_driver atmel_trng_driver = {
	.probe		= atmel_trng_probe,
	.remove		= atmel_trng_remove,
	.driver		= {
		.name	= "atmel-trng",
		.pm	= &atmel_trng_pm_ops,
		.of_match_table = atmel_trng_dt_ids,
	},
};

static int __init atmel_trng_init(void)
{
	return platform_driver_register(&atmel_trng_driver);
}

static void __exit atmel_trng_exit(void)
{
	platform_driver_unregister(&atmel_trng_driver);
}

subsys_initcall(atmel_trng_init);
module_exit(atmel_trng_exit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Peter Korsgaard <jacmet@sunsite.dk>");
MODULE_DESCRIPTION("Atmel true random number generator driver");
