// SPDX-License-Identifier: GPL-2.0
/*
 * Driver to select GPIO lines as wakeup sources from DT.
 *
 * Copyright 2013 Daniel Mack
 * Copyright 2018 Boris Krasnovskiy
 *
 */

#include <linux/module.h>

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/suspend.h>
#include <linux/platform_device.h>
#include <linux/of_platform.h>

struct wkup_priv {
	int irq;
	struct wakeup_source *wks;
};

struct gpio_wakeup_priv {
	int count;
	struct wkup_priv wkup[0];
};

static irqreturn_t gpio_wakeup_isr(int irq, void *dev_id)
{
	struct device *dev = dev_id;
	struct gpio_wakeup_priv *priv = dev_get_drvdata(dev);
	int i;

	/* Ignore interrupts, while initialization have not finished yet */
	if (priv == NULL)
		return IRQ_HANDLED;

	/* Notify PM core we are wakeup source */
	pm_wakeup_event(dev, 0);

	for (i = 0; i < priv->count; i++) {
		if (priv->wkup[i].irq == irq) {
			pm_wakeup_ws_event(priv->wkup[i].wks, 0, 0);
			dev_info(dev, "GPIO Wakeup: %s\n", 
				priv->wkup[i].wks && priv->wkup[i].wks->name ? 
				priv->wkup[i].wks->name : dev->init_name);
			break;
		}
	}

	return IRQ_HANDLED;
}

static int gpio_wakeup_probe(struct platform_device *pdev)
{
	int ret, count, i, irq, irqflags;
	struct gpio_wakeup_priv *priv;
	struct device *dev = &pdev->dev;
	char const *name;

	count = platform_irq_count(pdev);
	if (count < 0)
		return count;

	if (count == 0) {
		dev_err(dev, "No wake IRQs specified\n");
		return -ENXIO;
	}

	priv = devm_kzalloc(dev, sizeof(struct gpio_wakeup_priv) +
		count * sizeof(struct wkup_priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->count = count;
	platform_set_drvdata(pdev, priv);

	for (i = 0; i < count; i++) {
		irq = platform_get_irq(pdev, i);

		if (irq < 0) {
			if (irq == -EPROBE_DEFER)
				return -EPROBE_DEFER;
			else {
				dev_err(dev, "Unable to retrieve IRQ %d, %d\n", i, irq);
				continue;
			}
		}

		irq_set_status_flags(irq, IRQ_NOAUTOEN);
		irqflags = irq_get_trigger_type(irq);

		ret = devm_request_threaded_irq(dev, irq, NULL, gpio_wakeup_isr,
			irqflags | IRQF_ONESHOT, pdev->name, dev);
		if (ret < 0) {
			dev_err(dev, "Unable to request IRQ %d, %d\n", irq, ret);
			continue;
		}

		priv->wkup[i].irq = irq;

		ret = of_property_read_string_index(dev->of_node,
			"interrupt-names", i, &name);

		if (!ret)
			priv->wkup[i].wks =	wakeup_source_register(name);
	}

	device_init_wakeup(dev, true);

	return 0;
}

static int gpio_wakeup_remove(struct platform_device *pdev)
{
	struct gpio_wakeup_priv *priv = platform_get_drvdata(pdev);
	int i;

	for (i = 0; i < priv->count; i++)
		wakeup_source_unregister(priv->wkup[i].wks);

	device_init_wakeup(&pdev->dev, false);

	return 0;
}

static int gpio_wakeup_suspend(struct device *dev)
{
	struct gpio_wakeup_priv *priv = dev_get_drvdata(dev);
	int i;

	for (i = 0; i < priv->count; i++) {
		if (priv->wkup[i].irq >= 0) {
			enable_irq(priv->wkup[i].irq);
			enable_irq_wake(priv->wkup[i].irq);
		}
	}

	return 0;
}

static int gpio_wakeup_resume(struct device *dev)
{
	struct gpio_wakeup_priv *priv = dev_get_drvdata(dev);
	int i;

	for (i = 0; i < priv->count; i++) {
		if (priv->wkup[i].irq >= 0) {
			disable_irq_wake(priv->wkup[i].irq);
			disable_irq_nosync(priv->wkup[i].irq);
		}
	}

	return 0;
}

static const SIMPLE_DEV_PM_OPS(gpio_wakeup_pm_ops,
			 gpio_wakeup_suspend, gpio_wakeup_resume);

static const struct of_device_id gpio_wakeup_of_match[] = {
	{ .compatible = "gpio-wakeup", },
	{ },
};
MODULE_DEVICE_TABLE(of, gpio_wakeup_of_match);

static struct platform_driver gpio_wakeup_driver = {
	.probe	= gpio_wakeup_probe,
	.remove	= gpio_wakeup_remove,
	.driver	= {
		.name	= "gpio-wakeup",
		.owner	= THIS_MODULE,
		.pm	= &gpio_wakeup_pm_ops,
		.of_match_table = of_match_ptr(gpio_wakeup_of_match),
	}
};

module_platform_driver(gpio_wakeup_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Mack <zonque@gmail.com>, Boris Krasnovskiy <boris.krasnovskiy@lairdtech.com>");
MODULE_DESCRIPTION("Driver to wake up systems from GPIOs");
MODULE_ALIAS("platform:gpio-wakeup");
