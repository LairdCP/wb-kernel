// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * GPIO OF based helper
 *
 * A simple DT based driver to provide access to GPIO functionality
 * to user-space via sysfs.
 *
 * Copyright (C) 2021 Boris Krasnovskiy <boris.krasnovskiy@ezurio.com>
 * Copyright (C) 2013 Pantelis Antoniou <panto@antoniou-consulting.com>
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/gpio/consumer.h>
#include <linux/pinctrl/consumer.h>
#include <linux/atomic.h>
#include <linux/interrupt.h>

struct gpio_entry {
	const char *name;
	struct gpio_desc *desc;
	int irq;
	atomic64_t counter;
};

struct gpio_helper_info {
	struct platform_device *pdev;
	struct gpio_entry *gpios;
	size_t size;
};

static const struct of_device_id gpio_of_helper_of_match[] = {
	{ .compatible = "gpio-of-helper", },
	{ },
};
MODULE_DEVICE_TABLE(of, gpio_of_helper_of_match);

static ssize_t status_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct gpio_helper_info *info = platform_get_drvdata(pdev);
	struct gpio_entry *entry;
	char *p, *e;
	int n;
	unsigned i;

	p = buf;
	e = p + PAGE_SIZE;
	n = 0;
	for (i = 0; i < info->size; ++i) {
		entry = &info->gpios[i];
		if (gpiod_get_direction(entry->desc))
			n = snprintf(p, e - p, "%2d %-24s %3d %-3s %llu\n",
				i, entry->name, desc_to_gpio(entry->desc), "IN",
				(unsigned long long)atomic64_read(&entry->counter));
		else
			n = snprintf(p, e - p, "%2d %-24s %3d %-3s\n",
				i, entry->name, desc_to_gpio(entry->desc), "OUT");

		p += n;
	}

	return p - buf;
}

static DEVICE_ATTR_RO(status);

static irqreturn_t gpio_of_helper_handler(int irq, void *ptr)
{
	struct gpio_entry *entry = ptr;

	/* caution - low speed interfaces only! */
	atomic64_inc(&entry->counter);

	return IRQ_HANDLED;
}

static int gpio_of_entry_create(struct device *dev, struct device_node *node,
	struct gpio_entry *entry)
{
	enum gpiod_flags gpio_flags;
	unsigned long irq_flags = 0;
	int ret;

	ret = of_property_read_string(node, "gpio-name", &entry->name);
	if (ret) {
		dev_err(dev, "Failed to get name property\n");
		return ret;
	}

	/* get the type of the node first */
	if (of_property_read_bool(node, "input")) {
		gpio_flags = GPIOD_IN;
		if (of_property_read_bool(node, "count-falling-edge"))
			irq_flags |= IRQF_TRIGGER_FALLING;
		if (of_property_read_bool(node, "count-rising-edge"))
			irq_flags |= IRQF_TRIGGER_RISING;
	} else if (of_property_read_bool(node, "output")) {
		if (of_property_read_bool(node, "init-high"))
			gpio_flags = GPIOD_OUT_HIGH;
		else if (of_property_read_bool(node, "init-low"))
			gpio_flags = GPIOD_OUT_LOW;
		else {
			dev_err(dev, "Initial gpio state not specified\n");
			return -EINVAL;
		}
	} else {
		dev_err(dev, "Not valid gpio node type\n");
		return -EINVAL;
	}

	entry->desc = devm_gpiod_get(dev, "gpio", gpio_flags);
	if (IS_ERR(entry->desc))
		return dev_err_probe(dev, PTR_ERR(entry->desc),
			"Failed to get gpio property of '%s'\n", entry->name);

	ret = gpiod_set_consumer_name(entry->desc, entry->name);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to set %s gpio name\n",
			entry->name);

	/* counter mode requested - need an interrupt */
	if (irq_flags) {
		entry->irq = gpiod_to_irq(entry->desc);
		if (entry->irq < 0)
			return dev_err_probe(dev, entry->irq,
				"Failed to get gpio irq '%s'\n", entry->name);

		ret = devm_request_irq(dev, entry->irq, gpio_of_helper_handler,
				irq_flags, entry->name, entry);
		if (ret)
			return dev_err_probe(dev, ret,
				"Failed to request irq of '%s'\n", entry->name);
	}

	return 0;
}

static int gpio_of_helper_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct gpio_helper_info *info;
	struct gpio_entry *entry;
	struct device_node *pnode = dev->of_node;
	struct device_node *cnode;
	struct pinctrl *pinctrl;
	unsigned i;
	int ret;

	/* we only support OF */
	if (!pnode) {
		dev_err(dev, "No platform of_node!\n");
		return -ENODEV;
	}

	pinctrl = devm_pinctrl_get_select_default(dev);
	if (IS_ERR(pinctrl)) {
		/* special handling for probe defer */
		if (PTR_ERR(pinctrl) == -EPROBE_DEFER)
			return -EPROBE_DEFER;

		dev_warn(&pdev->dev,
			"pins are not configured from the driver\n");
	}

	info = devm_kzalloc(dev, sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	info->size = of_get_child_count(pnode);
	info->gpios = devm_kzalloc(dev, sizeof(struct gpio_entry) * info->size,
		GFP_KERNEL);
	if (!info->gpios)
		return -ENOMEM;

	entry = info->gpios;

	for_each_child_of_node(pnode, cnode) {
		ret = gpio_of_entry_create(dev, cnode, entry);
		if (ret)
			return ret;
		++entry;
	}

	ret = device_create_file(dev, &dev_attr_status);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to create status sysfs attribute\n");

	for (i = 0; i < info->size; ++i) {
		gpiod_export(info->gpios[i].desc, 0);
		gpiod_export_link(dev, info->gpios[i].name, info->gpios[i].desc);
	}

	platform_set_drvdata(pdev, info);

	dev_info(dev, "gpio_of_helper started\n");

	return 0;
}

static int gpio_of_helper_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct gpio_helper_info *info = platform_get_drvdata(pdev);
	unsigned i;

	for (i = 0; i < info->size; ++i) {
		gpiod_unexport(info->gpios[i].desc);
		sysfs_remove_link(&dev->kobj, info->gpios[i].name);
	}

	device_remove_file(dev, &dev_attr_status);

	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int gpio_of_helper_suspend(struct device *dev)
{
	pinctrl_pm_select_sleep_state(dev);
	return 0;
}

static int gpio_of_helper_resume(struct device *dev)
{
	pinctrl_pm_select_default_state(dev);
	return 0;
}
#endif /* CONFIG_PM_SLEEP */

static SIMPLE_DEV_PM_OPS(gpio_of_helper_pm_ops, gpio_of_helper_suspend,
	gpio_of_helper_resume);

struct platform_driver gpio_of_helper_driver = {
	.probe		= gpio_of_helper_probe,
	.remove		= gpio_of_helper_remove,
	.driver = {
		.name		= "gpio-of-helper",
		.pm		= &gpio_of_helper_pm_ops,
		.of_match_table	= gpio_of_helper_of_match,
	},
};

module_platform_driver(gpio_of_helper_driver);

MODULE_AUTHOR("Boris Krasnovskiy <boris.krasnovskiy@ezurio.com>");
MODULE_DESCRIPTION("GPIO OF Helper driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:gpio-of-helper");
