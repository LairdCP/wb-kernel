/*
 * Semtech SC620 Backlight Driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/module.h>
#include <linux/i2c.h>
#include <linux/backlight.h>
#include <linux/err.h>
#include <linux/of.h>
#include <linux/regulator/consumer.h>

/* SC620 Registers */
#define CHN_ON_OFF_REG		0x00
#define BRIGHTNESS_BASE_REG	0x01
#define CHN_GAIN_REG		0x09

#define MAX_BRIGHTNESS		63
#define GAIN_STEP		3125

struct sc620_bl_data {
	struct i2c_client *i2c;
	struct regulator *power_supply;
	u32 max_current;
	u32 ctrl_mask;
	u8 gain;
	bool on;
};

static void sc620_set_brightness(struct sc620_bl_data *ctx, u8 val)
{
	u8 mask = ctx->ctrl_mask & 0xff;
	int i = 0;

	while (mask) {
		if (mask & 1)
			i2c_smbus_write_byte_data(ctx->i2c,
				BRIGHTNESS_BASE_REG + i, val);
		mask >>= 1;
		++i;
	}
}

static int sc620_on_off(struct sc620_bl_data *ctx, bool on)
{
	int ret;

	if (on) {
		ret = regulator_enable(ctx->power_supply);
		if (ret)
			return ret;

		i2c_smbus_write_byte_data(ctx->i2c, CHN_ON_OFF_REG,
			ctx->ctrl_mask & 0xff);

		i2c_smbus_write_byte_data(ctx->i2c, CHN_GAIN_REG,
			ctx->gain);
	} else if (regulator_is_enabled(ctx->power_supply)) {
		i2c_smbus_write_byte_data(ctx->i2c, CHN_ON_OFF_REG, 0);

		ret = regulator_disable(ctx->power_supply);
		if (ret)
			return ret;
	}

	ctx->on = on;

	return 0;
}

static int sc620_bl_update_status(struct backlight_device *bl)
{
	struct sc620_bl_data *ctx = bl_get_data(bl);

	bool on = !(bl->props.state & (BL_CORE_SUSPENDED | BL_CORE_FBBLANK))
		&& bl->props.power != FB_BLANK_POWERDOWN
		&& bl->props.brightness != 0;

	if (on != ctx->on)
		sc620_on_off(ctx, on);

	if (on)
		sc620_set_brightness(ctx, bl->props.brightness);

	return 0;
}

static const struct backlight_ops sc620_bl_ops = {
	.options = BL_CORE_SUSPENDRESUME,
	.update_status = sc620_bl_update_status,
};

static int sc620_probe(struct i2c_client *i2c, const struct i2c_device_id *id)
{
	struct device *dev = &i2c->dev;
	struct backlight_device *bl;
	struct sc620_bl_data *ctx;
	int ret;
	struct backlight_properties props;

	if (!i2c_check_functionality(i2c->adapter, I2C_FUNC_SMBUS_I2C_BLOCK))
		return -EIO;

	ctx = devm_kzalloc(dev, sizeof(struct sc620_bl_data), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->i2c = i2c;

	ctx->power_supply = devm_regulator_get(dev, "power");
	if (IS_ERR(ctx->power_supply))
		return PTR_ERR(ctx->power_supply);

	i2c_set_clientdata(i2c, ctx);

	ctx->gain = 0x8;
	ctx->max_current = (ctx->gain + 1) * (MAX_BRIGHTNESS * GAIN_STEP) / 100;
	ctx->ctrl_mask = 0xff;

	memset(&props, 0, sizeof(props));

	props.type = BACKLIGHT_RAW;
	props.max_brightness = MAX_BRIGHTNESS;
	props.brightness = MAX_BRIGHTNESS / 2;
	props.power = FB_BLANK_POWERDOWN;

	if (dev->of_node) {
		of_property_read_u32(dev->of_node, "ctrl-mask",
			&ctx->ctrl_mask);

		ret = of_property_read_u32(dev->of_node, "max-current",
			&ctx->max_current);

		if (ret >= 0) {
			ctx->gain = ctx->max_current * 100 /
				(MAX_BRIGHTNESS * GAIN_STEP);

			if (ctx->gain > 0)
				--ctx->gain;

			if (ctx->gain > 0xf)
				ctx->gain = 0xf;
		}

		of_property_read_u32(dev->of_node,
			"default-brightness-level", &props.brightness);

		if (props.brightness > MAX_BRIGHTNESS)
			props.brightness = MAX_BRIGHTNESS;
	}

	bl = devm_backlight_device_register(dev, "sc620_backlight",
		dev, ctx, &sc620_bl_ops, &props);
	if (IS_ERR(bl)) {
		ret = PTR_ERR(bl);
		dev_err(dev,
			"failed to register backlight. err: %d\n", ret);
		return ret;
	}

	sc620_on_off(ctx, false);

	dev_info(dev, "Semtech SC620 Backlight driver Initialized\n");

	return 0;
}

static int sc620_remove(struct i2c_client *i2c)
{
	struct sc620_bl_data *ctx = i2c_get_clientdata(i2c);

	sc620_on_off(ctx, false);

	return 0;
}

static const struct of_device_id sc620_dt_ids[] = {
	{ .compatible = "semtech,sc620", },
	{ }
};
MODULE_DEVICE_TABLE(of, sc620_dt_ids);

static const struct i2c_device_id sc620_ids[] = {
	{ "sc620", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, sc620_ids);

static struct i2c_driver sc620_driver = {
	.probe = sc620_probe,
	.remove = sc620_remove,
	.id_table = sc620_ids,
	.driver = {
		.name = "sc620_backlight",
		.of_match_table = of_match_ptr(sc620_dt_ids),
	},
};

module_i2c_driver(sc620_driver);

MODULE_DESCRIPTION("Semtech SC620 Backlight driver");
MODULE_AUTHOR("Boris Krasnovskiy <boris.krasnovskiy@lairdconnect.com>");
MODULE_LICENSE("GPL");
