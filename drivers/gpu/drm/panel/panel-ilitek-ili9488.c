/*
 * Ilitek ILI9488 TFT LCD drm_panel driver.
 *
 * This panel can be configured to support:
 * - 6-bit serial RGB interface
 * - 320x480 display
 * - MIPI DSI SPI 3 line mode
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <drm/drmP.h>
#include <drm/drm_panel.h>

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/pinctrl/consumer.h>
#include <linux/regulator/consumer.h>
#include <linux/spi/spi.h>

struct ili9488 {
	struct spi_device	*spi;
	struct backlight_device *backlight;
	struct regulator	*power;
	struct pinctrl		*pinctrl;
	struct pinctrl_state	*pins_sleep;
	struct pinctrl_state	*pins_boot;
	struct gpio_desc	*reset_gpio;
	struct drm_panel	panel;
};

static const u16 init_commands[] =
{
	0x000 | 0xC0,	// Power Control 1
	0x100 | 0x17,	// VREG1OUT - 5V
	0x100 | 0x17,	// VREG2OUT - 5V

	0x000 | 0xC1,	// Power Control 2
	0x100 | 0x44,	// VGH = VCI x 5, VGL = -VCI x 4

	0x000 | 0xC5,	// VCOM Control
	0x100 | 0x00,	// NV memory is not programmed
	0x100 | 0x3A,	// VCM_REG -1.09375V
	0x100 | 0x80,	// VCM_REG_EN - 1

	0x000 | 0x36,	// Memory Access control
	0x100 | 0x48,	// Mirrored

	0x000 | 0x3A,	// Interface Pixel Format
	0x100 | 0x60,	// RGB 18 bits/pixel

	0x000 | 0xB1,	// Frame Rate Control
	0x100 | 0xA0,	// Rate 60.76 Hz

	0x000 | 0xB4,	// Display Inversion Control
	0x100 | 0x02,	// 2 dot inversion

	0x000 | 0xB7,	// Entry Mode Set
	0x100 | 0xC6,

	0x000 | 0xE9,	// Set Image Function
	0x100 | 0x00,	// 24 bit data bus disable

	0x000 | 0xF7,	// Adjust Control 3
	0x100 | 0xA9,
	0x100 | 0x51,
	0x100 | 0x2C,
	0x100 | 0x82,

	0x000 | 0xE0,	// Positive Gamma Control
	0x100 | 0x01,
	0x100 | 0x13,
	0x100 | 0x1E,
	0x100 | 0x00,
	0x100 | 0x0D,
	0x100 | 0x03,
	0x100 | 0x3D,
	0x100 | 0x55,
	0x100 | 0x4F,
	0x100 | 0x06,
	0x100 | 0x10,
	0x100 | 0x0B,
	0x100 | 0x2C,
	0x100 | 0x32,
	0x100 | 0x0F,

	0x000 | 0xE1,	// Negative Gamma Control
	0x100 | 0x08,
	0x100 | 0x10,
	0x100 | 0x15,
	0x100 | 0x03,
	0x100 | 0x0E,
	0x100 | 0x03,
	0x100 | 0x32,
	0x100 | 0x34,
	0x100 | 0x44,
	0x100 | 0x07,
	0x100 | 0x10,
	0x100 | 0x0E,
	0x100 | 0x23,
	0x100 | 0x2E,
	0x100 | 0x0F,

	/********* set RGB interface mode *****************/
	0x000 | 0xB6,	// Display Function Control
	0x100 | 0x30,	// set RGB Variant
	0x100 | 0x02,	// GS, SS
	0x100 | 0x3B,

	0x000 | 0xB0,	// Interface Mode Control
	0x100 | 0x00,
	 /**************************************************/
	0x000 | 0x2A,	// Column Address Set
	0x100 | 0x00,
	0x100 | 0x00,
	0x100 | 0x01,
	0x100 | 0x3F,

	0x000 | 0x2B,	// Page Address Set
	0x100 | 0x00,
	0x100 | 0x00,
	0x100 | 0x01,
	0x100 | 0xDF,

	0x000 | 0x21,    // Display Inversion mode On
};

static const struct drm_display_mode dmt035qwnxnt_mode = {
	.clock = 12500,
	.hdisplay = 320,
	.hsync_start = 320 + 3,
	.hsync_end = 320 + 3 + 3,
	.htotal = 320 + 3 + 3 + 3,
	.vdisplay = 480,
	.vsync_start = 480 + 2,
	.vsync_end = 480 + 2 + 2,
	.vtotal = 480 + 2 + 2 + 2,
	.vrefresh = 60,
	.flags = DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC,
};

static const u32 bus_format = MEDIA_BUS_FMT_RGB666_1X18;

static inline struct ili9488 *panel_to_ili9488(struct drm_panel *panel)
{
	return container_of(panel, struct ili9488, panel);
}

static int ili9488_spi_write(struct spi_device *spi, u16 data)
{
	struct spi_transfer xfer = {
		.tx_buf	= &data,
		.len	= 2,
	};

	return spi_sync_transfer(spi, &xfer, 1);
}

static void ili9488_init(struct ili9488 *ctx)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(init_commands); ++i)
		ili9488_spi_write(ctx->spi, init_commands[i]);
}

static int ili9488_wake(struct ili9488 *ctx)
{
	struct spi_device *spi = ctx->spi;

	msleep(10);
	ili9488_spi_write(spi, 0x11); // Sleep OUT
	msleep(120);
	ili9488_spi_write(spi, 0x29); // Display ON
	ili9488_spi_write(spi, 0x2C); // Memory Write

	return 0;
}

static int ili9488_sleep(struct ili9488 *ctx)
{
	struct spi_device *spi = ctx->spi;

	ili9488_spi_write(spi, 0x28); // Display OFF
	msleep(10);
	ili9488_spi_write(spi, 0x10); // Sleep IN
	msleep(120);

	return 0;
}

static int ili9488_power_on(struct ili9488 *ctx)
{
	int ret;

	/* Assert RESET */
	if (ctx->pinctrl) {
		pinctrl_select_state(ctx->pinctrl, ctx->pins_boot);
		gpiod_direction_output(ctx->reset_gpio, 0);
	} else
		gpiod_set_value(ctx->reset_gpio, 0);

	ret = regulator_enable(ctx->power);
	if (ret < 0) {
		dev_err(&ctx->spi->dev, "unable to enable regulators\n");
		return ret;
	}
	usleep_range(10, 20);

	/* De-assert RESET */
	gpiod_set_value(ctx->reset_gpio, 1);

	msleep(5);

	return 0;
}

static int ili9488_power_off(struct ili9488 *ctx)
{
	/* Assert RESET */
	if (ctx->pinctrl) {
		pinctrl_select_state(ctx->pinctrl, ctx->pins_sleep);
		gpiod_direction_output(ctx->reset_gpio, 0);
	} else
		gpiod_set_value(ctx->reset_gpio, 0);

	return regulator_disable(ctx->power);
}

static int ili9488_enable(struct drm_panel *panel)
{
	struct ili9488 *ctx = panel_to_ili9488(panel);

	ili9488_wake(ctx);

	backlight_enable(ctx->backlight);

	return 0;
}

static int ili9488_disable(struct drm_panel *panel)
{
	struct ili9488 *ctx = panel_to_ili9488(panel);

	backlight_disable(ctx->backlight);

	ili9488_sleep(ctx);

	return 0;
}

static int ili9488_prepare(struct drm_panel *panel)
{
	struct ili9488 *ctx = panel_to_ili9488(panel);
	int ret;

	ret = ili9488_power_on(ctx);
	if (ret < 0)
		return ret;

	ili9488_init(ctx);

	return ret;
}

static int ili9488_unprepare(struct drm_panel *panel)
{
	struct ili9488 *ctx = panel_to_ili9488(panel);

	return ili9488_power_off(ctx);
}

static int ili9488_get_modes(struct drm_panel *panel)
{
	struct drm_connector *connector = panel->connector;
	struct drm_display_mode *mode;

	mode = drm_mode_duplicate(panel->drm, &dmt035qwnxnt_mode);

	drm_mode_set_name(mode);

	mode->type = DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_PREFERRED;
	mode->width_mm = 49;
	mode->height_mm = 73;

	connector->display_info.bpc = 6;
	connector->display_info.width_mm = mode->width_mm;
	connector->display_info.height_mm = mode->height_mm;
	connector->display_info.bus_flags = 0;

	drm_display_info_set_bus_formats(&connector->display_info,
					 &bus_format, 1);

	drm_mode_probed_add(connector, mode);

	return 1; /* Number of modes */
}

static const struct drm_panel_funcs ili9488_drm_funcs = {
	.disable = ili9488_disable,
	.unprepare = ili9488_unprepare,
	.prepare = ili9488_prepare,
	.enable = ili9488_enable,
	.get_modes = ili9488_get_modes,
};

static int ili9488_probe(struct spi_device *spi)
{
	struct device *dev = &spi->dev;
	struct device_node *np;
	struct ili9488 *ctx;
	int ret;

	ctx = devm_kzalloc(dev, sizeof(struct ili9488), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	spi->bits_per_word = 9;

	ret = spi_setup(spi);
	if (ret < 0) {
		dev_err(dev, "spi setup failed.\n");
		return ret;
	}

	ctx->spi = spi;

	ctx->power = devm_regulator_get(dev, "power");
	if (IS_ERR(ctx->power)) {
		dev_err(dev, "Couldn't get our power regulator\n");
		return PTR_ERR(ctx->power);
	}

	np = of_parse_phandle(dev->of_node, "backlight", 0);
	if (np) {
		ctx->backlight = of_find_backlight_by_node(np);
		of_node_put(np);

		if (!ctx->backlight)
			return -EPROBE_DEFER;
	}

	ctx->pinctrl = devm_pinctrl_get(dev);
	if (!IS_ERR(ctx->pinctrl)) {
		ctx->pins_boot = pinctrl_lookup_state(ctx->pinctrl,
			PINCTRL_STATE_DEFAULT);
		if (IS_ERR(ctx->pins_boot)) {
			dev_err(dev, "Couldn't get default pinctrl\n");
			return PTR_ERR(ctx->pins_boot);
		}

		ctx->pins_sleep = pinctrl_lookup_state(ctx->pinctrl,
			PINCTRL_STATE_SLEEP);
		if (IS_ERR(ctx->pins_sleep)) {
			dev_err(dev, "Couldn't get sleep pinctrl\n");
			ctx->pins_sleep = NULL;
		}

		pinctrl_select_state(ctx->pinctrl,
			ctx->pins_sleep ? ctx->pins_sleep : ctx->pins_boot);
	}
	else
		ctx->pinctrl = NULL;

	ctx->reset_gpio = devm_gpiod_get(dev, "reset", GPIOD_OUT_LOW);
	if (IS_ERR(ctx->reset_gpio)) {
		dev_err(dev, "Couldn't get our reset GPIO\n");
		return PTR_ERR(ctx->reset_gpio);
	}
	gpiod_set_consumer_name(ctx->reset_gpio, "Panel Reset");

	spi_set_drvdata(spi, ctx);

	drm_panel_init(&ctx->panel);

	ctx->panel.dev = dev;
	ctx->panel.funcs = &ili9488_drm_funcs;

	ret = drm_panel_add(&ctx->panel);

	if (!ret)
		dev_info(dev, "Ilitek 9488 Panel driver Initialized\n");

	return ret;
}

static int ili9488_remove(struct spi_device *spi)
{
	struct ili9488 *ctx = spi_get_drvdata(spi);

	backlight_disable(ctx->backlight);

	ili9488_sleep(ctx);
	ili9488_power_off(ctx);

	drm_panel_remove(&ctx->panel);

	return 0;
}

static const struct of_device_id ili9488_of_match[] = {
	{
		.compatible = "ilitek,ili9488",
		.data = NULL,
	},
	{ }
};
MODULE_DEVICE_TABLE(of, ili9488_of_match);

static const struct spi_device_id ili9341_id[] = {
	{ "ili9488", 0 },
	{ }
};
MODULE_DEVICE_TABLE(spi, ili9341_id);


static struct spi_driver ili9488_driver = {
	.probe = ili9488_probe,
	.remove = ili9488_remove,
	.driver = {
		.name = "panel-ilitek-ili9488",
		.of_match_table = ili9488_of_match,
	},
};
module_spi_driver(ili9488_driver);

MODULE_AUTHOR("Boris Krasnovskiy <boris.krasnovskiy@lairdconnect.com>");
MODULE_DESCRIPTION("ILI9488 LCD panel driver");
MODULE_LICENSE("GPL v2");
