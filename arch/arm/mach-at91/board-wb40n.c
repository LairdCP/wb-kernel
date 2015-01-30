/*
 * Copyright (C) 2011 Summit Data Communications, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/types.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/clk.h>

#include <mach/hardware.h>
#include <asm/setup.h>
#include <asm/mach-types.h>
#include <asm/irq.h>

#include <asm/mach/arch.h>
#include <asm/mach/map.h>
#include <asm/mach/irq.h>

#include <mach/board.h>
#include <mach/gpio.h>
#include <linux/gpio_keys.h>
#include <linux/input.h>
#include <mach/at91sam9_smc.h>
#include <mach/system_rev.h>

#include "sam9_smc.h"
#include "generic.h"

static void __init wb40n_init_early(void)
{
	/* Initialize processor: 18.432 MHz crystal */
	at91_initialize(18432000);

	/* DBGU on ttyS0. (Rx & Tx only) */
	at91_register_uart(0, 0, 0);

	/* USART0 on ttyS1. (Rx, Tx, CTS, RTS, DTR, DSR, DCD, RI) */
	at91_register_uart(AT91SAM9260_ID_US0, 1, ATMEL_UART_CTS | ATMEL_UART_RTS
			   | ATMEL_UART_DTR | ATMEL_UART_DSR | ATMEL_UART_DCD
			   | ATMEL_UART_RI);

	/* USART1 on ttyS2. (Rx, Tx, RTS, CTS) */
	at91_register_uart(AT91SAM9260_ID_US1, 2, ATMEL_UART_CTS | ATMEL_UART_RTS);

	/* USART3 on ttyS3 - Bluetooth interface. (Rx, Tx, RTS, CTS) */
	at91_register_uart(AT91SAM9260_ID_US3, 3, ATMEL_UART_CTS | ATMEL_UART_RTS);

	/* set serial console to ttyS0 (ie, DBGU) */
	at91_set_serial_console(0);
}

/*
 * USB Host port
 */
static struct at91_usbh_data __initdata wb40n_usbh_data = {
	.ports		= 2,
};

/*
 * USB Device port
 */
static struct at91_udc_data __initdata wb40n_udc_data = {
	.vbus_pin	= AT91_PIN_PC21,
	.vbus_active_low = 1,
	.pullup_pin	= 0, /* pull-up driven by UDC on the AT91SAM9G20 */
};

/*
 * Audio (BlueTooth PCM interface)
 */
struct ssd40nbt_info {
	int		ssc_id;
	struct clk	*dac_clk;
	char		shortname[32];
};

static struct ssd40nbt_info ssd40nbt_data = {
	.ssc_id		= 0,
	.shortname	= "SSD40NBT Bluetooth Audio Path",
};

#if defined(CONFIG_SND_SSD40NBT)
static void __init ssd40nbt_set_clk(struct ssd40nbt_info *info)
{
	struct clk *pck0;
	struct clk *plla;

	pck0 = clk_get(NULL, "pck0");
	plla = clk_get(NULL, "plla");

	/* SSD40NBT MCK Clock */
	at91_set_B_periph(AT91_PIN_PB16, 0);	/* PCK0 */

	clk_set_parent(pck0, plla);
	clk_put(plla);

	info->dac_clk = pck0;
}
#else
static void __init ssd40nbt_set_clk(struct ssd40nbt_info *info) {}
#endif

/*
 * MACB Ethernet device
 */
static struct at91_eth_data __initdata wb40n_macb_data = {
	.phy_irq_pin	= AT91_PIN_PB1,
	.is_rmii	= 1,
};

static void __init wb40n_add_device_macb(void)
{
	at91_add_device_eth(&wb40n_macb_data);
}

/*
 * NAND flash
 */
static struct mtd_partition __initdata wb40n_nand_partition[] = {
	{
		.name   = "bootstrap",
		.offset = 0,
		.size   = 0x00020000,
	},
	{
		.name	= "u-boot",
		.offset	= MTDPART_OFS_NXTBLK,
		.size	= 0x00060000,
	},
	{
		.name	= "env",
		.offset	= MTDPART_OFS_NXTBLK,
		.size	= 0x00020000,
	},
	{
		.name	= "kernel-a",
		.offset	= MTDPART_OFS_NXTBLK,
		.size	= 0x00200000,
	},
	{
		.name	= "kernel-b",
		.offset	= MTDPART_OFS_NXTBLK,
		.size	= 0x00200000,
	},
	{
		.name	= "rootfs-a",
		.offset	= MTDPART_OFS_NXTBLK,
		.size	= 0x1D80000,
	},
	{
		.name	= "rootfs-b",
		.offset	= MTDPART_OFS_NXTBLK,
		.size	= 0x1D80000,
	},
	{
		.name	= "logs",
		.offset	= MTDPART_OFS_NXTBLK,
		.size	= MTDPART_SIZ_FULL,
	},
};

static struct atmel_nand_data __initdata wb40n_nand_data = {
	.ale		= 21,
	.cle		= 22,
//	.det_pin	= ... not connected
	.rdy_pin	= AT91_PIN_PC13,
	.enable_pin	= AT91_PIN_PC14,
	.parts		= wb40n_nand_partition,
	.num_parts	= ARRAY_SIZE(wb40n_nand_partition),
};

static struct sam9_smc_config __initdata wb40n_nand_smc_config = {
	.ncs_read_setup		= 0,
	.nrd_setup		= 2,
	.ncs_write_setup	= 0,
	.nwe_setup		= 2,

	.ncs_read_pulse		= 4,
	.nrd_pulse		= 4,
	.ncs_write_pulse	= 4,
	.nwe_pulse		= 4,

	.read_cycle		= 7,
	.write_cycle		= 7,

	.mode			= AT91_SMC_READMODE | AT91_SMC_WRITEMODE | AT91_SMC_EXNWMODE_DISABLE,
	.tdf_cycles		= 3,
};

static void __init wb40n_add_device_nand(void)
{
	wb40n_nand_data.bus_width_16 = board_have_nand_16bit();
	/* setup bus-width (8 or 16) */
	if (wb40n_nand_data.bus_width_16)
		wb40n_nand_smc_config.mode |= AT91_SMC_DBW_16;
	else
		wb40n_nand_smc_config.mode |= AT91_SMC_DBW_8;

	/* configure chip-select 3 (NAND) */
	sam9_smc_configure(3, &wb40n_nand_smc_config);

	at91_add_device_nand(&wb40n_nand_data);
}

static unsigned int wb40n_slot_b = 1;

static int __init wb40n_slot_b_setup(char *options)
{
	if (!strcmp(options, "0"))
		wb40n_slot_b = 0;
	else if (!strcmp(options, "no"))
		wb40n_slot_b = 0;
	return 0;
}
__setup("slot_b=", wb40n_slot_b_setup);

/*
 * MCI (SD/MMC)
 * wp_pin and vcc_pin are not connected
 */
#if defined(CONFIG_MMC_ATMELMCI) || defined(CONFIG_MMC_ATMELMCI_MODULE)
static struct mci_platform_data __initdata wb40n_mmc_data = {
	.slot[0] = {
		.bus_width	= 4,
		.detect_pin	= AT91_PIN_PC5,
		.wp_pin		= -ENODEV,
	},
	.slot[1] = {
		.bus_width	= 4,
//		.detect_pin	= AT91_PIN_PC11,
		.wp_pin		= -ENODEV,
	},

};
#else
static struct at91_mmc_data __initdata wb40n_mmc_data = {
	.slot_b		= 1,
	.wire4		= 1,
//	.det_pin	= AT91_PIN_PC11,
};
#endif

static void __init wb40n_add_device_mmc(void)
{
	wb40n_mmc_data.slot_b = wb40n_slot_b,
#if defined(CONFIG_MMC_ATMELMCI) || defined(CONFIG_MMC_ATMELMCI_MODULE)
	at91_add_device_mci(0, &wb40n_mmc_data);
#else
	at91_add_device_mmc(0, &wb40n_mmc_data);
#endif
}

/*
 * LEDs
 */
static struct gpio_led wb40n_leds[] = {
	{	/* stat0 */
		.name			= "stat0",
		.gpio			= AT91_PIN_PA28,
		.active_low		= 1,
		.default_trigger	= "none",
	},
	{	/* stat1 */
		.name			= "stat1",
		.gpio			= AT91_PIN_PA29,
		.active_low		= 1,
		.default_trigger	= "none",
	},
	{	/* led0 */
		.name			= "led0",
		.gpio			= AT91_PIN_PA25,
		.active_low		= 1,
		.default_trigger	= "none",
	},
	{	/* led1 */
		.name			= "led1",
		.gpio			= AT91_PIN_PA26,
		.default_trigger	= "heartbeat",
	},
	{	/* led2 */
		.name			= "led2",
		.gpio			= AT91_PIN_PA27,
		.active_low		= 1,
		.default_trigger	= "none",
	}
};

static void __init wb40n_add_device_gpio_leds(void)
{
	at91_gpio_leds(wb40n_leds, ARRAY_SIZE(wb40n_leds));
}

static void __init wb40n_board_init(void)
{
	/* Serial */
	at91_add_device_serial();
	/* USB Host */
#if defined(CONFIG_MACH_WB40N_REV2)
	at91_set_gpio_output(AT91_PIN_PA22, 0); /* USB current switch enable, low true */
	at91_set_gpio_input(AT91_PIN_PC15, 1); /* USB current limit (FAULT), low true */
#else /* REV3 */
	at91_set_gpio_output(AT91_PIN_PC0, 0); /* USB current switch enable, low true */
	at91_set_gpio_input(AT91_PIN_PC1, 1); /* USB current limit (FAULT), low true */
#endif
	at91_add_device_usbh(&wb40n_usbh_data);
	/* USB Device */
	at91_set_gpio_input(AT91_PIN_PC21, 0); /* USB BUS voltage detect, internal pullup disabled */
	at91_set_gpio_output(AT91_PIN_PC20, 0); /* USB device pullup-enable on H+W board - LEAVE THIS TURNED OFF! */
	at91_add_device_udc(&wb40n_udc_data);
	/* NAND */
	wb40n_add_device_nand();
	/* Ethernet */
	wb40n_add_device_macb();
	/* MMC */
	wb40n_add_device_mmc();
	/* SSC (BlueTooth interface of SSD40NBT) */
	ssd40nbt_set_clk(&ssd40nbt_data);
	at91_add_device_ssc(AT91SAM9260_ID_SSC, ATMEL_SSC_TX | ATMEL_SSC_RD);
	/* LEDs */
	wb40n_add_device_gpio_leds();
	/* Wifi Module config */
	/* SYS_RST_L - De-assert system reset */
	at91_set_gpio_output(AT91_PIN_PB13, 1);
	/* CHIP_PWD_L - De-assert powerdown */
	at91_set_gpio_output(AT91_PIN_PB31, 1);
	/* BT_RST_L - Hold BlueTooth in reset until it is needed by the BT stack */
	at91_set_gpio_output(AT91_PIN_PC11, 0);
}

MACHINE_START(WB40N, "Workgroup Bridge 40N")
	/* Maintainer: ccole@summitdata.com */
	.timer		= &at91sam926x_timer,
	.map_io		= at91_map_io,
	.init_early	= wb40n_init_early,
	.init_irq	= at91_init_irq_default,
	.init_machine	= wb40n_board_init,
MACHINE_END
