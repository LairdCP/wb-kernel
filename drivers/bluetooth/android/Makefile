# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Linux Bluetooth Android device drivers.
#

obj-$(CPTCFG_BT_88W8997_MCHAR_USB) += bt8997usb.o
bt8997usb-y	+= bt_main.o bt_usb.o bt_proc.o mbt_char.o bt_init.o

obj-$(CPTCFG_BT_88W8997_MCHAR_SDIO) += bt8997sd.o
bt8997sd-y += bt_main_nxpsd.o bt_sdiommc_nxpsd.o bt_proc_nxpsd.o \
	mbt_char_nxpsd.o bt_init_nxpsd.o
