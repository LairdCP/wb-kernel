obj-$(CONFIG_MWLWIFI)	+= mwlwifi.o
mwlwifi-y			+= main.o
mwlwifi-y			+= mac80211.o
mwlwifi-y			+= fwdl.o
mwlwifi-y			+= fwcmd.o
mwlwifi-y			+= tx.o
mwlwifi-y			+= rx.o
mwlwifi-y			+= isr.o
mwlwifi-$(CONFIG_THERMAL)	+= thermal.o
mwlwifi-$(CONFIG_DEBUG_FS)	+= debugfs.o

obj-$(CONFIG_MWLWIFI_PCIE) += mwlwifi_pcie.o
mwlwifi_pcie-y += pcie.o

obj-$(CONFIG_MWLWIFI_SDIO) += mwlwifi_sdio.o
mwlwifi_sdio-y += sdio.o

ccflags-y += -D__CHECK_ENDIAN__
