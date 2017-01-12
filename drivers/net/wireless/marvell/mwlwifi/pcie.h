#ifndef _PCIE_H_
#define _PCIE_H_

#include <linux/pci.h>
#include <linux/pcieport_if.h>
#include <linux/interrupt.h>

#include "main.h"

struct mwl_pcie_card {
	struct mwl_priv *priv;
	struct pci_dev *pdev;
	int chip_type;
	void __iomem *iobase0; /* MEM Base Address Register 0  */
	void __iomem *iobase1; /* MEM Base Address Register 1  */
	u32 next_bar_num;
	struct mwl_desc_data desc_data[SYSADPT_NUM_OF_DESC_DATA];
	/* number of descriptors owned by fw at any one time */
	int fw_desc_cnt[SYSADPT_NUM_OF_DESC_DATA];
};

void mwl_pcie_tx_done(unsigned long data);
void mwl_pcie_rx_recv(unsigned long data);

#endif
