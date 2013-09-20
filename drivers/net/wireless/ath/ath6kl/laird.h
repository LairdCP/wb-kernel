/*
 * Copyright (c) 2012 Laird Technologies, Inc.
 */
#ifndef LAIRD_DRIVER_H
#define LAIRD_DRIVER_H

// Laird version is 32bit value.  Parsed in the form w.x.y.z.  
// increment y.z as needed for each change
#define LAIRD_DRV_VERSION 0x03040006

#ifdef LAIRD_FIPS
#include <linux/etherdevice.h>
#include "laird_common.h"

extern bool fips_mode;
extern const laird_register_data_t *laird_register_data;

// receive: laird_skb_rx will return non-zero to let driver process packet
static inline int  laird_skb_rx_prep(struct sk_buff *skb, pfn_laird_skb_rx_continue pfncb)
{
	if (!laird_register_data) return -1;
	if (!laird_register_data->pfn_rx_prep) return -1;
	return (*(laird_register_data->pfn_rx_prep))(skb, pfncb);
}

// transmit: prepare sk_buff -- encryption/encapsulation
static inline int laird_skb_encrypt_prep(struct sk_buff *skb, struct net_device *dev, int wmm, pfn_laird_skb_tx_continue pfncb)
{
	if (!laird_register_data) return -1;
	if (!laird_register_data->pfn_tx_prep) return -1;
	return (*(laird_register_data->pfn_tx_prep))(skb, dev, wmm, pfncb);
}

// transmit: flow control
static inline void laird_stop_queue(struct net_device *dev)
{
	if (!laird_register_data) return;
	if (!laird_register_data->pfn_stop_queue) return;
	return (*(laird_register_data->pfn_stop_queue))(dev);
}

static inline void laird_wake_queue(struct net_device *dev)
{
	if (!laird_register_data) return;
	if (!laird_register_data->pfn_wake_queue) return;
	(*(laird_register_data->pfn_wake_queue))(dev);
}

// key operations
static inline void laird_addkey(struct net_device *ndev, u8 key_index,
                         bool pairwise,
                         const u8 *mac_addr,
                         const u8 *key, int keylen,
                         const u8 *seq, int seqlen)
{
	if (!laird_register_data) return;
	if (!laird_register_data->pfn_addkey) return;
	(*(laird_register_data->pfn_addkey))
		(ndev, key_index, pairwise, mac_addr, key, keylen, seq, seqlen);
}

static inline void laird_delkey(struct net_device *ndev, u8 key_index)
{
	if (!laird_register_data) return;
	if (!laird_register_data->pfn_delkey) return;
	(*(laird_register_data->pfn_delkey))(ndev, key_index);
}

// bssid
static inline void laird_setbssid(const u8 *bssid)
{
	if (!laird_register_data) return;
	if (!laird_register_data->pfn_setbssid) return;
	(*(laird_register_data->pfn_setbssid))(bssid);
}

// stopping the driver (rmmod) support
static inline void laird_stop_txrx(void)
{
	if (!laird_register_data) return;
	if (!laird_register_data->pfn_stop_txrx) return;
	(*(laird_register_data->pfn_stop_txrx))();
}

#endif // LAIRD_FIPS
#endif /* LAIRD_DRIVER_H */
