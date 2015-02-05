/*
 * Copyright (c) 2013 Laird, Inc.
 * Licensed under GPLv2.
 */

#ifndef LAIRD_COMMON_H
#define LAIRD_COMMON_H


/* res<0 to fail packet, else continue receive */
typedef void (*pfn_laird_skb_rx_continue) (struct sk_buff * skb, int res);

/* transmit: continue transmit after encryption/encapsulation
 * routine in driver
 * isfips=-1 to fail the skb
 * isfips=1 to indicate that skb has been encrypted/encapsulated in 802.11
 */
typedef int (*pfn_laird_skb_tx_continue) (struct sk_buff * skb,
					  struct net_device * dev, int isfips);

/* receive: laird_skb_rx will return non-zero to let driver process packet
 * return<0 if a failure occurs
 * 0 on success and pfncb will be called later (possibly not with same skb)
 */
typedef int (*pfn_laird_skb_rx_prep) (struct sk_buff * skb,
				      pfn_laird_skb_rx_continue pfncb);

/* transmit: prepare sk_buff -- encryption/encapsulation
 * return<0 if a failure occurs
 * 0 on success and pfncb will be called later (possibly not with same skb)
 */
typedef int (*pfn_laird_skb_tx_prep) (struct sk_buff * skb,
				      struct net_device * dev, int wmm,
				      pfn_laird_skb_tx_continue pfncb);

/* transmit: flow control */
typedef void (*pfn_laird_stop_queue) (struct net_device * dev);
typedef void (*pfn_laird_wake_queue) (struct net_device * dev);

/* key operations */
typedef void (*pfn_laird_addkey) (struct net_device * ndev, u8 key_index,
				  bool pairwise,
				  const u8 * mac_addr,
				  const u8 * key, int keylen,
				  const u8 * seq, int seqlen);
typedef void (*pfn_laird_delkey) (struct net_device * ndev, u8 key_index);

/* bssid */
typedef void (*pfn_laird_setbssid) (const u8 * bssid);

/* stopping the driver (rmmod) support */
typedef int (*pfn_laird_stop_txrx) (void);

typedef struct {
	pfn_laird_skb_rx_prep pfn_rx_prep;
	pfn_laird_skb_tx_prep pfn_tx_prep;
	pfn_laird_stop_queue pfn_stop_queue;
	pfn_laird_wake_queue pfn_wake_queue;
	pfn_laird_addkey pfn_addkey;
	pfn_laird_delkey pfn_delkey;
	pfn_laird_setbssid pfn_setbssid;
	pfn_laird_stop_txrx pfn_stop_txrx;
} laird_register_data_t;

/* external driver function that the laird module will call */
extern int ath6kl_laird_register(const laird_register_data_t * ptr);

#endif /* LAIRD_COMMON_H */
