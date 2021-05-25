/*
 * Copyright (c) 2019 Laird Connectivity Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef LAIRD_KFIPS_H
#define LAIRD_KFIPS_H

#ifdef CONFIG_ATH6KL_LAIRD_FIPS

#include <linux/fips.h>

// helper functions to get to aead functions
#define LAIRD_HDR_TYPE (ar->fips_mode ? WMI_DATA_HDR_DATA_TYPE_802_11 : 0)

void laird_connect_event(void);
int laird_data_rx(struct sk_buff **pskb);
int laird_data_tx(struct sk_buff **pskb, struct net_device *dev);
void laird_addkey(struct net_device *ndev, u8 key_index,
		  bool pairwise,
		  const u8 * mac_addr,
		  const u8 * key, int keylen,
		  const u8 * seq, int seqlen);
void laird_delkey(struct net_device *ndev, u8 key_index);
void laird_deinit(void);

#else

#define LAIRD_HDR_TYPE 0

static inline
void laird_connect_event(void) { return; }

static inline
int laird_data_rx(struct sk_buff **pskb) { return -ENODEV; }

static inline
int laird_data_tx(struct sk_buff **pskb, struct net_device *dev)
{ return -ENODEV; }

static inline
void laird_addkey(struct net_device *ndev, u8 key_index,
		  bool pairwise,
		  const u8 * mac_addr,
		  const u8 * key, int keylen,
		  const u8 * seq, int seqlen) {}

static inline
void laird_delkey(struct net_device *ndev, u8 key_index) {}

static inline
void laird_deinit(void) {}

#endif /* CONFIG_ATH6KL_LAIRD_FIPS */

#endif
