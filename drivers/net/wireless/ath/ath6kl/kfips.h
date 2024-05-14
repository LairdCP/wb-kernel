/*
 * Copyright (c) 2019 Ezurio Inc.
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

#ifndef KFIPS_H
#define KFIPS_H

#include <linux/fips.h>

#ifdef CONFIG_ATH6KL_FIPS

/* helper functions to get to aead functions */
#define KFIPS_HDR_TYPE (ar->fips_mode ? WMI_DATA_HDR_DATA_TYPE_802_11 : 0)

void kfips_connect_event(void);
int kfips_data_rx(struct sk_buff **pskb);
int kfips_data_tx(struct sk_buff **pskb, struct net_device *dev);
void kfips_addkey(struct net_device *ndev, u8 key_index,
		  bool pairwise,
		  const u8 * mac_addr,
		  const u8 * key, int keylen,
		  const u8 * seq, int seqlen);
void kfips_delkey(struct net_device *ndev, u8 key_index);
void kfips_deinit(void);

#else

#define KFIPS_HDR_TYPE 0

static inline
void kfips_connect_event(void) {}

static inline
int kfips_data_rx(struct sk_buff **pskb) { return -ENODEV; }

static inline
int kfips_data_tx(struct sk_buff **pskb, struct net_device *dev)
{ return -ENODEV; }

static inline
void kfips_addkey(struct net_device *ndev, u8 key_index,
		  bool pairwise,
		  const u8 * mac_addr,
		  const u8 * key, int keylen,
		  const u8 * seq, int seqlen) {}

static inline
void kfips_delkey(struct net_device *ndev, u8 key_index) {}

static inline
void kfips_deinit(void) {}

#endif /* CONFIG_ATH6KL_FIPS */

#endif
