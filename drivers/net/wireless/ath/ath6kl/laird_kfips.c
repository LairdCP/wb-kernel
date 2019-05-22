/*
 * Copyright (c) 2019 Laird Connect Inc.
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

/* Laird: Single Station 802.11 data packets using Kernel Crypto */

#include "core.h"
#include "debug.h"
#include "htc-ops.h"
#include "trace.h"

#include "laird_fips.h"
#ifdef CONFIG_ATH6KL_LAIRD_FIPS

#define is_ethertype(type_or_len)	((type_or_len) >= 0x0600)

struct _llc_snap_hdr {
	u8 dsap;
	u8 ssap;
	u8 cntl;
	u8 org_code[3];
	__be16 eth_type;
} __packed;

static const unsigned char llc_snap[] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };

#if 1
#ifndef __packed
#define __packed __attribute((packed))
#endif

struct laird_wlanhdr {
	u8 fc[2];
#define FC0_FTYPE      (3<<2)
#define FC0_FTYPE_DATA (2<<2)
#define FC0_STYPE_QOS  (1<<7)
#define FC1_TODS       (1<<0)
#define FC1_FROMDS     (1<<1)
#define FC1_MOREFRAGS  (1<<2)
#define FC1_PROTECTED  (1<<6)
	__le16 dur;
	u8 addr1[6];
	u8 addr2[6];
	u8 addr3[6];
	u8 seq[2];
#define SEQ0_FRAG (0xF)
} __packed;

struct laird_wlanhdr_qos {
	u8 fc[2];
	__le16 dur;
	u8 addr1[6];
	u8 addr2[6];
	u8 addr3[6];
	u8 seq[2];
	u8 qos[2];
#define QOS0_TID (0xF)
#define QOS0_AMSDU (1<<7)
} __packed;
#define WLANHDR_QOS_PAD 2

#endif

static int wlanhdrlen(struct laird_wlanhdr *hdr);

#define LAIRD_SIMULT_REASSEMBLE_BUFS	16

// sequence id for matching fragments
// 0 indicates an invalid/empty entry
// (for a valid entry b24 or b25 will be set)
// b0..3 = fragnum
// b4..15 = seqnum
// b16..19 = qostid
// b24 = non-qos packet
// b25 = qos packet
typedef long seqid_t;

static int seqid_is_same_seq(seqid_t seq1, seqid_t seq2)
{
	seq1 &= ~0xF;
	seq2 &= ~0xF;
	return (seq1==seq2);
}

static int seqid_is_first_frag(seqid_t seq)
{
	return ((seq & 0xF)==0);
}

static int seqid_is_next(seqid_t seq1, seqid_t seq2)
{
	return (seq1==(seq2-1));
}

// create seqid from packet
static seqid_t seqid_from_skb(struct sk_buff *skb)
{
	seqid_t seqid;
	struct laird_wlanhdr *hdr = (void*)skb->data;
	int is_qos;
	if (skb->len < sizeof(*hdr)) return 0;
	is_qos = hdr->fc[0] & FC0_STYPE_QOS;
	if (is_qos) {
		struct laird_wlanhdr_qos *hdrq = (void*)hdr;
		if (skb->len < sizeof(*hdrq)) return 0;
		seqid = 2<<8 | (hdrq->qos[0] & QOS0_TID);
	} else {
		seqid = 1<<8;
	}
	seqid <<=8;
	seqid |= hdr->seq[1];
	seqid <<= 8;
	seqid |= hdr->seq[0];
	return seqid;
}

/*======================================================================*/
typedef struct {
	struct sk_buff *skb;
	seqid_t seqid;
} frag_entry_t;

static struct {
	frag_entry_t frag[LAIRD_SIMULT_REASSEMBLE_BUFS]; // array of fragments
	int index; // next index to insert at
} _rdata;

static int index_next(int index)
{
	return (index + 1) % LAIRD_SIMULT_REASSEMBLE_BUFS;
}

static int index_prev(int index)
{
	return (index - 1 + LAIRD_SIMULT_REASSEMBLE_BUFS) % LAIRD_SIMULT_REASSEMBLE_BUFS;
}

static void frag_entry_create(frag_entry_t *fd, struct sk_buff *skb, seqid_t seqid)
{
	fd->skb = skb;
	if (fd->skb) fd->seqid = seqid;
}

static void frag_entry_free(frag_entry_t *fd)
{
	fd->seqid = 0;
	if (fd->skb)
		dev_kfree_skb(fd->skb);
	fd->skb = NULL;
}

/*======================================================================*/
// return matching fragment entry if one exists
static frag_entry_t *lairdReassemblyArraySearch(seqid_t seqid)
{
	int i;
	int index;

	// note, need to search all entries
	// as there may be holes when frags complete out of order
	index = _rdata.index;
	for (i=LAIRD_SIMULT_REASSEMBLE_BUFS; i--; ) {
		index = index_prev(index);
		if (seqid_is_same_seq(_rdata.frag[index].seqid, seqid)) {
			// found a match
			return &_rdata.frag[index];
		}
	}
	return NULL; // failed to find a match
}

// create a new frag (delete old matching frag)
// always save to newest frag entry
static int lairdReassemblyNewFrag(frag_entry_t *frag, struct sk_buff *skb, seqid_t seqid)
{
	if (frag) {
		frag_entry_free(frag); // free the old entry if a match was found
	}
	// use the next entry
	frag = &_rdata.frag[_rdata.index];
	frag_entry_free(frag); // free the new entry if it was in use
	frag_entry_create(frag, skb, seqid);
	if (!frag->skb) {
		// failed to store the skb
		return -ENOMEM;
	}
	// advance the fragment index
	_rdata.index = index_next(_rdata.index);
	// fragment is not done
	return 0;
}

// append the skb payload to frag, if it is the next fragment
#define FC1_FRAG_MATCH (FC1_TODS|FC1_FROMDS|FC1_PROTECTED)
static int lairdReassemblyAppendFrag(frag_entry_t *frag, struct sk_buff *from_skb, seqid_t seqid)
{
	struct sk_buff *to_skb;
	struct laird_wlanhdr *to_hdr;
	struct laird_wlanhdr *from_hdr;
	char* destPtr;
	char* srcPtr;
	int len;
	short do_decrypt;

	if (!seqid_is_next(frag->seqid, seqid)) {
		// not the next fragment
		return -1;
	}

	to_skb = frag->skb;
	to_hdr = (void*)to_skb->data;
	from_hdr = (void*)from_skb->data;

	// note, seq[0], seq[1] and qostid/non-qos have already been verified to match

	if ((from_hdr->fc[1] & FC1_FRAG_MATCH) != (to_hdr->fc[1] & FC1_FRAG_MATCH)) {
		return -1;
	}
	if (memcmp(from_hdr->addr1, to_hdr->addr1, 18) != 0) {
		return -1;
	}
	do_decrypt = from_hdr->fc[1] & FC1_PROTECTED;

	/* Calculate the destination pointer for the copy */
	destPtr = to_skb->data + to_skb->len;

	/* Calculate the source pointer for the copy */
	len = wlanhdrlen(from_hdr);
	if  (do_decrypt) {
		len+=8;
	}
	srcPtr = (char *)from_hdr + len;

	/* Calculate the number of bytes to copy */
	len  = from_skb->len - len;
	if (len <= 0)
		return -1;

	if (skb_tailroom(to_skb) < len) {
		return -1;
	}
	skb_put(to_skb, len);
	memcpy(destPtr, srcPtr, len);

	// update the fragment seqid and wlanhdr
	frag->seqid = seqid;
	to_hdr->seq[0] = from_hdr->seq[0];
	to_hdr->seq[1] = from_hdr->seq[1];
	to_hdr->fc[1]  = from_hdr->fc[1];

	if (to_hdr->fc[1] & FC1_MOREFRAGS) {
		return 1;
	}
	return 0;
}

DEFINE_SPINLOCK(laird_defrag_spinlock);

// if an error is returned, the caller still owns the skb
//
// if an error does not occur, the incoming skb is consumed
// if the incoming skb does not complete a fragment, *skbin = NULL
// if the incoming skb completes a fragment, *skbin returns a different skb
static int lairdReassemblyProcess(struct sk_buff **skbin)
{
	struct sk_buff *skb = *skbin;
	frag_entry_t *frag;
	seqid_t seqid;
	int res;

	if (!skbin)
		return -1;

	skb = *skbin;
	if (!skb || !skb->data) {
		return -1;
	}

	seqid = seqid_from_skb(skb);
	if (!seqid) {
		return -1;
	}

	spin_lock_bh(&laird_defrag_spinlock);

	frag = lairdReassemblyArraySearch(seqid);
	if (seqid_is_first_frag(seqid)) {
		res = lairdReassemblyNewFrag(frag, skb, seqid);
		if (res) {
			spin_unlock_bh(&laird_defrag_spinlock);
			return res;
		}
		// the skb is now held by the reassembly code
		*skbin = NULL;
		spin_unlock_bh(&laird_defrag_spinlock);
		return 0;
	}
	if (!frag) {
		// no match found, discard fragment, return as error
		spin_unlock_bh(&laird_defrag_spinlock);
		return -1;
	}
	res = lairdReassemblyAppendFrag(frag, skb, seqid);
	if (res < 0) {
		spin_unlock_bh(&laird_defrag_spinlock);
		return res;
	}
	// fragment was consumed
	dev_kfree_skb(skb);
	if (res) {
		// defragmentation is not complete
		*skbin = NULL;
		spin_unlock_bh(&laird_defrag_spinlock);
		return 0;
	}
	// defragmentation is complete, return the packet
	*skbin = frag->skb;
	frag->skb = NULL;
	frag_entry_free(frag);
	spin_unlock_bh(&laird_defrag_spinlock);
	return 0;
}


static int lairdReassemblyPurgeAll(void)
{
	int index;

	spin_lock_bh(&laird_defrag_spinlock);
	for(index=0; index<LAIRD_SIMULT_REASSEMBLE_BUFS; index++) {
		frag_entry_free(&_rdata.frag[index]);
	}
	spin_unlock_bh(&laird_defrag_spinlock);
	return 0;
}

typedef u64 lrd_seq_t;
typedef struct {
	int refcount;
	u8 key[16];
	int keylen;
	lrd_seq_t rsc;
	lrd_seq_t rscqos[16];
	u64 tsc;
	void *tfm;
} lrd_key_t;


// call without spinlock (tfm alloc is non-atomic)
static lrd_key_t *lrd_key_malloc(const u8 *key, int keylen)
{
	void *tfm;
	lrd_key_t *pk;
	pk = kmalloc(sizeof(*pk), GFP_ATOMIC);
	if (pk) {
		memset(pk, 0, sizeof(*pk));
		tfm = _ccm_key_setup_encrypt("ccm(aes)", key, keylen, 8);
		if (IS_ERR(tfm)) {
			// failed to initialize crypto
			printk(KERN_ERR "%s: 802.11 ccmp key setup failed", __func__);
			tfm = NULL;
		}
		pk->tfm = tfm;
		if (!tfm) {
			kfree(pk);
			pk = NULL;
		}
	}
	return pk;
}

// should be called with spinlock
static void lrd_key_unref(lrd_key_t *pk)
{
	if (!pk)
		return;
	if (--pk->refcount < 0) {
		_ccm_key_free(pk->tfm);
		memset(pk, 0, sizeof(*pk));
		kfree(pk);
	}
}


typedef struct {
	lrd_key_t *pcur; // current key
} lrd_key_index_t;

typedef struct {
	u8 addr[6];
	int len;
} lrd_bssid_info_t;

static struct {
	lrd_key_index_t ki[4];
	u8 tx_index;
	lrd_bssid_info_t bssid_info;
} __glob;

DEFINE_SPINLOCK(laird_key_spinlock);

/* set the user priority (up) to be used, -1 for non-wmm packets */
/* note: skb is an ethernet packet */
static int laird_skb_up(struct sk_buff *skb)
{
	struct ethhdr *eth_hdr;
	__be16 type;
	int up;

	up = 0;
	if (skb->priority >= 256) {
		up = skb->priority - 256;
		if (up > 7)
			up = 0;
	}
	if (skb->len >= sizeof(struct ethhdr) + 2) {
		eth_hdr = (struct ethhdr *)skb->data;
		type = eth_hdr->h_proto;
		if (type == htons(ETH_P_IP)) {
			u8 *iph = (u8 *) (eth_hdr + 1);
			int upip;
			if (iph[0] >> 4 == 4) {
				upip = iph[1] >> 5;
				if (upip > up)
					up = upip;
			}
		}
	}
	return up;
}

// build associated data and return length
static int ecr_set_aad(struct laird_wlanhdr *hdr, u8 *aad, u8 *b_0)
{
	int aadlen = 22;
	u8 up = 0;
	u8 *iv = (u8*)(hdr + 1);
	aad[2+0] = hdr->fc[0] & ~0x70;
	aad[2+1] = hdr->fc[1] & ~0x38;
	memcpy(&aad[2+2], &hdr->addr1[0], 18);
	aad[2+20] = hdr->seq[0] & SEQ0_FRAG;
	aad[2+21] = 0;
	if (hdr->fc[0] & FC0_STYPE_QOS) {
		struct laird_wlanhdr_qos *hdrq = (void*)hdr;
		aad[2+22] = hdrq->qos[0] & (QOS0_TID|QOS0_AMSDU);
		aad[2+23] = 0;
		aadlen = 24;
		iv += 2 + WLANHDR_QOS_PAD;
		up = hdrq->qos[0] & QOS0_TID;
	}
	aad[0] = 0;
	aad[1] = aadlen;
	memset(&aad[aadlen+2], 0, CCM_AAD_LEN - (aadlen+2));

	b_0[0] = 0x1;
	b_0[1] = up; /* qos_tid | (mgmt << 4); */
	memcpy(&b_0[2], hdr->addr2, ETH_ALEN);
	b_0[8]  = iv[7];
	b_0[9]  = iv[6];
	b_0[10] = iv[5];
	b_0[11] = iv[4];
	b_0[12] = iv[1];
	b_0[13] = iv[0];
	return aadlen;
}

static int wlanhdrlen(struct laird_wlanhdr *hdr)
{
	if (hdr->fc[0] & FC0_STYPE_QOS) {
		return sizeof(*hdr) + 2 + WLANHDR_QOS_PAD;
	}
	return sizeof(*hdr);
}

// return non-zero if the transmit encryption key is set
static int laird_using_encrypt(void)
{
	lrd_key_t *pk;
	u8 tx_index;
	int res = 0;
	spin_lock_bh(&laird_key_spinlock);
	tx_index = __glob.tx_index;
	if (tx_index < 4) {
		pk = __glob.ki[tx_index].pcur;
		if (pk) {
			res = 1;
		}
	}
	spin_unlock_bh(&laird_key_spinlock);
	return res;
}

static int laird_skb_encrypt(struct sk_buff *skb)
{
	struct laird_wlanhdr *wlan_hdr = (void*)skb->data;
	u8 b_0[AES_BLOCK_SIZE];
	u8 aad[CCM_AAD_LEN];
	int aadlen;
	u8 *iv;
	u8 *pdata;
	u8 *pmic;
	lrd_key_t *pk;
	u64 tsc;
	u8 tx_index;
	int res;

	spin_lock_bh(&laird_key_spinlock);
	tx_index = __glob.tx_index;
	if (tx_index < 4) {
		pk = __glob.ki[tx_index].pcur;
		if (pk) {
			pk->refcount++;
			tsc = ++pk->tsc;
		}
	} else {
		pk = NULL;
	}
	spin_unlock_bh(&laird_key_spinlock);

	if (!pk) {
		// no key for transmit
		return -EINVAL;
	}

	iv = (u8*)wlan_hdr + wlanhdrlen(wlan_hdr);
	iv[0] = (tsc >> 0) & 0xFF;
	iv[1] = (tsc >> 8) & 0xFF;
	iv[2] = 0;
	iv[3] = (1<<5) | (tx_index<<6);
	iv[4] = (tsc >> 16) & 0xFF;
	iv[5] = (tsc >> 24) & 0xFF;
	iv[6] = (tsc >> 32) & 0xFF;
	iv[7] = (tsc >> 40) & 0xFF;

	aadlen = ecr_set_aad(wlan_hdr, aad, b_0) ;
	pdata = (u8*)wlan_hdr + wlanhdrlen(wlan_hdr) + 8;
	pmic = (u8*)(skb->data) + skb->len - 8;
	res = _ccm_encrypt(pk->tfm, b_0, aad+2, aadlen,
					   pdata, pmic - pdata, pmic);
	if (res) {
		// encrypt failure
	}

	spin_lock_bh(&laird_key_spinlock);
	lrd_key_unref(pk);
	spin_unlock_bh(&laird_key_spinlock);

	return res;
}


static int laird_skb_replay_check(struct laird_wlanhdr *wlan_hdr, lrd_key_t *pk)
{
	u8 *iv = (u8*)(wlan_hdr + 1);
	lrd_seq_t pn;
	lrd_seq_t *prsc;

	if (wlan_hdr->fc[0] & FC0_STYPE_QOS) {
		struct laird_wlanhdr_qos *hdrq = (void*)wlan_hdr;
		iv += 2 + WLANHDR_QOS_PAD;
		prsc = &pk->rscqos[hdrq->qos[0] & QOS0_TID];
	} else {
		prsc = &pk->rsc;
	}
	pn = iv[7];
	pn = (pn << 8) | iv[6];
	pn = (pn << 8) | iv[5];
	pn = (pn << 8) | iv[4];
	pn = (pn << 8) | iv[1];
	pn = (pn << 8) | iv[0];

	if (pn <= *prsc)
		return -1;
	*prsc = pn;
	return 0;
}

static int laird_skb_decrypt(struct sk_buff *skb)
{
	struct laird_wlanhdr *wlan_hdr = (void*)skb->data;
	u8 *iv = (u8*)wlan_hdr + wlanhdrlen(wlan_hdr);
	u8 b_0[AES_BLOCK_SIZE];
	u8 aad[CCM_AAD_LEN];
	int aadlen;
	u8 *pdata;
	u8 *pmic;
	int res;

	lrd_key_t *pk = NULL;

	spin_lock_bh(&laird_key_spinlock);
	pk = __glob.ki[iv[3]>>6].pcur;
	if (pk)
		pk->refcount++;
	spin_unlock_bh(&laird_key_spinlock);

	if (!pk) {
		return -EINVAL;
	}

	aadlen = ecr_set_aad(wlan_hdr, aad, b_0) ;
	pdata = (u8*)wlan_hdr + wlanhdrlen(wlan_hdr) + 8;
	pmic = (u8*)(skb->data) + skb->len - 8;

	res = _ccm_decrypt(pk->tfm, b_0, aad+2, aadlen,
						pdata, pmic - pdata, pmic);

	if (res) {
		// decrypt failure
	} else {
		res = laird_skb_replay_check(wlan_hdr, pk);
		if (res) {
			// replay failure
		}
	}

	spin_lock_bh(&laird_key_spinlock);
	lrd_key_unref(pk);
	spin_unlock_bh(&laird_key_spinlock);

	return res;
}

int laird_data_tx(struct sk_buff **skbin, struct net_device *dev)
{
	struct ath6kl *ar = ath6kl_priv(dev);
	struct ath6kl_vif *vif = netdev_priv(dev);
	int wmm = ar->wmi->is_wmm_enabled;
	struct sk_buff *skb = *skbin;
	struct ethhdr *eth_hdr;
	//struct ieee80211_hdr *hdr;
	struct laird_wlanhdr *wlan_hdr;
	struct _llc_snap_hdr *llc_hdr;
	u16 type;
	int res = 0;
	size_t size;
	int up;
	int do_encrypt = 1;

	/* if not in fips_mode use the normal routine */
	if (!fips_mode)
		return 0;

	if (skb->len < sizeof(struct ethhdr))
		return -EINVAL;

	eth_hdr = (struct ethhdr *) skb->data;
	type = htons(eth_hdr->h_proto);

	if (type == ETH_P_PAE) {
		// EAPOL packet -- may be sent encrypted or unencrypted
		do_encrypt = laird_using_encrypt();
	}

	if (skb_cloned(skb) ||
		skb_headroom(skb) < dev->needed_headroom ||
		skb_tailroom(skb) < dev->needed_tailroom)
	{
		/* make a copy -- cloned, or insufficient head/tail room */
		skb = skb_copy_expand(skb, dev->needed_headroom,
							  dev->needed_tailroom, GFP_ATOMIC);
		if (!skb) {
			skb = *skbin;
			res = -ENOMEM;
			goto fail;
		}
		// using new skb
		eth_hdr = (struct ethhdr *) skb->data;
	}

	size = sizeof(struct laird_wlanhdr) - sizeof(struct ethhdr);

	if (is_ethertype(type)) {
		llc_hdr = ((struct _llc_snap_hdr *)(eth_hdr + 1)) - 1;
		size += sizeof(*llc_hdr);
	} else {
		llc_hdr = NULL;
	}
	if (ar->wmi->is_wmm_enabled) {
		size += 2 + WLANHDR_QOS_PAD;
		up = laird_skb_up(skb);
	}

	if (do_encrypt) {
		// allocate room for IV, filled in during encrypt
		size += 8;
		// allocate room for ICV, filled in during encrypt
		if (skb_tailroom(skb) < 8) {
			res = -ENOMEM;
			goto fail;
		}
		skb_put(skb, 8);
	}
	if (skb_headroom(skb) < size) {
		res = -ENOMEM;
		goto fail;
	}
	skb_push(skb, size);

	wlan_hdr = (struct laird_wlanhdr *) skb->data;
	{
		u8 da[6];
		memcpy(da, &eth_hdr->h_dest, 6);
		// note: use memmove as the locations may overlap
		memmove(wlan_hdr->addr2, &eth_hdr->h_source, 6);
		memcpy(wlan_hdr->addr3, da, 6);
		memcpy(wlan_hdr->addr1, vif->bssid, 6);
	}
	wlan_hdr->fc[0] = FC0_FTYPE_DATA | (wmm ? FC0_STYPE_QOS : 0); // data
	wlan_hdr->fc[1] = FC1_TODS; // tods
	if (do_encrypt) wlan_hdr->fc[1] |= FC1_PROTECTED; // encrypted
	wlan_hdr->dur = 0;
	wlan_hdr->seq[0] = 0;
	wlan_hdr->seq[1] = 0;
	if (ar->wmi->is_wmm_enabled) {
		struct laird_wlanhdr_qos *hdrq = (void*)wlan_hdr;
		hdrq->qos[0] = up;
		hdrq->qos[1] = 0;
	}

	// convert DIX to 802.3
	if (llc_hdr) {
		llc_hdr = ((struct _llc_snap_hdr *)(eth_hdr + 1)) - 1;
		memcpy(llc_hdr, llc_snap, sizeof(llc_snap));
		// note, type is already present from ethhdr
	}

	if (do_encrypt) {
		res = laird_skb_encrypt(skb);
		if (res) {
			// encryption failure
			goto fail;
		}
	}

	if (skb != *skbin) {
		/* if we mad a copy of the skb... free the old skb, return new skb */
		dev_kfree_skb(*skbin);
		*skbin = skb;
	}
	return 1;

fail:
	if (skb != *skbin) {
		/* if we made a copy of the skb... free the new skb */
		dev_kfree_skb(skb);
	}
	// error_stat_tx(res);
	return res;
}


int laird_data_rx(struct sk_buff **skbin)
{
	struct sk_buff *skb = *skbin;
	struct laird_wlanhdr *wlan_hdr;
	int res = 0;
	u8 *pm;
	int mlen;

	int do_decrypt, is_qos, hdrlen, fragNum, is_amsdu;

	/* if not in fips_mode use the normal routine */
	if (!fips_mode) {
		return 0;
	}

	if (skb->len < sizeof(struct laird_wlanhdr)) {
		return -EINVAL;
	}

	wlan_hdr = (void*)skb->data;
	if ((wlan_hdr->fc[0] & FC0_FTYPE) != FC0_FTYPE_DATA) {
		return -EINVAL;
	}
	if ((wlan_hdr->fc[1] & (FC1_TODS|FC1_FROMDS)) != FC1_FROMDS) {
		return -EINVAL;
	}

	do_decrypt = wlan_hdr->fc[1] & 0x40;
	is_qos = wlan_hdr->fc[0] & FC0_STYPE_QOS;
	hdrlen = 24 + (is_qos ? 4 : 0); // qos field plus 2 pad bytes
	fragNum = wlan_hdr->seq[0] & SEQ0_FRAG;
	is_amsdu = 0;

	mlen = skb->len - hdrlen - (do_decrypt ? 16 : 0);
	pm = (u8*)wlan_hdr + hdrlen + (do_decrypt ? 8 : 0);
	if (mlen <= 0) {
		// packet is too short
		return -EINVAL;
	}

	if (is_qos) {
		struct laird_wlanhdr_qos *hdrq = (void*)wlan_hdr;
		if (hdrq->qos[0] & QOS0_AMSDU) {
			is_amsdu = 1;
			if (!do_decrypt) {
				// discard unencrypted AMSDU
				// only EAPOL are unencrypted and should not be AMSDU
				return -EINVAL;
			}
		}
	}

	if (!do_decrypt) {
		if (laird_using_encrypt()) {
			// transmit key is set, all receive should be encrypted
			return -EINVAL;
		}
		if (fragNum == 0) {
			struct _llc_snap_hdr *llc = (void *)pm;
			u16 type;
			if (mlen < sizeof(*llc)) {
				return -EINVAL;
			}
			if (0 != memcmp(llc, llc_snap, sizeof(llc_snap))) {
				return -EINVAL;
			}
			type = htons(llc->eth_type);
			if (type != ETH_P_PAE) {
				return -EINVAL;
			}
		}
	} else {
		res = laird_skb_decrypt(skb);
		if (res) {
			// decrypt failure
			return -EINVAL;
		}
		// remove the mic
		skb_trim(skb, skb->len - 8);
	}

	/* If this is part of a fragmented buffer, pass to reassembly */
	if ((fragNum > 0) || (wlan_hdr->fc[1] & FC1_MOREFRAGS)) {
		if (is_amsdu) {
			return -EINVAL;
		}
		res = lairdReassemblyProcess(skbin);
		if (res < 0) {
			/* The skb was consumed by reassembly */
			return -EINVAL;
		}
		// defragmentation may return a different skb
		skb = *skbin;
		if (!skb) {
			return 1;
		}
		wlan_hdr = (void*)skb->data;
	}

	// change header from 802.11 to ethernet, and remove IV
	{
		struct ethhdr eh;
		int pulllen = hdrlen + (do_decrypt ? 8 : 0);
		if (is_amsdu) {
			pulllen += 2;
		} else {
			pulllen +=  sizeof(struct _llc_snap_hdr);
		}
		if (skb->len < pulllen) {
			return -EINVAL;
		}
		memcpy(eh.h_dest, wlan_hdr->addr1, sizeof(eh.h_dest));
		memcpy(eh.h_source, wlan_hdr->addr3, sizeof(eh.h_source));
		skb_pull(skb, pulllen - sizeof(eh));
		memcpy(skb->data, &eh, 12);
	}
	return 1; // caller continues packet processing
}

static lrd_seq_t _laird_seq(const u8 *leseq, int leseqlen)
{
	lrd_seq_t seq;
	seq = 0;
	if (!leseq || leseqlen != 6) return seq;
	while (leseqlen) {
		seq <<= 8;
		seq += leseq[--leseqlen];
	}
	return seq;
}


void laird_addkey(struct net_device *ndev, u8 key_index,
						 bool pairwise,
						 const u8 * mac_addr,
						 const u8 * key, int keylen,
						 const u8 * seq, int seqlen)
{
	lrd_key_index_t *ki;
	lrd_key_t *pk;

	if (key_index >= 4)
		return;
	if (keylen != 16 && keylen != 0)
		return;
	if (seqlen > 8)
		return;

	if (keylen != 0) {
		// allocate before the spinlock, delete if unused
		pk = lrd_key_malloc(key, keylen);
	}

	spin_lock_bh(&laird_key_spinlock);
	if (pairwise)
		__glob.tx_index = key_index;
	ki = &__glob.ki[key_index & 3];
	if (keylen == 0) {
		// deleting the key
		lrd_key_unref(ki->pcur);
		ki->pcur = NULL;
	} else {
		lrd_key_t *pcur = ki->pcur;
		if (pcur && (0 == memcmp(pcur->key, key, 16))) {
			; // key is unchanged -- ignore, replay attempt?
			lrd_key_unref(pk);
		} else {
			lrd_key_unref(ki->pcur);
			// create new key
			ki->pcur = pk;
			if (ki->pcur) {
				int i;
				pk->rsc = _laird_seq(seq, seqlen);
				for (i=0; i<16; i++) pk->rscqos[i] = pk->rsc;
				memcpy(pk->key, key, keylen);
				pk->keylen = keylen;
			}
		}
	}
	spin_unlock_bh(&laird_key_spinlock);
}

void laird_delkey(struct net_device *ndev, u8 key_index)
{
	laird_addkey(ndev, key_index, 0, NULL, NULL, 0, NULL, 0);
}

void laird_deinit(void)
{
	int i;
	lairdReassemblyPurgeAll();
	for (i=0; i<4; i++) {
		laird_delkey(NULL, i);
	}
}
#endif
