/*
 * Copyright (c) 2013 Laird, Inc.
 * Licensed under GPLv2.
 */

#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include "laird_i.h"
#include "moddebug.h"
#include "touser.h"
#include "mod2urw.h"

#define ETHTYPE_IP     0x0800

/* statistics for debugging */
#define FIPS_STAT_INC(name) fips_stat_##name += 1
#define FIPS_STAT_DEF(name) \
	static uint fips_stat_##name; \
	module_param(fips_stat_##name, uint, S_IRUGO)

FIPS_STAT_DEF(rx_unencrypted_ok);
FIPS_STAT_DEF(rx_decrypt_ok);
FIPS_STAT_DEF(rx_no_memory);
FIPS_STAT_DEF(rx_bad_packet);
FIPS_STAT_DEF(rx_discard_amsdu);
FIPS_STAT_DEF(rx_fragment);
FIPS_STAT_DEF(rx_discard_unencrypted);
FIPS_STAT_DEF(rx_decrypt_fail);
FIPS_STAT_DEF(rx_decrypt_replay);
FIPS_STAT_DEF(rx_decrypt_no_key);
FIPS_STAT_DEF(rx_unspecified_error);

FIPS_STAT_DEF(tx_unencrypted_ok);
FIPS_STAT_DEF(tx_encrypt_ok);
FIPS_STAT_DEF(tx_no_memory);
FIPS_STAT_DEF(tx_bad_packet);
FIPS_STAT_DEF(tx_unencrypted_fail);
FIPS_STAT_DEF(tx_encrypt_fail);
FIPS_STAT_DEF(tx_encrypt_no_key);
FIPS_STAT_DEF(tx_unspecified_error);

#ifdef LAIRD_DEBUG
static void debug_skb_trace(const char *fn, int line,
							struct sk_buff *skb, int status);
#define DEBUG_SKB_TRACE(skb,res) \
	debug_skb_trace(__FUNCTION__, __LINE__, skb, res)
static void debug_skb_dump(const char *fn, struct sk_buff *skb);
#define DEBUG_SKB_DUMP(skb) \
	debug_skb_dump(__FUNCTION__, skb);
#else
#define DEBUG_SKB_TRACE(skb,res)
#define DEBUG_SKB_DUMP(skb)
#endif

typedef unsigned long long lrd_seq_t;

static void error_stat_rx(int res)
{
	int *perr;
	if (res >= 0) {
		if (res == 0)
			perr = &fips_stat_rx_decrypt_ok;
		else if (res == 1)
			perr = &fips_stat_rx_unencrypted_ok;
		else
			return;
	} else {
		switch (-res) {
		case ENOMEM:
		case E_LRD_RX_NO_MEMORY:
			perr = &fips_stat_rx_no_memory;
			break;
		case E_LRD_RX_BAD_PACKET:
			perr = &fips_stat_rx_bad_packet;
			break;
		case E_LRD_RX_DISCARD_AMSDU:
			perr = &fips_stat_rx_discard_amsdu;
			break;
		case E_LRD_RX_FRAGMENT:
			perr = &fips_stat_rx_fragment;
			break;
		case E_LRD_RX_DISCARD_UNENCRYPTED:
			perr = &fips_stat_rx_discard_unencrypted;
			break;
		case E_LRD_RX_DECRYPT_FAIL:
			perr = &fips_stat_rx_decrypt_fail;
			break;
		case E_LRD_RX_DECRYPT_REPLAY:
			perr = &fips_stat_rx_decrypt_replay;
			break;
		case E_LRD_RX_DECRYPT_NO_KEY:
			perr = &fips_stat_rx_decrypt_no_key;
			break;
		default:
			perr = &fips_stat_rx_unspecified_error;
			break;
		}
	}
	*perr += 1;
}

static void error_stat_tx(int res)
{
	int *perr;
	if (res >= 0) {
		if (res == 0)
			perr = &fips_stat_tx_encrypt_ok;
		else if (res == 1)
			perr = &fips_stat_tx_unencrypted_ok;
		else
			return;
	} else {
		switch (-res) {
		case ENOMEM:
		case E_LRD_TX_NO_MEMORY:
			perr = &fips_stat_tx_no_memory;
			break;
		case E_LRD_TX_BAD_PACKET:
			perr = &fips_stat_tx_bad_packet;
			break;
		case E_LRD_TX_UNENCRYPTED_FAIL:
			perr = &fips_stat_tx_unencrypted_fail;
			break;
		case E_LRD_TX_ENCRYPT_FAIL:
			perr = &fips_stat_tx_encrypt_fail;
			break;
		case E_LRD_TX_ENCRYPT_NO_KEY:
			perr = &fips_stat_tx_encrypt_no_key;
			break;
		default:
			perr = &fips_stat_tx_unspecified_error;
			break;
		}
	}
	*perr += 1;
}

static struct {
	struct sk_buff_head skbq_tx;
	struct sk_buff_head skbq_rx;
	int tx_stop_tasklet;
	int stopping_txrx;	/* rmmod */
} __glob;

/* spinlock for protecting the queues */
static DEFINE_SPINLOCK(skbq_tx_lock);
static DEFINE_SPINLOCK(skbq_rx_lock);

static DEFINE_MUTEX(mutex_stopping_txrx);

static int cryp_counter;

/* private data stored in socket buffer (using skb.cb[]) */
typedef struct {
	int res;
	int done;
	union {
		pfn_laird_skb_rx_continue rxcontinue;
		pfn_laird_skb_tx_continue txcontinue;
		void *pfn;
	} fn;
	struct net_device *dev;
	int up;			/* user priority (-1 is non-wmm) */
	int idx;
} laird_skb_priv_t;

/* laird_skb_priv_set() - save private data in tx/rx skb
 * use skb cb[] to store private data
 * TBD: save original skb->cb
 */
static laird_skb_priv_t *laird_skb_priv_set(struct sk_buff *skb,
					    void *pfn,
					    struct net_device *dev, int up)
{
	laird_skb_priv_t *pd = (void *)skb->cb;
	pd->res = -1;
	pd->done = 0;
	pd->fn.pfn = pfn;
	pd->dev = dev;
	pd->idx = cryp_counter++;
	pd->up = up;
	return pd;
}

static laird_skb_priv_t *laird_skb_priv_get(struct sk_buff *skb)
{
	laird_skb_priv_t *pd = (void *)skb->cb;
	return pd;
}

static inline int laird_skb_idx(struct sk_buff *skb)
{
	laird_skb_priv_t *pd = (void *)skb->cb;
	return pd->idx;
}

/* return true if both rx/txq are empty */
static inline int __crypqs_empty(void)
{
	int res = 1;
	spin_lock_bh(&skbq_tx_lock);
	if (!skb_queue_empty(&__glob.skbq_tx))
		res = 0;
	spin_unlock_bh(&skbq_tx_lock);
	spin_lock_bh(&skbq_rx_lock);
	if (!skb_queue_empty(&__glob.skbq_rx))
		res = 0;
	spin_unlock_bh(&skbq_rx_lock);
	return res;
}

/* called when exitting the driver (rmmod)
 * note -- process level, not softirq/bh
 */
static int __cryp_wait_txrx_completed(void)
{
	mutex_lock(&mutex_stopping_txrx);
	__glob.stopping_txrx = 1;
	if (!__crypqs_empty()) {
		/* wait for unlock when queues go empty */
		if (mutex_lock_interruptible(&mutex_stopping_txrx)) {
			return -1;
		}
	}
	__glob.stopping_txrx = 0;
	/* check if mutex is locked, and unlock it if it is locked */
	if (mutex_is_locked(&mutex_stopping_txrx)) {
		mutex_unlock(&mutex_stopping_txrx);
	}
	return 0;
}

/* if we are stopping txrx and queues are empty signal */
static void inline __cryp_signal_if_txrx_completed(void)
{
	if (!__glob.stopping_txrx)
		return;
	if (!__crypqs_empty())
		return;
	if (mutex_is_locked(&mutex_stopping_txrx)) {
		/* unlock the mutex to allow wait to finish */
		mutex_unlock(&mutex_stopping_txrx);
	}
}

/* multiprocessor system can execute multiple tasklets simultaneously
 * so only use one tasklet for both rx/tx processing
 * tasklet for post-crypto operation processing
 */
static void __tasklet_exec(unsigned long);
DECLARE_TASKLET(__tasklet, __tasklet_exec, 0);

/* callback when sdclkm_xxx crypto operation completes */
static void __callback_rx(void *din, int res);

/* socket buffer encryption
 * return: -1 failure, 0 processed, 1 driver to process
 */
int laird_skb_rx_prep(struct sk_buff *skb, pfn_laird_skb_rx_continue pfn)
{
	int res;
	sdclkm_cb_t cbd;

	if (__glob.stopping_txrx) {
		return -1;
	}
	laird_skb_priv_set(skb, pfn, NULL, 0);
	DEBUG_SKB_TRACE(skb, 0);
	DEBUG_SKB_DUMP(skb);
	cbd.pfn = __callback_rx;
	cbd.pdata = skb;
	res = sdclkm_skb_receive(&cbd, skb);
	if (res != 0) {
		DEBUG_SKB_TRACE(skb, res);
		error_stat_rx(res);
		return res;
	}

	/* put on rx queue */
	spin_lock_bh(&skbq_rx_lock);
	__skb_queue_tail(&__glob.skbq_rx, skb);
	spin_unlock_bh(&skbq_rx_lock);

	return 0;
}

/* callback called at process level when crypto operation completes
 * note callback could be with different skb than originally submitted
 */
static void __callback_rx(void *din, int res)
{
	struct sk_buff *skb = din;
	laird_skb_priv_t *pd = laird_skb_priv_get(skb);
	DEBUG_SKB_TRACE(skb, res);
	DEBUG_SKB_DUMP(skb);
	pd->res = res;
	pd->done = 1;
	tasklet_schedule(&__tasklet);
	/* processing continues below in __tasklet_exec() */
}

/* callback when sdclkm_xxx crypto operation completes
 * or directly in _part1() if operation fails/doesn't need crypto
 */
static void __callback_tx(void *din, int res);

/* set the user priority (up) to be used, -1 for non-wmm packets */
static int laird_skb_up(struct sk_buff *skb, int wmm)
{
	struct ethhdr *eth_hdr;
	__be16 type;
	int up;

	if (!wmm) {
		return -1;
	}

	up = 0;
	if (skb->priority >= 256) {
		up = skb->priority - 256;
		if (up > 7)
			up = 0;
	}
	if (skb->len >= sizeof(struct ethhdr) + 2) {
		eth_hdr = (struct ethhdr *)skb->data;
		type = eth_hdr->h_proto;
		if (type == be16_to_cpu(ETHTYPE_IP)) {
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

/* socket buffer encryption */
int laird_skb_tx_prep(struct sk_buff *skbin, struct net_device *dev, int wmm,
		      pfn_laird_skb_tx_continue pfn)
{
	int res;
	sdclkm_cb_t cbd;
	struct sk_buff *skb = skbin;
	laird_skb_priv_t *pd;

	if (__glob.stopping_txrx) {
		return -1;
	}
	if (skb->len < sizeof(struct ethhdr)) {
		return -1;
	}

	if (skb_cloned(skb) ||
		skb_headroom(skb) < dev->needed_headroom ||
		skb_tailroom(skb) < dev->needed_tailroom)
	{
		/* make a copy -- cloned, or insufficient head/tail room */
		skb = skb_copy_expand(skb, dev->needed_headroom, dev->needed_tailroom, GFP_ATOMIC);
		if (!skb) {
			skb = skbin;
			res = -ENOMEM;
			goto fail;
		}
	}

	pd = laird_skb_priv_set(skb, pfn, dev, laird_skb_up(skb, wmm));
	DEBUG_SKB_TRACE(skb, 0);
	DEBUG_SKB_DUMP(skb);
	cbd.pfn = __callback_tx;
	cbd.pdata = skb;
	res = sdclkm_skb_transmit(&cbd, skb, &pd->up);
	if (res != 0) {
		goto fail;
	}

	/* put on skb queue */
	spin_lock_bh(&skbq_tx_lock);
	__skb_queue_tail(&__glob.skbq_tx, skb);
	spin_unlock_bh(&skbq_tx_lock);

	res = 0; /* success */
fail:
	if (res) {
		DEBUG_SKB_TRACE(skb, res);
	}
	if (skb != skbin) {
		/* if we made a copy of the skb...
		 * if failure, free the new skb; if success, free the input skb
		 */
        dev_kfree_skb(res ? skb : skbin);
	}
	if (res != 0)
		error_stat_tx(res);
	return res;
}

/* callback called at process level when crypto operation completes
 * note callback could be with different skb than originally submitted
 */
static void __callback_tx(void *din, int res)
{
	struct sk_buff *skb = din;
	laird_skb_priv_t *pd = laird_skb_priv_get(skb);
	DEBUG_SKB_TRACE(skb, res);
	DEBUG_SKB_DUMP(skb);
	pd->res = res;
	pd->done = 1;
	tasklet_schedule(&__tasklet);
	/* processing continues below in __tasklet_exec() */
}

/* a single tasklet processes both receive and transmit
 * don't want two tasklets executing simultaneously on multi-processor
 * tasklet to complete skb processing and pass skb back to driver
 */
static void __tasklet_exec(unsigned long unused)
{
	struct sk_buff *skb;
	laird_skb_priv_t *pd;

	spin_lock_bh(&skbq_tx_lock);
	while (1) {
		if (__glob.tx_stop_tasklet) {
			/* flow control has stopped transmit packet submission */
			break;
		}
		skb = skb_peek(&__glob.skbq_tx);
		if (!skb)
			break;
		pd = laird_skb_priv_get(skb);
		if (!pd->done)
			break;
		(void)skb_dequeue(&__glob.skbq_tx);
		DEBUG_SKB_TRACE(skb, pd->res);
		error_stat_tx(pd->res);
		spin_unlock_bh(&skbq_tx_lock);
		(*(pd->fn.txcontinue)) (skb, pd->dev, pd->res < 0 ? -1 : 1);
		spin_lock_bh(&skbq_tx_lock);
	}
	spin_unlock_bh(&skbq_tx_lock);

	spin_lock_bh(&skbq_rx_lock);
	while (1) {
		skb = skb_peek(&__glob.skbq_rx);
		if (!skb)
			break;
		pd = laird_skb_priv_get(skb);
		if (!pd->done)
			break;
		(void)skb_dequeue(&__glob.skbq_rx);
		DEBUG_SKB_TRACE(skb, pd->res);
		error_stat_rx(pd->res);
		spin_unlock_bh(&skbq_rx_lock);
		(*(pd->fn.rxcontinue)) (skb, pd->res < 0 ? -1 : 1);
		spin_lock_bh(&skbq_rx_lock);
	}
	spin_unlock_bh(&skbq_rx_lock);

	__cryp_signal_if_txrx_completed();
}

/* transmit flow control
 * stop the fips tasklet from submitting transmit packets
 */
static DEFINE_SPINLOCK(tx_stop_tasklet_lock);
void laird_stop_queue(struct net_device *dev)
{
	spin_lock_bh(&tx_stop_tasklet_lock);
	__glob.tx_stop_tasklet = 1;
	spin_unlock_bh(&tx_stop_tasklet_lock);
}

/* enable the fips tasklet to submit transmit packets */
void laird_wake_queue(struct net_device *dev)
{
	int val;
	spin_lock_bh(&tx_stop_tasklet_lock);
	val = __glob.tx_stop_tasklet;
	__glob.tx_stop_tasklet = 0;
	spin_unlock_bh(&tx_stop_tasklet_lock);
	if (val) {
		/* transmit was unblocked */
		tasklet_schedule(&__tasklet);
	}
}

/* callback called at process level when crypto operation completes */
static void __callback_del_data(void *din, int res)
{
	kfree(din);
	(void)res;
}

/* note, this routine does not return a status as
 * the operation has not completed when this routine returns
 */
void laird_addkey(struct net_device *ndev,
		  u8 key_index, bool pairwise,
		  const u8 * mac_addr,
		  const u8 * key, int keylen, const u8 * seq, int seqlen)
{
	int res;
	sdclkm_cb_t cbd;
	struct {
		u32 key_index;
		u8 key[16];
		u8 seq[8];
	} *p;


	if (key_index >= 4)
		return;
	if (keylen != 16 && keylen != 0)
		return;
	if (seqlen > 8)
		return;

	/* store data in allocated memory */
	p = kmalloc(sizeof(*p), GFP_ATOMIC);
	if (!p) {
		printk(KERN_ALERT "%s: alloc failed\n", __FUNCTION__);
		return;
	}
	p->key_index = key_index | (pairwise ? (1UL >> 31) : 0);
	if (keylen)
		memcpy(p->key, key, keylen);
	if (seqlen)
		memcpy(p->seq, seq, seqlen);

	cbd.pfn = __callback_del_data;
	cbd.pdata = p;

	res = sdclkm_addkey(&cbd,
			    &p->key_index, p->key, keylen, p->seq, seqlen);
	if (res != 0) {
		kfree(p);
	}

}

void laird_delkey(struct net_device *ndev, u8 key_index)
{
	laird_addkey(ndev, key_index, 0, NULL, NULL, 0, NULL, 0);
}

void laird_setbssid(const u8 * bssid)
{
	int res;
	sdclkm_cb_t cbd;
	struct {
		u8 bssid[6];
	} *p;

	_printkhexs(__FUNCTION__, "bssid", bssid, bssid ? 6 : 0);

	/* store data in allocated memory */
	p = kmalloc(sizeof(*p), GFP_ATOMIC);
	if (!p) {
		printk(KERN_ALERT "%s: alloc failed\n", __FUNCTION__);
		return;
	}
	if (bssid)
		memcpy(p->bssid, bssid, 6);

	cbd.pfn = __callback_del_data;
	cbd.pdata = p;

	res = sdclkm_setbssid(&cbd, p->bssid, bssid ? 6 : 0);
	if (res != 0) {
		kfree(p);
	}
}

/* stopping the driver (rmmod) to wait for cryp queues (txrx) to complete */
int laird_stop_txrx(void)
{
	int res;
	res = __cryp_wait_txrx_completed();
	return res;
}

int laird_txrx_init(void)
{
	skb_queue_head_init(&__glob.skbq_tx);
	skb_queue_head_init(&__glob.skbq_rx);
	return 0;
}

#ifdef LAIRD_DEBUG
static void debug_skb_trace(const char *fn, int line,
							struct sk_buff *skb, int status)
{
	printk(KERN_ALERT "%s: index %d, line %d, status=%d\n",
		   fn, laird_skb_idx(skb), line, status);
}

static void debug_skb_dump(const char *fn, struct sk_buff *skb)
{
	_printkhexs(fn, "skb", skb->data, skb->len);
}
#endif

const laird_register_data_t register_data = {
	.pfn_rx_prep = &laird_skb_rx_prep,
	.pfn_tx_prep = &laird_skb_tx_prep,
	.pfn_stop_queue = &laird_stop_queue,
	.pfn_wake_queue = &laird_wake_queue,
	.pfn_addkey = &laird_addkey,
	.pfn_delkey = &laird_delkey,
	.pfn_setbssid = &laird_setbssid,
	.pfn_stop_txrx = &laird_stop_txrx
};
