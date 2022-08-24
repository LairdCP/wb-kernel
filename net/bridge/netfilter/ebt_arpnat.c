/*
 *  ebt_arpnat.c
 *
 *	Authors:
 *      Kestutis Barkauskas <gpl@wilibox.com>
 *
 *  November, 2005
 *
 *	Rewritten by:
 *         Kestutis Barkauskas and Kestutis Kupciunas <gpl@ubnt.com>
 *
 *  June, 2010
 *
 *      Updated to work with more recent kernel versions (e.g., 2.6.30)
 *      Ditched entry expiration in favor of wiping entries with duplicate ips, when situation arises
 *      Fixed arpnat procfs (though both arpnat_cache and arpnat_info are both in root procfs directory now)
 *
 *      Eric Bishop <eric@gargoyle-router.com>
 *
 *  January, 2021
 *
 *      Updated to take advantage of kernel 4.19 helpers
 *      Fixed DHCP relay operation it's now correctly sends client MAC to DHCP server
 *      Fixed arpnat procfs
 *
 *      Boris Krasnovskiy <boris.krasnovskiy@lairdconnect.com>
 */

//#define DEBUG

#include <linux/module.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/inetdevice.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter_bridge/ebt_nat.h>
#include <net/ip.h>
#include <net/checksum.h>

#include "../br_private.h"

struct dhcp_packet {
	u8 op;      /* BOOTREQUEST or BOOTREPLY */
	u8 htype;   /* hardware address type. 1 = 10mb ethernet */
	u8 hlen;    /* hardware address length */
	u8 hops;    /* used by relay agents only */
	u32 xid;    /* unique id */
	u16 secs;   /* elapsed since client began acquisition/renewal */
	u16 flags;  /* only one flag so far: */
	u32 ciaddr; /* client IP (if client is in BOUND, RENEW or REBINDING state) */
	u32 yiaddr; /* 'your' (client) IP address */
	/* IP address of next server to use in bootstrap, returned in DHCPOFFER, DHCPACK by server */
	u32 siaddr_nip;
	u32 gateway_nip; /* relay agent IP address */
	u8 chaddr[16];   /* link-layer client hardware address (MAC) */
	u8 sname[64];    /* server host name (ASCIZ) */
	u8 file[128];    /* boot file name (ASCIZ) */
} __packed;

#define BROADCAST_FLAG	0x8000 /* "I need broadcast replies" */

#define BOOTPREQUEST	1
#define BOOTPREPLY	2

#define DHCP_MIN_SIZE (sizeof(struct udphdr) + sizeof(struct dhcp_packet))

struct mac2val
{
	u32 val;
	u8 mac[ETH_ALEN];

	struct list_head node;
};

static u8 chaddr_orig[ETH_ALEN];
static u32 chaddr_xid;

static LIST_HEAD(arpnat_table);
static spinlock_t arpnat_lock = __SPIN_LOCK_UNLOCKED(arpnat_lock);

static struct mac2val* find_by_mac(struct list_head *head, const u8 *mac)
{
	struct mac2val *entry;

	list_for_each_entry(entry, head, node) {
		if (ether_addr_equal(entry->mac, mac))
			return entry;
	}
	return NULL;
}

static struct mac2val* find_by_val(struct list_head *head, u32 val)
{
	struct mac2val *entry;

	list_for_each_entry(entry, head, node) {
		if (entry->val == val)
			return entry;
	}
	return NULL;
}

static inline void clear_entry(struct mac2val* entry)
{
	list_del(&entry->node);
	kfree(entry);
}

static inline void clear_by_val(struct list_head *head, u32 ip)
{
	struct mac2val* entry = find_by_val(head, ip);
	if (entry)
		clear_entry(entry);
}

static void free_list(struct list_head *head)
{
	struct mac2val *entry;

	list_for_each_entry(entry, head, node)
		clear_entry(entry);
}

static struct mac2val* add_val(struct list_head *head, const u8 *mac, u32 val)
{
	struct mac2val *entry;

	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return NULL;

	INIT_LIST_HEAD(&entry->node);
	ether_addr_copy(entry->mac, mac);
	entry->val = val;

	list_add(&entry->node, head);

	return entry;
}

static struct mac2val* update_arp_nat(const u8 *mac, u32 ip)
{
	struct list_head *head = &arpnat_table;
	struct mac2val *entry;

	entry = find_by_mac(head, mac);
	if (!entry) {
		clear_by_val(head, ip); /* if entries with new ip exist, wipe them */
		entry = add_val(head, mac, ip);
	} else if (entry->val != ip) {
		clear_by_val(head, ip); /* if entries with new ip exist, wipe them */
		entry->val = ip;
	}

	return entry;
}

#if IS_ENABLED(CONFIG_PROC_FS)

static int arpnat_cache_show(struct seq_file *s, void *v)
{
	struct mac2val* entry;

	spin_lock_bh(&arpnat_lock);
	list_for_each_entry(entry, &arpnat_table, node)
		seq_printf(s, "%pM\t%pI4\n", entry->mac, &entry->val);
	spin_unlock_bh(&arpnat_lock);

	return 0;
}

static int arpnat_info_show(struct seq_file *s, void *v)
{
#ifdef DEBUG
	seq_printf(s, "Debug: 1\n");
#else
	seq_printf(s, "Debug: 0\n");
#endif

#if IS_ENABLED(CONFIG_BRIDGE_EBT_ARPNAT_DHCPRELAY)
	seq_printf(s, "BOOTPNAT: 1\n");
#else
	seq_printf(s, "BOOTPNAT: 0\n");
#endif
	return 0;
}

static int arpnat_cache_open(struct inode *inode, struct file* file)
{
	return single_open(file, arpnat_cache_show, NULL);
}
static int arpnat_info_open(struct inode *inode, struct file* file)
{
	return single_open(file, arpnat_info_show, NULL);
}

static struct proc_ops arpnat_cache_proc_ops = {
	.proc_open    = arpnat_cache_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};
static struct proc_ops arpnat_info_proc_ops = {
	.proc_open    = arpnat_info_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};
#endif


static unsigned int ebt_target_arpnat(struct sk_buff *pskb, const struct xt_action_param *par)
{
	const struct net_device *in  =  xt_in(par);
	const struct net_device *out =  xt_out(par);

	const struct ebt_nat_info *info = (struct ebt_nat_info *) par->targinfo;

	struct arphdr *ah = NULL;
	struct arphdr _arph;

	//used for target only
	u8 *eth_smac = eth_hdr(pskb)->h_source;
	u8 *eth_dmac = eth_hdr(pskb)->h_dest;
	u32 *arp_sip = NULL;
	u8 *arp_smac = NULL;
	u32 *arp_dip = NULL;
	u8 *arp_dmac = NULL;
	struct mac2val *entry = NULL;

	/* if it's an arp packet, initialize pointers to arp source/dest ip/mac addresses in skb */
	if (eth_hdr(pskb)->h_proto == __constant_htons(ETH_P_ARP)) {
		pr_devel("ARPNAT ARP DETECTED\n");

		ah = skb_header_pointer(pskb, 0, sizeof(_arph), &_arph);
		if (ah->ar_hln == ETH_ALEN && ah->ar_pro == __constant_htons(ETH_P_IP) && ah->ar_pln == 4) {
			unsigned char *raw = skb_network_header(pskb);
			arp_sip = (u32*)(raw + sizeof(struct arphdr) + (arp_hdr(pskb)->ar_hln));
			arp_smac = raw + sizeof(struct arphdr);
			arp_dip = (u32*)(raw + sizeof(struct arphdr) + (2*(arp_hdr(pskb)->ar_hln)) + arp_hdr(pskb)->ar_pln);
			arp_dmac = raw + sizeof(struct arphdr) + arp_hdr(pskb)->ar_hln + arp_hdr(pskb)->ar_pln;
		}
	}

	if (in) {
		struct net_bridge_port *in_br_port;
		in_br_port = br_port_get_rcu(in);

		/* handle input packets */
		pr_devel("ARPNAT INBOUND DETECTED\n");

		if (ah) {
#ifdef DEBUG
			pr_devel("IN ARPNAT:\n");
			pr_devel("          arp_smac=%pM, arp_dmac=%pM\n", arp_smac, arp_dmac);
			pr_devel("          arp_sip =%pI4, arp_dip =%pI4\n", arp_sip, arp_dip);
			switch (ah->ar_op) {
				case __constant_htons(ARPOP_REPLY):
					pr_devel("           arp_op=reply\n");
					break;

				case __constant_htons(ARPOP_REQUEST):
					pr_devel("           arp_op=request\n");
					break;

				default:
					pr_devel("           arp_op=%d\n", ntohs(ah->ar_op));
					break;
			}
#endif
			if (inet_confirm_addr(dev_net(in_br_port->br->dev), __in_dev_get_rcu(in_br_port->br->dev), 0, *arp_dip, RT_SCOPE_HOST)) {
				pr_devel("          TO US\n");
				return info->target;
			}


			spin_lock_bh(&arpnat_lock);
			entry = find_by_val(&arpnat_table, *arp_dip);
			switch (ah->ar_op)
			{
				case __constant_htons(ARPOP_REPLY):
				case __constant_htons(ARPOP_REQUEST):
				if (entry) {
					u32 dip = *arp_dip;
					u32 sip = inet_select_addr(in_br_port->br->dev, dip, RT_SCOPE_LINK);
					if (!is_multicast_ether_addr(eth_dmac)) {
						pr_devel("          %pM -> %pM\n", eth_dmac, entry->mac);

						ether_addr_copy(arp_dmac, entry->mac);
						ether_addr_copy(eth_dmac, entry->mac);
						pskb->pkt_type = (dip != sip) ? PACKET_OTHERHOST : pskb->pkt_type;
					}
					spin_unlock_bh(&arpnat_lock);
					/*if (dip != sip)
					{
						pr_devel("SEND ARP REQUEST: %pI4 -> %pI4\n", &sip, &dip);
						arp_send(ARPOP_REQUEST, ETH_P_ARP, dip, &in_br_port->br->dev, sip, NULL, in_br_port->br->dev.dev_addr, NULL);
					}*/
					return info->target;
				}
				break;
			}
			spin_unlock_bh(&arpnat_lock);
		} else if (eth_hdr(pskb)->h_proto == __constant_htons(ETH_P_IP)) {
			struct iphdr *iph = ip_hdr(pskb);

#if IS_ENABLED(CONFIG_BRIDGE_EBT_ARPNAT_DHCPRELAY_IMPERSONATE)
			if (iph->protocol == IPPROTO_UDP && !(iph->frag_off & __constant_htons(IP_OFFSET))) {
				struct udphdr *uh = (struct udphdr*)((u32*)iph + iph->ihl);
				if (uh->dest == __constant_htons(68)) {
					struct dhcp_packet *dhcp = (struct dhcp_packet*)((u8*)uh + sizeof(*uh));
					u32 size = pskb->len - (iph->ihl << 2);

					if (size >= DHCP_MIN_SIZE && dhcp->op == BOOTPREPLY && dhcp->xid == chaddr_xid &&
						ether_addr_equal(dhcp->chaddr, in->dev_addr)) {
						pr_devel("IN BOOTPREPLY: %pM[%pI4] -> %pM[%pI4] xid=%x\n",
							dhcp->chaddr, &dhcp->yiaddr, eth_dmac, &iph->daddr, dhcp->xid);

						/* Preserve host DHCP HWADDR of the requestor */
						ether_addr_copy(dhcp->chaddr, chaddr_orig);
						/* Change the DHCP HWADDR of the requestor to the HWADDR of the out device */
						if (!is_multicast_ether_addr(eth_dmac))
							ether_addr_copy(eth_dmac, chaddr_orig);

						/* Recalculate checksums */
						uh->check = 0;
						pskb->csum = csum_partial(uh, size, 0);
						uh->check = csum_tcpudp_magic(iph->saddr, iph->daddr, size, iph->protocol, pskb->csum);
						if (uh->check == 0)
							uh->check = 0xFFFF;

						return info->target;
					}
				}
			}
#endif
			if (!is_multicast_ether_addr(eth_dmac)) {
				spin_lock_bh(&arpnat_lock);
				entry = find_by_val(&arpnat_table, iph->daddr);
				if (entry) {
					if (inet_confirm_addr(dev_net(in_br_port->br->dev), __in_dev_get_rcu(in_br_port->br->dev),  0, iph->daddr, RT_SCOPE_HOST)) {
						//to me
						pr_devel("IP PKT TO ME: %pM[%pI4] -> %pM[type: %d]\n", eth_dmac, &iph->daddr, in_br_port->br->dev->dev_addr, pskb->pkt_type);
						ether_addr_copy(eth_dmac, in_br_port->br->dev->dev_addr);
					} else {
						pr_devel("IP PKT TO OTHER: %pM[%pI4] -> %pM[type: %d]\n", eth_dmac, &iph->daddr, entry->mac, pskb->pkt_type);
						ether_addr_copy(eth_dmac, entry->mac);
						pskb->pkt_type = PACKET_OTHERHOST;
					}
					spin_unlock_bh(&arpnat_lock);
					return info->target;
				}
				spin_unlock_bh(&arpnat_lock);
			}
		}

		if (!is_multicast_ether_addr(eth_dmac)) {
			if (!ether_addr_equal(in_br_port->br->dev->dev_addr, eth_dmac) && !ether_addr_equal(in->dev_addr, eth_dmac))
				return EBT_DROP;

			spin_lock_bh(&arpnat_lock);
			entry = find_by_mac(&arpnat_table, eth_dmac);
			ether_addr_copy(eth_dmac, entry ? entry->mac : in_br_port->br->dev->dev_addr);
			spin_unlock_bh(&arpnat_lock);
		}
	}
	else if (out) {
		struct net_bridge_port *out_br_port;
		out_br_port = br_port_get_rcu(out);

		/* handle outbound packets */
		if (ah) {
			switch (ah->ar_op) {
				case __constant_htons(ARPOP_REQUEST):
				case __constant_htons(ARPOP_REPLY):

				/* do BR ip lookup */
				if (inet_confirm_addr(dev_net(out_br_port->br->dev), __in_dev_get_rcu(out_br_port->br->dev), 0, *arp_dip, RT_SCOPE_HOST))
					return info->target;

				if (!inet_confirm_addr(dev_net(out_br_port->br->dev), __in_dev_get_rcu(out_br_port->br->dev), 0, *arp_sip, RT_SCOPE_HOST)) {
					spin_lock_bh(&arpnat_lock);
					update_arp_nat(arp_smac, *arp_sip);
					spin_unlock_bh(&arpnat_lock);
				}

				eth_smac = eth_hdr(pskb)->h_source;
				arp_smac = skb_network_header(pskb) + sizeof(struct arphdr);
#ifdef DEBUG
				pr_devel("OUT ARPNAT: %pM -> %pM\n", eth_smac, out->dev_addr);
				pr_devel("           arp_smac=%pM, arp_dmac=%pM\n", arp_smac, arp_dmac);
				pr_devel("           arp_sip =%pI4, arp_dip =%pI4\n", arp_sip, arp_dip);
				switch (ah->ar_op) {
					case __constant_htons(ARPOP_REPLY):
						pr_devel("           arp_op=reply\n");
						break;

					case __constant_htons(ARPOP_REQUEST):
						pr_devel("           arp_op=request\n");
						break;

					default:
						pr_devel("           arp_op=%d\n", ntohs(ah->ar_op));
						break;
				}
#endif
				ether_addr_copy(arp_smac, out->dev_addr);
				ether_addr_copy(eth_smac, out->dev_addr);
				return info->target;
			}
		}
		else if (eth_hdr(pskb)->h_proto == __constant_htons(ETH_P_IP)) {
			struct iphdr *iph = ip_hdr(pskb);

#if IS_ENABLED(CONFIG_BRIDGE_EBT_ARPNAT_DHCPRELAY)
			if (iph->protocol == IPPROTO_UDP && !(iph->frag_off & __constant_htons(IP_OFFSET))) {
				struct udphdr *uh = (struct udphdr*)((u32*)iph + iph->ihl);
				if (uh->dest == __constant_htons(67)) {
					struct dhcp_packet *dhcp = (struct dhcp_packet*)((u8*)uh + sizeof(*uh));
					u32 size = pskb->len - (iph->ihl << 2);

					if (size >= DHCP_MIN_SIZE && dhcp->op == BOOTPREQUEST) {
						pr_devel("OUT BOOTPREQUEST: %pM[%pI4] -> %pM[%pI4] xid=%x\n",
							dhcp->chaddr, &dhcp->yiaddr, eth_dmac, &iph->daddr, dhcp->xid);

						ether_addr_copy(eth_smac, out->dev_addr);

#if IS_ENABLED(CONFIG_BRIDGE_EBT_ARPNAT_DHCPRELAY_IMPERSONATE)
						/* Preserve transaction ID */
						chaddr_xid = dhcp->xid;
						/* Preserve host DHCP HWADDR of the requestor */
						ether_addr_copy(chaddr_orig, dhcp->chaddr);
						/* Change the DHCP HWADDR of the requestor to the HWADDR of the out device */
						ether_addr_copy(dhcp->chaddr, out->dev_addr);
#else
						/* DHCP server sends unicast replies to the MAC in 'chaddr'
						   as a result they will be never received
						   To resolve the issue force broadcast replies
						*/
						if (dhcp->flags & __constant_htons(BROADCAST_FLAG))
							return info->target;

						dhcp->flags |= __constant_htons(BROADCAST_FLAG);
#endif

						/* Recalculate checksums */
						uh->check = 0;
						pskb->csum = csum_partial(uh, size, 0);
						uh->check = csum_tcpudp_magic(iph->saddr, iph->daddr, size, iph->protocol, pskb->csum);
						if (uh->check == 0)
							uh->check = 0xFFFF;

						return info->target;
					}
				}
			}
#endif
			/* use any packet for MAC/IP and update table if necessary */
			if (!inet_confirm_addr(dev_net(out_br_port->br->dev), __in_dev_get_rcu(out_br_port->br->dev), 0, iph->saddr, RT_SCOPE_HOST)) {
				spin_lock_bh(&arpnat_lock);
				entry = find_by_val(&arpnat_table, iph->saddr);
				if (!entry)
					update_arp_nat(eth_smac, iph->saddr);
				spin_unlock_bh(&arpnat_lock);

				if (!entry)
					pr_devel("OUT ARPNAT ADDED ETH_P_IP: Source %pM[%pI4] Destination %pM[%pI4]\n",
						eth_smac, &iph->saddr, eth_dmac, &iph->daddr);
			}
		}

		ether_addr_copy(eth_smac, out->dev_addr);
	}

	return info->target;
}

static int ebt_target_nat_arpcheck(const struct xt_tgchk_param *par)
{
	return 0;
}

static struct xt_target arpnat =
{
	.name		= EBT_ARPNAT_TARGET,
	.revision	= 0,
	.family		= NFPROTO_BRIDGE,
	.table		= "nat",
	.hooks		= (1 << NF_BR_NUMHOOKS) | (1 << NF_BR_POST_ROUTING) |  (1 << NF_BR_PRE_ROUTING) ,
	.target		= ebt_target_arpnat,
	.checkentry	= ebt_target_nat_arpcheck,
	.targetsize	= XT_ALIGN(sizeof(struct ebt_nat_info)),
	.me		= THIS_MODULE
};

static int __init init(void)
{
#if IS_ENABLED(CONFIG_PROC_FS)
	struct proc_dir_entry *proc_arpnat_dir;

	proc_arpnat_dir = proc_mkdir("arpnat", NULL);
	if (!proc_arpnat_dir)
		return -ENOMEM;

	proc_create("info", 0, proc_arpnat_dir, &arpnat_info_proc_ops);
	proc_create("cache", 0, proc_arpnat_dir, &arpnat_cache_proc_ops);
#endif

	return xt_register_target(&arpnat);
}

static void __exit fini(void)
{
	xt_unregister_target(&arpnat);
	free_list(&arpnat_table);

#if IS_ENABLED(CONFIG_PROC_FS)
	remove_proc_entry("arpnat/info", NULL);
	remove_proc_entry("arpnat/cache", NULL);
	remove_proc_entry("arpnat", NULL);
#endif
}

module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
