/*
 *  ebt_arpnat
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

#define GIADDR_OFFSET (24)    /* Gateway IP address */
#define CHADDR_OFFSET (28)

#define BOOTPNAT

static u8 chaddr_orig_bootp_relay[ETH_ALEN];

struct arpnat_dat
{
	u32 ip;
	u8 mac[ETH_ALEN];
} __packed;

struct mac2ip
{
	struct hlist_node node;
	struct arpnat_dat data;
};

static HLIST_HEAD(arpnat_table);
static spinlock_t arpnat_lock = __SPIN_LOCK_UNLOCKED(arpnat_lock);

static struct mac2ip* find_mac_nat(struct hlist_head* head, const u8* mac)
{
	struct mac2ip *tpos;
	struct mac2ip *result = NULL;
	struct hlist_node *n;

	hlist_for_each_entry_safe(tpos, n, head, node)
	{
		if (ether_addr_equal(tpos->data.mac, mac))
		{
			result = tpos;
			break;
		}
	}
	return result;
}

static struct mac2ip* find_ip_nat(struct hlist_head *head, u32 ip)
{
	struct mac2ip *tpos;
	struct mac2ip *result = NULL;
	struct hlist_node *n;

	hlist_for_each_entry_safe(tpos, n, head, node)
	{
		if (tpos->data.ip == ip)
		{
			result = tpos;
			break;
		}
	}
	return result;
}


static void clear_ip_nat(struct hlist_head *head, u32 ip)
{
	struct mac2ip* tpos;
	struct hlist_node* n;

	hlist_for_each_entry_safe(tpos, n, head, node)
	{
		if (tpos->data.ip == ip)
		{
			hlist_del(&tpos->node);
			kfree(tpos);
		}
	}
}

static void free_arp_nat(struct hlist_head *head)
{
	struct mac2ip *tpos;
	struct hlist_node *n;
	hlist_for_each_entry_safe(tpos, n, head, node)
	{
		hlist_del(&tpos->node);
		kfree(tpos);
	}
}

static struct mac2ip* update_arp_nat(struct hlist_head *head, const u8 *mac, u32 ip)
{
	struct mac2ip *entry;

	entry = find_mac_nat(head, mac);
	if (!entry)
	{
		clear_ip_nat(head, ip); /* if entries with new ip exist, wipe them */
		entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
		if (!entry)
		{
			return NULL;
		}
		INIT_HLIST_NODE(&entry->node);
		hlist_add_head(&entry->node, head);
		ether_addr_copy(entry->data.mac, mac);
		entry->data.ip = ip;
	}
	else if(entry->data.ip != ip)
	{
		clear_ip_nat(head, ip); /* if entries with new ip exist, wipe them */
		entry->data.ip = ip;
	}
	return entry;
}

#ifdef CONFIG_PROC_FS

static void *arpnat_start(struct seq_file *seq, loff_t *loff_pos)
{
	static unsigned long counter = 0;

	/* beginning a new sequence ? */
	if ( *loff_pos == 0 )
	{
		/* yes => return a non null value to begin the sequence */
		return &counter;
	}
	else
	{
		/* no => it's the end of the sequence, return end to stop reading */
		*loff_pos = 0;
		return NULL;
	}
}

static void *arpnat_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return NULL;
}

static void arpnat_stop(struct seq_file *seq, void *v)
{
	//don't need to do anything
}

static int arpnat_cache_show(struct seq_file *s, void *v)
{
	struct mac2ip* tpos;
	struct hlist_node* n;

	spin_lock_bh(&arpnat_lock);
	hlist_for_each_entry_safe(tpos, n, &arpnat_table, node)
	{
		seq_printf(s, "%pM\t%pI4\n", tpos->data.mac, &tpos->data.ip);
	}
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

#ifdef BOOTPNAT
	seq_printf(s, "BOOTPNAT: 1\n");
#else
	seq_printf(s, "BOOTPNAT: 0\n");
#endif
	return 0;
}

static struct seq_operations arpnat_cache_sops = {
	.start = arpnat_start,
	.next  = arpnat_next,
	.stop  = arpnat_stop,
	.show  = arpnat_cache_show
};
static struct seq_operations arpnat_info_sops = {
	.start = arpnat_start,
	.next  = arpnat_next,
	.stop  = arpnat_stop,
	.show  = arpnat_info_show
};

static int arpnat_cache_open(struct inode *inode, struct file* file)
{
	return seq_open(file, &arpnat_cache_sops);
}
static int arpnat_info_open(struct inode *inode, struct file* file)
{
	return seq_open(file, &arpnat_info_sops);
}

static struct file_operations arpnat_cache_fops = {
	.owner   = THIS_MODULE,
	.open    = arpnat_cache_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};
static struct file_operations arpnat_info_fops = {
	.owner   = THIS_MODULE,
	.open    = arpnat_info_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
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
	struct mac2ip *entry = NULL;

	/* if it's an arp packet, initialize pointers to arp source/dest ip/mac addresses in skb */
	if (eth_hdr(pskb)->h_proto == __constant_htons(ETH_P_ARP))
	{
		pr_devel("ARPNAT ARP DETECTED\n");

		ah = skb_header_pointer(pskb, 0, sizeof(_arph), &_arph);
		if (ah->ar_hln == ETH_ALEN && ah->ar_pro == __constant_htons(ETH_P_IP) && ah->ar_pln == 4)
		{
			unsigned char *raw = skb_network_header(pskb);
			arp_sip = (u32*)(raw + sizeof(struct arphdr) + (arp_hdr(pskb)->ar_hln));
			arp_smac = raw + sizeof(struct arphdr);
			arp_dip = (u32*)(raw + sizeof(struct arphdr) + (2*(arp_hdr(pskb)->ar_hln)) + arp_hdr(pskb)->ar_pln);
			arp_dmac = raw + sizeof(struct arphdr) + arp_hdr(pskb)->ar_hln + arp_hdr(pskb)->ar_pln;
		}
		else
		{
			ah = NULL;
		}
	}

	if (in)
	{
		struct net_bridge_port *in_br_port;
		in_br_port = br_port_get_rcu(in);

		/* handle input packets */
		pr_devel("ARPNAT INBOUND DETECTED\n");

		if (ah)
		{
#ifdef DEBUG
			pr_devel("IN ARPNAT:\n");
			pr_devel("          arp_smac=%pM, arp_dmac=%pM\n", arp_smac, arp_dmac);
			pr_devel("          arp_sip =%pI4, arp_dip =%pI4\n", arp_sip, arp_dip);
			switch (ah->ar_op)
			{
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
			if (inet_confirm_addr(dev_net(in_br_port->br->dev), __in_dev_get_rcu(in_br_port->br->dev) , 0, *arp_dip, RT_SCOPE_HOST))
			{
				pr_devel("          TO US\n");
				return info->target;
			}


			spin_lock_bh(&arpnat_lock);
			entry = find_ip_nat(&arpnat_table, *arp_dip);
			switch (ah->ar_op)
			{
				case __constant_htons(ARPOP_REPLY):
				case __constant_htons(ARPOP_REQUEST):
				if (entry)
				{
					u32 dip = *arp_dip;
					u32 sip = inet_select_addr(in_br_port->br->dev, dip, RT_SCOPE_LINK);
					if (! (eth_dmac[0] & 1))
					{
						pr_devel("          %pM -> %pM\n", eth_dmac, entry->data.mac);

						ether_addr_copy(arp_dmac, entry->data.mac);
						ether_addr_copy(eth_dmac, entry->data.mac);
						(pskb)->pkt_type = (dip != sip) ? PACKET_OTHERHOST : (pskb)->pkt_type;
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
		}
		else if (eth_hdr(pskb)->h_proto == __constant_htons(ETH_P_IP))
		{
			struct iphdr *iph = ip_hdr(pskb);
#ifdef BOOTPNAT
			if (iph->protocol == IPPROTO_UDP && !(iph->frag_off & __constant_htons(IP_OFFSET)))
			{
				struct udphdr *uh = (struct udphdr*)((u32 *)iph + iph->ihl);
				if (uh->dest == __constant_htons(67) || uh->dest == __constant_htons(68)) {
					//do something illegal for BOOTP
					u32* giaddrp = (u32*)(((u8*)uh) + sizeof(*uh) + GIADDR_OFFSET);
					u8* mac = (u8*)(giaddrp + 1);
					u32 ihl = iph->ihl << 2;
					u32 size = (pskb)->len - ihl;

					//iph->daddr = 0xffffffff;
					// Recall the original BOOTP CHADDR
					ether_addr_copy(mac, chaddr_orig_bootp_relay);
					pr_devel("IN BOOTPRELAY: %pM[%pI4] -> %pM[%pI4]\n", eth_dmac, &iph->daddr, mac, &iph->daddr);
					ether_addr_copy(eth_dmac, mac);
					*giaddrp = 0;
					uh->dest = __constant_htons(68);
					iph->check = 0;
					uh->check = 0;
					iph->check = ip_fast_csum(iph, iph->ihl);
					(pskb)->csum = csum_partial(uh, size, 0);
					uh->check = csum_tcpudp_magic(iph->saddr, iph->daddr, size, iph->protocol, pskb->csum);
					if (uh->check == 0)
						uh->check = 0xFFFF;

					return info->target;
				}
			}
#endif
			spin_lock_bh(&arpnat_lock);
			entry = find_ip_nat(&arpnat_table, iph->daddr);
			if (entry)
			{
				if (inet_confirm_addr(dev_net(in_br_port->br->dev), __in_dev_get_rcu(in_br_port->br->dev),  0, entry->data.ip, RT_SCOPE_HOST))
				{
					//to me
					pr_devel("IP PKT TO ME: %pM[%pI4] -> %pM[type: %d]\n", eth_dmac, &iph->daddr, in_br_port->br->dev->dev_addr, pskb->pkt_type);
					ether_addr_copy(eth_dmac, in_br_port->br->dev->dev_addr);
				}
				else
				{
					pr_devel("IP PKT TO OTHER: %pM[%pI4] -> %pM[type: %d]\n", eth_dmac, &iph->daddr, entry->data.mac, pskb->pkt_type);
					ether_addr_copy(eth_dmac, entry->data.mac);
					pskb->pkt_type = PACKET_OTHERHOST;
				}
				spin_unlock_bh(&arpnat_lock);
				return info->target;
			}
			spin_unlock_bh(&arpnat_lock);
		}

		if (! (eth_dmac[0] & 1))
		{
			if (!ether_addr_equal(in_br_port->br->dev->dev_addr, eth_dmac) && !ether_addr_equal(in->dev_addr, eth_dmac))
			{
				return EBT_DROP;
			}
			spin_lock_bh(&arpnat_lock);
			entry = find_mac_nat(&arpnat_table, eth_dmac);
			ether_addr_copy(eth_dmac, entry ? entry->data.mac : in_br_port->br->dev->dev_addr);
			spin_unlock_bh(&arpnat_lock);
		}
	}
	else if (out)
	{
		struct net_bridge_port *out_br_port;
		out_br_port = br_port_get_rcu(out);

		/* handle outbound packets */
		if (ah)
		{
			switch (ah->ar_op)
			{
				case __constant_htons(ARPOP_REQUEST):
				case __constant_htons(ARPOP_REPLY):

				/* do BR ip lookup */
				if (inet_confirm_addr(dev_net(out_br_port->br->dev), __in_dev_get_rcu(out_br_port->br->dev), 0, *arp_dip, RT_SCOPE_HOST))
				{
					return info->target;
				}
				if (!inet_confirm_addr(dev_net(out_br_port->br->dev), __in_dev_get_rcu(out_br_port->br->dev), 0, *arp_sip, RT_SCOPE_HOST))
				{
					spin_lock_bh(&arpnat_lock);
					update_arp_nat(&arpnat_table, arp_smac, *arp_sip);
					spin_unlock_bh(&arpnat_lock);
				}

				//pskb = skb_unshare(pskb, GFP_ATOMIC);
				eth_smac = eth_hdr(pskb)->h_source;
				arp_smac = skb_network_header(pskb) + sizeof(struct arphdr);
#ifdef DEBUG
				pr_devel("OUT ARPNAT: %pM -> %pM\n", eth_smac, out->dev_addr);
				pr_devel("           arp_smac=%pM, arp_dmac=%pM\n", arp_smac, arp_dmac);
				pr_devel("           arp_sip =%pI4, arp_dip =%pI4\n", arp_sip, arp_dip);
				switch (ah->ar_op)
				{
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
				break;
			}
		}
		else if (eth_hdr(pskb)->h_proto == __constant_htons(ETH_P_IP) && !ether_addr_equal(out_br_port->br->dev->dev_addr, eth_smac))
		{
			struct iphdr *iph = ip_hdr(pskb);

#ifdef BOOTPNAT
			if (iph->protocol == IPPROTO_UDP && !(iph->frag_off & __constant_htons(IP_OFFSET)))
			{
				struct udphdr *uh = (struct udphdr*)((u32*)iph + iph->ihl);
				if (uh->dest == __constant_htons(67) || uh->dest == __constant_htons(68))
				{
					// do something illegal for BOOTP
					u32 giaddr = inet_confirm_addr(dev_net(out), __in_dev_get_rcu(out), 0, 0, RT_SCOPE_LINK);
					u32* giaddrp = (u32*)(((u8*)uh) + sizeof(*uh) + GIADDR_OFFSET);
					u8 *chaddrp = (u8*)(((u8*)uh) + sizeof(*uh) + CHADDR_OFFSET);
					u32 ihl = iph->ihl << 2;
					u32 size = pskb->len - ihl;

					pr_devel("OUT BOOTPRELAY: %pI4 -> %pI4\n", giaddrp, &giaddr);

					*giaddrp = giaddr;
					// Save off the original BOOTP CHADDR
					ether_addr_copy(chaddr_orig_bootp_relay, chaddrp);
					// Change the DHCP HWADDR of the requestor to the HDADDR of the out device
					ether_addr_copy(chaddrp, out->dev_addr);

					/* Fix the checksum */
					uh->check = 0;
					pskb->csum = csum_partial(uh, size, 0);
					uh->check = csum_tcpudp_magic(iph->saddr, iph->daddr, size, iph->protocol, (pskb)->csum);
					if (uh->check == 0)
						uh->check = 0xFFFF;
				}
			}
			else
#endif
			{
				/* use any packet for MAC/IP and update table if necessary */
				if (!inet_confirm_addr(dev_net(out_br_port->br->dev), __in_dev_get_rcu(out_br_port->br->dev), 0, iph->saddr, RT_SCOPE_HOST))
				{
					spin_lock_bh(&arpnat_lock);
					entry = find_ip_nat(&arpnat_table, iph->saddr);
					if (!entry)
						update_arp_nat(&arpnat_table, eth_smac, iph->saddr);
					spin_unlock_bh(&arpnat_lock);

					if (!entry)
					{
						pr_devel("OUT ARPNAT ADDED ETH_P_IP: Source %pM[%pI4] Destination %pM[%pI4]\n",
						      eth_smac, &iph->saddr, eth_dmac, &iph->daddr);
					}
				}
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
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *proc_arpnat_info;
	struct proc_dir_entry *proc_arpnat_cache;

	proc_arpnat_info = proc_create("arpnat_info", 0, NULL, &arpnat_info_fops);
	proc_arpnat_cache = proc_create("arpnat_cache", 0, NULL, &arpnat_cache_fops);
#endif
	return xt_register_target(&arpnat);
}

static void __exit fini(void)
{
	xt_unregister_target(&arpnat);
	free_arp_nat(&arpnat_table);
#ifdef CONFIG_PROC_FS
	remove_proc_entry("arpnat_info", NULL);
	remove_proc_entry("arpnat_cache", NULL);
#endif
}

module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
