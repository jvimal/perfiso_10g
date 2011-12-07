#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "rl.h"

/* Layer 3 netfilter hooks */
extern struct net_device *iso_netdev;
struct nf_hook_ops hook_in;
struct nf_hook_ops hook_out;

/* L3 netfilter specific code */
unsigned int iso_rx_iptables(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *));

unsigned int iso_tx_iptables(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *));

int iso_tx_iptables_init(void);
void iso_tx_iptables_exit(void);

int iso_rx_iptables_init(void);
void iso_rx_iptables_exit(void);

enum iso_verdict iso_tx(struct sk_buff *skb, const struct net_device *out);
enum iso_verdict iso_rx(struct sk_buff *skb, const struct net_device *in);

/* This is what "ip_output" would do */
inline void skb_xmit(struct sk_buff *skb) {
	skb_dst(skb)->output(skb);
}

int iso_tx_iptables_init() {
	hook_out.hook = iso_tx_iptables;
	hook_out.hooknum= NF_INET_POST_ROUTING;
	hook_out.pf = PF_INET;
	hook_out.priority = NF_IP_PRI_FIRST;

	return nf_register_hook(&hook_out);
}

int iso_rx_iptables_init() {
	hook_in.hook = iso_rx_iptables;
	hook_in.hooknum= NF_INET_LOCAL_IN;
	hook_in.pf = PF_INET;
	hook_in.priority = NF_IP_PRI_FIRST;

	return nf_register_hook(&hook_in);
}

void iso_tx_iptables_exit() {
	nf_unregister_hook(&hook_out);
}

void iso_rx_iptables_exit() {
	nf_unregister_hook(&hook_in);
}

unsigned int iso_rx_iptables(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	enum iso_verdict verdict;
	/* out will be NULL if this is PRE_ROUTING */
	if(in != iso_netdev)
		return NF_ACCEPT;

	verdict = iso_rx(skb, in);

	switch(verdict) {
	case ISO_VERDICT_DROP:
		return NF_DROP;

	default:
	case ISO_VERDICT_SUCCESS:
		return NF_ACCEPT;
	}

	/* Unreachable */
	return NF_DROP;
}

unsigned int iso_tx_iptables(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	enum iso_verdict verdict;

	/* out shouldn't be NULL, but let's be careful anyway */
	if(out != iso_netdev)
		return NF_ACCEPT;

	verdict = iso_tx(skb, out);

	switch(verdict) {
	case ISO_VERDICT_DROP:
		return NF_DROP;

	case ISO_VERDICT_SUCCESS:
		return NF_STOLEN;

	default:
		return NF_ACCEPT;
	}

	/* Unreachable */
	return NF_DROP;
}

/* Local Variables: */
/* indent-tabs-mode:t */
/* End: */

