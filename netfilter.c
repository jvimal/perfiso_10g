#include <linux/netfilter_bridge.h>
#include "rl.h"

#ifndef NETFILTER
#error "Compiling netfilter.c without -DNETFILTER"
#endif

/*
 * TODO: running this code for a long time triggers a
 * "bug while scheduling atomic"; so we're grabbing a
 * lock somewhere...  Until that's sorted, netfilter
 * stays in a separate branch.
 */

typedef int (*ok_fn_t)(struct sk_buff *);
struct ok_func_ptr {
	ok_fn_t function;
};

#define OKPTR(skb) ((struct ok_func_ptr *)((skb)->cb))

extern struct net_device *iso_netdev;
struct nf_hook_ops hook_in;
struct nf_hook_ops hook_out;

/* Bridge specific code */
unsigned int iso_rx_netfilter(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *));

unsigned int iso_tx_netfilter(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *));

int iso_tx_hook_init(void);
void iso_tx_hook_exit(void);

int iso_rx_hook_init(void);
void iso_rx_hook_exit(void);


enum iso_verdict iso_tx(struct sk_buff *skb, const struct net_device *out);
enum iso_verdict iso_rx(struct sk_buff *skb, const struct net_device *in);

/* This is what "br_dev_queue_push_xmit" would do */
inline void skb_xmit(struct sk_buff *skb) {
	ok_fn_t okfn = OKPTR(skb)->function;
	if(likely(okfn)) {
		okfn(skb);
	} else {
		skb_push(skb, ETH_HLEN);
		dev_queue_xmit(skb);
	}
}

int iso_tx_hook_init() {
	if(iso_netdev == NULL)
		return 1;

	hook_out.hook = iso_tx_netfilter;
	hook_out.hooknum= NF_INET_POST_ROUTING;
	hook_out.pf = PF_INET;
	hook_out.priority = NF_IP_PRI_FIRST;

    return nf_register_hook(&hook_out);
}

int iso_rx_hook_init() {
	hook_in.hook = iso_rx_netfilter;
	hook_in.hooknum= NF_INET_PRE_ROUTING;
	hook_in.pf = PF_INET;
	hook_in.priority = NF_IP_PRI_FIRST;

    return nf_register_hook(&hook_in);
}

void iso_tx_hook_exit() {
	nf_unregister_hook(&hook_out);
}

void iso_rx_hook_exit() {
	nf_unregister_hook(&hook_in);
}


unsigned int iso_rx_netfilter(unsigned int hooknum,
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

unsigned int iso_tx_netfilter(unsigned int hooknum,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	enum iso_verdict verdict;

	/* out shouldn't be NULL, but let's be careful anyway */
	if(out != iso_netdev)
		return NF_ACCEPT;

	rcu_read_lock_bh();
	OKPTR(skb)->function = okfn;
	verdict = iso_tx(skb, out);
	rcu_read_unlock_bh();

	switch(verdict) {
	case ISO_VERDICT_DROP:
		return NF_DROP;

	case ISO_VERDICT_SUCCESS:
		return NF_STOLEN;

	case ISO_VERDICT_PASS:
	default:
		return NF_ACCEPT;
	}

	/* Unreachable */
	return NF_DROP;
}

/* Local Variables: */
/* indent-tabs-mode:t */
/* End: */
