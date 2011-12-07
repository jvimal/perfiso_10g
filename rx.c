
#include <linux/netfilter_bridge.h>
#include "tx.h"
#include "rx.h"
#include "vq.h"

extern char *iso_param_dev;
extern struct net_device *iso_netdev;

#if defined ISO_HOOK_BRIDGE
int iso_rx_bridge_init(void);
void iso_rx_bridge_exit(void);
#elif defined ISO_HOOK_IPTABLES
int iso_rx_iptables_init(void);
void iso_rx_iptables_exit(void);
#else
#error "Please choose a hook method: ISO_HOOK_BRIDGE or ISO_HOOK_IPTABLES"
#endif

int iso_rx_init() {
	printk(KERN_INFO "perfiso: Init RX path\n");
	iso_vqs_init();
#if defined ISO_HOOK_BRIDGE
	return iso_rx_bridge_init();
#elif defined ISO_HOOK_IPTABLES
	return iso_rx_iptables_init();
#endif
}

void iso_rx_exit() {
#if defined ISO_HOOK_BRIDGE
	iso_rx_bridge_exit();
#elif defined ISO_HOOK_IPTABLES
	iso_rx_iptables_exit();
#endif
	iso_vqs_exit();
}

enum iso_verdict iso_rx(struct sk_buff *skb, const struct net_device *in)
{
	struct iso_tx_class *txc;
	iso_class_t klass;
	struct iso_per_dest_state *state;
	struct iso_vq *vq;
	struct iso_vq_stats *stats;
	struct iso_rc_state *rc;
	int changed;
	enum iso_verdict verdict = ISO_VERDICT_SUCCESS;

	rcu_read_lock();

	/* Pick VQ */
	klass = iso_rx_classify(skb);
	vq = iso_vq_find(klass);
	if(vq == NULL)
		goto accept;

	iso_vq_enqueue(vq, skb);

	txc = iso_txc_find(klass);
	if(txc == NULL)
		goto accept;

	state = iso_state_get(txc, skb, 1);
	if(unlikely(state == NULL))
		goto accept;

	rc = &state->tx_rc;
	changed = iso_rc_rx(rc, skb);

	/* XXX: for now */
	if(changed)
		state->rl->rate = rc->rfair;

	if(unlikely(iso_is_generated_feedback(skb)))
		verdict = ISO_VERDICT_DROP;

	stats = per_cpu_ptr(vq->percpu_stats, smp_processor_id());
	if(IsoAutoGenerateFeedback) {
		ktime_t now = ktime_get();
		u64 dt = ktime_us_delta(ktime_get(), stats->last_feedback_gen_time);

		if(dt > ISO_FEEDBACK_INTERVAL_US) {
			iso_generate_feedback(iso_vq_over_limits(vq), skb);
			stats->last_feedback_gen_time = now;
		}
	}

 accept:
	rcu_read_unlock();
	return verdict;
}

inline iso_class_t iso_rx_classify(struct sk_buff *skb) {
	/* Classify just like TX context would have */
	iso_class_t klass;
#if defined ISO_TX_CLASS_DEV
	klass = skb->dev;
#elif defined ISO_TX_CLASS_ETHER_SRC
	memcpy((void *)&klass, eth_hdr(skb)->h_dest, ETH_ALEN);
#elif defined ISO_TX_CLASS_MARK
	klass = skb->mark;
#endif
	return klass;
}

int iso_vq_install(char *_klass) {
	iso_class_t klass;
	struct iso_vq *vq;
	int ret = 0;

	rcu_read_lock();
	klass = iso_class_parse(_klass);
	vq = iso_vq_find(klass);
	if(vq != NULL) {
		ret = -1;
		printk(KERN_INFO "perfiso: class %s not found\n", _klass);
		goto err;
	}

	vq = iso_vq_alloc(klass);
	if(vq == NULL) {
		printk(KERN_INFO "perfiso: could not allocate vq\n");
		ret = -1;
		goto err;
	}

 err:
	rcu_read_unlock();
	return ret;
}

/* Create a feebdack packet and prepare for transmission.  Returns 1 if successful. */
inline int iso_generate_feedback(int bit, struct sk_buff *pkt) {
	struct sk_buff *skb;
	struct ethhdr *eth_to, *eth_from;
	struct iphdr *iph_to, *iph_from;

	eth_from = eth_hdr(pkt);
	if(unlikely(eth_from->h_proto != htons(ETH_P_IP)))
		return 0;

	/* XXX: netdev_alloc_skb's meant to allocate packets for receiving.
	 * Is it okay to use for transmitting?
	 */
	skb = netdev_alloc_skb(iso_netdev, ISO_FEEDBACK_PACKET_SIZE);
	if(likely(skb)) {
		skb->len = ISO_FEEDBACK_PACKET_SIZE;
		skb->protocol = htons(ETH_P_IP);
		skb->pkt_type = PACKET_OUTGOING;

		skb_reset_mac_header(skb);
		skb_set_tail_pointer(skb, ISO_FEEDBACK_PACKET_SIZE);
		eth_to = eth_hdr(skb);

		memcpy(eth_to->h_source, eth_from->h_dest, ETH_ALEN);
		memcpy(eth_to->h_dest, eth_from->h_source, ETH_ALEN);
		eth_to->h_proto = eth_from->h_proto;

		skb_pull(skb, ETH_HLEN);
		skb_reset_network_header(skb);
		iph_to = ip_hdr(skb);
		iph_from = ip_hdr(pkt);

		iph_to->ihl = 5;
		iph_to->version = 4;
		iph_to->tos = 0x2 | (bit ? ISO_ECN_REFLECT_MASK : 0);
		iph_to->tot_len = htons(ISO_FEEDBACK_HEADER_SIZE - 14);
		iph_to->id = iph_from->id;
		iph_to->frag_off = 0;
		iph_to->ttl = ISO_FEEDBACK_PACKET_TTL;
		iph_to->protocol = (u8)ISO_FEEDBACK_PACKET_IPPROTO;
		iph_to->saddr = iph_from->daddr;
		iph_to->daddr = iph_from->saddr;

		/* NB: this function doesn't "send" the packet */
		ip_send_check(iph_to);

		/* Driver owns the buffer now; we don't need to free it */
		skb_xmit(skb);
		return 1;
	}

	return 0;
}

inline int iso_is_generated_feedback(struct sk_buff *skb) {
	struct ethhdr *eth;
	struct iphdr *iph;
	eth = eth_hdr(skb);
	if(likely(eth->h_proto == htons(ETH_P_IP))) {
		iph = ip_hdr(skb);
		if(unlikely(iph->protocol == ISO_FEEDBACK_PACKET_IPPROTO))
			return 1;
	}
	return 0;
}

/* Local Variables: */
/* indent-tabs-mode:t */
/* End: */

