#ifndef __RL_H__
#define __RL_H__
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/completion.h>
#include <linux/hrtimer.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/seq_file.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ktime.h>
#include <net/ip.h>
#include <net/inet_ecn.h>
#include <net/tcp.h>
#include <net/dst.h>
#include <linux/hash.h>
#include <linux/crc16.h>
#include "params.h"

#define RLNAME_MAX_CHARS (64)

enum iso_verdict {
	ISO_VERDICT_SUCCESS,
	ISO_VERDICT_DROP,
	ISO_VERDICT_PASS,
	ISO_VERDICT_ERROR,
};

struct iso_rl_queue {
	struct sk_buff_head list;
	int first_pkt_size;
	u64 bytes_enqueued;
	u64 bytes_xmit;
	u64 tokens;
	int cpu;
	int waiting;

	struct iso_rl *rl;
	struct hrtimer *cputimer;
	struct list_head active_list;
};

struct iso_rl {
	u32 ip;
	u32 rate;
	u32 weight, waiting;
	u32 active_weight;

	spinlock_t spinlock;
	u64 total_tokens;
	ktime_t last_update_time;
	ktime_t last_rate_update_time;
	char name[RLNAME_MAX_CHARS];
	/* 0 if the rl is really a "class" without a queue. */
	int leaf;
	int cap;
	int throttled;

	u64 accum_xmit, accum_enqueued;

	struct iso_rl *parent;
	struct list_head siblings;
	struct list_head children;
	struct list_head waiting_list;
	struct list_head waiting_node;
	struct list_head prealloc_list;
	struct hlist_node hash_node;
	struct iso_tx_class *txc;

	/* The list of all rls */
	struct list_head list;
	struct iso_rl_queue __percpu *queue;
};

/* The per-cpu control block for rate limiters */
struct iso_rl_cb {
	spinlock_t spinlock;
	struct hrtimer timer;
	struct tasklet_struct xmit_timeout;
	struct list_head active_list;
#ifdef DEBUG
	ktime_t last;
	u64 avg_us;
#endif
	int cpu;
};

extern struct iso_rl_cb __percpu *rlcb;
extern struct iso_rl *rootrl;
extern struct list_head rls;

/* The few rate limiter parameters */
extern int ISO_TOKENBUCKET_TIMEOUT_NS;
extern int ISO_MAX_BURST_TIME_US;
extern int ISO_BURST_FACTOR;
extern int ISO_RATE_INITIAL;
extern int ISO_MAX_QUEUE_LEN_BYTES;
extern int ISO_MIN_BURST_BYTES;
extern void skb_xmit(struct sk_buff *);

void iso_rl_exit(void);
int iso_rl_prep(void);
int iso_rl_init(struct iso_rl *);

struct iso_rl *iso_rl_new(char *name);
int iso_rl_attach(struct iso_rl *parent, struct iso_rl *child);
inline void iso_rl_dequeue_root(void);

void iso_rl_free(struct iso_rl *);
void iso_rl_show(struct iso_rl *, struct seq_file *);
inline void iso_rl_clock(struct iso_rl *);
enum iso_verdict iso_rl_enqueue(struct iso_rl *, struct sk_buff *, int cpu);
u32 iso_rl_dequeue(unsigned long _q);
enum hrtimer_restart iso_rl_timeout(struct hrtimer *);
inline int iso_rl_borrow_tokens(struct iso_rl *, struct iso_rl_queue *);
static inline ktime_t iso_rl_gettimeout(void);
static inline u64 iso_rl_singleq_burst(struct iso_rl *);
void iso_rl_xmit_tasklet(unsigned long _cb);
inline void iso_rl_activate_queue(struct iso_rl_queue *q);
inline void iso_rl_deactivate_queue(struct iso_rl_queue *q);

inline void iso_rl_activate_tree(struct iso_rl *rl, struct iso_rl_queue *q);
inline void iso_rl_deactivate_tree(struct iso_rl *rl, struct iso_rl_queue *q);
inline void iso_rl_fill_tokens(void);

static inline int skb_size(struct sk_buff *skb) {
	return ETH_HLEN + skb->len;
}

static inline ktime_t iso_rl_gettimeout() {
	return ktime_set(0, ISO_TOKENBUCKET_TIMEOUT_NS);
}


static inline u64 iso_rl_singleq_burst(struct iso_rl *rl) {
	return ((rl->rate * ISO_MAX_BURST_TIME_US) >> 3) / ISO_BURST_FACTOR;
}

static inline void iso_rl_accum(struct iso_rl *rl) {
	u64 xmit;
	int i;
	struct iso_rl_queue *q;

	xmit = 0;
	for_each_online_cpu(i) {
		q = per_cpu_ptr(rl->queue, i);
		xmit += q->bytes_xmit;
	}

	rl->accum_xmit = xmit;
}


#define ISO_ECN_REFLECT_MASK (1 << 3)

static inline int skb_set_feedback(struct sk_buff *skb) {
	struct ethhdr *eth;
	struct iphdr *iph;
	u8 newdscp;

	eth = eth_hdr(skb);
	if(unlikely(eth->h_proto != __constant_htons(ETH_P_IP)))
		return 1;

	iph = ip_hdr(skb);
	newdscp = iph->tos | ISO_ECN_REFLECT_MASK;
	ipv4_copy_dscp(newdscp, iph);
	return 0;
}

static inline int skb_has_feedback(struct sk_buff *skb) {
	struct ethhdr *eth;
	struct iphdr *iph;

	eth = eth_hdr(skb);
	if(unlikely(eth->h_proto != __constant_htons(ETH_P_IP)))
		return 0;

	iph = ip_hdr(skb);
	if(likely(iph->protocol != ISO_FEEDBACK_PACKET_IPPROTO))
		return 0;
	return iph->id;
}

#endif /* __RL_H__ */

/* Local Variables: */
/* indent-tabs-mode:t */
/* End: */
