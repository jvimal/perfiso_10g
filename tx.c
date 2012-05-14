
#include <linux/netfilter_bridge.h>
#include <linux/if_ether.h>
#include "tx.h"
#include "vq.h"

extern char *iso_param_dev;
extern struct net_device *iso_netdev;
struct hlist_head iso_tx_bucket[ISO_MAX_TX_BUCKETS];
struct list_head txc_list;
ktime_t txc_last_update_time;
ktime_t txc_last_check_time;
s64 txc_total_tokens;
int txc_total_weight;
atomic_t txc_active_rate;
spinlock_t txc_spinlock;
extern int iso_exiting;

int iso_tx_hook_init(void);

int iso_tx_init() {
	printk(KERN_INFO "perfiso: Init TX path\n");

	INIT_LIST_HEAD(&txc_list);

	txc_last_update_time = ktime_get();
	txc_last_check_time = ktime_get();

	spin_lock_init(&txc_spinlock);
	if(iso_rl_prep())
		return -1;

	txc_total_weight = 0;
	atomic_set(&txc_active_rate, 0);

	return iso_tx_hook_init();
}

void iso_tx_exit() {
	int i;
	struct hlist_head *head;
	struct hlist_node *node, *nextnode;
	struct iso_tx_class *txc;

	iso_rl_exit();

	for(i = 0; i < ISO_MAX_TX_BUCKETS; i++) {
		head = &iso_tx_bucket[i];
		hlist_for_each_entry_safe(txc, nextnode, node, head, hash_node) {
			hlist_del(&txc->hash_node);
			iso_txc_free(txc);
		}
	}

	free_percpu(rlcb);
}

void iso_txc_check_idle() {
	struct iso_tx_class *txc, *txc_next;
	ktime_t now = ktime_get();

	for_each_txc(txc) {
		if(!spin_trylock(&txc->rl.spinlock))
			continue;

		if(txc->active && ktime_us_delta(now, txc->rl.last_update_time) > 10000) {
			txc->active = 0;
			atomic_sub(txc->rl.rate, &txc_active_rate);
		}

		spin_unlock(&txc->rl.spinlock);
	}

	txc_last_check_time = now;
}

inline void iso_txc_global_tick() {
	u64 dtokens, dt, maxtokens;
	ktime_t now = ktime_get();

	dt = ktime_us_delta(now, txc_last_update_time);

	if(dt < 10)
		return;

	dtokens = (ISO_MAX_TX_RATE * dt) >> 3;
	maxtokens = (ISO_MAX_TX_RATE * ISO_TXC_UPDATE_INTERVAL_US) >> 3;

	txc_total_tokens = min(maxtokens, txc_total_tokens + dtokens);
	txc_last_update_time = now;
}

inline void iso_txc_rl_tick(struct iso_tx_class *txc, struct iso_rl *rl) {
	unsigned long flags;
	int active_rate;
	ktime_t now;
	u64 us, min_borrow, max_tokens, curr_rate;

	now = ktime_get();
	us = ktime_us_delta(now, rl->last_update_time);

	if(unlikely(ktime_us_delta(now, txc_last_check_time) > 10000))
		iso_txc_check_idle();

	if(!spin_trylock_irqsave(&rl->spinlock, flags))
		return;

	if(rl->waiting && !txc->active) {
		txc->active = 1;
		rl->rate = txc->weight * ISO_MAX_TX_RATE / txc_total_weight;
		atomic_add(rl->rate, &txc_active_rate);
	}

	active_rate = atomic_read(&txc_active_rate);

	if(active_rate == 0) {
		/* This shouldn't be the case */
		active_rate = rl->rate;
	}

	curr_rate = (u64)ISO_MAX_TX_RATE * rl->rate / active_rate;
	min_borrow = (us * curr_rate) >> 3;

	if(spin_trylock_irq(&txc_spinlock)) {
		iso_txc_global_tick();

		if(txc_total_tokens < min_borrow) {
			min_borrow = (rl->rate * us) >> 3;
		}

		rl->total_tokens += min_borrow;
		txc_total_tokens -= min_borrow;

		spin_unlock_irq(&txc_spinlock);

		/* This ensures that between updates, this rate limiter does
		   not burst at more than max tx rate */
		//max_tokens = (u64)4 * ISO_MIN_BURST_BYTES;

		rl->total_tokens = min(rl->total_tokens, (ISO_MAX_TX_RATE * 200LLU) >> 3);
		rl->total_tokens = max(rl->total_tokens, ISO_MIN_BURST_BYTES);
		rl->last_update_time = now;
	}

 unlock:
	spin_unlock_irqrestore(&rl->spinlock, flags);
}

/* Called with rcu lock */
void iso_txc_show(struct iso_tx_class *txc, struct seq_file *s) {
	int i, nth;
	struct hlist_node *node;
	struct hlist_head *head;
	struct iso_rl *rl;
	struct iso_per_dest_state *state;

	char buff[128];
	char vqc[128];

	iso_class_show(txc->klass, buff);
	if(txc->vq) {
		iso_class_show(txc->vq->klass, vqc);
	} else {
		sprintf(vqc, "(none)");
	}

	seq_printf(s, "txc class %s  assoc vq %s  freelist %d"
			   "   active %d   txc_total %lld (%dM)\n",
			   buff, vqc, txc->freelist_count,
			   txc->active, txc_total_tokens, atomic_read(&txc_active_rate));

	seq_printf(s, "txc rl   xmit %llu   queued %llu\n",
			   txc->rl.accum_xmit, txc->rl.accum_enqueued);

	iso_rl_show(&txc->rl, s);
	seq_printf(s, "\n");

	seq_printf(s, "per dest state:\n");
	for(i = 0; i < ISO_MAX_STATE_BUCKETS; i++) {
		head = &txc->state_bucket[i];
		hlist_for_each_entry_rcu(state, node, head, hash_node) {
			seq_printf(s, "ip %x   rl %p   hash %d\n", state->ip_key, state->rl, i);
			iso_rc_show(&state->tx_rc, s);
		}
	}

	seq_printf(s, "rate limiters:\n");
	for(i = 0; i < ISO_MAX_RL_BUCKETS; i++) {
		head = &txc->rl_bucket[i];
		nth = 0;

		hlist_for_each_entry_rcu(rl, node, head, hash_node) {
			if(nth == 0) {
				seq_printf(s, "hash %d ", i);
			}
			iso_rl_show(rl, s);
			nth++;
		}
	}
	seq_printf(s, "\n");
}

enum iso_verdict iso_tx(struct sk_buff *skb, const struct net_device *out)
{
	struct iso_tx_class *txc;
	struct iso_per_dest_state *state;
	struct iso_rl *rl;
	struct iso_rl_queue *q;
	struct iso_vq *vq;
	enum iso_verdict verdict = ISO_VERDICT_PASS;
	int cpu = smp_processor_id();

	rcu_read_lock();

	txc = iso_txc_find(iso_txc_classify(skb));
	if(txc == NULL)
		goto accept;

	state = iso_state_get(txc, skb, 0);
	if(unlikely(state == NULL)) {
		/* printk(KERN_INFO "perfiso: running out of memory!\n"); */
		/* XXX: Temporary: could be an L2 packet... */
		goto accept;
	}

	rl = state->rl;
	vq = txc->vq;

	/* XXX: find out if this is really needed */
	// iso_txc_rl_tick(txc, &txc->rl);

	/* Enqueue in RL */
	verdict = iso_rl_enqueue(rl, skb, cpu);
	q = per_cpu_ptr(rl->queue, cpu);

	if(likely(vq)) {
		if(iso_vq_over_limits(vq))
			q->feedback_backlog++;
	}

	iso_rl_dequeue((unsigned long)q);
 accept:
	rcu_read_unlock();
	return verdict;
}

/* Called with rcu lock */
struct iso_per_dest_state
*iso_state_get(struct iso_tx_class *txc,
			   struct sk_buff *skb,
			   int rx)
{
	struct ethhdr *eth;
	struct iphdr *iph;
	struct iso_per_dest_state *state = NULL, *nextstate;
	struct hlist_head *head;
	struct hlist_node *node;

	u32 ip, hash;

	eth = eth_hdr(skb);

	if(unlikely(eth->h_proto != __constant_htons(ETH_P_IP))) {
		/* TODO: l2 packet, map all to a single rate state and RL */
		/* Right now, we just pass it thru */
		return NULL;
	}

	iph = ip_hdr(skb);

	ip = ntohl(iph->daddr);
	if(rx) ip = ntohl(iph->saddr);

	hash = jhash_1word(ip, 0xfacedead) & (ISO_MAX_STATE_BUCKETS - 1);
	head = &txc->state_bucket[hash];

	state = NULL;
	hlist_for_each_entry_rcu(state, node, head, hash_node) {
		if(state->ip_key == ip)
			break;
	}

	if(likely(state != NULL))
		return state;

	if(!spin_trylock(&txc->writelock))
		return NULL;

	/* Check again; shouldn't we use a rwlock_t? */
	hlist_for_each_entry_rcu(state, node, head, hash_node) {
		if(state->ip_key == ip)
			break;
	}

	if(unlikely(state != NULL))
		goto unlock;

	list_for_each_entry_safe(state, nextstate, &txc->prealloc_state_list, prealloc_list) {
		state->ip_key = ip;
		state->rl = iso_pick_rl(txc, ip);
		if(state->rl == NULL)
			break;

		iso_rc_init(&state->tx_rc);
		INIT_HLIST_NODE(&state->hash_node);
		hlist_add_head_rcu(&state->hash_node, head);
		/* remove from prealloc list */
		list_del_init(&state->prealloc_list);
		txc->freelist_count--;
		break;
	}

	/* Do we need to reallocate? */
	if(txc->freelist_count <= 10)
		schedule_work(&txc->allocator);

 unlock:
	spin_unlock(&txc->writelock);

	return state;
}

void iso_state_free(struct iso_per_dest_state *state) {
	free_percpu(state->tx_rc.stats);
	kfree(state);
}

/* Called with txc->writelock */
struct iso_rl *iso_pick_rl(struct iso_tx_class *txc, __le32 ip) {
	struct iso_rl *rl = NULL, *temp;
	struct hlist_head *head;
	struct hlist_node *node;
	rcu_read_lock();

	head = &txc->rl_bucket[jhash_1word(ip, 0xfaceface) & (ISO_MAX_RL_BUCKETS - 1)];
	hlist_for_each_entry_rcu(rl, node, head, hash_node) {
		if(rl->ip == ip)
			goto found;
	}

	rl = NULL;
	list_for_each_entry_safe(rl, temp, &txc->prealloc_rl_list, prealloc_list) {
		rl->ip = ip;
		hlist_add_head_rcu(&rl->hash_node, head);
		/* remove from prealloc list */
		list_del_init(&rl->prealloc_list);
		break;
	}

 found:
	rcu_read_unlock();

	return rl;
}

void iso_txc_init(struct iso_tx_class *txc) {
	int i;
	for(i = 0; i < ISO_MAX_RL_BUCKETS; i++)
		INIT_HLIST_HEAD(&txc->rl_bucket[i]);

	for(i = 0; i < ISO_MAX_STATE_BUCKETS; i++)
		INIT_HLIST_HEAD(&txc->state_bucket[i]);

	INIT_LIST_HEAD(&txc->list);
	INIT_LIST_HEAD(&txc->prealloc_state_list);
	INIT_LIST_HEAD(&txc->prealloc_rl_list);

	INIT_HLIST_NODE(&txc->hash_node);
	txc->vq = NULL;
	spin_lock_init(&txc->writelock);
	txc->freelist_count = 0;

	iso_rl_init(&txc->rl);
	txc->weight = 1;
	txc->active = 0;
	txc->vrate = 100;

	INIT_WORK(&txc->allocator, iso_txc_allocator);
}

void iso_txc_allocator(struct work_struct *work) {
	struct iso_tx_class *txc = container_of(work, struct iso_tx_class, allocator);
	iso_txc_prealloc(txc, 32);
}

/* Can sleep */
struct iso_tx_class *iso_txc_alloc(iso_class_t klass) {
	struct iso_tx_class *txc;
	struct hlist_head *head;

	txc = kmalloc(sizeof(*txc), GFP_KERNEL);
	if(!txc)
		return NULL;

	iso_txc_init(txc);
	txc->klass = klass;

	/* Preallocate some perdest state and rate limiters.  32 entries
	 * ought to be enough for everybody ;) */
	iso_txc_prealloc(txc, 32);

	rcu_read_lock();
	head = iso_txc_find_bucket(klass);
	hlist_add_head_rcu(&txc->hash_node, head);
	list_add_tail_rcu(&txc->list, &txc_list);
	txc_total_weight += txc->weight;
	iso_txc_recompute_rates();
	rcu_read_unlock();

	return txc;
}

void iso_state_init(struct iso_per_dest_state *state) {
	state->rl = NULL;
	iso_rc_init(&state->tx_rc);
	INIT_LIST_HEAD(&state->prealloc_list);
	INIT_HLIST_NODE(&state->hash_node);
}

void iso_txc_prealloc(struct iso_tx_class *txc, int num) {
	int i;
	struct iso_per_dest_state *state;
	struct iso_rl *rl;
	unsigned long flags;

	printk(KERN_INFO "Preallocating %d RLs and per-dest-states\n", num);

	for(i = 0; i < num; i++) {
		state = kmalloc(sizeof(*state), GFP_KERNEL);
		if(state == NULL)
			break;

		state->tx_rc.stats = alloc_percpu(struct iso_rc_stats);
		if(state->tx_rc.stats == NULL) {
			kfree(state);
			break;
		}

		rl = kmalloc(sizeof(*rl), GFP_KERNEL);
		if(rl == NULL) {
			free_percpu(state->tx_rc.stats);
			kfree(state);
			break;
		}

		iso_state_init(state);
		iso_rl_init(rl);
		rl->txc = txc;

		spin_lock_irqsave(&txc->writelock, flags);
		txc->freelist_count++;
		list_add_tail(&state->prealloc_list, &txc->prealloc_state_list);
		list_add_tail(&rl->prealloc_list, &txc->prealloc_rl_list);
		spin_unlock_irqrestore(&txc->writelock, flags);
	}
}

/* Called with rcu lock */
void iso_txc_free(struct iso_tx_class *txc) {
	struct hlist_head *head;
	struct hlist_node *n, *nn;
	struct iso_rl *rl, *temprl;
	struct iso_per_dest_state *state, *tempstate;
	int i;

	synchronize_rcu();

	/* Kill each rate limiter */
	for(i = 0; i < ISO_MAX_RL_BUCKETS; i++) {
		head = &txc->rl_bucket[i];
		hlist_for_each_entry_safe(rl, n, nn, head, hash_node) {
			hlist_del_init_rcu(&rl->hash_node);
			iso_rl_free(rl);
		}
	}

	/* Kill each state */
	for(i = 0; i < ISO_MAX_STATE_BUCKETS; i++) {
		head = &txc->state_bucket[i];
		hlist_for_each_entry_safe(state, n, nn, head, hash_node) {
			hlist_del_init_rcu(&state->hash_node);
			iso_state_free(state);
		}
	}

	/* Release the class; it could be an interface */
	iso_class_free(txc->klass);

	/* Free preallocated */
	list_for_each_entry_safe(rl, temprl, &txc->prealloc_rl_list, prealloc_list) {
		list_del_rcu(&rl->prealloc_list);
		iso_rl_free(rl);
	}

	list_for_each_entry_safe(state, tempstate, &txc->prealloc_state_list, prealloc_list) {
		list_del_rcu(&state->prealloc_list);
		iso_state_free(state);
	}

	if(txc->vq) {
		atomic_dec(&txc->vq->refcnt);
	}

	free_percpu(txc->rl.queue);
	kfree(txc);
}

#if defined ISO_TX_CLASS_DEV
int iso_txc_dev_install(char *name) {
	struct iso_tx_class *txc;
	struct net_device *dev;
	int ret = 0;

	rcu_read_lock();
	dev = dev_get_by_name_rcu(&init_net, name);

	if(dev == NULL) {
		printk(KERN_INFO "perfiso: dev %s not found!\n", name);
		ret = -1;
		goto err;
	}

	/* Check if we have already created */
	txc = iso_txc_find(dev);
	if(txc != NULL) {
		dev_put(dev);
		ret = -1;
		goto err;
	}

	txc = iso_txc_alloc(dev);

	if(txc == NULL) {
		dev_put(dev);
		printk(KERN_INFO "perfiso: Could not allocate tx context\n");
		ret = -1;
		goto err;
	}

 err:
	rcu_read_unlock();
	return ret;
}
#elif defined ISO_TX_CLASS_ETHER_SRC
int iso_txc_ether_src_install(char *hwaddr) {
	iso_class_t ether_src;
	int ret = 0;
	struct iso_tx_class *txc;

	ret = -!mac_pton(hwaddr, (u8*)&ether_src);

	if(ret) {
		printk(KERN_INFO "perfiso: Cannot parse ether address from %s\n", hwaddr);
		goto end;
	}

	/* Check if we have already created */
	txc = iso_txc_find(ether_src);
	if(txc != NULL) {
		ret = -1;
		goto end;
	}

	txc = iso_txc_alloc(ether_src);

	if(txc == NULL) {
		ret = -1;
		goto end;
	}

 end:
	return ret;
}
#elif defined (ISO_TX_CLASS_MARK) || defined (ISO_TX_CLASS_IPADDR)
int iso_txc_mark_install(char *mark) {
	iso_class_t m = iso_class_parse(mark);
	struct iso_tx_class *txc;
	int ret = 0;

	/* Check if we have already created */
	txc = iso_txc_find(m);
	if(txc != NULL) {
		ret = -1;
		goto end;
	}

	txc = iso_txc_alloc(m);
	if(txc == NULL) {
		ret = -1;
		goto end;
	}

 end:
	return ret;
}
#endif

int iso_txc_install(char *klass) {
	int ret;
#if defined ISO_TX_CLASS_DEV
	ret = iso_txc_dev_install(klass);
#elif defined ISO_TX_CLASS_ETHER_SRC
	ret = iso_txc_ether_src_install(klass);
#elif defined (ISO_TX_CLASS_MARK) || defined (ISO_TX_CLASS_IPADDR)
	ret = iso_txc_mark_install(klass);
#endif
	return ret;
}
/* Local Variables: */
/* indent-tabs-mode:t */
/* End: */

