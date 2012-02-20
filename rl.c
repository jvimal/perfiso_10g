
#include "rl.h"
#include "tx.h"

extern int iso_exiting;

void iso_rl_init(struct iso_rl *rl) {
	int i;
	rl->rate = ISO_RFAIR_INITIAL;
	rl->total_tokens = 15000;
	rl->last_update_time = ktime_get();
	rl->local = alloc_percpu(struct iso_rl_local);
	rl->accum_xmit = 0;
	rl->bytes_enqueued = 0;
	rl->first_pkt_size = 0;

	spin_lock_init(&rl->spinlock);
	skb_queue_head_init(&rl->queue);

	hrtimer_init(&rl->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	rl->timer.function = iso_rl_timeout;

	tasklet_init(&rl->xmit_tasklet, iso_rl_dequeue, (unsigned long)rl);

	for_each_possible_cpu(i) {
		struct iso_rl_local *l = per_cpu_ptr(rl->local, i);

		l->bytes_xmit = 0;

		l->feedback_backlog = 0;
		l->token_pool = NULL;
		l->tokens = 0;

		l->cpu = i;
		l->rl = rl;
	}

	INIT_LIST_HEAD(&rl->prealloc_list);
	rl->parent = NULL;
}

void iso_rl_free(struct iso_rl *rl) {
	free_percpu(rl->local);
	kfree(rl);
}

/* Called with rcu lock */
void iso_rl_show(struct iso_rl *rl, struct seq_file *s) {
	struct iso_rl_local *l;
	int i, first = 1;

	seq_printf(s, "ip %x   rate %u   total_tokens %llu   last %llx   "
			   "first_pkt_size %u   enqueued %u   %p\n",
			   rl->ip, rl->rate, rl->total_tokens, *(u64 *)&rl->last_update_time,
			   rl->first_pkt_size, skb_queue_len(&rl->queue), rl);

	for_each_online_cpu(i) {
		if(first) {
			seq_printf(s, "\tcpu   fbacklog   tokens   xmit\n");
			first = 0;
		}
		l = per_cpu_ptr(rl->local, i);

		if(l->tokens > 0) {
			seq_printf(s, "\t%3d   %10llu   %6u   %10llu\n",
					   i, l->feedback_backlog, l->tokens, l->bytes_xmit);
		}
	}
}

inline void iso_rl_clock(struct iso_rl *rl) {
	u64 cap, us;
	ktime_t now;

	if(!iso_rl_should_refill(rl))
		return;

	now = ktime_get();
	us = ktime_us_delta(now, rl->last_update_time);
	rl->total_tokens += (rl->rate * us) >> 3;

	/* This is needed if we have TSO.  MIN_BURST_BYTES will be ~64K */
	cap = max((rl->rate * ISO_MAX_BURST_TIME_US) >> 3, (u32)ISO_MIN_BURST_BYTES);
	rl->total_tokens = min(cap, rl->total_tokens);

	rl->last_update_time = now;
}

enum iso_verdict iso_rl_xmit(struct iso_rl *rl, struct sk_buff *pkt) {
	struct iso_rl_local *l = per_cpu_ptr(rl->local, smp_processor_id());
	enum iso_verdict verdict = ISO_VERDICT_SUCCESS;
	int len, bunch;

	len = skb_size(pkt);

	if(len < l->tokens) {
		l->tokens -= len;
		if(l->feedback_backlog) {
			if(!skb_set_feedback(pkt))
				l->feedback_backlog = 0;
		}

		skb_xmit(pkt);
	} else {
		spin_lock(&rl->spinlock);

		bunch = iso_rl_borrow(rl, len);

		if(bunch) {
			l->tokens += (bunch - len);
		} else {
			verdict = iso_rl_enqueue(rl, pkt);
		}

		spin_unlock(&rl->spinlock);

		if(bunch) {
			if(l->feedback_backlog) {
				if(!skb_set_feedback(pkt))
					l->feedback_backlog = 0;
			}

			skb_xmit(pkt);
		} else {
			/* XXX: Start timer, or enqueue in backlog list */
			if(!hrtimer_active(&rl->timer))
				hrtimer_start(&rl->timer, iso_rl_gettimeout(), HRTIMER_MODE_REL);
		}
	}

	return verdict;
}

/* Simple enqueue function */
inline enum iso_verdict iso_rl_enqueue(struct iso_rl *rl, struct sk_buff *pkt) {
	if(skb_queue_len(&rl->queue) > ISO_MAX_QUEUE_LEN_PKT)
		return ISO_VERDICT_DROP;
	__skb_queue_tail(&rl->queue, pkt);
	rl->bytes_enqueued += skb_size(pkt);
	return ISO_VERDICT_SUCCESS;
}

/* This function MUST be executed with interrupts enabled */
void iso_rl_dequeue(unsigned long _rl) {
	u32 size;
	int timeout = 0;
	struct sk_buff *pkt;
	struct iso_rl *rl = (struct iso_rl *)_rl;
	struct sk_buff_head list, *skq;

	/*
	 * Two cases:
	 * (1) the current CPU holds the spinlock, but it's always
	 * held from a sirq and sirq's cannot be pre-empted by another sirq.
	 *
	 * (2) another CPU is holding the lock, so we spin-wait
	 */

	spin_lock(&rl->spinlock);
	iso_rl_clock(rl);
	skb_queue_head_init(&list);
	skq = &rl->queue;

	/* This shouldn't happen... */
	if(skb_queue_len(skq) == 0)
		goto unlock;

	pkt = skb_peek(skq);
	size = skb_size(pkt);
	rl->first_pkt_size = size;
	timeout = 1;

	while(size <= rl->total_tokens) {
		pkt = __skb_dequeue(skq);
		rl->total_tokens -= size;
		rl->bytes_enqueued -= size;

		__skb_queue_tail(&list, pkt);

		if(skb_queue_len(skq) == 0) {
			timeout = 0;
			break;
		}

		pkt = skb_peek(skq);
		size = skb_size(pkt);
		rl->first_pkt_size = size;
	}

unlock:
	spin_unlock(&rl->spinlock);

	/* Now transfer the dequeued packets to the parent's queue */
	while((pkt = __skb_dequeue(&list)) != NULL) {
		skb_xmit(pkt);
	}

	if(timeout && !iso_exiting) {
		if(!hrtimer_active(&rl->timer))
			hrtimer_start(&rl->timer, iso_rl_gettimeout(), HRTIMER_MODE_REL);
	}
}

/* HARDIRQ timeout */
enum hrtimer_restart iso_rl_timeout(struct hrtimer *timer) {
	/* schedue xmit tasklet to go into softirq context */
	struct iso_rl *rl = container_of(timer, struct iso_rl, timer);
	tasklet_schedule(&rl->xmit_tasklet);
	return HRTIMER_NORESTART;
}

/* Borrow at least min tokens; called with rl lock held */
inline u64 iso_rl_borrow(struct iso_rl *rl, u64 minimum) {
	u64 borrow = max(iso_rl_singleq_burst(rl), minimum);
	u64 borrowp;
	u64 ret = 0;

	if(rl->total_tokens >= borrow) {
		rl->total_tokens -= borrow;
		ret = borrow;
	} else if(rl->parent != NULL) {
		borrowp = iso_rl_borrow(rl->parent, minimum);
		rl->total_tokens += borrowp;

		/* Unroll the second iteration */
		if(borrowp && rl->total_tokens >= borrow) {
			rl->total_tokens -= borrow;
			ret = borrow;
		}
	}

	return ret;
}

/* Local Variables: */
/* indent-tabs-mode:t */
/* End: */
