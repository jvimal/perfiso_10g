
#include "rl.h"
#include "tx.h"

struct iso_rl_cb __percpu *rlcb;
extern int iso_exiting;

/* Called the first time when the module is initialised */
int iso_rl_prep() {
	int cpu, max;

	rlcb = alloc_percpu(struct iso_rl_cb);
	if(rlcb == NULL)
		return -1;

	/* Init everything; but what about hotplug?  Hmm... */
	for_each_possible_cpu(cpu) {
		struct iso_rl_cb *cb = per_cpu_ptr(rlcb, cpu);
		spin_lock_init(&cb->spinlock);
		cb->cpu = cpu;
		INIT_LIST_HEAD(&cb->active_list);

		cb->thread = kthread_create(iso_rl_thread, (void *)cb, "iso_rl_thread");

		if(IS_ERR(cb->thread)) {
			printk(KERN_INFO "kthread creation failed on cpu %d\n", cpu);
			goto err;
		}

		kthread_bind(cb->thread, cpu);
	}

	for_each_possible_cpu(cpu) {
		struct iso_rl_cb *cb = per_cpu_ptr(rlcb, cpu);
		wake_up_process(cb->thread);
	}

	return 0;

 err:
	max = cpu;
	for_each_possible_cpu(cpu) {
		struct iso_rl_cb *cb = per_cpu_ptr(rlcb, cpu);

		if(cpu >= max)
			break;

		if(!IS_ERR(cb->thread))
			kthread_stop(cb->thread);
	}

	free_percpu(rlcb);
	return -1;
}

void iso_rl_exit() {
	int cpu;

	for_each_possible_cpu(cpu) {
		struct iso_rl_cb *cb = per_cpu_ptr(rlcb, cpu);
		kthread_stop(cb->thread);
	}
}

int iso_rl_thread(void *_cb) {
	struct iso_rl_cb *cb = (struct iso_rl_cb *)_cb;
	struct iso_rl_queue *q, *qnext, *first;
	unsigned long us, count;

#define budget 1024

	while(!kthread_should_stop()) {
		count = 0;
		first = list_entry(cb->active_list.next, struct iso_rl_queue, active_list);

		/* This call can nest */
		local_bh_disable();
		list_for_each_entry_safe(q, qnext, &cb->active_list, active_list) {
			if(count == 0)
				first = q;
			if(qnext == first || count++ > budget)
				break;

			iso_rl_clock(q->rl);
			list_del_init(&q->active_list);
			iso_rl_dequeue((unsigned long)q);
		}
		local_bh_enable();

		us = ISO_TOKENBUCKET_TIMEOUT_NS/1000;
		usleep_range(us, us);
	}

	return 0;
}

void iso_rl_init(struct iso_rl *rl) {
	int i;
	rl->rate = ISO_RFAIR_INITIAL;
	rl->total_tokens = 15000;
	rl->last_update_time = ktime_get();
	rl->queue = alloc_percpu(struct iso_rl_queue);
	rl->accum_xmit = 0;
	rl->accum_enqueued = 0;
	spin_lock_init(&rl->spinlock);

	for_each_possible_cpu(i) {
		struct iso_rl_queue *q = per_cpu_ptr(rl->queue, i);

		skb_queue_head_init(&q->list);
		q->first_pkt_size = 0;
		q->bytes_enqueued = 0;
		q->bytes_xmit = 0;

		q->feedback_backlog = 0;
		q->tokens = 0;

		spin_lock_init(&q->spinlock);

		q->cpu = i;
		q->rl = rl;

		INIT_LIST_HEAD(&q->active_list);
	}

	INIT_LIST_HEAD(&rl->prealloc_list);
	rl->txc = NULL;
}

void iso_rl_free(struct iso_rl *rl) {
	free_percpu(rl->queue);
	kfree(rl);
}

/* Called with rcu lock */
void iso_rl_show(struct iso_rl *rl, struct seq_file *s) {
	struct iso_rl_queue *q;
	int i, first = 1;

	seq_printf(s, "ip %x   rate %llu   total_tokens %llu   last %llx   %p\n",
			   rl->ip, rl->rate, rl->total_tokens, *(u64 *)&rl->last_update_time, rl);

	for_each_online_cpu(i) {
		if(first) {
			seq_printf(s, "\tcpu   len"
					   "   first_len   queued   fbacklog   tokens  active?\n");
			first = 0;
		}
		q = per_cpu_ptr(rl->queue, i);

		if(q->tokens > 0 || skb_queue_len(&q->list) > 0) {
			seq_printf(s, "\t%3d   %3d   %3d   %10llu   %6llu   %10llu   %d\n",
					   i, skb_queue_len(&q->list), q->first_pkt_size,
					   q->bytes_enqueued, q->feedback_backlog, q->tokens,
					   !list_empty(&q->active_list));
		}
	}
}

/* This function could be called from HARDIRQ context */
void iso_rl_clock(struct iso_rl *rl) {
	unsigned long flags;
	u64 cap, us;
	ktime_t now;

	if(!iso_rl_should_refill(rl))
		return;

	if(!spin_trylock_irqsave(&rl->spinlock, flags))
		return;

	now = ktime_get();
	us = ktime_us_delta(now, rl->last_update_time);
	rl->total_tokens += (rl->rate * us) >> 3;

	/* This is needed if we have TSO.  MIN_BURST_BYTES will be ~64K */
	cap = max((rl->rate * ISO_MAX_BURST_TIME_US) >> 3, (u64)ISO_MIN_BURST_BYTES);
	rl->total_tokens = min(cap, rl->total_tokens);

	rl->last_update_time = now;

	spin_unlock_irqrestore(&rl->spinlock, flags);
}

enum iso_verdict iso_rl_enqueue(struct iso_rl *rl, struct sk_buff *pkt, int cpu) {
	struct iso_rl_queue *q = per_cpu_ptr(rl->queue, cpu);
	enum iso_verdict verdict;

	spin_lock(&q->spinlock);

	if(skb_queue_len(&q->list) == ISO_MAX_QUEUE_LEN_PKT+1) {
		verdict = ISO_VERDICT_DROP;
		goto done;
	}

	/* we don't need locks */
	__skb_queue_tail(&q->list, pkt);
	q->bytes_enqueued += skb_size(pkt);

	verdict = ISO_VERDICT_SUCCESS;

 done:
	spin_unlock(&q->spinlock);
	return verdict;
}

/* This function MUST be executed with interrupts enabled */
void iso_rl_dequeue(unsigned long _q) {
	int timeout = 0;
	u64 sum = 0;
	u32 size;
	struct sk_buff *pkt;
	struct iso_rl_queue *q = (struct iso_rl_queue *)_q;
	struct iso_rl_queue *rootq;
	struct iso_rl *rl = q->rl;
	enum iso_verdict verdict;
	struct sk_buff_head *skq, list;

	/* Try to borrow from the global token pool; if that fails,
	   program the timeout for this queue */

	if(unlikely(q->tokens < q->first_pkt_size)) {
		timeout = iso_rl_borrow_tokens(rl, q);
		if(timeout)
			goto timeout;
	}

	spin_lock(&q->spinlock);
	skb_queue_head_init(&list);
	skq = &q->list;

	if(skb_queue_len(skq) == 0)
		goto unlock;

	pkt = skb_peek(skq);
	sum = size = skb_size(pkt);
	q->first_pkt_size = size;
	timeout = 1;

	while(sum <= q->tokens) {
		pkt = __skb_dequeue(skq);
		q->tokens -= size;
		q->bytes_enqueued -= size;

		if(q->feedback_backlog) {
			if(!skb_set_feedback(pkt))
				q->feedback_backlog = 0;
		}

		if(rl->txc == NULL) {
			skb_xmit(pkt);
			q->bytes_xmit += size;
		} else {
			/* Enqueue in parent tx class's rate limiter */
			__skb_queue_tail(&list, pkt);
		}

		if(skb_queue_len(skq) == 0) {
			timeout = 0;
			break;
		}

		pkt = skb_peek(skq);
		sum += (size = skb_size(pkt));
		q->first_pkt_size = size;
	}

unlock:
	spin_unlock(&q->spinlock);

	if(rl->txc != NULL) {
		/* Now transfer the dequeued packets to the parent's queue */
		while((pkt = __skb_dequeue(&list)) != NULL) {
			verdict = iso_rl_enqueue(&rl->txc->rl, pkt, q->cpu);
			if(verdict == ISO_VERDICT_DROP)
				kfree_skb(pkt);
		}

		/* Trigger the parent dequeue */
		rootq = per_cpu_ptr(rl->txc->rl.queue, q->cpu);
		iso_rl_dequeue((unsigned long)rootq);
	}

timeout:
	if(timeout && list_empty(&q->active_list)) {
		struct iso_rl_cb *cb = per_cpu_ptr(rlcb, q->cpu);
		list_add_tail(&q->active_list, &cb->active_list);
	}

	return;
}

inline int iso_rl_borrow_tokens(struct iso_rl *rl, struct iso_rl_queue *q) {
	unsigned long flags;
	u64 borrow;
	int timeout = 1;

	spin_lock_irqsave(&rl->spinlock, flags);
	borrow = max(iso_rl_singleq_burst(rl), (u64)q->first_pkt_size);

	if(rl->total_tokens >= borrow) {
		rl->total_tokens -= borrow;
		q->tokens += borrow;
		/* XXX: Because we borrow when we are running low of tokens,
		   we don't need to cap */
		/*
		  cap = max((rl->rate * ISO_MAX_BURST_TIME_US) >> 3, (u64)ISO_MIN_BURST_BYTES);
		  q->tokens = min(cap, q->tokens);
		*/
		timeout = 0;
	}

	spin_unlock_irqrestore(&rl->spinlock, flags);
	return timeout;
}

/* Local Variables: */
/* indent-tabs-mode:t */
/* End: */
