/*
 * net/sched/sch_eyeq.c		EyeQ end-to-end QoS scheduler.
 *
 * Reuses code from sch_mq.c: Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <linux/interrupt.h>
#include <linux/hrtimer.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>

#define ISO_QUANTUM_BYTES (65536)
#define ONE_GBPS (1LLU * 1000 * 1000 * 1000)
#define RL_DIRECT ((struct iso_rl_class *)-1L)
#define HTB_VER (0x30011)
#if HTB_VER >> 16 != TC_HTB_PROTOVER
#error "Mismatched sch_htb.c and pkt_sch.h"
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,8,0)
#define HLIST_for_each_entry(a,b,c,d) hlist_for_each_entry(a,c,d)
#define HLIST_for_each_entry_safe(a,b,c,d,e) hlist_for_each_entry_safe(a,c,d,e)
#else
#define OLD_KERNEL
#define HLIST_for_each_entry hlist_for_each_entry
#define HLIST_for_each_entry_safe hlist_for_each_entry_safe
#endif

#include "rate_est.h"

struct mq_sched {
	struct Qdisc *sch;
	struct Qdisc		**qdiscs;
	struct tcf_proto *filter_list;
	struct Qdisc_class_hash clhash;

	/* Default class */
	int defcls;
};

struct iso_rate_cfg {
	u64 rate_bps;
	u32 mult;
	u32 shift;
};

/*
 * This is the leaf structure that resides on every CPU.  This will
 * hold all packets and keep track of tokens.
 */

struct iso_rl_local_sched;

struct iso_rl_queue {
	/* TODO: replace this by pfifo qdisc */
	struct sk_buff_head list;
	struct gnet_stats_basic_packed bstats;
	struct gnet_stats_queue qstats;

	s64 tokens;
	s64 deficit;
	int throttled;
	int pcpu_waiting;
	u64 next;

	struct iso_rl_class *rl;
	struct iso_rl_queue *parent;
	struct hrtimer *cputimer;
	struct list_head active_list;
	struct list_head active_node;
};

/*
 * Each class represents a rate limiter.  If it's a leaf, then it also
 * has a queue with actual packets.
 */

struct iso_rl_class {
	struct Qdisc_class_common common;
	struct gnet_stats_basic_packed bstats;
	struct gnet_stats_queue qstats;

	int refcnt;

	u32 weight;
	struct rate_est rate_est;

	struct iso_rate_cfg rate_to_time;

	/* Protects the following two quantities. */
	spinlock_t spinlock;
	u64 next;

	/* 0 if the rl is really a "class" without a queue. */
	int leaf;
	int cap;
	int throttled;
	int quanta;

	struct iso_rl_class *parent;
	struct list_head siblings;
	struct list_head children;

	struct iso_rl_queue __percpu *queue;

	/* The filters in this class */
	struct tcf_proto *filter_list;
	int filter_cnt;

	/* The parent */
	struct Qdisc *root;
};

/*
 * This is the per-queue control block, keeping track of timers for
 * each CPU.  This will be the root qdisc on each TX queue.
 */
struct iso_rl_local_sched {
	struct Qdisc *qdisc;
	struct mq_sched *global_sched;
	spinlock_t spinlock;
	struct hrtimer timer;
	struct list_head active_list;

	/* Non-shaped packets go directly here */
	struct sk_buff_head direct_queue;
	int max_direct_qlen;
	int direct_pkts;
	int qid;
};

/* Func decl */
static struct iso_rl_class *iso_rl_find(u32 handle, struct mq_sched *global);
static struct iso_rl_class *iso_rl_classify(struct sk_buff *skb, struct mq_sched *global, int *qerr);
static struct sk_buff *iso_rl_dequeue_tree(struct iso_rl_queue *q, u64 now, struct iso_rl_local_sched *cb, u64 *);
static u64 l2t_ns(struct iso_rate_cfg *r, unsigned int len);

enum hrtimer_restart iso_rl_local_timeout(struct hrtimer *timer) {
	/* schedue xmit tasklet to go into softirq context */
	struct iso_rl_local_sched *cb = container_of(timer, struct iso_rl_local_sched, timer);
	__netif_schedule(qdisc_root(cb->qdisc));
	return HRTIMER_NORESTART;
}

static int iso_rl_local_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct iso_rl_local_sched *cb = qdisc_priv(sch);
	cb->qdisc = sch;
	/* This will be filled in later */
	cb->global_sched = NULL;
	spin_lock_init(&cb->spinlock);
	hrtimer_init(&cb->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	cb->timer.function = iso_rl_local_timeout;
	INIT_LIST_HEAD(&cb->active_list);

	skb_queue_head_init(&cb->direct_queue);
	/* This will be filled in later */
	cb->qid = 0;
	cb->max_direct_qlen = 1000;
	cb->direct_pkts = 0;
	return 0;
}

static void iso_rl_local_destroy(struct Qdisc *sch)
{
	struct iso_rl_local_sched *cb = qdisc_priv(sch);
	hrtimer_cancel(&cb->timer);
	__skb_queue_purge(&cb->direct_queue);
}

inline void iso_rl_activate_queue(struct iso_rl_queue *q, struct iso_rl_local_sched *cb) {
        struct iso_rl_queue *parent = q->parent;

        /* This queue will be a leaf */
        if (q->pcpu_waiting)
                return;

	while (parent) {
                q->pcpu_waiting += 1;
                if (q->pcpu_waiting == 1) {
                        list_add_tail(&q->active_node, &parent->active_list);
                }

                q = parent;
                parent = q->parent;
        }

        /* Finally, add the root node to the per-cpu control block */
        if(list_empty(&q->active_node))
                list_add_tail(&q->active_node, &cb->active_list);
}

inline void iso_rl_deactivate_queue(struct iso_rl_queue *q) {
	struct iso_rl_queue *parent = q->parent;
	if (!q->pcpu_waiting)
		return;

        /* This queue will be a leaf */
	while (parent) {
		q->pcpu_waiting -= 1;
		if (q->pcpu_waiting == 0) {
			list_del_init(&q->active_node);
		}

		q = parent;
		parent = q->parent;
	}

	/* Finally, remove from pcpu block if needed */
	if(list_empty(&q->active_list) && !list_empty(&q->active_node))
                list_del_init(&q->active_node);
}

static int iso_rl_local_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct iso_rl_local_sched *cb = qdisc_priv(sch);
	struct mq_sched *global = cb->global_sched;
	struct iso_rl_class *cl = NULL;
	struct iso_rl_queue *q;
	int ret = NET_XMIT_SUCCESS;

	/* 1. classify the packet */
	cl = iso_rl_classify(skb, global, &ret);

	/* 2. if no class, enqueue into direct */
	if (cl == NULL || cl == RL_DIRECT) {
		if (cb->direct_queue.qlen < cb->max_direct_qlen) {
			__skb_queue_tail(&cb->direct_queue, skb);
			cb->direct_pkts++;
			goto done;
		} else {
			return qdisc_drop(skb, sch);
		}
	}

	q = per_cpu_ptr(cl->queue, cb->qid);

	if (q->list.qlen < cb->max_direct_qlen) {
		__skb_queue_tail(&q->list, skb);
		q->qstats.backlog += skb->len;
		q->qstats.qlen += 1;
		iso_rl_activate_queue(q, cb);
	} else {
		kfree_skb(skb);
		q->qstats.drops++;
		ret = NET_XMIT_DROP;
	}
done:
	/* 3. update stats and then return result */
	sch->q.qlen++;
	return ret;
}

static struct sk_buff *iso_rl_local_dequeue(struct Qdisc *sch)
{
	struct iso_rl_local_sched *cb = qdisc_priv(sch);
	struct sk_buff *skb;
	struct iso_rl_queue *q, *qtmp;
	int count;
	u64 now;
	u64 next = ~0;

	/* 1. check for packets in the direct queue */
	skb = __skb_dequeue(&cb->direct_queue);
	if (skb != NULL) {
		qdisc_bstats_update(sch, skb);
		qdisc_unthrottled(sch);
		sch->q.qlen--;
		return skb;
	}

	now = ktime_to_ns(ktime_get());

	count = 0;
	do {
		/* 2. walk cb->active_list and dequeue packets in the tree */
		count++;
		list_for_each_entry_safe(q, qtmp, &cb->active_list, active_node) {
			count++;
			skb = iso_rl_dequeue_tree(q, now, cb, &next);
			if (skb) {
				bstats_update(&q->bstats, skb);
				sch->q.qlen--;
				qdisc_unthrottled(sch);
				return skb;
			}
		}
	} while (count < 100);

	if (!list_empty(&cb->active_list)) {
		ktime_t dt = ktime_set(0, max_t(u64, 10000, next - now));
		qdisc_throttled(sch);
		hrtimer_start(&cb->timer, dt, HRTIMER_MODE_REL);
	}

	return NULL;
}

inline int iso_rl_borrow_tokens(struct iso_rl_class *rl, struct iso_rl_queue *q) {
	int timeout = 1;
	u64 now = ktime_to_ns(ktime_get());

	if (q->throttled)
		return 1;

	spin_lock(&rl->spinlock);

	if (rl->next <= now) {
		rl->next = now + rl->quanta;
		q->tokens += rl->quanta;
		timeout = 0;
		q->throttled = 0;
		q->next = ~0;
	} else {
		q->throttled = 1;
		q->next = rl->next;
		rl->next += rl->quanta;
	}

	spin_unlock(&rl->spinlock);
	return timeout;
}

struct sk_buff *
iso_rl_dequeue(struct iso_rl_queue *q, u64 now,
	       struct iso_rl_local_sched *cb, u64 *next_event)
{
	int timeout = 0;
	u32 size;
	struct sk_buff *pkt;
	struct iso_rl_class *rl = q->rl;
	struct sk_buff_head *skq;
	s64 toks_reqd;

	skq = &q->list;
	if (unlikely(skq->qlen == 0))
		return NULL;

	pkt = skb_peek(skq);
	toks_reqd = l2t_ns(&rl->rate_to_time, qdisc_pkt_len(pkt));

	if (q->tokens < toks_reqd) {
		if (q->next <= now) {
			q->throttled = 0;
			q->next = ~0;
			q->tokens += rl->quanta;
		} else {
			if (!q->throttled)
				iso_rl_borrow_tokens(rl, q);
			timeout = 1;
			*next_event = min_t(u64, *next_event, q->next);
			pkt = NULL;
			goto timeout;
		}
	}

	size = qdisc_pkt_len(pkt);
	pkt = __skb_dequeue(skq);
	q->tokens -= toks_reqd;
	bstats_update(&q->bstats, pkt);

	q->qstats.backlog -= size;
	q->qstats.qlen--;
	rate_est_update(&q->rl->rate_est, size);
timeout:
	if (skq->qlen == 0) {
		iso_rl_deactivate_queue(q);
	} else {
		iso_rl_activate_queue(q, cb);
	}

	return pkt;
}

static struct sk_buff *
iso_rl_dequeue_tree(struct iso_rl_queue *q, u64 now,
		    struct iso_rl_local_sched *cb, u64 *next_event)
{
	struct iso_rl_queue *curr, *next;
	int timeout;
	struct sk_buff *skb;
	struct iso_rate_cfg *rlrate = &q->rl->rate_to_time;

	if (q->rl->leaf) {
		return iso_rl_dequeue(q, now, cb, next_event);
	}

	/* This should never happen */
	if (unlikely(list_empty(&q->active_list))) {
		return NULL;
	}

	if (q->tokens < 0) {
		if (q->next <= now) {
			q->tokens += q->rl->quanta;
			q->throttled = 0;
			q->next = ~0;
		} else {
			timeout = iso_rl_borrow_tokens(q->rl, q);
			if (timeout) {
				*next_event = min_t(u64, *next_event, q->next);
				return NULL;
			}
		}
	}

	list_for_each_entry_safe(curr, next, &q->active_list, active_node) {
		if (curr->deficit < 0) {
			curr->deficit += ISO_QUANTUM_BYTES;
			list_move_tail(&curr->active_node, &q->active_list);
			continue;
		}

		skb = iso_rl_dequeue_tree(curr, now, cb, next_event);
		if (skb) {
			q->tokens -= l2t_ns(rlrate, qdisc_pkt_len(skb));
			curr->deficit -= qdisc_pkt_len(skb);
			bstats_update(&q->bstats, skb);
			rate_est_update(&q->rl->rate_est, qdisc_pkt_len(skb));
			return skb;
		}
	}

	return NULL;
}

static struct Qdisc_ops prl_qdisc_ops __read_mostly = {
	.id = "prl_local",
	.priv_size = sizeof(struct iso_rl_local_sched),
	.init = iso_rl_local_init,
	.destroy = iso_rl_local_destroy,
	.enqueue = iso_rl_local_enqueue,
	.dequeue = iso_rl_local_dequeue,
};

/*
 * Class operations that bridge single-queue and multi-queue.
 */
static const struct nla_policy htb_policy[TCA_HTB_MAX + 1] = {
	[TCA_HTB_PARMS] = { .len = sizeof(struct tc_htb_opt) },
	[TCA_HTB_INIT]  = { .len = sizeof(struct tc_htb_glob) },
	[TCA_HTB_CTAB]  = { .type = NLA_BINARY, .len = TC_RTAB_SIZE },
	[TCA_HTB_RTAB]  = { .type = NLA_BINARY, .len = TC_RTAB_SIZE },
};

static struct iso_rl_class *iso_rl_find(u32 handle, struct mq_sched *global_sched)
{
	struct Qdisc_class_common *clc;

	clc = qdisc_class_find(&global_sched->clhash, handle);
	if (clc == NULL)
		return NULL;

	return container_of(clc, struct iso_rl_class, common);
}

static struct iso_rl_class *
iso_rl_classify(struct sk_buff *skb, struct mq_sched *global, int *qerr)
{
	struct Qdisc *sch = global->sch;
	struct iso_rl_class *cl;
	struct tcf_result res;
	struct tcf_proto *tcf;
	int result;

	if (skb->priority == sch->handle)
		return RL_DIRECT;

	/* TODO: skb->priority?  This needs some checking. */
	cl = iso_rl_find(skb->priority, global);
	if (cl)
		return cl;

	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	tcf = global->filter_list;

	while (tcf && (result = tc_classify(skb, tcf, &res)) >= 0) {
		cl = (void *)res.class;
		if (!cl) {
			if (res.classid == sch->handle)
				return RL_DIRECT;

			cl = iso_rl_find(res.classid, global);
			if (!cl)
				break;
		}

		if (cl->leaf)
			return cl;

		tcf = cl->filter_list;
	}

	/* TODO: enqueue into default first before direct */

	/* Enqueue into direct class */
	return RL_DIRECT;
}

static u64 l2t_ns(struct iso_rate_cfg *r, unsigned int len)
{
        return ((u64)len * r->mult) >> r->shift;
}

static void prl_precompute_ratedata(struct iso_rate_cfg *r)
{
        r->shift = 0;
        r->mult = 1;

        if (r->rate_bps > 0) {
                r->shift = 15;
                r->mult = div64_u64(8LLU * NSEC_PER_SEC * (1 << r->shift), r->rate_bps);
        }
}

void iso_rl_set_rate(struct iso_rl_class *cl, u64 rate_bps)
{
	cl->rate_to_time.rate_bps = rate_bps;
	prl_precompute_ratedata(&cl->rate_to_time);
	cl->quanta = l2t_ns(&cl->rate_to_time, ISO_QUANTUM_BYTES);
}

int iso_rl_class_init(struct iso_rl_class *cl)
{
	int i;
	iso_rl_set_rate(cl, ONE_GBPS);
	cl->weight = 1;
	if (rate_est_init(&cl->rate_est))
		goto enobufs1;

	spin_lock_init(&cl->spinlock);
	cl->next = ktime_to_ns(ktime_get());

	/* A class when allocated will be a leaf...*/
	cl->leaf = 1;
	cl->throttled = 0;
	cl->parent = NULL;
	INIT_LIST_HEAD(&cl->siblings);
	INIT_LIST_HEAD(&cl->children);
	cl->filter_cnt = 0;
	cl->refcnt = 1;

	cl->queue = alloc_percpu(struct iso_rl_queue);
	if (cl->queue == NULL)
		goto enobufs2;

	for_each_possible_cpu(i) {
		struct iso_rl_queue *q = per_cpu_ptr(cl->queue, i);
		skb_queue_head_init(&q->list);
		memset(&q->bstats, 0, sizeof(q->bstats));
		memset(&q->qstats, 0, sizeof(q->qstats));

		q->tokens = 0;
		q->deficit = ISO_QUANTUM_BYTES;
		q->rl = cl;
		q->throttled = 0;
		q->pcpu_waiting = 0;
		q->parent = NULL;
		q->next = ktime_to_ns(ktime_get());

		INIT_LIST_HEAD(&q->active_list);
		INIT_LIST_HEAD(&q->active_node);
	}

	return 0;
enobufs2:
	rate_est_free(&cl->rate_est);
enobufs1:
	return -ENOBUFS;
}

void iso_rl_attach(struct iso_rl_class *child, struct iso_rl_class *parent)
{
	/* TODO: locking? */
	int cpu;
	int purge = 0;

	if (child->parent == parent)
		return;

	if (parent->leaf) {
		parent->leaf = 0;
		/* Purge all queues */
		purge = 1;
	}

	for_each_possible_cpu(cpu) {
		struct iso_rl_queue *qparent = per_cpu_ptr(parent->queue, cpu);
		struct iso_rl_queue *qchild = per_cpu_ptr(child->queue, cpu);
		qchild->parent = qparent;

		if (purge) {
			__skb_queue_purge(&qparent->list);
		}
	}

	list_move_tail(&child->siblings, &parent->children);
	child->parent = parent;
	return;
}

static int iso_rl_change_class(struct Qdisc *sch, u32 classid,
			       u32 parentid, struct nlattr **tca,
			       unsigned long *arg)
{
	int err = -EINVAL;
	struct mq_sched *global = qdisc_priv(sch);
	struct iso_rl_class *cl = (struct iso_rl_class *)*arg, *parent;
	struct nlattr *opt = tca[TCA_OPTIONS];

	/* TODO: this is specific to htb. */
	struct nlattr *tb[__TCA_HTB_MAX];
	struct tc_htb_opt *hopt;

	if (!opt)
		goto failure;

	err = nla_parse_nested(tb, TCA_HTB_MAX, opt, htb_policy);
	if (err < 0)
		goto failure;

	err = -EINVAL;
	if (tb[TCA_HTB_PARMS] == NULL)
		goto failure;

	parent = (parentid == TC_H_ROOT) ? NULL : iso_rl_find(parentid, global);

	hopt = nla_data(tb[TCA_HTB_PARMS]);
	if (!hopt->rate.rate || !hopt->ceil.rate)
		goto failure;

	/* This means we're creating a new class */
	if (!cl) {
		err = -EINVAL;

		if (!classid || TC_H_MAJ(classid ^ sch->handle) ||
		    iso_rl_find(classid, global)) {
			err = -EEXIST;
			goto failure;
		}

		/* check depth? */

		err = -ENOBUFS;
		cl = kzalloc(sizeof(*cl), GFP_KERNEL);
		if (!cl)
			goto failure;

		cl->root = sch;
		if (iso_rl_class_init(cl)) {
			kfree(cl);
			goto failure;
		}

		sch_tree_lock(sch);
		if (parent) {
			iso_rl_attach(cl, parent);
		}

		cl->common.classid = classid;
		cl->parent = parent;
		qdisc_class_hash_insert(&global->clhash, &cl->common);
	}

	cl->rate_to_time.rate_bps = (u64)hopt->rate.rate << 3;
	iso_rl_set_rate(cl, cl->rate_to_time.rate_bps);

	sch_tree_unlock(sch);

	qdisc_class_hash_grow(sch, &global->clhash);
	*arg = (unsigned long)cl;
	return 0;

failure:
	return err;
}

static void iso_rl_destroy_class(struct Qdisc *sch, struct iso_rl_class *cl)
{
	int i;
	tcf_destroy_chain(&cl->filter_list);

	if (cl->queue) {
		struct iso_rl_queue *q;

		for_each_possible_cpu(i) {
			q = per_cpu_ptr(cl->queue, i);
			__skb_queue_purge(&q->list);
		}

		free_percpu(cl->queue);
	}

	rate_est_free(&cl->rate_est);
	kfree(cl);
}

static int iso_rl_delete_class(struct Qdisc *sch, unsigned long arg)
{
	struct mq_sched *global = qdisc_priv(sch);
	struct iso_rl_class *cl = (struct iso_rl_class *)arg;

	if (!cl)
		return 0;

	if (cl->filter_cnt || !list_empty(&cl->children))
		return -EBUSY;

	sch_tree_lock(sch);

	qdisc_class_hash_remove(&global->clhash, &cl->common);
	list_del_init(&cl->siblings);
	BUG_ON(--cl->refcnt == 0);

	sch_tree_unlock(sch);
	return 0;
}

static struct tcf_proto **iso_rl_find_tcf(struct Qdisc *sch, unsigned long arg)
{
	struct mq_sched *q = qdisc_priv(sch);
	struct iso_rl_class *cl = (struct iso_rl_class *)arg;
	struct tcf_proto **fl = cl ? &cl->filter_list : &q->filter_list;
	return fl;
}

static unsigned long iso_rl_bind_filter(struct Qdisc *sch, unsigned long parent,
					u32 classid)
{
	struct mq_sched *global = qdisc_priv(sch);
	struct iso_rl_class *cl = iso_rl_find(classid, global);
	if (cl)
		cl->filter_cnt++;
	return (unsigned long)cl;
}

static void iso_rl_unbind_filter(struct Qdisc *sch, unsigned long arg)
{
	struct iso_rl_class *cl = (struct iso_rl_class *)arg;
	if (cl)
		cl->filter_cnt--;
}

/*
 * The multiqueue portion of the code will be below.
 */

static void mq_destroy(struct Qdisc *sch)
{
	struct net_device *dev = qdisc_dev(sch);
	struct mq_sched *priv = qdisc_priv(sch);
	struct iso_rl_class *cl;
	struct hlist_node *next;
#ifdef OLD_KERNEL
	struct hlist_node *n;
#endif
	unsigned int ntx, i;

	if (!priv->qdiscs)
		return;

	for (ntx = 0; ntx < dev->num_tx_queues && priv->qdiscs[ntx]; ntx++)
		qdisc_destroy(priv->qdiscs[ntx]);

	/* Destroy all filters and classes */
	for (i = 0; i < priv->clhash.hashsize; i++) {
		HLIST_for_each_entry(cl, n, &priv->clhash.hash[i], common.hnode)
			tcf_destroy_chain(&cl->filter_list);
	}

	for (i = 0; i < priv->clhash.hashsize; i++) {
		HLIST_for_each_entry_safe(cl, n, next, &priv->clhash.hash[i],
					  common.hnode)
			iso_rl_destroy_class(sch, cl);
	}

	qdisc_class_hash_destroy(&priv->clhash);
	kfree(priv->qdiscs);
}

static int mq_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct net_device *dev = qdisc_dev(sch);
	struct mq_sched *priv = qdisc_priv(sch);
	struct iso_rl_local_sched *cb;
	struct netdev_queue *dev_queue;
	struct Qdisc *qdisc;
	unsigned int ntx;
	int err;
	int tx_queue_len;

	/* TODO: right now we try to be a drop-in replacement for htb.
	 * We should change this later. */
	struct nlattr *tb[TCA_HTB_INIT + 1];
	struct tc_htb_glob *gopt;

	if (sch->parent != TC_H_ROOT)
		return -EOPNOTSUPP;

	if (!netif_is_multiqueue(dev))
		return -EOPNOTSUPP;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_HTB_INIT, opt, htb_policy);
	if (err < 0)
		return err;

	if (tb[TCA_HTB_INIT] == NULL) {
		pr_err("mq/prl/htb: bad tc tool?\n");
		return -EINVAL;
	}

	gopt = nla_data(tb[TCA_HTB_INIT]);
	if (gopt->version != HTB_VER >> 16) {
		pr_err("mq/prl/htb: need tc version %d (minor is %d), you have %d\n",
		       HTB_VER >> 16, HTB_VER & 0xffff, gopt->version);
		return -EINVAL;
	}

	err = qdisc_class_hash_init(&priv->clhash);
	if (err < 0)
		return err;

	priv->defcls = gopt->defcls;

	priv->sch = sch;

	tx_queue_len = qdisc_dev(sch)->tx_queue_len;
	if (tx_queue_len < 2) /* Some devices have zero tx_queue_len */
		tx_queue_len = 2;

	/* pre-allocate qdiscs, attachment can't fail */
	priv->qdiscs = kcalloc(dev->num_tx_queues, sizeof(priv->qdiscs[0]),
			       GFP_KERNEL);
	if (priv->qdiscs == NULL)
		return -ENOMEM;

	for (ntx = 0; ntx < dev->num_tx_queues; ntx++) {
		dev_queue = netdev_get_tx_queue(dev, ntx);
		qdisc = qdisc_create_dflt(dev_queue, &prl_qdisc_ops,
					  TC_H_MAKE(TC_H_MAJ(sch->handle),
						    TC_H_MIN(ntx + 1)));
		if (qdisc == NULL)
			goto err;

		cb = qdisc_priv(qdisc);
		cb->qid = ntx;
		cb->global_sched = priv;
		cb->max_direct_qlen = tx_queue_len;
		priv->qdiscs[ntx] = qdisc;
	}

	sch->flags |= TCQ_F_MQROOT;
	return 0;

err:
	mq_destroy(sch);
	return -ENOMEM;
}

static void mq_attach(struct Qdisc *sch)
{
	struct net_device *dev = qdisc_dev(sch);
	struct mq_sched *priv = qdisc_priv(sch);
	struct Qdisc *qdisc;
	unsigned int ntx;

	for (ntx = 0; ntx < dev->num_tx_queues; ntx++) {
		qdisc = priv->qdiscs[ntx];
		qdisc = dev_graft_qdisc(qdisc->dev_queue, qdisc);
		if (qdisc)
			qdisc_destroy(qdisc);
	}
	kfree(priv->qdiscs);
	priv->qdiscs = NULL;
}

static int mq_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct net_device *dev = qdisc_dev(sch);
	struct Qdisc *qdisc;
	unsigned int ntx;

	sch->q.qlen = 0;
	memset(&sch->bstats, 0, sizeof(sch->bstats));
	memset(&sch->qstats, 0, sizeof(sch->qstats));

	for (ntx = 0; ntx < dev->num_tx_queues; ntx++) {
		qdisc = netdev_get_tx_queue(dev, ntx)->qdisc_sleeping;
		spin_lock_bh(qdisc_lock(qdisc));
		sch->q.qlen		+= qdisc->q.qlen;
		sch->bstats.bytes	+= qdisc->bstats.bytes;
		sch->bstats.packets	+= qdisc->bstats.packets;
		sch->qstats.qlen	+= qdisc->qstats.qlen;
		sch->qstats.backlog	+= qdisc->qstats.backlog;
		sch->qstats.drops	+= qdisc->qstats.drops;
		sch->qstats.requeues	+= qdisc->qstats.requeues;
		sch->qstats.overlimits	+= qdisc->qstats.overlimits;
		spin_unlock_bh(qdisc_lock(qdisc));
	}
	return 0;
}

static struct netdev_queue *mq_queue_get(struct Qdisc *sch, unsigned long cl)
{
	struct net_device *dev = qdisc_dev(sch);
	unsigned long ntx = cl - 1;

	if (ntx >= dev->num_tx_queues)
		return NULL;
	return netdev_get_tx_queue(dev, ntx);
}

static struct netdev_queue *mq_select_queue(struct Qdisc *sch,
					    struct tcmsg *tcm)
{
	unsigned int ntx = TC_H_MIN(tcm->tcm_parent);
	struct netdev_queue *dev_queue = mq_queue_get(sch, ntx);

	if (!dev_queue) {
		struct net_device *dev = qdisc_dev(sch);

		return netdev_get_tx_queue(dev, 0);
	}
	return dev_queue;
}

static int mq_graft(struct Qdisc *sch, unsigned long cl, struct Qdisc *new,
		    struct Qdisc **old)
{
	struct netdev_queue *dev_queue = mq_queue_get(sch, cl);
	struct net_device *dev = qdisc_dev(sch);

	if (dev->flags & IFF_UP)
		dev_deactivate(dev);

	*old = dev_graft_qdisc(dev_queue, new);
	if (dev->flags & IFF_UP)
		dev_activate(dev);
	return 0;
}

static struct Qdisc *mq_leaf(struct Qdisc *sch, unsigned long cl)
{
	struct netdev_queue *dev_queue = mq_queue_get(sch, cl);

	return dev_queue->qdisc_sleeping;
}

static unsigned long mq_get(struct Qdisc *sch, u32 classid)
{
	unsigned int ntx = TC_H_MIN(classid);
	struct mq_sched *global = qdisc_priv(sch);
	struct iso_rl_class *cl;

	/* If it's one of those top device queue classes. */
	if (mq_queue_get(sch, ntx))
		return 0;

	cl = iso_rl_find(classid, global);
	if (cl)
		cl->refcnt++;

	return (unsigned long)cl;
}

static void mq_put(struct Qdisc *sch, unsigned long _cl)
{
	struct net_device *dev = qdisc_dev(sch);
	struct iso_rl_class *cl = (struct iso_rl_class *)_cl;
	struct mq_sched *global;

	if (_cl < (unsigned long)dev->num_tx_queues)
		return;

	global = qdisc_priv(sch);
	if (--cl->refcnt == 0)
		iso_rl_destroy_class(sch, cl);
}

static int mq_dump_class(struct Qdisc *sch, unsigned long _cl,
			 struct sk_buff *skb, struct tcmsg *tcm)
{
	struct netdev_queue *dev_queue = mq_queue_get(sch, _cl);
	struct iso_rl_class *cl = (struct iso_rl_class *)_cl;
	spinlock_t *root_lock = qdisc_root_sleeping_lock(sch);
	struct nlattr *nest;
	struct tc_htb_opt opt;

	/* TODO: simple protection, but this needs to change when
	 * configuring iso_rl_class. */
	if (dev_queue == NULL) {
		spin_lock_bh(root_lock);
		tcm->tcm_parent = cl->parent ? cl->parent->common.classid : TC_H_ROOT;
		tcm->tcm_handle = cl->common.classid;

		nest = nla_nest_start(skb, TCA_OPTIONS);
		if (nest == NULL)
			goto nla_put_failure;
		memset(&opt, 0, sizeof(opt));

		opt.rate.rate = cl->rate_to_time.rate_bps >> 3;
		opt.buffer = 0;
		opt.ceil.rate = opt.rate.rate;
		opt.quantum = 0;
		opt.prio = 0;
		opt.level = 0;
		if (nla_put(skb, TCA_HTB_PARMS, sizeof(opt), &opt))
			goto nla_put_failure;

		nla_nest_end(skb, nest);
		spin_unlock_bh(root_lock);
		return skb->len;

	nla_put_failure:
		spin_unlock_bh(root_lock);
		nla_nest_cancel(skb, nest);
		return -1;
	}

	tcm->tcm_parent = TC_H_ROOT;
	tcm->tcm_handle |= TC_H_MIN(_cl);
	tcm->tcm_info = dev_queue->qdisc_sleeping->handle;
	return 0;
}

static void iso_rl_class_accum_stats(struct iso_rl_class *cl)
{
	int cpu;
	spin_lock_bh(&cl->spinlock);

	memset(&cl->bstats, 0, sizeof(cl->bstats));
	memset(&cl->qstats, 0, sizeof(cl->qstats));

	for_each_online_cpu(cpu) {
		struct iso_rl_queue *q = per_cpu_ptr(cl->queue, cpu);
		cl->bstats.bytes += q->bstats.bytes;
		cl->bstats.packets += q->bstats.packets;

		cl->qstats.qlen += q->qstats.qlen;
		cl->qstats.backlog += q->qstats.backlog;
		cl->qstats.drops += q->qstats.drops;
		cl->qstats.requeues += q->qstats.requeues;
		cl->qstats.overlimits += q->qstats.overlimits;
	}

	spin_unlock_bh(&cl->spinlock);
}

static int mq_dump_class_stats(struct Qdisc *sch, unsigned long _cl,
			       struct gnet_dump *d)
{
	struct netdev_queue *dev_queue = mq_queue_get(sch, _cl);

	if (dev_queue == NULL) {
		struct iso_rl_class *cl = (struct iso_rl_class *)_cl;
		struct gnet_stats_rate_est r;

		iso_rl_class_accum_stats(cl);

		if (gnet_stats_copy_basic(d, &cl->bstats) < 0 ||
		    gnet_stats_copy_queue(d, &cl->qstats) < 0)
			return -1;

		/* grr, bps = bytes/sec */
		r.bps = (cl->rate_est.rate_mbps * 1000000) >> 3;
		r.pps = 1;

		return gnet_stats_copy_rate_est(d, NULL, &r);
	}

	sch = dev_queue->qdisc_sleeping;
	sch->qstats.qlen = sch->q.qlen;
	if (gnet_stats_copy_basic(d, &sch->bstats) < 0 ||
	    gnet_stats_copy_queue(d, &sch->qstats) < 0)
		return -1;

	return 0;
}

static void mq_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct net_device *dev = qdisc_dev(sch);
	struct mq_sched *q = qdisc_priv(sch);
	struct iso_rl_class *cl;
#ifdef OLD_KERNEL
	struct hlist_node *n;
#endif
	unsigned int i, ntx;

	if (arg->stop)
		return;

	if (arg->count < dev->num_tx_queues) {
		for (ntx = 0; ntx < dev->num_tx_queues; ntx++) {
			if (arg->count < arg->skip) {
				arg->count++;
				continue;
			}

			if (arg->fn(sch, ntx + 1, arg) < 0) {
				break;
			}

			arg->count++;
		}
	}

	for (i = 0; i < q->clhash.hashsize; i++) {
		HLIST_for_each_entry(cl, n, &q->clhash.hash[i], common.hnode) {
			if (arg->count < arg->skip) {
				arg->count++;
				continue;
			}

			if (arg->fn(sch, (unsigned long)cl, arg) < 0) {
				arg->stop = 1;
				return;
			}

			arg->count++;
		}
	}
}

static const struct Qdisc_class_ops mq_class_ops = {
	.select_queue	= mq_select_queue,
	.graft		= mq_graft,
	.leaf		= mq_leaf,
	.get		= mq_get,
	.put		= mq_put,
	.walk		= mq_walk,
	.dump		= mq_dump_class,
	.dump_stats	= mq_dump_class_stats,
	.change = iso_rl_change_class,
	.delete = iso_rl_delete_class,
	.tcf_chain = iso_rl_find_tcf,
	.bind_tcf = iso_rl_bind_filter,
	.unbind_tcf = iso_rl_unbind_filter,
};

struct Qdisc_ops mq_qdisc_ops __read_mostly = {
	.cl_ops		= &mq_class_ops,
	.id		= "htb",
	.priv_size	= sizeof(struct mq_sched),
	.init		= mq_init,
	.destroy	= mq_destroy,
	.attach		= mq_attach,
	.dump		= mq_dump,
	.owner		= THIS_MODULE,
};

static int __init htb_module_init(void)
{
	return register_qdisc(&mq_qdisc_ops);
}

static void __exit htb_module_exit(void)
{
	unregister_qdisc(&mq_qdisc_ops);
}

module_init(htb_module_init);
module_exit(htb_module_exit);
MODULE_LICENSE("GPL");
