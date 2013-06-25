#ifndef __RATE_EST_H__
#define __RATE_EST_H__

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

typedef u32 rate_t;

struct rate_pcpu_stats {
	u64 bytes;
};

struct rate_est {
	rate_t rate_mbps;
	ktime_t last_aggregated;
	int period_us;
	u64 bytes;
	spinlock_t lock;
	struct rate_pcpu_stats __percpu *rate_stats;
};

/* API */
int rate_est_init(struct rate_est *, int period_us);
void rate_est_free(struct rate_est *);
inline struct rate_pcpu_stats *get_cpu_stats(struct rate_est *r);
void rate_est_update(struct rate_est *r, u64 bytes);
void rate_est_aggregate(struct rate_est *r);

#endif /* __RATE_EST_H__ */
