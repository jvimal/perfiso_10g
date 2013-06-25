#ifndef __RCP_H__
#define __RCP_H__

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

#include "rate_est.h"
#define RCP_MIN_RATE_MBPS (10LLU)

struct rcp {
	rate_t capacity_mbps;
	struct rate_est *util;
	rate_t fair_share_mbps;
	int period_us;

	ktime_t last_computed;
	spinlock_t lock;
};

void rcp_init(struct rcp *r,
	      int capacity_mbps, struct rate_est *util,
	      int period_us);

void rcp_update(struct rcp *);

#endif /* __RCP_H__ */
