#include "rcp.h"

void rcp_init(struct rcp *r,
	      int capacity_mbps, struct rate_est *util,
	      int period_us)
{
	r->capacity_mbps = capacity_mbps;
	r->util = util;
	r->fair_share_mbps = capacity_mbps;
	r->last_computed = ktime_get();
	r->period_us = period_us;
	spin_lock_init(&r->lock);
}

void rcp_update(struct rcp *r)
{
	ktime_t now = ktime_get();
	rate_t util_mbps;
	u64 num;

	if (ktime_us_delta(now, r->last_computed) < r->period_us)
		return;

	if (!spin_trylock(&r->lock))
		return;

	r->last_computed = now;
	util_mbps = r->util->rate_mbps;
	num = r->fair_share_mbps;
	num *= (4 * r->capacity_mbps - util_mbps);
	num /= (r->capacity_mbps * 3);

	num = min_t(u64, num, r->capacity_mbps);
	num = max(num, RCP_MIN_RATE_MBPS);

	r->fair_share_mbps = num;
	spin_unlock(&r->lock);
}
