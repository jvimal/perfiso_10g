#ifndef __RATE_EST_H__
#define __RATE_EST_H__

struct rate_pcpu_stats {
	u64 bytes;
};

struct rate_est {
	u32 rate_mbps;
	ktime_t last_aggregated;
	int period_us;
	u64 bytes;
	spinlock_t lock;
	struct rate_pcpu_stats __percpu *rate_stats;
};

/* API */
int rate_est_init(struct rate_est *);
void rate_est_free(struct rate_est *);
static inline
struct rate_pcpu_stats *get_cpu_stats(struct rate_est *r);
void rate_est_update(struct rate_est *r, u64 bytes);
void rate_est_aggregate(struct rate_est *r);

int rate_est_init(struct rate_est *r)
{
	int cpu;
	r->rate_mbps = 0;
	r->last_aggregated = ktime_get();

	/* rate estimates over 10ms */
	r->period_us = 10000;
	r->bytes = 0;
	r->rate_stats = alloc_percpu(struct rate_pcpu_stats);

	if (r->rate_stats == NULL)
		return -ENOBUFS;

	spin_lock_init(&r->lock);

	for_each_possible_cpu(cpu) {
		struct rate_pcpu_stats *s = per_cpu_ptr(r->rate_stats, cpu);
		s->bytes = 0;
	}

	return 0;
}

void rate_est_free(struct rate_est *r)
{
	if (r->rate_stats != NULL)
		free_percpu(r->rate_stats);
}

static inline
struct rate_pcpu_stats *get_cpu_stats(struct rate_est *r)
{
	return per_cpu_ptr(r->rate_stats, smp_processor_id());
}

void rate_est_update(struct rate_est *r, u64 bytes)
{
	struct rate_pcpu_stats *s = get_cpu_stats(r);
	s->bytes += bytes;
	rate_est_aggregate(r);
}

void rate_est_aggregate(struct rate_est *r)
{
	ktime_t now = ktime_get();
	u64 total = 0;
	int cpu;

	if (likely(ktime_us_delta(now, r->last_aggregated) < r->period_us))
		return;

	if (!spin_trylock(&r->lock))
		return;

	r->last_aggregated = now;
	for_each_online_cpu(cpu) {
		struct rate_pcpu_stats *s = per_cpu_ptr(r->rate_stats, cpu);
		total += s->bytes;
	}

	/* bits/us = mb/s */
	r->rate_mbps = ((total - r->bytes) << 3) / r->period_us;
	r->bytes = total;
	spin_unlock(&r->lock);
}

#endif /* __RATE_EST_H__ */
