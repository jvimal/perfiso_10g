#ifndef __RX_H__
#define __RX_H__
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
#include <linux/jhash.h>

#include "rcp.h"

#define MAX_BUCKETS (2048)
typedef u32 iso_class_t;

enum rx_class_type {
	RXCL_TOP,
	RXCL_CONTAINER,
	RXCL_INTRA_TOR,
	RXCL_INTER_TOR,
};

struct iso_rx_context {
	/* list of classes.  For now we will have only one kind of
	 * classifier (tcp port).  */

	/* for a first try, we will only do inter-ToR fairness.  We
	 * will do the split later. */
	spinlock_t lock;
	struct list_head cl_list;
	struct hlist_head cl_hash[MAX_BUCKETS];
};

struct iso_rx_class {
	struct hlist_node hash_node;
	struct list_head list_node;

	struct iso_rx_class *parent;
	struct rate_est rx_rate_est;
	struct rcp rcp;

	enum rx_class_type cltype;
	struct iso_rx_context *ctx;
	iso_class_t klass;
	u32 weight;
};


// init function to set up receive path handler
int iso_rxctx_init(struct iso_rx_context *ctx, struct net_device *dev);

// exit function to remove rx path handler

// init function for rx_class
int iso_rxcl_init(struct iso_rx_class *cl);
void iso_rxcl_free(struct iso_rx_class *cl);

// free function for rx_class

// sysfs to allow configuration on receive path

rx_handler_result_t iso_rx_handler(struct sk_buff **);
int iso_rx(struct iso_rx_context *ctx, struct sk_buff *skb);

struct iso_rx_class *iso_rxcl_alloc(struct iso_rx_context *ctx, iso_class_t klass);

iso_class_t iso_class_parse(char *buff);
struct iso_rx_class *iso_rxcl_find(iso_class_t klass,
				   struct iso_rx_context *rxctx);

#endif /* __RX_H__ */
