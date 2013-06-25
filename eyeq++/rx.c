#include "tx.h"
#include "rx.h"
#include "params.h"

u32 iso_class_hash(iso_class_t klass)
{
	return jhash_1word(klass, 0xdeadbeef);
}

int iso_rxctx_init(struct iso_rx_context *ctx, struct net_device *dev)
{
	int ret = 0;
	int i;

	rtnl_lock();
	ret = netdev_rx_handler_register(dev, iso_rx_handler, NULL);
	rtnl_unlock();
	synchronize_net();

	if (ret)
		goto err;

	INIT_LIST_HEAD(&ctx->cl_list);
	for (i = 0; i < MAX_BUCKETS; i++) {
		INIT_HLIST_HEAD(&ctx->cl_hash[i]);
	}

	return 0;
err:
	return ret;
}

void iso_rxctx_free(struct iso_rx_context *ctx)
{
	struct iso_rx_class *cl, *clnext;

	list_for_each_entry_safe(cl, clnext, &ctx->cl_list, list_node)
	{
		iso_rxcl_free(cl);
	}
	return;
}

struct iso_rx_context *iso_rxctx_dev(const struct net_device *dev)
{
	struct Qdisc *qdisc = dev->qdisc;
	struct mq_sched *mq = qdisc_priv(qdisc);
	return &mq->rx;
}

rx_handler_result_t iso_rx_handler(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct iso_rx_context *rxctx;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;

	if (unlikely(!IsoGlobalEnabled))
		return RX_HANDLER_PASS;

	rxctx = iso_rxctx_dev(skb->dev);
	if (iso_rx(rxctx, skb)) {
		kfree_skb(skb);
		return RX_HANDLER_CONSUMED;
	}

	return RX_HANDLER_PASS;
}

int iso_rxcl_install(char *_klass, struct iso_rx_context *ctx)
{
	iso_class_t klass = iso_class_parse(_klass);
	struct iso_rx_class *cl;
	int ret = 0;

	cl = iso_rxcl_find(klass, ctx);
	if (cl != NULL) {
		ret = -EEXIST;
		goto err;
	}

	cl = iso_rxcl_alloc(ctx, klass);
	if (cl == NULL) {
		ret = -ENOBUFS;
		goto err;
	}

err:
	return ret;
}

int iso_rx(struct iso_rx_context *ctx, struct sk_buff *skb)
{

	return 0;
}

struct iso_rx_class *iso_rxcl_alloc(struct iso_rx_context *ctx, iso_class_t klass)
{
	struct iso_rx_class *cl = kmalloc(sizeof(struct iso_rx_class), GFP_KERNEL);
	struct hlist_head *head;
	u32 hash;

	if (cl) {
		cl->ctx = ctx;
		cl->klass = klass;
		if (iso_rxcl_init(cl))
			goto free;
		hash = iso_class_hash(klass);
		head = &ctx->cl_hash[hash & (MAX_BUCKETS - 1)];

		spin_lock(&ctx->lock);
		hlist_add_head(&cl->hash_node, head);
		list_add_tail(&cl->list_node, &ctx->cl_list);
		spin_unlock(&ctx->lock);
		return cl;
	free:
		iso_rxcl_free(cl);
	}

	return NULL;
}

int iso_rxcl_init(struct iso_rx_class *cl)
{
	if (rate_est_init(&cl->rx_rate_est,
			  ISO_VQ_UPDATE_INTERVAL_US))
		return -ENOBUFS;

	rcp_init(&cl->rcp, ISO_VQ_DRAIN_RATE_MBPS,
		 &cl->rx_rate_est, ISO_VQ_UPDATE_INTERVAL_US);
	return 0;
}

void iso_rxcl_free(struct iso_rx_class *cl)
{
	rate_est_free(&cl->rx_rate_est);
	list_del(&cl->list_node);
	hlist_del(&cl->hash_node);
	kfree(cl);
}

iso_class_t iso_class_parse(char *buff)
{
	u32 ret;
	sscanf(buff, "%u", &ret);
	return ret;
}

struct iso_rx_class *iso_rxcl_find(iso_class_t klass,
				   struct iso_rx_context *rxctx)
{
	u32 hash = iso_class_hash(klass);
	struct hlist_head *head = &rxctx->cl_hash[hash & (MAX_BUCKETS - 1)];
	struct hlist_node *node;
	struct iso_rx_class *cl;

	hlist_for_each_entry(cl, node, head, hash_node) {
		if (cl->klass == klass)
			return cl;
	}

	return NULL;
}
