#include "tx.h"
#include "rx.h"

int IsoGlobalEnabled = 0;

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

int iso_rx(struct iso_rx_context *ctx, struct sk_buff *skb)
{

	return 0;
}
