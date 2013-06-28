
#include <linux/sysctl.h>
#include <linux/moduleparam.h>
#include <linux/stat.h>
#include <linux/semaphore.h>
#include <linux/netdevice.h>
#include <linux/if.h>

#include "params.h"
#include "tx.h"
#include "rx.h"
#include "vq.h"

// params
int ISO_FALPHA = 8;
/* All rates are in Mb/s.  This 9800 instead of 10000 accounts for
 * Ethernet framing overheads. */
int ISO_MAX_TX_RATE = 9800;
int ISO_VQ_DRAIN_RATE_MBPS = 9000;
int ISO_MAX_BURST_TIME_US = 150;
int ISO_MIN_BURST_BYTES = 65536;
int ISO_RATEMEASURE_INTERVAL_US = 1000 * 100;
int ISO_TOKENBUCKET_TIMEOUT_NS = 50 * 1000;
int ISO_TOKENBUCKET_MARK_THRESH_BYTES = 512 * 1024;
int ISO_TOKENBUCKET_DROP_THRESH_BYTES = 512 * 1024;
int ISO_VQ_MARK_THRESH_BYTES = 128 * 1024;
int ISO_VQ_MAX_BYTES = 256 * 1024;
int ISO_RFAIR_INITIAL = 5000;
int ISO_MIN_RFAIR = 10;
int ISO_RFAIR_INCREMENT = 10;
int ISO_RFAIR_DECREASE_INTERVAL_US = 120;
int ISO_RFAIR_INCREASE_INTERVAL_US = 120;
int ISO_RFAIR_FEEDBACK_TIMEOUT_US = 1000 * 1000;
int ISO_RFAIR_FEEDBACK_TIMEOUT_DEFAULT_RATE = 10;
int IsoGlobalEnabled = 1;
int IsoAutoGenerateFeedback = 1;
int ISO_FEEDBACK_INTERVAL_US = 100;
int ISO_FEEDBACK_INTERVAL_BYTES = 10000;

// TODO: We are assuming that we don't need to do any VLAN tag
// ourselves
const int ISO_FEEDBACK_PACKET_SIZE = 100;
const u16 ISO_FEEDBACK_HEADER_SIZE = 20;
const u8 ISO_FEEDBACK_PACKET_TTL = 64;
int ISO_FEEDBACK_PACKET_IPPROTO = 143; // should be some unused protocol

// New parameters
int ISO_RL_UPDATE_INTERVAL_US = 20;
int ISO_BURST_FACTOR = 8;
int ISO_VQ_UPDATE_INTERVAL_US = 200;
int ISO_TXC_UPDATE_INTERVAL_US = 200;
int ISO_VQ_REFRESH_INTERVAL_US = 500;
int ISO_MAX_QUEUE_LEN_BYTES = 128 * 1024;
int ISO_TX_MARK_THRESH = 100 * 1024;
int ISO_GSO_THRESH_RATE = 1000;
int ISO_GSO_MIN_SPLIT_BYTES = 10000;
int ISO_ECN_MARK_THRESH_BYTES = 30 * 1500;
int ISO_VQ_HRCP_US = 1000;

struct iso_param iso_params[64] = {
  {"ISO_MAX_TX_RATE", &ISO_MAX_TX_RATE },
  {"ISO_VQ_DRAIN_RATE_MBPS", &ISO_VQ_DRAIN_RATE_MBPS },
  {"ISO_MAX_BURST_TIME_US", &ISO_MAX_BURST_TIME_US },
  {"ISO_MIN_BURST_BYTES", &ISO_MIN_BURST_BYTES },
  {"ISO_RATEMEASURE_INTERVAL_US", &ISO_RATEMEASURE_INTERVAL_US },
  {"ISO_TOKENBUCKET_TIMEOUT_NS", &ISO_TOKENBUCKET_TIMEOUT_NS },
  {"ISO_TOKENBUCKET_MARK_THRESH_BYTES", &ISO_TOKENBUCKET_MARK_THRESH_BYTES },
  {"ISO_TOKENBUCKET_DROP_THRESH_BYTES", &ISO_TOKENBUCKET_DROP_THRESH_BYTES },
  {"ISO_VQ_MARK_THRESH_BYTES", &ISO_VQ_MARK_THRESH_BYTES },
  {"ISO_VQ_MAX_BYTES", &ISO_VQ_MAX_BYTES },
  {"ISO_RFAIR_INITIAL", &ISO_RFAIR_INITIAL },
  {"ISO_MIN_RFAIR", &ISO_MIN_RFAIR },
  {"ISO_RFAIR_FEEDBACK_TIMEOUT", &ISO_RFAIR_FEEDBACK_TIMEOUT_US },
  {"ISO_RFAIR_FEEDBACK_TIMEOUT_DEFAULT_RATE", &ISO_RFAIR_FEEDBACK_TIMEOUT_DEFAULT_RATE },
  {"IsoGlobalEnabled", &IsoGlobalEnabled },
  {"IsoAutoGenerateFeedback", &IsoAutoGenerateFeedback },
  {"ISO_FEEDBACK_PACKET_IPPROTO", &ISO_FEEDBACK_PACKET_IPPROTO },
  {"ISO_FEEDBACK_INTERVAL_US", &ISO_FEEDBACK_INTERVAL_US },
  {"ISO_FEEDBACK_INTERVAL_BYTES", &ISO_FEEDBACK_INTERVAL_BYTES },
  {"ISO_RL_UPDATE_INTERVAL_US", &ISO_RL_UPDATE_INTERVAL_US },
  {"ISO_VQ_UPDATE_INTERVAL_US", &ISO_VQ_UPDATE_INTERVAL_US },
  {"ISO_TXC_UPDATE_INTERVAL_US", &ISO_TXC_UPDATE_INTERVAL_US },
  {"ISO_VQ_REFRESH_INTERVAL_US", &ISO_VQ_REFRESH_INTERVAL_US },
  {"ISO_MAX_QUEUE_LEN_BYTES", &ISO_MAX_QUEUE_LEN_BYTES },
  {"ISO_TX_MARK_THRESH", &ISO_TX_MARK_THRESH },
  {"ISO_ECN_MARK_THRESH_BYTES", &ISO_ECN_MARK_THRESH_BYTES },
  {"ISO_VQ_HRCP_US", &ISO_VQ_HRCP_US },
  {"", NULL},
};

struct ctl_table iso_params_table[32];
struct ctl_path iso_params_path[] = {
	{ .procname = "perfiso" },
	{ },
};
struct ctl_table_header *iso_sysctl;

#ifdef QDISC
struct net_device *iso_search_netdev(char *name) {
	struct net *net;
	struct net_device *dev;
	for_each_net(net) {
		for_each_netdev(net, dev) {
			if (strncmp(name, dev->name, IFNAMSIZ) == 0)
				return dev;
		}
	}
	return NULL;
}
#else
struct net_device *iso_search_netdev(char *name) {
	return iso_param_dev;
}
#endif

int iso_params_init() {
	int i;

	memset(iso_params_table, 0, sizeof(iso_params_table));

	for(i = 0; i < 32; i++) {
		struct ctl_table *entry = &iso_params_table[i];
		if(iso_params[i].ptr == NULL)
			break;

		entry->procname = iso_params[i].name;
		entry->data = iso_params[i].ptr;
		entry->maxlen = sizeof(int);
		entry->mode = 0644;
		entry->proc_handler = proc_dointvec;
	}

	iso_sysctl = register_sysctl_paths(iso_params_path, iso_params_table);
	if(iso_sysctl == NULL)
		goto err;

	return 0;

 err:
	return -1;
}

void iso_params_exit() {
	unregister_sysctl_table(iso_sysctl);
}

/*
 * Create a new TX context with a specific filter
 * If compiled with CLASS_DEV
 * echo -n eth0 > /sys/module/perfiso/parameters/create_txc
 *
 * If compiled with CLASS_ETHER_SRC
 * echo -n dev eth0 00:00:00:00:01:01 > /sys/module/perfiso/parameters/create_txc
 */
static DEFINE_SEMAPHORE(config_mutex);
static int iso_sys_create_txc(const char *val, struct kernel_param *kp) {
	char buff[128];
	char klass[128];
	char devname[128];
	int len, ret;
	struct iso_tx_context *txctx;
	struct net_device *dev = NULL;

	len = min(127, (int)strlen(val));
	strncpy(buff, val, len);
	buff[len] = '\0';

	if(down_interruptible(&config_mutex))
		return -EINVAL;

	sscanf(buff, "dev %s %s", devname, klass);

	dev = iso_search_netdev(devname);
	if (dev && iso_enabled(dev)) {
		txctx = iso_txctx_dev(dev);
		ret = iso_txc_install(klass, txctx);
	} else {
		ret = -EINVAL;
	}

	up(&config_mutex);

	if(ret)
		return -EINVAL;

	printk(KERN_INFO "perfiso: created tx context for class %s, dev %s\n",
	       klass, devname);
	return 0;
}

static int iso_sys_noget(const char *val, struct kernel_param *kp) {
	return 0;
}

module_param_call(create_txc, iso_sys_create_txc, iso_sys_noget, NULL, S_IWUSR);

/*
 * Create a new RX context (vq) with a specific filter
 * If compiled with CLASS_DEV
 * echo -n eth0 > /sys/module/perfiso/parameters/create_vq
 *
 * If compiled with CLASS_ETHER_SRC
 * echo -n dev eth0 00:00:00:00:01:01 > /sys/module/perfiso/parameters/create_vq
 */
static int iso_sys_create_vq(const char *val, struct kernel_param *kp) {
	char buff[128];
	char devname[128];
	char klass[128];
	struct iso_rx_context *rxctx;
	struct net_device *dev = NULL;
	int len, ret;

	len = min(127, (int)strlen(val));
	strncpy(buff, val, len);
	buff[len] = '\0';

	if(down_interruptible(&config_mutex))
		return -EINVAL;

	sscanf(buff, "dev %s %s", devname, klass);
	rcu_read_lock();
	dev = iso_search_netdev(devname);
	if (dev && iso_enabled(dev)) {
		rxctx = iso_rxctx_dev(dev);
		ret = iso_vq_install(klass, rxctx);
	} else {
		ret = -EINVAL;
	}
	rcu_read_unlock();
	up(&config_mutex);

	if(ret)
		return -EINVAL;

	printk(KERN_INFO "perfiso: created vq for class %s, dev %s\n", klass, devname);
	return 0;
}

module_param_call(create_vq, iso_sys_create_vq, iso_sys_noget, NULL, S_IWUSR);

/*
 * Associate the TX path with a VQ.
 * echo -n dev eth0 associate txc 00:00:00:00:01:01 vq 00:00:00:00:01:01
 * > /sys/module/perfiso/parameters/assoc_txc_vq
 */
static int iso_sys_assoc_txc_vq(const char *val, struct kernel_param *kp) {
	char _txc[128], _vqc[128], _devname[128];
	iso_class_t txclass, vqclass;
	struct iso_tx_class *txc;
	struct iso_vq *vq;
	struct net_device *dev = NULL;
	struct iso_rx_context *rxctx;
	struct iso_tx_context *txctx;
	int n, ret = 0;

	n = sscanf(val, "dev %s associate txc %s vq %s", _devname, _txc, _vqc);

	if(down_interruptible(&config_mutex))
		return -EINVAL;

	rcu_read_lock();
	if(n != 3) {
		ret = -EINVAL;
		goto out;
	}

	dev = iso_search_netdev(_devname);
	if ((dev == NULL) || !iso_enabled(dev))
		goto out;

	txclass = iso_class_parse(_txc);
	vqclass = iso_class_parse(_vqc);
	rxctx = iso_rxctx_dev(dev);
	txctx = iso_txctx_dev(dev);

	txc = iso_txc_find(txclass, txctx);
	if(txc == NULL) {
		ret = -EINVAL;
		goto out;
	}

	vq = iso_vq_find(vqclass, rxctx);
	if(vq == NULL) {
		printk(KERN_INFO "perfiso: Could not find vq %s\n", _vqc);
		ret = -EINVAL;
		goto out;
	}

	/* XXX: locks?  synchronisation? */
	if(txc->vq) {
		atomic_dec(&txc->vq->refcnt);
	}

	txc->vq = vq;
	atomic_inc(&vq->refcnt);

	printk(KERN_INFO "perfiso: Associated txc %s with vq %s on %s\n",
	       _txc, _vqc, _devname);
 out:

	rcu_read_unlock();
	up(&config_mutex);
	return ret;
}

module_param_call(assoc_txc_vq, iso_sys_assoc_txc_vq, iso_sys_noget, NULL, S_IWUSR);

/*
 * Set TXC's weight
 * echo -n dev eth0 00:00:00:00:01:01 weight <w>
 * > /sys/module/perfiso/parameters/set_txc_weight
 */
static int iso_sys_set_txc_weight(const char *val, struct kernel_param *kp) {
	char _txc[128], _devname[128];
	iso_class_t klass;
	struct iso_tx_class *txc;
	unsigned long flags;
	int n, ret = 0, weight;
	struct net_device *dev = NULL;
	struct iso_tx_context *txctx;

	if(down_interruptible(&config_mutex))
		return -EINVAL;

	rcu_read_lock();
	n = sscanf(val, "dev %s %s weight %d", _devname, _txc, &weight);
	if(n != 3) {
		ret = -EINVAL;
		goto out;
	}

	dev = iso_search_netdev(_devname);
	if ((dev == NULL) || !iso_enabled(dev)) {
		ret = -EINVAL;
		goto out;
	}

	txctx = iso_txctx_dev(dev);
	klass = iso_class_parse(_txc);
	txc = iso_txc_find(klass, txctx);
	if(txc == NULL) {
		printk(KERN_INFO "perfiso: Could not find txc %s\n", _txc);
		ret = -EINVAL;
		goto out;
	}

	if(weight < 0 || weight > 1024) {
		printk(KERN_INFO "perfiso: Invalid weight.  Weight must lie in [1, 1024]\n");
		ret = -EINVAL;
		goto out;
	}

	spin_lock_irqsave(&txc->writelock, flags);
	txctx->txc_total_weight -= txc->weight;
	txc->weight = (u32)weight;
	txctx->txc_total_weight += txc->weight;
	spin_unlock_irqrestore(&txc->writelock, flags);

	iso_txc_recompute_rates(txctx);

	printk(KERN_INFO "perfiso: Set weight %d for txc %s on dev %s\n",
	       weight, _txc, _devname);
 out:

	rcu_read_unlock();
	up(&config_mutex);
	return ret;
}

module_param_call(set_txc_weight, iso_sys_set_txc_weight, iso_sys_noget, NULL, S_IWUSR);


/*
 * Set TXC's rate
 * echo -n dev eth0 00:00:00:00:01:01 rate <w>
 * > /sys/module/perfiso/parameters/set_txc_rate
 */
static int iso_sys_set_txc_rate(const char *val, struct kernel_param *kp) {
	char _txc[128], _devname[128];
	iso_class_t klass;
	struct iso_tx_class *txc;
	unsigned long flags;
	int n, ret = 0, debug;
	u64 minrate, maxrate;
	struct net_device *dev = NULL;
	struct iso_tx_context *txctx;

	if(down_interruptible(&config_mutex))
		return -EINVAL;

	rcu_read_lock();
	n = sscanf(val, "dev %s %s minrate %llu maxrate %llu %d", _devname, _txc, &minrate, &maxrate, &debug);
	if(n != 5) {
		ret = -EINVAL;
		goto out;
	}

	dev = iso_search_netdev(_devname);
	if ((dev == NULL) || !iso_enabled(dev)) {
		ret = -EINVAL;
		goto out;
	}

	txctx = iso_txctx_dev(dev);
	klass = iso_class_parse(_txc);
	txc = iso_txc_find(klass, txctx);
	if(txc == NULL) {
		printk(KERN_INFO "perfiso: Could not find txc %s\n", _txc);
		ret = -EINVAL;
		goto out;
	}

#define OK_TXC(rate) (((rate) > 0 && (rate) <= (ISO_MAX_TX_RATE + 1200)))
	if(!OK_TXC(minrate) || !OK_TXC(maxrate)) {
		printk(KERN_INFO "perfiso: Invalid rate.  Rate must lie in [1, %d]\n",
		       ISO_MAX_TX_RATE + 1200);
		ret = -EINVAL;
		goto out;
	}

	spin_lock_irqsave(&txc->writelock, flags);
	txc->conf_min_rate = minrate;
	txc->conf_max_rate = maxrate;
	spin_unlock_irqrestore(&txc->writelock, flags);

	iso_txc_recompute_rates(txctx);

	if (debug)
		printk(KERN_INFO "perfiso: Set minrate %llu maxrate %llu for txc %s on dev %s\n",
		       minrate, maxrate, _txc, _devname);
 out:

	rcu_read_unlock();
	up(&config_mutex);
	return ret;
}

module_param_call(set_txc_rate, iso_sys_set_txc_rate, iso_sys_noget, NULL, S_IWUSR);



/*
 * Set VQ's weight
 * echo -n dev %s 00:00:00:00:01:01 weight <w>
 * > /sys/module/perfiso/parameters/set_vq_weight
 */
extern spinlock_t vq_spinlock;
static int iso_sys_set_vq_weight(const char *val, struct kernel_param *kp) {
	char _vqc[128], _devname[128];
	iso_class_t vqclass;
	struct iso_vq *vq;
	unsigned long flags;
	int n, ret = 0, weight;
	struct iso_rx_context *rxctx;
	struct net_device *dev = NULL;

	if(down_interruptible(&config_mutex))
		return -EINVAL;

	rcu_read_lock();
	n = sscanf(val, "dev %s %s weight %d", _devname, _vqc, &weight);
	if(n != 3) {
		ret = -EINVAL;
		goto out;
	}

	dev = iso_search_netdev(_devname);
	if ((dev == NULL) || !iso_enabled(dev)) {
		ret = -EINVAL;
		goto out;
	}

	rxctx = iso_rxctx_dev(dev);
	vqclass = iso_class_parse(_vqc);
	vq = iso_vq_find(vqclass, rxctx);
	if(vq == NULL) {
		printk(KERN_INFO "perfiso: Could not find vq %s\n", _vqc);
		ret = -EINVAL;
		goto out;
	}

	if(weight < 0 || weight > 1024) {
		printk(KERN_INFO "perfiso: Invalid weight.  Weight must lie in [1, 1024]\n");
		ret = -EINVAL;
		goto out;
	}

	spin_lock_irqsave(&rxctx->vq_spinlock, flags);
	vq->weight = (u64)weight;
	iso_vq_calculate_rates(rxctx);
	spin_unlock_irqrestore(&rxctx->vq_spinlock, flags);

	printk(KERN_INFO "perfiso: Set weight %d for vq %s on dev %s\n",
	       weight, _vqc, _devname);
 out:

	rcu_read_unlock();
	up(&config_mutex);
	return ret;
}

module_param_call(set_vq_weight, iso_sys_set_vq_weight, iso_sys_noget, NULL, S_IWUSR);


/*
 * Set VQ's Rate (cap its rate in Mb/s)
 * echo -n dev %s 00:00:00:00:01:01 rate 1000
 * > /sys/module/perfiso/parameters/set_vq_rate
 */
extern spinlock_t vq_spinlock;
static int iso_sys_set_vq_rate(const char *val, struct kernel_param *kp) {
	char _vqc[128], _devname[128];
	iso_class_t vqclass;
	struct iso_vq *vq;
	unsigned long flags;
	int n, ret = 0, debug;
	u64 minrate, maxrate;
	struct iso_rx_context *rxctx;
	struct net_device *dev = NULL;

	if(down_interruptible(&config_mutex))
		return -EINVAL;

	rcu_read_lock();
	n = sscanf(val, "dev %s %s minrate %llu maxrate %llu %d", _devname, _vqc, &min_rate, &max_rate, &debug);
	if(n != 5) {
		ret = -EINVAL;
		goto out;
	}

	dev = iso_search_netdev(_devname);
	if ((dev == NULL) || !iso_enabled(dev)) {
		ret = -EINVAL;
		goto out;
	}

	rxctx = iso_rxctx_dev(dev);
	vqclass = iso_class_parse(_vqc);
	vq = iso_vq_find(vqclass, rxctx);
	if(vq == NULL) {
		printk(KERN_INFO "perfiso: Could not find vq %s\n", _vqc);
		ret = -EINVAL;
		goto out;
	}

#define OK(rate) (((rate) > 0 && (rate) <= (ISO_MAX_TX_RATE + 1200)))
	if(!OK(min_rate) || !OK(max_rate)) {
		printk(KERN_INFO "perfiso: Invalid rate.  Rate must lie in (0, %d]\n",
		       ISO_MAX_TX_RATE + 1200;
		ret = -EINVAL;
		goto out;
	}

	spin_lock_irqsave(&rxctx->vq_spinlock, flags);
	vq->conf_min_rate = minrate;
	vq->conf_max_rate = maxrate;
	spin_unlock_irqrestore(&rxctx->vq_spinlock, flags);

	if (debug)
		printk(KERN_INFO "perfiso: Set minrate %llu maxrate %llu for vq %s on dev %s\n",
		       minrate, maxrate, _vqc, _devname);
 out:

	rcu_read_unlock();
	up(&config_mutex);
	return ret;
}

module_param_call(set_vq_rate, iso_sys_set_vq_rate, iso_sys_noget, NULL, S_IWUSR);


/*
 * Delete a txc.
 * echo -n dev eth0 txc 00:00:00:00:01:01
 * > /sys/module/perfiso/parameters/delete_txc
 */
static int iso_sys_delete_txc(const char *val, struct kernel_param *kp) {
	char _txc[128], _devname[128];
	iso_class_t txclass;
	struct iso_tx_class *txc;
	struct net_device *dev = NULL;
	struct iso_tx_context *txctx;
	int n, ret = 0;

	if(down_interruptible(&config_mutex))
		return -EINVAL;

	n = sscanf(val, "dev %s txc %s", _devname, _txc);
	if (n != 2) {
		ret = -EINVAL;
		goto out;
	}

	dev = iso_search_netdev(_devname);
	if ((dev == NULL) || !iso_enabled(dev)) {
		ret = -EINVAL;
		goto out;
	}

	txclass = iso_class_parse(_txc);
	txctx = iso_txctx_dev(dev);

	txc = iso_txc_find(txclass, txctx);
	if (txc == NULL) {
		ret = -EINVAL;
		goto out;
	}

	/* Remove the txc from the hash table. */
	hlist_del(&txc->hash_node);
	txctx->txc_total_weight -= txc->weight;
	iso_txc_recompute_rates(txctx);
	iso_txc_free(txc);

	printk(KERN_INFO "perfiso: Delete txc %s on dev %s\n",
	       _txc, _devname);

out:
	up(&config_mutex);
	return ret;
}

module_param_call(delete_txc, iso_sys_delete_txc, iso_sys_noget, NULL, S_IWUSR);

/*
 * Delete a VQ.
 * echo -n dev eth0 vq 00:00:00:00:01:01
 * > /sys/module/perfiso/parameters/delete_vq
 */
static int iso_sys_delete_vq(const char *val, struct kernel_param *kp) {
	char _rxc[128], _devname[128];
	iso_class_t vqclass;
	struct iso_vq *vq;
	struct net_device *dev = NULL;
	struct iso_rx_context *rxctx;
	int n, ret = 0;

	if(down_interruptible(&config_mutex))
		return -EINVAL;

	n = sscanf(val, "dev %s vq %s", _devname, _rxc);
	if (n != 2) {
		ret = -EINVAL;
		goto out;
	}

	dev = iso_search_netdev(_devname);
	if ((dev == NULL) || !iso_enabled(dev)) {
		ret = -EINVAL;
		goto out;
	}

	vqclass = iso_class_parse(_rxc);
	rxctx = iso_rxctx_dev(dev);

	vq = iso_vq_find(vqclass, rxctx);
	if (vq == NULL) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * A VQ can be removed only after all txc's pointing to it are
	 * removed.  iso_vq_free itself checks for this condition.
	 */
	if (atomic_read(&vq->refcnt) > 0) {
		ret = -EINVAL;
		printk(KERN_INFO "perfiso: vq %s refcnt > 0.  Delete txc's first.\n",
		       _rxc);
		goto out;
	}

	iso_vq_free(vq);

	printk(KERN_INFO "perfiso: Delete vq %s on dev %s\n",
	       _rxc, _devname);

out:
	up(&config_mutex);
	return ret;
}

module_param_call(delete_vq, iso_sys_delete_vq, iso_sys_noget, NULL, S_IWUSR);

#ifdef QDISC
int iso_enabled(struct net_device *dev) {
	struct Qdisc *qdisc = dev->qdisc;
	if (qdisc)
		return qdisc->flags & TCQ_F_EYEQ;
	return 0;
}
#else
int iso_enabled(struct net_device *dev) {
	return dev == iso_netdev;
}
#endif

static int iso_sys_recompute_dev(const char *val, struct kernel_param *kp) {
	char buff[128];
	char devname[128];
	int len, ret, n;
	struct iso_tx_context *txctx;
	struct iso_rx_context *rxctx;
	struct net_device *dev = NULL;

	len = min(127, (int)strlen(val));
	strncpy(buff, val, len);
	buff[len] = '\0';
	ret = 0;

	if(down_interruptible(&config_mutex))
		return -EINVAL;

	n = sscanf(buff, "dev %s", devname);

	if (n != 1) {
		ret = -EINVAL;
		goto out;
	}

	dev = iso_search_netdev(devname);
	if (dev && iso_enabled(dev)) {
		txctx = iso_txctx_dev(dev);
		rxctx = iso_rxctx_dev(dev);

		iso_txc_recompute_rates(txctx);
		iso_vq_calculate_rates(rxctx);
	} else {
		ret = -EINVAL;
	}

	up(&config_mutex);

out:
	if(ret)
		return -EINVAL;

	return 0;
}

module_param_call(recompute_dev, iso_sys_recompute_dev, iso_sys_noget, NULL, S_IWUSR);

/* Local Variables: */
/* indent-tabs-mode:t */
/* End: */

