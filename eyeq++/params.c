
#include <linux/sysctl.h>
#include <linux/moduleparam.h>
#include <linux/stat.h>
#include <linux/semaphore.h>
#include <linux/netdevice.h>
#include <linux/if.h>

#include "params.h"
#include "common.h"

// params
/* All rates are in Mb/s.  This 9800 instead of 10000 accounts for
 * Ethernet framing overheads. */
int ISO_MAX_TX_RATE = 9800;
int ISO_VQ_DRAIN_RATE_MBPS = 9000;
int ISO_MIN_RFAIR = 10;
int IsoGlobalEnabled = 1;
int IsoAutoGenerateFeedback = 1;
int ISO_FEEDBACK_INTERVAL_US = 100;
int ISO_FEEDBACK_INTERVAL_BYTES = 10000;

// TODO: We are assuming that we don't need to do any VLAN tag
// ourselves
const int ISO_FEEDBACK_PACKET_SIZE = 64;
const u16 ISO_FEEDBACK_HEADER_SIZE = 20;
const u8 ISO_FEEDBACK_PACKET_TTL = 64;
int ISO_FEEDBACK_PACKET_IPPROTO = 143; // should be some unused protocol

// New parameters
int ISO_VQ_UPDATE_INTERVAL_US = 200;
int ISO_VQ_HRCP_US = 1000;

struct iso_param iso_params[64] = {
  {"ISO_MAX_TX_RATE", &ISO_MAX_TX_RATE },
  {"ISO_VQ_DRAIN_RATE_MBPS", &ISO_VQ_DRAIN_RATE_MBPS },
  {"ISO_MIN_RFAIR", &ISO_MIN_RFAIR },
  {"IsoGlobalEnabled", &IsoGlobalEnabled },
  {"IsoAutoGenerateFeedback", &IsoAutoGenerateFeedback },
  {"ISO_FEEDBACK_PACKET_IPPROTO", &ISO_FEEDBACK_PACKET_IPPROTO },
  {"ISO_FEEDBACK_INTERVAL_US", &ISO_FEEDBACK_INTERVAL_US },
  {"ISO_FEEDBACK_INTERVAL_BYTES", &ISO_FEEDBACK_INTERVAL_BYTES },
  {"ISO_VQ_HRCP_US", &ISO_VQ_HRCP_US },
  {"", NULL},
};

struct ctl_table iso_params_table[32];
struct ctl_path iso_params_path[] = {
	{ .procname = "eyeq" },
	{ },
};
struct ctl_table_header *iso_sysctl;

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

static int iso_sys_noget(const char *v, struct kernel_param *kp)
{
	return 0;
}

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

static DEFINE_SEMAPHORE(config_mutex);

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
		ret = iso_rxcl_install(klass, rxctx);
	} else {
		ret = -EINVAL;
	}
	rcu_read_unlock();
	up(&config_mutex);

	if(ret)
		return -EINVAL;

	printk(KERN_INFO "eyeq: created vq for class %s, dev %s\n", klass, devname);
	return 0;
}

module_param_call(create_vq, iso_sys_create_vq, iso_sys_noget, NULL, S_IWUSR);

/*
 * Set VQ's weight
 * echo -n dev %s 00:00:00:00:01:01 weight <w>
 * > /sys/module/perfiso/parameters/set_vq_weight
 */
extern spinlock_t vq_spinlock;
static int iso_sys_set_vq_weight(const char *val, struct kernel_param *kp) {
	char _vqc[128], _devname[128];
	iso_class_t vqclass;
	struct iso_rx_class *vq;
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
	vq = iso_rxcl_find(vqclass, rxctx);
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

	vq->weight = (u64)weight;

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
	struct iso_rx_class *vq;
	int n, ret = 0, rate;
	struct iso_rx_context *rxctx;
	struct net_device *dev = NULL;

	if(down_interruptible(&config_mutex))
		return -EINVAL;

	rcu_read_lock();
	n = sscanf(val, "dev %s %s rate %d", _devname, _vqc, &rate);
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
	vq = iso_rxcl_find(vqclass, rxctx);
	if(vq == NULL) {
		printk(KERN_INFO "perfiso: Could not find vq %s\n", _vqc);
		ret = -EINVAL;
		goto out;
	}

	if(rate < 0 || rate > ISO_VQ_DRAIN_RATE_MBPS) {
		printk(KERN_INFO "perfiso: Invalid rate.  Rate must lie in [0, %d]\n",
		       ISO_VQ_DRAIN_RATE_MBPS);
		ret = -EINVAL;
		goto out;
	}

	printk(KERN_INFO "perfiso: Set rate %d for vq %s on dev %s\n",
	       rate, _vqc, _devname);
 out:

	rcu_read_unlock();
	up(&config_mutex);
	return ret;
}

module_param_call(set_vq_rate, iso_sys_set_vq_rate, iso_sys_noget, NULL, S_IWUSR);

/*
 * Delete a VQ.
 * echo -n dev eth0 vq 00:00:00:00:01:01
 * > /sys/module/perfiso/parameters/delete_vq
 */
static int iso_sys_delete_vq(const char *val, struct kernel_param *kp) {
	char _rxc[128], _devname[128];
	iso_class_t vqclass;
	struct iso_rx_class *vq;
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

	vq = iso_rxcl_find(vqclass, rxctx);
	if (vq == NULL) {
		ret = -EINVAL;
		goto out;
	}

	iso_rxcl_free(vq);

	printk(KERN_INFO "perfiso: Delete vq %s on dev %s\n",
	       _rxc, _devname);

out:
	up(&config_mutex);
	return ret;
}

module_param_call(delete_vq, iso_sys_delete_vq, iso_sys_noget, NULL, S_IWUSR);

int iso_enabled(struct net_device *dev) {
	struct Qdisc *qdisc = dev->qdisc;
	if (qdisc)
		return qdisc->flags & TCQ_F_EYEQ;
	return 0;
}

/* Local Variables: */
/* indent-tabs-mode:t */
/* End: */
