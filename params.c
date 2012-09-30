
#include <linux/sysctl.h>
#include <linux/moduleparam.h>
#include <linux/stat.h>
#include <linux/semaphore.h>

#include "params.h"
#include "tx.h"
#include "rx.h"
#include "vq.h"

// params
int ISO_FALPHA = 8;
/* All rates are in Mbps */
int ISO_MAX_TX_RATE = 9800;
// The VQ's net drain rate in Mbps is 90% of 10G ~ 9000 Mbps
/* TODO: explain why this is 8500 and not 9000!  hint: due to GRO */
int ISO_VQ_DRAIN_RATE_MBPS = 10000;
int ISO_MAX_BURST_TIME_US = 150;
int ISO_MIN_BURST_BYTES = 65536;
int ISO_RATEMEASURE_INTERVAL_US = 1000 * 100;
int ISO_TOKENBUCKET_TIMEOUT_NS = 50 * 1000;
int ISO_TOKENBUCKET_MARK_THRESH_BYTES = 512 * 1024;
int ISO_TOKENBUCKET_DROP_THRESH_BYTES = 512 * 1024;
int ISO_VQ_MARK_THRESH_BYTES = 128 * 1024;
int ISO_VQ_MAX_BYTES = 256 * 1024;
int ISO_RFAIR_INITIAL = 5000;
int ISO_MIN_RFAIR = 2;
int ISO_RFAIR_INCREMENT = 10;
int ISO_RFAIR_DECREASE_INTERVAL_US = 120;
int ISO_RFAIR_INCREASE_INTERVAL_US = 120;
int ISO_RFAIR_FEEDBACK_TIMEOUT_US = 1000 * 1000;
int ISO_RFAIR_FEEDBACK_TIMEOUT_DEFAULT_RATE = 10;
int IsoGlobalEnabled = 0;
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
int ISO_RL_UPDATE_INTERVAL_US = 20;
int ISO_BURST_FACTOR = 8;
int ISO_VQ_UPDATE_INTERVAL_US = 200;
int ISO_TXC_UPDATE_INTERVAL_US = 100;
int ISO_VQ_REFRESH_INTERVAL_US = 500;
int ISO_MAX_QUEUE_LEN_BYTES = 128 * 1024;
int ISO_TX_MARK_THRESH = 100 * 1024;
int ISO_GSO_THRESH_RATE = 1000;
int ISO_GSO_MIN_SPLIT_BYTES = 10000;

struct iso_param iso_params[64] = {
  {"ISO_FALPHA", &ISO_FALPHA },
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
  {"ISO_RFAIR_INCREMENT", &ISO_RFAIR_INCREMENT },
  {"ISO_RFAIR_DECREASE_INTERVAL_US", &ISO_RFAIR_DECREASE_INTERVAL_US },
  {"ISO_RFAIR_INCREASE_INTERVAL_US", &ISO_RFAIR_INCREASE_INTERVAL_US },
  {"ISO_RFAIR_FEEDBACK_TIMEOUT", &ISO_RFAIR_FEEDBACK_TIMEOUT_US },
  {"ISO_RFAIR_FEEDBACK_TIMEOUT_DEFAULT_RATE", &ISO_RFAIR_FEEDBACK_TIMEOUT_DEFAULT_RATE },
  {"IsoGlobalEnabled", &IsoGlobalEnabled },
  {"IsoAutoGenerateFeedback", &IsoAutoGenerateFeedback },
  {"ISO_FEEDBACK_PACKET_IPPROTO", &ISO_FEEDBACK_PACKET_IPPROTO },
  {"ISO_FEEDBACK_INTERVAL_US", &ISO_FEEDBACK_INTERVAL_US },
  {"ISO_FEEDBACK_INTERVAL_BYTES", &ISO_FEEDBACK_INTERVAL_BYTES },
  {"ISO_RL_UPDATE_INTERVAL_US", &ISO_RL_UPDATE_INTERVAL_US },
  {"ISO_BURST_FACTOR", &ISO_BURST_FACTOR },
  {"ISO_VQ_UPDATE_INTERVAL_US", &ISO_VQ_UPDATE_INTERVAL_US },
  {"ISO_TXC_UPDATE_INTERVAL_US", &ISO_TXC_UPDATE_INTERVAL_US },
  {"ISO_VQ_REFRESH_INTERVAL_US", &ISO_VQ_REFRESH_INTERVAL_US },
  {"ISO_MAX_QUEUE_LEN_BYTES", &ISO_MAX_QUEUE_LEN_BYTES },
  {"ISO_TX_MARK_THRESH", &ISO_TX_MARK_THRESH },
  {"", NULL},
};

struct ctl_table iso_params_table[32];
struct ctl_path iso_params_path[] = {
	{ .procname = "perfiso" },
	{ },
};
struct ctl_table_header *iso_sysctl;

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
 * echo -n 00:00:00:00:01:01 > /sys/module/perfiso/parameters/create_txc
 */
static DEFINE_SEMAPHORE(config_mutex);
static int iso_sys_create_txc(const char *val, struct kernel_param *kp) {
	char buff[128];
	int len, ret;

	len = min(127, (int)strlen(val));
	strncpy(buff, val, len);
	buff[len] = '\0';

	if(down_interruptible(&config_mutex))
		return -EINVAL;

	ret = iso_txc_install(buff);

	up(&config_mutex);

	if(ret)
		return -EINVAL;

	printk(KERN_INFO "perfiso: created tx context for class %s\n", buff);
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
 * echo -n 00:00:00:00:01:01 > /sys/module/perfiso/parameters/create_vq
 */
static int iso_sys_create_vq(const char *val, struct kernel_param *kp) {
	char buff[128];
	int len, ret;

	len = min(127, (int)strlen(val));
	strncpy(buff, val, len);
	buff[len] = '\0';

	if(down_interruptible(&config_mutex))
		return -EINVAL;

	ret = iso_vq_install(buff);

	up(&config_mutex);

	if(ret)
		return -EINVAL;

	printk(KERN_INFO "perfiso: created vq for class %s\n", buff);
	return 0;
}

module_param_call(create_vq, iso_sys_create_vq, iso_sys_noget, NULL, S_IWUSR);

/*
 * Associate the TX path with a VQ.
 * echo -n associate txc 00:00:00:00:01:01 vq 00:00:00:00:01:01
 * > /sys/module/perfiso/parameters/assoc_txc_vq
 */
static int iso_sys_assoc_txc_vq(const char *val, struct kernel_param *kp) {
	char _txc[128], _vqc[128];
	iso_class_t txclass, vqclass;
	struct iso_tx_class *txc;
	struct iso_vq *vq;

	int n, ret = 0;

	n = sscanf(val, "associate txc %s vq %s", _txc, _vqc);
	if(n != 2) {
		ret = -EINVAL;
		goto out;
	}

	txclass = iso_class_parse(_txc);
	vqclass = iso_class_parse(_vqc);

	txc = iso_txc_find(txclass);
	if(txc == NULL) {
		ret = -EINVAL;
		goto out;
	}

	vq = iso_vq_find(vqclass);
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

	printk(KERN_INFO "perfiso: Associated txc %s with vq %s\n",
		   _txc, _vqc);
 out:
	return ret;
}

module_param_call(assoc_txc_vq, iso_sys_assoc_txc_vq, iso_sys_noget, NULL, S_IWUSR);

/*
 * Set TXC's weight
 * echo -n 00:00:00:00:01:01 weight <w>
 * > /sys/module/perfiso/parameters/set_txc_weight
 */
static int iso_sys_set_txc_weight(const char *val, struct kernel_param *kp) {
	char _txc[128];
	iso_class_t klass;
	struct iso_tx_class *txc;
	unsigned long flags;
	int n, ret = 0, weight;

	n = sscanf(val, "%s weight %d", _txc, &weight);
	if(n != 2) {
		ret = -EINVAL;
		goto out;
	}

	klass = iso_class_parse(_txc);
	txc = iso_txc_find(klass);
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
	txc_total_weight -= txc->weight;
	txc->weight = (u32)weight;
	txc->rl.weight = weight;
	txc_total_weight += txc->weight;
	spin_unlock_irqrestore(&txc->writelock, flags);

	printk(KERN_INFO "perfiso: Set weight %d for txc %s\n",
		   weight, _txc);
 out:
	return ret;
}

module_param_call(set_txc_weight, iso_sys_set_txc_weight, iso_sys_noget, NULL, S_IWUSR);


/*
 * Set VQ's weight
 * echo -n 00:00:00:00:01:01 weight <w>
 * > /sys/module/perfiso/parameters/set_vq_weight
 */
extern spinlock_t vq_spinlock;
static int iso_sys_set_vq_weight(const char *val, struct kernel_param *kp) {
	char _vqc[128];
	iso_class_t vqclass;
	struct iso_vq *vq;
	unsigned long flags;
	int n, ret = 0, weight;

	n = sscanf(val, "%s weight %d", _vqc, &weight);
	if(n != 2) {
		ret = -EINVAL;
		goto out;
	}

	vqclass = iso_class_parse(_vqc);
	vq = iso_vq_find(vqclass);
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

	spin_lock_irqsave(&vq_spinlock, flags);
	vq->weight = (u64)weight;
	iso_vq_calculate_rates();
	spin_unlock_irqrestore(&vq_spinlock, flags);

	printk(KERN_INFO "perfiso: Set weight %d for vq %s\n",
		   weight, _vqc);
 out:
	return ret;
}

module_param_call(set_vq_weight, iso_sys_set_vq_weight, iso_sys_noget, NULL, S_IWUSR);

/* Local Variables: */
/* indent-tabs-mode:t */
/* End: */

