#ifndef __PARAMS_H__
#define __PARAMS_H__

#include <linux/types.h>
#include <net/pkt_sched.h>

#include "rx.h"

/* All rates are in Mbps */
extern int ISO_MAX_TX_RATE;

// The VQ's net drain rate in Mbps is 90% of 10G ~ 9000 Mbps
extern int ISO_VQ_DRAIN_RATE_MBPS;
extern int ISO_RFAIR_INITIAL;
extern int ISO_MIN_RFAIR;
extern int IsoGlobalEnabled;
extern int IsoAutoGenerateFeedback;
extern int ISO_FEEDBACK_INTERVAL_US;
extern int ISO_FEEDBACK_INTERVAL_BYTES;

// TODO: We are assuming that we don't need to do any VLAN tag
// ourselves
extern const int ISO_FEEDBACK_PACKET_SIZE;
extern const u16 ISO_FEEDBACK_HEADER_SIZE;
extern const u8 ISO_FEEDBACK_PACKET_TTL;
extern int ISO_FEEDBACK_PACKET_IPPROTO; // should be some unused protocol

// New parameters
extern int ISO_VQ_UPDATE_INTERVAL_US;
extern int ISO_VQ_HRCP_US;

// MUST be 1 less than a power of 2
#define ISO_MAX_QUEUE_LEN_PKT (127)

#define ISO_IDLE_TIMEOUT_US (100 * 1000 * 10 * 1000)
#define ISO_IDLE_RATE (2500)
#define ISO_GSO_MAX_SIZE (32767)

struct iso_param {
	char name[64];
	int *ptr;
};

extern struct iso_param iso_params[64];
extern int iso_num_params;

int iso_params_init(void);
void iso_params_exit(void);

int iso_enabled(struct net_device *dev);

extern struct iso_rx_context *iso_rxctx_dev(const struct net_device *dev);
extern int iso_rxcl_install(char *_klass, struct iso_rx_context *ctx);

#endif /* __PARAMS_H__ */

/* Local Variables: */
/* indent-tabs-mode:t */
/* End: */
