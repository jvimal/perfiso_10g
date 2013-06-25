#ifndef __TX_H__
#define __TX_H__

#include "rx.h"

struct mq_sched {
	struct Qdisc *sch;
	struct Qdisc		**qdiscs;
	struct tcf_proto *filter_list;
	struct Qdisc_class_hash clhash;

	/* For receive path */
	struct iso_rx_context rx;

	/* Default class */
	int defcls;
};

#endif /* __TX_H__ */
