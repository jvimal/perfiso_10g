
HOOK=bridge

obj-m += perfiso.o

perfiso-y := stats.o rc.o rl.o vq.o tx.o rx.o params.o main.o

EXTRA_CFLAGS += -DISO_TX_CLASS_MARK

ifeq ($(HOOK),iptables)
	perfiso-y += iptables.o
	EXTRA_CFLAGS += -DISO_HOOK_IPTABLES
else
	perfiso-y += bridge.o
	EXTRA_CFLAGS += -DISO_HOOK_BRIDGE
endif

all:
	make -C /usr/src/linux-cfs-bw M=`pwd`
