

obj-m += perfiso.o

perfiso-y := stats.o rc.o rl.o vq.o tx.o rx.o params.o qdisc.o main.o
EXTRA_CFLAGS += -DISO_TX_CLASS_L4PORT -DQDISC -O2

all:
	make -j9 -C /lib/modules/$(shell uname -r)/build M=`pwd`
