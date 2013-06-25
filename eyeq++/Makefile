
obj-m += sch_eyeq.o

sch_eyeq-y := rx.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=`pwd`

.PHONY: .clean
clean:
	rm *.o *.ko *.mod.c modules.order Module.symvers
