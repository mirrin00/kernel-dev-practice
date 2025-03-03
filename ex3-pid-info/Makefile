obj-m := pid-info.o
SRC := $(shell pwd)
MOD_CFLAGS := -g

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) CFLAGS_MODULE=$(MOD_CFLAGS) EXTRA_CFLAGS='-I$(SRC)'

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules_install

clean:
	rm -f *.o *.ko *.mod.c Module.markers Module.symvers modules.order
