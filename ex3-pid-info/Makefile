obj-m := pid-info.o
SRC := $(shell pwd)
MOD_CFLAGS := -g -I$(SRC)

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) CFLAGS_MODULE='$(MOD_CFLAGS)'

modules_install:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules_install

clean:
	rm -f *.o *.ko *.mod.c Module.markers Module.symvers modules.order
