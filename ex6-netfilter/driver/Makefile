FIREWALL_CFLAGS += -g -DDEBUG
ccflags-y += ${FIREWALL_CFLAGS}
CC += ${FIREWALL_CFLAGS}

obj-m := firewall.o
KBUILD=/lib/modules/$(shell uname -r)/build/

all:
	EXTRA_CFLAGS="$(FIREWALL_CFLAGS)" $(MAKE) -C $(KBUILD) M=$(PWD) modules
clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean
load:
	sudo insmod firewall.ko
unload:
	sudo rmmod firewall
log:
	sudo dmesg | grep "\[firewall\]" || true