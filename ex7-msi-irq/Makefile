FIREWALL_CFLAGS += -g -DDEBUG
ccflags-y += ${FIREWALL_CFLAGS}
CC += ${FIREWALL_CFLAGS}

obj-m := msi-example.o
KBUILD=/lib/modules/$(shell uname -r)/build/

all:
	EXTRA_CFLAGS="$(FIREWALL_CFLAGS)" $(MAKE) -C $(KBUILD) M=$(PWD) modules
clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean
load:
	sudo insmod msi-example.ko
unload:
	sudo rmmod msi-example
log:
	sudo dmesg | grep "\[msi-example\]" || true