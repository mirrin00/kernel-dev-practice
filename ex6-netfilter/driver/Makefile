obj-m := firewall.o
KBUILD=/lib/modules/$(shell uname -r)/build/

.PHONY: load unload log clean

all:
	$(MAKE) -C $(KBUILD) M=$(PWD) modules
clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean
load:
	sudo insmod firewall.ko
unload:
	sudo rmmod firewall
log:
	sudo dmesg | grep "\[firewall\]" || true