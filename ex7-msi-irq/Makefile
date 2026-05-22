obj-m := msi-example.o
KBUILD=/lib/modules/$(shell uname -r)/build/

all:
	$(MAKE) -C $(KBUILD) M=$(PWD) modules
clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean
load:
	sudo insmod msi-example.ko
unload:
	sudo rmmod msi-example
log:
	sudo dmesg | grep "\[msi-example\]" || true