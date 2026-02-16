# Makefile is supposed to be run in container
# To use it on host change variables below
BUILD_DIR ?= /build
WORK_DIR ?= /work

# === versions
KVER ?= 6.12.71
BUSYBOX_VER ?= 1.36.1
DROPBEAR_VER ?= 2024.85
ALPINE_MAKE_ROOTFS_VER ?= 0.8.1
ALPINE_MAKE_ROOTFS_BRACNH ?= v3.23

# ==== configs
KERNEL_CFG ?= 
BUSYBOX_CFG ?= .config.busybox
ARCH = x86_64

# ====
LINUX_DIRNAME := linux-${KVER}
LINUX_TAR := $(LINUX_DIRNAME).tar.xz
KERNEL_PATH := $(BUILD_DIR)/$(LINUX_DIRNAME)
BZIMAGE := $(KERNEL_PATH)/arch/$(ARCH)/boot/bzImage
KERNEL_COMPILE_CMDS_REPLACE ?=

# === minimal linux ramfs ===
BUSYBOX_DIRNAME := busybox-$(BUSYBOX_VER)
BUSYBOX_TAR := $(BUSYBOX_DIRNAME).tar.bz2
BUSYBOX_PATH := $(BUILD_DIR)/$(BUSYBOX_DIRNAME)
DROPBEAR_DIRNAME := DROPBEAR_$(DROPBEAR_VER)
DROPBEAR_TAR := $(DROPBEAR_DIRNAME).tar.gz
DROPBEAR_PATH := $(BUILD_DIR)/dropbear-$(DROPBEAR_DIRNAME)
SKELETON_BB_PATH := $(WORK_DIR)/rootfs-files/busybox
RAMFS_BB_DIR := $(BUILD_DIR)/ramfs-busybox
RAMFS_BB_IMAGE := $(BUILD_DIR)/ramfs-busybox.img

# === alpine rootfs ===
ROOTFS_ALPINE_IMG_PATH := $(BUILD_DIR)/rootfs-alpine.img
ROOTFS_ALPINE_ROOTFS_PATH := $(BUILD_DIR)/rootfs-alpine
ROOTFS_ALPINE_SCRIPT := $(WORK_DIR)/rootfs-files/alpine/setup.sh
ALPINE_MAKE_ROOTFS_TAR := alpine-make-rootfs-$(ALPINE_MAKE_ROOTFS_VER).tar.gz
ROOTFS_ALPINE_MAKE_PATH := $(BUILD_DIR)/alpine-make-rootfs-$(ALPINE_MAKE_ROOTFS_VER)

ROOTFS_ALPINE_PACKAGES := "openrc-init alpine-base fish python3 openssh-server vim"

# === qemu/ssh options ===
QEMU_SSH_PORT ?= 2222
QEMU_MEMORY ?= 256m
QEMU_IMG_OPTS := -initrd $(RAMFS_BB_IMAGE)
SSH_OPTS := -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
SSH_USER := root@127.0.0.1
SSH := ssh $(SSH_OPTS) -p $(QEMU_SSH_PORT) $(SSH_USER)
SCP := scp -O $(SSH_OPTS) -P $(QEMU_SSH_PORT)
SSH_CMD ?=

# === Modules options ===
MODULE_NAME ?=
MODULE_DIRNAME ?=
MODULE_KO := $(MODULE_NAME).ko
MODULE_DIRPATH := $(BUILD_DIR)/$(MODULE_DIRNAME)
MODULE_PATH := $(MODULE_DIRPATH)/$(MODULE_KO)

# === Other vars ===
NPROC := $(shell nproc)
RSYNC := rsync -r -u -l --progress
INSTALL_MODULES ?=
RUN_IMAGE_CODENAME ?=

ifeq ($(strip $(RUN_IMAGE_CODENAME)),busybox)
	QEMU_IMG_OPTS := -initrd $(RAMFS_BB_IMAGE)
else ifeq ($(strip $(RUN_IMAGE_CODENAME)),alpine)
	QEMU_IMG_OPTS := -hda $(ROOTFS_ALPINE_IMG_PATH)
else ifeq ($(RUN_IMAGE_CODENAME),debian)
	QEMU_IMG_OPTS := -hda TODO
endif

all:
	@echo "Use targets directly"

$(LINUX_TAR):
	wget https://cdn.kernel.org/pub/linux/kernel/v6.x/$@

$(KERNEL_PATH): $(LINUX_TAR)
	cd $(BUILD_DIR)
	tar -xf $(WORK_DIR)/$(LINUX_TAR) -C $(BUILD_DIR)

kernel-configure: $(KERNEL_PATH)
ifeq ($(strip $(KERNEL_CFG)),)
	make defconfig -C $(KERNEL_PATH)
else
	cp $(KERNEL_CFG) $(KERNEL_PATH)/.config
endif

kernel-build:
	make -j$(NPROC) -C $(KERNEL_PATH)

prepare-ksource: $(KERNEL_PATH)

kernel-compile-commands:
	cd $(KERNEL_PATH) && python3 scripts/clang-tools/gen_compile_commands.py
ifneq ($(strip $(KERNEL_COMPILE_CMDS_REPLACE)),)
	cd $(KERNEL_PATH) && sed -i "s|$(BUILD_DIR)|$(KERNEL_COMPILE_CMDS_REPLACE)|g" compile_commands.json
endif


.PHONY: prepare-ksource kernel-configure kernel-build

# === Making rootfs with busybox ===

$(BUSYBOX_TAR):
	wget https://busybox.net/downloads/$@

$(BUSYBOX_PATH): $(BUSYBOX_TAR)
	tar -xf $(BUSYBOX_TAR) -C $(BUILD_DIR)

$(BUSYBOX_PATH)/_install: $(BUSYBOX_PATH)
	cp $(BUSYBOX_CFG) $(BUSYBOX_PATH)/.config
	make -j$(NPROC) -C $(BUSYBOX_PATH)
	make install -C $(BUSYBOX_PATH)

$(DROPBEAR_TAR):
	wget https://github.com/mkj/dropbear/archive/refs/tags/$@

$(DROPBEAR_PATH): $(DROPBEAR_TAR)
	tar -xf $(DROPBEAR_TAR) -C $(BUILD_DIR)

$(DROPBEAR_PATH)/_install: $(DROPBEAR_PATH)
	cd $(DROPBEAR_PATH) && ./configure --disable-zlib --enable-static
	make -C $(DROPBEAR_PATH) -j$(NPROC) PROGRAMS="dropbear dbclient scp" DESTDIR=$(DROPBEAR_PATH)/_install install

$(RAMFS_BB_IMAGE): $(BUSYBOX_PATH)/_install $(SKELETON_BB_PATH)
	mkdir -p $(RAMFS_BB_DIR)
	cd $(RAMFS_BB_DIR) && mkdir -p bin etc/dropbear dev root proc sys tmp
	$(RSYNC) $(BUSYBOX_PATH)/_install/* $(RAMFS_BB_DIR)
	$(RSYNC) $(DROPBEAR_PATH)/_install/usr/local/* $(RAMFS_BB_DIR)
ifneq ($(strip $(INSTALL_MODULES)),)
	make -C $(KERNEL_PATH) INSTALL_MOD_PATH=$(RAMFS_BB_DIR) modules_install
endif
	$(RSYNC) rootfs-files/busybox/ $(RAMFS_BB_DIR)
	cd $(RAMFS_BB_DIR) && find . | cpio --quiet -H newc -o | gzip -9 -n > $(RAMFS_BB_IMAGE)

busybox: $(BUSYBOX_PATH)/_install
dropbear: $(DROPBEAR_PATH)/_install
ramfs-busybox: $(RAMFS_BB_IMAGE)
remove-ramfs-busybox:
	rm -f $(RAMFS_BB_IMAGE)

.PHONY: busybox ramfs-busybox dropbear

# === Make rootfs with alpine ===

$(ALPINE_MAKE_ROOTFS_TAR):
	wget https://github.com/alpinelinux/alpine-make-rootfs/archive/refs/tags/v$(ALPINE_MAKE_ROOTFS_VER).tar.gz \
		-O $(ALPINE_MAKE_ROOTFS_TAR)

$(ROOTFS_ALPINE_MAKE_PATH): $(ALPINE_MAKE_ROOTFS_TAR)
	tar -xf $(ALPINE_MAKE_ROOTFS_TAR) -C $(BUILD_DIR)

$(ROOTFS_ALPINE_ROOTFS_PATH): $(ROOTFS_ALPINE_MAKE_PATH) $(ROOTFS_ALPINE_SCRIPT)
	rm -rf $(ROOTFS_ALPINE_ROOTFS_PATH)
	cd $(ROOTFS_ALPINE_MAKE_PATH) && \
		APK="$(ROOTFS_ALPINE_MAKE_PATH)/apk.static" ./alpine-make-rootfs --branch $(ALPINE_MAKE_ROOTFS_BRACNH) \
		--packages $(ROOTFS_ALPINE_PACKAGES) $(ROOTFS_ALPINE_ROOTFS_PATH) \
		$(ROOTFS_ALPINE_SCRIPT)

$(ROOTFS_ALPINE_IMG_PATH): $(ROOTFS_ALPINE_ROOTFS_PATH)
ifneq ($(strip $(INSTALL_MODULES)),)
	make -C $(KERNEL_PATH) INSTALL_MOD_PATH=$(ROOTFS_ALPINE_ROOTFS_PATH) modules_install
endif
	virt-make-fs -F qcow2 -s +100M -t ext4 --blocksize=512 $(ROOTFS_ALPINE_ROOTFS_PATH) $(ROOTFS_ALPINE_IMG_PATH)

rootfs-alpine: $(ROOTFS_ALPINE_IMG_PATH)
remove-rootfs-alpine-dir:
	rm -rf $(ROOTFS_ALPINE_ROOTFS_PATH)
remove-rootfs-alpine:
	rm -f $(ROOTFS_ALPINE_IMG_PATH)

# === Make rootfs with debootstrap ===
# TODO

# === Modules commands ===

module-build:
	mkdir -p $(BUILD_DIR)/$(MODULE_DIRNAME)
	$(RSYNC) $(WORK_DIR)/$(MODULE_DIRNAME)/* $(BUILD_DIR)/$(MODULE_DIRNAME)
	make -j$(NPROC) -C $(MODULE_DIRPATH) KERNEL_SRC=$(KERNEL_PATH)

module-sync-vm:
	$(SCP) $(MODULE_PATH) $(SSH_USER):/tmp/.

module-reload:
	$(SSH) rmmod $(MODULE_KO) || true
	$(SSH) insmod /tmp/$(MODULE_KO)

# === QEMU commands ===

# To change init process set rdinit=/path/to/init in kernel args
qemu-run:
	qemu-system-x86_64 --enable-kvm -smp cpus=4 -m $(QEMU_MEMORY) -cpu host -nographic \
	-append "console=ttyS0 root=/dev/sda rw" \
	-nic user,hostfwd=tcp:127.0.0.1:$(QEMU_SSH_PORT)-:22 \
	-kernel $(BZIMAGE) $(QEMU_IMG_OPTS)

qemu-kill:
	kill $(shell pgrep -f qemu-system-x86_64)

qemu-ssh:
	TERM="xterm-256color" $(SSH) $(SSH_CMD)
