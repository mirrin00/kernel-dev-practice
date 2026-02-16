#!/usr/bin/env just --justfile

PWD := `pwd`
docker := "podman"
img_name := "kernel-dev-img"
cnt_name := "kernel-dev"
build_dir :=  PWD / "build"
install_modules := ""
docker-make := docker + " exec -it " + cnt_name + " make INSTALL_MODULES=" + install_modules + " "

# === Working with containers ===
build-image:
	{{ docker }} build -t {{ img_name }} .

start-container *EXTRA_ARGS:
	mkdir -p {{ build_dir }}
	{{ docker }} run --rm -d -it -v {{ PWD }}:/work:Z -v {{ build_dir }}:/build:Z --name {{ cnt_name }} --device=/dev/kvm {{ EXTRA_ARGS }} {{ img_name }}

stop-container:
	{{ docker }} kill {{ cnt_name }}

icontainer:
	{{ docker }} exec -it {{ cnt_name }} /bin/bash

# === Kernel build ===

kernel-compile-commands:
	{{ docker-make }} KERNEL_COMPILE_CMDS_REPLACE={{ build_dir }} kernel-compile-commands

kernel-build:
	{{ docker-make }} kernel-build

kernel-configure config="":
	{{ docker-make }} KERNEL_CFG={{config}} kernel-configure

# === Build options ===

ramfs-busybox:
	{{ docker-make }} ramfs-busybox

ramfs-rebuild-busybox:
	{{ docker-make }} remove-ramfs-busybox
	{{ docker-make }} ramfs-busybox

rootfs-alpine:
	{{ docker-make }} rootfs-alpine

rootfs-rebuild-alpine:
	{{ docker-make }} remove-rootfs-alpine
	{{ docker-make }} rootfs-alpine

# === Module commands ===

module-build module-dir module-name:
	{{ docker-make }} MODULE_NAME="{{ module-name }}" MODULE_DIRNAME={{ module-dir }} module-build

module-sync-vm module-dir module-name: (module-build module-dir module-name)
	{{ docker-make }} MODULE_NAME="{{ module-name }}" MODULE_DIRNAME={{ module-dir }} module-sync-vm

module-reload module-dir module-name:
	{{ docker-make }} MODULE_NAME="{{ module-name }}" MODULE_DIRNAME={{ module-dir }} module-reload

module-rebuild module-dir module-name: (module-sync-vm module-dir module-name) (module-reload module-dir module-name)

# === QEMU commands ===

qemu-run rootfs_type="busybox":
	{{ docker-make }} RUN_IMAGE_CODENAME="{{ rootfs_type }}" qemu-run

qemu-kill:
	{{ docker-make }} qemu-kill

ssh *CMD:
	{{ docker-make }} SSH_CMD="{{ CMD }}" qemu-ssh

# === General commands ===
make *ARGS:
	{{ docker-make }} {{ ARGS }}
