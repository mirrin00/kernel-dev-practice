# kernel-dev-practice
Source code for the kernel development workshops at the ETU

The program of workshops can be found in the following files:
* [2026 (current)](./README.md)
* [2025](./README-2025.md)

# Practice 1

## Setup environment

### Container and entrypoint

#### Docker/Podman

All work is done in the docker container. [The image](./Dockerfile)
is very simple, it just installs necessary utilities to build kernel
and make rootfs.

Everything can be done in rootless mode.

#### Makefile

[Makefile](./Makefile) is the entrypoint for almost all commands in this
project. The Makefile is a bit overcomplicate ;). **The Makefile is assumed
to be used inside the container**. For **host use**, change the `BUILD_DIR`
and `WORK_DIR` variables. You can also configure versions and other parameters
using the corresponding variables

The most important targets are:
* `kernel-configure` downloads, unzips and configures linux kernel. Config can be specified with `KERNEL_CFG` variable
* `kernel-build` [re]builds linux kernel
* `kernel-compile-commands` creates `compile-commands.json` for `clangd`
* `ramfs-busybox` builds initrd ramfs based on `busybox` and `dropbear`
* `rootfs-alpine` builds ext4 rootfs based on `alpine`. The installed packages can be configured using the `ROOTFS_ALPINE_PACKAGES` variable
* `module-*` [re]builds out-of-tree kernel modules, copys them into the VM and inserts them
* `qemu-run` runs qemu with specified rootfs
* `qemu-kill` kills qemu process
* `qemu-ssh` connects to VM with ssh

#### Justfile

It could be just another Makefile, but it is [justfile](./justfile)
for the [`just`](https://github.com/casey/just).
It is the out-of-container entrypoint to execute commands in the project.
It's basically a copy of the main targets from the Makefile, but with
some more comfortable arguments.

### Kernel

Download linux kernel: https://www.kernel.org/
Select the latest longterm version, currently it is
[6.12.15](https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.15.tar.xz)

Example commands for debian-based distro:
```shell
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.15.tar.xz
# Unpack
tar -xf linux-6.12.15.tar.xz
# Install deps
apt install gcc make build-essential libncurses-dev bison flex libssl-dev libelf-dev
# Install qemu and gdb
apt install qemu-system gdb
```

* To set the default config, run the `make defconfig` command
* To open the TUI-based configuration tool, run the `make menuconfig`
  (or `make nconfig` for ncurses-based TUI) command
* To build kernel, run the `make -j<nproc>` command

### Rootfs image

#### Ready images (debian example)

Download debian minimal rootfs image: https://cloud.debian.org/images/cloud/ .
For example, [debian-13-nocloud (passwordless root)](https://cloud.debian.org/images/cloud/trixie/20260220-2394/debian-13-nocloud-amd64-20260220-2394.qcow2)

Customize the image for your own use:
* Configure ssh (required to run with [ssh forwarding](#run-with-ssh-forwarding))
    * Install openssh-server
    * Configure `sshd`
    * Generate ssh keys
    * Copy the public key to the VM
* Configure local mount (required to run with [virtual filesystem](#run-with-the-virtual-filesystem-to-passthrough-the-host-dir))
    * Example command: `mount -t 9p -o trans=virtio mnt /root/mnt`
    * Update `/etc/fstab`
* Install the necessary utils

#### Making your own rootfs image

Minimal ramfs with busybox and dropbear:
* Busybox:
    * Download source code https://busybox.net/downloads/busybox-1.36.1.tar.bz2
    * Configure static build (via [config](./.config.busybox) or `make menuconfig`)
    * Build and install
* Dropbear
    * Download source code https://github.com/mkj/dropbear/archive/refs/tags/DROPBEAR_2024.85.tar.gz
    * Configure static build `./configure --disable-zlib --enable-static`
    * Build and install
* Putting it all together:
    * Copy [skeleton rootfs](./rootfs-files/busybox/)
    * Copy files from busybox and dropbear builds
    * Change [init](./rootfs-files/busybox/init) process as you wish
    * Create initrd `find . | cpio --quiet -H newc -o | gzip -9 -n > ramfs-busybox.img`

Alpine-based rootfs:
* Clone repo with script https://github.com/alpinelinux/alpine-make-rootfs
* Run script `./alpine-make-rootfs` (read the documentation for available flags)
* To fine-tune rootfs use the [post-installation script](./rootfs-files/alpine/setup.sh)
* Make filesystem `virt-make-fs -F qcow2 -s +100M -t ext4 --blocksize=512 /build/rootfs-alpine rootfs-alpine.img`

Usefull links:
* [Linux kernel doc about initrd](https://docs.kernel.org/admin-guide/initrd.html)
* [Linux kernel doc about initramfs](https://www.kernel.org/doc/html/latest/filesystems/ramfs-rootfs-initramfs.html)
* [Debian wiki about initramfs and two stage boot](https://wiki.debian.org/initramfs)
* [Script to make simple rootfs](https://github.com/alpinelinux/alpine-make-rootfs)
* [Script to make real VM image (including partitioning)](https://www.kernel.org/doc/html/latest/kbuild/modules.html#module-installation)

## How to run with QEMU

### Run with your own rootfs

```shell
# Initrd exmaple
qemu-system-x86_64 --enable-kvm -smp cpus=4 -m 256m -cpu host -nographic -append "console=ttyS0 root=/dev/sda rw" -nic user,hostfwd=tcp:127.0.0.1:2222-:22 -kernel /build/linux-6.12.71/arch/x86_64/boot/bzImage -initrd /build/ramfs-busybox.img
# Rootfs example
qemu-system-x86_64 --enable-kvm -smp cpus=4 -m 256m -cpu host -nographic -append "console=ttyS0 root=/dev/sda rw" -nic user,hostfwd=tcp:127.0.0.1:2222-:22 -kernel /build/linux-6.12.71/arch/x86_64/boot/bzImage -hda /build/rootfs-alpine.img
```

### Run with the kernel installed in rootfs

```shell
qemu-system-x86_64 -smp cpus=4 -m 256m -cpu host -nographic  debian-13-nocloud-amd64-20260220-2394.qcow2
```

### Run with the custom kernel

```shell
qemu-system-x86_64 -smp cpus=4 -m 256m -cpu host -nographic -kernel /build/linux-6.12.71/arch/x86_64/boot/bzImage -hda debian-13-nocloud-amd64-20260220-2394.qcow2 -append "console=ttyS0 root=/dev/sda1" --enable-kvm
```

**NOTE**: `/dev/sda1` may be different on your image

### Run with ssh forwarding

See [documentation](https://www.qemu.org/docs/master/system/qemu-manpage.html) for more options

```shell
qemu-system-x86_64 -smp cpus=4 -m 256m -cpu host -nographic -kernel /build/linux-6.12.71/arch/x86_64/boot/bzImage -hda debian-13-nocloud-amd64-20260220-2394.qcow2 -append "console=ttyS0 root=/dev/sda1" --enable-kvm -nic user,hostfwd=tcp:127.0.0.1:2222-:22
```

### Run with the virtual filesystem to passthrough the host dir

See [documentation](https://www.qemu.org/docs/master/system/qemu-manpage.html) for more options

```shell
qemu-system-x86_64 -smp cpus=4 -m 256m -cpu host -nographic -kernel /wspc/linux-6.12.15-ddebug/vmlinux -hda debian-13-nocloud-amd64-20260220-2394.qcow2 -append "console=ttyS0 root=/dev/sda1" --enable-kvm -nic user,hostfwd=tcp:127.0.0.1:2222-:22 -virtfs local,path=/wspc/,mount_tag=mnt,security_model=mapped-xattr,id=mnt
```

### Run with the netconsole module

See [documentation](https://www.kernel.org/doc/html/latest/networking/netconsole.html) for parameter descriptions

```shell
qemu-system-x86_64 -smp cpus=4 -m 256m -cpu host -nographic -kernel /wspc/linux-6.12.15-ddebug/vmlinux -hda debian-13-nocloud-amd64-20260220-2394.qcow2 -append "console=ttyS0 root=/dev/sda1 netconsole=@10.0.2.15/,4444@192.168.140.226/" --enable-kvm -nic user,hostfwd=tcp:127.0.0.1:2222-:22 -virtfs local,path=/wspc/,mount_tag=mnt,security_model=mapped-xattr,id=mnt
```

**NOTE**: your ip address (`192.168.140.226` in the example) may be different

## Modules

### First "Hello World" module

* [Module dir](./ex1/)
* Compile it
* Copy the `ex1.ko` file to the VM
* Insert the module using the `insmod ex1.ko` command

### Second module

1. Copy the [`ex2` dir](./ex2/) to the kernel source tree, into the `drivers/misc`
2. Add `source "drivers/misc/ex2/Kconfig"` to the `Kconfig`
3. Add `obj-$(CONFIG_MY_EXAMPLE) += ex2/` to the `Makefile`
4. Use `make modules_install` to install compiled modules
    1. For your own rootfs look at the `install_modules` in `justfile` and `INSTALL_MODULES` in `Makefile`

# Usefull links

* [Labs on linux](https://linux-kernel-labs.github.io/refs/heads/master/labs/kernel_modules.html)
* [Notes for debug](https://cs4118.github.io/dev-guides/kernel-debugging.html)
* [How to defer work in the kernel](https://linux-kernel-labs.github.io/refs/heads/master/labs/deferred_work.html)

