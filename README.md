# kernel-dev-practice
Source code for the kernel development workshops at the ETU

# Practice 1

## Setup environment

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

Download debian minimal rootfs image: https://cloud.debian.org/images/cloud/ .
For example, [debian-12-nocloud (passwordless root)](https://cloud.debian.org/images/cloud/bookworm/20250210-2019/debian-12-nocloud-amd64-20250210-2019.qcow2)

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

### How to run with QEMU

#### Run with the kernel installed in rootfs

```shell
qemu-system-x86_64 -smp cpus=4 -m 256m -cpu host -nographic  debian-12-nocloud-amd64-20250210-2019.qcow2
```

#### Run with the custom kernel

```shell
qemu-system-x86_64 -smp cpus=4 -m 256m -cpu host -nographic -kernel /wspc/linux-6.12.15-origin/vmlinux -hda debian-12-nocloud-amd64-20250210-2019.qcow2 -append "console=ttyS0 root=/dev/sda1" --enable-kvm
```

**NOTE**: `/dev/sda1` may be different on your image

#### Run with ssh forwarding

See [documentation](https://www.qemu.org/docs/master/system/qemu-manpage.html) for more options

```shell
qemu-system-x86_64 -smp cpus=4 -m 256m -cpu host -nographic -kernel /wspc/linux-6.12.15-origin/vmlinux -hda debian-12-nocloud-amd64-20250210-2019.qcow2 -append "console=ttyS0 root=/dev/sda1" --enable-kvm -nic user,hostfwd=tcp:127.0.0.1:2222-:22
```

#### Run with the virtual filesystem to passthrough the host dir

See [documentation](https://www.qemu.org/docs/master/system/qemu-manpage.html) for more options

```shell
qemu-system-x86_64 -smp cpus=4 -m 256m -cpu host -nographic -kernel /wspc/linux-6.12.15-ddebug/vmlinux -hda debian-12-nocloud-amd64-20250210-2019.qcow2 -append "console=ttyS0 root=/dev/sda1" --enable-kvm -nic user,hostfwd=tcp:127.0.0.1:2222-:22 -virtfs local,path=/wspc/,mount_tag=mnt,security_model=mapped-xattr,id=mnt
```

#### Run with the netconsole module

See [documentation](https://www.kernel.org/doc/html/latest/networking/netconsole.html) for parameter descriptions

```shell
qemu-system-x86_64 -smp cpus=4 -m 256m -cpu host -nographic -kernel /wspc/linux-6.12.15-ddebug/vmlinux -hda debian-12-nocloud-amd64-20250210-2019.qcow2 -append "console=ttyS0 root=/dev/sda1 netconsole=@10.0.2.15/,4444@192.168.140.226/" --enable-kvm -nic user,hostfwd=tcp:127.0.0.1:2222-:22 -virtfs local,path=/wspc/,mount_tag=mnt,security_model=mapped-xattr,id=mnt
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

### Third module

* To use dynamic debug:
    * Enable it in the config
    * Recompile the kernel
    * Activate debug messages in the module via `/proc/dynamic_debug/contol`
* GDB: TBD
* Tracepoints: TBD

# Usefull links

* [Labs on linux](https://linux-kernel-labs.github.io/refs/heads/master/labs/kernel_modules.html)
* [Notes for debug](https://cs4118.github.io/dev-guides/kernel-debugging.html)

