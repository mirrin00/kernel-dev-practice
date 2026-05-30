# kernel-dev-practice
Source code for the kernel development workshops at the ETU

The program of workshops can be found in the following files:
* [2026 (current)](./README.md)
* [2025](./README-2025.md)

# Quickstart

```shell
# Build docker image to work with project
just build-image
# Start container
just start-container
# Download and configure kernel. Another config can be used
# Command without config uses defconfig from kernel
just kernel-configure config.san
# Build the kernel
just kernel-build
# Build busybox ramfs. It downloads busybox, dropbear and fish
just ramfs-busybox
# Also alpine or debian rootfs can be build
# just rootfs-alpine
# just rootfs-debian
# Create qcow2 for the home (can be used between vms and rebuilds) and
# qcow2 for the external dev (for block and fs exampels). Filesare created
# at the /tmp, so after container restart they are removed
just make create-tmp-disk
just make create-tmp-home
# Build and insmod module to the vm
just module-rebuild ex9-fs mfs
```

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

# Practice 2 & 3

## Tracepoints

1. [Ftrace](https://www.kernel.org/doc/html/latest/trace/ftrace.html)
    1. Compile the kernel with ftrace support, see [`config.ftrace` config](./config.ftrace)
    2. Enable tracing (function or function_graph)
    3. Trace some kernel events (e.g. `ksys_read,write`)
2. Make your own tracepoints with trace_printk
3. Define a trace point with `TRACE_EVENT` macro (see [details](https://lwn.net/Articles/379903/))
    1. Be careful, it is required separate header file!

## Modules

### Module 3: dynamic debug & tracepoint usage

* [Module `pid-info` (dir ex3-pid-info)](./ex3-pid-info/)
* To use [dynamic debug](https://www.kernel.org/doc/html/latest/admin-guide/dynamic-debug-howto.html):
    * Enable dynamic debug (`CONFIG_DYNAMIC_DEBUG` option) in the kernel config.
      See [`config.ddebug` config](./config.ddebug)
    * Recompile the kernel
    * Activate debug messages in the module via `/proc/dynamic_debug/contol`
* Tracepoints: [see section with tracepoints](#tracepoints)

### Module 4: sanitizers

* [Module `check-sanitizers` (dir ex4-sanitizers)](./ex4-sanitizers/), [`config.san` config](./config.san)
* [KASAN](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html)
    * Detects memory access bugs: use-after-free, double free, out of bounds access, ...
    * Enable `CONFIG_KASAN` option in the kernel config
    * Add the `kasan_multi_shot=Y` argument to the kernel load
      so that it does not go silent after the first error
    * Very strong impact on system performance
* [KMEMLEAK](https://www.kernel.org/doc/html/latest/dev-tools/kmemleak.html)
    * Detects memory leaks
    * Enable `CONFIG_DEBUG_KMEMLEAK` option in the kernel config
    * Run `echo scan > /sys/kernel/debug/kmemleak` to trigger a memory leak search
    * Run `cat /sys/kernel/debug/kmemleak` to get information about memory leaks found
* [LOCKDEP](https://www.kernel.org/doc/html/latest/locking/lockdep-design.html)
    * Detects bugs in locking: deadlocks, missing lock, lock correctness, ...
    * Enable `CONFIG_LOCKDEP` option in the kernel config
    * Use the `lockdep_assert_held*` family of macro to increase lockdep strength

Check out [syzkaller](https://github.com/google/syzkaller) about kernel fuzzing.
It is very exciting

### Module livecode: simple common kernel API

* [Module `livecode` (dir livecode)](./livecode/)
* [Memory allocation](https://www.kernel.org/doc/html/latest/core-api/memory-allocation.html):
    * For most cases: `kmalloc`/`kzalloc`/`kcalloc`
    * For some cases: `vmalloc`
    * To allocate many identical objects: [kmemcache](https://www.kernel.org/doc/html/latest/core-api/mm-api.html#c.kmem_cache_create)
* [Strings](https://www.kernel.org/doc/html/latest/core-api/kernel-api.html#string-conversions):
    * `sscanf`
    * `strto*` family of functions
* [List](https://docs.kernel.org/core-api/list.html)
    * The basic structure that links the entities together
    * Use `list_for_each` family of macro to iterate over list
    * Supports rcu locking
* [Atomic operations](https://www.kernel.org/doc/html/latest/core-api/wrappers/atomic_t.html)
    * `atomic_t`
    * Basic operations: `atomic_set`, `atomic_read`, `atomic_inc`, ...
    * Advanced operations: `atomic_cmpxchg`, `atomic_fetch_add`, `atomic_inc_not_zero`, ...
    * Bit operations: `set_bit`, `test_bit`, `clean_bit`
* [Kthread](https://www.kernel.org/doc/html/latest/driver-api/basics.html#c.kthread_create)
    * New schedulable entity
    * Use `kthread_create` or `kthread_run` to create a new kthread
    * Use `kthread_should_stop` to check if a thread should be stopped
* [Workqueue](https://www.kernel.org/doc/html/latest/core-api/workqueue.html)
    * Defer work to another context
    * Module workqueues and system workqueues
    * Normal `work_struct` to defer work to another context
    * Delayed `delayed_work` to defer work for a while
* [Sleep](https://www.kernel.org/doc/html/latest/timers/delay_sleep_functions.html):
    * Wait a certain amount of time
    * For most cases: `delay`/`msleep`
    * Timers with callback (irq context)
* [Completion](https://www.kernel.org/doc/html/latest/scheduler/completion.html)
    * Wait for some event
    * A `wait_for_completion*` family of functions for a variety of situations
    * Use `complete` to wake up only one waiter and `complete_all` to wake up all waiters
* [Refcnt](https://www.kernel.org/doc/html/latest/core-api/kref.html)
    * Control the lifetime of the object
    * Basic `+1` in constructor and `-1` in destructor
    * Pin an object (_may be under lock_) before use
* [Locking](https://www.kernel.org/doc/html/latest/kernel-hacking/locking.html) ([link2](https://www.kernel.org/doc/html/latest/locking/locktypes.html))
    * Protect a critical section from concurrent access/modification
    * spinlock, mutex, semaphor, rwlock, [seqlock](https://docs.kernel.org/locking/seqlock.html)
    * [Read-Copy-Update](https://www.kernel.org/doc/html/latest/RCU/whatisRCU.html)
* Not considered, but worth mentioning:
    * [Wait Queues](https://www.kernel.org/doc/html/v7.0/kernel-hacking/hacking.html#wait-queues-include-linux-wait-h)
    * [Tasklets](https://www.kernel.org/doc/html/v7.0/kernel-hacking/hacking.html#software-interrupt-context-softirqs-and-tasklets)
    * `struct sbitmap` (`linux/sbitmap.h`)
    * [Memory barriers](https://www.kernel.org/doc/html/latest/core-api/wrappers/memory-barriers.html)
    * `alloc_pages`
    * [DMA](https://www.kernel.org/doc/html/latest/core-api/dma-api-howto.html)
    * Hashtable (`linux/hashtable.h`)
    * [Xarrays](https://docs.kernel.org/core-api/xarray.html)

### Module 5: queue

* [Module `queue` (dir ex5-queue)](./ex5-queue/)
* A complex example of using a common kernel API
* Repeats [livecode modile](#module-livecode-simple-common-kernel-api), but connects various mechanics into a single system

# Practice 4

## Modules

### Module 8: simple block

* [Module `sblock` (dir ex8-block)](./ex8-block/)
* Block device
    * Open block device with `bdev_file_open_by_path` or `bdev_file_open_by_dev`
    * Get logical block size with `bdev_logical_block_size`
        * Requests smaller than a logical block size are invalid
    * `bd_nr_sectors` field reports number of sectors in the bdev
    * `bdev_nonrot` field reports whether the bdev is a rotating device or not
    * `bdev_get_integrity` is used to get integrity information
* Bio (Block I/O)
    * `struct bio` to crate Block I/O
    * `bioset` used for allocations (from module or system)
    * Add data pages with `bio_add_page`
        * Bio can contain several different pages (look at the `bio->bi_io_vec`)
        * A single item in `bio->bi_io_vec` can be a multipage
    * Bio iterator: `bio->bi_iter`
    * Send bio with `submit_bio` or `submit_bio_noacct`. At the end of the request, `bio->bi_end_io` is called with private data (`bio->bi_private`)
        * For blocking submission, use `submit_bio_wait`
    * [Integrity](https://www.kernel.org/doc/html/latest/block/data-integrity.html)
        * `bio_integrity_alloc` is used to allocate integrity structure
        * `bio_integrity_add_page` is used to add intergiry to a bio
* Chaining bio
    * Combine multiple bios into one chain and process the result after all bios are completed
    * Use `bio_chain` to chain previous bio to the new one
    * Do not forget `submit_bio` for the previous bio
* Block device creation
    * bio-based or mutli-queue based modes (*mq is not present in the module*)
    * `struct gendisk` is the core of the block device
    * Setup the parameters using the `struct queue_limits`
    * Setup the callbacks with the `struct block_device_operations`
* Scatterlist API (`linux/scatterlist.h`):
    * Collect into single list several dma buffers
    * Allocate list with `sg_alloc_table`
    * Use `sg_set_page` to setup page
    * Iterate over sg list with `for_each_sgtable_sg`
* Not considered, but worth mentioning:
    * `io_uring`
    * [Userspace block device (`ublk`)](https://www.kernel.org/doc/html/latest/block/ublk.html)

## Usefull links

* [Repository: Simple multi-queue block device creation](https://github.com/CodeImp/sblkdev/tree/master)
* [Presentation: Block I/O Layer](https://www.cs.cornell.edu/courses/cs4410/2021fa/assets/material/lecture24_blk_layer.pdf)
* [Labs on Linux: Block Device Drivers](https://linux-kernel-labs.github.io/refs/heads/master/labs/block_device_drivers.html)
* [Linux Kernel Doc: Multi-Queue Block IO Queueing Mechanism](https://docs.kernel.org/block/blk-mq.html)
https://lwn.net/Articles/26404/

# Practice 5

## Modules

### Module 9: simple filesystem

* [Module `mfs` (dir ex9-fs)](./ex9-fs/)
* Register fs with `register_filesystem`
    * The `FS_REQUIRES_DEV` flag indicates that a block device is required.
* Superblock (sb)
    * Version
    * Byte-ordering (le/be)
    * Magic
    * Reserve bytes
    * `static_assert` on the sb size
    * Checksum (sha256)
* Metadata:
    * Stores inodes and other information about where to find user data
    * Can store journals and other stuff for reliability & recovery
* On mount:
    * Read superblock
    * Check magic, version and other fields
    * Repair superblock/metadata
    * Read & create root
* Super opeations (`struct super_operations`)
    * inode allocation & destroying
    * superblock destroying
    * writing inode to the dev
* Inode
    * The main part of the filesystem
    * Embedded generic inode into your custom inode structure
    * Read inode from the metadata or create new
    * Setup inode operations
        * For directories setup `lookup` (to get inode by dentry), `create` (to create a new inode with dentry) and `unlink` (to remove dentry)
        * For files setup address opeations for read/write syscalls

## Usefull links

* [Description of the old kernel fs data structures](https://aeb.win.tue.nl/linux/lk/lk-8.html)
* [Repository: kernel filesystem example](https://github.com/sysprog21/simplefs) (a more real and complex example of fs implementation)

# Usefull links

* [Labs on linux](https://linux-kernel-labs.github.io/refs/heads/master/labs/kernel_modules.html)
* [Notes for debug](https://cs4118.github.io/dev-guides/kernel-debugging.html)
* [How to defer work in the kernel](https://linux-kernel-labs.github.io/refs/heads/master/labs/deferred_work.html)
* [Kernel Development Learning Pipeline (KDLP)](https://kdlp.underground.software/slides/index.html)
