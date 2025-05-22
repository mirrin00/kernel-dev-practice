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

# Practice 2

## Useful knowledge

### How to use gdb with qemu

1. Add the `-s` option to the `qemu` command to start gdb server on port 1234
2. Enable the `DEBUG_SYMBOLS` option in the kernel config
3. Add the `CFLAGS_MODULE='-g'` flag to the `Makefile` of the kernel module
4. Make `make scripts_gdb` to generate gdb support commands
5. Run `gdb vmlinux` and `target remote :1234` to connect to the vm
6. Run the `lx-symbols <module_path>` command in gdb to load symbols from the kernel module

Dor more inforamtion check
[kernel documentation](https://www.kernel.org/doc/html/v6.14-rc3/process/debugging/gdb-kernel-debugging.html)
about debugging with `gdb`. See [`config.gdb` config](./config.gdb)

### Tracepoints

1. [Ftrace](https://www.kernel.org/doc/html/latest/trace/ftrace.html)
    1. Compile the kernel with ftrace support, see [`config.ftrace` config](./config.ftrace)
    2. Enable tracing (function or function_graph)
    3. Trace some kernel events (e.g. `ksys_read,write`)
2. Make your own tracepoints with trace_printk
3. Define a trace point with `TRACE_EVENT` macro (see [details](https://lwn.net/Articles/379903/))
    1. Be careful, it is required separate header file!

## Modules

### Third module: complex exmaple with dynamic debug & tracepoints

* [Module dir](./ex3-pid-info/)
* To use [dynamic debug](https://www.kernel.org/doc/html/latest/admin-guide/dynamic-debug-howto.html):
    * Enable dynamic debug (`CONFIG_DYNAMIC_DEBUG` option) in the kernel config.
      See [`config.ddebug` config](./config.ddebug)
    * Recompile the kernel
    * Activate debug messages in the module via `/proc/dynamic_debug/contol`
* GDB: [see section with gdb](#how-to-use-gdb-with-qemu)
* Tracepoints: [see section with tracepoints](#tracepoints)

### Fourth module: sanitizers

* [Module dir](./ex4-sanitizers/), [`config.san` config](./config.san)
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

# Practice 3

### Fifth module: Basic structures and API

* [Module dir](./ex5-queue/)
* [Memory allocation](https://www.kernel.org/doc/html/latest/core-api/memory-allocation.html):
    * For most cases: `kmalloc`/`kzalloc`/`kcalloc`
    * For some cases: `vmalloc`
    * To allocate many identical objects: [kmemcache](https://www.kernel.org/doc/html/latest/core-api/mm-api.html#c.kmem_cache_create)
* [Strings](https://www.kernel.org/doc/html/latest/core-api/kernel-api.html#string-conversions):
    * `sscanf`
    * `strto*` family of functions
* [List](https://www.kernel.org/doc/html/latest/core-api/kernel-api.html#list-management-functions)
    * The basic structure that links the entities together
    * Use `list_for_each` family of macro to iterate over list
* [Workqueue](https://www.kernel.org/doc/html/latest/core-api/workqueue.html)
    * Defer work to another context
    * Module workqueues and system workqueues
    * Normal `work_struct` to defer work to another context
    * Delayed `delayed_work` to defer work for a while
* [Kthread](https://www.kernel.org/doc/html/latest/driver-api/basics.html#c.kthread_create)
    * New schedulable entity
    * Use `kthread_create` or `kthread_run` to create a new kthread
    * Use `kthread_should_stop` to check if a thread should be stopped
* [Sleep](https://www.kernel.org/doc/html/latest/timers/delay_sleep_functions.html):
    * Wait a certain amount of time
    * For most cases: `delay`/`msleep`
    * Timers with callback
* [Completion](https://www.kernel.org/doc/html/latest/scheduler/completion.html)
    * Wait for some event
    * A `wait_for_completion*` family of functions for a variety of situations
    * Use `complete` to wake up only one waiter and `complete_all` to wake up all waiters
* [Refcnt](https://www.kernel.org/doc/html/latest/core-api/kref.html)
    * Control the lifetime of the object
    * Basic `+1` in constructor and `-1` in destructor
    * Pin an object (_may be under lock_) before use
* [Atomic operations](https://www.kernel.org/doc/html/latest/core-api/wrappers/atomic_t.html)
    * `atomic_t`
    * Basic operations: `atomic_set`, `atomic_read`, `atomic_inc`, ...
    * Advanced operations: `atomic_cmpxchg`, `atomic_fetch_add`, `atomic_inc_not_zero`, ...
    * Bit operations: `set_bit`, `test_bit`, `clean_bit`
* [Memory barriers](https://www.kernel.org/doc/html/latest/core-api/wrappers/memory-barriers.html)
* [Locking](https://www.kernel.org/doc/html/latest/kernel-hacking/locking.html) ([link2](https://www.kernel.org/doc/html/latest/locking/locktypes.html))
    * Protect a critical section from concurrent access/modification
    * spinlock, mutex, semaphor, rwlock
    * [Read-Copy-Update](https://www.kernel.org/doc/html/latest/RCU/whatisRCU.html)

# Practice 4

### Sixth module: Custom char device for network filtering
* [Module dir](./ex6-netfilter/)
* [Char devices](https://linux-kernel-labs.github.io/refs/heads/master/labs/device_drivers.html)
* [Netfilter](https://linux-kernel-labs.github.io/refs/heads/master/labs/networking.html#netfilter-1)

# Practice 5

### Seventh module: Custom QEMU device and PCI driver implementation for it
* [Module dir](./ex7-msi-irq)
* [PCI drivers](https://docs.kernel.org/PCI/pci.html)

# Usefull links

* [Labs on linux](https://linux-kernel-labs.github.io/refs/heads/master/labs/kernel_modules.html)
* [Notes for debug](https://cs4118.github.io/dev-guides/kernel-debugging.html)
* [How to defer work in the kernel](https://linux-kernel-labs.github.io/refs/heads/master/labs/deferred_work.html)

