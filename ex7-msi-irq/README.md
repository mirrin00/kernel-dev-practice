# Description

This kernel module implements PCI driver for custom QEMU device. QEMU device send interrupts and the driver handles them.

To run this example:
1) Download QEMU source code for version 8.0.5
2) Copy 'qemu-device/msi-example.c' to 'qemu/hw/misc/msi-example.c'
3) Modify 'qemu/hw/misc/Kconfig' by adding config parameter for device:
```
config MSI_EXAMPLE
    bool
    default y if TEST_DEVICES
    depends on PCI && MSI_NONBROKEN
```
4) Modify 'qemu/hw/misc/meson.build' by adding string:
```
softmmu_ss.add(when: 'CONFIG_MSI_EXAMPLE', if_true: files('msi-example.c'))
```
5) Compile QEMU with the device
6) Run your VM with this QEMU and commandline argument:
```
qemu/build/qemu-system-x86_64 -device msi-example
```
7) Load kernel module into VM kernel
