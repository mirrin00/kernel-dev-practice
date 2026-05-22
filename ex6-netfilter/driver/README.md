# Task

It is necessary to implement an analog of the firewall. You must be able to create your own rules for filtering traffic (IPv4 only).
Command syntax: <package type> <address> <protocol> <action>.
- `<package type>` -- INPUT or OUTPUT
- `<address>` -- IPv4 address or "all"
- `<protocol>` -- support of ICMP, TCP, UDP packages
- `<action>` -- ACCEPT or DROP

Rules are created by writing a character device to the node. Reading the file should return a list of rules in any order.

IOCTL must be implemented to control the device.:
- `IOCTL_RESET` -- clear rules list
- `IOCTL_ENABLE` -- enable filter, netfilter should be enabled by default
- `IOCTL_DISABLE` -- disable filter
- `IOCTL_SET_INTERFACE` -- set a name for the interface that will be filtered. By default, the ens3 interface is set

# Solution

Kernel module implements char device with net filter. Source code is located in 'driver' directory. 'user' directory contains user space program which tests basic filter functionality.
