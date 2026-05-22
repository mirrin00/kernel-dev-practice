#!/bin/sh

ip link set up dev eth0
ip addr add 10.0.2.15/24 dev eth0
ip r add 0.0.0.0/0 via 10.0.2.2 dev eth0
