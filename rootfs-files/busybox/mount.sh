#!/bin/sh

mount -a
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts
