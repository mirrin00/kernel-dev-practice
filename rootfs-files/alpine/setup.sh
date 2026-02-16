#!/bin/sh

cd $ROOTFS

# Setup serial console

echo "ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100" >> etc/inittab

# Setup network
echo "nameserver 1.1.1.1" >  etc/resolv.conf

mkdir -p etc/network
cat > etc/network/interfaces <<-EOF
	auto eth0
	iface eth0 inet dhcp

	post-up /etc/network/if-post-up.d/*
	post-down /etc/network/if-post-down.d/*
EOF

ln -s /etc/init.d/networking etc/runlevels/default/networking

# Setup sshd
cat >> etc/ssh/sshd_config <<-EOF
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
EOF
ln -s /etc/init.d/sshd etc/runlevels/default/sshd

# Setup hostname
echo "qemu-vm" > etc/hostname

# Setup automount of several dirs
cat >> etc/init.d/automount <<-EOF
#!/sbin/openrc-run

description="Mount sysfs tracefs and devpts"

start() {
    ebegin "Mounting sysfs+tracefs+devpts"
    mount -t sysfs none /sys
    mount -t tracefs none /sys/kernel/tracing
    mkdir -p /dev/pts
    mount -t devpts devpts /dev/pts
    eend $?
}
EOF

chmod +x etc/init.d/automount
ln -s /etc/init.d/automount etc/runlevels/default/automount

# Disable password & unlock root, only for VM!!!

sed -i "s|root:x:0:0|root::0:0|" etc/passwd
sed -i "s|root:\*::0|root:::0|" etc/shadow
