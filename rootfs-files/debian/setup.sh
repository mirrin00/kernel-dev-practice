#!/bin/bash

cd $1
REPL=$(pwd)

# Setup serial console
fakechroot chroot ./ systemctl enable serial-getty@ttyS0

# Setup network
mkdir -p etc/network/interfaces.d
cat > etc/network/interfaces.d/ens3 <<-EOF
	auto ens3
	iface ens3 inet dhcp

	post-up /etc/network/if-post-up.d/*
	post-down /etc/network/if-post-down.d/*
EOF

# Setup sshd
cat >> etc/ssh/sshd_config <<-EOF
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
EOF

# Setup hostname
echo "qemu-vm" > etc/hostname

# # Remove symlinks
rm proc dev
for f in $(find . -type l); do
    target=$(ls -lh $f | grep -E "$REPL.*$" -o)
    if [ -n "$target" ]; then
        new_target=$(echo $target | sed "s|$REPL||")
        rm -f $f
        ln -s $new_target $f
    fi
done

# Disable password & unlock root, only for VM!!!
sed -i "s|root:x:0:0|root::0:0|" etc/passwd
sed -i "s|root:\*:|root::|" etc/shadow
