FROM debian:trixie-slim

WORKDIR /work
ENTRYPOINT [ "tail", "-f" ]

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    vim libncurses5-dev gcc make git exuberant-ctags \
    libssl-dev bison flex libelf-dev bc dwarves zstd git-email \
    bzip2 initramfs-tools rsync wget file musl-tools e2fsprogs \
    dosfstools libguestfs-tools debootstrap fakechroot \
    qemu-system
