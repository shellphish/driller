#!/bin/sh

# make a directory for our modified qemu
mkdir driller_qemu

# require qemu 2.3.0
QEMU_GIT="git://git.qemu.org/qemu.git"

git clone $QEMU_GIT
cd qemu
git checkout tags/v2.3.0

# apply the driller patch
git apply ../patches/driller-qemu.patch

./driller-config
make -j

X64_DEST="x86_64-linux-user/qemu-x86_64"
I386_DEST="i386-linux-user/qemu-i386"

mv $X64_DEST ../driller_qemu/driller-qemu-x86_64
mv $I386_DEST ../driller_qemu/driller-qemu-i386

echo "All done!"
