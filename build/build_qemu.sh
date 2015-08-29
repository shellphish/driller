#!/bin/bash -e

pushd $(dirname "$0") >/dev/null
BUILD_DIR="`pwd`"
popd >/dev/null

DRILLER_QEMU="driller-qemu/"

cd $BUILD_DIR

# remove qemu directory
rm -rf ../$DRILLER_QEMU

# make a directory for our modified qemu
mkdir ../$DRILLER_QEMU

# require qemu 2.3.0
QEMU_GIT="git://git.qemu.org/qemu.git"

# remove qemu git directory
rm -rf qemu

git clone $QEMU_GIT
cd qemu
git checkout tags/v2.3.0

# apply the driller patch
git apply ../../patches/driller-qemu.patch

./driller-config
make -j

X64_DEST="x86_64-linux-user/qemu-x86_64"
I386_DEST="i386-linux-user/qemu-i386"

mv $X64_DEST ../../$DRILLER_QEMU/driller-qemu-x86_64
mv $I386_DEST ../../$DRILLER_QEMU/driller-qemu-i386

echo "Done with ELF qemu!"
cd ..

CGC_QEMU_GIT="git@git.seclab.cs.ucsb.edu:cgc/qemu.git"

# remove cgc_qemu
rm -rf cgc_qemu

git clone $CGC_QEMU_GIT "cgc_qemu"
cd cgc_qemu
git checkout base_tracer
./cgc_configure_opt
make -j

cp i386-linux-user/qemu-i386 ../../$DRILLER_QEMU/driller-qemu-cgc

echo "Done with CGC qemu!"
echo "All done!"
