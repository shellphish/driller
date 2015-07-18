#!/bin/bash -e

# cd into the build directory
pushd $(dirname "$0") >/dev/null
BUILD_DIR="`pwd`"
popd >/dev/null

cd $BUILD_DIR

# require afl 1.83b
VERS="1.83b"
AFL_URL="http://lcamtuf.coredump.cx/afl/releases/afl-$VERS.tgz"

ARCHIVE="`basename -- "$AFL_URL"`"

wget -O "$ARCHIVE" -- "$AFL_URL" || exit 1

rm -rf "afl-$VERS" || exit 1
tar xf "$ARCHIVE" || exit 1

# apply the driller patch
cd afl-$VERS

patch afl-fuzz.c < ../../patches/driller-afl.patch
patch qemu_mode/build_qemu_support.sh < ../../patches/driller-afl-qemu-mode.patch

make -j
cd qemu_mode
./build_qemu_support.sh
cd ..

cp afl-fuzz ../../driller-afl-fuzz

cd ..
ln -s afl-$VERS afl

echo "All done!"
