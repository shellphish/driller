#!/bin/bash -e

# cd into the build directory
pushd $(dirname "$0") >/dev/null
BUILD_DIR="`pwd`"
popd >/dev/null

cd $BUILD_DIR

git clone git@git.seclab.cs.ucsb.edu:mpizza/driller-afl.git

cd driller-afl

make -j
cd qemu_mode
./build_qemu_support.sh
cd ..

cp afl-fuzz ../../driller-afl-fuzz

cd ..
ln -s driller-afl afl

echo "All done!"
