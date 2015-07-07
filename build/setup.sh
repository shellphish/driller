#!/bin/bash -e

pushd $(dirname "$0") >/dev/null
DRILLER_DIR="`pwd`/.."
popd >/dev/null

sudo apt-get install libpixman-1-dev

cd $DRILLER_DIR
./build/build_qemu.sh
./build/build_afl.sh
pip install -r reqs.txt
