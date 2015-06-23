#!/bin/bash -e

pushd $(dirname "$0") >/dev/null
DRILLER_DIR="`pwd`"
popd >/dev/null

cd $DRILLER_DIR
./build_qemu.sh
./build_afl.sh
pip install -r reqs.txt
